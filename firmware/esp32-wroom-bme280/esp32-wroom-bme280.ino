// Unlicense — NANOBYTE Block 0.0 desk-mote firmware
//
// ESP32-WROOM-32 + BME280 → nanobyte-proto telemetry over USB-serial.
//
// Wiring (BME280 breakout, I²C mode):
//   BME280 VCC  → ESP32 3V3   (⚠ NOT 5V — BME280 is 3.3V only)
//   BME280 GND  → ESP32 GND
//   BME280 SDA  → ESP32 GPIO21
//   BME280 SCL  → ESP32 GPIO22
//
// The I²C address auto-detects between 0x76 (AdaFruit-style, default) and
// 0x77 (some generic breakouts). No config needed.
//
// Wire format on Serial (115200 baud):
//   One ASCII line per telemetry frame.
//   Line = hex-encoded bytes + '\n'.
//   Bytes decode to a canonical `nanobyte-proto` frame:
//     magic[2] = 0x4E 0xB0
//     version  = 0x01
//     kind     = 0x10  (BME280_SAMPLE — demo-specific, distinct from kind::TELEMETRY)
//     seq[2]   = big-endian u16, increments per frame
//     len[2]   = big-endian u16 payload length (always 15 for this kind)
//     payload  = 15 bytes:
//        mote_id[4]      big-endian u32 — 0x00010001 for this specific board
//        seq[2]          big-endian u16 — matches header seq
//        class[1]        u8 0..=3 per trivial classifier below
//        confidence[1]   u8 — unused, always 0 in Block 0.0
//        cap_mv_over_10  u8 — fake 3.3V constant = 33
//        temp_c100[2]    big-endian i16 — centi-°C
//        humidity_x100[2] big-endian u16 — centi-percent (0..=10000)
//        pressure_hPa_x10[2] big-endian u16 — tenths of hPa (e.g. 10132 = 1013.2 hPa)
//     crc16[2]           big-endian CRC-16/CCITT-FALSE of payload
//
// Lines beginning with '#' are debug text and must be ignored by the decoder.

#include <Wire.h>
#include <Adafruit_Sensor.h>
#include <Adafruit_BME280.h>

// ── Pin configuration ────────────────────────────────────────────────────
// ESP32 Arduino core default I²C pins. If your BME280 is wired elsewhere,
// change only these two lines.
static const int PIN_SDA = 21;
static const int PIN_SCL = 22;

// ── nanobyte-proto constants — MUST match nanobyte-core/src/lib.rs ───────
static const uint8_t MAGIC0 = 0x4E;
static const uint8_t MAGIC1 = 0xB0;
static const uint8_t PROTOCOL_VERSION = 0x01;
static const uint8_t KIND_BME280 = 0x10;

// Board identity. Top byte is the "cassette" = 0x01 ("ESP32-WROOM batch").
// Low 16 bits = 1 for now; if you have more than one board, bump this per board.
static const uint32_t MOTE_ID = 0x00010001UL;

// ── State ────────────────────────────────────────────────────────────────
Adafruit_BME280 bme;
uint16_t g_seq = 0;
unsigned long g_last_emit_ms = 0;
float g_last_temp = 0.0f;
unsigned long g_last_temp_ms = 0;

// ── CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF, no reflect) ─────────────
// Matches Rust `crc::CRC_16_IBM_3740` used by nanobyte-proto.
static uint16_t crc16_ccitt_false(const uint8_t *data, size_t len) {
  uint16_t crc = 0xFFFF;
  for (size_t i = 0; i < len; i++) {
    crc ^= ((uint16_t)data[i]) << 8;
    for (int b = 0; b < 8; b++) {
      if (crc & 0x8000) { crc = (crc << 1) ^ 0x1021; }
      else              { crc = (crc << 1); }
    }
  }
  return crc;
}

// ── Trivial 4-way classifier ─────────────────────────────────────────────
// Matches Classification enum: Null(0), C1(1), C2(2), C3(3).
// Block 0.0 mapping for BME280:
//   Null        — stable conditions
//   C1 (=1)     — humidity > 70 %
//   C2 (=2)     — temp rising > 0.5 °C/s
//   C3 (=3)     — pressure dropped > 1 hPa in last reading (storm incoming)
// Real BNN replaces this in Block 0.2.
static uint8_t classify(float temp_c, float humidity_pct, float pressure_hpa) {
  unsigned long now = millis();

  // C2: temperature-rate spike
  if (g_last_temp_ms != 0) {
    float dt_s = (now - g_last_temp_ms) / 1000.0f;
    if (dt_s > 0.0f) {
      float rate = (temp_c - g_last_temp) / dt_s;
      if (rate > 0.5f) {
        g_last_temp = temp_c;
        g_last_temp_ms = now;
        return 2;
      }
    }
  }
  g_last_temp = temp_c;
  g_last_temp_ms = now;

  // C1: high humidity
  if (humidity_pct > 70.0f) return 1;

  // C3 would need a rolling pressure baseline — Block 0.1 feature.

  return 0; // Null / heartbeat (P30: emit even when nothing interesting)
}

// ── Emit one telemetry frame as a hex-encoded line ───────────────────────
static void emit_frame(float temp_c, float humidity_pct, float pressure_hpa) {
  // Build 15-byte payload
  int16_t  temp_c100      = (int16_t)(temp_c * 100.0f);
  uint16_t humidity_x100  = (uint16_t)constrain(humidity_pct * 100.0f, 0.0f, 65535.0f);
  uint16_t pressure_x10   = (uint16_t)constrain(pressure_hpa * 10.0f,  0.0f, 65535.0f);
  uint8_t  cls            = classify(temp_c, humidity_pct, pressure_hpa);

  uint8_t payload[15];
  payload[0]  = (MOTE_ID >> 24) & 0xFF;
  payload[1]  = (MOTE_ID >> 16) & 0xFF;
  payload[2]  = (MOTE_ID >>  8) & 0xFF;
  payload[3]  = (MOTE_ID      ) & 0xFF;
  payload[4]  = (g_seq >> 8) & 0xFF;
  payload[5]  = (g_seq     ) & 0xFF;
  payload[6]  = cls;
  payload[7]  = 0;   // confidence — placeholder
  payload[8]  = 33;  // cap_mv_over_10 — fake 3.3 V rail
  payload[9]  = (temp_c100 >> 8) & 0xFF;
  payload[10] = (temp_c100     ) & 0xFF;
  payload[11] = (humidity_x100 >> 8) & 0xFF;
  payload[12] = (humidity_x100     ) & 0xFF;
  payload[13] = (pressure_x10 >> 8) & 0xFF;
  payload[14] = (pressure_x10     ) & 0xFF;

  // Build 8-byte header
  uint8_t header[8];
  header[0] = MAGIC0;
  header[1] = MAGIC1;
  header[2] = PROTOCOL_VERSION;
  header[3] = KIND_BME280;
  header[4] = (g_seq >> 8) & 0xFF;
  header[5] = (g_seq     ) & 0xFF;
  header[6] = (sizeof(payload) >> 8) & 0xFF;
  header[7] = (sizeof(payload)     ) & 0xFF;

  // CRC-16 over payload only (matches nanobyte-proto Rust implementation)
  uint16_t crc = crc16_ccitt_false(payload, sizeof(payload));
  uint8_t crc_bytes[2] = { (uint8_t)(crc >> 8), (uint8_t)(crc & 0xFF) };

  // Emit hex-encoded line: header + payload + crc
  auto hex2 = [](uint8_t b) {
    const char *h = "0123456789abcdef";
    char out[3] = { h[(b >> 4) & 0xF], h[b & 0xF], 0 };
    Serial.print(out);
  };
  for (size_t i = 0; i < sizeof(header); i++)  hex2(header[i]);
  for (size_t i = 0; i < sizeof(payload); i++) hex2(payload[i]);
  for (size_t i = 0; i < sizeof(crc_bytes); i++) hex2(crc_bytes[i]);
  Serial.println();

  g_seq++;
}

void setup() {
  Serial.begin(115200);
  while (!Serial && millis() < 2000) { /* wait briefly for USB serial */ }
  Serial.println("# nanobyte-mote esp32-wroom-bme280 Block 0.0 booting");

  Wire.begin(PIN_SDA, PIN_SCL);

  // Auto-detect BME280 I²C address (0x76 default, 0x77 some breakouts).
  bool ok = bme.begin(0x76);
  if (!ok) ok = bme.begin(0x77);
  if (!ok) {
    Serial.println("# ERROR: BME280 not found at 0x76 or 0x77");
    Serial.println("# Check wiring: VCC→3V3, GND→GND, SDA→GPIO21, SCL→GPIO22");
    while (1) { delay(1000); }
  }

  Serial.print("# BME280 found at 0x");
  Serial.println(bme.sensorID() ? "77" : "76"); // rough — Adafruit lib stores addr internally
  Serial.println("# emitting nanobyte-proto frames at 1 Hz over Serial @ 115200");
}

void loop() {
  unsigned long now = millis();
  if (now - g_last_emit_ms < 1000) { delay(20); return; }
  g_last_emit_ms = now;

  float t = bme.readTemperature();      // °C
  float h = bme.readHumidity();          // %
  float p = bme.readPressure() / 100.0f; // Pa → hPa

  if (isnan(t) || isnan(h) || isnan(p)) {
    Serial.println("# WARN: BME280 read returned NaN — skipping frame");
    return;
  }

  emit_frame(t, h, p);
}
