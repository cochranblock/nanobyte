//! nanobyte-test — single staged test binary. P16: CI = Test Binary.
//!
//! Exit 0 on pass, 1 on first failing stage. Prints a one-line result per
//! stage so downstream log parsers (and humans) can read the result
//! without opening a test harness.
//!
//! Block 0.0 stages: compile (implicit), unit (roundtrips), protocol
//! (encode/decode), sim-smoke (build + run frame emit).
//! Block 0.1+ adds: integration (hive ↔ sim transport), HIL loop (real
//! hardware test), fuzz (randomized proto corruption).

use anyhow::{anyhow, Result};
use nanobyte_core::{Classification, MoteId, PROTOCOL_VERSION};
use nanobyte_mote::{build_frame, Classifier, MoteIdentity, NullClassifier, SensorSample};
use nanobyte_proto::{decode, encode, kind, Header};

fn stage_unit() -> Result<()> {
    // Classification roundtrip — the known-good sanity check.
    for c in [
        Classification::Null,
        Classification::Platinum,
        Classification::Water,
        Classification::Metallic,
    ] {
        if Classification::from_u8(c as u8) != c {
            return Err(anyhow!("classification roundtrip failed for {:?}", c));
        }
    }

    // MoteId cassette/serial split — verifies the compression layout.
    let id = MoteId(0x00_2A_C3_04);
    if id.cassette() != 0x2A || id.serial() != 0xC304 {
        return Err(anyhow!("MoteId split broken"));
    }

    // Mote frame-build roundtrip — verifies mote → core integration.
    let identity = MoteIdentity {
        id: MoteId(0x0001_0000),
        seq: 5,
        bnn_version: 0,
    };
    let sample = SensorSample {
        photodiode: [0, 0, 0, 0],
        temp_c100: 2500,
        hall: 0,
        cap_mv_over_10: 33,
    };
    let cls = NullClassifier.classify(&sample);
    let frame = build_frame(&identity, &sample, cls);
    if frame.class != Classification::Null || frame.seq != 5 {
        return Err(anyhow!("mote frame build broken"));
    }
    Ok(())
}

fn stage_protocol() -> Result<()> {
    // Heartbeat encode → decode → match.
    let h = Header {
        version: PROTOCOL_VERSION,
        payload_kind: kind::HEARTBEAT,
        seq: 0xABCD,
        payload_len: 0,
    };
    let bytes = encode(h, &[]);
    let (parsed, payload) = decode(&bytes).map_err(|e| anyhow!("decode failed: {}", e))?;
    if parsed != h || !payload.is_empty() {
        return Err(anyhow!("heartbeat roundtrip drifted"));
    }

    // Telemetry with payload.
    let h2 = Header {
        version: PROTOCOL_VERSION,
        payload_kind: kind::TELEMETRY,
        seq: 1,
        payload_len: 4,
    };
    let payload = [0xDE, 0xAD, 0xBE, 0xEF];
    let bytes = encode(h2, &payload);
    let (parsed, got) = decode(&bytes).map_err(|e| anyhow!("telemetry decode: {}", e))?;
    if parsed != h2 || got != payload {
        return Err(anyhow!("telemetry roundtrip drifted"));
    }

    // Corrupted CRC must be rejected.
    let mut bad = encode(h2, &payload);
    bad[10] ^= 0x01;
    if decode(&bad).is_ok() {
        return Err(anyhow!("crc corruption not detected"));
    }
    Ok(())
}

fn run_stage<F: FnOnce() -> Result<()>>(name: &str, f: F) -> Result<()> {
    match f() {
        Ok(()) => {
            println!("[PASS] {name}");
            Ok(())
        }
        Err(e) => {
            println!("[FAIL] {name}: {e}");
            Err(e)
        }
    }
}

fn main() {
    println!("nanobyte-test — Block 0.0 stages");
    let stages: Vec<(&str, fn() -> Result<()>)> =
        vec![("unit", stage_unit), ("protocol", stage_protocol)];
    for (name, f) in stages {
        if run_stage(name, f).is_err() {
            std::process::exit(1);
        }
    }
    println!("[ALL PASS] nanobyte-test Block 0.0");
}
