//! nanobyte-ground-serial — Block 0.0 desk-mote demo companion.
//!
//! Opens a USB-serial port, reads line-delimited hex-encoded `nanobyte-proto`
//! frames emitted by the ESP32-WROOM + BME280 sketch, decodes them, stores
//! the most recent N frames in an in-memory ring buffer, and serves a live
//! dashboard at http://localhost:4000/.
//!
//! Lines beginning with `#` are treated as device-side debug output and
//! echoed to the local log at DEBUG level rather than parsed as frames.
//!
//! Usage:
//!     nanobyte-ground-serial --port /dev/cu.usbserial-0001
//!     nanobyte-ground-serial --port /dev/cu.usbserial-0001 --bind 0.0.0.0:4000

use anyhow::{Context, Result};
use axum::{extract::State, response::Html, routing::get, Router};
use clap::Parser;
use nanobyte_proto::decode;
use std::collections::VecDeque;
use std::io::{BufRead, BufReader};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

const KIND_BME280: u8 = 0x10;
const RING_SIZE: usize = 120;

/// Decoded + application-interpreted frame for the dashboard.
#[derive(Clone, Debug)]
struct DeskFrame {
    received: Instant,
    seq: u16,
    mote_id: u32,
    class: u8,
    cap_mv_over_10: u8,
    temp_c: f32,
    humidity_pct: f32,
    pressure_hpa: f32,
}

impl DeskFrame {
    /// Parse the 15-byte payload defined in the ESP32 sketch.
    fn parse_payload(seq: u16, payload: &[u8]) -> Option<Self> {
        if payload.len() != 15 {
            return None;
        }
        let mote_id = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        // payload[4..6] = seq echo, already have it from header
        let class = payload[6];
        let cap_mv_over_10 = payload[8];
        let temp_c100 = i16::from_be_bytes([payload[9], payload[10]]);
        let humidity_x100 = u16::from_be_bytes([payload[11], payload[12]]);
        let pressure_x10 = u16::from_be_bytes([payload[13], payload[14]]);
        Some(Self {
            received: Instant::now(),
            seq,
            mote_id,
            class,
            cap_mv_over_10,
            temp_c: temp_c100 as f32 / 100.0,
            humidity_pct: humidity_x100 as f32 / 100.0,
            pressure_hpa: pressure_x10 as f32 / 10.0,
        })
    }
}

#[derive(Default)]
struct AppState {
    ring: Mutex<VecDeque<DeskFrame>>,
    total_frames: Mutex<u64>,
    total_bad: Mutex<u64>,
    port_path: String,
}

#[derive(Parser, Debug)]
#[command(
    name = "nanobyte-ground-serial",
    version,
    about = "NANOBYTE serial listener — ESP32-WROOM desk-mote demo"
)]
struct Args {
    /// Serial port path (e.g. /dev/cu.usbserial-0001 on macOS).
    #[arg(long)]
    port: String,
    /// Baud rate — must match the sketch (115200).
    #[arg(long, default_value_t = 115200)]
    baud: u32,
    /// HTTP dashboard bind address.
    #[arg(long, default_value = "127.0.0.1:4000")]
    bind: String,
}

fn class_label(c: u8) -> &'static str {
    match c {
        0 => "null (heartbeat)",
        1 => "C1 · humid",
        2 => "C2 · warming",
        3 => "C3 · pressure-drop",
        _ => "unknown",
    }
}

async fn dashboard(State(state): State<Arc<AppState>>) -> Html<String> {
    let ring = state.ring.lock().unwrap().clone();
    let total_frames = *state.total_frames.lock().unwrap();
    let total_bad = *state.total_bad.lock().unwrap();

    let mut rows = String::new();
    for f in ring.iter().rev() {
        let age_ms = f.received.elapsed().as_millis();
        rows.push_str(&format!(
            "<tr><td>{}</td><td>0x{:08X}</td><td>{}</td><td>{:.2}</td><td>{:.1}</td><td>{:.1}</td><td>{} ms</td></tr>",
            f.seq,
            f.mote_id,
            class_label(f.class),
            f.temp_c,
            f.humidity_pct,
            f.pressure_hpa,
            age_ms,
        ));
    }
    if rows.is_empty() {
        rows.push_str("<tr><td colspan=\"7\" style=\"opacity:0.6;font-style:italic\">waiting for first frame from the ESP32…</td></tr>");
    }

    let html = format!(
        "<!doctype html>\n<html><head>\n<title>NANOBYTE desk-mote</title>\n<meta http-equiv=\"refresh\" content=\"1\">\n<style>\nbody {{ font-family: -apple-system, monospace; padding: 2rem; max-width: 900px; margin: 0 auto; }}\ntable {{ border-collapse: collapse; width: 100%; margin-top: 1rem; }}\nth, td {{ padding: 0.4rem 0.6rem; text-align: left; border-bottom: 1px solid #ccc; font-size: 0.9rem; }}\nth {{ background: #f3f3f3; }}\n.meta {{ opacity: 0.7; font-size: 0.85rem; }}\n</style>\n</head>\n<body>\n<h1>NANOBYTE — desk-mote</h1>\n<p class=\"meta\">ESP32-WROOM + BME280 over USB serial → nanobyte-proto → this page. Auto-refresh 1 s.</p>\n<p class=\"meta\">Serial: <code>{port}</code> · frames decoded: <strong>{total_frames}</strong> · bad lines: <strong>{total_bad}</strong></p>\n<table><tr><th>seq</th><th>mote_id</th><th>class</th><th>°C</th><th>%RH</th><th>hPa</th><th>age</th></tr>{rows}</table>\n<p class=\"meta\" style=\"margin-top:2rem\">Mission plan: <code>~/.claude/plans/shotgun-nanobyte-sensor-swarm.plan.md</code></p>\n</body></html>",
        port = state.port_path,
        total_frames = total_frames,
        total_bad = total_bad,
        rows = rows,
    );
    Html(html)
}

/// Blocking serial-read loop. Runs on a dedicated OS thread so axum's tokio
/// runtime stays unblocked. Pushes parsed frames into the shared ring buffer.
fn serial_loop(port_path: String, baud: u32, state: Arc<AppState>) -> Result<()> {
    let port = serialport::new(&port_path, baud)
        .timeout(Duration::from_secs(2))
        .open()
        .with_context(|| format!("opening serial port {}", port_path))?;
    info!("serial listener opened {} @ {} baud", port_path, baud);

    let mut reader = BufReader::new(port);
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => {
                // EOF on serial is unusual — likely unplug. Small backoff, retry.
                warn!("serial eof, sleeping 1 s");
                std::thread::sleep(Duration::from_secs(1));
                continue;
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                continue;
            }
            Err(e) => {
                warn!("serial read error: {} — retrying in 1 s", e);
                std::thread::sleep(Duration::from_secs(1));
                continue;
            }
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with('#') {
            debug!("device: {}", &trimmed[1..].trim());
            continue;
        }
        // Hex decode.
        let bytes = match hex::decode(trimmed) {
            Ok(b) => b,
            Err(e) => {
                debug!("non-hex line ({} chars): {}", trimmed.len(), e);
                *state.total_bad.lock().unwrap() += 1;
                continue;
            }
        };
        match decode(&bytes) {
            Ok((header, payload)) => {
                if header.payload_kind != KIND_BME280 {
                    debug!("unexpected kind 0x{:02x}; ignoring", header.payload_kind);
                    continue;
                }
                match DeskFrame::parse_payload(header.seq, payload) {
                    Some(f) => {
                        let mut ring = state.ring.lock().unwrap();
                        if ring.len() == RING_SIZE {
                            ring.pop_front();
                        }
                        ring.push_back(f);
                        *state.total_frames.lock().unwrap() += 1;
                    }
                    None => {
                        warn!("payload wrong size: {} bytes", payload.len());
                        *state.total_bad.lock().unwrap() += 1;
                    }
                }
            }
            Err(e) => {
                debug!("proto decode failed: {}", e);
                *state.total_bad.lock().unwrap() += 1;
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let args = Args::parse();
    let state = Arc::new(AppState {
        ring: Mutex::new(VecDeque::with_capacity(RING_SIZE)),
        total_frames: Mutex::new(0),
        total_bad: Mutex::new(0),
        port_path: args.port.clone(),
    });

    // Dedicate an OS thread to the blocking serial read so the async
    // runtime only handles HTTP.
    let serial_state = state.clone();
    let port = args.port.clone();
    std::thread::spawn(move || {
        if let Err(e) = serial_loop(port, args.baud, serial_state) {
            tracing::error!("serial loop exited: {:?}", e);
        }
    });

    let app = Router::new().route("/", get(dashboard)).with_state(state);
    info!("http://{} — serial {} @ {} baud", args.bind, args.port, args.baud);
    let listener = tokio::net::TcpListener::bind(&args.bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
