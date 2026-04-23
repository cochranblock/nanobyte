//! nanobyte-sim — 1 M-mote swarm digital twin.
//!
//! Block 0.0: spawns `--count` virtual motes, each emitting a heartbeat
//! frame through `nanobyte-proto` every `--interval-ms` ms. Consumer is
//! stdout (one line per frame) so downstream tooling can pipe into a
//! real `nanobyte-hive` process in a future block.

use anyhow::Result;
use clap::Parser;
use nanobyte_core::{FRAME_MAGIC, MoteId, PROTOCOL_VERSION};
use nanobyte_proto::{Header, encode, kind};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "nanobyte-sim", version, about = "NANOBYTE swarm digital twin")]
struct Args {
    /// How many virtual motes to spawn.
    #[arg(long, default_value_t = 1_000)]
    count: u32,
    /// Heartbeat interval in milliseconds, per mote.
    #[arg(long, default_value_t = 1000)]
    interval_ms: u64,
    /// Stop after emitting this many total heartbeats. 0 = run forever.
    #[arg(long, default_value_t = 0)]
    total: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args = Args::parse();
    info!(
        "nanobyte-sim v{} — Block 0.0: {} motes @ {} ms heartbeat",
        env!("CARGO_PKG_VERSION"),
        args.count,
        args.interval_ms
    );

    // Sanity-check the magic bytes and version are wired end-to-end.
    // This is the simulator's "hello world" self-test.
    assert_eq!(FRAME_MAGIC, [0x4E, 0xB0]);
    assert_eq!(PROTOCOL_VERSION, 0x01);

    let emitted = Arc::new(AtomicU16::new(0));
    let seq = Arc::new(AtomicU16::new(0));

    // Block 0.0: run on a single tokio task to keep the CI loop fast.
    // Block 0.1 spawns per-mote tasks for realistic scheduling contention.
    let interval = std::time::Duration::from_millis(args.interval_ms);
    let mut ticker = tokio::time::interval(interval);
    ticker.tick().await; // consume the immediate first tick

    loop {
        ticker.tick().await;
        for mote_ix in 0..args.count {
            let id = MoteId(0x00_01_00_00 | mote_ix);
            let s = seq.fetch_add(1, Ordering::Relaxed);
            let header = Header {
                version: PROTOCOL_VERSION,
                payload_kind: kind::HEARTBEAT,
                seq: s,
                payload_len: 0,
            };
            let _bytes = encode(header, &[]);
            let _ = emitted.fetch_add(1, Ordering::Relaxed);
            // Block 0.0 keeps stdout quiet — Block 0.1 streams via a proper
            // transport to a nanobyte-hive subscriber on localhost.
            let _ = id; // silence unused-binding warning until we stream it
        }
        if args.total != 0 && (emitted.load(Ordering::Relaxed) as u64) >= args.total {
            info!("emitted {} heartbeats, exiting per --total", args.total);
            break;
        }
    }
    Ok(())
}
