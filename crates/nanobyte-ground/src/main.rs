//! nanobyte-ground — mission control plane.
//!
//! Block 0.0: serves a placeholder HTML page at http://localhost:4000/
//! that confirms the binary built and the protocol constants resolve.
//! Block 0.1 adds the swarm-map renderer + uplink composer.

use anyhow::Result;
use axum::{routing::get, Router};
use clap::Parser;
use nanobyte_core::{FRAME_MAGIC, PROTOCOL_VERSION};
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "nanobyte-ground", version, about = "NANOBYTE ground control")]
struct Args {
    /// Bind address for the local dashboard.
    #[arg(long, default_value = "127.0.0.1:4000")]
    bind: String,
}

async fn index() -> axum::response::Html<String> {
    let body = format!(
        "<!doctype html>\n<html><head><title>NANOBYTE ground</title></head>\n<body style=\"font-family:monospace;padding:2rem\">\n<h1>NANOBYTE ground — Block 0.0</h1>\n<p>Mission plan: <code>~/.claude/plans/shotgun-nanobyte-sensor-swarm.plan.md</code></p>\n<table><tr><td>Protocol version</td><td>0x{:02X}</td></tr><tr><td>Frame magic</td><td>0x{:02X}{:02X}</td></tr><tr><td>Ground binary version</td><td>{}</td></tr></table>\n<p>Block 0.1 wires the swarm map + uplink composer.</p>\n</body></html>",
        PROTOCOL_VERSION,
        FRAME_MAGIC[0],
        FRAME_MAGIC[1],
        env!("CARGO_PKG_VERSION"),
    );
    axum::response::Html(body)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args = Args::parse();
    let app = Router::new().route("/", get(index));
    info!(
        "nanobyte-ground v{} — Block 0.0 listening on http://{}",
        env!("CARGO_PKG_VERSION"),
        args.bind
    );
    let listener = tokio::net::TcpListener::bind(&args.bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
