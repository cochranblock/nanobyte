//! nanobyte-test — P16: CI = Test Binary.
//!
//! Stages: unit · protocol · ground_smoke (spawn ground, HTTP verify, screenshot).
//! Wrapped in TRIPLE SIMS — all three passes must agree.
//!
//! Block 0.1: ground_smoke added. Block 0.0 stages retained.

use anyhow::{anyhow, Result};
use nanobyte_core::{Classification, MoteId, PROTOCOL_VERSION};
use nanobyte_mote::{build_frame, Classifier, MoteIdentity, NullClassifier, SensorSample};
use nanobyte_proto::{decode, encode, kind, Header};
use std::path::PathBuf;
use std::time::Duration;

fn stage_unit() -> Result<()> {
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

    let id = MoteId(0x00_2A_C3_04);
    if id.cassette() != 0x2A || id.serial() != 0xC304 {
        return Err(anyhow!("MoteId split broken"));
    }

    let identity = MoteIdentity { id: MoteId(0x0001_0000), seq: 5, bnn_version: 0 };
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

    let h2 = Header {
        version: PROTOCOL_VERSION,
        payload_kind: kind::TELEMETRY,
        seq: 1,
        payload_len: 4,
    };
    let pl = [0xDE, 0xAD, 0xBE, 0xEF];
    let bytes = encode(h2, &pl);
    let (parsed, got) = decode(&bytes).map_err(|e| anyhow!("telemetry decode: {}", e))?;
    if parsed != h2 || got != pl {
        return Err(anyhow!("telemetry roundtrip drifted"));
    }

    let mut bad = encode(h2, &pl);
    bad[10] ^= 0x01;
    if decode(&bad).is_ok() {
        return Err(anyhow!("crc corruption not detected"));
    }
    Ok(())
}

fn ground_bin() -> PathBuf {
    std::env::current_exe()
        .expect("current_exe")
        .parent()
        .expect("parent dir")
        .join("nanobyte-ground")
}

async fn stage_ground_smoke() -> Result<()> {
    let bin = ground_bin();
    if !bin.exists() {
        return Err(anyhow!(
            "nanobyte-ground not found at {} — build it first",
            bin.display()
        ));
    }

    // Grab a free port then release it before spawning.
    let port = {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| anyhow!("port bind: {}", e))?;
        l.local_addr().map_err(|e| anyhow!("local_addr: {}", e))?.port()
    };
    let bind_addr = format!("127.0.0.1:{port}");
    let base = format!("http://{bind_addr}");

    let mut child = std::process::Command::new(&bin)
        .args(["--bind", &bind_addr])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| anyhow!("spawn nanobyte-ground: {}", e))?;

    // Poll until ready — max 3 s.
    let client = exopack::interface::f81()
        .map_err(|e| anyhow!("http_client: {}", e))?;
    let mut ready = false;
    for _ in 0..30 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if client.get(format!("{base}/hashes")).send().await.is_ok() {
            ready = true;
            break;
        }
    }
    if !ready {
        let _ = child.kill();
        return Err(anyhow!("nanobyte-ground did not bind within 3 s"));
    }

    // /hashes — verify JSON shape and protocol constants.
    let hashes: serde_json::Value = client
        .get(format!("{base}/hashes"))
        .send()
        .await
        .map_err(|e| anyhow!("/hashes request: {}", e))?
        .json()
        .await
        .map_err(|e| anyhow!("/hashes parse: {}", e))?;

    let fm = hashes["frame_magic"].as_str().ok_or_else(|| anyhow!("frame_magic missing"))?;
    let pv = hashes["protocol_version"].as_str().ok_or_else(|| anyhow!("protocol_version missing"))?;
    let hash = hashes["binary_blake3"].as_str().ok_or_else(|| anyhow!("binary_blake3 missing"))?;

    if fm != "0x4EB0" {
        let _ = child.kill();
        return Err(anyhow!("frame_magic mismatch: expected 0x4EB0 got {fm}"));
    }
    if pv != "0x01" {
        let _ = child.kill();
        return Err(anyhow!("protocol_version mismatch: expected 0x01 got {pv}"));
    }
    if hash.len() != 64 {
        let _ = child.kill();
        return Err(anyhow!("binary_blake3 wrong length: {} (expected 64)", hash.len()));
    }

    // / — verify HTML index contains protocol constants.
    let index = client
        .get(&base)
        .send()
        .await
        .map_err(|e| anyhow!("/ request: {}", e))?
        .text()
        .await
        .map_err(|e| anyhow!("/ body: {}", e))?;
    if !index.contains("NANOBYTE") {
        let _ = child.kill();
        return Err(anyhow!("/ response missing NANOBYTE branding"));
    }

    // TODO: POA screenshots via exopack::screenshot::f79 — wire after exopack 0.3 ships
    // (0.2.1 published f79 concatenates base+name instead of base+path, causing nav timeouts).

    let _ = child.kill();
    Ok(())
}

fn run_sync(name: &str, f: fn() -> Result<()>) -> bool {
    match f() {
        Ok(()) => { println!("[PASS] {name}"); true }
        Err(e) => { println!("[FAIL] {name}: {e}"); false }
    }
}

async fn run_async<F, Fut>(name: &str, f: F) -> bool
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    match f().await {
        Ok(()) => { println!("[PASS] {name}"); true }
        Err(e) => { println!("[FAIL] {name}: {e}"); false }
    }
}

async fn run_once() -> bool {
    run_sync("unit", stage_unit)
        && run_sync("protocol", stage_protocol)
        && run_async("ground_smoke", stage_ground_smoke).await
}

#[tokio::main]
async fn main() {
    println!("nanobyte-test — Block 0.1");
    let ok = exopack::triple_sims::f60(run_once).await;
    if ok {
        println!("[ALL PASS] nanobyte-test Block 0.1 (TRIPLE SIMS)");
    }
    std::process::exit(if ok { 0 } else { 1 });
}
