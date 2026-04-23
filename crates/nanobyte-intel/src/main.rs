//! nanobyte-intel — web-traffic intel for cochranblock.org.
//!
//! Single embedded Rust binary. No sqlite, no external DB. sled storage,
//! bincode encoding, zstd compression. Reads approuter-acme.log for probe
//! events (failed TLS handshakes with real client IPs — what free-tier CF
//! GraphQL won't show you), indexes them, and answers the intel questions
//! you'd otherwise pay $25/mo for CF Pro to get.
//!
//! Subcommands (P13 tokenized aliases in parens):
//!   ingest <file>       (i0)  parse an approuter-acme log, add to sled store
//!   stats                (i1)  summary: total probes, unique IPs, time range
//!   top [N]              (i2)  top N client IPs by probe count
//!   asns [N]             (i3)  top N ASNs (Team Cymru DNS lookup, cached)
//!   ip <IP>              (i4)  timeline + count for one IP
//!   dwell [--min-hits N] (i5)  IPs with sustained probing — meeting-pattern candidates

use anyhow::{anyhow, Context, Result};
use bincode::config::standard as bincode_std;
use bincode::serde::{decode_from_slice, encode_to_vec};
use clap::{Parser, Subcommand};
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::path::PathBuf;
use tracing::info;

// ── Event model ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeEvent {
    /// Seconds since unix epoch.
    pub ts_unix: i64,
    /// Client IP from the TLS accept path (real, not CF edge).
    pub ip: IpAddr,
    /// Coarse classification of what went wrong — tells us which tool
    /// fingerprinted us.
    pub reason: ProbeReason,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProbeReason {
    /// rustls rejected because the client didn't send the extension.
    /// Older TLS libs and many stripped-down scanners fail this way.
    SigAlgRequired,
    /// Corrupt record of InvalidContentType — scanner sending raw HTTP
    /// or a bad protocol negotiation.
    InvalidContentType,
    /// EOF during handshake — scanner hung up mid-way or probe is a
    /// connect-only-no-TLS probe.
    HandshakeEof,
    /// Anything we don't recognize yet. String is truncated (<=80 chars).
    Other(String),
}

impl ProbeReason {
    pub fn from_line(s: &str) -> Self {
        if s.contains("SignatureAlgorithmsExtensionRequired") {
            Self::SigAlgRequired
        } else if s.contains("InvalidContentType") {
            Self::InvalidContentType
        } else if s.contains("tls handshake eof") {
            Self::HandshakeEof
        } else {
            let trimmed: String = s.chars().take(80).collect();
            Self::Other(trimmed)
        }
    }
    pub fn label(&self) -> &'static str {
        match self {
            Self::SigAlgRequired => "sigalg-required",
            Self::InvalidContentType => "invalid-content-type",
            Self::HandshakeEof => "handshake-eof",
            Self::Other(_) => "other",
        }
    }
}

// ── Access-log model (approuter t40 schema) ─────────────────────────────
//
// approuter already emits one JSONL line per request to ~/approuter/analytics/
// events_*.jsonl. IP is privacy-hashed as `ip_hash` (12-hex-char string). We
// treat that hash as the "pseudonymous IP" — same visitor → same hash. Good
// enough for dwell/session/path analysis; ASN/geo of CF-fronted traffic lives
// outside our reach regardless.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessEvent {
    pub ts_unix: i64,
    pub host: String,
    pub path: String,
    pub method: String,
    pub status: u16,
    pub duration_ms: u64,
    pub country: String,
    pub city: String,
    pub region: String,
    pub ua_family: String,
    pub is_bot: bool,
    /// The hashed client IP from approuter (12 hex chars). Stable per visitor.
    pub ip_hash: String,
}

// ── Geo cache (ip-api.com free batch) ───────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GeoInfo {
    pub country: String,
    pub country_code: String,
    pub region: String,
    pub city: String,
    pub isp: String,
    pub org: String,
    /// "AS15169 Google LLC" combined field from ip-api
    pub as_field: String,
    /// Unix-seconds of the lookup — geo changes rarely, 30-day TTL.
    pub looked_up_at: i64,
}

// ── Storage ─────────────────────────────────────────────────────────────
// Layout (IP is the primary key for all traffic intel):
//   tree "probes"     — key = 8-byte BE unix-seconds || 4-byte seq  (chrono-sorted)
//                       val = zstd(bincode(ProbeEvent))
//   tree "access"     — key = 8-byte BE unix-seconds || 4-byte seq
//                       val = zstd(bincode(AccessEvent))
//   tree "asn_cache"  — key = ip string bytes
//                       val = zstd(bincode(AsnInfo))
//   tree "geo_cache"  — key = ip string bytes
//                       val = zstd(bincode(GeoInfo))

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AsnInfo {
    pub asn: u32,
    pub country: String,
    pub org: String,
    /// Unix-seconds of the lookup so we can expire old entries.
    pub looked_up_at: i64,
}

pub struct Store {
    db: sled::Db,
    probes: sled::Tree,
    access: sled::Tree,
    asn_cache: sled::Tree,
    geo_cache: sled::Tree,
}

impl Store {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let db = sled::open(path.into()).context("open sled")?;
        let probes = db.open_tree("probes")?;
        let access = db.open_tree("access")?;
        let asn_cache = db.open_tree("asn_cache")?;
        let geo_cache = db.open_tree("geo_cache")?;
        Ok(Self { db, probes, access, asn_cache, geo_cache })
    }

    pub fn insert_access(&self, seq: u32, ev: &AccessEvent) -> Result<()> {
        let mut key = [0u8; 12];
        key[..8].copy_from_slice(&ev.ts_unix.to_be_bytes());
        key[8..].copy_from_slice(&seq.to_be_bytes());
        let raw = encode_to_vec(ev, bincode_std())?;
        let comp = zstd::encode_all(&raw[..], 3)?;
        self.access.insert(key, comp)?;
        Ok(())
    }

    pub fn iter_access(&self) -> impl Iterator<Item = Result<AccessEvent>> + '_ {
        self.access.iter().map(|r| {
            let (_, v) = r?;
            let raw = zstd::decode_all(&v[..])?;
            let (ev, _): (AccessEvent, _) = decode_from_slice(&raw, bincode_std())?;
            Ok(ev)
        })
    }

    pub fn access_count(&self) -> usize {
        self.access.len()
    }

    pub fn get_geo(&self, ip: &IpAddr) -> Result<Option<GeoInfo>> {
        let key = ip.to_string().into_bytes();
        match self.geo_cache.get(&key)? {
            None => Ok(None),
            Some(v) => {
                let raw = zstd::decode_all(&v[..])?;
                let (gi, _): (GeoInfo, _) = decode_from_slice(&raw, bincode_std())?;
                Ok(Some(gi))
            }
        }
    }

    pub fn put_geo(&self, ip: &IpAddr, gi: &GeoInfo) -> Result<()> {
        let key = ip.to_string().into_bytes();
        let raw = encode_to_vec(gi, bincode_std())?;
        let comp = zstd::encode_all(&raw[..], 3)?;
        self.geo_cache.insert(key, comp)?;
        Ok(())
    }

    pub fn insert_probe(&self, seq: u32, ev: &ProbeEvent) -> Result<()> {
        let mut key = [0u8; 12];
        key[..8].copy_from_slice(&ev.ts_unix.to_be_bytes());
        key[8..].copy_from_slice(&seq.to_be_bytes());
        let raw = encode_to_vec(ev, bincode_std())?;
        let comp = zstd::encode_all(&raw[..], 3)?;
        self.probes.insert(key, comp)?;
        Ok(())
    }

    pub fn iter_probes(&self) -> impl Iterator<Item = Result<ProbeEvent>> + '_ {
        self.probes.iter().map(|r| {
            let (_, v) = r?;
            let raw = zstd::decode_all(&v[..])?;
            let (ev, _): (ProbeEvent, _) = decode_from_slice(&raw, bincode_std())?;
            Ok(ev)
        })
    }

    pub fn probe_count(&self) -> usize {
        self.probes.len()
    }

    pub fn get_asn(&self, ip: &IpAddr) -> Result<Option<AsnInfo>> {
        let key = ip.to_string().into_bytes();
        match self.asn_cache.get(&key)? {
            None => Ok(None),
            Some(v) => {
                let raw = zstd::decode_all(&v[..])?;
                let (ai, _): (AsnInfo, _) = decode_from_slice(&raw, bincode_std())?;
                Ok(Some(ai))
            }
        }
    }

    pub fn put_asn(&self, ip: &IpAddr, ai: &AsnInfo) -> Result<()> {
        let key = ip.to_string().into_bytes();
        let raw = encode_to_vec(ai, bincode_std())?;
        let comp = zstd::encode_all(&raw[..], 3)?;
        self.asn_cache.insert(key, comp)?;
        Ok(())
    }

    pub fn flush(&self) -> Result<()> {
        self.db.flush()?;
        Ok(())
    }
}

// ── Log parsing ─────────────────────────────────────────────────────────
// approuter-acme emits ANSI-colored tracing output. We strip the color
// codes before matching. Example line:
//   [2m2026-04-14T17:59:44.1Z[0m [33mWARN[0m [2mapprouter_acme::proxy[0m[2m:[0m tls accept from 194.36.25.40:51234: received corrupt message of type InvalidContentType

fn strip_ansi(s: &str) -> String {
    // A tight, allocation-light ANSI-color stripper. We only remove CSI
    // sequences of the form ESC [ ... m — enough for `tracing` output.
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            if let Some('[') = chars.peek() {
                chars.next();
                while let Some(c2) = chars.next() {
                    if c2 == 'm' || c2 == 'K' {
                        break;
                    }
                }
                continue;
            }
        }
        out.push(c);
    }
    out
}

fn parse_line(raw: &str) -> Option<(i64, IpAddr, ProbeReason)> {
    let s = strip_ansi(raw);
    let ts_end = s.find('Z')?;
    let ts_str = &s[..=ts_end];
    let ts_unix = parse_rfc3339_to_unix(ts_str)?;
    // Find "tls accept from <IP>:<port>"
    let idx = s.find("tls accept from ")?;
    let rest = &s[idx + "tls accept from ".len()..];
    let colon = rest.find(':')?;
    let ip_str = &rest[..colon];
    let ip: IpAddr = ip_str.parse().ok()?;
    let reason = ProbeReason::from_line(&s);
    Some((ts_unix, ip, reason))
}

/// Minimal RFC3339 → unix-seconds. We only need second precision; fractional
/// seconds and the trailing 'Z' are tolerated, not required.
fn parse_rfc3339_to_unix(s: &str) -> Option<i64> {
    // Expect: YYYY-MM-DDTHH:MM:SS[.fraction]Z
    if s.len() < 20 {
        return None;
    }
    let year: i64 = s.get(0..4)?.parse().ok()?;
    let mon: u32 = s.get(5..7)?.parse().ok()?;
    let day: u32 = s.get(8..10)?.parse().ok()?;
    let hour: u32 = s.get(11..13)?.parse().ok()?;
    let min: u32 = s.get(14..16)?.parse().ok()?;
    let sec: u32 = s.get(17..19)?.parse().ok()?;
    // Days since unix epoch for civil calendar — Howard Hinnant algorithm.
    let y = if mon <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as i64;
    let doy = (153 * (mon as i64 + if mon > 2 { -3 } else { 9 }) + 2) / 5
        + day as i64
        - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    let secs = days * 86400 + (hour as i64) * 3600 + (min as i64) * 60 + (sec as i64);
    Some(secs)
}

// ── Team Cymru ASN lookup ───────────────────────────────────────────────
// Reverses the IPv4 octets and queries TXT origin.asn.cymru.com. Format:
//   "15169 | 8.8.8.0/24 | US | arin | 2014-03-14"
// Then AS{asn}.asn.cymru.com for the org description.

async fn asn_lookup(ip: &IpAddr) -> Result<AsnInfo> {
    let v4 = match ip {
        IpAddr::V4(v) => v.octets(),
        IpAddr::V6(_) => return Err(anyhow!("v6 lookup not implemented")),
    };
    let rev = format!(
        "{}.{}.{}.{}.origin.asn.cymru.com",
        v4[3], v4[2], v4[1], v4[0]
    );
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
    let txt_resp = resolver.txt_lookup(&rev).await.context("cymru origin txt")?;
    let Some(record) = txt_resp.iter().next() else {
        return Err(anyhow!("no TXT for {}", rev));
    };
    let txt = record.iter().map(|b| String::from_utf8_lossy(b).to_string()).collect::<Vec<_>>().join("");
    let parts: Vec<String> = txt.split('|').map(|p| p.trim().to_string()).collect();
    if parts.len() < 3 {
        return Err(anyhow!("bad cymru TXT: {}", txt));
    }
    let asn: u32 = parts[0].split_whitespace().next().unwrap_or("0").parse().unwrap_or(0);
    let country = parts.get(2).cloned().unwrap_or_default();
    // Follow-up lookup for ASN description
    let mut org = String::new();
    if asn > 0 {
        let asn_name = format!("AS{}.asn.cymru.com", asn);
        if let Ok(resp) = resolver.txt_lookup(&asn_name).await {
            if let Some(r) = resp.iter().next() {
                let s = r.iter().map(|b| String::from_utf8_lossy(b).to_string()).collect::<Vec<_>>().join("");
                let pp: Vec<&str> = s.split('|').map(|p| p.trim()).collect();
                if pp.len() >= 5 {
                    org = pp[4].to_string();
                } else if !pp.is_empty() {
                    org = pp.last().copied().unwrap_or("").to_string();
                }
            }
        }
    }
    Ok(AsnInfo {
        asn,
        country,
        org,
        looked_up_at: now_unix(),
    })
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ── ip-api.com batch geo lookup ─────────────────────────────────────────
// Free tier: 45 req/min on single endpoint, but /batch accepts up to 100 IPs
// per POST and counts as ONE request. Free fields: country, countryCode,
// regionName, city, isp, org, as, query.

#[derive(Debug, Deserialize)]
struct IpApiEntry {
    #[serde(default)] status: String,
    #[serde(default)] country: String,
    #[serde(rename = "countryCode", default)] country_code: String,
    #[serde(rename = "regionName", default)] region_name: String,
    #[serde(default)] city: String,
    #[serde(default)] isp: String,
    #[serde(default)] org: String,
    #[serde(default, rename = "as")] as_field: String,
    #[serde(default)] query: String,
}

async fn geo_batch(
    client: &reqwest::Client,
    ips: &[IpAddr],
) -> Result<Vec<(IpAddr, GeoInfo)>> {
    if ips.is_empty() {
        return Ok(vec![]);
    }
    let payload: Vec<serde_json::Value> = ips
        .iter()
        .map(|ip| {
            serde_json::json!({
                "query": ip.to_string(),
                "fields": "status,country,countryCode,regionName,city,isp,org,as,query"
            })
        })
        .collect();
    let resp = client
        .post("http://ip-api.com/batch")
        .json(&payload)
        .send()
        .await?;
    let entries: Vec<IpApiEntry> = resp.json().await?;
    let now = now_unix();
    let mut out = Vec::new();
    for e in entries {
        if e.status != "success" {
            continue;
        }
        let ip: IpAddr = match e.query.parse() {
            Ok(i) => i,
            Err(_) => continue,
        };
        let gi = GeoInfo {
            country: e.country,
            country_code: e.country_code,
            region: e.region_name,
            city: e.city,
            isp: e.isp,
            org: e.org,
            as_field: e.as_field,
            looked_up_at: now,
        };
        out.push((ip, gi));
    }
    Ok(out)
}

// ── CLI ─────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(name = "nanobyte-intel", version, about = "cochranblock.org threat-intel — sled+bincode+zstd")]
struct Args {
    /// Sled db path. Default: ~/.nanobyte-intel/
    #[arg(long)]
    db: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Ingest an approuter-acme-format log (failed TLS probes, real client IPs).
    Ingest { file: PathBuf },
    /// Ingest approuter analytics JSONL (successful requests, privacy-hashed IPs).
    IngestAccess { file: PathBuf },
    /// Summary stats (probes + access).
    Stats,
    /// Top N client IPs by probe count.
    Top { #[arg(default_value_t = 25)] n: usize },
    /// Top N ASNs by probe count — Team Cymru DNS lookup, cached in sled.
    Asns { #[arg(default_value_t = 20)] n: usize },
    /// Resolve geo (city+region+ISP+ASN) for every unique IP — ip-api.com batched, cached.
    Geo {
        /// Only resolve IPs with at least this many probe hits (skips long-tail noise).
        #[arg(long, default_value_t = 1)]
        min_hits: usize,
        /// Refresh cached entries older than this many days.
        #[arg(long, default_value_t = 30)]
        refresh_days: i64,
    },
    /// Show everything known for one IP: probes, access, ASN, geo, timeline.
    Ip { ip: IpAddr },
    /// Show everything known for one privacy-hashed visitor (approuter access).
    Hash { ip_hash: String },
    /// Top N cities from resolved geo cache.
    Cities { #[arg(default_value_t = 25)] n: usize },
    /// Top N ISP/org strings from resolved geo cache.
    Orgs { #[arg(default_value_t = 25)] n: usize },
    /// IPs with sustained probing — meeting-pattern candidates.
    Dwell { #[arg(long, default_value_t = 5)] min_hits: usize },
    /// Access-log session analysis: ip_hash dwell windows, paths, ua.
    Sessions {
        /// Only dwell ≥ this many seconds.
        #[arg(long, default_value_t = 3600)]
        min_seconds: i64,
        /// Exclude bots (ua classifier said so).
        #[arg(long)]
        humans_only: bool,
    },
}

fn default_db() -> PathBuf {
    if let Some(home) = dirs_home() {
        home.join(".nanobyte-intel")
    } else {
        PathBuf::from("./.nanobyte-intel")
    }
}

fn dirs_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().init();
    let args = Args::parse();
    let db_path = args.db.unwrap_or_else(default_db);
    let store = Store::open(&db_path)?;
    match args.cmd {
        Cmd::Ingest { file } => cmd_ingest(&store, &file)?,
        Cmd::IngestAccess { file } => cmd_ingest_access(&store, &file)?,
        Cmd::Stats => cmd_stats(&store)?,
        Cmd::Top { n } => cmd_top(&store, n)?,
        Cmd::Asns { n } => cmd_asns(&store, n).await?,
        Cmd::Geo { min_hits, refresh_days } => cmd_geo(&store, min_hits, refresh_days).await?,
        Cmd::Ip { ip } => cmd_ip(&store, ip).await?,
        Cmd::Hash { ip_hash } => cmd_hash(&store, &ip_hash)?,
        Cmd::Cities { n } => cmd_cities(&store, n)?,
        Cmd::Orgs { n } => cmd_orgs(&store, n)?,
        Cmd::Dwell { min_hits } => cmd_dwell(&store, min_hits)?,
        Cmd::Sessions { min_seconds, humans_only } => cmd_sessions(&store, min_seconds, humans_only)?,
    }
    store.flush()?;
    Ok(())
}

fn cmd_ingest(store: &Store, file: &PathBuf) -> Result<()> {
    let f = File::open(file).with_context(|| format!("open {:?}", file))?;
    let rd = BufReader::new(f);
    let mut seq: u32 = 0;
    let mut kept = 0usize;
    let mut skipped = 0usize;
    for line in rd.lines() {
        let line = line?;
        match parse_line(&line) {
            Some((ts, ip, reason)) => {
                let ev = ProbeEvent { ts_unix: ts, ip, reason };
                store.insert_probe(seq, &ev)?;
                seq = seq.wrapping_add(1);
                kept += 1;
            }
            None => skipped += 1,
        }
    }
    info!("ingested {} events, skipped {} lines", kept, skipped);
    println!("kept={} skipped={} db_probes={}", kept, skipped, store.probe_count());
    Ok(())
}

fn cmd_stats(store: &Store) -> Result<()> {
    let mut n = 0usize;
    let mut ts_min = i64::MAX;
    let mut ts_max = i64::MIN;
    let mut by_ip: HashMap<IpAddr, usize> = HashMap::new();
    let mut by_reason: HashMap<&'static str, usize> = HashMap::new();
    for ev in store.iter_probes() {
        let ev = ev?;
        n += 1;
        ts_min = ts_min.min(ev.ts_unix);
        ts_max = ts_max.max(ev.ts_unix);
        *by_ip.entry(ev.ip).or_insert(0) += 1;
        *by_reason.entry(ev.reason.label()).or_insert(0) += 1;
    }
    if n == 0 {
        println!("no probes — run 'ingest' first");
        return Ok(());
    }
    let dur_s = (ts_max - ts_min).max(1);
    println!("probes         : {}", n);
    println!("unique ips     : {}", by_ip.len());
    println!("first seen     : {} UTC", ts_to_iso(ts_min));
    println!("last seen      : {} UTC", ts_to_iso(ts_max));
    println!("window         : {}h {}m", dur_s / 3600, (dur_s % 3600) / 60);
    println!("probes / hour  : {:.0}", n as f64 / (dur_s as f64 / 3600.0));
    println!("reasons:");
    let mut rr: Vec<_> = by_reason.into_iter().collect();
    rr.sort_by_key(|(_, c)| std::cmp::Reverse(*c));
    for (k, c) in rr {
        println!("  {:>5}  {}", c, k);
    }
    Ok(())
}

fn ts_to_iso(ts: i64) -> String {
    // Minimal ISO-8601 rendering (no tz lib needed). Uses day-calc inverse.
    let mut secs = ts;
    let sec = (secs.rem_euclid(60)) as u32;
    secs = secs.div_euclid(60);
    let min = (secs.rem_euclid(60)) as u32;
    secs = secs.div_euclid(60);
    let hour = (secs.rem_euclid(24)) as u32;
    let days = secs.div_euclid(24);
    // Inverse of the Hinnant day-calc used in parse_rfc3339_to_unix
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let mon = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let year = y + if mon <= 2 { 1 } else { 0 };
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", year, mon, day, hour, min, sec)
}

fn cmd_top(store: &Store, n: usize) -> Result<()> {
    let mut by_ip: HashMap<IpAddr, (usize, i64, i64)> = HashMap::new();
    for ev in store.iter_probes() {
        let ev = ev?;
        let e = by_ip.entry(ev.ip).or_insert((0, i64::MAX, i64::MIN));
        e.0 += 1;
        e.1 = e.1.min(ev.ts_unix);
        e.2 = e.2.max(ev.ts_unix);
    }
    let mut v: Vec<_> = by_ip.into_iter().collect();
    v.sort_by_key(|(_, (c, _, _))| std::cmp::Reverse(*c));
    println!("{:>5}  {:<17}  {:<20}  {:<20}  dwell", "hits", "ip", "first", "last");
    for (ip, (count, first, last)) in v.into_iter().take(n) {
        let dur = last - first;
        let dh = dur / 3600; let dm = (dur % 3600) / 60;
        println!("{:>5}  {:<17}  {:<20}  {:<20}  {}h{:02}m",
                 count, ip, ts_to_iso(first), ts_to_iso(last), dh, dm);
    }
    Ok(())
}

async fn cmd_asns(store: &Store, n: usize) -> Result<()> {
    // Build top-IP list first, then look up each (cached)
    let mut by_ip: HashMap<IpAddr, usize> = HashMap::new();
    for ev in store.iter_probes() {
        let ev = ev?;
        *by_ip.entry(ev.ip).or_insert(0) += 1;
    }
    let mut ips: Vec<_> = by_ip.into_iter().collect();
    ips.sort_by_key(|(_, c)| std::cmp::Reverse(*c));
    let mut by_asn: HashMap<u32, (String, String, usize)> = HashMap::new(); // asn -> (cc, org, hits)
    for (ip, hits) in ips.iter().take(400) {
        let ai = if let Some(ai) = store.get_asn(ip)? {
            ai
        } else {
            match asn_lookup(ip).await {
                Ok(ai) => {
                    store.put_asn(ip, &ai)?;
                    ai
                }
                Err(_) => AsnInfo::default(),
            }
        };
        let entry = by_asn.entry(ai.asn).or_insert((ai.country.clone(), ai.org.clone(), 0));
        entry.2 += hits;
    }
    let mut rows: Vec<_> = by_asn.into_iter().collect();
    rows.sort_by_key(|(_, (_, _, c))| std::cmp::Reverse(*c));
    println!("{:>6}  {:>8}  {:<3}  org", "hits", "asn", "cc");
    for (asn, (cc, org, hits)) in rows.into_iter().take(n) {
        println!("{:>6}  AS{:<6}  {:<3}  {}", hits, asn, cc, org);
    }
    Ok(())
}

async fn cmd_ip(store: &Store, ip: IpAddr) -> Result<()> {
    // Collect probe events for this IP
    let mut probes: Vec<ProbeEvent> = Vec::new();
    for ev in store.iter_probes() {
        let ev = ev?;
        if ev.ip == ip {
            probes.push(ev);
        }
    }
    probes.sort_by_key(|e| e.ts_unix);

    // Resolve or load ASN
    let asn = match store.get_asn(&ip)? {
        Some(a) => a,
        None => {
            eprintln!("(resolving ASN via Team Cymru DNS…)");
            match asn_lookup(&ip).await {
                Ok(a) => { store.put_asn(&ip, &a)?; a }
                Err(e) => { eprintln!("asn lookup failed: {}", e); AsnInfo::default() }
            }
        }
    };

    // Resolve or load geo
    let geo = match store.get_geo(&ip)? {
        Some(g) => g,
        None => {
            eprintln!("(resolving geo via ip-api.com…)");
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(20))
                .build()?;
            match geo_batch(&client, &[ip]).await {
                Ok(mut v) if !v.is_empty() => {
                    let (_, g) = v.remove(0);
                    store.put_geo(&ip, &g)?;
                    g
                }
                _ => GeoInfo::default(),
            }
        }
    };

    println!("== {} ==", ip);
    println!("  ASN    : AS{}  {} ({})", asn.asn, asn.org, asn.country);
    println!("  geo    : {} / {} / {}", geo.city, geo.region, geo.country_code);
    println!("  ISP    : {}", geo.isp);
    println!("  org    : {}", geo.org);
    println!("  as_str : {}", geo.as_field);

    if probes.is_empty() {
        println!("  probes : 0 (no direct-path TLS handshake events)");
    } else {
        let first = probes.first().unwrap().ts_unix;
        let last = probes.last().unwrap().ts_unix;
        let dur = last - first;
        println!("  probes : {} events, dwell {}h{:02}m", probes.len(), dur/3600, (dur%3600)/60);
        println!("  first  : {}", ts_to_iso(first));
        println!("  last   : {}", ts_to_iso(last));
        println!("  recent :");
        for e in probes.iter().rev().take(10) {
            println!("    {}  {}", ts_to_iso(e.ts_unix), e.reason.label());
        }
    }
    Ok(())
}

fn cmd_hash(store: &Store, ip_hash: &str) -> Result<()> {
    // Look up an access-log session by the privacy-hashed visitor id.
    let mut events: Vec<AccessEvent> = Vec::new();
    for ev in store.iter_access() {
        let ev = ev?;
        if ev.ip_hash == ip_hash {
            events.push(ev);
        }
    }
    if events.is_empty() {
        println!("no access events for ip_hash {}", ip_hash);
        return Ok(());
    }
    events.sort_by_key(|e| e.ts_unix);
    let first = events.first().unwrap().ts_unix;
    let last = events.last().unwrap().ts_unix;
    let dur = last - first;
    let uniq_paths: std::collections::HashSet<_> = events.iter().map(|e| &e.path).collect();
    let sample = events.first().unwrap();
    println!("== ip_hash {} ==", ip_hash);
    println!("  events  : {}  unique paths: {}", events.len(), uniq_paths.len());
    println!("  dwell   : {}h{:02}m  ({} → {})", dur/3600, (dur%3600)/60, ts_to_iso(first), ts_to_iso(last));
    println!("  country : {}  city: {}  region: {}", sample.country, sample.city, sample.region);
    println!("  ua      : {}  bot: {}", sample.ua_family, sample.is_bot);
    println!("  timeline (first 40 hits):");
    for e in events.iter().take(40) {
        println!("    {}  {:>3} {:<6} {:<40}  host={}", ts_to_iso(e.ts_unix), e.status, e.method, e.path.chars().take(40).collect::<String>(), e.host);
    }
    if events.len() > 40 {
        println!("    ... ({} more)", events.len() - 40);
    }
    Ok(())
}

fn cmd_cities(store: &Store, n: usize) -> Result<()> {
    let mut by_city: HashMap<(String, String, String), (usize, Vec<IpAddr>)> = HashMap::new();
    for item in store.geo_cache.iter() {
        let (k, v) = item?;
        let raw = zstd::decode_all(&v[..])?;
        let (gi, _): (GeoInfo, _) = decode_from_slice(&raw, bincode_std())?;
        let ip_str = String::from_utf8_lossy(&k).to_string();
        let ip: IpAddr = match ip_str.parse() { Ok(i) => i, Err(_) => continue };
        let key = (gi.country_code.clone(), gi.region.clone(), gi.city.clone());
        let e = by_city.entry(key).or_insert((0, Vec::new()));
        e.0 += 1;
        e.1.push(ip);
    }
    let mut v: Vec<_> = by_city.into_iter().collect();
    v.sort_by_key(|(_, (c, _))| std::cmp::Reverse(*c));
    println!("{:>5}  {:<3}  {:<20}  {:<25}  sample_ip", "ips", "cc", "region", "city");
    for ((cc, region, city), (count, ips)) in v.into_iter().take(n) {
        let sample = ips.first().map(|i| i.to_string()).unwrap_or_default();
        println!("{:>5}  {:<3}  {:<20}  {:<25}  {}", count, cc, region.chars().take(20).collect::<String>(), city.chars().take(25).collect::<String>(), sample);
    }
    Ok(())
}

fn cmd_orgs(store: &Store, n: usize) -> Result<()> {
    let mut by_org: HashMap<String, (usize, Vec<IpAddr>)> = HashMap::new();
    for item in store.geo_cache.iter() {
        let (k, v) = item?;
        let raw = zstd::decode_all(&v[..])?;
        let (gi, _): (GeoInfo, _) = decode_from_slice(&raw, bincode_std())?;
        let ip_str = String::from_utf8_lossy(&k).to_string();
        let ip: IpAddr = match ip_str.parse() { Ok(i) => i, Err(_) => continue };
        // Prefer org, fall back to isp
        let org = if !gi.org.is_empty() { gi.org.clone() } else { gi.isp.clone() };
        let e = by_org.entry(org).or_insert((0, Vec::new()));
        e.0 += 1;
        e.1.push(ip);
    }
    let mut v: Vec<_> = by_org.into_iter().collect();
    v.sort_by_key(|(_, (c, _))| std::cmp::Reverse(*c));
    println!("{:>5}  org", "ips");
    for (org, (count, _)) in v.into_iter().take(n) {
        println!("{:>5}  {}", count, org);
    }
    Ok(())
}

async fn cmd_geo(store: &Store, min_hits: usize, refresh_days: i64) -> Result<()> {
    // Build hits-per-IP from probes table
    let mut by_ip: HashMap<IpAddr, usize> = HashMap::new();
    for ev in store.iter_probes() {
        let ev = ev?;
        *by_ip.entry(ev.ip).or_insert(0) += 1;
    }
    let cutoff = now_unix() - refresh_days * 86400;
    let mut need: Vec<IpAddr> = Vec::new();
    for (ip, hits) in &by_ip {
        if *hits < min_hits { continue; }
        match store.get_geo(ip)? {
            Some(g) if g.looked_up_at >= cutoff => continue,
            _ => need.push(*ip),
        }
    }
    println!("resolving {} IPs via ip-api.com batch (cache has {} already)",
             need.len(), store.geo_cache.len());
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;
    // ip-api free tier: 15 req/min. Batch endpoint = 1 req per 100 IPs.
    // Sleep 4.2s between batches to stay under 15/min with margin.
    let mut resolved = 0;
    for chunk in need.chunks(100) {
        match geo_batch(&client, chunk).await {
            Ok(items) => {
                for (ip, gi) in &items {
                    store.put_geo(ip, gi)?;
                    resolved += 1;
                }
            }
            Err(e) => eprintln!("batch err: {}", e),
        }
        if chunk.len() == 100 {
            tokio::time::sleep(std::time::Duration::from_millis(4200)).await;
        }
    }
    println!("resolved={}  total_geo_cache={}", resolved, store.geo_cache.len());
    Ok(())
}

fn cmd_ingest_access(store: &Store, file: &PathBuf) -> Result<()> {
    let f = File::open(file).with_context(|| format!("open {:?}", file))?;
    let rd = BufReader::new(f);
    let mut seq: u32 = 0;
    let mut kept = 0usize;
    let mut skipped = 0usize;
    #[derive(Deserialize)]
    struct Raw {
        ts: i64, host: String, path: String, method: String,
        status: u16, duration_ms: u64,
        #[serde(default)] country: String,
        #[serde(default)] city: String,
        #[serde(default)] region: String,
        #[serde(default)] ua_family: String,
        #[serde(default)] is_bot: bool,
        #[serde(default)] ip_hash: String,
    }
    for line in rd.lines() {
        let line = line?;
        let r: Raw = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(_) => { skipped += 1; continue; }
        };
        let ev = AccessEvent {
            ts_unix: r.ts, host: r.host, path: r.path, method: r.method,
            status: r.status, duration_ms: r.duration_ms,
            country: r.country, city: r.city, region: r.region,
            ua_family: r.ua_family, is_bot: r.is_bot, ip_hash: r.ip_hash,
        };
        store.insert_access(seq, &ev)?;
        seq = seq.wrapping_add(1);
        kept += 1;
    }
    println!("kept={} skipped={} db_access={}", kept, skipped, store.access_count());
    Ok(())
}

fn cmd_sessions(store: &Store, min_seconds: i64, humans_only: bool) -> Result<()> {
    #[derive(Default, Debug)]
    struct S {
        first: i64, last: i64, count: usize,
        paths: std::collections::HashSet<String>,
        country: String, city: String, region: String, ua: String, bot: bool,
    }
    let mut by_hash: HashMap<String, S> = HashMap::new();
    for ev in store.iter_access() {
        let ev = ev?;
        let s = by_hash.entry(ev.ip_hash.clone()).or_insert_with(|| S {
            first: i64::MAX, last: i64::MIN, ..Default::default()
        });
        if ev.ts_unix < s.first { s.first = ev.ts_unix; }
        if ev.ts_unix > s.last  { s.last  = ev.ts_unix; }
        s.count += 1;
        s.paths.insert(ev.path);
        if s.country.is_empty() { s.country = ev.country; }
        if s.city.is_empty()    { s.city    = ev.city; }
        if s.region.is_empty()  { s.region  = ev.region; }
        if s.ua.is_empty()      { s.ua      = ev.ua_family; }
        s.bot = s.bot || ev.is_bot;
    }
    let mut rows: Vec<(String, S)> = by_hash.into_iter().collect();
    rows.sort_by_key(|(_, s)| std::cmp::Reverse(s.last - s.first));
    println!("{:>9}  {:>6}  {:>6}  {:<3}  {:<5}  {:<14}  ip_hash", "dwell", "hits", "paths", "cc", "bot", "ua");
    println!("{}", "-".repeat(90));
    let mut shown = 0;
    for (hash, s) in &rows {
        if shown >= 40 { break; }
        let dwell = s.last - s.first;
        if dwell < min_seconds { continue; }
        if humans_only && s.bot { continue; }
        let dh = dwell / 3600; let dm = (dwell % 3600) / 60; let ds = dwell % 60;
        let ua = s.ua.chars().take(14).collect::<String>();
        println!("  {}h{:02}m{:02}s  {:>6}  {:>6}  {:<3}  {:<5}  {:<14}  {}",
                 dh, dm, ds, s.count, s.paths.len(), s.country, s.bot, ua, hash);
        shown += 1;
    }
    Ok(())
}

fn cmd_dwell(store: &Store, min_hits: usize) -> Result<()> {
    let mut by_ip: HashMap<IpAddr, (usize, i64, i64)> = HashMap::new();
    for ev in store.iter_probes() {
        let ev = ev?;
        let e = by_ip.entry(ev.ip).or_insert((0, i64::MAX, i64::MIN));
        e.0 += 1;
        e.1 = e.1.min(ev.ts_unix);
        e.2 = e.2.max(ev.ts_unix);
    }
    let mut v: Vec<_> = by_ip.into_iter()
        .filter(|(_, (c, _, _))| *c >= min_hits)
        .collect();
    v.sort_by_key(|(_, (_, f, l))| std::cmp::Reverse(l - f));
    println!("{:>5}  {:<17}  {:>8}  {}", "hits", "ip", "dwell", "span");
    for (ip, (count, first, last)) in v.into_iter().take(50) {
        let dur = last - first;
        println!("{:>5}  {:<17}  {:>5}h{:02}m  {} → {}",
                 count, ip, dur/3600, (dur%3600)/60, ts_to_iso(first), ts_to_iso(last));
    }
    Ok(())
}
