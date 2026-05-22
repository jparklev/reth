//! `witness-follower` — a stateful, continuously-running validator.
//!
//! Unlike `witness-stream` (which fetches a manifest, processes it in one pass,
//! and exits), the follower polls `head.json` on a tick, validates every block
//! it hasn't already seen, and persists its progress to a cursor file so that a
//! restart resumes where it left off.
//!
//! Designed to run as a long-lived systemd service. Several copies typically
//! run in parallel against the same bucket — each with its own state dir,
//! cursor, JSONL, and metrics port — to give the operator a divergence signal
//! between independent readers.
//!
//! `--fetch-delay-ms` injects an artificial sleep before each S3 fetch. This is
//! how we model a geographically remote reader on the same box without
//! resorting to host-level traffic shaping.

use clap::Parser;
use eyre::Context;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use metrics_exporter_prometheus::PrometheusBuilder;
use rand::Rng;
use reth_chainspec::{ChainSpec, MAINNET};
use serde::{Deserialize, Serialize};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tracing::{debug, error, info, warn};

#[path = "live_manifest.rs"]
mod live_manifest;
#[path = "signing.rs"]
mod signing;
#[path = "validate_core.rs"]
mod validate_core;

use validate_core::{decode_bundle, validate_bundle, Encoding};

/// Continuously poll `head.json`, validate every fresh block, expose metrics.
#[derive(Parser, Debug)]
#[command(about = "Stateful follower-validator for a witness bucket")]
struct Cli {
    /// Logical name; appears in metrics labels and JSONL lines.
    #[arg(long, env = "READER_NAME", default_value = "reader")]
    name: String,
    /// Hetzner endpoint, e.g. `https://fsn1.your-objectstorage.com`.
    #[arg(long, env = "S3_ENDPOINT")]
    endpoint: String,
    /// Bucket name.
    #[arg(long, env = "S3_BUCKET")]
    bucket: String,
    /// Region (Hetzner: `fsn1`).
    #[arg(long, env = "S3_REGION", default_value = "fsn1")]
    region: String,
    /// Manifest object key.
    #[arg(long, env = "S3_MANIFEST", default_value = "witnesses/exex/head.json")]
    manifest: String,
    /// Optional public CDN base URL. When set, witness objects + signatures are
    /// fetched over HTTPS without S3 auth. Latency is usually dramatically
    /// better — but the manifest fetch still uses the S3 API for HEAD-style
    /// ETag tracking on a slowly-changing object.
    #[arg(long, env = "WITNESS_BASE_URL")]
    base_url: Option<String>,
    /// Path to the producer's 32-byte ed25519 public key. When set, every
    /// witness AND the manifest are signature-verified before validation.
    #[arg(long, env = "WITNESS_PUBKEY")]
    pubkey: Option<PathBuf>,
    /// Cursor file: stores the last successfully validated block_number+hash.
    #[arg(long, env = "FOLLOWER_CURSOR")]
    cursor: PathBuf,
    /// Append-only JSONL of one line per validated/failed block.
    #[arg(long, env = "FOLLOWER_JSONL")]
    jsonl: PathBuf,
    /// `/metrics` listener address. `0.0.0.0:0` disables the endpoint.
    #[arg(long, env = "FOLLOWER_METRICS_ADDR", default_value = "127.0.0.1:0")]
    metrics_addr: SocketAddr,
    /// Base poll interval between manifest fetches, milliseconds.
    #[arg(long, default_value = "1500")]
    poll_ms: u64,
    /// Random jitter added to each poll interval, milliseconds. Prevents
    /// thundering-herd polling when several readers share a host.
    #[arg(long, default_value = "500")]
    jitter_ms: u64,
    /// Artificial fetch delay (one sleep before each witness/manifest fetch),
    /// used to simulate a geographically remote reader. 0 disables.
    #[arg(long, default_value = "0")]
    fetch_delay_ms: u64,
    /// Skip the first N manifest entries on a cold start (no cursor).
    #[arg(long, default_value = "0")]
    cold_start_skip: usize,
    /// If a block fails validation this many consecutive times, bump the
    /// cursor past it and continue. A bad witness in S3 (producer bug,
    /// missing bytecode, etc.) would otherwise wedge the follower forever;
    /// in production we'd rather log + advance than stop. Set to 0 to disable
    /// — useful in test runs where every divergence must be investigated.
    #[arg(long, default_value = "10")]
    skip_after_failures: u32,
}

const FOLLOW_TICK_TOTAL: &str = "witness_follower_tick_total";
const FOLLOW_HEAD_BLOCK: &str = "witness_follower_head_block";
const FOLLOW_VALIDATED_BLOCK: &str = "witness_follower_validated_block";
const FOLLOW_LAG_BLOCKS: &str = "witness_follower_head_lag_blocks";
const FOLLOW_VALIDATE_TOTAL: &str = "witness_follower_validate_total";
const FOLLOW_FETCH_LATENCY_SECONDS: &str = "witness_follower_fetch_latency_seconds";
const FOLLOW_VALIDATE_LATENCY_SECONDS: &str = "witness_follower_validate_latency_seconds";
const FOLLOW_E2E_LATENCY_SECONDS: &str = "witness_follower_e2e_latency_seconds";
const FOLLOW_LAST_SUCCESS_TS: &str = "witness_follower_last_success_timestamp";
const FOLLOW_BYTES_TOTAL: &str = "witness_follower_bytes_total";
const FOLLOW_SKIPPED_BLOCK_TOTAL: &str = "witness_follower_skipped_block_total";

fn describe_metrics() {
    use metrics::{describe_counter, describe_gauge, describe_histogram, Unit};
    describe_counter!(FOLLOW_TICK_TOTAL, "Manifest poll ticks (labelled result=ok|err)");
    describe_counter!(
        FOLLOW_VALIDATE_TOTAL,
        "Block validation attempts (labelled result=ok|sig_err|state_root_err|fetch_err)"
    );
    describe_counter!(FOLLOW_BYTES_TOTAL, "Total bytes fetched from S3/CDN");
    describe_counter!(
        FOLLOW_SKIPPED_BLOCK_TOTAL,
        "Blocks the follower had to skip after N consecutive failures (producer bug, missing code, etc.)"
    );
    describe_gauge!(FOLLOW_HEAD_BLOCK, "Highest block number visible in head.json");
    describe_gauge!(FOLLOW_VALIDATED_BLOCK, "Highest block this reader has validated");
    describe_gauge!(FOLLOW_LAG_BLOCKS, "head_block - validated_block");
    describe_gauge!(
        FOLLOW_LAST_SUCCESS_TS,
        "Unix timestamp (seconds) of the most recent successful validation"
    );
    describe_histogram!(
        FOLLOW_FETCH_LATENCY_SECONDS,
        Unit::Seconds,
        "Wall clock per S3/CDN witness fetch (includes signature)"
    );
    describe_histogram!(
        FOLLOW_VALIDATE_LATENCY_SECONDS,
        Unit::Seconds,
        "Wall clock per witness decode + execute + root recompute"
    );
    describe_histogram!(
        FOLLOW_E2E_LATENCY_SECONDS,
        Unit::Seconds,
        "fetch + validate + cursor update per block"
    );
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Cursor {
    /// Last successfully validated block number (and the hash, so an aborted
    /// fork doesn't quietly replay).
    last_block_number: u64,
    last_block_hash: alloy_primitives::B256,
    /// Wall-clock timestamp of the last successful validation, ISO-8601.
    updated_at: String,
    /// Total number of blocks validated by this reader since process start
    /// — pure observability, NOT a load-bearing field.
    blocks_validated: u64,
}

impl Cursor {
    fn fresh() -> Self {
        Self {
            last_block_number: 0,
            last_block_hash: alloy_primitives::B256::ZERO,
            updated_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            blocks_validated: 0,
        }
    }

    fn load(path: &Path) -> eyre::Result<Self> {
        let bytes = std::fs::read(path).wrap_err_with(|| format!("read {}", path.display()))?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    fn save(&self, path: &Path) -> eyre::Result<()> {
        // Atomic write: tmp + rename + fsync of parent dir. A torn cursor on
        // crash is worse than no cursor at all — the reader would silently
        // skip blocks.
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(&tmp, path)?;
        if let Some(dir) = path.parent() {
            if let Ok(d) = std::fs::File::open(dir) {
                let _ = d.sync_all();
            }
        }
        Ok(())
    }
}

fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    if let Some(p) = cli.cursor.parent() {
        std::fs::create_dir_all(p).ok();
    }
    if let Some(p) = cli.jsonl.parent() {
        std::fs::create_dir_all(p).ok();
    }

    let spec: Arc<ChainSpec> = MAINNET.clone();
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().worker_threads(2).build()?;
    rt.block_on(run(cli, spec))
}

async fn run(cli: Cli, spec: Arc<ChainSpec>) -> eyre::Result<()> {
    // Metrics server (best-effort: don't fail process startup over it).
    if !(cli.metrics_addr.port() == 0 && cli.metrics_addr.ip().is_unspecified()) {
        match spawn_metrics(cli.metrics_addr).await {
            Ok(bound) => info!(reader = %cli.name, %bound, "metrics endpoint listening"),
            Err(err) => warn!(reader = %cli.name, ?err, "metrics server failed to start"),
        }
    }
    describe_metrics();

    let verifying_key = match &cli.pubkey {
        Some(p) => Some(signing::load_verifying_key(p).wrap_err("load --pubkey")?),
        None => None,
    };
    let s3 = build_s3_client(&cli).await;
    let http = reqwest::Client::builder()
        .pool_idle_timeout(Duration::from_secs(90))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    let mut cursor = Cursor::load(&cli.cursor).unwrap_or_else(|err| {
        info!(reader = %cli.name, ?err, "no cursor; starting fresh");
        Cursor::fresh()
    });
    // Surface the loaded cursor so dashboards don't show validated_block=0 on
    // every reader restart. The gauge would otherwise be silent until the
    // next successful validation lands.
    if cursor.last_block_number > 0 {
        metrics::gauge!(FOLLOW_VALIDATED_BLOCK).set(cursor.last_block_number as f64);
    }
    info!(
        reader = %cli.name,
        last_block = cursor.last_block_number,
        last_hash = %cursor.last_block_hash,
        "follower starting"
    );

    let mut cold_start = cursor.last_block_number == 0;
    let mut rng = rand::rng();
    // `(block_number, consecutive_failures)` for the block we're currently
    // stuck on. Reset on success or when the block number changes.
    let mut stuck: Option<(u64, u32)> = None;

    loop {
        let tick_started = Instant::now();
        match fetch_manifest(&cli, &s3, &http, verifying_key.as_ref()).await {
            Ok(entries) => {
                metrics::counter!(FOLLOW_TICK_TOTAL, "result" => "ok").increment(1);
                if let Some(head) = entries.iter().max_by_key(|e| e.block_number) {
                    metrics::gauge!(FOLLOW_HEAD_BLOCK).set(head.block_number as f64);
                    // i64 because the lag can transiently go negative right
                    // after a reorg / manifest rewind. Saturate at 0 for
                    // monotonic scraping clients.
                    let lag = head
                        .block_number
                        .saturating_sub(cursor.last_block_number)
                        as f64;
                    metrics::gauge!(FOLLOW_LAG_BLOCKS).set(lag);
                }

                // The manifest is newest-first; sort ascending for replay.
                let mut entries = entries;
                entries.sort_by_key(|e| e.block_number);

                let mut to_process: Vec<live_manifest::ManifestEntry> = entries
                    .into_iter()
                    .filter(|e| e.block_number > cursor.last_block_number)
                    .collect();
                if cold_start && !to_process.is_empty() {
                    let skip = cli.cold_start_skip.min(to_process.len().saturating_sub(1));
                    if skip > 0 {
                        info!(reader = %cli.name, skip, "cold-start skipping initial entries");
                        to_process.drain(..skip);
                    }
                    cold_start = false;
                }

                for entry in to_process {
                    match process_one(
                        &cli,
                        spec.clone(),
                        &s3,
                        &http,
                        verifying_key.as_ref(),
                        &entry,
                        &mut cursor,
                    )
                    .await
                    {
                        Ok(()) => {
                            stuck = None;
                        }
                        Err(err) => {
                            // The follower never crashes on a per-block
                            // error: we log, count, and back off. The
                            // producer-or-network glitch usually resolves
                            // itself, and the next manifest tick retries
                            // (cursor hasn't advanced).
                            //
                            // BUT: a witness that's structurally broken
                            // (producer bug, missing bytecode, corrupted
                            // upload) wedges the follower forever. After
                            // `skip_after_failures` consecutive attempts on
                            // the same block, bump the cursor past it,
                            // record the metric, and continue. The operator
                            // can later inspect events.jsonl + s3 to decide
                            // whether to re-upload.
                            let failures = match stuck {
                                Some((b, n)) if b == entry.block_number => n + 1,
                                _ => 1,
                            };
                            stuck = Some((entry.block_number, failures));
                            error!(
                                reader = %cli.name,
                                block = entry.block_number,
                                failures,
                                ?err,
                                "process_one failed"
                            );
                            if cli.skip_after_failures > 0 &&
                                failures >= cli.skip_after_failures
                            {
                                warn!(
                                    reader = %cli.name,
                                    block = entry.block_number,
                                    failures,
                                    "skipping block after persistent failures; advancing cursor"
                                );
                                metrics::counter!(
                                    FOLLOW_SKIPPED_BLOCK_TOTAL,
                                    "reader" => cli.name.clone()
                                )
                                .increment(1);
                                write_jsonl(
                                    &cli.jsonl,
                                    &serde_json::json!({
                                        "ts": rfc3339_now(),
                                        "reader": cli.name,
                                        "block_number": entry.block_number,
                                        "block_hash": format!("{:?}", entry.block_hash),
                                        "object_key": entry.object_key,
                                        "result": "skipped_after_failures",
                                        "failures": failures,
                                        "error": format!("{err}"),
                                    }),
                                );
                                cursor.last_block_number = entry.block_number;
                                cursor.last_block_hash = entry.block_hash;
                                cursor.updated_at = rfc3339_now();
                                if let Err(err) = cursor.save(&cli.cursor) {
                                    warn!(reader = %cli.name, ?err, "cursor save failed");
                                }
                                stuck = None;
                                continue;
                            }
                            tokio::time::sleep(Duration::from_secs(2)).await;
                            break;
                        }
                    }
                }
            }
            Err(err) => {
                metrics::counter!(FOLLOW_TICK_TOTAL, "result" => "err").increment(1);
                warn!(reader = %cli.name, ?err, "manifest fetch failed");
            }
        }

        let elapsed = tick_started.elapsed();
        let jitter = if cli.jitter_ms > 0 {
            Duration::from_millis(rng.random_range(0..=cli.jitter_ms))
        } else {
            Duration::ZERO
        };
        let base = Duration::from_millis(cli.poll_ms);
        let sleep_for = base.saturating_sub(elapsed) + jitter;
        if sleep_for > Duration::ZERO {
            tokio::time::sleep(sleep_for).await;
        }
    }
}

async fn fetch_manifest(
    cli: &Cli,
    s3: &aws_sdk_s3::Client,
    http: &reqwest::Client,
    verifying_key: Option<&ed25519_dalek::VerifyingKey>,
) -> eyre::Result<Vec<live_manifest::ManifestEntry>> {
    apply_fetch_delay(cli).await;
    let bytes = if let Some(base) = &cli.base_url {
        http_get(http, base, &cli.manifest).await?
    } else {
        s3_get(s3, &cli.bucket, &cli.manifest).await?
    };
    if let Some(vk) = verifying_key {
        let sig_key = format!("{}.sig", cli.manifest);
        let sig = if let Some(base) = &cli.base_url {
            http_get(http, base, &sig_key).await?
        } else {
            s3_get(s3, &cli.bucket, &sig_key).await?
        };
        signing::verify(vk, &bytes, &sig).wrap_err("manifest sig verify")?;
    }
    let m: live_manifest::LiveManifest =
        serde_json::from_slice(&bytes).wrap_err("parse manifest")?;
    Ok(m.entries)
}

async fn process_one(
    cli: &Cli,
    spec: Arc<ChainSpec>,
    s3: &aws_sdk_s3::Client,
    http: &reqwest::Client,
    verifying_key: Option<&ed25519_dalek::VerifyingKey>,
    entry: &live_manifest::ManifestEntry,
    cursor: &mut Cursor,
) -> eyre::Result<()> {
    let e2e_started = Instant::now();

    // Fetch witness + optional signature.
    let fetch_started = Instant::now();
    apply_fetch_delay(cli).await;
    let bytes = if let Some(base) = &cli.base_url {
        http_get(http, base, &entry.object_key).await
    } else {
        s3_get(s3, &cli.bucket, &entry.object_key).await
    };
    let bytes = match bytes {
        Ok(b) => b,
        Err(err) => {
            metrics::counter!(FOLLOW_VALIDATE_TOTAL, "result" => "fetch_err").increment(1);
            write_jsonl(
                &cli.jsonl,
                &serde_json::json!({
                    "ts": rfc3339_now(),
                    "reader": cli.name,
                    "block_number": entry.block_number,
                    "block_hash": format!("{:?}", entry.block_hash),
                    "object_key": entry.object_key,
                    "result": "fetch_err",
                    "error": format!("{err}"),
                }),
            );
            return Err(err);
        }
    };
    metrics::counter!(FOLLOW_BYTES_TOTAL).increment(bytes.len() as u64);
    if let Some(vk) = verifying_key {
        let sig_key = format!("{}.sig", entry.object_key);
        let sig = if let Some(base) = &cli.base_url {
            http_get(http, base, &sig_key).await?
        } else {
            s3_get(s3, &cli.bucket, &sig_key).await?
        };
        if let Err(err) = signing::verify(vk, &bytes, &sig) {
            metrics::counter!(FOLLOW_VALIDATE_TOTAL, "result" => "sig_err").increment(1);
            write_jsonl(
                &cli.jsonl,
                &serde_json::json!({
                    "ts": rfc3339_now(),
                    "reader": cli.name,
                    "block_number": entry.block_number,
                    "block_hash": format!("{:?}", entry.block_hash),
                    "object_key": entry.object_key,
                    "result": "sig_err",
                    "error": format!("{err}"),
                }),
            );
            return Err(eyre::eyre!("witness sig verify failed: {err}"));
        }
    }
    let fetch_elapsed = fetch_started.elapsed();
    metrics::histogram!(FOLLOW_FETCH_LATENCY_SECONDS).record(fetch_elapsed.as_secs_f64());

    // Decode + validate on a blocking worker so the runtime stays responsive.
    let validate_started = Instant::now();
    let bytes_len = bytes.len();
    let encoding = Encoding::from_path(&entry.object_key);
    let outcome_res = tokio::task::spawn_blocking(move || -> eyre::Result<_> {
        let bundle = decode_bundle(&bytes, encoding).wrap_err("decode bundle")?;
        validate_bundle(spec, bundle)
    })
    .await
    .wrap_err("validator task panicked")?;
    let validate_elapsed = validate_started.elapsed();
    metrics::histogram!(FOLLOW_VALIDATE_LATENCY_SECONDS).record(validate_elapsed.as_secs_f64());

    let outcome = match outcome_res {
        Ok(o) => o,
        Err(err) => {
            metrics::counter!(FOLLOW_VALIDATE_TOTAL, "result" => "decode_err").increment(1);
            write_jsonl(
                &cli.jsonl,
                &serde_json::json!({
                    "ts": rfc3339_now(),
                    "reader": cli.name,
                    "block_number": entry.block_number,
                    "block_hash": format!("{:?}", entry.block_hash),
                    "object_key": entry.object_key,
                    "fetch_ms": fetch_elapsed.as_millis(),
                    "validate_ms": validate_elapsed.as_millis(),
                    "result": "decode_err",
                    "error": format!("{err}"),
                }),
            );
            return Err(err);
        }
    };
    if outcome.computed_root != outcome.expected_root {
        metrics::counter!(FOLLOW_VALIDATE_TOTAL, "result" => "state_root_err").increment(1);
        write_jsonl(
            &cli.jsonl,
            &serde_json::json!({
                "ts": rfc3339_now(),
                "reader": cli.name,
                "block_number": entry.block_number,
                "block_hash": format!("{:?}", entry.block_hash),
                "object_key": entry.object_key,
                "fetch_ms": fetch_elapsed.as_millis(),
                "validate_ms": validate_elapsed.as_millis(),
                "result": "state_root_err",
                "computed": format!("{:?}", outcome.computed_root),
                "expected": format!("{:?}", outcome.expected_root),
            }),
        );
        return Err(eyre::eyre!(
            "state root mismatch: computed {:?} expected {:?}",
            outcome.computed_root,
            outcome.expected_root,
        ));
    }

    // Cursor advances ONLY after a successful root recomputation. Order:
    //   1. mutate in-memory cursor
    //   2. save atomically to disk
    //   3. emit metric/jsonl
    //
    // If step 2 fails we still update the gauge, but the next restart will
    // replay this block — that's strictly safer than skipping.
    cursor.last_block_number = entry.block_number;
    cursor.last_block_hash = entry.block_hash;
    cursor.blocks_validated += 1;
    cursor.updated_at = rfc3339_now();
    if let Err(err) = cursor.save(&cli.cursor) {
        warn!(reader = %cli.name, ?err, "cursor save failed");
    }

    let e2e = e2e_started.elapsed();
    let now_secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    metrics::counter!(FOLLOW_VALIDATE_TOTAL, "result" => "ok").increment(1);
    metrics::histogram!(FOLLOW_E2E_LATENCY_SECONDS).record(e2e.as_secs_f64());
    metrics::gauge!(FOLLOW_VALIDATED_BLOCK).set(entry.block_number as f64);
    metrics::gauge!(FOLLOW_LAST_SUCCESS_TS).set(now_secs as f64);
    write_jsonl(
        &cli.jsonl,
        &serde_json::json!({
            "ts": rfc3339_now(),
            "reader": cli.name,
            "block_number": entry.block_number,
            "block_hash": format!("{:?}", entry.block_hash),
            "object_key": entry.object_key,
            "size_bytes": bytes_len,
            "fetch_ms": fetch_elapsed.as_millis(),
            "validate_ms": validate_elapsed.as_millis(),
            "e2e_ms": e2e.as_millis(),
            "result": "ok",
        }),
    );
    debug!(
        reader = %cli.name,
        block = entry.block_number,
        fetch_ms = fetch_elapsed.as_millis(),
        validate_ms = validate_elapsed.as_millis(),
        e2e_ms = e2e.as_millis(),
        "validated"
    );
    Ok(())
}

async fn apply_fetch_delay(cli: &Cli) {
    if cli.fetch_delay_ms > 0 {
        tokio::time::sleep(Duration::from_millis(cli.fetch_delay_ms)).await;
    }
}

fn rfc3339_now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn write_jsonl(path: &Path, value: &serde_json::Value) {
    use std::io::Write;
    match std::fs::OpenOptions::new().create(true).append(true).open(path) {
        Ok(mut f) => {
            let mut s = value.to_string();
            s.push('\n');
            let _ = f.write_all(s.as_bytes());
        }
        Err(err) => warn!(?err, "jsonl open failed"),
    }
}

// ---------------------------------------------------------------------------
// Metrics HTTP server (tiny — only /metrics)
// ---------------------------------------------------------------------------

async fn spawn_metrics(addr: SocketAddr) -> eyre::Result<SocketAddr> {
    let handle = PrometheusBuilder::new().install_recorder().wrap_err("install recorder")?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .wrap_err_with(|| format!("bind {addr}"))?;
    let bound = listener.local_addr()?;
    tokio::spawn(async move {
        loop {
            let (stream, _peer) = match listener.accept().await {
                Ok(v) => v,
                Err(err) => {
                    warn!(?err, "metrics accept failed");
                    continue;
                }
            };
            let io = TokioIo::new(stream);
            let handle = handle.clone();
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |_req: hyper::Request<_>| {
                    let body = handle.render();
                    async move {
                        Ok::<_, std::convert::Infallible>(
                            hyper::Response::builder()
                                .status(200)
                                .header(
                                    hyper::header::CONTENT_TYPE,
                                    "text/plain; version=0.0.4; charset=utf-8",
                                )
                                .body(Full::new(Bytes::from(body)))
                                .unwrap(),
                        )
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(io, service).await;
            });
        }
    });
    Ok(bound)
}

// ---------------------------------------------------------------------------
// S3 / HTTP helpers
// ---------------------------------------------------------------------------

async fn build_s3_client(cli: &Cli) -> aws_sdk_s3::Client {
    let loader = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(cli.region.clone()))
        .endpoint_url(&cli.endpoint);
    let shared = loader.load().await;
    let s3_config = aws_sdk_s3::config::Builder::from(&shared).force_path_style(true).build();
    aws_sdk_s3::Client::from_conf(s3_config)
}

async fn s3_get(client: &aws_sdk_s3::Client, bucket: &str, key: &str) -> eyre::Result<Vec<u8>> {
    let resp = client
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .wrap_err_with(|| format!("GET s3://{bucket}/{key}"))?;
    Ok(resp.body.collect().await?.into_bytes().to_vec())
}

async fn http_get(client: &reqwest::Client, base: &str, key: &str) -> eyre::Result<Vec<u8>> {
    let url = format!("{}/{}", base.trim_end_matches('/'), key);
    let resp = client.get(&url).send().await.wrap_err_with(|| format!("GET {url}"))?;
    if !resp.status().is_success() {
        eyre::bail!("GET {url}: HTTP {}", resp.status());
    }
    Ok(resp.bytes().await?.to_vec())
}

