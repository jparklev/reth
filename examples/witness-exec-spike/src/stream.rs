//! Multi-block streaming validator: prefetch witness N+1 while validating N.
//!
//! Flow:
//! ```
//!   ┌─────────────┐   bounded channel    ┌──────────────┐
//!   │  fetcher    │ ───── (capacity=2) ─▶│  validator   │
//!   │  task       │                      │  task        │
//!   │  (tokio)    │                      │ (spawn_blk)  │
//!   └─────────────┘                      └──────────────┘
//!         │                                    │
//!         ▼                                    ▼
//!     S3 GET ×N                          execute + root × N
//! ```
//!
//! Reports per-block wall-clock for fetch + compute + total, plus aggregate
//! mean / p50 / p99 over the whole run.
//!
//! Optional cross-validation against a prod RPC: for each block hash, query
//! `eth_getBlockByHash` and assert the header's `stateRoot` matches the
//! validator's computed root. If `--rpc` is not set we trust the producer's
//! `expected_state_root` (which it copied straight from the header).

use clap::Parser;
use eyre::{Context, OptionExt};
use reth_chainspec::{ChainSpec, MAINNET};
use serde::{Deserialize, Serialize};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::mpsc;

#[path = "validate_core.rs"]
mod validate_core;
use validate_core::{decode_bundle, validate_bundle, Encoding, ValidationOutcome};

#[derive(Parser, Debug)]
#[command(about = "Stream-validate a list of blocks with prefetch")]
struct Cli {
    /// Hetzner endpoint, e.g. https://fsn1.your-objectstorage.com
    #[arg(long, env = "S3_ENDPOINT")]
    endpoint: String,
    /// Bucket name.
    #[arg(long, env = "S3_BUCKET")]
    bucket: String,
    /// Region (Hetzner: fsn1).
    #[arg(long, env = "S3_REGION", default_value = "fsn1")]
    region: String,
    /// Manifest object key (JSON: { "blocks": [{ "number", "hash", "key" }, ...] }).
    #[arg(long, env = "S3_MANIFEST", default_value = "witnesses/streaming/manifest.json")]
    manifest: String,
    /// Optional Ethereum RPC URL to cross-validate state roots against
    /// (e.g. http://prod-reth:8545). When set, fetches eth_getBlockByHash
    /// and asserts header.state_root matches the computed root.
    #[arg(long, env = "ETH_RPC")]
    rpc: Option<String>,
    /// Prefetch queue depth (channel capacity). Default 2 keeps memory bounded.
    #[arg(long, default_value = "2")]
    prefetch: usize,
    /// Skip the first N blocks in the manifest (useful for warm-up exclusion).
    #[arg(long, default_value = "0")]
    skip: usize,
    /// Stop after this many blocks (0 = all).
    #[arg(long, default_value = "0")]
    limit: usize,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Manifest {
    blocks: Vec<ManifestEntry>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ManifestEntry {
    number: u64,
    hash: alloy_primitives::B256,
    key: String,
}

/// One item carried from fetcher to validator.
struct FetchedItem {
    entry: ManifestEntry,
    bytes: Vec<u8>,
    encoding: Encoding,
    fetch_elapsed: Duration,
    arrived_at: Instant,
}

fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let spec: Arc<ChainSpec> = MAINNET.clone();

    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    rt.block_on(run(cli, spec))
}

async fn run(cli: Cli, spec: Arc<ChainSpec>) -> eyre::Result<()> {
    // 1. Build S3 client + fetch manifest.
    let client = build_s3_client(&cli).await;
    let manifest_bytes = s3_get(&client, &cli.bucket, &cli.manifest)
        .await
        .wrap_err_with(|| format!("fetch manifest s3://{}/{}", cli.bucket, cli.manifest))?;
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes).wrap_err("parse manifest")?;
    let entries: Vec<ManifestEntry> = manifest
        .blocks
        .into_iter()
        .skip(cli.skip)
        .take(if cli.limit == 0 { usize::MAX } else { cli.limit })
        .collect();
    println!("manifest: {} entries (skip={} limit={})", entries.len(), cli.skip, cli.limit);
    if entries.is_empty() {
        eyre::bail!("no entries to validate");
    }

    // 2. Spawn fetcher: pushes fetched bytes into a bounded channel.
    let (tx, mut rx) = mpsc::channel::<eyre::Result<FetchedItem>>(cli.prefetch);
    let bucket = cli.bucket.clone();
    let fetch_entries = entries.clone();
    let client_for_fetch = client.clone();
    let fetcher = tokio::spawn(async move {
        for entry in fetch_entries {
            let started = Instant::now();
            let result = s3_get(&client_for_fetch, &bucket, &entry.key).await.map(|bytes| {
                let encoding = Encoding::from_path(&entry.key);
                FetchedItem {
                    entry: entry.clone(),
                    bytes,
                    encoding,
                    fetch_elapsed: started.elapsed(),
                    arrived_at: Instant::now(),
                }
            });
            if tx.send(result).await.is_err() {
                break;
            }
        }
    });

    // 3. Optional RPC client for cross-validation.
    let rpc_client = cli.rpc.as_ref().map(|url| (reqwest::Client::new(), url.clone()));

    // 4. Validator loop. We run the CPU work in spawn_blocking so the tokio runtime stays
    //    responsive for the prefetcher.
    let mut per_block: Vec<PerBlockStats> = Vec::with_capacity(entries.len());
    let run_started = Instant::now();
    while let Some(result) = rx.recv().await {
        let item = result.wrap_err("fetch")?;
        let entry = item.entry.clone();
        let fetch_elapsed = item.fetch_elapsed;
        let bytes_len = item.bytes.len();
        let arrived = item.arrived_at;

        let spec_clone = spec.clone();
        let bytes = item.bytes;
        let encoding = item.encoding;

        let validate_start = Instant::now();
        let outcome = tokio::task::spawn_blocking(move || -> eyre::Result<ValidationOutcome> {
            let bundle = decode_bundle(&bytes, encoding).wrap_err("decode envelope")?;
            validate_bundle(spec_clone, bundle)
        })
        .await
        .wrap_err("validator task panicked")??;
        let compute_elapsed = validate_start.elapsed();

        if outcome.computed_root != outcome.expected_root {
            eyre::bail!(
                "block {} (#{}): STATE-ROOT MISMATCH bundle: got {:?} expected {:?}",
                outcome.block_hash,
                outcome.block_number,
                outcome.computed_root,
                outcome.expected_root,
            );
        }

        // Cross-validate against prod RPC if configured.
        if let Some((rpc, url)) = &rpc_client {
            let header_root = eth_get_block_state_root(rpc, url, outcome.block_hash)
                .await
                .wrap_err("eth_getBlockByHash")?;
            if header_root != outcome.computed_root {
                eyre::bail!(
                    "block {} (#{}): RPC MISMATCH header.state_root={:?} validator={:?}",
                    outcome.block_hash,
                    outcome.block_number,
                    header_root,
                    outcome.computed_root,
                );
            }
        }

        // wall-clock from when the bytes landed in the channel:
        let wall_clock = arrived.elapsed();
        println!(
            "block #{} {:?}  fetch={:>6.0}ms  compute={:>6.0}ms  wall={:>6.0}ms  txs={} gas={} size={:.2}MiB",
            outcome.block_number,
            outcome.block_hash,
            fetch_elapsed.as_secs_f64() * 1000.0,
            compute_elapsed.as_secs_f64() * 1000.0,
            wall_clock.as_secs_f64() * 1000.0,
            outcome.tx_count,
            outcome.gas_used,
            bytes_len as f64 / (1024.0 * 1024.0),
        );

        per_block.push(PerBlockStats {
            block_number: entry.number,
            fetch: fetch_elapsed,
            compute: compute_elapsed,
            wall_clock,
            bytes: bytes_len,
            tx_count: outcome.tx_count,
            gas_used: outcome.gas_used,
        });
    }
    fetcher.await.ok();

    let run_total = run_started.elapsed();
    print_summary(&per_block, run_total, cli.rpc.is_some());
    Ok(())
}

#[allow(dead_code)] // some fields used only for debugging
#[derive(Clone, Copy, Debug)]
struct PerBlockStats {
    block_number: u64,
    fetch: Duration,
    compute: Duration,
    wall_clock: Duration,
    bytes: usize,
    tx_count: usize,
    gas_used: u64,
}

fn print_summary(per_block: &[PerBlockStats], run_total: Duration, rpc_checked: bool) {
    if per_block.is_empty() {
        return;
    }
    let n = per_block.len();
    let mut fetches: Vec<f64> = per_block.iter().map(|s| s.fetch.as_secs_f64() * 1000.0).collect();
    let mut computes: Vec<f64> =
        per_block.iter().map(|s| s.compute.as_secs_f64() * 1000.0).collect();
    let mut walls: Vec<f64> =
        per_block.iter().map(|s| s.wall_clock.as_secs_f64() * 1000.0).collect();
    fetches.sort_by(|a, b| a.partial_cmp(b).unwrap());
    computes.sort_by(|a, b| a.partial_cmp(b).unwrap());
    walls.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let mean = |v: &[f64]| v.iter().sum::<f64>() / v.len() as f64;
    let pct = |v: &[f64], p: f64| {
        let idx = ((v.len() as f64 - 1.0) * p).round() as usize;
        v[idx.min(v.len() - 1)]
    };

    let total_bytes: u64 = per_block.iter().map(|s| s.bytes as u64).sum();
    let total_gas: u64 = per_block.iter().map(|s| s.gas_used).sum();

    println!();
    println!("==================================================");
    println!("STREAMING SUMMARY  ({} blocks, RPC-cross-check={})", n, rpc_checked);
    println!("  total wall:           {:>8.3}s", run_total.as_secs_f64());
    println!(
        "  per-block fetch (ms): mean={:>6.1}  p50={:>6.1}  p99={:>6.1}",
        mean(&fetches),
        pct(&fetches, 0.50),
        pct(&fetches, 0.99)
    );
    println!(
        "  per-block compute(ms): mean={:>6.1}  p50={:>6.1}  p99={:>6.1}",
        mean(&computes),
        pct(&computes, 0.50),
        pct(&computes, 0.99)
    );
    println!(
        "  per-block wall   (ms): mean={:>6.1}  p50={:>6.1}  p99={:>6.1}",
        mean(&walls),
        pct(&walls, 0.50),
        pct(&walls, 0.99)
    );
    println!("  steady-state throughput: {:.2} blocks/sec", n as f64 / run_total.as_secs_f64());
    println!(
        "  total bytes fetched:  {:.2} MiB  (avg {:.2} MiB/block)",
        total_bytes as f64 / (1024.0 * 1024.0),
        total_bytes as f64 / (1024.0 * 1024.0) / n as f64
    );
    println!("  total gas validated:  {}", total_gas);
    println!("==================================================");
}

// ============================================================================
// S3
// ============================================================================

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
    let bytes = resp.body.collect().await.wrap_err("collect body")?.into_bytes().to_vec();
    Ok(bytes)
}

// ============================================================================
// Eth RPC (just the one method we need)
// ============================================================================

async fn eth_get_block_state_root(
    client: &reqwest::Client,
    url: &str,
    hash: alloy_primitives::B256,
) -> eyre::Result<alloy_primitives::B256> {
    #[derive(Serialize)]
    struct Req<'a> {
        jsonrpc: &'a str,
        id: u32,
        method: &'a str,
        params: (alloy_primitives::B256, bool),
    }
    #[derive(Deserialize)]
    struct Resp {
        result: Option<BlockHeader>,
        error: Option<serde_json::Value>,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct BlockHeader {
        state_root: alloy_primitives::B256,
    }

    let body = Req { jsonrpc: "2.0", id: 1, method: "eth_getBlockByHash", params: (hash, false) };
    let resp: Resp = client
        .post(url)
        .json(&body)
        .send()
        .await
        .wrap_err("rpc send")?
        .json()
        .await
        .wrap_err("rpc parse")?;
    if let Some(err) = resp.error {
        eyre::bail!("rpc error: {err}");
    }
    Ok(resp.result.ok_or_eyre("rpc returned null block")?.state_root)
}
