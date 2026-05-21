//! Validate one block from a witness fetched from S3 (or local file).
//!
//! Encoding is auto-detected from path suffix:
//!   - `*.json`             → pretty JSON envelope (v0)
//!   - `*.zst` / `*.bin.zst` → bincode + zstd (v1)
//!
//! See `validate_core::validate_bundle` for the actual pipeline.

use clap::Parser;
use eyre::{Context, OptionExt};
use reth_chainspec::{ChainSpec, MAINNET};
use std::{path::PathBuf, sync::Arc, time::Instant};

#[path = "validate_core.rs"]
mod validate_core;
use validate_core::{decode_bundle, validate_bundle, Encoding};

#[derive(Parser, Debug)]
#[command(about = "Validate a block from a witness fetched from S3")]
struct Cli {
    /// Hetzner endpoint, e.g. https://fsn1.your-objectstorage.com
    #[arg(long, env = "S3_ENDPOINT")]
    endpoint: Option<String>,
    /// Bucket name.
    #[arg(long, env = "S3_BUCKET")]
    bucket: Option<String>,
    /// Region (Hetzner: fsn1).
    #[arg(long, env = "S3_REGION", default_value = "fsn1")]
    region: String,
    /// Key (e.g. witnesses/0xabc...def.zst).
    #[arg(long, env = "S3_KEY")]
    key: Option<String>,

    /// Alternatively, read directly from a local file.
    #[arg(long, conflicts_with_all = ["endpoint", "bucket", "key"])]
    local: Option<PathBuf>,

    /// Chain (mainnet only).
    #[arg(long, default_value = "mainnet")]
    chain: String,
}

fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    if cli.chain != "mainnet" {
        eyre::bail!("only mainnet supported in spike");
    }
    let spec: Arc<ChainSpec> = MAINNET.clone();

    let overall_start = Instant::now();

    // ---------- 1. Fetch ----------
    let t_fetch = Instant::now();
    let (raw, source_path) = if let Some(local) = &cli.local {
        let bytes = std::fs::read(local).wrap_err_with(|| format!("read {}", local.display()))?;
        (bytes, local.to_string_lossy().into_owned())
    } else {
        let bytes = fetch_from_s3(&cli)?;
        (bytes, cli.key.clone().unwrap_or_default())
    };
    let fetch_elapsed = t_fetch.elapsed();
    let encoding = Encoding::from_path(&source_path);
    println!(
        "[1/3] fetch:    {:>7.3}s  ({:.2} MiB, encoding={:?})",
        fetch_elapsed.as_secs_f64(),
        raw.len() as f64 / (1024.0 * 1024.0),
        encoding,
    );

    // ---------- 2. Decode envelope ----------
    let t_envelope = Instant::now();
    let bundle = decode_bundle(&raw, encoding).wrap_err("decode envelope")?;
    let envelope_elapsed = t_envelope.elapsed();
    println!(
        "[2/3] envelope: {:>7.3}s  (block #{}, state nodes={}, codes={}, ancestors={})",
        envelope_elapsed.as_secs_f64(),
        bundle.block_number,
        bundle.witness.state.len(),
        bundle.witness.codes.len(),
        bundle.witness.headers.len(),
    );

    // ---------- 3. Validate (decode block, reveal, execute, root) ----------
    let outcome = validate_bundle(spec, bundle).wrap_err("validate bundle")?;

    if outcome.computed_root != outcome.expected_root {
        eyre::bail!(
            "STATE-ROOT MISMATCH: got {:?}, expected {:?}",
            outcome.computed_root,
            outcome.expected_root
        );
    }
    println!(
        "[3/3] validate: {:>7.3}s  (decode={:.3}s reveal={:.3}s execute={:.3}s root={:.3}s) txs={} gas={}",
        outcome.timings.total_compute.as_secs_f64(),
        outcome.timings.decode.as_secs_f64(),
        outcome.timings.reveal.as_secs_f64(),
        outcome.timings.execute.as_secs_f64(),
        outcome.timings.root.as_secs_f64(),
        outcome.tx_count,
        outcome.gas_used,
    );
    println!();
    println!("OK: state root {} matches header", outcome.computed_root);
    println!("OK: header hash {}", outcome.block_hash);

    let total = overall_start.elapsed();
    println!();
    println!("==================================================");
    println!("TOTAL fetch→verify:        {:>7.3}s", total.as_secs_f64());
    println!("  fetch (S3 GET):          {:>7.3}s", fetch_elapsed.as_secs_f64());
    println!("  envelope decode:         {:>7.3}s", envelope_elapsed.as_secs_f64());
    println!("  compute (decode→root):   {:>7.3}s", outcome.timings.total_compute.as_secs_f64());
    println!("==================================================");

    Ok(())
}

// ============================================================================
// S3 fetch
// ============================================================================

fn fetch_from_s3(cli: &Cli) -> eyre::Result<Vec<u8>> {
    let endpoint = cli.endpoint.clone().ok_or_eyre("--endpoint required")?;
    let bucket = cli.bucket.clone().ok_or_eyre("--bucket required")?;
    let key = cli.key.clone().ok_or_eyre("--key required")?;

    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().worker_threads(2).build()?;

    rt.block_on(async move {
        let loader = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(cli.region.clone()))
            .endpoint_url(&endpoint);
        let shared = loader.load().await;

        let s3_config = aws_sdk_s3::config::Builder::from(&shared).force_path_style(true).build();
        let client = aws_sdk_s3::Client::from_conf(s3_config);

        let resp = client
            .get_object()
            .bucket(&bucket)
            .key(&key)
            .send()
            .await
            .wrap_err_with(|| format!("GET s3://{bucket}/{key}"))?;
        let bytes = resp.body.collect().await.wrap_err("collect body")?.into_bytes().to_vec();
        Ok::<_, eyre::Report>(bytes)
    })
}
