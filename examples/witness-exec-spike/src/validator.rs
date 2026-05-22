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

#[path = "signing.rs"]
mod signing;
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

    /// CDN / HTTP base URL (e.g. https://cdn.example.com). When set, fetches
    /// `{base_url}/{key}` over plain HTTPS instead of using the S3 API.
    #[arg(long, env = "WITNESS_BASE_URL")]
    base_url: Option<String>,

    /// Path to the 32-byte ed25519 public key. When set, the validator will
    /// fetch `<key>.sig` and reject the witness unless the signature verifies.
    #[arg(long, env = "WITNESS_PUBKEY")]
    pubkey: Option<PathBuf>,

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

    // ---------- 1. Fetch (+ optional signature) ----------
    let verifying_key = match &cli.pubkey {
        Some(p) => Some(signing::load_verifying_key(p)?),
        None => None,
    };

    let t_fetch = Instant::now();
    let (raw, sig_bytes, source_path) = if let Some(local) = &cli.local {
        let bytes = std::fs::read(local).wrap_err_with(|| format!("read {}", local.display()))?;
        let sig = if verifying_key.is_some() {
            let sig_path = local.with_extension(
                local
                    .extension()
                    .map(|e| format!("{}.sig", e.to_string_lossy()))
                    .unwrap_or_default(),
            );
            Some(
                std::fs::read(&sig_path)
                    .wrap_err_with(|| format!("read {}", sig_path.display()))?,
            )
        } else {
            None
        };
        (bytes, sig, local.to_string_lossy().into_owned())
    } else if let Some(base) = &cli.base_url {
        let key = cli.key.clone().ok_or_eyre("--key required for --base-url")?;
        let (bytes, sig) = fetch_from_http(base, &key, verifying_key.is_some())?;
        (bytes, sig, key)
    } else {
        let key = cli.key.clone().ok_or_eyre("--key required")?;
        let (bytes, sig) = fetch_from_s3(&cli, verifying_key.is_some())?;
        (bytes, sig, key)
    };
    let fetch_elapsed = t_fetch.elapsed();
    let encoding = Encoding::from_path(&source_path);
    println!(
        "[1/3] fetch:    {:>7.3}s  ({:.2} MiB, encoding={:?}, signed={})",
        fetch_elapsed.as_secs_f64(),
        raw.len() as f64 / (1024.0 * 1024.0),
        encoding,
        sig_bytes.is_some(),
    );

    // Verify signature BEFORE decoding — refuses to allocate a 3.5MiB bundle for
    // an unsigned blob.
    if let (Some(key), Some(sig)) = (&verifying_key, &sig_bytes) {
        signing::verify(key, &raw, sig).wrap_err("signature verify")?;
        println!("        sig OK");
    } else if verifying_key.is_some() {
        eyre::bail!("--pubkey set but no signature fetched");
    }

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

/// Returns `(witness_bytes, optional_signature_bytes)`. The signature is only
/// fetched when `fetch_sig == true`.
fn fetch_from_s3(cli: &Cli, fetch_sig: bool) -> eyre::Result<(Vec<u8>, Option<Vec<u8>>)> {
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

        let bytes = {
            let resp = client
                .get_object()
                .bucket(&bucket)
                .key(&key)
                .send()
                .await
                .wrap_err_with(|| format!("GET s3://{bucket}/{key}"))?;
            resp.body.collect().await.wrap_err("collect body")?.into_bytes().to_vec()
        };
        let sig = if fetch_sig {
            let sk = format!("{key}.sig");
            let resp = client
                .get_object()
                .bucket(&bucket)
                .key(&sk)
                .send()
                .await
                .wrap_err_with(|| format!("GET s3://{bucket}/{sk}"))?;
            Some(resp.body.collect().await.wrap_err("collect sig")?.into_bytes().to_vec())
        } else {
            None
        };
        Ok::<_, eyre::Report>((bytes, sig))
    })
}

/// Plain-HTTP fetch (for CDN paths). Concurrent fetch of object + .sig over one
/// reqwest client (connection pool, HTTP/2).
fn fetch_from_http(
    base: &str,
    key: &str,
    fetch_sig: bool,
) -> eyre::Result<(Vec<u8>, Option<Vec<u8>>)> {
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().worker_threads(2).build()?;
    rt.block_on(async move {
        // Persistent client = connection pool + keep-alive. HTTP/2 is negotiated
        // via ALPN if the workspace's reqwest features enable it.
        let client = reqwest::Client::builder()
            .pool_idle_timeout(std::time::Duration::from_secs(90))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        let bytes_fut = http_get(&client, base, key);
        let sig_fut = async {
            if fetch_sig {
                Ok(Some(http_get(&client, base, &format!("{key}.sig")).await?))
            } else {
                Ok::<Option<Vec<u8>>, eyre::Report>(None)
            }
        };
        let (b, s) = tokio::try_join!(bytes_fut, sig_fut)?;
        Ok::<_, eyre::Report>((b, s))
    })
}

async fn http_get(client: &reqwest::Client, base: &str, key: &str) -> eyre::Result<Vec<u8>> {
    let url = format!("{}/{}", base.trim_end_matches('/'), key);
    let resp = client.get(&url).send().await.wrap_err_with(|| format!("GET {url}"))?;
    if !resp.status().is_success() {
        eyre::bail!("GET {url}: HTTP {}", resp.status());
    }
    Ok(resp.bytes().await?.to_vec())
}
