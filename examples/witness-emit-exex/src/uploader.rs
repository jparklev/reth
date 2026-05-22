//! `witness-uploader` — watches the ExEx emit directory, signs each new
//! `<num>-<hash>.witness.zst`, uploads it to S3, and atomically replaces the
//! published `head.json` manifest.
//!
//! Companion to `reth-witness-emit-node`. Same wire format and manifest schema
//! as `witness-publisher` from the sidecar spike — readers (`witness-stream` /
//! `witness-validator`) need no changes.
//!
//! Stale handling: `*.witness.zst.stale` files (renamed by the ExEx on reorg)
//! are rewound out of the manifest if they had been published, then deleted.

use clap::Parser;
use eyre::{eyre, Context};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{sync::Mutex, time::timeout};
use tracing::{error, info, warn};

#[path = "bundle.rs"]
mod bundle;
#[path = "uploader_live_manifest.rs"]
mod live_manifest;
#[path = "metrics_server.rs"]
mod metrics_server;
#[path = "uploader_signing.rs"]
mod signing;

use live_manifest::{LiveManifest, ManifestEntry};

#[derive(Parser, Debug, Clone)]
#[command(about = "Upload witness bundles produced by the witness-emit ExEx")]
struct Cli {
    /// Directory to watch. New `<num>-<hash>.witness.zst` files appear here.
    #[arg(long, env = "WITNESS_EMIT_DIR")]
    emit_dir: PathBuf,
    /// Polling interval (no inotify dependency).
    #[arg(long, default_value = "500")]
    poll_ms: u64,
    /// Path to 32-byte ed25519 signing seed.
    #[arg(long, env = "WITNESS_SIGNING_KEY")]
    signing_key: PathBuf,
    /// Writer ID; matches `writer-keys/<id>.pub` in the bucket.
    #[arg(long, env = "WITNESS_WRITER_ID", default_value = "primary")]
    writer_id: String,
    /// S3 endpoint, e.g. `https://fsn1.your-objectstorage.com`.
    #[arg(long, env = "S3_ENDPOINT")]
    endpoint: String,
    /// Bucket name.
    #[arg(long, env = "S3_BUCKET")]
    bucket: String,
    /// Region.
    #[arg(long, env = "S3_REGION", default_value = "fsn1")]
    region: String,
    /// Prefix under which witnesses + head.json live.
    #[arg(long, default_value = "witnesses/exex")]
    prefix: String,
    /// Stats log file: append-only JSONL per uploaded block.
    #[arg(long, default_value = "/var/lib/witness-emit/uploader-stats.jsonl")]
    stats: PathBuf,
    /// Cursor file (last uploaded `block_number` — for restart deduplication).
    #[arg(long, default_value = "/var/lib/witness-emit/uploader-cursor.json")]
    cursor: PathBuf,
    /// Max retries per put.
    #[arg(long, default_value = "3")]
    upload_retries: u32,
    /// Delete local file after successful upload (and after manifest publish).
    #[arg(long, default_value = "true")]
    delete_after_upload: bool,
    /// Make uploaded objects publicly readable (so a CDN can serve them).
    #[arg(long, default_value = "true")]
    public_read: bool,
    /// Bind a Prometheus `/metrics` endpoint here. `0.0.0.0:0` disables.
    #[arg(long, default_value = "127.0.0.1:19003")]
    metrics_addr: SocketAddr,
    /// Cloudflare R2 endpoint. When all four R2 flags are set, every witness
    /// + signature is dual-uploaded to R2 as a CDN-fronted edge cache. R2
    /// failures NEVER block the Hetzner write or the manifest update;
    /// Hetzner remains source of truth. Leave unset to disable dual-write.
    #[arg(long, env = "R2_ENDPOINT")]
    r2_endpoint: Option<String>,
    /// Cloudflare R2 bucket name.
    #[arg(long, env = "R2_BUCKET")]
    r2_bucket: Option<String>,
    /// R2 access key id (NOT the global AWS_ACCESS_KEY_ID — R2 uses its
    /// own credentials).
    #[arg(long, env = "R2_ACCESS_KEY_ID")]
    r2_access_key_id: Option<String>,
    /// R2 secret access key.
    #[arg(long, env = "R2_SECRET_ACCESS_KEY")]
    r2_secret_access_key: Option<String>,
    /// R2 region — always `auto`. Exposed as a flag for parity.
    #[arg(long, env = "R2_REGION", default_value = "auto")]
    r2_region: String,
}

const UPLOAD_TOTAL: &str = "witness_uploader_upload_total";
const UPLOAD_LATENCY_SECONDS: &str = "witness_uploader_upload_latency_seconds";
const UPLOAD_TOTAL_LATENCY_SECONDS: &str = "witness_uploader_total_latency_seconds";
const UPLOAD_SIZE_BYTES: &str = "witness_uploader_size_bytes";
const UPLOAD_RETRIES_TOTAL: &str = "witness_uploader_retries_total";
const UPLOAD_HIGHEST_BLOCK: &str = "witness_uploader_highest_block";
const UPLOAD_INBOX_DEPTH: &str = "witness_uploader_inbox_depth";
const UPLOAD_STALE_HANDLED_TOTAL: &str = "witness_uploader_stale_handled_total";
const R2_UPLOAD_TOTAL: &str = "witness_uploader_r2_upload_total";
const R2_UPLOAD_LATENCY_SECONDS: &str = "witness_uploader_r2_upload_latency_seconds";

fn describe_metrics() {
    use metrics::{describe_counter, describe_gauge, describe_histogram, Unit};
    describe_counter!(UPLOAD_TOTAL, "Witness uploads, labelled result=ok|err");
    describe_counter!(UPLOAD_RETRIES_TOTAL, "S3 put retry attempts");
    describe_counter!(UPLOAD_STALE_HANDLED_TOTAL, "Stale files processed (manifest rewinds)");
    describe_histogram!(UPLOAD_LATENCY_SECONDS, Unit::Seconds, "S3 PUT latency per witness");
    describe_histogram!(
        UPLOAD_TOTAL_LATENCY_SECONDS,
        Unit::Seconds,
        "Total file-pickup -> manifest-published latency"
    );
    describe_histogram!(UPLOAD_SIZE_BYTES, Unit::Bytes, "Encoded witness size per upload");
    describe_gauge!(UPLOAD_HIGHEST_BLOCK, "Highest block number whose witness has been published");
    describe_gauge!(UPLOAD_INBOX_DEPTH, "Number of witness files waiting to be uploaded");
    describe_counter!(
        R2_UPLOAD_TOTAL,
        "R2 dual-write outcomes (labelled result=ok|err). Hetzner stays source of truth regardless."
    );
    describe_histogram!(
        R2_UPLOAD_LATENCY_SECONDS,
        Unit::Seconds,
        "R2 dual-write latency per witness+sig pair"
    );
}

fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    if let Some(parent) = cli.cursor.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    if let Some(parent) = cli.stats.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    let signing_key = signing::load_signing_key(&cli.signing_key)
        .wrap_err_with(|| format!("load signing key {}", cli.signing_key.display()))?;
    info!(
        writer_id = %cli.writer_id,
        pubkey = %hex::encode(signing_key.verifying_key().to_bytes()),
        emit_dir = %cli.emit_dir.display(),
        bucket = %cli.bucket,
        prefix = %cli.prefix,
        "uploader starting"
    );

    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().worker_threads(4).build()?;
    rt.block_on(run(cli, signing_key))
}

async fn run(cli: Cli, signing_key: ed25519_dalek::SigningKey) -> eyre::Result<()> {
    if let Err(err) = metrics_server::install_and_serve(cli.metrics_addr).await {
        warn!(?err, addr = %cli.metrics_addr, "metrics server failed to start");
    } else {
        describe_metrics();
    }

    let s3 = build_s3_client(&cli).await;

    // R2 dual-write is opt-in: enabled only when all four R2 flags are set.
    // We construct the client up front so per-block uploads don't pay the
    // credential-resolution cost each tick.
    let r2 = match maybe_build_r2_client(&cli).await {
        Some(client) => {
            info!(bucket = %cli.r2_bucket.as_deref().unwrap_or(""), "R2 dual-write enabled");
            Some(Arc::new(client))
        }
        None => {
            info!("R2 dual-write disabled (set R2_ENDPOINT/R2_BUCKET/R2_ACCESS_KEY_ID/R2_SECRET_ACCESS_KEY to enable)");
            None
        }
    };

    // Load the existing manifest from S3, or start empty.
    let manifest = match s3_get(&s3, &cli.bucket, &format!("{}/head.json", cli.prefix)).await {
        Ok(bytes) => serde_json::from_slice::<LiveManifest>(&bytes)
            .unwrap_or_else(|_| LiveManifest::empty(&cli.writer_id)),
        Err(_) => LiveManifest::empty(&cli.writer_id),
    };
    let manifest = Arc::new(Mutex::new(manifest));

    let mut seen_uploaded: HashSet<PathBuf> = HashSet::new();
    let poll = Duration::from_millis(cli.poll_ms);

    loop {
        // Pick up stale files first so we can rewind the manifest before
        // appending newer blocks.
        if let Err(err) = handle_stale(&cli, &s3, manifest.clone()).await {
            warn!(?err, "handle_stale failed");
        }

        // Find candidate `<num>-<hash>.witness.zst` files (NOT `.tmp` or
        // `.stale`), sort by block number ascending.
        let entries = match list_witnesses(&cli.emit_dir) {
            Ok(v) => v,
            Err(err) => {
                warn!(?err, "list_witnesses failed");
                tokio::time::sleep(poll).await;
                continue;
            }
        };

        // Inbox depth is observed AFTER the stale-pickup pass so it reflects
        // the next pass's work, not the previous pass.
        metrics::gauge!(UPLOAD_INBOX_DEPTH).set(entries.len() as f64);

        let mut uploaded_this_pass = 0usize;
        for (block_number, block_hash, path) in entries {
            if seen_uploaded.contains(&path) {
                continue;
            }
            match upload_one(
                &cli,
                &s3,
                r2.as_ref(),
                &signing_key,
                manifest.clone(),
                block_number,
                block_hash,
                &path,
            )
            .await
            {
                Ok(()) => {
                    metrics::counter!(UPLOAD_TOTAL, "result" => "ok").increment(1);
                    metrics::gauge!(UPLOAD_HIGHEST_BLOCK).set(block_number as f64);
                    seen_uploaded.insert(path.clone());
                    if cli.delete_after_upload {
                        if let Err(err) = std::fs::remove_file(&path) {
                            warn!(?err, ?path, "delete after upload failed");
                        } else {
                            seen_uploaded.remove(&path);
                        }
                    }
                    persist_cursor(&cli.cursor, block_number);
                    uploaded_this_pass += 1;
                }
                Err(err) => {
                    metrics::counter!(UPLOAD_TOTAL, "result" => "err").increment(1);
                    error!(block = block_number, ?err, "upload failed");
                    break; // back off; try again next tick
                }
            }
        }

        if uploaded_this_pass == 0 {
            tokio::time::sleep(poll).await;
        }
    }
}

fn list_witnesses(dir: &Path) -> eyre::Result<Vec<(u64, String, PathBuf)>> {
    let mut out = Vec::new();
    for ent in std::fs::read_dir(dir).wrap_err_with(|| format!("read_dir {}", dir.display()))? {
        let ent = ent?;
        let path = ent.path();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        if !name.ends_with(".witness.zst") {
            continue;
        }
        // Form: `<num>-<hash>.witness.zst`
        let stem = name.trim_end_matches(".witness.zst");
        let (num_s, hash_s) = match stem.split_once('-') {
            Some(p) => p,
            None => continue,
        };
        let Ok(num) = num_s.parse::<u64>() else { continue };
        out.push((num, hash_s.to_string(), path));
    }
    out.sort_by_key(|(n, _, _)| *n);
    Ok(out)
}

async fn upload_one(
    cli: &Cli,
    s3: &aws_sdk_s3::Client,
    r2: Option<&Arc<aws_sdk_s3::Client>>,
    signing_key: &ed25519_dalek::SigningKey,
    manifest: Arc<Mutex<LiveManifest>>,
    block_number: u64,
    block_hash_hex: String,
    path: &Path,
) -> eyre::Result<()> {
    let started = Instant::now();
    let bytes = std::fs::read(path).wrap_err_with(|| format!("read {}", path.display()))?;
    let size_bytes = bytes.len() as u64;
    let sha = hex::encode(Sha256::digest(&bytes));

    let sig = signing::sign(signing_key, &bytes);
    let signed_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let witness_key = format!("{}/{}-{}.witness.zst", cli.prefix, block_number, block_hash_hex);
    let sig_key = format!("{witness_key}.sig");

    s3_put_with_retry(
        s3,
        &cli.bucket,
        &witness_key,
        bytes.clone(),
        cli.upload_retries,
        cli.public_read,
    )
    .await?;
    s3_put_with_retry(s3, &cli.bucket, &sig_key, sig.to_vec(), cli.upload_retries, cli.public_read)
        .await?;
    let upload_elapsed = started.elapsed();

    // R2 dual-write: fire-and-forget. Hetzner is source of truth; the manifest
    // update below races nothing against R2. If R2 fails we log + count, but
    // the head.json still publishes against the Hetzner copy.
    let r2_upload_ms = if let (Some(client), Some(bucket)) = (r2, cli.r2_bucket.as_deref()) {
        let r2_started = Instant::now();
        let client = client.clone();
        let bucket = bucket.to_string();
        let wk = witness_key.clone();
        let sk = sig_key.clone();
        let wb = bytes.clone();
        let sb = sig.to_vec();
        let retries = cli.upload_retries;
        // We DO `await` here so the per-block stats line includes r2 timing.
        // Hetzner has already ACKed so the only loss-of-ordering risk is that
        // R2 lands after the manifest publishes, which is fine: readers
        // hitting R2 before it's warm just fall back to Hetzner.
        let res = tokio::spawn(async move {
            // R2 buckets created via the Cloudflare dashboard generally have
            // the `r2.dev` public hostname turned on, so we don't set
            // `public_read=true` here (R2 doesn't honour the AWS ACL header
            // anyway — it returns InvalidArgument). Visibility is bucket-wide.
            s3_put_with_retry(&client, &bucket, &wk, wb, retries, false).await?;
            s3_put_with_retry(&client, &bucket, &sk, sb, retries, false).await?;
            eyre::Ok(())
        })
        .await;
        let elapsed = r2_started.elapsed();
        match res {
            Ok(Ok(())) => {
                metrics::counter!(R2_UPLOAD_TOTAL, "result" => "ok").increment(1);
                metrics::histogram!(R2_UPLOAD_LATENCY_SECONDS).record(elapsed.as_secs_f64());
                Some(elapsed.as_millis())
            }
            Ok(Err(err)) => {
                metrics::counter!(R2_UPLOAD_TOTAL, "result" => "err").increment(1);
                warn!(block = block_number, ?err, "R2 dual-write failed (Hetzner unaffected)");
                None
            }
            Err(err) => {
                metrics::counter!(R2_UPLOAD_TOTAL, "result" => "err").increment(1);
                warn!(block = block_number, ?err, "R2 dual-write task panicked");
                None
            }
        }
    } else {
        None
    };

    // The on-disk filename uses `{block_hash:x}` (no 0x), but the manifest
    // wants a real B256. Parse it back.
    let block_hash = parse_b256_hex(&block_hash_hex)?;
    let parent_hash = peek_parent_hash(path).unwrap_or_else(|err| {
        warn!(?err, ?path, "could not peek parent hash; recording 0x0");
        alloy_primitives::B256::ZERO
    });

    let entry = ManifestEntry {
        block_number,
        block_hash,
        parent_hash,
        object_key: witness_key.clone(),
        content_sha256: sha.clone(),
        signed_at: signed_at.clone(),
        size_bytes,
    };

    let manifest_bytes = {
        let mut m = manifest.lock().await;
        m.push_front(entry.clone());
        serde_json::to_vec_pretty(&*m)?
    };
    let manifest_sig = signing::sign(signing_key, &manifest_bytes);
    let head_key = format!("{}/head.json", cli.prefix);
    let head_sig_key = format!("{head_key}.sig");
    s3_put_with_retry(
        s3,
        &cli.bucket,
        &head_sig_key,
        manifest_sig.to_vec(),
        cli.upload_retries,
        cli.public_read,
    )
    .await?;
    s3_put_with_retry(
        s3,
        &cli.bucket,
        &head_key,
        manifest_bytes,
        cli.upload_retries,
        cli.public_read,
    )
    .await?;

    let total = started.elapsed();
    metrics::histogram!(UPLOAD_LATENCY_SECONDS).record(upload_elapsed.as_secs_f64());
    metrics::histogram!(UPLOAD_TOTAL_LATENCY_SECONDS).record(total.as_secs_f64());
    metrics::histogram!(UPLOAD_SIZE_BYTES).record(size_bytes as f64);
    let stats_line = serde_json::json!({
        "ts": signed_at,
        "block_number": block_number,
        "block_hash": format!("{:?}", block_hash),
        "object_key": witness_key,
        "size_bytes": size_bytes,
        "upload_ms": upload_elapsed.as_millis(),
        "total_ms": total.as_millis(),
        "sha256": sha,
        "r2_upload_ms": r2_upload_ms,
    });
    append_stats(&cli.stats, &stats_line);
    info!(
        block = block_number,
        size_kb = size_bytes / 1024,
        upload_ms = upload_elapsed.as_millis(),
        "uploaded"
    );
    Ok(())
}

/// Read just enough of the witness file to recover the parent hash. The bundle
/// embeds the RLP-encoded header, so we decode that.
fn peek_parent_hash(path: &Path) -> eyre::Result<alloy_primitives::B256> {
    use alloy_consensus::Header;
    use alloy_rlp::Decodable;

    let bytes = std::fs::read(path)?;
    // Decompress the bincode envelope.
    let raw = zstd::stream::decode_all(bytes.as_slice())?;
    let bundle: bundle::WitnessBundle = bincode::deserialize(&raw)?;
    let mut header_bytes = bundle.header.as_ref();
    let header = Header::decode(&mut header_bytes)?;
    Ok(header.parent_hash)
}

fn parse_b256_hex(s: &str) -> eyre::Result<alloy_primitives::B256> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() != 64 {
        return Err(eyre!("bad hash hex len {}: {s}", s.len()));
    }
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(s, &mut bytes)?;
    Ok(alloy_primitives::B256::from(bytes))
}

async fn handle_stale(
    cli: &Cli,
    _s3: &aws_sdk_s3::Client,
    manifest: Arc<Mutex<LiveManifest>>,
) -> eyre::Result<()> {
    let dir = &cli.emit_dir;
    let read = std::fs::read_dir(dir).wrap_err_with(|| format!("read_dir {}", dir.display()))?;
    let mut rewind_to: Option<u64> = None;
    let mut to_delete: Vec<PathBuf> = Vec::new();
    for ent in read {
        let ent = ent?;
        let path = ent.path();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        if !name.ends_with(".witness.zst.stale") {
            continue;
        }
        let stem = name.trim_end_matches(".witness.zst.stale");
        if let Some((num_s, _hash_s)) = stem.split_once('-') &&
            let Ok(num) = num_s.parse::<u64>()
        {
            rewind_to = Some(match rewind_to {
                Some(r) => r.min(num.saturating_sub(1)),
                None => num.saturating_sub(1),
            });
        }
        to_delete.push(path);
    }
    if let Some(rw) = rewind_to {
        let mut m = manifest.lock().await;
        m.rewind_above(rw);
        warn!(rewound_above = rw, "rewound manifest due to stale files");
    }
    let stale_count = to_delete.len();
    for p in to_delete {
        if let Err(err) = std::fs::remove_file(&p) {
            warn!(?err, ?p, "delete stale failed");
        }
    }
    if stale_count > 0 {
        metrics::counter!(UPLOAD_STALE_HANDLED_TOTAL).increment(stale_count as u64);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// S3 helpers
// ---------------------------------------------------------------------------

async fn build_s3_client(cli: &Cli) -> aws_sdk_s3::Client {
    let loader = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(cli.region.clone()))
        .endpoint_url(&cli.endpoint);
    let shared = loader.load().await;
    let s3_config = aws_sdk_s3::config::Builder::from(&shared).force_path_style(true).build();
    aws_sdk_s3::Client::from_conf(s3_config)
}

/// Build an R2 client only if all four R2 flags are populated. R2 uses its
/// own credentials (not AWS env vars) so we feed them explicitly via
/// `Credentials::new`.
async fn maybe_build_r2_client(cli: &Cli) -> Option<aws_sdk_s3::Client> {
    let (endpoint, bucket, akid, sak) = match (
        cli.r2_endpoint.as_deref(),
        cli.r2_bucket.as_deref(),
        cli.r2_access_key_id.as_deref(),
        cli.r2_secret_access_key.as_deref(),
    ) {
        (Some(e), Some(b), Some(a), Some(s)) => (e, b, a, s),
        _ => return None,
    };
    let _ = bucket; // bucket is used inside upload_one, not the client.

    let creds = aws_credential_types::Credentials::new(
        akid.to_string(),
        sak.to_string(),
        None,
        None,
        "uploader-r2",
    );
    let loader = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(cli.r2_region.clone()))
        .endpoint_url(endpoint)
        .credentials_provider(creds);
    let shared = loader.load().await;
    let s3_config = aws_sdk_s3::config::Builder::from(&shared).force_path_style(true).build();
    Some(aws_sdk_s3::Client::from_conf(s3_config))
}

async fn s3_get(client: &aws_sdk_s3::Client, bucket: &str, key: &str) -> eyre::Result<Vec<u8>> {
    let resp = client.get_object().bucket(bucket).key(key).send().await?;
    let bytes = resp.body.collect().await?.into_bytes().to_vec();
    Ok(bytes)
}

async fn s3_put_with_retry(
    client: &aws_sdk_s3::Client,
    bucket: &str,
    key: &str,
    bytes: Vec<u8>,
    max_retries: u32,
    public_read: bool,
) -> eyre::Result<()> {
    let mut attempt = 0u32;
    loop {
        let mut req = client
            .put_object()
            .bucket(bucket)
            .key(key)
            .body(aws_sdk_s3::primitives::ByteStream::from(bytes.clone()));
        if public_read {
            req = req.acl(aws_sdk_s3::types::ObjectCannedAcl::PublicRead);
        }
        let res = timeout(Duration::from_secs(20), req.send()).await;
        match res {
            Ok(Ok(_)) => return Ok(()),
            Ok(Err(e)) => {
                metrics::counter!(UPLOAD_RETRIES_TOTAL, "kind" => "error").increment(1);
                if attempt >= max_retries {
                    return Err(eyre!("s3 put {key}: {e}"));
                }
                warn!(key, attempt, err = %e, "s3 put failed; retrying");
            }
            Err(_) => {
                metrics::counter!(UPLOAD_RETRIES_TOTAL, "kind" => "timeout").increment(1);
                if attempt >= max_retries {
                    return Err(eyre!("s3 put {key}: timeout"));
                }
                warn!(key, attempt, "s3 put timeout; retrying");
            }
        }
        tokio::time::sleep(Duration::from_millis(200 * (1u64 << attempt.min(4)))).await;
        attempt += 1;
    }
}

fn persist_cursor(path: &Path, cursor: u64) {
    if let Err(e) = std::fs::write(path, format!("{cursor}\n")) {
        warn!(err = %e, "persist cursor failed");
    }
}

fn append_stats(path: &Path, line: &serde_json::Value) {
    use std::io::Write;
    let mut f = match std::fs::OpenOptions::new().create(true).append(true).open(path) {
        Ok(f) => f,
        Err(e) => {
            warn!(err = %e, "stats open failed");
            return;
        }
    };
    let mut s = line.to_string();
    s.push('\n');
    let _ = f.write_all(s.as_bytes());
}
