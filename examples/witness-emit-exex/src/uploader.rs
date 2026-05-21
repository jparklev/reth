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
    let s3 = build_s3_client(&cli).await;

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

        let mut uploaded_this_pass = 0usize;
        for (block_number, block_hash, path) in entries {
            if seen_uploaded.contains(&path) {
                continue;
            }
            match upload_one(
                &cli,
                &s3,
                &signing_key,
                manifest.clone(),
                block_number,
                block_hash,
                &path,
            )
            .await
            {
                Ok(()) => {
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

    s3_put_with_retry(s3, &cli.bucket, &witness_key, bytes, cli.upload_retries, cli.public_read)
        .await?;
    s3_put_with_retry(s3, &cli.bucket, &sig_key, sig.to_vec(), cli.upload_retries, cli.public_read)
        .await?;
    let upload_elapsed = started.elapsed();

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
    let stats_line = serde_json::json!({
        "ts": signed_at,
        "block_number": block_number,
        "block_hash": format!("{:?}", block_hash),
        "object_key": witness_key,
        "size_bytes": size_bytes,
        "upload_ms": upload_elapsed.as_millis(),
        "total_ms": total.as_millis(),
        "sha256": sha,
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
    for p in to_delete {
        if let Err(err) = std::fs::remove_file(&p) {
            warn!(?err, ?p, "delete stale failed");
        }
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
                if attempt >= max_retries {
                    return Err(eyre!("s3 put {key}: {e}"));
                }
                warn!(key, attempt, err = %e, "s3 put failed; retrying");
            }
            Err(_) => {
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
