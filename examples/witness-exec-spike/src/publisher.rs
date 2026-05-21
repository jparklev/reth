//! Continuous canonical-head witness publisher.
//!
//! Architecture (the "C" path):
//!   - Subscribe to `newHeads` over the local reth WS endpoint (best-effort; falls back
//!     to HTTP polling on disconnect).
//!   - On every observed head, target `head_num - target_lag` (default 3 — well past
//!     reth's engine persistence threshold of 2 so the block is readable from a
//!     read-only MDBX snapshot).
//!   - Maintain a per-block cursor, backfilling any gaps (missed WS events, restart).
//!   - For each target: open one fresh `factory.provider()` (one MDBX RO txn), resolve
//!     block + parent + state from that same txn — so we never mix views across reorgs.
//!     Retry on transient "not yet persisted" errors with bounded backoff.
//!   - Execute, capture witness, bincode+zstd encode, ed25519-sign, upload `.zst` +
//!     `.zst.sig` to `witnesses/live/<num>-<hash>.witness.zst`, then atomically PUT
//!     `head.json` + `head.json.sig` advertising the new head.
//!   - Reorg detection: if a target block's parent_hash doesn't match the previously
//!     published entry at `(num-1)`, rewind the manifest above that depth and republish.
//!
//! Why not approach A (ExEx inside producer-mode reth):
//!   ExEx would be cleaner upstream-wise, but per project constraints we cannot touch
//!   the running prod reth and don't have storage budget for a dedicated producer reth.
//!   This sidecar reads the prod MDBX read-only (well-tested pattern from the spike) and
//!   trades a small constant latency (the `target_lag` blocks) for full isolation.

use alloy_consensus::BlockHeader;
use alloy_primitives::B256;
use alloy_rlp::Encodable;
use clap::Parser;
use eyre::{eyre, Context};
use futures_util::{SinkExt, StreamExt};
use reth_chainspec::{ChainSpec, MAINNET};
use reth_db::DatabaseEnv;
use reth_ethereum::{
    evm::{revm::database::StateProviderDatabase, EthEvmConfig},
    node::EthereumNode,
    provider::providers::{BlockchainProvider, ReadOnlyConfig},
};
use reth_evm::{execute::Executor, ConfigureEvm};
use reth_ethereum::node::api::NodeTypesWithDBAdapter;
use reth_provider::ProviderFactory;
use reth_revm::{db::State, witness::ExecutionWitnessRecord};
use reth_storage_api::{
    BlockHashReader, BlockNumReader, BlockReader, HeaderProvider, StateProviderFactory,
    TransactionVariant,
};
use reth_trie_common::ExecutionWitnessMode;

/// Concrete factory type the publisher uses. Inferred from `open_read_only` —
/// `ProviderFactoryBuilder<EthereumNode>::open_read_only(...)` returns
/// `ProviderFactory<NodeTypesWithDBAdapter<EthereumNode, DatabaseEnv>>`.
type EthFactory = ProviderFactory<NodeTypesWithDBAdapter<EthereumNode, DatabaseEnv>>;
use sha2::{Digest, Sha256};
use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    sync::{mpsc, Mutex},
    time::timeout,
};
use tracing::{debug, error, info, warn};

#[path = "live_manifest.rs"]
mod live_manifest;
#[path = "signing.rs"]
mod signing;
#[path = "validate_core.rs"]
mod validate_core;

// Re-export bundle types from validate_core so we use the SAME types as the validator
// when self-checking. Otherwise we end up with two distinct `WitnessBundle` types.
use live_manifest::{LiveManifest, ManifestEntry};
use validate_core::{encode_bundle, Encoding, WitnessBundle};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser, Debug, Clone)]
#[command(about = "Continuous canonical-head witness publisher (sidecar)")]
struct Cli {
    /// Path to reth datadir (opened read-only).
    #[arg(long, env = "RETH_DATADIR")]
    datadir: PathBuf,
    /// Reth WS endpoint, used to subscribe to `newHeads`.
    #[arg(long, env = "RETH_WS", default_value = "ws://127.0.0.1:8547")]
    ws: String,
    /// Reth HTTP RPC, used for backup polling when WS is down.
    #[arg(long, env = "RETH_HTTP", default_value = "http://127.0.0.1:8545")]
    http: String,
    /// Lag in blocks behind reth's PERSISTED best block. `1` is correct and lowest:
    /// target = best_block_number, parent = best_block_number-1, and
    /// `state_by_block_hash(parent)` only needs one changeset (which is always fresh).
    /// Larger values give more headroom if reth is committing fast but cost more lag.
    ///
    /// Note: best_block_number itself lags chain head by reth's engine persistence
    /// threshold (default 2), so the effective lag from chain head is
    /// `persistence_threshold + target_lag` ≈ 3 blocks ≈ 36s.
    #[arg(long, default_value = "1")]
    target_lag: u64,
    /// Path to 32-byte ed25519 signing seed.
    #[arg(long, env = "WITNESS_SIGNING_KEY")]
    signing_key: PathBuf,
    /// Writer ID; matches `writer-keys/<id>.pub` in the bucket.
    #[arg(long, env = "WITNESS_WRITER_ID", default_value = "primary")]
    writer_id: String,
    /// S3 endpoint, e.g. https://fsn1.your-objectstorage.com
    #[arg(long, env = "S3_ENDPOINT")]
    endpoint: String,
    /// Bucket name.
    #[arg(long, env = "S3_BUCKET")]
    bucket: String,
    /// Region.
    #[arg(long, env = "S3_REGION", default_value = "fsn1")]
    region: String,
    /// Prefix under which witnesses + head.json live.
    #[arg(long, default_value = "witnesses/live")]
    prefix: String,
    /// Cursor file: persists last-published block so we can resume after restart.
    #[arg(long, default_value = "/var/lib/reth/witness-publisher/cursor.json")]
    cursor: PathBuf,
    /// Stats log file: append-only JSONL per published block.
    #[arg(long, default_value = "/var/lib/reth/witness-publisher/stats.jsonl")]
    stats: PathBuf,
    /// Stop after producing this many blocks (0 = run forever).
    #[arg(long, default_value = "0")]
    limit: u64,
    /// Maximum number of upload retries on transient failures.
    #[arg(long, default_value = "3")]
    upload_retries: u32,
    /// Maximum number of "block not readable yet" retries per target block.
    #[arg(long, default_value = "10")]
    read_retries: u32,
    /// If true, mark uploaded witnesses + head.json as `public-read` ACL so they
    /// can be fetched via plain HTTPS without S3 SigV4 (e.g. through a CDN that
    /// can't carry credentials).
    #[arg(long, default_value = "true")]
    public_read: bool,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

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

    let spec: Arc<ChainSpec> = MAINNET.clone();

    let signing_key = signing::load_signing_key(&cli.signing_key)
        .wrap_err_with(|| format!("load signing key {}", cli.signing_key.display()))?;
    let pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());
    info!(writer_id = %cli.writer_id, pubkey = %pubkey_hex, "publisher starting");

    // Open the RO factory ONCE up front. `factory.provider()` is cheap and gives a
    // fresh MDBX RO txn per call.
    let runtime_handle = reth_tasks::Runtime::test();
    let factory = EthereumNode::provider_factory_builder().open_read_only(
        spec.clone(),
        ReadOnlyConfig::from_datadir(&cli.datadir),
        runtime_handle,
    )?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(4)
        .build()?;

    rt.block_on(run(cli, spec, factory, signing_key))
}

async fn run(
    cli: Cli,
    spec: Arc<ChainSpec>,
    factory: EthFactory,
    signing_key: ed25519_dalek::SigningKey,
) -> eyre::Result<()> {
    // S3 client (long-lived).
    let s3 = build_s3_client(&cli).await;

    // Load (or initialize) the live manifest from S3.
    let manifest = match s3_get(&s3, &cli.bucket, &format!("{}/head.json", cli.prefix)).await {
        Ok(bytes) => serde_json::from_slice::<LiveManifest>(&bytes)
            .unwrap_or_else(|_| LiveManifest::empty(&cli.writer_id)),
        Err(_) => LiveManifest::empty(&cli.writer_id),
    };
    let manifest = Arc::new(Mutex::new(manifest));

    // Load cursor (last-published block_number) from disk.
    let mut cursor: u64 = match std::fs::read_to_string(&cli.cursor)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
    {
        Some(c) => c,
        None => {
            // Fall back to manifest head, or 0.
            let m = manifest.lock().await;
            m.head.as_ref().map(|h| h.block_number).unwrap_or(0)
        }
    };
    info!(start_cursor = cursor, "loaded cursor");

    // Channel between head-watcher and publisher. Watcher sends "saw chain head N";
    // publisher computes target = N - lag, processes any gap, and uploads.
    let (head_tx, mut head_rx) = mpsc::channel::<u64>(64);

    // Spawn the head-watcher.
    let watcher_ws = cli.ws.clone();
    let watcher_http = cli.http.clone();
    let watcher_tx = head_tx.clone();
    tokio::spawn(async move {
        head_watcher(watcher_ws, watcher_http, watcher_tx).await;
    });

    // Main loop: every chain-head event, re-read reth's local `best_block_number`
    // (the highest fully-persisted block) and target up to `best_block - target_lag`.
    // Why best_block rather than chain_head: we need to read state at parent_hash,
    // and `state_by_block_hash` for any block strictly before best_block has to walk
    // changesets back from best_block. Reth's changeset cache only keeps a small
    // window, and the DB fallback path is incorrect for distant lookups. Targeting
    // best_block lets us use the latest-state provider (no changeset walk).
    let mut published_count: u64 = 0;
    while let Some(_chain_head) = head_rx.recv().await {
        let best = match read_best_block_number(&factory) {
            Ok(b) => b,
            Err(e) => {
                warn!(err = %e, "read best_block_number failed");
                continue;
            }
        };
        let target = best.saturating_sub(cli.target_lag);
        if cursor == 0 {
            cursor = target.saturating_sub(1);
        }
        while cursor < target {
            let next = cursor + 1;
            match publish_block(
                &spec,
                &factory,
                &s3,
                &cli,
                &signing_key,
                manifest.clone(),
                next,
            )
            .await
            {
                Ok(()) => {
                    cursor = next;
                    persist_cursor(&cli.cursor, cursor);
                    published_count += 1;
                    if cli.limit != 0 && published_count >= cli.limit {
                        info!(published = published_count, "limit reached, exiting");
                        return Ok(());
                    }
                }
                Err(e) => {
                    error!(block = next, err = ?e, "publish failed; SKIPPING this block");
                    // Advance cursor past this block so we don't grind forever on a
                    // block whose state we can't reconstruct from the RO snapshot.
                    // The skipped block is also recorded to stats so we can audit later.
                    let skip_line = serde_json::json!({
                        "ts": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                        "block_number": next,
                        "skipped": true,
                        "err": format!("{e}"),
                    });
                    append_stats(&cli.stats, &skip_line);
                    cursor = next;
                    persist_cursor(&cli.cursor, cursor);
                    // Keep going on the next iteration so we try block (next+1).
                }
            }
        }
    }

    Ok(())
}

/// Read reth's persisted best block number from the RO factory.
fn read_best_block_number(factory: &EthFactory) -> eyre::Result<u64> {
    let provider = factory.provider().wrap_err("open RO provider")?;
    Ok(provider.best_block_number()?)
}

// ---------------------------------------------------------------------------
// Head watcher (WS subscribe, HTTP fallback)
// ---------------------------------------------------------------------------

async fn head_watcher(ws_url: String, http_url: String, tx: mpsc::Sender<u64>) {
    loop {
        match ws_subscribe_newheads(&ws_url, tx.clone()).await {
            Ok(()) => warn!("ws stream ended without error; reconnecting"),
            Err(e) => warn!(err = %e, "ws subscribe failed; falling back to http polling"),
        }
        // Fallback HTTP polling for a short window before retrying WS.
        let until = Instant::now() + Duration::from_secs(30);
        let client = reqwest::Client::new();
        let mut last: u64 = 0;
        while Instant::now() < until {
            if let Ok(n) = http_block_number(&client, &http_url).await {
                if n != last {
                    last = n;
                    let _ = tx.send(n).await;
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
}

async fn ws_subscribe_newheads(url: &str, tx: mpsc::Sender<u64>) -> eyre::Result<()> {
    use tokio_tungstenite::tungstenite::Message;

    let (mut ws, _resp) = tokio_tungstenite::connect_async(url)
        .await
        .wrap_err_with(|| format!("ws connect {url}"))?;
    info!(%url, "ws connected, subscribing to newHeads");

    let sub = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_subscribe",
        "params": ["newHeads"],
    });
    ws.send(Message::Text(sub.to_string().into())).await.wrap_err("ws send subscribe")?;

    // First message = subscription id ack. Ignore and start streaming notifications.
    while let Some(msg) = ws.next().await {
        let msg = msg.wrap_err("ws recv")?;
        let text = match msg {
            Message::Text(t) => t,
            Message::Ping(p) => {
                ws.send(Message::Pong(p)).await.ok();
                continue;
            }
            Message::Close(_) => return Err(eyre!("ws closed")),
            _ => continue,
        };
        // Parse out `.params.result.number` (hex string) — robust against ack messages
        // that have no `params` field.
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
            if let Some(num_s) = v
                .get("params")
                .and_then(|p| p.get("result"))
                .and_then(|r| r.get("number"))
                .and_then(|n| n.as_str())
            {
                if let Some(head) = parse_hex_u64(num_s) {
                    debug!(head, "ws newHead");
                    let _ = tx.send(head).await;
                }
            }
        }
    }
    Ok(())
}

fn parse_hex_u64(s: &str) -> Option<u64> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(s, 16).ok()
}

async fn http_block_number(client: &reqwest::Client, url: &str) -> eyre::Result<u64> {
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": []
    });
    let v: serde_json::Value = client
        .post(url)
        .json(&body)
        .send()
        .await
        .wrap_err("http eth_blockNumber")?
        .json()
        .await
        .wrap_err("http parse")?;
    let s = v.get("result").and_then(|r| r.as_str()).ok_or_else(|| eyre!("no result"))?;
    parse_hex_u64(s).ok_or_else(|| eyre!("invalid hex: {s}"))
}

// ---------------------------------------------------------------------------
// Per-block publish (the hard part)
// ---------------------------------------------------------------------------

/// Produce + sign + upload the witness for `block_number`. Updates the live
/// manifest on success. Handles reorg by rewinding the manifest above the
/// fork point.
async fn publish_block(
    spec: &Arc<ChainSpec>,
    factory: &EthFactory,
    s3: &aws_sdk_s3::Client,
    cli: &Cli,
    signing_key: &ed25519_dalek::SigningKey,
    manifest: Arc<Mutex<LiveManifest>>,
    block_number: u64,
) -> eyre::Result<()> {
    let started = Instant::now();

    // 1. Produce witness from the read-only MDBX snapshot.
    let prod = tokio::task::spawn_blocking({
        let spec = spec.clone();
        let factory = factory.clone();
        let read_retries = cli.read_retries;
        move || produce_witness(&spec, &factory, block_number, read_retries)
    })
    .await
    .wrap_err("produce_witness task panicked")??;

    let produce_elapsed = started.elapsed();

    // 2. Encode (bincode + zstd-3).
    let encoded = encode_bundle(&prod.bundle, Encoding::BincodeZstd).wrap_err("encode bundle")?;
    let size_bytes = encoded.len() as u64;
    let sha = hex::encode(Sha256::digest(&encoded));

    // 3. Sign.
    let sig = signing::sign(signing_key, &encoded);
    let signed_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    // 4. Detect reorg vs last-published. If parent_hash doesn't match the manifest's
    //    entry at (block_number-1), rewind the manifest above (block_number-1).
    {
        let mut m = manifest.lock().await;
        if let Some(prev) = m.entries.iter().find(|e| e.block_number == block_number - 1) {
            if prev.block_hash != prod.parent_hash {
                warn!(
                    block_number,
                    expected_parent = %prev.block_hash,
                    actual_parent  = %prod.parent_hash,
                    "reorg detected, rewinding manifest"
                );
                m.rewind_above(block_number - 1);
                // Note: we don't rewind cursor; the new fork is being published from
                // this block forward. Orphans remain in S3 but are not advertised.
            }
        }
    }

    // 5. Upload witness + .sig (with retry).
    let witness_key =
        format!("{}/{}-{}.witness.zst", cli.prefix, block_number, hex_no_prefix(prod.block_hash));
    let sig_key = format!("{witness_key}.sig");

    let upload_start = Instant::now();
    s3_put_with_retry(
        s3,
        &cli.bucket,
        &witness_key,
        encoded.clone(),
        cli.upload_retries,
        cli.public_read,
    )
    .await?;
    s3_put_with_retry(s3, &cli.bucket, &sig_key, sig.to_vec(), cli.upload_retries, cli.public_read)
        .await?;
    let upload_elapsed = upload_start.elapsed();

    // 6. Build manifest entry + atomically replace head.json.
    let entry = ManifestEntry {
        block_number,
        block_hash: prod.block_hash,
        parent_hash: prod.parent_hash,
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
    // Upload the .sig FIRST so a reader fetching head.json never sees a fresher
    // manifest than the sig that signs it (the reverse can briefly happen).
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

    let total_elapsed = started.elapsed();

    // 7. Stats log line.
    let stats_line = serde_json::json!({
        "ts": signed_at,
        "block_number": block_number,
        "block_hash": format!("{:?}", prod.block_hash),
        "parent_hash": format!("{:?}", prod.parent_hash),
        "size_bytes": size_bytes,
        "sha256": sha,
        "object_key": witness_key,
        "produce_ms": produce_elapsed.as_millis(),
        "upload_ms": upload_elapsed.as_millis(),
        "e2e_ms": total_elapsed.as_millis(),
        "tx_count": prod.tx_count,
        "gas_used": prod.gas_used,
    });
    append_stats(&cli.stats, &stats_line);

    info!(
        block = block_number,
        size_kb = size_bytes / 1024,
        produce_ms = produce_elapsed.as_millis(),
        upload_ms = upload_elapsed.as_millis(),
        e2e_ms = total_elapsed.as_millis(),
        "published"
    );

    Ok(())
}

/// Output of [`produce_witness`].
struct Produced {
    bundle: WitnessBundle,
    block_hash: B256,
    parent_hash: B256,
    tx_count: u64,
    gas_used: u64,
}

/// Reconstruct + execute the block, producing a witness, then **self-validate**
/// (re-execute against the produced witness and verify the state root). If the
/// witness doesn't round-trip we treat the attempt as transient and retry — this
/// catches the case where reth's historical state provider returns inconsistent
/// state (mixing pre/post snapshots due to changeset cache eviction) and our
/// executor accepts it but the witness is internally broken.
fn produce_witness(
    spec: &Arc<ChainSpec>,
    factory: &EthFactory,
    block_number: u64,
    max_retries: u32,
) -> eyre::Result<Produced> {
    let mut attempt = 0u32;
    loop {
        let outcome = try_produce_witness(spec, factory, block_number)
            .and_then(|p| self_validate(spec, p));
        match outcome {
            Ok(p) => return Ok(p),
            Err(e) => {
                let chain = format!("{e:?}");
                // All known race-condition error families when we're slightly ahead of
                // what reth's RO snapshot can serve, plus the self-validation failures
                // that show the produced witness is inconsistent with the actual chain.
                let transient = chain.contains("not found")
                    || chain.contains("not yet persisted")
                    || chain.contains("nonce too low")
                    || chain.contains("does not exist")
                    || chain.contains("missing")
                    || chain.contains("execute_with_state_closure")
                    || chain.contains("StateRootMismatch")
                    || chain.contains("InsufficientFunds")
                    || chain.contains("LackOfFundForMaxFee")
                    || chain.contains("self-validate")
                    || chain.contains("blind node");
                if !transient || attempt >= max_retries {
                    return Err(e);
                }
                let delay = Duration::from_millis(500 * (1u64 << attempt.min(4)));
                debug!(block = block_number, attempt, ?delay, err = %chain, "transient produce error, backing off");
                std::thread::sleep(delay);
                attempt += 1;
            }
        }
    }
}

/// Re-execute the produced witness end-to-end (exactly what a stateless validator
/// does) and assert the recomputed post-state root matches the block header.
fn self_validate(spec: &Arc<ChainSpec>, p: Produced) -> eyre::Result<Produced> {
    let bundle = p.bundle.clone();
    let outcome = validate_core::validate_bundle(spec.clone(), bundle)
        .wrap_err("self-validate: validate_bundle")?;
    if outcome.computed_root != outcome.expected_root {
        return Err(eyre!(
            "self-validate: state root mismatch for block {} (got {:?}, expected {:?})",
            p.bundle.block_number,
            outcome.computed_root,
            outcome.expected_root,
        ));
    }
    Ok(p)
}

/// One single produce attempt — all reads from the same fresh provider txn.
fn try_produce_witness(
    spec: &Arc<ChainSpec>,
    factory: &EthFactory,
    block_number: u64,
) -> eyre::Result<Produced> {
    // Fresh provider = fresh MDBX RO txn = consistent view across all reads below.
    let provider = factory.provider().wrap_err("open RO provider")?;

    // Resolve the canonical hash at `block_number` from THIS txn.
    let block_hash = provider
        .block_hash(block_number)?
        .ok_or_else(|| eyre!("block {block_number}: hash not found (not yet persisted)"))?;

    let recovered = provider
        .recovered_block(block_hash.into(), TransactionVariant::WithHash)?
        .ok_or_else(|| eyre!("block {block_number}: body not found (not yet persisted)"))?;
    let recovered = Arc::new(recovered);
    let parent_hash = recovered.parent_hash();
    let parent_state_root = provider
        .header_by_hash_or_number(parent_hash.into())?
        .ok_or_else(|| eyre!("parent header {parent_hash} not found"))?
        .state_root();
    let expected_state_root = recovered.state_root();

    // BlockchainProvider gives us a `StateProviderFactory`. Built from the same
    // factory; the historical state provider it returns is backed by its OWN fresh
    // RO txn, but that's OK because we only ask for state at a hash we just confirmed
    // exists in storage (block_number-1 is well behind chain head per --target-lag).
    let blockchain = BlockchainProvider::new(factory.clone())?;
    let state_provider = blockchain.state_by_block_hash(parent_hash)?;
    let evm_config = EthEvmConfig::new(spec.clone());
    let mut db = State::builder()
        .with_database(StateProviderDatabase::new(&state_provider))
        .with_bundle_update()
        .build();

    let mut witness_record = ExecutionWitnessRecord::default();
    let executor = evm_config.executor(&mut db);
    let output = executor
        .execute_with_state_closure(&recovered, |statedb: &State<_>| {
            witness_record.record_executed_state(statedb, ExecutionWitnessMode::Canonical);
        })
        .wrap_err("execute_with_state_closure failed")?;

    let witness = witness_record
        .into_execution_witness(
            &state_provider,
            &provider,
            block_number,
            ExecutionWitnessMode::Canonical,
        )
        .wrap_err("into_execution_witness failed")?;

    let mut header_buf = Vec::new();
    recovered.header().encode(&mut header_buf);
    let mut body_buf = Vec::new();
    recovered.body().encode(&mut body_buf);

    let bundle = WitnessBundle {
        header: header_buf.into(),
        block_body: body_buf.into(),
        witness,
        parent_state_root,
        expected_state_root,
        block_number,
    };

    Ok(Produced {
        bundle,
        block_hash,
        parent_hash,
        tx_count: recovered.body().transactions.len() as u64,
        gas_used: output.result.gas_used,
    })
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

// ---------------------------------------------------------------------------
// Cursor + stats persistence
// ---------------------------------------------------------------------------

fn persist_cursor(path: &PathBuf, cursor: u64) {
    if let Err(e) = std::fs::write(path, format!("{cursor}\n")) {
        warn!(err = %e, "persist cursor failed");
    }
}

fn append_stats(path: &PathBuf, line: &serde_json::Value) {
    use std::io::Write;
    let mut f =
        match std::fs::OpenOptions::new().create(true).append(true).open(path) {
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

fn hex_no_prefix(h: B256) -> String {
    format!("{:x}", h)
}
