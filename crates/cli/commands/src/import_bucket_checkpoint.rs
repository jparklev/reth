//! Spike: `reth import-bucket-checkpoint`.
//!
//! Fetches the bucket-state checkpoint manifest, reads the pinned header, and
//! seeds MDBX + static_files so that subsequent `reth node` runs treat the
//! pinned block as the canonical local tip. The CL's first forkchoiceUpdated
//! then triggers only a short backfill (pinned → tip) instead of a full
//! staged sync from genesis.
//!
//! **Spike #2 scope**: this lands the engine-tree anchor (headers + per-stage
//! `StageCheckpoint::new(pinned)`) AND drains the bucket-state HashMaps into
//! the hashed-keyed MDBX tables (`HashedAccounts`, `HashedStorages`,
//! `Bytecodes`). With storage_v2 enabled (the default), reth's
//! `LatestStateProviderRef` reads from these tables, so `ExecutionStage` past
//! `pinned` can now load parent state. The trie tables (`AccountsTrie`,
//! `StoragesTrie`) are still empty; `MerkleStage` will fail on the first
//! backfill run until spike #3 computes + populates the trie from the
//! hashed state. See `docs/CHECKPOINT-IMPORT-SYNC.md` for the
//! productionization roadmap.

use crate::common::{AccessRights, CliNodeTypes, Environment, EnvironmentArgs};
use alloy_consensus::BlockHeader as AlloyBlockHeader;
use clap::Parser;
use reth_bucket_state_client::{
    BucketStateClientConfig, BucketStateConnConfig, HttpBucketStateClient,
};
use reth_chainspec::{EthChainSpec, EthereumHardforks};
use reth_cli::chainspec::ChainSpecParser;
use reth_db_api::{tables, transaction::DbTxMut};
use reth_node_api::NodePrimitives;
use reth_node_core::args::BucketArgs;
use reth_primitives_traits::{header::HeaderMut, Bytecode, SealedHeader, StorageEntry};
use reth_provider::{
    BlockNumReader, BucketStateClient, DBProvider, DatabaseProviderFactory,
    StaticFileProviderFactory, StaticFileWriter, StorageSettingsCache,
};
use std::{sync::Arc, time::Instant};
use tracing::{info, warn};

use crate::init_state::without_evm::setup_without_evm;

/// Import a bucket-state checkpoint as the local canonical tip.
#[derive(Debug, Parser)]
pub struct ImportBucketCheckpointCommand<C: ChainSpecParser> {
    #[command(flatten)]
    pub env: EnvironmentArgs<C>,

    #[command(flatten)]
    pub bucket: BucketArgs,
}

impl<C: ChainSpecParser<ChainSpec: EthChainSpec + EthereumHardforks>>
    ImportBucketCheckpointCommand<C>
{
    /// Execute the `import-bucket-checkpoint` command.
    pub async fn execute<N>(self, runtime: reth_tasks::Runtime) -> eyre::Result<()>
    where
        N: CliNodeTypes<
            ChainSpec = C::ChainSpec,
            Primitives: NodePrimitives<BlockHeader: HeaderMut>,
        >,
    {
        if self.bucket.bucket_url.is_none() {
            return Err(eyre::eyre!("--bucket-url is required for import-bucket-checkpoint"));
        }
        if self.bucket.bucket_endpoint.is_none() {
            return Err(eyre::eyre!("--bucket-endpoint is required for import-bucket-checkpoint"));
        }

        info!(target: "reth::cli", "import-bucket-checkpoint starting");

        // Step 1: boot the bucket-state client (mirrors the wiring in
        // `crates/node/builder/src/launch/engine.rs`). This downloads the
        // signed checkpoint manifest, verifies the writer signature, and
        // hydrates the plain-state HashMaps into memory.
        let cache_dir = BucketStateConnConfig::default_cache_dir();
        let state_cfg = BucketStateClientConfig {
            conn: BucketStateConnConfig {
                bucket_url: self.bucket.bucket_url.clone().expect("checked above"),
                endpoint: self.bucket.bucket_endpoint.clone().expect("checked above"),
                region: self.bucket.bucket_region.clone(),
                anonymous: self.bucket.bucket_anonymous,
                access_key_env: "BUCKET_ACCESS_KEY".into(),
                secret_key_env: "BUCKET_SECRET_KEY".into(),
                trusted_writers: self
                    .bucket
                    .bucket_trusted_writers
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect(),
                cache_dir,
            },
            checkpoint_prefix: self.bucket.bucket_state_prefix.clone(),
            target_block: None,
            apply_deltas: true,
            // Offline import: no concurrent eth_call traffic to OOM, and
            // the box typically has plenty of RAM (tens of GB). Crank up
            // shard fetch concurrency to amortize S3 latency across the
            // ~thousands of shards in a full mainnet checkpoint.
            max_concurrent_shard_loads: 32,
        };

        let state_client = HttpBucketStateClient::new_blocking(state_cfg)
            .map_err(|err| eyre::eyre!("bucket-state init failed: {err}"))?;

        let pinned_block = BucketStateClient::pinned_block_number(&*state_client);
        let pinned_hash =
            BucketStateClient::pinned_block_hash(&*state_client).ok_or_else(|| {
                eyre::eyre!(
                    "bucket-state checkpoint did not expose a pinned_block_hash; \
                     v4 manifest required"
                )
            })?;
        let pinned_header = BucketStateClient::pinned_header(&*state_client).ok_or_else(|| {
            eyre::eyre!(
                "bucket-state checkpoint did not expose a pinned_header; \
                 v4 manifest required"
            )
        })?;

        // Sanity: the embedded header's hash must match the manifest hash.
        let computed_hash = pinned_header.hash_slow();
        if computed_hash != pinned_hash {
            return Err(eyre::eyre!(
                "pinned_header hash {computed_hash:?} does not match \
                 manifest pinned_block_hash {pinned_hash:?}"
            ));
        }
        if pinned_header.number() != pinned_block {
            return Err(eyre::eyre!(
                "pinned_header.number ({}) does not match manifest \
                 pinned_block_number ({pinned_block})",
                pinned_header.number()
            ));
        }

        info!(
            target: "reth::cli",
            pinned_block,
            pinned_hash = ?pinned_hash,
            state_root = ?pinned_header.state_root(),
            "Loaded bucket-state checkpoint manifest"
        );

        // Step 2: open the datadir RW and call `setup_without_evm`.
        // This refuses to run on a non-fresh datadir (any block_number > 0
        // that is also < pinned).
        let Environment { provider_factory, .. } = self.env.init::<N>(AccessRights::RW, runtime)?;
        let static_file_provider = provider_factory.static_file_provider();
        let provider_rw = provider_factory.database_provider_rw()?;
        let last_block_number = provider_rw.last_block_number()?;

        if last_block_number > 0 && last_block_number < pinned_block {
            return Err(eyre::eyre!(
                "Data directory must be empty (or already at the pinned block) \
                 when running import-bucket-checkpoint. Last block: {last_block_number}, \
                 pinned: {pinned_block}. Remove the datadir and retry."
            ));
        }
        if last_block_number >= pinned_block {
            info!(
                target: "reth::cli",
                last_block_number,
                pinned_block,
                "Datadir already at or past pinned block; nothing to do"
            );
            return Ok(());
        }

        // SAFETY: insert_block requires its header type to implement HeaderMut
        // so we can convert the alloy_consensus::Header from the manifest into
        // the node's NodePrimitives::BlockHeader type. For mainnet/sepolia this
        // is the same type.
        //
        // We construct an instance of NodePrimitives::BlockHeader and copy fields
        // from the alloy Header by setting them via HeaderMut. For the EthereumNode
        // (the only node bucket-mode currently supports), BlockHeader == alloy Header,
        // so the conversion is a no-op clone in practice.
        let header_for_setup: <N::Primitives as NodePrimitives>::BlockHeader =
            alloy_to_node_header::<N>(&pinned_header)?;

        // Sanity: bucket-state-client is hash-keyed and writes only
        // `HashedAccounts` / `HashedStorages`, which reth's
        // `LatestStateProviderRef` consults only when storage_v2 is set.
        // `init_genesis_with_settings` (called by `env.init`) already wrote
        // `StorageSettings::v2()` because that's the default; this is a
        // belt-and-suspenders check so a future storage_v1-default regression
        // surfaces as a loud error here instead of silent execution divergence
        // on the first backfill block past pinned.
        let storage_settings = provider_rw.cached_storage_settings();
        if !storage_settings.use_hashed_state() {
            return Err(eyre::eyre!(
                "import-bucket-checkpoint requires storage_v2 (use_hashed_state) so the \
                 hashed-keyed bucket-state can be drained into HashedAccounts/HashedStorages. \
                 Re-run with --storage.v2 (the default) on a fresh datadir."
            ));
        }

        setup_without_evm(
            &provider_rw,
            SealedHeader::new(header_for_setup, pinned_hash),
            |number| {
                let mut header = <<N::Primitives as NodePrimitives>::BlockHeader>::default();
                header.set_number(number);
                header
            },
        )?;

        // Pad the v2 changeset static-file segments up to pinned-1 with
        // empty entries. Reth's boot-time consistency check compares each
        // stage checkpoint against its segment's tip; without this padding,
        // `AccountChangeSets` and `StorageChangeSets` stay at tip=0 while
        // `AccountsHistory` / `StoragesHistory` stage checkpoints jump to
        // pinned, and the launcher panics with "RocksDB and static file
        // inconsistency was found that would trigger an unwind to block 0".
        // `init_from_state_dump`'s v2 path does this via
        // `prepare_account_changeset_writer` / `prepare_storage_changeset_writer`;
        // mirror the same logic here.
        pad_v2_changeset_segments::<N>(&static_file_provider, pinned_block)?;

        // Static-files commit must happen before the DB tx commit so the
        // header is durably visible. This mirrors the order in
        // `crates/cli/commands/src/init_state/mod.rs` line 111.
        static_file_provider.commit()?;
        provider_rw.commit()?;

        info!(target: "reth::cli", "Engine-tree anchor committed; starting plain-state drain");

        // Step 3: stream every shard's rows through MDBX cursor writes.
        //
        // We deliberately bypass `hydrate_all_shards` + `iter_*` here:
        // the full mainnet plain state is ~100+ GB, too large to hold
        // in the moka caches alongside reth's own working set. The
        // streaming API fetches one shard at a time, decodes its rows
        // directly into MDBX put/upsert calls, and drops the decoded
        // bytes before fetching the next shard — peak RAM stays bounded
        // by `max_concurrent_shard_loads × per-shard-decode-buffer`.
        //
        // We write only the hashed-keyed tables because the bucket-state
        // client is hash-prefix-sharded and doesn't expose plain
        // addresses. With storage_v2 (verified above),
        // `LatestStateProviderRef::basic_account` reads `HashedAccounts`
        // and storage reads come from `HashedStorages`.
        drain_shards_into_mdbx(&provider_factory, &state_client)?;

        // Spike #3 will run a compute_state_root_chunked pass + populate
        // AccountsTrie/StoragesTrie. Without it, MerkleStage cannot
        // incrementally compute the root from changesets (there are no
        // changesets back to genesis) and will fail on the first backfill
        // run. Logging loudly so this isn't a surprise.
        warn!(
            target: "reth::cli",
            pinned_block,
            "Trie tables (AccountsTrie/StoragesTrie) are still empty. \
             MerkleStage will fail on the first backfill block past pinned \
             until spike #3 (state-root compute pass) lands."
        );

        info!(
            target: "reth::cli",
            pinned_block,
            pinned_hash = ?pinned_hash,
            "Checkpoint import complete. Datadir is anchored at pinned block \
             and hashed plain state is drained."
        );
        Ok(())
    }
}

/// Pad the v2 changeset static-file segments (`AccountChangeSets`,
/// `StorageChangeSets`) with empty entries up to `pinned_block - 1`.
/// Reth's startup `check_consistency` compares each stage checkpoint
/// against its segment's tip; since the import advances
/// `AccountsHistory` / `StoragesHistory` stage checkpoints to `pinned`
/// but the segments would otherwise stay at tip=0, the launcher would
/// trigger an unwind to block 0. Padding closes the gap.
///
/// Note: writing 25M empty changeset entries is fast — they're size-zero
/// rows in a static file, just incrementing the segment's block_end.
fn pad_v2_changeset_segments<N>(
    static_file_provider: &reth_provider::providers::StaticFileProvider<N::Primitives>,
    pinned_block: u64,
) -> eyre::Result<()>
where
    N: CliNodeTypes,
{
    use reth_static_file_types::StaticFileSegment;
    if pinned_block == 0 {
        return Ok(());
    }
    let target = pinned_block - 1;
    let t0 = Instant::now();
    for segment in [StaticFileSegment::AccountChangeSets, StaticFileSegment::StorageChangeSets] {
        let mut writer = static_file_provider.get_writer(pinned_block, segment)?;
        let next_block = writer.next_block_number();
        if next_block > target {
            continue;
        }
        info!(
            target: "reth::cli",
            ?segment,
            from_block = next_block,
            to_block = target,
            "Padding empty v2 changeset segment before drain"
        );
        for empty_block in next_block..=target {
            match segment {
                StaticFileSegment::AccountChangeSets => {
                    writer.append_account_changeset(Vec::new(), empty_block)?;
                }
                StaticFileSegment::StorageChangeSets => {
                    writer.append_storage_changeset(Vec::new(), empty_block)?;
                }
                _ => unreachable!(),
            }
            if empty_block.is_multiple_of(5_000_000) {
                info!(
                    target: "reth::cli",
                    ?segment,
                    padded_to = empty_block,
                    elapsed_s = t0.elapsed().as_secs(),
                    "Padding progress"
                );
            }
        }
    }
    info!(
        target: "reth::cli",
        target,
        elapsed_s = t0.elapsed().as_secs(),
        "v2 changeset segment padding complete"
    );
    Ok(())
}

/// Stream every shard's checkpoint artifacts into MDBX. For each shard we
/// open one RW transaction, fetch + decode the shard's rows directly via
/// `HttpBucketStateClient::drain_shard_streaming` (which writes to our
/// closures, not to the moka caches), `put` accounts + `upsert` storage
/// rows + `put` bytecodes, then commit the transaction. Peak memory is
/// bounded by one shard's decoded contents, not the cumulative state.
///
/// Tombstones (`None` values) are skipped — `LatestStateProviderRef`
/// already treats missing entries as zero / empty / absent.
fn drain_shards_into_mdbx<PF>(
    provider_factory: &PF,
    state_client: &HttpBucketStateClient,
) -> eyre::Result<()>
where
    PF: DatabaseProviderFactory,
    PF::ProviderRW: DBProvider<Tx: DbTxMut>,
{
    use reth_db_api::cursor::DbCursorRW;

    let total_t0 = Instant::now();
    let shard_ids = state_client.shard_ids();
    let total_shards = shard_ids.len();
    let mut total_accounts: usize = 0;
    let mut total_storage: usize = 0;
    let mut total_codes: usize = 0;
    let mut last_log_t = Instant::now();

    for (shard_idx, shard) in shard_ids.into_iter().enumerate() {
        let provider_rw = provider_factory.database_provider_rw()?;
        let mut shard_accounts: usize = 0;
        let mut shard_storage: usize = 0;
        let mut shard_codes: usize = 0;
        {
            let tx = provider_rw.tx_ref();
            let mut storage_cursor = tx.cursor_dup_write::<tables::HashedStorages>()?;
            state_client.drain_shard_streaming(
                shard,
                |hashed_addr, maybe_account| {
                    let Some(account) = maybe_account else {
                        return;
                    };
                    // The hashed-state table accepts non-sorted puts; for
                    // a one-time import the per-row B-tree cost is worth
                    // it to avoid an external sort.
                    if let Err(err) = tx.put::<tables::HashedAccounts>(hashed_addr, account) {
                        warn!(target: "reth::cli", ?err, "HashedAccounts put failed");
                    }
                    shard_accounts += 1;
                },
                |hashed_addr, hashed_slot, maybe_value| {
                    let Some(value) = maybe_value else {
                        return;
                    };
                    // Skip zero values: empty slots are absence, not a
                    // stored zero. Storing them bloats MDBX and diverges
                    // from the LatestStateProviderRef "missing == zero"
                    // contract.
                    if value.is_zero() {
                        return;
                    }
                    if let Err(err) = storage_cursor
                        .upsert(hashed_addr, &StorageEntry { key: hashed_slot, value })
                    {
                        warn!(target: "reth::cli", ?err, "HashedStorages upsert failed");
                    }
                    shard_storage += 1;
                },
                |code_hash, maybe_bytes| {
                    let Some(bytes) = maybe_bytes else {
                        return;
                    };
                    if bytes.is_empty() {
                        return;
                    }
                    if let Err(err) =
                        tx.put::<tables::Bytecodes>(code_hash, Bytecode::new_raw(bytes))
                    {
                        warn!(target: "reth::cli", ?err, "Bytecodes put failed");
                    }
                    shard_codes += 1;
                },
            )?;
        }
        provider_rw.commit()?;
        total_accounts += shard_accounts;
        total_storage += shard_storage;
        total_codes += shard_codes;

        // Log every ~30s or every 64 shards so the operator can see
        // progress on a multi-hour import without spamming.
        if last_log_t.elapsed().as_secs() >= 30 || shard_idx.is_multiple_of(64) {
            info!(
                target: "reth::cli",
                shard = shard_idx + 1,
                of = total_shards,
                accounts = total_accounts,
                storage = total_storage,
                codes = total_codes,
                elapsed_s = total_t0.elapsed().as_secs(),
                "Drain progress"
            );
            last_log_t = Instant::now();
        }
    }

    info!(
        target: "reth::cli",
        accounts = total_accounts,
        storage = total_storage,
        codes = total_codes,
        elapsed_s = total_t0.elapsed().as_secs(),
        "Plain-state drain into MDBX complete"
    );

    Ok(())
}

impl<C: ChainSpecParser> ImportBucketCheckpointCommand<C> {
    /// Returns the underlying chain being used to run this command.
    pub fn chain_spec(&self) -> Option<&Arc<C::ChainSpec>> {
        Some(&self.env.chain)
    }
}

/// Convert an `alloy_consensus::Header` (which the bucket manifest exposes)
/// into the node primitives' header type. For Ethereum the two are the same
/// concrete type, so this is effectively a typed copy; the round-trip via
/// `HeaderMut::set_*` keeps this generic over chains whose header layouts
/// extend alloy's (e.g. Optimism's extra fields default to their defaults,
/// which is fine for a finalized historical block we're never going to
/// re-execute).
///
/// We use RLP encode/decode for a chain-agnostic conversion. Both alloy
/// Header and EthereumNode's BlockHeader implement `alloy_rlp::Encodable`
/// and `Decodable`. For the spike this is unbeatable for simplicity: zero
/// chain-specific code, full fidelity for any header type that has an RLP
/// round-trip with alloy::Header.
fn alloy_to_node_header<N>(
    h: &alloy_consensus::Header,
) -> eyre::Result<<N::Primitives as NodePrimitives>::BlockHeader>
where
    N: CliNodeTypes<Primitives: NodePrimitives<BlockHeader: HeaderMut>>,
{
    use alloy_rlp::{Decodable, Encodable};
    let mut buf = Vec::with_capacity(600);
    h.encode(&mut buf);
    let decoded =
        <<N::Primitives as NodePrimitives>::BlockHeader>::decode(&mut &buf[..]).map_err(|err| {
            eyre::eyre!("failed to round-trip alloy header into node header via RLP: {err}")
        })?;
    Ok(decoded)
}
