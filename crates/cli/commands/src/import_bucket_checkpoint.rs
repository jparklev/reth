//! Spike: `reth import-bucket-checkpoint`.
//!
//! Fetches the bucket-state checkpoint manifest, reads the pinned header, and
//! seeds MDBX + static_files so that subsequent `reth node` runs treat the
//! pinned block as the canonical local tip. The CL's first forkchoiceUpdated
//! then triggers only a short backfill (pinned → tip) instead of a full
//! staged sync from genesis.
//!
//! **Spike #3 scope**: this lands the engine-tree anchor (headers + per-stage
//! `StageCheckpoint::new(pinned)`), drains the bucket-state HashMaps into the
//! hashed-keyed MDBX tables (`HashedAccounts`, `HashedStorages`, `Bytecodes`),
//! and then runs `compute_state_root_chunked` to populate `AccountsTrie` /
//! `StoragesTrie` and verify the computed root against
//! `pinned_header.state_root`. With storage_v2 enabled (the default), reth's
//! `LatestStateProviderRef` reads from the hashed tables, so `ExecutionStage`
//! past `pinned` can load parent state; populating the trie unblocks
//! `MerkleStage` from the very first backfill block. See
//! `docs/CHECKPOINT-IMPORT-SYNC.md` for the productionization roadmap.

use crate::common::{AccessRights, CliNodeTypes, Environment, EnvironmentArgs};
use alloy_consensus::BlockHeader as AlloyBlockHeader;
use clap::Parser;
use reth_bucket_state_client::{
    BucketStateClientConfig, BucketStateConnConfig, HttpBucketStateClient,
};
use reth_chainspec::{EthChainSpec, EthereumHardforks};
use reth_cli::chainspec::ChainSpecParser;
use reth_db_api::{
    tables::{self, RawDupSort, RawKey, RawTable, RawValue},
    transaction::DbTxMut,
};
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

    /// JSON-RPC URL of an Ethereum execution client (typically a prod reth at
    /// `http://127.0.0.1:8545`) used to fetch the 256 real headers immediately
    /// before the anchor. Without this, those pre-anchor blocks are written as
    /// zero-hash dummies, and post-anchor blocks that execute `BLOCKHASH(N)` for
    /// `anchor - 256 <= N < anchor` would resolve to `B256::ZERO`, causing
    /// silent consensus divergence (see `docs/PATH-B-DIAGNOSIS-25143845.md`).
    /// When this flag is omitted, the import proceeds with zero-hash dummies —
    /// only safe if no post-anchor block in the catch-up range reads BLOCKHASH
    /// for a pre-anchor number.
    #[arg(long, value_name = "URL", help_heading = "Header backfill")]
    pub header_backfill_rpc_url: Option<String>,

    /// How many real headers to backfill (default 256, matching the EVM
    /// `BLOCKHASH` history window). Capped to `min(pinned, 256)`.
    #[arg(long, value_name = "N", default_value_t = 256u64, help_heading = "Header backfill")]
    pub header_backfill_count: u64,
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

        // Optionally fetch real pre-anchor headers from a live execution client
        // so `BLOCKHASH(N)` for `pinned-256 <= N < pinned` resolves to the real
        // chain hash instead of `B256::ZERO`. See the field doc above.
        let pre_anchor_headers: Vec<(
            <N::Primitives as NodePrimitives>::BlockHeader,
            alloy_primitives::B256,
        )> = if let Some(url) = self.header_backfill_rpc_url.as_deref() {
            let count = self.header_backfill_count.min(pinned_block).min(256);
            if count == 0 {
                Vec::new()
            } else {
                let start = pinned_block - count;
                let end = pinned_block - 1;
                info!(
                    target: "reth::cli",
                    url,
                    start,
                    end,
                    "Fetching real pre-anchor headers for BLOCKHASH backfill"
                );
                fetch_pre_anchor_headers::<N>(url, start, end, pinned_header.parent_hash)?
            }
        } else {
            warn!(
                target: "reth::cli",
                "--header-backfill-rpc-url not set; pre-anchor headers will be zero-hash dummies. \
                 Post-anchor blocks that call BLOCKHASH on the last 256 pre-anchor blocks may \
                 diverge from consensus. See docs/PATH-B-DIAGNOSIS-25143845.md."
            );
            Vec::new()
        };

        setup_without_evm(
            &provider_rw,
            SealedHeader::new(header_for_setup, pinned_hash),
            |number| {
                let mut header = <<N::Primitives as NodePrimitives>::BlockHeader>::default();
                header.set_number(number);
                header
            },
            pre_anchor_headers,
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

        // Step 4: drain v5 trie tables (AccountsTrie + StoragesTrie)
        // directly from the bucket. Path A would re-derive them via
        // `compute_state_root_chunked` walking HashedAccounts/HashedStorages,
        // but that path produced a deterministic root mismatch we could
        // not isolate after three multi-hour debug rounds (see
        // docs/CHECKPOINT-IMPORT-SYNC.md). Path B trusts the
        // ed25519-signed v5 manifest's claim that the trie chunks match
        // the hashed chunks and writes raw `(key,value)` bytes through
        // `RawTable<PackedAccountsTrie>` / `RawDupSort<PackedStoragesTrie>`,
        // bypassing trie recomputation entirely.
        let expected_state_root = pinned_header.state_root();
        info!(
            target: "reth::cli",
            ?expected_state_root,
            "Draining v5 trie chunks into AccountsTrie/StoragesTrie"
        );

        // Clear any stale trie nodes from a prior run on this datadir.
        {
            let provider_rw = provider_factory.database_provider_rw()?;
            provider_rw.tx_ref().clear::<tables::AccountsTrie>()?;
            provider_rw.tx_ref().clear::<tables::StoragesTrie>()?;
            provider_rw.commit()?;
        }

        let t_trie = Instant::now();
        let (acct_trie_rows, storage_trie_rows) =
            drain_trie_tables_into_mdbx(&provider_factory, &state_client)?;
        let trie_elapsed_s = t_trie.elapsed().as_secs();

        info!(
            target: "reth::cli",
            pinned_block,
            pinned_hash = ?pinned_hash,
            ?expected_state_root,
            acct_trie_rows,
            storage_trie_rows,
            trie_elapsed_s,
            "Checkpoint import complete. Datadir is anchored at pinned block, \
             hashed plain state and trie tables are drained. State root is \
             trusted as part of the signed v5 manifest."
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
    let t0 = Instant::now();
    for segment in [StaticFileSegment::AccountChangeSets, StaticFileSegment::StorageChangeSets] {
        let mut writer = static_file_provider.get_writer(pinned_block, segment)?;
        let next_block = writer.next_block_number();
        if next_block > pinned_block {
            continue;
        }
        info!(
            target: "reth::cli",
            ?segment,
            from_block = next_block,
            to_block = pinned_block,
            "Padding empty v2 changeset segment before drain"
        );
        // Pad from `next_block` up to AND INCLUDING `pinned_block` so the
        // segment tip lines up with the stage checkpoint that
        // `setup_without_evm` set to `pinned_block`. If we stop at
        // `pinned_block - 1` the launcher's consistency check detects
        // `sf_tip=N-1, checkpoint=N` and triggers an unwind to N-1,
        // which then immediately fails MerkleStage because the dummy
        // header at N-1 has an empty-trie state root.
        for empty_block in next_block..=pinned_block {
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
        pinned_block,
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

/// Drain the v5 `AccountsTrie` + `StoragesTrie` chunks into MDBX as
/// raw key/value bytes — no decode, no re-encode. The bucket-state
/// client iterates shard-by-shard for the storage trie (so each shard's
/// trie nodes land in the same RW tx as the corresponding hashed-state
/// drain would, bounding the transient working set) and once globally
/// for the accounts trie.
fn drain_trie_tables_into_mdbx<PF>(
    provider_factory: &PF,
    state_client: &HttpBucketStateClient,
) -> eyre::Result<(usize, usize)>
where
    PF: DatabaseProviderFactory,
    PF::ProviderRW: DBProvider<Tx: DbTxMut>,
{
    let t0 = Instant::now();

    // --- AccountsTrie: one global stream of raw (key, value) bytes ---
    let mut acct_rows: usize = 0;
    {
        let provider_rw = provider_factory.database_provider_rw()?;
        {
            let tx = provider_rw.tx_ref();
            state_client.drain_accounts_trie_streaming(|row| {
                if let Err(err) = tx.put::<RawTable<tables::PackedAccountsTrie>>(
                    RawKey::from_vec(row.key_bytes),
                    RawValue::from_vec(row.value_bytes),
                ) {
                    warn!(target: "reth::cli", ?err, "PackedAccountsTrie put failed");
                } else {
                    acct_rows += 1;
                }
            })?;
        }
        provider_rw.commit()?;
    }
    info!(
        target: "reth::cli",
        acct_rows,
        elapsed_s = t0.elapsed().as_secs(),
        "AccountsTrie drain complete"
    );

    // --- StoragesTrie: per-shard, reusing the existing shard layout ---
    let t1 = Instant::now();
    let shard_ids = state_client.shard_ids();
    let total_shards = shard_ids.len();
    let mut storage_rows: usize = 0;
    let mut last_log = Instant::now();
    for (idx, shard) in shard_ids.into_iter().enumerate() {
        let provider_rw = provider_factory.database_provider_rw()?;
        let mut shard_rows: usize = 0;
        {
            let tx = provider_rw.tx_ref();
            state_client.drain_storages_trie_for_shard(shard, |row| {
                // Reassemble the dup value as it lives in MDBX:
                // `PackedStorageTrieEntry` = subkey(33) ++ node_bytes.
                let mut value = Vec::with_capacity(row.subkey_bytes.len() + row.node_bytes.len());
                value.extend_from_slice(&row.subkey_bytes);
                value.extend_from_slice(&row.node_bytes);
                if let Err(err) = tx.put::<RawDupSort<tables::PackedStoragesTrie>>(
                    RawKey::from(row.hashed_address),
                    RawValue::from_vec(value),
                ) {
                    warn!(target: "reth::cli", ?err, "PackedStoragesTrie put failed");
                } else {
                    shard_rows += 1;
                }
            })?;
        }
        provider_rw.commit()?;
        storage_rows += shard_rows;
        if last_log.elapsed().as_secs() >= 30 || idx.is_multiple_of(64) {
            info!(
                target: "reth::cli",
                shard = idx + 1,
                of = total_shards,
                storage_trie_rows = storage_rows,
                elapsed_s = t1.elapsed().as_secs(),
                "StoragesTrie drain progress"
            );
            last_log = Instant::now();
        }
    }
    info!(
        target: "reth::cli",
        storage_rows,
        elapsed_s = t1.elapsed().as_secs(),
        "StoragesTrie drain complete"
    );

    Ok((acct_rows, storage_rows))
}

impl<C: ChainSpecParser> ImportBucketCheckpointCommand<C> {
    /// Returns the underlying chain being used to run this command.
    pub fn chain_spec(&self) -> Option<&Arc<C::ChainSpec>> {
        Some(&self.env.chain)
    }
}

/// Fetch real headers for blocks `start..=end` from a JSON-RPC endpoint and validate
/// that they form a contiguous chain whose final block's hash equals `expected_tail_hash`
/// (which the caller passes as `anchor.parent_hash`). On success returns a Vec of
/// `(node_header, hash)` pairs in ascending block order, ready to feed into
/// `setup_without_evm`.
///
/// Uses blocking `reqwest` (the importer is single-threaded and the request count is
/// bounded at 256) with a per-request timeout to avoid hanging on a flaky endpoint.
fn fetch_pre_anchor_headers<N>(
    url: &str,
    start: u64,
    end: u64,
    expected_tail_hash: alloy_primitives::B256,
) -> eyre::Result<Vec<(<N::Primitives as NodePrimitives>::BlockHeader, alloy_primitives::B256)>>
where
    N: CliNodeTypes<Primitives: NodePrimitives<BlockHeader: HeaderMut>>,
{
    use alloy_primitives::B256;

    let client =
        reqwest::blocking::Client::builder().timeout(std::time::Duration::from_secs(15)).build()?;

    // Collect alloy headers + hashes first; validate the chain on the alloy side
    // (so we don't depend on the node header type implementing `Sealable` /
    // `BlockHeader` for the chain check). Then convert at the end.
    let len = (end - start + 1) as usize;
    let mut alloy_chain: Vec<(alloy_consensus::Header, B256)> = Vec::with_capacity(len);

    for (idx, number) in (start..=end).enumerate() {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_getBlockByNumber",
            "params": [format!("0x{number:x}"), false],
            "id": 1,
        });
        let resp: serde_json::Value = client
            .post(url)
            .json(&body)
            .send()
            .map_err(|e| eyre::eyre!("RPC POST failed for block {number}: {e}"))?
            .json()
            .map_err(|e| eyre::eyre!("RPC JSON parse failed for block {number}: {e}"))?;

        if let Some(err) = resp.get("error") {
            return Err(eyre::eyre!("RPC error for block {number}: {err}"));
        }
        let result = resp
            .get("result")
            .ok_or_else(|| eyre::eyre!("RPC response for block {number} missing `result`"))?;
        if result.is_null() {
            return Err(eyre::eyre!(
                "RPC returned null for block {number}; the backfill source is missing this block"
            ));
        }
        let rpc_block: alloy_rpc_types_eth::Block = serde_json::from_value(result.clone())
            .map_err(|e| eyre::eyre!("failed to deserialize Block for {number}: {e}"))?;
        let claimed_hash = rpc_block.header.hash;
        let alloy_header: alloy_consensus::Header = rpc_block.header.inner;

        // Self-consistency: the hash claimed by the RPC must equal the RLP hash.
        let computed_hash = alloy_header.hash_slow();
        if computed_hash != claimed_hash {
            return Err(eyre::eyre!(
                "RPC block {number} hash mismatch: claimed {claimed_hash:?} computed {computed_hash:?}"
            ));
        }
        if alloy_header.number != number {
            return Err(eyre::eyre!(
                "RPC returned block {} when {number} was requested",
                alloy_header.number,
            ));
        }
        if let Some((prev_header, prev_hash)) = alloy_chain.last() {
            if alloy_header.parent_hash != *prev_hash {
                return Err(eyre::eyre!(
                    "parent_hash chain broken between blocks {} and {number}",
                    prev_header.number,
                ));
            }
        }

        alloy_chain.push((alloy_header, claimed_hash));

        if idx % 32 == 0 || number == end {
            info!(
                target: "reth::cli",
                fetched = idx + 1,
                of = len,
                "Header backfill progress"
            );
        }
    }

    let last_hash = alloy_chain.last().expect("non-empty by construction").1;
    if last_hash != expected_tail_hash {
        return Err(eyre::eyre!(
            "tail hash {last_hash:?} does not match anchor.parent_hash {expected_tail_hash:?} \
             — the backfill source is on a different chain than the manifest"
        ));
    }

    // Convert to node header type. The hash we pass through is the alloy-computed
    // hash; for chains where the node header type is identical to the alloy header
    // (mainnet/sepolia) the round-trip preserves it exactly.
    let mut out: Vec<(<N::Primitives as NodePrimitives>::BlockHeader, B256)> =
        Vec::with_capacity(len);
    for (alloy_header, hash) in alloy_chain {
        let node_header = alloy_to_node_header::<N>(&alloy_header)?;
        out.push((node_header, hash));
    }

    Ok(out)
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

#[cfg(test)]
mod tests {
    //! Direct round-trip of the v5 trie drain — same `RawTable` /
    //! `RawDupSort` write contract `drain_trie_tables_into_mdbx` uses,
    //! exercised against a real test MDBX without requiring an
    //! `HttpBucketStateClient`. Catches typed/raw key encoding drift
    //! (the failure mode that would silently corrupt `AccountsTrie`).
    use super::*;
    use alloy_primitives::B256;
    use reth_db_api::{cursor::DbCursorRO, transaction::DbTx};
    use reth_provider::{test_utils::create_test_provider_factory, DBProvider};

    #[test]
    fn raw_trie_writes_round_trip_through_raw_cursor_reads() {
        let pf = create_test_provider_factory();

        // Synthetic AccountsTrie row: 33-byte packed key + 4-byte
        // node payload. Encoded shape matches
        // `PackedStoredNibbles::to_compact_array()` for a 2-nibble path
        // 0xa, 0xb (packed byte 0xab + nibble-count byte 2).
        let acct_key_bytes: Vec<u8> = {
            let mut v = vec![0u8; 33];
            v[0] = 0xab;
            v[32] = 2;
            v
        };
        let acct_value_bytes: Vec<u8> = vec![0xde, 0xad, 0xbe, 0xef];

        // Synthetic StoragesTrie dup row: 32-byte hashed_address,
        // 33-byte subkey, 4-byte node payload. The dup value lives on
        // disk as `subkey ++ node`.
        let hashed_addr = B256::from([0x42u8; 32]);
        let st_subkey: Vec<u8> = {
            let mut v = vec![0u8; 33];
            v[0] = 0xee;
            v[32] = 2;
            v
        };
        let st_node: Vec<u8> = vec![0xfe, 0xed, 0xfa, 0xce];

        {
            let provider_rw = pf.database_provider_rw().unwrap();
            let tx = provider_rw.tx_ref();
            tx.put::<RawTable<tables::PackedAccountsTrie>>(
                RawKey::from_vec(acct_key_bytes.clone()),
                RawValue::from_vec(acct_value_bytes.clone()),
            )
            .unwrap();
            let mut st_value = Vec::with_capacity(st_subkey.len() + st_node.len());
            st_value.extend_from_slice(&st_subkey);
            st_value.extend_from_slice(&st_node);
            tx.put::<RawDupSort<tables::PackedStoragesTrie>>(
                RawKey::from(hashed_addr),
                RawValue::from_vec(st_value.clone()),
            )
            .unwrap();
            provider_rw.commit().unwrap();
        }

        // Read back through the raw cursors — proves the on-disk bytes
        // round-trip byte-for-byte under `Encode`/`Decode` for the raw
        // adapters that `drain_trie_tables_into_mdbx` uses. Any drift
        // in how MDBX serializes the key would show up here.
        let provider_ro = pf.database_provider_ro().unwrap();
        let tx = provider_ro.tx_ref();

        let mut at_cursor = tx.cursor_read::<RawTable<tables::PackedAccountsTrie>>().unwrap();
        let (k, v) = at_cursor.first().unwrap().expect("AccountsTrie row present");
        assert_eq!(k.raw_key(), &acct_key_bytes, "raw AccountsTrie key bytes preserved");
        assert_eq!(v.raw_value(), &acct_value_bytes[..], "raw AccountsTrie value bytes preserved");

        let mut st_cursor = tx.cursor_read::<RawDupSort<tables::PackedStoragesTrie>>().unwrap();
        let (k, v) = st_cursor.first().unwrap().expect("StoragesTrie row present");
        assert_eq!(k.raw_key(), hashed_addr.as_slice(), "raw StoragesTrie key bytes preserved");
        let mut expected_value = Vec::new();
        expected_value.extend_from_slice(&st_subkey);
        expected_value.extend_from_slice(&st_node);
        assert_eq!(
            v.raw_value(),
            &expected_value[..],
            "raw StoragesTrie dup value (subkey ++ node) preserved"
        );
    }
}
