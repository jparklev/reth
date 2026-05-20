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
use alloy_primitives::{B256, U256};
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

/// Number of `(account or storage slot)` writes after which to commit the
/// pending DB transaction. Keeps MDBX dirty-page footprint bounded during
/// the multi-hundred-million-entry drain.
const DRAIN_COMMIT_THRESHOLD: usize = 1_000_000;

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
            max_concurrent_shard_loads: 2,
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

        // Static-files commit must happen before the DB tx commit so the
        // header is durably visible. This mirrors the order in
        // `crates/cli/commands/src/init_state/mod.rs` line 111.
        static_file_provider.commit()?;
        provider_rw.commit()?;

        info!(target: "reth::cli", "Engine-tree anchor committed; starting plain-state drain");

        // Step 3: eagerly hydrate every checkpoint shard. The bucket-state
        // client's normal read path is lazy (shards materialize on first
        // SLOAD that hits them); for the import we want the full snapshot
        // in memory so we can drain it into MDBX in one shot.
        let hydrate_t0 = Instant::now();
        state_client
            .hydrate_all_shards()
            .map_err(|err| eyre::eyre!("hydrate_all_shards failed: {err}"))?;
        info!(
            target: "reth::cli",
            elapsed_ms = hydrate_t0.elapsed().as_millis() as u64,
            accounts = state_client.account_count(),
            storage = state_client.storage_count(),
            codes = state_client.code_count(),
            "Bucket-state shards fully materialized"
        );

        // Step 4: drain the in-memory caches into MDBX. We write only the
        // hashed-keyed tables because the bucket-state client doesn't know
        // plain addresses (everything is keccak-prefix-sharded). With
        // storage_v2, `LatestStateProviderRef::basic_account` reads
        // `HashedAccounts` keyed by keccak(addr), and storage reads come
        // from `HashedStorages` keyed by keccak(addr) + keccak(slot).
        drain_state_into_mdbx(&provider_factory, &state_client)?;

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

/// Drain the bucket-state-client's in-memory account/storage/code caches
/// into MDBX. We use raw cursor `put` / `upsert` calls because the bucket
/// caches yield rows in hash-bucket order (not sorted), so the
/// append/append_dup MDBX fast path doesn't apply.
///
/// Commits in chunks of `DRAIN_COMMIT_THRESHOLD` to bound MDBX dirty-page
/// accumulation. Per-account writes touch only `HashedAccounts`, per-storage
/// writes touch `HashedStorages` (DupSort), and per-code writes touch
/// `Bytecodes`. We do NOT touch `PlainAccountState`, `PlainStorageState`,
/// `AccountChangeSets`, `StorageChangeSets`, `AccountsHistory`, or
/// `StoragesHistory` — none of those are reachable from the bucket-state
/// hash-keyed format, and with storage_v2 + the post-pinned engine-tree
/// anchor, reth's stage pipeline doesn't need them for blocks ≤ pinned.
fn drain_state_into_mdbx<PF>(
    provider_factory: &PF,
    state_client: &HttpBucketStateClient,
) -> eyre::Result<()>
where
    PF: DatabaseProviderFactory,
    PF::ProviderRW: DBProvider<Tx: DbTxMut>,
{
    use reth_db_api::cursor::DbCursorRW;

    let total_t0 = Instant::now();
    let mut total_accounts: usize = 0;
    let mut total_storage: usize = 0;
    let mut total_codes: usize = 0;

    // --- Bytecodes pass ---
    // Smallest of the three families. Single transaction is fine.
    {
        let provider_rw = provider_factory.database_provider_rw()?;
        let tx = provider_rw.tx_ref();
        for (code_hash, bytes) in state_client.iter_codes() {
            tx.put::<tables::Bytecodes>(code_hash, Bytecode::new_raw(bytes))?;
            total_codes += 1;
        }
        provider_rw.commit()?;
        info!(target: "reth::cli", count = total_codes, "Drained Bytecodes");
    }

    // --- HashedAccounts pass ---
    // Each row is ~100 bytes; commit every threshold to bound dirty pages.
    {
        let mut provider_rw = provider_factory.database_provider_rw()?;
        let mut pending: usize = 0;
        for (hashed_addr, account) in state_client.iter_accounts() {
            provider_rw.tx_ref().put::<tables::HashedAccounts>(hashed_addr, account)?;
            total_accounts += 1;
            pending += 1;
            if pending >= DRAIN_COMMIT_THRESHOLD {
                provider_rw.commit()?;
                provider_rw = provider_factory.database_provider_rw()?;
                pending = 0;
                info!(
                    target: "reth::cli",
                    drained = total_accounts,
                    elapsed_s = total_t0.elapsed().as_secs(),
                    "Drained HashedAccounts chunk"
                );
            }
        }
        provider_rw.commit()?;
        info!(target: "reth::cli", count = total_accounts, "Drained HashedAccounts");
    }

    // --- HashedStorages pass ---
    // DupSort table keyed by `B256` (hashed addr) with `StorageEntry`
    // (key=hashed_slot, value=U256) as the duplicate value. The cache
    // yields rows in HashMap order, NOT sorted by (addr, slot), so we
    // can't use append_dup; we use `upsert` which does a full B-tree
    // lookup but also handles the unsorted insertion order correctly.
    //
    // We materialize the cache iter into a Vec up front so we can do
    // chunked commits without having to restart the moka iterator
    // (moka's iter is single-pass and the second pass would have no
    // ordering guarantee, so a skip-N replay would double-write some
    // rows and miss others).
    {
        let mut storage_rows: Vec<(B256, B256, U256)> =
            state_client.iter_storage().filter(|(_, _, v)| !v.is_zero()).collect();
        info!(
            target: "reth::cli",
            count = storage_rows.len(),
            "Collected HashedStorages rows for drain"
        );
        // Sort by (hashed_addr, hashed_slot) so DupSort upserts hit the
        // MDBX append fast path within each address group.
        storage_rows.sort_unstable_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));

        let mut idx: usize = 0;
        while idx < storage_rows.len() {
            let chunk_end = (idx + DRAIN_COMMIT_THRESHOLD).min(storage_rows.len());
            let provider_rw = provider_factory.database_provider_rw()?;
            {
                let tx = provider_rw.tx_ref();
                let mut cursor = tx.cursor_dup_write::<tables::HashedStorages>()?;
                for (hashed_addr, hashed_slot, value) in &storage_rows[idx..chunk_end] {
                    cursor
                        .upsert(*hashed_addr, &StorageEntry { key: *hashed_slot, value: *value })?;
                    total_storage += 1;
                }
            }
            provider_rw.commit()?;
            info!(
                target: "reth::cli",
                drained = total_storage,
                of = storage_rows.len(),
                elapsed_s = total_t0.elapsed().as_secs(),
                "Drained HashedStorages chunk"
            );
            idx = chunk_end;
        }
        info!(target: "reth::cli", count = total_storage, "Drained HashedStorages");
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
