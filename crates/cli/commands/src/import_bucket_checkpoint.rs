//! Spike: `reth import-bucket-checkpoint`.
//!
//! Fetches the bucket-state checkpoint manifest, reads the pinned header, and
//! seeds MDBX + static_files so that subsequent `reth node` runs treat the
//! pinned block as the canonical local tip. The CL's first forkchoiceUpdated
//! then triggers only a short backfill (pinned → tip) instead of a full
//! staged sync from genesis.
//!
//! **Spike scope**: this lands the engine-tree anchor (headers + per-stage
//! `StageCheckpoint::new(pinned)`). It does NOT drain the bucket's plain
//! state into MDBX or rebuild the trie. As-is, `eth_blockNumber` after this
//! command returns `pinned`, the bucket-state RPC continues serving reads at
//! ≤ pinned, but the *first* block executed past pinned will fail in
//! `ExecutionStage` because `LatestStateProviderRef` reads plain state from
//! empty MDBX tables. See `docs/CHECKPOINT-IMPORT-SYNC.md` for the
//! productionization roadmap.

use crate::common::{AccessRights, CliNodeTypes, Environment, EnvironmentArgs};
use alloy_consensus::BlockHeader as AlloyBlockHeader;
use clap::Parser;
use reth_bucket_state_client::{
    BucketStateClientConfig, BucketStateConnConfig, HttpBucketStateClient,
};
use reth_chainspec::{EthChainSpec, EthereumHardforks};
use reth_cli::chainspec::ChainSpecParser;
use reth_node_api::NodePrimitives;
use reth_node_core::args::BucketArgs;
use reth_primitives_traits::{header::HeaderMut, SealedHeader};
use reth_provider::{
    BlockNumReader, BucketStateClient, DBProvider, DatabaseProviderFactory,
    StaticFileProviderFactory, StaticFileWriter,
};
use std::sync::Arc;
use tracing::info;

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

        info!(
            target: "reth::cli",
            pinned_block,
            pinned_hash = ?pinned_hash,
            "Checkpoint import complete. Datadir is anchored at pinned block. \
             NOTE: plain-state was NOT drained into MDBX; the very first block \
             past pinned will fail in ExecutionStage until that follow-up ships."
        );
        Ok(())
    }
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
