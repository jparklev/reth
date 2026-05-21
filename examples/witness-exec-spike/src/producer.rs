//! Produce an `ExecutionWitness` for a given block by opening a reth datadir read-only.
//!
//! Mirrors what `debug_executionWitnessByBlockHash` does, but bypasses the live RPC.
//! Used to manufacture witnesses for the spike validator without depending on a
//! working witness RPC on the prod node.
//!
//! Layout of the JSON file emitted to S3 / local disk:
//!
//! ```json
//! {
//!   "header":  "0x<rlp(header)>",
//!   "block_body": "0x<rlp(body)>",
//!   "witness": { ... alloy_rpc_types_debug::ExecutionWitness ... }
//! }
//! ```
//!
//! The validator reads this exact file shape, reconstructs a `RecoveredBlock`, reveals
//! a `SparseStateTrie` from the witness, executes via `WitnessDatabase`, and verifies
//! the post-state root + header hash.

use alloy_consensus::BlockHeader;
use alloy_primitives::{Bytes, B256};
use alloy_rlp::Encodable;
use clap::Parser;
use eyre::WrapErr;
use reth_chainspec::{ChainSpec, MAINNET};
use reth_ethereum::{
    evm::{revm::database::StateProviderDatabase, EthEvmConfig},
    node::EthereumNode,
    provider::providers::{ReadOnlyConfig, BlockchainProvider},
};
use reth_evm::{execute::Executor, ConfigureEvm};
use reth_revm::{db::State, witness::ExecutionWitnessRecord};
use reth_storage_api::{BlockReader, HeaderProvider, StateProviderFactory, TransactionVariant};
use reth_trie_common::ExecutionWitnessMode;
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, sync::Arc, time::Instant};

#[derive(Parser, Debug)]
#[command(about = "Produce an ExecutionWitness for a block from a reth datadir (read-only)")]
struct Cli {
    /// Path to reth datadir (e.g. /var/lib/reth). Opened read-only.
    #[arg(long, env = "RETH_DATADIR")]
    datadir: PathBuf,
    /// Block hash to produce a witness for.
    #[arg(long)]
    block: B256,
    /// Output path for the JSON witness bundle.
    #[arg(long)]
    out: PathBuf,
    /// Chain (mainnet only for now).
    #[arg(long, default_value = "mainnet")]
    chain: String,
}

/// JSON envelope written to disk / S3. Validator reads this exact shape.
#[derive(Serialize, Deserialize, Debug)]
pub struct WitnessBundle {
    /// RLP-encoded block header.
    pub header: Bytes,
    /// RLP-encoded block body.
    pub block_body: Bytes,
    /// The execution witness (state nodes, codes, keys, ancestor headers).
    pub witness: alloy_rpc_types_debug::ExecutionWitness,
    /// Parent state root — convenience for validator (== header.state_root of parent).
    pub parent_state_root: B256,
    /// Expected post-state root — convenience (== this block's header.state_root).
    pub expected_state_root: B256,
    /// Block number — convenience.
    pub block_number: u64,
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

    let runtime = reth_tasks::Runtime::test();
    let factory = EthereumNode::provider_factory_builder().open_read_only(
        spec.clone(),
        ReadOnlyConfig::from_datadir(&cli.datadir),
        runtime,
    )?;

    // Resolve block.
    let provider = factory.provider()?;
    let recovered = provider
        .recovered_block(cli.block.into(), TransactionVariant::WithHash)?
        .ok_or_else(|| eyre::eyre!("block {} not found", cli.block))?;
    let recovered = Arc::new(recovered);
    let parent_hash = recovered.parent_hash();
    let parent_state_root = provider
        .header_by_hash_or_number(parent_hash.into())?
        .ok_or_else(|| eyre::eyre!("parent header {} not found", parent_hash))?
        .state_root();
    let expected_state_root = recovered.state_root();
    let block_number = recovered.number();

    println!(
        "producing witness for block {} (number={}) parent={} expected_root={}",
        cli.block, block_number, parent_hash, expected_state_root
    );

    // Use BlockchainProvider to get a StateProviderFactory we can call state_by_block_hash on.
    let blockchain = BlockchainProvider::new(factory.clone())?;

    let started = Instant::now();
    let state_provider = blockchain.state_by_block_hash(parent_hash)?;
    let evm_config = EthEvmConfig::new(spec);
    let mut db = State::builder()
        .with_database(StateProviderDatabase::new(&state_provider))
        .with_bundle_update()
        .build();

    let mut witness_record = ExecutionWitnessRecord::default();
    let executor = evm_config.executor(&mut db);
    executor
        .execute_with_state_closure(&recovered, |statedb: &State<_>| {
            witness_record.record_executed_state(statedb, ExecutionWitnessMode::Canonical);
        })
        .wrap_err("execute_with_state_closure failed")?;

    // Generate proofs + headers.
    let witness = witness_record
        .into_execution_witness(
            &state_provider,
            &provider,
            block_number,
            ExecutionWitnessMode::Canonical,
        )
        .wrap_err("into_execution_witness failed")?;

    let produce_elapsed = started.elapsed();

    // Encode header + body.
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

    let json = serde_json::to_vec_pretty(&bundle)?;
    std::fs::write(&cli.out, &json)?;
    println!(
        "wrote {} ({} bytes, state nodes={}, codes={}) in {:.2}s",
        cli.out.display(),
        json.len(),
        bundle.witness.state.len(),
        bundle.witness.codes.len(),
        produce_elapsed.as_secs_f64()
    );
    Ok(())
}
