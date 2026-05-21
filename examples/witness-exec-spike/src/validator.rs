//! Validate a block from a witness fetched from S3 (or local file).
//!
//! End-to-end:
//! 1. Fetch witness bundle JSON from S3 (or local file).
//! 2. Decode header + body, re-construct `RecoveredBlock`.
//! 3. Build `DecodedMultiProofV2` from `witness.state` and reveal a `SparseStateTrie`.
//! 4. Build `WitnessDb` (state from sparse trie, codes by `keccak(bytecode)`, block
//!    hashes from ancestor headers in the witness).
//! 5. Execute via `EthEvmConfig::executor`.
//! 6. Recompute post-state root from the sparse trie + bundle changes.
//! 7. Assert post-state root == header.state_root.
//!
//! Reports wall-clock for each phase.

use alloy_consensus::{Block as ConsensusBlock, Header};
use alloy_primitives::{keccak256, map::B256Map, Address, Bytes, B256, U256};
use alloy_rlp::{Decodable, Encodable};
use alloy_trie::TrieAccount;
use clap::Parser;
use eyre::{Context, OptionExt};
use itertools::Itertools;
use rayon::prelude::*;
use reth_chainspec::{ChainSpec, MAINNET};
use reth_ethereum_primitives::BlockBody;
use reth_evm::{execute::Executor, ConfigureEvm};
use reth_evm_ethereum::EthEvmConfig;
use reth_execution_errors::SparseStateTrieResult;
use reth_primitives_traits::SealedBlock;
use reth_revm::{
    bytecode::Bytecode,
    db::State,
    state::AccountInfo,
    Database,
};
use reth_trie::{HashedPostState, KeccakKeyHasher, Nibbles, EMPTY_ROOT_HASH, TRIE_ACCOUNT_RLP_MAX_SIZE};
use reth_trie_common::DecodedMultiProofV2;
use reth_trie_sparse::{RevealableSparseTrie, SparseStateTrie, SparseTrie};
use serde::{Deserialize, Serialize};
use std::{
    path::PathBuf,
    sync::Arc,
    time::Instant,
};

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
    /// Key (e.g. witnesses/0xabc...def.json).
    #[arg(long, env = "S3_KEY")]
    key: Option<String>,

    /// Alternatively, read directly from a local file.
    #[arg(long, conflicts_with_all = ["endpoint", "bucket", "key"])]
    local: Option<PathBuf>,

    /// Chain (mainnet only).
    #[arg(long, default_value = "mainnet")]
    chain: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct WitnessBundle {
    header: Bytes,
    block_body: Bytes,
    witness: alloy_rpc_types_debug::ExecutionWitness,
    parent_state_root: B256,
    expected_state_root: B256,
    block_number: u64,
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
    let raw = if let Some(local) = &cli.local {
        std::fs::read(local).wrap_err_with(|| format!("read {}", local.display()))?
    } else {
        fetch_from_s3(&cli)?
    };
    let fetch_elapsed = t_fetch.elapsed();
    println!(
        "[1/6] fetch:    {:>7.3}s  ({:.2} MiB)",
        fetch_elapsed.as_secs_f64(),
        raw.len() as f64 / (1024.0 * 1024.0)
    );

    // ---------- 2. Decode ----------
    let t_decode = Instant::now();
    let bundle: WitnessBundle = serde_json::from_slice(&raw).wrap_err("decode bundle JSON")?;
    let header = Header::decode(&mut bundle.header.as_ref()).wrap_err("decode header")?;
    let body = BlockBody::decode(&mut bundle.block_body.as_ref()).wrap_err("decode body")?;
    let consensus_block = ConsensusBlock::new(header.clone(), body);
    let sealed = SealedBlock::seal_slow(consensus_block);
    let recovered = sealed.try_recover().wrap_err("recover senders")?;
    let decode_elapsed = t_decode.elapsed();
    println!(
        "[2/6] decode:   {:>7.3}s  (block #{}, state nodes={}, codes={}, ancestors={})",
        decode_elapsed.as_secs_f64(),
        bundle.block_number,
        bundle.witness.state.len(),
        bundle.witness.codes.len(),
        bundle.witness.headers.len(),
    );

    // ---------- 3. Reveal sparse trie ----------
    let t_reveal = Instant::now();
    // ExecutionWitness `state` is Vec<Bytes>. Compute keccak(node) keys.
    let mut state_witness: B256Map<Bytes> = B256Map::default();
    for node in &bundle.witness.state {
        state_witness.insert(keccak256(node), node.clone());
    }
    let multiproof =
        DecodedMultiProofV2::from_witness(bundle.parent_state_root, &state_witness)
            .wrap_err("DecodedMultiProofV2::from_witness")?;
    let mut sparse: SparseStateTrie = SparseStateTrie::default();
    sparse
        .reveal_decoded_multiproof_v2(multiproof)
        .wrap_err("reveal_decoded_multiproof_v2")?;
    let reveal_elapsed = t_reveal.elapsed();
    println!("[3/6] reveal:   {:>7.3}s", reveal_elapsed.as_secs_f64());

    // ---------- 4. Build bytecode + blockhash maps ----------
    let mut codes: B256Map<Bytecode> = B256Map::default();
    for raw in &bundle.witness.codes {
        codes.insert(keccak256(raw), Bytecode::new_raw(raw.clone()));
    }
    let mut ancestor_hashes: alloy_primitives::map::HashMap<u64, B256> = Default::default();
    for h in &bundle.witness.headers {
        let hdr = Header::decode(&mut h.as_ref()).wrap_err("decode ancestor header")?;
        let h = hdr.hash_slow();
        ancestor_hashes.insert(hdr.number, h);
    }

    // ---------- 5. Execute ----------
    let t_exec = Instant::now();
    let evm_config = EthEvmConfig::new(spec.clone());
    let db = WitnessDb {
        sparse: &sparse,
        codes: &codes,
        ancestor_hashes: &ancestor_hashes,
    };
    let state = State::builder().with_database(db).with_bundle_update().build();

    let executor = evm_config.executor(state);
    let output = executor.execute(&recovered).wrap_err("execute block")?;
    let bundle_state = output.state;
    let exec_elapsed = t_exec.elapsed();
    println!(
        "[5/6] execute:  {:>7.3}s  (txs={}, gas_used={})",
        exec_elapsed.as_secs_f64(),
        recovered.body().transactions.len(),
        output.result.gas_used
    );

    // ---------- 6. State root + verify ----------
    let t_root = Instant::now();
    let hashed_state =
        HashedPostState::from_bundle_state::<KeccakKeyHasher>(bundle_state.state.iter());
    let mut sparse = sparse;
    let computed_root = calculate_state_root(&mut sparse, hashed_state)
        .wrap_err("calculate_state_root")?;
    let root_elapsed = t_root.elapsed();
    println!("[6/6] root:     {:>7.3}s", root_elapsed.as_secs_f64());

    if computed_root != bundle.expected_state_root {
        eyre::bail!(
            "STATE-ROOT MISMATCH: got {:?}, expected {:?}",
            computed_root,
            bundle.expected_state_root
        );
    }
    println!();
    println!("OK: state root {} matches header", computed_root);
    println!("OK: header hash {}", recovered.hash());

    let total = overall_start.elapsed();
    println!();
    println!("==================================================");
    println!("TOTAL fetch→verify:         {:>7.3}s", total.as_secs_f64());
    println!("  fetch (S3 GET):           {:>7.3}s", fetch_elapsed.as_secs_f64());
    println!("  decode (JSON+RLP):        {:>7.3}s", decode_elapsed.as_secs_f64());
    println!("  reveal sparse trie:       {:>7.3}s", reveal_elapsed.as_secs_f64());
    println!("  execute (revm):           {:>7.3}s", exec_elapsed.as_secs_f64());
    println!("  state root recompute:     {:>7.3}s", root_elapsed.as_secs_f64());
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

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()?;

    rt.block_on(async move {
        let loader = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(cli.region.clone()))
            .endpoint_url(&endpoint);
        let shared = loader.load().await;

        let s3_config =
            aws_sdk_s3::config::Builder::from(&shared).force_path_style(true).build();
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

// ============================================================================
// WitnessDb — reth_revm::Database impl backed by sparse trie + bytecode map
// ============================================================================

#[derive(Debug)]
struct WitnessDb<'a> {
    sparse: &'a SparseStateTrie,
    codes: &'a B256Map<Bytecode>,
    ancestor_hashes: &'a alloy_primitives::map::HashMap<u64, B256>,
}

impl<'a> Database for WitnessDb<'a> {
    type Error = WitnessDbError;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        let hashed_address = keccak256(address);
        let Some(bytes) = self.sparse.get_account_value(&hashed_address) else {
            return Ok(None);
        };
        let account = TrieAccount::decode(&mut bytes.as_slice())
            .map_err(|e| WitnessDbError::Decode(format!("account: {e}")))?;
        Ok(Some(AccountInfo {
            balance: account.balance,
            nonce: account.nonce,
            code_hash: account.code_hash,
            account_id: None,
            code: None,
        }))
    }

    fn storage(&mut self, address: Address, slot: U256) -> Result<U256, Self::Error> {
        let hashed_address = keccak256(address);
        let hashed_slot = keccak256(B256::from(slot));
        let Some(value) = self.sparse.get_storage_slot_value(&hashed_address, &hashed_slot) else {
            return Ok(U256::ZERO);
        };
        U256::decode(&mut value.as_slice())
            .map_err(|e| WitnessDbError::Decode(format!("storage: {e}")))
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.codes
            .get(&code_hash)
            .cloned()
            .ok_or(WitnessDbError::MissingCode(code_hash))
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        self.ancestor_hashes
            .get(&number)
            .copied()
            .ok_or(WitnessDbError::MissingBlockHash(number))
    }
}

#[derive(Debug, thiserror::Error)]
enum WitnessDbError {
    #[error("decode: {0}")]
    Decode(String),
    #[error("missing code for hash {0}")]
    MissingCode(B256),
    #[error("missing block hash for number {0}")]
    MissingBlockHash(u64),
}

impl reth_revm::database_interface::DBErrorMarker for WitnessDbError {}

// ============================================================================
// State-root recompute — ported from ress/crates/engine/src/tree/root.rs,
// adapted to current upstream SparseStateTrie / RevealableSparseTrie API.
// ============================================================================

fn calculate_state_root(
    trie: &mut SparseStateTrie,
    state: HashedPostState,
) -> SparseStateTrieResult<B256> {
    use std::sync::mpsc;

    // Storage tries (parallel).
    let (storage_tx, storage_rx) = mpsc::channel();
    state
        .storages
        .into_iter()
        .map(|(address, storage)| (address, storage, trie.take_storage_trie(&address)))
        .par_bridge()
        .map(|(address, storage, storage_trie)| {
            let mut storage_trie = storage_trie.unwrap_or_else(RevealableSparseTrie::revealed_empty);

            if storage.wiped {
                storage_trie.wipe()?;
            }
            for (hashed_slot, value) in storage
                .storage
                .into_iter()
                .sorted_unstable_by_key(|(hashed_slot, _)| *hashed_slot)
            {
                let nibbles = Nibbles::unpack(hashed_slot);
                if value.is_zero() {
                    storage_trie.remove_leaf(&nibbles)?;
                } else {
                    storage_trie.update_leaf(nibbles, alloy_rlp::encode_fixed_size(&value).to_vec())?;
                }
            }
            let _ = storage_trie.root();
            SparseStateTrieResult::Ok((address, storage_trie))
        })
        .for_each_init(|| storage_tx.clone(), |storage_tx, result| storage_tx.send(result).unwrap());
    drop(storage_tx);
    for result in storage_rx {
        let (address, storage_trie) = result?;
        trie.insert_storage_trie(address, storage_trie);
    }

    // Account leaves.
    let mut account_rlp_buf = Vec::with_capacity(TRIE_ACCOUNT_RLP_MAX_SIZE);
    for (hashed_address, account) in
        state.accounts.into_iter().sorted_unstable_by_key(|(hashed_address, _)| *hashed_address)
    {
        let nibbles = Nibbles::unpack(hashed_address);
        let account = account.unwrap_or_default();
        let storage_root = if let Some(storage_trie) = trie.storage_trie_mut(&hashed_address) {
            storage_trie.root()
        } else if let Some(value) = trie.get_account_value(&hashed_address) {
            TrieAccount::decode(&mut &value[..])?.storage_root
        } else {
            EMPTY_ROOT_HASH
        };

        if account.is_empty() && storage_root == EMPTY_ROOT_HASH {
            trie.remove_account_leaf(&nibbles)?;
        } else {
            account_rlp_buf.clear();
            account.into_trie_account(storage_root).encode(&mut account_rlp_buf);
            trie.update_account_leaf(nibbles, account_rlp_buf.clone())?;
        }
    }

    trie.root()
}
