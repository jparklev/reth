//! Per-block witness validation, factored so both `witness-validator`
//! (single block) and `witness-stream` (many blocks) can share it.
//!
//! The two pieces here:
//!   - [`validate_bundle`]: decode → reveal → execute → recompute root, returning a
//!     [`BlockTimings`] breakdown and the computed state root.
//!   - [`WitnessDb`] + [`calculate_state_root`]: the building blocks.
//!
//! All wall-clock measurements are `std::time::Instant`-based; this module
//! is fully sync (the streaming binary calls it from `spawn_blocking`).

use alloy_consensus::{Block as ConsensusBlock, Header};
use alloy_primitives::{keccak256, map::B256Map, Address, Bytes, B256, U256};
use alloy_rlp::{Decodable, Encodable};
use alloy_trie::TrieAccount;
use eyre::Context;
use itertools::Itertools;
use rayon::prelude::*;
use reth_chainspec::ChainSpec;
use reth_ethereum_primitives::BlockBody;
use reth_evm::{execute::Executor, ConfigureEvm};
use reth_evm_ethereum::EthEvmConfig;
use reth_execution_errors::SparseStateTrieResult;
use reth_primitives_traits::SealedBlock;
use reth_revm::{bytecode::Bytecode, db::State, state::AccountInfo, Database};
use reth_trie::{
    HashedPostState, KeccakKeyHasher, Nibbles, EMPTY_ROOT_HASH, TRIE_ACCOUNT_RLP_MAX_SIZE,
};
use reth_trie_common::DecodedMultiProofV2;
use reth_trie_sparse::{RevealableSparseTrie, SparseStateTrie, SparseTrie};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

#[path = "bundle.rs"]
mod bundle;
pub(crate) use bundle::{decode_bundle, encode_bundle, Encoding, WitnessBundle};

/// Per-phase timings for one validated block. Fields are read by the
/// single-block validator binary; the streaming binary uses `total_compute`
/// only — hence the per-binary dead-code allowance.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct BlockTimings {
    pub(crate) decode: Duration,
    pub(crate) reveal: Duration,
    pub(crate) execute: Duration,
    pub(crate) root: Duration,
    /// `decode + reveal + execute + root`. Excludes fetch.
    pub(crate) total_compute: Duration,
}

/// Result of validating one bundle.
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct ValidationOutcome {
    pub(crate) block_number: u64,
    pub(crate) block_hash: B256,
    pub(crate) computed_root: B256,
    pub(crate) expected_root: B256,
    pub(crate) gas_used: u64,
    pub(crate) tx_count: usize,
    pub(crate) timings: BlockTimings,
}

/// Decode → reveal → execute → state-root → verify. Returns the per-phase timings
/// and computed root. Caller checks `computed_root == expected_root`.
pub(crate) fn validate_bundle(
    spec: Arc<ChainSpec>,
    bundle: WitnessBundle,
) -> eyre::Result<ValidationOutcome> {
    let t_decode = Instant::now();
    let header = Header::decode(&mut bundle.header.as_ref()).wrap_err("decode header")?;
    let body = BlockBody::decode(&mut bundle.block_body.as_ref()).wrap_err("decode body")?;
    let consensus_block = ConsensusBlock::new(header.clone(), body);
    let sealed = SealedBlock::seal_slow(consensus_block);
    let recovered = sealed.try_recover().wrap_err("recover senders")?;
    let decode = t_decode.elapsed();

    let t_reveal = Instant::now();
    let mut state_witness: B256Map<Bytes> = B256Map::default();
    for node in &bundle.witness.state {
        state_witness.insert(keccak256(node), node.clone());
    }
    let multiproof = DecodedMultiProofV2::from_witness(bundle.parent_state_root, &state_witness)
        .wrap_err("DecodedMultiProofV2::from_witness")?;
    let mut sparse: SparseStateTrie = SparseStateTrie::default();
    sparse.reveal_decoded_multiproof_v2(multiproof).wrap_err("reveal_decoded_multiproof_v2")?;

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
    let reveal = t_reveal.elapsed();

    let t_exec = Instant::now();
    let evm_config = EthEvmConfig::new(spec);
    let db = WitnessDb { sparse: &sparse, codes: &codes, ancestor_hashes: &ancestor_hashes };
    let state = State::builder().with_database(db).with_bundle_update().build();
    let executor = evm_config.executor(state);
    let output = executor.execute(&recovered).wrap_err("execute block")?;
    let bundle_state = output.state;
    let gas_used = output.result.gas_used;
    let tx_count = recovered.body().transactions.len();
    let execute = t_exec.elapsed();

    let t_root = Instant::now();
    let hashed_state =
        HashedPostState::from_bundle_state::<KeccakKeyHasher>(bundle_state.state.iter());
    let mut sparse = sparse;
    let computed_root =
        calculate_state_root(&mut sparse, hashed_state).wrap_err("calculate_state_root")?;
    let root = t_root.elapsed();

    let total_compute = decode + reveal + execute + root;
    Ok(ValidationOutcome {
        block_number: bundle.block_number,
        block_hash: recovered.hash(),
        computed_root,
        expected_root: bundle.expected_state_root,
        gas_used,
        tx_count,
        timings: BlockTimings { decode, reveal, execute, root, total_compute },
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
        self.codes.get(&code_hash).cloned().ok_or(WitnessDbError::MissingCode(code_hash))
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        self.ancestor_hashes.get(&number).copied().ok_or(WitnessDbError::MissingBlockHash(number))
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
// State-root recompute — ress-style. Storage tries are recomputed in parallel
// via rayon; account leaves serially (cheap by comparison).
// ============================================================================

fn calculate_state_root(
    trie: &mut SparseStateTrie,
    state: HashedPostState,
) -> SparseStateTrieResult<B256> {
    use std::sync::mpsc;

    let (storage_tx, storage_rx) = mpsc::channel();
    state
        .storages
        .into_iter()
        .map(|(address, storage)| (address, storage, trie.take_storage_trie(&address)))
        .par_bridge()
        .map(|(address, storage, storage_trie)| {
            let mut storage_trie =
                storage_trie.unwrap_or_else(RevealableSparseTrie::revealed_empty);
            if storage.wiped {
                storage_trie.wipe()?;
            }
            for (hashed_slot, value) in
                storage.storage.into_iter().sorted_unstable_by_key(|(hashed_slot, _)| *hashed_slot)
            {
                let nibbles = Nibbles::unpack(hashed_slot);
                if value.is_zero() {
                    storage_trie.remove_leaf(&nibbles)?;
                } else {
                    storage_trie
                        .update_leaf(nibbles, alloy_rlp::encode_fixed_size(&value).to_vec())?;
                }
            }
            let _ = storage_trie.root();
            SparseStateTrieResult::Ok((address, storage_trie))
        })
        .for_each_init(|| storage_tx.clone(), |tx, r| tx.send(r).unwrap());
    drop(storage_tx);
    for result in storage_rx {
        let (address, storage_trie) = result?;
        trie.insert_storage_trie(address, storage_trie);
    }

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
