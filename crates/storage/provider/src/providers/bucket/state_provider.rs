//! Phase 26.x — bucket-mode StateProvider decorator.
//!
//! Wraps an inner [`StateProviderBox`] with a [`BucketStateClient`]:
//! plain-state reads (`basic_account`, `storage`, `bytecode_by_hash`)
//! check the bucket first, then fall through to the wrapped provider
//! on miss. Trie / proof / hashed-post-state methods always pass
//! through to the inner provider — the bucket only stores plain
//! state, never trie nodes.
//!
//! See `crates/storage/provider/src/providers/bucket/mod.rs` for the
//! [`BucketStateClient`] trait definition. The HTTP/Vortex
//! implementer lives in `crates/bucket-state-client/`.

use crate::providers::BucketStateClientArc;
use alloy_primitives::{
    Address, BlockNumber, Bytes, StorageKey, StorageValue, B256, U256,
};
use reth_primitives_traits::{Account, Bytecode};
use reth_storage_api::{
    AccountReader, BlockHashReader, BytecodeReader, HashedPostStateProvider, StateProofProvider,
    StateProvider, StateRootProvider, StorageRootProvider,
};
use reth_storage_errors::provider::ProviderResult;
use reth_trie::{
    updates::TrieUpdates, AccountProof, HashedPostState, HashedStorage, MultiProof,
    MultiProofTargets, StorageMultiProof, StorageProof, TrieInput,
};
use revm_database::BundleState;
use tracing::debug;

/// StateProvider decorator that consults a [`BucketStateClient`]
/// before delegating to an inner [`StateProvider`].
///
/// The decorator is only attached to the *latest* / pinned-finalized
/// state path; historical state below the bucket's checkpoint anchor
/// still goes through the inner provider unchanged. The bucket is
/// the source of truth for the in-memory plain-state at
/// `pinned_block_number()`; for any other block the decorator is a
/// no-op (returns inner's result).
///
/// Misses are intentional: a bucket that boots from a 5k-account
/// spike checkpoint won't have the long tail, and we want
/// `eth_getBalance(<random_addr>)` to fall through to MDBX rather
/// than erroneously return `None`.
pub struct BucketStateProvider {
    bucket: BucketStateClientArc,
    inner: Box<dyn StateProvider + Send + 'static>,
}

impl BucketStateProvider {
    /// Wrap `inner` with a bucket-backed fast path.
    pub fn new(
        bucket: BucketStateClientArc,
        inner: Box<dyn StateProvider + Send + 'static>,
    ) -> Self {
        Self { bucket, inner }
    }

    /// Pinned block of the underlying bucket client. Exposed so
    /// `BlockchainProvider` can decide whether to attach the
    /// decorator at all (no point wrapping a historical state at
    /// block < checkpoint).
    pub fn pinned_block_number(&self) -> BlockNumber {
        self.bucket.pinned_block_number()
    }
}

impl std::fmt::Debug for BucketStateProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BucketStateProvider")
            .field("pinned_block", &self.bucket.pinned_block_number())
            .finish()
    }
}

// ============ AccountReader: bucket first, then inner ============

impl AccountReader for BucketStateProvider {
    fn basic_account(&self, address: &Address) -> ProviderResult<Option<Account>> {
        match self.bucket.account(*address)? {
            Some(acc) => {
                debug!(
                    target: "providers::bucket",
                    %address,
                    nonce = acc.nonce,
                    balance = %acc.balance,
                    "BucketStateProvider::basic_account hit"
                );
                Ok(Some(acc))
            }
            None => {
                debug!(
                    target: "providers::bucket",
                    %address,
                    "BucketStateProvider::basic_account miss → inner"
                );
                self.inner.basic_account(address)
            }
        }
    }
}

// ============ BytecodeReader: bucket first, then inner ===========

impl BytecodeReader for BucketStateProvider {
    fn bytecode_by_hash(&self, code_hash: &B256) -> ProviderResult<Option<Bytecode>> {
        if let Some(bytes) = self.bucket.code_by_hash(*code_hash)? {
            debug!(
                target: "providers::bucket",
                %code_hash,
                len = bytes.len(),
                "BucketStateProvider::bytecode_by_hash hit"
            );
            return Ok(Some(Bytecode::new_raw(bytes)));
        }
        debug!(
            target: "providers::bucket",
            %code_hash,
            "BucketStateProvider::bytecode_by_hash miss → inner"
        );
        self.inner.bytecode_by_hash(code_hash)
    }
}

// ============ BlockHashReader: always delegate ==================

impl BlockHashReader for BucketStateProvider {
    fn block_hash(&self, number: BlockNumber) -> ProviderResult<Option<B256>> {
        self.inner.block_hash(number)
    }

    fn canonical_hashes_range(
        &self,
        start: BlockNumber,
        end: BlockNumber,
    ) -> ProviderResult<Vec<B256>> {
        self.inner.canonical_hashes_range(start, end)
    }
}

// ============ StateRootProvider: delegate ========================

impl StateRootProvider for BucketStateProvider {
    fn state_root(&self, hashed_state: HashedPostState) -> ProviderResult<B256> {
        self.inner.state_root(hashed_state)
    }

    fn state_root_from_nodes(&self, input: TrieInput) -> ProviderResult<B256> {
        self.inner.state_root_from_nodes(input)
    }

    fn state_root_with_updates(
        &self,
        hashed_state: HashedPostState,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        self.inner.state_root_with_updates(hashed_state)
    }

    fn state_root_from_nodes_with_updates(
        &self,
        input: TrieInput,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        self.inner.state_root_from_nodes_with_updates(input)
    }
}

// ============ StorageRootProvider: delegate ======================

impl StorageRootProvider for BucketStateProvider {
    fn storage_root(
        &self,
        address: Address,
        hashed_storage: HashedStorage,
    ) -> ProviderResult<B256> {
        self.inner.storage_root(address, hashed_storage)
    }

    fn storage_proof(
        &self,
        address: Address,
        slot: B256,
        hashed_storage: HashedStorage,
    ) -> ProviderResult<StorageProof> {
        self.inner.storage_proof(address, slot, hashed_storage)
    }

    fn storage_multiproof(
        &self,
        address: Address,
        slots: &[B256],
        hashed_storage: HashedStorage,
    ) -> ProviderResult<StorageMultiProof> {
        self.inner.storage_multiproof(address, slots, hashed_storage)
    }
}

// ============ StateProofProvider: delegate =======================

impl StateProofProvider for BucketStateProvider {
    fn proof(
        &self,
        input: TrieInput,
        address: Address,
        slots: &[B256],
    ) -> ProviderResult<AccountProof> {
        self.inner.proof(input, address, slots)
    }

    fn multiproof(
        &self,
        input: TrieInput,
        targets: MultiProofTargets,
    ) -> ProviderResult<MultiProof> {
        self.inner.multiproof(input, targets)
    }

    fn witness(
        &self,
        input: TrieInput,
        target: HashedPostState,
    ) -> ProviderResult<Vec<Bytes>> {
        self.inner.witness(input, target)
    }
}

// ============ HashedPostStateProvider: delegate ==================

impl HashedPostStateProvider for BucketStateProvider {
    fn hashed_post_state(&self, bundle_state: &BundleState) -> HashedPostState {
        self.inner.hashed_post_state(bundle_state)
    }
}

// ============ StateProvider: storage methods + plain reads =======

impl StateProvider for BucketStateProvider {
    fn storage(
        &self,
        account: Address,
        storage_key: StorageKey,
    ) -> ProviderResult<Option<StorageValue>> {
        let slot = U256::from_be_bytes(storage_key.0);
        match self.bucket.storage(account, slot)? {
            Some(value) => {
                debug!(
                    target: "providers::bucket",
                    %account,
                    %slot,
                    %value,
                    "BucketStateProvider::storage hit"
                );
                Ok(Some(value))
            }
            None => {
                debug!(
                    target: "providers::bucket",
                    %account,
                    %slot,
                    "BucketStateProvider::storage miss → inner"
                );
                self.inner.storage(account, storage_key)
            }
        }
    }

    fn storage_by_hashed_key(
        &self,
        address: Address,
        hashed_storage_key: StorageKey,
    ) -> ProviderResult<Option<StorageValue>> {
        // The bucket is keyed by plain (unhashed) slot, so we can't
        // serve this variant — always fall through.
        self.inner.storage_by_hashed_key(address, hashed_storage_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::{BucketHeaderClient, BucketStateClient};
    use alloy_consensus::Header;
    use alloy_primitives::Address;
    use reth_storage_errors::provider::ProviderResult;
    use std::sync::Arc;

    #[derive(Debug)]
    struct MockBucket {
        addr: Address,
        nonce: u64,
        balance: U256,
        code_hash: B256,
        slot_key: U256,
        slot_value: U256,
        code: Bytes,
        pinned: u64,
    }

    impl BucketHeaderClient for MockBucket {
        fn header_by_number(&self, _: BlockNumber) -> ProviderResult<Option<Header>> {
            Ok(None)
        }
        fn latest_finalized_block_number(&self) -> BlockNumber {
            self.pinned
        }
    }

    impl BucketStateClient for MockBucket {
        fn account(&self, addr: Address) -> ProviderResult<Option<Account>> {
            if addr == self.addr {
                Ok(Some(Account {
                    nonce: self.nonce,
                    balance: self.balance,
                    bytecode_hash: Some(self.code_hash),
                }))
            } else {
                Ok(None)
            }
        }
        fn storage(&self, addr: Address, slot: U256) -> ProviderResult<Option<U256>> {
            if addr == self.addr && slot == self.slot_key {
                Ok(Some(self.slot_value))
            } else {
                Ok(None)
            }
        }
        fn code_by_hash(&self, h: B256) -> ProviderResult<Option<Bytes>> {
            if h == self.code_hash {
                Ok(Some(self.code.clone()))
            } else {
                Ok(None)
            }
        }
        fn pinned_block_number(&self) -> BlockNumber {
            self.pinned
        }
    }

    /// Use the existing test_utils MockEthProvider's StateProvider impl as the inner.
    #[test]
    fn bucket_state_provider_hits_bucket_before_inner() {
        use crate::test_utils::MockEthProvider;
        let inner = MockEthProvider::default();
        let inner_state = StateProviderFactoryTestHelper::latest(&inner).expect("latest");
        let addr = Address::from([0x11; 20]);
        let code = Bytes::from(vec![0x60, 0x00]);
        let code_hash = alloy_primitives::keccak256(&code);
        let bucket: BucketStateClientArc = Arc::new(MockBucket {
            addr,
            nonce: 7,
            balance: U256::from(42u64),
            code_hash,
            slot_key: U256::from(1u64),
            slot_value: U256::from(99u64),
            code: code.clone(),
            pinned: 25_120_500,
        });
        let provider = BucketStateProvider::new(bucket, inner_state);
        // Hit
        let acc = provider.basic_account(&addr).expect("ok").expect("present");
        assert_eq!(acc.balance, U256::from(42u64));
        assert_eq!(acc.nonce, 7);
        let stored = provider
            .storage(addr, B256::from(U256::from(1u64).to_be_bytes::<32>()))
            .expect("ok")
            .expect("present");
        assert_eq!(stored, U256::from(99u64));
        let bytecode = provider.bytecode_by_hash(&code_hash).expect("ok").expect("present");
        assert_eq!(bytecode.original_byte_slice(), &code[..]);
        // Miss → fall through (MockEthProvider returns None for unknown addrs)
        let other = Address::from([0x22; 20]);
        assert!(provider.basic_account(&other).expect("ok").is_none());
        assert_eq!(provider.pinned_block_number(), 25_120_500);
    }

    /// Tiny shim so we can call StateProviderFactory::latest on the
    /// mock without dragging the full trait into scope at every
    /// call-site.
    struct StateProviderFactoryTestHelper;
    impl StateProviderFactoryTestHelper {
        fn latest<P: crate::StateProviderFactory>(p: &P) -> ProviderResult<Box<dyn StateProvider + Send + 'static>> {
            p.latest()
        }
    }

    /// A bucket client that records every read it serves so a test
    /// can assert "this dispatch path actually exercised the bucket".
    #[derive(Debug, Default)]
    struct CountingBucket {
        accounts_seen: std::sync::Mutex<Vec<Address>>,
        storage_seen: std::sync::Mutex<Vec<(Address, U256)>>,
        code_seen: std::sync::Mutex<Vec<B256>>,
        // Optional pre-populated values; if absent, returns None.
        accounts: std::collections::HashMap<Address, Account>,
        storage: std::collections::HashMap<(Address, U256), U256>,
        code: std::collections::HashMap<B256, Bytes>,
    }

    impl BucketHeaderClient for CountingBucket {
        fn header_by_number(&self, _: BlockNumber) -> ProviderResult<Option<Header>> {
            Ok(None)
        }
        fn latest_finalized_block_number(&self) -> BlockNumber {
            42
        }
    }

    impl BucketStateClient for CountingBucket {
        fn account(&self, addr: Address) -> ProviderResult<Option<Account>> {
            self.accounts_seen.lock().unwrap().push(addr);
            Ok(self.accounts.get(&addr).copied())
        }
        fn storage(&self, addr: Address, slot: U256) -> ProviderResult<Option<U256>> {
            self.storage_seen.lock().unwrap().push((addr, slot));
            Ok(self.storage.get(&(addr, slot)).copied())
        }
        fn code_by_hash(&self, h: B256) -> ProviderResult<Option<Bytes>> {
            self.code_seen.lock().unwrap().push(h);
            Ok(self.code.get(&h).cloned())
        }
        fn pinned_block_number(&self) -> BlockNumber {
            42
        }
    }

    /// Sanity check that the three hot-path StateProvider methods
    /// (basic_account / storage / bytecode_by_hash) flow through
    /// the bucket before falling back to the inner provider. This
    /// is the dispatch surface revm exercises during `eth_call` and
    /// `eth_estimateGas`.
    #[test]
    fn bucket_state_provider_records_dispatch_for_eth_call_surface() {
        use crate::test_utils::MockEthProvider;
        let inner = MockEthProvider::default();
        let inner_state = StateProviderFactoryTestHelper::latest(&inner).expect("latest");

        let usdc = Address::from([0xaa; 20]);
        let vitalik = Address::from([0xbb; 20]);
        let code = Bytes::from(vec![0x60, 0x80, 0x60, 0x40]);
        let code_hash = alloy_primitives::keccak256(&code);
        let balance_slot = U256::from(0xbf4954u64);

        let bucket = CountingBucket {
            accounts: [
                (
                    usdc,
                    Account { nonce: 1, balance: U256::ZERO, bytecode_hash: Some(code_hash) },
                ),
                (
                    vitalik,
                    Account {
                        nonce: 5_894,
                        balance: U256::from(5_676_727_086_076_375_109u128),
                        bytecode_hash: None,
                    },
                ),
            ]
            .into_iter()
            .collect(),
            storage: [((usdc, balance_slot), U256::from(0x1c804u64))]
                .into_iter()
                .collect(),
            code: [(code_hash, code.clone())].into_iter().collect(),
            ..Default::default()
        };
        // Take the inspection handles before moving the bucket into
        // the Arc — the Arc itself doesn't let us reach back into the
        // struct fields.
        let bucket = Arc::new(bucket);
        let inspect = bucket.clone();
        let provider = BucketStateProvider::new(
            bucket as BucketStateClientArc,
            inner_state,
        );

        // 1. basic_account hit + bytecode hit + storage hit, simulating
        //    revm's "load contract, run balanceOf" sequence.
        let acc = provider.basic_account(&usdc).unwrap().expect("usdc present");
        assert_eq!(acc.nonce, 1);
        assert_eq!(acc.bytecode_hash, Some(code_hash));
        let bytecode = provider.bytecode_by_hash(&code_hash).unwrap().expect("code");
        assert_eq!(bytecode.original_byte_slice(), code.as_ref());
        let stored = provider
            .storage(usdc, B256::from(balance_slot.to_be_bytes::<32>()))
            .unwrap()
            .expect("slot");
        assert_eq!(stored, U256::from(0x1c804u64));
        // 2. miss → fall-through. An unknown address must still hit the
        //    bucket FIRST (so the bucket can answer if it ever gains
        //    coverage) but resolve to None via the inner provider.
        let stranger = Address::from([0xcc; 20]);
        assert!(provider.basic_account(&stranger).unwrap().is_none());

        // Inspect the recorded dispatch.
        let accounts_seen = inspect.accounts_seen.lock().unwrap();
        let storage_seen = inspect.storage_seen.lock().unwrap();
        let code_seen = inspect.code_seen.lock().unwrap();
        assert_eq!(accounts_seen.len(), 2, "two basic_account calls dispatched");
        assert_eq!(accounts_seen[0], usdc);
        assert_eq!(accounts_seen[1], stranger);
        assert_eq!(storage_seen.len(), 1, "one storage call dispatched");
        assert_eq!(storage_seen[0], (usdc, balance_slot));
        assert_eq!(code_seen.len(), 1, "one bytecode_by_hash call dispatched");
        assert_eq!(code_seen[0], code_hash);
    }
}
