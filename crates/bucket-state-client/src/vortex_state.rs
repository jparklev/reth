//! Vortex chunk decoders for the Phase 26.x state artifacts.
//!
//! Schemas mirror the writer side
//! (`crates/relay-state-checkpointer/src/vortex_writer.rs` and
//! `crates/relay-rpc/src/backends/state_artifacts.rs`):
//!
//! - `accounts.vortex`         : `hashed_address(32), nonce(i64), balance(32 BE), code_hash(32)`
//! - `storage.vortex`          : `hashed_address(32), hashed_slot(32), value(32 BE)`
//! - `code.vortex`             : `code_hash(32), code(binary)`
//! - `state_account_deltas`    : `block_num(i64), address, nonce, balance, code_hash`
//! - `state_storage_deltas`    : `block_num(i64), address, slot, value`
//! - `state_code_deltas`       : `block_num(i64), code_hash, code`
//!
//! Decoders are streaming: each row is yielded to a caller-supplied
//! closure rather than collected into an intermediate `Vec<Row>`. This
//! matters for fat-contract storage shards (up to 5M rows) where a
//! `Vec<StorageRow>` materialization (plus the per-row `Vec<u8>` heap
//! allocations the previous API produced) inflated peak RSS into the
//! multi-GB range and OOM'd cold eth_calls. With streaming decode the
//! caller writes directly into the destination moka cache, and the
//! only transient buffers are tight `Vec<B256>` / `Vec<U256>` columns
//! (~32 bytes per row, no per-row heap header).

use std::sync::Arc;

use alloy_primitives::{Address, Bytes, B256, U256};
use object_store::{memory::InMemory, path::Path as ObjectPath, ObjectStore, ObjectStoreExt};
use vortex::{
    array::{
        accessor::ArrayAccessor,
        arrays::{
            struct_::StructArrayExt, PrimitiveArray, StructArray as VortexStructArray,
            VarBinViewArray as VortexVarBinViewArray,
        },
        stream::ArrayStreamExt,
        ExecutionCtx, VortexSessionExecute,
    },
    session::VortexSession,
    VortexSessionDefault,
};
use vortex_file::OpenOptionsSessionExt;
use vortex_io::object_store::ObjectStoreReadAt;

use crate::BucketStateClientError;

// ============== row structs ==================

#[derive(Debug, Clone)]
pub struct AccountRow {
    pub hashed_address: B256,
    pub nonce: u64,
    pub balance: U256,
    pub code_hash: B256,
}

#[derive(Debug, Clone)]
pub struct StorageRow {
    pub hashed_address: B256,
    pub hashed_slot: B256,
    pub value: U256,
}

#[derive(Debug, Clone)]
pub struct CodeRow {
    pub code_hash: B256,
    pub code: Bytes,
}

#[derive(Debug, Clone)]
pub struct AccountDeltaRow {
    pub block_num: u64,
    pub address: Address,
    pub nonce: u64,
    pub balance: U256,
    pub code_hash: B256,
}

#[derive(Debug, Clone)]
pub struct StorageDeltaRow {
    pub block_num: u64,
    pub address: Address,
    pub slot: U256,
    pub value: U256,
}

#[derive(Debug, Clone)]
pub struct CodeDeltaRow {
    pub block_num: u64,
    pub code_hash: B256,
    pub code: Bytes,
}

// ============== streaming decoders ====================
//
// Each decoder reads packed `Vec<B256>` / `Vec<U256>` columns rather
// than per-row `Vec<Vec<u8>>`. The columns are dropped as soon as the
// `for_each` walk finishes, so the chunk's residency is bounded by:
//
//   N rows × (sum of fixed-width column sizes)
//
// For storage that's `32 + 32 + 32 = 96` bytes/row, vs the previous
// `3 × (Vec header 24B + alloc header + 32B)` = ~170+ bytes/row, with
// each `Vec` triggering a separate `malloc` call (the worst part for
// fragmentation / allocator overhead).

pub(crate) async fn decode_accounts_chunk<F>(
    bytes: Vec<u8>,
    mut sink: F,
) -> Result<usize, BucketStateClientError>
where
    F: FnMut(AccountRow),
{
    let arr = read_struct(bytes).await?;
    let mut ctx = VortexSession::default().create_execution_ctx();
    let addresses = varbin_b256(&mut ctx, &arr, "hashed_address")?;
    let nonces = primitive_required::<i64>(&mut ctx, &arr, "nonce")?;
    let balances = varbin_u256(&mut ctx, &arr, "balance")?;
    let code_hashes = varbin_b256(&mut ctx, &arr, "code_hash")?;
    let n = addresses.len();
    check_len(n, nonces.len(), "nonce")?;
    check_len(n, balances.len(), "balance")?;
    check_len(n, code_hashes.len(), "code_hash")?;
    for i in 0..n {
        sink(AccountRow {
            hashed_address: addresses[i],
            nonce: nonces[i] as u64,
            balance: balances[i],
            code_hash: code_hashes[i],
        });
    }
    Ok(n)
}

pub(crate) async fn decode_storage_chunk<F>(
    bytes: Vec<u8>,
    mut sink: F,
) -> Result<usize, BucketStateClientError>
where
    F: FnMut(StorageRow),
{
    let arr = read_struct(bytes).await?;
    let mut ctx = VortexSession::default().create_execution_ctx();
    let addresses = varbin_b256(&mut ctx, &arr, "hashed_address")?;
    let slots = varbin_b256(&mut ctx, &arr, "hashed_slot")?;
    let values = varbin_u256(&mut ctx, &arr, "value")?;
    let n = addresses.len();
    check_len(n, slots.len(), "hashed_slot")?;
    check_len(n, values.len(), "value")?;
    for i in 0..n {
        sink(StorageRow { hashed_address: addresses[i], hashed_slot: slots[i], value: values[i] });
    }
    Ok(n)
}

pub(crate) async fn decode_code_chunk<F>(
    bytes: Vec<u8>,
    mut sink: F,
) -> Result<usize, BucketStateClientError>
where
    F: FnMut(CodeRow),
{
    let arr = read_struct(bytes).await?;
    let mut ctx = VortexSession::default().create_execution_ctx();
    let hashes = varbin_b256(&mut ctx, &arr, "code_hash")?;
    // Code is variable-length; collecting to Bytes (Arc<[u8]>) is the
    // smallest representation we can hand to the cache.
    let codes = varbin_bytes(&mut ctx, &arr, "code")?;
    let n = hashes.len();
    check_len(n, codes.len(), "code")?;
    for (hash, code) in hashes.into_iter().zip(codes) {
        sink(CodeRow { code_hash: hash, code });
    }
    Ok(n)
}

pub(crate) async fn decode_account_deltas_chunk<F>(
    bytes: Vec<u8>,
    mut sink: F,
) -> Result<usize, BucketStateClientError>
where
    F: FnMut(AccountDeltaRow),
{
    let arr = read_struct(bytes).await?;
    let mut ctx = VortexSession::default().create_execution_ctx();
    let block_nums = primitive_required::<i64>(&mut ctx, &arr, "block_num")?;
    let addresses = varbin_address(&mut ctx, &arr, "address")?;
    let nonces = primitive_required::<i64>(&mut ctx, &arr, "nonce")?;
    let balances = varbin_u256(&mut ctx, &arr, "balance")?;
    let code_hashes = varbin_b256(&mut ctx, &arr, "code_hash")?;
    let n = block_nums.len();
    check_len(n, addresses.len(), "address")?;
    check_len(n, nonces.len(), "nonce")?;
    check_len(n, balances.len(), "balance")?;
    check_len(n, code_hashes.len(), "code_hash")?;
    for i in 0..n {
        sink(AccountDeltaRow {
            block_num: block_nums[i] as u64,
            address: addresses[i],
            nonce: nonces[i] as u64,
            balance: balances[i],
            code_hash: code_hashes[i],
        });
    }
    Ok(n)
}

pub(crate) async fn decode_storage_deltas_chunk<F>(
    bytes: Vec<u8>,
    mut sink: F,
) -> Result<usize, BucketStateClientError>
where
    F: FnMut(StorageDeltaRow),
{
    let arr = read_struct(bytes).await?;
    let mut ctx = VortexSession::default().create_execution_ctx();
    let block_nums = primitive_required::<i64>(&mut ctx, &arr, "block_num")?;
    let addresses = varbin_address(&mut ctx, &arr, "address")?;
    let slots = varbin_u256(&mut ctx, &arr, "slot")?;
    let values = varbin_u256(&mut ctx, &arr, "value")?;
    let n = block_nums.len();
    check_len(n, addresses.len(), "address")?;
    check_len(n, slots.len(), "slot")?;
    check_len(n, values.len(), "value")?;
    for i in 0..n {
        sink(StorageDeltaRow {
            block_num: block_nums[i] as u64,
            address: addresses[i],
            slot: slots[i],
            value: values[i],
        });
    }
    Ok(n)
}

pub(crate) async fn decode_code_deltas_chunk<F>(
    bytes: Vec<u8>,
    mut sink: F,
) -> Result<usize, BucketStateClientError>
where
    F: FnMut(CodeDeltaRow),
{
    let arr = read_struct(bytes).await?;
    let mut ctx = VortexSession::default().create_execution_ctx();
    let block_nums = primitive_required::<i64>(&mut ctx, &arr, "block_num")?;
    let hashes = varbin_b256(&mut ctx, &arr, "code_hash")?;
    let codes = varbin_bytes(&mut ctx, &arr, "code")?;
    let n = block_nums.len();
    check_len(n, hashes.len(), "code_hash")?;
    check_len(n, codes.len(), "code")?;
    for ((block_num, hash), code) in block_nums.into_iter().zip(hashes).zip(codes) {
        sink(CodeDeltaRow { block_num: block_num as u64, code_hash: hash, code });
    }
    Ok(n)
}

// ============== plumbing ==================

async fn read_struct(bytes: Vec<u8>) -> Result<VortexStructArray, BucketStateClientError> {
    let store = Arc::new(InMemory::new()) as Arc<dyn ObjectStore>;
    let path = ObjectPath::from("artifact.vortex");
    let size = bytes.len() as u64;
    store
        .put(&path, bytes.into())
        .await
        .map_err(|err| BucketStateClientError::Vortex(format!("stage in-memory: {err}")))?;
    let session = VortexSession::default();
    let handle = vortex_io::runtime::Handle::find()
        .ok_or_else(|| BucketStateClientError::Vortex("no vortex runtime handle".into()))?;
    let read_at = ObjectStoreReadAt::new(Arc::clone(&store), path.clone(), handle);
    let options = session.open_options().with_some_file_size(Some(size));
    let file = options
        .open(Arc::new(read_at))
        .await
        .map_err(|err| BucketStateClientError::Vortex(format!("open: {err}")))?;
    let array = file
        .scan()
        .map_err(|err| BucketStateClientError::Vortex(format!("scan: {err}")))?
        .into_array_stream()
        .map_err(|err| BucketStateClientError::Vortex(format!("stream: {err}")))?
        .read_all()
        .await
        .map_err(|err| BucketStateClientError::Vortex(format!("read: {err}")))?;
    let mut ctx = session.create_execution_ctx();
    let s: VortexStructArray = array
        .execute(&mut ctx)
        .map_err(|err| BucketStateClientError::Vortex(format!("execute: {err}")))?;
    Ok(s)
}

fn primitive_required<T>(
    ctx: &mut ExecutionCtx,
    array: &VortexStructArray,
    name: &str,
) -> Result<Vec<T>, BucketStateClientError>
where
    T: vortex::array::dtype::NativePType + Copy + Default,
{
    let field = array
        .unmasked_field_by_name(name)
        .map_err(|err| BucketStateClientError::Vortex(format!("missing {name}: {err}")))?;
    let values: PrimitiveArray = field
        .clone()
        .execute(ctx)
        .map_err(|err| BucketStateClientError::Vortex(format!("decode {name}: {err}")))?;
    Ok(values
        .with_iterator(|iter| iter.map(|v| v.copied().unwrap_or_default()).collect::<Vec<_>>()))
}

fn varbin_array(
    ctx: &mut ExecutionCtx,
    array: &VortexStructArray,
    name: &str,
) -> Result<VortexVarBinViewArray, BucketStateClientError> {
    let field = array
        .unmasked_field_by_name(name)
        .map_err(|err| BucketStateClientError::Vortex(format!("missing {name}: {err}")))?;
    field
        .clone()
        .execute(ctx)
        .map_err(|err| BucketStateClientError::Vortex(format!("decode {name}: {err}")))
}

/// Collect a fixed-32-byte varbin column into a tight `Vec<B256>`.
/// One contiguous allocation; no per-row Vec.
fn varbin_b256(
    ctx: &mut ExecutionCtx,
    array: &VortexStructArray,
    name: &str,
) -> Result<Vec<B256>, BucketStateClientError> {
    let values = varbin_array(ctx, array, name)?;
    values.with_iterator(|iter| {
        let mut out = Vec::with_capacity(iter.size_hint().0);
        for v in iter {
            let bytes = v.unwrap_or(&[]);
            if bytes.len() != 32 {
                return Err(BucketStateClientError::Decode(format!(
                    "{name}: expected 32-byte value, got {}",
                    bytes.len()
                )));
            }
            let mut buf = [0u8; 32];
            buf.copy_from_slice(bytes);
            out.push(B256::from(buf));
        }
        Ok(out)
    })
}

/// Collect a fixed-20-byte varbin column (addresses) into `Vec<Address>`.
fn varbin_address(
    ctx: &mut ExecutionCtx,
    array: &VortexStructArray,
    name: &str,
) -> Result<Vec<Address>, BucketStateClientError> {
    let values = varbin_array(ctx, array, name)?;
    values.with_iterator(|iter| {
        let mut out = Vec::with_capacity(iter.size_hint().0);
        for v in iter {
            let bytes = v.unwrap_or(&[]);
            if bytes.len() != 20 {
                return Err(BucketStateClientError::Decode(format!(
                    "{name}: expected 20-byte address, got {}",
                    bytes.len()
                )));
            }
            let mut buf = [0u8; 20];
            buf.copy_from_slice(bytes);
            out.push(Address::from(buf));
        }
        Ok(out)
    })
}

/// Collect a varbin column of big-endian U256 values directly. Same
/// motivation as `varbin_b256` — no per-row Vec.
fn varbin_u256(
    ctx: &mut ExecutionCtx,
    array: &VortexStructArray,
    name: &str,
) -> Result<Vec<U256>, BucketStateClientError> {
    let values = varbin_array(ctx, array, name)?;
    Ok(values.with_iterator(|iter| {
        let mut out = Vec::with_capacity(iter.size_hint().0);
        for v in iter {
            let bytes = v.unwrap_or(&[]);
            out.push(U256::from_be_slice(bytes));
        }
        out
    }))
}

/// Variable-length payloads (bytecode). We have to allocate per row,
/// but `Bytes` is an `Arc<[u8]>` so the cache stores cheap clones.
fn varbin_bytes(
    ctx: &mut ExecutionCtx,
    array: &VortexStructArray,
    name: &str,
) -> Result<Vec<Bytes>, BucketStateClientError> {
    let values = varbin_array(ctx, array, name)?;
    Ok(values.with_iterator(|iter| {
        let mut out = Vec::with_capacity(iter.size_hint().0);
        for v in iter {
            let bytes = v.unwrap_or(&[]);
            out.push(Bytes::copy_from_slice(bytes));
        }
        out
    }))
}

fn check_len(expected: usize, got: usize, name: &str) -> Result<(), BucketStateClientError> {
    if expected != got {
        return Err(BucketStateClientError::Decode(format!(
            "column length mismatch: expected {expected} rows for {name}, got {got}"
        )));
    }
    Ok(())
}
