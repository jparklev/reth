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
//! We decode entire chunks (no filter pushdown — checkpoints are
//! ~MB-scale, deltas ~10s of KB / epoch). The bytes arrive as an
//! in-memory `Vec<u8>`; we stage them in an `InMemory` object_store
//! the same way relay-rpc's reader does, then open via vortex-file.

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

// ============== decoders ====================

pub(crate) async fn decode_accounts_chunk(
    bytes: Vec<u8>,
) -> Result<Vec<AccountRow>, BucketStateClientError> {
    let arr = read_struct(bytes).await?;
    let mut ctx = VortexSession::default().create_execution_ctx();
    let addresses = varbin_required(&mut ctx, &arr, "hashed_address")?;
    let nonces = primitive_required::<i64>(&mut ctx, &arr, "nonce")?;
    let balances = varbin_required(&mut ctx, &arr, "balance")?;
    let code_hashes = varbin_required(&mut ctx, &arr, "code_hash")?;
    let mut out = Vec::with_capacity(addresses.len());
    for i in 0..addresses.len() {
        out.push(AccountRow {
            hashed_address: bytes_to_b256(&addresses[i])?,
            nonce: nonces[i] as u64,
            balance: U256::from_be_slice(&balances[i]),
            code_hash: bytes_to_b256(&code_hashes[i])?,
        });
    }
    Ok(out)
}

pub(crate) async fn decode_storage_chunk(
    bytes: Vec<u8>,
) -> Result<Vec<StorageRow>, BucketStateClientError> {
    let arr = read_struct(bytes).await?;
    let mut ctx = VortexSession::default().create_execution_ctx();
    let addresses = varbin_required(&mut ctx, &arr, "hashed_address")?;
    let slots = varbin_required(&mut ctx, &arr, "hashed_slot")?;
    let values = varbin_required(&mut ctx, &arr, "value")?;
    let mut out = Vec::with_capacity(addresses.len());
    for i in 0..addresses.len() {
        out.push(StorageRow {
            hashed_address: bytes_to_b256(&addresses[i])?,
            hashed_slot: bytes_to_b256(&slots[i])?,
            value: U256::from_be_slice(&values[i]),
        });
    }
    Ok(out)
}

pub(crate) async fn decode_code_chunk(
    bytes: Vec<u8>,
) -> Result<Vec<CodeRow>, BucketStateClientError> {
    let arr = read_struct(bytes).await?;
    let mut ctx = VortexSession::default().create_execution_ctx();
    let hashes = varbin_required(&mut ctx, &arr, "code_hash")?;
    let codes = varbin_required(&mut ctx, &arr, "code")?;
    let mut out = Vec::with_capacity(hashes.len());
    for i in 0..hashes.len() {
        out.push(CodeRow {
            code_hash: bytes_to_b256(&hashes[i])?,
            code: Bytes::from(codes[i].clone()),
        });
    }
    Ok(out)
}

pub(crate) async fn decode_account_deltas_chunk(
    bytes: Vec<u8>,
) -> Result<Vec<AccountDeltaRow>, BucketStateClientError> {
    let arr = read_struct(bytes).await?;
    let mut ctx = VortexSession::default().create_execution_ctx();
    let block_nums = primitive_required::<i64>(&mut ctx, &arr, "block_num")?;
    let addresses = varbin_required(&mut ctx, &arr, "address")?;
    let nonces = primitive_required::<i64>(&mut ctx, &arr, "nonce")?;
    let balances = varbin_required(&mut ctx, &arr, "balance")?;
    let code_hashes = varbin_required(&mut ctx, &arr, "code_hash")?;
    let mut out = Vec::with_capacity(block_nums.len());
    for i in 0..block_nums.len() {
        out.push(AccountDeltaRow {
            block_num: block_nums[i] as u64,
            address: bytes_to_address(&addresses[i])?,
            nonce: nonces[i] as u64,
            balance: U256::from_be_slice(&balances[i]),
            code_hash: bytes_to_b256(&code_hashes[i])?,
        });
    }
    Ok(out)
}

pub(crate) async fn decode_storage_deltas_chunk(
    bytes: Vec<u8>,
) -> Result<Vec<StorageDeltaRow>, BucketStateClientError> {
    let arr = read_struct(bytes).await?;
    let mut ctx = VortexSession::default().create_execution_ctx();
    let block_nums = primitive_required::<i64>(&mut ctx, &arr, "block_num")?;
    let addresses = varbin_required(&mut ctx, &arr, "address")?;
    let slots = varbin_required(&mut ctx, &arr, "slot")?;
    let values = varbin_required(&mut ctx, &arr, "value")?;
    let mut out = Vec::with_capacity(block_nums.len());
    for i in 0..block_nums.len() {
        out.push(StorageDeltaRow {
            block_num: block_nums[i] as u64,
            address: bytes_to_address(&addresses[i])?,
            slot: U256::from_be_slice(&slots[i]),
            value: U256::from_be_slice(&values[i]),
        });
    }
    Ok(out)
}

pub(crate) async fn decode_code_deltas_chunk(
    bytes: Vec<u8>,
) -> Result<Vec<CodeDeltaRow>, BucketStateClientError> {
    let arr = read_struct(bytes).await?;
    let mut ctx = VortexSession::default().create_execution_ctx();
    let block_nums = primitive_required::<i64>(&mut ctx, &arr, "block_num")?;
    let hashes = varbin_required(&mut ctx, &arr, "code_hash")?;
    let codes = varbin_required(&mut ctx, &arr, "code")?;
    let mut out = Vec::with_capacity(block_nums.len());
    for i in 0..block_nums.len() {
        out.push(CodeDeltaRow {
            block_num: block_nums[i] as u64,
            code_hash: bytes_to_b256(&hashes[i])?,
            code: Bytes::from(codes[i].clone()),
        });
    }
    Ok(out)
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

fn varbin_required(
    ctx: &mut ExecutionCtx,
    array: &VortexStructArray,
    name: &str,
) -> Result<Vec<Vec<u8>>, BucketStateClientError> {
    let field = array
        .unmasked_field_by_name(name)
        .map_err(|err| BucketStateClientError::Vortex(format!("missing {name}: {err}")))?;
    let values: VortexVarBinViewArray = field
        .clone()
        .execute(ctx)
        .map_err(|err| BucketStateClientError::Vortex(format!("decode {name}: {err}")))?;
    Ok(values
        .with_iterator(|iter| iter.map(|v| v.map(|b| b.to_vec()).unwrap_or_default()).collect()))
}

fn bytes_to_b256(b: &[u8]) -> Result<B256, BucketStateClientError> {
    if b.len() != 32 {
        return Err(BucketStateClientError::Decode(format!(
            "expected 32-byte hash, got {}",
            b.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(b);
    Ok(B256::from(out))
}

fn bytes_to_address(b: &[u8]) -> Result<Address, BucketStateClientError> {
    if b.len() != 20 {
        return Err(BucketStateClientError::Decode(format!(
            "expected 20-byte address, got {}",
            b.len()
        )));
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(b);
    Ok(Address::from(out))
}
