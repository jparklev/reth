//! Vortex chunk writers for the v2 hash-keyed checkpointer.
//!
//! Schemas must stay byte-aligned with the decoders in
//! `reth-bucket-state-client::vortex_state` (`hashed_address`,
//! `hashed_slot`, etc.). A schema change in either place must be
//! mirrored.
//!
//! Rows are pre-sorted by the caller — accounts by `hashed_address`,
//! storage by `(hashed_address, hashed_slot)` — so future Vortex
//! range-fetch work has sorted row groups to bind to.

use alloy_primitives::{B256, U256};
use eyre::{Context, Result};
use vortex::{
    array::{
        arrays::{PrimitiveArray, StructArray as VortexStructArray},
        builders::{ArrayBuilder, VarBinViewBuilder},
        dtype::{DType, FieldNames, NativePType, Nullability},
        validity::Validity,
        IntoArray,
    },
    buffer::{Buffer, ByteBufferMut},
    session::VortexSession,
    VortexSessionDefault,
};
use vortex_file::WriteOptionsSessionExt;

pub(crate) async fn accounts_chunk(rows: &[(B256, u64, U256, B256)]) -> Result<Vec<u8>> {
    let len = rows.len();
    let data = VortexStructArray::new(
        FieldNames::from(["hashed_address", "nonce", "balance", "code_hash"]),
        vec![
            binary_required(rows.iter().map(|(h, _, _, _)| h.as_slice().to_vec()).collect()),
            primitive_required(rows.iter().map(|(_, n, _, _)| *n as i64)),
            binary_required(
                rows.iter().map(|(_, _, b, _)| b.to_be_bytes::<32>().to_vec()).collect(),
            ),
            binary_required(rows.iter().map(|(_, _, _, h)| h.as_slice().to_vec()).collect()),
        ],
        len,
        Validity::NonNullable,
    )
    .into_array();
    write_vortex(data).await
}

pub(crate) async fn storage_chunk(rows: &[(B256, B256, U256)]) -> Result<Vec<u8>> {
    let len = rows.len();
    let data = VortexStructArray::new(
        FieldNames::from(["hashed_address", "hashed_slot", "value"]),
        vec![
            binary_required(rows.iter().map(|(a, _, _)| a.as_slice().to_vec()).collect()),
            binary_required(rows.iter().map(|(_, s, _)| s.as_slice().to_vec()).collect()),
            binary_required(rows.iter().map(|(_, _, v)| v.to_be_bytes::<32>().to_vec()).collect()),
        ],
        len,
        Validity::NonNullable,
    )
    .into_array();
    write_vortex(data).await
}

pub(crate) async fn code_chunk(rows: &[(B256, Vec<u8>)]) -> Result<Vec<u8>> {
    let len = rows.len();
    let data = VortexStructArray::new(
        FieldNames::from(["code_hash", "code"]),
        vec![
            binary_required(rows.iter().map(|(h, _)| h.as_slice().to_vec()).collect()),
            binary_required(rows.iter().map(|(_, c)| c.clone()).collect()),
        ],
        len,
        Validity::NonNullable,
    )
    .into_array();
    write_vortex(data).await
}

async fn write_vortex(data: vortex::array::ArrayRef) -> Result<Vec<u8>> {
    let session = VortexSession::default();
    let mut out = ByteBufferMut::empty();
    session
        .write_options()
        .write(&mut out, data.to_array_stream())
        .await
        .context("vortex write failed")?;
    Ok(out.freeze().to_vec())
}

fn primitive_required<T, I>(values: I) -> vortex::array::ArrayRef
where
    T: NativePType,
    I: IntoIterator<Item = T>,
{
    PrimitiveArray::new(
        Buffer::<T>::from(values.into_iter().collect::<Vec<_>>()),
        Validity::NonNullable,
    )
    .into_array()
}

fn binary_required(values: Vec<Vec<u8>>) -> vortex::array::ArrayRef {
    let mut builder =
        VarBinViewBuilder::with_capacity(DType::Binary(Nullability::NonNullable), values.len());
    for value in values {
        builder.append_value(value);
    }
    ArrayBuilder::finish(&mut builder)
}
