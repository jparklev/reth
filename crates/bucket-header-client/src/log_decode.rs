//! Vortex logs chunk decode → `Vec<(block_num, tx_idx, log_idx, alloy_primitives::Log)>`.
//!
//! Schema parity with `crates/relay-rpc/src/backends/vortex_logs.rs`
//! (12 fields). The receipts decoder joins logs by `tx_idx` to
//! populate [`reth_ethereum_primitives::Receipt::logs`].

use std::sync::Arc;

use alloy_primitives::{Address, B256, Bytes, Log, LogData};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use eyre::{Result, eyre};
use object_store::{ObjectStore, ObjectStoreExt};
use object_store::path::Path as ObjectPath;
use vortex::array::accessor::ArrayAccessor;
use vortex::array::arrays::struct_::StructArrayExt;
use vortex::array::arrays::{
    PrimitiveArray, StructArray as VortexStructArray,
    VarBinViewArray as VortexVarBinViewArray,
};
use vortex::array::expr::{col, eq, lit, root, select};
use vortex::array::stream::ArrayStreamExt;
use vortex::array::{ExecutionCtx, VortexSessionExecute, scalar::Scalar};
use vortex::session::VortexSession;
use vortex::VortexSessionDefault;
use vortex_buffer::ByteBuffer;
use vortex_file::{Footer, OpenOptionsSessionExt};
use vortex_io::object_store::ObjectStoreReadAt;

use super::VortexPreloadRange;

const LOG_COLUMNS: &[&str] = &[
    "block_num",
    "block_hash",
    "log_idx",
    "tx_idx",
    "tx_hash",
    "address",
    "topic0",
    "topic1",
    "topic2",
    "topic3",
    "data",
];

/// One decoded log row, sortable by (tx_idx, log_idx).
#[derive(Debug, Clone)]
pub(crate) struct DecodedLog {
    pub block_num: u64,
    pub tx_idx: u32,
    pub log_idx: u32,
    pub log: Log,
}

/// Decode all log rows for the given block from a Vortex `logs` chunk.
pub(crate) async fn decode_logs_chunk(
    store: Arc<dyn ObjectStore>,
    path: ObjectPath,
    block_num: u64,
    file_size: Option<u64>,
    footer_metadata_b64: Option<&str>,
    preload_ranges: &[VortexPreloadRange],
) -> Result<Vec<DecodedLog>> {
    let session = VortexSession::default();
    let handle = vortex_io::runtime::Handle::find()
        .ok_or_else(|| eyre!("no vortex runtime handle available"))?;
    let read_at = ObjectStoreReadAt::new(Arc::clone(&store), path.clone(), handle);

    let mut options = session.open_options();
    options = options.with_some_file_size(file_size);

    if let Some(b64) = footer_metadata_b64 {
        let bytes = BASE64.decode(b64).map_err(|err| eyre!("decode footer b64: {err}"))?;
        let footer = Footer::from_metadata_bytes(ByteBuffer::copy_from(&bytes), session.clone())
            .map_err(|err| eyre!("footer parse: {err}"))?;
        options = options.with_footer(footer);
    }

    for range in preload_ranges {
        if range.length == 0 {
            continue;
        }
        let end = range
            .offset
            .checked_add(range.length)
            .ok_or_else(|| eyre!("preload range overflow"))?;
        let bytes = store
            .get_range(&path, range.offset..end)
            .await
            .map_err(|err| eyre!("preload {}..{}: {err}", range.offset, end))?;
        options =
            options.with_preloaded_file_range(range.offset, ByteBuffer::copy_from(bytes.as_ref()));
    }

    let file = options
        .open(Arc::new(read_at))
        .await
        .map_err(|err| eyre!("open vortex logs file: {err}"))?;

    let array = file
        .scan()
        .map_err(|err| eyre!("scan vortex logs: {err}"))?
        .with_filter(eq(col("block_num"), lit(Scalar::from(block_num as i64))))
        .with_projection(select(LOG_COLUMNS, root()))
        .into_array_stream()
        .map_err(|err| eyre!("stream vortex logs: {err}"))?
        .read_all()
        .await
        .map_err(|err| eyre!("read vortex logs: {err}"))?;
    let mut ctx = session.create_execution_ctx();
    let struct_arr: VortexStructArray =
        array.execute(&mut ctx).map_err(|err| eyre!("decode vortex logs: {err}"))?;
    rows_to_logs(&mut ctx, struct_arr, Some(block_num))
}

pub(crate) fn rows_to_logs(
    ctx: &mut ExecutionCtx,
    struct_arr: VortexStructArray,
    block_filter: Option<u64>,
) -> Result<Vec<DecodedLog>> {
    let block_num = primitive_required::<i64>(ctx, &struct_arr, "block_num")?;
    let log_idx = primitive_required::<i32>(ctx, &struct_arr, "log_idx")?;
    let tx_idx = primitive_required::<i32>(ctx, &struct_arr, "tx_idx")?;
    let address = varbin_required(ctx, &struct_arr, "address")?;
    let topic0 = varbin_required(ctx, &struct_arr, "topic0")?;
    let topic1 = varbin_optional(ctx, &struct_arr, "topic1")?;
    let topic2 = varbin_optional(ctx, &struct_arr, "topic2")?;
    let topic3 = varbin_optional(ctx, &struct_arr, "topic3")?;
    let data = varbin_required(ctx, &struct_arr, "data")?;

    let len = struct_arr.len();
    let mut out = Vec::with_capacity(len);
    for row in 0..len {
        let row_block = block_num[row] as u64;
        if let Some(filter) = block_filter
            && row_block != filter
        {
            continue;
        }
        let addr = bytes_to_address(&address[row])
            .map_err(|err| eyre!("row {row} address: {err}"))?;
        let mut topics: Vec<B256> = Vec::new();
        if !topic0[row].is_empty() {
            topics.push(bytes_to_b256(&topic0[row])
                .map_err(|err| eyre!("row {row} topic0: {err}"))?);
        }
        for (idx, t) in [&topic1[row], &topic2[row], &topic3[row]].iter().enumerate() {
            if let Some(bytes) = t.as_ref() {
                if !bytes.is_empty() {
                    topics.push(
                        bytes_to_b256(bytes)
                            .map_err(|err| eyre!("row {row} topic{}: {err}", idx + 1))?,
                    );
                }
            }
        }
        let log_data = LogData::new(topics, Bytes::from(data[row].clone()))
            .ok_or_else(|| eyre!("row {row} too many topics for log"))?;
        out.push(DecodedLog {
            block_num: row_block,
            tx_idx: tx_idx[row] as u32,
            log_idx: log_idx[row] as u32,
            log: Log { address: addr, data: log_data },
        });
    }
    out.sort_by_key(|d| (d.tx_idx, d.log_idx));
    Ok(out)
}

fn primitive_required<T>(
    ctx: &mut ExecutionCtx,
    array: &VortexStructArray,
    name: &str,
) -> Result<Vec<T>>
where
    T: vortex::array::dtype::NativePType + Copy + Default,
{
    let field = array
        .unmasked_field_by_name(name)
        .map_err(|err| eyre!("vortex logs missing {name}: {err}"))?;
    let values: PrimitiveArray =
        field.clone().execute(ctx).map_err(|err| eyre!("decode {name}: {err}"))?;
    Ok(values.with_iterator(|iter| {
        iter.map(|v| v.copied().unwrap_or_default()).collect::<Vec<_>>()
    }))
}

fn varbin_required(
    ctx: &mut ExecutionCtx,
    array: &VortexStructArray,
    name: &str,
) -> Result<Vec<Vec<u8>>> {
    Ok(varbin_optional(ctx, array, name)?
        .into_iter()
        .map(|v| v.unwrap_or_default())
        .collect())
}

fn varbin_optional(
    ctx: &mut ExecutionCtx,
    array: &VortexStructArray,
    name: &str,
) -> Result<Vec<Option<Vec<u8>>>> {
    let field = array
        .unmasked_field_by_name(name)
        .map_err(|err| eyre!("vortex logs missing {name}: {err}"))?;
    let values: VortexVarBinViewArray =
        field.clone().execute(ctx).map_err(|err| eyre!("decode {name}: {err}"))?;
    Ok(values.with_iterator(|iter| iter.map(|v| v.map(|b| b.to_vec())).collect::<Vec<_>>()))
}

fn bytes_to_b256(b: &[u8]) -> Result<B256> {
    if b.len() != 32 {
        return Err(eyre!("expected 32-byte hash, got {}", b.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(b);
    Ok(B256::from(out))
}

fn bytes_to_address(b: &[u8]) -> Result<Address> {
    if b.len() != 20 {
        return Err(eyre!("expected 20-byte address, got {}", b.len()));
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(b);
    Ok(Address::from(out))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use object_store::ObjectStoreExt;
    use object_store::memory::InMemory;
    use vortex::array::IntoArray;
    use vortex::array::arrays::StructArray;
    use vortex::array::builders::{ArrayBuilder, VarBinViewBuilder};
    use vortex::array::dtype::{DType, FieldNames, Nullability};
    use vortex::array::validity::Validity;
    use vortex::buffer::{Buffer, ByteBufferMut};
    use vortex_file::WriteOptionsSessionExt;

    #[tokio::test]
    async fn decodes_synthetic_logs_chunk() {
        let store = Arc::new(InMemory::new()) as Arc<dyn ObjectStore>;
        let chunk_path = "epoch-7/logs/test-logs-sha.vortex";
        let object_path = ObjectPath::from(format!("chunks/{chunk_path}"));
        let bytes = build_synthetic_logs_chunk().await;
        let file_size = bytes.len() as u64;
        store
            .put(&object_path, bytes.freeze().to_vec().into())
            .await
            .expect("put logs object");

        let decoded =
            decode_logs_chunk(store, object_path, 101, Some(file_size), None, &[])
                .await
                .expect("decode logs");
        // Block 101 has 2 logs (tx_idx=0 with 2 topics, tx_idx=1 anonymous).
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].tx_idx, 0);
        assert_eq!(decoded[0].log_idx, 0);
        assert_eq!(decoded[0].log.address.as_slice(), &[0x11; 20][..]);
        assert_eq!(decoded[0].log.data.topics().len(), 2);
        // Anonymous log (empty topic0) has 0 topics.
        assert_eq!(decoded[1].tx_idx, 1);
        assert_eq!(decoded[1].log.data.topics().len(), 0);
    }

    pub(crate) async fn build_synthetic_logs_chunk() -> ByteBufferMut {
        let session = VortexSession::default();
        let data = StructArray::new(
            FieldNames::from(LOG_COLUMNS),
            vec![
                primitive_array([100_i64, 101, 101]),
                binary_array([
                    Some(vec![0x10; 32]),
                    Some(vec![0x11; 32]),
                    Some(vec![0x11; 32]),
                ]),
                primitive_array([0_i32, 0, 1]),
                primitive_array([0_i32, 0, 1]),
                binary_array([
                    Some(vec![0x20; 32]),
                    Some(vec![0x21; 32]),
                    Some(vec![0x22; 32]),
                ]),
                binary_array([
                    Some(vec![0x10; 20]),
                    Some(vec![0x11; 20]),
                    Some(vec![0x12; 20]),
                ]),
                // topic0 — anonymous log has empty topic0
                binary_array([
                    Some(vec![0xa0; 32]),
                    Some(vec![0xa1; 32]),
                    Some(Vec::new()),
                ]),
                binary_array([None, Some(vec![0xb1; 32]), None]),
                binary_array([None, None, None]),
                binary_array([None, None, None]),
                binary_array([
                    Some(b"data-0".to_vec()),
                    Some(b"data-1".to_vec()),
                    Some(b"data-anon".to_vec()),
                ]),
            ],
            3,
            Validity::NonNullable,
        )
        .into_array();
        let mut out = ByteBufferMut::empty();
        session
            .write_options()
            .write(&mut out, data.to_array_stream())
            .await
            .expect("write logs test chunk");
        out
    }

    fn primitive_array<T>(values: impl IntoIterator<Item = T>) -> vortex::array::ArrayRef
    where
        T: vortex::array::dtype::NativePType,
    {
        PrimitiveArray::new(
            Buffer::<T>::from(values.into_iter().collect::<Vec<_>>()),
            Validity::NonNullable,
        )
        .into_array()
    }

    fn binary_array<const N: usize>(values: [Option<Vec<u8>>; N]) -> vortex::array::ArrayRef {
        let mut builder =
            VarBinViewBuilder::with_capacity(DType::Binary(Nullability::Nullable), values.len());
        for value in values {
            match value {
                Some(v) => builder.append_value(v),
                None => builder.append_null(),
            }
        }
        ArrayBuilder::finish(&mut builder)
    }
}
