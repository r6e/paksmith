//! `FRawStaticIndexBuffer` reader (Phase 3g render data).
//!
//! Materializes the per-triangle vertex indices as `Vec<u32>` regardless of the
//! on-wire 16- vs 32-bit width. Wire-format reference:
//! `docs/formats/mesh/vertex-formats.md` §`FRawStaticIndexBuffer`; oracle
//! `FabianFG/CUE4Parse` `FRawStaticIndexBuffer.cs`.

use std::io::Read;

use crate::asset::AssetContext;
use crate::error::{AssetParseFault, AssetWireField, BoundsUnit};

use super::read;
use super::vertex_buffers::MAX_VERTICES_PER_LOD;

/// Max indices per LOD — `MAX_VERTICES_PER_LOD × 6`. A non-degenerate triangle
/// list has ≤ 3 indices/triangle and ≤ ~2 triangles/vertex; ×6 is a generous
/// ceiling that still bounds the allocation before the bulk read.
pub(crate) const MAX_INDICES_PER_LOD: u32 = MAX_VERTICES_PER_LOD * 6;

/// Read an `FRawStaticIndexBuffer` into a `Vec<u32>`.
///
/// Wire: `is32bit` (lax `int != 0`), `elementSize` (`i32`, always `1`),
/// `byteCount` (`i32`, total payload bytes — index count is derived), the raw
/// `byteCount`-byte payload (parsed as `u16`/`u32` per `is32bit`), then — for
/// UE 4.25+ — a trailing `bShouldExpandTo32Bit` (lax bool, discarded). The
/// derived index count is capped at [`MAX_INDICES_PER_LOD`] before the bulk
/// read, and `byteCount` must be a whole multiple of the index size.
pub(crate) fn read_index_buffer<R: Read>(
    reader: &mut R,
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<Vec<u32>> {
    let is_32bit = read::read_lax_bool32(reader, asset_path, AssetWireField::MeshIndexIs32Bit)?;

    let element_size = read::read_i32(reader, asset_path, AssetWireField::MeshIndexElementSize)?;
    if element_size != 1 {
        return Err(read::fault(
            asset_path,
            AssetParseFault::IndexBufferElementSizeInvalid {
                observed: element_size,
            },
        ));
    }

    let byte_count_raw = read::read_i32(reader, asset_path, AssetWireField::MeshIndexByteCount)?;
    let byte_count = u32::try_from(byte_count_raw).map_err(|_| {
        read::fault(
            asset_path,
            AssetParseFault::NegativeValue {
                field: AssetWireField::MeshIndexByteCount,
                value: i64::from(byte_count_raw),
            },
        )
    })?;

    let index_size: u32 = if is_32bit { 4 } else { 2 };
    if byte_count % index_size != 0 {
        return Err(read::fault(
            asset_path,
            AssetParseFault::IndexBufferByteCountMismatch {
                byte_count: byte_count_raw,
                index_size,
            },
        ));
    }
    let count = byte_count / index_size;
    if count > MAX_INDICES_PER_LOD {
        return Err(read::fault(
            asset_path,
            AssetParseFault::BoundsExceeded {
                field: AssetWireField::MeshIndexByteCount,
                value: u64::from(count),
                limit: u64::from(MAX_INDICES_PER_LOD),
                unit: BoundsUnit::Items,
            },
        ));
    }

    let mut indices = Vec::new();
    for _ in 0..count {
        let idx = if is_32bit {
            read::read_u32(reader, asset_path, AssetWireField::MeshIndexData)?
        } else {
            u32::from(read::read_u16(
                reader,
                asset_path,
                AssetWireField::MeshIndexData,
            )?)
        };
        indices.push(idx);
    }

    // UE 4.25+ appends `bShouldExpandTo32Bit` after the payload (read + discard).
    if ctx.version.is_ue4_25_or_later() {
        let _expand =
            read::read_lax_bool32(reader, asset_path, AssetWireField::MeshIndexShouldExpand)?;
    }

    Ok(indices)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::asset::property::test_utils::make_ctx_with_version;

    /// Build the `FRawStaticIndexBuffer` header (`is32bit`, `elementSize`,
    /// `byteCount`) + the raw payload bytes.
    fn buf(is_32bit: bool, payload: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&i32::from(is_32bit).to_le_bytes());
        b.extend_from_slice(&1i32.to_le_bytes()); // elementSize
        b.extend_from_slice(&i32::try_from(payload.len()).unwrap().to_le_bytes());
        b.extend_from_slice(payload);
        b
    }

    /// 16-bit indices widen to `u32`. UE4.24 (no trailing bShouldExpandTo32Bit).
    #[test]
    fn index_buffer_16bit_widens() {
        let ctx = make_ctx_with_version(514, None);
        let payload: Vec<u8> = [1u16, 2, 3].iter().flat_map(|i| i.to_le_bytes()).collect();
        let idx = read_index_buffer(&mut Cursor::new(buf(false, &payload)), &ctx, "T").unwrap();
        assert_eq!(idx, vec![1, 2, 3]);
    }

    /// 32-bit indices. UE4.27 reads + discards the trailing bShouldExpandTo32Bit.
    #[test]
    fn index_buffer_32bit_with_expand_flag() {
        let ctx = make_ctx_with_version(522, None);
        let payload: Vec<u8> = [70000u32, 5].iter().flat_map(|i| i.to_le_bytes()).collect();
        let mut bytes = buf(true, &payload);
        bytes.extend_from_slice(&1i32.to_le_bytes()); // bShouldExpandTo32Bit
        let idx = read_index_buffer(&mut Cursor::new(bytes), &ctx, "T").unwrap();
        assert_eq!(idx, vec![70000, 5]);
    }

    /// `elementSize != 1` is rejected.
    #[test]
    fn index_buffer_rejects_bad_element_size() {
        let ctx = make_ctx_with_version(514, None);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0i32.to_le_bytes()); // is32bit
        bytes.extend_from_slice(&2i32.to_le_bytes()); // elementSize = 2 (invalid)
        let err = read_index_buffer(&mut Cursor::new(bytes), &ctx, "T").unwrap_err();
        assert!(
            matches!(
                err,
                crate::error::PaksmithError::AssetParse {
                    fault: AssetParseFault::IndexBufferElementSizeInvalid { observed: 2 },
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    /// A `byteCount` not divisible by the index size is rejected.
    #[test]
    fn index_buffer_rejects_misaligned_byte_count() {
        let ctx = make_ctx_with_version(514, None);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0i32.to_le_bytes()); // is32bit = false → index size 2
        bytes.extend_from_slice(&1i32.to_le_bytes()); // elementSize
        bytes.extend_from_slice(&3i32.to_le_bytes()); // byteCount = 3 (not /2)
        bytes.extend_from_slice(&[0, 0, 0]);
        let err = read_index_buffer(&mut Cursor::new(bytes), &ctx, "T").unwrap_err();
        assert!(
            matches!(
                err,
                crate::error::PaksmithError::AssetParse {
                    fault: AssetParseFault::IndexBufferByteCountMismatch {
                        byte_count: 3,
                        index_size: 2
                    },
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    /// A negative `byteCount` is rejected.
    #[test]
    fn index_buffer_rejects_negative_byte_count() {
        let ctx = make_ctx_with_version(514, None);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0i32.to_le_bytes());
        bytes.extend_from_slice(&1i32.to_le_bytes());
        bytes.extend_from_slice(&(-4i32).to_le_bytes());
        let err = read_index_buffer(&mut Cursor::new(bytes), &ctx, "T").unwrap_err();
        assert!(
            matches!(
                err,
                crate::error::PaksmithError::AssetParse {
                    fault: AssetParseFault::NegativeValue { .. },
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    /// An empty index buffer (`byteCount == 0`) yields an empty `Vec`.
    #[test]
    fn index_buffer_empty() {
        let ctx = make_ctx_with_version(514, None);
        let idx = read_index_buffer(&mut Cursor::new(buf(false, &[])), &ctx, "T").unwrap();
        assert!(idx.is_empty());
    }
}
