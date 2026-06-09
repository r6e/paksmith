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
/// Wire: `is32bit` (`bool32`), `elementSize` (`i32`, always `1`),
/// `byteCount` (`i32`, total payload bytes — index count is derived), the raw
/// `byteCount`-byte payload (parsed as `u16`/`u32` per `is32bit`), then — for
/// UE 4.25+ — a trailing `bShouldExpandTo32Bit` (`bool32`, discarded). The
/// derived index count is capped at [`MAX_INDICES_PER_LOD`] before the bulk
/// read, and `byteCount` must be a whole multiple of the index size.
pub(crate) fn read_index_buffer<R: Read>(
    reader: &mut R,
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<Vec<u32>> {
    let is_32bit =
        crate::asset::wire::read_bool32(reader, asset_path, AssetWireField::MeshIndexIs32Bit)?;

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
        let _expand = crate::asset::wire::read_bool32(
            reader,
            asset_path,
            AssetWireField::MeshIndexShouldExpand,
        )?;
    }

    Ok(indices)
}

/// Read an `FMultisizeIndexContainer` into a `Vec<u32>`.
///
/// This is the skeletal-mesh `Indices` / `AdjacencyIndexBuffer` index format
/// (oracle `FabianFG/CUE4Parse` `FMultisizeIndexContainer.cs`), distinct from
/// the static-mesh [`read_index_buffer`] above; both materialize per-triangle
/// vertex indices as `Vec<u32>` regardless of on-wire width.
///
/// Wire (UE 4.24+, `bOldNeedsCPUAccess` prefix absent): `DataSize` (`u8`, 2 or
/// 4) selecting the per-element index width, then a `ReadBulkArray` header
/// (`elementSize: i32`, `elementCount: i32`) and `elementCount` indices of
/// `DataSize` bytes each (widened from `u16` when `DataSize == 2`).
///
/// `DataSize` MUST be exactly 2 or 4 — this is STRICTER than CUE4Parse (which
/// treats any `DataSize != 2` as 4-byte); the ambiguous value is rejected so a
/// corrupt byte can't silently widen the stride. The caller passes the
/// per-call-site `field` tag (`SkelLodIndexCount` / `SkelLodAdjacencyIndexCount`)
/// for the bulk-array header's count cap.
pub(crate) fn read_multisize_index_container<R: Read + ?Sized>(
    r: &mut R,
    asset_path: &str,
    field: AssetWireField,
) -> crate::Result<Vec<u32>> {
    let data_size = read::read_u8(r, asset_path, AssetWireField::SkelMeshIndexDataSize)?;
    if data_size != 2 && data_size != 4 {
        return Err(read::fault(
            asset_path,
            AssetParseFault::MultisizeIndexDataSizeInvalid { data_size },
        ));
    }
    let (_elem_size, count) =
        // _elem_size is intentionally discarded: paksmith relies on the
        // EOF-bounded per-element read loop rather than the elem-size
        // cross-check (CUE4Parse's ReadBulkArray<T> asserts elem-size ==
        // sizeof(T); the loop is the simpler equivalent here).
        read::read_bulk_array_header(r, asset_path, field, MAX_INDICES_PER_LOD)?;
    // Vec::new() rather than Vec::with_capacity(count): `count` is an
    // attacker-controlled wire value; pre-allocating against it allows a
    // lying count to DoS via over-reservation before the first read hits
    // EOF. The per-element loop is EOF-bounded, so growth is limited to the
    // bytes actually present.
    let mut indices = Vec::new();
    for _ in 0..count {
        let value = if data_size == 2 {
            u32::from(read::read_u16(
                r,
                asset_path,
                AssetWireField::SkelMeshIndexElement,
            )?)
        } else {
            read::read_u32(r, asset_path, AssetWireField::SkelMeshIndexElement)?
        };
        indices.push(value);
    }
    Ok(indices)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::asset::property::test_utils::make_ctx_with_version;
    use crate::error::PaksmithError;

    /// Field tag the `read_multisize_index_container` tests pass for the
    /// bulk-array header (the real call sites pass `SkelLodIndexCount` /
    /// `SkelLodAdjacencyIndexCount`).
    const F: AssetWireField = AssetWireField::SkelMeshIndexElement;

    /// Append a UE bulk-array header (`elementSize: i32`, `elementCount: i32`).
    fn bulk_header(buf: &mut Vec<u8>, element_size: i32, element_count: i32) {
        buf.extend_from_slice(&element_size.to_le_bytes());
        buf.extend_from_slice(&element_count.to_le_bytes());
    }

    /// Pin the derived cap's literal value so the `MAX_VERTICES_PER_LOD * 6`
    /// arithmetic is mutation-covered.
    #[test]
    fn max_indices_per_lod_value() {
        assert_eq!(MAX_INDICES_PER_LOD, 25_165_824); // 4 Mi × 6
    }

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

    /// A derived index count one past the cap is rejected with the cap value as
    /// `limit`. Pins the `count > MAX_INDICES_PER_LOD` check against a `==`
    /// mutant (which would accept the over-cap count).
    #[test]
    fn index_buffer_count_over_cap_is_rejected() {
        let ctx = make_ctx_with_version(514, None);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0i32.to_le_bytes()); // is32bit = false → index size 2
        bytes.extend_from_slice(&1i32.to_le_bytes()); // elementSize
        // byteCount yields count = MAX_INDICES_PER_LOD + 1 (> cap). No payload
        // needed — the cap fires before the bulk read.
        let byte_count = (MAX_INDICES_PER_LOD + 1) * 2;
        bytes.extend_from_slice(&i32::try_from(byte_count).unwrap().to_le_bytes());
        let err = read_index_buffer(&mut Cursor::new(bytes), &ctx, "T").unwrap_err();
        assert!(matches!(
            err,
            crate::error::PaksmithError::AssetParse {
                fault: AssetParseFault::BoundsExceeded {
                    field: AssetWireField::MeshIndexByteCount,
                    limit,
                    ..
                },
                ..
            } if limit == u64::from(MAX_INDICES_PER_LOD)
        ));
    }

    /// A derived index count *exactly* at the cap is accepted by the bounds
    /// check (the failure that follows is the bulk read hitting EOF, **not**
    /// `BoundsExceeded`). Pins the check as `>` (not `>=`), which would reject
    /// the at-cap count.
    #[test]
    fn index_buffer_count_at_cap_passes_bounds_then_eofs() {
        let ctx = make_ctx_with_version(514, None);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0i32.to_le_bytes()); // is32bit = false → index size 2
        bytes.extend_from_slice(&1i32.to_le_bytes()); // elementSize
        let byte_count = MAX_INDICES_PER_LOD * 2; // count == cap
        bytes.extend_from_slice(&i32::try_from(byte_count).unwrap().to_le_bytes());
        // No payload → the (in-bounds) bulk read EOFs on its first element.
        let err = read_index_buffer(&mut Cursor::new(bytes), &ctx, "T").unwrap_err();
        assert!(matches!(
            err,
            crate::error::PaksmithError::AssetParse {
                fault: AssetParseFault::UnexpectedEof {
                    field: AssetWireField::MeshIndexData
                },
                ..
            }
        ));
    }

    /// An empty index buffer (`byteCount == 0`) yields an empty `Vec`.
    #[test]
    fn index_buffer_empty() {
        let ctx = make_ctx_with_version(514, None);
        let idx = read_index_buffer(&mut Cursor::new(buf(false, &[])), &ctx, "T").unwrap();
        assert!(idx.is_empty());
    }

    // ===== read_multisize_index_container (FMultisizeIndexContainer) =====

    #[test]
    fn multisize_index_container_16bit() {
        let mut buf = vec![2u8]; // DataSize = 2
        bulk_header(&mut buf, 2, 3); // elementSize=2, elementCount=3
        for v in [1u16, 2, 3] {
            buf.extend_from_slice(&v.to_le_bytes());
        }
        let mut cur = Cursor::new(buf.as_slice());
        let indices = read_multisize_index_container(&mut cur, "T", F).unwrap();
        assert_eq!(indices, vec![1u32, 2, 3]);
        assert_eq!(cur.position(), buf.len() as u64); // full consumption
    }

    #[test]
    fn multisize_index_container_32bit() {
        let mut buf = vec![4u8]; // DataSize = 4
        bulk_header(&mut buf, 4, 2);
        for v in [70_000u32, 1] {
            buf.extend_from_slice(&v.to_le_bytes());
        }
        let mut cur = Cursor::new(buf.as_slice());
        let indices = read_multisize_index_container(&mut cur, "T", F).unwrap();
        assert_eq!(indices, vec![70_000u32, 1]);
        assert_eq!(cur.position(), buf.len() as u64);
    }

    #[test]
    fn multisize_index_container_invalid_data_size() {
        let buf = vec![3u8]; // DataSize = 3 → invalid
        let err =
            read_multisize_index_container(&mut Cursor::new(buf.as_slice()), "T", F).unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::MultisizeIndexDataSizeInvalid { data_size: 3 },
                ..
            }
        ));
    }

    #[test]
    fn multisize_index_container_truncated_is_eof() {
        let mut buf = vec![2u8];
        bulk_header(&mut buf, 2, 3); // claims 3 elements
        buf.extend_from_slice(&1u16.to_le_bytes()); // supplies 1
        let err =
            read_multisize_index_container(&mut Cursor::new(buf.as_slice()), "T", F).unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::UnexpectedEof {
                    field: AssetWireField::SkelMeshIndexElement
                },
                ..
            }
        ));
    }
}
