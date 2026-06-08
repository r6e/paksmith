//! `FMultisizeIndexContainer` + `FSkinWeightVertexBuffer` readers for the
//! skeletal-mesh streamed-data blob (Phase 3h PR5a).
//!
//! Wire-format reference: `docs/formats/mesh/skeletal-mesh.md`; oracle
//! `FabianFG/CUE4Parse` `FMultisizeIndexContainer.cs` / `FSkinWeightVertexBuffer.cs`
//! / `FSkinWeightInfo.cs` @ `cf74fc32`.
//!
//! Two readers live here:
//! - [`read_multisize_index_container`] — the skeletal `Indices` /
//!   `AdjacencyIndexBuffer` payload (a `DataSize`-selected u16/u32 bulk array).
//! - [`read_skin_weight_vertex_buffer`] — the per-vertex bone indices/weights,
//!   forked on `FAnimObjectVersion >= UnlimitedBoneInfluences` into the LEGACY
//!   (UE4.24) and NEW (UE4.25+) cooked layouts.
//!
//! Both decode per-vertex influences as fixed-width `[u16; 8]` / `[u8; 8]`
//! (zero-padded to 8 influences). The NEW path's variable-bones-per-vertex
//! variant is consumed off the wire but NOT decoded in PR5a (documented
//! limitation); the readers are `#[allow(dead_code)]` until Task 6/7 wires them
//! into `read_streamed_data`.

use std::io::{Cursor, Read};

use crate::asset::AssetContext;
use crate::asset::custom_version::{
    ANIM_OBJECT_VERSION_GUID, INCREASE_BONE_INDEX_LIMIT_PER_CHUNK, INCREASED_SKIN_WEIGHT_PRECISION,
    SKELETAL_MESH_CUSTOM_VERSION_GUID, SPLIT_MODEL_AND_RENDER_DATA,
    UE5_MAIN_STREAM_OBJECT_VERSION_GUID, UNLIMITED_BONE_INFLUENCES,
};
use crate::asset::wire::{is_av_data_stripped, read_bool32, read_strip_data_flags};
use crate::error::{AssetParseFault, AssetWireField};

use super::index_buffer::MAX_INDICES_PER_LOD;
use super::read;
use super::vertex_buffers::MAX_VERTICES_PER_LOD;

/// Max influences materialized per vertex. UE caps a cooked influence list at 8
/// (`MAX_TOTAL_INFLUENCES`); `bExtraBoneInfluences` / `maxBoneInfluences > 4`
/// selects 8 vs 4. The materialized `[u16; 8]` / `[u8; 8]` arrays are always
/// zero-padded to this width.
const MAX_INFLUENCES: usize = 8;

/// `u32` mirror of [`MAX_INFLUENCES`] for the `maxBoneInfluences` count cap
/// (the count helpers take a `u32` max). Pinned equal in
/// `max_influences_u32_mirrors_usize`.
const MAX_INFLUENCES_U32: u32 = 8;

/// `(bone_indices, bone_weights)` materialized by [`read_skin_weight_vertex_buffer`]
/// — per-vertex fixed-width arrays zero-padded to [`MAX_INFLUENCES`] influences.
type SkinWeights = (Vec<[u16; 8]>, Vec<[u8; 8]>);

/// Byte cap for the new-format `newData` raw influence blob
/// (`ReadBulkArray<byte>`). Derived as the worst-case fully-dense layout:
/// `MAX_VERTICES_PER_LOD` vertices × 8 influences × (2-byte index + 2-byte
/// weight) = `MAX_VERTICES_PER_LOD × 32`. Bounds the allocation before the bulk
/// read; the per-vertex decode then bounds itself to the materialized blob.
pub(crate) const MAX_SKIN_WEIGHT_DATA_BYTES: u32 = MAX_VERTICES_PER_LOD * 32;

/// Read an `FMultisizeIndexContainer` into a `Vec<u32>`.
///
/// Wire (UE 4.24+, `bOldNeedsCPUAccess` prefix absent): `DataSize` (`u8`, 2 or
/// 4) selecting the per-element index width, then a `ReadBulkArray` header
/// (`elementSize: i32`, `elementCount: i32`) and `elementCount` indices of
/// `DataSize` bytes each (widened from `u16` when `DataSize == 2`).
///
/// `DataSize` MUST be exactly 2 or 4 — this is STRICTER than CUE4Parse (which
/// treats any `DataSize != 2` as 4-byte); the ambiguous value is rejected so a
/// corrupt byte can't silently widen the stride.
#[allow(
    dead_code,
    reason = "wired into read_streamed_data in Phase 3h Task 6/7; covered by the multisize_index_container_* tests"
)]
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
        read::read_bulk_array_header(r, asset_path, field, MAX_INDICES_PER_LOD)?;
    let mut indices = Vec::with_capacity(count as usize);
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

/// Read an `FSkinWeightVertexBuffer` into `(bone_indices, bone_weights)`, each a
/// per-vertex fixed-width array zero-padded to 8 influences.
///
/// Path select: `FAnimObjectVersion >= UnlimitedBoneInfluences(5)` chooses the
/// NEW (UE4.25+) cooked layout; otherwise the LEGACY (UE4.24) layout. See the
/// module docs for the per-path wire shapes. The NEW path's
/// `bVariableBonesPerVertex` variant is consumed off the wire but left
/// undecoded (empty result + `tracing::warn!`) in PR5a.
#[allow(
    dead_code,
    reason = "wired into read_streamed_data in Phase 3h Task 6/7; covered by the skin_weights_* tests"
)]
pub(crate) fn read_skin_weight_vertex_buffer<R: Read + ?Sized>(
    r: &mut R,
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<SkinWeights> {
    let version_for = |guid| ctx.custom_versions.version_for(guid);
    let new_format =
        version_for(ANIM_OBJECT_VERSION_GUID).is_some_and(|v| v >= UNLIMITED_BONE_INFLUENCES);
    if new_format {
        read_skin_weights_new(r, ctx, asset_path)
    } else {
        read_skin_weights_legacy(r, ctx, asset_path)
    }
}

/// LEGACY (UE4.24) `FSkinWeightVertexBuffer`: `FStripDataFlags` +
/// `bExtraBoneInfluences` (`bool32`) + an optional 4-byte stride skip (on
/// `FSkeletalMeshCustomVersion >= SplitModelAndRenderData`) + `NumVertices`
/// (`u32`), then — unless the data is AV-stripped — a `ReadBulkArray` of
/// `FSkinWeightInfo` (`n × u8` bone indices then `n × u8` weights, `n = 8` iff
/// `bExtraBoneInfluences` else `4`).
fn read_skin_weights_legacy<R: Read + ?Sized>(
    r: &mut R,
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<SkinWeights> {
    let version_for = |guid| ctx.custom_versions.version_for(guid);
    let (data_global, _class) =
        read_strip_data_flags(r, asset_path, AssetWireField::SkinWeightFlags)?;
    let b_extra = read_bool32(r, asset_path, AssetWireField::SkinWeightFlags)?;
    if version_for(SKELETAL_MESH_CUSTOM_VERSION_GUID)
        .is_some_and(|v| v >= SPLIT_MODEL_AND_RENDER_DATA)
    {
        // Stride (u32) — read-and-discarded.
        let _stride = read::read_u32(r, asset_path, AssetWireField::SkinWeightStride)?;
    }
    let _num_vertices = read::read_capped_count(
        r,
        asset_path,
        AssetWireField::SkinWeightVertexCount,
        MAX_VERTICES_PER_LOD,
    )?;
    let n = if b_extra { 8 } else { 4 };
    if is_av_data_stripped(data_global) {
        return Ok((Vec::new(), Vec::new()));
    }
    let (_elem_size, count) = read::read_bulk_array_header(
        r,
        asset_path,
        AssetWireField::SkinWeightVertexCount,
        MAX_VERTICES_PER_LOD,
    )?;
    let mut bone_indices = Vec::with_capacity(count as usize);
    let mut bone_weights = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let mut idx = [0u16; MAX_INFLUENCES];
        for slot in idx.iter_mut().take(n) {
            *slot = u16::from(read::read_u8(
                r,
                asset_path,
                AssetWireField::SkinWeightBoneIndex,
            )?);
        }
        let mut wt = [0u8; MAX_INFLUENCES];
        for slot in wt.iter_mut().take(n) {
            *slot = read::read_u8(r, asset_path, AssetWireField::SkinWeightBoneWeight)?;
        }
        bone_indices.push(idx);
        bone_weights.push(wt);
    }
    Ok((bone_indices, bone_weights))
}

/// NEW (UE4.25+) `FSkinWeightVertexBuffer`. See the in-body comments for the
/// per-field oracle order. PR5a decodes only the fixed-stride
/// (`!bVariableBonesPerVertex`) layout; the variable variant is consumed off
/// the wire but left undecoded.
fn read_skin_weights_new<R: Read + ?Sized>(
    r: &mut R,
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<SkinWeights> {
    let version_for = |guid| ctx.custom_versions.version_for(guid);
    let (data_global, _class) =
        read_strip_data_flags(r, asset_path, AssetWireField::SkinWeightFlags)?;
    let b_variable = read_bool32(r, asset_path, AssetWireField::SkinWeightFlags)?;
    let max_bone_influences = read::read_capped_count(
        r,
        asset_path,
        AssetWireField::SkinWeightMaxInfluences,
        MAX_INFLUENCES_U32,
    )?;
    let _num_bones = read::read_u32(r, asset_path, AssetWireField::SkinWeightNumBones)?;
    let num_vertices = read::read_capped_count(
        r,
        asset_path,
        AssetWireField::SkinWeightVertexCount,
        MAX_VERTICES_PER_LOD,
    )?;
    // bUse16BitBoneIndex is ALWAYS present in the new branch
    // (IncreaseBoneIndexLimitPerChunk=4 < UnlimitedBoneInfluences=5).
    let b_use_16bit_bone_index = if version_for(ANIM_OBJECT_VERSION_GUID)
        .is_some_and(|v| v >= INCREASE_BONE_INDEX_LIMIT_PER_CHUNK)
    {
        read_bool32(r, asset_path, AssetWireField::SkinWeightPrecisionFlags)?
    } else {
        false
    };
    // bUse16BitBoneWeight is a UE5-only gate (IncreasedSkinWeightPrecision=90) —
    // ALWAYS false/absent for UE4.
    let b_use_16bit_bone_weight = if version_for(UE5_MAIN_STREAM_OBJECT_VERSION_GUID)
        .is_some_and(|v| v >= INCREASED_SKIN_WEIGHT_PRECISION)
    {
        read_bool32(r, asset_path, AssetWireField::SkinWeightPrecisionFlags)?
    } else {
        false
    };
    // Per-vertex influence width: bExtraBoneInfluences = maxBoneInfluences > 4,
    // then 8 vs 4 — NOT maxBoneInfluences (which would desync for 5/6/7).
    let num_skel = if max_bone_influences > 4 { 8 } else { 4 };

    // newData: gated on the DATA strip flags' AV bit.
    let new_data = if is_av_data_stripped(data_global) {
        Vec::new()
    } else {
        let (_elem_size, count) = read::read_bulk_array_header(
            r,
            asset_path,
            AssetWireField::SkinWeightNewData,
            MAX_SKIN_WEIGHT_DATA_BYTES,
        )?;
        let mut buf = vec![0u8; count as usize];
        r.read_exact(&mut buf)
            .map_err(|_| read::eof(asset_path, AssetWireField::SkinWeightNewData))?;
        buf
    };

    // Lookup block: the header is read UNCONDITIONALLY; LookupData is gated on
    // the lookup strip flags' OWN AV bit (NOT the data strip flags).
    let (lookup_global, _lookup_class) =
        read_strip_data_flags(r, asset_path, AssetWireField::SkinWeightFlags)?;
    let _num_lookup = read::read_i32(r, asset_path, AssetWireField::SkinWeightLookupCount)?;
    if !is_av_data_stripped(lookup_global) {
        let (_elem_size, lk_count) = read::read_bulk_array_header(
            r,
            asset_path,
            AssetWireField::SkinWeightLookupData,
            MAX_VERTICES_PER_LOD,
        )?;
        for _ in 0..lk_count {
            // LookupData (u32 per vertex) — read-and-discarded in PR5a (only
            // used to drive the variable-bones decode, which is deferred).
            let _ = read::read_u32(r, asset_path, AssetWireField::SkinWeightLookupData)?;
        }
    }

    // AV-stripped data → no influence blob to decode (cooked-out geometry).
    if is_av_data_stripped(data_global) {
        return Ok((Vec::new(), Vec::new()));
    }

    if b_variable {
        // newData + lookup are already consumed off the main cursor, so it stays
        // aligned regardless of decode. Variable-bones decode (offset-indexed via
        // the lookup table) is deferred to a later PR.
        tracing::warn!(
            "variable bones-per-vertex skin weights not decoded (LOD geometry skin data omitted)"
        );
        return Ok((Vec::new(), Vec::new()));
    }

    decode_fixed_stride(
        &new_data,
        asset_path,
        num_vertices,
        num_skel,
        b_use_16bit_bone_index,
        b_use_16bit_bone_weight,
    )
}

/// Decode the fixed-stride `newData` blob (`!bVariableBonesPerVertex`): per
/// vertex, `num_skel` bone indices then `num_skel` weights, each `u16` or `u8`
/// per the precision flags. Reads off a fresh `Cursor` over `new_data` so an
/// under-run surfaces as a typed EOF without touching the main cursor.
fn decode_fixed_stride(
    new_data: &[u8],
    asset_path: &str,
    num_vertices: u32,
    num_skel: usize,
    b_use_16bit_bone_index: bool,
    b_use_16bit_bone_weight: bool,
) -> crate::Result<SkinWeights> {
    let mut cur = Cursor::new(new_data);
    let mut bone_indices = Vec::with_capacity(num_vertices as usize);
    let mut bone_weights = Vec::with_capacity(num_vertices as usize);
    for _ in 0..num_vertices {
        let mut idx = [0u16; MAX_INFLUENCES];
        for slot in idx.iter_mut().take(num_skel) {
            *slot = if b_use_16bit_bone_index {
                read::read_u16(&mut cur, asset_path, AssetWireField::SkinWeightBoneIndex)?
            } else {
                u16::from(read::read_u8(
                    &mut cur,
                    asset_path,
                    AssetWireField::SkinWeightBoneIndex,
                )?)
            };
        }
        let mut wt = [0u8; MAX_INFLUENCES];
        for slot in wt.iter_mut().take(num_skel) {
            *slot = if b_use_16bit_bone_weight {
                // UNVERIFIED (dead path in PR5a — UE5-only u16 weights, no
                // oracle/fixture): take the high byte of the normalized u16
                // weight. Flagged for verification when UE5 support lands.
                (read::read_u16(&mut cur, asset_path, AssetWireField::SkinWeightBoneWeight)? >> 8)
                    as u8
            } else {
                read::read_u8(&mut cur, asset_path, AssetWireField::SkinWeightBoneWeight)?
            };
        }
        bone_indices.push(idx);
        bone_weights.push(wt);
    }
    Ok((bone_indices, bone_weights))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::custom_version::{CustomVersion, CustomVersionContainer};
    use crate::asset::export_table::ExportTable;
    use crate::asset::import_table::ImportTable;
    use crate::asset::name_table::NameTable;
    use crate::asset::version::AssetVersion;
    use crate::error::PaksmithError;
    use std::sync::Arc;

    const F: AssetWireField = AssetWireField::SkelMeshIndexElement;

    /// Append a UE bulk-array header (`elementSize: i32`, `elementCount: i32`).
    fn bulk_header(buf: &mut Vec<u8>, element_size: i32, element_count: i32) {
        buf.extend_from_slice(&element_size.to_le_bytes());
        buf.extend_from_slice(&element_count.to_le_bytes());
    }

    /// Build an `AssetContext` stamping `FAnimObjectVersion`,
    /// `FSkeletalMeshCustomVersion`, and `FUE5MainStreamObjectVersion` at the
    /// requested positions (the three plugins the skin-weight reader gates on).
    /// `ue5_main` stays below `INCREASED_SKIN_WEIGHT_PRECISION` so the u16-weight
    /// gate never fires for these UE4 byte streams.
    fn skin_ctx(anim: i32, skel_mesh: i32, ue5_main: i32) -> AssetContext {
        let custom_versions = CustomVersionContainer {
            versions: vec![
                CustomVersion {
                    guid: ANIM_OBJECT_VERSION_GUID,
                    version: anim,
                },
                CustomVersion {
                    guid: SKELETAL_MESH_CUSTOM_VERSION_GUID,
                    version: skel_mesh,
                },
                CustomVersion {
                    guid: UE5_MAIN_STREAM_OBJECT_VERSION_GUID,
                    version: ue5_main,
                },
            ],
        };
        AssetContext::new(
            Arc::new(NameTable::default()),
            Arc::new(ImportTable::default()),
            Arc::new(ExportTable::default()),
            AssetVersion {
                legacy_file_version: -7,
                file_version_ue4: 518,
                file_version_ue5: None,
                file_version_licensee_ue4: 0,
            },
            Arc::new(custom_versions),
            None,
        )
    }

    /// A legacy ctx: `FAnimObjectVersion` below `UnlimitedBoneInfluences` so the
    /// LEGACY path is taken; `FSkeletalMeshCustomVersion` at
    /// `SplitModelAndRenderData` so the stride skip fires.
    fn legacy_ctx() -> AssetContext {
        skin_ctx(
            UNLIMITED_BONE_INFLUENCES - 1,
            SPLIT_MODEL_AND_RENDER_DATA,
            0,
        )
    }

    /// A new-format ctx: `FAnimObjectVersion` at `UnlimitedBoneInfluences` so the
    /// NEW path is taken (and `bUse16BitBoneIndex` reads, since
    /// `IncreaseBoneIndexLimitPerChunk(4) < 5`); `ue5_main` below the u16-weight
    /// gate.
    fn new_ctx() -> AssetContext {
        skin_ctx(UNLIMITED_BONE_INFLUENCES, SPLIT_MODEL_AND_RENDER_DATA, 0)
    }

    // ===== Task 3: read_multisize_index_container =====

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

    // ===== Task 4: LEGACY path =====

    /// Append a legacy `FSkinWeightInfo`: `n × u8` bone indices then `n × u8`
    /// weights.
    fn legacy_vertex(buf: &mut Vec<u8>, bones: &[u8], weights: &[u8]) {
        buf.extend_from_slice(bones);
        buf.extend_from_slice(weights);
    }

    #[test]
    fn skin_weights_legacy_4_influences() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0u8, 0u8]); // FStripDataFlags (not AV-stripped)
        buf.extend_from_slice(&0u32.to_le_bytes()); // bExtraBoneInfluences = 0
        buf.extend_from_slice(&0u32.to_le_bytes()); // stride (skipped)
        buf.extend_from_slice(&2u32.to_le_bytes()); // numVertices
        bulk_header(&mut buf, 8, 2); // FSkinWeightInfo bulk: elementSize=8, count=2
        legacy_vertex(&mut buf, &[1, 2, 3, 4], &[10, 20, 30, 40]);
        legacy_vertex(&mut buf, &[5, 6, 7, 8], &[50, 60, 70, 80]);

        let mut cur = Cursor::new(buf.as_slice());
        let (bone_indices, bone_weights) =
            read_skin_weight_vertex_buffer(&mut cur, &legacy_ctx(), "T").unwrap();
        assert_eq!(
            bone_indices,
            vec![[1, 2, 3, 4, 0, 0, 0, 0], [5, 6, 7, 8, 0, 0, 0, 0]]
        );
        assert_eq!(
            bone_weights,
            vec![[10, 20, 30, 40, 0, 0, 0, 0], [50, 60, 70, 80, 0, 0, 0, 0]]
        );
        assert_eq!(cur.position(), buf.len() as u64);
    }

    #[test]
    fn skin_weights_legacy_8_influences() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0u8, 0u8]); // FStripDataFlags
        buf.extend_from_slice(&1u32.to_le_bytes()); // bExtraBoneInfluences = 1
        buf.extend_from_slice(&0u32.to_le_bytes()); // stride
        buf.extend_from_slice(&1u32.to_le_bytes()); // numVertices
        bulk_header(&mut buf, 16, 1);
        legacy_vertex(
            &mut buf,
            &[1, 2, 3, 4, 5, 6, 7, 8],
            &[11, 22, 33, 44, 55, 66, 77, 88],
        );

        let mut cur = Cursor::new(buf.as_slice());
        let (bone_indices, bone_weights) =
            read_skin_weight_vertex_buffer(&mut cur, &legacy_ctx(), "T").unwrap();
        assert_eq!(bone_indices, vec![[1, 2, 3, 4, 5, 6, 7, 8]]);
        assert_eq!(bone_weights, vec![[11, 22, 33, 44, 55, 66, 77, 88]]);
        assert_eq!(cur.position(), buf.len() as u64);
    }

    // ===== Task 5: NEW path =====

    /// Append the new-format metadata up to (and including) `bUse16BitBoneIndex`.
    fn new_meta(
        buf: &mut Vec<u8>,
        b_variable: u32,
        max_bone_influences: u32,
        num_bones: u32,
        num_vertices: u32,
        b_use_16bit_bone_index: u32,
    ) {
        buf.extend_from_slice(&[0u8, 0u8]); // data FStripDataFlags (not AV-stripped)
        buf.extend_from_slice(&b_variable.to_le_bytes());
        buf.extend_from_slice(&max_bone_influences.to_le_bytes());
        buf.extend_from_slice(&num_bones.to_le_bytes());
        buf.extend_from_slice(&num_vertices.to_le_bytes());
        buf.extend_from_slice(&b_use_16bit_bone_index.to_le_bytes());
    }

    #[test]
    fn skin_weights_new_fixed_stride() {
        let mut buf = Vec::new();
        new_meta(&mut buf, 0, 4, 3, 2, 0); // !variable, maxBI=4, numBones=3, numVerts=2, 8bit idx
        // newData: 2 verts × num_skel(4) × 2 (idx+wt) = 16 bytes.
        bulk_header(&mut buf, 1, 16);
        buf.extend_from_slice(&[1, 2, 3, 4]); // v0 indices
        buf.extend_from_slice(&[10, 20, 30, 40]); // v0 weights
        buf.extend_from_slice(&[5, 6, 7, 8]); // v1 indices
        buf.extend_from_slice(&[50, 60, 70, 80]); // v1 weights
        // lookup block: AV-stripped so LookupData is skipped (count==0 case).
        buf.extend_from_slice(&[0x02u8, 0u8]); // lookup FStripDataFlags (AV bit set)
        buf.extend_from_slice(&0i32.to_le_bytes()); // numLookupVertices = 0

        let mut cur = Cursor::new(buf.as_slice());
        let (bone_indices, bone_weights) =
            read_skin_weight_vertex_buffer(&mut cur, &new_ctx(), "T").unwrap();
        assert_eq!(
            bone_indices,
            vec![[1, 2, 3, 4, 0, 0, 0, 0], [5, 6, 7, 8, 0, 0, 0, 0]]
        );
        assert_eq!(
            bone_weights,
            vec![[10, 20, 30, 40, 0, 0, 0, 0], [50, 60, 70, 80, 0, 0, 0, 0]]
        );
        assert_eq!(cur.position(), buf.len() as u64);
    }

    #[test]
    fn skin_weights_new_16bit_bone_index() {
        let mut buf = Vec::new();
        new_meta(&mut buf, 0, 4, 3, 1, 1); // bUse16BitBoneIndex = 1
        // newData: 1 vert × num_skel(4) × (2-byte idx) + 4 × (1-byte wt) = 12 bytes.
        bulk_header(&mut buf, 1, 12);
        for v in [300u16, 301, 302, 303] {
            buf.extend_from_slice(&v.to_le_bytes()); // 8 bytes of indices
        }
        buf.extend_from_slice(&[10, 20, 30, 40]); // 4 bytes of weights
        buf.extend_from_slice(&[0x02u8, 0u8]); // lookup FStripDataFlags (AV-stripped)
        buf.extend_from_slice(&0i32.to_le_bytes()); // numLookupVertices = 0

        let mut cur = Cursor::new(buf.as_slice());
        let (bone_indices, bone_weights) =
            read_skin_weight_vertex_buffer(&mut cur, &new_ctx(), "T").unwrap();
        assert_eq!(bone_indices, vec![[300, 301, 302, 303, 0, 0, 0, 0]]);
        assert_eq!(bone_weights, vec![[10, 20, 30, 40, 0, 0, 0, 0]]);
        assert_eq!(cur.position(), buf.len() as u64);
    }

    #[test]
    fn skin_weights_new_variable_is_omitted() {
        let mut buf = Vec::new();
        new_meta(&mut buf, 1, 4, 3, 2, 0); // bVariableBonesPerVertex = 1
        // newData blob (consumed wholesale, contents irrelevant to the defer).
        bulk_header(&mut buf, 1, 8);
        buf.extend_from_slice(&[0u8; 8]);
        // lookup block with LookupData PRESENT (not AV-stripped) → exercises the
        // unconditional-header + own-AV-bit gating + full consumption.
        buf.extend_from_slice(&[0u8, 0u8]); // lookup FStripDataFlags (not AV-stripped)
        buf.extend_from_slice(&2i32.to_le_bytes()); // numLookupVertices
        bulk_header(&mut buf, 4, 2); // LookupData bulk: 2 × u32
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&1u32.to_le_bytes());

        let mut cur = Cursor::new(buf.as_slice());
        let (bone_indices, bone_weights) =
            read_skin_weight_vertex_buffer(&mut cur, &new_ctx(), "T").unwrap();
        assert!(bone_indices.is_empty());
        assert!(bone_weights.is_empty());
        assert_eq!(cur.position(), buf.len() as u64); // cursor fully aligned
    }

    /// AV-stripped data → both `newData` and the bulk geometry are absent, so
    /// the result is empty but the lookup header is still consumed.
    #[test]
    fn skin_weights_new_av_stripped_data() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x02u8, 0u8]); // data FStripDataFlags (AV-stripped)
        buf.extend_from_slice(&0u32.to_le_bytes()); // bVariable
        buf.extend_from_slice(&4u32.to_le_bytes()); // maxBoneInfluences
        buf.extend_from_slice(&3u32.to_le_bytes()); // numBones
        buf.extend_from_slice(&2u32.to_le_bytes()); // numVertices
        buf.extend_from_slice(&0u32.to_le_bytes()); // bUse16BitBoneIndex
        // No newData (AV-stripped). Lookup header still read unconditionally.
        buf.extend_from_slice(&[0x02u8, 0u8]); // lookup AV-stripped
        buf.extend_from_slice(&0i32.to_le_bytes()); // numLookupVertices

        let mut cur = Cursor::new(buf.as_slice());
        let (bone_indices, bone_weights) =
            read_skin_weight_vertex_buffer(&mut cur, &new_ctx(), "T").unwrap();
        // AV-stripped → no influence blob → empty result, lookup header consumed.
        assert!(bone_indices.is_empty());
        assert!(bone_weights.is_empty());
        assert_eq!(cur.position(), buf.len() as u64);
    }

    /// The `MAX_SKIN_WEIGHT_DATA_BYTES` cap is the worst-case dense byte count.
    #[test]
    fn max_skin_weight_data_bytes_is_pinned() {
        assert_eq!(MAX_SKIN_WEIGHT_DATA_BYTES, MAX_VERTICES_PER_LOD * 32);
        assert_eq!(MAX_SKIN_WEIGHT_DATA_BYTES, 134_217_728); // 4 Mi × 32
    }

    #[test]
    fn max_influences_u32_mirrors_usize() {
        assert_eq!(MAX_INFLUENCES_U32 as usize, MAX_INFLUENCES);
        assert_eq!(MAX_INFLUENCES, 8);
    }
}
