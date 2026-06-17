//! `FSkinWeightVertexBuffer` reader for the skeletal-mesh streamed-data blob
//! (Phase 3h PR5a).
//!
//! Wire-format reference: `docs/formats/mesh/skeletal-mesh.md`; oracle
//! `FabianFG/CUE4Parse` `FSkinWeightVertexBuffer.cs` / `FSkinWeightInfo.cs` @
//! `cf74fc32`. (The companion `FMultisizeIndexContainer` index format lives in
//! `index_buffer.rs` alongside the static-mesh index reader.)
//!
//! [`read_skin_weight_vertex_buffer`] reads the per-vertex bone indices/weights,
//! forked on `FAnimObjectVersion >= UnlimitedBoneInfluences` into the LEGACY
//! (UE4.24) and NEW (UE4.25+) cooked layouts.
//!
//! Both decode per-vertex influences as fixed-width `[u16; 8]` / `[u8; 8]`
//! (zero-padded to 8 influences). The NEW path has two deferred variants:
//! - `bVariableBonesPerVertex` — consumed off the wire but NOT decoded (empty
//!   result + warn); deferred to a later PR.
//! - `bUse16BitBoneWeight` — UE5-only (`FUE5MainStreamObjectVersion >=
//!   IncreasedSkinWeightPrecision(90)`), always absent for paksmith's UE4.24–4.27
//!   target; the narrowing (`u16 >> 8 → u8`) is UNVERIFIED (no oracle/fixture),
//!   so the path is omitted entirely (empty result + warn) rather than shipping
//!   unverified decode logic.
//!
//! Both readers are wired into `skeletal_mesh::read_streamed_data` (Task 6/7).

use std::io::{Cursor, Read};

use crate::asset::custom_version::{
    ANIM_OBJECT_VERSION_GUID, INCREASE_BONE_INDEX_LIMIT_PER_CHUNK, INCREASED_SKIN_WEIGHT_PRECISION,
    SKELETAL_MESH_CUSTOM_VERSION_GUID, SPLIT_MODEL_AND_RENDER_DATA,
    UE5_MAIN_STREAM_OBJECT_VERSION_GUID, UNLIMITED_BONE_INFLUENCES,
};
use crate::asset::wire::{is_av_data_stripped, read_bool32, read_strip_data_flags};
use crate::asset::{AssetContext, BoneWeights};
use crate::error::AssetWireField;

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
/// — per-vertex bone indices (fixed-width, zero-padded to [`MAX_INFLUENCES`]) and
/// the precision-tagged [`BoneWeights`] (`U8` for the common cooked layout, `U16`
/// for UE5 `IncreasedSkinWeightPrecision`).
type SkinWeights = (Vec<[u16; 8]>, BoneWeights);

/// Byte cap for the new-format `newData` raw influence blob
/// (`ReadBulkArray<byte>`). Derived as the worst-case fully-dense layout:
/// `MAX_VERTICES_PER_LOD` vertices × 8 influences × (2-byte index + 2-byte
/// weight) = `MAX_VERTICES_PER_LOD × 32`. Bounds the allocation before the bulk
/// read; the per-vertex decode then bounds itself to the materialized blob.
pub(crate) const MAX_SKIN_WEIGHT_DATA_BYTES: u32 = MAX_VERTICES_PER_LOD * 32;

/// Read one vertex's influence list: `n` bone indices then `n` `u8` weights,
/// each into a zero-padded `[_; MAX_INFLUENCES]` array. Bone indices are `u16`
/// when `use_16bit_bone_index`, `u8` (widened) otherwise; weights are always
/// `u8` here (the UE5 16-bit-weight path is gated out before any caller reaches
/// this).
///
/// Shared by [`read_skin_weights_legacy`] (always `use_16bit_bone_index =
/// false`) and [`decode_fixed_stride`] (passes its `bUse16BitBoneIndex` flag) —
/// the per-vertex body the two outer loops have in common.
fn read_vertex_influences<R: Read + ?Sized>(
    r: &mut R,
    asset_path: &str,
    n: usize,
    use_16bit_bone_index: bool,
) -> crate::Result<([u16; MAX_INFLUENCES], [u8; MAX_INFLUENCES])> {
    let mut idx = [0u16; MAX_INFLUENCES];
    for slot in idx.iter_mut().take(n) {
        *slot = if use_16bit_bone_index {
            read::read_u16(r, asset_path, AssetWireField::SkinWeightBoneIndex)?
        } else {
            u16::from(read::read_u8(
                r,
                asset_path,
                AssetWireField::SkinWeightBoneIndex,
            )?)
        };
    }
    let mut wt = [0u8; MAX_INFLUENCES];
    for slot in wt.iter_mut().take(n) {
        *slot = read::read_u8(r, asset_path, AssetWireField::SkinWeightBoneWeight)?;
    }
    Ok((idx, wt))
}

/// Read an `FSkinWeightVertexBuffer` into `(bone_indices, bone_weights)`, each a
/// per-vertex fixed-width array zero-padded to 8 influences.
///
/// Path select: `FAnimObjectVersion >= UnlimitedBoneInfluences(5)` chooses the
/// NEW (UE4.25+) cooked layout; otherwise the LEGACY (UE4.24) layout. See the
/// module docs for the per-path wire shapes. The NEW path has two deferred
/// variants that return empty influences with a `tracing::warn!`:
/// - `bVariableBonesPerVertex` — offset-indexed decode deferred to a later PR.
/// - `bUse16BitBoneWeight` — UE5-only; omitted (no oracle/fixture to verify
///   the narrowing); the wire data is already consumed off the main cursor
///   before the decode gate, so cursor alignment is unaffected.
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
        return Ok((Vec::new(), BoneWeights::default()));
    }
    let (_elem_size, count) =
        // _elem_size intentionally discarded: EOF-bounded per-element read
        // loop is the equivalent of CUE4Parse's elem-size == sizeof(T) check.
        read::read_bulk_array_header(
            r,
            asset_path,
            AssetWireField::SkinWeightVertexCount,
            MAX_VERTICES_PER_LOD,
        )?;
    // Vec::new() rather than Vec::with_capacity(count): attacker-controlled
    // wire count could DoS via pre-alloc on truncated data; the loop is
    // EOF-bounded so growth tracks bytes actually consumed.
    let mut bone_indices = Vec::new();
    let mut bone_weights = Vec::new();
    for _ in 0..count {
        // LEGACY bone indices are always u8 (16-bit indices arrived with the
        // NEW format's bUse16BitBoneIndex), so use_16bit_bone_index = false.
        let (idx, wt) = read_vertex_influences(r, asset_path, n, false)?;
        bone_indices.push(idx);
        bone_weights.push(wt);
    }
    Ok((bone_indices, BoneWeights::U8(bone_weights)))
}

/// NEW (UE4.25+) `FSkinWeightVertexBuffer`. See the in-body comments for the
/// per-field oracle order. PR5a decodes only the fixed-stride,
/// `!bVariableBonesPerVertex`, 8-bit-weight layout; both the variable-bones
/// variant and the UE5 16-bit-weight variant are consumed off the wire but
/// left undecoded (empty result + warn).
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
    // u32; not capped — discarded immediately, cannot drive allocation.
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
        let (_elem_size, count) =
            // _elem_size intentionally discarded: EOF-bounded byte consumption
            // via `take` + length-check is the equivalent of CUE4Parse's
            // ReadBulkArray<byte> elem-size == sizeof(byte) assertion.
            read::read_bulk_array_header(
                r,
                asset_path,
                AssetWireField::SkinWeightNewData,
                MAX_SKIN_WEIGHT_DATA_BYTES,
            )?;
        // Consume incrementally (`take` + `read_to_end`) rather than pre-sizing
        // a `vec![0; count]` against the attacker-controlled `count` — a count
        // that lies larger than the data grows the buffer only to the bytes
        // actually present, then the post-read length check surfaces the
        // shortfall as EOF (matching the `read.rs` incremental-consumption
        // contract; `read_to_end` returns `Ok` on a short read, so the explicit
        // check is required).
        let mut buf = Vec::new();
        let _read = r
            .take(u64::from(count))
            .read_to_end(&mut buf)
            .map_err(|_| read::eof(asset_path, AssetWireField::SkinWeightNewData))?;
        if buf.len() != count as usize {
            return Err(read::eof(asset_path, AssetWireField::SkinWeightNewData));
        }
        buf
    };

    // Lookup block: the header is read UNCONDITIONALLY; LookupData is gated on
    // the lookup strip flags' OWN AV bit (NOT the data strip flags).
    let (lookup_global, _lookup_class) =
        read_strip_data_flags(r, asset_path, AssetWireField::SkinWeightFlags)?;
    let _num_lookup = read::read_i32(r, asset_path, AssetWireField::SkinWeightLookupCount)?;
    if !is_av_data_stripped(lookup_global) {
        let (_elem_size, lk_count) =
            // _elem_size intentionally discarded: per-element read loop is
            // EOF-bounded; elem-size cross-check deferred (lookup u32 size
            // is implicit from the AssetWireField context).
            read::read_bulk_array_header(
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
        return Ok((Vec::new(), BoneWeights::default()));
    }

    if b_variable {
        // newData + lookup are already consumed off the main cursor, so it stays
        // aligned regardless of decode. Variable-bones decode (offset-indexed via
        // the lookup table) is deferred to a later PR.
        tracing::warn!(
            "variable bones-per-vertex skin weights not decoded (LOD skin data omitted)"
        );
        return Ok((Vec::new(), BoneWeights::default()));
    }

    if b_use_16bit_bone_weight {
        // UE5-only gate (FUE5MainStreamObjectVersion >= IncreasedSkinWeightPrecision(90)).
        // Always absent for paksmith's UE4.24–4.27 target. The u16→u8 narrowing
        // (`>> 8`) is UNVERIFIED (no oracle or fixture), so decode is omitted
        // entirely rather than shipping unverified logic. newData + lookup are
        // already consumed off the main cursor above, so cursor alignment is
        // unaffected.
        tracing::warn!("UE5 16-bit skin weights not decoded (LOD skin data omitted)");
        return Ok((Vec::new(), BoneWeights::default()));
    }

    decode_fixed_stride(
        &new_data,
        asset_path,
        num_vertices,
        num_skel,
        b_use_16bit_bone_index,
    )
}

/// Decode the fixed-stride `newData` blob (`!bVariableBonesPerVertex`,
/// `!bUse16BitBoneWeight`): per vertex, `num_skel` bone indices then `num_skel`
/// u8 weights. Bone indices are u16 when `b_use_16bit_bone_index`, u8 otherwise.
/// Reads off a fresh `Cursor` over `new_data` so an under-run surfaces as a
/// typed EOF without touching the main cursor.
fn decode_fixed_stride(
    new_data: &[u8],
    asset_path: &str,
    num_vertices: u32,
    num_skel: usize,
    b_use_16bit_bone_index: bool,
) -> crate::Result<SkinWeights> {
    let mut cur = Cursor::new(new_data);
    // Vec::new() rather than Vec::with_capacity(num_vertices): num_vertices
    // is an attacker-controlled wire value (capped but still up to
    // MAX_VERTICES_PER_LOD = 4 Mi). Pre-allocating against it with an empty
    // or short newData blob would reserve ~96 MiB before the first cursor
    // read hits EOF. Growth is bounded by the actual bytes in the newData
    // slice (already validated + length-checked upstream).
    let mut bone_indices = Vec::new();
    let mut bone_weights = Vec::new();
    for _ in 0..num_vertices {
        // Weights are always u8 here: b_use_16bit_bone_weight is gated out
        // before decode_fixed_stride is ever called.
        let (idx, wt) =
            read_vertex_influences(&mut cur, asset_path, num_skel, b_use_16bit_bone_index)?;
        bone_indices.push(idx);
        bone_weights.push(wt);
    }
    Ok((bone_indices, BoneWeights::U8(bone_weights)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::custom_version::{CustomVersion, CustomVersionContainer};
    use crate::asset::export_table::ExportTable;
    use crate::asset::import_table::ImportTable;
    use crate::asset::name_table::NameTable;
    use crate::asset::version::AssetVersion;
    use crate::error::{AssetParseFault, PaksmithError};
    use std::sync::Arc;

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
            BoneWeights::U8(vec![
                [10, 20, 30, 40, 0, 0, 0, 0],
                [50, 60, 70, 80, 0, 0, 0, 0]
            ])
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
        assert_eq!(
            bone_weights,
            BoneWeights::U8(vec![[11, 22, 33, 44, 55, 66, 77, 88]])
        );
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
            BoneWeights::U8(vec![
                [10, 20, 30, 40, 0, 0, 0, 0],
                [50, 60, 70, 80, 0, 0, 0, 0]
            ])
        );
        assert_eq!(cur.position(), buf.len() as u64);
    }

    /// `maxBoneInfluences > 4` → `num_skel == 8` (NOT `max_bone_influences`, NOT
    /// `× width`). The single vertex fills all 8 influence slots with no
    /// zero-pad — the discriminating case for the Task-1 `>4 ? 8 : 4` correction.
    /// Were `num_skel = max_bone_influences as usize` (= 5), the decode would
    /// read 5 indices + 5 weights (10 of 16 bytes), leaving slots 5-7 zero and
    /// mis-consuming the blob.
    #[test]
    fn skin_weights_new_max_influences_over_four_uses_eight() {
        let mut buf = Vec::new();
        new_meta(&mut buf, 0, 5, 3, 1, 0); // maxBI=5, numVerts=1, 8-bit idx
        // newData: 1 vert × num_skel(8) × 2 (idx+wt) = 16 bytes.
        bulk_header(&mut buf, 1, 16);
        buf.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]); // 8 indices
        buf.extend_from_slice(&[11, 22, 33, 44, 55, 66, 77, 88]); // 8 weights
        buf.extend_from_slice(&[0x02u8, 0u8]); // lookup AV-stripped
        buf.extend_from_slice(&0i32.to_le_bytes()); // numLookupVertices = 0

        let mut cur = Cursor::new(buf.as_slice());
        let (bone_indices, bone_weights) =
            read_skin_weight_vertex_buffer(&mut cur, &new_ctx(), "T").unwrap();
        assert_eq!(bone_indices, vec![[1, 2, 3, 4, 5, 6, 7, 8]]);
        assert_eq!(
            bone_weights,
            BoneWeights::U8(vec![[11, 22, 33, 44, 55, 66, 77, 88]])
        );
        assert_eq!(cur.position(), buf.len() as u64);
    }

    /// A `newData` header claiming more bytes than the stream supplies surfaces
    /// as a typed EOF (the incremental `take` + length-check, NOT a 128 MiB
    /// pre-alloc).
    #[test]
    fn skin_weights_new_data_truncated_is_eof() {
        let mut buf = Vec::new();
        new_meta(&mut buf, 0, 4, 3, 2, 0);
        bulk_header(&mut buf, 1, 16); // claims 16 bytes
        buf.extend_from_slice(&[0u8; 8]); // supplies 8

        let err = read_skin_weight_vertex_buffer(&mut Cursor::new(buf.as_slice()), &new_ctx(), "T")
            .unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::UnexpectedEof {
                    field: AssetWireField::SkinWeightNewData
                },
                ..
            }
        ));
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
        assert_eq!(
            bone_weights,
            BoneWeights::U8(vec![[10, 20, 30, 40, 0, 0, 0, 0]])
        );
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

    /// A ctx with `FUE5MainStreamObjectVersion >= IncreasedSkinWeightPrecision(90)`
    /// so `bUse16BitBoneWeight` is read off the wire (UE5 new-format path).
    fn ue5_weight_ctx() -> AssetContext {
        skin_ctx(
            UNLIMITED_BONE_INFLUENCES,
            SPLIT_MODEL_AND_RENDER_DATA,
            INCREASED_SKIN_WEIGHT_PRECISION,
        )
    }

    /// `bUse16BitBoneWeight = 1` (UE5-only) → the decode is omitted entirely:
    /// empty bone data returned, cursor stays fully aligned. The `>> 8` narrowing
    /// is NOT attempted; the path has never had an oracle/fixture to verify it.
    ///
    /// `new_meta` writes `bUse16BitBoneIndex` but NOT `bUse16BitBoneWeight`
    /// (the latter is gated by the UE5 main-stream version present in the ctx).
    /// The wire therefore adds one extra `bool32` for `bUse16BitBoneWeight`
    /// after `new_meta`'s last field.
    #[test]
    fn skin_weights_new_16bit_weight_is_omitted() {
        let mut buf = Vec::new();
        new_meta(&mut buf, 0, 4, 3, 2, 0); // !variable, 8-bit bone index
        // bUse16BitBoneWeight = 1 (the UE5-only field appended after bUse16BitBoneIndex).
        buf.extend_from_slice(&1u32.to_le_bytes());
        // newData blob present (consumed wholesale; decode must not touch it).
        bulk_header(&mut buf, 1, 16);
        buf.extend_from_slice(&[0u8; 16]);
        // Lookup block AV-stripped.
        buf.extend_from_slice(&[0x02u8, 0u8]); // lookup FStripDataFlags (AV-stripped)
        buf.extend_from_slice(&0i32.to_le_bytes()); // numLookupVertices

        let mut cur = Cursor::new(buf.as_slice());
        let (bone_indices, bone_weights) =
            read_skin_weight_vertex_buffer(&mut cur, &ue5_weight_ctx(), "T").unwrap();
        // 16-bit-weight path → decode omitted, empty result.
        assert!(bone_indices.is_empty());
        assert!(bone_weights.is_empty());
        // Full cursor consumption: main cursor must be at end (decode runs on
        // the separate newData Cursor, so skipping it does NOT desync).
        assert_eq!(cur.position(), buf.len() as u64);
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

    /// A `decode_fixed_stride` call with `num_vertices = MAX_VERTICES_PER_LOD`
    /// but an empty `newData` blob surfaces as a typed EOF on the first bone-index
    /// read — NOT as an OOM/panic from over-reserving ~96 MiB. This pins the
    /// Vec::new() contract: growth is bounded by bytes actually consumed, not the
    /// wire count.
    #[test]
    fn decode_fixed_stride_huge_count_empty_data_is_eof() {
        use super::super::vertex_buffers::MAX_VERTICES_PER_LOD;

        let mut buf = Vec::new();
        new_meta(&mut buf, 0, 4, 1, MAX_VERTICES_PER_LOD, 0); // num_vertices = 4 Mi
        // newData bulk header claims 0 bytes → the blob is empty.
        bulk_header(&mut buf, 1, 0);
        // Lookup block (AV-stripped — just the two-byte header + count).
        buf.extend_from_slice(&[0x02u8, 0u8]); // lookup AV-stripped
        buf.extend_from_slice(&0i32.to_le_bytes()); // numLookupVertices

        let err = read_skin_weight_vertex_buffer(&mut Cursor::new(buf.as_slice()), &new_ctx(), "T")
            .unwrap_err();
        // The first per-vertex read inside decode_fixed_stride hits EOF.
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::UnexpectedEof {
                        field: AssetWireField::SkinWeightBoneIndex
                    },
                    ..
                }
            ),
            "expected SkinWeightBoneIndex EOF, got: {err:?}"
        );
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
