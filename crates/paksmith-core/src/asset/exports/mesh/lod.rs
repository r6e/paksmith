//! `FStaticMeshLODResources` reader (Phase 3g render data).
//!
//! Orchestrates the leaf vertex / index / section readers into one LOD of
//! render geometry. Wire-format reference: `docs/formats/mesh/static-mesh.md`
//! §`FStaticMeshLODResources`; oracle `FabianFG/CUE4Parse`
//! `FStaticMeshLODResources.cs` (`ca637ae`).
//!
//! # Scope: the UE 4.23–4.27 new-cooked, inlined layout
//!
//! This reader targets the `StaticMesh.UseNewCookedFormat` (UE 4.23+) layout:
//! an outer `FStripDataFlags`, the section array, `MaxDeviation`,
//! `bIsLODCookedOut`, `bInlined`, then — when the LOD carries buffers
//! (`!AudioVisualStripped && !bIsLODCookedOut`, the cooked-runtime case) and is
//! inlined — `SerializeBuffers` followed by the 12-byte `FStaticMeshBuffersSize`
//! trailer. The legacy (pre-4.23) layout is rejected upstream
//! ([`super::render_data`]); a non-inlined LOD (`bInlined == false`, the
//! editor-only `FByteBulkData` path) surfaces as
//! [`crate::error::PaksmithError::UnsupportedFeature`].
//!
//! ## UNVERIFIED version proxy
//!
//! The `AdjacencyIndexBuffer` is gated in CUE4Parse on
//! `FUE5ReleaseStreamObjectVersion < RemovingTessellation` (tessellation was
//! removed in UE5.0). paksmith restricts this reader to UE4, where that gate is
//! *always* satisfied, so the adjacency buffer is read whenever
//! `!CDSF_AdjacencyData` — no UE5 custom-version mapping is needed. Should the
//! scope ever widen to UE5, this gate must be re-derived against the oracle.

use std::io::Cursor;

use crate::asset::wire::read_strip_data_flags;
use crate::asset::{AssetContext, StaticMeshLod};
use crate::error::{AssetWireField, PaksmithError};

use super::index_buffer::read_index_buffer;
use super::read;
use super::section::read_section;
use super::vertex_buffers::{
    MAX_VERTICES_PER_LOD, read_color_buffer, read_position_buffer, read_static_mesh_vertex_buffer,
};

/// Max sections (draw calls) per LOD (`static-mesh.md` §Caps). A high stock-UE
/// LOD has a handful; 64 is a generous ceiling enforced before the section loop.
pub(crate) const MAX_SECTIONS_PER_LOD: u32 = 64;

/// Max entries in an `FWeightedRandomSampler` `Prob`/`Alias` array. The samplers
/// are sized to the triangle count, so the per-LOD index ceiling bounds them.
pub(crate) const MAX_SAMPLER_ENTRIES: u32 = MAX_VERTICES_PER_LOD * 6;

// NOTE: no `#[cfg(feature = "__test_utils")]` cap accessors — per the
// `texture2d.rs` convention they are deferred until an integration-test
// consumer exists; the in-source tests pin the caps via the
// `BoundsExceeded { limit }` error field.

// `FStripDataFlags` `GlobalStripFlags` bits (`FStripDataFlags.cs`).
const STRIP_EDITOR_DATA: u8 = 1; // bit 0 — `IsEditorDataStripped`
const STRIP_AV_DATA: u8 = 1 << 1; // bit 1 — `IsAudioVisualDataStripped`

// `FStaticMeshLODResources.EClassDataStripFlag` `ClassStripFlags` values.
const CDSF_ADJACENCY_DATA: u8 = 1;
const CDSF_REVERSED_INDEX_BUFFER: u8 = 4;
const CDSF_RAY_TRACING_RESOURCES: u8 = 8;

/// Read one `FStaticMeshLODResources` (UE 4.23–4.27 new-cooked layout).
///
/// Wire: outer `FStripDataFlags` → `Sections[]` (`i32` count, capped) →
/// `MaxDeviation` (`f32`) → `bIsLODCookedOut` + `bInlined` (lax `u32` bools).
/// When the LOD carries buffers (`!AVStripped && !bIsLODCookedOut`): if
/// `bInlined`, `SerializeBuffers` then the 12-byte `FStaticMeshBuffersSize`
/// trailer; otherwise [`PaksmithError::UnsupportedFeature`]. A cooked-out /
/// audio-visual-stripped LOD has no buffers and decodes to empty geometry (just
/// its sections).
///
/// # Errors
/// [`crate::PaksmithError`] from a truncated / corrupt LOD record or an
/// unsupported non-inlined LOD.
pub(crate) fn read_lod(
    cur: &mut Cursor<&[u8]>,
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<StaticMeshLod> {
    let (outer_global, _outer_class) =
        read_strip_data_flags(cur, asset_path, AssetWireField::MeshLodResStripFlags)?;

    let section_count = read::read_capped_count(
        cur,
        asset_path,
        AssetWireField::MeshSectionCount,
        MAX_SECTIONS_PER_LOD,
    )?;
    let mut sections = Vec::with_capacity(section_count as usize);
    for _ in 0..section_count {
        sections.push(read_section(cur, ctx, asset_path)?);
    }

    let _max_deviation = read::read_f32(cur, asset_path, AssetWireField::MeshLodMaxDeviation)?;

    let is_lod_cooked_out =
        read::read_lax_bool32(cur, asset_path, AssetWireField::MeshLodCookedOut)?;
    let b_inlined = read::read_lax_bool32(cur, asset_path, AssetWireField::MeshLodInlined)?;

    let mut lod = StaticMeshLod {
        sections,
        positions: Vec::new(),
        normals: Vec::new(),
        tangents: Vec::new(),
        uvs: [None, None, None, None],
        num_tex_coords: 0,
        colors: None,
        indices: Vec::new(),
    };

    let av_stripped = outer_global & STRIP_AV_DATA != 0;
    if !av_stripped && !is_lod_cooked_out {
        if !b_inlined {
            return Err(PaksmithError::UnsupportedFeature {
                context: "non-inlined FStaticMeshLODResources bulk data (editor-only \
                          FByteBulkData path) — Phase 3g+"
                    .to_string(),
            });
        }
        serialize_buffers(cur, ctx, asset_path, &mut lod)?;
        // FStaticMeshBuffersSize: SerializedBuffersSize + DepthOnlyIBSize +
        // ReversedIBsSize (3 × u32), read-and-discarded.
        read::skip(cur, 12, asset_path, AssetWireField::MeshLodBuffersSize)?;
    }

    Ok(lod)
}

/// `FStaticMeshLODResources::SerializeBuffers` — fills `lod`'s geometry.
///
/// Inner `FStripDataFlags` → `PositionVertexBuffer` → `StaticMeshVertexBuffer`
/// → `ColorVertexBuffer` → `IndexBuffer` → the five read-and-discarded auxiliary
/// index buffers (each `CDSF`/strip-gated) → the UE-4.25+ ray-tracing geometry
/// bulk array (gated `!CDSF_RayTracingResources`) → `Sections.Length + 1`
/// area-weighted `FWeightedRandomSampler`s.
fn serialize_buffers(
    cur: &mut Cursor<&[u8]>,
    ctx: &AssetContext,
    asset_path: &str,
    lod: &mut StaticMeshLod,
) -> crate::Result<()> {
    let (inner_global, inner_class) =
        read_strip_data_flags(cur, asset_path, AssetWireField::MeshLodResStripFlags)?;

    let positions = read_position_buffer(cur, asset_path)?;
    let vertex = read_static_mesh_vertex_buffer(cur, ctx, asset_path)?;
    let colors = read_color_buffer(cur, asset_path)?;
    let indices = read_index_buffer(cur, ctx, asset_path)?;

    if positions.len() != vertex.normals.len() {
        return Err(read::fault(
            asset_path,
            crate::error::AssetParseFault::MeshVertexBufferLengthMismatch {
                positions: u32::try_from(positions.len()).unwrap_or(u32::MAX),
                tangents: u32::try_from(vertex.normals.len()).unwrap_or(u32::MAX),
            },
        ));
    }

    // Five auxiliary index buffers, read-and-discarded. `ReversedIndexBuffer` /
    // `ReversedDepthOnlyIndexBuffer` are present iff `!CDSF_ReversedIndexBuffer`;
    // `WireframeIndexBuffer` iff editor data is not stripped; `AdjacencyIndexBuffer`
    // iff `!CDSF_AdjacencyData` (UE4: always past the tessellation-removal gate).
    let reversed_present = inner_class & CDSF_REVERSED_INDEX_BUFFER == 0;
    if reversed_present {
        let _ = read_index_buffer(cur, ctx, asset_path)?; // ReversedIndexBuffer
    }
    let _ = read_index_buffer(cur, ctx, asset_path)?; // DepthOnlyIndexBuffer
    if reversed_present {
        let _ = read_index_buffer(cur, ctx, asset_path)?; // ReversedDepthOnlyIndexBuffer
    }
    if inner_global & STRIP_EDITOR_DATA == 0 {
        let _ = read_index_buffer(cur, ctx, asset_path)?; // WireframeIndexBuffer
    }
    if inner_class & CDSF_ADJACENCY_DATA == 0 {
        let _ = read_index_buffer(cur, ctx, asset_path)?; // AdjacencyIndexBuffer
    }

    // UE 4.25+ (`StaticMesh.HasRayTracingGeometry`): the ray-tracing geometry
    // bulk array, gated `!CDSF_RayTracingResources`. Read-and-discarded.
    if ctx.version.is_ue4_25_or_later() && inner_class & CDSF_RAY_TRACING_RESOURCES == 0 {
        read::skip_bulk_array(cur, asset_path, AssetWireField::MeshRayTracingGeometry)?;
    }

    // areaWeightedSectionSamplers (one per section) + areaWeightedSampler (one).
    for _ in 0..=lod.sections.len() {
        read_weighted_random_sampler(cur, asset_path)?;
    }

    lod.positions = positions;
    lod.normals = vertex.normals;
    lod.tangents = vertex.tangents;
    lod.uvs = vertex.uvs;
    lod.num_tex_coords = vertex.num_tex_coords;
    lod.colors = colors;
    lod.indices = indices;
    Ok(())
}

/// Consume one `FWeightedRandomSampler` — the `Prob` (`float[]`), `Alias`
/// (`int[]`), and `TotalWeight` (`f32`) fields, in order. The sampler is a
/// sampling-acceleration structure, not geometry, so its payload is
/// read-and-discarded (counts capped, bytes skipped) rather than materialized.
fn read_weighted_random_sampler(cur: &mut Cursor<&[u8]>, asset_path: &str) -> crate::Result<()> {
    let field = AssetWireField::MeshLodSampler;
    let prob = read::read_capped_count(cur, asset_path, field, MAX_SAMPLER_ENTRIES)?;
    read::skip(cur, u64::from(prob) * 4, asset_path, field)?; // Prob: f32[]
    let alias = read::read_capped_count(cur, asset_path, field, MAX_SAMPLER_ENTRIES)?;
    read::skip(cur, u64::from(alias) * 4, asset_path, field)?; // Alias: i32[]
    let _total_weight = read::read_f32(cur, asset_path, field)?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Shared byte builders for the LOD / render-data tests.

    use half::f16;

    /// A complete inlined `FStaticMeshLODResources` (UE 4.23, object version
    /// `517` — the first new-cooked version; `< 4.25`, so no ray-tracing block
    /// and 2-bool sections): one section, three vertices
    /// `(0,0,0)`/`(1,0,0)`/`(0,1,0)`, a `[0,1,2]` triangle, no per-vertex color.
    /// The inner strip flags strip editor data + the reversed + adjacency
    /// buffers, so only `IndexBuffer` and `DepthOnlyIndexBuffer` follow the four
    /// geometry buffers; two empty area-weighted samplers and the 12-byte
    /// buffers-size trailer close it.
    #[must_use]
    pub(crate) fn inlined_lod_ue4_23() -> Vec<u8> {
        let mut b = Vec::new();
        // Outer FStripDataFlags (not AV-stripped).
        b.push(0);
        b.push(0);
        // Sections: count 1 + one section (5 i32 + 2 lax bools, UE4.23 < 4.25).
        b.extend_from_slice(&1i32.to_le_bytes());
        for v in [0i32, 0, 1, 0, 2] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        for _ in 0..2 {
            b.extend_from_slice(&1i32.to_le_bytes()); // bEnableCollision, bCastShadow
        }
        b.extend_from_slice(&0.0f32.to_le_bytes()); // MaxDeviation
        b.extend_from_slice(&0i32.to_le_bytes()); // bIsLODCookedOut = 0
        b.extend_from_slice(&1i32.to_le_bytes()); // bInlined = 1

        // SerializeBuffers. Inner strip: editor stripped (bit0) + CDSF
        // ReversedIndexBuffer (4) | AdjacencyData (1) = 5.
        b.push(1);
        b.push(5);
        // FPositionVertexBuffer: stride 12, 3 verts.
        b.extend_from_slice(&12i32.to_le_bytes());
        b.extend_from_slice(&3i32.to_le_bytes());
        for v in [[0.0f32, 0.0, 0.0], [1.0, 0.0, 0.0], [0.0, 1.0, 0.0]] {
            for c in v {
                b.extend_from_slice(&c.to_le_bytes());
            }
        }
        // FStaticMeshVertexBuffer: strip(2), NumTexCoords 1, NumVertices 3,
        // bUseFullPrecisionUVs 0, bUseHighPrecisionTangentBasis 0, then per-vertex
        // 2 packed normals (8 B) + 1 f16 UV (4 B).
        b.push(0);
        b.push(0);
        b.extend_from_slice(&1i32.to_le_bytes());
        b.extend_from_slice(&3i32.to_le_bytes());
        b.extend_from_slice(&0i32.to_le_bytes());
        b.extend_from_slice(&0i32.to_le_bytes());
        for _ in 0..3 {
            b.extend_from_slice(&0u32.to_le_bytes()); // TangentX
            b.extend_from_slice(&0u32.to_le_bytes()); // TangentZ
            b.extend_from_slice(&f16::from_f32(0.0).to_bits().to_le_bytes());
            b.extend_from_slice(&f16::from_f32(0.0).to_bits().to_le_bytes());
        }
        // FColorVertexBuffer: strip(2), stride 4, 0 verts → None.
        b.push(0);
        b.push(0);
        b.extend_from_slice(&4i32.to_le_bytes());
        b.extend_from_slice(&0i32.to_le_bytes());
        // IndexBuffer: 16-bit, byteCount 6, [0,1,2].
        b.extend_from_slice(&0i32.to_le_bytes()); // is32bit = 0
        b.extend_from_slice(&1i32.to_le_bytes()); // elementSize
        b.extend_from_slice(&6i32.to_le_bytes()); // byteCount
        for i in [0u16, 1, 2] {
            b.extend_from_slice(&i.to_le_bytes());
        }
        // DepthOnlyIndexBuffer: empty (reversed / wireframe / adjacency stripped).
        b.extend_from_slice(&0i32.to_le_bytes());
        b.extend_from_slice(&1i32.to_le_bytes());
        b.extend_from_slice(&0i32.to_le_bytes());
        // areaWeightedSectionSamplers (1) + areaWeightedSampler (1): empty.
        for _ in 0..2 {
            b.extend_from_slice(&0i32.to_le_bytes()); // Prob count
            b.extend_from_slice(&0i32.to_le_bytes()); // Alias count
            b.extend_from_slice(&0.0f32.to_le_bytes()); // TotalWeight
        }
        // FStaticMeshBuffersSize trailer (3 × u32).
        b.extend_from_slice(&[0u8; 12]);
        b
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::test_support::inlined_lod_ue4_23;
    use super::*;
    use crate::asset::property::test_utils::make_ctx_with_version;

    #[test]
    fn inlined_lod_decodes_and_consumes_exactly() {
        let ctx = make_ctx_with_version(517, None);
        let bytes = inlined_lod_ue4_23();
        let mut cur = Cursor::new(bytes.as_slice());
        let lod = read_lod(&mut cur, &ctx, "T").unwrap();
        // Exact consumption guards against a width / conditional / count desync.
        assert_eq!(
            cur.position(),
            bytes.len() as u64,
            "consumed every LOD byte"
        );
        assert_eq!(lod.sections.len(), 1);
        assert_eq!(lod.sections[0].num_triangles, 1);
        assert_eq!(lod.positions.len(), 3);
        assert_eq!(lod.normals.len(), 3);
        assert_eq!(lod.tangents.len(), 3);
        assert_eq!(lod.num_tex_coords, 1);
        assert!(lod.colors.is_none());
        assert_eq!(lod.indices, vec![0, 1, 2]);
        assert!((lod.positions[1].x - 1.0).abs() < 1e-6);
        assert!((lod.positions[2].y - 1.0).abs() < 1e-6);
    }

    /// Minimal LOD header (no buffers): outer strip + section count + MaxDeviation
    /// + the two cooked/inlined bools, parameterized.
    fn lod_header(global_strip: u8, cooked_out: bool, inlined: bool) -> Vec<u8> {
        let mut b = Vec::new();
        b.push(global_strip);
        b.push(0);
        b.extend_from_slice(&0i32.to_le_bytes()); // 0 sections
        b.extend_from_slice(&0.0f32.to_le_bytes()); // MaxDeviation
        b.extend_from_slice(&i32::from(cooked_out).to_le_bytes());
        b.extend_from_slice(&i32::from(inlined).to_le_bytes());
        b
    }

    #[test]
    fn cooked_out_lod_has_no_buffers() {
        let ctx = make_ctx_with_version(517, None);
        let bytes = lod_header(0, true, true); // bIsLODCookedOut = 1 → no buffers
        let mut cur = Cursor::new(bytes.as_slice());
        let lod = read_lod(&mut cur, &ctx, "T").unwrap();
        assert_eq!(cur.position(), bytes.len() as u64);
        assert!(lod.positions.is_empty() && lod.indices.is_empty());
    }

    #[test]
    fn av_stripped_lod_has_no_buffers() {
        let ctx = make_ctx_with_version(517, None);
        let bytes = lod_header(STRIP_AV_DATA, false, true); // AV stripped → no buffers
        let mut cur = Cursor::new(bytes.as_slice());
        let lod = read_lod(&mut cur, &ctx, "T").unwrap();
        assert_eq!(cur.position(), bytes.len() as u64);
        assert!(lod.positions.is_empty());
    }

    #[test]
    fn non_inlined_lod_is_unsupported() {
        let ctx = make_ctx_with_version(517, None);
        let bytes = lod_header(0, false, false); // bInlined = 0 → unsupported bulk path
        let mut cur = Cursor::new(bytes.as_slice());
        let err = read_lod(&mut cur, &ctx, "T").unwrap_err();
        assert!(matches!(err, PaksmithError::UnsupportedFeature { .. }));
    }

    #[test]
    fn section_count_over_cap_is_rejected() {
        let ctx = make_ctx_with_version(517, None);
        let mut bytes = Vec::new();
        bytes.push(0);
        bytes.push(0);
        bytes.extend_from_slice(&(i32::try_from(MAX_SECTIONS_PER_LOD).unwrap() + 1).to_le_bytes());
        let mut cur = Cursor::new(bytes.as_slice());
        let err = read_lod(&mut cur, &ctx, "T").unwrap_err();
        // Pin both the field and the live cap value (the `limit`) — this stands
        // in for the deferred `__test_utils` accessor.
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: crate::error::AssetParseFault::BoundsExceeded {
                    field: AssetWireField::MeshSectionCount,
                    limit,
                    ..
                },
                ..
            } if limit == u64::from(MAX_SECTIONS_PER_LOD)
        ));
    }
}
