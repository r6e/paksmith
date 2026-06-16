//! `FStaticMeshLODResources` reader (Phase 3g render data).
//!
//! Orchestrates the leaf vertex / index / section readers into one LOD of
//! render geometry. Wire-format reference: `docs/formats/mesh/static-mesh.md`
//! §`FStaticMeshLODResources`; oracle `FabianFG/CUE4Parse`
//! `FStaticMeshLODResources.cs` (`ca637ae`).
//!
//! # Scope: the UE 4.23–5.3 new-cooked, inlined layout
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
//! The UE5 `SerializeBuffers` envelope (5.0–5.3, the only UE5 band that reaches
//! here — `FIRST_UNSUPPORTED_UE5_VERSION` rejects ≥ 5.4 at the package level) is
//! byte-identical to UE4.27 except that the tessellation `AdjacencyIndexBuffer`
//! was removed in UE5.0; that is the lone version-gated read below. The UE5.5+
//! `bHasRayTracingGeometry` field and UE5.6+ header changes are above the
//! supported band and are not handled.
//!
//! ## Adjacency-buffer version gate
//!
//! Per the oracle (`FStaticMeshLODResources.SerializeBuffers`), the
//! `AdjacencyIndexBuffer` is present iff `FUE5ReleaseStreamObjectVersion <
//! RemovingTessellation` (tessellation removed in UE5.0) AND `!CDSF_AdjacencyData`.
//! UE4 assets carry no `FUE5ReleaseStreamObjectVersion`, so the gate keeps the
//! pre-UE5 behaviour (buffer present); UE5.0+ cooks stamp it at/above
//! `RemovingTessellation`, so the buffer is absent.

use std::io::Cursor;

use crate::asset::custom_version::{REMOVING_TESSELLATION, UE5_RELEASE_STREAM_OBJECT_VERSION_GUID};
use crate::asset::wire::{STRIP_FLAG_AV_DATA, STRIP_FLAG_EDITOR_DATA, read_strip_data_flags};
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

// `FStaticMeshLODResources.EClassDataStripFlag` `ClassStripFlags` values.
const CDSF_ADJACENCY_DATA: u8 = 1;
const CDSF_REVERSED_INDEX_BUFFER: u8 = 4;
const CDSF_RAY_TRACING_RESOURCES: u8 = 8;

/// Read one `FStaticMeshLODResources` (UE 4.23–4.27 new-cooked layout).
///
/// Wire: outer `FStripDataFlags` → `Sections[]` (`i32` count, capped) →
/// `MaxDeviation` (`f32`) → `bIsLODCookedOut` + `bInlined` (`u32` bools).
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
        crate::asset::wire::read_bool32(cur, asset_path, AssetWireField::MeshLodCookedOut)?;
    let b_inlined =
        crate::asset::wire::read_bool32(cur, asset_path, AssetWireField::MeshLodInlined)?;

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

    let av_stripped = outer_global & STRIP_FLAG_AV_DATA != 0;
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
    // Per-vertex colors come from their own bulk `elementCount`; cross-check it
    // against the vertex count so the SoA invariant (index `i` is vertex `i`
    // across positions / normals / tangents / uvs / colors) actually holds.
    if let Some(colors) = &colors {
        read::ensure_bulk_count(
            asset_path,
            AssetWireField::MeshColorData,
            u32::try_from(positions.len()).unwrap_or(u32::MAX),
            u32::try_from(colors.len()).unwrap_or(u32::MAX),
        )?;
    }

    // Five auxiliary index buffers, read-and-discarded. `ReversedIndexBuffer` /
    // `ReversedDepthOnlyIndexBuffer` are present iff `!CDSF_ReversedIndexBuffer`;
    // `WireframeIndexBuffer` iff editor data is not stripped.
    let reversed_present = inner_class & CDSF_REVERSED_INDEX_BUFFER == 0;
    if reversed_present {
        let _ = read_index_buffer(cur, ctx, asset_path)?; // ReversedIndexBuffer
    }
    let _ = read_index_buffer(cur, ctx, asset_path)?; // DepthOnlyIndexBuffer
    if reversed_present {
        let _ = read_index_buffer(cur, ctx, asset_path)?; // ReversedDepthOnlyIndexBuffer
    }
    if inner_global & STRIP_FLAG_EDITOR_DATA == 0 {
        let _ = read_index_buffer(cur, ctx, asset_path)?; // WireframeIndexBuffer
    }
    // `AdjacencyIndexBuffer` is present iff the engine still serialises
    // tessellation adjacency (`FUE5ReleaseStreamObjectVersion <
    // RemovingTessellation` — true for all UE4, removed in UE5.0) AND the
    // `CDSF_AdjacencyData` class flag is clear. Mirrors CUE4Parse
    // `FStaticMeshLODResources.SerializeBuffers` and the skeletal-mesh gate
    // (`skeletal_mesh.rs`). UE4 assets carry no `FUE5ReleaseStreamObjectVersion`,
    // so `is_none_or` keeps the pre-UE5 behaviour (buffer present). This assumes a
    // UE5 cook always stamps the version (real cooks do — mesh serialization
    // registers it); a crafted UE5 asset that omits it would read a phantom
    // adjacency buffer here, which surfaces as a bounded parse error (the export
    // then degrades to a generic property bag), not a desync hazard.
    let tessellation_present = ctx
        .custom_versions
        .version_for(UE5_RELEASE_STREAM_OBJECT_VERSION_GUID)
        .is_none_or(|v| v < REMOVING_TESSELLATION);
    if tessellation_present && inner_class & CDSF_ADJACENCY_DATA == 0 {
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
    //! Shared byte builders + context builders for the LOD / render-data tests.

    use std::sync::Arc;

    use half::f16;

    use crate::asset::AssetContext;
    use crate::asset::custom_version::{
        CustomVersion, CustomVersionContainer, UE5_RELEASE_STREAM_OBJECT_VERSION_GUID,
    };
    use crate::asset::export_table::ExportTable;
    use crate::asset::import_table::ImportTable;
    use crate::asset::name_table::{FName, NameTable};
    use crate::asset::version::AssetVersion;

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
        // Sections: count 1 + one section (5 i32 + 2 bools, UE4.23 < 4.25).
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
        // FPositionVertexBuffer: stride 12, NumVertices 3, bulk header (12, 3),
        // 3 verts.
        b.extend_from_slice(&12i32.to_le_bytes());
        b.extend_from_slice(&3i32.to_le_bytes());
        b.extend_from_slice(&12i32.to_le_bytes()); // bulk elementSize
        b.extend_from_slice(&3i32.to_le_bytes()); // bulk elementCount
        for v in [[0.0f32, 0.0, 0.0], [1.0, 0.0, 0.0], [0.0, 1.0, 0.0]] {
            for c in v {
                b.extend_from_slice(&c.to_le_bytes());
            }
        }
        // FStaticMeshVertexBuffer: strip(2), NumTexCoords 1, NumVertices 3,
        // bUseFullPrecisionUVs 0, bUseHighPrecisionTangentBasis 0; then the
        // tangent bulk array (header + 3 × 8 B packed normals) and the UV bulk
        // array (header + 3 × 1 f16 UV).
        b.push(0);
        b.push(0);
        b.extend_from_slice(&1i32.to_le_bytes()); // NumTexCoords
        b.extend_from_slice(&3i32.to_le_bytes()); // NumVertices
        b.extend_from_slice(&0i32.to_le_bytes()); // bUseFullPrecisionUVs
        b.extend_from_slice(&0i32.to_le_bytes()); // bUseHighPrecisionTangentBasis
        b.extend_from_slice(&8i32.to_le_bytes()); // tangent bulk itemSize
        b.extend_from_slice(&3i32.to_le_bytes()); // tangent bulk itemCount
        for _ in 0..3 {
            b.extend_from_slice(&0u32.to_le_bytes()); // TangentX
            b.extend_from_slice(&0u32.to_le_bytes()); // TangentZ
        }
        b.extend_from_slice(&4i32.to_le_bytes()); // UV bulk itemSize
        b.extend_from_slice(&3i32.to_le_bytes()); // UV bulk itemCount (3 verts × 1 channel)
        for _ in 0..3 {
            b.extend_from_slice(&f16::from_f32(0.0).to_bits().to_le_bytes());
            b.extend_from_slice(&f16::from_f32(0.0).to_bits().to_le_bytes());
        }
        // FColorVertexBuffer: strip(2), stride 4, 0 verts → None (no bulk array).
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

    /// A complete inlined UE5.0 `FStaticMeshLODResources`: 3 verts
    /// `(0,0,0)/(1,0,0)/(0,1,0)`, a `[0,1,2]` triangle, no per-vertex color. The
    /// UE5 deltas vs [`inlined_lod_ue4_23`]: the section carries the four-bool
    /// layout (collision, shadow, `bForceOpaque` [4.25+], `bVisibleInRayTracing`
    /// [4.27+]; no `bAffectDistanceFieldLighting`, which is 5.1+), the index
    /// buffers use the 4.25+ form (trailing `bShouldExpandTo32Bit`), and the inner
    /// strip strips reversed + ray-tracing buffers (class `12`) while leaving
    /// `CDSF_AdjacencyData` (1) CLEAR — so the adjacency buffer is gated purely by
    /// engine version (removed under `FUE5ReleaseStreamObjectVersion >=
    /// RemovingTessellation`) and **no** adjacency bytes follow.
    #[must_use]
    pub(crate) fn inlined_lod_ue5_0() -> Vec<u8> {
        // 4.25+ index buffer (`is32bit` + `elementSize` + `byteCount` + data +
        // `bShouldExpandTo32Bit`).
        fn idx_425(b: &mut Vec<u8>, indices: &[u16]) {
            b.extend_from_slice(&0i32.to_le_bytes()); // is32bit
            b.extend_from_slice(&1i32.to_le_bytes()); // elementSize
            b.extend_from_slice(&i32::try_from(indices.len() * 2).unwrap().to_le_bytes());
            for i in indices {
                b.extend_from_slice(&i.to_le_bytes());
            }
            b.extend_from_slice(&0i32.to_le_bytes()); // bShouldExpandTo32Bit
        }

        let mut b = Vec::new();
        b.push(0); // outer strip global
        b.push(0); // outer strip class
        b.extend_from_slice(&1i32.to_le_bytes()); // section count
        for v in [0i32, 0, 1, 0, 2] {
            b.extend_from_slice(&v.to_le_bytes()); // material/first/numTri/min/max
        }
        for _ in 0..4 {
            b.extend_from_slice(&1i32.to_le_bytes()); // 4 UE5.0 section bools
        }
        b.extend_from_slice(&0.0f32.to_le_bytes()); // MaxDeviation
        b.extend_from_slice(&0i32.to_le_bytes()); // bIsLODCookedOut
        b.extend_from_slice(&1i32.to_le_bytes()); // bInlined
        b.push(1); // inner strip global: editor stripped
        b.push(12); // inner strip class: reversed (4) | ray-tracing (8); adjacency clear
        // PositionVertexBuffer: stride 12, 3 verts.
        b.extend_from_slice(&12i32.to_le_bytes());
        b.extend_from_slice(&3i32.to_le_bytes());
        b.extend_from_slice(&12i32.to_le_bytes());
        b.extend_from_slice(&3i32.to_le_bytes());
        for v in [[0.0f32, 0.0, 0.0], [1.0, 0.0, 0.0], [0.0, 1.0, 0.0]] {
            for c in v {
                b.extend_from_slice(&c.to_le_bytes());
            }
        }
        // StaticMeshVertexBuffer: strip(0,0), 1 UV, 3 verts, low-precision;
        // tangent bulk (8,3)+24 B, UV bulk (4,3)+12 B (all zero).
        b.push(0);
        b.push(0);
        b.extend_from_slice(&1i32.to_le_bytes()); // NumTexCoords
        b.extend_from_slice(&3i32.to_le_bytes()); // NumVertices
        b.extend_from_slice(&0i32.to_le_bytes()); // bUseFullPrecisionUVs
        b.extend_from_slice(&0i32.to_le_bytes()); // bUseHighPrecisionTangentBasis
        b.extend_from_slice(&8i32.to_le_bytes()); // tangent itemSize
        b.extend_from_slice(&3i32.to_le_bytes()); // tangent itemCount
        b.extend_from_slice(&[0u8; 24]);
        b.extend_from_slice(&4i32.to_le_bytes()); // UV itemSize
        b.extend_from_slice(&3i32.to_le_bytes()); // UV itemCount
        b.extend_from_slice(&[0u8; 12]);
        // ColorVertexBuffer: strip(0,0), stride 4, 0 verts → None.
        b.push(0);
        b.push(0);
        b.extend_from_slice(&4i32.to_le_bytes());
        b.extend_from_slice(&0i32.to_le_bytes());
        // IndexBuffer + DepthOnlyIndexBuffer (reversed/wireframe/ray-tracing/
        // adjacency all absent).
        idx_425(&mut b, &[0, 1, 2]);
        idx_425(&mut b, &[]);
        // areaWeightedSectionSamplers (1) + areaWeightedSampler (1): empty.
        for _ in 0..2 {
            b.extend_from_slice(&0i32.to_le_bytes());
            b.extend_from_slice(&0i32.to_le_bytes());
            b.extend_from_slice(&0.0f32.to_le_bytes());
        }
        b.extend_from_slice(&[0u8; 12]); // FStaticMeshBuffersSize trailer
        b
    }

    /// A UE5 (`file_version_ue5 = 1004`) [`AssetContext`] stamping
    /// `FUE5ReleaseStreamObjectVersion` at `release` — pass
    /// `REMOVING_TESSELLATION` (or any value at/above it) for a UE5.0–5.3 cook
    /// in which the tessellation adjacency buffer has been removed. The name table
    /// carries `"None"` (index 0) so callers that drive the full `UStaticMesh`
    /// read (tagged-property terminator) work.
    #[must_use]
    pub(crate) fn ue5_release_ctx(release: i32) -> AssetContext {
        AssetContext::new(
            Arc::new(NameTable {
                names: vec![FName::new("None")],
            }),
            Arc::new(ImportTable::default()),
            Arc::new(ExportTable::default()),
            AssetVersion {
                legacy_file_version: -8,
                file_version_ue4: 522,
                file_version_ue5: Some(1004),
                file_version_licensee_ue4: 0,
            },
            Arc::new(CustomVersionContainer {
                versions: vec![CustomVersion {
                    guid: UE5_RELEASE_STREAM_OBJECT_VERSION_GUID,
                    version: release,
                }],
            }),
            None,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::test_support::{inlined_lod_ue4_23, inlined_lod_ue5_0, ue5_release_ctx};
    use super::*;
    use crate::asset::property::test_utils::make_ctx_with_version;

    /// UE5 (`FUE5ReleaseStreamObjectVersion >= RemovingTessellation`): the
    /// `AdjacencyIndexBuffer` was removed from the engine, so a LOD whose inner
    /// strip leaves `CDSF_AdjacencyData` clear still carries no adjacency buffer.
    /// The reader must skip it by version rather than read a phantom buffer (which
    /// would desync into the area-weighted samplers).
    #[test]
    fn ue5_lod_skips_adjacency_buffer_by_version() {
        let ctx = ue5_release_ctx(REMOVING_TESSELLATION);
        let bytes = inlined_lod_ue5_0();
        let mut cur = Cursor::new(bytes.as_slice());
        let lod = read_lod(&mut cur, &ctx, "T").unwrap();
        assert_eq!(
            cur.position(),
            bytes.len() as u64,
            "consumed every LOD byte"
        );
        assert_eq!(lod.positions.len(), 3);
        assert_eq!(lod.indices, vec![0, 1, 2]);
    }

    /// The gate is `FUE5ReleaseStreamObjectVersion < RemovingTessellation`: a cook
    /// stamping a version strictly *above* `RemovingTessellation` (the realistic
    /// UE5.0–5.3 case) also omits the adjacency buffer. Pins the comparison
    /// direction — a `>`-mutated gate would read a phantom buffer here and desync.
    #[test]
    fn ue5_lod_skips_adjacency_above_removing_tessellation() {
        let ctx = ue5_release_ctx(REMOVING_TESSELLATION + 1);
        let bytes = inlined_lod_ue5_0();
        let mut cur = Cursor::new(bytes.as_slice());
        let lod = read_lod(&mut cur, &ctx, "T").unwrap();
        assert_eq!(
            cur.position(),
            bytes.len() as u64,
            "consumed every LOD byte"
        );
        assert_eq!(lod.indices, vec![0, 1, 2]);
    }

    /// Pin the derived cap's literal value so the `MAX_VERTICES_PER_LOD * 6`
    /// arithmetic is mutation-covered (a symbolic equality would track the
    /// mutant on both sides).
    #[test]
    fn max_sampler_entries_value() {
        assert_eq!(MAX_SAMPLER_ENTRIES, 25_165_824); // 4 Mi × 6
    }

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
        let bytes = lod_header(STRIP_FLAG_AV_DATA, false, true); // AV stripped → no buffers
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

    /// A `Prob`/`Alias` count over [`MAX_SAMPLER_ENTRIES`] is rejected. The
    /// sampler arrays sit deep in `SerializeBuffers`, so this drives a full
    /// (minimal) inlined LOD whose first area-weighted sampler claims an
    /// oversized `Prob` count. Pins the cap value (stands in for the deferred
    /// accessor) and the `MAX_VERTICES_PER_LOD * 6` arithmetic.
    #[test]
    fn sampler_count_over_cap_is_rejected() {
        let ctx = make_ctx_with_version(517, None);
        // A minimal inlined LOD with 0 sections so the first sampler is read
        // immediately after the (empty) buffers.
        let mut b = Vec::new();
        b.push(0);
        b.push(0); // outer strip
        b.extend_from_slice(&0i32.to_le_bytes()); // 0 sections
        b.extend_from_slice(&0.0f32.to_le_bytes()); // MaxDeviation
        b.extend_from_slice(&0i32.to_le_bytes()); // bIsLODCookedOut
        b.extend_from_slice(&1i32.to_le_bytes()); // bInlined
        b.push(1);
        b.push(5); // inner strip: editor + reversed + adjacency stripped
        b.extend_from_slice(&12i32.to_le_bytes()); // position stride
        b.extend_from_slice(&0i32.to_le_bytes()); // position NumVertices
        b.extend_from_slice(&12i32.to_le_bytes()); // position bulk elementSize
        b.extend_from_slice(&0i32.to_le_bytes()); // position bulk elementCount
        b.push(0);
        b.push(0); // vertex strip
        b.extend_from_slice(&1i32.to_le_bytes()); // NumTexCoords
        b.extend_from_slice(&0i32.to_le_bytes()); // NumVertices
        b.extend_from_slice(&0i32.to_le_bytes()); // fullPrecUV
        b.extend_from_slice(&0i32.to_le_bytes()); // highPrecTan
        b.extend_from_slice(&8i32.to_le_bytes()); // tangent itemSize
        b.extend_from_slice(&0i32.to_le_bytes()); // tangent itemCount
        b.extend_from_slice(&4i32.to_le_bytes()); // uv itemSize
        b.extend_from_slice(&0i32.to_le_bytes()); // uv itemCount
        b.push(0);
        b.push(0); // color strip
        b.extend_from_slice(&4i32.to_le_bytes()); // color stride
        b.extend_from_slice(&0i32.to_le_bytes()); // color NumVertices (→ None)
        b.extend_from_slice(&0i32.to_le_bytes()); // index is32bit
        b.extend_from_slice(&1i32.to_le_bytes()); // index elementSize
        b.extend_from_slice(&0i32.to_le_bytes()); // index byteCount
        b.extend_from_slice(&0i32.to_le_bytes()); // depth-only is32bit
        b.extend_from_slice(&1i32.to_le_bytes()); // depth-only elementSize
        b.extend_from_slice(&0i32.to_le_bytes()); // depth-only byteCount
        // First areaWeightedSectionSampler: Prob count over the cap.
        b.extend_from_slice(&(i32::try_from(MAX_SAMPLER_ENTRIES).unwrap() + 1).to_le_bytes());
        let mut cur = Cursor::new(b.as_slice());
        let err = read_lod(&mut cur, &ctx, "T").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: crate::error::AssetParseFault::BoundsExceeded {
                    field: AssetWireField::MeshLodSampler,
                    limit,
                    ..
                },
                ..
            } if limit == u64::from(MAX_SAMPLER_ENTRIES)
        ));
    }

    /// Append an `FRawStaticIndexBuffer` (UE 4.25+ form: trailing
    /// `bShouldExpandTo32Bit`) holding the given 16-bit indices.
    fn idx_425(b: &mut Vec<u8>, indices: &[u16]) {
        b.extend_from_slice(&0i32.to_le_bytes()); // is32bit
        b.extend_from_slice(&1i32.to_le_bytes()); // elementSize
        b.extend_from_slice(&i32::try_from(indices.len() * 2).unwrap().to_le_bytes()); // byteCount
        for i in indices {
            b.extend_from_slice(&i.to_le_bytes());
        }
        b.extend_from_slice(&0i32.to_le_bytes()); // bShouldExpandTo32Bit
    }

    /// A UE4.27 LOD with **nothing** stripped: all five auxiliary index buffers
    /// are present, the ray-tracing geometry bulk array is present (4.25+), and
    /// the area-weighted samplers are non-empty. Exact consumption pins every
    /// strip-flag gate (in the "present" state the all-stripped fixture can't
    /// reach) plus the sampler payload skips.
    #[test]
    fn unstripped_lod_reads_all_aux_buffers_and_consumes_exactly() {
        let ctx = make_ctx_with_version(522, None); // UE4.27 → is_ue4_25 (ray tracing + expand bool)
        let mut b = Vec::new();
        b.push(0);
        b.push(0); // outer strip
        b.extend_from_slice(&1i32.to_le_bytes()); // 1 section
        for v in [0i32, 0, 1, 0, 0] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        for _ in 0..4 {
            b.extend_from_slice(&1i32.to_le_bytes()); // UE4.27: 4 section bools
        }
        b.extend_from_slice(&0.0f32.to_le_bytes()); // MaxDeviation
        b.extend_from_slice(&0i32.to_le_bytes()); // bIsLODCookedOut
        b.extend_from_slice(&1i32.to_le_bytes()); // bInlined
        // Inner strip: 0,0 → editor NOT stripped, no CDSF bits → every aux buffer present.
        b.push(0);
        b.push(0);
        // Position: 1 vertex.
        b.extend_from_slice(&12i32.to_le_bytes());
        b.extend_from_slice(&1i32.to_le_bytes());
        b.extend_from_slice(&12i32.to_le_bytes());
        b.extend_from_slice(&1i32.to_le_bytes());
        b.extend_from_slice(&[0u8; 12]);
        // Vertex: 1 vertex, 1 UV channel.
        b.push(0);
        b.push(0);
        b.extend_from_slice(&1i32.to_le_bytes()); // NumTexCoords
        b.extend_from_slice(&1i32.to_le_bytes()); // NumVertices
        b.extend_from_slice(&0i32.to_le_bytes()); // fullPrecUV
        b.extend_from_slice(&0i32.to_le_bytes()); // highPrecTan
        b.extend_from_slice(&8i32.to_le_bytes()); // tangent itemSize
        b.extend_from_slice(&1i32.to_le_bytes()); // tangent itemCount
        b.extend_from_slice(&[0u8; 8]);
        b.extend_from_slice(&4i32.to_le_bytes()); // uv itemSize
        b.extend_from_slice(&1i32.to_le_bytes()); // uv itemCount
        b.extend_from_slice(&[0u8; 4]);
        // Color: 1 vertex.
        b.push(0);
        b.push(0);
        b.extend_from_slice(&4i32.to_le_bytes()); // stride
        b.extend_from_slice(&1i32.to_le_bytes()); // NumVertices
        b.extend_from_slice(&4i32.to_le_bytes()); // bulk elementSize
        b.extend_from_slice(&1i32.to_le_bytes()); // bulk elementCount
        b.extend_from_slice(&[1, 2, 3, 4]);
        // IndexBuffer + the five auxiliary index buffers (all present).
        idx_425(&mut b, &[0]); // IndexBuffer
        idx_425(&mut b, &[]); // ReversedIndexBuffer (CDSF_Reversed clear)
        idx_425(&mut b, &[]); // DepthOnlyIndexBuffer
        idx_425(&mut b, &[]); // ReversedDepthOnlyIndexBuffer (CDSF_Reversed clear)
        idx_425(&mut b, &[]); // WireframeIndexBuffer (editor not stripped)
        idx_425(&mut b, &[]); // AdjacencyIndexBuffer (CDSF_Adjacency clear)
        // Ray-tracing geometry bulk array (4.25+, CDSF_RayTracing clear): empty.
        b.extend_from_slice(&0i32.to_le_bytes()); // elementSize
        b.extend_from_slice(&0i32.to_le_bytes()); // elementCount
        // areaWeightedSectionSamplers (1) + areaWeightedSampler (1); first non-empty.
        b.extend_from_slice(&2i32.to_le_bytes()); // Prob count = 2
        b.extend_from_slice(&[0u8; 8]); // 2 × f32
        b.extend_from_slice(&2i32.to_le_bytes()); // Alias count = 2
        b.extend_from_slice(&[0u8; 8]); // 2 × i32
        b.extend_from_slice(&0.0f32.to_le_bytes()); // TotalWeight
        b.extend_from_slice(&0i32.to_le_bytes()); // 2nd sampler Prob count = 0
        b.extend_from_slice(&0i32.to_le_bytes()); // Alias count = 0
        b.extend_from_slice(&0.0f32.to_le_bytes()); // TotalWeight
        b.extend_from_slice(&[0u8; 12]); // FStaticMeshBuffersSize trailer

        let mut cur = Cursor::new(b.as_slice());
        let lod = read_lod(&mut cur, &ctx, "T").unwrap();
        assert_eq!(
            cur.position(),
            b.len() as u64,
            "every aux buffer + ray-tracing + samplers consumed exactly"
        );
        assert_eq!(lod.positions.len(), 1);
        assert_eq!(lod.indices, vec![0]);
        assert_eq!(lod.colors.as_ref().unwrap().len(), 1);
    }

    /// A color buffer whose count disagrees with the position count is rejected
    /// (the SoA invariant: colors must be vertex-aligned).
    #[test]
    fn color_count_mismatch_is_rejected() {
        let ctx = make_ctx_with_version(517, None);
        let mut b = Vec::new();
        b.push(0);
        b.push(0); // outer strip
        b.extend_from_slice(&0i32.to_le_bytes()); // 0 sections
        b.extend_from_slice(&0.0f32.to_le_bytes()); // MaxDeviation
        b.extend_from_slice(&0i32.to_le_bytes()); // bIsLODCookedOut
        b.extend_from_slice(&1i32.to_le_bytes()); // bInlined
        b.push(1);
        b.push(5); // inner strip: editor + reversed + adjacency stripped
        // Position: 1 vertex.
        b.extend_from_slice(&12i32.to_le_bytes());
        b.extend_from_slice(&1i32.to_le_bytes());
        b.extend_from_slice(&12i32.to_le_bytes());
        b.extend_from_slice(&1i32.to_le_bytes());
        b.extend_from_slice(&[0u8; 12]);
        // Vertex: 1 vertex, 1 UV channel.
        b.push(0);
        b.push(0);
        b.extend_from_slice(&1i32.to_le_bytes());
        b.extend_from_slice(&1i32.to_le_bytes());
        b.extend_from_slice(&0i32.to_le_bytes());
        b.extend_from_slice(&0i32.to_le_bytes());
        b.extend_from_slice(&8i32.to_le_bytes());
        b.extend_from_slice(&1i32.to_le_bytes());
        b.extend_from_slice(&[0u8; 8]);
        b.extend_from_slice(&4i32.to_le_bytes());
        b.extend_from_slice(&1i32.to_le_bytes());
        b.extend_from_slice(&[0u8; 4]);
        // Color: 2 vertices — mismatches the single position.
        b.push(0);
        b.push(0);
        b.extend_from_slice(&4i32.to_le_bytes()); // stride
        b.extend_from_slice(&2i32.to_le_bytes()); // NumVertices = 2
        b.extend_from_slice(&4i32.to_le_bytes()); // bulk elementSize
        b.extend_from_slice(&2i32.to_le_bytes()); // bulk elementCount = 2
        b.extend_from_slice(&[0u8; 8]); // 2 colors
        // IndexBuffer (empty) — read before the cross-checks fire.
        b.extend_from_slice(&0i32.to_le_bytes());
        b.extend_from_slice(&1i32.to_le_bytes());
        b.extend_from_slice(&0i32.to_le_bytes());
        let err = read_lod(&mut Cursor::new(b.as_slice()), &ctx, "T").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: crate::error::AssetParseFault::MeshBulkArrayCountMismatch {
                    field: AssetWireField::MeshColorData,
                    expected: 1,
                    observed: 2,
                },
                ..
            }
        ));
    }
}
