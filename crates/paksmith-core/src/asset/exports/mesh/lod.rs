//! `FStaticMeshLODResources` reader (Phase 3g render data).
//!
//! Orchestrates the leaf vertex / index / section readers into one LOD of
//! render geometry. Wire-format reference: `docs/formats/mesh/static-mesh.md`
//! §`FStaticMeshLODResources`; oracle `FabianFG/CUE4Parse`
//! `FStaticMeshLODResources.cs` (`ca637ae`).
//!
//! # Scope: the UE 4.23–5.3 new-cooked layout (inlined + non-inlined LODs)
//!
//! This reader targets the `StaticMesh.UseNewCookedFormat` (UE 4.23+) layout:
//! an outer `FStripDataFlags`, the section array, `MaxDeviation`,
//! `bIsLODCookedOut`, `bInlined`, then — when the LOD carries buffers
//! (`!AudioVisualStripped && !bIsLODCookedOut`, the cooked-runtime case):
//!
//! - **inlined** (`bInlined == true`): `SerializeBuffers` in-stream.
//! - **non-inlined** (`bInlined == false`, the streamed `.ubulk` path): an
//!   `FByteBulkData` header whose payload is resolved via
//!   [`AssetContext::bulk_resolver`] and decoded with the same `SerializeBuffers`,
//!   followed by the in-stream availability-info trailer. When no resolver is
//!   present (header-only / in-memory parse) or the record is unresolvable
//!   (compressed bulk, missing companion), it degrades to
//!   [`crate::error::PaksmithError::UnsupportedFeature`] (→ generic property bag).
//!
//! Both paths then consume the shared 12-byte `FStaticMeshBuffersSize` trailer.
//! The pre-4.23 legacy layout is decoded separately by [`read_lod_legacy`]
//! (dispatched from [`super::render_data`]) — a deliberately UNVERIFIED path (#561).
//!
//! The UE5 `SerializeBuffers` envelope (5.0–5.4) is byte-identical to UE4.27
//! except that the tessellation `AdjacencyIndexBuffer` was removed in UE5.0.
//! UE 5.5 (object 1013, #643) inserts a serialized `bHasRayTracingGeometry`
//! bool before the buffers — consumed via a version-gated 4-byte skip in
//! [`read_lod`]. UE5.6+ header changes are above the supported band (ceiling
//! 1014) and are not handled.
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
const CDSF_MIN_LOD_DATA: u8 = 2;
const CDSF_REVERSED_INDEX_BUFFER: u8 = 4;
const CDSF_RAY_TRACING_RESOURCES: u8 = 8;

/// Read one `FStaticMeshLODResources` (UE 4.23–4.27 new-cooked layout).
///
/// Wire: outer `FStripDataFlags` → `Sections[]` (`i32` count, capped) →
/// `MaxDeviation` (`f32`) → `bIsLODCookedOut` + `bInlined` (`u32` bools).
/// When the LOD carries buffers (`!AVStripped && !bIsLODCookedOut`): if
/// `bInlined`, `SerializeBuffers` in-stream; otherwise [`read_non_inlined_lod`]
/// resolves the streamed `.ubulk` geometry (degrading to
/// [`PaksmithError::UnsupportedFeature`] when unresolvable). Either way the
/// 12-byte `FStaticMeshBuffersSize` trailer closes the LOD. A cooked-out /
/// audio-visual-stripped LOD has no buffers and decodes to empty geometry (just
/// its sections).
///
/// # Errors
/// [`crate::PaksmithError`] from a truncated / corrupt LOD record, or
/// [`PaksmithError::UnsupportedFeature`] for an unresolvable non-inlined LOD.
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

    let mut lod = StaticMeshLod::with_sections(sections);

    let av_stripped = outer_global & STRIP_FLAG_AV_DATA != 0;
    if !av_stripped && !is_lod_cooked_out {
        // UE 5.5: a serialized `bHasRayTracingGeometry` bool (4 bytes)
        // precedes the buffers (CUE4Parse FStaticMeshLODResources.cs,
        // `Ar.Game >= GAME_UE5_5`; no custom-version signal exists —
        // the versioned-package proxy is object version 1013). #643.
        if ctx
            .version
            .ue5_at_least(crate::asset::version::VER_UE5_ASSETREGISTRY_PACKAGEBUILDDEPENDENCIES)
        {
            read::skip(cur, 4, asset_path, AssetWireField::MeshLodInlined)?;
        }
        if b_inlined {
            serialize_buffers(cur, ctx, asset_path, &mut lod)?;
        } else {
            read_non_inlined_lod(cur, ctx, asset_path, &mut lod)?;
        }
        // FStaticMeshBuffersSize: SerializedBuffersSize + DepthOnlyIBSize +
        // ReversedIBsSize (3 × u32), read-and-discarded. Shared by both paths.
        read::skip(cur, 12, asset_path, AssetWireField::MeshLodBuffersSize)?;
    }

    Ok(lod)
}

/// Read a non-inlined (streamed) `FStaticMeshLODResources` LOD: the geometry
/// buffers live out-of-line in a companion `.ubulk`, referenced by an
/// `FByteBulkData` header. Resolves the payload via `ctx.bulk_resolver` and
/// decodes it with the same [`serialize_buffers`] used for inlined LODs, then
/// consumes the in-stream availability-info trailer from the main cursor.
///
/// Degrades to [`PaksmithError::UnsupportedFeature`] (→ generic property bag) when
/// no resolver is present (header-only / in-memory parse) or the payload is
/// unresolvable (compressed bulk, missing companion file) — never an
/// empty-geometry typed mesh.
///
/// Wire order (oracle `FStaticMeshLODResources.cs`, `!bInlined` branch, UE4.23–4.27
/// / UE5.0–5.3 generic path): the `FByteBulkData` header, then — when
/// `element_count > 0` — the resolved `SerializeBuffers` blob (decoded from the
/// `.ubulk` bytes, NOT the main cursor), then the availability-info trailer
/// consumed **unconditionally** from the main cursor (present even when
/// `element_count == 0`): `DepthOnlyNumTriangles + Packed` (8) + the
/// buffer-count/stride stats (72) + — while the engine still serialises
/// tessellation adjacency — the `AdjacencyIndexBuffer` stats (8). The shared
/// 12-byte `FStaticMeshBuffersSize` follows in the caller.
fn read_non_inlined_lod(
    cur: &mut Cursor<&[u8]>,
    ctx: &AssetContext,
    asset_path: &str,
    lod: &mut StaticMeshLod,
) -> crate::Result<()> {
    let Some(resolver) = ctx.bulk_resolver.as_ref() else {
        return Err(PaksmithError::UnsupportedFeature {
            context: "non-inlined FStaticMeshLODResources bulk data without a bulk \
                      resolver (header-only parse)"
                .to_string(),
        });
    };

    let bulk = crate::asset::bulk_data::FByteBulkData::read_from_ctx(cur, ctx, asset_path)?;
    if bulk.element_count > 0 {
        let payload = resolver.resolve(&bulk, asset_path)?;
        let mut buf_cur = Cursor::new(payload.bytes.as_slice());
        serialize_buffers(&mut buf_cur, ctx, asset_path, lod)?;
    }

    // Availability-info trailer, consumed unconditionally from the MAIN cursor
    // (present even when element_count == 0): DepthOnlyNumTriangles + Packed (8) +
    // the buffer-count/stride stats (4*4 + 2*4 + 2*4 + 5*2*4 = 72).
    read::skip(
        cur,
        8 + 72,
        asset_path,
        AssetWireField::MeshLodAvailabilityInfo,
    )?;
    // The AdjacencyIndexBuffer stats are version-gated ONLY (`tessellation_present`
    // — `FUE5ReleaseStreamObjectVersion < RemovingTessellation`). Unlike the
    // inlined adjacency buffer in `serialize_buffers`, there is NO
    // `CDSF_AdjacencyData` strip-flag check here: the inner `FStripDataFlags` live
    // in the `.ubulk` payload, not the main stream, and these are fixed-size
    // availability stats rather than the conditional buffer itself.
    if tessellation_present(ctx) {
        read::skip(cur, 8, asset_path, AssetWireField::MeshLodAvailabilityInfo)?;
    }
    Ok(())
}

/// Whether the engine still serialises tessellation adjacency data —
/// `FUE5ReleaseStreamObjectVersion < RemovingTessellation` (true for all UE4,
/// removed in UE5.0). A UE4 asset carries no `FUE5ReleaseStreamObjectVersion`, so
/// `is_none_or` keeps the pre-UE5 behaviour (adjacency present). Gates both the
/// inlined `AdjacencyIndexBuffer` in [`serialize_buffers`] and the non-inlined
/// availability-info adjacency stats in [`read_non_inlined_lod`].
fn tessellation_present(ctx: &AssetContext) -> bool {
    ctx.custom_versions
        .version_for(UE5_RELEASE_STREAM_OBJECT_VERSION_GUID)
        .is_none_or(|v| v < REMOVING_TESSELLATION)
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
    if tessellation_present(ctx) && inner_class & CDSF_ADJACENCY_DATA == 0 {
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

/// Read a pre-UE4.23 legacy `FStaticMeshLODResources` (the
/// `!StaticMesh.UseNewCookedFormat` path). Differs from the new-cooked [`read_lod`]:
/// the geometry follows `MaxDeviation` directly with NO `bIsLODCookedOut` /
/// `bInlined` flags and NO `FStaticMeshBuffersSize` trailer, and the buffers use
/// [`serialize_buffers_legacy`].
///
/// **UNVERIFIED contract.** paksmith has no real pre-4.23 cooked fixture, so this
/// path is validated only against synthetic fixtures built from the CUE4Parse
/// oracle reading (`FStaticMeshLODResources.SerializeBuffersLegacy`); it cannot be
/// cross-checked against ground truth (see #561 — built deliberately UNVERIFIED).
///
/// **Reachable version band.** The legacy branch fires for `!is_ue4_23_or_later()`,
/// i.e. object version `< 517`. paksmith's object-version proxy collapses UE4
/// engine minors, so object `517` already means `{4.21, 4.22, 4.23}` → those route
/// to the new-cooked reader. Thus this path is reached only for object `≤ 516`
/// (UE4 `≤ 4.20`, down to paksmith's 504 floor). It is **tested at object 516**
/// (~UE4.20). Caveats:
/// - UE4.21/4.22 use the legacy wire format in-engine but share object 517 with
///   4.23, so paksmith mis-routes them to the new reader — distinguishing them
///   needs engine-version detection (a later phase), not this reader.
/// - The whole reachable band (object ≤516, UE4 ≤4.20 — INCLUDING the tested 516)
///   carries an unverified distance-field edge: the oracle only consults the DF
///   block's class-strip bit for `Game >= UE4_21`, whereas the shared
///   `read_distance_field_block` applies it unconditionally — so an asset with that
///   bit set would desync. The fixture sets it to 0, so this path is un-exercised.
/// - The lower sub-band (object 504–515, UE4 ≤4.19) has two more unverified edges:
///   pre-4.17 has no samplers, and pre-4.20 screen sizes are plain `f32` (not
///   `FPerPlatformFloat`). None of these is gated (no clean object-version proxy for
///   the boundaries), so each may desync.
///
/// Two oracle gates simplify out below paksmith's 504 version floor: the inline
/// `FDistanceFieldVolumeData` window (`< RENAME_CROUCHMOVESCHARACTERDOWN` = 394)
/// and the reversed-index version fork (`>= SOUND_CONCURRENCY_PACKAGE` = 489) are
/// both unreachable, so the distance field is always the render-data block and the
/// auxiliary-index fork is purely strip-flag-driven.
pub(crate) fn read_lod_legacy(
    cur: &mut Cursor<&[u8]>,
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<StaticMeshLod> {
    let (outer_global, outer_class) =
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

    let mut lod = StaticMeshLod::with_sections(sections);

    // Buffers present unless audio-visual data or min-LOD class data is stripped
    // (oracle `!IsAudioVisualDataStripped() && !CDSF_MinLodData`).
    let av_stripped = outer_global & STRIP_FLAG_AV_DATA != 0;
    let min_lod_stripped = outer_class & CDSF_MIN_LOD_DATA != 0;
    if !av_stripped && !min_lod_stripped {
        serialize_buffers_legacy(cur, ctx, asset_path, &mut lod, outer_global, outer_class)?;
    }

    Ok(lod)
}

/// `FStaticMeshLODResources::SerializeBuffersLegacy` — the pre-UE4.23 geometry
/// layout. Unlike [`serialize_buffers`] there are NO inner `FStripDataFlags` (the
/// outer LOD strip `global`/`class` gates the auxiliary buffers) and NO ray-tracing
/// block. Order: `PositionVertexBuffer` → `StaticMeshVertexBuffer` →
/// `ColorVertexBuffer` → `IndexBuffer`, then the auxiliary index buffers and the
/// UE4.17+ samplers. See [`read_lod_legacy`] for the UNVERIFIED contract.
fn serialize_buffers_legacy(
    cur: &mut Cursor<&[u8]>,
    ctx: &AssetContext,
    asset_path: &str,
    lod: &mut StaticMeshLod,
    global: u8,
    class: u8,
) -> crate::Result<()> {
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
    if let Some(colors) = &colors {
        read::ensure_bulk_count(
            asset_path,
            AssetWireField::MeshColorData,
            u32::try_from(positions.len()).unwrap_or(u32::MAX),
            u32::try_from(colors.len()).unwrap_or(u32::MAX),
        )?;
    }

    // Auxiliary index buffers, read-and-discarded. The legacy reversed-index fork:
    // `!CDSF_ReversedIndexBuffer` → ReversedIndexBuffer + DepthOnlyIndexBuffer +
    // ReversedDepthOnlyIndexBuffer; otherwise just DepthOnlyIndexBuffer. (The oracle's
    // `>= SOUND_CONCURRENCY_PACKAGE` version guard on this fork is always true above
    // paksmith's 504 floor, so it reduces to the strip-flag check.)
    if class & CDSF_REVERSED_INDEX_BUFFER == 0 {
        let _ = read_index_buffer(cur, ctx, asset_path)?; // ReversedIndexBuffer
        let _ = read_index_buffer(cur, ctx, asset_path)?; // DepthOnlyIndexBuffer
        let _ = read_index_buffer(cur, ctx, asset_path)?; // ReversedDepthOnlyIndexBuffer
    } else {
        let _ = read_index_buffer(cur, ctx, asset_path)?; // DepthOnlyIndexBuffer
    }
    if global & STRIP_FLAG_EDITOR_DATA == 0 {
        let _ = read_index_buffer(cur, ctx, asset_path)?; // WireframeIndexBuffer
    }
    // Adjacency is gated purely on `!CDSF_AdjacencyData` — legacy is always pre-UE5,
    // so tessellation adjacency is still serialised.
    if class & CDSF_ADJACENCY_DATA == 0 {
        let _ = read_index_buffer(cur, ctx, asset_path)?; // AdjacencyIndexBuffer
    }

    // areaWeightedSectionSamplers (one per section) + areaWeightedSampler (one),
    // present for UE4.17+ (oracle `Ar.Game > GAME_UE4_16`). paksmith has no clean
    // object-version proxy for the 4.17 boundary, so these are read unconditionally
    // — correct for the object ≤516 (~UE4.20) tested band; a UE4.14–4.16 asset (no
    // samplers) would desync here (part of the UNVERIFIED contract in `read_lod_legacy`).
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
        push_lod_header_ue4_23(&mut b, true);
        push_serialize_buffers_blob_ue4_23(&mut b);
        // FStaticMeshBuffersSize trailer (3 × u32).
        b.extend_from_slice(&[0u8; 12]);
        b
    }

    /// The leading `FStaticMeshLODResources` fields before the geometry: outer
    /// `FStripDataFlags` (not AV-stripped), one section (5 i32 + 2 bools, UE4.23
    /// `< 4.25`), `MaxDeviation`, `bIsLODCookedOut = 0`, and the given `bInlined`.
    fn push_lod_header_ue4_23(b: &mut Vec<u8>, b_inlined: bool) {
        b.push(0); // outer FStripDataFlags global
        b.push(0); // outer FStripDataFlags class
        b.extend_from_slice(&1i32.to_le_bytes()); // section count
        for v in [0i32, 0, 1, 0, 2] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        for _ in 0..2 {
            b.extend_from_slice(&1i32.to_le_bytes()); // bEnableCollision, bCastShadow
        }
        b.extend_from_slice(&0.0f32.to_le_bytes()); // MaxDeviation
        b.extend_from_slice(&0i32.to_le_bytes()); // bIsLODCookedOut = 0
        b.extend_from_slice(&i32::from(b_inlined).to_le_bytes()); // bInlined
    }

    /// The UE5.0 variant of [`push_lod_header_ue4_23`]: the section carries the
    /// four-bool layout (collision, shadow, `bForceOpaque` [4.25+],
    /// `bVisibleInRayTracing` [4.27+]) instead of two bools.
    fn push_lod_header_ue5_0(b: &mut Vec<u8>, b_inlined: bool) {
        b.push(0); // outer FStripDataFlags global
        b.push(0); // outer FStripDataFlags class
        b.extend_from_slice(&1i32.to_le_bytes()); // section count
        for v in [0i32, 0, 1, 0, 2] {
            b.extend_from_slice(&v.to_le_bytes()); // material/first/numTri/min/max
        }
        for _ in 0..4 {
            b.extend_from_slice(&1i32.to_le_bytes()); // 4 UE5.0 section bools
        }
        b.extend_from_slice(&0.0f32.to_le_bytes()); // MaxDeviation
        b.extend_from_slice(&0i32.to_le_bytes()); // bIsLODCookedOut = 0
        b.extend_from_slice(&i32::from(b_inlined).to_le_bytes()); // bInlined
    }

    /// The `FStaticMeshLODResources::SerializeBuffers` geometry blob (UE4.23):
    /// 3 verts `(0,0,0)/(1,0,0)/(0,1,0)`, a `[0,1,2]` triangle, no per-vertex
    /// color. Shared by [`inlined_lod_ue4_23`] (where it follows `bInlined`
    /// in-stream) and the non-inlined LOD tests (where it is the resolved
    /// `.ubulk` payload). The inner strip flags strip editor data plus the
    /// reversed and adjacency buffers, so only `IndexBuffer` and
    /// `DepthOnlyIndexBuffer` follow the four geometry buffers; two empty
    /// area-weighted samplers close it.
    pub(crate) fn push_serialize_buffers_blob_ue4_23(b: &mut Vec<u8>) {
        // Inner strip: editor stripped (bit0) + CDSF ReversedIndexBuffer (4) |
        // AdjacencyData (1) = 5.
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
    }

    /// The standalone UE4.23 `SerializeBuffers` blob — used as the resolved
    /// `.ubulk` payload of a non-inlined LOD.
    #[cfg(feature = "__test_utils")]
    #[must_use]
    pub(crate) fn serialize_buffers_blob_ue4_23() -> Vec<u8> {
        let mut b = Vec::new();
        push_serialize_buffers_blob_ue4_23(&mut b);
        b
    }

    /// A pre-UE4.23 legacy `FStaticMeshLODResources` (object 516, ~UE4.20, the
    /// `!StaticMesh.UseNewCookedFormat` path): outer `FStripDataFlags`, the section
    /// array, `MaxDeviation`, then `SerializeBuffersLegacy` — with NO inner strip
    /// flags, NO `bIsLODCookedOut`/`bInlined`, and NO buffers-size trailer. The
    /// buffer body reuses the new-format `SerializeBuffers` blob minus its leading
    /// 2-byte inner `FStripDataFlags`: with the outer strip `(0x01 editor-stripped,
    /// class 5 = reversed|adjacency)` the legacy reader consumes the identical
    /// `Index` + `DepthOnly` + 2 samplers sequence the blob carries.
    #[cfg(feature = "__test_utils")]
    #[must_use]
    pub(crate) fn legacy_lod_ue4_20() -> Vec<u8> {
        let mut b = Vec::new();
        b.push(0x01); // outer FStripDataFlags global = STRIP_FLAG_EDITOR_DATA (no wireframe)
        b.push(5); // class = CDSF_REVERSED_INDEX_BUFFER (4) | CDSF_ADJACENCY_DATA (1)
        b.extend_from_slice(&1i32.to_le_bytes()); // section count
        for v in [0i32, 0, 1, 0, 2] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        for _ in 0..2 {
            b.extend_from_slice(&1i32.to_le_bytes()); // 2 section bools (< 4.25)
        }
        b.extend_from_slice(&0.0f32.to_le_bytes()); // MaxDeviation
        // SerializeBuffersLegacy body = the SerializeBuffers blob without its leading
        // 2-byte inner FStripDataFlags (legacy uses the outer strip above).
        let mut blob = Vec::new();
        push_serialize_buffers_blob_ue4_23(&mut blob);
        b.extend_from_slice(&blob[2..]);
        b
    }

    /// A legacy LOD whose outer strip flags are CLEAR (`global = 0`, `class = 0`),
    /// exercising the auxiliary-index branches the class-5 [`legacy_lod_ue4_20`]
    /// fixture's stripped path doesn't: the `!CDSF_ReversedIndexBuffer` 3-buffer
    /// fork (Reversed + DepthOnly + ReversedDepth), the editor-present
    /// `WireframeIndexBuffer`, and the `!CDSF_AdjacencyData` `AdjacencyIndexBuffer`.
    /// Empty geometry (0 sections / 0 vertices) so every buffer is a minimal header.
    #[cfg(feature = "__test_utils")]
    #[must_use]
    pub(crate) fn legacy_lod_all_aux_buffers() -> Vec<u8> {
        fn empty_index(b: &mut Vec<u8>) {
            b.extend_from_slice(&0i32.to_le_bytes()); // is32bit
            b.extend_from_slice(&1i32.to_le_bytes()); // elementSize
            b.extend_from_slice(&0i32.to_le_bytes()); // byteCount
        }
        let mut b = Vec::new();
        b.push(0x00); // outer global: editor NOT stripped → WireframeIndexBuffer present
        b.push(0x00); // outer class: reversed clear (3-buffer fork) + adjacency clear
        b.extend_from_slice(&0i32.to_le_bytes()); // section count = 0
        b.extend_from_slice(&0.0f32.to_le_bytes()); // MaxDeviation
        // PositionVertexBuffer: stride 12, 0 verts, bulk(12, 0).
        b.extend_from_slice(&12i32.to_le_bytes());
        b.extend_from_slice(&0i32.to_le_bytes());
        b.extend_from_slice(&12i32.to_le_bytes());
        b.extend_from_slice(&0i32.to_le_bytes());
        // StaticMeshVertexBuffer: strip(0,0), 1 texcoord, 0 verts, low precision,
        // tangent bulk(8, 0), UV bulk(4, 0).
        b.push(0);
        b.push(0);
        b.extend_from_slice(&1i32.to_le_bytes()); // NumTexCoords
        b.extend_from_slice(&0i32.to_le_bytes()); // NumVertices
        b.extend_from_slice(&0i32.to_le_bytes()); // bUseFullPrecisionUVs
        b.extend_from_slice(&0i32.to_le_bytes()); // bUseHighPrecisionTangentBasis
        b.extend_from_slice(&8i32.to_le_bytes()); // tangent itemSize
        b.extend_from_slice(&0i32.to_le_bytes()); // tangent itemCount
        b.extend_from_slice(&4i32.to_le_bytes()); // UV itemSize
        b.extend_from_slice(&0i32.to_le_bytes()); // UV itemCount
        // ColorVertexBuffer: strip(0,0), stride 4, 0 verts → None.
        b.push(0);
        b.push(0);
        b.extend_from_slice(&4i32.to_le_bytes());
        b.extend_from_slice(&0i32.to_le_bytes());
        // IndexBuffer + the reversed-fork (3: Reversed/DepthOnly/ReversedDepth) +
        // WireframeIndexBuffer + AdjacencyIndexBuffer — all empty headers.
        for _ in 0..6 {
            empty_index(&mut b);
        }
        // samplers: 0 sections → `0..=0` → one areaWeightedSampler (empty).
        b.extend_from_slice(&0i32.to_le_bytes()); // Prob count
        b.extend_from_slice(&0i32.to_le_bytes()); // Alias count
        b.extend_from_slice(&0.0f32.to_le_bytes()); // TotalWeight
        b
    }

    /// A legacy LOD with `CDSF_MinLodData` (class bit `0x02`) set → the buffers are
    /// stripped and `SerializeBuffersLegacy` is skipped entirely (header only). Pins
    /// the `!av_stripped && !min_lod_stripped` gate in [`read_lod_legacy`].
    #[cfg(feature = "__test_utils")]
    #[must_use]
    pub(crate) fn legacy_lod_min_lod_stripped() -> Vec<u8> {
        let mut b = Vec::new();
        b.push(0x00); // outer global (not AV-stripped)
        b.push(0x02); // outer class = CDSF_MinLodData → buffers stripped
        b.extend_from_slice(&1i32.to_le_bytes()); // section count = 1
        for v in [0i32, 0, 1, 0, 2] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        for _ in 0..2 {
            b.extend_from_slice(&1i32.to_le_bytes()); // 2 section bools
        }
        b.extend_from_slice(&0.0f32.to_le_bytes()); // MaxDeviation — no buffers follow
        b
    }

    /// `PAYLOAD_IN_SEPARATE_FILE | NO_OFFSET_FIXUP` — the flag word for an
    /// uncompressed streamed `FByteBulkData` record, mirroring the constants
    /// pinned by `bulk_data.rs` (`FLAG_PAYLOAD_IN_SEPARATE_FILE` `0x0100` |
    /// `FLAG_NO_OFFSET_FIXUP` `0x1_0000`).
    #[cfg(feature = "__test_utils")]
    const SEPARATE_FILE_NO_FIXUP: u32 = 0x0001_0100;

    /// [`SEPARATE_FILE_NO_FIXUP`] with `COMPRESSED_LZO` (`0x10`) set — a streamed
    /// record the resolver rejects (`UnsupportedBulkCompression`).
    #[cfg(feature = "__test_utils")]
    const SEPARATE_FILE_LZO: u32 = SEPARATE_FILE_NO_FIXUP | 0x10;

    /// Write a 20-byte `FByteBulkData` header for a separate-file (streamed)
    /// record: the given `flags` word (e.g. [`SEPARATE_FILE_NO_FIXUP`]),
    /// `element_count` and `size_on_disk`, `offset_in_file = 0`.
    #[cfg(feature = "__test_utils")]
    fn push_separate_file_bulk_header(
        b: &mut Vec<u8>,
        flags: u32,
        element_count: i32,
        size_on_disk: usize,
    ) {
        b.extend_from_slice(&flags.to_le_bytes());
        b.extend_from_slice(&element_count.to_le_bytes());
        b.extend_from_slice(&u32::try_from(size_on_disk).unwrap().to_le_bytes());
        b.extend_from_slice(&0i64.to_le_bytes()); // offset_in_file
    }

    /// A non-inlined UE4.23 `FStaticMeshLODResources`: the leading header with
    /// `bInlined = 0`, a separate-file `FByteBulkData` header (whose payload — the
    /// `SerializeBuffers` blob — is resolved out-of-band from a companion
    /// `.ubulk`), the in-stream availability-info trailer, and the shared
    /// `FStaticMeshBuffersSize`. `bulk_size_on_disk` is the `.ubulk` payload length.
    #[cfg(feature = "__test_utils")]
    #[must_use]
    pub(crate) fn non_inlined_lod_ue4_23(bulk_size_on_disk: usize) -> Vec<u8> {
        let mut b = Vec::new();
        push_lod_header_ue4_23(&mut b, false); // bInlined = 0
        push_separate_file_bulk_header(&mut b, SEPARATE_FILE_NO_FIXUP, 3, bulk_size_on_disk);
        // Availability-info trailer (UE4 path, per CUE4Parse
        // FStaticMeshLODResources.cs): DepthOnlyNumTriangles + Packed (8), the
        // buffer-count/stride stats (4*4 + 2*4 + 2*4 + 5*2*4 = 72), and — since UE4
        // is below RemovingTessellation — the AdjacencyIndexBuffer stats (8).
        b.extend_from_slice(&[0u8; 8 + 72 + 8]);
        // FStaticMeshBuffersSize (3 × u32), shared with the inlined path.
        b.extend_from_slice(&[0u8; 12]);
        b
    }

    /// A non-inlined UE5.0 LOD with an EMPTY streamed payload (`element_count =
    /// 0`): no geometry to resolve, but the in-stream availability-info trailer is
    /// still consumed. UE5 omits the tessellation `AdjacencyIndexBuffer` stats, so
    /// the trailer is `8 + 72` with NO trailing `+8`.
    #[cfg(feature = "__test_utils")]
    #[must_use]
    pub(crate) fn non_inlined_lod_ue5_0_empty() -> Vec<u8> {
        let mut b = Vec::new();
        push_lod_header_ue5_0(&mut b, false); // bInlined = 0
        push_separate_file_bulk_header(&mut b, SEPARATE_FILE_NO_FIXUP, 0, 0); // element_count 0 → no geometry
        // Availability-info trailer WITHOUT the adjacency stats (UE5 removed them).
        b.extend_from_slice(&[0u8; 8 + 72]);
        b.extend_from_slice(&[0u8; 12]); // FStaticMeshBuffersSize
        b
    }

    /// A non-inlined UE4.23 LOD whose `FByteBulkData` header sets a compression
    /// flag (LZO) with `element_count > 0` — the resolver rejects it
    /// (`UnsupportedBulkCompression`) when the geometry is fetched. No trailer (the
    /// reader errors before reaching it).
    #[cfg(feature = "__test_utils")]
    #[must_use]
    pub(crate) fn non_inlined_lod_ue4_23_compressed() -> Vec<u8> {
        let mut b = Vec::new();
        push_lod_header_ue4_23(&mut b, false);
        push_separate_file_bulk_header(&mut b, SEPARATE_FILE_LZO, 3, 16);
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
        push_lod_header_ue5_0(&mut b, true);
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

    /// UE 5.5 (object 1013, #643): a serialized `bHasRayTracingGeometry`
    /// bool precedes the buffers and is skipped; at 1012 nothing extra
    /// is read (regression pin). Header-length pin guards the splice.
    #[test]
    fn ue5_1013_ray_tracing_bool_skipped() {
        // UE5.0-shaped fixture offsets: strip(2) + count(4) +
        // section ints(20) → 4 bools at 26..42 → maxDev(4) +
        // cookedOut(4) + bInlined(4) → header ends at 54.
        const FIFTH_BOOL_AT: usize = 42;
        const HEADER_END: usize = 54;
        let full = inlined_lod_ue5_0();
        assert_eq!(
            &full[HEADER_END - 4..HEADER_END],
            &1i32.to_le_bytes(),
            "offset pin: bInlined=1 must close the header"
        );
        // ≥ 1008 contexts read the fifth section bool
        // (bAffectDistanceFieldLighting, 5.1+), so both legs splice it in.
        let with_fifth = |extra_after_header: bool| {
            let mut w = full[..FIFTH_BOOL_AT].to_vec();
            w.extend_from_slice(&1i32.to_le_bytes()); // fifth section bool
            w.extend_from_slice(&full[FIFTH_BOOL_AT..HEADER_END]);
            if extra_after_header {
                w.extend_from_slice(&0u32.to_le_bytes()); // bHasRayTracingGeometry
            }
            w.extend_from_slice(&full[HEADER_END..]);
            w
        };

        // 1013: the serialized ray-tracing bool IS present and skipped.
        let wire = with_fifth(true);
        let mut ctx = ue5_release_ctx(REMOVING_TESSELLATION);
        ctx.version.file_version_ue5 = Some(1013);
        let mut cur = Cursor::new(&wire[..]);
        let lod = read_lod(&mut cur, &ctx, "m.uasset").unwrap();
        assert_eq!(cur.position(), wire.len() as u64, "every byte consumed");
        assert_eq!(lod.positions.len(), 3, "geometry decodes past the skip");

        // 1012: NO ray-tracing bool on the wire — the skip must not fire.
        let wire12 = with_fifth(false);
        let mut ctx12 = ue5_release_ctx(REMOVING_TESSELLATION);
        ctx12.version.file_version_ue5 = Some(1012);
        let mut cur12 = Cursor::new(&wire12[..]);
        let lod12 = read_lod(&mut cur12, &ctx12, "m.uasset").unwrap();
        assert_eq!(cur12.position(), wire12.len() as u64);
        assert_eq!(lod12.positions.len(), 3);
    }

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
    fn non_inlined_lod_without_resolver_is_unsupported() {
        // No bulk resolver on the context (the in-memory/header-only path) → a
        // non-inlined LOD cannot fetch its streamed geometry, so it degrades to
        // UnsupportedFeature (the export then falls back to a property bag).
        let ctx = make_ctx_with_version(517, None);
        let bytes = lod_header(0, false, false); // bInlined = 0, no resolver
        let mut cur = Cursor::new(bytes.as_slice());
        let err = read_lod(&mut cur, &ctx, "T").unwrap_err();
        assert!(matches!(err, PaksmithError::UnsupportedFeature { .. }));
    }

    // The resolver-backed tests construct a `BulkDataResolver` via the
    // `__test_utils`-gated `new_for_test_with_ubulk`, so they are gated to match
    // (a plain `cargo test` build does not enable `__test_utils`).
    #[cfg(feature = "__test_utils")]
    #[test]
    fn non_inlined_lod_resolves_geometry_from_ubulk() {
        use std::sync::Arc;

        use super::test_support::{non_inlined_lod_ue4_23, serialize_buffers_blob_ue4_23};
        use crate::asset::bulk_data::BulkDataResolver;

        // With a bulk resolver on the context, a non-inlined LOD fetches its
        // SerializeBuffers blob from the companion `.ubulk` and decodes the same
        // geometry an inlined LOD would, then consumes the in-stream
        // availability-info trailer + FStaticMeshBuffersSize.
        let blob = serialize_buffers_blob_ue4_23();
        let resolver = Arc::new(BulkDataResolver::new_for_test_with_ubulk(
            Vec::<u8>::new(), // stitched uasset — unused for the separate-file tier
            0,                // total_header_size
            0,                // bulk_data_start_offset
            blob.clone(),     // the `.ubulk` payload
        ));
        let mut ctx = make_ctx_with_version(517, None);
        ctx.bulk_resolver = Some(resolver);

        let bytes = non_inlined_lod_ue4_23(blob.len());
        let mut cur = Cursor::new(bytes.as_slice());
        let lod = read_lod(&mut cur, &ctx, "T").unwrap();
        assert_eq!(
            cur.position(),
            bytes.len() as u64,
            "consumed every byte of the non-inlined LOD record"
        );
        assert_eq!(lod.positions.len(), 3, "geometry resolved from .ubulk");
        assert_eq!(lod.indices, vec![0, 1, 2]);
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn non_inlined_lod_empty_payload_consumes_trailer_without_adjacency() {
        use std::sync::Arc;

        use super::test_support::non_inlined_lod_ue5_0_empty;
        use crate::asset::bulk_data::BulkDataResolver;

        // UE5 (tessellation removed) + element_count == 0: no geometry is
        // resolved, but the availability-info trailer is still consumed — and it
        // carries NO adjacency stats. Pins the `element_count > 0` gate and the
        // non-inlined tessellation gate (a phantom +8 would break consume-exactly).
        let resolver = Arc::new(BulkDataResolver::new_for_test_with_ubulk(
            Vec::<u8>::new(),
            0,
            0,
            Vec::<u8>::new(),
        ));
        let mut ctx = ue5_release_ctx(REMOVING_TESSELLATION);
        ctx.bulk_resolver = Some(resolver);

        let bytes = non_inlined_lod_ue5_0_empty();
        let mut cur = Cursor::new(bytes.as_slice());
        let lod = read_lod(&mut cur, &ctx, "T").unwrap();
        assert_eq!(
            cur.position(),
            bytes.len() as u64,
            "consumed the availability-info trailer exactly (no adjacency stats)"
        );
        assert!(
            lod.positions.is_empty(),
            "an empty streamed payload yields no geometry"
        );
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn non_inlined_lod_compressed_bulk_is_rejected() {
        use std::sync::Arc;

        use super::test_support::non_inlined_lod_ue4_23_compressed;
        use crate::asset::bulk_data::BulkDataResolver;

        // A compressed (LZO) streamed payload is rejected by the resolver; the
        // error propagates so the export degrades to a property bag (the
        // package-resilience contract turns any typed-reader error into Generic).
        let resolver = Arc::new(BulkDataResolver::new_for_test_with_ubulk(
            Vec::<u8>::new(),
            0,
            0,
            Vec::<u8>::new(),
        ));
        let mut ctx = make_ctx_with_version(517, None);
        ctx.bulk_resolver = Some(resolver);

        let bytes = non_inlined_lod_ue4_23_compressed();
        let mut cur = Cursor::new(bytes.as_slice());
        let err = read_lod(&mut cur, &ctx, "T").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: crate::error::AssetParseFault::UnsupportedBulkCompression { .. },
                ..
            }
        ));
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn legacy_lod_decodes_all_auxiliary_index_buffers() {
        use super::test_support::legacy_lod_all_aux_buffers;

        // global = 0 (editor present → WireframeIndexBuffer), class = 0 (reversed
        // clear → the 3-buffer fork; adjacency clear → AdjacencyIndexBuffer). Pins
        // the strip-flag branches in serialize_buffers_legacy that the stripped
        // class-5 fixture leaves untaken — a flipped `&`/branch reads the wrong
        // buffer count and breaks consume-exactly.
        let ctx = make_ctx_with_version(516, None); // ~UE4.20 (legacy)
        let bytes = legacy_lod_all_aux_buffers();
        let mut cur = Cursor::new(bytes.as_slice());
        let lod = read_lod_legacy(&mut cur, &ctx, "T").unwrap();
        assert_eq!(
            cur.position(),
            bytes.len() as u64,
            "consumed all 6 auxiliary index buffers + the sampler"
        );
        assert!(lod.positions.is_empty());
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn legacy_lod_min_lod_stripped_has_no_buffers() {
        use super::test_support::legacy_lod_min_lod_stripped;

        // CDSF_MinLodData stripped → SerializeBuffersLegacy is skipped (header only).
        // Pins the `!av_stripped && !min_lod_stripped` gate: an `&&`→`||` mutant
        // would still try to read the (absent) buffers and EOF.
        let ctx = make_ctx_with_version(516, None);
        let bytes = legacy_lod_min_lod_stripped();
        let mut cur = Cursor::new(bytes.as_slice());
        let lod = read_lod_legacy(&mut cur, &ctx, "T").unwrap();
        assert_eq!(
            cur.position(),
            bytes.len() as u64,
            "consumed only the LOD header (buffers stripped)"
        );
        assert!(lod.positions.is_empty());
        assert_eq!(lod.sections.len(), 1);
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
