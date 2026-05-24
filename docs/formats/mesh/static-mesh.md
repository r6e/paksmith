# StaticMesh (`UStaticMesh`)

> Rigid-geometry asset — environment props, architectural pieces,
> anything that doesn't deform at runtime. Serialized as a tagged-
> property body followed by a cooked render-data payload with
> per-LOD vertex and index buffer sets.

## Overview

`UStaticMesh` is the most common geometry asset type in UE content.
Each `StaticMesh` carries one or more **Levels Of Detail** (LODs),
each LOD a complete mesh at a specific simplification level (LOD 0 =
full quality; higher LODs = lower polygon count). At runtime the
engine picks the LOD based on screen-space size.

On disk a `UStaticMesh` is a `UObject` export with two segments:

1. **Tagged-property segment** — settings, body setup, asset
   metadata.
2. **Cooked render-data segment** — `FStripDataFlags` + `bCooked`
   flag + `BodySetup` + the `FStaticMeshRenderData` payload containing
   per-LOD `FStaticMeshLODResources` records with vertex / index
   buffers plus per-section ranges.

The per-LOD vertex layout is governed by the shared
[`vertex-formats.md`](vertex-formats.md) catalog.

**Status: not yet implemented in paksmith.** Phase 3+ deliverable.
This doc enumerates the wire layout from CUE4Parse references with
explicit Phase-3 TODO markers in Caps & limits and Verification.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| UE 4.0+ | `UStaticMesh` + `FStaticMeshRenderData` introduced. | `CUE4Parse/UE4/Assets/Exports/StaticMesh/UStaticMesh.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d`[^1] |
| UE 4.20 (object version 504) | Section info encoding tweaks; vertex buffer layout stable. | Same[^1] |
| UE 4.23+ | `numInlinedLODs: u8` appended after the LOD array inside `FStaticMeshRenderData`. | Same[^1] |
| UE 4.25 (`VER_UE4_RAW_MESH_BULK_DATA_REMOVED`) | Raw mesh source data removed from cooked output. | Same[^1] |
| UE 5.0+ | `NaniteResources: FNaniteResources` added inside `FStaticMeshRenderData` after `numInlinedLODs`. Classic LOD payload still present for non-Nanite / fallback. | Same[^1] |
| UE 5.2+ | Ray-tracing-acceleration-structure payload added. | Same[^1] |

Per-version field-by-field enumeration is Phase 3+ work; the
table above sketches the change shape.

## Wire layout

### Segment 1: tagged-property stream

Common properties paksmith will encounter (each per
[`../property/tagged.md`](../property/tagged.md)):

| Property name | Type | Semantics |
|---------------|------|-----------|
| `StaticMaterials` | `ArrayProperty<StructProperty(FStaticMaterial)>` | Material slots by index. |
| `BodySetup` | `ObjectProperty` (`UBodySetup`) | Collision body. |
| `LODGroup` | `NameProperty` | LOD-group preset (e.g. `"LargeProp"`, `"SmallProp"`). |
| `LightMapCoordinateIndex` | `IntProperty` | UV channel used for light maps. |
| `LightMapResolution` | `IntProperty` | Light-map resolution in pixels. |
| `bAllowCPUAccess` | `BoolProperty` | Whether mesh data is CPU-accessible at runtime. |
| `NavCollision` | `ObjectProperty` | Navigation-mesh collision proxy. |
| `MinLOD` / `MaxLOD` | `IntProperty` / `StructProperty` | Per-platform LOD ranges. |
| `NaniteSettings` | `StructProperty` (`FMeshNaniteSettings`) | UE5+; opt-in Nanite parameters. |

Properties terminate with the standard `"None"` tag.

### Segment 2: `UStaticMesh.Deserialize` level (after properties)

`UStaticMesh.Deserialize` reads these fields immediately after the
tagged-property stream terminates. `FStaticMeshRenderData` is then
conditionally present based on `bCooked`.[^1]

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `FStripDataFlags` | variable | — | strip-flags struct | Governs which subsections are omitted from cooked output. |
| `bCooked` | 4 | LE | `u32` (bool) | Expected `1` for cooked content. Guards whether `FStaticMeshRenderData` follows. |
| `BodySetup` | 4 | LE | `FPackageIndex` | Reference to collision `UBodySetup`. |
| *(other UStaticMesh-level fields)* | — | — | — | Version-gated fields (navigation collision, LOD groups, etc.). Full enumeration is Phase 3 work. |

### `FStaticMeshRenderData` (present when `bCooked == true`)

`FStaticMeshRenderData` starts directly with the LOD array — no
`bCooked` or preamble field inside it. The `bCooked` read above
is at `UStaticMesh.Deserialize` level.[^1]

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `LODs` | variable | — | `FStaticMeshLODResources[]` | Counted-array prefix + per-LOD records. |
| `numInlinedLODs` (UE 4.23+) | 1 | — | `u8` | Count of LODs whose data is inlined (vs. streamed). |
| `NaniteResources` (UE 5.0+) | variable | — | `FNaniteResources` | When `NaniteSettings.bEnabled` was true at cook. |
| `Bounds` | 28 (UE4) / 56 (UE5 LWC) | LE | `FBoxSphereBounds` | Origin (3 × f32/f64) + BoxExtent (3 × f32/f64) + SphereRadius (f32/f64). Under UE5 LWC (`Ver ≥ LARGE_WORLD_COORDINATES`), each component widens to f64 (8 bytes), giving 24+24+8 = 56 bytes. |
| `bLODsShareStaticLighting` | 4 | LE | `u32` (bool) | |
| `ScreenSize` | variable | LE | `f32[]` | Per-LOD screen-size thresholds. UE 4.9+: 8 entries; older: 4 entries. UE 4.20+: each is `FPerPlatformFloat`. |

Note: `bReducedBySimplygon` and `MinLODs` are not present in the
`FStaticMeshRenderData` constructor at this oracle SHA.

### `FStaticMeshLODResources` (per-LOD record)

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `Sections` | variable | — | `FStaticMeshSection[]` | Counted-array prefix + per-section ranges. |
| `MaxDeviation` | 4 | LE | `f32` | Simplification error tolerance. |
| `VertexBuffers` | variable | — | `FStaticMeshVertexBuffers` | Position + normal-tangent + UV-channels + colors buffers. |
| `IndexBuffer` | variable | — | `FRawStaticIndexBuffer` | Per-triangle vertex indices. |
| `AdjacencyIndexBuffer` | variable | — | `FRawStaticIndexBuffer` | Tessellation adjacency (typically absent in cooked content). |
| `WireframeIndexBuffer` | variable | — | `FRawStaticIndexBuffer` | Editor wireframe (typically absent in cooked). |

Per-buffer wire layouts live in [`vertex-formats.md`](vertex-formats.md).

### `FStaticMeshSection` (per-draw-call record)

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `MaterialIndex` | 4 | LE | `i32` | Index into `UStaticMesh::StaticMaterials`. |
| `FirstIndex` | 4 | LE | `i32` | First triangle index this section draws. |
| `NumTriangles` | 4 | LE | `i32` | Triangle count for this section. |
| `MinVertexIndex` | 4 | LE | `i32` | Inclusive lower vertex range. |
| `MaxVertexIndex` | 4 | LE | `i32` | Inclusive upper vertex range. |
| `bEnableCollision` | 4 | LE | `u32` (bool) | |
| `bCastShadow` | 4 | LE | `u32` (bool) | |
| `bForceOpaque` (UE 4.25+) | 4 | LE | `u32` (bool) | |
| `bVisibleInRayTracing` (UE 4.27+) | 4 | LE | `u32` (bool) | |

### Worked example

`(none yet — no static-mesh fixture)`. When Phase 3 adds fixtures,
the canonical anchor will be `minimal_static_mesh_v5.uasset` — a
single-LOD cube with one section, three or four uncompressed
vertices, and a 12-index `IndexBuffer`.

## Variants

### Nanite-enabled (UE 5+)

When the asset's `NaniteSettings.bEnabled` was true at cook time, an
`FNaniteResources` blob follows `numInlinedLODs` inside
`FStaticMeshRenderData`. The blob holds the virtualized-mesh page
tables; the classic LOD array is still present (used as fallback on
hardware that doesn't support Nanite).

Paksmith's Phase 3 implementation should make Nanite an opt-in
follow-up rather than a base requirement — the classic LOD payload
is sufficient for most extraction use cases.

### Vertex / index buffer compression

Some platforms enable vertex / index buffer compression (e.g.
`bCompressBuffers` cooker option). Cooked PC content typically
disables this; mobile cooked content may enable. The compressed-
buffer wire shape is significantly different and is Phase 3+
work to specialize.

## Caps & limits

**Phase 3+ deferred work.** When the static-mesh reader lands:

- `MAX_LODS_PER_MESH` cap (~8 — UE never cooks more LODs than this
  in practice).
- `MAX_SECTIONS_PER_LOD` cap.
- Per-LOD vertex / index buffer count caps inherited from
  `MAX_UNCOMPRESSED_ENTRY_BYTES` / `MAX_UEXP_SIZE` via the
  parent `.uasset` / `.uexp`.

See `docs/security/allocation-caps.md` for the broader policy.

## Verification

- **Fixture:** `(none yet — Phase 3 deliverable)`.
- **Cross-validation oracle:** CUE4Parse[^1] (sole oracle —
  `AstroTechies/unrealmodding` doesn't ship mesh exports; verified
  HTTP 404 on `unreal_asset/src/exports/{static_mesh,skeletal_mesh,skeleton,mesh_vertex_buffers}_export.rs`).
- **Known divergences:** none yet — no implementation to diverge.
- **Hex anchor commands:** (none yet — Phase 3 deliverable).

## Paksmith implementation

**Parser module:** *(not yet implemented — planned under
`crates/paksmith-core/src/asset/exports/mesh/static_mesh.rs`)*

**Status:** `not impl`. Encounters of `StaticMesh` exports
today parse the tagged-property segment but fall through to
`PropertyBag::Opaque` when the `FStaticMeshRenderData` blob starts
being misread as more tagged properties.

**Phase plan:** `docs/plans/ROADMAP.md` Phase 3 (Export Pipeline) +
likely Phase 9 (3D Viewport for rendering the result). A Phase 3
plan should:

1. Add a `crates/paksmith-core/src/asset/exports/mesh/static_mesh.rs`
   module with `StaticMesh::read_from`.
2. Add the per-LOD / per-section types.
3. Hook a per-export dispatch by class name (export's `class_index`
   resolves to a `StaticMesh` import → trigger the specialized
   reader).
4. Add `MAX_LODS_PER_MESH` / `MAX_SECTIONS_PER_LOD` caps.
5. Add fixtures + cross-validation against CUE4Parse[^1].

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Exports/StaticMesh/UStaticMesh.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` plus `FStaticMeshRenderData.cs`, `FStaticMeshLODResources.cs`, `FStaticMeshSection.cs` in the same directory. Primary oracle; covers every version conditional paksmith will need.
