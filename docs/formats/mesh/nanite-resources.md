# Nanite Resources (`FNaniteResources`)

> Virtualized-geometry payload that follows a `UStaticMesh`'s
> `numInlinedLODs` when the mesh was cooked with `NaniteSettings.bEnabled`
> (UE 5.0+). Carries the streamable-page bulk data, the BVH-hierarchy
> nodes, and the per-page metadata that the runtime needs to dispatch
> Nanite's compute-shader rasterization.

## Overview

Nanite is UE 5's virtualized-micropolygon mesh representation: instead
of a discrete LOD chain, Nanite cooks one extremely-high-poly mesh
into a hierarchical cluster representation that the renderer streams
on demand and rasterizes via compute. The on-disk payload follows the
existing `FStaticMeshRenderData` body inside a cooked `.uasset` /
`.uexp` (see [`static-mesh.md`](static-mesh.md) §*Nanite-enabled*),
gated on whether the asset's `NaniteSettings.bEnabled` tagged
property was true at cook time. The classic LOD payload still ships
in the same asset as Nanite's fallback mesh.

The blob is structured as:

- **Strip-flags header** — `FStripDataFlags` controls whether the
  remainder is present at all (cooked-without-Nanite-data assets have
  the audio-visual-data stripped flag set).
- **Resource flags** — `NANITE_RESOURCE_FLAG` u32 indicating
  vertex-color / imposter / DDC-streaming / forced-on opt-ins.
- **`StreamablePages` bulk data** — `FByteBulkData` holding the
  streamable Nanite pages (the bulk of the data; typically megabytes).
- **`RootData`** — counted `u8[]` carrying the always-resident root
  pages (small subset, embedded inline).
- **Page metadata** — counted `FPageStreamingState[]` plus
  `FPackedHierarchyNode[]` plus `HierarchyRootOffsets[]` plus
  `PageDependencies[]`.
- **(UE 5.6+) Assembly transforms** — counted `FMatrix3x4[]` for
  multi-instance assembly.
- **(UE 5.7+) Assembly bone attachments + page-range lookup** —
  additional counted arrays.
- **(UE 5.6+) Mesh bounds** — `FBoxSphereBounds` (2 × `FVector` +
  `f32` radius).
- **Imposter atlas** — counted `u16[]` for screen-space-distant
  rendering.
- **Quantization-precision and input-mesh statistics** — fixed-width
  i32/u32/u16 fields summarizing the source mesh (counts of triangles,
  vertices, meshes, texcoords, clusters; precision bits for positions
  and normals).
- **(UE 5.7+) Voxel materials mask** — `u64`.

**Document status: complete.** Wire format documented in full for the
top-level `FNaniteResources` field sequence, the strip-data gate, the
`NANITE_RESOURCE_FLAG` catalog, the `FPageStreamingState` per-page
record (with the UE 5.3 layout split), and the `FPackedHierarchyNode`
fixed-fanout-4 dispatch. The deep sub-records carried inside Nanite's
streamable pages (`FCluster`, `FHierarchyNodeSlice`, `FPageRangeKey`,
`FNaniteStreamableData`, `FMatrix3x4` per-element layout) are
identified by name and deferred to CUE4Parse's
`Assets/Exports/Nanite/` directory — they are bit-packed
compute-shader-readable structures whose byte-level decomposition is
out of scope for the format-reference layer this doc lives at and
belong with the GPU-cluster decode pipeline (a Phase 3+ deliverable).

**Paksmith parser status: `not impl`.** Phase 3+ deliverable. Per
[`static-mesh.md`](static-mesh.md) §*Nanite-enabled*, paksmith's Phase
3 implementation should make Nanite parsing opt-in — the classic
fallback LOD chain in the same asset is sufficient for most
extraction-oriented use cases.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| UE 5.0+ | `FNaniteResources` introduced inside `FStaticMeshRenderData` after `numInlinedLODs`. Pre-UE-5.2 `FPageStreamingState.Flags` is `u32` gated on `LARGE_WORLD_COORDINATES` (absent in 5.0EA). | `CUE4Parse/UE4/Assets/Exports/Nanite/NaniteResources.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d`[^1] |
| UE 5.1+ | `NumClusters: u32` added after `NumInputTexCoords`. | Same[^1] |
| UE 5.2+ | `NormalPrecision: i32` added after `PositionPrecision`. | Same[^1] |
| UE 5.3+ | `FPageStreamingState` widened layout: `DependenciesNum` narrows from `u32` to `u16`, `MaxHierarchyDepth: u8` and `Flags: u8` added. | Same[^1] |
| UE 5.6+ | `AssemblyTransforms: FMatrix3x4[]` (counted) added after `PageDependencies`. `MeshBounds: FBoxSphereBounds` added at the end of the assembly group. `NumInputMeshes`/`NumInputTexCoords` REMOVED. | Same[^1] |
| UE 5.7+ | `AssemblyBoneAttachmentData: u32[]` + `PageRangeLookup: FPageRangeKey[]` added after `AssemblyTransforms`. `PageDependencies` per-element type narrows from `u32` to `u16`. `VoxelMaterialsMask: u64` added at the end. | Same[^1] |

## Wire layout

Serialized inline after `FStaticMeshRenderData.numInlinedLODs` (per
[`static-mesh.md`](static-mesh.md) §*Wire layout — body*) when the
asset's `NaniteSettings.bEnabled` tagged property was true at cook.

### Strip-flags gate

| order | field | size | endian | type | semantics |
|-------|-------|------|--------|------|-----------|
| 1 | `stripFlags` | 2 | LE | `FStripDataFlags` | Strip-flags marker. When `IsAudioVisualDataStripped()` is true (the asset was cooked WITHOUT Nanite data despite the gate firing), the entire remainder is absent — the record ends after the 2 strip-flag bytes. |

All subsequent fields are present only when `!stripFlags.IsAudioVisualDataStripped()`.

### Top-level header

| order | field | size | endian | type | semantics |
|-------|-------|------|--------|------|-----------|
| 2 | `ResourceFlags` | 4 | LE | `NANITE_RESOURCE_FLAG` (`u32`) | Bit-flag set — see catalog below. |
| 3 | `StreamablePages` | variable | — | `FByteBulkData` | Streamable Nanite-page payload. See [`../asset/bulk-data.md`](../asset/bulk-data.md). |
| 4 | `RootData` | variable | LE | `u8[]` (counted) | Always-resident root-page bytes. Counted (`i32` length prefix). |
| 5 | `PageStreamingStates` | variable | LE | `FPageStreamingState[]` (counted) | Per-page metadata. See sub-record below. |
| 6 | `HierarchyNodes` | variable | LE | `FPackedHierarchyNode[]` (counted) | BVH-hierarchy nodes. See sub-record below. |
| 7 | `HierarchyRootOffsets` | variable | LE | `u32[]` (counted) | Per-mesh-root offset into `HierarchyNodes[]`. |
| 8 | `PageDependencies` | variable | LE | `u16[]` (UE 5.7+) or `u32[]` (UE 5.0-5.6) (counted) | Per-page dependency indices into `PageStreamingStates[]`. Per-element width narrows in UE 5.7+. |

### Assembly group (UE 5.6+ only)

Present only when `Ar.Game >= EGame.GAME_UE5_6`:

| order | field | size | endian | type | semantics |
|-------|-------|------|--------|------|-----------|
| 9 | `AssemblyTransforms` | variable | LE | `FMatrix3x4[]` (counted) | Per-instance world-space transforms (3×4 = 12 floats = 48 bytes each). Counted. |

### Assembly extensions (UE 5.7+ only)

Present only when `Ar.Game >= EGame.GAME_UE5_7`:

| order | field | size | endian | type | semantics |
|-------|-------|------|--------|------|-----------|
| 10 | `AssemblyBoneAttachmentData` | variable | LE | `u32[]` (counted) | Per-bone attachment indices for skeletal assembly. |
| 11 | `PageRangeLookup` | variable | LE | `FPageRangeKey[]` (counted) | Page-range lookup table (sub-record layout deferred to CUE4Parse's `FPageRangeKey.cs`). |

### Mesh bounds (UE 5.6+ only)

Present only when `Ar.Game >= EGame.GAME_UE5_6`:

| order | field | size | endian | type | semantics |
|-------|-------|------|--------|------|-----------|
| 12 | `MeshBounds` | 28 (UE4-precision) / 52 (LWC) | LE | `FBoxSphereBounds` = `FVector` (origin) + `FVector` (box extent) + `f32` (sphere radius) | Bounding volume of the source mesh. Per-`FVector` widths follow the parent archive's LWC dispatch (UE4 = 12 bytes per `FVector`, UE 5.0+ LWC = 24 bytes per `FVector`). Sphere radius is always `f32` (4 bytes). |

### Atlas + statistics

| order | field | size | endian | type | semantics |
|-------|-------|------|--------|------|-----------|
| 13 | `ImposterAtlas` | variable | LE | `u16[]` (counted) | Imposter-atlas texture data (used as screen-space-distant render proxy). |
| 14 | `NumRootPages` | 4 | LE | `i32` | Count of root pages (the first N entries of `PageStreamingStates` that are always-resident; the rest are streamable). |
| 15 | `PositionPrecision` | 4 | LE | `i32` | Bits of precision for quantized vertex positions. |
| 16 | `NormalPrecision` (UE 5.2+) | 4 | LE | `i32` | Bits of precision for quantized vertex normals. Pre-UE-5.2 = absent. |
| 17 | `NumInputTriangles` | 4 | LE | `u32` | Source-mesh triangle count (pre-Nanite-clusterization). |
| 18 | `NumInputVertices` | 4 | LE | `u32` | Source-mesh vertex count. |
| 19 | `NumInputMeshes` (UE < 5.6) | 2 | LE | `u16` | Source sub-mesh count. **REMOVED in UE 5.6+.** |
| 20 | `NumInputTexCoords` (UE < 5.6) | 2 | LE | `u16` | Source UV channel count. Engine-asserted ceiling at `NANITE_MAX_UVS = 4`. **REMOVED in UE 5.6+.** |
| 21 | `NumClusters` (UE 5.1+) | 4 | LE | `u32` | Total cluster count across all pages. Pre-UE-5.1 = absent. |
| 22 | `VoxelMaterialsMask` (UE 5.7+) | 8 | LE | `u64` | Bit-mask of voxel materials referenced. Pre-UE-5.7 = absent. |

### `FPageStreamingState` (per-page metadata sub-record)

Layout differs across the UE 5.3 boundary:

**UE 5.3+ layout (20 bytes):**

| offset | size | name | type | semantics |
|--------|------|------|------|-----------|
| 0 | 4 | `BulkOffset` | `u32` | Byte offset into `StreamablePages` (or `RootData` when index < `NumRootPages`). |
| 4 | 4 | `BulkSize` | `u32` | Byte length within the bulk source. |
| 8 | 4 | `PageSize` | `u32` | Decompressed page size. |
| 12 | 4 | `DependenciesStart` | `u32` | Start index into `PageDependencies[]`. |
| 16 | 2 | `DependenciesNum` | `u16` | Dependency count (was `u32` pre-5.3). |
| 18 | 1 | `MaxHierarchyDepth` | `u8` | Depth in the BVH hierarchy (UE 5.3+ only). |
| 19 | 1 | `Flags` | `u8` (`NANITE_PAGE_FLAG`) | Per-page flags (was `u32` pre-5.3). |

Total: 20 bytes.

**UE 5.0–5.2 layout (variable):**

| offset | size | name | type | semantics |
|--------|------|------|------|-----------|
| 0 | 4 | `BulkOffset` | `u32` | Same. |
| 4 | 4 | `BulkSize` | `u32` | Same. |
| 8 | 4 | `PageSize` | `u32` | Same. |
| 12 | 4 | `DependenciesStart` | `u32` | Same. |
| 16 | 4 | `DependenciesNum` | `u32` | Was `u32` pre-5.3. |
| 20 | 4 (UE 5.0+ LWC) or 0 (5.0 EA) | `Flags` | `u32` (`NANITE_PAGE_FLAG`) | Present only when `Ar.Ver >= EUnrealEngineObjectUE5Version.LARGE_WORLD_COORDINATES`; UE 5.0 EA (pre-LWC) had no `Flags` field at all. |

Total: 24 bytes (UE 5.0+ LWC) or 20 bytes (UE 5.0 EA pre-LWC).

### `FPackedHierarchyNode` (BVH-node sub-record)

A single hierarchy node carries exactly `NANITE_MAX_BVH_NODE_FANOUT = 4`
`FHierarchyNodeSlice` records (the fanout constant is engine-defined,
not on the wire — the array is fixed-length 4, NOT counted):

| order | field | size | endian | type | semantics |
|-------|-------|------|--------|------|-----------|
| 1 | `Slices` | variable | LE | `FHierarchyNodeSlice[4]` (fixed length, NOT counted) | Per-child BVH slice. The `FHierarchyNodeSlice` byte layout is deferred to CUE4Parse's `Assets/Exports/Nanite/FHierarchyNodeSlice.cs` (bit-packed cluster-descent metadata). |

### `NANITE_RESOURCE_FLAG` catalog (`u32` bit-flag)

| Bit | Value | Name | Semantics |
|-----|-------|------|-----------|
| — | `0x00000000` | `NONE` | No flags set. |
| 0 | `0x00000001` | `HAS_VERTEX_COLOR` | Source mesh had per-vertex colors. |
| 1 | `0x00000002` | `HAS_IMPOSTER` (CUE4Parse spells this `HAS_IMPOSTED` — engine-source typo preserved upstream; the value `0x00000002` is authoritative) | `ImposterAtlas` carries data (otherwise the array is empty). |
| 2 | `0x00000004` | `STREAMING_DATA_IN_DDC` | Streaming bulk data lives in the Editor DDC, not the cooked archive (relevant for editor builds; cooked content should not see this flag). |
| 3 | `0x00000008` | `FORCE_ENABLED` | Nanite was force-enabled regardless of `NaniteSettings.bEnabled`. |

### `NANITE_PAGE_FLAG` catalog (`u8` UE 5.3+ / `u32` UE 5.0-5.2 bit-flag)

| Bit | Value | Name | Semantics |
|-----|-------|------|-----------|
| — | `0x00` | `NONE` | No flags set. |
| 0 | `0x01` | `RELATIVE_ENCODING` | Page uses relative encoding (vs absolute) for cluster-descent indices. |

## Variants

### Strip-flags-stripped builds

When `stripFlags.IsAudioVisualDataStripped()` is true, the entire
record after the 2 strip-flag bytes is absent on wire. This happens
when the asset is cooked with `NaniteSettings.bEnabled` (which
triggers the gate from the parent `FStaticMeshRenderData`) but the
target platform doesn't support Nanite or the cooker stripped the
GPU-rasterizer data. The fallback LOD chain in the parent asset is
the only renderable representation in this case.

### Pre-LWC UE 5.0 EA

UE 5.0 Early Access (pre-`LARGE_WORLD_COORDINATES`) `FPageStreamingState`
has NO `Flags` field at all (the version gate
`Ar.Ver >= EUnrealEngineObjectUE5Version.LARGE_WORLD_COORDINATES`
guards the `u32` read). The record is 20 bytes in that variant
instead of 24.

### UE 5.6 `NumInputMeshes` / `NumInputTexCoords` removal

UE 5.6 removed both `NumInputMeshes` and `NumInputTexCoords` from the
serialized record (they're no longer needed at runtime). Pre-5.6
content carries them; 5.6+ content does not.

### UE 5.7 `PageDependencies` element-width narrowing

`PageDependencies` per-element type narrowed from `u32` to `u16` in
UE 5.7 (`Ar.Game >= EGame.GAME_UE5_7 ? Ar.Read<ushort>() : Ar.Read<uint>()`).
Total byte length for the same logical entry count halves at the
5.7 boundary.

### Game-specific quirks

CUE4Parse handles two game-specific deviations: `EGame.GAME_TheFirstDescendant`
forces the version container to `GAME_UE5_3` when loading individual
pages (handled in `TryLoadPage`, not in the top-level
`FNaniteResources` constructor — so the wire-layout for this doc is
unaffected); `EGame.GAME_Aion2` skips an extra fixed-array of the same
length as `ImposterAtlas` (`Ar.SkipFixedArray(1)`) after the imposter
atlas. These are runtime behaviours, not wire-format extensions to
account for in a conformant parser unless targeting those specific
games.

## Caps & limits

### Format-defined limits (wire-imposed)

- **`FStripDataFlags`**: 2 bytes in all UE 5+ cooked content (`u8` editor-only-strip flags + `u8` class-specific-strip flags). The same struct used elsewhere in the asset family; conditional-size behavior is irrelevant here because all UE 5+ archives are above the gate threshold.
- **`ResourceFlags`**: `u32` with defined bits 0..=3 (`NONE`,
  `HAS_VERTEX_COLOR`, `HAS_IMPOSTER`, `STREAMING_DATA_IN_DDC`,
  `FORCE_ENABLED`); bits 4..=31 are not allocated by the engine.
- **`FPageStreamingState`**: 20 bytes (UE 5.3+) or 24 bytes
  (UE 5.0+ LWC) or 20 bytes (UE 5.0 EA pre-LWC).
- **`FPackedHierarchyNode`**: fixed 4 × `FHierarchyNodeSlice` (the
  `4` is engine-defined `NANITE_MAX_BVH_NODE_FANOUT`, NOT on wire).
- **`FMatrix3x4`**: fixed 48 bytes (12 × `f32`).
- **`FBoxSphereBounds`**: 28 bytes (UE4 precision) or 52 bytes (LWC) —
  2 × `FVector` + `f32` sphere radius.
- **`PageDependencies`** per-element type: `u16` (UE 5.7+) or `u32`
  (UE 5.0-5.6).
- **Counted arrays** (`RootData`, `PageStreamingStates`,
  `HierarchyNodes`, `HierarchyRootOffsets`, `PageDependencies`,
  `AssemblyTransforms`, `AssemblyBoneAttachmentData`,
  `PageRangeLookup`, `ImposterAtlas`): `i32` length prefix, fixed-width
  per entry.
- **`NumInputTexCoords`** (UE < 5.6): engine-asserted ceiling at
  `NANITE_MAX_UVS = 4`.

### Implementation hardening (recommended for any parser)

A Nanite-resources reader (paksmith does not yet have one) MUST:

- **Verify all `i32` count prefixes are non-negative** before allocating the 9 counted arrays. A negative count cast to `usize` produces `usize::MAX`-adjacent values. Per-array byte-budget multipliers: `1 × count` (`RootData`), `20 or 24 × count` (`PageStreamingStates`), `~variable × count` (`HierarchyNodes` — depends on `FHierarchyNodeSlice` size), `4 × count` (`HierarchyRootOffsets`, `AssemblyBoneAttachmentData`), `2 or 4 × count` (`PageDependencies`), `48 × count` (`AssemblyTransforms`), `2 × count` (`ImposterAtlas`).
- **Cap `PageStreamingStates.Length`, `HierarchyNodes.Length`, `RootData.Length`** at a project-defined ceiling. Real cooked Nanite meshes can have thousands of pages and hundreds of thousands of hierarchy nodes; a `u32::MAX` count would drive multi-GiB allocations per array.
- **Validate `ResourceFlags`** against the defined bit-set `0x0000000F`. Reject (or warn + ignore) any bit set in `0xFFFFFFF0` — those bits are not engine-defined and indicate corruption or a forward-compat extension this parser doesn't know about.
- **Validate `NANITE_PAGE_FLAG`** values (`u8` UE 5.3+ / `u32` UE 5.0-5.2) against the defined bit-set `0x01`. Reject (or warn + ignore) any bit set above bit 0.
- **Bounds-check `NumRootPages`** against `PageStreamingStates.Length` before any page-loading dispatch (the first `NumRootPages` entries are sourced from `RootData`; the rest from `StreamablePages`). A `NumRootPages > PageStreamingStates.Length` would index past the array.
- **Bounds-check every `FPageStreamingState.BulkOffset + BulkSize`** against the size of its source buffer (either `RootData.Length` for index < `NumRootPages`, or `StreamablePages` size for the rest). Use `checked_add` on the sum.
- **Cap `FPageStreamingState.PageSize`** at a project-defined ceiling before pre-allocating any decompression buffer for the page. `PageSize` is the declared decompressed page size (`u32`); a `u32::MAX` value would drive a 4 GiB per-page allocation. The `MAX_UNCOMPRESSED_ENTRY_BYTES` cap from [`../asset/bulk-data.md`](../asset/bulk-data.md) §*Implementation hardening* bounds the total `StreamablePages` payload but not the per-page declared decompressed size; a separate per-page check is needed before any decompressor pre-allocates.
- **Bounds-check every `DependenciesStart + DependenciesNum`** against `PageDependencies.Length` before any dependency-walk. **Use `checked_add` on the sum** — pre-UE-5.3 both fields are `u32`, so their sum can wrap a `u32` and produce a small index that silently passes the `< PageDependencies.Length` check, letting an attacker walk an arbitrary dependency range. UE 5.3+ narrows `DependenciesNum` to `u16` but the same overflow-bypass applies if the sum is performed in `u16` arithmetic (`DependenciesNum: u16 + DependenciesStart: u32` widened correctly to `u32` avoids the issue, but parser-side type discipline matters).
- **Bounds-check every `HierarchyRootOffsets[i]`** against `HierarchyNodes.Length`.
- **Bounds-check every `PageDependencies[i]`** against `PageStreamingStates.Length`.
- **Cap `NumInputTriangles` and `NumInputVertices`** at a project-defined ceiling. Both are `u32`; a `u32::MAX` value is wire-syntactically valid but indicates a corrupt or hostile asset. These fields are statistical metadata, not direct allocation drivers, but downstream code that allocates per-triangle / per-vertex buffers based on them needs the cap.
- **Cap `NumInputTexCoords`** at the engine-asserted `NANITE_MAX_UVS = 4` (pre-UE-5.6). CUE4Parse doesn't enforce this in source; paksmith MUST reject larger values.
- **Reject NaN / ±∞ in every `AssemblyTransforms[i]` component** (each is `FMatrix3x4` = 12 × `f32`; per cooked entry 12 floats to validate). The transforms are applied to per-instance vertex positions at render time; attacker-controlled NaN / infinity in any matrix component propagates through ALL vertex transforms for that instance, matching the same hazard class that drives the `MeshExtension` / `MeshOrigin` MUST in [`vertex-formats.md`](vertex-formats.md) §*Caps & limits — Implementation hardening*. Validate each component with `is_finite()` before storing. (NaN/inf in `MeshBounds` is lower severity — it's a rendering-time bounding volume that doesn't drive per-vertex math — but a parser SHOULD apply the same `is_finite()` validation to the 6 / 12 floats in the `FBoxSphereBounds` origin + extent + radius for defense in depth.)
- **Inherit allocation caps** for the `FByteBulkData` payload from `MAX_UNCOMPRESSED_ENTRY_BYTES` per [`../asset/bulk-data.md`](../asset/bulk-data.md) §*Implementation hardening*. Nanite's `StreamablePages` is typically the largest single bulk-data payload in any cooked asset (multi-megabyte to multi-gigabyte range).

See `docs/security/allocation-caps.md` for the broader policy.

## Verification

- **Fixture:** No byte-exact worked example is provided in this doc — the top-level record's variable-version dispatch (6 separate UE-version gates affecting different fields) plus the nested per-page records make a synthetic minimal fixture impractical without significant misrepresentation of the format's flexibility. CUE4Parse's parsing path against real cooked Nanite assets (UE 5.0, 5.1, 5.2, 5.3, 5.6, 5.7) is the canonical reference; Phase 3+ paksmith implementation should validate against the same.
- **Cross-validation oracle:** CUE4Parse[^1] (sole oracle; no Rust counterpart parses Nanite).
- **Known divergences:** none — no paksmith implementation to diverge.

## Paksmith implementation

**Parser module:** *(not yet implemented — planned under
`crates/paksmith-core/src/asset/exports/mesh/nanite.rs`, called from
`asset/exports/mesh/static_mesh.rs` after `numInlinedLODs` when the
asset's `NaniteSettings.bEnabled` tagged property was true at cook)*

**Status:** `not impl`.

**Phase plan:** `docs/plans/ROADMAP.md` Phase 3+ (mesh-format reader).
Per [`static-mesh.md`](static-mesh.md) §*Nanite-enabled*, Nanite
parsing is an opt-in feature; the classic fallback LOD chain in the
same asset is sufficient for most extraction-oriented use cases.

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Exports/Nanite/NaniteResources.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` (top-level `FNaniteResources` constructor with all 6 UE-version dispatches), `FPageStreamingState.cs` (UE 5.3 layout split), `FPackedHierarchyNode.cs` (fixed 4 × `FHierarchyNodeSlice`), `NaniteConstants.cs` (`NANITE_RESOURCE_FLAG`, `NANITE_PAGE_FLAG`, `NANITE_MAX_BVH_NODE_FANOUT`, `NANITE_MAX_UVS`). Deeper sub-records (`FCluster`, `FHierarchyNodeSlice`, `FPageRangeKey`, `FNaniteStreamableData`, `FMatrix3x4` per-element layout) live in the same `Assets/Exports/Nanite/` directory and are deferred to CUE4Parse as canonical source.
