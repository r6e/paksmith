# SkeletalMesh (`USkeletalMesh`)

> Character / deformable-geometry asset — meshes that deform at
> runtime by binding vertices to a `USkeleton`'s bone hierarchy via
> skin weights.

## Overview

`USkeletalMesh` is the asset type for characters, vehicles,
animated props, and any geometry that needs runtime deformation. The
mesh's vertices each carry **bone influences** — a small set of
bone indices (typically 4 or 8) and matching weights that sum to
1.0. At runtime the GPU skinning step transforms each vertex by the
weighted average of its bones' current poses.

On disk, a `USkeletalMesh` is structurally similar to a
[`static-mesh.md`](static-mesh.md):

1. **Tagged-property segment** with settings + the
   `Skeleton: ObjectProperty(USkeleton)` reference.
2. **Cooked LOD payload** — `FStripDataFlags` + `ImportedBounds` +
   `SkeletalMaterials` + `ReferenceSkeleton`, then (for cooked
   content) a `bCooked` flag gating the LOD array.

The key difference from `UStaticMesh` is that the per-LOD vertex
layout includes skin-weight data (per-vertex bone indices + weights)
and each section carries a **bone map** (LOD-local-to-global bone
index translation). See [`skeleton.md`](skeleton.md) for the
`FReferenceSkeleton` wire layout.

**Status: not yet implemented in paksmith.** Phase 3+ deliverable.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| UE 4.0+ | `USkeletalMesh` + `FStaticLODModel` introduced. | `CUE4Parse/UE4/Assets/Exports/SkeletalMesh/USkeletalMesh.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d`[^1] |
| UE 4.16 (`FSkeletalMeshCustomVersion.SplitModelAndRenderData`) | Cooked LOD records split from editor LOD model; `bCooked` gate added at `USkeletalMesh.Deserialize` level. | Same[^1] |
| UE 4.16 (`FSkeletalMeshCustomVersion.CombineSectionWithChunk`) | Section and chunk merged; `FSkelMeshChunk` only present pre-this version. | Same[^1] |
| UE 4.20 (object version 504) | Skin-weight precision split; `bExtraBoneInfluences` variant. | Same[^1] |
| UE 4.24 (`FAnimObjectVersion.IncreaseBoneIndexLimitPerChunk`) | `bUse16BitBoneIndex` added (in both `FSkelMeshSection` and `FSkinWeightVertexBuffer`). | Same[^1] |
| UE 5.0+ | Optional cloth simulation data; `UseNewCookedFormat` version variant. | Same[^1] |

The per-version conditionals are dense; full enumeration is a
Phase 3 deliverable.

## Wire layout

### Segment 1: tagged-property stream

Common properties:

| Property name | Type | Semantics |
|---------------|------|-----------|
| `Skeleton` | `ObjectProperty` (`USkeleton`) | The skeleton this mesh binds to. See [`skeleton.md`](skeleton.md). |
| `Materials` | `ArrayProperty<StructProperty(FSkeletalMaterial)>` | Material slots. |
| `LODInfo` | `ArrayProperty<StructProperty(FSkeletalMeshLODInfo)>` | Per-LOD settings. |
| `PhysicsAsset` | `ObjectProperty` (`UPhysicsAsset`) | Ragdoll / rigid-body simulation. |
| `Sockets` | `ArrayProperty<ObjectProperty(USkeletalMeshSocket)>` | Attachment points. |
| `MeshClothingAssets` | `ArrayProperty<ObjectProperty(UClothingAssetBase)>` | UE 4.16+. |
| `MorphTargets` | `ArrayProperty<ObjectProperty(UMorphTarget)>` | Blend shapes. |
| `bHasVertexColors` | `BoolProperty` | |
| `EnablePerPolyCollision` | `BoolProperty` | |

### Segment 2: cooked LOD payload (after properties)

`USkeletalMesh.Deserialize` reads these fields after the tagged-
property stream. There is no `FSkeletalMeshRenderData` wrapper class
at this oracle SHA — the LOD payload is inlined directly into
`USkeletalMesh.Deserialize`.[^1]

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `FStripDataFlags` | variable | — | strip-flags struct | Governs which subsections are omitted. |
| `ImportedBounds` | 28 | LE | `FBoxSphereBounds` | Origin (3 × f32) + extent (3 × f32) + sphere radius (1 × f32). |
| `SkeletalMaterials` | variable | — | `FSkeletalMaterial[]` | Material slots (counted array). |
| `ReferenceSkeleton` | variable | — | `FReferenceSkeleton` | See [`skeleton.md`](skeleton.md). |
| *(editor LOD models)* | variable | — | `FStaticLODModel[]` | Present only when `skelMeshVer < SplitModelAndRenderData` OR when editor data is not stripped. See `FStaticLODModel` below. |
| `bCooked` | 4 | LE | `u32` (bool) | Present only when `skelMeshVer ≥ SplitModelAndRenderData`. Expected `1` for cooked. Gates the cooked LOD array below. |
| *(cooked LOD count)* | 4 | LE | `i32` | Count of LOD records that follow; only when `bCooked == true && LODModels == null` at this point. |
| *(cooked LOD records)* | variable | — | `FStaticLODModel[]` | Per-LOD cooked records (see `FStaticLODModel.SerializeRenderItem` below). |

### `FStaticLODModel` (per-LOD record)

CUE4Parse uses `FStaticLODModel` for cooked LOD records (the engine
source `FSkeletalMeshLODRenderData` maps to this type in the oracle).
Two serialization paths exist: the legacy path (pre-`SplitModelAndRenderData`)
reads the merged `VertexBufferGPUSkin`; the modern cooked path calls
`SerializeRenderItem`/`SerializeRenderItem_Legacy`. The table below
covers the main (non-cooked-render-item) constructor used for editor
and pre-split data.[^1]

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `FStripDataFlags` | variable | — | strip-flags struct | Governs which fields are omitted. |
| `Sections` | variable | — | `FSkelMeshSection[]` | Counted-array prefix + per-section records. |
| `Indices` | variable | — | `FMultisizeIndexContainer` | Index buffer. Pre-`SplitModelAndRenderData`: full `FMultisizeIndexContainer`. Post: `ReadBulkArray<uint>()` wrapped in container. |
| `ActiveBoneIndices` | variable | — | `short[]` | Bones referenced by this LOD. |
| `Chunks` | variable | — | `FSkelMeshChunk[]` | Present only when `skelMeshVer < CombineSectionWithChunk`; counted array. |
| `Size` | 4 | LE | `i32` | Total vertex data size (bytes). |
| `NumVertices` | 4 | LE | `i32` | Vertex count. Gated on `!IsAudioVisualDataStripped()`. |
| `RequiredBones` | variable | — | `short[]` | Bones that must be evaluated for this LOD. |
| `RawPointIndices` | variable | — | `FIntBulkData` | Present only when editor data is not stripped. CUE4Parse throws `ParserException` for this path; Phase 3 must skip. |
| `MeshToImportVertexMap` | variable | — | `i32[]` | Present when `Ver ≥ ADD_SKELMESH_MESHTOIMPORTVERTEXMAP`. |
| `MaxImportVertex` | 4 | LE | `i32` | Present with `MeshToImportVertexMap`. |
| `NumTexCoords` | 4 | LE | `i32` | Gated on `!IsAudioVisualDataStripped()`. |
| `VertexBufferGPUSkin` | variable | — | `FSkeletalMeshVertexBuffer` | **One merged buffer** containing positions + normals + UVs. Present when `skelMeshVer < SplitModelAndRenderData` and AV data not stripped. NOT three separate Position/Static/SkinWeight buffers at this path. |
| `SkinWeightVertexBuffer` (optional) | variable | — | `FSkinWeightVertexBuffer` | Present when `skelMeshVer ≥ UseSeparateSkinWeightBuffer`. |
| `ColorVertexBuffer` (optional) | variable | — | `FSkeletalMeshVertexColorBuffer` | Present when `bHasVertexColors == true`. Format depends on `skelMeshVer ≥ UseSharedColorBufferFormat`. |
| `AdjacencyIndexBuffer` (optional) | variable | — | `FMultisizeIndexContainer` | Present when `CDSF_AdjacencyData` not stripped. |
| `ClothVertexBuffer` (optional) | variable | — | `FSkeletalMeshVertexClothBuffer` | Present when cloth data exists (`HasClothData()`). |

### `FSkelMeshSection` (per-draw-call record)

Two serialization paths: the editor/pre-cooked constructor (used above)
and `SerializeRenderItem` (called in the cooked-render-item path). The
field sequence below is from the editor constructor; the render-item
path omits some version-gated fields and adds others.[^1]

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `FStripDataFlags` | variable | — | strip-flags struct | |
| `MaterialIndex` | 2 | LE | `short` | Index into `Materials`. |
| *(legacy chunk index)* | 2 | LE | `ushort` | Dummy; present only when `skelMeshVer < CombineSectionWithChunk`. |
| `BaseIndex` | 4 | LE | `int` | First triangle index. Gated on `!IsAudioVisualDataStripped()`. |
| `NumTriangles` | 4 | LE | `int` | Triangle count. Gated on `!IsAudioVisualDataStripped()`. |
| *(legacy triangle sorting)* | 1 | — | `byte` | Dummy; present only when `skelMeshVer < RemoveTriangleSorting`. |
| *(APEX Cloth flags)* | variable | — | various | Version-gated legacy cloth section flags. |
| `bRecomputeTangent` | 4 | LE | `u32` (bool) | `FRecomputeTangentCustomVersion ≥ RuntimeRecomputeTangent`. |
| `RecomputeTangentsVertexMaskChannel` | 1 | — | `byte` | `FRecomputeTangentCustomVersion ≥ RecomputeTangentVertexColorMask`. |
| `bCastShadow` | 4 | LE | `u32` (bool) | `FEditorObjectVersion ≥ RefactorMeshEditorMaterials`. |
| `bVisibleInRayTracing` | 4 | LE | `u32` (bool) | `FUE5MainStreamObjectVersion ≥ SkelMeshSectionVisibleInRayTracingFlagAdded`. |
| `BaseVertexIndex` | 4 | LE | `uint` | `skelMeshVer ≥ CombineSectionWithChunk` and AV data not stripped. |
| `SoftVertices` | variable | — | `FSoftVertex[]` | Editor data only; stripped in cooked. |
| `bUse16BitBoneIndex` | 4 | LE | `u32` (bool) | `FAnimObjectVersion ≥ IncreaseBoneIndexLimitPerChunk`. Present here (FSkelMeshSection) AND in FSkinWeightVertexBuffer. |
| `BoneMap` | variable | — | `ushort[]` | LOD-local-to-global bone index translation. |
| `NumVertices` | 4 | LE | `int` | `skelMeshVer ≥ SaveNumVertices`. |
| `MaxBoneInfluences` | 4 | LE | `int` | Bones per vertex (typically 4 or 8). |
| `ClothMappingDataLODs` | variable | — | `FMeshToMeshVertData[][]` | Nested array (outer = LOD bias; `FUE5ReleaseStreamObjectVersion ≥ AddClothMappingLODBias` → array-of-arrays; older → single array wrapped). |
| `CorrespondClothAssetIndex` | 2 | LE | `short` | Cloth-asset slot. |
| `ClothingData` | 8 | LE | `FClothingSectionData` | `skelMeshVer ≥ NewClothingSystemAdded` (UE 4.16+). |
| `OverlappingVertices` | variable | — | `Map<int, int[]>` | `FOverlappingVerticesCustomVersion ≥ DetectOVerlappingVertices`. |
| `bDisabled` | 4 | LE | `u32` (bool) | `FReleaseObjectVersion ≥ AddSkeletalMeshSectionDisable`. |
| `GenerateUpToLodIndex` | 4 | LE | `int` | `skelMeshVer ≥ SectionIgnoreByReduceAdded`. |
| `OriginalDataSectionIndex` | 4 | LE | `int` | `FEditorObjectVersion ≥ SkeletalMeshBuildRefactor`. |
| `ChunkedParentSectionIndex` | 4 | LE | `int` | Same gate. |

### `FSkinWeightVertexBuffer`

Per-vertex skin-weight payload. Wire shape is version-dispatched
on `bNewWeightFormat` (`FAnimObjectVersion ≥ UnlimitedBoneInfluences`).
Both paths are prefixed by `FStripDataFlags`.[^1]

**Legacy path** (`!bNewWeightFormat` or `!UseNewCookedFormat`):

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `FStripDataFlags` | variable | — | strip-flags struct | |
| `bExtraBoneInfluences` | 4 | LE | `u32` (bool) | `true` → 8 influences per vertex; `false` → 4. |
| `Stride` (optional) | 4 | LE | `uint` | Present only when `skelMeshVer ≥ SplitModelAndRenderData`. |
| `NumVertices` | 4 | LE | `uint` | |
| `Weights` | variable | — | bulk `FSkinWeightInfo[]` | Per-vertex bone-index + weight pairs. |

**New-format path** (`bNewWeightFormat = FAnimObjectVersion ≥ UnlimitedBoneInfluences`):

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `FStripDataFlags` | variable | — | strip-flags struct | |
| `bVariableBonesPerVertex` | 4 | LE | `u32` (bool) | |
| `MaxBoneInfluences` | 4 | LE | `uint` | |
| `NumBones` | 4 | LE | `uint` | |
| `NumVertices` | 4 | LE | `uint` | |
| `bUse16BitBoneIndex` | 4 | LE | `u32` (bool) | `FAnimObjectVersion ≥ IncreaseBoneIndexLimitPerChunk`. |
| `bUse16BitBoneWeight` | 4 | LE | `u32` (bool) | `FUE5MainStreamObjectVersion ≥ IncreasedSkinWeightPrecision`. |
| `WeightData` | variable | — | bulk `byte[]` | Raw weight payload (decoded later). |
| *(lookup strip flags + data)* | variable | — | `FStripDataFlags` + `uint[]` | Lookup table for variable-bones path. |

Full Phase 3 enumeration: see `FSkinWeightVertexBuffer.cs` in the oracle[^1]
for the exact dispatch and lookup-table decoding.

### Worked example

`(none yet — no skeletal-mesh fixture)`. When Phase 3 adds
fixtures, the canonical anchor will be `minimal_skeletal_mesh_v5.uasset`
— a single-LOD mesh with 3-4 vertices bound to a 2-bone minimal
skeleton.

## Variants

### 4 vs 8 bone influences per vertex

UE supports both. The choice is per-LOD via `bExtraBoneInfluences`.
Cooked PC content commonly uses 4 (smaller); cooked next-gen content
may use 8 for higher-fidelity characters.

### 8-bit vs 16-bit bone indices

UE 4.24+ supports 16-bit bone indices for meshes referencing more
than 256 bones. The flag appears in both `FSkelMeshSection` and
`FSkinWeightVertexBuffer`, gated on `FAnimObjectVersion.IncreaseBoneIndexLimitPerChunk`.

### Cloth simulation

When a section participates in cloth simulation, additional
`ClothMappingDataLODs` (in `FSkelMeshSection`) and `ClothVertexBuffer`
(in `FStaticLODModel`) entries appear. Phase 3 strategy: read past
cloth payloads as opaque bytes for the initial implementation.

### Morph targets

Blend-shape vertex deltas. Each morph target is a separate
`UMorphTarget` UObject referenced by the SkeletalMesh's
`MorphTargets` property. Per-morph-target wire shape lives in a
follow-up doc; the `SkeletalMesh` only carries references.

## Caps & limits

**Phase 3+ deferred work.** Same shape as static-mesh:

- `MAX_LODS_PER_MESH`.
- `MAX_SECTIONS_PER_LOD`.
- `MAX_BONES_PER_MESH` — `BoneMap.Length` per section is bounded by
  this cap (likely `2^16 = 65,536` to match the 16-bit-bone-index ceiling).
- Per-LOD buffer caps inherited from underlying file caps.

See `docs/security/allocation-caps.md` for the broader policy.

## Verification

- **Fixture:** `(none yet — Phase 3 deliverable)`.
- **Cross-validation oracle:** CUE4Parse[^1] (sole oracle; see [`static-mesh.md`](static-mesh.md) Verification for details on why no Rust counterpart exists).
- **Known divergences:** none yet.
- **Hex anchor commands:** (none yet — Phase 3 deliverable).

## Paksmith implementation

**Parser module:** *(not yet implemented — planned under
`crates/paksmith-core/src/asset/exports/mesh/skeletal_mesh.rs`)*

**Status:** `not impl`. Same fall-through-to-`Opaque`
behavior as static-mesh today.

**Phase plan:** `docs/plans/2026-05-19-ue-format-docs-mesh.md` Phase 3 (Export Pipeline) +
Phase 9 (3D Viewport).

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Exports/SkeletalMesh/USkeletalMesh.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` plus `FStaticLODModel.cs`, `FSkelMeshSection.cs`, `FSkinWeightVertexBuffer.cs` in the same directory. Primary oracle; covers every version conditional paksmith will need. Note: CUE4Parse uses `FStaticLODModel` for the cooked LOD record; there is no `FSkeletalMeshRenderData` wrapper class or `FSkeletalMeshLODRenderData`/`FSkelMeshRenderSection` at this SHA.
