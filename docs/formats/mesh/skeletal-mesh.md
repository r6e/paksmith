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

**Document status: complete.** Wire format documented in full for
the `USkeletalMesh` two-segment body, the `FStaticLODModel`
per-LOD record (with version-conditional field gating from UE 4.0
through UE 5.x), the `FSkelMeshSection` per-draw-call record
(both editor and cooked-render-item paths), and the
`FSkinWeightVertexBuffer` per-vertex skin-weight payload (both
legacy and new-format `UnlimitedBoneInfluences` paths). The
`FSkeletalMeshVertexBuffer` (skeletal-merged position+normal+UV
buffer used pre-`SplitModelAndRenderData`) is documented in
[`vertex-formats.md`](vertex-formats.md) §*FSkeletalMeshVertexBuffer*.
Cloth
simulation sub-payloads and morph-target deltas are identified
and deferred (separate UObject reference chain).

**Paksmith parser status: `not impl`.** Phase 3+ deliverable.
Same fall-through-to-`Opaque` behavior as static-mesh today.

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
| `ImportedBounds` | 28 (UE4) / 56 (UE5 LWC) | LE | `FBoxSphereBounds` | Origin (3 × f32/f64) + BoxExtent (3 × f32/f64) + SphereRadius (f32/f64). Under UE5 LWC (`Ver ≥ LARGE_WORLD_COORDINATES`), each component widens to f64 (8 bytes), giving 24+24+8 = 56 bytes. |
| `SkeletalMaterials` | variable | — | `FSkeletalMaterial[]` | Material slots (counted array). |
| `ReferenceSkeleton` | variable | — | `FReferenceSkeleton` | See [`skeleton.md`](skeleton.md). |
| *(editor LOD models)* | variable | — | `FStaticLODModel[]` | Editor LOD models are read via exclusive version dispatch: legacy path (`skelMeshVer < SplitModelAndRenderData`) reads the LOD model array directly; modern path (`skelMeshVer >= SplitModelAndRenderData`) reads the array only when `!IsEditorDataStripped()` (editor data present) — when stripped, no LOD models are read on the modern path. These are exclusive branches, not OR conditions. See `FStaticLODModel` below. |
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

Shared per-buffer wire layouts (`FColorVertexBuffer`, `FMultisizeIndexContainer`) live in [`vertex-formats.md`](vertex-formats.md). `FSkeletalMeshVertexBuffer` (the skeletal-merged position+normal+UV buffer used by the pre-`SplitModelAndRenderData` path) is structurally distinct from `FStaticMeshVertexBuffer` and is documented in [`vertex-formats.md`](vertex-formats.md) §*FSkeletalMeshVertexBuffer*.

### `FSkelMeshSection` — editor constructor (`FSkeletalMeshLODModel`)

The editor/pre-cooked `FSkeletalMeshLODModel` constructor path. This is
**not** the path paksmith implements; it is preserved here as a reference
for the full field set. See the cooked path subsection below for the
`SerializeRenderItem` layout that paksmith's reader targets.[^1]

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
| `ClothingData` | 20 | LE | `FClothingSectionData` | `FGuid AssetGuid` (16) + `int AssetLodIndex` (4); `[StructLayout(LayoutKind.Sequential)]`. `skelMeshVer ≥ NewClothingSystemAdded` (UE 4.16+). |
| `OverlappingVertices` | variable | — | `Map<int, int[]>` | `FOverlappingVerticesCustomVersion ≥ DetectOVerlappingVertices`. |
| `bDisabled` | 4 | LE | `u32` (bool) | `FReleaseObjectVersion ≥ AddSkeletalMeshSectionDisable`. |
| `GenerateUpToLodIndex` | 4 | LE | `int` | `skelMeshVer ≥ SectionIgnoreByReduceAdded`. |
| `OriginalDataSectionIndex` | 4 | LE | `int` | `FEditorObjectVersion ≥ SkeletalMeshBuildRefactor`. |
| `ChunkedParentSectionIndex` | 4 | LE | `int` | Same gate. |

### `FSkelMeshSection` — cooked render path (`SerializeRenderItem`)

The `SerializeRenderItem` path used in editor-data-stripped cooked assets.
This is the path **paksmith implements** (PR3 of Phase 3h). Source:
`FSkelMeshSection.cs` (`SerializeRenderItem`) in CUE4Parse.[^1]

Key differences from the editor constructor above: `bRecomputeTangent`,
`BaseVertexIndex`, `NumVertices`, `MaxBoneInfluences`, and `ClothingData`
are **unconditional** on this path; the legacy-only fields (`SoftVertices`,
`bUse16BitBoneIndex`, `OverlappingVertices`, `GenerateUpToLodIndex`,
`OriginalDataSectionIndex`, `ChunkedParentSectionIndex`, legacy chunk
index, APEX cloth flags, triangle-sorting dummy) do **not** appear; and a
`DupVertData`/`DupVertIndexData` skip pair is present only on pre-UE4.23
or non-stripped assets (cooked-only concept absent from the editor path).

Fields in wire order:

| # | field | size | endian | type | condition |
|---|-------|------|--------|------|-----------|
| 1 | `FStripDataFlags` | variable | — | strip-flags struct | unconditional; `class` bits used for dup-vert gate |
| 2 | `MaterialIndex` | 2 | LE | `i16` | unconditional |
| 3 | `BaseIndex` | 4 | LE | `i32` | unconditional |
| 4 | `NumTriangles` | 4 | LE | `i32` | unconditional |
| 5 | `bRecomputeTangent` | 4 | LE | `u32` (bool) | **unconditional** |
| 6 | `RecomputeTangentsVertexMaskChannel` | 1 | — | `u8` | `FRecomputeTangentCustomVersion ≥ RecomputeTangentVertexColorMask`; default `0` |
| 7 | `bCastShadow` | 4 | LE | `u32` (bool) | `FEditorObjectVersion ≥ RefactorMeshEditorMaterials`; default `true` |
| 8 | `bVisibleInRayTracing` | 4 | LE | `u32` (bool) | `FUE5MainStreamObjectVersion ≥ SkelMeshSectionVisibleInRayTracingFlagAdded`; default `true` |
| 9 | `BaseVertexIndex` | 4 | LE | `u32` | **unconditional** |
| 10 | `ClothMappingDataLODs` | variable | — | `FMeshToMeshVertData[][]` | unconditional; shape switches on `FUE5ReleaseStreamObjectVersion ≥ AddClothMappingLODBias` (new: outer count + inner arrays; legacy: single inner array only); each `FMeshToMeshVertData` is 64 bytes; arrays are consumed and discarded |
| 11 | `BoneMap` | variable | — | `i32` count + `N×u16` | unconditional; count sign-checked and capped |
| 12 | `NumVertices` | 4 | LE | `i32` | **unconditional**; sign-checked |
| 13 | `MaxBoneInfluences` | 4 | LE | `i32` | **unconditional**; sign-checked and capped at 8 |
| 14 | `CorrespondClothAssetIndex` | 2 | LE | `i16` | unconditional |
| 15 | `ClothingData` (`FClothingSectionData`) | 20 | LE | `FGuid` (16) + `i32` (4) | **unconditional**; consumed and discarded |
| 16–17 | `DupVertData` / `DupVertIndexData` | variable | — | `i32` count + `N×4` / `i32` count + `N×8` | gated on `game < UE4.23 OR !IsClassDataStripped(DuplicatedVertices)`; consumed and discarded when present |
| 18 | `bDisabled` | 4 | LE | `u32` (bool) | `FReleaseObjectVersion ≥ AddSkeletalMeshSectionDisable`; default `false` |

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

### Worked example — `FSkinWeightVertexBuffer` new-format-path header (26 bytes)

The new-format-path (`FAnimObjectVersion ≥ UnlimitedBoneInfluences`,
UE 4.25+) header for a UE 5.x cooked skeletal-mesh LOD with 4
vertices, 4 max bone influences per vertex, 8 total bone slots
addressable, fixed-bones-per-vertex (no variable bones), 8-bit
bone indices, 8-bit bone weights, no audio-visual stripping:

```
Offset (within header)  Bytes (LE)        Field
----------------------  ---------------   --------------------
+0                      00 00             FStripDataFlags = 0x0000 (GlobalStripFlags + ClassStripFlags; no strip)
+2                      00 00 00 00       bVariableBonesPerVertex = 0 (u32 bool; fixed bones-per-vertex)
+6                      04 00 00 00       MaxBoneInfluences = 4 (u32; standard 4 bones per vertex)
+10                     08 00 00 00       NumBones = 8 (u32; total addressable bones)
+14                     04 00 00 00       NumVertices = 4 (u32)
+18                     00 00 00 00       bUse16BitBoneIndex = 0 (u32 bool; FAnimObjectVersion ≥ IncreaseBoneIndexLimitPerChunk)
+22                     00 00 00 00       bUse16BitBoneWeight = 0 (u32 bool; FUE5MainStreamObjectVersion ≥ IncreasedSkinWeightPrecision)
+26                     <(WeightData bulk payload + lookup strip-flags + lookup table follow)>
```

The `WeightData` payload size is approximately
`NumVertices × MaxBoneInfluences × (bone_index_size + bone_weight_size)`
when `bVariableBonesPerVertex == 0`. With the example values:
`4 × 4 × (1 + 1) = 32 bytes` of raw skin-weight data. When
`bVariableBonesPerVertex == 1`, the actual payload is variable
length and the trailing lookup table (`FStripDataFlags + uint[]`)
indexes per-vertex offsets into `WeightData`.

For the legacy path (pre-`UnlimitedBoneInfluences`), the header is
smaller: `FStripDataFlags` + `bExtraBoneInfluences: u32` +
optional `Stride: u32` (when `skelMeshVer ≥ SplitModelAndRenderData`)
+ `NumVertices: u32`, then the typed `FSkinWeightInfo[]` bulk array
inline.

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

### Format-defined limits (wire-imposed)

- **`FSkelMeshSection.MaterialIndex`**: `i16`; max representable `i16::MAX = 32767`.
- **`FSkelMeshSection.BaseIndex` / `NumTriangles` / `NumVertices` / `MaxBoneInfluences` / `BaseVertexIndex`**: `i32` / `u32` fields per the wire layout table above.
- **`FSkelMeshSection.bUse16BitBoneIndex`**: `u32` (bool); when `1`, bone indices are 16-bit (max `u16::MAX = 65535` addressable bones per LOD).
- **`FSkinWeightVertexBuffer.MaxBoneInfluences`** (new-format path): `u32`; format-allowed up to `u32::MAX` but UE writers conventionally cap at 8 (`bExtraBoneInfluences` ceiling).
- **`FSkinWeightVertexBuffer.bUse16BitBoneWeight`** (UE 5.x): `u32` (bool); when `1`, per-influence weights are 16-bit instead of 8-bit.
- **`FClothingSectionData`**: fixed 20 bytes (`FGuid AssetGuid` 16 + `i32 AssetLodIndex` 4); `[StructLayout(LayoutKind.Sequential)]` per CUE4Parse.
- **`ActiveBoneIndices` / `RequiredBones` / `BoneMap`**: `short[]` / `ushort[]` arrays with `i32` count prefixes.

### Implementation hardening (recommended for any parser)

A skeletal-mesh reader (paksmith does not yet have one) MUST:

- **Cap LOD count** at `MAX_LODS_PER_MESH` (typically `8`).
- **Cap sections per LOD** at `MAX_SECTIONS_PER_LOD` (typically `64`).
- **Cap bones per mesh** at `MAX_BONES_PER_MESH` (typically `2^16 = 65,536` to match the 16-bit-bone-index ceiling). `BoneMap.Length` per section is bounded by this cap.
- **Validate `FSkelMeshSection.MaterialIndex`** is in `[0, Materials.Length)` before using it as an array index into the parent `USkeletalMesh::Materials`. The field is `i16` on wire; an unchecked negative value (`MaterialIndex < 0`) or out-of-range positive value drives an out-of-bounds read on the material slot lookup.
- **Verify `i32` count prefixes are non-negative** before any allocation arithmetic. The following fields are all signed `i32` on the wire and a negative value is a sign-extension attack vector: `FStaticLODModel.{Size, NumVertices, NumTexCoords, MeshToImportVertexMap.count, MaxImportVertex}`, `FSkelMeshSection.{NumTriangles, NumVertices, MaxBoneInfluences}`.
- **Cap `FSkinWeightVertexBuffer.MaxBoneInfluences`** at `MAX_BONE_INFLUENCES_PER_VERTEX` (typically `8`); enforce `1 ≤ value ≤ MAX_BONE_INFLUENCES_PER_VERTEX`. The skin-weight payload is sized `MaxBoneInfluences × bytes_per_influence × NumVertices`; a max-value `u32` would blow the allocator before the file-residual-bytes backstop catches it.
- **Cap `FSkinWeightVertexBuffer.NumBones`** at `MAX_BONES_PER_MESH`. Direct allocation driver.
- **Cap `FSkelMeshSection.MaxBoneInfluences`** at the same `MAX_BONE_INFLUENCES_PER_VERTEX`; enforce `1 ≤ value ≤ MAX_BONE_INFLUENCES_PER_VERTEX`. Per-vertex skin-weight allocation is `MaxBoneInfluences × (bone_index_size + bone_weight_size)`; negative / zero values are sign-extension and divide-by-zero attack vectors respectively.
- **Cap `ActiveBoneIndices` / `RequiredBones` / `FSkelMeshSection.BoneMap` count prefixes** at `MAX_BONES_PER_MESH` (all `i32` count prefixes; all direct allocation drivers).
- **Bound doubly-nested counted structures with independent per-dimension caps** to prevent quadratic allocator amplification:
  - `FSkelMeshSection.ClothMappingDataLODs` (`FMeshToMeshVertData[][]`): needs `MAX_LOD_CLOTH_MAPPING_DEPTH` + per-LOD entry count cap.
  - `FSkelMeshSection.OverlappingVertices` (`Map<i32, i32[]>`): needs outer-map entry cap + per-entry inner `i32[]` count cap.
- **Inherit per-LOD buffer caps** from `MAX_UNCOMPRESSED_ENTRY_BYTES` / `MAX_UEXP_SIZE`.

See `docs/security/allocation-caps.md` for the broader policy.

## Verification

- **Fixture:** The 26-byte `FSkinWeightVertexBuffer` new-format-path header Worked example above is byte-exact and self-contained. A full skeletal-mesh fixture (`minimal_skeletal_mesh_v5.uasset` — single-LOD mesh with 3-4 vertices bound to a 2-bone minimal skeleton) is a Phase 3 deliverable.
- **Hex anchor commands:**
  ```
  # Synthesize the 26-byte FSkinWeightVertexBuffer new-format header
  # from the Worked example (4 vertices, 4 max bone influences, 8
  # bones, fixed bones-per-vertex, 8-bit indices, 8-bit weights):
  printf '\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x08\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' | xxd
  ```
  A conformant skeletal-mesh parser fed these 26 bytes at the
  matching offset MUST decode them as a new-format skin-weight
  header expecting 32 bytes of fixed-stride `WeightData` to follow.
- **Cross-validation oracle:** CUE4Parse[^1] (sole oracle; see [`static-mesh.md`](static-mesh.md) Verification for details on why no Rust counterpart exists).
- **Known divergences:** none — no paksmith implementation to diverge.

## Paksmith implementation

**Parser module:** *(not yet implemented — planned under
`crates/paksmith-core/src/asset/exports/mesh/skeletal_mesh.rs`)*

**Status:** `not impl`. Same fall-through-to-`Opaque`
behavior as static-mesh today.

**Phase plan:** `docs/plans/ROADMAP.md` Phase 3 (Export Pipeline) +
Phase 9 (3D Viewport).

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Exports/SkeletalMesh/USkeletalMesh.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` plus `FStaticLODModel.cs`, `FSkelMeshSection.cs`, `FSkinWeightVertexBuffer.cs` in the same directory. Primary oracle; covers every version conditional paksmith will need. Note: CUE4Parse uses `FStaticLODModel` for the cooked LOD record; there is no `FSkeletalMeshRenderData` wrapper class or `FSkeletalMeshLODRenderData`/`FSkelMeshRenderSection` at this SHA.
