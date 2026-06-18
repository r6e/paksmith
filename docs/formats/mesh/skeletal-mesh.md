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
per-LOD record (both the editor constructor and the cooked
`SerializeRenderItem` path, including the UE 4.24 format boundary,
`bIsLODCookedOut`/`bInlined` flags, `RequiredBones`/`ActiveBoneIndices`
arrays, and the full streamed blob), the `FSkelMeshSection`
per-draw-call record (both editor and cooked-render-item paths),
`FSkinWeightVertexBuffer` (both legacy UE4.24 and new UE4.25+
`UnlimitedBoneInfluences` paths, including the `num_skel` rule and
deferred variants), and `FMultisizeIndexContainer` (the skeletal index
buffer). The `FSkeletalMeshVertexBuffer` (skeletal-merged
position+normal+UV buffer used pre-`SplitModelAndRenderData`) is
documented in [`vertex-formats.md`](vertex-formats.md)
§*FSkeletalMeshVertexBuffer*. Cloth simulation sub-payloads and
morph-target deltas are identified and deferred (separate UObject
reference chain).

**Paksmith parser status (PR5c, Phase 3h):** All inlined LODs'
`SerializeStreamedData` blobs are parsed (indices, positions,
normals/tangents/UVs, per-vertex bone influences, vertex colors). The
full `read_typed` path — `FStripDataFlags` through `BuffersSize`, the
blob, the post-loop tail, and the cursor-landing sentinel — is
implemented for cooked UE 4.24+ assets. The non-inlined
(`FByteBulkData`) path is also implemented (PR5c): bulk LODs are
consumed (header + `SerializeAvailabilityInfo` skip) and their geometry
stays empty (external `.ubulk` not captured). The bone-map
LOD-local→global remap is consumed at glTF-export time (PR6; see
[glTF export mapping](#gltf-export-mapping-gltfskeletalmeshhandler-pr6)).
Deferred: inline-payload bulk-LOD
geometry parsing (future enhancement), cloth sub-payloads, and non-empty
`FSkinWeightProfilesData`. **After PR5c the LOD wire structure is fully
traversed (cursor-correct for every LOD, cooked UE 4.24+); the remaining
items above are geometry-*decode* gaps, not traversal gaps.**

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| UE 4.0+ | `USkeletalMesh` + `FStaticLODModel` introduced. | `CUE4Parse/UE4/Assets/Exports/SkeletalMesh/USkeletalMesh.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d`[^1] |
| UE 4.16 (`FSkeletalMeshCustomVersion.SplitModelAndRenderData`) | Cooked LOD records split from editor LOD model; `bCooked` gate added at `USkeletalMesh.Deserialize` level. | Same[^1] |
| UE 4.16 (`FSkeletalMeshCustomVersion.CombineSectionWithChunk`) | Section and chunk merged; `FSkelMeshChunk` only present pre-this version. | Same[^1] |
| UE 4.20 (object version 504) | Skin-weight precision split; `bExtraBoneInfluences` variant. | Same[^1] |
| UE 4.24 (`FAnimObjectVersion.IncreaseBoneIndexLimitPerChunk`) | `bUse16BitBoneIndex` added (in both `FSkelMeshSection` and `FSkinWeightVertexBuffer`). | Same[^1] |
| UE 4.24 (`FRenderingObjectVersion ≥ MaterialShaderMapIdSerialization`) | `UseNewCookedFormat` boundary: cooked LODs switch from `SerializeRenderItem_Legacy` to `SerializeRenderItem` (`bIsLODCookedOut` + `bInlined` fields added to the LOD header). | Same[^1]; UEViewer `UnMesh4.cpp`[^2] |
| UE 5.0+ | Optional cloth simulation data added to LOD payloads. | Same[^1] |

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

### `FStaticLODModel` — cooked render path (`SerializeRenderItem`)

The `SerializeRenderItem` path is the cooked LOD record format for
**UE ≥ 4.24** (`UseNewCookedFormat = Game >= GAME_UE4_24` per CUE4Parse
`VersionContainer`). It is what `read_typed` in `USkeletalMesh.Deserialize`
reaches after the `bCooked` gate. Sources: CUE4Parse `FStaticLODModel.cs`
(`SerializeRenderItem`) at the reference SHA[^1]; gildor UEViewer
`UnMesh4.cpp`.[^2]

Pre-4.24 cooked LODs (4.16–4.23) use a **separate** `SerializeRenderItem_Legacy`
path — a different header with no `bIsLODCookedOut` or `bInlined` fields —
and are not documented here. See the [4.24 format boundary](#ue424-new-cooked-format-boundary)
subsection below.

`LODModels` = `i32` count (capped) + N × the record below.
`read_typed` reaches this array in the cooked branch (`bCooked == true`).

Fields in wire order:

| # | field | size | endian | type | condition |
|---|-------|------|--------|------|-----------|
| 1 | `FStripDataFlags` | 2 | — | `u8` global + `u8` class | unconditional; the **global** byte drives the AV-data gate |
| 2 | `bIsLODCookedOut` | 4 | LE | `u32` (strict bool — `ReadBoolean`: only `0` or `1` accepted) | unconditional |
| 3 | `bInlined` | 4 | LE | `u32` (strict bool — `ReadBoolean`) | unconditional; `true` → streamed blob is inline in this stream; `false` → external `FByteBulkData` (separate `.ubulk` file) |
| 4 | `RequiredBones` | 4 + N×2 | LE | `i32` count + N×`i16` | **unconditional**; bone indices that must be evaluated for this LOD |
| 5 | `Sections` | 4 + N×var | LE | `i32` count + N×`FSkelMeshSection` (`SerializeRenderItem`) | gated: `!IsAudioVisualDataStripped(global) && !bIsLODCookedOut`; see [cooked section record](#fskelmeshsection--cooked-render-path-serializerenderitem) |
| 6 | `ActiveBoneIndices` | 4 + N×2 | LE | `i32` count + N×`i16` | same gate as `Sections` |
| 7 | `BuffersSize` | 4 | LE | `u32` | same gate as `Sections`; byte count of the streamed buffer blob that immediately follows; marks blob-start |
| — | *(streamed blob)* | `BuffersSize` bytes | — | index container + position/tangent/color vertex buffers + `FSkinWeightVertexBuffer` + cloth | immediately follows `BuffersSize`; inline in the stream when `bInlined == true`, external `FByteBulkData` when `false` |

`RequiredBones` is **unconditional** — it is read regardless of the AV-data
strip flag or `bIsLODCookedOut`. `Sections`, `ActiveBoneIndices`, and
`BuffersSize` are all absent when `IsAudioVisualDataStripped(global)` or
`bIsLODCookedOut` is set.

#### UE4.24 new-cooked-format boundary {#ue424-new-cooked-format-boundary}

`SerializeRenderItem` is the cooked LOD format **only** for UE ≥ 4.24. The
discriminator is `FRenderingObjectVersion ≥ MaterialShaderMapIdSerialization`
(a 4.24-era version constant). The `FSkeletalMeshCustomVersion` is identical
across 4.23/4.24/4.25 and cannot be used to distinguish them.

Below 4.24 (4.16–4.23), cooked LODs use `SerializeRenderItem_Legacy`, which
has no `bIsLODCookedOut` or `bInlined` fields. Feeding a legacy-cooked
payload to the new-format reader mis-parses it; the strict `ReadBoolean`
checks on `bIsLODCookedOut` and `bInlined` provide a natural backstop
(values other than 0/1 are rejected with a typed error in most cases).

**Unversioned packages** (the norm for shipping games) carry no in-file
4.23-vs-4.24 signal; both CUE4Parse and UEViewer ultimately gate
`UseNewCookedFormat` on an out-of-band engine version. paksmith degrades
`FRenderingObjectVersion` present-and-below-threshold to `UnsupportedFeature`;
when `FRenderingObjectVersion` is absent (unversioned), it proceeds with the
new format and relies on the strict-bool backstop to reject a legacy-as-new
mis-parse.

#### Streamed blob, the LOD loop, and the BuffersSize seek

The streamed blob (everything from `BuffersSize` onward) contains the index
container, position/tangent/color vertex buffers, `FSkinWeightVertexBuffer`,
and optional cloth buffers — the actual renderable geometry data. The blob is
inline in the stream when `bInlined == true`, or deferred to an external
`.ubulk` when `false`.

`LODModels` = `i32` count (capped) + N × `FStaticLODModel::SerializeRenderItem`.
`read_typed` reads the `LODModels` count and loops over **every** LOD. For each
inlined LOD (`bInlined && block_present`), it parses the header (`FStripDataFlags`
through `BuffersSize`) and then the streamed blob via `read_streamed_data` (the
10-item wire order described in the
[SerializeStreamedData](#serializestreameddata-streamed-blob-cooked-inlined-ue424427)
section below). After `read_streamed_data` completes, `read_typed` **seeks
`blob_start + BuffersSize`** to re-sync the cursor onto the next LOD, where
`blob_start` is the position immediately after `BuffersSize` was read.

The seek is bounded `[blob_end, total_len]` (forward-only on BOTH ends): a
`BuffersSize` so large that `blob_start + BuffersSize > total_len` is rejected;
a `BuffersSize` so small that the seek target falls inside already-parsed blob
bytes (i.e. `< blob_end`) is equally rejected. Either out-of-range case produces
a `SkeletalLodCursorDesync` fault and the asset degrades to `Generic`.

**Why the seek, rather than structural parsing?** After the geometry buffers the
streamed blob carries a version-gated tail (the UE4.27 ray-tracing
`SkipFixedArray`, plus UE5-only morph / vertex-attribute / half-edge buffers).
That tail's `HasRayTracingData` gate is controlled by the engine `Game` enum, not
an in-file version field, and UE4.26 and UE4.27 share `file_version_ue4 = 522`, so
paksmith cannot distinguish them in-band. Rather than guess the gate, `read_streamed_data`
**stops after `FSkinWeightProfilesData`** (the last item it reads) and does NOT
read the version-gated tail at all; the `blob_start + BuffersSize` seek skips it.
This re-syncs correctly for BOTH 4.26 (no tail → the seek is a no-op) and 4.27
(tail present → the seek jumps it) — no over-read and no 4.26 desync. The geometry
buffers (items 2–5) are parsed before the tail and are never affected. See item 10
in the `SerializeStreamedData` table for the tail note.

**UNVERIFIED contract:** `BuffersSize`-as-blob-length is not confirmed by the
oracles. CUE4Parse discards `BuffersSize` entirely (`Ar.Position += 4` at read
time) and navigates structurally between LODs; paksmith has no real cooked
multi-LOD fixture to test against. This is a deliberate, documented divergence
guarded by the cursor-landing sentinel (below): a wrong seek desyncs the cursor
→ `SkeletalLodCursorDesync` → `Generic`, never silent garbage geometry.

A LOD whose block is absent (`IsAudioVisualDataStripped || bIsLODCookedOut`)
leaves geometry empty and is **not** seeked — the cursor stops after
`RequiredBones` and the next LOD header starts immediately. A **non-inlined**
LOD (`bInlined == false`, block present — the external `FByteBulkData`
bulk-streaming path) reads the `FByteBulkData` header (consuming any inline
payload per the bulk flags) and — when `element_count > 0` — skips a byte-exact
`SerializeAvailabilityInfo` metadata block off the main archive to land on the
next LOD. The bulk LOD's geometry stays empty (external `.ubulk` not captured).
See [Non-inlined (bulk) LOD branch](#non-inlined-bulk-lod-branch) below.

#### Post-loop tail (UE4.24–4.27)

After the LOD loop, the following fields are consumed in wire order before the
export payload ends. Source: oracle `USkeletalMesh.Deserialize` @ `cf74fc32`.[^1]

| # | field | size | condition | notes |
|---|-------|------|-----------|-------|
| 1 | `numInlinedLODs` | 1 | inside `UseNewCookedFormat` block (= always for UE4.24+) | `u8`; read and discarded |
| 2 | `numNonOptionalLODs` | 1 | same | `u8`; read and discarded |
| 3 | `dummyObjs` | 4 + N×4 | ungated | `i32` count (capped at `MAX_DUMMY_OBJECTS`) + N × `FPackageIndex`; consumed and discarded |
| 4 | UV-channel skip | 4 + N×4 | `FRenderingObjectVersion` PRESENT **and** `< TextureStreamingMeshUVChannelData(10)` | `SkipFixedArray(4)`: `i32` count + `count × 4` bytes; **never fires** for UE4.24+ (`is_some_and` gate; the 4.24 boundary guarantees present → `≥ 36 > 10`); kept for cursor-math completeness |
| 5 | `FNaniteResources` | — | `Game >= UE5.5` | does NOT fire for UE4.24–4.27; a UE5.5+ asset desyncs into the sentinel |

`FNaniteResources` is positionally inside the cooked block but gated on the
`Game >= UE5.5` engine enum value — out-of-band for paksmith's UE4 range.
The UV-channel skip uses `is_some_and` (not `is_none_or`) so an ABSENT
`FRenderingObjectVersion` does not fire the skip, matching CUE4Parse's
cooked Game-map fallback which returns `≥ 10`.

#### Cursor-landing sentinel

After the LOD loop and the post-loop tail, `read_typed` asserts:

```
cursor.position() == total_len
```

`total_len` is the byte length of the entire export payload. This works because
the `UObject` object-GUID tail (the `bSerializeGuid` bool + optional `FGuid`) is
consumed **early** in `read_typed` (at the end of segment 1, before segment 2
begins), so segment 2 — the LODs + the post-loop tail — runs all the way to the
payload end with nothing trailing.

Any mismatch produces `AssetParseFault::SkeletalLodCursorDesync { position, expected }`,
which the package walker catches and uses to degrade the asset to `Asset::Generic`
(a plain property bag). This is the safety net for the unverified `BuffersSize`
seek: a wrong seek desyncs the cursor off `total_len`, the sentinel fires, and the
result is a conservative generic asset — never garbage geometry.

The sentinel bound is `forward-only`: a seek target outside `[blob_end, total_len]`
is rejected before the seek executes (desync fault without ever moving the cursor),
so a hostile `BuffersSize` cannot seek backward into already-parsed bytes and
re-read them as a fake LOD.

#### Scope and deferrals (PR5c)

PR5c completes the skeletal-mesh **LOD wire traversal** (every cooked UE 4.24+ LOD lands the cursor correctly); the items below are geometry-*decode* gaps. Deferred:

- **Inline-payload bulk-LOD geometry** — when `FByteBulkData.element_count > 0`
  and the bulk flags indicate `ForceInlinePayload`, the geometry lives in the
  inline payload of the `FByteBulkData` record itself (not in an external
  `.ubulk`). `FByteBulkData::read_from` already consumes this payload, but
  paksmith does not extract geometry from it. This is a future enhancement
  requiring a payload-capture change to `read_from`.
- **Bone-map LOD-local→global remap** — each `FSkelMeshSection.BoneMap` is a
  LOD-local-to-global bone index table; the remap from LOD-local indices (used
  in skin-weight data) to skeleton-global indices (needed for glTF export) is
  performed at export time by the `GltfSkeletalMeshHandler` (PR6; see
  [glTF export mapping](#gltf-export-mapping-gltfskeletalmeshhandler-pr6)).

Sources: CUE4Parse[^1]; UEViewer[^2].

### Non-inlined (bulk) LOD branch {#non-inlined-bulk-lod-branch}

When `bInlined == false` and the section/bone block is present (i.e.
`!IsAudioVisualDataStripped && !bIsLODCookedOut`), the LOD's streamed geometry
is in an `FByteBulkData` record: the header lives in the main stream; the
geometry payload is typically in an external `.ubulk` file. paksmith reads the
`FByteBulkData` header via `FByteBulkData::read_from` (which also consumes any
inline payload present — `ForceInlinePayload`/`LazyLoadable`/`None` bulk flags
handled correctly), then — when `element_count > 0` — skips a byte-exact
`SerializeAvailabilityInfo` metadata block off the main archive to land on the
next LOD.

**The bulk LOD's geometry stays empty.** The external `.ubulk` payload is not
captured by the current pak reader, and the rare inline-payload case (`element_count > 0`
with `ForceInlinePayload`) is likewise not decoded — `read_from` already consumed
those bytes, but geometry extraction from them is deferred as a future enhancement.
The completeness win: mixed inline/bulk meshes now **parse** (inlined LODs carry
geometry; bulk LODs are consumed-but-empty) instead of degrading to `Generic`.

**The `element_count > 0` gate (UNVERIFIED):** CUE4Parse gates on
`ElementCount > 0 && Data != null`, but `Data != null` is *file-resolvability*
(can the `.ubulk` payload be opened?) — not a wire fact. paksmith uses
`element_count > 0` alone, its wire-deterministic subset. This is a deliberate
UNVERIFIED contract choice (no non-inlined fixture available to test against),
corroborated by a CUE4Parse UE5.8 branch that gates on `ElementCount > 0` alone.
The cursor-landing sentinel guards a wrong gate: a misread skips past `total_len`
→ `SkeletalLodCursorDesync` → `Generic`, never silent garbage geometry.

Source: CUE4Parse `FStaticLODModel.cs` `SerializeRenderItem` else-branch[^1].

### `SerializeAvailabilityInfo` — non-inlined LOD metadata skip {#serializeavailabilityinfo}

Called when `element_count > 0` on the non-inlined path. This block is written
by the cooker off the main archive (not inside the `FByteBulkData` payload).
**The skip is byte-exact** — no seek to re-sync, so every addend must be
accounted for precisely. Source: CUE4Parse `FStaticLODModel.SerializeAvailabilityInfo`[^1].

**Constant region** (always present):

| addend | bytes | field |
|--------|-------|-------|
| `FMultiSizeIndexContainer` index meta | 5 = `1 + 4` | `DataSize` (1 byte) + `ElementCount` (`i32`) |
| Adjacency index meta | 5 | Present iff `FUE5ReleaseStreamObjectVersion < RemovingTessellation` (`is_none_or` — UE4's absent version → true) **AND** LOD `class` strip byte does NOT have `CDSF_AdjacencyData (0x01)`. |
| `FStaticMeshVertexBuffer` meta | 16 | Tangent/UV buffer metadata. |
| `FPositionVertexBuffer` meta | 8 | Position buffer metadata. |
| `FColorVertexBuffer` meta | 8 | Color buffer metadata. |
| `FSkinWeightVertexBuffer` metadata | **12** (UE4.24) or **24** (UE4.25+) | See `MetadataSize` derivation below. |

The `FSkinWeightVertexBuffer` metadata size (`MetadataSize`) is derived using
the same custom-version comparisons the live reader uses (anti-drift):

- `FAnimObjectVersion < UnlimitedBoneInfluences(5)` → **12** (legacy, UE4.24).
- `FAnimObjectVersion >= UnlimitedBoneInfluences(5)` → `16 + 4 + precision_term + 4`:
  - `+4` for `IncreaseBoneIndexLimitPerChunk` is unconditional on this path
    (`UnlimitedBoneInfluences(5) > IncreaseBoneIndexLimitPerChunk(4)`, so the
    new-format gate already implies the bone-limit gate).
  - `precision_term = 4` if `FUE5MainStreamObjectVersion >= IncreasedSkinWeightPrecision(90)`,
    else `0` (always `0` for UE4.24–4.27; fires only on UE5 assets).
  - `+4` unconditional trailing term.
  - UE4.25–4.27 result: **24** (`16 + 4 + 0 + 4`).

The `!UseNewCookedFormat → 8` legacy-legacy branch from the oracle is unreachable
here: `read_typed`'s UE4.24 `MaterialShaderMapIdSerialization` gate guarantees
`UseNewCookedFormat` is active before any LOD is read.

**Live count-driven reads** (off the main archive, each count capped before the skip):

1. **Cloth** — only when any section has cloth data (`sections.iter().any(|s| s.has_cloth_data)`):
   read a capped `i32 num`; skip `num × 8 + 8` bytes; then iff
   `FUE5ReleaseStreamObjectVersion >= AddClothMappingLODBias(15)` (UE5-only, never
   fires for UE4), skip `num × 4` more bytes.

2. **`SkinWeightProfiles`** (UNCONDITIONAL): read a capped `i32 count`; skip `count × 8`
   bytes (`count` × `FName`-pair = `NameIndex i32` + `Number i32`).

3. **Ray-tracing** — `HasRayTracingData && Game >= UE5.6`: never fires for the UE4 range
   paksmith targets. A UE5.6 asset reaching here desyncs into the post-loop sentinel →
   `Generic`.

**Worked example — UE4.25+, no cloth, adjacency present, profiles count 0:**

```
5   (FMultiSizeIndexContainer index meta: 1+4)
+ 5   (adjacency meta: present, UE4 → FUE5ReleaseStreamObjectVersion absent)
+ 16  (FStaticMeshVertexBuffer meta)
+ 8   (FPositionVertexBuffer meta)
+ 8   (FColorVertexBuffer meta)
+ 24  (FSkinWeightVertexBuffer MetadataSize, UE4.25+: 16+4+0+4)
= 66  constant bytes skipped
+ 4   (SkinWeightProfiles i32 count = 0; no further skip)
= 70  total bytes consumed
```

Sources: CUE4Parse `FStaticLODModel.SerializeAvailabilityInfo` and
`FSkinWeightVertexBuffer.MetadataSize`[^1].

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
| 6 | `RecomputeTangentsVertexMaskChannel` | 1 | — | `u8` | `FRecomputeTangentCustomVersion ≥ RecomputeTangentVertexColorMask`; default `3` (`ESkinVertexColorChannel::None`) |
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

### `SerializeStreamedData` — streamed blob (cooked, inlined; UE4.24–4.27) {#serializestreameddata-streamed-blob-cooked-inlined-ue424427}

Immediately follows the LOD header's `BuffersSize` field when
`bInlined == true && !IsAudioVisualDataStripped && !bIsLODCookedOut`.
Source: CUE4Parse `FStaticLODModel.cs` `SerializeStreamedData` @ `cf74fc32`.[^1]

Ten items in wire order. **paksmith reads items 1–9 and STOPS** — it does not
read item 10 (the version-gated tail); the `blob_start + BuffersSize` seek in
`read_typed` skips it (see the iteration note above).

| # | item | condition | notes |
|---|------|-----------|-------|
| 1 | inner `FStripDataFlags` | unconditional | 2×`u8` (global + class); the `class` byte drives the adjacency gate (item 7) |
| 2 | `Indices` — `FMultisizeIndexContainer` | unconditional | skeletal index buffer; see [`FMultisizeIndexContainer`](#fmultisizeindexcontainer) below |
| 3 | `PositionVertexBuffer` | unconditional | reuses static-mesh position buffer wire shape |
| 4 | `StaticMeshVertexBuffer` | unconditional | tangents + UVs; reuses static-mesh vertex buffer wire shape |
| 5 | `FSkinWeightVertexBuffer` | unconditional | per-vertex bone indices + weights; see [`FSkinWeightVertexBuffer`](#fskinweightvertexbuffer) below |
| 6 | `ColorVertexBuffer` | `bHasVertexColors` tagged property is `true` (NOT a wire field; default `false`) | segment-1 tagged property `GetOrDefault<bool>("bHasVertexColors")` drives this gate |
| 7 | `AdjacencyIndexBuffer` — `FMultisizeIndexContainer` | `FUE5ReleaseStreamObjectVersion` absent **or** `< RemovingTessellation(3)`, **and** `!IsClassDataStripped(CDSF_AdjacencyData=1)` | UE4 always lacks `FUE5ReleaseStreamObjectVersion`, so the first half is always true; the class-strip bit from item 1 gates it; read-and-discard |
| 8 | `ClothVertexBuffer` | `HasClothData()` — any parsed section's `ClothMappingDataLODs` is non-empty | see cloth shape note below; paksmith defers cloth (skips) |
| 9 | `FSkinWeightProfilesData` | **unconditional** | `i32` count (must be ≥ 0) + `count` entries; `count == 0` is the cooked norm and proceeds; `count > 0` is not decoded — paksmith rejects with `UnsupportedFeature`. **This is the LAST item paksmith reads.** |
| 10 | ray-tracing geometry tail | `HasRayTracingData` (UE 4.27+): `SkipFixedArray(1)` — `i32` count + `count × 1` byte | **paksmith does NOT read this item** (nor the UE5-only morph / vertex-attribute / half-edge tails that would follow on a UE5 wire). Its `HasRayTracingData` gate is controlled by the engine `Game` enum, and UE4.26 and UE4.27 share `file_version_ue4 = 522`, so paksmith cannot distinguish them in-band — a version gate would mis-fire on 4.26 (which lacks this tail) and mis-read the next LOD's header as a spurious count → desync. Instead `read_streamed_data` stops after item 9 and the `blob_start + BuffersSize` seek in `read_typed` skips the entire tail. This re-syncs correctly for BOTH 4.26 (no tail → no-op seek) and 4.27 (tail present → the seek jumps it) |

**Cloth buffer shape (item 8, skipped):** inner `FStripDataFlags` (2×`u8`); if
AV-stripped, done; else `SkipBulkArrayData` (the cloth vertex bulk array); then —
when `FSkeletalMeshCustomVersion ≥ CompactClothVertexBuffer` (always true for
UE 4.24+) — `ClothIndexMapping`: `i32` count + `count × u64`.

### `FMultisizeIndexContainer`

Skeletal-mesh index buffer. Wire shape (UE 4.24+, `bOldNeedsCPUAccess` prefix
absent — not present on the 4.24+ cooked path):[^1]

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `DataSize` | 1 | — | `u8` | Per-index byte width; MUST be exactly `2` (16-bit indices) or `4` (32-bit indices). paksmith rejects any other value — stricter than CUE4Parse, which treats any `DataSize != 2` as 4-byte and silently mis-aligns corrupted data. |
| `elementSize` | 4 | LE | `i32` | Bulk-array header: bytes per element (cross-check against `DataSize`). |
| `elementCount` | 4 | LE | `i32` | Element count; sign-checked and capped at `MAX_INDICES_PER_LOD`. |
| `Indices` | variable | — | `u16[]` or `u32[]` | `elementCount` indices of `DataSize` bytes each; `u16` entries are widened to `u32`. |

This type is structurally distinct from `FRawStaticIndexBuffer` (the static-mesh
index buffer, documented in [`vertex-formats.md`](vertex-formats.md)
§*FRawStaticIndexBuffer / FMultisizeIndexContainer*): `FRawStaticIndexBuffer`
leads with a `u32 is32bit` bool and a byte-array bulk payload; `FMultisizeIndexContainer`
leads with a `u8 DataSize` and a typed-element bulk array.

### `FSkinWeightVertexBuffer`

Per-vertex skin-weight payload. Path is dispatched on
`bNewWeightFormat = FAnimObjectVersion ≥ UnlimitedBoneInfluences(5)`:
UE 4.24 takes the LEGACY path; UE 4.25+ takes the NEW path.[^1]

**Key per-vertex influence count rule (both paths):**
`num_skel = maxBoneInfluences > 4 ? 8 : 4`

This means `maxBoneInfluences ∈ {1,2,3,4}` → 4 influences per vertex, and
`maxBoneInfluences ∈ {5,6,7,8}` → 8 influences. Using `maxBoneInfluences`
directly as the stride desyncs for values in {5,6,7} — the `> 4 ? 8 : 4` rule
is the oracle-correct formula.

**Legacy path** (`!bNewWeightFormat` — UE 4.24):

| # | field | size | endian | type | semantics |
|---|-------|------|--------|------|-----------|
| 1 | `FStripDataFlags` | 2 | — | 2×`u8` | Global AV-stripped bit gates the weight data read. |
| 2 | `bExtraBoneInfluences` | 4 | LE | `u32` (bool) | `true` → `num_skel = 8`; `false` → `num_skel = 4`. |
| 3 | `Stride` (optional) | 4 | LE | `u32` | Present only when `FSkeletalMeshCustomVersion ≥ SplitModelAndRenderData`; read-and-discarded. |
| 4 | `NumVertices` | 4 | LE | `u32` | Capped at `MAX_VERTICES_PER_LOD`. |
| 5 | `Weights` (bulk `FSkinWeightInfo[]`) | variable | — | bulk header (`elementSize i32`, `elementCount i32`) + data | Absent when AV-stripped. Per vertex: `num_skel × u8` bone indices then `num_skel × u8` weights; widened to `[u16;8]` / `[u8;8]` zero-padded to 8 slots. |

**New-format path** (`bNewWeightFormat` — UE 4.25+):

| # | field | size | endian | type | semantics |
|---|-------|------|--------|------|-----------|
| 1 | `FStripDataFlags` | 2 | — | 2×`u8` | Global AV-stripped bit gates `newData`; retained for the gate below. |
| 2 | `bVariableBonesPerVertex` | 4 | LE | `u32` (bool) | `true` → variable-bones path: per-vertex influences are offset-indexed via the lookup table (see below) rather than fixed-stride. |
| 3 | `MaxBoneInfluences` | 4 | LE | `u32` | Capped at `MAX_INFLUENCES(8)`. Drives `num_skel = > 4 ? 8 : 4`. |
| 4 | `NumBones` | 4 | LE | `u32` | Total addressable bones; capped at `MAX_BONES_PER_MESH`. |
| 5 | `NumVertices` | 4 | LE | `u32` | Capped at `MAX_VERTICES_PER_LOD`. |
| 6 | `bUse16BitBoneIndex` | 4 | LE | `u32` (bool) | Present when `FAnimObjectVersion ≥ IncreaseBoneIndexLimitPerChunk(4)` — **always present** on the new path because `IncreaseBoneIndexLimitPerChunk(4) < UnlimitedBoneInfluences(5)`. |
| 7 | `bUse16BitBoneWeight` | 4 | LE | `u32` (bool) | Present when `FUE5MainStreamObjectVersion ≥ IncreasedSkinWeightPrecision(90)` — **UE5-only**; always absent for UE4.24–4.27. |
| 8 | `newData` (bulk `byte[]`) | variable | — | bulk header + raw bytes | Gated on the **data** strip flags' AV bit (field 1). Raw per-vertex influence bytes; capped at `MAX_SKIN_WEIGHT_DATA_BYTES = MAX_VERTICES_PER_LOD × 32`. |
| 9 | lookup block | unconditional header | — | `FStripDataFlags` (2×`u8`) + `numLookupVertices` (`i32`) + `LookupData` bulk | The lookup **header** is unconditional; `LookupData` (`u32[]` bulk array) is gated on the **lookup's own** AV bit — NOT the data strip flags from field 1. |

Per-vertex decode from `newData` (fixed-stride path, `!bVariableBonesPerVertex`):
sequential blocks of `num_skel` bone indices (`u16` when `bUse16BitBoneIndex`,
else `u8`→`u16`) then `num_skel` weights — `u8` (`BoneWeights::U8`), or `u16`
losslessly (`BoneWeights::U16`) when `bUse16BitBoneWeight`. Results are
zero-padded to `[u16;8]` / `[u8;8]` / `[u16;8]`.

Per-vertex decode (variable-bones path, `bVariableBonesPerVertex == true`):
`LookupData` carries one `u32` per vertex (`LookupData.Length == NumVertices`).
For vertex `i`, the high 24 bits (`LookupData[i] >> 8`) are the byte OFFSET of the
vertex's record within `newData`, and the low 8 bits (`LookupData[i] & 0xFF`) are
its influence COUNT — except a low byte of `0` falls back to `num_skel`
(`MaxBoneInfluences > 4 ? 8 : 4`), which means "use the fixed default", NOT a
zero-influence vertex. Each record is read by random-access seek to its offset
(offsets need not be contiguous and may leave gaps), then `count` bone indices
followed by `count` weights (same `u8`/`u16` widths as the fixed-stride path),
zero-padded to 8 slots. A count exceeding `MAX_INFLUENCES(8)` is rejected.

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

The `WeightData` payload size when `bVariableBonesPerVertex == 0` is
`NumVertices × num_skel × (bone_index_size + bone_weight_size)`, where
`num_skel = MaxBoneInfluences > 4 ? 8 : 4` (NOT `MaxBoneInfluences` directly).
With the example values: `MaxBoneInfluences=4 → num_skel=4`, so
`4 × 4 × (1 + 1) = 32 bytes`. A mesh with `MaxBoneInfluences=5` would yield
`num_skel=8` (not 5) and `4 × 8 × (1 + 1) = 64 bytes`. When
`bVariableBonesPerVertex == 1`, the actual payload is variable length and the
trailing lookup table (`FStripDataFlags + uint[]`) indexes per-vertex offsets
into `WeightData`.

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

**Parser modules:**
- `crates/paksmith-core/src/asset/exports/mesh/skeletal_mesh.rs` — `read_typed` (full cooked UE 4.24+ path: LOD loop + inlined-LOD streamed blob + post-loop tail + cursor-landing sentinel), `read_streamed_data` (the 10-item blob orchestration), `read_lod_post_loop_tail` (post-loop tail + sentinel), `read_static_lod_model` (LOD header → `LodHeader`), `read_skel_mesh_section_render` (per-section cooked record).
- `crates/paksmith-core/src/asset/exports/mesh/skin_weights.rs` — `read_skin_weight_vertex_buffer` (LEGACY + NEW paths), `read_multisize_index_container`.

**Status (PR5c, Phase 3h — LOD traversal complete for cooked UE 4.24+):** All inlined LODs' geometry is
parsed: indices, positions, normals/tangents/UVs, per-vertex bone
indices/weights, and vertex colors. Non-inlined (bulk) LODs are consumed
(FByteBulkData header + SerializeAvailabilityInfo skip) with geometry left
empty. The LOD loop, the `BuffersSize` seek, the non-inlined bulk path,
`skip_availability_info`, the post-loop tail, and the cursor-landing sentinel
are all implemented. The bone-map LOD-local→global remap is consumed by the
glTF exporter (PR6; see the export-mapping section below). Both fixed-stride and
variable-bones-per-vertex skin weights, and UE5 16-bit bone weights, are decoded.
Deferred: inline-payload bulk-LOD geometry parsing (future enhancement), cloth
sub-payloads, non-empty `FSkinWeightProfilesData`.

**Phase plan:** `docs/plans/ROADMAP.md` Phase 3 (Export Pipeline) +
Phase 9 (3D Viewport).

### glTF export mapping (`GltfSkeletalMeshHandler`, PR6)

This section documents how paksmith **lowers** a parsed `USkeletalMesh` into a
self-contained skinned glTF 2.0 binary (`.glb`) — the export-side mapping, NOT a
wire format. The skin semantics follow the glTF 2.0 specification's skinning
chapter: <https://registry.khronos.org/glTF/specs/2.0/glTF-2.0.html#skins>.
Source: `crates/paksmith-core/src/export/skeletal_mesh.rs` +
`crates/paksmith-core/src/export/gltf_common.rs`.

#### Coordinate basis

paksmith bakes the UE→glTF change-of-basis `B` directly into vertex positions
via `convert_position`: a UE vertex `(x, y, z)` (left-handed, Z-up, centimetres)
maps to glTF `(0.01·x, 0.01·z, 0.01·y)` — a cm→m scale of `0.01` plus a Y↔Z axis
swap (the swap also flips handedness, basis determinant `−1`). `B` is the pure
linear `0.01·P` form of that mapping (no translation).

To keep the skeleton in the SAME frame as the baked geometry, each bone node's
local glTF matrix is the conjugation `B · L · B⁻¹`, where `L` is that bone's
(child-relative) bind transform. This conjugation makes the node-hierarchy
product telescope to a node-global `B · G · B⁻¹` (`G` = the global bind, the
parent-chain product). The inverse-bind-matrices are correspondingly
`(B · G · B⁻¹)⁻¹ = B · G⁻¹ · B⁻¹`, so `jointGlobal · IBM = I` for every joint in
the bind pose and a fully-weighted vertex renders at rest. This is paksmith's
emission math, not a UE wire fact.

#### Bone nodes and skin

The exporter emits one glTF `node` per bone in skeleton order (parallel to the
reference skeleton's bone list), parenting each via the bone's `parent_index`
(`−1` denotes a root). A single glTF `skin` ties the joint list (those bone
nodes) to an `inverseBindMatrices` accessor (`MAT4`, `F32`, no `bufferView`
target — per the glTF spec, the IBM bufferView MUST NOT declare a target). The
IBMs are computed from the reference-skeleton bind pose with `glam`'s f64 math
and narrowed to f32 on emit. The mesh node that carries the skin is
identity-transformed: glTF skinning folds in `inverse(meshNodeGlobal)`, so a
non-identity mesh node would break the bind pose.

#### Skin attributes

Each LOD's primitives carry the geometry attributes (`POSITION`, `NORMAL`,
`TANGENT`, `TEXCOORD_n`, `COLOR_0`) plus the skin attributes:

- `JOINTS_0` — `VEC4`; `UNSIGNED_BYTE` when the skeleton has ≤ 256 bones, else
  `UNSIGNED_SHORT`; **not** normalized.
- `WEIGHTS_0` — `VEC4`, `UNSIGNED_BYTE`, **normalized**.
- `JOINTS_1` / `WEIGHTS_1` — a second `VEC4` pair, emitted **only** when at least
  one vertex in the LOD uses an influence slot beyond the first four (more than
  four influences).

#### Bone-map remap

Per-vertex bone indices in the skin-weight buffer are **LOD-section-local**: they
index into the owning `FSkelMeshSection`'s `BoneMap`, not the global skeleton. At
emit time each vertex is matched to the section whose
`[base_vertex_index, base_vertex_index + num_vertices)` range contains it, and
its local indices are remapped to global skeleton indices through THAT section's
`bone_map`. The LOD-union bone map is deliberately not used. (On the rare
overlap of two sections' ranges, the later section in iteration order wins.)

#### Weight normalization

UE stores per-vertex skin weights as `u8` influences summing to `255`. glTF
requires each vertex's normalized weights to sum to `≈ 1.0`, i.e. the emitted
`u8` bytes to sum to `255`. paksmith renormalizes by folding the residual
(`255 − sum`) into the vertex's largest-weight slot with saturating arithmetic.
For cooked weights authored to sum near `255` this yields an emitted sum of
exactly `255`; the known edge case where raw weights sum well above `255` can
clip and leave the post-fold sum slightly under `255` is outside the verified
scope (cooked content does not exercise it). A vertex whose influence weights
sum to zero — degenerate, or claimed by no section — is bound to the root bone
(skeleton index `0`) at rest, `(255, 0, 0, 0)`; because `jointMatrix · IBM = I`
for the root in the bind pose, such vertices render at rest and stay glTF-valid.

#### Deferrals (bind pose only)

3h exports the mesh in its **bind pose** only. Out of scope for this phase,
consistent with the design doc's *Out of scope* list: `UAnimSequence` animation
tracks (→ glTF `animations`), morph targets (`UMorphTarget` blend shapes),
sockets (per-bone attachment points), and cloth surfacing — cloth wire blocks
are byte-skipped by the parser but not surfaced in the exported glTF.

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Exports/SkeletalMesh/USkeletalMesh.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` plus `FStaticLODModel.cs`, `FSkelMeshSection.cs`, `FSkinWeightVertexBuffer.cs` in the same directory. Primary oracle; covers every version conditional paksmith will need. Note: CUE4Parse uses `FStaticLODModel` for the cooked LOD record; there is no `FSkeletalMeshRenderData` wrapper class or `FSkeletalMeshLODRenderData`/`FSkelMeshRenderSection` at this SHA.

[^2]: `gildor/UEViewer` (Gildor's UModel) — `Unreal/UnrealMesh/UnMesh4.cpp`. Secondary oracle for cooked `FStaticLODModel` LOD header layout (`SerializeRenderItem` field order, `RequiredBones` position, `UseNewCookedFormat` boundary). Consulted to cross-validate CUE4Parse field ordering for the PR3/PR4 wire facts.
