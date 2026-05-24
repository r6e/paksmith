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
2. **`FSkeletalMeshRenderData` payload** with per-LOD geometry +
   skin-weight buffers + section records.

The key difference is the per-LOD vertex layout includes
`FSkinWeightVertexBuffer` (per-vertex bone indices + weights) and
the section records carry **bone maps** (the LOD-local-to-global
bone index translation).

**Status: not yet implemented in paksmith.** Phase 3+ deliverable.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| UE 4.0+ | `USkeletalMesh` + `FSkeletalMeshRenderData` introduced. | `CUE4Parse/UE4/Assets/Exports/SkeletalMesh/USkeletalMesh.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d`[^1] |
| UE 4.20 (~object version 504) | Skin-weight precision split (8-bit-bone-influence variant added). | Same[^1] |
| UE 4.24 (~object version 510) | 16-bit-bone-influence variant added for meshes referencing > 256 bones. | Same[^1] |
| UE 4.26 (~object version 518) | `FSkinWeightVertexBuffer` shape revised. | Same[^1] |
| UE 5.0+ | Optional cloth simulation data, virtualized-mesh integration. | Same[^1] |
| UE 5.4+ | Animation-Budget-Allocator integration metadata. | Same[^1] |

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

### Segment 2: `FSkeletalMeshRenderData`

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `bCooked` | 4 | LE | `u32` (bool) | Expected `1`. |
| `LODRenderData` | variable | — | `FStaticLODModel[]` | Counted-array prefix + per-LOD records. |
| `bRequiresFullPrecisionUVs` | 4 | LE | `u32` (bool) | If `1`, UVs serialized as 32-bit floats; otherwise 16-bit halves. |
| `bHasVertexColors` | 4 | LE | `u32` (bool) | |
| `Bounds` | 28 | LE | `FBoxSphereBounds` | Origin (3 × f32) + extent (3 × f32) + sphere radius (1 × f32). |

### `FStaticLODModel` (per-LOD record)

CUE4Parse uses `FStaticLODModel` for the cooked LOD records (the class
`FSkeletalMeshLODRenderData` used in engine source maps to this type in
the oracle).[^1]

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `Sections` | variable | — | `FSkelMeshSection[]` | Counted-array prefix + per-section records. |
| `Indices` | variable | — | `FMultisizeIndexContainer` | Index buffer (16-bit or 32-bit elements). |
| `ActiveBoneIndices` | variable | — | `i16[]` | Bones referenced by this LOD. |
| `RequiredBones` | variable | — | `i16[]` | Bones that must be evaluated for this LOD. |
| `PositionVertexBuffer` | variable | — | `FPositionVertexBuffer` | Per-vertex positions. See [`vertex-formats.md`](vertex-formats.md). |
| `StaticMeshVertexBuffer` | variable | — | `FSkeletalMeshVertexBuffer` | Per-vertex normal-tangent + UVs. |
| `SkinWeightVertexBuffer` | variable | — | `FSkinWeightVertexBuffer` | Per-vertex bone indices + weights. |
| `ColorVertexBuffer` (optional) | variable | — | `FSkeletalMeshVertexColorBuffer` | Per-vertex colors when `bHasVertexColors == 1`. |
| `AdjacencyIndexBuffer` (optional) | variable | — | `FMultisizeIndexContainer` | Tessellation adjacency. |
| `ClothVertexBuffer` (optional) | variable | — | `FSkeletalMeshVertexClothBuffer` | Cloth-simulation per-vertex data. |

### `FSkelMeshSection` (per-draw-call record)

CUE4Parse uses `FSkelMeshSection` for the cooked section records.[^1]

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `MaterialIndex` | 2 | LE | `u16` | Index into `Materials`. |
| `BaseIndex` | 4 | LE | `u32` | First triangle index. |
| `NumTriangles` | 4 | LE | `u32` | Triangle count. |
| `BoneMap` | variable | — | `u16[]` | LOD-local-to-global bone index translation. |
| `NumVertices` | 4 | LE | `u32` | Vertex count contributing to this section. |
| `MaxBoneInfluences` | 4 | LE | `u32` | Bones per vertex (typically 4 or 8). |
| `bUse16BitBoneIndex` (UE 4.24+) | 4 | LE | `u32` (bool) | If `1`, skin-weight bone indices are u16; otherwise u8. |
| `CorrespondClothAssetIndex` (optional) | 2 | LE | `i16` | Cloth-asset slot. |
| `ClothMappingData` (optional) | variable | — | `FMeshToMeshVertData[]` | Cloth-vertex-to-render-vertex mapping. |
| `bDisabled` | 4 | LE | `u32` (bool) | Hide-section flag. |

### `FSkinWeightVertexBuffer`

The per-vertex skin-weight payload. Each vertex carries
`MaxBoneInfluences` `(bone_index, weight)` pairs:

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `bExtraBoneInfluences` | 4 | LE | `u32` (bool) | If `1`, 8 influences per vertex; otherwise 4. |
| `bVariableBonesPerVertex` (UE 4.25+) | 4 | LE | `u32` (bool) | If `1`, per-vertex count varies (uncommon). |
| `MaxBoneInfluences` | 4 | LE | `u32` | Per-vertex influence count. |
| `NumVertices` | 4 | LE | `u32` | |
| `Weights` | variable | — | `[u8 or u16] × Vertex × MaxBoneInfluences` | Bone indices (per `bUse16BitBoneIndex`) interleaved with `u8` weights. |

The exact interleaving is version-conditional; full enumeration is
Phase 3 work.

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
than 256 bones (e.g. crowd characters with merged skeletons). The
flag is per-section via `bUse16BitBoneIndex`.

### Cloth simulation

When a section participates in cloth simulation, additional
`ClothMappingData` and `ClothVertexBuffer` entries appear. Cooked
content rarely strips these (cloth is mostly runtime); Phase 3 can
read past them as opaque bytes for the initial implementation.

### Morph targets

Blend-shape vertex deltas. Each morph target is a separate
`UMorphTarget` UObject referenced by the SkeletalMesh's
`MorphTargets` property. Per-morph-target wire shape lives in a
follow-up doc; the `SkeletalMesh` only carries references.

## Caps & limits

**Phase 3+ deferred work.** Same shape as static-mesh:

- `MAX_LODS_PER_MESH`.
- `MAX_SECTIONS_PER_LOD`.
- A `MAX_BONES_PER_MESH` cap (likely `2^16 = 65,536` to match the
  16-bit-bone-index ceiling).
- Per-LOD buffer caps inherited from underlying file caps.

## Verification

- **Fixture:** `(none yet — Phase 3 deliverable)`.
- **Cross-validation oracle:** CUE4Parse[^1] (sole oracle —
  `AstroTechies/unrealmodding` doesn't ship mesh exports; verified
  HTTP 404 on `unreal_asset/src/exports/{static_mesh,skeletal_mesh,skeleton,mesh_vertex_buffers}_export.rs`).
- **Known divergences:** none yet.

## Paksmith implementation

**Parser module:** *(not yet implemented — planned under
`crates/paksmith-core/src/asset/exports/mesh/skeletal_mesh.rs`)*

**Status:** `not impl`. Same fall-through-to-`Opaque`
behavior as static-mesh today.

**Phase plan:** `docs/plans/2026-05-19-ue-format-docs-mesh.md` Phase 3 (Export Pipeline) +
Phase 9 (3D Viewport).

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Exports/SkeletalMesh/USkeletalMesh.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` plus `FStaticLODModel.cs`, `FSkelMeshSection.cs`, `FSkinWeightVertexBuffer.cs` in the same directory. Primary oracle; covers every version conditional paksmith will need. (The plan named `FSkeletalMeshRenderData.cs`, `FSkeletalMeshLODRenderData.cs`, `FSkelMeshRenderSection.cs` — those files don't exist at this SHA; CUE4Parse uses `FStaticLODModel.cs` and `FSkelMeshSection.cs` for the cooked records.)
