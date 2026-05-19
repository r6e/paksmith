# UE Mesh Family Documentation — PR 9 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Populate `docs/formats/mesh/` with four documents — `static-mesh.md` (`UStaticMesh`), `skeletal-mesh.md` (`USkeletalMesh`), `skeleton.md` (`USkeleton` — the bone hierarchy referenced by `SkeletalMesh`), and `vertex-formats.md` (packed vertex layouts shared across both mesh types). All four are `partial | not impl`: paksmith has no mesh parser code yet (Phase 3+ deliverable). Add four rows to the root inventory.

**Architecture:** Mesh formats are the densest binary structures in cooked UE content — heavy version-conditional branching across UE 4.20, 4.25, 4.27, and the UE5 line, with optional Nanite + virtual-shadow-map metadata that adds another dimension. The docs document the structural skeleton (LOD record shapes, vertex / index buffer layouts, skin weight encoding) from oracle references and explicitly mark the per-version conditionals as Phase 3+ work to enumerate exhaustively. The `vertex-formats.md` doc is shared infrastructure: both static and skeletal meshes serialize packed vertex layouts (`FPositionVertex`, `FStaticMeshUVItem`, `FPackedNormal`, etc.) that benefit from a single reference.

**Tech Stack:** Pure markdown. PR 1 linters. Primary oracle is `FabianFG/CUE4Parse/UE4/Assets/Exports/StaticMesh/` and `SkeletalMesh/`; secondary is `AstralOrigin/unreal_asset/unreal_asset/src/exports/`. The mesh readers are among the most version-conditional code in either oracle, so cross-validation will be load-bearing for Phase 3.

**Spec reference:** `docs/design/2026-05-19-ue-format-docs.md` (commit `72b364e`). **Prerequisite:** PR 1 (framework scaffold) has merged to `main`.

---

## Prerequisites

Follow [PREAMBLE.md](2026-05-19-ue-format-docs-PREAMBLE.md). Family name `mesh`; capture `<CUE4PARSE_SHA>` and `<UNREAL_ASSET_SHA>` at preamble Step 7.

## File structure

**Create (4 docs):**

- `docs/formats/mesh/static-mesh.md` — `UStaticMesh`.
- `docs/formats/mesh/skeletal-mesh.md` — `USkeletalMesh`.
- `docs/formats/mesh/skeleton.md` — `USkeleton` (referenced by SkeletalMesh).
- `docs/formats/mesh/vertex-formats.md` — packed vertex layouts shared by both.

**Modify (1):**

- `docs/formats/README.md` — add four rows to the inventory.

**Oracle citation policy.** Primary: `CUE4Parse/UE4/Assets/Exports/StaticMesh/` and `SkeletalMesh/` (per-LOD readers, vertex buffer layouts, skin weight encoding). Secondary: `unreal_asset/src/exports/`. The CUE4Parse readers have visibly heavy version-conditional branching — citations should land on specific lines where the per-version conditional fires.

**Hex-anchor policy.** `(none yet — Phase 3 deliverable)` for all four docs. paksmith has no mesh fixtures; adding them is a Phase 3 task. Suggested fixture set when Phase 3 opens: `minimal_static_mesh_v5.uasset` (UE 4.27 single-LOD), `minimal_skeletal_mesh_v5.uasset` (UE 4.27 single-LOD + minimal skeleton).

---

## Task 1: Per-family setup

Run [PREAMBLE.md](2026-05-19-ue-format-docs-PREAMBLE.md)'s "Per-family setup" with `<family> = mesh`. Capture oracle SHAs at preamble Step 7 for use across this plan's doc citations.

---

## Task 2: Author `docs/formats/mesh/static-mesh.md` (partial)

`UStaticMesh` is the rigid-geometry asset type — environment props,
architectural pieces, anything that doesn't deform at runtime.
On disk: tagged properties + `FStaticMeshRenderData` payload with
the per-LOD vertex / index buffer sets.

**Files:**
- Create: `docs/formats/mesh/static-mesh.md`

**Oracle references:**
- `CUE4Parse/UE4/Assets/Exports/StaticMesh/UStaticMesh.cs`
- `CUE4Parse/UE4/Assets/Exports/StaticMesh/FStaticMeshRenderData.cs`
- `CUE4Parse/UE4/Assets/Exports/StaticMesh/FStaticMeshLODResources.cs`

- [ ] **Step 2: Write the doc**

Write `docs/formats/mesh/static-mesh.md`:

````markdown
# StaticMesh (`UStaticMesh`)

> Rigid-geometry asset — environment props, architectural pieces,
> anything that doesn't deform at runtime. Serialized as a tagged-
> property body followed by an `FStaticMeshRenderData` payload with
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
2. **`FStaticMeshRenderData` payload** — the actual geometry: per-LOD
   `FStaticMeshLODResources` records with vertex / index buffers
   plus per-section ranges.

The per-LOD vertex layout is governed by the shared
[`vertex-formats.md`](vertex-formats.md) catalog.

**Status: not yet implemented in paksmith.** Phase 3+ deliverable.
This doc enumerates the wire layout from CUE4Parse references with
explicit Phase-3 TODO markers in Caps & limits and Verification.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| UE 4.0+ | `UStaticMesh` + `FStaticMeshRenderData` introduced. | `CUE4Parse/UE4/Assets/Exports/StaticMesh/UStaticMesh.cs@<CUE4PARSE_SHA>`[^1] |
| UE 4.20 (`VER_UE4_RENAME_CROUCHMOVESCHARACTERDOWN` ≈ object version 504) | Section info encoding tweaks; vertex buffer layout stable. | Same[^1] |
| UE 4.25 (`VER_UE4_RAW_MESH_BULK_DATA_REMOVED` ≈ 514) | Raw mesh source data removed from cooked output. | Same[^1] |
| UE 4.27 (`VER_UE4_STATIC_MESH_LOD_DEPTHGROUPS` ≈ 522) | LOD depth-group metadata added. | Same[^1] |
| UE 5.0+ | Nanite virtualized-mesh payload (`FStaticMeshNaniteResources`) added when the asset opts in. The classic LOD payload is still present for non-Nanite content / fallback. | Same[^1] |
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

### Segment 2: `FStaticMeshRenderData`

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `bCooked` | 4 | LE | `u32` (bool) | Expected `1` for cooked. |
| `LODs` | variable | — | `FStaticMeshLODResources[]` | Counted-array prefix + per-LOD records. |
| `NaniteResources` (UE5+) | variable | — | `FStaticMeshNaniteResources` | When `NaniteSettings.bEnabled` was true at cook. |
| `Bounds` | 32 | LE | `FBoxSphereBounds` | Origin + extent + sphere radius (3+3+1 floats; native struct). |
| `bLODsShareStaticLighting` | 4 | LE | `u32` (bool) | |
| `bReducedBySimplygon` | 4 | LE | `u32` (bool) | UE 4.27 only. |
| `MinLODs` | variable | — | per-platform overrides | Editor-only-stripped in cooked content. |

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
`FStaticMeshNaniteResources` blob follows the LOD array. The blob
holds the virtualized-mesh page tables; the classic LOD array is
still present (used as fallback on hardware that doesn't support
Nanite).

Paksmith's Phase 3 implementation should make Nanite an opt-in
follow-up rather than a base requirement — the classic LOD payload
is sufficient for most extraction use cases.

### High Precision UVs

UE supports both 16-bit and 32-bit UV coordinate encoding (a setting
on each LOD's vertex buffer). The choice changes the per-vertex UV
size — documented in [`vertex-formats.md`](vertex-formats.md).

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
- **Cross-validation oracle:** CUE4Parse[^1] (primary) and
  `unreal_asset`[^2]. Both decode the full StaticMesh wire surface;
  paksmith will cross-validate when implementing.
- **Known divergences:** none yet — no implementation to diverge.

## Paksmith implementation

**Parser module:** *(not yet implemented — planned under
`crates/paksmith-core/src/asset/exports/mesh/static_mesh.rs`)*

**Status:** `not implemented`. Encounters of `StaticMesh` exports
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
5. Add fixtures + cross-validation against unreal_asset[^2].

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Exports/StaticMesh/UStaticMesh.cs@<CUE4PARSE_SHA>` plus `FStaticMeshRenderData.cs`, `FStaticMeshLODResources.cs`, `FStaticMeshSection.cs` in the same directory. Primary oracle; covers every version conditional paksmith will need.
[^2]: `AstralOrigin/unreal_asset/unreal_asset/src/exports/static_mesh_export.rs@<UNREAL_ASSET_SHA>` — Rust counterpart. Will be paksmith's fixture-gen cross-validation oracle when Phase 3 lands.
````

- [ ] **Step 3: Commit** (preamble convention — required-headings linter must pass before commit)

```bash
git add docs/formats/mesh/static-mesh.md
git commit -m "$(cat <<'EOF'
docs(formats): add StaticMesh partial reference

Documents UStaticMesh: tagged-property segment with common
properties (StaticMaterials / BodySetup / LODGroup / LightMap* /
MinLOD / NaniteSettings), the FStaticMeshRenderData payload with
per-LOD records, and the per-section (FStaticMeshSection) shape.
Calls out the Nanite / High-Precision-UV / buffer-compression
variants. partial-not-impl; Phase 3 work scoped.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Author `docs/formats/mesh/skeletal-mesh.md` (partial)

`USkeletalMesh` is the character / deformable-geometry asset type.
Same shape as `StaticMesh` plus skin weights, bone influences, and a
reference to a `USkeleton` for the bone hierarchy.

**Files:**
- Create: `docs/formats/mesh/skeletal-mesh.md`

**Oracle references:**
- `CUE4Parse/UE4/Assets/Exports/SkeletalMesh/USkeletalMesh.cs`
- `CUE4Parse/UE4/Assets/Exports/SkeletalMesh/FSkeletalMeshRenderData.cs`
- `CUE4Parse/UE4/Assets/Exports/SkeletalMesh/FSkeletalMeshLODRenderData.cs`

- [ ] **Step 2: Write the doc**

Write `docs/formats/mesh/skeletal-mesh.md`:

````markdown
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
| UE 4.0+ | `USkeletalMesh` + `FSkeletalMeshRenderData` introduced. | `CUE4Parse/UE4/Assets/Exports/SkeletalMesh/USkeletalMesh.cs@<CUE4PARSE_SHA>`[^1] |
| UE 4.20 (~object version 504) | Skin-weight precision split (8-bit-bone-influence variant added). | Same[^1] |
| UE 4.24 (~object version 510) | 16-bit-bone-influence variant added for meshes referencing > 256 bones. | Same[^1] |
| UE 4.26 (~object version 518) | `FSkinWeightDataVertexBuffer` shape revised. | Same[^1] |
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
| `LODRenderData` | variable | — | `FSkeletalMeshLODRenderData[]` | Counted-array prefix + per-LOD records. |
| `bRequiresFullPrecisionUVs` | 4 | LE | `u32` (bool) | If `1`, UVs serialized as 32-bit floats; otherwise 16-bit halves. |
| `bHasVertexColors` | 4 | LE | `u32` (bool) | |
| `Bounds` | 32 | LE | `FBoxSphereBounds` | Mesh bounds. |

### `FSkeletalMeshLODRenderData` (per-LOD record)

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `RenderSections` | variable | — | `FSkelMeshRenderSection[]` | Counted-array prefix + per-section records. |
| `Indices` | variable | — | `FMultisizeIndexContainer` | Index buffer (16-bit or 32-bit elements). |
| `ActiveBoneIndices` | variable | — | `i16[]` | Bones referenced by this LOD. |
| `RequiredBones` | variable | — | `i16[]` | Bones that must be evaluated for this LOD. |
| `PositionVertexBuffer` | variable | — | `FPositionVertexBuffer` | Per-vertex positions. See [`vertex-formats.md`](vertex-formats.md). |
| `StaticMeshVertexBuffer` | variable | — | `FStaticMeshVertexBuffer` | Per-vertex normal-tangent + UVs. |
| `SkinWeightVertexBuffer` | variable | — | `FSkinWeightVertexBuffer` | Per-vertex bone indices + weights. |
| `ColorVertexBuffer` (optional) | variable | — | `FColorVertexBuffer` | Per-vertex colors when `bHasVertexColors == 1`. |
| `AdjacencyIndexBuffer` (optional) | variable | — | `FMultisizeIndexContainer` | Tessellation adjacency. |
| `ClothVertexBuffer` (optional) | variable | — | `FSkeletalMeshVertexClothBuffer` | Cloth-simulation per-vertex data. |

### `FSkelMeshRenderSection` (per-draw-call record)

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
- **Cross-validation oracle:** CUE4Parse[^1] and `unreal_asset`[^2].
- **Known divergences:** none yet.

## Paksmith implementation

**Parser module:** *(not yet implemented — planned under
`crates/paksmith-core/src/asset/exports/mesh/skeletal_mesh.rs`)*

**Status:** `not implemented`. Same fall-through-to-`Opaque`
behavior as static-mesh today.

**Phase plan:** `docs/plans/ROADMAP.md` Phase 3 (Export Pipeline) +
Phase 9 (3D Viewport).

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Exports/SkeletalMesh/USkeletalMesh.cs@<CUE4PARSE_SHA>` plus `FSkeletalMeshRenderData.cs`, `FSkeletalMeshLODRenderData.cs`, `FSkelMeshRenderSection.cs`, `FSkinWeightVertexBuffer.cs` in the same directory.
[^2]: `AstralOrigin/unreal_asset/unreal_asset/src/exports/skeletal_mesh_export.rs@<UNREAL_ASSET_SHA>` — Rust counterpart.
````

- [ ] **Step 3: Commit** (preamble convention — required-headings linter must pass before commit)

```bash
git add docs/formats/mesh/skeletal-mesh.md
git commit -m "$(cat <<'EOF'
docs(formats): add SkeletalMesh partial reference

Documents USkeletalMesh: tagged-property segment + the Skeleton
reference, FSkeletalMeshRenderData payload with per-LOD records,
per-section bone maps, and the FSkinWeightVertexBuffer skin-weight
layout. Notes the 4-vs-8 bone-influence and 8-vs-16-bit bone-index
variants plus the cloth-simulation / morph-target side data.
partial-not-impl; Phase 3 work scoped.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Author `docs/formats/mesh/skeleton.md` (partial)

`USkeleton` is the bone hierarchy referenced by `USkeletalMesh` and
`UAnimSequence`. Wire content is dominated by the `FReferenceSkeleton`
sub-record (bone names, parent indices, ref-pose transforms) plus
the animation slot manager.

**Files:**
- Create: `docs/formats/mesh/skeleton.md`

**Oracle references:**
- `CUE4Parse/UE4/Assets/Exports/Animation/USkeleton.cs`
- `CUE4Parse/UE4/Assets/Exports/Animation/FReferenceSkeleton.cs`

- [ ] **Step 2: Write the doc**

Write `docs/formats/mesh/skeleton.md`:

````markdown
# Skeleton (`USkeleton`)

> Bone hierarchy referenced by `USkeletalMesh` and `UAnimSequence` —
> bone names, parent indices, and the reference-pose transform per
> bone.

## Overview

`USkeleton` is the asset type holding a character's bone hierarchy.
A SkeletalMesh binds its vertices to a Skeleton via its `Skeleton`
ObjectProperty; an AnimSequence references the same Skeleton so its
bone-track-ordered keyframes match the mesh's bone-index ordering.

The Skeleton itself doesn't carry geometry — it's pure topology
plus a reference pose. Per-bone:

- **Name** — bone identifier (FName).
- **Parent index** — `i32` into the bone array (`-1` = root).
- **Reference-pose transform** — `FTransform` (rotation + translation
  + scale) at bind time.

UE assigns each bone a stable index. The order is determined at
import-from-DCC time and is what AnimSequence keyframes are
indexed against. Renaming a bone in DCC requires a re-import; the
indices are not GUID-stable.

**Status: not yet implemented in paksmith.** Phase 3+ deliverable.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| UE 4.0+ | `USkeleton` + `FReferenceSkeleton` introduced. | `CUE4Parse/UE4/Assets/Exports/Animation/USkeleton.cs@<CUE4PARSE_SHA>`[^1] |
| UE 4.16+ | `FBoneNode` (per-bone metadata) added; `FReferenceSkeleton` shape stable. | Same[^1] |
| UE 4.25+ | Virtual bones (`FVirtualBone`) added; reference skeleton's `Compute*` helpers internal. | Same[^1] |
| UE 5.0+ | LWC (`FTransform` LWC double-precision variant); ref-pose transform width may differ. | Same[^1] |

## Wire layout

### Segment 1: tagged-property stream

| Property name | Type | Semantics |
|---------------|------|-----------|
| `BoneTree` | `ArrayProperty<StructProperty(FBoneNode)>` | Per-bone metadata (translation-retargeting mode, etc.). |
| `RefSkeleton` | (NOT a property — serialized binary, see below) | The bone hierarchy itself. |
| `AnimRetargetSources` | `MapProperty<NameProperty, StructProperty(FReferencePose)>` | Per-source retargeting tables. |
| `SmartNames` | `StructProperty(FSmartNameContainer)` | Curve / morph names; UE 4.13+. |
| `VirtualBones` | `ArrayProperty<StructProperty(FVirtualBone)>` | UE 4.25+. |
| `Sockets` | `ArrayProperty<ObjectProperty(USkeletalMeshSocket)>` | |
| `Notifies` | `ArrayProperty<NameProperty>` | Anim-notify name slots. |
| `Guid` | `StructProperty(Guid)` | Stable identifier for retargeting. |

Properties terminate with the standard `"None"` tag.

### Segment 2: `FReferenceSkeleton` (serialized after properties)

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `RawRefBoneInfo` | variable | — | `FMeshBoneInfo[]` | Counted-array prefix + per-bone metadata. |
| `RawRefBonePose` | variable | — | `FTransform[]` | Per-bone reference-pose transform. |
| `RawNameToIndexMap` | variable | — | `Map<FName, i32>` | FName→bone-index lookup. (Cooked content often omits this since it's recomputable from `RawRefBoneInfo`.) |

### `FMeshBoneInfo` (per-bone record)

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `Name` | 8 | LE | `FName` | Bone name. |
| `ParentIndex` | 4 | LE | `i32` | Index of parent bone in this array; `-1` for root. |
| `ExportName` (editor-only) | variable | — | `FString` | Original DCC name. Stripped from cooked content. |

### `FTransform` (per-bone reference pose)

Native struct, paksmith doesn't tag-decode. Wire layout (UE4 single-precision):

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `Rotation` | 16 | LE | `FQuat` (4 × f32) | Rotation as quaternion. |
| `Translation` | 12 | LE | `FVector` (3 × f32) | Translation. |
| `Scale3D` | 12 | LE | `FVector` (3 × f32) | Per-axis scale. |

Total: 40 bytes per UE4 transform.

UE5 LWC (Large World Coordinates) widens `FVector` from f32 to f64
(24 bytes each instead of 12). The per-transform total becomes
`16 + 24 + 24 = 64` bytes in UE5 LWC content. The choice is
gate-by-asset-version; paksmith's Phase 3 reader will need both
paths.

### Worked example

`(none yet — no skeleton fixture)`. When Phase 3 adds fixtures, the
anchor will be the SkeletalMesh fixture's referenced Skeleton — a
2-or-3-bone minimal skeleton with reasonable ref-pose transforms.

## Variants

### Virtual bones (UE 4.25+)

`FVirtualBone` lets retargeting target a bone derived from two
existing bones (e.g. "midpoint between left-hand and head"). The
asset's `VirtualBones` property carries them; they don't affect the
RawRefBoneInfo array's indexing.

### LWC transforms (UE 5.x)

UE5 widens `FVector` to f64 when `LWC_FLOAT_AND_VECTOR` is active
(default in UE5). Paksmith's Phase 3 reader dispatches on
`file_version_ue5 ≥ 1000` to pick the right transform width.

### Retargeting sources

`AnimRetargetSources` holds named retargeting tables (e.g.
"FromUnreal4Mannequin") so anims authored on one skeleton can play
on another. Each entry is an `FReferencePose` — a per-bone transform
delta against the canonical RawRefBonePose.

## Caps & limits

**Phase 3+ deferred work.**

- `MAX_BONES_PER_SKELETON` cap (likely `2^16` matching the
  16-bit-bone-index ceiling that SkeletalMesh uses for the bone map).
- Allocation caps inherited from the parent property reader's
  `MAX_COLLECTION_ELEMENTS` (the bone arrays are container-property
  arrays of FMeshBoneInfo struct records).

## Verification

- **Fixture:** `(none yet — Phase 3 deliverable)`.
- **Cross-validation oracle:** CUE4Parse[^1] and `unreal_asset`[^2].
- **Known divergences:** none yet.

## Paksmith implementation

**Parser module:** *(not yet implemented — planned under
`crates/paksmith-core/src/asset/exports/mesh/skeleton.rs`)*

**Status:** `not implemented`.

**Phase plan:** `docs/plans/ROADMAP.md` Phase 3. Likely ships
together with SkeletalMesh since they're tightly coupled.

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Exports/Animation/USkeleton.cs@<CUE4PARSE_SHA>` plus `FReferenceSkeleton.cs`, `FMeshBoneInfo.cs` in the same directory.
[^2]: `AstralOrigin/unreal_asset/unreal_asset/src/exports/skeleton_export.rs@<UNREAL_ASSET_SHA>` — Rust counterpart.
````

- [ ] **Step 3: Commit** (preamble convention — required-headings linter must pass before commit)

```bash
git add docs/formats/mesh/skeleton.md
git commit -m "$(cat <<'EOF'
docs(formats): add Skeleton partial reference

Documents USkeleton: tagged-property segment + the FReferenceSkeleton
binary blob (RawRefBoneInfo bone-array, RawRefBonePose transform-
array, optional RawNameToIndexMap). Per-bone wire shape with
FMeshBoneInfo (Name + ParentIndex) and per-bone FTransform
(quaternion + translation + scale; 40 bytes UE4 single-precision /
64 bytes UE5 LWC). Notes virtual bones, retargeting sources, and
the LWC dispatch by file_version_ue5. partial-not-impl; Phase 3
work scoped.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Author `docs/formats/mesh/vertex-formats.md` (partial)

Shared infrastructure: the per-vertex packed layouts used by both
`UStaticMesh` and `USkeletalMesh`. Decoupled into its own doc because
`FPositionVertexBuffer`, `FStaticMeshVertexBuffer`, `FColorVertexBuffer`,
and `FPackedNormal` apply to both mesh types.

**Files:**
- Create: `docs/formats/mesh/vertex-formats.md`

**Oracle references:**
- `CUE4Parse/UE4/Assets/Exports/StaticMesh/FPositionVertexBuffer.cs`
- `CUE4Parse/UE4/Assets/Exports/StaticMesh/FStaticMeshVertexBuffer.cs`
- `CUE4Parse/UE4/Assets/Exports/StaticMesh/FColorVertexBuffer.cs`
- `CUE4Parse/UE4/Objects/Core/Math/FPackedNormal.cs`

- [ ] **Step 2: Write the doc**

Write `docs/formats/mesh/vertex-formats.md`:

````markdown
# Packed vertex formats

> Per-vertex packed binary layouts used by `UStaticMesh` and
> `USkeletalMesh`: positions, normals + tangents, UVs, colors. The
> packing choices trade GPU memory for sample precision.

## Overview

UE's mesh vertex data is **packed** for GPU efficiency. A
single vertex in a cooked mesh isn't a flat `(position, normal,
tangent, uv0, uv1, color)` struct — each component lives in its
own buffer (Structure-of-Arrays layout), and within each buffer
the per-vertex bytes use a packed encoding chosen at cook time
based on the LOD's quality target.

This doc catalogs the buffer-level wire shapes shared across
`static-mesh.md` and `skeletal-mesh.md`. Per-buffer details:

- **Position buffer** — always full f32 precision.
- **Normal-tangent buffer** — typically packed (3 components ×
  10-bit each, or 4 × 8-bit), with a "high precision" override
  for f16-per-component.
- **UV buffer** — typically `f16` halves; "high precision" override
  for `f32`. 0–4 UV channels per vertex.
- **Color buffer** — `FColor` (4 × `u8`) when present; entire buffer
  omitted otherwise.

**Status: not yet implemented in paksmith.** Phase 3+ deliverable.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| UE 4.0+ | Packed vertex formats introduced. | `CUE4Parse/UE4/Assets/Exports/StaticMesh/FPositionVertexBuffer.cs@<CUE4PARSE_SHA>`[^1] |
| UE 4.20+ | High-precision-UV opt-in (`bUseFullPrecisionUVs`) | Same[^1] |
| UE 4.25+ | `FPackedNormal` 10-10-10-2 normal-tangent variant added (replaces 8-8-8-8 by default for newer LODs). | Same[^1] |
| UE 5.0+ | LWC widens `FPositionVertex` from f32 to f64. | Same[^1] |

The 10-10-10-2 vs 8-8-8-8 normal-tangent split is the most-impactful
version-conditional in this doc.

## Wire layout

### `FPositionVertexBuffer`

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `Stride` | 4 | LE | `i32` | Bytes per vertex; typically `12` (UE4 f32 vector) or `24` (UE5 LWC f64 vector). |
| `NumVertices` | 4 | LE | `i32` | Vertex count. |
| `Vertices` | `Stride × NumVertices` | LE | f32 or f64 vec3 | Per-vertex positions. |

UE5 LWC content carries f64 positions; the `Stride` field
disambiguates without paksmith having to read the parent asset's
version explicitly.

### `FStaticMeshVertexBuffer` — normal-tangent + UV layout

The most-complex vertex buffer. Encodes per-vertex normal + tangent
(2 vectors) and 1–4 UV channels.

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `NumTexCoords` | 4 | LE | `i32` | UV channel count (1–4). |
| `Stride` | 4 | LE | `i32` | Bytes per vertex. |
| `NumVertices` | 4 | LE | `i32` | |
| `bUseFullPrecisionUVs` | 4 | LE | `u32` (bool) | If `1`, UVs are `f32`; otherwise `f16` halves. |
| `bUseHighPrecisionTangentBasis` | 4 | LE | `u32` (bool) | If `1`, normal+tangent are `f16` halves (8 bytes); otherwise packed (4 or 8 bytes). |
| `TangentsData` | variable | — | per-vertex packed normal+tangent | See packing dispatch below. |
| `TexCoordData` | variable | — | per-vertex UV × NumTexCoords | f16 or f32 per UV component. |

Per-vertex tangent-basis packing dispatch:

| `bUseHighPrecisionTangentBasis` | UE version | Tangent + Normal encoding | Bytes per vertex |
|----------------------------------|------------|----------------------------|-------------------|
| `false` | UE 4.0+ | `FPackedNormal × 2` (8-8-8-8 each = 4 bytes × 2) | 8 |
| `false` | UE 4.25+ | `FPackedRGBA16N × 2` (10-10-10-2 each, 16-bit total → 4 bytes × 2) | 8 |
| `true` | UE 4.0+ | `FFloat16 × 8` (f16 per component, 4 per normal × 2 normals) | 16 |

(The two `false` cases share the same 8-byte size but different
encodings — the asset version disambiguates. Phase 3 will need to
key off `file_version_ue4 ≥ 514` (`VER_UE4_RAW_MESH_BULK_DATA_REMOVED`,
the version-conditional that gates the 10-10-10-2 default).)

### `FPackedNormal` (8-8-8-8 normal-tangent component)

| offset | size | name | semantics |
|--------|------|------|-----------|
| 0 | 1 | `X` | X component as `i8 / 127` mapped to `[-1, 1]`. |
| 1 | 1 | `Y` | Y component. |
| 2 | 1 | `Z` | Z component. |
| 3 | 1 | `W` | W component (sign bit for tangent handedness). |

Total: 4 bytes per normal or tangent.

### `FPackedRGBA16N` (10-10-10-2 normal-tangent component)

A `u32` packed with 4 fields:

| bits | size | name | semantics |
|------|------|------|-----------|
| 0–9 | 10 | `X` | X component as `u10 / 511 - 1` mapped to `[-1, 1]`. |
| 10–19 | 10 | `Y` | Y component. |
| 20–29 | 10 | `Z` | Z component. |
| 30–31 | 2 | `W` | 2-bit sign for tangent handedness. |

Total: 4 bytes per normal or tangent. Provides ~2× the precision of
the 8-bit variant for the same byte cost.

### `FColorVertexBuffer`

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `Stride` | 4 | LE | `i32` | Typically `4` (FColor = BGRA8). |
| `NumVertices` | 4 | LE | `i32` | |
| `Colors` | `Stride × NumVertices` | LE | `FColor` (4 × `u8`) | BGRA order (not RGBA). |

The whole buffer is omitted when the LOD has no vertex colors —
typically signaled by `bHasVertexColors == 0` on the parent
`FStaticMeshRenderData` or `FSkeletalMeshRenderData`.

### `FRawStaticIndexBuffer` / `FMultisizeIndexContainer`

Index buffers — counts the triangles' vertex references.

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `bShouldUseInt32` (StaticMesh) | 4 | LE | `u32` (bool) | If `1`, 32-bit indices; otherwise 16-bit. |
| `ElementSize` (SkeletalMesh `FMultisizeIndexContainer`) | 1 | — | `u8` | `2` or `4` (bytes per index). |
| `NumIndices` | 4 | LE | `i32` | Index count. |
| `Indices` | `ElementSize × NumIndices` | LE | `u16[]` or `u32[]` | Per-triangle vertex indices, 3 per triangle. |

UE picks 16-bit when the LOD's `MaxVertexIndex < 65,535` (most
production assets); 32-bit only when the LOD exceeds the cap.

### Worked example

`(none yet — no mesh fixture)`. When Phase 3 adds fixtures, the
canonical anchor will be the cube's `FPositionVertexBuffer`:
`Stride = 12, NumVertices = 8, Vertices = [-0.5, -0.5, -0.5, ...]`
giving 4-byte stride header + 4-byte count + 96 bytes of f32 vertex
data.

## Variants

### LWC positions (UE 5.x)

When `FPositionVertexBuffer::Stride == 24`, positions are `f64`
triples (LWC). Phase 3 readers must check stride rather than
hardcoding `f32`.

### High-precision UVs

When `bUseFullPrecisionUVs == 1`, UVs are full `f32` (8 bytes per
UV channel) instead of `f16` halves (4 bytes per channel). Visible
in the buffer's per-vertex `Stride` field.

### 10-10-10-2 vs 8-8-8-8 tangent basis

`bUseHighPrecisionTangentBasis == 0` is the common case;
`== 1` is rare in cooked content. Within the `== 0` case, the
disambiguation between 8-8-8-8 (older) and 10-10-10-2 (newer)
relies on the asset version.

## Caps & limits

**Phase 3+ deferred work.** Per-buffer:

- `Stride × NumVertices` must fit in the parent file's residual
  bytes (caps inherited from `MAX_UNCOMPRESSED_ENTRY_BYTES` /
  `MAX_UEXP_SIZE`).
- A future `MAX_VERTICES_PER_LOD` cap (in addition to the cap above)
  to bound per-LOD allocator amplification.

## Verification

- **Fixture:** `(none yet — Phase 3 deliverable)`.
- **Cross-validation oracle:** CUE4Parse[^1] and `unreal_asset`[^2].
- **Known divergences:** none yet.

## Paksmith implementation

**Parser module:** *(not yet implemented — planned under
`crates/paksmith-core/src/asset/exports/mesh/vertex_formats.rs`,
shared by both `static_mesh.rs` and `skeletal_mesh.rs`)*

**Status:** `not implemented`.

**Phase plan:** `docs/plans/ROADMAP.md` Phase 3.

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Exports/StaticMesh/FPositionVertexBuffer.cs@<CUE4PARSE_SHA>` plus `FStaticMeshVertexBuffer.cs`, `FColorVertexBuffer.cs`, `FRawStaticIndexBuffer.cs`, and `CUE4Parse/UE4/Objects/Core/Math/FPackedNormal.cs` for the bit-packing.
[^2]: `AstralOrigin/unreal_asset/unreal_asset/src/exports/mesh_vertex_buffers.rs@<UNREAL_ASSET_SHA>` — Rust counterpart.
````

- [ ] **Step 3: Commit** (preamble convention — required-headings linter must pass before commit)

```bash
git add docs/formats/mesh/vertex-formats.md
git commit -m "$(cat <<'EOF'
docs(formats): add packed-vertex-formats partial reference

Documents the per-vertex packed binary layouts shared by static and
skeletal meshes: FPositionVertexBuffer (full-f32 / UE5 LWC f64),
FStaticMeshVertexBuffer (normal-tangent + UV with high-precision-
UV and high-precision-tangent-basis opt-ins, plus the 8-8-8-8 vs
10-10-10-2 tangent-basis dispatch), FColorVertexBuffer (BGRA u8),
and FRawStaticIndexBuffer / FMultisizeIndexContainer (16-bit vs
32-bit indices). FPackedNormal and FPackedRGBA16N bit-packing
spelled out. partial-not-impl; Phase 3 work scoped.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: Update root inventory + final verification + push

**Files:**
- Modify: `docs/formats/README.md`

- [ ] **Step 2: Add four rows to the inventory**

Verify the existing inventory layout with `grep -n "^|" docs/formats/README.md`, then use Edit to insert four new rows.

Rows to insert:

```markdown
| `mesh/static-mesh.md` | partial | not impl | — | CUE4Parse @ `<CUE4PARSE_SHA>` | n/a |
| `mesh/skeletal-mesh.md` | partial | not impl | — | CUE4Parse @ `<CUE4PARSE_SHA>` | n/a |
| `mesh/skeleton.md` | partial | not impl | — | CUE4Parse @ `<CUE4PARSE_SHA>` | n/a |
| `mesh/vertex-formats.md` | partial | not impl | — | CUE4Parse @ `<CUE4PARSE_SHA>` | n/a |
```

All four `partial | not impl`. `Last verified` is `n/a` because
there's no implementation to verify against.

- [ ] **Step 6: Run typos**

Run: `typos docs/formats/mesh/`
Expected: clean. Domain terms (`Nanite`, `LWC`, `quaternion`,
`FPackedNormal`, `FPackedRGBA16N`, `FQuat`, `FMultisizeIndexContainer`,
`FSkelMeshRenderSection`) likely to flag — extend `_typos.toml` only
when reword isn't natural.

- [ ] **Step 8: Commit the inventory update**

```bash
git add docs/formats/README.md
git commit -m "$(cat <<'EOF'
docs(formats): register the mesh-family docs in the inventory

Four partial-not-impl rows (static-mesh, skeletal-mesh, skeleton,
vertex-formats): wire format documented from CUE4Parse + unreal_asset
oracles, paksmith implementation deferred to Phase 3. Last-verified
n/a; Phase 3's PR should bump to a real SHA when the mesh readers
land.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

```
<sha> docs(formats): register the mesh-family docs in the inventory
<sha> docs(formats): add packed-vertex-formats partial reference
<sha> docs(formats): add Skeleton partial reference
<sha> docs(formats): add SkeletalMesh partial reference
<sha> docs(formats): add StaticMesh partial reference
```

- [ ] **Step 11: Open the PR**

Title: `docs(formats): populate mesh family (static-mesh/skeletal-mesh/skeleton/vertex-formats)`

Body — write to a tempfile first, then `gh pr create --body-file <tempfile>`:

```markdown
## Summary

Lands PR 9 of the UE format documentation framework. Populates
`docs/formats/mesh/` with four documents:

- **`static-mesh.md`** — `UStaticMesh` tagged-property segment +
  `FStaticMeshRenderData` payload with per-LOD `FStaticMeshLODResources`
  records, `FStaticMeshSection` per-draw-call records, and the
  Nanite-enabled variant.
- **`skeletal-mesh.md`** — `USkeletalMesh` with the `Skeleton`
  reference, `FSkeletalMeshRenderData` payload, per-section bone
  maps, `FSkinWeightVertexBuffer` skin-weight layout, the 4-vs-8
  influence and 8-vs-16-bit-bone-index variants, plus cloth and
  morph-target side data.
- **`skeleton.md`** — `USkeleton` with the `FReferenceSkeleton`
  binary blob: `FMeshBoneInfo` (`Name + ParentIndex`) array and
  per-bone `FTransform` (40 bytes UE4 / 64 bytes UE5 LWC). Virtual
  bones, retargeting sources documented.
- **`vertex-formats.md`** — shared packed-vertex layouts:
  `FPositionVertexBuffer` (`f32` / UE5 LWC `f64`),
  `FStaticMeshVertexBuffer` (normal-tangent + UV with the 8-8-8-8
  vs 10-10-10-2 dispatch), `FColorVertexBuffer` (BGRA `u8`), and
  the index-buffer 16-vs-32-bit width.

All four are `partial | not impl`: wire format documented from
CUE4Parse and unreal_asset oracles, paksmith implementation is
Phase 3+ deferred.

Four rows added to the root inventory, all `partial | not impl`.

## Linked issue

(none — design spec drives this work)

## Test plan

- [x] `paksmith-doc-lint required-headings` passes.
- [x] `paksmith-doc-lint status-enum` passes on the updated inventory.
- [x] `typos docs/formats/mesh/` clean.
- [x] `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features` clean.
- [x] Cross-referenced every wire-format claim against CUE4Parse +
      unreal_asset (no paksmith-side parser to triangulate against).

## Pre-flight checklist

- [x] PR title is a Conventional Commit.
- [x] Branch name follows `<type>/<kebab-case>`.
- [x] `cargo fmt --all` clean (no Rust changed).
- [x] `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean.
- [x] Documentation updated (this PR IS documentation).
- [x] No `unsafe` introduced.
- [x] Touched a parser? No — pure docs PR.

## Security considerations

The docs document the cap shape Phase 3 will need:
`MAX_LODS_PER_MESH`, `MAX_SECTIONS_PER_LOD`, `MAX_BONES_PER_SKELETON`
(`2^16` matching the 16-bit-bone-index ceiling SkeletalMesh uses),
`MAX_VERTICES_PER_LOD`. The packed-vertex doc spells out the
`Stride × NumVertices` budget that the per-LOD vertex allocator
needs to respect.

## Notes for reviewers

- All four docs are `partial | not impl`. The format is rich
  (densest binary structures in UE) so the docs land closer to
  "complete reference for Phase 3 to validate against" than
  "stub-with-pointers"; the partial label reflects the
  not-yet-verified-against-paksmith-code status.
- The vertex-formats doc deliberately splits the static-mesh and
  skeletal-mesh docs' shared concerns into a third doc rather than
  duplicating. The spec's directory layout reserved this slot for
  exactly this purpose.
- The `static-mesh.md` and `skeletal-mesh.md` Worked Example
  sections are `(none yet)` because no mesh fixtures exist. Adding
  them is a Phase 3 deliverable. The Phase 3 plan should produce
  `minimal_static_mesh_v5.uasset` and `minimal_skeletal_mesh_v5.uasset`
  alongside the parser work.
```

---

## Done criteria

Per [PREAMBLE.md](2026-05-19-ue-format-docs-PREAMBLE.md)'s tail (linters green, typos clean, rustdoc clean, PR open, reviewer panel converged), plus this plan's inventory specifics enumerated above.
  (static-mesh, skeletal-mesh, skeleton, vertex-formats).
