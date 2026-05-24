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
Likely ships together with [`skeletal-mesh.md`](skeletal-mesh.md) since
they're tightly coupled.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| UE 4.0+ | `USkeleton` + `FReferenceSkeleton` introduced. | `CUE4Parse/UE4/Assets/Exports/Animation/USkeleton.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d`[^1] |
| UE 4.12+ (`REFERENCE_SKELETON_REFACTOR`) | `FinalNameToIndexMap` added; `FMeshBoneInfo.BoneColor` dropped from cooked output. This is a UE4 object version constant. | Same[^1] |
| UE 4.16+ | `FBoneNode` (per-bone metadata) added; `FReferenceSkeleton` shape stable. | Same[^1] |
| UE 4.25+ | Virtual bones (`FVirtualBone`) added; reference skeleton's `Compute*` helpers internal. | Same[^1] |
| UE 5.0+ | LWC (`FTransform` double-precision variant); ref-pose transform width may differ. | Same[^1] |

## Wire layout

### Segment 1: tagged-property stream

| Property name | Type | Semantics |
|---------------|------|-----------|
| `BoneTree` | `ArrayProperty<StructProperty(FBoneNode)>` | Per-bone metadata (translation-retargeting mode, etc.). |
| `AnimRetargetSources` | `MapProperty<NameProperty, StructProperty(FReferencePose)>` | Per-source retargeting tables. |
| `SmartNames` | `StructProperty(FSmartNameContainer)` | Curve / morph names; UE 4.13+. |
| `VirtualBones` | `ArrayProperty<StructProperty(FVirtualBone)>` | UE 4.25+. |
| `Sockets` | `ArrayProperty<ObjectProperty(USkeletalMeshSocket)>` | |
| `Notifies` | `ArrayProperty<NameProperty>` | Anim-notify name slots. |
| `Guid` | `StructProperty(FGuid)` | Stable identifier for retargeting. |

Properties terminate with the standard `"None"` tag.

`RefSkeleton` is **not** a tagged property — it is serialized as a
binary blob immediately after the property stream terminates (see
Segment 2).

### Segment 2: `FReferenceSkeleton` (serialized after properties)

CUE4Parse exposes the post-virtual-bone-merge arrays as `FinalRef*`
fields.[^1]

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `FinalRefBoneInfo` | variable | — | `FMeshBoneInfo[]` | Counted-array prefix + per-bone metadata. |
| `FinalRefBonePose` | variable | — | `FTransform[]` | Per-bone reference-pose transform. |
| `FinalNameToIndexMap` | variable | — | `Map<FName, i32>` | FName→bone-index lookup. Present when `Ver ≥ REFERENCE_SKELETON_REFACTOR` (UE 4.12+); cooked content typically includes this. |

### `FMeshBoneInfo` (per-bone record)

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `Name` | 8 | LE | `FName` | Bone name. |
| `ParentIndex` | 4 | LE | `i32` | Index of parent bone in this array; `-1` for root. |
| `BoneColor` (pre-refactor) | 4 | LE | `FColor` | Present only when `Ver < REFERENCE_SKELETON_REFACTOR` (pre-UE 4.12); absent in all modern cooked content. |
| `ExportName` (editor-only) | variable | — | `FString` | Original DCC name. Stripped from cooked content. |

### `FTransform` (per-bone reference pose)

Native struct, not tag-decoded. Wire layout (UE4 single-precision):

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `Rotation` | 16 | LE | `FQuat` (4 × f32) | Rotation as quaternion. |
| `Translation` | 12 | LE | `FVector` (3 × f32) | Translation. |
| `Scale3D` | 12 | LE | `FVector` (3 × f32) | Per-axis scale. |

UE5 LWC (Large World Coordinates) widens both `FVector` and `FQuat`
from f32 to f64. `FQuat` widens from 16 bytes (4 × f32) to 32 bytes
(4 × f64); each `FVector` widens from 12 bytes (3 × f32) to 24 bytes
(3 × f64). The per-transform total becomes `32 + 24 + 24 = 80` bytes
in UE5 LWC content (vs 40 bytes in UE4). A Phase 3 reader using the
incorrect 64-byte total would underallocate bone-pose arrays by 25%
per bone. The choice is gated by asset version; paksmith's Phase 3
reader will need both paths.

### Worked example

`(none yet — no skeleton fixture)`. When Phase 3 adds fixtures, the
anchor will be the SkeletalMesh fixture's referenced Skeleton — a
2-or-3-bone minimal skeleton with reasonable ref-pose transforms.

## Variants

### Virtual bones (UE 4.25+)

`FVirtualBone` lets retargeting target a bone derived from two
existing bones (e.g. "midpoint between left-hand and head"). The
asset's `VirtualBones` property carries them; they don't affect the
`FinalRefBoneInfo` array's indexing.

### LWC transforms (UE 5.x)

UE5 widens both `FVector` and `FQuat` to f64 when LWC is active
(default in UE5). `FTransform` total is 80 bytes under LWC vs 40
bytes in UE4. Paksmith's Phase 3 reader dispatches on
`file_version_ue5 ≥ 1000` to pick the right transform width.

### Retargeting sources

`AnimRetargetSources` holds named retargeting tables (e.g.
"FromUnreal4Mannequin") so anims authored on one skeleton can play
on another.

## Caps & limits

**Phase 3+ deferred work.**

- `MAX_BONES_PER_SKELETON` — direct cap on `FinalRefBoneInfo.Length`
  (the `FReferenceSkeleton` fields are serialized as binary counted-
  arrays, NOT as tagged-property container properties, so this cap is
  independent of the property reader's `MAX_COLLECTION_ELEMENTS`).
  Likely `2^16` matching the 16-bit-bone-index ceiling from
  `FStaticLODModel`.
- Allocation caps inherited from the parent `.uasset` / `.uexp` file
  size caps via `MAX_UNCOMPRESSED_ENTRY_BYTES`.
- `FinalRefBonePose.Length` and `FinalNameToIndexMap.Length` MUST equal
  `FinalRefBoneInfo.Length` (parity invariant; per-bone pose array and
  name→index map are 1:1 with the bone metadata array). Reader should
  reject content where these counts disagree — divergence allows
  attacker-controlled count amplification past the `MAX_BONES_PER_SKELETON`
  cap.

See `docs/security/allocation-caps.md` for the broader policy.

## Verification

- **Fixture:** `(none yet — Phase 3 deliverable)`.
- **Cross-validation oracle:** CUE4Parse[^1] (sole oracle; see [`static-mesh.md`](static-mesh.md) Verification for details on why no Rust counterpart exists).
- **Known divergences:** none yet.
- **Hex anchor commands:** (none yet — Phase 3 deliverable).

## Paksmith implementation

**Parser module:** *(not yet implemented — planned under
`crates/paksmith-core/src/asset/exports/mesh/skeleton.rs`)*

**Status:** `not impl`.

**Phase plan:** `docs/plans/ROADMAP.md` Phase 3.

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Exports/Animation/USkeleton.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` plus `FReferenceSkeleton.cs` and `FMeshBoneInfo.cs` in the same directory. Primary oracle; the `FinalRef*` field names reflect CUE4Parse's post-virtual-bone-merge representation.
