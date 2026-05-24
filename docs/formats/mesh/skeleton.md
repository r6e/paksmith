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
| `VirtualBones` | `ArrayProperty<StructProperty(FVirtualBone)>` | UE 4.25+. |
| `Sockets` | `ArrayProperty<ObjectProperty(USkeletalMeshSocket)>` | |
| `Notifies` | `ArrayProperty<NameProperty>` | Anim-notify name slots. |

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

UE5 LWC widens both `FQuat` and `FVector` to f64; see Variants section for the 80-byte total.

### Segment 3: post-property binary reads

After the property stream and `FReferenceSkeleton` (Segment 2), additional
fields are read from the archive sequentially, each gated on an object
version constant:[^1]

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `AnimRetargetSources` | variable | — | counted-map (`numEntries: i32`, then per-entry `FName + FReferencePose`) | Version-conditional: present when `Ver >= FIX_ANIMATIONBASEPOSE_SERIALIZATION`. |
| `Guid` | 16 | LE | `FGuid` | Stable identifier for retargeting. Version-conditional: present when `Ver >= SKELETON_GUID_SERIALIZATION`. Read via `Ar.Read<FGuid>()` — NOT a tagged property. |
| `NameMappings` | variable | — | counted-map (`FName` key + `FSmartNameMapping` value per entry) | Version-conditional: present when `Ver >= SKELETON_ADD_SMARTNAMES`. Binary read for smart-name/curve data. |
| `FStripDataFlags + ExistingMarkerNames` | variable | — | `FStripDataFlags` (2 bytes) + counted `FName[]` (when `!IsEditorDataStripped`) | Version-conditional: present when `FAnimObjectVersion >= StoreMarkerNamesOnSkeleton`. When the strip flag indicates editor data is stripped (cooked content), the array is absent and only the strip-flags pair appears on wire. |

`Guid` (top-level skeleton identifier for retargeting) is a binary read
after the property stream, not a tagged property. It is distinct from
`VirtualBoneGuid`, which IS a tagged property (`GetOrDefault<FGuid>`)
and remains in Segment 1 if present.

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

- `MAX_BONES_PER_SKELETON` — direct cap on `FinalRefBoneInfo.Length`.
  Likely `2^16` matching the 16-bit-bone-index ceiling from
  `FStaticLODModel`.
- Allocation caps inherited from the parent `.uasset` / `.uexp` file
  size caps via `MAX_UNCOMPRESSED_ENTRY_BYTES`.
- `FinalRefBonePose.Length` MUST equal `FinalRefBoneInfo.Length` (parity invariant; per-bone pose array is 1:1 with the bone metadata array). When `FinalNameToIndexMap` is present (UE 4.12+, gated by `REFERENCE_SKELETON_REFACTOR`), its size MUST also equal `FinalRefBoneInfo.Length`. Reader should reject content where these counts disagree — divergence allows attacker-controlled count amplification past the `MAX_BONES_PER_SKELETON` cap.
- `FMeshBoneInfo.ParentIndex` (`i32`) MUST be either `-1` (root) or a strictly smaller index than the bone's own position in `FinalRefBoneInfo`. Reader MUST reject cycles, self-references, and forward references — any bone-traversal algorithm walking parent links without these guards will infinite-loop. Combined with `MAX_BONES_PER_SKELETON` this bounds the worst-case parent-walk depth.
- `FinalNameToIndexMap` values are `i32` bone indices into `FinalRefBoneInfo`. Reader MUST validate every value falls in `[0, FinalRefBoneInfo.Length)` before using as an array index — attacker-controlled out-of-range values would cause OOB reads on any name→index lookup.
- `AnimRetargetSources` outer-map count (`i32`), `NameMappings` outer-map count (`i32`), and `ExistingMarkerNames` array count (`i32`) — all signed `i32` count prefixes — MUST be verified `≥ 0` before reserving capacity. A negative count cast directly to `usize` in Rust produces `usize::MAX`-adjacent values that bypass per-collection sanity checks before hitting the file-residual-bytes backstop.

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
