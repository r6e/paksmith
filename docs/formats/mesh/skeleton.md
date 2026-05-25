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

**Document status: complete.** Wire format documented in full for
the three segments of the `USkeleton` export body: the
tagged-property stream (BoneTree / VirtualBones / Sockets /
Notifies), the binary `FReferenceSkeleton` blob (with `FMeshBoneInfo`
and `FTransform` per-bone records, single-precision UE4 vs LWC UE5
dispatch), the per-bone metadata struct `FBoneNode` carried by the
`BoneTree` tagged property, and the post-property binary reads
(`AnimRetargetSources`, `Guid`, `NameMappings` with its
`FSmartNameMapping` value record and `FCurveMetaData` sub-record,
`FStripDataFlags + ExistingMarkerNames`) with their version gates.
`FBoneNode` and `FSmartNameMapping` are documented inline in
§*Wire layout* below (previously deferred). The `FAnimCurveType`
discriminant carried inside each `FCurveMetaData.Type` field is
identified by name and deferred to CUE4Parse's
`FAnimCurveType.cs` — it is the one-layer-deeper sub-record that
remains outside this doc's scope.

**Paksmith parser status: `not impl`.** Phase 3+ deliverable.
Likely ships together with [`skeletal-mesh.md`](skeletal-mesh.md)
since they're tightly coupled.

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

### `FBoneNode` (per-bone metadata, 1 byte per entry)

Per-bone metadata struct carried by the `BoneTree` tagged property
in Segment 1
(`ArrayProperty<StructProperty(FBoneNode)>` per Segment 1's
property table). Each entry is a single
`EBoneTranslationRetargetingMode` enum byte — the struct has no
`ExpressionGuid`, no `bOverride`, no further fields:

| order | field | size | endian | type | semantics |
|-------|-------|------|--------|------|-----------|
| 1 | `TranslationRetargetingMode` | 1 | — | `u8` (`EBoneTranslationRetargetingMode`) | Per-bone retargeting strategy. |

`EBoneTranslationRetargetingMode` enum values (per the source):

| Value | Name | Meaning |
|-------|------|---------|
| 0 | `Animation` | Use translation from animation data (default). |
| 1 | `Skeleton` | Use fixed translation from skeleton. |
| 2 | `AnimationScaled` | Use translation from animation, but scale length by skeleton's proportions. |
| 3 | `AnimationRelative` | Use translation from animation, also play the difference from the retargeting pose as an additive. |
| 4 | `OrientAndScale` | Apply delta orientation and scale from ref pose. |

The `BoneTree` array's length equals the bone count in the parent
`FReferenceSkeleton`'s `FinalRefBoneInfo` (1:1 correspondence with
bones, established in Segment 2 below). Because `BoneTree` is an
`ArrayProperty<StructProperty(FBoneNode)>`, the wire layout follows
the `Array<StructProperty>` extended shape from
[`../property/containers.md`](../property/containers.md): a single
shared `inner_header` (`FPropertyTag`) precedes all N element
bodies (its `size` field covers the combined byte total, not a
per-element bound), then each `FBoneNode` body is a tagged-property
tree containing one `ByteProperty`/`EnumProperty` field
(`TranslationRetargetingMode`) terminated by the standard `None`
property tag. The 1-byte enum value in the table above is the
payload of that inner property's tag within the per-element tree —
NOT a bare byte following a per-element `FPropertyTag` header.
Tagged-property field decoding follows
[`../property/tagged.md`](../property/tagged.md).

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

Native struct, not tag-decoded. Wire layout (UE4 single-precision / UE5 LWC double-precision):

| field | size (UE4) | size (UE5 LWC) | endian | type | semantics |
|-------|------------|----------------|--------|------|-----------|
| `Rotation` | 16 | 32 | LE | `FQuat` (4 × f32 / 4 × f64) | Rotation as quaternion. Per CUE4Parse FTransform constructor: `Rotation = new FQuat(Ar)` — reads doubles under LWC per the FQuat XML doc ("USE Ar.Read&lt;FQuat&gt; FOR FLOATS AND new FQuat(Ar) FOR DOUBLES"). |
| `Translation` | 12 | 24 | LE | `FVector` (3 × f32 / 3 × f64) | Translation. |
| `Scale3D` | 12 | 24 | LE | `FVector` (3 × f32 / 3 × f64) | Per-axis scale. |

Totals: UE4 = 40 bytes (16+12+12); UE5 LWC = 80 bytes (32+24+24). See Variants section for the LWC-vs-UE4 dispatch rationale.

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

### `FSmartNameMapping` (value record in `NameMappings` map)

The value record in the Segment 3 `NameMappings` counted-map (per
`Ver >= SKELETON_ADD_SMARTNAMES`). The wire layout dispatches on
three version axes, and the read is conditional throughout — the
struct can contain just one of the maps, none of them, or all
three combined depending on the version-constant set:

| order | field | size | endian | type | semantics |
|-------|-------|------|--------|------|-----------|
| 1a | `GuidMap` | variable | LE | `Map<FName, FGuid>` (counted) | **Conditional:** read when `FFrameworkObjectVersion >= SmartNameRefactor` AND `FAnimPhysObjectVersion < SmartNameRefactorForDeterministicCooking`. Counted map (`i32` count + per-entry `FName` key + `FGuid` value). |
| 1b | (skip) | 2 | — | `ushort` | **Conditional:** read and discarded when `FFrameworkObjectVersion < SmartNameRefactor` (legacy path). |
| 1c | `UidMap` | variable | LE | `Map<ushort, FName>` (counted) | **Conditional:** same gate as 1b (legacy path). Counted map (`i32` count + per-entry `ushort` key + `FName` value). |
| 2 | `CurveMetaDataMap` | variable | LE | `Map<FName, FCurveMetaData>` (counted, optional) | **Conditional:** read when `FFrameworkObjectVersion >= MoveCurveTypesToSkeleton`. Each value is an `FCurveMetaData` record (see below). |

On the modern post-`SmartNameRefactorForDeterministicCooking` path
the gates for 1a and 1c both fall through (neither map appears on
wire), leaving only `CurveMetaDataMap` when its own gate is met.

#### `FCurveMetaData` (value record in `CurveMetaDataMap`)

| order | field | size | endian | type | semantics |
|-------|-------|------|--------|------|-----------|
| 1 | `Type` | variable | LE | `FAnimCurveType` | Curve type discriminant + flags (sub-format not catalogued in this doc; refer to CUE4Parse's `FAnimCurveType.cs` for the per-field layout). |
| 2 | `LinkedBones` | variable | LE | `FName[]` (counted) | Bones whose animation drives this curve. `i32` count prefix + per-entry FName. |
| 3 | `MaxLOD` | 1 (typical) or 4 (KingdomHearts3) | LE | `u8` (or `i32`) | **Conditional:** read when `FAnimPhysObjectVersion >= AddLODToCurveMetaData`. Maximum LOD level at which the curve is evaluated. |

### Worked example — minimal 2-bone `FReferenceSkeleton` body (112 bytes, UE 4.12+ single-precision)

A `FReferenceSkeleton` for a 2-bone hierarchy at UE 4.12+ (post-
`REFERENCE_SKELETON_REFACTOR`, so no per-bone `BoneColor`; cooked
content, so no `ExportName`; single-precision `FTransform`). The
bones are "Root" (parent=-1) and "Hip" (parent=0). Each
`FTransform` carries the identity rotation, zero translation, and
unit scale:

```
Offset (within body)  Bytes (LE)                                                                  Field
--------------------  --------------------------------------------------------------------------  --------------------
+0                    02 00 00 00                                                                  FinalRefBoneInfo count = 2 (i32 prefix)
+4                    <"Root" FName: 8 bytes>                                                      FMeshBoneInfo[0].Name (index + number, both i32 LE; opaque per fname.md)
+12                   FF FF FF FF                                                                  FMeshBoneInfo[0].ParentIndex = -1 (i32; root)
+16                   <"Hip" FName: 8 bytes>                                                       FMeshBoneInfo[1].Name
+24                   00 00 00 00                                                                  FMeshBoneInfo[1].ParentIndex = 0 (i32; child of Root)
+28                   02 00 00 00                                                                  FinalRefBonePose count = 2 (i32 prefix)
+32                   <FTransform[0]: 40 bytes — Quat 16 + Vector 12 + Vector 12>                 FMeshBoneInfo[0] reference pose
+72                   <FTransform[1]: 40 bytes>                                                     FMeshBoneInfo[1] reference pose
+112                  <(end of FReferenceSkeleton core; FinalNameToIndexMap follows when present)>
```

Total fixed body = 4 + 12 + 12 + 4 + 40 + 40 = **112 bytes**.

When `FinalNameToIndexMap` is present (UE 4.12+, gated by
`REFERENCE_SKELETON_REFACTOR`), it follows the `FinalRefBonePose`
array: 4-byte `i32` map count + per-entry `FName` (8 bytes) + `i32`
bone index. For the 2-bone example: 4 + 2 × (8 + 4) = 28 bytes,
bringing the total to **140 bytes**.

Under UE 5.x with LWC (`Ver ≥ LARGE_WORLD_COORDINATES`), each
`FTransform` widens from 40 to 80 bytes (f64 components), pushing
the core body to 4 + 12 + 12 + 4 + 80 + 80 = **192 bytes** (or
220 with the optional name-to-index map).

### Worked example — identity `FTransform` (40 bytes, UE4 single-precision)

The `<FTransform[i]: 40 bytes>` placeholders above each expand to the byte sequence below for an identity transform (zero translation, identity rotation, unit scale):

```
Offset (within transform)  Bytes (LE)                                       Field
-------------------------  -----------------------------------------------  ------
+0                         00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 3F  Rotation = FQuat(0, 0, 0, 1) — identity (4 × f32 LE)
+16                        00 00 00 00 00 00 00 00 00 00 00 00              Translation = FVector(0, 0, 0) (3 × f32 LE)
+28                        00 00 80 3F 00 00 80 3F 00 00 80 3F              Scale3D = FVector(1, 1, 1) (3 × f32 LE)
+40                                                                          (end of FTransform)
```

(`0x3F800000` is f32 LE for `1.0`; `0x00000000` is f32 LE for `0.0`.)

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
`file_version_ue5 ≥ LARGE_WORLD_COORDINATES` to pick the right
transform width — earlier UE 5.0 content (file_version_ue5 below
that constant) is single-precision.

### Retargeting sources

`AnimRetargetSources` holds named retargeting tables (e.g.
"FromUnreal4Mannequin") so anims authored on one skeleton can play
on another.

## Caps & limits

### Format-defined limits (wire-imposed)

- **`FMeshBoneInfo.Name`**: 8-byte `FName` (i32 index + i32 number per [`../primitive/fname.md`](../primitive/fname.md)).
- **`FMeshBoneInfo.ParentIndex`**: `i32`; max representable `i32::MAX`.
- **`FMeshBoneInfo.BoneColor`** (pre-UE 4.12 only): 4-byte `FColor`.
- **`FTransform`**: 40 bytes UE4 (single-precision) or 80 bytes UE5 LWC (double-precision; gated on `Ver ≥ LARGE_WORLD_COORDINATES`).
- **`FReferenceSkeleton` array count prefixes**: `i32` for `FinalRefBoneInfo`, `FinalRefBonePose`, and `FinalNameToIndexMap`.
- **`Guid`** (top-level skeleton identifier): fixed 16-byte `FGuid` (4-u32-LE layout per [`../primitive/fguid.md`](../primitive/fguid.md)); present when `Ver ≥ SKELETON_GUID_SERIALIZATION`.

### Implementation hardening (recommended for any parser)

A skeleton reader (paksmith does not yet have one) MUST:

- **Cap `MAX_BONES_PER_SKELETON`** at `2^16 = 65,536` to match the 16-bit-bone-index ceiling from `FStaticLODModel`. Direct cap on `FinalRefBoneInfo.Length`.
- **Enforce the parity invariant**: `FinalRefBonePose.Length` MUST equal `FinalRefBoneInfo.Length` (per-bone pose array is 1:1 with the bone metadata array). When `FinalNameToIndexMap` is present (UE 4.12+, gated by `REFERENCE_SKELETON_REFACTOR`), its size MUST also equal `FinalRefBoneInfo.Length`. **The `BoneTree` tagged-property array's length MUST also equal `FinalRefBoneInfo.Length`** — the Segment 1 `BoneTree` and the Segment 2 `FinalRefBoneInfo` are bone-indexed in parallel, so a mismatch lets attacker-controlled data in one array reference bones from a different index space in the other. Reader MUST reject content where any of these counts disagree — divergence allows attacker-controlled count amplification past the cap and cross-array index confusion.
- **Validate `FMeshBoneInfo.ParentIndex`**: MUST be either `-1` (root) or a strictly smaller index than the bone's own position in `FinalRefBoneInfo`. Reject cycles, self-references, and forward references — any bone-traversal algorithm walking parent links without these guards will infinite-loop. Combined with `MAX_BONES_PER_SKELETON` this bounds the worst-case parent-walk depth.
- **Validate `FinalNameToIndexMap` values**: each `i32` value MUST fall in `[0, FinalRefBoneInfo.Length)` before any name→index lookup uses it as an array index — attacker-controlled out-of-range values would cause OOB reads.
- **Verify all `i32` count prefixes are non-negative** before reserving capacity. The following are all `i32` on the wire and MUST be verified: `AnimRetargetSources` outer-map count, `NameMappings` outer-map count, `ExistingMarkerNames` array count, and the inner maps inside each `FSmartNameMapping` value (`GuidMap` count, `UidMap` count, `CurveMetaDataMap` count) plus the `LinkedBones` array count inside each `FCurveMetaData`. A negative count cast to `usize` in Rust produces `usize::MAX`-adjacent values that bypass per-collection sanity checks before hitting the file-residual-bytes backstop.
- **Validate `FBoneNode.TranslationRetargetingMode` against the defined enum range** `0..=4` (`Animation`, `Skeleton`, `AnimationScaled`, `AnimationRelative`, `OrientAndScale`). The wire byte is u8 (`0..=255`) — values `5..=255` are not defined by `EBoneTranslationRetargetingMode` and MUST be rejected (or, if forward-compat is desired, mapped to `Animation` with a warning). A naive `match` without a default arm will allow undefined values to drive downstream retargeting math through an unreachable branch.
- **Inherit allocation caps** from the parent `.uasset` / `.uexp` file size caps via `MAX_UNCOMPRESSED_ENTRY_BYTES`.

See `docs/security/allocation-caps.md` for the broader policy.

## Verification

- **Fixture:** The 112-byte `FReferenceSkeleton` Worked example above is byte-exact and self-contained for a 2-bone UE 4.12+ single-precision body (excluding the optional `FinalNameToIndexMap`). A skeleton fixture paired with a skeletal-mesh fixture is a Phase 3 deliverable.
- **Hex anchor commands:**
  ```
  # Synthesize the 40-byte identity FTransform from the Worked example
  # (Quat(0,0,0,1) + Vector(0,0,0) + Vector(1,1,1)):
  printf '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x3F\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x3F\x00\x00\x80\x3F\x00\x00\x80\x3F' | xxd
  ```
  A conformant skeleton parser fed these 40 bytes MUST decode them as an identity rotation, zero translation, unit scale per-bone reference pose (single-precision UE4 path).
- **Cross-validation oracle:** CUE4Parse[^1] (sole oracle; see [`static-mesh.md`](static-mesh.md) Verification for details on why no Rust counterpart exists).
- **Known divergences:** none — no paksmith implementation to diverge.

## Paksmith implementation

**Parser module:** *(not yet implemented — planned under
`crates/paksmith-core/src/asset/exports/mesh/skeleton.rs`)*

**Status:** `not impl`.

**Phase plan:** `docs/plans/ROADMAP.md` Phase 3.

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Exports/Animation/USkeleton.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` plus `FReferenceSkeleton.cs` and `FMeshBoneInfo.cs` in the same directory. Primary oracle; the `FinalRef*` field names reflect CUE4Parse's post-virtual-bone-merge representation.
