# AnimSequence (`UAnimSequence`)

> Baked keyframe animation data for a `USkeleton` — per-bone-track
> rotation / translation / scale curves, compressed via one of
> several codecs.

## Overview

`UAnimSequence` is the asset type for a single animation clip — a
walk cycle, an attack swing, a facial-expression blend shape. On
disk: a tagged-property segment with the target `USkeleton`
reference plus playback settings, followed by a compressed-keyframe
payload carrying the per-bone-track keyframes encoded via one of
several codecs.

Seven `ACF_*` codecs cover the UE4 legacy path (uncompressed,
packed, identity); see Per-codec key wire shapes table below. UE
4.21+ added the ACL-codec variant (`FACLCompressedAnimData`, backed
by the Animation Compression Library by Nicholas Frechette); ACL
detection is supported but decoding requires the upstream ACL
library or a Rust binding.

**Document status: complete.** Wire format documented in full for
the two-segment `UAnimSequence` export body: the tagged-property
stream (with `SkeletonGuid` direct read), and the compressed
keyframe payload with three version-dispatched paths
(`SerializeCompressedData` pre-4.23, `SerializeCompressedData2`
4.23-4.24, `SerializeCompressedData3` 4.25+). Outer-wrapper +
`FUECompressedAnimData` length-sentinel + `ReadSerializedByteStream`
+ `InitViewsFromBuffer` interaction documented for both modern
paths. The 7 legacy `ACF_*` codec per-key wire shapes are
catalogued. The ACL codec (`FACLCompressedAnimData`) is identified
by name; decoding requires the upstream ACL library and is out of
scope. `UAnimMontage` and composite/additive sequence types are
separate UObject classes and explicitly out of scope.

**Paksmith parser status: `not impl`.** Phase 3+ deliverable.

## Versions

> Note: UE version numbers in the table are derived from community
> knowledge (UE release history). The oracle names gating constants
> (`FFrameworkObjectVersion::MoveCompressedAnimDataToTheDDC`,
> `FUE5MainStreamObjectVersion::RemovingSourceAnimationData`, etc.)
> but not their UE-release version. Phase 3 implementation should
> anchor against the named constants, not the version numbers.

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| UE 4.0+ | `UAnimSequence` introduced with the seven legacy `ACF_*` codecs; compressed data serialized inline via `SerializeCompressedData()` (pre-4.23 path). | `CUE4Parse/UE4/Assets/Exports/Animation/UAnimSequence.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d`[^1] |
| UE 4.12+ | Compressed data moved out of inline serialization into a DDC-backed blob (`FFrameworkObjectVersion::MoveCompressedAnimDataToTheDDC`). | Same[^1] |
| UE 4.21+ | ACL codec (`FACLCompressedAnimData`) added as the recommended default; bone-compression settings object introduced. | Same[^1] |
| UE 4.23 (`GAME_UE4_23`) | Dispatch switches from `SerializeCompressedData()` to `SerializeCompressedData2()` — outer wrapper + `FUECompressedAnimData.SerializeCompressedData` (length sentinels) + `ReadSerializedByteStream` + `CurveCodecPath` + `CompressedCurveByteStream`. | Same[^1] |
| UE 4.25 (`GAME_UE4_25`) | Dispatch switches to `SerializeCompressedData3()` — same outer structure as 4.23-4.24 with base fields serialized before codec fields inside the `FUECompressedAnimData` section. | Same[^1] |
| UE 5.0+ (`RemovingSourceAnimationData`) | Source raw animation data stripped; curve-compression streams added. | Same[^1] |

## Wire layout

A serialized `UAnimSequence` export body has two segments. The
property stream owns the metadata; the compressed payload carries
the keyframe data.

### Segment 1: tagged-property stream

Properties come from `UAnimationAsset` (base), `UAnimSequenceBase`
(parent), and `UAnimSequence` itself:

| Property name | Source class | Type | Semantics |
|---------------|--------------|------|-----------|
| `Skeleton` | `UAnimationAsset` | `ObjectProperty` (`FPackageIndex → USkeleton`) | Target skeleton — must match the per-track key indices. See [`../mesh/skeleton.md`](../mesh/skeleton.md). |
| `SequenceLength` | `UAnimSequenceBase` | `FloatProperty` | Seconds. |
| `RateScale` | `UAnimSequenceBase` | `FloatProperty` | Playback rate multiplier; default `1.0`. |
| `Notifies` | `UAnimSequenceBase` | `ArrayProperty<StructProperty(FAnimNotifyEvent)>` | Time-coded notify events. |
| `NumFrames` | `UAnimSequence` | `IntProperty` | Total frame count (used before 4.12+; may be absent in newer cooked content). |
| `BoneCompressionSettings` | `UAnimSequence` | `ObjectProperty` (`UAnimBoneCompressionSettings`) | UE 4.21+; per-bone codec + mask settings. |
| `CurveCompressionSettings` | `UAnimSequence` | `ObjectProperty` (`UAnimCurveCompressionSettings`) | UE 4.21+; curve-channel codec settings. |
| `AdditiveAnimType` | `UAnimSequence` | `ByteProperty` / `EnumProperty` (`EAdditiveAnimationType`) | `AAT_None` / `AAT_LocalSpaceBase` / `AAT_MeshSpaceAdditive`. |
| `RefPoseType` | `UAnimSequence` | `ByteProperty` / `EnumProperty` (`EAnimationMode`) | Reference pose type. |
| `RefPoseSeq` | `UAnimSequence` | `ObjectProperty` | Reference pose animation sequence. |
| `RefFrameIndex` | `UAnimSequence` | `IntProperty` | Frame index into `RefPoseSeq`. |
| `RetargetSource` | `UAnimSequence` | `NameProperty` | Named retarget source on the target skeleton. |
| `RetargetSourceAssetReferencePose` | `UAnimSequence` | `ArrayProperty<StructProperty(FTransform)>` | Override reference pose for retargeting. |
| `Interpolation` | `UAnimSequence` | `ByteProperty` / `EnumProperty` (`EAnimInterpolationType`) | `Linear` or `Step` interpolation between keys. |

`RawCurveData` is editor-only and stripped from cooked content
(`// RawCurveData = GetOrDefault<FRawCurveTracks>(nameof(RawCurveData));`
commented out in the oracle). Properties terminate with the standard
`"None"` tag. The codec format fields (`KeyEncodingFormat`,
`*CompressionFormat`, `CompressedTrackOffsets`) are NOT tagged
properties — they serialize directly in Segment 2.

Additionally, `UAnimationAsset::Deserialize` reads a raw `FGuid`
(`SkeletonGuid`) directly after the tagged-property stream when
`Ar.Ver >= EUnrealEngineObjectUE4Version.SKELETON_GUID_SERIALIZATION`.

### Segment 2: compressed keyframe payload

Immediately after the property terminator (and the `SkeletonGuid`
when present), a strip-flags marker gates editor-only raw data, then
the compressed payload serializes.

The dispatch method is determined by the game version:

- `Ar.Game < GAME_UE4_23` → `SerializeCompressedData()` (legacy/pre-4.23)
- `Ar.Game == GAME_UE4_23` or `GAME_UE4_24` → `SerializeCompressedData2()`
- `Ar.Game >= GAME_UE4_25` → `SerializeCompressedData3()`

#### `SerializeCompressedData` (pre-4.23 legacy path)

The legacy path serializes codec fields and keyframe bytes inline.
Phase 3 implementation should oracle-verify each field from
`UAnimSequence.cs` `SerializeCompressedData()` — the wire-field
order is version-dependent and this path is less commonly encountered
in modern cooked content.

#### `SerializeCompressedData2` (UE 4.23–4.24)

Outer wrapper fields:

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `CompressedRawDataSize` | 4 | LE | `i32` | Size of raw (uncompressed) data; MUST be `≥ 0`. |
| `CompressedTrackToSkeletonMapTable` | variable | LE | `i32[]` (count-prefixed) | Count then `i32` skeleton-track indices; count MUST be `≥ 0`. |
| `CompressedCurveNames` | variable | — | counted array of `FSmartName` | Curve name entries; count MUST be `≥ 0`. |

Inside `FUECompressedAnimData.SerializeCompressedData` (length sentinels only — **NOT** inline bytes):

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `KeyEncodingFormat` | 1 | — | `u8` (`AnimationKeyFormat`) | **KEY-TIMING** encoding scheme: `AKF_ConstantKeyLerp` (0, uniform time steps) / `AKF_VariableKeyLerp` (1, explicit per-key timestamps) / `AKF_PerTrackCompression` (2, per-track custom). NOT the translation/scale codec selector — those are `TranslationCompressionFormat` / `ScaleCompressionFormat` fields using `AnimationCompressionFormat` (`ACF_*`). |
| `TranslationCompressionFormat` | 1 | — | `u8` (`AnimationCompressionFormat`) | Per-bone translation codec (`ACF_*`). |
| `RotationCompressionFormat` | 1 | — | `u8` (`AnimationCompressionFormat`) | Per-bone rotation codec. |
| `ScaleCompressionFormat` | 1 | — | `u8` (`AnimationCompressionFormat`) | Per-bone scale codec. |
| `CompressedNumberOfFrames` | 4 | LE | `i32` | Total frame / key count; MUST be `≥ 0`. |
| *(CompressedTrackOffsets sentinel)* | 4 | LE | `i32` | Count of `CompressedTrackOffsets` entries — **count only, no array here**. MUST be `≥ 0`. |
| *(CompressedScaleOffsets.OffsetData sentinel)* | 4 | LE | `i32` | Count of scale-offset entries — **count only**. MUST be `≥ 0`. |
| `CompressedScaleOffsets.StripSize` | 4 | LE | `i32` | Stride divisor for `OffsetData` indexing. MUST be `> 0` (divide-by-zero guard) AND `≥ 0` (sign guard) — both checks required. |
| *(CompressedByteStream sentinel)* | 4 | LE | `i32` | Length of `CompressedByteStream` — **length only, no bytes here**. MUST be `≥ 0`. Read LAST in the `!baseFirst` path. |

> The actual byte content of `CompressedByteStream` and array contents of
> `CompressedTrackOffsets` are populated AFTER this section via
> `InitViewsFromBuffer(serializedByteStream)` — the bytes come from
> `ReadSerializedByteStream` below, not from inline reads here.

Inside `ReadSerializedByteStream` (follows `FUECompressedAnimData.SerializeCompressedData`):

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `numBytes` | 4 | LE | `i32` | Byte count of serialized stream; MUST be `≥ 0`. |
| `bUseBulkDataForLoad` | 1 | — | `bool` | **SECURITY: Reader MUST reject when `true`** — the oracle throws `NotImplementedException`; the bulk-data load path is not supported. |
| `serializedByteStream` | `numBytes` | — | `u8[]` | Present only when `bUseBulkDataForLoad == false`. Bounds-check `numBytes` against remaining archive length before allocating. |

After `ReadSerializedByteStream`, `InitViewsFromBuffer(serializedByteStream)` re-splits
the byte buffer into `CompressedByteStream`, `CompressedTrackOffsets`, and
`CompressedScaleOffsets.OffsetData` using the length sentinels read above.

Remaining outer wrapper fields (after `FUECompressedAnimData` + `ReadSerializedByteStream`):

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `CurveCodecPath` | variable | — | `FString` | Identifies the curve codec. |
| `CompressedCurveByteStream` | variable | LE | `u8[]` (count-prefixed) | Curve-channel compressed bytes; count MUST be `≥ 0`. |

> **Unknown codec discriminant:** Reader MUST reject any `AnimationCompressionFormat`
> value outside the documented `ACF_*` set with a parse error. A `match` with a
> catch-all default arm is NOT acceptable — silent fallthrough on a crafted value
> causes misparse downstream.

#### `SerializeCompressedData3` (UE 4.25+)

Outer wire-order (distinct from `SerializeCompressedData2` — `serializedByteStream` reads FIRST, before curve fields and the conditional `FUECompressedAnimData` block):

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `CompressedRawDataSize` | 4 | LE | `i32` | Original uncompressed data size (for sanity). MUST be `≥ 0`. |
| `CompressedTrackToSkeletonMapTable` | variable | — | `FTrackToSkeletonMap[]` | Counted array (i32 count + entries). Bone-track-index to skeleton-bone-index mapping. Count MUST be `≥ 0`. |
| `CompressedCurveNames` | variable | — | `FSmartName[]` | Counted array (i32 count + entries). Count MUST be `≥ 0`. |
| `serializedByteStream` | variable | — | (see `ReadSerializedByteStream` below) | Read via `numBytes: i32` + `bUseBulkDataForLoad: bool` + optional inline payload. **SECURITY: `bUseBulkDataForLoad == true` MUST be rejected** — oracle throws `NotImplementedException`. |
| `BoneCodecDDCHandle` | variable | — | `FString` | Identifies the bone-compression codec variant. Key used to resolve `BoneCompressionSettings.GetCodec(BoneCodecDDCHandle)`. Empty or unknown handle means no codec resolves — the conditional `FUECompressedAnimData` block below MUST be skipped entirely. |
| `CurveCodecPath` | variable | — | `FString` | Curve-codec dispatch path. |
| `numCurveBytes` | 4 | LE | `i32` | Curve byte count. MUST be `≥ 0` (sign-extension reject). |
| `CompressedCurveByteStream` | numCurveBytes | — | `u8[]` | Curve byte payload. |

**Conditional `FUECompressedAnimData` block** — only present if `BoneCompressionSettings.GetCodec(BoneCodecDDCHandle) != null`. When the codec doesn't resolve, the oracle logs a warning and stops — none of these fields are read; reader MUST NOT unconditionally parse them.

`FUECompressedAnimData.SerializeCompressedData` (baseFirst order, called when codec resolves):

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `CompressedNumberOfFrames` | 4 | LE | `i32` | Total frame / key count (via `BaseSerializeCompressedData`, baseFirst). MUST be `≥ 0`. |
| `KeyEncodingFormat` | 1 | — | `u8` (`AnimationKeyFormat`) | **KEY-TIMING** encoding scheme: `AKF_ConstantKeyLerp` (0) / `AKF_VariableKeyLerp` (1) / `AKF_PerTrackCompression` (2). NOT the translation/scale codec selector. |
| `TranslationCompressionFormat` | 1 | — | `u8` (`AnimationCompressionFormat`) | Per-bone translation codec (`ACF_*`). |
| `RotationCompressionFormat` | 1 | — | `u8` (`AnimationCompressionFormat`) | Per-bone rotation codec. |
| `ScaleCompressionFormat` | 1 | — | `u8` (`AnimationCompressionFormat`) | Per-bone scale codec. |
| *(CompressedByteStream sentinel)* | 4 | LE | `i32` | Length only — actual bytes come from `serializedByteStream` above. MUST be `≥ 0`. Read FIRST in baseFirst order (before track/scale offset sentinels). |
| *(CompressedTrackOffsets sentinel)* | 4 | LE | `i32` | Count only; MUST be `≥ 0`. |
| *(CompressedScaleOffsets.OffsetData sentinel)* | 4 | LE | `i32` | Count only; MUST be `≥ 0`. |
| `CompressedScaleOffsets.StripSize` | 4 | LE | `i32` | Stride divisor for `OffsetData` indexing. MUST be `> 0` (divide-by-zero guard) AND `≥ 0` (sign guard) — both checks required. |

`InitViewsFromBuffer(serializedByteStream)` populates `CompressedByteStream`, `CompressedTrackOffsets`, and `CompressedScaleOffsets.OffsetData` from the byte buffer read above — those bytes are NOT re-read inline here.

> **Unknown-discriminant reject:** Same requirement as `SerializeCompressedData2` — both `AnimationCompressionFormat` (`ACF_*`) AND `AnimationKeyFormat` (`AKF_*`) values outside documented sets MUST be rejected with parse error. A `match` with catch-all default arm is NOT acceptable.

#### ACL codec payload (`FACLCompressedAnimData`)

When ACL is active, the compressed payload is a raw ACL bitstream
(`CompressedByteStream: u8[]`). The ACL library (not paksmith)
decodes bone tracks from this stream. CUE4Parse adapts this via
`AnimBoneCompressionCodec_ACLBase.cs` in the `ACL/` subdirectory
— the codec object is a `UAnimBoneCompressionCodec_ACLBase` subclass
that allocates `FACLCompressedAnimData` and binds the bulk data.
Paksmith Phase 3 can detect ACL (non-null `BoneCompressionSettings`
referencing an ACL codec) but decoding requires the upstream ACL
library or a Rust binding.

### Per-codec key wire shapes (legacy, community-knowledge)

Each rotation track encodes one quaternion per key. Per-codec
per-key sizes below are derived from community references — verify
against the `AnimationCompressionUtils.cs` oracle when Phase 3
implements:

| Codec | Per-key bytes | Encoding |
|-------|---------------|----------|
| `ACF_None` | 16 | 4 × f32 (full quaternion, no W reconstruction). |
| `ACF_Float96NoW` | 12 | 3 × f32; W reconstructed. |
| `ACF_Fixed48NoW` | 6 | 3 × i16 in `[-32768, 32767]` → quaternion components. |
| `ACF_IntervalFixed32NoW` | 4 | 3 × u10 packed into u32 + per-track min/max stored at track header. |
| `ACF_Fixed32NoW` | 4 | 3 × u10 packed into u32 + global range. |
| `ACF_Float32NoW` | 4 | 32 bits total — quaternion packed into a single u32 (W reconstructed from sign). NOT 3 × f32 (that is `ACF_Float96NoW` above). |
| `ACF_Identity` | 0 | No bytes — track is a static identity quaternion. |

Translation and scale tracks use the same enum but are typically
`ACF_None` or `ACF_Float96NoW` (translations are less amenable to
quantization than rotations).

### Worked example — `FUECompressedAnimData` baseFirst header (24 bytes, UE 4.25+ path)

The `FUECompressedAnimData.SerializeCompressedData` baseFirst-order
header (called inside `SerializeCompressedData3` when
`BoneCompressionSettings.GetCodec(BoneCodecDDCHandle)` resolves to a
non-null codec) is fixed at 24 bytes. For a 30-frame animation with
uncompressed-translation, full-quaternion-but-3-component-no-W
rotations, uncompressed scale, constant-key-lerp timing, and no
per-track / per-scale offset tables:

```
Offset (within FUECompressedAnimData)  Bytes (LE)        Field
-------------------------------------  ---------------   --------------------
+0                                     1E 00 00 00       CompressedNumberOfFrames = 30 (i32; baseFirst)
+4                                     00                KeyEncodingFormat = 0 (u8; AKF_ConstantKeyLerp)
+5                                     00                TranslationCompressionFormat = 0 (u8; ACF_None — full f32 quaternion per key)
+6                                     01                RotationCompressionFormat = 1 (u8; ACF_Float96NoW — 3 × f32; W reconstructed)
+7                                     00                ScaleCompressionFormat = 0 (u8; ACF_None)
+8                                     00 00 00 00       CompressedByteStream sentinel = 0 (i32; length only — bytes come from serializedByteStream)
+12                                    00 00 00 00       CompressedTrackOffsets sentinel = 0 (i32; count only)
+16                                    00 00 00 00       CompressedScaleOffsets.OffsetData sentinel = 0 (i32; count only)
+20                                    03 00 00 00       CompressedScaleOffsets.StripSize = 3 (i32; one entry per OffsetData stride)
+24                                                       (end of header — InitViewsFromBuffer populates the arrays from serializedByteStream)
```

The baseFirst order (`SerializeCompressedData3`, UE 4.25+) reads
`CompressedNumberOfFrames` FIRST, then the four codec bytes, then
the three sentinels, then `StripSize`. This differs from
`SerializeCompressedData2` (UE 4.23-4.24), where the codec bytes
come FIRST then `CompressedNumberOfFrames` — sentinel order is
also subtly different. A Phase 3 parser dispatches on
`Ar.Game` per §*Segment 2* dispatch.

## Variants

### Compositing / additive sequences

UE supports composite sequences (`UAnimComposite`) and additive
sequences. These are separate UObject classes outside this doc; only
`UAnimSequence` is covered here.

`UAnimMontage` is a sectioned/compositing animation class (one or
more `AnimSequence` references stitched into named sections like
"Attack", "Loop", "End"). Out of scope for paksmith Phase 3 — separate
class. Additive animation is the `AdditiveAnimType` property ON
`UAnimSequence` itself (see tagged-property table above).

## Caps & limits

### Format-defined limits (wire-imposed)

- **`KeyEncodingFormat` (`AnimationKeyFormat`)**: `u8`; documented
  values `0..=2` (`AKF_ConstantKeyLerp`, `AKF_VariableKeyLerp`,
  `AKF_PerTrackCompression`). Values `3..=255` are wire-valid bytes
  but have no defined semantics.
- **`AnimationCompressionFormat` (`ACF_*`)**: `u8`; documented
  values `0..=6` covering the 7 legacy codecs. Values outside this
  range are wire-valid but undefined.
- **`CompressedRawDataSize` / `CompressedNumberOfFrames`**: `i32` LE.
- **`CompressedTrackToSkeletonMapTable`**: `i32[]` LE (count-prefixed).
- **`CompressedCurveNames`**: `FSmartName[]` (count-prefixed).
- **Sentinels** (`CompressedByteStream`,
  `CompressedTrackOffsets`, `CompressedScaleOffsets.OffsetData`):
  all `i32` LE length/count fields.
- **`CompressedScaleOffsets.StripSize`**: `i32` LE; documented
  positive values (typically 3 or 6 for the per-bone scale-offset
  stride).
- **`ReadSerializedByteStream.numBytes`**: `i32` LE.
- **`bUseBulkDataForLoad`**: `bool` (UE archive convention).
- **Curve-codec fields**: `CurveCodecPath: FString`,
  `numCurveBytes: i32`, `CompressedCurveByteStream: u8[]`.

### Implementation hardening (recommended for any parser)

An `UAnimSequence` reader (paksmith does not yet have one) MUST:

- **Cap `MAX_TRACKS_PER_ANIM`** at the skeleton's bone count (see
  [`../mesh/skeleton.md`](../mesh/skeleton.md)
  §*Implementation hardening*) — one track per bone is the upper
  bound by construction.
- **Verify all `i32` count / size prefixes are non-negative** before
  any cast to `usize` or array allocation. The full list:
  `CompressedNumberOfFrames`, `CompressedRawDataSize`,
  `CompressedByteStream sentinel`,
  `CompressedTrackOffsets sentinel`,
  `CompressedScaleOffsets.OffsetData sentinel`,
  `CompressedScaleOffsets.StripSize`,
  `ReadSerializedByteStream.numBytes`, `numCurveBytes`. A negative
  `i32 → usize` cast produces a value near `usize::MAX`, bypassing
  per-collection sanity checks before file-residual bytes are
  touched.
- **Validate `CompressedScaleOffsets.StripSize` as `> 0`** before
  use as the stride divisor for `OffsetData` indexing. A value of
  `0` is a divide-by-zero on the index computation; negative values
  cause underflow. BOTH a sign-extension guard AND a divide-by-zero
  guard — both checks required.
- **Validate `KeyEncodingFormat`** (`u8` `AnimationKeyFormat`)
  against the documented `AKF_*` set (`0`, `1`, `2`). Values `3..=255`
  MUST be rejected with parse error. A `match` with catch-all
  default arm is NOT acceptable — silent fallthrough corrupts all
  subsequent reads (the format determines per-key timing layout).
- **Validate `AnimationCompressionFormat`** (`ACF_*`) for
  `TranslationCompressionFormat`, `RotationCompressionFormat`,
  `ScaleCompressionFormat` against the documented set. Same
  catch-all rejection MUST.
- **Reject `bUseBulkDataForLoad == true`** at the
  `ReadSerializedByteStream` site — the oracle throws
  `NotImplementedException`; the bulk-data load path is not
  supported. Surface
  `AssetParseFault::UnsupportedAnimBulkDataLoad` or similar.
- **Bounds-check `ReadSerializedByteStream.numBytes`** against
  remaining archive length before allocating the buffer.
- **Inherit per-codec wire-byte caps** from
  `MAX_UNCOMPRESSED_ENTRY_BYTES`.

See `docs/security/allocation-caps.md` for the broader policy.

## Verification

- **Fixture:** The 24-byte `FUECompressedAnimData` baseFirst-order
  header Worked example above is byte-exact and self-contained for
  the modern `SerializeCompressedData3` path (UE 4.25+). Full
  anim-sequence fixtures with codec-specific keyframe payloads are
  Phase 3 deliverables.
- **Hex anchor commands:**
  ```
  # Synthesize the 24-byte FUECompressedAnimData baseFirst header from
  # the Worked example (30 frames, AKF_ConstantKeyLerp, ACF_None /
  # Float96NoW / None codec triple, no track/scale offset tables,
  # StripSize=3):
  printf '\x1E\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00' | xxd
  ```
  A conformant `UAnimSequence` parser fed these 24 bytes at the
  matching offset MUST decode them as a 30-frame animation with
  constant-key timing and the documented codec triple.
- **Cross-validation oracle:** CUE4Parse[^1] (sole oracle — no Rust
  counterpart for the animation family).
- **Known divergences:** none — no paksmith implementation to
  diverge.

## Paksmith implementation

**Parser module:** *(not yet implemented — planned under
`crates/paksmith-core/src/asset/exports/animation/anim_sequence.rs`)*

**Status:** `not impl`.

**Phase plan:** `docs/plans/ROADMAP.md` Phase 3 (Export Pipeline).

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Exports/Animation/UAnimSequence.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` — primary oracle. Supporting files in the same directory: `AnimSequenceBase.cs`, `UAnimationAsset.cs`, `AnimCompressionTypes.cs` (codec types, `FUECompressedAnimData`, `FCompressedOffsetData`), `AnimationCompressionFormat.cs` (codec enum), `AnimationKeyFormat.cs`, `AnimBoneCompressionCodec.cs`, `AnimBoneCompressionSettings.cs`, `AnimCurveCompressionCodec.cs`, `AnimCurveCompressionSettings.cs`, and the `ACL/` subdirectory for the ACL codec adapters (`AnimBoneCompressionCodec_ACLBase.cs` etc.).
