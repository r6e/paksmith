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

The compressed-keyframe codec set has expanded significantly across
UE4 minor versions and again in UE5. UE4 ships at minimum:

- **`ACF_None`** — uncompressed per-bone-track keyframes.
- **`ACF_Float96NoW`** — quaternion as 3 × `f32` (W reconstructed
  from sign).
- **`ACF_Fixed48NoW`** — quaternion as 3 × `i16` mapped to `[-1, 1]`.
- **`ACF_IntervalFixed32NoW`** — quaternion as 3 × `u10` packed into
  a single `u32` with per-track min/max.
- **`ACF_Fixed32NoW`** — quaternion as 3 × `u10` with global range.
- **`ACF_Float32NoW`** — quaternion as 3 × `f32` (full precision
  legacy variant).
- **`ACF_Identity`** — track has no animation (single key,
  zero bytes).

UE 4.21+ added the ACL-codec variant (`FACLCompressedAnimData`,
backed by the Animation Compression Library by Nicholas Frechette);
UE 4.25+ added per-bone-mask compression; UE 5.0+ expanded with
curve-only compression streams.

**Status: not yet implemented in paksmith.** Phase 3+ deliverable.

## Versions

> Note: UE version numbers in the table are derived from community
> knowledge (UE release history). The oracle names gating constants
> (`FFrameworkObjectVersion::MoveCompressedAnimDataToTheDDC`,
> `FUE5MainStreamObjectVersion::RemovingSourceAnimationData`, etc.)
> but not their UE-release version. Phase 3 implementation should
> anchor against the named constants, not the version numbers.

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| UE 4.0+ | `UAnimSequence` introduced with the seven legacy `ACF_*` codecs. | `CUE4Parse/UE4/Assets/Exports/Animation/UAnimSequence.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d`[^1] |
| UE 4.12+ | Compressed data moved out of inline serialization into a DDC-backed blob (`FFrameworkObjectVersion::MoveCompressedAnimDataToTheDDC`). | Same[^1] |
| UE 4.21+ | ACL codec (`FACLCompressedAnimData`) added as the recommended default; bone-compression settings object introduced. | Same[^1] |
| UE 4.25+ | Per-bone-mask compression added; serialization order changed (base fields before codec fields for `GAME_UE4_25+`). | Same[^1] |
| UE 5.0+ (`RemovingSourceAnimationData`) | Source raw animation data stripped; curve-compression streams added; `CompressedNumberOfFrames` → `CompressedNumberOfKeys`. | Same[^1] |

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
| `AdditiveAnimType` | `UAnimSequence` | `ByteProperty` / `EnumProperty` (`EAdditiveAnimationType`) | `AAT_None` / `LocalSpaceBase` / `MeshSpaceAdditive`. |

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

For UE 4.12+ cooked content, the payload is a `FUECompressedAnimData`
(legacy codecs) or `FACLCompressedAnimData` (ACL codec). The
dispatch is based on the `BoneCompressionSettings` object reference:
if none is set, the legacy `FUECompressedAnimData` path applies.

#### Legacy codec payload (`FUECompressedAnimData`)

Serialization order depends on version:

For UE 4.25+ (`baseFirst == true`):

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `CompressedNumberOfFrames` | 4 | LE | `i32` | Total frame / key count. |
| `KeyEncodingFormat` | 1 | — | `u8` (enum `AnimationKeyFormat`) | Translation / scale codec selector. |
| `TranslationCompressionFormat` | 1 | — | `u8` (enum `AnimationCompressionFormat`) | Per-bone translation codec. |
| `RotationCompressionFormat` | 1 | — | `u8` (enum `AnimationCompressionFormat`) | Per-bone rotation codec (one of the `ACF_*` above). |
| `ScaleCompressionFormat` | 1 | — | `u8` (enum `AnimationCompressionFormat`) | Per-bone scale codec. |
| `CompressedByteStreamLen` | 4 | LE | `i32` | Byte count of the compressed keyframe stream. |
| `CompressedByteStream` | variable | — | `u8[]` | Codec-dependent per-track keyframe bytes. |
| `CompressedTrackOffsets` | variable | — | `i32[]` (count-prefixed) | Per-track byte-offset table into the stream. |
| `CompressedScaleOffsets.OffsetData` | variable | — | `i32[]` (count-prefixed) | Scale-track offsets. |
| `CompressedScaleOffsets.StripSize` | 4 | LE | `i32` | Entries per track in the scale offset table. |

For pre-4.25 (`baseFirst == false`), the serialization order is
inverted — codec bytes come FIRST, then `CompressedNumberOfFrames`,
then track offsets, then scale offsets, then byte stream:

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `KeyEncodingFormat` | 1 | — | `u8` (enum `AnimationKeyFormat`) | Translation / scale codec selector. |
| `TranslationCompressionFormat` | 1 | — | `u8` (enum `AnimationCompressionFormat`) | Per-bone translation codec. |
| `RotationCompressionFormat` | 1 | — | `u8` (enum `AnimationCompressionFormat`) | Per-bone rotation codec. |
| `ScaleCompressionFormat` | 1 | — | `u8` (enum `AnimationCompressionFormat`) | Per-bone scale codec. |
| `CompressedNumberOfFrames` | 4 | LE | `i32` | Total frame / key count. |
| `CompressedTrackOffsets` | variable | — | `i32[]` (count-prefixed) | Per-track byte-offset table. |
| `CompressedScaleOffsets.OffsetData` | variable | — | `i32[]` (count-prefixed) | Scale-track offsets. |
| `CompressedScaleOffsets.StripSize` | 4 | LE | `i32` | Entries per track in the scale offset table. |
| `CompressedByteStreamLen` | 4 | LE | `i32` | Byte count of the compressed keyframe stream. |
| `CompressedByteStream` | variable | — | `u8[]` | Codec-dependent per-track keyframe bytes. |

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
| `ACF_Float32NoW` | 4 | 3 × f32 (W reconstructed, legacy variant). |
| `ACF_Identity` | 0 | No bytes — track is a static identity quaternion. |

Translation and scale tracks use the same enum but are typically
`ACF_None` or `ACF_Float96NoW` (translations are less amenable to
quantization than rotations).

### Worked example

`(none yet — Phase 3 deliverable)`.

## Variants

### ACL codec (UE 4.21+)

UE 4.21+ recommends ACL; cooked content from modern engines almost
exclusively uses ACL. The ACL codec is identified by the
`BoneCompressionSettings` tagged property referencing an
`UAnimBoneCompressionCodec_ACL*` asset. Decoding requires the
upstream Animation Compression Library or a Rust binding; without it
paksmith can detect the codec but cannot extract keyframes.

### Per-bone-mask compression (UE 4.25+)

`UAnimBoneCompressionSettings` lets per-bone curves use different
codecs (e.g. high-precision for the spine, low-precision for the
fingers). The `BoneCompressionSettings` object reference gates this
path.

### Curve compression (UE 5+)

Curves (facial-blend-shape weights, IK targets, etc.) compress
separately from bone tracks. The `CurveCompressionSettings` object
reference gates the curve-codec dispatch; curve data appends after
the bone-track block as a `CurveCodecPath`-routed byte stream.

### Compositing / additive sequences

UE supports composite sequences (`UAnimComposite`) and additive
sequences (`UAnimMontage`). These are separate UObject classes
outside this doc; only `UAnimSequence` is covered here.

## Caps & limits

**Phase 3+ deferred work.** When the AnimSequence reader lands:

- `MAX_FRAMES_PER_ANIM` cap (long animations are split into clips at
  the asset level rather than packed into one sequence; a cap of
  65 536 is a reasonable starting point).
- `MAX_TRACKS_PER_ANIM` cap (one per bone; bounded by the skeleton's
  bone count — see [`../mesh/skeleton.md`](../mesh/skeleton.md)).
- Per-codec wire-byte caps inherited from `MAX_UNCOMPRESSED_ENTRY_BYTES`.

## Verification

- **Fixture:** `(none yet — Phase 3 deliverable)`.
- **Hex anchor commands:** `(none yet — Phase 3 deliverable)`.
- **Cross-validation oracle:** CUE4Parse[^1] (sole oracle — no Rust
  counterpart for the animation family).
- **Known divergences:** none yet — no implementation to diverge.

## Paksmith implementation

**Parser module:** *(not yet implemented — planned under
`crates/paksmith-core/src/asset/exports/animation/anim_sequence.rs`)*

**Status:** `not impl`.

**Phase plan:** `docs/plans/ROADMAP.md` Phase 3 (Export Pipeline).

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Exports/Animation/UAnimSequence.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` — primary oracle. Supporting files in the same directory: `AnimSequenceBase.cs`, `UAnimationAsset.cs`, `AnimCompressionTypes.cs` (codec types, `FUECompressedAnimData`, `FCompressedOffsetData`), `AnimationCompressionFormat.cs` (codec enum), `AnimationKeyFormat.cs`, `AnimBoneCompressionCodec.cs`, `AnimBoneCompressionSettings.cs`, `AnimCurveCompressionCodec.cs`, `AnimCurveCompressionSettings.cs`, and the `ACL/` subdirectory for the ACL codec adapters (`AnimBoneCompressionCodec_ACLBase.cs` etc.).
