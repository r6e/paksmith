# SoundWave (`USoundWave`)

> Audio asset — sample-rate / channel / duration metadata plus one or
> more compressed audio buffers in bulk-data sidecars. The codec used
> for the buffers is platform-dependent; see
> [`audio-codecs.md`](audio-codecs.md).

## Overview

`USoundWave` is the UE asset type for sound effects, music, dialog,
and any other audio playable through the audio engine. On disk a
`USoundWave` carries:

1. **Audio settings** — sample rate, channel count, duration, loop
   metadata, attenuation curves — as tagged properties (see
   [`../property/tagged.md`](../property/tagged.md)). These are
   deserialized by `USoundBase::Deserialize` (the parent class) before
   any USoundWave-specific binary follows.
2. **Compressed audio buffers** — one or more `FByteBulkData` records
   pointing at codec-compressed sample data (Vorbis / Opus / ADPCM /
   Bink / platform-native). Stored in the `.uexp` or `.ubulk`
   companions per the standard bulk-data tier dispatch (see
   [`../asset/ubulk.md`](../asset/ubulk.md)).

The cooker picks the codec per target platform at cook time. A single
`USoundWave` asset can hold several platform-specific compressed forms
(Vorbis-for-PC + Opus-for-mobile + AT9-for-PS), each in its own
`FByteBulkData` keyed by codec name.

Whether the asset streams (chunks on demand) or loads inline is
resolved at deserialization time from a combination of the version
table and the tagged `bStreaming` / `LoadingBehavior` properties —
not from a standalone wire field.

**Status: not yet implemented in paksmith.** Phase 3+ deliverable.

## Versions

> Note: UE version numbers in the table are derived from community
> knowledge (UE release history). The oracle (`USoundWave.cs`) names
> the gating constants (`SOUND_COMPRESSION_TYPE_ADDED`, `EGame.GAME_UE5_4`, etc.)
> but not their UE-release version. Phase 3 implementation should anchor
> against the named constants, not the version numbers.

| UE version range | Wire-format change | Source |
|------------------|--------------------|--------|
| UE 4.0+ | `USoundWave` introduced; per-platform compressed buffers via `FFormatContainer` (non-streaming path). | `CUE4Parse/UE4/Assets/Exports/Sound/USoundWave.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d`[^1] |
| UE 4.12+ (`SOUND_COMPRESSION_TYPE_ADDED`) | Dummy `FName` compression-type field inserted; removed again before `FFrameworkObjectVersion::RemoveSoundWaveCompressionName`. | Same[^1] |
| UE 4.25+ | `FStreamedAudioPlatformData` added for large/streaming assets. | Same[^1] |
| UE 5.4+ | `PlatformCuePoints` array (`FSoundWaveCuePoint[]`) serialized before platform data when cooked. | Same[^1] |

## Wire layout

The USoundWave-specific binary begins immediately after `base.Deserialize`
(the tagged-property segment owned by `USoundBase`). The following
describes only the USoundWave-specific payload.

### Streaming resolution

**Streaming dispatch precedence** (per `USoundWave.cs` Deserialize):
1. Default: `bStreaming = Ar.Versions["SoundWave.UseAudioStreaming"]` (version-table-driven).
2. If the asset carries a tagged `bStreaming` BoolProperty: that value is used; `LoadingBehavior` is **NOT consulted**.
3. Else if the asset carries a tagged `LoadingBehavior` NameProperty: `bStreaming = !loadingBehavior.IsNone && loadingBehavior.Text != "ESoundWaveLoadingBehavior::ForceInline"`.

Steps 2 and 3 are mutually exclusive (`if`/`else if`), not sequential overrides — when both tags are present, `bStreaming` wins and `LoadingBehavior` is ignored.

The resolved `bStreaming` value gates the downstream serialization branch.

### Segment 1: USoundWave header

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `Flags` | 4 | LE | `ESoundWaveFlag` (u32 bitfield) | Bit 0: `CookedFlag`. Bit 1: `HasOwnerLoadingBehaviorFlag`. Bits 2–4: loading-behavior enum. |
| `DummyCompressionName` | variable | — | `FName` | Present only between `SOUND_COMPRESSION_TYPE_ADDED` and `FFrameworkObjectVersion::RemoveSoundWaveCompressionName`. Read and discarded. |

`bCooked` is extracted from `Flags & CookedFlag` (bit 0), not read as
a standalone field.

### Segment 2: UE 5.4+ cue points (cooked only)

When `UE >= 5.4 && bCooked`:

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `PlatformCuePoints` | variable | — | `FStructFallback[]` (`SoundWaveCuePoint`) | Count-prefixed array of cue-point metadata. |

### Segment 3: platform data (branched on `bStreaming`)

#### Non-streaming path (`bStreaming == false`)

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `CompressedFormatData` | variable | — | `FFormatContainer` | Per-platform codec buffers (cooked path). |
| *(or)* `RawData` | variable | — | `FByteBulkData` | Editor raw PCM (non-cooked path; paksmith only targets cooked). |
| `CompressedDataGuid` | 16 | LE | `FGuid` | Identifies the specific cook of the compressed data. |

#### Streaming path (`bStreaming == true`)

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `CompressedDataGuid` | 16 | LE | `FGuid` | Cook identifier. |
| `RunningPlatformData` | variable | — | `FStreamedAudioPlatformData` | Chunked streaming layout (cooked path only). |

### Parse recovery / streaming-flip retry

The oracle wraps `SerializePlatformData` in a try/catch. If the initial parse throws any exception:

1. `bStreaming` is flipped (`bStreaming = !bStreaming`).
2. Archive position is restored (`Ar.Position = saved`).
3. All output fields are reset (`CompressedFormatData = null; RawData = null; CompressedDataGuid = default; RunningPlatformData = null`).
4. `SerializePlatformData` is retried with the flipped interpretation.

A Phase 3 parser that hard-fails on a single-pass parse without this retry will reject assets whose version-table streaming guess was wrong but whose opposite-branch parse would succeed. This recovery is CUE4Parse-specific behavior; the engine reads `bStreaming` deterministically from cook-time state.

### `FFormatContainer`

A count-prefixed sequence of `(FName, FByteBulkData)` pairs:

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `NumFormats` | 4 | LE | `i32` | Number of codec entries. |
| `Key` | variable | — | `FName` | Codec key (e.g. `"OGG"`, `"OPUS"`, `"BINKA"`). |
| `Value` | variable | — | `FByteBulkData` | Compressed buffer for this codec. |
| *(repeat Key+Value for each entry)* | | | | |

Keys are `FName` values identifying the platform codec; they are read
without enumeration by CUE4Parse (the common key strings are a UE
convention, not enforced by this class). See
[`audio-codecs.md`](audio-codecs.md) for the key catalog.

### `FStreamedAudioPlatformData`

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `NumChunks` | 4 | LE | `i32` | Number of streaming chunks. |
| `AudioFormat` | variable | — | `FName` | Codec for all chunks (e.g. `"OGG"`). |
| `Chunks` | variable | — | `FStreamedAudioChunk[NumChunks]` | Per-chunk records. |

Each `FStreamedAudioChunk`:

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `Flags` | 4 | LE | `EStreamedAudioChunk` (u32) | Bit 0: `IsCooked`. Bit 1: `HasSeekOffset`. Bit 2: `IsInlined`. |
| `BulkData` | variable | — | `FByteBulkData` | Compressed chunk payload. |
| `DataSize` | 4 | LE | `i32` | Compressed bytes in this chunk. |
| `AudioDataSize` | 4 | LE | `i32` | Decoded byte size (used for output buffer sizing). Phase 3 MUST clamp against `MAX_AUDIO_DECODED_BYTES` (see [`audio-codecs.md`](audio-codecs.md) Caps) before allocating the output buffer. |
| `SeekOffsetInAudioFrames` | 4 | LE | `u32` | Present only when `Flags & HasSeekOffset`. |

### Worked example

`(none yet — Phase 3 deliverable)`.

## Variants

### Streamed vs inline

See [Streaming resolution](#streaming-resolution) in Wire layout for
the `bStreaming` dispatch and [Parse recovery](#parse-recovery--streaming-flip-retry)
for the retry behavior.

### Multiple codec entries

A cooked archive built for multiple platforms (e.g. Win64 + Android)
carries entries for each platform's codec in the same `FFormatContainer`.
paksmith's Phase 3 reader will expose all available codecs to the user
and default to the first public-spec option.

### Editor-only metadata

In editor builds, additional fields (raw PCM source, import settings,
waveform thumbnail) appear in the tagged-property segment.
Cooked content (paksmith's target) has these stripped.

## Caps & limits

**Phase 3+ deferred work.** When the SoundWave reader lands:

- `MAX_STREAMING_CHUNKS_PER_SOUNDWAVE` cap.
- `MAX_PLATFORM_FORMATS_PER_SOUNDWAVE` cap (bounded by `FFormatContainer::NumFormats`).
- Per-chunk byte caps inherited from `MAX_UNCOMPRESSED_ENTRY_BYTES`
  / `MAX_UEXP_SIZE` via the underlying bulk-data carrier.
- `FFormatContainer.NumFormats`, `FStreamedAudioPlatformData.NumChunks`,
  `FStreamedAudioChunk.DataSize`, `FStreamedAudioChunk.AudioDataSize` —
  all signed `i32` — MUST be verified `≥ 0` before any cast to `usize`
  or use as loop counter. A negative `i32` cast directly to `usize` produces
  a value near `usize::MAX`, bypassing per-collection sanity checks. This
  is mandatory Phase 3 implementation guidance.

## Verification

- **Fixture:** `(none yet — Phase 3 deliverable)`.
- **Hex anchor commands:** `(none yet — Phase 3 deliverable)`.
- **Cross-validation oracle:** CUE4Parse[^1] (sole oracle — verified
  HTTP 404 on AstroTechies/unrealmodding/unreal_asset/src/exports/sound_export.rs;
  AstralOrigin/ is a misnomer org name).
- **Known divergences:** none yet — no implementation to diverge.

## Paksmith implementation

**Parser module:** *(not yet implemented — planned under
`crates/paksmith-core/src/asset/exports/audio/sound_wave.rs`)*

**Status:** `not impl`. Encounters of `SoundWave` exports
today parse the tagged-property segment but fall through to
`PropertyBag::Opaque` when the `Flags` field that begins the
USoundWave-specific payload starts.

**Phase plan:** `docs/plans/ROADMAP.md` Phase 3 (Export Pipeline).
A Phase 3 plan should:

1. Add a `crates/paksmith-core/src/asset/exports/audio/sound_wave.rs`
   module with `SoundWave::read_from`.
2. Resolve `bStreaming` via the version-table + tagged-property precedence chain.
3. Add the `FFormatContainer` reader (count-prefixed `FName → FByteBulkData` pairs).
4. Add the `FStreamedAudioPlatformData` / `FStreamedAudioChunk` readers.
5. Add the UE 5.4+ `PlatformCuePoints` path.
6. Hook per-export class-name dispatch.
7. Add fixtures + cross-validation against CUE4Parse[^1].

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Exports/Sound/USoundWave.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d`, plus `FStreamedAudioPlatformData.cs` and `FStreamedAudioChunk.cs` in the same `Assets/Exports/Sound/` directory. `FFormatContainer.cs` is at `CUE4Parse/UE4/Objects/UObject/`.
