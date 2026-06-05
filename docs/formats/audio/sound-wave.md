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

**Document status: complete.** Wire format documented in full for
the three-segment `USoundWave` export body: the tagged-property
stream (inherited from `USoundBase`; common audio settings
catalogued), the USoundWave-specific binary header
(`Flags` + version-conditional `DummyCompressionName`), the
optional UE 5.4+ `PlatformCuePoints`, and the platform-data
segment branched on the resolved `bStreaming` value (with both
`FFormatContainer` non-streaming and `FStreamedAudioPlatformData`
streaming paths fully documented). The CUE4Parse-specific
streaming-flip retry behavior is called out so a Phase 3 parser
can choose to mirror or skip it. Per-codec wire formats live in
[`audio-codecs.md`](audio-codecs.md).

**Paksmith parser status: `partial`.** The full USoundWave binary
header is parsed (Phase 3f): the tagged-property segment, the `Flags` /
`bCooked`, the `DummyCompressionName`, and every platform-data branch —
non-streaming `FFormatContainer` (cooked) / `RawData` (non-cooked), the
streaming `FStreamedAudioPlatformData`, each with the
`CompressedDataGuid`, plus the streaming-flip retry. Export of the codec
buffers is `partial`: `OggHandler` / `WavHandler` passthrough-export the
`"OGG"` / `"PCM"` / `"ADPCM"` buffers (complete standard containers →
playable `.ogg` / `.wav`), and `WavHandler` decodes the IMA/DVI ADPCM
(`0x0011`) variant to a 16-bit PCM WAV (see
[`audio-codecs.md`](audio-codecs.md)). The remaining per-codec decoders
(Microsoft ADPCM, Vorbis, Opus) are independent Phase 3+ deliverables.

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
3. Else if the asset carries a tagged `LoadingBehavior` NameProperty: `bStreaming = !loadingBehavior.IsNone && loadingBehavior.Text != "ESoundWaveLoadingBehavior::ForceInline"`. **Game-specific refinement:** on `EGame.GAME_Stray`, if the initial result is `true`, clamp further: `bStreaming = loadingBehavior.Text != "ESoundWaveLoadingBehavior::RetainOnLoad"`. (Other games may have similar refinements added in future oracle SHAs — implementations targeting a specific game SHOULD cross-check `USoundWave.cs` at the oracle version.)

Steps 2 and 3 are mutually exclusive (`if`/`else if`), not sequential overrides — when both tags are present, `bStreaming` wins and `LoadingBehavior` is ignored.

The resolved `bStreaming` value gates the downstream serialization branch.

### Segment 1a: USoundWave tagged properties (from `USoundBase`)

Common tagged properties carried in the property stream (read via standard tagged-property iteration before the binary header):

| Property name | Type | Semantics |
|---------------|------|-----------|
| `SoundGroup` | `ByteProperty` / `EnumProperty` (`ESoundGroup`) | Engineering tag (Effects / Voice / Music / etc.). |
| `Duration` | `FloatProperty` | Seconds. |
| `bLooping` | `BoolProperty` | |
| `NumChannels` | `IntProperty` | Mono = 1, Stereo = 2, surround formats > 2. |
| `SampleRate` | `IntProperty` | Hz (typically 44100 or 48000). |
| `RawPCMDataSize` | `IntProperty` | Uncompressed byte size; useful for memory budgets. |
| `bMature` | `BoolProperty` | Content filter. |
| `SpokenText` | `StrProperty` | Subtitle text. |
| `Subtitles` | `ArrayProperty<StructProperty(FSubtitleCue)>` | Time-coded subtitles. |
| `bStreaming` | `BoolProperty` | Wins over `LoadingBehavior` if present (see Streaming dispatch). |
| `LoadingBehavior` | `NameProperty` (`ESoundWaveLoadingBehavior`) | Fallback streaming-resolution input. |
| `Volume` | `FloatProperty` | Default playback volume. |
| `Pitch` | `FloatProperty` | Default playback pitch. |
| `AttenuationSettings` | `ObjectProperty` (`USoundAttenuation`) | 3D-spatialization reference. |
| `ModulationSettings` | `StructProperty(FSoundModulationDefaultSettings)` | UE 4.26+. |

These are surfaced by the standard tagged-property reader (see [`../property/tagged.md`](../property/tagged.md)) and consumed by `USoundWave.Deserialize` via `TryGetValue` lookups — they are NOT enumerated in the binary `Deserialize` body itself.

### Segment 1b: USoundWave binary header

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

A count-prefixed sequence of `(FName, FByteBulkData)` pairs. The
`FByteBulkData` per-record wire layout is documented canonically in
[`../asset/bulk-data.md`](../asset/bulk-data.md).

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

### Worked example — streaming-path header (32 bytes)

A cooked `USoundWave` taking the streaming branch (resolved
`bStreaming = true`), at a version where `DummyCompressionName`
is NOT present and pre-UE-5.4 (no `PlatformCuePoints`). The
binary header through the `FStreamedAudioPlatformData` opening
fields is fixed at 32 bytes; per-chunk records follow:

```
Offset (within payload)  Bytes (LE)                                       Field
-----------------------  -----------------------------------------------  --------------------
+0                       01 00 00 00                                      Flags = 0x00000001 (u32; CookedFlag set, no owner-loading-behavior, loading-behavior enum = 0)
+4                       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  CompressedDataGuid = zero (16 bytes FGuid)
+20                      01 00 00 00                                      NumChunks = 1 (i32; one streaming chunk follows)
+24                      <AudioFormat: 8 bytes FName — opaque per fname.md>  AudioFormat codec key (e.g. "OGG", "OPUS", "BINKA")
+32                      <FStreamedAudioChunk record follows — see Chunk table above>
```

The `bCooked` derivation: `Flags & 0x00000001 != 0` → `true`. The
non-CookedFlag bits (`HasOwnerLoadingBehaviorFlag` bit 1 and
loading-behavior enum bits 2-4) are all zero in this minimal
example.

For the non-streaming branch, the same `Flags` byte applies; then
the layout is `FFormatContainer` (variable per-codec entries) +
`CompressedDataGuid` (16 bytes). Per-format chunk records use the
[`audio-codecs.md`](audio-codecs.md) FName-key dispatch.

## Variants

### Streamed vs inline

See [Streaming resolution](#streaming-resolution) in Wire layout for
the `bStreaming` dispatch and [Parse recovery](#parse-recovery--streaming-flip-retry)
for the retry behavior.

### Multiple codec entries

A cooked archive built for multiple platforms (e.g. Win64 + Android)
carries entries for each platform's codec in the same `FFormatContainer`.
The parsed `SoundWaveData` carries every codec key, but Phase 3f's
passthrough handlers each export the first wire-order buffer they support
(`OggHandler` → `"OGG"`, `WavHandler` → `"PCM"` / `"ADPCM"`); surfacing
all available codec entries for user selection is a later deliverable.

### Editor-only metadata

In editor builds, additional fields (raw PCM source, import settings,
waveform thumbnail) appear in the tagged-property segment.
Cooked content (paksmith's target) has these stripped.

## Caps & limits

### Format-defined limits (wire-imposed)

- **`Flags`**: `u32` bitfield; only bits 0-4 currently allocated
  per `ESoundWaveFlag` (bit 0 `CookedFlag`, bit 1
  `HasOwnerLoadingBehaviorFlag`, bits 2-4 loading-behavior enum).
- **`CompressedDataGuid`**: fixed `[u8; 16]` (`FGuid` 4-u32-LE
  per [`../primitive/fguid.md`](../primitive/fguid.md)).
- **`FFormatContainer.NumFormats`**: `i32`; max representable
  `i32::MAX`.
- **`FStreamedAudioPlatformData.NumChunks`**: `i32`.
- **`FStreamedAudioChunk.Flags`**: `u32`; bits 0-2 currently
  allocated per `EStreamedAudioChunk` (bit 0 `IsCooked`, bit 1
  `HasSeekOffset`, bit 2 `IsInlined`).
- **`FStreamedAudioChunk.DataSize` / `AudioDataSize`**: `i32`.
- **`FStreamedAudioChunk.SeekOffsetInAudioFrames`**: `u32`
  (conditional on `Flags & HasSeekOffset`).
- **Codec key (`FName` in `FFormatContainer`)**: 8 bytes
  (`u32` index + `u32` number per [`../primitive/fname.md`](../primitive/fname.md));
  string content is convention, not wire-enforced (see
  [`audio-codecs.md`](audio-codecs.md)).

### Implementation hardening (recommended for any parser)

A `USoundWave` reader MUST:

- **Cap `FFormatContainer.NumFormats`** at
  `MAX_PLATFORM_FORMATS_PER_SOUNDWAVE` (typically `8` — UE
  rarely cooks more than a few codecs per asset).
- **Cap `FStreamedAudioPlatformData.NumChunks`** at
  `MAX_STREAMING_CHUNKS_PER_SOUNDWAVE`.
- **Verify all `i32` count prefixes are non-negative** before
  any cast to `usize` or use as loop counter:
  `FFormatContainer.NumFormats`,
  `FStreamedAudioPlatformData.NumChunks`,
  `FStreamedAudioChunk.DataSize`,
  `FStreamedAudioChunk.AudioDataSize`,
  `PlatformCuePoints` count prefix. A negative `i32` cast
  directly to `usize` produces `usize::MAX`-adjacent values that
  bypass per-collection sanity checks.
- **Clamp `FStreamedAudioChunk.AudioDataSize`** against
  `MAX_AUDIO_DECODED_BYTES` (see
  [`audio-codecs.md`](audio-codecs.md) §*Caps & limits*) before
  allocating the decoded output buffer. The wire field is
  attacker-influenced; a high value drives the
  decompression-output allocation.
- **Coerce `u32` boolean / bit-flag fields** per UE convention
  (`!= 0` → true). Per the same convention used in
  [`../mesh/vertex-formats.md`](../mesh/vertex-formats.md)
  §*Implementation hardening*.
- **Use `checked_add`** on
  `FStreamedAudioChunk.BulkData.OffsetInFile + DataSize` before
  any seek-window comparison (defeats near-`u64::MAX`
  wraparound).
- **Inherit per-chunk byte caps** from
  `MAX_UNCOMPRESSED_ENTRY_BYTES` / `MAX_UEXP_SIZE` via the
  underlying bulk-data carrier.
- **Optional**: implementations MAY mirror CUE4Parse's
  streaming-flip retry behavior (see §*Parse recovery*) for
  forward-compatibility with miscued version-table assets;
  paksmith's Phase 3f reader mirrors it — on a parse failure it
  rewinds, flips the resolved `bStreaming`, and re-parses the
  opposite branch.

See `docs/security/allocation-caps.md` for the broader policy.

## Verification

- **Fixture:** The 32-byte streaming-path header Worked example
  above is byte-exact and self-contained (excluding the per-chunk
  `FStreamedAudioChunk` records and the `BulkData` payload itself,
  which live elsewhere per `OffsetInFile`). Real-cooked SoundWave
  fixtures are a Phase 3 deliverable.
- **Hex anchor commands:**
  ```
  # Synthesize the 32-byte streaming-path header from the Worked
  # example (CookedFlag set, zero key GUID, 1 streaming chunk,
  # opaque 8-byte AudioFormat FName placeholder):
  printf '\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' | xxd
  ```
  A conformant `USoundWave` parser fed these 32 bytes MUST decode
  them as a cooked streaming asset with a single chunk and a
  zero-key (placeholder) `AudioFormat` FName; per-chunk records
  follow at offset +32.
- **Cross-validation oracle:** CUE4Parse[^1] (sole oracle — no
  Rust counterpart for the audio family).
- **Known divergences:** the non-streaming codec-buffer selection —
  paksmith picks the **first wire-order** `FFormatContainer` key, where
  CUE4Parse's `SortedDictionary.First()` picks the alphabetically-smallest
  (a no-op for the single-format cooked norm; see `export/audio.rs`).

## Paksmith implementation

**Parser module:** `crates/paksmith-core/src/asset/exports/audio/sound_wave.rs`
(the binary-header + platform-data reader) + `crates/paksmith-core/src/export/audio.rs`
(`OggHandler` / `WavHandler` export) + `crates/paksmith-core/src/export/adpcm.rs`
(IMA/DVI ADPCM decoder).

**Status:** `partial`. The full USoundWave binary header is parsed
(tagged properties, `Flags` / `bCooked`, `DummyCompressionName`, all
platform-data branches with `CompressedDataGuid`, the streaming-flip
retry). `OggHandler` / `WavHandler` passthrough-export the `"OGG"` /
`"PCM"` / `"ADPCM"` buffers (complete standard containers → playable
`.ogg` / `.wav`), and `WavHandler` decodes the IMA/DVI ADPCM (`0x0011`)
variant to a 16-bit PCM WAV. The remaining per-codec decoders (Microsoft
ADPCM, Vorbis, Opus) are independent Phase 3+ deliverables.

**Phase plan:** `docs/plans/ROADMAP.md` Phase 3 (Export Pipeline). The SoundWave reader implementation lands per the wire layouts documented above; cross-validation fixtures + per-codec decoder integration are independent Phase 3+ deliverables.

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Exports/Sound/USoundWave.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d`, plus `FStreamedAudioPlatformData.cs` and `FStreamedAudioChunk.cs` in the same `Assets/Exports/Sound/` directory. `FFormatContainer.cs` is at `CUE4Parse/UE4/Objects/UObject/`.
