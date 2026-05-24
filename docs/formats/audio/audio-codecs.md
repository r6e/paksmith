# Audio codecs in `USoundWave` buffers

> Per-platform compressed audio formats UE writes into
> `FFormatContainer` bulk-data buffers — Vorbis (legacy default),
> Opus (modern desktop / mobile), ADPCM (legacy), Bink Audio (UE5
> default), and platform-native (XMA2, AT9, OPUSNX).

## Overview

When `USoundWave` (see [`sound-wave.md`](sound-wave.md)) cooks for a
platform, the cooker picks one or more codecs from this catalog and
writes the compressed sample buffer into the asset's `FFormatContainer`
keyed by codec name (e.g. `"OGG"`, `"OPUS"`, `"BINKA"`). At runtime
UE looks up the platform's preferred codec in the container,
materializes the compressed buffer, and feeds it to the matching
decoder.

CUE4Parse reads the codec key as a plain `FName` without enumerating
or enforcing specific key strings[^1] — the key names below are UE
convention, confirmed by community tools, not enforced by
`FFormatContainer` itself.

Some codecs (Vorbis, Opus, ADPCM) are standard formats with public
specs. Others (Bink Audio, XMA2, AT9, OPUSNX) are platform-licensed
proprietary codecs with no public stream-format documentation —
paksmith documents the *platform-key dispatch* and the wire-shape
boundary, but cannot redistribute decoder logic for the proprietary
codecs and cannot ship sample fixtures encoded in them.

**Status: not yet implemented in paksmith.** Phase 3+ deliverable.

## Versions

> Note: UE version numbers in the table are derived from community
> knowledge (UE release history). The oracle (`USoundWave.cs`) names
> the gating constants (`SOUND_COMPRESSION_TYPE_ADDED`, `EGame.GAME_UE5_4`, etc.)
> but not their UE-release version. Phase 3 implementation should anchor
> against the named constants, not the version numbers.

| UE version range | Wire-format change | Source |
|------------------|--------------------|--------|
| UE 4.0+ | Vorbis (`"OGG"`) introduced as the default UE4 codec; ADPCM (`"ADPCM"`) added for short / loop-sensitive content. | `CUE4Parse/UE4/Assets/Exports/Sound/USoundWave.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d`[^1] |
| UE 4.16+ | Opus (`"OPUS"`) added — replaces Vorbis on mobile platforms. | Same[^1] |
| UE 4.22+ | Bink Audio (`"BINKA"`) added via RAD Game Tools / Epic Games Tools. Same proprietary-codec posture as Bink Video / Oodle. | Same[^1] |
| UE 5.0+ | Bink Audio becomes the default cooked-content codec on most platforms; Vorbis remains as fallback. | Same[^1] |
| Per-platform | XMA2 (Xbox), AT9 (PlayStation), OPUSNX (Nintendo Switch). | Same[^1] |

## Wire layout

### Codec dispatch by `FFormatContainer` key

Each compressed buffer's interpretation is governed by its `FName` key
in the `FFormatContainer`. CUE4Parse reads these as plain `FName` values;
the key strings below are the commonly observed UE conventions:

| Key (FName) | Codec | Wire format | Status |
|-------------|-------|-------------|--------|
| `"OGG"` | Vorbis | Standard Ogg-Vorbis container (Xiph.org Vorbis-I spec)[^2] | Public spec. |
| `"OPUS"` | Opus | Ogg-Opus container (IETF RFC 7845, payload per RFC 6716)[^3] | Public spec. |
| `"ADPCM"` | Microsoft IMA ADPCM | WAV container (`WAVE_FORMAT_IMA_ADPCM`, tag `0x0011`), IMA ADPCM in chunked blocks. Phase 3 MUST validate `nSamplesPerBlock` against `nBlockAlign` (consistency check) and cap against `MAX_AUDIO_DECODED_BYTES` (decompression bomb guard); mismatches are a reject condition. | Public spec. |
| `"BINKA"` | Bink Audio | RAD Game Tools proprietary | Proprietary — see below. |
| `"XMA2"` | XMA2 | Microsoft Xbox proprietary | Proprietary. |
| `"AT9"` | ATRAC9 | Sony PlayStation proprietary | Proprietary. |
| `"OPUSNX"` | Opus (Switch-specific framing) | Modified Ogg-Opus | Mostly public; Switch-specific glue is proprietary. |
| `"PCM"` | Uncompressed | Raw `i16` samples interleaved by channel | Trivial; sometimes used for ultra-short audio (UI clicks). |

### Bink Audio buffer (`"BINKA"`)

Proprietary RAD format. Wire layout details live in the licensed
Bink SDK documentation (`BinkAudio.txt`)[^4]; paksmith cannot
reproduce them and cannot ship a decoder. The future Bink-audio
support shape mirrors the Oodle approach (see
[`../compression/oodle.md`](../compression/oodle.md)):

1. Runtime-loaded shared library (`bink2w64.dll` / `libbink_audio*.so` etc.).
2. Single decoder entry point called with the compressed buffer + an output buffer sized to the declared sample count.
3. paksmith does not bundle the SDK; users provide the licensed library.

### Platform-native buffers (`"XMA2"`, `"AT9"`, `"OPUSNX"`)

| Codec | Decoder availability |
|-------|----------------------|
| XMA2 | Microsoft platform SDK only (no public spec). |
| AT9 | Sony platform SDK only (no public spec). |
| OPUSNX | Nintendo platform SDK; based on standard Opus with Switch-specific glue. |

These codecs are restricted to their respective platform SDKs; a
cross-platform extractor (like paksmith) typically cannot decode them.
Phase 3+ will document the *detection* (paksmith identifies them via
the FName key) and surface an `AssetParseFault::UnsupportedAudioCodec`
or similar; actual decoding is out of scope.

### Worked example

`(none yet — Phase 3 deliverable)`.

## Variants

### UE codec-priority dispatch

UE writers pick codecs per platform target. A multi-platform cooked
build typically carries both `"OGG"` (PC fallback) and `"OPUS"` or
`"OPUSNX"` (mobile / console). paksmith's Phase 3 extractor should
expose all available codecs to the user and default to the first
public-spec option.

### Decoder selection per Rust crate

Public-spec codecs map to Rust crates:

| Codec | Rust crate | License |
|-------|------------|---------|
| Vorbis | `lewton` | Apache-2.0 OR MIT; pure-Rust. |
| Opus | `audiopus` (FFI to `libopus`) | MIT / BSD. |
| ADPCM | `hound` for WAV/RIFF container demux + a paksmith-side IMA-ADPCM block decoder | `hound`: Apache-2.0; IMA-ADPCM decoder: paksmith-owned. |
| PCM (uncompressed) | trivial; no decoder crate needed. | — |

Proprietary codecs (BINKA, XMA2, AT9) require licensed runtime SDKs;
paksmith documents the detection but not the decode.

## Caps & limits

**Phase 3+ deferred work.** When the codec dispatch lands:

- A `MAX_AUDIO_BUFFER_BYTES` cap per buffer (likely matching
  `MAX_UNCOMPRESSED_ENTRY_BYTES = 8 GiB`).
- A `MAX_AUDIO_DECODED_BYTES` cap on the per-codec output buffer
  (analogous to the `MAX_DECODED_TEXTURE_BYTES` discussed in
  [`../texture/pixel-formats.md`](../texture/pixel-formats.md)).
- For Ogg-framed buffers (`"OGG"`/`"OPUS"`): the decoder loop MUST
  stop once the running decoded-byte count exceeds `MAX_AUDIO_DECODED_BYTES`.
  `lewton` and `audiopus` don't enforce this for the caller — Phase 3
  must implement the cap at the consumer side of the streaming iterator.

## Verification

- **Fixture:** `(none yet — Phase 3 deliverable)`.
- **Hex anchor commands:** `(none yet — Phase 3 deliverable)`.
- **Cross-validation oracle:** CUE4Parse[^1] (sole oracle — verified
  HTTP 404 on AstroTechies/unrealmodding/unreal_asset/src/exports/sound_export.rs;
  AstralOrigin/ is a misnomer org name) for the FName-key dispatch;
  upstream codec specs (Xiph[^2], IETF[^3]) for the per-codec wire
  details.
- **Known divergences:** none yet — paksmith doesn't implement any
  audio codec.

## Paksmith implementation

**Parser module:** *(not yet implemented — planned under
`crates/paksmith-core/src/asset/exports/audio/codecs/`)*

**Status:** `not impl`. Detection of codec keys is gated on the
`USoundWave` reader landing first (see [`sound-wave.md`](sound-wave.md));
per-codec decoders are independent Phase 3+ deliverables.

**Phase plan:** `docs/plans/ROADMAP.md` Phase 3. A Phase 3 plan
should:

1. Add a `crates/paksmith-core/src/asset/exports/audio/codecs/` module
   with one submodule per public-spec codec (`vorbis.rs`, `opus.rs`,
   `adpcm.rs`, `pcm.rs`).
2. Wire the `lewton` / `audiopus` / `hound` dependencies.
3. Add a Vorbis fixture and round-trip test.
4. Surface proprietary codecs as `UnsupportedAudioCodec` errors at
   decode time (parallel to the Oodle approach for proprietary
   compression).

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Exports/Sound/USoundWave.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d`. CUE4Parse reads codec keys as plain `FName` values without enumerating the key strings; no per-codec reader files exist at this path.
[^2]: Xiph.org "Vorbis I specification" — public reference for the OGG/Vorbis bitstream. Cited by name; not linked because the precise URL has churned across Xiph reorganizations.
[^3]: IETF RFC 6716 (Definition of the Opus Audio Codec) and RFC 7845 (Ogg Encapsulation for the Opus Audio Codec) — public references for Opus. Cited by RFC number.
[^4]: RAD Game Tools / Epic Games Tools "Bink Audio SDK Documentation" — distributed with the licensed SDK; no public URL. Cited by name per the same posture as the Oodle doc.
