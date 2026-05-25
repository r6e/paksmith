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

**Document status: complete (publicly-documented surface).** Wire
format documented in full for the `FFormatContainer` key-dispatch
catalog (Vorbis / Opus / ADPCM / PCM with public specs, plus
identification of the proprietary codecs by FName key) and for
ADPCM's `wFormatTag` sub-dispatch (the UE `"ADPCM"` key alone
doesn't pin a variant). The proprietary codec internal stream
layouts (Bink Audio, XMA2, AT9, OPUSNX Switch-specific glue) are
RAD/platform-licensed and intentionally NOT documented here — same
posture as [`../compression/oodle.md`](../compression/oodle.md).
A parser implementer can detect a codec's identity from this doc
and dispatch to the appropriate decoder (public spec or licensed
SDK).

**Paksmith parser status: `not impl`.** Detection of codec keys
is gated on the `USoundWave` reader landing first (see
[`sound-wave.md`](sound-wave.md)); per-codec decoders are
independent Phase 3+ deliverables.

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
| `"ADPCM"` | ADPCM | WAV container[^5]; `wFormatTag` field carries the actual ADPCM variant (`WAVE_FORMAT_ADPCM = 0x0002` for MS ADPCM, `WAVE_FORMAT_DVI_ADPCM = 0x0011` for DVI/IMA ADPCM; CUE4Parse's `EAudioFormat` enum). The UE `"ADPCM"` key does not pin a specific variant — Phase 3 must read `wFormatTag` from the WAV header and dispatch on the actual value. For each variant, Phase 3 MUST compute the decoded output byte count from the WAV header fields per the variant's WAV-spec formula (not from `nBlockAlign`, which bounds the compressed input). The running decoded total MUST be clamped against `MAX_AUDIO_DECODED_BYTES` (decompression-bomb guard). Phase 3 should also reject `data_chunk_size % nBlockAlign != 0` as a corrupt-input early check (and MUST first reject `nBlockAlign == 0` to avoid divide-by-zero on the modulo). | Public spec. |
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

### Worked example — ADPCM `fmt ` sub-chunk core (18 bytes, IMA/DVI variant)

The UE `"ADPCM"` `FName` key doesn't pin a specific ADPCM variant —
a parser must read the WAV header's `wFormatTag` field and
dispatch on the actual value. For an IMA/DVI ADPCM-encoded mono
22050 Hz buffer with 256-byte blocks, the `fmt ` sub-chunk core
(excluding the 4-byte `"fmt "` chunk ID and 4-byte sub-chunk size
prefix) is:

```
Offset (within fmt core)  Bytes (LE)        Field
------------------------  ---------------   --------------------
+0                        11 00              wFormatTag = 0x0011 (WAVE_FORMAT_DVI_ADPCM)
+2                        01 00              nChannels = 1 (mono)
+4                        22 56 00 00        nSamplesPerSec = 22050 Hz (0x00005622)
+8                        2A 2B 00 00        nAvgBytesPerSec ≈ 11050 (depends on samples-per-block; illustrative)
+12                       00 01              nBlockAlign = 256 bytes per block (0x0100)
+14                       04 00              wBitsPerSample = 4 bits/sample
+16                       02 00              cbSize = 2 (bytes of extra format info — samples-per-block u16 follows)
+18                       (end of core; samples-per-block u16 follows in the 2-byte extension)
```

The discriminant a parser dispatches on is the first 2 bytes:

- `wFormatTag = 0x0001` → `WAVE_FORMAT_PCM` (raw 16-bit PCM; no ADPCM decode needed despite the UE `"ADPCM"` key)
- `wFormatTag = 0x0002` → `WAVE_FORMAT_ADPCM` (Microsoft ADPCM)
- `wFormatTag = 0x0011` → `WAVE_FORMAT_DVI_ADPCM` (IMA/DVI ADPCM — most common in cooked UE content per the `"ADPCM"` key)

Per the Microsoft WAV / RIFF specification[^5], the `fmt ` sub-chunk size for IMA ADPCM is
exactly `20` bytes total: the 18 bytes shown above plus a 2-byte
`samples-per-block` u16. Microsoft ADPCM uses `wBitsPerSample = 4`
also but a different `cbSize` extension. The `data` sub-chunk
contains the encoded blocks; each block carries `nBlockAlign` bytes
holding compressed samples.

## Variants

### UE codec-priority dispatch

UE writers pick codecs per platform target. A multi-platform cooked
build typically carries both `"OGG"` (PC fallback) and `"OPUS"` or
`"OPUSNX"` (mobile / console). paksmith's Phase 3 extractor should
expose all available codecs to the user and default to the first
public-spec option.

## Caps & limits

### Format-defined limits (wire-imposed)

- **`FFormatContainer` codec key**: `FName` (8 bytes) per
  [`../primitive/fname.md`](../primitive/fname.md); convention,
  not enforced — any FName is wire-valid.
- **WAV `wFormatTag` (ADPCM dispatch)**: `u16` LE; documented
  values per the Microsoft WAV spec[^5].
  `0x0001` PCM, `0x0002` MS-ADPCM, `0x0011` IMA-ADPCM, etc.
- **WAV `nChannels` / `wBitsPerSample`**: `u16` LE per the WAV
  spec.
- **WAV `nSamplesPerSec` / `nAvgBytesPerSec`**: `u32` LE.
- **WAV `nBlockAlign`**: `u16` LE; the per-block byte stride for
  ADPCM data.
- **Ogg page header** (for `"OGG"` / `"OPUS"` keys): public
  specs (Xiph[^2], IETF RFC 3533 for Ogg framing).

### Implementation hardening (recommended for any parser)

A codec decoder (paksmith does not yet have one) MUST:

- **Cap decoded output buffer per buffer/chunk** against
  `MAX_AUDIO_DECODED_BYTES` (named here for future Phase 3
  implementation; not yet defined in code). Applies to all codecs.
- **For Ogg-framed buffers (`"OGG"` / `"OPUS"`)**: the decoder
  loop MUST stop once the running decoded-byte count exceeds
  `MAX_AUDIO_DECODED_BYTES`. Rust crates `lewton` and `audiopus`
  don't enforce this for the caller — implement the cap at the
  consumer side of the streaming iterator.
- **For ADPCM buffers**: dispatch on `wFormatTag` and apply
  per-variant consistency checks per the WAV spec. For each
  variant, compute the decoded output byte count from the WAV
  header fields per the variant's formula (NOT from
  `nBlockAlign`, which bounds the compressed input). The running
  decoded total MUST be clamped against `MAX_AUDIO_DECODED_BYTES`.
- **Reject `nBlockAlign == 0` for ADPCM before any modulo
  operation**. A zero alignment would cause divide-by-zero
  (panic in Rust, undefined behavior in C/C++) in the
  `data_chunk_size % nBlockAlign` check below.
- **Reject `data_chunk_size % nBlockAlign != 0`** for ADPCM as a
  corrupt-input early check (only after the `nBlockAlign != 0`
  guard above).
- **Validate `wFormatTag`** against a known-variant allow-list
  before dispatching; surface `AssetParseFault::UnsupportedAudioFormat
  { tag }` for unknown values. Don't fall through to a default
  decoder.
- **For proprietary codecs** (`"BINKA"` / `"XMA2"` / `"AT9"` /
  `"OPUSNX"`): a parser without the licensed SDK MUST stop at
  detection and surface
  `AssetParseFault::UnsupportedAudioCodec { name }` rather than
  attempting to read the stream bytes. The boundary mirrors
  Oodle (see [`../compression/oodle.md`](../compression/oodle.md)).
- **For runtime-SDK-loaded codecs** (when implemented): pass
  explicit output-size bounds to the SDK call rather than
  trusting decoder self-bounds.

## Verification

- **Fixture:** The 18-byte ADPCM `fmt ` sub-chunk core Worked
  example above is byte-exact and self-contained. Real-cooked
  audio fixtures across the dominant codec set (OGG / OPUS /
  ADPCM / BINKA-detection) are Phase 3 deliverables; proprietary
  codec fixtures aren't redistributable.
- **Hex anchor commands:**
  ```
  # Synthesize the 18-byte IMA-ADPCM fmt core from the Worked example:
  printf '\x11\x00\x01\x00\x22\x56\x00\x00\x2A\x2B\x00\x00\x00\x01\x04\x00\x02\x00' | xxd
  ```
  A conformant ADPCM dispatcher fed these 18 bytes MUST identify
  `wFormatTag = 0x0011` and route to an IMA/DVI ADPCM decoder
  (or surface `UnsupportedAudioFormat` if not implemented).
- **Cross-validation oracle:** CUE4Parse[^1] (sole oracle — no
  Rust counterpart for the audio family) for the FName-key
  dispatch; upstream codec specs (Microsoft WAV[^5], Xiph[^2], IETF
  RFC 6716 + RFC 7845[^3]) for the per-codec wire details.
- **Known divergences:** none — paksmith doesn't implement any
  audio codec.

## Paksmith implementation

**Parser module:** *(not yet implemented — planned under
`crates/paksmith-core/src/asset/exports/audio/codecs/`)*

**Status:** `not impl`. Detection of codec keys is gated on the
`USoundWave` reader landing first (see [`sound-wave.md`](sound-wave.md));
per-codec decoders are independent Phase 3+ deliverables.

**Phase plan:** `docs/plans/ROADMAP.md` Phase 3 (Export Pipeline). The codec dispatch lands as part of the SoundWave reader work; per-codec decoders are independent Phase 3+ deliverables.

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Exports/Sound/USoundWave.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d`. CUE4Parse reads codec keys as plain `FName` values without enumerating the key strings; no per-codec reader files exist at this path.
[^2]: Xiph.org "Vorbis I specification" — public reference for the OGG/Vorbis bitstream. Cited by name; not linked because the precise URL has churned across Xiph reorganizations.
[^3]: IETF RFC 6716 (Definition of the Opus Audio Codec) and RFC 7845 (Ogg Encapsulation for the Opus Audio Codec) — public references for Opus. Cited by RFC number.
[^4]: RAD Game Tools / Epic Games Tools "Bink Audio SDK Documentation" — distributed with the licensed SDK; no public URL. Cited by name per the same posture as the Oodle doc.
[^5]: Microsoft RIFF / WAVE file format specification — public reference; cited by name. URL not pinned (Microsoft documentation paths churn). Covers `wFormatTag` discriminant values, `fmt ` sub-chunk layout, `nBlockAlign` semantics, and per-variant ADPCM decode formulas. The widely-distributed "Multimedia Programmer's Reference" (1991, IBM/Microsoft) is the authoritative reference for the WAVE format; contemporary equivalents are available via Microsoft Learn under "Waveform Audio File Format."
