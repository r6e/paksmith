# UE Audio Family Documentation — PR 10 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Populate `docs/formats/audio/` with two documents — `sound-wave.md` (`USoundWave`, the audio asset UObject) and `audio-codecs.md` (per-platform codec catalog: Vorbis / Opus / ADPCM / Bink Audio / platform-native). Both are `partial | not impl`: paksmith has zero audio parser code (Phase 3+ deliverable). Add two rows to the root inventory.

**Architecture:** Audio is simpler than mesh — fewer per-field version conditionals, no LOD chains, no GPU packing decisions. The wire surface splits cleanly into "the `USoundWave` UObject with its property settings + bulk-data pointers" and "the actual codec stream inside the bulk-data payload". Two docs reflect that split.

**Tech Stack:** Pure markdown. PR 1 linters. Primary oracle is `FabianFG/CUE4Parse/UE4/Assets/Exports/Sound/`; secondary is `AstralOrigin/unreal_asset/unreal_asset/src/exports/sound_export.rs`. For codec-specific framing the docs additionally cite upstream standards (Xiph.org for Vorbis / Opus) without those replacing CUE4Parse as the integration oracle.

**Spec reference:** `docs/design/2026-05-19-ue-format-docs.md` (commit `72b364e`). **Prerequisite:** PR 1 (framework scaffold) has merged to `main`.

---

## Prerequisites

- PR 1 (`docs/ue-format-docs-framework`) has merged to `main`.
- Working in a worktree under `.claude/worktrees/docs+ue-format-docs-audio/`.
- `cargo build -p paksmith-doc-lint --release` succeeds.

## File structure

**Create (2 docs):**

- `docs/formats/audio/sound-wave.md` — `USoundWave` asset.
- `docs/formats/audio/audio-codecs.md` — codec catalog (Vorbis / Opus / ADPCM / Bink Audio / platform-native).

**Modify (1):**

- `docs/formats/README.md` — add two rows to the inventory.

**Oracle citation policy.** Primary: `CUE4Parse/UE4/Assets/Exports/Sound/USoundWave.cs` and the `Sound/` neighbors. Secondary: `unreal_asset/src/exports/sound_export.rs`. Codec-specific upstream standards (Xiph.org Vorbis-I spec, IETF RFC 6716 for Opus) cited by name only — paksmith treats those as external standards, not as engine-integration oracles.

**Hex-anchor policy.** `(none yet — Phase 3 deliverable)` for both docs. paksmith has no audio fixtures.

---

## Task 1: Create worktree + verify prerequisites

**Files:** (environment setup only)

- [ ] **Step 1: Confirm PR 1 has merged**

Run: `git fetch origin && git log origin/main --oneline | grep -c "format documentation framework"`
Expected: ≥ 1.

- [ ] **Step 2: Create the worktree from origin/main**

From the primary checkout root:

Run: `git worktree add .claude/worktrees/docs+ue-format-docs-audio -b docs/ue-format-docs-audio origin/main`

- [ ] **Step 3: Switch session cwd into the worktree**

Run: `cd .claude/worktrees/docs+ue-format-docs-audio && pwd && git branch --show-current`
Expected: prints the worktree path and `docs/ue-format-docs-audio`.

- [ ] **Step 4: Verify the framework scaffold is present**

Run: `ls docs/formats/audio/README.md docs/formats/TEMPLATE.md docs/formats/CONVENTIONS.md`
Expected: all three files listed.

- [ ] **Step 5: Build the linter binary**

Run: `cargo build -p paksmith-doc-lint --release`
Expected: clean.

- [ ] **Step 6: Linter smoke-test**

Run: `cargo run -p paksmith-doc-lint --release -- required-headings docs/formats/`
Expected: exits 0.

Run: `cargo run -p paksmith-doc-lint --release -- status-enum docs/formats/README.md`
Expected: exits 0.

- [ ] **Step 7: Confirm no audio parser exists**

Run: `find crates/paksmith-core/src -iname "*audio*" -o -iname "*sound*"`
Expected: no output.

Run: `grep -rln "USoundWave\|SoundWave::" crates/paksmith-core/src`
Expected: no output.

No commit — environment setup only.

---

## Task 2: Author `docs/formats/audio/sound-wave.md` (partial)

`USoundWave` is the UObject for an audio asset. Wire content: a
tagged-property segment with audio settings (sample rate, channel
count, duration) + one or more `FByteBulkData` records carrying the
per-platform compressed audio buffers.

**Files:**
- Create: `docs/formats/audio/sound-wave.md`

**Oracle references:**
- `CUE4Parse/UE4/Assets/Exports/Sound/USoundWave.cs`
- `CUE4Parse/UE4/Assets/Exports/Sound/FStreamedAudioPlatformData.cs` (UE 4.27+).

- [ ] **Step 1: Look up oracle SHAs**

Run: `git ls-remote https://github.com/FabianFG/CUE4Parse HEAD | cut -f1` — `<CUE4PARSE_SHA>`.
Run: `git ls-remote https://github.com/AstralOrigin/unreal_asset HEAD | cut -f1` — `<UNREAL_ASSET_SHA>`.

- [ ] **Step 2: Write the doc**

Write `docs/formats/audio/sound-wave.md`:

````markdown
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
   [`../property/tagged.md`](../property/tagged.md)).
2. **Compressed audio buffers** — one or more `FByteBulkData` records
   pointing at codec-compressed sample data (Vorbis / Opus / ADPCM /
   Bink / platform-native). Stored in the `.uexp` or `.ubulk`
   companions per the standard bulk-data tier dispatch (see
   [`../asset/ubulk.md`](../asset/ubulk.md)).

The cooker picks the codec per target platform at cook time. A
single `USoundWave` asset can hold several platform-specific
compressed forms (Vorbis-for-PC + Opus-for-mobile + AT9-for-PS),
each in its own `FByteBulkData` keyed by platform.

**Status: not yet implemented in paksmith.** Phase 3+ deliverable.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| UE 4.0+ | `USoundWave` introduced; per-platform compressed buffers via `FByteBulkData`. | `CUE4Parse/UE4/Assets/Exports/Sound/USoundWave.cs@<CUE4PARSE_SHA>`[^1] |
| UE 4.25+ | Streamed audio (`FStreamedAudioPlatformData`) introduced for large assets — chunks the audio into demand-loaded segments. | Same[^1] |
| UE 4.27+ | Stream caching expanded; per-chunk metadata gained additional fields. | Same[^1] |
| UE 5.0+ | Audio link integration (`USoundWave::AudioLink`) added as a tagged property; wire shape stable. | Same[^1] |

## Wire layout

### Segment 1: tagged-property stream

Common properties:

| Property name | Type | Semantics |
|---------------|------|-----------|
| `SoundGroup` | `ByteProperty` / `EnumProperty` (`ESoundGroup`) | Engineering tag (Effects / Voice / Music / etc.). |
| `Duration` | `FloatProperty` | Seconds. |
| `bLooping` | `BoolProperty` | |
| `NumChannels` | `IntProperty` | Mono = 1, Stereo = 2, surround formats > 2. |
| `SampleRate` | `IntProperty` | Hz (typically 44100 or 48000). |
| `RawPCMDataSize` | `IntProperty` | Uncompressed byte size; useful for memory budgets. |
| `bMature` | `BoolProperty` | Content filter. |
| `bManualWordWrap` | `BoolProperty` | |
| `SpokenText` | `StrProperty` | Subtitle text. |
| `Subtitles` | `ArrayProperty<StructProperty(FSubtitleCue)>` | Time-coded subtitles. |
| `bIsStreamed` | `BoolProperty` | If `1`, audio uses `FStreamedAudioPlatformData` rather than inline `FByteBulkData`. |
| `Volume` | `FloatProperty` | Default playback volume. |
| `Pitch` | `FloatProperty` | Default playback pitch. |
| `AttenuationSettings` | `ObjectProperty` (`USoundAttenuation`) | 3D-spatialization. |
| `ModulationSettings` | `StructProperty(FSoundModulationDefaultSettings)` | UE 4.26+. |

### Segment 2: per-platform compressed buffers

Following the tagged-property terminator, `USoundWave` serializes
the per-platform `FByteBulkData` records.

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `bCooked` | 4 | LE | `u32` (bool) | Expected `1` for cooked. |
| `CompressedFormatData` | variable | — | `FFormatContainer` | Map of `(FName platform_format → FByteBulkData compressed_buffer)`. |
| `ResourceID` | 4 | LE | `u32` | Hash identifier (legacy). |

The `FFormatContainer` is a `TMap<FName, FByteBulkData>` — keys
identify the platform / codec combination (e.g. `"OGG"`,
`"OPUS"`, `"ADPCM"`, `"BINKA"`, `"XMA2"`, `"AT9"`). Values are
per-codec compressed buffers stored via the standard bulk-data
mechanism (see [`../asset/ubulk.md`](../asset/ubulk.md)).

### `FStreamedAudioPlatformData` (UE 4.25+, when `bIsStreamed == 1`)

Large audio assets (music, long dialog) use a chunked streaming
layout instead of monolithic bulk data:

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `NumChunks` | 4 | LE | `i32` | Number of streaming chunks. |
| `AudioFormat` | variable | — | `FName` | Codec for these chunks. |
| `Chunks` | variable | — | `FStreamedAudioChunk[]` | Per-chunk records. |

Each `FStreamedAudioChunk`:

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `DataSize` | 4 | LE | `i32` | Compressed bytes in this chunk. |
| `AudioDataSize` | 4 | LE | `i32` | Decoded byte size for this chunk (used for buffer sizing). |
| `BulkData` | variable | — | `FByteBulkData` | The chunk's compressed buffer. |

### Worked example

`(none yet — no audio fixture)`. When Phase 3 adds fixtures, the
canonical anchor will be `minimal_soundwave_v5.uasset` — a tiny
stereo 44.1 kHz Vorbis asset with a single `.ubulk`-resident
compressed buffer.

## Variants

### Streamed vs inline

UE picks streamed for assets above a per-project threshold (commonly
~50 KB). Streamed assets use `FStreamedAudioPlatformData` and split
the audio across many `.ubulk` chunks; inline assets use a single
`FByteBulkData` per platform-codec entry. The dispatch is the
`bIsStreamed` property.

### Multiple platform-codec entries

A cooked archive built for multiple platforms (e.g. Win64 + Android)
carries entries for each platform in the same asset. paksmith's
Phase 3 reader will need to pick the entry matching the current
extraction request, or expose all entries to let the consumer
choose.

### Editor-only metadata

In editor builds, additional fields (raw PCM source, import
settings, waveform thumbnail) appear in the tagged-property segment.
Cooked content (paksmith's target) has these stripped.

## Caps & limits

**Phase 3+ deferred work.** When the SoundWave reader lands:

- `MAX_STREAMING_CHUNKS_PER_SOUNDWAVE` cap.
- `MAX_PLATFORM_FORMATS_PER_SOUNDWAVE` cap.
- Per-chunk byte caps inherited from `MAX_UNCOMPRESSED_ENTRY_BYTES`
  / `MAX_UEXP_SIZE` via the underlying bulk-data carrier.

## Verification

- **Fixture:** `(none yet — Phase 3 deliverable)`.
- **Cross-validation oracle:** CUE4Parse[^1] (primary) and
  `unreal_asset`[^2].
- **Known divergences:** none yet — no implementation to diverge.

## Paksmith implementation

**Parser module:** *(not yet implemented — planned under
`crates/paksmith-core/src/asset/exports/audio/sound_wave.rs`)*

**Status:** `not implemented`. Encounters of `SoundWave` exports
today parse the tagged-property segment but fall through to
`PropertyBag::Opaque` when the `CompressedFormatData` map starts.

**Phase plan:** `docs/plans/ROADMAP.md` Phase 3 (Export Pipeline).
A Phase 3 plan should:

1. Add a `crates/paksmith-core/src/asset/exports/audio/sound_wave.rs`
   module with `SoundWave::read_from`.
2. Add the `FFormatContainer` reader (TMap of FName → FByteBulkData).
3. Add the `FStreamedAudioPlatformData` reader for `bIsStreamed`
   assets.
4. Hook per-export class-name dispatch.
5. Add fixtures + cross-validation against `unreal_asset`[^2].

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Exports/Sound/USoundWave.cs@<CUE4PARSE_SHA>` and `FStreamedAudioPlatformData.cs` in the same directory.
[^2]: `AstralOrigin/unreal_asset/unreal_asset/src/exports/sound_export.rs@<UNREAL_ASSET_SHA>` — Rust counterpart.
````

- [ ] **Step 3: Lint check**

Run: `cargo run -p paksmith-doc-lint --release -- required-headings docs/formats/`
Expected: exits 0.

- [ ] **Step 4: Commit**

```bash
git add docs/formats/audio/sound-wave.md
git commit -m "$(cat <<'EOF'
docs(formats): add SoundWave partial reference

Documents USoundWave: tagged-property segment with audio settings
(SoundGroup / Duration / NumChannels / SampleRate / Volume / Pitch /
AttenuationSettings / etc.), the FFormatContainer of platform-keyed
compressed buffers (TMap<FName, FByteBulkData>), and the UE 4.25+
FStreamedAudioPlatformData chunked layout for large assets.
partial-not-impl; Phase 3 work scoped.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Author `docs/formats/audio/audio-codecs.md` (partial)

The codec catalog inside `FByteBulkData` payloads. UE supports
multiple codecs per platform; the platform-key in `FFormatContainer`
identifies which one a given buffer uses.

**Files:**
- Create: `docs/formats/audio/audio-codecs.md`

**Oracle references:**
- `CUE4Parse/UE4/Assets/Exports/Sound/` (codec dispatch in `USoundWave.GetSound()`).
- Upstream codec specs by name only (Xiph.org Vorbis-I, IETF RFC 6716 for Opus).

- [ ] **Step 1: Look up oracle SHAs**

Run: `git ls-remote https://github.com/FabianFG/CUE4Parse HEAD | cut -f1` — `<CUE4PARSE_SHA>`.
Run: `git ls-remote https://github.com/AstralOrigin/unreal_asset HEAD | cut -f1` — `<UNREAL_ASSET_SHA>`.

- [ ] **Step 2: Write the doc**

Write `docs/formats/audio/audio-codecs.md`:

````markdown
# Audio codecs in `USoundWave` buffers

> Per-platform compressed audio formats UE writes into
> `FFormatContainer` bulk-data buffers — Vorbis (legacy default),
> Opus (modern desktop / mobile), ADPCM (legacy), Bink Audio (UE5
> default), and platform-native (XMA, AT9, OPUSNX).

## Overview

When `USoundWave` (see [`sound-wave.md`](sound-wave.md)) cooks for a
platform, the cooker picks one or more codecs from this catalog and
writes the compressed sample buffer into the asset's
`FFormatContainer` keyed by codec name (e.g. `"OGG"`, `"OPUS"`,
`"BINKA"`). At runtime UE looks up the platform's preferred codec
in the container, materializes the compressed buffer, and feeds it
to the matching decoder.

Some codecs (Vorbis, Opus, ADPCM) are standard formats with public
specs. Others (Bink Audio, XMA, AT9, OPUSNX) are platform-licensed
proprietary codecs with no public stream-format documentation —
paksmith documents the *platform-key dispatch* and the wire-shape
boundary, but cannot redistribute decoder logic for the proprietary
codecs and can't ship sample fixtures encoded in them.

**Status: not yet implemented in paksmith.** Phase 3+ deliverable.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| UE 4.0+ | Vorbis (`"OGG"`) introduced as the default UE4 codec; ADPCM (`"ADPCM"`) added for short / loop-sensitive content. | `CUE4Parse/UE4/Assets/Exports/Sound/USoundWave.cs@<CUE4PARSE_SHA>`[^1] |
| UE 4.16+ | Opus (`"OPUS"`) added — replaces Vorbis on mobile platforms. | Same[^1] |
| UE 4.22+ | Bink Audio (`"BINKA"`) added via RAD Game Tools / Epic Games Tools. Same proprietary-codec posture as Bink Video / Oodle. | Same[^1] |
| UE 5.0+ | Bink Audio becomes the default cooked-content codec on most platforms; Vorbis remains as fallback. | Same[^1] |
| Per-platform | XMA / XMA2 (Xbox), AT9 (PlayStation), OPUSNX (Nintendo Switch). | Same[^1] |

## Wire layout

### Codec dispatch by `FFormatContainer` key

Each compressed buffer's interpretation is governed by its key:

| Key (FName) | Codec | Wire format | Status |
|-------------|-------|--------------|--------|
| `"OGG"` | Vorbis | Standard Ogg-Vorbis container (Xiph.org Vorbis-I spec) | Public spec. |
| `"OPUS"` | Opus | Ogg-Opus container (IETF RFC 7845, payload per RFC 6716) | Public spec. |
| `"ADPCM"` | Microsoft IMA ADPCM | WAV container, IMA ADPCM in chunked blocks | Public spec. |
| `"BINKA"` | Bink Audio | RAD Game Tools proprietary | Proprietary — see Variants. |
| `"XMA2"` | XMA2 | Microsoft Xbox proprietary | Proprietary. |
| `"AT9"` | ATRAC9 | Sony PlayStation proprietary | Proprietary. |
| `"OPUSNX"` | Opus (Switch-specific framing) | Modified Ogg-Opus | Mostly public; Switch-specific glue is proprietary. |
| `"PCM"` | Uncompressed | Raw `i16` samples interleaved by channel | Trivial; sometimes used for ultra-short audio (UI clicks). |

### Vorbis buffer (`"OGG"`)

The compressed buffer is a complete **Ogg-Vorbis** file embedded in
the bulk-data payload:

| offset | size | name | semantics |
|--------|------|------|-----------|
| 0 | 4 | `OggS` magic | Standard Ogg page header signature (`0x53676749` big-endian / `4F 67 67 53`). |
| 4 | variable | Ogg pages | Vorbis-encoded sample data wrapped in Ogg framing. |

The wire format is exactly what `libvorbisfile` accepts. paksmith's
Phase 3 implementation should use the `lewton` Rust crate
(pure-Rust Vorbis decoder) for decoding.

### Opus buffer (`"OPUS"`)

Same shape as Vorbis but with **Ogg-Opus** framing per RFC 7845.
Decoder: the `opus` Rust crate (FFI to `libopus`) or `audiopus`
(pure-Rust port).

### ADPCM buffer (`"ADPCM"`)

The buffer is a WAV file with `WAVE_FORMAT_IMA_ADPCM` (format tag
`0x0011`) inside:

| offset | size | name | semantics |
|--------|------|------|-----------|
| 0 | 4 | `RIFF` magic | RIFF container header. |
| 4 | 4 | filesize | Little-endian. |
| 8 | 4 | `WAVE` | Format identifier. |
| 12 | variable | fmt + data chunks | Standard WAV layout. |

The IMA ADPCM block format is per the WAV spec; samples decode to
16-bit PCM at the declared sample rate.

### Bink Audio buffer (`"BINKA"`)

Proprietary RAD format. Wire layout details live in the licensed
Bink SDK documentation (`BinkAudio.txt`); paksmith cannot
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
cross-platform extractor (like paksmith) typically cannot decode
them. Phase 3+ will document the *detection* (paksmith identifies
them via the FName key) and surfaces an `AssetParseFault::UnsupportedAudioCodec`
or similar; actual decoding is out of scope.

### Worked example

`(none yet — no audio fixture)`. When Phase 3 adds a Vorbis fixture
(the public-spec choice), the canonical anchor will be the first
8 bytes of the bulk-data buffer matching `4F 67 67 53` (the `OggS`
magic).

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
| Opus | `audiopus` (FFI to `libopus`) or `opusic-sys` | MIT / BSD. |
| ADPCM | `hound` for the WAV/RIFF container demux + a paksmith-side IMA-ADPCM block decoder (no Rust crate covers IMA ADPCM end-to-end as of writing) | `hound`: Apache-2.0; IMA-ADPCM decoder: paksmith-owned. |
| PCM (uncompressed) | trivial; no decoder crate needed. |

Proprietary codecs (BINKA, XMA2, AT9) require licensed runtime SDKs;
paksmith documents the detection but not the decode.

## Caps & limits

**Phase 3+ deferred work.** When the codec dispatch lands:

- A `MAX_AUDIO_BUFFER_BYTES` cap per buffer (likely matching
  `MAX_UNCOMPRESSED_ENTRY_BYTES = 8 GiB`).
- A `MAX_AUDIO_DECODED_BYTES` cap on the per-codec output buffer
  (analogous to the `MAX_DECODED_TEXTURE_BYTES` discussed in
  [`../texture/pixel-formats.md`](../texture/pixel-formats.md)).

## Verification

- **Fixture:** `(none yet — Phase 3 deliverable)`. A Vorbis fixture
  is the most useful first addition since its wire format is fully
  public.
- **Cross-validation oracle:** CUE4Parse[^1] for the FName-key
  dispatch; upstream codec specs (Xiph, IETF) for the per-codec
  wire details.
- **Known divergences:** none yet — paksmith doesn't implement any
  audio codec.

## Paksmith implementation

**Parser module:** *(not yet implemented — planned under
`crates/paksmith-core/src/asset/exports/audio/codecs/`)*

**Status:** `not implemented`. Detection of codec keys is gated on
the `USoundWave` reader landing first (see
[`sound-wave.md`](sound-wave.md)); per-codec decoders are independent
Phase 3+ deliverables.

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

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Exports/Sound/USoundWave.cs@<CUE4PARSE_SHA>` and the per-codec readers (`OggVorbisAudioReader.cs`, etc.) in `CUE4Parse/UE4/Assets/Exports/Sound/`. paksmith's codec dispatch mirrors CUE4Parse's FName-key approach.
[^2]: Xiph.org "Vorbis I specification" — public reference for the OGG/Vorbis bitstream. Cited by name; not linked because the precise URL has churned across Xiph reorganizations.
[^3]: IETF RFC 6716 (Definition of the Opus Audio Codec) and RFC 7845 (Ogg Encapsulation for the Opus Audio Codec) — public references for Opus. Cited by RFC number.
[^4]: RAD Game Tools / Epic Games Tools "Bink Audio SDK Documentation" — distributed with the licensed SDK; no public URL. Cited by name per the same posture as the Oodle doc.
````

- [ ] **Step 3: Lint check**

Run: `cargo run -p paksmith-doc-lint --release -- required-headings docs/formats/`
Expected: exits 0.

- [ ] **Step 4: Commit**

```bash
git add docs/formats/audio/audio-codecs.md
git commit -m "$(cat <<'EOF'
docs(formats): add audio-codecs partial reference

Documents the per-platform codec catalog in FFormatContainer:
Vorbis (OGG; lewton crate), Opus (OPUS; audiopus crate), Microsoft
IMA ADPCM (ADPCM; hound + paksmith-side decoder), Bink Audio (BINKA;
proprietary, same SDK-load posture as Oodle), and platform-native
(XMA2 / AT9 / OPUSNX). Spells out the FName-key dispatch and the
detection-vs-decode split (paksmith detects all codecs; decodes only
the public-spec ones). partial-not-impl; Phase 3 work scoped.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Update root inventory + final verification + push

**Files:**
- Modify: `docs/formats/README.md`

- [ ] **Step 1: Capture branch HEAD + oracle SHAs**

Run: `git rev-parse --short HEAD` — note as `<SHA>`.
Run: `git ls-remote https://github.com/FabianFG/CUE4Parse HEAD | cut -f1` — `<CUE4PARSE_SHA>`.

- [ ] **Step 2: Add two rows to the inventory**

Verify the existing inventory layout with `grep -n "^|" docs/formats/README.md`, then use Edit to insert two new rows.

Rows to insert:

```markdown
| `audio/sound-wave.md` | partial | not impl | — | CUE4Parse @ `<CUE4PARSE_SHA>` | n/a |
| `audio/audio-codecs.md` | partial | not impl | — | CUE4Parse @ `<CUE4PARSE_SHA>` | n/a |
```

Both `partial | not impl`.

- [ ] **Step 3: Run the status-enum linter**

Run: `cargo run -p paksmith-doc-lint --release -- status-enum docs/formats/README.md`
Expected: exits 0.

- [ ] **Step 4: Run the required-headings linter**

Run: `cargo run -p paksmith-doc-lint --release -- required-headings docs/formats/`
Expected: exits 0.

- [ ] **Step 5: Verify the file tree matches the inventory**

Run: `ls docs/formats/audio/*.md | sort`
Expected:
```
docs/formats/audio/README.md
docs/formats/audio/audio-codecs.md
docs/formats/audio/sound-wave.md
```

- [ ] **Step 6: Run typos**

Run: `typos docs/formats/audio/`
Expected: clean. Domain terms (`Vorbis`, `Opus`, `ADPCM`, `BINKA`,
`XMA2`, `OPUSNX`, `Xiph`, `lewton`, `audiopus`, `claxon`, `hound`,
`FFormatContainer`, `FStreamedAudioPlatformData`) likely to flag —
extend `_typos.toml` only when reword isn't natural.

- [ ] **Step 7: Run `cargo doc -D warnings`**

Run: `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features`
Expected: clean.

- [ ] **Step 8: Commit the inventory update**

```bash
git add docs/formats/README.md
git commit -m "$(cat <<'EOF'
docs(formats): register the audio-family docs in the inventory

Two partial-not-impl rows (sound-wave, audio-codecs): wire format
documented from CUE4Parse + upstream codec specs (Xiph Vorbis, IETF
Opus), paksmith implementation deferred to Phase 3. Last-verified
n/a; Phase 3's PR should bump to a real SHA when the SoundWave
reader and at least one decoder land.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 9: Inspect the commit log**

Run: `git log --oneline origin/main..HEAD`
Expected: 3 commits (newest first):

```
<sha> docs(formats): register the audio-family docs in the inventory
<sha> docs(formats): add audio-codecs partial reference
<sha> docs(formats): add SoundWave partial reference
```

- [ ] **Step 10: Push the branch**

Run: `git push -u origin docs/ue-format-docs-audio`

- [ ] **Step 11: Open the PR**

Title: `docs(formats): populate audio family (sound-wave/audio-codecs)`

Body — write to a tempfile first, then `gh pr create --body-file <tempfile>`:

```markdown
## Summary

Lands PR 10 of the UE format documentation framework. Populates
`docs/formats/audio/` with two documents:

- **`sound-wave.md`** — `USoundWave` UObject with audio-setting
  tagged properties, the `FFormatContainer` TMap of platform-keyed
  `FByteBulkData` records, and the UE 4.25+ `FStreamedAudioPlatformData`
  chunked layout.
- **`audio-codecs.md`** — per-platform codec catalog (Vorbis / Opus
  / ADPCM / Bink Audio / XMA2 / AT9 / OPUSNX) with the FName-key
  dispatch, the public-spec-vs-proprietary split, and the Rust crate
  mapping for the decoders Phase 3 will use (`lewton`, `audiopus`,
  `hound`).

Both `partial | not impl`. Two rows added to the root inventory.

## Linked issue

(none — design spec drives this work)

## Test plan

- [x] `paksmith-doc-lint required-headings` passes.
- [x] `paksmith-doc-lint status-enum` passes on the updated inventory.
- [x] `typos docs/formats/audio/` clean.
- [x] `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features` clean.
- [x] Cross-referenced every wire-format claim against CUE4Parse +
      upstream codec specs (Xiph for Vorbis, IETF RFCs for Opus).

## Pre-flight checklist

- [x] PR title is a Conventional Commit.
- [x] Branch name follows `<type>/<kebab-case>`.
- [x] `cargo fmt --all` clean (no Rust changed).
- [x] `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean.
- [x] Documentation updated (this PR IS documentation).
- [x] No `unsafe` introduced.
- [x] Touched a parser? No — pure docs PR.

## Security considerations

The codec doc identifies a `MAX_AUDIO_DECODED_BYTES` cap as Phase 3+
work, parallel to the `MAX_DECODED_TEXTURE_BYTES` shape established
by the texture pixel-formats doc. The decompression-bomb posture
carries over: a compressed audio buffer that wants to expand 100×
on decode is exactly the same attack-surface shape as a compressed
texture mip that wants to expand 4×.

## Notes for reviewers

- The audio docs adopt the same posture as the Oodle doc for
  proprietary codecs (Bink Audio, XMA2, AT9, OPUSNX): document the
  detection surface, identify the future runtime-loaded SDK
  integration shape, but do not reproduce byte-level format details.
- Vorbis is positioned as the natural first Phase 3 decoder
  implementation because its wire format is fully public (Xiph
  Vorbis-I spec) and the `lewton` pure-Rust crate is mature.
- The `audio-codecs.md` doc explicitly maps codecs to Rust crates
  (`lewton`, `audiopus`, `hound`) so the Phase 3 plan has a
  ready dependency choice.
```

- [ ] **Step 12: Run the standard reviewer panel**

Dispatch in a SINGLE message with multiple Agent tool calls:

- code-reviewer (general quality + spec adherence + factual accuracy
  against CUE4Parse references)
- code-architect (the public-spec / proprietary split is honest, the
  Rust-crate dependency mapping is sensible for Phase 3)
- code-simplifier (the codec table isn't over-explained, the
  per-codec wire-shape sections are appropriately compact)

Address issues, re-run on the fix commit, repeat until APPROVED.

---

## Done criteria

- 3 commits on `docs/ue-format-docs-audio` (two docs + inventory).
- `paksmith-doc-lint required-headings docs/formats/` exits 0.
- `paksmith-doc-lint status-enum docs/formats/README.md` exits 0.
- `typos docs/formats/audio/` clean.
- `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features` clean.
- PR open with `--body-file`-generated body and lowercase verb-first title.
- Reviewer panel converged.
- Two rows present in inventory: `partial | not impl` × 2
  (sound-wave, audio-codecs).
