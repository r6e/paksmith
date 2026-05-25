# Paksmith Phase 3f: SoundWave → WAV / OGG export (architecture overview)

> **For agentic workers:** This is an **overview** plan. Decoder selection (lewton vs symphonia for Vorbis; hound for WAV write) settles at kickoff. Once locked, rewritten Phase-2g-style with full TDD steps. See `docs/plans/phase-3-export-pipeline.md` §Sub-phase index.

**Goal:** Decode `USoundWave` assets into export-ready audio buffers. **MVP scope**: passthrough of OGG/OPUS keys (rewrite the FFormatContainer buffer verbatim as `.ogg` / `.opus`) + `UnsupportedAudioCodec` for proprietary codecs. **Follow-up scope**: ADPCM → WAV (public spec, small decoder); WEM → OGG (Wwise header rewrite, no Vorbis decode); proprietary codecs gated on Phase 8's SDK loader.

**Depends on:** 3a (FormatHandler), 3b (FByteBulkData resolver for FFormatContainer buffers).
**Does NOT depend on:** 3c.

**Architecture:**

```plaintext
crates/paksmith-core/src/
├── asset/exports/audio/
│   ├── mod.rs                # sound_wave::read_from dispatcher
│   ├── sound_wave.rs         # USoundWave parser
│   ├── format_container.rs   # FFormatContainer (codec FName → buffer)
│   └── streamed.rs           # FStreamedAudioPlatformData (streaming path)
└── export/
    └── audio.rs              # OggPassthroughHandler, OpusPassthroughHandler, WavHandler
```

`Asset::SoundWave { sample_rate, channels, duration, codec_buffers: Vec<CodecBuffer>, streaming: Option<StreamedAudio> }`. `CodecBuffer { codec: AudioCodec, bytes: Vec<u8> }`.

---

## Scope (MVP — 3f proper):

- **Parser:** USoundWave's full Deserialize shape per [`../formats/audio/sound-wave.md`](../formats/audio/sound-wave.md): tagged-property segment (from `USoundBase::Deserialize`), `Flags: u32` (with `bCooked = Flags & 0x01` extracted as a derived bool, NOT read as a standalone field per `sound-wave.md:100-101`), conditional `DummyCompressionName` FName (UE 4.12–pre-RemoveSoundWaveCompressionName), UE 5.4+ `PlatformCuePoints` array (gated on `bCooked` from Flags), then platform-data branch on `bStreaming` (non-streaming → `FFormatContainer` + `CompressedDataGuid`; streaming → `CompressedDataGuid` + `FStreamedAudioPlatformData`).
- **`bStreaming` resolution (mutually-exclusive precedence — `if`/`else if`, NOT sequential overrides).** Per `sound-wave.md:60-65`:
  1. **Default:** `bStreaming = Ar.Versions["SoundWave.UseAudioStreaming"]` (version-table-driven).
  2. **If the asset carries a tagged `bStreaming` BoolProperty:** that value wins. `LoadingBehavior` is **NOT consulted in this branch.**
  3. **Else if the asset carries a tagged `LoadingBehavior` NameProperty:** `bStreaming = !loadingBehavior.IsNone && loadingBehavior.Text != "ESoundWaveLoadingBehavior::ForceInline"`.

  Steps 2 and 3 are **mutually exclusive** (`if`/`else if`), not sequential overrides — when both tags are present, `bStreaming` wins and `LoadingBehavior` is ignored. The TDD plan MUST encode this as an exclusive branch in code and as a separate test case: an asset carrying both tags + a `LoadingBehavior` value that would otherwise flip the streaming bit MUST decode with `bStreaming` taking precedence.
- **Streaming-flip retry** per format-doc §Parse recovery: wrap the platform-data parse; on initial failure, flip `bStreaming` and retry once. This mirrors CUE4Parse's recovery and avoids version-table-misalignment hard-rejection.
- **`FFormatContainer` reader**: `i32 NumFormats`, then `(FName codec, FByteBulkData buffer)` pairs. Each buffer resolved via 3b's `BulkDataResolver`.
- **`FStreamedAudioPlatformData` reader**: chunked streaming layout (`NumChunks`, `AudioFormat`, per-chunk `FStreamedAudioChunk` with `Flags`, `BulkData`, `DataSize`, `AudioDataSize`, optional `SeekOffsetInAudioFrames`).
- **`AudioCodec` enum**: `Ogg`, `Opus`, `Adpcm`, `Pcm`, `Binka`, `Xma2`, `At9`, `OpusNx`, `Unknown(String)`. The `FName` codec key dispatches.
- **MVP handlers:**
  - `OggPassthroughHandler` — `supports`: `Asset::SoundWave` with any codec buffer where `codec == AudioCodec::Ogg`. Output extension: `"ogg"`. Writes the first matching codec buffer's bytes verbatim.
  - `OpusPassthroughHandler` — same for `AudioCodec::Opus`. Output extension: `"opus"`.
  - `PcmWavHandler` — supports `AudioCodec::Pcm`; wraps raw PCM samples in a WAV header. Output extension: `"wav"`.
- **Caps**: `MAX_AUDIO_DECODED_BYTES = 1 GiB`, `MAX_STREAMING_CHUNKS_PER_SOUNDWAVE = 4096`, `MAX_PLATFORM_FORMATS_PER_SOUNDWAVE = 16` (a single USoundWave never carries more codec variants than that).
- **Error variants**: `UnsupportedAudioCodec { codec_name }`, `AudioStreamingChunksExceeded`, `AudioFormatsExceeded`, `AudioBufferEmpty { codec }`.
- **Tests**: synthetic single-codec USoundWave (OGG passthrough). Cross-validate against CUE4Parse via `paksmith-fixture-gen`.

## Follow-ups (in scope for Phase 3, NOT MVP):

- **`AdpcmWavHandler`**: ADPCM → WAV decoder. Public WAV-spec; the codec dispatches on `wFormatTag` inside the WAV-headered ADPCM buffer (MS ADPCM `0x0002`, DVI/IMA ADPCM `0x0011`). Reasonable to ship in 3f after MVP because the spec is public + small.
- **`WemOggHandler`**: WEM (Wwise) → OGG via header rewrite. WEM is essentially OGG-Vorbis with a Wwise-custom 12+ byte header at front; replacing the WEM packet headers with standard Ogg page headers via the [`ww2ogg`](https://github.com/hcs64/ww2ogg) algorithm (well-documented). No Vorbis decoder required — just framing rewrite.

## Out of scope (named target phases):

- **BINKA, XMA2, AT9, OPUSNX** — proprietary codecs requiring licensed SDKs. → **Phase 8.** Same runtime-loaded shared-library pattern Phase 8 ships for Oodle. 3f surfaces all four as `UnsupportedAudioCodec { codec_name: "BINKA" }` etc. with a tracked-Phase-8 hook.
- **In-app audio playback** (decode Vorbis/Opus/ADPCM to raw PCM samples for the GUI viewer pane). → **Phase 7 (GUI Asset Viewers).** Phase 3f's job is export-to-file: passthrough rewrap + WAV wrapping is sufficient. Phase 7 needs full decoders for the playback widget; different deps (`lewton` or `symphonia` for Vorbis decode, etc.).
- **Streaming chunk reassembly into a single continuous OGG file.** A streaming USoundWave's chunks each carry independent OGG-framed bytes. Concatenating them produces a valid OGG (Vorbis tolerates concatenated streams) but not a single canonical Vorbis bitstream. 3f's MVP exports the first chunk; multi-chunk reassembly is a 3f follow-up.
- **`USoundCue` / `USoundClass` / `USoundAttenuation`** — related audio export classes that are NOT `USoundWave`. Out of scope; Phase 3+ adds when needed.

---

## Crate-selection candidates (decide at kickoff)

| Component | Candidate | Notes |
|-----------|-----------|-------|
| WAV writer | `hound` | Pure-Rust WAV reader+writer; minimal deps; license MIT/Apache. **Recommended** for `WavHandler`. |
| WAV writer alt. | hand-rolled RIFF/WAV writer | ~50 lines; avoids new dep if `hound` brings transitive deps we don't want. Recommended only if dep audit blocks `hound`. |
| OGG framing inspection (WEM follow-up) | `ogg` (pure-Rust container library) | For verifying generated OGG passthrough output. Optional in MVP. |
| Vorbis / Opus decode (PHASE 7, NOT 3f) | `lewton` (Vorbis), `audiopus` (Opus) | Listed for context — NOT pulled in 3f's MVP. |

---

## Milestone breakdown (proposed)

1. **3f-1: Variant + tagged-property segment + dispatch wiring.** USoundWave class name routes to typed reader.
2. **3f-2: USoundWave binary header + streaming dispatch.** `Flags`, `bStreaming` resolution (3-step precedence per format doc), DummyCompressionName conditional. Cue points UE 5.4+ when cooked.
3. **3f-3: `FFormatContainer` reader** + non-streaming path. Each codec buffer extracted via 3b's resolver. Streaming-flip retry on failure.
4. **3f-4: `FStreamedAudioPlatformData` reader** + streaming path. Chunked layout with per-chunk `FByteBulkData`.
5. **3f-5: `OggPassthroughHandler` + `OpusPassthroughHandler`** (MVP). Cross-validate against CUE4Parse-generated `.ogg` byte-for-byte (passthrough should be exact).
6. **3f-6: `PcmWavHandler`** (MVP). Hound-based WAV header + sample data.
7. **3f-7 (follow-up): `AdpcmWavHandler`.** Decode ADPCM → WAV. Public spec.
8. **3f-8 (follow-up): `WemOggHandler`.** WEM header rewrite to OGG framing.

Each task: failing TDD test against hand-built byte fixture → impl → gate → commit. Wire-format specialist MANDATORY.

---

## Fixture-count gate

3f's TDD conversion adds ~5-7 fixtures (one per codec key: OGG, OPUS, PCM, ADPCM-MS, ADPCM-DVI; plus a streaming `FStreamedAudioPlatformData` fixture and a streaming-flip-retry fixture). Bump `.github/workflows/ci.yml`'s fixture-count constant per `feedback_fixture_count_gate.md`.

## Contract callouts for TDD conversion

- **`TypedReaderFn` returns `Result<(Asset, Vec<FByteBulkData>)>`** (per 3a R3 fix). The audio reader collects per-codec / per-chunk `FByteBulkData` records during `FFormatContainer` / `FStreamedAudioPlatformData` parsing and returns them in the second tuple element; the dispatch caller drives `insert_bulk_records`. Typed audio-reader signature: `pub(crate) fn read_typed(payload: &[u8], ctx: &AssetContext, asset_path: &str) -> crate::Result<(Asset, Vec<FByteBulkData>)>`.

## Open questions for kickoff

1. **Streaming-flip retry shape.** CUE4Parse retries with `bStreaming` flipped on exception; do we mimic exactly, or surface the version-table miss explicitly to the user?
2. **WAV writer dep audit.** `hound` is small but adds a transitive; weigh against ~50 lines of hand-rolled RIFF.
3. **OGG passthrough exactness.** Does the FFormatContainer OGG buffer carry a fully-formed Ogg bitstream, or just the Vorbis packet payload requiring Ogg framing addition? Format doc says full Ogg container per Xiph spec — verify with a real cooked SoundWave fixture at kickoff before locking the passthrough handler shape.
4. **Multi-codec USoundWave priority.** When the asset carries both OGG and OPUS buffers, which does the default handler return? Recommendation: user picks via `find_handler_by_extension("ogg" | "opus", &asset)`. The default `find_handler` returns the first registered handler that supports the asset; let the registration order determine the default (Ogg first, then Opus, then PCM, then Adpcm).

---

## Review panel (when 3f enters TDD)

- Wire-format pass — MANDATORY (`FFormatContainer` + `FStreamedAudioPlatformData` are non-trivial).
- Security pass — MANDATORY (sign-extension on `NumFormats` / `NumChunks` / `DataSize` / `AudioDataSize` per format doc §Caps).
- Streaming-flip retry needs special scrutiny — easy to introduce double-error states.
- Deep-impact tracer — MANDATORY (adds `Asset::SoundWave` variant).

5 reviewers per task PR.

---

## References

- Wire-format references:
  - [`../formats/audio/sound-wave.md`](../formats/audio/sound-wave.md) — USoundWave wire layout.
  - [`../formats/audio/audio-codecs.md`](../formats/audio/audio-codecs.md) — codec dispatch + per-codec wire shape.
- Master index: [`phase-3-export-pipeline.md`](phase-3-export-pipeline.md).
- WEM → OGG reference: `ww2ogg` (`hcs64/ww2ogg`) algorithm — header rewrite, no Vorbis decode required.
