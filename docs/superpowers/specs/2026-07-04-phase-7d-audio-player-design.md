# Phase 7d — GUI Audio Player Design

**Goal:** Add an in-app audio player `ViewMode::Audio` to the `paksmith-gui` tabbed
viewer, giving USoundWave assets real-time playback (play/pause, seek, volume,
waveform) for the codecs `paksmith-core` can decode, and a metadata + export
fallback for the ones it cannot.

**Builds on:** Phase 7a (tabbed viewer + `ViewMode`), Phase 7b (texture viewer —
the pure-state / async-task / thin-view pattern this mirrors), Phase 3f (audio
decode: PCM, ADPCM, Vorbis→PCM) and the Phase 3 export façade.

**Split from:** Phase 7c chrome, which deferred the AudioPlayer because it needs a
real-time audio-output dependency, is platform-dependent, and is hard to
unit-test — none of which belong in a chrome slice.

---

## Background — what already exists

- **Core decodes audio to bytes and samples.** `crate::export` handlers turn a
  parsed USoundWave into standard containers: `WavHandler` (PCM passthrough /
  ADPCM→16-bit PCM), `OggHandler` (Vorbis passthrough), `VorbisHandler`
  (Vorbis→PCM WAV via `symphonia`), and `RawSoundHandler` (proprietary
  Opus/Bink/XMA/AT9 surfaced raw). `export/pcm.rs::build_pcm_wav(samples,
  channels, sample_rate)` wraps interleaved `i16` samples into RIFF/WAVE and is
  the common tail of every decode path. A 1 GiB decoded-bytes cap
  (`MAX_AUDIO_DECODED_BYTES`) guards against decompression bombs.
- **No sample-level public API yet.** The decode internals exist but are only
  reachable through the byte-producing handlers; there is no `classify_audio` or
  decode-to-samples entry point analogous to texture's `classify_texture` /
  `decode_texture_mip`.
- **The 7a/7b GUI pattern is ready.** `ViewMode` (`state/tabs.rs`), per-tab state
  (`Tab.texture`), an async decode task (`task/texture.rs`), a thin
  `#[mutants::skip]` view (`widgets/texture_viewer.rs`), detection in `app.rs`'s
  `AssetLoaded` handler, and dispatch + a conditional switcher entry in
  `panels/content.rs`.
- **No audio output anywhere.** iced 0.14 has no audio. `paksmith-gui` has no
  audio-output dependency. `symphonia` lives in core, for Vorbis *decode* only.

---

## Architecture

### 1. Core additions (`paksmith-core`)

Two public functions, parallel to the texture surface, keep all decoding
core-owned and tested:

```rust
/// Cheap, pure classification of the primary USoundWave export. Metadata is read
/// from the USoundWave's parsed UE tagged properties (no decode), so it works for
/// non-playable codecs too. `playable` is true iff core can decode the codec
/// (PCM / ADPCM / Vorbis). Property-sourced fields are `Option` because
/// availability varies by asset/codec (see Risks); the plan pins exactly which
/// are present against the fixtures.
pub fn classify_audio(package: &Package) -> Option<AudioInfo>;

pub struct AudioInfo {
    pub export_idx: usize,
    pub codec_label: String,        // "PCM", "ADPCM", "Vorbis (Ogg)", "Opus", ...
    pub channels: Option<u16>,      // UE `NumChannels` tagged property
    pub duration_secs: Option<f32>, // UE `Duration` tagged property (best-effort)
    pub playable: bool,
}
```

The authoritative `sample_rate` and `channels` for a *playable* sound come from
`AudioPcm` after decode (read from the cooked stream header), which the metadata
header shows once decoded. `sample_rate` is deliberately *not* in `AudioInfo`:
it isn't a reliable tagged property (it lives in the WAV/Ogg header), so the
pre-decode header shows codec · channels · duration and gains the sample rate
after decode.

/// Decode the primary export to interleaved 16-bit PCM. Reuses the tested
/// Vorbis→PCM / ADPCM→PCM / PCM-passthrough internals, under the 1 GiB cap.
pub fn decode_audio_to_pcm(package: &Package, export_idx: usize)
    -> crate::Result<AudioPcm>;

pub struct AudioPcm {
    pub samples: Vec<i16>,   // interleaved
    pub sample_rate: u32,
    pub channels: u16,
}
```

`classify_audio` returns `Some` for every USoundWave (so any sound offers the
Audio view); `playable = false` for the proprietary codecs (Opus/Bink/XMA/AT9)
that have no in-core decoder. `decode_audio_to_pcm` is only called for playable
assets.

### 2. Playback engine — `rodio`, output-only

Playback output is the one part that cannot be pure. It is quarantined exactly
as Phase 7b quarantined the iced image `Handle`:

- Add **`rodio`** with **decoders disabled** (`default-features = false`) — we
  use only its `OutputStream`, `Sink`, and `SamplesBuffer<i16>`. Core does the
  decoding; rodio never parses a container.
- A **single app-level** `OutputStream` + `Sink` holds the currently-playing
  sound. One sound plays at a time (two is meaningless here), so there is one
  output, not one-per-tab.
- The rodio-touching operations (`play` / `pause` / `set_volume` / `stop` /
  append a `SamplesBuffer` sliced from a sample offset) live behind a thin,
  `#[mutants::skip]` audio-output seam. **Everything decision-shaped stays pure
  and mutation-tested:** PCM decode, waveform peak downsampling, the transport
  state machine, `mm:ss` formatting, and the seek offset math.
- **Seek** = truncate the sink and re-append a `SamplesBuffer` starting at the
  target sample offset. Because we own all the samples, this is format-agnostic
  and needs no reliance on rodio's version-dependent `try_seek`.

### 3. Playback lifecycle

- **One active playback, globally.** Switching tabs, closing the owning tab, or
  opening another sound **stops** the current sink first.
- **No autoplay.** Opening a sound promotes the tab to `ViewMode::Audio` in a
  ready/paused state; the user presses play.
- A **play-gated tick** (`iced::time::every`, subscribed only while a sound is
  playing) advances the playhead/elapsed readout from the sink's real playback
  position; it is `Subscription::none()` when paused/stopped so an idle Audio
  tab costs nothing.

---

## GUI components (mirrors 7b)

| File | Responsibility | Testability |
|---|---|---|
| `state/audio_view.rs` | Pure `AudioState { export_idx, info, decoded: Option<AudioPcm>, waveform_peaks, transport, volume, error, generation }`; pure helpers: peak downsampling, elapsed↔`mm:ss`, click-x→sample-offset seek math, transport transitions. | Unit + mutation tested |
| `task/audio.rs` | `async decode(pkg: Arc<Package>, export_idx) -> Result<AudioPcm, String>` → `Message::AudioDecoded { path, result, generation }`. | Thin async glue |
| `widgets/audio_player.rs` | Thin `#[mutants::skip]` view: metadata header, waveform `canvas` + playhead, transport row. | Manual smoke |
| `state/tabs.rs` | `ViewMode::Audio` variant; `audio: audio_view::AudioState` field on `Tab`; `audio_available(tab)`. | Unit tested (pure) |
| `panels/content.rs` | `ViewMode::Audio` dispatch arm; conditional switcher entry. | Skip-zone view / unit-tested availability |
| `app.rs` | Detection in `AssetLoaded` (`classify_audio` → promote view + dispatch decode); `Message` arms (`AudioDecoded`, `AudioPlayPause`, `AudioStop`, `AudioSeek(f32)`, `AudioVolume(f32)`, `AudioTick`); the rodio sink holder; the play-gated tick subscription. | Update arms unit-tested; sink holder in skip-zone |

The `Transport` state is a small pure enum, e.g. `Playing { started_pos } |
Paused { pos } | Stopped`, with `elapsed`/duration derived — transitions and
derivations are unit + mutation tested.

---

## Data flow

1. User opens a USoundWave → async parse (existing) → `Message::AssetLoaded`.
2. `AssetLoaded` calls `classify_audio(pkg)`. On `Some`, populate `tab.audio.info`
   and (if the default view is still active) promote the tab to `ViewMode::Audio`.
3. If `info.playable`, immediately dispatch `task::audio::decode(pkg, idx)`.
4. `Message::AudioDecoded` stores `AudioPcm`, computes `waveform_peaks` (pure),
   and leaves transport `Stopped`/ready. Stale results are dropped via the
   `generation` guard (same as texture).
5. Play/pause/seek/volume messages drive the transport state machine (pure) and
   the rodio seam (glue). The play-gated tick advances the playhead while
   playing.

---

## UX

**Playable sound:** metadata header (codec · channels · duration, gaining sample
rate once decoded) →
waveform overview (static min/max peaks per column, drawn on an iced `canvas`)
with a playhead line and click/drag-to-seek → transport row (play/pause toggle,
stop, volume slider, `elapsed / duration`).

**Non-playable (proprietary) sound:** the Audio tab still appears (it *is* a
sound), showing the metadata header plus "Codec _X_ can't be decoded in-app —
use **Export As…** to save the raw stream." No transport row. Driven by
`info.playable = false`.

---

## Error handling

- **Decode error** → `AudioState.error`, rendered inline; non-fatal (matches the
  texture view). The tab remains usable (metadata still shows).
- **No audio device / rodio init failure** → the view still renders metadata +
  waveform with playback controls disabled, plus a toast ("No audio output
  available"). **Never panics** — core stays panic-free, the GUI degrades
  gracefully.
- **Oversized decode** → already rejected by core's 1 GiB cap, surfaced as a
  normal decode error.

---

## Testing strategy

- **Core:** `classify_audio` and `decode_audio_to_pcm` are TDD'd against the
  existing audio fixtures (`export/testdata/vorbis_stereo.ogg`,
  `adpcm_ima_*`/`adpcm_ms_*` WAV+expected-PCM pairs), 0-missed mutants.
- **GUI pure state:** waveform peak downsampling, transport transitions, seek
  offset math, and time formatting are unit + mutation tested with divergent
  inputs (per the PR #620 lesson — no degenerate/identity assertions).
- **The rodio sink** is the single `#[mutants::skip]` seam, verified by a
  **manual smoke checklist** (plays, pauses, seeks, volume, stops on tab
  switch/close), exactly as 7b's image `Handle` was.

---

## Risks / hazards (validate in the plan before building on them)

1. **`OutputStream` is `!Send` and must stay alive.** Where it lives relative to
   iced 0.14's app state — and whether iced's runtime imposes `Send` on the state
   — is the one real unknown. **Mitigation:** the plan's first task verifies
   empirically whether the stream can live in `App`; if not, fall back to a
   dedicated audio thread owning the stream, driven by a command channel.
2. **rodio feature surface.** Confirm `default-features = false` yields
   `OutputStream` + `Sink` + `SamplesBuffer` without pulling decoder crates;
   pin exact features in the plan.
3. **Seek/position API.** The truncate-and-re-append seek avoids `try_seek`, but
   reading the live playback position for the playhead may need `Sink::get_pos`
   (rodio ≥ 0.19) or a samples-consumed estimate — pin in the plan.
4. **Linux CI needs ALSA headers.** `rodio`→`cpal` needs `libasound2-dev` on the
   ubuntu runners (same class of issue as muda needing `libgtk-3-dev`). Add it to
   the Linux CI setup; mac/Windows are unaffected.
5. **New dependency review.** `rodio` + `cpal` enter the tree → `cargo-deny` /
   `cargo-audit` will scan them; check licenses and advisories in the plan.
6. **Metadata property availability.** `NumChannels` is a confirmed USoundWave
   tagged property; `Duration` is best-effort and may be absent on some assets.
   The plan's TDD pins which metadata is present pre-decode against the fixtures;
   the header degrades gracefully (shows "—") for absent fields.

---

## Scope / non-goals (YAGNI for v1)

In: single-file transport (play/pause/stop), seek, volume, static waveform,
metadata, export fallback for undecodable codecs.

Out: looping, playback-rate/pitch, playlists/queue, equalizer, spectrogram,
recording, and in-app decoding of proprietary codecs (Opus/Bink/XMA/AT9 — remain
export-only).

---

## Dependencies added

- `rodio` (workspace dependency, `default-features = false`) in `paksmith-gui`
  only. Core gains no new dependency (`decode_audio_to_pcm` reuses the existing
  `symphonia`-based Vorbis path and the in-house ADPCM/PCM decoders).
