# Phase 7d — GUI Audio Player Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an in-app audio player `ViewMode::Audio` to `paksmith-gui` giving USoundWave assets real-time playback (play/pause, seek, volume, waveform) for PCM/ADPCM/Vorbis, with a metadata + export fallback for undecodable codecs.

**Architecture:** Core gains two additive public functions (`classify_audio`, `decode_audio_to_pcm`) that reuse the existing tested decode paths. The GUI mirrors the Phase 7b texture viewer (pure `state/` · async `task/` · thin `#[mutants::skip]` `widgets/` · `Message` arms in `app.rs`). `rodio` is added **output-only** behind a single `#[mutants::skip]` `AudioOutput` seam; all decode / waveform / transport / seek logic is pure and mutation-tested.

**Tech Stack:** Rust, `paksmith-core` (decode), `iced` 0.14 (GUI), `rodio` 0.22 (audio output, decoders disabled), existing `symphonia` (core Vorbis decode).

## Global Constraints

- **MSRV 1.88** — no let-chains, no if-let match guards; `let-else`, `LazyLock`, `is_some_and`, `const fn` are fine.
- **No panics in core** — every fallible core path returns `Result<T, PaksmithError>`; reuse existing variants (`InvalidArgument { arg, reason }`, `UnsupportedFeature { context }`, `Internal { context }`).
- **TDD** — write the failing test first, watch it fail, then implement.
- **`rodio` is the only new dependency**, added to `paksmith-gui` only, `default-features = false` (no decoder stack). Core gains **no** new dependency.
- **`rodio`'s `OutputStream`/`Sink` are `!Send`** and the stream must stay alive for audio to continue. Its placement is resolved empirically in Task 1.
- **Single `#[mutants::skip]` seam:** only the `AudioOutput` wrapper (and the thin `widgets/audio_player.rs` view) touch rodio / are skip-marked. Everything else is pure and mutation-tested.
- **Mutation discipline:** `cargo mutants --in-diff <origin/main...HEAD>` must report 0 missed at full-PR scope before push; tests must use divergent (non-degenerate) inputs.
- **Linux CI needs `libasound2-dev`** (rodio→cpal→alsa-sys), added in Task 1.
- **Naming (verbatim):** `ViewMode::Audio`; core `classify_audio` / `decode_audio_to_pcm`; types `AudioInfo`, `AudioPcm`; GUI `AudioState`, `Transport`, `AudioOutput`; messages `AudioDecoded`, `AudioPlayPause`, `AudioStop`, `AudioVolume(f32)`, `AudioSeek(f32)`, `AudioTick`.
- **Every change gets the adversarial review panel before push** (per project CLAUDE.md). Playback (the `AudioOutput` seam + the view) is verified by a **manual smoke checklist**, not unit tests.

---

## File Structure

**Core (`crates/paksmith-core/src/`):**
- `asset/exports/audio/mod.rs` — **modify**: add `pub fn classify_audio`, `pub fn decode_audio_to_pcm`, `pub struct AudioInfo`, `pub struct AudioPcm`. Re-export from `asset` (mirror how `classify_texture`/`decode_texture_mip` are re-exported).
- `export/pcm.rs` — **modify**: add a `pub(crate) fn parse_pcm_wav(wav: &[u8]) -> crate::Result<(u16, u32, Vec<i16>)>` (channels, sample_rate, interleaved samples) if no reusable WAV parser exists; otherwise reuse the existing `parse_wav` test helper by promoting it to `pub(crate)`.

**GUI (`crates/paksmith-gui/src/`):**
- `state/audio_view.rs` — **create**: `AudioState`, `Transport`, `DecodedAudio`, and pure helpers (waveform peaks, transport transitions, seek math, time format).
- `task/audio.rs` — **create**: `async fn decode(...) -> Result<DecodedAudio, String>`.
- `widgets/audio_player.rs` — **create**: thin `#[mutants::skip]` `view`.
- `audio_output.rs` — **create**: the `#[mutants::skip]` `AudioOutput` rodio seam (top-level module, sibling to `app.rs`).
- `state/tabs.rs` — **modify**: `ViewMode::Audio`, `Tab.audio`, `audio_available`, `open_or_activate`, `pick_view_after_load`.
- `panels/content.rs` — **modify**: `ViewMode::Audio` dispatch arm + switcher entry.
- `app.rs` — **modify**: `Message` arms, `AssetLoaded` detection, the `AudioOutput` holder on `App`, the play-gated tick in `subscription()`.
- `state/mod.rs`, `task/mod.rs`, `widgets/mod.rs`, `lib.rs`/`main.rs` module lists — **modify**: register new modules.

**CI / deps:**
- `Cargo.toml` (workspace) — add `rodio` to `[workspace.dependencies]`.
- `crates/paksmith-gui/Cargo.toml` — `rodio.workspace = true`.
- `.github/workflows/*.yml` — add `libasound2-dev` install on ubuntu jobs that build the GUI.

---

## Task 1: rodio dependency + `AudioOutput` seam + `!Send` placement + Linux CI

**This task is the de-risking spike. It resolves rodio's exact 0.22 API, the `!Send` `OutputStream` placement, and produces the seam every later task calls. Its playback behaviour is verified by manual smoke, not unit tests.**

**Files:**
- Modify: `Cargo.toml` (workspace `[workspace.dependencies]`), `crates/paksmith-gui/Cargo.toml`
- Create: `crates/paksmith-gui/src/audio_output.rs`
- Modify: `crates/paksmith-gui/src/main.rs` (or `lib.rs`) module list
- Modify: `.github/workflows/ci.yml` (+ any other ubuntu GUI-building job)

**Interfaces:**
- Produces: a `#[mutants::skip]` seam
  ```rust
  pub struct AudioOutput { /* owns OutputStream + Sink; fields private */ }
  impl AudioOutput {
      /// None if no audio device / init failed (never panics).
      pub fn new() -> Option<Self>;
      /// Replace whatever is playing with these samples and start playing.
      pub fn play_samples(&mut self, samples: Vec<i16>, channels: u16, sample_rate: u32);
      pub fn pause(&mut self);
      pub fn resume(&mut self);
      pub fn stop(&mut self);
      pub fn set_volume(&mut self, volume: f32);
      /// Current playback position, if the backend exposes it.
      pub fn position(&self) -> Option<std::time::Duration>;
      /// True once the queued samples have finished playing.
      pub fn finished(&self) -> bool;
  }
  ```

- [ ] **Step 1: Pin the rodio version + minimal features.** Add to workspace `Cargo.toml` `[workspace.dependencies]`:
  ```toml
  # Phase 7d: audio OUTPUT only. `default-features = false` drops rodio's decoder
  # stack (symphonia/hound/etc.) — paksmith-core decodes; rodio just plays raw
  # i16 samples via SamplesBuffer. Keep only what OutputStream/Sink/SamplesBuffer
  # need. Pin the exact minimal feature set here after Step 2 confirms it builds.
  rodio = { version = "0.22", default-features = false }
  ```
  And in `crates/paksmith-gui/Cargo.toml` under `[dependencies]`: `rodio.workspace = true`.

- [ ] **Step 2: Confirm the minimal build + resolve the exact API.** Run `cargo build -p paksmith-gui`. In `audio_output.rs`, write the seam against rodio 0.22's real API — **verify each call against `cargo doc --open -p rodio` or the source in `~/.cargo`**, since the API changed across 0.19–0.22. Expect roughly:
  ```rust
  //! The one place that touches `rodio`. Real-time audio output cannot be
  //! unit-tested, so this whole module is `#[mutants::skip]` and verified by the
  //! manual smoke checklist in the Phase 7d plan (Task 1). All decision logic
  //! (decode, waveform, transport, seek) lives in pure modules elsewhere.

  use std::time::Duration;
  use rodio::{OutputStream, Sink, buffer::SamplesBuffer};

  pub struct AudioOutput {
      // Field order matters: `sink` is dropped before `_stream`. `_stream` MUST
      // outlive the sink and stay alive for the whole app — dropping it stops
      // all audio.
      sink: Sink,
      _stream: OutputStream,
  }

  #[mutants::skip]
  impl AudioOutput {
      pub fn new() -> Option<Self> {
          // rodio 0.22: OutputStreamBuilder::open_default_stream() (verify exact
          // path/name). Returns Result; map any error to None so a missing audio
          // device degrades gracefully instead of panicking.
          let stream = OutputStream::try_default().ok()?; // ADJUST to 0.22 API
          let sink = Sink::try_new(stream.mixer()).ok()?;  // ADJUST to 0.22 API
          sink.pause();
          Some(Self { sink, _stream: stream })
      }
      pub fn play_samples(&mut self, samples: Vec<i16>, channels: u16, sample_rate: u32) {
          self.sink.stop(); // clear any prior queue
          self.sink.append(SamplesBuffer::new(channels, sample_rate, samples));
          self.sink.play();
      }
      pub fn pause(&mut self) { self.sink.pause(); }
      pub fn resume(&mut self) { self.sink.play(); }
      pub fn stop(&mut self) { self.sink.stop(); }
      pub fn set_volume(&mut self, volume: f32) { self.sink.set_volume(volume); }
      pub fn position(&self) -> Option<Duration> { Some(self.sink.get_pos()) } // if 0.22 has get_pos; else None
      pub fn finished(&self) -> bool { self.sink.empty() }
  }
  ```
  Record in the module doc comment the EXACT 0.22 constructor names used and whether `get_pos` exists (drives whether the playhead reads `position()` or estimates from a samples-consumed counter — see Task 8).

- [ ] **Step 3: Resolve the `!Send` placement.** Determine whether `AudioOutput` can be a field on the iced `App` struct. Add a temporary field `audio: Option<AudioOutput>` to `App` and `cargo build -p paksmith-gui`.
  - If it compiles and runs: `AudioOutput` lives on `App` (simplest). Keep the field.
  - If iced's runtime rejects the non-`Send` state (compile error mentioning `Send`): fall back to a dedicated audio thread that owns the `OutputStream`+`Sink` and receives commands over an `std::sync::mpsc` channel; `App` holds only the `Sender<AudioCommand>` (which IS `Send`). In that case `AudioOutput` becomes the thread + channel wrapper, keeping the same public method surface above (methods send commands).
  - **Document the outcome** in the module doc — later tasks depend only on the method surface, not the internal choice.

- [ ] **Step 4: Register the module.** Add `mod audio_output;` (and `pub use` if needed) to `main.rs`/`lib.rs`. Run `cargo build -p paksmith-gui` — expect clean.

- [ ] **Step 5: Add `libasound2-dev` to Linux CI.** In every ubuntu job that builds `paksmith-gui` (grep `.github/workflows/` for `ubuntu` + existing `libgtk-3-dev`/`apt-get`), add `libasound2-dev` to the `apt-get install` list, next to the existing GUI deps. Mirror exactly how `libgtk-3-dev` is installed (see MEMORY: muda needed libgtk on Linux CI).

- [ ] **Step 6: Manual smoke.** Add a temporary `#[cfg(test)]`-free scratch call (or a `cargo run` one-off, then revert) that builds an `AudioOutput`, plays ~0.5s of a generated 440 Hz sine (`(0..22050).map(|i| ((i as f32 * 440.0 * 2.0 * PI / 44100.0).sin() * 8000.0) as i16)`, channels=1, rate=44100), and confirm you HEAR a tone. Revert the scratch. Note the result in the task report.

- [ ] **Step 7: Gates + commit.** `cargo fmt --all`; `cargo clippy -p paksmith-gui --all-targets --all-features -- -D warnings`; `cargo build --workspace`. Commit:
  ```bash
  git add -A
  git commit -m "feat(gui): add rodio audio-output seam (phase 7d task 1)"
  ```

---

## Task 2: Core `AudioPcm` + `decode_audio_to_pcm`

**Files:**
- Modify: `crates/paksmith-core/src/asset/exports/audio/mod.rs`
- Modify: `crates/paksmith-core/src/export/pcm.rs` (add/expose a WAV→samples parser)
- Modify: `crates/paksmith-core/src/asset/mod.rs` (re-export, mirroring `decode_texture_mip`)

**Interfaces:**
- Consumes: `Package::payloads: Vec<Asset>`, `Package::resolve_bulk_for_export(idx) -> crate::Result<Vec<BulkData>>`, `Asset::SoundWave(SoundWaveData)`, `SoundWaveData { properties, cooked, streaming, compressed_format_keys, streamed, .. }`, `export::vorbis::transcode_vorbis_to_pcm(&[u8]) -> Result<Option<Vec<u8>>>`, `export::adpcm::transcode_adpcm_to_pcm(&[u8]) -> Result<Option<Vec<u8>>>`, the audio.rs helpers `active_codec(&SoundWaveData) -> Option<&str>` and the bulk-to-bytes helpers (`extract_nonstreaming`/`assemble_streaming` — make them reachable from this module or inline the equivalent).
- Produces:
  ```rust
  pub struct AudioPcm { pub samples: Vec<i16>, pub sample_rate: u32, pub channels: u16 }
  pub fn decode_audio_to_pcm(package: &Package, export_idx: usize) -> crate::Result<AudioPcm>;
  ```

- [ ] **Step 1: Failing test — decode IMA-ADPCM mono to samples.** In `asset/exports/audio/mod.rs` tests (reuse the existing `nonstreaming(&["ADPCM"])` + `bulk(..)` helpers from the audio export tests; see `audio.rs:687` `wav_handler_decodes_ima_adpcm_buffer`). Build a `Package` whose primary export is that SoundWave with the `adpcm_ima_mono.wav` cooked buffer as its bulk, then:
  ```rust
  #[test]
  fn decode_audio_to_pcm_ima_adpcm_mono_matches_expected() {
      const EXPECTED: &[u8] = include_bytes!("../../../export/testdata/adpcm_ima_mono_expected.pcm");
      let pkg = /* package with SoundWave(nonstreaming(&["ADPCM"])) + bulk(adpcm_ima_mono.wav) */;
      let pcm = decode_audio_to_pcm(&pkg, 0).expect("decode ok");
      assert_eq!(pcm.channels, 1);
      assert_eq!(pcm.sample_rate, 44100);
      // Samples, re-serialized LE, equal the ffmpeg oracle PCM byte-for-byte.
      let bytes: Vec<u8> = pcm.samples.iter().flat_map(|s| s.to_le_bytes()).collect();
      assert_eq!(bytes, EXPECTED);
  }
  ```
  (Look at `audio.rs` tests for the exact `Package`/`nonstreaming`/`bulk` construction helpers; reuse them verbatim.)

- [ ] **Step 2: Run — expect FAIL** (`decode_audio_to_pcm` undefined). `cargo test -p paksmith-core decode_audio_to_pcm_ima_adpcm_mono_matches_expected`.

- [ ] **Step 3: Add the WAV→samples parser** in `export/pcm.rs`. The cooked/decoded WAV may have a non-minimal header, so scan for `fmt ` + `data` chunks (reuse the existing `parse_wav` test helper — promote it to `pub(crate)` — rather than writing a new one if it already finds chunks robustly):
  ```rust
  /// Parse a 16-bit PCM WAV into (channels, sample_rate, interleaved i16 samples).
  /// Rejects non-PCM / non-16-bit with `UnsupportedFeature`.
  pub(crate) fn parse_pcm_wav(wav: &[u8]) -> crate::Result<(u16, u32, Vec<i16>)> {
      let (fmt, data) = parse_wav(wav).ok_or_else(|| crate::PaksmithError::Internal {
          context: "decoded audio is not a valid WAV".to_string(),
      })?;
      if fmt.format_tag != 1 || fmt.bits_per_sample != 16 {
          return Err(crate::PaksmithError::UnsupportedFeature {
              context: format!("audio WAV is not 16-bit PCM (tag={}, bits={})", fmt.format_tag, fmt.bits_per_sample),
          });
      }
      let samples = data.chunks_exact(2).map(|b| i16::from_le_bytes([b[0], b[1]])).collect();
      Ok((fmt.channels, fmt.sample_rate, samples))
  }
  ```
  (Confirm `parse_wav`'s exact return shape from `adpcm.rs`/`vorbis.rs` tests and match field names.)

- [ ] **Step 4: Implement `decode_audio_to_pcm`.** In `asset/exports/audio/mod.rs`:
  ```rust
  pub struct AudioPcm { pub samples: Vec<i16>, pub sample_rate: u32, pub channels: u16 }

  pub fn decode_audio_to_pcm(package: &Package, export_idx: usize) -> crate::Result<AudioPcm> {
      let asset = package.payloads.get(export_idx).ok_or(crate::PaksmithError::InvalidArgument {
          arg: "export_idx",
          reason: format!("out of range (payloads: {})", package.payloads.len()),
      })?;
      let Asset::SoundWave(data) = asset else {
          return Err(crate::PaksmithError::InvalidArgument {
              arg: "export_idx",
              reason: "export is not a USoundWave".to_string(),
          });
      };
      let bulk = package.resolve_bulk_for_export(export_idx)?;
      let cooked = /* reach the codec container bytes: reuse audio.rs
                      extract_nonstreaming / assemble_streaming per data.streamed */;
      let codec = active_codec(data).ok_or(crate::PaksmithError::Internal {
          context: "USoundWave has no active codec".to_string(),
      })?;
      // Produce 16-bit PCM WAV bytes via the existing tested decode paths.
      let wav: Vec<u8> = match codec.to_ascii_uppercase().as_str() {
          "OGG" => crate::export::vorbis::transcode_vorbis_to_pcm(&cooked)?
              .ok_or(crate::PaksmithError::Internal {
                  context: "cooked OGG buffer is not decodable Ogg-Vorbis".to_string(),
              })?,
          "ADPCM" | "PCM" => match crate::export::adpcm::transcode_adpcm_to_pcm(&cooked)? {
              Some(pcm) => pcm,   // ADPCM decoded to PCM WAV
              None => cooked,     // already PCM WAV — passthrough
          },
          other => return Err(crate::PaksmithError::UnsupportedFeature {
              context: format!("audio codec `{other}` is not decodable in-app"),
          }),
      };
      let (channels, sample_rate, samples) = crate::export::pcm::parse_pcm_wav(&wav)?;
      Ok(AudioPcm { samples, sample_rate, channels })
  }
  ```
  Re-export from `asset/mod.rs` alongside `decode_texture_mip` (grep for `pub use ...decode_texture_mip` and add `decode_audio_to_pcm`, `AudioPcm`).

- [ ] **Step 5: Run — expect PASS.** `cargo test -p paksmith-core decode_audio_to_pcm_ima_adpcm_mono_matches_expected`.

- [ ] **Step 6: Add coverage for the other codecs + errors.** Add tests: MS-ADPCM stereo (`adpcm_ms_stereo` vs expected), Vorbis (`vorbis_stereo.ogg` → assert channels=2, rate=44100; energy band like `vorbis.rs:247`, since lossy), a non-SoundWave export → `InvalidArgument`, an out-of-range `export_idx` → `InvalidArgument`, and a proprietary codec (`nonstreaming(&["OPUS"])`) → `UnsupportedFeature`. Run all: `cargo test -p paksmith-core decode_audio_to_pcm`.

- [ ] **Step 7: Mutation + gates.** `cargo fmt --all`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`; `cargo test -p paksmith-core`; then `cargo mutants -p paksmith-core --file crates/paksmith-core/src/asset/exports/audio/mod.rs --file crates/paksmith-core/src/export/pcm.rs` and ensure 0 missed on the new lines. Commit:
  ```bash
  git commit -am "feat(core): add decode_audio_to_pcm (phase 7d task 2)"
  ```

---

## Task 3: Core `AudioInfo` + `classify_audio`

**Files:**
- Modify: `crates/paksmith-core/src/asset/exports/audio/mod.rs`, `crates/paksmith-core/src/asset/mod.rs`

**Interfaces:**
- Consumes: `Package::payloads`, `Package::has_bulk_records(idx) -> bool`, `Asset::SoundWave`, `SoundWaveData.properties` (`PropertyBag::Tree { properties }`), the property accessor pattern (`scalar_property(properties, "NumChannels")` → `PropertyValue::Int`), `active_codec`, `codec_prefix`.
- Produces:
  ```rust
  pub struct AudioInfo {
      pub export_idx: usize,
      pub codec_label: String,
      pub channels: Option<u16>,
      pub duration_secs: Option<f32>,
      pub playable: bool,
  }
  pub fn classify_audio(package: &Package) -> Option<AudioInfo>;
  ```

- [ ] **Step 1: Failing test — classify an ADPCM SoundWave as playable.**
  ```rust
  #[test]
  fn classify_audio_reports_playable_adpcm_with_channels() {
      let pkg = /* Package with primary export SoundWave(nonstreaming(&["ADPCM"]))
                   carrying a single NumChannels=1 tagged property + bulk */;
      let info = classify_audio(&pkg).expect("is a sound");
      assert_eq!(info.export_idx, 0);
      assert_eq!(info.codec_label, "ADPCM");
      assert_eq!(info.channels, Some(1));
      assert!(info.playable);
  }
  ```
  (Reuse the SoundWave test builders; see `sound_wave.rs:672` `assert_single_numchannels` for how NumChannels sits in the property bag.)

- [ ] **Step 2: Run — expect FAIL.** `cargo test -p paksmith-core classify_audio_reports_playable_adpcm_with_channels`.

- [ ] **Step 3: Implement `classify_audio`.** Scan payloads for the first `Asset::SoundWave` with bulk records (mirror `classify_texture`'s `has_bulk_records` guard). Map the codec to `codec_label` + `playable`; read `NumChannels`/`Duration` from the property bag (Option — absent is fine):
  ```rust
  pub fn classify_audio(package: &Package) -> Option<AudioInfo> {
      let (export_idx, data) = package.payloads.iter().enumerate().find_map(|(i, a)| match a {
          Asset::SoundWave(d) if package.has_bulk_records(i) => Some((i, d)),
          _ => None,
      })?;
      let codec = active_codec(data)?; // e.g. "ADPCM", "PCM", "OGG", "OPUS", ...
      let (codec_label, playable) = match codec.to_ascii_uppercase().as_str() {
          "PCM" => ("PCM".to_string(), true),
          "ADPCM" => ("ADPCM".to_string(), true),
          "OGG" => ("Vorbis (Ogg)".to_string(), true),
          other => (other.to_string(), false),
      };
      let (channels, duration_secs) = read_sound_metadata(data); // Option each
      Some(AudioInfo { export_idx, codec_label, channels, duration_secs, playable })
  }

  /// Read NumChannels (Int) + Duration (Float) from the tagged-property bag.
  fn read_sound_metadata(data: &SoundWaveData) -> (Option<u16>, Option<f32>) {
      let PropertyBag::Tree { properties } = &data.properties else { return (None, None) };
      let channels = scalar_property(properties, "NumChannels").and_then(|p| match p.value {
          PropertyValue::Int(n) => u16::try_from(n).ok(),
          _ => None,
      });
      let duration = scalar_property(properties, "Duration").and_then(|p| match p.value {
          PropertyValue::Float(f) => Some(f),
          _ => None,
      });
      (channels, duration)
  }
  ```
  (Verify `PropertyValue`'s exact variant names — `Int`/`Float`/`Name` — from `sound_wave.rs:483` `scalar_property`/`bool_property`/`name_property`. Adjust if channels is stored as a different numeric variant.)

- [ ] **Step 4: Run — expect PASS.**

- [ ] **Step 5: Coverage.** Add: OGG → `codec_label == "Vorbis (Ogg)"`, `playable`; OPUS → `playable == false`, `codec_label == "OPUS"`; a package with no SoundWave → `None`; a SoundWave without bulk records → `None`; a SoundWave whose bag lacks NumChannels → `channels == None` (graceful). Run: `cargo test -p paksmith-core classify_audio`.

- [ ] **Step 6: Mutation + gates + commit.** Same gate set as Task 2 Step 7 (mutate `audio/mod.rs`). Commit:
  ```bash
  git commit -am "feat(core): add classify_audio (phase 7d task 3)"
  ```

---

## Task 4: GUI pure state — `AudioState` + `ViewMode::Audio` + tab wiring

**Files:**
- Create: `crates/paksmith-gui/src/state/audio_view.rs`
- Modify: `crates/paksmith-gui/src/state/mod.rs` (`pub mod audio_view;`)
- Modify: `crates/paksmith-gui/src/state/tabs.rs`

**Interfaces:**
- Consumes: `paksmith_core::asset::{AudioInfo, AudioPcm}` (Task 2/3).
- Produces:
  ```rust
  // state/audio_view.rs
  pub struct DecodedAudio { pub samples: Vec<i16>, pub sample_rate: u32, pub channels: u16 }
  pub enum Transport { Stopped, Playing, Paused }
  pub struct AudioState {
      pub export_idx: usize,
      pub info: Option<AudioInfo>,
      pub decoded: Option<DecodedAudio>,
      pub waveform: Vec<(f32, f32)>, // (min,max) per column bucket, in [-1,1]
      pub transport: Transport,
      pub position_secs: f32,        // playhead, seconds
      pub volume: f32,               // 0.0..=1.0
      pub error: Option<String>,
  }
  impl Default for AudioState { /* transport Stopped, volume 1.0, rest empty/None/0 */ }
  // state/tabs.rs
  pub enum ViewMode { Properties, Hex, Info, Texture, Audio } // + Audio
  // Tab gains `pub audio: audio_view::AudioState`
  pub fn audio_available(tab: &Tab) -> bool; // tab.audio.info.is_some()
  ```

- [ ] **Step 1: Failing test — `audio_available` reflects a classified sound.** In `state/tabs.rs` tests:
  ```rust
  #[test]
  fn audio_available_is_true_only_once_classified() {
      let mut tab = /* a Tab via open_or_activate or a test constructor */;
      assert!(!audio_available(&tab));
      tab.audio.info = Some(/* an AudioInfo */);
      assert!(audio_available(&tab));
  }
  ```

- [ ] **Step 2: Run — expect FAIL** (no `audio` field / `audio_available`). 

- [ ] **Step 3: Create `state/audio_view.rs`** with the structs above (mirror `texture_view.rs:169` `TextureState` + its `Default`). `Transport::Stopped` default, `volume: 1.0`.

- [ ] **Step 4: Wire `state/tabs.rs`** — add `Audio` to `ViewMode` (state/tabs.rs:15), add `pub audio: audio_view::AudioState` to `Tab` (state/tabs.rs:35), initialise it in `open_or_activate` (state/tabs.rs:76: `audio: audio_view::AudioState::default(),`), add `audio_available` next to `texture_available` (state/tabs.rs:62), and extend `pick_view_after_load` (state/tabs.rs:159) to prefer Audio when available:
  ```rust
  if texture_available(tab) {
      tab.view = ViewMode::Texture;
  } else if audio_available(tab) {
      tab.view = ViewMode::Audio;
  } else if matches!(&tab.content, TabContent::Ready { parsed: Err(_), .. }) {
      tab.view = ViewMode::Info;
  }
  ```
  Register `pub mod audio_view;` in `state/mod.rs`.

- [ ] **Step 5: Run — expect PASS.**

- [ ] **Step 6: Add a `pick_view_after_load` promotion test** (divergent from texture): a tab with `audio.info = Some` and empty texture mips, default `Properties` view → after `pick_view_after_load` → `ViewMode::Audio`; and a tab where the user already set `Hex` → stays `Hex`. Run tests.

- [ ] **Step 7: Gates + mutation + commit.** `cargo fmt`; `cargo clippy -p paksmith-gui --all-targets --all-features -- -D warnings`; `cargo test -p paksmith-gui`; `cargo mutants -p paksmith-gui --file crates/paksmith-gui/src/state/tabs.rs` (0 missed on `audio_available` + the promotion branch). Commit:
  ```bash
  git commit -am "feat(gui): add ViewMode::Audio + AudioState wiring (phase 7d task 4)"
  ```

---

## Task 5: Pure waveform peaks + time formatting

**Files:** Modify `crates/paksmith-gui/src/state/audio_view.rs`

**Interfaces:**
- Produces:
  ```rust
  /// Downsample interleaved samples to `columns` (min,max) pairs in [-1.0, 1.0],
  /// averaging channels to mono for the overview. `columns == 0` or empty → empty.
  pub fn compute_waveform(samples: &[i16], channels: u16, columns: usize) -> Vec<(f32, f32)>;
  /// Format seconds as `m:ss` (e.g. 75.0 -> "1:15"). Negative clamps to "0:00".
  pub fn format_time(secs: f32) -> String;
  ```

- [ ] **Step 1: Failing tests.**
  ```rust
  #[test]
  fn compute_waveform_buckets_min_max_mono() {
      // 4 samples, 2 columns: bucket0 = [i16::MIN, 0] -> (-1.0, 0.0);
      //                       bucket1 = [0, i16::MAX] -> (0.0, ~1.0)
      let s = [i16::MIN, 0, 0, i16::MAX];
      let w = compute_waveform(&s, 1, 2);
      assert_eq!(w.len(), 2);
      assert!((w[0].0 - -1.0).abs() < 1e-3 && w[0].1.abs() < 1e-3);
      assert!(w[1].0.abs() < 1e-3 && (w[1].1 - 1.0).abs() < 1e-3);
  }
  #[test]
  fn compute_waveform_empty_or_zero_columns_is_empty() {
      assert!(compute_waveform(&[], 1, 4).is_empty());
      assert!(compute_waveform(&[1, 2, 3], 1, 0).is_empty());
  }
  #[test]
  fn format_time_minutes_seconds() {
      assert_eq!(format_time(0.0), "0:00");
      assert_eq!(format_time(75.0), "1:15");
      assert_eq!(format_time(-5.0), "0:00");
      assert_eq!(format_time(605.0), "10:05");
  }
  ```

- [ ] **Step 2: Run — expect FAIL.**

- [ ] **Step 3: Implement.** Mono-average channels, bucket into `columns`, track min/max per bucket, normalise by `i16::MAX as f32`. `format_time`: clamp `<0` to 0, `let m = (secs as u32)/60; let s = (secs as u32)%60; format!("{m}:{s:02}")`. Keep the sample→f32 cast under an explicit `#[allow(clippy::cast_precision_loss)]` with a one-line justification (audio amplitude, exactness irrelevant).

- [ ] **Step 4: Run — expect PASS.**

- [ ] **Step 5: Gates + mutation + commit.** Mutate `audio_view.rs`; 0 missed (the min/max + the `/60`,`%60` + the clamp must be pinned by the divergent asserts above). Commit:
  ```bash
  git commit -am "feat(gui): pure waveform + time-format helpers (phase 7d task 5)"
  ```

---

## Task 6: Pure transport state machine + seek math

**Files:** Modify `crates/paksmith-gui/src/state/audio_view.rs`

**Interfaces:**
- Produces (methods on `AudioState`, all pure — no rodio):
  ```rust
  impl AudioState {
      /// Toggle play/pause. Returns the action the caller must apply to the
      /// AudioOutput seam so the pure state and the sink stay in lockstep.
      pub fn toggle_play(&mut self) -> PlaybackAction;
      pub fn stop(&mut self) -> PlaybackAction;      // -> Stop; position 0
      pub fn set_volume(&mut self, v: f32);          // clamp 0..=1
      /// Map a click at fractional x (0..=1) over the waveform to a seek position.
      pub fn seek_fraction(&mut self, frac: f32) -> PlaybackAction; // -> SeekTo(secs)
      /// Advance the playhead to `secs` (from the tick reading the sink position).
      pub fn set_position(&mut self, secs: f32);
      pub fn duration_secs(&self) -> f32; // decoded samples/channels/rate, else info, else 0
  }
  pub enum PlaybackAction { Play, Pause, Stop, SeekTo(f32), None }
  ```

- [ ] **Step 1: Failing tests** (divergent, cover each transition):
  ```rust
  #[test]
  fn toggle_play_cycles_stopped_playing_paused() {
      let mut a = playable_state(); // decoded Some, transport Stopped
      assert_eq!(a.toggle_play(), PlaybackAction::Play);
      assert!(matches!(a.transport, Transport::Playing));
      assert_eq!(a.toggle_play(), PlaybackAction::Pause);
      assert!(matches!(a.transport, Transport::Paused));
      assert_eq!(a.toggle_play(), PlaybackAction::Play);
      assert!(matches!(a.transport, Transport::Playing));
  }
  #[test]
  fn toggle_play_without_decode_is_noop() {
      let mut a = AudioState::default(); // decoded None
      assert_eq!(a.toggle_play(), PlaybackAction::None);
      assert!(matches!(a.transport, Transport::Stopped));
  }
  #[test]
  fn seek_fraction_maps_to_seconds_and_plays() {
      let mut a = playable_state_with_duration(10.0);
      assert_eq!(a.seek_fraction(0.5), PlaybackAction::SeekTo(5.0));
      assert!((a.position_secs - 5.0).abs() < 1e-3);
      assert_eq!(a.seek_fraction(-1.0), PlaybackAction::SeekTo(0.0)); // clamp low
      assert_eq!(a.seek_fraction(2.0), PlaybackAction::SeekTo(10.0)); // clamp high
  }
  #[test]
  fn set_volume_clamps() {
      let mut a = AudioState::default();
      a.set_volume(1.5); assert!((a.volume - 1.0).abs() < 1e-6);
      a.set_volume(-1.0); assert!(a.volume.abs() < 1e-6);
  }
  #[test]
  fn stop_resets_position() {
      let mut a = playable_state();
      a.set_position(3.0);
      assert_eq!(a.stop(), PlaybackAction::Stop);
      assert!(a.position_secs.abs() < 1e-6);
      assert!(matches!(a.transport, Transport::Stopped));
  }
  ```

- [ ] **Step 2: Run — expect FAIL.**

- [ ] **Step 3: Implement** the methods. `toggle_play`: `None` if `decoded.is_none()`; else Stopped/Paused→Playing (return `Play`), Playing→Paused (return `Pause`). `seek_fraction`: `secs = (frac.clamp(0.0,1.0) * duration).`; set `position_secs`, return `SeekTo(secs)`. `duration_secs`: prefer decoded (`samples.len()/channels/rate`), else `info.duration_secs`, else 0.

- [ ] **Step 4: Run — expect PASS.**

- [ ] **Step 5: Gates + mutation + commit.** Mutate `audio_view.rs`; 0 missed. Commit:
  ```bash
  git commit -am "feat(gui): pure transport + seek state machine (phase 7d task 6)"
  ```

---

## Task 7: Async decode task + detection + `AudioDecoded`

**Files:**
- Create: `crates/paksmith-gui/src/task/audio.rs`; modify `task/mod.rs`
- Modify: `crates/paksmith-gui/src/app.rs`

**Interfaces:**
- Consumes: `paksmith_core::asset::{Package, decode_audio_to_pcm, classify_audio}`, `DecodedAudio`, `AudioState::compute_waveform`.
- Produces: `task::audio::decode(pkg, idx) -> Result<DecodedAudio, String>`; `Message::AudioDecoded { path, result, generation }`.

- [ ] **Step 1: Create `task/audio.rs`** mirroring `task/texture.rs` exactly:
  ```rust
  use std::sync::Arc;
  use paksmith_core::asset::{Package, decode_audio_to_pcm};
  use crate::state::audio_view::DecodedAudio;

  #[allow(clippy::unused_async, reason = "async required by iced Task::perform")]
  pub async fn decode(pkg: Arc<Package>, export_idx: usize) -> Result<DecodedAudio, String> {
      decode_audio_to_pcm(&pkg, export_idx)
          .map(|p| DecodedAudio { samples: p.samples, sample_rate: p.sample_rate, channels: p.channels })
          .map_err(|e| e.to_string())
  }
  ```
  Register `pub mod audio;` in `task/mod.rs`.

- [ ] **Step 2: Add the `Message::AudioDecoded` variant** (mirror `TextureDecoded`, app.rs:245): `AudioDecoded { path: String, result: Result<crate::state::audio_view::DecodedAudio, String>, generation: u64 }`.

- [ ] **Step 3: Detection in `AssetLoaded`** (app.rs:790, after the `classify_texture` block, in the same `if let Some(tab) = ...` borrow): if not a texture, try `classify_audio`; on `Some`, set `tab.audio.info`, `tab.audio.export_idx`, reset transport/decoded/error, and set `decode_task = Task::perform(crate::task::audio::decode(arc.clone(), info.export_idx), move |result| Message::AudioDecoded { path: task_path, result, generation })` — but ONLY when texture didn't already claim the tab and `info.playable` (non-playable sounds get the view + metadata but no decode). Keep the single-classify discipline: `pick_view_after_load` reads `audio_available` (info set), not a re-classify.

- [ ] **Step 4: Add the `AudioDecoded` update arm** (mirror `TextureDecoded`, app.rs:925 — generation fence + path lookup + tab-still-applies guard):
  ```rust
  Message::AudioDecoded { path, result, generation } => {
      if generation != app.archive_generation { return Task::none(); }
      if let Some(tab) = app.tabs.open.iter_mut().find(|t| t.path == path) {
          if tab.audio.info.is_some() { // still an audio tab
              match result {
                  Ok(decoded) => {
                      tab.audio.waveform = crate::state::audio_view::compute_waveform(
                          &decoded.samples, decoded.channels, WAVEFORM_COLUMNS);
                      tab.audio.decoded = Some(decoded);
                      tab.audio.error = None;
                  }
                  Err(msg) => { tab.audio.error = Some(msg); }
              }
          }
      }
      Task::none()
  }
  ```
  Add `const WAVEFORM_COLUMNS: usize = 512;` near the other app.rs consts.

- [ ] **Step 5: Test the update arm** (pure state effect): construct an `App`, an audio tab with `info = Some`, feed `Message::AudioDecoded { Ok(decoded) }` via `update`, assert `tab.audio.decoded.is_some()` and `!tab.audio.waveform.is_empty()`; feed an `Err` and assert `error == Some`. Divergent inputs. `cargo test -p paksmith-gui audio_decoded`.

- [ ] **Step 6: Gates + mutation + commit.** Mutate app.rs (the new arm) + task/audio.rs. Commit:
  ```bash
  git commit -am "feat(gui): async audio decode + detection + AudioDecoded (phase 7d task 7)"
  ```

---

## Task 8: Playback wiring — play/pause/stop/volume + play-gated tick

**Files:** Modify `crates/paksmith-gui/src/app.rs`

**Interfaces:**
- Consumes: the `AudioOutput` seam (Task 1), `AudioState` transport methods + `PlaybackAction` (Task 6).
- Produces: `Message::{AudioPlayPause, AudioStop, AudioVolume(f32), AudioTick}`; the `App.audio: Option<AudioOutput>` holder; a play-gated `iced::time::every` tick.

- [ ] **Step 1: Add the `App.audio` holder** (or `Sender`, per Task 1's outcome). Initialise in `App::default()`/boot with `AudioOutput::new()` (may be `None` → playback disabled, no panic).

- [ ] **Step 2: Add a helper that applies a `PlaybackAction` to the seam.** Extract a small `#[mutants::skip]` fn `apply_playback(app: &mut App, action: PlaybackAction, samples_for_play: Option<...>)` OR inline — the seam calls are glue; the DECISION (which action) came from the pure `AudioState` methods, so only the pure part is mutation-tested. On `Play`, (re)feed the decoded samples to the seam from `position_secs` (slice `samples` from `position_secs * rate * channels`); on `SeekTo`, same slice-and-append; on `Pause`/`Stop`, forward.

- [ ] **Step 3: Add the message arms:**
  ```rust
  Message::AudioPlayPause => { if let Some(tab)=app.tabs.active_tab_mut(){ let act=tab.audio.toggle_play(); /* apply to seam */ } Task::none() }
  Message::AudioStop      => { if let Some(tab)=app.tabs.active_tab_mut(){ let act=tab.audio.stop(); /* seam.stop */ } Task::none() }
  Message::AudioVolume(v) => { if let Some(tab)=app.tabs.active_tab_mut(){ tab.audio.set_volume(v); /* seam.set_volume(v) */ } Task::none() }
  Message::AudioTick      => { if let Some(tab)=app.tabs.active_tab_mut(){ /* read seam.position() (or estimate) -> tab.audio.set_position(secs); if seam.finished() -> tab.audio.stop() */ } Task::none() }
  ```
  Use `AudioOutput::position()` if Task 1 found `get_pos`; otherwise advance `position_secs` by the tick interval while `Playing` (pure `set_position(position_secs + dt)`).

- [ ] **Step 4: Play-gated tick in `subscription()`** (app.rs:1335, mirror the console tick): subscribe `iced::time::every(Duration::from_millis(100)).map(|_| Message::AudioTick)` only when the active tab's `transport` is `Playing`; else `Subscription::none()`. Add a small pure predicate `audio_tick_active(app: &App) -> bool` and unit-test it (Playing → true; Paused/Stopped/no-tab → false), so the subscription glue stays `#[mutants::skip]` but the gate is tested.

- [ ] **Step 5: Tests.** Unit-test `audio_tick_active` (divergent). Unit-test the `AudioVolume`/`AudioStop`/`AudioPlayPause` arms' pure state effects (transport + volume + position), with `App.audio = None` so no device is needed. `cargo test -p paksmith-gui audio`.

- [ ] **Step 6: Manual smoke** (playback): open a real PCM/ADPCM/Vorbis USoundWave, press play → hear it; pause/resume; volume; stop; switch tab mid-play → stops. Note results.

- [ ] **Step 7: Gates + mutation + commit.** Commit:
  ```bash
  git commit -am "feat(gui): audio playback wiring + play-gated tick (phase 7d task 8)"
  ```

---

## Task 9: Waveform canvas widget + click-to-seek

**Files:**
- Create: `crates/paksmith-gui/src/widgets/audio_player.rs` (waveform canvas portion); modify `widgets/mod.rs`
- Modify: `crates/paksmith-gui/src/app.rs` (`AudioSeek(f32)` arm)

**Interfaces:**
- Consumes: `AudioState.waveform`, `position_secs`, `duration_secs()`, `seek_fraction` (Task 6).
- Produces: an iced `canvas::Program` drawing the waveform + playhead and emitting `Message::AudioSeek(frac)` on click/drag; `Message::AudioSeek(f32)` arm.

- [ ] **Step 1: Add the `AudioSeek` arm** (app.rs), mirroring Task 8's action application: `Message::AudioSeek(frac) => { if let Some(tab)=app.tabs.active_tab_mut(){ let act = tab.audio.seek_fraction(frac); /* apply SeekTo to seam: re-append samples from offset */ } Task::none() }`. Test the pure effect (position moves; divergent fracs) with `App.audio = None`.

- [ ] **Step 2: Implement the waveform `canvas`.** In `widgets/audio_player.rs`, a `#[mutants::skip]` `struct Waveform<'a> { peaks: &'a [(f32,f32)], playhead_frac: f32, accent: Color }` implementing `iced::widget::canvas::Program<Message>`: `draw` renders each column's min/max as a vertical line and a playhead line at `playhead_frac * width`; `update` maps a left-press/drag at cursor x to `Message::AudioSeek((x/width).clamp(0,1))`. (Consult iced 0.14 `canvas` docs; the drawing/hit-test is glue — skip-marked — the fraction math is tested in Task 6.)

- [ ] **Step 3: Manual smoke** — waveform renders; clicking/dragging seeks audibly to the right spot.

- [ ] **Step 4: Gates + commit.** (No new pure logic beyond Step 1's tested arm.) Commit:
  ```bash
  git commit -am "feat(gui): waveform canvas + click-to-seek (phase 7d task 9)"
  ```

---

## Task 10: Audio player view + dispatch + switcher + non-playable/error UX

**Files:**
- Modify: `crates/paksmith-gui/src/widgets/audio_player.rs` (the `view` fn)
- Modify: `crates/paksmith-gui/src/panels/content.rs`

**Interfaces:**
- Consumes: everything above.
- Produces: `pub fn view<'a>(state: &AudioState, accent: iced::Color) -> Element<'a, Message>`.

- [ ] **Step 1: Implement `audio_player::view`** (`#[mutants::skip]`, mirror `texture_viewer::view` shape at `widgets/texture_viewer.rs:115`):
  - Metadata header: `info.codec_label`, `channels` (or "—"), `format_time(duration)`, plus sample rate once `decoded` (from `decoded.sample_rate`).
  - If `info.playable`: the `Waveform` canvas (Task 9) + a transport row — play/pause button (label from `transport`), stop button, a `slider(0.0..=1.0, volume, Message::AudioVolume)`, and `format_time(position) / format_time(duration)`.
  - If NOT playable: metadata + `text("Codec {codec_label} can't be decoded in-app — use Export As… to save the raw stream.")`, no transport.
  - If `error.is_some()`: show the error line (non-fatal) beneath the header.
  - If `info.playable` but `decoded.is_none()` and no error: show "Decoding…".

- [ ] **Step 2: Dispatch + switcher in `content.rs`** (mirror texture, content.rs:45 + content.rs:84):
  - In the `match tab.view`, add: `ViewMode::Audio => audio_player::view(&tab.audio, accent),`.
  - Add `let show_audio = audio_available(tab);`, thread it into `view_mode_switcher(tab.view, accent, show_texture, show_audio)`, and inside the switcher: `if show_audio { modes.push((ViewMode::Audio, "Audio")); }`. Update the `view_mode_switcher` signature + its one call site.

- [ ] **Step 3: Manual smoke** — open playable + non-playable + a decode-error sound; verify the view for each (transport vs export hint vs error line); verify the "Audio" switcher button appears only for sounds and switches views.

- [ ] **Step 4: Full gates + commit.** `cargo fmt --all`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`; `cargo test --workspace --all-features`; `RUSTDOCFLAGS="-D warnings" cargo doc -p paksmith-gui --no-deps`; `typos .`; full-PR `cargo mutants --in-diff` 0-missed. Commit:
  ```bash
  git commit -am "feat(gui): audio player view + dispatch + switcher (phase 7d task 10)"
  ```

---

## Final integration + review

- [ ] Run the full CI-mirror gate set (fmt, clippy `--all-targets --all-features -D warnings`, `cargo test --workspace --all-features`, `cargo doc -D warnings`, typos, full-PR `cargo mutants --in-diff` 0-missed, `cargo deny check` + `cargo audit` for the new rodio/cpal tree).
- [ ] Complete the **manual smoke checklist** (the one untestable surface): play/pause/seek/volume/stop across PCM, ADPCM, and Vorbis sounds; non-playable codec shows metadata + export hint; no-audio-device degrades gracefully (no panic); tab switch/close stops playback.
- [ ] Run the adversarial review panel (≥3 + specialists: security for the new deps + file/O paths, deep-impact for the `!Send`/lifetime seam, plus code/architect/simplifier) to convergence before push.

---

## Self-Review (author checklist — completed)

**Spec coverage:** classify_audio (Task 3) · decode_audio_to_pcm (Task 2) · rodio output-only seam + `!Send` placement + Linux CI (Task 1) · ViewMode::Audio + AudioState + lifecycle wiring (Tasks 4,7,8) · one-at-a-time/stop-on-switch (Task 8 seam re-feed + tab-switch smoke) · no autoplay (Task 7 dispatches decode, not play) · waveform+seek (Tasks 5,6,9) · transport/volume (Tasks 6,8) · playable-vs-proprietary UX (Task 10) · error/no-device handling (Tasks 1,10) · testing split pure-vs-skip (throughout) · all six spec hazards (Task 1 steps 2/3/5, Task 2 codec routing, Task 3 metadata Options). No spec requirement is unassigned.

**Placeholder scan:** the only deliberately-deferred specifics are rodio's exact 0.22 constructor names + `get_pos` (Task 1 Step 2 pins them empirically — this is the spike's job, not a placeholder) and the iced-`canvas` drawing calls (Task 9, glue). Every core/pure step carries complete code.

**Type consistency:** `AudioInfo`/`AudioPcm` (core) → `DecodedAudio`/`AudioState`/`Transport`/`PlaybackAction` (GUI) used consistently; `classify_audio`/`decode_audio_to_pcm`/`compute_waveform`/`format_time`/`toggle_play`/`seek_fraction`/`audio_available`/`audio_tick_active` names stable across tasks; `Message` variants match the Global Constraints list.
