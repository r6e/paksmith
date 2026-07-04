//! The one place that touches `rodio`. Real-time audio output cannot be
//! unit-tested, so this whole module is `#[mutants::skip]` and verified by the
//! manual smoke checklist in the Phase 7d plan (Task 1). All decision logic
//! (decode, waveform, transport, seek) lives in pure modules elsewhere.
//!
//! # rodio 0.22 API
//!
//! rodio 0.22.2 renamed the playback surface away from the older
//! `OutputStream` / `Sink` types most tutorials show. The seam uses:
//!
//! - `rodio::DeviceSinkBuilder::open_default_sink()` — opens the default OS
//!   output device, returning a `rodio::MixerDeviceSink`. This handle owns the
//!   underlying `cpal::Stream`; dropping it stops **all** audio, so it is kept
//!   alive for the whole [`AudioOutput`] lifetime as the `_device` field.
//! - `rodio::Player::connect_new(mixer)` — creates the per-stream queue and
//!   transport (the 0.22 replacement for `Sink`), connected to the device's
//!   `rodio::mixer::Mixer` (obtained via `MixerDeviceSink::mixer()`). Every
//!   `Player` control (`append` / `play` / `pause` / `stop` / `set_volume` /
//!   `get_pos` / `empty`) takes `&self`.
//! - `rodio::buffer::SamplesBuffer::new(channels, sample_rate, data)` — wraps
//!   raw PCM as a playable source. In 0.22 its sample type is `f32`
//!   (`rodio::Sample`) and `channels` / `sample_rate` are
//!   `NonZero<u16>` / `NonZero<u32>`. The caller's 16-bit PCM is normalized to
//!   `f32` here; zero channel/rate inputs are rejected (logged, not played).
//!
//! `Player::get_pos()` **exists** in rodio 0.22 and returns a
//! [`Duration`], so [`AudioOutput::position`] reads the playhead directly
//! rather than estimating it from a samples-consumed counter (relevant to the
//! transport work in Task 8).
//!
//! # `!Send` placement (brief Step 3 outcome)
//!
//! `MixerDeviceSink` wraps a `cpal::Stream`, which is `!Send`, so `AudioOutput`
//! is `!Send`. Task 1 resolved the placement empirically: iced 0.14 keeps
//! application state on the main thread and imposes `Send` only on the async
//! `Task` futures its executor runs — not on the state struct — so
//! `AudioOutput` lives directly as an `Option<AudioOutput>` field on the `App`
//! struct. No dedicated audio thread or command channel is required. Later
//! tasks depend only on the public method surface below, not on this internal
//! choice.

use std::num::NonZero;
use std::time::Duration;

use rodio::buffer::SamplesBuffer;
use rodio::{DeviceSinkBuilder, MixerDeviceSink, Player};

/// Owns the rodio output device and its single playback queue.
///
/// Constructed lazily via [`AudioOutput::new`]; a missing or unopenable audio
/// device yields `None` rather than panicking, so the GUI degrades to a silent
/// (no-playback) state instead of crashing.
pub struct AudioOutput {
    // Field order matters: `player` is dropped before `_device`. `_device` MUST
    // outlive the player and stay alive for the whole app — dropping it stops
    // all audio.
    player: Player,
    _device: MixerDeviceSink,
}

#[mutants::skip]
impl AudioOutput {
    /// Opens the default audio device, or returns `None` if no device is
    /// available or initialization fails (never panics).
    pub fn new() -> Option<Self> {
        let device = DeviceSinkBuilder::open_default_sink().ok()?;
        let player = Player::connect_new(device.mixer());
        // Start paused: nothing plays until `play_samples` queues a source.
        player.pause();
        Some(Self {
            player,
            _device: device,
        })
    }

    /// Replaces whatever is currently playing with `samples` and starts
    /// playback.
    ///
    /// `samples` is interleaved 16-bit PCM; it is normalized to rodio's `f32`
    /// sample format internally. A zero `channels` or `sample_rate` is invalid:
    /// the request is logged and ignored rather than played.
    pub fn play_samples(&mut self, samples: Vec<i16>, channels: u16, sample_rate: u32) {
        let (Some(channels), Some(sample_rate)) =
            (NonZero::new(channels), NonZero::new(sample_rate))
        else {
            tracing::warn!(
                channels,
                sample_rate,
                "ignoring audio play request: zero channel count or sample rate"
            );
            return;
        };
        // rodio's `Sample` is `f32`. `From<i16> for f32` is lossless (i16 fits
        // in f32's 24-bit mantissa), so this normalization uses no `as` cast and
        // trips none of the workspace cast lints. Dividing by 2^15 maps the
        // i16 range onto roughly [-1.0, 1.0).
        let samples: Vec<f32> = samples
            .into_iter()
            .map(|s| f32::from(s) / 32_768.0)
            .collect();
        // Empty the prior queue so the new source replaces (not follows) it.
        self.player.stop();
        self.player
            .append(SamplesBuffer::new(channels, sample_rate, samples));
        self.player.play();
    }

    /// Pauses playback (resumable via [`AudioOutput::resume`]).
    pub fn pause(&mut self) {
        self.player.pause();
    }

    /// Resumes playback after a [`AudioOutput::pause`].
    ///
    /// Currently unused: the Phase 7d transport re-feeds a fresh `SamplesBuffer`
    /// from the paused position on resume (via [`AudioOutput::play_samples`])
    /// rather than un-pausing in place, so this method is retained only for a
    /// possible future non-re-feed resume path. `#[mutants::skip]` (module-wide)
    /// already covers it.
    pub fn resume(&mut self) {
        self.player.play();
    }

    /// Stops playback and empties the queue.
    pub fn stop(&mut self) {
        self.player.stop();
    }

    /// Sets the output volume. `1.0` is unattenuated; `0.0` is silent.
    pub fn set_volume(&mut self, volume: f32) {
        self.player.set_volume(volume);
    }

    /// The current playback position, as reported by the backend.
    ///
    /// Always `Some` in rodio 0.22 (the backend exposes `get_pos`); the
    /// `Option` is retained so the seam can degrade gracefully if a future
    /// backend lacks a playhead.
    // `unnecessary_wraps`: the `Option` return is the fixed seam contract
    // ("position, if the backend exposes it") that later Phase 7d tasks code
    // against — clippy can't see that cross-task API stability requirement, and
    // rodio 0.22 happening to always expose `get_pos` doesn't license narrowing
    // the surface.
    #[allow(clippy::unnecessary_wraps)]
    pub fn position(&self) -> Option<Duration> {
        Some(self.player.get_pos())
    }

    /// Whether the queued samples have finished playing (queue is empty).
    pub fn finished(&self) -> bool {
        self.player.empty()
    }
}
