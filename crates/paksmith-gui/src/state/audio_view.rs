//! Audio-view state: transport, decoded PCM, and waveform overview.
//!
//! Pure structs; no iced imports. Mirrors
//! [`super::texture_view::TextureState`]'s shape so the audio and texture
//! panels follow the same single-responsibility pattern: state lives here,
//! widget rendering lives in `widgets/audio_player` (a later Phase 7d task).

use paksmith_core::asset::AudioInfo;

/// A decoded audio clip as interleaved 16-bit PCM samples.
///
/// Produced when an asset is decoded from its source codec (OGG Vorbis, PCM,
/// ADPCM, …) via `decode_audio_to_pcm`. Held in [`AudioState::decoded`].
/// Constructed by the audio decode task (later Phase 7d task).
#[derive(Debug, Clone)]
pub struct DecodedAudio {
    /// Frame-interleaved signed 16-bit samples (channel 0, channel 1, …).
    pub samples: Vec<i16>,
    /// Sample rate in Hz (e.g. 44 100).
    pub sample_rate: u32,
    /// Number of channels (1 = mono, 2 = stereo, …).
    pub channels: u16,
}

/// Playback transport state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Transport {
    /// Playback is idle; no audio output thread is active.
    #[default]
    Stopped,
    /// Audio is actively playing; the playhead is advancing.
    /// Constructed by the audio player widget (later Phase 7d task).
    Playing,
    /// Playback is suspended; the playhead holds its position.
    /// Constructed by the audio player widget (later Phase 7d task).
    Paused,
}

/// The action to apply to the audio-output sink that corresponds to a pure
/// state transition. Returned by mutating [`AudioState`] methods so the caller
/// can keep the state machine and the rodio sink in lockstep without coupling
/// them directly.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PlaybackAction {
    /// Start or resume playback from the current position.
    Play,
    /// Pause playback; hold the current position.
    Pause,
    /// Stop playback and reset the position to 0.
    Stop,
    /// Seek the sink to the given absolute position in seconds.
    SeekTo(f32),
    /// No sink action required (e.g. toggle called with no decoded audio).
    None,
}

/// All view state for the audio inspector panel.
///
/// Mirrors [`super::texture_view::TextureState`]'s shape: pure Rust, no iced
/// imports, so it can be unit-tested without a renderer. The audio player
/// widget (`widgets/audio_player`, later Phase 7d task) reads this state each
/// frame.
#[derive(Debug, Clone)]
pub struct AudioState {
    /// Export index within the `Package` that holds the `USoundWave` export.
    ///
    /// Set by the `AssetLoaded` handler via `classify_audio`; used when
    /// dispatching a decode task. Defaults to `0` (harmless sentinel when no
    /// audio is loaded).
    pub export_idx: usize,
    /// Lightweight classification summary, populated by the `AssetLoaded`
    /// handler via [`paksmith_core::asset::classify_audio`]. `None` until a
    /// sound-wave asset is loaded.
    ///
    /// Also serves as the per-frame "decodable audio loaded" signal for
    /// [`audio_available`](crate::state::tabs::audio_available): non-`None`
    /// iff the tab's current content is a sound-wave asset.
    pub info: Option<AudioInfo>,
    /// Decoded PCM data, populated after a successful decode task. `None` until
    /// the user triggers decode (or auto-decode fires on load).
    /// Constructed by the audio decode task (later Phase 7d task).
    pub decoded: Option<DecodedAudio>,
    /// Waveform overview: one `(min, max)` amplitude pair per display column
    /// bucket, both in `[-1.0, 1.0]`. Empty until the asset is decoded.
    pub waveform: Vec<(f32, f32)>,
    /// Current playback transport state.
    pub transport: Transport,
    /// Playhead position in seconds.
    pub position_secs: f32,
    /// Absolute track position (seconds) at which the current sink buffer began
    /// playing — i.e. the offset the samples were re-fed from on the last
    /// `Play`/`SeekTo`.
    ///
    /// Needed because rodio's `Player::get_pos` is *buffer-relative*: it resets
    /// to zero every time the audio seam re-feeds a fresh `SamplesBuffer`
    /// (stop + append) and reports only elapsed time within the current source.
    /// The tick reconstructs the absolute playhead as
    /// `playback_offset_secs + get_pos()`. Defaults to `0.0`.
    pub playback_offset_secs: f32,
    /// Playback volume in `0.0..=1.0`.
    pub volume: f32,
    /// Error message from the most recent decode or playback attempt, if any.
    pub error: Option<String>,
}

impl Default for AudioState {
    fn default() -> Self {
        Self {
            export_idx: 0,
            info: None,
            decoded: None,
            waveform: Vec::new(),
            transport: Transport::Stopped,
            position_secs: 0.0,
            playback_offset_secs: 0.0,
            volume: 1.0,
            error: None,
        }
    }
}

impl AudioState {
    /// Duration of the loaded audio in seconds.
    ///
    /// Priority: decoded PCM data (whole frame count ÷ sample-rate, in floating
    /// point) → [`AudioInfo`] metadata → `0.0`.
    ///
    /// The decoded path divides in floating point, so the result keeps
    /// sub-second precision — `seek_fraction` and the playhead readout depend on
    /// it (a 1.5 s clip reports `1.5`, not `1.0`).
    pub fn duration_secs(&self) -> f32 {
        if let Some(decoded) = &self.decoded {
            let ch = usize::from(decoded.channels.max(1));
            let frames = decoded.samples.len() / ch; // whole interleaved frames
            let rate = decoded.sample_rate.max(1);
            #[allow(clippy::cast_precision_loss)]
            // Audio frame counts + rates for realistic durations fit f32 precision
            // (2^24 frames at 44 100 Hz ≈ 6 h). Float division keeps sub-second
            // accuracy, which `seek_fraction` and the playhead readout depend on.
            return frames as f32 / rate as f32;
        }
        if let Some(d) = self.info.as_ref().and_then(|i| i.duration_secs) {
            return d;
        }
        0.0
    }

    /// Toggle play/pause. Returns the [`PlaybackAction`] the caller must apply
    /// to the audio-output seam so the pure state and the sink stay in lockstep.
    ///
    /// Returns [`PlaybackAction::None`] when no audio has been decoded yet.
    pub fn toggle_play(&mut self) -> PlaybackAction {
        if self.decoded.is_none() {
            return PlaybackAction::None;
        }
        match self.transport {
            Transport::Playing => {
                self.transport = Transport::Paused;
                PlaybackAction::Pause
            }
            Transport::Stopped | Transport::Paused => {
                self.transport = Transport::Playing;
                PlaybackAction::Play
            }
        }
    }

    /// Stop playback, reset the playhead to zero, and return
    /// [`PlaybackAction::Stop`].
    pub fn stop(&mut self) -> PlaybackAction {
        self.transport = Transport::Stopped;
        self.position_secs = 0.0;
        PlaybackAction::Stop
    }

    /// Set the playback volume, clamped to `0.0..=1.0`.
    pub fn set_volume(&mut self, v: f32) {
        self.volume = v.clamp(0.0, 1.0);
    }

    /// Map a fractional scrub position (`0.0`–`1.0`) over the waveform to an
    /// absolute seek position in seconds and return [`PlaybackAction::SeekTo`].
    ///
    /// `frac` is clamped to `0.0..=1.0` before multiplication so out-of-range
    /// values (e.g. `-1.0` or `2.0`) produce valid seek positions.
    pub fn seek_fraction(&mut self, frac: f32) -> PlaybackAction {
        let secs = frac.clamp(0.0, 1.0) * self.duration_secs();
        self.position_secs = secs;
        PlaybackAction::SeekTo(secs)
    }

    /// Advance the playhead from the current buffer's start offset by
    /// `elapsed_secs` (rodio's buffer-relative `get_pos`), yielding the absolute
    /// track position `playback_offset_secs + elapsed_secs`.
    pub fn advance_playhead(&mut self, elapsed_secs: f32) {
        self.position_secs = self.playback_offset_secs + elapsed_secs;
    }
}

/// Downsample interleaved `samples` to `columns` `(min, max)` pairs in `[-1.0, 1.0]`,
/// averaging channels to mono for the overview. Returns empty if `columns == 0` or
/// `samples` is empty. `channels == 0` is treated as `1` (defensive).
pub fn compute_waveform(samples: &[i16], channels: u16, columns: usize) -> Vec<(f32, f32)> {
    if columns == 0 || samples.is_empty() {
        return Vec::new();
    }
    let ch = usize::from(channels.max(1));
    let norm = f32::from(i16::MAX);
    let ch_f32 = f32::from(channels.max(1));

    // Convert interleaved samples to mono frames by averaging all channels.
    let frames: Vec<f32> = samples
        .chunks(ch)
        .map(|frame| {
            let sum: f32 = frame.iter().map(|&s| f32::from(s)).sum();
            sum / ch_f32
        })
        .collect();

    let frame_count = frames.len();
    if frame_count == 0 {
        return Vec::new();
    }

    // Clamp effective columns to available frames so no bucket is left empty.
    let effective_cols = columns.min(frame_count);
    let mut result = vec![(f32::MAX, f32::MIN); effective_cols];

    for (frame_idx, &sample) in frames.iter().enumerate() {
        // Integer arithmetic distributes frames evenly across columns. Because
        // `effective_cols <= frame_count` and `frame_idx <= frame_count - 1`, the
        // quotient `(frame_idx * effective_cols) / frame_count` is always
        // `<= effective_cols - 1`, so the index is in range without a clamp.
        let col = (frame_idx * effective_cols) / frame_count;
        let (min, max) = &mut result[col];
        *min = (*min).min(sample);
        *max = (*max).max(sample);
    }

    result
        .into_iter()
        .map(|(min, max)| (min / norm, max / norm))
        .collect()
}

/// Format seconds as `m:ss` (e.g. `75.0` → `"1:15"`). Negative values clamp to `"0:00"`.
#[allow(clippy::cast_possible_truncation)] // intentional floor; audio durations fit u32
#[allow(clippy::cast_sign_loss)] // sign-loss impossible: value is clamped to ≥ 0.0 above
pub fn format_time(secs: f32) -> String {
    let secs = secs.max(0.0);
    let total = secs as u32;
    let m = total / 60;
    let s = total % 60;
    format!("{m}:{s:02}")
}

/// The interleaved-sample index at which to resume playback for a clip of
/// `len` interleaved samples (`channels`-interleaved, `sample_rate` Hz), given
/// an absolute playhead `position_secs`.
///
/// Converts seconds → interleaved index, clamps to `len` (a position past the
/// end resumes at the end = silence), then frame-aligns DOWN to a channel
/// boundary so stereo L/R never swap. `position_secs` is non-negative in
/// production (reset to 0 by [`AudioState::stop`]; only
/// [`AudioState::advance_playhead`]/[`AudioState::seek_fraction`] write it).
/// `channels` is guarded with `.max(1)` so a 0-channel clip can't
/// divide-by-zero.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    reason = "interleaved index for realistic audio lengths fits usize; negative/NaN position saturates to 0"
)]
pub fn resume_sample_offset(
    position_secs: f32,
    sample_rate: u32,
    channels: u16,
    len: usize,
) -> usize {
    let mut start = (position_secs * sample_rate as f32 * f32::from(channels)) as usize;
    start = start.min(len);
    start -= start % usize::from(channels).max(1);
    start
}

#[cfg(test)]
mod tests {
    use super::*;
    use paksmith_core::asset::AudioInfo;

    // --- test helpers ---

    fn playable_state() -> AudioState {
        AudioState {
            // 88 200 interleaved samples, 2 ch, 44 100 Hz → 1.0 s.
            // ch=2 is load-bearing: the `/ch → *ch` mutant in `duration_secs`
            // yields 88_200 * 2 / 44_100 = 4 instead of 1, failing the pin test.
            decoded: Some(DecodedAudio {
                samples: vec![0i16; 88_200],
                sample_rate: 44_100,
                channels: 2,
            }),
            ..AudioState::default()
        }
    }

    fn playable_state_with_duration(duration_secs: f32) -> AudioState {
        // 100 Hz, 1 channel: each sample = 1/100 s.
        // Frame count = duration_secs * 100 (e.g. 10.0 → 1 000 frames), so
        // `duration_secs()` = frames / rate = `duration_secs` exactly (float).
        let sample_rate: u32 = 100;
        let channels: u16 = 1;
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        // In tests, `duration_secs` is always a small positive integer (≤ 600),
        // so truncation and sign-loss are impossible.
        let num_samples = (duration_secs * 100.0_f32) as usize;
        AudioState {
            decoded: Some(DecodedAudio {
                samples: vec![0i16; num_samples],
                sample_rate,
                channels,
            }),
            ..AudioState::default()
        }
    }

    // --- transport state machine ---

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
    fn stop_resets_position() {
        let mut a = playable_state();
        // Drive transport OUT of Stopped first so `stop()` genuinely RESETS it
        // (default state is already Stopped, which would make the reset a no-op
        // and leave the transport assignment unverified).
        assert_eq!(a.toggle_play(), PlaybackAction::Play);
        assert!(matches!(a.transport, Transport::Playing));
        a.position_secs = 3.0;
        assert_eq!(a.stop(), PlaybackAction::Stop);
        assert!(a.position_secs.abs() < 1e-6);
        assert!(matches!(a.transport, Transport::Stopped));
    }

    #[test]
    fn advance_playhead_adds_offset_to_elapsed() {
        // Absolute playhead = playback_offset_secs + elapsed. Asymmetric values
        // (offset 5.0, elapsed 2.0 → 7.0) kill a `+ -> -` (3.0) or `+ -> *` (10.0)
        // mutant.
        let mut a = AudioState {
            playback_offset_secs: 5.0,
            ..AudioState::default()
        };
        a.advance_playhead(2.0);
        assert!(
            (a.position_secs - 7.0).abs() < 1e-6,
            "got {}",
            a.position_secs
        );
        // A second case with offset 0 pins that the offset term matters (a
        // `+ -> *` mutant gives 0.0 here, diverging from 3.5).
        let mut b = AudioState::default();
        b.advance_playhead(3.5);
        assert!(
            (b.position_secs - 3.5).abs() < 1e-6,
            "got {}",
            b.position_secs
        );
    }

    // --- seek ---

    #[test]
    #[allow(clippy::float_cmp)]
    fn seek_fraction_maps_to_seconds_and_clamps() {
        let mut a = playable_state_with_duration(10.0);
        // 0.5 × 10 = 5.0 (exact in f32)
        assert_eq!(a.seek_fraction(0.5), PlaybackAction::SeekTo(5.0));
        assert!((a.position_secs - 5.0).abs() < 1e-3);
        // clamp low: −1.0 → 0.0
        assert_eq!(a.seek_fraction(-1.0), PlaybackAction::SeekTo(0.0));
        // clamp high: 2.0 → 1.0 × 10 = 10.0
        assert_eq!(a.seek_fraction(2.0), PlaybackAction::SeekTo(10.0));
    }

    // --- volume ---

    #[test]
    fn set_volume_stores_and_clamps() {
        let mut a = AudioState::default();
        // Divergent in-range value: differs from the 1.0 default, so a mutant
        // that drops the assignment (leaving volume at 1.0) fails here.
        a.set_volume(0.5);
        assert!(
            (a.volume - 0.5).abs() < 1e-6,
            "in-range volume must be stored"
        );
        // Clamp high: 1.5 → 1.0.
        a.set_volume(1.5);
        assert!(
            (a.volume - 1.0).abs() < 1e-6,
            "volume 1.5 must clamp to 1.0"
        );
        // Clamp low: −0.5 → 0.0.
        a.set_volume(-0.5);
        assert!(a.volume.abs() < 1e-6, "volume −0.5 must clamp to 0.0");
    }

    // --- duration ---

    #[test]
    #[allow(clippy::float_cmp)]
    fn duration_secs_from_decoded_channels_pin() {
        // 88 200 interleaved samples, 2 ch, 44 100 Hz:
        // frames = 88 200 / 2 = 44 100; secs = 44_100.0 / 44_100.0 = 1.0 (float).
        // A `/ ch → * ch` mutant gives 88 200 * 2 / 44 100 = 4 (not 1); fails.
        // A `/ rate → * rate` mutant gives 44 100 * 44 100 overflows or diverges.
        let a = playable_state();
        assert_eq!(a.duration_secs(), 1.0_f32);
    }

    #[test]
    fn duration_secs_is_fractional_not_truncated() {
        // 132 300 samples, 2 ch, 44 100 Hz → 66 150 frames / 44 100 = 1.5 s.
        // Integer division (66 150 / 44 100 = 1) would report 1.0; float keeps 1.5
        // so `seek_fraction` and the playhead stay sub-second accurate.
        let a = AudioState {
            decoded: Some(DecodedAudio {
                samples: vec![0i16; 132_300],
                sample_rate: 44_100,
                channels: 2,
            }),
            ..AudioState::default()
        };
        assert!(
            (a.duration_secs() - 1.5).abs() < 1e-6,
            "got {}",
            a.duration_secs()
        );
    }

    #[test]
    fn duration_secs_falls_back_to_info() {
        // decoded None → must consult info.duration_secs (7.0 ≠ 0.0 or 1.0).
        let a = AudioState {
            info: Some(AudioInfo {
                export_idx: 0,
                codec_label: "PCM".to_owned(),
                channels: None,
                duration_secs: Some(7.0),
                playable: true,
            }),
            ..AudioState::default()
        };
        assert!((a.duration_secs() - 7.0).abs() < 1e-6);
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn duration_secs_returns_zero_when_neither() {
        // Both decoded and info are None.
        let a = AudioState::default();
        assert_eq!(a.duration_secs(), 0.0_f32);
    }

    #[test]
    fn compute_waveform_buckets_min_max_mono() {
        // 4 samples, 1 channel, 2 columns:
        // bucket 0 = [i16::MIN, 0] -> (-1.0, 0.0)
        // bucket 1 = [0, i16::MAX] -> (0.0, ~1.0)
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
    fn compute_waveform_averages_channels_to_mono() {
        // Stereo: one interleaved frame [L=2000, R=6000] averages to 4000, so
        // the single bucket is 4000/32767 ≈ 0.1221 for both min and max. Divergent
        // L/R values pin the `sum / channels` averaging (a `*` mutant would yield
        // 16000/32767 ≈ 0.4883).
        let w = compute_waveform(&[2000, 6000], 2, 1);
        assert_eq!(w.len(), 1);
        assert!((w[0].0 - 0.1221).abs() < 1e-3, "min {}", w[0].0);
        assert!((w[0].1 - 0.1221).abs() < 1e-3, "max {}", w[0].1);
    }

    #[test]
    fn compute_waveform_distributes_frames_into_asymmetric_buckets() {
        // 6 mono frames into 3 columns: col0={3000,9000}, col1={-6000,12000},
        // col2={-15000,6000}. Distinct mid-range values per bucket pin the bucket
        // index arithmetic (`* -> +` empties col2; `/ -> %` indexes out of range),
        // the min/max tracking (a swap flips each pair), and the normalization
        // (`/ -> %` on a mid-range value diverges hugely from the ÷32767 result).
        let s = [3000, 9000, -6000, 12000, -15000, 6000];
        let w = compute_waveform(&s, 1, 3);
        assert_eq!(w.len(), 3);
        let close = |a: f32, b: f32| (a - b).abs() < 1e-3;
        assert!(
            close(w[0].0, 0.0916) && close(w[0].1, 0.2747),
            "col0 {:?}",
            w[0]
        );
        assert!(
            close(w[1].0, -0.1831) && close(w[1].1, 0.3662),
            "col1 {:?}",
            w[1]
        );
        assert!(
            close(w[2].0, -0.4578) && close(w[2].1, 0.1831),
            "col2 {:?}",
            w[2]
        );
    }

    #[test]
    fn format_time_minutes_seconds() {
        assert_eq!(format_time(0.0), "0:00");
        assert_eq!(format_time(75.0), "1:15");
        assert_eq!(format_time(-5.0), "0:00");
        assert_eq!(format_time(605.0), "10:05");
    }

    // --- resume_sample_offset (divergent, mutation-killing) ---

    #[test]
    fn resume_sample_offset_converts_seconds_to_interleaved_index() {
        // Mono: 2.0 s × 100 Hz × 1 ch = 200. Non-unit position AND rate so a mutant
        // dropping either factor changes the result.
        assert_eq!(resume_sample_offset(2.0, 100, 1, 1000), 200);
    }

    #[test]
    fn resume_sample_offset_scales_by_channel_count() {
        // Same position/rate as the mono case, stereo → 2.0 × 100 × 2 = 400.
        // Dropping `f32::from(channels)` would yield 200 (the mono result).
        assert_eq!(resume_sample_offset(2.0, 100, 2, 1000), 400);
    }

    #[test]
    fn resume_sample_offset_frame_aligns_down_for_stereo() {
        // 1.5 s × 5 Hz × 3 ch = 22.5 → 22 (exact in f32); 22 % 3 = 1, so the
        // frame-align subtracts 1 → 21. Deleting `- start % channels` leaves 22;
        // deleting `.max(1)` doesn't matter here but the odd-boundary landing pins
        // the modulo. `len` is large so the clamp is a no-op.
        assert_eq!(resume_sample_offset(1.5, 5, 3, 100_000), 21);
    }

    #[test]
    fn resume_sample_offset_clamps_position_past_end() {
        // Position far beyond the clip: 9999 × 100 × 2 ≫ len. Clamps to 1000 (already
        // even, so frame-align leaves it). Deleting `.min(len)` would slice OOB.
        assert_eq!(resume_sample_offset(9999.0, 100, 2, 1000), 1000);
    }

    #[test]
    fn resume_sample_offset_zero_channels_does_not_panic() {
        // 0-channel clip: raw index = 1.0 × 100 × 0 = 0; the `.max(1)` guards the
        // `% 0` divide-by-zero. Returns 0 without panicking.
        assert_eq!(resume_sample_offset(1.0, 100, 0, 10), 0);
    }

    #[test]
    fn audio_state_default_transport_is_stopped() {
        assert_eq!(AudioState::default().transport, Transport::Stopped);
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn audio_state_default_volume_is_one() {
        assert_eq!(AudioState::default().volume, 1.0);
    }

    #[test]
    fn audio_state_default_has_no_info() {
        assert!(AudioState::default().info.is_none());
    }

    #[test]
    fn audio_state_default_has_no_decoded() {
        assert!(AudioState::default().decoded.is_none());
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn audio_state_default_position_is_zero() {
        assert_eq!(AudioState::default().position_secs, 0.0);
    }

    #[test]
    fn audio_state_default_waveform_is_empty() {
        assert!(AudioState::default().waveform.is_empty());
    }
}
