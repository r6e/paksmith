//! Audio-view state: transport, decoded PCM, and waveform overview.
//!
//! Pure structs; no iced imports. Mirrors
//! [`super::texture_view::TextureState`]'s shape so the audio and texture
//! panels follow the same single-responsibility pattern: state lives here,
//! widget rendering lives in `widgets/audio_player` (a later Phase 7d task).

// Most fields and two Transport variants are defined now but consumed by the
// audio-player widget and decode task landed in later Phase 7d tasks. Suppress
// dead_code for the whole module until those tasks fill in the constructors.
#![allow(dead_code)]

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
            volume: 1.0,
            error: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
