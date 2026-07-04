//! Async task: decode a single audio clip from a parsed `Package`.

use std::sync::Arc;

use paksmith_core::asset::{Package, decode_audio_to_pcm};

use crate::state::audio_view::DecodedAudio;

/// Decode the audio export at `export_idx` within `pkg`.
///
/// The CPU decode work runs off the UI thread via `iced::Task::perform`.
/// The result is mapped into the GUI's [`DecodedAudio`] type or a stringified
/// error so the caller can store it directly on
/// [`crate::state::audio_view::AudioState`].
// `async` is required by `iced::Task::perform` even though the body is sync.
#[allow(clippy::unused_async, reason = "async required by iced Task::perform")]
pub async fn decode(pkg: Arc<Package>, export_idx: usize) -> Result<DecodedAudio, String> {
    decode_audio_to_pcm(&pkg, export_idx)
        .map(|p| DecodedAudio {
            samples: p.samples,
            sample_rate: p.sample_rate,
            channels: p.channels,
        })
        .map_err(|e| e.to_string())
}
