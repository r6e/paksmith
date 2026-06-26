//! Async task: decode a single texture mip level from a parsed `Package`.

use std::sync::Arc;

use paksmith_core::asset::{Package, decode_texture_mip};

use crate::state::texture_view::DecodedMip;

/// Decode mip level `mip` for the texture export at `export_idx` within `pkg`.
///
/// The CPU decode work runs off the UI thread via `iced::Task::perform`.
/// The result is mapped into the GUI's [`DecodedMip`] type or a stringified
/// error so the caller can store it directly on [`TextureState`].
// `async` is required by `iced::Task::perform` even though the body is sync.
#[allow(clippy::unused_async, reason = "async required by iced Task::perform")]
pub async fn decode(
    pkg: Arc<Package>,
    export_idx: usize,
    mip: usize,
) -> Result<DecodedMip, String> {
    decode_texture_mip(&pkg, export_idx, mip)
        .map(|decoded| DecodedMip {
            width: decoded.width,
            height: decoded.height,
            rgba: decoded.rgba,
        })
        .map_err(|e| e.to_string())
}
