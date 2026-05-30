//! `UTexture2D` (and Phase-3e sibling) typed export readers.
//!
//! Wire-format reference: `docs/formats/texture/texture2d.md`. A
//! `UTexture2D` export body has two segments — a standard
//! `FPropertyTag` tagged-property stream, then a trailing
//! `FTexturePlatformData` blob carrying the cooked mip chain.
//!
//! Phase 3e lands incrementally:
//! - **3e-1** ([`texture2d::read_from`]): routes the `Texture2D`
//!   class through dispatch and decodes **segment 1** (tagged
//!   properties) into [`crate::asset::Texture2DData`].
//! - **3e-2+**: the `FTexturePlatformData` header, the per-mip
//!   records, the per-pixel-format decoders, and `PngHandler`.

pub(crate) mod texture2d;
