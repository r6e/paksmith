//! `UTexture2D` (and Phase-3e sibling) typed export readers.
//!
//! Wire-format reference: `docs/formats/texture/texture2d.md`. A
//! `UTexture2D` export body has two segments — a standard
//! `FPropertyTag` tagged-property stream, then a trailing
//! `FTexturePlatformData` blob carrying the cooked mip chain.
//!
//! Phase 3e lands incrementally:
//! - **3e-1**: routes the `Texture2D` class through dispatch and
//!   decodes **segment 1** (tagged properties).
//! - **3e-2a** ([`texture2d::read_from`]): the `FTexturePlatformData`
//!   header start — the version-gated stripped-data prefix, `SizeX`,
//!   `SizeY`, `PackedData`, `PixelFormat` — into
//!   [`crate::asset::Texture2DData`].
//! - **3e-2b+**: the rest of the header (`OptData` / `CPUCopy` /
//!   `FirstMipToSerialize` / mip-count), the per-mip records, the
//!   per-pixel-format decoders, and `PngHandler`.

pub(crate) mod texture2d;
