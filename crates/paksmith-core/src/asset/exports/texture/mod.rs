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
//! - **3e-2** ([`texture2d::read_from`]): the **full**
//!   `FTexturePlatformData` header — the version-gated stripped-data
//!   prefix, `SizeX`, `SizeY`, `PackedData`, `PixelFormat` (3e-2a), then
//!   the conditional `OptData` / `CPUCopy`, `FirstMipToSerialize`, and
//!   the mip-count prefix (3e-2b) — into [`crate::asset::Texture2DData`].
//! - **3e-3+**: the per-mip `FTexture2DMipMap` records (with their
//!   `FByteBulkData`), the per-pixel-format decoders, and `PngHandler`.

pub(crate) mod texture2d;
