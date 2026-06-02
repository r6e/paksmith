//! `UTexture2D` (and Phase-3e sibling) typed export readers.
//!
//! Wire-format reference: `docs/formats/texture/texture2d.md`. A
//! `UTexture2D` export body is a standard `FPropertyTag` tagged-property
//! stream, then the `UTexture` / `UTexture2D` binary entry (strip flags +
//! owner cooked/serialize flags), then the `FTexturePlatformData` blob
//! carrying the cooked mip chain.
//!
//! Phase 3e lands incrementally:
//! - **3e-1**: routes the `Texture2D` class through dispatch and
//!   decodes **segment 1** (tagged properties).
//! - **3e-2** ([`texture2d::read_from`]): the **full**
//!   `FTexturePlatformData` header — the version-gated stripped-data
//!   prefix, `SizeX`, `SizeY`, `PackedData`, `PixelFormat` (3e-2a), then
//!   the conditional `OptData` / `CPUCopy`, `FirstMipToSerialize`, and
//!   the mip-count prefix (3e-2b) — into [`crate::asset::Texture2DData`].
//! - **3e-3** ([`texture2d::read_from`], cont.): the **segment-2 entry**
//!   (`UTexture` / `UTexture2D` `FStripDataFlags` + owner `bCooked` +
//!   `bSerializeMipData`) that precedes the platform data, then the
//!   per-mip `FTexture2DMipMap` records — `bCooked` (UE4) + each mip's
//!   `FByteBulkData` payload record (iff `bSerializeMipData`) +
//!   `SizeX`/`SizeY`/`SizeZ`. Per-mip dimensions land in
//!   [`crate::asset::Texture2DData::mips`]; the bulk records are surfaced
//!   keyed by export index and stored in `Package` by `read_from_inner`
//!   (3e-3b) so the mip bytes resolve lazily via
//!   `Package::resolve_bulk_for_export`.
//! - **3e-4** ([`pixel_format`]): the `EPixelFormat` enum + uncompressed
//!   decoders (`PF_R8G8B8A8`, `PF_B8G8R8A8`, `PF_G8`, `PF_G16`) that turn a
//!   mip's encoded bytes into RGBA8, plus the `MAX_DECODED_TEXTURE_BYTES`
//!   cap.
//! - **3e-5** ([`pixel_format`]): the BC family (`PF_DXT1`/`PF_DXT3`/
//!   `PF_DXT5`/`PF_BC4`/`PF_BC5`/`PF_BC7`) via the `bcdec_rs` crate.
//! - **3e-6** ([`pixel_format`]): the mobile families via `texture2ddecoder` —
//!   ASTC (`PF_ASTC_4x4`/`6x6`/`8x8`/`10x10`/`12x12`) and ETC
//!   (`PF_ETC1`/`PF_ETC2_RGB`/`PF_ETC2_RGBA`). The HDR family (3e-7) +
//!   `PngHandler` (3e-8) follow.

pub(crate) mod pixel_format;
pub(crate) mod texture2d;
