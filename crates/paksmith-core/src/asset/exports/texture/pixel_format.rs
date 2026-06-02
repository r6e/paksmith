//! `EPixelFormat` pixel-format decoders (Phase 3e-4).
//!
//! A `UTexture2D`'s `FTexturePlatformData` names its pixel layout by
//! `EPixelFormat` *name* (an `FString`, e.g. `"PF_DXT5"`) — see
//! `docs/formats/texture/pixel-formats.md`. This module turns a mip's
//! encoded bytes (in a given format) into a tightly-packed **RGBA8** buffer
//! that the `PngHandler` (3e-8) can write.
//!
//! 3e-4 ships the **uncompressed** formats: `PF_R8G8B8A8`, `PF_B8G8R8A8`,
//! `PF_G8`, `PF_G16`. The block-compressed (BC/DXT, ASTC, ETC2) and HDR
//! families land with their decoders in later 3e milestones; until then
//! their names parse to [`PixelFormat::Unknown`] and decode to
//! [`AssetParseFault::UnsupportedPixelFormat`].
//!
//! **Divergence from the CUE4Parse oracle.** CUE4Parse's
//! `TextureDecoder.DecodeBytes` (`cf74fc32`) treats `PF_B8G8R8A8` / `PF_G8`
//! / `PF_G16` as *raw* — it returns the bytes unchanged plus a format tag
//! and lets the downstream image library (SkiaSharp) interpret the channel
//! order. paksmith has no such library, so it converts to RGBA8 itself
//! using the standard channel semantics:
//! - `PF_R8G8B8A8` → direct copy.
//! - `PF_B8G8R8A8` → swizzle the B/R channels (DirectX byte order → RGBA).
//! - `PF_G8` → grayscale replicated to R=G=B, opaque alpha.
//! - `PF_G16` → 16-bit LE grayscale, high byte taken as the 8-bit value
//!   (truncation, not rounding/rescale — matches the common DDS/Skia
//!   down-convert), replicated to R=G=B, opaque alpha.
//!
//! **sRGB.** The decoders do **no** color-space transform — bytes pass
//! through linearly. The `SRGB` tagged property is metadata the
//! `PngHandler` (3e-8) carries into the PNG's own sRGB chunk; the decoded
//! buffer is raw channel values either way.
//!
//! **Verification caveat.** The channel order (B/R swizzle, G16 high-byte)
//! is byte-construction-correct against the public DDS/DXGI memory-order
//! convention (`DXGI_FORMAT_B8G8R8A8_UNORM` = B,G,R,A in memory) and pinned
//! by distinct-per-channel tests — but those tests are *synthetic* (built
//! from the same understanding as the decoder), so they prove internal
//! consistency, not wire-fidelity. End-to-end cross-validation against the
//! CUE4Parse oracle on a real cooked asset is a 3e-8 obligation (the
//! `PngHandler` PNG round-trip).
//!
//! The whole module is `dead_code`-allowed: it ships the decode API +
//! the four uncompressed decoders, but its first production consumer is
//! 3e-8's `PngHandler` (mirrors how `Package::insert_bulk_records` shipped
//! ahead of its 3e-3b caller). The in-source tests exercise every item.
#![allow(
    dead_code,
    reason = "3e-4 ships the decode layer; 3e-8's PngHandler is the first production consumer"
)]

use crate::PaksmithError;
use crate::error::AssetParseFault;

use super::texture2d::MAX_TEXTURE_DIMENSION;

/// Bytes per pixel of the decoded RGBA8 output.
const RGBA8_BYTES_PER_PIXEL: u64 = 4;

/// Per-call cap on a single decoded mip's RGBA8 buffer
/// (`width × height × 4`). Derived from [`MAX_TEXTURE_DIMENSION`]: the
/// largest legitimate mip (`16384 × 16384`) decodes to `16384² × 4` = 1 GiB
/// of RGBA8, so this is exactly that ceiling — anything larger means a
/// corrupt dimension (or a `u64` overflow on the product) and is rejected
/// before allocating. Coherent with the parser-side `MAX_UEXP_SIZE` (1 GiB)
/// and well under `MAX_BULK_DATA_SIZE` (8 GiB).
///
/// This is a **per-call (single-mip)** ceiling. A cross-mip / per-package
/// decode budget is deferred until 3e-8's `PngHandler` actually drives a
/// whole-chain decode (no accumulating caller exists yet).
pub(super) const MAX_DECODED_TEXTURE_BYTES: u64 =
    (MAX_TEXTURE_DIMENSION as u64) * (MAX_TEXTURE_DIMENSION as u64) * RGBA8_BYTES_PER_PIXEL;

/// A decoded texture mip: a tightly-packed row-major RGBA8 buffer plus its
/// pixel dimensions. `rgba.len() == width * height * 4`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DecodedTexture {
    /// Mip width in pixels.
    pub width: u32,
    /// Mip height in pixels.
    pub height: u32,
    /// Row-major RGBA8 pixels (`width × height × 4` bytes).
    pub rgba: Vec<u8>,
}

/// The subset of `EPixelFormat` paksmith decodes in 3e-4 (the uncompressed
/// formats), plus [`Unknown`](Self::Unknown) for every other name. Later 3e
/// milestones add a variant + a decode arm together as each family lands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PixelFormat {
    /// `PF_R8G8B8A8` — 4 B/px, wire channel order R, G, B, A.
    R8G8B8A8,
    /// `PF_B8G8R8A8` — 4 B/px, wire channel order B, G, R, A.
    B8G8R8A8,
    /// `PF_G8` — 1 B/px 8-bit grayscale.
    G8,
    /// `PF_G16` — 2 B/px 16-bit little-endian grayscale.
    G16,
    /// An `EPixelFormat` name paksmith has no decoder for (a not-yet-handled
    /// family, or a genuinely unknown / typo'd name). The name is retained
    /// for [`AssetParseFault::UnsupportedPixelFormat`].
    Unknown(String),
}

impl PixelFormat {
    /// Resolve an `EPixelFormat` wire name (e.g. `"PF_B8G8R8A8"`) to a
    /// [`PixelFormat`]; unrecognized names become [`Unknown`](Self::Unknown).
    pub(crate) fn from_name(name: &str) -> Self {
        match name {
            "PF_R8G8B8A8" => Self::R8G8B8A8,
            "PF_B8G8R8A8" => Self::B8G8R8A8,
            "PF_G8" => Self::G8,
            "PF_G16" => Self::G16,
            other => Self::Unknown(other.to_string()),
        }
    }
}

/// A `fn(encoded, rgba)` that decodes one mip's `encoded` bytes into the
/// pre-sized `rgba` output. The single dispatch match below pairs each
/// format's encoded stride with its decoder, so the [`PixelFormat::Unknown`]
/// no-decoder case is handled exactly once (no second match, no panic arm).
type MipDecoder = fn(encoded: &[u8], rgba: &mut [u8]);

/// Decode one mip's `encoded` bytes (in `format`, `width × height`) into a
/// tightly-packed RGBA8 [`DecodedTexture`].
///
/// # Errors
/// - [`AssetParseFault::UnsupportedPixelFormat`] if `format` is
///   [`PixelFormat::Unknown`] (no decoder).
/// - [`AssetParseFault::DecodedTextureBytesExceeded`] if `width × height × 4`
///   exceeds [`MAX_DECODED_TEXTURE_BYTES`] or overflows `u64`.
/// - [`AssetParseFault::TextureMipSizeMismatch`] if `encoded.len()` is not
///   exactly `width × height × bytes_per_pixel(format)`.
pub(crate) fn decode_mip(
    format: &PixelFormat,
    encoded: &[u8],
    width: u32,
    height: u32,
    asset_path: &str,
) -> crate::Result<DecodedTexture> {
    // Single dispatch: each format yields its encoded stride (`bpp`) and its
    // decoder; `Unknown` (no decoder) returns early here, so neither the size
    // logic below nor the decode call can ever see it (no `unreachable!`).
    let (bpp, decode): (u64, MipDecoder) = match format {
        // `copy_from_slice` panics on a length mismatch, but the size check
        // below guarantees `encoded.len() == width × height × 4 == rgba.len()`
        // for this `bpp == 4` format before `decode` is ever called — keep that
        // check ahead of the call if this is ever reordered.
        PixelFormat::R8G8B8A8 => (4, |encoded, rgba| rgba.copy_from_slice(encoded)),
        PixelFormat::B8G8R8A8 => (4, decode_b8g8r8a8),
        PixelFormat::G8 => (1, decode_g8),
        PixelFormat::G16 => (2, decode_g16),
        PixelFormat::Unknown(name) => {
            return Err(fault(
                asset_path,
                AssetParseFault::UnsupportedPixelFormat { name: name.clone() },
            ));
        }
    };

    // RGBA8 output size = pixels × 4. Reject overflow / over-cap BEFORE
    // allocating. (Dimensions reaching the texture reader are capped at
    // MAX_TEXTURE_DIMENSION, so this never fires for in-range mips; it
    // guards a future/other caller passing arbitrary dimensions.)
    let pixels = u64::from(width).checked_mul(u64::from(height));
    let decoded_bytes = pixels.and_then(|p| p.checked_mul(RGBA8_BYTES_PER_PIXEL));
    let decoded_bytes = match decoded_bytes {
        Some(bytes) if bytes <= MAX_DECODED_TEXTURE_BYTES => bytes,
        other => {
            return Err(fault(
                asset_path,
                AssetParseFault::DecodedTextureBytesExceeded {
                    bytes: other.unwrap_or(u64::MAX),
                    cap: MAX_DECODED_TEXTURE_BYTES,
                },
            ));
        }
    };

    // Encoded size = pixels × bpp. `bpp <= 4`, so this cannot overflow once
    // `pixels × 4` (above) did not — but compute it checked anyway so the
    // unreachable overflow degrades to a size mismatch rather than a panic.
    let expected = pixels.and_then(|p| p.checked_mul(bpp));
    if expected != Some(encoded.len() as u64) {
        return Err(fault(
            asset_path,
            AssetParseFault::TextureMipSizeMismatch {
                expected: expected.unwrap_or(u64::MAX),
                actual: encoded.len(),
            },
        ));
    }

    // `decoded_bytes <= MAX_DECODED_TEXTURE_BYTES` (1 GiB) → fits `usize` on
    // every target (1 GiB < `u32::MAX`, so even a 32-bit `usize` holds it).
    #[allow(
        clippy::cast_possible_truncation,
        reason = "decoded_bytes is validated <= MAX_DECODED_TEXTURE_BYTES (1 GiB) < usize::MAX above"
    )]
    let mut rgba = vec![0u8; decoded_bytes as usize];
    decode(encoded, &mut rgba);
    Ok(DecodedTexture {
        width,
        height,
        rgba,
    })
}

/// `PF_B8G8R8A8` (B,G,R,A wire order) → RGBA8: swizzle the B and R channels.
fn decode_b8g8r8a8(encoded: &[u8], rgba: &mut [u8]) {
    for (src, dst) in encoded.chunks_exact(4).zip(rgba.chunks_exact_mut(4)) {
        dst[0] = src[2]; // dst R ← src[2] (the R byte in B,G,R,A)
        dst[1] = src[1]; // dst G ← src[1] (unchanged)
        dst[2] = src[0]; // dst B ← src[0] (the B byte in B,G,R,A)
        dst[3] = src[3]; // dst A ← src[3] (unchanged)
    }
}

/// `PF_G8` (8-bit grayscale) → RGBA8: replicate to R=G=B, opaque alpha.
fn decode_g8(encoded: &[u8], rgba: &mut [u8]) {
    for (g, dst) in encoded.iter().zip(rgba.chunks_exact_mut(4)) {
        write_gray(dst, *g);
    }
}

/// `PF_G16` (16-bit LE grayscale) → RGBA8: take the high byte as the 8-bit
/// gray value (truncation), replicate to R=G=B, opaque alpha.
fn decode_g16(encoded: &[u8], rgba: &mut [u8]) {
    for (px, dst) in encoded.chunks_exact(2).zip(rgba.chunks_exact_mut(4)) {
        write_gray(dst, px[1]); // px[1] = high byte of the little-endian u16
    }
}

/// Write one opaque RGBA8 pixel replicating `gray` to R=G=B (alpha `0xFF`).
/// `dst` is one `chunks_exact_mut(4)` slice, so the four indices never panic.
fn write_gray(dst: &mut [u8], gray: u8) {
    dst[0] = gray;
    dst[1] = gray;
    dst[2] = gray;
    dst[3] = 0xFF;
}

/// Wrap an [`AssetParseFault`] for `asset_path`.
fn fault(asset_path: &str, fault: AssetParseFault) -> PaksmithError {
    PaksmithError::AssetParse {
        asset_path: asset_path.to_string(),
        fault,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_name_resolves_the_decodable_formats() {
        assert_eq!(PixelFormat::from_name("PF_R8G8B8A8"), PixelFormat::R8G8B8A8);
        assert_eq!(PixelFormat::from_name("PF_B8G8R8A8"), PixelFormat::B8G8R8A8);
        assert_eq!(PixelFormat::from_name("PF_G8"), PixelFormat::G8);
        assert_eq!(PixelFormat::from_name("PF_G16"), PixelFormat::G16);
    }

    #[test]
    fn from_name_unrecognized_is_unknown_with_the_name() {
        assert_eq!(
            PixelFormat::from_name("PF_DXT5"),
            PixelFormat::Unknown("PF_DXT5".to_string())
        );
    }

    #[test]
    fn max_decoded_texture_bytes_is_one_gib_from_the_dimension_cap() {
        // 16384 × 16384 × 4 = 1 GiB — the largest legitimate decoded mip.
        assert_eq!(MAX_DECODED_TEXTURE_BYTES, 1024 * 1024 * 1024);
    }

    #[test]
    fn r8g8b8a8_decodes_by_direct_copy() {
        // One pixel, distinct channels: copied verbatim.
        let decoded =
            decode_mip(&PixelFormat::R8G8B8A8, &[10, 20, 30, 40], 1, 1, "t").expect("decode");
        assert_eq!(decoded.width, 1);
        assert_eq!(decoded.height, 1);
        assert_eq!(decoded.rgba, vec![10, 20, 30, 40]);
    }

    #[test]
    fn b8g8r8a8_swizzles_the_b_and_r_channels() {
        // DISTINCT per channel (B=1, G=2, R=3, A=4) so a reversed swizzle is
        // caught — a gray pixel (B=G=R) would pass either way.
        let decoded = decode_mip(&PixelFormat::B8G8R8A8, &[1, 2, 3, 4], 1, 1, "t").expect("decode");
        // RGBA: R=3 (the R byte), G=2, B=1 (the B byte), A=4.
        assert_eq!(decoded.rgba, vec![3, 2, 1, 4]);
    }

    #[test]
    fn g8_replicates_grayscale_with_opaque_alpha() {
        let decoded = decode_mip(&PixelFormat::G8, &[42], 1, 1, "t").expect("decode");
        assert_eq!(decoded.rgba, vec![42, 42, 42, 0xFF]);
    }

    #[test]
    fn g16_takes_the_high_byte_with_opaque_alpha() {
        // LE u16 = 0x1234 → high byte 0x12 is the 8-bit gray value.
        let decoded = decode_mip(&PixelFormat::G16, &[0x34, 0x12], 1, 1, "t").expect("decode");
        assert_eq!(decoded.rgba, vec![0x12, 0x12, 0x12, 0xFF]);
    }

    #[test]
    fn multi_pixel_decode_covers_every_pixel_in_order() {
        // 2×1 B8G8R8A8 → both pixels swizzled, in order.
        let encoded = [1, 2, 3, 4, 5, 6, 7, 8]; // px0 BGRA=(1,2,3,4), px1=(5,6,7,8)
        let decoded = decode_mip(&PixelFormat::B8G8R8A8, &encoded, 2, 1, "t").expect("decode");
        assert_eq!(decoded.rgba, vec![3, 2, 1, 4, 7, 6, 5, 8]);
    }

    #[test]
    fn unknown_format_is_rejected_with_its_name() {
        match decode_mip(&PixelFormat::from_name("PF_DXT5"), &[0; 16], 4, 4, "t") {
            Err(PaksmithError::AssetParse {
                fault: AssetParseFault::UnsupportedPixelFormat { name },
                ..
            }) => assert_eq!(name, "PF_DXT5"),
            other => panic!("expected UnsupportedPixelFormat, got {other:?}"),
        }
    }

    #[test]
    fn encoded_size_mismatch_is_rejected() {
        // 2×2 R8G8B8A8 expects 16 bytes; supply 15.
        match decode_mip(&PixelFormat::R8G8B8A8, &[0u8; 15], 2, 2, "t") {
            Err(PaksmithError::AssetParse {
                fault: AssetParseFault::TextureMipSizeMismatch { expected, actual },
                ..
            }) => {
                assert_eq!(expected, 16);
                assert_eq!(actual, 15);
            }
            other => panic!("expected TextureMipSizeMismatch, got {other:?}"),
        }
    }

    #[test]
    fn over_cap_dimensions_are_rejected_before_allocating() {
        // 20000 × 20000 × 4 = 1.6 GiB > 1 GiB cap. (Empty `encoded` would
        // also mismatch, but the cap check fires first.)
        match decode_mip(&PixelFormat::R8G8B8A8, &[], 20_000, 20_000, "t") {
            Err(PaksmithError::AssetParse {
                fault: AssetParseFault::DecodedTextureBytesExceeded { bytes, cap },
                ..
            }) => {
                assert_eq!(bytes, 20_000u64 * 20_000 * 4);
                assert_eq!(cap, MAX_DECODED_TEXTURE_BYTES);
            }
            other => panic!("expected DecodedTextureBytesExceeded, got {other:?}"),
        }
    }

    #[test]
    fn at_cap_dimensions_pass_the_cap_check() {
        // 16384 × 16384 × 4 == cap exactly → not rejected by the cap (`>`,
        // not `>=`); it then mismatches on the (empty) encoded slice, which
        // proves the cap branch let it through.
        match decode_mip(&PixelFormat::R8G8B8A8, &[], 16384, 16384, "t") {
            Err(PaksmithError::AssetParse {
                fault: AssetParseFault::TextureMipSizeMismatch { .. },
                ..
            }) => {}
            other => panic!("expected TextureMipSizeMismatch (cap passed), got {other:?}"),
        }
    }

    #[test]
    fn overflowing_dimensions_are_rejected_as_decoded_bytes_exceeded() {
        // u32::MAX × u32::MAX × 4 overflows u64 → reported as cap-exceeded
        // with u64::MAX, never panics or allocates.
        match decode_mip(&PixelFormat::R8G8B8A8, &[], u32::MAX, u32::MAX, "t") {
            Err(PaksmithError::AssetParse {
                fault: AssetParseFault::DecodedTextureBytesExceeded { bytes, .. },
                ..
            }) => assert_eq!(bytes, u64::MAX),
            other => panic!("expected DecodedTextureBytesExceeded(overflow), got {other:?}"),
        }
    }
}
