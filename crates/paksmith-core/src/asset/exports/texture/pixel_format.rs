//! `EPixelFormat` pixel-format decoders (Phase 3e-4, 3e-5, 3e-6).
//!
//! A `UTexture2D`'s `FTexturePlatformData` names its pixel layout by
//! `EPixelFormat` *name* (an `FString`, e.g. `"PF_DXT5"`) — see
//! `docs/formats/texture/pixel-formats.md`. This module turns a mip's
//! encoded bytes (in a given format) into a tightly-packed **RGBA8** buffer
//! that the `PngHandler` (3e-8) can write.
//!
//! - **3e-4** ships the **uncompressed** formats: `PF_R8G8B8A8`,
//!   `PF_B8G8R8A8`, `PF_G8`, `PF_G16`.
//! - **3e-5** ships the **BC family** (block-compressed, desktop):
//!   `PF_DXT1` (BC1), `PF_DXT3` (BC2), `PF_DXT5` (BC3), `PF_BC4`, `PF_BC5`,
//!   `PF_BC7` — block decode via the [`bcdec_rs`] crate.
//! - **3e-6** ships the **mobile** families via the [`texture2ddecoder`]
//!   crate: ASTC `PF_ASTC_4x4`/`6x6`/`8x8`/`10x10`/`12x12` (variable block
//!   dimensions) and ETC `PF_ETC1` / `PF_ETC2_RGB` / `PF_ETC2_RGBA`.
//!
//! HDR (`PF_BC6H`, FloatRGB/RGBA — 3e-7) lands later; until then those names
//! parse to [`PixelFormat::Unknown`] and decode to
//! [`AssetParseFault::UnsupportedPixelFormat`].
//!
//! **Divergence from the CUE4Parse oracle.** CUE4Parse's
//! `TextureDecoder.DecodeBytes` (`cf74fc32`) treats the uncompressed formats
//! as *raw* (bytes + a format tag, channel order resolved by SkiaSharp) and
//! routes the compressed families through decoders. paksmith has no image
//! library, so it converts to RGBA8 itself using the standard channel
//! semantics:
//! - `PF_R8G8B8A8` → direct copy.
//! - `PF_B8G8R8A8` → swizzle the B/R channels (DirectX byte order → RGBA).
//! - `PF_G8` → grayscale replicated to R=G=B, opaque alpha.
//! - `PF_G16` → 16-bit LE grayscale, high byte taken as the 8-bit value
//!   (truncation, not rounding/rescale — matches the common DDS/Skia
//!   down-convert), replicated to R=G=B, opaque alpha.
//! - `BC1`/`BC2`/`BC3`/`BC7` → `bcdec_rs` RGBA8 output, copied verbatim.
//! - `BC4` (1-channel) → grayscale replicated to R=G=B, opaque alpha —
//!   matching CUE4Parse's `BCDecoder.BC4`.
//! - `BC5` (2-channel) → normal map: R, G passthrough and the **blue/Z
//!   channel reconstructed** as `√(1 − x² − y²)`, matching CUE4Parse's
//!   `BCDecoder.GetZNormal` (see [`reconstruct_z_normal`]). This bakes a
//!   "`BC5` is a tangent-space normal map" assumption (its dominant use).
//! - **ASTC / ETC** → `texture2ddecoder` decodes a whole mip into a `u32`
//!   buffer it packs as **BGRA** (`color()` = `[b,g,r,a]` LE bytes);
//!   [`decode_t2d`] swaps each pixel to RGBA8. ASTC additionally restores the
//!   normal-map blue/Z when `is_normal_map` is set (UE drops blue before
//!   encoding) — matching CUE4Parse's `isNormalMap`-gated ASTC path. ETC
//!   carries full color and is never normal-restored.
//!
//! **sRGB.** The decoders do **no** color-space transform — bytes pass
//! through linearly. The `SRGB` tagged property is metadata the
//! `PngHandler` (3e-8) carries into the PNG's own sRGB chunk; the decoded
//! buffer is raw channel values either way.
//!
//! **Verification caveat.** The channel mappings (B/R swizzle, G16 high-byte,
//! the `bcdec_rs` RGBA8 order, the BC4/BC5 expansion, the `texture2ddecoder`
//! BGRA→RGBA swap) are byte-construction-correct against public conventions
//! and the decoder libraries' own packing, and pinned by tests (e.g. an ASTC
//! void-extent block of a known constant color) — but those tests are
//! *synthetic* (built from the same understanding as the decoder), so they
//! prove internal consistency, not wire-fidelity. End-to-end cross-validation
//! against the CUE4Parse oracle on a real cooked asset is a 3e-8 obligation
//! (the `PngHandler` PNG round-trip).
//!
//! The whole module is `dead_code`-allowed: it ships the decode API + the
//! uncompressed, BC, and ASTC/ETC decoders, but its first production consumer
//! is 3e-8's `PngHandler` (mirrors how `Package::insert_bulk_records` shipped
//! ahead of its 3e-3b caller). The in-source tests exercise every item.
#![allow(
    dead_code,
    reason = "3e-4/3e-5/3e-6 ship the decode layer; 3e-8's PngHandler is the first production consumer"
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

/// The subset of `EPixelFormat` paksmith decodes (3e-4 uncompressed, 3e-5 BC,
/// 3e-6 ASTC/ETC), plus [`Unknown`](Self::Unknown) for every other name. Later
/// 3e milestones add a variant + a decode arm together as each family lands.
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
    /// `PF_DXT1` — BC1, 8-byte 4×4 block, RGB(+1-bit alpha).
    Bc1,
    /// `PF_DXT3` — BC2, 16-byte 4×4 block, RGBA (explicit 4-bit alpha).
    Bc2,
    /// `PF_DXT5` — BC3, 16-byte 4×4 block, RGBA (interpolated alpha).
    Bc3,
    /// `PF_BC4` — 8-byte 4×4 block, single channel → grayscale RGBA8.
    Bc4,
    /// `PF_BC5` — 16-byte 4×4 block, two channels → normal map (Z reconstructed).
    Bc5,
    /// `PF_BC7` — 16-byte 4×4 block, high-quality RGBA.
    Bc7,
    /// `PF_ASTC_4x4` — 16-byte block, 4×4 pixels.
    Astc4x4,
    /// `PF_ASTC_6x6` — 16-byte block, 6×6 pixels.
    Astc6x6,
    /// `PF_ASTC_8x8` — 16-byte block, 8×8 pixels.
    Astc8x8,
    /// `PF_ASTC_10x10` — 16-byte block, 10×10 pixels.
    Astc10x10,
    /// `PF_ASTC_12x12` — 16-byte block, 12×12 pixels.
    Astc12x12,
    /// `PF_ETC1` — 8-byte 4×4 block, RGB (legacy mobile).
    Etc1,
    /// `PF_ETC2_RGB` — 8-byte 4×4 block, RGB.
    Etc2Rgb,
    /// `PF_ETC2_RGBA` — 16-byte 4×4 block, RGB + EAC 8-bit alpha.
    Etc2Rgba,
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
            "PF_DXT1" => Self::Bc1,
            "PF_DXT3" => Self::Bc2,
            "PF_DXT5" => Self::Bc3,
            "PF_BC4" => Self::Bc4,
            "PF_BC5" => Self::Bc5,
            "PF_BC7" => Self::Bc7,
            "PF_ASTC_4x4" => Self::Astc4x4,
            "PF_ASTC_6x6" => Self::Astc6x6,
            "PF_ASTC_8x8" => Self::Astc8x8,
            "PF_ASTC_10x10" => Self::Astc10x10,
            "PF_ASTC_12x12" => Self::Astc12x12,
            "PF_ETC1" => Self::Etc1,
            "PF_ETC2_RGB" => Self::Etc2Rgb,
            "PF_ETC2_RGBA" => Self::Etc2Rgba,
            other => Self::Unknown(other.to_string()),
        }
    }

    /// The `EPixelFormat` wire name for this format (the inverse of
    /// [`from_name`](Self::from_name) for the decodable variants), used in
    /// [`AssetParseFault::PixelFormatDecodeFailed`] messages.
    fn label(&self) -> &str {
        match self {
            Self::R8G8B8A8 => "PF_R8G8B8A8",
            Self::B8G8R8A8 => "PF_B8G8R8A8",
            Self::G8 => "PF_G8",
            Self::G16 => "PF_G16",
            Self::Bc1 => "PF_DXT1",
            Self::Bc2 => "PF_DXT3",
            Self::Bc3 => "PF_DXT5",
            Self::Bc4 => "PF_BC4",
            Self::Bc5 => "PF_BC5",
            Self::Bc7 => "PF_BC7",
            Self::Astc4x4 => "PF_ASTC_4x4",
            Self::Astc6x6 => "PF_ASTC_6x6",
            Self::Astc8x8 => "PF_ASTC_8x8",
            Self::Astc10x10 => "PF_ASTC_10x10",
            Self::Astc12x12 => "PF_ASTC_12x12",
            Self::Etc1 => "PF_ETC1",
            Self::Etc2Rgb => "PF_ETC2_RGB",
            Self::Etc2Rgba => "PF_ETC2_RGBA",
            Self::Unknown(name) => name,
        }
    }
}

/// A block-compressed mip decoder: `(encoded, rgba, width, height,
/// is_normal_map) -> Result`. Returns the decoder library's error verbatim
/// (BC is infallible and always returns `Ok`; ASTC/ETC via `texture2ddecoder`
/// can fail). The BC decoders ignore `is_normal_map`; ASTC uses it to restore
/// the dropped normal-map blue/Z.
type BlockDecoder = fn(&[u8], &mut [u8], u32, u32, bool) -> Result<(), &'static str>;

/// A `texture2ddecoder` whole-mip entry point: `(encoded, width, height,
/// &mut bgra_u32) -> Result`.
type T2dDecoder = fn(&[u8], usize, usize, &mut [u32]) -> Result<(), &'static str>;

/// How a format's encoded mip is sized and decoded into RGBA8.
///
/// Splitting the dispatch by codec class keeps each decoder's signature
/// minimal — linear decoders need only `(encoded, rgba)`, while block
/// decoders also need the dimensions and the normal-map flag — and couples
/// each class's encoded-size formula with its decoder so [`decode_mip`]
/// validates the right length before allocating. The [`PixelFormat::Unknown`]
/// no-decoder case returns before a `Codec` is ever built (no panic arm).
enum Codec {
    /// Uncompressed: `encoded.len() == width × height × bytes_per_pixel`.
    Linear {
        bytes_per_pixel: u64,
        decode: fn(encoded: &[u8], rgba: &mut [u8]),
    },
    /// Block-compressed (`block_w × block_h`-pixel blocks):
    /// `encoded.len() == ceil(w/block_w) × ceil(h/block_h) × bytes_per_block`.
    /// Covers BC (4×4, via `bcdec_rs`), ETC (4×4, via `texture2ddecoder`), and
    /// ASTC (variable block dims, via `texture2ddecoder`).
    Block {
        block_w: u32,
        block_h: u32,
        bytes_per_block: usize,
        decode: BlockDecoder,
    },
}

/// Decode one mip's `encoded` bytes (in `format`, `width × height`) into a
/// tightly-packed RGBA8 [`DecodedTexture`].
///
/// `is_normal_map` is the texture's tangent-space-normal flag (in UE, derived
/// from `CompressionSettings == TC_Normalmap`); it gates ASTC's blue/Z
/// reconstruction (UE drops the blue channel of normal maps before ASTC
/// encoding). It does **not** affect BC5, which is intrinsically 2-channel and
/// always reconstructs Z, nor any other format. A future 3e-8 caller threads
/// this in from the parsed tagged properties; today only tests set it.
///
/// # Errors
/// - [`AssetParseFault::UnsupportedPixelFormat`] if `format` is
///   [`PixelFormat::Unknown`] (no decoder).
/// - [`AssetParseFault::DecodedTextureBytesExceeded`] if `width × height × 4`
///   exceeds [`MAX_DECODED_TEXTURE_BYTES`] or overflows `u64`.
/// - [`AssetParseFault::TextureMipSizeMismatch`] if `encoded.len()` is not
///   exactly the format's encoded size (`pixels × bytes_per_pixel` for the
///   uncompressed formats, `ceil(w/bw) × ceil(h/bh) × bytes_per_block` for
///   block-compressed).
/// - [`AssetParseFault::PixelFormatDecodeFailed`] if a block decoder rejects
///   the bytes (a defensive backstop — the size + buffer are validated first).
pub(crate) fn decode_mip(
    format: &PixelFormat,
    encoded: &[u8],
    width: u32,
    height: u32,
    is_normal_map: bool,
    asset_path: &str,
) -> crate::Result<DecodedTexture> {
    // Dispatch to the format's codec (size formula + decoder). `Unknown` (no
    // decoder) returns early here, so neither the size logic nor the decode
    // call below ever sees a decoder-less format (no `unreachable!`).
    let Some(codec) = codec_for(format) else {
        return Err(fault(
            asset_path,
            AssetParseFault::UnsupportedPixelFormat {
                name: format.label().to_string(),
            },
        ));
    };

    // RGBA8 output size = pixels × 4 (for every format — BC decodes to the same
    // pixel count). Reject overflow / over-cap BEFORE allocating. (Dimensions
    // reaching the texture reader are capped at MAX_TEXTURE_DIMENSION; this
    // also guards a future/other caller passing arbitrary dimensions.)
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

    // Encoded size depends on the codec class. Both compute checked so an
    // overflow degrades to a size mismatch rather than a panic.
    let expected = match &codec {
        Codec::Linear {
            bytes_per_pixel, ..
        } => pixels.and_then(|p| p.checked_mul(*bytes_per_pixel)),
        Codec::Block {
            block_w,
            block_h,
            bytes_per_block,
            ..
        } => block_encoded_len(width, height, *block_w, *block_h, *bytes_per_block),
    };
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
    match codec {
        Codec::Linear { decode, .. } => decode(encoded, &mut rgba),
        // The size check + correct `rgba` sizing make the block decoders'
        // `Err` unreachable here, but propagate it (don't swallow a partial
        // decode) — a future decoder rejecting malformed bytes surfaces it.
        Codec::Block { decode, .. } => decode(encoded, &mut rgba, width, height, is_normal_map)
            .map_err(|reason| pixel_format_decode_failed(format, reason, asset_path))?,
    }
    Ok(DecodedTexture {
        width,
        height,
        rgba,
    })
}

/// Map a decodable [`PixelFormat`] to its [`Codec`] (encoded-size formula +
/// decoder). `None` for [`PixelFormat::Unknown`] (no decoder), which
/// [`decode_mip`] turns into [`AssetParseFault::UnsupportedPixelFormat`].
fn codec_for(format: &PixelFormat) -> Option<Codec> {
    Some(match format {
        // `copy_from_slice` panics on a length mismatch, but `decode_mip`'s
        // size check guarantees `encoded.len() == rgba.len()` for this 4-B/px
        // format before the decoder runs — keep that check ahead of the call.
        PixelFormat::R8G8B8A8 => Codec::Linear {
            bytes_per_pixel: 4,
            decode: |encoded, rgba| rgba.copy_from_slice(encoded),
        },
        PixelFormat::B8G8R8A8 => Codec::Linear {
            bytes_per_pixel: 4,
            decode: decode_b8g8r8a8,
        },
        PixelFormat::G8 => Codec::Linear {
            bytes_per_pixel: 1,
            decode: decode_g8,
        },
        PixelFormat::G16 => Codec::Linear {
            bytes_per_pixel: 2,
            decode: decode_g16,
        },
        PixelFormat::Bc1 => bc_codec(BC1_BLOCK_BYTES, decode_bc1),
        PixelFormat::Bc2 => bc_codec(BC2_BLOCK_BYTES, decode_bc2),
        PixelFormat::Bc3 => bc_codec(BC3_BLOCK_BYTES, decode_bc3),
        PixelFormat::Bc4 => bc_codec(BC4_BLOCK_BYTES, decode_bc4),
        PixelFormat::Bc5 => bc_codec(BC5_BLOCK_BYTES, decode_bc5),
        PixelFormat::Bc7 => bc_codec(BC7_BLOCK_BYTES, decode_bc7),
        PixelFormat::Astc4x4 => astc_codec(4, 4, decode_astc_4x4),
        PixelFormat::Astc6x6 => astc_codec(6, 6, decode_astc_6x6),
        PixelFormat::Astc8x8 => astc_codec(8, 8, decode_astc_8x8),
        PixelFormat::Astc10x10 => astc_codec(10, 10, decode_astc_10x10),
        PixelFormat::Astc12x12 => astc_codec(12, 12, decode_astc_12x12),
        PixelFormat::Etc1 => etc_codec(ETC_RGB_BLOCK_BYTES, decode_etc1),
        PixelFormat::Etc2Rgb => etc_codec(ETC_RGB_BLOCK_BYTES, decode_etc2_rgb),
        PixelFormat::Etc2Rgba => etc_codec(ETC_RGBA_BLOCK_BYTES, decode_etc2_rgba),
        PixelFormat::Unknown(_) => return None,
    })
}

/// Build a 4×4-block BC [`Codec`].
fn bc_codec(bytes_per_block: usize, decode: BlockDecoder) -> Codec {
    Codec::Block {
        block_w: 4,
        block_h: 4,
        bytes_per_block,
        decode,
    }
}

/// Build an ASTC [`Codec`] (always 16-byte blocks; the block *dimensions*
/// vary per format).
fn astc_codec(block_w: u32, block_h: u32, decode: BlockDecoder) -> Codec {
    Codec::Block {
        block_w,
        block_h,
        bytes_per_block: ASTC_BLOCK_BYTES,
        decode,
    }
}

/// Build a 4×4-block ETC [`Codec`].
fn etc_codec(bytes_per_block: usize, decode: BlockDecoder) -> Codec {
    Codec::Block {
        block_w: 4,
        block_h: 4,
        bytes_per_block,
        decode,
    }
}

/// Wrap a [`PixelFormat`]'s block-decode failure (the decoder library's
/// `&str`) into an [`AssetParseFault::PixelFormatDecodeFailed`].
fn pixel_format_decode_failed(
    format: &PixelFormat,
    reason: &str,
    asset_path: &str,
) -> PaksmithError {
    fault(
        asset_path,
        AssetParseFault::PixelFormatDecodeFailed {
            format: format.label().to_string(),
            reason: reason.to_string(),
        },
    )
}

/// Encoded byte length of a block-compressed mip:
/// `ceil(w/block_w) × ceil(h/block_h) × bytes_per_block`, computed checked so
/// an overflow surfaces as a size mismatch (never a panic). `None` on `u64`
/// overflow. (BC and ETC pass `block_w = block_h = 4`; ASTC passes its block
/// dimensions.)
fn block_encoded_len(
    width: u32,
    height: u32,
    block_w: u32,
    block_h: u32,
    bytes_per_block: usize,
) -> Option<u64> {
    // Widen to u64 first so the ceil-div and products are overflow-checked.
    let blocks_x = u64::from(width).div_ceil(u64::from(block_w));
    let blocks_y = u64::from(height).div_ceil(u64::from(block_h));
    blocks_x
        .checked_mul(blocks_y)?
        .checked_mul(bytes_per_block as u64)
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

// ===== BC family (block-compressed) decoders =====
//
// Every BC mip is a grid of 4×4-pixel blocks. `bcdec_rs` decodes one block at
// a time into a destination using a row pitch. paksmith decodes each block
// into a private 4×4 RGBA8 tile and copies the in-bounds region into `rgba`,
// which both handles edge mips (dimensions not a multiple of 4 — the block
// overhangs the image) and confines the per-format channel handling to one
// `decode_tile` closure.

/// Side of a BC block in pixels (the whole family is 4×4).
const BC_BLOCK_DIM: usize = 4;
/// Bytes in a decoded 4×4 RGBA8 tile (`4 × 4 × 4`).
const BC_TILE_BYTES: usize = BC_BLOCK_DIM * BC_BLOCK_DIM * 4;
/// Row stride of the RGBA8 tile, in bytes (`4 px × 4 B/px`).
const BC_TILE_PITCH: usize = BC_BLOCK_DIM * 4;

// Encoded bytes per 4×4 block, per BC format — the SINGLE source of truth for
// each format's block size, referenced by both the dispatch's `Codec::Block`
// arm (which feeds `block_encoded_len` validation) and the matching
// `decode_bcN` wrapper (which feeds `chunks_exact`). Sharing one constant per
// format means the validation stride and the decode stride cannot drift.
const BC1_BLOCK_BYTES: usize = 8;
const BC2_BLOCK_BYTES: usize = 16;
const BC3_BLOCK_BYTES: usize = 16;
const BC4_BLOCK_BYTES: usize = 8;
const BC5_BLOCK_BYTES: usize = 16;
const BC7_BLOCK_BYTES: usize = 16;

/// Encoded bytes per ASTC block (always 16; the block *dimensions* vary).
const ASTC_BLOCK_BYTES: usize = 16;
/// Encoded bytes per ETC RGB / ETC1 4×4 block.
const ETC_RGB_BLOCK_BYTES: usize = 8;
/// Encoded bytes per ETC2 RGBA (ETC2 RGB + EAC alpha) 4×4 block.
const ETC_RGBA_BLOCK_BYTES: usize = 16;

/// Decode a BC mip block-by-block. `decode_tile` turns one `block` of encoded
/// bytes into a 4×4 RGBA8 `tile`; this loop copies each tile's in-bounds
/// region into `rgba`, clamping blocks that overhang the right/bottom edge.
///
/// `encoded` is pre-validated by [`decode_mip`] to hold exactly
/// `ceil(w/4) × ceil(h/4)` whole blocks, and `rgba` to be `w × h × 4` bytes,
/// so every slice index below is in bounds.
///
/// Always returns `Ok` (BC decode is infallible) — the `Result` lets the six
/// `decode_bcN` wrappers tail-return it without an `Ok(())` each, matching the
/// fallible [`BlockDecoder`] signature their ASTC/ETC peers genuinely need.
#[allow(
    clippy::unnecessary_wraps,
    reason = "Result unifies the BlockDecoder fn-pointer type; ASTC/ETC peers fail for real"
)]
fn decode_bc_mip(
    encoded: &[u8],
    rgba: &mut [u8],
    width: u32,
    height: u32,
    bytes_per_block: usize,
    decode_tile: impl Fn(&[u8], &mut [u8; BC_TILE_BYTES]),
) -> Result<(), &'static str> {
    let width = width as usize;
    let height = height as usize;
    // The chunk loop only iterates when `encoded` is non-empty, which (after
    // `decode_mip`'s size check) requires `ceil(w/4) × ceil(h/4) × bpb > 0`,
    // i.e. both dimensions ≥ 1 — so `blocks_x ≥ 1` and the `% blocks_x` below
    // is never a divide-by-zero. An empty mip simply runs zero iterations.
    let blocks_x = width.div_ceil(BC_BLOCK_DIM);
    let row_pitch = width * 4;
    let mut tile = [0u8; BC_TILE_BYTES];
    for (block_index, block) in encoded.chunks_exact(bytes_per_block).enumerate() {
        decode_tile(block, &mut tile);
        let left = (block_index % blocks_x) * BC_BLOCK_DIM;
        let top = (block_index / blocks_x) * BC_BLOCK_DIM;
        // Clamp the block to the image: edge blocks contribute fewer than 4
        // columns/rows. `left < width` and `top < height` hold because the
        // block count matches `ceil(w/4) × ceil(h/4)`.
        let copy_w = BC_BLOCK_DIM.min(width - left);
        let copy_h = BC_BLOCK_DIM.min(height - top);
        for row in 0..copy_h {
            let dst = (top + row) * row_pitch + left * 4;
            let src = row * BC_TILE_PITCH;
            rgba[dst..dst + copy_w * 4].copy_from_slice(&tile[src..src + copy_w * 4]);
        }
    }
    Ok(())
}

/// `PF_DXT1` (BC1) → RGBA8 (8-byte blocks).
fn decode_bc1(
    encoded: &[u8],
    rgba: &mut [u8],
    width: u32,
    height: u32,
    _is_normal_map: bool,
) -> Result<(), &'static str> {
    decode_bc_mip(
        encoded,
        rgba,
        width,
        height,
        BC1_BLOCK_BYTES,
        |block, tile| {
            bcdec_rs::bc1(block, tile, BC_TILE_PITCH);
        },
    )
}

/// `PF_DXT3` (BC2) → RGBA8 (16-byte blocks).
fn decode_bc2(
    encoded: &[u8],
    rgba: &mut [u8],
    width: u32,
    height: u32,
    _is_normal_map: bool,
) -> Result<(), &'static str> {
    decode_bc_mip(
        encoded,
        rgba,
        width,
        height,
        BC2_BLOCK_BYTES,
        |block, tile| {
            bcdec_rs::bc2(block, tile, BC_TILE_PITCH);
        },
    )
}

/// `PF_DXT5` (BC3) → RGBA8 (16-byte blocks).
fn decode_bc3(
    encoded: &[u8],
    rgba: &mut [u8],
    width: u32,
    height: u32,
    _is_normal_map: bool,
) -> Result<(), &'static str> {
    decode_bc_mip(
        encoded,
        rgba,
        width,
        height,
        BC3_BLOCK_BYTES,
        |block, tile| {
            bcdec_rs::bc3(block, tile, BC_TILE_PITCH);
        },
    )
}

/// `PF_BC4` (single channel, 8-byte blocks) → grayscale RGBA8 (R=G=B, opaque),
/// matching CUE4Parse's `BCDecoder.BC4`.
fn decode_bc4(
    encoded: &[u8],
    rgba: &mut [u8],
    width: u32,
    height: u32,
    _is_normal_map: bool,
) -> Result<(), &'static str> {
    decode_bc_mip(
        encoded,
        rgba,
        width,
        height,
        BC4_BLOCK_BYTES,
        |block, tile| {
            // bcdec_rs writes a 4×4 R8 block (1 B/px, pitch = 4 bytes). `false` =
            // UNORM (UE's `PF_BC4` is unsigned; the SNORM variant isn't a UE format).
            let mut r = [0u8; BC_BLOCK_DIM * BC_BLOCK_DIM];
            bcdec_rs::bc4(block, &mut r, BC_BLOCK_DIM, false);
            for (px, &gray) in r.iter().enumerate() {
                write_gray(&mut tile[px * 4..px * 4 + 4], gray);
            }
        },
    )
}

/// `PF_BC5` (two channels, 16-byte blocks) → normal-map RGBA8: R, G passthrough
/// with the blue/Z channel reconstructed (see [`reconstruct_z_normal`]). This
/// matches the combined effect of CUE4Parse's `TextureDecoder` BC5 path:
/// `BCDecoder.BC5` decodes R/G (and leaves blue at `0xFF`), then `TextureDecoder`
/// overwrites blue with `BCDecoder.GetZNormal(R, G)` — paksmith does both in one
/// pass.
fn decode_bc5(
    encoded: &[u8],
    rgba: &mut [u8],
    width: u32,
    height: u32,
    _is_normal_map: bool,
) -> Result<(), &'static str> {
    decode_bc_mip(
        encoded,
        rgba,
        width,
        height,
        BC5_BLOCK_BYTES,
        |block, tile| {
            // bcdec_rs writes a 4×4 RG8 block (2 B/px, pitch = 8 bytes): R from the
            // first sub-block, G from the second. `false` = UNORM (UE's `PF_BC5`).
            let mut rg = [0u8; BC_BLOCK_DIM * BC_BLOCK_DIM * 2];
            bcdec_rs::bc5(block, &mut rg, BC_BLOCK_DIM * 2, false);
            for (px, rg_px) in rg.chunks_exact(2).enumerate() {
                let (r, g) = (rg_px[0], rg_px[1]);
                let dst = &mut tile[px * 4..px * 4 + 4];
                dst[0] = r;
                dst[1] = g;
                dst[2] = reconstruct_z_normal(r, g);
                dst[3] = 0xFF;
            }
        },
    )
}

/// `PF_BC7` → RGBA8 (16-byte blocks).
fn decode_bc7(
    encoded: &[u8],
    rgba: &mut [u8],
    width: u32,
    height: u32,
    _is_normal_map: bool,
) -> Result<(), &'static str> {
    decode_bc_mip(
        encoded,
        rgba,
        width,
        height,
        BC7_BLOCK_BYTES,
        |block, tile| {
            bcdec_rs::bc7(block, tile, BC_TILE_PITCH);
        },
    )
}

// ===== ASTC + ETC (mobile) decoders =====
//
// Unlike `bcdec_rs` (per-block), `texture2ddecoder` decodes a whole mip at
// once into a `&mut [u32]` and handles the block loop + edge clamping itself.
// Its `color(r,g,b,a) = u32::from_le_bytes([b, g, r, a])` packs **BGRA** in
// memory, so `decode_t2d` swaps each pixel to RGBA8. ASTC additionally
// restores the normal-map blue/Z channel when the texture is a normal map
// (UE drops blue before ASTC encoding); ETC carries full RGBA and never does.

/// Decode a whole mip with a `texture2ddecoder` function into RGBA8.
/// Allocates a `width × height` `u32` buffer (BGRA, the crate's packing),
/// runs `decode`, then swaps each pixel into `rgba` as R,G,B,A.
///
/// **Panic containment.** `texture2ddecoder` *panics* (rather than returning
/// `Err`) on some malformed block bit-patterns — e.g. an invalid ASTC block
/// mode drives out-of-range indexing inside the crate. paksmith decodes
/// UNTRUSTED bytes, so the call is wrapped in [`std::panic::catch_unwind`]: a
/// corrupt texture surfaces as an `Err` (→ `PixelFormatDecodeFailed`), never a
/// process crash. On panic the half-written `bgra` buffer is discarded. (The
/// contained panic still prints via the default panic hook; tests that
/// deliberately feed garbage silence it locally — see
/// `astc_decoder_panics_are_contained`.)
///
/// This relies on **unwinding** panics: `catch_unwind` is a no-op under
/// `panic = "abort"`. No workspace profile sets it — but note the panic
/// strategy is the *consuming binary's* profile, so a downstream crate
/// building paksmith-core with `panic = "abort"` would defeat the containment.
/// The `AssertUnwindSafe` is sound: the only captured mutable state is the
/// local `bgra`, discarded on the panic path, so no broken invariant escapes.
///
/// `pixels = width × height` is computed unchecked, but this is private and
/// only reached via [`decode_mip`] *after* its `width × height × 4 ≤ 1 GiB`
/// cap check, so `width × height ≤ 268M` — no `usize` overflow on any target.
fn decode_t2d(
    encoded: &[u8],
    rgba: &mut [u8],
    width: u32,
    height: u32,
    decode: T2dDecoder,
) -> Result<(), &'static str> {
    let pixels = (width as usize) * (height as usize);
    let mut bgra = vec![0u32; pixels];
    let decoded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        decode(encoded, width as usize, height as usize, &mut bgra)
    }));
    match decoded {
        Ok(Ok(())) => {}
        Ok(Err(reason)) => return Err(reason),
        Err(_) => return Err("texture2ddecoder panicked on malformed block data"),
    }
    for (px, dst) in bgra.iter().zip(rgba.chunks_exact_mut(4)) {
        // `color()` packed [b, g, r, a] as the u32's little-endian bytes;
        // re-order to RGBA8.
        let bgra_bytes = px.to_le_bytes();
        dst[0] = bgra_bytes[2]; // R
        dst[1] = bgra_bytes[1]; // G
        dst[2] = bgra_bytes[0]; // B
        dst[3] = bgra_bytes[3]; // A
    }
    Ok(())
}

/// Overwrite each pixel's blue channel with the reconstructed normal-map Z
/// (`reconstruct_z_normal(R, G)`) — UE drops blue before encoding normal-map
/// ASTC, so it's restored from R/G the same way BC5 always is. Matches
/// CUE4Parse's `TextureDecoder` ASTC path (applied only when `isNormalMap`).
fn restore_normal_z(rgba: &mut [u8]) {
    for dst in rgba.chunks_exact_mut(4) {
        dst[2] = reconstruct_z_normal(dst[0], dst[1]);
    }
}

/// Decode an ASTC mip (16-byte blocks of `decode`'s block dimensions) into
/// RGBA8, restoring the normal-map Z channel when `is_normal_map` is set.
fn decode_astc(
    encoded: &[u8],
    rgba: &mut [u8],
    width: u32,
    height: u32,
    is_normal_map: bool,
    decode: T2dDecoder,
) -> Result<(), &'static str> {
    decode_t2d(encoded, rgba, width, height, decode)?;
    if is_normal_map {
        restore_normal_z(rgba);
    }
    Ok(())
}

/// `PF_ASTC_4x4` → RGBA8.
fn decode_astc_4x4(
    encoded: &[u8],
    rgba: &mut [u8],
    width: u32,
    height: u32,
    is_normal_map: bool,
) -> Result<(), &'static str> {
    decode_astc(
        encoded,
        rgba,
        width,
        height,
        is_normal_map,
        texture2ddecoder::decode_astc_4_4,
    )
}
/// `PF_ASTC_6x6` → RGBA8.
fn decode_astc_6x6(
    encoded: &[u8],
    rgba: &mut [u8],
    width: u32,
    height: u32,
    is_normal_map: bool,
) -> Result<(), &'static str> {
    decode_astc(
        encoded,
        rgba,
        width,
        height,
        is_normal_map,
        texture2ddecoder::decode_astc_6_6,
    )
}
/// `PF_ASTC_8x8` → RGBA8.
fn decode_astc_8x8(
    encoded: &[u8],
    rgba: &mut [u8],
    width: u32,
    height: u32,
    is_normal_map: bool,
) -> Result<(), &'static str> {
    decode_astc(
        encoded,
        rgba,
        width,
        height,
        is_normal_map,
        texture2ddecoder::decode_astc_8_8,
    )
}
/// `PF_ASTC_10x10` → RGBA8.
fn decode_astc_10x10(
    encoded: &[u8],
    rgba: &mut [u8],
    width: u32,
    height: u32,
    is_normal_map: bool,
) -> Result<(), &'static str> {
    decode_astc(
        encoded,
        rgba,
        width,
        height,
        is_normal_map,
        texture2ddecoder::decode_astc_10_10,
    )
}
/// `PF_ASTC_12x12` → RGBA8.
fn decode_astc_12x12(
    encoded: &[u8],
    rgba: &mut [u8],
    width: u32,
    height: u32,
    is_normal_map: bool,
) -> Result<(), &'static str> {
    decode_astc(
        encoded,
        rgba,
        width,
        height,
        is_normal_map,
        texture2ddecoder::decode_astc_12_12,
    )
}

/// `PF_ETC1` → RGBA8 (8-byte blocks). ETC carries full color, so the
/// `is_normal_map` flag does not apply (mirrors CUE4Parse, which restores Z
/// only for ASTC, not ETC).
fn decode_etc1(
    encoded: &[u8],
    rgba: &mut [u8],
    width: u32,
    height: u32,
    _is_normal_map: bool,
) -> Result<(), &'static str> {
    decode_t2d(encoded, rgba, width, height, texture2ddecoder::decode_etc1)
}
/// `PF_ETC2_RGB` → RGBA8 (8-byte blocks).
fn decode_etc2_rgb(
    encoded: &[u8],
    rgba: &mut [u8],
    width: u32,
    height: u32,
    _is_normal_map: bool,
) -> Result<(), &'static str> {
    decode_t2d(
        encoded,
        rgba,
        width,
        height,
        texture2ddecoder::decode_etc2_rgb,
    )
}
/// `PF_ETC2_RGBA` → RGBA8 (16-byte blocks: ETC2 RGB + EAC 8-bit alpha).
fn decode_etc2_rgba(
    encoded: &[u8],
    rgba: &mut [u8],
    width: u32,
    height: u32,
    _is_normal_map: bool,
) -> Result<(), &'static str> {
    decode_t2d(
        encoded,
        rgba,
        width,
        height,
        texture2ddecoder::decode_etc2_rgba8,
    )
}

/// Reconstruct a tangent-space normal map's Z (blue) byte from the X (`r`) and
/// Y (`g`) channels, byte-for-byte matching CUE4Parse's `BCDecoder.GetZNormal`:
/// map each channel to `[-1, 1]`, take `z = √(1 − x² − y²)` clamped to `[0, 1]`,
/// then map back to a byte as `z × 127 + 128`.
///
/// **3e-8 cross-val watch:** CUE4Parse computes the sqrt in `f64`
/// (`Math.Sqrt`) before narrowing, whereas this uses `f32` throughout. The
/// two can differ by 1 LSB on some inputs — acceptable here (the tests are
/// self-consistent and byte-exact oracle parity is a 3e-8 obligation), but a
/// 1-LSB BC5-blue mismatch at the PNG round-trip would trace back to here.
fn reconstruct_z_normal(r: u8, g: u8) -> u8 {
    let xf = f32::from(r) / 127.5 - 1.0;
    let yf = f32::from(g) / 127.5 - 1.0;
    // sqrt of the non-negative radicand, then clamp to 1 (matches GetZNormal's
    // `sqrt(max(0, ..))` followed by `min(1)`).
    let z = (1.0 - xf * xf - yf * yf).max(0.0).sqrt().min(1.0);
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "z ∈ [0,1] → z*127 + 128 ∈ [128,255], always a valid u8"
    )]
    let byte = (z * 127.0 + 128.0) as u8;
    byte
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
    use proptest::prelude::*;

    #[test]
    fn from_name_resolves_the_decodable_formats() {
        assert_eq!(PixelFormat::from_name("PF_R8G8B8A8"), PixelFormat::R8G8B8A8);
        assert_eq!(PixelFormat::from_name("PF_B8G8R8A8"), PixelFormat::B8G8R8A8);
        assert_eq!(PixelFormat::from_name("PF_G8"), PixelFormat::G8);
        assert_eq!(PixelFormat::from_name("PF_G16"), PixelFormat::G16);
        // BC family (3e-5): the wire names are the DXT/BC aliases.
        assert_eq!(PixelFormat::from_name("PF_DXT1"), PixelFormat::Bc1);
        assert_eq!(PixelFormat::from_name("PF_DXT3"), PixelFormat::Bc2);
        assert_eq!(PixelFormat::from_name("PF_DXT5"), PixelFormat::Bc3);
        assert_eq!(PixelFormat::from_name("PF_BC4"), PixelFormat::Bc4);
        assert_eq!(PixelFormat::from_name("PF_BC5"), PixelFormat::Bc5);
        assert_eq!(PixelFormat::from_name("PF_BC7"), PixelFormat::Bc7);
        // ASTC + ETC mobile families (3e-6).
        assert_eq!(PixelFormat::from_name("PF_ASTC_4x4"), PixelFormat::Astc4x4);
        assert_eq!(PixelFormat::from_name("PF_ASTC_6x6"), PixelFormat::Astc6x6);
        assert_eq!(PixelFormat::from_name("PF_ASTC_8x8"), PixelFormat::Astc8x8);
        assert_eq!(
            PixelFormat::from_name("PF_ASTC_10x10"),
            PixelFormat::Astc10x10
        );
        assert_eq!(
            PixelFormat::from_name("PF_ASTC_12x12"),
            PixelFormat::Astc12x12
        );
        assert_eq!(PixelFormat::from_name("PF_ETC1"), PixelFormat::Etc1);
        assert_eq!(PixelFormat::from_name("PF_ETC2_RGB"), PixelFormat::Etc2Rgb);
        assert_eq!(
            PixelFormat::from_name("PF_ETC2_RGBA"),
            PixelFormat::Etc2Rgba
        );
    }

    /// Every decodable format's `label()` is the inverse of `from_name`, so a
    /// `PixelFormatDecodeFailed` reports the right wire name. Pins every
    /// `label()` arm against a mutation.
    #[test]
    fn label_round_trips_through_from_name() {
        for fmt in [
            PixelFormat::R8G8B8A8,
            PixelFormat::B8G8R8A8,
            PixelFormat::G8,
            PixelFormat::G16,
            PixelFormat::Bc1,
            PixelFormat::Bc2,
            PixelFormat::Bc3,
            PixelFormat::Bc4,
            PixelFormat::Bc5,
            PixelFormat::Bc7,
            PixelFormat::Astc4x4,
            PixelFormat::Astc6x6,
            PixelFormat::Astc8x8,
            PixelFormat::Astc10x10,
            PixelFormat::Astc12x12,
            PixelFormat::Etc1,
            PixelFormat::Etc2Rgb,
            PixelFormat::Etc2Rgba,
        ] {
            assert_eq!(PixelFormat::from_name(fmt.label()), fmt, "{fmt:?}");
        }
    }

    #[test]
    fn from_name_unrecognized_is_unknown_with_the_name() {
        // PF_BC6H is an HDR format not handled until 3e-7.
        assert_eq!(
            PixelFormat::from_name("PF_BC6H"),
            PixelFormat::Unknown("PF_BC6H".to_string())
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
        let decoded = decode_mip(&PixelFormat::R8G8B8A8, &[10, 20, 30, 40], 1, 1, false, "t")
            .expect("decode");
        assert_eq!(decoded.width, 1);
        assert_eq!(decoded.height, 1);
        assert_eq!(decoded.rgba, vec![10, 20, 30, 40]);
    }

    #[test]
    fn b8g8r8a8_swizzles_the_b_and_r_channels() {
        // DISTINCT per channel (B=1, G=2, R=3, A=4) so a reversed swizzle is
        // caught — a gray pixel (B=G=R) would pass either way.
        let decoded =
            decode_mip(&PixelFormat::B8G8R8A8, &[1, 2, 3, 4], 1, 1, false, "t").expect("decode");
        // RGBA: R=3 (the R byte), G=2, B=1 (the B byte), A=4.
        assert_eq!(decoded.rgba, vec![3, 2, 1, 4]);
    }

    #[test]
    fn g8_replicates_grayscale_with_opaque_alpha() {
        let decoded = decode_mip(&PixelFormat::G8, &[42], 1, 1, false, "t").expect("decode");
        assert_eq!(decoded.rgba, vec![42, 42, 42, 0xFF]);
    }

    #[test]
    fn g16_takes_the_high_byte_with_opaque_alpha() {
        // LE u16 = 0x1234 → high byte 0x12 is the 8-bit gray value.
        let decoded =
            decode_mip(&PixelFormat::G16, &[0x34, 0x12], 1, 1, false, "t").expect("decode");
        assert_eq!(decoded.rgba, vec![0x12, 0x12, 0x12, 0xFF]);
    }

    #[test]
    fn multi_pixel_decode_covers_every_pixel_in_order() {
        // 2×1 B8G8R8A8 → both pixels swizzled, in order.
        let encoded = [1, 2, 3, 4, 5, 6, 7, 8]; // px0 BGRA=(1,2,3,4), px1=(5,6,7,8)
        let decoded =
            decode_mip(&PixelFormat::B8G8R8A8, &encoded, 2, 1, false, "t").expect("decode");
        assert_eq!(decoded.rgba, vec![3, 2, 1, 4, 7, 6, 5, 8]);
    }

    #[test]
    fn unknown_format_is_rejected_with_its_name() {
        match decode_mip(
            &PixelFormat::from_name("PF_BC6H"),
            &[0; 16],
            4,
            4,
            false,
            "t",
        ) {
            Err(PaksmithError::AssetParse {
                fault: AssetParseFault::UnsupportedPixelFormat { name },
                ..
            }) => assert_eq!(name, "PF_BC6H"),
            other => panic!("expected UnsupportedPixelFormat, got {other:?}"),
        }
    }

    #[test]
    fn encoded_size_mismatch_is_rejected() {
        // 2×2 R8G8B8A8 expects 16 bytes; supply 15.
        match decode_mip(&PixelFormat::R8G8B8A8, &[0u8; 15], 2, 2, false, "t") {
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
        match decode_mip(&PixelFormat::R8G8B8A8, &[], 20_000, 20_000, false, "t") {
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
        match decode_mip(&PixelFormat::R8G8B8A8, &[], 16384, 16384, false, "t") {
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
        match decode_mip(&PixelFormat::R8G8B8A8, &[], u32::MAX, u32::MAX, false, "t") {
            Err(PaksmithError::AssetParse {
                fault: AssetParseFault::DecodedTextureBytesExceeded { bytes, .. },
                ..
            }) => assert_eq!(bytes, u64::MAX),
            other => panic!("expected DecodedTextureBytesExceeded(overflow), got {other:?}"),
        }
    }

    // ===== BC family (3e-5) =====

    /// A solid-color BC1 block: `color0` (RGB565, LE) repeated, `color1` = 0,
    /// indices all 0 → every pixel decodes to `color0` (opaque 4-color mode,
    /// `color0 > color1`). The 8-byte block tiles a single 4×4.
    fn bc1_solid_block(color0_le: [u8; 2]) -> [u8; 8] {
        [color0_le[0], color0_le[1], 0x00, 0x00, 0, 0, 0, 0]
    }

    #[test]
    fn bc1_decodes_in_rgba_channel_order_not_bgra() {
        // Empirical channel-order check (the plan requires verifying bcdec_rs's
        // order before relying on it): solid red (RGB565 0xF800) → (255,0,0,255),
        // solid blue (0x001F) → (0,0,255,255). Red in byte 0 + blue in byte 2
        // proves RGBA output, not BGRA.
        let red = bc1_solid_block([0x00, 0xF8]);
        let decoded = decode_mip(&PixelFormat::Bc1, &red, 4, 4, false, "t").expect("decode");
        assert_eq!(&decoded.rgba[0..4], &[255, 0, 0, 255]);
        assert!(
            decoded
                .rgba
                .chunks_exact(4)
                .all(|px| px == [255, 0, 0, 255])
        );

        let blue = bc1_solid_block([0x1F, 0x00]);
        let decoded = decode_mip(&PixelFormat::Bc1, &blue, 4, 4, false, "t").expect("decode");
        assert_eq!(&decoded.rgba[0..4], &[0, 0, 255, 255]);
    }

    #[test]
    fn bc1_per_row_pattern_pins_tile_strides() {
        // color0 = red, color1 = blue; the index bytes select color0 for rows
        // 0 & 2 and color1 for rows 1 & 3. A spatially-VARYING tile pins the
        // block→image row strides (`BC_TILE_PITCH`, `row * BC_TILE_PITCH`) that
        // a solid-color block can't distinguish — a wrong stride reads the
        // wrong tile row and the per-row colors no longer alternate.
        // Index bytes (S3TC, row-major, pixel 0 in the low bits): 0x00 = row of
        // index 0 (color0), 0x55 = 0b01010101 = row of index 1 (color1).
        let block = [0x00, 0xF8, 0x1F, 0x00, 0x00, 0x55, 0x00, 0x55];
        let decoded = decode_mip(&PixelFormat::Bc1, &block, 4, 4, false, "t").expect("decode");
        let red = [255, 0, 0, 255];
        let blue = [0, 0, 255, 255];
        // 4-wide image → each `chunks_exact(16)` is one pixel row of 4 RGBA px.
        for (y, row) in decoded.rgba.chunks_exact(4 * 4).enumerate() {
            let expected = if y % 2 == 0 { red } else { blue };
            assert!(
                row.chunks_exact(4).all(|px| px == expected),
                "row {y} should be {expected:?}, got {row:?}"
            );
        }
    }

    #[test]
    fn bc1_edge_mip_clamps_overhanging_blocks() {
        // 5×5 → ceil(5/4)=2 blocks/axis = 4 blocks (32 bytes). The right-column
        // and bottom-row blocks overhang the image and must be clamped; all four
        // are solid red, so every one of the 25 pixels must be red.
        let red = bc1_solid_block([0x00, 0xF8]);
        let encoded: Vec<u8> = red.iter().copied().cycle().take(4 * 8).collect();
        let decoded = decode_mip(&PixelFormat::Bc1, &encoded, 5, 5, false, "t").expect("decode");
        assert_eq!(decoded.rgba.len(), 5 * 5 * 4);
        assert!(
            decoded
                .rgba
                .chunks_exact(4)
                .all(|px| px == [255, 0, 0, 255])
        );
    }

    #[test]
    fn bc4_expands_single_channel_to_grayscale() {
        // r0 == r1 == 200 → every pixel's lone channel is 200 (mode-independent);
        // expanded to grayscale (200,200,200,255), matching CUE4Parse's BC4.
        let block = [200, 200, 0, 0, 0, 0, 0, 0];
        let decoded = decode_mip(&PixelFormat::Bc4, &block, 4, 4, false, "t").expect("decode");
        assert!(
            decoded
                .rgba
                .chunks_exact(4)
                .all(|px| px == [200, 200, 200, 255])
        );
    }

    #[test]
    fn bc5_places_rg_and_reconstructs_normal_z() {
        // Red sub-block 100, green sub-block 200 (mode-independent constants) →
        // R=100, G=200, B=reconstruct_z_normal(100,200), A=255. Distinct R≠G
        // proves the channel placement (R = first sub-block, G = second).
        let block = [100, 100, 0, 0, 0, 0, 0, 0, 200, 200, 0, 0, 0, 0, 0, 0];
        let decoded = decode_mip(&PixelFormat::Bc5, &block, 4, 4, false, "t").expect("decode");
        let z = reconstruct_z_normal(100, 200);
        assert_eq!(z, 228);
        assert!(
            decoded
                .rgba
                .chunks_exact(4)
                .all(|px| px == [100, 200, z, 255])
        );
    }

    #[test]
    fn bc2_decodes_explicit_alpha_plus_color_block() {
        // BC2 = [8B explicit 4-bit alpha][8B BC1-style color block]. Opaque
        // alpha (all `0xF` nibbles) + a solid-red color block → every pixel
        // (255,0,0,255). Value-pinned so a no-op decoder body is caught.
        let mut block = [0xFFu8; 16];
        block[8..].copy_from_slice(&bc1_solid_block([0x00, 0xF8]));
        let decoded = decode_mip(&PixelFormat::Bc2, &block, 4, 4, false, "t").expect("decode");
        assert!(
            decoded
                .rgba
                .chunks_exact(4)
                .all(|px| px == [255, 0, 0, 255])
        );
    }

    #[test]
    fn bc3_decodes_interpolated_alpha_plus_color_block() {
        // BC3 = [2B alpha endpoints + 6B alpha indices][8B BC1-style color].
        // alpha0 == alpha1 == 255 → opaque; solid-red color → (255,0,0,255).
        let mut block = [0u8; 16];
        block[0] = 255; // alpha0
        block[1] = 255; // alpha1
        block[8..].copy_from_slice(&bc1_solid_block([0x00, 0xF8]));
        let decoded = decode_mip(&PixelFormat::Bc3, &block, 4, 4, false, "t").expect("decode");
        assert!(
            decoded
                .rgba
                .chunks_exact(4)
                .all(|px| px == [255, 0, 0, 255])
        );
    }

    #[test]
    fn bc7_decodes_a_nonzero_block() {
        // Hand-packing BC7 mode bits isn't worth it; an all-`0xFF` block is
        // mode 0 and decodes to a non-zero color. "Not all zero" + full length
        // kills a no-op decoder body (wire-exact BC7 values are a 3e-8 job).
        let decoded =
            decode_mip(&PixelFormat::Bc7, &[0xFFu8; 16], 4, 4, false, "t").expect("decode");
        assert_eq!(decoded.rgba.len(), 4 * 4 * 4);
        assert!(
            decoded.rgba.iter().any(|&b| b != 0),
            "BC7 decode produced all-zero output"
        );
    }

    #[test]
    fn reconstruct_z_normal_matches_getznormal() {
        // x = ±1 (r = 255 or 0) drives the radicand ≤ 0 → z = 0 → byte 128.
        assert_eq!(reconstruct_z_normal(255, 128), 128);
        assert_eq!(reconstruct_z_normal(0, 0), 128);
        // Near-flat normal (r=g=128 ≈ centre) → z ≈ 1 → byte 254.
        assert_eq!(reconstruct_z_normal(128, 128), 254);
        // Off-centre pin (also asserted by the BC5 test).
        assert_eq!(reconstruct_z_normal(100, 200), 228);
    }

    #[test]
    fn block_encoded_len_uses_ceil_div_block_count() {
        // BC / ETC (4×4 blocks).
        assert_eq!(block_encoded_len(4, 4, 4, 4, 8), Some(8)); // 1×1 block × 8
        assert_eq!(block_encoded_len(8, 8, 4, 4, 16), Some(64)); // 2×2 × 16
        assert_eq!(block_encoded_len(5, 5, 4, 4, 8), Some(32)); // ceil(5/4)=2 → 2×2 × 8
        assert_eq!(block_encoded_len(1, 1, 4, 4, 8), Some(8)); // ceil(1/4)=1 → 1×1 × 8
        // ASTC variable block dims (16-byte blocks).
        assert_eq!(block_encoded_len(8, 8, 8, 8, 16), Some(16)); // 1×1 × 16
        assert_eq!(block_encoded_len(9, 9, 8, 8, 16), Some(64)); // ceil(9/8)=2 → 2×2 × 16
        assert_eq!(block_encoded_len(12, 6, 6, 6, 16), Some(32)); // 2×1 × 16
        assert_eq!(block_encoded_len(u32::MAX, u32::MAX, 4, 4, 16), None); // overflow → None
    }

    #[test]
    fn bc_encoded_size_mismatch_is_rejected() {
        // BC1 4×4 needs exactly 8 bytes; supply 7.
        match decode_mip(&PixelFormat::Bc1, &[0u8; 7], 4, 4, false, "t") {
            Err(PaksmithError::AssetParse {
                fault: AssetParseFault::TextureMipSizeMismatch { expected, actual },
                ..
            }) => {
                assert_eq!(expected, 8);
                assert_eq!(actual, 7);
            }
            other => panic!("expected TextureMipSizeMismatch, got {other:?}"),
        }
    }

    /// Build a 16-byte ASTC LDR void-extent (constant-color) block decoding to
    /// the given RGBA8 color, matching `texture2ddecoder`'s detection
    /// (`buf[0]==0xFC && buf[1]&1==1 && buf[1]&2==0` → `color(buf[9], buf[11],
    /// buf[13], buf[15])` — it reads the high byte of each 16-bit UNORM).
    fn astc_void_extent_block(r: u8, g: u8, b: u8, a: u8) -> [u8; 16] {
        let mut block = [0u8; 16];
        block[0] = 0xFC;
        // void-extent marker (bit0 = 1), LDR (bit1 = 0), and the two reserved
        // bits 10/11 (bits 2-3 of byte 1) set to 1 as the ASTC spec requires.
        block[1] = 0x0D;
        // 16-bit UNORM per channel; both bytes = the value so the high byte reads it.
        (block[8], block[9]) = (r, r);
        (block[10], block[11]) = (g, g);
        (block[12], block[13]) = (b, b);
        (block[14], block[15]) = (a, a);
        block
    }

    #[test]
    fn astc_void_extent_decodes_in_rgba_channel_order() {
        // Empirical channel-order check for `texture2ddecoder`'s BGRA `u32`
        // packing → RGBA8 swap: a red constant-color block → all (255,0,0,255),
        // blue → (0,0,255,255). Red in byte 0 + blue in byte 2 proves RGBA.
        let red = astc_void_extent_block(255, 0, 0, 255);
        let decoded = decode_mip(&PixelFormat::Astc4x4, &red, 4, 4, false, "t").expect("decode");
        assert!(
            decoded
                .rgba
                .chunks_exact(4)
                .all(|px| px == [255, 0, 0, 255])
        );

        let blue = astc_void_extent_block(0, 0, 255, 255);
        let decoded = decode_mip(&PixelFormat::Astc4x4, &blue, 4, 4, false, "t").expect("decode");
        assert!(
            decoded
                .rgba
                .chunks_exact(4)
                .all(|px| px == [0, 0, 255, 255])
        );
    }

    #[test]
    fn astc_normal_map_reconstructs_blue_z_when_flagged() {
        // A red block (R=255, G=0). Without the flag, blue passes through as 0;
        // with `is_normal_map`, blue = reconstruct_z_normal(255, 0) = 128 (the
        // x=1 boundary). Distinct, so the conditional restore is pinned.
        let red = astc_void_extent_block(255, 0, 0, 255);
        let plain = decode_mip(&PixelFormat::Astc4x4, &red, 4, 4, false, "t").expect("decode");
        assert!(plain.rgba.chunks_exact(4).all(|px| px == [255, 0, 0, 255]));

        assert_eq!(reconstruct_z_normal(255, 0), 128);
        let normal = decode_mip(&PixelFormat::Astc4x4, &red, 4, 4, true, "t").expect("decode");
        assert!(
            normal
                .rgba
                .chunks_exact(4)
                .all(|px| px == [255, 0, 128, 255])
        );
    }

    #[test]
    fn astc_each_block_size_decodes_one_void_extent() {
        // Each ASTC format decoded at exactly its block dimensions = a single
        // 16-byte void-extent block → the whole block_dim² image is red. Pins
        // each format's block dims (the `Codec::Block` size formula) and that
        // its decoder routes to a `texture2ddecoder` fn whose block grid needs
        // *no more* data than supplied. NOTE: a void-extent block fills
        // regardless of block size, so this does NOT distinguish routing to a
        // *same-or-larger* block fn (e.g. 6x6 → 8x8 both need 1 block at 6×6) —
        // that exact format→fn pairing is verified by 3e-8 cross-validation
        // against real assets (hand-built non-void blocks aren't practical).
        let red = astc_void_extent_block(255, 0, 0, 255);
        for (fmt, dim) in [
            (PixelFormat::Astc4x4, 4u32),
            (PixelFormat::Astc6x6, 6),
            (PixelFormat::Astc8x8, 8),
            (PixelFormat::Astc10x10, 10),
            (PixelFormat::Astc12x12, 12),
        ] {
            let decoded = decode_mip(&fmt, &red, dim, dim, false, "t").expect("decode");
            assert_eq!(decoded.rgba.len(), (dim as usize) * (dim as usize) * 4);
            assert!(
                decoded
                    .rgba
                    .chunks_exact(4)
                    .all(|px| px == [255, 0, 0, 255]),
                "{fmt:?}"
            );
        }
    }

    #[test]
    fn etc_formats_validate_block_size_and_decode() {
        // ETC1 / ETC2_RGB = 8-byte blocks, ETC2_RGBA = 16-byte, all 4×4.
        // Value-pinning ETC output by hand isn't practical (3e-8 cross-val
        // covers values); pin the dispatch + block size: a correctly-sized
        // block decodes to a full buffer.
        for (fmt, bpb) in [
            (PixelFormat::Etc1, ETC_RGB_BLOCK_BYTES),
            (PixelFormat::Etc2Rgb, ETC_RGB_BLOCK_BYTES),
            (PixelFormat::Etc2Rgba, ETC_RGBA_BLOCK_BYTES),
        ] {
            let decoded =
                decode_mip(&fmt, &vec![0u8; bpb], 4, 4, false, "t").expect("zero block decodes");
            assert_eq!(decoded.rgba.len(), 4 * 4 * 4);
            // A real decode writes non-zero bytes (opaque alpha / a non-black
            // base color); a no-op'd decoder would leave the pre-zeroed buffer
            // all-zero. Asserting "not all zero" kills that mutant.
            assert!(
                decoded.rgba.iter().any(|&b| b != 0),
                "{fmt:?} decoded to all-zero (no-op?)"
            );
        }
        // A wrong size (ETC2_RGB needs 8, supply 16) → size mismatch.
        assert!(matches!(
            decode_mip(&PixelFormat::Etc2Rgb, &[0u8; 16], 4, 4, false, "t"),
            Err(PaksmithError::AssetParse {
                fault: AssetParseFault::TextureMipSizeMismatch { .. },
                ..
            })
        ));
    }

    #[test]
    fn astc_decoder_panics_are_contained() {
        // `texture2ddecoder` panics internally on malformed ASTC blocks;
        // `decode_mip` must contain it (catch_unwind) and return a typed
        // `PixelFormatDecodeFailed`, never crash — paksmith decodes untrusted
        // bytes. Silence the (contained) panic output for this garbage input.
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        // All-0xFF is not a void-extent and drives an invalid-mode panic.
        let result = decode_mip(&PixelFormat::Astc4x4, &[0xFFu8; 16], 4, 4, false, "t");
        std::panic::set_hook(prev);
        match result {
            Err(PaksmithError::AssetParse {
                fault: AssetParseFault::PixelFormatDecodeFailed { format, .. },
                ..
            }) => assert_eq!(format, "PF_ASTC_4x4"),
            other => panic!("expected contained PixelFormatDecodeFailed, got {other:?}"),
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// Untrusted-input hardening for the BC decoders: arbitrary
        /// correctly-sized encoded bytes never panic (`bcdec_rs` is bounded
        /// purely by the validated length) and always yield a full-size RGBA8
        /// buffer. Covers edge mips (5×5, 7×4, 9×1) and the 1×1 sub-block case.
        /// (ASTC can't share this "always Ok" assert — `texture2ddecoder` *can*
        /// panic on garbage; that's covered by the deterministic
        /// `astc_decoder_panics_are_contained` test. ETC routes through the
        /// same `decode_t2d`/`catch_unwind` path.)
        #[test]
        fn bc_decoders_never_panic_on_arbitrary_exact_length_blocks(
            pool in prop::collection::vec(any::<u8>(), 4096),
        ) {
            // (format, bytes_per_block, width, height)
            let cases: &[(PixelFormat, usize, u32, u32)] = &[
                (PixelFormat::Bc1, BC1_BLOCK_BYTES, 5, 5),
                (PixelFormat::Bc1, BC1_BLOCK_BYTES, 1, 1),
                (PixelFormat::Bc2, BC2_BLOCK_BYTES, 5, 3),
                (PixelFormat::Bc3, BC3_BLOCK_BYTES, 7, 4),
                (PixelFormat::Bc4, BC4_BLOCK_BYTES, 5, 5),
                (PixelFormat::Bc5, BC5_BLOCK_BYTES, 4, 6),
                (PixelFormat::Bc7, BC7_BLOCK_BYTES, 9, 1),
            ];
            for (fmt, bpb, w, h) in cases {
                let need_u64 = block_encoded_len(*w, *h, 4, 4, *bpb).expect("len fits u64");
                let need = usize::try_from(need_u64).expect("small fixture len fits usize");
                let decoded = decode_mip(fmt, &pool[..need], *w, *h, false, "t")
                    .expect("exact-length input must decode");
                prop_assert_eq!(decoded.rgba.len(), (*w as usize) * (*h as usize) * 4);
            }
        }
    }
}
