//! `EPixelFormat` pixel-format decoders (Phase 3e-4, 3e-5).
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
//!
//! The mobile families (ASTC, ETC2 — 3e-6) and HDR (`PF_BC6H`, FloatRGB/RGBA
//! — 3e-7) land later; until then their names parse to
//! [`PixelFormat::Unknown`] and decode to
//! [`AssetParseFault::UnsupportedPixelFormat`].
//!
//! **Divergence from the CUE4Parse oracle.** CUE4Parse's
//! `TextureDecoder.DecodeBytes` (`cf74fc32`) treats the uncompressed formats
//! as *raw* (bytes + a format tag, channel order resolved by SkiaSharp) and
//! routes BC through its own decoder. paksmith has no image library, so it
//! converts to RGBA8 itself using the standard channel semantics:
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
//!
//! **sRGB.** The decoders do **no** color-space transform — bytes pass
//! through linearly. The `SRGB` tagged property is metadata the
//! `PngHandler` (3e-8) carries into the PNG's own sRGB chunk; the decoded
//! buffer is raw channel values either way.
//!
//! **Verification caveat.** The channel mappings (B/R swizzle, G16 high-byte,
//! the `bcdec_rs` RGBA8 order, the BC4/BC5 expansion) are byte-construction-
//! correct against public conventions (the DDS/DXGI memory-order rule, the
//! `bcdec_rs` docs, CUE4Parse's BC4/BC5 expansion) and pinned by
//! distinct-per-channel tests — but those tests are *synthetic* (built from
//! the same understanding as the decoder), so they prove internal
//! consistency, not wire-fidelity. End-to-end cross-validation against the
//! CUE4Parse oracle on a real cooked asset is a 3e-8 obligation (the
//! `PngHandler` PNG round-trip).
//!
//! The whole module is `dead_code`-allowed: it ships the decode API + the
//! uncompressed and BC decoders, but its first production consumer is 3e-8's
//! `PngHandler` (mirrors how `Package::insert_bulk_records` shipped ahead of
//! its 3e-3b caller). The in-source tests exercise every item.
#![allow(
    dead_code,
    reason = "3e-4/3e-5 ship the decode layer; 3e-8's PngHandler is the first production consumer"
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

/// The subset of `EPixelFormat` paksmith decodes (3e-4 uncompressed + 3e-5
/// BC family), plus [`Unknown`](Self::Unknown) for every other name. Later 3e
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
            other => Self::Unknown(other.to_string()),
        }
    }
}

/// How a format's encoded mip is sized and decoded into RGBA8.
///
/// Splitting the dispatch by codec class keeps each decoder's signature
/// minimal — linear decoders need only `(encoded, rgba)`, while block
/// decoders also need the dimensions to place/clamp 4×4 blocks — and couples
/// each class's encoded-size formula with its decoder so [`decode_mip`]
/// validates the right length before allocating. The [`PixelFormat::Unknown`]
/// no-decoder case returns before a `Codec` is ever built (no panic arm).
enum Codec {
    /// Uncompressed: `encoded.len() == width × height × bytes_per_pixel`.
    Linear {
        bytes_per_pixel: u64,
        decode: fn(encoded: &[u8], rgba: &mut [u8]),
    },
    /// BC block-compressed (4×4 blocks):
    /// `encoded.len() == ceil(w/4) × ceil(h/4) × bytes_per_block`.
    Bc {
        bytes_per_block: usize,
        decode: fn(encoded: &[u8], rgba: &mut [u8], width: u32, height: u32),
    },
}

/// Decode one mip's `encoded` bytes (in `format`, `width × height`) into a
/// tightly-packed RGBA8 [`DecodedTexture`].
///
/// # Errors
/// - [`AssetParseFault::UnsupportedPixelFormat`] if `format` is
///   [`PixelFormat::Unknown`] (no decoder).
/// - [`AssetParseFault::DecodedTextureBytesExceeded`] if `width × height × 4`
///   exceeds [`MAX_DECODED_TEXTURE_BYTES`] or overflows `u64`.
/// - [`AssetParseFault::TextureMipSizeMismatch`] if `encoded.len()` is not
///   exactly the format's encoded size (`pixels × bytes_per_pixel` for the
///   uncompressed formats, `ceil(w/4) × ceil(h/4) × bytes_per_block` for BC).
pub(crate) fn decode_mip(
    format: &PixelFormat,
    encoded: &[u8],
    width: u32,
    height: u32,
    asset_path: &str,
) -> crate::Result<DecodedTexture> {
    // Dispatch: each format yields its codec (encoded-size formula + decoder).
    // `Unknown` (no decoder) returns early here, so neither the size logic nor
    // the decode call below ever sees a decoder-less format (no `unreachable!`).
    let codec = match format {
        PixelFormat::R8G8B8A8 => Codec::Linear {
            bytes_per_pixel: 4,
            // `copy_from_slice` panics on a length mismatch, but the size check
            // below guarantees `encoded.len() == rgba.len()` for this 4-B/px
            // format before `decode` is ever called — keep that check ahead of
            // the call if this is ever reordered.
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
        PixelFormat::Bc1 => Codec::Bc {
            bytes_per_block: BC1_BLOCK_BYTES,
            decode: decode_bc1,
        },
        PixelFormat::Bc2 => Codec::Bc {
            bytes_per_block: BC2_BLOCK_BYTES,
            decode: decode_bc2,
        },
        PixelFormat::Bc3 => Codec::Bc {
            bytes_per_block: BC3_BLOCK_BYTES,
            decode: decode_bc3,
        },
        PixelFormat::Bc4 => Codec::Bc {
            bytes_per_block: BC4_BLOCK_BYTES,
            decode: decode_bc4,
        },
        PixelFormat::Bc5 => Codec::Bc {
            bytes_per_block: BC5_BLOCK_BYTES,
            decode: decode_bc5,
        },
        PixelFormat::Bc7 => Codec::Bc {
            bytes_per_block: BC7_BLOCK_BYTES,
            decode: decode_bc7,
        },
        PixelFormat::Unknown(name) => {
            return Err(fault(
                asset_path,
                AssetParseFault::UnsupportedPixelFormat { name: name.clone() },
            ));
        }
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
        Codec::Bc {
            bytes_per_block, ..
        } => bc_encoded_len(width, height, *bytes_per_block),
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
        Codec::Bc { decode, .. } => decode(encoded, &mut rgba, width, height),
    }
    Ok(DecodedTexture {
        width,
        height,
        rgba,
    })
}

/// Encoded byte length of a BC mip: `ceil(w/4) × ceil(h/4) × bytes_per_block`,
/// computed checked so an overflow surfaces as a size mismatch (never a
/// panic). `None` on `u64` overflow.
fn bc_encoded_len(width: u32, height: u32, bytes_per_block: usize) -> Option<u64> {
    // Widen to u64 first so the ceil-div uses the (lossless) usize→u64 block
    // dim and the products are overflow-checked in u64.
    let block_dim = BC_BLOCK_DIM as u64;
    let blocks_x = u64::from(width).div_ceil(block_dim);
    let blocks_y = u64::from(height).div_ceil(block_dim);
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
// each format's block size, referenced by both the dispatch's `Codec::Bc`
// arm (which feeds `bc_encoded_len` validation) and the matching `decode_bcN`
// wrapper (which feeds `chunks_exact`). Sharing one constant per format means
// the validation stride and the decode stride cannot drift.
const BC1_BLOCK_BYTES: usize = 8;
const BC2_BLOCK_BYTES: usize = 16;
const BC3_BLOCK_BYTES: usize = 16;
const BC4_BLOCK_BYTES: usize = 8;
const BC5_BLOCK_BYTES: usize = 16;
const BC7_BLOCK_BYTES: usize = 16;

/// Decode a BC mip block-by-block. `decode_tile` turns one `block` of encoded
/// bytes into a 4×4 RGBA8 `tile`; this loop copies each tile's in-bounds
/// region into `rgba`, clamping blocks that overhang the right/bottom edge.
///
/// `encoded` is pre-validated by [`decode_mip`] to hold exactly
/// `ceil(w/4) × ceil(h/4)` whole blocks, and `rgba` to be `w × h × 4` bytes,
/// so every slice index below is in bounds.
fn decode_bc_mip(
    encoded: &[u8],
    rgba: &mut [u8],
    width: u32,
    height: u32,
    bytes_per_block: usize,
    decode_tile: impl Fn(&[u8], &mut [u8; BC_TILE_BYTES]),
) {
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
}

/// `PF_DXT1` (BC1) → RGBA8 (8-byte blocks).
fn decode_bc1(encoded: &[u8], rgba: &mut [u8], width: u32, height: u32) {
    decode_bc_mip(
        encoded,
        rgba,
        width,
        height,
        BC1_BLOCK_BYTES,
        |block, tile| {
            bcdec_rs::bc1(block, tile, BC_TILE_PITCH);
        },
    );
}

/// `PF_DXT3` (BC2) → RGBA8 (16-byte blocks).
fn decode_bc2(encoded: &[u8], rgba: &mut [u8], width: u32, height: u32) {
    decode_bc_mip(
        encoded,
        rgba,
        width,
        height,
        BC2_BLOCK_BYTES,
        |block, tile| {
            bcdec_rs::bc2(block, tile, BC_TILE_PITCH);
        },
    );
}

/// `PF_DXT5` (BC3) → RGBA8 (16-byte blocks).
fn decode_bc3(encoded: &[u8], rgba: &mut [u8], width: u32, height: u32) {
    decode_bc_mip(
        encoded,
        rgba,
        width,
        height,
        BC3_BLOCK_BYTES,
        |block, tile| {
            bcdec_rs::bc3(block, tile, BC_TILE_PITCH);
        },
    );
}

/// `PF_BC4` (single channel, 8-byte blocks) → grayscale RGBA8 (R=G=B, opaque),
/// matching CUE4Parse's `BCDecoder.BC4`.
fn decode_bc4(encoded: &[u8], rgba: &mut [u8], width: u32, height: u32) {
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
    );
}

/// `PF_BC5` (two channels, 16-byte blocks) → normal-map RGBA8: R, G passthrough
/// with the blue/Z channel reconstructed (see [`reconstruct_z_normal`]). This
/// matches the combined effect of CUE4Parse's `TextureDecoder` BC5 path:
/// `BCDecoder.BC5` decodes R/G (and leaves blue at `0xFF`), then `TextureDecoder`
/// overwrites blue with `BCDecoder.GetZNormal(R, G)` — paksmith does both in one
/// pass.
fn decode_bc5(encoded: &[u8], rgba: &mut [u8], width: u32, height: u32) {
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
    );
}

/// `PF_BC7` → RGBA8 (16-byte blocks).
fn decode_bc7(encoded: &[u8], rgba: &mut [u8], width: u32, height: u32) {
    decode_bc_mip(
        encoded,
        rgba,
        width,
        height,
        BC7_BLOCK_BYTES,
        |block, tile| {
            bcdec_rs::bc7(block, tile, BC_TILE_PITCH);
        },
    );
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
    }

    #[test]
    fn from_name_unrecognized_is_unknown_with_the_name() {
        // PF_ASTC_4x4 is a mobile format not handled until 3e-6.
        assert_eq!(
            PixelFormat::from_name("PF_ASTC_4x4"),
            PixelFormat::Unknown("PF_ASTC_4x4".to_string())
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
        match decode_mip(&PixelFormat::from_name("PF_ASTC_4x4"), &[0; 16], 4, 4, "t") {
            Err(PaksmithError::AssetParse {
                fault: AssetParseFault::UnsupportedPixelFormat { name },
                ..
            }) => assert_eq!(name, "PF_ASTC_4x4"),
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
        let decoded = decode_mip(&PixelFormat::Bc1, &red, 4, 4, "t").expect("decode");
        assert_eq!(&decoded.rgba[0..4], &[255, 0, 0, 255]);
        assert!(
            decoded
                .rgba
                .chunks_exact(4)
                .all(|px| px == [255, 0, 0, 255])
        );

        let blue = bc1_solid_block([0x1F, 0x00]);
        let decoded = decode_mip(&PixelFormat::Bc1, &blue, 4, 4, "t").expect("decode");
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
        let decoded = decode_mip(&PixelFormat::Bc1, &block, 4, 4, "t").expect("decode");
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
        let decoded = decode_mip(&PixelFormat::Bc1, &encoded, 5, 5, "t").expect("decode");
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
        let decoded = decode_mip(&PixelFormat::Bc4, &block, 4, 4, "t").expect("decode");
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
        let decoded = decode_mip(&PixelFormat::Bc5, &block, 4, 4, "t").expect("decode");
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
        let decoded = decode_mip(&PixelFormat::Bc2, &block, 4, 4, "t").expect("decode");
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
        let decoded = decode_mip(&PixelFormat::Bc3, &block, 4, 4, "t").expect("decode");
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
        let decoded = decode_mip(&PixelFormat::Bc7, &[0xFFu8; 16], 4, 4, "t").expect("decode");
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
    fn bc_encoded_len_uses_ceil_div_block_count() {
        assert_eq!(bc_encoded_len(4, 4, 8), Some(8)); // 1×1 block × 8
        assert_eq!(bc_encoded_len(8, 8, 16), Some(64)); // 2×2 × 16
        assert_eq!(bc_encoded_len(5, 5, 8), Some(32)); // ceil(5/4)=2 → 2×2 × 8
        assert_eq!(bc_encoded_len(1, 1, 8), Some(8)); // ceil(1/4)=1 → 1×1 × 8
        assert_eq!(bc_encoded_len(u32::MAX, u32::MAX, 16), None); // overflow → None
    }

    #[test]
    fn bc_encoded_size_mismatch_is_rejected() {
        // BC1 4×4 needs exactly 8 bytes; supply 7.
        match decode_mip(&PixelFormat::Bc1, &[0u8; 7], 4, 4, "t") {
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

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// Untrusted-input hardening: arbitrary correctly-sized encoded bytes
        /// must never panic any BC decoder (the block loop + `bcdec_rs` are
        /// bounded purely by the validated length) and must always yield a
        /// full-size RGBA8 buffer. Covers edge mips (5×5, 7×4, 9×1) and the
        /// 1×1 sub-block case.
        #[test]
        fn bc_decoders_never_panic_on_arbitrary_exact_length_blocks(
            pool in prop::collection::vec(any::<u8>(), 4096),
        ) {
            let cases: &[(PixelFormat, usize, u32, u32)] = &[
                (PixelFormat::Bc1, BC1_BLOCK_BYTES, 4, 4),
                (PixelFormat::Bc1, BC1_BLOCK_BYTES, 5, 5),
                (PixelFormat::Bc1, BC1_BLOCK_BYTES, 1, 1),
                (PixelFormat::Bc2, BC2_BLOCK_BYTES, 5, 3),
                (PixelFormat::Bc3, BC3_BLOCK_BYTES, 7, 4),
                (PixelFormat::Bc4, BC4_BLOCK_BYTES, 5, 5),
                (PixelFormat::Bc5, BC5_BLOCK_BYTES, 4, 6),
                (PixelFormat::Bc7, BC7_BLOCK_BYTES, 9, 1),
            ];
            for (fmt, bpb, w, h) in cases {
                let need_u64 = bc_encoded_len(*w, *h, *bpb).expect("len fits u64");
                let need = usize::try_from(need_u64).expect("small fixture len fits usize");
                let decoded = decode_mip(fmt, &pool[..need], *w, *h, "t")
                    .expect("exact-length input must decode");
                prop_assert_eq!(decoded.rgba.len(), (*w as usize) * (*h as usize) * 4);
            }
        }
    }
}
