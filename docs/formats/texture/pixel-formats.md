# Pixel formats (`EPixelFormat`)

> UE's enum of GPU pixel layouts — every variant a `Texture2D` /
> `TextureCube` / `Texture2DArray` etc. might use on disk. The
> `string PixelFormat` field in `FTexturePlatformData` names
> one of these variants; the decoded variant drives mip-byte
> interpretation.

## Overview

`EPixelFormat` is UE's tagged catalog of pixel layouts that the GPU
sampler hardware can address natively. Each variant is a small
enum-like constant with a known block size (in pixels), bytes per
block, and decoding rules.

In cooked content, the dominant formats per platform are:

- **Desktop**: `PF_DXT1` (legacy diffuse), `PF_DXT5` (alpha-diffuse),
  `PF_BC4` (single-channel — height maps, masks), `PF_BC5` (two-
  channel — normal maps), `PF_BC6H` (HDR), `PF_BC7` (high-quality
  RGB / RGBA).
- **Mobile (Android, mid-tier)**: `PF_ETC2_RGB`, `PF_ETC2_RGBA`.
- **Mobile (iOS / high-tier Android / desktop fallback)**:
  `PF_ASTC_4x4` through `PF_ASTC_12x12` (variable block-size).
- **Special**: `PF_R8G8B8A8`, `PF_B8G8R8A8`, `PF_FloatRGBA` (HDR),
  `PF_G8` (grayscale), `PF_G16` (16-bit grayscale).

paksmith will document the dominant set first; less-common variants
(PVRTC for older iOS, ETC1 for legacy Android, ASTC HDR variants) get
added when Phase 3+ encounters real-world cooked content using them.

**Status: not yet implemented in paksmith.** The texture exporter
(Phase 3+) will need per-format decoders to produce viewable image
output (PNG/EXR/etc.). This doc enumerates the formats and their
block-level wire shapes; the decoders themselves live with Phase 3+
work.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| All UE4 + UE5 | `EPixelFormat` evolves additively — new variants get appended; existing variants don't change semantics. UE5 added some HDR formats; the dominant cooked-content set is stable across UE 4.21–5.x. | `CUE4Parse/UE4/Assets/Exports/Texture/PixelFormat.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d`[^1] |

UE serializes `EPixelFormat` by name (FString) in
`FTexturePlatformData`, not by discriminant value, so additive
changes don't break older parsers — they just produce "unknown
format" errors for new variants.

## Wire layout

`EPixelFormat` isn't a wire layout by itself — the variant *name*
is on the wire (an `FString` inside `FTexturePlatformData`); the
variant *semantics* are the bytes-per-block and per-block decoding
rules below.

### Block-compressed formats (DXT / BC family)

| Variant | Block size (pixels) | Bytes per block | Encoded channels | Common use |
|---------|---------------------|------------------|-------------------|------------|
| `PF_DXT1` | 4×4 | 8 | RGB (no alpha; 1-bit alpha variant exists) | Diffuse / albedo (legacy). |
| `PF_DXT3` | 4×4 | 16 | RGBA (4-bit explicit alpha) | Rarely used in cooked UE content. |
| `PF_DXT5` | 4×4 | 16 | RGBA (interpolated alpha) | Diffuse-with-alpha. |
| `PF_BC4` | 4×4 | 8 | Single-channel (R only) | Height maps, masks. |
| `PF_BC5` | 4×4 | 16 | Two-channel (RG) | Normal maps (X+Y; Z reconstructed). |
| `PF_BC6H` | 4×4 | 16 | RGB float | HDR. |
| `PF_BC7` | 4×4 | 16 | RGBA | High-quality diffuse / albedo. |

For all BC-family formats, mip dimensions are rounded up to
multiples of 4 (the block size). A 17×17 mip serializes as 5×5
blocks = 25 blocks. The wire-byte size of a mip is
`ceil(width / 4) × ceil(height / 4) × bytes_per_block`.

### ASTC family

| Variant | Block size (pixels) | Bytes per block | Encoded channels | Common use |
|---------|---------------------|------------------|-------------------|------------|
| `PF_ASTC_4x4` | 4×4 | 16 | RGBA | Highest quality. |
| `PF_ASTC_6x6` | 6×6 | 16 | RGBA | Medium quality. |
| `PF_ASTC_8x8` | 8×8 | 16 | RGBA | Lower quality. |
| `PF_ASTC_10x10` | 10×10 | 16 | RGBA | Very compressed. |
| `PF_ASTC_12x12` | 12×12 | 16 | RGBA | Smallest. |

ASTC always uses 16-byte blocks; the block dimension varies. Mip
size: `ceil(width / blockX) × ceil(height / blockY) × 16`.

### ETC2 family

| Variant | Block size (pixels) | Bytes per block | Encoded channels |
|---------|---------------------|------------------|-------------------|
| `PF_ETC2_RGB` | 4×4 | 8 | RGB. |
| `PF_ETC2_RGBA` | 4×4 | 16 | RGBA. |

### Uncompressed formats

| Variant | Bytes per pixel | Channels | Notes |
|---------|------------------|----------|-------|
| `PF_R8G8B8A8` | 4 | RGBA | Linear or sRGB depending on `SRGB` property. |
| `PF_B8G8R8A8` | 4 | BGRA | Direct-X-friendly byte order. |
| `PF_R8` / `PF_G8` | 1 | Grayscale | Mask / height. |
| `PF_R16F` / `PF_G16` | 2 | 16-bit single-channel | Precision-sensitive. |
| `PF_A16B16G16R16` | 8 | RGBA 16-bit | HDR cinematic. |
| `PF_FloatRGB` | 4 | RGB packed float (R11G11B10F). | HDR. |
| `PF_FloatRGBA` | 8 | RGBA half-float (16F × 4 channels) | HDR with alpha. |

For uncompressed formats, mip wire-byte size is
`width × height × bytes_per_pixel`.

### Worked example

`(none yet — no texture fixture)`. When Phase 3 adds fixtures, the
canonical anchor will be the first mip's bytes of a `PF_DXT5`
texture — the first 4×4 block (16 bytes) starts with two
`u8` alpha endpoints followed by 6 bytes of alpha
indices, then two `u16` color endpoints (RGB) followed by 4 bytes
of color indices.

## Variants

The "unknown format" case: when `PixelFormat` resolves to a
variant paksmith doesn't recognize (e.g. a new UE5 HDR format added
after this doc was last updated), the reader should produce
`AssetParseFault::UnsupportedPixelFormat { name }` rather than
attempting to decode bytes per a guessed format. Forward-compatibility
follows the same shape as the `CompressionMethod::UnknownByName`
pattern in [`../compression/oodle.md`](../compression/oodle.md).

## Caps & limits

**Phase 3+ deferred work.** When the texture decoder lands:

- Per-mip byte cap inherited from `MAX_UNCOMPRESSED_ENTRY_BYTES` / `MAX_UEXP_SIZE`.
- A per-decoded-pixel cap on the intermediate RGBA8 buffer. Expansion
  ratios vary by format:
  - **BC/DXT family worst case (DXT1):** 0.5 B/px compressed → 4 B/px
    RGBA8 = 8× expansion. A 1 GiB DXT1 mip becomes an 8 GiB
    intermediate buffer.
  - **ASTC worst case (ASTC_12x12):** 144 px per 16-byte block →
    0.111 B/px → 4 B/px RGBA8 = ~36× expansion. A 1 GiB ASTC_12x12 mip
    becomes ~36 GiB.

  `MAX_DECODED_TEXTURE_BYTES` must be sized against the ASTC worst
  case, not the BC/DXT case — otherwise ASTC_12x12 inputs bypass the
  cap by ~4.5×.

## Verification

- **Fixture:** `(none yet — Phase 3 deliverable)`.
- **Hex anchor commands:** `(none yet — Phase 3 deliverable)`.
- **Cross-validation oracle:** CUE4Parse[^1] for the enum +
  per-format decoders.
- **Known divergences:** none yet.

## Paksmith implementation

**Parser module:** *(not yet implemented — planned under
`crates/paksmith-core/src/asset/exports/texture/pixel_format.rs`)*

**Status:** `not impl`. Even the enum representation isn't
in paksmith's code today — `PixelFormat` is just an `FString`
that the property reader surfaces as a string.

**Phase plan:** `docs/plans/ROADMAP.md` Phase 3 (Export Pipeline).
The Phase 3 plan should:

1. Add a Rust `PixelFormat` enum mirroring CUE4Parse's coverage
   (with `Unknown(String)` for forward-compatibility).
2. Add per-format `decode_block` functions for the dominant set.
3. Add a `MAX_DECODED_TEXTURE_BYTES` cap.

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Exports/Texture/PixelFormat.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` and `CUE4Parse-Conversion/Textures/TextureDecoder.cs` — primary oracle for the enum + decoders.
