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

**Document status: complete.** Wire format documented in full for
the dominant variant set across the BC/DXT, ASTC, ETC2, and
uncompressed families — block size, bytes per block, channel
layout, and mip-byte-size formula for each. The full `EPixelFormat`
enum has ~80 variants (CUE4Parse's `PixelFormat.cs` is the
exhaustive list); paksmith documents the variants commonly seen in
cooked shipping content (the lists below are the practical superset
a parser needs to decode any shipping UE texture). Less-common
variants (legacy PVRTC, ETC1, sparse ASTC HDR variants) get added
when Phase 3+ encounters real-world cooked content using them.

**Paksmith parser status: `not impl`.** The texture exporter
(Phase 3+) will need per-format decoders to produce viewable image
output (PNG/EXR/etc.). Today `PixelFormat` is just an `FString` the
property reader surfaces as a string; no decoders exist.

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

### Worked example — `PF_DXT5` 4×4 block (16 bytes)

A `PF_DXT5` (BC3) block is the canonical illustrative example
because it carries both the alpha-channel sub-block (BC4-like,
8 bytes) and the color sub-block (DXT1-like, 8 bytes) — exercising
the full BC-family wire pattern. Per the standard S3TC / BC3
specification (Microsoft DirectX docs; OpenGL ARB_texture_compression_s3tc),
a single 4×4 pixel block occupies exactly 16 bytes laid out as:

```
Offset (within block)  Bytes (LE)              Field
---------------------  ----------------------  ---------------------
+0                     FF                       alpha_endpoint_0 (u8; here 255 = fully opaque)
+1                     00                       alpha_endpoint_1 (u8; here 0   = fully transparent)
+2                     00 00 00 00 00 00        alpha_indices    (48 bits = 16 × 3-bit indices into the alpha-interp ramp)
+8                     1F F8                    color_endpoint_0 (u16 RGB565 LE; here 0xF81F = red-magenta extremum)
+10                    E0 07                    color_endpoint_1 (u16 RGB565 LE; here 0x07E0 = pure green)
+12                    00 00 00 00              color_indices    (32 bits = 16 × 2-bit indices into the color-interp ramp)
+16                                              (end of block)
```

A 4×4 block stores exactly 16 pixels using 16 bytes — a 2:1
compression ratio against `PF_R8G8B8A8` (4 B/px → 1 B/px). For a
mip with `SizeX = 64` and `SizeY = 64`, the wire byte count is
`(64/4) × (64/4) × 16 = 16 × 16 × 16 = 4096 bytes`.

## Variants

The "unknown format" case: when `PixelFormat` resolves to a
variant paksmith doesn't recognize (e.g. a new UE5 HDR format added
after this doc was last updated), the reader should produce
`AssetParseFault::UnsupportedPixelFormat { name }` rather than
attempting to decode bytes per a guessed format. Forward-compatibility
follows the same shape as the `CompressionMethod::UnknownByName`
pattern in [`../compression/oodle.md`](../compression/oodle.md).

## Caps & limits

### Format-defined limits (wire-imposed)

- **Block-compressed format byte counts** are fixed per the variant
  tables above (BC family: 8 or 16 bytes per 4×4 block; ASTC: 16
  bytes per variable-size block; ETC2: 8 or 16 bytes per 4×4
  block).
- **Uncompressed format byte counts** are fixed per pixel
  (`PF_R8G8B8A8` = 4 B/px, `PF_B8G8R8A8` = 4 B/px, `PF_G8` = 1 B/px,
  `PF_G16` = 2 B/px, `PF_FloatRGBA` = 8 B/px, etc.).
- **Mip wire-byte size** is deterministic from
  `(width, height, format)` per the tables above —
  block-compressed: `ceil(W/blockX) × ceil(H/blockY) × bytes_per_block`;
  uncompressed: `W × H × bytes_per_pixel`. A parser MUST compute
  expected size from these formulas and reject mips whose
  on-disk size mismatches.

### Implementation hardening (recommended for any parser)

A pixel-format decoder (paksmith does not yet have one) MUST:

- **Inherit per-mip byte caps** from
  `MAX_UNCOMPRESSED_ENTRY_BYTES` / `MAX_UEXP_SIZE`.
- **Cap the intermediate RGBA8 decoded buffer** with
  `MAX_DECODED_TEXTURE_BYTES`. Expansion ratios from on-disk
  encoded bytes to RGBA8 vary significantly:
  - **BC/DXT family worst case (`PF_DXT1`):** 0.5 B/px compressed
    → 4 B/px RGBA8 = **8× expansion**. A 1 GiB DXT1 mip becomes
    an 8 GiB intermediate buffer.
  - **ASTC worst case (`PF_ASTC_12x12`):** 144 px per 16-byte
    block → 0.111 B/px → 4 B/px RGBA8 = **~36× expansion**. A
    1 GiB ASTC_12x12 mip becomes ~36 GiB.

  `MAX_DECODED_TEXTURE_BYTES` MUST be sized against the ASTC
  worst case, not the BC/DXT case — otherwise ASTC_12x12 inputs
  bypass the cap by ~4.5×.
- **Use `checked_mul` on the mip-byte computation** to defeat
  overflow at the `width × height` step before the block-count
  ceiling divides apply.
- **Validate variant names against a known-variant allow-list**
  before dispatching. Unrecognized names MUST surface
  `AssetParseFault::UnsupportedPixelFormat { name }` rather than
  passing garbage bytes to a default decoder. The
  forward-compatibility pattern matches
  `CompressionMethod::UnknownByName` in
  [`../compression/oodle.md`](../compression/oodle.md).

## Verification

- **Fixture:** The Worked example above is byte-exact and
  self-contained for a single 16-byte `PF_DXT5` block. Real-cooked
  texture fixtures across the dominant pixel-format set are Phase 3
  deliverables.
- **Hex anchor commands:**
  ```
  # Synthesize the 16-byte PF_DXT5 block from the Worked example:
  printf '\xFF\x00\x00\x00\x00\x00\x00\x00\x1F\xF8\xE0\x07\x00\x00\x00\x00' | xxd
  ```
  A conformant PF_DXT5 decoder fed these 16 bytes MUST treat them
  as a single 4×4 pixel block with alpha endpoints `{255, 0}`
  and color endpoints `{0xF81F, 0x07E0}` (RGB565 LE).
- **Cross-validation oracle:** CUE4Parse[^1] for the enum +
  per-format decoders. Public reference specs (Microsoft DirectX
  BC3 documentation, OpenGL `ARB_texture_compression_s3tc` for
  S3TC, Khronos ASTC specification, ETC2 in OpenGL ES 3.0 spec)
  are the upstream authorities for the block layouts and are
  freely available.
- **Known divergences:** none — no paksmith implementation to
  diverge.

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
