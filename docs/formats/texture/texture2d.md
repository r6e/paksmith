# Texture2D (`UTexture2D`)

> 2D texture asset — the most-common UE texture type. A
> `UObject`-derived tagged-property body followed by an
> `FTexturePlatformData` payload with the actual mip chain.

## Overview

`UTexture2D` is the UE class for 2D images: UI assets, material
diffuse / normal / metallic maps, sprite sheets, virtual-texture
tiles, light-cookies. On disk a `Texture2D` is a serialized
`UObject` whose export body is the tagged-property stream (see
[`../property/tagged.md`](../property/tagged.md) for the
mechanics) plus a trailing `FTexturePlatformData` blob — the
properties carry the texture's settings (compression, sRGB,
addressing mode, etc.) and the platform-data blob carries the
actual pixel bytes split into a mip chain.

The mip chain itself is partitioned across the `.uasset`, `.uexp`,
and `.ubulk` files using a tiered streaming layout — see
[`mips-and-streaming.md`](mips-and-streaming.md). The pixel format
that governs how each mip's bytes are interpreted is enumerated in
[`pixel-formats.md`](pixel-formats.md).

**Status: not yet implemented in paksmith.** This doc fills in the
wire format from CUE4Parse references but Caps & limits and
Verification are explicitly Phase 3+ deferred work.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| UE 4.0+ | `UTexture2D` introduced; serialized as tagged properties + `FTexturePlatformData`. | `CUE4Parse/UE4/Assets/Exports/Texture/UTexture2D.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d`[^1] |
| UE 4.23+ | Virtual-texturing fields (`VirtualTextureBuildSettings`, etc.) added; mostly tagged properties so no wire-format break. | Same[^1] |
| UE 5.0+ | Optional `FStripDataFlags` prefix to several embedded structs; the structural shape doesn't change. | Same[^1] |

Within paksmith's accepted UE range, the `Texture2D` wire shape is
governed by the underlying tagged-property iteration plus the
`FTexturePlatformData` blob; per-version variance lives inside the
blob rather than at the `Texture2D` outer layer.

## Wire layout

A serialized `UTexture2D` export body has two segments:

### Segment 1: tagged-property stream

Standard `FPropertyTag` iteration (see [`../property/tagged.md`](../property/tagged.md)).
Common property names paksmith will encounter:

| Property name | Type | Semantics |
|---------------|------|-----------|
| `SRGB` | `BoolProperty` | Apply sRGB encoding on sample. |
| `CompressionSettings` | `ByteProperty` / `EnumProperty` (`TextureCompressionSettings`) | DXT / BC / ASTC / etc. — drives the cooker's choice of `EPixelFormat`. |
| `Filter` | `ByteProperty` / `EnumProperty` (`TextureFilter`) | Nearest / Linear / Anisotropic sampling. |
| `AddressX`, `AddressY` | `ByteProperty` / `EnumProperty` (`TextureAddress`) | Wrap / Clamp / Mirror. |
| `MipGenSettings` | `ByteProperty` / `EnumProperty` (`TextureMipGenSettings`) | Mip-generation algorithm chosen at cook time. |
| `LODBias` | `IntProperty` | Mip-level bias applied at runtime. |
| `NumCinematicMipLevels` | `IntProperty` | Cinematic-quality streaming reservation. |
| `NeverStream` | `BoolProperty` | If true, all mips inline in `.uasset` / `.uexp`. |
| `bUseLegacyGamma` | `BoolProperty` | Legacy gamma curve flag. |
| `LightingGuid` | `StructProperty` (`Guid`) | Editor-only consistency token. |

The properties terminate with the standard `"None"` tag.

### Segment 2: `FTexturePlatformData`

Immediately after the property terminator, an `FTexturePlatformData`
blob serializes. The blob carries the cooked mip chain plus the
metadata to interpret it.

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `SizeX` | 4 | LE | `i32` | Top-mip width in pixels (or blocks for compressed formats). |
| `SizeY` | 4 | LE | `i32` | Top-mip height. |
| `PackedData` | 4 | LE | `u32` | Bit-packed: bit 31 = cubemap flag; bit 30 = `HasOptData`; bit 29 = `HasCpuCopy`; low 29 bits = `NumSlices`. |
| `PixelFormat` | variable | — | `FString` | Name of the `EPixelFormat` variant (e.g. `"PF_DXT5"`). See [`pixel-formats.md`](pixel-formats.md). |
| `OptData` | 8 | LE | `FOptTexturePlatformData` | **Conditional:** present only when bit 30 of `PackedData` is set. Contains `ExtData: u32` + `NumMipsInTail: u32`. |
| `CPUCopy` | variable | — | `FSharedImage` | **Conditional:** present only when bit 29 of `PackedData` is set (UE 5.4+). Inline decoded copy: `SizeX: i32`, `SizeY: i32`, `SizeZ: i32`, `Format: u8` (EPixelFormat discriminant), `GammaSpace: u8`, `RawDataLen: i64`, `RawData[RawDataLen]`. |
| `FirstMipToSerialize` | 4 | LE | `i32` | Top-mip skip-count (cooking optimization for downscaled platforms). |
| `Mips` | variable | — | `FTexture2DMipMap[]` | `i32` mip count prefix + per-mip records; see [`mips-and-streaming.md`](mips-and-streaming.md). |
| `bIsVirtual` | 4 | LE | `bool` (4-byte UE) | **Version-conditional:** present only when `Ar.Versions["VirtualTextures"]` is set. `false` = standard mip chain; `true` = `FVirtualTextureBuiltData` follows. |

## Variants

### Virtual textures

When `bIsVirtual == 1`, the trailing data isn't a flat mip array but
an `FVirtualTextureBuiltData` record (page table + tile chunks). Far
less common in cooked content than streaming `Texture2D`; deferred.

### Texture cube / 2D array / volume

Related sibling export classes — `UTextureCube`, `UTexture2DArray`,
`UVolumeTexture` — share the `FTexturePlatformData` wire shape but
differ in `PackedData` slice/face counts and mip stride. Each will get
its own format doc when Phase 3 specializes.

### Stripped editor-only data

When `PKG_FilterEditorOnly` is set on the package (typical for cooked
content), several `FStripDataFlags` markers gate editor-only fields
inside the platform-data blob. paksmith's existing summary check
already verifies the editor-only-stripped state.

## Caps & limits

**Phase 3+ deferred work.** When the texture reader lands, paksmith
will enforce caps mirroring the rest of the codebase:

- A per-texture `MAX_TEXTURE_DIMENSION` cap on `SizeX` / `SizeY` to
  prevent attacker-controlled-multi-GB allocations from a corrupted
  dimension field.
- A `MAX_MIP_COUNT` cap on the mip array prefix.
- A per-mip-byte cap inherited from the surrounding
  `MAX_UNCOMPRESSED_ENTRY_BYTES` (8 GiB) and `MAX_UEXP_SIZE` (1 GiB)
  in the parent pak + uexp layers.

See `docs/security/allocation-caps.md` for the broader policy.

## Verification

- **Fixture:** `(none yet — Phase 3 deliverable)`. Phase 3 will add
  `tests/fixtures/minimal_texture2d_uncompressed.uasset` /
  `_dxt5.uasset` / `_bc7.uasset` covering the dominant pixel formats.
- **Hex anchor commands:** `(none yet — Phase 3 deliverable)`.
- **Cross-validation oracle:** CUE4Parse[^1] (primary). No Rust
  counterpart in the surveyed ecosystem decodes `Texture2D` exports
  yet; a cross-validation oracle will be identified when Phase 3
  lands.
- **Known divergences:** none yet — no implementation to diverge.

## Paksmith implementation

**Parser module:** *(not yet implemented — planned under
`crates/paksmith-core/src/asset/exports/texture/`)*

**Status:** `not impl`. Encounters of `Texture2D` exports today
parse through the generic tagged-property iterator (the property
stream decodes successfully, surfacing as a `PropertyBag::Tree`);
the trailing `FTexturePlatformData` blob causes the iteration to
read past the "None" terminator into platform-data bytes, the read
errors, and the export falls back to `PropertyBag::Opaque` with a
`tracing::warn!` event. No actual mip bytes are recoverable until
the parser lands.

**Phase plan:** `docs/plans/ROADMAP.md` Phase 3 (Export Pipeline).
A Phase 3 plan should:

1. Add a `crates/paksmith-core/src/asset/exports/texture/` module
   with `Texture2D::read_from`.
2. Hook a per-export dispatch by class name (the export table's
   `class_index` resolves to the `Texture2D` import → trigger the
   specialized reader).
3. Add cap constants (`MAX_TEXTURE_DIMENSION`, `MAX_MIP_COUNT`).
4. Add fixtures + identify a cross-validation oracle (no existing
   Rust decoder for `Texture2D` was found in the surveyed ecosystem
   at authoring time).

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Exports/Texture/UTexture2D.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` and `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Exports/Texture/FTexturePlatformData.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` — primary oracle. Covers every version-conditional field paksmith will need.
