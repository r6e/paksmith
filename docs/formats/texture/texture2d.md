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

**Document status: complete.** Wire format documented in full for
the two segments of the `UTexture2D` export body: the
tagged-property stream (common property names + types) and the
trailing `FTexturePlatformData` blob (full byte-level field table,
`PackedData` bit-layout, `FOptTexturePlatformData` and `FSharedImage`
optional sub-records, mip-count prefix). Per-mip `FTexture2DMipMap`
internals are deferred to [`mips-and-streaming.md`](mips-and-streaming.md);
`EPixelFormat` per-variant byte layouts to
[`pixel-formats.md`](pixel-formats.md). The `FVirtualTextureBuiltData`
sub-format (rare in cooked content) is documented in
[`virtual-textures.md`](virtual-textures.md).

**Paksmith parser status: `partial`.** The `Texture2D` class routes
through the export-class dispatch to
`asset/exports/texture/texture2d.rs::read_from`, which decodes
**segment 1** (the tagged-property stream) plus the **full**
`FTexturePlatformData` header — the version-gated stripped-data prefix,
`SizeX`, `SizeY`, `PackedData`, `PixelFormat` (3e-2a), then the
conditional `OptData` / `CPUCopy`, `FirstMipToSerialize`, and the
mip-count prefix (3e-2b). The per-mip records + bytes land in 3e-3; no
mip bytes are recoverable until then. (Before 3e-1 the generic iterator
already decoded segment 1 to a `PropertyBag::Tree`, stopping cleanly
at the `"None"` terminator and leaving the platform-data blob
unread — `read_properties` never reads past `"None"`, so there is no
`PropertyBag::Opaque` fallback for a well-formed `Texture2D`. 3e-1
promotes that same segment-1 read to the typed `Asset::Texture2D`
variant that the `PngHandler` dispatches on.)

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| UE 4.0+ | `UTexture2D` introduced; serialized as tagged properties + `FTexturePlatformData`. | `CUE4Parse/UE4/Assets/Exports/Texture/UTexture2D.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d`[^1] |
| UE 4.23+ | Virtual Texturing: adds optional `bIsVirtual` flag + `FVirtualTextureBuiltData` payload (gated by `Ar.Versions["VirtualTextures"]`); related tagged-property additions on UTexture2D do not break the wire format. | Same[^1] |
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

### Segment-2 entry: `UTexture` / `UTexture2D` binary preamble

After the property terminator — and **before** the `FTexturePlatformData`
— `UTexture.Deserialize` and `UTexture2D.Deserialize` serialize a fixed
binary preamble. It is unconditional for the cooked-texture range and
gates whether the platform data is even present.

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `UTexture` `FStripDataFlags` | 2 | — | `u8` `GlobalStripFlags` + `u8` `ClassStripFlags` | `IsEditorDataStripped() = (GlobalStripFlags & 1) != 0`. Cooked content has editor data stripped; when **not** stripped, an editor `FByteBulkData` / `FEditorBulkData` (version-gated by `FUE5MainStreamObjectVersion`) follows here, which a cooked-only parser will not encounter. |
| `UTexture2D` `FStripDataFlags` | 2 | — | `u8` + `u8` | A second strip-flags pair; value otherwise unused by the reader. |
| `bCooked` | 4 | LE | `u32` bool (`ReadBoolean` ∈ {0,1}) | Owner-level cooked flag, gated `Ar.Ver >= ADD_COOKED_TO_TEXTURE2D` (UE4 object version 227 — far below any modern floor, so always present). `DeserializeCookedPlatformData` (the `FTexturePlatformData`) runs **only** when `bCooked == true`; `false` ⇒ no platform data. |
| `bSerializeMipData` | 4 | LE | `u32` bool (`ReadBoolean` ∈ {0,1}) | **Version-conditional:** present only for `Ar.Game >= GAME_UE5_3` (and `GAME_TheFirstDescendant`). When `false`, the per-mip `FTexture2DMipMap` records carry **no** inline `FByteBulkData` (mip bytes live entirely in side files). Defaults `true` when absent. |

`FStripDataFlags`'s single-argument constructor (`new FStripDataFlags(Ar)`)
chains to `OLDEST_LOADABLE_PACKAGE`, so both bytes are read for every
loadable package; the 2-argument form gates on a `minVersion` and reads 0
bytes below it.

**UE 5.2 vs 5.3 version-mapping note.** CUE4Parse's `EGame`→`FPackageFileVersion`
table maps *both* `GAME_UE5_2` and `GAME_UE5_3` to UE5 object version
`1009` (`< GAME_UE5_4 => (522, 1009)`); object versions `1010`
(`SCRIPT_SERIALIZATION_OFFSET`) and `1011` are 5.4-preview. A parser
without an engine-version signal (e.g. a game profile) therefore cannot
distinguish a 5.2 texture (no `bSerializeMipData`) from a 5.3 texture
(`bSerializeMipData` present) at object version `1009` — the field's
4-byte *presence* is what shifts the layout. `Ar.Game >= GAME_UE5_3` is an
engine-version gate, not an object-version one.

### Segment-2 platform-data key: `DeserializeCookedPlatformData` wrapper

When `bCooked` is set, `DeserializeCookedPlatformData` does **not** open
straight onto the `FTexturePlatformData`. It is a `None`-terminated loop
over *running-platform* entries (one per cooked target format), each
prefixed by a key:

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `pixelFormatName` | 8 | LE | `FName` (`i32` index + `i32` number) | The running-platform key. `None` (index 0) terminates the loop — a leading `None` means no platform data was cooked. Distinct from the `FTexturePlatformData.PixelFormat` `FString` below. |
| `skipOffset` | 4 / 8 | LE | `i32` (pre-4.20) / `i64` (UE 4.20+) | Offset to the end of this entry's `FTexturePlatformData`, used to **skip** non-primary cooked formats. For UE 5.0+ it is `AbsolutePosition + Read<i64>()` (relative); otherwise absolute. |
| `FTexturePlatformData` | variable | — | struct | The platform data (table below). Only the **first** entry (`Format == PF_Unknown`) is fully parsed; later entries are seeked past via their `skipOffset`. |

A typical single-target cooked texture has exactly one entry followed by a
`None` `pixelFormatName`. A reader that only needs the primary cooked
format reads the leading `pixelFormatName` + `skipOffset`, parses the first
`FTexturePlatformData`, and (because the export is bounded by
`serial_size`) may stop at the mip chain without consuming the trailing
`bIsVirtual` or the `None` terminator.

### Segment 2: `FTexturePlatformData`

Immediately after the platform-data key's `skipOffset`, an
`FTexturePlatformData` blob serializes. The blob carries the cooked mip
chain plus the metadata to interpret it.

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `SizeX` | 4 | LE | `i32` | Top-mip width in pixels (always pixel units, even for block-compressed formats; block count is derived as ceil(SizeX / blockWidth)). |
| `SizeY` | 4 | LE | `i32` | Top-mip height. |
| `PackedData` | 4 | LE | `u32` | Bit-packed: bit 31 = cubemap flag; bit 30 = `HasOptData`; bit 29 = `HasCpuCopy`; low 30 bits (bits 0-29) = `NumSlices` — note bit 29 overlaps `HasCpuCopy`; CUE4Parse's `GetNumSlices()` does not strip bit 29 (`BitMask_NumSlices = (1u << 30) - 1 = 0x3FFF_FFFF`), so any future paksmith implementation must use the same wide mask for parity. |
| `PixelFormat` | variable | — | `FString` | Name of the `EPixelFormat` variant (e.g. `"PF_DXT5"`). See [`pixel-formats.md`](pixel-formats.md). |
| `OptData` | 8 | LE | `FOptTexturePlatformData` | **Conditional:** present only when bit 30 of `PackedData` is set. Contains `ExtData: u32` + `NumMipsInTail: u32`. |
| `CPUCopy` | variable | — | `FSharedImage` | **Conditional:** present only when bit 29 of `PackedData` is set (UE 5.4+). Inline decoded copy: `SizeX: i32`, `SizeY: i32`, `SizeZ: i32`, `Format: u8` (EPixelFormat discriminant — enum is `: byte` per CUE4Parse PixelFormat.cs), `GammaSpace: u8`, `RawDataLen: i64`, `RawData[RawDataLen]`. |
| `FirstMipToSerialize` | 4 | LE | `i32` | Top-mip skip-count (cooking optimization for downscaled platforms). |
| `Mips` | variable | — | `FTexture2DMipMap[]` | `i32` mip count prefix + per-mip records; see [`mips-and-streaming.md`](mips-and-streaming.md). |
| `bIsVirtual` | 4 | LE | `bool` (4-byte UE) | **Version-conditional:** present only when `Ar.Versions["VirtualTextures"]` is set. `false` = standard mip chain; `true` = `FVirtualTextureBuiltData` follows. |

#### UE 5.0+ stripped-data prefix

UE 5.0+ packages with `IsFilterEditorOnly` set (cooked content)
prepend a 16-byte `PlaceholderDerivedDataSize` opaque skip before
`SizeX`. UE 5.2+ further prepends a single `bUsingDerivedData`
flag byte; when `true`, the platform-data uses the derived-data
cache (not handled by paksmith or CUE4Parse), and when `false`,
the same 16-byte skip applies (minus 1 byte for the flag itself).
A reader walking the platform-data on UE 5.2+ cooked content
MUST advance the cursor by `15` bytes after the `bUsingDerivedData`
flag check before reading `SizeX`.

### Worked example — `FTexturePlatformData` header prefix (32 bytes)

A minimal platform-data segment for a 64×64 single-slice
non-cubemap `PF_DXT5` texture with no opt data, no CPU copy, no
virtual texture, and exactly one mip:

```
Offset  Bytes (LE)                                       Field
------  -----------------------------------------------  -------------------------
+0      40 00 00 00                                      SizeX = 64 (i32 LE)
+4      40 00 00 00                                      SizeY = 64 (i32 LE)
+8      01 00 00 00                                      PackedData = 1 (NumSlices=1; no cubemap, no opt, no CPU copy)
+12     08 00 00 00                                      PixelFormat FString length = 8 (i32 LE; includes null terminator)
+16     50 46 5F 44 58 54 35 00                          PixelFormat bytes = "PF_DXT5\0" (8 bytes UTF-8)
+24     00 00 00 00                                      FirstMipToSerialize = 0 (i32 LE)
+28     01 00 00 00                                      mipCount = 1 (i32 LE)
+32     <FTexture2DMipMap record follows — see mips-and-streaming.md>
```

The `bIsVirtual` byte (when present) follows the last mip record.
Per the existing `FTexturePlatformData` field table above, this
example sets `PackedData = 1` (binary
`00000000 00000000 00000000 00000001`): bit 31 = 0 (not cubemap),
bit 30 = 0 (no opt data), bit 29 = 0 (no CPU copy), bits 0-29 (the
`NumSlices` mask) = `1`. The `OptData` and `CPUCopy` sub-records
are absent because their gating bits are zero.

## Variants

### Virtual textures

When `bIsVirtual != 0`, the trailing data isn't a flat mip array but
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

### Format-defined limits (wire-imposed)

- **`SizeX` / `SizeY`**: `i32` fields, max representable
  `i32::MAX` ≈ 2.1 billion pixels per dimension. (Practical UE
  textures stay below 16384 — the GPU sampler limit on most
  hardware.)
- **`PackedData`**: `u32`; bit 31 = cubemap, bit 30 = HasOptData,
  bit 29 = HasCpuCopy, bits 0-29 = NumSlices (30 bits, max
  `(1<<30)-1` ≈ 1 billion slices). Note bit 29 overlaps the
  `NumSlices` mask — CUE4Parse's `GetNumSlices()` does not strip
  it, so a CPU-copy-flagged texture would publish
  `NumSlices = real_slices | (1<<29)` if the slice count is
  literally interpreted; the engine's writer convention reserves
  bit 29 for the flag and uses bits 0-28 for the actual slice
  count on CPU-copy-bearing textures.
- **`PixelFormat`**: variable-length `FString` (max length per
  [`../primitive/fstring.md`](../primitive/fstring.md)). UE
  variant names are short ASCII strings like `"PF_DXT5"`.
- **`OptData`**: fixed 8 bytes when present (4-byte `ExtData` +
  4-byte `NumMipsInTail`); absent when bit 30 of `PackedData` is
  clear.
- **`CPUCopy` (`FSharedImage`)**: variable-length sub-record;
  fixed 22-byte header (3 × `i32` + `u8` + `u8` + `i64` =
  12 + 1 + 1 + 8) plus `RawDataLen` bytes; absent when bit 29 of
  `PackedData` is clear. UE 5.4+ only.
- **`FirstMipToSerialize`**: `i32` field; max representable
  `i32::MAX`.
- **Mip count prefix**: `i32` field; max representable
  `i32::MAX` ≈ 2.1 billion mips per texture (well beyond the
  ~16 mips a real texture has).
- **`bIsVirtual`**: 4-byte UE-encoded `bool`; only present when
  `Ar.Versions["VirtualTextures"]` is set.

### Implementation hardening (recommended for any parser)

A texture reader MUST (paksmith's reader implements these as the
corresponding fields land — the `SizeX`/`SizeY` cap is in 3e-2a; the
mip-count, `NumMipsInTail`, and CPU-copy `RawDataLen` caps in 3e-2b):

- **Cap `SizeX` / `SizeY`** at a project-defined
  `MAX_TEXTURE_DIMENSION` (typically `16384`) before any
  allocation. A 4 GiB-pixel dimension claim from a corrupted
  field would otherwise drive a multi-GB intermediate buffer.
- **Cap the mip-count prefix** at `MAX_MIP_COUNT` (typically
  `32`, generous against `log2(16384) ≈ 14`) before allocating
  the `FTexture2DMipMap[]` array. The `i32` prefix is
  attacker-influenced; an `i32::MAX` claim drives a 2.1B-element
  allocation.
- **Use `checked_mul` on `SizeX * SizeY * bytes_per_block`** to
  defeat overflow when computing the expected mip byte count for
  bounds-checking against the per-mip cap.
- **Validate `PixelFormat` against a known-variant allow-list**
  per [`pixel-formats.md`](pixel-formats.md); unrecognized variants
  MUST surface a typed error rather than passing garbage bytes
  to a decoder.
- **Cap `OptData.NumMipsInTail`** at `MAX_MIPS_IN_TAIL` (typically
  matches `MAX_MIP_COUNT`).
- **Cap `CPUCopy.RawDataLen`** at `MAX_UNCOMPRESSED_ENTRY_BYTES`
  (8 GiB) before reading.
- **Inherit per-mip-byte caps** from the surrounding pak / uexp
  layers (`MAX_UNCOMPRESSED_ENTRY_BYTES = 8 GiB`,
  `MAX_UEXP_SIZE = 1 GiB`).

See `docs/security/allocation-caps.md` for the broader policy.

## Verification

- **Fixture:** The Worked example above is byte-exact and self-
  contained for the 32-byte `FTexturePlatformData` header prefix
  (sans the trailing `FTexture2DMipMap` record). Real-cooked
  texture fixtures (`minimal_texture2d_uncompressed.uasset` /
  `_dxt5.uasset` / `_bc7.uasset` covering the dominant pixel
  formats) are Phase 3 deliverables.
- **Hex anchor commands:**
  ```
  # Synthesize the 32-byte FTexturePlatformData header prefix from the
  # Worked example (64x64 single-slice PF_DXT5, no opt/CPU/virtual):
  printf '\x40\x00\x00\x00\x40\x00\x00\x00\x01\x00\x00\x00\x08\x00\x00\x00PF_DXT5\x00\x00\x00\x00\x00\x01\x00\x00\x00' | xxd
  ```
  A conformant `Texture2D` parser fed these 32 bytes MUST decode
  them as a 64×64 single-slice non-cubemap `PF_DXT5` platform-data
  header expecting exactly one mip record to follow.
- **Cross-validation oracle:** CUE4Parse[^1] — the
  `FTexturePlatformData` constructor row-for-row in §*Wire layout*
  above. No Rust counterpart in the surveyed ecosystem decodes
  `Texture2D` exports yet; a cross-validation oracle will be
  identified when Phase 3 lands.
- **Known divergences:** none — no paksmith implementation to
  diverge.

## Paksmith implementation

**Parser module:** `crates/paksmith-core/src/asset/exports/texture/texture2d.rs`
(`read_from` / `read_typed`), registered for the `Texture2D` class name
in `asset/exports/dispatch.rs` (Phase 3e-1).

**Status:** `partial`. Decodes segment 1 (tagged properties) plus the
**full** `FTexturePlatformData` header — the version-gated stripped-data
prefix, `SizeX`, `SizeY`, `PackedData`, `PixelFormat` (3e-2a), then the
conditional `OptData` (bit 30) / `CPUCopy` (bit 29),
`FirstMipToSerialize`, and the mip-count prefix (3e-2b) — into
`Asset::Texture2D(Texture2DData)`. The per-mip records and the
`PngHandler` land in the later 3e milestones. See
`docs/plans/phase-3e-texture-export.md`.

**Phase plan:** `docs/plans/phase-3e-texture-export.md` (Phase 3 export
pipeline). Remaining work:

1. **3e-3:** per-mip `FTexture2DMipMap` records + `FByteBulkData` lazy
   resolution.
2. **3e-4..3e-7:** `EPixelFormat` enum + per-format decoders.
3. **3e-8:** `PngHandler` + fixtures + cross-validation oracle.

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Exports/Texture/UTexture2D.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` and `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Exports/Texture/FTexturePlatformData.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` — primary oracle. Covers every version-conditional field paksmith will need.
