# Texture mip chains and streaming

> How a texture's mip chain is partitioned across the `.uasset`,
> `.uexp`, and `.ubulk` files, and how the runtime streaming system
> decides which mips to load.

## Overview

A UE texture isn't a single image — it's a **mip chain**: the full-
resolution top mip plus a sequence of progressively-halved-resolution
downsamples (mip 0 = full, mip 1 = half-each-axis, mip 2 = quarter-
each-axis, etc.). The chain stops when one dimension reaches 1
pixel.

On disk, mips are stored in three storage tiers depending on cooker
decisions and the texture's streaming settings:

- **Inline** in the `.uasset`: the top mip(s) of small textures
  (UI icons, etc.) or any texture with `NeverStream = true`. Cheapest
  to load because no companion file lookup.
- **In `.uexp`**: most textures' inline mips. The `.uexp` sidecar
  carries them as part of the export body (see
  [`../asset/uexp.md`](../asset/uexp.md)).
- **Streaming, in `.ubulk`**: the top (high-resolution) mips of
  larger textures. The runtime streaming system demand-loads these
  based on camera proximity / texture LOD settings (see
  [`../asset/ubulk.md`](../asset/ubulk.md)).

Each per-mip `FTexture2DMipMap` record contains an `FByteBulkData`
field whose flags identify which tier the mip's bytes live in plus
their offset / size within that tier's file.

**Status: not yet implemented in paksmith.** Phase 2e detects
`.ubulk` siblings (see [`../asset/ubulk.md`](../asset/ubulk.md)) but
doesn't stitch their bytes. Phase 3+ work — driven by the texture
exporter — will implement per-mip resolution.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| UE 4.0+ | Three-tier (inline / uexp / ubulk) streaming introduced. | `CUE4Parse/UE4/Assets/Objects/FByteBulkData.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d`[^1] |
| UE 4.20+ | `SizeZ` field added to `FTexture2DMipMap` for volume/array textures. | `CUE4Parse/UE4/Assets/Exports/Texture/FTexture2DMipMap.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d`[^1] |
| UE 5.0+ | `FBulkDataCookedIndex` introduced for some bulk-data records; mostly applies to runtime-virtual-texture chunks. | Same[^1] |

## Wire layout

### `FTexture2DMipMap` (per-mip record)

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `bCooked` | 4 | LE | `u32` | Bool encoded as u32; expected `1` for cooked content. Present only when `Ar.Ver >= TEXTURE_SOURCE_ART_REFACTOR` and `Ar.Game < UE5`. |
| `BulkData` | variable | — | `FByteBulkData` | The actual mip byte payload + tier metadata. |
| `SizeX` | 4 | LE | `i32` | Mip width in pixels (block units for compressed). |
| `SizeY` | 4 | LE | `i32` | Mip height. |
| `SizeZ` | 4 | LE | `i32` | Mip depth (1 for `Texture2D`; >1 for `Texture2DArray` / `VolumeTexture`). Present only for UE 4.20+. |

Note the unusual ordering: `BulkData` is serialized **between**
`bCooked` and the `SizeX/Y/Z` triple, not after them.

### `FByteBulkData`

The per-storage-tier record.

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `BulkDataFlags` | 4 | LE | `u32` | Bitfield publishing the storage tier + flags. See bit catalog below. |
| `ElementCount` | 4 or 8 | LE | `uint` | Number of elements (bytes for byte bulk data). Width is 8 bytes when `BULKDATA_Size64Bit` is set, 4 bytes otherwise. |
| `SizeOnDisk` | 4 or 8 | LE | `uint` | Stored byte size (post-compression if applicable). Width is 8 bytes when `BULKDATA_Size64Bit` is set, 4 bytes otherwise. |
| `OffsetInFile` | 8 | LE | `i64` | Byte offset within the containing file (which file depends on the tier flags). |

The "containing file" is whichever of `.uasset` / `.uexp` / `.ubulk`
the flags identify.

### `BulkDataFlags` bit catalog

| Bit name | Hex | Meaning |
|----------|-----|---------|
| `BULKDATA_PayloadAtEndOfFile` | `0x0001` | Payload bytes are at `OffsetInFile` of the *parent file* (`.uasset` for inline, `.uexp` for uexp-resident). |
| `BULKDATA_SerializeCompressedZLIB` | `0x0002` | Payload zlib-compressed; decompress before use. `BULKDATA_SerializeCompressed` is an alias for this flag. |
| `BULKDATA_ForceSingleElementSerialization` | `0x0004` | Element-by-element serialization (rare for textures). |
| `BULKDATA_SingleUse` | `0x0008` | Discard after first read. |
| `BULKDATA_CompressedLZO` | `0x0010` | Payload LZO-compressed (rare in cooked content). |
| `BULKDATA_Unused` | `0x0020` | Legacy. |
| `BULKDATA_ForceInlinePayload` | `0x0040` | Inline regardless of streaming settings. |
| `BULKDATA_ForceStreamPayload` | `0x0080` | Force streaming (use `.ubulk`). |
| `BULKDATA_PayloadInSeperateFile` [sic] | `0x0100` | Payload is in a separate file (`.ubulk`). ("Seperate" preserves the UE engine enum spelling exactly.) |
| `BULKDATA_SerializeCompressedBitWindow` | `0x0200` | Uses a custom bit window for compression. |
| `BULKDATA_Force_NOT_InlinePayload` | `0x0400` | Prevent inlining even when other flags would allow it. |
| `BULKDATA_OptionalPayload` | `0x0800` | Payload may not be present at all (`.uptnl` companion). |
| `BULKDATA_MemoryMappedPayload` | `0x1000` | Memory-mapped on supported platforms. |
| `BULKDATA_Size64Bit` | `0x2000` | Sizes are 64-bit. |
| `BULKDATA_DuplicateNonOptionalPayload` | `0x4000` | Duplicated for redundancy. |
| `BULKDATA_BadDataVersion` | `0x8000` | Sentinel for older bad data. |
| `BULKDATA_NoOffsetFixUp` | `0x0001_0000` | Don't apply offset fix-up. |
| `BULKDATA_WorkspaceDomainPayload` | `0x0002_0000` | Editor-domain payload. |

### Tier dispatch

The tier the bytes live in is determined by `BulkDataFlags`:

| Flag combination | Tier | File |
|------------------|------|------|
| `BULKDATA_PayloadAtEndOfFile` only | Inline | The `.uasset` itself; `OffsetInFile` is from the `.uasset`'s start. |
| `BULKDATA_PayloadAtEndOfFile` + (in `.uexp` region) | uexp-resident | `.uexp`; offset is from `.uasset` start (after stitching, that's `total_header_size + uexp_offset`). |
| `BULKDATA_PayloadInSeperateFile` [sic] | Streaming | `.ubulk`; offset is from `.ubulk`'s start. |
| `BULKDATA_OptionalPayload` + `BULKDATA_PayloadInSeperateFile` [sic] | Optional streaming | `.uptnl`. |

The distinction between "inline" and "uexp-resident" comes down to
whether `OffsetInFile` falls within `[0, total_header_size)`
(inline) or `[total_header_size, …)` (uexp-resident). Both use the
same flag (`BULKDATA_PayloadAtEndOfFile`); the offset disambiguates.

### Worked example

`(none yet — no texture fixture)`. When Phase 3 lands, a `PF_DXT5`
512×512 texture's mip chain would publish 10 mips (`512×512` →
`256×256` → … → `1×1`); the top 3-5 might be in `.ubulk`-streaming
tier while the bottom (downsampled) ones live in `.uexp`-resident
tier.

## Variants

### Cubemaps and texture arrays

Cubemap textures have 6 face mip chains; `SizeZ = 6` (or
`6 × num_array_slices` for cube arrays). The per-mip records carry
all faces concatenated.

### Virtual textures

Virtual textures don't use the three-tier mip system — they use a
page-table-and-tile-chunks scheme published by
`FVirtualTextureBuiltData`. Documented in `texture2d.md`'s Variants
section.

### `BULKDATA_SerializeCompressedZLIB` per-mip compression

Texture mips can be compressed at the `FByteBulkData` layer (in
addition to per-block compression from the pak layer). The mip's
post-decompression bytes are the actual pixel data. Bulk-data
decompression is `not impl` in paksmith. When Phase 3+ adds the mip
resolver, the existing pak-block zlib decompressor at
`crates/paksmith-core/src/container/pak/mod.rs` is the reuse target
for `BULKDATA_SerializeCompressedZLIB` mips; Oodle-compressed mip
bulk data is gated on the same SDK integration as the pak-side Oodle
work (see [`../compression/oodle.md`](../compression/oodle.md)).

## Caps & limits

**Phase 3+ deferred work.** When the mip resolver lands:

- A `MAX_MIPS_PER_TEXTURE` cap (UE never cooks more than ~16
  mips for any reasonable resolution — 16,384px max width / height).
- The per-mip byte caps inherited from the underlying file's caps
  (`MAX_UNCOMPRESSED_ENTRY_BYTES` for pak-resident bytes,
  `MAX_UEXP_SIZE` for `.uexp` bytes, future `.ubulk` cap).

## Verification

- **Fixture:** `(none yet — Phase 3 deliverable)`.
- **Hex anchor commands:** `(none yet — Phase 3 deliverable)`.
- **Cross-validation oracle:** CUE4Parse[^1].
- **Known divergences:** none yet.

## Paksmith implementation

**Parser module:** *(not yet implemented — planned under
`crates/paksmith-core/src/asset/exports/texture/mip_resolver.rs`)*

**Status:** `not impl`. paksmith's Phase 2e companion
detection identifies that a `.ubulk` exists but doesn't read its
bytes (see [`../asset/ubulk.md`](../asset/ubulk.md)). Phase 3 will
add the mip resolver that combines the `.uasset` / `.uexp` / `.ubulk`
into a per-mip byte lookup.

**Phase plan:** `docs/plans/ROADMAP.md` Phase 3 (Export Pipeline).
The Phase 3 plan should:

1. Add an `FByteBulkData` reader with the flag-bit catalog.
2. Add a `MipResolver` that takes a `(Package, ubulk_bytes)` pair
   and returns per-mip byte slices.
3. Hook the resolver into the planned Phase 3 texture exporter.

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Exports/Texture/FTexture2DMipMap.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d`, `CUE4Parse/UE4/Assets/Objects/FByteBulkData.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d`, and `CUE4Parse/UE4/Assets/Objects/EBulkDataFlags.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` — primary oracle for the per-mip + bulk-data records and the flag-bit catalog.
