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

**Document status: complete.** Wire format documented in full for
the per-mip `FTexture2DMipMap` record, the `FByteBulkData`
sub-record (with explicit 32/64-bit field-width gating on
`BULKDATA_Size64Bit`), the full `BulkDataFlags` bit catalog
(including the high-bit flags `LazyLoadable`, `AlwaysAllowDiscard`,
`HasAsyncReadPending`, `DataIsMemoryMapped` that the prior version
of this doc had missed), and the three-tier dispatch logic. The
`FVirtualTextureBuiltData` page-table sub-format is identified by
name and deferred to a future dedicated doc.

**Paksmith parser status: `not impl`.** Phase 2e detects
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
| `BulkData` | variable | — | `FByteBulkData` | The actual mip byte payload + tier metadata. Present when serialization caller passes `bSerializeMipData=true` (the default for cooked content; mipdata-less serialization is editor-only). |
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
| `ElementCount` | 4 or 8 | LE | `i32` / `i64` | Number of elements (bytes for byte bulk data). 8 bytes (i64) when `BULKDATA_Size64Bit` is set, otherwise 4 bytes (i32). Signed. |
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
| `BULKDATA_LazyLoadable` | `0x0004_0000` | Payload is lazy-loadable (deferred I/O). |
| `BULKDATA_AlwaysAllowDiscard` | `0x1000_0000` | Always allow discard (high-bit flag, bit 28). |
| `BULKDATA_HasAsyncReadPending` | `0x2000_0000` | Async read in flight (bit 29). |
| `BULKDATA_DataIsMemoryMapped` | `0x4000_0000` | Memory-mapped at runtime (bit 30). |

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

### Worked example — `FTexture2DMipMap` record for inline 64×64 mip (44 bytes)

A `Texture2D` mip record at UE 4.20+ for a 64×64 `PF_DXT5` mip
stored inline in `.uexp` (uexp-resident tier, uncompressed), with
the standard `bCooked = true` prefix:

```
Offset (within record)  Bytes (LE)                Field
----------------------  ------------------------  ---------------------
+0                      01 00 00 00               bCooked = 1 (u32 LE bool; UE 4.x cooked content)
+4                      01 00 00 00               BulkDataFlags = 0x00000001 (BULKDATA_PayloadAtEndOfFile)
+8                      00 10 00 00               ElementCount = 0x00001000 = 4096 (i32 LE; for PF_DXT5 64x64: (64/4)*(64/4)*16 = 4096)
+12                     00 10 00 00               SizeOnDisk = 4096 (u32 LE; uncompressed at the bulk layer)
+16                     00 02 00 00 00 00 00 00   OffsetInFile = 0x00000200 = 512 (i64 LE; offset within .uexp)
+24                     40 00 00 00               SizeX = 64 (i32 LE)
+28                     40 00 00 00               SizeY = 64 (i32 LE)
+32                     01 00 00 00               SizeZ = 1 (i32 LE; UE 4.20+)
+36                     <(BulkData payload bytes follow at OffsetInFile in the parent file, not in this record)>
```

For UE 5.0+ cooked content the `bCooked` u32 prefix is absent
(replaced by the `Ar.IsFilterEditorOnly` runtime check per
`FTexture2DMipMap.cs`); the record would be 32 bytes plus the
trailing `BulkData` payload reference. For pre-UE-4.20 content
the `SizeZ` field is absent (record is 28 bytes).

`BulkDataFlags = 0x00000001` (`BULKDATA_PayloadAtEndOfFile`)
puts the payload at `OffsetInFile = 512` from the start of the
parent `.uexp` file. To distinguish inline (in `.uasset`) from
uexp-resident, the reader checks whether
`OffsetInFile < total_header_size` (inline) or
`OffsetInFile >= total_header_size` (uexp-resident); both use the
same flag. To put the same payload in `.ubulk` instead, set
`BulkDataFlags = 0x00000100` (`BULKDATA_PayloadInSeperateFile`)
and `OffsetInFile` becomes the byte offset within `.ubulk`.

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

### Format-defined limits (wire-imposed)

- **`bCooked`**: 4-byte UE-encoded bool (when present); only
  `0` and `1` are semantically meaningful.
- **`BulkDataFlags`**: `u32` bitmask; bits 0-17 + 28-30 are
  currently allocated per the catalog above. Bits 18-27 and 31
  SHOULD be zero on conformant writers.
- **`ElementCount`**: `i32` (4 bytes) by default; `i64` (8 bytes)
  when `BULKDATA_Size64Bit` (bit 13) is set. Max `i32::MAX`
  ≈ 2.1 billion / `i64::MAX` ≈ 9.2 quintillion.
- **`SizeOnDisk`**: `u32` (4 bytes) by default; `u64` (8 bytes)
  when `BULKDATA_Size64Bit` is set.
- **`OffsetInFile`**: `i64` (8 bytes) — always 64-bit, even when
  `BULKDATA_Size64Bit` is unset. Max `i64::MAX`.
- **`SizeX` / `SizeY` / `SizeZ`**: `i32` fields (max
  `i32::MAX`); `SizeZ` absent pre-UE-4.20.

### Implementation hardening (recommended for any parser)

A mip resolver (paksmith does not yet have one) MUST:

- **Cap mip count per texture** at `MAX_MIPS_PER_TEXTURE`
  (typically `32`). UE never cooks more than ~16 mips for any
  reasonable resolution (`log2(16384) ≈ 14`).
- **Cap `SizeX` / `SizeY` / `SizeZ`** at `MAX_TEXTURE_DIMENSION`
  (typically `16384`) before any allocation. Same hazard as
  documented in [`texture2d.md`](texture2d.md) §*Implementation hardening*.
- **Cap `ElementCount` / `SizeOnDisk`** at
  `MAX_UNCOMPRESSED_ENTRY_BYTES` (8 GiB) before any allocation
  driven by those fields.
- **Use `checked_add` on `OffsetInFile + SizeOnDisk`** before
  any seek-window comparison against the parent file's byte
  count. An `OffsetInFile` near `i64::MAX` plus any nonzero
  `SizeOnDisk` wraps under naive signed arithmetic.
- **Validate `OffsetInFile` is non-negative** before any seek
  (it's signed `i64` on the wire but conceptually unsigned for
  this use).
- **Reject unknown `BulkDataFlags` bits** (bits 18-27, 31) that
  would otherwise propagate uninterpreted state into downstream
  reads. The "valid bits" allow-list MUST be explicit.
- **For `BULKDATA_SerializeCompressedZLIB` mips**, reuse the pak
  zlib decompressor with the same per-block decompression-bomb
  cap; the `ElementCount` field publishes the expected
  decompressed size (verify post-decompress).
- **For `BULKDATA_OptionalPayload` mips** routed to `.uptnl`, a
  reader MUST surface a typed `MissingCompanionFile { kind:
  Uptnl }` error if the `.uptnl` sibling is absent — not silent
  zero-length substitution (matches
  [`../container/iostore-uptnl.md`](../container/iostore-uptnl.md)
  §*Implementation hardening*).

See `docs/security/allocation-caps.md` for the broader policy.

## Verification

- **Fixture:** The Worked example above is byte-exact and
  self-contained for a 36-byte UE 4.20+ `FTexture2DMipMap`
  record (excluding the BulkData payload itself, which lives
  elsewhere in the parent file per `OffsetInFile`). Real-cooked
  texture fixtures (`minimal_texture2d_uncompressed.uasset` with
  inline mip, `_streaming.uasset` with `.ubulk` mip) are Phase 3
  deliverables.
- **Hex anchor commands:**
  ```
  # Synthesize the 36-byte UE 4.20+ FTexture2DMipMap record from the
  # Worked example (bCooked + BulkData header + 64x64x1 dimensions):
  printf '\x01\x00\x00\x00\x01\x00\x00\x00\x00\x10\x00\x00\x00\x10\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x40\x00\x00\x00\x01\x00\x00\x00' | xxd
  ```
  A conformant `FTexture2DMipMap` parser fed these 36 bytes (with
  a parent `.uexp` carrying 4096 bytes of `PF_DXT5` data at offset
  512) MUST decode them as a 64×64×1 inline mip with the standard
  cooked-content flags.
- **Cross-validation oracle:** CUE4Parse[^1] — the
  `FTexture2DMipMap` and `FByteBulkData` constructors row-for-row
  in §*Wire layout* above.
- **Known divergences:** none — no paksmith implementation to
  diverge.

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
