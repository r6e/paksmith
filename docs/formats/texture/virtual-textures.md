# Virtual Textures (`FVirtualTextureBuiltData`)

> Page-table + tile-chunk payload that follows a UTexture2D when its
> `bIsVirtual` flag is set (UE 4.23+). Replaces the standard mip
> chain for textures cooked as virtual textures (sparse, paged,
> tile-streamed).

## Overview

A Virtual Texture (VT) is UE's sparse / paged texture representation:
instead of cooking a full mip chain that all loads into GPU memory,
the cooker emits a virtual address space partitioned into fixed-size
tiles, plus a runtime page-table that maps virtual addresses to
physical tile slots loaded on demand. The on-disk payload is a single
`FVirtualTextureBuiltData` blob written immediately after the standard
`UTexture2D` header (gated by `bIsVirtual` per
[`texture2d.md`](texture2d.md) §*Wire layout*).

The blob itself has three structural pieces:

- **Tile dimensions and layer count** — fixed header (tile size,
  border, layer count, block dimensions).
- **Mip + tile dispatch tables** — counted `u32[]` arrays that map
  a `(mip, tile)` pair to a chunk index + byte offset within that
  chunk. UE5.0 introduced a new dispatch path
  (`TileOffsetData[]` + `BaseOffsetPerMip[]` + `ChunkIndexPerMip[]`)
  that coexists with the legacy path
  (`TileIndexPerChunk[]` + `TileIndexPerMip[]` + `TileOffsetInChunk[]`);
  both arrays are always serialized but only one is populated for a
  given asset (per CUE4Parse's `IsLegacyData()` discriminant on
  `TileOffsetInChunk.Length`).
- **Per-layer pixel formats and chunk data** — `LayerTypes[NumLayers]`
  selects the GPU format per layer (FString-encoded enum names per
  [`pixel-formats.md`](pixel-formats.md)), then a counted
  `FVirtualTextureDataChunk[]` carries the actual tile bytes via
  `FByteBulkData` per chunk.

UE5.0+ adds **layer fallback colors** (`FLinearColor[NumLayers]`,
16 bytes per layer, used when a tile can't be resolved) and **per-chunk
SHA-1 hashes** (20 bytes per chunk, prefixed to each chunk header but
skipped by CUE4Parse without verification).

**Document status: complete.** Wire format documented in full for the
fixed header, both dispatch paths (legacy + UE5.0+), the per-layer
pixel-format array, the per-layer fallback colors (UE5.0+), and the
per-chunk record (`FVirtualTextureDataChunk` with version-conditional
SHA prefix + per-layer codec selection + `FByteBulkData` payload).
The `FVirtualTextureTileOffsetData` sub-record (UE5.0+) is documented
inline. The tile payload bytes inside each chunk's `FByteBulkData` are
opaque GPU-format-dependent data; the codec (`EVirtualTextureCodec`
discriminant) determines the per-tile decode path but the decoded
pixel bytes themselves are out of scope for this format doc (see
[`pixel-formats.md`](pixel-formats.md) for the per-format decode
reference).

**Paksmith parser status: `partial` (flag only).** Phase 3e-VT-a reads the
trailing `bIsVirtual` flag on `UTexture2D` (so virtual textures are
*identified* — `Texture2DData::is_virtual` — rather than silently mis-parsed
as standard textures), but does **not** yet parse the `FVirtualTextureBuiltData`
blob below: 3e-VT-b parses it and 3e-VT-c flattens the page table to pixels.
Virtual Textures are far less common in cooked content than standard streaming
`Texture2D`, so paksmith deferred them past the initial mip-chain support.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| UE 4.23+ | `FVirtualTextureBuiltData` introduced; gated by `Ar.Versions["VirtualTextures"]` on `UTexture2D`. Legacy dispatch path (`TileIndexPerChunk` + `TileIndexPerMip` + `TileOffsetInChunk`) is the only one. | `CUE4Parse/UE4/Assets/Exports/Texture/FVirtualTextureBuiltData.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d`[^1] |
| UE 4.27+ | `FVirtualTextureDataChunk.CodecPayloadOffset` widens from `u16` to `u32`. | Same[^1] |
| UE 5.0+ | New dispatch path added alongside legacy: `TileDataOffsetPerLayer` (early in header), `ChunkIndexPerMip` / `BaseOffsetPerMip` / `TileOffsetData[]` (after `NumMips`/`Width`/`Height`), `LayerFallbackColors[NumLayers]` (after `LayerTypes`). Per-chunk `FSHAHash` (20 bytes) prefixed to each `FVirtualTextureDataChunk` header. | Same[^1] |

## Wire layout

Serialized inline after the standard `UTexture2D` header when
`bIsVirtual == true` (see [`texture2d.md`](texture2d.md) §*Wire layout*
for the parent gate).

### Fixed header

| order | field | size | endian | type | semantics |
|-------|-------|------|--------|------|-----------|
| 1 | `bCooked` | 4 | LE | `u32` (bool) | UE archive `ReadBoolean()` — strict `{0, 1}`. |
| 2 | `NumLayers` | 4 | LE | `u32` | Layer count. Hard cap of 8 per `VIRTUALTEXTURE_DATA_MAXLAYERS` (CUE4Parse asserts `<= 8u`). |
| 3 | `WidthInBlocks` | 4 | LE | `u32` | Width in compressed-block units. |
| 4 | `HeightInBlocks` | 4 | LE | `u32` | Height in compressed-block units. |
| 5 | `TileSize` | 4 | LE | `u32` | Tile edge length in texels (typical: 128 / 256). |
| 6 | `TileBorderSize` | 4 | LE | `u32` | Per-edge border for sampling continuity. Physical tile = `TileSize + 2 × TileBorderSize`. |
| 7 | `TileDataOffsetPerLayer` (UE 5.0+) | variable | LE | `u32[]` (counted) | Per-layer byte offsets within a per-tile data block. Counted (`i32` prefix + `u32 × count`). **Absent below UE 5.0.** |

### Mip dimensions

| order | field | size | endian | type | semantics |
|-------|-------|------|--------|------|-----------|
| 8 | `NumMips` | 4 | LE | `u32` | Mip-level count. |
| 9 | `Width` | 4 | LE | `u32` | Full-resolution width in texels. |
| 10 | `Height` | 4 | LE | `u32` | Full-resolution height in texels. |

### Dispatch tables (UE 5.0+ path, conditional)

Present only when `Ar.Game >= EGame.GAME_UE5_0`:

| order | field | size | endian | type | semantics |
|-------|-------|------|--------|------|-----------|
| 11 | `ChunkIndexPerMip` | variable | LE | `u32[]` (counted) | Per-mip-level index into `Chunks[]`. Counted (`i32` prefix). |
| 12 | `BaseOffsetPerMip` | variable | LE | `u32[]` (counted) | Per-mip-level base byte offset into the chunk. `~0u` sentinel = no data for this mip. |
| 13 | `TileOffsetData` | variable | LE | `FVirtualTextureTileOffsetData[]` (counted) | Per-mip-level tile-address dispatch table (see sub-record below). Counted via `ReadArray(() => new ...)` — `i32` count prefix + per-entry record. |

### Dispatch tables (legacy path, always serialized)

These three arrays are always present on wire (even in UE 5.0+
content) but are populated/empty depending on which dispatch path the
cooker chose. CUE4Parse's `IsLegacyData()` returns `true` when
`TileOffsetInChunk == null || TileOffsetInChunk.Length > 0`:

| order | field | size | endian | type | semantics |
|-------|-------|------|--------|------|-----------|
| 14 | `TileIndexPerChunk` | variable | LE | `u32[]` (counted) | Per-chunk first-tile-index. Counted. Used by legacy-path `GetChunkIndex_Legacy(tileIndex)`. |
| 15 | `TileIndexPerMip` | variable | LE | `u32[]` (counted) | Per-mip first-tile-index. Counted. Used by legacy-path `GetTileIndex_Legacy(vLevel, vAddress)`. |
| 16 | `TileOffsetInChunk` | variable | LE | `u32[]` (counted) | Per-tile byte-offset within its chunk. Counted. **Empty in modern UE 5.0+ content** (and `IsLegacyData()` returns false). |

### Per-layer pixel formats

| order | field | size | endian | type | semantics |
|-------|-------|------|--------|------|-----------|
| 17 | `LayerTypes` | variable | LE | `EPixelFormat[NumLayers]` (fixed length, NOT counted) | Per-layer GPU pixel format. Each entry is an FString naming the `EPixelFormat` enum value (e.g. `"PF_DXT1"`), parsed by `Enum.Parse(typeof(EPixelFormat), Ar.ReadFString())`. The array length is `NumLayers` from field 2 — no `i32` count prefix. See [`pixel-formats.md`](pixel-formats.md) for the enum-name catalog. |

### Per-layer fallback colors (UE 5.0+ only)

| order | field | size | endian | type | semantics |
|-------|-------|------|--------|------|-----------|
| 18 | `LayerFallbackColors` (UE 5.0+) | `16 × NumLayers` | LE | `FLinearColor[NumLayers]` (fixed length, NOT counted) | Per-layer fallback color (4 × `f32` RGBA = 16 bytes each). Array length is `NumLayers` from field 2. Used at runtime when a tile can't be resolved (returns the fallback instead of sampling actual texels). **Absent below UE 5.0.** |

### Chunks (variable count)

| order | field | size | endian | type | semantics |
|-------|-------|------|--------|------|-----------|
| 19 | `Chunks` | variable | — | `FVirtualTextureDataChunk[]` (counted) | Per-chunk tile-payload records. Counted (`i32` prefix + per-entry constructor). See `FVirtualTextureDataChunk` below. |

### `FVirtualTextureTileOffsetData` (UE 5.0+ sub-record)

Modern UE 5.0+ per-mip tile-address dispatch table:

| order | field | size | endian | type | semantics |
|-------|-------|------|--------|------|-----------|
| 1 | `Width` | 4 | LE | `u32` | Tile-grid width at this mip level. |
| 2 | `Height` | 4 | LE | `u32` | Tile-grid height at this mip level. |
| 3 | `MaxAddress` | 4 | LE | `u32` | Maximum virtual address in this mip's range. |
| 4 | `Addresses` | variable | LE | `u32[]` (counted) | Block-start addresses (used as upper-bound search keys for `GetTileOffset(vAddress)`). |
| 5 | `Offsets` | variable | LE | `u32[]` (counted) | Per-block byte offsets aligned with `Addresses[]`. `~0u` sentinel = no data for that block. |

Fixed header is 12 bytes; total varies with `Addresses.Length` and
`Offsets.Length` (both `4 + 4×count`).

### `FVirtualTextureDataChunk` (per-chunk record)

Per-chunk payload entry: SHA prefix (UE 5.0+) + size header + per-layer
codec dispatch + bulk-data payload.

| order | field | size | endian | type | semantics |
|-------|-------|------|--------|------|-----------|
| 1 | `bulkDataHash` (UE 5.0+) | 20 | — | `FSHAHash` | Per-chunk content hash. **CUE4Parse skips this without verification** (`Ar.Position += FSHAHash.SIZE`). Conformant parsers SHOULD verify. **Absent below UE 5.0.** |
| 2 | `SizeInBytes` | 4 | LE | `u32` | Total decompressed/decoded byte length of all tiles in this chunk. |
| 3 | `CodecPayloadSize` | 4 | LE | `u32` | Header-extension payload size carrying per-codec metadata (e.g. compression-method tables). |
| 4 | per-layer (× `NumLayers`) | variable | LE | see semantics | For each of `NumLayers` iterations: `CodecType: u8` (`EVirtualTextureCodec` discriminant — see below) + `CodecPayloadOffset: u32` (UE 4.27+) or `u16` (pre-4.27). `EGame.GAME_DeltaForce` skips the per-layer offset read — see §*Variants — Game-specific quirks* for the dispatch contract. |
| 5 | `BulkData` | variable | — | `FByteBulkData` | Bulk-data record holding the actual tile bytes. See [`../asset/bulk-data.md`](../asset/bulk-data.md) for the full bulk-data layout. |

`EVirtualTextureCodec` (`u8`):

| Value | Name | Semantics |
|-------|------|-----------|
| 0 | `Black` | Special-case codec — all output pixels are `(0,0,0,0)`. |
| 1 | `OpaqueBlack` | All output pixels are `(0,0,0,255)`. |
| 2 | `White` | All output pixels are `(255,255,255,255)`. |
| 3 | `Flat` | All output pixels are `(128,125,255,255)` (flat normal map). |
| 4 | `RawGPU` | Uncompressed data in a GPU-ready format (e.g. R8G8B8A8, BC7, ASTC). |
| 5 | `ZippedGPU_DEPRECATED` | Deprecated — same as `RawGPU` but with zlib payload wrapper. |
| 6 | `Crunch_DEPRECATED` | Deprecated — Crunch-library-compressed data. |
| 7 | `Max` | Sentinel — not a valid codec. |

### Worked example — minimal `FVirtualTextureBuiltData` header (UE 4.27, 1 layer, 0 mips, 0 chunks)

A degenerate 1-layer / 0-mip / 0-chunk virtual texture in UE 4.27
(pre-UE-5 — no `TileDataOffsetPerLayer`, no UE5+ dispatch tables, no
`LayerFallbackColors`, no per-chunk SHA prefix). The legacy dispatch
arrays are empty (`count=0`):

```
Offset  Bytes (LE)                                       Field
------  -----------------------------------------------  -------------------------
+0      01 00 00 00                                      bCooked = 1 (UE archive bool, 4 bytes)
+4      01 00 00 00                                      NumLayers = 1
+8      00 00 00 00                                      WidthInBlocks = 0
+12     00 00 00 00                                      HeightInBlocks = 0
+16     80 00 00 00                                      TileSize = 128
+20     04 00 00 00                                      TileBorderSize = 4
+24     00 00 00 00                                      NumMips = 0
+28     00 00 00 00                                      Width = 0
+32     00 00 00 00                                      Height = 0
+36     00 00 00 00                                      TileIndexPerChunk count = 0 (legacy, empty)
+40     00 00 00 00                                      TileIndexPerMip count = 0 (legacy, empty)
+44     00 00 00 00                                      TileOffsetInChunk count = 0 (legacy, empty)
+48     08 00 00 00                                      LayerTypes[0] FString length = 8 ("PF_DXT1" + NUL)
+52     50 46 5F 44 58 54 31 00                          "PF_DXT1" + NUL
+60     00 00 00 00                                      Chunks count = 0
+64                                                       (end of header — no chunks follow)
```

Total = 64 bytes for the degenerate 0-mip / 0-chunk shell.

A real cooked virtual texture has all three dispatch arrays sized to
`NumMips + 1` or to actual tile counts (typically thousands of `u32`
entries) and at least one chunk carrying a bulk-data payload.

### Worked example — first 12 bytes of `FVirtualTextureTileOffsetData`

The 12-byte fixed header of an `FVirtualTextureTileOffsetData` record
at mip level 0 with `Width = 4, Height = 4, MaxAddress = 16`:

```
Offset  Bytes (LE)         Field
------  ---------------    --------------------
+0      04 00 00 00        Width = 4 (tile-grid)
+4      04 00 00 00        Height = 4 (tile-grid)
+8      10 00 00 00        MaxAddress = 16
+12                         (Addresses + Offsets counted arrays follow)
```

## Variants

### Dispatch-path divergence (legacy vs UE 5.0+)

Both dispatch paths exist in parallel on the wire for UE 5.0+ content.
The chosen path at runtime is determined by `IsLegacyData()`:
`TileOffsetInChunk == null || TileOffsetInChunk.Length > 0` means
legacy; otherwise the UE5.0+ `TileOffsetData[]` is the active path.
Pre-UE-5 content always uses the legacy path (the UE5.0+ fields aren't
serialized).

### Codec-payload offset width (4.27 boundary)

`FVirtualTextureDataChunk.CodecPayloadOffset` is `u32` from UE 4.27
onward, `u16` before. CUE4Parse switches on `Ar.Game >= EGame.GAME_UE4_27`.

### `EVirtualTextureCodec` deprecated variants

`ZippedGPU_DEPRECATED` (5) and `Crunch_DEPRECATED` (6) are still
catalogued in the source's enum but cooked content from any modern UE
should not emit them. A conformant parser MAY reject these codecs or
SHOULD warn and skip the chunk.

### Game-specific quirks

CUE4Parse handles one game-specific deviation in `FVirtualTextureDataChunk`:
`EGame.GAME_DeltaForce` skips the `CodecPayloadOffset` per-layer read
entirely. The per-layer loop reads only `CodecType: u8` for each of
`NumLayers` iterations and advances without consuming the trailing
`u32` / `u16` offset bytes. A conformant parser targeting Delta Force
content MUST replicate this skip; a parser targeting any other game
MUST read the offset (`u32` UE 4.27+ / `u16` pre-4.27) per the field
table in §*Wire layout — `FVirtualTextureDataChunk`*. This is the
only game-specific deviation in `FVirtualTextureBuiltData` — all other
games follow the version-gated dispatch.

### Layer count assertion (CUE4Parse-specific)

CUE4Parse asserts `NumLayers <= 8` (per `VIRTUALTEXTURE_DATA_MAXLAYERS`)
via `Debug.Assert`. Wire-syntactically `NumLayers` is `u32` so the
asserted bound is an engine-level invariant, not a wire-imposed one.
The fixed `LayerTypes[NumLayers]` and (UE 5.0+) `LayerFallbackColors[NumLayers]`
arrays would over-allocate without this cap.

## Caps & limits

### Format-defined limits (wire-imposed)

- **`bCooked`**: 4-byte UE archive bool (`ReadBoolean()` is strict `{0, 1}`).
- **`NumLayers`**: `u32`; engine-asserted ceiling at 8 per `VIRTUALTEXTURE_DATA_MAXLAYERS`.
- **Counted arrays** (`TileIndexPerChunk`, `TileIndexPerMip`, `TileOffsetInChunk`, `TileDataOffsetPerLayer`, `ChunkIndexPerMip`, `BaseOffsetPerMip`, `TileOffsetData`, `Chunks`, plus `Addresses` / `Offsets` inside each `FVirtualTextureTileOffsetData`): `i32` length prefix, fixed-width per entry.
- **Fixed-length arrays** (`LayerTypes`, `LayerFallbackColors`): length is `NumLayers` from field 2; NO `i32` count prefix on wire. `LayerFallbackColors` is 16 bytes per entry; `LayerTypes` is per-entry FString-encoded enum name.
- **`FVirtualTextureDataChunk` header**: variable — 28 + 5 × NumLayers (UE 5.0+, with SHA prefix + `u32` CodecPayloadOffset) or 8 + 5 × NumLayers (UE 4.27, no SHA + `u32` offset) or 8 + 3 × NumLayers (pre-4.27, no SHA + `u16` offset) or **28 + 1 × NumLayers / 8 + 1 × NumLayers** for `EGame.GAME_DeltaForce` content (UE 5.0+ / pre-UE-5 respectively — the per-layer entry is only the 1-byte `CodecType`, no offset field).
- **`FSHAHash`**: fixed 20 bytes per `FSHAHash.SIZE`.
- **`EVirtualTextureCodec`**: `u8`; defined values 0–6 (with 7 = `Max` sentinel).
- **`~0u` sentinel** (`0xFFFFFFFF`): used in `Offsets[]` and `BaseOffsetPerMip[]` to mean "no data for this block / mip".

### Implementation hardening (recommended for any parser)

A virtual-texture reader (paksmith does not yet have one) MUST:

- **Cap `NumLayers`** at the engine-asserted 8. CUE4Parse uses `Debug.Assert` (no runtime check in release); paksmith MUST validate `NumLayers <= 8` and reject larger values to bound the fixed-length `LayerTypes` and `LayerFallbackColors` array allocations.
- **Verify all `i32` count prefixes are non-negative** before allocating the counted arrays. The 8 outer counted arrays plus the 2 inner counted arrays inside each `FVirtualTextureTileOffsetData` are all `i32` on wire; negative values cast to `usize` produce `usize::MAX`-adjacent allocations. Per-array byte-budget: `4 × count` for the `u32[]` arrays; per `FVirtualTextureTileOffsetData` the budget is `12 + 4 + 4 × addresses_count + 4 + 4 × offsets_count = 20 + 4 × (addresses_count + offsets_count)` bytes (12-byte fixed header + 2 separate `i32` count prefixes + per-entry `u32` for each array).
- **Cap individual counted arrays** at a project-defined ceiling. Real cooked VTs have dispatch arrays in the thousands of entries; a `u32::MAX` count would drive a 16 GiB allocation for a single `u32[]` array.
- **Validate `EVirtualTextureCodec`** is in `0..=6` before any per-tile decode dispatch. Codec value 7 (`Max`) is a sentinel; values 8..=255 are wire-valid bytes but undefined codecs. A reader MAY reject any value above 6, or SHOULD warn and skip the chunk for forward-compat. The two deprecated codecs (5, 6) MAY also be rejected — modern UE content shouldn't emit them.
- **Validate `LayerTypes` FString-decoded values** parse as known `EPixelFormat` enum names before storing. `Enum.Parse` would throw on an unknown name; a hostile chunk could carry an arbitrary FString that fails to parse. Reject with a structured error rather than propagating the parse exception.
- **Bounds-check `ChunkIndex` against `Chunks.Length`** before any tile-data dispatch. `GetChunkIndex(vLevel)` returns `(int) ChunkIndexPerMip[vLevel]` cast unchecked — an out-of-range value would index past `Chunks[]`. The dispatch is responsible, not the wire layout, but the parser should validate `ChunkIndexPerMip[i] < Chunks.Length` at parse time.
- **Bounds-check the legacy-path dispatch arrays** for any pre-UE-5 content (or UE 5.0+ content where `IsLegacyData()` returns true): every `TileIndexPerChunk[i]` MUST be `<= TileOffsetInChunk.Length` (each entry is the starting tile-index for chunk `i`; the final entry equals `TileOffsetInChunk.Length` to bound the last chunk). Every `TileIndexPerMip[i]` MUST be `<= TileOffsetInChunk.Length` AND the array MUST be non-decreasing (`TileIndexPerMip[i] <= TileIndexPerMip[i+1]`) — the per-mip first-tile-index is used to bound a half-open range `[TileIndexPerMip[i], TileIndexPerMip[i+1])` of tile indices, so a non-monotonic value lets `GetTileIndex_Legacy` derive a sentinel-comparison-bypassing tile index. An OOB legacy index reads attacker-controlled adjacent memory in the legacy-path dispatch chain.
- **Bounds-check `Offsets[i]` against the addressed chunk's `SizeInBytes`** for any offset that isn't the `~0u` sentinel, **using `checked_add`** for the `BaseOffsetPerMip[mip] + Offsets[tileBlock]` sum. Both fields are `u32`; the sum can wrap and silently pass the `< SizeInBytes` check, producing a small offset that reads from the wrong region of the chunk. An offset past the chunk size would otherwise drive an out-of-bounds tile read.
- **Treat `bulkDataHash` (UE 5.0+) as a content integrity check, not a key-validation oracle**. CUE4Parse currently skips it without verification (`Ar.Position += FSHAHash.SIZE`). A conformant parser SHOULD verify the SHA-1 against the decompressed chunk bytes; a parser that does NOT verify MUST cap the chunk's bulk-data payload size against the parent-asset / parent-container budget before reading.
- **Inherit allocation caps** for the `FByteBulkData` payloads from `MAX_UNCOMPRESSED_ENTRY_BYTES` per [`../asset/bulk-data.md`](../asset/bulk-data.md) §*Implementation hardening*.

See `docs/security/allocation-caps.md` for the broader policy.

## Verification

- **Fixture:** The 64-byte degenerate Worked example above is byte-exact and self-contained for the pre-UE-5 / 1-layer / 0-mip / 0-chunk shell. A real cooked virtual-texture fixture is a Phase 3 deliverable; CUE4Parse's parsing path is the canonical reference for real-world content.
- **Hex anchor command:**
  ```
  # Synthesize the 64-byte degenerate FVirtualTextureBuiltData header
  # (UE 4.27, NumLayers=1, NumMips=0, TileSize=128, TileBorderSize=4, LayerTypes[0]="PF_DXT1", 0 chunks):
  printf '\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x50\x46\x5F\x44\x58\x54\x31\x00\x00\x00\x00\x00' | xxd
  ```
  A conformant virtual-texture parser fed these 64 bytes MUST decode them as a cooked 1-layer header with `TileSize=128`, `TileBorderSize=4`, zero mips, zero chunks, and `LayerTypes[0] = PF_DXT1`.
- **Cross-validation oracle:** CUE4Parse[^1] (sole oracle; no Rust counterpart parses virtual textures).
- **Known divergences:** none — no paksmith implementation to diverge.

## Paksmith implementation

**Flag (3e-VT-a):** `asset/exports/texture/texture2d.rs` reads the trailing
`bIsVirtual` `u32` after the mip records, gated by
`AssetVersion::is_virtual_textures_or_later` (object-version proxy `517` for
the `VirtualTextures` feature; UE5 always). The result is stored as
`Texture2DData::is_virtual`; `crate::export::PngHandler` reports virtual
textures as not-yet-renderable.

**Blob parser module:** *(not yet implemented — planned under
`crates/paksmith-core/src/asset/exports/texture/virtual_textures.rs`, called
from `texture2d.rs` when `bIsVirtual == true`, in milestone 3e-VT-b)*

**Status:** `partial` — `bIsVirtual` flag read (3e-VT-a); the
`FVirtualTextureBuiltData` blob parse (3e-VT-b) + page-table flatten to PNG
(3e-VT-c) are pending.

**Phase plan:** `docs/plans/phase-3e-texture-export.md` milestone 3e-VT.

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Exports/Texture/FVirtualTextureBuiltData.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` (top-level constructor + `IsLegacyData()` discriminant + per-tile-address dispatch), `FVirtualTextureDataChunk.cs` (per-chunk record with `EVirtualTextureCodec` catalog and version-conditional UE 4.27 / UE 5.0+ widening). `FByteBulkData` per [`../asset/bulk-data.md`](../asset/bulk-data.md); `EPixelFormat` enum-name list per [`pixel-formats.md`](pixel-formats.md); `FSHAHash` per `Objects/Core/Misc/FSHAHash.cs` (fixed 20 bytes).
