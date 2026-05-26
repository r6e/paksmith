# IoStore `.utoc` (Table of Contents)

> Index file for an IoStore container — the metadata sidecar that maps
> chunk IDs to byte offsets in the `.ucas` data file.

## Overview

IoStore is Unreal Engine's replacement for `.pak`, introduced in UE 4.27
and the dominant shipped-game container format from UE 5.x onward. A single
IoStore container comprises two coupled files (always at the same path
prefix):

- **`.utoc`** — Table of Contents. Holds the chunk-ID index, container
  metadata, encryption parameters, and compression-block descriptors.
- **`.ucas`** — Container As-Stream. The bulk data file; chunk payloads
  concatenated.

A third sidecar, `.uptnl` (Optional Container Data), is also part of the
IoStore trio for patch / optional content distribution. See
[`iostore-ucas.md`](iostore-ucas.md) and [`iostore-uptnl.md`](iostore-uptnl.md).

**Document status: complete.** Wire format documented in full
for the TOC header, per-chunk records (`FIoChunkId`,
`FIoOffsetAndLength`), compression-block table, compression-method
table, optional perfect-hash arrays, optional signature block, and
optional directory-index / per-chunk metadata sections. All cross-
validated against CUE4Parse at the pinned SHA[^1]. The full
`FIoStoreTocEntryMeta` byte layout (per-chunk SHA-1 hash + flags)
is summarized at the table-row level; the `FIoChunkHash` /
`FSHAHash` discriminant variance under
`ReplaceIoChunkHashWithIoHash` (TOC v8) is called out in
§*Variants*.

**Paksmith parser status: `not impl`.** No IoStore parser yet —
Phase 8 deliverable. This doc serves as the reference for that
implementation work; it does not depend on the parser existing.

## Versions

The TOC header carries an `EIoStoreTocVersion: u8` discriminant.
Known versions (per `FIoStoreTocHeader.cs`[^1]):

| Value | `EIoStoreTocVersion` name | Wire-format change |
|-------|---------------------------|---------------------|
| 0 | `Invalid` | Sentinel — never on disk. |
| 1 | `Initial` | First shipping format (UE 4.27). Header + chunk-IDs + offset+length + compression-blocks + compression-methods + (optional) signature. |
| 2 | `DirectoryIndex` | Adds an optional directory-index buffer (when `EIoContainerFlags::Indexed` is set). |
| 3 | `PartitionSize` | Adds `PartitionCount: u32` and `PartitionSize: u64` to the header. Pre-`PartitionSize` readers MUST default `PartitionCount = 1` and `PartitionSize = u64::MAX`. |
| 4 | `PerfectHash` | Adds a `ChunkPerfectHashSeeds: i32[TocChunkPerfectHashSeedsCount]` array between offset+length and compression-blocks. |
| 5 | `PerfectHashWithOverflow` | Adds a `ChunkIndicesWithoutPerfectHash: i32[TocChunksWithoutPerfectHashCount]` overflow array immediately after the perfect-hash seeds. |
| 6 | `OnDemandMetaData` | Adds (when `EIoContainerFlags::OnDemand` is set, ONLY at this exact version) two trailing FSHAHash arrays: per-chunk and per-compressed-block on-demand metadata. |
| 7 | `RemovedOnDemandMetaData` | Removes the v6 on-demand trailers; header schema unchanged otherwise. |
| 8 | `ReplaceIoChunkHashWithIoHash` (current Latest) | `FIoStoreTocEntryMeta.ChunkHash` switches from `FIoChunkHash` (32 bytes) to `FSHAHash` (20 bytes); a 3-byte pad follows the flags byte to preserve the per-meta record alignment. |
| 9 | `LatestPlusOne` | Sentinel — never on disk. |

A reader MUST reject `Version == 0` or `Version >= LatestPlusOne`
as wire-format-invalid; intermediate values are forward-readable
because each newer version is a strict superset of the previous.

## Wire layout

A `.utoc` file is a fixed 144-byte header followed by an ordered
run of variable-length sections; each section's presence and length
is derived from header fields. All multi-byte integers are
little-endian unless explicitly noted (`FIoOffsetAndLength` uses
big-endian — see below).

### Header (`FIoStoreTocHeader`, fixed 144 bytes)

| offset | size | endian | name | type | semantics |
|--------|------|--------|------|------|-----------|
| 0 | 16 | — | `TocMagic` | `[u8; 16]` | MUST equal `2D 3D 3D 2D 2D 3D 3D 2D 2D 3D 3D 2D 2D 3D 3D 2D` (ASCII `-==--==--==--==-`). |
| 16 | 1 | — | `Version` | `u8` | `EIoStoreTocVersion` discriminant (1-8 valid per §*Versions*). |
| 17 | 1 | — | `_reserved0` | `u8` | Padding; readers ignore. |
| 18 | 2 | LE | `_reserved1` | `u16` | Padding; readers ignore. |
| 20 | 4 | LE | `TocHeaderSize` | `u32` | Self-check field. Currently `144`; a reader MUST reject mismatches. |
| 24 | 4 | LE | `TocEntryCount` | `u32` | Number of chunks (sizes the `ChunkIds`, `ChunkOffsetLengths`, and optional `ChunkMetas` arrays). |
| 28 | 4 | LE | `TocCompressedBlockEntryCount` | `u32` | Number of compression-block entries. |
| 32 | 4 | LE | `TocCompressedBlockEntrySize` | `u32` | Self-check field. Currently `12`; a reader MUST reject mismatches. |
| 36 | 4 | LE | `CompressionMethodNameCount` | `u32` | Number of compression-method names (NOT counting the implicit slot 0 = `None`). |
| 40 | 4 | LE | `CompressionMethodNameLength` | `u32` | Per-name byte length (typically `32`). |
| 44 | 4 | LE | `CompressionBlockSize` | `u32` | Uncompressed bytes per compression block (typically `64 KiB`). |
| 48 | 4 | LE | `DirectoryIndexSize` | `u32` | Byte length of the optional directory-index payload (`0` if no index). |
| 52 | 4 | LE | `PartitionCount` | `u32` | Multi-partition container support (TOC v3+); pre-v3 readers MUST set this to `1`. |
| 56 | 8 | LE | `ContainerId` | `u64` (`FIoContainerId`) | Stable per-container identifier. |
| 64 | 16 | LE | `EncryptionKeyGuid` | `[u8; 16]` (`FGuid`) | AES-256 key identifier (zero when not encrypted); 4-`u32`-LE layout per [`../primitive/fguid.md`](../primitive/fguid.md). Key resolution (footer-GUID → `Crypto.json` entry → 32-byte AES key) follows the same conventions documented in [`../crypto/aes-pak.md`](../crypto/aes-pak.md) §*`Crypto.json` (UE 4.20+ key-file format)*. |
| 80 | 4 | LE | `ContainerFlags` | `u32` (`EIoContainerFlags` bitmask) | Bit 0 `Compressed`, bit 1 `Encrypted`, bit 2 `Signed`, bit 3 `Indexed`, bit 4 `OnDemand`. |
| 84 | 4 | LE | `TocChunkPerfectHashSeedsCount` | `u32` | Length of the optional perfect-hash seed array (TOC v4+). |
| 88 | 8 | LE | `PartitionSize` | `u64` | Bytes per partition (TOC v3+); pre-v3 readers MUST set this to `u64::MAX`. |
| 96 | 4 | LE | `TocChunksWithoutPerfectHashCount` | `u32` | Length of the optional perfect-hash-overflow array (TOC v5+). |
| 100 | 4 | LE | `_reserved7` | `u32` | Padding; readers ignore. |
| 104 | 40 | LE | `_reserved8` | `[u64; 5]` | Padding; readers ignore. |
| 144 | — | — | (end of header) | | The TOC body sections follow contiguously. |

After the header, the body sections appear in this fixed order
(presence gated by version + flags):

### Chunk-ID array (`FIoChunkId[TocEntryCount]`, 12 bytes each)

Each `FIoChunkId` is a 12-byte packed struct:

| offset (in chunk-id) | size | endian | name | type | semantics |
|----------------------|------|--------|------|------|-----------|
| 0 | 8 | LE | `ChunkId` | `u64` | Stable chunk identifier (often an `FPackageId` hash). |
| 8 | 2 | **BE** | `ChunkIndex` | `u16` | Per-chunk index (network byte order — bytes swapped on read; see code note below). |
| 10 | 1 | — | `_padding` | `u8` | Always zero. |
| 11 | 1 | — | `ChunkType` | `u8` | `EIoChunkType` (UE4) or `EIoChunkType5` (UE5+) discriminant. |

The `ChunkIndex` byte-swap is a UE convention — it stays
network-order on disk and gets host-swapped at read time. A reader
MUST byte-swap (e.g. `u16::from_be_bytes`) when decoding the
2-byte field at offset 8.

The `ChunkType` enum varies by UE major version:

| Value | `EIoChunkType` (UE4) | `EIoChunkType5` (UE5+) | Extension hint |
|-------|----------------------|------------------------|----------------|
| 0 | `Invalid` | `Invalid` | — |
| 1 | `InstallManifest` | `ExportBundleData` | `.uasset` / `.umap` |
| 2 | `ExportBundleData` | `BulkData` | `.uexp` / `.ubulk` |
| 3 | `BulkData` | `OptionalBulkData` | `.ubulk` / `.uptnl` |
| 4 | `OptionalBulkData` | `MemoryMappedBulkData` | `.uptnl` / `.m.ubulk` |
| 5 | `MemoryMappedBulkData` | `ScriptObjects` | `.m.ubulk` / — |
| 6 | `LoaderGlobalMeta` | `ContainerHeader` | — |
| 7 | `LoaderInitialLoadMeta` | `ExternalFile` | — |
| 8 | `LoaderGlobalNames` | `ShaderCodeLibrary` | — / `.ushaderbytecode` |
| 9 | `LoaderGlobalNameHashes` | `ShaderCode` | — / `.dxbc` |
| 10 | `ContainerHeader` | `PackageStoreEntry` | — |
| 11 | — | `DerivedData` | — |
| 12 | — | `EditorDerivedData` | — |
| 13 | — | `PackageResource` | — |

### Offset+Length array (`FIoOffsetAndLength[TocEntryCount]`, 10 bytes each)

Each entry is a packed 10-byte record with two **big-endian** 40-bit
fields (the only BE encoding in the entire `.utoc`):

| offset (in record) | size | endian | name | type | semantics |
|--------------------|------|--------|------|------|-----------|
| 0 | 5 | **BE** | `Offset` | `u40` | Byte offset into the `.ucas` (or `.uptnl` for `Optional`-flagged chunks). Max `(1<<40)-1` = 1 TiB. |
| 5 | 5 | **BE** | `Length` | `u40` | Uncompressed byte length of the chunk. Max 1 TiB. |

A reader unpacks each field as
`((b[0] as u64) << 32) | ((b[1] as u64) << 24) | ((b[2] as u64) << 16) | ((b[3] as u64) << 8) | (b[4] as u64)`.

### Perfect-hash sections (optional, TOC v4+)

| TOC version | Section | Type | Length |
|-------------|---------|------|--------|
| `>= PerfectHash (4)` | `ChunkPerfectHashSeeds` | `i32[]` LE | `TocChunkPerfectHashSeedsCount` entries |
| `>= PerfectHashWithOverflow (5)` | `ChunkIndicesWithoutPerfectHash` | `i32[]` LE | `TocChunksWithoutPerfectHashCount` entries |

The perfect-hash arrays support O(1) chunk-ID lookup via FNV-1a-
style hashing keyed by seed; the overflow array carries chunk
indices the perfect-hash function couldn't place.

### Compression-block table (`FIoStoreTocCompressedBlockEntry[TocCompressedBlockEntryCount]`, 12 bytes each)

Each entry is a packed 12-byte record:

| offset (in entry) | size | endian | name | type | semantics |
|-------------------|------|--------|------|------|-----------|
| 0 | 5 | LE | `Offset` | `u40` | Byte offset into the `.ucas` partition where the compressed block starts. Max 1 TiB. |
| 5 | 3 | LE | `CompressedSize` | `u24` | On-disk byte count of this compression block. Max `(1<<24)-1` = 16 MiB-1. |
| 8 | 3 | LE | `UncompressedSize` | `u24` | Decompressed byte count (always `<= CompressionBlockSize` header field; only the final block of a chunk may be short). |
| 11 | 1 | — | `CompressionMethodIndex` | `u8` | Index into the compression-method table (`0` = `None`, `1..=CompressionMethodNameCount` = a named method). |

Unpacking: reads a `u64` LE at offset 0 and masks `(1<<40)-1` for
`Offset`; reads a `u32` LE at offset 4 and `(value >> 8) & 0x00FFFFFF`
for `CompressedSize`; reads a `u32` LE at offset 8 and
`value & 0x00FFFFFF` for `UncompressedSize`; takes the high byte of
the same `u32` for `CompressionMethodIndex`.

### Compression-method name table (`u8[CompressionMethodNameLength × CompressionMethodNameCount]`)

A contiguous run of `CompressionMethodNameCount` fixed-width name
slots; each slot is `CompressionMethodNameLength` bytes (typically
`32`), holding a null-padded ASCII codec name (e.g. `"Zlib"`,
`"Oodle"`, `"LZ4"`). Empty slots are valid (treated as `None`).

The implicit slot 0 (= `CompressionMethod::None`) is NOT present
on disk; readers prepend it logically so a `CompressionMethodIndex`
of `0` maps to "uncompressed".

### Signature block (optional, when `EIoContainerFlags::Signed` is set)

When the `Signed` flag is set in `ContainerFlags`, an
RSA-signed manifest follows the compression-method table:

| offset (in section) | size | endian | name | type | semantics |
|---------------------|------|--------|------|------|-----------|
| 0 | 4 | LE | `HashSize` | `i32` | Byte length of each signature blob. |
| 4 | `HashSize` | — | `TocSignature` | `[u8; HashSize]` | RSA signature over the TOC body up to this point. |
| 4 + HashSize | `HashSize` | — | `BlockSignature` | `[u8; HashSize]` | RSA signature over the per-block hash array. |
| 4 + 2×HashSize | 20 × `TocCompressedBlockEntryCount` | — | `ChunkBlockSignature` | `FSHAHash[TocCompressedBlockEntryCount]` | Per-compression-block SHA-1 hash (20 bytes each). |

paksmith readers MAY skip signature verification by advancing the
cursor `HashSize + HashSize + 20*TocCompressedBlockEntryCount`
bytes; CUE4Parse takes that path. Production readers SHOULD
verify both signatures.

### Directory-index buffer (optional, TOC v2+ + `Indexed` flag + `DirectoryIndexSize > 0`)

When the `Indexed` flag is set in `ContainerFlags`, the
`DirectoryIndexSize` bytes that follow encode a virtual-path-to-
chunk-ID directory tree. The tree consists of three FName-style
tables (directory entries, file entries, string table) per
`FIoDirectoryIndexResource`; the per-entry record types are
`FIoDirectoryIndexEntry` and `FIoFileIndexEntry`. Full byte-level
documentation of this sub-format is in
[`iostore-directory-index.md`](iostore-directory-index.md); readers
that don't need path lookup MAY skip the entire buffer via
`cursor += DirectoryIndexSize`.

### Chunk-meta array (`FIoStoreTocEntryMeta[TocEntryCount]`, optional)

The per-chunk metadata array is at the very end of the file. CUE4Parse
only reads it when `EIoStoreTocReadOptions::ReadTocMeta` is set; the
section is always present in a complete `.utoc` but its presence is
indicated implicitly (residual bytes after all required sections).
Each `FIoStoreTocEntryMeta` is:

| TOC version | Layout | Total bytes |
|-------------|--------|-------------|
| `< ReplaceIoChunkHashWithIoHash (8)` | `FIoChunkHash` (32 bytes) + `FIoStoreTocEntryMetaFlags: u8` (bit 0 `Compressed`, bit 1 `MemoryMapped`) | 33 bytes |
| `>= ReplaceIoChunkHashWithIoHash (8)` | `FSHAHash` (20 bytes) + `FIoStoreTocEntryMetaFlags: u8` + 3 bytes padding | 24 bytes |

### OnDemand metadata (optional, ONLY at TOC v6 with `OnDemand` flag)

When `Version == OnDemandMetaData` exactly AND `OnDemand` flag is
set, two final trailing arrays appear:

- `OnDemandChunkMeta: FIoHash[TocEntryCount]` (20 bytes each)
- `OnDemandCompressedBlockMeta: FIoHash[TocCompressedBlockEntryCount]` (20 bytes each)

TOC v7+ removes these trailers (the `RemovedOnDemandMetaData`
discriminant marks the removal).

### Worked example — minimal header (144 bytes)

A `.utoc` header for a single-chunk, single-block, uncompressed,
non-encrypted, non-indexed container at TOC v3 (`PartitionSize`):

```
Offset  Bytes (LE; multi-byte annotated)                  Field
------  ------------------------------------------------  -------------------------
+0      2D 3D 3D 2D 2D 3D 3D 2D 2D 3D 3D 2D 2D 3D 3D 2D  TocMagic = "-==--==--==--==-"
+16     03                                                Version = 3 (PartitionSize)
+17     00                                                _reserved0
+18     00 00                                             _reserved1
+20     90 00 00 00                                       TocHeaderSize = 144
+24     01 00 00 00                                       TocEntryCount = 1
+28     01 00 00 00                                       TocCompressedBlockEntryCount = 1
+32     0C 00 00 00                                       TocCompressedBlockEntrySize = 12
+36     01 00 00 00                                       CompressionMethodNameCount = 1
+40     20 00 00 00                                       CompressionMethodNameLength = 32
+44     00 00 01 00                                       CompressionBlockSize = 65536
+48     00 00 00 00                                       DirectoryIndexSize = 0
+52     01 00 00 00                                       PartitionCount = 1
+56     EF BE AD DE 00 00 00 00                           ContainerId = 0xDEADBEEF (u64 LE)
+64     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  EncryptionKeyGuid = {00000000-0000-0000-0000-000000000000}
+80     00 00 00 00                                       ContainerFlags = 0 (no flags set)
+84     00 00 00 00                                       TocChunkPerfectHashSeedsCount = 0
+88     00 00 00 00 00 00 00 00                           PartitionSize = 0 (irrelevant when PartitionCount=1)
+96     00 00 00 00                                       TocChunksWithoutPerfectHashCount = 0
+100    00 00 00 00                                       _reserved7
+104    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  _reserved8[0..2]
+120    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  _reserved8[2..4]
+136    00 00 00 00 00 00 00 00                           _reserved8[4]
+144                                                       (end of header — TOC body starts)
```

### Worked example — `FIoChunkId` (12 bytes, demonstrates BE chunkIndex)

A chunk ID with `ChunkId = 0x1234567890ABCDEF`,
`ChunkIndex = 0x0001` (= 1), `ChunkType = 2` (`ExportBundleData`
on UE4, `BulkData` on UE5):

```
Offset  Bytes (wire)              Field
------  ------------------------  --------------------
+0      EF CD AB 90 78 56 34 12   ChunkId = 0x1234567890ABCDEF (u64 LE)
+8      00 01                     ChunkIndex = 0x0001 (u16 BE — on host: u16::from_be_bytes([0x00, 0x01]))
+10     00                        _padding
+11     02                        ChunkType = 2 (ExportBundleData / BulkData)
```

### Worked example — `FIoOffsetAndLength` (10 bytes, BE 40-bit pair)

A chunk located at `.ucas` offset `0x0000000400` (= 1024 bytes)
with uncompressed length `0x0000001000` (= 4096 bytes):

```
Offset  Bytes (BE)                Field
------  ------------------------  --------------------
+0      00 00 00 04 00            Offset = 0x0000000400 = 1024 (u40 BE — high byte first)
+5      00 00 00 10 00            Length = 0x0000001000 = 4096 (u40 BE)
```

Note the big-endian byte order is unique to this record type
within `.utoc` — every other multi-byte field uses LE.

### Worked example — `FIoStoreTocCompressedBlockEntry` (12 bytes, packed)

A compression-block entry pointing at `.ucas` offset
`0x0000010000` (= 64 KiB) carrying a 1024-byte zlib-compressed block
that decompresses to 4096 bytes:

```
Offset  Bytes (wire)              Field
------  ------------------------  --------------------
+0      00 00 01 00 00            Offset = 0x0000010000 = 65536 (u40 LE)
+5      00 04 00                  CompressedSize = 0x000400 = 1024 (u24 LE)
+8      00 10 00                  UncompressedSize = 0x001000 = 4096 (u24 LE)
+11     01                        CompressionMethodIndex = 1 (e.g. "Zlib", if it's slot 1)
```

## Variants

Variation has two orthogonal axes:

### `EIoStoreTocVersion` (header field)

See §*Versions* for the full enum. Each later version is a strict
superset; readers gate optional sections on the version
discriminant.

### `EIoContainerFlags` (header field, bitmask)

| Bit | Flag | Effect on layout |
|-----|------|------------------|
| 0 | `Compressed` | Per-block compression in effect (compression-method indices in the block table may be non-zero). |
| 1 | `Encrypted` | Per-block AES-256 ECB encryption (key identified by `EncryptionKeyGuid`). |
| 2 | `Signed` | Signature block present after the compression-method table. |
| 3 | `Indexed` | Directory-index buffer present (requires TOC v2+). |
| 4 | `OnDemand` | OnDemand metadata trailers present (requires TOC v6 exactly). |

## Caps & limits

### Format-defined limits (wire-imposed)

- **`TocMagic`**: fixed 16 bytes; any deviation is wire-invalid.
- **`Version`**: `u8` discriminant; valid range `1..=8` currently
  (see §*Versions* table). `0` and `>=9` are wire-invalid.
- **`TocHeaderSize`**: must equal `144` (fixed by the header schema).
- **`TocCompressedBlockEntrySize`**: must equal `12` (matches the
  packed `FIoStoreTocCompressedBlockEntry` layout).
- **`FIoOffsetAndLength.Offset`** and **`FIoOffsetAndLength.Length`**:
  40-bit BE fields, max `(1<<40)-1` ≈ 1 TiB each.
- **`FIoStoreTocCompressedBlockEntry.Offset`**: 40-bit LE field,
  max 1 TiB.
- **`FIoStoreTocCompressedBlockEntry.CompressedSize`** and
  **`UncompressedSize`**: 24-bit LE fields, max
  `(1<<24)-1` ≈ 16 MiB-1 per block.
- **`FIoStoreTocCompressedBlockEntry.CompressionMethodIndex`**:
  `u8`, max representable value `255`. (The valid-range
  validation against the actual `CompressionMethodNameCount` is
  parser policy — see §*Implementation hardening*.)
- **`CompressionMethodNameLength`**: typically `32`; readers MUST
  use the header field, not hard-code `32`.
- **`EIoContainerFlags`**: `u32`; bits 0-4 currently allocated.
  Bits 5-31 SHOULD be zero on conformant writers.
- **`FIoChunkId`**: 12 bytes packed; `ChunkIndex` is BE on disk.

### Implementation hardening (recommended for any parser)

A `.utoc` reader (paksmith does not yet have one) MUST cap before
allocation:

- **`TocEntryCount`**: cap before allocating
  `Vec<FIoChunkId>` / `Vec<FIoOffsetAndLength>` / per-chunk metas.
  A 4 GiB-claim `u32` would drive 12 × `TocEntryCount` bytes of
  chunk-ID allocation alone (~48 GiB at the worst case).
- **`TocCompressedBlockEntryCount`**: cap before allocating
  `Vec<FIoStoreTocCompressedBlockEntry>`. 12 × count bytes; same
  hazard as above.
- **`CompressionMethodNameCount` × `CompressionMethodNameLength`**:
  cap the product before allocating the contiguous name buffer. A
  `CompressionMethodNameLength` of `u32::MAX` would otherwise drive
  a 4 GiB allocation for a single name.
- **`DirectoryIndexSize`**: cap before reading. A `u32::MAX`
  size_on_disk claim would drive a 4 GiB read.
- **`PartitionSize`**: validate that
  `PartitionCount * PartitionSize` doesn't overflow `u64` and stays
  within a project-defined ceiling. Use `checked_mul` before any
  partition-arithmetic check. Additionally MUST reject
  `PartitionSize == 0 AND PartitionCount > 1` at parse time — a
  reader that proceeds would divide-by-zero on
  `partition_index = block.Offset / PartitionSize`
  (see [`iostore-ucas.md`](iostore-ucas.md) §*Partitioned layout*).
- **`CompressionMethodIndex` range**: validate
  `index <= CompressionMethodNameCount` before indexing the method
  table (slot 0 = implicit `None`; slots `1..=CompressionMethodNameCount`
  are named methods). A malformed TOC with `index = 255` and a
  table of 4 named methods would otherwise out-of-bounds-access.
- **Offset + length arithmetic**: all `Offset + Length` (or
  `Offset + CompressedSize`) sums against the `.ucas` size must use
  `checked_add` to defeat the near-`u64::MAX` wraparound attack.
- **`TocChunkPerfectHashSeedsCount`** and
  **`TocChunksWithoutPerfectHashCount`**: cap before allocating the
  `i32[]` arrays.
- **`HashSize` in signature block**: cap before reading the
  signature bytes (an attacker-supplied `i32::MAX` would drive a
  2 GiB allocation).
- **Magic-byte validation**: MUST reject mismatches before
  proceeding to the version byte. A reader that proceeds without
  magic validation can interpret an unrelated file as a TOC.
- **Per-block decompression cap**: inherit
  `MAX_UNCOMPRESSED_ENTRY_BYTES = 8 GiB` from the pak side as the
  cumulative per-chunk decompressed budget; bound each individual
  block at `CompressionBlockSize`.

See `docs/security/allocation-caps.md` for the broader policy that
the planned Phase 8 caps will follow.

## Verification

- **Fixture:** The minimal-header Worked example above is byte-exact
  and self-contained — synthesizing just the 144-byte header is
  sufficient to exercise magic validation, version parsing, and the
  `TocHeaderSize` self-check. A real-cooked `.utoc` (with
  `.ucas` companion) for end-to-end cross-validation is a Phase 8
  deliverable.
- **Hex anchor commands:**
  ```
  # Synthesize the 16-byte TOC magic:
  printf '\x2D\x3D\x3D\x2D\x2D\x3D\x3D\x2D\x2D\x3D\x3D\x2D\x2D\x3D\x3D\x2D' | xxd
  # Synthesize the 12-byte FIoChunkId from the Worked example:
  printf '\xEF\xCD\xAB\x90\x78\x56\x34\x12\x00\x01\x00\x02' | xxd
  # Synthesize the 12-byte FIoStoreTocCompressedBlockEntry from the Worked example:
  printf '\x00\x00\x01\x00\x00\x00\x04\x00\x00\x10\x00\x01' | xxd
  ```
  A conformant `.utoc` reader fed these bytes at the matching
  offsets MUST decode them as the values shown in the Worked
  examples.
- **Cross-validation oracle:** CUE4Parse's `FIoStoreTocResource`,
  `FIoStoreTocHeader`, `FIoChunkId`, `FIoOffsetAndLength`,
  `FIoStoreTocCompressedBlockEntry`, and `FIoStoreTocEntryMeta`[^1]
  — the full layout cited row-by-row in §*Wire layout* above.
  `trumank/repak` has no IoStore coverage; CUE4Parse is the
  sole external Rust-adjacent oracle (the project is C# but its
  byte layouts are wire-faithful).
- **Known divergences:** none — no paksmith implementation to
  diverge.

## Paksmith implementation

**Parser module:** *(not yet implemented — planned under `crates/paksmith-core/src/container/iostore/`)*

**Status:** `not impl`.

**Phase plan:** `docs/plans/ROADMAP.md` Phase 8 (IoStore Support).

The Phase 8 parser SHOULD follow this doc's wire layout
row-for-row. Worked examples here are intended as test fixtures
for the implementation work.

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/IO/Objects/FIoStoreTocHeader.cs@ecc4878950336126f125af0747190edf474b2a21` (header + `EIoStoreTocVersion` + `EIoContainerFlags`), `FIoChunkId.cs` (chunk-ID + `EIoChunkType` / `EIoChunkType5`), `FIoOffsetAndLength.cs` (BE 40-bit pair), `FIoStoreTocCompressedBlockEntry.cs` (packed 12-byte entry), `FIoStoreTocResource.cs` (top-level read order + section gating), `FIoStoreTocEntryMeta.cs` (per-chunk metadata variant under TOC v8), all at the same pinned SHA. `IoStoreReader.cs` covers the end-to-end open flow.
