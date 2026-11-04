# IoStore `.utoc` (Table of Contents)

> Index file for an IoStore container — the metadata sidecar that maps
> chunk IDs to the compression blocks that hold their bytes in the
> `.ucas` data file.

## Overview

An IoStore container is a `.utoc` and its `.ucas` data, at the same path
prefix:

- **`.utoc`** — Table of Contents. Holds the chunk-ID index, container
  metadata, encryption parameters, and compression-block descriptors.
- **`.ucas`** — Container As-Stream. The bulk data file; chunk payloads
  concatenated.

**Document status: complete.** Wire format documented in full
for the TOC header, per-chunk records (`FIoChunkId`,
`FIoOffsetAndLength`), compression-block table, compression-method
table, optional perfect-hash arrays, optional signature block, and
optional directory-index / per-chunk metadata sections. All cross-
validated against CUE4Parse[^1][^3]. The full
`FIoStoreTocEntryMeta` byte layout (per-chunk hash + flags)
is summarized at the table-row level; the `FIoChunkHash` /
`FSHAHash` discriminant variance under
`ReplaceIoChunkHashWithIoHash` (TOC v8) is called out in
§*Chunk-meta array*.

**Paksmith parser status: `not impl`.** No IoStore parser yet —
Phase 8 deliverable. This doc serves as the reference for that
implementation work; it does not depend on the parser existing.

## Versions

The TOC header carries an `EIoStoreTocVersion: u8` discriminant.
Known versions (per `FIoStoreTocHeader.cs`[^1][^3]):

| Value | `EIoStoreTocVersion` name | Wire-format change |
|-------|---------------------------|---------------------|
| 0 | `Invalid` | Sentinel. |
| 1 | `Initial` | First format (retoc maps no release to it[^2]). Header + chunk-IDs + offset+length + compression-blocks + compression-methods + (optional) signature. |
| 2 | `DirectoryIndex` | Adds an optional directory-index buffer (when `EIoContainerFlags::Indexed` is set). |
| 3 | `PartitionSize` | Adds `PartitionCount: u32` and `PartitionSize: u64` to the header. Pre-`PartitionSize` readers MUST default `PartitionCount = 1` and `PartitionSize = u64::MAX`. |
| 4 | `PerfectHash` | Adds a `ChunkPerfectHashSeeds: i32[TocChunkPerfectHashSeedsCount]` array between offset+length and compression-blocks. |
| 5 | `PerfectHashWithOverflow` | Adds a `ChunkIndicesWithoutPerfectHash: i32[TocChunksWithoutPerfectHashCount]` overflow array immediately after the perfect-hash seeds. |
| 6 | `OnDemandMetaData` | Adds (when `EIoContainerFlags::OnDemand` is set, ONLY at this exact version) two trailing FSHAHash arrays: per-chunk and per-compressed-block on-demand metadata. |
| 7 | `RemovedOnDemandMetaData` | Removes the v6 on-demand trailers; header schema unchanged otherwise. |
| 8 | `ReplaceIoChunkHashWithIoHash` | `FIoStoreTocEntryMeta.ChunkHash` switches from `FIoChunkHash` (32 bytes) to `FSHAHash` (20 bytes), and 3 padding bytes follow the flags byte. |
| 9 | `AddedSourceHashes` | Newer CUE4Parse[^3] defines it; its TOC reader takes the same branches at 9 as at 8. |
| 10 | `ContainerEncryptionMethod` | Newer CUE4Parse[^3] defines it and, from this version, takes the encryption method from header byte 81 (below it, `Encrypted` alone selects AES-ECB). With AES-CTR, an array of 12-byte IVs follows the compression-block table, one per compression block and then one for the directory index when `Indexed` is set. The reader rejects a TOC whose `EncryptionIVCount` (read from header offset 104 for `GAME_UE6_0` and later game profiles, 0 otherwise) differs from that count. |

## Wire layout

A `.utoc` file is a fixed 144-byte header followed by an ordered
run of variable-length sections. All multi-byte integers are
little-endian unless explicitly noted (`FIoOffsetAndLength` uses
big-endian — see below).

### Header (`FIoStoreTocHeader`, fixed 144 bytes)

| offset | size | endian | name | type | semantics |
|--------|------|--------|------|------|-----------|
| 0 | 16 | — | `TocMagic` | `[u8; 16]` | MUST equal `2D 3D 3D 2D 2D 3D 3D 2D 2D 3D 3D 2D 2D 3D 3D 2D` (ASCII `-==--==--==--==-`). |
| 16 | 1 | — | `Version` | `u8` | `EIoStoreTocVersion` discriminant (per §*Versions*). |
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
| 64 | 16 | LE | `EncryptionKeyGuid` | `[u8; 16]` (`FGuid`) | AES-256 key identifier (zero when not encrypted); 4-`u32`-LE layout per [`../primitive/fguid.md`](../primitive/fguid.md). |
| 80 | 1 | — | `ContainerFlags` | `u8` (`EIoContainerFlags` bitmask)[^1][^2][^3] | Bit 0 `Compressed`, bit 1 `Encrypted`, bit 2 `Signed`, bit 3 `Indexed`, bit 4 `OnDemand`. |
| 81 | 1 | — | `EncryptionMethod` | `u8` (`EIoEncryptionMethod`) | From TOC v10, newer CUE4Parse[^3] takes this byte as `EIoEncryptionMethod` (`0` `None`, `1` `AES`, `2` `AES_CTR`); only `2` changes how an `Encrypted` container is decrypted (see §*Versions*). |
| 82 | 2 | LE | `_reserved4` | `u16` | Reserved. |
| 84 | 4 | LE | `TocChunkPerfectHashSeedsCount` | `u32` | Length of the optional perfect-hash seed array (TOC v4+). |
| 88 | 8 | LE | `PartitionSize` | `u64` | Bytes per partition (TOC v3+); pre-v3 readers MUST set this to `u64::MAX`. |
| 96 | 4 | LE | `TocChunksWithoutPerfectHashCount` | `u32` | Length of the optional perfect-hash-overflow array (TOC v5+). |
| 100 | 4 | LE | `_reserved7` | `u32` | Reserved. Newer CUE4Parse reads it as `TocSourceHashCount` for `GAME_UE6_0` and later game profiles[^3]. |
| 104 | 40 | LE | `_reserved8` | `[u64; 5]` | Reserved. Newer CUE4Parse reads its first 4 bytes as `EncryptionIVCount: u32` (see §*Versions*) for `GAME_UE6_0` and later game profiles, and zeroes it below TOC v10[^3]. |
| 144 | — | — | (end of header) | | The TOC body sections follow contiguously. |

From TOC v10, an AES-CTR container also has an IV array between the
compression-block table and the compression-method table (see
§*Versions*).

After the header, the body sections appear in this fixed order:

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
| 0 | 5 | **BE** | `Offset` | `u40` | Uncompressed offset: `Offset / CompressionBlockSize` is the chunk's first compression-block index and `Offset % CompressionBlockSize` its start within that block[^1]. Max `(1<<40)-1` ≈ 1 TiB. |
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
| 0 | 5 | LE | `Offset` | `u40` | Byte offset of the compressed block across the container's `.ucas` partitions: `Offset / PartitionSize` is the partition and `Offset % PartitionSize` the position in it[^4]. Max 1 TiB. |
| 5 | 3 | LE | `CompressedSize` | `u24` | Compressed byte count of this block: the codec of a compressed block takes exactly this many bytes. In an `Encrypted` container every block is read and decrypted as `CompressedSize` rounded up to a multiple of 16 (see [`iostore-ucas.md`](iostore-ucas.md) §*Worked example*). Max `(1<<24)-1` = 16 MiB-1. |
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

When the `Signed` flag is set in `ContainerFlags`, a
signature block follows the compression-method table:

| offset (in section) | size | endian | name | type | semantics |
|---------------------|------|--------|------|------|-----------|
| 0 | 4 | LE | `HashSize` | `i32` | Byte length of each signature blob. |
| 4 | `HashSize` | — | `TocSignature` | `[u8; HashSize]` | TOC signature. |
| 4 + HashSize | `HashSize` | — | `BlockSignature` | `[u8; HashSize]` | Block signature. |
| 4 + 2×HashSize | 20 × `TocCompressedBlockEntryCount` | — | `ChunkBlockSignature` | `FSHAHash[TocCompressedBlockEntryCount]` | Per-compression-block SHA-1 hash (20 bytes each). |

paksmith readers MAY skip signature verification by advancing the
cursor `HashSize + HashSize + 20*TocCompressedBlockEntryCount`
bytes; CUE4Parse takes that path.

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

CUE4Parse only reads the per-chunk metadata array when
`EIoStoreTocReadOptions::ReadTocMeta` is set. Each
`FIoStoreTocEntryMeta` is:

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
+80     00                                                ContainerFlags = 0 (no flags set)
+81     00                                                EncryptionMethod = 0
+82     00 00                                             _reserved4
+84     00 00 00 00                                       TocChunkPerfectHashSeedsCount = 0
+88     FF FF FF FF FF FF FF FF                           PartitionSize = 0xFFFFFFFFFFFFFFFF (u64::MAX)
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

A chunk at offset `0x0000000400` (= 1024 bytes)
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

### `EIoStoreTocVersion` (header field)

See §*Versions* for the enum values; readers gate optional sections
on the version discriminant.

### `EIoContainerFlags` (header field, bitmask)

| Bit | Flag | Effect on layout |
|-----|------|------------------|
| 0 | `Compressed` | Container-compressed bit; each block's `CompressionMethodIndex` selects its codec (`0` = none). |
| 1 | `Encrypted` | AES-256 encryption (key identified by `EncryptionKeyGuid`): ECB, or CTR from TOC v10 when `EncryptionMethod` is `2`. A CTR counter block is a 12-byte IV followed by a big-endian `u32` AES-block counter that starts at 0[^3]. |
| 2 | `Signed` | Signature block present after the compression-method table. |
| 3 | `Indexed` | Directory-index buffer present (requires TOC v2+). |
| 4 | `OnDemand` | OnDemand metadata trailers present (requires TOC v6 exactly). |

## Caps & limits

### Format-defined limits (wire-imposed)

- **`TocMagic`**: fixed 16 bytes; any deviation is wire-invalid.
- **`Version`**: `u8` discriminant (see §*Versions* table).
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
- **`EIoContainerFlags`**: `u8`[^1][^3]; bits 0-4 currently allocated.
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
- **`PartitionSize`**: MUST reject `PartitionSize == 0` at parse time for TOC v3 and
  later, whatever `PartitionCount` is: CUE4Parse's chunk `Read`
  divides every block's `Offset` by `PartitionSize`,
  single-partition containers included[^4]
  (see [`iostore-ucas.md`](iostore-ucas.md) §*Partitioned layout*).
- **`CompressionMethodIndex` range**: validate
  `index <= CompressionMethodNameCount` before indexing the method
  table (slot 0 = implicit `None`; slots `1..=CompressionMethodNameCount`
  are named methods). A malformed TOC with `index = 255` and a
  table of 4 named methods would otherwise out-of-bounds-access.
- **`CompressionBlockSize`**: MUST reject `0` at parse time; a
  chunk's `Offset` is divided by it (§*Offset+Length array*)[^4].
- **Compression-block range**: validate that a non-empty chunk's
  block indices, from `Offset / CompressionBlockSize` through the block
  holding its last byte, are all below
  `TocCompressedBlockEntryCount` before indexing the block
  table[^4].
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
  `trumank/repak` has no IoStore coverage; CUE4Parse (C#, with
  wire-faithful byte layouts) is the wire-layout oracle, and retoc[^2][^4]
  is cited for its release-to-TOC-version mapping, its header read and
  its block reads.
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

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/IO/Objects/FIoStoreTocHeader.cs@ecc4878950336126f125af0747190edf474b2a21` (header + `EIoStoreTocVersion` + `EIoContainerFlags`), `FIoChunkId.cs` (chunk-ID + `EIoChunkType` / `EIoChunkType5`), `FIoOffsetAndLength.cs` (BE 40-bit pair), `FIoStoreTocCompressedBlockEntry.cs` (packed 12-byte entry), `FIoStoreTocResource.cs` (top-level read order + section gating), `FIoStoreTocEntryMeta.cs` (per-chunk metadata variant under TOC v8), all at the same pinned SHA. At that revision `FIoStoreTocHeader.cs` L20-L22 put `LatestPlusOne` (9) right after `ReplaceIoChunkHashWithIoHash`, and L26 declares `EIoContainerFlags` as a `uint`, which L82 reads from header bytes 80-83. `CUE4Parse/UE4/IO/IoStoreReader.cs` covers the end-to-end open flow, and its L231-L235 turn a chunk's `Offset` into a compression-block index and an offset within that block.
[^2]: `trumank/retoc/retoc/src/version.rs@885a8dae740cb1ce1e41ff2e74f67f9f0c118237` L10-L22 and L25-L40 — `EngineVersion` starts at `UE4_25`, and `toc_version` maps UE 4.25 and 4.26 to `DirectoryIndex` (v2), UE 4.27 to `PartitionSize` (v3) and UE 5.5-5.7 to `ReplaceIoChunkHashWithIoHash` (v8), the newest version it maps. retoc's `README.md` at the same revision (L40) says overrides may be required for some games, usually pre-5.0 ones, where the IoStore version was not well defined. `retoc/src/lib.rs` at the same revision reads header byte 80 as `u8` container flags, then `reserved3: u8` and `reserved4: u16` (L225-L227, with the types at L1128 and L1205-L1207).
[^3]: `FabianFG/CUE4Parse/CUE4Parse/UE4/IO/Objects/FIoStoreTocHeader.cs@77b94fa26cde08d34e80be2ced29c8f8885ff0a7` L8-L24 — `AddedSourceHashes` (9) and `ContainerEncryptionMethod` (10) follow `ReplaceIoChunkHashWithIoHash`, and `LatestPlusOne` is 11. L27 declares `EIoContainerFlags` as a `byte`, and L96-L98 read `ContainerFlags`, then `EncryptionMethod` (one byte) and a `u16`. L102-L113 read offset 100 as `TocSourceHashCount` and offset 104 as `EncryptionIVCount` for `GAME_UE6_0` and later game profiles; for earlier profiles they skip offset 100 and read bytes 104-143 as `CustomGameData`. `FIoStoreTocResource.cs` at the same revision substitutes the encryption method and zeroes the IV count below v10 (L76-L80); it rejects an IV count other than the compression-block count (plus one when `Indexed` is set) under AES-CTR, or other than zero under any other method (L135-L139), then reads the IVs after the compression blocks (L142). Its version gates (L70, L76, L100, L105, L179, L197, L205) take the same branches at 9 as at 8. `CUE4Parse/UE4/IO/FIoStoreEncryptionIV.cs` L7 and L23-L28 give the 12-byte IV and the `EIoEncryptionMethod` values. `CUE4Parse/UE4/IO/IoStoreReader.cs` L513 and L524 test the method for `AES_CTR`; L518-L519 and L530 decrypt the directory index with the last IV and each compression block with its own, and `CUE4Parse/Encryption/Aes/Aes.cs` L15 and L172-L180 build the counter block; L104 and L121 default its starting counter to 0.
[^4]: `FabianFG/CUE4Parse/CUE4Parse/UE4/IO/IoStoreReader.cs@ecc4878950336126f125af0747190edf474b2a21` L233-L234 derive a chunk's first and last compression-block indices from `Offset`, `Length` and `CompressionBlockSize`, L244-L246 loop over that range, indexing `CompressionBlocks`, and L256-L257 split each block's `Offset` by `PartitionSize` into a partition index and a position within that partition. `CUE4Parse/UE4/IO/Objects/FIoStoreTocResource.cs` L50-L53 at the same SHA substitute `PartitionCount` 1 and `PartitionSize` `ulong.MaxValue` below TOC v3. `trumank/retoc/retoc/src/lib.rs@885a8dae740cb1ce1e41ff2e74f67f9f0c118237` L646-L649 (`read`) index `compression_blocks` with the same range.
