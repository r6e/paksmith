# IoStore `.ucas` (Container As-Stream)

> Bulk-data file for an IoStore container — chunk payloads concatenated,
> referenced by offset+length pairs in the matching `.utoc`.

## Overview

`.ucas` ("Container As-Stream") holds the actual data payloads of an
IoStore container. It is purely a byte stream — no header, no per-chunk
metadata. All structure lives in the paired `.utoc` file
([`iostore-utoc.md`](iostore-utoc.md)), which publishes `(chunk_id → offset, length, compression-block-list)`
mappings into this file.

Compression and AES-256 ECB encryption are applied at the
compression-block granularity, the same way `.pak` does it, with parameters
(block size, method, key) all carried in the `.utoc`.

**Document status: complete.** The `.ucas` file is structureless
by format — a flat byte stream of concatenated chunk payloads with
no header, no length field, no terminator. All wire structure
(chunk locations, compression-block boundaries, encryption flags,
compression method per block) lives in the paired `.utoc`
([`iostore-utoc.md`](iostore-utoc.md)). This doc documents the
structurelessness, the per-block decode chain, and the partitioned
layout that TOC v3+ enables.

**Paksmith parser status: `not impl`.** Phase 8 deliverable. The
IoStore reader will materialize `.ucas` chunks by following
`(chunk_id → first_block_index, last_block_index)` mappings from
the `.utoc` and walking the compression-block table.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| UE 4.27+ | No on-stream version field — `.ucas` is unstructured bytes. All version-conditional shape lives in `.utoc`. | `CUE4Parse/UE4/IO/IoStoreReader.cs@ecc4878950336126f125af0747190edf474b2a21`[^1] |

## Wire layout

| offset | size | endian | name | type | semantics |
|--------|------|--------|------|------|-----------|
| 0 | filesize | — | `chunks` | byte stream | Concatenation of chunk payloads. Each chunk's bounds are published by the matching `.utoc`. |

A chunk payload is one or more compression blocks (per the `.utoc`'s
`FIoStoreTocCompressedBlockEntry` array — see
[`iostore-utoc.md`](iostore-utoc.md) §*Compression-block table*).
When the chunk is uncompressed, the payload is the raw chunk bytes;
when compressed, it is the concatenated compressed blocks, each
readable as a single decompress call against the method named in
the `.utoc`'s compression-method table.

When the `.utoc`'s `EIoContainerFlags::Encrypted` bit is set, the
encryption is applied at the compression-block granularity in
AES-256 ECB mode — same as pak's per-entry encryption (see
[`../crypto/aes-pak.md`](../crypto/aes-pak.md)). The key is
identified by the TOC's `EncryptionKeyGuid` field; the bytes on
disk are `EncryptedBlock = AES-256-ECB(key, padded(CompressedBlock))`,
where the writer 16-byte-aligns the block to the AES block
boundary at write time.

### Partitioned layout (TOC v3+)

When the `.utoc` declares `PartitionCount > 1`, the `.ucas` is
split into multiple files on disk, named with a partition suffix
(e.g. `Container.ucas`, `Container_s1.ucas`, `Container_s2.ucas`).
Each partition is at most `PartitionSize` bytes (from the TOC
header). A reader maps a `FIoStoreTocCompressedBlockEntry.Offset`
to a `(partition_index, offset_within_partition)` pair via
`partition_index = Offset / PartitionSize`,
`offset_within_partition = Offset % PartitionSize`.

For `PartitionCount == 1` (pre-TOC-v3 or single-partition
v3+ containers), the entire `.ucas` is one file and the partition
arithmetic collapses to identity.

### Worked example — minimal `.ucas` referenced by a TOC

Because `.ucas` is structureless, a worked example must show both
the `.ucas` bytes AND the matching `.utoc` records that carve them.
Suppose a 12-byte `.ucas` carrying a single uncompressed chunk:

```
.ucas file contents (12 bytes — arbitrary opaque payload):

Offset  Bytes (wire)              Field
------  ------------------------  ------
+0      48 65 6C 6C 6F 20 49 6F 53 74 6F 21  payload (ASCII "Hello IoSt!" + zero-pad — 12 bytes)
+12                                            (EOF — file is exactly the chunk's bytes)
```

The matching `.utoc` records that resolve `chunk_id` to these
bytes:

```
ChunkOffsetLengths[i] (FIoOffsetAndLength, 10 bytes, BE):
  Offset = 0    (5-byte BE u40; chunk starts at .ucas byte 0)
  Length = 12   (5-byte BE u40; chunk is 12 bytes uncompressed)

CompressionBlocks[i] (FIoStoreTocCompressedBlockEntry, 12 bytes):
  Offset = 0                    (5-byte LE u40; block starts at .ucas byte 0)
  CompressedSize = 12           (3-byte LE u24; on-disk byte count)
  UncompressedSize = 12         (3-byte LE u24; matches CompressedSize when uncompressed)
  CompressionMethodIndex = 0    (u8; 0 = None)
```

Reader logic to materialize the payload:

1. Locate the chunk index `i` for the desired `FIoChunkId` (via
   `.utoc`'s perfect-hash array or linear scan).
2. Use `ChunkOffsetLengths[i]` to determine the chunk's
   `Offset = 0` and `Length = 12` in `.ucas`.
3. Walk the compression blocks that cover bytes
   `[Offset, Offset + Length)` (here, just `CompressionBlocks[i]`).
4. For each block: seek to `block.Offset` in `.ucas`, read
   `block.CompressedSize` bytes, decrypt (if `Encrypted` flag),
   decompress (if `CompressionMethodIndex != 0`), and emit
   `block.UncompressedSize` bytes to the chunk's output buffer.

For an `OptionalBulkData`-typed chunk (`EIoChunkType` value 3 on
UE4 or 4 on UE5), the same logic applies but the reader sources
bytes from `.uptnl` instead of `.ucas` — see
[`iostore-uptnl.md`](iostore-uptnl.md).

## Variants

None on the `.ucas` wire itself. The two on-disk variants are
selected by the matching `.utoc`:

- **Per-chunk compression / encryption flags** (encoded in the
  TOC's `EIoContainerFlags` and per-block
  `CompressionMethodIndex`).
- **Partition count** (TOC v3+; affects whether `.ucas` exists as
  one file or multiple).

## Caps & limits

### Format-defined limits (wire-imposed)

- **None at the file level.** `.ucas` is structureless: no header,
  no length field, no terminator. The on-disk byte count is the
  union of all per-block byte ranges plus dead space between blocks
  (format-permitted but unused). A single `.ucas` partition is at
  most `PartitionSize` bytes (from the TOC).
- **Per-block bounds** are imposed by the matching `.utoc`'s
  `FIoStoreTocCompressedBlockEntry`:
  - `block.Offset`: 40-bit LE, max 1 TiB.
  - `block.CompressedSize`: 24-bit LE, max ~16 MiB-1 per block.
  - `block.UncompressedSize`: 24-bit LE, same max.
- **Per-chunk bounds** are imposed by the matching `.utoc`'s
  `FIoOffsetAndLength` (40-bit BE, max 1 TiB each for `Offset` and
  `Length`).

### Implementation hardening (recommended for any parser)

A `.ucas` reader (paksmith does not yet have one) MUST:

- **Inherit `MAX_UNCOMPRESSED_ENTRY_BYTES = 8 GiB`** from the pak
  side as the cumulative per-chunk decompressed budget.
- **Cap each block's decompression output** at the TOC header's
  `CompressionBlockSize` field; a decompressor that produces more
  bytes than declared indicates corruption or a decompression-bomb
  attempt.
- **Use `checked_add` on `block.Offset + block.CompressedSize`**
  before any seek-window comparison (defeats near-`u64::MAX`
  wraparound attacks).
- **Validate `CompressionMethodIndex < CompressionMethodNameCount + 1`**
  before indexing the method table (rejects out-of-range indices
  surfaced by malformed `.utoc`s).
- **Reject mis-aligned encrypted regions** (block byte counts not
  divisible by 16 when `Encrypted` flag is set), per
  [`../crypto/aes-pak.md`](../crypto/aes-pak.md).
- **Validate partition arithmetic** (`PartitionCount * PartitionSize`)
  with `checked_mul` to bound the total addressable byte range; an
  unbounded multiplication would overflow `u64` for adversarial TOC
  values.

See `docs/security/allocation-caps.md` for the broader policy that
the planned Phase 8 caps will follow.

## Verification

- **Fixture:** The Worked example above is byte-exact and self-
  contained — a 12-byte synthetic `.ucas` + the matching `.utoc`
  records carry the spec. A real-cooked `.ucas` + `.utoc` pair for
  end-to-end cross-validation is a Phase 8 deliverable.
- **Hex anchor commands:**
  ```
  # Synthesize the 12-byte structureless .ucas from the Worked example:
  printf 'Hello IoSt!\x00' | xxd
  ```
  A conformant IoStore reader fed this 12-byte file plus the
  matching TOC records MUST return the same 12 bytes as the chunk
  payload.
- **Cross-validation oracle:** CUE4Parse's `IoStoreReader`[^1].
  The `.ucas` read path is inlined with the `.utoc` chunk lookup;
  no standalone `.ucas` parser exists in CUE4Parse because the
  file has no internal structure to parse.
- **Known divergences:** none — no paksmith implementation to
  diverge.

## Paksmith implementation

**Parser module:** *(not yet implemented — planned under `crates/paksmith-core/src/container/iostore/`)*

**Status:** `not impl`.

**Phase plan:** `docs/plans/ROADMAP.md` Phase 8 (IoStore Support).

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/IO/IoStoreReader.cs@ecc4878950336126f125af0747190edf474b2a21` — primary oracle. The `.ucas` reading happens inline with `.utoc` chunk lookup in this file's `ReadAsync`.
