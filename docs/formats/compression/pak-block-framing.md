# Pak entry compression-block framing

> How a single `.pak` entry's compressed payload is partitioned into
> per-block compressed byte ranges, and how those ranges decompress
> into the entry's uncompressed bytes.

## Overview

When a `.pak` entry is compressed (`compression != 0` in its header,
referencing a non-`None` method in the footer's compression-methods
table — see [`../container/pak.md`](../container/pak.md)), its
payload is not one continuous compressed stream. Instead, the payload
is sliced into fixed-size **blocks** of uncompressed bytes (typically
64 KiB each, the last possibly smaller), each block compressed
independently into a variable-size compressed range, and the resulting
ranges concatenated to form the payload.

The entry header carries a `compression_blocks` array — one record
per block describing the compressed byte range. The reader iterates:
for each block, seek to the block's absolute start position, read the
compressed bytes, decompress to a buffer of `compression_block_size`
uncompressed bytes (or smaller for the final block), write to the
output stream, advance.

The independence per block is what makes pak archives streamable: a
consumer asking for a specific byte range of an entry only needs to
decompress the blocks that overlap that range. Paksmith's
`read_entry_to(path, writer)` streams the full entry block by block
to keep peak memory bounded.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| Wire version 3 (`CompressionEncryption`, UE 4.4) | Block framing introduced; offsets are **file-relative**. Paksmith rejects these with `UnsupportedVersion` — see Implementation note. | `trumank/repak/repak/src/entry.rs@355b5f62f51959c7cc6dd5a51708646ef483065d`[^1] |
| Wire version 5+ (`RelativeChunkOffsets`, UE 4.20+) | Block offsets became **entry-relative** (start is from the entry's payload start, not the file start). Paksmith's `stream_zlib_to` normalizes to absolute by adding the entry's payload base offset. | Same[^1] |
| Wire version 8+ | Per-entry `compression` byte became a 1-based index into the footer's compression-method FName table (instead of a raw method ID). Block framing itself unchanged. | Same[^1] |
| Wire version 10+ (`PathHashIndex`) | Encoded entry format: block boundaries move from explicit `(start: u64, end: u64)` pairs to per-block `u32` compressed sizes; synthesized into block ranges during parsing. See Variants. | `FabianFG/CUE4Parse/CUE4Parse/UE4/Pak/PakFileReader.cs@ecc4878950336126f125af0747190edf474b2a21`[^2] |

V8A vs V8B: the per-entry compression byte width changes (u8 vs u32);
the block-array shape is unchanged. See [`../container/pak.md`](../container/pak.md).

## Wire layout

The compression-blocks array appears in two distinct wire shapes
depending on the pak version. Both shapes produce in-memory
`CompressionBlock { start: u64, end: u64 }` values after parsing.

### Inline entries (v3-v9): per-block `(start: u64, end: u64)` pairs

For v3-v9 archives, the `FPakEntry` record in the flat index stores
blocks as explicit 16-byte pairs:

| field | size | type | semantics |
|-------|------|------|-----------|
| `compression_blocks_count` | 4 | `u32` LE | Number of blocks. Present only when `compression_method != None`. |
| `compression_blocks` | `count × 16` | `CompressionBlock[]` | Per-block `(start: u64 LE, end: u64 LE)` pairs. |
| `encrypted` | 1 | `u8` | Per-entry AES-256 ECB flag. When `1`, the compressed bytes within each block must be decrypted before decompression. |
| `compression_block_size` | 4 | `u32` LE | Uncompressed bytes per block (typically `64 * 1024 = 65,536`). Last block may be smaller. Always present in v3+, value `0` for uncompressed entries. |

Each `CompressionBlock` record on disk is two LE `u64`s: 16 bytes total.

### Encoded entries (v10+): per-block `u32` compressed sizes

V10+ archives store entries in a bit-packed encoded form in the
path-hash index's encoded-entries blob. Block boundaries are not
stored as `(start, end)` pairs; instead, the reader reconstructs them:

| field | size | type | semantics |
|-------|------|------|-----------|
| per-block compressed size | 4 | `u32` LE | One per block (when `block_count > 1` or `is_encrypted`). |

The parser walks these sizes, accumulating a cursor from
`in_data_record_size` (the size of the in-data `FPakEntry` record that
precedes each entry's payload). For unencrypted entries, `cursor`
advances by `block_compressed_size`. For encrypted entries, it
advances by `(block_compressed_size + 15) & !15` — i.e., rounded up
to the next AES-block boundary (16 bytes), because encrypted blocks
are zero-padded to an AES-aligned length on disk. The unaligned
`block_compressed_size` still forms the logical `end - start` for the
`CompressionBlock` struct; only the cursor advance is aligned.

**Single-block non-encrypted shortcut**: when `block_count == 1 && !is_encrypted`,
no per-block size is written in the encoded stream. The parser derives
the single block as `[in_data_record_size, in_data_record_size + compressed_size)`.

### Per-block `(start, end)` semantics

After parsing, every `CompressionBlock` carries two `u64` offsets:

- `start` is the byte offset of the first compressed byte of the block.
- `end` is the byte offset one past the last compressed byte of the block.
- `len = end - start` bytes of compressed data to read.
- Paksmith rejects `start > end` as `IndexParseFault::CompressionBlockInvalid { start, end }`.
- An empty block (`start == end`) is legal but unusual.

The **relativity** of `start` and `end` depends on the pak version:

- **V3 / V4** (`CompressionEncryption` / `IndexEncryption`): offsets are
  **file-relative**. Paksmith rejects compressed entries from these
  versions with `PaksmithError::UnsupportedVersion` rather than
  attempting normalization (see `mod.rs:1324-1331`).
- **V5+** (`RelativeChunkOffsets` onward): offsets are
  **entry-relative**. `start = 0x40` means "byte 0x40 after the
  entry's in-data record, i.e. in the entry's payload region". The
  reader normalizes by adding the entry's payload base offset.
- **V10+** (encoded entries): offsets are synthesized entry-relative
  (starting from `in_data_record_size`), equivalent to the v5+ shape.

### Decompression loop

Pseudocode (paksmith's `stream_zlib_to` family, `mod.rs:1314+`):

```
remaining = uncompressed_size
for each block (start, end) in compression_blocks:
    abs_start = entry.offset + start  # start is entry-record-relative
    seek_to(abs_start)
    block_len = end - start
    try_reserve(block_len) → compressed  # fallible; OOM → typed error
    read block_len compressed bytes into compressed
    if encrypted:
        AES-256-ECB-decrypt compressed in place
    remaining_budget = remaining + 1  # +1 to detect over-expansion
    decompress with method's decoder, taking at most remaining_budget bytes:
        per-chunk read + try_reserve into block_out
    if block_out.len() > remaining:
        return DecompressionFault::DecompressionBomb
    writer.write_all(&block_out)
    remaining -= block_out.len()
assert remaining == 0
```

The `take(budget)` and per-block `try_reserve` are paksmith's
decompression-bomb defense: a malicious entry that claims a 1 KiB
uncompressed size but contains a 1 GiB-expanding block is rejected
when the budget is exhausted, with no allocation past the budget
itself.

### Worked example: compression-blocks array

*(none yet — pending fixture-stability follow-up; per-block offsets are
layout-dependent and vary by fixture. Tracked in
[#347](https://github.com/r6e/paksmith/issues/347).)*

## Variants

### V3-V4 file-relative offsets (unsupported)

V3 and V4 archives published block offsets relative to the file start.
Paksmith's `stream_zlib_to` explicitly rejects these with
`PaksmithError::UnsupportedVersion` (`mod.rs:1324-1331`) rather than
attempting normalization. Pre-v5 compressed archives are rare in
practice (UE 4.4 through early UE 4.20 era), and supporting the
normalization adds surface area for off-by-one bugs. The rejection is
intentional and documented in the module-level `//! It does NOT yet
handle:` list.

### V10+ encoded entries

V10+ encoded entries use per-block `u32` sizes instead of `(start, end)` pairs — see
Wire layout §*Encoded entries (v10+)* and
[`../container/pak.md`](../container/pak.md) for full detail.

### Empty blocks

`start == end` is legal and represents a zero-byte compressed block
that decompresses to zero bytes. UE writers don't emit empty blocks
in practice; paksmith handles them defensively for malformed input.

## Caps & limits

- **`MAX_UNCOMPRESSED_ENTRY_BYTES = 8 GiB`**
  (`crates/paksmith-core/src/container/pak/mod.rs:86`). Cap on the
  total `uncompressed_size` of any single entry. The block-loop's
  `remaining` counter is bounded by this from the start. Surfaces as
  `IndexParseFault::BoundsExceeded { field: WireField::UncompressedSize, value, limit, unit: BoundsUnit::Bytes, path }`.
- **`MAX_BLOCKS_PER_ENTRY = 16_777_216`**
  (`crates/paksmith-core/src/container/pak/index/entry_header.rs:25`).
  Cap on the number of compression blocks per inline (v3-v9) entry
  (~16M blocks of 64 KiB = 1 TiB entry). Surfaces as
  `IndexParseFault::BoundsExceeded { field: WireField::BlockCount, value, limit, unit: BoundsUnit::Items, path }`.
  V10+ encoded entries mask block count to 16 bits (max 65 535) so
  this cap is unreachable on the encoded path.
- **Per-block decompression budget** = `remaining + 1`. A block that
  decompresses to more than `remaining` bytes is the canonical
  "decompression bomb" signal. Surfaces as
  `DecompressionFault::DecompressionBomb { block_index, actual, claimed_uncompressed }`.
- **Per-block compressed reservation** via `try_reserve_exact`. A
  too-large `block_len` (claimed > available memory) surfaces as
  `DecompressionFault::CompressedBlockReserveFailed { block_index, requested, source }`
  rather than aborting the process.
- **`start > end` rejected.**
  `IndexParseFault::CompressionBlockInvalid { start, end }`.

See `docs/security/allocation-caps.md` for the broader policy.

## Verification

- **Fixtures:**
  - `tests/fixtures/real_v11_compressed.pak` — V11 archive with a
    zlib-compressed entry; cleanest single-entry block-framing
    anchor.
  - `tests/fixtures/real_v10_compressed.pak` — V10 counterpart.
  - `tests/fixtures/real_v8a_compressed.pak` / `real_v8b_compressed.pak`
    — V8 family with the u8 vs u32 compression-byte width split.
- **Hex anchor commands:** see *Worked example: compression-blocks array*
  under Wire layout.
- **Cross-validation oracle:** repak[^1] (paksmith's primary pak
  oracle) and CUE4Parse[^2]. Every compressed fixture round-trips
  through repak at fixture-gen time.
- **Known divergences:** none on the block-framing wire shape itself.
  The v3-v4 file-relative path is intentionally unsupported in
  paksmith; repak handles it. Both agree on v5+ entry-relative
  semantics and v10+ encoded-entry block reconstruction.

## Paksmith implementation

**Parser modules:**
- `crates/paksmith-core/src/container/pak/index/compression.rs` —
  `CompressionMethod`, `CompressionBlock`.
- `crates/paksmith-core/src/container/pak/index/entry_header.rs` —
  `PakEntryHeader::{Inline, Encoded}` with the per-block array;
  `encoded_entry_in_data_record_size` for the cursor base offset.
- `crates/paksmith-core/src/container/pak/mod.rs` — `stream_zlib_to`
  block loop (the canonical reference implementation; other methods
  share the same outer loop shape).

**Status:** `complete` for v5-v11. V3-V4 compressed entries are
rejected at `stream_zlib_to` with `UnsupportedVersion`.

**Public surface:**
- `pub struct CompressionBlock` — `start()`, `end()`, `len()`, `is_empty()`.
- `pub enum CompressionMethod` — `None`, `Zlib`, `Gzip`, `Oodle`,
  `Zstd`, `Lz4`, `Unknown(NonZeroU32)`, `UnknownByName(String)`
  (`#[non_exhaustive]`).
- `pub fn CompressionBlock::new(start, end) -> Result<Self>` —
  validates `start <= end`.

**Error variants** (selected):
- `IndexParseFault::CompressionBlockInvalid { start, end }`.
- `IndexParseFault::BoundsExceeded { field: WireField::BlockCount, value, limit, unit: BoundsUnit::Items, path }`.
- `IndexParseFault::BoundsExceeded { field: WireField::UncompressedSize, value, limit, unit: BoundsUnit::Bytes, path }`.
- `DecompressionFault::CompressedBlockReserveFailed { block_index, requested, source }`.
- `DecompressionFault::DecompressionBomb { block_index, actual, claimed_uncompressed }`.
- `DecompressionFault::ZlibStreamError { block_index, kind, message }`
  (for the zlib path; other methods get analogous variants when
  implemented).

**Cap constants:** see *Caps & limits* above.

**Phase plan:** `docs/plans/phase-1-foundation.md`.

## References

[^1]: `trumank/repak/repak/src/entry.rs@355b5f62f51959c7cc6dd5a51708646ef483065d` — paksmith's primary pak oracle. Documents the v5+ entry-relative-offsets convention and the per-block `(start, end)` u64 pair.
[^2]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Pak/PakFileReader.cs@ecc4878950336126f125af0747190edf474b2a21` — secondary oracle. Block-decompression loop shape and v10+ encoded-entry reconstruction are consistent.
