# LZ4 decompression

Per-block codec documentation for LZ4-compressed pak entries. The
block *framing* (how an entry's payload is split into
`FPakCompressedBlock` regions) is method-agnostic and documented in
[`pak-block-framing.md`](pak-block-framing.md); this doc covers what
lives inside each block when the entry's compression method resolves
to `LZ4`.

## Overview

Each compression block of an LZ4 pak entry is one independent **raw
LZ4 block** (the `LZ4 Block Format`): no LZ4-frame magic, no frame
descriptor, no content/block checksum, and no stored decompressed
size. The reader must know each block's decompressed size out of
band — for pak entries it is derived from the entry header: every
block inflates to exactly `compression_block_size` bytes except the
last, which takes the remainder of `uncompressed_size`.

Writers observed in the ecosystem produce exactly this form: repak
compresses each block with `lz4_flex::block::compress` (raw block,
no size prefix), and the CUE4Parse reference decodes with the K4os
`LZ4Codec.Decode(source, destination)` raw-block API into a
caller-sized buffer.[^1]

## Versions

LZ4 is expressible in pak archives from **v8 onward only**: the
method field became a 1-based index into the footer's FName
compression-slot table in v8, and `"LZ4"` is resolved by name. The
v3-v7 numeric method IDs have no standard LZ4 assignment (see
`container/pak/index/compression.rs::CompressionMethod::from_u32`),
so a pre-v8 archive cannot declare LZ4 through any documented wire
value. The raw block codec itself is version-independent.

## Wire layout

A raw LZ4 block is a sequence of variable-length records:

```
sequence := token(1) [lit-len-ext...] literals [match-offset(2 LE) [match-len-ext...]]
```

- **token** — high nibble: literal count (15 = extended by
  additional bytes, each 255 continuing); low nibble: match length
  minus 4 (15 = extended likewise).
- **literals** — copied verbatim to the output.
- **match offset** — u16 little-endian back-reference into the
  already-produced output window (offset 0 is invalid).
- The final sequence ends after its literals (no match part).

There is **no length header and no checksum** in the block; a
corrupted literal byte decodes "successfully" into wrong output.
Integrity for pak entries therefore rests entirely on the entry's
SHA1 (computed over the on-disk *compressed* block bytes — see
`verify_entry`).

### Per-block decompressed size derivation

```
expected(i) = min(compression_block_size,
                  uncompressed_size - sum(expected(0..i)))
```

Non-final blocks MUST inflate to exactly `compression_block_size`;
the final block to the remaining byte count. A block inflating past
its expected size is malformed (and, defensively, a
decompression-bomb attempt).

## Variants

- **Raw block vs LZ4 frame**: pak entries use raw blocks only. The
  frame format (magic `0x184D2204`, descriptors, checksums) does not
  appear inside pak compression blocks.
- **Size-prepended blocks**: some Rust APIs
  (`compress_prepend_size`) prefix the decompressed size; pak blocks
  carry no such prefix — the size is derived as above.
- **High-compression encoders** (LZ4-HC) emit the same block format;
  decoding is identical.

## Caps & limits

### Format-defined limits (wire-imposed)

- Match offsets are 16-bit: back-references reach at most 65535
  bytes — an inherent bound on window state, not on output size.
- A raw block has no self-declared output size; the *pak layer*
  bounds it via `compression_block_size` and `uncompressed_size`.

### Implementation hardening (recommended for any parser)

- Bound every block's output buffer to the derived expected size
  BEFORE decoding; treat over-expansion as a hard error (paksmith:
  the pre-sized buffer makes `decompress_into` fail on
  over-expansion — the buffer IS the bomb cap).
- Enforce the non-final-block == `compression_block_size` invariant
  and the cumulative == `uncompressed_size` invariant (truncation /
  padding detection).
- Validate block byte-ranges against the file and entry bounds
  before reading (shared, method-agnostic:
  `validate_block_bounds`, see
  [`pak-block-framing.md`](pak-block-framing.md)).
- `uncompressed_size` is capped at open time
  (`MAX_UNCOMPRESSED_ENTRY_BYTES`, 8 GiB) like every entry,
  compressed or not.

## Verification

Cross-validated end-to-end against repak-written fixtures
(`tests/fixtures/real_v8b_lz4.pak`, `real_v11_lz4.pak` — generated
by `paksmith-fixture-gen`, which drives repak's writer): paksmith
decompresses repak's raw LZ4 blocks back to the byte-exact source
payload at both the earliest FName-slot version (v8b) and the
current one (v11). Decode semantics additionally verified against
the CUE4Parse reference (`Compression.cs` routes `LZ4` to the K4os
raw-block `LZ4Codec.Decode`) — both anchors agree the block is raw
and the output size is caller-derived.[^1]

Negative behavior (short non-final block, short final block,
over-expanding block, structural corruption, OOM at the output
reservation) is pinned by synthetic v8b paks built in
`paksmith-core-tests` (`build_v8b_lz4_pak`) with real entry hashes —
repak zeroes entry hash slots, so the hash-path tests require the
synthetic writer.

## Paksmith implementation

`stream_lz4_to` in `crates/paksmith-core/src/container/pak/mod.rs`
(issue #636), mirroring `stream_zlib_to`'s discipline:

- Same version guard (pre-v5 relative-offset floor), same shared
  `validate_block_bounds` walk, same hoisted two-buffer scheme (one
  compressed-input + one decompressed-output buffer reused across
  blocks; the full `uncompressed_size` never lives in memory).
- Decodes with `lz4_flex::block::decompress_into` into a buffer
  pre-sized to the block's expected output — over-expansion errors
  inside the decoder (`DecompressionFault::Lz4DecodeError`) instead
  of allocating, so no `take(+1)`-style trick is needed.
- Faults: corrupt blocks → `Lz4DecodeError`; short non-final blocks
  → `NonFinalBlockSizeMismatch`; cumulative shortfall →
  `SizeUnderrun`; fallible reservations → 
  `CompressedBlockReserveFailed` (input, shared seam with zlib) and
  `Lz4OutputReserveFailed` (output, seam `PakSeam::Lz4OutputReserve`).
- `verify_entry` routes LZ4 through the same block-walk hash arm as
  zlib (the entry SHA1 covers on-disk compressed bytes; no
  decompression happens on the verify path). Because raw LZ4 blocks
  carry no checksum, this SHA1 is the ONLY content-integrity layer
  for LZ4 entries — a tampered literal byte that decodes cleanly is
  caught by `verify_entry`, not by `read_entry`.
- Encrypted + compressed entries remain rejected upstream
  (see issue #634); LZ4 support does not change that gate.

## References

[^1]: Decode-side oracle: `FabianFG/CUE4Parse/CUE4Parse/Compression/Compression.cs` (routes `CompressionMethod.LZ4` to the K4os raw-block `LZ4Codec.Decode`). Write-side oracle: `trumank/repak` `repak/src/data.rs` (`lz4_flex::block::compress`) and `repak/src/entry.rs` (`lz4_flex::block::decompress_into` with `chunks_mut(compression_block_size)` — the per-block size derivation this doc specifies). Block-format specification: the LZ4 project's `lz4_Block_format.md` (lz4/lz4 on GitHub).
