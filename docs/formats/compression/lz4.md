# LZ4 decompression

> Per-block codec for LZ4-compressed pak entries: each compression
> block is one raw **LZ4 Block Format** stream (no frame magic, no
> stored size). Resolvable only in v8+ archives, via the footer's
> FName compression-slot table.

## Overview

The block *framing* (how an entry's payload is split into
`FPakCompressedBlock` regions) is method-agnostic and documented in
[`pak-block-framing.md`](pak-block-framing.md); this doc covers what
lives inside each block when the entry's compression method resolves
to `LZ4`.

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

| UE version range | Wire-format change | Source |
|------------------|--------------------|--------|
| Wire version 8+ | LZ4 resolvable. The compression method became a 1-based index into the footer's FName compression-slot table in v8; `"LZ4"` is matched by name (`CompressionMethod::from_name`). The v3-v7 numeric method IDs paksmith recognizes are `Zlib=1`, `Gzip=2`, `Oodle=4` (`CompressionMethod::from_u32`) — none is LZ4 — so paksmith resolves LZ4 only through the v8+ FName slot table. | `trumank/repak/repak/src/entry.rs@e215472c51db69328b1ce77be2db24d24c1d646b`[^1] |

The raw block codec itself is version-independent: only the *method
resolution* is version-gated, not the block format.

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
budget(i) = uncompressed_size - sum(produced(0..i))
```

Every block decodes into a budget bounded by the REMAINING output —
mirroring the zlib path's `take(remaining + 1)` bound. Non-final
blocks MUST produce exactly `compression_block_size` (checked after
decode); the final block takes whatever remains, and the cumulative
total must equal `uncompressed_size` exactly. A block inflating
past its budget is malformed (and, defensively, a
decompression-bomb attempt).

Both cited references normalize **single-block** entries: repak
substitutes the entry's `uncompressed` size when there is exactly
one block (`entry.rs`, `ranges.len() == 1` branch), and CUE4Parse's
encoded-entry constructor does the same (`compressionBlocksCount ==
1 → UncompressedSize`). The remaining-based budget above is
observably equivalent: a single block is also the final block, so
its budget is the full `uncompressed_size` regardless of the stored
`compression_block_size` — a single-block entry declaring a
`compression_block_size` *smaller* than its `uncompressed_size` (a
shape no writer in paksmith's fixture corpus produces, but which
both references accept) decodes identically here.

The inconsistent claim `uncompressed_size > block_count ×
compression_block_size` splits by index generation: the v10+
**encoded** index rejects it at parse time
(`IndexParseFault::BoundsExceeded`, fail-closed, both codecs),
while the v3-v9 **inline** index applies no parse-time bound — the
shape reaches the decoder, where single-block entries decode (see
above) and lying multi-block entries die at the non-final
exact-size check. Whether real UE 4.26-era v10 archives emit a
truncated single-block `compression_block_size` (and would thus
need the references' normalization on the encoded-parse path) is
unconfirmed and tracked in issue #685.

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
- A raw LZ4 block of N compressed bytes decodes to at most `N × 255`
  bytes (literals copy 1:1; each match-length extension byte
  contributes ≤ 255 output bytes). This is the maximum expansion
  ratio a parser can rely on to bound a per-block allocation without
  trusting the (attacker-controlled) `compression_block_size`.

### Implementation hardening (recommended for any parser)

- Bound every block's output buffer to the derived expected size
  BEFORE decoding; treat over-expansion as a hard error (paksmith:
  the pre-sized buffer makes `decompress_into` fail on
  over-expansion — the buffer IS the bomb cap).
- Additionally cap that pre-sized buffer by `compressed_len × 255`
  (the max block expansion above), so a crafted
  `compression_block_size` cannot force a huge *eager* allocation
  before the decode even runs (paksmith: `lz4_block_output_cap`,
  #636). A valid block's real output never exceeds this bound, so the
  cap never rejects well-formed data.
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
payload at both v8b — the earliest 5-slot/u32-index FName-table
layout; v8a's 4-slot/u8-index variant is exercised by the zlib
corpus, and slot resolution is method-agnostic — and the current
version (v11). Decode semantics additionally verified against
the CUE4Parse reference (`Compression.cs` routes `LZ4` to the K4os
raw-block `LZ4Codec.Decode`) — both anchors agree the block is raw
and the output size is caller-derived.[^1]

Integrity-path coverage: repak writes a **real** entry SHA1, but
only the *legacy* directory index (v8b) stores a per-entry hash
field, so `verify_entry` on `real_v8b_lz4.pak` reaches the hash arm
and returns `Verified` — an end-to-end check that paksmith's entry
hashing matches repak's over real blocks. The v10+ **encoded** index
(v11) carries no per-entry hash field, so `verify_entry` on
`real_v11_lz4.pak` returns `SkippedNoHash` (structural, not a zeroed
slot). Negative behavior (short non-final block, short final block,
over-expanding block, structural corruption, OOM at the output
reservation) is pinned by synthetic v8b paks built with
`testing::wire::build_v8b_lz4_pak`, which writes a legacy index with
a real hash so the hash arm and the decode-failure faults are
observable — and lets tests craft the inconsistent claims a real
writer never produces.

## Paksmith implementation

**Status:** `complete`. One documented derivation divergence vs the
cited references remains, on the v10+ **encoded** index only: a
single-block entry whose stored `compression_block_size` is smaller
than its `uncompressed_size` is rejected fail-closed at index parse
(`IndexParseFault::BoundsExceeded`) rather than decoded via the
references' single-block normalization — see "Per-block decompressed
size derivation" and issue #685. On v3-v9 legacy indexes the same
shape decodes identically to the references.

`stream_lz4_to` in `crates/paksmith-core/src/container/pak/mod.rs`
(issue #636), mirroring `stream_zlib_to`'s discipline:

- Same shared `validate_block_bounds` walk and the same hoisted
  two-buffer scheme (one compressed-input + one decompressed-output
  buffer reused across blocks; the full `uncompressed_size` never
  lives in memory). Unlike `stream_zlib_to` it takes no `version` and
  has no pre-v5 relative-offset guard: `LZ4` is reachable only via the
  v8+ FName slot table, so any entry reaching the decoder already
  parsed as v8+ (where block offsets are relative) — the guard would
  be unreachable dead code.
- Decodes with `lz4_flex::block::decompress_into` into a buffer
  pre-sized to the block's expected output, capped by
  `lz4_block_output_cap` (`compressed_len × 255`) so a crafted
  `compression_block_size` cannot force a huge eager allocation
  (#636). Over-expansion errors inside the decoder
  (`DecompressionFault::Lz4DecodeError`) instead of allocating, so no
  `take(+1)`-style trick is needed.
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

[^1]: Decode-side oracle: `FabianFG/CUE4Parse/CUE4Parse/Compression/Compression.cs@c7e78422ec4858036c9bba5d9d3c55eb197f93c9` (routes `CompressionMethod.LZ4` to the K4os raw-block `LZ4Codec.Decode`). Write-side oracle: `trumank/repak/repak/src/data.rs@e215472c51db69328b1ce77be2db24d24c1d646b` (`lz4_flex::block::compress`) and `trumank/repak/repak/src/entry.rs@e215472c51db69328b1ce77be2db24d24c1d646b` (`lz4_flex::block::decompress_into` with `chunks_mut(chunk_size)`, where `chunk_size` is the entry's `uncompressed` size for single-block entries and `compression_block_size` otherwise — see "Per-block decompressed size derivation" for how that maps onto the formula this doc specifies). Block-format specification: the LZ4 project's `lz4_Block_format.md` (`lz4/lz4` on GitHub).
