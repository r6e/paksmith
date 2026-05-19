# UE Compression Family Documentation — PR 6 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Populate `docs/formats/compression/` with three documents: `pak-block-framing.md` (`complete | complete`, how `.pak` carves entry payloads into compressed blocks), `zlib.md` (`complete | complete`, paksmith's only fully-implemented decompressor), and `oodle.md` (`partial | partial`, detection works but decompression rejects due to Epic's proprietary licensing). Add three rows to the root inventory.

**Architecture:** Two docs reflect Phase 1 shipped work; the Oodle doc honestly reflects paksmith's design constraint — the codec is detected at the parser layer but decompression is left to a future runtime-loaded shared library because the codec is non-redistributable. The decompression-bomb defense (`take(budget+1)` + per-block `try_reserve`) is load-bearing across both shipped formats and warrants its own subsection.

**Tech Stack:** Pure markdown. PR 1 linters. Primary oracle is `trumank/repak` (paksmith's pak cross-validator); secondary is CUE4Parse. For Oodle: the canonical public reference is `cbloomrants.blogspot.com` documentation plus the headers in `OODLE-2.x` SDK distributions; neither of those is a redistributable code reference, so paksmith cites `CUE4Parse/Compression/Oodle.cs` for the integration surface (which has the same loader-shape questions paksmith faces).

**Spec reference:** `docs/design/2026-05-19-ue-format-docs.md` (commit `72b364e`). **Prerequisite:** PR 1 (framework scaffold) has merged to `main`.

---

## Prerequisites

Follow [PREAMBLE.md](2026-05-19-ue-format-docs-PREAMBLE.md). Family name `compression`; capture `<REPAK_SHA>` and `<CUE4PARSE_SHA>` at preamble Step 7.

## File structure

**Create (3 docs):**

- `docs/formats/compression/pak-block-framing.md` — entry-payload block framing.
- `docs/formats/compression/zlib.md` — Zlib decompression.
- `docs/formats/compression/oodle.md` — Oodle (partial — detection only).

**Modify (1):**

- `docs/formats/README.md` — add three rows to the inventory.

**Oracle citation policy.** Primary: `trumank/repak` (matches paksmith's fixture cross-validator) plus `CUE4Parse/Compression/` for the codec integration surface. The Oodle doc additionally cites `RAD Game Tools / Epic Games Tools` documentation by name (no link — the upstream docs sit behind an SDK download). No engine-source links.

**Hex-anchor policy.** `tests/fixtures/real_v11_compressed.pak` carries a compressed entry; its `compression_blocks` array anchors `pak-block-framing.md`. `zlib.md` reuses the same fixture but anchors on the per-block compressed bytes. `oodle.md` uses `(none yet — no Oodle fixture; Oodle is non-redistributable so we cannot ship one)`.

---

## Task 1: Per-family setup

Run [PREAMBLE.md](2026-05-19-ue-format-docs-PREAMBLE.md)'s "Per-family setup" with `<family> = compression`. Capture oracle SHAs at preamble Step 7 for use across this plan's doc citations.

---

## Task 2: Author `docs/formats/compression/pak-block-framing.md`

How a single pak entry's payload is carved into compressed blocks, what the per-block `(start, end)` records carry, and how v3-v4 file-relative vs v5+ entry-relative offsets differ.

**Files:**
- Create: `docs/formats/compression/pak-block-framing.md`

**Ground truth references:**
- `crates/paksmith-core/src/container/pak/index/compression.rs` (127 lines) — `CompressionMethod`, `CompressionBlock`.
- `crates/paksmith-core/src/container/pak/index/entry_header.rs` (885 lines) — `PakEntryHeader`, `EntryCommon`, `CompressionFieldWidth`.
- `crates/paksmith-core/src/container/pak/mod.rs:1221+` — `stream_zlib_to`, the per-block decompression loop.
- `crates/paksmith-core/src/container/pak/version.rs:119` — `RelativeChunkOffsets` variant (v5+ entry-relative).

- [ ] **Step 1: Read the parsers**

Run: `cat crates/paksmith-core/src/container/pak/index/compression.rs`
Run: `head -150 crates/paksmith-core/src/container/pak/index/entry_header.rs`
Run: `sed -n '1221,1300p' crates/paksmith-core/src/container/pak/mod.rs`

Note the v3-v4 vs v5+ offset-relativity split and the role of
`compression_block_size` in the entry header.

- [ ] **Step 3: Capture a hex anchor for the compression-blocks array**

Run: `xxd tests/fixtures/real_v11_compressed.pak | head -40`
Locate the entry header's compression-blocks array. Each block is two u64s (start, end). Capture the bytes for the worked-example block.

- [ ] **Step 4: Write the doc**

Write `docs/formats/compression/pak-block-framing.md`:

````markdown
# Pak entry compression-block framing

> How a single `.pak` entry's compressed payload is partitioned into
> per-block `(start, end)` byte ranges, and how those ranges decompress
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
per block, each `(start_offset, end_offset)` of the compressed
representation. The reader iterates: for each block, seek to
`start_offset`, read `end_offset - start_offset` compressed bytes,
decompress to a buffer of `compression_block_size` uncompressed bytes
(or smaller for the final block), write to the output stream, advance.

The independence per block is what makes pak archives streamable: a
consumer asking for a specific byte range of an entry only needs to
decompress the blocks that overlap that range. Paksmith's
`read_entry_to(path, writer)` streams the full entry block by block
to keep peak memory bounded.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| Wire version 3 (`CompressionEncryption`, UE 4.4) | Block framing introduced; offsets are **file-relative**. | `trumank/repak/repak/src/entry.rs@<REPAK_SHA>`[^1] |
| Wire version 5+ (`RelativeChunkOffsets`, UE 4.20+) | Block offsets became **entry-relative** (start is from the entry's payload start, not the file start). Reader subtracts the entry header bytes when normalizing. | Same[^1] |
| Wire version 8+ | Per-entry `compression` byte became a 1-based index into the footer's compression-method FName table (instead of a raw method ID). Block framing itself unchanged. | Same[^1] |

V8A vs V8B: the per-entry compression byte width changes (u8 vs u32);
the block-array shape doesn't. See [`../container/pak.md`](../container/pak.md).

## Wire layout

### Per-entry block framing (within `PakEntryHeader`)

| field | size | type | semantics |
|-------|------|------|-----------|
| `compression_blocks_count` | 4 | `u32` LE | Number of blocks. Implicit — derived from the array size in the parsed header. |
| `compression_blocks` | `count × 16` | `CompressionBlock[]` | Per-block `(start: u64, end: u64)` pairs. |
| `encrypted` | 1 | `u8` | Per-entry AES-256 ECB flag. When `1`, the compressed bytes within each block must be decrypted before decompression. |
| `compression_block_size` | 4 | `u32` LE | Uncompressed bytes per block (typically `64 * 1024 = 65,536`). Last block may be smaller. |

Each `CompressionBlock` is two LE `u64`s on disk: 16 bytes total per block.

### Per-block `(start, end)` semantics

- `start` is the byte offset of the first compressed byte of the block.
- `end` is the byte offset one past the last compressed byte of the block.
- Both are u64. `len = end - start` (paksmith rejects `start > end` as
  `IndexParseFault::CompressionBlockInvalid { start, end }`).
- An empty block (`start == end`) is legal but unusual.

The **relativity** of `start` and `end` depends on the pak version:

- **V3 / V4** (`Initial` / `IndexEncryption`): offsets are
  **file-relative**. `start = 0x1A40` means "byte 0x1A40 in the .pak
  file itself".
- **V5+** (`RelativeChunkOffsets` onward): offsets are
  **entry-relative**. `start = 0x40` means "byte 0x40 after the
  entry's header, i.e. in the entry's payload region". Reader
  normalizes by adding the per-entry payload base offset.

V10+ encoded entries (in the path-hash index's EntryData region)
sometimes elide the explicit blocks array when there's a single
block or when all blocks are exactly `compression_block_size` and
contiguous — the encoding's bit hints let the reader synthesize the
blocks rather than store them. See `entry_header.rs::PakEntryHeader::Flat`
and `EncodedInData` for the dispatch.

### Decompression loop

Pseudocode (paksmith's `stream_*_to` family):

```
remaining = uncompressed_size
for each block (start, end) in compression_blocks:
    seek_to(absolute_offset(start))
    read block_len = end - start compressed bytes (try_reserve)
    if encrypted:
        AES-256-ECB-decrypt the compressed bytes in place
    budget = remaining + 1   # +1 to detect over-expansion
    decompress with method's decoder, taking at most `budget` bytes:
        per-chunk read + try_reserve, append to scratch
    block_decompressed_len = scratch.len()
    if block_decompressed_len > expected:
        return DecompressionFault::BombDetected
    writer.write_all(&scratch)
    remaining -= block_decompressed_len
assert remaining == 0
```

The `take(budget)` and per-block `try_reserve` are paksmith's
decompression-bomb defense: a malicious entry that claims a 1 KiB
uncompressed size but contains a 1 GiB-expanding block is rejected
when the budget is exhausted, with no allocation past the budget
itself.

### Worked example: compression-blocks array

```bash
xxd tests/fixtures/real_v11_compressed.pak | head -40
```

Find the entry header's compression-blocks array — each record is
two u64s LE. The byte sequence `40 00 00 00 00 00 00 00` (= start
offset `0x40`) followed by `00 04 00 00 00 00 00 00` (= end offset
`0x400`) would denote a single 960-byte block running from offset
`0x40` to `0x3FF` of the entry's payload (v5+ relativity).

*(Re-run Step 3 to capture the actual fixture bytes.)*

## Variants

### V3-V4 file-relative offsets

Older archives publish block offsets relative to the file. The
reader subtracts the entry's payload start to normalize to
entry-relative before decompressing. This is a paksmith-side
normalization, not a wire-format conversion — the on-disk bytes
remain file-relative.

### V10+ encoded entries

V10+ archives store entries in a tightly-packed bitfield form (see
[`../container/pak.md`](../container/pak.md) — "Entry header (encoded
form, v10+)"). For single-block or fully-aligned multi-block entries,
the blocks array may be elided and the blocks computed by the
reader from `(offset, size, compression_block_size, block_count)`.

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
- **Per-block decompression budget** = `remaining + 1`. A block that
  decompresses to more than `remaining + 1` bytes is the canonical
  "decompression bomb" signal. Surfaces as
  `DecompressionFault::ExpansionExceedsBudget { block_index, … }`.
- **Per-block compressed reservation** via `try_reserve`. A
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
- **Cross-validation oracle:** repak[^1] (paksmith's primary pak
  oracle) and CUE4Parse[^2]. Every compressed fixture round-trips
  through repak at fixture-gen time.
- **Known divergences:** none on the block-framing wire shape itself.
  The v3-v4 file-relative → entry-relative normalization is internal
  to paksmith's reader; repak handles it the same way.

## Paksmith implementation

**Parser modules:**
- `crates/paksmith-core/src/container/pak/index/compression.rs` —
  `CompressionMethod`, `CompressionBlock`.
- `crates/paksmith-core/src/container/pak/index/entry_header.rs` —
  `PakEntryHeader::{Flat, EncodedInData}` with the per-block array.
- `crates/paksmith-core/src/container/pak/mod.rs` — `stream_zlib_to`
  block loop (the canonical reference implementation; other methods
  share the same outer loop shape).

**Status:** `complete`.

**Public surface:**
- `pub struct CompressionBlock` — `start()`, `end()`, `len()`, `is_empty()`.
- `pub enum CompressionMethod` — `None`, `Zlib`, `Gzip`, `Oodle`,
  `Zstd`, `Lz4`, `Unknown(NonZeroU32)`, `UnknownByName(String)`
  (`#[non_exhaustive]`).
- `pub fn CompressionBlock::new(start, end) -> Result<Self>` —
  validates `start <= end`.

**Error variants** (selected):
- `IndexParseFault::CompressionBlockInvalid { start, end }`.
- `IndexParseFault::BoundsExceeded { field: WireField::UncompressedSize, value, limit, unit: BoundsUnit::Bytes, path }`.
- `DecompressionFault::CompressedBlockReserveFailed { block_index, requested, source }`.
- `DecompressionFault::ExpansionExceedsBudget { block_index, … }`.
- `DecompressionFault::ZlibStreamError { block_index, kind, message }`
  (for the zlib path; other methods get analogous variants when
  implemented).

**Cap constants:**
- `MAX_UNCOMPRESSED_ENTRY_BYTES: u64 = 8 GiB` (`pak/mod.rs:86`).

**Phase plan:** `docs/plans/phase-1-foundation.md`.

## References

[^1]: `trumank/repak/repak/src/entry.rs@<REPAK_SHA>` — paksmith's primary pak oracle. Documents the V5+ entry-relative-offsets convention and the per-block `(start, end)` u64 pair.
[^2]: `FabianFG/CUE4Parse/CUE4Parse/PakFile/PakFileReader.cs@<CUE4PARSE_SHA>` — secondary oracle. Block-decompression loop shape is consistent.
````

- [ ] **Step 5: Commit** (preamble convention — required-headings linter must pass before commit)

```bash
git add docs/formats/compression/pak-block-framing.md
git commit -m "$(cat <<'EOF'
docs(formats): add pak entry block-framing reference

Documents the per-entry compression-blocks array: each record is two
u64s (start, end), wire version 3-4 file-relative vs v5+ entry-
relative offsets, compression_block_size (typically 64 KiB), and the
V10+ encoded-form's elision of the blocks array for single-block or
fully-aligned entries. Spells out the take(budget+1) + per-block
try_reserve decompression-bomb defense.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Author `docs/formats/compression/zlib.md`

The only fully-implemented decompression backend. Wire shape is just "the per-block bytes are a zlib stream"; the interesting content is paksmith's bomb-defense layering.

**Files:**
- Create: `docs/formats/compression/zlib.md`

**Ground truth references:**
- `crates/paksmith-core/src/container/pak/mod.rs:1221+` — `stream_zlib_to`.
- `crates/paksmith-core/src/error.rs` — `DecompressionFault::ZlibStreamError`, `CompressedBlockReserveFailed`, related variants.
- Dependency: `flate2` crate (`ZlibDecoder`).

- [ ] **Step 1: Read the parser**

Run: `sed -n '1221,1450p' crates/paksmith-core/src/container/pak/mod.rs`

- [ ] **Step 3: Capture a fresh hex anchor**

Run: `xxd tests/fixtures/real_v11_compressed.pak | head -50`
Find the first compressed block's bytes. A zlib stream starts with
the 2-byte zlib header `78 ...` (CMF byte 0x78 = deflate, 32 KiB
window; FLG byte varies). Capture the first 8-16 bytes.

- [ ] **Step 4: Write the doc**

Write `docs/formats/compression/zlib.md`:

````markdown
# Zlib decompression

> The default `.pak` compression backend — Zlib (RFC 1950) wrapping a
> deflate stream (RFC 1951). The only decompressor paksmith fully
> implements; every other UE compression method is detected but not
> decompressed.

## Overview

When a pak entry uses `CompressionMethod::Zlib` (raw method ID `1`
for v3-v7 archives, FName `"Zlib"` in the footer's compression-method
table for v8+ archives — see
[`../container/pak.md`](../container/pak.md)), each block of its
payload (see [`pak-block-framing.md`](pak-block-framing.md)) is a
standalone Zlib stream.

UE's writer uses the standard Zlib container (RFC 1950): a 2-byte
header (CMF + FLG), the deflate data (RFC 1951), and a 4-byte
Adler-32 checksum trailer. The 32 KiB sliding-window default
(CMF = `0x78`) is universal in cooked UE content.

Paksmith decompresses through the `flate2` crate's `ZlibDecoder`,
wrapping it in a `Read::take(budget)` adapter to enforce the
decompression-bomb cap on a per-block basis. See Caps & limits.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| Wire version 3+ | Zlib introduced. Method ID `1` (v3-v7) or FName `"Zlib"` (v8+). Stream layout (RFC 1950 zlib wrapping RFC 1951 deflate) has not changed. | `trumank/repak/repak/src/compression.rs@<REPAK_SHA>`[^1] |

## Wire layout

Per RFC 1950 — paksmith does not invent any wrapper on top of the
zlib stream. Each compression block's bytes are exactly one zlib
stream:

| offset (within block) | size | name | semantics |
|----------------------|------|------|-----------|
| 0 | 1 | `CMF` | Compression Method and Flags. UE cooked content uses `0x78` (method=deflate=8, info=7=32 KiB window). |
| 1 | 1 | `FLG` | Flags (FCHECK + FDICT + FLEVEL). FDICT is always 0; FLEVEL varies (`0x9C` = default compression, `0xDA` = best compression — both observed). |
| 2 | variable | `DEFLATE` | RFC 1951 deflate data. |
| `end - 4` | 4 | `ADLER32` | Adler-32 checksum of the uncompressed bytes (big-endian per RFC 1950). |

A typical UE-cooked zlib block starts with `78 9C` or `78 DA`.

### Worked example: first compressed block

```bash
xxd tests/fixtures/real_v11_compressed.pak | head -50
```

Find the first compressed block's bytes (the entry header's first
`CompressionBlock`'s `(start, end)` range). The first 2 bytes are
the CMF + FLG zlib header — almost always `78 9C` or `78 DA` in
UE cooked content.

*(Re-run Step 3 to capture exact bytes.)*

## Variants

### Compression level

UE writers may produce streams at any zlib compression level (1 = fastest, 9 = best). The decompressor doesn't need to know; the stream self-describes via the FLG byte. Paksmith ignores the level for decoding purposes.

### Dictionary

UE's writer doesn't use the optional preset-dictionary feature (RFC 1950 FDICT bit). Paksmith would refuse to decode an FDICT-bit-set stream because `flate2::ZlibDecoder` requires a caller-provided dictionary in that case — but no UE writer has been observed to emit one.

## Caps & limits

The decompression-bomb defense is the load-bearing safety layer.
Three nested controls:

- **Entry-level cap.** `uncompressed_size > MAX_UNCOMPRESSED_ENTRY_BYTES = 8 GiB`
  rejected at index-parse time (`IndexParseFault::BoundsExceeded { field: WireField::UncompressedSize, … }`).
- **Per-block budget cap.** Each block decompresses against a
  `take(budget)` adapter where `budget = remaining_uncompressed + 1`.
  A block expanding past `budget` is stopped at exactly `budget`
  bytes; the post-block size check rejects as
  `DecompressionFault::ExpansionExceedsBudget { block_index, … }`.
  The `+1` is deliberate: it makes the post-loop check
  `decompressed > expected` rather than `≥ expected`, surfacing
  bombs that aim to exactly hit the declared size as well as those
  that overshoot.
- **Per-chunk fallible allocation.** The decompressor reads into a
  scratch buffer in fixed-size chunks; the per-block decompressed
  Vec grows via `try_reserve` per chunk, surfacing allocator
  pressure as `DecompressionFault::CompressedBlockReserveFailed { block_index, requested, source }`
  rather than an `alloc::handle_alloc_error` abort.

These three are layered: the entry-level cap bounds the worst case
the budget can adopt; the budget bounds what the decompressor will
read; the per-chunk reserve bounds what the allocator commits at any
instant. Bypassing any one without bypassing all three is impossible
in current code.

## Verification

- **Fixtures:**
  - `tests/fixtures/real_v11_compressed.pak` — V11 zlib-compressed.
  - `tests/fixtures/real_v10_compressed.pak` — V10 counterpart.
  - `tests/fixtures/real_v8a_compressed.pak` / `real_v8b_compressed.pak`
    — V8 family.
- **Cross-validation oracle:** repak[^1] (paksmith's primary pak
  oracle). Decompresses every compressed fixture identically
  byte-for-byte.
- **Known divergences:** none on zlib decoding. Paksmith's fallible-allocation
  + bomb-budget layering is paksmith-specific; repak uses an
  infallible decompressor (panic on OOM). Both produce the same
  decompressed bytes on legitimate input.

## Paksmith implementation

**Parser module:** `crates/paksmith-core/src/container/pak/mod.rs`
(`stream_zlib_to` at line 1221 plus the dispatch sites that route to
it).

**Status:** `complete`.

**Public surface:**
- Zlib is the only `CompressionMethod` paksmith's
  `PakReader::read_entry` / `read_entry_to` / `verify_entry` will
  fully process. Other methods route to
  `PaksmithError::UnsupportedCompression { method }`.
- The decompression path itself is `pub(in crate::container::pak)`;
  consumers go through `PakReader::read_entry(path)` →
  `Vec<u8>` or `PakReader::read_entry_to(path, writer)` →
  streamed.

**Error variants:**
- `DecompressionFault::ZlibStreamError { block_index, kind, message }` —
  any error surfaced by `flate2::ZlibDecoder` (truncation, invalid
  block, bad Adler-32, etc.). Carries `block_index` and the underlying
  `io::ErrorKind` for diagnostics.
- `DecompressionFault::CompressedBlockReserveFailed { block_index, requested, source }`.
- `DecompressionFault::ExpansionExceedsBudget { block_index, … }`.

**Cap constants:** `MAX_UNCOMPRESSED_ENTRY_BYTES = 8 GiB` (inherited
from the pak layer; see [`pak-block-framing.md`](pak-block-framing.md)).

**Dependencies:** `flate2 ≥ 1.x` (workspace pin). The crate provides
`ZlibDecoder` over the `miniz_oxide` Rust-native deflate
implementation by default — no C `zlib` linkage in paksmith's
default-features build.

**Phase plan:** `docs/plans/phase-1-foundation.md`.

## References

[^1]: `trumank/repak/repak/src/compression.rs@<REPAK_SHA>` — primary oracle. Wraps `flate2` similarly; consensus on zlib being the default UE compression backend.
[^2]: RFC 1950 (Zlib container) and RFC 1951 (deflate stream) are the IETF standards. Not cited inline because they're external to the UE ecosystem; readers needing them can find them by number.
````

- [ ] **Step 5: Commit** (preamble convention — required-headings linter must pass before commit)

```bash
git add docs/formats/compression/zlib.md
git commit -m "$(cat <<'EOF'
docs(formats): add zlib decompression reference

Documents the standard RFC 1950 zlib container wrapping an RFC 1951
deflate stream as paksmith's only fully-implemented decompression
backend. Spells out the three-layer decompression-bomb defense
(entry cap MAX_UNCOMPRESSED_ENTRY_BYTES = 8 GiB, per-block
take(budget+1), per-chunk try_reserve) and the flate2 dependency
(miniz_oxide backend, no C zlib linkage).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Author `docs/formats/compression/oodle.md` (partial)

Oodle Data (Mermaid, Kraken, Selkie, Leviathan, LZNA, BitKnit, plus LZ4 wrapped) is Epic-licensed proprietary compression. Paksmith detects Oodle-compressed entries but cannot decompress them because the codec is non-redistributable. This doc documents the detection surface, the rejection behavior, and the future shape of the runtime-loaded shared-library integration.

**Files:**
- Create: `docs/formats/compression/oodle.md`

**Ground truth references:**
- `crates/paksmith-core/src/container/pak/index/compression.rs:32` — `CompressionMethod::Oodle` variant.
- `crates/paksmith-core/src/container/pak/mod.rs:811` and `:1006` — rejection sites where Oodle currently routes to `UnsupportedCompression`.
- `crates/paksmith-core/src/error.rs` — `UnsupportedCompression { method }` variant.

- [ ] **Step 1: Read the parsers**

Run: `grep -n "Oodle\|UnsupportedCompression" crates/paksmith-core/src/container/pak/mod.rs | head -20`
Run: `grep -n "UnsupportedCompression\|Oodle" crates/paksmith-core/src/error.rs | head -10`

- [ ] **Step 3: Write the doc**

Write `docs/formats/compression/oodle.md`:

````markdown
# Oodle decompression

> RAD Game Tools' Oodle Data compression suite — Epic's recommended
> backend for shipped UE titles. Paksmith detects Oodle-compressed
> entries but rejects them at decompression time; the codec is
> proprietary and non-redistributable.

## Overview

Oodle Data is a commercial compression suite licensed by RAD Game
Tools (now part of Epic Games Tools) covering several encoders:

- **Kraken** — high-ratio, mid-speed; the default for UE5 shipping.
- **Mermaid** — faster decode, lower ratio than Kraken.
- **Selkie** — faster decode than Mermaid, lower ratio.
- **Leviathan** — highest ratio, slowest decode; used for cold-load assets.
- **LZNA** — older, replaced by Kraken in newer SDKs.
- **BitKnit** — short-block variant.

On disk in a UE pak, Oodle compression is signaled by `CompressionMethod::Oodle`
(method ID `4` in v3-v7 archives; FName `"Oodle"` in the v8+
compression-method table). The per-entry compression-blocks framing
(see [`pak-block-framing.md`](pak-block-framing.md)) is identical to
zlib-compressed entries — what differs is the per-block compressed
bytes are an Oodle stream rather than a zlib stream.

**Paksmith status: `partial`.** Paksmith detects Oodle archives at
parse time (the entry's `CompressionMethod` resolves to
`CompressionMethod::Oodle`) but rejects decompression with
`PaksmithError::UnsupportedCompression { method: Oodle }`. The codec
is **not bundled** with paksmith because Oodle requires a
RAD/Epic license. A future runtime-loaded shared-library integration
will let consumers who have a licensed Oodle SDK installed enable
decompression at runtime; the integration shape is sketched below
under Variants.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| Wire version 4+ (UE 4.16+, sporadically; UE 4.21+ commonly; UE 5.x universally) | Oodle introduced as `CompressionMethod::Oodle` (raw method ID 4 in v3-v7; FName `"Oodle"` in v8+). | `CUE4Parse/Compression/Oodle.cs@<CUE4PARSE_SHA>`[^1] |
| Oodle SDK 2.6 → 2.9 | Stream-format-compatible across SDK versions; a decoder built against SDK 2.6 reads streams compressed with SDK 2.9 and vice versa within the published-compatibility matrix. Encoder choices (Kraken vs Mermaid vs Selkie) are encoded in the stream header byte. | RAD Game Tools / Epic Games Tools "Oodle Data" documentation (no public URL — distributed with the licensed SDK). |

Within paksmith's accepted UE range, Oodle stream format itself does
not change across UE versions — UE bundles a specific Oodle SDK per
engine release, but the on-disk stream is compatible across them.

## Wire layout

Per RAD's Oodle SDK documentation; reproduced here at a high level
because the byte-level format is proprietary and Epic does not
publish it.

| offset (within block) | size | name | semantics |
|----------------------|------|------|-----------|
| 0 | 2 | `header` | Stream header. High nibble = encoder family (Kraken, Mermaid, Selkie, Leviathan). Low nibble + flags = SDK-version-dependent metadata. |
| 2 | variable | `payload` | Encoder-specific payload. Each encoder has its own internal block / chunk structure. |

The full byte layout is documented only in the licensed Oodle SDK
(specifically the `OodleNetwork2.pdf` and `OodleCore_Compression.h`
headers shipped with each SDK release). Paksmith does not reproduce
it here because:

1. Reverse-engineered byte-level documentation would distribute
   information Epic / RAD treats as proprietary.
2. paksmith does not need it — the future integration calls into
   the licensed shared library, which accepts a compressed buffer
   and writes the decompressed output; no parsing of the
   Oodle-internal layout happens on the paksmith side.

If a future paksmith needs Oodle byte-level documentation (e.g. for
a fixture-gen oracle), the right move is to cite CUE4Parse's
`Compression/Oodle.cs` for its loader-integration code and rely on
RAD's documentation for the format details, with no reverse-engineered
content shipped in this repo.

### Worked example

`(none yet — no Oodle fixture)`. Oodle-compressed test fixtures are
not shipped with paksmith because:

1. Oodle-compressed bytes would require either redistributing
   Oodle-licensed cooked content (not allowed) or generating fresh
   Oodle-compressed bytes with a licensed Oodle SDK paksmith does
   not ship.
2. Detection (the part paksmith does implement) can be exercised
   with a synthetic fixture whose entry header declares
   `CompressionMethod::Oodle` and whose payload is unreachable —
   the parser stops at the unsupported-decompression error before
   reading any compressed bytes. No production fixture is needed.

## Variants

### Encoder selection

The high nibble of the stream's first header byte selects the
encoder (Kraken, Mermaid, Selkie, Leviathan, etc.). Different UE
projects use different encoders depending on their decompression
performance budget; cooked content within one game typically picks
one encoder for all assets. The decoder dispatches on the header
byte; consumers don't need to know the encoder in advance.

### Future runtime-loaded SDK integration

When implemented, the shape paksmith expects to use:

1. **No build-time dependency.** Paksmith builds and tests run
   without the Oodle SDK; the codec is opt-in at runtime.
2. **Runtime `dlopen`/`LoadLibrary` of `liboo2corelinux64.so` /
   `oo2core_win64.dll` / `liboo2coremac64.dylib`.** The library
   path is configurable via an environment variable or a future
   `[oodle]` section in a profile config.
3. **`OodleLZ_Decompress` is the only entry point called.** Its C
   signature is `intptr_t OodleLZ_Decompress(const u8* in, intptr_t in_size, u8* out, intptr_t out_size, int fuzz_safe, int check_crc, int verbosity, void* dec_buf, intptr_t dec_buf_size, void* fp_callback, void* user_data, void* scratch, intptr_t scratch_size, int thread_phase)`.
   `fuzz_safe = 1` is required (it's the option that makes Oodle
   reject malformed streams instead of crashing).
4. **Decompression cap layering matches zlib.** The Oodle output
   buffer is bounded by the same per-block budget the zlib path
   uses; Oodle's own bounds-checking serves as a second layer.

This integration is **deferred work** — not yet in any phase plan.
A natural insertion point is a Phase 3+ task that adds support for
Oodle-compressed asset bulk-data (which is the most common
shipping-cooked-game blocker on paksmith adoption today).

## Caps & limits

No Oodle-specific caps yet. When the SDK integration lands, it will
inherit:

- The pak entry-level cap (`MAX_UNCOMPRESSED_ENTRY_BYTES = 8 GiB`).
- The per-block budget layering described in
  [`zlib.md`](zlib.md).
- An additional `OodleLZ_Decompress` `out_size` bound that the
  Oodle library itself enforces (defense in depth).

See `docs/security/allocation-caps.md` for the broader policy.

## Verification

- **Fixture:** `(none yet — Oodle non-redistributable)`. The
  detection path can be exercised with a synthetic fixture that
  declares `CompressionMethod::Oodle` and whose entry's compressed
  bytes are unreachable; the parser stops at the unsupported-
  decompression error before reading. Such a synthetic fixture is
  not currently in the test suite — adding one would surface the
  detection coverage in CI without requiring a licensed Oodle SDK.
- **Cross-validation oracle:** CUE4Parse[^1] for the loader-
  integration code. The licensed Oodle SDK is the authoritative
  reference for the stream format itself.
- **Known divergences:**
  - **Decompression unimplemented.** CUE4Parse offers a `dlopen`-style
    runtime SDK load; paksmith currently rejects. Both projects
    agree on the *detection* — the FName slot reads as `"Oodle"`,
    the method byte reads as `4` — only the post-detection action
    differs.

## Paksmith implementation

**Parser module:**
`crates/paksmith-core/src/container/pak/index/compression.rs`
(`CompressionMethod::Oodle` variant) plus the rejection sites in
`crates/paksmith-core/src/container/pak/mod.rs:811`, `:1006`, and
`:1069`.

**Status:** `partial`. Detection ships; decompression rejects with
`PaksmithError::UnsupportedCompression { method: Oodle }`.

**Public surface:**
- `CompressionMethod::Oodle` — detection variant.
- `PakReader::read_entry(path)` returns
  `PaksmithError::UnsupportedCompression { method: Oodle }` for any
  Oodle-compressed entry.

**Error variants:**
- `PaksmithError::UnsupportedCompression { method: CompressionMethod::Oodle }`.
- Future: `DecompressionFault::OodleLibraryNotFound`,
  `OodleStreamError { … }`, etc. when the SDK integration lands.

**Cap constants:** none yet.

**Phase plan:** not yet in a phase plan. A Phase 3+ insertion is the
likely path — texture / audio / mesh bulk-data work is the dominant
use case for Oodle-compressed entries.

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/Compression/Oodle.cs@<CUE4PARSE_SHA>` — primary oracle for the loader-integration shape. Covers the `dlopen`-equivalent runtime load and the `OodleLZ_Decompress` call signature.
[^2]: RAD Game Tools / Epic Games Tools "Oodle Data SDK Documentation" — distributed with the licensed SDK; no public URL. Cite by name (not link) per the no-engine-source attribution rule, which applies analogously to RAD's proprietary SDK documentation.
````

- [ ] **Step 4: Commit** (preamble convention — required-headings linter must pass before commit)

```bash
git add docs/formats/compression/oodle.md
git commit -m "$(cat <<'EOF'
docs(formats): add Oodle partial reference

Documents the Oodle Data suite (Kraken/Mermaid/Selkie/Leviathan/
LZNA/BitKnit) as paksmith's detected-but-not-decompressed
compression method. Explains the proprietary-codec / licensing
constraint that motivates the runtime-loaded SDK integration shape
sketched in Variants. Documents the current rejection path
(UnsupportedCompression { method: Oodle }) and the future
OodleLZ_Decompress entry-point contract.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Update root inventory + final verification + push

**Files:**
- Modify: `docs/formats/README.md`

- [ ] **Step 2: Add three rows to the inventory**

Verify the existing inventory layout with `grep -n "^|" docs/formats/README.md`, then use Edit to insert three new rows.

Rows to insert:

```markdown
| `compression/pak-block-framing.md` | complete | complete | `container/pak/index/compression.rs` | repak @ `<REPAK_SHA>` | `<SHA>` |
| `compression/zlib.md` | complete | complete | `container/pak/mod.rs` | repak @ `<REPAK_SHA>` | `<SHA>` |
| `compression/oodle.md` | partial | partial | `container/pak/index/compression.rs` | CUE4Parse @ `<CUE4PARSE_SHA>` | `<SHA>` |
```

Two `complete | complete`, one `partial | partial`. The Oodle row's
`Last verified` is this branch's HEAD — the detection behavior IS
verified against the real codepath; what's partial is the
decompression, which the doc documents accurately as unimplemented.

- [ ] **Step 8: Commit the inventory update**

```bash
git add docs/formats/README.md
git commit -m "$(cat <<'EOF'
docs(formats): register the compression-family docs in the inventory

Two complete-complete rows (pak-block-framing — the per-entry
block array; zlib — the only fully-implemented decompressor) and
one partial-partial row (oodle — detection works, decompression
rejects pending the runtime-loaded SDK integration). Last-verified
anchor for all three is this branch's HEAD.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

```
<sha> docs(formats): register the compression-family docs in the inventory
<sha> docs(formats): add Oodle partial reference
<sha> docs(formats): add zlib decompression reference
<sha> docs(formats): add pak entry block-framing reference
```

- [ ] **Step 11: Open the PR**

Title: `docs(formats): populate compression family (pak-block-framing/zlib/oodle)`

Body — write to a tempfile first, then `gh pr create --body-file <tempfile>`:

```markdown
## Summary

Lands PR 6 of the UE format documentation framework. Populates
`docs/formats/compression/` with three documents:

- **`pak-block-framing.md`** — per-entry compression-blocks array,
  v3-v4 file-relative vs v5+ entry-relative offsets, the
  `compression_block_size` field, V10+ encoded-form block elision,
  and the per-block decompression-loop pseudocode.
- **`zlib.md`** — RFC 1950 / RFC 1951 stream wrapping, the
  `78 9C` / `78 DA` header signature observed in UE cooked content,
  the three-layer decompression-bomb defense (entry-cap +
  per-block budget + per-chunk `try_reserve`), and the `flate2`
  dependency.
- **`oodle.md`** *(partial)* — RAD Game Tools' proprietary Oodle
  Data suite (Kraken / Mermaid / Selkie / Leviathan), paksmith's
  detection-but-not-decompression behavior, the licensing constraint
  driving the runtime-loaded shared-library integration, and the
  future `OodleLZ_Decompress` entry-point contract.

Three rows added to the root inventory: two `complete | complete`,
one `partial | partial`.

## Linked issue

(none — design spec drives this work)

## Test plan

- [x] `paksmith-doc-lint required-headings` passes on all docs.
- [x] `paksmith-doc-lint status-enum` passes on the updated inventory.
- [x] `typos docs/formats/compression/` clean.
- [x] `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features` clean.
- [x] Cross-validated every wire-format claim against trumank/repak (primary) + CUE4Parse (secondary).

## Pre-flight checklist

- [x] PR title is a Conventional Commit.
- [x] Branch name follows `<type>/<kebab-case>`.
- [x] `cargo fmt --all` clean (no Rust changed).
- [x] `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean.
- [x] Documentation updated (this PR IS documentation).
- [x] No `unsafe` introduced.
- [x] Touched a parser? No — pure docs PR.

## Security considerations

The pak-block-framing and zlib docs document paksmith's
decompression-bomb defense explicitly. The defense has three
layers: entry-level cap (`MAX_UNCOMPRESSED_ENTRY_BYTES = 8 GiB`),
per-block `take(budget+1)`, per-chunk `try_reserve`. Bypassing one
without bypassing all three is impossible in current code; the docs
make that invariant a visible property of the codebase.

The Oodle doc documents the future SDK integration's `fuzz_safe = 1`
requirement — Oodle's own option for rejecting malformed streams
rather than crashing. Listed as a non-negotiable when the SDK
integration lands.

## Notes for reviewers

- The `oodle.md` Wire layout deliberately does not reproduce
  byte-level Oodle format details. Per the doc's Wire layout
  section, those details are in the licensed SDK and reproducing
  them here would distribute Epic/RAD proprietary information.
  paksmith does not need byte-level Oodle docs to operate — the
  future SDK integration calls the library, which handles parsing
  internally.
- The `pak-block-framing.md` worked example uses
  `tests/fixtures/real_v11_compressed.pak`. The `zlib.md` example
  uses the same fixture's first block's bytes. The `oodle.md` has
  no hex anchor because no Oodle fixture exists (and one cannot be
  generated without a licensed Oodle SDK).
- The `oodle.md` doc cites `RAD Game Tools / Epic Games Tools
  "Oodle Data SDK Documentation"` by name without a URL. This is
  intentional — the rule that bans engine-source links applies
  analogously to RAD's proprietary documentation.
```

---

## Done criteria

Per [PREAMBLE.md](2026-05-19-ue-format-docs-PREAMBLE.md)'s tail (linters green, typos clean, rustdoc clean, PR open, reviewer panel converged), plus this plan's inventory specifics enumerated above.
  inventory).
- `paksmith-doc-lint required-headings docs/formats/` exits 0.
- `paksmith-doc-lint status-enum docs/formats/README.md` exits 0.
- `typos docs/formats/compression/` clean.
- `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features` clean.
- PR open with `--body-file`-generated body and lowercase verb-first title.
- Reviewer panel converged.
- Three rows present in inventory: two `complete | complete`
  (pak-block-framing, zlib), one `partial | partial` (oodle).
