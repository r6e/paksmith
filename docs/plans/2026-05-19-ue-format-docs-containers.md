# UE Container Family Documentation — PR 3 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land PR 3 from the framework spec — populate `docs/formats/container/` with four documents: one full byte-level reference for `.pak` v1–v11 (`pak.md`) and three stubs for the IoStore trio (`iostore-utoc.md`, `iostore-ucas.md`, `iostore-uptnl.md`). Add four rows to the root inventory.

**Architecture:** Asymmetric work split. `pak.md` is large and `complete | complete` because paksmith ships a comprehensive v1–v11 reader at `crates/paksmith-core/src/container/pak/`. The IoStore docs are short `stub | not impl` because Phase 8 hasn't opened — the docs exist as anchor points for the inventory and to mark the territory for future authors. Each doc is its own commit; inventory update + final verification close the PR.

**Tech Stack:** Pure markdown. Linter binaries from PR 1. The pak doc's references point at `trumank/repak` (paksmith's primary pak oracle, named in `crates/paksmith-fixture-gen/`) and CUE4Parse's pak reader; IoStore docs cite CUE4Parse exclusively because repak doesn't cover IoStore.

**Spec reference:** `docs/design/2026-05-19-ue-format-docs.md` (commit `72b364e`). **Prerequisite:** PR 1 (framework scaffold) must have merged to `main`.

---

## Prerequisites

Follow [PREAMBLE.md](2026-05-19-ue-format-docs-PREAMBLE.md) for the per-family setup. This plan's family name is `containers`; capture `<REPAK_SHA>` and `<CUE4PARSE_SHA>` at preamble Step 7.

## File structure

**Create (4 docs):**

- `docs/formats/container/pak.md` — full byte-level reference, v1–v11.
- `docs/formats/container/iostore-utoc.md` — stub.
- `docs/formats/container/iostore-ucas.md` — stub.
- `docs/formats/container/iostore-uptnl.md` — stub.

**Modify (1):**

- `docs/formats/README.md` — add four rows to the inventory table.

**Oracle citation policy.** For pak: cite `trumank/repak` as primary (matches paksmith's existing fixture oracle) and `CUE4Parse/PakFile/` as secondary. For IoStore: cite `CUE4Parse/IO/` only — no Rust IoStore oracle of comparable maturity exists. SHAs are looked up at execution time per the spec's "Sourcing and attribution" section.

**Hex-anchor policy.** `pak.md` has natural anchors in `tests/fixtures/real_v11_minimal.pak` (the footer is at `filesize - 221`). The IoStore stubs use `(none yet — Phase 8 deliverable)` per the spec.

---

## Task 1: Per-family setup

Run [PREAMBLE.md](2026-05-19-ue-format-docs-PREAMBLE.md)'s "Per-family setup" with **`<family> = containers`** (branch/worktree slug) and **`<dir> = container`** (singular — the `docs/formats/` subdirectory). Capture `<REPAK_SHA>` and `<CUE4PARSE_SHA>` at preamble Step 7.

---

## Task 2: Author `docs/formats/container/pak.md`

The flagship doc of this PR. Eleven wire versions, two index layouts, V8A/V8B disambiguation, FNV-1a hashing, three footer-size families, AES-256 ECB encryption.

**Files:**
- Create: `docs/formats/container/pak.md`

**Ground truth references:**
- `crates/paksmith-core/src/container/pak/version.rs` — `PakVersion` enum, footer-size constants, `PAK_MAGIC`.
- `crates/paksmith-core/src/container/pak/footer.rs` — `PakFooter` struct and parser.
- `crates/paksmith-core/src/container/pak/mod.rs` — `PakReader` orchestration, `MAX_UNCOMPRESSED_ENTRY_BYTES`.
- `crates/paksmith-core/src/container/pak/index/mod.rs` — index dispatcher, `ENTRY_MIN_RECORD_BYTES`, FNV-1a constants and `fnv64_path`.
- `crates/paksmith-core/src/container/pak/index/flat.rs` — flat index (v3–v9), `max_flat_index_entries`.
- `crates/paksmith-core/src/container/pak/index/path_hash.rs` — path-hash + encoded directory index (v10+), `max_index_bytes`, `max_fdi_bytes`.
- `crates/paksmith-core/src/container/pak/index/entry_header.rs` — `PakEntryHeader`, `EntryCommon`, `CompressionFieldWidth`.
- `crates/paksmith-core/src/container/pak/index/compression.rs` — `CompressionMethod`, `CompressionBlock`.

**Oracle references:** `trumank/repak/repak/src/pak.rs` (primary — matches paksmith's fixture cross-validation oracle) and `FabianFG/CUE4Parse/CUE4Parse/FileProvider/Objects/VfsEntry.cs` (secondary).

- [ ] **Step 1: Read the parser modules**

Run: `cat crates/paksmith-core/src/container/pak/version.rs`
Run: `cat crates/paksmith-core/src/container/pak/footer.rs | head -200`
Run: `cat crates/paksmith-core/src/container/pak/index/mod.rs | head -120`
Run: `cat crates/paksmith-core/src/container/pak/index/entry_header.rs | head -100`

The module-level doc comments and the constant definitions in `version.rs` carry the most-quoted facts.

- [ ] **Step 2: Verify hex-anchor offset against a real fixture**

Run: `ls -l tests/fixtures/real_v11_minimal.pak`
Note the byte size as `<FILESIZE>`. Compute the footer offset: `<FILESIZE> - 221` (v11 footer size).

Run: `xxd -s $((<FILESIZE> - 221)) -l 32 tests/fixtures/real_v11_minimal.pak`
Note the first 32 bytes of the footer (encryption_guid 16 + encrypted_flag 1 + magic 4 + version 4 + index_offset start). The magic at offset `+17` should be `e1 12 6f 5a` (LE of `0x5A6F12E1`).

Use this captured offset and the actual bytes in the `### Worked example: v11 footer` block below.

- [ ] **Step 3: Write the doc** (using `<REPAK_SHA>` and `<CUE4PARSE_SHA>` from preamble Step 7)

Write `docs/formats/container/pak.md`:

````markdown
# Pak (`.pak`)

> Unreal Engine's primary archive format — eleven wire versions (V1–V11)
> covering UE 4.0 through UE 5.x. Single-file container with a tail-anchored
> footer, two index layouts, optional AES-256 encryption, and per-entry
> compression-block framing.

## Overview

A `.pak` file is a single-file archive: a concatenation of entry payloads
followed by an index region and a fixed-size footer. The footer sits at
known byte offsets from the end of the file and is the only structure
locatable without parsing anything else; everything else is reached via
offsets the footer publishes.

There are three structural concerns a complete pak parser must handle:

1. **Footer parsing.** Read the trailing 44–222 bytes (size depends on
   version). Extract version, encryption flag, index offset and size,
   index SHA1, optional encryption-key GUID, optional compression-method
   FName table, optional frozen-index flag.
2. **Index parsing.** Seek to `index_offset`, read `index_size` bytes
   (decrypt first if `encrypted == true`), verify SHA1 if non-zero. Then
   dispatch on the version: flat index for v3–v9, path-hash + encoded
   directory index for v10+.
3. **Entry payload reading.** Each index entry carries a `PakEntryHeader`
   pointing at a per-entry payload region. The header layout has evolved
   across versions; compression-block framing and per-entry encryption
   live here.

Paksmith's parser dispatch is centered on `PakVersion::has_path_hash_index()`,
which is `true` for v10 and v11 only. Within each side of that split,
per-version field widths and presence-of-field flags account for the
remaining variance.

## Versions

| Wire version | Paksmith variant | UE version | Wire-format change | Source |
|--------------|------------------|------------|---------------------|--------|
| 1 | `Initial` | UE 4.0 | Initial pak format. | `trumank/repak/repak/src/pak.rs@<REPAK_SHA>`[^1] |
| 2 | `NoTimestamps` | UE 4.3 | Removed per-entry timestamps. | Same[^1] |
| 3 | `CompressionEncryption` | UE 4.4 | Added compression-block framing and AES-256 ECB entry encryption. | Same[^1] |
| 4 | `IndexEncryption` | UE 4.16 | Added index-region encryption (toggle in footer). | Same[^1] |
| 5 | `RelativeChunkOffsets` | UE 4.20 | Compression-block offsets became entry-relative instead of file-relative. | Same[^1] |
| 6 | `DeleteRecords` | UE 4.21 | Added entry delete markers (used during patching). | Same[^1] |
| 7 | `EncryptionKeyGuid` | UE 4.22 | Added 16-byte encryption-key GUID to the footer. | Same[^1] |
| 8 | `V8A` | UE 4.22 (brief) | Added 4-slot compression-method FName table; per-entry compression byte is `u8`. | Same[^1] |
| 8 | `V8B` | UE 4.23 – 4.24 | Compression-method table grew to 5 slots; compression byte returned to `u32`. | Same[^1] |
| 9 | `FrozenIndex` | UE 4.25 | Added 1-byte frozen-index writer flag (parser treats frozen identically). | Same[^1] |
| 10 | `PathHashIndex` | UE 4.26 | Replaced flat index with FNV-1a-64 path-hash index + encoded directory index. | Same[^1] |
| 11 | `Fnv64BugFix` | UE 4.27 | Fixed Unicode-aware lowercasing bug in path-hash hashing (ASCII paths byte-equivalent to v10). | Same[^1] |

**Wire-version 8 ambiguity.** V8A and V8B both serialize as `version = 8`. They
are disambiguated at footer-parse time by the slot count in the compression-
method FName table (4 vs 5). Paksmith's `PakVersion::try_from(8)` returns
`V8B` by default; the footer parser post-corrects to `V8A` after counting
slots. Per-entry decode dispatches on the resolved variant.

## Wire layout

### Footer (tail-anchored)

The footer's size depends on the version, and so does the offset to seek to
from the file end. The parser determines version by reading the magic at a
candidate offset, falling through size candidates until one matches.

| Variant | Total size | When |
|---------|------------|------|
| Legacy (`< V7`) | 44 bytes | Wire version 1–6. |
| V7+ | 61 bytes | Wire version 7. |
| V8A | 189 bytes | V7+ base + 4 × 32-byte compression-slot table. |
| V8B / V10 / V11 | 221 bytes | V7+ base + 5 × 32-byte compression-slot table. |
| V9 | 222 bytes | V8B+ base + 1-byte frozen-index flag. |

#### Legacy footer (44 bytes, wire version 1–6)

| offset (from footer start) | size | endian | name | type | semantics |
|---------------------------|------|--------|------|------|-----------|
| 0 | 4 | LE | `magic` | `u32` | Must equal `0x5A6F12E1`. |
| 4 | 4 | LE | `version` | `u32` | Wire version (1–6). |
| 8 | 8 | LE | `index_offset` | `u64` | Byte offset where index begins. |
| 16 | 8 | LE | `index_size` | `u64` | Byte length of the index region. |
| 24 | 20 | — | `index_hash` | `Sha1Digest` | SHA1 of the index bytes (zero-filled = no integrity claim). |

#### V7+ footer (61 bytes, wire version 7)

| offset (from footer start) | size | endian | name | type | semantics |
|---------------------------|------|--------|------|------|-----------|
| 0 | 16 | — | `encryption_key_guid` | `[u8; 16]` | All-zero if no encryption key was assigned. |
| 16 | 1 | — | `encrypted` | `u8` | `1` = index is AES-encrypted; `0` = clear. |
| 17 | 4 | LE | `magic` | `u32` | Must equal `0x5A6F12E1`. |
| 21 | 4 | LE | `version` | `u32` | Wire version (7). |
| 25 | 8 | LE | `index_offset` | `u64` | Byte offset where index begins. |
| 33 | 8 | LE | `index_size` | `u64` | Byte length of the index region. |
| 41 | 20 | — | `index_hash` | `Sha1Digest` | SHA1 of the (possibly-encrypted) index bytes. |

#### V8+ footer additions

After the V7+ 61-byte base:

| offset (from V7+ base end) | size | endian | name | type | semantics |
|---------------------------|------|--------|------|------|-----------|
| 0 | `N × 32` | — | `compression_methods` | `FName[N]` | Fixed 32-byte slots; null- or whitespace-terminated UTF-8. `N = 4` for V8A, `N = 5` for V8B+. |

The compression-method table is the per-archive registry of compression
backend names. Per-entry compression bytes are 1-based indices into this
table: byte `0` means "no compression"; byte `N` selects slot `N - 1`.
Unrecognized slot strings decode to `None` (the entry is still readable if
it has no compression byte set).

#### V9 footer addition

After the V8B+ table:

| offset | size | endian | name | type | semantics |
|--------|------|--------|------|------|-----------|
| 0 | 1 | — | `frozen_index` | `u8` | Writer flag indicating the index was frozen at archive-creation time. Parser treats frozen identically to non-frozen. |

#### V10+ footer

V10 and V11 use the V8B+ footer shape verbatim. They differ from V8B only in
the index region (path-hash layout) and the per-entry encoding (encoded
form), not in the footer.

### Index regions

Two layouts, gated by version:

- **Flat index** (v3–v9). One contiguous block:
  - `FString mount_point`
  - `i32 entry_count`
  - `entry_count` × `(FString filename + PakEntryHeader)` records

- **Path-hash + encoded directory index** (v10+). Three sub-regions:
  - `FString mount_point`
  - `u32 entry_count` (used to size the EntryData region)
  - `FString path_hash_seed_or_empty` (paksmith does not require this)
  - Path-hash index (PHI): `FNV1a64(lowercased UTF-16 path) → encoded_offset` table
  - Full directory index (FDI): nested `FString directory → (FString filename → encoded_offset)`
  - EntryData region: concatenation of `EncodedPakEntry` records (variable-length, no per-entry length prefix — the encoding's bit-pattern is self-describing)

The FDI is the source of truth for paksmith's `(path → entry)` lookups. The
PHI is consulted at `PakReader::open` time as a cross-check: any mismatch
between PHI mappings and FDI walk surfaces as
`IndexParseFault::PhiFdiInconsistency` (issue #131).

See `docs/formats/primitive/fstring.md` for FString and `fname.md` for FName
wire shapes; the pak-side FString reader is strict (`len == 0` rejected) per
the FDI record-size invariant.

### Entry header (flat-index, v3–v9)

| offset | size | endian | name | type | semantics |
|--------|------|--------|------|------|-----------|
| 0 | 8 | LE | `offset` | `u64` | Byte offset of the entry payload in the file. |
| 8 | 8 | LE | `size` | `u64` | Compressed size of the payload. |
| 16 | 8 | LE | `uncompressed_size` | `u64` | Decompressed size of the payload. |
| 24 | 4 or 1 | LE | `compression` | `u32` (V8B+: u32; V8A: u8) | Compression-method index (0 = no compression, 1+ = slot in footer's compression-method table). For v3–v7 archives that predate the FName table, this is a fixed enum identifier. |
| 28 (V8B+) / 25 (V8A) | 20 | — | `sha1` | `Sha1Digest` | Payload SHA1 (zero = no integrity claim). |
| `+ 20` | variable | — | `compression_blocks` | `CompressionBlock[]` | Present iff `compression != 0`. See below. |
| `+ blocks` | 1 | — | `encrypted` | `u8` | Per-entry AES encryption flag. |
| `+ 1` | 4 | LE | `compression_block_size` | `u32` | Block size (often `64 KiB`). |

Per-block `CompressionBlock` (when present): two `u64` offsets `(start, end)`.
For v5+ archives the offsets are entry-relative; for v3–v4 they are
file-relative.

### Entry header (encoded form, v10+)

V10+ uses a tightly-packed bitfield representation per entry, designed to
fit a typical entry into 33–37 bytes in the FDI's EntryData region. The
encoding's high u32 word carries:

- Compression-block count (5 bits)
- Compression-block size (6 bits, encoded as `block_size / 64KiB`)
- Compression method index (6 bits)
- Encryption flag (1 bit)
- Sizes-fit-in-u32 hints (2 bits)
- Offset-fits-in-u32 hint (1 bit)

Followed by:
- `offset`: u32 or u64
- `uncompressed_size`: u32 or u64
- `size` (if compressed): u32 or u64
- Compression blocks: full `(start, end)` u64 pairs, or computed by formula
  when block count > 1 and all blocks are aligned

V10+ encoded entries **omit the per-entry SHA1**. Paksmith's
`PakReader::verify_entry` returns
`AssetParseFault::IntegrityStripped { target }` if asked to verify a v10+
entry's SHA1 directly.

### Worked example: v11 footer

```bash
# 221 = FOOTER_SIZE_V8B_PLUS (the v10/v11 footer size)
FILESIZE=$(stat -f%z tests/fixtures/real_v11_minimal.pak 2>/dev/null \
           || stat -c%s tests/fixtures/real_v11_minimal.pak)
xxd -s $((FILESIZE - 221)) -l 32 tests/fixtures/real_v11_minimal.pak
```

The first 16 bytes are the all-zero encryption-key-GUID (no key assigned to
this fixture). Byte 16 is the `encrypted` flag (`00`). Bytes 17–20 are the
magic `e1 12 6f 5a` (LE of `0x5A6F12E1`). Bytes 21–24 are the wire version
`0b 00 00 00` (= 11). Bytes 25–32 are the start of `index_offset` (u64 LE).

*(Exact bytes vary by fixture; replace with the captured output from
Task 2 Step 3 once anchored.)*

## Variants

### V8A vs V8B

Both write `version = 8` on the wire. Disambiguated by:

| | V8A | V8B |
|--|-----|-----|
| Footer total size | 189 bytes | 221 bytes |
| Compression-method table slots | 4 | 5 |
| Per-entry compression byte width | `u8` (1 byte) | `u32` (4 bytes) |
| UE versions | 4.22 (brief) | 4.23 – 4.24 |

`PakVersion::try_from(8)` returns `V8B` by default; the footer parser post-
corrects to `V8A` after counting slots. Consumers reading the variant from
the resolved `PakFooter` get authoritative classification.

### Flat vs path-hash index

`PakVersion::has_path_hash_index()` returns `true` only for V10 and V11. The
flat index is a contiguous `(filename → header)` list; the path-hash index
adds the PHI hash table and splits headers into the encoded-entry form. See
the Wire layout section.

### Legacy footer

V1–V6 archives use the 44-byte footer (no encryption key GUID, no encrypted
flag, no compression-method table). The parser dispatches on candidate
footer sizes in descending order to handle this.

## Caps & limits

paksmith enforces structural caps to prevent attacker-controlled allocation
amplification. Every cap exposes a `#[cfg(feature = "__test_utils")]`
accessor so boundary tests can read the live value rather than re-declaring
the literal.

- **`MAX_UNCOMPRESSED_ENTRY_BYTES = 8 GiB`**
  (`crates/paksmith-core/src/container/pak/mod.rs:86`).
  Largest single uncompressed entry paksmith will read. Surfaces as
  `IndexParseFault::BoundsExceeded { field: WireField::UncompressedSize, value, limit, unit: BoundsUnit::Bytes, path }`.
- **`max_flat_index_entries()`**
  (`crates/paksmith-core/src/container/pak/index/flat.rs:55`).
  Hard cap on `entry_count` for the flat index. Computed from
  `MAX_INDEX_BYTES / ENTRY_MIN_RECORD_BYTES` (54). Surfaces as
  `IndexParseFault::BoundsExceeded { field: WireField::FlatEntryCount, … }`.
- **`max_index_bytes()`**
  (`crates/paksmith-core/src/container/pak/index/path_hash.rs:86`).
  Cap on `index_size` from the footer. Surfaces as
  `IndexParseFault::BoundsExceeded { field: WireField::IndexSize, … }`.
- **`max_fdi_bytes()`**
  (`crates/paksmith-core/src/container/pak/index/path_hash.rs:79`).
  Cap on the FDI subregion size in v10+ archives.
- **`ENTRY_MIN_RECORD_BYTES = 54`**
  (`crates/paksmith-core/src/container/pak/index/mod.rs:51`).
  Used to bound `entry_count` against `index_size`. Computed as
  `5 (min FString) + 8 (offset) + 8 (size) + 8 (usize) + 4 (compr) + 20 (sha1) + 1 (encrypted)`.

See `docs/security/allocation-caps.md` for the broader allocation-cap
policy.

## Verification

- **Fixtures.** `tests/fixtures/real_v3_*.pak`, `real_v6_*.pak`, `real_v7_*.pak`,
  `real_v8a_*.pak`, `real_v8b_*.pak`, `real_v10_*.pak`, `real_v11_*.pak` —
  all generated by `paksmith-fixture-gen` and cross-validated against
  `trumank/repak`. The `minimal_*` variants exercise the smallest valid
  pak; `mixed_paths_*` exercises FDI-path-shape edge cases; `multi_*`
  exercises multi-entry indices; `compressed_*` exercises the
  compression-block framing.
- **Cross-validation oracle.** Every fixture round-trips through repak[^1]
  at fixture-gen time. CUE4Parse[^2] is the secondary oracle for fields
  repak handles loosely (e.g. the FDI / PHI consistency check).
- **Known divergences:**
  - **V10 / V11 hashing on non-ASCII paths.** Paksmith uses
    `to_ascii_lowercase` rather than Unicode-aware lowercasing, matching
    UE's V10 bug exactly and V11's Unicode-aware lowercasing on ASCII
    paths only. Non-ASCII paths produce a hash that disagrees with UE,
    triggering `IndexParseFault::PhiFdiInconsistency` at open time. Real
    cooked archives use ASCII-only paths, so the practical impact is nil
    — but a non-ASCII fixture would fail to open. See
    `crates/paksmith-core/src/container/pak/index/mod.rs` `fn fnv64_path`.
  - **V8A default decoding.** `PakVersion::try_from(8)` returns `V8B`.
    The footer parser corrects to `V8A` based on slot count; callers
    invoking `try_from(8)` directly without the footer parser get the
    wrong variant. repak and CUE4Parse handle this similarly.

## Paksmith implementation

**Parser modules:**
- `crates/paksmith-core/src/container/pak/version.rs` — `PakVersion`,
  footer-size constants, `PAK_MAGIC`.
- `crates/paksmith-core/src/container/pak/footer.rs` — `PakFooter`, the
  footer parser, V8A/V8B disambiguation logic.
- `crates/paksmith-core/src/container/pak/mod.rs` — `PakReader`,
  `MAX_UNCOMPRESSED_ENTRY_BYTES`, the `ContainerReader` trait impl.
- `crates/paksmith-core/src/container/pak/index/mod.rs` — `PakIndex`
  dispatcher, FNV-1a constants, `ENTRY_MIN_RECORD_BYTES`.
- `crates/paksmith-core/src/container/pak/index/flat.rs` — flat-index
  parser, `max_flat_index_entries`.
- `crates/paksmith-core/src/container/pak/index/path_hash.rs` — path-hash +
  encoded directory index parser, `max_index_bytes`, `max_fdi_bytes`.
- `crates/paksmith-core/src/container/pak/index/entry_header.rs` —
  `PakEntryHeader`, `EntryCommon`, `CompressionFieldWidth`.
- `crates/paksmith-core/src/container/pak/index/compression.rs` —
  `CompressionMethod`, `CompressionBlock`.

**Status:** `complete`.

**Public surface:**
- `pub struct PakReader` — `open()`, `entries()`, `read_entry(path)`,
  `read_entry_to(path, writer)`, `verify_index()`, `verify_entry(path)`,
  `verify()`, `archive_claims_integrity()`.
- `pub struct PakFooter` — `version()`, `index_offset()`, `index_size()`,
  `index_hash()`, `is_encrypted()`, `encryption_key_guid()`, `frozen_index()`.
- `pub enum PakVersion` — `Initial`, `NoTimestamps`, …, `Fnv64BugFix`
  (`#[non_exhaustive]`). `wire_version()` returns the on-disk u32.
- `pub enum PakEntryHeader` — `Flat { common, … }`, `EncodedInData { common, … }`.
- `pub enum CompressionMethod` — `None`, `Zlib`, `Oodle`, etc.
- `pub const PAK_MAGIC: u32 = 0x5A6F_12E1`.

**Error variants** (selected — see `crates/paksmith-core/src/error.rs` for
the full enum):
- `PaksmithError::UnsupportedVersion { version }` — version outside 1–11.
- `PaksmithError::InvalidFooter { fault: InvalidFooterFault::* }` —
  `OtherUnpromoted { reason }` (catch-all currently used for magic mismatch
  / version-unsupported until promoted to typed variants),
  `IndexRegionOffsetOverflow { offset, size }`,
  `IndexRegionPastFileSize { offset, size, file_size }`.
- `PaksmithError::InvalidIndex { fault: IndexParseFault::* }` —
  `BoundsExceeded { field: WireField, value, limit, unit, path }` (every
  cap-exceeded case surfaces this with a specific `WireField` discriminant
  — `UncompressedSize` / `FlatEntryCount` / `IndexSize` / `FdiSize` / …),
  `FStringMalformed`, `PhiFdiInconsistency`, `AllocationFailed`, …
- `PaksmithError::HashMismatch { target, expected, actual }` — index or
  entry SHA1 verification failure.
- `PaksmithError::IntegrityStripped { target }` — verification asked for a
  zero-SHA target.
- `PaksmithError::EntryNotFound { path }`.

**Cap constants:** see Caps & limits.

**Test files:** in-source `mod tests` blocks in each module above, plus
integration tests under `crates/paksmith-core/tests/` (notably
`pak_integration.rs`, `footer_proptest.rs`) and the comprehensive synthetic
fixtures generated by `paksmith-fixture-gen` and cross-validated against
`trumank/repak`.

**Phase plan:** `docs/plans/phase-1-foundation.md`.

## References

[^1]: `trumank/repak/repak/src/pak.rs@<REPAK_SHA>` — paksmith's primary pak
    oracle. Used by `paksmith-fixture-gen` for round-trip validation on every
    generated `.pak` fixture; the wire-version decisions in this doc reflect
    repak's tested coverage.
[^2]: `FabianFG/CUE4Parse/CUE4Parse/FileProvider/Objects/VfsEntry.cs@<CUE4PARSE_SHA>` —
    secondary oracle; cited for the FDI / PHI consistency invariant that
    paksmith now cross-checks at open time (issue #131).
````

- [ ] **Step 4: Commit** (preamble convention — required-headings linter must pass before commit)

```bash
git add docs/formats/container/pak.md
git commit -m "$(cat <<'EOF'
docs(formats): add .pak v1-v11 reference

Documents the full pak format across all eleven wire versions:
footer-size families (44/61/189/221/222), the V8A/V8B
slot-count disambiguation, the flat-vs-path-hash index split,
v10+ encoded entries, the FNV-1a-64 path-hashing (with the
ASCII-only lowercasing carve-out), and every cap paksmith
applies. Cross-validated against trumank/repak (paksmith's
primary pak oracle) with CUE4Parse as secondary for the
FDI/PHI consistency invariant.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Author `docs/formats/container/iostore-utoc.md` (partial)

IoStore is the Phase 8 deliverable; paksmith has no parser yet. This doc
sketches the territory: what `.utoc` is, what it points at, and where the
authoritative reference lives. Every H2 section is present (linter
requirement); Caps & limits and Verification explicitly mark unimplemented
with prose-form TODOs — making this `partial`, not `stub`, per the spec's
status enum.

**Files:**
- Create: `docs/formats/container/iostore-utoc.md`

**Oracle:** `CUE4Parse/UE4/IO/IoStoreReader.cs` (primary; no Rust IoStore
oracle of comparable maturity exists).

- [ ] **Step 1: Write the doc** (using `<CUE4PARSE_SHA>` from preamble Step 7)

Write `docs/formats/container/iostore-utoc.md`:

````markdown
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

**Status: not yet implemented in paksmith.** This doc reserves a slot in
the inventory for the Phase 8 work; full byte-level content will be
authored when the parser lands.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| UE 4.27+ | Initial IoStore format (TOC v1+). Multiple TOC versions exist within UE 5's lifetime. | `CUE4Parse/UE4/IO/IoStoreReader.cs@<CUE4PARSE_SHA>`[^1] |

To be filled in when the parser is built; UE has released several `EIoStoreTocVersion` revisions across the UE5 line.

## Wire layout

To be authored alongside the Phase 8 parser. The high-level shape per
CUE4Parse:

- Fixed `FIoStoreTocHeader` (signature `"-==--==--==--==-"`, ~144 bytes).
- Chunk-ID table (`FIoChunkId[]`).
- Per-chunk offset+length table.
- Compression-block table.
- Compression-method name table (FName-style 32-byte slots, like pak V8+).
- Optional AES-256 ECB encryption-key signature blocks.
- Optional directory-index (UE 5.x).

See the oracle[^1] for the authoritative shape pending paksmith's own parser.

## Variants

To be enumerated by `EIoStoreTocVersion` once parsing lands. Known variants
include `Initial`, `DirectoryIndex`, `PartitionSize`, `PerfectHash`,
`PerfectHashWithOverflow`, `OnDemandMetaData` (most recent).

## Caps & limits

Paksmith does not yet parse `.utoc`; no caps are defined. When the parser
lands it will enforce structural caps mirroring the pak side (entry counts,
allocation sizes, compression-block table sizes). See
`docs/security/allocation-caps.md` for the project-wide cap policy.

## Verification

- **Fixture:** `(none yet — Phase 8 deliverable)`.
- **Cross-validation oracle:** CUE4Parse's `IoStoreReader`[^1]. Phase 8 will
  add a Rust IoStore oracle (`trumank/repak` has no IoStore coverage at
  time of writing).
- **Known divergences:** none yet — no implementation to diverge.

## Paksmith implementation

**Parser module:** *(not yet implemented — planned under `crates/paksmith-core/src/container/iostore/`)*

**Status:** `not impl`.

**Phase plan:** `docs/plans/ROADMAP.md` Phase 8 (IoStore Support).

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/IO/IoStoreReader.cs@<CUE4PARSE_SHA>` — primary oracle for IoStore TOC format. Cite specific subfiles (`FIoStoreTocHeader`, `FIoChunkId`, etc.) when the per-record sections of this doc fill in.
````

- [ ] **Step 2: Commit** (preamble convention — required-headings linter must pass before commit)

```bash
git add docs/formats/container/iostore-utoc.md
git commit -m "$(cat <<'EOF'
docs(formats): add IoStore .utoc partial doc

All eight H2 sections present (linter requirement); Caps & limits
and Verification carry explicit unimplemented markers — partial,
not stub, per the spec. Points at CUE4Parse for the byte-level
reference until paksmith's own parser lands (Phase 8).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Author `docs/formats/container/iostore-ucas.md` (partial)

**Files:**
- Create: `docs/formats/container/iostore-ucas.md`

- [ ] **Step 1: Write the doc** (using `<CUE4PARSE_SHA>` from preamble Step 7)

Write `docs/formats/container/iostore-ucas.md`:

````markdown
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

**Status: not yet implemented in paksmith.** Phase 8 deliverable.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| UE 4.27+ | No on-stream version field — `.ucas` is unstructured bytes. All version-conditional shape lives in `.utoc`. | `CUE4Parse/UE4/IO/IoStoreReader.cs@<CUE4PARSE_SHA>`[^1] |

## Wire layout

| offset | size | endian | name | type | semantics |
|--------|------|--------|------|------|-----------|
| 0 | filesize | — | `chunks` | byte stream | Concatenation of chunk payloads. Each chunk's bounds are published by the matching `.utoc`. |

A chunk payload is one or more compression blocks (per the `.utoc`'s
block table). When the chunk is uncompressed, the payload is the raw
chunk bytes; when compressed, it is the concatenated compressed blocks,
each readable as a single decompress call against the method named in the
`.utoc`'s compression-method table.

When encryption is enabled (per the `.utoc`'s `bIsEncrypted` flag), the
encryption is applied at the compression-block granularity in AES-256 ECB
mode — same as pak's per-entry encryption.

## Variants

None on the wire. All variance lives in `.utoc`.

## Caps & limits

Paksmith does not yet parse `.ucas`; caps will be defined alongside the
Phase 8 parser. The pak-side `MAX_UNCOMPRESSED_ENTRY_BYTES = 8 GiB` cap is
the obvious analog for per-chunk decompression bounds.

## Verification

- **Fixture:** `(none yet — Phase 8 deliverable)`.
- **Cross-validation oracle:** CUE4Parse's `IoStoreReader`[^1].
- **Known divergences:** none yet.

## Paksmith implementation

**Parser module:** *(not yet implemented — planned under `crates/paksmith-core/src/container/iostore/`)*

**Status:** `not impl`.

**Phase plan:** `docs/plans/ROADMAP.md` Phase 8 (IoStore Support).

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/IO/IoStoreReader.cs@<CUE4PARSE_SHA>` — primary oracle. The `.ucas` reading happens inline with `.utoc` chunk lookup in this file's `ReadAsync`.
````

- [ ] **Step 2: Commit** (preamble convention — required-headings linter must pass before commit)

```bash
git add docs/formats/container/iostore-ucas.md
git commit -m "$(cat <<'EOF'
docs(formats): add IoStore .ucas partial doc

The file is unstructured bytes pointed at by .utoc offset+length
pairs; this doc captures that load-bearing fact and notes the
Phase 8 parser will define caps mirroring the pak side. Caps &
limits and Verification carry explicit TODO markers — partial,
not stub.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Author `docs/formats/container/iostore-uptnl.md` (partial)

**Files:**
- Create: `docs/formats/container/iostore-uptnl.md`

- [ ] **Step 1: Write the doc** (using `<CUE4PARSE_SHA>` from preamble Step 7)

Write `docs/formats/container/iostore-uptnl.md`:

````markdown
# IoStore `.uptnl` (Optional Container Data)

> Optional-payload sidecar for an IoStore container — chunk data that
> ships separately from the primary `.ucas`, typically for patches,
> language packs, or DLC.

## Overview

`.uptnl` is the third file in the IoStore trio (`.utoc` + `.ucas` +
optional `.uptnl`). It holds chunk payloads that the shipping container
references but doesn't ship inline — used for content the engine treats as
loadable-on-demand: optional language assets, day-one patches, DLC
overlays.

Structurally `.uptnl` is identical to `.ucas`: an unstructured byte stream
of chunk payloads. The matching `.utoc` is the only file that distinguishes
which chunks live in `.ucas` vs `.uptnl`, via a per-chunk
`EIoContainerFlags::Optional` flag (or a similar bit on the chunk record,
depending on TOC version).

**Status: not yet implemented in paksmith.** Phase 8 deliverable.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| UE 4.27+ | No on-stream version field; the `.utoc` determines whether a `.uptnl` is expected and where each optional chunk lives within it. | `CUE4Parse/UE4/IO/IoStoreReader.cs@<CUE4PARSE_SHA>`[^1] |

## Wire layout

Identical to `.ucas` (see [`iostore-ucas.md`](iostore-ucas.md)) — an
unstructured byte stream of chunk payloads with bounds and per-chunk
compression/encryption parameters all published by the matching `.utoc`.

The semantic difference (optional vs primary) is encoded entirely in the
`.utoc`, not in the `.uptnl` byte stream.

## Variants

None on the wire.

## Caps & limits

Paksmith does not yet parse `.uptnl`; caps will be defined alongside the
Phase 8 parser. Same considerations as `.ucas`.

## Verification

- **Fixture:** `(none yet — Phase 8 deliverable)`.
- **Cross-validation oracle:** CUE4Parse's `IoStoreReader`[^1].
- **Known divergences:** none yet.

## Paksmith implementation

**Parser module:** *(not yet implemented — planned under `crates/paksmith-core/src/container/iostore/`)*

**Status:** `not impl`.

**Phase plan:** `docs/plans/ROADMAP.md` Phase 8 (IoStore Support).

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/IO/IoStoreReader.cs@<CUE4PARSE_SHA>` — primary oracle. The `.uptnl` path is opened alongside `.utoc` + `.ucas` in `IoStoreReader.Initialize`.
````

- [ ] **Step 2: Commit** (preamble convention — required-headings linter must pass before commit)

```bash
git add docs/formats/container/iostore-uptnl.md
git commit -m "$(cat <<'EOF'
docs(formats): add IoStore .uptnl partial doc

Wire shape is identical to .ucas; the semantic distinction
(optional chunks) lives in .utoc. Phase 8 deliverable; Caps &
limits and Verification carry explicit TODO markers — partial,
not stub.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: Update root inventory + final verification + push

**Files:**
- Modify: `docs/formats/README.md`

- [ ] **Step 1: Add four rows to the inventory table**

Locate the inventory table in `docs/formats/README.md` (the line beginning `| Doc | Doc status | Parser status |`). Use the Edit tool to insert four new rows after the separator row.

The rows (substituting `<SHA>` = `git rev-parse --short HEAD`, `<REPAK_SHA>` / `<CUE4PARSE_SHA>` from preamble Step 7). The IoStore rows use `partial` (not `stub`) because every H2 section is filled with prose, including explicit TODO markers in Caps & limits and Verification — matching the spec's `partial` definition:

```markdown
| `container/pak.md` | complete | complete | `container/pak/` | repak @ `<REPAK_SHA>` | `<SHA>` |
| `container/iostore-utoc.md` | partial | not impl | — | CUE4Parse @ `<CUE4PARSE_SHA>` | n/a |
| `container/iostore-ucas.md` | partial | not impl | — | CUE4Parse @ `<CUE4PARSE_SHA>` | n/a |
| `container/iostore-uptnl.md` | partial | not impl | — | CUE4Parse @ `<CUE4PARSE_SHA>` | n/a |
```

- [ ] **Step 2: Run the preamble's Per-family final-verification + push tail**

Follow [PREAMBLE.md](2026-05-19-ue-format-docs-PREAMBLE.md)'s "Per-family final-verification + push tail" (status-enum lint, required-headings lint, file-tree check, typos, `cargo doc -D warnings`).

- [ ] **Step 3: Commit the inventory update**

```bash
git add docs/formats/README.md
git commit -m "$(cat <<'EOF'
docs(formats): register the container-family docs in the inventory

One complete-complete row (pak) and three partial-not-impl rows
(iostore-utoc, iostore-ucas, iostore-uptnl). Last-verified anchor
for pak is this branch's HEAD; IoStore rows use n/a per the spec's
inventory column semantics.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

Expected commit log after this step: 5 commits (1 per doc + 1 for the inventory).

- [ ] **Step 4: Push and open the PR per preamble**

Title: `docs(formats): populate container family (.pak v1-v11 + IoStore trio stubs)`

Body — write to a tempfile first, then `gh pr create --body-file <tempfile>`. Never inline via `--body "$(cat <<EOF ...)"`.

```markdown
## Summary

Lands PR 3 of the UE format documentation framework. Populates
`docs/formats/container/` with four documents:

- **`pak.md`** — full byte-level reference for `.pak` v1–v11, including
  the V8A/V8B disambiguation, flat-vs-path-hash index split, v10+
  encoded entries, FNV-1a-64 path hashing (with ASCII-only lowercasing
  carve-out), every cap, and every known divergence.
- **`iostore-utoc.md`**, **`iostore-ucas.md`**, **`iostore-uptnl.md`** —
  partial docs for the Phase 8 IoStore trio. All eight H2 sections
  present (linter requirement); Caps & limits and Verification carry
  explicit TODO markers — partial, not stub, per the spec's status
  enum. Cite CUE4Parse as the authoritative reference pending
  paksmith's own parser.

Four rows added to the root inventory: one `complete | complete` (pak)
and three `partial | not impl` (IoStore).

## Linked issue

(none — design spec drives this work)

## Test plan

- [x] `paksmith-doc-lint required-headings` passes on all docs.
- [x] `paksmith-doc-lint status-enum` passes on the updated inventory.
- [x] `typos docs/formats/container/` clean.
- [x] `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features` clean (no Rust changes).
- [x] Cross-validated every wire-format claim against trumank/repak (primary) + CUE4Parse (secondary).

## Pre-flight checklist

- [x] PR title is a Conventional Commit.
- [x] Branch name follows `<type>/<kebab-case>`.
- [x] `cargo fmt --all` clean (no Rust changed).
- [x] `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean (no Rust changed).
- [x] Documentation updated (this PR IS documentation).
- [x] No `unsafe` introduced.
- [x] Touched a parser? No — pure docs PR.

## Security considerations

None directly — pure documentation. The pak doc spells out paksmith's
security posture explicitly: every cap constant referenced, the FDI/PHI
consistency invariant explained, AES-256 ECB encryption noted at both the
index and entry levels, embedded-NUL rejection in pak-side FStrings
cross-linked to the primitive doc.

## Notes for reviewers

- The pak `### Worked example` block in the Wire layout section depends on
  byte offsets captured at authoring time (Task 2 Step 3). Re-running the
  `xxd` command against the same fixture should produce identical bytes;
  the hex-anchor CI check (deferred per the framework spec) will eventually
  enforce this automatically.
- The pak doc deliberately collapses v1–v11 into one document (per the
  spec's directory layout — "covers v1–v11 in one doc (variants table)").
  The Versions table carries the full per-version delta; the Wire layout
  section captures the union shape and notes per-version conditionals
  inline.
- The IoStore stubs cite CUE4Parse only because no Rust IoStore oracle of
  comparable maturity exists. When Phase 8 lands, it may introduce a
  fixture-cross-validation crate parallel to repak — the stubs should be
  upgraded to `complete | complete` and the inventory row's oracle bumped
  at that point.
```

(Reviewer panel dispatch + convergence per [PREAMBLE.md](2026-05-19-ue-format-docs-PREAMBLE.md).)

---

## Done criteria

Per [PREAMBLE.md](2026-05-19-ue-format-docs-PREAMBLE.md)'s tail, plus this plan's specifics: four rows in the inventory — one `complete | complete` (pak), three `partial | not impl` (IoStore).
