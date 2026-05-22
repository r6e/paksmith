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
| 1 | `Initial` | UE 4.0 | Initial pak format. | `trumank/repak/repak/src/pak.rs@355b5f62f51959c7cc6dd5a51708646ef483065d`[^1] |
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

**Wire-version 8 ambiguity.** V8A and V8B both serialize as `version = 8`;
disambiguation is footer-parse-time, by the compression-method FName
table's slot count. See Variants → *V8A vs V8B*.

## Wire layout

Every claim in this section's tables and prose is cross-validated against
repak[^1] (paksmith's primary pak oracle) and CUE4Parse[^2] (secondary).
See References for the pinned commits.

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
| V9 | 222 bytes | V7+ base + 1-byte frozen-index flag + 5 × 32-byte compression-slot table. |

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

#### V9 footer addition (between hash and compression-method table)

For V9 only, a one-byte `frozen_index` flag sits immediately after the V7+
base's `index_hash` and before the V8+ compression-method table[^1]:

| offset (from V7+ base end) | size | endian | name | type | semantics |
|---------------------------|------|--------|------|------|-----------|
| 0 | 1 | — | `frozen_index` | `u8` | Writer flag indicating the index was frozen at archive-creation time. Parser reads this byte only when `footer_size == FOOTER_SIZE_V9`; for other versions the field is initialized to `false` without consulting wire bytes. |

#### V8+ footer additions (compression-method table)

After the V7+ 61-byte base — or, for V9, after the `frozen_index` byte —
sits the compression-method table[^1]:

| offset | size | endian | name | type | semantics |
|--------|------|--------|------|------|-----------|
| 0 | `N × 32` | — | `compression_methods` | `FName[N]` | Fixed 32-byte slots; null- or whitespace-terminated UTF-8. `N = 4` for V8A, `N = 5` for V8B / V9 / V10 / V11. |

The compression-method table is the per-archive registry of compression
backend names. Per-entry compression bytes are 1-based indices into this
table: byte `0` means "no compression"; byte `N` selects slot `N - 1`.
Unrecognized slot strings decode to `None` (the entry is still readable if
it has no compression byte set).

#### V10+ footer

V10 and V11 use the V8B footer shape verbatim. They differ from V8B only in
the index region (path-hash layout) and the per-entry encoding (encoded
form), not in the footer.

### Index regions

Two layouts, gated by version:

- **Flat index** (v3–v9)[^1]. One contiguous block:
  - `FString mount_point`
  - `u32 entry_count`
  - `entry_count` × `(FString filename + PakEntryHeader)` records

- **Path-hash + encoded directory index** (v10+)[^1]. Sub-regions in order:
  - `FString mount_point`
  - `u32 file_count` (bounds the FDI entries allocation and validates that the FDI yields exactly this many entries)
  - `u64 path_hash_seed` (consumed by PHI/FDI cross-validation — see issue #131)
  - Optional path-hash index (PHI) header + body: `FNV1a64(lowercased UTF-16 path) → encoded_offset` table
  - **Required** full directory index (FDI) header + body: nested `FString directory → (FString filename → encoded_offset)`
  - `u32 encoded_entries_size` + EntryData blob: concatenation of `EncodedPakEntry` records (variable-length, no per-entry length prefix — the encoding's bit-pattern is self-describing)

The FDI is the source of truth for paksmith's `(path → entry)` lookups. The
PHI is consulted at `PakReader::open` time as a cross-check: any mismatch
between PHI mappings and FDI walk surfaces as
`IndexParseFault::PhiFdiInconsistency`.

See `docs/formats/primitive/fstring.md` for FString and
`docs/formats/primitive/fname.md` for FName wire shapes; the pak-side
FString reader is strict (`len == 0` rejected) per the FDI record-size
invariant.

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

V10+ uses a tightly-packed bitfield representation per entry. The
encoding's high u32 word carries the following fields (bit positions
MSB-first):

- Offset-fits-in-u32 hint (1 bit, bit 31)
- Uncompressed-size-fits-in-u32 hint (1 bit, bit 30)
- Compressed-size-fits-in-u32 hint (1 bit, bit 29 — consumed only when `compression_method != 0`)
- Compression method index (6 bits, mask `(bits >> 23) & 0x3f`)
- Encryption flag (1 bit, mask `(bits & (1 << 22)) != 0`)
- Compression-block count (16 bits, mask `(bits >> 6) & 0xffff`)
- Compression-block size (6 bits, mask `bits & 0x3f`, encoded as `block_size >> 11` — i.e. units of 2 KiB; the sentinel value `0x3f` means "doesn't fit, read the actual size as the next u32")

Followed by, in order:
- `offset`: u32 or u64 (per bit 31)
- `uncompressed_size`: u32 or u64 (per bit 30)
- `compressed_size` (only when compressed): u32 or u64 (per bit 29)
- Compression blocks:
  - **Single-block + non-encrypted** (`block_count == 1 && !is_encrypted`):
    no bytes on the wire — `start = in_data_record_size`, `end = start + compressed_size`.
  - **Otherwise** (multi-block, or single-block encrypted): `block_count`
    × per-block `u32` compressed size. The full `(start, end)` pair for
    each block is derived by cursor accumulation; encrypted entries
    advance the cursor with AES-block alignment.

A typical single-block compressed entry with u32 fields fits the index
record in ~16–20 bytes; an uncompressed entry with u32 offset and size
is 12 bytes. The high u32 word plus fields encodes the structure
compactly without per-entry length prefixes.

V10+ encoded entries **omit the per-entry SHA1**. Paksmith's
`PakReader::verify_entry` returns `Ok(VerifyOutcome::SkippedNoHash)` for
v10+ encoded entries — the `Encoded` variant returns `None` from
`sha1()`, which is the unambiguous "no integrity claim" signal (distinct
from a real-but-zero digest on an `Inline` entry, which is the v3-v9
tampering signal). `PaksmithError::IntegrityStripped` fires only for
`Inline` entries with an all-zero SHA1 when the archive's index hash is
non-zero, or for FDI/PHI region-hash verification via `verify_region` —
see `Paksmith implementation` → Error variants for the full target list.

### Worked example: v11 footer

```bash
# Negative seek: -221 is the v11 footer size measured from end-of-file.
xxd -s -221 -l 32 tests/fixtures/real_v11_minimal.pak
```

Expected output:

```
00000112: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000122: 00e1 126f 5a0b 0000 004a 0000 0000 0000  ...oZ....J......
```

The first 16 bytes are the all-zero encryption-key-GUID (no key assigned to
this fixture). Byte 16 is the `encrypted` flag (`00`). Bytes 17–20 are the
magic `e1 12 6f 5a` (LE of `0x5A6F12E1`). Bytes 21–24 are the wire version
`0b 00 00 00` (= 11). Bytes 25–32 are the start of `index_offset` (u64 LE).

## Variants

### V8A vs V8B

Both write `version = 8` on the wire[^1]. Disambiguated by:

| | V8A | V8B |
|--|-----|-----|
| Footer total size | 189 bytes | 221 bytes |
| Compression-method table slots | 4 | 5 |
| Per-entry compression byte width | `u8` (1 byte) | `u32` (4 bytes) |
| UE versions | 4.22 (brief) | 4.23 – 4.24 |

Paksmith's `PakVersion::try_from(8)` returns `V8B` by default; the footer
parser post-corrects to `V8A` after counting slots, and consumers reading
the variant from the resolved `PakFooter` get authoritative classification.
Callers invoking `try_from(8)` without the footer parser get the wrong
variant — see Verification → Known divergences.

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
  Hard cap of 10,000,000 entries for the flat index (`MAX_FLAT_INDEX_ENTRIES`);
  the parser also derives a per-archive ceiling from `index_size /
  ENTRY_MIN_RECORD_BYTES` (54). Surfaces as
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
  `5 (min FString) + 8 (offset) + 8 (size) + 8 (uncompressed_size) + 4 (compr) + 20 (sha1) + 1 (encrypted)`.

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
- **Hex anchor commands.** See *Worked example: v11 footer* under Wire
  layout — `xxd -s -221 -l 32 tests/fixtures/real_v11_minimal.pak`
  reproduces the embedded expected output byte-for-byte. Per-version
  anchors for the v8a/v8b/v10/legacy footer shapes belong in a follow-up.
- **Cross-validation oracle.** Every fixture round-trips through repak[^1]
  at fixture-gen time. CUE4Parse[^2] is the secondary oracle for the wire
  shape of FDI records and compression-block tables. The PHI/FDI
  consistency check itself is paksmith-specific hardening (issue #131) —
  CUE4Parse does not enforce that invariant.
- **Known divergences:**
  - **V10 / V11 hashing on non-ASCII paths.** Paksmith uses
    `to_ascii_lowercase` rather than Unicode-aware lowercasing, matching
    UE's V10 bug exactly and V11's Unicode-aware lowercasing on ASCII
    paths only. Non-ASCII paths produce a hash that disagrees with UE,
    triggering `IndexParseFault::PhiFdiInconsistency` at open time. Real
    cooked archives use ASCII-only paths, so the practical impact is nil
    — but a non-ASCII fixture would fail to open. See
    `crates/paksmith-core/src/container/pak/index/mod.rs` `fn fnv64_path`.
  - **V8A default decoding.** `PakVersion::try_from(8)` returns `V8B`;
    callers bypassing the footer parser get the wrong variant. repak and
    CUE4Parse handle this similarly. Full disambiguation table in
    Variants → *V8A vs V8B*.

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
- `pub enum PakEntryHeader` — `Inline { common, … }`, `Encoded { common }`.
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
- `PaksmithError::IntegrityStripped { target: HashTarget }` — verification
  asked for a target whose hash field is zero on an archive that claims
  integrity (non-zero index hash). Fires for `Inline` entries with zero
  SHA1 (strip detection), and also for the FDI/PHI region hashes when
  `verify_region` finds them zero. Not fired for v10+ `Encoded` entries,
  which naturally omit SHA1 and surface as `Ok(SkippedNoHash)`.
- `PaksmithError::EntryNotFound { path }`.

**Cap constants:** see Caps & limits.

**Test files:** in-source `mod tests` blocks in each module above, plus
integration tests under `crates/paksmith-core/tests/` (notably
`pak_integration.rs`, `footer_proptest.rs`) and the comprehensive synthetic
fixtures generated by `paksmith-fixture-gen` and cross-validated against
`trumank/repak`.

**Phase plan:** `docs/plans/phase-1-foundation.md`.

## References

[^1]: `trumank/repak/repak/src/pak.rs@355b5f62f51959c7cc6dd5a51708646ef483065d` — paksmith's primary pak
    oracle. Used by `paksmith-fixture-gen` for round-trip validation on every
    generated `.pak` fixture; the wire-version decisions in this doc reflect
    repak's tested coverage.
[^2]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Pak/PakFileReader.cs@ecc4878950336126f125af0747190edf474b2a21` —
    secondary oracle; cited for the FDI record-shape and compression-block
    table layout. CUE4Parse silently skips PHI cross-validation at this
    commit (it advances past the 36-byte PHI header via
    `primaryIndex.Position += 36` without invoking any hash check), so the
    PHI/FDI consistency check in paksmith (issue #131) is paksmith-specific
    hardening rather than something this oracle attests.
