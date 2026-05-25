# FName (`FName`)

> UE's interned string reference: an index into the per-package name table
> plus a numeric suffix.

## Overview

UE's `FName` is the engine's interned-string type. On disk, an `FName`
reference is **not** a string — it's a pair of integers (table index +
numeric suffix) that resolves against a per-package name table. The string
data lives once in the table; every site that uses it stores only the
reference.

This doc covers two distinct wire shapes:

1. The **name table entry** — one row in the per-package name pool, which IS
   on-disk string data plus two hash trailers.
2. The **FName reference** — the (table-index, number) pair stored at every
   use site (import names, export names, property names, struct paths).

**Document status: complete.** Wire format documented in full against
CUE4Parse[^1] with a worked example below showing a 2-entry name
table plus a use-site reference.

**Paksmith parser status: complete.** Module
`crates/paksmith-core/src/asset/name_table.rs`.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| `FileVersionUE4 ≥ 504` (UE 4.21+) | Current "name table entry with hash trailers" shape. | `CUE4Parse/UE4/Objects/UObject/FNameEntrySerialized.cs@380d005380d166a3fc19a8bb6940a61af8261e8a`[^1] |
| `FileVersionUE4 < 504` | No hash trailers — FString only. | Same source[^1] |

Paksmith currently parses the UE 4.21+ layout exclusively, matching the
`LegacyFileVersion ∈ {-9, -8, -7}` window enforced in the package summary
parser — see [`fcustom-version.md`](fcustom-version.md) for the
more-negative-is-newer convention.

## Wire layout

### Name table entry (one row of the pool)

| offset (within row) | size | endian | name | type | semantics |
|---------------------|------|--------|------|------|-----------|
| 0 | variable | — | `name` | `FString`[^3] | Base name string (no `_NN` suffix). |
| `sizeof(name)` | 2 | LE | `hash_no_case` | `u16` | CityHash16 of the case-folded name. Read and discarded by paksmith. |
| `sizeof(name) + 2` | 2 | LE | `hash_case` | `u16` | CityHash16 of the original-case name. Read and discarded by paksmith. |

Row size: `sizeof(name) + 4` bytes. The two hash trailers are validated to
exist (the parser fails if they're truncated) but their values are not
checked.

### Name table container

| offset | size | endian | name | type | semantics |
|--------|------|--------|------|------|-----------|
| 0 | 4 | LE | `count` | `i32` | Number of name entries that follow. |
| 4 | `Σ sizeof(rows)` | — | `rows` | name-entry[count] | Variable-width rows per the layout above. |

### FName reference (at use sites — for context)

Each FName reference in import/export records, property tags, etc. is a pair
of integers:

| offset (within reference) | size | endian | name | type | semantics |
|---------------------------|------|--------|------|------|-----------|
| 0 | 4 | LE | `index` | `u32` | 0-based index into the package's name table. |
| 4 | 4 | LE | `number` | `u32` | Numeric suffix (`0` means no suffix; non-zero is rendered as `_{number-1}`). |

The reference layout is documented here for cross-referencing but is **not**
parsed by `name_table.rs` — each consuming record reads its own references.
Per-consumer details belong in [`../asset/uasset.md`](../asset/uasset.md)
(import / export tables) and [`../property/tagged.md`](../property/tagged.md)
(property tags).

### Worked example

A synthetic 2-entry name-table container with names `"None"` and `"Foo"`,
both using zeroed hash trailers (cooker normally fills these with
`CityHash16` values; the parser reads-and-discards them so zero is wire-valid):

```
Offset  Bytes (LE)                                          Field
------  --------------------------------------------------  -------------------------------
+0      02 00 00 00                                         count = 2 (i32)

# Entry 0: "None" (5-byte FString + 4-byte hash trailers = 13 bytes total)
+4      05 00 00 00                                         FString length = 5 (ASCII; chars + null)
+8      4E 6F 6E 65 00                                      bytes: "N o n e \0"
+13     00 00                                               hash_no_case (u16, read+discarded)
+15     00 00                                               hash_case (u16, read+discarded)

# Entry 1: "Foo" (4-byte FString + 4-byte hash trailers = 12 bytes total)
+17     04 00 00 00                                         FString length = 4
+21     46 6F 6F 00                                         bytes: "F o o \0"
+25     00 00                                               hash_no_case
+27     00 00                                               hash_case
+29                                                          (end of name table — 29 bytes)
```

A use-site reference to `Foo_3` (rendered with suffix `_{number-1}` where
`number = 4`):

```
Offset  Bytes (LE)                                          Field
------  --------------------------------------------------  -------------------------------
+0      01 00 00 00                                         index = 1 (u32; → name-table[1] = "Foo")
+4      04 00 00 00                                         number = 4 (u32; → suffix "_3")
+8                                                           (end of reference — 8 bytes)
```

Decoded: `Foo_3`. The `_{number-1}` convention is UE's: `number = 0`
means "no suffix" (renders as bare `"Foo"`), `number = 1` means `_0`,
`number = 2` means `_1`, etc.

## Variants

- **Pre-UE 4.21 layout.** Not supported by paksmith; see Versions table.
- **UE5 "Names V2" / hash-table variants.** Some UE5 cooked builds use a
  different in-memory representation (`FNamePool` with sharded buckets);
  this is an in-memory concern, not a wire-format one. The on-disk
  package-name-table shape documented above still applies to UE5 packages.

## Caps & limits

### Format-defined limits (wire-imposed)

- **`count` field range:** `i32`, signed. Wire-imposed maximum of
  `i32::MAX = 2_147_483_647` entries. The signedness is the relevant
  wire fact — negative counts are not a valid count but the wire format
  permits them as bytes; that's an implementation-hardening concern below.
- **Per-entry size:** `sizeof(FString) + 4` bytes. The `FString` length
  is `i32` per [`fstring.md`](fstring.md) (with negative length signaling
  UTF-16 encoding); the two hash trailers are fixed `u16`.
- **Reference fields:** `index` and `number` are both `u32`. Wire-imposed
  index range: `0..=u32::MAX`. Real index range is bounded by the actual
  name-table size at lookup time (implementation-hardening, not
  wire-imposed).

### Implementation hardening (recommended for any parser)

- **`count < 0` MUST be rejected.** A negative `i32` count cast to
  `usize` for allocation produces near-`usize::MAX` values; immediate
  OOM. Paksmith surfaces this as
  `AssetParseFault::NegativeValue { field: AssetWireField::NameCount, value }`.
- **Upper bound on `count` SHOULD be enforced.** A conservative cap
  prevents attacker-controlled multi-GB allocations. Paksmith uses
  `MAX_NAME_TABLE_ENTRIES = 1_048_576` (see
  `crates/paksmith-core/src/asset/name_table.rs:34`). Real-world packages
  rarely exceed a few thousand names. Surfaces as
  `AssetParseFault::BoundsExceeded { field: NameCount, value, limit, unit: Items }`.
- **Allocation failure handling.** Use a fallible reservation
  (`try_reserve` in Rust, equivalent in other languages) rather than
  infallible allocation. Paksmith routes failures through
  `AssetParseFault::AllocationFailed { context: NameTable, … }`.
- **Reference `index` bounds-check.** At lookup time, `index >=
  name_table.len()` MUST be rejected — OOB indexes are an OOB-read /
  panic vector. The primitive itself does NOT enforce this (the table
  isn't visible to the reference's reader); the consuming record (import
  table, export table, property tag) MUST bounds-check before use.

See `docs/security/allocation-caps.md` for the broader allocation-cap
policy.

## Verification

- **Fixture:** the Worked example above is synthetic and self-contained
  (byte-exact for any reader to validate against). The
  `tests/fixtures/minimal_uasset_v5.uasset` and sibling fixtures contain
  real name tables embedded inside `.uasset` files; extracting a single
  name-table entry requires walking the package summary to find the
  name-table offset, then reading from there.
- **Hex anchor commands:**
  ```
  # Synthesize the 2-entry name-table example from the Worked example
  # above. The bytes correspond to the offsets +0..+28 (29 bytes total).
  # The container byte sequence (count=2, "None" entry, "Foo" entry):
  printf '\x02\x00\x00\x00\x05\x00\x00\x00None\x00\x00\x00\x00\x00\x04\x00\x00\x00Foo\x00\x00\x00\x00\x00' | xxd
  ```
  Any conformant parser fed these 29 bytes MUST produce a 2-entry
  name table with `name_table[0] = "None"` and `name_table[1] = "Foo"`.
- **Cross-validation oracle:** CUE4Parse's `FNameEntrySerialized` reader[^1]
  and `unreal_asset`'s in-memory `FName` type[^2]. CUE4Parse confirms the
  `FString + u16 + u16` row shape for UE 4.21+; `unreal_asset` exposes the
  reference type (the wire entry read is threaded through the asset reader,
  not a standalone method).
- **Known divergences:** none. Both readers consume the same `FString + u16 + u16` bytes.

## Paksmith implementation

**Parser module:** `crates/paksmith-core/src/asset/name_table.rs`

**Status:** `complete`.

**Public surface:**
- `pub struct FName(Arc<str>)` — interned name; `Clone` is one atomic bump.
- `pub struct NameTable` — the per-package pool.
- `NameTable::read_from<R: Read + Seek>(reader, offset, count, asset_path) -> Result<NameTable>` — seeks to the table offset, reads `count` rows.
- `NameTable::get(index: u32) -> Option<&FName>` — 0-based lookup.

**Error variants:**
- `AssetParseFault::NegativeValue { field: NameCount, value }`.
- `AssetParseFault::BoundsExceeded { field: NameCount, value, limit, unit }`.
- `AssetParseFault::AllocationFailed { context: NameTable, … }`.
- `AssetParseFault::FStringMalformed { kind }` — forwarded from each entry's
  base-name FString.

**Cap constants:**
- `MAX_NAME_TABLE_ENTRIES: u32 = 1_048_576` (`name_table.rs:34`).

**Test files:** `crates/paksmith-core/src/asset/name_table.rs` `mod tests`
plus integration cases in `crates/paksmith-core-tests/`.

**Phase plan:** `docs/plans/phase-2a-uasset-header.md` (Task 6).

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Objects/UObject/FNameEntrySerialized.cs@380d005380d166a3fc19a8bb6940a61af8261e8a` — reference C# `FNameEntrySerialized` reader and the hash-trailer shape for UE 4.21+.
[^2]: `AstroTechies/unrealmodding/unreal_asset/unreal_asset_base/src/types/fname.rs@f4df5d8e75b1e184832384d1865f0b696b90a614` — Rust `FName` reference enum (in-memory type). The wire entry read in unrealmodding is threaded through the asset reader rather than exposed as a standalone `FNameEntry::read`; paksmith's row-shape cross-validation is against CUE4Parse, with the unrealmodding citation here providing the type-shape oracle.
[^3]: See [`fstring.md`](fstring.md) for FString wire details.
