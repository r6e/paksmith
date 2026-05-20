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

Paksmith's parser owns the table entry shape; the reference shape is read by
each consuming record (import table, export table, tagged-property
iteration) since the wire form differs slightly per consumer.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| `FileVersionUE4 ≥ 504` (UE 4.21+) | Current "name table entry with hash trailers" shape. | `CUE4Parse/UE4/Objects/UObject/FNameEntrySerialized.cs@380d005380d166a3fc19a8bb6940a61af8261e8a`[^1] |
| `FileVersionUE4 < 504` | No hash trailers — FString only. | Same source[^1] |

Paksmith currently parses the UE 4.21+ layout exclusively, matching the
`LegacyFileVersion ∈ {-9, -8, -7}` window enforced in the package summary
parser. (UE's convention: the legacy-file-version constant becomes more
negative with each engine major release, so the gate accepts UE4.21 through
UE5.4+.)

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
| 0 | 4 | LE | `index` | `i32` | 0-based index into the package's name table. |
| 4 | 4 | LE | `number` | `i32` | Numeric suffix (`0` means no suffix; non-zero is rendered as `_{number-1}`). |

The reference layout is documented here for cross-referencing but is **not**
parsed by `name_table.rs` — each consuming record reads its own references.
Per-consumer details belong in the planned `asset/uasset.md` (import /
export tables) and `property/tagged.md` (property tags); both are stubs at
the time this doc landed.

## Variants

- **Pre-UE 4.21 layout.** Not supported by paksmith; see Versions table.
- **UE5 "Names V2" / hash-table variants.** Some UE5 cooked builds use a
  different in-memory representation (`FNamePool` with sharded buckets);
  this is an in-memory concern, not a wire-format one. The on-disk
  package-name-table shape documented above still applies to UE5 packages.

## Caps & limits

- **`count < 0` rejected.** Surfaces as
  `AssetParseFault::NegativeValue { field: AssetWireField::NameCount, value }`.
- **`count > MAX_NAME_TABLE_ENTRIES` rejected.**
  `MAX_NAME_TABLE_ENTRIES = 1_048_576` (see
  `crates/paksmith-core/src/asset/name_table.rs:34`). Surfaces as
  `AssetParseFault::BoundsExceeded { field: NameCount, value, limit, unit: Items }`.
  Sized to cover any realistic package (real-world packages rarely exceed a
  few thousand names) while preventing attacker-controlled multi-GB
  allocations.
- **Allocation failure handled.** `try_reserve_asset` is used for the names
  `Vec`; failures surface as
  `AssetParseFault::AllocationFailed { context: NameTable, … }`.

See `docs/security/allocation-caps.md` for the broader allocation-cap
policy.

## Verification

- **Fixture:** `(none yet — see issue #339)` — `tests/fixtures/minimal_uasset_v5.uasset`
  carries a name table starting near offset `0x20`, with first entry the
  FString `"None"` (length-prefix `05 00 00 00`, bytes `4E 6F 6E 65 00`)
  followed by the two `u16` hash trailers, but a precise hex-anchor block
  belongs in the primitive-focused fixture work tracked there.
- **Cross-validation oracle:** CUE4Parse's `FNameEntrySerialized` reader[^1]
  and `unreal_asset`'s in-memory `FName` type[^2]. CUE4Parse confirms the
  `FString + u16 + u16` row shape for UE 4.21+; `unreal_asset` exposes the
  reference type (the wire entry read is threaded through the asset reader,
  not a standalone method).
- **Known divergences:** none on the wire shape. Paksmith discards the
  hash trailers; CUE4Parse keeps them in memory for some downstream
  consumers but reads the same bytes.

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
