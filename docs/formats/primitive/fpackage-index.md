# FPackageIndex (`FPackageIndex`)

> UE's tagged reference into the package's import or export table — a single
> i32 with sign-encoded table selection.

## Overview

Every cross-object reference inside a UE package — `outer`, `class`, `super`,
`template` — serializes as an `FPackageIndex`. The wire form is a single
signed `i32`; the sign of that integer selects which of the package's two
tables (imports or exports) the reference points into, and the absolute value
gives a 1-based index. Zero is the null reference.

This encoding is uniform across every reference field in the wire format,
which is why paksmith wraps the raw i32 in a typed enum
(`PackageIndex::{Null, Import, Export}`) and gates every wire-read site
through one shared decode function.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| All UE4 + UE5 | Stable since UE3. | `CUE4Parse/UE4/Objects/UObject/ObjectResource.cs@380d005380d166a3fc19a8bb6940a61af8261e8a`[^1] |

The `(0 = Null, positive = Export, negative = Import)` convention has been
stable since UE3. The shape has never changed across engine versions.

## Wire layout

| offset | size | endian | name | type | semantics |
|--------|------|--------|------|------|-----------|
| 0 | 4 | LE | `Index` | `i32` | Tagged table reference; see decode table below. |

Total: 4 bytes.

### Decode table

| Wire `i32` value | Decoded reference |
|------------------|--------------------|
| `0` | `Null` |
| `n > 0` | `Export(n - 1)` (1-based wire, 0-based decoded) |
| `n < 0`, `n > i32::MIN` | `Import((-n) - 1)` |
| `i32::MIN` | **Reject** — no positive counterpart (see Caps & limits) |

The 1-based encoding is a historical UE convention: the engine's internal
`INDEX_NONE` is `-1`, so positive `0` is reserved for the null sentinel and
real export indices start at `1`.

## Variants

None on the wire — one shape, one decode procedure.

## Caps & limits

- **`i32::MIN` rejected.** The wire value `-2_147_483_648` has no positive
  counterpart (`-i32::MIN` overflows), so paksmith refuses to decode it as
  an Import index. Surfaces as
  `AssetParseFault::PackageIndexUnderflow { field: AssetWireField::… }`,
  with `field` naming the specific reference site
  (`OuterIndex`/`ClassIndex`/`SuperIndex`/`TemplateIndex`/`OuterIndexImport`).
  UE writers never produce `i32::MIN`; only malicious or corrupted archives
  can trigger this. See `crates/paksmith-core/src/asset/package_index.rs:60`.
- **Index range:** decoded `Export(i)` and `Import(i)` values are bounded
  to `0..=i32::MAX - 1 = 2_147_483_646` by the decode procedure. No further
  range cap is applied at parse time — the consuming code (import-table or
  export-table lookup) validates the index against the actual table length.

## Verification

- **Fixture:** `(none yet)` — `tests/fixtures/minimal_uasset_v5.uasset`
  contains FPackageIndex references in its import/export tables, but the
  current fixture suite does not isolate one for a named hex anchor. A
  primitive-focused fixture covering each of the three states (Null, Import,
  Export) plus the `i32::MIN` rejection would be a worthwhile follow-up.
- **Cross-validation oracle:** CUE4Parse's `FPackageIndex` constructor (reads
  via `Ar.Read<int>()`)[^1] and `unreal_asset`'s `PackageIndex` newtype[^2].
  Both agree on the `(0 = Null, +n = Export(n-1), -n = Import(-n-1))` decode.
- **Known divergences:** CUE4Parse does not explicitly reject `i32::MIN` —
  it lets the `-i32::MIN` overflow wrap, producing an Import index of
  `2_147_483_647`. Paksmith treats this as a malformed archive instead;
  practical impact is nil because UE writers never emit `i32::MIN`.

## Paksmith implementation

**Parser module:** `crates/paksmith-core/src/asset/package_index.rs`

**Status:** `complete`.

**Public surface:**
- `pub enum PackageIndex { Null, Import(u32), Export(u32) }` (with `#[non_exhaustive]`).
- `PackageIndex::try_from_raw(i32) -> Result<PackageIndex, PackageIndexError>`.
- `PackageIndex::to_raw() -> i32` — round-trip encoder.
- `read_package_index<R: Read>(reader, asset_path, field) -> Result<PackageIndex>` — pub(crate) wire-read wrapper that maps `PackageIndexError` to `AssetParseFault::PackageIndexUnderflow`.
- `impl Display` — renders `"Null"`, `"Import(N)"`, or `"Export(N)"`.
- `impl Serialize` — JSON string matching `Display`.

**Error variants:**
- `PackageIndexError::ImportIndexUnderflow` (private to the module) — raised when `try_from_raw` sees `i32::MIN`.
- `AssetParseFault::PackageIndexUnderflow { field: AssetWireField }` — the public-facing wire error.

**Cap constants:** none (only the `i32::MIN` rejection, which is structural
not configurable).

**Test files:** `crates/paksmith-core/src/asset/package_index.rs` `mod tests`.

**Phase plan:** `docs/plans/phase-2a-uasset-header.md` (Task 3).

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Objects/UObject/ObjectResource.cs@380d005380d166a3fc19a8bb6940a61af8261e8a` — reference C# `FPackageIndex` class (defined alongside `FObjectResource` and friends in `ObjectResource.cs`), including the i32-read constructor and the null / export / import sign convention.
[^2]: `AstroTechies/unrealmodding/unreal_asset/unreal_asset_base/src/types/mod.rs@f4df5d8e75b1e184832384d1865f0b696b90a614` — Rust `PackageIndex` newtype around a raw `i32`; paksmith cross-validates the `(0 = Null, negative = Import, positive = Export)` sign convention against this crate. No separate `package_index.rs` file exists — the type is defined inline in `types/mod.rs`.
