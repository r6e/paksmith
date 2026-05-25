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

**Document status: complete.** Wire format documented in full against
CUE4Parse[^1] with a worked example below covering all four decode
states (Null, Export, Import, `i32::MIN` reject).

**Paksmith parser status: complete.** Module
`crates/paksmith-core/src/asset/package_index.rs`.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| All UE4 + UE5 | Stable since UE3. | `CUE4Parse/UE4/Objects/UObject/ObjectResource.cs@380d005380d166a3fc19a8bb6940a61af8261e8a`[^1] |

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

### Worked example

Four wire values exercising all decode states. Each is a single 4-byte
LE i32:

```
Bytes (LE)          Wire i32             Decoded
----------          -----------          --------
00 00 00 00          0                    Null
01 00 00 00         +1                    Export(0)   ← first export
05 00 00 00         +5                    Export(4)
FF FF FF FF         -1                    Import(0)   ← INDEX_NONE-adjacent
FE FF FF FF         -2                    Import(1)
00 00 00 80         i32::MIN              REJECT — no positive counterpart
```

The `i32::MIN` rejection case is the only path that produces a parse
error. All other 2³² possible 4-byte sequences decode to one of
{Null, Export(0..2_147_483_647), Import(0..2_147_483_646)}.

## Variants

None on the wire — one shape, one decode procedure.

## Caps & limits

### Format-defined limits (wire-imposed)

- **`Export(n)` range:** `0..=i32::MAX − 1 = 2_147_483_646`. Bounded
  by the i32 wire encoding minus the +1 base (positive wire value `n`
  decodes to `Export(n − 1)`).
- **`Import(n)` range:** `0..=i32::MAX − 1 = 2_147_483_646`. Bounded
  by the absolute value of negative wire values minus 1 base; the
  `i32::MIN` edge case has no positive counterpart and is the one
  un-decodable wire value (see below).

### Implementation hardening (recommended for any parser)

- **`i32::MIN` MUST be rejected.** The wire value `-2_147_483_648`
  has no positive counterpart (`-i32::MIN` overflows in two's-complement),
  so it can NOT be decoded as a well-formed `Import(n)`. A robust parser
  MUST reject the file at this value rather than wrap into a spurious
  `Import(2_147_483_647)`. Paksmith surfaces this as
  `AssetParseFault::PackageIndexUnderflow { field: AssetWireField::… }`,
  with `field` naming the specific reference site
  (`ImportOuterIndex`/`ExportClassIndex`/`ExportSuperIndex`/`ExportTemplateIndex`/`ExportOuterIndex`).
  UE writers never produce `i32::MIN`; only malicious or corrupted
  archives can trigger this. See
  `crates/paksmith-core/src/asset/package_index.rs:60`.
- **Decoded index bounds-check against actual table length.** The
  primitive's decode procedure validates the wire value; it does NOT
  validate the resulting `Export(i)` / `Import(i)` against the
  package's actual import/export table size. The consuming code
  (import-table lookup, export-table lookup) MUST bounds-check
  `i < table.len()` before using the index — failure is a separate
  OOB hazard handled per-table.
- **Known cross-implementation divergence.** CUE4Parse does NOT
  explicitly reject `i32::MIN` — it lets the `-i32::MIN` overflow
  wrap, producing an Import index of `2_147_483_647`. Paksmith
  treats this as malformed; both behaviors are observable in the
  wild. A maximally-strict parser MUST reject; a CUE4Parse-compatible
  parser MAY wrap. Cross-validation tools should normalize this case
  to avoid divergent outputs.

## Verification

- **Fixture:** `tests/fixtures/minimal_uasset_v5.uasset` and the other
  `minimal_uasset_v5_*.uasset` fixtures contain `FPackageIndex`
  references in their import/export tables. Direct extraction of a
  single 4-byte FPackageIndex requires walking the package summary
  to find the import/export table offsets — the Worked example above
  provides byte-exact synthetic examples covering all four decode
  states without needing fixture extraction. A primitive-focused
  fixture file is intentionally NOT needed: the wire format is small
  enough that the synthetic example IS the spec.
- **Hex anchor commands:**
  ```
  # Synthesize an Export(0) wire value:
  printf '\x01\x00\x00\x00' | xxd
  # Synthesize an Import(0) wire value (INDEX_NONE-adjacent):
  printf '\xFF\xFF\xFF\xFF' | xxd
  # Synthesize the i32::MIN rejection case:
  printf '\x00\x00\x00\x80' | xxd
  ```
  Any conformant parser exercised on these four-byte sequences MUST
  produce the decoded values shown in the Worked example.
- **Cross-validation oracle:** CUE4Parse's `FPackageIndex` constructor (reads
  via `Ar.Read<int>()`)[^1] and `unreal_asset`'s `PackageIndex` newtype[^2].
  Both agree on the `(0 = Null, +n = Export(n-1), -n = Import(-n-1))` decode.
- **Known divergences:** CUE4Parse does not explicitly reject `i32::MIN`
  (see Implementation hardening above). Paksmith treats it as malformed.

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
- `PackageIndexError::ImportIndexUnderflow` (not re-exported at the crate's public API) — raised when `try_from_raw` sees `i32::MIN`.
- `AssetParseFault::PackageIndexUnderflow { field: AssetWireField }` — the public-facing wire error.

**Cap constants:** none (only the `i32::MIN` rejection, which is structural
not configurable).

**Test files:** `crates/paksmith-core/src/asset/package_index.rs` `mod tests`.

**Phase plan:** `docs/plans/phase-2a-uasset-header.md` (Task 3).

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Objects/UObject/ObjectResource.cs@380d005380d166a3fc19a8bb6940a61af8261e8a` — reference C# `FPackageIndex` class (defined alongside `FObjectResource` and friends in `ObjectResource.cs`), including the i32-read constructor and the null / export / import sign convention.
[^2]: `AstroTechies/unrealmodding/unreal_asset/unreal_asset_base/src/types/mod.rs@f4df5d8e75b1e184832384d1865f0b696b90a614` — Rust `PackageIndex` newtype around a raw `i32`; paksmith cross-validates the `(0 = Null, negative = Import, positive = Export)` sign convention against this crate. No separate `package_index.rs` file exists — the type is defined inline in `types/mod.rs`.
