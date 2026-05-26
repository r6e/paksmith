# UExp (`.uexp`)

> Export-body sidecar for split UE assets — the concatenated property
> streams of every export in a package, keyed by the export table's
> `(serial_offset, serial_size)` pairs.

## Overview

UE 4.16+ default-cooks `.uasset` files **split**: the structural header
(summary + name table + import table + export table + ancillary
offsets) lives in `.uasset` and is truncated at `total_header_size`;
the property bodies of every export are concatenated into a sibling
`.uexp` file.

`.uexp` has no internal structure of its own — it is a flat byte stream.
The export table's `(serial_offset, serial_size)` pairs partition it
into per-export property bodies, which are then decoded by the
tagged-property reader (the dedicated tagged-property doc is planned
under `docs/formats/property/`)
or — eventually — the unversioned-property reader (Phase 2f).

The on-disk file `.uexp` cannot be parsed in isolation: the export
table that names its byte ranges lives in the paired `.uasset`. See
[`companion-resolution.md`](companion-resolution.md) for the
discovery + stitching rules.

**Document status: complete.** Wire format documented in full for
the structureless `.uexp` byte stream (no header, no magic, no
version field), the `.uasset`-export-table → `.uexp`-byte-range
stitching contract, the `uasset.len() == total_header_size`
invariant the stitcher enforces, the per-export
`(serial_offset, serial_size)` partition the tagged-property reader
iterates against, and the four-state companion-detection table
(in §[`companion-resolution.md`](companion-resolution.md)).

**Paksmith parser status: `complete`.** Phase 2e (Tasks 1, 4)
deliverable; ships as part of `paksmith-core/src/asset/package.rs`.
The `.uexp` byte stream is consumed by the stitching step and then
by the per-export payload reader — there is no standalone `.uexp`
parser module.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| UE 4.16+ | Split-asset cooking introduced; `.uexp` carries the export bodies. Default-on from UE 4.16; some games disable it. | `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Package.cs@ecc4878950336126f125af0747190edf474b2a21`[^1] |

The `.uexp` byte stream's *shape* (concatenated property bodies) is
stable across UE versions; what's *inside* each body changes per the
property-tag and export-table wire-format changes documented under
[`../property/`](../property/README.md) and [`uasset.md`](uasset.md).

## Wire layout

| offset | size | endian | name | type | semantics |
|--------|------|--------|------|------|-----------|
| 0 | filesize | — | `export_bodies` | byte stream | Concatenation of per-export tagged-property streams. Boundaries published by the paired `.uasset`'s export table. |

There is no `.uexp`-level header, magic number, or version field. The
file is purely a payload region.

### Stitching with `.uasset`

Paksmith materializes split assets by concatenating `uasset_bytes ++
uexp_bytes` into a single contiguous buffer. After stitching:

- All export `serial_offset` values point into that combined buffer.
- Offsets in `[0, total_header_size)` resolve inside the `.uasset` half;
  offsets in `[total_header_size, total_header_size + uexp.len())`
  resolve inside the `.uexp` half.
- The reader treats the result identically to a monolithic asset.

The load-bearing invariant: `uasset.len() == total_header_size` for any
split asset. UE writes this exactly. Paksmith verifies it at stitch
time and rejects mismatches as
`AssetParseFault::SplitAssetSizeMismatch { uasset_len, total_header_size }`.

### Worked example: first export body

*(none yet — see [#347](https://github.com/r6e/paksmith/issues/347):
the current split fixture `tests/fixtures/real_v8b_split.pak` contains
a synthetic placeholder `.uexp` (16 bytes of `0xaa`), which cannot
illustrate an `FPropertyTag` stream. A real-cooked-game fixture with a
tagged-property export is tracked in that issue.)*

## Variants

None on the wire — `.uexp` is structureless. Variation comes from
*what's inside* each export body, which is per-property and is
governed by the property family of docs.

## Caps & limits

### Format-defined limits (wire-imposed)

- **No `.uexp`-internal wire limits.** The file is a flat byte stream with no header / magic / version field. The `(serial_offset, serial_size)` pairs that partition it are stored in the paired `.uasset`'s export table (see [`uasset.md`](uasset.md) §*Export table*).
- **Per-export `serial_size` width**: `i32` LE (UE4 < 511) or `i64` LE (UE4 ≥ 511); the paksmith parser widens to `i64` in memory.
- **Combined `uasset.len() + uexp.len()`**: must fit in `usize` on the host platform (32-bit-target overflow guard).

### Implementation hardening (recommended for any parser)

- **`MAX_UEXP_SIZE = 1 GiB`**
  (`crates/paksmith-core/src/asset/package.rs:55`). Largest acceptable
  `.uexp` size. Enforced before any allocation runs to prevent a
  malicious pak entry from forcing a multi-GiB combined-buffer
  reservation. Surfaces as
  `AssetParseFault::BoundsExceeded { field: UexpSize, value, limit, unit: Bytes }`.
- **Combined `.uasset + .uexp` size** must fit in `usize` on the host
  platform — protects against 32-bit-target overflow.
- **Per-export payload caps** (`MAX_PAYLOAD_BYTES = 256 MiB`) apply
  to bodies *within* the stitched buffer; they live with the
  `.uasset` doc rather than here.

See `docs/security/allocation-caps.md` for the broader allocation-cap
policy.

## Verification

- **Fixture:** `tests/fixtures/real_v8b_split.pak` contains a paired
  `.uasset` + `.uexp` (no `.ubulk` in this fixture). Paksmith reads them
  through `Package::read_from_pak` directly; there is no public CLI
  extractor today, so callers verify by parsing through the library or
  by an ad-hoc Rust harness using `PakReader::read_entry`. A real-cooked
  `.uexp` fixture for a worked-example hex anchor is tracked in
  [#347](https://github.com/r6e/paksmith/issues/347) — the synthetic
  `.uexp` in `real_v8b_split.pak` is 16 bytes of `0xaa` placeholder.
- **Cross-validation oracle:** `unreal_asset`[^2] (split-asset
  fixture-gen confirms paksmith's stitching produces a buffer
  semantically identical to unreal_asset's monolithic-form output) and
  CUE4Parse[^1].
- **Known divergences:** none on the wire — `.uexp` is structureless,
  and paksmith's stitching produces byte-identical input to the
  per-property reader as both oracles do.

## Paksmith implementation

**Parser module:** `.uexp` reading is integrated into
`crates/paksmith-core/src/asset/package.rs` (`Package::read_from`,
`Package::read_from_pak`). There is no standalone `.uexp` parser —
the byte stream is consumed by the stitching step and then by the
per-export payload reader.

**Status:** `complete`.

**Public surface:**
- `Package::read_from(uasset: &[u8], uexp: Option<&[u8]>, mappings: Option<&Usmap>, asset_path: &str) -> Result<Self>` —
  caller supplies both halves; `uexp` is `None` for monolithic, `Some` for split.
- `Package::read_from_pak(pak_path, virtual_path, mappings: Option<&Usmap>) -> Result<Self>` —
  convenience wrapper that resolves the `.uexp` companion via the pak
  reader (see [`companion-resolution.md`](companion-resolution.md)).

**Error variants:**
- `AssetParseFault::MissingCompanionFile { kind: CompanionFileKind::Uexp }` —
  any export's payload extends past `uasset.len()` and no `.uexp`
  was provided.
- `AssetParseFault::SplitAssetSizeMismatch { uasset_len, total_header_size }` —
  the invariant `uasset.len() == total_header_size` is violated.
- `AssetParseFault::BoundsExceeded { field: AssetWireField::UexpSize, … }` —
  `.uexp` size exceeds `MAX_UEXP_SIZE`.

**Cap constants:**
- `MAX_UEXP_SIZE: usize = 1 GiB` (`asset/package.rs:55`).

**Phase plan:**
- `.uexp` companion stitching: `docs/plans/phase-2e-companion-files.md`
  (Task 1 — Phase 2e PR #316).
- `.uexp` lookup in pak (`read_from_pak`):
  `docs/plans/phase-2e-companion-files.md` (Task 4 — Phase 2e PR #317).

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Package.cs@ecc4878950336126f125af0747190edf474b2a21` — primary oracle for the split-asset stitching convention.
[^2]: `AstroTechies/unrealmodding/unreal_asset/src/asset.rs@f4df5d8e75b1e184832384d1865f0b696b90a614` — paksmith's fixture-gen oracle. Confirms stitched-buffer semantic equivalence on every split-asset fixture.
