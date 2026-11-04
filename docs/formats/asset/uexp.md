# UExp (`.uexp`)

> Export-body sidecar for split UE assets. It holds the serialized body
> of every export in a package, located by the export table's
> `(serial_offset, serial_size)` pairs.

## Overview

UE 4.16+ default-cooks `.uasset` files **split**: the structural header
(summary + name table + import table + export table + ancillary
offsets) lives in `.uasset` and is truncated at `total_header_size`;
the bodies of every export are concatenated into a sibling
`.uexp` file.

`.uexp` has no header or version field. The export table's
`(serial_offset, serial_size)` pairs locate each export's body in it,
in stitched offsets.
In the cooked UE 4.18, 4.27 and 5.0 samples checked[^3], the file ends
with a 4-byte `PACKAGE_FILE_TAG` right after the last body. Each
body's properties are decoded by the tagged-property reader
([`../property/tagged.md`](../property/tagged.md)) or the
unversioned-property reader
([`../property/unversioned.md`](../property/unversioned.md)).

The on-disk file `.uexp` cannot be parsed in isolation: the export
table that names its byte ranges lives in the paired `.uasset`. See
[`companion-resolution.md`](companion-resolution.md) for the
discovery + stitching rules.

**Document status: complete.** Wire format documented in full for
the `.uexp` byte stream (no header or version field), the
`.uasset`-export-table → `.uexp`-byte-range
stitching contract, the `uasset.len() == total_header_size`
invariant the stitcher enforces, the per-export
`(serial_offset, serial_size)` byte ranges, and the four-state
companion-detection table
(in §[`companion-resolution.md`](companion-resolution.md)).

**Paksmith parser status: `complete`.** Phase 2e (Tasks 3, 4)
deliverable; ships as part of `paksmith-core/src/asset/package.rs`.
The `.uexp` byte stream is consumed by the stitching step and then
by the per-export payload reader — there is no standalone `.uexp`
parser module.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| UE 4.16+ | Split-asset cooking introduced; `.uexp` carries the export bodies. Default-on from UE 4.16; some games disable it. | `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Package.cs@ecc4878950336126f125af0747190edf474b2a21`[^1] |

What's *inside* each export body changes per the property
wire-format changes documented under
[`../property/`](../property/README.md).

## Wire layout

| offset | size | endian | name | type | semantics |
|--------|------|--------|------|------|-----------|
| 0 | variable | — | `export_bodies` | byte stream | The per-export bodies, located by the paired `.uasset`'s export table in stitched offsets (see *Stitching with `.uasset`*). |
| filesize - 4 | 4 | LE | `package_tag` | `u32` | `0x9E2A83C1` (`PACKAGE_FILE_TAG`, bytes `c1 83 2a 9e`), the value of the `.uasset`'s `magic`. |

The table is the layout of every `.uexp` in the samples checked[^3].
A `.uexp`-resident bulk payload (see [`bulk-data.md`](bulk-data.md)) is
located by its own `OffsetInFile`; none of the samples has one.
unreal_asset writes the same four bytes after the last export[^4].

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

None in the samples checked[^3]; see *Wire layout*.

## Caps & limits

### Format-defined limits (wire-imposed)

- **No `.uexp`-internal wire limits.** The file has no header or version field. The `(serial_offset, serial_size)` pairs that locate its export bodies are stored in the paired `.uasset`'s export table (see [`uasset.md`](uasset.md) §*Export table*).
- **Per-export `serial_size` width**: `i32` LE (UE4 < 511) or `i64` LE (UE4 ≥ 511); the paksmith parser widens to `i64` in memory.
- **Combined `uasset.len() + uexp.len()`**: must fit in `usize` on the host platform (32-bit-target overflow guard).

### Implementation hardening (recommended for any parser)

- **`MAX_UEXP_SIZE = 1 GiB`**
  (`crates/paksmith-core/src/asset/package.rs:79`). Largest acceptable
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
- **Cross-validation oracle:** `unreal_asset`[^2] and CUE4Parse[^1].
- **Known divergences:** paksmith rejects a package whose exports reach
  into the `.uexp` when its `.uasset` length differs from
  `total_header_size` (`SplitAssetSizeMismatch`); CUE4Parse bases the
  `.uexp` at the `.uasset`'s length without that check[^1].

## Paksmith implementation

**Parser module:** `.uexp` reading is integrated into
`crates/paksmith-core/src/asset/package.rs` (`Package::read_from`,
`Package::read_from_pak`). There is no standalone `.uexp` parser —
the byte stream is consumed by the stitching step and then by the
per-export payload reader.

**Status:** `complete`.

**Public surface:**
- `Package::read_from(uasset: &[u8], uexp: Option<&[u8]>, mappings: Option<&Arc<Usmap>>, asset_path: &str) -> Result<Self>` —
  caller supplies both halves; `uexp` is `None` for monolithic, `Some` for split.
- `Package::read_from_pak(pak_path, virtual_path, mappings: Option<&Arc<Usmap>>) -> Result<Self>` —
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
- `MAX_UEXP_SIZE: usize = 1 GiB` (`asset/package.rs:79`).

**Phase plan:**
- `.uexp` companion stitching: `docs/plans/phase-2e-companion-files.md`
  (Task 3 — Phase 2e PR #316).
- `.uexp` lookup in pak (`read_from_pak`):
  `docs/plans/phase-2e-companion-files.md` (Task 4 — Phase 2e PR #317).

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Package.cs@ecc4878950336126f125af0747190edf474b2a21` — primary oracle for the split-asset stitching convention. L168-L176 open the `.uexp` as an archive based at the `.uasset`'s length, and L208-L210 (lazy) and L496-L498 seek each export's `SerialOffset` and deserialize it up to `SerialOffset + SerialSize` (`AbstractUePackage.cs` L81-L87 at the same revision).
[^2]: `AstroTechies/unrealmodding/unreal_asset/src/asset.rs@f4df5d8e75b1e184832384d1865f0b696b90a614` — paksmith's fixture-gen oracle. Fixture-gen parses the split fixture with it as a `.uasset` + `.uexp` pair and as their concatenation, and compares the two parses' export counts.
[^3]: `matyalatte/Matya-Uasset-Samples@a7921caec72aca1d1a9cf28e488d702dceaf6f93` — the 24 cooked split packages under `4.18/`, `4.27/` and `5.0/`, eight per version. Each `.uexp` ends in `c1 83 2a 9e`. In each package the exports' `(serial_offset, serial_size)` ranges run back to back from `total_header_size`, which equals the `.uasset`'s length, to the tag, and the summary's `bulk_data_start_offset` is the tag's stitched offset. `4.27/T_Worm_A.uexp` is 3,340 bytes with the tag at 0xd08 (stitched offset 4157, the 821-byte `.uasset` plus 3336); the tag is at 0xcdc in `4.18/T_Worm_A.uexp` and at 0xc4f in `5.0/T_Worm_A.uexp`.
[^4]: `AstroTechies/unrealmodding/unreal_asset/src/asset.rs@f4df5d8e75b1e184832384d1865f0b696b90a614` — on write, L1400 writes `[0xc1, 0x83, 0x2a, 0x9e]` after the last export and L1402-L1405 set `bulk_data_start_offset` to that position. On read, L987-L990 bound each export's parse at the next export's `serial_offset`, and the last one's at 4 bytes before the end of the combined `.uasset` + `.uexp` data.
