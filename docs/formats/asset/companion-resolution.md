# Companion file resolution

> How paksmith locates the `.uexp` and `.ubulk` siblings of a `.uasset`
> across loose files, pak entries, and IoStore chunks (planned).

## Overview

A UE package on disk is one to three files:

- `.uasset` — header + tables, always present.
- `.uexp` — export bodies, present for split assets (UE 4.16+ default).
- `.ubulk` — bulk-data payloads, present when the asset has bulk records.

The three siblings share a path prefix and differ only in extension.
Resolution comes down to: take the `.uasset` path, swap the extension,
look up the result in the same container the `.uasset` came from.

Paksmith implements three resolution flows:

1. **In-memory** — caller provides bytes for both `.uasset` and (optional) `.uexp`.
   No file I/O, no path resolution; the caller has already decided which
   buffer is which. This is the lowest-level API.
2. **Pak archive** — caller provides a `PakReader` and a virtual path to a
   `.uasset` entry; paksmith derives sibling virtual paths and looks them
   up in the pak index.
3. **Loose filesystem** *(planned)* — caller provides a `.uasset` path on
   disk; paksmith reads the file and probes for sibling files with the
   same prefix and the `.uexp` / `.ubulk` extensions.

The split-vs-monolithic dispatch and the per-flow lookup are unified by
the same four-state table at the core of `Package::read_from`.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| UE 4.16+ | Split-asset cooking introduced; `.uexp` siblings became expected by default. | `CUE4Parse/UE4/Assets/Package.cs@ecc4878950336126f125af0747190edf474b2a21`[^1] |
| All UE4 + UE5 | `.ubulk` siblings predate the split convention; the path-derivation rules have been stable since UE4 0.0. | Same[^1] |

There is no version-conditional change to the resolution rules
themselves — the path-derivation (swap extension) and the four-state
detection logic are version-agnostic. Per-file wire-format changes
live in [`uasset.md`](uasset.md), [`uexp.md`](uexp.md), and
[`ubulk.md`](ubulk.md).

## Wire layout

There is no on-wire structure to resolution — this doc covers a
procedure that operates on filesystem paths and pak virtual paths.

### Path derivation

```rust
fn derive_companion_path(base: &str, new_ext: &str) -> String
```

Implementation (`crates/paksmith-core/src/asset/package.rs:274`): strip
the trailing `.uasset` from `base` and append `new_ext`. If `base` does
not end in `.uasset` (e.g., a `.umap`), `new_ext` is appended directly
to the full string — this is the fallback for edge inputs, not the
normal case. UE writer tool chains always produce siblings from
`.uasset` base paths. Examples:

| Input `.uasset` path | Companion ext | Derived path |
|----------------------|---------------|---------------|
| `Game/Weapons/Sword.uasset` | `.uexp` | `Game/Weapons/Sword.uexp` |
| `Game/Weapons/Sword.uasset` | `.ubulk` | `Game/Weapons/Sword.ubulk` |

UE writers always emit siblings with this exact prefix relationship.
No casing variance, no directory traversal — the derived path is the
companion's path.

### Four-state companion-detection table

Inside `Package::read_from`, the dispatch on `(needs_uexp, uexp_provided)`
yields four cases:

| `needs_uexp` (any export's payload extends past `uasset.len()`) | `uexp_provided` (caller supplied `Some(&uexp)`) | Outcome |
|---|---|---|
| false | None | Monolithic asset. Borrow `uasset` as the single buffer; no stitch. |
| false | Some | **Warn** ("`.uexp` companion bytes provided but no export payload extends past .uasset.len(); ignoring companion") and proceed as monolithic. The extra buffer is dropped. |
| true | Some | Split asset. Stitch `uasset ++ uexp` into a combined buffer; verify `uasset.len() == total_header_size` (`SplitAssetSizeMismatch` if not). |
| true | None | **Reject** with `AssetParseFault::MissingCompanionFile { kind: CompanionFileKind::Uexp }`. |

`needs_uexp` is determined by walking the export table and asking
whether any export's `(serial_offset + serial_size)` extends past
`uasset.len()`. This is the structural discriminator between
monolithic and split; using `total_header_size` would be tautological
(it always equals `uasset.len()` in a split asset by definition).

### Pak-archive resolution flow

`Package::read_from_pak(pak_path, virtual_path, mappings)`:

1. Open the pak.
2. Read the `.uasset` entry at `virtual_path`.
3. Derive the `.uexp` sibling path; attempt `read_entry`. Three outcomes:
   - `Ok(bytes)` → pass `Some(&bytes)` to `Package::read_from`.
   - `Err(EntryNotFound)` → pass `None` (monolithic).
   - any other error → propagate.
4. Derive the `.ubulk` sibling path; probe with `index_entry()` (O(1)
   hashmap probe, no decompression).
   - Present → emit `tracing::warn!` ("`.ubulk` companion found but bulk
     data stitching is not yet supported").
   - Absent → silent; monolithic-without-bulk is normal.
5. Hand both buffers (and `virtual_path` as the asset_path tag) to
   `Package::read_from`.

The `.ubulk` probe uses `index_entry` rather than `read_entry`
deliberately — `read_entry` would decompress and allocate the full
bulk payload only to discard it, which is wasteful when all we need
is presence/absence.

## Variants

### Loose filesystem flow (planned)

Paksmith does not yet expose `Package::read_from_path` for loose-file
input. When it lands, the resolution will mirror the pak flow:

1. Read the `.uasset` file.
2. Derive sibling paths via `derive_companion_path`.
3. For each sibling: probe with `std::fs::metadata`; on success, read.
4. Hand the buffers to `Package::read_from`.

The four-state table applies identically.

### IoStore flow (planned)

Phase 8's IoStore support will require its own resolution flow because
IoStore packages are referenced by chunk IDs, not virtual paths. The
TOC publishes a chunk per logical file, with separate `IoChunkType`s
for `ExportBundleData`, `BulkData`, `OptionalBulkData`, etc.
Resolution becomes "look up the matching chunk ID via `EIoChunkType`"
rather than "swap the path extension".

## Caps & limits

- **`MAX_UEXP_SIZE = 1 GiB`** — enforced when a `.uexp` is provided.
  See [`uexp.md`](uexp.md).
- **Combined `uasset.len() + uexp.len()` overflow** — paksmith checks
  for `usize` overflow on the combined-buffer reservation before
  allocating; surfaces as `AssetParseFault::U64ArithmeticOverflow` with
  `operation = AssetOverflowSite::SplitAssetConcatExtent`.
- **No `.ubulk` cap yet** — detection-only at present. See
  [`ubulk.md`](ubulk.md).

## Verification

- **Fixtures:**
  - `tests/fixtures/minimal_uasset_v5.uasset` — monolithic case
    (no companion needed).
  - `tests/fixtures/real_v8b_split.pak` — split-asset case
    (`.uasset` + `.uexp` entries only; no `.ubulk` in the current
    synthetic fixture suite — tracked in
    [#347](https://github.com/r6e/paksmith/issues/347)).
- **Cross-validation oracle:** CUE4Parse[^1] follows the identical
  path-derivation convention (swap extension); the four-state
  detection is paksmith's own elaboration, with the rejection cases
  matching what CUE4Parse implicitly handles (CUE4Parse fails harder
  on `MissingCompanionFile`-equivalent situations by erroring during
  buffer access rather than at a structured detection point).
- **Known divergences:**
  - **Monolithic-with-extra-uexp behavior.** Paksmith warns and
    discards the extra buffer. CUE4Parse and unreal_asset don't
    expose an analog of this call shape (their APIs take a path,
    not buffers), so the divergence is API-shape-only.

## Paksmith implementation

**Parser module:** `crates/paksmith-core/src/asset/package.rs`.

**Status:** `complete` for the in-memory and pak-archive flows.
`partial` overall pending the loose-filesystem and IoStore flows
(both deferred to later phases).

**Public surface:**
- `Package::read_from(uasset: &[u8], uexp: Option<&[u8]>, mappings: Option<&Usmap>, asset_path: &str) -> Result<Self>` —
  in-memory flow with explicit buffers.
- `Package::read_from_pak<P: AsRef<Path>>(pak_path: P, virtual_path: &str, mappings: Option<&Usmap>) -> Result<Self>` —
  pak-archive flow.
- `fn derive_companion_path(base: &str, new_ext: &str) -> String` —
  pub(super); helper used by both flows.

**Error variants:**
- `AssetParseFault::MissingCompanionFile { kind: CompanionFileKind }` —
  `Uexp` is live; `Ubulk` is defined but currently inert (detection,
  not error).
- `AssetParseFault::SplitAssetSizeMismatch { uasset_len, total_header_size }`.
- `AssetParseFault::BoundsExceeded { field: AssetWireField::UexpSize, … }`.

**Phase plan:**
- In-memory flow + four-state detection: `docs/plans/phase-2e-companion-files.md`
  (Task 1 — Phase 2e PR #316).
- Pak-archive flow: same plan (Task 4 — Phase 2e PR #317).
- Loose-filesystem flow: not yet planned.
- IoStore flow: `docs/plans/ROADMAP.md` Phase 8.

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Package.cs@ecc4878950336126f125af0747190edf474b2a21` — primary oracle. CUE4Parse's package loader follows the same `(swap-extension, look-up-in-container)` convention paksmith implements.
