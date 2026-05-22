# UBulk (`.ubulk`)

> Bulk-data sidecar for UE assets — large payloads (texture mips, audio
> bodies, animation streams) that the engine streams separately from
> the main `.uasset` / `.uexp`.

## Overview

`.ubulk` holds the bulk-data payloads referenced by a UE asset:
high-resolution texture mip chains, audio sample buffers, animation
streaming data, anything large enough that the engine wants to demand-
load it rather than carrying it inline. The format is structureless —
a flat byte stream whose interpretation depends entirely on the
asset's bulk-data records (which live in `.uasset`).

Multiple bulk-data records inside one `.uasset` carve `.ubulk` into
per-record byte ranges with `(offset, size, compression-method, flags)`
metadata. The records carry the structure; the file carries the bytes.

**Paksmith status: detection-only** (Phase 2e PR #317). The pak reader
notices when a sibling `.ubulk` exists and emits a `tracing::warn!`
event so operators see the "this asset has bulk data we're not yet
reading" signal. Phase 2f will replace detection with real bulk-data
stitching and per-record decode (textures, audio, anim).

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| All UE4 + UE5 | Structureless byte stream; the wire shape is "whatever the `.uasset`'s `FByteBulkData` records say". The shape of the records evolves (compression flags, offset width), not the `.ubulk` itself. | `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Package.cs@ecc4878950336126f125af0747190edf474b2a21`[^1] |

`.ubulk` as a file has no version field; record-shape variance lives
inside the parent `.uasset`'s bulk-data records.

## Wire layout

| offset | size | endian | name | type | semantics |
|--------|------|--------|------|------|-----------|
| 0 | filesize | — | `bulk_records` | byte stream | Concatenation of bulk-data record payloads. Boundaries published by the `.uasset`'s bulk-data records, not by any structure in this file. |

A bulk-data record's payload may itself be compression-block-framed
(matching `.pak`'s entry compression — the dedicated compression doc is
planned under `docs/formats/compression/`) or AES-encrypted; the
per-record flags in `.uasset` drive that decode.

### Worked example: first bytes of a `.ubulk`

*(none yet — see [#347](https://github.com/r6e/paksmith/issues/347).
The current synthetic fixture suite carries no `.ubulk` entries at all;
a real-cooked-game fixture is tracked in that issue.)*

## Variants

None on the wire — `.ubulk` is structureless. Variation comes from
the bulk-data records inside the parent `.uasset`, which paksmith
will document under `texture/`, `audio/`, etc. as those families
get Phase 2f+ implementation work.

## Caps & limits

**Detection only — no caps enforced yet.** Phase 2f will add caps
mirroring the pak side:
- A per-record uncompressed-size cap (analog to `MAX_UNCOMPRESSED_ENTRY_BYTES`
  in the pak reader).
- A total `.ubulk` file-size cap (analog to `MAX_UEXP_SIZE` for the
  `.uexp` companion).
- Compression-block-framing caps applied to compressed records.

See `docs/security/allocation-caps.md` for the broader policy that
the future caps will follow.

## Verification

- **Fixture:** `(none yet — see [#347](https://github.com/r6e/paksmith/issues/347))` —
  `tests/fixtures/real_v8b_split.pak` only carries `.uasset` + `.uexp`
  entries; no `.ubulk` is present in the current synthetic fixture
  suite. A real-cooked fixture with a `.ubulk` sibling is tracked there.
- **Hex anchor commands:** `(none yet — see [#347](https://github.com/r6e/paksmith/issues/347))`.
- **Cross-validation oracle:** CUE4Parse[^1] and `unreal_asset`[^2].
  Phase 2f work will cross-validate paksmith's per-record reader
  against both.
- **Known divergences:**
  - **No paksmith reader yet.** CUE4Parse and unreal_asset read
    `.ubulk` payloads (driven by `FByteBulkData` records). Paksmith
    currently only detects existence and warns; bulk-data records in
    parsed `.uasset` packages carry their `.ubulk` offsets in the
    summary's `bulk_data_start_offset` field but the payloads aren't
    materialized.

## Paksmith implementation

**Parser module:** detection logic in
`crates/paksmith-core/src/asset/package.rs` (`Package::read_from_pak`,
lines ~658–676). No standalone bulk-data reader yet.

**Status:** `partial` (detection ships; payload reading deferred to
Phase 2f).

**Public surface:**
- `Package::read_from_pak(pak_path, virtual_path)` — detects sibling
  `.ubulk` via `PakReader::index_entry()` (O(1) probe; no decompression)
  and emits a `tracing::warn!` event if present. No API exposed for
  reading the bulk-data payload.

**Error variants:**
- `AssetParseFault::MissingCompanionFile { kind: CompanionFileKind::Ubulk }` —
  defined in `crates/paksmith-core/src/error.rs` (~line 3057) for future
  use. Currently inert: detection treats a missing `.ubulk` as expected
  and detection of a present `.ubulk` triggers a warn, not an error.

**Cap constants:** none yet (Phase 2f deliverable).

**Phase plan:**
- Detection: `docs/plans/phase-2e-companion-files.md` (Task 4 —
  Phase 2e PR #317).
- Payload reading: `docs/plans/ROADMAP.md` Phase 2f (bulk-data
  stitching).

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Package.cs@ecc4878950336126f125af0747190edf474b2a21` — primary oracle. The `FByteBulkData.Serialize` family covers the in-`.uasset` records that drive `.ubulk` decoding.
[^2]: `AstroTechies/unrealmodding/unreal_asset/src/asset.rs@f4df5d8e75b1e184832384d1865f0b696b90a614` — Rust oracle. Bulk-data reading is supported here; paksmith will cross-validate against it when Phase 2f implements the reader.
