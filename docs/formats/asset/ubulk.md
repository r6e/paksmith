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

**Document status: complete.** The `.ubulk` file is structureless
by format — a flat byte stream whose record boundaries are published
by the parent `.uasset`'s `FByteBulkData` records, not by any
internal structure in the `.ubulk` file. This doc documents the
structurelessness, the per-record metadata's role in the parent
asset, and how compressed / encrypted records interact with the
`.ubulk` byte ranges. The full wire layout of `FByteBulkData`
records (with their version-conditional field widths) is documented
canonically in [`bulk-data.md`](bulk-data.md); this doc cross-
references there for the per-record mechanics.

**Paksmith parser status: `implemented`** (Phase 3b PRs #480 / #481 /
#483 + Task 6). `BulkDataResolver` handles all four storage tiers
(inline / uexp-resident / streaming `.ubulk` / optional-streaming
`.uptnl`), gated by the full per-record + per-export + per-package
defense chain (see [`bulk-data.md`](bulk-data.md)). The Phase 2e
"detection-only `tracing::warn!`" surface is gone; the resolver is
constructed lazily inside `Package::read_from_pak` and only fires
the `.ubulk` / `.uptnl` loader closures when downstream consumers
call `Package::resolve_bulk_for_export` (3e/3g/3h typed exports
drive this). Per-format export (texture mips / vertex bytes /
audio chunks) lands in the format-handler sub-phases.

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
(matching `.pak`'s entry compression — see
[`../compression/pak-block-framing.md`](../compression/pak-block-framing.md))
or AES-encrypted (see [`../crypto/aes-pak.md`](../crypto/aes-pak.md));
the per-record flags in `.uasset` drive that decode.

### Worked example — uncompressed 32-byte bulk record

Because `.ubulk` is structureless, a worked example must show both
the `.ubulk` bytes AND the parent `.uasset`'s `FByteBulkData` record
that carves them. Suppose a 32-byte `.ubulk` carrying a single
uncompressed record:

```
.ubulk file contents (32 bytes — arbitrary opaque payload):

Offset  Bytes (LE)                                       Field
------  -----------------------------------------------  ------
+0      00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  payload[0..16]
+16     10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F  payload[16..32]
+32                                                       (EOF — file is exactly the record's bytes)
```

The matching `FByteBulkData` record inside the parent `.uasset`
publishes (at least) four pieces of metadata; the per-record byte
layout (with version-conditional widening) is documented canonically
in [`bulk-data.md`](bulk-data.md). The example here gives the field
values symbolically:

```
FByteBulkData record (conceptual; field types deferred to the
                      FByteBulkData doc):
  bulk_data_flags   = 0x00000100   (BULKDATA_PayloadInSeperateFile;
                                    routes to .ubulk per the tier-dispatch
                                    table in bulk-data.md; not compressed,
                                    not encrypted)
  element_count     = 32           (one element per byte for raw byte payloads)
  size_on_disk      = 32           (matches uncompressed size when no compression)
  offset_in_file    = 0            (byte offset within .ubulk)
```

Reader logic to materialize the payload:

1. Open the sibling `.ubulk` (located via [`companion-resolution.md`](companion-resolution.md)).
2. Seek to `offset_in_file = 0`.
3. Read `size_on_disk = 32` bytes.
4. If `bulk_data_flags` indicates compression, dispatch to the
   compression-blocks decoder; if it indicates encryption, dispatch
   to AES decrypt first; otherwise hand the 32 raw bytes to the
   per-asset-class decoder (texture mip, audio sample buffer, anim
   stream, etc.).

Multiple records inside one `.uasset` carve the `.ubulk` into
adjacent or overlapping byte ranges; the records carry all the
structure, the file carries the bytes.

## Variants

None on the wire — `.ubulk` is structureless. Variation comes from
the bulk-data records inside the parent `.uasset`, which paksmith
will document under `texture/`, `audio/`, etc. as those families
get sub-phase 3e/3f/3g/3h implementation work.

## Caps & limits

### Format-defined limits (wire-imposed)

- **None at the file level.** `.ubulk` is structureless by format:
  no header, no length field, no terminator. The on-disk byte count
  is just the union of all per-record byte ranges; any byte not
  claimed by a record is dead space (format-permitted but unused).
- **Per-record bounds** are imposed by the parent `.uasset`'s
  `FByteBulkData` record (the record carries the `offset_in_file`,
  `size_on_disk`, and `element_count` metadata that publishes each
  range). Exact wire widths are version-conditional; see
  [`bulk-data.md`](bulk-data.md) §*Format-defined limits* for the
  canonical width-vs-version table. `.ubulk` itself does not
  constrain them.

### Implementation hardening (recommended for any parser)

A reader that materializes `.ubulk` payloads (paksmith does as of
Phase 3b — see [`bulk-data.md`](bulk-data.md) for the full cap
chain) MUST cap before allocation:

- **Per-record uncompressed-size cap** (analog to
  `MAX_UNCOMPRESSED_ENTRY_BYTES` in the pak reader). The record's
  `size_on_disk` and `element_count` are attacker-influenced fields
  read from the parent `.uasset`; a 4 GiB record claim must not
  drive a 4 GiB allocation without a cap check.
- **Total `.ubulk` file-size cap** (analog to `MAX_UEXP_SIZE` for
  the `.uexp` companion). Bounds the seek window the reader will
  honor for `offset_in_file + size_on_disk` claims. The addition
  itself MUST use overflow-checked arithmetic (e.g.
  `offset_in_file.checked_add(size_on_disk_as_u64)`); an attacker-
  supplied `offset_in_file` near `u64::MAX` plus any nonzero
  `size_on_disk` wraps to a small number under naive arithmetic and
  silently passes a unsigned cap comparison.
- **Compression-block-framing caps** apply to compressed records,
  inherited from
  [`../compression/pak-block-framing.md`](../compression/pak-block-framing.md).
- **AES decryption caps** apply to encrypted records, inherited from
  [`../crypto/aes-pak.md`](../crypto/aes-pak.md).

See `docs/security/allocation-caps.md` for the broader policy that
paksmith's Phase 3b cap constants follow.

## Verification

- **Fixture:** The Worked example above is byte-exact and self-
  contained — the file's structurelessness means a 32-byte synthetic
  hex blob fully specifies the wire shape. A real-cooked
  `.ubulk` + parent `.uasset` pair (for end-to-end cross-validation
  of the records-driven decode) is tracked at
  [#347](https://github.com/r6e/paksmith/issues/347);
  `tests/fixtures/real_v8b_split.pak` covers `.uasset` + `.uexp` but
  not `.ubulk`.
- **Hex anchor commands:**
  ```
  # Synthesize the 32-byte structureless .ubulk from the Worked example:
  printf '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F' | xxd
  ```
  A conformant reader fed these 32 bytes plus an `FByteBulkData`
  record with `offset=0, size=32, no compression` MUST return the
  same 32 bytes as the bulk payload.
- **Cross-validation oracle:** CUE4Parse[^1] and `unreal_asset`[^2].
  Both read `.ubulk` payloads driven by `FByteBulkData` records;
  paksmith's structurelessness claim and the records-on-the-asset-
  side decode shape are consistent with both. Paksmith's
  `BulkDataResolver` (Phase 3b) follows the same records-driven
  decode shape.
- **Known divergences:** none specific to the `.ubulk` file shape.
  Record-level decode divergences (e.g. SizeOnDisk widening,
  reserved-bit handling) are documented in
  [`bulk-data.md`](bulk-data.md) §Verification.

## Paksmith implementation

**Parser module:** `crates/paksmith-core/src/asset/bulk_data.rs`
holds the `BulkDataResolver` (tier dispatch + cap chain + zlib
decode); `crates/paksmith-core/src/asset/package.rs`
(`Package::read_from_pak`) wires the resolver with lazy
`Arc<PakReader>`-backed `.ubulk` / `.uptnl` loader closures.

**Status:** `implemented` (Phase 3b — PRs #480 + #481 + #483 + Task
6 wiring). The detection-only `tracing::warn!` from Phase 2e is
gone.

**Public surface:**
- `Package::read_from_pak(pak_path, virtual_path, mappings)` —
  builds the resolver with lazy companion-file loaders. The `.ubulk`
  / `.uptnl` entries are NOT eagerly read at pak-open; the closures
  fire only when downstream consumers call
  `Package::resolve_bulk_for_export`.
- `Package::resolve_bulk_for_export(export_idx)` — first-call lazy
  resolution + per-call `OnceLock`-cached return. Drives the
  `BulkDataResolver::resolve` chain over the records previously
  registered via `Package::insert_bulk_records` (the 3e/3g/3h
  typed-reader hook).

**Error variants:** see [`bulk-data.md`](bulk-data.md) §Caps & limits
for the full list. `.ubulk`-specific:
- `AssetParseFault::MissingCompanionFile { kind: CompanionFileKind::Ubulk }` —
  fires when a streaming-tier record references `.ubulk` bytes but
  the companion is absent from the pak.
- `AssetParseFault::BulkDataCompanionTooLarge { kind: Ubulk, .. }` —
  fires if `.ubulk` exceeds `MAX_UBULK_FILE_SIZE` (16 GiB) at the
  lazy-load boundary.

**Cap constants** (defined in `crates/paksmith-core/src/asset/bulk_data.rs`):
see [`bulk-data.md`](bulk-data.md) §*Implementation hardening*.

**Phase plan:**
- Phase 3b — `docs/plans/phase-3b-bulk-data-resolver.md`. Resolver
  + tier dispatch + wiring. (Previous Phase 2e `tracing::warn!`
  detection — `docs/plans/phase-2e-companion-files.md` Task 4,
  PR #317 — was superseded.)

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Package.cs@ecc4878950336126f125af0747190edf474b2a21` — primary oracle. The `FByteBulkData.Serialize` family covers the in-`.uasset` records that drive `.ubulk` decoding.
[^2]: `AstroTechies/unrealmodding/unreal_asset/src/asset.rs@f4df5d8e75b1e184832384d1865f0b696b90a614` — Rust oracle. Bulk-data reading is supported here; paksmith's Phase 3b `BulkDataResolver` cross-validates against this shape (see [`bulk-data.md`](bulk-data.md) §Verification).
