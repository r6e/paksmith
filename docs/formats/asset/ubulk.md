# UBulk (`.ubulk`)

> Bulk-data sidecar for UE assets — large payloads (texture mips, audio
> bodies) that a package's bulk-data records place in a file separate
> from the main `.uasset` / `.uexp`.

## Overview

`.ubulk` holds bulk-data payloads referenced by a UE asset, such as
high-resolution texture mip chains and audio sample buffers. The
format is structureless — a flat byte stream whose interpretation
depends entirely on the asset's bulk-data records.

Multiple bulk-data records inside one `.uasset` carve `.ubulk` into
per-record byte ranges with `(offset, size, flags)` metadata. The
records carry the structure; the file carries the bytes.

**Document status: complete.** The `.ubulk` file is structureless
by format — a flat byte stream whose record boundaries are published
by the parent `.uasset`'s `FByteBulkData` records, not by any
internal structure in the `.ubulk` file. This doc documents the
structurelessness, the per-record metadata's role in the parent
asset, and how compressed records interact with the `.ubulk` byte
ranges. The full wire layout of `FByteBulkData` records (with their
version-conditional field widths) is documented canonically in
[`bulk-data.md`](bulk-data.md); this doc cross-references there for
the per-record mechanics.

**Paksmith parser status: `complete`** (Phase 3b PRs #480 / #481 /
#483 + Task 6). `BulkDataResolver` handles all four storage tiers
(inline / uexp-resident / streaming `.ubulk` / optional-streaming
`.uptnl`), gated by the per-record + per-export + per-package
defense chain (see [`bulk-data.md`](bulk-data.md)). The Phase 2e
"detection-only `tracing::warn!`" surface is gone; the resolver is
constructed inside `Package::read_from_pak` and runs the `.ubulk` /
`.uptnl` loader closures only on demand (see
[Paksmith implementation](#paksmith-implementation)).

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| All UE4 + UE5 | Structureless byte stream; the wire shape is "whatever the `.uasset`'s `FByteBulkData` records say". | `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Package.cs@ecc4878950336126f125af0747190edf474b2a21`[^1] |

`.ubulk` as a file has no version field; record-shape variance lives
inside the parent `.uasset`'s bulk-data records.

## Wire layout

| offset | size | endian | name | type | semantics |
|--------|------|--------|------|------|-----------|
| 0 | filesize | — | `bulk_records` | byte stream | Bulk-data record payloads. Boundaries published by the `.uasset`'s bulk-data records, not by any structure in this file. |

A bulk-data record's flags may mark its payload compressed: see
[`bulk-data.md`](bulk-data.md) §*Payload decompression* for the zlib
framing and §*LZO and BitWindow (fail-closed)* for the other two
compression flags.

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
  bulk_data_flags   = 0x00010501   (PayloadAtEndOfFile | PayloadInSeperateFile
                                    | Force_NOT_InlinePayload | NoOffsetFixUp,
                                    a UE 4.26+ cooked word; the separate-file
                                    bit routes it to .ubulk per the tier-dispatch
                                    table in bulk-data.md; not compressed)
  element_count     = 32           (one element per byte for raw byte payloads)
  size_on_disk      = 32           (matches uncompressed size when no compression)
  offset_in_file    = 0            (byte offset within .ubulk)
```

Reader logic to materialize the payload:

1. Open the sibling `.ubulk` (located via [`companion-resolution.md`](companion-resolution.md)).
2. Seek to `offset_in_file = 0`.
3. Read `size_on_disk = 32` bytes.
4. If `bulk_data_flags` sets `BULKDATA_SerializeCompressedZLIB`, decode
   the chunked `FCompressedChunkInfo` framing
   ([`bulk-data.md`](bulk-data.md) §*Payload decompression*); for the
   LZO and BitWindow flags see [`bulk-data.md`](bulk-data.md)
   §*LZO and BitWindow (fail-closed)*. With no compression flag set,
   hand the 32 raw bytes to the per-asset-class decoder (texture mip,
   audio sample buffer, etc.).

Multiple records inside one `.uasset` carve the `.ubulk` into
adjacent or overlapping byte ranges; the records carry all the
structure, the file carries the bytes.

## Variants

None on the wire — `.ubulk` is structureless. Variation comes from
the bulk-data records inside the parent `.uasset`.

## Caps & limits

### Format-defined limits (wire-imposed)

- **None at the file level.** `.ubulk` is structureless by format:
  no header, no length field, no terminator. Any byte not claimed
  by a record is dead space (format-permitted but unused).
- **Per-record bounds** are imposed by the parent `.uasset`'s
  `FByteBulkData` record (the record carries the `offset_in_file`,
  `size_on_disk`, and `element_count` metadata that publishes each
  range). Exact wire widths are version-conditional; see
  [`bulk-data.md`](bulk-data.md) §*Format-defined limits* for the
  canonical width-vs-version table. `.ubulk` itself does not
  constrain them.

### Implementation hardening (recommended for any parser)

A reader that materializes `.ubulk` payloads (paksmith does as of
Phase 3b — see [`bulk-data.md`](bulk-data.md) for its record-level
caps) MUST cap before allocation:

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
  silently passes an unsigned cap comparison.

See `docs/security/allocation-caps.md` for the broader policy.

## Verification

- **Fixture:** The Worked example above is byte-exact and self-
  contained — the file's structurelessness means a 32-byte synthetic
  hex blob fully specifies the wire shape.
- **Hex anchor commands:**
  ```
  # Synthesize the 32-byte structureless .ubulk from the Worked example:
  printf '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F' | xxd
  ```
  A conformant reader fed these 32 bytes plus an `FByteBulkData`
  record with `offset=0, size=32, no compression` MUST return the
  same 32 bytes as the bulk payload.
- **Cross-validation oracle:** CUE4Parse[^1]. It reads `.ubulk`
  payloads driven by `FByteBulkData` records; paksmith's
  structurelessness claim and the records-on-the-asset-side decode
  shape are consistent with it.
- **Known divergences:** documented in [`bulk-data.md`](bulk-data.md)
  §Verification, among them `SizeOnDisk` widening, reserved-bit
  handling and where a record's read starts inside its `.ubulk`.

## Paksmith implementation

**Parser module:** `crates/paksmith-core/src/asset/bulk_data.rs`
holds the `BulkDataResolver` (tier dispatch + cap chain + zlib
decode); `crates/paksmith-core/src/asset/package.rs`
(`Package::read_from_pak`) wires the resolver with lazy
`Arc<PakReader>`-backed `.ubulk` / `.uptnl` loader closures.

**Status:** `complete` (Phase 3b — PRs #480 + #481 + #483 + Task
6 wiring). The detection-only `tracing::warn!` from Phase 2e is
gone.

**Public surface:**
- `Package::read_from_pak(pak_path, virtual_path, mappings)` —
  builds the resolver with lazy companion-file loaders. The `.ubulk`
  / `.uptnl` entries are NOT eagerly read at pak-open; each loader
  runs on the first resolve that needs it (a mesh reader's streamed
  LOD, or `Package::resolve_bulk_for_export`) and at most once per
  package. A companion that fails to load reports that failure again
  instead of loading again.
- `Package::resolve_bulk_for_export(export_idx)` — first-call lazy
  resolution + per-call `OnceLock`-cached return. Drives
  `BulkDataResolver::resolve_all` over the records previously
  registered via `Package::insert_bulk_records` (the typed-reader
  hook), charging them against a bulk-read ledger of the call's own
  (see [`bulk-data.md`](bulk-data.md)).

**Error variants** (`.ubulk`-specific):
- `AssetParseFault::MissingCompanionFile { kind: CompanionFileKind::Ubulk }` —
  fires when a streaming-tier record references `.ubulk` bytes but
  the companion is absent from the pak.
- `AssetParseFault::BulkDataCompanionTooLarge { kind: Ubulk, .. }` —
  fires if `.ubulk` exceeds `MAX_UBULK_FILE_SIZE` (16 GiB) at the
  lazy-load boundary.

**Cap constants:** defined in `crates/paksmith-core/src/asset/bulk_data.rs`;
[`bulk-data.md`](bulk-data.md) §*Implementation hardening* covers the
record-level ones.

**Phase plan:**
- Phase 3b — `docs/plans/phase-3b-bulk-data-resolver.md`. Resolver
  + tier dispatch + wiring. (Previous Phase 2e `tracing::warn!`
  detection — `docs/plans/phase-2e-companion-files.md` Task 4,
  PR #317 — was superseded.)

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Package.cs@ecc4878950336126f125af0747190edf474b2a21` — primary oracle. It attaches the `.ubulk` as a payload archive (L178-L183); `CUE4Parse/UE4/Assets/Objects/TBulkData.cs` (`GetBulkArchive`, L109-L161) and `FByteBulkData.cs` (`ReadBulkDataInto`, L93-L117) at the same commit read each record's bytes from it: the flags pick the archive, and the read takes `SizeOnDisk` bytes from `OffsetInFile`, or from 0 when the archive is exactly `SizeOnDisk` bytes long (`TBulkData.cs` L131, L144).
