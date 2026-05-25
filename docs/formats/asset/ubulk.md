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
structurelessness, the per-record metadata location in the parent
asset, and how compressed / encrypted records interact with the
`.ubulk` byte ranges. The records' wire layout itself lives in
[`uasset.md`](uasset.md) §*Bulk-data records* (where `FByteBulkData`
is documented).

**Paksmith parser status: `partial`** (Phase 2e PR #317). The pak
reader notices when a sibling `.ubulk` exists and emits a
`tracing::warn!` event so operators see the "this asset has bulk
data we're not yet reading" signal. Phase 2f will replace detection
with real bulk-data stitching and per-record decode (textures,
audio, anim).

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

The matching `FByteBulkData` record inside the parent `.uasset` (per
[`uasset.md`](uasset.md) §*Bulk-data records*) carries:

```
FByteBulkData record (in the parent .uasset):
  bulk_data_flags   = 0x00000001   (BULKDATA_PayloadAtEndOfFile or similar; not compressed, not encrypted)
  element_count     = 32           (u32; one element per byte for raw byte payloads)
  size_on_disk      = 32           (u32; matches uncompressed size when no compression)
  offset_in_file    = 0            (u64; byte offset within .ubulk)
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
get Phase 2f+ implementation work.

## Caps & limits

### Format-defined limits (wire-imposed)

- **None at the file level.** `.ubulk` is structureless by format:
  no header, no length field, no terminator. The on-disk byte count
  is just the union of all per-record byte ranges; any byte not
  claimed by a record is dead space (format-permitted but unused).
- **Per-record bounds** are imposed by the parent `.uasset`'s
  `FByteBulkData` record fields (`offset_in_file: u64`,
  `size_on_disk: u32`, `element_count: u32`). The record-side wire
  bounds are documented in [`uasset.md`](uasset.md) §*Bulk-data
  records*; `.ubulk` itself does not constrain them.

### Implementation hardening (recommended for any parser)

A reader that materializes `.ubulk` payloads (paksmith does not yet,
beyond detection) MUST cap before allocation:

- **Per-record uncompressed-size cap** (analog to
  `MAX_UNCOMPRESSED_ENTRY_BYTES` in the pak reader). The record's
  `size_on_disk` and `element_count` are attacker-influenced fields
  read from the parent `.uasset`; a 4 GiB record claim must not
  drive a 4 GiB allocation without a cap check.
- **Total `.ubulk` file-size cap** (analog to `MAX_UEXP_SIZE` for
  the `.uexp` companion). Bounds the seek window the reader will
  honor for `offset_in_file + size_on_disk` claims.
- **Compression-block-framing caps** apply to compressed records,
  inherited from
  [`../compression/pak-block-framing.md`](../compression/pak-block-framing.md).
- **AES decryption caps** apply to encrypted records, inherited from
  [`../crypto/aes-pak.md`](../crypto/aes-pak.md).

See `docs/security/allocation-caps.md` for the broader policy that
the planned Phase 2f caps will follow.

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
  side decode shape are consistent with both.
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
