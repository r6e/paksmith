# Bulk-data records (`FByteBulkData` / `FByteBulkDataHeader`)

> Shared header structure that locates and sizes a large binary payload —
> a texture mip, a sound buffer, an animation chunk — within one of three
> tiers: inline in the parent `.uasset`/`.uexp`, separate in `.ubulk`, or
> optional in `.uptnl`. Used pervasively across `Texture2D`, `SoundWave`,
> `SkeletalMesh`, `AnimSequence`, and any other UObject carrying bulk
> payloads.

## Overview

`FByteBulkData` is UE's shared bulk-data container. Wherever a UObject
needs to point at a large binary payload that can be streamed (texture
mips, audio buffers, animation chunks, etc.), the wire layout for that
pointer is the same `FByteBulkDataHeader` record described below — a
fixed-ish header (with two version-conditional field widths) followed
optionally by inline payload bytes, or just a sized reference into one
of the companion sidecar files.

Concretely, an `FByteBulkData` record on the wire publishes:

1. **`BulkDataFlags: u32`** — bitfield describing the storage tier
   (inline / uexp / `.ubulk` / `.uptnl`), compression, encryption, and
   size-format choices.
2. **`ElementCount`** — number of elements (bytes for byte bulk data;
   the "uncompressed" element count).
3. **`SizeOnDisk`** — bytes occupied by the on-wire payload (post-
   compression if applicable).
4. **`OffsetInFile`** — byte offset into the containing file.
5. **Conditional skip regions** when `BULKDATA_BadDataVersion` or
   `BULKDATA_DuplicateNonOptionalPayload` are set.

Where the payload bytes live is governed by the `BulkDataFlags`:

- **Inline** (in `.uasset`): `BULKDATA_PayloadAtEndOfFile` set and
  `OffsetInFile` falls within `[0, total_header_size)`.
- **`.uexp`-resident**: `BULKDATA_PayloadAtEndOfFile` set and
  `OffsetInFile` falls within `[total_header_size, …)`.
- **`.ubulk` streaming**: `BULKDATA_PayloadInSeperateFile` set (note the
  engine's spelling preserves "Seperate"); `OffsetInFile` is from the
  start of the `.ubulk` file.
- **`.uptnl` optional**: `BULKDATA_OptionalPayload` + `BULKDATA_PayloadInSeperateFile`
  both set; `OffsetInFile` is from the start of the `.uptnl` file.

This doc is the canonical wire-layout reference for `FByteBulkData`.
Downstream docs ([`ubulk.md`](ubulk.md),
[`../texture/mips-and-streaming.md`](../texture/mips-and-streaming.md),
[`../audio/sound-wave.md`](../audio/sound-wave.md)) cross-reference
here for the per-record mechanics; they retain only the format-
specific framing (where a particular record appears within their
parent format, how the record's metadata interacts with the format's
own structure).

**Document status: complete.** Wire format documented in full for
the `FByteBulkDataHeader` constructor's main serial path
(`BulkDataFlags` + version-conditional `ElementCount`/`SizeOnDisk`/`OffsetInFile` widths +
`BulkDataStartOffset` fixup + two flag-gated skip regions) and the
full 22-entry `EBulkDataFlags` catalog. The two alternate read paths
(via `IoPackage.BulkDataMap` and `Package.DataResourceMap` short-
circuits at the head of the constructor) are identified by name and
deferred: they're reader-side optimizations using pre-baked
per-record metadata tables, not new wire formats.

**Paksmith parser status: `partial`.** Companion-file detection
ships (Phase 2e PR #317 — `.uexp` / `.ubulk` sibling lookups); the
`FByteBulkData` record reader itself is a Phase 2f / Phase 3+
deliverable. No materialization of bulk-data payloads yet.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| UE 4.0+ | `FByteBulkData` introduced as the shared bulk-payload header. Initial widths: `ElementCount: i32`, `SizeOnDisk: u32`, `OffsetInFile: i32`. | `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Objects/FByteBulkDataHeader.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d`[^1] |
| UE 4.3+ (`BULKDATA_AT_LARGE_OFFSETS`) | `OffsetInFile` widens from `i32` (4 bytes) to `i64` (8 bytes) per the version constant. Paksmith's pak v3+ accepted range starts at UE 4.4+, so paksmith always sees the 8-byte form. | Same[^1] |
| UE 4.26+ (`BULKDATA_NoOffsetFixUp`) | Flag added at bit 16. When set, the reader does NOT apply the `BulkDataStartOffset` fixup. Used for already-final-absolute offsets. | `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Objects/EBulkDataFlags.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d`[^1] |
| UE 4.27+ | `BULKDATA_Size64Bit` flag (bit 13) starts seeing widespread use. When set, `ElementCount` widens to `i64` (8 bytes) and `SizeOnDisk` widens to `u64` (8 bytes). | Same[^1] |
| UE 5.0+ | `IoPackage.BulkDataMap` short-circuit added (the constructor first reads a `dataIndex: i32`; if it indexes into a pre-baked `BulkDataMap` table, the inline-serial fields below are NOT read — the metadata comes from the pre-baked table). | Same[^1] |
| UE 5.0+ | Three high-bit flags added: `BULKDATA_AlwaysAllowDiscard` (bit 28), `BULKDATA_HasAsyncReadPending` (bit 29), `BULKDATA_DataIsMemoryMapped` (bit 30). Bit 18 `BULKDATA_LazyLoadable` added in the same era. | Same[^1] |

The `BulkDataFlags` discriminant + version-constant pair determines
every field width and skip-region presence — there is no
top-level header version field on the record itself.

## Wire layout

### Main serial path (`FByteBulkDataHeader.Serialize`)

When neither the `IoPackage.BulkDataMap` nor the `Package.DataResourceMap`
short-circuit fires (both check for pre-baked metadata tables; the
common cooked-content path skips these and reads the wire fields
below directly), the constructor reads:

| order | field | size | endian | type | semantics |
|-------|-------|------|--------|------|-----------|
| 1 | `BulkDataFlags` | 4 | LE | `u32` (`EBulkDataFlags` bitmask) | Storage tier + compression + size-format selector. Bit allocations per the catalog below. |
| 2 | `ElementCount` | 4 or 8 | LE | `i32` / `i64` | Number of elements. 8 bytes (`i64`) when `BULKDATA_Size64Bit` (bit 13) is set, otherwise 4 bytes (`i32`). Signed on both widths. For byte bulk data, equals the uncompressed byte count. |
| 3 | `SizeOnDisk` | 4 or 8 | LE | `u32` / `i64` (low 32 bits used) | Bytes occupied by the on-wire payload (post-compression if applicable). With `BULKDATA_Size64Bit` unset: 4 bytes `u32`. With set: 8 bytes read as `i64`, but CUE4Parse's reference implementation discards the upper 32 bits (`(uint) Ar.Read<long>()`). Conformant parsers should follow the reference: read 8 bytes signed, retain the low 32 bits. |
| 4 | `OffsetInFile` | 8 or 4 | LE | `i64` / `i32` | Byte offset into the containing file. Width is gated on the `BULKDATA_AT_LARGE_OFFSETS` UE version constant (UE 4.3+): 8 bytes (`i64`) for that range and later; 4 bytes (`i32`) on older packages. Paksmith's pak v3+ accepted range starts at UE 4.4+, so paksmith readers always see 8 bytes. **Pre-fixup wire value**: a reader MUST add `Ar.Owner.Summary.BulkDataStartOffset` to the read value UNLESS `BULKDATA_NoOffsetFixUp` (bit 16) is set. |
| 5 | *(conditional)* | 2 | — | skip | When `BULKDATA_BadDataVersion` (bit 15) is set, `Ar.Position += sizeof(ushort)` (2 bytes). The reader then CLEARS the `BULKDATA_BadDataVersion` bit from `BulkDataFlags` (does not propagate to downstream consumers). |
| 6 | *(conditional)* | 12–20 | — | skip | When `BULKDATA_DuplicateNonOptionalPayload` (bit 14) is set, three additional fields follow: `DuplicateFlags: EBulkDataFlags` (4 bytes), `DuplicateSizeOnDisk` (4 or 8 bytes gated on `BULKDATA_Size64Bit`), `DuplicateOffset` (4 or 8 bytes gated on `BULKDATA_AT_LARGE_OFFSETS`). Total additional bytes: 12 (neither gate), 16 (one gate), or 20 (both gates). |

Total fixed-header size on paksmith's accepted UE range (no
`Size64Bit`, no `BadDataVersion`, no `DuplicateNonOptionalPayload`):
4 + 4 + 4 + 8 = **20 bytes**.

### `EBulkDataFlags` catalog (full)

| Bit | Name | Hex | Meaning |
|-----|------|-----|---------|
| 0 | `BULKDATA_PayloadAtEndOfFile` | `0x0001` | Payload bytes are at `OffsetInFile` of the *parent file* (`.uasset` for inline, `.uexp` for uexp-resident; disambiguated by the offset's range relative to `total_header_size`). |
| 1 | `BULKDATA_SerializeCompressedZLIB` | `0x0002` | Payload zlib-compressed; decompress before use. `BULKDATA_SerializeCompressed` is an alias for this flag. |
| 2 | `BULKDATA_ForceSingleElementSerialization` | `0x0004` | Element-by-element serialization (rare for byte bulk data). |
| 3 | `BULKDATA_SingleUse` | `0x0008` | Discard after first read. |
| 4 | `BULKDATA_CompressedLZO` | `0x0010` | Payload LZO-compressed (rare in cooked content). |
| 5 | `BULKDATA_Unused` | `0x0020` | Legacy; readers skip records with this flag set. |
| 6 | `BULKDATA_ForceInlinePayload` | `0x0040` | Inline regardless of streaming settings. |
| 7 | `BULKDATA_ForceStreamPayload` | `0x0080` | Force streaming (use `.ubulk`). |
| 8 | `BULKDATA_PayloadInSeperateFile` | `0x0100` | Payload is in `.ubulk`. ("Seperate" preserves the UE engine enum spelling exactly.) |
| 9 | `BULKDATA_SerializeCompressedBitWindow` | `0x0200` | Uses a custom bit window for compression. |
| 10 | `BULKDATA_Force_NOT_InlinePayload` | `0x0400` | Prevent inlining even when other flags would allow it. |
| 11 | `BULKDATA_OptionalPayload` | `0x0800` | Payload may not be present at all. When combined with `BULKDATA_PayloadInSeperateFile`, routes to `.uptnl`. |
| 12 | `BULKDATA_MemoryMappedPayload` | `0x1000` | Memory-mapped on supported platforms. |
| 13 | `BULKDATA_Size64Bit` | `0x2000` | `ElementCount` and `SizeOnDisk` are 64-bit. |
| 14 | `BULKDATA_DuplicateNonOptionalPayload` | `0x4000` | Duplicated for redundancy. **Wire side-effect:** when set, an additional `DuplicateFlags: u32` (4 bytes) + `DuplicateSizeOnDisk` (4 bytes `u32` or 8 bytes `u64`, gated on `BULKDATA_Size64Bit`) + `DuplicateOffset` (4 bytes `i32` or 8 bytes `i64`, gated on `BULKDATA_AT_LARGE_OFFSETS`) follow the main `OffsetInFile`. Total additional bytes: 12, 16, 16, or 20 depending on the two gates. |
| 15 | `BULKDATA_BadDataVersion` | `0x8000` | Sentinel for older bad data. **Wire side-effect:** when set, an additional 2-byte `ushort` follows the main `OffsetInFile`; the flag is cleared after reading (does not propagate to consumers of `BulkDataFlags`). |
| 16 | `BULKDATA_NoOffsetFixUp` | `0x0001_0000` | When set, skip the `OffsetInFile += Ar.Owner.Summary.BulkDataStartOffset` adjustment. The on-wire `OffsetInFile` is already an absolute file offset. UE 4.26+. |
| 17 | `BULKDATA_WorkspaceDomainPayload` | `0x0002_0000` | Editor-domain payload. |
| 18 | `BULKDATA_LazyLoadable` | `0x0004_0000` | Payload is lazy-loadable (deferred I/O). |
| 28 | `BULKDATA_AlwaysAllowDiscard` | `0x1000_0000` | Always allow discard. |
| 29 | `BULKDATA_HasAsyncReadPending` | `0x2000_0000` | Async read in flight. |
| 30 | `BULKDATA_DataIsMemoryMapped` | `0x4000_0000` | Memory-mapped at runtime. |

Allocated bits: 0-18 + 28-30 (22 entries). Bits 19-27 are
unallocated in CUE4Parse's reference implementation; parsers SHOULD
warn on records with these bits set. Bit 31 was historically
`BULKDATA_UsesIoDispatcher` (now commented-out in
`EBulkDataFlags.cs`); treat as reserved and warn rather than
hard-reject to avoid breaking content from UE builds that re-activate
the slot.

### Tier dispatch (file lookup)

Once `BulkDataFlags` and `OffsetInFile` (post-fixup) are resolved,
the reader maps the record to its physical file:

| Flag combination | Tier | File | Offset interpretation |
|------------------|------|------|------------------------|
| `BULKDATA_PayloadAtEndOfFile` only, `OffsetInFile < total_header_size` | Inline | `.uasset` itself | Offset from `.uasset` start. |
| `BULKDATA_PayloadAtEndOfFile` only, `OffsetInFile >= total_header_size` | uexp-resident | `.uexp` | Offset from `.uasset` start (after stitching, that's `total_header_size + uexp_offset`). |
| `BULKDATA_PayloadInSeperateFile` only | Streaming | `.ubulk` | Offset from `.ubulk` start (absolute). |
| `BULKDATA_OptionalPayload + BULKDATA_PayloadInSeperateFile` | Optional streaming | `.uptnl` | Offset from `.uptnl` start (absolute). |

See [`ubulk.md`](ubulk.md) and `../texture/mips-and-streaming.md`
for the per-format consumer side; this section is the wire-side
dispatch table.

### Payload decompression

When `BULKDATA_SerializeCompressedZLIB` is set, the on-disk payload
is zlib-compressed; readers decompress via the same zlib reader used
by the pak per-block path (see
[`../compression/zlib.md`](../compression/zlib.md)). The decompressed
output size is `ElementCount` bytes (for byte bulk data); a reader
MUST clamp this against `MAX_UNCOMPRESSED_ENTRY_BYTES` before
allocating the output buffer (decompression-bomb guard).

### Alternate read paths (UE 5.0+ pre-baked metadata)

When the parent archive is an `IoPackage` with a non-empty
`BulkDataMap`, or a `Package` with a non-empty `DataResourceMap`,
the `FByteBulkDataHeader` constructor short-circuits the inline
serial reads above: instead of reading the 20-byte header, it reads
a single `dataIndex: i32` (4 bytes) and looks the metadata up in
the pre-baked table. The wire format of those tables (`BulkDataMap`,
`DataResourceMap`) is documented at the parent format level and is
out of scope for this doc. A parser implementing only the inline
serial path MUST validate that neither table is present before
proceeding (CUE4Parse short-circuits at the head of the constructor).

### Worked example — minimal 20-byte FByteBulkDataHeader (UE 4.4+, no special flags)

The minimal cooked-content header: a `.ubulk`-routed streaming payload
of 256 bytes located at offset 0 of the `.ubulk` companion. No
`Size64Bit`, no `BadDataVersion`, no `DuplicateNonOptionalPayload`,
no `NoOffsetFixUp` (so a non-zero `BulkDataStartOffset` fixup would
apply — example assumes the parent's `BulkDataStartOffset = 0`):

```
Offset (within record)  Bytes (LE)                Field
----------------------  ------------------------  --------------------
+0                      00 01 00 00               BulkDataFlags = 0x00000100 (BULKDATA_PayloadInSeperateFile; routes to .ubulk)
+4                      00 01 00 00               ElementCount = 256 (i32 LE; uncompressed byte count)
+8                      00 01 00 00               SizeOnDisk = 256 (u32 LE; same as ElementCount when uncompressed)
+12                     00 00 00 00 00 00 00 00   OffsetInFile = 0 (i64 LE; offset within .ubulk; pre-fixup wire value)
+20                                                (end of header — payload bytes follow at OffsetInFile in .ubulk)
```

For inline / uexp-resident records, replace `BulkDataFlags` with
`0x00000001` (`BULKDATA_PayloadAtEndOfFile`) and set `OffsetInFile`
to an offset within the `.uasset` byte range; the tier-dispatch logic
above selects `.uasset` (when `OffsetInFile < total_header_size`) or
`.uexp` otherwise.

With `BULKDATA_Size64Bit` set (`BulkDataFlags |= 0x00002000`), the
header widens to 28 bytes: 4 (flags) + 8 (ElementCount i64) + 8
(SizeOnDisk u64) + 8 (OffsetInFile i64).

## Variants

### Size-format dispatch (`BULKDATA_Size64Bit`)

The single largest variant axis. When bit 13 is set, `ElementCount`
and `SizeOnDisk` both widen from 4 bytes to 8 bytes — total header
grows from 20 to 28 bytes (or larger with the conditional skip
regions). UE writers set this flag when the payload exceeds 4 GiB
or when the asset is built for a platform with 64-bit native sizes.

### Offset-format dispatch (`BULKDATA_AT_LARGE_OFFSETS`, UE 4.3+)

Pre-UE-4.3, `OffsetInFile` was 4 bytes (`i32`). Post-`BULKDATA_AT_LARGE_OFFSETS`
(UE 4.3+), it's 8 bytes (`i64`). Paksmith's pak v3+ range starts at
UE 4.4+, so paksmith always sees the 8-byte form — but the 4-byte
form is documented for spec completeness.

### Tier routing (`.uasset` vs `.uexp` vs `.ubulk` vs `.uptnl`)

Per §*Tier dispatch* above. Tier selection is a function of two
flag bits plus the offset-vs-total_header_size comparison. There are
four possible tiers; the four-way table is exhaustive.

### Skip-region presence

`BULKDATA_BadDataVersion` adds a 2-byte ushort skip. `BULKDATA_DuplicateNonOptionalPayload`
adds 12-20 bytes. Both are post-`OffsetInFile`. A reader unaware of
these flags loses cursor alignment on every record carrying them.

### Pre-baked metadata short-circuit (UE 5.0+)

When the parent archive carries a `BulkDataMap` (IoPackage) or
`DataResourceMap` (Package), the inline serial read is replaced by
a 4-byte `dataIndex` lookup. This is a separate variant of the
record's on-wire shape: 4 bytes total instead of 20.

## Caps & limits

### Format-defined limits (wire-imposed)

- **`BulkDataFlags`**: `u32` bitmask; bits 0-18 + 28-30 currently
  allocated. Bits 19-27 and 31 are wire-format-undefined.
- **`ElementCount`**: `i32` (max `i32::MAX` ≈ 2.1 billion) or `i64`
  (max `i64::MAX` ≈ 9.2 quintillion) gated on `BULKDATA_Size64Bit`.
- **`SizeOnDisk`**: `u32` (max `u32::MAX` ≈ 4 GiB) when
  `BULKDATA_Size64Bit` is unset; 8 bytes read as `i64` with the
  upper 32 bits discarded when set (per the reference
  implementation's `(uint) Ar.Read<long>()` cast — effective max
  remains ~4 GiB despite the wider read). Matches the wire-layout
  table treatment.
- **`OffsetInFile`**: `i32` (max `i32::MAX` ≈ 2.1 GiB) or `i64` (max
  `i64::MAX` ≈ 9.2 EiB) gated on `BULKDATA_AT_LARGE_OFFSETS`.
- **`DuplicateFlags`** (when present): `u32`.
- **`DuplicateSizeOnDisk`** and **`DuplicateOffset`** (when present):
  same widths as their non-duplicate counterparts.
- **`BadDataVersion` skip region** (when bit 15 set): fixed 2 bytes.

### Implementation hardening (recommended for any parser)

A `FByteBulkDataHeader` reader MUST:

- **Verify `i32` / `i64` count and size fields are non-negative**
  before any cast to `usize` or use as loop counter. `ElementCount`,
  `SizeOnDisk` (as signed only when widened), and `OffsetInFile`
  (always signed). A negative `i32 → usize` cast produces
  `usize::MAX`-adjacent values that bypass per-collection sanity
  checks.
- **Use `checked_add` on `OffsetInFile + BulkDataStartOffset`** when
  applying the fix-up (i.e., when `BULKDATA_NoOffsetFixUp` is unset).
  Both fields are attacker-influenced; an `OffsetInFile` near
  `i64::MAX` plus a positive `BulkDataStartOffset` overflows under
  naive addition.
- **Use `checked_add` on `resolved_offset + SizeOnDisk`** before any
  seek-window comparison against the parent file's byte count. A
  resolved offset near `i64::MAX` plus any nonzero `SizeOnDisk` wraps.
- **Cap `ElementCount` and `SizeOnDisk`** against
  `MAX_UNCOMPRESSED_ENTRY_BYTES` (8 GiB) before allocation. The
  fields are attacker-influenced; a maximum-value `u64` would blow
  the allocator before the file-residual-bytes backstop catches it.
- **Warn on unallocated `BulkDataFlags` bits** (bits 19-27, 31).
  Unknown bits propagate uninterpreted state into downstream
  consumers; bit 18 (`BULKDATA_LazyLoadable`) is allocated and MUST
  be accepted. Bit 31 was historically `BULKDATA_UsesIoDispatcher`
  (commented out in the reference implementation) — treat as
  reserved and warn rather than hard-reject so re-activation in
  future UE builds doesn't break paksmith.
- **Clear `BULKDATA_BadDataVersion` from the returned
  `BulkDataFlags` value** before handing the record to downstream
  consumers (matches the reference implementation: the constructor
  clears the bit after reading the 2-byte skip). Any downstream
  consumer that re-checks `HasFlag(BadDataVersion)` post-
  construction must observe `false`. A reader that preserves the
  raw wire value would let attacker-influenced state propagate
  through the rest of the parse.
- **Bounds-check the `BULKDATA_DuplicateNonOptionalPayload` skip
  region** against the remaining archive bytes before each of the
  three field reads. The total skip is one of three distinct
  values — 12 bytes (neither gate), 16 bytes (exactly one of
  `BULKDATA_Size64Bit` or `BULKDATA_AT_LARGE_OFFSETS` set; both
  combinations sum to 16), or 20 bytes (both gates set). An
  attacker-crafted record near EOF could otherwise drive a read
  past the archive end.
- **Validate tier-dispatch consistency**: a record with
  `BULKDATA_OptionalPayload` set MUST also have
  `BULKDATA_PayloadInSeperateFile` set (the routing combination
  documented above). Any flag combination outside the four-way
  tier-dispatch table — including `BULKDATA_PayloadAtEndOfFile` +
  `BULKDATA_PayloadInSeperateFile` set simultaneously — MUST be
  rejected with a typed error rather than warned-and-accepted. A
  miss-dispatched payload could be sourced from the wrong file at
  an indeterminate offset, which is a memory-safety hazard
  attacker-controllable via the flag bits.
- **Reject mis-aligned encrypted regions** when the payload tier
  carries encrypted blocks (per the parent format's encryption
  conventions; see [`../crypto/aes-pak.md`](../crypto/aes-pak.md)).
- **For `BULKDATA_SerializeCompressedZLIB` payloads**: bound the
  decompressed output at `MAX_UNCOMPRESSED_ENTRY_BYTES`; the
  `ElementCount` field publishes the expected decompressed size
  (verify post-decompress matches).
- **For `BULKDATA_OptionalPayload + BULKDATA_PayloadInSeperateFile`**:
  surface `MissingCompanionFile { kind: Uptnl }` or similar when
  `.uptnl` is absent. Paksmith's current `CompanionFileKind` enum
  defines `Uexp` and `Ubulk` only; a `Uptnl` variant is expected
  when `.uptnl` support is implemented (no specific phase claim).
  Silent zero-length substitution masks data-integrity loss
  (matches [`../container/iostore-uptnl.md`](../container/iostore-uptnl.md)
  §*Implementation hardening*).
- **For the alternate read paths** (UE 5.0+ pre-baked metadata
  tables): when the constructor short-circuits to a 4-byte
  `dataIndex: i32` lookup, MUST validate `0 <= dataIndex <
  BulkDataMap.Length` (or `DataResourceMap.Length`) before using
  as an array index. A negative `dataIndex` or one past the table
  length is an OOB read on the lookup.

See `docs/security/allocation-caps.md` for the broader policy.

## Verification

- **Fixture:** The 20-byte minimal-header Worked example above is
  byte-exact and self-contained. Real-cooked `FByteBulkData` records
  appear in every texture / mesh / audio / animation export; Phase 3
  fixtures will exercise the multi-tier dispatch end-to-end.
- **Hex anchor commands:**
  ```
  # Synthesize the 20-byte minimal FByteBulkDataHeader from the
  # Worked example (.ubulk-routed, 256-byte payload, OffsetInFile=0):
  printf '\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' | xxd
  ```
  A conformant `FByteBulkData` parser fed these 20 bytes MUST
  decode them as a single-payload record routed to `.ubulk` with
  `ElementCount = SizeOnDisk = 256` bytes and `OffsetInFile = 0`.
- **Cross-validation oracle:** CUE4Parse[^1] — the
  `FByteBulkDataHeader` constructor row-for-row in §*Wire layout*
  above. `EBulkDataFlags` enum verified against
  `CUE4Parse/UE4/Assets/Objects/EBulkDataFlags.cs` at the same SHA.
- **Known divergences:** none — no paksmith implementation to
  diverge.

## Paksmith implementation

**Parser module:** *(not yet implemented — planned under
`crates/paksmith-core/src/asset/bulk_data.rs`)*

**Status:** `partial`. Companion-file detection ships (Phase 2e
PR #317 — sibling lookups for `.uexp` / `.ubulk` / `.uptnl`); the
`FByteBulkData` record reader itself is not yet implemented.
Texture / mesh / audio / animation exports today fall through to
`PropertyBag::Opaque` when their `FByteBulkData` records are
reached (per the Phase 3+ fallthrough behavior documented in each
export-type doc).

**Phase plan:** `docs/plans/ROADMAP.md` Phase 2f (bulk-data
stitching) + Phase 3+ (per-format consumer wiring). The record
reader lands first; per-format consumer hookups (texture mips,
audio chunks, animation keyframes) follow.

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Objects/FByteBulkDataHeader.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` (primary oracle for the header constructor) and `EBulkDataFlags.cs` in the same directory (full flag catalog). `FByteBulkData.cs` in the same directory covers the wrapping payload-read logic (zlib decompression, bulk-archive resolution); the per-record header layout above is sourced from `FByteBulkDataHeader.cs`.
