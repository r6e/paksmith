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

**Paksmith parser status: `complete`.** The `FByteBulkData` record
reader (`FByteBulkData::read_from` in
`crates/paksmith-core/src/asset/bulk_data.rs`) parses the full wire
shape including flag validation, `Size64Bit` field widening,
`BadDataVersion` 2-byte tail discard, and
`DuplicateNonOptionalPayload` block skip, with caps enforced inline.
The `BulkDataResolver` (same module) materializes payload bytes across
all four tiers (inline / uexp-resident / `.ubulk` / `.uptnl`) —
applying the offset fix-up, the per-package byte budget, and the
chunked `FCompressedChunkInfo` zlib decompression described under
*Payload decompression* below
([#644](https://github.com/r6e/paksmith/issues/644)) — and the
Phase 3 format handlers consume the resolved bytes.

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
| 3 | `SizeOnDisk` | 4 or 8 | LE | `u32` / `u64` | Bytes occupied by the on-wire payload (post-compression if applicable). With `BULKDATA_Size64Bit` unset: 4 bytes `u32`. With set: 8 bytes read as `u64`. **Reference deviation:** CUE4Parse's reference implementation reads 8 bytes signed and truncates to the low 32 bits (`(uint) Ar.Read<long>()`), effectively capping `SizeOnDisk` at ~4 GiB. Paksmith reads the full `u64` and relies on `MAX_BULK_DATA_SIZE` (8 GiB) — and `MAX_BULK_DATA_COMPRESSED_SIZE` (512 MiB) for compressed records — to cap pathological values. The paksmith policy is strictly safer than the reference truncation: a wire value like `0x0000_0001_0000_0000` (4 GiB + 0) is interpreted as `4_294_967_296` by paksmith (caught by the 8 GiB cap on a per-record basis, or by the resolver's per-package budget) instead of silently truncated to `0` bytes. Legitimate cooked content has `SizeOnDisk` well under 4 GiB so behavior matches the reference on valid input. |
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
unallocated in CUE4Parse's reference implementation; reference
parsers SHOULD warn on records with these bits set. Bit 31 was
historically `BULKDATA_UsesIoDispatcher` (now commented-out in
`EBulkDataFlags.cs`); the reference treats it as reserved and warns
rather than hard-rejecting, to avoid breaking content from UE
builds that re-activate the slot.

**Paksmith deviation:** paksmith's `BulkDataFlags::validate()`
hard-rejects bits 19-27 and bit 31 via
`AssetParseFault::UnknownBulkDataFlags`. The deliberate stricter
policy mirrors the `SizeOnDisk` deviation above: paksmith's
security-conscious parser fails loud on unknown bits rather than
warning-and-continuing, since cooked content from real engines
never sets reserved bits and any record with them set is a
crafted-input / wire-corruption signal. If a future UE build
re-activates bit 31 (or any other reserved bit), paksmith's
`VALID_FLAG_MASK` constant + bit catalog get updated in one PR.

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

When `BULKDATA_SerializeCompressedZLIB` is set, the on-disk payload is
zlib-compressed. In the engine this routes through
`FArchive::SerializeCompressed`, which writes the **chunked
`FCompressedChunkInfo` framing**. Each `FCompressedChunkInfo` is two
little-endian `i64`s (`CompressedSize`, `UncompressedSize`; the
pre-UE4 `u32` layout is below paksmith's version floor). The layout:

1. **Tag record** — `CompressedSize` carries the magic:
   `PACKAGE_FILE_TAG` (`0x9E2A83C1`, v1) or `ARCHIVE_V2_HEADER_TAG`
   (`0x22222222_9E2A83C1` — `PACKAGE_FILE_TAG` in the low 32 bits,
   v2). `UncompressedSize` carries the compression chunk size, with a
   legacy quirk: the value `PACKAGE_FILE_TAG` here is a sentinel
   meaning `LOADING_COMPRESSION_CHUNK_SIZE` (131072 = 128 KiB).
   Byte-swapped tag forms mark big-endian producers.
2. **v2 only: compression-format byte** — `0` = inline FString-named
   format, `1` = None, `2` = Oodle, `3` = Zlib, `4` = Gzip, `5` = LZ4.
   The v1 header has no format field; readers decode v1 payloads with
   the caller's legacy format (Zlib for `FByteBulkData`).
3. **Summary record** — total compressed / total uncompressed sizes.
4. **Chunk table** — `ceil(total_uncompressed / chunk_size)` records;
   the per-field sums MUST equal the summary totals.
5. **Chunk streams** — one independent zlib stream per table entry,
   back to back; each decompresses to exactly its entry's
   `UncompressedSize`, concatenated in order.

This is a **distinct framing** from both the pak per-block
`FPakCompressedBlock` path (see
[`../compression/zlib.md`](../compression/zlib.md)) and a single raw
zlib stream. The total decompressed size is `ElementCount` bytes (for
byte bulk data); a reader MUST bound its work by the real input
length before trusting any wire-claimed size (decompression-bomb /
allocation-amplification guard). Layout verified against the
CUE4Parse reference (`FByteBulkData.cs` →
`FArchive.SerializeCompressedNew`, `Compression.cs`) and
cross-anchored against independent community decoders
(Remnant-2-Save-Parser, revision-go).[^2]

**Paksmith implementation** (`decompress_zlib` in
`asset/bulk_data.rs`, [#644](https://github.com/r6e/paksmith/issues/644));
deviations are all fail-closed:

- **Pre-parse claim cap**: `ElementCount` (the decompressed-size
  claim) is capped at `MAX_BULK_DATA_SIZE` (8 GiB) before any
  framing parse — the per-record transient-output ceiling,
  independent of the resolver's 16 GiB per-package budget.
- **Little-endian only**: the byte-swapped tag forms
  (`PACKAGE_FILE_TAG_SWAPPED`, 64-bit-swapped v1/v2 tags) are
  recognized and rejected, not swap-decoded — consistent with the
  parser-wide LE policy.
- **Zlib only**: v2 named formats (None/Oodle/Gzip/LZ4) surface
  `UnsupportedBulkCompression`; a v2 inline-FString format name is
  rejected without parsing the string (no known bulk-data producer).
- **Exact totals**: the summary's uncompressed total must equal
  `ElementCount` exactly (the reference decoder tolerates `<=`; the
  engine writer always emits `==`, so a mismatch is treated as
  corruption), chunk-table sums must equal the summary, each chunk
  must inflate to exactly its claimed size, and the framing must
  consume the record's `SizeOnDisk` region exactly (no trailing
  bytes).
- **Bounded allocation**: the chunk table's byte size is validated
  against the real remaining input before it is walked, the table
  is validated and consumed in place (never copied into an owned
  buffer), and the output buffer is pre-sized from the compressed
  input length (never from wire claims), growing only as real bytes
  are produced — each chunk's read is capped at its claimed size + 1
  so an over-long stream is detected rather than inflated.
- A **zero-size record** carries no framing at all (the engine
  early-outs before writing the header); empty input with
  `ElementCount = 0` decodes to an empty payload.

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
  `BULKDATA_Size64Bit` is unset; 8 bytes read as `u64` when set
  (paksmith deviates from the CUE4Parse reference truncation —
  see the wire-layout table's `SizeOnDisk` row). Effective bound
  for paksmith is `MAX_BULK_DATA_SIZE` (8 GiB) per-record and
  `MAX_TOTAL_BULK_DATA_BYTES_PER_PACKAGE` (16 GiB) cumulatively.
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
  `MAX_BULK_DATA_SIZE` (8 GiB; declared in
  `crates/paksmith-core/src/asset/bulk_data.rs`) before allocation.
  For compressed records the tighter `MAX_BULK_DATA_COMPRESSED_SIZE`
  (512 MiB) cap fires first. The fields are attacker-influenced; a
  maximum-value `u64` would blow the allocator before the
  file-residual-bytes backstop catches it. `MAX_BULK_DATA_SIZE`
  shares the 8 GiB value with `container::pak::MAX_UNCOMPRESSED_ENTRY_BYTES`
  by convention — bulk-data records share the per-entry decompressed
  ceiling — but the two constants are independent (visibility +
  module ownership).
- **Reject (paksmith) or warn (reference) on unallocated
  `BulkDataFlags` bits** (bits 19-27, 31). Unknown bits propagate
  uninterpreted state into downstream consumers; bit 18
  (`BULKDATA_LazyLoadable`) is allocated and MUST be accepted. Bit
  31 was historically `BULKDATA_UsesIoDispatcher` (commented out in
  the reference implementation). The reference treats it as
  reserved and warns rather than hard-rejecting. **Paksmith's
  `BulkDataFlags::validate()` hard-rejects** via
  `AssetParseFault::UnknownBulkDataFlags` — see "Paksmith deviation"
  on bit 31 in §`BulkDataFlags` bit catalog above.
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
  decompressed output at `MAX_BULK_DATA_SIZE` (paksmith enforces
  this on the `ElementCount` claim before parsing the chunk
  framing); the `ElementCount` field publishes the expected
  decompressed size (verify the framing totals match).
- **For `BULKDATA_OptionalPayload + BULKDATA_PayloadInSeperateFile`**:
  surface `MissingCompanionFile { kind: Uptnl }` when `.uptnl` is
  absent. Paksmith's `CompanionFileKind` enum defines all three
  variants (`Uexp`, `Ubulk`, `Uptnl`), and the resolver routes the
  optional-payload tier accordingly. Silent zero-length substitution
  masks data-integrity loss
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
- **Known divergences:**
  1. **`SizeOnDisk` widening under `Size64Bit`:** paksmith reads
     the full `u64` (no upper-bit truncation). CUE4Parse uses
     `(uint) Ar.Read<long>()` to truncate to the low 32 bits.
     Paksmith's policy is strictly safer — attacker-controlled
     upper bits surface via `MAX_BULK_DATA_SIZE` (8 GiB) instead
     of silently masking. See the wire-layout `SizeOnDisk` row.
  2. **Reserved-bit hard-reject:** paksmith's `validate()` rejects
     bits 19-27 and 31; the reference warns. See "Paksmith
     deviation" in the `BulkDataFlags` bit catalog and the
     hardening checklist above.

## Paksmith implementation

**Parser module:** `crates/paksmith-core/src/asset/bulk_data.rs`
ships in Phase 3b Task 3:

- `FByteBulkData::read_from(reader, asset_path) -> Result<Self>`
  parses one wire record, enforcing the full cap chain inline
  (`UnknownBulkDataFlags`, `BulkDataElementCountNegative`,
  `BulkDataCompressedSizeExceeded`, `BulkDataSizeExceeded`).
- `BulkDataFlags::validate()` rejects reserved bits.
- `BulkDataFlags::is_any_compressed()` returns true if any
  compression flag (`zlib | lzo | bitwindow`) is set.
- `FByteBulkData` is `#[non_exhaustive]` — fields-bearing
  construction routes through `read_from` only.

**Status:** `complete`. The record reader, the `BulkDataResolver`
(tier dispatch + offset fix-up + chunked-`FCompressedChunkInfo` zlib
decompression + per-package byte budget), and the
`Package::read_from_pak` integration all ship, and the Phase 3 typed
export readers (texture mips: 3e; static mesh: 3g; skeletal mesh: 3h;
audio: 3f) consume the resolved bytes. The chunked zlib framing under
*Payload decompression* shipped with
[#644](https://github.com/r6e/paksmith/issues/644); the remaining
compression follow-ups are LZO/BitWindow
([#559](https://github.com/r6e/paksmith/issues/559)).

**Phase plan:** `docs/plans/ROADMAP.md` Phase 3 + the per-task
plans in `docs/plans/phase-3b-bulk-data-resolver.md`.

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Objects/FByteBulkDataHeader.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` (primary oracle for the header constructor) and `EBulkDataFlags.cs` in the same directory (full flag catalog). `FByteBulkData.cs` in the same directory covers the wrapping payload-read logic (zlib decompression, bulk-archive resolution); the per-record header layout above is sourced from `FByteBulkDataHeader.cs`.

[^2]: Chunked-framing layout (primary oracle): `FabianFG/CUE4Parse/CUE4Parse/UE4/Readers/FArchive.cs` (`SerializeCompressedNew`) and `CUE4Parse/Compression/Compression.cs` (`LOADING_COMPRESSION_CHUNK_SIZE`). Independent cross-anchors: `Brabb3l/Remnant-2-Save-Parser` `src/sav.rs` (`ARCHIVE_V2_HEADER_TAG`, Rust) and `t1nky/revision-go` `remnant/save_file.go` (tag constants + chunk size, Go).
