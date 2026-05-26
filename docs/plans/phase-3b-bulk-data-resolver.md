# Paksmith Phase 3b: FByteBulkData byte access + BulkDataResolver

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Cargo exit-code caveat:** Every cargo command piped through `tail`, `head`, or `grep` in this plan returns `0` even when cargo failed. After running any cargo gate, re-run unpiped, set `set -o pipefail`, or inspect `${PIPESTATUS[0]}`.

**Goal:** Replace Phase 2e's `.ubulk`-detection-only warn (currently at `package.rs:654-672`) with a real `BulkDataResolver` that materializes payload bytes across **all four storage tiers**: inline (`.uasset`), uexp-resident (`.uexp`), streaming (`.ubulk`), and optional-streaming (`.uptnl`). Texture mip and audio buffer storage uses uexp-resident frequently — a resolver that only handles `.ubulk` would not unblock 3e/3f/3g/3h. `.uptnl` is the optional-streaming variant gated by `BULKDATA_OptionalPayload`; commonly used for IoStore-cooked optional mip data in shipping games.

**Architecture:** Three new types + one extended:

- `FByteBulkData` — the per-record metadata on the wire (lives inside `.uasset` exports). Fields: `BulkDataFlags: u32`, `ElementCount: i32 | i64`, `SizeOnDisk: u32 | u64`, `OffsetInFile: i32 | i64`, plus the `BULKDATA_DuplicateNonOptionalPayload` and `BULKDATA_BadDataVersion` wire-side-effect blocks.
- `BulkDataFlags` — `u32` bitfield wrapper with named accessors per the catalog at `docs/formats/texture/mips-and-streaming.md`.
- `BulkDataResolver` — given a `PakReader` (or other `ContainerReader`), a parent asset path, the stitched `.uasset`+`.uexp` bytes, and the package summary's `BulkDataStartOffset`, materializes the bytes for a given `FByteBulkData` record into a `BulkData { bytes: Vec<u8>, flags: BulkDataFlags, source_tier: BulkDataTier }`.
- `BulkData` — replaces 3a's placeholder type with real fields.

The resolver dispatches on `BulkDataFlags`:

| Flag combination | Tier | Source bytes |
|------------------|------|--------------|
| `BULKDATA_PayloadAtEndOfFile` + offset < total_header_size | Inline | `.uasset` body, post-fixup offset = `OffsetInFile + BulkDataStartOffset` |
| `BULKDATA_PayloadAtEndOfFile` + offset ≥ total_header_size | uexp-resident | `.uexp` body, same fixup |
| `BULKDATA_PayloadInSeperateFile` (no `BULKDATA_OptionalPayload`) | Streaming | `.ubulk` body, offset is absolute (no fixup) |
| `BULKDATA_OptionalPayload` + `BULKDATA_PayloadInSeperateFile` | OptionalStreaming | `.uptnl` body, offset is absolute (no fixup) |

`BULKDATA_SerializeCompressedZLIB` records are decompressed via the existing pak-layer zlib path; Oodle-compressed bulk data is rejected with `UnsupportedBulkCompression` (lands when Phase 8's IoStore Oodle integration ships).

**Tech Stack:** Same as Phase 2g. No new workspace dependencies (reuses `flate2`).

---

## Scope vs deferred work

**In scope:**

- `FByteBulkData::read_from(reader, ctx)` — full wire-shape parse including the `BULKDATA_Size64Bit` field-width gating, `BULKDATA_AT_LARGE_OFFSETS` offset-width gating (paksmith's UE 4.4+ floor → always 8-byte offset), `BULKDATA_DuplicateNonOptionalPayload` side-effect block, `BULKDATA_BadDataVersion` 2-byte ushort discard.
- `BulkDataFlags` named-bit catalog covering bits 0–18, 28–30 per the wire-format reference. Unknown bits in the reserved range (19–27, 31) get rejected with `UnknownBulkDataFlags { bits }`.
- `BulkDataResolver` dispatching across **all four tiers**: inline / uexp-resident / `.ubulk` / `.uptnl` with offset-fixup (`BulkDataStartOffset`) handling. Uses `checked_add` on every offset+size arithmetic site. Both `.ubulk` and `.uptnl` are lazy-loaded on first access (separate caches).
- Zlib decompression path for `BULKDATA_SerializeCompressedZLIB`. Reuses the pak-layer's decompressor.
- `Package::read_from_pak` integration: when an export's exported asset has bulk data, the resolver fetches the bytes; results stored in a new `Package::bulk_data: Vec<BulkData>` field keyed by export index (or `None` per export when that export has no bulk data).
- 4 new cap constants:
  - `MAX_BULK_DATA_SIZE = 8 * 1024 * 1024 * 1024` (8 GiB; matches `MAX_UNCOMPRESSED_ENTRY_BYTES`).
  - `MAX_UBULK_FILE_SIZE = 16 * 1024 * 1024 * 1024` (16 GiB; bounds the seek window into `.ubulk`). Same cap applies to `.uptnl` via the `MAX_UPTNL_FILE_SIZE` alias of the same value (no separate constant needed; the resolver reuses the limit).
  - `MAX_BULK_DATA_RECORDS_PER_EXPORT = 256` — **enforced at the 3e/3g/3h typed-reader sites** (where records are read mid-parse), NOT at the resolver. 3b only defines the cap; 3e/3g/3h's plans pin the per-export counter + fire site. See "Cap enforcement contract" below.
  - `MAX_TOTAL_BULK_DATA_BYTES_PER_PACKAGE = 16 * 1024 * 1024 * 1024` (16 GiB; global accumulator across all resolved records in a single `Package::resolve_bulk_data` call — defense against the OOM surface where N exports × 256 records × 8 GiB could drive unbounded heap commitment).
  - Each cap exposes a `#[cfg(feature = "__test_utils")]` accessor per CLAUDE.md convention.

**Cap enforcement contract:**

- `MAX_BULK_DATA_SIZE` — enforced inside `FByteBulkData::read_from` (3b Task 3) on every record's `SizeOnDisk` field.
- `MAX_UBULK_FILE_SIZE` / `MAX_UPTNL_FILE_SIZE` — enforced inside the resolver's lazy-load closures (3b Task 5/6) on companion-file size before any seek.
- `MAX_BULK_DATA_RECORDS_PER_EXPORT` — enforced at typed-reader sites (3e/3g/3h) where records are read mid-parse via a per-export counter pattern. Each typed-reader plan pins the check site in its TDD steps. 3b ships the cap and error variant; if a downstream sub-phase forgets to enforce, the cap is dead — `feedback_specialist_reviewers_default.md` requires the security pass to check this when 3e/3g/3h enter review.
- `MAX_TOTAL_BULK_DATA_BYTES_PER_PACKAGE` — enforced inside the resolver via a `bytes_resolved_so_far: u64` accumulator on the resolver struct, incremented after every successful `resolve()`. Fires `BulkDataPackageBudgetExceeded { resolved, cap }`.
- New `AssetParseFault` variants (12 total — original 10 plus `BulkDataConflictingTierFlags` and `BulkDataCompressedSizeExceeded` added during R1 security review):
  - `BulkDataOffsetOob { tier, offset, size, file_size }` — resolved offset+size overruns the source file.
  - `BulkDataOffsetFixupOverflow { offset, fixup }` — `OffsetInFile + BulkDataStartOffset` overflows during the offset fix-up step.
  - `BulkDataEndOffsetOverflow { offset, size }` — `resolved_offset + size_on_disk` overflows when computing the end-of-payload position.
  - `BulkDataSizeExceeded { size, cap }` — `SizeOnDisk` > `MAX_BULK_DATA_SIZE`.
  - `BulkDataRecordsExceeded { count, cap }` — export has more `FByteBulkData` records than `MAX_BULK_DATA_RECORDS_PER_EXPORT`.
  - `BulkDataPackageBudgetExceeded { resolved, cap }` — cumulative resolved bytes exceed `MAX_TOTAL_BULK_DATA_BYTES_PER_PACKAGE` (global budget across all records in one Package).
  - `BulkDataNoTierFlag { flags }` — `BulkDataFlags` is valid (all bits in the catalog) but has none of the four tier-routing bits set (no `PayloadAtEndOfFile`, no `PayloadInSeperateFile`). Distinguishes from `UnknownBulkDataFlags` (which is "reserved bits set").
  - `BulkDataElementCountNegative { count }` — `ElementCount` is `i32`/`i64` signed; negative values are wire-corruption-or-attack indicators that must reject before any consumer treats the count as a buffer length.
  - `BulkDataDecompressLengthMismatch { expected, actual }` — `BULKDATA_SerializeCompressedZLIB` payload decompressed to a different byte count than `ElementCount` claims. Surfaces truncated / over-long compressed streams.
  - `UnknownBulkDataFlags { bits }` — `BulkDataFlags` carries bits outside the documented catalog (bits 19-27 or bit 31).
  - `UnsupportedBulkCompression { method }` — `BULKDATA_SerializeCompressedLZO`, `BULKDATA_SerializeCompressedBitWindow`, or Oodle (the latter routes to Phase 8's SDK loader).
  - Each variant has a hand-rolled `Display` arm + a pin-table test (mirror Phase 2g Task 1's pattern).
  - **NOT** `UnsupportedOptionalPayload` — `.uptnl` is now in-scope; per-tier `MissingCompanionFile { kind: Uptnl }` covers the "record points at .uptnl but the file isn't in the pak" case.
- 12 in-source unit tests covering: each tier dispatch, offset fixup, zlib decompression, `BULKDATA_Size64Bit` field widening, `BULKDATA_DuplicateNonOptionalPayload` side-effect skip, `BULKDATA_BadDataVersion` 2-byte discard, every new cap-rejection path, every new error variant Display.
- 5 integration tests in `paksmith-core-tests` (or new file `bulk_data_integration.rs`): real `.pak` fixtures exercising inline / uexp-resident / streaming / optional-streaming tiers with hand-built `FByteBulkData` records.
- 1 fixture-gen extension: `paksmith-fixture-gen` gains `build_minimal_uasset_with_bulk_data(tier: BulkDataTier)` producing a synthetic `.uasset` + `.uexp` (+`.ubulk` when needed) with a known bulk-data record. Cross-validate against CUE4Parse (the only oracle for FByteBulkData per the format docs — `unreal_asset` doesn't expose bulk reads).

**Deferred to NAMED later phases (per master-index deferral policy):**

- **Oodle-compressed bulk data.** → **Phase 8.** Returns `UnsupportedBulkCompression { method: "Oodle" }`; Phase 8's IoStore Oodle integration ships the runtime-loaded SDK + plugs into the same `BulkDataResolver` compression-dispatch arm.
- **LZO + BitWindow bulk compression.** Rare in cooked content per the format docs; returns `UnsupportedBulkCompression { method: "LZO" }` / `{ method: "BitWindow" }`. Phase 3 follow-up issue tracks each — when a real-world fixture surfaces, decoders land directly in this resolver's dispatch arm (no new sub-phase needed).
- **`pub` API for `BulkData` and `Package::bulk_data`.** → **Phase 4.** Today the type is `pub` from `paksmith_core::export` (the trait signature in 3a requires it), but `Package::bulk_data` is `pub(crate)`. Phase 3e/3g/3h consume it through `Package::export_bulk_data(export_index)` accessor (also `pub(crate)`). Phase 4 promotes to `pub` when `paksmith extract` lands.
- **Memory-mapped reads (`BULKDATA_MemoryMappedPayload`, `BULKDATA_DataIsMemoryMapped`).** → **Phase 4 performance pass.** Phase 3b reads into `Vec<u8>` unconditionally; mmap optimization lands alongside `paksmith extract`'s bulk-extraction flow where memory pressure first becomes measurable.
- **Async lazy-loadable resolution (`BULKDATA_LazyLoadable`).** → **Phase 5.** Phase 3b's resolver is synchronous and eager; lazy loading lands with async runtime introduction per ROADMAP §Phase 5.

---

## Design decisions locked here

1. **`BulkData::bytes` is owned `Vec<u8>`, not borrowed.** Per master-index Design Decision #6: borrowing would force lifetime-parameter contamination across the export pipeline. One allocation per resolved record; acceptable.

2. **`BulkDataResolver` is stateful — it owns the `PakReader` reference, the parent asset path, and the `BulkDataStartOffset`.** Not a free function. Construction: `BulkDataResolver::new(reader, parent_path, summary)`. Each `resolve(&self, record: &FByteBulkData)` call dispatches by tier and returns `Result<BulkData>`. The resolver caches the `.ubulk` bytes (if loaded) so multiple records in the same export don't trigger repeated `read_entry` calls.

3. **Streaming / OptionalStreaming-tier reads load the whole companion file into a cached `Vec<u8>` on first access.** For inline / uexp-resident tiers the resolver already owns the stitched `.uasset+.uexp` buffer via `Arc<[u8]>`, so byte extraction is a slice. For streaming / optional-streaming tiers, the loader closure calls `reader.read_entry(&path)` returning a `Vec<u8>` of the whole companion file (e.g. the whole `.ubulk`), cached in the resolver's `OnceLock<Vec<u8>>`. Subsequent records on the same companion slice through the cached vec — one I/O + allocation per companion file per Package lifetime.

   **Trade-off accepted:** one whole-file read instead of seeking + reading only the wanted byte range. The R1 design speculated about a `read_entry_to(&mut dyn Write)` per-record fast path; on review the heuristic ("cache after second hit, not first") was complex without profiling evidence that the win was real. The simpler design here (cache-on-first-access) is correct for the common case (a single .ubulk → many mips → all bytes eventually consumed). If profiling later shows ".ubulk has many MBs unused per Package open" becomes load-bearing, revisit then.

   The whole-file load is bounded by `MAX_UBULK_FILE_SIZE = 16 GiB` (pak-layer's existing cap on companion read). The lazy-resolution Design Decision #5 already mitigates the worst case — `paksmith inspect` never triggers the resolver at all, so streaming companions never load during property-tree workflows.

4. **`Package::bulk_data_cache: HashMap<usize, OnceLock<Vec<BulkData>>>` keyed by export index.** Sparse: a package with 100k exports where only 3 carry bulk data uses 3 HashMap entries, not 100k preallocated empty Vecs (saves ~2.4 MB on large packages per the architect-panel finding). Each entry is a `OnceLock` because `resolve_bulk_for_export` may be called concurrently (Phase 5 async eventually); the cache is filled exactly once per export. Records (`Vec<FByteBulkData>` metadata) live alongside in a parallel `HashMap<usize, Vec<FByteBulkData>>` populated during initial parse.

5. **The resolver is LAZY.** `Package::read_from_pak` constructs and stores the `BulkDataResolver` but does NOT call `resolve()` on any record. Bulk-data materialization happens only when a downstream consumer explicitly asks via `Package::resolve_bulk_for_export(export_idx) -> &[BulkData]`. Rationale: `paksmith inspect` (the dominant Phase 2/3 workflow) and the GUI tree-view (Phase 6/7) never touch bulk data; eager resolution would allocate hundreds of MB per package open for workloads that never use it. The lazy design also eliminates the OOM-at-open surface where a crafted package claiming many large records would force the parser to allocate all of them before any decision logic ran.

   **API shape:**

   - `Package::read_from_pak(path) -> Self` — constructs the package + resolver; no bulk-data I/O.
   - `Package::resolve_bulk_for_export(&self, export_idx) -> crate::Result<&[BulkData]>` — on first call, walks the export's records (parsed during initial read) and resolves each; caches the result in a `OnceLock<Vec<BulkData>>` per export. Subsequent calls return the cached slice.
   - 3e/3g/3h's typed readers call `resolve_bulk_for_export` only when they actually need mip bytes / vertex bytes / chunk bytes — typically inside the format-handler `export()` path, not the parse-time path.

   The records themselves (`Vec<FByteBulkData>` metadata) ARE parsed eagerly during initial package read — they're tiny (32-48 bytes per record) and feed parser correctness checks even when bytes aren't materialized.

6. **`FByteBulkData::read_from` does NOT consume payload bytes.** It only reads the wire-format record (flags + counts + offset). Payload-byte materialization is the resolver's job. This separation keeps the wire reader testable in isolation against hand-built record bytes.

7. **Offset fix-up is conditional on `BULKDATA_NoOffsetFixUp` (bit 16).** Per the format doc: when NOT set, resolved offset = `OffsetInFile + BulkDataStartOffset`. When set, resolved offset = `OffsetInFile` directly. Uses `i64::checked_add`; overflow → `BulkDataOffsetOverflow`.

8. **The tier disambiguation between inline and uexp-resident is by offset comparison against `summary.total_header_size`.** Per `mips-and-streaming.md` §Tier dispatch: both inline and uexp-resident use `BULKDATA_PayloadAtEndOfFile`; the resolved offset falling in `[0, total_header_size)` vs `[total_header_size, ...)` distinguishes them. The resolver picks the source slice accordingly: `bytes[0..total_header_size]` for inline (`.uasset`), `bytes[total_header_size..]` (or the separate `.uexp` buffer pre-stitch) for uexp-resident.

9. **`BulkDataTier` is a `pub` enum** so 3e/3f/3g/3h can branch on it for diagnostic output:

   ```rust
   #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
   pub enum BulkDataTier {
       Inline,
       UexpResident,
       Streaming,         // .ubulk
       OptionalStreaming, // .uptnl
   }
   ```

10. **`.uptnl` lazy load mirrors `.ubulk` exactly.** The resolver carries TWO `OnceLock<Vec<u8>>` caches, one per file. `.uptnl` opens only on first `BulkDataTier::OptionalStreaming` resolution. Absence of `.uptnl` when a record claims OptionalStreaming → `MissingCompanionFile { kind: Uptnl }` (the existing `CompanionFileKind::Uptnl` variant in `error.rs`, if absent add it).

11. **`BULKDATA_DuplicateNonOptionalPayload` reads-and-discards the extra fields.** The duplicate payload at the alternate offset is a redundancy mechanism; we read the primary record's payload and skip the duplicate's offset+size+flags. The skip happens during `FByteBulkData::read_from`, not at resolve time. Total skip is **12 bytes (no Size64Bit) or 16 bytes (with Size64Bit)** — paksmith's UE 4.4+ floor always has `BULKDATA_AT_LARGE_OFFSETS` set per `mips-and-streaming.md:80`, so `DuplicateOffset` is always 8 bytes. The format doc's broader "12 / 16 / 16 / 20" matrix covers pre-4.3 content that paksmith doesn't accept.

12. **`BULKDATA_BadDataVersion` (bit 15) discards 2 trailing bytes after the main `OffsetInFile`.** Per the format doc. The flag is cleared after reading so downstream consumers don't see it set.

13. **`BulkDataResolver` is `Send + Sync`.** The loader closures are bounded `Fn() -> Result<Vec<u8>> + Send + Sync + 'static`. The byte-budget accumulator uses `AtomicU64` with `Ordering::Relaxed` (the counter has no happens-before relationship to other memory; SeqCst's barriers were wasted — zero cost on x86, ~5-10ns on ARM64). This makes `Package` (which owns the resolver) safely Send-able across thread boundaries — required for Phase 5 (async runtime), Phase 7 (Iced GUI Commands moving Package between threads), and any future GUI workflow that off-loads bulk resolution to a worker pool. The Relaxed ordering still preserves the cap invariant: every successful resolve observes its own `now` ≤ cap in the monotonically-increasing successful-claim sequence; rollbacks decrement only against unsuccessful claims, never below the consistent successful total.

14. **`MAX_TOTAL_BULK_DATA_BYTES_PER_PACKAGE` enforcement runs BEFORE allocation, not after** — `bytes_resolved.fetch_add(claimed_size, Relaxed)` is called against the wire record's CLAIMED size (`record.size_on_disk` for uncompressed; `record.element_count` for zlib-compressed — both already cap-checked in `FByteBulkData::read_from`) BEFORE `decompress_zlib` or `raw.to_vec()` allocates the actual buffer. If the budget check rejects, no allocation has happened — peak heap stays within the 16 GiB ceiling the cap advertises. On decompression failure (e.g. corrupt zlib stream), the budget reserve is rolled back via `fetch_sub` so subsequent resolves see consistent state.

    **No tracing events or other side effects between `fetch_add` and either rollback OR successful return.** Side effects in that critical section would not be undone on rollback. The resolver currently performs only the budget arithmetic + the materialization in that window; future contributors MUST preserve this discipline.

    Resolver-level enforcement (not typed-reader-level) means 3e/3g/3h don't need to track running totals; they just call `resolve()` and propagate errors.

15. **`MAX_BULK_DATA_RECORDS_PER_EXPORT` enforced defensively at the records-insertion boundary**, NOT only at typed-reader sites. The R1 design routed enforcement entirely through 3e/3g/3h's typed readers; the security R2 review pointed out that ANY future class with bulk data (e.g. `GenericGameClass`) bypasses that path. Fix: `Package::insert_bulk_records(idx, records)` (the single insertion point) validates `records.len() <= MAX_BULK_DATA_RECORDS_PER_EXPORT` and fires `BulkDataRecordsExceeded` if not. The typed readers still count records during parse for their own diagnostics, but the defensive cap on the storage boundary closes the loophole for currently-unforeseen future classes.

---

## Wire-format reference

Authoritative source: [`../formats/texture/mips-and-streaming.md`](../formats/texture/mips-and-streaming.md) §`FByteBulkData` (lines 73–110) and §`BulkDataFlags` bit catalog (lines 85–110).

Key shape:

```
FByteBulkData record (paksmith range: UE 4.4+ → OffsetInFile always 8 bytes):

  i32       BulkDataFlags       (bitfield; see catalog)
  [i32|i64] ElementCount        (i64 when BULKDATA_Size64Bit, else i32)
  [u32|u64] SizeOnDisk          (u64 when BULKDATA_Size64Bit, else u32)
  i64       OffsetInFile        (paksmith floor UE 4.4+ → always 8 bytes)

  -- if BULKDATA_BadDataVersion (bit 15):
    u16     <discarded ushort>

  -- if BULKDATA_DuplicateNonOptionalPayload (bit 14):
    u32       DuplicateFlags
    [u32|u64] DuplicateSizeOnDisk    (u64 when Size64Bit)
    [i32|i64] DuplicateOffset        (paksmith floor → always 8 bytes)

[ payload at resolved offset in the tier's source file ]
```

The full bit catalog (bits 0–30) is in the format doc; the resolver dispatches:

- `BULKDATA_PayloadAtEndOfFile` (bit 0) → inline OR uexp-resident, disambiguated by `resolved_offset < total_header_size`.
- `BULKDATA_PayloadInSeperateFile` (bit 8) → streaming (`.ubulk`).
- `BULKDATA_OptionalPayload` (bit 11) + above → `.uptnl` (deferred).
- `BULKDATA_SerializeCompressedZLIB` (bit 1) → decompress via flate2 after extraction.

Cross-validation oracle: CUE4Parse's `FByteBulkData.cs` at the SHA pinned in the format doc (`cf74fc32fe1b40e9fd3440032508c5e1d50cf58d`).

---

## Task overview

7 tasks, one PR each.

| # | Title | Files |
|---|---|---|
| 1 | New error variants + cap constants | `error.rs`, `asset/bulk_data.rs` |
| 2 | `BulkDataFlags` + `BulkDataTier` types | `asset/bulk_data.rs` |
| 3 | `FByteBulkData::read_from` wire-format parser | `asset/bulk_data.rs` |
| 4 | Replace 3a's `BulkData` placeholder with real fields | `export/mod.rs`, `asset/bulk_data.rs` |
| 5 | `BulkDataResolver` impl: tier dispatch + offset fixup + zlib | `asset/bulk_data.rs` |
| 6 | Wire resolver into `Package::read_from_pak`; remove the warn | `asset/package.rs` |
| 7 | Fixture-gen extension + integration tests | `paksmith-fixture-gen/`, `paksmith-core-tests/` |

---

### Task 1: Error variants + cap constants

**Files:**

- Modify: `crates/paksmith-core/src/error.rs` — 12 new `AssetParseFault` variants (10 from the original plan + `BulkDataConflictingTierFlags` and `BulkDataCompressedSizeExceeded` added during R1 security review), each with a `Display` arm and a pin-table test (Phase 2g Task 1 pattern). Add `CompanionFileKind::Uptnl` (verified absent from current source).
- Modify: `crates/paksmith-core/src/asset/bulk_data.rs` — new caps + `BulkDataTier` enum + `BulkDataTier` Display impl. **Plan revision (2026-05-26):** caps moved from `seams.rs` to `asset/bulk_data.rs` per established convention (`container/pak/mod.rs::MAX_UNCOMPRESSED_ENTRY_BYTES`, `asset/property/bag.rs::MAX_PROPERTY_DEPTH`, etc.). `seams.rs` is OOM-injection-only infrastructure.

- [ ] **Step 1: Add cap constants in `asset/bulk_data.rs`.** (See "Plan revision (2026-05-26)" above for why this is `asset/bulk_data.rs`, not `seams.rs`.)

```rust
/// Maximum decompressed bulk-data payload size (8 GiB). Matches
/// `MAX_UNCOMPRESSED_ENTRY_BYTES` — a single `FByteBulkData` record
/// can't exceed an entry's worst-case decompressed size.
pub(crate) const MAX_BULK_DATA_SIZE: u64 = 8 * 1024 * 1024 * 1024;

/// Maximum `.ubulk` / `.uptnl` file size (16 GiB). Bounds the seek
/// window for streaming-tier records before any allocation.
/// The same constant applies to both companion files (no separate
/// `MAX_UPTNL_FILE_SIZE` constant).
pub(crate) const MAX_UBULK_FILE_SIZE: u64 = 16 * 1024 * 1024 * 1024;

/// Maximum FByteBulkData records per export. Real cooked content
/// rarely exceeds ~8 records (one per mip + duplicates). Cap at 256
/// to prevent a malformed export claiming N records and driving
/// allocation amplification. **Enforced at the 3e/3g/3h typed-reader
/// sites**, not in 3b — see plan §"Cap enforcement contract."
pub(crate) const MAX_BULK_DATA_RECORDS_PER_EXPORT: usize = 256;

/// Global budget on cumulative resolved bulk-data bytes per Package.
/// Without this, N exports × MAX_BULK_DATA_RECORDS_PER_EXPORT × 8 GiB
/// would be unbounded. Enforced by the resolver's running accumulator.
pub(crate) const MAX_TOTAL_BULK_DATA_BYTES_PER_PACKAGE: u64 = 16 * 1024 * 1024 * 1024;

// __test_utils accessors:
#[cfg(feature = "__test_utils")]
pub fn max_bulk_data_size() -> u64 { MAX_BULK_DATA_SIZE }
#[cfg(feature = "__test_utils")]
pub fn max_ubulk_file_size() -> u64 { MAX_UBULK_FILE_SIZE }
#[cfg(feature = "__test_utils")]
pub fn max_bulk_data_records_per_export() -> usize { MAX_BULK_DATA_RECORDS_PER_EXPORT }
#[cfg(feature = "__test_utils")]
pub fn max_total_bulk_data_bytes_per_package() -> u64 { MAX_TOTAL_BULK_DATA_BYTES_PER_PACKAGE }
```

- [ ] **Step 2: Add `BulkDataTier` enum to `asset/bulk_data.rs`.**

(`BulkData` itself is widened from 3a's unit-struct stub to a fields-bearing struct in **Task 4**, not here. Task 2 only adds the tier enum so Task 1's `BulkDataOffsetOob { tier: BulkDataTier, ... }` Display arm can name the type.) The four-variant enum is sized + Hash + Eq so it can be a HashMap key if needed downstream.

```rust
//! `FByteBulkData` reader + `BulkDataResolver` (Phase 3b).
//!
//! See `docs/plans/phase-3b-bulk-data-resolver.md` for the plan and
//! `docs/formats/texture/mips-and-streaming.md` for the wire format.

/// `#[non_exhaustive]` reserves the right for Phase 8 (IoStore) to
/// extend with additional tiers (e.g. partition-spanning streaming)
/// without an SemVer-major bump.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum BulkDataTier {
    /// Payload bytes live in the parent `.uasset` body (resolved
    /// offset < `total_header_size`).
    Inline,
    /// Payload bytes live in the `.uexp` companion body (resolved
    /// offset ≥ `total_header_size`).
    UexpResident,
    /// Payload bytes live in the `.ubulk` companion (offset is
    /// absolute within `.ubulk`, no fixup).
    Streaming,
    /// Payload bytes live in the `.uptnl` companion (the
    /// `BULKDATA_OptionalPayload` tier). Lazy-loaded; absence of
    /// `.uptnl` produces `MissingCompanionFile { kind: Uptnl }`.
    OptionalStreaming,
}
```

> Why all four variants here and not in Task 2? Task 1 (Step 3) defines `BulkDataOffsetOob { tier: BulkDataTier, ... }` — the enum must exist before that variant compiles. Ordering: Step 2 here, then Step 3 below.

- [ ] **Step 3: Add the 10 `AssetParseFault` variants in `error.rs` with hand-rolled `Display` arms + add `CompanionFileKind::Uptnl`.**

The `CompanionFileKind::Uptnl` variant is **confirmed absent** from current `error.rs` (verified: only `Uexp` and `Ubulk` exist at `error.rs:~3127-3146`). Add it as part of this step — Display arm returns `"uptnl"`, mirror the Phase 2e `Ubulk` pattern. Without this variant, the `.uptnl` loader closures in Task 6 can't fire `MissingCompanionFile { kind: Uptnl }`.

Mirror the existing variant style (Phase 2g Task 1's `ArrayOfStructHeaderMissing` shape):

```rust
// In AssetParseFault enum (alongside existing variants):

/// Resolved bulk-data offset + size overruns the source file.
BulkDataOffsetOob {
    tier: crate::asset::bulk_data::BulkDataTier,
    offset: u64,
    size: u64,
    file_size: u64,
},

/// `OffsetInFile + BulkDataStartOffset` overflowed during offset
/// fix-up (`BULKDATA_NoOffsetFixUp` was unset).
BulkDataOffsetFixupOverflow {
    offset: i64,
    fixup: i64,
},

/// `resolved_offset + size_on_disk` overflowed when computing the
/// end-of-payload position (separate from the fix-up step above).
BulkDataEndOffsetOverflow {
    offset: u64,
    size: u64,
},

/// `FByteBulkData.SizeOnDisk` exceeds [`MAX_BULK_DATA_SIZE`].
BulkDataSizeExceeded { size: u64, cap: u64 },

/// `FByteBulkData.ElementCount` is negative (sign-extension attack
/// or wire corruption — the count is i32/i64 on the wire and must
/// be `>= 0` before any consumer treats it as a buffer length).
BulkDataElementCountNegative { count: i64 },

/// Export carries more `FByteBulkData` records than
/// [`MAX_BULK_DATA_RECORDS_PER_EXPORT`]. Fired at the typed-reader
/// site (3e/3g/3h), not by the resolver.
BulkDataRecordsExceeded { count: usize, cap: usize },

/// Cumulative resolved bulk-data bytes across all records in one
/// Package exceeds [`MAX_TOTAL_BULK_DATA_BYTES_PER_PACKAGE`].
BulkDataPackageBudgetExceeded { resolved: u64, cap: u64 },

/// `BulkDataFlags` is valid (all bits in the catalog) but has none
/// of the four tier-routing bits set: no `BULKDATA_PayloadAtEndOfFile`
/// AND no `BULKDATA_PayloadInSeperateFile`. The wire format requires
/// at least one to identify the source file.
BulkDataNoTierFlag { flags: u32 },

/// `BULKDATA_SerializeCompressedZLIB` payload decompressed to a
/// different byte count than `ElementCount` claims. Surfaces
/// truncated, over-long, or stream-corrupted compressed inputs.
BulkDataDecompressLengthMismatch { expected: i64, actual: usize },

/// `BulkDataFlags` carries bits outside the documented catalog
/// (bits 19–27 or bit 31).
UnknownBulkDataFlags { bits: u32 },

/// `FByteBulkData` requested a compression method paksmith doesn't
/// support in Phase 3 (LZO, BitWindow are Phase 3 follow-ups when a
/// fixture surfaces; Oodle ships in Phase 8 via the runtime-SDK loader).
UnsupportedBulkCompression { method: &'static str },
```

`Display` arms (hand-rolled per repo convention):

```rust
Self::BulkDataOffsetOob { tier, offset, size, file_size } => write!(
    f,
    "bulk-data record overruns {tier:?} source: offset {offset} + size {size} \
     > file size {file_size}"
),
Self::BulkDataOffsetFixupOverflow { offset, fixup } => write!(
    f,
    "bulk-data offset fix-up overflowed: {offset} + {fixup} > i64::MAX"
),
Self::BulkDataEndOffsetOverflow { offset, size } => write!(
    f,
    "bulk-data end-of-payload computation overflowed: resolved offset {offset} \
     + size {size} > u64::MAX"
),
Self::BulkDataSizeExceeded { size, cap } => write!(
    f,
    "bulk-data SizeOnDisk {size} exceeds cap {cap}"
),
Self::BulkDataElementCountNegative { count } => write!(
    f,
    "bulk-data ElementCount {count} is negative (sign-extension or corrupt asset)"
),
Self::BulkDataRecordsExceeded { count, cap } => write!(
    f,
    "export has {count} FByteBulkData records, exceeds cap {cap}"
),
Self::BulkDataPackageBudgetExceeded { resolved, cap } => write!(
    f,
    "cumulative bulk-data bytes resolved ({resolved}) exceeds per-package cap ({cap})"
),
Self::BulkDataNoTierFlag { flags } => write!(
    f,
    "BulkDataFlags 0x{flags:08X} sets no tier-routing bit \
     (need PayloadAtEndOfFile=0x01 or PayloadInSeperateFile=0x100)"
),
Self::BulkDataDecompressLengthMismatch { expected, actual } => write!(
    f,
    "zlib bulk-data decompressed to {actual} bytes; record ElementCount claims {expected}"
),
Self::UnknownBulkDataFlags { bits } => write!(
    f,
    "BulkDataFlags carries unknown bits 0x{bits:08X} \
     (allocated bits: 0-18, 28-30; bits 19-27 and 31 are reserved)"
),
Self::UnsupportedBulkCompression { method } => write!(
    f,
    "bulk-data compression method {method} is not yet supported"
),
```

- [ ] **Step 4: Add pin-table Display tests, one per variant.**

```rust
// In error.rs::tests:

#[test]
fn asset_parse_display_bulk_data_offset_oob() {
    let s = AssetParseFault::BulkDataOffsetOob {
        tier: crate::asset::bulk_data::BulkDataTier::UexpResident,
        offset: 1024,
        size: 4096,
        file_size: 2048,
    }.to_string();
    assert_eq!(
        s,
        "bulk-data record overruns UexpResident source: offset 1024 + size 4096 \
         > file size 2048"
    );
}

#[test]
fn asset_parse_display_bulk_data_offset_fixup_overflow() {
    let s = AssetParseFault::BulkDataOffsetFixupOverflow {
        offset: i64::MAX - 10,
        fixup: 20,
    }.to_string();
    assert!(s.starts_with("bulk-data offset fix-up overflowed:"));
    assert!(s.contains("> i64::MAX"));
}

#[test]
fn asset_parse_display_bulk_data_end_offset_overflow() {
    let s = AssetParseFault::BulkDataEndOffsetOverflow {
        offset: u64::MAX - 5,
        size: 100,
    }.to_string();
    assert!(s.starts_with("bulk-data end-of-payload computation overflowed:"));
    assert!(s.contains("> u64::MAX"));
}

#[test]
fn asset_parse_display_bulk_data_element_count_negative() {
    let s = AssetParseFault::BulkDataElementCountNegative { count: -1 }.to_string();
    assert_eq!(
        s,
        "bulk-data ElementCount -1 is negative (sign-extension or corrupt asset)"
    );
}

#[test]
fn asset_parse_display_bulk_data_package_budget_exceeded() {
    let s = AssetParseFault::BulkDataPackageBudgetExceeded {
        resolved: 20 * 1024 * 1024 * 1024,
        cap: 16 * 1024 * 1024 * 1024,
    }.to_string();
    assert_eq!(
        s,
        "cumulative bulk-data bytes resolved (21474836480) exceeds per-package cap (17179869184)"
    );
}

#[test]
fn asset_parse_display_bulk_data_no_tier_flag() {
    // 0x0002 = SerializeCompressedZLIB only; no tier bit.
    let s = AssetParseFault::BulkDataNoTierFlag { flags: 0x0000_0002 }.to_string();
    assert_eq!(
        s,
        "BulkDataFlags 0x00000002 sets no tier-routing bit \
         (need PayloadAtEndOfFile=0x01 or PayloadInSeperateFile=0x100)"
    );
}

#[test]
fn asset_parse_display_bulk_data_decompress_length_mismatch() {
    let s = AssetParseFault::BulkDataDecompressLengthMismatch {
        expected: 4096,
        actual: 3500,
    }.to_string();
    assert_eq!(
        s,
        "zlib bulk-data decompressed to 3500 bytes; record ElementCount claims 4096"
    );
}

#[test]
fn asset_parse_display_bulk_data_size_exceeded() {
    let s = AssetParseFault::BulkDataSizeExceeded {
        size: 9 * 1024 * 1024 * 1024,
        cap: 8 * 1024 * 1024 * 1024,
    }.to_string();
    assert_eq!(
        s,
        "bulk-data SizeOnDisk 9663676416 exceeds cap 8589934592"
    );
}

#[test]
fn asset_parse_display_bulk_data_records_exceeded() {
    let s = AssetParseFault::BulkDataRecordsExceeded { count: 300, cap: 256 }.to_string();
    assert_eq!(s, "export has 300 FByteBulkData records, exceeds cap 256");
}

#[test]
fn asset_parse_display_unknown_bulk_data_flags() {
    let s = AssetParseFault::UnknownBulkDataFlags { bits: 0x0008_0000 }.to_string();
    assert_eq!(
        s,
        "BulkDataFlags carries unknown bits 0x00080000 \
         (allocated bits: 0-18, 28-30; bits 19-27 and 31 are reserved)"
    );
}

#[test]
fn asset_parse_display_unsupported_bulk_compression() {
    let s = AssetParseFault::UnsupportedBulkCompression { method: "Oodle" }.to_string();
    assert_eq!(s, "bulk-data compression method Oodle is not yet supported");
}
```

- [ ] **Step 5: Lint + test + doc gate.**

```shell
set -o pipefail
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features 2>&1 | tail -15
cargo clean -p paksmith-core
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
```

- [ ] **Step 6: Commit.**

```bash
git add crates/paksmith-core/src/error.rs crates/paksmith-core/src/asset/bulk_data.rs docs/plans/phase-3b-bulk-data-resolver.md
git commit -m "$(cat <<'EOF'
feat(error): add 12 bulk-data fault variants + 5 cap constants + BulkDataTier + CompanionFileKind::Uptnl

3b foundation. Phase 3b's BulkDataResolver fires these variants when
the wire-format invariants on FByteBulkData records are violated.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: `BulkDataFlags` + `BulkDataTier` types

**Files:**

- Create: `crates/paksmith-core/src/asset/bulk_data.rs`.
- Modify: `crates/paksmith-core/src/asset/mod.rs` (declare `pub mod bulk_data;`).

- [ ] **Step 1: Write the failing tests in `bulk_data.rs::tests`.**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_payload_at_end_of_file_detected() {
        let f = BulkDataFlags(0x0000_0001);
        assert!(f.payload_at_end_of_file());
        assert!(!f.payload_in_separate_file());
        assert!(!f.size_64_bit());
    }

    #[test]
    fn flags_payload_in_separate_file_detected() {
        let f = BulkDataFlags(0x0000_0100);
        assert!(!f.payload_at_end_of_file());
        assert!(f.payload_in_separate_file());
    }

    #[test]
    fn flags_size_64_bit_detected() {
        let f = BulkDataFlags(0x0000_2000);
        assert!(f.size_64_bit());
    }

    #[test]
    fn flags_zlib_compressed_detected() {
        let f = BulkDataFlags(0x0000_0002);
        assert!(f.is_zlib_compressed());
        assert!(!f.is_lzo_compressed());
    }

    #[test]
    fn flags_optional_payload_detected() {
        let f = BulkDataFlags(0x0000_0800);
        assert!(f.optional_payload());
    }

    #[test]
    fn flags_no_offset_fixup_detected() {
        let f = BulkDataFlags(0x0001_0000);
        assert!(f.no_offset_fixup());
    }

    #[test]
    fn flags_validate_rejects_reserved_bits() {
        // Bit 19 is reserved per the catalog.
        let f = BulkDataFlags(0x0008_0000);
        match f.validate() {
            Err(crate::PaksmithError::AssetParse {
                fault: crate::AssetParseFault::UnknownBulkDataFlags { bits },
                ..
            }) => assert_eq!(bits, 0x0008_0000),
            other => panic!("expected UnknownBulkDataFlags, got {other:?}"),
        }
    }

    #[test]
    fn flags_validate_accepts_all_documented_bits() {
        // bits 0-18 + 28-30 are all allocated per the catalog.
        let allocated: u32 = 0x7007_FFFF;
        let f = BulkDataFlags(allocated);
        assert!(f.validate().is_ok());
    }
}
```

- [ ] **Step 2: Implement `BulkDataFlags` and run the tests.**

```rust
/// Bitfield wrapper for `FByteBulkData.BulkDataFlags`. Catalog at
/// `docs/formats/texture/mips-and-streaming.md` §BulkDataFlags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub struct BulkDataFlags(pub u32);

const FLAG_PAYLOAD_AT_END_OF_FILE: u32         = 0x0000_0001;
const FLAG_SERIALIZE_COMPRESSED_ZLIB: u32      = 0x0000_0002;
const FLAG_FORCE_SINGLE_ELEMENT: u32           = 0x0000_0004;
const FLAG_SINGLE_USE: u32                     = 0x0000_0008;
const FLAG_COMPRESSED_LZO: u32                 = 0x0000_0010;
const FLAG_UNUSED: u32                         = 0x0000_0020;
const FLAG_FORCE_INLINE_PAYLOAD: u32           = 0x0000_0040;
const FLAG_FORCE_STREAM_PAYLOAD: u32           = 0x0000_0080;
const FLAG_PAYLOAD_IN_SEPARATE_FILE: u32       = 0x0000_0100;
const FLAG_SERIALIZE_COMPRESSED_BITWINDOW: u32 = 0x0000_0200;
const FLAG_FORCE_NOT_INLINE: u32               = 0x0000_0400;
const FLAG_OPTIONAL_PAYLOAD: u32               = 0x0000_0800;
const FLAG_MEMORY_MAPPED: u32                  = 0x0000_1000;
const FLAG_SIZE_64_BIT: u32                    = 0x0000_2000;
const FLAG_DUPLICATE_NON_OPTIONAL: u32         = 0x0000_4000;
const FLAG_BAD_DATA_VERSION: u32               = 0x0000_8000;
const FLAG_NO_OFFSET_FIXUP: u32                = 0x0001_0000;
const FLAG_WORKSPACE_DOMAIN: u32               = 0x0002_0000;
const FLAG_LAZY_LOADABLE: u32                  = 0x0004_0000;
const FLAG_ALWAYS_ALLOW_DISCARD: u32           = 0x1000_0000;
const FLAG_HAS_ASYNC_READ_PENDING: u32         = 0x2000_0000;
const FLAG_DATA_IS_MEMORY_MAPPED: u32          = 0x4000_0000;

const VALID_FLAG_MASK: u32 = 0x7007_FFFF;

impl BulkDataFlags {
    #[must_use] pub fn payload_at_end_of_file(self) -> bool    { (self.0 & FLAG_PAYLOAD_AT_END_OF_FILE) != 0 }
    #[must_use] pub fn payload_in_separate_file(self) -> bool  { (self.0 & FLAG_PAYLOAD_IN_SEPARATE_FILE) != 0 }
    #[must_use] pub fn optional_payload(self) -> bool          { (self.0 & FLAG_OPTIONAL_PAYLOAD) != 0 }
    #[must_use] pub fn no_offset_fixup(self) -> bool           { (self.0 & FLAG_NO_OFFSET_FIXUP) != 0 }
    #[must_use] pub fn size_64_bit(self) -> bool               { (self.0 & FLAG_SIZE_64_BIT) != 0 }
    #[must_use] pub fn is_zlib_compressed(self) -> bool        { (self.0 & FLAG_SERIALIZE_COMPRESSED_ZLIB) != 0 }
    #[must_use] pub fn is_lzo_compressed(self) -> bool         { (self.0 & FLAG_COMPRESSED_LZO) != 0 }
    #[must_use] pub fn is_bitwindow_compressed(self) -> bool   { (self.0 & FLAG_SERIALIZE_COMPRESSED_BITWINDOW) != 0 }
    #[must_use] pub fn has_duplicate_non_optional(self) -> bool { (self.0 & FLAG_DUPLICATE_NON_OPTIONAL) != 0 }
    #[must_use] pub fn has_bad_data_version(self) -> bool      { (self.0 & FLAG_BAD_DATA_VERSION) != 0 }

    /// Validates that no reserved bits are set.
    ///
    /// # Errors
    /// [`AssetParseFault::UnknownBulkDataFlags`] when bits outside
    /// the documented catalog (bits 19–27 or bit 31) are set.
    pub fn validate(self) -> crate::Result<()> {
        let unknown_bits = self.0 & !VALID_FLAG_MASK;
        if unknown_bits != 0 {
            return Err(crate::PaksmithError::AssetParse {
                asset_path: String::new(), // caller fills in
                fault: crate::AssetParseFault::UnknownBulkDataFlags {
                    bits: self.0,
                },
            });
        }
        Ok(())
    }
}
```

> The empty `asset_path` is a known UX wart; the caller wraps the error and replaces. Same pattern as Phase 2c's depth-cap errors. Phase 3+ may introduce an error-builder pattern, but out of scope here.

- [ ] **Step 3: Run.**

```shell
set -o pipefail
cargo test -p paksmith-core asset::bulk_data::tests 2>&1 | tail -15
```

- [ ] **Step 4: Lint + test + doc gate.** Same shell block as Task 1 Step 5.

- [ ] **Step 5: Commit.**

```bash
git add crates/paksmith-core/src/asset/mod.rs crates/paksmith-core/src/asset/bulk_data.rs
git commit -m "$(cat <<'EOF'
feat(bulk-data): add BulkDataFlags + BulkDataTier types

Catalog from docs/formats/texture/mips-and-streaming.md §BulkDataFlags.
validate() rejects reserved bits before resolver dispatch.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: `FByteBulkData::read_from` wire-format parser

**Files:**

- Modify: `crates/paksmith-core/src/asset/bulk_data.rs` — append `FByteBulkData` struct and parser.

- [ ] **Step 1: Write failing TDD test with hand-built record bytes.**

```rust
#[test]
fn read_minimal_inline_record() {
    // 24 bytes: flags(0x0001) + ElementCount(4096 i32) + SizeOnDisk(4096 u32) + OffsetInFile(512 i64).
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0x0000_0001u32.to_le_bytes()); // flags
    bytes.extend_from_slice(&4096i32.to_le_bytes());        // element_count i32
    bytes.extend_from_slice(&4096u32.to_le_bytes());        // size_on_disk u32
    bytes.extend_from_slice(&512i64.to_le_bytes());         // offset_in_file i64

    let mut cur = std::io::Cursor::new(bytes);
    let record = FByteBulkData::read_from(&mut cur, "test.uasset").expect("read");
    assert_eq!(record.flags.0, 0x0000_0001);
    assert_eq!(record.element_count, 4096);
    assert_eq!(record.size_on_disk, 4096);
    assert_eq!(record.offset_in_file, 512);
    assert!(!record.flags.size_64_bit());
}

#[test]
fn read_size_64_bit_widens_fields() {
    // ElementCount + SizeOnDisk widen to 8 bytes when Size64Bit set.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&FLAG_SIZE_64_BIT.to_le_bytes());
    bytes.extend_from_slice(&(4096i64).to_le_bytes());      // i64
    bytes.extend_from_slice(&(4096u64).to_le_bytes());      // u64
    bytes.extend_from_slice(&(512i64).to_le_bytes());

    let mut cur = std::io::Cursor::new(bytes);
    let record = FByteBulkData::read_from(&mut cur, "test.uasset").expect("read");
    assert_eq!(record.element_count, 4096);
    assert_eq!(record.size_on_disk, 4096);
}

#[test]
fn read_rejects_size_exceeded() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0x0000_0001u32.to_le_bytes());
    bytes.extend_from_slice(&0i32.to_le_bytes());
    bytes.extend_from_slice(&u32::MAX.to_le_bytes()); // ~4 GiB — under cap
    bytes.extend_from_slice(&0i64.to_le_bytes());

    let mut cur = std::io::Cursor::new(bytes);
    // Bare u32::MAX (~4 GiB) is under the 8 GiB cap — should pass.
    let _ = FByteBulkData::read_from(&mut cur, "test.uasset").expect("under cap");

    // Now force above cap via Size64Bit + 9 GiB.
    let mut bytes2 = Vec::new();
    bytes2.extend_from_slice(&FLAG_SIZE_64_BIT.to_le_bytes());
    bytes2.extend_from_slice(&0i64.to_le_bytes());
    bytes2.extend_from_slice(&(9u64 * 1024 * 1024 * 1024).to_le_bytes());
    bytes2.extend_from_slice(&0i64.to_le_bytes());
    let mut cur2 = std::io::Cursor::new(bytes2);
    match FByteBulkData::read_from(&mut cur2, "test.uasset") {
        Err(crate::PaksmithError::AssetParse {
            fault: crate::AssetParseFault::BulkDataSizeExceeded { size, .. },
            ..
        }) => assert_eq!(size, 9 * 1024 * 1024 * 1024),
        other => panic!("expected BulkDataSizeExceeded, got {other:?}"),
    }
}

#[test]
fn read_skips_bad_data_version_ushort() {
    // Set BULKDATA_BadDataVersion → 2 trailing bytes after offset get discarded.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(0x0000_0001 | FLAG_BAD_DATA_VERSION).to_le_bytes());
    bytes.extend_from_slice(&4096i32.to_le_bytes());
    bytes.extend_from_slice(&4096u32.to_le_bytes());
    bytes.extend_from_slice(&512i64.to_le_bytes());
    bytes.extend_from_slice(&[0xDE, 0xAD]); // the discarded ushort

    let mut cur = std::io::Cursor::new(bytes);
    let record = FByteBulkData::read_from(&mut cur, "test.uasset").expect("read");
    // Discarded; flag also cleared per the wire-format spec.
    assert!(!record.flags.has_bad_data_version());
    // Cursor MUST be at end (no trailing bytes left).
    assert_eq!(cur.position(), bytes.len() as u64);
}

#[test]
fn read_skips_duplicate_non_optional_block() {
    // BULKDATA_DuplicateNonOptionalPayload: skip 4 (flags) + 4|8 (size) + 8 (offset) extra bytes.
    // With Size64Bit unset: total skip = 4 + 4 + 8 = 16 bytes.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(0x0000_0001 | FLAG_DUPLICATE_NON_OPTIONAL).to_le_bytes());
    bytes.extend_from_slice(&4096i32.to_le_bytes());
    bytes.extend_from_slice(&4096u32.to_le_bytes());
    bytes.extend_from_slice(&512i64.to_le_bytes());
    // Duplicate block (16 bytes total: u32 flags + u32 size + i64 offset):
    bytes.extend_from_slice(&[0xAA; 16]);

    let mut cur = std::io::Cursor::new(bytes);
    let record = FByteBulkData::read_from(&mut cur, "test.uasset").expect("read");
    assert_eq!(cur.position(), bytes.len() as u64); // duplicate block consumed
}
```

- [ ] **Step 2: Implement `FByteBulkData::read_from`.**

```rust
use std::io::{Read, Seek};
use byteorder::{LittleEndian, ReadBytesExt};

/// One `FByteBulkData` record on the wire. Lives inside a `.uasset`
/// export's serialized data; published per-mip (textures) /
/// per-codec (audio).
#[derive(Debug, Clone)]
pub struct FByteBulkData {
    pub flags: BulkDataFlags,
    pub element_count: i64,
    pub size_on_disk: u64,
    pub offset_in_file: i64,
}

impl FByteBulkData {
    /// Read one record from `reader`. Consumes the wire-format
    /// fields and discards the `BadDataVersion` 2-byte block + the
    /// `DuplicateNonOptionalPayload` block per the format spec.
    ///
    /// # Errors
    /// [`AssetParseFault::UnknownBulkDataFlags`] for reserved bits,
    /// [`AssetParseFault::BulkDataSizeExceeded`] for size cap, etc.
    pub fn read_from<R: Read + Seek>(
        reader: &mut R,
        asset_path: &str,
    ) -> crate::Result<Self> {
        let raw_flags = reader.read_u32::<LittleEndian>().map_err(|_| {
            crate::PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: crate::AssetParseFault::UnexpectedEof {
                    field: crate::AssetWireField::BulkDataFlags,
                },
            }
        })?;
        let flags = BulkDataFlags(raw_flags);
        flags.validate().map_err(|e| match e {
            crate::PaksmithError::AssetParse { fault, .. } => {
                crate::PaksmithError::AssetParse {
                    asset_path: asset_path.to_string(),
                    fault,
                }
            }
            other => other,
        })?;

        // ElementCount + SizeOnDisk widen to 64-bit when Size64Bit is set.
        let element_count: i64 = if flags.size_64_bit() {
            reader.read_i64::<LittleEndian>()
        } else {
            reader.read_i32::<LittleEndian>().map(i64::from)
        }
        .map_err(|_| eof(asset_path, crate::AssetWireField::BulkDataElementCount))?;
        // Sign-check: ElementCount is signed on wire but consumers treat
        // it as a buffer length. A negative value is wire corruption
        // (or attacker sign-extension). Reject before further use.
        if element_count < 0 {
            return Err(crate::PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: crate::AssetParseFault::BulkDataElementCountNegative {
                    count: element_count,
                },
            });
        }

        let size_on_disk: u64 = if flags.size_64_bit() {
            reader.read_u64::<LittleEndian>()
        } else {
            reader.read_u32::<LittleEndian>().map(u64::from)
        }
        .map_err(|_| eof(asset_path, crate::AssetWireField::BulkDataSizeOnDisk))?;

        if size_on_disk > crate::seams::MAX_BULK_DATA_SIZE {
            return Err(crate::PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: crate::AssetParseFault::BulkDataSizeExceeded {
                    size: size_on_disk,
                    cap: crate::seams::MAX_BULK_DATA_SIZE,
                },
            });
        }

        let offset_in_file = reader
            .read_i64::<LittleEndian>()
            .map_err(|_| eof(asset_path, crate::AssetWireField::BulkDataOffsetInFile))?;

        // Side-effect blocks per the format spec.
        let mut flags_clean = flags;
        if flags.has_bad_data_version() {
            // 2-byte ushort discarded; flag cleared after read.
            let _ = reader.read_u16::<LittleEndian>().map_err(|_| {
                eof(asset_path, crate::AssetWireField::BulkDataBadDataVersionTail)
            })?;
            flags_clean.0 &= !FLAG_BAD_DATA_VERSION;
        }
        if flags.has_duplicate_non_optional() {
            // Skip duplicate block: 4 (DupFlags u32) + [4|8] (DupSize) + 8 (DupOffset).
            let size_field_width = if flags.size_64_bit() { 8 } else { 4 };
            let total_skip = 4 + size_field_width + 8;
            let mut sink = [0u8; 20];
            reader
                .read_exact(&mut sink[..total_skip])
                .map_err(|_| eof(asset_path, crate::AssetWireField::BulkDataDuplicateBlock))?;
        }

        Ok(Self {
            flags: flags_clean,
            element_count,
            size_on_disk,
            offset_in_file,
        })
    }
}

fn eof(asset_path: &str, field: crate::AssetWireField) -> crate::PaksmithError {
    crate::PaksmithError::AssetParse {
        asset_path: asset_path.to_string(),
        fault: crate::AssetParseFault::UnexpectedEof { field },
    }
}
```

> Add `AssetWireField::BulkDataFlags`, `BulkDataElementCount`, `BulkDataSizeOnDisk`, `BulkDataOffsetInFile`, `BulkDataBadDataVersionTail`, `BulkDataDuplicateBlock` to the existing `AssetWireField` enum in `error.rs`. Each Display arm prints the field name verbatim ("BulkDataFlags", etc.).

- [ ] **Step 3: Run.** `cargo test -p paksmith-core asset::bulk_data::tests 2>&1 | tail -15`.

- [ ] **Step 4: Lint + test + doc gate.** Same shell block as Task 1 Step 5.

- [ ] **Step 5: Commit.**

```bash
git add crates/paksmith-core/src/asset/bulk_data.rs crates/paksmith-core/src/error.rs
git commit -m "$(cat <<'EOF'
feat(bulk-data): FByteBulkData::read_from parses wire-format record

Handles Size64Bit field widening, BadDataVersion 2-byte discard, and
DuplicateNonOptionalPayload block skip per the wire-format spec.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: Expand `BulkData` from the 3a unit-struct stub to the full-shape record

**Files:**

- Modify: `crates/paksmith-core/src/asset/bulk_data.rs` — add fields to the unit struct.
- No changes to `export/mod.rs` — it already `pub use crate::asset::bulk_data::BulkData;` from 3a Task 2.

3a Task 2 shipped `pub struct BulkData;` (unit struct, zero fields, in `asset/bulk_data.rs`). 3b Task 4 widens it to carry the resolved bytes + the source record + the tier. Because the 3a starting shape is a unit struct (NOT a fields-bearing struct with hidden `_private: ()` field), the widening is purely additive — no downstream consumer could have destructure-matched the unit, so adding fields is non-breaking even to paranoid pattern-match consumers.

- [ ] **Step 1: Expand the unit struct in `asset/bulk_data.rs`.**

```rust
// Replace 3a's unit-struct definition:
//   pub struct BulkData;
// with the full-fields shape:

/// Resolved bulk-data payload — bytes plus metadata about which
/// tier they came from and how they were decoded (compression).
///
/// Produced by [`BulkDataResolver::resolve`]. Consumed by Phase 3
/// format handlers ([`crate::export::FormatHandler`]).
#[derive(Debug, Clone)]
pub struct BulkData {
    /// Resolved, decompressed payload bytes. Owned (not a slice
    /// into the pak buffer) per master-index Design Decision #6.
    pub bytes: Vec<u8>,
    /// The wire-format record this payload was resolved from.
    pub record: FByteBulkData,
    /// Which storage tier the bytes came from (inline / uexp /
    /// streaming / optional-streaming).
    pub tier: BulkDataTier,
}
```

The `pub use` re-export in `export/mod.rs` (already shipped in 3a Task 2 Step 3) now exposes the full type with no module-side edit. Downstream code can pattern-match `BulkData { bytes, record, tier }` once 3b lands; until 3b lands, only the unit-struct binding is available.

- [ ] **Step 3: Run all tests to verify nothing broke.**

```shell
set -o pipefail
cargo test --workspace --all-features 2>&1 | tail -15
```

3a's `GenericHandler::export` ignores `bulk`; this swap should be transparent.

- [ ] **Step 4: Lint + test + doc gate.** Same shell block as Task 1 Step 5.

- [ ] **Step 5: Commit.**

```bash
git add crates/paksmith-core/src/export/mod.rs crates/paksmith-core/src/asset/bulk_data.rs
git commit -m "$(cat <<'EOF'
refactor(export): replace BulkData placeholder with real fields

Closes 3a's #[doc(hidden)] _private placeholder. Handlers can now
access bytes + record + tier.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: `BulkDataResolver` — tier dispatch, offset fixup, zlib decompression

**Files:**

- Modify: `crates/paksmith-core/src/asset/bulk_data.rs` — append resolver.

- [ ] **Step 1: Write failing TDD tests covering each tier.**

```rust
#[test]
fn resolve_inline_tier_returns_uasset_slice() {
    // Synthetic .uasset: 100-byte header (offsets < 100 → inline),
    // then 200 bytes of "uexp-resident" payload. BulkDataStartOffset = 0.
    let uasset = {
        let mut b = vec![0xAA; 100];
        b.extend_from_slice(&vec![0xBB; 200]);
        b
    };
    let record = FByteBulkData {
        flags: BulkDataFlags(FLAG_PAYLOAD_AT_END_OF_FILE),
        element_count: 16,
        size_on_disk: 16,
        offset_in_file: 32, // < 100 → inline
    };
    let resolver = BulkDataResolver::new_for_test(&uasset, /* total_header_size */ 100, /* bulk_start_offset */ 0);
    let data = resolver.resolve(&record, "test.uasset").expect("resolve");
    assert_eq!(data.tier, BulkDataTier::Inline);
    assert_eq!(data.bytes.len(), 16);
    assert!(data.bytes.iter().all(|&b| b == 0xAA));
}

#[test]
fn resolve_uexp_resident_returns_uexp_slice() {
    let uasset = {
        let mut b = vec![0xAA; 100];
        b.extend_from_slice(&vec![0xBB; 200]);
        b
    };
    let record = FByteBulkData {
        flags: BulkDataFlags(FLAG_PAYLOAD_AT_END_OF_FILE),
        element_count: 16,
        size_on_disk: 16,
        offset_in_file: 120, // ≥ 100 → uexp-resident
    };
    let resolver = BulkDataResolver::new_for_test(&uasset, 100, 0);
    let data = resolver.resolve(&record, "test.uasset").expect("resolve");
    assert_eq!(data.tier, BulkDataTier::UexpResident);
    assert_eq!(data.bytes.len(), 16);
    assert!(data.bytes.iter().all(|&b| b == 0xBB));
}

#[test]
fn resolve_offset_fixup_applies_bulk_start_offset() {
    // BulkDataStartOffset = 50, OffsetInFile = 30 → resolved = 80.
    let uasset = {
        let mut b = vec![0xAA; 100];
        b.extend_from_slice(&vec![0xBB; 200]);
        b
    };
    let record = FByteBulkData {
        flags: BulkDataFlags(FLAG_PAYLOAD_AT_END_OF_FILE),
        element_count: 8,
        size_on_disk: 8,
        offset_in_file: 30,
    };
    let resolver = BulkDataResolver::new_for_test(&uasset, 100, 50);
    let data = resolver.resolve(&record, "test.uasset").expect("resolve");
    // resolved = 30 + 50 = 80 → still inline (80 < 100).
    assert_eq!(data.tier, BulkDataTier::Inline);
    // First 8 bytes from offset 80.
    assert!(data.bytes.iter().all(|&b| b == 0xAA));
}

#[test]
fn resolve_no_offset_fixup_bypasses_bulk_start() {
    let uasset = vec![0xAA; 200];
    let record = FByteBulkData {
        flags: BulkDataFlags(FLAG_PAYLOAD_AT_END_OF_FILE | FLAG_NO_OFFSET_FIXUP),
        element_count: 8,
        size_on_disk: 8,
        offset_in_file: 50,
    };
    let resolver = BulkDataResolver::new_for_test(&uasset, 200, 999);
    let data = resolver.resolve(&record, "test.uasset").expect("resolve");
    // No fixup applied: resolved = 50 (NOT 50 + 999).
    assert_eq!(data.bytes.len(), 8);
}

#[test]
fn resolve_zlib_decompresses() {
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;
    let original = b"hello bulk data world".to_vec();
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&original).unwrap();
    let compressed = encoder.finish().unwrap();

    let mut uasset = vec![0u8; 64];
    uasset.extend_from_slice(&compressed);
    let record = FByteBulkData {
        flags: BulkDataFlags(FLAG_PAYLOAD_AT_END_OF_FILE | FLAG_SERIALIZE_COMPRESSED_ZLIB),
        element_count: original.len() as i64,
        size_on_disk: compressed.len() as u64,
        offset_in_file: 64,
    };
    let resolver = BulkDataResolver::new_for_test(&uasset, 64 + compressed.len(), 0);
    let data = resolver.resolve(&record, "test.uasset").expect("resolve");
    assert_eq!(data.bytes, original);
}

#[test]
fn resolve_rejects_oob_offset() {
    let uasset = vec![0u8; 100];
    let record = FByteBulkData {
        flags: BulkDataFlags(FLAG_PAYLOAD_AT_END_OF_FILE),
        element_count: 8,
        size_on_disk: 50,
        offset_in_file: 80, // 80 + 50 = 130 > 100
    };
    let resolver = BulkDataResolver::new_for_test(&uasset, 100, 0);
    match resolver.resolve(&record, "test.uasset") {
        Err(crate::PaksmithError::AssetParse {
            fault: crate::AssetParseFault::BulkDataOffsetOob { offset, size, file_size, .. },
            ..
        }) => {
            assert_eq!(offset, 80);
            assert_eq!(size, 50);
            assert_eq!(file_size, 100);
        }
        other => panic!("expected BulkDataOffsetOob, got {other:?}"),
    }
}

#[test]
fn resolve_rejects_offset_overflow() {
    let uasset = vec![0u8; 100];
    let record = FByteBulkData {
        flags: BulkDataFlags(FLAG_PAYLOAD_AT_END_OF_FILE),
        element_count: 1,
        size_on_disk: 1,
        offset_in_file: i64::MAX - 10,
    };
    let resolver = BulkDataResolver::new_for_test(&uasset, 100, 20);
    match resolver.resolve(&record, "test.uasset") {
        Err(crate::PaksmithError::AssetParse {
            fault: crate::AssetParseFault::BulkDataOffsetFixupOverflow { .. },
            ..
        }) => {}
        other => panic!("expected BulkDataOffsetFixupOverflow, got {other:?}"),
    }
}

#[test]
fn resolve_optional_streaming_loads_from_uptnl() {
    // Streaming + OptionalPayload → .uptnl tier.
    // The test resolver carries a uptnl_loader closure (extended in this task).
    let uptnl_bytes = vec![0xCC; 32];
    let uasset = vec![0u8; 100];
    let record = FByteBulkData {
        flags: BulkDataFlags(FLAG_PAYLOAD_IN_SEPARATE_FILE | FLAG_OPTIONAL_PAYLOAD),
        element_count: 16,
        size_on_disk: 16,
        offset_in_file: 0,
    };
    let resolver = BulkDataResolver::new_for_test_with_uptnl(&uasset, 100, 0, uptnl_bytes.clone());
    let data = resolver.resolve(&record, "test.uasset").expect("resolve");
    assert_eq!(data.tier, BulkDataTier::OptionalStreaming);
    assert_eq!(data.bytes.len(), 16);
    assert!(data.bytes.iter().all(|&b| b == 0xCC));
}

#[test]
fn resolve_missing_uptnl_when_optional_streaming_errors_typed() {
    let uasset = vec![0u8; 100];
    let record = FByteBulkData {
        flags: BulkDataFlags(FLAG_PAYLOAD_IN_SEPARATE_FILE | FLAG_OPTIONAL_PAYLOAD),
        element_count: 8,
        size_on_disk: 8,
        offset_in_file: 0,
    };
    // Default test resolver has no .uptnl loader.
    let resolver = BulkDataResolver::new_for_test(&uasset, 100, 0);
    match resolver.resolve(&record, "test.uasset") {
        Err(crate::PaksmithError::AssetParse {
            fault: crate::AssetParseFault::MissingCompanionFile {
                kind: crate::error::CompanionFileKind::Uptnl,
            },
            ..
        }) => {}
        other => panic!("expected MissingCompanionFile(Uptnl), got {other:?}"),
    }
}

#[test]
fn resolve_rejects_unsupported_lzo() {
    let uasset = vec![0u8; 100];
    let record = FByteBulkData {
        flags: BulkDataFlags(FLAG_PAYLOAD_AT_END_OF_FILE | FLAG_COMPRESSED_LZO),
        element_count: 8,
        size_on_disk: 8,
        offset_in_file: 0,
    };
    let resolver = BulkDataResolver::new_for_test(&uasset, 100, 0);
    match resolver.resolve(&record, "test.uasset") {
        Err(crate::PaksmithError::AssetParse {
            fault: crate::AssetParseFault::UnsupportedBulkCompression { method },
            ..
        }) => assert_eq!(method, "LZO"),
        other => panic!("expected UnsupportedBulkCompression(LZO), got {other:?}"),
    }
}
```

- [ ] **Step 2: Implement `BulkDataResolver`.**

```rust
/// Resolves `FByteBulkData` records into materialized payload bytes
/// across all three storage tiers (inline, uexp-resident, streaming).
///
/// Construct via `Package::read_from_pak`'s integration code. Test
/// helpers use [`Self::new_for_test`] (gated on `__test_utils`).
pub struct BulkDataResolver {
    /// Stitched `.uasset` + `.uexp` bytes; offsets index this buffer.
    /// `Arc<[u8]>` (NOT `&'a [u8]`) because the resolver lives inside
    /// `Package`, which owns the stitched bytes via an `Arc<[u8]>` —
    /// borrowing from a sibling field would require Pin / ouroboros /
    /// yoke. `Arc` clones are one refcount bump; size is identical
    /// (16 bytes fat-pointer on 64-bit) to `&'a [u8]`.
    stitched: std::sync::Arc<[u8]>,
    /// `summary.total_header_size` — boundary between inline (uasset)
    /// and uexp-resident tiers.
    total_header_size: u64,
    /// `summary.bulk_data_start_offset` — applied to offsets unless
    /// `BULKDATA_NoOffsetFixUp` is set.
    bulk_data_start_offset: i64,
    /// Lazy-loaded `.ubulk` bytes (Some after at least one streaming-
    /// tier record was resolved). Behind a OnceLock so resolution
    /// across multiple records pays the lookup cost once. Closure
    /// is `'static` because the resolver is `'static` (owns Arc<[u8]>
    /// rather than borrowing).
    ubulk_loader: Box<dyn Fn() -> crate::Result<Vec<u8>> + Send + Sync + 'static>,
    ubulk_cache: std::sync::OnceLock<Vec<u8>>,
    /// Lazy-loaded `.uptnl` bytes (mirrors `.ubulk` for the
    /// `BULKDATA_OptionalPayload` tier).
    uptnl_loader: Box<dyn Fn() -> crate::Result<Vec<u8>> + Send + Sync + 'static>,
    uptnl_cache: std::sync::OnceLock<Vec<u8>>,
    /// Cumulative resolved bytes across all `resolve()` calls.
    /// Enforces `MAX_TOTAL_BULK_DATA_BYTES_PER_PACKAGE` — incremented
    /// after every successful resolution; on overflow → fire
    /// `BulkDataPackageBudgetExceeded` BEFORE returning the bytes.
    /// AtomicU64 because the resolver is `Send + Sync` (see Send/Sync
    /// design note below) and concurrent resolvers across exports
    /// share a single budget.
    bytes_resolved: std::sync::atomic::AtomicU64,
}

impl BulkDataResolver {
    /// Production constructor. `ubulk_loader` / `uptnl_loader` are
    /// closures that open the respective companion (via
    /// `PakReader::read_entry`) on first matching-tier resolution.
    /// Both closures should fire `MissingCompanionFile { kind: ... }`
    /// when the companion isn't in the pak.
    ///
    /// **The closures MUST be `Send + Sync`.** Phase 5 (async runtime)
    /// and Phase 7 (GUI Iced commands) move `Package` across thread
    /// boundaries; a non-Send resolver would force every consumer to
    /// stay single-threaded. `PakReader` is already `Send + Sync` per
    /// Phase 1; closures borrowing it through a captured `&PakReader`
    /// satisfy the bound automatically.
    pub(crate) fn new<U, T>(
        stitched: std::sync::Arc<[u8]>,
        total_header_size: u64,
        bulk_data_start_offset: i64,
        ubulk_loader: U,
        uptnl_loader: T,
    ) -> Self
    where
        U: Fn() -> crate::Result<Vec<u8>> + Send + Sync + 'static,
        T: Fn() -> crate::Result<Vec<u8>> + Send + Sync + 'static,
    {
        Self {
            stitched,
            total_header_size,
            bulk_data_start_offset,
            ubulk_loader: Box::new(ubulk_loader),
            ubulk_cache: std::sync::OnceLock::new(),
            uptnl_loader: Box::new(uptnl_loader),
            uptnl_cache: std::sync::OnceLock::new(),
            bytes_resolved: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Test-only constructor. Both companion loaders fire
    /// `MissingCompanionFile` so tests not exercising streaming /
    /// optional-streaming tiers don't accidentally hit a hidden
    /// load path. Use [`Self::new_for_test_with_uptnl`] when the
    /// test needs `.uptnl` bytes.
    ///
    /// Closures are `Fn() + Send + Sync` automatically (they capture
    /// nothing and don't share state).
    /// Test-only constructor. Accepts anything convertible to
    /// `Arc<[u8]>` so callers can pass `&[u8]` / `Vec<u8>` /
    /// `Box<[u8]>` etc. without an explicit `Arc::from()` step at
    /// every test site. Each call pays one `Arc<[u8]>` allocation
    /// (negligible at test scale).
    #[cfg(feature = "__test_utils")]
    pub fn new_for_test(stitched: impl Into<std::sync::Arc<[u8]>>, total_header_size: u64, bulk_data_start_offset: i64) -> Self {
        Self::new(
            stitched.into(),
            total_header_size,
            bulk_data_start_offset,
            || Err(crate::PaksmithError::AssetParse {
                asset_path: "test".to_string(),
                fault: crate::AssetParseFault::MissingCompanionFile {
                    kind: crate::error::CompanionFileKind::Ubulk,
                },
            }),
            || Err(crate::PaksmithError::AssetParse {
                asset_path: "test".to_string(),
                fault: crate::AssetParseFault::MissingCompanionFile {
                    kind: crate::error::CompanionFileKind::Uptnl,
                },
            }),
        )
    }

    /// Test-only constructor supplying `.uptnl` bytes inline. Used
    /// by `resolve_optional_streaming_loads_from_uptnl` and similar.
    /// `move || Ok(uptnl.clone())` is `Send + Sync` because the
    /// captured `Vec<u8>` is itself `Send + Sync`.
    #[cfg(feature = "__test_utils")]
    pub fn new_for_test_with_uptnl(
        stitched: impl Into<std::sync::Arc<[u8]>>,
        total_header_size: u64,
        bulk_data_start_offset: i64,
        uptnl: Vec<u8>,
    ) -> Self {
        Self::new(
            stitched.into(),
            total_header_size,
            bulk_data_start_offset,
            || Err(crate::PaksmithError::AssetParse {
                asset_path: "test".to_string(),
                fault: crate::AssetParseFault::MissingCompanionFile {
                    kind: crate::error::CompanionFileKind::Ubulk,
                },
            }),
            move || Ok(uptnl.clone()),
        )
    }

    /// Resolve a single record. Dispatches by tier and applies
    /// compression decode if requested.
    ///
    /// # Errors
    /// Any [`crate::PaksmithError`] from offset arithmetic, OOB
    /// checks, compression decode, or `.ubulk` loading.
    pub fn resolve(&self, record: &FByteBulkData, asset_path: &str) -> crate::Result<BulkData> {
        if record.flags.is_lzo_compressed() {
            return Err(crate::PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: crate::AssetParseFault::UnsupportedBulkCompression { method: "LZO" },
            });
        }
        if record.flags.is_bitwindow_compressed() {
            return Err(crate::PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: crate::AssetParseFault::UnsupportedBulkCompression { method: "BitWindow" },
            });
        }

        // Offset fix-up.
        let resolved_offset: u64 = if record.flags.no_offset_fixup() {
            // No fixup — offset is the raw value. Reject if negative.
            if record.offset_in_file < 0 {
                return Err(crate::PaksmithError::AssetParse {
                    asset_path: asset_path.to_string(),
                    fault: crate::AssetParseFault::BulkDataOffsetFixupOverflow {
                        offset: record.offset_in_file,
                        fixup: 0,
                    },
                });
            }
            #[allow(clippy::cast_sign_loss, reason = "validated >= 0 above")]
            { record.offset_in_file as u64 }
        } else {
            let fixed = record.offset_in_file.checked_add(self.bulk_data_start_offset).ok_or_else(|| {
                crate::PaksmithError::AssetParse {
                    asset_path: asset_path.to_string(),
                    fault: crate::AssetParseFault::BulkDataOffsetFixupOverflow {
                        offset: record.offset_in_file,
                        fixup: self.bulk_data_start_offset,
                    },
                }
            })?;
            if fixed < 0 {
                return Err(crate::PaksmithError::AssetParse {
                    asset_path: asset_path.to_string(),
                    fault: crate::AssetParseFault::BulkDataOffsetFixupOverflow {
                        offset: record.offset_in_file,
                        fixup: self.bulk_data_start_offset,
                    },
                });
            }
            #[allow(clippy::cast_sign_loss, reason = "validated >= 0 above")]
            { fixed as u64 }
        };

        // Tier dispatch.
        // `source_bytes: &[u8]` deref from either Arc<[u8]> (inline /
        // uexp-resident) or the OnceLock-cached companion Vec<u8>
        // (streaming / optional-streaming). The Arc keeps the borrow
        // checker happy — the resolver owns its stitched bytes, and
        // the slice lifetime ties to &self.
        let (tier, source_bytes): (BulkDataTier, &[u8]) = if record.flags.payload_in_separate_file() {
            if record.flags.optional_payload() {
                // OptionalStreaming — load .uptnl lazily.
                let uptnl = self.uptnl()?;
                (BulkDataTier::OptionalStreaming, uptnl)
            } else {
                // Streaming — load .ubulk lazily.
                let ubulk = self.ubulk()?;
                (BulkDataTier::Streaming, ubulk)
            }
        } else if record.flags.payload_at_end_of_file() {
            // Inline vs uexp-resident — disambiguate by offset.
            if resolved_offset < self.total_header_size {
                (BulkDataTier::Inline, &self.stitched[..])
            } else {
                (BulkDataTier::UexpResident, &self.stitched[..])
            }
        } else {
            // Flags valid (passed validate() above) but no tier-routing
            // bit set. Distinct from `UnknownBulkDataFlags` (reserved
            // bits set) — this is "well-formed flags, no source-file
            // routing." Surface a typed error so the operator sees the
            // tier-bit gap.
            return Err(crate::PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: crate::AssetParseFault::BulkDataNoTierFlag { flags: record.flags.0 },
            });
        };

        // Bounds check resolved_offset + size_on_disk against source slice.
        let end = resolved_offset.checked_add(record.size_on_disk).ok_or_else(|| {
            crate::PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: crate::AssetParseFault::BulkDataEndOffsetOverflow {
                    offset: resolved_offset,
                    size: record.size_on_disk,
                },
            }
        })?;
        if end > source_bytes.len() as u64 {
            return Err(crate::PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: crate::AssetParseFault::BulkDataOffsetOob {
                    tier,
                    offset: resolved_offset,
                    size: record.size_on_disk,
                    file_size: source_bytes.len() as u64,
                },
            });
        }

        let raw = &source_bytes[resolved_offset as usize..end as usize];

        // **Budget check BEFORE allocation.** The earlier R1 design
        // ran the check after `decompress_zlib` produced an 8 GiB
        // Vec, allowing peak heap to reach 24 GiB before rejection.
        // Move the accumulator update to happen against the CLAIMED
        // size from the wire record (`record.size_on_disk` for
        // uncompressed; `record.element_count` for compressed, which
        // is the decompressed-byte claim) BEFORE the actual
        // materialization. On err, no allocation has happened; on
        // ok, the actual bytes fit within the already-reserved budget.
        let claimed_size: u64 = if record.flags.is_zlib_compressed() {
            // For compressed records, ElementCount is the
            // decompressed-byte claim (per mips-and-streaming.md:78
            // "Number of elements (bytes for byte bulk data)").
            // Already sign-checked at FByteBulkData::read_from.
            record.element_count as u64
        } else {
            record.size_on_disk
        };

        use std::sync::atomic::Ordering;
        // Relaxed ordering: bytes_resolved is a pure counter with no
        // happens-before relationship to other memory; SeqCst's
        // barriers are wasted (zero on x86, ~5-10ns on ARM64).
        let prev = self.bytes_resolved.fetch_add(claimed_size, Ordering::Relaxed);
        // checked_add (NOT saturating_add) so the error variant
        // reports a coherent value even at the impossible-to-reach
        // u64-overflow point. None == over-budget by definition;
        // Some(now) > cap == over-budget per the explicit check.
        let over_budget = match prev.checked_add(claimed_size) {
            Some(now) if now <= crate::seams::MAX_TOTAL_BULK_DATA_BYTES_PER_PACKAGE => false,
            Some(now) => {
                self.bytes_resolved.fetch_sub(claimed_size, Ordering::Relaxed);
                return Err(crate::PaksmithError::AssetParse {
                    asset_path: asset_path.to_string(),
                    fault: crate::AssetParseFault::BulkDataPackageBudgetExceeded {
                        resolved: now,
                        cap: crate::seams::MAX_TOTAL_BULK_DATA_BYTES_PER_PACKAGE,
                    },
                });
            }
            None => true,
        };
        if over_budget {
            // u64 overflow path — unreachable in practice given
            // MAX_BULK_DATA_RECORDS_PER_EXPORT and per-record cap,
            // but defensive code keeps the invariant explicit.
            self.bytes_resolved.fetch_sub(claimed_size, Ordering::Relaxed);
            return Err(crate::PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: crate::AssetParseFault::BulkDataPackageBudgetExceeded {
                    resolved: u64::MAX,
                    cap: crate::seams::MAX_TOTAL_BULK_DATA_BYTES_PER_PACKAGE,
                },
            });
        }
        // **No tracing events or other side effects between the
        // fetch_add and the materialization.** Side effects between
        // the increment and (possible) rollback would not be undone.

        // Compression dispatch. Allocation happens here, AFTER the
        // budget is reserved.
        let bytes = if record.flags.is_zlib_compressed() {
            decompress_zlib(raw, record.element_count, asset_path).map_err(|e| {
                // Decompression failed — roll back the budget reserve
                // so subsequent resolves see a consistent count.
                self.bytes_resolved.fetch_sub(claimed_size, Ordering::Relaxed);
                e
            })?
        } else {
            raw.to_vec()
        };

        Ok(BulkData {
            bytes,
            record: record.clone(),
            tier,
        })
    }

    fn ubulk(&self) -> crate::Result<&[u8]> {
        if let Some(bytes) = self.ubulk_cache.get() {
            return Ok(bytes);
        }
        let loaded = (self.ubulk_loader)()?;
        let _ = self.ubulk_cache.set(loaded);
        Ok(self.ubulk_cache.get().expect("just set"))
    }

    fn uptnl(&self) -> crate::Result<&[u8]> {
        if let Some(bytes) = self.uptnl_cache.get() {
            return Ok(bytes);
        }
        let loaded = (self.uptnl_loader)()?;
        let _ = self.uptnl_cache.set(loaded);
        Ok(self.uptnl_cache.get().expect("just set"))
    }
}

fn decompress_zlib(compressed: &[u8], expected_size: i64, asset_path: &str) -> crate::Result<Vec<u8>> {
    use flate2::read::ZlibDecoder;
    use std::io::Read;

    // ElementCount was already sign-checked at FByteBulkData::read_from
    // (3b Task 3). Defense in depth: re-assert here so this function
    // is safe-by-construction if called from a future site that
    // bypasses the read-side check.
    if expected_size < 0 {
        return Err(crate::PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: crate::AssetParseFault::BulkDataElementCountNegative { count: expected_size },
        });
    }
    let expected = expected_size as u64;

    let mut decoder = ZlibDecoder::new(compressed);
    let mut out: Vec<u8> = if expected > 0 && expected <= crate::seams::MAX_BULK_DATA_SIZE {
        Vec::with_capacity(expected as usize)
    } else {
        Vec::new()
    };
    // Bound the read by MAX_BULK_DATA_SIZE so a 1-byte-of-input →
    // 8-GiB-of-output decompression bomb dies early.
    let mut limited = decoder.take(crate::seams::MAX_BULK_DATA_SIZE);
    limited.read_to_end(&mut out).map_err(|e| crate::PaksmithError::AssetParse {
        asset_path: asset_path.to_string(),
        fault: crate::AssetParseFault::CompressionDecodeFailed {
            method: "zlib",
            reason: e.to_string(),
        },
    })?;
    // Post-decompress length check: a truncated stream produces fewer
    // bytes than ElementCount claims; a too-long stream produces more.
    // Either is wire-corruption-or-attack; surface as a typed error.
    if out.len() as u64 != expected {
        return Err(crate::PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: crate::AssetParseFault::BulkDataDecompressLengthMismatch {
                expected: expected_size,
                actual: out.len(),
            },
        });
    }
    Ok(out)
}
```

> `AssetParseFault::CompressionDecodeFailed` and `InvalidOffset` already exist from Phase 1/2; reuse them. If not, add as part of this task.

- [ ] **Step 3: Run.** `cargo test -p paksmith-core --features __test_utils asset::bulk_data::tests::resolve 2>&1 | tail -15`.

- [ ] **Step 4: Lint + test + doc gate.** Same shell block as Task 1 Step 5.

- [ ] **Step 5: Commit.**

```bash
git add crates/paksmith-core/src/asset/bulk_data.rs
git commit -m "$(cat <<'EOF'
feat(bulk-data): BulkDataResolver — tier dispatch + zlib + cap-checks

Inline / uexp-resident / streaming dispatch with checked_add on every
offset arithmetic site. .uptnl / LZO / BitWindow / Oodle all surface
as typed errors.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 6: Wire resolver into `Package::read_from_pak` — remove the Phase 2e warn

**Files:**

- Modify: `crates/paksmith-core/src/asset/package.rs`.

- [ ] **Step 1: Delete the `tracing::warn!` at lines 654-672.**

Replace with:

```rust
// Phase 3b: detect .ubulk and .uptnl; supply the resolver with both
// loader closures. Each companion opens lazily on first matching-tier
// resolution. Closures MUST be `'static` (Send + Sync bound from
// resolver) — capture cloned `Arc<PakReader>`, NOT `&reader`.
let ubulk_path = derive_companion_path(virtual_path, ".ubulk");
let uptnl_path = derive_companion_path(virtual_path, ".uptnl");
let virtual_path_owned = virtual_path.to_string();

// PakReader is already Arc-shareable via Phase 1 design (Send + Sync).
// Clone the Arc into each closure rather than capturing &reader,
// which would not satisfy 'static.
let reader_for_ubulk = std::sync::Arc::clone(&reader);
let ubulk_path_for_closure = ubulk_path.clone();
let virtual_for_ubulk = virtual_path_owned.clone();
let ubulk_loader = move || -> crate::Result<Vec<u8>> {
    match reader_for_ubulk.read_entry(&ubulk_path_for_closure) {
        Ok(bytes) => Ok(bytes),
        Err(PaksmithError::EntryNotFound { .. }) => Err(PaksmithError::AssetParse {
            asset_path: virtual_for_ubulk.clone(),
            fault: AssetParseFault::MissingCompanionFile {
                kind: crate::error::CompanionFileKind::Ubulk,
            },
        }),
        Err(e) => Err(e),
    }
};

let reader_for_uptnl = std::sync::Arc::clone(&reader);
let uptnl_path_for_closure = uptnl_path.clone();
let virtual_for_uptnl = virtual_path_owned.clone();
let uptnl_loader = move || -> crate::Result<Vec<u8>> {
    match reader_for_uptnl.read_entry(&uptnl_path_for_closure) {
        Ok(bytes) => Ok(bytes),
        Err(PaksmithError::EntryNotFound { .. }) => Err(PaksmithError::AssetParse {
            asset_path: virtual_for_uptnl.clone(),
            fault: AssetParseFault::MissingCompanionFile {
                kind: crate::error::CompanionFileKind::Uptnl,
            },
        }),
        Err(e) => Err(e),
    }
};
```

- [ ] **Step 0: Prerequisite — wrap `PakReader::open` result in `Arc::new` at the `Package::read_from_pak` call site.**

Phase 1's `PakReader::open` returns `Result<PakReader>` (verified against current source). The R2 closure design requires `'static`-bound closures that capture cloned `Arc<PakReader>` (not `&reader`). So before the closures land:

```rust
// In Package::read_from_pak, change:
//   let reader = PakReader::open(pak_path)?;
// to:
let reader = std::sync::Arc::new(PakReader::open(pak_path)?);
```

This is a one-line change at one call site (`asset/package.rs::Package::read_from_pak`) — NOT a Phase 1 API surface change. `PakReader` remains as-is; the wrapping happens at the caller. Downstream uses of `reader.read_entry()` (e.g. existing uexp / ubulk detection at `package.rs:642-672`) continue to work via `Arc<PakReader>`'s auto-deref to `&PakReader`.

This step is blocking — without it, the closures in Step 1 don't compile.

- [ ] **Step 2: Construct the resolver in `read_from`, pass it through to `read_payloads`.**

`Package::read_from` already builds `summary`, `names`, `imports`, `exports`. Add resolver construction immediately after `summary` is read:

```rust
// Convert the stitched `Vec<u8>` (owned by Package's read pipeline)
// into the resolver's `Arc<[u8]>` form. `Vec::into_boxed_slice()`
// is alloc-free ONLY when `vec.capacity() == vec.len()` — otherwise
// it calls `shrink_to_fit()` first, which reallocates AND memcpys
// the full payload. **Pin the stitching invariant** so the bytes
// Vec is exactly-sized:
//
//   let mut bytes = Vec::with_capacity(uasset.len() + uexp.len().unwrap_or(0));
//   bytes.extend_from_slice(uasset);
//   if let Some(uexp_bytes) = uexp { bytes.extend_from_slice(uexp_bytes); }
//   // bytes.capacity() == bytes.len() — no reallocation on the line below.
//
// If for any reason the stitching site over-reserves capacity,
// add `bytes.shrink_to_fit()` BEFORE `into_boxed_slice()` to make
// the reallocation explicit at the source, not implicit here.
let stitched: std::sync::Arc<[u8]> = std::sync::Arc::from(bytes.into_boxed_slice());
let resolver = BulkDataResolver::new(
    stitched,
    summary.total_header_size as u64,
    summary.bulk_data_start_offset,
    ubulk_loader,
    uptnl_loader,
);
```

If `Package::read_from`'s top-level `bytes` parameter is still `&[u8]` from Phase 2's signature, change it to `Vec<u8>` here (or `Arc<[u8]>` directly). The Phase 2 callers that pass `&bytes` to `read_from` need to either `bytes.to_vec()` or pass through an `Arc<[u8]>` end-to-end — choose at TDD kickoff based on caller cascade impact. Phase 1 callers (`Package::read_from_pak` via `reader.read_entry()`) already get a `Vec<u8>` from `read_entry`, so the `read_from` signature change is trivial on that path; only test callers in Phase 2's `__test_utils` suite need `bytes.to_vec()` if they were passing `&bytes`.

For the `read_from_pak` entry point, the resolver uses the real `.ubulk` loader closure from Step 1. For the lower-level `read_from` (which accepts raw bytes), the resolver gets a closure that always errors — `read_from` is for unit-test paths where streaming-tier records aren't expected. If a streaming-tier record IS encountered, the resolver fires the typed error.

- [ ] **Step 3: Add lazy bulk-data fields + accessor to `Package`.**

`Package` carries TWO sparse maps + the resolver instance: one for parsed records (eager), one for resolved bytes (lazy via `OnceLock`). The accessor `resolve_bulk_for_export` is the only path that drives I/O on companion files. `paksmith inspect` never calls it; the typed readers in 3e/3g/3h call it on-demand from inside their format-handler `export()` paths (not their parse-time `read_from` paths).

```rust
use std::collections::HashMap;
use std::sync::OnceLock;

pub struct Package {
    // ...existing fields...

    /// `FByteBulkData` records + lazy-resolved bytes per export.
    /// Sparse: keys are export indices that carry bulk records.
    /// **Single map with tuple values** (NOT two parallel maps) so
    /// the records and the cache slot are always in lockstep — no
    /// "records present but cache slot missing" failure mode.
    /// Populated by 3e/3g/3h typed readers via `Package::insert_bulk_records`.
    pub(crate) bulk_data: HashMap<usize, (Vec<FByteBulkData>, OnceLock<Vec<BulkData>>)>,

    /// The resolver itself, holding the stitched buffer + companion
    /// loader closures + per-package byte budget accumulator. Lives
    /// for the package's lifetime; cheap to construct. Owns its
    /// stitched bytes via `Arc<[u8]>` so no lifetime parameter
    /// propagates through `Package`.
    ///
    /// **`Arc<BulkDataResolver>` (NOT owned), to preserve the
    /// `MAX_TOTAL_BULK_DATA_BYTES_PER_PACKAGE` cap under `Package::Clone`.**
    /// `Package` derives `Clone` for downstream convenience (the GUI
    /// clones Packages across event-loop ticks; tests clone freely).
    /// If the resolver were owned, `Package::clone()` would deep-copy
    /// the `AtomicU64::bytes_resolved` accumulator at its current
    /// value, then each clone would accumulate against its own fresh
    /// 16 GiB headroom — multiplying the effective budget. Sharing
    /// via Arc means every clone observes the same atomic counter.
    pub(crate) resolver: std::sync::Arc<BulkDataResolver>,
}

impl Package {
    /// 3e/3g/3h typed-reader hook: insert the FByteBulkData records
    /// collected during parse for `export_idx`. The cache slot is
    /// created alongside in the same insert, so subsequent
    /// `resolve_bulk_for_export` calls can never miss the cache
    /// half of the pair.
    ///
    /// **Defensive cap enforcement:** `records.len()` is checked
    /// against `MAX_BULK_DATA_RECORDS_PER_EXPORT` here so the cap
    /// fires even for export classes outside 3e/3g/3h's planned
    /// coverage (e.g. a future class added without security review,
    /// or a generic-class path that constructs records). Per
    /// Design Decision #15.
    ///
    /// # Errors
    /// [`crate::AssetParseFault::BulkDataRecordsExceeded`] when
    /// records.len() exceeds the cap.
    pub(crate) fn insert_bulk_records(
        &mut self,
        export_idx: usize,
        records: Vec<FByteBulkData>,
    ) -> crate::Result<()> {
        if records.len() > crate::seams::MAX_BULK_DATA_RECORDS_PER_EXPORT {
            return Err(crate::PaksmithError::AssetParse {
                asset_path: self.asset_path.clone(),
                fault: crate::AssetParseFault::BulkDataRecordsExceeded {
                    count: records.len(),
                    cap: crate::seams::MAX_BULK_DATA_RECORDS_PER_EXPORT,
                },
            });
        }
        self.bulk_data.insert(export_idx, (records, OnceLock::new()));
        Ok(())
    }

    /// Resolve all bulk-data records for the given export. On first
    /// call, runs the resolver against each record and caches the
    /// result. Subsequent calls return the cached slice in O(1).
    ///
    /// Returns an empty slice for exports with no bulk records.
    ///
    /// # Errors
    /// Any [`crate::PaksmithError`] from the resolver (cap exceeded,
    /// companion missing, decompression failure, etc.). Errors are
    /// NOT cached — a failing resolve attempts again on next call.
    /// (Intentional: a transient I/O failure shouldn't poison the
    /// export forever.)
    pub fn resolve_bulk_for_export(&self, export_idx: usize) -> crate::Result<&[BulkData]> {
        let Some((records, cache)) = self.bulk_data.get(&export_idx) else {
            return Ok(&[]);
        };
        // OnceLock-cached resolution. On miss, walk records, resolve
        // each, and store. On hit, return cached slice.
        if let Some(cached) = cache.get() {
            return Ok(cached.as_slice());
        }
        let mut resolved = Vec::with_capacity(records.len());
        for record in records {
            resolved.push(self.resolver.resolve(record, &self.asset_path)?);
        }
        // set() can race with another thread; if set fails, get()
        // will return the already-set value. Either way the result
        // is observed.
        let _ = cache.set(resolved);
        Ok(cache.get().expect("just set or raced").as_slice())
    }
}
```

For Phase 3b proper, the typed-reader sites in 3e/3g/3h are what call `FByteBulkData::read_from` mid-parse and populate `bulk_records`. Phase 3b ships the maps as empty. The 3e/3g/3h plans pin the population sites in their TDD steps.

- [ ] **Step 4: Run full test suite, verify Phase 2e's warn no longer fires.**

```shell
set -o pipefail
cargo test --workspace --all-features 2>&1 | tail -20
```

The existing `tracing-test`-captured warn assertion (if any) in Phase 2e tests will need to be removed or updated — search for `"'.ubulk' companion found but bulk data stitching"` and replace the assertion with one that checks the warn is NOT fired.

- [ ] **Step 5: Lint + test + doc gate.** Same shell block as Task 1 Step 5.

- [ ] **Step 6: Commit.**

```bash
git add crates/paksmith-core/src/asset/package.rs
git commit -m "$(cat <<'EOF'
feat(asset): wire BulkDataResolver into Package::read_from_pak

Removes Phase 2e's "ubulk not yet stitched" warn. Package now carries
Vec<Vec<BulkData>> per export; populated by 3e/3g typed readers.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 7: Fixture-gen extension + integration tests

**Files:**

- Modify: `crates/paksmith-fixture-gen/src/uasset.rs` (or similar — locate the existing fixture builder).
- Create: `crates/paksmith-core-tests/tests/bulk_data_integration.rs`.

- [ ] **Step 1: Add `build_minimal_uasset_with_bulk_data(tier: BulkDataTier)` to fixture-gen.**

Produces a synthetic `.uasset` (+ `.uexp`/`.ubulk` as needed) with one `FByteBulkData` record at the requested tier and a 16-byte payload. Cross-validate against CUE4Parse — Phase 3 spec requires CUE4Parse parity; the exact cross-validation tooling lands here (candidates: shelling out to a CUE4Parse CLI binary, or pinning a small Rust harness against pre-cooked reference outputs).

Per `feedback_format_docs_are_not_implementation_status.md`: the fixture-count gate at `.github/workflows/ci.yml` will need bumping for each new committed `.pak` fixture. Bump in same PR.

- [ ] **Step 2: Write integration tests covering each tier.**

```rust
// tests/bulk_data_integration.rs
use paksmith_core::asset::Package;
use paksmith_core::asset::bulk_data::BulkDataTier;

#[test]
fn inline_bulk_data_resolves_from_uasset() {
    let pak = include_bytes!("../../tests/fixtures/minimal_inline_bulk.pak");
    let pkg = Package::read_from_pak_bytes(pak, "Game/Test.uasset", None).expect("read");
    let records = pkg.bulk_data_for_export(0).expect("export 0 has bulk records");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].tier, BulkDataTier::Inline);
    assert_eq!(records[0].bytes.len(), 16);
}

#[test]
fn uexp_resident_bulk_data_resolves_from_uexp() {
    let pak = include_bytes!("../../tests/fixtures/minimal_uexp_resident_bulk.pak");
    let pkg = Package::read_from_pak_bytes(pak, "Game/Test.uasset", None).expect("read");
    let records = pkg.bulk_data_for_export(0).expect("export 0 has bulk records");
    assert_eq!(records[0].tier, BulkDataTier::UexpResident);
}

#[test]
fn streaming_bulk_data_resolves_from_ubulk() {
    let pak = include_bytes!("../../tests/fixtures/minimal_streaming_bulk.pak");
    let pkg = Package::read_from_pak_bytes(pak, "Game/Test.uasset", None).expect("read");
    let records = pkg.bulk_data_for_export(0).expect("export 0 has bulk records");
    assert_eq!(records[0].tier, BulkDataTier::Streaming);
}

#[test]
fn optional_streaming_bulk_data_resolves_from_uptnl() {
    let pak = include_bytes!("../../tests/fixtures/minimal_optional_streaming_bulk.pak");
    let pkg = Package::read_from_pak_bytes(pak, "Game/Test.uasset", None).expect("read");
    let records = pkg.bulk_data_for_export(0).expect("export 0 has bulk records");
    assert_eq!(records[0].tier, BulkDataTier::OptionalStreaming);
}

#[test]
fn missing_ubulk_when_streaming_record_present_errors_typed() {
    // .pak contains the .uasset with a streaming-tier record but no .ubulk.
    let pak = include_bytes!("../../tests/fixtures/streaming_bulk_no_ubulk.pak");
    match Package::read_from_pak_bytes(pak, "Game/Test.uasset", None) {
        Err(paksmith_core::PaksmithError::AssetParse {
            fault: paksmith_core::AssetParseFault::MissingCompanionFile { kind, .. },
            ..
        }) => assert_eq!(kind, paksmith_core::error::CompanionFileKind::Ubulk),
        other => panic!("expected MissingCompanionFile(Ubulk), got {other:?}"),
    }
}
```

- [ ] **Step 3: Bump CI's fixture-count gate.**

Per `feedback_fixture_count_gate.md`: `.github/workflows/ci.yml` carries a hardcoded `expected=N` count for `tests/fixtures/*.pak`. Bump by +5 (the five new fixtures — inline, uexp-resident, streaming, optional-streaming, streaming-no-ubulk).

- [ ] **Step 4: Lint + test + doc gate.** Same shell block as Task 1 Step 5.

- [ ] **Step 5: Commit.**

```bash
git add crates/paksmith-fixture-gen/src/uasset.rs tests/fixtures/minimal_inline_bulk.pak tests/fixtures/minimal_uexp_resident_bulk.pak tests/fixtures/minimal_streaming_bulk.pak tests/fixtures/minimal_optional_streaming_bulk.pak tests/fixtures/streaming_bulk_no_ubulk.pak crates/paksmith-core-tests/tests/bulk_data_integration.rs .github/workflows/ci.yml
git commit -m "$(cat <<'EOF'
test(bulk-data): fixture-gen + 5 tier-coverage integration tests

Closes Phase 3b. Each of the four tiers (inline / uexp-resident /
streaming / optional-streaming) has a synthetic fixture + integration
test. Missing .ubulk produces a typed MissingCompanionFile error.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Review panel (Phase 3b specifics)

Per `feedback_specialist_reviewers_default.md` four-trigger walk:

- **Wire-format pass** — MANDATORY. 3b parses `FByteBulkData` from on-wire bytes. Cross-validate against CUE4Parse references in the format docs.
- **Security pass** — MANDATORY. Offset arithmetic, attacker-controllable `OffsetInFile`/`SizeOnDisk` fields, cap rejection paths, OOB checks. Highest-priority specialist for 3b.
- **Deep-impact tracer** — MANDATORY for Task 4 (replaces 3a's placeholder type) and Task 6 (changes `Package` shape).
- **Performance** — soft trigger. The resolver's `OnceLock`-cached `.ubulk` load matters but isn't a hot loop. Optional.

Total reviewers per task: 5 (standard 3 + wire-format + security), 6 for Task 4 and Task 6 (+ deep-impact).

Convergence loop per Phase 2g's standard.

---

## After 3b lands

- `Package::bulk_data` exists and is populated by typed readers in 3e/3g.
- The Phase 2e warn is gone; replaced by real resolution + typed errors for malformed/missing companions.
- 3e (texture mips) and 3g (mesh vertex buffers) can construct + consume `BulkDataResolver` references.
- The `.uptnl` deferred path stays surfaced as `UnsupportedOptionalPayload` until a downstream sub-phase requires it.

---

## References

- Master index: [`phase-3-export-pipeline.md`](phase-3-export-pipeline.md).
- Wire-format reference: [`../formats/texture/mips-and-streaming.md`](../formats/texture/mips-and-streaming.md) §`FByteBulkData` + §`BulkDataFlags`.
- Current ubulk detection: `crates/paksmith-core/src/asset/package.rs:654-672`.
- Existing zlib decompressor (reuse target): `crates/paksmith-core/src/container/pak/mod.rs` (per the format doc's note at mips-and-streaming.md:195).
- Phase 2e companion-file plan (historical context): [`phase-2e-companion-files.md`](phase-2e-companion-files.md).
