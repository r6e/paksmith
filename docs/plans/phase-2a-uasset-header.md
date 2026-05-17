# Paksmith Phase 2a: UAsset Header & Tables Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Parse the UAsset package header (FPackageFileSummary, FName table, FObjectImport table, FObjectExport table) for UE 4.21–UE 5.x assets stored inside `.pak` archives, and surface the structure via a new `paksmith inspect <pak> <virtual/path>` CLI command. Property bodies stay opaque (raw bytes) in this milestone — tagged-property iteration lands in Phase 2b.

**Architecture:** New `paksmith-core::asset` module mirroring the structure of `paksmith-core::container::pak`: a typed wire-format parser per component (name table, import table, export table, package summary), an `AssetContext` bundle threading version + tables through downstream parsers, and a top-level `Package` aggregate. Errors promote `PaksmithError::AssetParse`'s placeholder `reason: String` to a typed `AssetParseFault` sub-enum (same pattern as `IndexParseFault`/`DecompressionFault`/`InvalidFooterFault`). Cross-parser validation mirrors the Phase-1 trumank/repak pattern: `paksmith-fixture-gen` (already excluded from `default-members`) takes a new git dep on `AstroTechies/unreal_asset` and round-trips synthetic fixtures through both parsers.

**Tech Stack:** Rust 1.85, `thiserror` (typed sub-enums), `byteorder` (LE wire-format reads), `serde` (JSON output for `inspect`), `tracing` (warn-level operator visibility on caps/allocator pressure), `proptest` (property-based wire-format round-trips), `tracing-test` (capture-and-assert log events), `unreal_asset` (dev/fixture-gen only, cross-parser oracle), `clap` (CLI), `tempfile` (test isolation).

---

## Deliverable

`paksmith inspect <pak> <virtual/path>` opens the archive, finds the named entry, parses its bytes as a UAsset package, and prints a JSON document describing the package's structural header — name table, import table, export table, engine version, package flags, custom-version GUIDs — plus an opaque `payload_bytes: <N>` marker for the as-yet-unparsed export bodies.

```json
{
  "asset_path": "Game/Maps/Demo.uasset",
  "summary": {
    "version": {
      "legacy_file_version": -8,
      "file_version_ue4": 522,
      "file_version_ue5": 1004,
      "file_version_licensee_ue4": 0
    },
    "package_flags": 2147484672,
    "total_header_size": 1280,
    "folder_name": "None",
    "saved_by_engine_version": "5.1.1-0+++UE5+Release-5.1",
    "compatible_with_engine_version": "5.0.0-0+++UE5+Release-5.0",
    "custom_versions": [
      { "guid": "00000000-0000-0000-0000-000000000000", "version": 3 }
    ]
  },
  "names": ["/Script/Engine", "Default__Object", "RootComponent"],
  "imports": [
    {
      "class_package": "/Script/CoreUObject",
      "class_name": "Package",
      "outer_index": "Null",
      "object_name": "/Script/Engine"
    }
  ],
  "exports": [
    {
      "class_index": "Import(2)",
      "super_index": "Null",
      "outer_index": "Null",
      "object_name": "Default__Object",
      "serial_size": 84,
      "serial_offset": 1280
    }
  ],
  "payload_bytes": 84
}
```

> Abbreviated for readability — the real `paksmith inspect` output
> includes ~40 summary fields (header offsets, generation counts,
> editor-only opt fields) and ~22 export fields (dependency counts,
> per-export flags). See `crates/paksmith-cli/tests/snapshots/
> inspect_cli__inspect_json_snapshot.snap` for the full pinned shape.
> The example here intentionally cherry-picks the fields that pin the
> "Deliverable contract" — resolved FName strings, the `summary.
> version` nested form, `payload_bytes` as a top-level scalar.

## Scope vs deferred work

**In scope (this plan):**

- UE 4.21–UE 5.x package summary parsing (`LegacyFileVersion ∈ {-7, -8}`)
- Name table with dual-CityHash16 hashes (UE 4.21+ `VER_UE4_NAME_HASHES_SERIALIZED = 504`)
- Import table (FObjectImport: ClassPackage, ClassName, OuterIndex, ObjectName, PackageName for UE 5.1+, bImportOptional for UE 5.0+)
- Export table (FObjectExport: full v22 layout including PreloadDependency offsets, IsAsset flag)
- FPackageIndex (i32 → Null/Import/Export enum)
- Custom version container
- Engine version (FEngineVersion: major.minor.patch-changelist+branch)
- `Asset::Generic(PropertyBag::Opaque(Vec<u8>))` — payload bytes carried but not interpreted
- `paksmith inspect` CLI command + JSON output
- Cross-parser fixture validation via `unreal_asset`

**Deferred to later milestones:**

- Tagged-property iteration (FPropertyTag) — **Phase 2b**
- Primitive property payloads (Bool/Int/Float/Str/Name/Enum) — **Phase 2b**
- Container properties (Array/Map/Set/Struct + 128-deep recursion guard) — **Phase 2c**
- Object reference resolution through the import table — **Phase 2d**
- `.uexp` / `.ubulk` companion files (assets split across multiple files at SerialOffset ≥ TotalHeaderSize) — **Phase 2e**
- AES-encrypted uasset bytes — deferred indefinitely (Phase 5 once profile-keyed decryption lands)
- AssetRegistry, ThumbnailTable, GatherableTextData, SearchableNames bodies — read offsets, don't parse contents
- LegacyFileVersion ∈ {-6, -5, ...} (UE 4.16–4.20) — deferred indefinitely; rejected as `UnsupportedLegacyFileVersion`
- Property-tag-stripped ("unversioned") assets — deferred to Phase 2b alongside the versioned tag reader

## Design decisions locked here (so 2b–2e don't relitigate)

1. **Name table representation:** `Vec<Arc<str>>`. Indexes into this Vec are `u32` FName references; cloning an `FName` is one atomic refcount bump. The `Arc<str>` choice (vs `Arc<String>`) avoids the indirection-plus-cap overhead — `str` is the minimal representation. Capacity is `try_reserve_exact`'d up front from the wire-claimed `NameCount`.
2. **Property recursion depth cap:** `MAX_PROPERTY_DEPTH = 128` (matches FModel's nesting bound; Unreal in practice nests structs ≤ 12 deep but the cap exists for malicious archives). Defined in `asset::property_bag` as a `pub const` even though 2a never recurses — locks the contract for 2c.
3. **`AssetContext` shape:** owned, `Clone`-cheap. Wraps `Arc<NameTable>`, `Arc<ImportTable>`, `Arc<ExportTable>`, and a `Copy`-able `AssetVersion`. Property parsers in 2b–2d take `&AssetContext` by reference; `Clone::clone` is two `Arc::clone`s + a `Copy`. Owned rather than borrowed because the context must outlive its source `Package` (the CLI's `inspect` returns owned data; the GUI's PropertyInspector widget holds it across event-loop ticks).
4. **Structural caps (rejected before allocation):**
   - `MAX_NAME_TABLE_ENTRIES = 1_048_576` (1 Mi names)
   - `MAX_IMPORT_TABLE_ENTRIES = 524_288` (512 Ki imports)
   - `MAX_EXPORT_TABLE_ENTRIES = 524_288` (512 Ki exports)
   - `MAX_CUSTOM_VERSIONS = 1024`
   - `MAX_TOTAL_HEADER_SIZE = 256 * 1024 * 1024` (256 MiB — typical headers are <1 MiB but level/blueprint headers can balloon)
   - `MAX_FNAME_BYTE_LEN`: reuse `FSTRING_MAX_LEN = 65_536` from `container::pak::index::fstring`
5. **Error sub-enum:** `AssetParseFault` lives in `error.rs`, mirroring `IndexParseFault`. Wire-stable `Display` impl pinned by per-variant unit tests. `#[non_exhaustive]` + `PartialEq + Eq + Clone`.
6. **Top-level type names follow UE's `F*` prefix where the wire format is being mirrored 1:1** (e.g., `FPackageFileSummary` becomes `PackageSummary` in Rust — drop the F since Rust types use upper-camel and the F is just UE's struct-naming convention). Module-internal helper types (`FPackageIndex` → `PackageIndex`) follow the same rule.

7. **Security posture — paksmith reads untrusted bytes.** Every Phase-2 parser MUST treat its input as adversarial. The threat model is a crafted `.pak` / `.uasset` / `.uexp` / `.usmap` that forces paksmith into OOM, panic, infinite loop, or undefined behavior. Defensive primitives every parser uses:
   - **Reject before allocate.** Every wire-claimed count or size is compared against a structural cap (the `MAX_*` constants above) *before* any `Vec::with_capacity` / `try_reserve` call.
   - **`try_reserve` not `with_capacity`** for any allocation whose size is wire-derived. `with_capacity` aborts the process on OOM; `try_reserve` returns `Err`.
   - **`checked_add` / `checked_mul`** for offset arithmetic, surfacing overflow as `AssetParseFault::U64ArithmeticOverflow`.
   - **`usize::try_from(...)?`** when narrowing `i64` / `u64` offsets to `usize` so 32-bit targets fail loudly instead of truncating.
   - **No panic on slice indexing.** Pre-validate `start + size <= buffer.len()` before any `&buf[start..end]`; surface OOB as `AssetParseFault::InvalidOffset`.
   - **Bounded recursion** via `MAX_PROPERTY_DEPTH` and `MAX_INHERITANCE_DEPTH` (Phase 2f) plus cycle detection where the data structure is a user-supplied graph (.usmap `super_type`).
   - **Bounded decompression** via `take(N)` adapters around `brotli::Decompressor` and `zstd::stream::Decoder` (Phase 2f) so a decompression bomb can't produce GBs of output even if the header claims a smaller `decompressed_size`.

   See each phase's task list for the cap values and the rejection sites.

---

## File Structure

```plaintext
crates/paksmith-core/src/
├── asset/                              # NEW
│   ├── mod.rs                          # NEW — Asset enum, AssetContext, Package, module re-exports
│   ├── version.rs                      # NEW — AssetVersion + UE4/UE5 version constants
│   ├── engine_version.rs               # NEW — FEngineVersion parser
│   ├── custom_version.rs               # NEW — CustomVersion + CustomVersionContainer
│   ├── package_index.rs                # NEW — PackageIndex (Null/Import/Export i32 wrapper)
│   ├── name_table.rs                   # NEW — FName, NameTable, read_from
│   ├── import_table.rs                 # NEW — ObjectImport, ImportTable, read_from
│   ├── export_table.rs                 # NEW — ObjectExport, ExportTable, read_from
│   ├── summary.rs                      # NEW — PackageSummary (FPackageFileSummary), read_from
│   ├── package.rs                      # NEW — Package::read_from(bytes) + read_from_pak helper
│   ├── property_bag.rs                 # NEW — PropertyBag::Opaque, MAX_PROPERTY_DEPTH
│   ├── guid.rs                         # EMERGED — FGuid newtype + canonical 8-4-4-4-12 Display
│   ├── wire.rs                         # EMERGED — read_bool32 / write_bool32 helpers
│   └── fstring.rs                      # EMERGED — read_asset_fstring adapter (IndexParseFault → AssetParseFault)
├── container/pak/index/fstring.rs      # MODIFY — promote read_fstring from pub(super) to pub(crate)
├── error.rs                            # MODIFY — promote AssetParse to typed AssetParseFault
└── lib.rs                              # MODIFY — pub mod asset

crates/paksmith-cli/src/
├── commands/
│   ├── mod.rs                          # MODIFY — register inspect command
│   └── inspect.rs                      # NEW — `paksmith inspect` impl
└── main.rs                             # MODIFY — clap subcommand wiring

crates/paksmith-fixture-gen/src/
├── main.rs                             # MODIFY — register uasset fixture writer
└── uasset.rs                           # NEW — synthetic uasset emitter + unreal_asset cross-validation

crates/paksmith-core/tests/
├── asset_integration.rs                # NEW — open pak → parse uasset → assert JSON
└── asset_proptest.rs                   # NEW — property-based round-trip + cap rejection

tests/fixtures/
└── real_v8b_uasset.pak               # NEW — generated; one .uasset entry, known structure

ARCHITECTURE.md                         # MODIFY — promote asset/ from "planned" to "current"
README.md                               # MODIFY — add inspect to the CLI usage section
docs/plans/ROADMAP.md                   # MODIFY — mark Phase 2a complete, link this plan
```

---

### Task 1: Promote `AssetParse` placeholder to typed `AssetParseFault`

**Files:**

- Modify: `crates/paksmith-core/src/error.rs:85-98` (the existing `AssetParse` variant) — change `reason: String` to `fault: AssetParseFault`
- Modify: `crates/paksmith-core/src/error.rs` (end of file, before tests) — add `AssetParseFault` enum + `Display` impl + `AssetWireField` + `AssetOverflowSite` + `AssetAllocationContext` typed payload enums

**Why this task first:** every subsequent parser returns `Result<T, PaksmithError>` and constructs `AssetParse { fault: ..., asset_path: ... }`. Building it now means later tasks write to a stable error API rather than scaffolding placeholder strings.

**Pattern reference:** `IndexParseFault` (lines 499–820 of the same file) is the canonical sub-enum shape — read it before writing this task. The promotion mirrors issue #112's `DecompressionFault` transition.

- [ ] **Step 1: Write the failing Display-stability test**

Add to `crates/paksmith-core/src/error.rs` test module (find the existing `#[cfg(test)] mod tests` block and add inside it):

```rust
#[test]
fn asset_parse_display_invalid_magic() {
    let err = PaksmithError::AssetParse {
        asset_path: "Game/Maps/Demo.uasset".to_string(),
        fault: AssetParseFault::InvalidMagic {
            observed: 0xDEADBEEF,
            expected: 0x9E2A83C1,
        },
    };
    assert_eq!(
        format!("{err}"),
        "asset deserialization failed for `Game/Maps/Demo.uasset`: \
         invalid uasset magic: observed 0xdeadbeef, expected 0x9e2a83c1"
    );
}

#[test]
fn asset_parse_display_unsupported_legacy_version() {
    let err = PaksmithError::AssetParse {
        asset_path: "x.uasset".to_string(),
        fault: AssetParseFault::UnsupportedLegacyFileVersion { version: -6 },
    };
    assert_eq!(
        format!("{err}"),
        "asset deserialization failed for `x.uasset`: \
         unsupported legacy file version -6 (paksmith Phase 2a accepts -7 and -8)"
    );
}

#[test]
fn asset_parse_display_bounds_exceeded() {
    let err = PaksmithError::AssetParse {
        asset_path: "x.uasset".to_string(),
        fault: AssetParseFault::BoundsExceeded {
            field: AssetWireField::NameCount,
            value: 2_000_000,
            limit: 1_048_576,
            unit: BoundsUnit::Items,
        },
    };
    assert_eq!(
        format!("{err}"),
        "asset deserialization failed for `x.uasset`: \
         name_count 2000000 exceeds maximum 1048576 items"
    );
}

#[test]
fn asset_parse_display_negative_value() {
    let err = PaksmithError::AssetParse {
        asset_path: "x.uasset".to_string(),
        fault: AssetParseFault::NegativeValue {
            field: AssetWireField::NameCount,
            value: -1,
        },
    };
    assert_eq!(
        format!("{err}"),
        "asset deserialization failed for `x.uasset`: \
         name_count value -1 is negative"
    );
}

#[test]
fn asset_parse_display_package_index_oob() {
    let err = PaksmithError::AssetParse {
        asset_path: "x.uasset".to_string(),
        fault: AssetParseFault::PackageIndexOob {
            field: AssetWireField::ImportOuterIndex,
            index: 99,
            table_size: 4,
        },
    };
    assert_eq!(
        format!("{err}"),
        "asset deserialization failed for `x.uasset`: \
         import_outer_index 99 out of bounds (table has 4 entries)"
    );
}

#[test]
fn asset_parse_display_package_index_underflow() {
    let err = PaksmithError::AssetParse {
        asset_path: "x.uasset".to_string(),
        fault: AssetParseFault::PackageIndexUnderflow {
            field: AssetWireField::ImportOuterIndex,
        },
    };
    assert_eq!(
        format!("{err}"),
        "asset deserialization failed for `x.uasset`: \
         import_outer_index value was i32::MIN (structurally undecodable as PackageIndex)"
    );
}

#[test]
fn asset_parse_display_unsupported_compression_in_summary() {
    let err = PaksmithError::AssetParse {
        asset_path: "x.uasset".to_string(),
        fault: AssetParseFault::UnsupportedCompressionInSummary {
            site: CompressionInSummarySite::CompressionFlags,
            observed: 1,
        },
    };
    assert_eq!(
        format!("{err}"),
        "asset deserialization failed for `x.uasset`: \
         unsupported in-summary compression: compression_flags = 1 \
         (modern UE writers emit 0)"
    );
}
```

- [ ] **Step 2: Run the new tests to verify they fail**

Run: `cargo test -p paksmith-core --lib error::tests::asset_parse_display 2>&1 | tail -20`
Expected: 7 compile errors (or test failures) — `AssetParseFault`, `AssetWireField`, and `CompressionInSummarySite` don't exist yet.

- [ ] **Step 3: Replace the `AssetParse` variant in `PaksmithError`**

Find the existing `AssetParse` block (currently around `error.rs:85-98`) and replace it with:

```rust
/// Asset deserialization failed.
///
/// `fault` categorizes the failure mode (invalid magic, unsupported
/// version, bounds violations, allocation pressure, EOF). The
/// [`Display`] impl on [`AssetParseFault`] preserves the wire-stable
/// operator-facing message shape; per-variant unit tests pin the
/// exact strings so log greps + monitoring rules survive future
/// variant additions.
///
/// Promoted from the Phase-1 placeholder `reason: String` shape so
/// tests can `matches!` on typed variants rather than substring-grep,
/// matching the precedent set by [`IndexParseFault`] (issue #94),
/// [`DecompressionFault`] (issue #112), and [`InvalidFooterFault`]
/// (issue #64).
///
/// [`Display`]: std::fmt::Display
#[error("asset deserialization failed for `{asset_path}`: {fault}")]
AssetParse {
    /// Structured category + payload for the parse fault.
    fault: AssetParseFault,
    /// Asset path that could not be parsed.
    asset_path: String,
},
```

- [ ] **Step 4: Add `AssetParseFault` + payload enums at the end of `error.rs`**

Add immediately before the `#[cfg(test)] mod tests` block:

```rust
/// Structured category + payload for [`PaksmithError::AssetParse`].
///
/// `#[non_exhaustive]` because Phase 2b–2e will land additional
/// variants (FPropertyTag faults, container-property OOM, recursion-
/// depth violations); downstream `match` arms survive without source
/// breakage. `PartialEq + Eq + Clone` mirrors [`IndexParseFault`]
/// (issue #94) so tests can use `assert_eq!` alongside `matches!`.
///
/// **Display format** is wire-stable — every variant has a dedicated
/// `error_display_asset_parse_*` unit test that pins the exact string.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AssetParseFault {
    /// The first 4 bytes of the asset weren't the UE package magic
    /// (`0x9E2A83C1`). Either the file isn't a uasset, or the
    /// preceding pak-level decompression returned garbage.
    InvalidMagic {
        /// The u32 read from offset 0 of the asset bytes.
        observed: u32,
        /// The expected magic (`0x9E2A83C1`). Carried explicitly so
        /// the Display message is self-contained for log greps.
        expected: u32,
    },
    /// The `LegacyFileVersion` (an `i32` read from offset 4) isn't one
    /// of the values Phase 2a supports (`-7` or `-8`). Earlier values
    /// (`-6` and shallower) shipped with UE 4.20 and below; later
    /// values don't exist yet. Rejected explicitly rather than risking
    /// silent misparse of a divergent on-disk layout.
    UnsupportedLegacyFileVersion {
        /// The legacy file version read from the asset.
        version: i32,
    },
    /// `FileVersionUE4` is below the Phase 2a floor (`504`,
    /// `VER_UE4_NAME_HASHES_SERIALIZED`). Pre-floor archives lack the
    /// dual-CityHash16 name hash format Phase 2a requires.
    UnsupportedFileVersionUE4 {
        /// The UE4 object version read from the asset.
        version: i32,
        /// The Phase 2a floor.
        minimum: i32,
    },
    /// A wire-claimed count or size exceeds a structural cap. Same
    /// shape as [`IndexParseFault::BoundsExceeded`] (issue #133);
    /// separate variant because the field set is asset-specific.
    /// Carries `unit` so operators can disambiguate bytes-bounded
    /// fields (`TotalHeaderSize`, `NameOffset`, etc.) from
    /// items-bounded fields (`NameCount`, `ImportCount`, etc.) at
    /// log-grep time.
    BoundsExceeded {
        /// Wire-format field name.
        field: AssetWireField,
        /// The header-claimed value.
        value: u64,
        /// The cap it exceeds.
        limit: u64,
        /// Unit the cap is expressed in.
        unit: BoundsUnit,
    },
    /// A wire-claimed `i32` or `u32` offset/count is negative when the
    /// field is documented non-negative, or it points past the end of
    /// the asset bytes. Distinct from [`Self::BoundsExceeded`] because
    /// the limit is the asset's byte length, not a structural cap.
    InvalidOffset {
        /// Wire-format field name.
        field: AssetWireField,
        /// The offset value as read.
        offset: i64,
        /// Length of the asset bytes — the upper bound `offset`
        /// exceeded (or `0` for the "negative offset" case).
        asset_size: u64,
    },
    /// A wire-claimed signed value (count/offset/size) was negative when
    /// the field is documented non-negative. Distinct from
    /// [`Self::InvalidOffset`] (which is non-negative-but-out-of-bounds)
    /// because the sign violation is a structural decode failure with no
    /// upper bound to compare against — the value didn't reach far enough
    /// into the field's domain to be meaningful. UE writers never emit
    /// negative counts/offsets/sizes; produced only by malicious or
    /// corrupted archives.
    ///
    /// Covers negative `NameCount`/`ImportCount`/`ExportCount`/
    /// `CustomVersionCount`, negative `NameOffset`/`ImportOffset`/
    /// `ExportOffset`/`ExportSerialOffset`, and negative
    /// `ExportSerialSize`. The wire-read `i32`/`i64` is widened to `i64`
    /// so the operator-visible string preserves the on-wire signedness.
    NegativeValue {
        /// Wire-format field name.
        field: AssetWireField,
        /// The wire-read negative value (widened to i64 from i32 where
        /// applicable to preserve sign).
        value: i64,
    },
    /// An [`PackageIndex`](crate::asset::package_index::PackageIndex)
    /// resolved to an import/export table slot that doesn't exist.
    /// Fires from the import-walk (when an `OuterIndex` references a
    /// missing import) and from the export-walk symmetrically.
    PackageIndexOob {
        /// Wire-format field name (e.g. `ImportOuterIndex`,
        /// `ExportClassIndex`).
        field: AssetWireField,
        /// The 0-based table index derived from the on-wire i32.
        index: u32,
        /// The size of the table being indexed.
        table_size: u32,
    },
    /// A wire-read `i32` was `i32::MIN`, which has no representable
    /// positive counterpart and so cannot be decoded as either an
    /// import or an export reference. Distinct from
    /// [`Self::PackageIndexOob`] because there is no in-range
    /// alternative for the operator to consider — the value was
    /// structurally undecodable. UE writers never emit this; produced
    /// only by malicious / corrupted archives.
    PackageIndexUnderflow {
        /// Wire-format field name.
        field: AssetWireField,
    },
    /// The package summary's `compression_flags` was non-zero or
    /// `compressed_chunks_count` was non-zero — Phase 2a rejects
    /// in-summary compression because the trailing payload regions
    /// would be transformed and the offset arithmetic in
    /// [`crate::asset::package::Package`] wouldn't apply directly.
    /// Modern UE writers always emit `0` here; non-zero signals an
    /// older or non-standard cooker.
    UnsupportedCompressionInSummary {
        /// Which of the two summary slots tripped.
        site: CompressionInSummarySite,
        /// The observed value at the site (the flags value or the
        /// chunks count).
        observed: u64,
    },
    /// An FString within the asset header was malformed. Reuses the
    /// existing [`FStringFault`] sub-enum so the FString reader
    /// (`crate::container::pak::index::fstring::read_fstring`) can
    /// surface its faults uniformly into either the pak-index or the
    /// asset-parse top-level.
    FStringMalformed {
        /// Sub-category of the malformation.
        kind: FStringFault,
    },
    /// A header-claimed `u32`/`i32` size doesn't fit in `usize` on
    /// this platform. Practically a 32-bit-target concern (or a
    /// malicious archive on 64-bit hosts).
    U64ExceedsPlatformUsize {
        /// Wire-format field name.
        field: AssetWireField,
        /// The value that didn't fit.
        value: u64,
    },
    /// A `try_reserve` / `try_reserve_exact` call returned `Err`.
    /// Surfaced as a typed error rather than letting the allocator
    /// abort the process — mirrors the pak parser's approach.
    AllocationFailed {
        /// What was being reserved.
        context: AssetAllocationContext,
        /// Bytes (or items, per `unit`) the reservation requested.
        requested: usize,
        /// Unit of `requested`.
        unit: BoundsUnit,
        /// Underlying allocator failure.
        source: std::collections::TryReserveError,
    },
    /// An offset arithmetic operation overflowed.
    U64ArithmeticOverflow {
        /// Which parse site produced the overflow.
        operation: AssetOverflowSite,
    },
    /// The bytes ran out mid-record. Distinct from
    /// [`Self::InvalidOffset`] because no offset is at fault — the
    /// reader simply reached EOF inside a record whose structural
    /// size implied more bytes available.
    UnexpectedEof {
        /// Which record was being read when EOF hit.
        field: AssetWireField,
    },
}

impl fmt::Display for AssetParseFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic { observed, expected } => write!(
                f,
                "invalid uasset magic: observed {observed:#010x}, expected {expected:#010x}"
            ),
            Self::UnsupportedLegacyFileVersion { version } => write!(
                f,
                "unsupported legacy file version {version} \
                 (paksmith Phase 2a accepts -7 and -8)"
            ),
            Self::UnsupportedFileVersionUE4 { version, minimum } => write!(
                f,
                "unsupported FileVersionUE4 {version} (minimum {minimum})"
            ),
            Self::BoundsExceeded { field, value, limit, unit } => {
                write!(f, "{field} {value} exceeds maximum {limit} {unit}")
            }
            Self::InvalidOffset { field, offset, asset_size } => write!(
                f,
                "{field} offset {offset} out of bounds (asset size {asset_size})"
            ),
            Self::NegativeValue { field, value } => write!(
                f,
                "{field} value {value} is negative"
            ),
            Self::PackageIndexOob { field, index, table_size } => write!(
                f,
                "{field} {index} out of bounds (table has {table_size} entries)"
            ),
            Self::PackageIndexUnderflow { field } => write!(
                f,
                "{field} value was i32::MIN (structurally undecodable as PackageIndex)"
            ),
            Self::UnsupportedCompressionInSummary { site, observed } => write!(
                f,
                "unsupported in-summary compression: {site} = {observed} (modern UE writers emit 0)"
            ),
            Self::FStringMalformed { kind } => write!(f, "FString: {kind}"),
            Self::U64ExceedsPlatformUsize { field, value } => write!(
                f,
                "{field} value {value} exceeds platform usize"
            ),
            Self::AllocationFailed { context, requested, unit, source } => write!(
                f,
                "could not reserve {requested} {unit} for {context}: {source}"
            ),
            Self::U64ArithmeticOverflow { operation } => {
                write!(f, "u64 arithmetic overflow during {operation}")
            }
            Self::UnexpectedEof { field } => {
                write!(f, "unexpected EOF reading {field}")
            }
        }
    }
}

/// Wire-format field names referenced by [`AssetParseFault`] variants.
///
/// Closed set: each variant maps 1:1 to a specific UE on-disk field.
/// `Display` renders the snake_case name operators see in error messages.
/// `#[non_exhaustive]` so 2b–2e can extend the set without source breakage
/// in downstream `match` arms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AssetWireField {
    /// `FPackageFileSummary::NameCount`.
    NameCount,
    /// `FPackageFileSummary::NameOffset`.
    NameOffset,
    /// `FPackageFileSummary::ImportCount`.
    ImportCount,
    /// `FPackageFileSummary::ImportOffset`.
    ImportOffset,
    /// `FPackageFileSummary::ExportCount`.
    ExportCount,
    /// `FPackageFileSummary::ExportOffset`.
    ExportOffset,
    /// `FPackageFileSummary::TotalHeaderSize`.
    TotalHeaderSize,
    /// `FPackageFileSummary::CustomVersionContainer` element count.
    CustomVersionCount,
    /// `FObjectImport::OuterIndex` package-index slot.
    ImportOuterIndex,
    /// `FObjectExport::ClassIndex` package-index slot.
    ExportClassIndex,
    /// `FObjectExport::SuperIndex` package-index slot.
    ExportSuperIndex,
    /// `FObjectExport::OuterIndex` package-index slot.
    ExportOuterIndex,
    /// `FObjectExport::TemplateIndex` package-index slot.
    ExportTemplateIndex,
    /// `FObjectExport::SerialOffset`.
    ExportSerialOffset,
    /// `FObjectExport::SerialSize`.
    ExportSerialSize,
    /// An FName index referenced anywhere in the header (import/export
    /// name slot, custom-version name, folder name, etc.).
    NameIndex,
}

impl fmt::Display for AssetWireField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::NameCount => "name_count",
            Self::NameOffset => "name_offset",
            Self::ImportCount => "import_count",
            Self::ImportOffset => "import_offset",
            Self::ExportCount => "export_count",
            Self::ExportOffset => "export_offset",
            Self::TotalHeaderSize => "total_header_size",
            Self::CustomVersionCount => "custom_version_count",
            Self::ImportOuterIndex => "import_outer_index",
            Self::ExportClassIndex => "export_class_index",
            Self::ExportSuperIndex => "export_super_index",
            Self::ExportOuterIndex => "export_outer_index",
            Self::ExportTemplateIndex => "export_template_index",
            Self::ExportSerialOffset => "export_serial_offset",
            Self::ExportSerialSize => "export_serial_size",
            Self::NameIndex => "name_index",
        };
        f.write_str(s)
    }
}

/// Closed set of overflow sites in the asset parser. Same shape as
/// [`OverflowSite`] for the pak parser; kept separate so each variant
/// names an asset-specific computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AssetOverflowSite {
    /// `NameOffset + NameCount * record_size` overflowed.
    NameTableExtent,
    /// `ImportOffset + ImportCount * record_size` overflowed.
    ImportTableExtent,
    /// `ExportOffset + ExportCount * record_size` overflowed.
    ExportTableExtent,
    /// An export's `SerialOffset + SerialSize` overflowed.
    ExportPayloadExtent,
}

impl fmt::Display for AssetOverflowSite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::NameTableExtent => "name-table extent computation",
            Self::ImportTableExtent => "import-table extent computation",
            Self::ExportTableExtent => "export-table extent computation",
            Self::ExportPayloadExtent => "export-payload extent computation",
        };
        f.write_str(s)
    }
}

/// Closed set of allocation contexts in the asset parser. Same intent
/// as [`AllocationContext`]; separate enum because the contexts are
/// asset-specific.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AssetAllocationContext {
    /// `Vec<Arc<str>>` for the name table.
    NameTable,
    /// `Vec<ObjectImport>` for the import table.
    ImportTable,
    /// `Vec<ObjectExport>` for the export table.
    ExportTable,
    /// `Vec<CustomVersion>` for the custom-version container.
    CustomVersionContainer,
    /// `Vec<u8>` for an export's opaque payload bytes.
    ExportPayloadBytes,
}

impl fmt::Display for AssetAllocationContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::NameTable => "name table",
            Self::ImportTable => "import table",
            Self::ExportTable => "export table",
            Self::CustomVersionContainer => "custom-version container",
            Self::ExportPayloadBytes => "export payload bytes",
        };
        f.write_str(s)
    }
}

/// Discriminator for [`AssetParseFault::UnsupportedCompressionInSummary`].
///
/// Two distinct sites in the summary can carry "compression is on":
/// the `compression_flags` u32 and the `compressed_chunks_count` i32.
/// Phase 2a rejects both at zero; this enum tells operators which one
/// tripped. Closed set with `Display` rendering the wire-field name so
/// log greps look the same whether triage starts from the typed
/// variant or the rendered string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CompressionInSummarySite {
    /// The `compression_flags` u32 slot was non-zero.
    CompressionFlags,
    /// The `compressed_chunks` `TArray` was non-empty.
    CompressedChunksCount,
}

impl fmt::Display for CompressionInSummarySite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::CompressionFlags => "compression_flags",
            Self::CompressedChunksCount => "compressed_chunks_count",
        };
        f.write_str(s)
    }
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p paksmith-core --lib error::tests::asset_parse_display`
Expected: 6 tests pass.

- [ ] **Step 6: Find and update the existing `error_display_asset_parse` test**

The current placeholder test (around `error.rs:~2200` — grep `error_display_asset_parse`) constructs `AssetParse { reason: ... }`. Replace its body with the new typed-variant form so it stays meaningful as a sanity check. Search:

```bash
grep -n "fn error_display_asset_parse" crates/paksmith-core/src/error.rs
```

Replace the function body with:

```rust
#[test]
fn error_display_asset_parse() {
    // Sanity check the top-level error wrapper format. Variant-level
    // Display strings are pinned by `asset_parse_display_*` tests.
    let err = PaksmithError::AssetParse {
        asset_path: "Game/Maps/Demo.uasset".to_string(),
        fault: AssetParseFault::UnsupportedLegacyFileVersion { version: -6 },
    };
    assert!(format!("{err}").starts_with("asset deserialization failed for `Game/Maps/Demo.uasset`:"));
}
```

- [ ] **Step 7: Run the full error-module test suite**

Run: `cargo test -p paksmith-core --lib error::tests`
Expected: all tests pass (no regressions in `IndexParseFault`/`DecompressionFault`/etc. coverage).

- [ ] **Step 8: Run workspace clippy with the GHAS-equivalent flags**

Per `MEMORY.md` (`ghas_clippy_extra_lints.md`): the local default misses `__test_utils` surface. Run:

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Expected: no warnings.

- [ ] **Step 9: Commit**

```bash
git add crates/paksmith-core/src/error.rs
git commit -m "$(cat <<'EOF'
feat(error): promote AssetParse placeholder to typed AssetParseFault

Mirrors IndexParseFault/DecompressionFault/InvalidFooterFault — typed
sub-enum with wire-stable Display, non_exhaustive, PartialEq+Eq+Clone.
Variants cover invalid magic, unsupported legacy/UE4 versions, bounds-
exceeded caps, invalid offsets, PackageIndex OOB, FString malformations,
usize overflow, allocation pressure, arithmetic overflow, and unexpected
EOF. AssetWireField + AssetOverflowSite + AssetAllocationContext payload
enums keep wire-field naming closed-set.

Phase 2a prerequisite — every uasset parser added in subsequent tasks
constructs this fault rather than scaffolding a placeholder string.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: Promote `read_fstring` to crate-public; add `AssetVersion`

**Files:**

- Modify: `crates/paksmith-core/src/container/pak/index/fstring.rs:39` — change `pub(super)` to `pub(crate)`
- Modify: `crates/paksmith-core/src/container/pak/index/mod.rs` (top of file) — re-export `read_fstring` as `pub(crate) use`
- Create: `crates/paksmith-core/src/asset/mod.rs` — module skeleton
- Create: `crates/paksmith-core/src/asset/version.rs` — `AssetVersion` struct + UE constants
- Modify: `crates/paksmith-core/src/lib.rs:8` — add `pub mod asset;`

**Why:** every wire-format reader added downstream needs FStrings (FName entries, FolderName, ClassPackage, etc.) and the version newtype (read-time branching on `FileVersionUE4 ≥ VER_UE4_NAME_HASHES_SERIALIZED`).

> **Correction (correctness audit, third pass):** the asset-side FString reader (`read_asset_fstring` in `asset/fstring.rs`) now accepts `len == 0` and returns `""`. CUE4Parse's `FArchive.ReadFString` does the same, and real UAsset bytes legitimately encode empty FStrings as `len=0` (UE writers also emit the `len=1, single-null-byte` form, but the reader accepts both). The pak-side `read_fstring` stays strict (issue #104 — FDI record-size invariants depend on the 5-byte minimum). Landed in commit `d65909d`.

- [ ] **Step 1: Add the file-scope visibility anchor**

The visibility check is a file-scope `use ... as _;` inside
`crates/paksmith-core/src/asset/mod.rs` — NOT an external integration
test under `tests/`. Integration tests link against the crate as an
external consumer and cannot see `pub(crate)` symbols, so the
original "create `tests/fstring_crate_visible.rs`" instruction would
not compile. Inside `mod.rs`, a file-scope `use` resolves at the same
visibility tier as the rest of the crate and surfaces visibility
regressions as a real compile error (sharper than a `#[test]` block
that only asserts a path resolves).

Add to `crates/paksmith-core/src/asset/mod.rs` (below the existing
`pub use version::AssetVersion;`):

```rust
/// Compile-time pin: `read_fstring` is reachable from this module via
/// the `pub(crate)` re-export at [`crate::container::pak::index`].
/// The `use` import below would fail to resolve if visibility
/// regressed; later tasks (e.g., the FName / NameTable parsers) will
/// remove this anchor when they import `read_fstring` for real.
#[allow(unused_imports)]
use crate::container::pak::index::read_fstring as _phase_2a_fstring_anchor;
```

The `_phase_2a_fstring_anchor` alias documents intent and marks the
binding as deliberately unused (the `_` prefix); the
`#[allow(unused_imports)]` is defensive in case a lint level changes.

- [ ] **Step 2: Verify the anchor compiles after promotion**

Before Step 3 runs, the anchor will fail to resolve (the symbol is
still `pub(super)`). Run:

```
cargo build -p paksmith-core 2>&1 | tail -10
```

Expected: compile error `function`read_fstring`is private` (or
`module`fstring`is private`) at the `use` line in `asset/mod.rs`.
Step 3 promotes the visibility and the build goes clean.

- [ ] **Step 3: Promote the FString reader visibility**

Edit `crates/paksmith-core/src/container/pak/index/fstring.rs:39`:

Change:

```rust
pub(super) fn read_fstring<R: Read>(reader: &mut R) -> crate::Result<String> {
```

to:

```rust
pub(crate) fn read_fstring<R: Read>(reader: &mut R) -> crate::Result<String> {
```

Edit `crates/paksmith-core/src/container/pak/index/mod.rs` (top — find the existing `mod fstring;` declaration):

Change `mod fstring;` to:

```rust
mod fstring;
pub(crate) use fstring::read_fstring;
```

- [ ] **Step 4: Create the asset module skeleton**

Create `crates/paksmith-core/src/asset/mod.rs`:

```rust
//! UAsset deserialization.
//!
//! # Scope (Phase 2a)
//!
//! Parses the structural header of UE 4.21–UE 5.x `.uasset` files:
//! - [`summary::PackageSummary`] (`FPackageFileSummary`): file versions,
//!   table offsets/counts, package flags, engine version, custom
//!   versions.
//! - [`name_table::NameTable`]: the FName string pool with dual
//!   CityHash16 hashes (UE 4.21+ `VER_UE4_NAME_HASHES_SERIALIZED`).
//! - [`import_table::ImportTable`] (`FObjectImport[]`).
//! - [`export_table::ExportTable`] (`FObjectExport[]`).
//!
//! Property bodies (`FPropertyTag`-iterated payloads inside export
//! serialized regions) are carried as opaque bytes via
//! [`property_bag::PropertyBag::Opaque`]; tagged-property iteration
//! lands in Phase 2b.
//!
//! # Module layout
//!
//! Each wire-format component owns a `mod.rs`-equivalent file:
//! `version`, `engine_version`, `custom_version`, `package_index`,
//! `name_table`, `import_table`, `export_table`, `summary`. The
//! aggregate `Package::read_from` in [`package`] orchestrates them.
//!
//! See `docs/plans/phase-2a-uasset-header.md` for the implementation
//! plan and `docs/design/SPEC.md` § "Asset Data Model" for the
//! architectural intent.

pub mod custom_version;
pub mod engine_version;
pub mod export_table;
pub mod import_table;
pub mod name_table;
pub mod package;
pub mod package_index;
pub mod property_bag;
pub mod summary;
pub mod version;

use std::sync::Arc;

use serde::Serialize;

pub use custom_version::{CustomVersion, CustomVersionContainer};
pub use engine_version::EngineVersion;
pub use export_table::{ExportTable, ObjectExport};
pub use import_table::{ImportTable, ObjectImport};
pub use name_table::{FName, NameTable};
pub use package::Package;
pub use package_index::PackageIndex;
pub use property_bag::PropertyBag;
pub use summary::PackageSummary;
pub use version::AssetVersion;

/// Top-level domain type for a deserialized UE asset.
///
/// Phase 2a ships only the [`Self::Generic`] variant carrying a
/// [`Package`] plus an opaque payload. Specialized variants
/// (`Texture`, `StaticMesh`, etc., per `docs/design/SPEC.md`) land in
/// Phase 3 once the property system can decode them.
///
/// `#[non_exhaustive]` so downstream consumers can pattern-match with
/// `_` and survive future variant additions.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub enum Asset {
    /// The universal fallback: structural header + opaque payload.
    Generic(Package),
}

/// Bundle threading the parsed name/import/export tables and version
/// through downstream property parsers (Phase 2b+).
///
/// `Arc`-wrapped components so `clone()` is two atomic refcount bumps
/// — important because the GUI's PropertyInspector widget holds a
/// context across many event-loop ticks and must not block on table
/// copies.
///
/// Phase 2a builds this from a parsed [`Package`] via [`Package::context`]
/// even though no Phase 2a code reads from it — the type is locked
/// here so Phase 2b can land additive without re-litigating shape.
#[derive(Debug, Clone)]
pub struct AssetContext {
    /// The parsed FName pool (shared by all import/export references).
    pub names: Arc<NameTable>,
    /// The parsed import table.
    pub imports: Arc<ImportTable>,
    /// The parsed export table.
    pub exports: Arc<ExportTable>,
    /// Version constants the parsers branch on.
    pub version: AssetVersion,
}
```

- [ ] **Step 5: Create the version constants file**

Create `crates/paksmith-core/src/asset/version.rs`:

```rust
//! UE engine-version constants and the [`AssetVersion`] bundle.
//!
//! Source of truth: UE's `EUnrealEngineObjectUE4Version`,
//! `EUnrealEngineObjectUE5Version`, `EPackageFileTag` enums (in
//! `Engine/Source/Runtime/Core/Public/UObject/ObjectVersion.h` and
//! `ObjectVersionUE5.h`). Each `VER_UE4_*` / `VER_UE5_*` constant
//! below is a wire-format gate — a field is read only when the
//! file's reported version is ≥ the constant.
//!
//! Phase 2a accepts `LegacyFileVersion ∈ {-7, -8}` and
//! `FileVersionUE4 ≥ VER_UE4_NAME_HASHES_SERIALIZED`. Narrower
//! windows can be widened by Phase 2b+ without changing this file's
//! shape; the constants here are stable.

use serde::Serialize;

/// UE package magic (`'\x9E*\x83\xC1'`). First 4 bytes of every
/// `.uasset` file.
pub const PACKAGE_FILE_TAG: u32 = 0x9E2A_83C1;

/// Byte-swapped magic, used by UE itself for cross-endian detection.
/// Rejected by paksmith — we don't support BE-encoded uassets.
pub const PACKAGE_FILE_TAG_SWAPPED: u32 = 0xC183_2A9E;

/// Phase 2a lower bound for `FileVersionUE4`. Below this, the name
/// table doesn't carry the dual CityHash16 hash pair we require.
/// (UE4.21 = 503, this constant = 504.)
pub const VER_UE4_NAME_HASHES_SERIALIZED: i32 = 504;

/// UE 4.x: `LocalizationId` FString added to the package summary
/// (editor-only — present only when `PKG_FilterEditorOnly` is NOT set).
pub const VER_UE4_ADDED_PACKAGE_SUMMARY_LOCALIZATION_ID: i32 = 516;

/// UE 4.x: `OwnerPersistentGuid` (FGuid) added to summary. Lives
/// between `ADDED_PACKAGE_OWNER` and `NON_OUTER_PACKAGE_IMPORT` only
/// — UE removed it immediately. Editor-only.
pub const VER_UE4_ADDED_PACKAGE_OWNER: i32 = 518;

/// UE 4.x: `OwnerPersistentGuid` retired (was added at 518, removed
/// here at 520). Phase 2a always reads `LegacyFileVersion ≤ -7`
/// (UE 4.21+ = 520+), so `OwnerPersistentGuid` is never in the wire
/// stream we accept.
pub const VER_UE4_NON_OUTER_PACKAGE_IMPORT: i32 = 520;

/// UE 5.0+: `FileVersionUE5` is present when `LegacyFileVersion ≤ -8`.
/// Values are sequential from this base; the canonical numbering is
/// verified against CUE4Parse's `EUnrealEngineObjectUE5Version`
/// (`CUE4Parse/UE4/Versions/ObjectVersion.cs`) and the `unreal_asset`
/// oracle's `ObjectVersionUE5` enum.
pub const VER_UE5_INITIAL_VERSION: i32 = 1000;

/// UE 5.0+: enables stripping names not referenced from export data —
/// a name-table optimisation. Gates `names_referenced_from_export_data_count`
/// in the summary.
pub const VER_UE5_NAMES_REFERENCED_FROM_EXPORT_DATA: i32 = 1001;

/// UE 5.0+: `payload_toc_offset` (i64) added to the summary.
pub const VER_UE5_PAYLOAD_TOC: i32 = 1002;

/// UE 5.0+: `bImportOptional` (i32 bool, NOT u8) appended to
/// `FObjectImport`; `generate_public_hash` (i32 bool) appended to
/// `FObjectExport`.
pub const VER_UE5_OPTIONAL_RESOURCES: i32 = 1003;

/// UE 5.0+: large-world-coordinates (no wire-format impact for the
/// fields Phase 2a reads).
pub const VER_UE5_LARGE_WORLD_COORDINATES: i32 = 1004;

/// UE 5.0+: `package_guid` FGuid removed from `FObjectExport`.
/// Below this version, the export carries 16 GUID bytes; at or above,
/// it does not.
pub const VER_UE5_REMOVE_OBJECT_EXPORT_PACKAGE_GUID: i32 = 1005;

/// UE 5.0+: `is_inherited_instance` (i32 bool) added to `FObjectExport`.
pub const VER_UE5_TRACK_OBJECT_EXPORT_IS_INHERITED: i32 = 1006;

/// UE 5.0+: `SoftObjectPath` list added to the summary
/// (`soft_object_paths_count` + `soft_object_paths_offset`).
pub const VER_UE5_ADD_SOFTOBJECTPATH_LIST: i32 = 1008;

/// UE 5.0+: `data_resource_offset` (i32) added to the summary.
pub const VER_UE5_DATA_RESOURCES: i32 = 1009;

/// Resolved version snapshot for one parsed asset. Threaded by `&` or
/// `Copy` into every downstream parser. Cheap to copy (5 × i32).
///
/// `Default` returns the zero version (legacy=0, ue4=0, ue5=None,
/// licensee=0) — useful only for test fixtures that don't exercise
/// version-gated branches. Real callers must construct explicitly via
/// `PackageSummary::read_from`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub struct AssetVersion {
    /// The `LegacyFileVersion` field from the start of the summary.
    /// Phase 2a accepts `-7` (UE 4.21–4.27) and `-8` (UE 5.0+).
    pub legacy_file_version: i32,
    /// `FileVersionUE4` (`EUnrealEngineObjectUE4Version`).
    pub file_version_ue4: i32,
    /// `FileVersionUE5`. `None` when `legacy_file_version > -8`.
    pub file_version_ue5: Option<i32>,
    /// `FileVersionLicenseeUE4` (project-specific licensee version).
    pub file_version_licensee_ue4: i32,
}

impl AssetVersion {
    /// True iff the asset's reported version is ≥ `floor` for UE4.
    #[must_use]
    pub fn ue4_at_least(self, floor: i32) -> bool {
        self.file_version_ue4 >= floor
    }

    /// True iff the asset's reported UE5 version is ≥ `floor`.
    /// Returns `false` when no UE5 version is present (pre-UE5 asset).
    #[must_use]
    pub fn ue5_at_least(self, floor: i32) -> bool {
        self.file_version_ue5.is_some_and(|v| v >= floor)
    }
}
```

- [ ] **Step 6: Wire `asset` into the crate root**

Edit `crates/paksmith-core/src/lib.rs:8`:

Change:

```rust
pub mod container;
pub mod digest;
pub mod error;
```

to:

```rust
pub mod asset;
pub mod container;
pub mod digest;
pub mod error;
```

- [ ] **Step 7: Run the visibility test + workspace build**

Run:

```bash
cargo build -p paksmith-core
cargo test -p paksmith-core --test fstring_crate_visible
```

Expected: build OK; the smoke test compiles and passes.

- [ ] **Step 8: Run clippy**

Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings`
Expected: no warnings.

- [ ] **Step 9: Commit**

```bash
git add crates/paksmith-core/src/container/pak/index/fstring.rs \
        crates/paksmith-core/src/container/pak/index/mod.rs \
        crates/paksmith-core/src/asset/ \
        crates/paksmith-core/src/lib.rs \
        crates/paksmith-core/tests/fstring_crate_visible.rs
git commit -m "$(cat <<'EOF'
feat(asset): scaffold asset/ module + AssetVersion; promote read_fstring

Adds crates/paksmith-core/src/asset/{mod.rs,version.rs} as the Phase 2a
module skeleton — declares submodules, re-exports public types, and
defines AssetVersion + UE wire-format version constants
(VER_UE4_NAME_HASHES_SERIALIZED, VER_UE5_*, PACKAGE_FILE_TAG).

Promotes container::pak::index::fstring::read_fstring from pub(super)
to pub(crate) so asset/ parsers can share one FString reader. Smoke
test (tests/fstring_crate_visible.rs) pins the visibility.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: `PackageIndex` — typed wrapper around UE's i32 import/export reference

**Files:**

- Create: `crates/paksmith-core/src/asset/package_index.rs`

**Why:** UE encodes object references as a single signed i32 where `0 = Null`, positive values index into the export table (1-based, so `1` → `exports[0]`), and negative values index into the import table (1-based mirror, `-1` → `imports[0]`). Every `OuterIndex`, `ClassIndex`, `SuperIndex`, `TemplateIndex` field uses this encoding. Wrapping it in a typed enum prevents off-by-one errors at every dereference site.

- [ ] **Step 1: Write the encode/decode round-trip tests**

Create `crates/paksmith-core/src/asset/package_index.rs` with tests first (file content below). For now add only this skeleton so the tests can run:

```rust
//! Typed wrapper around UE's i32 import/export reference encoding.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_round_trip() {
        let pi = PackageIndex::try_from_raw(0).unwrap();
        assert_eq!(pi, PackageIndex::Null);
        assert_eq!(pi.to_raw(), 0);
    }

    #[test]
    fn import_round_trip() {
        let pi = PackageIndex::try_from_raw(-3).unwrap();
        assert_eq!(pi, PackageIndex::Import(2));
        assert_eq!(pi.to_raw(), -3);
    }

    #[test]
    fn export_round_trip() {
        let pi = PackageIndex::try_from_raw(5).unwrap();
        assert_eq!(pi, PackageIndex::Export(4));
        assert_eq!(pi.to_raw(), 5);
    }

    #[test]
    fn import_min_avoids_overflow() {
        // i32::MIN has no positive counterpart; wrapping_abs would
        // wrap to i32::MIN. PackageIndex must surface this as an
        // explicit error rather than constructing Import(2147483647).
        assert_eq!(
            PackageIndex::try_from_raw(i32::MIN),
            Err(PackageIndexError::ImportIndexUnderflow),
        );
    }

    #[test]
    fn display_format() {
        assert_eq!(format!("{}", PackageIndex::Null), "Null");
        assert_eq!(format!("{}", PackageIndex::Import(2)), "Import(2)");
        assert_eq!(format!("{}", PackageIndex::Export(4)), "Export(4)");
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p paksmith-core --lib asset::package_index::tests 2>&1 | tail -15`
Expected: compile errors — `PackageIndex`, `PackageIndexError`, `to_raw`, `try_from_raw` don't exist.

- [ ] **Step 3: Implement `PackageIndex`**

Replace the file body with:

```rust
//! Typed wrapper around UE's i32 import/export reference encoding.
//!
//! UE encodes object references as a single `i32` where `0 = Null`,
//! positive values are 1-based indices into the export table
//! (`1 → exports[0]`), and negative values are 1-based mirrors of the
//! import table (`-1 → imports[0]`). The encoding is uniform across
//! every `OuterIndex`, `ClassIndex`, `SuperIndex`, `TemplateIndex`
//! field in the wire format.
//!
//! Wrapping the raw i32 in this typed enum keeps the "+1 / -1 / 0
//! sentinel" arithmetic in one place — every dereference site reads
//! the typed variant rather than re-deriving the indexing.

use std::fmt;

/// Typed reference to an entry in the import table, the export table,
/// or `Null`.
///
/// Decoded from the on-wire `i32`:
/// - `0` → [`Self::Null`]
/// - positive `n` → [`Self::Export(n as u32 - 1)`]
/// - negative `n` → [`Self::Import((-n) as u32 - 1)`]
///
/// `Copy` because the payload is one u32 — cheaper to pass by value
/// than by reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageIndex {
    /// The reference is null (UE's `INDEX_NONE`-via-PackageIndex).
    Null,
    /// 0-based index into the import table.
    Import(u32),
    /// 0-based index into the export table.
    Export(u32),
}

impl PackageIndex {
    /// Decode from the raw wire i32, surfacing `i32::MIN` as a typed
    /// error rather than panicking. Used at every wire-read site.
    ///
    /// # Errors
    /// Returns [`PackageIndexError::ImportIndexUnderflow`] when
    /// `raw == i32::MIN`.
    pub fn try_from_raw(raw: i32) -> Result<Self, PackageIndexError> {
        match raw {
            0 => Ok(Self::Null),
            1.. => Ok(Self::Export((raw - 1) as u32)),
            i32::MIN => Err(PackageIndexError::ImportIndexUnderflow),
            _ => Ok(Self::Import((-raw - 1) as u32)),
        }
    }

    /// Re-encode to the on-wire i32.
    ///
    /// # Panics (debug builds)
    /// Panics in debug builds if a synthetic `PackageIndex::Export(i)` or
    /// `PackageIndex::Import(i)` carries `i > i32::MAX as u32 - 1`. The
    /// wire-read path via [`Self::try_from_raw`] never produces such a
    /// value (its output is bounded to `0..=i32::MAX - 1`), so only direct
    /// construction (fixture-gen, test builders) can trip this. Release
    /// builds wrap silently — callers building synthetic values must
    /// validate the input before constructing the variant.
    #[must_use]
    pub fn to_raw(self) -> i32 {
        match self {
            Self::Null => 0,
            Self::Export(i) => {
                debug_assert!(
                    i < i32::MAX as u32,
                    "PackageIndex::Export({i}) exceeds i32::MAX - 1; constructable only via try_from_raw or validated synthetic source"
                );
                (i as i32) + 1
            }
            Self::Import(i) => {
                debug_assert!(
                    i < i32::MAX as u32,
                    "PackageIndex::Import({i}) exceeds i32::MAX - 1; constructable only via try_from_raw or validated synthetic source"
                );
                -((i as i32) + 1)
            }
        }
    }
}

impl serde::Serialize for PackageIndex {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Render via Display so JSON shows "Null" / "Import(N)" / "Export(N)"
        // — matches the inspect-output contract (Task 14 deliverable above).
        // Derives like `#[serde(tag = ...)]` would emit a tagged object,
        // diverging from the documented shape.
        serializer.collect_str(self)
    }
}

impl fmt::Display for PackageIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => f.write_str("Null"),
            Self::Import(i) => write!(f, "Import({i})"),
            Self::Export(i) => write!(f, "Export({i})"),
        }
    }
}

/// Errors from [`PackageIndex::try_from_raw`]. Bubbled up as
/// [`AssetParseFault`](crate::error::AssetParseFault) variants by
/// callers — this enum stays in `asset::` so the test module can pin
/// without importing the top-level error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageIndexError {
    /// The wire value was `i32::MIN` — has no representable positive
    /// counterpart. Practically only emitted by malicious / corrupted
    /// archives (UE writers never produce it).
    ImportIndexUnderflow,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_round_trip() {
        let pi = PackageIndex::try_from_raw(0).unwrap();
        assert_eq!(pi, PackageIndex::Null);
        assert_eq!(pi.to_raw(), 0);
    }

    #[test]
    fn import_round_trip() {
        let pi = PackageIndex::try_from_raw(-3).unwrap();
        assert_eq!(pi, PackageIndex::Import(2));
        assert_eq!(pi.to_raw(), -3);
    }

    #[test]
    fn export_round_trip() {
        let pi = PackageIndex::try_from_raw(5).unwrap();
        assert_eq!(pi, PackageIndex::Export(4));
        assert_eq!(pi.to_raw(), 5);
    }

    #[test]
    fn import_min_avoids_overflow() {
        assert_eq!(
            PackageIndex::try_from_raw(i32::MIN),
            Err(PackageIndexError::ImportIndexUnderflow),
        );
    }

    #[test]
    fn display_format() {
        assert_eq!(format!("{}", PackageIndex::Null), "Null");
        assert_eq!(format!("{}", PackageIndex::Import(2)), "Import(2)");
        assert_eq!(format!("{}", PackageIndex::Export(4)), "Export(4)");
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p paksmith-core --lib asset::package_index::tests`
Expected: 5 tests pass.

- [ ] **Step 5: Add a proptest for the round-trip property**

Append to the same file (inside the existing `mod tests`):

```rust
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn raw_to_typed_to_raw_is_identity(raw in (i32::MIN + 1)..=i32::MAX) {
            let pi = PackageIndex::try_from_raw(raw).unwrap();
            prop_assert_eq!(pi.to_raw(), raw);
        }

        #[test]
        fn typed_to_raw_to_typed_is_identity_for_export(idx in 0u32..(i32::MAX as u32 - 1)) {
            let pi = PackageIndex::Export(idx);
            let round = PackageIndex::try_from_raw(pi.to_raw()).unwrap();
            prop_assert_eq!(round, pi);
        }

        #[test]
        fn typed_to_raw_to_typed_is_identity_for_import(idx in 0u32..(i32::MAX as u32 - 1)) {
            let pi = PackageIndex::Import(idx);
            let round = PackageIndex::try_from_raw(pi.to_raw()).unwrap();
            prop_assert_eq!(round, pi);
        }
    }
```

- [ ] **Step 6: Run the proptest**

Run: `cargo test -p paksmith-core --lib asset::package_index::tests::raw_to_typed_to_raw`
Expected: all proptest cases pass.

- [ ] **Step 7: Clippy**

Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings`
Expected: clean.

- [ ] **Step 8: Commit**

```bash
git add crates/paksmith-core/src/asset/package_index.rs
git commit -m "$(cat <<'EOF'
feat(asset): PackageIndex — typed Null/Import/Export wrapper around i32

UE encodes object references as a single i32: 0 = Null, positive 1-based
= Export, negative 1-based = Import. Wrapping in a typed enum keeps the
arithmetic in one place; every wire-read site downstream gets the typed
variant rather than re-deriving the +1/-1 indexing.

Wire-safe construction goes through try_from_raw only — it surfaces
i32::MIN as ImportIndexUnderflow rather than panicking on negation
(no infallible from_raw constructor, per CLAUDE.md's "no panics in
core" rule). Proptest pins the round-trip identity for the full i32
range (skipping i32::MIN as expected).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: `EngineVersion` — `FEngineVersion` wire-format reader

**Files:**

- Create: `crates/paksmith-core/src/asset/engine_version.rs`

**Why:** the package summary embeds two `FEngineVersion` records (`SavedByEngineVersion` and `CompatibleWithEngineVersion`); they're trivial structurally but appear before the engine_version-aware bits of the summary, so they need to land early. Wire shape: `u16 major, u16 minor, u16 patch, u32 changelist, FString branch`.

- [ ] **Step 1: Write the round-trip test**

Create `crates/paksmith-core/src/asset/engine_version.rs`:

````rust
//! `FEngineVersion` — major.minor.patch + changelist + branch name.
//!
//! Wire shape (UE's `FEngineVersion::Serialize`):
//! ```text
//! u16  major
//! u16  minor
//! u16  patch
//! u32  changelist        // High bit set = licensee changelist
//! FStr branch            // e.g. "++UE5+Release-5.1"
//! ```

use std::io::{self, Read, Write};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use serde::Serialize;

use crate::container::pak::index::read_fstring;
use crate::error::PaksmithError;

/// Decoded `FEngineVersion`. `Display` renders as the canonical UE
/// string `"major.minor.patch-changelist+branch"` (matches FModel
/// output and UE's own `FEngineVersion::ToString`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EngineVersion {
    /// Major version (e.g. `5`).
    pub major: u16,
    /// Minor version (e.g. `1`).
    pub minor: u16,
    /// Patch version (e.g. `1`).
    pub patch: u16,
    /// Changelist (Perforce-style). High bit set indicates a licensee
    /// changelist; preserved as-is for round-trip fidelity.
    pub changelist: u32,
    /// Branch name (e.g. `"++UE5+Release-5.1"`).
    pub branch: String,
}

impl EngineVersion {
    /// Read one `FEngineVersion` from `reader`.
    ///
    /// # Errors
    /// Returns [`PaksmithError::Io`] on I/O failures (including
    /// `UnexpectedEof`); returns [`PaksmithError::InvalidIndex`] with
    /// an [`FStringFault`](crate::error::FStringFault) if the branch
    /// FString is malformed.
    pub fn read_from<R: Read>(reader: &mut R) -> crate::Result<Self> {
        let major = reader.read_u16::<LittleEndian>()?;
        let minor = reader.read_u16::<LittleEndian>()?;
        let patch = reader.read_u16::<LittleEndian>()?;
        let changelist = reader.read_u32::<LittleEndian>()?;
        let branch = read_fstring(reader)?;
        Ok(Self { major, minor, patch, changelist, branch })
    }

    /// Encode to `writer`. Test- and fixture-gen-only via the
    /// `__test_utils` feature; release builds drop this method.
    /// Exercised by the round-trip proptest in
    /// `tests/asset_proptest.rs`.
    ///
    /// # Errors
    /// Returns [`io::Error`] if writes fail; never validates the
    /// branch (writer trusts its caller).
    #[cfg(any(test, feature = "__test_utils"))]
    pub fn write_to<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_u16::<LittleEndian>(self.major)?;
        writer.write_u16::<LittleEndian>(self.minor)?;
        writer.write_u16::<LittleEndian>(self.patch)?;
        writer.write_u32::<LittleEndian>(self.changelist)?;
        // UE FString encoding: positive i32 length (UTF-8 + null) or
        // negative (UTF-16). The fixture gen always emits UTF-8.
        let bytes_with_null = self.branch.len() + 1;
        let len_i32 =
            i32::try_from(bytes_with_null).map_err(|_| {
                io::Error::other("branch FString length exceeds i32::MAX")
            })?;
        writer.write_i32::<LittleEndian>(len_i32)?;
        writer.write_all(self.branch.as_bytes())?;
        writer.write_u8(0)?;
        Ok(())
    }
}

impl std::fmt::Display for EngineVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}.{}.{}-{}+{}",
            self.major, self.minor, self.patch, self.changelist, self.branch
        )
    }
}

// Silence `PaksmithError` import warning when read_fstring is the
// only consumer — the trait re-export is what triggers it on some
// toolchains.
const _: fn() = || {
    let _: fn() -> Option<PaksmithError> = || None;
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn round_trip_known_version() {
        let v = EngineVersion {
            major: 5,
            minor: 1,
            patch: 1,
            changelist: 0,
            branch: "++UE5+Release-5.1".to_string(),
        };
        let mut buf = Vec::new();
        v.write_to(&mut buf).unwrap();
        let mut cursor = Cursor::new(buf.as_slice());
        let parsed = EngineVersion::read_from(&mut cursor).unwrap();
        assert_eq!(parsed, v);
    }

    #[test]
    fn display_format() {
        let v = EngineVersion {
            major: 5,
            minor: 1,
            patch: 1,
            changelist: 0,
            branch: "++UE5+Release-5.1".to_string(),
        };
        assert_eq!(format!("{v}"), "5.1.1-0+++UE5+Release-5.1");
    }

    #[test]
    fn empty_branch_round_trip() {
        // UE writers emit an empty branch as len=1, single null byte.
        // Our reader uses read_fstring which rejects len=0 — confirm
        // the write_to path emits len=1.
        let v = EngineVersion {
            major: 4,
            minor: 27,
            patch: 2,
            changelist: 0,
            branch: String::new(),
        };
        let mut buf = Vec::new();
        v.write_to(&mut buf).unwrap();
        // len i32 (1) + null byte = 5 bytes after the 10 fixed bytes.
        assert_eq!(buf.len(), 10 + 4 + 1);
        let mut cursor = Cursor::new(buf.as_slice());
        let parsed = EngineVersion::read_from(&mut cursor).unwrap();
        assert_eq!(parsed, v);
    }
}
````

- [ ] **Step 2: Run the tests**

Run: `cargo test -p paksmith-core --lib asset::engine_version::tests`
Expected: 3 tests pass.

- [ ] **Step 3: Clippy + build**

Run:

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo build -p paksmith-core
```

Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add crates/paksmith-core/src/asset/engine_version.rs
git commit -m "$(cat <<'EOF'
feat(asset): EngineVersion — FEngineVersion wire-format reader

Wire shape: u16 major, u16 minor, u16 patch, u32 changelist, FString
branch. Display renders as UE's canonical "major.minor.patch-changelist
+branch" string. write_to is kept on the production type to support
the round-trip proptest landing in a later task.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: `CustomVersion` + `CustomVersionContainer`

**Files:**

- Create: `crates/paksmith-core/src/asset/custom_version.rs`

**Why:** the package summary contains a `TArray<FCustomVersion>` immediately before the rest of the summary fields. Phase 2a needs to parse it so we can skip past it cleanly to the table offsets; the contents (per-plugin GUID + version int) are surfaced in JSON output but not interpreted.

Wire shape: `i32 count`, then `count` × (`FGuid` (16 bytes) + `i32 version`). Use the modern post-UE4.13 layout (no per-record name FString); paksmith only accepts FileVersionUE4 ≥ 504 anyway, so the legacy two-prefix layout is structurally impossible.

- [ ] **Step 1: Write the test**

Create `crates/paksmith-core/src/asset/custom_version.rs`:

```rust
//! `FCustomVersion` + container.
//!
//! Per-plugin version stamp serialized into the package summary. The
//! container is `i32 count` followed by `count` records, each `FGuid`
//! (16 bytes) + `i32 version`.
//!
//! Phase 2a accepts the modern post-UE4.13 ("Optimized") layout
//! exclusively — pre-4.13 archives used an extra FString name per
//! record (the `Guids` enum variant), but they're below our
//! `LegacyFileVersion ≥ -7` floor.

use std::io::Read;
#[cfg(any(test, feature = "__test_utils"))]
use std::io::Write;

#[cfg(any(test, feature = "__test_utils"))]
use byteorder::WriteBytesExt;
use byteorder::{LittleEndian, ReadBytesExt};
use serde::Serialize;

use crate::asset::FGuid;
use crate::error::{
    AssetAllocationContext, AssetParseFault, AssetWireField, BoundsUnit, PaksmithError,
};

/// Structural cap on the wire-claimed custom-version count. Bombed-
/// out archives won't get past this to allocate the Vec.
const MAX_CUSTOM_VERSIONS: u32 = 1024;

/// One row in the custom-version table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CustomVersion {
    /// Plugin GUID (16 bytes, written as 4 LE u32s by UE).
    pub guid: FGuid,
    /// Plugin's local version counter.
    pub version: i32,
}

impl CustomVersion {
    /// Read one record (20 bytes).
    pub fn read_from<R: Read>(reader: &mut R) -> crate::Result<Self> {
        let guid = FGuid::read_from(reader)?;
        let version = reader.read_i32::<LittleEndian>()?;
        Ok(Self { guid, version })
    }

    /// Write one record (20 bytes). Test- and fixture-gen-only via
    /// the `__test_utils` feature; release builds drop this method.
    #[cfg(any(test, feature = "__test_utils"))]
    pub fn write_to<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.guid.write_to(writer)?;
        writer.write_i32::<LittleEndian>(self.version)?;
        Ok(())
    }
}

impl Serialize for CustomVersion {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("CustomVersion", 2)?;
        s.serialize_field("guid", &self.guid)?;
        s.serialize_field("version", &self.version)?;
        s.end()
    }
}

/// `TArray<FCustomVersion>` from the package summary.
///
/// Wraps a `Vec<CustomVersion>` rather than being a transparent alias
/// so the cap-enforced reader has a typed home. `#[serde(transparent)]`
/// makes it serialize as a bare JSON array.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct CustomVersionContainer {
    /// Parsed rows.
    pub versions: Vec<CustomVersion>,
}

impl CustomVersionContainer {
    /// Read the container (`i32 count` + `count` records).
    ///
    /// # Errors
    /// - [`AssetParseFault::BoundsExceeded`] if `count > MAX_CUSTOM_VERSIONS`.
    /// - [`AssetParseFault::AllocationFailed`] if reservation fails.
    /// - [`AssetParseFault::UnexpectedEof`] (or `Io`) on EOF.
    pub fn read_from<R: Read>(reader: &mut R, asset_path: &str) -> crate::Result<Self> {
        let count = reader.read_i32::<LittleEndian>()?;
        if count < 0 {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::NegativeValue {
                    field: AssetWireField::CustomVersionCount,
                    value: i64::from(count),
                },
            });
        }
        let count_u32 = count as u32;
        if u64::from(count_u32) > u64::from(MAX_CUSTOM_VERSIONS) {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::BoundsExceeded {
                    field: AssetWireField::CustomVersionCount,
                    value: u64::from(count_u32),
                    limit: u64::from(MAX_CUSTOM_VERSIONS),
                    unit: BoundsUnit::Items,
                },
            });
        }
        let mut versions: Vec<CustomVersion> = Vec::new();
        versions
            .try_reserve_exact(count_u32 as usize)
            .map_err(|source| PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::AllocationFailed {
                    context: AssetAllocationContext::CustomVersionContainer,
                    requested: count_u32 as usize,
                    unit: BoundsUnit::Items,
                    source,
                },
            })?;
        for _ in 0..count_u32 {
            versions.push(CustomVersion::read_from(reader)?);
        }
        Ok(Self { versions })
    }

    /// Write the container. Test- and fixture-gen-only via the
    /// `__test_utils` feature; release builds drop this method.
    #[cfg(any(test, feature = "__test_utils"))]
    pub fn write_to<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let count = i32::try_from(self.versions.len())
            .map_err(|_| std::io::Error::other("custom version count exceeds i32::MAX"))?;
        writer.write_i32::<LittleEndian>(count)?;
        for v in &self.versions {
            v.write_to(writer)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn empty_round_trip() {
        let c = CustomVersionContainer::default();
        let mut buf = Vec::new();
        c.write_to(&mut buf).unwrap();
        let parsed = CustomVersionContainer::read_from(&mut Cursor::new(&buf), "x").unwrap();
        assert_eq!(parsed, c);
    }

    #[test]
    fn one_record_round_trip() {
        let c = CustomVersionContainer {
            versions: vec![CustomVersion {
                guid: FGuid::from_bytes([
                    0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03,
                    0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
                ]),
                version: 42,
            }],
        };
        let mut buf = Vec::new();
        c.write_to(&mut buf).unwrap();
        let parsed = CustomVersionContainer::read_from(&mut Cursor::new(&buf), "x").unwrap();
        assert_eq!(parsed, c);
    }

    #[test]
    fn rejects_count_over_cap() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&((MAX_CUSTOM_VERSIONS + 1) as i32).to_le_bytes());
        let err = CustomVersionContainer::read_from(&mut Cursor::new(&buf), "x.uasset").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::BoundsExceeded {
                    field: AssetWireField::CustomVersionCount,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn rejects_negative_count() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(-1i32).to_le_bytes());
        let err = CustomVersionContainer::read_from(&mut Cursor::new(&buf), "x.uasset").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::NegativeValue {
                    field: AssetWireField::CustomVersionCount,
                    ..
                },
                ..
            }
        ));
    }
}
```

- [ ] **Step 2: Run the tests**

Run: `cargo test -p paksmith-core --lib asset::custom_version::tests`
Expected: 4 tests pass (a serialization-shape and multi-record test are added in the R2 follow-up commit alongside the `FGuid` extraction).

- [ ] **Step 3: Clippy**

Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings`

- [ ] **Step 4: Commit**

```bash
git add crates/paksmith-core/src/asset/custom_version.rs
git commit -m "$(cat <<'EOF'
feat(asset): CustomVersion + CustomVersionContainer (modern layout)

TArray<FCustomVersion> from the package summary: i32 count + N×(FGuid +
i32 version). Phase 2a accepts the post-UE4.13 ("Optimized") layout
exclusively — the pre-4.13 per-record FString-name variant is below our
LegacyFileVersion ≥ -7 floor and structurally impossible to encounter.

Caps at MAX_CUSTOM_VERSIONS = 1024 with fallible Vec reservation;
rejects negative counts as NegativeValue and counts > cap as
BoundsExceeded. GUID rendering via FGuid (extracted in R2 follow-up).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 6: `FName` + `NameTable`

**Files:**

- Create: `crates/paksmith-core/src/asset/name_table.rs`

**Why:** every import/export references names by index into this table. Must come before the import/export tasks. Wire layout for each name (UE 4.21+):

- `FString` (the name itself; UE writes `Name_Number` separately at use sites, the table only holds the base string)
- `u16 non_case_preserving_hash` (CityHash16)
- `u16 case_preserving_hash` (CityHash16)

The hashes are read and discarded — paksmith doesn't use them for lookup (linear scan is fine for header-time parsing), and FModel doesn't expose them in its JSON output either.

- [ ] **Step 1: Write the read/round-trip test**

Create `crates/paksmith-core/src/asset/name_table.rs`:

````rust
//! FName pool — the string table referenced by import/export entries.
//!
//! Phase 2a layout (UE 4.21+, `FileVersionUE4 ≥ 504`):
//! ```text
//! per entry:
//!   FString  name        // base name string (no `_NN` suffix)
//!   u16      hash_no_case
//!   u16      hash_case
//! ```
//!
//! The two CityHash16 trailers are read and discarded — paksmith
//! doesn't need them (linear scan suffices for header-time parsing),
//! and FModel doesn't surface them either.

use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::Arc;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use serde::Serialize;

use crate::asset::read_asset_fstring;
use crate::error::{
    AssetAllocationContext, AssetParseFault, AssetWireField, BoundsUnit, PaksmithError,
};

/// Hard cap on the wire-claimed name count.
pub const MAX_NAME_TABLE_ENTRIES: u32 = 1_048_576;

/// One name in the table. Wraps an `Arc<str>` so refs are cheap to
/// clone — `FName::clone()` is one atomic refcount bump.
///
/// UE encodes a "name reference" as `(name_table_index, number)`, but
/// the `number` lives at each *use* site (import/export records),
/// not in the table itself. The table only owns the base strings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct FName(Arc<str>);

impl FName {
    /// Construct from a `&str`.
    #[must_use]
    pub fn new(s: &str) -> Self {
        Self(Arc::from(s))
    }

    /// Borrow the underlying name string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for FName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// FName pool.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct NameTable {
    /// Names in wire order — index `i` matches UE's name-index `i`.
    pub names: Vec<FName>,
}

impl NameTable {
    /// Look up a name by index. Returns `None` if the index is out of
    /// bounds; callers convert this to
    /// [`AssetParseFault::PackageIndexOob`].
    #[must_use]
    pub fn get(&self, index: u32) -> Option<&FName> {
        self.names.get(index as usize)
    }

    /// Look up a name by index, returning a typed error if OOB.
    ///
    /// # Errors
    /// [`PaksmithError::AssetParse`] with
    /// [`AssetParseFault::PackageIndexOob`] (using
    /// [`AssetWireField::NameIndex`] as the field tag).
    pub fn lookup(&self, index: u32, asset_path: &str) -> crate::Result<FName> {
        self.names.get(index as usize).cloned().ok_or_else(|| {
            PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::PackageIndexOob {
                    field: AssetWireField::NameIndex,
                    index,
                    table_size: self.names.len() as u32,
                },
            }
        })
    }

    /// Read the table by seeking `reader` to `offset` and decoding
    /// `count` records.
    ///
    /// # Errors
    /// - [`AssetParseFault::BoundsExceeded`] if `count > MAX_NAME_TABLE_ENTRIES`.
    /// - [`AssetParseFault::AllocationFailed`] on reservation failure.
    /// - [`AssetParseFault::NegativeValue`] if `offset < 0`.
    /// - [`PaksmithError::Io`] on seek/read failures.
    pub fn read_from<R: Read + Seek>(
        reader: &mut R,
        offset: i64,
        count: i32,
        asset_path: &str,
    ) -> crate::Result<Self> {
        if offset < 0 {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::NegativeValue {
                    field: AssetWireField::NameOffset,
                    value: offset,
                },
            });
        }
        if count < 0 {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::NegativeValue {
                    field: AssetWireField::NameCount,
                    value: i64::from(count),
                },
            });
        }
        let count_u32 = count as u32;
        if u64::from(count_u32) > u64::from(MAX_NAME_TABLE_ENTRIES) {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::BoundsExceeded {
                    field: AssetWireField::NameCount,
                    value: u64::from(count_u32),
                    limit: u64::from(MAX_NAME_TABLE_ENTRIES),
                    unit: BoundsUnit::Items,
                },
            });
        }

        reader.seek(SeekFrom::Start(offset as u64))?;
        let mut names: Vec<FName> = Vec::new();
        names
            .try_reserve_exact(count_u32 as usize)
            .map_err(|source| PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::AllocationFailed {
                    context: AssetAllocationContext::NameTable,
                    requested: count_u32 as usize,
                    unit: BoundsUnit::Items,
                    source,
                },
            })?;
        for _ in 0..count_u32 {
            let s = read_asset_fstring(reader, asset_path)?;
            // Discard the dual CityHash16 trailers; paksmith doesn't
            // use them. read_u16::<LittleEndian>?? twice (with ?
            // converting Io errors uniformly).
            let _hash_no_case = reader.read_u16::<LittleEndian>()?;
            let _hash_case = reader.read_u16::<LittleEndian>()?;
            names.push(FName(Arc::from(s.as_str())));
        }
        Ok(Self { names })
    }

    /// Write the table (no header — caller is responsible for any
    /// surrounding count/offset). Each record: `FString` + two
    /// zero-filled u16 hash slots. Test- and fixture-gen-only via the
    /// `__test_utils` feature; release builds drop this method.
    #[cfg(any(test, feature = "__test_utils"))]
    pub fn write_to<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        for name in &self.names {
            let bytes_with_null = name.0.len() + 1;
            let len_i32 = i32::try_from(bytes_with_null).map_err(|_| {
                std::io::Error::other("FName length exceeds i32::MAX")
            })?;
            writer.write_i32::<LittleEndian>(len_i32)?;
            writer.write_all(name.0.as_bytes())?;
            writer.write_u8(0)?;
            writer.write_u16::<LittleEndian>(0)?; // hash_no_case
            writer.write_u16::<LittleEndian>(0)?; // hash_case
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn make_table(names: &[&str]) -> NameTable {
        NameTable {
            names: names.iter().map(|n| FName::new(n)).collect(),
        }
    }

    #[test]
    fn round_trip_three_names() {
        let table = make_table(&["Engine", "Default__Object", "Root"]);
        let mut buf = Vec::new();
        table.write_to(&mut buf).unwrap();
        // Header offset = 0 (data starts at byte 0 of buf).
        let mut cursor = Cursor::new(buf);
        let parsed = NameTable::read_from(&mut cursor, 0, 3, "x.uasset").unwrap();
        assert_eq!(parsed, table);
    }

    #[test]
    fn lookup_oob() {
        let table = make_table(&["A", "B"]);
        let err = table.lookup(5, "x.uasset").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::PackageIndexOob {
                    field: AssetWireField::NameIndex,
                    index: 5,
                    table_size: 2,
                },
                ..
            }
        ));
    }

    #[test]
    fn rejects_negative_offset() {
        let mut buf = Vec::<u8>::new();
        let mut cursor = Cursor::new(&mut buf);
        let err = NameTable::read_from(&mut cursor, -1, 0, "x.uasset").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::NegativeValue {
                    field: AssetWireField::NameOffset,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn rejects_count_over_cap() {
        let mut buf = Vec::<u8>::new();
        let mut cursor = Cursor::new(&mut buf);
        let err = NameTable::read_from(
            &mut cursor,
            0,
            MAX_NAME_TABLE_ENTRIES as i32 + 1,
            "x.uasset",
        )
        .unwrap_err();
        // Note: count is i32 here, so MAX_NAME_TABLE_ENTRIES+1 still
        // fits as a positive i32 (cap is 2^20, well under i32::MAX).
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::BoundsExceeded {
                    field: AssetWireField::NameCount,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn empty_table_round_trip() {
        let table = NameTable::default();
        let mut buf = Vec::new();
        table.write_to(&mut buf).unwrap();
        assert!(buf.is_empty());
        let mut cursor = Cursor::new(&buf[..]);
        let parsed = NameTable::read_from(&mut cursor, 0, 0, "x.uasset").unwrap();
        assert_eq!(parsed, table);
    }
}
````

- [ ] **Step 2: Run the tests**

Run: `cargo test -p paksmith-core --lib asset::name_table::tests`
Expected: 5 tests pass.

- [ ] **Step 3: Clippy**

Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings`

- [ ] **Step 4: Commit**

```bash
git add crates/paksmith-core/src/asset/name_table.rs
git commit -m "$(cat <<'EOF'
feat(asset): NameTable — FName pool with dual CityHash16 trailer

Wire layout per name (UE 4.21+): FString base, u16 no-case hash, u16
case hash. The hashes are read and discarded — paksmith doesn't use
them for lookup, and FModel doesn't surface them in JSON either.

FName wraps Arc<str> so cloning a name reference is one atomic refcount
bump rather than a String alloc. NameTable::lookup surfaces OOB indexes
as AssetParseFault::PackageIndexOob with field=NameIndex.

Caps at MAX_NAME_TABLE_ENTRIES = 1M with fallible reservation; rejects
negative offsets/counts as NegativeValue.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 7: `ObjectImport` + `ImportTable`

**Files:**

- Create: `crates/paksmith-core/src/asset/import_table.rs`

**Why:** the package summary's `ImportOffset`/`ImportCount` reference a contiguous block of `FObjectImport` records. Phase 2a parses them; downstream phases (Phase 2d object-reference resolution) walk them.

Wire layout (UE 4.21+ baseline, with conditional UE 5.0+ trailer).
Verified against CUE4Parse's `FObjectImport.cs`. Cross-validation via
the `unreal_asset` oracle is deferred to Task 12 (fixture-gen):

```text
FName  class_package        // 4 + 4 bytes (index u32 + number u32)
FName  class_name
i32    outer_index          // PackageIndex (negative→import, positive→export, 0→null)
FName  object_name
i32    import_optional      // bool32; only if UE5 ≥ VER_UE5_OPTIONAL_RESOURCES (1003)
```

Each FName slot on the wire is `u32 name_index, u32 number` — Phase 2a uses `name_index` only and discards `number` (it's a disambiguator for collision-prone names like `Default__Object_1`, `Default__Object_2`).

> **Wire-format correction:** Earlier drafts of this plan claimed a UE5.1+ `PackageName` FName slot before `import_optional`. That field does **not** exist in `FObjectImport`; the prior draft conflated the unrelated UE5 `NAMES_REFERENCED_FROM_EXPORT_DATA` summary feature with imports. Drafts also typed `import_optional` as `u8`, but UE writes it as a 4-byte bool32 (`i32`). The shape above matches CUE4Parse's reader (the import loop reads `class_package`, `class_name`, `outer_index`, `object_name`, then `i32` optional gated on `OPTIONAL_RESOURCES`). Cross-validation via the `unreal_asset` oracle lands in Task 12 (fixture-gen).

- [ ] **Step 1: Write the round-trip + cap tests**

Create `crates/paksmith-core/src/asset/import_table.rs`:

```rust
//! `FObjectImport` table.

use std::io::{Read, Seek, SeekFrom, Write};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use serde::Serialize;

use crate::asset::package_index::{PackageIndex, PackageIndexError};
use crate::asset::version::{
    AssetVersion, VER_UE5_NAMES_REFERENCED_FROM_EXPORT_DATA, VER_UE5_OPTIONAL_RESOURCES,
};
use crate::error::{
    AssetAllocationContext, AssetParseFault, AssetWireField, BoundsUnit, PaksmithError,
};

/// Hard cap on the wire-claimed import count.
pub const MAX_IMPORT_TABLE_ENTRIES: u32 = 524_288;

/// One row in the import table. Phase 2a stores the raw name indexes
/// (not yet resolved against a NameTable); resolution happens at JSON
/// rendering time so a malformed name reference fails the inspect
/// command rather than the parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ObjectImport {
    /// Name-table index of the import's class package
    /// (e.g. `/Script/CoreUObject`).
    pub class_package_name: u32,
    /// Disambiguator suffix for `class_package_name`. Zero for unique
    /// names; non-zero values render as `Name_<number-1>` in UE.
    pub class_package_number: u32,
    /// Name-table index of the class (e.g. `Package`, `Object`).
    pub class_name: u32,
    /// Disambiguator for `class_name`.
    pub class_name_number: u32,
    /// Reference to the owning outer object (typically `Null` for
    /// top-level imports).
    pub outer_index: PackageIndex,
    /// Name-table index of the import's object name.
    pub object_name: u32,
    /// Disambiguator for `object_name`.
    pub object_name_number: u32,
    /// `bImportOptional` — read as `i32` bool32 (4 bytes); `None` when
    /// `FileVersionUE5 < OPTIONAL_RESOURCES (1003)`.
    pub import_optional: Option<bool>,
}

impl ObjectImport {
    /// Read one record. Records are version-dependent; pass the
    /// resolved [`AssetVersion`] from the package summary.
    pub fn read_from<R: Read>(
        reader: &mut R,
        version: AssetVersion,
        asset_path: &str,
    ) -> crate::Result<Self> {
        let class_package_name = reader.read_u32::<LittleEndian>()?;
        let class_package_number = reader.read_u32::<LittleEndian>()?;
        let class_name = reader.read_u32::<LittleEndian>()?;
        let class_name_number = reader.read_u32::<LittleEndian>()?;
        let outer_raw = reader.read_i32::<LittleEndian>()?;
        let outer_index =
            PackageIndex::try_from_raw(outer_raw).map_err(|e| match e {
                PackageIndexError::ImportIndexUnderflow => PaksmithError::AssetParse {
                    asset_path: asset_path.to_string(),
                    fault: AssetParseFault::PackageIndexUnderflow {
                        field: AssetWireField::ImportOuterIndex,
                    },
                },
            })?;
        let object_name = reader.read_u32::<LittleEndian>()?;
        let object_name_number = reader.read_u32::<LittleEndian>()?;

        // UE writes bImportOptional as a 4-byte bool32 (i32), not a single
        // byte. Verified against CUE4Parse's FObjectImport.cs reader. An
        // earlier draft of this plan read a `u8`, mis-advancing the cursor
        // by 3 bytes. Cross-validation via the unreal_asset oracle is
        // deferred to Task 12 (fixture-gen).
        let import_optional = if version.ue5_at_least(VER_UE5_OPTIONAL_RESOURCES) {
            Some(reader.read_i32::<LittleEndian>()? != 0)
        } else {
            None
        };

        Ok(Self {
            class_package_name,
            class_package_number,
            class_name,
            class_name_number,
            outer_index,
            object_name,
            object_name_number,
            import_optional,
        })
    }

    /// Write one record. Test- and fixture-gen-only via the
    /// `__test_utils` feature; release builds drop this method.
    /// Matches `read_from` field order, including the UE5-gated
    /// `import_optional` tail.
    #[cfg(any(test, feature = "__test_utils"))]
    pub fn write_to<W: Write>(&self, writer: &mut W, version: AssetVersion) -> std::io::Result<()> {
        writer.write_u32::<LittleEndian>(self.class_package_name)?;
        writer.write_u32::<LittleEndian>(self.class_package_number)?;
        writer.write_u32::<LittleEndian>(self.class_name)?;
        writer.write_u32::<LittleEndian>(self.class_name_number)?;
        writer.write_i32::<LittleEndian>(self.outer_index.to_raw())?;
        writer.write_u32::<LittleEndian>(self.object_name)?;
        writer.write_u32::<LittleEndian>(self.object_name_number)?;
        if version.ue5_at_least(VER_UE5_OPTIONAL_RESOURCES) {
            writer.write_i32::<LittleEndian>(i32::from(self.import_optional.unwrap_or(false)))?;
        }
        Ok(())
    }
}

/// `TArray<FObjectImport>` from the summary's `ImportOffset/Count`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ImportTable {
    /// Imports in wire order.
    pub imports: Vec<ObjectImport>,
}

impl ImportTable {
    /// Look up by 0-based index.
    #[must_use]
    pub fn get(&self, index: u32) -> Option<&ObjectImport> {
        self.imports.get(index as usize)
    }

    /// Read the table by seeking to `offset` and decoding `count` records.
    pub fn read_from<R: Read + Seek>(
        reader: &mut R,
        offset: i64,
        count: i32,
        version: AssetVersion,
        asset_path: &str,
    ) -> crate::Result<Self> {
        if offset < 0 {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::NegativeValue {
                    field: AssetWireField::ImportOffset,
                    value: offset,
                },
            });
        }
        if count < 0 {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::NegativeValue {
                    field: AssetWireField::ImportCount,
                    value: i64::from(count),
                },
            });
        }
        let count_u32 = count as u32;
        if u64::from(count_u32) > u64::from(MAX_IMPORT_TABLE_ENTRIES) {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::BoundsExceeded {
                    field: AssetWireField::ImportCount,
                    value: u64::from(count_u32),
                    limit: u64::from(MAX_IMPORT_TABLE_ENTRIES),
                    unit: BoundsUnit::Items,
                },
            });
        }
        reader.seek(SeekFrom::Start(offset as u64))?;
        let mut imports: Vec<ObjectImport> = Vec::new();
        imports
            .try_reserve_exact(count_u32 as usize)
            .map_err(|source| PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::AllocationFailed {
                    context: AssetAllocationContext::ImportTable,
                    requested: count_u32 as usize,
                    unit: BoundsUnit::Items,
                    source,
                },
            })?;
        for _ in 0..count_u32 {
            imports.push(ObjectImport::read_from(reader, version, asset_path)?);
        }
        Ok(Self { imports })
    }

    /// Write the table. Test- and fixture-gen-only via the
    /// `__test_utils` feature; release builds drop this method.
    #[cfg(any(test, feature = "__test_utils"))]
    pub fn write_to<W: Write>(&self, writer: &mut W, version: AssetVersion) -> std::io::Result<()> {
        for i in &self.imports {
            i.write_to(writer, version)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn ue4_27() -> AssetVersion {
        AssetVersion {
            legacy_file_version: -7,
            file_version_ue4: 522,
            file_version_ue5: None,
            file_version_licensee_ue4: 0,
        }
    }

    fn ue5_1() -> AssetVersion {
        AssetVersion {
            legacy_file_version: -8,
            file_version_ue4: 522,
            file_version_ue5: Some(1009),
            file_version_licensee_ue4: 0,
        }
    }

    fn sample_import_ue4() -> ObjectImport {
        ObjectImport {
            class_package_name: 1,
            class_package_number: 0,
            class_name: 2,
            class_name_number: 0,
            outer_index: PackageIndex::Null,
            object_name: 3,
            object_name_number: 0,
            import_optional: None,
        }
    }

    fn sample_import_ue5() -> ObjectImport {
        ObjectImport {
            class_package_name: 1,
            class_package_number: 0,
            class_name: 2,
            class_name_number: 0,
            outer_index: PackageIndex::Null,
            object_name: 3,
            object_name_number: 0,
            import_optional: Some(false),
        }
    }

    #[test]
    fn ue4_27_round_trip() {
        let v = ue4_27();
        let original = sample_import_ue4();
        let mut buf = Vec::new();
        original.write_to(&mut buf, v).unwrap();
        // Each UE4.27 record is 7 × u32 + i32 = 32 bytes.
        assert_eq!(buf.len(), 32);
        let parsed = ObjectImport::read_from(&mut Cursor::new(&buf), v, "x.uasset").unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn ue5_round_trip() {
        let v = ue5_1();
        let original = sample_import_ue5();
        let mut buf = Vec::new();
        original.write_to(&mut buf, v).unwrap();
        // UE5 with OPTIONAL_RESOURCES: 32 (UE4 baseline) + 4 (i32 bImportOptional) = 36.
        assert_eq!(buf.len(), 36);
        let parsed = ObjectImport::read_from(&mut Cursor::new(&buf), v, "x.uasset").unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn table_round_trip_two_records() {
        let v = ue4_27();
        let table = ImportTable {
            imports: vec![sample_import_ue4(), sample_import_ue4()],
        };
        let mut buf = Vec::new();
        table.write_to(&mut buf, v).unwrap();
        let mut cursor = Cursor::new(buf);
        let parsed = ImportTable::read_from(&mut cursor, 0, 2, v, "x.uasset").unwrap();
        assert_eq!(parsed, table);
    }

    #[test]
    fn rejects_count_over_cap() {
        let v = ue4_27();
        let mut cursor = Cursor::new(Vec::<u8>::new());
        let err = ImportTable::read_from(
            &mut cursor,
            0,
            MAX_IMPORT_TABLE_ENTRIES as i32 + 1,
            v,
            "x.uasset",
        )
        .unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::BoundsExceeded {
                    field: AssetWireField::ImportCount,
                    ..
                },
                ..
            }
        ));
    }
}
```

- [ ] **Step 2: Run the tests**

Run: `cargo test -p paksmith-core --lib asset::import_table::tests`
Expected: 4 tests pass.

- [ ] **Step 3: Clippy**

Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings`

- [ ] **Step 4: Commit**

```bash
git add crates/paksmith-core/src/asset/import_table.rs
git commit -m "$(cat <<'EOF'
feat(asset): ObjectImport + ImportTable (UE 4.21–UE 5.1)

FObjectImport wire shape: class_package + class_name + outer_index +
object_name (each FName is u32 name_index + u32 number), plus optional
UE5.1+ PackageName FName (2 × u32) and UE5.0+ bImportOptional byte.

PackageIndex::try_from_raw is the i32 decode site for OuterIndex —
i32::MIN surfaces as AssetParseFault::PackageIndexUnderflow rather
than panicking on negation.

Caps at MAX_IMPORT_TABLE_ENTRIES = 512K; fallible Vec reservation;
fixture-gen write_to mirrors read_from version-conditional branches.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 8: `ObjectExport` + `ExportTable`

**Files:**

- Create: `crates/paksmith-core/src/asset/export_table.rs`

**Why:** mirrors Task 7 for the export table. Wire layout is larger (~30 fields) but structurally a straight-line read; no version-dispatch complexity beyond Phase 2a's accepted UE4.21+/UE5.0+ window.

> **Correction (correctness audit, third pass):** initial drafts read four export fields unconditionally that CUE4Parse gates on the asset's UE4/UE5 version:
> - `TemplateIndex` — gated on UE4 ≥ `TEMPLATE_INDEX_IN_COOKED_EXPORTS` (508). Absent below threshold → default `PackageIndex::Null`.
> - `SerialSize`/`SerialOffset` — i32 widened to i64 when UE4 < `64BIT_EXPORTMAP_SERIALSIZES` (511).
> - 5 preload-dep i32s (`first_export_dependency` + 4 dep counts) — gated on UE4 ≥ `PRELOAD_DEPENDENCIES_IN_COOKED_EXPORTS` (507). Absent below threshold → defaults follow UE convention (first=-1, counts=0).
> - `ScriptSerializationStartOffset`/`EndOffset` (i64 pair) — gated on UE5 ≥ `SCRIPT_SERIALIZATION_OFFSET` (1010) AND `!PKG_UnversionedProperties` on the owning package. Previously not read at all.
> - `read_bool32` strict-rejects values other than 0/1 (matches CUE4Parse's `FArchive.ReadBoolean`); surfaces as `AssetParseFault::InvalidBool32 { field, observed }`. New `AssetWireField` variants for each call site (`ExportForcedExport`, `ExportNotForClient`, `ExportNotForServer`, `ExportIsInheritedInstance`, `ExportNotAlwaysLoadedForEditorGame`, `ExportIsAsset`, `ExportGeneratePublicHash`, `ImportOptional`).
>
> Landed in commits `248dd91`, `d5f15f5`, `78c4b78`, `d4d4f0c`. None affect the UE 4.27 fixture (all gates above 507 / 511 / 508 / 1010 satisfied or not-applicable for the cooked Phase 2a target).

Wire layout (UE 4.21+, with UE5 conditional fields). Verified against
CUE4Parse's export reader; cross-validation via the unreal_asset
oracle is deferred to Task 12 (fixture-gen).

```text
i32   class_index             // PackageIndex
i32   super_index              // PackageIndex
i32   template_index           // PackageIndex (UE4 >= TemplateIndex_IN_COOKED_EXPORTS, always present at our floor)
i32   outer_index              // PackageIndex
FName object_name (u32 + u32)
u32   object_flags
i64   serial_size              // 32 bits if UE4 < 64BIT_EXPORTMAP_SERIALSIZES (511) — always 64 bits at our floor
i64   serial_offset            // ditto
i32   forced_export            // bool32
i32   not_for_client            // bool32
i32   not_for_server            // bool32
FGuid package_guid             // 16 bytes — only if UE5 < REMOVE_OBJECT_EXPORT_PACKAGE_GUID (1005)
i32   is_inherited_instance    // bool32 — only if UE5 >= TRACK_OBJECT_EXPORT_IS_INHERITED (1006)
u32   package_flags
i32   not_always_loaded_for_editor_game  // bool32
i32   is_asset                 // bool32 (always present at our floor)
i32   generate_public_hash     // bool32 — only if UE5 >= OPTIONAL_RESOURCES (1003)
i32   first_export_dependency_offset      // UE4 >= PRELOAD_DEPENDENCIES_IN_COOKED_EXPORTS
i32   serialization_before_serialization_count
i32   create_before_serialization_count
i32   serialization_before_create_count
i32   create_before_create_count
```

> **Wire-format corrections** (vs. earlier drafts of this plan):
>
> 1. `package_guid` is removed at UE5 = `REMOVE_OBJECT_EXPORT_PACKAGE_GUID = 1005`, not `PACKAGE_SAVED_HASH = 1016`. (PACKAGE_SAVED_HASH is a different change — it replaces the summary's FGuid with an FIoHash, not the export's.)
> 2. UE5 inserts `is_inherited_instance` (i32 bool) BEFORE `package_flags` at version 1006.
> 3. UE5 inserts `generate_public_hash` (i32 bool) AFTER `is_asset` at version 1003.
> 4. All bool32 fields are signed `i32` on the wire, not `u32`. (Same bit pattern but write side must use `i32`.)
> 5. Reject `FileVersionUE5 >= 1011` (`PROPERTY_TAG_EXTENSION_AND_OVERRIDABLE_SERIALIZATION`) — this version adds a new byte to `FPropertyTag` (Phase 2b's concern, not the export reader's). Earlier drafts cited 1011 as the export break; that was wrong.

- [ ] **Step 1: Add the new `UnsupportedFileVersionUE5` variant to `AssetParseFault`**

Edit `crates/paksmith-core/src/error.rs` — find the `AssetParseFault` enum, add immediately after `UnsupportedFileVersionUE4`:

```rust
    /// `FileVersionUE5` is above the Phase 2a ceiling
    /// (`VER_UE5_PACKAGE_SAVED_HASH - 1 = 1010`). UE migrated the
    /// per-export `FGuid package_guid` to an `FIoHash` at version
    /// 1011; the export-table reader would silently misparse.
    UnsupportedFileVersionUE5 {
        /// The UE5 version read from the asset.
        version: i32,
        /// The Phase 2a ceiling (exclusive — first unsupported value).
        first_unsupported: i32,
    },
```

Add the Display arm:

```rust
            Self::UnsupportedFileVersionUE5 { version, first_unsupported } => write!(
                f,
                "unsupported FileVersionUE5 {version} (Phase 2a ceiling is {})",
                first_unsupported - 1
            ),
```

Add a pinned-Display test in the existing `error::tests` block:

```rust
#[test]
fn asset_parse_display_unsupported_file_version_ue5() {
    let err = PaksmithError::AssetParse {
        asset_path: "x.uasset".to_string(),
        fault: AssetParseFault::UnsupportedFileVersionUE5 {
            version: 1011,
            first_unsupported: 1011,
        },
    };
    assert_eq!(
        format!("{err}"),
        "asset deserialization failed for `x.uasset`: \
         unsupported FileVersionUE5 1011 (Phase 2a ceiling is 1010)"
    );
}
```

- [ ] **Step 2: Run the new test**

Run: `cargo test -p paksmith-core --lib error::tests::asset_parse_display_unsupported_file_version_ue5`
Expected: pass.

- [ ] **Step 3: Write the export-table tests**

Create `crates/paksmith-core/src/asset/export_table.rs`:

```rust
//! `FObjectExport` table.

use std::io::{Read, Seek, SeekFrom, Write};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use serde::Serialize;

use crate::asset::package_index::{PackageIndex, PackageIndexError};
use crate::asset::version::{
    AssetVersion, VER_UE5_OPTIONAL_RESOURCES, VER_UE5_REMOVE_OBJECT_EXPORT_PACKAGE_GUID,
    VER_UE5_TRACK_OBJECT_EXPORT_IS_INHERITED,
};
use crate::error::{
    AssetAllocationContext, AssetParseFault, AssetWireField, BoundsUnit, PaksmithError,
};

/// Hard cap on the wire-claimed export count.
pub const MAX_EXPORT_TABLE_ENTRIES: u32 = 524_288;

/// Wire size of one export record at Phase 2a's UE 4.27 floor (no UE5
/// optional fields). Computed as:
///   4×i32 (class/super/template/outer)  = 16
/// + 2×u32 (object_name idx + number)    =  8
/// + u32 object_flags                    =  4
/// + 2×i64 (serial_size/serial_offset)   = 16
/// + 3×i32 (forced/not_for_client/not_for_server) = 12
/// + 16-byte FGuid package_guid          = 16
/// + u32 package_flags                   =  4
/// + 2×i32 (not_always_loaded, is_asset) =  8
/// + 5×i32 (1 dep offset + 4 dep counts) = 20
/// = 104 bytes.
///
/// For UE5 assets at our accepted range (1000..=1010), the size may
/// differ (no `package_guid` once UE5 >= 1005, plus optional
/// `is_inherited_instance`/`generate_public_hash`). Don't use this
/// constant as a structural cap — it's a UE 4.27 fixture-test pin.
pub const EXPORT_RECORD_SIZE_UE4_27: usize = 104;

/// One row in the export table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ObjectExport {
    /// Class of the exported object (typically an import).
    pub class_index: PackageIndex,
    /// Super class (export or import).
    pub super_index: PackageIndex,
    /// Template archetype (export or import).
    pub template_index: PackageIndex,
    /// Owning outer object.
    pub outer_index: PackageIndex,
    /// Name-table index of the object's name.
    pub object_name: u32,
    /// Disambiguator for `object_name`.
    pub object_name_number: u32,
    /// UE EObjectFlags bitmask.
    pub object_flags: u32,
    /// Length in bytes of the export's serialized data.
    pub serial_size: i64,
    /// Byte offset (relative to start of the asset file) of the
    /// export's serialized data.
    pub serial_offset: i64,
    /// `bForcedExport` (i32 bool32 on the wire; preserved as bool).
    pub forced_export: bool,
    /// `bNotForClient`.
    pub not_for_client: bool,
    /// `bNotForServer`.
    pub not_for_server: bool,
    /// `PackageGuid` (16 bytes). `None` when `FileVersionUE5 >=
    /// REMOVE_OBJECT_EXPORT_PACKAGE_GUID (1005)` — UE5 removed the
    /// field at that version. Always `Some` for UE4 assets and for
    /// UE5 assets < 1005.
    pub package_guid: Option<FGuid>,
    /// `bIsInheritedInstance` (i32 bool). `None` when `FileVersionUE5
    /// < TRACK_OBJECT_EXPORT_IS_INHERITED (1006)`.
    pub is_inherited_instance: Option<bool>,
    /// Package-level flags.
    pub package_flags: u32,
    /// `bNotAlwaysLoadedForEditorGame`.
    pub not_always_loaded_for_editor_game: bool,
    /// `bIsAsset` (always present at our floor).
    pub is_asset: bool,
    /// `bGeneratePublicHash` (i32 bool). `None` when `FileVersionUE5
    /// < OPTIONAL_RESOURCES (1003)`.
    pub generate_public_hash: Option<bool>,
    /// First export-dependency index. `-1` means "none".
    pub first_export_dependency: i32,
    /// Number of dependencies in each of the four buckets.
    pub serialization_before_serialization_count: i32,
    pub create_before_serialization_count: i32,
    pub serialization_before_create_count: i32,
    pub create_before_create_count: i32,
}

impl ObjectExport {
    /// Read one record. The wire shape is version-dependent for UE5
    /// fields; pass the resolved `AssetVersion` from the summary.
    pub fn read_from<R: Read>(
        reader: &mut R,
        version: AssetVersion,
        asset_path: &str,
    ) -> crate::Result<Self> {
        let class_raw = reader.read_i32::<LittleEndian>()?;
        let super_raw = reader.read_i32::<LittleEndian>()?;
        let template_raw = reader.read_i32::<LittleEndian>()?;
        let outer_raw = reader.read_i32::<LittleEndian>()?;

        let decode = |raw: i32, field: AssetWireField| -> crate::Result<PackageIndex> {
            PackageIndex::try_from_raw(raw).map_err(|e| match e {
                PackageIndexError::ImportIndexUnderflow => PaksmithError::AssetParse {
                    asset_path: asset_path.to_string(),
                    fault: AssetParseFault::PackageIndexUnderflow { field },
                },
            })
        };

        let class_index = decode(class_raw, AssetWireField::ExportClassIndex)?;
        let super_index = decode(super_raw, AssetWireField::ExportSuperIndex)?;
        let template_index = decode(template_raw, AssetWireField::ExportTemplateIndex)?;
        let outer_index = decode(outer_raw, AssetWireField::ExportOuterIndex)?;

        let object_name = reader.read_u32::<LittleEndian>()?;
        let object_name_number = reader.read_u32::<LittleEndian>()?;
        let object_flags = reader.read_u32::<LittleEndian>()?;
        let serial_size = reader.read_i64::<LittleEndian>()?;
        let serial_offset = reader.read_i64::<LittleEndian>()?;
        // All bool32 fields are i32 on the wire (signed), per UE source.
        let forced_export = reader.read_i32::<LittleEndian>()? != 0;
        let not_for_client = reader.read_i32::<LittleEndian>()? != 0;
        let not_for_server = reader.read_i32::<LittleEndian>()? != 0;

        // package_guid: 16 bytes, present only when UE5 < REMOVE_OBJECT_EXPORT_PACKAGE_GUID (1005).
        let package_guid =
            if !version.ue5_at_least(VER_UE5_REMOVE_OBJECT_EXPORT_PACKAGE_GUID) {
                Some(FGuid::read_from(reader)?)
            } else {
                None
            };

        // is_inherited_instance: i32 bool, added at UE5 1006.
        let is_inherited_instance =
            if version.ue5_at_least(VER_UE5_TRACK_OBJECT_EXPORT_IS_INHERITED) {
                Some(reader.read_i32::<LittleEndian>()? != 0)
            } else {
                None
            };

        let package_flags = reader.read_u32::<LittleEndian>()?;
        let not_always_loaded_for_editor_game =
            reader.read_i32::<LittleEndian>()? != 0;
        let is_asset = reader.read_i32::<LittleEndian>()? != 0;

        // generate_public_hash: i32 bool, added at UE5 1003.
        let generate_public_hash =
            if version.ue5_at_least(VER_UE5_OPTIONAL_RESOURCES) {
                Some(reader.read_i32::<LittleEndian>()? != 0)
            } else {
                None
            };

        let first_export_dependency = reader.read_i32::<LittleEndian>()?;
        let serialization_before_serialization_count =
            reader.read_i32::<LittleEndian>()?;
        let create_before_serialization_count = reader.read_i32::<LittleEndian>()?;
        let serialization_before_create_count = reader.read_i32::<LittleEndian>()?;
        let create_before_create_count = reader.read_i32::<LittleEndian>()?;

        if serial_size < 0 {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::NegativeValue {
                    field: AssetWireField::ExportSerialSize,
                    value: serial_size,
                },
            });
        }
        if serial_offset < 0 {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::NegativeValue {
                    field: AssetWireField::ExportSerialOffset,
                    value: serial_offset,
                },
            });
        }

        Ok(Self {
            class_index,
            super_index,
            template_index,
            outer_index,
            object_name,
            object_name_number,
            object_flags,
            serial_size,
            serial_offset,
            forced_export,
            not_for_client,
            not_for_server,
            package_guid,
            is_inherited_instance,
            package_flags,
            not_always_loaded_for_editor_game,
            is_asset,
            generate_public_hash,
            first_export_dependency,
            serialization_before_serialization_count,
            create_before_serialization_count,
            serialization_before_create_count,
            create_before_create_count,
        })
    }

    /// Write one record. Test- and fixture-gen-only via the
    /// `__test_utils` feature; release builds drop this method.
    /// Matches `read_from` field order, including version-gated
    /// `package_guid`, `is_inherited_instance`, and
    /// `generate_public_hash` tail fields.
    #[cfg(any(test, feature = "__test_utils"))]
    pub fn write_to<W: Write>(
        &self,
        writer: &mut W,
        version: AssetVersion,
    ) -> std::io::Result<()> {
        writer.write_i32::<LittleEndian>(self.class_index.to_raw())?;
        writer.write_i32::<LittleEndian>(self.super_index.to_raw())?;
        writer.write_i32::<LittleEndian>(self.template_index.to_raw())?;
        writer.write_i32::<LittleEndian>(self.outer_index.to_raw())?;
        writer.write_u32::<LittleEndian>(self.object_name)?;
        writer.write_u32::<LittleEndian>(self.object_name_number)?;
        writer.write_u32::<LittleEndian>(self.object_flags)?;
        writer.write_i64::<LittleEndian>(self.serial_size)?;
        writer.write_i64::<LittleEndian>(self.serial_offset)?;
        // bool32 fields written as i32 on the wire.
        writer.write_i32::<LittleEndian>(i32::from(self.forced_export))?;
        writer.write_i32::<LittleEndian>(i32::from(self.not_for_client))?;
        writer.write_i32::<LittleEndian>(i32::from(self.not_for_server))?;
        if let Some(g) = self.package_guid {
            g.write_to(writer)?;
        }
        if let Some(b) = self.is_inherited_instance {
            writer.write_i32::<LittleEndian>(i32::from(b))?;
        }
        writer.write_u32::<LittleEndian>(self.package_flags)?;
        writer.write_i32::<LittleEndian>(i32::from(self.not_always_loaded_for_editor_game))?;
        writer.write_i32::<LittleEndian>(i32::from(self.is_asset))?;
        if let Some(b) = self.generate_public_hash {
            writer.write_i32::<LittleEndian>(i32::from(b))?;
        }
        writer.write_i32::<LittleEndian>(self.first_export_dependency)?;
        writer.write_i32::<LittleEndian>(self.serialization_before_serialization_count)?;
        writer.write_i32::<LittleEndian>(self.create_before_serialization_count)?;
        writer.write_i32::<LittleEndian>(self.serialization_before_create_count)?;
        writer.write_i32::<LittleEndian>(self.create_before_create_count)?;
        let _ = version; // gating already applied via Option fields above.
        Ok(())
    }
}

/// `TArray<FObjectExport>` from the summary's `ExportOffset/Count`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ExportTable {
    /// Exports in wire order.
    pub exports: Vec<ObjectExport>,
}

impl ExportTable {
    /// Look up by 0-based index.
    #[must_use]
    pub fn get(&self, index: u32) -> Option<&ObjectExport> {
        self.exports.get(index as usize)
    }

    /// Read the table by seeking to `offset` and decoding `count` records.
    /// `version` controls the conditional UE5 fields in each record.
    pub fn read_from<R: Read + Seek>(
        reader: &mut R,
        offset: i64,
        count: i32,
        version: AssetVersion,
        asset_path: &str,
    ) -> crate::Result<Self> {
        if offset < 0 {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::NegativeValue {
                    field: AssetWireField::ExportOffset,
                    value: offset,
                },
            });
        }
        if count < 0 {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::NegativeValue {
                    field: AssetWireField::ExportCount,
                    value: i64::from(count),
                },
            });
        }
        let count_u32 = count as u32;
        if u64::from(count_u32) > u64::from(MAX_EXPORT_TABLE_ENTRIES) {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::BoundsExceeded {
                    field: AssetWireField::ExportCount,
                    value: u64::from(count_u32),
                    limit: u64::from(MAX_EXPORT_TABLE_ENTRIES),
                    unit: BoundsUnit::Items,
                },
            });
        }
        reader.seek(SeekFrom::Start(offset as u64))?;
        let mut exports: Vec<ObjectExport> = Vec::new();
        exports
            .try_reserve_exact(count_u32 as usize)
            .map_err(|source| PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::AllocationFailed {
                    context: AssetAllocationContext::ExportTable,
                    requested: count_u32 as usize,
                    unit: BoundsUnit::Items,
                    source,
                },
            })?;
        for _ in 0..count_u32 {
            exports.push(ObjectExport::read_from(reader, version, asset_path)?);
        }
        Ok(Self { exports })
    }

    /// Write the table. Test- and fixture-gen-only via the
    /// `__test_utils` feature; release builds drop this method.
    #[cfg(any(test, feature = "__test_utils"))]
    pub fn write_to<W: Write>(&self, writer: &mut W, version: AssetVersion) -> std::io::Result<()> {
        for e in &self.exports {
            e.write_to(writer, version)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn ue4_27() -> AssetVersion {
        AssetVersion {
            legacy_file_version: -7,
            file_version_ue4: 522,
            file_version_ue5: None,
            file_version_licensee_ue4: 0,
        }
    }

    fn sample_export_ue4_27() -> ObjectExport {
        ObjectExport {
            class_index: PackageIndex::Import(0),
            super_index: PackageIndex::Null,
            template_index: PackageIndex::Null,
            outer_index: PackageIndex::Null,
            object_name: 5,
            object_name_number: 0,
            object_flags: 0x0008_0000,
            serial_size: 84,
            serial_offset: 1280,
            forced_export: false,
            not_for_client: false,
            not_for_server: false,
            package_guid: Some(FGuid::from_bytes([0u8; 16])),
            is_inherited_instance: None,
            package_flags: 0,
            not_always_loaded_for_editor_game: false,
            is_asset: true,
            generate_public_hash: None,
            first_export_dependency: -1,
            serialization_before_serialization_count: 0,
            create_before_serialization_count: 0,
            serialization_before_create_count: 0,
            create_before_create_count: 0,
        }
    }

    #[test]
    fn record_size_pinned_ue4_27() {
        let e = sample_export_ue4_27();
        let mut buf = Vec::new();
        e.write_to(&mut buf, ue4_27()).unwrap();
        assert_eq!(buf.len(), EXPORT_RECORD_SIZE_UE4_27);
    }

    #[test]
    fn round_trip_one_record() {
        let e = sample_export_ue4_27();
        let v = ue4_27();
        let mut buf = Vec::new();
        e.write_to(&mut buf, v).unwrap();
        let parsed = ObjectExport::read_from(&mut Cursor::new(&buf), v, "x.uasset").unwrap();
        assert_eq!(parsed, e);
    }

    #[test]
    fn table_round_trip() {
        let v = ue4_27();
        let table = ExportTable {
            exports: vec![sample_export_ue4_27(), sample_export_ue4_27()],
        };
        let mut buf = Vec::new();
        table.write_to(&mut buf, v).unwrap();
        let parsed = ExportTable::read_from(&mut Cursor::new(buf), 0, 2, v, "x.uasset").unwrap();
        assert_eq!(parsed, table);
    }

    #[test]
    fn rejects_negative_serial_size() {
        let mut e = sample_export_ue4_27();
        let v = ue4_27();
        e.serial_size = -1;
        let mut buf = Vec::new();
        e.write_to(&mut buf, v).unwrap();
        let err = ObjectExport::read_from(&mut Cursor::new(&buf), v, "x.uasset").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::NegativeValue {
                    field: AssetWireField::ExportSerialSize,
                    ..
                },
                ..
            }
        ));
    }
}
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p paksmith-core --lib asset::export_table::tests`
Expected: 4 tests pass.

- [ ] **Step 5: Clippy**

Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings`

- [ ] **Step 6: Commit**

```bash
git add crates/paksmith-core/src/asset/export_table.rs crates/paksmith-core/src/error.rs
git commit -m "$(cat <<'EOF'
feat(asset): ObjectExport + ExportTable (UE 4.21–UE 5.0)

FObjectExport wire shape: 4×PackageIndex + FName + flags + i64 size +
i64 offset + 3×bool32 + FGuid + pflags + 2×bool32 + 5×i32 dependency
counters = 104 bytes for UE 4.27. EXPORT_RECORD_SIZE_UE4_27 pinned by a const + unit test.

PackageIndex decode mirrors ImportTable's pattern — i32::MIN surfaces
as AssetParseFault::PackageIndexOob with the specific field tag
(ExportClassIndex/SuperIndex/TemplateIndex/OuterIndex).

Adds AssetParseFault::UnsupportedFileVersionUE5 — Phase 2a ceiling is
1010 (one below VER_UE5_PACKAGE_SAVED_HASH where the per-export FGuid
migrates to FIoHash and the record shape changes). Pinned-display test
added alongside.

Caps at MAX_EXPORT_TABLE_ENTRIES = 512K; fallible reservation; rejects
negative serial_offset / serial_size as NegativeValue.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 9: `PackageSummary` — the orchestrating `FPackageFileSummary` parser

**Files:**

- Create: `crates/paksmith-core/src/asset/summary.rs`

> **Correction (correctness audit, third pass):** two issues in the summary's version + GUID handling, both verified against CUE4Parse `FPackageFileSummary.cs` HEAD lines 115-343:
> - `PersistentGuid` gate widened to include the UE4 ≥ `ADDED_PACKAGE_OWNER (518)` floor (previously gated only on `!PKG_FilterEditorOnly`). Reading the FGuid on a pre-518 uncooked asset consumed 16 bytes that aren't on the wire, corrupting every subsequent offset.
> - `OwnerPersistentGuid: Option<FGuid>` added — emitted as a second FGuid in the narrow UE4 `[518, 520)` window when `!PKG_FilterEditorOnly`. Per CUE4Parse, this lives immediately after `PersistentGuid`.
> - `legacy_file_version = -9` (UE 5.4+) added to the accepted window. -9 introduces no new wire fields within Phase 2a's UE5 < 1011 ceiling (the PACKAGE_SAVED_HASH change at 1015 is outside our range), so the widening is forward-compat only.
>
> Landed in commits `911c2e5`, `bb33ae4`. Neither affects the UE 4.27 cooked-asset fixture: PersistentGuid and OwnerPersistentGuid are both suppressed by `PKG_FilterEditorOnly`; UE 4.27 ships at legacy=-7.

> **Correction (correctness audit, fourth pass):** two additional summary-layer gates missed by Task 9's initial drafts, both verified against CUE4Parse `FPackageFileSummary.cs` HEAD:
> - `SearchableNamesOffset` gated on `FileVersionUE >= ADDED_SEARCHABLE_NAMES (510)` (was unconditional). Field type changes from `i32` to `Option<i32>`. At UE4 504–509 paksmith was misaligning 4 bytes.
> - `PreloadDependencyCount` + `PreloadDependencyOffset` gated on `FileVersionUE >= PRELOAD_DEPENDENCIES_IN_COOKED_EXPORTS (507)` (were unconditional). Both field types change from `i32` to `Option<i32>`. At UE4 504–506 paksmith was misaligning 8 bytes.
>
> Landed in commits `b2230bb`, `d1406d4`. Neither affects the UE 4.27 cooked-asset fixture (UE4 522 fires both gates) — fixture SHA1 stays at `416e875f137a485c13c864bbe5c6ac193da631a7` and the inspect snapshot is unchanged (`Some(0)` serialises identically to a raw `i32: 0`).
>
> The meta-finding is that the existing synthetic round-trip used paksmith's own `write_to` to build the wire bytes, which made it writer/reader-self-consistent: a wrong byte that the writer emits and the reader accepts passes silently, and the `unreal_asset` oracle only runs at UE 4.27 where these gates fire. Commit `8fed6f5` adds hand-crafted UE4 504/506/507/509/510 byte-level boundary tests at the `PackageSummary` layer (paralleling PR #224's `ObjectExport`-layer boundary tests) that assemble bytes through a parallel writer walking CUE4Parse's wire order directly. Closes the test-bed gap that allowed Bugs A and B to slip past.

**Why:** this is the orchestrator. It reads the magic, the legacy/UE4/UE5 version bytes, then all the table offsets/counts and miscellaneous fields, validates Phase 2a's accepted version window, and returns a [`PackageSummary`] that downstream tasks (`Package::read_from`) use to seek to the name/import/export regions.

The wire format is large. To keep the test cycle tight, this task splits into "read each section in isolation" sub-steps first, then assembles. Sub-step ordering matches wire order.

Wire layout (Phase 2a accepted: LegacyFileVersion ∈ {-7, -8}):

```text
u32  package_file_tag                          // 0x9E2A83C1
i32  legacy_file_version                       // -7 (UE4.21+) or -8 (UE5)
i32  legacy_ue3_version                        // ignored; UE writes -1
i32  file_version_ue4
i32  file_version_ue5                          // only if legacy_file_version <= -8
i32  file_version_licensee_ue4
CustomVersionContainer                         // i32 count + 20×count bytes
i32  total_header_size
FStr folder_name
u32  package_flags
i32  name_count
i32  name_offset
i32  soft_object_paths_count                   // only if UE5 >= ADD_SOFTOBJECTPATH_LIST (1008)
i32  soft_object_paths_offset                  // same gate
FStr localization_id                           // only if UE4 >= ADDED_PACKAGE_SUMMARY_LOCALIZATION_ID (516) AND NOT (package_flags & PKG_FilterEditorOnly)
i32  gatherable_text_data_count                // UE 4.13+, always present at our UE 4.21+ floor
i32  gatherable_text_data_offset
i32  export_count
i32  export_offset
i32  import_count
i32  import_offset
i32  depends_offset
i32  soft_package_references_count             // UE 4.17+, always present at our floor
i32  soft_package_references_offset
i32  searchable_names_offset                   // UE 4.20+, always present at our floor
i32  thumbnail_table_offset
FGuid guid                                     // 16 bytes (will be FIoHash at UE5 >= PACKAGE_SAVED_HASH = 1016 — out of our range)
FGuid persistent_guid                          // 16 bytes; editor-only — present iff NOT (package_flags & PKG_FilterEditorOnly). See "Correction (Task 12)" below.
TArray<FGenerationInfo>                        // i32 count + 8×count bytes (i32 export_count, i32 name_count)
FEngineVersion saved_by_engine_version
FEngineVersion compatible_with_engine_version
u32  compression_flags                         // always 0 in modern archives — reject non-zero
TArray<FCompressedChunk>                       // i32 count — reject non-empty (Phase 2a doesn't decompress in-summary chunks)
u32  package_source
TArray<FString> additional_packages_to_cook    // i32 count + N FStrings
i32  asset_registry_data_offset
i64  bulk_data_start_offset
i32  world_tile_info_data_offset
TArray<i32> chunk_ids                          // i32 count + count×i32
i32  preload_dependency_count
i32  preload_dependency_offset
i32  names_referenced_from_export_data_count   // UE5+
i64  payload_toc_offset                        // UE5+
i32  data_resource_offset                      // UE5 ≥ 1009
```

Phase 2a reads every field but only structurally validates the ones that gate table reads (counts/offsets for name/import/export). The rest are surfaced verbatim in the JSON dump or stored opaquely.

> **Correction (Task 12):** Initial drafts modeled `persistent_guid` as `FGuid` unconditionally. Empirical cross-validation against CUE4Parse (`FPackageFileSummary.cs:326`) confirmed the field is gated on `!PKG_FilterEditorOnly`. Implemented as `Option<FGuid>` in commit `e541c55`. See `summary.rs:407-411` for the documented gap on `OwnerPersistentGuid` (deferred to a future ADR).

- [ ] **Step 1: Write magic + version tests**

Create `crates/paksmith-core/src/asset/summary.rs`:

```rust
//! `FPackageFileSummary` — the asset header at byte 0 of every `.uasset`.

use std::io::{Read, Write};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use serde::Serialize;

use crate::asset::FGuid;
use crate::asset::custom_version::CustomVersionContainer;
use crate::asset::engine_version::EngineVersion;
use crate::asset::version::{
    AssetVersion, PACKAGE_FILE_TAG, PACKAGE_FILE_TAG_SWAPPED,
    VER_UE4_ADDED_PACKAGE_SUMMARY_LOCALIZATION_ID, VER_UE4_NAME_HASHES_SERIALIZED,
    VER_UE5_ADD_SOFTOBJECTPATH_LIST, VER_UE5_DATA_RESOURCES,
    VER_UE5_NAMES_REFERENCED_FROM_EXPORT_DATA, VER_UE5_PAYLOAD_TOC,
};
use crate::asset::read_asset_fstring;
use crate::error::{AssetParseFault, PaksmithError};

/// Hard cap on the wire-claimed `total_header_size`.
pub const MAX_TOTAL_HEADER_SIZE: i32 = 256 * 1024 * 1024;

/// Phase 2a ceiling on `FileVersionUE5` (exclusive). Verified against
/// CUE4Parse's `EUnrealEngineObjectUE5Version` enum
/// (`CUE4Parse/UE4/Versions/ObjectVersion.cs`):
///
/// - `PROPERTY_TAG_EXTENSION_AND_OVERRIDABLE_SERIALIZATION = 1011`
///   adds a new byte after `HasPropertyGuid` in `FPropertyTag`.
///   Phase 2b's tag reader does not handle this and would misparse.
/// - `PROPERTY_TAG_COMPLETE_TYPE_NAME = 1012` replaces the legacy
///   FName-typed tag with a tree-based type-name representation.
///   Phase 2b's tag reader does not handle this at all.
/// - `PACKAGE_SAVED_HASH = 1016` replaces the summary's `FGuid` with
///   an `FIoHash` (different size + shape).
///
/// The earliest UE5 version that breaks Phase 2's readers is therefore
/// `PROPERTY_TAG_EXTENSION_AND_OVERRIDABLE_SERIALIZATION = 1011` (an
/// FPropertyTag wire-format break, not an export break as a prior draft
/// of this plan asserted). Accept versions 1000–1010 inclusive; reject
/// 1011+. The `ObjectExport.package_guid` removal at version 1005, the
/// `is_inherited_instance` addition at 1006, the `generate_public_hash`
/// addition at 1003, the `data_resource_offset` summary addition at
/// 1009, etc. are all WITHIN the accepted range and are handled with
/// conditional reads (see Tasks 7–9).
pub const FIRST_UNSUPPORTED_UE5_VERSION: i32 = 1011;

/// Parsed [`FPackageFileSummary`].
///
/// Every field below corresponds 1:1 with a UE wire-format field; the
/// names follow `snake_case` rather than UE's `PascalCase`. Fields that
/// reference table offsets/counts are typed as `i32` (wire-faithful);
/// the validation that they're non-negative happens at the dependent
/// reader's seek site rather than here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PackageSummary {
    pub version: AssetVersion,
    pub custom_versions: CustomVersionContainer,
    pub total_header_size: i32,
    pub folder_name: String,
    pub package_flags: u32,
    pub name_count: i32,
    pub name_offset: i32,
    /// `soft_object_paths_count` — `None` when `FileVersionUE5 < ADD_SOFTOBJECTPATH_LIST (1008)`.
    pub soft_object_paths_count: Option<i32>,
    /// `soft_object_paths_offset` — `None` when same gate as above.
    pub soft_object_paths_offset: Option<i32>,
    /// `LocalizationId` — only present when `FileVersionUE4 >=
    /// ADDED_PACKAGE_SUMMARY_LOCALIZATION_ID (516)` AND the
    /// `PKG_FilterEditorOnly` package flag is NOT set. Cooked game
    /// archives almost always have `PKG_FilterEditorOnly` set, so
    /// expect `None` in practice. Verified against CUE4Parse's
    /// `FPackageFileSummary` reader.
    pub localization_id: Option<String>,
    pub gatherable_text_data_count: i32,
    pub gatherable_text_data_offset: i32,
    pub export_count: i32,
    pub export_offset: i32,
    pub import_count: i32,
    pub import_offset: i32,
    pub depends_offset: i32,
    pub soft_package_references_count: i32,
    pub soft_package_references_offset: i32,
    pub searchable_names_offset: i32,
    pub thumbnail_table_offset: i32,
    pub guid: FGuid,
    pub persistent_guid: Option<FGuid>,
    pub generation_count: i32,
    pub saved_by_engine_version: EngineVersion,
    pub compatible_with_engine_version: EngineVersion,
    pub package_source: u32,
    pub asset_registry_data_offset: i32,
    pub bulk_data_start_offset: i64,
    pub world_tile_info_data_offset: i32,
    pub preload_dependency_count: i32,
    pub preload_dependency_offset: i32,
    pub names_referenced_from_export_data_count: Option<i32>,
    pub payload_toc_offset: Option<i64>,
    pub data_resource_offset: Option<i32>,
}

impl PackageSummary {
    /// Read the summary from byte 0 of `reader`.
    pub fn read_from<R: Read>(reader: &mut R, asset_path: &str) -> crate::Result<Self> {
        // Magic
        let tag = reader.read_u32::<LittleEndian>()?;
        if tag != PACKAGE_FILE_TAG {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::InvalidMagic {
                    observed: tag,
                    expected: PACKAGE_FILE_TAG,
                },
            });
        }
        let _ = PACKAGE_FILE_TAG_SWAPPED;

        // Versions
        let legacy_file_version = reader.read_i32::<LittleEndian>()?;
        if !matches!(legacy_file_version, -7 | -8) {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::UnsupportedLegacyFileVersion {
                    version: legacy_file_version,
                },
            });
        }
        let _legacy_ue3_version = reader.read_i32::<LittleEndian>()?;
        let file_version_ue4 = reader.read_i32::<LittleEndian>()?;
        if file_version_ue4 < VER_UE4_NAME_HASHES_SERIALIZED {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::UnsupportedFileVersionUE4 {
                    version: file_version_ue4,
                    minimum: VER_UE4_NAME_HASHES_SERIALIZED,
                },
            });
        }
        let file_version_ue5 = if legacy_file_version <= -8 {
            Some(reader.read_i32::<LittleEndian>()?)
        } else {
            None
        };
        if let Some(v) = file_version_ue5 {
            if v >= FIRST_UNSUPPORTED_UE5_VERSION {
                return Err(PaksmithError::AssetParse {
                    asset_path: asset_path.to_string(),
                    fault: AssetParseFault::UnsupportedFileVersionUE5 {
                        version: v,
                        first_unsupported: FIRST_UNSUPPORTED_UE5_VERSION,
                    },
                });
            }
        }
        let file_version_licensee_ue4 = reader.read_i32::<LittleEndian>()?;
        let version = AssetVersion {
            legacy_file_version,
            file_version_ue4,
            file_version_ue5,
            file_version_licensee_ue4,
        };

        // Custom versions
        let custom_versions = CustomVersionContainer::read_from(reader, asset_path)?;

        // Header size + folder
        let total_header_size = reader.read_i32::<LittleEndian>()?;
        if total_header_size < 0 || total_header_size > MAX_TOTAL_HEADER_SIZE {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::BoundsExceeded {
                    field: crate::error::AssetWireField::TotalHeaderSize,
                    value: total_header_size.max(0) as u64,
                    limit: MAX_TOTAL_HEADER_SIZE as u64,
                    unit: BoundsUnit::Bytes,
                },
            });
        }
        let folder_name = read_asset_fstring(reader, asset_path)?;
        let package_flags = reader.read_u32::<LittleEndian>()?;

        // Table offsets/counts
        let name_count = reader.read_i32::<LittleEndian>()?;
        let name_offset = reader.read_i32::<LittleEndian>()?;
        // soft_object_paths_count/offset only present when UE5 >= ADD_SOFTOBJECTPATH_LIST (1008).
        // Verified against CUE4Parse's FPackageFileSummary reader (FabianFG/CUE4Parse,
        // CUE4Parse/UE4/Objects/UObject/FPackageFileSummary.cs line 248).
        let (soft_object_paths_count, soft_object_paths_offset) =
            if version.ue5_at_least(VER_UE5_ADD_SOFTOBJECTPATH_LIST) {
                let c = reader.read_i32::<LittleEndian>()?;
                let o = reader.read_i32::<LittleEndian>()?;
                (Some(c), Some(o))
            } else {
                (None, None)
            };
        // LocalizationId is editor-only — present iff UE4 >= 516 AND NOT PKG_FilterEditorOnly.
        // PKG_FilterEditorOnly = 0x80000000 (UE's EPackageFlags enum). Verified against CUE4Parse
        // (same file, line 254-260). Cooked game assets almost always have the flag set, so this
        // typically resolves to None. Reading it unconditionally — as a prior draft did — corrupts
        // every subsequent offset for cooked-asset inputs.
        const PKG_FILTER_EDITOR_ONLY: u32 = 0x8000_0000;
        let localization_id = if version.ue4_at_least(VER_UE4_ADDED_PACKAGE_SUMMARY_LOCALIZATION_ID)
            && (package_flags & PKG_FILTER_EDITOR_ONLY) == 0
        {
            Some(read_asset_fstring(reader, asset_path)?)
        } else {
            None
        };
        let gatherable_text_data_count = reader.read_i32::<LittleEndian>()?;
        let gatherable_text_data_offset = reader.read_i32::<LittleEndian>()?;
        let export_count = reader.read_i32::<LittleEndian>()?;
        let export_offset = reader.read_i32::<LittleEndian>()?;
        let import_count = reader.read_i32::<LittleEndian>()?;
        let import_offset = reader.read_i32::<LittleEndian>()?;
        let depends_offset = reader.read_i32::<LittleEndian>()?;
        let soft_package_references_count = reader.read_i32::<LittleEndian>()?;
        let soft_package_references_offset = reader.read_i32::<LittleEndian>()?;
        let searchable_names_offset = reader.read_i32::<LittleEndian>()?;
        let thumbnail_table_offset = reader.read_i32::<LittleEndian>()?;

        // GUIDs. `persistent_guid` is editor-only — present iff
        // PKG_FilterEditorOnly is clear (corrected at Task 12).
        let guid = FGuid::read_from(reader)?;
        let persistent_guid = if (package_flags & PKG_FILTER_EDITOR_ONLY) == 0 {
            Some(FGuid::read_from(reader)?)
        } else {
            None
        };

        // Generations (count + 8 bytes per record; we discard the rows)
        let generation_count = reader.read_i32::<LittleEndian>()?;
        for _ in 0..generation_count.max(0) {
            let _ = reader.read_i32::<LittleEndian>()?;
            let _ = reader.read_i32::<LittleEndian>()?;
        }

        // Engine versions
        let saved_by_engine_version = EngineVersion::read_from(reader)?;
        let compatible_with_engine_version = EngineVersion::read_from(reader)?;

        // Compression — must be zero+empty (Phase 2a rejects in-summary compression).
        let compression_flags = reader.read_u32::<LittleEndian>()?;
        if compression_flags != 0 {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::UnsupportedCompressionInSummary {
                    site: crate::error::CompressionInSummarySite::CompressionFlags,
                    observed: u64::from(compression_flags),
                },
            });
        }
        let compressed_chunks_count = reader.read_i32::<LittleEndian>()?;
        if compressed_chunks_count != 0 {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::UnsupportedCompressionInSummary {
                    site: crate::error::CompressionInSummarySite::CompressedChunksCount,
                    observed: compressed_chunks_count.max(0) as u64,
                },
            });
        }

        let package_source = reader.read_u32::<LittleEndian>()?;

        // additional_packages_to_cook: i32 count + N FStrings — discard.
        let additional_count = reader.read_i32::<LittleEndian>()?;
        for _ in 0..additional_count.max(0) {
            let _ = read_asset_fstring(reader, asset_path)?;
        }

        let asset_registry_data_offset = reader.read_i32::<LittleEndian>()?;
        let bulk_data_start_offset = reader.read_i64::<LittleEndian>()?;
        let world_tile_info_data_offset = reader.read_i32::<LittleEndian>()?;

        // chunk_ids: discard
        let chunk_id_count = reader.read_i32::<LittleEndian>()?;
        for _ in 0..chunk_id_count.max(0) {
            let _ = reader.read_i32::<LittleEndian>()?;
        }

        let preload_dependency_count = reader.read_i32::<LittleEndian>()?;
        let preload_dependency_offset = reader.read_i32::<LittleEndian>()?;

        // UE5-only trailing fields, each gated on its own version constant.
        // Verified against CUE4Parse FPackageFileSummary reader. Cross-
        // validation via the unreal_asset oracle is deferred to Task 12
        // (fixture-gen). The version constants are:
        //   - NAMES_REFERENCED_FROM_EXPORT_DATA = 1001 (NOT 1009 as a prior
        //     draft asserted; 1009 is DATA_RESOURCES and unrelated)
        //   - PAYLOAD_TOC = 1002
        //   - DATA_RESOURCES = 1009
        let names_referenced_from_export_data_count =
            if version.ue5_at_least(VER_UE5_NAMES_REFERENCED_FROM_EXPORT_DATA) {
                Some(reader.read_i32::<LittleEndian>()?)
            } else {
                None
            };
        let payload_toc_offset = if version.ue5_at_least(VER_UE5_PAYLOAD_TOC) {
            Some(reader.read_i64::<LittleEndian>()?)
        } else {
            None
        };
        let data_resource_offset =
            if version.ue5_at_least(VER_UE5_DATA_RESOURCES) {
                Some(reader.read_i32::<LittleEndian>()?)
            } else {
                None
            };

        Ok(Self {
            version,
            custom_versions,
            total_header_size,
            folder_name,
            package_flags,
            name_count,
            name_offset,
            soft_object_paths_count,
            soft_object_paths_offset,
            localization_id,
            gatherable_text_data_count,
            gatherable_text_data_offset,
            export_count,
            export_offset,
            import_count,
            import_offset,
            depends_offset,
            soft_package_references_count,
            soft_package_references_offset,
            searchable_names_offset,
            thumbnail_table_offset,
            guid,
            persistent_guid,
            generation_count,
            saved_by_engine_version,
            compatible_with_engine_version,
            package_source,
            asset_registry_data_offset,
            bulk_data_start_offset,
            world_tile_info_data_offset,
            preload_dependency_count,
            preload_dependency_offset,
            names_referenced_from_export_data_count,
            payload_toc_offset,
            data_resource_offset,
        })
    }

    /// Write — matches `read_from` field-for-field. Test- and
    /// fixture-gen-only via the `__test_utils` feature; release builds
    /// drop this method.
    #[cfg(any(test, feature = "__test_utils"))]
    pub fn write_to<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_u32::<LittleEndian>(PACKAGE_FILE_TAG)?;
        writer.write_i32::<LittleEndian>(self.version.legacy_file_version)?;
        writer.write_i32::<LittleEndian>(-1)?; // legacy_ue3_version
        writer.write_i32::<LittleEndian>(self.version.file_version_ue4)?;
        if let Some(v) = self.version.file_version_ue5 {
            writer.write_i32::<LittleEndian>(v)?;
        }
        writer.write_i32::<LittleEndian>(self.version.file_version_licensee_ue4)?;
        self.custom_versions.write_to(writer)?;
        writer.write_i32::<LittleEndian>(self.total_header_size)?;
        write_fstring(writer, &self.folder_name)?;
        writer.write_u32::<LittleEndian>(self.package_flags)?;
        writer.write_i32::<LittleEndian>(self.name_count)?;
        writer.write_i32::<LittleEndian>(self.name_offset)?;
        if let Some(c) = self.soft_object_paths_count {
            writer.write_i32::<LittleEndian>(c)?;
            writer.write_i32::<LittleEndian>(self.soft_object_paths_offset.unwrap_or(0))?;
        }
        if let Some(ref s) = self.localization_id {
            write_fstring(writer, s)?;
        }
        writer.write_i32::<LittleEndian>(self.gatherable_text_data_count)?;
        writer.write_i32::<LittleEndian>(self.gatherable_text_data_offset)?;
        writer.write_i32::<LittleEndian>(self.export_count)?;
        writer.write_i32::<LittleEndian>(self.export_offset)?;
        writer.write_i32::<LittleEndian>(self.import_count)?;
        writer.write_i32::<LittleEndian>(self.import_offset)?;
        writer.write_i32::<LittleEndian>(self.depends_offset)?;
        writer.write_i32::<LittleEndian>(self.soft_package_references_count)?;
        writer.write_i32::<LittleEndian>(self.soft_package_references_offset)?;
        writer.write_i32::<LittleEndian>(self.searchable_names_offset)?;
        writer.write_i32::<LittleEndian>(self.thumbnail_table_offset)?;
        self.guid.write_to(writer)?;
        // Editor-only — emit iff PKG_FilterEditorOnly clear
        // (mirrors `read_from`; corrected at Task 12).
        if let Some(ref g) = self.persistent_guid {
            g.write_to(writer)?;
        }
        writer.write_i32::<LittleEndian>(self.generation_count)?;
        for _ in 0..self.generation_count.max(0) {
            writer.write_i32::<LittleEndian>(self.export_count)?;
            writer.write_i32::<LittleEndian>(self.name_count)?;
        }
        self.saved_by_engine_version.write_to(writer)?;
        self.compatible_with_engine_version.write_to(writer)?;
        writer.write_u32::<LittleEndian>(0)?; // compression_flags
        writer.write_i32::<LittleEndian>(0)?; // compressed_chunks_count
        writer.write_u32::<LittleEndian>(self.package_source)?;
        writer.write_i32::<LittleEndian>(0)?; // additional_packages_to_cook count
        writer.write_i32::<LittleEndian>(self.asset_registry_data_offset)?;
        writer.write_i64::<LittleEndian>(self.bulk_data_start_offset)?;
        writer.write_i32::<LittleEndian>(self.world_tile_info_data_offset)?;
        writer.write_i32::<LittleEndian>(0)?; // chunk_id_count
        writer.write_i32::<LittleEndian>(self.preload_dependency_count)?;
        writer.write_i32::<LittleEndian>(self.preload_dependency_offset)?;
        if let Some(c) = self.names_referenced_from_export_data_count {
            writer.write_i32::<LittleEndian>(c)?;
        }
        if let Some(o) = self.payload_toc_offset {
            writer.write_i64::<LittleEndian>(o)?;
        }
        if let Some(o) = self.data_resource_offset {
            writer.write_i32::<LittleEndian>(o)?;
        }
        Ok(())
    }
}

fn write_fstring<W: Write>(writer: &mut W, s: &str) -> std::io::Result<()> {
    let bytes_with_null = s.len() + 1;
    let len_i32 = i32::try_from(bytes_with_null)
        .map_err(|_| std::io::Error::other("FString length exceeds i32::MAX"))?;
    writer.write_i32::<LittleEndian>(len_i32)?;
    writer.write_all(s.as_bytes())?;
    writer.write_u8(0)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn minimal_ue4_27_summary() -> PackageSummary {
        PackageSummary {
            version: AssetVersion {
                legacy_file_version: -7,
                file_version_ue4: 522,
                file_version_ue5: None,
                file_version_licensee_ue4: 0,
            },
            custom_versions: CustomVersionContainer::default(),
            total_header_size: 0,
            folder_name: "None".to_string(),
            package_flags: 0,
            name_count: 0,
            name_offset: 0,
            soft_object_paths_count: None,
            soft_object_paths_offset: None,
            localization_id: None,
            gatherable_text_data_count: 0,
            gatherable_text_data_offset: 0,
            export_count: 0,
            export_offset: 0,
            import_count: 0,
            import_offset: 0,
            depends_offset: 0,
            soft_package_references_count: 0,
            soft_package_references_offset: 0,
            searchable_names_offset: 0,
            thumbnail_table_offset: 0,
            guid: FGuid::from_bytes([0u8; 16]),
            // PKG_FilterEditorOnly set above, so persistent_guid is None
            // (editor-only — see "Correction (Task 12)" earlier in this doc).
            persistent_guid: None,
            generation_count: 0,
            saved_by_engine_version: EngineVersion {
                major: 4, minor: 27, patch: 2, changelist: 0,
                branch: "++UE4+Release-4.27".to_string(),
            },
            compatible_with_engine_version: EngineVersion {
                major: 4, minor: 27, patch: 0, changelist: 0,
                branch: "++UE4+Release-4.27".to_string(),
            },
            package_source: 0,
            asset_registry_data_offset: 0,
            bulk_data_start_offset: 0,
            world_tile_info_data_offset: 0,
            preload_dependency_count: 0,
            preload_dependency_offset: 0,
            names_referenced_from_export_data_count: None,
            payload_toc_offset: None,
            data_resource_offset: None,
        }
    }

    #[test]
    fn ue4_27_minimal_round_trip() {
        let s = minimal_ue4_27_summary();
        let mut buf = Vec::new();
        s.write_to(&mut buf).unwrap();
        let parsed = PackageSummary::read_from(&mut Cursor::new(&buf), "x.uasset").unwrap();
        assert_eq!(parsed, s);
    }

    #[test]
    fn ue5_1_minimal_round_trip() {
        let mut s = minimal_ue4_27_summary();
        s.version.legacy_file_version = -8;
        s.version.file_version_ue5 = Some(1009);
        s.names_referenced_from_export_data_count = Some(0);
        s.payload_toc_offset = Some(0);
        s.data_resource_offset = Some(0);
        let mut buf = Vec::new();
        s.write_to(&mut buf).unwrap();
        let parsed = PackageSummary::read_from(&mut Cursor::new(&buf), "x.uasset").unwrap();
        assert_eq!(parsed, s);
    }

    #[test]
    fn rejects_wrong_magic() {
        let mut buf = vec![];
        buf.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        let err = PackageSummary::read_from(&mut Cursor::new(&buf), "x.uasset").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::InvalidMagic { observed: 0xDEAD_BEEF, .. },
                ..
            }
        ));
    }

    #[test]
    fn rejects_unsupported_legacy_version() {
        let mut buf = vec![];
        buf.extend_from_slice(&PACKAGE_FILE_TAG.to_le_bytes());
        buf.extend_from_slice(&(-6i32).to_le_bytes());
        let err = PackageSummary::read_from(&mut Cursor::new(&buf), "x.uasset").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::UnsupportedLegacyFileVersion { version: -6 },
                ..
            }
        ));
    }

    #[test]
    fn rejects_too_old_ue4_version() {
        let mut buf = vec![];
        buf.extend_from_slice(&PACKAGE_FILE_TAG.to_le_bytes());
        buf.extend_from_slice(&(-7i32).to_le_bytes()); // legacy
        buf.extend_from_slice(&(-1i32).to_le_bytes()); // ue3
        buf.extend_from_slice(&(503i32).to_le_bytes()); // file_version_ue4 < 504
        let err = PackageSummary::read_from(&mut Cursor::new(&buf), "x.uasset").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::UnsupportedFileVersionUE4 { version: 503, .. },
                ..
            }
        ));
    }

    #[test]
    fn rejects_ue5_above_ceiling() {
        let mut buf = vec![];
        buf.extend_from_slice(&PACKAGE_FILE_TAG.to_le_bytes());
        buf.extend_from_slice(&(-8i32).to_le_bytes());
        buf.extend_from_slice(&(-1i32).to_le_bytes());
        buf.extend_from_slice(&(522i32).to_le_bytes()); // ue4
        buf.extend_from_slice(&(1011i32).to_le_bytes()); // ue5 — first unsupported
        let err = PackageSummary::read_from(&mut Cursor::new(&buf), "x.uasset").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::UnsupportedFileVersionUE5 { version: 1011, .. },
                ..
            }
        ));
    }
}
```

- [ ] **Step 2: Run the tests**

Run: `cargo test -p paksmith-core --lib asset::summary::tests`
Expected: 6 tests pass.

- [ ] **Step 3: Clippy**

Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings`

- [ ] **Step 4: Commit**

```bash
git add crates/paksmith-core/src/asset/summary.rs
git commit -m "$(cat <<'EOF'
feat(asset): PackageSummary — FPackageFileSummary orchestrator

Reads magic, legacy/UE4/UE5/licensee versions, CustomVersionContainer,
header size, FolderName, package flags, table offsets/counts for name/
import/export, GUIDs, generation list, two FEngineVersion stamps,
compression flags (rejected non-zero), package source, asset registry,
bulk data, chunk IDs, preload dependencies, and UE5 trailers
(names_referenced, payload_toc, data_resource).

Phase 2a accepts LegacyFileVersion ∈ {-7, -8}, FileVersionUE4 ≥ 504
(VER_UE4_NAME_HASHES_SERIALIZED), FileVersionUE5 < 1011 (the IoHash
migration). Rejection paths are pinned by unit tests for each gate.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 10: `PropertyBag::Opaque` + `MAX_PROPERTY_DEPTH`

**Files:**

- Create: `crates/paksmith-core/src/asset/property_bag.rs`

**Why:** Phase 2a doesn't decode property bodies, but the `Package` aggregate type signature needs a non-placeholder `PropertyBag` so Phase 2b can extend it additively. Locks `MAX_PROPERTY_DEPTH = 128` as a `pub const` for forward compat.

- [ ] **Step 1: Write the property-bag scaffolding test**

Create `crates/paksmith-core/src/asset/property_bag.rs`:

```rust
//! Decoded property body for one export.
//!
//! Phase 2a ships only the [`Self::Opaque`] variant — the export's
//! serialized bytes are carried verbatim. Phase 2b lands the
//! tagged-property iterator that produces typed [`Self::Tree`]
//! payloads; Phase 2c lands the container properties whose recursive
//! parsing is bounded by [`MAX_PROPERTY_DEPTH`].

use serde::Serialize;

/// Hard cap on nested struct/array/map depth in the property tree.
/// Defined here in Phase 2a even though only Phase 2c references it,
/// to lock the contract before downstream parsers are written. Value
/// chosen to match FModel's nesting bound; UE assets in practice
/// never nest beyond ~12.
pub const MAX_PROPERTY_DEPTH: usize = 128;

/// Decoded body for one export.
///
/// `#[non_exhaustive]` so Phase 2b can add a `Tree` variant without
/// source-breaking downstream `match` arms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PropertyBag {
    /// Phase 2a: raw bytes carved out of the asset's payload region.
    Opaque {
        /// The export's serialized bytes (length matches
        /// `ObjectExport::serial_size`).
        #[serde(serialize_with = "serialize_byte_count")]
        bytes: Vec<u8>,
    },
}

impl PropertyBag {
    /// Convenience constructor for the Phase-2a opaque variant.
    #[must_use]
    pub fn opaque(bytes: Vec<u8>) -> Self {
        Self::Opaque { bytes }
    }

    /// Number of bytes in the bag (raw payload bytes for Opaque).
    #[must_use]
    pub fn byte_len(&self) -> usize {
        match self {
            Self::Opaque { bytes } => bytes.len(),
        }
    }
}

/// Serialize `bytes` as just its length, not its content. Asset
/// payloads can be megabytes; serializing them inline would blow up
/// `inspect` JSON output. Phase 2b's `Tree` variant will serialize
/// the decoded property structure instead.
fn serialize_byte_count<S: serde::Serializer>(
    bytes: &Vec<u8>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_u64(bytes.len() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opaque_byte_len() {
        let bag = PropertyBag::opaque(vec![0u8; 84]);
        assert_eq!(bag.byte_len(), 84);
    }

    #[test]
    fn serialize_renders_byte_count_not_payload() {
        let bag = PropertyBag::opaque(vec![1, 2, 3, 4, 5]);
        let json = serde_json::to_string(&bag).unwrap();
        assert_eq!(json, r#"{"kind":"opaque","bytes":5}"#);
    }

    #[test]
    fn max_depth_constant_is_locked() {
        assert_eq!(MAX_PROPERTY_DEPTH, 128);
    }
}
```

- [ ] **Step 2: Add `serde_json` to dev-deps (test uses it)**

Edit `crates/paksmith-core/Cargo.toml` — under `[dev-dependencies]`, add:

```toml
serde_json.workspace = true
```

- [ ] **Step 3: Run the tests**

Run: `cargo test -p paksmith-core --lib asset::property_bag::tests`
Expected: 3 tests pass.

- [ ] **Step 4: Clippy**

Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings`

- [ ] **Step 5: Commit**

```bash
git add crates/paksmith-core/src/asset/property_bag.rs crates/paksmith-core/Cargo.toml
git commit -m "$(cat <<'EOF'
feat(asset): PropertyBag::Opaque + MAX_PROPERTY_DEPTH

Phase 2a ships PropertyBag::Opaque carrying raw export payload bytes.
serde rendering elides the bytes (renders count only) — payloads can
be megabytes; inlining would explode inspect JSON.

MAX_PROPERTY_DEPTH = 128 locked here even though only Phase 2c
recurses; pins the contract before downstream parsers exist. Matches
FModel's nesting bound.

non_exhaustive on PropertyBag so Phase 2b's Tree variant lands
additively without breaking downstream match arms.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 10b: Extract the minimal-UE4.27 builder to `testing/uasset.rs`

**Files:**

- Create: `crates/paksmith-core/src/testing/uasset.rs`
- Modify: `crates/paksmith-core/src/testing/mod.rs` — add `pub mod uasset;`

**Why:** Tasks 11 and 13 both need a single source of truth for "build a minimal UE 4.27 .uasset blob with the offsets patched correctly." Without this extraction, the ~80-line builder would be duplicated across the unit-test module (`asset/package.rs::tests`) and the fixture-generator crate (`paksmith-fixture-gen/src/uasset.rs`), and the two copies would drift the moment the wire layout gained a field. Same precedent as `testing/v10.rs` (issue #68), which promoted the V10+ FDI synthesizer out of `pak/index/mod.rs`'s test block for the same reason.

**Feature-unification caveat (read before implementing):** the existing `__test_utils` feature is currently activated ONLY by `paksmith-core`'s self-dev-dep — `cargo build --workspace --release` does NOT compile `testing/v10.rs` into the cli/gui rlibs because no non-dev edge requests it. Task 12 below changes that: it makes `paksmith-fixture-gen → paksmith-core` a non-dev dep with `features = ["__test_utils"]` activated, so any `--workspace` build (including release CI) will compile `testing::uasset` (and `testing::v10`, `testing::oom`) into the rlibs of every paksmith-core dependent in the resolution graph (cli, gui, fixture-gen). Linker DCE strips the unused symbols from the final binaries, but they're in the dependency rlibs. The `__` naming convention remains the soft guarantee — downstream consumers must not import from `paksmith_core::testing`. The Cargo.toml comment on `__test_utils` already warns reviewers to verify this trade-off whenever a new non-dev dep edge is added; this is the first such edge.

**Implementor's alternative**: if a future reviewer rejects this trade-off, the fallback is to duplicate the builder — keep `testing/uasset.rs` for `asset/package.rs::tests` only, and have `paksmith-fixture-gen/src/uasset.rs` carry its own copy. Cost: the 80-line duplication this task exists to prevent, plus the eventual drift between the two copies. Acceptable only if the reviewer judges the cross-crate `__test_utils` activation worse than that duplication.

- [ ] **Step 1: Add `pub mod uasset` to `testing/mod.rs`**

Edit `crates/paksmith-core/src/testing/mod.rs`:

```rust
//! Test-utility surface for the integration test suite under
//! `tests/` and for in-source `#[cfg(test)] mod tests` blocks that
//! want to avoid duplicating wire-format synthesis helpers.
//!
//! **Stability**: gated behind the `__test_utils` Cargo feature
//! (note the leading `__` prefix — the convention signals "internal
//! to paksmith's test infra; do not depend on this from downstream
//! crates"). Anything `pub` here is a `cargo test`-only surface and
//! may change in any release.

pub mod oom;
pub mod uasset;
pub mod v10;
```

- [ ] **Step 2: Create the builder module**

Create `crates/paksmith-core/src/testing/uasset.rs`:

```rust
//! Minimal UE 4.27 `.uasset` byte synthesizer for Phase-2a tests.
//!
//! Promoted out of `asset::package`'s test block so that:
//! 1. Phase 2a's integration test (`tests/asset_integration.rs`) and
//!    the unit test inside `asset::package` share one builder rather
//!    than maintaining parallel copies.
//! 2. `paksmith-fixture-gen` can reach this builder via the
//!    `__test_utils` feature without duplicating the wire-format
//!    assembly (mirrors the [`v10`] precedent for the pak FDI).
//!
//! **Stability:** gated behind the `__test_utils` feature; do not
//! depend on this from downstream crates.
//!
//! [`v10`]: super::v10

#![allow(clippy::missing_panics_doc)]

use crate::asset::custom_version::CustomVersionContainer;
use crate::asset::engine_version::EngineVersion;
use crate::asset::export_table::{ExportTable, ObjectExport, EXPORT_RECORD_SIZE_UE4_27};
use crate::asset::import_table::{ImportTable, ObjectImport};
use crate::asset::name_table::{FName, NameTable};
use crate::asset::package_index::PackageIndex;
use crate::asset::summary::PackageSummary;
use crate::asset::version::AssetVersion;

/// Materialized minimal package — bytes plus the structurally-equal
/// `PackageSummary` / `NameTable` / `ImportTable` / `ExportTable` the
/// bytes encode. Tests compare against these tables verbatim; the
/// caller does not need to rebuild them in test code.
pub struct MinimalPackage {
    pub bytes: Vec<u8>,
    pub summary: PackageSummary,
    pub names: NameTable,
    pub imports: ImportTable,
    pub exports: ExportTable,
    pub payload: Vec<u8>,
}

/// Build a minimal UE 4.27 .uasset blob: 3 names
/// (`"/Script/CoreUObject"`, `"Package"`, `"Default__Object"`), 1
/// import (`/Script/CoreUObject Package Default__Object`, Null outer),
/// 1 export (class = Import(0), 16-byte opaque payload).
///
/// Offset layout is computed up front using
/// [`EXPORT_RECORD_SIZE_UE4_27`] for the export-table extent (locked at 104
/// bytes by Task 8); the summary is written once with placeholders,
/// measured, then rewritten with the patched offsets — its byte
/// length is invariant under offset patching because every offset is
/// a fixed-width i32.
#[must_use]
pub fn build_minimal_ue4_27() -> MinimalPackage {
    let version = AssetVersion {
        legacy_file_version: -7,
        file_version_ue4: 522,
        file_version_ue5: None,
        file_version_licensee_ue4: 0,
    };
    let names = NameTable {
        names: vec![
            FName::new("/Script/CoreUObject"),
            FName::new("Package"),
            FName::new("Default__Object"),
        ],
    };
    let imports = ImportTable {
        imports: vec![ObjectImport {
            class_package_name: 0,
            class_package_number: 0,
            class_name: 1,
            class_name_number: 0,
            outer_index: PackageIndex::Null,
            object_name: 2,
            object_name_number: 0,
            package_name: None,
            import_optional: None,
        }],
    };
    let payload: Vec<u8> = vec![0xAA; 16];

    // Build the export with a placeholder serial_offset. UE 4.27 fixture
    // has no UE5 conditional fields, so package_guid is Some and the UE5
    // flag-options are all None.
    let mut exports = ExportTable {
        exports: vec![ObjectExport {
            class_index: PackageIndex::Import(0),
            super_index: PackageIndex::Null,
            template_index: PackageIndex::Null,
            outer_index: PackageIndex::Null,
            object_name: 2,
            object_name_number: 0,
            object_flags: 0,
            serial_size: payload.len() as i64,
            serial_offset: 0,
            forced_export: false,
            not_for_client: false,
            not_for_server: false,
            package_guid: Some(FGuid::from_bytes([0u8; 16])),
            is_inherited_instance: None,
            package_flags: 0,
            not_always_loaded_for_editor_game: false,
            is_asset: true,
            generate_public_hash: None,
            first_export_dependency: -1,
            serialization_before_serialization_count: 0,
            create_before_serialization_count: 0,
            serialization_before_create_count: 0,
            create_before_create_count: 0,
        }],
    };

    let mut summary = PackageSummary {
        version,
        custom_versions: CustomVersionContainer::default(),
        total_header_size: 0,
        folder_name: "None".to_string(),
        // Cooked-game flag — turns off LocalizationId and other editor-only fields
        // in the wire stream. Required for round-trip correctness with localization_id: None.
        package_flags: 0x8000_0000,
        name_count: names.names.len() as i32,
        name_offset: 0,
        // UE 4.27 fixture: no UE5 soft_object_paths list.
        soft_object_paths_count: None,
        soft_object_paths_offset: None,
        // UE 4.27 (= UE4 522) is past LOCALIZATION_ID (516), but PKG_FilterEditorOnly
        // is set above, so the field is omitted from the wire stream.
        localization_id: None,
        gatherable_text_data_count: 0,
        gatherable_text_data_offset: 0,
        export_count: exports.exports.len() as i32,
        export_offset: 0,
        import_count: imports.imports.len() as i32,
        import_offset: 0,
        depends_offset: 0,
        soft_package_references_count: 0,
        soft_package_references_offset: 0,
        searchable_names_offset: 0,
        thumbnail_table_offset: 0,
        guid: FGuid::from_bytes([0u8; 16]),
        // Cooked synthetic fixture: PKG_FilterEditorOnly set, so persistent_guid is None.
        persistent_guid: None,
        generation_count: 1,
        saved_by_engine_version: EngineVersion {
            major: 4,
            minor: 27,
            patch: 2,
            changelist: 0,
            branch: "++UE4+Release-4.27".to_string(),
        },
        compatible_with_engine_version: EngineVersion {
            major: 4,
            minor: 27,
            patch: 0,
            changelist: 0,
            branch: "++UE4+Release-4.27".to_string(),
        },
        package_source: 0,
        asset_registry_data_offset: 0,
        bulk_data_start_offset: 0,
        world_tile_info_data_offset: 0,
        preload_dependency_count: 0,
        preload_dependency_offset: 0,
        names_referenced_from_export_data_count: None,
        payload_toc_offset: None,
        data_resource_offset: None,
    };

    // Pre-pass: write the summary with zero offsets to measure its
    // wire size. The size is invariant under offset patching (every
    // offset slot is fixed-width i32).
    let mut sum_buf = Vec::new();
    summary.write_to(&mut sum_buf).unwrap();
    let summary_end = i32::try_from(sum_buf.len()).unwrap();

    let mut names_buf = Vec::new();
    names.write_to(&mut names_buf).unwrap();
    let mut imports_buf = Vec::new();
    imports.write_to(&mut imports_buf, version).unwrap();
    let exports_size = i32::try_from(EXPORT_RECORD_SIZE_UE4_27 * exports.exports.len()).unwrap();

    summary.name_offset = summary_end;
    summary.import_offset = summary_end + names_buf.len() as i32;
    summary.export_offset = summary.import_offset + imports_buf.len() as i32;
    summary.total_header_size = summary.export_offset + exports_size;

    exports.exports[0].serial_offset = i64::from(summary.total_header_size);

    sum_buf.clear();
    summary.write_to(&mut sum_buf).unwrap();
    assert_eq!(
        i32::try_from(sum_buf.len()).unwrap(),
        summary_end,
        "summary byte size must be stable under offset patching"
    );
    let mut exports_buf = Vec::new();
    exports.write_to(&mut exports_buf, version).unwrap();
    assert_eq!(exports_buf.len() as i32, exports_size, "export records must match EXPORT_RECORD_SIZE_UE4_27");

    let mut bytes = sum_buf;
    bytes.extend_from_slice(&names_buf);
    bytes.extend_from_slice(&imports_buf);
    bytes.extend_from_slice(&exports_buf);
    bytes.extend_from_slice(&payload);

    MinimalPackage {
        bytes,
        summary,
        names,
        imports,
        exports,
        payload,
    }
}
```

- [ ] **Step 3: Build paksmith-core**

Run: `cargo build -p paksmith-core --features __test_utils`
Expected: clean.

- [ ] **Step 4: Clippy**

Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings`

- [ ] **Step 5: Commit**

```bash
git add crates/paksmith-core/src/testing/uasset.rs crates/paksmith-core/src/testing/mod.rs
git commit -m "$(cat <<'EOF'
feat(testing): minimal UE 4.27 uasset builder under __test_utils

Promotes the offset-patched .uasset synthesizer out of asset::package's
test block so that the Phase 2a integration test (Task 11) and the
fixture-gen crate (Task 13) share one builder. Same precedent as
testing/v10.rs (#68) — the V10+ FDI synthesizer was extracted for the
identical reason once the integration test layer arrived.

Returns a MinimalPackage with the bytes plus the structurally-equal
PackageSummary / NameTable / ImportTable / ExportTable so callers can
assert against the tables verbatim without rebuilding them.

EXPORT_RECORD_SIZE_UE4_27 (locked in Task 8) drives the export-table extent
calculation rather than a duplicate two-pass write.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 11: `Package::read_from` — full integration parse

**Files:**

- Create: `crates/paksmith-core/src/asset/package.rs`

**Why:** ties together summary + name table + import table + export table + payload bytes. Produces a typed [`Package`] aggregate that downstream callers (CLI, fixture-gen) consume.

- [ ] **Step 1: Write the integration test**

Create `crates/paksmith-core/src/asset/package.rs`:

```rust
//! Top-level UAsset aggregate.
//!
//! [`Package::read_from`] orchestrates the per-component parsers:
//! 1. [`PackageSummary::read_from`] from byte 0.
//! 2. [`NameTable::read_from`] seeked to `summary.name_offset`.
//! 3. [`ImportTable::read_from`] seeked to `summary.import_offset`.
//! 4. [`ExportTable::read_from`] seeked to `summary.export_offset`.
//! 5. Per-export payload bytes carved out of the buffer.
//!
//! Each export's bytes are stored as
//! [`PropertyBag::Opaque`](crate::asset::property_bag::PropertyBag::Opaque)
//! for Phase 2a; Phase 2b's tagged-property iterator replaces this.

use std::io::{Cursor, Read, Seek, SeekFrom};
use std::sync::Arc;

use serde::Serialize;

use crate::asset::export_table::ExportTable;
use crate::asset::import_table::ImportTable;
use crate::asset::name_table::NameTable;
use crate::asset::property_bag::PropertyBag;
use crate::asset::summary::PackageSummary;
use crate::asset::{AssetContext, AssetVersion};
use crate::error::{
    AssetAllocationContext, AssetOverflowSite, AssetParseFault, AssetWireField, BoundsUnit,
    PaksmithError,
};

/// One parsed `.uasset` package: structural header + opaque payloads.
#[derive(Debug, Clone, Serialize)]
pub struct Package {
    /// Virtual path of the asset within its archive (e.g.
    /// `Game/Maps/Demo.uasset`).
    pub asset_path: String,
    /// Parsed package summary.
    pub summary: PackageSummary,
    /// Parsed FName pool.
    pub names: NameTable,
    /// Parsed import table.
    pub imports: ImportTable,
    /// Parsed export table.
    pub exports: ExportTable,
    /// Per-export opaque payload bodies — same order as
    /// [`Self::exports.exports`].
    pub payloads: Vec<PropertyBag>,
}

impl Package {
    /// Parse a `.uasset` from `bytes`.
    pub fn read_from(bytes: &[u8], asset_path: &str) -> crate::Result<Self> {
        let asset_size = bytes.len() as u64;
        let mut cursor = Cursor::new(bytes);
        let summary = PackageSummary::read_from(&mut cursor, asset_path)?;

        let names = NameTable::read_from(
            &mut cursor,
            i64::from(summary.name_offset),
            summary.name_count,
            asset_path,
        )?;
        let imports = ImportTable::read_from(
            &mut cursor,
            i64::from(summary.import_offset),
            summary.import_count,
            summary.version,
            asset_path,
        )?;
        let exports = ExportTable::read_from(
            &mut cursor,
            i64::from(summary.export_offset),
            summary.export_count,
            summary.version,
            asset_path,
        )?;

        let payloads = read_payloads(&mut cursor, &exports, asset_size, asset_path)?;

        Ok(Self {
            asset_path: asset_path.to_string(),
            summary,
            names,
            imports,
            exports,
            payloads,
        })
    }

    /// Build an [`AssetContext`] from this package. Used by Phase 2b+
    /// property parsers; Phase 2a only constructs it for the API
    /// shape sanity check in tests.
    #[must_use]
    pub fn context(&self) -> AssetContext {
        AssetContext {
            names: Arc::new(self.names.clone()),
            imports: Arc::new(self.imports.clone()),
            exports: Arc::new(self.exports.clone()),
            version: self.summary.version,
        }
    }
}

fn read_payloads<R: Read + Seek>(
    reader: &mut R,
    exports: &ExportTable,
    asset_size: u64,
    asset_path: &str,
) -> crate::Result<Vec<PropertyBag>> {
    let mut payloads: Vec<PropertyBag> = Vec::new();
    payloads
        .try_reserve_exact(exports.exports.len())
        .map_err(|source| PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::AllocationFailed {
                context: AssetAllocationContext::ExportTable,
                requested: exports.exports.len(),
                unit: BoundsUnit::Items,
                source,
            },
        })?;

    for e in &exports.exports {
        let offset = e.serial_offset as u64;
        let size = e.serial_size as u64;
        let end = offset.checked_add(size).ok_or_else(|| {
            PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::U64ArithmeticOverflow {
                    operation: AssetOverflowSite::ExportPayloadExtent,
                },
            }
        })?;
        if end > asset_size {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::InvalidOffset {
                    field: AssetWireField::ExportSerialOffset,
                    offset: e.serial_offset,
                    asset_size,
                },
            });
        }
        reader.seek(SeekFrom::Start(offset))?;
        let size_usize = usize::try_from(size).map_err(|_| PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::U64ExceedsPlatformUsize {
                field: AssetWireField::ExportSerialSize,
                value: size,
            },
        })?;
        let mut buf: Vec<u8> = Vec::new();
        buf.try_reserve_exact(size_usize).map_err(|source| {
            PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::AllocationFailed {
                    context: AssetAllocationContext::ExportPayloadBytes,
                    requested: size_usize,
                    unit: BoundsUnit::Bytes,
                    source,
                },
            }
        })?;
        buf.resize(size_usize, 0);
        reader.read_exact(&mut buf)?;
        payloads.push(PropertyBag::opaque(buf));
    }
    Ok(payloads)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::uasset::{build_minimal_ue4_27, MinimalPackage};

    #[test]
    fn round_trip_minimal_ue4_27() {
        let MinimalPackage { bytes, summary, names, imports, exports, payload } =
            build_minimal_ue4_27();
        let parsed = Package::read_from(&bytes, "test.uasset").unwrap();
        assert_eq!(parsed.summary, summary);
        assert_eq!(parsed.names, names);
        assert_eq!(parsed.imports, imports);
        assert_eq!(parsed.exports, exports);
        assert_eq!(parsed.payloads.len(), 1);
        assert_eq!(parsed.payloads[0], PropertyBag::opaque(payload));
    }

    #[test]
    fn rejects_export_payload_past_eof() {
        let MinimalPackage { mut bytes, .. } = build_minimal_ue4_27();
        bytes.truncate(bytes.len() - 8);
        let err = Package::read_from(&bytes, "test.uasset").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::InvalidOffset {
                    field: AssetWireField::ExportSerialOffset,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn context_clones_cheaply() {
        let MinimalPackage { bytes, .. } = build_minimal_ue4_27();
        let pkg = Package::read_from(&bytes, "test.uasset").unwrap();
        let ctx_a = pkg.context();
        let ctx_b = ctx_a.clone();
        assert!(Arc::ptr_eq(&ctx_a.names, &ctx_b.names));
    }
}

```

- [ ] **Step 2: Add `read_from_pak` to `impl Package`**

Append inside `impl Package` (above the closing `}`):

```rust
    /// Open a `.pak` archive at `pak_path`, find the entry at
    /// `virtual_path`, decompress its bytes, and parse as a UAsset.
    ///
    /// # Errors
    /// Any [`PaksmithError`] from the pak layer (open, find entry,
    /// decompress) or the asset layer (parse).
    pub fn read_from_pak<P: AsRef<std::path::Path>>(
        pak_path: P,
        virtual_path: &str,
    ) -> crate::Result<Self> {
        use crate::container::ContainerReader;
        let reader = crate::container::pak::PakReader::open(pak_path)?;
        let bytes = reader.read_entry(virtual_path)?;
        Self::read_from(&bytes, virtual_path)
    }
```

No dedicated unit test for `read_from_pak` — the real-fixture round-trip in `tests/asset_integration.rs` (Task 15) exercises it end-to-end. A unit test against an invalid pak would only assert "returns some error," which doesn't add information beyond what the inner `PakReader::open` + `read_entry` tests already cover.

- [ ] **Step 3: Run the tests**

Run: `cargo test -p paksmith-core --lib asset::package::tests`
Expected: 3 tests pass (`round_trip_minimal_ue4_27`, `rejects_export_payload_past_eof`, `context_clones_cheaply`).

- [ ] **Step 4: Clippy**

Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings`

- [ ] **Step 5: Commit**

```bash
git add crates/paksmith-core/src/asset/package.rs
git commit -m "$(cat <<'EOF'
feat(asset): Package::read_from + read_from_pak

Orchestrates summary → names → imports → exports → payloads. Each
export's serial region is carved out of the asset bytes and stored as
PropertyBag::Opaque pending Phase 2b's tagged-property iterator.

Rejects payload extents past EOF as AssetParseFault::InvalidOffset;
SerialOffset+SerialSize overflow surfaces as U64ArithmeticOverflow.

Package::context() builds an AssetContext (Arc-shared tables + Copy
version) — the bundle Phase 2b+ property parsers thread through their
recursion. Cheap-clone property pinned by a test.

Package::read_from_pak is a thin (PakReader::open → read_entry →
read_from) wrapper the CLI inspect command dispatches through. The
fixture-driven integration test in tests/asset_integration.rs (Task 15)
exercises it end-to-end.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 12: `paksmith-fixture-gen` — synthetic UAsset emitter

**Files:**

- Modify: `crates/paksmith-fixture-gen/Cargo.toml` — add `unreal_asset` git dep
- Create: `crates/paksmith-fixture-gen/src/uasset.rs` — fixture builder + parser cross-validation
- Modify: `crates/paksmith-fixture-gen/src/main.rs` — register the uasset fixture
- Modify: `deny.toml` — allow the new git source (per `MEMORY.md` cargo_deny_git_deps.md)
- Create: `tests/fixtures/real_v8b_uasset.pak` is the output produced by the generator

**Why:** mirrors the Phase-1 `trumank/repak` cross-parser pattern. Every fixture this tool emits is round-tripped through `unreal_asset` (AstroTechies/unreal_asset) to catch generator/parser-shared bugs.

The exact API of `unreal_asset` should be confirmed at implementation time — its crate may have evolved. The code below targets the version pinned in the Cargo.toml change; if the API has drifted, adjust call sites without changing the test intent (parse the fixture, confirm names/imports/exports match what paksmith produced).

- [ ] **Step 1: Add the `unreal_asset` git dep**

Edit `crates/paksmith-fixture-gen/Cargo.toml` — under `[dependencies]`, append:

```toml
# Cross-parser oracle for uasset cross-validation. Mirrors the
# trumank/repak pattern in this crate. Pinned to a SHA (verified to
# expose Asset::new + asset.imports + asset.asset_data.exports at
# write time of this plan). The crate IS on crates.io as 0.1.16 from
# this same monorepo, but the workspace structure means the
# unreal_asset_base / unreal_asset_exports / unreal_asset_properties
# sister crates need to come from the same revision — pinning git
# avoids the version-skew risk crates.io's per-crate publication
# allows.
unreal_asset = { version = "0.1", git = "https://github.com/AstroTechies/unrealmodding", rev = "f4df5d8e75b1e184832384d1865f0b696b90a614" }
```

> **Note (implementor):** the `rev` above pins the `main` HEAD at plan-write time (2025-11-28). If a tagged release lands before this task runs, prefer the tag SHA. Verify by `cargo update -p unreal_asset && cargo build -p paksmith-fixture-gen` after editing — the build either succeeds (API still matches) or fails with type errors (in which case adjust the call sites in Step 4 below; the contract — three structural assertions on the parsed Asset — is what matters).

- [ ] **Step 2: Update `deny.toml` for the new git source**

Per `MEMORY.md` `cargo_deny_git_deps.md`: a new git dep needs entries in both `[sources]` and `[bans]`. Edit `deny.toml` — find the existing `[sources]` block listing `repak`'s git URL and add a sibling entry:

```toml
# (inside [sources])
allow-git = [
    "https://github.com/trumank/repak",
    "https://github.com/AstroTechies/unrealmodding",
]
```

Verify the `[bans]` block already permits `version =` on git deps; the unreal_asset dep above includes a `version = "0.3"` clause to satisfy this.

- [ ] **Step 3: Write the fixture-gen integration test**

Create `crates/paksmith-fixture-gen/src/uasset.rs`:

```rust
//! Synthetic UAsset fixture generator + parser cross-validation.
//!
//! Mirrors the trumank/repak cross-parser pattern: every uasset this
//! module emits is parsed back through `unreal_asset` (AstroTechies)
//! to catch bugs that would otherwise pass paksmith's
//! generator-and-parser-share-the-bug blind spot.

use std::fs;
use std::path::Path;

use paksmith_core::asset::Package;
use paksmith_core::testing::uasset::{build_minimal_ue4_27, MinimalPackage};

/// Emit a known-good minimal UE 4.27 uasset to `path`.
///
/// Round-trips the result through paksmith's parser and asserts the
/// re-parse matches the source structure. Cross-validates the emitted
/// bytes against `unreal_asset`'s parser (see
/// `cross_validate_with_unreal_asset` below).
pub fn write_minimal_ue4_27(path: &Path) -> anyhow::Result<()> {
    let MinimalPackage { bytes, .. } = build_minimal_ue4_27();
    fs::write(path, &bytes)?;

    // Self-test: paksmith re-parses what paksmith wrote.
    let parsed = Package::read_from(&bytes, path.to_string_lossy().as_ref())
        .map_err(|e| anyhow::anyhow!("paksmith re-parse failed: {e}"))?;
    anyhow::ensure!(parsed.names.names.len() == 3, "expected 3 names");
    anyhow::ensure!(parsed.imports.imports.len() == 1, "expected 1 import");
    anyhow::ensure!(parsed.exports.exports.len() == 1, "expected 1 export");

    cross_validate_with_unreal_asset(&bytes)?;
    Ok(())
}

/// Parse `bytes` through `unreal_asset` and assert the structural
/// fields match what paksmith would produce.
///
/// API verified against `unreal_asset` revision
/// `f4df5d8e75b1e184832384d1865f0b696b90a614` (2025-11-28):
/// - `Asset::new(asset_data, bulk_data, engine_version, mappings)`
///   takes the .uasset reader, an optional .uexp reader, the engine
///   version enum, and an optional `.usmap` mappings file. The
///   constructor performs the parse — no separate `parse_data()` call.
/// - `asset.imports: Vec<Import>` is a public field.
/// - `asset.asset_data.exports: Vec<Export<PackageIndex>>` is reached
///   through the public `asset_data` field.
/// - `asset.get_name_map().get_ref().get_name_map_index_list()`
///   returns the parsed name list.
///
/// Phase 2a's synthetic fixture embeds the export payload bytes
/// directly after `total_header_size`, so `bulk_data` (the `.uexp`
/// reader) is `None`.
fn cross_validate_with_unreal_asset(bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::Cursor;
    use unreal_asset::engine_version::EngineVersion;
    use unreal_asset::Asset;

    let asset = Asset::new(
        Cursor::new(bytes.to_vec()),
        None,
        EngineVersion::VER_UE4_27,
        None,
    )
    .map_err(|e| anyhow::anyhow!("unreal_asset parse failed: {e}"))?;

    let name_count = asset.get_name_map().get_ref().get_name_map_index_list().len();
    anyhow::ensure!(
        name_count == 3,
        "unreal_asset saw {name_count} names; paksmith wrote 3"
    );
    anyhow::ensure!(
        asset.imports.len() == 1,
        "unreal_asset saw {} imports; paksmith wrote 1",
        asset.imports.len()
    );
    anyhow::ensure!(
        asset.asset_data.exports.len() == 1,
        "unreal_asset saw {} exports; paksmith wrote 1",
        asset.asset_data.exports.len()
    );
    Ok(())
}
```

- [ ] **Step 4: Add paksmith-core dep with `__test_utils` feature**

Edit `crates/paksmith-fixture-gen/Cargo.toml`:

```toml
# Move paksmith-core OUT of [dev-dependencies] and INTO [dependencies]
# (the same entry, just relocated) so the new src/uasset.rs module can
# import the builder from paksmith-core::testing::uasset. Enable the
# __test_utils feature on this side.
#
# THIS IS THE FIRST NON-DEV EDGE INTO paksmith-core THAT ACTIVATES
# __test_utils. Until now, the feature was activated only by
# paksmith-core's own dev-dep self-import — which gets pruned out of
# release builds. After this change, `cargo build --workspace
# --release` compiles paksmith-core::testing::{uasset,v10,oom} into
# every paksmith-core dependent's rlib (cli, gui, fixture-gen).
# Linker DCE strips the unused symbols from the final binaries; the
# `__` naming convention remains the soft guarantee against
# downstream import. See Task 10b's "Feature-unification caveat" for
# the full trade-off discussion and the fallback alternative.
[dependencies]
paksmith-core = { path = "../paksmith-core", version = "0.1", features = ["__test_utils"] }
anyhow = "1"
```

- [ ] **Step 5: Wire the fixture generator into `main.rs`**

The existing `paksmith-fixture-gen/src/main.rs` uses a `Fixture` struct + `write_fixture` helper to drive a data-driven matrix of repak-generated paks. The uasset emitter is a sibling concern (paksmith-synthesized, not repak), so call it directly from `main`:

```rust
mod uasset;

// ... at the end of main() — after the existing repak fixture loop:

println!("Generating UAsset fixtures (paksmith-synthesized, cross-validated via unreal_asset)...");
let out_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
    .join("../../tests/fixtures");
let uasset_path = out_dir.join("minimal_uasset_v5.uasset");
uasset::write_minimal_ue4_27(&uasset_path)
    .unwrap_or_else(|e| panic!("uasset fixture write: {e}"));
println!("wrote {} ({} bytes)", uasset_path.display(),
         std::fs::metadata(&uasset_path).unwrap().len());
```

- [ ] **Step 6: Run the fixture-gen tool**

Run: `cargo run -p paksmith-fixture-gen`
Expected: emits `tests/fixtures/minimal_uasset_v5.uasset`; `cross_validate_with_unreal_asset` succeeds against the bytes.

- [ ] **Step 7: Clippy across the workspace**

Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings`

- [ ] **Step 8: Commit**

```bash
git add crates/paksmith-fixture-gen/Cargo.toml \
        crates/paksmith-fixture-gen/src/uasset.rs \
        crates/paksmith-fixture-gen/src/main.rs \
        deny.toml \
        tests/fixtures/minimal_uasset_v5.uasset
git commit -m "$(cat <<'EOF'
feat(fixture-gen): synthetic UE 4.27 uasset + unreal_asset cross-validation

Mirrors the trumank/repak pattern from Phase 1: emits a known-good
minimal uasset (3 names, 1 import, 1 export, 16-byte opaque payload)
and round-trips through both paksmith and AstroTechies/unreal_asset
to catch generator-and-parser-share-the-bug blind spots.

deny.toml gains the unreal_asset git source per
MEMORY.md/cargo_deny_git_deps.md (both [sources] and version = clause).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 13: `paksmith-fixture-gen` — wrap the uasset in a synthetic pak

**Files:**

- Modify: `crates/paksmith-fixture-gen/src/uasset.rs` — add `write_minimal_pak_with_uasset`
- Modify: `crates/paksmith-fixture-gen/src/main.rs` — call the new function

**Why:** the asset integration test (`tests/asset_integration.rs`, Task 15) needs a `.pak` containing the synthetic uasset. The existing fixture-gen already uses `repak::PakBuilder` to build synthetic paks for Phase 1 (see `crates/paksmith-fixture-gen/src/main.rs:81` — `write_fixture`); this task calls the same API directly to embed the uasset bytes as a single pak entry.

- [ ] **Step 1: Add the wrapper function**

Append to `crates/paksmith-fixture-gen/src/uasset.rs`:

```rust
use std::fs::File;

use repak::{PakBuilder, Version};

/// Emit `tests/fixtures/real_v8b_uasset.pak` — a synthetic v8b pak
/// containing one uncompressed entry, the minimal UE 4.27 uasset.
///
/// Uses `repak::PakBuilder` directly (mirroring the existing
/// `write_fixture` helper in `main.rs`) rather than the data-driven
/// `Fixture` table, because the uasset payload is paksmith-synthesized
/// at runtime — the `Fixture` table assumes `&'static [u8]` payloads.
///
/// Version v8b is the default for Phase 2a's integration test because
/// it's the modern shape (FName-based compression slot table, u32
/// compression byte) — the asset reader is version-independent past
/// the entry-read, so the choice here only matters for the pak layer.
pub fn write_minimal_pak_with_uasset(path: &Path) -> anyhow::Result<()> {
    let MinimalPackage { bytes: uasset_bytes, .. } = build_minimal_ue4_27();

    // Atomic write via .tmp + rename, mirroring `write_fixture`'s
    // crash-safety pattern.
    let tmp = path.with_file_name(format!(
        "{}.tmp",
        path.file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| anyhow::anyhow!("path has no filename: {}", path.display()))?
    ));
    {
        let file = File::create(&tmp)?;
        let mut writer = PakBuilder::new().writer(
            file,
            Version::V8B,
            "../../../".to_string(),
            None,
        );
        writer
            .write_file("Game/Maps/Demo.uasset", false, &uasset_bytes)
            .map_err(|e| anyhow::anyhow!("repak write_file: {e}"))?;
        writer
            .write_index()
            .map_err(|e| anyhow::anyhow!("repak write_index: {e}"))?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}
```

- [ ] **Step 2: Wire into `main.rs`**

After the existing `uasset::write_minimal_ue4_27` call from Task 12, add:

```rust
let pak_path = out_dir.join("real_v8b_uasset.pak");
uasset::write_minimal_pak_with_uasset(&pak_path)
    .unwrap_or_else(|e| panic!("real_v8b_uasset.pak: {e}"));
println!("wrote {} ({} bytes)", pak_path.display(),
         std::fs::metadata(&pak_path).unwrap().len());
```

- [ ] **Step 3: Run the fixture generator**

Run: `cargo run -p paksmith-fixture-gen`
Expected: emits both `tests/fixtures/minimal_uasset_v5.uasset` and `tests/fixtures/real_v8b_uasset.pak`.

- [ ] **Step 4: Verify the pak round-trips through paksmith**

Run:

```bash
cargo run -p paksmith-cli -- list tests/fixtures/real_v8b_uasset.pak
```

Expected: one entry, `Game/Maps/Demo.uasset`, with the uasset byte count as compressed_size == uncompressed_size (no compression).

- [ ] **Step 5: Clippy**

Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings`

- [ ] **Step 6: Commit**

```bash
git add crates/paksmith-fixture-gen/src/ tests/fixtures/real_v8b_uasset.pak
git commit -m "$(cat <<'EOF'
test(fixture-gen): real_v8b_uasset.pak wraps the synthetic uasset

Asset integration tests need a .pak entry-point. This emits a single
uncompressed entry at Game/Maps/Demo.uasset containing the synthetic
UE 4.27 uasset from the previous task, wrapped via the existing
Phase-1 pak builder.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 14: `paksmith inspect` CLI command + JSON output

**Files:**

- Create: `crates/paksmith-cli/src/commands/inspect.rs`
- Modify: `crates/paksmith-cli/src/commands/mod.rs` — register the module
- Modify: `crates/paksmith-cli/src/main.rs` — add the clap subcommand

**Why:** the user-facing deliverable. `paksmith inspect <pak> <virtual/path>` prints the parsed Package as JSON to stdout.

- [ ] **Step 1: Write the integration test for the CLI command**

Create `crates/paksmith-cli/tests/inspect_cli.rs`:

```rust
#![allow(missing_docs)]

use std::path::PathBuf;
use std::process::Command;

fn fixture_path(name: &str) -> PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    PathBuf::from(manifest)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures")
        .join(name)
}

#[test]
fn inspect_emits_valid_json_with_expected_fields() {
    let pak = fixture_path("real_v8b_uasset.pak");
    assert!(
        pak.exists(),
        "fixture {} is missing — run `cargo run -p paksmith-fixture-gen`. \
         The fixture is also pinned in crates/paksmith-core/tests/fixture_anchor.rs, \
         so silent-skip on absence here would still fail the anchor test.",
        pak.display()
    );

    let output = Command::new(env!("CARGO_BIN_EXE_paksmith"))
        .args(["inspect", pak.to_str().unwrap(), "Game/Maps/Demo.uasset"])
        .output()
        .expect("run paksmith inspect");
    assert!(
        output.status.success(),
        "paksmith inspect failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("inspect output must be valid JSON");
    assert_eq!(json["asset_path"], "Game/Maps/Demo.uasset");
    assert_eq!(json["names"].as_array().unwrap().len(), 3);
    assert_eq!(json["imports"].as_array().unwrap().len(), 1);
    assert_eq!(json["exports"].as_array().unwrap().len(), 1);
    assert_eq!(json["summary"]["version"]["legacy_file_version"], -7);
}

/// Snapshot the full JSON shape so the inspect contract (the
/// "Deliverable" section of the Phase 2a plan) is pinned at the byte
/// level. Insta is added as a dev-dep alongside this test; on first
/// run, `cargo insta accept` writes the baseline.
///
/// The `payload_bytes` count and `serial_offset` may shift if the
/// summary/import/export wire layouts gain a field — that's a real
/// change worth surfacing in review rather than silently approving.
#[test]
fn inspect_json_snapshot() {
    let pak = fixture_path("real_v8b_uasset.pak");
    assert!(pak.exists(), "fixture missing — run paksmith-fixture-gen");
    let output = Command::new(env!("CARGO_BIN_EXE_paksmith"))
        .args(["inspect", pak.to_str().unwrap(), "Game/Maps/Demo.uasset"])
        .output()
        .expect("run paksmith inspect");
    assert!(output.status.success());
    let json_str = String::from_utf8(output.stdout).unwrap();
    insta::assert_snapshot!(json_str);
}
```

Add to `paksmith-cli/Cargo.toml` `[dev-dependencies]`:

```toml
serde_json = { workspace = true }
insta = { version = "1", features = ["json"] }
```

- [ ] **Step 2: Run the test (it fails — `inspect` subcommand doesn't exist)**

Run: `cargo test -p paksmith-cli --test inspect_cli 2>&1 | tail -20`
Expected: clap rejects the unknown subcommand.

- [ ] **Step 3: Implement the `inspect` command**

Create `crates/paksmith-cli/src/commands/inspect.rs`:

```rust
//! `paksmith inspect <pak> <virtual/path>` — dump a uasset's
//! structural header as JSON.

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use paksmith_core::asset::Package;

/// Run the `inspect` subcommand.
pub fn run(pak: PathBuf, asset: String) -> ExitCode {
    let pkg = match Package::read_from_pak(&pak, &asset) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("paksmith inspect: {e}");
            return ExitCode::from(2);
        }
    };
    match serde_json::to_writer_pretty(std::io::stdout().lock(), &pkg) {
        Ok(()) => {
            let _ = std::io::stdout().lock().write_all(b"\n");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("paksmith inspect: json serialization failed: {e}");
            ExitCode::from(2)
        }
    }
}
```

- [ ] **Step 4: Register the subcommand in `main.rs`**

Edit `crates/paksmith-cli/src/main.rs` — find the clap `Subcommand` enum and the dispatch match. Add:

```rust
// In the Subcommand enum:
    /// Dump a uasset's structural header as JSON.
    Inspect {
        /// Path to the .pak file.
        pak: PathBuf,
        /// Virtual path of the asset within the archive.
        asset: String,
    },

// In the dispatch match:
        Subcommand::Inspect { pak, asset } => commands::inspect::run(pak, asset),
```

Edit `crates/paksmith-cli/src/commands/mod.rs`:

```rust
pub mod inspect;
```

- [ ] **Step 5: Run the test**

Run: `cargo test -p paksmith-cli --test inspect_cli`
Expected: passes (assuming the fixture has been generated; the test skips with a message otherwise).

- [ ] **Step 6: Manually exercise the command**

Run:

```bash
cargo run -p paksmith-fixture-gen
cargo run -p paksmith-cli -- inspect tests/fixtures/real_v8b_uasset.pak Game/Maps/Demo.uasset
```

Expected: pretty-printed JSON matching the shape in this plan's "Deliverable" section.

- [ ] **Step 7: Clippy**

Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings`

- [ ] **Step 8: Commit**

```bash
git add crates/paksmith-cli/src/commands/inspect.rs \
        crates/paksmith-cli/src/commands/mod.rs \
        crates/paksmith-cli/src/main.rs \
        crates/paksmith-cli/tests/inspect_cli.rs \
        crates/paksmith-cli/Cargo.toml
git commit -m "$(cat <<'EOF'
feat(cli): paksmith inspect — dump uasset header as JSON

Opens a .pak, reads the named entry, parses through Package::read_from_pak,
and prints the structural header (summary, names, imports, exports,
opaque payload byte counts) as pretty-printed JSON on stdout.

Exit code 0 on success, 2 on any error (parse, I/O, JSON). Integration
test (tests/inspect_cli.rs) drives the binary end-to-end against the
generated fixture and asserts the JSON shape.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 15: Integration test — open pak, parse uasset, assert structure

**Files:**

- Create: `crates/paksmith-core/tests/asset_integration.rs`
- Modify: `crates/paksmith-core/tests/fixture_anchor.rs` — add `anchor_real_v8b_uasset_fixture_bytes`

**Why:** end-to-end smoke test at the core-library level (independent of the CLI). Drives `Package::read_from_pak` against the synthetic fixture and asserts the parsed structure.

- [ ] **Step 1: Write the test**

Create `crates/paksmith-core/tests/asset_integration.rs`:

```rust
#![allow(missing_docs)]

use std::path::PathBuf;

use paksmith_core::asset::package_index::PackageIndex;
use paksmith_core::asset::Package;

fn fixture_path(name: &str) -> PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    PathBuf::from(manifest)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures")
        .join(name)
}

fn assert_fixture_present(pak: &PathBuf) {
    assert!(
        pak.exists(),
        "fixture {} is missing — run `cargo run -p paksmith-fixture-gen`. \
         Pinned in fixture_anchor.rs so CI fails loud here regardless.",
        pak.display()
    );
}

#[test]
fn round_trip_minimal_pak_uasset() {
    let pak = fixture_path("real_v8b_uasset.pak");
    assert_fixture_present(&pak);

    let pkg = Package::read_from_pak(&pak, "Game/Maps/Demo.uasset")
        .expect("parse minimal uasset from synthetic pak");

    assert_eq!(pkg.asset_path, "Game/Maps/Demo.uasset");
    assert_eq!(pkg.summary.version.legacy_file_version, -7);
    assert_eq!(pkg.summary.version.file_version_ue4, 522);
    assert!(pkg.summary.version.file_version_ue5.is_none());
    assert_eq!(pkg.names.names.len(), 3);
    assert_eq!(pkg.names.names[0].as_str(), "/Script/CoreUObject");
    assert_eq!(pkg.imports.imports.len(), 1);
    assert_eq!(pkg.imports.imports[0].outer_index, PackageIndex::Null);
    assert_eq!(pkg.exports.exports.len(), 1);
    assert_eq!(pkg.exports.exports[0].class_index, PackageIndex::Import(0));
    assert!(pkg.exports.exports[0].is_asset);
    assert_eq!(pkg.exports.exports[0].serial_size, 16);
    assert_eq!(pkg.payloads.len(), 1);
    assert_eq!(pkg.payloads[0].byte_len(), 16);
}

#[test]
fn context_arc_sharing() {
    let pak = fixture_path("real_v8b_uasset.pak");
    assert_fixture_present(&pak);
    let pkg = Package::read_from_pak(&pak, "Game/Maps/Demo.uasset").unwrap();
    let ctx1 = pkg.context();
    let ctx2 = ctx1.clone();
    // Same Arc — cloning the context is a refcount bump.
    assert!(std::sync::Arc::ptr_eq(&ctx1.names, &ctx2.names));
    assert!(std::sync::Arc::ptr_eq(&ctx1.imports, &ctx2.imports));
    assert!(std::sync::Arc::ptr_eq(&ctx1.exports, &ctx2.exports));
}
```

- [ ] **Step 2: Add a fixture anchor in `fixture_anchor.rs`**

Edit `crates/paksmith-core/tests/fixture_anchor.rs` — find the existing block of `anchor_real_v*_minimal_fixture_bytes` tests (around line 98 in the Phase 1 file) and add a sibling:

```rust
#[test]
fn anchor_real_v8b_uasset_fixture_bytes() {
    // Phase 2a integration test depends on this fixture's exact bytes
    // (round_trip_minimal_pak_uasset asserts the uasset structure
    // derived from them). Sha1 here catches the silent failure mode
    // where the fixture-gen output drifts (e.g., a future PakBuilder
    // version padding the index differently).
    //
    // To regenerate: `cargo run -p paksmith-fixture-gen`, then
    // `sha1sum tests/fixtures/real_v8b_uasset.pak` and paste below.
    anchor_fixture_sha1(
        "real_v8b_uasset.pak",
        // SHA1 produced on first run — paste the actual digest the
        // implementor sees after `cargo run -p paksmith-fixture-gen`.
        // Then re-run this test to confirm the anchor matches.
        "REPLACE_WITH_ACTUAL_SHA1_AFTER_FIRST_FIXTURE_GEN_RUN",
    );
}
```

> **Implementor:** the SHA1 above is a placeholder the test framework will fail on. Run `cargo run -p paksmith-fixture-gen` once, get the SHA1 via `shasum tests/fixtures/real_v8b_uasset.pak`, paste it in, and re-run the test. This is the same workflow Phase 1's eight existing anchors use; the placeholder string is a hint, not silent acceptance — `anchor_fixture_sha1` panics on mismatch with the actual digest.

- [ ] **Step 3: Run the tests**

Run:

```bash
cargo run -p paksmith-fixture-gen
shasum tests/fixtures/real_v8b_uasset.pak
# paste the SHA1 into anchor_real_v8b_uasset_fixture_bytes above
cargo test -p paksmith-core --test asset_integration
cargo test -p paksmith-core --test fixture_anchor anchor_real_v8b_uasset
```

Expected: both tests pass.

- [ ] **Step 4: Clippy**

Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings`

- [ ] **Step 5: Commit**

```bash
git add crates/paksmith-core/tests/asset_integration.rs \
        crates/paksmith-core/tests/fixture_anchor.rs
git commit -m "$(cat <<'EOF'
test(asset): end-to-end pak→uasset integration test

Opens real_v8b_uasset.pak, parses the Game/Maps/Demo.uasset entry
via Package::read_from_pak, and asserts the structural shape:
3 names, 1 import (Null outer), 1 export (Import(0) class, 16-byte
opaque payload). Second test pins the AssetContext Arc-sharing
property — cloning is O(1) refcount bumps, not table copies.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 16: Property-based round-trip + cap-rejection proptest

**Files:**

- Create: `crates/paksmith-core/tests/asset_proptest.rs`

**Why:** the per-component round-trip unit tests cover happy paths; a proptest sweeps the structural-cap and version-conditional branches that hand-crafted tests miss. Mirrors `crates/paksmith-core/tests/footer_proptest.rs` and `index_proptest.rs` from Phase 1.

- [ ] **Step 1: Write the proptest**

Create `crates/paksmith-core/tests/asset_proptest.rs`:

```rust
#![allow(missing_docs)]

use proptest::prelude::*;

use paksmith_core::asset::custom_version::{
    CustomVersion, CustomVersionContainer, MAX_CUSTOM_VERSIONS,
};
use paksmith_core::asset::engine_version::EngineVersion;
use paksmith_core::asset::import_table::{
    ImportTable, ObjectImport, MAX_IMPORT_TABLE_ENTRIES,
};
use paksmith_core::asset::name_table::{FName, NameTable, MAX_NAME_TABLE_ENTRIES};
use paksmith_core::asset::package_index::PackageIndex;
use paksmith_core::asset::version::AssetVersion;
use paksmith_core::error::{AssetParseFault, AssetWireField, PaksmithError};

prop_compose! {
    fn arb_ue4_27_version()(licensee in any::<i32>()) -> AssetVersion {
        AssetVersion {
            legacy_file_version: -7,
            file_version_ue4: 522,
            file_version_ue5: None,
            file_version_licensee_ue4: licensee,
        }
    }
}

prop_compose! {
    fn arb_engine_version()(
        major in any::<u16>(),
        minor in any::<u16>(),
        patch in any::<u16>(),
        changelist in any::<u32>(),
        branch in "[a-zA-Z0-9+\\-_.]{0,32}",
    ) -> EngineVersion {
        EngineVersion { major, minor, patch, changelist, branch }
    }
}

proptest! {
    #[test]
    fn engine_version_round_trip(v in arb_engine_version()) {
        let mut buf = Vec::new();
        v.write_to(&mut buf).unwrap();
        let parsed = EngineVersion::read_from(&mut std::io::Cursor::new(&buf)).unwrap();
        prop_assert_eq!(parsed, v);
    }

    #[test]
    fn custom_version_container_round_trip(
        rows in proptest::collection::vec((any::<[u8; 16]>(), any::<i32>()), 0..16)
    ) {
        let c = CustomVersionContainer {
            versions: rows.into_iter().map(|(g, v)| CustomVersion { guid: FGuid::from_bytes(g), version: v }).collect(),
        };
        let mut buf = Vec::new();
        c.write_to(&mut buf).unwrap();
        let parsed =
            CustomVersionContainer::read_from(&mut std::io::Cursor::new(&buf), "x.uasset").unwrap();
        prop_assert_eq!(parsed, c);
    }

    #[test]
    fn name_table_round_trip(
        names in proptest::collection::vec("[a-zA-Z][a-zA-Z0-9_]{0,15}", 0..32)
    ) {
        let table = NameTable {
            names: names.iter().map(|s| FName::new(s)).collect(),
        };
        let mut buf = Vec::new();
        table.write_to(&mut buf).unwrap();
        let mut cursor = std::io::Cursor::new(&buf);
        let parsed = NameTable::read_from(
            &mut cursor,
            0,
            table.names.len() as i32,
            "x.uasset",
        )
        .unwrap();
        prop_assert_eq!(parsed, table);
    }

    #[test]
    fn name_table_rejects_count_over_cap(over in 1u32..1024) {
        let count = (MAX_NAME_TABLE_ENTRIES as i64 + over as i64) as i32;
        let err = NameTable::read_from(
            &mut std::io::Cursor::new(Vec::<u8>::new()),
            0,
            count,
            "x.uasset",
        )
        .unwrap_err();
        prop_assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::BoundsExceeded {
                    field: AssetWireField::NameCount,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn import_table_round_trip(count in 0u32..8) {
        let v = AssetVersion {
            legacy_file_version: -7,
            file_version_ue4: 522,
            file_version_ue5: None,
            file_version_licensee_ue4: 0,
        };
        let table = ImportTable {
            imports: (0..count).map(|i| ObjectImport {
                class_package_name: i,
                class_package_number: 0,
                class_name: i + 1,
                class_name_number: 0,
                outer_index: PackageIndex::Null,
                object_name: i + 2,
                object_name_number: 0,
                package_name: None,
                import_optional: None,
            }).collect(),
        };
        let mut buf = Vec::new();
        table.write_to(&mut buf, v).unwrap();
        let parsed = ImportTable::read_from(
            &mut std::io::Cursor::new(buf),
            0,
            count as i32,
            v,
            "x.uasset",
        ).unwrap();
        prop_assert_eq!(parsed, table);
    }

    #[test]
    fn import_count_cap_rejection(over in 1u32..1024) {
        let v = AssetVersion {
            legacy_file_version: -7,
            file_version_ue4: 522,
            file_version_ue5: None,
            file_version_licensee_ue4: 0,
        };
        let count = (MAX_IMPORT_TABLE_ENTRIES as i64 + over as i64) as i32;
        let err = ImportTable::read_from(
            &mut std::io::Cursor::new(Vec::<u8>::new()),
            0,
            count,
            v,
            "x.uasset",
        )
        .unwrap_err();
        prop_assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::BoundsExceeded {
                    field: AssetWireField::ImportCount,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn custom_version_count_cap_rejection(over in 1u32..1024) {
        let count = MAX_CUSTOM_VERSIONS + over;
        let mut buf = Vec::new();
        buf.extend_from_slice(&(count as i32).to_le_bytes());
        let err = CustomVersionContainer::read_from(
            &mut std::io::Cursor::new(&buf),
            "x.uasset",
        )
        .unwrap_err();
        prop_assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::BoundsExceeded {
                    field: AssetWireField::CustomVersionCount,
                    ..
                },
                ..
            }
        ));
    }
}
```

- [ ] **Step 2: Run the proptest**

Run: `cargo test -p paksmith-core --test asset_proptest`
Expected: all property tests pass (default 256 cases each).

- [ ] **Step 3: Clippy**

Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings`

- [ ] **Step 4: Commit**

```bash
git add crates/paksmith-core/tests/asset_proptest.rs
git commit -m "$(cat <<'EOF'
test(asset): proptest — round-trips + structural-cap rejections

Property-based coverage for the wire-format round-trip identity
(EngineVersion, CustomVersionContainer, NameTable, ImportTable) and
for cap rejection (NameCount / ImportCount / CustomVersionCount over
MAX_*). Mirrors footer_proptest.rs / index_proptest.rs structure
from Phase 1.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 17: Documentation updates

**Files:**

- Modify: `ARCHITECTURE.md` — promote `asset/` from "planned" to "current"
- Modify: `README.md` — add `inspect` to the CLI usage examples
- Modify: `docs/plans/ROADMAP.md` — mark Phase 2a complete, link this plan
- Modify: `crates/paksmith-core/src/lib.rs` — update the top-doc to mention Phase 2a scope

**Why:** docs ship with the code. Same precedent as PR #126 ("docs: refresh README + ARCHITECTURE + CLAUDE.md + ROADMAP for Phase 1 reality").

- [ ] **Step 1: Update `ARCHITECTURE.md`**

Find the `### Modules — current` block. Add `asset/` to it:

```markdown
- `asset/` — UAsset deserialization. Phase 2a ships the structural
  header parser: [`PackageSummary`](FPackageFileSummary equivalent),
  [`NameTable`] (FName pool with dual CityHash16 trailer), `ImportTable`,
  `ExportTable`, plus the [`AssetContext`] bundle threaded through
  downstream property parsers. Property bodies are carried as opaque
  byte payloads via `PropertyBag::Opaque`; tagged-property iteration
  lands in Phase 2b.
```

Remove the corresponding `asset/` line from `### Modules — planned`.

- [ ] **Step 2: Update `README.md`**

Find the existing `paksmith list` example. Add immediately after:

````markdown
### `paksmith inspect`

Dump a uasset's structural header (summary, name table, import/export
tables) as JSON. Property bodies are carried as opaque byte counts
in this phase; full property decoding lands in Phase 2b.

```bash
paksmith inspect path/to/archive.pak Game/Maps/Demo.uasset
```
````

- [ ] **Step 3: Update `docs/plans/ROADMAP.md`**

Find the Phase 2 entry. Add a status line at the top:

```markdown
**Status:** Phase 2a complete — see `phase-2a-uasset-header.md`. Phase
2b–2e (tagged-property iteration, container properties, object refs,
`.uexp` stitching) are scoped but not yet planned.
```

- [ ] **Step 4: Update the crate root doc**

Edit `crates/paksmith-core/src/lib.rs` — update the top-doc:

```rust
//! Core library for parsing and extracting Unreal Engine game assets.
//!
//! **Phase 1 scope**: container readers for the `.pak` archive format
//! (see [`container::pak`]).
//!
//! **Phase 2a scope** (current): UAsset structural-header parsing —
//! [`asset::PackageSummary`] (`FPackageFileSummary`),
//! [`asset::NameTable`] (FName pool), [`asset::ImportTable`],
//! [`asset::ExportTable`], with property bodies carried as opaque
//! byte payloads via [`asset::PropertyBag::Opaque`]. Tagged-property
//! iteration lands in Phase 2b.
//!
//! IoStore container reading, format handlers, and game profile
//! management remain planned per `docs/plans/ROADMAP.md`.
```

- [ ] **Step 5: Run the full test suite as a regression check**

Run:

```bash
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add ARCHITECTURE.md README.md docs/plans/ROADMAP.md crates/paksmith-core/src/lib.rs
git commit -m "$(cat <<'EOF'
docs: promote asset/ to current; add inspect to README; Phase 2a status

ARCHITECTURE.md moves asset/ from "planned" to "current" with a one-
paragraph summary of Phase 2a scope. README.md gains a paksmith inspect
example alongside the existing list one. ROADMAP.md gets a Phase 2a
status line. lib.rs top-doc names the Phase 2a deliverables.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Self-review checklist (run before opening the PR)

1. **Spec coverage:** every section in the "Deliverable" JSON shape (summary, names, imports, exports, payload_bytes) maps to a parsed Rust field on `Package`. ✓
2. **Wire-stable Display:** every `AssetParseFault` variant has a `error::tests::asset_parse_display_*` pin. ✓
3. **Structural caps:** name/import/export/custom-version/header-size each have a `MAX_*` constant and a unit/proptest covering the rejection path. ✓
4. **Fallible allocations:** every `Vec::try_reserve_exact` site surfaces failures as `AssetParseFault::AllocationFailed`. ✓
5. **`#[non_exhaustive]`:** on every new public enum (`AssetParseFault`, `AssetWireField`, `AssetOverflowSite`, `AssetAllocationContext`, `PropertyBag`, `Asset`). ✓
6. **No panics:** every wire-read site uses `Result<T, PaksmithError>`. No infallible `PackageIndex::from_raw` constructor exists (deleted per CLAUDE.md "no panics in core" — see PR #151); `try_from_raw` is the sole construction path and surfaces `i32::MIN` as `PackageIndexError::ImportIndexUnderflow`. Synthetic test/fixture construction uses `try_from_raw(...).unwrap()`. ✓
7. **No placeholders:** every task ships runnable code. `unreal_asset` API is pinned to commit `f4df5d8e75b1e184832384d1865f0b696b90a614` with the actual call shape (`Asset::new` + public `imports` field + `asset_data.exports`). The pak builder uses `repak::PakBuilder::new().writer(...).write_file(...)` directly, mirroring the existing `write_fixture` helper. The fixture-anchor SHA1 is filled in by running fixture-gen once — same Phase 1 workflow, anchored loud-fail on mismatch.
8. **Type consistency:** `PackageIndex::Null/Import/Export`, `FName::new/as_str`, `Package::read_from/read_from_pak/context`, `AssetContext.names/imports/exports/version` — all referenced consistently across tasks.
9. **Commit cadence:** one commit per task, ≤200 lines each (Task 9 may exceed if the summary writer is included; consider splitting summary read vs write into 9a/9b at implementation time if the diff is uncomfortably large).
10. **Clippy with `--all-targets --all-features`:** every task ends with this command per `MEMORY.md` `ghas_clippy_extra_lints.md`. ✓
11. **`cargo fmt --all -- --check`:** every task ends with this command. CI's `Lint` job runs both `cargo fmt --all -- --check` AND clippy; clippy passing locally does NOT imply fmt is clean — see PR #149 follow-up. The `.githooks/pre-commit` hook also enforces this when wired up via `git config core.hooksPath .githooks` (one-time per clone).

## Out-of-scope reminders for the implementor

Do not let these creep into the diff:

- Tagged-property iteration / `FPropertyTag` reader
- Property type-specific payload parsing (Bool / Int variants / Float / Str / Name / Enum / Array / Map / Set / Struct)
- Object reference resolution through the import table beyond what `Package::context()` exposes
- `.uexp` companion file support (Phase 2e)
- Asset-level AES decryption
- AssetRegistry / ThumbnailTable / GatherableTextData parsing
- Versions outside `LegacyFileVersion ∈ {-7, -8}` and `FileVersionUE4 ∈ [504, ∞)` and `FileVersionUE5 ∈ [1000, 1010]`

If the implementor finds a real-world asset that doesn't fit this window, the right move is to add a typed-error variant rejecting it (mirroring how Phase 1 rejected pre-v3 paks), not to widen the support window.
