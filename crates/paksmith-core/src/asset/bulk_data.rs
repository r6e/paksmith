//! Phase 3b lands the real `FByteBulkData` / `BulkDataResolver` /
//! `BulkData` types in this module. 3a ships a unit struct so the
//! `FormatHandler::export` signature in `crate::export` compiles
//! against the type identity; 3b's PR widens to fields-bearing in a
//! single atomic change.
//!
//! Why unit struct, not `_private: ()` hidden field? A unit struct
//! exposes no destructurable FIELD surface — so 3b's widening to
//! `BulkData { bytes: ..., record: ..., tier: ... }` doesn't break
//! any field-destructure pattern (none exists today). The
//! hidden-field placeholder approach would ship a `#[doc(hidden)]`
//! field that a paranoid downstream could destructure-match
//! (`BulkData { _private }`), which would break at 3b.
//!
//! # Cap constants
//!
//! Caps follow the project-wide convention of living in the module
//! that uses them, mirroring `container/pak/mod.rs::MAX_UNCOMPRESSED_ENTRY_BYTES`,
//! `asset/name_table.rs::MAX_NAME_TABLE_ENTRIES`, and
//! `asset/property/bag.rs::MAX_PROPERTY_DEPTH`. Each cap has a
//! `#[cfg(feature = "__test_utils")]` accessor so the boundary
//! integration tests read the live value rather than duplicating
//! the constant. The plan's `seams.rs` location is rejected —
//! `seams.rs` is OOM-injection-only.

/// Maximum decompressed bulk-data payload size (8 GiB). Shares the
/// 8 GiB ceiling with `MAX_UNCOMPRESSED_ENTRY_BYTES` in
/// `container::pak` by convention — a single `FByteBulkData` record
/// can't exceed an entry's worst-case decompressed size. The two
/// caps are not const-linked because `MAX_UNCOMPRESSED_ENTRY_BYTES`
/// is `pub(in crate::container::pak)` (visibility intentional;
/// container-internal). Reviewers changing either constant must
/// re-pair the value here.
pub(crate) const MAX_BULK_DATA_SIZE: u64 = 8 * 1024 * 1024 * 1024;

/// Maximum compressed bulk-data payload size on disk (512 MiB).
/// Tighter than `MAX_BULK_DATA_SIZE` (8 GiB) — defense-in-depth
/// against a crafted record whose `SizeOnDisk` (compressed bytes
/// for `BULKDATA_SerializeCompressedZLIB`) approaches the
/// decompressed cap. Limits the bytes we read off disk before any
/// decompression attempt; the 8 GiB decompressed cap then bounds
/// the post-decompression buffer separately. Mirrors the
/// `MAX_USMAP_COMPRESSED_SIZE` (64 MiB) / `MAX_USMAP_DECOMPRESSED_SIZE`
/// (256 MiB) pair in `asset/mappings.rs` — the 1:16 compressed-to-
/// decompressed ratio matches the per-package budget headroom
/// (`MAX_TOTAL_BULK_DATA_BYTES_PER_PACKAGE` = 16 GiB / per-record
/// decompressed = 8 GiB). Real-world `.ubulk` records compressed
/// top out around 50–100 MB; 512 MiB gives ~5x typical headroom.
pub(crate) const MAX_BULK_DATA_COMPRESSED_SIZE: u64 = 512 * 1024 * 1024;

/// Maximum `.ubulk` / `.uptnl` file size (16 GiB). Bounds the seek
/// window for streaming-tier records before any allocation. The
/// same constant applies to both companion files; the resolver
/// reuses it for both `BulkDataTier::Streaming` and
/// `BulkDataTier::OptionalStreaming` lazy loads.
pub(crate) const MAX_UBULK_FILE_SIZE: u64 = 16 * 1024 * 1024 * 1024;

/// Maximum `FByteBulkData` records per export. Real cooked content
/// rarely exceeds ~8 records (one per mip + duplicates). Cap at 256
/// to prevent a malformed export claiming N records and driving
/// allocation amplification. Enforced at `Package::insert_bulk_records`
/// (closing the typed-reader bypass loophole) and at typed-reader
/// sites in Phase 3e/3g/3h via a per-export counter pattern.
pub(crate) const MAX_BULK_DATA_RECORDS_PER_EXPORT: usize = 256;

/// Global budget on cumulative resolved bulk-data bytes per Package
/// (16 GiB). Without this, N exports × `MAX_BULK_DATA_RECORDS_PER_EXPORT`
/// × `MAX_BULK_DATA_SIZE` would be unbounded heap commitment.
/// Enforced by the resolver's running accumulator BEFORE allocation
/// (see plan Design Decision #14).
pub(crate) const MAX_TOTAL_BULK_DATA_BYTES_PER_PACKAGE: u64 = 16 * 1024 * 1024 * 1024;

/// Test-only accessor for `MAX_BULK_DATA_SIZE` (8 GiB). Integration
/// tests in `paksmith-core-tests` read the live value via this
/// accessor so boundary fixtures stay synchronized with cap changes.
#[cfg(feature = "__test_utils")]
#[must_use]
pub fn max_bulk_data_size() -> u64 {
    MAX_BULK_DATA_SIZE
}

/// Test-only accessor for `MAX_BULK_DATA_COMPRESSED_SIZE` (512 MiB).
#[cfg(feature = "__test_utils")]
#[must_use]
pub fn max_bulk_data_compressed_size() -> u64 {
    MAX_BULK_DATA_COMPRESSED_SIZE
}

/// Test-only accessor for `MAX_UBULK_FILE_SIZE` (16 GiB).
#[cfg(feature = "__test_utils")]
#[must_use]
pub fn max_ubulk_file_size() -> u64 {
    MAX_UBULK_FILE_SIZE
}

/// Test-only accessor for `MAX_BULK_DATA_RECORDS_PER_EXPORT` (256).
#[cfg(feature = "__test_utils")]
#[must_use]
pub fn max_bulk_data_records_per_export() -> usize {
    MAX_BULK_DATA_RECORDS_PER_EXPORT
}

/// Test-only accessor for `MAX_TOTAL_BULK_DATA_BYTES_PER_PACKAGE`
/// (16 GiB).
#[cfg(feature = "__test_utils")]
#[must_use]
pub fn max_total_bulk_data_bytes_per_package() -> u64 {
    MAX_TOTAL_BULK_DATA_BYTES_PER_PACKAGE
}

/// Identifies where a resolved `FByteBulkData` record's bytes live.
///
/// The resolver dispatches on `BulkDataFlags`:
///
/// | Flag combination | Tier |
/// |------------------|------|
/// | `BULKDATA_PayloadAtEndOfFile` + offset < `total_header_size` | [`Self::Inline`] |
/// | `BULKDATA_PayloadAtEndOfFile` + offset ≥ `total_header_size` | [`Self::UexpResident`] |
/// | `BULKDATA_PayloadInSeperateFile` (no `OptionalPayload`) | [`Self::Streaming`] |
/// | `BULKDATA_OptionalPayload` + `PayloadInSeperateFile` | [`Self::OptionalStreaming`] |
///
/// `#[non_exhaustive]` reserves the right for Phase 8 (IoStore) to
/// extend with additional tiers (e.g. partition-spanning streaming)
/// without an SemVer-major bump.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
#[non_exhaustive]
pub enum BulkDataTier {
    /// Payload bytes live in the parent `.uasset` body (resolved
    /// offset < `total_header_size`).
    Inline,
    /// Payload bytes live in the `.uexp` companion body (resolved
    /// offset ≥ `total_header_size`).
    UexpResident,
    /// Payload bytes live in the `.ubulk` companion file (offset is
    /// absolute within `.ubulk`, no `BulkDataStartOffset` fix-up).
    Streaming,
    /// Payload bytes live in the `.uptnl` companion file (the
    /// `BULKDATA_OptionalPayload` tier). Lazy-loaded; absence of
    /// `.uptnl` produces
    /// `MissingCompanionFile { kind: CompanionFileKind::Uptnl }`.
    OptionalStreaming,
}

impl std::fmt::Display for BulkDataTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Inline => "inline",
            Self::UexpResident => "uexp-resident",
            Self::Streaming => "streaming",
            Self::OptionalStreaming => "optional-streaming",
        };
        f.write_str(s)
    }
}

/// Resolved bulk-data payload. **3a unit-struct stub.**
///
/// # Breaking change at 3b
///
/// 3b's PR widens this to a fields-bearing struct carrying
/// `bytes: Vec<u8>`, `record: FByteBulkData`, and
/// `tier: BulkDataTier`. The widening doesn't break field-pattern
/// match arms (none can exist on a unit struct today), but it
/// DOES break direct unit-literal construction:
///
/// ```rust,ignore
/// // Works in 3a, breaks at 3b:
/// let bulk = paksmith_core::export::BulkData;
/// ```
///
/// Phase 3 internal callers should treat `BulkData` as
/// constructor-opaque; 3b adds the necessary constructors via
/// `BulkDataResolver`. External consumers don't need to construct
/// `BulkData` in 3a (handlers receive `Option<&BulkData>` and
/// today's `GenericHandler` ignores the argument).
#[derive(Debug, Clone)]
pub struct BulkData;

/// `FByteBulkData` wire record. **3a unit-struct stub.**
///
/// Phase 3b widens this to carry the wire fields (BulkDataFlags,
/// ElementCount, SizeOnDisk, OffsetInFile). 3a ships the unit stub
/// only so the `TypedReaderFn` signature in
/// `crate::asset::exports::dispatch` (which returns
/// `Result<(Asset, Vec<FByteBulkData>)>`) compiles. The Phase 3a
/// dispatch table is empty, so no typed reader actually emits an
/// `FByteBulkData` value until 3b lands the real wire-reader.
///
/// # Breaking change at 3b
///
/// 3b's PR widens this to a fields-bearing struct. The widening
/// doesn't break field-pattern match arms (none can exist on a unit
/// struct today), but it DOES break direct unit-literal
/// construction. No Phase 3a code constructs `FByteBulkData`
/// (dispatch table is empty).
#[derive(Debug, Clone)]
pub struct FByteBulkData;

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the five cap values directly. Kills cargo-mutants
    /// arithmetic mutations on the constant definitions (e.g.
    /// `8 * 1024 * 1024 * 1024` → `8 + 1024 + 1024 + 1024`
    /// would produce 4120, not 8 GiB; this assertion catches the
    /// drift). Also pins values against accidental tightening or
    /// loosening — every cap is documented in the parent module's
    /// doc-comments with a calibrated value; changing the constant
    /// without updating the doc-comment is a frequent drift mode
    /// (see commit `3bf6370`).
    #[test]
    fn caps_pin_expected_values() {
        assert_eq!(MAX_BULK_DATA_SIZE, 8_589_934_592, "8 GiB");
        assert_eq!(MAX_BULK_DATA_COMPRESSED_SIZE, 536_870_912, "512 MiB");
        assert_eq!(MAX_UBULK_FILE_SIZE, 17_179_869_184, "16 GiB");
        assert_eq!(MAX_BULK_DATA_RECORDS_PER_EXPORT, 256);
        assert_eq!(
            MAX_TOTAL_BULK_DATA_BYTES_PER_PACKAGE, 17_179_869_184,
            "16 GiB"
        );
    }

    /// Pins each `__test_utils`-gated accessor to return its
    /// corresponding constant. Kills cargo-mutants body-replacement
    /// mutations (e.g. `fn max_bulk_data_size() -> u64 { 0 }` would
    /// pass any test that doesn't actually call the accessor — this
    /// assertion forces an exact match against the constant). The
    /// pair (`caps_pin_expected_values` + this test) gives full
    /// mutation coverage on both the constant arithmetic and the
    /// accessor body.
    #[cfg(feature = "__test_utils")]
    #[test]
    fn accessors_return_constants() {
        assert_eq!(max_bulk_data_size(), MAX_BULK_DATA_SIZE);
        assert_eq!(
            max_bulk_data_compressed_size(),
            MAX_BULK_DATA_COMPRESSED_SIZE
        );
        assert_eq!(max_ubulk_file_size(), MAX_UBULK_FILE_SIZE);
        assert_eq!(
            max_bulk_data_records_per_export(),
            MAX_BULK_DATA_RECORDS_PER_EXPORT
        );
        assert_eq!(
            max_total_bulk_data_bytes_per_package(),
            MAX_TOTAL_BULK_DATA_BYTES_PER_PACKAGE
        );
    }
}
