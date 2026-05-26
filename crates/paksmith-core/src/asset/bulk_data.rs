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

/// `u32` bitfield wrapper for `FByteBulkData.BulkDataFlags`. Catalog
/// at `docs/formats/texture/mips-and-streaming.md` §BulkDataFlags;
/// canonical wire-format reference at `docs/formats/asset/bulk-data.md`.
///
/// The newtype wraps the raw `u32` from the wire. Construction is via
/// [`From<u32>`] (`BulkDataFlags::from(raw_u32)`) — the inner field is
/// private to prevent callers bypassing [`Self::validate`] by
/// constructing arbitrary bit patterns with a tuple-constructor. This
/// mirrors the [`crate::Sha1Digest`] private-field convention.
///
/// Bits 19-27 and bit 31 are reserved; [`Self::validate`] rejects them.
///
/// `serde::Serialize` is derived so `Asset::*` variants carrying
/// flags (3e/3g/3h typed readers) get clean JSON output via the
/// existing externally-tagged serialization.
///
/// **Naming note:** the engine bit `BULKDATA_PayloadInSeperateFile`
/// preserves a wire-source typo (`Seperate`). The Rust API uses
/// the corrected English spelling on accessors for readability;
/// the constant `FLAG_PAYLOAD_IN_SEPARATE_FILE` follows the same
/// convention. The wire-source spelling is documented on the
/// accessor to keep grepping engine sources tractable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub struct BulkDataFlags(u32);

impl From<u32> for BulkDataFlags {
    fn from(raw: u32) -> Self {
        Self(raw)
    }
}

// Named-bit constants. The flags are documented in
// `docs/formats/texture/mips-and-streaming.md` §BulkDataFlags. The
// engine source preserves the `Seperate` typo on bit 8; the Rust
// constant follows English conventions for consistency with the
// accessor method name.
//
// `#[allow(dead_code)]`: each constant is pinned by
// `flag_constants_pin_expected_values`, so `#[expect]` would falsely
// fire under test cfg.
const FLAG_PAYLOAD_AT_END_OF_FILE: u32 = 0x0000_0001;
const FLAG_SERIALIZE_COMPRESSED_ZLIB: u32 = 0x0000_0002;
#[allow(
    dead_code,
    reason = "documented bit catalog; not all accessors live yet"
)]
const FLAG_FORCE_SINGLE_ELEMENT: u32 = 0x0000_0004;
#[allow(
    dead_code,
    reason = "documented bit catalog; not all accessors live yet"
)]
const FLAG_SINGLE_USE: u32 = 0x0000_0008;
const FLAG_COMPRESSED_LZO: u32 = 0x0000_0010;
#[allow(
    dead_code,
    reason = "documented bit catalog; not all accessors live yet"
)]
const FLAG_UNUSED: u32 = 0x0000_0020;
#[allow(
    dead_code,
    reason = "documented bit catalog; not all accessors live yet"
)]
const FLAG_FORCE_INLINE_PAYLOAD: u32 = 0x0000_0040;
#[allow(
    dead_code,
    reason = "documented bit catalog; not all accessors live yet"
)]
const FLAG_FORCE_STREAM_PAYLOAD: u32 = 0x0000_0080;
const FLAG_PAYLOAD_IN_SEPARATE_FILE: u32 = 0x0000_0100;
const FLAG_SERIALIZE_COMPRESSED_BITWINDOW: u32 = 0x0000_0200;
#[allow(
    dead_code,
    reason = "documented bit catalog; not all accessors live yet"
)]
const FLAG_FORCE_NOT_INLINE: u32 = 0x0000_0400;
const FLAG_OPTIONAL_PAYLOAD: u32 = 0x0000_0800;
#[allow(
    dead_code,
    reason = "documented bit catalog; not all accessors live yet"
)]
const FLAG_MEMORY_MAPPED: u32 = 0x0000_1000;
const FLAG_SIZE_64_BIT: u32 = 0x0000_2000;
const FLAG_DUPLICATE_NON_OPTIONAL: u32 = 0x0000_4000;
const FLAG_BAD_DATA_VERSION: u32 = 0x0000_8000;
const FLAG_NO_OFFSET_FIXUP: u32 = 0x0001_0000;
#[allow(
    dead_code,
    reason = "documented bit catalog; not all accessors live yet"
)]
const FLAG_WORKSPACE_DOMAIN: u32 = 0x0002_0000;
#[allow(
    dead_code,
    reason = "documented bit catalog; not all accessors live yet"
)]
const FLAG_LAZY_LOADABLE: u32 = 0x0004_0000;
#[allow(
    dead_code,
    reason = "documented bit catalog; not all accessors live yet"
)]
const FLAG_ALWAYS_ALLOW_DISCARD: u32 = 0x1000_0000;
#[allow(
    dead_code,
    reason = "documented bit catalog; not all accessors live yet"
)]
const FLAG_HAS_ASYNC_READ_PENDING: u32 = 0x2000_0000;
#[allow(
    dead_code,
    reason = "documented bit catalog; not all accessors live yet"
)]
const FLAG_DATA_IS_MEMORY_MAPPED: u32 = 0x4000_0000;

/// Mask of every documented allocated bit (bits 0-18 + 28-30).
/// Bits 19-27 and bit 31 are reserved and trigger
/// `UnknownBulkDataFlags` in [`BulkDataFlags::validate`].
const VALID_FLAG_MASK: u32 = 0x7007_FFFF;

impl BulkDataFlags {
    /// `BULKDATA_PayloadAtEndOfFile` (bit 0). When set, the payload
    /// lives in the parent file (`.uasset` for inline,
    /// `.uexp` for uexp-resident; tier disambiguated by offset).
    #[must_use]
    pub fn payload_at_end_of_file(self) -> bool {
        (self.0 & FLAG_PAYLOAD_AT_END_OF_FILE) != 0
    }

    /// `BULKDATA_PayloadInSeperateFile` (bit 8, preserves the
    /// wire-source typo). When set, the payload lives in `.ubulk`
    /// (or `.uptnl` if `BULKDATA_OptionalPayload` is also set).
    #[must_use]
    pub fn payload_in_separate_file(self) -> bool {
        (self.0 & FLAG_PAYLOAD_IN_SEPARATE_FILE) != 0
    }

    /// `BULKDATA_OptionalPayload` (bit 11). Routes
    /// `payload_in_separate_file` records to `.uptnl` instead of
    /// `.ubulk`. The wire format requires
    /// `payload_in_separate_file` to also be set when this is on.
    #[must_use]
    pub fn optional_payload(self) -> bool {
        (self.0 & FLAG_OPTIONAL_PAYLOAD) != 0
    }

    /// `BULKDATA_NoOffsetFixUp` (bit 16). When set, `OffsetInFile`
    /// is used directly; when unset, the reader MUST add
    /// `PackageSummary::bulk_data_start_offset` to get the actual
    /// in-file position.
    #[must_use]
    pub fn no_offset_fixup(self) -> bool {
        (self.0 & FLAG_NO_OFFSET_FIXUP) != 0
    }

    /// `BULKDATA_Size64Bit` (bit 13). Widens `ElementCount` and
    /// `SizeOnDisk` from 4-byte fields to 8-byte fields on the
    /// wire.
    #[must_use]
    pub fn size_64_bit(self) -> bool {
        (self.0 & FLAG_SIZE_64_BIT) != 0
    }

    /// `BULKDATA_SerializeCompressedZLIB` (bit 1). Payload is
    /// zlib-compressed; the resolver must decompress after
    /// fetching `SizeOnDisk` bytes.
    #[must_use]
    pub fn is_zlib_compressed(self) -> bool {
        (self.0 & FLAG_SERIALIZE_COMPRESSED_ZLIB) != 0
    }

    /// `BULKDATA_CompressedLZO` (bit 4). LZO compression is rare in
    /// cooked content; the resolver rejects with
    /// `UnsupportedBulkCompression`. Phase 3 follow-up: surface a
    /// fixture and add an LZO decoder.
    #[must_use]
    pub fn is_lzo_compressed(self) -> bool {
        (self.0 & FLAG_COMPRESSED_LZO) != 0
    }

    /// `BULKDATA_SerializeCompressedBitWindow` (bit 9). Custom
    /// bit-window compression. The resolver rejects with
    /// `UnsupportedBulkCompression`.
    #[must_use]
    pub fn is_bitwindow_compressed(self) -> bool {
        (self.0 & FLAG_SERIALIZE_COMPRESSED_BITWINDOW) != 0
    }

    /// `BULKDATA_DuplicateNonOptionalPayload` (bit 14). When set,
    /// additional duplicate-flags + duplicate-size + duplicate-offset
    /// fields follow `OffsetInFile` on the wire. The duplicate is a
    /// redundancy mechanism — the reader consumes its bytes but the
    /// resolver uses the primary record's offset.
    #[must_use]
    pub fn has_duplicate_non_optional(self) -> bool {
        (self.0 & FLAG_DUPLICATE_NON_OPTIONAL) != 0
    }

    /// `BULKDATA_BadDataVersion` (bit 15). When set, an extra 2-byte
    /// ushort follows `OffsetInFile`; the reader discards it and
    /// clears the flag. Sentinel for older bad-data records.
    #[must_use]
    pub fn has_bad_data_version(self) -> bool {
        (self.0 & FLAG_BAD_DATA_VERSION) != 0
    }

    /// Reject any bits outside the documented catalog (bits 19-27
    /// or bit 31). Returns the raw fault — callers wrap with their
    /// asset path via `PaksmithError::AssetParse { asset_path, fault }`.
    ///
    /// Returning the fault (not the full `PaksmithError`) avoids the
    /// "construct an empty asset_path and ask the caller to replace"
    /// pattern from earlier phases. The caller has the path on hand
    /// and wraps once at the call site.
    ///
    /// # Errors
    /// [`crate::error::AssetParseFault::UnknownBulkDataFlags`] when any
    /// reserved bit is set.
    pub fn validate(self) -> Result<(), crate::error::AssetParseFault> {
        let unknown_bits = self.0 & !VALID_FLAG_MASK;
        if unknown_bits != 0 {
            return Err(crate::error::AssetParseFault::UnknownBulkDataFlags { bits: self.0 });
        }
        Ok(())
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

    // BulkDataFlags accessor + validate tests. Each test isolates
    // exactly one bit pattern so a regression on any single accessor
    // surfaces independently. Hex literals match the bit catalog in
    // `docs/formats/texture/mips-and-streaming.md` §BulkDataFlags.

    #[test]
    fn flags_payload_at_end_of_file_detected() {
        let f = BulkDataFlags::from(0x0000_0001);
        assert!(f.payload_at_end_of_file());
        assert!(!f.payload_in_separate_file());
        assert!(!f.size_64_bit());
    }

    #[test]
    fn flags_payload_in_separate_file_detected() {
        let f = BulkDataFlags::from(0x0000_0100);
        assert!(!f.payload_at_end_of_file());
        assert!(f.payload_in_separate_file());
    }

    #[test]
    fn flags_size_64_bit_detected() {
        let f = BulkDataFlags::from(0x0000_2000);
        assert!(f.size_64_bit());
    }

    #[test]
    fn flags_zlib_compressed_detected() {
        let f = BulkDataFlags::from(0x0000_0002);
        assert!(f.is_zlib_compressed());
        assert!(!f.is_lzo_compressed());
        assert!(!f.is_bitwindow_compressed());
    }

    #[test]
    fn flags_lzo_compressed_detected() {
        let f = BulkDataFlags::from(0x0000_0010);
        assert!(!f.is_zlib_compressed());
        assert!(f.is_lzo_compressed());
        assert!(!f.is_bitwindow_compressed());
    }

    #[test]
    fn flags_bitwindow_compressed_detected() {
        let f = BulkDataFlags::from(0x0000_0200);
        assert!(!f.is_zlib_compressed());
        assert!(!f.is_lzo_compressed());
        assert!(f.is_bitwindow_compressed());
    }

    #[test]
    fn flags_optional_payload_detected() {
        let f = BulkDataFlags::from(0x0000_0800);
        assert!(f.optional_payload());
    }

    #[test]
    fn flags_no_offset_fixup_detected() {
        let f = BulkDataFlags::from(0x0001_0000);
        assert!(f.no_offset_fixup());
    }

    #[test]
    fn flags_duplicate_non_optional_detected() {
        let f = BulkDataFlags::from(0x0000_4000);
        assert!(f.has_duplicate_non_optional());
    }

    #[test]
    fn flags_bad_data_version_detected() {
        let f = BulkDataFlags::from(0x0000_8000);
        assert!(f.has_bad_data_version());
    }

    #[test]
    fn flags_validate_rejects_reserved_bit_19() {
        // Bit 19 is reserved per the catalog.
        let f = BulkDataFlags::from(0x0008_0000);
        match f.validate() {
            Err(crate::error::AssetParseFault::UnknownBulkDataFlags { bits }) => {
                assert_eq!(bits, 0x0008_0000);
            }
            other => panic!("expected UnknownBulkDataFlags, got {other:?}"),
        }
    }

    #[test]
    fn flags_validate_rejects_reserved_bit_31() {
        // Bit 31 (0x8000_0000) is reserved.
        let f = BulkDataFlags::from(0x8000_0000);
        assert!(matches!(
            f.validate(),
            Err(crate::error::AssetParseFault::UnknownBulkDataFlags { bits: 0x8000_0000 }),
        ));
    }

    #[test]
    fn flags_validate_accepts_all_documented_bits() {
        // Bits 0-18 + 28-30 are all allocated per the catalog. The
        // mask 0x7007_FFFF must accept the maximum-valid pattern.
        let allocated: u32 = 0x7007_FFFF;
        let f = BulkDataFlags::from(allocated);
        assert!(f.validate().is_ok());
    }

    #[test]
    fn flags_validate_accepts_zero() {
        // An all-zeros flag word has no reserved bits set; validate()
        // is concerned with reserved-bit rejection, NOT with tier
        // routing (that's BulkDataNoTierFlag, fired elsewhere).
        let f = BulkDataFlags::from(0x0000_0000);
        assert!(f.validate().is_ok());
    }

    #[test]
    fn flag_constants_pin_expected_values() {
        // Pins every `FLAG_*` constant + `VALID_FLAG_MASK` to its
        // documented bit position. Kills cargo-mutants arithmetic
        // mutations on the bit-shift expressions AND catches
        // accidental wide-value typos (e.g. `0x1000_1000` instead
        // of `0x0000_1000`) that would slip past the mask check
        // because the typo'd bit happens to be in the valid range.
        // Catalog source: `docs/formats/texture/mips-and-streaming.md`
        // §BulkDataFlags.
        assert_eq!(FLAG_PAYLOAD_AT_END_OF_FILE, 0x0000_0001);
        assert_eq!(FLAG_SERIALIZE_COMPRESSED_ZLIB, 0x0000_0002);
        assert_eq!(FLAG_FORCE_SINGLE_ELEMENT, 0x0000_0004);
        assert_eq!(FLAG_SINGLE_USE, 0x0000_0008);
        assert_eq!(FLAG_COMPRESSED_LZO, 0x0000_0010);
        assert_eq!(FLAG_UNUSED, 0x0000_0020);
        assert_eq!(FLAG_FORCE_INLINE_PAYLOAD, 0x0000_0040);
        assert_eq!(FLAG_FORCE_STREAM_PAYLOAD, 0x0000_0080);
        assert_eq!(FLAG_PAYLOAD_IN_SEPARATE_FILE, 0x0000_0100);
        assert_eq!(FLAG_SERIALIZE_COMPRESSED_BITWINDOW, 0x0000_0200);
        assert_eq!(FLAG_FORCE_NOT_INLINE, 0x0000_0400);
        assert_eq!(FLAG_OPTIONAL_PAYLOAD, 0x0000_0800);
        assert_eq!(FLAG_MEMORY_MAPPED, 0x0000_1000);
        assert_eq!(FLAG_SIZE_64_BIT, 0x0000_2000);
        assert_eq!(FLAG_DUPLICATE_NON_OPTIONAL, 0x0000_4000);
        assert_eq!(FLAG_BAD_DATA_VERSION, 0x0000_8000);
        assert_eq!(FLAG_NO_OFFSET_FIXUP, 0x0001_0000);
        assert_eq!(FLAG_WORKSPACE_DOMAIN, 0x0002_0000);
        assert_eq!(FLAG_LAZY_LOADABLE, 0x0004_0000);
        assert_eq!(FLAG_ALWAYS_ALLOW_DISCARD, 0x1000_0000);
        assert_eq!(FLAG_HAS_ASYNC_READ_PENDING, 0x2000_0000);
        assert_eq!(FLAG_DATA_IS_MEMORY_MAPPED, 0x4000_0000);
        assert_eq!(VALID_FLAG_MASK, 0x7007_FFFF);
    }
}
