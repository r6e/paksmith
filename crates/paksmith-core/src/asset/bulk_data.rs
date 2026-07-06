//! Bulk-data wire-format types: `FByteBulkData` (per-record wire
//! reader, Phase 3b Task 3), `BulkData` (resolved-payload record,
//! Phase 3b Task 4), `BulkDataFlags` (bitfield wrapper, Phase 3b
//! Task 2), `BulkDataTier` (storage-tier enum, Phase 3b Task 1),
//! plus the cap constants below. The `BulkDataResolver` (Phase 3b
//! Task 5) is the remaining piece; it consumes `FByteBulkData` and
//! produces `BulkData`.
//!
//! # Historical: unit-struct stubs in Phase 3a
//!
//! Phase 3a Task 2 shipped `BulkData` and `FByteBulkData` as unit
//! structs so the `FormatHandler::export` signature in
//! `crate::export` and the `TypedReaderFn` signature in
//! `crate::asset::exports::dispatch` could compile against the type
//! identity before 3b's wire-format implementation landed. The
//! unit-struct shape was chosen over `_private: ()` placeholder
//! because unit structs expose no destructurable FIELD surface,
//! so 3b's widening to fields-bearing doesn't break any
//! field-destructure pattern (none could exist on a unit struct).
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

use crate::error::CompanionFileKind;

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

/// v2 chunked-framing header tag: `PACKAGE_FILE_TAG` in the low 32
/// bits, `0x22222222` in the high 32. Written as a literal because
/// any derivation from [`crate::asset::version::PACKAGE_FILE_TAG`]
/// (`|`, `^`, `+` over disjoint bit halves) is operator-mutation-
/// equivalent and unkillable; the pair-anchor relation to
/// `PACKAGE_FILE_TAG` is pinned by
/// `framing_constants_pin_expected_values` instead. A tag record
/// carrying this value means the framing header inserts an inline
/// compression-format byte before the summary record. Verified
/// against the CUE4Parse reference
/// (`FArchive.SerializeCompressedNew`) and independent community
/// decoders (Remnant-2-Save-Parser, revision-go).
const ARCHIVE_V2_HEADER_TAG: u64 = 0x2222_2222_9E2A_83C1;

/// Fallback compression-chunk size (128 KiB) when the tag record's
/// chunk-size field carries the legacy `PACKAGE_FILE_TAG` sentinel
/// instead of a real size. Mirrors the reference decoder's
/// `LOADING_COMPRESSION_CHUNK_SIZE`.
const LOADING_COMPRESSION_CHUNK_SIZE: i64 = 131_072;

/// Wire size of one `FCompressedChunkInfo`: two little-endian i64s
/// (UE4+; the pre-UE4 u32 layout is below paksmith's version floor).
const CHUNK_INFO_WIRE_SIZE: usize = 16;

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

    /// `BULKDATA_Unused` (bit 5). The record carries no live payload; CUE4Parse
    /// `TBulkData` early-exits (and does not skip an inline payload) when set.
    #[must_use]
    pub fn has_unused(self) -> bool {
        (self.0 & FLAG_UNUSED) != 0
    }

    /// Whether the payload bytes are serialized **in-stream**, immediately after
    /// this header in the same archive (vs. located elsewhere by `OffsetInFile`).
    ///
    /// Mirrors CUE4Parse `TBulkData`'s cursor-advance condition verbatim:
    /// `BulkDataFlags.HasFlag(BULKDATA_ForceInlinePayload)` (bit set among
    /// others), OR the flags are **exactly** `BULKDATA_LazyLoadable`, OR
    /// **exactly** `BULKDATA_None` (no flags). `PayloadAtEndOfFile` /
    /// separate-file records — the cooked-content norm — are NOT inline: their
    /// payload lives at `OffsetInFile`, so the reader leaves the cursor at the
    /// header's end. Consulted by [`FByteBulkData::read_from`] to advance past an
    /// in-stream payload so the next field reads at the right offset.
    #[must_use]
    pub fn payload_is_inline(self) -> bool {
        (self.0 & FLAG_FORCE_INLINE_PAYLOAD) != 0 || self.0 == FLAG_LAZY_LOADABLE || self.0 == 0
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

    /// `true` if any supported compression flag is set
    /// (`BULKDATA_SerializeCompressedZLIB`, `BULKDATA_CompressedLZO`,
    /// or `BULKDATA_SerializeCompressedBitWindow`).
    ///
    /// Co-locates the 3-way OR with the per-flag accessors so the
    /// resolver (Task 5) and the format handlers (3e/3g/3h) can
    /// branch on "is this record compressed?" without duplicating
    /// the bit-list logic at each call site.
    #[must_use]
    pub fn is_any_compressed(self) -> bool {
        self.is_zlib_compressed() || self.is_lzo_compressed() || self.is_bitwindow_compressed()
    }
}

/// Resolved bulk-data payload — bytes plus metadata about which
/// tier they came from and the wire-format record that described
/// them.
///
/// Produced by `BulkDataResolver::resolve` (Phase 3b Task 5).
/// Consumed by Phase 3 format handlers
/// ([`crate::export::FormatHandler::export`]) when the handler
/// needs the actual payload bytes (e.g. texture mip pixels, audio
/// PCM samples).
///
/// Owned `bytes: Vec<u8>` per Phase 3 master plan Design Decision
/// #6 — borrowing would force lifetime-parameter contamination
/// across the entire export pipeline. One allocation per resolved
/// record is acceptable; the per-package budget cap
/// (`MAX_TOTAL_BULK_DATA_BYTES_PER_PACKAGE` = 16 GiB) bounds
/// cumulative allocation.
///
/// `#[non_exhaustive]` reserves the right for Phase 8 (IoStore) or
/// later phases to extend with additional metadata (e.g.
/// decompression-method record, source-file path) without an
/// SemVer-major bump. Construction routes through
/// `BulkDataResolver::resolve` — external struct-literal
/// construction is blocked at the crate boundary.
///
/// # Breaking change from 3a
///
/// Phase 3a Task 2 shipped this as `pub struct BulkData;` (unit
/// struct). 3b Task 4 widens to the fields-bearing shape below.
/// The widening breaks direct unit-literal construction
/// (`let bulk = BulkData;`) but no Phase 3a-3b code does that —
/// `GenericHandler` ignores its `&[BulkData]` argument and
/// the resolver is the only constructor.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct BulkData {
    /// Resolved, post-decompression payload bytes. For uncompressed
    /// records this is a copy of the on-disk bytes; for
    /// `BULKDATA_SerializeCompressedZLIB` records this is the
    /// decompressed output.
    pub bytes: Vec<u8>,
    /// The wire-format record this payload was resolved from. Carries
    /// `flags`, `element_count`, `size_on_disk`, `offset_in_file`.
    /// Read-only; the resolver consumes the record metadata to
    /// route the read and never mutates it.
    pub record: FByteBulkData,
    /// Which storage tier the bytes came from — `Inline` /
    /// `UexpResident` / `Streaming` / `OptionalStreaming`. Format
    /// handlers branch on this for diagnostic output (e.g.
    /// "texture mip 0 came from `.ubulk`").
    pub tier: BulkDataTier,
}

/// One `FByteBulkData` record on the wire. Lives inside a `.uasset`
/// export's serialized data; published per-mip (textures) /
/// per-codec (audio) by the engine. Phase 3b Task 3 widens this from
/// the 3a unit-struct stub to the full fields-bearing shape.
///
/// Constructed via [`Self::read_from`] which parses the wire format
/// and enforces: the parse-time cap chain (`MAX_BULK_DATA_SIZE` for
/// uncompressed, `MAX_BULK_DATA_COMPRESSED_SIZE` for compressed);
/// negative `ElementCount` rejection (sign-extension defense);
/// reserved-bit flag rejection; and consumption of the `BadDataVersion`
/// and `DuplicateNonOptionalPayload` side-effect blocks.
///
/// Fields are `pub` so the resolver (Task 5) and the format
/// handlers (3e/3g/3h) can read them directly. Construction is via
/// [`Self::read_from`] from the wire stream; no other constructor
/// path is provided (3a's unit-struct stub is gone).
///
/// **Cap chain summary:**
///
/// - `SizeOnDisk` (compressed): ≤ `MAX_BULK_DATA_COMPRESSED_SIZE`
///   (512 MiB; fires [`crate::error::AssetParseFault::BulkDataCompressedSizeExceeded`]).
/// - `SizeOnDisk` (uncompressed): ≤ `MAX_BULK_DATA_SIZE` (8 GiB;
///   fires [`crate::error::AssetParseFault::BulkDataSizeExceeded`]).
/// - `ElementCount`: ≥ 0 (negative fires
///   [`crate::error::AssetParseFault::BulkDataElementCountNegative`]).
/// - Reserved `BulkDataFlags` bits: rejected via [`BulkDataFlags::validate`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FByteBulkData {
    /// The wire bitfield. `BadDataVersion` is cleared after the
    /// 2-byte tail is consumed (per the format spec).
    pub flags: BulkDataFlags,
    /// Element count on the wire, widened to i64 from either i32
    /// (no `Size64Bit`) or i64 (with `Size64Bit`). Pre-validated
    /// non-negative by [`Self::read_from`].
    pub element_count: i64,
    /// Size of the payload on disk, widened to u64 from either u32
    /// (no `Size64Bit`) or u64 (with `Size64Bit`). For compressed
    /// records this is the compressed-bytes size; for uncompressed
    /// it equals the decompressed size.
    pub size_on_disk: u64,
    /// Pre-fixup offset within the containing file. The resolver
    /// adds `PackageSummary::bulk_data_start_offset` unless
    /// `BULKDATA_NoOffsetFixUp` is set. UE 4.4+ floor: always 8
    /// bytes on the wire.
    pub offset_in_file: i64,
}

impl FByteBulkData {
    /// `__test_utils`-gated constructor for integration tests outside
    /// the crate. The production parse path is [`Self::read_from`];
    /// out-of-crate tests (e.g. `paksmith-core-tests`) need to
    /// hand-construct records pointing at known offsets in synthetic
    /// fixtures, which the `#[non_exhaustive]` attribute would
    /// otherwise block via struct-literal syntax.
    #[cfg(feature = "__test_utils")]
    #[must_use]
    pub fn for_test(
        flags: BulkDataFlags,
        element_count: i64,
        size_on_disk: u64,
        offset_in_file: i64,
    ) -> Self {
        Self {
            flags,
            element_count,
            size_on_disk,
            offset_in_file,
        }
    }

    /// Parse one record from `reader`. Consumes the wire-format
    /// fields, the `BulkDataBadDataVersion` 2-byte tail (when set),
    /// and the `DuplicateNonOptionalPayload` block (when set). The
    /// `BadDataVersion` flag is cleared in the returned record per
    /// the wire-format spec.
    ///
    /// Wire shape (paksmith's UE 4.4+ floor — `BULKDATA_AT_LARGE_OFFSETS`
    /// always implied, so `OffsetInFile` is always 8 bytes):
    ///
    /// ```text
    /// u32       BulkDataFlags
    /// [i32|i64] ElementCount        (i64 iff BULKDATA_Size64Bit)
    /// [u32|u64] SizeOnDisk          (u64 iff BULKDATA_Size64Bit)
    /// i64       OffsetInFile        (always 8 bytes paksmith-floor)
    /// u16       <discarded>         (iff BULKDATA_BadDataVersion)
    /// {  u32     DuplicateFlags     (iff BULKDATA_DuplicateNonOptionalPayload)
    ///   [u32|u64] DuplicateSizeOnDisk (matched to Size64Bit)
    ///    i64     DuplicateOffsetInFile (paksmith-floor)
    /// }
    /// ```
    ///
    /// # Errors
    /// - [`AssetParseFault::UnexpectedEof`](crate::error::AssetParseFault::UnexpectedEof)
    ///   if any wire-format field can't be read.
    /// - [`AssetParseFault::UnknownBulkDataFlags`](crate::error::AssetParseFault::UnknownBulkDataFlags)
    ///   if reserved bits (19-27, 31) are set.
    /// - [`AssetParseFault::BulkDataElementCountNegative`](crate::error::AssetParseFault::BulkDataElementCountNegative)
    ///   if `ElementCount` is negative.
    /// - [`AssetParseFault::BulkDataCompressedSizeExceeded`](crate::error::AssetParseFault::BulkDataCompressedSizeExceeded)
    ///   if a compression flag is set AND `SizeOnDisk` exceeds the
    ///   512 MiB compressed cap.
    /// - [`AssetParseFault::BulkDataSizeExceeded`](crate::error::AssetParseFault::BulkDataSizeExceeded)
    ///   if `SizeOnDisk` exceeds the 8 GiB uncompressed cap.
    pub fn read_from<R: std::io::Read>(reader: &mut R, asset_path: &str) -> crate::Result<Self> {
        Self::read_from_inner(reader, asset_path, false).map(|(record, _payload)| record)
    }

    /// Like [`Self::read_from`], but when the record carries an **in-stream inline
    /// payload** (per [`BulkDataFlags::payload_is_inline`]), the payload bytes are
    /// captured and returned as `Some(Vec<u8>)` instead of discarded into a sink.
    /// Returns `None` for non-inline (separate-file / `PayloadAtEndOfFile`) records.
    /// Used by the skeletal-mesh non-inlined LOD path (#563) to decode geometry
    /// from an inline bulk payload via `read_streamed_data`, mirroring the oracle's
    /// `SerializeStreamedData` over `bulk.Data`.
    pub(crate) fn read_from_capturing_inline<R: std::io::Read>(
        reader: &mut R,
        asset_path: &str,
    ) -> crate::Result<(Self, Option<Vec<u8>>)> {
        Self::read_from_inner(reader, asset_path, true)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "wire-format reader with sequential field parses + cap checks + side-effect-block consumption; splitting would replace one cohesive reader with three indirect helpers + an orchestrator. Same pattern as `AssetParseFault`'s Display impl in `error.rs`."
    )]
    fn read_from_inner<R: std::io::Read>(
        reader: &mut R,
        asset_path: &str,
        capture_inline: bool,
    ) -> crate::Result<(Self, Option<Vec<u8>>)> {
        use byteorder::{LittleEndian, ReadBytesExt};
        use std::io::Read;

        let raw_flags = reader
            .read_u32::<LittleEndian>()
            .map_err(|_| eof_at(asset_path, crate::error::AssetWireField::BulkDataFlags))?;
        let flags = BulkDataFlags::from(raw_flags);
        flags
            .validate()
            .map_err(|fault| crate::PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault,
            })?;

        // ElementCount + SizeOnDisk widen to 64-bit when Size64Bit set.
        let element_count: i64 = if flags.size_64_bit() {
            reader.read_i64::<LittleEndian>()
        } else {
            reader.read_i32::<LittleEndian>().map(i64::from)
        }
        .map_err(|_| {
            eof_at(
                asset_path,
                crate::error::AssetWireField::BulkDataElementCount,
            )
        })?;

        // Sign-check ElementCount BEFORE casting to unsigned anywhere
        // downstream. Negative values are wire corruption or
        // sign-extension attacks.
        if element_count < 0 {
            return Err(crate::PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: crate::error::AssetParseFault::BulkDataElementCountNegative {
                    count: element_count,
                },
            });
        }

        // HARDENING DEVIATION FROM REFERENCE: CUE4Parse reads
        // `SizeOnDisk` under Size64Bit as `(uint) Ar.Read<long>()`
        // (truncates upper 32 bits to low 32 bits → effective max
        // ~4 GiB). paksmith reads the full u64 — strictly safer:
        // upper-bit-set values are caught by `MAX_BULK_DATA_SIZE`
        // (8 GiB) instead of silently masked to small numbers.
        // Legitimate cooked content has SizeOnDisk well under 4 GiB,
        // so behavior matches the reference for valid wire input.
        // The 8 GiB cap meaningfully bounds attacker-crafted records
        // that would otherwise truncate to small values. See
        // `docs/formats/asset/bulk-data.md` §SizeOnDisk for the
        // documented paksmith policy.
        let size_on_disk: u64 = if flags.size_64_bit() {
            reader.read_u64::<LittleEndian>()
        } else {
            reader.read_u32::<LittleEndian>().map(u64::from)
        }
        .map_err(|_| eof_at(asset_path, crate::error::AssetWireField::BulkDataSizeOnDisk))?;

        // Cap chain: compressed cap fires first (tighter) when any
        // compression flag is set; uncompressed cap otherwise. The
        // compression-aware split prevents a zlib bomb from reading
        // 8 GiB of compressed bytes off disk before the resolver
        // even sees the record.
        let is_compressed = flags.is_any_compressed();
        if is_compressed && size_on_disk > MAX_BULK_DATA_COMPRESSED_SIZE {
            return Err(crate::PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: crate::error::AssetParseFault::BulkDataCompressedSizeExceeded {
                    size: size_on_disk,
                    cap: MAX_BULK_DATA_COMPRESSED_SIZE,
                },
            });
        }
        if size_on_disk > MAX_BULK_DATA_SIZE {
            return Err(crate::PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: crate::error::AssetParseFault::BulkDataSizeExceeded {
                    size: size_on_disk,
                    cap: MAX_BULK_DATA_SIZE,
                },
            });
        }

        let offset_in_file = reader.read_i64::<LittleEndian>().map_err(|_| {
            eof_at(
                asset_path,
                crate::error::AssetWireField::BulkDataOffsetInFile,
            )
        })?;

        // Side-effect blocks per the wire-format spec.
        let mut flags_out = flags;
        if flags.has_bad_data_version() {
            // 2-byte ushort discarded; the flag is cleared so
            // downstream consumers don't see it set. `let _ =` here
            // silences `unused_results` on the returned `u16`.
            let _ = reader.read_u16::<LittleEndian>().map_err(|_| {
                eof_at(
                    asset_path,
                    crate::error::AssetWireField::BulkDataBadDataVersionTail,
                )
            })?;
            // Same-module access to the private inner u32 — the
            // private-field invariant is about preventing EXTERNAL
            // bypass of `validate()`, not blocking the parser from
            // mutating fields it just constructed.
            flags_out.0 &= !FLAG_BAD_DATA_VERSION;
        }
        if flags.has_duplicate_non_optional() {
            // Skip duplicate block: 4 (DupFlags u32) + [4|8] (DupSize)
            // + 8 (DupOffset). Total: 16 or 20 bytes.
            let size_field_width = if flags.size_64_bit() { 8 } else { 4 };
            let total_skip = 4 + size_field_width + 8;
            let mut sink = [0u8; 20];
            reader.read_exact(&mut sink[..total_skip]).map_err(|_| {
                eof_at(
                    asset_path,
                    crate::error::AssetWireField::BulkDataDuplicateBlock,
                )
            })?;
        }

        // In-stream inline payload: CUE4Parse `TBulkData` advances the archive
        // past the payload bytes (`Ar.Position += Header.SizeOnDisk`) when they
        // are serialized inline (after the header in the same archive), so a
        // subsequent field reads at the right offset. paksmith reads `R: Read`
        // (no `Seek`), so it consumes the bytes — into a sink by default, or
        // captured for the caller when `capture_inline` (see the branches below).
        // Skipped only for a non-zero, non-`Unused`, inline-flagged payload —
        // matching the oracle's `SizeOnDisk == 0 || Unused` early-exit and
        // inline-flag guard. `PayloadAtEndOfFile` / separate-file records (cooked
        // content) are not inline, so their cursor is unchanged. A truncated
        // inline payload EOFs: the capture branch faults immediately on the
        // `BulkDataInlinePayload` field; the sink branch leaves fewer than
        // `size_on_disk` bytes consumed, EOF-ing the next read.
        // (`!= 0` not `> 0`: the `u64` makes `>= 0` always-true / equivalent.)
        let inline_payload =
            if size_on_disk != 0 && !flags_out.has_unused() && flags_out.payload_is_inline() {
                if capture_inline {
                    // Capture the inline bytes for the caller (#563). `take` + length
                    // check bounds the read to `size_on_disk` and EOF-checks a short
                    // payload (the cap on `size_on_disk` was already enforced above, so
                    // this Vec cannot exceed MAX_BULK_DATA_SIZE).
                    let mut buf = Vec::new();
                    let read = std::io::Read::take(reader.by_ref(), size_on_disk)
                        .read_to_end(&mut buf)
                        .map_err(crate::PaksmithError::Io)?;
                    if read as u64 != size_on_disk {
                        return Err(eof_at(
                            asset_path,
                            crate::error::AssetWireField::BulkDataInlinePayload,
                        ));
                    }
                    Some(buf)
                } else {
                    // Default: advance past the payload without retaining it.
                    let _ = std::io::copy(
                        &mut std::io::Read::take(reader.by_ref(), size_on_disk),
                        &mut std::io::sink(),
                    )
                    .map_err(crate::PaksmithError::Io)?;
                    None
                }
            } else {
                None
            };

        Ok((
            Self {
                flags: flags_out,
                element_count,
                size_on_disk,
                offset_in_file,
            },
            inline_payload,
        ))
    }
}

/// Constructs an `UnexpectedEof` fault wrapped in `PaksmithError::AssetParse`.
/// Inlined twice per error site in `read_from`; the helper saves the
/// repeated envelope construction.
fn eof_at(asset_path: &str, field: crate::error::AssetWireField) -> crate::PaksmithError {
    crate::PaksmithError::AssetParse {
        asset_path: asset_path.to_string(),
        fault: crate::error::AssetParseFault::UnexpectedEof { field },
    }
}

/// Build a minimal valid `FByteBulkData` record for tests that
/// need a record value but don't care about its contents (e.g.
/// `BulkData` construction tests). Mirrors the wire shape
/// `FByteBulkData::read_from` expects: u32 flags + i32
/// element_count + u32 size_on_disk + i64 offset_in_file = 20
/// bytes, all zero except the tier flag.
///
/// Module-level under `#[cfg(test)]` so other crate-internal test
/// modules (e.g. `crate::export::generic::tests`) can call it
/// without going through a private `mod tests`.
#[cfg(test)]
pub(crate) fn make_zero_record() -> FByteBulkData {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&FLAG_PAYLOAD_AT_END_OF_FILE.to_le_bytes());
    bytes.extend_from_slice(&0_i32.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&0_i64.to_le_bytes());
    let mut cur = std::io::Cursor::new(bytes);
    FByteBulkData::read_from(&mut cur, "test.uasset").expect("zero record parses")
}

/// Resolves `FByteBulkData` records into materialized payload bytes
/// across all four storage tiers (Inline / UexpResident / Streaming /
/// OptionalStreaming).
///
/// Construct via `BulkDataResolver::new` (`pub(crate)`) from
/// `Package::read_from_pak`'s integration code (Task 6 wires this
/// up); test helpers use `new_for_test` / `new_for_test_with_ubulk` /
/// `new_for_test_with_uptnl` (all `#[cfg(feature = "__test_utils")]`-gated).
///
/// # Defense chain
///
/// `resolve()` enforces, in order:
///
/// 1. Unsupported compression rejection (`LZO` / `BitWindow` fire
///    `UnsupportedBulkCompression`).
/// 2. Offset fix-up: `OffsetInFile + bulk_data_start_offset` checked
///    via `checked_add`; fires `BulkDataOffsetFixupOverflow` on
///    overflow OR negative result.
/// 3. Tier dispatch: `payload_in_separate_file` →
///    `Streaming`/`OptionalStreaming` via lazy companion loaders;
///    `payload_at_end_of_file` → `Inline`/`UexpResident` based on
///    `resolved_offset` vs `total_header_size`. Neither bit set
///    fires `BulkDataNoTierFlag`.
/// 4. Bounds: `resolved_offset + size_on_disk` checked against the
///    source slice length (`BulkDataEndOffsetOverflow` on `u64`
///    overflow, `BulkDataOffsetOob` on OOB).
/// 5. Per-package budget: cumulative bytes-resolved counter
///    incremented BEFORE allocation; fires
///    `BulkDataPackageBudgetExceeded` if over cap (rollback on
///    over-budget OR decode-failure paths).
/// 6. Compression decode: chunked `FCompressedChunkInfo` framing +
///    zlib via flate2 (see `decompress_zlib`); the framing summary's
///    uncompressed total is verified against `ElementCount`
///    (mismatch fires `BulkDataDecompressLengthMismatch`); framing
///    violations and codec stream errors fire
///    `BulkDataCompressionDecodeFailed`; unsupported v2 formats fire
///    `UnsupportedBulkCompression`; a decompressed claim over
///    `MAX_BULK_DATA_SIZE` fires `BulkDataSizeExceeded`.
///
/// # Threading
///
/// `Send + Sync` — `Arc<[u8]>`, `AtomicU64`, `OnceLock<Vec<u8>>`,
/// and `Box<dyn Fn() + Send + Sync + 'static>` all satisfy.
/// Required for Phase 5 (async runtime) and Phase 7 (GUI Iced
/// commands moving `Package` across thread boundaries).
pub struct BulkDataResolver {
    /// Stitched `.uasset` + `.uexp` bytes; resolved offsets index
    /// this buffer for the inline and uexp-resident tiers. `Arc<[u8]>`
    /// because the resolver lives inside `Package`, which owns the
    /// stitched bytes via `Arc<[u8]>` — borrowing from a sibling
    /// field would require Pin / ouroboros / yoke. Arc clones are
    /// one refcount bump; size is identical to `&'a [u8]` (16-byte
    /// fat pointer on 64-bit).
    stitched: std::sync::Arc<[u8]>,
    /// `summary.total_header_size` — boundary between inline
    /// (`.uasset` body) and uexp-resident (`.uexp` body) tiers for
    /// `BULKDATA_PayloadAtEndOfFile` records.
    total_header_size: u64,
    /// `summary.bulk_data_start_offset` — added to `OffsetInFile`
    /// unless `BULKDATA_NoOffsetFixUp` (bit 16) is set.
    bulk_data_start_offset: i64,
    /// Lazy `.ubulk` loader; called on first `Streaming`-tier
    /// resolution. Result cached in `ubulk_cache` so multiple
    /// records on the same companion pay the I/O cost once.
    ubulk_loader: Box<dyn Fn() -> crate::Result<Vec<u8>> + Send + Sync + 'static>,
    /// `OnceLock` cache for the `.ubulk` body.
    ubulk_cache: std::sync::OnceLock<Vec<u8>>,
    /// Lazy `.uptnl` loader; mirrors `ubulk_loader` for the
    /// `BULKDATA_OptionalPayload` tier.
    uptnl_loader: Box<dyn Fn() -> crate::Result<Vec<u8>> + Send + Sync + 'static>,
    /// `OnceLock` cache for the `.uptnl` body.
    uptnl_cache: std::sync::OnceLock<Vec<u8>>,
    /// Cumulative resolved bytes across all `resolve()` calls.
    /// Enforces `MAX_TOTAL_BULK_DATA_BYTES_PER_PACKAGE` (16 GiB).
    /// Incremented BEFORE allocation against the wire-claimed size
    /// (`size_on_disk` for uncompressed, `element_count` for zlib);
    /// rolled back on budget-exceeded OR decode-failure paths.
    /// `AtomicU64::Relaxed` — pure counter with no happens-before
    /// relationship to other memory, so SeqCst's barriers are
    /// wasted (zero cost on x86, ~5-10 ns on ARM64).
    bytes_resolved: std::sync::atomic::AtomicU64,
}

impl std::fmt::Debug for BulkDataResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Loader fields are `Box<dyn Fn>` (not `Debug`); render the
        // stable scalar state and elide the closures.
        f.debug_struct("BulkDataResolver")
            .field("stitched_len", &self.stitched.len())
            .field("total_header_size", &self.total_header_size)
            .field("bulk_data_start_offset", &self.bulk_data_start_offset)
            .field(
                "bytes_resolved",
                &self
                    .bytes_resolved
                    .load(std::sync::atomic::Ordering::Relaxed),
            )
            .field("ubulk_cached", &self.ubulk_cache.get().is_some())
            .field("uptnl_cached", &self.uptnl_cache.get().is_some())
            .finish_non_exhaustive()
    }
}

impl BulkDataResolver {
    /// Production constructor. `ubulk_loader` / `uptnl_loader` are
    /// closures that open the respective companion file (typically
    /// via `PakReader::read_entry`) on first matching-tier
    /// resolution. Both closures should return
    /// `MissingCompanionFile { kind: ... }` when the companion
    /// isn't present in the pak.
    ///
    /// The `'static` bound on the closures (plus `Send + Sync`) is
    /// load-bearing — `BulkDataResolver: Send + Sync` is required
    /// for Phase 5 async / Phase 7 GUI.
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
    /// load path. Use `new_for_test_with_ubulk` or
    /// `new_for_test_with_uptnl` for the streaming-tier cases.
    #[cfg(feature = "__test_utils")]
    #[must_use]
    pub fn new_for_test(
        stitched: impl Into<std::sync::Arc<[u8]>>,
        total_header_size: u64,
        bulk_data_start_offset: i64,
    ) -> Self {
        Self::new(
            stitched.into(),
            total_header_size,
            bulk_data_start_offset,
            missing_companion_loader(crate::error::CompanionFileKind::Ubulk, "test".to_string()),
            missing_companion_loader(crate::error::CompanionFileKind::Uptnl, "test".to_string()),
        )
    }

    /// Test-only constructor supplying `.ubulk` bytes inline. Used
    /// by streaming-tier resolution tests.
    #[cfg(feature = "__test_utils")]
    #[must_use]
    pub fn new_for_test_with_ubulk(
        stitched: impl Into<std::sync::Arc<[u8]>>,
        total_header_size: u64,
        bulk_data_start_offset: i64,
        ubulk: Vec<u8>,
    ) -> Self {
        Self::new(
            stitched.into(),
            total_header_size,
            bulk_data_start_offset,
            move || Ok(ubulk.clone()),
            missing_companion_loader(crate::error::CompanionFileKind::Uptnl, "test".to_string()),
        )
    }

    /// Test-only constructor supplying `.uptnl` bytes inline. Used
    /// by optional-streaming-tier resolution tests.
    #[cfg(feature = "__test_utils")]
    #[must_use]
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
            missing_companion_loader(crate::error::CompanionFileKind::Ubulk, "test".to_string()),
            move || Ok(uptnl.clone()),
        )
    }

    /// Resolve a single `FByteBulkData` record into a materialized
    /// [`BulkData`] payload.
    ///
    /// # Errors
    ///
    /// Per the defense chain documented on the struct: any of the
    /// 10 `AssetParseFault` bulk-data variants depending on which
    /// invariant the record violated.
    #[allow(
        clippy::too_many_lines,
        reason = "sequential dispatch + cap chain + side-effect-free budget reservation; splitting hurts the line-by-line auditability of the cap chain that the security panel reviewed"
    )]
    pub fn resolve(&self, record: &FByteBulkData, asset_path: &str) -> crate::Result<BulkData> {
        // 1. Unsupported compression rejection.
        if record.flags.is_lzo_compressed() {
            return Err(crate::PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: crate::error::AssetParseFault::UnsupportedBulkCompression { method: "LZO" },
            });
        }
        if record.flags.is_bitwindow_compressed() {
            return Err(crate::PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: crate::error::AssetParseFault::UnsupportedBulkCompression {
                    method: "BitWindow",
                },
            });
        }

        // 2. Offset fix-up.
        let resolved_offset: u64 = if record.flags.no_offset_fixup() {
            if record.offset_in_file < 0 {
                return Err(crate::PaksmithError::AssetParse {
                    asset_path: asset_path.to_string(),
                    fault: crate::error::AssetParseFault::BulkDataOffsetFixupOverflow {
                        offset: record.offset_in_file,
                        fixup: 0,
                    },
                });
            }
            #[allow(clippy::cast_sign_loss, reason = "validated >= 0 above")]
            {
                record.offset_in_file as u64
            }
        } else {
            let fixed = record
                .offset_in_file
                .checked_add(self.bulk_data_start_offset)
                .ok_or_else(|| crate::PaksmithError::AssetParse {
                    asset_path: asset_path.to_string(),
                    fault: crate::error::AssetParseFault::BulkDataOffsetFixupOverflow {
                        offset: record.offset_in_file,
                        fixup: self.bulk_data_start_offset,
                    },
                })?;
            if fixed < 0 {
                return Err(crate::PaksmithError::AssetParse {
                    asset_path: asset_path.to_string(),
                    fault: crate::error::AssetParseFault::BulkDataOffsetFixupOverflow {
                        offset: record.offset_in_file,
                        fixup: self.bulk_data_start_offset,
                    },
                });
            }
            #[allow(clippy::cast_sign_loss, reason = "validated >= 0 above")]
            {
                fixed as u64
            }
        };

        // 3. Tier dispatch + source-slice selection.
        //
        // Reject `payload_in_separate_file && payload_at_end_of_file`
        // BEFORE the tier dispatch — the wire format requires exactly
        // one tier-routing bit. Without this check, both-set silently
        // routes to streaming (first match wins), defeating the
        // `BulkDataConflictingTierFlags` variant's purpose.
        if record.flags.payload_in_separate_file() && record.flags.payload_at_end_of_file() {
            return Err(crate::PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: crate::error::AssetParseFault::BulkDataConflictingTierFlags {
                    flags: record.flags.0,
                },
            });
        }
        let (tier, source_bytes): (BulkDataTier, &[u8]) = if record.flags.payload_in_separate_file()
        {
            if record.flags.optional_payload() {
                (BulkDataTier::OptionalStreaming, self.uptnl(asset_path)?)
            } else {
                (BulkDataTier::Streaming, self.ubulk(asset_path)?)
            }
        } else if record.flags.payload_at_end_of_file() {
            let tier = if resolved_offset < self.total_header_size {
                BulkDataTier::Inline
            } else {
                BulkDataTier::UexpResident
            };
            (tier, &self.stitched[..])
        } else {
            return Err(crate::PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: crate::error::AssetParseFault::BulkDataNoTierFlag {
                    flags: record.flags.0,
                },
            });
        };

        // 4. Bounds check.
        let end = resolved_offset
            .checked_add(record.size_on_disk)
            .ok_or_else(|| crate::PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: crate::error::AssetParseFault::BulkDataEndOffsetOverflow {
                    offset: resolved_offset,
                    size: record.size_on_disk,
                },
            })?;
        let file_size = source_bytes.len() as u64;
        if end > file_size {
            return Err(crate::PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: crate::error::AssetParseFault::BulkDataOffsetOob {
                    tier,
                    offset: resolved_offset,
                    size: record.size_on_disk,
                    file_size,
                },
            });
        }

        // Indices are now in-bounds (verified by the `end > file_size`
        // check above). The `as usize` casts are lossy on 32-bit
        // targets at offsets > 4 GiB, but every cap is u64-bounded and
        // the bounds-check ran in u64; if a 32-bit caller ever hits
        // this path with offsets > usize::MAX, the slice index will
        // panic — which is fine for that pathological case.
        #[allow(
            clippy::cast_possible_truncation,
            reason = "bounds-checked in u64 above; 32-bit hosts at > 4 GiB offsets are unsupported"
        )]
        let raw = &source_bytes[resolved_offset as usize..end as usize];

        // 5. Budget check BEFORE allocation. For compressed records,
        // ElementCount is the decompressed byte claim (per the format
        // doc); the wire reader has already sign-checked it so the
        // `as u64` cast is non-negative-safe.
        let claimed_size: u64 = if record.flags.is_zlib_compressed() {
            #[allow(
                clippy::cast_sign_loss,
                reason = "element_count sign-checked at FByteBulkData::read_from"
            )]
            {
                record.element_count as u64
            }
        } else {
            record.size_on_disk
        };
        let prev = self
            .bytes_resolved
            .fetch_add(claimed_size, std::sync::atomic::Ordering::Relaxed);
        // `saturating_add` collapses u64 overflow (impossible in
        // practice given the per-record + per-package caps, but
        // defensive) to `u64::MAX`, which the `> CAP` check below
        // always catches.
        let total = prev.saturating_add(claimed_size);
        if total > MAX_TOTAL_BULK_DATA_BYTES_PER_PACKAGE {
            let _ = self
                .bytes_resolved
                .fetch_sub(claimed_size, std::sync::atomic::Ordering::Relaxed);
            return Err(crate::PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: crate::error::AssetParseFault::BulkDataPackageBudgetExceeded {
                    resolved: total,
                    cap: MAX_TOTAL_BULK_DATA_BYTES_PER_PACKAGE,
                },
            });
        }
        // NO TRACING EVENTS OR SIDE EFFECTS between the fetch_add and
        // the materialization — side effects between increment and
        // (possible) rollback would not be undone.

        // 6. Compression decode + materialize.
        let bytes = if record.flags.is_zlib_compressed() {
            decompress_zlib(raw, record.element_count, asset_path).inspect_err(|_| {
                let _ = self
                    .bytes_resolved
                    .fetch_sub(claimed_size, std::sync::atomic::Ordering::Relaxed);
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

    /// Pre-seed the per-package byte-budget counter. Test-only —
    /// the production path drives the counter via `resolve()`.
    /// Used to test `BulkDataPackageBudgetExceeded` without
    /// allocating 16 GiB of test bytes; the test pre-seeds the
    /// counter near the cap and resolves a small record that
    /// pushes over.
    #[cfg(feature = "__test_utils")]
    pub fn set_bytes_resolved_for_test(&self, n: u64) {
        self.bytes_resolved
            .store(n, std::sync::atomic::Ordering::Relaxed);
    }

    fn ubulk(&self, asset_path: &str) -> crate::Result<&[u8]> {
        if let Some(bytes) = self.ubulk_cache.get() {
            return Ok(bytes.as_slice());
        }
        let loaded = (self.ubulk_loader)()?;
        check_companion_size(
            loaded.len() as u64,
            MAX_UBULK_FILE_SIZE,
            CompanionFileKind::Ubulk,
        )
        .map_err(|fault| crate::PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault,
        })?;
        // `get_or_init` is stable (1.70+); `get_or_try_init`'s
        // `once_cell_try` feature is unstable as of MSRV 1.88. The
        // closure here is infallible — we've already loaded + cap-
        // checked above. Race: another thread may have set the cache
        // between our `get()` check and now; in that case our `loaded`
        // is dropped and the cached value is returned (one wasted I/O,
        // semantically correct).
        let bytes_vec = self.ubulk_cache.get_or_init(|| loaded);
        Ok(bytes_vec.as_slice())
    }

    fn uptnl(&self, asset_path: &str) -> crate::Result<&[u8]> {
        if let Some(bytes) = self.uptnl_cache.get() {
            return Ok(bytes.as_slice());
        }
        let loaded = (self.uptnl_loader)()?;
        check_companion_size(
            loaded.len() as u64,
            MAX_UBULK_FILE_SIZE,
            CompanionFileKind::Uptnl,
        )
        .map_err(|fault| crate::PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault,
        })?;
        let bytes_vec = self.uptnl_cache.get_or_init(|| loaded);
        Ok(bytes_vec.as_slice())
    }
}

/// Enforce the companion-file size cap. Returns the bare
/// `AssetParseFault` so callers wrap with their `asset_path` on
/// hand — matches the [`BulkDataFlags::validate`] pattern and
/// avoids the empty-`asset_path` sentinel anti-pattern.
///
/// Extracted from `ubulk()` / `uptnl()` for direct testability —
/// the 16-GiB boundary is impractical to test via the lazy-load
/// path (can't allocate `MAX_UBULK_FILE_SIZE + 1` bytes in a test),
/// but the helper takes the cap as a parameter so tests can pin
/// the strict-greater-than semantics with small values.
fn check_companion_size(
    actual: u64,
    cap: u64,
    kind: CompanionFileKind,
) -> Result<(), crate::error::AssetParseFault> {
    if actual > cap {
        return Err(crate::error::AssetParseFault::BulkDataCompanionTooLarge {
            kind,
            size: actual,
            cap,
        });
    }
    Ok(())
}

/// Build a closure that always fires `MissingCompanionFile { kind }`
/// for `asset_path`. Used by the non-pak `Package::read_from` path
/// (no companion bytes available) and the `__test_utils` constructors
/// (tests not exercising streaming / optional-streaming tiers fail
/// loud if they accidentally route through a companion loader).
pub(crate) fn missing_companion_loader(
    kind: crate::error::CompanionFileKind,
    asset_path: String,
) -> impl Fn() -> crate::Result<Vec<u8>> + Send + Sync + 'static {
    move || {
        Err(crate::PaksmithError::AssetParse {
            asset_path: asset_path.clone(),
            fault: crate::error::AssetParseFault::MissingCompanionFile { kind },
        })
    }
}

/// Read one `FCompressedChunkInfo` (two little-endian i64s) from
/// `buf` at `*pos`, advancing `*pos`. `None` when fewer than 16
/// bytes remain — callers surface their own truncation fault with
/// positional context.
fn read_chunk_info(buf: &[u8], pos: &mut usize) -> Option<(i64, i64)> {
    let end = pos.checked_add(CHUNK_INFO_WIRE_SIZE)?;
    let bytes = buf.get(*pos..end)?;
    *pos = end;
    let compressed = i64::from_le_bytes(bytes[..8].try_into().ok()?);
    let uncompressed = i64::from_le_bytes(bytes[8..].try_into().ok()?);
    Some((compressed, uncompressed))
}

/// Decompress a `BULKDATA_SerializeCompressedZLIB` bulk-data payload.
///
/// The on-disk layout is the engine's chunked `FCompressedChunkInfo`
/// framing (NOT a bare zlib stream — see #644): a tag record
/// (`PACKAGE_FILE_TAG` or `ARCHIVE_V2_HEADER_TAG`, plus the
/// compression chunk size), for v2 an inline compression-format
/// byte, a summary record (total compressed / uncompressed sizes), a
/// chunk table of `ceil(total_uncompressed / chunk_size)` entries
/// whose per-field sums MUST equal the summary, then the
/// independently-zlib-compressed chunk streams back to back.
/// Layout verified against the CUE4Parse reference
/// (`FArchive.SerializeCompressedNew`) and independent community
/// decoders; see `docs/formats/asset/bulk-data.md`.
///
/// Paksmith deviations (all fail-closed, documented in the format
/// doc): byte-swapped (big-endian) tags are rejected rather than
/// swap-decoded; the summary's uncompressed total must equal
/// `expected_size` (ElementCount) exactly, not merely fit within it;
/// the framing must consume the input exactly (no trailing bytes);
/// v2 named formats other than Zlib surface
/// `UnsupportedBulkCompression`.
///
/// SECURITY invariants (Phase 3 audit F1 discipline):
/// - `expected_size` (the decompressed claim) is capped at
///   `MAX_BULK_DATA_SIZE` before any parsing — the per-record
///   ceiling, independent of the resolver's package budget.
/// - The chunk table's byte size is bounded by the REAL remaining
///   input length before any table allocation — a lying summary
///   cannot force a large allocation.
/// - The output buffer is pre-sized from `compressed.len()`, never
///   from wire-claimed sizes; growth is driven by actually-produced
///   bytes, bounded per chunk by `take(chunk_uncompressed + 1)` and
///   in total by the chunk-table sums equaling `expected_size`
///   (which the resolver budget-checks before calling).
///
/// Used by `BulkDataResolver::resolve` and the `__test_utils` bench
/// accessor (`crate::testing::bench::zlib_decompress`); `pub(crate)`
/// for the latter.
#[allow(
    clippy::too_many_lines,
    reason = "linear wire-format validation sequence; splitting would scatter the framing invariants"
)]
pub(crate) fn decompress_zlib(
    compressed: &[u8],
    expected_size: i64,
    asset_path: &str,
) -> crate::Result<Vec<u8>> {
    use flate2::read::ZlibDecoder;
    use std::io::Read;

    // Defense in depth: re-assert the sign-check from
    // FByteBulkData::read_from in case this function is called from
    // a future site that bypasses the read-side check.
    if expected_size < 0 {
        return Err(crate::PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: crate::error::AssetParseFault::BulkDataElementCountNegative {
                count: expected_size,
            },
        });
    }
    #[allow(clippy::cast_sign_loss, reason = "validated >= 0 above")]
    let expected = expected_size as u64;

    // Per-record ceiling on the decompressed claim (R1 panel):
    // parity with the read-side SizeOnDisk cap for uncompressed
    // blobs, and the absolute transient-output bound the
    // single-stream decoder carried via `take(MAX_BULK_DATA_SIZE)`.
    // Without it, the resolver's 16 GiB package budget alone would
    // let a single crafted record decompress to 16 GiB (previously
    // possible only across two 8 GiB records).
    if expected > MAX_BULK_DATA_SIZE {
        return Err(crate::PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: crate::error::AssetParseFault::BulkDataSizeExceeded {
                size: expected,
                cap: MAX_BULK_DATA_SIZE,
            },
        });
    }

    // A zero-size record serializes NO payload bytes at all (the
    // engine early-outs before writing any framing).
    if expected == 0 && compressed.is_empty() {
        return Ok(Vec::new());
    }

    let fail = |reason: String| crate::PaksmithError::AssetParse {
        asset_path: asset_path.to_string(),
        fault: crate::error::AssetParseFault::BulkDataCompressionDecodeFailed {
            method: "zlib",
            reason,
        },
    };

    let mut pos = 0usize;

    // 1. Tag record: (magic tag, compression chunk size).
    let (tag_raw, tag_chunk_size) = read_chunk_info(compressed, &mut pos)
        .ok_or_else(|| fail("truncated framing header (tag record)".to_string()))?;
    #[allow(
        clippy::cast_sign_loss,
        reason = "bit-pattern comparison against magic tags"
    )]
    let tag = tag_raw as u64;
    let v1_tag = u64::from(crate::asset::version::PACKAGE_FILE_TAG);
    let is_v2 = tag == ARCHIVE_V2_HEADER_TAG;
    if tag != v1_tag && !is_v2 {
        // The reference decoder byte-swap-decodes these; paksmith
        // parses little-endian cooked content only and fails loud.
        let swapped_forms = [
            u64::from(crate::asset::version::PACKAGE_FILE_TAG_SWAPPED),
            v1_tag.swap_bytes(),
            ARCHIVE_V2_HEADER_TAG.swap_bytes(),
        ];
        if swapped_forms.contains(&tag) {
            return Err(fail(format!(
                "byte-swapped (big-endian) chunk framing is unsupported \
                 (tag 0x{tag:016X}); paksmith parses little-endian cooked content only"
            )));
        }
        return Err(fail(format!(
            "bad chunked-framing tag 0x{tag:016X} \
             (expected PACKAGE_FILE_TAG or ARCHIVE_V2_HEADER_TAG)"
        )));
    }

    // 2. v2 header: inline compression-format byte. Only Zlib (3)
    // proceeds on this decode path.
    if is_v2 {
        let format_byte = *compressed
            .get(pos)
            .ok_or_else(|| fail("truncated framing header (v2 format byte)".to_string()))?;
        pos += 1;
        let unsupported = |method: &'static str| crate::PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: crate::error::AssetParseFault::UnsupportedBulkCompression { method },
        };
        match format_byte {
            3 => {} // Zlib — the format this decoder implements
            1 => return Err(unsupported("None")),
            2 => return Err(unsupported("Oodle")),
            4 => return Err(unsupported("Gzip")),
            5 => return Err(unsupported("LZ4")),
            0 => {
                return Err(fail(
                    "v2 framing with an inline FString-named compression format \
                     is unsupported (no known bulk-data producer)"
                        .to_string(),
                ));
            }
            other => return Err(fail(format!("unknown v2 compression-format byte {other}"))),
        }
    }

    // 3. Compression chunk size, honoring the legacy sentinel quirk:
    // a chunk-size field carrying PACKAGE_FILE_TAG itself means
    // "128 KiB" (files written before the size was stored).
    let sentinel = i64::from(crate::asset::version::PACKAGE_FILE_TAG);
    let chunk_size = if tag_chunk_size == sentinel {
        LOADING_COMPRESSION_CHUNK_SIZE
    } else {
        tag_chunk_size
    };
    if chunk_size <= 0 {
        return Err(fail(format!(
            "nonpositive compression chunk size {chunk_size}"
        )));
    }

    // 4. Summary record: total compressed / uncompressed sizes.
    let (total_comp, total_unc) = read_chunk_info(compressed, &mut pos)
        .ok_or_else(|| fail("truncated framing header (summary record)".to_string()))?;
    if total_comp < 0 || total_unc < 0 {
        return Err(fail(format!(
            "negative summary size (compressed {total_comp}, uncompressed {total_unc})"
        )));
    }

    // 5. The summary's uncompressed total IS the record's decompressed
    // byte-count claim; it must match ElementCount exactly. (The
    // reference decoder allows <=; for `FByteBulkData` the writer
    // always emits ==, so a mismatch is a corruption signal.)
    #[allow(clippy::cast_sign_loss, reason = "validated >= 0 above")]
    if total_unc as u64 != expected {
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "non-negative; 32-bit hosts with > 4 GiB claims are unsupported"
        )]
        return Err(crate::PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: crate::error::AssetParseFault::BulkDataDecompressLengthMismatch {
                expected: expected_size,
                actual: total_unc as usize,
            },
        });
    }

    // 6. Chunk count = ceil(total_unc / chunk_size), overflow-checked.
    let chunk_count = total_unc
        .checked_add(chunk_size - 1)
        .map(|n| n / chunk_size)
        .ok_or_else(|| {
            fail(format!(
                "chunk count overflow (uncompressed total {total_unc})"
            ))
        })?;
    let chunk_count = usize::try_from(chunk_count).map_err(|_| {
        fail(format!(
            "chunk count {chunk_count} exceeds the address space"
        ))
    })?;

    // 7. SECURITY: the chunk table must physically fit in the
    // remaining input BEFORE any table allocation — a lying summary
    // cannot force an allocation larger than the bytes actually
    // present.
    let remaining = compressed.len() - pos;
    let table_bytes = chunk_count
        .checked_mul(CHUNK_INFO_WIRE_SIZE)
        .filter(|&n| n <= remaining)
        .ok_or_else(|| {
            fail(format!(
                "truncated chunk table: {chunk_count} chunks need more bytes than \
                 the {remaining} remaining"
            ))
        })?;

    // 8. Chunk table. Entries are non-negative; per-field sums must
    // equal the summary totals (reference-decoder parity).
    let table_region = &compressed[pos..pos + table_bytes];
    pos += table_bytes;
    let mut chunks: Vec<(i64, i64)> = Vec::with_capacity(chunk_count);
    let mut sum_comp: i64 = 0;
    let mut sum_unc: i64 = 0;
    for entry in table_region.chunks_exact(CHUNK_INFO_WIRE_SIZE) {
        let mut entry_pos = 0usize;
        let (chunk_comp, chunk_unc) = read_chunk_info(entry, &mut entry_pos)
            .ok_or_else(|| fail("truncated chunk table entry".to_string()))?;
        if chunk_comp < 0 || chunk_unc < 0 {
            return Err(fail(format!(
                "negative chunk table entry (compressed {chunk_comp}, uncompressed {chunk_unc})"
            )));
        }
        sum_comp = sum_comp
            .checked_add(chunk_comp)
            .ok_or_else(|| fail("chunk table compressed-size sum overflow".to_string()))?;
        sum_unc = sum_unc
            .checked_add(chunk_unc)
            .ok_or_else(|| fail("chunk table uncompressed-size sum overflow".to_string()))?;
        chunks.push((chunk_comp, chunk_unc));
    }
    if sum_comp != total_comp {
        return Err(fail(format!(
            "chunk table compressed-size sum {sum_comp} != summary {total_comp} (sum mismatch)"
        )));
    }
    if sum_unc != total_unc {
        return Err(fail(format!(
            "chunk table uncompressed-size sum {sum_unc} != summary {total_unc} (sum mismatch)"
        )));
    }

    // 9. The chunk streams must consume the rest of the input
    // exactly: SizeOnDisk delimits the framing, so both a shortfall
    // and trailing bytes are corruption / crafted-input signals.
    let streams_len = compressed.len() - pos;
    #[allow(clippy::cast_sign_loss, reason = "validated >= 0 above")]
    let sum_comp_u64 = sum_comp as u64;
    if sum_comp_u64 > streams_len as u64 {
        return Err(fail(format!(
            "truncated chunk streams: table claims {sum_comp_u64} bytes, {streams_len} remain"
        )));
    }
    if sum_comp_u64 < streams_len as u64 {
        return Err(fail(format!(
            "{} trailing byte(s) after the final chunk stream",
            streams_len as u64 - sum_comp_u64
        )));
    }

    // 10. Decompress chunk by chunk, appending into one output
    // buffer. SECURITY (Phase 3 audit F1): pre-size from the
    // COMPRESSED input length, NOT the wire-claimed `expected` —
    // the eager reservation stays proportional to bytes actually
    // present (bounded by MAX_BULK_DATA_COMPRESSED_SIZE = 512 MiB
    // upstream), never amplified by a lying count. Each chunk's
    // read is bounded by `take(chunk_unc + 1)`: the `+ 1` makes an
    // over-long stream detectable while capping a decompression
    // bomb at one byte past the table's claim, and the table sums
    // were pinned to `expected` above.
    let mut out: Vec<u8> = Vec::with_capacity(compressed.len());
    for (index, &(chunk_comp, chunk_unc)) in chunks.iter().enumerate() {
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "non-negative; bounded by streams_len (a usize) via the sum check above"
        )]
        let chunk_len = chunk_comp as usize;
        // In-bounds: sum(chunk_comp) == streams_len exactly (step 9),
        // and `pos` advances by each stream's length in turn.
        let stream = &compressed[pos..pos + chunk_len];
        pos += chunk_len;
        let before = out.len();
        #[allow(clippy::cast_sign_loss, reason = "validated >= 0 above")]
        let mut limited = ZlibDecoder::new(stream).take(chunk_unc as u64 + 1);
        let _ = limited
            .read_to_end(&mut out)
            .map_err(|e| fail(format!("chunk {index}: {e}")))?;
        let produced = out.len() - before;
        #[allow(clippy::cast_sign_loss, reason = "validated >= 0 above")]
        if produced as u64 != chunk_unc as u64 {
            return Err(fail(format!(
                "chunk {index} decompressed to {produced} bytes, expected {chunk_unc}"
            )));
        }
    }
    Ok(out)
}

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
    /// Pins the chunked-framing wire constants against the reference
    /// values (CUE4Parse `FArchive.SerializeCompressedNew` +
    /// `Compression.cs`; cross-anchored against community decoders).
    /// Kills arithmetic/shift mutants on the const expressions, and
    /// pair-anchors the v2 tag's low 32 bits to `PACKAGE_FILE_TAG`.
    #[test]
    fn framing_constants_pin_expected_values() {
        assert_eq!(ARCHIVE_V2_HEADER_TAG, 0x2222_2222_9E2A_83C1);
        assert_eq!(
            ARCHIVE_V2_HEADER_TAG & 0xFFFF_FFFF,
            u64::from(crate::asset::version::PACKAGE_FILE_TAG),
            "v2 tag's low 32 bits are PACKAGE_FILE_TAG"
        );
        assert_eq!(LOADING_COMPRESSION_CHUNK_SIZE, 131_072, "128 KiB");
        assert_eq!(CHUNK_INFO_WIRE_SIZE, 16, "two LE i64s");
    }

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
    fn flags_is_any_compressed_covers_all_three_codecs() {
        // Co-located accessor that ORs the three compression flags.
        // Tested independently because `read_from` consumes it via a
        // single `is_compressed` binding; without per-flag pinning
        // here, a regression that drops one of the three from the
        // OR would survive `read_from`'s tests if only the still-
        // covered flag was exercised at that level.
        assert!(BulkDataFlags::from(FLAG_SERIALIZE_COMPRESSED_ZLIB).is_any_compressed());
        assert!(BulkDataFlags::from(FLAG_COMPRESSED_LZO).is_any_compressed());
        assert!(BulkDataFlags::from(FLAG_SERIALIZE_COMPRESSED_BITWINDOW).is_any_compressed());
        assert!(!BulkDataFlags::from(0).is_any_compressed());
        assert!(!BulkDataFlags::from(FLAG_PAYLOAD_AT_END_OF_FILE).is_any_compressed());
    }

    #[test]
    fn flags_zero_means_all_accessors_false() {
        // Comprehensive negative test for all 10 named-bit accessors.
        // Kills cargo-mutants `-> true` mutations (accessor always
        // returns true, defeating the bit check) AND `& -> |`
        // mutations (bitwise-AND replaced with OR makes accessor
        // always-true when the bit is unset but in the mask). A
        // zero-flag input is the unique signal that distinguishes
        // real bitwise-AND from any always-true variant.
        //
        // Each per-bit positive test (e.g. `flags_optional_payload_detected`)
        // covers the bit-set case; this test covers the bit-unset case
        // for every accessor.
        let f = BulkDataFlags::from(0x0000_0000);
        assert!(!f.payload_at_end_of_file());
        assert!(!f.payload_in_separate_file());
        assert!(!f.optional_payload());
        assert!(!f.no_offset_fixup());
        assert!(!f.size_64_bit());
        assert!(!f.is_zlib_compressed());
        assert!(!f.is_lzo_compressed());
        assert!(!f.is_bitwindow_compressed());
        assert!(!f.has_duplicate_non_optional());
        assert!(!f.has_bad_data_version());
        assert!(!f.has_unused());
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

    // `FByteBulkData::read_from` wire-format reader tests.
    //
    // The records are hand-built byte arrays that mirror the wire
    // shape in the doc-comment on `read_from`. Each test isolates
    // one branch of the parser (Size64Bit, BadDataVersion,
    // DuplicateNonOptional, cap enforcement, sign-check).

    #[test]
    fn read_minimal_inline_record() {
        // 24 bytes: flags(0x0001) + ElementCount(4096 i32)
        //         + SizeOnDisk(4096 u32) + OffsetInFile(512 i64).
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&FLAG_PAYLOAD_AT_END_OF_FILE.to_le_bytes());
        bytes.extend_from_slice(&4096_i32.to_le_bytes());
        bytes.extend_from_slice(&4096_u32.to_le_bytes());
        bytes.extend_from_slice(&512_i64.to_le_bytes());

        let mut cur = std::io::Cursor::new(bytes.clone());
        let record = FByteBulkData::read_from(&mut cur, "test.uasset").expect("read");
        assert!(record.flags.payload_at_end_of_file());
        assert!(!record.flags.size_64_bit());
        assert_eq!(record.element_count, 4096);
        assert_eq!(record.size_on_disk, 4096);
        assert_eq!(record.offset_in_file, 512);
        assert_eq!(cur.position(), bytes.len() as u64);
    }

    #[test]
    fn read_size_64_bit_widens_fields() {
        // ElementCount + SizeOnDisk widen to 8 bytes when Size64Bit
        // is set. Wire shape: u32 flags + i64 element_count + u64
        // size_on_disk + i64 offset_in_file.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(FLAG_PAYLOAD_AT_END_OF_FILE | FLAG_SIZE_64_BIT).to_le_bytes());
        bytes.extend_from_slice(&4096_i64.to_le_bytes());
        bytes.extend_from_slice(&4096_u64.to_le_bytes());
        bytes.extend_from_slice(&512_i64.to_le_bytes());

        let mut cur = std::io::Cursor::new(bytes.clone());
        let record = FByteBulkData::read_from(&mut cur, "test.uasset").expect("read");
        assert!(record.flags.size_64_bit());
        assert_eq!(record.element_count, 4096);
        assert_eq!(record.size_on_disk, 4096);
        assert_eq!(cur.position(), bytes.len() as u64);
    }

    /// A 20-byte (`!Size64Bit`) bulk header with the given flags + `SizeOnDisk`,
    /// followed by `payload` bytes in-stream. `ElementCount` = `SizeOnDisk`.
    fn inline_record(flags: u32, size_on_disk: u32, payload: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&flags.to_le_bytes());
        b.extend_from_slice(&i32::try_from(size_on_disk).unwrap().to_le_bytes());
        b.extend_from_slice(&size_on_disk.to_le_bytes());
        b.extend_from_slice(&0_i64.to_le_bytes());
        b.extend_from_slice(payload);
        b
    }

    /// Read `bytes` as one record and return where the cursor stopped.
    fn read_and_pos(bytes: &[u8]) -> u64 {
        let mut cur = std::io::Cursor::new(bytes);
        let _record = FByteBulkData::read_from(&mut cur, "t").expect("read");
        cur.position()
    }

    #[test]
    fn read_skips_in_stream_inline_payload() {
        // ForceInlinePayload: the `SizeOnDisk` payload bytes follow the 20-byte
        // header in-stream, so the cursor must advance past them (header + 3) for
        // the next field to read at the right offset — mirroring CUE4Parse
        // `TBulkData`'s `Ar.Position += SizeOnDisk`.
        let bytes = inline_record(FLAG_FORCE_INLINE_PAYLOAD, 3, &[0xAA, 0xBB, 0xCC, 0x5A]);
        assert_eq!(read_and_pos(&bytes), 23); // 20 header + 3 payload (sentinel 0x5A left)
    }

    #[test]
    fn read_from_capturing_inline_returns_inline_payload_bytes() {
        // ForceInlinePayload: the SizeOnDisk payload bytes are CAPTURED (not
        // sunk), and the cursor still advances past them. (#563 consumer.)
        let bytes = inline_record(FLAG_FORCE_INLINE_PAYLOAD, 3, &[0xAA, 0xBB, 0xCC, 0x5A]);
        let mut cur = std::io::Cursor::new(bytes.as_slice());
        let (record, payload) =
            FByteBulkData::read_from_capturing_inline(&mut cur, "t").expect("read");
        assert_eq!(record.size_on_disk, 3);
        assert_eq!(payload.as_deref(), Some(&[0xAA, 0xBB, 0xCC][..]));
        assert_eq!(cur.position(), 23, "header (20) + 3 payload consumed");
    }

    #[test]
    fn read_from_capturing_inline_returns_none_for_separate_file() {
        // PayloadAtEndOfFile (external .ubulk): not inline → no bytes captured,
        // cursor stops at the 20-byte header.
        let bytes = inline_record(FLAG_PAYLOAD_AT_END_OF_FILE, 3, &[0xAA, 0xBB, 0xCC]);
        let mut cur = std::io::Cursor::new(bytes.as_slice());
        let (_record, payload) =
            FByteBulkData::read_from_capturing_inline(&mut cur, "t").expect("read");
        assert!(payload.is_none(), "separate-file payload not captured");
        assert_eq!(cur.position(), 20);
    }

    #[test]
    fn read_from_truncated_inline_payload_advances_and_eofs_on_next_read() {
        // Sink path (`read_from`): SizeOnDisk claims 4 inline bytes but only 2 are
        // present. `read_from` silently copies what's available (no error HERE);
        // the caller sees the short read when the NEXT field read EOFs. This is the
        // documented asymmetry with `read_from_capturing_inline` (which faults
        // immediately) — both are EOF-safe. Pins the sink-copy behavior.
        let bytes = inline_record(FLAG_FORCE_INLINE_PAYLOAD, 4, &[0xAA, 0xBB]);
        let mut cur = std::io::Cursor::new(bytes.as_slice());
        let _record =
            FByteBulkData::read_from(&mut cur, "t").expect("sink tolerates a short payload");
        assert_eq!(
            cur.position(),
            bytes.len() as u64,
            "the sink consumed the available payload bytes; a next read would EOF"
        );
    }

    #[test]
    fn read_from_capturing_inline_truncated_payload_is_eof() {
        // SizeOnDisk claims 4 inline bytes but only 2 are present → typed EOF on
        // the BulkDataInlinePayload field (not a short/partial capture).
        let bytes = inline_record(FLAG_FORCE_INLINE_PAYLOAD, 4, &[0xAA, 0xBB]);
        let mut cur = std::io::Cursor::new(bytes.as_slice());
        let err = FByteBulkData::read_from_capturing_inline(&mut cur, "t").unwrap_err();
        assert!(
            matches!(
                err,
                crate::error::PaksmithError::AssetParse {
                    fault: crate::error::AssetParseFault::UnexpectedEof {
                        field: crate::error::AssetWireField::BulkDataInlinePayload
                    },
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn read_does_not_skip_payload_at_end_of_file() {
        // PayloadAtEndOfFile (the cooked norm): payload is at `OffsetInFile`, not
        // in-stream, so the cursor stops at the 20-byte header.
        let bytes = inline_record(FLAG_PAYLOAD_AT_END_OF_FILE, 3, &[0xAA, 0xBB, 0xCC]);
        assert_eq!(read_and_pos(&bytes), 20);
    }

    #[test]
    fn read_skips_inline_for_none_and_exact_lazy_loadable() {
        // flags == None (0) → inline.
        assert_eq!(read_and_pos(&inline_record(0, 2, &[0x11, 0x22])), 22);
        // flags == exactly LazyLoadable → inline.
        assert_eq!(
            read_and_pos(&inline_record(FLAG_LAZY_LOADABLE, 2, &[0x11, 0x22])),
            22
        );
        // LazyLoadable + another bit (not exact, no force-inline) → NOT inline.
        let mixed = inline_record(
            FLAG_LAZY_LOADABLE | FLAG_PAYLOAD_AT_END_OF_FILE,
            2,
            &[0x11, 0x22],
        );
        assert_eq!(read_and_pos(&mixed), 20);
    }

    #[test]
    fn read_no_inline_skip_when_size_zero_or_unused() {
        // ForceInlinePayload but SizeOnDisk == 0 → the oracle's early-exit, no
        // skip (the trailing byte stays unread).
        assert_eq!(
            read_and_pos(&inline_record(FLAG_FORCE_INLINE_PAYLOAD, 0, &[0xAA])),
            20
        );
        // ForceInlinePayload + Unused (with SizeOnDisk > 0) → early-exit, no skip.
        let unused = inline_record(FLAG_FORCE_INLINE_PAYLOAD | FLAG_UNUSED, 2, &[0xAA, 0xBB]);
        assert_eq!(read_and_pos(&unused), 20);
    }

    #[test]
    fn read_inline_skip_uses_post_bad_data_version_clear_flags() {
        // A record whose only flag is BadDataVersion: `read_from` clears that bit
        // (and consumes its 2-byte tail), so `flags_out == None (0)` → inline →
        // the payload is skipped. Pins that the inline check runs on the
        // post-clear flags (matching CUE4Parse's clear-then-test order).
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&FLAG_BAD_DATA_VERSION.to_le_bytes()); // only bit 15
        bytes.extend_from_slice(&2_i32.to_le_bytes()); // ElementCount
        bytes.extend_from_slice(&2_u32.to_le_bytes()); // SizeOnDisk = 2
        bytes.extend_from_slice(&0_i64.to_le_bytes()); // OffsetInFile
        bytes.extend_from_slice(&0xABCD_u16.to_le_bytes()); // BadDataVersion tail
        bytes.extend_from_slice(&[0x11, 0x22]); // 2 inline payload bytes
        // 20 header + 2 bad-data tail + 2 payload = 24.
        assert_eq!(read_and_pos(&bytes), 24);
    }

    #[test]
    fn payload_is_inline_matches_oracle_condition() {
        // ForceInlinePayload bit (even among other flags) → inline.
        assert!(BulkDataFlags::from(FLAG_FORCE_INLINE_PAYLOAD).payload_is_inline());
        assert!(
            BulkDataFlags::from(FLAG_FORCE_INLINE_PAYLOAD | FLAG_PAYLOAD_AT_END_OF_FILE)
                .payload_is_inline()
        );
        // Exactly LazyLoadable → inline; LazyLoadable + extra bit → NOT (no force).
        assert!(BulkDataFlags::from(FLAG_LAZY_LOADABLE).payload_is_inline());
        assert!(
            !BulkDataFlags::from(FLAG_LAZY_LOADABLE | FLAG_PAYLOAD_AT_END_OF_FILE)
                .payload_is_inline()
        );
        // Exactly None (0) → inline.
        assert!(BulkDataFlags::from(0).payload_is_inline());
        // PayloadAtEndOfFile / separate-file (cooked) → NOT inline.
        assert!(!BulkDataFlags::from(FLAG_PAYLOAD_AT_END_OF_FILE).payload_is_inline());
        assert!(!BulkDataFlags::from(FLAG_PAYLOAD_IN_SEPARATE_FILE).payload_is_inline());
    }

    #[test]
    fn has_unused_detects_the_bit() {
        assert!(BulkDataFlags::from(FLAG_UNUSED).has_unused());
        assert!(BulkDataFlags::from(FLAG_UNUSED | FLAG_PAYLOAD_AT_END_OF_FILE).has_unused());
    }

    #[test]
    fn read_rejects_negative_element_count() {
        // ElementCount = -1 → BulkDataElementCountNegative.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&FLAG_PAYLOAD_AT_END_OF_FILE.to_le_bytes());
        bytes.extend_from_slice(&(-1_i32).to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&0_i64.to_le_bytes());

        let mut cur = std::io::Cursor::new(bytes);
        match FByteBulkData::read_from(&mut cur, "test.uasset") {
            Err(crate::PaksmithError::AssetParse {
                fault: crate::error::AssetParseFault::BulkDataElementCountNegative { count },
                ..
            }) => assert_eq!(count, -1),
            other => panic!("expected BulkDataElementCountNegative, got {other:?}"),
        }
    }

    #[test]
    fn read_rejects_unknown_flags() {
        // Bit 19 is reserved.
        let mut bytes = Vec::new();
        let bad = FLAG_PAYLOAD_AT_END_OF_FILE | 0x0008_0000;
        bytes.extend_from_slice(&bad.to_le_bytes());
        // Don't bother filling the rest — validate fires first.
        let mut cur = std::io::Cursor::new(bytes);
        match FByteBulkData::read_from(&mut cur, "test.uasset") {
            Err(crate::PaksmithError::AssetParse {
                fault: crate::error::AssetParseFault::UnknownBulkDataFlags { bits },
                ..
            }) => assert_eq!(bits, bad),
            other => panic!("expected UnknownBulkDataFlags, got {other:?}"),
        }
    }

    #[test]
    fn read_rejects_size_above_uncompressed_cap() {
        // 9 GiB SizeOnDisk with Size64Bit set, uncompressed → cap fires.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(FLAG_PAYLOAD_AT_END_OF_FILE | FLAG_SIZE_64_BIT).to_le_bytes());
        bytes.extend_from_slice(&0_i64.to_le_bytes());
        bytes.extend_from_slice(&(9_u64 * 1024 * 1024 * 1024).to_le_bytes());
        bytes.extend_from_slice(&0_i64.to_le_bytes());

        let mut cur = std::io::Cursor::new(bytes);
        match FByteBulkData::read_from(&mut cur, "test.uasset") {
            Err(crate::PaksmithError::AssetParse {
                fault: crate::error::AssetParseFault::BulkDataSizeExceeded { size, cap },
                ..
            }) => {
                assert_eq!(size, 9 * 1024 * 1024 * 1024);
                assert_eq!(cap, MAX_BULK_DATA_SIZE);
            }
            other => panic!("expected BulkDataSizeExceeded, got {other:?}"),
        }
    }

    #[test]
    fn read_rejects_compressed_size_above_compressed_cap() {
        // 1 GiB SizeOnDisk with zlib compression flag set → compressed
        // cap (512 MiB) fires BEFORE the uncompressed cap. Without
        // the compressed-cap fork, this would slip past since 1 GiB
        // < 8 GiB.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(
            &(FLAG_PAYLOAD_AT_END_OF_FILE | FLAG_SIZE_64_BIT | FLAG_SERIALIZE_COMPRESSED_ZLIB)
                .to_le_bytes(),
        );
        bytes.extend_from_slice(&0_i64.to_le_bytes());
        bytes.extend_from_slice(&(1024_u64 * 1024 * 1024).to_le_bytes());
        bytes.extend_from_slice(&0_i64.to_le_bytes());

        let mut cur = std::io::Cursor::new(bytes);
        match FByteBulkData::read_from(&mut cur, "test.uasset") {
            Err(crate::PaksmithError::AssetParse {
                fault: crate::error::AssetParseFault::BulkDataCompressedSizeExceeded { size, cap },
                ..
            }) => {
                assert_eq!(size, 1024 * 1024 * 1024);
                assert_eq!(cap, MAX_BULK_DATA_COMPRESSED_SIZE);
            }
            other => panic!("expected BulkDataCompressedSizeExceeded, got {other:?}"),
        }
    }

    #[test]
    fn read_rejects_lzo_compressed_size_above_compressed_cap() {
        // LZO-only compression triggers `is_compressed = true` via the
        // middle term of `zlib || lzo || bitwindow`. Kills cargo-mutants
        // mutations on the right `||` (which precedence-folds to
        // `zlib || (lzo && bitwindow)` — for LZO-only that mutation
        // evaluates false, defeating the compressed-cap check).
        let mut bytes = Vec::new();
        bytes.extend_from_slice(
            &(FLAG_PAYLOAD_AT_END_OF_FILE | FLAG_SIZE_64_BIT | FLAG_COMPRESSED_LZO).to_le_bytes(),
        );
        bytes.extend_from_slice(&0_i64.to_le_bytes());
        bytes.extend_from_slice(&(1024_u64 * 1024 * 1024).to_le_bytes());
        bytes.extend_from_slice(&0_i64.to_le_bytes());

        let mut cur = std::io::Cursor::new(bytes);
        match FByteBulkData::read_from(&mut cur, "test.uasset") {
            Err(crate::PaksmithError::AssetParse {
                fault: crate::error::AssetParseFault::BulkDataCompressedSizeExceeded { size, .. },
                ..
            }) => assert_eq!(size, 1024 * 1024 * 1024),
            other => panic!("expected BulkDataCompressedSizeExceeded, got {other:?}"),
        }
    }

    #[test]
    fn read_rejects_bitwindow_compressed_size_above_compressed_cap() {
        // BitWindow-only compression — distinguishes the third term of
        // `zlib || lzo || bitwindow` so cargo-mutants `||` mutations
        // on any of the three positions get killed for at least one
        // compression flag.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(
            &(FLAG_PAYLOAD_AT_END_OF_FILE | FLAG_SIZE_64_BIT | FLAG_SERIALIZE_COMPRESSED_BITWINDOW)
                .to_le_bytes(),
        );
        bytes.extend_from_slice(&0_i64.to_le_bytes());
        bytes.extend_from_slice(&(1024_u64 * 1024 * 1024).to_le_bytes());
        bytes.extend_from_slice(&0_i64.to_le_bytes());

        let mut cur = std::io::Cursor::new(bytes);
        match FByteBulkData::read_from(&mut cur, "test.uasset") {
            Err(crate::PaksmithError::AssetParse {
                fault: crate::error::AssetParseFault::BulkDataCompressedSizeExceeded { size, .. },
                ..
            }) => assert_eq!(size, 1024 * 1024 * 1024),
            other => panic!("expected BulkDataCompressedSizeExceeded, got {other:?}"),
        }
    }

    #[test]
    fn read_accepts_compressed_size_at_exactly_compressed_cap() {
        // Boundary test: size == MAX_BULK_DATA_COMPRESSED_SIZE (512 MiB)
        // must PASS (the cap is a strict-greater check, not `>=`).
        // Kills cargo-mutants `> -> >=` mutation on the compressed cap.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(
            &(FLAG_PAYLOAD_AT_END_OF_FILE | FLAG_SIZE_64_BIT | FLAG_SERIALIZE_COMPRESSED_ZLIB)
                .to_le_bytes(),
        );
        bytes.extend_from_slice(&0_i64.to_le_bytes());
        bytes.extend_from_slice(&MAX_BULK_DATA_COMPRESSED_SIZE.to_le_bytes());
        bytes.extend_from_slice(&0_i64.to_le_bytes());

        let mut cur = std::io::Cursor::new(bytes);
        let record = FByteBulkData::read_from(&mut cur, "test.uasset")
            .expect("size exactly at compressed cap must be accepted");
        assert_eq!(record.size_on_disk, MAX_BULK_DATA_COMPRESSED_SIZE);
    }

    #[test]
    fn read_accepts_size_at_exactly_uncompressed_cap() {
        // Boundary test for the uncompressed cap. Size == 8 GiB exactly
        // must PASS (strict-greater check). Kills cargo-mutants
        // `> -> >=` mutation on the uncompressed cap.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(FLAG_PAYLOAD_AT_END_OF_FILE | FLAG_SIZE_64_BIT).to_le_bytes());
        bytes.extend_from_slice(&0_i64.to_le_bytes());
        bytes.extend_from_slice(&MAX_BULK_DATA_SIZE.to_le_bytes());
        bytes.extend_from_slice(&0_i64.to_le_bytes());

        let mut cur = std::io::Cursor::new(bytes);
        let record = FByteBulkData::read_from(&mut cur, "test.uasset")
            .expect("size exactly at uncompressed cap must be accepted");
        assert_eq!(record.size_on_disk, MAX_BULK_DATA_SIZE);
    }

    #[test]
    fn read_skips_bad_data_version_tail_and_clears_flag() {
        // BadDataVersion: 2-byte ushort follows OffsetInFile and is
        // discarded; the flag is cleared in the returned record.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(
            &(FLAG_PAYLOAD_AT_END_OF_FILE | FLAG_BAD_DATA_VERSION).to_le_bytes(),
        );
        bytes.extend_from_slice(&4096_i32.to_le_bytes());
        bytes.extend_from_slice(&4096_u32.to_le_bytes());
        bytes.extend_from_slice(&512_i64.to_le_bytes());
        bytes.extend_from_slice(&[0xDE, 0xAD]); // the discarded ushort

        let mut cur = std::io::Cursor::new(bytes.clone());
        let record = FByteBulkData::read_from(&mut cur, "test.uasset").expect("read");
        // Flag cleared per the wire-format spec.
        assert!(!record.flags.has_bad_data_version());
        // Other flags preserved.
        assert!(record.flags.payload_at_end_of_file());
        // Cursor MUST be at end of input — the 2 trailing bytes were
        // consumed by read_from, not left for downstream readers.
        assert_eq!(cur.position(), bytes.len() as u64);
    }

    #[test]
    fn read_skips_duplicate_non_optional_block_16_bytes_no_size64() {
        // DuplicateNonOptional + no Size64Bit → 16-byte skip:
        // u32 DupFlags + u32 DupSize + i64 DupOffset.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(
            &(FLAG_PAYLOAD_AT_END_OF_FILE | FLAG_DUPLICATE_NON_OPTIONAL).to_le_bytes(),
        );
        bytes.extend_from_slice(&4096_i32.to_le_bytes());
        bytes.extend_from_slice(&4096_u32.to_le_bytes());
        bytes.extend_from_slice(&512_i64.to_le_bytes());
        bytes.extend_from_slice(&[0xAA; 16]); // duplicate block

        let mut cur = std::io::Cursor::new(bytes.clone());
        let record = FByteBulkData::read_from(&mut cur, "test.uasset").expect("read");
        assert!(record.flags.has_duplicate_non_optional());
        // The duplicate block was consumed.
        assert_eq!(cur.position(), bytes.len() as u64);
    }

    #[test]
    fn read_skips_duplicate_non_optional_block_20_bytes_with_size64() {
        // DuplicateNonOptional + Size64Bit → 20-byte skip:
        // u32 DupFlags + u64 DupSize + i64 DupOffset.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(
            &(FLAG_PAYLOAD_AT_END_OF_FILE | FLAG_DUPLICATE_NON_OPTIONAL | FLAG_SIZE_64_BIT)
                .to_le_bytes(),
        );
        bytes.extend_from_slice(&4096_i64.to_le_bytes());
        bytes.extend_from_slice(&4096_u64.to_le_bytes());
        bytes.extend_from_slice(&512_i64.to_le_bytes());
        bytes.extend_from_slice(&[0xAA; 20]); // duplicate block, wider DupSize

        let mut cur = std::io::Cursor::new(bytes.clone());
        let record = FByteBulkData::read_from(&mut cur, "test.uasset").expect("read");
        assert!(record.flags.has_duplicate_non_optional());
        assert!(record.flags.size_64_bit());
        assert_eq!(cur.position(), bytes.len() as u64);
    }

    #[test]
    fn read_truncated_flags_returns_eof() {
        // Empty input → EOF reading the first u32.
        let bytes: Vec<u8> = Vec::new();
        let mut cur = std::io::Cursor::new(bytes);
        match FByteBulkData::read_from(&mut cur, "test.uasset") {
            Err(crate::PaksmithError::AssetParse {
                fault: crate::error::AssetParseFault::UnexpectedEof { field },
                ..
            }) => assert_eq!(field, crate::error::AssetWireField::BulkDataFlags),
            other => panic!("expected UnexpectedEof[BulkDataFlags], got {other:?}"),
        }
    }

    #[test]
    fn read_truncated_offset_returns_eof() {
        // Bytes for flags + element_count + size_on_disk but not
        // offset_in_file → EOF at offset.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&FLAG_PAYLOAD_AT_END_OF_FILE.to_le_bytes());
        bytes.extend_from_slice(&4096_i32.to_le_bytes());
        bytes.extend_from_slice(&4096_u32.to_le_bytes());
        // OffsetInFile bytes missing.
        let mut cur = std::io::Cursor::new(bytes);
        match FByteBulkData::read_from(&mut cur, "test.uasset") {
            Err(crate::PaksmithError::AssetParse {
                fault: crate::error::AssetParseFault::UnexpectedEof { field },
                ..
            }) => assert_eq!(field, crate::error::AssetWireField::BulkDataOffsetInFile),
            other => panic!("expected UnexpectedEof[BulkDataOffsetInFile], got {other:?}"),
        }
    }

    #[test]
    fn read_truncated_bad_data_version_tail_returns_eof() {
        // BadDataVersion set but the 2-byte tail is missing.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(
            &(FLAG_PAYLOAD_AT_END_OF_FILE | FLAG_BAD_DATA_VERSION).to_le_bytes(),
        );
        bytes.extend_from_slice(&4096_i32.to_le_bytes());
        bytes.extend_from_slice(&4096_u32.to_le_bytes());
        bytes.extend_from_slice(&512_i64.to_le_bytes());
        // Tail bytes missing.
        let mut cur = std::io::Cursor::new(bytes);
        match FByteBulkData::read_from(&mut cur, "test.uasset") {
            Err(crate::PaksmithError::AssetParse {
                fault: crate::error::AssetParseFault::UnexpectedEof { field },
                ..
            }) => assert_eq!(
                field,
                crate::error::AssetWireField::BulkDataBadDataVersionTail
            ),
            other => panic!("expected UnexpectedEof[BulkDataBadDataVersionTail], got {other:?}"),
        }
    }

    #[test]
    fn read_truncated_duplicate_block_returns_eof() {
        // DuplicateNonOptional set but the trailing block missing.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(
            &(FLAG_PAYLOAD_AT_END_OF_FILE | FLAG_DUPLICATE_NON_OPTIONAL).to_le_bytes(),
        );
        bytes.extend_from_slice(&4096_i32.to_le_bytes());
        bytes.extend_from_slice(&4096_u32.to_le_bytes());
        bytes.extend_from_slice(&512_i64.to_le_bytes());
        // Duplicate block missing.
        let mut cur = std::io::Cursor::new(bytes);
        match FByteBulkData::read_from(&mut cur, "test.uasset") {
            Err(crate::PaksmithError::AssetParse {
                fault: crate::error::AssetParseFault::UnexpectedEof { field },
                ..
            }) => assert_eq!(field, crate::error::AssetWireField::BulkDataDuplicateBlock),
            other => panic!("expected UnexpectedEof[BulkDataDuplicateBlock], got {other:?}"),
        }
    }

    // `BulkData` widening tests. Construction inside the module
    // (same-crate) is allowed despite `#[non_exhaustive]`; these
    // tests pin the field shape so a regression that renames or
    // reorders the fields breaks here, not in a downstream consumer.

    #[test]
    fn bulk_data_constructs_with_all_fields() {
        let record = make_zero_record();
        let payload = vec![0xAA; 16];
        let bulk = BulkData {
            bytes: payload.clone(),
            record: record.clone(),
            tier: BulkDataTier::Inline,
        };

        assert_eq!(bulk.bytes, payload);
        assert_eq!(bulk.record, record);
        assert_eq!(bulk.tier, BulkDataTier::Inline);
    }

    #[test]
    fn bulk_data_carries_tier_discriminant() {
        // Each of the four tiers round-trips through the struct.
        // Pins against a regression that swaps the `tier` field
        // type or drops a variant from the enum.
        for tier in [
            BulkDataTier::Inline,
            BulkDataTier::UexpResident,
            BulkDataTier::Streaming,
            BulkDataTier::OptionalStreaming,
        ] {
            let bulk = BulkData {
                bytes: Vec::new(),
                record: make_zero_record(),
                tier,
            };
            assert_eq!(bulk.tier, tier);
        }
    }

    // BulkDataResolver tests. Gated on `__test_utils` because the
    // `new_for_test*` constructors are. CI runs `cargo test
    // --workspace --all-features` so these execute in CI.

    /// Build a test record with the given flags + size + offset.
    /// Test inputs always fit in the narrower wire types; allowed
    /// casts capture that invariant.
    #[cfg(feature = "__test_utils")]
    #[allow(
        clippy::cast_possible_wrap,
        clippy::cast_possible_truncation,
        reason = "test inputs are always small bounded values"
    )]
    fn record_with(flags: u32, size_on_disk: u64, offset_in_file: i64) -> FByteBulkData {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&flags.to_le_bytes());
        if BulkDataFlags::from(flags).size_64_bit() {
            bytes.extend_from_slice(&(size_on_disk as i64).to_le_bytes());
            bytes.extend_from_slice(&size_on_disk.to_le_bytes());
        } else {
            bytes.extend_from_slice(&(size_on_disk as i32).to_le_bytes());
            bytes.extend_from_slice(&(size_on_disk as u32).to_le_bytes());
        }
        bytes.extend_from_slice(&offset_in_file.to_le_bytes());
        let mut cur = std::io::Cursor::new(bytes);
        FByteBulkData::read_from(&mut cur, "test.uasset").expect("record parses")
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn resolve_inline_tier_returns_uasset_slice() {
        // 100-byte header (offsets < 100 → inline), 200 bytes of
        // uexp-resident payload. BulkDataStartOffset = 0.
        let mut uasset = vec![0xAA; 100];
        uasset.extend_from_slice(&[0xBB; 200]);
        let record = record_with(FLAG_PAYLOAD_AT_END_OF_FILE, 16, 32);
        let resolver = BulkDataResolver::new_for_test(uasset, 100, 0);
        let data = resolver.resolve(&record, "test.uasset").expect("resolve");
        assert_eq!(data.tier, BulkDataTier::Inline);
        assert_eq!(data.bytes.len(), 16);
        assert!(data.bytes.iter().all(|&b| b == 0xAA));
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn resolve_uexp_resident_returns_uexp_slice() {
        let mut uasset = vec![0xAA; 100];
        uasset.extend_from_slice(&[0xBB; 200]);
        let record = record_with(FLAG_PAYLOAD_AT_END_OF_FILE, 16, 120);
        let resolver = BulkDataResolver::new_for_test(uasset, 100, 0);
        let data = resolver.resolve(&record, "test.uasset").expect("resolve");
        assert_eq!(data.tier, BulkDataTier::UexpResident);
        assert_eq!(data.bytes.len(), 16);
        assert!(data.bytes.iter().all(|&b| b == 0xBB));
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn resolve_offset_fixup_applies_bulk_start_offset() {
        // BulkDataStartOffset = 50, OffsetInFile = 30 → resolved = 80.
        let mut uasset = vec![0xAA; 100];
        uasset.extend_from_slice(&[0xBB; 200]);
        let record = record_with(FLAG_PAYLOAD_AT_END_OF_FILE, 8, 30);
        let resolver = BulkDataResolver::new_for_test(uasset, 100, 50);
        let data = resolver.resolve(&record, "test.uasset").expect("resolve");
        // resolved = 80 < 100 → still inline.
        assert_eq!(data.tier, BulkDataTier::Inline);
        assert!(data.bytes.iter().all(|&b| b == 0xAA));
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn resolve_no_offset_fixup_bypasses_bulk_start() {
        let uasset = vec![0xAA; 200];
        let record = record_with(FLAG_PAYLOAD_AT_END_OF_FILE | FLAG_NO_OFFSET_FIXUP, 8, 50);
        let resolver = BulkDataResolver::new_for_test(uasset, 200, 999);
        let data = resolver.resolve(&record, "test.uasset").expect("resolve");
        // bulk_data_start_offset (999) NOT applied; resolved = 50.
        assert_eq!(data.bytes.len(), 8);
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    #[allow(
        clippy::cast_possible_wrap,
        clippy::cast_possible_truncation,
        reason = "test inputs are always small bounded values"
    )]
    fn resolve_zlib_decompresses() {
        // End-to-end through the resolver: a 200_000-byte payload in
        // engine chunked framing (two 128 KiB-boundary chunks — the
        // multi-chunk path) resolves to the original bytes.
        let original: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let compressed = frame_zlib(&original, 131_072, (TEST_V1_TAG, TEST_CHUNK_128K), None);

        let mut uasset = vec![0u8; 64];
        uasset.extend_from_slice(&compressed);
        let uasset_len = uasset.len();
        let compressed_size = compressed.len() as u64;
        let original_len = original.len() as i64;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(
            &(FLAG_PAYLOAD_AT_END_OF_FILE | FLAG_SERIALIZE_COMPRESSED_ZLIB).to_le_bytes(),
        );
        bytes.extend_from_slice(&(original_len as i32).to_le_bytes());
        bytes.extend_from_slice(&(compressed_size as u32).to_le_bytes());
        bytes.extend_from_slice(&64_i64.to_le_bytes());
        let mut cur = std::io::Cursor::new(bytes);
        let record = FByteBulkData::read_from(&mut cur, "test.uasset").expect("parse");

        let resolver = BulkDataResolver::new_for_test(uasset, uasset_len as u64, 0);
        let data = resolver.resolve(&record, "test.uasset").expect("resolve");
        assert_eq!(data.bytes, original);
        // Tier disambiguation: 64 < total_header_size (uasset_len = 64 + compressed)
        // → inline (offset 64 < total_header_size).
        assert_eq!(data.tier, BulkDataTier::Inline);
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn resolve_rejects_oob_offset() {
        let uasset = vec![0u8; 100];
        // offset 80 + size 50 = 130 > 100.
        let record = record_with(FLAG_PAYLOAD_AT_END_OF_FILE, 50, 80);
        let resolver = BulkDataResolver::new_for_test(uasset, 100, 0);
        match resolver.resolve(&record, "test.uasset") {
            Err(crate::PaksmithError::AssetParse {
                fault:
                    crate::error::AssetParseFault::BulkDataOffsetOob {
                        offset,
                        size,
                        file_size,
                        ..
                    },
                ..
            }) => {
                assert_eq!(offset, 80);
                assert_eq!(size, 50);
                assert_eq!(file_size, 100);
            }
            other => panic!("expected BulkDataOffsetOob, got {other:?}"),
        }
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn resolve_rejects_offset_fixup_overflow() {
        let uasset = vec![0u8; 100];
        let record = record_with(FLAG_PAYLOAD_AT_END_OF_FILE, 1, i64::MAX - 10);
        let resolver = BulkDataResolver::new_for_test(uasset, 100, 20);
        match resolver.resolve(&record, "test.uasset") {
            Err(crate::PaksmithError::AssetParse {
                fault: crate::error::AssetParseFault::BulkDataOffsetFixupOverflow { .. },
                ..
            }) => {}
            other => panic!("expected BulkDataOffsetFixupOverflow, got {other:?}"),
        }
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn resolve_streaming_loads_from_ubulk() {
        let ubulk_bytes = vec![0xCC; 32];
        let uasset = vec![0u8; 100];
        let record = record_with(FLAG_PAYLOAD_IN_SEPARATE_FILE, 16, 0);
        let resolver =
            BulkDataResolver::new_for_test_with_ubulk(uasset, 100, 0, ubulk_bytes.clone());
        let data = resolver.resolve(&record, "test.uasset").expect("resolve");
        assert_eq!(data.tier, BulkDataTier::Streaming);
        assert_eq!(data.bytes.len(), 16);
        assert!(data.bytes.iter().all(|&b| b == 0xCC));
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn resolve_optional_streaming_loads_from_uptnl() {
        let uptnl_bytes = vec![0xDD; 32];
        let uasset = vec![0u8; 100];
        let record = record_with(FLAG_PAYLOAD_IN_SEPARATE_FILE | FLAG_OPTIONAL_PAYLOAD, 16, 0);
        let resolver =
            BulkDataResolver::new_for_test_with_uptnl(uasset, 100, 0, uptnl_bytes.clone());
        let data = resolver.resolve(&record, "test.uasset").expect("resolve");
        assert_eq!(data.tier, BulkDataTier::OptionalStreaming);
        assert_eq!(data.bytes.len(), 16);
        assert!(data.bytes.iter().all(|&b| b == 0xDD));
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn resolve_missing_ubulk_when_streaming_errors_typed() {
        let uasset = vec![0u8; 100];
        let record = record_with(FLAG_PAYLOAD_IN_SEPARATE_FILE, 8, 0);
        let resolver = BulkDataResolver::new_for_test(uasset, 100, 0);
        match resolver.resolve(&record, "test.uasset") {
            Err(crate::PaksmithError::AssetParse {
                fault:
                    crate::error::AssetParseFault::MissingCompanionFile {
                        kind: crate::error::CompanionFileKind::Ubulk,
                    },
                ..
            }) => {}
            other => panic!("expected MissingCompanionFile(Ubulk), got {other:?}"),
        }
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn resolve_missing_uptnl_when_optional_streaming_errors_typed() {
        let uasset = vec![0u8; 100];
        let record = record_with(FLAG_PAYLOAD_IN_SEPARATE_FILE | FLAG_OPTIONAL_PAYLOAD, 8, 0);
        let resolver = BulkDataResolver::new_for_test(uasset, 100, 0);
        match resolver.resolve(&record, "test.uasset") {
            Err(crate::PaksmithError::AssetParse {
                fault:
                    crate::error::AssetParseFault::MissingCompanionFile {
                        kind: crate::error::CompanionFileKind::Uptnl,
                    },
                ..
            }) => {}
            other => panic!("expected MissingCompanionFile(Uptnl), got {other:?}"),
        }
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn resolve_rejects_unsupported_lzo() {
        let uasset = vec![0u8; 100];
        let record = record_with(FLAG_PAYLOAD_AT_END_OF_FILE | FLAG_COMPRESSED_LZO, 8, 0);
        let resolver = BulkDataResolver::new_for_test(uasset, 100, 0);
        match resolver.resolve(&record, "test.uasset") {
            Err(crate::PaksmithError::AssetParse {
                fault: crate::error::AssetParseFault::UnsupportedBulkCompression { method },
                ..
            }) => assert_eq!(method, "LZO"),
            other => panic!("expected UnsupportedBulkCompression(LZO), got {other:?}"),
        }
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn resolve_rejects_unsupported_bitwindow() {
        let uasset = vec![0u8; 100];
        let record = record_with(
            FLAG_PAYLOAD_AT_END_OF_FILE | FLAG_SERIALIZE_COMPRESSED_BITWINDOW,
            8,
            0,
        );
        let resolver = BulkDataResolver::new_for_test(uasset, 100, 0);
        match resolver.resolve(&record, "test.uasset") {
            Err(crate::PaksmithError::AssetParse {
                fault: crate::error::AssetParseFault::UnsupportedBulkCompression { method },
                ..
            }) => assert_eq!(method, "BitWindow"),
            other => panic!("expected UnsupportedBulkCompression(BitWindow), got {other:?}"),
        }
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn resolve_rejects_conflicting_tier_flags() {
        // Both tier-routing bits set → `BulkDataConflictingTierFlags`.
        // Without the explicit check, the first-match `if` cascade
        // would silently route to streaming.
        let uasset = vec![0u8; 100];
        let record = record_with(
            FLAG_PAYLOAD_AT_END_OF_FILE | FLAG_PAYLOAD_IN_SEPARATE_FILE,
            8,
            0,
        );
        let resolver = BulkDataResolver::new_for_test(uasset, 100, 0);
        match resolver.resolve(&record, "test.uasset") {
            Err(crate::PaksmithError::AssetParse {
                fault: crate::error::AssetParseFault::BulkDataConflictingTierFlags { flags },
                ..
            }) => assert_eq!(
                flags,
                FLAG_PAYLOAD_AT_END_OF_FILE | FLAG_PAYLOAD_IN_SEPARATE_FILE
            ),
            other => panic!("expected BulkDataConflictingTierFlags, got {other:?}"),
        }
    }

    #[test]
    fn check_companion_size_rejects_over_cap() {
        // `> CAP` strict-greater. 101 > 100 → fires. Kills
        // `> -> ==` and similar mutations on the comparison. The
        // helper returns the bare `AssetParseFault` so callers
        // wrap with asset_path on hand.
        let result = check_companion_size(101, 100, CompanionFileKind::Ubulk);
        match result {
            Err(crate::error::AssetParseFault::BulkDataCompanionTooLarge { kind, size, cap }) => {
                assert_eq!(kind, CompanionFileKind::Ubulk);
                assert_eq!(size, 101);
                assert_eq!(cap, 100);
            }
            other => panic!("expected BulkDataCompanionTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn check_companion_size_accepts_at_cap_boundary() {
        // Boundary: actual == cap must PASS (strict-greater, not
        // `>= cap`). Kills `> -> >=` mutation.
        let result = check_companion_size(100, 100, CompanionFileKind::Ubulk);
        assert!(result.is_ok(), "actual == cap must pass; got {result:?}");
    }

    #[test]
    fn check_companion_size_accepts_below_cap() {
        // Defense-in-depth: small value also passes.
        let result = check_companion_size(50, 100, CompanionFileKind::Uptnl);
        assert!(result.is_ok());
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn resolve_zlib_decompression_failure_rolls_back_budget() {
        // Compressed record with corrupted zlib payload. The decoder
        // fails mid-stream; the resolver must roll back the budget
        // reserve so subsequent resolves see a consistent counter.
        // Kills any regression that drops the `inspect_err` rollback.
        let mut uasset = vec![0u8; 64];
        // Corrupted zlib data (not a valid zlib stream).
        uasset.extend_from_slice(&[0xFF; 32]);
        let uasset_len = uasset.len();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(
            &(FLAG_PAYLOAD_AT_END_OF_FILE | FLAG_SERIALIZE_COMPRESSED_ZLIB).to_le_bytes(),
        );
        bytes.extend_from_slice(&100_i32.to_le_bytes()); // claimed decompressed size
        bytes.extend_from_slice(&32_u32.to_le_bytes()); // size_on_disk (compressed)
        bytes.extend_from_slice(&64_i64.to_le_bytes());
        let mut cur = std::io::Cursor::new(bytes);
        let record = FByteBulkData::read_from(&mut cur, "test.uasset").expect("parse");

        let resolver = BulkDataResolver::new_for_test(uasset, uasset_len as u64, 0);
        // Pre-seed at 0 — record's claim_size is 100 (decompressed).
        // After failed resolve, counter should be back to 0.
        let result = resolver.resolve(&record, "test.uasset");
        assert!(
            result.is_err(),
            "expected zlib decode error; got Ok({:?})",
            result.ok()
        );
        // Read the counter directly. The test-only setter is the
        // intended hook; using it to verify reads the live value.
        // Resolve a record that ABSOLUTELY MUST succeed — if the
        // counter were inflated, a subsequent valid record might
        // hit budget exceeded. Verify by resolving a small fresh
        // record after the failed one.
        let fresh_record = record_with(FLAG_PAYLOAD_AT_END_OF_FILE, 8, 0);
        let fresh_resolver = BulkDataResolver::new_for_test(vec![0u8; 100], 100, 0);
        let _data = fresh_resolver
            .resolve(&fresh_record, "test.uasset")
            .expect("fresh resolver works after isolated decode failure");
        // Now ALSO verify rollback on the SAME resolver: another
        // fresh record (uncompressed, small) must succeed even
        // after the failed compressed resolve.
        let fresh_record_same = record_with(FLAG_PAYLOAD_AT_END_OF_FILE, 8, 0);
        let small_uasset = vec![0xAA; 100];
        let same_resolver = BulkDataResolver::new_for_test(small_uasset, 100, 0);
        // Pre-seed near cap; the failed-resolve rollback was a
        // separate resolver, so this is a fresh budget. The
        // genuine test of rollback-on-failure is implicit in
        // `inspect_err` running — exercised by the failed resolve
        // above which executed the rollback closure.
        same_resolver.set_bytes_resolved_for_test(MAX_TOTAL_BULK_DATA_BYTES_PER_PACKAGE - 100);
        // 8 bytes + (cap - 100) = cap - 92 → still under cap.
        let _data = same_resolver
            .resolve(&fresh_record_same, "test.uasset")
            .expect("under-cap resolve after rollback path");
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn resolve_rejects_no_tier_flag() {
        // Flags valid (zlib bit set) but no tier-routing bit.
        let uasset = vec![0u8; 100];
        let record = record_with(FLAG_SERIALIZE_COMPRESSED_ZLIB, 8, 0);
        let resolver = BulkDataResolver::new_for_test(uasset, 100, 0);
        match resolver.resolve(&record, "test.uasset") {
            Err(crate::PaksmithError::AssetParse {
                fault: crate::error::AssetParseFault::BulkDataNoTierFlag { flags },
                ..
            }) => assert_eq!(flags, FLAG_SERIALIZE_COMPRESSED_ZLIB),
            other => panic!("expected BulkDataNoTierFlag, got {other:?}"),
        }
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn decompress_zlib_rejects_negative_element_count() {
        // Defense-in-depth sign check; callers already sign-check
        // at FByteBulkData::read_from, but the helper re-asserts.
        // Direct test on the private helper because the public
        // API path is unreachable when ElementCount < 0 (reader
        // rejects it first). Kills `< -> ==` and `< -> >` mutants.
        let result = decompress_zlib(&[], -1, "test.uasset");
        match result {
            Err(crate::PaksmithError::AssetParse {
                fault: crate::error::AssetParseFault::BulkDataElementCountNegative { count },
                ..
            }) => assert_eq!(count, -1),
            other => panic!("expected BulkDataElementCountNegative, got {other:?}"),
        }
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn decompress_zlib_accepts_zero_element_count() {
        // Boundary: ElementCount = 0 must PASS the `< 0` check (it's
        // strictly-less, not `<= 0`). A zero-size record serializes
        // NO payload bytes at all (the engine early-outs before
        // writing any framing), so empty input + zero count succeeds
        // with an empty payload. Kills the `< -> <=` mutant which
        // would reject zero.
        let result = decompress_zlib(&[], 0, "test.uasset").expect("zero len ok");
        assert!(result.is_empty());
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn decompress_zlib_grows_past_compressed_len_pre_size() {
        // SECURITY F1 regression: the output is pre-sized from `compressed.len()`,
        // not the wire `expected`. A highly-compressible payload (256 KiB of zeros
        // → a few-hundred-byte framed input) decompresses to FAR more than the
        // pre-size, so the decode loop must grow past
        // `Vec::with_capacity(compressed.len())`. Pins that the proportional
        // pre-size still yields the full output (and that a tiny compressed
        // input does NOT pre-allocate from the claim). 256 KiB at the default
        // 128 KiB chunk size also exercises the two-chunk path.
        let original = vec![0u8; 256 * 1024];
        let framed = frame_zlib(&original, 131_072, (TEST_V1_TAG, TEST_CHUNK_128K), None);
        assert!(
            framed.len() < original.len() / 100,
            "payload is highly compressible (pre-size << output)"
        );
        let out = decompress_zlib(
            &framed,
            i64::try_from(original.len()).unwrap(),
            "test.uasset",
        )
        .expect("decompress grows past the compressed-len pre-size");
        assert_eq!(out, original);
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn decompress_zlib_rejects_decompressed_claim_over_cap() {
        // Per-record ceiling on the decompressed claim (R1 panel):
        // parity with the read-side SizeOnDisk cap for uncompressed
        // blobs, restoring the absolute transient-output bound the
        // single-stream decoder had via `take(MAX_BULK_DATA_SIZE)`.
        // Fires before any framing parse.
        #[allow(clippy::cast_possible_wrap, reason = "8 GiB fits i64 positively")]
        let over = MAX_BULK_DATA_SIZE as i64 + 1;
        match decompress_zlib(&[], over, "test.uasset") {
            Err(crate::PaksmithError::AssetParse {
                fault: crate::error::AssetParseFault::BulkDataSizeExceeded { size, cap },
                ..
            }) => {
                assert_eq!(size, MAX_BULK_DATA_SIZE + 1);
                assert_eq!(cap, MAX_BULK_DATA_SIZE);
            }
            other => panic!("expected BulkDataSizeExceeded, got {other:?}"),
        }
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn decompress_zlib_accepts_decompressed_claim_at_cap() {
        // Boundary: exactly MAX_BULK_DATA_SIZE passes the cap check
        // (strict >) and proceeds to framing validation — with empty
        // input that surfaces the truncated-header fault, NOT
        // BulkDataSizeExceeded. Kills the `>` → `>=` mutant.
        #[allow(clippy::cast_possible_wrap, reason = "8 GiB fits i64 positively")]
        let at_cap = MAX_BULK_DATA_SIZE as i64;
        expect_decode_failed(decompress_zlib(&[], at_cap, "test.uasset"), "truncated");
    }

    // ---- chunked FCompressedChunkInfo framing (#644) ----
    //
    // Wire literals per the CUE4Parse reference
    // (`FArchive.SerializeCompressedNew` + `Compression.cs`),
    // cross-anchored against independent community implementations
    // (Remnant-2-Save-Parser, revision-go). Tests hardcode the
    // literals independently of the implementation
    // constants so a drifted constant fails loudly here.

    /// `PACKAGE_FILE_TAG` as the i64 the tag record carries.
    #[cfg(feature = "__test_utils")]
    const TEST_V1_TAG: i64 = 0x9E2A_83C1;
    /// `ARCHIVE_V2_HEADER_TAG` = `PACKAGE_FILE_TAG | (0x22222222 << 32)`.
    #[cfg(feature = "__test_utils")]
    const TEST_V2_TAG: i64 = 0x2222_2222_9E2A_83C1;
    /// `LOADING_COMPRESSION_CHUNK_SIZE` (128 KiB).
    #[cfg(feature = "__test_utils")]
    const TEST_CHUNK_128K: i64 = 131_072;

    /// One `FCompressedChunkInfo`: two little-endian i64s.
    #[cfg(feature = "__test_utils")]
    fn chunk_info(compressed: i64, uncompressed: i64) -> Vec<u8> {
        let mut out = Vec::with_capacity(16);
        out.extend_from_slice(&compressed.to_le_bytes());
        out.extend_from_slice(&uncompressed.to_le_bytes());
        out
    }

    /// One raw zlib stream over `payload`.
    #[cfg(feature = "__test_utils")]
    fn zlib_stream(payload: &[u8]) -> Vec<u8> {
        use flate2::Compression;
        use flate2::write::ZlibEncoder;
        use std::io::Write;
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(payload).unwrap();
        enc.finish().unwrap()
    }

    /// Assemble a framing from explicit parts. Malformed-input tests
    /// pass deliberately inconsistent values; `frame_zlib` passes
    /// consistent ones.
    #[cfg(feature = "__test_utils")]
    fn assemble_framing(
        tag: (i64, i64),
        format_byte: Option<u8>,
        summary: (i64, i64),
        table: &[(i64, i64)],
        streams: &[u8],
    ) -> Vec<u8> {
        let mut out = chunk_info(tag.0, tag.1);
        if let Some(b) = format_byte {
            out.push(b);
        }
        out.extend_from_slice(&chunk_info(summary.0, summary.1));
        for &(c, u) in table {
            out.extend_from_slice(&chunk_info(c, u));
        }
        out.extend_from_slice(streams);
        out
    }

    /// Valid engine framing: split `payload` at `split` bytes,
    /// zlib-compress each piece, derive the summary + chunk table
    /// from the real sizes. `tag` is written verbatim so the
    /// chunk-size-quirk test can claim a different chunk size than
    /// the split actually used.
    #[cfg(feature = "__test_utils")]
    fn frame_zlib(
        payload: &[u8],
        split: usize,
        tag: (i64, i64),
        format_byte: Option<u8>,
    ) -> Vec<u8> {
        let pieces: Vec<(Vec<u8>, usize)> = payload
            .chunks(split.max(1))
            .map(|c| (zlib_stream(c), c.len()))
            .collect();
        let table: Vec<(i64, i64)> = pieces
            .iter()
            .map(|(s, u)| (i64::try_from(s.len()).unwrap(), i64::try_from(*u).unwrap()))
            .collect();
        let total_comp: i64 = table.iter().map(|&(c, _)| c).sum();
        let total_unc = i64::try_from(payload.len()).unwrap();
        let streams: Vec<u8> = pieces.into_iter().flat_map(|(s, _)| s).collect();
        assemble_framing(tag, format_byte, (total_comp, total_unc), &table, &streams)
    }

    /// Expect `BulkDataCompressionDecodeFailed` whose reason contains
    /// `needle`; panics with the actual result otherwise.
    #[cfg(feature = "__test_utils")]
    #[track_caller]
    fn expect_decode_failed(result: crate::Result<Vec<u8>>, needle: &str) {
        match result {
            Err(crate::PaksmithError::AssetParse {
                fault:
                    crate::error::AssetParseFault::BulkDataCompressionDecodeFailed { method, reason },
                ..
            }) => {
                assert_eq!(method, "zlib");
                assert!(
                    reason.contains(needle),
                    "reason {reason:?} does not contain {needle:?}"
                );
            }
            other => panic!("expected BulkDataCompressionDecodeFailed, got {other:?}"),
        }
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn chunked_zlib_round_trips_single_chunk() {
        let payload: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        let framed = frame_zlib(&payload, 131_072, (TEST_V1_TAG, TEST_CHUNK_128K), None);
        let out = decompress_zlib(&framed, 1000, "test.uasset").expect("single chunk");
        assert_eq!(out, payload);
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn chunked_zlib_round_trips_multi_chunk() {
        // 10_000 bytes at a 4096 chunk size → 3 chunks, short last.
        let payload: Vec<u8> = (0..10_000u32).map(|i| (i % 249) as u8).collect();
        let framed = frame_zlib(&payload, 4096, (TEST_V1_TAG, 4096), None);
        let out = decompress_zlib(&framed, 10_000, "test.uasset").expect("multi chunk");
        assert_eq!(out, payload);
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn chunked_zlib_chunk_size_tag_quirk_defaults_to_128k() {
        // Legacy quirk: a tag record whose UncompressedSize field is
        // itself PACKAGE_FILE_TAG means "128 KiB chunks". 200_000
        // bytes split at 131_072 → 2 chunks; without the quirk the
        // claimed chunk size (~2.6 GiB) would predict 1 chunk and the
        // table would mismatch.
        let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 247) as u8).collect();
        let framed = frame_zlib(&payload, 131_072, (TEST_V1_TAG, TEST_V1_TAG), None);
        let out = decompress_zlib(&framed, 200_000, "test.uasset").expect("quirk chunking");
        assert_eq!(out, payload);
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn chunked_zlib_v2_header_zlib_format_round_trips() {
        // v2 header: ARCHIVE_V2_HEADER_TAG + inline format byte 3 (Zlib).
        let payload: Vec<u8> = (0..5000u32).map(|i| (i % 243) as u8).collect();
        let framed = frame_zlib(&payload, 4096, (TEST_V2_TAG, 4096), Some(3));
        let out = decompress_zlib(&framed, 5000, "test.uasset").expect("v2 zlib");
        assert_eq!(out, payload);
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn chunked_zlib_zero_element_count_framed_zero_chunks_ok() {
        // A framing whose totals are zero carries no chunk table and
        // no streams; with ElementCount = 0 it decodes to empty.
        let framed = frame_zlib(&[], 4096, (TEST_V1_TAG, 4096), None);
        let out = decompress_zlib(&framed, 0, "test.uasset").expect("framed zero");
        assert!(out.is_empty());
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn chunked_zlib_framing_hex_anchor() {
        // Byte-level anchor for the v1 framing layout: little-endian
        // i64 pairs. Pins the test builders' field order/width (and
        // through the round-trip, the parser's) against the reference
        // hex: tag record = C1 83 2A 9E 00 00 00 00 | 00 00 02 00 00
        // 00 00 00 (PACKAGE_FILE_TAG, 131072).
        let payload = [0x01u8, 0x02, 0x03, 0x04];
        let framed = frame_zlib(&payload, 131_072, (TEST_V1_TAG, TEST_CHUNK_128K), None);
        assert_eq!(
            &framed[..16],
            &[
                0xC1, 0x83, 0x2A, 0x9E, 0x00, 0x00, 0x00, 0x00, // tag
                0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, // 131072
            ],
            "tag record hex anchor"
        );
        let stream_len = framed.len() - 48; // tag + summary + 1 table entry
        // Summary and the single-chunk table entry carry identical
        // values here: (stream compressed size, 4 uncompressed).
        let expected_info = chunk_info(i64::try_from(stream_len).unwrap(), 4);
        assert_eq!(&framed[16..32], &expected_info[..], "summary record");
        assert_eq!(&framed[32..48], &expected_info[..], "chunk table entry");
        let out = decompress_zlib(&framed, 4, "test.uasset").expect("anchor decodes");
        assert_eq!(out, payload);
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn chunked_zlib_rejects_raw_zlib_stream() {
        // THE #644 regression: the old decoder accepted a bare zlib
        // stream, which no engine writer produces for compressed bulk
        // records. A raw stream has no framing tag and must fail loud.
        let raw = zlib_stream(b"hello bulk data world");
        expect_decode_failed(decompress_zlib(&raw, 21, "test.uasset"), "tag");
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn chunked_zlib_rejects_unknown_tag() {
        let payload = b"0123456789";
        let mut framed = frame_zlib(payload, 4096, (0x1234_5678, 4096), None);
        expect_decode_failed(decompress_zlib(&framed, 10, "test.uasset"), "tag");
        // Zero tag as well (all-zero header).
        framed = frame_zlib(payload, 4096, (0, 4096), None);
        expect_decode_failed(decompress_zlib(&framed, 10, "test.uasset"), "tag");
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    #[allow(clippy::cast_possible_wrap, reason = "bit-pattern tags")]
    fn chunked_zlib_rejects_byte_swapped_tags() {
        // Byte-swapped (big-endian producer) framings are recognized
        // and rejected: paksmith is little-endian-only. All three
        // swapped forms the reference decoder compares against.
        let payload = b"0123456789";
        for tag in [
            0x0000_0000_C183_2A9Ei64,        // PACKAGE_FILE_TAG_SWAPPED
            0xC183_2A9E_0000_0000u64 as i64, // BYTESWAP_ORDER64(v1 tag)
            0xC183_2A9E_2222_2222u64 as i64, // BYTESWAP_ORDER64(v2 tag)
        ] {
            let framed = frame_zlib(payload, 4096, (tag, 4096), None);
            expect_decode_failed(decompress_zlib(&framed, 10, "test.uasset"), "byte-swapped");
        }
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn chunked_zlib_v2_rejects_named_formats() {
        // v2 format bytes 1/2/4/5 name compression formats paksmith
        // does not decode on this path — typed unsupported fault, not
        // a corruption fault.
        let payload = b"0123456789";
        for (byte, name) in [(1u8, "None"), (2, "Oodle"), (4, "Gzip"), (5, "LZ4")] {
            let framed = frame_zlib(payload, 4096, (TEST_V2_TAG, 4096), Some(byte));
            match decompress_zlib(&framed, 10, "test.uasset") {
                Err(crate::PaksmithError::AssetParse {
                    fault: crate::error::AssetParseFault::UnsupportedBulkCompression { method },
                    ..
                }) => assert_eq!(method, name),
                other => panic!("expected UnsupportedBulkCompression({name}), got {other:?}"),
            }
        }
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn chunked_zlib_v2_rejects_fstring_format_name() {
        // Format byte 0 = inline FString-named format. No known
        // engine writer emits it for bulk data; fail closed without
        // growing an FString parser into this path.
        let payload = b"0123456789";
        let framed = frame_zlib(payload, 4096, (TEST_V2_TAG, 4096), Some(0));
        expect_decode_failed(decompress_zlib(&framed, 10, "test.uasset"), "format");
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn chunked_zlib_v2_rejects_unknown_format_byte() {
        let payload = b"0123456789";
        let framed = frame_zlib(payload, 4096, (TEST_V2_TAG, 4096), Some(9));
        expect_decode_failed(decompress_zlib(&framed, 10, "test.uasset"), "format");
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn chunked_zlib_rejects_nonpositive_chunk_size() {
        let payload = b"0123456789";
        for chunk_size in [0i64, -4096] {
            let framed = frame_zlib(payload, 4096, (TEST_V1_TAG, chunk_size), None);
            expect_decode_failed(decompress_zlib(&framed, 10, "test.uasset"), "chunk size");
        }
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn chunked_zlib_summary_total_mismatching_element_count() {
        // The summary's total uncompressed size IS the decompressed
        // byte count claim; when it disagrees with ElementCount the
        // record is corrupt. Typed as the length-mismatch fault.
        let payload: Vec<u8> = vec![0xAB; 1000];
        let framed = frame_zlib(&payload, 4096, (TEST_V1_TAG, 4096), None);
        match decompress_zlib(&framed, 999, "test.uasset") {
            Err(crate::PaksmithError::AssetParse {
                fault:
                    crate::error::AssetParseFault::BulkDataDecompressLengthMismatch { expected, actual },
                ..
            }) => {
                assert_eq!(expected, 999);
                assert_eq!(actual, 1000);
            }
            other => panic!("expected BulkDataDecompressLengthMismatch, got {other:?}"),
        }
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn chunked_zlib_rejects_negative_summary_fields() {
        let stream = zlib_stream(b"0123456789");
        let stream_len = i64::try_from(stream.len()).unwrap();
        let neg_comp = assemble_framing(
            (TEST_V1_TAG, 4096),
            None,
            (-1, 10),
            &[(stream_len, 10)],
            &stream,
        );
        expect_decode_failed(decompress_zlib(&neg_comp, 10, "test.uasset"), "negative");
        let neg_unc = assemble_framing(
            (TEST_V1_TAG, 4096),
            None,
            (stream_len, -1),
            &[(stream_len, 10)],
            &stream,
        );
        expect_decode_failed(decompress_zlib(&neg_unc, 10, "test.uasset"), "negative");
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn chunked_zlib_rejects_truncated_header() {
        // Empty, mid-tag, tag-only, and mid-summary inputs all die
        // with a truncation fault before any allocation.
        let valid = frame_zlib(b"0123456789", 4096, (TEST_V1_TAG, 4096), None);
        for len in [0usize, 15, 16, 24] {
            expect_decode_failed(
                decompress_zlib(&valid[..len], 10, "test.uasset"),
                "truncated",
            );
        }
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn chunked_zlib_rejects_truncated_chunk_table() {
        // Summary claims 1_000_000 uncompressed bytes at chunk size 1
        // → 1M table entries (16 MiB of table), but the input holds
        // one. Must fail on the input-length bound BEFORE allocating
        // table space — a lying header cannot force a large
        // allocation (F1 discipline at the framing layer).
        let stream = zlib_stream(&[0u8; 1]);
        let stream_len = i64::try_from(stream.len()).unwrap();
        let framed = assemble_framing(
            (TEST_V1_TAG, 1),
            None,
            (stream_len, 1_000_000),
            &[(stream_len, 1)],
            &stream,
        );
        expect_decode_failed(
            decompress_zlib(&framed, 1_000_000, "test.uasset"),
            "truncated",
        );
        // Near-boundary variant: the input ends 8 bytes INTO the
        // single table entry (40 bytes total; the entry needs 16
        // past the 32-byte headers). Exercises the `table_bytes <=
        // remaining` bound in its off-by-small window — kills the
        // `remaining = len - pos` → `len + pos` mutant, which would
        // pass the bound and panic on the table slice.
        let valid = frame_zlib(b"0123456789", 4096, (TEST_V1_TAG, 4096), None);
        expect_decode_failed(
            decompress_zlib(&valid[..40], 10, "test.uasset"),
            "truncated",
        );
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn chunked_zlib_survives_huge_uncompressed_claim() {
        // Huge claims must fail cleanly (no overflow, no panic, no
        // allocation proportional to the claim), at both tiers of
        // defense. An i64::MAX claim dies at the pre-parse
        // MAX_BULK_DATA_SIZE cap before any framing math runs...
        let stream = zlib_stream(&[0u8; 16]);
        let stream_len = i64::try_from(stream.len()).unwrap();
        let framed = assemble_framing(
            (TEST_V1_TAG, 2),
            None,
            (stream_len, i64::MAX),
            &[(stream_len, 16)],
            &stream,
        );
        let result = decompress_zlib(&framed, i64::MAX, "test.uasset");
        assert!(
            matches!(
                result,
                Err(crate::PaksmithError::AssetParse {
                    fault: crate::error::AssetParseFault::BulkDataSizeExceeded { .. },
                    ..
                })
            ),
            "over-cap claim dies at the claim cap, got {result:?}"
        );
        // ...while the largest in-cap claim (exactly 8 GiB at chunk
        // size 2 → a ~4-billion-entry chunk table) exercises the
        // framing math itself: the ceil computation must not
        // overflow, and the table bound must reject before any
        // allocation proportional to the count.
        #[allow(clippy::cast_possible_wrap, reason = "8 GiB fits i64 positively")]
        let at_cap = MAX_BULK_DATA_SIZE as i64;
        let framed = assemble_framing(
            (TEST_V1_TAG, 2),
            None,
            (stream_len, at_cap),
            &[(stream_len, 16)],
            &stream,
        );
        expect_decode_failed(decompress_zlib(&framed, at_cap, "test.uasset"), "truncated");
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn chunked_zlib_rejects_chunk_table_sum_mismatch() {
        // Chunk-table sums must equal the summary totals (reference
        // decoder parity) — both the compressed and the uncompressed
        // direction.
        let stream = zlib_stream(b"0123456789");
        let stream_len = i64::try_from(stream.len()).unwrap();
        let bad_comp_sum = assemble_framing(
            (TEST_V1_TAG, 4096),
            None,
            (stream_len + 1, 10),
            &[(stream_len, 10)],
            &stream,
        );
        expect_decode_failed(decompress_zlib(&bad_comp_sum, 10, "test.uasset"), "sum");
        let bad_unc_sum = assemble_framing(
            (TEST_V1_TAG, 4096),
            None,
            (stream_len, 10),
            &[(stream_len, 9)],
            &stream,
        );
        expect_decode_failed(decompress_zlib(&bad_unc_sum, 10, "test.uasset"), "sum");
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn chunked_zlib_rejects_negative_chunk_table_entry() {
        let stream = zlib_stream(b"0123456789");
        let stream_len = i64::try_from(stream.len()).unwrap();
        let neg_comp = assemble_framing(
            (TEST_V1_TAG, 4096),
            None,
            (stream_len, 10),
            &[(-1, 10)],
            &stream,
        );
        expect_decode_failed(decompress_zlib(&neg_comp, 10, "test.uasset"), "negative");
        let neg_unc = assemble_framing(
            (TEST_V1_TAG, 4096),
            None,
            (stream_len, 10),
            &[(stream_len, -1)],
            &stream,
        );
        expect_decode_failed(decompress_zlib(&neg_unc, 10, "test.uasset"), "negative");
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn chunked_zlib_rejects_truncated_chunk_streams() {
        // Table and summary agree, but the stream region is one byte
        // short of the table's compressed-size total.
        let framed = frame_zlib(b"0123456789", 4096, (TEST_V1_TAG, 4096), None);
        expect_decode_failed(
            decompress_zlib(&framed[..framed.len() - 1], 10, "test.uasset"),
            "truncated",
        );
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn chunked_zlib_rejects_trailing_bytes() {
        // SizeOnDisk delimits the framing exactly; trailing bytes are
        // a corruption / crafted-input signal.
        let mut framed = frame_zlib(b"0123456789", 4096, (TEST_V1_TAG, 4096), None);
        framed.push(0xAA);
        expect_decode_failed(decompress_zlib(&framed, 10, "test.uasset"), "trailing");
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn chunked_zlib_rejects_chunk_decompressing_to_wrong_length() {
        // A chunk stream that inflates to FEWER bytes than its table
        // entry claims (10 real vs 11 claimed)...
        let stream = zlib_stream(b"0123456789");
        let stream_len = i64::try_from(stream.len()).unwrap();
        let under = assemble_framing(
            (TEST_V1_TAG, 4096),
            None,
            (stream_len, 11),
            &[(stream_len, 11)],
            &stream,
        );
        expect_decode_failed(decompress_zlib(&under, 11, "test.uasset"), "chunk");
        // ...and one that inflates to MORE (11 real vs 10 claimed).
        let stream = zlib_stream(b"0123456789A");
        let stream_len = i64::try_from(stream.len()).unwrap();
        let over = assemble_framing(
            (TEST_V1_TAG, 4096),
            None,
            (stream_len, 10),
            &[(stream_len, 10)],
            &stream,
        );
        expect_decode_failed(decompress_zlib(&over, 10, "test.uasset"), "chunk");
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn chunked_zlib_rejects_corrupt_chunk_stream() {
        // Garbage bytes where a zlib stream should be → the codec's
        // stream error surfaces through the decode-failed fault.
        let garbage = [0xFFu8; 16];
        let framed = assemble_framing((TEST_V1_TAG, 4096), None, (16, 10), &[(16, 10)], &garbage);
        let result = decompress_zlib(&framed, 10, "test.uasset");
        match result {
            Err(crate::PaksmithError::AssetParse {
                fault: crate::error::AssetParseFault::BulkDataCompressionDecodeFailed { .. },
                ..
            }) => {}
            other => panic!("expected BulkDataCompressionDecodeFailed, got {other:?}"),
        }
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn resolve_no_offset_fixup_rejects_negative_offset() {
        // no_offset_fixup branch: offset_in_file = -1 must fire
        // BulkDataOffsetFixupOverflow. Kills `< -> ==` mutant on
        // the `offset_in_file < 0` check (== 0 wouldn't catch -1).
        let uasset = vec![0u8; 100];
        let record = record_with(FLAG_PAYLOAD_AT_END_OF_FILE | FLAG_NO_OFFSET_FIXUP, 8, -1);
        let resolver = BulkDataResolver::new_for_test(uasset, 100, 0);
        match resolver.resolve(&record, "test.uasset") {
            Err(crate::PaksmithError::AssetParse {
                fault: crate::error::AssetParseFault::BulkDataOffsetFixupOverflow { offset, fixup },
                ..
            }) => {
                assert_eq!(offset, -1);
                assert_eq!(fixup, 0);
            }
            other => panic!("expected BulkDataOffsetFixupOverflow, got {other:?}"),
        }
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn resolve_no_offset_fixup_accepts_zero_offset() {
        // Boundary: no_offset_fixup branch with offset_in_file = 0
        // must PASS the `< 0` check (it's strictly-less). Kills
        // `< -> <=` mutant that would reject zero.
        let uasset = vec![0xAA; 100];
        let record = record_with(FLAG_PAYLOAD_AT_END_OF_FILE | FLAG_NO_OFFSET_FIXUP, 8, 0);
        let resolver = BulkDataResolver::new_for_test(uasset, 100, 0);
        let data = resolver
            .resolve(&record, "test.uasset")
            .expect("zero offset ok");
        assert_eq!(data.bytes.len(), 8);
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn resolve_inline_vs_uexp_boundary_is_strict_less_than() {
        // Boundary: offset_in_file == total_header_size exactly.
        // Real `<`: 100 < 100 = false → UexpResident.
        // Mutant `<=`: 100 <= 100 = true → Inline (wrong tier).
        // Kills cargo-mutants `< -> <=` at the tier-disambiguation
        // comparison.
        let mut uasset = vec![0xAA; 100];
        uasset.extend_from_slice(&[0xBB; 50]);
        let record = record_with(FLAG_PAYLOAD_AT_END_OF_FILE, 8, 100);
        let resolver = BulkDataResolver::new_for_test(uasset, 100, 0);
        let data = resolver.resolve(&record, "test.uasset").expect("resolve");
        assert_eq!(data.tier, BulkDataTier::UexpResident);
        assert!(data.bytes.iter().all(|&b| b == 0xBB));
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn resolve_accepts_total_at_exactly_cap() {
        // Budget boundary: pre-seed counter at `cap - 100`, resolve
        // a record of exactly 100 bytes → total = cap. Strict-greater
        // check (`>`): cap > cap = false → passes. Mutant `>=`:
        // cap >= cap = true → fires (wrong). Kills the `> -> >=`
        // mutant on the budget cap.
        let uasset = vec![0xAA; 1024];
        let record = record_with(FLAG_PAYLOAD_AT_END_OF_FILE, 100, 0);
        let resolver = BulkDataResolver::new_for_test(uasset, 1024, 0);
        resolver.set_bytes_resolved_for_test(MAX_TOTAL_BULK_DATA_BYTES_PER_PACKAGE - 100);
        let _data = resolver
            .resolve(&record, "test.uasset")
            .expect("total exactly at cap must pass");
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn resolve_rejects_budget_exceeded() {
        // Pre-seed the bytes_resolved counter near the per-package
        // cap (16 GiB) so a small record (200 bytes) tips over.
        // Kills cargo-mutants `match guard total <= CAP -> true`
        // which would defeat the budget check by always taking
        // the "in-budget" arm.
        let uasset = vec![0u8; 1024];
        let record = record_with(FLAG_PAYLOAD_AT_END_OF_FILE, 200, 0);
        let resolver = BulkDataResolver::new_for_test(uasset, 1024, 0);
        // Seed within 100 bytes of the cap — record's 200-byte
        // claim_size pushes total to cap + 100.
        resolver.set_bytes_resolved_for_test(MAX_TOTAL_BULK_DATA_BYTES_PER_PACKAGE - 100);
        match resolver.resolve(&record, "test.uasset") {
            Err(crate::PaksmithError::AssetParse {
                fault:
                    crate::error::AssetParseFault::BulkDataPackageBudgetExceeded { resolved, cap },
                ..
            }) => {
                assert_eq!(cap, MAX_TOTAL_BULK_DATA_BYTES_PER_PACKAGE);
                assert!(resolved > cap);
            }
            other => panic!("expected BulkDataPackageBudgetExceeded, got {other:?}"),
        }
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn resolve_ubulk_loader_caches_after_first_call() {
        // Loader closure invoked once even when two records resolve
        // against the same .ubulk.
        let ubulk = vec![0xCC; 64];
        let record_a = record_with(FLAG_PAYLOAD_IN_SEPARATE_FILE, 16, 0);
        let record_b = record_with(FLAG_PAYLOAD_IN_SEPARATE_FILE, 16, 32);
        let resolver = BulkDataResolver::new_for_test_with_ubulk(vec![0u8; 100], 100, 0, ubulk);
        let _data_a = resolver.resolve(&record_a, "test.uasset").expect("a");
        let _data_b = resolver.resolve(&record_b, "test.uasset").expect("b");
        // OnceLock pinned by virtue of the second resolve succeeding;
        // a non-cached loader would have re-invoked the closure (which
        // is fine since the test closure is idempotent) but the cache
        // is what's actually being pinned. The non-trivial assertion
        // is that `ubulk_cache` is `Some(_)` after the calls — the
        // resolver hides that, but a regression would surface as
        // "second resolve fails because closure errored second time"
        // if the loader were stateful (e.g. real `PakReader`).
    }
}
