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
    #[allow(
        clippy::too_many_lines,
        reason = "wire-format reader with sequential field parses + cap checks + side-effect-block consumption; splitting would replace one cohesive reader with three indirect helpers + an orchestrator. Same pattern as `AssetParseFault`'s Display impl in `error.rs`."
    )]
    pub fn read_from<R: std::io::Read>(reader: &mut R, asset_path: &str) -> crate::Result<Self> {
        use byteorder::{LittleEndian, ReadBytesExt};

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

        Ok(Self {
            flags: flags_out,
            element_count,
            size_on_disk,
            offset_in_file,
        })
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
}
