//! Error types for paksmith operations.

use std::collections::TryReserveError;
use std::fmt;
use std::io;

/// Top-level error type for all paksmith-core operations.
#[derive(Debug, thiserror::Error)]
pub enum PaksmithError {
    /// AES decryption failed because the key is missing or wrong.
    #[error("decryption failed for `{path}`: invalid or missing AES key")]
    Decryption {
        /// Archive or entry path that could not be decrypted.
        path: String,
    },

    /// The pak file format version is not recognized or not supported.
    #[error("unsupported pak version {version}")]
    UnsupportedVersion {
        /// Raw version number read from the footer.
        version: u32,
    },

    /// Decompression of an entry's data failed.
    #[error("decompression failed for `{path}` at offset {offset}: {reason}")]
    Decompression {
        /// Path of the entry whose data could not be decompressed.
        path: String,
        /// Byte offset within the archive where decompression failed.
        offset: u64,
        /// Human-readable reason describing why decompression failed
        /// (zlib stream error, oversized output, unsupported method, etc.).
        reason: String,
    },

    /// Asset deserialization failed.
    ///
    /// **Phase-2 scaffolding.** No production code constructs this
    /// variant yet — UAsset parsing lands in Phase 2 (per
    /// `docs/plans/ROADMAP.md`). Display format is pinned by
    /// `error_display_asset_parse` (see tests below) so the
    /// operator-visible message shape stays stable across the gap.
    #[error("asset deserialization failed for `{asset_path}`: {reason}")]
    AssetParse {
        /// Human-readable reason for the failure.
        reason: String,
        /// Asset path that could not be parsed.
        asset_path: String,
    },

    /// The pak footer is malformed or unreadable.
    #[error("invalid pak footer: {reason}")]
    InvalidFooter {
        /// Human-readable reason describing what's wrong with the footer.
        reason: String,
    },

    /// The pak index is malformed, allocation-bombed, or otherwise
    /// rejects parsing. The structured `fault` carries category-specific
    /// detail so consumers can match exhaustively rather than substring-
    /// scanning a `String` reason; the [`Display`] impl on
    /// [`IndexParseFault`] reproduces the same operator-visible shape
    /// the prior `reason: String` form had.
    ///
    /// [`Display`]: std::fmt::Display
    #[error("invalid pak index: {fault}")]
    InvalidIndex {
        /// Structured category + payload for the parse failure.
        fault: IndexParseFault,
    },

    /// A requested entry was not found in the archive.
    #[error("entry not found: `{path}`")]
    EntryNotFound {
        /// Path that was looked up.
        path: String,
    },

    /// A user-supplied argument was invalid.
    ///
    /// `arg` is the compile-time argument name (e.g. `"--filter"`); using
    /// `&'static str` enforces that runtime input never lands in this slot.
    #[error("invalid argument `{arg}`: {reason}")]
    InvalidArgument {
        /// Name of the argument (e.g. `--filter`).
        arg: &'static str,
        /// Human-readable reason describing what's wrong with the argument.
        reason: String,
    },

    /// SHA1 verification of an index or entry's bytes failed: the stored
    /// hash and the recomputed hash disagree.
    ///
    /// `target` identifies what was being verified ([`HashTarget::Index`] or
    /// [`HashTarget::Entry`] which carries the entry path). Splitting
    /// `target` into a typed enum prevents the previous (kind="index",
    /// path=Some(...)) nonsensical combination at the type level.
    ///
    /// `expected` and `actual` are hex-encoded SHA1 digests, always 40 hex
    /// characters; they are safe to log because they reveal a fixed-length
    /// hash, not entry contents. For the case where the entry's stored hash
    /// slot is zero but the archive *does* claim integrity (an attacker
    /// stripped the tag, not "no claim recorded"), see [`Self::IntegrityStripped`]
    /// instead — that's a structurally different signal worth a dedicated
    /// variant for monitoring/alerting.
    #[error("SHA1 mismatch: {target} expected={expected} actual={actual}")]
    HashMismatch {
        /// What was being verified.
        target: HashTarget,
        /// Hex-encoded SHA1 expected from the parsed metadata. Always
        /// 40 hex chars.
        expected: String,
        /// Hex-encoded SHA1 of the actual bytes read from disk. Always
        /// 40 hex chars.
        actual: String,
    },

    /// An entry's stored SHA1 slot is zeroed but the archive's index hash
    /// is non-zero — i.e., the writer recorded integrity for the archive
    /// as a whole but this one entry's hash slot is empty. UE writers
    /// produce all-or-nothing hashing, so a mixed state is the signature
    /// of an attacker stripping the integrity tag for a single entry to
    /// bypass per-entry verification.
    ///
    /// Distinct from [`Self::HashMismatch`] because there is nothing to
    /// compare digests against — the tag was removed, not changed.
    /// Monitoring rules can alert on this variant separately, since
    /// random corruption almost never zeroes 20 contiguous bytes.
    #[error(
        "integrity tag stripped for {target}: archive index is hashed but \
         this slot was zeroed (possible tampering)"
    )]
    IntegrityStripped {
        /// What was being verified — only `HashTarget::Entry` is currently
        /// constructed (the index is the reference for the policy and so
        /// can't be the stripped target).
        target: HashTarget,
    },

    /// Underlying I/O failure.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Structured category + payload for [`PaksmithError::InvalidIndex`].
///
/// Each variant captures the operation that detected the fault plus
/// enough machine-readable context to identify it without parsing a
/// human-readable string. Tests can match exhaustively
/// (`assert!(matches!(err, PaksmithError::InvalidIndex { fault:
/// IndexParseFault::BoundsExceeded { field: "file_count", .. } }))`)
/// rather than substring-scanning a `String` reason.
///
/// **Display format** mirrors the prior `reason: String` text shapes
/// so operator-visible messages are stable across the refactor.
///
/// `#[non_exhaustive]` because new categories will be added as new
/// parse paths land (e.g., Phase 2 UAsset parsing); downstream
/// `match` statements survive without source breakage.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum IndexParseFault {
    /// A header-claimed count or size exceeds a structural cap.
    /// E.g. `block_count > MAX_BLOCKS_PER_ENTRY`,
    /// `file_count > fdi_size / 9`,
    /// `entry_count > index_size / ENTRY_MIN_RECORD_BYTES`,
    /// `encoded_entries_size > index_size`,
    /// `fdi_size > MAX_FDI_BYTES`.
    ///
    /// Construction invariant (caller-enforced): `value > limit`.
    BoundsExceeded {
        /// Wire-format field name (`"file_count"`, `"block_count"`,
        /// `"fdi_size"`, etc.).
        field: &'static str,
        /// The header-claimed value.
        value: u64,
        /// The cap it exceeds.
        limit: u64,
        /// Unit of `value`/`limit`. Lets monitoring/dashboards group
        /// alerts by units rather than parsing the `field` string.
        unit: BoundsUnit,
        /// Path of the entry the bound applies to, when the field is
        /// per-entry (e.g. `"uncompressed_size"`). `None` for
        /// archive-level bounds (e.g. `"fdi_size"`, `"file_count"`).
        path: Option<String>,
    },
    /// A `try_reserve` / `try_reserve_exact` call returned `Err`.
    /// Surfaced rather than letting the allocator abort the process.
    AllocationFailed {
        /// Free-form context label naming what we were reserving
        /// (`"v10+ encoded entries"`, `"compression blocks"`, etc.).
        context: &'static str,
        /// Number of items or bytes (depending on context) we tried
        /// to reserve.
        requested: usize,
        /// Underlying allocator error, carrying OS-level detail.
        source: TryReserveError,
        /// Path of the entry whose payload allocation failed, when
        /// the reservation was per-entry. `None` for index-level
        /// reservations.
        path: Option<String>,
    },
    /// A header-claimed `u64` size doesn't fit in `usize` on the
    /// current platform. Practically a 32-bit-target concern.
    U64ExceedsPlatformUsize {
        /// Wire-format field name.
        field: &'static str,
        /// The u64 value that didn't fit.
        value: u64,
        /// Path of the entry the field applies to, when per-entry
        /// (e.g. `"uncompressed_size"`). `None` for archive-level
        /// (e.g. `"index_size"`, `"fdi_size"`).
        path: Option<String>,
    },
    /// Two views of the same entry's metadata (in-data record vs.
    /// index header) disagreed on a specific field. This is the
    /// canonical tampering signal — UE writers don't emit
    /// inconsistent records on the happy path.
    FieldMismatch {
        /// Path of the entry whose records disagreed.
        path: String,
        /// Wire-format field name (`"sha1"`, `"compressed_size"`,
        /// `"compression_method"`, etc.).
        field: &'static str,
        /// Display of the index-header value.
        index_value: String,
        /// Display of the in-data-record value.
        payload_value: String,
    },
    /// An FString length-prefix or contents was malformed.
    FStringMalformed {
        /// Sub-category of the malformation.
        kind: FStringFault,
    },
    /// A v10+ encoded-entry's offset into the encoded-entries blob is
    /// out of bounds.
    EncodedOffsetOob {
        /// The offset the FDI claimed.
        offset: usize,
        /// The actual size of the encoded-entries blob.
        blob_size: usize,
    },
    /// A v10+ FDI's negative encoded_offset (1-based index into the
    /// non-encoded-entries fallback) is out of range.
    NonEncodedIndexOob {
        /// The 0-based index derived from the negative offset.
        index: usize,
        /// The actual count of non-encoded entries.
        count: usize,
    },
    /// A v10+ archive's main index header declared no full directory
    /// index. Required for paksmith's filename-recovery path.
    MissingFullDirectoryIndex,
    /// An offset arithmetic operation on a `u64` overflowed. Surfaced
    /// rather than wrapping silently.
    U64ArithmeticOverflow {
        /// Path of the entry whose computation overflowed. `None` for
        /// sites parsed before the path is resolved (e.g., the
        /// encoded-entries blob walk in `PakEntryHeader::read_encoded`,
        /// where paths are reconstructed later via the FDI). Matches
        /// the `Option<String>` shape used by `BoundsExceeded` and
        /// `U64ExceedsPlatformUsize` for the same reason.
        path: Option<String>,
        /// Which parse site produced the overflow. See
        /// [`OverflowSite`] for the closed set.
        operation: OverflowSite,
    },
    /// An entry read produced fewer bytes than the entry claimed.
    ShortEntryRead {
        /// Path of the entry whose read came up short.
        path: String,
        /// Bytes actually written.
        written: u64,
        /// Bytes the entry claimed.
        expected: u64,
    },
    /// A compression block had `start > end`.
    CompressionBlockInvalid {
        /// The bad start offset.
        start: u64,
        /// The (smaller) end offset.
        end: u64,
    },
    /// The full-directory-index walk produced more entries than the
    /// main-index `file_count` claimed. Caught by the per-push budget
    /// guard added in PR #29.
    FdiFileCountOverflow {
        /// The main-index claimed file count that the FDI overflowed.
        file_count: u32,
    },
    /// A v10+ `encoded_offset` doesn't fit in `usize` on this
    /// platform (negative values that overflow on conversion). Distinct
    /// from `U64ExceedsPlatformUsize` because the source value is `i32`,
    /// not `u64`.
    EncodedOffsetUsizeOverflow {
        /// The signed `i32` offset that didn't fit.
        offset: i32,
    },
    /// The `verify()` orchestrator detected a state that should be
    /// unreachable on the happy path (e.g., index verification
    /// returning `SkippedEncrypted` despite the open-time check that
    /// rejects encrypted indices).
    InvariantViolated {
        /// Human-readable description of which invariant fired.
        reason: &'static str,
    },
    /// An entry's offset (or computed payload end) is past the
    /// archive's file size. Promoted out of the prior
    /// `EntryWireViolation` string-bag because the offset-vs-file_size
    /// cluster has a uniform shape (path + observed-vs-limit u64s
    /// discriminated by which computation caught it). Same precedent
    /// as `BlockBoundsViolation`. Issue #48.
    OffsetPastFileSize {
        /// Path of the entry whose offset check failed.
        path: String,
        /// Which computation surfaced the violation.
        kind: OffsetPastFileSizeKind,
        /// The offset (or computed payload end) that was past
        /// the file size.
        observed: u64,
        /// The file size — the upper bound that `observed` exceeded.
        limit: u64,
    },
    /// A compression block's start/end disagreed with the entry's
    /// payload region or the file. Structured variant covering the
    /// block-bounds cluster — uniform shape across the read paths
    /// (path + block_index + observed-vs-limit u64s).
    BlockBoundsViolation {
        /// Path of the entry whose block check failed.
        path: String,
        /// 0-based index of the offending block within the entry.
        block_index: usize,
        /// Sub-category of the violation.
        kind: BlockBoundsKind,
        /// The observed offset value that triggered the rejection.
        observed: u64,
        /// The limit the observed value violated.
        limit: u64,
    },
}

/// Unit qualifier for [`IndexParseFault::BoundsExceeded`].
/// Lets monitoring/dashboards group alerts by unit without parsing
/// the `field` string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BoundsUnit {
    /// `value`/`limit` are byte counts.
    Bytes,
    /// `value`/`limit` are item counts (entries, blocks, slots, etc.).
    Items,
}

/// Parser site that produced an [`IndexParseFault::U64ArithmeticOverflow`].
///
/// Closed set of names rather than `&'static str` so callers and tests
/// get compile-time exhaustiveness: a typo at a callsite is a
/// compile error, and tests using `matches!(err, ...
/// U64ArithmeticOverflow { operation: OverflowSite::EncodedBlockEnd, .. })`
/// cannot silently pass a stale string. Sites are named after the
/// computation that overflowed.
///
/// `Display` emits the canonical wire-stable name (snake_case for new
/// names, `+`-prefixed for the original `offset+header` token retained
/// for log/dashboard stability).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OverflowSite {
    /// `entry.header().offset() + in_data.wire_size()` — the absolute
    /// file offset of the entry's payload. Computed before every
    /// per-block read in `verify_entry` and `read_entry`.
    OffsetPlusHeader,
    /// `entry.header().offset() + block.start()` — the absolute file
    /// offset of a compression block's first byte.
    BlockStart,
    /// `entry.header().offset() + block.end()` — the absolute file
    /// offset of a compression block's one-past-last byte.
    BlockEnd,
    /// `payload_start + payload_size` — the absolute file offset of
    /// the entry's payload-end. Paired with the
    /// [`IndexParseFault::OffsetPastFileSize`] bounds check
    /// (variant [`OffsetPastFileSizeKind::PayloadEndBounds`]): this
    /// overflow site fires when the arithmetic itself wraps; that
    /// one fires when the (non-wrapping) result exceeds `file_size`.
    PayloadEnd,
    /// Encoded-entry single-block trivial path:
    /// `in_data_record_size + compressed_size`. The actually-triggerable
    /// overflow site addressed by issue #44.
    EncodedSingleBlockEnd,
    /// Encoded-entry multi-block loop: `cursor + block_compressed_size`.
    /// Defensive — bounded by `u32::MAX × 65 535` from the wire format
    /// today, but checked for discipline-consistency.
    EncodedBlockEnd,
    /// Encoded-entry multi-block loop: `start + advance` (cursor
    /// advance, AES-aligned for encrypted blocks). Defensive for the
    /// same reason as [`Self::EncodedBlockEnd`].
    EncodedBlockCursor,
}

impl fmt::Display for OverflowSite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Stable, wire-grep-able names. Operator-facing logs and any
        // downstream tooling that hard-codes the previous `&'static str`
        // values (e.g., dashboards, regression tests in dependent
        // projects) keep working.
        let s = match self {
            Self::OffsetPlusHeader => "offset+header",
            Self::BlockStart => "block_start",
            Self::BlockEnd => "block_end",
            Self::PayloadEnd => "payload_end",
            Self::EncodedSingleBlockEnd => "encoded_single_block_end",
            Self::EncodedBlockEnd => "encoded_block_end",
            Self::EncodedBlockCursor => "encoded_block_cursor",
        };
        f.write_str(s)
    }
}

/// Sub-category of [`IndexParseFault::OffsetPastFileSize`].
///
/// Discriminates which offset computation surfaced the violation.
/// Both cases are "this entry would read bytes that don't exist in
/// the archive", but the diagnostic varies: the header-offset case
/// is the index claiming a header at an impossible location, while
/// the payload-end case is the entry header internally consistent
/// but the payload computation walking past EOF.
///
/// **Naming note**: the `PayloadEndBounds` variant name carries the
/// `Bounds` suffix to disambiguate from
/// [`OverflowSite::PayloadEnd`] — that one names the *arithmetic*
/// overflow site (`offset + size` wraps), this one names the
/// *bounds-check* site (`offset + size` exceeds `file_size`). Both
/// flow through [`IndexParseFault`] and a stale `use` would
/// otherwise pattern-match the wrong one silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OffsetPastFileSizeKind {
    /// The entry header's recorded `offset` field is at-or-past the
    /// archive's `file_size`. The header itself can't even be read.
    /// **Comparator**: `offset >= file_size` (inclusive — equality
    /// means the header would start AT EOF, can't be read).
    EntryHeaderOffset,
    /// The entry's payload-end (computed from header `offset + size`)
    /// is past `file_size`. The header reads fine but its payload
    /// region extends past EOF.
    /// **Comparator**: `payload_end > file_size` (strict — equality
    /// means the payload ends exactly at EOF, which is fine; the
    /// upper bound is exclusive).
    PayloadEndBounds,
}

impl fmt::Display for OffsetPastFileSizeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Wire-stable strings: the operator-facing diagnostic
        // distinguishes the two cases via these tokens, so log
        // greps / dashboards keep working across refactors.
        let s = match self {
            Self::EntryHeaderOffset => "header offset past file_size",
            Self::PayloadEndBounds => "payload end past file_size",
        };
        f.write_str(s)
    }
}

/// Sub-category of [`IndexParseFault::BlockBoundsViolation`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BlockBoundsKind {
    /// Block start was below the payload region (overlapping the
    /// in-data FPakEntry header).
    StartOverlapsHeader,
    /// Block end was past the file's recorded size.
    EndPastFileSize,
}

/// Sub-category of [`IndexParseFault::FStringMalformed`].
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum FStringFault {
    /// Length prefix was `i32::MIN` — has no positive counterpart so
    /// can't be converted via `checked_abs`.
    LengthIsI32Min,
    /// Length-prefix's absolute value exceeds the per-FString
    /// hard-cap (anti-OOM).
    LengthExceedsMaximum {
        /// The bad length value (always positive — already absolute).
        length: u32,
        /// The configured cap.
        maximum: u32,
    },
    /// FString bytes ended without the expected null terminator.
    MissingNullTerminator {
        /// Which encoding's null-rule was violated.
        encoding: FStringEncoding,
    },
    /// FString bytes failed to decode in the declared encoding.
    InvalidEncoding {
        /// Which encoding the parse attempted.
        encoding: FStringEncoding,
    },
}

impl std::fmt::Display for FStringFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LengthIsI32Min => write!(f, "FString length i32::MIN overflows"),
            Self::LengthExceedsMaximum { length, maximum } => {
                write!(f, "FString length {length} exceeds maximum {maximum}")
            }
            Self::MissingNullTerminator { encoding } => {
                write!(f, "{encoding} FString missing null terminator")
            }
            Self::InvalidEncoding { encoding } => {
                write!(f, "invalid {encoding} string in index")
            }
        }
    }
}

/// FString text encoding. Not `#[non_exhaustive]`: the wire format
/// only ever distinguishes UTF-8 (positive length) and UTF-16
/// (negative length); a third variant would require a wire-format
/// extension and a deliberate update here.
#[derive(Debug, Clone, Copy)]
pub enum FStringEncoding {
    /// Positive-length FString: UTF-8 bytes + null terminator.
    Utf8,
    /// Negative-length FString: UTF-16 LE code units + null terminator.
    Utf16,
}

impl std::fmt::Display for BoundsUnit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bytes => write!(f, "bytes"),
            Self::Items => write!(f, "items"),
        }
    }
}

impl std::fmt::Display for BlockBoundsKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StartOverlapsHeader => write!(f, "start overlaps in-data header"),
            Self::EndPastFileSize => write!(f, "end exceeds file_size"),
        }
    }
}

impl std::fmt::Display for FStringEncoding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Utf8 => write!(f, "UTF-8"),
            Self::Utf16 => write!(f, "UTF-16"),
        }
    }
}

impl std::fmt::Display for IndexParseFault {
    // Long match-arm-per-variant body; the variant count IS the
    // function's complexity. Splitting would just hide it.
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BoundsExceeded {
                field,
                value,
                limit,
                unit,
                path,
            } => {
                if let Some(p) = path {
                    write!(
                        f,
                        "entry `{p}` {field} {value} exceeds maximum {limit} {unit}"
                    )
                } else {
                    write!(f, "{field} {value} exceeds maximum {limit} {unit}")
                }
            }
            Self::AllocationFailed {
                context,
                requested,
                source,
                path,
            } => {
                if let Some(p) = path {
                    write!(
                        f,
                        "could not reserve {requested} {context} for entry `{p}`: {source}"
                    )
                } else {
                    write!(f, "could not reserve {requested} {context}: {source}")
                }
            }
            Self::U64ExceedsPlatformUsize { field, value, path } => {
                if let Some(p) = path {
                    write!(f, "entry `{p}` {field} {value} exceeds platform usize")
                } else {
                    write!(f, "{field} {value} exceeds platform usize")
                }
            }
            Self::FieldMismatch {
                path,
                field,
                index_value,
                payload_value,
            } => {
                write!(
                    f,
                    "in-data header mismatch for `{path}`: {field} index={index_value} data={payload_value}"
                )
            }
            Self::FStringMalformed { kind } => write!(f, "{kind}"),
            Self::EncodedOffsetOob { offset, blob_size } => {
                write!(
                    f,
                    "v10+ encoded_offset {offset} >= encoded_entries_size {blob_size}"
                )
            }
            Self::NonEncodedIndexOob { index, count } => {
                write!(f, "v10+ non-encoded index {index} >= count {count}")
            }
            Self::MissingFullDirectoryIndex => {
                write!(f, "v10+ archive must have a full directory index")
            }
            Self::U64ArithmeticOverflow { path, operation } => match path {
                Some(p) => write!(f, "entry `{p}` {operation} overflows u64"),
                None => write!(f, "{operation} overflows u64"),
            },
            Self::ShortEntryRead {
                path,
                written,
                expected,
            } => {
                write!(
                    f,
                    "entry `{path}` short read: wrote {written} of {expected} expected bytes"
                )
            }
            Self::CompressionBlockInvalid { start, end } => {
                write!(f, "compression block start {start} exceeds end {end}")
            }
            Self::FdiFileCountOverflow { file_count } => {
                write!(
                    f,
                    "v10+ FDI carries more files than file_count claims ({file_count})"
                )
            }
            Self::EncodedOffsetUsizeOverflow { offset } => {
                write!(f, "v10+ encoded_offset {offset} doesn't fit in usize")
            }
            Self::InvariantViolated { reason } => write!(f, "{reason}"),
            Self::OffsetPastFileSize {
                path,
                kind,
                observed,
                limit,
            } => {
                write!(
                    f,
                    "entry `{path}` {kind}: observed={observed} limit={limit}"
                )
            }
            Self::BlockBoundsViolation {
                path,
                block_index,
                kind,
                observed,
                limit,
            } => {
                write!(
                    f,
                    "entry `{path}` block {block_index} {kind}: observed={observed} limit={limit}"
                )
            }
        }
    }
}

/// What was being SHA1-verified when a [`PaksmithError::HashMismatch`]
/// fired. Splitting "index vs entry" into a typed enum makes nonsensical
/// combinations (entry without path, index with path) unrepresentable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashTarget {
    /// The pak index region (footer's stored hash vs computed hash of the
    /// index bytes).
    Index,
    /// A specific entry's stored bytes (entry's stored SHA1 vs computed
    /// hash of the on-disk bytes — compressed for zlib entries, raw
    /// payload for uncompressed).
    Entry {
        /// Path of the entry whose hash failed to verify.
        path: String,
    },
}

impl std::fmt::Display for HashTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Index => f.write_str("index"),
            Self::Entry { path } => write!(f, "entry `{path}`"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_decryption() {
        let err = PaksmithError::Decryption {
            path: "Game/Content.pak".into(),
        };
        assert_eq!(
            err.to_string(),
            "decryption failed for `Game/Content.pak`: invalid or missing AES key"
        );
    }

    #[test]
    fn error_display_unsupported_version() {
        let err = PaksmithError::UnsupportedVersion { version: 99 };
        assert_eq!(err.to_string(), "unsupported pak version 99");
    }

    #[test]
    fn error_display_invalid_footer() {
        let err = PaksmithError::InvalidFooter {
            reason: "magic mismatch".into(),
        };
        assert_eq!(err.to_string(), "invalid pak footer: magic mismatch");
    }

    #[test]
    fn error_display_decompression_includes_path_and_reason() {
        let err = PaksmithError::Decompression {
            path: "Content/X.uasset".into(),
            offset: 1024,
            reason: "invalid zlib stream".into(),
        };
        assert_eq!(
            err.to_string(),
            "decompression failed for `Content/X.uasset` at offset 1024: invalid zlib stream"
        );
    }

    #[test]
    fn error_display_invalid_argument() {
        let err = PaksmithError::InvalidArgument {
            arg: "--filter",
            reason: "unmatched bracket".into(),
        };
        assert_eq!(
            err.to_string(),
            "invalid argument `--filter`: unmatched bracket"
        );
    }

    #[test]
    fn error_display_hash_mismatch_index() {
        let err = PaksmithError::HashMismatch {
            target: HashTarget::Index,
            expected: "abcdef1234".into(),
            actual: "0000000000".into(),
        };
        assert_eq!(
            err.to_string(),
            "SHA1 mismatch: index expected=abcdef1234 actual=0000000000"
        );
    }

    #[test]
    fn error_display_hash_mismatch_entry_includes_path() {
        let err = PaksmithError::HashMismatch {
            target: HashTarget::Entry {
                path: "Content/X.uasset".into(),
            },
            expected: "abcdef".into(),
            actual: "000000".into(),
        };
        assert_eq!(
            err.to_string(),
            "SHA1 mismatch: entry `Content/X.uasset` expected=abcdef actual=000000"
        );
    }

    #[test]
    fn error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file missing");
        let err: PaksmithError = io_err.into();
        assert!(matches!(err, PaksmithError::Io(_)));
    }

    /// The `From<io::Error>` impl must preserve the inner error's
    /// `kind`. A debugging caller that does
    /// `if let PaksmithError::Io(e) = err { e.kind() }` should get
    /// the original ErrorKind, not a default. Without this pin a
    /// future `From` rewrite that swaps to
    /// `io::Error::other(io_err.to_string())` would compile but
    /// silently lose the kind discriminator.
    #[test]
    fn error_from_io_preserves_kind() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file missing");
        let err: PaksmithError = io_err.into();
        let PaksmithError::Io(inner) = err else {
            panic!("expected PaksmithError::Io");
        };
        assert_eq!(inner.kind(), io::ErrorKind::NotFound);

        // Also pin a non-NotFound kind so a future regression that
        // hard-coded `NotFound` in the From impl wouldn't slip through.
        let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "denied");
        let err: PaksmithError = io_err.into();
        let PaksmithError::Io(inner) = err else {
            panic!("expected PaksmithError::Io");
        };
        assert_eq!(inner.kind(), io::ErrorKind::PermissionDenied);
    }

    /// `PaksmithError::AssetParse` is Phase-2 scaffolding: the variant
    /// is declared (error.rs:36) but no production code constructs it
    /// yet. Pin the Display format so a future Phase 2 implementation
    /// can rely on the operator-visible message shape, AND so the
    /// variant doesn't bit-rot before its first real caller lands.
    /// Per issue #31's audit: kept rather than removed because Phase 2
    /// (UAsset parsing) is the immediate next phase per the roadmap.
    #[test]
    fn error_display_asset_parse() {
        let err = PaksmithError::AssetParse {
            reason: "unknown property type".into(),
            asset_path: "Content/Hero.uasset".into(),
        };
        assert_eq!(
            err.to_string(),
            "asset deserialization failed for `Content/Hero.uasset`: unknown property type"
        );
    }

    // ---------------------------------------------------------------
    // IndexParseFault::Display pin tests (issue #50)
    //
    // Pin the operator-visible substrings (path, field name, numeric
    // values, unit labels) for each variant. We assert substrings, not
    // exact message text, so trivial wording polish — punctuation,
    // word reordering, capitalization tweaks — doesn't break the
    // tests. The substrings chosen are the fields downstream
    // dashboards/log greps would key on.
    //
    // Coverage rationale: every IndexParseFault variant Display arm
    // gets at least one test. Variants with optional fields
    // (BoundsExceeded, AllocationFailed, U64ExceedsPlatformUsize,
    // U64ArithmeticOverflow with Option<String> path) get both Some
    // and None branches pinned, since the two branches use distinct
    // format strings.
    // ---------------------------------------------------------------

    /// Helper: stringify an `IndexParseFault` via the wrapping
    /// `PaksmithError::InvalidIndex`. Tests want the wire-stable
    /// operator output, which is what `{err}` emits — the
    /// `#[error("invalid pak index: {fault}")]` `thiserror` template
    /// prefixes a category label, but the `{fault}` interpolation
    /// goes through `IndexParseFault::Display` directly. Using
    /// `fault.to_string()` skips the prefix and gives us the
    /// inner-Display text we're pinning.
    fn fault_display(fault: &IndexParseFault) -> String {
        fault.to_string()
    }

    #[test]
    fn index_parse_fault_display_bounds_exceeded_with_path() {
        let s = fault_display(&IndexParseFault::BoundsExceeded {
            field: "uncompressed_size",
            value: 1_000_000_000,
            limit: 100_000_000,
            unit: BoundsUnit::Bytes,
            path: Some("Content/Big.uasset".into()),
        });
        assert!(s.contains("Content/Big.uasset"), "got: {s}");
        // Anchor with surrounding text so the limit's substring
        // overlap with the value (`100000000` ⊂ `1000000000`) doesn't
        // create a false-positive when the value drops out of the
        // template entirely.
        assert!(s.contains("uncompressed_size 1000000000"), "got: {s}");
        assert!(s.contains("maximum 100000000 bytes"), "got: {s}");
    }

    #[test]
    fn index_parse_fault_display_bounds_exceeded_archive_level() {
        // Archive-level: no per-entry path. Different format-string
        // branch from the per-entry case above.
        let s = fault_display(&IndexParseFault::BoundsExceeded {
            field: "file_count",
            value: 999_999,
            limit: 1_000,
            unit: BoundsUnit::Items,
            path: None,
        });
        assert!(
            !s.contains("entry `"),
            "archive-level must not include `entry`: {s}"
        );
        assert!(s.contains("file_count"), "got: {s}");
        assert!(s.contains("999999"), "got: {s}");
        assert!(s.contains("1000"), "got: {s}");
        assert!(s.contains("items"), "got: {s}");
    }

    #[test]
    fn index_parse_fault_display_allocation_failed_with_path() {
        // TryReserveError can't be constructed directly — get one by
        // attempting an obviously-unreservable allocation.
        let source = Vec::<u8>::new()
            .try_reserve_exact(usize::MAX)
            .expect_err("reserving usize::MAX must fail");
        let s = fault_display(&IndexParseFault::AllocationFailed {
            context: "compression blocks",
            requested: 1_048_576,
            source,
            path: Some("Content/Mid.uasset".into()),
        });
        assert!(s.contains("Content/Mid.uasset"), "got: {s}");
        assert!(s.contains("compression blocks"), "got: {s}");
        assert!(s.contains("1048576"), "got: {s}");
    }

    #[test]
    fn index_parse_fault_display_allocation_failed_archive_level() {
        let source = Vec::<u8>::new()
            .try_reserve_exact(usize::MAX)
            .expect_err("reserving usize::MAX must fail");
        let s = fault_display(&IndexParseFault::AllocationFailed {
            context: "v10+ encoded entries",
            requested: 100_000,
            source,
            path: None,
        });
        assert!(
            !s.contains("entry `"),
            "archive-level must not include `entry`: {s}"
        );
        assert!(s.contains("v10+ encoded entries"), "got: {s}");
        assert!(s.contains("100000"), "got: {s}");
    }

    #[test]
    fn index_parse_fault_display_u64_exceeds_platform_usize_with_path() {
        let s = fault_display(&IndexParseFault::U64ExceedsPlatformUsize {
            field: "uncompressed_size",
            value: u64::MAX,
            path: Some("Content/Huge.uasset".into()),
        });
        assert!(s.contains("Content/Huge.uasset"), "got: {s}");
        assert!(s.contains("uncompressed_size"), "got: {s}");
        assert!(s.contains(&u64::MAX.to_string()), "got: {s}");
        assert!(s.contains("usize"), "got: {s}");
    }

    #[test]
    fn index_parse_fault_display_u64_exceeds_platform_usize_archive_level() {
        let s = fault_display(&IndexParseFault::U64ExceedsPlatformUsize {
            field: "index_size",
            value: u64::MAX,
            path: None,
        });
        assert!(!s.contains("entry `"), "got: {s}");
        assert!(s.contains("index_size"), "got: {s}");
        // Pin the full token so this variant is distinguishable from
        // EncodedOffsetUsizeOverflow ("doesn't fit in usize"). Bare
        // contains("usize") would cross-render without failure.
        assert!(s.contains("exceeds platform usize"), "got: {s}");
    }

    #[test]
    fn index_parse_fault_display_field_mismatch() {
        let s = fault_display(&IndexParseFault::FieldMismatch {
            path: "Content/X.uasset".into(),
            field: "compressed_size",
            index_value: "100".into(),
            payload_value: "200".into(),
        });
        assert!(s.contains("Content/X.uasset"), "got: {s}");
        assert!(s.contains("compressed_size"), "got: {s}");
        // Anchor with the diagnostic-category label so a future
        // reword (e.g., to "field disagreement") fails loudly.
        assert!(s.contains("in-data header mismatch"), "got: {s}");
        // Anchor index_value and payload_value with their key prefixes.
        assert!(s.contains("index=100"), "got: {s}");
        assert!(s.contains("data=200"), "got: {s}");
    }

    #[test]
    fn index_parse_fault_display_fstring_malformed_delegates_to_inner() {
        let s = fault_display(&IndexParseFault::FStringMalformed {
            kind: FStringFault::LengthIsI32Min,
        });
        // Display delegates to FStringFault::Display verbatim — substring
        // pin on the canonical message.
        assert!(s.contains("i32::MIN"), "got: {s}");
    }

    #[test]
    fn index_parse_fault_display_encoded_offset_oob() {
        let s = fault_display(&IndexParseFault::EncodedOffsetOob {
            offset: 5_000,
            blob_size: 2_048,
        });
        assert!(s.contains("5000"), "got: {s}");
        assert!(s.contains("2048"), "got: {s}");
        assert!(s.contains("encoded"), "got: {s}");
    }

    #[test]
    fn index_parse_fault_display_non_encoded_index_oob() {
        let s = fault_display(&IndexParseFault::NonEncodedIndexOob { index: 7, count: 3 });
        assert!(s.contains('7'), "got: {s}");
        assert!(s.contains('3'), "got: {s}");
        assert!(s.contains("non-encoded"), "got: {s}");
    }

    #[test]
    fn index_parse_fault_display_missing_full_directory_index() {
        let s = fault_display(&IndexParseFault::MissingFullDirectoryIndex);
        assert!(s.contains("v10+"), "got: {s}");
        assert!(s.contains("full directory index"), "got: {s}");
    }

    #[test]
    fn index_parse_fault_display_u64_arithmetic_overflow_with_path() {
        let s = fault_display(&IndexParseFault::U64ArithmeticOverflow {
            path: Some("Content/Y.uasset".into()),
            operation: OverflowSite::OffsetPlusHeader,
        });
        assert!(s.contains("Content/Y.uasset"), "got: {s}");
        // Operator-stable token from OverflowSite::Display.
        assert!(s.contains("offset+header"), "got: {s}");
        assert!(s.contains("overflows u64"), "got: {s}");
    }

    #[test]
    fn index_parse_fault_display_u64_arithmetic_overflow_no_path() {
        let s = fault_display(&IndexParseFault::U64ArithmeticOverflow {
            path: None,
            operation: OverflowSite::EncodedSingleBlockEnd,
        });
        assert!(!s.contains("entry `"), "got: {s}");
        assert!(s.contains("encoded_single_block_end"), "got: {s}");
        assert!(s.contains("overflows u64"), "got: {s}");
    }

    #[test]
    fn index_parse_fault_display_short_entry_read() {
        let s = fault_display(&IndexParseFault::ShortEntryRead {
            path: "Content/Z.uasset".into(),
            written: 50,
            expected: 100,
        });
        assert!(s.contains("Content/Z.uasset"), "got: {s}");
        // Anchor: bare `contains("50")` would be satisfied by "100"
        // elsewhere in the message. Pin the full token instead.
        assert!(s.contains("wrote 50 of 100"), "got: {s}");
        assert!(s.contains("short read"), "got: {s}");
    }

    #[test]
    fn index_parse_fault_display_compression_block_invalid() {
        let s = fault_display(&IndexParseFault::CompressionBlockInvalid {
            start: 200,
            end: 100,
        });
        // Pin the start-vs-end ordering so a future swap that
        // accidentally rendered `start 100 exceeds end 200` would
        // fail here.
        assert!(s.contains("start 200"), "got: {s}");
        assert!(s.contains("end 100"), "got: {s}");
        assert!(s.contains("compression block"), "got: {s}");
        assert!(s.contains("exceeds"), "got: {s}");
    }

    #[test]
    fn index_parse_fault_display_fdi_file_count_overflow() {
        let s = fault_display(&IndexParseFault::FdiFileCountOverflow { file_count: 42 });
        assert!(s.contains("42"), "got: {s}");
        assert!(s.contains("FDI"), "got: {s}");
        assert!(s.contains("file_count"), "got: {s}");
    }

    #[test]
    fn index_parse_fault_display_encoded_offset_usize_overflow() {
        let s = fault_display(&IndexParseFault::EncodedOffsetUsizeOverflow { offset: -123 });
        assert!(s.contains("-123"), "got: {s}");
        // Pin the full token so this is distinguishable from
        // U64ExceedsPlatformUsize ("exceeds platform usize").
        assert!(s.contains("doesn't fit in usize"), "got: {s}");
    }

    #[test]
    fn index_parse_fault_display_invariant_violated_passes_through_reason() {
        let s = fault_display(&IndexParseFault::InvariantViolated {
            reason: "verify_index returned SkippedEncrypted on a v6 archive",
        });
        // Verbatim pass-through — pin the full reason string so a
        // future template wrapper (e.g., adding "invariant: " prefix)
        // would surface here.
        assert_eq!(s, "verify_index returned SkippedEncrypted on a v6 archive");
    }

    #[test]
    fn index_parse_fault_display_offset_past_file_size_entry_header_offset() {
        let s = fault_display(&IndexParseFault::OffsetPastFileSize {
            path: "Content/A.uasset".into(),
            kind: OffsetPastFileSizeKind::EntryHeaderOffset,
            observed: 5_000,
            limit: 4_000,
        });
        assert!(s.contains("Content/A.uasset"), "got: {s}");
        assert!(s.contains("header offset past file_size"), "got: {s}");
        assert!(s.contains("5000"), "got: {s}");
        assert!(s.contains("4000"), "got: {s}");
    }

    #[test]
    fn index_parse_fault_display_offset_past_file_size_payload_end_bounds() {
        let s = fault_display(&IndexParseFault::OffsetPastFileSize {
            path: "Content/B.uasset".into(),
            kind: OffsetPastFileSizeKind::PayloadEndBounds,
            observed: 10_000,
            limit: 9_000,
        });
        assert!(s.contains("Content/B.uasset"), "got: {s}");
        assert!(s.contains("payload end past file_size"), "got: {s}");
        assert!(s.contains("10000"), "got: {s}");
        assert!(s.contains("9000"), "got: {s}");
    }

    #[test]
    fn index_parse_fault_display_block_bounds_violation_start_overlaps_header() {
        let s = fault_display(&IndexParseFault::BlockBoundsViolation {
            path: "Content/C.uasset".into(),
            block_index: 2,
            kind: BlockBoundsKind::StartOverlapsHeader,
            observed: 30,
            limit: 50,
        });
        assert!(s.contains("Content/C.uasset"), "got: {s}");
        // BlockBoundsKind::Display token.
        assert!(s.contains("start overlaps in-data header"), "got: {s}");
        assert!(s.contains("block 2"), "got: {s}");
        assert!(s.contains("30"), "got: {s}");
        assert!(s.contains("50"), "got: {s}");
    }

    #[test]
    fn index_parse_fault_display_block_bounds_violation_end_past_file_size() {
        let s = fault_display(&IndexParseFault::BlockBoundsViolation {
            path: "Content/D.uasset".into(),
            block_index: 0,
            kind: BlockBoundsKind::EndPastFileSize,
            observed: 1_000_000,
            limit: 500_000,
        });
        assert!(s.contains("Content/D.uasset"), "got: {s}");
        assert!(s.contains("end exceeds file_size"), "got: {s}");
        assert!(s.contains("block 0"), "got: {s}");
        // Symmetric with the StartOverlapsHeader test — pin
        // observed/limit so a future format-string divergence on
        // only this branch surfaces.
        assert!(s.contains("observed=1000000"), "got: {s}");
        assert!(s.contains("limit=500000"), "got: {s}");
    }

    /// Pin all `OverflowSite` Display tokens. Only `OffsetPlusHeader`
    /// and `EncodedSingleBlockEnd` are exercised through the
    /// `U64ArithmeticOverflow` parent-variant tests — the remaining 5
    /// (`BlockStart`, `BlockEnd`, `PayloadEnd`, `EncodedBlockEnd`,
    /// `EncodedBlockCursor`) need a dedicated pin since their tokens
    /// are wire-stable log/dashboard keys per the variant docs.
    #[test]
    fn overflow_site_display_tokens_are_wire_stable() {
        let cases: &[(OverflowSite, &str)] = &[
            (OverflowSite::OffsetPlusHeader, "offset+header"),
            (OverflowSite::BlockStart, "block_start"),
            (OverflowSite::BlockEnd, "block_end"),
            (OverflowSite::PayloadEnd, "payload_end"),
            (
                OverflowSite::EncodedSingleBlockEnd,
                "encoded_single_block_end",
            ),
            (OverflowSite::EncodedBlockEnd, "encoded_block_end"),
            (OverflowSite::EncodedBlockCursor, "encoded_block_cursor"),
        ];
        for (site, expected) in cases {
            assert_eq!(site.to_string(), *expected);
        }
    }

    /// Pin the three `FStringFault` Display arms not exercised by
    /// `index_parse_fault_display_fstring_malformed_delegates_to_inner`
    /// (`LengthExceedsMaximum`, `MissingNullTerminator`,
    /// `InvalidEncoding`). The encoding-aware variants also pin
    /// `FStringEncoding::Display` transitively (UTF-8 and UTF-16
    /// tokens are otherwise unreachable from any test).
    #[test]
    fn fstring_fault_display_covers_all_arms() {
        let s = IndexParseFault::FStringMalformed {
            kind: FStringFault::LengthExceedsMaximum {
                length: 100_000,
                maximum: 65_536,
            },
        }
        .to_string();
        assert!(s.contains("100000"), "got: {s}");
        assert!(s.contains("65536"), "got: {s}");
        assert!(s.contains("exceeds"), "got: {s}");

        let s = IndexParseFault::FStringMalformed {
            kind: FStringFault::MissingNullTerminator {
                encoding: FStringEncoding::Utf8,
            },
        }
        .to_string();
        assert!(s.contains("null terminator"), "got: {s}");
        // Transitive coverage for FStringEncoding::Utf8 Display token.
        assert!(s.contains("UTF-8"), "got: {s}");

        let s = IndexParseFault::FStringMalformed {
            kind: FStringFault::InvalidEncoding {
                encoding: FStringEncoding::Utf16,
            },
        }
        .to_string();
        // Transitive coverage for FStringEncoding::Utf16 Display token.
        assert!(s.contains("UTF-16"), "got: {s}");
    }
}
