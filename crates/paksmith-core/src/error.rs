//! Error types for paksmith operations.

use std::collections::TryReserveError;
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
    BoundsExceeded {
        /// Wire-format field name (`"file_count"`, `"block_count"`,
        /// `"fdi_size"`, etc.).
        field: &'static str,
        /// The header-claimed value.
        value: u64,
        /// The cap it exceeds.
        limit: u64,
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
    },
    /// A header-claimed `u64` size doesn't fit in `usize` on the
    /// current platform. Practically a 32-bit-target concern.
    U64ExceedsPlatformUsize {
        /// Wire-format field name.
        field: &'static str,
        /// The u64 value that didn't fit.
        value: u64,
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
        /// Path of the entry whose computation overflowed.
        path: String,
        /// What was being computed (`"block_start"`, `"block_end"`,
        /// `"offset+header"`, `"payload_end"`).
        operation: &'static str,
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
    /// An entry-scoped wire-format anomaly that doesn't fit one of the
    /// other categorical variants. Carries the entry path plus a
    /// runtime-context message describing the specific violation.
    /// Use the more-specific variants (`BoundsExceeded`,
    /// `U64ArithmeticOverflow`, `ShortEntryRead`, etc.) where they
    /// fit; this is the catch-all for wire-format details that don't
    /// generalize across entries.
    EntryWireViolation {
        /// Path of the entry whose wire-format check failed.
        path: String,
        /// Detail message including any value-specific context.
        message: String,
    },
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

/// FString text encoding.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum FStringEncoding {
    /// Positive-length FString: UTF-8 bytes + null terminator.
    Utf8,
    /// Negative-length FString: UTF-16 LE code units + null terminator.
    Utf16,
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
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BoundsExceeded {
                field,
                value,
                limit,
            } => {
                write!(f, "{field} {value} exceeds maximum {limit}")
            }
            Self::AllocationFailed {
                context,
                requested,
                source,
            } => {
                write!(f, "could not reserve {requested} {context}: {source}")
            }
            Self::U64ExceedsPlatformUsize { field, value } => {
                write!(f, "{field} {value} exceeds platform usize")
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
            Self::U64ArithmeticOverflow { path, operation } => {
                write!(f, "entry `{path}` {operation} overflows u64")
            }
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
            Self::EntryWireViolation { path, message } => {
                write!(f, "entry `{path}` {message}")
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
}
