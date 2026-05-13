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
    /// Encoded-entry / FDI sub-fault wrapper. Groups all v10+
    /// encoded-path faults under a single top-level variant. See
    /// [`EncodedFault`] for the full sub-category set and the
    /// motivation; this variant is the wrapper that carries them.
    Encoded {
        /// Sub-category of the encoded-path fault.
        kind: EncodedFault,
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

/// Sub-category of [`IndexParseFault::Encoded`].
///
/// Groups the v10+ encoded-path / FDI-walk faults that previously
/// lived as distinct top-level `IndexParseFault` variants. Issue #60
/// nesting reduced the top-level variant count and made the encoded
/// vs. inline distinction structural — when a code path is logically
/// "v10+ encoded sub-fault," it constructs `IndexParseFault::Encoded
/// { kind: EncodedFault::... }`, mirroring how
/// [`IndexParseFault::FStringMalformed`] nests [`FStringFault`].
///
/// Display strings are wire-stable (operators / log greps / dashboard
/// regexes match against these), so renaming variants here is fine
/// but rewording the Display arm is a breaking change.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum EncodedFault {
    /// A v10+ encoded-entry's offset into the encoded-entries blob is
    /// out of bounds. Was `IndexParseFault::EncodedOffsetOob`.
    OffsetOob {
        /// Path of the entry whose encoded_offset was out of bounds.
        /// Populated inline at the FDI-walk construction site (where
        /// `full_path` is in scope), so unlike
        /// [`Self::CompressedSizeMismatch`] this variant doesn't need
        /// `Option`-typed enrichment via `with_index_path`.
        path: String,
        /// The offset the FDI claimed.
        offset: usize,
        /// The actual size of the encoded-entries blob.
        blob_size: usize,
    },
    /// A v10+ FDI's negative encoded_offset (1-based index into the
    /// non-encoded-entries fallback) is out of range.
    NonEncodedIndexOob {
        /// Path of the entry whose negative offset was out of range.
        /// Populated inline at the FDI-walk site.
        path: String,
        /// The 0-based index derived from the negative offset.
        index: usize,
        /// The actual count of non-encoded entries.
        count: usize,
    },
    /// A v10+ `encoded_offset` doesn't fit in `usize` on this
    /// platform (negative values that overflow on conversion).
    /// Distinct from `IndexParseFault::U64ExceedsPlatformUsize`
    /// because the source value is `i32`, not `u64`. Was
    /// `IndexParseFault::EncodedOffsetUsizeOverflow`.
    OffsetUsizeOverflow {
        /// Path of the entry whose offset didn't fit. Populated
        /// inline at the FDI-walk site.
        path: String,
        /// The signed `i32` offset that didn't fit.
        offset: i32,
    },
    /// A v10+ multi-block encoded entry's wire `compressed_size`
    /// disagrees with the sum of its per-block compressed sizes.
    /// `compressed_size` is read off the wire as a (potentially
    /// u64-wide) varint and is otherwise structurally orphaned —
    /// the cursor walk uses per-block u32 sizes for boundaries, not
    /// `compressed_size`. Without this cross-check, a malicious
    /// archive could claim e.g. `compressed_size = u64::MAX - 1`
    /// while the per-block sizes sum to a few KiB, and the lie
    /// would propagate to `PakEntryHeader::compressed_size()` and
    /// any downstream consumer (the CLI `list` command, future
    /// JSON/GUI surfaces) that reports it as the entry's payload
    /// size. Fired by `PakEntryHeader::read_encoded`'s multi-block
    /// path; the single-block path is structurally exempt because
    /// it derives the block from `compressed_size` itself. Was
    /// `IndexParseFault::EncodedCompressedSizeMismatch`.
    CompressedSizeMismatch {
        /// The `compressed_size` claimed on the wire.
        claimed: u64,
        /// The sum of per-block (unaligned) compressed sizes the
        /// parser actually walked. For encrypted entries this is
        /// the unaligned total — block cursors advance by the
        /// AES-aligned size on disk, but the wire `compressed_size`
        /// is the logical (unaligned) payload size.
        computed: u64,
        /// Path of the entry whose claim mismatched. `None` at
        /// `read_encoded`'s parse site (paths come from the FDI
        /// walk later); enriched by [`PaksmithError::with_index_path`]
        /// at the FDI-walk caller.
        path: Option<String>,
    },
    /// The full-directory-index walk produced more entries than the
    /// main-index `file_count` claimed. Caught by the per-push
    /// budget guard added in PR #29. Was
    /// `IndexParseFault::FdiFileCountOverflow`; renamed to
    /// `Exceeded` during the #60 nesting to align with
    /// `BoundsExceeded` vocabulary (the original "Overflow"
    /// suffix collided with arithmetic-overflow concepts).
    FdiFileCountExceeded {
        /// The main-index claimed file count that the FDI overflowed.
        file_count: u32,
    },
}

impl PaksmithError {
    /// Fill in the virtual entry path on an `InvalidIndex` error whose
    /// inner fault carries `path: Option<String>` and is currently
    /// `None`. Used by the v10+ FDI walk to enrich errors thrown by
    /// [`crate::container::pak::index::PakEntryHeader::read_encoded`]
    /// before they escape: that parser can't know the full path
    /// (paths are reconstructed later by the FDI), but the FDI walk
    /// can — and an operator-visible error with a full virtual path
    /// is more actionable than one without. No-op for non-`InvalidIndex`
    /// errors, for variants that don't carry a path field, and for
    /// variants that carry `path: String` (those are populated at
    /// construction — there's nothing to fill in).
    #[must_use]
    pub(crate) fn with_index_path(mut self, path: &str) -> Self {
        if let PaksmithError::InvalidIndex { fault } = &mut self {
            fault.set_path_if_unset(path);
        }
        self
    }
}

impl IndexParseFault {
    /// If this fault carries `path: Option<String>` and the path is
    /// currently `None`, set it to `Some(path.to_owned())`. No-op for
    /// variants without a path field, for variants whose `Option<String>`
    /// path is already populated, and for variants that carry
    /// `path: String` unconditionally (already populated at
    /// construction). Caller in [`PaksmithError::with_index_path`].
    fn set_path_if_unset(&mut self, p: &str) {
        // Closed match, not `_ =>`, so a future variant gains a
        // visible decision point: enrich here, or document why not.
        // Includes nested `EncodedFault` variants: adding a sixth
        // sub-fault requires a deliberate decision in this match,
        // not just an `EncodedFault` enum-level addition.
        match self {
            Self::BoundsExceeded { path, .. }
            | Self::AllocationFailed { path, .. }
            | Self::U64ExceedsPlatformUsize { path, .. }
            | Self::U64ArithmeticOverflow { path, .. }
            | Self::Encoded {
                kind: EncodedFault::CompressedSizeMismatch { path, .. },
            } => {
                if path.is_none() {
                    *path = Some(p.to_owned());
                }
            }
            Self::BlockBoundsViolation { .. }
            | Self::CompressionBlockInvalid { .. }
            | Self::Encoded {
                kind:
                    EncodedFault::OffsetOob { .. }
                    | EncodedFault::OffsetUsizeOverflow { .. }
                    | EncodedFault::NonEncodedIndexOob { .. }
                    | EncodedFault::FdiFileCountExceeded { .. },
            }
            | Self::FieldMismatch { .. }
            | Self::FStringMalformed { .. }
            | Self::InvariantViolated { .. }
            | Self::MissingFullDirectoryIndex
            | Self::OffsetPastFileSize { .. }
            | Self::ShortEntryRead { .. } => {}
        }
    }
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
            Self::Encoded { kind } => write!(f, "{kind}"),
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

impl std::fmt::Display for EncodedFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Wire-stable strings: operators / dashboards / log greps
        // match against these. Renaming an arm is a breaking change
        // for downstream consumers; preserve the pre-#60 text.
        match self {
            Self::OffsetOob {
                path,
                offset,
                blob_size,
            } => {
                write!(
                    f,
                    "entry `{path}` v10+ encoded_offset {offset} >= encoded_entries_size {blob_size}"
                )
            }
            Self::NonEncodedIndexOob { path, index, count } => {
                write!(
                    f,
                    "entry `{path}` v10+ non-encoded index {index} >= count {count}"
                )
            }
            Self::OffsetUsizeOverflow { path, offset } => {
                write!(
                    f,
                    "entry `{path}` v10+ encoded_offset {offset} doesn't fit in usize"
                )
            }
            Self::CompressedSizeMismatch {
                claimed,
                computed,
                path,
            } => {
                if let Some(p) = path {
                    write!(
                        f,
                        "entry `{p}` encoded compressed_size mismatch: \
                         wire claim {claimed} != sum of per-block sizes {computed}"
                    )
                } else {
                    write!(
                        f,
                        "encoded compressed_size mismatch: \
                         wire claim {claimed} != sum of per-block sizes {computed}"
                    )
                }
            }
            Self::FdiFileCountExceeded { file_count } => {
                write!(
                    f,
                    "v10+ FDI carries more files than file_count claims ({file_count})"
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

    /// `with_index_path` MUST preserve any path the inner fault
    /// already carries. The FDI walk is one of potentially several
    /// future enrichment boundaries; if a deeper layer happens to
    /// know the path first, we don't want the FDI walk to clobber
    /// it. Pin the runtime check at `error.rs:374` (`if path.is_none()`).
    #[test]
    fn with_index_path_does_not_overwrite_existing_path() {
        let err = PaksmithError::InvalidIndex {
            fault: IndexParseFault::BoundsExceeded {
                field: "uncompressed_size",
                value: 100,
                limit: 50,
                unit: BoundsUnit::Bytes,
                path: Some("Original/path.uasset".into()),
            },
        };
        let enriched = err.with_index_path("New/path.uasset");
        let PaksmithError::InvalidIndex {
            fault: IndexParseFault::BoundsExceeded { path: Some(p), .. },
        } = enriched
        else {
            panic!("expected enriched BoundsExceeded with Some(path)");
        };
        assert_eq!(p, "Original/path.uasset");
    }

    /// `with_index_path` MUST be a no-op for fault variants that
    /// don't carry a `path` field. Pin the closed match in
    /// `set_path_if_unset` so a future contributor accidentally
    /// adding `EncodedFault::OffsetUsizeOverflow` (or any other
    /// no-path variant) to the enriching arm gets caught here, not
    /// by an operator confused why an offset-overflow error suddenly
    /// claims a path.
    #[test]
    fn with_index_path_is_no_op_on_non_path_carrying_variant() {
        // `MissingFullDirectoryIndex` is unambiguously path-less:
        // it's an archive-level fault (no per-entry context) and
        // the variant carries no fields at all. Any future
        // contributor accidentally moving it to the enriching arm
        // would break this test.
        let err = PaksmithError::InvalidIndex {
            fault: IndexParseFault::MissingFullDirectoryIndex,
        };
        let enriched = err.with_index_path("Some/path.uasset");
        assert!(
            !enriched.to_string().contains("Some/path.uasset"),
            "MissingFullDirectoryIndex has no path field; \
             with_index_path must not introduce one. Display was: {enriched}"
        );
    }

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
    /// is declared but no production code constructs it
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
    fn index_parse_fault_display_encoded_compressed_size_mismatch_with_path() {
        let s = fault_display(&IndexParseFault::Encoded {
            kind: EncodedFault::CompressedSizeMismatch {
                claimed: u64::MAX - 1,
                computed: 12_288,
                path: Some("Content/foo.uasset".into()),
            },
        });
        assert!(s.contains("Content/foo.uasset"), "got: {s}");
        assert!(s.contains("encoded compressed_size mismatch"), "got: {s}");
        // Pin both numbers — operators chasing the diagnostic need
        // to see claimed AND computed to spot which one's the lie.
        assert!(s.contains(&(u64::MAX - 1).to_string()), "got: {s}");
        assert!(s.contains("12288"), "got: {s}");
    }

    #[test]
    fn index_parse_fault_display_encoded_compressed_size_mismatch_no_path() {
        // Pre-FDI-walk path-less branch (read_encoded fires before
        // the FDI walk knows the virtual path; with_index_path
        // fills it in afterward, but the path-less Display branch
        // is the format used in any context that doesn't go through
        // enrichment).
        let s = fault_display(&IndexParseFault::Encoded {
            kind: EncodedFault::CompressedSizeMismatch {
                claimed: 1_000_000,
                computed: 500_000,
                path: None,
            },
        });
        assert!(
            !s.contains("entry `"),
            "path-less must not include `entry`: {s}"
        );
        assert!(s.contains("encoded compressed_size mismatch"), "got: {s}");
        assert!(s.contains("1000000"), "got: {s}");
        assert!(s.contains("500000"), "got: {s}");
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
        let s = fault_display(&IndexParseFault::Encoded {
            kind: EncodedFault::OffsetOob {
                path: "Content/foo.uasset".into(),
                offset: 5_000,
                blob_size: 2_048,
            },
        });
        assert!(s.contains("Content/foo.uasset"), "got: {s}");
        assert!(s.contains("5000"), "got: {s}");
        assert!(s.contains("2048"), "got: {s}");
        assert!(s.contains("encoded"), "got: {s}");
    }

    #[test]
    fn index_parse_fault_display_non_encoded_index_oob() {
        let s = fault_display(&IndexParseFault::Encoded {
            kind: EncodedFault::NonEncodedIndexOob {
                path: "Content/bar.uasset".into(),
                index: 7,
                count: 3,
            },
        });
        assert!(s.contains("Content/bar.uasset"), "got: {s}");
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
    fn index_parse_fault_display_fdi_file_count_exceeded() {
        let s = fault_display(&IndexParseFault::Encoded {
            kind: EncodedFault::FdiFileCountExceeded { file_count: 42 },
        });
        assert!(s.contains("42"), "got: {s}");
        assert!(s.contains("FDI"), "got: {s}");
        assert!(s.contains("file_count"), "got: {s}");
    }

    #[test]
    fn index_parse_fault_display_encoded_offset_usize_overflow() {
        let s = fault_display(&IndexParseFault::Encoded {
            kind: EncodedFault::OffsetUsizeOverflow {
                path: "Content/baz.uasset".into(),
                offset: -123,
            },
        });
        assert!(s.contains("Content/baz.uasset"), "got: {s}");
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
