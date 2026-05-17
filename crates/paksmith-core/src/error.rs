//! Error types for paksmith operations.

use std::collections::TryReserveError;
use std::fmt;
use std::io;

// Layering note: this top-level error module imports
// `CompressionMethod` from the pak container, while
// `container::pak::index::compression` imports `IndexParseFault` and
// `PaksmithError` from here. Rust accepts the use-path cycle (use-paths
// aren't compile-cycles), and the `CompressionMethod` type itself is a
// leaf with no further deps. Reviewers in PR #123 surfaced the
// inversion; the alternatives — re-export through a neutral
// `crate::types` module, or project to an owned label string — were
// considered and rejected on these grounds:
//
//   - The wire-stable Display arm for `UnsupportedMethod` already
//     renders via `{method:?}` (i.e. the `Debug` derive output of
//     `CompressionMethod`), so Debug-derive coupling exists on the
//     chosen path too — operator log greps see Debug-formatted text
//     regardless of which alternative we picked. The deciding factor
//     for rejecting label projection is that it would ADD a second
//     coupling site at the test layer (assertions matching on
//     `String` labels would also be tied to Debug output), doubling
//     the surface where a CompressionMethod variant rename silently
//     propagates. Keeping the rich type at the match site limits the
//     coupling to the Display layer, where the wire-stability
//     contract is already documented and the substring it produces
//     is the operator-visible truth anyway.
//   - The re-export module would exist only for this one type. It
//     either stays one type forever (low value, friction at every
//     future fault-payload decision) or grows into a kitchen-sink
//     leaf, at which point both `error` and `container` reach into
//     it — the same inversion plus an extra hop.
//
// Re-evaluate this trade-off if any of the following lands:
//   - The `iostore` container parser introduces a parallel
//     compression-method type (then a `crate::types` shim houses two
//     types instead of one and the accretion argument inverts).
//   - A non-container module (e.g., Phase-2 asset parsing) needs to
//     construct `DecompressionFault::UnsupportedMethod` from outside
//     the `container::pak` tree.
//   - The `compression` module grows a non-trivial dep that would
//     transitively pollute consumers of `error::DecompressionFault`.
use crate::container::pak::index::CompressionMethod;

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
    ///
    /// `fault` categorizes the failure mode (unsupported method,
    /// decompression bomb, per-block size mismatch, allocation
    /// failure, zlib stream error, size underrun). Issue #112
    /// promoted this from a free-form `reason: String` so tests
    /// can `matches!` on typed variants rather than substring-grep
    /// on the Display string. The Display impl on `DecompressionFault`
    /// preserves the wire-stable operator-facing token shapes from
    /// the prior `reason` form, so log greps + monitoring rules
    /// keep working.
    #[error("decompression failed for `{path}` at offset {offset}: {fault}")]
    Decompression {
        /// Path of the entry whose data could not be decompressed.
        path: String,
        /// Byte offset within the archive where decompression failed.
        offset: u64,
        /// Structured category + payload for the decompression fault.
        fault: DecompressionFault,
    },

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

    /// The pak footer is malformed or unreadable. The structured
    /// `fault` carries category-specific detail so consumers can
    /// match exhaustively rather than substring-scanning a `String`
    /// reason; the [`Display`] impl on [`InvalidFooterFault`] reproduces
    /// the same operator-visible shape the prior `reason: String`
    /// form had.
    ///
    /// Issue #64 promoted the index-bounds-check sites to typed
    /// [`InvalidFooterFault::IndexRegionOffsetOverflow`] and
    /// [`InvalidFooterFault::IndexRegionPastFileSize`] variants;
    /// the magic / version / FName-table sites still use
    /// [`InvalidFooterFault::OtherUnpromoted`] until they justify
    /// their own typed variants (likely when the iostore `.utoc`
    /// footer parser lands and creates a second site for each).
    ///
    /// [`Display`]: std::fmt::Display
    #[error("invalid pak footer: {fault}")]
    InvalidFooter {
        /// Structured category + payload for the footer fault.
        fault: InvalidFooterFault,
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
    /// `target` identifies what was being verified — see [`HashTarget`]
    /// for the variants ([`HashTarget::Index`], [`HashTarget::Entry`]
    /// carrying the entry path, [`HashTarget::Fdi`], [`HashTarget::Phi`]).
    /// Splitting `target` into a typed enum prevents the previous
    /// (kind="index", path=Some(...)) nonsensical combination at the
    /// type level.
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
        /// What was being verified. Constructed for [`HashTarget::Entry`]
        /// (per-entry slot zeroed by `verify_entry`) and for
        /// [`HashTarget::Fdi`] / [`HashTarget::Phi`] (region slot zeroed
        /// by `verify_region`, issue #86). The footer's main-index hash
        /// is the *reference* for the all-or-nothing policy, so
        /// [`HashTarget::Index`] is never the stripped target — there's
        /// no other slot to compare it against.
        target: HashTarget,
    },

    /// Underlying I/O failure.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Structured category + payload for [`PaksmithError::InvalidFooter`].
///
/// Mirrors [`IndexParseFault`] for footer-level violations: the
/// previous `InvalidFooter { reason: String }` shape was a
/// string-bag that consumers had to substring-scan. Issue #64
/// promoted the index-bounds-check sites to the structured
/// `IndexRegion*` variants so tests can match exhaustively
/// (`matches!(err, ... InvalidFooterFault::IndexRegionPastFileSize { .. })`).
///
/// **Display format** mirrors the prior `reason: String` text shapes
/// so operator-visible messages are stable across the refactor —
/// log greps and dashboards keep working.
///
/// `#[non_exhaustive]` because new categories will be added as the
/// remaining magic / version / FName-table sites get promoted out
/// of [`Self::OtherUnpromoted`] (likely when iostore's `.utoc`
/// footer parser lands a second site for each).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum InvalidFooterFault {
    /// Transitional free-form reason for footer faults that haven't
    /// been promoted to typed variants yet (magic-not-found,
    /// version-unsupported, FName-table malformations, etc.). Each
    /// remaining call site is a candidate for promotion when a
    /// second instance of the same shape lands.
    ///
    /// Named `OtherUnpromoted` (rather than `Other`) as a friction
    /// signal: the explicit "Unpromoted" suffix makes contributors
    /// reaching for a fallback at construction sites pause to ask
    /// "should this be its own typed variant?" before defaulting to
    /// the string-bag.
    OtherUnpromoted {
        /// Human-readable reason describing what's wrong with the
        /// footer.
        reason: String,
    },
    /// `index_offset + index_size` overflows u64 — the footer
    /// claims an index region that's unrepresentable as a u64
    /// byte range. Practically only reachable with a malicious
    /// archive (a UE writer never emits this shape).
    IndexRegionOffsetOverflow {
        /// The footer-claimed index_offset.
        offset: u64,
        /// The footer-claimed index_size.
        size: u64,
    },
    /// `index_offset + index_size > file_size` — the footer claims
    /// an index region that extends past the actual end of the
    /// archive. Conceptually the archive-region analog of
    /// [`IndexParseFault::OffsetPastFileSize`] (per-entry
    /// granularity); they're kept as separate variants because the
    /// two have different per-entry vs archive-level invariants and
    /// distinct top-level error categories (`InvalidFooter` vs
    /// `InvalidIndex`).
    ///
    /// Carries the raw `(offset, size, file_size)` rather than a
    /// computed `observed` so an operator can see *which* of the
    /// two footer fields was the lying one — this matches the
    /// pre-#64 string content (`"index extends past EOF: offset=…
    /// size=… file_size=…"`).
    IndexRegionPastFileSize {
        /// The footer-claimed index_offset.
        offset: u64,
        /// The footer-claimed index_size.
        size: u64,
        /// The actual archive file size — the upper bound that
        /// `offset + size` exceeded.
        file_size: u64,
    },
}

impl std::fmt::Display for InvalidFooterFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Wire-stable strings: match the prior `reason: String`
        // shape so log greps / dashboards keep working.
        match self {
            Self::OtherUnpromoted { reason } => f.write_str(reason),
            Self::IndexRegionOffsetOverflow { offset, size } => {
                write!(
                    f,
                    "index_offset + index_size overflows u64 (offset={offset} size={size})"
                )
            }
            Self::IndexRegionPastFileSize {
                offset,
                size,
                file_size,
            } => {
                write!(
                    f,
                    "index extends past EOF: offset={offset} size={size} file_size={file_size}"
                )
            }
        }
    }
}

/// Structured category + payload for [`PaksmithError::Decompression`].
///
/// Issue #112: replaces the prior `Decompression { reason: String }`
/// shape so tests can `matches!` on typed variants instead of
/// substring-grep on the Display string. Tests in
/// `tests/pak_integration.rs` previously used `reason.contains(...)`
/// to discriminate which decompression case fired; they now match on
/// these typed variants.
///
/// **Display format** mirrors the prior `reason: String` text shapes
/// so operator-visible messages are stable across the refactor.
///
/// `#[non_exhaustive]` for the same forward-compat rationale as
/// [`InvalidFooterFault`] / [`IndexParseFault`] — new categories
/// will land as new compression methods or parse paths are added.
///
/// `PartialEq + Eq` to enable `assert_eq!(err, expected)` in tests
/// alongside `matches!`. All payload types are equality-comparable:
/// [`CompressionMethod`] derives PartialEq, primitives are trivial,
/// `TryReserveError` got PartialEq in stdlib 1.66, and
/// [`io::ErrorKind`] is `Copy + Eq` (we store `kind + message`
/// rather than the full `io::Error` because the latter isn't
/// Clone/PartialEq).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecompressionFault {
    /// The entry's compression method isn't supported by paksmith.
    /// Currently fires for Gzip, Oodle, Zstd, Lz4, Unknown(_), and
    /// UnknownByName(_); only None and Zlib are wired up. Both
    /// `read_entry` (and its `stream_entry_to` worker) and
    /// `verify_entry` reject these uniformly rather than silently
    /// returning ciphertext / unhashed bytes.
    UnsupportedMethod {
        /// The unsupported method's typed value, as parsed from the
        /// entry header (or resolved through the v8+ FName slot).
        method: CompressionMethod,
    },
    /// A compression block decompressed beyond the entry's claimed
    /// `uncompressed_size`. The decoder is bounded to
    /// `uncompressed_size + 1` bytes per block, so this fires the
    /// moment the lie is detectable.
    DecompressionBomb {
        /// 0-based index of the offending block.
        block_index: usize,
        /// Cumulative decompressed bytes after this block — the
        /// value that exceeded the claim.
        actual: u64,
        /// The entry's wire-claimed `uncompressed_size`.
        claimed_uncompressed: u64,
    },
    /// A non-final compression block decompressed to a size other
    /// than the entry's declared `compression_block_size`. Without
    /// this check, a malicious pak could deliver truncated payloads
    /// that still summed to the claimed `uncompressed_size` by
    /// padding the final block.
    NonFinalBlockSizeMismatch {
        /// 0-based index of the offending block.
        block_index: usize,
        /// The entry's declared `compression_block_size`.
        expected: u32,
        /// Actual decompressed length of this block.
        actual: u64,
    },
    /// Cumulative decompressed total fell short of the entry's
    /// claimed `uncompressed_size` after the decompression loop
    /// terminated. The per-block bomb check catches `actual >
    /// claimed`; this catches the `actual < claimed` underrun.
    SizeUnderrun {
        /// Bytes actually written.
        actual: u64,
        /// Bytes the entry claimed.
        expected: u64,
    },
    /// Per-block compressed-bytes buffer reservation failed before
    /// any decompression has started. Fired by the
    /// `try_reserve_exact(block_len_usize)` site in
    /// `stream_zlib_to`. Distinct from a generic OOM because the
    /// path is bounded by `MAX_UNCOMPRESSED_ENTRY_BYTES` upstream
    /// — surfacing here means a fallible reservation legitimately
    /// failed at the pre-decode stage.
    CompressedBlockReserveFailed {
        /// 0-based block index for context.
        block_index: usize,
        /// Bytes the reservation requested.
        requested: usize,
        /// Underlying `try_reserve_exact` failure reason.
        source: TryReserveError,
    },
    /// Mid-decompression scratch buffer reservation failed AFTER
    /// some bytes were already committed to the per-block output.
    /// Fired by the `try_reserve(n)` site inside `stream_zlib_to`'s
    /// inner read loop. Distinct from
    /// [`Self::CompressedBlockReserveFailed`] because the
    /// `already_committed` value tells operators triaging an OOM
    /// whether the failure happened at the first chunk (small
    /// allocator pressure) or after gigabytes had accumulated
    /// (genuine large-entry OOM).
    ZlibScratchReserveFailed {
        /// 0-based block index for context.
        block_index: usize,
        /// Bytes the (failing) reservation requested.
        requested: usize,
        /// Bytes already committed to the per-block output buffer
        /// when the reservation failed (i.e. `block_out.len()` at
        /// the moment of failure). Pre-promotion this was rendered
        /// in the message text only; now structurally preserved.
        already_committed: usize,
        /// Underlying `try_reserve` failure reason.
        source: TryReserveError,
    },
    /// The underlying zlib decoder produced an error (corrupt zlib
    /// stream, unexpected EOF mid-block, etc.). [`io::Error`] isn't
    /// `Clone` or `PartialEq`, so the [`io::ErrorKind`] + message
    /// string are preserved rather than the full error. The `kind`
    /// field enables typed matching against e.g. `InvalidData` or
    /// `UnexpectedEof`; the `message` field preserves the upstream
    /// context for Display rendering and operator log greps.
    ZlibStreamError {
        /// 0-based index of the block that failed.
        block_index: usize,
        /// Kind of the underlying [`io::Error`].
        kind: io::ErrorKind,
        /// Display string of the underlying error.
        message: String,
    },
}

impl fmt::Display for DecompressionFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Wire-stable strings: match the prior `reason: String` text
        // shapes so log greps / dashboard regexes / monitoring
        // alerts continue to match.
        match self {
            Self::UnsupportedMethod { method } => {
                write!(f, "unsupported compression method {method:?}")
            }
            Self::DecompressionBomb {
                block_index,
                actual,
                claimed_uncompressed,
            } => write!(
                f,
                "block {block_index} pushed total to {actual} bytes, exceeding uncompressed_size {claimed_uncompressed}"
            ),
            Self::NonFinalBlockSizeMismatch {
                block_index,
                expected,
                actual,
            } => write!(
                f,
                "non-final block {block_index} decompressed to {actual} bytes, expected {expected}"
            ),
            Self::SizeUnderrun { actual, expected } => {
                write!(f, "decompressed {actual} bytes, expected {expected}")
            }
            // Wire-stable: matches the pre-promotion `format!` text
            // verbatim ("could not reserve N bytes for block I: e").
            Self::CompressedBlockReserveFailed {
                block_index,
                requested,
                source,
            } => write!(
                f,
                "could not reserve {requested} bytes for block {block_index}: {source}"
            ),
            // Wire-stable: matches the pre-promotion text verbatim,
            // including the `block_out.len() = K` segment that
            // operator log greps may key on.
            Self::ZlibScratchReserveFailed {
                block_index,
                requested,
                already_committed,
                source,
            } => write!(
                f,
                "could not reserve {requested} more bytes for zlib block {block_index} \
                 (block_out.len() = {already_committed}): {source}"
            ),
            Self::ZlibStreamError {
                block_index,
                message,
                ..
            } => write!(f, "zlib block {block_index}: {message}"),
        }
    }
}

/// Structured category + payload for [`PaksmithError::InvalidIndex`].
///
/// Each variant captures the operation that detected the fault plus
/// enough machine-readable context to identify it without parsing a
/// human-readable string. Tests can match exhaustively
/// (`assert!(matches!(err, PaksmithError::InvalidIndex { fault:
/// IndexParseFault::BoundsExceeded { field: WireField::FdiFileCount, .. } }))`)
/// rather than substring-scanning a `String` reason.
///
/// **Display format** mirrors the prior `reason: String` text shapes
/// so operator-visible messages are stable across the refactor — with
/// one documented exception: [`Self::AllocationFailed`] gained a
/// `unit: BoundsUnit` field in #133 (so operators can disambiguate
/// "65535 bytes" from "65535 items"), and the rendered text now reads
/// `"could not reserve N {unit} for {context}: {source}"` rather than
/// the pre-#133 `"could not reserve N {context}: {source}"`. Operator
/// log greps anchored on the *full* pre-#133 shape need a one-time
/// update; greps anchored on substrings like
/// `"could not reserve \d+ bytes"` or `"compression blocks"` keep
/// matching.
///
/// `#[non_exhaustive]` because new categories will be added as new
/// parse paths land (e.g., Phase 2 UAsset parsing); downstream
/// `match` statements survive without source breakage.
///
/// `PartialEq + Eq` (issue #94): all payload types are
/// equality-comparable as of stdlib 1.66 (`TryReserveError` got
/// `PartialEq` in that release, which had been the only blocker).
/// Enables `assert_eq!(err, expected)` in tests, complementing the
/// existing `matches!` patterns. Mirrors `InvalidFooterFault`.
#[derive(Debug, Clone, PartialEq, Eq)]
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
        /// Wire-format field name. Closed set per [`WireField`] (#134).
        field: WireField,
        /// The header-claimed value.
        value: u64,
        /// The cap it exceeds.
        limit: u64,
        /// Unit of `value`/`limit`. Lets monitoring/dashboards group
        /// alerts by units rather than parsing the `field` string.
        ///
        /// Unlike [`AllocationFailed`](Self::AllocationFailed) (where
        /// [`AllocationContext::unit`] derives the unit from the
        /// variant), `WireField` spans non-metric fields
        /// (`Sha1`, `IsEncrypted`, `CompressionMethod`) whose
        /// `BoundsExceeded` instances don't carry a meaningful
        /// bytes-vs-items distinction, so the unit stays an explicit
        /// field at the call site.
        unit: BoundsUnit,
        /// Path of the entry the bound applies to, when the field is
        /// per-entry (e.g. [`WireField::UncompressedSize`]). `None`
        /// for archive-level bounds (e.g. [`WireField::FdiSize`]).
        path: Option<String>,
    },
    /// A `try_reserve` / `try_reserve_exact` call returned `Err`.
    /// Surfaced rather than letting the allocator abort the process.
    AllocationFailed {
        /// What was being reserved. Closed set per
        /// [`AllocationContext`] (#134). The unit (bytes vs items)
        /// is derived from the context's variant via
        /// [`AllocationContext::unit`].
        context: AllocationContext,
        /// Number of `context.unit()`s we tried to reserve.
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
        /// Wire-format field name. Closed set per [`WireField`] (#134).
        field: WireField,
        /// The u64 value that didn't fit.
        value: u64,
        /// Path of the entry the field applies to, when per-entry
        /// (e.g. [`WireField::UncompressedSize`]). `None` for
        /// archive-level (e.g. [`WireField::IndexSize`]).
        path: Option<String>,
    },
    /// Two views of the same entry's metadata (in-data record vs.
    /// index header) disagreed on a specific field. This is the
    /// canonical tampering signal — UE writers don't emit
    /// inconsistent records on the happy path.
    FieldMismatch {
        /// Path of the entry whose records disagreed.
        path: String,
        /// Wire-format field name. Closed set per [`WireField`] (#134).
        field: WireField,
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
    /// archive's file size. Offending values + their upper bound
    /// are carried by the per-variant payload of
    /// [`OffsetPastFileSizeKind`] — same struct-variant pattern as
    /// [`Self::BlockBoundsViolation`] (issue #216).
    OffsetPastFileSize {
        /// Path of the entry whose offset check failed.
        path: String,
        /// Which computation surfaced the violation, with the
        /// offending value + bound carried as struct-variant fields.
        kind: OffsetPastFileSizeKind,
    },
    /// A compression block's start/end disagreed with the entry's
    /// payload region or the file. Offending values + their
    /// directional bound are carried by the per-variant payload of
    /// [`BlockBoundsKind`].
    BlockBoundsViolation {
        /// Path of the entry whose block check failed.
        path: String,
        /// 0-based index of the offending block within the entry.
        block_index: usize,
        /// Sub-category of the violation with directional payload.
        kind: BlockBoundsKind,
    },
    /// A v10+ index sub-region (FDI or PHI) declared by the
    /// main-index header would seek/read past the archive's
    /// `file_size`. Distinct from
    /// [`InvalidFooterFault::IndexRegionPastFileSize`] (which only
    /// covers the main-index region declared in the footer) — the
    /// FDI/PHI regions live at independent offsets controlled by
    /// the wire, and were previously surfacing as bare
    /// `PaksmithError::Io(UnexpectedEof)` at read time. Issue #127.
    ///
    /// Cap fires BEFORE the `MAX_FDI_BYTES`/`MAX_INDEX_BYTES`
    /// allocation, defusing the amplification where a malicious
    /// archive could force a cap-sized `Vec::resize` per
    /// `PakReader::open` call.
    RegionPastFileSize {
        /// Which sub-region's offset/size violated the file bound.
        region: IndexRegionKind,
        /// Which check fired — the offset alone or the offset+size end.
        kind: RegionPastFileSizeKind,
        /// The wire-declared region offset.
        offset: u64,
        /// The wire-declared region size.
        size: u64,
        /// The archive's actual file size — the upper bound.
        file_size: u64,
    },
    /// V10+ Path-Hash Index (PHI) disagrees with the Full Directory
    /// Index (FDI). The FDI provides the path → encoded_offset
    /// mapping authoritatively; the PHI is the hash-keyed
    /// O(1)-lookup mirror. UE writers populate them from the same
    /// source map, so any disagreement is a corruption signal — or
    /// a tampering signal in the threat model where an attacker has
    /// rewritten the PHI's stored SHA-1 (which we already verify
    /// against the main-index header per #86) to redirect a known
    /// hash to a different offset. Issue #131.
    ///
    /// The four sub-kinds discriminate via [`PhiFdiInconsistencyKind`]:
    /// missing, offset-mismatch, extra, and duplicate. Sentinel `0`
    /// values for fields that don't apply to a given kind — see the
    /// per-field docs and the kind enum's variant docs for which
    /// fields are load-bearing per kind.
    PhiFdiInconsistency {
        /// FDI-derived virtual path. Empty for [`PhiFdiInconsistencyKind::ExtraPhiEntries`]
        /// and [`PhiFdiInconsistencyKind::DuplicateHash`] (those
        /// kinds detect PHI-side anomalies that don't map back to
        /// any FDI path).
        path: String,
        /// Which class of inconsistency fired.
        kind: PhiFdiInconsistencyKind,
        /// FNV-64 of the path with the wire-stored `path_hash_seed`
        /// for [`PhiFdiInconsistencyKind::MissingPhiEntry`] /
        /// [`PhiFdiInconsistencyKind::OffsetMismatch`]; the offending
        /// PHI hash for [`PhiFdiInconsistencyKind::ExtraPhiEntries`]
        /// / [`PhiFdiInconsistencyKind::DuplicateHash`].
        expected_hash: u64,
        /// FDI's claimed `encoded_offset` for the path. `0` for kinds
        /// where no FDI counterpart exists
        /// ([`PhiFdiInconsistencyKind::ExtraPhiEntries`],
        /// [`PhiFdiInconsistencyKind::DuplicateHash`]).
        fdi_offset: i32,
        /// PHI's stored `encoded_offset`. `0` for
        /// [`PhiFdiInconsistencyKind::MissingPhiEntry`] (no PHI entry
        /// to read an offset from); the PHI's value for
        /// [`PhiFdiInconsistencyKind::OffsetMismatch`] /
        /// [`PhiFdiInconsistencyKind::ExtraPhiEntries`]; the second
        /// occurrence's offset for
        /// [`PhiFdiInconsistencyKind::DuplicateHash`].
        phi_offset: i32,
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
///
/// `PartialEq + Eq` (issue #94): same rationale as
/// [`IndexParseFault`] — all payload types are equality-comparable;
/// `assert_eq!` in tests complements `matches!`.
#[derive(Debug, Clone, PartialEq, Eq)]
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
        /// walk later); enriched by `with_index_path`
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
    ///
    /// No `actual` field: the per-push guard fires the moment the
    /// (N+1)th entry would be pushed past `file_count`, so the
    /// actual count is always `file_count + 1` by construction —
    /// carrying it would add no information. Contrast with the
    /// post-walk reconciliation in [`Self::FdiFileCountShort`],
    /// where the discrepancy can be any positive amount and the
    /// `actual` field is meaningful.
    FdiFileCountExceeded {
        /// The main-index claimed file count that the FDI overflowed.
        file_count: u32,
    },
    /// The full-directory-index walk produced FEWER entries than the
    /// main-index `file_count` claimed. Symmetric counterpart to
    /// [`Self::FdiFileCountExceeded`] for truncated FDIs (writer
    /// crash, bit-flip in a `dir_count`, hand-crafted truncated
    /// archive). Without this check, downstream consumers see a
    /// smaller archive than the original. Added in issue #87.
    ///
    /// Named `Short` (not `Underflow`) deliberately: the
    /// `Exceeded`/`Overflow` rename in #76 was specifically to
    /// escape arithmetic-overflow vocabulary (`U64ArithmeticOverflow`,
    /// `OverflowSite`); reintroducing `Underflow` here would put
    /// that mistake back into the enum. `Short` is a comparison
    /// verb like `Exceeded` and pairs naturally with it.
    FdiFileCountShort {
        /// The main-index claimed file count.
        file_count: u32,
        /// The actual count produced by walking the FDI. Always
        /// strictly less than `file_count` (equality is the valid
        /// case and short-circuits the error; the per-push guard
        /// ensures the `>` case is caught earlier as
        /// [`Self::FdiFileCountExceeded`]). `u64` so a future
        /// `entries.len() > u32::MAX` can't truncate to match
        /// `file_count` (#136).
        actual: u64,
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
                    | EncodedFault::FdiFileCountExceeded { .. }
                    | EncodedFault::FdiFileCountShort { .. },
            }
            | Self::FieldMismatch { .. }
            | Self::FStringMalformed { .. }
            | Self::InvariantViolated { .. }
            | Self::MissingFullDirectoryIndex
            | Self::OffsetPastFileSize { .. }
            | Self::RegionPastFileSize { .. }
            | Self::PhiFdiInconsistency { .. }
            | Self::ShortEntryRead { .. } => {}
        }
    }
}

/// Unit qualifier for [`IndexParseFault::BoundsExceeded`] and
/// [`IndexParseFault::AllocationFailed`].
/// Lets monitoring/dashboards group alerts by unit without parsing
/// the `field` / `context` string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BoundsUnit {
    /// `value`/`limit`/`requested` are byte counts.
    Bytes,
    /// `value`/`limit`/`requested` are item counts (entries, blocks, slots, etc.).
    Items,
}

/// Wire-format field name for [`IndexParseFault`] variants that pin a
/// specific field. Replaces the prior `field: &'static str` stringly-typed
/// pattern (closes #134).
///
/// Closed set of names rather than `&'static str` so callers and tests
/// get compile-time exhaustiveness: a typo at a callsite is a compile
/// error, and tests using `matches!(err, ... { field:
/// WireField::FdiFileCount, .. })` cannot silently pass against a stale
/// string. Same precedent as [`OverflowSite`].
///
/// `Display` emits the canonical wire-stable snake_case name. Operator
/// log greps and downstream tooling that hard-coded the previous
/// `&'static str` values keep working: every variant Displays to the
/// exact string the call site previously passed.
///
/// Derives mirror the [`OverflowSite`] / [`AllocationContext`] precedent
/// (`Debug + Clone + Copy + PartialEq + Eq`, no `Hash`). No in-tree
/// caller uses these as `HashMap` keys or in `HashSet`; add `Hash` only
/// when a real consumer materializes.
///
/// **Naming convention** (mirrors [`AllocationContext`]):
/// - `Flat` prefix for v3-v9 flat-index sites (`FlatEntryCount`).
/// - `V10` prefix for v10+-specific sites (`V10NonEncodedCount`,
///   `V10EncodedEntriesSize`).
/// - `Fdi` prefix for Full Directory Index region sites
///   (`FdiSize`, `FdiFileCount`, `FdiDirCount`).
/// - `Phi` prefix for Path Hash Index region sites (`PhiSize`,
///   `PhiEntryCount`). `Fdi`/`Phi` are v10+-exclusive by definition,
///   so the bare region prefix carries the same scope information
///   without a redundant `V10` qualifier.
/// - Bare names for per-entry fields that apply across layout versions
///   (`UncompressedSize`, `CompressedSize`, `Sha1`, `IsEncrypted`,
///   etc.) — the lack of prefix means "applies regardless of layout".
///
/// **Variant identifier ≠ Display token.** Variant names carry the
/// prefix discipline above; Display strings are wire-stable snake_case
/// (`FlatEntryCount` → `"entry_count"`, `V10EncodedEntriesSize` →
/// `"encoded_entries_size"`). A future contributor adding a new
/// prefixed variant should preserve the unprefixed Display form so
/// operator log greps and dashboards survive the rename. The pin test
/// `wire_field_display_tokens_are_wire_stable` enforces this (a typo
/// or accidental Display-rename breaks the build).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WireField {
    /// Per-entry: declared decompressed size.
    UncompressedSize,
    /// Per-entry: declared compressed (on-disk) size.
    CompressedSize,
    /// Per-entry: per-block compressed length (block end − block start).
    BlockLength,
    /// Per-entry: declared compression-block size (uniform per non-final block).
    CompressionBlockSize,
    /// Per-entry: number of compression blocks.
    BlockCount,
    /// Per-entry: SHA-1 digest field.
    Sha1,
    /// Per-entry: encryption flag.
    IsEncrypted,
    /// Per-entry: compression method discriminant.
    CompressionMethod,
    /// Per-entry: full compression-block layout (used by
    /// [`IndexParseFault::FieldMismatch`] when individual blocks differ).
    CompressionBlocks,
    /// Archive-level: number of entries in a flat (v3-v9) index.
    FlatEntryCount,
    /// Archive-level: number of non-encoded entries in a v10+ main index.
    V10NonEncodedCount,
    /// Archive-level: number of files in a v10+ Full Directory Index.
    FdiFileCount,
    /// Archive-level: number of directories in a v10+ Full Directory Index.
    FdiDirCount,
    /// Archive-level: byte size of the Full Directory Index region.
    FdiSize,
    /// Archive-level: byte size of the Path Hash Index region
    /// (issue #131). Distinct from `FdiSize` so operators grepping
    /// for PHI-region bounds violations see the right region tag
    /// in log lines / dashboards.
    PhiSize,
    /// Archive-level: entry count in the Path Hash Index body
    /// header (issue #131). Distinct from `FdiFileCount` (the FDI's
    /// file count) — surfaces when a forged PHI `count` u32
    /// exceeds the PHI byte budget.
    PhiEntryCount,
    /// Archive-level: byte size of the encoded-entries blob in a v10+ main index.
    V10EncodedEntriesSize,
    /// Archive-level: byte size of the main index (footer-declared).
    IndexSize,
}

impl fmt::Display for WireField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Wire-stable snake_case names. Match the `&'static str` values
        // that the call sites passed before #134 typified the field.
        let s = match self {
            Self::UncompressedSize => "uncompressed_size",
            Self::CompressedSize => "compressed_size",
            Self::BlockLength => "block_length",
            Self::CompressionBlockSize => "compression_block_size",
            Self::BlockCount => "block_count",
            Self::Sha1 => "sha1",
            Self::IsEncrypted => "is_encrypted",
            Self::CompressionMethod => "compression_method",
            Self::CompressionBlocks => "compression_blocks",
            Self::FlatEntryCount => "entry_count",
            Self::V10NonEncodedCount => "non_encoded_count",
            Self::FdiFileCount => "file_count",
            Self::FdiDirCount => "dir_count",
            Self::FdiSize => "fdi_size",
            Self::PhiSize => "phi_size",
            Self::PhiEntryCount => "phi_entry_count",
            Self::V10EncodedEntriesSize => "encoded_entries_size",
            Self::IndexSize => "index_size",
        };
        f.write_str(s)
    }
}

/// What was being allocated when [`IndexParseFault::AllocationFailed`]
/// fires. Replaces the prior `context: &'static str` stringly-typed
/// pattern (closes #134).
///
/// Closed set of allocation sites rather than free-form labels so a
/// new reservation site requires explicitly extending this enum (caught
/// at compile time) rather than typing a fresh ad-hoc string.
///
/// `Display` emits a bare noun-phrase label naming WHAT was being
/// reserved (no leading unit word). The unit is rendered separately
/// by the `AllocationFailed` Display arm via [`Self::unit`], so the
/// rendered shape is `"could not reserve N {unit} for {context}:
/// {source}"` — e.g. `"could not reserve 65536 bytes for v10+ index:
/// ..."` or `"could not reserve 32 items for compression blocks:
/// ..."`. The bare-label convention prevents the `"bytes for bytes
/// for v10+ index"` stutter that would result from contexts whose
/// pre-#134 strings already led with the unit word.
///
/// **Wire-stability vs pre-PR #144 (#134):** for the `*Bytes`
/// variants, the rendered text gains a `for {label}` suffix that
/// disambiguates the unit (the operator alert grep
/// `"could not reserve \d+ bytes"` keeps matching, just with more
/// detail after). For the `*Items`-unit variants, the pre-#134
/// `&'static str` strings already contained the noun-phrase the unit
/// suggests ("compression blocks"), so the rendered shape is
/// `"could not reserve N items for compression blocks: ..."` — also
/// a one-time text change from `"compression blocks: ..."`. Operator
/// log greps that anchored on the *full* `"could not reserve N {old-
/// context}: ..."` shape will need a one-time update.
///
/// **Naming convention** (for new variants — applied uniformly here):
/// - Prefix `V10` for v10+-specific allocation sites (`V10MainIndexBytes`,
///   `V10IndexEntries`, etc.).
/// - Prefix `Inline`/`Encoded` for the two compression-block read paths.
/// - Prefix `Flat` for v3-v9 flat-layout sites.
/// - Suffix `Bytes` for raw byte buffers (paired with `BoundsUnit::Bytes`).
/// - Suffix with a domain plural noun for typed-element collections.
/// - Bare names (no scope prefix) for version-agnostic sites: utility
///   allocations like `DedupTracker` and `ByPathLookup`, and per-entry
///   buffers like `EntryPayloadBytes` (the `Bytes` suffix marks the
///   raw-byte-buffer shape; "bare" refers to the absent layout-version
///   prefix, not the absent suffix).
///
/// **Suffix is load-bearing for [`Self::unit`].** A variant whose
/// reservation is byte-keyed MUST end in `Bytes`; everything else maps
/// to `BoundsUnit::Items`. Naming a u16-slot reservation `*Bytes` or a
/// byte-buffer reservation without the `Bytes` suffix silently mislabels
/// the rendered fault. The mapping is pinned by
/// `allocation_context_unit_mapping_is_pinned`; if a new variant breaks
/// the suffix↔unit contract, the test catches it but the warning is
/// here so the naming choice is deliberate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AllocationContext {
    /// Per-entry payload byte buffer.
    /// Constructed in `PakReader::read_entry` (the `ContainerReader`
    /// trait override at `container/pak/mod.rs`'s `read_entry`
    /// implementation), which allocates the output Vec upfront before
    /// streaming into it.
    EntryPayloadBytes,
    /// Per-entry compression-block records, inline-header read path.
    InlineCompressionBlocks,
    /// Per-entry compression-block records, encoded-header read path.
    EncodedCompressionBlocks,
    /// Flat-index entries vector (v3-v9 sequential index).
    FlatIndexEntries,
    /// Per-walk dedup tracker (HashSet of seen filenames).
    DedupTracker,
    /// `by_path` lookup HashMap for fast entry resolution.
    ByPathLookup,
    /// v10+ main-index byte buffer (slurp before parsing).
    V10MainIndexBytes,
    /// v10+ encoded-entries blob byte buffer.
    V10EncodedEntriesBytes,
    /// v10+ non-encoded entries vector.
    V10NonEncodedEntries,
    /// v10+ Full Directory Index byte buffer.
    V10FdiBytes,
    /// v10+ Path Hash Index byte buffer (issue #131). Slurped at
    /// parse time so the FDI/PHI cross-validation can resolve hash
    /// keys against the path-walk. Bounded by `MAX_FDI_BYTES`
    /// (the PHI's worst case is roughly proportional to the FDI
    /// path count — 12 bytes per entry plus 4 for the count header).
    V10PhiBytes,
    /// v10+ Path Hash Index entries `HashMap<u64, i32>` (issue
    /// #146 R1 finding): the parsed PHI table is reserved as a
    /// HashMap with count entries, distinct from the byte-buffer
    /// slurp [`Self::V10PhiBytes`]. Split into its own variant so
    /// `unit()` returns the structurally-correct
    /// [`BoundsUnit::Items`].
    V10PhiEntries,
    /// v10+ entries vector (combined encoded + non-encoded view).
    V10IndexEntries,
    /// FString UTF-8 byte buffer (issue #132 item 3). Allocated in
    /// `fstring::read_fstring` for positive-length (UTF-8) FStrings.
    /// Bounded by `FSTRING_MAX_LEN = 65 536` bytes.
    FStringUtf8Bytes,
    /// FString UTF-16 code-unit buffer (issue #132 item 3).
    /// Allocated in `fstring::read_fstring` for negative-length
    /// (UTF-16) FStrings. Bounded by `FSTRING_MAX_LEN = 65 536`
    /// code units (= 131 072 bytes). `unit: BoundsUnit::Items`
    /// since the reservation is in u16 slots, not bytes.
    FStringUtf16CodeUnits,
    /// v10+ FDI full-path string buffer (issue #132 item 3).
    /// Allocated per FDI walk iteration when joining
    /// `dir_prefix + file_name`. Bounded transitively by the
    /// per-FString cap (`2 * FSTRING_MAX_LEN`).
    FdiFullPathBytes,
}

impl AllocationContext {
    /// Unit of the `requested` field on
    /// [`IndexParseFault::AllocationFailed`]. Derived structurally
    /// from the variant naming: `*Bytes` variants reserve byte
    /// buffers; `FStringUtf16CodeUnits` reserves u16 slots
    /// (`BoundsUnit::Items`); the remaining variants reserve item
    /// vectors / map entries. Single source of truth — call sites
    /// cannot pair the wrong unit with a context.
    #[must_use]
    pub fn unit(&self) -> BoundsUnit {
        match self {
            Self::EntryPayloadBytes
            | Self::V10MainIndexBytes
            | Self::V10EncodedEntriesBytes
            | Self::V10FdiBytes
            | Self::V10PhiBytes
            | Self::FStringUtf8Bytes
            | Self::FdiFullPathBytes => BoundsUnit::Bytes,
            Self::InlineCompressionBlocks
            | Self::EncodedCompressionBlocks
            | Self::FlatIndexEntries
            | Self::DedupTracker
            | Self::ByPathLookup
            | Self::V10NonEncodedEntries
            | Self::V10PhiEntries
            | Self::V10IndexEntries
            | Self::FStringUtf16CodeUnits => BoundsUnit::Items,
        }
    }
}

impl fmt::Display for AllocationContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Bare noun-phrase labels — the unit is rendered separately by
        // the `AllocationFailed` Display arm so this string MUST NOT
        // begin with the unit word, or the rendered text stutters
        // (e.g. "bytes for bytes for v10+ index").
        //
        // Pinned per-variant by `allocation_context_display_tokens_are_wire_stable`.
        let s = match self {
            Self::EntryPayloadBytes => "entry payload",
            Self::InlineCompressionBlocks => "compression blocks",
            Self::EncodedCompressionBlocks => "encoded compression blocks",
            Self::FlatIndexEntries => "entries",
            Self::DedupTracker => "dedup tracker for entries",
            Self::ByPathLookup => "by-path lookup entries",
            Self::V10MainIndexBytes => "v10+ index",
            Self::V10EncodedEntriesBytes => "v10+ encoded entries",
            Self::V10NonEncodedEntries => "non-encoded entries for v10+ index",
            Self::V10FdiBytes => "v10+ full directory index",
            Self::V10PhiBytes => "v10+ path hash index",
            Self::V10PhiEntries => "entries for v10+ path hash index",
            Self::V10IndexEntries => "entries for v10+ index",
            Self::FStringUtf8Bytes => "FString UTF-8 buffer",
            Self::FStringUtf16CodeUnits => "FString UTF-16 code units",
            Self::FdiFullPathBytes => "FDI full-path buffer",
        };
        f.write_str(s)
    }
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
    /// **Comparator**: `entry_offset >= file_size_max` (inclusive
    /// — equality means the header would start AT EOF, can't be
    /// read).
    EntryHeaderOffset {
        /// The entry header's declared `offset` field on the wire.
        entry_offset: u64,
        /// The archive's recorded file size — the upper bound
        /// `entry_offset` must stay strictly less than.
        file_size_max: u64,
    },
    /// The entry's payload-end (computed from header `offset + size`)
    /// is past `file_size`. The header reads fine but its payload
    /// region extends past EOF.
    /// **Comparator**: `payload_end > file_size_max` (strict —
    /// equality means the payload ends exactly at EOF, which is
    /// fine; the upper bound is exclusive).
    PayloadEndBounds {
        /// The computed payload-end byte offset
        /// (`entry_offset + in_data + compressed_size`).
        payload_end: u64,
        /// The archive's recorded file size — the upper bound
        /// `payload_end` must stay at-or-below.
        file_size_max: u64,
    },
}

impl fmt::Display for OffsetPastFileSizeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Wire-stable strings: the operator-facing diagnostic
        // distinguishes the two cases via these tokens, so log
        // greps / dashboards keep working across refactors. The
        // per-variant struct payload is rendered by the parent
        // `OffsetPastFileSize` Display arm as `observed=`/`limit=`,
        // not here.
        let s = match self {
            Self::EntryHeaderOffset { .. } => "header offset past file_size",
            Self::PayloadEndBounds { .. } => "payload end past file_size",
        };
        f.write_str(s)
    }
}

/// Sub-category of [`IndexParseFault::BlockBoundsViolation`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BlockBoundsKind {
    /// Block start was below the payload region (overlapping the
    /// in-data FPakEntry header). Failure condition:
    /// `block_start < payload_start_min`.
    StartOverlapsHeader {
        /// The block's absolute start offset on disk.
        block_start: u64,
        /// The minimum legal start (payload region begin).
        /// `block_start` must be `>=` this.
        payload_start_min: u64,
    },
    /// Block end was past the file's recorded size. Failure
    /// condition: `block_end > file_size_max`.
    EndPastFileSize {
        /// The block's absolute end offset on disk (exclusive).
        block_end: u64,
        /// The maximum legal end (recorded file size). `block_end`
        /// must be `<=` this.
        file_size_max: u64,
    },
    /// Block start was less than the previous block's end —
    /// blocks must be declared in strictly monotonically-increasing
    /// file order (overlapping or backward-ordered blocks would
    /// decompress fine but make `verify_entry`'s "same archive ⇒
    /// same hash" guarantee dependent on the declared (mutable)
    /// block order rather than on payload content). Issue #129.
    /// Failure condition: `block_start < prev_block_end_min`.
    OutOfOrder {
        /// The offending block's absolute start offset.
        block_start: u64,
        /// The preceding block's absolute end offset — the lower
        /// bound `block_start` must equal-or-exceed.
        prev_block_end_min: u64,
    },
}

/// Discriminator for [`IndexParseFault::RegionPastFileSize`]: which
/// v10+ sub-region's offset/size violated the file bound.
///
/// Display tokens are wire-stable — operators / log greps match on
/// `"fdi"` / `"phi"` to filter by region. Distinct from the footer's
/// `IndexRegionPastFileSize` (`"index extends past EOF: ..."`) which
/// covers only the main-index region declared in the footer; this
/// enum covers the two sub-regions declared INSIDE the main-index
/// header. Issue #127.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IndexRegionKind {
    /// Full Directory Index. Carries the `(dir_name, [(file_name,
    /// encoded_offset)])` walk used for path recovery.
    Fdi,
    /// Path Hash Index. Optional FNV-64 `(hash, encoded_offset)`
    /// table; paksmith skips parsing it today but still hashes its
    /// bytes for tamper-detection via [`Self::Fdi`]'s sibling
    /// verification path.
    Phi,
}

/// Discriminator for [`IndexParseFault::RegionPastFileSize`]: which
/// check fired. Symmetric with [`OffsetPastFileSizeKind`] but at
/// region scope rather than entry scope.
///
/// Display tokens are wire-stable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RegionPastFileSizeKind {
    /// The region's declared `offset` alone is at-or-past
    /// `file_size`. Comparator: `offset >= file_size` (inclusive —
    /// equality means the region would start AT EOF, can't be read).
    OffsetPastEof,
    /// The region's `offset` is in-range but `offset + size`
    /// exceeds `file_size`. Comparator: `offset + size > file_size`
    /// (strict — equality means the region ends exactly at EOF,
    /// which is fine; the upper bound is exclusive).
    RegionEndPastEof,
}

/// Discriminator for [`IndexParseFault::PhiFdiInconsistency`]:
/// which class of PHI/FDI disagreement fired. Issue #131.
///
/// Wire-stable Display tokens. Operators / log greps filter on
/// `"missing PHI entry"`, `"PHI/FDI offset mismatch"`, etc.
///
/// All four kinds are corruption signals — UE writers populate
/// the PHI and FDI from the same source map, so a well-formed
/// archive can never produce any of them. In the attacker model
/// where the PHI's stored SHA-1 in the main-index header has also
/// been rewritten (the only way to make the bytes hash-clean while
/// disagreeing with FDI), this variant is the only line of defense.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PhiFdiInconsistencyKind {
    /// FDI references a path whose FNV-64 hash is not present in
    /// the PHI table. UE writers always populate the PHI from the
    /// same source as the FDI, so a missing entry is a tampered-
    /// or corrupted-PHI signal. `phi_offset` is carried as `0`
    /// (no PHI entry to read).
    MissingPhiEntry,
    /// PHI's stored offset for the path's hash disagrees with the
    /// FDI's offset for that path. This is the canonical "redirect
    /// a known hash to a different offset" attack the issue #131
    /// pathological-input section describes.
    OffsetMismatch,
    /// PHI contains entries whose FNV-64 hashes do not correspond
    /// to any FDI-walked path. Catches the "stuff PHI with extras
    /// pointing nowhere" amplification. `path` is empty and
    /// `fdi_offset` is `0` (no FDI counterpart to reference).
    ExtraPhiEntries,
    /// PHI contains two or more entries with the same FNV-64 hash.
    /// UE's writer (per repak's `generate_path_hash_index`) emits
    /// one entry per source path; collisions in FNV-64 over
    /// realistic UE path counts (~10⁻¹⁰ for 100K paths) are
    /// astronomical, so a duplicate is structural malformation.
    /// `path` is empty and `fdi_offset` is `0`; `expected_hash`
    /// is the colliding hash and `phi_offset` is the second
    /// occurrence's offset.
    DuplicateHash,
}

/// Sub-category of [`IndexParseFault::FStringMalformed`].
///
/// `PartialEq + Eq` (issue #94 transitive): `FStringFault` is nested
/// inside [`IndexParseFault::FStringMalformed`], so the parent's
/// `PartialEq + Eq` derives require the same on the payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FStringFault {
    /// Length prefix was `0`. UE's writer convention represents an
    /// empty FString as `len=1, byte=0x00` (one-byte null terminator
    /// only), never `len=0`. The historical "len=0 → empty string"
    /// short-circuit was a footgun: it accepted a 4-byte record
    /// shape never produced by UE writers, and made
    /// `MIN_FDI_*_RECORD_BYTES = 9` (which assumes the 5-byte
    /// minimum FString) loose by ~12.5% against an adversarial
    /// FDI packing `len=0` records. Issue #104.
    LengthIsZero,
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
            Self::LengthIsZero => {
                write!(f, "FString length is zero (UE writes empty as len=1+nul)")
            }
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
///
/// `PartialEq + Eq` (issue #94 transitive): `FStringEncoding` is
/// nested inside [`FStringFault::MissingNullTerminator`] and
/// [`FStringFault::InvalidEncoding`], so the chain back to
/// `IndexParseFault`'s `PartialEq + Eq` derives requires it here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
        // Wire-stable tokens — pinned by the
        // `index_parse_fault_display_block_bounds_*` tests. The
        // per-variant struct payload is rendered by the parent
        // `BlockBoundsViolation` Display arm as `observed=`/`limit=`,
        // not here.
        match self {
            Self::StartOverlapsHeader { .. } => write!(f, "start overlaps in-data header"),
            Self::EndPastFileSize { .. } => write!(f, "end exceeds file_size"),
            Self::OutOfOrder { .. } => write!(f, "out of order with previous block"),
        }
    }
}

impl std::fmt::Display for IndexRegionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Fdi => "fdi",
            Self::Phi => "phi",
        };
        f.write_str(s)
    }
}

impl std::fmt::Display for RegionPastFileSizeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::OffsetPastEof => "offset past EOF",
            Self::RegionEndPastEof => "extends past EOF",
        };
        f.write_str(s)
    }
}

impl std::fmt::Display for PhiFdiInconsistencyKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::MissingPhiEntry => "missing PHI entry",
            Self::OffsetMismatch => "PHI/FDI offset mismatch",
            Self::ExtraPhiEntries => "extra PHI entries",
            Self::DuplicateHash => "duplicate PHI hash",
        };
        f.write_str(s)
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
                // Wire format: include the unit so operators sizing
                // budget alerts can distinguish "{N} bytes for X"
                // from "{N} items for X". Unit derived from the
                // context per [`AllocationContext::unit`].
                if let Some(p) = path {
                    write!(
                        f,
                        "could not reserve {requested} {unit} for {context} for entry `{p}`: {source}",
                        unit = context.unit(),
                    )
                } else {
                    write!(
                        f,
                        "could not reserve {requested} {unit} for {context}: {source}",
                        unit = context.unit(),
                    )
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
            Self::OffsetPastFileSize { path, kind } => {
                // Map per-variant struct payload back to the wire-
                // stable `observed=`/`limit=` tokens — see the
                // `BlockBoundsViolation` arm above for the same
                // pattern + rationale (issues #135 / #216).
                let (observed, limit) = match *kind {
                    OffsetPastFileSizeKind::EntryHeaderOffset {
                        entry_offset,
                        file_size_max,
                    } => (entry_offset, file_size_max),
                    OffsetPastFileSizeKind::PayloadEndBounds {
                        payload_end,
                        file_size_max,
                    } => (payload_end, file_size_max),
                };
                write!(
                    f,
                    "entry `{path}` {kind}: observed={observed} limit={limit}"
                )
            }
            Self::BlockBoundsViolation {
                path,
                block_index,
                kind,
            } => {
                // Map per-variant struct payload back to the wire-
                // stable `observed=`/`limit=` tokens that log greps
                // and operator dashboards pin on — see the
                // `index_parse_fault_display_block_bounds_*` tests
                // for the byte-for-byte assertions. Kept inline (vs
                // a `BlockBoundsKind::observed_and_limit()` accessor)
                // so the projection lives at the only consumer site
                // instead of being frozen as a stable API surface
                // that would re-introduce the implicit-direction
                // contract one level deeper.
                let (observed, limit) = match *kind {
                    BlockBoundsKind::StartOverlapsHeader {
                        block_start,
                        payload_start_min,
                    } => (block_start, payload_start_min),
                    BlockBoundsKind::EndPastFileSize {
                        block_end,
                        file_size_max,
                    } => (block_end, file_size_max),
                    BlockBoundsKind::OutOfOrder {
                        block_start,
                        prev_block_end_min,
                    } => (block_start, prev_block_end_min),
                };
                write!(
                    f,
                    "entry `{path}` block {block_index} {kind}: observed={observed} limit={limit}"
                )
            }
            Self::RegionPastFileSize {
                region,
                kind,
                offset,
                size,
                file_size,
            } => {
                write!(
                    f,
                    "{region} {kind}: offset={offset} size={size} file_size={file_size}"
                )
            }
            Self::PhiFdiInconsistency {
                path,
                kind,
                expected_hash,
                fdi_offset,
                phi_offset,
            } => {
                // Uniform shape across all four kinds so log greps can
                // pattern-match on `{kind}: ` consistently. `path` is
                // empty for Extra/Duplicate; the rendered text reads
                // sensibly either way (`""` quotes empty for those
                // kinds, making it obvious no path is implicated).
                write!(
                    f,
                    "{kind} at path \"{path}\" (hash=0x{expected_hash:016x} fdi_offset={fdi_offset} phi_offset={phi_offset})"
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
            Self::FdiFileCountShort { file_count, actual } => {
                write!(
                    f,
                    "v10+ FDI walk yielded {actual} entries but file_count claims {file_count}"
                )
            }
        }
    }
}

/// What was being SHA1-verified when a [`PaksmithError::HashMismatch`]
/// fired. Splitting "index vs entry" into a typed enum makes nonsensical
/// combinations (entry without path, index with path) unrepresentable.
///
/// `#[non_exhaustive]` so future targets (e.g., the IoStore manifest
/// region, or per-block compressed-data hashes that some UE versions
/// emit) can be added without breaking downstream pattern-matchers.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
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
    /// V10+ full directory index region. Lives at an arbitrary file
    /// offset outside the main-index byte range; the main-index header
    /// carries an independent SHA1 slot for it. The pre-#86 reader
    /// discarded the slot, leaving FDI bytes covered by nothing — a
    /// silent tamper-detection gap closed by hashing this region in
    /// [`crate::container::pak::PakReader::verify_index`].
    Fdi,
    /// V10+ path hash index region (optional). Same shape as [`Self::Fdi`];
    /// only present when the archive's main-index header recorded
    /// `has_path_hash_index = true`. paksmith doesn't consult the
    /// path-hash table at parse time (the FDI provides full paths
    /// directly), so the hash slot is the ONLY line of defense for
    /// PHI bytes.
    Phi,
}

impl std::fmt::Display for HashTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Index => f.write_str("index"),
            Self::Entry { path } => write!(f, "entry `{path}`"),
            Self::Fdi => f.write_str("v10+ full directory index"),
            Self::Phi => f.write_str("v10+ path hash index"),
        }
    }
}

impl From<IndexRegionKind> for HashTarget {
    fn from(region: IndexRegionKind) -> Self {
        match region {
            IndexRegionKind::Fdi => Self::Fdi,
            IndexRegionKind::Phi => Self::Phi,
        }
    }
}

/// Defense-in-depth helper: validate a v10+ index sub-region's
/// `(offset, size)` against `file_size` before any seek/read/alloc.
/// Returns the typed [`IndexParseFault::RegionPastFileSize`] fault on
/// violation, distinguishing `OffsetPastEof` (offset alone past EOF;
/// no `read_exact` can succeed) from `RegionEndPastEof` (offset
/// in-range but `offset + size` exceeds the file or overflows `u64`).
///
/// Used at FDI parse time (in the v10+ index parser) AND FDI/PHI
/// verify time ([`crate::container::pak::PakReader::verify_index`]) —
/// colocated here so both call sites share one comparator definition
/// and one Display shape. Issue #127.
pub(crate) fn check_region_bounds(
    region: IndexRegionKind,
    offset: u64,
    size: u64,
    file_size: u64,
) -> Result<(), IndexParseFault> {
    if offset >= file_size {
        return Err(IndexParseFault::RegionPastFileSize {
            region,
            kind: RegionPastFileSizeKind::OffsetPastEof,
            offset,
            size,
            file_size,
        });
    }
    if offset.checked_add(size).is_none_or(|end| end > file_size) {
        return Err(IndexParseFault::RegionPastFileSize {
            region,
            kind: RegionPastFileSizeKind::RegionEndPastEof,
            offset,
            size,
            file_size,
        });
    }
    Ok(())
}

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
    /// of the values Phase 2a supports (`-7`, `-8`, or `-9`). Earlier
    /// values (`-6` and shallower) shipped with UE 4.20 and below;
    /// later values (`-10` and beyond) don't exist yet. Rejected
    /// explicitly rather than risking silent misparse of a divergent
    /// on-disk layout.
    UnsupportedLegacyFileVersion {
        /// The legacy file version read from the asset.
        version: i32,
    },
    /// The asset is uncooked (`PKG_FilterEditorOnly` NOT set in
    /// `package_flags`) and the `FileVersionUE4` is at or above
    /// `VER_UE4_NON_OUTER_PACKAGE_IMPORT (520)`. At that version,
    /// uncooked `FObjectImport` carries an extra `PackageName` FName
    /// that paksmith's import reader does NOT consume; the cursor
    /// would silently mis-align by 8 bytes per record. Phase 2a's
    /// primary target is pak-extracted (cooked) assets, so this
    /// variant exists to reject uncooked input at the summary
    /// boundary rather than silently misparse downstream.
    UncookedAsset {
        /// The `package_flags` value as read from the wire.
        package_flags: u32,
        /// The `file_version_ue4` value as read from the wire.
        file_version_ue4: i32,
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
    /// `FileVersionUE5` is above the Phase 2a ceiling (1010).
    /// At UE5 version 1011 (`PROPERTY_TAG_EXTENSION_AND_OVERRIDABLE_SERIALIZATION`),
    /// UE adds a byte to `FPropertyTag` that Phase 2b's tagged-
    /// property reader cannot decode. The export-table reader itself
    /// is shape-stable at 1011 (per-export `package_guid` was already
    /// removed at 1005; summary-level FGuid migrates to FIoHash at
    /// 1016, well above the ceiling). The variant exists so Task 9
    /// (`PackageSummary`) can reject out-of-range assets at the
    /// summary boundary before downstream readers misparse.
    UnsupportedFileVersionUE5 {
        /// The UE5 version read from the asset.
        version: i32,
        /// The Phase 2a ceiling (exclusive — first unsupported value).
        first_unsupported: i32,
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
    /// A `PackageIndex` resolved to an import/export table slot that
    /// doesn't exist. Fires from the import-walk (when an
    /// `OuterIndex` references a missing import) and from the
    /// export-walk symmetrically.
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
    /// would be transformed and the offset arithmetic in the asset
    /// `Package` wouldn't apply directly. Modern UE writers always
    /// emit `0` here; non-zero signals an older or non-standard
    /// cooker.
    UnsupportedCompressionInSummary {
        /// Which of the two summary slots tripped.
        site: CompressionInSummarySite,
        /// The observed value at the site (the flags value or the
        /// chunks count). Signed so a negative `compressed_chunks_count`
        /// — itself a wire-format violation — surfaces with its actual
        /// value rather than being clamped to zero. `compression_flags`
        /// is a `u32` on the wire and always fits non-negatively.
        observed: i64,
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
        /// What was being reserved. Unit (bytes vs items) is derived
        /// from the context's variant via
        /// [`AssetAllocationContext::unit`].
        context: AssetAllocationContext,
        /// Number of `context.unit()`s the reservation requested.
        requested: usize,
        /// Underlying allocator failure.
        source: TryReserveError,
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
    /// A UE bool32 wire-field carried a value other than 0 or 1.
    /// CUE4Parse's `FArchive.ReadBoolean` rejects any other value;
    /// paksmith now matches that contract rather than collapsing
    /// non-zero bytes to `true`. Produced only by malicious or
    /// corrupted archives — UE writers always emit 0 or 1.
    InvalidBool32 {
        /// Which wire-field carried the invalid value.
        field: AssetWireField,
        /// The raw i32 read from the wire.
        observed: i32,
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
                 (paksmith Phase 2a accepts -7, -8, and -9)"
            ),
            Self::UncookedAsset {
                package_flags,
                file_version_ue4,
            } => write!(
                f,
                "uncooked asset (package_flags=0x{package_flags:08x}, file_version_ue4={file_version_ue4}); \
                 paksmith requires PKG_FilterEditorOnly to be set on assets at \
                 FileVersionUE4 >= 520"
            ),
            Self::UnsupportedFileVersionUE4 { version, minimum } => write!(
                f,
                "unsupported FileVersionUE4 {version} (minimum {minimum})"
            ),
            Self::UnsupportedFileVersionUE5 {
                version,
                first_unsupported,
            } => write!(
                f,
                "unsupported FileVersionUE5 {version} (Phase 2a ceiling is {})",
                first_unsupported - 1
            ),
            Self::BoundsExceeded {
                field,
                value,
                limit,
                unit,
            } => {
                write!(f, "{field} {value} exceeds maximum {limit} {unit}")
            }
            Self::InvalidOffset {
                field,
                offset,
                asset_size,
            } => write!(
                f,
                "{field} offset {offset} out of bounds (asset size {asset_size})"
            ),
            Self::NegativeValue { field, value } => write!(f, "{field} value {value} is negative"),
            Self::PackageIndexOob {
                field,
                index,
                table_size,
            } => write!(
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
            Self::FStringMalformed { kind } => write!(f, "{kind}"),
            Self::U64ExceedsPlatformUsize { field, value } => {
                write!(f, "{field} value {value} exceeds platform usize")
            }
            Self::AllocationFailed {
                context,
                requested,
                source,
            } => write!(
                f,
                "could not reserve {requested} {unit} for {context}: {source}",
                unit = context.unit(),
            ),
            Self::U64ArithmeticOverflow { operation } => {
                write!(f, "u64 arithmetic overflow during {operation}")
            }
            Self::UnexpectedEof { field } => {
                write!(f, "unexpected EOF reading {field}")
            }
            Self::InvalidBool32 { field, observed } => write!(
                f,
                "{field} bool32 value {observed} is not 0 or 1 (CUE4Parse's \
                 FArchive.ReadBoolean rejects any other value)"
            ),
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
    /// `FPackageFileSummary::GenerationCount` (an `i32` count for the
    /// `FGenerationInfo` array; rows are discarded by paksmith).
    GenerationCount,
    /// `FPackageFileSummary::AdditionalPackagesToCookCount` (an `i32`
    /// count for the `additional_packages_to_cook` FString array; rows
    /// are discarded by paksmith).
    AdditionalPackagesToCookCount,
    /// `FPackageFileSummary::ChunkIdCount` (an `i32` count for the
    /// chunk-ids `i32` array; rows are discarded by paksmith).
    ChunkIdCount,
    /// `FObjectExport::bForcedExport` — UE bool32.
    ExportForcedExport,
    /// `FObjectExport::bNotForClient` — UE bool32.
    ExportNotForClient,
    /// `FObjectExport::bNotForServer` — UE bool32.
    ExportNotForServer,
    /// `FObjectExport::bIsInheritedInstance` — UE bool32 (UE5 >= 1006).
    ExportIsInheritedInstance,
    /// `FObjectExport::bNotAlwaysLoadedForEditorGame` — UE bool32.
    ExportNotAlwaysLoadedForEditorGame,
    /// `FObjectExport::bIsAsset` — UE bool32.
    ExportIsAsset,
    /// `FObjectExport::bGeneratePublicHash` — UE bool32 (UE5 >= 1003).
    ExportGeneratePublicHash,
    /// `FObjectImport::bImportOptional` — UE bool32 (UE5 >= 1003).
    ImportOptional,
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
            Self::GenerationCount => "generation_count",
            Self::AdditionalPackagesToCookCount => "additional_packages_to_cook_count",
            Self::ChunkIdCount => "chunk_id_count",
            Self::ExportForcedExport => "export_forced_export",
            Self::ExportNotForClient => "export_not_for_client",
            Self::ExportNotForServer => "export_not_for_server",
            Self::ExportIsInheritedInstance => "export_is_inherited_instance",
            Self::ExportNotAlwaysLoadedForEditorGame => "export_not_always_loaded_for_editor_game",
            Self::ExportIsAsset => "export_is_asset",
            Self::ExportGeneratePublicHash => "export_generate_public_hash",
            Self::ImportOptional => "import_optional",
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
    /// `Vec<PropertyBag>` for the per-export payload collection.
    ExportPayloads,
}

impl AssetAllocationContext {
    /// Unit of the `requested` field on
    /// [`AssetParseFault::AllocationFailed`]. Same derivation as
    /// [`AllocationContext::unit`] — `*Bytes` variants reserve
    /// byte buffers; the rest reserve item vectors.
    #[must_use]
    pub fn unit(&self) -> BoundsUnit {
        match self {
            Self::ExportPayloadBytes => BoundsUnit::Bytes,
            Self::NameTable
            | Self::ImportTable
            | Self::ExportTable
            | Self::CustomVersionContainer
            | Self::ExportPayloads => BoundsUnit::Items,
        }
    }
}

impl fmt::Display for AssetAllocationContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::NameTable => "name table",
            Self::ImportTable => "import table",
            Self::ExportTable => "export table",
            Self::CustomVersionContainer => "custom-version container",
            Self::ExportPayloadBytes => "export payload bytes",
            Self::ExportPayloads => "export payloads",
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

#[cfg(test)]
mod tests {
    use super::*;

    /// `with_index_path` MUST preserve any path the inner fault
    /// already carries. The FDI walk is one of potentially several
    /// future enrichment boundaries; if a deeper layer happens to
    /// know the path first, we don't want the FDI walk to clobber
    /// it. Pin the runtime check in `set_path_if_unset`'s
    /// `if path.is_none()` arms.
    #[test]
    fn with_index_path_does_not_overwrite_existing_path() {
        let err = PaksmithError::InvalidIndex {
            fault: IndexParseFault::BoundsExceeded {
                field: WireField::UncompressedSize,
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
    fn error_display_invalid_footer_other() {
        let err = PaksmithError::InvalidFooter {
            fault: InvalidFooterFault::OtherUnpromoted {
                reason: "magic mismatch".into(),
            },
        };
        assert_eq!(err.to_string(), "invalid pak footer: magic mismatch");
    }

    /// Issue #64: pin the new typed-variant Display strings for the
    /// two index-bounds-check sites. Companion to the typed-`matches!`
    /// regression tests in footer.rs's tests module.
    #[test]
    fn error_display_invalid_footer_index_region_offset_overflow() {
        let err = PaksmithError::InvalidFooter {
            fault: InvalidFooterFault::IndexRegionOffsetOverflow {
                offset: u64::MAX,
                size: 1,
            },
        };
        let s = err.to_string();
        assert!(s.contains("invalid pak footer:"), "got: {s}");
        assert!(s.contains("overflows u64"), "got: {s}");
        assert!(s.contains("offset="), "got: {s}");
        assert!(s.contains("size="), "got: {s}");
    }

    #[test]
    fn error_display_invalid_footer_index_region_past_file_size() {
        let err = PaksmithError::InvalidFooter {
            fault: InvalidFooterFault::IndexRegionPastFileSize {
                offset: 1_536,
                size: 512,
                file_size: 1_024,
            },
        };
        let s = err.to_string();
        assert!(s.contains("invalid pak footer:"), "got: {s}");
        assert!(s.contains("past EOF"), "got: {s}");
        // Pin all three raw inputs (#64 type-design HIGH: must
        // expose offset+size separately, not just the computed sum,
        // so operators can spot which footer field was lying).
        assert!(s.contains("offset=1536"), "got: {s}");
        assert!(s.contains("size=512"), "got: {s}");
        assert!(s.contains("file_size=1024"), "got: {s}");
    }

    #[test]
    fn error_display_decompression_includes_path_and_fault() {
        // Use ZlibStreamError as a representative variant; the
        // wire-stable Display string mirrors the prior `reason: String`
        // shape ("zlib block N: <message>").
        let err = PaksmithError::Decompression {
            path: "Content/X.uasset".into(),
            offset: 1024,
            fault: DecompressionFault::ZlibStreamError {
                block_index: 0,
                kind: io::ErrorKind::InvalidData,
                message: "invalid zlib stream".into(),
            },
        };
        assert_eq!(
            err.to_string(),
            "decompression failed for `Content/X.uasset` at offset 1024: zlib block 0: invalid zlib stream"
        );
    }

    // Per-variant Display assertions for DecompressionFault. The
    // `Display` impl carries a wire-stable contract (operator log
    // greps and monitoring rules key on these strings); these tests
    // pin every variant's rendered output against the pre-promotion
    // `format!` text so accidental drift fails CI rather than
    // silently breaking downstream observability. Mirrors the
    // per-variant test pattern used for `InvalidFooterFault` above.

    #[test]
    fn decompression_fault_display_unsupported_method() {
        let fault = DecompressionFault::UnsupportedMethod {
            method: CompressionMethod::Oodle,
        };
        assert_eq!(fault.to_string(), "unsupported compression method Oodle");
    }

    #[test]
    fn decompression_fault_display_decompression_bomb() {
        let fault = DecompressionFault::DecompressionBomb {
            block_index: 3,
            actual: 4097,
            claimed_uncompressed: 4096,
        };
        assert_eq!(
            fault.to_string(),
            "block 3 pushed total to 4097 bytes, exceeding uncompressed_size 4096"
        );
    }

    #[test]
    fn decompression_fault_display_non_final_block_size_mismatch() {
        let fault = DecompressionFault::NonFinalBlockSizeMismatch {
            block_index: 1,
            expected: 65536,
            actual: 32768,
        };
        assert_eq!(
            fault.to_string(),
            "non-final block 1 decompressed to 32768 bytes, expected 65536"
        );
    }

    #[test]
    fn decompression_fault_display_size_underrun() {
        let fault = DecompressionFault::SizeUnderrun {
            actual: 100,
            expected: 200,
        };
        assert_eq!(fault.to_string(), "decompressed 100 bytes, expected 200");
    }

    #[test]
    fn decompression_fault_display_compressed_block_reserve_failed() {
        // Construct a real `TryReserveError` by asking for a
        // pathologically large allocation. The Display string of
        // `TryReserveError` itself is platform-dependent (it bottoms
        // out in `AllocError` / `CapacityOverflow`), so the test
        // pins only the format-string scaffold around it via
        // `starts_with` rather than a full equality check on the
        // tail.
        let source = Vec::<u8>::new()
            .try_reserve_exact(usize::MAX)
            .expect_err("usize::MAX byte reservation must fail");
        let fault = DecompressionFault::CompressedBlockReserveFailed {
            block_index: 0,
            requested: 64,
            source,
        };
        let s = fault.to_string();
        assert!(
            s.starts_with("could not reserve 64 bytes for block 0: "),
            "wire-stable prefix drifted: got {s:?}"
        );
    }

    #[test]
    fn decompression_fault_display_zlib_scratch_reserve_failed() {
        let source = Vec::<u8>::new()
            .try_reserve_exact(usize::MAX)
            .expect_err("usize::MAX byte reservation must fail");
        let fault = DecompressionFault::ZlibScratchReserveFailed {
            block_index: 2,
            requested: 1024,
            already_committed: 4096,
            source,
        };
        let s = fault.to_string();
        assert!(
            s.starts_with(
                "could not reserve 1024 more bytes for zlib block 2 (block_out.len() = 4096): "
            ),
            "wire-stable prefix drifted: got {s:?}"
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

    /// Sanity-check the `AssetParse` wrapper format. Variant-level
    /// Display strings are pinned by `asset_parse_display_*` tests.
    #[test]
    fn error_display_asset_parse() {
        let err = PaksmithError::AssetParse {
            asset_path: "Game/Maps/Demo.uasset".to_string(),
            fault: AssetParseFault::UnsupportedLegacyFileVersion { version: -6 },
        };
        assert!(
            format!("{err}")
                .starts_with("asset deserialization failed for `Game/Maps/Demo.uasset`:")
        );
    }

    #[test]
    fn asset_parse_display_invalid_magic() {
        let err = PaksmithError::AssetParse {
            asset_path: "Game/Maps/Demo.uasset".to_string(),
            fault: AssetParseFault::InvalidMagic {
                observed: 0xDEAD_BEEF,
                expected: 0x9E2A_83C1,
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
             unsupported legacy file version -6 (paksmith Phase 2a accepts -7, -8, and -9)"
        );
    }

    #[test]
    fn asset_parse_display_uncooked_asset() {
        let err = PaksmithError::AssetParse {
            asset_path: "x.uasset".to_string(),
            fault: AssetParseFault::UncookedAsset {
                package_flags: 0,
                file_version_ue4: 522,
            },
        };
        assert_eq!(
            format!("{err}"),
            "asset deserialization failed for `x.uasset`: \
             uncooked asset (package_flags=0x00000000, file_version_ue4=522); \
             paksmith requires PKG_FilterEditorOnly to be set on assets at \
             FileVersionUE4 >= 520"
        );
    }

    #[test]
    fn asset_parse_display_unsupported_file_version_ue4() {
        let err = PaksmithError::AssetParse {
            asset_path: "x.uasset".to_string(),
            fault: AssetParseFault::UnsupportedFileVersionUE4 {
                version: 503,
                minimum: 504,
            },
        };
        assert_eq!(
            format!("{err}"),
            "asset deserialization failed for `x.uasset`: \
             unsupported FileVersionUE4 503 (minimum 504)"
        );
    }

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
    fn asset_parse_display_invalid_offset() {
        let err = PaksmithError::AssetParse {
            asset_path: "x.uasset".to_string(),
            fault: AssetParseFault::InvalidOffset {
                field: AssetWireField::ExportSerialOffset,
                offset: 9999,
                asset_size: 1000,
            },
        };
        assert_eq!(
            format!("{err}"),
            "asset deserialization failed for `x.uasset`: \
             export_serial_offset offset 9999 out of bounds (asset size 1000)"
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

    #[test]
    fn asset_parse_display_fstring_malformed() {
        // Use `LengthIsZero` as a representative inner kind. The outer
        // `AssetParseFault::FStringMalformed` Display delegates verbatim
        // to `FStringFault::Display` — matching the precedent in
        // `IndexParseFault::FStringMalformed`. No "FString:" prefix is
        // added by the outer arm; the wrapper provides asset-path
        // context and the inner `FStringFault::LengthIsZero` message
        // already starts with "FString".
        let err = PaksmithError::AssetParse {
            asset_path: "x.uasset".to_string(),
            fault: AssetParseFault::FStringMalformed {
                kind: FStringFault::LengthIsZero,
            },
        };
        assert_eq!(
            format!("{err}"),
            "asset deserialization failed for `x.uasset`: \
             FString length is zero (UE writes empty as len=1+nul)"
        );
    }

    #[test]
    fn asset_parse_display_u64_exceeds_platform_usize() {
        let err = PaksmithError::AssetParse {
            asset_path: "x.uasset".to_string(),
            fault: AssetParseFault::U64ExceedsPlatformUsize {
                field: AssetWireField::TotalHeaderSize,
                value: u64::MAX,
            },
        };
        assert_eq!(
            format!("{err}"),
            "asset deserialization failed for `x.uasset`: \
             total_header_size value 18446744073709551615 exceeds platform usize"
        );
    }

    #[test]
    fn asset_parse_display_allocation_failed() {
        // Construct a real `TryReserveError` via a pathologically large
        // reservation. `TryReserveError`'s Display is std-controlled
        // and platform-dependent (it bottoms out in `AllocError` /
        // `CapacityOverflow`), so this test pins only the wire-stable
        // prefix produced by our format string. Mirrors the pattern
        // used by the `DecompressionFault` allocation tests above.
        let source = Vec::<u8>::new()
            .try_reserve_exact(usize::MAX)
            .expect_err("usize::MAX byte reservation must fail");
        let err = PaksmithError::AssetParse {
            asset_path: "x.uasset".to_string(),
            fault: AssetParseFault::AllocationFailed {
                context: AssetAllocationContext::ExportPayloadBytes,
                requested: 1024,
                source,
            },
        };
        let s = format!("{err}");
        assert!(
            s.starts_with(
                "asset deserialization failed for `x.uasset`: \
                 could not reserve 1024 bytes for export payload bytes: "
            ),
            "wire-stable prefix drifted: got {s:?}"
        );
    }

    #[test]
    fn asset_parse_display_u64_arithmetic_overflow() {
        let err = PaksmithError::AssetParse {
            asset_path: "x.uasset".to_string(),
            fault: AssetParseFault::U64ArithmeticOverflow {
                operation: AssetOverflowSite::NameTableExtent,
            },
        };
        assert_eq!(
            format!("{err}"),
            "asset deserialization failed for `x.uasset`: \
             u64 arithmetic overflow during name-table extent computation"
        );
    }

    #[test]
    fn asset_parse_display_unexpected_eof() {
        let err = PaksmithError::AssetParse {
            asset_path: "x.uasset".to_string(),
            fault: AssetParseFault::UnexpectedEof {
                field: AssetWireField::ImportCount,
            },
        };
        assert_eq!(
            format!("{err}"),
            "asset deserialization failed for `x.uasset`: \
             unexpected EOF reading import_count"
        );
    }

    #[test]
    fn asset_parse_display_invalid_bool32() {
        let err = PaksmithError::AssetParse {
            asset_path: "x.uasset".to_string(),
            fault: AssetParseFault::InvalidBool32 {
                field: AssetWireField::ExportForcedExport,
                observed: 2,
            },
        };
        assert_eq!(
            format!("{err}"),
            "asset deserialization failed for `x.uasset`: \
             export_forced_export bool32 value 2 is not 0 or 1 \
             (CUE4Parse's FArchive.ReadBoolean rejects any other value)"
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
            field: WireField::UncompressedSize,
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
            field: WireField::FdiFileCount,
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
            context: AllocationContext::InlineCompressionBlocks,
            requested: 1_048_576,
            source,
            path: Some("Content/Mid.uasset".into()),
        });
        // Pin adjacency of count + unit + context (the format-string
        // shape, not just substring containment) so a reordering or
        // template change is caught loudly.
        assert!(
            s.contains("1048576 items for compression blocks for entry `Content/Mid.uasset`"),
            "got: {s}"
        );
    }

    #[test]
    fn index_parse_fault_display_allocation_failed_archive_level() {
        let source = Vec::<u8>::new()
            .try_reserve_exact(usize::MAX)
            .expect_err("reserving usize::MAX must fail");
        let s = fault_display(&IndexParseFault::AllocationFailed {
            context: AllocationContext::V10IndexEntries,
            requested: 100_000,
            source,
            path: None,
        });
        assert!(
            !s.contains("entry `"),
            "archive-level must not include `entry`: {s}"
        );
        assert!(
            s.contains("100000 items for entries for v10+ index"),
            "got: {s}"
        );
    }

    /// PR #144 R1 finding (sev 6): the AllocationFailed Display tests
    /// only covered `BoundsUnit::Items`, even though the byte-mode case
    /// is the entire motivation of the new `unit` field. This test
    /// pins the byte-mode rendering of every `*Bytes` AllocationContext
    /// variant — and would have caught the R1 "bytes for bytes" Display
    /// stutter before merge.
    #[test]
    fn index_parse_fault_display_allocation_failed_bytes_unit_no_stutter() {
        let make_source = || {
            Vec::<u8>::new()
                .try_reserve_exact(usize::MAX)
                .expect_err("reserving usize::MAX must fail")
        };

        // The four `*Bytes`-suffixed contexts. Pin the exact rendered
        // shape so the bare-noun-phrase Display convention is enforced
        // — any future rename that adds back the leading "bytes" to a
        // context Display string would re-introduce the R1 stutter and
        // fail this test.
        let cases: &[(AllocationContext, &str)] = &[
            (
                AllocationContext::EntryPayloadBytes,
                "could not reserve 65536 bytes for entry payload",
            ),
            (
                AllocationContext::V10MainIndexBytes,
                "could not reserve 65536 bytes for v10+ index",
            ),
            (
                AllocationContext::V10EncodedEntriesBytes,
                "could not reserve 65536 bytes for v10+ encoded entries",
            ),
            (
                AllocationContext::V10FdiBytes,
                "could not reserve 65536 bytes for v10+ full directory index",
            ),
        ];
        for (context, expected_prefix) in cases {
            let s = fault_display(&IndexParseFault::AllocationFailed {
                context: *context,
                requested: 65_536,
                source: make_source(),
                path: None,
            });
            assert!(
                s.contains(expected_prefix),
                "context={context:?}: expected prefix `{expected_prefix}`, got: {s}"
            );
            // Negative assertion: the stutter "bytes for bytes" must NOT appear.
            assert!(
                !s.contains("bytes for bytes"),
                "context={context:?}: rendered text contains `bytes for bytes` stutter: {s}"
            );
        }
    }

    #[test]
    fn index_parse_fault_display_u64_exceeds_platform_usize_with_path() {
        let s = fault_display(&IndexParseFault::U64ExceedsPlatformUsize {
            field: WireField::UncompressedSize,
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
            field: WireField::IndexSize,
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
            field: WireField::CompressedSize,
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
            kind: OffsetPastFileSizeKind::EntryHeaderOffset {
                entry_offset: 5_000,
                file_size_max: 4_000,
            },
        });
        assert!(s.contains("Content/A.uasset"), "got: {s}");
        assert!(s.contains("header offset past file_size"), "got: {s}");
        // Issue #216: per-variant struct payload still renders via the
        // wire-stable `observed=`/`limit=` tokens on the parent
        // OffsetPastFileSize Display arm.
        assert!(s.contains("observed=5000"), "got: {s}");
        assert!(s.contains("limit=4000"), "got: {s}");
    }

    #[test]
    fn index_parse_fault_display_offset_past_file_size_payload_end_bounds() {
        let s = fault_display(&IndexParseFault::OffsetPastFileSize {
            path: "Content/B.uasset".into(),
            kind: OffsetPastFileSizeKind::PayloadEndBounds {
                payload_end: 10_000,
                file_size_max: 9_000,
            },
        });
        assert!(s.contains("Content/B.uasset"), "got: {s}");
        assert!(s.contains("payload end past file_size"), "got: {s}");
        assert!(s.contains("observed=10000"), "got: {s}");
        assert!(s.contains("limit=9000"), "got: {s}");
    }

    /// FDI region declares an offset past EOF. Distinct prefix
    /// (`fdi`) so log greps don't conflate with the footer's
    /// `IndexRegionPastFileSize` (`index extends past EOF: ...`).
    /// Both numeric fields are surfaced so the operator can verify
    /// which value lied. Issue #127.
    #[test]
    fn index_parse_fault_display_region_past_file_size_fdi_offset() {
        let s = fault_display(&IndexParseFault::RegionPastFileSize {
            region: IndexRegionKind::Fdi,
            kind: RegionPastFileSizeKind::OffsetPastEof,
            offset: 5_000,
            size: 100,
            file_size: 4_000,
        });
        assert!(s.contains("fdi"), "expected `fdi` discriminator, got: {s}");
        assert!(s.contains("offset past EOF"), "got: {s}");
        // Anchored substrings so `5000` ⊂ `50000` overlap can't false-positive.
        assert!(s.contains("offset=5000"), "got: {s}");
        assert!(s.contains("size=100"), "got: {s}");
        assert!(s.contains("file_size=4000"), "got: {s}");
    }

    /// PHI region: offset is in-range but `offset + size` overflows
    /// the file. Pins the `extends past EOF` variant + `phi`
    /// discriminator.
    #[test]
    fn index_parse_fault_display_region_past_file_size_phi_end() {
        let s = fault_display(&IndexParseFault::RegionPastFileSize {
            region: IndexRegionKind::Phi,
            kind: RegionPastFileSizeKind::RegionEndPastEof,
            offset: 3_000,
            size: 2_000,
            file_size: 4_500,
        });
        assert!(s.contains("phi"), "expected `phi` discriminator, got: {s}");
        assert!(s.contains("extends past EOF"), "got: {s}");
        assert!(s.contains("offset=3000"), "got: {s}");
        assert!(s.contains("size=2000"), "got: {s}");
        assert!(s.contains("file_size=4500"), "got: {s}");
    }

    /// Issue #131: PHI/FDI inconsistency Display covers all four
    /// kinds. Pin one per kind so a wording drift on any single arm
    /// fails its own test rather than a shared template test.
    #[test]
    fn index_parse_fault_display_phi_fdi_inconsistency_missing() {
        let s = fault_display(&IndexParseFault::PhiFdiInconsistency {
            path: "Content/A.uasset".into(),
            kind: PhiFdiInconsistencyKind::MissingPhiEntry,
            expected_hash: 0xdead_beef_cafe_babe,
            fdi_offset: 42,
            phi_offset: 0,
        });
        assert!(s.contains("missing PHI entry"), "got: {s}");
        assert!(s.contains("Content/A.uasset"), "got: {s}");
        assert!(s.contains("0xdeadbeefcafebabe"), "got: {s}");
        assert!(s.contains("fdi_offset=42"), "got: {s}");
        assert!(s.contains("phi_offset=0"), "got: {s}");
    }

    #[test]
    fn index_parse_fault_display_phi_fdi_inconsistency_offset_mismatch() {
        let s = fault_display(&IndexParseFault::PhiFdiInconsistency {
            path: "Content/B.uasset".into(),
            kind: PhiFdiInconsistencyKind::OffsetMismatch,
            expected_hash: 0x1234_5678_9abc_def0,
            fdi_offset: 100,
            phi_offset: 200,
        });
        assert!(s.contains("PHI/FDI offset mismatch"), "got: {s}");
        assert!(s.contains("Content/B.uasset"), "got: {s}");
        assert!(s.contains("fdi_offset=100"), "got: {s}");
        assert!(s.contains("phi_offset=200"), "got: {s}");
    }

    #[test]
    fn index_parse_fault_display_phi_fdi_inconsistency_extra() {
        let s = fault_display(&IndexParseFault::PhiFdiInconsistency {
            // Extra-PHI entries have no FDI path counterpart;
            // `path` is empty by convention.
            path: String::new(),
            kind: PhiFdiInconsistencyKind::ExtraPhiEntries,
            expected_hash: 0xaaaa_bbbb_cccc_dddd,
            fdi_offset: 0,
            phi_offset: 99,
        });
        assert!(s.contains("extra PHI entries"), "got: {s}");
        assert!(s.contains("phi_offset=99"), "got: {s}");
        assert!(s.contains("0xaaaabbbbccccdddd"), "got: {s}");
    }

    #[test]
    fn index_parse_fault_display_phi_fdi_inconsistency_duplicate() {
        let s = fault_display(&IndexParseFault::PhiFdiInconsistency {
            path: String::new(),
            kind: PhiFdiInconsistencyKind::DuplicateHash,
            expected_hash: 0xffff_eeee_dddd_cccc,
            fdi_offset: 0,
            phi_offset: 77,
        });
        assert!(s.contains("duplicate PHI hash"), "got: {s}");
        assert!(s.contains("0xffffeeeeddddcccc"), "got: {s}");
        assert!(s.contains("phi_offset=77"), "got: {s}");
    }

    /// Issue #131: pin every variant of `PhiFdiInconsistencyKind`
    /// against its wire-stable Display token. Operators / dashboards
    /// match against these in log streams; a future rename or
    /// reordering of the token would silently break greps without
    /// this test.
    #[test]
    fn phi_fdi_inconsistency_kind_display_tokens_are_wire_stable() {
        let cases: &[(PhiFdiInconsistencyKind, &str)] = &[
            (
                PhiFdiInconsistencyKind::MissingPhiEntry,
                "missing PHI entry",
            ),
            (
                PhiFdiInconsistencyKind::OffsetMismatch,
                "PHI/FDI offset mismatch",
            ),
            (
                PhiFdiInconsistencyKind::ExtraPhiEntries,
                "extra PHI entries",
            ),
            (PhiFdiInconsistencyKind::DuplicateHash, "duplicate PHI hash"),
        ];
        for (kind, expected) in cases {
            assert_eq!(kind.to_string(), *expected);
        }
    }

    #[test]
    fn index_parse_fault_display_block_bounds_violation_start_overlaps_header() {
        let s = fault_display(&IndexParseFault::BlockBoundsViolation {
            path: "Content/C.uasset".into(),
            block_index: 2,
            kind: BlockBoundsKind::StartOverlapsHeader {
                block_start: 30,
                payload_start_min: 50,
            },
        });
        assert!(s.contains("Content/C.uasset"), "got: {s}");
        // BlockBoundsKind::Display token.
        assert!(s.contains("start overlaps in-data header"), "got: {s}");
        assert!(s.contains("block 2"), "got: {s}");
        // Issue #135: per-variant struct payload still renders via
        // the wire-stable `observed=`/`limit=` tokens on the parent
        // BlockBoundsViolation Display arm.
        assert!(s.contains("observed=30"), "got: {s}");
        assert!(s.contains("limit=50"), "got: {s}");
    }

    #[test]
    fn index_parse_fault_display_block_bounds_violation_end_past_file_size() {
        let s = fault_display(&IndexParseFault::BlockBoundsViolation {
            path: "Content/D.uasset".into(),
            block_index: 0,
            kind: BlockBoundsKind::EndPastFileSize {
                block_end: 1_000_000,
                file_size_max: 500_000,
            },
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

    /// Issue #129: the OutOfOrder variant fires when `block[i].start <
    /// block[i-1].end`. Pins the new Display token + per-variant shape.
    /// `block_start` is the offending block's start, `prev_block_end_min`
    /// is the preceding block's end (the lower bound it must equal-or-
    /// exceed). Pinned via `observed=`/`limit=` tokens for wire stability.
    #[test]
    fn index_parse_fault_display_block_bounds_violation_out_of_order() {
        let s = fault_display(&IndexParseFault::BlockBoundsViolation {
            path: "Content/E.uasset".into(),
            block_index: 1,
            kind: BlockBoundsKind::OutOfOrder {
                block_start: 100,
                prev_block_end_min: 200,
            },
        });
        assert!(s.contains("Content/E.uasset"), "got: {s}");
        // Pin the FULL wire-stable token, not just `"out of order"`
        // — a rename to "out of order (legacy)" / "out of order [seq]"
        // would otherwise pass while silently breaking operator log
        // greps. Mirrors how the sibling `StartOverlapsHeader` /
        // `EndPastFileSize` tests pin their complete tokens.
        assert!(s.contains("out of order with previous block"), "got: {s}");
        assert!(s.contains("block 1"), "got: {s}");
        assert!(s.contains("observed=100"), "got: {s}");
        assert!(s.contains("limit=200"), "got: {s}");
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

    /// Pin all `WireField` Display tokens. Mirror of
    /// `overflow_site_display_tokens_are_wire_stable` for the
    /// closed-set typed-name pattern. Per the type doc-comment, every
    /// variant Displays to the exact `&'static str` the call site
    /// previously passed pre-#134 — operator log greps and downstream
    /// tooling that hard-coded the old strings depend on this.
    /// Without this test, a typo in a Display arm
    /// (`"compression_block_sze"`) would compile, pass clippy, pass
    /// every other test, and silently break dashboard greps.
    #[test]
    fn wire_field_display_tokens_are_wire_stable() {
        let cases: &[(WireField, &str)] = &[
            (WireField::UncompressedSize, "uncompressed_size"),
            (WireField::CompressedSize, "compressed_size"),
            (WireField::BlockLength, "block_length"),
            (WireField::CompressionBlockSize, "compression_block_size"),
            (WireField::BlockCount, "block_count"),
            (WireField::Sha1, "sha1"),
            (WireField::IsEncrypted, "is_encrypted"),
            (WireField::CompressionMethod, "compression_method"),
            (WireField::CompressionBlocks, "compression_blocks"),
            (WireField::FlatEntryCount, "entry_count"),
            (WireField::V10NonEncodedCount, "non_encoded_count"),
            (WireField::FdiFileCount, "file_count"),
            (WireField::FdiDirCount, "dir_count"),
            (WireField::FdiSize, "fdi_size"),
            (WireField::PhiSize, "phi_size"),
            (WireField::PhiEntryCount, "phi_entry_count"),
            (WireField::V10EncodedEntriesSize, "encoded_entries_size"),
            (WireField::IndexSize, "index_size"),
        ];
        for (field, expected) in cases {
            assert_eq!(field.to_string(), *expected);
        }
    }

    /// Pin all `AllocationContext` Display tokens. Same precedent as
    /// `wire_field_display_tokens_are_wire_stable` /
    /// `overflow_site_display_tokens_are_wire_stable`. The
    /// `*Bytes`-suffixed variants Display to bare noun phrases (no
    /// leading "bytes" word) — a future rename that adds back the
    /// leading unit would re-introduce the PR #144 R1 "bytes for
    /// bytes" stutter and fail this test.
    #[test]
    fn allocation_context_display_tokens_are_wire_stable() {
        let cases: &[(AllocationContext, &str)] = &[
            (AllocationContext::EntryPayloadBytes, "entry payload"),
            (
                AllocationContext::InlineCompressionBlocks,
                "compression blocks",
            ),
            (
                AllocationContext::EncodedCompressionBlocks,
                "encoded compression blocks",
            ),
            (AllocationContext::FlatIndexEntries, "entries"),
            (AllocationContext::DedupTracker, "dedup tracker for entries"),
            (AllocationContext::ByPathLookup, "by-path lookup entries"),
            (AllocationContext::V10MainIndexBytes, "v10+ index"),
            (
                AllocationContext::V10EncodedEntriesBytes,
                "v10+ encoded entries",
            ),
            (
                AllocationContext::V10NonEncodedEntries,
                "non-encoded entries for v10+ index",
            ),
            (AllocationContext::V10FdiBytes, "v10+ full directory index"),
            (AllocationContext::V10PhiBytes, "v10+ path hash index"),
            (
                AllocationContext::V10PhiEntries,
                "entries for v10+ path hash index",
            ),
            (AllocationContext::V10IndexEntries, "entries for v10+ index"),
            (AllocationContext::FStringUtf8Bytes, "FString UTF-8 buffer"),
            (
                AllocationContext::FStringUtf16CodeUnits,
                "FString UTF-16 code units",
            ),
            (AllocationContext::FdiFullPathBytes, "FDI full-path buffer"),
        ];
        for (context, expected) in cases {
            assert_eq!(context.to_string(), *expected);
        }
    }

    /// Issue #146: pin the `AllocationContext::unit()` mapping for
    /// every variant. Without this, a future variant added with the
    /// wrong unit (e.g. an `EntryPayloadItems` variant mistakenly
    /// returning `Bytes`) would render misleading diagnostics. The
    /// exhaustive `match` in `unit()` makes adding a new variant a
    /// compile error rather than a silent default — this test
    /// additionally pins the EXISTING variant mappings so a future
    /// edit that flips one (e.g. `*Bytes` → `Items`) trips here.
    #[test]
    fn allocation_context_unit_mapping_is_pinned() {
        let cases: &[(AllocationContext, BoundsUnit)] = &[
            (AllocationContext::EntryPayloadBytes, BoundsUnit::Bytes),
            (
                AllocationContext::InlineCompressionBlocks,
                BoundsUnit::Items,
            ),
            (
                AllocationContext::EncodedCompressionBlocks,
                BoundsUnit::Items,
            ),
            (AllocationContext::FlatIndexEntries, BoundsUnit::Items),
            (AllocationContext::DedupTracker, BoundsUnit::Items),
            (AllocationContext::ByPathLookup, BoundsUnit::Items),
            (AllocationContext::V10MainIndexBytes, BoundsUnit::Bytes),
            (AllocationContext::V10EncodedEntriesBytes, BoundsUnit::Bytes),
            (AllocationContext::V10NonEncodedEntries, BoundsUnit::Items),
            (AllocationContext::V10FdiBytes, BoundsUnit::Bytes),
            (AllocationContext::V10PhiBytes, BoundsUnit::Bytes),
            (AllocationContext::V10PhiEntries, BoundsUnit::Items),
            (AllocationContext::V10IndexEntries, BoundsUnit::Items),
            (AllocationContext::FStringUtf8Bytes, BoundsUnit::Bytes),
            // FStringUtf16CodeUnits is the only variant whose name
            // doesn't end in `Bytes` but whose reservation is in
            // u16 SLOTS (not bytes) — pinned explicitly so a future
            // "all *Bytes → Bytes, everything else → Items" auto-
            // gen doesn't trip on the exception.
            (AllocationContext::FStringUtf16CodeUnits, BoundsUnit::Items),
            (AllocationContext::FdiFullPathBytes, BoundsUnit::Bytes),
        ];
        for (context, expected) in cases {
            assert_eq!(
                context.unit(),
                *expected,
                "AllocationContext::{context:?}.unit() mismatch"
            );
        }
    }

    /// Issue #127: direct table-driven test of [`check_region_bounds`]
    /// covering BOTH region variants AND all three failure modes
    /// (offset-past, end-past, checked-add overflow) plus the
    /// in-range accept and at-boundary accept (strict `>` end
    /// comparator). The FDI integration tests in
    /// `container::pak::index::tests` exercise the parse-time call
    /// site via `PakIndex::read_from`, but the helper is also
    /// invoked from `verify_region` for PHI where the parse-time
    /// path can't reach it — this test pins the PHI arms directly.
    #[test]
    fn check_region_bounds_covers_all_arms() {
        // Happy paths — must return Ok.
        for region in [IndexRegionKind::Fdi, IndexRegionKind::Phi] {
            assert!(
                check_region_bounds(region, 100, 50, 1000).is_ok(),
                "in-range region {region:?} must accept",
            );
            // Strict `>` boundary: offset + size == file_size is fine.
            assert!(
                check_region_bounds(region, 100, 900, 1000).is_ok(),
                "region ending exactly at file_size must accept ({region:?})",
            );
        }

        // OffsetPastEof — offset == file_size (inclusive comparator).
        let err =
            check_region_bounds(IndexRegionKind::Phi, 1000, 50, 1000).expect_err("offset == EOF");
        assert!(matches!(
            err,
            IndexParseFault::RegionPastFileSize {
                region: IndexRegionKind::Phi,
                kind: RegionPastFileSizeKind::OffsetPastEof,
                offset: 1000,
                size: 50,
                file_size: 1000,
            }
        ));

        // RegionEndPastEof — offset in-range, sum exceeds file_size.
        let err = check_region_bounds(IndexRegionKind::Phi, 500, 600, 1000).expect_err("end past");
        assert!(matches!(
            err,
            IndexParseFault::RegionPastFileSize {
                region: IndexRegionKind::Phi,
                kind: RegionPastFileSizeKind::RegionEndPastEof,
                offset: 500,
                size: 600,
                file_size: 1000,
            }
        ));

        // checked_add overflow — `offset + size` exceeds u64::MAX.
        let err =
            check_region_bounds(IndexRegionKind::Phi, 100, u64::MAX, 1000).expect_err("overflow");
        assert!(matches!(
            err,
            IndexParseFault::RegionPastFileSize {
                region: IndexRegionKind::Phi,
                kind: RegionPastFileSizeKind::RegionEndPastEof,
                offset: 100,
                size: u64::MAX,
                file_size: 1000,
            }
        ));
    }

    /// Pin the [`From<IndexRegionKind> for HashTarget`] mapping —
    /// the very purpose of this impl is to remove the manual-sync
    /// footgun where `verify_region` previously took both enums as
    /// separate parameters. A future variant added to one enum but
    /// not the other would silently misroute without this lock.
    /// Issue #127 review-panel R1 finding.
    #[test]
    fn index_region_kind_to_hash_target_mapping_is_load_bearing() {
        assert_eq!(HashTarget::from(IndexRegionKind::Fdi), HashTarget::Fdi);
        assert_eq!(HashTarget::from(IndexRegionKind::Phi), HashTarget::Phi);
    }

    /// Pin every variant of [`IndexRegionKind`] against its
    /// wire-stable Display token. Operators and log greps filter
    /// by these (`"fdi"` / `"phi"`); a future rename or token drift
    /// would break dashboard regexes silently without this test.
    /// Issue #127.
    #[test]
    fn index_region_kind_display_tokens_are_wire_stable() {
        let cases: &[(IndexRegionKind, &str)] =
            &[(IndexRegionKind::Fdi, "fdi"), (IndexRegionKind::Phi, "phi")];
        for (kind, expected) in cases {
            assert_eq!(kind.to_string(), *expected);
        }
    }

    /// Pin every variant of [`RegionPastFileSizeKind`] against its
    /// wire-stable Display token. Sibling to
    /// [`Self::index_region_kind_display_tokens_are_wire_stable`].
    #[test]
    fn region_violation_kind_display_tokens_are_wire_stable() {
        let cases: &[(RegionPastFileSizeKind, &str)] = &[
            (RegionPastFileSizeKind::OffsetPastEof, "offset past EOF"),
            (RegionPastFileSizeKind::RegionEndPastEof, "extends past EOF"),
        ];
        for (kind, expected) in cases {
            assert_eq!(kind.to_string(), *expected);
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

    /// Pin all `AssetWireField` Display tokens. Mirror of
    /// `wire_field_display_tokens_are_wire_stable` for the asset-side
    /// closed set. Every variant Displays to a wire-stable snake_case
    /// name operators rely on in log greps and dashboards; a typo in
    /// any Display arm would compile, pass clippy, and silently break
    /// downstream tooling without this pin.
    #[test]
    fn asset_wire_field_display_tokens_are_wire_stable() {
        let cases: &[(AssetWireField, &str)] = &[
            (AssetWireField::NameCount, "name_count"),
            (AssetWireField::NameOffset, "name_offset"),
            (AssetWireField::ImportCount, "import_count"),
            (AssetWireField::ImportOffset, "import_offset"),
            (AssetWireField::ExportCount, "export_count"),
            (AssetWireField::ExportOffset, "export_offset"),
            (AssetWireField::TotalHeaderSize, "total_header_size"),
            (AssetWireField::CustomVersionCount, "custom_version_count"),
            (AssetWireField::ImportOuterIndex, "import_outer_index"),
            (AssetWireField::ExportClassIndex, "export_class_index"),
            (AssetWireField::ExportSuperIndex, "export_super_index"),
            (AssetWireField::ExportOuterIndex, "export_outer_index"),
            (AssetWireField::ExportTemplateIndex, "export_template_index"),
            (AssetWireField::ExportSerialOffset, "export_serial_offset"),
            (AssetWireField::ExportSerialSize, "export_serial_size"),
            (AssetWireField::NameIndex, "name_index"),
            (AssetWireField::GenerationCount, "generation_count"),
            (
                AssetWireField::AdditionalPackagesToCookCount,
                "additional_packages_to_cook_count",
            ),
            (AssetWireField::ChunkIdCount, "chunk_id_count"),
            (AssetWireField::ExportForcedExport, "export_forced_export"),
            (AssetWireField::ExportNotForClient, "export_not_for_client"),
            (AssetWireField::ExportNotForServer, "export_not_for_server"),
            (
                AssetWireField::ExportIsInheritedInstance,
                "export_is_inherited_instance",
            ),
            (
                AssetWireField::ExportNotAlwaysLoadedForEditorGame,
                "export_not_always_loaded_for_editor_game",
            ),
            (AssetWireField::ExportIsAsset, "export_is_asset"),
            (
                AssetWireField::ExportGeneratePublicHash,
                "export_generate_public_hash",
            ),
            (AssetWireField::ImportOptional, "import_optional"),
        ];
        for (field, expected) in cases {
            assert_eq!(field.to_string(), *expected);
        }
    }

    /// Pin all `AssetOverflowSite` Display tokens. Same precedent as
    /// `overflow_site_display_tokens_are_wire_stable`. The tokens are
    /// the operator-visible substring of the
    /// `AssetParseFault::U64ArithmeticOverflow` Display arm.
    #[test]
    fn asset_overflow_site_display_tokens_are_wire_stable() {
        let cases: &[(AssetOverflowSite, &str)] = &[
            (
                AssetOverflowSite::NameTableExtent,
                "name-table extent computation",
            ),
            (
                AssetOverflowSite::ImportTableExtent,
                "import-table extent computation",
            ),
            (
                AssetOverflowSite::ExportTableExtent,
                "export-table extent computation",
            ),
            (
                AssetOverflowSite::ExportPayloadExtent,
                "export-payload extent computation",
            ),
        ];
        for (site, expected) in cases {
            assert_eq!(site.to_string(), *expected);
        }
    }

    /// Pin all `AssetAllocationContext` Display tokens. Same precedent
    /// as `allocation_context_display_tokens_are_wire_stable`. Bare
    /// noun phrases (no leading "bytes" word) match the pak-side
    /// convention that avoids the "bytes for bytes" stutter.
    #[test]
    fn asset_allocation_context_display_tokens_are_wire_stable() {
        let cases: &[(AssetAllocationContext, &str)] = &[
            (AssetAllocationContext::NameTable, "name table"),
            (AssetAllocationContext::ImportTable, "import table"),
            (AssetAllocationContext::ExportTable, "export table"),
            (
                AssetAllocationContext::CustomVersionContainer,
                "custom-version container",
            ),
            (
                AssetAllocationContext::ExportPayloadBytes,
                "export payload bytes",
            ),
            (AssetAllocationContext::ExportPayloads, "export payloads"),
        ];
        for (context, expected) in cases {
            assert_eq!(context.to_string(), *expected);
        }
    }

    /// Issue #146: asset-side sibling of
    /// `allocation_context_unit_mapping_is_pinned` — pins every
    /// variant's unit so a regression on the asset-context's
    /// implicit mapping is caught.
    #[test]
    fn asset_allocation_context_unit_mapping_is_pinned() {
        let cases: &[(AssetAllocationContext, BoundsUnit)] = &[
            (AssetAllocationContext::NameTable, BoundsUnit::Items),
            (AssetAllocationContext::ImportTable, BoundsUnit::Items),
            (AssetAllocationContext::ExportTable, BoundsUnit::Items),
            (
                AssetAllocationContext::CustomVersionContainer,
                BoundsUnit::Items,
            ),
            (
                AssetAllocationContext::ExportPayloadBytes,
                BoundsUnit::Bytes,
            ),
            (AssetAllocationContext::ExportPayloads, BoundsUnit::Items),
        ];
        for (context, expected) in cases {
            assert_eq!(
                context.unit(),
                *expected,
                "AssetAllocationContext::{context:?}.unit() mismatch"
            );
        }
    }

    /// Pin both `CompressionInSummarySite` Display tokens. Each token
    /// renders the underlying wire-field name (`compression_flags` /
    /// `compressed_chunks_count`) so log greps land on the same string
    /// whether triage starts from the typed variant or the rendered
    /// message.
    #[test]
    fn compression_in_summary_site_display_tokens_are_wire_stable() {
        let cases: &[(CompressionInSummarySite, &str)] = &[
            (
                CompressionInSummarySite::CompressionFlags,
                "compression_flags",
            ),
            (
                CompressionInSummarySite::CompressedChunksCount,
                "compressed_chunks_count",
            ),
        ];
        for (site, expected) in cases {
            assert_eq!(site.to_string(), *expected);
        }
    }
}
