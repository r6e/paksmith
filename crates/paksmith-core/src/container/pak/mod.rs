//! Unreal Engine `.pak` archive reader.
//!
//! # Supported scope
//!
//! This reader implements:
//! - Footer parsing for v1–v11 paks.
//! - Flat-entry index layout for v3–v9.
//! - **Path-hash + encoded-directory index** for v10/v11 (the bit-packed
//!   FPakEntry format, full-directory-index walk, and FNV-1a path
//!   hashing for cross-archive lookup; see
//!   [`crate::container::pak::index::PakIndex::read_from`] for dispatch).
//! - V8+ FName-based compression-method indirection (the per-entry
//!   compression byte is a 1-based index into a 4- or 5-slot FName table
//!   stored in the footer; resolution happens in
//!   [`crate::container::pak::index::PakEntryHeader::read_from`]).
//! - V8A's narrower u8 compression byte (V8B and later use u32).
//! - V9's optional `frozen_index` flag (parsed for round-trip; v9
//!   archives with frozen=true are rejected at open since the index
//!   region would be in UE's compiled-frozen layout).
//! - The duplicate FPakEntry record header that real archives write before
//!   each payload at [`crate::container::pak::index::PakEntryHeader::offset`],
//!   with cross-validation against the index entry.
//! - Zlib decompression for v5+ archives (block offsets are relative to the
//!   entry record start).
//! - SHA1 verification of the index and per-entry stored bytes via opt-in
//!   [`PakReader::verify_index`], [`PakReader::verify_entry`], and
//!   [`PakReader::verify`]. **v10+ encoded entries omit SHA1**, so
//!   `verify_entry` surfaces them as `SkippedNoHash`. Verification is
//!   opt-in to keep list-only workloads from paying the cost.
//!
//! It does NOT yet handle:
//! - AES decryption of the index or of individual entries.
//! - Gzip / Oodle / Zstd / LZ4 compression — only zlib is wired up
//!   downstream of the FName resolution.
//! - Pre-v5 absolute-offset compression blocks (rare in real archives).
//! - V9 frozen-index format (rejected at open).
//!
//! # File-immutability assumption
//!
//! [`PakReader`] holds a single [`std::fs::File`] handle inside a
//! [`std::sync::Mutex`], opened at [`PakReader::open`] time and reused for
//! every entry read. The reader caches `file_size` at open time and assumes
//! the file is immutable for its lifetime — a file that shrinks between
//! `open` and a later read will surface as a typed `InvalidIndex` (the
//! per-entry payload-end-vs-file-size check fires before the read), and a
//! file that grows or is replaced will silently read different bytes than
//! the cached index describes. Truncation racing the read mid-stream
//! still surfaces as [`PaksmithError::Io`] (`UnexpectedEof`).

pub mod footer;
pub mod index;
pub mod version;

use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Mutex;

use flate2::read::ZlibDecoder;
use sha1::{Digest, Sha1};
use tracing::{debug, error, warn};

use crate::container::{ContainerFormat, ContainerReader, EntryFlags, EntryMetadata};
use crate::digest::Sha1Digest;
use crate::error::{
    AllocationContext, BlockBoundsKind, BoundsUnit, DecompressionFault, HashTarget,
    IndexParseFault, IndexRegionKind, OffsetPastFileSizeKind, OverflowSite, PaksmithError,
    WireField, check_region_bounds,
};

use self::footer::PakFooter;
use self::index::{CompressionMethod, PakEntryHeader, PakIndex, PakIndexEntry, RegionDescriptor};
use self::version::PakVersion;

/// Hard ceiling on the uncompressed size of a single entry, applied before
/// any allocation. Sized to comfortably exceed any realistic UE asset (the
/// largest cooked textures peak in the low hundreds of MiB) while preventing
/// a malicious index that claims a multi-terabyte entry from triggering an
/// allocator abort. Tunable upwards if a legitimate archive ever trips it.
///
/// Exposed to integration tests via [`max_uncompressed_entry_bytes`] so that
/// boundary tests don't hard-code the literal and stay correct if the cap
/// ever changes.
const MAX_UNCOMPRESSED_ENTRY_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// Test-only accessor for `MAX_UNCOMPRESSED_ENTRY_BYTES`. The cap is
/// an implementation detail of the parser — tests that care about the
/// boundary read it from here rather than duplicating the literal,
/// which would silently drift if the cap ever changes.
///
/// Gated behind the `__test_utils` feature so it's not part of the
/// stable public API. Integration tests in this crate enable it via
/// `dev-dependencies`-style activation; downstream consumers cannot
/// pin against this value.
#[cfg(feature = "__test_utils")]
pub fn max_uncompressed_entry_bytes() -> u64 {
    MAX_UNCOMPRESSED_ENTRY_BYTES
}

/// Reader for `.pak` archive files.
///
/// Holds a single `Mutex<File>` opened at `open()` time and reused for
/// every entry read, replacing the previous "reopen the file on every
/// `read_entry`" pattern. The mutex serializes concurrent reads (which
/// is required anyway because each read seeks the shared cursor); for
/// paksmith's single-threaded CLI/GUI usage there's no contention.
///
/// `EntryMetadata` is constructed on demand by the
/// [`ContainerReader::entries`] iterator — there is no
/// `Vec<EntryMetadata>` cache alongside the parsed index. The
/// underlying index DOES materialize a `Vec<PakIndexEntry>` at
/// `open()` time; the laziness is only in projecting each
/// `PakIndexEntry` to an owned `EntryMetadata` per `next()` call.
#[derive(Debug)]
pub struct PakReader {
    file_size: u64,
    footer: PakFooter,
    index: PakIndex,
    file: Mutex<File>,
}

impl PakReader {
    /// Open and parse a `.pak` file at the given path.
    ///
    /// Rejects pre-v3 archives, v9 frozen-index archives, and archives
    /// with an AES-encrypted index. Per-entry AES and pre-v5
    /// absolute-offset compression blocks are deferred to read time.
    /// See the module-level docs for the full supported/unsupported
    /// matrix.
    pub fn open<P: AsRef<Path>>(path: P) -> crate::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = File::open(&path)?;
        let mut buffered = BufReader::new(&file);
        let file_size = buffered.seek(SeekFrom::End(0))?;

        let footer = PakFooter::read_from(&mut buffered)?;

        if footer.is_encrypted() {
            return Err(PaksmithError::Decryption {
                path: path.display().to_string(),
            });
        }

        // V9's `frozen_index = true` writer flag means the index region
        // is in UE's compiled-frozen layout — completely different bytes
        // than the flat-entry parser expects. Silently parsing as if not
        // frozen would produce garbage entries (paths read as gibberish,
        // offsets pointing nowhere). Repak's writer doesn't currently
        // emit frozen=true so the cross-parser tests can't catch this;
        // reject explicitly at open time. See #7 follow-up for proper
        // frozen-index parsing.
        if footer.frozen_index() {
            return Err(PaksmithError::UnsupportedVersion {
                version: footer.version().wire_version(),
            });
        }

        // v1/v2 entry records have a different shape (timestamp field
        // pre-v2, no trailing flags+block_size). PakEntryHeader::read_from
        // assumes the v3+ layout. We have no fixtures for v1/v2 and
        // they're rare in the wild, so reject explicitly rather than
        // silently misparse.
        if footer.version() < PakVersion::CompressionEncryption {
            return Err(PaksmithError::UnsupportedVersion {
                version: footer.version().wire_version(),
            });
        }

        // PakIndex::read_from seeks to index_offset itself (v10+ needs to
        // seek elsewhere for the full directory index, so it owns the
        // seek dance).
        let index = PakIndex::read_from(
            &mut buffered,
            footer.version(),
            footer.index_offset(),
            footer.index_size(),
            file_size,
            footer.compression_methods(),
        )?;
        // Drop the BufReader's borrow so we can move `file` into the
        // Mutex. The BufReader is throwaway — entry reads will create
        // fresh BufReaders against the locked File handle.
        drop(buffered);

        // Issue #58: the per-entry payload-end-vs-file-size check
        // already exists at verify_entry / stream_*_to time, but
        // never fires for `paksmith list`-style consumers that
        // surface `compressed_size()` without extracting. Walk the
        // index once at open and reject any entry whose claim
        // implies on-disk bytes past EOF, so consumers reading the
        // header can't be lied to. Covers single-block,
        // multi-block, and zero-block entries uniformly through
        // the same single iteration.
        //
        // For encrypted multi-block entries, `compressed_size` is
        // the unaligned sum; the actual on-disk extent is up to
        // `16 * block_count` bytes larger due to AES padding. We
        // accept that ~1 MiB worst-case under-check at open since
        // the read-time per-block bound at `stream_zlib_to` still
        // catches anything beyond the wire claim that would
        // actually walk past EOF.
        for entry in index.entries() {
            let header = entry.header();
            let offset = header.offset();
            let compressed = header.compressed_size();
            let uncompressed = header.uncompressed_size();
            // The on-disk extent of an entry is
            // `offset + in_data_header_size + compressed`, NOT just
            // `offset + compressed`: every entry has an in-data
            // FPakEntry record sitting between `offset` and the
            // payload bytes. Pre-#85 this check used `offset +
            // compressed`, leaving a window where marginal-lying
            // entries (off by ≤ in_data_header_size, ~50-70 bytes)
            // bypassed the typed `OffsetPastFileSize` and surfaced
            // as bare `Io::UnexpectedEof` at read time. `wire_size`
            // works for both Inline (v3-v9) and Encoded (v10+)
            // variants — Encoded reuses the V8B+ in-data shape.
            //
            // The footer's index-bounds check already pinned
            // `index_offset + index_size <= file_size`, so a
            // malformed footer's `file_size` is sanitized by the
            // time we reach this loop. The remaining attack vector
            // is per-entry header lies, which this loop closes.
            let in_data_size = header.wire_size();
            let payload_end = offset
                .checked_add(in_data_size)
                .and_then(|p| p.checked_add(compressed))
                .ok_or_else(|| PaksmithError::InvalidIndex {
                    fault: IndexParseFault::U64ArithmeticOverflow {
                        path: Some(entry.filename().to_string()),
                        operation: OverflowSite::PayloadEnd,
                    },
                })?;
            if payload_end > file_size {
                warn!(
                    path = entry.filename(),
                    offset,
                    in_data_size,
                    compressed,
                    file_size,
                    "entry payload extends past file_size at open time"
                );
                return Err(PaksmithError::InvalidIndex {
                    fault: IndexParseFault::OffsetPastFileSize {
                        path: entry.filename().to_string(),
                        kind: OffsetPastFileSizeKind::PayloadEndBounds,
                        observed: payload_end,
                        limit: file_size,
                    },
                });
            }
            // Open-time `uncompressed_size` backstop. The parse-time
            // `block_count * compression_block_size` cap in
            // `read_encoded` is structurally tight for compressed
            // multi-block AND single-block paths (issue #58 sibling),
            // but it doesn't bound the `compression_block_size` field
            // itself — an attacker who sets that to `u32::MAX` lifts
            // the cap to ~256 TiB. The inline v3-v9 path doesn't
            // apply ANY parse-time cap. This open-time check covers
            // both gaps uniformly: any consumer reading
            // `uncompressed_size()` (CLI list, JSON output, alloc
            // estimators) is bounded by `MAX_UNCOMPRESSED_ENTRY_BYTES`
            // (8 GiB), the same backstop `verify_entry`/`read_entry`
            // already rely on at extract time.
            if uncompressed > MAX_UNCOMPRESSED_ENTRY_BYTES {
                warn!(
                    path = entry.filename(),
                    uncompressed,
                    limit = MAX_UNCOMPRESSED_ENTRY_BYTES,
                    "entry uncompressed_size exceeds backstop at open time"
                );
                return Err(PaksmithError::InvalidIndex {
                    fault: IndexParseFault::BoundsExceeded {
                        field: WireField::UncompressedSize,
                        value: uncompressed,
                        limit: MAX_UNCOMPRESSED_ENTRY_BYTES,
                        unit: BoundsUnit::Bytes,
                        path: Some(entry.filename().to_string()),
                    },
                });
            }
        }

        Ok(Self {
            file_size,
            footer,
            index,
            file: Mutex::new(file),
        })
    }

    /// The pak format version of this archive.
    pub fn version(&self) -> PakVersion {
        self.footer.version()
    }

    /// Look up the parsed index entry for `path`, exposing the wire-level
    /// fields (entry offset, on-disk sizes, compression blocks, stored
    /// SHA1) that the lighter [`EntryMetadata`] hides.
    ///
    /// Use this when a caller needs to compute a derived offset (e.g., to
    /// poke at a specific payload byte for a corruption test) and would
    /// otherwise have to hardcode arithmetic that drifts when the on-disk
    /// header layout changes. Returns `None` if no entry has that path.
    #[must_use]
    pub fn index_entry(&self, path: &str) -> Option<&PakIndexEntry> {
        self.index.find(path)
    }

    /// Whether the archive's index hash slot is non-zero — i.e., the
    /// writer recorded an integrity claim. When `true`, any zero entry
    /// hash slot is treated as a tampering signal (an attacker stripping
    /// the integrity tag) rather than "no claim recorded." See
    /// [`PakReader::verify_entry`] for the details.
    fn archive_claims_integrity(&self) -> bool {
        !self.footer.index_hash().is_zero()
    }

    /// Acquire the shared file handle, recovering from poison.
    ///
    /// **Safety contract.** A previous panic-while-locked left the file
    /// cursor at an unknown position, so the recovered guard cannot be
    /// trusted to be at any particular offset. **Every caller MUST seek
    /// before its first read** (typically via `BufReader::seek` or by
    /// going through [`Self::open_entry_into`], which seeks
    /// unconditionally). Reading from the guard's initial position
    /// after a poisoned lock would silently return bytes from wherever
    /// the panicked thread left off. This invariant is upheld today by
    /// every lock site in this file; future additions must preserve it.
    fn locked(&self) -> std::sync::MutexGuard<'_, File> {
        self.file
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Verify the SHA1 hash recorded in the footer against the actual bytes
    /// of the index.
    ///
    /// Returns:
    /// - `Ok(VerifyOutcome::Verified)` when the stored hash matches.
    /// - `Ok(VerifyOutcome::SkippedNoHash)` when the footer's stored hash
    ///   is all zeros — UE writers leave the field zero-filled when
    ///   integrity hashing was not enabled at archive-creation time, so a
    ///   zeroed slot means "no integrity claim to verify against," not
    ///   "tampered."
    /// - `Err(HashMismatch { target: Index, .. })` when a non-zero stored
    ///   hash disagrees with the recomputed digest — the only signal of
    ///   actual tampering or transit corruption.
    ///
    /// # Security note
    ///
    /// An attacker who can rewrite the archive can zero the index hash
    /// slot to force `Ok(SkippedNoHash)` — a downgrade attack. Callers in
    /// security-sensitive contexts should treat any `SkippedNoHash`
    /// outcome as suspicious unless they have out-of-band evidence the
    /// archive was never hashed (e.g., known-pre-hashing UE version).
    /// [`VerifyStats::is_fully_verified`] provides a one-call check for
    /// "every byte that could have been hashed was hashed."
    ///
    /// Opt-in: not called by [`PakReader::open`] because hashing the index
    /// is an extra full-index read that list-only callers don't need to
    /// pay for.
    pub fn verify_index(&self) -> crate::Result<VerifyOutcome> {
        let main = self.verify_main_index_region()?;
        // V10+ also has FDI/PHI regions at arbitrary file offsets that
        // the main-index byte range doesn't cover. Verify them here so
        // a caller using `verify_index()` directly (rather than the
        // higher-level `verify()`) gets full tamper coverage. Issue #86.
        let fdi = self.verify_fdi_region()?;
        let phi = self.verify_phi_region()?;
        Ok(combine_index_outcomes(main, fdi, phi))
    }

    /// Hash and verify the main-index byte range (the `index_offset` ..
    /// `index_offset + index_size` window referenced by the footer).
    /// Always present regardless of pak version.
    fn verify_main_index_region(&self) -> crate::Result<VerifyOutcome> {
        if self.footer.index_hash().is_zero() {
            debug!("index has no recorded SHA1; skipping verification");
            return Ok(VerifyOutcome::SkippedNoHash);
        }
        let guard = self.locked();
        let mut file = BufReader::new(&*guard);
        let _ = file.seek(SeekFrom::Start(self.footer.index_offset()))?;
        let mut buf = [0u8; HASH_BUFFER_BYTES];
        let actual = sha1_of_reader(&mut file, self.footer.index_size(), &mut buf)?;
        if actual != self.footer.index_hash() {
            let expected = self.footer.index_hash().to_string();
            let actual_hex = actual.to_string();
            error!(
                expected = %expected,
                actual = %actual_hex,
                "index hash mismatch — archive may be tampered or corrupted"
            );
            return Err(PaksmithError::HashMismatch {
                target: HashTarget::Index,
                expected,
                actual: actual_hex,
            });
        }
        Ok(VerifyOutcome::Verified)
    }

    /// Hash and verify the v10+ full-directory-index region.
    /// `Ok(None)` for pre-v10 (flat) archives where no FDI exists.
    /// `Ok(Some(SkippedNoHash))` when the FDI hash slot is zero
    /// ("no integrity claim recorded at write time").
    fn verify_fdi_region(&self) -> crate::Result<Option<VerifyOutcome>> {
        let Some(regions) = self.index.encoded_regions() else {
            return Ok(None);
        };
        Ok(Some(
            self.verify_region(regions.fdi(), IndexRegionKind::Fdi)?,
        ))
    }

    /// Hash and verify the v10+ path-hash-index region.
    /// `Ok(None)` for pre-v10 archives or v10+ archives that recorded
    /// `has_path_hash_index = false` (the PHI is optional even in v10+).
    fn verify_phi_region(&self) -> crate::Result<Option<VerifyOutcome>> {
        let Some(regions) = self.index.encoded_regions() else {
            return Ok(None);
        };
        let Some(phi) = regions.phi() else {
            return Ok(None);
        };
        Ok(Some(self.verify_region(phi, IndexRegionKind::Phi)?))
    }

    /// Shared region-hashing helper used by `verify_fdi_region` and
    /// `verify_phi_region`. Both regions have identical wire shape:
    /// an `(offset, size, SHA1)` triple in the main-index header
    /// pointing into the parent file.
    ///
    /// When the stored hash slot is zero, applies the same
    /// strip-detection policy as `verify_entry`: if the archive
    /// claims integrity (footer index_hash non-zero), surface as
    /// [`PaksmithError::IntegrityStripped`] — an attacker who can
    /// recompute the footer hash can zero a region hash slot to
    /// downgrade the region to `SkippedNoHash`, evading callers that
    /// match on `verify_index() == Verified` rather than going
    /// through `is_fully_verified()`. The PHI case is the more
    /// dangerous of the two because paksmith never inspects PHI
    /// bytes during parse, so the slot is the ONLY tamper signal.
    fn verify_region(
        &self,
        region: RegionDescriptor,
        region_kind: IndexRegionKind,
    ) -> crate::Result<VerifyOutcome> {
        let target = HashTarget::from(region_kind);
        // Issue #127: pre-validate the region's wire-declared
        // `(offset, size)` against `file_size` BEFORE the zero-hash
        // short-circuit. Order matters: a zero-hash PHI with
        // `phi_offset = u64::MAX` would otherwise return
        // `SkippedNoHash` and leave the malformed header
        // unflagged — moving the bounds check first surfaces the
        // typed fault even when the archive declined to record an
        // integrity hash. For FDI this also runs at open time
        // (parse-time check in `read_v10_plus_from`); for PHI this
        // is the primary defense since the parser doesn't seek to
        // PHI at open. Shared comparator via `check_region_bounds`.
        check_region_bounds(region_kind, region.offset(), region.size(), self.file_size)
            .map_err(|fault| PaksmithError::InvalidIndex { fault })?;
        if region.hash().is_zero() {
            if self.archive_claims_integrity() {
                error!(
                    region = %target,
                    expected = "non-zero (archive-wide integrity claimed)",
                    actual = "0000000000000000000000000000000000000000",
                    "region has zero SHA1 but archive index does — \
                     possible integrity-strip attack"
                );
                return Err(PaksmithError::IntegrityStripped { target });
            }
            debug!(
                region = %target,
                "region has no recorded SHA1; skipping verification"
            );
            return Ok(VerifyOutcome::SkippedNoHash);
        }
        let guard = self.locked();
        let mut file = BufReader::new(&*guard);
        let _ = file.seek(SeekFrom::Start(region.offset()))?;
        let mut buf = [0u8; HASH_BUFFER_BYTES];
        let actual = sha1_of_reader(&mut file, region.size(), &mut buf)?;
        if actual != region.hash() {
            let expected = region.hash().to_string();
            let actual_hex = actual.to_string();
            error!(
                region = %target,
                expected = %expected,
                actual = %actual_hex,
                "region hash mismatch — archive may be tampered or corrupted"
            );
            return Err(PaksmithError::HashMismatch {
                target,
                expected,
                actual: actual_hex,
            });
        }
        Ok(VerifyOutcome::Verified)
    }

    /// Verify the SHA1 hash of a single entry's on-disk stored bytes. For
    /// uncompressed entries this is the payload itself; for compressed
    /// entries it is the concatenation of the per-block compressed bytes
    /// (UE hashes the on-disk representation, not the decompressed content).
    ///
    /// **Scope:** the entry's stored SHA1 covers payload bytes only, NOT
    /// the in-data FPakEntry record header. Tampering inside the in-data
    /// header is caught earlier by `PakEntryHeader::matches_payload` and
    /// surfaces as `InvalidIndex`, not `HashMismatch`.
    ///
    /// # Archive-wide integrity policy
    ///
    /// UE's stock writer is all-or-nothing for entries that CARRY a
    /// SHA1 field on the wire: it either records integrity hashes for
    /// the entire archive or for none of it. The reader treats "mixed
    /// state" (index hash non-zero, one entry hash zero) as the
    /// attacker signature of a stripped integrity tag, surfacing as
    /// [`PaksmithError::IntegrityStripped`]. When the index hash is
    /// also zero (the archive claims no integrity), a zero entry hash
    /// is accepted as `Ok(SkippedNoHash)`. This closes the bypass path
    /// where an attacker would zero a single entry's hash slot to
    /// force a silent skip.
    ///
    /// **V10+ encoded entries are exempt** from the strip-detection
    /// gate because their wire format omits the SHA1 field entirely
    /// (only the in-data record carries it). Such entries are the
    /// [`crate::container::pak::index::PakEntryHeader::Encoded`]
    /// variant — `sha1()` returns `None` rather than a placeholder
    /// zero — and always surface as `Ok(SkippedNoHash)` regardless of
    /// the archive's index hash. There's no "stripped" state to
    /// detect when no slot exists in the first place.
    ///
    /// **Compatibility caveat:** third-party packers that don't follow
    /// UE's stock all-or-nothing pattern (custom packers, partial
    /// regeneration, mod tools) may legitimately produce mixed-state
    /// archives. Such files will surface as `IntegrityStripped` here even
    /// though they aren't tampered. If you need to accept third-party
    /// packers, treat `IntegrityStripped` as a distinguishable warning
    /// rather than a hard rejection at the call site.
    ///
    /// Returns:
    /// - `Ok(VerifyOutcome::Verified)` on a hash match.
    /// - `Ok(VerifyOutcome::SkippedNoHash)` when the entry's stored SHA1
    ///   is all zeros (no integrity claim recorded at write time).
    /// - `Ok(VerifyOutcome::SkippedEncrypted)` for AES-encrypted entries —
    ///   verifying ciphertext without the key is not supported.
    /// - `Err(EntryNotFound)` for unknown paths.
    /// - `Err(Decompression)` for unsupported compression methods (Gzip,
    ///   Oodle, Zstd, Lz4, UnknownByName, Unknown). We refuse to hash
    ///   arbitrary bytes that we can't interpret; doing otherwise risks
    ///   reporting a misleading `HashMismatch` for a well-formed archive
    ///   in a method we don't support yet.
    /// - `Err(InvalidIndex)` for offset/bounds problems uncovered while
    ///   reading.
    /// - `Err(HashMismatch { target: Entry { path }, .. })` when the
    ///   stored hash disagrees with the recomputed digest.
    #[allow(clippy::too_many_lines)] // bounded by the per-block error branches
    pub fn verify_entry(&self, path: &str) -> crate::Result<VerifyOutcome> {
        let entry = self
            .index
            .find(path)
            .ok_or_else(|| PaksmithError::EntryNotFound {
                path: path.to_string(),
            })?;

        // Encryption check first: if the bytes at entry.header().offset() are
        // ciphertext, hashing them is meaningless. This priority is
        // intentional — an encrypted-AND-zero-hash entry reports as
        // SkippedEncrypted, not SkippedNoHash, because encryption is the
        // stronger reason we can't verify.
        if entry.header().is_encrypted() {
            debug!(path, "entry is encrypted; skipping SHA1 verification");
            return Ok(VerifyOutcome::SkippedEncrypted);
        }

        // V10+ encoded entries have NO sha1 field on the wire (the
        // bit-packed `FPakEntry::EncodeTo` format omits it; only the
        // in-data record carries one). The Encoded variant returns
        // `None` from `sha1()`, which is the unambiguous "no integrity
        // claim was made" signal — distinct from a real-but-zero digest
        // on an Inline entry, which is the v3-v9 tampering signal we
        // want to surface.
        let Some(expected_sha1) = entry.header().sha1() else {
            debug!(
                path,
                "entry has no recorded SHA1 (encoded entry); skipping verification"
            );
            return Ok(VerifyOutcome::SkippedNoHash);
        };

        if expected_sha1.is_zero() {
            // Inline entry with an all-zero SHA1. If the archive opts
            // into integrity (non-zero index_hash), this is a tampering
            // signal we want to surface; otherwise it's a legitimate
            // "no integrity recorded" case.
            if self.archive_claims_integrity() {
                error!(
                    path,
                    expected = "non-zero (archive-wide integrity claimed)",
                    actual = "0000000000000000000000000000000000000000",
                    "entry has zero SHA1 but archive index does — \
                     possible integrity-strip attack"
                );
                return Err(PaksmithError::IntegrityStripped {
                    target: HashTarget::Entry {
                        path: path.to_string(),
                    },
                });
            }
            debug!(path, "entry has no recorded SHA1; skipping verification");
            return Ok(VerifyOutcome::SkippedNoHash);
        }

        let guard = self.locked();
        let mut file = BufReader::new(&*guard);
        let in_data = self.open_entry_into(&mut file, entry)?;

        // Single buffer reused across all per-block reads so multi-block
        // entries don't pay N heap allocations.
        let mut buf = [0u8; HASH_BUFFER_BYTES];

        let actual = match entry.header().compression_method() {
            CompressionMethod::None => {
                // Mirror the payload-end bounds check from
                // `stream_uncompressed_to` so a truncated archive
                // surfaces as the structured `OffsetPastFileSize`
                // variant rather than a bare `Io::UnexpectedEof` from
                // `read_exact` partway through hashing. Uniform
                // diagnostic across the verify and read paths is the
                // whole point of the typed variant (issue #48).
                //
                // Pre-#85 this used `offset + uncompressed_size`,
                // missing the in-data header bytes between them. Use
                // the file cursor (which `open_entry_into` already
                // advanced past the in-data header) as the payload
                // start, matching `stream_uncompressed_to`'s
                // `payload_end = file.stream_position()? + size`
                // pattern exactly — this is now defense-in-depth
                // since #85's open-time check rejects the same shape
                // upstream, but keeping the verify path correct
                // preserves the documented diagnostic contract for
                // any future caller that bypasses `PakReader::open`.
                let payload_end = file
                    .stream_position()?
                    .checked_add(entry.header().uncompressed_size())
                    .ok_or_else(|| PaksmithError::InvalidIndex {
                        fault: IndexParseFault::U64ArithmeticOverflow {
                            path: Some(path.to_string()),
                            operation: OverflowSite::PayloadEnd,
                        },
                    })?;
                if payload_end > self.file_size {
                    return Err(PaksmithError::InvalidIndex {
                        fault: IndexParseFault::OffsetPastFileSize {
                            path: path.to_string(),
                            kind: OffsetPastFileSizeKind::PayloadEndBounds,
                            observed: payload_end,
                            limit: self.file_size,
                        },
                    });
                }
                sha1_of_reader(&mut file, entry.header().uncompressed_size(), &mut buf)?
            }
            CompressionMethod::Zlib => {
                // Hash the on-disk compressed bytes block-by-block. Block
                // offsets are relative to entry.header().offset() (v5+ convention,
                // already enforced in stream_zlib_to).
                let payload_start = entry
                    .header()
                    .offset()
                    .checked_add(in_data.wire_size())
                    .ok_or_else(|| PaksmithError::InvalidIndex {
                        fault: IndexParseFault::U64ArithmeticOverflow {
                            path: Some(path.to_string()),
                            operation: OverflowSite::OffsetPlusHeader,
                        },
                    })?;
                let mut hasher = Sha1::new();
                for (i, block) in entry.header().compression_blocks().iter().enumerate() {
                    let abs_start = entry
                        .header()
                        .offset()
                        .checked_add(block.start())
                        .ok_or_else(|| PaksmithError::InvalidIndex {
                            fault: IndexParseFault::U64ArithmeticOverflow {
                                path: Some(path.to_string()),
                                operation: OverflowSite::BlockStart,
                            },
                        })?;
                    let abs_end = entry
                        .header()
                        .offset()
                        .checked_add(block.end())
                        .ok_or_else(|| PaksmithError::InvalidIndex {
                            fault: IndexParseFault::U64ArithmeticOverflow {
                                path: Some(path.to_string()),
                                operation: OverflowSite::BlockEnd,
                            },
                        })?;
                    if abs_start < payload_start {
                        return Err(PaksmithError::InvalidIndex {
                            fault: IndexParseFault::BlockBoundsViolation {
                                path: path.to_string(),
                                block_index: i,
                                kind: BlockBoundsKind::StartOverlapsHeader,
                                observed: abs_start,
                                limit: payload_start,
                            },
                        });
                    }
                    if abs_end > self.file_size {
                        return Err(PaksmithError::InvalidIndex {
                            fault: IndexParseFault::BlockBoundsViolation {
                                path: path.to_string(),
                                block_index: i,
                                kind: BlockBoundsKind::EndPastFileSize,
                                observed: abs_end,
                                limit: self.file_size,
                            },
                        });
                    }
                    let _ = file.seek(SeekFrom::Start(abs_start))?;
                    feed_hasher(&mut hasher, &mut file, block.len(), &mut buf)?;
                }
                Sha1Digest::from(<[u8; 20]>::from(hasher.finalize()))
            }
            // Already rejected at the top of read_entry for known unsupported
            // methods; here we extend the same policy to verify_entry rather
            // than silently succeed by hashing whatever bytes are at offset.
            method @ (CompressionMethod::Gzip
            | CompressionMethod::Oodle
            | CompressionMethod::Zstd
            | CompressionMethod::Lz4
            | CompressionMethod::Unknown(_)
            | CompressionMethod::UnknownByName(_)) => {
                return Err(PaksmithError::Decompression {
                    path: path.to_string(),
                    offset: entry.header().offset(),
                    fault: DecompressionFault::UnsupportedMethod {
                        method: method.clone(),
                    },
                });
            }
        };

        if actual != expected_sha1 {
            let expected = expected_sha1.to_string();
            let actual_hex = actual.to_string();
            error!(
                path,
                expected = %expected,
                actual = %actual_hex,
                "entry hash mismatch — payload may be tampered or corrupted"
            );
            return Err(PaksmithError::HashMismatch {
                target: HashTarget::Entry {
                    path: path.to_string(),
                },
                expected,
                actual: actual_hex,
            });
        }

        Ok(VerifyOutcome::Verified)
    }

    /// Verify the index hash AND every entry's hash, returning structured
    /// counts of what was actually checked vs skipped. Stops on the first
    /// `HashMismatch` and returns the error.
    ///
    /// **Skips are reported, not silenced.** Entries that have no recorded
    /// hash (UE didn't enable integrity at write time) and entries that are
    /// AES-encrypted (we have no key) are counted in the returned
    /// [`VerifyStats`]. Callers can inspect the report to decide whether
    /// `Ok` means "all bytes intact" or "some bytes weren't verifiable" —
    /// avoiding the silent partial-success failure mode that returning bare
    /// `Result<()>` would create.
    pub fn verify(&self) -> crate::Result<VerifyStats> {
        let mut stats = VerifyStats::default();
        // Drive each region with its own helper rather than calling
        // `verify_index` once and mapping a single outcome — the per-
        // region calls let us populate `VerifyStats.fdi`/`phi` with
        // fine-grained state instead of bucketing the worst-case
        // outcome across all three regions.
        match self.verify_main_index_region()? {
            VerifyOutcome::Verified => stats.index_verified = true,
            VerifyOutcome::SkippedNoHash => stats.index_skipped_no_hash = true,
            // verify_main_index_region has no encrypted-index concept
            // today, so this arm shouldn't be reachable. Surface it as
            // a typed error rather than panicking — CLAUDE.md says no
            // panics in core.
            VerifyOutcome::SkippedEncrypted => {
                return Err(PaksmithError::InvalidIndex {
                    fault: IndexParseFault::InvariantViolated {
                        reason: "verify_main_index_region returned SkippedEncrypted \
                                 (internal invariant violated)",
                    },
                });
            }
        }
        stats.fdi = match self.verify_fdi_region()? {
            None => RegionVerifyState::NotPresent,
            Some(VerifyOutcome::Verified) => RegionVerifyState::Verified,
            Some(VerifyOutcome::SkippedNoHash) => RegionVerifyState::SkippedNoHash,
            Some(VerifyOutcome::SkippedEncrypted) => {
                return Err(PaksmithError::InvalidIndex {
                    fault: IndexParseFault::InvariantViolated {
                        reason: "verify_fdi_region returned SkippedEncrypted \
                                 (internal invariant violated)",
                    },
                });
            }
        };
        stats.phi = match self.verify_phi_region()? {
            None => RegionVerifyState::NotPresent,
            Some(VerifyOutcome::Verified) => RegionVerifyState::Verified,
            Some(VerifyOutcome::SkippedNoHash) => RegionVerifyState::SkippedNoHash,
            Some(VerifyOutcome::SkippedEncrypted) => {
                return Err(PaksmithError::InvalidIndex {
                    fault: IndexParseFault::InvariantViolated {
                        reason: "verify_phi_region returned SkippedEncrypted \
                                 (internal invariant violated)",
                    },
                });
            }
        };
        for entry in self.index.entries() {
            match self.verify_entry(entry.filename())? {
                VerifyOutcome::Verified => stats.entries_verified += 1,
                VerifyOutcome::SkippedNoHash => stats.entries_skipped_no_hash += 1,
                VerifyOutcome::SkippedEncrypted => stats.entries_skipped_encrypted += 1,
            }
        }
        let fdi_skipped = matches!(stats.fdi, RegionVerifyState::SkippedNoHash);
        let phi_skipped = matches!(stats.phi, RegionVerifyState::SkippedNoHash);
        if stats.index_skipped_no_hash
            || fdi_skipped
            || phi_skipped
            || stats.entries_skipped_encrypted > 0
            || stats.entries_skipped_no_hash > 0
        {
            warn!(
                index_skipped = stats.index_skipped_no_hash,
                fdi_skipped,
                phi_skipped,
                encrypted = stats.entries_skipped_encrypted,
                no_hash = stats.entries_skipped_no_hash,
                verified = stats.entries_verified,
                "verify(): some bytes were not hashed; inspect VerifyStats"
            );
        }
        Ok(stats)
    }

    /// Position `reader` at `entry.header().offset()`, parse the in-data FPakEntry
    /// header, and validate it against the index entry. Returns the parsed
    /// in-data header; the caller continues reading the payload from
    /// `reader` (now positioned just past the header).
    ///
    /// Takes a reader by reference rather than opening one internally so
    /// callers can share the `PakReader`'s single `Mutex<File>` handle.
    /// Bounds-checks the entry offset against [`Self::file_size`] before
    /// seeking, so a malformed pak can't read past EOF undetected.
    fn open_entry_into<R: Read + Seek>(
        &self,
        reader: &mut R,
        entry: &PakIndexEntry,
    ) -> crate::Result<PakEntryHeader> {
        let path = entry.filename();

        // SAFETY: structurally unreachable from a successfully-opened
        // reader. Issue #82's open-time iteration above (around line
        // 222-249) computes `payload_end = offset + wire_size() +
        // compressed` and rejects `payload_end > file_size`.
        // `wire_size()` is strictly positive for every entry shape
        // (50 bytes for V8A, 53 for V8B+/v3-v7, more when compression
        // blocks are present), so `offset >= file_size` implies
        // `payload_end > file_size` upstream and surfaces as
        // `OffsetPastFileSizeKind::PayloadEndBounds`, not
        // `EntryHeaderOffset`. The branch is kept as a typed-error
        // safety net so a future refactor that breaks the open-time
        // invariant surfaces here as `EntryHeaderOffset` rather than
        // as `Io::UnexpectedEof` from the seek below. Issue #92.
        if entry.header().offset() >= self.file_size {
            return Err(PaksmithError::InvalidIndex {
                fault: IndexParseFault::OffsetPastFileSize {
                    path: path.to_string(),
                    kind: OffsetPastFileSizeKind::EntryHeaderOffset,
                    observed: entry.header().offset(),
                    limit: self.file_size,
                },
            });
        }

        let _ = reader.seek(SeekFrom::Start(entry.header().offset()))?;
        let in_data = PakEntryHeader::read_from(
            reader,
            self.footer.version(),
            self.footer.compression_methods(),
        )?;

        entry.header().matches_payload(&in_data, path)?;
        Ok(in_data)
    }

    /// Inner streaming primitive shared by `read_entry_to` (trait method,
    /// looks up the entry by path) and `read_entry` (override, looks up
    /// the entry by path AND wraps with try_reserve_exact). Takes a
    /// pre-resolved `&PakIndexEntry` so callers don't pay two HashMap
    /// lookups for the same path.
    fn stream_entry_to(&self, entry: &PakIndexEntry, writer: &mut dyn Write) -> crate::Result<u64> {
        let path = entry.filename();

        // Reject what we definitely can't handle BEFORE opening the file
        // or parsing the in-data header. Otherwise a misleading "in-data
        // header mismatch" surfaces when the bytes at entry.header().offset() are
        // actually ciphertext (encrypted entry) rather than a real
        // FPakEntry.
        if entry.header().is_encrypted() {
            return Err(PaksmithError::Decryption {
                path: path.to_string(),
            });
        }
        match entry.header().compression_method() {
            CompressionMethod::None | CompressionMethod::Zlib => {}
            method @ (CompressionMethod::Gzip
            | CompressionMethod::Oodle
            | CompressionMethod::Zstd
            | CompressionMethod::Lz4
            | CompressionMethod::Unknown(_)
            | CompressionMethod::UnknownByName(_)) => {
                warn!(path, ?method, "rejected unsupported compression method");
                return Err(PaksmithError::Decompression {
                    path: path.to_string(),
                    offset: entry.header().offset(),
                    fault: DecompressionFault::UnsupportedMethod {
                        method: method.clone(),
                    },
                });
            }
        }

        // No `uncompressed_size > MAX_UNCOMPRESSED_ENTRY_BYTES` re-check
        // here: issue #58's open-time iteration in `PakReader::open`
        // already enforces the cap for every index entry, and the index
        // is immutable post-open. The deleted re-check was dead code
        // post-#58. Open-time enforcement is pinned by the
        // `open_rejects_oversized_uncompressed_size` integration test.
        // Issue #92.
        let guard = self.locked();
        let mut file = BufReader::new(&*guard);
        let in_data = self.open_entry_into(&mut file, entry)?;
        // After open_entry_into, `file` is positioned just past the in-data
        // FPakEntry record. Use the parsed in-data header's wire_size as
        // the single source of truth for the payload start, so any future
        // change to the wire format only needs updating in
        // PakEntryHeader::read_from (which `wire_size` mirrors by
        // construction).
        let payload_start = entry
            .header()
            .offset()
            .checked_add(in_data.wire_size())
            .ok_or_else(|| PaksmithError::InvalidIndex {
                fault: IndexParseFault::U64ArithmeticOverflow {
                    path: Some(path.to_string()),
                    operation: OverflowSite::OffsetPlusHeader,
                },
            })?;

        match entry.header().compression_method() {
            CompressionMethod::None => {
                stream_uncompressed_to(&mut file, entry, self.file_size, writer)
            }
            CompressionMethod::Zlib => stream_zlib_to(
                &mut file,
                entry,
                self.file_size,
                payload_start,
                self.version(),
                writer,
            ),
            // Already rejected at the top of `stream_entry_to`; this
            // arm exists to keep the match exhaustive (per CLAUDE.md
            // "no panics in core") without an opaque `_` catch-all.
            // If we ever reach here, the early-reject path was bypassed
            // by a refactor — surface as `InvariantViolated` so an
            // operator gets a typed error rather than a panic, and the
            // bug is unmistakable in logs.
            CompressionMethod::Gzip
            | CompressionMethod::Oodle
            | CompressionMethod::Zstd
            | CompressionMethod::Lz4
            | CompressionMethod::Unknown(_)
            | CompressionMethod::UnknownByName(_) => Err(PaksmithError::InvalidIndex {
                fault: IndexParseFault::InvariantViolated {
                    reason: "stream_entry_to dispatch reached an unsupported \
                                 CompressionMethod arm — early-reject at top of \
                                 function was bypassed (see issue #138)",
                },
            }),
        }
    }
}

impl ContainerReader for PakReader {
    fn entries(&self) -> Box<dyn Iterator<Item = EntryMetadata> + '_> {
        Box::new(self.index.entries().iter().map(|e| {
            EntryMetadata::new(
                e.filename().to_owned(),
                e.header().compressed_size(),
                e.header().uncompressed_size(),
                EntryFlags {
                    compressed: *e.header().compression_method() != CompressionMethod::None,
                    encrypted: e.header().is_encrypted(),
                },
            )
        }))
    }

    fn read_entry_to(&self, path: &str, writer: &mut dyn Write) -> crate::Result<u64> {
        let entry = self
            .index
            .find(path)
            .ok_or_else(|| PaksmithError::EntryNotFound {
                path: path.to_string(),
            })?;
        self.stream_entry_to(entry, writer)
    }

    /// Implements the trait's required `read_entry` (no default — see
    /// the trait docstring for why). Reserves the full uncompressed
    /// size via `Vec::try_reserve_exact` upfront, surfacing OOM as a
    /// typed `InvalidIndex` before any I/O begins.
    fn read_entry(&self, path: &str) -> crate::Result<Vec<u8>> {
        let entry = self
            .index
            .find(path)
            .ok_or_else(|| PaksmithError::EntryNotFound {
                path: path.to_string(),
            })?;

        let uncompressed_size = entry.header().uncompressed_size();
        // No `uncompressed_size > MAX_UNCOMPRESSED_ENTRY_BYTES` re-check
        // here: issue #58's open-time iteration enforces the cap for
        // every index entry, and the index is immutable post-open.
        // The deleted re-check was dead code post-#58. Open-time
        // enforcement is pinned by `open_rejects_oversized_uncompressed_size`.
        // Issue #92.
        let size_usize =
            usize::try_from(uncompressed_size).map_err(|_| PaksmithError::InvalidIndex {
                fault: IndexParseFault::U64ExceedsPlatformUsize {
                    field: WireField::UncompressedSize,
                    value: uncompressed_size,
                    path: Some(path.to_string()),
                },
            })?;

        // Allocate fallibly upfront so a legitimate-but-large entry on a
        // memory-constrained host surfaces as a typed error rather than an
        // allocator abort during the streaming write.
        let mut buf: Vec<u8> = Vec::new();
        buf.try_reserve_exact(size_usize).map_err(|source| {
            warn!(path, size = size_usize, error = %source, "output reservation failed");
            PaksmithError::InvalidIndex {
                fault: IndexParseFault::AllocationFailed {
                    context: AllocationContext::EntryPayloadBytes,
                    requested: size_usize,
                    unit: BoundsUnit::Bytes,
                    source,
                    path: Some(path.to_string()),
                },
            }
        })?;
        // Call the inner streamer directly with the entry we already
        // resolved, avoiding a second HashMap find through `read_entry_to`.
        let _ = self.stream_entry_to(entry, &mut buf)?;
        Ok(buf)
    }

    fn format(&self) -> ContainerFormat {
        ContainerFormat::Pak
    }

    fn mount_point(&self) -> &str {
        self.index.mount_point()
    }
}

/// Stream the uncompressed payload of `entry` from `file` to `writer`.
/// Returns the number of bytes written.
///
/// Peak heap allocation is `io::copy`'s internal 8 KiB scratch buffer —
/// the entry's full uncompressed bytes never live in memory at once.
fn stream_uncompressed_to<R: Read + Seek>(
    file: &mut R,
    entry: &PakIndexEntry,
    file_size: u64,
    writer: &mut dyn Write,
) -> crate::Result<u64> {
    let path = entry.filename();
    let size = entry.header().uncompressed_size();

    // For uncompressed entries the payload immediately follows the in-data
    // header, so the reader is already positioned correctly. Bounds-check
    // the payload against EOF before reading.
    let payload_end =
        file.stream_position()?
            .checked_add(size)
            .ok_or_else(|| PaksmithError::InvalidIndex {
                fault: IndexParseFault::U64ArithmeticOverflow {
                    path: Some(path.to_string()),
                    operation: OverflowSite::PayloadEnd,
                },
            })?;
    if payload_end > file_size {
        return Err(PaksmithError::InvalidIndex {
            fault: IndexParseFault::OffsetPastFileSize {
                path: path.to_string(),
                kind: OffsetPastFileSizeKind::PayloadEndBounds,
                observed: payload_end,
                limit: file_size,
            },
        });
    }

    let mut limited = file.by_ref().take(size);
    let written = io::copy(&mut limited, writer)?;
    if written != size {
        // Should be unreachable given the bounds check above, but the
        // file-grew-since-open invariant could be violated by an external
        // truncation. Surface it as a typed error instead of silent
        // short-write.
        return Err(PaksmithError::InvalidIndex {
            fault: IndexParseFault::ShortEntryRead {
                path: path.to_string(),
                written,
                expected: size,
            },
        });
    }
    Ok(written)
}

/// Stream the zlib-decompressed payload of `entry` from `file` to
/// `writer`. Returns the number of decompressed bytes written.
///
/// Peak heap allocation is one block at a time: a per-block compressed
/// buffer (bounded by the block's `len()`) plus a per-block decompressed
/// buffer (bounded by the remaining output budget). The full
/// `uncompressed_size` never lives in memory at once.
#[allow(clippy::too_many_lines)] // bounded by the per-block error-reporting branches
fn stream_zlib_to<R: Read + Seek>(
    file: &mut R,
    entry: &PakIndexEntry,
    file_size: u64,
    payload_start: u64,
    version: PakVersion,
    writer: &mut dyn Write,
) -> crate::Result<u64> {
    let path = entry.filename();

    if version < PakVersion::RelativeChunkOffsets {
        // Pre-v5 paks store absolute file offsets in compression_blocks rather
        // than offsets relative to the entry record. Real-world v3/v4 paks are
        // rare; reject explicitly rather than silently producing garbage.
        return Err(PaksmithError::UnsupportedVersion {
            version: version.wire_version(),
        });
    }

    let uncompressed_size = entry.header().uncompressed_size();
    let mut bytes_written: u64 = 0;

    // Per-call scratch buffer reused across all compression blocks.
    // Hoisted out of the per-block loop so a multi-block entry pays
    // one allocation, not N — at 32 KiB heap-alloc per block, a
    // 100-block entry × 10k entries during bulk extract was tens of
    // thousands of redundant allocs. 32 KiB matches zlib's typical
    // inflate window. Heap-allocated (not `[0u8; 32 * 1024]`) to
    // satisfy clippy's `large_stack_arrays` lint and stay portable
    // to small-stack platforms.
    let mut scratch = vec![0u8; 32 * 1024];

    for (i, block) in entry.header().compression_blocks().iter().enumerate() {
        // v5+ block offsets are relative to entry.header().offset(), and must point
        // past the in-data header into the payload region.
        let abs_start = entry
            .header()
            .offset()
            .checked_add(block.start())
            .ok_or_else(|| PaksmithError::InvalidIndex {
                fault: IndexParseFault::U64ArithmeticOverflow {
                    path: Some(path.to_string()),
                    operation: OverflowSite::BlockStart,
                },
            })?;
        let abs_end = entry
            .header()
            .offset()
            .checked_add(block.end())
            .ok_or_else(|| PaksmithError::InvalidIndex {
                fault: IndexParseFault::U64ArithmeticOverflow {
                    path: Some(path.to_string()),
                    operation: OverflowSite::BlockEnd,
                },
            })?;
        if abs_start < payload_start {
            return Err(PaksmithError::InvalidIndex {
                fault: IndexParseFault::BlockBoundsViolation {
                    path: path.to_string(),
                    block_index: i,
                    kind: BlockBoundsKind::StartOverlapsHeader,
                    observed: abs_start,
                    limit: payload_start,
                },
            });
        }
        if abs_end > file_size {
            return Err(PaksmithError::InvalidIndex {
                fault: IndexParseFault::BlockBoundsViolation {
                    path: path.to_string(),
                    block_index: i,
                    kind: BlockBoundsKind::EndPastFileSize,
                    observed: abs_end,
                    limit: file_size,
                },
            });
        }

        let block_len = block.len();
        let block_len_usize =
            usize::try_from(block_len).map_err(|_| PaksmithError::InvalidIndex {
                fault: IndexParseFault::U64ExceedsPlatformUsize {
                    field: WireField::BlockLength,
                    value: block_len,
                    path: Some(path.to_string()),
                },
            })?;

        let _ = file.seek(SeekFrom::Start(abs_start))?;
        // Per-block compressed buffer is bounded by file_size (via the
        // abs_end check above). Allocate fallibly so OOM is typed.
        let mut compressed: Vec<u8> = Vec::new();
        let reserve_res = compressed.try_reserve_exact(block_len_usize);
        // Cfg-gated test seam: lets integration tests in
        // `tests/oom_pak.rs` exercise the
        // `CompressedBlockReserveFailed` typed-error path without a
        // real OOM. The seam vanishes from production builds when
        // `__test_utils` is disabled. See `testing::oom` module docs.
        #[cfg(feature = "__test_utils")]
        let reserve_res =
            reserve_res.and_then(|()| crate::testing::oom::maybe_fail_compressed_reserve());
        reserve_res.map_err(|e| {
            warn!(path, block = i, block_len, error = %e, "zlib block reservation failed");
            PaksmithError::Decompression {
                path: path.to_string(),
                offset: abs_start,
                fault: DecompressionFault::CompressedBlockReserveFailed {
                    block_index: i,
                    requested: block_len_usize,
                    source: e,
                },
            }
        })?;
        compressed.resize(block_len_usize, 0);
        file.read_exact(&mut compressed)?;

        // Bound the decoder to the remaining output budget plus one byte.
        // The +1 lets us detect "decompressed more than we expected" without
        // allowing unbounded growth: a zlib bomb that wants to expand past
        // `uncompressed_size` will be cut off at uncompressed_size + 1, then
        // the post-loop length check rejects.
        let remaining = uncompressed_size.saturating_sub(bytes_written);
        let budget = remaining.saturating_add(1);
        let mut limited = ZlibDecoder::new(&compressed[..]).take(budget);
        // Per-block decompressed buffer. We can't `write_all` directly
        // into the output writer because we need the full block's
        // decompressed length for the bomb check and the per-block
        // sanity assertion before committing.
        //
        // The previous implementation used `read_to_end`, which grows
        // the Vec infallibly via `Vec::reserve`. Combined with the
        // 8 GiB `MAX_UNCOMPRESSED_ENTRY_BYTES` ceiling on `budget`,
        // that path could OOM-abort on a malicious entry. Instead, we
        // read in fixed-size scratch chunks and `try_reserve` per
        // chunk so the allocation grows fallibly and surfaces as a
        // typed `Decompression` error rather than an
        // `alloc::handle_alloc_error` abort.
        let mut block_out: Vec<u8> = Vec::new();
        let written = loop {
            let n = limited.read(&mut scratch).map_err(|e| {
                warn!(path, block = i, abs_start, error = %e, "zlib decompress failed");
                PaksmithError::Decompression {
                    path: path.to_string(),
                    offset: abs_start,
                    fault: DecompressionFault::ZlibStreamError {
                        block_index: i,
                        kind: e.kind(),
                        message: e.to_string(),
                    },
                }
            })?;
            if n == 0 {
                break block_out.len();
            }
            let scratch_res = block_out.try_reserve(n);
            // Cfg-gated test seam: lets `tests/oom_pak.rs` exercise
            // the `ZlibScratchReserveFailed` typed-error path without
            // a real OOM. Vanishes from production builds when
            // `__test_utils` is disabled. See `testing::oom` module
            // docs for the full rationale.
            #[cfg(feature = "__test_utils")]
            let scratch_res =
                scratch_res.and_then(|()| crate::testing::oom::maybe_fail_scratch_reserve());
            scratch_res.map_err(|e| {
                // Mirror the warn! at the sibling CompressedBlockReserveFailed
                // site so operators triaging an OOM via the tracing stream
                // see both reserve-failed paths. `already_committed` is the
                // triage signal that distinguishes small-allocator-pressure
                // (failure on the first chunk) from genuine large-entry OOM
                // (failure after gigabytes accumulated).
                warn!(
                    path,
                    block = i,
                    requested = n,
                    already_committed = block_out.len(),
                    error = %e,
                    "zlib scratch reservation failed mid-decode"
                );
                PaksmithError::Decompression {
                    path: path.to_string(),
                    offset: abs_start,
                    fault: DecompressionFault::ZlibScratchReserveFailed {
                        block_index: i,
                        requested: n,
                        already_committed: block_out.len(),
                        source: e,
                    },
                }
            })?;
            block_out.extend_from_slice(&scratch[..n]);
        };

        let new_total = bytes_written.saturating_add(written as u64);
        if new_total > uncompressed_size {
            warn!(
                path,
                block = i,
                actual = new_total,
                uncompressed_size,
                "decompression bomb: block exceeded uncompressed_size"
            );
            return Err(PaksmithError::Decompression {
                path: path.to_string(),
                offset: abs_start,
                fault: DecompressionFault::DecompressionBomb {
                    block_index: i,
                    actual: new_total,
                    claimed_uncompressed: uncompressed_size,
                },
            });
        }

        // Sanity: every block except possibly the last should produce exactly
        // compression_block_size bytes when decompressed.
        if i + 1 < entry.header().compression_blocks().len()
            && written as u64 != u64::from(entry.header().compression_block_size())
        {
            let expected = entry.header().compression_block_size();
            warn!(
                path,
                block = i,
                written,
                expected,
                "non-final block decompressed to wrong size"
            );
            return Err(PaksmithError::Decompression {
                path: path.to_string(),
                offset: abs_start,
                fault: DecompressionFault::NonFinalBlockSizeMismatch {
                    block_index: i,
                    expected,
                    actual: written as u64,
                },
            });
        }

        // Block validated — commit to the output writer.
        writer.write_all(&block_out)?;
        bytes_written = new_total;
    }

    if bytes_written != uncompressed_size {
        warn!(
            path,
            actual = bytes_written,
            uncompressed_size,
            "cumulative decompressed size mismatch"
        );
        return Err(PaksmithError::Decompression {
            path: path.to_string(),
            offset: entry.header().offset(),
            fault: DecompressionFault::SizeUnderrun {
                actual: bytes_written,
                expected: uncompressed_size,
            },
        });
    }

    Ok(bytes_written)
}

/// Default scratch-buffer size for streaming SHA1 computation. Sized to
/// match `BufReader`'s default capacity so we don't fragment reads against
/// the underlying buffered reader. Stack-allocated by callers as
/// `[0u8; HASH_BUFFER_BYTES]` (8 KiB is well within any reasonable stack
/// limit; neither `verify_index` nor `verify_entry` recurses).
const HASH_BUFFER_BYTES: usize = 8 * 1024;

/// Outcome of a single SHA1 verification call.
///
/// Marked `#[must_use]` because the variants distinguish "verified" from
/// "skipped because we couldn't check" — silently dropping the value with
/// `let _ = reader.verify_entry(p);` defeats the purpose of opt-in
/// verification. Marked `#[non_exhaustive]` because future variants
/// (e.g., `SkippedUnsupportedCompression`) are plausible follow-up work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "VerifyOutcome distinguishes Verified from Skipped — \
              check the variant or use VerifyStats::is_fully_verified"]
#[non_exhaustive]
pub enum VerifyOutcome {
    /// Hash was computed and matched the stored value.
    Verified,
    /// The stored hash slot is all zeros — UE's "no integrity claim
    /// recorded" sentinel. Nothing was hashed.
    SkippedNoHash,
    /// The entry is AES-encrypted; verifying ciphertext without the key is
    /// not supported. Only ever returned by [`PakReader::verify_entry`],
    /// never by [`PakReader::verify_index`].
    SkippedEncrypted,
}

/// Per-region verification state for the v10+ encoded-index regions
/// (full directory index and optional path hash index).
///
/// Distinct from [`VerifyOutcome`] because regions can be `NotPresent`
/// (pre-v10 archives have no FDI/PHI; PHI is also optional in v10+),
/// whereas `VerifyOutcome` always describes a region that exists.
/// `#[non_exhaustive]` for forward-compat with future region kinds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum RegionVerifyState {
    /// Region not present in this archive. Pre-v10 archives have no
    /// FDI or PHI; v10+ archives may omit the PHI. The default for
    /// `VerifyStats` so legacy callers see the natural value before
    /// [`PakReader::verify`] populates per-region state.
    #[default]
    NotPresent,
    /// Region's hash slot is the all-zero sentinel ("no integrity
    /// claim was recorded at write time"). Region bytes were not
    /// hashed. Counts against [`VerifyStats::is_fully_verified`].
    SkippedNoHash,
    /// Region bytes were hashed and matched the stored SHA1.
    Verified,
}

/// Structured report from [`PakReader::verify`]: counts of what was
/// actually hashed vs skipped, so callers can distinguish "fully verified"
/// from "verification ran but skipped some entries we couldn't check."
///
/// Marked `#[non_exhaustive]` to allow future fields (e.g., a count of
/// entries with detected I/O errors during partial-archive recovery)
/// without breaking downstream pattern-matchers. Fields are `pub(crate)`
/// — external callers read counts via the named accessors below
/// ([`Self::index_verified`], [`Self::entries_verified`], etc.) and
/// the high-level helper [`Self::is_fully_verified`]. This keeps the
/// struct's internal representation free to change (e.g., split a
/// counter into per-reason buckets) without breaking downstream
/// consumers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerifyStats {
    pub(crate) index_verified: bool,
    pub(crate) index_skipped_no_hash: bool,
    /// V10+ full-directory-index region state. `NotPresent` for v3-v9
    /// archives. Issue #86.
    pub(crate) fdi: RegionVerifyState,
    /// V10+ path-hash-index region state. `NotPresent` for v3-v9 and
    /// for v10+ archives without a PHI. Issue #86.
    pub(crate) phi: RegionVerifyState,
    pub(crate) entries_verified: usize,
    pub(crate) entries_skipped_no_hash: usize,
    pub(crate) entries_skipped_encrypted: usize,
}

impl VerifyStats {
    /// True iff the index hash was computed and matched.
    pub fn index_verified(&self) -> bool {
        self.index_verified
    }

    /// True iff the index had no recorded hash (zeroed slot, accepted
    /// as a no-integrity-claim signal rather than a tampering one).
    pub fn index_skipped_no_hash(&self) -> bool {
        self.index_skipped_no_hash
    }

    /// V10+ full-directory-index region verification state. Returns
    /// [`RegionVerifyState::NotPresent`] for pre-v10 archives. Issue
    /// #86: the FDI region's bytes live at an arbitrary file offset
    /// outside the main-index byte range, with an independent SHA1
    /// slot in the main-index header. Pre-fix, the slot was discarded.
    pub fn fdi(&self) -> RegionVerifyState {
        self.fdi
    }

    /// V10+ path-hash-index region verification state. Returns
    /// [`RegionVerifyState::NotPresent`] for pre-v10 archives and for
    /// v10+ archives whose main-index header recorded
    /// `has_path_hash_index = false`.
    pub fn phi(&self) -> RegionVerifyState {
        self.phi
    }

    /// Number of entries whose hash was computed and matched.
    pub fn entries_verified(&self) -> usize {
        self.entries_verified
    }

    /// Number of entries skipped because the stored SHA1 was the all-zero
    /// sentinel (no integrity claim recorded at write time) or the entry
    /// was a v10+ encoded record (which omits SHA1 from the wire format).
    pub fn entries_skipped_no_hash(&self) -> usize {
        self.entries_skipped_no_hash
    }

    /// Number of entries skipped because they are AES-encrypted (hashing
    /// ciphertext is meaningless without the key).
    pub fn entries_skipped_encrypted(&self) -> usize {
        self.entries_skipped_encrypted
    }

    /// Number of entries skipped for any reason (no-hash + encrypted).
    /// Sum of [`Self::entries_skipped_no_hash`] and
    /// [`Self::entries_skipped_encrypted`]. Convenience for callers
    /// that only care about the total skip count rather than the
    /// reason — e.g., the post-verify warn log in [`PakReader::verify`]
    /// and downstream "did anything get skipped?" predicates.
    pub fn total_skipped_entries(&self) -> usize {
        self.entries_skipped_no_hash + self.entries_skipped_encrypted
    }

    /// True iff every byte the verifier could see was hashed and matched.
    /// Use this in security-sensitive contexts where any `SkippedNoHash`
    /// outcome should be treated as a potential downgrade attack on the
    /// stored hash slot — UE's writer either records integrity for the
    /// whole archive or for none of it, so a partial-skip in a context
    /// you control end-to-end is a tampering signal.
    ///
    /// Equivalent to manually checking that the index was verified, no
    /// entries were skipped for either reason, and at least one entry was
    /// actually hashed. The "at least one entry" requirement defends
    /// against the empty-but-hashed-shell substitution attack: an
    /// attacker who replaces a populated archive with a zero-entry
    /// archive whose index correctly hashes still fails this check.
    ///
    /// **Caveat (issue #131):** for v10+ archives, `is_fully_verified()
    /// == true` only attests that the FDI/PHI region bytes hash to the
    /// SHA-1 values stored in the main-index header. It does NOT prove
    /// the FNV-64 keys inside the PHI table correspond to the FDI-
    /// derived paths — paksmith currently has no PHI ↔ FDI cross-
    /// validation primitive. (To actually exploit this gap, an attacker
    /// would also need to rewrite the PHI's stored SHA-1 inside the
    /// main index, the main-index hash itself, and whatever footer
    /// mechanism authenticates the main-index hash; if all those are
    /// under attacker control, the FNV-64-vs-FDI-path mismatch would
    /// still go undetected here.) The cross-validation primitive is
    /// the Phase-2 hook on top of `path_hash_seed` (#98 + #131); until
    /// it lands, treat `is_fully_verified() == true` as "stored hashes
    /// match stored bytes," not "the hash table is authoritative."
    pub fn is_fully_verified(&self) -> bool {
        // Region state passes if Verified or NotPresent — the latter
        // is the legitimate "no FDI/PHI in this archive" case for
        // pre-v10 archives and for v10+ archives without a PHI.
        // SkippedNoHash counts against full verification, same as
        // the main index's `index_skipped_no_hash`.
        let fdi_ok = matches!(
            self.fdi,
            RegionVerifyState::Verified | RegionVerifyState::NotPresent
        );
        let phi_ok = matches!(
            self.phi,
            RegionVerifyState::Verified | RegionVerifyState::NotPresent
        );
        self.index_verified
            && !self.index_skipped_no_hash
            && fdi_ok
            && phi_ok
            && self.entries_skipped_no_hash == 0
            && self.entries_skipped_encrypted == 0
            && self.entries_verified > 0
    }
}

/// Reduce per-region verify outcomes to a single conservative
/// `VerifyOutcome` for the back-compat return value of
/// [`PakReader::verify_index`]. The pre-#86 method returned only the
/// main-index outcome; post-fix, `verify_index` covers all three
/// regions and the conservative outcome is the "worst" state
/// observed across them — anything less than `Verified` from any
/// region wins, because any non-Verified state means full coverage
/// wasn't achieved.
///
/// `HashMismatch` / `IntegrityStripped` don't appear here: those
/// short-circuit as `Err` before this function is reached, so the
/// inputs are always `Ok` variants.
///
/// The per-region match is exhaustive (no `_` arm) so that any
/// future variant added to `VerifyOutcome` (it's `#[non_exhaustive]`
/// — e.g. the documented `SkippedUnsupportedCompression` candidate)
/// fails the build here rather than silently laundering into
/// `Verified`. That's the exact silent-tamper-gap shape #86 fixed
/// for the regions themselves; the same discipline must apply to
/// the outcome reducer.
fn combine_index_outcomes(
    main: VerifyOutcome,
    fdi: Option<VerifyOutcome>,
    phi: Option<VerifyOutcome>,
) -> VerifyOutcome {
    let reduce = |o: VerifyOutcome| match o {
        VerifyOutcome::Verified => VerifyOutcome::Verified,
        VerifyOutcome::SkippedNoHash => VerifyOutcome::SkippedNoHash,
        VerifyOutcome::SkippedEncrypted => VerifyOutcome::SkippedEncrypted,
    };
    let prefer_worse = |a: VerifyOutcome, b: VerifyOutcome| match (a, b) {
        (VerifyOutcome::Verified, other) | (other, VerifyOutcome::Verified) => other,
        // Any non-Verified beats Verified; among non-Verified states
        // the choice is arbitrary (callers should consult VerifyStats
        // for per-region detail). Pick `a` for determinism.
        (a, _) => a,
    };
    let mut worst = reduce(main);
    if let Some(o) = fdi {
        worst = prefer_worse(worst, reduce(o));
    }
    if let Some(o) = phi {
        worst = prefer_worse(worst, reduce(o));
    }
    worst
}

/// Read exactly `len` bytes from `reader` and return the SHA1 digest.
/// `buf` is the caller-owned scratch buffer — fixed-size at
/// [`HASH_BUFFER_BYTES`] so an empty buffer is structurally
/// unrepresentable (issue #45). Reusing one buffer across calls
/// avoids reallocating per invocation in the multi-block hashing path.
fn sha1_of_reader<R: Read>(
    reader: &mut R,
    len: u64,
    buf: &mut [u8; HASH_BUFFER_BYTES],
) -> crate::Result<Sha1Digest> {
    let mut hasher = Sha1::new();
    feed_hasher(&mut hasher, reader, len, buf)?;
    Ok(Sha1Digest::from(<[u8; 20]>::from(hasher.finalize())))
}

/// Append exactly `len` bytes from `reader` into the running `hasher`,
/// using `buf` as the per-iteration scratch buffer. Caller owns `buf`
/// so multi-call sequences (e.g., per-block hashing in
/// [`PakReader::verify_entry`]) can amortise its allocation.
///
/// The buffer type is a fixed-size `&mut [u8; HASH_BUFFER_BYTES]`
/// rather than a slice so the empty-buffer case (which would loop
/// forever consuming zero bytes per iteration) is unrepresentable.
/// Pre-PR-#45 this was guarded by a `debug_assert!` that was stripped
/// in release builds — a latent infinite-loop footgun.
fn feed_hasher<R: Read>(
    hasher: &mut Sha1,
    reader: &mut R,
    len: u64,
    buf: &mut [u8; HASH_BUFFER_BYTES],
) -> crate::Result<()> {
    // `buf.len()` rather than the const so the chunk size derives from
    // the buffer's actual capacity. Today they're identical (the type
    // guarantees `buf.len() == HASH_BUFFER_BYTES`), but if the signature
    // is ever generalised to a const-generic `<const N: usize>` the
    // const reference would silently cap at 8 KiB regardless of the
    // passed buffer.
    let mut remaining = len;
    while remaining > 0 {
        let want = remaining.min(buf.len() as u64) as usize;
        reader.read_exact(&mut buf[..want])?;
        hasher.update(&buf[..want]);
        remaining -= want as u64;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    /// The `locked()` helper recovers from a poisoned mutex
    /// via `PoisonError::into_inner`. The safety contract is "every
    /// caller MUST seek before its first read" — encoded in production
    /// by every existing call site. Pin that poisoning the mutex (by
    /// panicking while holding the guard) doesn't break subsequent
    /// reads: the high-level `read_entry` path seeks unconditionally
    /// via `open_entry_into`, so it must return correct bytes against
    /// the pre-poison baseline.
    ///
    /// This test lives in `pak/mod.rs` (not `tests/pak_integration.rs`)
    /// because `locked()` is private to the module; integration tests
    /// can't reach it. Poisoning via a real public API would require
    /// triggering a panic inside a `locked()`-guarded read path, which
    /// is brittle to wire up — direct access is the cleaner route.
    #[test]
    fn locked_recovers_from_poisoned_mutex() {
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/real_v11_minimal.pak");
        let reader = Arc::new(PakReader::open(&fixture).unwrap());
        let path = reader.entries().next().unwrap().path.clone();
        let expected = reader.read_entry(&path).unwrap();

        // Poison the mutex: spawn a thread that acquires the guard
        // then panics. After joining, the mutex is in PoisonError
        // state; `Mutex::lock()` would return `Err(PoisonError)`
        // forever after, but `locked()` recovers via `into_inner`.
        let r2 = Arc::clone(&reader);
        let handle = std::thread::spawn(move || {
            let _guard = r2.locked();
            panic!("deliberately poison the mutex for test");
        });
        let join_result = handle.join();
        assert!(
            join_result.is_err(),
            "poisoning thread must panic to set the mutex's poison flag"
        );

        // Verify the mutex is actually poisoned now — guards against
        // a future change where Mutex stops being poisonable (e.g.,
        // if we ever switched to parking_lot's non-poisoning Mutex).
        assert!(
            reader.file.is_poisoned(),
            "mutex should be poisoned after the thread panic"
        );

        // The post-poison read must succeed and return bytes-identical
        // output to the pre-poison baseline. If `locked()` propagated
        // the poison via `unwrap()` instead of `unwrap_or_else(into_inner)`,
        // this would panic. If the safety contract were violated (some
        // caller skipped the pre-read seek), the cursor would be at
        // wherever the panicked thread left off and the read would
        // return wrong bytes.
        let actual = reader.read_entry(&path).unwrap();
        assert_eq!(
            actual, expected,
            "read_entry after poison must return bytes-identical output to pre-poison baseline"
        );
    }

    /// Issue #45 contract pin: `feed_hasher` and `sha1_of_reader` take
    /// `&mut [u8; HASH_BUFFER_BYTES]` — a fixed-size array reference —
    /// so the empty-buffer case is structurally unrepresentable.
    /// Pre-fix the buffer was `&mut [u8]` and an empty buffer would
    /// loop forever consuming zero bytes per iteration; the only
    /// guard was a `debug_assert!` stripped in release builds.
    ///
    /// This test passes by *compiling*: the buffer must be exactly
    /// `[u8; HASH_BUFFER_BYTES]` to be accepted. The body pins the
    /// canonical SHA1 of the lowercase pangram (no trailing period)
    /// so a future regression in `feed_hasher` — e.g., an off-by-one
    /// in the read loop, or a wrong slice bound — fails here rather
    /// than silently producing the wrong digest.
    ///
    /// The expected digest is hardcoded rather than computed via
    /// `Sha1::digest(payload)` deliberately. If the `sha1` crate
    /// shipped a regression, both `feed_hasher` and `Sha1::digest`
    /// would call the same broken update/finalize path and produce
    /// matching wrong digests — the pin against the well-known
    /// public test vector catches that class of dependency
    /// regression.
    #[test]
    fn feed_hasher_pins_canonical_sha1_for_pangram() {
        let mut buf = [0u8; HASH_BUFFER_BYTES];
        let mut hasher = Sha1::new();
        let payload = b"the quick brown fox jumps over the lazy dog";
        let mut reader: &[u8] = payload;
        feed_hasher(&mut hasher, &mut reader, payload.len() as u64, &mut buf).unwrap();
        let actual: [u8; 20] = hasher.finalize().into();
        assert_eq!(
            Sha1Digest::from(actual).to_string(),
            "16312751ef9307c3fd1afbcb993cdc80464ba0f1",
            "feed_hasher must produce the canonical SHA1 digest"
        );
    }

    /// `feed_hasher` with `len: 0` must not invoke `read` on the
    /// reader at all. Pre-PR-#45 the implementation looped while
    /// `remaining > 0` — correct shape — but the test only verified
    /// the resulting digest matched the empty-input SHA1. That same
    /// digest would also be produced if the loop entered once,
    /// called `read_exact(&mut buf[..0])` (which is a no-op
    /// `Ok(())`), and then exited; the test wouldn't catch a
    /// regression that did exactly that.
    ///
    /// `PoisonReader` panics on any `read` call, so this test fails
    /// loudly on any future code that touches the reader when
    /// `len == 0`.
    #[test]
    fn feed_hasher_zero_length_does_not_call_read() {
        struct PoisonReader;
        impl Read for PoisonReader {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                panic!("feed_hasher must not call read() when len == 0");
            }
        }
        let mut buf = [0u8; HASH_BUFFER_BYTES];
        let mut hasher = Sha1::new();
        feed_hasher(&mut hasher, &mut PoisonReader, 0, &mut buf).unwrap();
        // SHA1 of the empty input — canonical reference value.
        let actual: [u8; 20] = hasher.finalize().into();
        assert_eq!(
            Sha1Digest::from(actual).to_string(),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
    }

    /// `feed_hasher` must correctly handle payloads larger than
    /// `HASH_BUFFER_BYTES` — i.e., the multi-iteration loop branch.
    /// Pre-fix coverage: the existing pangram test (43 bytes) and the
    /// integration tests against real fixtures (variable-size) both
    /// fit in a single iteration, leaving the
    /// `remaining > buf.len()` boundary untested directly. A future
    /// off-by-one in `remaining -= want as u64` (e.g., an accidental
    /// `+=`, or `remaining -= want as u64 - 1`) would slip past the
    /// short-payload tests but corrupt multi-block hashes.
    ///
    /// Uses `Sha1::digest(payload)` as the oracle — independent
    /// computation against the same input is the right shape for
    /// catching feed_hasher-specific bugs (off-by-one, wrong slice
    /// bound). The dependency-regression class is covered by the
    /// hardcoded-digest pin in
    /// `feed_hasher_pins_canonical_sha1_for_pangram`.
    #[test]
    fn feed_hasher_handles_multi_iteration_payloads() {
        // 3 full iterations + 17-byte remainder — exercises both the
        // full-buffer chunk branch and the partial-final-chunk branch.
        let payload_len = HASH_BUFFER_BYTES * 3 + 17;
        let payload: Vec<u8> = (0..payload_len).map(|i| (i % 251) as u8).collect();
        let mut buf = [0u8; HASH_BUFFER_BYTES];
        let mut hasher = Sha1::new();
        let mut reader: &[u8] = &payload;
        feed_hasher(&mut hasher, &mut reader, payload.len() as u64, &mut buf).unwrap();
        let actual: [u8; 20] = hasher.finalize().into();
        let expected: [u8; 20] = Sha1::digest(&payload).into();
        assert_eq!(
            actual, expected,
            "multi-iteration feed_hasher digest must match independent Sha1::digest oracle"
        );
    }
}
