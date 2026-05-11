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
//!   each payload at [`crate::container::pak::index::PakIndexEntry::offset`],
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

use std::fmt::Write as _;
use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Mutex;

use flate2::read::ZlibDecoder;
use sha1::{Digest, Sha1};
use tracing::{debug, error, warn};

use crate::container::{ContainerFormat, ContainerReader, EntryMetadata};
use crate::error::{HashTarget, PaksmithError};

use self::footer::PakFooter;
use self::index::{CompressionMethod, PakEntryHeader, PakIndex, PakIndexEntry};
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

/// Public accessor for [`MAX_UNCOMPRESSED_ENTRY_BYTES`]. The cap is an
/// implementation detail of the parser — tests that care about the boundary
/// should read it from here rather than duplicating the literal.
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
/// Entry metadata is materialized lazily from `index` via the
/// [`ContainerReader::entries`] iterator — there is no
/// `Vec<EntryMetadata>` cache alongside the parsed index.
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
    /// Rejects v8+ archives whose index layout is not yet implemented; see the
    /// module-level docs for the full Phase 1.5 scope.
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
                version: footer.version() as u32,
            });
        }

        // v1/v2 entry records have a different shape (timestamp field
        // pre-v2, no trailing flags+block_size). PakEntryHeader::read_from
        // assumes the v3+ layout. We have no fixtures for v1/v2 and
        // they're rare in the wild, so reject explicitly rather than
        // silently misparse.
        if footer.version() < PakVersion::CompressionEncryption {
            return Err(PaksmithError::UnsupportedVersion {
                version: footer.version() as u32,
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
            footer.compression_methods(),
        )?;
        // Drop the BufReader's borrow so we can move `file` into the
        // Mutex. The BufReader is throwaway — entry reads will create
        // fresh BufReaders against the locked File handle.
        drop(buffered);

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
        !is_zero_sha1(self.footer.index_hash())
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
        if is_zero_sha1(self.footer.index_hash()) {
            debug!("index has no recorded SHA1; skipping verification");
            return Ok(VerifyOutcome::SkippedNoHash);
        }
        let guard = self.locked();
        let mut file = BufReader::new(&*guard);
        let _ = file.seek(SeekFrom::Start(self.footer.index_offset()))?;
        let mut buf = vec![0u8; HASH_BUFFER_BYTES];
        let actual = sha1_of_reader(&mut file, self.footer.index_size(), &mut buf)?;
        if actual != *self.footer.index_hash() {
            let expected = hex(self.footer.index_hash());
            let actual_hex = hex(&actual);
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
    /// (only the in-data record carries it; see
    /// [`crate::container::pak::index::PakEntryHeader::omits_sha1`]).
    /// Such entries always surface as `Ok(SkippedNoHash)` regardless
    /// of the archive's index hash — there's no "stripped" state to
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
    ///   Oodle, Unknown). We refuse to hash arbitrary bytes that we can't
    ///   interpret; doing otherwise risks reporting a misleading
    ///   `HashMismatch` for a well-formed archive in a method we don't
    ///   support yet.
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

        // Encryption check first: if the bytes at entry.offset() are
        // ciphertext, hashing them is meaningless. This priority is
        // intentional — an encrypted-AND-zero-hash entry reports as
        // SkippedEncrypted, not SkippedNoHash, because encryption is the
        // stronger reason we can't verify.
        if entry.is_encrypted() {
            debug!(path, "entry is encrypted; skipping SHA1 verification");
            return Ok(VerifyOutcome::SkippedEncrypted);
        }

        if is_zero_sha1(entry.sha1()) {
            // V10+ encoded entries have NO sha1 field on the wire (the
            // bit-packed `FPakEntry::EncodeTo` format omits it; only the
            // in-data record carries one). They surface here with
            // `sha1 = [0u8; 20]` and `omits_sha1 = true`. Distinguishing
            // the two cases is critical:
            //
            //   - omits_sha1 = true  → no integrity claim was made for
            //     this entry's index header. Always SkippedNoHash, even
            //     when the archive's index_hash is non-zero. (Without
            //     this gate, every encoded entry on a v10+ pak that
            //     opted into archive-wide integrity hashing would
            //     false-positive as a tampering attack.)
            //   - omits_sha1 = false → the entry HAS a sha1 field and
            //     it was set to zeros. If the archive opts into
            //     integrity (non-zero index_hash), this is a tampering
            //     signal we want to surface; otherwise it's a
            //     legitimate "no integrity recorded" case.
            if !entry.omits_sha1() && self.archive_claims_integrity() {
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
        let mut buf = vec![0u8; HASH_BUFFER_BYTES];

        let actual = match entry.compression_method() {
            CompressionMethod::None => {
                sha1_of_reader(&mut file, entry.uncompressed_size(), &mut buf)?
            }
            CompressionMethod::Zlib => {
                // Hash the on-disk compressed bytes block-by-block. Block
                // offsets are relative to entry.offset() (v5+ convention,
                // already enforced in stream_zlib_to).
                let payload_start =
                    entry
                        .offset()
                        .checked_add(in_data.wire_size())
                        .ok_or_else(|| PaksmithError::InvalidIndex {
                            reason: format!("entry `{path}` offset+header overflows u64"),
                        })?;
                let mut hasher = Sha1::new();
                for (i, block) in entry.compression_blocks().iter().enumerate() {
                    let abs_start = entry.offset().checked_add(block.start()).ok_or_else(|| {
                        PaksmithError::InvalidIndex {
                            reason: format!("entry `{path}` block {i} start overflows u64"),
                        }
                    })?;
                    let abs_end = entry.offset().checked_add(block.end()).ok_or_else(|| {
                        PaksmithError::InvalidIndex {
                            reason: format!("entry `{path}` block {i} end overflows u64"),
                        }
                    })?;
                    if abs_start < payload_start {
                        return Err(PaksmithError::InvalidIndex {
                            reason: format!(
                                "entry `{path}` block {i} start {abs_start} overlaps in-data header (payload starts at {payload_start})"
                            ),
                        });
                    }
                    if abs_end > self.file_size {
                        return Err(PaksmithError::InvalidIndex {
                            reason: format!(
                                "entry `{path}` block {i} end {abs_end} exceeds file_size {}",
                                self.file_size
                            ),
                        });
                    }
                    let _ = file.seek(SeekFrom::Start(abs_start))?;
                    feed_hasher(&mut hasher, &mut file, block.len(), &mut buf)?;
                }
                let mut out = [0u8; 20];
                out.copy_from_slice(&hasher.finalize());
                out
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
                    offset: entry.offset(),
                    reason: format!("unsupported compression method {method:?}"),
                });
            }
        };

        if actual != *entry.sha1() {
            let expected = hex(entry.sha1());
            let actual_hex = hex(&actual);
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
        match self.verify_index()? {
            VerifyOutcome::Verified => stats.index_verified = true,
            VerifyOutcome::SkippedNoHash => stats.index_skipped_no_hash = true,
            // verify_index has no encrypted-index concept today, so this
            // arm shouldn't be reachable. Surface it as a typed error
            // rather than panicking — CLAUDE.md says no panics in core.
            VerifyOutcome::SkippedEncrypted => {
                return Err(PaksmithError::InvalidIndex {
                    reason: "verify_index returned SkippedEncrypted \
                             (internal invariant violated)"
                        .into(),
                });
            }
        }
        for entry in self.index.entries() {
            match self.verify_entry(entry.filename())? {
                VerifyOutcome::Verified => stats.entries_verified += 1,
                VerifyOutcome::SkippedNoHash => stats.entries_skipped_no_hash += 1,
                VerifyOutcome::SkippedEncrypted => stats.entries_skipped_encrypted += 1,
            }
        }
        if stats.index_skipped_no_hash
            || stats.entries_skipped_encrypted > 0
            || stats.entries_skipped_no_hash > 0
        {
            warn!(
                index_skipped = stats.index_skipped_no_hash,
                encrypted = stats.entries_skipped_encrypted,
                no_hash = stats.entries_skipped_no_hash,
                verified = stats.entries_verified,
                "verify(): some bytes were not hashed; inspect VerifyStats"
            );
        }
        Ok(stats)
    }

    /// Position `reader` at `entry.offset()`, parse the in-data FPakEntry
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

        if entry.offset() >= self.file_size {
            return Err(PaksmithError::InvalidIndex {
                reason: format!(
                    "entry `{path}` offset {} >= file_size {}",
                    entry.offset(),
                    self.file_size
                ),
            });
        }

        let _ = reader.seek(SeekFrom::Start(entry.offset()))?;
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
        // header mismatch" surfaces when the bytes at entry.offset() are
        // actually ciphertext (encrypted entry) rather than a real
        // FPakEntry.
        if entry.is_encrypted() {
            return Err(PaksmithError::Decryption {
                path: path.to_string(),
            });
        }
        match entry.compression_method() {
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
                    offset: entry.offset(),
                    reason: format!("unsupported compression method {method:?}"),
                });
            }
        }

        // Cap the size against a sane ceiling before doing any I/O.
        // Streaming means peak memory is a per-block scratch buffer
        // (compressed: bounded by `compression_block_size`; uncompressed:
        // bounded by `io::copy`'s internal buffer), but the cap still
        // serves as an "obviously malformed index" guard so callers
        // don't waste disk/network bandwidth on a multi-TB nonsense entry.
        let uncompressed_size = entry.uncompressed_size();
        if uncompressed_size > MAX_UNCOMPRESSED_ENTRY_BYTES {
            return Err(PaksmithError::InvalidIndex {
                reason: format!(
                    "entry `{path}` uncompressed_size {uncompressed_size} \
                     exceeds maximum {MAX_UNCOMPRESSED_ENTRY_BYTES}"
                ),
            });
        }

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
            .offset()
            .checked_add(in_data.wire_size())
            .ok_or_else(|| PaksmithError::InvalidIndex {
                reason: format!("entry `{path}` offset+header overflows u64"),
            })?;

        match entry.compression_method() {
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
            // Already rejected above; unreachable in practice but keep
            // the match exhaustive without an opaque _ arm.
            CompressionMethod::Gzip
            | CompressionMethod::Oodle
            | CompressionMethod::Zstd
            | CompressionMethod::Lz4
            | CompressionMethod::Unknown(_)
            | CompressionMethod::UnknownByName(_) => {
                unreachable!(
                    "unsupported compression method should have been rejected at the top of stream_entry_to"
                )
            }
        }
    }
}

impl ContainerReader for PakReader {
    fn entries(&self) -> Box<dyn Iterator<Item = EntryMetadata> + '_> {
        Box::new(self.index.entries().iter().map(|e| EntryMetadata {
            path: e.filename().to_owned(),
            compressed_size: e.compressed_size(),
            uncompressed_size: e.uncompressed_size(),
            is_compressed: *e.compression_method() != CompressionMethod::None,
            is_encrypted: e.is_encrypted(),
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

        let uncompressed_size = entry.uncompressed_size();
        // Cap-check BEFORE reserving — a malformed index claiming a
        // multi-TB size shouldn't trigger a multi-TB `try_reserve_exact`
        // call (which would either succeed and waste memory briefly, or
        // fail with a confusing OOM message instead of the precise
        // "exceeds maximum" diagnostic). Mirrors the same check in
        // `stream_entry_to`; lifting it here also makes the cap reachable
        // in this code path (otherwise it'd be dead under `read_entry`
        // because `try_reserve_exact` rejects first on most hosts).
        if uncompressed_size > MAX_UNCOMPRESSED_ENTRY_BYTES {
            return Err(PaksmithError::InvalidIndex {
                reason: format!(
                    "entry `{path}` uncompressed_size {uncompressed_size} \
                     exceeds maximum {MAX_UNCOMPRESSED_ENTRY_BYTES}"
                ),
            });
        }
        let size_usize =
            usize::try_from(uncompressed_size).map_err(|_| PaksmithError::InvalidIndex {
                reason: format!("entry `{path}` size {uncompressed_size} exceeds platform usize"),
            })?;

        // Allocate fallibly upfront so a legitimate-but-large entry on a
        // memory-constrained host surfaces as a typed error rather than an
        // allocator abort during the streaming write.
        let mut buf: Vec<u8> = Vec::new();
        buf.try_reserve_exact(size_usize).map_err(|e| {
            warn!(path, size = size_usize, error = %e, "output reservation failed");
            PaksmithError::InvalidIndex {
                reason: format!("could not reserve {size_usize} bytes for `{path}`: {e}"),
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
    let size = entry.uncompressed_size();

    // For uncompressed entries the payload immediately follows the in-data
    // header, so the reader is already positioned correctly. Bounds-check
    // the payload against EOF before reading.
    let payload_end =
        file.stream_position()?
            .checked_add(size)
            .ok_or_else(|| PaksmithError::InvalidIndex {
                reason: format!("entry `{path}` payload end overflows u64"),
            })?;
    if payload_end > file_size {
        return Err(PaksmithError::InvalidIndex {
            reason: format!(
                "entry `{path}` payload extends past EOF: end={payload_end} file_size={file_size}"
            ),
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
            reason: format!("entry `{path}` short read: wrote {written} of {size} expected bytes"),
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
            version: version as u32,
        });
    }

    let uncompressed_size = entry.uncompressed_size();
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

    for (i, block) in entry.compression_blocks().iter().enumerate() {
        // v5+ block offsets are relative to entry.offset(), and must point
        // past the in-data header into the payload region.
        let abs_start = entry.offset().checked_add(block.start()).ok_or_else(|| {
            PaksmithError::InvalidIndex {
                reason: format!("entry `{path}` block {i} start overflows u64"),
            }
        })?;
        let abs_end =
            entry
                .offset()
                .checked_add(block.end())
                .ok_or_else(|| PaksmithError::InvalidIndex {
                    reason: format!("entry `{path}` block {i} end overflows u64"),
                })?;
        if abs_start < payload_start {
            return Err(PaksmithError::InvalidIndex {
                reason: format!(
                    "entry `{path}` block {i} start {abs_start} overlaps in-data header (payload starts at {payload_start})"
                ),
            });
        }
        if abs_end > file_size {
            return Err(PaksmithError::InvalidIndex {
                reason: format!(
                    "entry `{path}` block {i} end {abs_end} exceeds file_size {file_size}"
                ),
            });
        }

        let block_len = block.len();
        let block_len_usize =
            usize::try_from(block_len).map_err(|_| PaksmithError::InvalidIndex {
                reason: format!("entry `{path}` block {i} length {block_len} exceeds usize"),
            })?;

        let _ = file.seek(SeekFrom::Start(abs_start))?;
        // Per-block compressed buffer is bounded by file_size (via the
        // abs_end check above). Allocate fallibly so OOM is typed.
        let mut compressed: Vec<u8> = Vec::new();
        compressed.try_reserve_exact(block_len_usize).map_err(|e| {
            warn!(path, block = i, block_len, error = %e, "zlib block reservation failed");
            PaksmithError::Decompression {
                path: path.to_string(),
                offset: abs_start,
                reason: format!("could not reserve {block_len_usize} bytes for block {i}: {e}"),
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
                    reason: format!("zlib block {i}: {e}"),
                }
            })?;
            if n == 0 {
                break block_out.len();
            }
            block_out
                .try_reserve(n)
                .map_err(|e| PaksmithError::Decompression {
                    path: path.to_string(),
                    offset: abs_start,
                    reason: format!(
                        "could not reserve {n} more bytes for zlib block {i} \
                         (block_out.len() = {}): {e}",
                        block_out.len()
                    ),
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
                reason: format!(
                    "block {i} pushed total to {new_total} bytes, exceeding uncompressed_size {uncompressed_size}"
                ),
            });
        }

        // Sanity: every block except possibly the last should produce exactly
        // compression_block_size bytes when decompressed.
        if i + 1 < entry.compression_blocks().len()
            && written as u64 != u64::from(entry.compression_block_size())
        {
            let expected = entry.compression_block_size();
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
                reason: format!(
                    "non-final block {i} decompressed to {written} bytes, expected {expected}"
                ),
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
            offset: entry.offset(),
            reason: format!("decompressed {bytes_written} bytes, expected {uncompressed_size}"),
        });
    }

    Ok(bytes_written)
}

/// Default scratch-buffer size for streaming SHA1 computation. Sized to
/// match `BufReader`'s default capacity so we don't fragment reads against
/// the underlying buffered reader. Heap-allocated.
const HASH_BUFFER_BYTES: usize = 8 * 1024;

/// SHA1 fixture for the all-zero hash slot. UE writers leave this 20-byte
/// region zero-filled when integrity hashing is not enabled at archive
/// creation time, so a zero hash means "no integrity claim recorded," not
/// "stored hash is the zero digest" (which would be cryptographically
/// nearly impossible anyway).
const ZERO_SHA1: [u8; 20] = [0u8; 20];

/// Whether `hash` is the all-zero sentinel used by UE to mean "no
/// integrity claim recorded."
fn is_zero_sha1(hash: &[u8; 20]) -> bool {
    hash == &ZERO_SHA1
}

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

/// Structured report from [`PakReader::verify`]: counts of what was
/// actually hashed vs skipped, so callers can distinguish "fully verified"
/// from "verification ran but skipped some entries we couldn't check."
///
/// Marked `#[non_exhaustive]` to allow future fields (e.g., a count of
/// entries with detected I/O errors during partial-archive recovery)
/// without breaking downstream pattern-matchers. Construct via
/// `VerifyStats { ..Default::default() }` if you need an explicit instance
/// in tests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerifyStats {
    /// True if the index hash was computed and matched.
    pub index_verified: bool,
    /// True if the index had no recorded hash (zeroed slot).
    pub index_skipped_no_hash: bool,
    /// Number of entries whose hash was computed and matched.
    pub entries_verified: usize,
    /// Number of entries skipped because the stored SHA1 was the all-zero
    /// sentinel (no integrity claim recorded at write time).
    pub entries_skipped_no_hash: usize,
    /// Number of entries skipped because they are AES-encrypted.
    pub entries_skipped_encrypted: usize,
}

impl VerifyStats {
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
    pub fn is_fully_verified(&self) -> bool {
        self.index_verified
            && !self.index_skipped_no_hash
            && self.entries_skipped_no_hash == 0
            && self.entries_skipped_encrypted == 0
            && self.entries_verified > 0
    }
}

/// Read exactly `len` bytes from `reader` and return the SHA1 digest.
/// `buf` is the caller-owned scratch buffer ([`HASH_BUFFER_BYTES`] is the
/// recommended size); reusing one buffer across calls avoids reallocating
/// per invocation in the multi-block hashing path.
fn sha1_of_reader<R: Read>(reader: &mut R, len: u64, buf: &mut [u8]) -> crate::Result<[u8; 20]> {
    let mut hasher = Sha1::new();
    feed_hasher(&mut hasher, reader, len, buf)?;
    let mut out = [0u8; 20];
    out.copy_from_slice(&hasher.finalize());
    Ok(out)
}

/// Append exactly `len` bytes from `reader` into the running `hasher`,
/// using `buf` as the per-iteration scratch buffer. Caller owns `buf` so
/// multi-call sequences (e.g., per-block hashing in
/// [`PakReader::verify_entry`]) can amortise its allocation.
fn feed_hasher<R: Read>(
    hasher: &mut Sha1,
    reader: &mut R,
    len: u64,
    buf: &mut [u8],
) -> crate::Result<()> {
    debug_assert!(!buf.is_empty(), "scratch buffer must be non-empty");
    let mut remaining = len;
    while remaining > 0 {
        let want = remaining.min(buf.len() as u64) as usize;
        reader.read_exact(&mut buf[..want])?;
        hasher.update(&buf[..want]);
        remaining -= want as u64;
    }
    Ok(())
}

/// Lowercase hex encoding of a byte slice. Used only in error messages and
/// log fields, never in cryptographic comparisons.
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    /// The `locked()` helper at line 213 recovers from a poisoned mutex
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
}
