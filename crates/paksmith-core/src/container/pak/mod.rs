//! Unreal Engine `.pak` archive reader.
//!
//! # Phase 1.5 scope
//!
//! This reader implements:
//! - Footer parsing for v1–v11 paks (rejects v8+ at [`PakReader::open`]).
//! - Flat-entry index layout matching the v3-era on-disk format.
//! - The duplicate FPakEntry record header that real archives write before
//!   each payload at [`crate::container::pak::index::PakIndexEntry::offset`],
//!   with cross-validation against the index entry.
//! - Zlib decompression for v5+ archives (block offsets are relative to the
//!   entry record start).
//!
//! - SHA1 verification of the index and per-entry stored bytes via opt-in
//!   [`PakReader::verify_index`], [`PakReader::verify_entry`], and
//!   [`PakReader::verify`]. Verification is opt-in to keep list-only
//!   workloads from paying the cost.
//!
//! It does NOT yet handle:
//! - The FName-based compression-method indirection introduced in v8 (#7).
//! - The path-hash + encoded-directory index introduced in v10 (#7).
//! - AES decryption of the index or of individual entries.
//! - Gzip / Oodle compression — only zlib is wired up.
//! - Pre-v5 absolute-offset compression blocks (rare in real archives).
//!
//! # File-immutability assumption
//!
//! [`PakReader`] caches the file size at [`PakReader::open`] time and reopens
//! the underlying file on each [`PakReader::read_entry`] call. The reader
//! assumes the underlying file is immutable for its lifetime — a file that
//! shrinks between `open` and `read_entry` will produce a misleading
//! [`PaksmithError::Io`] (UnexpectedEof) rather than a typed integrity error,
//! and a file that grows or is replaced will silently read different bytes
//! than the cached index describes. Tracked in issue #8 alongside the planned
//! single-handle redesign.

pub mod footer;
pub mod index;
pub mod version;

use std::fmt::Write as _;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

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
#[derive(Debug)]
pub struct PakReader {
    path: std::path::PathBuf,
    file_size: u64,
    footer: PakFooter,
    index: PakIndex,
    // INVARIANT: `entries` is a derived projection of `index.entries()` built
    // once in `open()`. Both are read-only after construction. Tracked for
    // collapsing into a single source of truth in issue #8.
    entries: Vec<EntryMetadata>,
}

impl PakReader {
    /// Open and parse a `.pak` file at the given path.
    ///
    /// Rejects v8+ archives whose index layout is not yet implemented; see the
    /// module-level docs for the full Phase 1.5 scope.
    pub fn open<P: AsRef<Path>>(path: P) -> crate::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mut file = BufReader::new(File::open(&path)?);
        let file_size = file.seek(SeekFrom::End(0))?;

        let footer = PakFooter::read_from(&mut file)?;

        if footer.is_encrypted() {
            return Err(PaksmithError::Decryption {
                path: path.display().to_string(),
            });
        }

        if footer.version() >= PakVersion::FNameBasedCompression {
            return Err(PaksmithError::UnsupportedVersion {
                version: footer.version() as u32,
            });
        }

        let _ = file.seek(SeekFrom::Start(footer.index_offset()))?;
        let index = PakIndex::read_from(&mut file, footer.version(), footer.index_size())?;

        let entries = index
            .entries()
            .iter()
            .map(|e| EntryMetadata {
                path: e.filename().to_owned(),
                compressed_size: e.compressed_size(),
                uncompressed_size: e.uncompressed_size(),
                is_compressed: e.compression_method() != CompressionMethod::None,
                is_encrypted: e.is_encrypted(),
            })
            .collect();

        Ok(Self {
            path,
            file_size,
            footer,
            index,
            entries,
        })
    }

    /// The pak format version of this archive.
    pub fn version(&self) -> PakVersion {
        self.footer.version()
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
    /// Opt-in: not called by [`PakReader::open`] because hashing the index
    /// is an extra full-index read that list-only callers don't need to
    /// pay for.
    pub fn verify_index(&self) -> crate::Result<VerifyOutcome> {
        if is_zero_sha1(self.footer.index_hash()) {
            debug!("index has no recorded SHA1; skipping verification");
            return Ok(VerifyOutcome::SkippedNoHash);
        }
        let mut file = BufReader::new(File::open(&self.path)?);
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
    pub fn verify_entry(&self, path: &str) -> crate::Result<VerifyOutcome> {
        let entry = self
            .index
            .find(path)
            .ok_or_else(|| PaksmithError::EntryNotFound {
                path: path.to_string(),
            })?;

        if entry.is_encrypted() {
            debug!(path, "entry is encrypted; skipping SHA1 verification");
            return Ok(VerifyOutcome::SkippedEncrypted);
        }

        if is_zero_sha1(entry.sha1()) {
            debug!(path, "entry has no recorded SHA1; skipping verification");
            return Ok(VerifyOutcome::SkippedNoHash);
        }

        let (mut file, in_data) = self.open_entry(entry)?;

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
                // already enforced in read_zlib).
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
            | CompressionMethod::Unknown(_)) => {
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
            // verify_index never returns SkippedEncrypted (the index is
            // not an entry). Treat as a programming error if we ever do.
            VerifyOutcome::SkippedEncrypted => {
                unreachable!("verify_index does not produce SkippedEncrypted");
            }
        }
        for entry in self.index.entries() {
            match self.verify_entry(entry.filename())? {
                VerifyOutcome::Verified => stats.entries_verified += 1,
                VerifyOutcome::SkippedNoHash => stats.entries_skipped_no_hash += 1,
                VerifyOutcome::SkippedEncrypted => stats.entries_skipped_encrypted += 1,
            }
        }
        if stats.entries_skipped_encrypted > 0 || stats.entries_skipped_no_hash > 0 {
            warn!(
                encrypted = stats.entries_skipped_encrypted,
                no_hash = stats.entries_skipped_no_hash,
                "verify(): some entries were not hashed; inspect VerifyStats"
            );
        }
        Ok(stats)
    }

    /// Read the in-data FPakEntry header, validate it against the index entry,
    /// and return both the file (positioned at the start of the payload) and
    /// the parsed in-data header.
    ///
    /// Bounds-checks the entry offset against [`Self::file_size`] before
    /// allocating or seeking, so a malformed pak can't trigger OOM or read
    /// past EOF undetected.
    fn open_entry(
        &self,
        entry: &PakIndexEntry,
    ) -> crate::Result<(BufReader<File>, PakEntryHeader)> {
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

        let mut file = BufReader::new(File::open(&self.path)?);
        let _ = file.seek(SeekFrom::Start(entry.offset()))?;
        let in_data = PakEntryHeader::read_from(&mut file)?;

        entry.header().matches_payload(&in_data, path)?;
        Ok((file, in_data))
    }
}

impl ContainerReader for PakReader {
    fn list_entries(&self) -> &[EntryMetadata] {
        &self.entries
    }

    fn read_entry(&self, path: &str) -> crate::Result<Vec<u8>> {
        let entry = self
            .index
            .find(path)
            .ok_or_else(|| PaksmithError::EntryNotFound {
                path: path.to_string(),
            })?;

        // Reject what we definitely can't handle BEFORE opening the file or
        // parsing the in-data header. Otherwise a misleading "in-data header
        // mismatch" surfaces when the bytes at entry.offset() are actually
        // ciphertext (encrypted entry) rather than a real FPakEntry.
        if entry.is_encrypted() {
            return Err(PaksmithError::Decryption {
                path: path.to_string(),
            });
        }
        match entry.compression_method() {
            CompressionMethod::None | CompressionMethod::Zlib => {}
            method @ (CompressionMethod::Gzip
            | CompressionMethod::Oodle
            | CompressionMethod::Unknown(_)) => {
                warn!(path, ?method, "rejected unsupported compression method");
                return Err(PaksmithError::Decompression {
                    path: path.to_string(),
                    offset: entry.offset(),
                    reason: format!("unsupported compression method {method:?}"),
                });
            }
        }

        // Cap allocation against a sane ceiling before doing any I/O.
        let uncompressed_size = entry.uncompressed_size();
        if uncompressed_size > MAX_UNCOMPRESSED_ENTRY_BYTES {
            return Err(PaksmithError::InvalidIndex {
                reason: format!(
                    "entry `{path}` uncompressed_size {uncompressed_size} \
                     exceeds maximum {MAX_UNCOMPRESSED_ENTRY_BYTES}"
                ),
            });
        }

        let (mut file, in_data) = self.open_entry(entry)?;
        // After open_entry, `file` is positioned just past the in-data
        // FPakEntry record. Use the parsed in-data header's wire_size as the
        // single source of truth for the payload start, so any future change
        // to the wire format only needs updating in PakEntryHeader::read_from
        // (which `wire_size` mirrors by construction).
        let payload_start = entry
            .offset()
            .checked_add(in_data.wire_size())
            .ok_or_else(|| PaksmithError::InvalidIndex {
                reason: format!("entry `{path}` offset+header overflows u64"),
            })?;

        match entry.compression_method() {
            CompressionMethod::None => read_uncompressed(&mut file, entry, self.file_size),
            CompressionMethod::Zlib => read_zlib(
                &mut file,
                entry,
                self.file_size,
                payload_start,
                self.version(),
            ),
            // Already rejected above; unreachable in practice but keep the
            // match exhaustive without an opaque _ arm.
            CompressionMethod::Gzip | CompressionMethod::Oodle | CompressionMethod::Unknown(_) => {
                unreachable!(
                    "unsupported compression method should have been rejected at the top of read_entry"
                )
            }
        }
    }

    fn format(&self) -> ContainerFormat {
        ContainerFormat::Pak
    }

    fn mount_point(&self) -> &str {
        self.index.mount_point()
    }
}

fn read_uncompressed(
    file: &mut BufReader<File>,
    entry: &PakIndexEntry,
    file_size: u64,
) -> crate::Result<Vec<u8>> {
    let path = entry.filename();
    let size =
        usize::try_from(entry.uncompressed_size()).map_err(|_| PaksmithError::InvalidIndex {
            reason: format!(
                "entry `{path}` size {} exceeds platform usize",
                entry.uncompressed_size()
            ),
        })?;

    // For uncompressed entries the payload immediately follows the in-data
    // header, so the reader is already positioned correctly. Bounds-check the
    // payload against EOF before allocating.
    let payload_end = file
        .stream_position()?
        .checked_add(entry.uncompressed_size())
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

    // Allocate fallibly so a legitimate-but-large entry on a memory-constrained
    // host surfaces as a typed error rather than an allocator abort.
    let mut buf: Vec<u8> = Vec::new();
    buf.try_reserve_exact(size).map_err(|e| {
        warn!(path, size, error = %e, "uncompressed output reservation failed");
        PaksmithError::InvalidIndex {
            reason: format!("could not reserve {size} bytes for `{path}`: {e}"),
        }
    })?;
    buf.resize(size, 0);
    file.read_exact(&mut buf)?;
    Ok(buf)
}

#[allow(clippy::too_many_lines)] // bounded by the per-block error-reporting branches
fn read_zlib(
    file: &mut BufReader<File>,
    entry: &PakIndexEntry,
    file_size: u64,
    payload_start: u64,
    version: PakVersion,
) -> crate::Result<Vec<u8>> {
    let path = entry.filename();

    if version < PakVersion::RelativeChunkOffsets {
        // Pre-v5 paks store absolute file offsets in compression_blocks rather
        // than offsets relative to the entry record. Real-world v3/v4 paks are
        // rare; reject explicitly rather than silently producing garbage.
        return Err(PaksmithError::UnsupportedVersion {
            version: version as u32,
        });
    }

    let uncompressed_size =
        usize::try_from(entry.uncompressed_size()).map_err(|_| PaksmithError::InvalidIndex {
            reason: format!(
                "entry `{path}` size {} exceeds platform usize",
                entry.uncompressed_size()
            ),
        })?;

    // Allocate fallibly. The MAX_UNCOMPRESSED_ENTRY_BYTES cap in read_entry
    // already keeps this reasonable; this guard catches the residual case
    // where the host doesn't actually have that much memory available, so we
    // surface a typed error instead of an allocator abort.
    let mut out: Vec<u8> = Vec::new();
    out.try_reserve_exact(uncompressed_size).map_err(|e| {
        warn!(path, uncompressed_size, error = %e, "zlib output reservation failed");
        PaksmithError::Decompression {
            path: path.to_string(),
            offset: entry.offset(),
            reason: format!("could not reserve {uncompressed_size} bytes for output: {e}"),
        }
    })?;

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
        // abs_end check above) but a multi-GiB pak could still trigger a
        // genuine OOM here. Allocate fallibly so the failure is typed.
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
        let remaining = uncompressed_size.saturating_sub(out.len());
        let budget = (remaining as u64).saturating_add(1);
        let mut limited = ZlibDecoder::new(&compressed[..]).take(budget);
        let written = limited.read_to_end(&mut out).map_err(|e| {
            warn!(path, block = i, abs_start, error = %e, "zlib decompress failed");
            PaksmithError::Decompression {
                path: path.to_string(),
                offset: abs_start,
                reason: format!("zlib block {i}: {e}"),
            }
        })?;

        if out.len() > uncompressed_size {
            let actual = out.len();
            warn!(
                path,
                block = i,
                actual,
                uncompressed_size,
                "decompression bomb: block exceeded uncompressed_size"
            );
            return Err(PaksmithError::Decompression {
                path: path.to_string(),
                offset: abs_start,
                reason: format!(
                    "block {i} produced {actual} bytes, exceeding uncompressed_size {uncompressed_size}"
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
    }

    if out.len() != uncompressed_size {
        let actual = out.len();
        warn!(
            path,
            actual, uncompressed_size, "cumulative decompressed size mismatch"
        );
        return Err(PaksmithError::Decompression {
            path: path.to_string(),
            offset: entry.offset(),
            reason: format!("decompressed {actual} bytes, expected {uncompressed_size}"),
        });
    }

    Ok(out)
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
#[derive(Debug, Clone, Default, PartialEq, Eq)]
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
