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

use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

use flate2::read::ZlibDecoder;

use crate::container::{ContainerFormat, ContainerReader, EntryMetadata};
use crate::error::PaksmithError;

use self::footer::PakFooter;
use self::index::{CompressionMethod, PakEntryHeader, PakIndex, PakIndexEntry};
use self::version::PakVersion;

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

    /// Read the in-data FPakEntry header, validate it against the index entry,
    /// and return the file positioned at the start of the payload.
    ///
    /// Bounds-checks every offset/size against [`Self::file_size`] before
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

        if entry.is_encrypted() {
            return Err(PaksmithError::Decryption {
                path: path.to_string(),
            });
        }

        let (mut file, _in_data) = self.open_entry(entry)?;
        // After open_entry, `file` is positioned just past the in-data
        // FPakEntry record, i.e., at the start of the payload bytes.
        let payload_start = entry
            .offset()
            .checked_add(in_data_header_size(entry))
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
            CompressionMethod::Gzip | CompressionMethod::Oodle | CompressionMethod::Unknown(_) => {
                Err(PaksmithError::Decompression {
                    path: path.to_string(),
                    offset: entry.offset(),
                })
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

/// On-disk size of the in-data FPakEntry header for `entry`. Mirrors the
/// branches in [`PakEntryHeader::read_from`] — must stay in sync.
fn in_data_header_size(entry: &PakIndexEntry) -> u64 {
    // Common fields: offset(8) + compressed(8) + uncompressed(8) +
    // compression_method(4) + sha1(20) + is_encrypted(1) = 49.
    let mut size: u64 = 8 + 8 + 8 + 4 + 20 + 1;
    if entry.compression_method() != CompressionMethod::None {
        // block_count(4) + N * (start(8) + end(8)) + compression_block_size(4)
        size += 4 + (entry.compression_blocks().len() as u64) * 16 + 4;
    }
    size
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

    let mut buf = vec![0u8; size];
    file.read_exact(&mut buf)?;
    Ok(buf)
}

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

    let mut out = Vec::with_capacity(uncompressed_size);

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
        let mut compressed = vec![0u8; block_len_usize];
        file.read_exact(&mut compressed)?;

        let mut decoder = ZlibDecoder::new(&compressed[..]);
        let written = decoder
            .read_to_end(&mut out)
            .map_err(|_| PaksmithError::Decompression {
                path: path.to_string(),
                offset: abs_start,
            })?;

        if out.len() > uncompressed_size {
            return Err(PaksmithError::Decompression {
                path: path.to_string(),
                offset: abs_start,
            });
        }

        // Sanity: every block except possibly the last should produce exactly
        // compression_block_size bytes when decompressed.
        if i + 1 < entry.compression_blocks().len()
            && written as u64 != u64::from(entry.compression_block_size())
        {
            return Err(PaksmithError::Decompression {
                path: path.to_string(),
                offset: abs_start,
            });
        }
    }

    if out.len() != uncompressed_size {
        return Err(PaksmithError::Decompression {
            path: path.to_string(),
            offset: entry.offset(),
        });
    }

    Ok(out)
}
