//! Unreal Engine `.pak` archive reader.
//!
//! # Phase 1 scope
//!
//! This reader implements footer parsing for v1–v11 paks and a flat-entry
//! index layout that matches the v3-era on-disk format. It does NOT yet handle:
//!
//! - The FName-based compression-method indirection introduced in v8.
//! - The path-hash + encoded-directory index introduced in v10.
//! - The duplicate FPakEntry header that real archives write before each
//!   payload at `entry.offset()`.
//! - AES decryption of the index or of individual entries.
//! - Decompression of stored entries.
//!
//! [`PakReader::open`] therefore rejects v8+ archives with
//! [`PaksmithError::UnsupportedVersion`]. [`PakReader::read_entry`] reads bytes
//! starting at `entry.offset()` directly, which is correct for the synthetic
//! fixtures used by the test suite but will return record-header bytes (not
//! payload) on a real UE-produced archive.
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

use crate::container::{ContainerFormat, ContainerReader, EntryMetadata};
use crate::error::PaksmithError;

use self::footer::PakFooter;
use self::index::{CompressionMethod, PakIndex};
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
    /// module-level docs for the full Phase 1 scope.
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

        if entry.compression_method() != CompressionMethod::None {
            return Err(PaksmithError::Decompression {
                path: path.to_string(),
                offset: entry.offset(),
            });
        }

        if entry.is_encrypted() {
            return Err(PaksmithError::Decryption {
                path: path.to_string(),
            });
        }

        let size = usize::try_from(entry.uncompressed_size()).map_err(|_| {
            PaksmithError::InvalidIndex {
                reason: format!(
                    "entry `{path}` size {} exceeds platform usize",
                    entry.uncompressed_size()
                ),
            }
        })?;

        let end = entry
            .offset()
            .checked_add(entry.uncompressed_size())
            .ok_or_else(|| PaksmithError::InvalidIndex {
                reason: format!("entry `{path}` offset+size overflows u64"),
            })?;
        if end > self.file_size {
            return Err(PaksmithError::InvalidIndex {
                reason: format!(
                    "entry `{path}` extends past EOF: offset={} size={} file_size={}",
                    entry.offset(),
                    entry.uncompressed_size(),
                    self.file_size
                ),
            });
        }

        let mut file = BufReader::new(File::open(&self.path)?);
        let _ = file.seek(SeekFrom::Start(entry.offset()))?;

        let mut buf = vec![0u8; size];
        file.read_exact(&mut buf)?;

        Ok(buf)
    }

    fn format(&self) -> ContainerFormat {
        ContainerFormat::Pak
    }

    fn mount_point(&self) -> &str {
        self.index.mount_point()
    }
}
