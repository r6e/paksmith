//! Unreal Engine `.pak` archive reader.

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
    #[allow(dead_code)]
    footer: PakFooter,
    index: PakIndex,
    entries: Vec<EntryMetadata>,
}

impl PakReader {
    /// Open and parse a `.pak` file at the given path.
    pub fn open<P: AsRef<Path>>(path: P) -> crate::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mut file = BufReader::new(File::open(&path)?);

        let footer = PakFooter::read_from(&mut file)?;

        if footer.encrypted {
            return Err(PaksmithError::Decryption {
                path: path.display().to_string(),
            });
        }

        let _ = file.seek(SeekFrom::Start(footer.index_offset))?;
        let index = PakIndex::read_from(&mut file, footer.version)?;

        let entries = index
            .entries
            .iter()
            .map(|e| EntryMetadata {
                path: e.filename.clone(),
                compressed_size: e.compressed_size,
                uncompressed_size: e.uncompressed_size,
                is_compressed: e.compression_method != CompressionMethod::None,
                is_encrypted: e.is_encrypted,
            })
            .collect();

        Ok(Self {
            path,
            footer,
            index,
            entries,
        })
    }

    /// The pak format version of this archive.
    pub fn version(&self) -> PakVersion {
        self.footer.version
    }
}

impl ContainerReader for PakReader {
    fn list_entries(&self) -> &[EntryMetadata] {
        &self.entries
    }

    fn read_entry(&self, path: &str) -> crate::Result<Vec<u8>> {
        let entry = self
            .index
            .entries
            .iter()
            .find(|e| e.filename == path)
            .ok_or_else(|| PaksmithError::EntryNotFound {
                path: path.to_string(),
            })?;

        if entry.compression_method != CompressionMethod::None {
            return Err(PaksmithError::Decompression {
                offset: entry.offset,
            });
        }

        if entry.is_encrypted {
            return Err(PaksmithError::Decryption {
                path: path.to_string(),
            });
        }

        let mut file = BufReader::new(File::open(&self.path)?);
        let _ = file.seek(SeekFrom::Start(entry.offset))?;

        let mut buf = vec![0u8; entry.uncompressed_size as usize];
        file.read_exact(&mut buf)?;

        Ok(buf)
    }

    fn format(&self) -> ContainerFormat {
        ContainerFormat::Pak
    }

    fn mount_point(&self) -> &str {
        &self.index.mount_point
    }
}
