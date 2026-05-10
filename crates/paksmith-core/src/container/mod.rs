//! Archive container readers.
//!
//! Each container format (`.pak`, `IoStore`) implements the [`ContainerReader`] trait.

pub mod pak;

use serde::Serialize;

/// Supported archive container formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ContainerFormat {
    /// Unreal Engine `.pak` archive.
    Pak,
    /// Unreal Engine I/O Store (`.utoc`/`.ucas`).
    IoStore,
}

/// Metadata for a single entry within a container archive.
#[derive(Debug, Clone, Serialize)]
pub struct EntryMetadata {
    /// Virtual path of the entry.
    pub path: String,
    /// Compressed size in bytes.
    pub compressed_size: u64,
    /// Uncompressed size in bytes.
    pub uncompressed_size: u64,
    /// Whether the entry is stored compressed.
    pub is_compressed: bool,
    /// Whether the entry is encrypted.
    pub is_encrypted: bool,
}

/// Trait for reading archive containers regardless of format.
pub trait ContainerReader: Send + Sync {
    /// List all entries in the archive.
    fn list_entries(&self) -> &[EntryMetadata];
    /// Read raw bytes for a specific entry by path.
    fn read_entry(&self, path: &str) -> crate::Result<Vec<u8>>;
    /// The container format this reader handles.
    fn format(&self) -> ContainerFormat;
    /// The virtual mount point for paths in this archive.
    fn mount_point(&self) -> &str;
}
