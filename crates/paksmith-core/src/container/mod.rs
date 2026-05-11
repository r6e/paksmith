//! Archive container readers.
//!
//! Each container format (`.pak`, `IoStore`) implements the [`ContainerReader`] trait.

pub mod pak;

use std::io::Write;

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
///
/// Designed for object safety (`dyn ContainerReader` works) so that
/// future format dispatch (Pak vs IoStore) can be done dynamically.
/// That's why [`Self::entries`] returns a boxed iterator rather than
/// `impl Iterator` — `impl Trait` in trait return position would
/// disqualify the trait from being `dyn`-compatible.
pub trait ContainerReader: Send + Sync {
    /// Lazy iterator over the archive's entries.
    ///
    /// Materialized on demand from the parsed index — no `Vec<EntryMetadata>`
    /// is stored alongside the index. Each call yields freshly-cloned owned
    /// metadata. For a workload that scans for one entry by path, prefer
    /// the implementor's `find` shortcut (e.g.
    /// [`crate::container::pak::PakReader::index_entry`]) over filtering
    /// this iterator — the iterator allocates a `String` per yielded item,
    /// while a direct lookup is O(1).
    fn entries(&self) -> Box<dyn Iterator<Item = EntryMetadata> + '_>;

    /// Stream a single entry's decompressed bytes to `writer`. Returns the
    /// number of bytes written.
    ///
    /// This is the streaming primitive — it never materializes the full
    /// payload in memory, so multi-GiB cooked content is handled in
    /// bounded scratch buffers. See [`Self::read_entry`] for the
    /// convenience wrapper that collects to a `Vec<u8>`.
    fn read_entry_to(&self, path: &str, writer: &mut dyn Write) -> crate::Result<u64>;

    /// Read raw bytes for a specific entry by path.
    ///
    /// Default implementation collects from [`Self::read_entry_to`] into a
    /// `Vec<u8>`. Implementors with a more efficient direct-collect path
    /// (e.g., `try_reserve_exact` to surface OOM as a typed error before
    /// I/O begins) may override.
    fn read_entry(&self, path: &str) -> crate::Result<Vec<u8>> {
        let mut buf = Vec::new();
        let _ = self.read_entry_to(path, &mut buf)?;
        Ok(buf)
    }

    /// The container format this reader handles.
    fn format(&self) -> ContainerFormat;

    /// The virtual mount point for paths in this archive.
    fn mount_point(&self) -> &str;
}
