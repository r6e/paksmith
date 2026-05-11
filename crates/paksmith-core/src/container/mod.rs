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
    /// Iterator over the archive's entries.
    ///
    /// **NOT lazy in the wire-parsing sense.** The full entries vector
    /// has already been parsed into the in-memory index by the time
    /// the implementor returns — what's lazy here is the construction
    /// of the per-call [`EntryMetadata`] (each `next()` allocates a
    /// fresh `String` for the `path` field). For an N-entry archive,
    /// iterating yields N owned `EntryMetadata` values and pays N
    /// heap allocations.
    ///
    /// For a workload that scans for one entry by path, prefer the
    /// implementor's `find` shortcut (e.g.
    /// [`crate::container::pak::PakReader::index_entry`]) over
    /// filtering this iterator — direct lookup is O(1) and
    /// allocation-free.
    ///
    /// The boxed iterator is the cost of keeping the trait
    /// object-safe; callers that need a borrowed-`&str` iterator must
    /// reach through the concrete reader type.
    fn entries(&self) -> Box<dyn Iterator<Item = EntryMetadata> + '_>;

    /// Stream a single entry's decompressed bytes to `writer`. Returns the
    /// number of bytes written.
    ///
    /// This is the streaming primitive — it never materializes the full
    /// payload in memory, so multi-GiB cooked content is handled in
    /// bounded scratch buffers. See [`Self::read_entry`] for the
    /// convenience wrapper that collects to a `Vec<u8>`.
    fn read_entry_to(&self, path: &str, writer: &mut dyn Write) -> crate::Result<u64>;

    /// Read raw bytes for a specific entry by path into an owned `Vec<u8>`.
    ///
    /// **Required, not defaulted, for safety.** A naïve default that just
    /// did `let mut v = Vec::new(); self.read_entry_to(path, &mut v)?;
    /// Ok(v)` would let `Vec` grow unboundedly during the streaming write
    /// — a malformed archive claiming a multi-GiB `uncompressed_size` on
    /// a memory-constrained host could trip the allocator's abort path
    /// before any typed error surfaces. Each implementor must provide
    /// its own collector that fallibly reserves the entry size upfront
    /// (typically via `Vec::try_reserve_exact`) so OOM becomes a
    /// recoverable typed error rather than a process kill.
    ///
    /// See `paksmith_core::container::pak::PakReader::read_entry` for
    /// the canonical implementation.
    fn read_entry(&self, path: &str) -> crate::Result<Vec<u8>>;

    /// The container format this reader handles.
    fn format(&self) -> ContainerFormat;

    /// The virtual mount point for paths in this archive.
    fn mount_point(&self) -> &str;
}

/// Compile-time assertion that [`ContainerReader`] is dyn-compatible.
/// The trait's docstring promises object-safety; this `const _` makes
/// that promise a build-failure if a future trait method takes `Self` by
/// value, returns `impl Trait`, or otherwise breaks dyn-compatibility.
#[allow(dead_code)]
const _: fn() = || {
    fn assert_dyn_compatible(_: &dyn ContainerReader) {}
};
