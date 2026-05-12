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
///
/// Constructed by [`ContainerReader`] implementors (typically inside
/// `entries()`) via [`Self::new`]. External readers access fields via
/// the named accessors below, not by struct-literal destructuring —
/// the struct is `#[non_exhaustive]` so future container formats
/// (iostore, future pak versions) can add fields (e.g.
/// `format_hint: Option<AssetKind>`, `mount_relative_path: String`)
/// without breaking downstream consumers.
///
/// Fields are `pub(crate)` to reserve the right to change internal
/// representation (e.g., interning paths, packing booleans into a
/// bitset) without an API break. The accessors are the stable surface.
///
/// The `Serialize` derive remains on by-name field projection — JSON
/// output keys match the field names exactly, so existing wire
/// consumers see no change.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct EntryMetadata {
    pub(crate) path: String,
    pub(crate) compressed_size: u64,
    pub(crate) uncompressed_size: u64,
    pub(crate) is_compressed: bool,
    pub(crate) is_encrypted: bool,
}

impl EntryMetadata {
    /// Construct an `EntryMetadata`. Used by [`ContainerReader`]
    /// implementors yielding entries from their `entries()` iterator.
    ///
    /// `#[non_exhaustive]` blocks struct-literal construction from
    /// outside this crate, so external trait implementors MUST go
    /// through this constructor — that's the seam that lets new
    /// fields be added later without breaking those implementors
    /// (the constructor signature is the breaking-change surface,
    /// not the struct definition).
    pub fn new(
        path: String,
        compressed_size: u64,
        uncompressed_size: u64,
        is_compressed: bool,
        is_encrypted: bool,
    ) -> Self {
        Self {
            path,
            compressed_size,
            uncompressed_size,
            is_compressed,
            is_encrypted,
        }
    }

    /// Virtual path of the entry within the archive.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Compressed size in bytes (equals [`Self::uncompressed_size`] when
    /// the entry is stored uncompressed).
    pub fn compressed_size(&self) -> u64 {
        self.compressed_size
    }

    /// Uncompressed size in bytes — the size the entry occupies when
    /// extracted.
    pub fn uncompressed_size(&self) -> u64 {
        self.uncompressed_size
    }

    /// True iff the entry is stored compressed (any non-None
    /// compression method).
    pub fn is_compressed(&self) -> bool {
        self.is_compressed
    }

    /// True iff the entry is AES-encrypted on disk.
    pub fn is_encrypted(&self) -> bool {
        self.is_encrypted
    }
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
