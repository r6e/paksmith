//! Archive container readers.
//!
//! Phase 1 ships only the `.pak` reader (see [`pak`]) implementing
//! [`ContainerReader`]. The [`ContainerFormat::IoStore`] variant
//! reserves the API surface for Phase 2's IoStore reader; no
//! [`ContainerReader`] implementor exists for it yet.

pub mod pak;

use std::io::Write;

use serde::Serialize;

/// Supported archive container formats.
///
/// Marked `#[non_exhaustive]` for forward-compat — Phase 2's IoStore
/// implementation will turn `IoStore` from a name-only variant into a
/// fully-supported reader, and future container kinds (e.g. raw uasset
/// directories) can be added without breaking external `match` arms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum ContainerFormat {
    /// Unreal Engine `.pak` archive.
    Pak,
    /// Unreal Engine I/O Store (`.utoc`/`.ucas`).
    IoStore,
}

/// Boolean flags for an [`EntryMetadata`]. Grouped into a struct so
/// `EntryMetadata::new`'s call sites can't accidentally swap the
/// `compressed`/`encrypted` arguments — both are bool, both adjacent,
/// the swap would compile silently. Named-field construction at the
/// call site spells out which flag is which.
///
/// Marked `#[non_exhaustive]` so future flags (e.g., a `delete_record`
/// boolean for v6+ archives, or `aes256` once UE adopts it) can be
/// added without breaking external `ContainerReader` implementors.
///
/// **No `new(compressed, encrypted)` constructor on purpose**: a
/// positional two-bool constructor would re-introduce the very
/// swap risk this type exists to prevent. In-crate callers
/// construct via named-field struct literals (allowed because
/// `#[non_exhaustive]` only blocks struct literals from *outside*
/// the crate). External `ContainerReader` implementors should use
/// [`Self::NONE`] + the [`Self::with_compressed`] / [`Self::with_encrypted`]
/// builder methods so each flag is labeled at the call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct EntryFlags {
    /// True iff the entry's payload is compressed on disk.
    /// Implementors derive this from their format's compression method
    /// (e.g. pak: `method != CompressionMethod::None`) — it's a
    /// computed property of the wire shape, not a header flag.
    pub compressed: bool,
    /// True iff the entry is AES-encrypted on disk.
    pub encrypted: bool,
}

impl EntryFlags {
    /// All flags false — the builder-pattern base for external
    /// `ContainerReader` implementors who can't use struct literals
    /// (`#[non_exhaustive]` blocks them from outside the crate).
    /// Chain [`Self::with_compressed`] / [`Self::with_encrypted`] to
    /// label each flag at the call site.
    pub const NONE: Self = Self {
        compressed: false,
        encrypted: false,
    };

    /// Set the `compressed` flag explicitly, returning `self` for
    /// chaining. Prefer [`Self::compressed`] (no-arg) when the
    /// always-true case is intended — the positional `bool` here
    /// re-introduces the swap-footgun the typed `EntryFlags` struct
    /// was built to defeat. Kept for the unusual case of conditionally
    /// setting from a runtime `bool`.
    #[must_use]
    pub fn with_compressed(mut self, v: bool) -> Self {
        self.compressed = v;
        self
    }

    /// Set the `encrypted` flag explicitly. See
    /// [`Self::with_compressed`] for the bool-footgun caveat — prefer
    /// [`Self::encrypted`] for the always-true case.
    #[must_use]
    pub fn with_encrypted(mut self, v: bool) -> Self {
        self.encrypted = v;
        self
    }

    /// Mark `compressed = true`, returning `self` for chaining
    /// (issue #137 L6). Zero-arg sugar to avoid the
    /// [`Self::with_compressed`]`(true)` bool-footgun where a future
    /// engineer could swap two `.with_*(true)` calls into
    /// `.with_*(false)`.
    #[must_use]
    pub fn compressed(self) -> Self {
        self.with_compressed(true)
    }

    /// Mark `encrypted = true`. See [`Self::compressed`] for the
    /// rationale.
    #[must_use]
    pub fn encrypted(self) -> Self {
        self.with_encrypted(true)
    }
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
/// **Implementor-facing trade-off**: the `#[non_exhaustive]` marker
/// pushes the breaking-change surface from struct-literal construction
/// into [`Self::new`]'s arity. Adding a parameter to `new` is itself
/// a breaking change for every external `ContainerReader` impl — if
/// this seam grows past ~6 args, prefer migrating to a builder
/// (preserves arg-name stability across additions).
#[derive(Debug, Clone)]
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
    /// through this constructor.
    ///
    /// Flags are grouped into [`EntryFlags`] (named-field struct)
    /// rather than two adjacent positional bools — the call site
    /// then reads `EntryFlags { compressed: ..., encrypted: ... }`,
    /// making argument-order swaps a compile error rather than a
    /// silent semantic bug.
    pub fn new(
        path: String,
        compressed_size: u64,
        uncompressed_size: u64,
        flags: EntryFlags,
    ) -> Self {
        Self {
            path,
            compressed_size,
            uncompressed_size,
            is_compressed: flags.compressed,
            is_encrypted: flags.encrypted,
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
