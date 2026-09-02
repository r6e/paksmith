//! Archive state: the loaded container and its tree model.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use paksmith_core::container::{ContainerReader, EntryIntegrity};

use crate::state::tree::Tree;

/// Per-entry metadata collected once at open time from [`paksmith_core::container::EntryMetadata`].
///
/// Stored in `LoadedArchive::entries` keyed by the entry's full path string.
/// The detail pane looks up the selected path in this map — absent paths
/// (directories, or the selection not yet resolved) yield `None`, which
/// renders the "Select a file to inspect" placeholder.
#[derive(Debug, Clone)]
pub struct EntryMeta {
    /// Uncompressed size in bytes.
    pub uncompressed_size: u64,
    /// Compressed size in bytes (equals `uncompressed_size` when stored raw).
    pub compressed_size: u64,
    /// True when the entry is stored with any compression method.
    pub is_compressed: bool,
    /// True when the entry is AES-encrypted on disk.
    pub is_encrypted: bool,
    /// File offset of the entry's on-disk RECORD, when recorded (#662).
    /// For pak this is where the duplicated entry header starts — the
    /// payload follows that header copy, so this is NOT the first payload
    /// byte (mirrors `EntryMetadata::offset`'s contract).
    pub offset: Option<u64>,
    // RETENTION, deliberately asymmetric with the CLI (#662): these
    // three detail fields roughly triple `EntryMeta` (24 -> 72 bytes) and
    // are held for EVERY entry, though only the selected one is rendered.
    // The CLI narrows its per-entry row for exactly that reason, but the
    // CLI prints once and exits; GUI selection is random-access. The
    // alternative is not archive I/O — core has already parsed the index
    // into memory — but re-deriving through the type-erased
    // `ContainerReader::entries` iterator, which is O(N) in entries and
    // allocates a fresh path String per item, on every click. Keeping
    // the map trades ~48 bytes per entry for O(1) selection.
    //
    // That trade is only forced because `ContainerReader` has no
    // per-path metadata lookup — core HAS an O(1) one for pak
    // (`PakIndex::by_path` behind `PakReader::index_entry`), but it is
    // not on the type-erased trait this holds. Adding one lets the pane
    // fetch on selection and these fields leave the map entirely;
    // scoped in #754, where the design question is what the default
    // body should be, since an O(N) default would silently hand a
    // future container a full scan per click.
    /// Compression method display name (e.g. "Zlib"), when the entry is
    /// compressed and the container recorded one (#662). Held as the
    /// shared `Arc<str>` the capturing iteration interned, not a
    /// `String`: an archive names few distinct methods, so retaining one
    /// per entry bumps a refcount rather than copying bytes. Compare
    /// these by VALUE — pointer identity only holds among entries from
    /// the same `entries()` call, and pak leaves its `Unknown(id)`
    /// rendering unshared by design.
    pub compression_method: Option<Arc<str>>,
    /// The entry's stored-SHA-1 claim (#662), classified once at capture
    /// by core's [`paksmith_core::container::ContainerReader::entry_integrity`]
    /// from the wire field plus the archive-level `claims_integrity`
    /// bit. Carries the digest, not formatted hex — rendering formats on
    /// demand, so this costs no heap per entry.
    pub integrity: EntryIntegrity,
}

/// A successfully opened archive and its derived state.
#[derive(Clone)]
pub struct LoadedArchive {
    /// Path to the `.pak` file on disk.
    pub path: PathBuf,
    /// Number of entries (files) inside the archive.
    pub entry_count: usize,
    /// `true` when the archive was AES-encrypted and a key was resolved.
    pub decrypted: bool,
    /// File-tree model built from the archive's entry paths.
    pub tree: Tree,
    /// Last reported scroll geometry of the file-tree viewport (#660).
    ///
    /// Fed by `Message::TreeScrolled` and consumed by the windowed tree
    /// view; lives here rather than on `App` so it resets with the archive.
    pub tree_scroll: crate::state::row_window::ScrollPos,
    /// Per-entry metadata keyed by full entry path (forward-slash separated).
    ///
    /// Populated once at open time; the detail pane queries this for the
    /// selected file. Directories have no entry here (they are synthetic nodes
    /// in the tree, not real archive entries).
    pub entries: BTreeMap<String, EntryMeta>,
    /// The open container reader (type-erased — #654: the GUI never
    /// names a concrete reader type), retained so asset tabs can read +
    /// parse entries on demand. `Arc` so the async asset-load task can
    /// share it across the `Task::perform` boundary (`ContainerReader`
    /// is `Send + Sync` by supertrait).
    pub reader: Arc<dyn ContainerReader>,
}

// `dyn ContainerReader` does not implement `Debug` (nor did the concrete
// reader); format it as an opaque marker so `LoadedArchive` (and therefore
// `Message`) keeps its `Debug` bound without touching core.
impl std::fmt::Debug for LoadedArchive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadedArchive")
            .field("path", &self.path)
            .field("entry_count", &self.entry_count)
            .field("decrypted", &self.decrypted)
            .field("tree", &self.tree)
            .field("tree_scroll", &self.tree_scroll)
            .field("entries", &self.entries)
            .field("reader", &"<ContainerReader>")
            .finish()
    }
}

/// Errors produced by the archive-open pipeline.
#[derive(Debug, Clone, thiserror::Error)]
pub enum OpenError {
    /// The archive appears to be encrypted but no key could be resolved.
    /// The GUI forwards this variant to the key-entry flow (Task 8).
    #[error("pak is locked (encrypted) and no key was found: {path}")]
    Locked {
        /// Path to the encrypted archive.
        path: PathBuf,
    },
    /// Any other core error (I/O, index corruption, decryption failure, …).
    ///
    /// Carries the attempted path for the same reason [`OpenError::Locked`]
    /// does: the GUI's archive-open failure card is scoped to a file, so it can
    /// name the file it reports on and be superseded by a later completed
    /// attempt on THAT path rather than on any path (#663). Core's own
    /// `Display` carries a path for some faults and not others, so the string
    /// cannot stand in for it.
    ///
    /// `message` is stringified at the boundary so `Message: Clone` is
    /// satisfied.
    #[error("{message}")]
    Core {
        /// Path the open was attempted on.
        path: PathBuf,
        /// Core's rendered error.
        message: String,
    },
}

impl OpenError {
    /// Build a [`OpenError::Core`] from a core error raised while opening
    /// `path`.
    ///
    /// Replaces a `From<PaksmithError>` impl: `From` cannot see the path, and a
    /// blanket `?` conversion is exactly how the path got dropped before.
    pub fn core(path: impl Into<PathBuf>, e: &paksmith_core::PaksmithError) -> Self {
        Self::Core {
            path: path.into(),
            message: e.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn open_plain_fixture_populates_tree() {
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("tests/fixtures/real_v8b_multi.pak"); // plain (unencrypted) multi-entry fixture
        let loaded = crate::task::open::run(fixture, None).await.unwrap();
        assert!(loaded.entry_count > 0);
        assert!(!loaded.tree.is_empty());
        assert!(loaded.tree.len() <= loaded.entry_count); // tree dedups duplicate paths
    }

    // ── B7: LoadedArchive Debug impl ──────────────────────────────────────────

    #[tokio::test]
    async fn loaded_archive_debug_contains_struct_name_and_reader_sentinel() {
        // Kills `replace <impl std::fmt::Debug for LoadedArchive>::fmt -> std::fmt::Result
        // with Ok(Default::default())`: a no-op fmt would produce an empty string,
        // not containing "LoadedArchive" or "<ContainerReader>".
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("tests/fixtures/real_v8b_uasset.pak");
        let loaded = crate::task::open::run(fixture, None).await.unwrap();
        let debug_str = format!("{loaded:?}");
        assert!(
            debug_str.contains("LoadedArchive"),
            "Debug must contain the struct name; got: {debug_str}"
        );
        assert!(
            debug_str.contains("<ContainerReader>"),
            "Debug must contain the reader sentinel; got: {debug_str}"
        );
    }
}
