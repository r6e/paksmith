//! Archive state: the loaded container and its tree model.

use std::collections::BTreeMap;
use std::path::PathBuf;

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
}

/// A successfully opened archive and its derived state.
#[derive(Debug, Clone)]
pub struct LoadedArchive {
    /// Path to the `.pak` file on disk.
    pub path: PathBuf,
    /// Number of entries (files) inside the archive.
    pub entry_count: usize,
    /// `true` when the archive was AES-encrypted and a key was resolved.
    pub decrypted: bool,
    /// File-tree model built from the archive's entry paths.
    pub tree: Tree,
    /// Per-entry metadata keyed by full entry path (forward-slash separated).
    ///
    /// Populated once at open time; the detail pane queries this for the
    /// selected file. Directories have no entry here (they are synthetic nodes
    /// in the tree, not real archive entries).
    pub entries: BTreeMap<String, EntryMeta>,
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
    /// Stringified at the message boundary so `Message: Clone` is satisfied.
    #[error("{0}")]
    Core(String),
}

impl From<paksmith_core::PaksmithError> for OpenError {
    fn from(e: paksmith_core::PaksmithError) -> Self {
        Self::Core(e.to_string())
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
        let loaded = crate::task::open::run(fixture).await.unwrap();
        assert!(loaded.entry_count > 0);
        assert!(!loaded.tree.is_empty());
        assert!(loaded.tree.len() <= loaded.entry_count); // tree dedups duplicate paths
    }
}
