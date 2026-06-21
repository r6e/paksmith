//! Async archive-open pipeline: resolve key → open reader → build tree model.

use std::path::PathBuf;

use paksmith_core::container::ContainerReader as _;
use paksmith_core::container::pak::PakReader;

use crate::state::archive::{LoadedArchive, OpenError};
use crate::state::tree::Tree;

/// Open `path`, auto-resolving an encrypted pak's key via the Phase 5 logic.
///
/// # Errors
///
/// Returns [`OpenError::Locked`] when the archive is encrypted but no key
/// could be resolved. Returns [`OpenError::Core`] for all other failures
/// (I/O, index corruption, decryption failure, etc.).
pub async fn run(path: PathBuf) -> Result<LoadedArchive, OpenError> {
    // No explicit --aes-key/--game/--detect from the GUI's default open path;
    // resolution falls back to the active profile context (wired in Task 12).
    let key = paksmith_core::profile::resolve::resolve_pak_key(&path, None, None, None).await?;
    let reader = match &key {
        Some(k) => PakReader::open_with_key(&path, k.clone())?,
        None => PakReader::open(&path)?,
    };
    let paths: Vec<String> = reader.entries().map(|e| e.path().to_string()).collect();
    let entry_count = paths.len();
    let tree = Tree::from_paths(paths);
    Ok(LoadedArchive {
        path,
        entry_count,
        decrypted: key.is_some(),
        tree,
    })
}
