//! Async archive-open pipeline: resolve key → open reader → build tree model.

use std::path::PathBuf;

use paksmith_core::AesKey;
use paksmith_core::PaksmithError;
use paksmith_core::container::ContainerReader as _;
use paksmith_core::container::pak::PakReader;

use crate::state::archive::{EntryMeta, LoadedArchive, OpenError};
use crate::state::tree::Tree;

/// Open `path`, auto-resolving an encrypted pak's key via the Phase 5 logic.
///
/// # Errors
///
/// Returns [`OpenError::Locked`] when the archive is encrypted but no key
/// could be resolved. Returns [`OpenError::Core`] for all other failures
/// (I/O, index corruption, decryption failure, etc.).
pub async fn run(path: PathBuf) -> Result<LoadedArchive, OpenError> {
    run_inner(path, None).await
}

/// Open `path` using an explicitly supplied `key`, bypassing profile resolution.
///
/// Used by the key-prompt panel when the user submits a hex key manually.
///
/// # Errors
///
/// Returns [`OpenError::Core`] when the key is wrong or the archive cannot
/// be opened for any other reason. A wrong key produces a `Decryption` error
/// from core; a correct key produces a loaded archive.
pub async fn run_with_key(path: PathBuf, key: AesKey) -> Result<LoadedArchive, OpenError> {
    run_inner(path, Some(key)).await
}

/// Open `path`, using a game-install `detect_dir` for profile auto-detection.
///
/// Used by the key-prompt panel's "Choose install dir…" button. Resolution
/// uses `--detect detect_dir` to find matching profiles.
///
/// # Errors
///
/// Returns [`OpenError::Locked`] when detection succeeds but the pak is still
/// not openable without a key (or detection finds no matching profile).
/// Returns [`OpenError::Core`] for all other failures.
pub async fn run_with_detect(
    path: PathBuf,
    detect_dir: PathBuf,
) -> Result<LoadedArchive, OpenError> {
    let resolved_key =
        paksmith_core::profile::resolve::resolve_pak_key(&path, None, None, Some(&detect_dir))
            .await?;

    let open_result = match &resolved_key {
        Some(k) => PakReader::open_with_key(&path, k.clone()),
        None => PakReader::open(&path),
    };

    let reader = match open_result {
        Ok(r) => r,
        Err(PaksmithError::Decryption { .. }) if resolved_key.is_none() => {
            return Err(OpenError::Locked { path });
        }
        Err(e) => return Err(e.into()),
    };

    let raw_entries: Vec<_> = reader.entries().collect();
    let entry_count = raw_entries.len();
    // Allocate each path string once and reuse it for both the BTreeMap key and
    // the paths Vec — avoids a second `to_string()` per entry.
    let mut entries = std::collections::BTreeMap::new();
    let mut paths: Vec<String> = Vec::with_capacity(entry_count);
    for e in raw_entries {
        let path_str = e.path().to_string();
        let _ = entries.insert(
            path_str.clone(),
            EntryMeta {
                uncompressed_size: e.uncompressed_size(),
                compressed_size: e.compressed_size(),
                is_compressed: e.is_compressed(),
                is_encrypted: e.is_encrypted(),
            },
        );
        paths.push(path_str);
    }
    let tree = Tree::from_paths(paths);
    Ok(LoadedArchive {
        path,
        entry_count,
        decrypted: resolved_key.is_some(),
        tree,
        entries,
    })
}

/// Shared implementation. `manual_key` is `None` for the default open path
/// (profile resolution), `Some` when the user supplied a key manually.
///
/// Detection rule: `Decryption { .. }` from core with `resolved_key.is_none()`
/// ⟹ the pak is encrypted and no key was found → `OpenError::Locked`.
/// With a manual key supplied the same variant means *wrong key* → `Core`.
async fn run_inner(path: PathBuf, manual_key: Option<AesKey>) -> Result<LoadedArchive, OpenError> {
    // No explicit --game/--detect from the GUI; resolution falls back to the
    // active profile context (wired in Task 12). When a manual key is supplied
    // resolve_pak_key shortcuts to `Ok(Some(key))` immediately.
    let resolved_key =
        paksmith_core::profile::resolve::resolve_pak_key(&path, manual_key.as_ref(), None, None)
            .await?;

    let open_result = match &resolved_key {
        Some(k) => PakReader::open_with_key(&path, k.clone()),
        None => PakReader::open(&path),
    };

    let reader = match open_result {
        Ok(r) => r,
        Err(PaksmithError::Decryption { .. }) if resolved_key.is_none() => {
            // Encrypted pak, no key available → prompt the user.
            return Err(OpenError::Locked { path });
        }
        Err(e) => return Err(e.into()),
    };

    let raw_entries: Vec<_> = reader.entries().collect();
    let entry_count = raw_entries.len();
    // Allocate each path string once and reuse it for both the BTreeMap key and
    // the paths Vec — avoids a second `to_string()` per entry.
    let mut entries = std::collections::BTreeMap::new();
    let mut paths: Vec<String> = Vec::with_capacity(entry_count);
    for e in raw_entries {
        let path_str = e.path().to_string();
        let _ = entries.insert(
            path_str.clone(),
            EntryMeta {
                uncompressed_size: e.uncompressed_size(),
                compressed_size: e.compressed_size(),
                is_compressed: e.is_compressed(),
                is_encrypted: e.is_encrypted(),
            },
        );
        paths.push(path_str);
    }
    let tree = Tree::from_paths(paths);
    Ok(LoadedArchive {
        path,
        entry_count,
        decrypted: resolved_key.is_some(),
        tree,
        entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use paksmith_core::AesKey;

    fn fixture_path(name: &str) -> PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("tests/fixtures")
            .join(name)
    }

    /// The encrypted fixture key from PROVENANCE-encrypted.md.
    fn fixture_key() -> AesKey {
        AesKey::from_hex("94d25bc3aeb420e0be914edc9d5435a1eaab5f2864e09e94019ac205b727a7de")
            .expect("valid fixture key")
    }

    #[tokio::test]
    async fn run_with_key_unlocks_encrypted_fixture() {
        let path = fixture_path("real_v8b_encrypted_index.pak");
        let loaded = run_with_key(path, fixture_key()).await.unwrap();
        assert!(loaded.entry_count > 0, "expected at least one entry");
        assert!(
            loaded.decrypted,
            "decrypted flag should be true after key-unlock"
        );
        assert!(!loaded.tree.is_empty(), "tree should be populated");
    }

    #[tokio::test]
    async fn run_no_key_encrypted_pak_returns_locked() {
        let path = fixture_path("real_v8b_encrypted_index.pak");
        let err = run(path.clone()).await.unwrap_err();
        assert!(
            matches!(err, OpenError::Locked { path: ref p } if p == &path),
            "expected Locked, got {err:?}"
        );
    }
}
