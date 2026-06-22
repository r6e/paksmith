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
/// `game` is an optional profile id selected in the toolbar.  When `Some`,
/// key resolution uses that profile directly (same as `--game` on the CLI).
/// When `None`, resolution falls back to the default heuristics (no `--game`).
///
/// # Errors
///
/// Returns [`OpenError::Locked`] when the archive is encrypted but no key
/// could be resolved. Returns [`OpenError::Core`] for all other failures
/// (I/O, index corruption, decryption failure, etc.).
pub async fn run(path: PathBuf, game: Option<String>) -> Result<LoadedArchive, OpenError> {
    run_inner(path, None, game).await
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
    run_inner(path, Some(key), None).await
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
    // `game = None` is intentional: the detect-dir flow auto-discovers the
    // game from the directory, so the toolbar-selected profile is deliberately
    // not forwarded (detect resolution wins in `resolve_pak_key` priority order).
    let resolved_key =
        paksmith_core::profile::resolve::resolve_pak_key(&path, None, None, Some(&detect_dir))
            .await?;

    build_loaded(path, resolved_key.as_ref())
}

/// Shared implementation.
///
/// - `manual_key`: `None` for default open (profile resolution), `Some` when
///   the user supplied a hex key manually (bypasses `game`/detect entirely).
/// - `game`: optional profile id from the toolbar selector; passed as the
///   `--game` argument to `resolve_pak_key`.
///
/// Detection rule: `Decryption { .. }` from core with `resolved_key.is_none()`
/// ⟹ the pak is encrypted and no key was found → `OpenError::Locked`.
/// With a manual key supplied the same variant means *wrong key* → `Core`.
async fn run_inner(
    path: PathBuf,
    manual_key: Option<AesKey>,
    game: Option<String>,
) -> Result<LoadedArchive, OpenError> {
    let resolved_key = paksmith_core::profile::resolve::resolve_pak_key(
        &path,
        manual_key.as_ref(),
        game.as_deref(),
        None,
    )
    .await?;

    build_loaded(path, resolved_key.as_ref())
}

/// Open the reader with the already-resolved key and build the [`LoadedArchive`],
/// mapping an encrypted-but-no-key `Decryption` error to [`OpenError::Locked`].
///
/// This is the single source of truth for the open→collect→tree pipeline shared
/// by both `run_inner` (which resolves via `resolve_pak_key`) and
/// `run_with_detect` (which resolves via `--detect`).
///
/// # Detection rule
///
/// `Decryption { .. }` from core with `resolved_key.is_none()` ⟹ the pak is
/// encrypted and no key is available → [`OpenError::Locked`].  With a key
/// present (`resolved_key.is_some()`) the same variant means *wrong key* →
/// [`OpenError::Core`].
fn build_loaded(path: PathBuf, resolved_key: Option<&AesKey>) -> Result<LoadedArchive, OpenError> {
    let open_result = match resolved_key {
        Some(k) => PakReader::open_with_key(&path, k.clone()),
        None => PakReader::open(&path),
    };

    let reader = match open_result {
        Ok(r) => std::sync::Arc::new(r),
        Err(PaksmithError::Decryption { .. }) if resolved_key.is_none() => {
            // Encrypted pak, no key available → prompt the user.
            return Err(OpenError::Locked { path });
        }
        Err(e) => return Err(e.into()),
    };

    let raw_entries: Vec<_> = reader.entries().collect(); // Arc<PakReader> derefs to &PakReader
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
        reader,
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
        let err = run(path.clone(), None).await.unwrap_err();
        assert!(
            matches!(err, OpenError::Locked { path: ref p } if p == &path),
            "expected Locked, got {err:?}"
        );
    }

    /// A wrong key (all zeros) must NOT produce `OpenError::Locked`.
    ///
    /// When `resolved_key` is `Some` (a key was supplied), a decryption failure
    /// means *wrong key*, not *no key* — the user should see a `Core` error, not
    /// be re-prompted with the locked panel.  This exercises the
    /// `resolved_key.is_some()` + `Decryption { .. }` branch in `run_inner`
    /// and kills the `with true` mutant on the `resolved_key.is_none()` guard
    /// (which would incorrectly return `Locked` even with a key present).
    #[tokio::test]
    async fn run_with_key_wrong_key_returns_core_error_not_locked() {
        let path = fixture_path("real_v8b_encrypted_index.pak");
        let wrong_key = AesKey::from_hex(&"00".repeat(32)).expect("valid all-zero key");
        let err = run_with_key(path, wrong_key).await.unwrap_err();
        assert!(
            !matches!(err, OpenError::Locked { .. }),
            "wrong key must not produce Locked — got {err:?}"
        );
        assert!(
            matches!(err, OpenError::Core(..)),
            "wrong key must produce Core decryption error — got {err:?}"
        );
    }

    #[tokio::test]
    async fn loaded_archive_retains_reader_for_entry_reads() {
        use paksmith_core::container::ContainerReader as _;
        let path = fixture_path("real_v8b_uasset.pak");
        let loaded = run(path, None).await.unwrap();
        // The retained reader must be able to read an entry's bytes on demand.
        let bytes = loaded.reader.read_entry("Game/Maps/Demo.uasset").unwrap();
        assert!(!bytes.is_empty(), "retained reader must read entry bytes");
    }
}
