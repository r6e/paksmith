//! Async archive-open pipeline: resolve key → open reader → build tree model.

use std::path::PathBuf;

use paksmith_core::AesKey;
use paksmith_core::PaksmithError;

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
            .await
            .map_err(|e| OpenError::core(&path, &e))?;

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
    // Issue #706 seam: switch to `resolve_pak_context` to also get the
    // profile's `MappingsSource`, load it once here, and carry the parsed
    // `Arc<Usmap>` in `LoadedArchive` for the asset/export tasks. The
    // same switch picks up the profile's engine-version hint (#656),
    // which the GUI likewise does not thread today — the texture viewer
    // is exactly where the UE 5.2-vs-5.3 gap shows.
    let resolved_key = paksmith_core::profile::resolve::resolve_pak_key(
        &path,
        manual_key.as_ref(),
        game.as_deref(),
        None,
    )
    .await
    .map_err(|e| OpenError::core(&path, &e))?;

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
    // #654: the container-agnostic factory — the GUI never names a
    // concrete reader type.
    let reader = match paksmith_core::container::open(&path, resolved_key) {
        Ok(r) => r,
        Err(PaksmithError::Decryption { .. }) if resolved_key.is_none() => {
            // Encrypted archive, no key available → prompt the user.
            return Err(OpenError::Locked { path });
        }
        Err(e) => return Err(OpenError::core(&path, &e)),
    };

    // Streamed, not collected: each `EntryMetadata` (with its owned path
    // string) is consumed and dropped before the next is built, so peak
    // memory is the retained `EntryMeta` map rather than that map PLUS a
    // full parallel Vec of core values (#662).
    let raw_entries = reader.entries();
    // A pre-allocation HINT, not a guarantee: the reader is
    // type-erased here and `ContainerReader::entries` promises nothing
    // about `size_hint`, so a future container may report 0 and cost
    // this Vec its reallocations — never correctness.
    let size_hint = raw_entries.size_hint().0;
    // Two owned copies of each path are needed — the BTreeMap key and the
    // tree's Vec — and core already allocated one, so MOVE it out with
    // `into_path` rather than copying twice. The metadata is read
    // first because that move consumes `e`.
    let mut entries = std::collections::BTreeMap::new();
    let mut paths: Vec<String> = Vec::with_capacity(size_hint);
    for e in raw_entries {
        let meta = EntryMeta {
            uncompressed_size: e.uncompressed_size(),
            compressed_size: e.compressed_size(),
            is_compressed: e.is_compressed(),
            is_encrypted: e.is_encrypted(),
            offset: e.offset(),
            // The shared form: this iteration interned it, so
            // retaining one per entry bumps a refcount rather than
            // copying bytes (a GUI-side pool was the wrong
            // home; core knows which names it can bound).
            compression_method: e.compression_method_shared(),
            // Via the reader that produced `e`, so the entry meets
            // its OWN archive's bit. The trait cannot enforce that
            // pairing (see `entry_integrity`'s docstring) — what it
            // removes is the bool a call site could get wrong, whose
            // easy wrong answer, false, is the one that hides a
            // strip. Pairing the right reader stays the caller's job,
            // and it matters once two archives are open at once.
            integrity: reader.entry_integrity(&e),
        };
        let path_str = e.into_path();
        let _ = entries.insert(path_str.clone(), meta);
        paths.push(path_str);
    }
    // One push per entry, so this IS the entry count — no separate
    // counter to drift from the loop.
    let entry_count = paths.len();
    let tree = Tree::from_paths(paths);
    Ok(LoadedArchive {
        path,
        entry_count,
        decrypted: resolved_key.is_some(),
        tree,
        tree_scroll: crate::state::row_window::ScrollPos::default(),
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
    async fn run_captures_entry_details_for_the_info_pane() {
        // #662: the open task must carry offset / method / SHA-1 status
        // from the container surface into EntryMeta. THREE fixtures so
        // every assertion is UNCONDITIONAL (a v11-only version would
        // make the SHA-1 block dead code — v11 encoded
        // records carry no hash field at all): v9_compressed supplies the
        // compressed arm, v9_multi (all-uncompressed) the uncompressed
        // arm with real hex claims, and v11 the NotInIndex arm.
        use paksmith_core::container::EntryIntegrity;

        // Every captured field is compared against the reader's OWN
        // metadata for the same entry, not merely `is_some()`: the
        // fixture's single entry sits at record offset 0, so an
        // `is_some()` assertion was satisfied just as well by a constant
        // `Some(0)`, and nothing pinned that the method name
        // belongs to THIS entry.
        // One binding for the v9 corpus — the value assertions below
        // reuse these names rather than re-spelling them.
        const V9_COMPRESSED: &str = "real_v9_compressed.pak";
        const V9_MULTI: &str = "real_v9_multi.pak";

        // Each fixture is opened ONCE: `run` retains the reader it used
        // (LoadedArchive::reader), so the oracle below is that same
        // reader re-queried, not a second parse of the same bytes.
        // Re-querying still discriminates — it compares what
        // the capture STORED against what the container surface says
        // now, which is the wiring this test names.
        let v9c = run(fixture_path(V9_COMPRESSED), None).await.unwrap();
        let v9m = run(fixture_path(V9_MULTI), None).await.unwrap();

        for (name, loaded) in [(V9_COMPRESSED, &v9c), (V9_MULTI, &v9m)] {
            let reader = &loaded.reader;
            let mut seen = 0usize;
            for e in reader.entries() {
                let m = loaded
                    .entries
                    .get(e.path())
                    .unwrap_or_else(|| panic!("{name}: {} missing from the map", e.path()));
                assert_eq!(
                    m.offset,
                    e.offset(),
                    "{name}: offset must be the entry's own"
                );
                assert_eq!(
                    m.compression_method.as_deref(),
                    e.compression_method_shared().as_deref(),
                    "{name}: method name must be the entry's own"
                );
                assert_eq!(
                    m.integrity,
                    reader.entry_integrity(&e),
                    "{name}: integrity must be the entry's own"
                );
                seen += 1;
            }
            assert!(seen > 0, "{name}: fixture must yield entries");
        }

        let compressed = v9c
            .entries
            .values()
            .find(|m| m.is_compressed)
            .expect("v9_compressed must contain a compressed entry");
        assert!(compressed.offset.is_some(), "offset must be captured");
        assert!(
            compressed.compression_method.is_some(),
            "compressed entries must carry the method name"
        );

        let uncompressed = v9m
            .entries
            .values()
            .find(|m| !m.is_compressed)
            .expect("v9_multi must contain an uncompressed entry");
        assert_eq!(
            uncompressed.compression_method, None,
            "uncompressed entries carry no method name"
        );
        for m in v9m.entries.values() {
            match &m.integrity {
                EntryIntegrity::Claim(digest) => {
                    assert!(
                        !digest.is_zero(),
                        "a real claim must not be the zero sentinel"
                    );
                }
                other => panic!("v9 inline records must yield Claim, got {other:?}"),
            }
        }

        // The v9 loops above compare each captured value against
        // `reader.entry_integrity(&e)` — the same call that produced it —
        // so they pin the per-entry PAIRING but are self-referential about
        // the value itself. This block is the one integrity assertion here
        // made against a literal, so it still fails if `entry_integrity`
        // starts answering differently. v11 also carries the only
        // hash-less records in this test's corpus.
        let v11 = run(fixture_path("real_v11_compressed.pak"), None)
            .await
            .unwrap();
        for m in v11.entries.values() {
            assert_eq!(
                m.integrity,
                EntryIntegrity::NotInIndex,
                "v11 BIT-PACKED index records carry no hash field (v10+ \
                 non-encoded entries are full Inline records that do)"
            );
        }
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
            matches!(err, OpenError::Core { .. }),
            "wrong key must produce Core decryption error — got {err:?}"
        );
    }

    #[tokio::test]
    async fn loaded_archive_retains_reader_for_entry_reads() {
        let path = fixture_path("real_v8b_uasset.pak");
        let loaded = run(path, None).await.unwrap();
        // The retained reader must be able to read an entry's bytes on demand.
        let bytes = loaded.reader.read_entry("Game/Maps/Demo.uasset").unwrap();
        assert!(!bytes.is_empty(), "retained reader must read entry bytes");
    }
}
