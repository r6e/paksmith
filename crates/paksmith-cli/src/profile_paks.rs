//! Profile-paks source resolution (issue #655): when a command is run
//! WITHOUT an explicit pak path, the `--game`/`--detect` profile's
//! `pak_paths` glob patterns are expanded into the concrete archive
//! list to operate on.
//!
//! Core stores the patterns as opaque strings; all matching happens
//! here with the CLI's existing `glob` dep (user-authored patterns are
//! the same trust level as `--filter` — see `path_util`'s note on the
//! backtracking matcher; never feed it registry-supplied input).

use std::path::{Component, Path, PathBuf};

use paksmith_core::PaksmithError;

/// Resolve the archives a command operates on: the explicit pak path
/// verbatim, or (when absent) the selected profile's expanded
/// `pak_paths`.
///
/// # Errors
///
/// Everything `profile_pak_patterns` faults on (no selector, unknown
/// id, detection 0/many, no patterns), plus expansion failures from
/// [`expand_patterns`].
pub(crate) fn resolve_pak_sources(
    explicit: Option<&Path>,
    game: Option<&str>,
    detect: Option<&Path>,
) -> paksmith_core::Result<Vec<PathBuf>> {
    if let Some(p) = explicit {
        return Ok(vec![p.to_path_buf()]);
    }
    let sel = paksmith_core::profile::resolve::profile_pak_patterns(game, detect)?;
    expand_patterns(&sel.id, &sel.patterns, detect)
}

/// Expand profile `pak_paths` glob patterns into existing archive files.
///
/// Absolute patterns stand alone; relative patterns join against the
/// `--detect` install dir (`base`) through a traversal guard (`..`,
/// root, and prefix components are rejected — same policy as
/// detection's `safe_join`). Matches are deduplicated, sorted, and
/// filtered to files; zero total matches is an error (fail-closed: a
/// profile-paks run that silently operated on nothing would read as
/// success).
fn expand_patterns(
    id: &str,
    patterns: &[String],
    base: Option<&Path>,
) -> paksmith_core::Result<Vec<PathBuf>> {
    let mut out: Vec<PathBuf> = Vec::new();
    for pattern in patterns {
        let effective: String = if Path::new(pattern).is_absolute() {
            pattern.clone()
        } else {
            let Some(dir) = base else {
                return Err(PaksmithError::InvalidArgument {
                    arg: "--detect",
                    reason: format!(
                        "profile `{id}` pattern `{pattern}` is relative and needs \
                         --detect <install-dir> to resolve against"
                    ),
                });
            };
            // The base dir is a LITERAL path, not pattern text — escape
            // its glob metacharacters (`[`, `*`, `?`, …; legal in real
            // install-dir names) so they can't corrupt or misattribute
            // the match. Only the profile's own pattern globs.
            let escaped_dir =
                std::path::PathBuf::from(glob::Pattern::escape(&dir.to_string_lossy()));
            let Some(joined) = safe_join_pattern(&escaped_dir, pattern) else {
                return Err(PaksmithError::InvalidArgument {
                    arg: "pak_paths",
                    reason: format!(
                        "profile `{id}` pattern `{pattern}` escapes the install dir \
                         (`..`, root, or prefix components are not allowed)"
                    ),
                });
            };
            joined.to_string_lossy().into_owned()
        };
        let matches = glob::glob(&effective).map_err(|e| PaksmithError::InvalidArgument {
            arg: "pak_paths",
            reason: format!("profile `{id}` pattern `{pattern}` is not a valid glob: {e}"),
        })?;
        for m in matches {
            // Unreadable match (racing deletion, permission) — skip, same
            // policy as glob itself uses for unreadable directories.
            let Ok(path) = m else { continue };
            if path.is_file() {
                out.push(path);
            }
        }
    }
    out.sort();
    out.dedup();
    if out.is_empty() {
        return Err(PaksmithError::InvalidArgument {
            arg: "pak_paths",
            reason: format!("profile `{id}` patterns matched no files"),
        });
    }
    Ok(out)
}

/// Join a RELATIVE pattern onto `dir`, rejecting parent/root/prefix
/// components (mirror of detection's `safe_join`; `.` is harmless).
/// Glob metacharacters pass through untouched — `*`/`?`/`[` are
/// ordinary `Normal` components to `Path`.
///
/// Symlink note (same documented policy as detection's `safe_join`):
/// the component guard bounds the JOINED PATH text, not what the
/// filesystem resolves it to — a symlink inside the install dir can
/// point outside it and the glob walk / archive open will follow it.
/// The profile and the `--detect` dir are the invoking user's own
/// input, so this crosses no privilege boundary (an explicit
/// `<path>` argument already grants the same read access).
fn safe_join_pattern(dir: &Path, pattern: &str) -> Option<PathBuf> {
    if pattern.is_empty() {
        return None;
    }
    let mut out = dir.to_path_buf();
    for comp in Path::new(pattern).components() {
        match comp {
            Component::Normal(c) => out.push(c),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(out)
}

/// The display form of each path, one element per path.
pub(crate) fn display_all(paths: &[PathBuf]) -> Vec<String> {
    paths.iter().map(|p| p.display().to_string()).collect()
}

/// Render a path list for human-facing labels/messages ("a, b, c").
pub(crate) fn join_display(paths: &[PathBuf]) -> String {
    display_all(paths).join(", ")
}

/// Open every source archive and collect its (filtered) entries — the
/// shared list/search loop. Per-source key resolution goes through the
/// same `resolve_pak_key` path as an explicit invocation.
pub(crate) fn collect_entry_groups(
    sources: Vec<PathBuf>,
    aes_key: Option<&paksmith_core::AesKey>,
    game: Option<&str>,
    detect: Option<&Path>,
    keep: impl Fn(&paksmith_core::container::EntryMetadata) -> bool,
) -> paksmith_core::Result<Vec<(PathBuf, Vec<paksmith_core::container::EntryMetadata>)>> {
    let mut groups = Vec::with_capacity(sources.len());
    for pak in sources {
        let key = crate::commands::key_resolve::resolve_pak_key(&pak, aes_key, game, detect)?;
        let reader = paksmith_core::container::open(&pak, key.as_ref())?;
        let entries: Vec<_> = reader.entries().filter(&keep).collect();
        groups.push((pak, entries));
    }
    Ok(groups)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn touch(p: &Path) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, b"x").unwrap();
    }

    #[test]
    fn absolute_pattern_expands_without_base() {
        let dir = tempfile::tempdir().unwrap();
        touch(&dir.path().join("Paks/a.pak"));
        touch(&dir.path().join("Paks/b.pak"));
        let pat = dir.path().join("Paks/*.pak").to_string_lossy().into_owned();
        let got = expand_patterns("hero", &[pat], None).unwrap();
        assert_eq!(got.len(), 2);
        assert!(got[0] < got[1], "sorted output");
    }

    #[test]
    fn relative_pattern_joins_against_detect_base() {
        let dir = tempfile::tempdir().unwrap();
        touch(&dir.path().join("Content/Paks/a.pak"));
        let got = expand_patterns(
            "hero",
            &["Content/Paks/*.pak".to_string()],
            Some(dir.path()),
        )
        .unwrap();
        assert_eq!(got, vec![dir.path().join("Content/Paks/a.pak")]);
    }

    #[test]
    fn relative_pattern_without_base_is_invalid_argument() {
        let err = expand_patterns("hero", &["Content/*.pak".to_string()], None).unwrap_err();
        assert!(
            matches!(
                &err,
                PaksmithError::InvalidArgument {
                    arg: "--detect",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn base_dir_with_glob_metacharacters_still_matches() {
        // The --detect dir is literal path text: a bracketed dir name
        // (real-world edition tags) must neither fail the glob compile
        // nor silently become a character class.
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("Game [2014]");
        touch(&dir.join("Paks/a.pak"));
        let got = expand_patterns("hero", &["Paks/*.pak".to_string()], Some(&dir)).unwrap();
        assert_eq!(got, vec![dir.join("Paks/a.pak")]);
    }

    #[test]
    fn parent_traversal_pattern_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let err = expand_patterns("hero", &["../outside/*.pak".to_string()], Some(dir.path()))
            .unwrap_err();
        assert!(
            matches!(
                &err,
                PaksmithError::InvalidArgument {
                    arg: "pak_paths",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn zero_matches_is_an_error_not_empty_success() {
        let dir = tempfile::tempdir().unwrap();
        let pat = dir.path().join("nope/*.pak").to_string_lossy().into_owned();
        let err = expand_patterns("hero", &[pat], None).unwrap_err();
        assert!(
            matches!(
                &err,
                PaksmithError::InvalidArgument {
                    arg: "pak_paths",
                    ..
                }
            ),
            "a run over nothing must be LOUD, got {err:?}"
        );
    }

    #[test]
    fn duplicate_matches_across_patterns_dedupe() {
        let dir = tempfile::tempdir().unwrap();
        touch(&dir.path().join("Paks/a.pak"));
        let p1 = dir.path().join("Paks/*.pak").to_string_lossy().into_owned();
        let p2 = dir.path().join("Paks/a.pak").to_string_lossy().into_owned();
        let got = expand_patterns("hero", &[p1, p2], None).unwrap();
        assert_eq!(got.len(), 1, "same file via two patterns appears once");
    }

    #[test]
    fn directories_matching_the_glob_are_filtered_out() {
        let dir = tempfile::tempdir().unwrap();
        touch(&dir.path().join("Paks/real.pak"));
        std::fs::create_dir_all(dir.path().join("Paks/fake.pak")).unwrap();
        let pat = dir.path().join("Paks/*.pak").to_string_lossy().into_owned();
        let got = expand_patterns("hero", &[pat], None).unwrap();
        assert_eq!(got, vec![dir.path().join("Paks/real.pak")]);
    }

    #[test]
    fn invalid_glob_syntax_is_invalid_argument() {
        // Built from a tempdir so the pattern is ABSOLUTE on every
        // platform — `/x/[` is relative on Windows (no drive prefix)
        // and would take the needs-`--detect` branch there instead.
        let dir = tempfile::tempdir().unwrap();
        let pat = dir.path().join("[").to_string_lossy().into_owned();
        let err = expand_patterns("hero", &[pat], None).unwrap_err();
        assert!(
            matches!(
                &err,
                PaksmithError::InvalidArgument {
                    arg: "pak_paths",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn explicit_path_bypasses_profiles_entirely() {
        // resolve_pak_sources with an explicit path never touches the
        // store — a nonexistent profile setup cannot interfere.
        let got = resolve_pak_sources(Some(Path::new("/x/y.pak")), None, None).unwrap();
        assert_eq!(got, vec![PathBuf::from("/x/y.pak")]);
    }
}
