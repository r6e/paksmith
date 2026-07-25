//! Small path helpers shared across CLI commands.

/// Compile a `--filter`-style glob (matched against FULL virtual paths).
/// Returns the glob error's message on failure; callers wrap it in their
/// own error shape (`InvalidArgument` in list/extract, the
/// `(flag, reason)` tuple in search's predicate compiler).
pub(crate) fn compile_glob(pattern: &str) -> Result<glob::Pattern, String> {
    glob::Pattern::new(pattern).map_err(|e| e.to_string())
}

/// Final path component (basename) of a `/`-separated virtual path.
pub(crate) fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Lowercased extension of a basename — `None` for no-extension or a
/// leading-dot dotfile (`.foo` has no extension).
pub(crate) fn extension_of(basename: &str) -> Option<String> {
    basename
        .rfind('.')
        .filter(|&i| i > 0)
        .map(|i| basename[i + 1..].to_ascii_lowercase())
}
