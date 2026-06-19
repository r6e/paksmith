//! Small path helpers shared across CLI commands.

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
