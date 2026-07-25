//! Small path helpers shared across CLI commands.

/// Compile a glob pattern for an entry-matching flag. What the glob is
/// matched AGAINST (full virtual path for `--filter`, basename for
/// search's `--name`) is each call site's contract, not this helper's.
/// Returns the glob error's message on failure; search's predicate
/// compiler wraps it in its `(flag, reason)` tuple, and
/// [`compile_opt_glob_arg`] wraps it for the `InvalidArgument` callers.
///
/// Complexity note: `glob` is a backtracking matcher — pathological
/// patterns (`a*a*a*…b`) are super-linear against long non-matching
/// paths, unlike the linear-time `--regex` predicate. Bounded in
/// practice (patterns are the invoking user's own input; core caps
/// paths at 64 Ki UTF-16 code units), so self-inflicted only — do not
/// expose glob matching to pak-supplied patterns.
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

/// [`compile_glob`] over an OPTIONAL pattern, wrapped as
/// `PaksmithError::InvalidArgument` under `arg` — the whole
/// `Option<String>` → `Option<Pattern>` shape list/extract share for
/// `--filter`.
pub(crate) fn compile_opt_glob_arg(
    arg: &'static str,
    pattern: Option<&str>,
) -> paksmith_core::Result<Option<glob::Pattern>> {
    pattern
        .map(|p| {
            compile_glob(p)
                .map_err(|reason| paksmith_core::PaksmithError::InvalidArgument { arg, reason })
        })
        .transpose()
}
