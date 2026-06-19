use std::path::{Component, Path, PathBuf};

/// Why a pak entry path could not be safely mapped under the output root.
#[derive(Debug)]
pub(crate) enum SafePathError {
    /// The entry path escaped the output root (`..`, absolute, drive/UNC),
    /// or flattening left nothing. Carries the offending entry path.
    Escapes(String),
    /// The entry path was empty.
    Empty,
}

impl std::fmt::Display for SafePathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Escapes(p) => write!(f, "entry path escapes output directory: {p}"),
            Self::Empty => write!(f, "empty entry path"),
        }
    }
}

/// Map an untrusted pak `entry_path` to a path strictly under `output_root`.
///
/// Lexical only — never canonicalizes (targets don't exist yet; canonicalize
/// is TOCTOU-prone). Backslashes are normalized to `/` so Windows-style
/// separators can't smuggle traversal. Rejects `..`, absolute roots, and
/// Windows drive/UNC prefixes.
pub(crate) fn safe_join(
    output_root: &Path,
    entry_path: &str,
    flat: bool,
) -> Result<PathBuf, SafePathError> {
    if entry_path.is_empty() {
        return Err(SafePathError::Empty);
    }

    let normalized = entry_path.replace('\\', "/");

    // Reject POSIX-absolute and Windows drive/UNC up front.
    if normalized.starts_with('/') {
        return Err(SafePathError::Escapes(entry_path.to_string()));
    }
    let bytes = normalized.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        return Err(SafePathError::Escapes(entry_path.to_string())); // C:
    }

    // Collect clean components; reject any `..` or rooted component.
    let mut parts: Vec<&str> = Vec::new();
    for seg in normalized.split('/') {
        match seg {
            "" | "." => {}
            ".." => return Err(SafePathError::Escapes(entry_path.to_string())),
            other => parts.push(other),
        }
    }

    let chosen: &[&str] = if flat {
        match parts.last() {
            Some(name) => std::slice::from_ref(name),
            None => return Err(SafePathError::Escapes(entry_path.to_string())),
        }
    } else {
        &parts
    };

    if chosen.is_empty() {
        return Err(SafePathError::Escapes(entry_path.to_string()));
    }

    let mut candidate = output_root.to_path_buf();
    for part in chosen {
        candidate.push(part);
    }

    // Defensive: confirm no component re-introduced a parent escape.
    debug_assert!(
        !candidate
            .components()
            .any(|c| matches!(c, Component::ParentDir)),
        "sanitized path still contains ParentDir"
    );

    Ok(candidate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn root() -> PathBuf {
        PathBuf::from("/out")
    }

    #[test]
    fn normal_path_mirrors_under_root() {
        let p = safe_join(&root(), "Game/Hero.uasset", false).unwrap();
        assert_eq!(p, PathBuf::from("/out/Game/Hero.uasset"));
    }

    #[test]
    fn flat_keeps_only_basename() {
        let p = safe_join(&root(), "Game/Sub/Hero.uasset", true).unwrap();
        assert_eq!(p, PathBuf::from("/out/Hero.uasset"));
    }

    #[test]
    fn error_display_is_informative() {
        // Pins the Display impl's actual output (a no-op `fmt` would pass an
        // `is_err()`/`matches!` check but produce an empty, useless message).
        let escapes = SafePathError::Escapes("../etc/passwd".to_string()).to_string();
        assert!(escapes.contains("../etc/passwd"), "got {escapes}");
        assert!(escapes.contains("escapes"), "got {escapes}");
        assert_eq!(SafePathError::Empty.to_string(), "empty entry path");
    }

    #[test]
    fn rejects_parent_traversal() {
        assert!(matches!(
            safe_join(&root(), "../../etc/passwd", false),
            Err(SafePathError::Escapes(_))
        ));
    }

    #[test]
    fn rejects_embedded_parent() {
        assert!(matches!(
            safe_join(&root(), "Game/../../etc/passwd", false),
            Err(SafePathError::Escapes(_))
        ));
    }

    #[test]
    fn rejects_posix_absolute() {
        assert!(matches!(
            safe_join(&root(), "/etc/passwd", false),
            Err(SafePathError::Escapes(_))
        ));
    }

    #[test]
    fn rejects_windows_drive_and_unc() {
        for evil in ["C:\\Windows\\system32", "\\\\server\\share\\x"] {
            assert!(
                matches!(
                    safe_join(&root(), evil, false),
                    Err(SafePathError::Escapes(_))
                ),
                "accepted {evil}"
            );
        }
    }

    #[test]
    fn rejects_empty() {
        assert!(matches!(
            safe_join(&root(), "", false),
            Err(SafePathError::Empty)
        ));
        assert!(matches!(
            safe_join(&root(), "../..", true),
            Err(SafePathError::Escapes(_))
        ));
    }

    #[test]
    fn handles_mixed_separators() {
        // Backslash is a path char on Unix but a separator on Windows;
        // we normalize backslashes to forward slashes before splitting
        // so a Windows-style entry can't smuggle a traversal.
        assert!(matches!(
            safe_join(&root(), "Game\\..\\..\\etc", false),
            Err(SafePathError::Escapes(_))
        ));
    }

    #[test]
    fn rejects_dot_only_path() {
        assert!(matches!(
            safe_join(&root(), ".", false),
            Err(SafePathError::Escapes(_))
        ));
        assert!(matches!(
            safe_join(&root(), "./.", false),
            Err(SafePathError::Escapes(_))
        ));
    }

    #[test]
    fn rejects_separator_only_path() {
        for evil in ["//", "///"] {
            assert!(
                matches!(
                    safe_join(&root(), evil, false),
                    Err(SafePathError::Escapes(_))
                ),
                "accepted {evil}"
            );
        }
    }
}
