use std::path::{Component, Path, PathBuf};

/// Why a pak entry path could not be safely mapped under the output root.
#[derive(Debug)]
pub(crate) enum SafePathError {
    /// The entry path escaped the output root (`..`, absolute, drive/UNC),
    /// or flattening left nothing. Carries the offending entry path.
    Escapes(String),
    /// The entry path was empty.
    Empty,
    /// A joined component names a Windows DOS device (`NUL`, `CON`, `COM1`, …),
    /// which Win32 can route to the device instead of a file. Carries
    /// the offending entry path.
    DeviceName(String),
}

impl std::fmt::Display for SafePathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Escapes(p) => write!(f, "entry path escapes output directory: {p}"),
            Self::Empty => write!(f, "empty entry path"),
            Self::DeviceName(p) => write!(f, "entry path names a reserved device: {p}"),
        }
    }
}

/// Whether Win32 would route `component` to a DOS device: its name up to
/// the first `.` or `:`, with trailing spaces dropped, is a reserved device
/// name in any case, so `NUL`, `con.txt`, `aux:stream` and `COM1 .bin` all
/// qualify. This is the widest mapping; Windows 11 routes fewer shapes.
fn is_dos_device_name(component: &str) -> bool {
    let stem = component
        .split_once(['.', ':'])
        .map_or(component, |(stem, _)| stem)
        .trim_end_matches(' ');
    is_reserved_device(&stem.to_ascii_uppercase())
}

fn is_reserved_device(upper: &str) -> bool {
    if matches!(upper, "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$") {
        return true;
    }
    let Some(port) = upper
        .strip_prefix("COM")
        .or_else(|| upper.strip_prefix("LPT"))
    else {
        return false;
    };
    // Microsoft's naming doc also reserves the ISO 8859-1 superscripts as ports.
    let mut chars = port.chars();
    matches!(
        (chars.next(), chars.next()),
        (Some('1'..='9' | '¹' | '²' | '³'), None)
    )
}

/// Map an untrusted pak `entry_path` to a path strictly under `output_root`.
///
/// Lexical only — never canonicalizes: the leaf does not exist yet, and where
/// the existing ancestor chain RESOLVES is checked by
/// `verify_resolves_inside_root` in `extract/mod.rs`. Backslashes are
/// normalized to `/` so Windows-style separators can't smuggle traversal.
/// Rejects `..`, absolute roots, and Windows drive/UNC prefixes. Also rejects,
/// on every platform, any joined component that names a DOS device, since
/// `create_dir_all` makes each directory the last component of its own call;
/// under `flat` only the file name is joined.
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
        if is_dos_device_name(part) {
            return Err(SafePathError::DeviceName(entry_path.to_string()));
        }
        // Windows-only prefix re-parse guard; the mechanism is documented on
        // `paksmith_core`'s detection `safe_join` (#658). Site-specific reason
        // it is needed HERE: the leading-drive check above inspects offsets 0-1
        // of the WHOLE string, so a non-leading `a/C:/…` sails past it — and
        // this is the copy that maps untrusted pak entry paths to a write.
        if !matches!(
            Path::new(part).components().next(),
            Some(Component::Normal(_))
        ) {
            return Err(SafePathError::Escapes(entry_path.to_string()));
        }
        candidate.push(part);
    }

    // Containment postcondition; like detection's, redundant by construction
    // given the guard above and kept as defence in depth. Do not simplify it to
    // `starts_with`: that is LEXICAL and accepts a `..` tail, so every component
    // past the root must be `Normal` too.
    let contained = candidate
        .strip_prefix(output_root)
        .is_ok_and(|tail| tail.components().all(|c| matches!(c, Component::Normal(_))));
    if !contained {
        return Err(SafePathError::Escapes(entry_path.to_string()));
    }

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
        assert_eq!(
            SafePathError::DeviceName("Game/NUL".to_string()).to_string(),
            "entry path names a reserved device: Game/NUL"
        );
    }

    /// Every component an entry adds is checked, not only the file name (#811).
    #[test]
    fn rejects_dos_device_names_in_any_joined_component() {
        for entry in [
            "Game/NUL",
            "Game/con",
            "Game/CON.uasset",
            "Game/nul.tar.gz",
            "Game/Aux.",
            "Game/PRN ",
            "Game/NUL .txt",
            "Game/COM1",
            "Game/LPT9.txt",
            "Game/COM¹",
            "Game/lpt²",
            "Game/lpt³.dat",
            "Game/NUL:",
            "Game/aux:stream",
            "Game/NUL:.txt",
            "Game/CONIN$",
            "Game/conout$.txt",
            "CON/Hero.uasset",
            "Game/NUL/Hero.uasset",
        ] {
            assert!(
                matches!(
                    safe_join(&root(), entry, false),
                    Err(SafePathError::DeviceName(_))
                ),
                "{entry:?} must be refused"
            );
        }
    }

    /// `--flat` joins only the file name: a device-named file is refused, and
    /// a device-named directory it discards is never created, so it is not
    /// refused.
    #[test]
    fn flat_checks_only_the_file_name_for_devices() {
        assert!(matches!(
            safe_join(&root(), "Game/Sub/PRN.bin", true),
            Err(SafePathError::DeviceName(_))
        ));
        let p = safe_join(&root(), "CON/Hero.uasset", true).unwrap();
        assert_eq!(p, PathBuf::from("/out/Hero.uasset"));
    }

    const DEVICE_LOOKALIKES: &[&str] = &[
        "CONSOLE.uasset",
        "NULL",
        "COM10",
        "LPT",
        "con_data.bin",
        "xCON",
        " NUL",
        "COM1x.bin",
        "CONIN",
        "CONERR$",
        "data:stream",
        "data:COM1",
        "com0.bin",
        "LPT0",
    ];

    #[test]
    fn accepts_names_that_only_resemble_devices() {
        for name in DEVICE_LOOKALIKES {
            let entry = format!("Game/{name}");
            assert!(
                safe_join(&root(), &entry, false).is_ok(),
                "{entry:?} must be accepted"
            );
        }
    }

    /// The host's own path API agrees that no accepted lookalike is a device,
    /// as a whole path or as a leaf of an existing directory: `GetFullPathNameW`
    /// rewrites a device path to `\\.\<device>`, as it does for a bare `COM1`
    /// and a leaf `NUL` (#811).
    #[cfg(windows)]
    #[test]
    fn the_host_maps_no_accepted_lookalike_to_a_device() {
        let maps_to_device = |path: &Path| {
            std::path::absolute(path)
                .unwrap()
                .to_string_lossy()
                .starts_with(r"\\.\")
        };
        let dir = tempfile::tempdir().unwrap();
        let leaf = |name: &str| dir.path().join(name);
        assert!(maps_to_device(Path::new("COM1")), "bare control");
        assert!(maps_to_device(&leaf("NUL")), "leaf control");
        for &name in DEVICE_LOOKALIKES {
            for path in [PathBuf::from(name), leaf(name)] {
                assert!(!maps_to_device(&path), "{path:?} maps to a device");
            }
        }
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

    /// A NON-LEADING drive prefix must not escape the output root. The leading
    /// check inspects offsets 0-1 of the whole string, so `a/C:/…` passes it and
    /// `push` then replaces the buffer. Only executes on `windows-latest`; a
    /// colon is an ordinary filename byte elsewhere.
    #[cfg(windows)]
    #[test]
    fn rejects_non_leading_drive_prefix() {
        // BARE-DRIVE root first: the only shape the postcondition cannot
        // backstop, so it is the one that pins the LOOP guard. With a rooted
        // root like `/out` a replaced buffer fails `strip_prefix` anyway, so
        // those cases cannot tell which guard fired. Deleting the loop guard
        // makes this `Ok("C:x")`. Not `a/C:..` — the all-`Normal` tail would
        // catch that one regardless.
        assert!(matches!(
            safe_join(Path::new("C:"), "a/C:x", false),
            Err(SafePathError::Escapes(_))
        ));
        // Nested: the drive segment replaces the buffer mid-join.
        for evil in ["a/C:/Windows/Temp/x.dll", "a/C:x", "a/C:../pwn.exe"] {
            assert!(
                matches!(
                    safe_join(&root(), evil, false),
                    Err(SafePathError::Escapes(_))
                ),
                "accepted {evil}"
            );
        }
        // `--flat` keeps only the LAST segment, so it escapes exactly when that
        // segment is the drive-like one — `a/C:/Windows/x.dll` flattens to
        // `x.dll` and is contained, which is why it is not listed here.
        for evil in ["a/C:x", "a/C:.."] {
            assert!(
                matches!(
                    safe_join(&root(), evil, true),
                    Err(SafePathError::Escapes(_))
                ),
                "accepted flat {evil}"
            );
        }
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
