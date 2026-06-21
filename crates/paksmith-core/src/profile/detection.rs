//! Declarative game auto-detection: rules stored on a profile that recognise a
//! game's install directory. Read-only, path-traversal-guarded, size-capped.
//! Network registry (5c) ships these rules so detection works for known games.

use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Maximum number of `require_paths` / `contains` rules accepted from the
/// untrusted registry (enforced by `validate_caps` in `registry::validate_caps`).
pub(crate) const MAX_REQUIRE_PATHS: usize = 64;
/// Maximum number of `contains` rules accepted from the untrusted registry.
pub(crate) const MAX_CONTAINS: usize = 64;
/// Cap on the bytes read from a `contains` target file before substring search.
pub(crate) const MAX_CONTAINS_READ: usize = 1024 * 1024;

/// Rules that recognise a game's install directory. All present rules must
/// pass (logical AND). A profile with no rules is never auto-detected.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectRules {
    /// Relative paths (file OR dir) that must ALL exist under the target dir.
    #[serde(default)]
    pub require_paths: Vec<String>,
    /// "file contains substring" rules; all must pass.
    #[serde(default)]
    pub contains: Vec<ContainsRule>,
}

/// A single "the file at `path` contains `substring`" rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainsRule {
    /// Relative path to a file under the target dir.
    pub path: String,
    /// Substring the file must contain (within the first `MAX_CONTAINS_READ` bytes).
    pub substring: String,
}

/// Join a rule's RELATIVE path onto `dir`, rejecting any escape. Returns `None`
/// for an absolute path, a root/drive prefix, a `..` parent component, or an
/// empty string — such a rule can never match and triggers no FS access on an
/// out-of-bounds path.
fn safe_join(dir: &Path, rel: &str) -> Option<PathBuf> {
    if rel.is_empty() {
        return None;
    }
    let mut out = dir.to_path_buf();
    for comp in Path::new(rel).components() {
        match comp {
            Component::Normal(c) => out.push(c),
            Component::CurDir => {} // "." — harmless
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(out)
}

/// True iff `rules` match the install directory `dir`. Read-only, bounded, and
/// traversal-guarded. A profile with no rules never matches.
pub fn rules_match(dir: &Path, rules: &DetectRules) -> bool {
    if rules.require_paths.is_empty() && rules.contains.is_empty() {
        return false;
    }
    for rel in &rules.require_paths {
        match safe_join(dir, rel) {
            Some(p) if p.exists() => {}
            _ => return false,
        }
    }
    for rule in &rules.contains {
        let Some(p) = safe_join(dir, &rule.path) else {
            return false;
        };
        if !file_contains(&p, &rule.substring) {
            return false;
        }
    }
    true
}

/// Whether the first `MAX_CONTAINS_READ` bytes of `path` contain `needle`.
/// Missing/unreadable file → false. An empty needle is trivially contained.
fn file_contains(path: &Path, needle: &str) -> bool {
    use std::io::Read as _;
    if needle.is_empty() {
        return true;
    }
    let Ok(file) = std::fs::File::open(path) else {
        return false;
    };
    let mut buf = Vec::with_capacity(MAX_CONTAINS_READ);
    if file
        .take(MAX_CONTAINS_READ as u64)
        .read_to_end(&mut buf)
        .is_err()
    {
        return false;
    }
    buf.windows(needle.len()).any(|w| w == needle.as_bytes())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;

    use super::*;
    use crate::profile::GameProfile;

    fn write(dir: &Path, rel: &str, body: &[u8]) {
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }

    // Pins the literal cap values. The matcher tests reference these constants
    // symbolically, so a mutation of the const *expression* (e.g. `1024 * 1024`
    // → `1024 + 1024`) would change production and test in lockstep and survive;
    // this asserts the concrete values directly.
    #[test]
    fn cap_constants_have_expected_values() {
        assert_eq!(MAX_REQUIRE_PATHS, 64);
        assert_eq!(MAX_CONTAINS, 64);
        assert_eq!(MAX_CONTAINS_READ, 1_048_576); // exactly 1 MiB (1024 * 1024)
    }

    #[test]
    fn matches_when_all_paths_present() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "Game/Content/Paks/x.pak", b"x");
        std::fs::create_dir_all(d.path().join("Game/Binaries")).unwrap();
        let rules = DetectRules {
            require_paths: vec!["Game/Content/Paks".into(), "Game/Binaries".into()],
            contains: vec![],
        };
        assert!(rules_match(d.path(), &rules));
    }

    #[test]
    fn no_match_when_a_path_missing() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("Game/Content/Paks")).unwrap();
        let rules = DetectRules {
            require_paths: vec!["Game/Content/Paks".into(), "Game/Missing".into()],
            contains: vec![],
        };
        assert!(!rules_match(d.path(), &rules));
    }

    #[test]
    fn contains_rule_passes_and_fails() {
        let d = tempfile::tempdir().unwrap();
        write(
            d.path(),
            "Game/Game.uproject",
            b"{\"name\":\"FortniteGame\"}",
        );
        let pass = DetectRules {
            require_paths: vec![],
            contains: vec![ContainsRule {
                path: "Game/Game.uproject".into(),
                substring: "FortniteGame".into(),
            }],
        };
        assert!(rules_match(d.path(), &pass));
        let fail = DetectRules {
            require_paths: vec![],
            contains: vec![ContainsRule {
                path: "Game/Game.uproject".into(),
                substring: "NotPresent".into(),
            }],
        };
        assert!(!rules_match(d.path(), &fail));
        let missing = DetectRules {
            require_paths: vec![],
            contains: vec![ContainsRule {
                path: "Game/Nope".into(),
                substring: "x".into(),
            }],
        };
        assert!(!rules_match(d.path(), &missing));
    }

    #[test]
    fn path_traversal_and_absolute_rules_do_not_match_or_escape() {
        let d = tempfile::tempdir().unwrap();
        // a real file OUTSIDE the dir that a traversal rule might try to reach
        let outside = d.path().parent().unwrap().join("secret.txt");
        let _ = std::fs::write(&outside, b"top secret");
        for bad in [
            "../secret.txt",
            "../../etc/passwd",
            "/etc/passwd",
            "",
            "Game/../../escape",
        ] {
            let rules = DetectRules {
                require_paths: vec![bad.to_string()],
                contains: vec![],
            };
            assert!(
                !rules_match(d.path(), &rules),
                "traversal/abs path `{bad}` must not match"
            );
        }
        let _ = std::fs::remove_file(&outside);
    }

    #[test]
    fn contains_rule_traversal_and_absolute_paths_do_not_match_or_escape() {
        let d = tempfile::tempdir().unwrap();
        // a real file OUTSIDE the dir that a traversal rule might try to reach
        let outside = d.path().parent().unwrap().join("secret.txt");
        let _ = std::fs::write(&outside, b"top secret");
        for bad in [
            "../secret.txt",
            "../../etc/passwd",
            "/etc/passwd",
            "",
            "Game/../../escape",
        ] {
            let rules = DetectRules {
                require_paths: vec![],
                contains: vec![ContainsRule {
                    path: bad.into(),
                    substring: "x".into(),
                }],
            };
            assert!(
                !rules_match(d.path(), &rules),
                "ContainsRule traversal/abs path `{bad}` must not match"
            );
        }
        let _ = std::fs::remove_file(&outside);
    }

    #[test]
    fn empty_rules_never_match() {
        let d = tempfile::tempdir().unwrap();
        assert!(!rules_match(d.path(), &DetectRules::default()));
    }

    #[test]
    fn contains_read_is_bounded() {
        let d = tempfile::tempdir().unwrap();
        // substring placed BEYOND the 1 MiB cap → not found.
        let mut body = vec![b'.'; MAX_CONTAINS_READ + 16];
        body.extend_from_slice(b"PAST_CAP");
        write(d.path(), "big.bin", &body);
        let rules = DetectRules {
            require_paths: vec![],
            contains: vec![ContainsRule {
                path: "big.bin".into(),
                substring: "PAST_CAP".into(),
            }],
        };
        assert!(
            !rules_match(d.path(), &rules),
            "substring beyond the read cap must not match"
        );
    }

    #[test]
    fn contains_read_cap_truncates_straddling_needle() {
        let d = tempfile::tempdir().unwrap();
        // Write exactly MAX_CONTAINS_READ bytes of filler followed by a needle
        // whose first byte starts at MAX_CONTAINS_READ - 2, so half of it falls
        // inside the cap and half outside.  The read truncates at MAX_CONTAINS_READ,
        // so the full needle can never be matched.
        let needle = b"STRADDLE";
        let overlap = 2usize;
        // filler: (MAX_CONTAINS_READ - overlap) bytes of '.', then the needle
        let mut body = vec![b'.'; MAX_CONTAINS_READ - overlap];
        body.extend_from_slice(needle);
        // The needle starts at index (MAX_CONTAINS_READ - overlap), so the first
        // `overlap` bytes of it land within the cap window; the rest are cut off.
        write(d.path(), "straddle.bin", &body);
        let rules = DetectRules {
            require_paths: vec![],
            contains: vec![ContainsRule {
                path: "straddle.bin".into(),
                substring: String::from_utf8(needle.to_vec()).unwrap(),
            }],
        };
        assert!(
            !rules_match(d.path(), &rules),
            "needle straddling the read cap must not match"
        );
    }

    #[test]
    fn detect_rules_toml_roundtrip() {
        let p = GameProfile {
            name: "G".into(),
            engine_version: None,
            keys: BTreeMap::default(),
            detect: Some(DetectRules {
                require_paths: vec!["Game/Content/Paks".into()],
                contains: vec![ContainsRule {
                    path: "Game/Game.uproject".into(),
                    substring: "Game".into(),
                }],
            }),
        };
        let text = toml::to_string_pretty(&p).unwrap();
        assert!(text.contains("require_paths"));
        let back: GameProfile = toml::from_str(&text).unwrap();
        let d = back.detect.unwrap();
        assert_eq!(d.require_paths, vec!["Game/Content/Paks".to_string()]);
        assert_eq!(d.contains[0].substring, "Game");
    }

    #[test]
    fn absent_detect_is_omitted_from_toml() {
        let p = GameProfile {
            name: "G".into(),
            engine_version: None,
            keys: BTreeMap::default(),
            detect: None,
        };
        let text = toml::to_string_pretty(&p).unwrap();
        assert!(
            !text.contains("detect"),
            "absent detect must not serialize: {text}"
        );
    }
}
