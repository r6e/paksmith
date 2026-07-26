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
/// Maximum number of `bytes` rules accepted from the untrusted registry.
///
/// Matches [`MAX_CONTAINS`] because the two rule kinds cost the same: each
/// reads up to [`MAX_CONTAINS_READ`] from one file and scans it once. Widening
/// that window is deliberately NOT part of this rule kind — detection already
/// amplifies across profiles, and the window is the multiplier (see #658).
pub(crate) const MAX_BYTES_RULES: usize = 64;

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
    /// "file contains byte signature" rules; all must pass (#658).
    ///
    /// `#[serde(default)]`, so documents written before this field existed
    /// still parse. Note the reverse is NOT true: [`DetectRules`] is
    /// `deny_unknown_fields` and the registry document is ed25519-signed, so a
    /// document USING this field is rejected outright by any binary built
    /// before it — which is why the field landed while the default endpoint is
    /// still a placeholder (#657) and no signed document is in circulation.
    #[serde(default)]
    pub bytes: Vec<BytesRule>,
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

/// A single "the file at `path` contains this byte signature" rule.
///
/// Exists because [`ContainsRule`]'s `substring` is a Rust `String` and so can
/// only express valid UTF-8. A binary signature — the heuristic class ROADMAP
/// §Phase 5 lists alongside subdirectory patterns and `.ini` contents — is
/// arbitrary bytes, and the ones that identify a build routinely are not
/// UTF-8.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BytesRule {
    /// Relative path to a file under the target dir.
    pub path: String,
    /// The signature as lowercase-or-uppercase hex, no separators and NO `0x`
    /// prefix — an even number of hex digits, decoded to the raw bytes searched
    /// for within the same bounded read window as `contains`
    /// (`MAX_CONTAINS_READ`, 1 MiB).
    ///
    /// Two deliberate divergences a reader will otherwise trip over:
    ///
    /// - **No `0x` prefix**, unlike [`crate::KeyGuid::from_hex`] and
    ///   `AesKey::from_hex`. Those decode fixed-width integers where a prefix
    ///   is idiomatic; this is a byte string of caller-chosen length, and
    ///   accepting a prefix would make `"0xAB"` mean one byte while `"0x0AB"`
    ///   is odd-length garbage. Even-length pure hex is the whole contract.
    /// - **Undecodable or EMPTY never matches**, whereas [`ContainsRule`]'s
    ///   empty `substring` is vacuously true. A detection rule that matches
    ///   every directory is a footgun; this form fails closed instead of
    ///   inheriting it.
    ///
    /// Capped by the registry's `MAX_STR` as a STRING, so at most 128
    /// decoded bytes.
    pub hex: String,
}

/// Decode an even-length, unprefixed, case-insensitive hex string to bytes.
///
/// `None` for odd length, any non-hex byte, or the empty string — every one of
/// which makes the owning rule fail to match rather than error, because a
/// malformed rule in a signed document must not fail the whole detection pass.
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    /// One hex digit → its nibble value. `None` for anything else, which is
    /// the ONLY non-hex rejection — an `is_ascii_hexdigit` pre-check ahead of
    /// this would be unreachable, and so an untestable branch.
    fn nibble(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }

    // Byte length, deliberately: a multi-byte char can make the length even
    // while the digit count is odd, and `nibble` then rejects its bytes.
    if s.is_empty() || !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in s.as_bytes().chunks(2) {
        // Two nibbles are at most 0xFF, so this cannot overflow and needs no
        // fallible conversion.
        out.push(nibble(pair[0])? * 16 + nibble(pair[1])?);
    }
    Some(out)
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
///
/// **Symlink note:** `safe_join` rejects rule strings that encode a path escape
/// (`..`, absolute, or root components), but an existing symlink *inside* `dir`
/// that points outside is followed by the OS as usual. A `require_paths` or
/// `contains` rule can therefore observe the existence or up-to-`MAX_CONTAINS_READ`
/// bytes of a file reachable via an in-directory symlink — this is a documented
/// limitation, not a traversal guard bypass. No behavior change.
pub fn rules_match(dir: &Path, rules: &DetectRules) -> bool {
    if rules.require_paths.is_empty() && rules.contains.is_empty() && rules.bytes.is_empty() {
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
    for rule in &rules.bytes {
        let Some(p) = safe_join(dir, &rule.path) else {
            return false;
        };
        // Undecodable or empty → fail closed. See `BytesRule::hex`.
        let Some(needle) = decode_hex(&rule.hex) else {
            return false;
        };
        if !file_contains_bytes(&p, &needle) {
            return false;
        }
    }
    true
}

/// Whether the first `MAX_CONTAINS_READ` bytes of `path` contain `needle`.
/// Missing/unreadable file → false. An empty needle is trivially contained.
fn file_contains(path: &Path, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    file_contains_bytes(path, needle.as_bytes())
}

/// Whether the first [`MAX_CONTAINS_READ`] bytes of `path` contain `needle`.
/// Missing/unreadable file → false.
///
/// The shared read-and-scan for both rule kinds. The EMPTY-needle policy is
/// deliberately left to each caller — `contains` treats it as vacuously true
/// (pre-existing), `bytes` refuses it — so this function is never called with
/// an empty needle and does not have to pick.
fn file_contains_bytes(path: &Path, needle: &[u8]) -> bool {
    use std::io::Read as _;
    debug_assert!(!needle.is_empty(), "callers own the empty-needle policy");
    let Ok(file) = std::fs::File::open(path) else {
        return false;
    };
    // Grow on demand (capped by `take` below) rather than reserving a full
    // `MAX_CONTAINS_READ` up front — a tiny marker file shouldn't reserve 1 MiB,
    // and across the contains-rule cap that eager reservation could total tens
    // of MiB transiently.
    let mut buf = Vec::new();
    if file
        .take(MAX_CONTAINS_READ as u64)
        .read_to_end(&mut buf)
        .is_err()
    {
        return false;
    }
    buf.windows(needle.len()).any(|w| w == needle)
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

    // ---------------------------------------------------------------------
    // Byte-signature rules (#658 item 3). ROADMAP §Phase 5 lists "binary
    // signatures in executables" as a detection heuristic; `contains` could
    // only express UTF-8 substrings, so a signature with non-UTF-8 bytes was
    // inexpressible.
    // ---------------------------------------------------------------------

    fn bytes_rules(path: &str, hex: &str) -> DetectRules {
        DetectRules {
            require_paths: Vec::new(),
            contains: Vec::new(),
            bytes: vec![BytesRule {
                path: path.into(),
                hex: hex.into(),
            }],
        }
    }

    /// A signature of bytes that are NOT valid UTF-8 — the capability
    /// `contains` structurally could not provide.
    #[test]
    fn byte_signature_matches_non_utf8_bytes() {
        let d = tempfile::tempdir().unwrap();
        // 0xFF 0xFE is not valid UTF-8, so no `substring` rule can express it.
        write(d.path(), "game.exe", &[0x00, 0x11, 0xFF, 0xFE, 0x22]);
        assert!(rules_match(d.path(), &bytes_rules("game.exe", "fffe")));
        assert!(rules_match(
            d.path(),
            &bytes_rules("game.exe", "0011fffe22")
        ));
    }

    /// Hex is case-insensitive; an absent signature does not match.
    #[test]
    fn byte_signature_is_case_insensitive_and_absent_does_not_match() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "game.exe", &[0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(rules_match(d.path(), &bytes_rules("game.exe", "DEADBEEF")));
        assert!(rules_match(d.path(), &bytes_rules("game.exe", "deadbeef")));
        assert!(!rules_match(d.path(), &bytes_rules("game.exe", "deadbeee")));
    }

    /// A malformed or empty hex needle NEVER matches — fail-closed, and a
    /// DELIBERATE divergence from `contains`, whose empty `substring` is
    /// vacuously true. An auto-detection rule that matches every directory is
    /// a footgun, so the byte form refuses rather than inherits it.
    #[test]
    fn malformed_or_empty_hex_never_matches() {
        let d = tempfile::tempdir().unwrap();
        // Contains a ZERO byte on purpose. A non-hex digit that decoded to 0
        // instead of rejecting would yield a needle of `[0x00, …]`, which a
        // file WITHOUT a zero byte would fail to contain anyway — masking the
        // defect. With the zero byte present, only a genuine rejection keeps
        // these from matching.
        write(d.path(), "game.exe", &[0x00, 0xDE, 0xAD, 0x00]);
        for bad in [
            "",         // empty: NOT vacuously true, unlike `substring`
            "d",        // odd length
            "deadb",    // odd length
            "zz",       // non-hex — would be `[0x00]` if a non-hex digit
            "zzzz",     // non-hex — would be `[0x00, 0x00]`
            "00zz",     // half-valid: a partial decode must not be used
            "de ad",    // internal space
            "0xdead",   // no `0x` prefix accepted (see BytesRule's doc)
            "00\u{e9}", // multi-byte char: even BYTE length, odd digit count
        ] {
            assert!(
                !rules_match(d.path(), &bytes_rules("game.exe", bad)),
                "hex {bad:?} must not match"
            );
        }
    }

    /// A missing file does not match, and — unlike `contains` with an empty
    /// substring — an undecodable needle does not short-circuit to true before
    /// the file is even consulted.
    #[test]
    fn byte_signature_missing_file_does_not_match() {
        let d = tempfile::tempdir().unwrap();
        assert!(!rules_match(d.path(), &bytes_rules("absent.exe", "dead")));
        assert!(!rules_match(d.path(), &bytes_rules("absent.exe", "")));
    }

    /// Traversal-guarded like every other rule kind.
    #[test]
    fn byte_signature_rejects_path_escape() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "game.exe", &[0xDE, 0xAD]);
        for esc in ["../game.exe", "/etc/passwd", ""] {
            assert!(
                !rules_match(d.path(), &bytes_rules(esc, "dead")),
                "path {esc:?} must not match"
            );
        }
    }

    /// Bounded by the same window as `contains`: a signature past
    /// `MAX_CONTAINS_READ` is not found.
    #[test]
    fn byte_signature_is_bounded_by_the_read_window() {
        let d = tempfile::tempdir().unwrap();
        let mut body = vec![0u8; MAX_CONTAINS_READ];
        body.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        write(d.path(), "big.exe", &body);
        assert!(
            !rules_match(d.path(), &bytes_rules("big.exe", "deadbeef")),
            "a signature beyond the read window must not match"
        );
        // …and the same signature inside the window does match, so the test
        // above fails for the window and not for the decoding.
        let mut inside = vec![0u8; 16];
        inside.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        write(d.path(), "small.exe", &inside);
        assert!(rules_match(d.path(), &bytes_rules("small.exe", "deadbeef")));
    }

    /// Rule kinds AND together, and `bytes` alone is enough to be detectable
    /// (a profile with only byte rules is not "no rules").
    #[test]
    fn bytes_rules_and_with_other_kinds_and_stand_alone() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "game.exe", &[0xDE, 0xAD]);
        write(d.path(), "cfg.ini", b"Engine=UE5");

        // bytes alone: detectable.
        assert!(rules_match(d.path(), &bytes_rules("game.exe", "dead")));

        // Combined with a passing contains + require_paths.
        let all = DetectRules {
            require_paths: vec!["cfg.ini".into()],
            contains: vec![ContainsRule {
                path: "cfg.ini".into(),
                substring: "UE5".into(),
            }],
            bytes: vec![BytesRule {
                path: "game.exe".into(),
                hex: "dead".into(),
            }],
        };
        assert!(rules_match(d.path(), &all));

        // A failing byte rule fails the whole conjunction even when the others pass.
        let mut one_bad = all.clone();
        one_bad.bytes[0].hex = "beef".into();
        assert!(!rules_match(d.path(), &one_bad));
    }

    #[test]
    fn byte_rule_cap_constant_has_expected_value() {
        assert_eq!(MAX_BYTES_RULES, 64);
    }

    #[test]
    fn matches_when_all_paths_present() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "Game/Content/Paks/x.pak", b"x");
        std::fs::create_dir_all(d.path().join("Game/Binaries")).unwrap();
        let rules = DetectRules {
            require_paths: vec!["Game/Content/Paks".into(), "Game/Binaries".into()],
            contains: vec![],
            bytes: Vec::new(),
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
            bytes: Vec::new(),
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
            bytes: Vec::new(),
        };
        assert!(rules_match(d.path(), &pass));
        let fail = DetectRules {
            require_paths: vec![],
            contains: vec![ContainsRule {
                path: "Game/Game.uproject".into(),
                substring: "NotPresent".into(),
            }],
            bytes: Vec::new(),
        };
        assert!(!rules_match(d.path(), &fail));
        let missing = DetectRules {
            require_paths: vec![],
            contains: vec![ContainsRule {
                path: "Game/Nope".into(),
                substring: "x".into(),
            }],
            bytes: Vec::new(),
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
                bytes: Vec::new(),
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
                bytes: Vec::new(),
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
            bytes: Vec::new(),
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
            bytes: Vec::new(),
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
                bytes: Vec::new(),
            }),
            mappings: None,
            pak_paths: Vec::new(),
        };
        let text = toml::to_string_pretty(&p).unwrap();
        assert!(text.contains("require_paths"));
        let back: GameProfile = toml::from_str(&text).unwrap();
        let d = back.detect.unwrap();
        assert_eq!(d.require_paths, vec!["Game/Content/Paks".to_string()]);
        assert_eq!(d.contains[0].substring, "Game");
        assert!(d.bytes.is_empty());
    }

    /// Byte rules survive the local store's TOML round-trip, and `hex` is
    /// carried verbatim rather than normalized — a store written by hand keeps
    /// whatever case the author used.
    #[test]
    fn byte_rules_toml_roundtrip() {
        let p = GameProfile {
            name: "G".into(),
            engine_version: None,
            keys: BTreeMap::default(),
            detect: Some(DetectRules {
                require_paths: Vec::new(),
                contains: Vec::new(),
                bytes: vec![BytesRule {
                    path: "Game/Binaries/Win64/Game.exe".into(),
                    hex: "DEADbeef".into(),
                }],
            }),
            mappings: None,
            pak_paths: Vec::new(),
        };
        let text = toml::to_string_pretty(&p).unwrap();
        assert!(text.contains("bytes"), "{text}");
        let back: GameProfile = toml::from_str(&text).unwrap();
        let d = back.detect.unwrap();
        assert_eq!(d.bytes[0].path, "Game/Binaries/Win64/Game.exe");
        assert_eq!(d.bytes[0].hex, "DEADbeef");
        assert!(d.require_paths.is_empty() && d.contains.is_empty());
    }

    /// A store written before `bytes` existed still loads (`serde(default)`),
    /// which is the compatibility direction that holds for the local store too.
    #[test]
    fn store_without_bytes_field_still_loads() {
        let text = r#"
name = "G"

[detect]
require_paths = ["Game/Paks"]
"#;
        let back: GameProfile = toml::from_str(text).unwrap();
        assert!(back.detect.unwrap().bytes.is_empty());
    }

    #[test]
    fn absent_detect_is_omitted_from_toml() {
        let p = GameProfile {
            name: "G".into(),
            engine_version: None,
            keys: BTreeMap::default(),
            detect: None,
            mappings: None,
            pak_paths: Vec::new(),
        };
        let text = toml::to_string_pretty(&p).unwrap();
        assert!(
            !text.contains("detect"),
            "absent detect must not serialize: {text}"
        );
    }
}
