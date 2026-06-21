//! Declarative game auto-detection: rules stored on a profile that recognise a
//! game's install directory. Read-only, path-traversal-guarded, size-capped.
//! Network registry (5c) ships these rules so detection works for known games.

use serde::{Deserialize, Serialize};

/// Maximum number of `require_paths` / `contains` rules accepted from the
/// untrusted registry (enforced by `validate_caps` in Task 3).
#[expect(
    dead_code,
    reason = "used by Task 3 cap validation, not yet implemented"
)]
pub(crate) const MAX_REQUIRE_PATHS: usize = 64;
/// Maximum number of `contains` rules accepted from the untrusted registry.
#[expect(
    dead_code,
    reason = "used by Task 3 cap validation, not yet implemented"
)]
pub(crate) const MAX_CONTAINS: usize = 64;
/// Cap on the bytes read from a `contains` target file before substring search.
#[expect(dead_code, reason = "used by Task 2 matcher, not yet implemented")]
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::profile::GameProfile;

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
