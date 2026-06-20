//! Registry document model + strict, capped parsing. (The async fetch client
//! is in the same module, added in Task 5.)

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::ProfileFault;
use crate::{AesKey, KeyGuid, PaksmithError};

// Used by parse_registry, validate_caps, and (Task 5/6) the async client +
// cache-load path. Clippy sees them as unused until those callers land.
#[allow(dead_code)]
pub(crate) const MAX_PROFILES: usize = 10_000;
#[allow(dead_code)]
pub(crate) const MAX_KEYS_PER_PROFILE: usize = 64;
#[allow(dead_code)]
pub(crate) const MAX_STR: usize = 256;

/// One profile as served by the registry (an explicit `id`, unlike the local
/// store where the id is the map key).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryProfile {
    /// Stable id (used by `--game`).
    pub id: String,
    /// Display name.
    pub name: String,
    /// Optional engine version.
    #[serde(default)]
    pub engine_version: Option<String>,
    /// guid → key (32-hex → 64-hex on the wire).
    #[serde(with = "crate::profile::keys_serde")]
    pub keys: BTreeMap<KeyGuid, AesKey>,
}

/// A parsed registry document.
#[derive(Debug, Clone)]
pub struct RegistryDoc {
    /// The profiles served.
    pub profiles: Vec<RegistryProfile>,
}

/// Cap-check a parsed [`RegistryDoc`]. Returns the doc unchanged on success, or
/// a descriptive error string on violation.
///
/// Extracted so Task 6's cache-load path can reuse identical cap enforcement
/// without duplicating the logic inside `parse_registry`.
// Task 6 (cache-load) calls this; suppress until that caller lands.
#[allow(dead_code)]
pub(crate) fn validate_caps(doc: RegistryDoc) -> Result<RegistryDoc, String> {
    if doc.profiles.len() > MAX_PROFILES {
        return Err(format!(
            "too many profiles: {} > {MAX_PROFILES}",
            doc.profiles.len()
        ));
    }
    for p in &doc.profiles {
        if p.id.len() > MAX_STR
            || p.name.len() > MAX_STR
            || p.engine_version.as_ref().is_some_and(|v| v.len() > MAX_STR)
        {
            return Err("profile string field exceeds cap".into());
        }
        if p.keys.len() > MAX_KEYS_PER_PROFILE {
            return Err(format!("too many keys in `{}`", p.id));
        }
    }
    Ok(doc)
}

/// Parse + cap-check a registry JSON array. `keys_serde` already rejects bad
/// guid/key hex (surfaced here as [`ProfileFault::RegistryParse`]).
// Task 5 (async client) calls this; suppress until that caller lands.
#[allow(dead_code)]
pub(crate) fn parse_registry(bytes: &[u8]) -> Result<RegistryDoc, PaksmithError> {
    let parse_err = |reason: String| PaksmithError::Profile {
        fault: ProfileFault::RegistryParse { reason },
    };
    let profiles: Vec<RegistryProfile> =
        serde_json::from_slice(bytes).map_err(|e| parse_err(e.to_string()))?;
    let doc = RegistryDoc { profiles };
    validate_caps(doc).map_err(parse_err)
}

#[cfg(test)]
mod tests {
    use super::*;

    const K: &str = "94d25bc3aeb420e0be914edc9d5435a1eaab5f2864e09e94019ac205b727a7de";

    #[test]
    fn parses_valid_array() {
        let json = format!(
            r#"[{{"id":"fortnite","name":"Fortnite","engine_version":"5.3","keys":{{"00000000000000000000000000000000":"{K}"}}}}]"#
        );
        let doc = parse_registry(json.as_bytes()).unwrap();
        assert_eq!(doc.profiles.len(), 1);
        assert_eq!(doc.profiles[0].id, "fortnite");
        assert_eq!(doc.profiles[0].keys.len(), 1);
    }

    #[test]
    fn rejects_too_many_profiles() {
        let one = r#"{"id":"x","name":"y","keys":{}}"#;
        let many = std::iter::repeat_n(one, MAX_PROFILES + 1)
            .collect::<Vec<_>>()
            .join(",");
        let err = parse_registry(format!("[{many}]").as_bytes()).unwrap_err();
        assert!(matches!(
            err,
            crate::PaksmithError::Profile {
                fault: crate::error::ProfileFault::RegistryParse { .. }
            }
        ));
    }

    #[test]
    fn rejects_bad_key_hex() {
        let err = parse_registry(
            br#"[{"id":"x","name":"y","keys":{"00000000000000000000000000000000":"nothex"}}]"#,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            crate::PaksmithError::Profile {
                fault: crate::error::ProfileFault::RegistryParse { .. }
            }
        ));
    }

    #[test]
    fn rejects_overlong_id() {
        let id = "a".repeat(MAX_STR + 1);
        let err = parse_registry(format!(r#"[{{"id":"{id}","name":"y","keys":{{}}}}]"#).as_bytes())
            .unwrap_err();
        assert!(matches!(
            err,
            crate::PaksmithError::Profile {
                fault: crate::error::ProfileFault::RegistryParse { .. }
            }
        ));
    }
}
