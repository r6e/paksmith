//! Frontend-agnostic key/profile resolution: shared by the CLI and GUI so the
//! Phase 5 `--game`/`--detect` logic lives in exactly one place.

use std::path::Path;

use crate::ProfileStore;
use crate::profile::cache::RegistryCache;
use crate::profile::detection::rules_match;

/// One profile that matched a directory scan.
pub struct DetectMatch {
    /// Profile id.
    pub id: String,
    /// Human-readable display name.
    pub name: String,
    /// Where the profile came from: `"local"` or `"registry"`.
    pub source: &'static str,
}

/// Load the registry cache, degrading a corrupt/unreadable cache to `None`.
pub(crate) fn load_cache_lenient() -> Option<RegistryCache> {
    match RegistryCache::load() {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "ignoring unreadable registry cache");
            None
        }
    }
}

/// Detect which stored/cached profiles match `dir` (loads store + cache, then
/// delegates to the pure `detect_in`).
pub fn detect_matches(dir: &Path) -> crate::Result<Vec<DetectMatch>> {
    let store = ProfileStore::load()?;
    let cache = load_cache_lenient();
    Ok(detect_in(&store, cache.as_ref(), dir))
}

/// Pure detection over an already-loaded store + cache — no env reads, no I/O
/// beyond `rules_match`'s bounded filesystem checks. Local profiles are emitted
/// first and shadow a cached registry entry of the same id (match or not). Only
/// profiles that carry detect rules can match. This is the unit-tested core.
pub(crate) fn detect_in(
    store: &ProfileStore,
    cache: Option<&RegistryCache>,
    dir: &Path,
) -> Vec<DetectMatch> {
    let mut out = Vec::new();
    for (id, p) in &store.profiles {
        let Some(rules) = &p.detect else { continue };
        if rules_match(dir, rules) {
            out.push(DetectMatch {
                id: id.clone(),
                name: p.name.clone(),
                source: "local",
            });
        }
    }
    let Some(c) = cache else { return out };
    for p in &c.doc.profiles {
        if store.profiles.contains_key(&p.id) {
            continue;
        }
        let Some(rules) = &p.detect else { continue };
        if rules_match(dir, rules) {
            out.push(DetectMatch {
                id: p.id.clone(),
                name: p.name.clone(),
                source: "registry",
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::GameProfile;
    use crate::profile::detection::DetectRules;

    #[test]
    fn detect_in_local_marker_matches() {
        let game = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(game.path().join("Game/Paks")).unwrap();
        let mut store = ProfileStore::default();
        let _ = store.profiles.insert(
            "demo".into(),
            GameProfile {
                name: "Demo".into(),
                engine_version: None,
                keys: BTreeMap::new(),
                detect: Some(DetectRules {
                    require_paths: vec!["Game/Paks".into()],
                    contains: vec![],
                }),
            },
        );
        let got = detect_in(&store, None, game.path());
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].id, "demo");
        assert_eq!(got[0].source, "local");
    }

    #[test]
    fn detect_in_local_shadows_registry_same_id() {
        let game = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(game.path().join("Game/Paks")).unwrap();
        let rules = DetectRules {
            require_paths: vec!["Game/Paks".into()],
            contains: vec![],
        };
        let mut store = ProfileStore::default();
        let _ = store.profiles.insert(
            "demo".into(),
            GameProfile {
                name: "Local".into(),
                engine_version: None,
                keys: BTreeMap::new(),
                detect: Some(rules.clone()),
            },
        );
        let cache = RegistryCache {
            fetched_at_unix: 0,
            doc: crate::profile::registry::RegistryDoc {
                profiles: vec![crate::profile::registry::RegistryProfile {
                    id: "demo".into(),
                    name: "Registry".into(),
                    engine_version: None,
                    keys: BTreeMap::new(),
                    detect: Some(rules),
                }],
            },
        };
        let got = detect_in(&store, Some(&cache), game.path());
        // "demo" appears ONCE (local shadows the registry entry of the same id).
        assert_eq!(got.iter().filter(|m| m.id == "demo").count(), 1);
        assert_eq!(got[0].source, "local");
    }
}
