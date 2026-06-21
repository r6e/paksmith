//! Frontend-agnostic key/profile resolution: shared by the CLI and GUI so the
//! Phase 5 `--game`/`--detect` logic lives in exactly one place.

use std::collections::BTreeMap;
use std::path::Path;

use crate::container::pak::PakReader;
use crate::error::ProfileFault;
use crate::profile::cache::RegistryCache;
use crate::profile::config::{RegistryConfig, ensure_key_matches_registry};
use crate::profile::detection::rules_match;
use crate::profile::registry::RegistryClient;
use crate::{
    AesKey, KeyGuid, PaksmithError, ProfileStore, ResolvedProfile, display_guid,
    resolve_profile_layered,
};

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
///
/// A corrupt or missing cache degrades gracefully to `None` (with a warning)
/// rather than failing the caller — the cache is optional and an auto-fetch
/// or local profiles can still proceed.
pub fn load_cache_lenient() -> Option<RegistryCache> {
    match RegistryCache::load() {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "ignoring unreadable registry cache");
            None
        }
    }
}

/// Return the current Unix timestamp in seconds.
///
/// Errors only if the system clock is before the Unix epoch (extremely
/// unlikely in practice).
pub fn now_unix() -> crate::Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| PaksmithError::InvalidArgument {
            arg: "clock",
            reason: e.to_string(),
        })
}

/// Resolve the AES key for a pak: `--aes-key` (wins) > `--game` (explicit id) >
/// `--detect` (auto-detect from an install dir). `None` when no selector is set.
///
/// This fn is `async` so the GUI can `.await` it inside `iced::Task::perform`
/// (Iced runs on tokio — a `block_on` there would panic). The CLI wraps it in
/// its existing synchronous `block_on`.
pub async fn resolve_pak_key(
    path: &Path,
    aes_key: Option<&AesKey>,
    game: Option<&str>,
    detect: Option<&Path>,
) -> crate::Result<Option<AesKey>> {
    if let Some(k) = aes_key {
        if game.is_some() {
            tracing::debug!("--aes-key overrides --game");
        } else if detect.is_some() {
            tracing::debug!("--aes-key overrides --detect");
        }
        return Ok(Some(k.clone()));
    }
    // Effective profile id: --game (explicit) wins over --detect (auto).
    let id: String = if let Some(g) = game {
        if detect.is_some() {
            tracing::debug!("--game overrides --detect");
        }
        g.to_string()
    } else if let Some(dir) = detect {
        if !dir.is_dir() {
            return Err(PaksmithError::InvalidArgument {
                arg: "--detect",
                reason: format!("not a directory: {}", dir.display()),
            });
        }
        let mut matches = detect_matches(dir)?;
        match matches.len() {
            0 => {
                return Err(PaksmithError::Profile {
                    fault: ProfileFault::DetectionNoMatch {
                        dir: dir.display().to_string(),
                    },
                });
            }
            1 => matches.remove(0).id,
            _ => {
                return Err(PaksmithError::Profile {
                    fault: ProfileFault::DetectionAmbiguous {
                        dir: dir.display().to_string(),
                        ids: matches
                            .iter()
                            .map(|m| m.id.as_str())
                            .collect::<Vec<_>>()
                            .join(", "),
                    },
                });
            }
        }
    } else {
        return Ok(None);
    };
    let id = id.as_str();

    let store = ProfileStore::load()?;
    let pak_guid = PakReader::read_footer_guid(path)?;

    // 1. Local profiles.toml wins — no network ever when the id is local.
    if let Some(profile) = store.profiles.get(id) {
        return resolve_within(&profile.keys, id, pak_guid);
    }

    // 2. Determine whether the cache is fresh enough to skip a fetch.
    let mut cache = load_cache_lenient();
    let cfg = RegistryConfig::load()?;
    let now = now_unix()?;
    let fresh = cache
        .as_ref()
        .is_some_and(|c| !c.is_stale(now, cfg.staleness_hours) && c.get(id).is_some());

    // 3. Auto-fetch when the id is absent locally AND the cache is missing/stale
    //    or doesn't contain this id. On fetch failure, keep the existing cache
    //    (stale or absent) and warn — do not propagate the error.
    if !fresh {
        match try_fetch(&cfg, now).await {
            Ok(fetched) => {
                // Best-effort save; don't propagate a save error.
                let _ = fetched.save();
                cache = Some(fetched);
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "registry fetch failed; using cached profiles if available"
                );
            }
        }
    }

    // 4. Resolve id from local store + cache. `resolve_profile_layered` tries
    //    local first (already handled above, so local always misses here), then
    //    the cache.
    match resolve_profile_layered(&store, cache.as_ref(), id) {
        Some(ResolvedProfile::Local(p)) => resolve_within(&p.keys, id, pak_guid),
        Some(ResolvedProfile::Registry(p)) => resolve_within(&p.keys, id, pak_guid),
        None => Err(PaksmithError::Profile {
            fault: ProfileFault::ProfileNotFound { id: id.to_string() },
        }),
    }
}

/// Fetch the registry and wrap the result in a [`RegistryCache`].
async fn try_fetch(cfg: &RegistryConfig, now: u64) -> crate::Result<RegistryCache> {
    ensure_key_matches_registry(&cfg.url, &cfg.public_key_hex)?;
    let client = RegistryClient::new()?;
    let doc = client.fetch(&cfg.url, &cfg.public_key_hex).await?;
    Ok(RegistryCache {
        fetched_at_unix: now,
        doc,
    })
}

/// Resolve the AES key for `pak_guid` from a `BTreeMap<KeyGuid, AesKey>`.
///
/// Resolution order: exact GUID match → zero-default (`KeyGuid::ZERO`) →
/// `NoKeyForGuid` error.
fn resolve_within(
    keys: &BTreeMap<KeyGuid, AesKey>,
    id: &str,
    pak_guid: Option<[u8; 16]>,
) -> crate::Result<Option<AesKey>> {
    let guid = pak_guid.map_or(KeyGuid::ZERO, KeyGuid::from_bytes);
    let key = keys
        .get(&guid)
        .or_else(|| keys.get(&KeyGuid::ZERO))
        .ok_or_else(|| PaksmithError::Profile {
            fault: ProfileFault::NoKeyForGuid {
                id: id.to_string(),
                guid: display_guid(pak_guid),
            },
        })?;
    Ok(Some(key.clone()))
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

    #[test]
    fn detect_in_registry_only_matches() {
        let game = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(game.path().join("Game/Paks")).unwrap();
        let rules = DetectRules {
            require_paths: vec!["Game/Paks".into()],
            contains: vec![],
        };
        let store = ProfileStore::default(); // empty — no local profiles
        let cache = RegistryCache {
            fetched_at_unix: 0,
            doc: crate::profile::registry::RegistryDoc {
                profiles: vec![crate::profile::registry::RegistryProfile {
                    id: "reg-game".into(),
                    name: "Registry Game".into(),
                    engine_version: None,
                    keys: BTreeMap::new(),
                    detect: Some(rules),
                }],
            },
        };
        let got = detect_in(&store, Some(&cache), game.path());
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].id, "reg-game");
        assert_eq!(got[0].source, "registry");
    }

    #[tokio::test]
    async fn aes_key_short_circuits_resolution() {
        // A bogus path that doesn't exist — proves we never read it when --aes-key wins.
        let hex = "ab".repeat(32);
        let key = crate::AesKey::from_hex(&hex).unwrap();
        let got = resolve_pak_key(Path::new("/nonexistent/x.pak"), Some(&key), None, None)
            .await
            .unwrap();
        // AesKey doesn't implement PartialEq (security); compare via to_hex().
        assert_eq!(got.unwrap().to_hex(), hex);
    }

    #[tokio::test]
    async fn no_flags_returns_none() {
        let got = resolve_pak_key(Path::new("/nonexistent/x.pak"), None, None, None)
            .await
            .unwrap();
        assert!(got.is_none());
    }
}
