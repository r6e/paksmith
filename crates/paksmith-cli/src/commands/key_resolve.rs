use std::collections::BTreeMap;
use std::path::Path;

use paksmith_core::container::pak::PakReader;
use paksmith_core::error::ProfileFault;
use paksmith_core::profile::cache::RegistryCache;
use paksmith_core::profile::registry::RegistryClient;
use paksmith_core::{
    AesKey, KeyGuid, PaksmithError, ProfileStore, RegistryConfig, ResolvedProfile, display_guid,
    resolve_profile_layered,
};

/// Resolve the AES key for a pak from `--aes-key` (wins) or `--game` (profile
/// lookup via the pak's footer GUID, with auto-fetch + offline fallback).
/// Returns `None` when neither flag is set.
pub(crate) fn resolve_pak_key(
    path: &Path,
    aes_key: Option<&AesKey>,
    game: Option<&str>,
) -> paksmith_core::Result<Option<AesKey>> {
    if let Some(k) = aes_key {
        if game.is_some() {
            tracing::debug!("--aes-key overrides --game");
        }
        return Ok(Some(k.clone()));
    }
    let Some(id) = game else { return Ok(None) };

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
        match try_fetch(&cfg, now) {
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

/// Return the current Unix timestamp in seconds.
pub(crate) fn now_unix() -> paksmith_core::Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| PaksmithError::InvalidArgument {
            arg: "clock",
            reason: e.to_string(),
        })
}

/// Fetch the registry and wrap the result in a [`RegistryCache`].
fn try_fetch(cfg: &RegistryConfig, now: u64) -> paksmith_core::Result<RegistryCache> {
    paksmith_core::profile::config::ensure_key_matches_registry(&cfg.url, &cfg.public_key_hex)?;
    let client = RegistryClient::new()?;
    let doc = crate::block_on(client.fetch(&cfg.url, &cfg.public_key_hex))?;
    Ok(RegistryCache {
        fetched_at_unix: now,
        doc,
    })
}

/// Load the registry cache, degrading a corrupt/unreadable cache to `None`
/// (with a warning) rather than failing the command — the cache is optional
/// and an auto-fetch / local profiles can still proceed.
pub(crate) fn load_cache_lenient() -> Option<RegistryCache> {
    match RegistryCache::load() {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "ignoring unreadable registry cache");
            None
        }
    }
}

/// Resolve the AES key for `pak_guid` from a `BTreeMap<KeyGuid, AesKey>`.
///
/// Mirrors [`paksmith_core::profile::resolve_key`] but operates on a bare
/// `BTreeMap` so it can serve both `GameProfile` and `RegistryProfile` keys
/// without taking the concrete profile type.
///
/// Resolution order: exact GUID match → zero-default (`KeyGuid::ZERO`) →
/// `NoKeyForGuid` error.
fn resolve_within(
    keys: &BTreeMap<KeyGuid, AesKey>,
    id: &str,
    pak_guid: Option<[u8; 16]>,
) -> paksmith_core::Result<Option<AesKey>> {
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
