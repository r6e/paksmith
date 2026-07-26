//! Frontend-agnostic key/profile resolution: shared by the CLI and GUI so the
//! Phase 5 `--game`/`--detect` logic lives in exactly one place.

use std::collections::BTreeMap;
use std::path::Path;

use crate::container::pak::PakReader;
use crate::error::ProfileFault;
use crate::profile::MappingsSource;
use crate::profile::cache::RegistryCache;
use crate::profile::config::{RegistryConfig, ensure_key_matches_registry};
use crate::profile::detection::rules_match;
use crate::profile::registry::RegistryClient;
use crate::{
    AesKey, KeyGuid, PaksmithError, ProfileStore, ResolvedProfile, display_guid,
    resolve_profile_layered,
};

/// One profile that matched a directory scan.
///
/// Marked `#[non_exhaustive]` so that adding fields in a future release is not
/// a breaking change for downstream crates.  In-crate struct literals continue
/// to work; external consumers can only construct it via functions that return
/// `Vec<DetectMatch>` (like `available_profiles`, `detect_matches`).
#[non_exhaustive]
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
pub(crate) fn now_unix() -> crate::Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| PaksmithError::InvalidArgument {
            arg: "clock",
            reason: e.to_string(),
        })
}

/// Everything a caller needs to open and decode a pak selected via
/// `--aes-key` / `--game` / `--detect`: the AES key (if any), the
/// selected profile's mappings source (#651), and its declared engine
/// version (#656).
///
/// The latter two are PARSE inputs rather than open inputs — they
/// reach `Package::read_from*_with` through
/// [`crate::asset::ReadOptions`], not the container layer — so a
/// caller that only opens (`list`/`search`) can ignore them. The
/// engine version travels as-is; `mappings` is a SOURCE (a path or
/// registry reference) that the caller first loads into an
/// `Arc<Usmap>`.
///
/// Marked `#[non_exhaustive]` (like [`DetectMatch`]) so future fields —
/// e.g. more profile-carried open state — are not breaking changes;
/// external consumers construct it only via [`resolve_pak_context`].
/// `engine_version` is the first field added under that allowance.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct PakOpenContext {
    /// Resolved AES key: explicit `--aes-key` wins; otherwise the
    /// profile's key store via footer-GUID lookup. `None` when no
    /// selector produced one.
    pub key: Option<AesKey>,
    /// The selected profile's mappings source. `None` when no profile
    /// was selected, the profile carries none, or the profile came from
    /// the remote registry (registry profiles cannot carry mappings —
    /// see [`MappingsSource`]). Call sites give an explicit
    /// `--mappings` argument precedence over this.
    pub mappings: Option<MappingsSource>,
    /// The selected profile's declared engine version, parsed
    /// leniently (#656): an unparsable string degrades to `None` with
    /// a warning, never an error — registry-authored strings are
    /// untrusted input, and one bad value must not fail an open.
    ///
    /// UNLIKE [`Self::mappings`], a REGISTRY profile can supply this:
    /// `RegistryProfile` has carried `engine_version` since the
    /// registry shipped, so this is the first profile-borne parse
    /// input that survives the local/registry split. Feeds
    /// [`crate::asset::AssetContext::engine_version_hint`].
    pub engine_version: Option<crate::asset::UeVersion>,
}

/// Resolve the AES key for a pak: `--aes-key` (wins) > `--game` (explicit id) >
/// `--detect` (auto-detect from an install dir). `None` when no selector is set.
///
/// Thin delegate over [`resolve_pak_context`] that keeps the pre-#651
/// key-only signature for callers that consume neither parse input
/// (the GUI open flow can migrate to the context form as a follow-up).
///
/// # Errors
///
/// See [`resolve_pak_context`].
pub async fn resolve_pak_key(
    path: &Path,
    aes_key: Option<&AesKey>,
    game: Option<&str>,
    detect: Option<&Path>,
) -> crate::Result<Option<AesKey>> {
    Ok(resolve_pak_context(path, aes_key, game, detect).await?.key)
}

/// Resolve the full [`PakOpenContext`]: the key plus the profile's
/// parse inputs — its mappings source (#651) and declared engine
/// version (#656).
///
/// Key precedence is unchanged from the pre-#651 `resolve_pak_key`:
/// `--aes-key` (wins) > `--game` (explicit id) > `--detect`. The parse
/// inputs come from the selected profile's `mappings` and
/// `engine_version` fields — and BOTH are resolved even when
/// `--aes-key` short-circuits the KEY lookup: an explicit key must not
/// silently drop them.
///
/// In the `--aes-key` combination, `--game` keeps its hard contract
/// (the named id must exist — locally or in the CACHED registry doc —
/// or the resolution fails with `ProfileNotFound`, exactly as it does
/// without `--aes-key`; a typo'd `--game` must never silently produce
/// a run stripped of its parse inputs), while `--detect` stays
/// best-effort (warn + `None` on no-unique-match — detection is
/// probabilistic, and pre-#651 this path never ran it at all).
/// `--aes-key` alone still performs zero
/// profile I/O, and no `--aes-key` combination touches the pak footer
/// or the network — a registry-only id must already be cached
/// (`profile fetch`) to be recognized here.
///
/// This fn is `async` so the GUI can `.await` it inside `iced::Task::perform`
/// (Iced runs on tokio — a `block_on` there would panic). The CLI wraps it in
/// its existing synchronous `block_on`.
pub async fn resolve_pak_context(
    path: &Path,
    aes_key: Option<&AesKey>,
    game: Option<&str>,
    detect: Option<&Path>,
) -> crate::Result<PakOpenContext> {
    if let Some(k) = aes_key {
        return explicit_key_context(k, game, detect);
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
        unique_detect_id(detect_matches(dir)?, dir)?
    } else {
        return Ok(ProfileParseInputs::default().into_context(None));
    };
    let id = id.as_str();

    let store = ProfileStore::load()?;
    let pak_guid = PakReader::read_footer_guid(path)?;

    // 1. Local profiles.toml wins — no network ever when the id is local.
    if let Some(profile) = store.profiles.get(id) {
        // Through `from_resolved` like every other site: the mapping
        // from a resolved profile to its parse inputs lives in exactly
        // one place (a duplicated arm here is what let the registry
        // `--detect` path silently drop the engine version).
        let inputs = ProfileParseInputs::from_resolved(&ResolvedProfile::Local(profile), id);
        return Ok(inputs.into_context(resolve_within(&profile.keys, id, pak_guid)?));
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
        Some(p) => {
            let key = resolve_within(p.keys(), id, pak_guid)?;
            Ok(ProfileParseInputs::from_resolved(&p, id).into_context(key))
        }
        None => Err(PaksmithError::Profile {
            fault: ProfileFault::ProfileNotFound { id: id.to_string() },
        }),
    }
}

/// A profile-paks selection (issue #655): the profile id plus its
/// `pak_paths` glob patterns, verbatim from the local store.
///
/// Path-free — unlike [`PakOpenContext`] this never reads a pak footer;
/// it answers "which archives does this profile name?", not "which key
/// opens this pak?". Pattern expansion (globbing, `--detect`-relative
/// joining) is the caller's job: core stores the patterns as opaque
/// strings and does no matching.
///
/// Marked `#[non_exhaustive]` (like [`PakOpenContext`]) so future
/// fields are not breaking; external consumers construct it only via
/// [`profile_pak_patterns`].
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ProfilePaks {
    /// The selected profile id (explicit `--game`, or the unique
    /// `--detect` match).
    pub id: String,
    /// The profile's `pak_paths` patterns, order preserved. Never empty
    /// — an empty list faults as [`ProfileFault::NoPakPaths`] instead.
    pub patterns: Vec<String>,
}

/// Resolve the profile-paks selection for `--game`/`--detect` (issue
/// #655): which profile, and which `pak_paths` patterns.
///
/// No network, ever — a registry-only id must already be cached
/// (`profile fetch`), and since
/// [`crate::profile::registry::RegistryProfile`] cannot carry
/// `pak_paths` (see [`MappingsSource`]'s registry note) a fetch could
/// never help: registry-sourced selections always fault as
/// [`ProfileFault::NoPakPaths`]. Precedence mirrors
/// [`resolve_pak_context`]: `--game` wins over `--detect`; `--detect`
/// requires an existing directory and a unique detection match.
///
/// # Errors
///
/// [`crate::PaksmithError::InvalidArgument`] when neither selector is
/// given or the `--detect` dir is not a directory;
/// [`ProfileFault::ProfileNotFound`] for an unknown id;
/// [`ProfileFault::DetectionNoMatch`] / [`ProfileFault::DetectionAmbiguous`]
/// per the `--detect` 0/1/many policy; [`ProfileFault::NoPakPaths`]
/// when the selected profile records no patterns.
pub fn profile_pak_patterns(
    game: Option<&str>,
    detect: Option<&Path>,
) -> crate::Result<ProfilePaks> {
    let store = ProfileStore::load()?;
    let cache = load_cache_lenient();
    profile_pak_patterns_in(&store, cache.as_ref(), game, detect)
}

/// Store-parameterized core of [`profile_pak_patterns`] (unit-testable,
/// no env reads beyond detection's bounded filesystem checks).
fn profile_pak_patterns_in(
    store: &ProfileStore,
    cache: Option<&RegistryCache>,
    game: Option<&str>,
    detect: Option<&Path>,
) -> crate::Result<ProfilePaks> {
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
        unique_detect_id(detect_in(store, cache, dir), dir)?
    } else {
        return Err(PaksmithError::InvalidArgument {
            arg: "--game/--detect",
            reason: "a profile selector is required when no pak path is given".to_string(),
        });
    };

    let patterns = match resolve_profile_layered(store, cache, &id) {
        Some(ResolvedProfile::Local(p)) => p.pak_paths.clone(),
        // RegistryProfile has no pak_paths field — a cached registry id
        // is a valid selection that cannot name archives.
        Some(ResolvedProfile::Registry(_)) => Vec::new(),
        None => {
            return Err(PaksmithError::Profile {
                fault: ProfileFault::ProfileNotFound { id },
            });
        }
    };
    if patterns.is_empty() {
        return Err(PaksmithError::Profile {
            fault: ProfileFault::NoPakPaths { id },
        });
    }
    Ok(ProfilePaks { id, patterns })
}

/// The unique profile id from a detection sweep, or the typed fault the
/// `--detect` contract specifies: zero matches → `DetectionNoMatch`,
/// more than one → `DetectionAmbiguous` (ids joined for the message).
/// The single 0/1/many policy shared by key resolution and the
/// `--aes-key` best-effort mappings path.
fn unique_detect_id(mut matches: Vec<DetectMatch>, dir: &Path) -> crate::Result<String> {
    match matches.len() {
        1 => Ok(matches.remove(0).id),
        0 => Err(PaksmithError::Profile {
            fault: ProfileFault::DetectionNoMatch {
                dir: dir.display().to_string(),
            },
        }),
        _ => Err(PaksmithError::Profile {
            fault: ProfileFault::DetectionAmbiguous {
                dir: dir.display().to_string(),
                ids: matches
                    .iter()
                    .map(|m| m.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
            },
        }),
    }
}

/// The `--aes-key` branch of [`resolve_pak_context`]: the explicit key
/// wins, but the selected profile still supplies its parse inputs.
///
/// #651/#656: an explicit key must not silently drop the profile's
/// mappings or engine version (see [`resolve_pak_context`]'s doc for
/// the per-selector contract). No pak-footer read and no network on
/// any `--aes-key` combination.
fn explicit_key_context(
    key: &AesKey,
    game: Option<&str>,
    detect: Option<&Path>,
) -> crate::Result<PakOpenContext> {
    if game.is_some() {
        tracing::debug!("--aes-key overrides --game");
    } else if detect.is_some() {
        tracing::debug!("--aes-key overrides --detect");
    }
    let inputs = if let Some(g) = game {
        if detect.is_some() {
            tracing::debug!("--game overrides --detect");
        }
        // HARD: same contract as keyed resolution — the named id must
        // exist (store errors propagate; unknown id is
        // `ProfileNotFound`).
        let store = ProfileStore::load()?;
        let cache = load_cache_lenient();
        named_profile_inputs_in(&store, cache.as_ref(), g)?
    } else if let Some(dir) = detect {
        // Best-effort: detection is probabilistic, so store or
        // detection problems degrade to no inputs with a warning.
        match ProfileStore::load() {
            Ok(store) => {
                let cache = load_cache_lenient();
                detect_profile_inputs_in(&store, cache.as_ref(), dir)
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "profile store unreadable; --aes-key set, continuing \
                     without profile parse inputs"
                );
                ProfileParseInputs::default()
            }
        }
    } else {
        ProfileParseInputs::default()
    };
    Ok(PakOpenContext {
        key: Some(key.clone()),
        mappings: inputs.mappings,
        engine_version: inputs.engine_version,
    })
}

/// HARD `--game` parse-inputs lookup for the `--aes-key` path (#651,
/// store-parameterized so it is unit-testable): a local profile yields
/// its mappings AND engine version; a CACHED registry id is a valid
/// selection that yields its engine version but no mappings (see
/// [`MappingsSource`]'s registry note); an unknown id is
/// `ProfileNotFound`, exactly as in keyed resolution. No network — a
/// registry-only id must already be cached (`profile fetch`).
fn named_profile_inputs_in(
    store: &ProfileStore,
    cache: Option<&RegistryCache>,
    id: &str,
) -> crate::Result<ProfileParseInputs> {
    resolve_profile_layered(store, cache, id)
        .map(|p| ProfileParseInputs::from_resolved(&p, id))
        .ok_or_else(|| PaksmithError::Profile {
            fault: ProfileFault::ProfileNotFound { id: id.to_string() },
        })
}

/// The parse-affecting state a selected profile contributes (#651
/// mappings, #656 engine version).
///
/// [`ProfileParseInputs::from_resolved`] is the SINGLE place that maps
/// a resolved profile to these, so the `--aes-key` and keyed paths
/// cannot drift and the next profile-borne parse input is a field here
/// rather than another arm to remember in two files.
#[derive(Clone, Debug, Default)]
struct ProfileParseInputs {
    mappings: Option<MappingsSource>,
    engine_version: Option<crate::asset::UeVersion>,
}

impl ProfileParseInputs {
    /// Map a resolved profile to its parse inputs.
    ///
    /// Registry profiles carry no mappings (`RegistryProfile` has no
    /// such field — see [`MappingsSource`]'s registry note) but DO
    /// carry `engine_version`: it is the one parse input that survives
    /// the local/registry split (#656).
    fn from_resolved(profile: &ResolvedProfile<'_>, id: &str) -> Self {
        Self {
            // Only `mappings` differs: a registry profile structurally cannot
            // carry one (see `MappingsSource`'s registry note). The explicit
            // match is what keeps that asymmetry visible.
            mappings: match profile {
                ResolvedProfile::Local(p) => p.mappings.clone(),
                ResolvedProfile::Registry(_) => None,
            },
            engine_version: parse_engine_version(profile.engine_version(), id),
        }
    }

    /// Pair these inputs with an already-resolved key to form the
    /// pak-open context.
    ///
    /// The single place the context's fields are assembled, for the
    /// same reason [`Self::from_resolved`] is the single mapper: the
    /// next profile-borne parse input becomes a field on this struct
    /// rather than a fourth thing to remember at four call sites.
    fn into_context(self, key: Option<AesKey>) -> PakOpenContext {
        PakOpenContext {
            key,
            mappings: self.mappings,
            engine_version: self.engine_version,
        }
    }
}

/// Parse a profile's stored `engine_version` leniently (#656).
///
/// Never errors: the string may be hand-edited or registry-authored
/// (untrusted), and a malformed value must degrade to "no hint" — the
/// parse then behaves exactly as it did before hints existed — rather
/// than failing an open the user could not otherwise explain.
fn parse_engine_version(raw: Option<&str>, id: &str) -> Option<crate::asset::UeVersion> {
    let raw = raw?;
    let parsed = crate::asset::UeVersion::parse_lenient(raw);
    if parsed.is_none() {
        tracing::warn!(
            profile = id,
            value = raw,
            "profile engine_version is not a `major.minor[.patch]` version \
             (e.g. \"5.3\"); continuing without an engine-version hint"
        );
    }
    parsed
}

/// Best-effort `--detect` parse-inputs lookup for the `--aes-key` path
/// (store-parameterized, unit-testable): the unique `detect_in` match's
/// parse inputs; anything else (zero or ambiguous matches) degrades to
/// the empty set with a warning.
fn detect_profile_inputs_in(
    store: &ProfileStore,
    cache: Option<&RegistryCache>,
    dir: &Path,
) -> ProfileParseInputs {
    match unique_detect_id(detect_in(store, cache, dir), dir) {
        // LAYERED, not local-only: `detect_in` matches cached registry
        // profiles too, and a registry profile carries `engine_version`
        // (#656). Looking only at the local store would silently drop
        // the hint for exactly the registry-shipped detect rules that
        // make auto-detection work out of the box.
        Ok(id) => profile_inputs_in(store, cache, &id),
        Err(e) => {
            tracing::warn!(
                error = %e,
                "--detect found no unique profile; --aes-key set, continuing \
                 without profile parse inputs"
            );
            ProfileParseInputs::default()
        }
    }
}

/// The parse inputs for `id` across the local store and the registry
/// cache (local wins), or the empty set if neither has it.
///
/// The same lookup as [`named_profile_inputs_in`] with the miss
/// swallowed — which is precisely the `--game`-vs-`--detect`
/// difference, a typo'd explicit id being loud where a failed
/// auto-detect is not.
fn profile_inputs_in(
    store: &ProfileStore,
    cache: Option<&RegistryCache>,
    id: &str,
) -> ProfileParseInputs {
    named_profile_inputs_in(store, cache, id).unwrap_or_default()
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
/// An EMPTY key map is `Ok(None)`: the profile configures no keys at all
/// (legitimate since #651 — a mappings-only profile for an unencrypted
/// game), matching `resolve_key_in`'s `None` for an empty map; an encrypted
/// pak then fails loudly downstream at `PakReader::open`. A POPULATED
/// map resolves exact GUID match → zero-default (`KeyGuid::ZERO`) →
/// `NoKeyForGuid` error (a genuine key/GUID mismatch — here this wrapper
/// diverges from the shared rule: `resolve_key_in` stays `None`, this
/// path errors).
fn resolve_within(
    keys: &BTreeMap<KeyGuid, AesKey>,
    id: &str,
    pak_guid: Option<[u8; 16]>,
) -> crate::Result<Option<AesKey>> {
    if keys.is_empty() {
        return Ok(None);
    }
    let key = crate::profile::resolve_key_in(keys, pak_guid.as_ref()).ok_or_else(|| {
        PaksmithError::Profile {
            fault: ProfileFault::NoKeyForGuid {
                id: id.to_string(),
                guid: display_guid(pak_guid),
            },
        }
    })?;
    Ok(Some(key.clone()))
}

/// Return all profiles available for selection: all local profiles first
/// (source `"local"`), then cached registry profiles whose id is NOT a local
/// id (source `"registry"`).  Unlike `detect_in`, this function does NOT
/// filter by detect rules — it lists every known profile regardless of whether
/// it has a matching installation directory.
///
/// Loads `ProfileStore` + the registry cache (degrading a missing/corrupt
/// cache to `None`) and delegates to the pure `available_in` helper.
///
/// # Errors
///
/// Propagates `ProfileStore::load` errors only. Registry-cache failures are
/// downgraded to `None` (with a warning).
pub fn available_profiles() -> crate::Result<Vec<DetectMatch>> {
    let store = ProfileStore::load()?;
    let cache = load_cache_lenient();
    Ok(available_in(&store, cache.as_ref()))
}

/// Pure: list all profiles from `store` (local) then from `cache` whose id is
/// NOT already in `store` (registry-only). No detect-rule filtering.
///
/// Emission order: local profiles first (BTreeMap iteration = alphabetical),
/// then unshadowed registry profiles in their doc order.
pub(crate) fn available_in(
    store: &ProfileStore,
    cache: Option<&RegistryCache>,
) -> Vec<DetectMatch> {
    let mut out = Vec::new();
    for (id, p) in &store.profiles {
        out.push(DetectMatch {
            id: id.clone(),
            name: p.name.clone(),
            source: "local",
        });
    }
    let Some(c) = cache else { return out };
    for p in &c.doc.profiles {
        if store.profiles.contains_key(&p.id) {
            continue;
        }
        out.push(DetectMatch {
            id: p.id.clone(),
            name: p.name.clone(),
            source: "registry",
        });
    }
    out
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

    /// Store with one `hero` profile carrying detect rules for
    /// `Game/Paks` and a mappings source.
    fn hero_store_with_detect(mappings: Option<crate::profile::MappingsSource>) -> ProfileStore {
        let mut store = ProfileStore::default();
        let _ = store.profiles.insert(
            "hero".into(),
            GameProfile {
                name: "Hero".into(),
                engine_version: None,
                keys: BTreeMap::new(),
                detect: Some(DetectRules {
                    require_paths: vec!["Game/Paks".into()],
                    contains: vec![],
                    bytes: Vec::new(),
                }),
                mappings,
                pak_paths: Vec::new(),
            },
        );
        store
    }

    #[test]
    fn named_profile_inputs_in_local_hit_returns_source() {
        // Kills the `-> Ok(None)` mutant and pins the #651 contract: an
        // explicit key must not drop the --game profile's mappings.
        let store = hero_store_with_detect(Some(crate::profile::MappingsSource::Path(
            "/maps/hero.usmap".into(),
        )));
        assert_eq!(
            named_profile_inputs_in(&store, None, "hero")
                .unwrap()
                .mappings,
            Some(crate::profile::MappingsSource::Path(
                "/maps/hero.usmap".into()
            ))
        );
    }

    #[test]
    fn named_profile_inputs_in_unknown_id_is_profile_not_found() {
        // A typo'd --game must be LOUD even with --aes-key set — never a
        // silent run stripped of its parse inputs (R1 architect
        // finding).
        let store = hero_store_with_detect(None);
        let err = named_profile_inputs_in(&store, None, "absent");
        assert!(matches!(
            err,
            Err(PaksmithError::Profile {
                fault: ProfileFault::ProfileNotFound { ref id }
            }) if id == "absent"
        ));
    }

    #[test]
    fn named_profile_inputs_in_cached_registry_id_is_none() {
        use crate::profile::registry::{RegistryDoc, RegistryProfile};
        // A cached registry id is a VALID selection; registry profiles
        // cannot carry mappings, so the answer is None — not an error.
        let store = ProfileStore::default();
        let cache = RegistryCache {
            fetched_at_unix: 0,
            doc: RegistryDoc {
                profiles: vec![RegistryProfile {
                    id: "reg".into(),
                    name: "Reg".into(),
                    engine_version: None,
                    keys: BTreeMap::new(),
                    detect: None,
                }],
            },
        };
        assert_eq!(
            named_profile_inputs_in(&store, Some(&cache), "reg")
                .unwrap()
                .mappings,
            None
        );
    }

    #[test]
    fn engine_version_parses_from_a_local_profile() {
        let mut store = hero_store_with_detect(None);
        assert_eq!(
            named_profile_inputs_in(&store, None, "hero")
                .unwrap()
                .engine_version,
            None,
            "no stored version means no hint"
        );
        store
            .profiles
            .get_mut("hero")
            .expect("seeded")
            .engine_version = Some("5.3".into());
        assert_eq!(
            named_profile_inputs_in(&store, None, "hero")
                .unwrap()
                .engine_version,
            crate::asset::UeVersion::parse_lenient("5.3")
        );
    }

    #[test]
    fn detect_matching_a_registry_profile_still_yields_its_engine_version() {
        // The registry ships detect rules so auto-detection works out
        // of the box, and registry profiles carry engine_version — so
        // a registry-sourced --detect match must NOT lose the hint.
        // (Local-store-only lookup was invisible pre-#656 because
        // registry profiles never carried mappings.)
        let game = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(game.path().join("Game/Paks")).unwrap();
        let store = ProfileStore::default(); // registry-only id
        let cache = RegistryCache {
            fetched_at_unix: 0,
            doc: crate::profile::registry::RegistryDoc {
                profiles: vec![crate::profile::registry::RegistryProfile {
                    id: "reg".into(),
                    name: "Registry".into(),
                    engine_version: Some("5.3".into()),
                    keys: BTreeMap::new(),
                    detect: Some(DetectRules {
                        require_paths: vec!["Game/Paks".into()],
                        contains: vec![],
                        bytes: Vec::new(),
                    }),
                }],
            },
        };
        let inputs = detect_profile_inputs_in(&store, Some(&cache), game.path());
        assert_eq!(
            inputs.engine_version,
            crate::asset::UeVersion::parse_lenient("5.3"),
            "a registry-sourced detect match must carry its engine version"
        );
        assert_eq!(inputs.mappings, None, "registry still carries no mappings");
    }

    #[test]
    fn engine_version_crosses_the_registry_split_unlike_mappings() {
        // The #656 asymmetry: RegistryProfile has always carried
        // engine_version, so a registry-sourced selection supplies a
        // parse hint even though it can never supply mappings.
        let store = ProfileStore::default();
        let cache = RegistryCache {
            fetched_at_unix: 0,
            doc: crate::profile::registry::RegistryDoc {
                profiles: vec![crate::profile::registry::RegistryProfile {
                    id: "reg".into(),
                    name: "Registry".into(),
                    engine_version: Some("5.3".into()),
                    keys: BTreeMap::new(),
                    detect: None,
                }],
            },
        };
        let inputs = named_profile_inputs_in(&store, Some(&cache), "reg").unwrap();
        assert_eq!(inputs.mappings, None, "registry never carries mappings");
        assert_eq!(
            inputs.engine_version,
            crate::asset::UeVersion::parse_lenient("5.3"),
            "registry DOES carry the engine version"
        );
    }

    #[test]
    fn unparsable_engine_version_degrades_to_no_hint() {
        // Hand-edited or registry-authored garbage must never fail an
        // open — it degrades to "no hint", i.e. the pre-#656 parse.
        let mut store = hero_store_with_detect(None);
        store
            .profiles
            .get_mut("hero")
            .expect("seeded")
            .engine_version = Some("Fortnite Chapter 5".into());
        assert_eq!(
            named_profile_inputs_in(&store, None, "hero")
                .expect("a malformed version is not an error")
                .engine_version,
            None
        );
    }

    #[test]
    fn detect_profile_inputs_in_unique_match() {
        let game_dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(game_dir.path().join("Game/Paks")).unwrap();
        let store = hero_store_with_detect(Some(crate::profile::MappingsSource::Path(
            "/maps/hero.usmap".into(),
        )));
        assert_eq!(
            detect_profile_inputs_in(&store, None, game_dir.path()).mappings,
            Some(crate::profile::MappingsSource::Path(
                "/maps/hero.usmap".into()
            )),
            "a UNIQUE --detect match supplies the profile's mappings"
        );
    }

    #[test]
    fn detect_profile_inputs_in_no_match_is_none() {
        let empty_dir = tempfile::tempdir().unwrap();
        let store = hero_store_with_detect(Some(crate::profile::MappingsSource::Path(
            "/maps/hero.usmap".into(),
        )));
        assert_eq!(
            detect_profile_inputs_in(&store, None, empty_dir.path()).mappings,
            None,
            "zero detect matches degrade to None"
        );
    }

    #[test]
    fn detect_profile_inputs_in_ambiguous_is_none() {
        let game_dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(game_dir.path().join("Game/Paks")).unwrap();
        let mut store = hero_store_with_detect(Some(crate::profile::MappingsSource::Path(
            "/maps/hero.usmap".into(),
        )));
        // Second profile matching the same directory → ambiguous.
        let hero = store.profiles["hero"].clone();
        let _ = store.profiles.insert("hero2".into(), hero);
        assert_eq!(
            detect_profile_inputs_in(&store, None, game_dir.path()).mappings,
            None,
            "ambiguous detection degrades to None"
        );
    }

    #[test]
    fn unique_detect_id_arms() {
        let dir = Path::new("/tmp/g");
        let m = |id: &str| DetectMatch {
            id: id.into(),
            name: id.into(),
            source: "local",
        };
        assert_eq!(unique_detect_id(vec![m("only")], dir).unwrap(), "only");
        assert!(matches!(
            unique_detect_id(vec![], dir),
            Err(PaksmithError::Profile {
                fault: ProfileFault::DetectionNoMatch { .. }
            })
        ));
        let err = unique_detect_id(vec![m("a"), m("b")], dir);
        assert!(matches!(
            err,
            Err(PaksmithError::Profile {
                fault: ProfileFault::DetectionAmbiguous { ref ids, .. }
            }) if ids == "a, b"
        ));
    }

    #[test]
    fn profile_inputs_in_returns_local_source() {
        let mut store = ProfileStore::default();
        let _ = store.profiles.insert(
            "hero".into(),
            GameProfile {
                name: "Hero".into(),
                engine_version: None,
                keys: BTreeMap::new(),
                detect: None,
                mappings: Some(crate::profile::MappingsSource::Path(
                    "/maps/hero.usmap".into(),
                )),
                pak_paths: Vec::new(),
            },
        );
        assert_eq!(
            profile_inputs_in(&store, None, "hero").mappings,
            Some(crate::profile::MappingsSource::Path(
                "/maps/hero.usmap".into()
            ))
        );
        assert_eq!(
            profile_inputs_in(&store, None, "absent").mappings,
            None,
            "unknown id is None, not an error"
        );
    }

    #[test]
    fn profile_inputs_in_none_when_profile_has_no_mappings() {
        let mut store = ProfileStore::default();
        let _ = store.profiles.insert(
            "plain".into(),
            GameProfile {
                name: "Plain".into(),
                engine_version: None,
                keys: BTreeMap::new(),
                detect: None,
                mappings: None,
                pak_paths: Vec::new(),
            },
        );
        assert_eq!(profile_inputs_in(&store, None, "plain").mappings, None);
    }

    /// Store with one `hero` profile carrying pak_paths patterns —
    /// delegates to `hero_store_with_detect` so the detect rules the
    /// --detect legs depend on live in exactly one place.
    fn hero_store_with_pak_paths(patterns: Vec<String>) -> ProfileStore {
        let mut store = hero_store_with_detect(None);
        store
            .profiles
            .get_mut("hero")
            .expect("hero_store_with_detect inserts it")
            .pak_paths = patterns;
        store
    }

    #[test]
    fn profile_pak_patterns_in_game_hit_returns_patterns_verbatim() {
        let store = hero_store_with_pak_paths(vec!["/g/Paks/*.pak".into(), "Extra/*.pak".into()]);
        let got = profile_pak_patterns_in(&store, None, Some("hero"), None).unwrap();
        assert_eq!(got.id, "hero");
        assert_eq!(
            got.patterns,
            vec!["/g/Paks/*.pak".to_string(), "Extra/*.pak".to_string()],
            "patterns pass through verbatim, order preserved"
        );
    }

    #[test]
    fn profile_pak_patterns_in_empty_patterns_is_no_pak_paths_fault() {
        // A profile that exists but records no archive locations is a
        // TYPED fault, not an empty success — the remedy (add patterns)
        // is the same whether the profile is local-without-field or
        // registry-sourced, so both collapse to NoPakPaths.
        let store = hero_store_with_pak_paths(Vec::new());
        let err = profile_pak_patterns_in(&store, None, Some("hero"), None).unwrap_err();
        assert!(
            matches!(
                &err,
                PaksmithError::Profile {
                    fault: ProfileFault::NoPakPaths { id }
                } if id == "hero"
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn profile_pak_patterns_in_registry_only_id_is_no_pak_paths_fault() {
        // RegistryProfile has no pak_paths field (deny_unknown_fields +
        // ed25519-signed doc — see MappingsSource's registry note), so a
        // cached registry id is a VALID selection that still faults.
        let store = ProfileStore::default();
        let cache = RegistryCache {
            fetched_at_unix: 0,
            doc: crate::profile::registry::RegistryDoc {
                profiles: vec![crate::profile::registry::RegistryProfile {
                    id: "reg-game".into(),
                    name: "Registry Game".into(),
                    engine_version: None,
                    keys: BTreeMap::new(),
                    detect: None,
                }],
            },
        };
        let err =
            profile_pak_patterns_in(&store, Some(&cache), Some("reg-game"), None).unwrap_err();
        assert!(
            matches!(
                &err,
                PaksmithError::Profile {
                    fault: ProfileFault::NoPakPaths { id }
                } if id == "reg-game"
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn profile_pak_patterns_in_unknown_id_is_profile_not_found() {
        let store = hero_store_with_pak_paths(vec!["/g/*.pak".into()]);
        let err = profile_pak_patterns_in(&store, None, Some("absent"), None).unwrap_err();
        assert!(
            matches!(
                &err,
                PaksmithError::Profile {
                    fault: ProfileFault::ProfileNotFound { id }
                } if id == "absent"
            ),
            "a typo'd --game must be LOUD, got {err:?}"
        );
    }

    #[test]
    fn profile_pak_patterns_in_detect_unique_match_returns_patterns() {
        let game = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(game.path().join("Game/Paks")).unwrap();
        let store = hero_store_with_pak_paths(vec!["Game/Paks/*.pak".into()]);
        let got = profile_pak_patterns_in(&store, None, None, Some(game.path())).unwrap();
        assert_eq!(got.id, "hero");
        assert_eq!(got.patterns, vec!["Game/Paks/*.pak".to_string()]);
    }

    #[test]
    fn profile_pak_patterns_in_detect_nonexistent_dir_is_invalid_argument() {
        let store = hero_store_with_pak_paths(vec!["/g/*.pak".into()]);
        let err =
            profile_pak_patterns_in(&store, None, None, Some(Path::new("/definitely/not/a/dir")))
                .unwrap_err();
        assert!(
            matches!(
                &err,
                PaksmithError::InvalidArgument {
                    arg: "--detect",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn profile_pak_patterns_in_game_wins_over_detect() {
        // Mirror of resolve_pak_context's precedence: --game overrides
        // --detect entirely (the dir is never even validated).
        let store = hero_store_with_pak_paths(vec!["/g/*.pak".into()]);
        let got = profile_pak_patterns_in(
            &store,
            None,
            Some("hero"),
            Some(Path::new("/definitely/not/a/dir")),
        )
        .unwrap();
        assert_eq!(got.id, "hero");
    }

    #[test]
    fn profile_pak_patterns_in_neither_selector_is_invalid_argument() {
        let store = hero_store_with_pak_paths(vec!["/g/*.pak".into()]);
        let err = profile_pak_patterns_in(&store, None, None, None).unwrap_err();
        assert!(
            matches!(&err, PaksmithError::InvalidArgument { .. }),
            "got {err:?}"
        );
    }

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
                    bytes: Vec::new(),
                }),
                mappings: None,
                pak_paths: Vec::new(),
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
            bytes: Vec::new(),
        };
        let mut store = ProfileStore::default();
        let _ = store.profiles.insert(
            "demo".into(),
            GameProfile {
                name: "Local".into(),
                engine_version: None,
                keys: BTreeMap::new(),
                detect: Some(rules.clone()),
                mappings: None,
                pak_paths: Vec::new(),
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
            bytes: Vec::new(),
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

    #[test]
    fn available_in_lists_local_then_unshadowed_registry() {
        let mut store = ProfileStore::default();
        let _ = store.profiles.insert(
            "local1".into(),
            GameProfile {
                name: "L1".into(),
                engine_version: None,
                keys: BTreeMap::new(),
                detect: None,
                mappings: None,
                pak_paths: Vec::new(),
            },
        );
        let _ = store.profiles.insert(
            "shared".into(),
            GameProfile {
                name: "Local".into(),
                engine_version: None,
                keys: BTreeMap::new(),
                detect: None,
                mappings: None,
                pak_paths: Vec::new(),
            },
        );
        let cache = RegistryCache {
            fetched_at_unix: 0,
            doc: crate::profile::registry::RegistryDoc {
                profiles: vec![
                    crate::profile::registry::RegistryProfile {
                        id: "shared".into(),
                        name: "Reg".into(),
                        engine_version: None,
                        keys: BTreeMap::new(),
                        detect: None,
                    },
                    crate::profile::registry::RegistryProfile {
                        id: "reg1".into(),
                        name: "R1".into(),
                        engine_version: None,
                        keys: BTreeMap::new(),
                        detect: None,
                    },
                ],
            },
        };
        let got = available_in(&store, Some(&cache));
        let ids: Vec<_> = got.iter().map(|m| m.id.as_str()).collect();
        // Both local1 and reg1 appear.
        assert!(ids.contains(&"local1"), "local1 must appear");
        assert!(ids.contains(&"reg1"), "reg1 must appear");
        // "shared" appears exactly once (local shadows the registry entry).
        assert_eq!(
            got.iter().filter(|m| m.id == "shared").count(),
            1,
            "shared must appear exactly once"
        );
        // The shared entry that appears has local source.
        let shared = got.iter().find(|m| m.id == "shared").unwrap();
        assert_eq!(shared.source, "local");
        // Local profiles appear before registry-only ones.
        let local1_pos = ids.iter().position(|&id| id == "local1").unwrap();
        let reg1_pos = ids.iter().position(|&id| id == "reg1").unwrap();
        assert!(
            local1_pos < reg1_pos,
            "local profiles must precede registry-only profiles"
        );
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

    // ── Kill 1: resolve_within -> Ok(None) mutant ─────────────────────────────
    //
    // A populated BTreeMap with KeyGuid::ZERO must yield Ok(Some(key)).
    // The `-> Ok(None)` mutant would return None despite a matching key being
    // present — the to_hex assertion below catches that.
    // An EMPTY map is Ok(None) (mappings-only profile, #651); a populated
    // map with no matching GUID is Err (NoKeyForGuid) — the pair kills the
    // `is_empty() -> true` / `-> false` mutants in both directions.

    #[test]
    fn resolve_within_zero_key_found() {
        let hex = "ab".repeat(32);
        let key = crate::AesKey::from_hex(&hex).unwrap();
        let mut map = BTreeMap::new();
        let _ = map.insert(KeyGuid::ZERO, key);
        let got = resolve_within(&map, "demo", None).unwrap();
        assert_eq!(
            got.unwrap().to_hex(),
            hex,
            "populated map must return Ok(Some(key))"
        );
    }

    #[test]
    fn resolve_within_empty_map_is_none_not_error() {
        // #651: a profile with NO keys at all (mappings-only) resolves to
        // "no key" — an unencrypted pak proceeds; an encrypted one fails
        // loudly at open. Pre-#651 this was Err(NoKeyForGuid).
        let map: BTreeMap<KeyGuid, crate::AesKey> = BTreeMap::new();
        let got = resolve_within(&map, "demo", None).unwrap();
        assert!(got.is_none(), "empty map must be Ok(None)");
    }

    #[test]
    fn resolve_within_populated_map_without_match_errors() {
        // A POPULATED map with no entry for the pak's GUID (and no
        // zero-default) is a genuine mismatch → NoKeyForGuid.
        let hex = "ab".repeat(32);
        let key = crate::AesKey::from_hex(&hex).unwrap();
        let mut map = BTreeMap::new();
        let _ = map.insert(KeyGuid::from_bytes([0xA1; 16]), key);
        let err = resolve_within(&map, "demo", Some([0xB2; 16]));
        assert!(
            err.is_err(),
            "populated map without a match must stay Err(NoKeyForGuid)"
        );
    }
}
