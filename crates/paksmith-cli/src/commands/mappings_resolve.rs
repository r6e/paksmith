//! Shared `.usmap` mappings resolution for `inspect` and `extract`
//! (#651). Two sources feed [`resolve_usmap`], in precedence order:
//!
//! 1. an explicit `--mappings <path>` — load failures attribute to
//!    `--mappings`;
//! 2. the profile selected by `--game`/`--detect` — load failures
//!    attribute to the selector that picked the profile, and they are
//!    HARD errors: a profile the user selected promising mappings it
//!    cannot deliver must not silently degrade to the no-mappings
//!    behavior (that would resurface the per-entry
//!    `UnversionedWithoutMappings` failures the profile was configured
//!    to fix).
//!
//! All loading routes through [`Usmap::from_path`] and inherits its
//! defensive caps.

use std::path::Path;
use std::sync::Arc;

use paksmith_core::MappingsSource;
use paksmith_core::PaksmithError;
use paksmith_core::asset::mappings::Usmap;

/// Load an explicit `--mappings` file, attributing failures to the flag.
fn load_explicit(path: &Path) -> paksmith_core::Result<Usmap> {
    Usmap::from_path(path).map_err(|e| PaksmithError::InvalidArgument {
        arg: "--mappings",
        reason: e.to_string(),
    })
}

/// Load a profile-supplied mappings source, attributing failures to
/// `selector` — the flag that picked the profile (`"--game"` or
/// `"--detect"`).
fn load_from_profile(
    source: &MappingsSource,
    selector: &'static str,
) -> paksmith_core::Result<Usmap> {
    let MappingsSource::Path(path) = source;
    Usmap::from_path(path).map_err(|e| PaksmithError::InvalidArgument {
        arg: selector,
        reason: format!("profile mappings file failed to load: {e}"),
    })
}

/// Resolve the effective usmap: explicit `--mappings` wins over the
/// profile source; `None` when neither is present. `selector` names the
/// flag that picked the profile, for load-failure attribution.
pub(crate) fn resolve_usmap(
    explicit: Option<&Path>,
    profile: Option<&MappingsSource>,
    selector: &'static str,
) -> paksmith_core::Result<Option<Arc<Usmap>>> {
    let usmap = match (explicit, profile) {
        (Some(path), _) => Some(load_explicit(path)?),
        (None, Some(source)) => Some(load_from_profile(source, selector)?),
        (None, None) => None,
    };
    Ok(usmap.map(Arc::new))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_bad_path_attributes_to_mappings_flag() {
        let err =
            resolve_usmap(Some(Path::new("/nonexistent/x.usmap")), None, "--game").unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::InvalidArgument {
                    arg: "--mappings",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn profile_bad_path_attributes_to_selector() {
        let src = MappingsSource::Path("/nonexistent/x.usmap".into());
        let err = resolve_usmap(None, Some(&src), "--game").unwrap_err();
        assert!(
            matches!(err, PaksmithError::InvalidArgument { arg: "--game", ref reason }
                if reason.contains("profile mappings")),
            "got {err:?}"
        );
        // The selector is threaded, not hardcoded: a --detect-selected
        // profile blames --detect.
        let err = resolve_usmap(None, Some(&src), "--detect").unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::InvalidArgument {
                    arg: "--detect",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn explicit_wins_over_profile() {
        // The profile path is broken; an (also broken) explicit path must
        // be the one reported — proof the explicit branch was taken.
        let src = MappingsSource::Path("/nonexistent/profile.usmap".into());
        let err = resolve_usmap(
            Some(Path::new("/nonexistent/explicit.usmap")),
            Some(&src),
            "--game",
        )
        .unwrap_err();
        assert!(
            matches!(err, PaksmithError::InvalidArgument { arg: "--mappings", ref reason }
                if reason.contains("explicit.usmap")),
            "got {err:?}"
        );
    }

    #[test]
    fn neither_source_is_none() {
        assert!(resolve_usmap(None, None, "--game").unwrap().is_none());
    }
}
