//! TOML disk I/O for the profile store. One file at
//! `<config_dir>/paksmith/profiles.toml`, overridable via
//! `PAKSMITH_CONFIG_DIR`. Written atomically with `0600` perms on unix.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::error::ProfileFault;
use crate::profile::ProfileStore;
use crate::{PaksmithError, StagedReplace};

/// `<base>/paksmith/profiles.toml`.
// Only called from tests; production code uses config_base_dir_from_env + join.
#[allow(dead_code)]
pub(crate) fn config_path_in(base: &Path) -> PathBuf {
    base.join("paksmith").join("profiles.toml")
}

/// Resolve `<base>/paksmith` from an explicit `PAKSMITH_CONFIG_DIR` value:
/// a non-empty value wins; empty/absent → the platform config dir. Pure
/// (env value passed in) so it is unit-testable under `-D unsafe-code`.
pub(crate) fn config_base_dir_from_env(
    env_override: Option<std::ffi::OsString>,
) -> Result<PathBuf, PaksmithError> {
    if let Some(base) = env_override.filter(|b| !b.is_empty()) {
        return Ok(std::path::Path::new(&base).join("paksmith"));
    }
    let base = dirs::config_dir().ok_or(PaksmithError::Profile {
        fault: ProfileFault::NoConfigDir,
    })?;
    Ok(base.join("paksmith"))
}

/// `<config_dir>/paksmith`, honoring `PAKSMITH_CONFIG_DIR`.
pub(crate) fn config_base_dir() -> Result<PathBuf, PaksmithError> {
    config_base_dir_from_env(std::env::var_os("PAKSMITH_CONFIG_DIR"))
}

/// Pure path-resolution logic for [`ProfileStore::config_path`], factored out
/// so it can be unit-tested without mutating the process environment (which
/// `std::env::set_var` requires `unsafe` for, forbidden by `-D unsafe-code`).
///
/// `env_override` is the value of `PAKSMITH_CONFIG_DIR`: a non-empty value
/// wins; an empty or absent value falls back to the platform config dir.
fn config_path_from_env(
    env_override: Option<std::ffi::OsString>,
) -> Result<PathBuf, PaksmithError> {
    Ok(config_base_dir_from_env(env_override)?.join("profiles.toml"))
}

impl ProfileStore {
    /// Resolve the store path: `$PAKSMITH_CONFIG_DIR/paksmith/profiles.toml`
    /// if set (and non-empty), else the platform config dir.
    pub fn config_path() -> Result<PathBuf, PaksmithError> {
        config_path_from_env(std::env::var_os("PAKSMITH_CONFIG_DIR"))
    }

    /// Load the store at the resolved [`Self::config_path`].
    pub fn load() -> Result<Self, PaksmithError> {
        Self::load_from(&Self::config_path()?)
    }

    /// Save the store to the resolved [`Self::config_path`]. On Unix the file
    /// ends exactly `0600`; when the filesystem creates the temp wider than
    /// that or does not apply it, the save returns [`ProfileFault::Io`] and
    /// the existing store is left as it was.
    pub fn save(&self) -> Result<(), PaksmithError> {
        self.save_to(&Self::config_path()?)
    }

    /// Load from an explicit path. Missing file → empty store.
    pub(crate) fn load_from(path: &Path) -> Result<Self, PaksmithError> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => {
                return Err(PaksmithError::Profile {
                    fault: ProfileFault::Io {
                        reason: e.to_string(),
                    },
                });
            }
        };
        toml::from_str(&text).map_err(|e| PaksmithError::Profile {
            fault: ProfileFault::CorruptStore {
                reason: e.message().to_string(),
            },
        })
    }

    /// Save to an explicit path: create the parent dir, then replace the file
    /// through [`StagedReplace::create_owner_only`].
    pub(crate) fn save_to(&self, path: &Path) -> Result<(), PaksmithError> {
        let io = |e: std::io::Error| PaksmithError::Profile {
            fault: ProfileFault::Io {
                reason: e.to_string(),
            },
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(io)?;
        }
        let text = toml::to_string_pretty(self).map_err(|e| PaksmithError::Profile {
            fault: ProfileFault::Io {
                reason: e.to_string(),
            },
        })?;
        replace_owner_only(path, text.as_bytes()).map_err(io)
    }
}

/// Writes `data` over `path` through [`StagedReplace::create_owner_only`]; a
/// failed create, permission or rename step names itself in the error.
pub(crate) fn replace_owner_only(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let mut staged = StagedReplace::create_owner_only(path)?;
    staged.file_mut().write_all(data)?;
    staged.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AesKey;
    use crate::profile::{GameProfile, KeyGuid};
    use std::collections::BTreeMap;

    const K1: &str = "94d25bc3aeb420e0be914edc9d5435a1eaab5f2864e09e94019ac205b727a7de";

    fn sample_store() -> ProfileStore {
        let mut keys = BTreeMap::new();
        let _ = keys.insert(KeyGuid::ZERO, AesKey::from_hex(K1).unwrap());
        let mut profiles = BTreeMap::new();
        let _ = profiles.insert(
            "fortnite".into(),
            GameProfile {
                name: "Fortnite".into(),
                engine_version: Some("5.3".into()),
                keys,
                detect: None,
                mappings: None,
                pak_paths: Vec::new(),
            },
        );
        ProfileStore { profiles }
    }

    #[test]
    fn load_missing_file_is_empty_store() {
        let dir = tempfile::tempdir().unwrap();
        let path = config_path_in(dir.path());
        let store = ProfileStore::load_from(&path).unwrap();
        assert!(store.profiles.is_empty());
    }

    #[test]
    fn save_then_load_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let path = config_path_in(dir.path());
        sample_store().save_to(&path).unwrap();
        let back = ProfileStore::load_from(&path).unwrap();
        assert_eq!(back.profiles["fortnite"].keys[&KeyGuid::ZERO].to_hex(), K1);
        assert_eq!(back.profiles["fortnite"].name, "Fortnite");
    }

    #[cfg(unix)]
    #[test]
    fn saved_file_is_0600() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = config_path_in(dir.path());
        sample_store().save_to(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "store must be saved 0600");
    }

    /// The store, keys included, must not be written through a link at the
    /// fixed temp name older versions used. Widened first, so the save is
    /// also seen to force `0600` back.
    #[cfg(unix)]
    #[test]
    fn a_link_at_the_old_temp_name_is_not_written_through() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let victim = outside.path().join("victim");
        std::fs::write(&victim, b"VICTIM").unwrap();
        let path = config_path_in(dir.path());
        sample_store().save_to(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let link = path.with_extension("toml.tmp");
        std::os::unix::fs::symlink(&victim, &link).unwrap();

        sample_store().save_to(&path).unwrap();

        assert_eq!(std::fs::read(&victim).unwrap(), b"VICTIM");
        let meta = std::fs::symlink_metadata(&path).unwrap();
        assert!(meta.is_file(), "the store was replaced by the link");
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    /// A directory at the store's path fails the replace after the content is
    /// staged.
    #[test]
    fn a_failed_save_names_its_step_and_leaves_no_temp() {
        let dir = tempfile::tempdir().unwrap();
        let path = config_path_in(dir.path());
        std::fs::create_dir_all(&path).unwrap();

        let err = sample_store().save_to(&path).unwrap_err();

        assert!(
            matches!(
                &err,
                PaksmithError::Profile { fault: ProfileFault::Io { reason } }
                    if reason.starts_with("replace destination: ")
            ),
            "{err:?}"
        );
        let names: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["profiles.toml"]);
    }

    #[test]
    fn corrupt_store_is_typed_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = config_path_in(dir.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "this is = not valid = toml [[[").unwrap();
        let err = ProfileStore::load_from(&path).unwrap_err();
        assert!(matches!(
            err,
            crate::PaksmithError::Profile {
                fault: crate::error::ProfileFault::CorruptStore { .. }
            }
        ));
    }

    #[test]
    fn config_path_honors_env_override() {
        // config_path_in is the pure core; this just checks the join shape.
        let p = config_path_in(std::path::Path::new("/tmp/xyz"));
        assert!(p.ends_with("paksmith/profiles.toml"));
        assert!(p.starts_with("/tmp/xyz"));
    }

    /// A non-empty `PAKSMITH_CONFIG_DIR` value wins: the resolved path is rooted
    /// at that override. Exercises `config_path_from_env`'s override branch and
    /// the join, killing both the `Ok(default)` and the `!is_empty` filter
    /// mutants without mutating the process environment.
    #[test]
    fn config_path_from_env_uses_non_empty_override() {
        let p = config_path_from_env(Some(std::ffi::OsString::from("/tmp/cfg"))).unwrap();
        assert!(
            p.starts_with("/tmp/cfg"),
            "override must root the path: {p:?}"
        );
        assert!(p.ends_with("paksmith/profiles.toml"));
    }

    /// An EMPTY override is filtered out, so resolution falls through to the
    /// platform config dir (NOT rooted at the empty string). With the `!`
    /// filter deleted, an empty `OsString` would survive the filter and the
    /// path would root at `""` — this asserts it does not.
    #[test]
    fn config_path_from_env_empty_override_falls_through() {
        let from_empty = config_path_from_env(Some(std::ffi::OsString::new()));
        let from_none = config_path_from_env(None);
        // Both paths take the platform-config-dir branch, so they must agree
        // (either both Ok with the same path, or both the NoConfigDir error).
        match (from_empty, from_none) {
            (Ok(e), Ok(n)) => assert_eq!(
                e, n,
                "empty override must be filtered out → same as absent override"
            ),
            (Err(_), Err(_)) => {} // no platform config dir on this host: both error identically
            other => panic!("empty and absent override must resolve identically: {other:?}"),
        }
    }

    #[test]
    fn config_base_dir_appends_paksmith_to_override() {
        // SAFETY-FREE: exercise the pure helper via the env-injecting variant.
        let base = config_base_dir_from_env(Some(std::ffi::OsString::from("/tmp/cfg"))).unwrap();
        assert!(base.ends_with("paksmith"));
        assert!(base.starts_with("/tmp/cfg"));
    }

    #[test]
    fn config_base_dir_empty_override_matches_none() {
        let from_empty = config_base_dir_from_env(Some(std::ffi::OsString::new()));
        let from_none = config_base_dir_from_env(None);
        assert_eq!(from_empty.is_ok(), from_none.is_ok());
    }

    /// `load_from` only swallows `NotFound` into an empty store; any other I/O
    /// error must surface as a typed `ProfileFault::Io`. Pointing it at a
    /// DIRECTORY makes `read_to_string` fail with a non-NotFound error, which
    /// pins the `e.kind() == NotFound` match guard (the `=> true` mutant would
    /// wrongly return an empty store).
    #[test]
    fn load_from_directory_is_typed_io_error() {
        let dir = tempfile::tempdir().unwrap();
        let err = ProfileStore::load_from(dir.path()).unwrap_err();
        assert!(
            matches!(
                err,
                crate::PaksmithError::Profile {
                    fault: crate::error::ProfileFault::Io { .. }
                }
            ),
            "reading a directory must surface as ProfileFault::Io, not an empty store: {err:?}"
        );
    }
}
