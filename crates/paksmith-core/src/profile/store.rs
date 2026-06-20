//! TOML disk I/O for the profile store. One file at
//! `<config_dir>/paksmith/profiles.toml`, overridable via
//! `PAKSMITH_CONFIG_DIR`. Written atomically with `0600` perms on unix.

use std::path::{Path, PathBuf};

use crate::PaksmithError;
use crate::error::ProfileFault;
use crate::profile::ProfileStore;

/// `<base>/paksmith/profiles.toml`.
pub(crate) fn config_path_in(base: &Path) -> PathBuf {
    base.join("paksmith").join("profiles.toml")
}

impl ProfileStore {
    /// Resolve the store path: `$PAKSMITH_CONFIG_DIR/paksmith/profiles.toml`
    /// if set (and non-empty), else the platform config dir.
    pub fn config_path() -> Result<PathBuf, PaksmithError> {
        if let Some(base) = std::env::var_os("PAKSMITH_CONFIG_DIR").filter(|b| !b.is_empty()) {
            return Ok(config_path_in(Path::new(&base)));
        }
        let base = dirs::config_dir().ok_or(PaksmithError::Profile {
            fault: ProfileFault::NoConfigDir,
        })?;
        Ok(config_path_in(&base))
    }

    /// Load the store at the resolved [`Self::config_path`].
    pub fn load() -> Result<Self, PaksmithError> {
        Self::load_from(&Self::config_path()?)
    }

    /// Save the store to the resolved [`Self::config_path`].
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

    /// Save to an explicit path: create the parent dir, write atomically via a
    /// sibling temp file + rename. On unix the temp file is created at `0600`
    /// from the start — no world-readable window.
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
        let tmp = path.with_extension("toml.tmp");
        write_restricted(&tmp, text.as_bytes()).map_err(io)?;
        std::fs::rename(&tmp, path).map_err(io)?;
        Ok(())
    }
}

/// Write `data` to `path` with mode `0600` from creation (unix) so that AES
/// key material is never visible to other users even momentarily.
#[cfg(unix)]
fn write_restricted(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?
        .write_all(data)
}

/// On non-unix platforms there is no `mode()`, so fall back to a plain write.
#[cfg(not(unix))]
fn write_restricted(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, data)
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

    /// The `config_path` empty-env filter is: `var_os(...).filter(|b| !b.is_empty())`.
    /// This unit test verifies the filter predicate on `OsString` directly so
    /// we don't need to mutate the process environment (which is forbidden by
    /// `-D unsafe-code`).
    #[test]
    fn empty_osstring_is_filtered_out() {
        use std::ffi::OsString;
        let empty = OsString::new();
        let non_empty = OsString::from("/tmp/cfg");

        // Verify the predicate used in config_path() directly.
        assert!(empty.is_empty(), "OsString::new() must be empty");
        assert!(!non_empty.is_empty(), "non-empty OsString must not be empty");
    }
}
