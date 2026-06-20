//! Registry configuration from `<config_dir>/paksmith/config.toml` `[registry]`.

use serde::Deserialize;

use crate::PaksmithError;
use crate::error::ProfileFault;
use crate::profile::signature::TRUSTED_REGISTRY_PUBKEY_HEX;

/// Documented placeholder default endpoint (no live registry yet).
pub(crate) const DEFAULT_REGISTRY_URL: &str = "https://registry.paksmith.invalid/profiles.json";

/// Resolved registry configuration.
#[derive(Debug, Clone)]
pub struct RegistryConfig {
    /// Registry endpoint (https).
    pub url: String,
    /// Re-fetch when the cache is older than this many hours.
    pub staleness_hours: u64,
    /// Trusted ed25519 verifying key (64-hex).
    pub public_key_hex: String,
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            url: DEFAULT_REGISTRY_URL.to_string(),
            staleness_hours: 24,
            public_key_hex: TRUSTED_REGISTRY_PUBKEY_HEX.to_string(),
        }
    }
}

#[derive(Deserialize, Default)]
struct RawConfig {
    #[serde(default)]
    registry: RawRegistry,
}

#[derive(Deserialize, Default)]
struct RawRegistry {
    url: Option<String>,
    staleness_hours: Option<u64>,
    public_key: Option<String>,
}

/// Parse a TOML string into a [`RegistryConfig`], falling back to defaults for
/// any missing `[registry]` section or fields. Corrupt TOML returns
/// [`ProfileFault::CorruptStore`].
pub(crate) fn from_toml_str(s: &str) -> Result<RegistryConfig, PaksmithError> {
    let raw: RawConfig = toml::from_str(s).map_err(|e| PaksmithError::Profile {
        fault: ProfileFault::CorruptStore {
            reason: e.message().to_string(),
        },
    })?;
    let d = RegistryConfig::default();
    Ok(RegistryConfig {
        url: raw.registry.url.unwrap_or(d.url),
        staleness_hours: raw.registry.staleness_hours.unwrap_or(d.staleness_hours),
        public_key_hex: raw.registry.public_key.unwrap_or(d.public_key_hex),
    })
}

/// Fail-closed guard against using the built-in placeholder key on a custom
/// endpoint.
///
/// The default trusted public key is the verifying key of a publicly-derived
/// throwaway keypair (seed `[1u8; 32]`). Using it to verify a
/// payload from a non-default endpoint provides zero integrity — anyone can
/// forge a signature with the matching (public) signing key. When the resolved
/// key is the placeholder AND the resolved URL is not the default endpoint,
/// refuse before any network I/O.
///
/// Pure (no env/IO) so it is trivially unit-testable from both CLI fetch paths.
pub fn ensure_key_matches_registry(url: &str, public_key_hex: &str) -> Result<(), PaksmithError> {
    // Case-insensitive: the hex decoder accepts upper- or lower-case, so an
    // uppercase copy of the placeholder is the same (forgeable) key and must
    // not slip past this guard.
    if public_key_hex.eq_ignore_ascii_case(TRUSTED_REGISTRY_PUBKEY_HEX)
        && url != DEFAULT_REGISTRY_URL
    {
        return Err(PaksmithError::Profile {
            fault: ProfileFault::PlaceholderKeyForCustomRegistry,
        });
    }
    Ok(())
}

impl RegistryConfig {
    /// Load from `<config_dir>/paksmith/config.toml`. A missing file or absent
    /// `[registry]` section returns compiled-in defaults. Corrupt TOML returns
    /// [`ProfileFault::CorruptStore`]. Other I/O errors return
    /// [`ProfileFault::Io`].
    pub fn load() -> Result<Self, PaksmithError> {
        let path = crate::profile::store::config_base_dir()?.join("config.toml");
        Self::load_from_path(&path)
    }

    /// Load from an explicit config file path. Used by [`Self::load`] after path
    /// resolution; exposed `pub(crate)` so it can be unit-tested independently
    /// of the `PAKSMITH_CONFIG_DIR` env variable.
    pub(crate) fn load_from_path(path: &std::path::Path) -> Result<Self, PaksmithError> {
        match std::fs::read_to_string(path) {
            Ok(s) => from_toml_str(&s),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(PaksmithError::Profile {
                fault: ProfileFault::Io {
                    reason: e.to_string(),
                },
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_when_empty() {
        let c = from_toml_str("").unwrap();
        assert_eq!(c.url, DEFAULT_REGISTRY_URL);
        assert_eq!(c.staleness_hours, 24);
        assert_eq!(
            c.public_key_hex,
            crate::profile::signature::TRUSTED_REGISTRY_PUBKEY_HEX
        );
    }

    #[test]
    fn overrides_parse() {
        let c = from_toml_str(
            "[registry]\nurl = \"https://example.test/r.json\"\nstaleness_hours = 6\npublic_key = \"ab\"\n",
        )
        .unwrap();
        assert_eq!(c.url, "https://example.test/r.json");
        assert_eq!(c.staleness_hours, 6);
        assert_eq!(c.public_key_hex, "ab");
    }

    #[test]
    fn partial_override_defaults_the_rest() {
        // Only `url` is set; staleness_hours + public_key fall back per-field.
        let c = from_toml_str("[registry]\nurl = \"https://example.test/r.json\"\n").unwrap();
        assert_eq!(c.url, "https://example.test/r.json");
        assert_eq!(
            c.staleness_hours, 24,
            "missing staleness_hours must default to 24"
        );
        assert_eq!(
            c.public_key_hex,
            crate::profile::signature::TRUSTED_REGISTRY_PUBKEY_HEX,
            "missing public_key must default to the trusted const"
        );
    }

    #[test]
    fn corrupt_is_typed_error() {
        let err = from_toml_str("this = = not toml [[[").unwrap_err();
        assert!(matches!(
            err,
            crate::PaksmithError::Profile {
                fault: crate::error::ProfileFault::CorruptStore { .. }
            }
        ));
    }

    #[test]
    fn load_from_path_missing_is_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = RegistryConfig::load_from_path(&dir.path().join("nope.toml")).unwrap();
        assert_eq!(cfg.url, DEFAULT_REGISTRY_URL);
    }

    #[test]
    fn load_from_path_present_is_parsed() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("config.toml");
        std::fs::write(&p, "[registry]\nurl = \"https://test.invalid/r.json\"\n").unwrap();
        let cfg = RegistryConfig::load_from_path(&p).unwrap();
        assert_eq!(cfg.url, "https://test.invalid/r.json");
    }

    #[test]
    fn placeholder_key_on_custom_url_is_refused() {
        let err =
            ensure_key_matches_registry("https://evil.example/r.json", TRUSTED_REGISTRY_PUBKEY_HEX)
                .unwrap_err();
        assert!(matches!(
            err,
            crate::PaksmithError::Profile {
                fault: crate::error::ProfileFault::PlaceholderKeyForCustomRegistry
            }
        ));
    }

    /// The hex decoder is case-insensitive, so an UPPERCASE copy of the
    /// placeholder is the same forgeable key — the guard must reject it too
    /// (`==` would miss it; `eq_ignore_ascii_case` catches it).
    #[test]
    fn uppercase_placeholder_key_on_custom_url_is_refused() {
        let upper = TRUSTED_REGISTRY_PUBKEY_HEX.to_ascii_uppercase();
        assert!(matches!(
            ensure_key_matches_registry("https://evil.example/r.json", &upper).unwrap_err(),
            crate::PaksmithError::Profile {
                fault: crate::error::ProfileFault::PlaceholderKeyForCustomRegistry
            }
        ));
    }

    #[test]
    fn custom_key_on_custom_url_is_allowed() {
        assert!(ensure_key_matches_registry("https://evil.example/r.json", "ab").is_ok());
    }

    #[test]
    fn placeholder_key_on_default_url_is_allowed() {
        assert!(
            ensure_key_matches_registry(DEFAULT_REGISTRY_URL, TRUSTED_REGISTRY_PUBKEY_HEX).is_ok()
        );
    }

    /// `load_from_path` on a directory (EISDIR, not NotFound) must return an
    /// `Io` fault, not `Ok(default)`. Pins the `NotFound` match guard so replacing
    /// it with `true` (treating ALL I/O errors as "file absent") is caught.
    #[test]
    fn load_from_path_directory_is_typed_io_error() {
        let dir = tempfile::tempdir().unwrap();
        let err = RegistryConfig::load_from_path(dir.path()).unwrap_err();
        assert!(
            matches!(
                err,
                crate::PaksmithError::Profile {
                    fault: crate::error::ProfileFault::Io { .. }
                }
            ),
            "reading a directory must produce an Io fault, not Ok(default): {err}"
        );
    }
}
