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

impl RegistryConfig {
    /// Load from `<config_dir>/paksmith/config.toml`. A missing file or absent
    /// `[registry]` section returns compiled-in defaults. Corrupt TOML returns
    /// [`ProfileFault::CorruptStore`]. Other I/O errors return
    /// [`ProfileFault::Io`].
    pub fn load() -> Result<Self, PaksmithError> {
        let path = crate::profile::store::config_base_dir()?.join("config.toml");
        match std::fs::read_to_string(&path) {
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
    fn corrupt_is_typed_error() {
        let err = from_toml_str("this = = not toml [[[").unwrap_err();
        assert!(matches!(
            err,
            crate::PaksmithError::Profile {
                fault: crate::error::ProfileFault::CorruptStore { .. }
            }
        ));
    }
}
