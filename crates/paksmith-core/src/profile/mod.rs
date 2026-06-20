//! Local game profiles: persistent, named AES key storage with guid→key
//! resolution. The store lives in a single TOML file (see [`store`]); key
//! testing lives in [`key_test`]. Network registry (5c) and auto-detection
//! (5d) are separate sub-phases and not part of this module.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::AesKey;

/// 16-byte UE encryption-key GUID. The all-zero GUID is the conventional
/// "default" key (single-key and pre-UE4.22 paks use it).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct KeyGuid([u8; 16]);

/// Failure decoding a 32-hex-char [`KeyGuid`]. Carries no key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyGuidHexError {
    /// The hex string was not 32 chars.
    WrongLength {
        /// Number of hex chars seen.
        got: usize,
    },
    /// A non-hex character was present.
    NonHex,
}

impl std::fmt::Display for KeyGuidHexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongLength { got } => write!(f, "expected 32 hex chars (16 bytes), got {got}"),
            Self::NonHex => f.write_str("GUID contains non-hex characters"),
        }
    }
}

impl std::error::Error for KeyGuidHexError {}

impl KeyGuid {
    /// The all-zero GUID = the "default" key.
    pub const ZERO: KeyGuid = KeyGuid([0u8; 16]);

    /// Wrap raw GUID bytes.
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The raw 16 GUID bytes.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// True iff this is the all-zero (default) GUID.
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 16]
    }

    /// Lowercase 32-char hex.
    pub fn to_hex(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(32);
        for b in self.0 {
            write!(s, "{b:02x}").expect("write to String is infallible");
        }
        s
    }

    /// Decode a 32-hex-char GUID (case-insensitive, no `0x` prefix).
    ///
    /// # Panics
    ///
    /// Does not panic in practice. The two `.expect()` calls inside are
    /// unreachable: `from_utf8` is called on a 2-byte slice already validated
    /// as ASCII hex digits, and `from_str_radix` is called on that same pair.
    pub fn from_hex(s: &str) -> Result<Self, KeyGuidHexError> {
        if s.len() != 32 {
            return Err(KeyGuidHexError::WrongLength { got: s.len() });
        }
        let mut bytes = [0u8; 16];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            if !chunk[0].is_ascii_hexdigit() || !chunk[1].is_ascii_hexdigit() {
                return Err(KeyGuidHexError::NonHex);
            }
            bytes[i] = u8::from_str_radix(
                std::str::from_utf8(chunk).expect("ascii-validated above"),
                16,
            )
            .expect("ascii-hex pair always parses");
        }
        Ok(Self(bytes))
    }
}

/// One game's stored keys + light metadata. The profile's id is the
/// [`ProfileStore`] map key, not a field here.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct GameProfile {
    /// Human-readable display name.
    pub name: String,
    /// Optional engine version (e.g. `"5.3"`); feeds future detection and the
    /// UE5.2-vs-5.3 texture-version gap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine_version: Option<String>,
    /// guid → key. Serialized as a TOML table of 32-hex → 64-hex strings.
    #[serde(default, with = "keys_serde")]
    pub keys: BTreeMap<KeyGuid, AesKey>,
}

/// The whole on-disk document.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProfileStore {
    /// id → profile.
    #[serde(default)]
    pub profiles: BTreeMap<String, GameProfile>,
}

/// Resolve the key for `pak_guid`: an exact GUID match wins; a pak with no
/// GUID or the all-zero GUID falls back to the [`KeyGuid::ZERO`] default;
/// otherwise `None`.
///
/// When a non-zero pak GUID is present but absent from the map, resolution
/// falls back to the zero-default if one exists. This means a profile that
/// stores only a single default key still opens GUID-tagged paks.
pub fn resolve_key<'a>(
    profile: &'a GameProfile,
    pak_guid: Option<&[u8; 16]>,
) -> Option<&'a AesKey> {
    match pak_guid {
        Some(bytes) if *bytes != [0u8; 16] => profile
            .keys
            .get(&KeyGuid::from_bytes(*bytes))
            .or_else(|| profile.keys.get(&KeyGuid::ZERO)),
        _ => profile.keys.get(&KeyGuid::ZERO),
    }
}

/// serde adapter: `BTreeMap<KeyGuid, AesKey>` ↔ a TOML table of hex strings.
/// `AesKey` is intentionally NOT `Serialize`; this is the only place a key is
/// turned into hex, gated to the profile store.
mod keys_serde {
    use std::collections::BTreeMap;

    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};

    use super::{AesKey, KeyGuid};

    pub fn serialize<S: Serializer>(
        keys: &BTreeMap<KeyGuid, AesKey>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        let as_hex: BTreeMap<String, String> =
            keys.iter().map(|(g, k)| (g.to_hex(), k.to_hex())).collect();
        s.collect_map(as_hex)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<BTreeMap<KeyGuid, AesKey>, D::Error> {
        let raw = BTreeMap::<String, String>::deserialize(d)?;
        let mut out = BTreeMap::new();
        for (g, k) in raw {
            let guid = KeyGuid::from_hex(&g).map_err(D::Error::custom)?;
            let key = AesKey::from_hex(&k).map_err(D::Error::custom)?;
            let _ = out.insert(guid, key);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::AesKey;

    fn key(h: &str) -> AesKey {
        AesKey::from_hex(h).unwrap()
    }
    const K1: &str = "94d25bc3aeb420e0be914edc9d5435a1eaab5f2864e09e94019ac205b727a7de";

    #[test]
    fn key_guid_hex_roundtrip_and_zero() {
        assert!(KeyGuid::ZERO.is_zero());
        let g = KeyGuid::from_hex("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6").unwrap();
        assert_eq!(g.to_hex(), "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6");
        assert!(!g.is_zero());
        assert!(matches!(
            KeyGuid::from_hex("a1b2"),
            Err(KeyGuidHexError::WrongLength { got: 4 })
        ));
        assert!(matches!(
            KeyGuid::from_hex(&"z".repeat(32)),
            Err(KeyGuidHexError::NonHex)
        ));
    }

    #[test]
    fn resolve_prefers_exact_guid_then_zero_default() {
        let g = KeyGuid::from_hex("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6").unwrap();
        let mut keys = BTreeMap::new();
        let _ = keys.insert(KeyGuid::ZERO, key(&"11".repeat(32)));
        let _ = keys.insert(g, key(K1));
        let p = GameProfile {
            name: "G".into(),
            engine_version: None,
            keys,
        };
        // exact GUID hit
        assert_eq!(resolve_key(&p, Some(g.as_bytes())).unwrap().to_hex(), K1);
        // pak has no GUID → zero-default
        assert_eq!(resolve_key(&p, None).unwrap().to_hex(), "11".repeat(32));
        // pak has all-zero GUID → zero-default
        assert_eq!(
            resolve_key(&p, Some(&[0u8; 16])).unwrap().to_hex(),
            "11".repeat(32)
        );
        // unknown GUID, no zero-default present
        let p2 = GameProfile {
            name: "G".into(),
            engine_version: None,
            keys: BTreeMap::new(),
        };
        assert!(resolve_key(&p2, Some(g.as_bytes())).is_none());
    }

    #[test]
    fn store_toml_roundtrip_is_deterministic() {
        let mut keys = BTreeMap::new();
        let _ = keys.insert(KeyGuid::ZERO, key(K1));
        let mut profiles = BTreeMap::new();
        let _ = profiles.insert(
            "fortnite".to_string(),
            GameProfile {
                name: "Fortnite".into(),
                engine_version: Some("5.3".into()),
                keys,
            },
        );
        let store = ProfileStore { profiles };
        let text = toml::to_string_pretty(&store).unwrap();
        assert!(text.contains("[profiles.fortnite]"));
        assert!(text.contains(r#"name = "Fortnite""#));
        assert!(text.contains(r#"engine_version = "5.3""#));
        assert!(text.contains(K1), "key serialized as hex");
        let back: ProfileStore = toml::from_str(&text).unwrap();
        assert_eq!(back.profiles["fortnite"].keys[&KeyGuid::ZERO].to_hex(), K1);
        assert_eq!(
            back.profiles["fortnite"].engine_version.as_deref(),
            Some("5.3")
        );
    }

    #[test]
    fn key_serialized_as_lowercase_hex_not_debug() {
        // AesKey Debug is redacted; the store must contain the real hex, never "<redacted>".
        let mut keys = BTreeMap::new();
        let _ = keys.insert(KeyGuid::ZERO, key(K1));
        let mut profiles = BTreeMap::new();
        let _ = profiles.insert(
            "g".into(),
            GameProfile {
                name: "G".into(),
                engine_version: None,
                keys,
            },
        );
        let text = toml::to_string_pretty(&ProfileStore { profiles }).unwrap();
        assert!(
            !text.contains("redacted"),
            "store must not contain a redacted Debug: {text}"
        );
    }
}
