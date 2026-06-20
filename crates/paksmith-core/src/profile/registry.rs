//! Registry document model + strict, capped parsing. Async HTTPS fetch client
//! ([`RegistryClient`]) added in Task 5.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::ProfileFault;
use crate::profile::signature::verify_detached;
use crate::{AesKey, KeyGuid, PaksmithError};

// Used by parse_registry, validate_caps, and (Task 5/6) the async client +
// cache-load path. Clippy sees them as unused until those callers land.
#[allow(dead_code)]
pub(crate) const MAX_PROFILES: usize = 10_000;
#[allow(dead_code)]
pub(crate) const MAX_KEYS_PER_PROFILE: usize = 64;
#[allow(dead_code)]
pub(crate) const MAX_STR: usize = 256;

/// One profile as served by the registry (an explicit `id`, unlike the local
/// store where the id is the map key).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryProfile {
    /// Stable id (used by `--game`).
    pub id: String,
    /// Display name.
    pub name: String,
    /// Optional engine version.
    #[serde(default)]
    pub engine_version: Option<String>,
    /// guid → key (32-hex → 64-hex on the wire).
    #[serde(with = "crate::profile::keys_serde")]
    pub keys: BTreeMap<KeyGuid, AesKey>,
}

/// A parsed registry document.
#[derive(Debug, Clone)]
pub struct RegistryDoc {
    /// The profiles served.
    pub profiles: Vec<RegistryProfile>,
}

/// Cap-check a parsed [`RegistryDoc`]. Returns the doc unchanged on success, or
/// a descriptive error string on violation.
///
/// Extracted so Task 6's cache-load path can reuse identical cap enforcement
/// without duplicating the logic inside `parse_registry`.
// Task 6 (cache-load) adds a second call site; suppress until that caller lands.
#[allow(dead_code)]
pub(crate) fn validate_caps(doc: RegistryDoc) -> Result<RegistryDoc, String> {
    if doc.profiles.len() > MAX_PROFILES {
        return Err(format!(
            "too many profiles: {} > {MAX_PROFILES}",
            doc.profiles.len()
        ));
    }
    for p in &doc.profiles {
        if p.id.len() > MAX_STR
            || p.name.len() > MAX_STR
            || p.engine_version.as_ref().is_some_and(|v| v.len() > MAX_STR)
        {
            return Err("profile string field exceeds cap".into());
        }
        if p.keys.len() > MAX_KEYS_PER_PROFILE {
            return Err(format!("too many keys in `{}`", p.id));
        }
    }
    Ok(doc)
}

/// Parse + cap-check a registry JSON array. `keys_serde` already rejects bad
/// guid/key hex (surfaced here as [`ProfileFault::RegistryParse`]).
pub(crate) fn parse_registry(bytes: &[u8]) -> Result<RegistryDoc, PaksmithError> {
    let parse_err = |reason: String| PaksmithError::Profile {
        fault: ProfileFault::RegistryParse { reason },
    };
    let profiles: Vec<RegistryProfile> =
        serde_json::from_slice(bytes).map_err(|e| parse_err(e.to_string()))?;
    let doc = RegistryDoc { profiles };
    validate_caps(doc).map_err(parse_err)
}

/// Maximum body size (bytes) accepted from the registry (payload or .sig).
///
/// Enforced by streaming chunks — `Content-Length` is not trusted.
pub(crate) const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

/// HTTPS registry client with rustls TLS, 10-second timeout, and a 5-redirect cap.
pub struct RegistryClient {
    http: reqwest::Client,
}

impl RegistryClient {
    /// Build a client. Returns an error if the underlying HTTP stack cannot be
    /// initialised (e.g. no TLS roots available).
    pub fn new() -> Result<Self, PaksmithError> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .map_err(|e| net_err(&e))?;
        Ok(Self { http })
    }

    /// Fetch `<url>` + `<url>.sig`, verify the ed25519 signature, parse, and return.
    ///
    /// `url` **must** use the `https://` scheme; `http://` is rejected with
    /// [`ProfileFault::InsecureUrl`] before any network I/O.
    pub async fn fetch(&self, url: &str, pubkey_hex: &str) -> Result<RegistryDoc, PaksmithError> {
        if !url.starts_with("https://") {
            return Err(PaksmithError::Profile {
                fault: ProfileFault::InsecureUrl {
                    url: url.to_string(),
                },
            });
        }
        self.fetch_inner(url, pubkey_hex).await
    }

    /// Test seam: like [`fetch`](Self::fetch) but skips the https-scheme gate so
    /// wiremock's `http://` test server can be used.
    ///
    /// Not available in production builds.
    #[cfg(test)]
    pub(crate) async fn fetch_allowing_http_for_test(
        &self,
        url: &str,
        pubkey_hex: &str,
    ) -> Result<RegistryDoc, PaksmithError> {
        self.fetch_inner(url, pubkey_hex).await
    }

    /// Common fetch-verify-parse path (scheme-agnostic; callers enforce scheme).
    async fn fetch_inner(&self, url: &str, pubkey_hex: &str) -> Result<RegistryDoc, PaksmithError> {
        let sig_url = format!("{url}.sig");
        let payload = self.get_capped(url).await?;
        let sig = self.get_capped(&sig_url).await?;
        verify_detached(&payload, &sig, pubkey_hex)?;
        parse_registry(&payload)
    }

    /// GET `url`, stream the body in chunks, and return the accumulated bytes.
    ///
    /// Bails with [`ProfileFault::ResponseTooLarge`] if the accumulated body
    /// would exceed [`MAX_BODY_BYTES`]. Does NOT trust `Content-Length`.
    async fn get_capped(&self, url: &str) -> Result<Vec<u8>, PaksmithError> {
        let mut resp = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| net_err(&e))?
            .error_for_status()
            .map_err(|e| net_err(&e))?;
        let mut body: Vec<u8> = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(|e| net_err(&e))? {
            if body.len() + chunk.len() > MAX_BODY_BYTES {
                return Err(PaksmithError::Profile {
                    fault: ProfileFault::ResponseTooLarge {
                        limit: MAX_BODY_BYTES,
                    },
                });
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }
}

fn net_err(e: &reqwest::Error) -> PaksmithError {
    PaksmithError::Profile {
        fault: ProfileFault::Network {
            reason: e.to_string(),
        },
    }
}

#[cfg(test)]
mod fetch_tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn keypair() -> (SigningKey, String) {
        use std::fmt::Write as _;
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk = sk.verifying_key().as_bytes().iter().fold(
            String::with_capacity(64),
            |mut s, b| {
                write!(s, "{b:02x}").expect("write to String is infallible");
                s
            },
        );
        (sk, pk)
    }
    const BODY: &str = r#"[{"id":"g","name":"G","keys":{}}]"#;

    #[tokio::test]
    async fn fetch_verifies_and_parses() {
        let (sk, pk) = keypair();
        let sig = sk.sign(BODY.as_bytes()).to_bytes().to_vec();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/r.json"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(BODY.as_bytes()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/r.json.sig"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(sig))
            .mount(&server)
            .await;
        let client = RegistryClient::new().unwrap();
        let url = format!("{}/r.json", server.uri());
        let doc = client
            .fetch_allowing_http_for_test(&url, &pk)
            .await
            .unwrap();
        assert_eq!(doc.profiles[0].id, "g");
    }

    #[tokio::test]
    async fn tampered_payload_fails_signature() {
        let (sk, pk) = keypair();
        let sig = sk.sign(b"OTHER").to_bytes().to_vec();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/r.json"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(BODY.as_bytes()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/r.json.sig"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(sig))
            .mount(&server)
            .await;
        let client = RegistryClient::new().unwrap();
        let url = format!("{}/r.json", server.uri());
        let err = client
            .fetch_allowing_http_for_test(&url, &pk)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            crate::PaksmithError::Profile {
                fault: crate::error::ProfileFault::SignatureInvalid
            }
        ));
    }

    #[tokio::test]
    async fn http_url_is_rejected() {
        let client = RegistryClient::new().unwrap();
        let err = client
            .fetch("http://example.test/r.json", "ab")
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            crate::PaksmithError::Profile {
                fault: crate::error::ProfileFault::InsecureUrl { .. }
            }
        ));
    }

    #[tokio::test]
    async fn oversized_body_is_rejected() {
        let (sk, pk) = keypair();
        // Serve a body 1 byte larger than the cap.
        let big_body = vec![b'['; MAX_BODY_BYTES + 1];
        let sig = sk.sign(&big_body).to_bytes().to_vec();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/big.json"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(big_body))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/big.json.sig"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(sig))
            .mount(&server)
            .await;
        let client = RegistryClient::new().unwrap();
        let url = format!("{}/big.json", server.uri());
        let err = client
            .fetch_allowing_http_for_test(&url, &pk)
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                crate::PaksmithError::Profile {
                    fault: crate::error::ProfileFault::ResponseTooLarge { .. }
                }
            ),
            "expected ResponseTooLarge, got: {err:?}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const K: &str = "94d25bc3aeb420e0be914edc9d5435a1eaab5f2864e09e94019ac205b727a7de";

    #[test]
    fn parses_valid_array() {
        let json = format!(
            r#"[{{"id":"fortnite","name":"Fortnite","engine_version":"5.3","keys":{{"00000000000000000000000000000000":"{K}"}}}}]"#
        );
        let doc = parse_registry(json.as_bytes()).unwrap();
        assert_eq!(doc.profiles.len(), 1);
        assert_eq!(doc.profiles[0].id, "fortnite");
        assert_eq!(doc.profiles[0].keys.len(), 1);
    }

    #[test]
    fn rejects_too_many_profiles() {
        let one = r#"{"id":"x","name":"y","keys":{}}"#;
        let many = std::iter::repeat_n(one, MAX_PROFILES + 1)
            .collect::<Vec<_>>()
            .join(",");
        let err = parse_registry(format!("[{many}]").as_bytes()).unwrap_err();
        assert!(matches!(
            err,
            crate::PaksmithError::Profile {
                fault: crate::error::ProfileFault::RegistryParse { .. }
            }
        ));
    }

    #[test]
    fn rejects_bad_key_hex() {
        let err = parse_registry(
            br#"[{"id":"x","name":"y","keys":{"00000000000000000000000000000000":"nothex"}}]"#,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            crate::PaksmithError::Profile {
                fault: crate::error::ProfileFault::RegistryParse { .. }
            }
        ));
    }

    #[test]
    fn rejects_overlong_id() {
        let id = "a".repeat(MAX_STR + 1);
        let err = parse_registry(format!(r#"[{{"id":"{id}","name":"y","keys":{{}}}}]"#).as_bytes())
            .unwrap_err();
        assert!(matches!(
            err,
            crate::PaksmithError::Profile {
                fault: crate::error::ProfileFault::RegistryParse { .. }
            }
        ));
    }

    fn assert_registry_parse_err(json: &str) {
        assert!(
            matches!(
                parse_registry(json.as_bytes()).unwrap_err(),
                crate::PaksmithError::Profile {
                    fault: crate::error::ProfileFault::RegistryParse { .. }
                }
            ),
            "expected RegistryParse for: {json}"
        );
    }

    #[test]
    fn rejects_overlong_name() {
        let name = "a".repeat(MAX_STR + 1);
        assert_registry_parse_err(&format!(r#"[{{"id":"x","name":"{name}","keys":{{}}}}]"#));
    }

    #[test]
    fn rejects_overlong_engine_version() {
        let v = "5".repeat(MAX_STR + 1);
        assert_registry_parse_err(&format!(
            r#"[{{"id":"x","name":"y","engine_version":"{v}","keys":{{}}}}]"#
        ));
    }

    #[test]
    fn rejects_too_many_keys() {
        // MAX_KEYS_PER_PROFILE + 1 distinct 32-hex GUIDs, each → a valid 64-hex key.
        let entries: Vec<String> = (0..=MAX_KEYS_PER_PROFILE)
            .map(|i| format!(r#""{i:032x}":"{K}""#))
            .collect();
        assert_registry_parse_err(&format!(
            r#"[{{"id":"x","name":"y","keys":{{{}}}}}]"#,
            entries.join(",")
        ));
    }

    #[test]
    fn accepts_exactly_max_profiles() {
        // Boundary: exactly MAX_PROFILES must be accepted (the cap is strict `>`).
        let one = r#"{"id":"x","name":"y","keys":{}}"#;
        let many = std::iter::repeat_n(one, MAX_PROFILES)
            .collect::<Vec<_>>()
            .join(",");
        let doc = parse_registry(format!("[{many}]").as_bytes()).unwrap();
        assert_eq!(doc.profiles.len(), MAX_PROFILES);
    }
}
