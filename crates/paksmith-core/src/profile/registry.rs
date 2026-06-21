//! Registry document model + strict, capped parsing. Async HTTPS fetch client
//! ([`RegistryClient`]) added in Task 5.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::ProfileFault;
use crate::profile::signature::verify_detached;
use crate::{AesKey, KeyGuid, PaksmithError};

pub(crate) const MAX_PROFILES: usize = 10_000;
pub(crate) const MAX_KEYS_PER_PROFILE: usize = 64;
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
    /// Optional auto-detection rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detect: Option<crate::profile::detection::DetectRules>,
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
        if let Some(d) = &p.detect {
            if d.require_paths.len() > crate::profile::detection::MAX_REQUIRE_PATHS {
                return Err(format!("too many require_paths in `{}`", p.id));
            }
            if d.contains.len() > crate::profile::detection::MAX_CONTAINS {
                return Err(format!("too many contains rules in `{}`", p.id));
            }
            if d.require_paths.iter().any(|s| s.len() > MAX_STR)
                || d.contains
                    .iter()
                    .any(|c| c.path.len() > MAX_STR || c.substring.len() > MAX_STR)
            {
                return Err(format!("detect string field exceeds cap in `{}`", p.id));
            }
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
            .redirect(reqwest::redirect::Policy::custom(|attempt| {
                if attempt.url().scheme() != "https" {
                    attempt.error("redirect to non-https URL refused".to_string())
                } else if attempt.previous().len() >= 5 {
                    attempt.stop()
                } else {
                    attempt.follow()
                }
            }))
            .build()
            .map_err(|e| net_err(&e))?;
        Ok(Self { http })
    }

    /// Fetch `<url>` + `<url>.sig`, verify the ed25519 signature, parse, and return.
    ///
    /// `url` **must** use the `https://` scheme; `http://` is rejected with
    /// [`ProfileFault::InsecureUrl`] before any network I/O unless the
    /// `PAKSMITH_ALLOW_HTTP` environment variable is set.
    ///
    /// # Security note — `PAKSMITH_ALLOW_HTTP`
    ///
    /// Setting `PAKSMITH_ALLOW_HTTP` **disables the https-only transport guard**.
    /// This affordance exists exclusively for integration tests and local
    /// development against a plaintext mock server (e.g. wiremock). **Never set
    /// it in production.** The ed25519 signature check over the trusted public key
    /// is unconditional and unaffected by this flag — a MITM cannot forge a valid
    /// payload without the signing key — but transport-level encryption is lost.
    pub async fn fetch(&self, url: &str, pubkey_hex: &str) -> Result<RegistryDoc, PaksmithError> {
        let allow_http = std::env::var_os("PAKSMITH_ALLOW_HTTP").is_some();
        if !scheme_permitted(url, allow_http) {
            return Err(PaksmithError::Profile {
                fault: ProfileFault::InsecureUrl {
                    url: url.to_string(),
                },
            });
        }
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

/// True iff `url` may be fetched given the `allow_http` override.
///
/// `https://` is always permitted; any other scheme is permitted only when
/// `allow_http` is set (the `PAKSMITH_ALLOW_HTTP` test/dev affordance). Pure —
/// extracted from `fetch` so the scheme/override matrix is unit-testable
/// without a live server (the env read stays in `fetch`).
fn scheme_permitted(url: &str, allow_http: bool) -> bool {
    allow_http || url.starts_with("https://")
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
        let pk =
            sk.verifying_key()
                .as_bytes()
                .iter()
                .fold(String::with_capacity(64), |mut s, b| {
                    write!(s, "{b:02x}").expect("write to String is infallible");
                    s
                });
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
        // Call fetch_inner directly: we're in the same crate, and we don't want
        // to set PAKSMITH_ALLOW_HTTP in-process (edition 2024 makes set_var
        // unsafe, and env state is process-global — would race http_url_is_rejected).
        let doc = client.fetch_inner(&url, &pk).await.unwrap();
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
        // fetch_inner bypasses the scheme gate — we're testing signature validation.
        let err = client.fetch_inner(&url, &pk).await.unwrap_err();
        assert!(matches!(
            err,
            crate::PaksmithError::Profile {
                fault: crate::error::ProfileFault::SignatureInvalid
            }
        ));
    }

    #[tokio::test]
    async fn http_url_is_rejected() {
        // PAKSMITH_ALLOW_HTTP must NOT be set for this test to be meaningful.
        // The integration test sets it only on a subprocess, never in-process,
        // so there is no in-process env race here.
        assert!(
            std::env::var_os("PAKSMITH_ALLOW_HTTP").is_none(),
            "PAKSMITH_ALLOW_HTTP must not be set when running unit tests"
        );
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
    async fn body_exactly_at_cap_is_accepted() {
        // A valid registry doc padded with trailing whitespace to EXACTLY
        // MAX_BODY_BYTES. serde_json tolerates trailing whitespace, so this still
        // parses. Paired with `oversized_body_is_rejected` (cap+1 → reject), this
        // pins the body-cap `>` (vs `>=`) and the `+` (vs `*`) accumulator: a
        // `>=` mutant would wrongly reject the exactly-cap body here.
        let (sk, pk) = keypair();
        let mut body = BODY.as_bytes().to_vec();
        body.resize(MAX_BODY_BYTES, b' ');
        assert_eq!(body.len(), MAX_BODY_BYTES);
        let sig = sk.sign(&body).to_bytes().to_vec();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/cap.json"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/cap.json.sig"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(sig))
            .mount(&server)
            .await;
        let client = RegistryClient::new().unwrap();
        let url = format!("{}/cap.json", server.uri());
        // fetch_inner bypasses the scheme gate — we're testing the body-size cap boundary.
        let doc = client.fetch_inner(&url, &pk).await.unwrap();
        assert_eq!(doc.profiles[0].id, "g");
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
        // fetch_inner bypasses the scheme gate — we're testing the body-size cap.
        let err = client.fetch_inner(&url, &pk).await.unwrap_err();
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

    /// A string field exactly `MAX_STR` chars long must be ACCEPTED.
    /// Pins the `>` (strict) vs `>=` operator in `validate_caps` — a `>=` mutant
    /// would incorrectly reject strings at the boundary.
    #[test]
    fn accepts_exactly_max_str_length() {
        let exactly = "a".repeat(MAX_STR);
        // id at boundary
        let doc =
            parse_registry(format!(r#"[{{"id":"{exactly}","name":"y","keys":{{}}}}]"#).as_bytes())
                .unwrap();
        assert_eq!(
            doc.profiles[0].id, exactly,
            "id exactly MAX_STR must be accepted"
        );

        // name at boundary
        let doc2 =
            parse_registry(format!(r#"[{{"id":"x","name":"{exactly}","keys":{{}}}}]"#).as_bytes())
                .unwrap();
        assert_eq!(
            doc2.profiles[0].name, exactly,
            "name exactly MAX_STR must be accepted"
        );

        // engine_version at boundary
        let doc3 = parse_registry(
            format!(r#"[{{"id":"x","name":"y","engine_version":"{exactly}","keys":{{}}}}]"#)
                .as_bytes(),
        )
        .unwrap();
        assert_eq!(
            doc3.profiles[0].engine_version.as_deref(),
            Some(exactly.as_str()),
            "engine_version exactly MAX_STR must be accepted"
        );
    }

    /// A profile with exactly `MAX_KEYS_PER_PROFILE` keys must be ACCEPTED.
    /// Pins the `>` (strict) operator in the keys cap check.
    #[test]
    fn accepts_exactly_max_keys_per_profile() {
        let k = "94d25bc3aeb420e0be914edc9d5435a1eaab5f2864e09e94019ac205b727a7de";
        let entries: Vec<String> = (0..MAX_KEYS_PER_PROFILE)
            .map(|i| format!(r#""{i:032x}":"{k}""#))
            .collect();
        let doc = parse_registry(
            format!(
                r#"[{{"id":"x","name":"y","keys":{{{}}}}}]"#,
                entries.join(",")
            )
            .as_bytes(),
        )
        .unwrap();
        assert_eq!(
            doc.profiles[0].keys.len(),
            MAX_KEYS_PER_PROFILE,
            "exactly MAX_KEYS_PER_PROFILE must be accepted"
        );
    }

    /// Pins the exact value of `MAX_BODY_BYTES` so that `*`→`+` operator
    /// mutations on `8 * 1024 * 1024` are caught. The constant is used only
    /// inside `RegistryClient::get_capped` (async, requires network), so this
    /// is the only sync-testable anchor for that cap value.
    #[test]
    fn max_body_bytes_is_8_mib() {
        assert_eq!(MAX_BODY_BYTES, 8_388_608, "MAX_BODY_BYTES must equal 8 MiB");
    }

    /// The `scheme_permitted` matrix pins the `||` operator (an `&&` mutant would
    /// reject https when `allow_http` is false — the (false, https) row catches it).
    #[test]
    fn scheme_permitted_matrix() {
        assert!(
            !scheme_permitted("http://x/r.json", false),
            "(false, http) must be refused"
        );
        assert!(
            scheme_permitted("https://x/r.json", false),
            "(false, https) must be allowed"
        );
        assert!(
            scheme_permitted("http://x/r.json", true),
            "(true, http) must be allowed"
        );
        assert!(
            scheme_permitted("https://x/r.json", true),
            "(true, https) must be allowed"
        );
    }

    #[test]
    fn rejects_too_many_require_paths() {
        let paths: Vec<String> = (0..=crate::profile::detection::MAX_REQUIRE_PATHS)
            .map(|i| format!(r#""p{i}""#))
            .collect();
        let json = format!(
            r#"[{{"id":"x","name":"y","keys":{{}},"detect":{{"require_paths":[{}]}}}}]"#,
            paths.join(",")
        );
        assert!(parse_registry(json.as_bytes()).is_err());
    }

    #[test]
    fn rejects_overlong_detect_path() {
        let long = "a".repeat(MAX_STR + 1);
        let json = format!(
            r#"[{{"id":"x","name":"y","keys":{{}},"detect":{{"require_paths":["{long}"]}}}}]"#
        );
        assert!(parse_registry(json.as_bytes()).is_err());
    }

    #[test]
    fn accepts_bounded_detect() {
        let json = r#"[{"id":"x","name":"y","keys":{},"detect":{"require_paths":["Game/Paks"],"contains":[{"path":"a.ini","substring":"X"}]}}]"#;
        let doc = parse_registry(json.as_bytes()).unwrap();
        assert!(doc.profiles[0].detect.is_some());
    }

    #[test]
    fn rejects_too_many_contains() {
        let rules: Vec<String> = (0..=crate::profile::detection::MAX_CONTAINS)
            .map(|i| format!(r#"{{"path":"p{i}","substring":"x"}}"#))
            .collect();
        let json = format!(
            r#"[{{"id":"x","name":"y","keys":{{}},"detect":{{"contains":[{}]}}}}]"#,
            rules.join(",")
        );
        assert!(parse_registry(json.as_bytes()).is_err());
    }

    #[test]
    fn rejects_overlong_contains_path() {
        let long = "a".repeat(MAX_STR + 1);
        let json = format!(
            r#"[{{"id":"x","name":"y","keys":{{}},"detect":{{"contains":[{{"path":"{long}","substring":"x"}}]}}}}]"#
        );
        assert!(parse_registry(json.as_bytes()).is_err());
    }

    #[test]
    fn rejects_overlong_contains_substring() {
        let long = "a".repeat(MAX_STR + 1);
        let json = format!(
            r#"[{{"id":"x","name":"y","keys":{{}},"detect":{{"contains":[{{"path":"a.ini","substring":"{long}"}}]}}}}]"#
        );
        assert!(parse_registry(json.as_bytes()).is_err());
    }
}
