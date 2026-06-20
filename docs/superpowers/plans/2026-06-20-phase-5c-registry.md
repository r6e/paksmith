# Phase 5c — Remote Game-Profile Registry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fetch ed25519-signed game profiles from a configurable HTTPS endpoint, verify + cache them (`0600`), layer them under the user's local store, and auto-fetch on `--game` resolution with graceful offline degradation.

**Architecture:** A new async `RegistryClient` (reqwest + rustls-tls) lives in `paksmith-core/src/profile/registry.rs`; the CLI builds a current-thread tokio runtime and `block_on`s it. Downloaded profiles are verified against a compiled-in (config-overridable) ed25519 key, parsed with strict caps, and cached as a separate `registry-cache.json` that user `profiles.toml` always overrides.

**Tech Stack:** Rust 2024 (MSRV 1.88 — no bump), `reqwest` (rustls-tls), `tokio` (current-thread rt), `ed25519-dalek`, `serde`/`serde_json`, `toml`, `dirs`; `wiremock` (dev) for mock-HTTP tests. Builds on 5b's `GameProfile`/`KeyGuid`/`ProfileStore`/`resolve_key`/`config` helpers/`write_restricted`/`ProfileFault`.

## Global Constraints

- MSRV 1.88; edition 2024. The new deps all build on 1.88 — do NOT bump MSRV. `Minimal versions` CI must resolve — pin sane floors.
- No panics in `paksmith-core` — all fallible ops return `Result<T, PaksmithError>`. `thiserror` + wire-stable `Display`; `tracing` (no `println!` in core; CLI commands print user output).
- **AES keys are secrets:** never in any log / `Debug` / error message. `AesKey` keeps 5a/5b zeroize/redaction + non-`Serialize`; registry/cache (de)serialize keys ONLY via the existing `keys_serde` hex adapter.
- **Network input is untrusted until verified:** https-only (reject `http://`); hard body-size cap (8 MiB) enforced on the READ (not trusting `Content-Length`); request timeout (10 s) + redirect cap (5); ed25519 **detached** signature over the raw payload bytes verified against the trusted key BEFORE any parse/cache; reject on verify failure even over HTTPS.
- **Strict parsing with caps on BOTH the fetch path and the cache-load path** (the cache file is user-editable = untrusted): max 10 000 profiles, max 64 keys/profile, max 256-char id/name/engine, 32-hex guid + 64-hex key only. No panics on malformed input.
- `registry-cache.json` holds AES keys → written `0600` from creation (reuse `write_restricted`), atomic temp+rename, under `<config_dir>/paksmith/` honoring `PAKSMITH_CONFIG_DIR`.
- TLS = **rustls** (pure-Rust, bundled webpki roots); NO OpenSSL/native-tls.
- The default registry URL + compiled-in trusted public key are **documented placeholders** (no live registry yet); the mechanism is fully tested via a committed deterministic test keypair + `wiremock`.
- Conventional commits; one logical change per commit. Run `cargo fmt --all`, `clippy --workspace --all-targets --all-features -D warnings`, `test --workspace --all-features`, `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features`, `typos .` before declaring a task done. Do NOT bump any `Cargo.toml` `version =`.
- Before the final push: run `cargo mutants --in-diff $(git merge-base origin/main HEAD)..HEAD --all-features` to 0 missed (the PR-diff mutants job is not in the local gate chain).

## File Structure

- `crates/paksmith-core/src/profile/store.rs` — MODIFY: extract `pub(crate) fn config_base_dir()` (resolve `<base>/paksmith` honoring `PAKSMITH_CONFIG_DIR`); make `write_restricted` `pub(crate)`.
- `crates/paksmith-core/src/profile/signature.rs` — CREATE: ed25519 detached verify + `TRUSTED_REGISTRY_PUBKEY_HEX`.
- `crates/paksmith-core/src/profile/config.rs` — CREATE: `RegistryConfig` from `config.toml` `[registry]`.
- `crates/paksmith-core/src/profile/registry.rs` — CREATE: `RegistryProfile`/`RegistryDoc` + strict parse + async `RegistryClient::fetch`.
- `crates/paksmith-core/src/profile/cache.rs` — CREATE: `RegistryCache` read/write (`0600`) + staleness + lookup.
- `crates/paksmith-core/src/profile/mod.rs` — MODIFY: register submodules; `resolve_layered` helper.
- `crates/paksmith-core/src/error.rs` — MODIFY: extend `ProfileFault` with registry variants.
- `crates/paksmith-core/Cargo.toml` + root `Cargo.toml` — MODIFY: add `reqwest`, `ed25519-dalek` (core deps); `tokio` + `wiremock` (core dev-deps).
- `crates/paksmith-cli/Cargo.toml` — MODIFY: add `tokio` (rt).
- `crates/paksmith-cli/src/commands/profile.rs` — MODIFY: `profile fetch`; `profile list` shows cached.
- `crates/paksmith-cli/src/commands/key_resolve.rs` — MODIFY: `--game` auto-fetch + offline degradation.
- `crates/paksmith-cli/src/main.rs` — MODIFY: build the tokio runtime; thread it to the fetch sites.
- `docs/plans/ROADMAP.md` + `deny.toml` — MODIFY (gate task).

---

### Task 1: Shared config-dir resolver + reusable `write_restricted`

5b's `config_path_from_env` hard-codes the `profiles.toml` filename. Extract the base-dir resolution so `config.toml` and `registry-cache.json` reuse it, and widen `write_restricted` to `pub(crate)` so `cache.rs` reuses the `0600` writer.

**Files:**
- Modify: `crates/paksmith-core/src/profile/store.rs`

**Interfaces:**
- Consumes: existing `config_path_in`, `config_path_from_env`, `ProfileFault::NoConfigDir`.
- Produces: `pub(crate) fn config_base_dir() -> Result<std::path::PathBuf, crate::PaksmithError>` (returns `<resolved>/paksmith`, honoring `PAKSMITH_CONFIG_DIR`; empty/absent → `dirs::config_dir()/paksmith`; neither → `ProfileFault::NoConfigDir`). `pub(crate) fn write_restricted(path: &std::path::Path, data: &[u8]) -> std::io::Result<()>` (both cfg variants made `pub(crate)`).

- [ ] **Step 1: Write the failing test** — in `store.rs`'s test module:

```rust
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
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p paksmith-core --all-features config_base_dir 2>&1 | tail -10`
Expected: FAIL — `config_base_dir_from_env` not found.

- [ ] **Step 3: Implement** — in `store.rs`, refactor the base resolution out of `config_path_from_env`:

```rust
/// Resolve `<base>/paksmith` from an explicit `PAKSMITH_CONFIG_DIR` value:
/// a non-empty value wins; empty/absent → the platform config dir. Pure
/// (env value passed in) so it is unit-testable under `-D unsafe-code`.
pub(crate) fn config_base_dir_from_env(
    env_override: Option<std::ffi::OsString>,
) -> Result<std::path::PathBuf, crate::PaksmithError> {
    if let Some(base) = env_override.filter(|b| !b.is_empty()) {
        return Ok(std::path::Path::new(&base).join("paksmith"));
    }
    let base = dirs::config_dir().ok_or(crate::PaksmithError::Profile {
        fault: crate::error::ProfileFault::NoConfigDir,
    })?;
    Ok(base.join("paksmith"))
}

/// `<config_dir>/paksmith`, honoring `PAKSMITH_CONFIG_DIR`.
pub(crate) fn config_base_dir() -> Result<std::path::PathBuf, crate::PaksmithError> {
    config_base_dir_from_env(std::env::var_os("PAKSMITH_CONFIG_DIR"))
}
```

Refactor `config_path_from_env` to delegate: `Ok(config_base_dir_from_env(env_override)?.join("profiles.toml"))` (and `config_path_in` stays for tests that join a base directly, OR re-express it via the new helper — keep its existing callers green). Change both `write_restricted` definitions from `fn` to `pub(crate) fn`.

- [ ] **Step 4: Run tests** — `cargo test -p paksmith-core --all-features profile:: 2>&1 | tail -10` (new + all existing 5b store tests pass).

- [ ] **Step 5: Commit**

```bash
git add crates/paksmith-core/src/profile/store.rs
git commit -m "refactor(profile): extract config_base_dir + share write_restricted for 5c"
```

---

### Task 2: ed25519 detached-signature verification (`signature.rs`)

**Files:**
- Create: `crates/paksmith-core/src/profile/signature.rs`
- Modify: `crates/paksmith-core/src/profile/mod.rs` (`pub(crate) mod signature;`)
- Modify: `crates/paksmith-core/src/error.rs` (`ProfileFault::SignatureInvalid`)
- Modify: root `Cargo.toml` + `crates/paksmith-core/Cargo.toml` (add `ed25519-dalek`)

**Interfaces:**
- Produces: `pub(crate) const TRUSTED_REGISTRY_PUBKEY_HEX: &str` (64-hex = 32-byte ed25519 key); `pub(crate) fn verify_detached(payload: &[u8], sig: &[u8], pubkey_hex: &str) -> Result<(), crate::PaksmithError>` (Ok on valid; else `ProfileFault::SignatureInvalid`; no payload/key bytes in the error; never panics on malformed sizes).
- Produces (error): `ProfileFault::SignatureInvalid` (Display: `"registry signature verification failed"`).

- [ ] **Step 1: Add the dep.** Root `Cargo.toml` `[workspace.dependencies]`: `ed25519-dalek = "2"`. `crates/paksmith-core/Cargo.toml` `[dependencies]`: `ed25519-dalek = { workspace = true }`. (Default features include signing — used by tests; production uses only verify.)

- [ ] **Step 2: Add the error variant** — in `error.rs`, add to `enum ProfileFault` (it is already `#[non_exhaustive]`):

```rust
    /// The registry payload's ed25519 signature did not verify against the
    /// trusted key. Carries no payload or key material.
    #[error("registry signature verification failed")]
    SignatureInvalid,
```

- [ ] **Step 3: Write the failing test** — create `signature.rs` with a test module that signs with a DETERMINISTIC test key (no rng):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn test_keypair() -> (SigningKey, String) {
        // Deterministic 32-byte seed → reproducible test keypair (no rng dep).
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pubkey_hex = hex_lower(sk.verifying_key().as_bytes());
        (sk, pubkey_hex)
    }
    fn hex_lower(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut s = String::new();
        for b in bytes { write!(s, "{b:02x}").unwrap(); }
        s
    }

    #[test]
    fn valid_signature_verifies() {
        let (sk, pk) = test_keypair();
        let payload = b"registry-bytes";
        let sig = sk.sign(payload).to_bytes();
        assert!(verify_detached(payload, &sig, &pk).is_ok());
    }

    #[test]
    fn tampered_payload_fails() {
        let (sk, pk) = test_keypair();
        let sig = sk.sign(b"registry-bytes").to_bytes();
        let err = verify_detached(b"registry-BYTES", &sig, &pk).unwrap_err();
        assert!(matches!(err, crate::PaksmithError::Profile {
            fault: crate::error::ProfileFault::SignatureInvalid }));
    }

    #[test]
    fn wrong_key_fails() {
        let (sk, _) = test_keypair();
        let other = hex_lower(SigningKey::from_bytes(&[9u8; 32]).verifying_key().as_bytes());
        let sig = sk.sign(b"x").to_bytes();
        assert!(verify_detached(b"x", &sig, &other).is_err());
    }

    #[test]
    fn malformed_sizes_error_not_panic() {
        let (_, pk) = test_keypair();
        assert!(verify_detached(b"x", &[0u8; 10], &pk).is_err());   // bad sig len
        assert!(verify_detached(b"x", &[0u8; 64], "abcd").is_err()); // bad key hex len
    }
}
```

- [ ] **Step 4: Run to verify it fails**

Run: `cargo test -p paksmith-core --all-features signature:: 2>&1 | tail -10`
Expected: FAIL — `verify_detached`/`TRUSTED_REGISTRY_PUBKEY_HEX` not found.

- [ ] **Step 5: Implement** — prepend to `signature.rs`:

```rust
//! Ed25519 detached-signature verification for the registry payload.

use ed25519_dalek::{Signature, VerifyingKey};

use crate::error::ProfileFault;
use crate::PaksmithError;

/// Compiled-in trusted ed25519 public key (32-byte, hex). DOCUMENTED
/// PLACEHOLDER until a live paksmith registry exists; overridable via
/// `[registry] public_key` in config. This value is the verifying key of a
/// throwaway keypair and is never used against a real endpoint yet.
pub(crate) const TRUSTED_REGISTRY_PUBKEY_HEX: &str =
    "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";

fn decode_hex_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 { return None; }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        if !chunk[0].is_ascii_hexdigit() || !chunk[1].is_ascii_hexdigit() { return None; }
        out[i] = u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
    }
    Some(out)
}

/// Verify a detached ed25519 signature over `payload` against `pubkey_hex`.
/// Returns `Ok(())` on success, else `ProfileFault::SignatureInvalid`. Never
/// panics; never includes payload/key material in the error.
pub(crate) fn verify_detached(payload: &[u8], sig: &[u8], pubkey_hex: &str) -> Result<(), PaksmithError> {
    let fail = || PaksmithError::Profile { fault: ProfileFault::SignatureInvalid };
    let key_bytes = decode_hex_32(pubkey_hex).ok_or_else(fail)?;
    let vk = VerifyingKey::from_bytes(&key_bytes).map_err(|_| fail())?;
    let sig_bytes: [u8; 64] = sig.try_into().map_err(|_| fail())?;
    let signature = Signature::from_bytes(&sig_bytes);
    vk.verify_strict(payload, &signature).map_err(|_| fail())
}
```

Register `pub(crate) mod signature;` in `profile/mod.rs`. NOTE: the placeholder pubkey above is a real ed25519 verifying key (the all-`0x33...` value is the standard ed25519 test vector key); the impl must accept it as well-formed. If `VerifyingKey::from_bytes` rejects it as non-canonical, regenerate the const from `SigningKey::from_bytes(&[1u8;32]).verifying_key()` and paste its hex — confirm at implementation.

- [ ] **Step 6: Run tests** — `cargo test -p paksmith-core --all-features signature:: 2>&1 | tail -10` (all pass).

- [ ] **Step 7: Commit**

```bash
git add crates/paksmith-core Cargo.toml
git commit -m "feat(profile): add ed25519 detached signature verification"
```

---

### Task 3: Registry config (`config.rs`)

**Files:**
- Create: `crates/paksmith-core/src/profile/config.rs`
- Modify: `crates/paksmith-core/src/profile/mod.rs` (`pub mod config;` + re-export `RegistryConfig`)

**Interfaces:**
- Consumes: `config_base_dir` (Task 1), `signature::TRUSTED_REGISTRY_PUBKEY_HEX` (Task 2), `ProfileFault::CorruptStore` (5b, reused for a corrupt config).
- Produces: `pub struct RegistryConfig { pub url: String, pub staleness_hours: u64, pub public_key_hex: String }`; `RegistryConfig::default()` (compiled-in defaults); `pub fn RegistryConfig::load() -> Result<RegistryConfig, crate::PaksmithError>` (reads `<base>/config.toml` `[registry]`; missing file/section/field → defaults; corrupt → `ProfileFault::CorruptStore`). Pure helper `pub(crate) fn from_toml_str(s: &str) -> Result<RegistryConfig, crate::PaksmithError>` for unit tests.
- Produces (const): `pub(crate) const DEFAULT_REGISTRY_URL: &str = "https://registry.paksmith.invalid/profiles.json";` (documented placeholder).

- [ ] **Step 1: Write the failing test** — in `config.rs` test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_when_empty() {
        let c = from_toml_str("").unwrap();
        assert_eq!(c.url, DEFAULT_REGISTRY_URL);
        assert_eq!(c.staleness_hours, 24);
        assert_eq!(c.public_key_hex, crate::profile::signature::TRUSTED_REGISTRY_PUBKEY_HEX);
    }

    #[test]
    fn overrides_parse() {
        let c = from_toml_str(
            "[registry]\nurl = \"https://example.test/r.json\"\nstaleness_hours = 6\npublic_key = \"ab\"\n",
        ).unwrap();
        assert_eq!(c.url, "https://example.test/r.json");
        assert_eq!(c.staleness_hours, 6);
        assert_eq!(c.public_key_hex, "ab");
    }

    #[test]
    fn corrupt_is_typed_error() {
        let err = from_toml_str("this = = not toml [[[").unwrap_err();
        assert!(matches!(err, crate::PaksmithError::Profile {
            fault: crate::error::ProfileFault::CorruptStore { .. } }));
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p paksmith-core --all-features profile::config 2>&1 | tail -10`
Expected: FAIL — `RegistryConfig`/`from_toml_str` not found.

- [ ] **Step 3: Implement** — prepend to `config.rs`:

```rust
//! Registry configuration from `<config_dir>/paksmith/config.toml` `[registry]`.

use serde::Deserialize;

use crate::error::ProfileFault;
use crate::profile::signature::TRUSTED_REGISTRY_PUBKEY_HEX;
use crate::PaksmithError;

/// DOCUMENTED PLACEHOLDER default endpoint (no live registry yet).
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

pub(crate) fn from_toml_str(s: &str) -> Result<RegistryConfig, PaksmithError> {
    let raw: RawConfig = toml::from_str(s).map_err(|e| PaksmithError::Profile {
        fault: ProfileFault::CorruptStore { reason: e.message().to_string() },
    })?;
    let d = RegistryConfig::default();
    Ok(RegistryConfig {
        url: raw.registry.url.unwrap_or(d.url),
        staleness_hours: raw.registry.staleness_hours.unwrap_or(d.staleness_hours),
        public_key_hex: raw.registry.public_key.unwrap_or(d.public_key_hex),
    })
}

impl RegistryConfig {
    /// Load from `<config_dir>/paksmith/config.toml`. Missing → defaults.
    pub fn load() -> Result<Self, PaksmithError> {
        let path = crate::profile::store::config_base_dir()?.join("config.toml");
        match std::fs::read_to_string(&path) {
            Ok(s) => from_toml_str(&s),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(PaksmithError::Profile {
                fault: ProfileFault::Io { reason: e.to_string() },
            }),
        }
    }
}
```

Register `pub mod config;` in `profile/mod.rs` and `pub use profile::config::RegistryConfig;` in `lib.rs`. (`signature` must be at least `pub(crate)` so `config.rs` reads its const — it is, from Task 2.)

- [ ] **Step 4: Run tests** — `cargo test -p paksmith-core --all-features profile::config 2>&1 | tail -10`.

- [ ] **Step 5: Commit**

```bash
git add crates/paksmith-core
git commit -m "feat(profile): add RegistryConfig (config.toml [registry])"
```

---

### Task 4: Registry model + strict parse (`registry.rs`, no network yet)

**Files:**
- Create: `crates/paksmith-core/src/profile/registry.rs` (model + `parse_registry`; the async client is Task 5)
- Modify: `crates/paksmith-core/src/profile/mod.rs` (`pub mod registry;` + re-exports)
- Modify: `crates/paksmith-core/src/error.rs` (`ProfileFault::RegistryParse`)

**Interfaces:**
- Consumes: `KeyGuid`, `AesKey`, `keys_serde` (5b — make `keys_serde` reachable: it is currently a private `mod` in `mod.rs`; widen to `pub(crate) mod keys_serde` so `registry.rs` can `#[serde(with = "crate::profile::keys_serde")]`).
- Produces: `pub struct RegistryProfile { pub id: String, pub name: String, pub engine_version: Option<String>, pub keys: BTreeMap<KeyGuid, AesKey> }` (Deserialize via keys_serde); `pub struct RegistryDoc { pub profiles: Vec<RegistryProfile> }`; `pub(crate) fn parse_registry(bytes: &[u8]) -> Result<RegistryDoc, crate::PaksmithError>` (strict serde_json + caps). Cap consts: `MAX_PROFILES = 10_000`, `MAX_KEYS_PER_PROFILE = 64`, `MAX_STR = 256`.
- Produces (error): `ProfileFault::RegistryParse { reason: String }`.

- [ ] **Step 1: Widen `keys_serde` + add the error variant.** In `profile/mod.rs` change `mod keys_serde {` → `pub(crate) mod keys_serde {`. In `error.rs` add:

```rust
    /// The registry payload could not be parsed or violated a size cap.
    #[error("registry parse error: {reason}")]
    RegistryParse {
        /// Detail (no key material).
        reason: String,
    },
```

- [ ] **Step 2: Write the failing test** — in `registry.rs` test module:

```rust
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
        let many = std::iter::repeat(one).take(MAX_PROFILES + 1).collect::<Vec<_>>().join(",");
        let err = parse_registry(format!("[{many}]").as_bytes()).unwrap_err();
        assert!(matches!(err, crate::PaksmithError::Profile {
            fault: crate::error::ProfileFault::RegistryParse { .. } }));
    }

    #[test]
    fn rejects_bad_key_hex() {
        let err = parse_registry(br#"[{"id":"x","name":"y","keys":{"00000000000000000000000000000000":"nothex"}}]"#).unwrap_err();
        assert!(matches!(err, crate::PaksmithError::Profile {
            fault: crate::error::ProfileFault::RegistryParse { .. } }));
    }

    #[test]
    fn rejects_overlong_id() {
        let id = "a".repeat(MAX_STR + 1);
        let err = parse_registry(format!(r#"[{{"id":"{id}","name":"y","keys":{{}}}}]"#).as_bytes()).unwrap_err();
        assert!(matches!(err, crate::PaksmithError::Profile {
            fault: crate::error::ProfileFault::RegistryParse { .. } }));
    }
}
```

- [ ] **Step 3: Run to verify it fails**

Run: `cargo test -p paksmith-core --all-features profile::registry 2>&1 | tail -10`
Expected: FAIL — `parse_registry`/`RegistryProfile` not found.

- [ ] **Step 4: Implement** — prepend to `registry.rs`:

```rust
//! Registry document model + strict, capped parsing. (The async fetch client
//! is in the same module, added in Task 5.)

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::error::ProfileFault;
use crate::{AesKey, KeyGuid, PaksmithError};

pub(crate) const MAX_PROFILES: usize = 10_000;
pub(crate) const MAX_KEYS_PER_PROFILE: usize = 64;
pub(crate) const MAX_STR: usize = 256;

/// One profile as served by the registry (an explicit `id`, unlike the local
/// store where the id is the map key).
#[derive(Debug, Clone, Deserialize)]
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

/// Parse + cap-check a registry JSON array. `keys_serde` already rejects bad
/// guid/key hex (surfaced here as `RegistryParse`).
pub(crate) fn parse_registry(bytes: &[u8]) -> Result<RegistryDoc, PaksmithError> {
    let parse_err = |reason: String| PaksmithError::Profile {
        fault: ProfileFault::RegistryParse { reason },
    };
    let profiles: Vec<RegistryProfile> =
        serde_json::from_slice(bytes).map_err(|e| parse_err(e.to_string()))?;
    if profiles.len() > MAX_PROFILES {
        return Err(parse_err(format!("too many profiles: {} > {MAX_PROFILES}", profiles.len())));
    }
    for p in &profiles {
        if p.id.len() > MAX_STR || p.name.len() > MAX_STR
            || p.engine_version.as_ref().is_some_and(|v| v.len() > MAX_STR)
        {
            return Err(parse_err("profile string field exceeds cap".into()));
        }
        if p.keys.len() > MAX_KEYS_PER_PROFILE {
            return Err(parse_err(format!("too many keys in `{}`", p.id)));
        }
    }
    Ok(RegistryDoc { profiles })
}
```

Register `pub mod registry;` in `profile/mod.rs`; re-export `pub use profile::registry::{RegistryProfile, RegistryDoc};` in `lib.rs`. NOTE: `keys_serde`'s deserialize maps `from_hex` failures to `D::Error::custom`, so a bad key surfaces as a serde error → `RegistryParse` (the `rejects_bad_key_hex` test confirms). `serde_json` is already a workspace dep.

- [ ] **Step 5: Run tests** — `cargo test -p paksmith-core --all-features profile::registry 2>&1 | tail -10`.

- [ ] **Step 6: Commit**

```bash
git add crates/paksmith-core
git commit -m "feat(profile): add registry model + strict capped parse"
```

---

### Task 5: Async registry client (`RegistryClient::fetch`)

**Files:**
- Modify: `crates/paksmith-core/src/profile/registry.rs` (add the async client)
- Modify: `crates/paksmith-core/src/error.rs` (`ProfileFault::{Network, InsecureUrl, ResponseTooLarge}`)
- Modify: root `Cargo.toml` + `crates/paksmith-core/Cargo.toml` (add `reqwest`; dev: `tokio`, `wiremock`)

**Interfaces:**
- Consumes: `parse_registry` (Task 4), `signature::verify_detached` (Task 2).
- Produces: `pub struct RegistryClient` (`RegistryClient::new() -> Result<Self, PaksmithError>` building a `reqwest::Client` with timeout + redirect cap); `pub async fn RegistryClient::fetch(&self, url: &str, pubkey_hex: &str) -> Result<RegistryDoc, PaksmithError>`. `pub(crate) const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;`.
- Produces (errors): `ProfileFault::{Network { reason }, InsecureUrl { url }, ResponseTooLarge { limit }}`.

- [ ] **Step 1: Add deps.** Root `Cargo.toml`: `reqwest = { version = "0.12", default-features = false, features = ["rustls-tls"] }`; dev: `wiremock = "0.6"`, and ensure `tokio = { version = "1", features = ["rt", "macros"] }` is available as a dev-dep. `crates/paksmith-core/Cargo.toml` `[dependencies]`: `reqwest = { workspace = true }`; `[dev-dependencies]`: `tokio = { workspace = true }`, `wiremock = { workspace = true }`. (No direct `tokio` runtime dep in core — reqwest brings the async machinery; core only `.await`s.)

- [ ] **Step 2: Add the error variants** — in `error.rs` `ProfileFault`:

```rust
    /// A network/HTTP error fetching the registry.
    #[error("registry network error: {reason}")]
    Network {
        /// Detail (URL/status; no key material).
        reason: String,
    },
    /// The registry URL was not https.
    #[error("registry URL must be https: {url}")]
    InsecureUrl {
        /// The rejected URL.
        url: String,
    },
    /// The registry response body exceeded the size cap.
    #[error("registry response exceeded {limit} bytes")]
    ResponseTooLarge {
        /// The cap in bytes.
        limit: usize,
    },
```

- [ ] **Step 3: Write the failing integration test** — in `registry.rs` test module (async, wiremock). Sign the served payload with the deterministic test key:

```rust
#[cfg(test)]
mod fetch_tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn keypair() -> (SigningKey, String) {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk = sk.verifying_key().as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        (sk, pk)
    }
    const BODY: &str = r#"[{"id":"g","name":"G","keys":{}}]"#;

    #[tokio::test]
    async fn fetch_verifies_and_parses() {
        let (sk, pk) = keypair();
        let sig = sk.sign(BODY.as_bytes()).to_bytes().to_vec();
        let server = MockServer::start().await;
        Mock::given(method("GET")).and(path("/r.json"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(BODY.as_bytes()))
            .mount(&server).await;
        Mock::given(method("GET")).and(path("/r.json.sig"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(sig))
            .mount(&server).await;
        // NOTE: wiremock serves http; the https-only guard is unit-tested
        // separately. Here we exercise verify+parse against a mock by allowing
        // the client to accept the mock's scheme in tests (see impl note).
        let client = RegistryClient::new().unwrap();
        let url = format!("{}/r.json", server.uri());
        let doc = client.fetch_allowing_http_for_test(&url, &pk).await.unwrap();
        assert_eq!(doc.profiles[0].id, "g");
    }

    #[tokio::test]
    async fn tampered_payload_fails_signature() {
        let (sk, pk) = keypair();
        let sig = sk.sign(b"OTHER").to_bytes().to_vec();
        let server = MockServer::start().await;
        Mock::given(method("GET")).and(path("/r.json"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(BODY.as_bytes()))
            .mount(&server).await;
        Mock::given(method("GET")).and(path("/r.json.sig"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(sig))
            .mount(&server).await;
        let client = RegistryClient::new().unwrap();
        let url = format!("{}/r.json", server.uri());
        let err = client.fetch_allowing_http_for_test(&url, &pk).await.unwrap_err();
        assert!(matches!(err, crate::PaksmithError::Profile {
            fault: crate::error::ProfileFault::SignatureInvalid }));
    }

    #[tokio::test]
    async fn http_url_is_rejected() {
        let client = RegistryClient::new().unwrap();
        let err = client.fetch("http://example.test/r.json", "ab").await.unwrap_err();
        assert!(matches!(err, crate::PaksmithError::Profile {
            fault: crate::error::ProfileFault::InsecureUrl { .. } }));
    }
}
```

- [ ] **Step 4: Run to verify it fails**

Run: `cargo test -p paksmith-core --all-features fetch_tests 2>&1 | tail -15`
Expected: FAIL — `RegistryClient`/`fetch` not found.

- [ ] **Step 5: Implement** — add to `registry.rs`:

```rust
use crate::profile::signature::verify_detached;

pub(crate) const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

/// HTTPS registry client (rustls TLS, capped + timed).
pub struct RegistryClient {
    http: reqwest::Client,
}

impl RegistryClient {
    /// Build a client with a 10s timeout and a 5-redirect cap.
    pub fn new() -> Result<Self, PaksmithError> {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .map_err(|e| net_err(&e))?;
        Ok(Self { http })
    }

    /// Fetch `<url>` + `<url>.sig`, verify, parse. https-only.
    pub async fn fetch(&self, url: &str, pubkey_hex: &str) -> Result<RegistryDoc, PaksmithError> {
        if !url.starts_with("https://") {
            return Err(PaksmithError::Profile {
                fault: ProfileFault::InsecureUrl { url: url.to_string() },
            });
        }
        self.fetch_inner(url, pubkey_hex).await
    }

    // Shared body used by `fetch` (after the https gate) and the test-only
    // entry point that skips the scheme gate so wiremock's http can be used.
    async fn fetch_inner(&self, url: &str, pubkey_hex: &str) -> Result<RegistryDoc, PaksmithError> {
        let sig_url = format!("{url}.sig");
        let payload = self.get_capped(url).await?;
        let sig = self.get_capped(&sig_url).await?;
        verify_detached(&payload, &sig, pubkey_hex)?;
        parse_registry(&payload)
    }

    #[cfg(test)]
    pub(crate) async fn fetch_allowing_http_for_test(
        &self, url: &str, pubkey_hex: &str,
    ) -> Result<RegistryDoc, PaksmithError> {
        self.fetch_inner(url, pubkey_hex).await
    }

    async fn get_capped(&self, url: &str) -> Result<Vec<u8>, PaksmithError> {
        let resp = self.http.get(url).send().await.map_err(|e| net_err(&e))?
            .error_for_status().map_err(|e| net_err(&e))?;
        let mut resp = resp;
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(|e| net_err(&e))? {
            if body.len() + chunk.len() > MAX_BODY_BYTES {
                return Err(PaksmithError::Profile {
                    fault: ProfileFault::ResponseTooLarge { limit: MAX_BODY_BYTES },
                });
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }
}

fn net_err(e: &reqwest::Error) -> PaksmithError {
    PaksmithError::Profile { fault: ProfileFault::Network { reason: e.to_string() } }
}
```

(The `get_capped` streams chunks and bails before exceeding the cap — it does NOT trust `Content-Length`.) Confirm `reqwest::Response::chunk` is available in the resolved reqwest 0.12 (it is); if the API differs, use `bytes_stream()` with the same accumulate-and-cap loop.

- [ ] **Step 6: Run tests** — `cargo test -p paksmith-core --all-features 2>&1 | tail -15` (fetch_tests + all prior). Add an `oversized` test if practical (serve a > cap body → `ResponseTooLarge`).

- [ ] **Step 7: Commit**

```bash
git add crates/paksmith-core Cargo.toml
git commit -m "feat(profile): add async RegistryClient::fetch (https, capped, signed)"
```

---

### Task 6: Registry cache (`cache.rs`)

**Files:**
- Create: `crates/paksmith-core/src/profile/cache.rs`
- Modify: `crates/paksmith-core/src/profile/mod.rs` (`pub mod cache;` + re-export)
- Modify: `crates/paksmith-core/src/error.rs` (`ProfileFault::CacheCorrupt`)

**Interfaces:**
- Consumes: `RegistryDoc`/`RegistryProfile`/`parse_registry` caps (Task 4), `config_base_dir` + `write_restricted` (Task 1).
- Produces: `pub struct RegistryCache { pub fetched_at_unix: u64, pub doc: RegistryDoc }`; `RegistryCache::{path() -> Result<PathBuf>, load() -> Result<Option<RegistryCache>>, save(&self) -> Result<()>, is_stale(&self, now_unix, staleness_hours) -> bool, get(&self, id) -> Option<&RegistryProfile>}`. On-disk JSON: `{ "fetched_at_unix": <u64>, "profiles": [<RegistryProfile>...] }`.
- Produces (error): `ProfileFault::CacheCorrupt { reason }`.

- [ ] **Step 1: Add the error variant** — `error.rs`:

```rust
    /// The registry cache file exists but could not be parsed.
    #[error("registry cache is corrupt: {reason}")]
    CacheCorrupt {
        /// Detail (no key material).
        reason: String,
    },
```

- [ ] **Step 2: Write the failing test** — `cache.rs` test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::registry::{RegistryDoc, RegistryProfile};
    use std::collections::BTreeMap;

    fn sample() -> RegistryCache {
        RegistryCache {
            fetched_at_unix: 1_000_000,
            doc: RegistryDoc { profiles: vec![RegistryProfile {
                id: "g".into(), name: "G".into(), engine_version: None, keys: BTreeMap::new(),
            }] },
        }
    }

    #[test]
    fn save_then_load_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("registry-cache.json");
        sample().save_to(&path).unwrap();
        let back = RegistryCache::load_from(&path).unwrap().unwrap();
        assert_eq!(back.fetched_at_unix, 1_000_000);
        assert_eq!(back.get("g").unwrap().name, "G");
    }

    #[test]
    fn load_missing_is_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(RegistryCache::load_from(&dir.path().join("nope.json")).unwrap().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn saved_cache_is_0600() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("registry-cache.json");
        sample().save_to(&path).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn corrupt_is_typed_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("registry-cache.json");
        std::fs::write(&path, "not json {{{").unwrap();
        assert!(matches!(RegistryCache::load_from(&path).unwrap_err(),
            crate::PaksmithError::Profile { fault: crate::error::ProfileFault::CacheCorrupt { .. } }));
    }

    #[test]
    fn staleness_boundary() {
        let c = sample(); // fetched_at = 1_000_000
        // 24h = 86_400s. now = fetched + 86_399 → fresh; +86_401 → stale.
        assert!(!c.is_stale(1_000_000 + 86_399, 24));
        assert!(c.is_stale(1_000_000 + 86_401, 24));
    }
}
```

- [ ] **Step 3: Run to verify it fails**

Run: `cargo test -p paksmith-core --all-features profile::cache 2>&1 | tail -10`
Expected: FAIL — `RegistryCache` not found.

- [ ] **Step 4: Implement** — prepend to `cache.rs`:

```rust
//! On-disk registry cache: `<config_dir>/paksmith/registry-cache.json`, 0600.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::ProfileFault;
use crate::profile::registry::{RegistryDoc, RegistryProfile};
use crate::profile::store::{config_base_dir, write_restricted};
use crate::PaksmithError;

/// Cached registry document + the wall-clock fetch time.
#[derive(Debug, Clone)]
pub struct RegistryCache {
    /// Unix seconds when fetched.
    pub fetched_at_unix: u64,
    /// The cached document.
    pub doc: RegistryDoc,
}

// On-disk shape. `profiles` reuses RegistryProfile's strict (capped via
// parse on the fetch path) serde; here we additionally re-validate on load.
#[derive(Serialize, Deserialize)]
struct OnDisk {
    fetched_at_unix: u64,
    profiles: Vec<RegistryProfile>,
}

impl RegistryCache {
    /// `<config_dir>/paksmith/registry-cache.json`.
    pub fn path() -> Result<PathBuf, PaksmithError> {
        Ok(config_base_dir()?.join("registry-cache.json"))
    }

    /// Load from the resolved path (None if absent).
    pub fn load() -> Result<Option<Self>, PaksmithError> {
        Self::load_from(&Self::path()?)
    }

    /// Save to the resolved path.
    pub fn save(&self) -> Result<(), PaksmithError> {
        self.save_to(&Self::path()?)
    }

    pub(crate) fn load_from(path: &Path) -> Result<Option<Self>, PaksmithError> {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(PaksmithError::Profile { fault: ProfileFault::Io { reason: e.to_string() } }),
        };
        let on_disk: OnDisk = serde_json::from_slice(&bytes).map_err(|e| PaksmithError::Profile {
            fault: ProfileFault::CacheCorrupt { reason: e.to_string() },
        })?;
        // Re-apply the registry caps to untrusted on-disk content.
        let doc = crate::profile::registry::validate_caps(RegistryDoc { profiles: on_disk.profiles })
            .map_err(|e| PaksmithError::Profile {
                fault: ProfileFault::CacheCorrupt { reason: e },
            })?;
        Ok(Some(Self { fetched_at_unix: on_disk.fetched_at_unix, doc }))
    }

    pub(crate) fn save_to(&self, path: &Path) -> Result<(), PaksmithError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| PaksmithError::Profile {
                fault: ProfileFault::Io { reason: e.to_string() } })?;
        }
        let on_disk = OnDisk { fetched_at_unix: self.fetched_at_unix, profiles: self.doc.profiles.clone() };
        let json = serde_json::to_vec_pretty(&on_disk).map_err(|e| PaksmithError::Profile {
            fault: ProfileFault::Io { reason: e.to_string() } })?;
        let tmp = path.with_extension("json.tmp");
        write_restricted(&tmp, &json).map_err(|e| PaksmithError::Profile {
            fault: ProfileFault::Io { reason: e.to_string() } })?;
        std::fs::rename(&tmp, path).map_err(|e| PaksmithError::Profile {
            fault: ProfileFault::Io { reason: e.to_string() } })
    }

    /// True iff `now_unix` is more than `staleness_hours` after the fetch time.
    pub fn is_stale(&self, now_unix: u64, staleness_hours: u64) -> bool {
        now_unix.saturating_sub(self.fetched_at_unix) > staleness_hours.saturating_mul(3600)
    }

    /// Look up a cached profile by id.
    pub fn get(&self, id: &str) -> Option<&RegistryProfile> {
        self.doc.profiles.iter().find(|p| p.id == id)
    }
}
```

This requires `RegistryProfile` to also derive `Serialize` (Task 4 defined only `Deserialize`) — add `Serialize` to `RegistryProfile`'s derives in `registry.rs` (the keys_serde adapter already supports serialize). And add a small `pub(crate) fn validate_caps(doc: RegistryDoc) -> Result<RegistryDoc, String>` to `registry.rs` extracted from `parse_registry`'s cap loop (so both the fetch parse and the cache load enforce identical caps) — refactor `parse_registry` to call it. Register `pub mod cache;` + `pub use profile::cache::RegistryCache;`.

- [ ] **Step 5: Run tests** — `cargo test -p paksmith-core --all-features profile::cache 2>&1 | tail -10`.

- [ ] **Step 6: Commit**

```bash
git add crates/paksmith-core
git commit -m "feat(profile): add registry cache (0600, staleness, capped load)"
```

---

### Task 7: Layered resolution helper (core)

**Files:**
- Modify: `crates/paksmith-core/src/profile/mod.rs`

**Interfaces:**
- Consumes: `ProfileStore`/`GameProfile` (5b), `RegistryCache`/`RegistryProfile` (Task 6).
- Produces: `pub fn resolve_profile_layered<'a>(store: &'a ProfileStore, cache: Option<&'a RegistryCache>, id: &str) -> Option<ResolvedProfile<'a>>` where `pub enum ResolvedProfile<'a> { Local(&'a GameProfile), Registry(&'a RegistryProfile) }`. Local wins; else cached registry profile; else None. (The CLI maps either arm's `keys` through `resolve_key`-equivalent guid logic — see Task 9.)

- [ ] **Step 1: Write the failing test** — in `mod.rs` tests:

```rust
#[test]
fn layered_resolution_prefers_local_then_cache() {
    use crate::profile::cache::RegistryCache;
    use crate::profile::registry::{RegistryDoc, RegistryProfile};
    let mut store = ProfileStore::default();
    store.profiles.insert("local".into(), GameProfile { name: "L".into(), engine_version: None, keys: BTreeMap::new() });
    let cache = RegistryCache { fetched_at_unix: 0, doc: RegistryDoc { profiles: vec![
        RegistryProfile { id: "remote".into(), name: "R".into(), engine_version: None, keys: BTreeMap::new() },
        RegistryProfile { id: "local".into(), name: "SHADOWED".into(), engine_version: None, keys: BTreeMap::new() },
    ] } };
    // local id → Local (user wins over the shadowing cache entry)
    assert!(matches!(resolve_profile_layered(&store, Some(&cache), "local"), Some(ResolvedProfile::Local(_))));
    // remote-only id → Registry
    assert!(matches!(resolve_profile_layered(&store, Some(&cache), "remote"), Some(ResolvedProfile::Registry(_))));
    // unknown → None
    assert!(resolve_profile_layered(&store, Some(&cache), "nope").is_none());
    // no cache, unknown → None
    assert!(resolve_profile_layered(&store, None, "remote").is_none());
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p paksmith-core --all-features layered_resolution 2>&1 | tail -10`
Expected: FAIL — `resolve_profile_layered` not found.

- [ ] **Step 3: Implement** — in `mod.rs`:

```rust
/// A profile resolved from either the local store or the registry cache.
pub enum ResolvedProfile<'a> {
    /// User-authored local profile (wins).
    Local(&'a GameProfile),
    /// Cached registry profile.
    Registry(&'a registry::RegistryProfile),
}

/// Resolve `id`: local store wins; else the registry cache; else `None`.
pub fn resolve_profile_layered<'a>(
    store: &'a ProfileStore,
    cache: Option<&'a cache::RegistryCache>,
    id: &str,
) -> Option<ResolvedProfile<'a>> {
    if let Some(p) = store.profiles.get(id) {
        return Some(ResolvedProfile::Local(p));
    }
    cache.and_then(|c| c.get(id)).map(ResolvedProfile::Registry)
}
```

Add `pub use profile::{ResolvedProfile, resolve_profile_layered};` to `lib.rs`. Add `assert_send_sync` pins for any new public type if it carries data (`ResolvedProfile` is borrow-only — skip pins; it's not `'static`).

- [ ] **Step 4: Run tests** — `cargo test -p paksmith-core --all-features layered 2>&1 | tail -10`.

- [ ] **Step 5: Commit**

```bash
git add crates/paksmith-core
git commit -m "feat(profile): add layered local-over-cache resolution"
```

---

### Task 8: CLI `profile fetch` + tokio runtime

**Files:**
- Modify: `crates/paksmith-cli/Cargo.toml` (add `tokio` rt)
- Modify: `crates/paksmith-cli/src/main.rs` (build a current-thread runtime)
- Modify: `crates/paksmith-cli/src/commands/profile.rs` (add `Fetch` subcommand)

**Interfaces:**
- Consumes: `RegistryConfig` (Task 3), `RegistryClient` (Task 5), `RegistryCache` (Task 6).
- Produces: `ProfileCmd::Fetch(FetchArgs)` (`--registry <url>`, `--force`); a CLI helper `fn run_fetch(args, rt) -> Result<u8>` that resolves config, `block_on`s `RegistryClient::fetch`, and saves the cache with `fetched_at_unix = SystemTime::now()`.

- [ ] **Step 1: Add `tokio`.** `crates/paksmith-cli/Cargo.toml` `[dependencies]`: `tokio = { workspace = true }` (workspace dep already adds `features = ["rt","macros"]`; the CLI needs `rt`).

- [ ] **Step 2: Write the failing CLI test** — append to `crates/paksmith-cli/tests/profile_cli.rs` (uses wiremock + the deterministic test key; serve a signed body):

```rust
// at top: add `use ed25519_dalek::{Signer, SigningKey};` and a helper to sign.
#[tokio::test]
async fn profile_fetch_caches_signed_registry() {
    use wiremock::matchers::{method, path as wpath};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    let cfg = tempfile::tempdir().unwrap();
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let pk: String = sk.verifying_key().as_bytes().iter().map(|b| format!("{b:02x}")).collect();
    let body = r#"[{"id":"g","name":"G","keys":{}}]"#;
    let sig = sk.sign(body.as_bytes()).to_bytes().to_vec();
    let server = MockServer::start().await;
    Mock::given(method("GET")).and(wpath("/r.json"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.as_bytes())).mount(&server).await;
    Mock::given(method("GET")).and(wpath("/r.json.sig"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(sig)).mount(&server).await;
    // Write a config.toml pointing at the mock (http) + the test pubkey, and
    // allow http in tests via PAKSMITH_ALLOW_HTTP=1 (test-only env gate — see impl note).
    let base = cfg.path().join("paksmith");
    std::fs::create_dir_all(&base).unwrap();
    std::fs::write(base.join("config.toml"),
        format!("[registry]\nurl = \"{}/r.json\"\npublic_key = \"{pk}\"\n", server.uri())).unwrap();

    let mut cmd = assert_cmd::Command::cargo_bin("paksmith").unwrap();
    cmd.env("PAKSMITH_CONFIG_DIR", cfg.path())
        .env("PAKSMITH_ALLOW_HTTP", "1")
        .args(["profile", "fetch"]).assert().success();
    // cache file now exists
    assert!(base.join("registry-cache.json").exists());
}
```

- [ ] **Step 3: Run to verify it fails**

Run: `cargo test -p paksmith-cli --test profile_cli profile_fetch 2>&1 | tail -15`
Expected: FAIL — no `fetch` subcommand.

- [ ] **Step 4: Implement.** In `main.rs`, build a current-thread runtime once and pass it to the dispatch (or build it lazily inside the fetch sites). Minimal approach — a helper the commands call:

```rust
// in main.rs or a small cli util module
pub(crate) fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build current-thread tokio runtime")
        .block_on(fut)
}
```

Add the `Fetch` variant + args to `ProfileCmd` (profile.rs) and the handler:

```rust
#[derive(Args)]
pub(crate) struct FetchArgs {
    /// Override the configured registry URL for this fetch.
    #[arg(long)]
    pub(crate) registry: Option<String>,
    /// Fetch even if the cache is still fresh.
    #[arg(long)]
    pub(crate) force: bool,
}

fn fetch(a: &FetchArgs) -> paksmith_core::Result<u8> {
    use paksmith_core::profile::registry::RegistryClient;
    use paksmith_core::{ProfileStore, RegistryConfig};
    use paksmith_core::profile::cache::RegistryCache;

    let cfg = RegistryConfig::load()?;
    let url = a.registry.clone().unwrap_or(cfg.url);
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| PaksmithError::InvalidArgument { arg: "clock", reason: e.to_string() })?.as_secs();
    if !a.force {
        if let Some(existing) = RegistryCache::load()? {
            if !existing.is_stale(now, cfg.staleness_hours) {
                println!("registry cache is fresh ({} profiles); use --force to re-fetch", existing.doc.profiles.len());
                return Ok(0);
            }
        }
    }
    let client = RegistryClient::new()?;
    let doc = crate::block_on(fetch_doc(&client, &url, &cfg.public_key_hex))?;
    let cache = RegistryCache { fetched_at_unix: now, doc };
    cache.save()?;
    println!("fetched {} profiles", cache.doc.profiles.len());
    Ok(0)
}

// http allowed only when PAKSMITH_ALLOW_HTTP=1 (tests/dev); production uses fetch() (https-only).
async fn fetch_doc(client: &RegistryClient, url: &str, pk: &str) -> paksmith_core::Result<paksmith_core::profile::registry::RegistryDoc> {
    if std::env::var_os("PAKSMITH_ALLOW_HTTP").is_some() {
        client.fetch_allowing_http_for_test(url, pk).await
    } else {
        client.fetch(url, pk).await
    }
}
```

IMPL NOTE: `fetch_allowing_http_for_test` is currently `#[cfg(test)]`-only (Task 5). To let the CLI integration test reach it via `PAKSMITH_ALLOW_HTTP`, change that method to a normal `pub(crate)` (not `#[cfg(test)]`) but keep the `https-only` guard in the public `fetch`; the http-allowing entry is reachable only behind the `PAKSMITH_ALLOW_HTTP` env gate in the CLI (documented as a test/dev affordance, never the default path). Confirm the security reviewer is comfortable with this gate, or alternatively run the CLI fetch test with a TLS mock — but `wiremock` is http-only, so the env-gated http path is the pragmatic test seam. Register `Fetch` in the `ProfileCmd` dispatch.

- [ ] **Step 5: Run tests** — `cargo test -p paksmith-cli --test profile_cli 2>&1 | tail -15`.

- [ ] **Step 6: Commit**

```bash
git add crates/paksmith-cli Cargo.toml
git commit -m "feat(cli): add profile fetch (signed registry) + tokio runtime"
```

---

### Task 9: `--game` auto-fetch + offline degradation + `profile list` cached

**Files:**
- Modify: `crates/paksmith-cli/src/commands/key_resolve.rs`
- Modify: `crates/paksmith-cli/src/commands/profile.rs` (`profile list` shows cached)

**Interfaces:**
- Consumes: `resolve_profile_layered`/`ResolvedProfile` (Task 7), `RegistryCache` (Task 6), `RegistryConfig` (Task 3), `RegistryClient` (Task 5), `resolve_key` (5b).
- Produces: extended `resolve_pak_key` that (1) checks local `profiles.toml` (no network), (2) checks fresh cache, (3) auto-fetches when the id is absent locally AND the cache is missing/stale, (4) on fetch failure falls back to a stale cache entry (warn) else errors. The pak GUID still selects the key within the resolved profile.

- [ ] **Step 1: Write the failing CLI test** — append to `profile_cli.rs`:

```rust
#[tokio::test]
async fn game_auto_fetches_registry_only_profile() {
    use wiremock::matchers::{method, path as wpath};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    let cfg = tempfile::tempdir().unwrap();
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let pk: String = sk.verifying_key().as_bytes().iter().map(|b| format!("{b:02x}")).collect();
    // a registry profile whose default (zero-GUID) key decrypts the v8b fixture
    let key = "94d25bc3aeb420e0be914edc9d5435a1eaab5f2864e09e94019ac205b727a7de";
    let body = format!(r#"[{{"id":"reg","name":"R","keys":{{"00000000000000000000000000000000":"{key}"}}}}]"#);
    let sig = sk.sign(body.as_bytes()).to_bytes().to_vec();
    let server = MockServer::start().await;
    Mock::given(method("GET")).and(wpath("/r.json")).respond_with(ResponseTemplate::new(200).set_body_bytes(body.as_bytes())).mount(&server).await;
    Mock::given(method("GET")).and(wpath("/r.json.sig")).respond_with(ResponseTemplate::new(200).set_body_bytes(sig)).mount(&server).await;
    let base = cfg.path().join("paksmith"); std::fs::create_dir_all(&base).unwrap();
    std::fs::write(base.join("config.toml"), format!("[registry]\nurl=\"{}/r.json\"\npublic_key=\"{pk}\"\n", server.uri())).unwrap();

    // --game reg has no local profile + no cache → auto-fetch → resolves the encrypted-index fixture
    let fixture = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap()
        .join("tests/fixtures/real_v8b_encrypted_index.pak");
    let mut cmd = assert_cmd::Command::cargo_bin("paksmith").unwrap();
    let out = cmd.env("PAKSMITH_CONFIG_DIR", cfg.path()).env("PAKSMITH_ALLOW_HTTP", "1")
        .args(["--game", "reg", "list"]).arg(fixture).assert().success();
    assert!(String::from_utf8(out.get_output().stdout.clone()).unwrap().contains("test.txt"));
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p paksmith-cli --test profile_cli game_auto 2>&1 | tail -15`
Expected: FAIL — auto-fetch not wired.

- [ ] **Step 3: Implement** — extend `resolve_pak_key` (key_resolve.rs). After the `--aes-key` short-circuit and `let Some(id) = game else { return Ok(None) }`, replace the local-only lookup with:

```rust
    use paksmith_core::profile::cache::RegistryCache;
    use paksmith_core::profile::registry::RegistryClient;
    use paksmith_core::{RegistryConfig, ResolvedProfile, resolve_profile_layered};

    let store = ProfileStore::load()?;
    let pak_guid = PakReader::read_footer_guid(path)?;

    // 1. local profiles.toml wins (no network)
    if let Some(profile) = store.profiles.get(id) {
        return resolve_within(profile_keys_local(profile), id, pak_guid);
    }
    // 2. fresh cache (no network)
    let mut cache = RegistryCache::load()?;
    let cfg = RegistryConfig::load()?;
    let now = now_unix()?;
    let fresh = cache.as_ref().is_some_and(|c| !c.is_stale(now, cfg.staleness_hours) && c.get(id).is_some());
    // 3. auto-fetch when id absent locally AND (no cache OR stale OR id not in cache)
    if !fresh {
        match try_fetch(&cfg, now) {
            Ok(fetched) => { let _ = fetched.save(); cache = Some(fetched); }
            Err(e) => tracing::warn!(error = %e, "registry fetch failed; using cached profiles if available"),
        }
    }
    match resolve_profile_layered(&store, cache.as_ref(), id) {
        Some(ResolvedProfile::Local(p)) => resolve_within(&p.keys, id, pak_guid),
        Some(ResolvedProfile::Registry(p)) => resolve_within(&p.keys, id, pak_guid),
        None => Err(PaksmithError::Profile { fault: ProfileFault::ProfileNotFound { id: id.to_string() } }),
    }
```

with small helpers in key_resolve.rs: `now_unix()` (SystemTime → secs, mapping error to InvalidArgument), `try_fetch(cfg, now) -> Result<RegistryCache>` (block_on the client fetch via the same `fetch_doc` http-gate helper, wrap in `RegistryCache { fetched_at_unix: now, doc }`), and `resolve_within(keys: &BTreeMap<KeyGuid,AesKey>, id, guid) -> Result<Option<AesKey>>` (mirror 5b: `keys.get(resolved_guid).or_else(zero)` → clone, else `NoKeyForGuid`). Reuse `paksmith_core::profile::resolve_key` by passing a temporary — OR factor the guid→key step to operate on a `&BTreeMap` (both `GameProfile` and `RegistryProfile` expose `keys`). Confirm the exact reuse against `resolve_key`'s signature at implementation; the contract is identical (exact guid → zero default → None).

Then update `profile list` (profile.rs) to also load `RegistryCache::load()?` and print cached profiles tagged `[registry]` (local ones tagged `[local]`), deduping by id with local shown when both exist.

- [ ] **Step 4: Run tests** — `cargo test -p paksmith-cli --all-features 2>&1 | tail -15` (new + all existing CLI + 5b `--game`/`--aes-key` tests green). Add an OFFLINE-degradation test: pre-seed a stale cache file, point config at a dead URL, assert `--game` still resolves from the stale cache (warn) — exit 0.

- [ ] **Step 5: Commit**

```bash
git add crates/paksmith-cli
git commit -m "feat(cli): --game auto-fetch with offline cache fallback; list shows cached"
```

---

### Task 10: ROADMAP + full gate chain

**Files:**
- Modify: `docs/plans/ROADMAP.md`; `deny.toml` (as needed)

- [ ] **Step 1: ROADMAP** — in the Phase 5 status block, note **5c (remote registry: signed fetch, cache, offline-degrading auto-fetch, `profile fetch`)** shipped; 5d (auto-detection) remains planned. Factual; no engine-source refs.

- [ ] **Step 2: cargo-deny** — `cargo deny check 2>&1 | tail -30`. The TLS stack (`rustls`, `ring`/`aws-lc-rs`, `webpki-roots`, `untrusted`) + transitive crates may flag licenses (e.g. `ring`'s mixed ISC/OpenSSL, `webpki`'s ISC). Add MINIMAL scoped `[[licenses.exceptions]]` per crate (the existing `option-ext`/symphonia precedent), each documenting why. If `[bans]` flags a duplicate version, review; if `[sources]` flags anything, it's crates.io (fine). Do NOT broadly relax.

- [ ] **Step 3: Full gate chain (each UNPIPED)**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
typos .
cargo deny check
cargo +1.88 check -p paksmith-core -p paksmith-cli   # MSRV (if installed)
```

Plus minimal-versions: `cargo +nightly -Zdirect-minimal-versions check -p paksmith-core -p paksmith-cli` (if available) — confirm `reqwest = "0.12"`, `tokio = "1"`, `ed25519-dalek = "2"`, `wiremock = "0.6"` floors resolve; bump a floor minimally if a needed API isn't present.

- [ ] **Step 4: cargo-mutants (before push)** — `git diff $(git merge-base origin/main HEAD)..HEAD > /tmp/pr.diff && cargo mutants --in-diff /tmp/pr.diff --no-shuffle -j 2 --all-features 2>&1 | tail -25` → drive to **0 missed**. Kill survivors with core unit tests (parse caps, signature, cache, config, resolution); refactor equivalents; add documented `.cargo/mutants.toml` excludes only for genuine network/IO/env-wrapper residue.

- [ ] **Step 5: Fixture-count gate** — 5c adds NO `.pak` fixtures (the test keypair + signed payload are inline/non-`.pak`); confirm `find tests/fixtures -maxdepth 1 -name '*.pak' | wc -l` is unchanged vs `.github/workflows/ci.yml`'s `expected=`.

- [ ] **Step 6: Commit**

```bash
git add docs/plans/ROADMAP.md deny.toml .cargo/mutants.toml
git commit -m "docs(roadmap): mark phase 5c (remote registry) shipped"
```

---

## Review & Push

- Adversarial whole-branch panel with **mandatory security specialist** (untrusted-network input: https-only, body cap, timeout/redirect, signature-before-parse, strict caps on fetch AND cache load; secrets-at-rest `0600`; no key in logs; the `PAKSMITH_ALLOW_HTTP` test seam; the placeholder trusted key) + code-reviewer + architect + simplifier + a **deep-impact tracer** (the new core async surface + reqwest/tokio in core; `keys_serde` visibility widening; `resolve_pak_key` rewrite; new public API + `ProfileFault` variants) + a **wire-format/crypto reviewer** (ed25519 detached-sig over raw bytes vs a canonicalization; reqwest rustls config).
- Cycle to convergence; re-dispatch the full panel after each fix commit.
- Verify gates personally; run cargo-mutants to 0 missed; touch the convergence marker (separate Bash call); push; open PR (`gh --body-file`); Monitor CI to green (watch **Minimal versions**, **cargo-deny**, **cargo-mutants**, **MSRV 1.88**, all 3 OS **Test** jobs). Do NOT merge — the user merges.

---

## Self-Review (plan vs spec)

**Spec coverage:**
- ed25519 detached verify + trusted key (compiled-in, config-overridable) → Task 2 + Task 3. ✓
- async fetch (tokio block_on at CLI), reqwest rustls-tls → Task 5 + Task 8. ✓
- https-only, body cap (read, not Content-Length), timeout, redirect cap → Task 5. ✓
- signature-before-parse → Task 5 (`fetch_inner`). ✓
- strict parse + caps on fetch AND cache-load → Task 4 (`validate_caps`) reused in Task 6. ✓
- separate `registry-cache.json` `0600` + atomic + staleness → Task 6. ✓
- config.toml `[registry]` (url/staleness/pubkey) → Task 3. ✓
- layered resolution (local wins → cache) → Task 7. ✓
- `--game` auto-fetch + offline degradation → Task 9. ✓
- `profile fetch` (`--registry`/`--force`) + `profile list` cached → Task 8 + Task 9. ✓
- `ProfileFault` registry variants → Tasks 2/4/5/6. ✓
- no MSRV bump; minimal-versions; cargo-deny exceptions → Task 10. ✓
- `AesKey` non-Serialize, keys via `keys_serde` → Task 4. ✓
- no new `.pak` fixtures → Task 10 gate check. ✓

**Type consistency:** `verify_detached(&[u8],&[u8],&str)` (T2); `RegistryConfig{url,staleness_hours,public_key_hex}` (T3); `RegistryProfile{id,name,engine_version,keys}` + `RegistryDoc{profiles}` + `parse_registry`/`validate_caps` (T4/6); `RegistryClient::{new,fetch}` + `MAX_BODY_BYTES` (T5); `RegistryCache{fetched_at_unix,doc}` + `{path,load,save,load_from,save_to,is_stale,get}` (T6); `resolve_profile_layered`/`ResolvedProfile{Local,Registry}` (T7); `config_base_dir`/`write_restricted` pub(crate) (T1) — referenced identically across tasks.

**Open implementation points (resolve against live code; each has a crisp deliverable + test):**
- `reqwest::Response::chunk` vs `bytes_stream` for the capped read (T5) — use whichever the resolved 0.12 exposes; the accumulate-and-cap contract is fixed.
- The `PAKSMITH_ALLOW_HTTP` test seam (T8) — confirm with the security reviewer; the public `fetch` stays https-only.
- `validate_caps` extraction from `parse_registry` (T4) so the cache load reuses identical caps (T6).
- Reuse of 5b `resolve_key`'s guid→key step over a `&BTreeMap<KeyGuid,AesKey>` for both local + registry profiles (T9) — factor or duplicate-minimally; contract identical.
- `toml::de::Error::message()` vs `to_string()` (T3) — match 5b's choice (5b used `.message()`).
- cargo-deny exceptions for the TLS stack (T10) — scope per-crate + document.
