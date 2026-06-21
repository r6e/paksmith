# Phase 5c — Remote Game-Profile Registry Design

**Status:** approved (brainstorming), pre-implementation
**Date:** 2026-06-20
**Roadmap:** Phase 5 (Game Profiles) — sub-phase 5c (remote registry)

## Context

Phase 5 decomposes into **5a AES decryption → 5b local profiles + key
management → 5c remote registry → 5d auto-detection**, each its own spec → plan
→ cycle. This document specifies **5c only**.

5b shipped the local profile store: `GameProfile`, `KeyGuid`, `ProfileStore`
(TOML at `<config_dir>/paksmith/profiles.toml`, `0600`), `resolve_key`, the
`profile` CLI (CRUD + key + test), and the global `--game` flag. No network or
async dependencies exist yet.

5c adds a **remote registry**: paksmith fetches game profiles (including AES
keys) from a configurable HTTPS endpoint, **verifies an ed25519 signature**,
caches the result to disk, and layers the cached profiles **under** the user's
local store. `--game` resolution **auto-fetches** when a profile isn't local
and the cache is missing or stale, degrading gracefully to the cache (or a
clear error) when offline. This is the first network + async surface in
paksmith.

## Goals / non-goals

- **Goal:** signed, cached, offline-degrading retrieval of community game
  profiles, layered under local profiles, with `paksmith profile fetch` and
  auto-fetch on `--game` resolution.
- **Non-goal:** auto-detection of a game from a directory (5d); a *write*/
  publish API (read-only client); a live community registry (none exists yet —
  the default endpoint + trusted key are documented placeholders; the
  mechanism is real + fully tested); user accounts/auth; an MSRV bump (the new
  deps all build on 1.88).

## Decisions (from brainstorming)

- **Async runtime:** real async via **tokio** (current-thread runtime built at
  the CLI boundary; core exposes an `async fn`, the CLI `block_on`s it).
- **Network client lives in `paksmith-core`** (`profile/registry.rs`), per the
  ROADMAP, so the future GUI shares it — core gains `reqwest` + `tokio`.
- **Separate cache file + layered resolution:** downloaded data lives in a
  read-only `registry-cache.json`; user `profiles.toml` always wins.
- **Auto-fetch on stale/missing** during `--game` resolution, with graceful
  offline degradation (never hard-fail merely because offline).
- **Signature:** **ed25519 detached** signature over the raw payload bytes
  (`ed25519-dalek`), signature fetched as a sidecar `<url>.sig`, verified
  against a **compiled-in trusted public key** overridable via config. Reject
  on verify failure **even over HTTPS**.

## Architecture

```
crates/paksmith-core/Cargo.toml                 # MODIFY: add reqwest (rustls-tls), tokio (rt), ed25519-dalek; wiremock (dev)
crates/paksmith-core/src/profile/signature.rs   # CREATE: ed25519 detached-sig verify + TRUSTED_PUBKEY const
crates/paksmith-core/src/profile/config.rs       # CREATE: RegistryConfig (url, staleness_hours, pubkey override) from config.toml
crates/paksmith-core/src/profile/registry.rs     # CREATE: RegistryProfile/RegistryDoc model + async RegistryClient::fetch (https-only, size cap, sig verify, strict parse)
crates/paksmith-core/src/profile/cache.rs         # CREATE: RegistryCache read/write (0600) + fetched_at + staleness
crates/paksmith-core/src/profile/mod.rs           # MODIFY: register submodules; layered-resolution helper over cache
crates/paksmith-core/src/error.rs                 # MODIFY: extend ProfileFault with registry/network/signature/cache variants
crates/paksmith-cli/Cargo.toml                    # MODIFY: tokio (rt) for block_on at the CLI boundary
crates/paksmith-cli/src/commands/profile.rs       # MODIFY: `profile fetch` subcommand; `profile list` shows cached
crates/paksmith-cli/src/commands/key_resolve.rs   # MODIFY: --game auto-fetch (block_on) + offline degradation
crates/paksmith-cli/src/main.rs                   # MODIFY: build the tokio runtime; thread it where fetch is driven
docs/plans/ROADMAP.md                             # MODIFY (gate task): mark 5c shipped
deny.toml                                          # MODIFY (gate task): license exceptions for TLS/transitive crates as needed
```

Core stays sync except `profile/registry.rs` (the one `async fn`). The CLI owns
the tokio runtime and orchestrates the layered resolution.

### Component 1 — `signature.rs`

```rust
/// Compiled-in trusted ed25519 public key for the default registry.
/// Documented PLACEHOLDER until a live registry exists; overridable via
/// `[registry] public_key` in config.
pub(crate) const TRUSTED_REGISTRY_PUBKEY_HEX: &str = "<32-byte ed25519 pubkey, hex>";

/// Verify a detached ed25519 signature over `payload` against `pubkey_hex`.
/// Returns `Ok(())` on a valid signature, else a typed error. No payload or
/// key material in the error.
pub(crate) fn verify_detached(payload: &[u8], sig: &[u8], pubkey_hex: &str) -> Result<(), ProfileFault>;
```

Uses `ed25519-dalek` `VerifyingKey::verify_strict`. 64-byte signature, 32-byte
key; malformed sizes → typed error, never panic.

### Component 2 — `config.rs`

```rust
pub struct RegistryConfig {
    pub url: String,             // default: compiled-in placeholder community URL
    pub staleness_hours: u64,    // default 24
    pub public_key_hex: String,  // default: TRUSTED_REGISTRY_PUBKEY_HEX
}
```

Loaded from `<config_dir>/paksmith/config.toml` `[registry]` (honoring
`PAKSMITH_CONFIG_DIR`); each field defaults from the compiled-in constants when
the file/section/field is absent. Missing file → all defaults (not an error);
corrupt → typed error. Reuses the 5b `config_path_from_env` base resolution.

### Component 3 — `registry.rs`

```rust
pub struct RegistryProfile {
    pub id: String,
    pub name: String,
    pub engine_version: Option<String>,
    pub keys: BTreeMap<KeyGuid, AesKey>,   // same hex (de)serialization as GameProfile
}
pub struct RegistryDoc { pub profiles: Vec<RegistryProfile> }

pub struct RegistryClient { /* reqwest::Client (rustls), caps */ }
impl RegistryClient {
    /// Fetch + verify + parse. https-only; body capped; timeout + redirect cap;
    /// fetch `<url>` and `<url>.sig`; ed25519-verify raw bytes vs `pubkey_hex`
    /// BEFORE parsing; strict JSON + per-field caps. Network/verify/parse
    /// failures → typed ProfileFault. Never logs key material.
    pub async fn fetch(&self, url: &str, pubkey_hex: &str) -> Result<RegistryDoc, ProfileFault>;
}
```

- `reqwest` with `default-features = false, features = ["rustls-tls"]` (pure-
  Rust TLS, no OpenSSL). Body read with a hard cap (~8 MiB) independent of
  `Content-Length`. Timeout ~10s, redirect cap (e.g. 5).
- Reject non-`https` URLs before any request.
- The wire form is a JSON array of profile objects (`id`, `name`,
  `engine_version?`, `keys{guid_hex:key_hex}`); strict serde + caps:
  max profiles (e.g. 10 000), max keys/profile (e.g. 64), max string lengths.
- Signature verified over the **raw payload bytes** (not a re-serialization),
  via `signature::verify_detached`, before parse/return.

### Component 4 — `cache.rs`

```rust
pub struct RegistryCache { pub fetched_at_unix: u64, pub doc: RegistryDoc }
impl RegistryCache {
    pub fn path() -> Result<PathBuf, PaksmithError>;          // <config>/paksmith/registry-cache.json (PAKSMITH_CONFIG_DIR honored)
    pub fn load() -> Result<Option<RegistryCache>, PaksmithError>;  // missing -> None; corrupt -> typed error; strict caps on parse
    pub fn save(&self) -> Result<(), PaksmithError>;          // atomic temp+rename, 0600 (reuse write_restricted)
    pub fn is_stale(&self, now_unix: u64, staleness_hours: u64) -> bool;
    pub fn get(&self, id: &str) -> Option<&RegistryProfile>;
}
```

`fetched_at_unix` is the wall-clock fetch time (the CLI supplies `now`;
`is_stale` takes `now` as a parameter so it is pure + unit-testable). Cache
holds AES keys → `0600`, same parser caps as the fetch path (the file is
user-editable = untrusted on load).

### Component 5 — layered resolution (`mod.rs` + CLI)

- Core helper: given a loaded `ProfileStore` + an optional `RegistryCache`,
  resolve an `id` → the user profile if present, else the cached registry
  profile. Pure + unit-testable.
- CLI `resolve_pak_key` (5b) extends: `profiles.toml[id]` (no network) → cache
  (fresh) (no network) → **auto-fetch** (block_on) when `id` is absent locally
  AND cache missing/stale → on success cache + use; **on fetch failure: stale
  cache entry if present (warn), else the existing `NoKeyForGuid`/profile-not-
  found error**. The pak's GUID still selects the key within the resolved
  profile (5b `resolve_key`). `--aes-key` still wins over `--game`.

### Component 6 — CLI

```
paksmith profile fetch [--registry <url>] [--force]   # explicit fetch+verify+cache; --force ignores staleness
paksmith profile list                                  # local profiles + cached registry profiles, source-tagged
```

`main` builds a current-thread tokio runtime (`tokio::runtime::Builder::
new_current_thread().enable_all().build()`) and `block_on`s the fetch (for both
`profile fetch` and the auto-fetch resolution path). `--registry` overrides the
config URL for one invocation.

## Error handling / exit codes

- Extend `ProfileFault` (5b, already `#[non_exhaustive]`) with registry
  variants: `Network { reason }`, `InsecureUrl { url }` (non-https),
  `ResponseTooLarge { limit }`, `SignatureInvalid`, `RegistryParse { reason }`,
  `CacheCorrupt { reason }`. Wire-stable `Display`, **no key/payload material**.
- CLI: network/verify/parse failures → exit 1; bad `--registry`/config → exit
  2 (`InvalidArgument`). Existing 0/1/2/BrokenPipe discipline unchanged. Offline
  auto-fetch failure that falls back to cache → exit 0 (with a warning); failure
  with no fallback → the normal resolution error.

## Security (mandatory security-reviewer surface)

- **Untrusted network input:** the response is attacker-influenceable until the
  signature is verified. Enforce **https-only**, a **hard body-size cap**
  (independent of `Content-Length`), a **timeout** + **redirect cap**, then
  **ed25519 signature verification of the raw bytes against the trusted key**
  before any parse or cache write. A verify failure aborts the fetch even over
  a valid TLS connection.
- **Defense-in-depth parsing:** strict serde + per-field caps on BOTH the fetch
  path and the cache-load path (the cache file is user-editable). No panics on
  malformed input.
- **Secrets at rest:** `registry-cache.json` holds AES keys → `0600` from
  creation (reuse 5b `write_restricted`), atomic temp+rename. No key material in
  logs/errors/`Debug` (the `AesKey` redaction invariants from 5a/5b hold).
- **TLS:** rustls (pure-Rust); no OpenSSL/native-tls.
- **Trust model:** the registry is trusted only insofar as it is signed by the
  pinned key; HTTPS alone is not sufficient (documented). The default key is a
  placeholder until a real registry + key exist.

## Testing

- **Unit:** `verify_detached` (valid sig passes; tampered payload / wrong key /
  malformed sizes fail — using a committed test ed25519 keypair + a signed test
  payload fixture); `RegistryConfig` defaults + TOML overrides; `RegistryCache`
  round-trip + `0600` + `is_stale` boundary (pure, `now` injected) + corrupt →
  typed error + caps; strict-parse + size-cap + https-only rejection; layered
  resolution (local wins / cache fallback / miss).
- **Integration (mock HTTP):** `wiremock` (dev-dep) serves a signed payload +
  `.sig`; `RegistryClient::fetch` succeeds; tampered payload → `SignatureInvalid`;
  oversized body → `ResponseTooLarge`; http URL → `InsecureUrl`; timeout/5xx →
  `Network`. Offline degradation: fetch fails → stale cache served (warn).
- **CLI (isolated `PAKSMITH_CONFIG_DIR`):** `profile fetch` against a wiremock
  endpoint caches + `profile list` shows the `[registry]`-tagged profiles;
  `--force`; `--game` resolves a registry-only profile via auto-fetch; offline
  (no/again-down endpoint) falls back to stale cache; bad `--registry` → exit 2.
- A **test keypair + signed fixture** are committed (these are NOT `.pak`
  fixtures, so the pak fixture-count gate is untouched).

## Build notes / risks

- **No MSRV bump:** `reqwest`/`tokio`/`ed25519-dalek` all have MSRVs below
  paksmith's 1.88, so they build on 1.88. The `Minimal versions` CI job needs
  floors that resolve — pin sane minimums and bump only if a needed API isn't
  in the floor.
- **cargo-deny:** the TLS stack (`rustls`, `ring`/`aws-lc-rs`) + transitive
  crates may need scoped `deny.toml` license exceptions (ISC/OpenSSL-style) and
  `allow`/`bans` review. Handle in the gate task; keep exceptions scoped +
  documented (the existing morton/option-ext precedent).
- **reqwest TLS backend:** use `rustls-tls` explicitly (`default-features =
  false`) to avoid pulling OpenSSL/native-tls (cross-platform, no native dep).
- **`AesKey`/`KeyGuid` reuse:** registry/cache (de)serialize keys via the same
  `keys_serde` hex path as `GameProfile` — `AesKey` stays non-`Serialize`.
- **cargo-mutants:** run `cargo mutants --in-diff` locally before the final push
  (the PR-diff job is not in the local gate chain — it has failed post-push on
  5a + 5b). Expect survivors on the new parse/verify/cache code; kill via unit
  tests, refactor equivalents, exclude only genuine residue.

## Scope boundary

5c ships signed, cached, offline-degrading registry retrieval + auto-fetch
resolution + `profile fetch`. Auto-detection from a directory (5d) and any
publish/write API are out of scope and get their own spec → plan → cycle.
