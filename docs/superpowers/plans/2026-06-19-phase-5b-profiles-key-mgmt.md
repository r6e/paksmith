# Phase 5b — Game Profiles + AES Key Management Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist AES keys as named, local game profiles and resolve the right key from a pak's encryption-key GUID, so users run `paksmith --game <id> ...` instead of pasting `--aes-key <hex>` every time.

**Architecture:** A new `paksmith-core/src/profile/` module holds the data model (`KeyGuid`, `GameProfile`, `ProfileStore`), TOML disk I/O (atomic + `0600`), guid→key resolution, and key-testing (reusing 5a's `open_with_key` + `verify_index`). The CLI gains a `profile` subcommand (CRUD + key management + test) and a global `--game <id>` flag whose key resolution lives in one shared CLI helper that every container command calls (each command owns its pak path; the footer GUID is readable without the key).

**Tech Stack:** Rust 2024 (MSRV 1.88), `serde` + `toml` (profile serialization), `dirs` (config dir), `thiserror`, `tracing`. Builds on 5a: `paksmith_core::AesKey`, `PakReader::open_with_key`, `PakReader::verify_index`, `footer.encryption_key_guid()`.

## Global Constraints

- MSRV 1.88; Rust edition 2024. No `if let` match guards / unstable syntax (use let-else).
- No panics in `paksmith-core` — all fallible ops return `Result<T, PaksmithError>`.
- `thiserror` errors with wire-stable `Display`; `tracing` for logs (no `println!`/`eprintln!` in core).
- **AES keys are secrets:** never appear in any log / `Debug` / error message. `AesKey` keeps its 5a `ZeroizeOnDrop` + redacted `Debug` + no `Display` + no *public* byte accessor. `AesKey` is **not** `Serialize`; the profile module serializes keys via a crate-internal `to_hex`.
- Profile store: one TOML file at `<config_dir>/paksmith/profiles.toml` (`dirs::config_dir`), overridable by the `PAKSMITH_CONFIG_DIR` env var (used verbatim as the base dir). Written atomically (temp file + rename) with `0600` perms on unix (best-effort/no-op elsewhere).
- `profile show` redacts keys by default; `--show-keys` reveals hex.
- `--aes-key` takes precedence over `--game` when both are supplied (explicit overrides stored), with a `debug!` note.
- Reuse the 5a vendored encrypted fixtures (`tests/fixtures/real_v8b_encrypted_index.pak`, key `94d25bc3aeb420e0be914edc9d5435a1eaab5f2864e09e94019ac205b727a7de`) — **no new `.pak` fixtures** (the CI fixture-count gate must stay untouched).
- Conventional commits; one logical change per commit. Run `cargo fmt --all`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace --all-features`, `typos .` before declaring a task done.
- Do NOT bump any `Cargo.toml` `version =` (release-please owns versions). Adding `[dependencies]` entries is fine.

## File Structure

- `crates/paksmith-core/src/container/pak/crypto.rs` — MODIFY: add `AesKey::from_hex` (pub) + `to_hex` (pub(crate)) + `AesKeyHexError`.
- `crates/paksmith-core/src/profile/mod.rs` — CREATE: `KeyGuid`, `GameProfile`, `ProfileStore`, `resolve_key`, serde adapters.
- `crates/paksmith-core/src/profile/store.rs` — CREATE: `config_path`, `load`, `save` (atomic + `0600`).
- `crates/paksmith-core/src/profile/key_test.rs` — CREATE: `KeyTestOutcome`, `test_key`.
- `crates/paksmith-core/src/container/pak/mod.rs` — MODIFY: `PakReader::read_footer_guid(path)`.
- `crates/paksmith-core/src/error.rs` — MODIFY: `PaksmithError::Profile { fault }` + `ProfileFault` enum.
- `crates/paksmith-core/src/lib.rs` — MODIFY: register `profile` module + re-exports.
- `crates/paksmith-core/Cargo.toml` + root `Cargo.toml` — MODIFY: add `toml`, `dirs`.
- `crates/paksmith-cli/src/commands/profile.rs` — CREATE: `profile` subcommand.
- `crates/paksmith-cli/src/commands/mod.rs` — MODIFY: register `Profile` variant; thread `game`.
- `crates/paksmith-cli/src/commands/key_resolve.rs` — CREATE: shared `resolve_key` CLI helper.
- `crates/paksmith-cli/src/commands/{list,inspect,extract,search}.rs` — MODIFY: call the shared resolver.
- `crates/paksmith-cli/src/main.rs` — MODIFY: `--game` flag; refactor `--aes-key` onto `AesKey::from_hex`.
- `docs/plans/ROADMAP.md` — MODIFY: mark 5b shipped.

---

### Task 1: Core hex codec — `AesKey::from_hex` / `to_hex`

Lift the CLI's `parse_aes_key` decode into core so both the `--aes-key` flag and the profile loader decode through one tested path, and give the profile serializer a crate-internal `to_hex`.

**Files:**
- Modify: `crates/paksmith-core/src/container/pak/crypto.rs`
- Modify: `crates/paksmith-cli/src/main.rs` (`parse_aes_key` delegates to `AesKey::from_hex`)

**Interfaces:**
- Produces: `pub fn AesKey::from_hex(s: &str) -> Result<AesKey, AesKeyHexError>` (strips optional `0x`/`0X`; requires exactly 64 ASCII-hex chars; case-insensitive). `pub enum AesKeyHexError { WrongLength { got: usize }, NonHex }` (impl `std::error::Error` + `Display`, no key material). `pub(crate) fn AesKey::to_hex(&self) -> String` (64 lowercase hex chars; crate-internal, profile serializer only).

- [ ] **Step 1: Write the failing test** — append to `crypto.rs`'s `#[cfg(test)] mod tests`:

```rust
#[test]
fn from_hex_roundtrips_with_to_hex() {
    let hex = "94d25bc3aeb420e0be914edc9d5435a1eaab5f2864e09e94019ac205b727a7de";
    let key = AesKey::from_hex(hex).expect("valid 64-hex key");
    assert_eq!(key.to_hex(), hex, "to_hex must round-trip from_hex (lowercase)");
}

#[test]
fn from_hex_accepts_0x_prefix_and_uppercase() {
    let lower = AesKey::from_hex("ab".repeat(32).as_str()).unwrap();
    let prefixed = AesKey::from_hex(&format!("0X{}", "AB".repeat(32))).unwrap();
    assert_eq!(lower.to_hex(), prefixed.to_hex(), "0x prefix + uppercase decode identically");
}

#[test]
fn from_hex_rejects_wrong_length_and_non_hex() {
    assert!(matches!(
        AesKey::from_hex(&"ab".repeat(31)),
        Err(AesKeyHexError::WrongLength { got: 62 })
    ));
    assert!(matches!(
        AesKey::from_hex(&format!("0x{}", "ab".repeat(31))),
        Err(AesKeyHexError::WrongLength { got: 62 })
    ));
    assert!(matches!(
        AesKey::from_hex(&format!("g{}", "a".repeat(63))),
        Err(AesKeyHexError::NonHex)
    ));
}

#[test]
fn aes_key_hex_error_display_has_no_key_material() {
    let e = AesKeyHexError::WrongLength { got: 10 };
    assert!(e.to_string().contains("64"), "message names the expected length: {e}");
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p paksmith-core --all-features from_hex 2>&1 | tail -15`
Expected: FAIL — `from_hex`, `to_hex`, `AesKeyHexError` not found.

- [ ] **Step 3: Implement** — in `crypto.rs`, add the error type and the two methods to `impl AesKey`:

```rust
/// Failure decoding a hex AES-256 key. Carries no key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AesKeyHexError {
    /// The hex string (after stripping an optional `0x`/`0X`) was not 64 chars.
    WrongLength {
        /// Number of hex chars seen (excluding the prefix).
        got: usize,
    },
    /// A non-hex character was present.
    NonHex,
}

impl std::fmt::Display for AesKeyHexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongLength { got } => {
                write!(f, "expected 64 hex chars (32 bytes), got {got}")
            }
            Self::NonHex => f.write_str("key contains non-hex characters"),
        }
    }
}

impl std::error::Error for AesKeyHexError {}

impl AesKey {
    /// Decode a 64-hex-char AES-256 key (optional `0x`/`0X` prefix,
    /// case-insensitive). Never includes key material in the error.
    pub fn from_hex(s: &str) -> Result<Self, AesKeyHexError> {
        let hex = s
            .strip_prefix("0x")
            .or_else(|| s.strip_prefix("0X"))
            .unwrap_or(s);
        if hex.len() != 64 {
            return Err(AesKeyHexError::WrongLength { got: hex.len() });
        }
        let mut bytes = [0u8; 32];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            if !chunk[0].is_ascii_hexdigit() || !chunk[1].is_ascii_hexdigit() {
                return Err(AesKeyHexError::NonHex);
            }
            bytes[i] = u8::from_str_radix(
                std::str::from_utf8(chunk).expect("ascii-validated above"),
                16,
            )
            .expect("ascii-hex pair always parses");
        }
        Ok(Self::new(bytes))
    }

    /// Lowercase 64-char hex of the key. Crate-internal: used ONLY by the
    /// profile serializer to write the `0600` store. Not public — keeps the
    /// no-public-byte-accessor invariant.
    pub(crate) fn to_hex(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(64);
        for b in self.0 {
            write!(s, "{b:02x}").expect("write to String is infallible");
        }
        s
    }
}
```

Then re-export `AesKeyHexError` alongside `AesKey` in `crypto.rs`'s module exports / `mod.rs` (`pub use crypto::{AesKey, AesKeyHexError};` — mirror the existing `pub use crypto::AesKey;`).

- [ ] **Step 4: Refactor the CLI flag onto the core codec** — in `crates/paksmith-cli/src/main.rs`, replace the body of `parse_aes_key` (keep its signature + `arg: "--aes-key"` context):

```rust
fn parse_aes_key(s: &str) -> paksmith_core::Result<paksmith_core::AesKey> {
    paksmith_core::AesKey::from_hex(s).map_err(|e| paksmith_core::PaksmithError::InvalidArgument {
        arg: "--aes-key",
        reason: e.to_string(),
    })
}
```

(The existing `parse_aes_key_*` CLI unit tests must still pass unchanged — they assert valid/`0x`/uppercase/wrong-length/non-hex behavior, all preserved by `from_hex`.)

- [ ] **Step 5: Run tests** — `cargo test -p paksmith-core -p paksmith-cli --all-features 2>&1 | tail -15` (new core tests + existing `parse_aes_key_*` all PASS).

- [ ] **Step 6: Commit**

```bash
git add crates/paksmith-core crates/paksmith-cli
git commit -m "feat(core): add AesKey::from_hex/to_hex hex codec"
```

---

### Task 2: Profile data model + resolution (`profile/mod.rs`)

`KeyGuid`, `GameProfile`, `ProfileStore`, the pure `resolve_key`, and serde adapters that round-trip through TOML. No disk I/O yet (Task 3).

**Files:**
- Create: `crates/paksmith-core/src/profile/mod.rs`
- Modify: `crates/paksmith-core/src/lib.rs` (register `pub mod profile;` + re-exports)
- Modify: root `Cargo.toml` + `crates/paksmith-core/Cargo.toml` (add `toml`)

**Interfaces:**
- Consumes: `AesKey`, `AesKey::from_hex`, `AesKey::to_hex` (Task 1).
- Produces:
  - `pub struct KeyGuid([u8; 16])` with `pub const ZERO: KeyGuid`, `pub fn is_zero(&self) -> bool`, `pub fn from_bytes([u8;16]) -> Self`, `pub fn as_bytes(&self) -> &[u8;16]`, `pub fn to_hex(&self) -> String` (32 lowercase hex), `pub fn from_hex(&str) -> Result<KeyGuid, KeyGuidHexError>`. Derives `Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug`.
  - `pub enum KeyGuidHexError { WrongLength { got: usize }, NonHex }` (Display, Error).
  - `pub struct GameProfile { pub name: String, pub engine_version: Option<String>, pub keys: BTreeMap<KeyGuid, AesKey> }` (the id is the `ProfileStore` map key, NOT a field). `#[derive(Clone, Debug, Default)]` + serde via the `keys_serde` adapter below.
  - `pub struct ProfileStore { pub profiles: BTreeMap<String, GameProfile> }` (`Clone, Debug, Default, Serialize, Deserialize`). On-disk TOML root: `[profiles.<id>] name=.. engine_version=.. [profiles.<id>.keys] "<32hex>"="<64hex>"`.
  - `pub fn resolve_key<'a>(profile: &'a GameProfile, pak_guid: Option<&[u8; 16]>) -> Option<&'a AesKey>` — exact GUID hit; pak `None`/all-zero → the `KeyGuid::ZERO` entry; else `None`.

- [ ] **Step 1: Add the `toml` dependency.** Root `Cargo.toml` `[workspace.dependencies]`: `toml = "0.8"`. `crates/paksmith-core/Cargo.toml` `[dependencies]`: `toml = { workspace = true }`. (serde is already a workspace dep with `derive`.)

- [ ] **Step 2: Write the failing tests** — create `crates/paksmith-core/src/profile/mod.rs` with ONLY a test module first:

```rust
#[cfg(test)]
mod tests {
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
        keys.insert(KeyGuid::ZERO, key(&"11".repeat(32)));
        keys.insert(g, key(K1));
        let p = GameProfile { name: "G".into(), engine_version: None, keys };
        // exact GUID hit
        assert_eq!(resolve_key(&p, Some(g.as_bytes())).unwrap().to_hex(), K1);
        // pak has no GUID → zero-default
        assert_eq!(resolve_key(&p, None).unwrap().to_hex(), "11".repeat(32));
        // pak has all-zero GUID → zero-default
        assert_eq!(resolve_key(&p, Some(&[0u8; 16])).unwrap().to_hex(), "11".repeat(32));
        // unknown GUID, no zero-default present
        let p2 = GameProfile { name: "G".into(), engine_version: None, keys: BTreeMap::new() };
        assert!(resolve_key(&p2, Some(g.as_bytes())).is_none());
    }

    #[test]
    fn store_toml_roundtrip_is_deterministic() {
        let mut keys = BTreeMap::new();
        keys.insert(KeyGuid::ZERO, key(K1));
        let mut profiles = BTreeMap::new();
        profiles.insert(
            "fortnite".to_string(),
            GameProfile { name: "Fortnite".into(), engine_version: Some("5.3".into()), keys },
        );
        let store = ProfileStore { profiles };
        let text = toml::to_string_pretty(&store).unwrap();
        assert!(text.contains("[profiles.fortnite]"));
        assert!(text.contains(r#"name = "Fortnite""#));
        assert!(text.contains(r#"engine_version = "5.3""#));
        assert!(text.contains(K1), "key serialized as hex");
        let back: ProfileStore = toml::from_str(&text).unwrap();
        assert_eq!(back.profiles["fortnite"].keys[&KeyGuid::ZERO].to_hex(), K1);
        assert_eq!(back.profiles["fortnite"].engine_version.as_deref(), Some("5.3"));
    }

    #[test]
    fn key_serialized_as_lowercase_hex_not_debug() {
        // AesKey Debug is redacted; the store must contain the real hex, never "<redacted>".
        let mut keys = BTreeMap::new();
        keys.insert(KeyGuid::ZERO, key(K1));
        let mut profiles = BTreeMap::new();
        profiles.insert("g".into(), GameProfile { name: "G".into(), engine_version: None, keys });
        let text = toml::to_string_pretty(&ProfileStore { profiles }).unwrap();
        assert!(!text.contains("redacted"), "store must not contain a redacted Debug: {text}");
    }
}
```

- [ ] **Step 3: Run to verify it fails**

Run: `cargo test -p paksmith-core --all-features profile:: 2>&1 | tail -15`
Expected: FAIL — `KeyGuid`, `GameProfile`, `ProfileStore`, `resolve_key` not found.

- [ ] **Step 4: Implement the model** — prepend to `profile/mod.rs` (above the test module):

```rust
//! Local game profiles: persistent, named AES key storage with guid→key
//! resolution. The store lives in a single TOML file (see [`store`]); key
//! testing lives in [`key_test`]. Network registry (5c) and auto-detection
//! (5d) are separate sub-phases and not part of this module.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::AesKey;

pub mod key_test;
pub mod store;

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
pub fn resolve_key<'a>(profile: &'a GameProfile, pak_guid: Option<&[u8; 16]>) -> Option<&'a AesKey> {
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
            out.insert(guid, key);
        }
        Ok(out)
    }
}
```

NOTE on `resolve_key`'s exact-hit fallback: when a non-zero pak GUID is present but absent from the map, it falls back to the zero-default if one exists (a profile with a single default key still opens a GUID-tagged pak). That is intentional and pinned by the `resolve_prefers_exact_guid_then_zero_default` test (the `p2` case has no zero entry → `None`).

- [ ] **Step 5: Register the module** — in `crates/paksmith-core/src/lib.rs`, add `pub mod profile;` (alongside the other `pub mod`s) and re-export the public types: `pub use profile::{GameProfile, KeyGuid, ProfileStore};`.

- [ ] **Step 6: Run tests** — `cargo test -p paksmith-core --all-features profile:: 2>&1 | tail -15` (all PASS).

- [ ] **Step 7: Commit**

```bash
git add crates/paksmith-core Cargo.toml
git commit -m "feat(profile): add KeyGuid/GameProfile/ProfileStore model + resolution"
```

---

### Task 3: Profile store disk I/O (`profile/store.rs`) + `ProfileFault`

Load/save the TOML store with the `PAKSMITH_CONFIG_DIR` override, atomic write, and `0600` perms. Add the typed error.

**Files:**
- Create: `crates/paksmith-core/src/profile/store.rs`
- Modify: `crates/paksmith-core/src/error.rs` (`PaksmithError::Profile { fault }` + `ProfileFault`)
- Modify: root `Cargo.toml` + `crates/paksmith-core/Cargo.toml` (add `dirs`)

**Interfaces:**
- Consumes: `ProfileStore` (Task 2), `PaksmithError`.
- Produces (on `ProfileStore`):
  - `pub fn config_path() -> Result<std::path::PathBuf, PaksmithError>` — `$PAKSMITH_CONFIG_DIR/paksmith/profiles.toml` if the env var is set, else `dirs::config_dir()/paksmith/profiles.toml`; errors `ProfileFault::NoConfigDir` if neither resolves.
  - `pub fn load() -> Result<ProfileStore, PaksmithError>` — missing file → `ProfileStore::default()`; parse failure → `ProfileFault::CorruptStore`.
  - `pub fn save(&self) -> Result<(), PaksmithError>` — create parent dir, write atomically (temp + rename), `0600` on unix.
- Produces (error): `PaksmithError::Profile { fault: ProfileFault }`; `pub enum ProfileFault { NoConfigDir, CorruptStore { reason: String }, Io { reason: String }, ProfileNotFound { id: String }, NoKeyForGuid { id: String, guid: String }, MalformedKey { reason: String } }` (the last three are used by Tasks 5–7).

- [ ] **Step 1: Add the `dirs` dependency.** Root `Cargo.toml` `[workspace.dependencies]`: `dirs = "5"`. `crates/paksmith-core/Cargo.toml` `[dependencies]`: `dirs = { workspace = true }`.

- [ ] **Step 2: Add the error type** — in `crates/paksmith-core/src/error.rs`, add a variant to `pub enum PaksmithError` (mirror `InvalidIndex { fault }`):

```rust
    /// A game-profile / key-store operation failed.
    #[error("profile error: {fault}")]
    Profile {
        /// Structured category + payload.
        fault: ProfileFault,
    },
```

and define the fault enum near the other fault enums (e.g. after `IndexParseFault`):

```rust
/// Structured category + payload for [`PaksmithError::Profile`].
#[derive(Debug, thiserror::Error)]
pub enum ProfileFault {
    /// No config directory could be resolved (no `PAKSMITH_CONFIG_DIR`, and
    /// the platform config dir is unavailable).
    #[error("no config directory available (set PAKSMITH_CONFIG_DIR)")]
    NoConfigDir,
    /// The store file exists but could not be parsed as a valid profile TOML.
    #[error("profile store is corrupt: {reason}")]
    CorruptStore {
        /// Parser-supplied detail (no key material).
        reason: String,
    },
    /// Reading or writing the store file failed.
    #[error("profile store I/O failed: {reason}")]
    Io {
        /// I/O detail.
        reason: String,
    },
    /// No profile with the given id exists.
    #[error("no profile named `{id}`")]
    ProfileNotFound {
        /// The requested id.
        id: String,
    },
    /// The profile has no key for the pak's encryption-key GUID.
    #[error("profile `{id}` has no key for GUID {guid}")]
    NoKeyForGuid {
        /// Profile id.
        id: String,
        /// 32-hex GUID that was looked up.
        guid: String,
    },
    /// A supplied key/guid hex was malformed.
    #[error("malformed key material: {reason}")]
    MalformedKey {
        /// Detail (no key bytes).
        reason: String,
    },
}
```

- [ ] **Step 3: Write the failing tests** — create `crates/paksmith-core/src/profile/store.rs` with a test module. Tests set `PAKSMITH_CONFIG_DIR` to a `tempfile::tempdir()`; run them `#[serial_test::serial]`-style by keeping them in ONE `#[test]` per concern but NOT relying on a shared process env across tests — instead pass the dir explicitly via a private `config_path_in(base)` helper that the public `config_path()` delegates to. (Env-var mutation across parallel tests is racy; the explicit-base helper avoids it.)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{GameProfile, KeyGuid};
    use crate::AesKey;
    use std::collections::BTreeMap;

    const K1: &str = "94d25bc3aeb420e0be914edc9d5435a1eaab5f2864e09e94019ac205b727a7de";

    fn sample_store() -> ProfileStore {
        let mut keys = BTreeMap::new();
        keys.insert(KeyGuid::ZERO, AesKey::from_hex(K1).unwrap());
        let mut profiles = BTreeMap::new();
        profiles.insert(
            "fortnite".into(),
            GameProfile { name: "Fortnite".into(), engine_version: Some("5.3".into()), keys },
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
            crate::PaksmithError::Profile { fault: crate::error::ProfileFault::CorruptStore { .. } }
        ));
    }

    #[test]
    fn config_path_honors_env_override() {
        // config_path_in is the pure core; this just checks the join shape.
        let p = config_path_in(std::path::Path::new("/tmp/xyz"));
        assert!(p.ends_with("paksmith/profiles.toml"));
        assert!(p.starts_with("/tmp/xyz"));
    }
}
```

- [ ] **Step 4: Run to verify it fails**

Run: `cargo test -p paksmith-core --all-features profile::store 2>&1 | tail -15`
Expected: FAIL — `config_path_in`, `load_from`, `save_to`, `load_from` not found.

- [ ] **Step 5: Implement** — prepend to `profile/store.rs`:

```rust
//! TOML disk I/O for the profile store. One file at
//! `<config_dir>/paksmith/profiles.toml`, overridable via
//! `PAKSMITH_CONFIG_DIR`. Written atomically with `0600` perms on unix.

use std::path::{Path, PathBuf};

use crate::error::ProfileFault;
use crate::profile::ProfileStore;
use crate::PaksmithError;

/// `<base>/paksmith/profiles.toml`.
pub(crate) fn config_path_in(base: &Path) -> PathBuf {
    base.join("paksmith").join("profiles.toml")
}

impl ProfileStore {
    /// Resolve the store path: `$PAKSMITH_CONFIG_DIR/paksmith/profiles.toml`
    /// if set, else the platform config dir.
    pub fn config_path() -> Result<PathBuf, PaksmithError> {
        if let Some(base) = std::env::var_os("PAKSMITH_CONFIG_DIR") {
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
                    fault: ProfileFault::Io { reason: e.to_string() },
                })
            }
        };
        toml::from_str(&text).map_err(|e| PaksmithError::Profile {
            fault: ProfileFault::CorruptStore { reason: e.message().to_string() },
        })
    }

    /// Save to an explicit path: create the parent dir, write atomically via a
    /// sibling temp file + rename, and set `0600` on unix.
    pub(crate) fn save_to(&self, path: &Path) -> Result<(), PaksmithError> {
        let io = |e: std::io::Error| PaksmithError::Profile {
            fault: ProfileFault::Io { reason: e.to_string() },
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(io)?;
        }
        let text = toml::to_string_pretty(self).map_err(|e| PaksmithError::Profile {
            fault: ProfileFault::Io { reason: e.to_string() },
        })?;
        let tmp = path.with_extension("toml.tmp");
        std::fs::write(&tmp, text.as_bytes()).map_err(io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)).map_err(io)?;
        }
        std::fs::rename(&tmp, path).map_err(io)?;
        Ok(())
    }
}
```

Add `serde`'s error `.message()`: `toml::de::Error` has `.message()`. If the installed `toml` version lacks it, use `e.to_string()` instead (resolve at implementation against the resolved `toml` crate API).

- [ ] **Step 6: Run tests** — `cargo test -p paksmith-core --all-features profile::store 2>&1 | tail -15` (all PASS, including `#[cfg(unix)]` perms).

- [ ] **Step 7: Commit**

```bash
git add crates/paksmith-core Cargo.toml
git commit -m "feat(profile): add TOML store load/save (atomic, 0600) + ProfileFault"
```

---

### Task 4: Key testing + `read_footer_guid` (`profile/key_test.rs`)

Test a candidate key against a pak, and add the footer-only GUID read that `--game` resolution needs.

**Files:**
- Create: `crates/paksmith-core/src/profile/key_test.rs`
- Modify: `crates/paksmith-core/src/container/pak/mod.rs` (`PakReader::read_footer_guid`)

**Interfaces:**
- Consumes: `AesKey`, `PakReader::open_with_key`, `PakReader::verify_index`, `footer.encryption_key_guid()`, `VerifyOutcome`.
- Produces:
  - `pub fn PakReader::read_footer_guid<P: AsRef<Path>>(path: P) -> Result<Option<[u8; 16]>, PaksmithError>` — opens the file, reads ONLY the footer (no index parse — works on an encrypted pak without a key), returns the encryption-key GUID copied out (or `None` for pre-v7 paks).
  - `pub enum KeyTestOutcome { Verified, Decrypted, WrongKey, Unsupported }` (Debug, PartialEq, Eq).
  - `pub fn test_key<P: AsRef<Path>>(pak: P, key: &AesKey) -> KeyTestOutcome` — `open_with_key` then `verify_index`: `Verified` if the index hash matches; `Decrypted` if it opened but there is no index hash to check (`SkippedNoHash`); `WrongKey` on `Decryption`; `Unsupported` on `UnsupportedFeature`; any other error also maps to `Unsupported` (the key isn't the problem).

- [ ] **Step 1: Write the failing tests** — create `crates/paksmith-core/src/profile/key_test.rs` test module (gated like other fixture tests so it finds `tests/fixtures`):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::pak::PakReader;
    use crate::AesKey;

    fn fixture(name: &str) -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(name)
    }
    const KEY: &str = "94d25bc3aeb420e0be914edc9d5435a1eaab5f2864e09e94019ac205b727a7de";

    #[test]
    fn test_key_verified_with_correct_key() {
        let key = AesKey::from_hex(KEY).unwrap();
        let out = test_key(fixture("real_v8b_encrypted_index.pak"), &key);
        assert_eq!(out, KeyTestOutcome::Verified, "correct key on UnrealPak fixture must Verify");
    }

    #[test]
    fn test_key_wrong_key_is_wrongkey() {
        let key = AesKey::from_hex(&"00".repeat(32)).unwrap();
        let out = test_key(fixture("real_v8b_encrypted_index.pak"), &key);
        assert_eq!(out, KeyTestOutcome::WrongKey);
    }

    #[test]
    fn read_footer_guid_returns_some_for_v8b() {
        // v8b is >= v7 so a GUID field is present (all-zero for this fixture).
        let guid = PakReader::read_footer_guid(fixture("real_v8b_encrypted_index.pak")).unwrap();
        assert_eq!(guid, Some([0u8; 16]), "fixture uses the default (all-zero) GUID");
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p paksmith-core --all-features key_test 2>&1 | tail -15`
Expected: FAIL — `test_key`, `KeyTestOutcome`, `read_footer_guid` not found.

- [ ] **Step 3: Implement `read_footer_guid`** — in `crates/paksmith-core/src/container/pak/mod.rs`, add to `impl PakReader`. Mirror how `open` reads the footer, but stop after the footer (study the existing footer-read in `open`/`from_reader` and reuse `PakFooter::read_from` against a seek to the footer offset). Skeleton:

```rust
    /// Read ONLY the pak footer and return its encryption-key GUID, if any.
    ///
    /// The footer (including the GUID) is NOT encrypted, so this works on an
    /// encrypted pak without a key — it is how `--game` resolution learns
    /// which key a pak needs before opening it. Returns `None` for pre-v7
    /// paks that have no GUID field.
    pub fn read_footer_guid<P: AsRef<Path>>(path: P) -> crate::Result<Option<[u8; 16]>> {
        let mut file = std::fs::File::open(path)?;
        // Reuse the same footer-location logic `open` uses. Resolve against the
        // live code: locate the footer (magic scan / fixed offset), then
        // `PakFooter::read_from`, then `footer.encryption_key_guid().copied()`.
        let footer = Self::read_footer_only(&mut file)?;
        Ok(footer.encryption_key_guid().copied())
    }
```

Implement `read_footer_only(&mut File) -> Result<PakFooter>` by extracting the footer-reading portion of `from_reader`/`open` (the part before index parsing) into a small private helper, and have both `read_footer_guid` and the existing open path call it (DRY). If extraction is risky, inline the footer-seek + `PakFooter::read_from` directly in `read_footer_guid` and add a code comment cross-referencing the open path. Either way: NO index parsing, NO decryption.

- [ ] **Step 4: Implement `test_key` + `KeyTestOutcome`** — prepend to `profile/key_test.rs`:

```rust
//! Test a candidate AES key against a pak: open + verify the index hash.

use std::path::Path;

use crate::container::pak::{PakReader, VerifyOutcome};
use crate::{AesKey, PaksmithError};

/// Result of testing a key against a pak.
#[derive(Debug, PartialEq, Eq)]
pub enum KeyTestOutcome {
    /// Opened and the index SHA-1 matched the decrypted plaintext.
    Verified,
    /// Opened, but the pak stores no index hash to verify against.
    Decrypted,
    /// The key did not decrypt the index (wrong key).
    WrongKey,
    /// The pak uses a layout this build can't decrypt (e.g. v10+ encrypted
    /// index) — the key may be correct.
    Unsupported,
}

/// Open `pak` with `key` and verify its index. See [`KeyTestOutcome`].
pub fn test_key<P: AsRef<Path>>(pak: P, key: &AesKey) -> KeyTestOutcome {
    let reader = match PakReader::open_with_key(pak, key.clone()) {
        Ok(r) => r,
        Err(PaksmithError::Decryption { .. }) => return KeyTestOutcome::WrongKey,
        Err(PaksmithError::UnsupportedFeature { .. }) => return KeyTestOutcome::Unsupported,
        Err(_) => return KeyTestOutcome::Unsupported,
    };
    match reader.verify_index() {
        Ok(VerifyOutcome::Verified) => KeyTestOutcome::Verified,
        Ok(VerifyOutcome::SkippedNoHash) => KeyTestOutcome::Decrypted,
        Ok(_) => KeyTestOutcome::Decrypted,
        Err(PaksmithError::Decryption { .. }) => KeyTestOutcome::WrongKey,
        Err(_) => KeyTestOutcome::Unsupported,
    }
}
```

Confirm the `VerifyOutcome` import path and variant names against the live `container::pak` exports (5a's `verify_index` returns `VerifyOutcome`). If `verify_index` is named differently or returns a different type, adapt the match (resolve at implementation; the contract is Verified/SkippedNoHash/wrong-key).

- [ ] **Step 5: Run tests** — `cargo test -p paksmith-core --all-features 'profile::key_test' 2>&1 | tail -15` (all PASS).

- [ ] **Step 6: Commit**

```bash
git add crates/paksmith-core
git commit -m "feat(profile): add test_key + PakReader::read_footer_guid"
```

---

### Task 5: CLI `profile` CRUD — `add` / `list` / `show` / `remove`

The management command (profile-level verbs only; key verbs + test are Task 6).

**Files:**
- Create: `crates/paksmith-cli/src/commands/profile.rs`
- Modify: `crates/paksmith-cli/src/commands/mod.rs` (add `Profile` variant + `pub(crate) mod profile;`; dispatch in `run`)

**Interfaces:**
- Consumes: `ProfileStore`, `GameProfile`, `ProfileStore::{load,save}`, `PaksmithError::Profile`, `ProfileFault::ProfileNotFound`, `OutputFormat`.
- Produces: `pub(crate) enum ProfileCmd` (clap `Subcommand`) with `Add/List/Show/Remove` (+ `Key`/`Test` added in Task 6) and `pub(crate) fn run(cmd: &ProfileCmd, format: OutputFormat) -> paksmith_core::Result<u8>`.

- [ ] **Step 1: Write the failing CLI integration test** — create `crates/paksmith-cli/tests/profile_cli.rs`. Drive the binary with a temp `PAKSMITH_CONFIG_DIR`:

```rust
//! Integration tests for the `profile` subcommand.
use assert_cmd::Command;
use tempfile::tempdir;

fn paksmith(config_dir: &std::path::Path) -> Command {
    let mut c = Command::cargo_bin("paksmith").unwrap();
    c.env("PAKSMITH_CONFIG_DIR", config_dir);
    c
}

#[test]
fn add_list_show_remove_roundtrip() {
    let cfg = tempdir().unwrap();
    // add
    paksmith(cfg.path())
        .args(["profile", "add", "fortnite", "--name", "Fortnite", "--engine-version", "5.3"])
        .assert()
        .success();
    // list shows it
    let out = paksmith(cfg.path()).args(["profile", "list"]).assert().success();
    let txt = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(txt.contains("fortnite"), "list shows the id: {txt}");
    assert!(txt.contains("Fortnite"), "list shows the name: {txt}");
    // show
    let shown = paksmith(cfg.path()).args(["profile", "show", "fortnite"]).assert().success();
    let stxt = String::from_utf8(shown.get_output().stdout.clone()).unwrap();
    assert!(stxt.contains("5.3"), "show includes engine version: {stxt}");
    // remove
    paksmith(cfg.path()).args(["profile", "remove", "fortnite"]).assert().success();
    let out2 = paksmith(cfg.path()).args(["profile", "list"]).assert().success();
    let txt2 = String::from_utf8(out2.get_output().stdout.clone()).unwrap();
    assert!(!txt2.contains("fortnite"), "removed profile is gone: {txt2}");
}

#[test]
fn show_unknown_profile_exits_2() {
    let cfg = tempdir().unwrap();
    paksmith(cfg.path()).args(["profile", "show", "nope"]).assert().code(2);
}

#[test]
fn add_duplicate_id_is_rejected() {
    let cfg = tempdir().unwrap();
    paksmith(cfg.path()).args(["profile", "add", "g", "--name", "G"]).assert().success();
    paksmith(cfg.path()).args(["profile", "add", "g", "--name", "G2"]).assert().code(2);
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p paksmith-cli --test profile_cli 2>&1 | tail -15`
Expected: FAIL — no `profile` subcommand (clap error / non-zero in an unexpected way).

- [ ] **Step 3: Implement the command** — create `crates/paksmith-cli/src/commands/profile.rs`:

```rust
use clap::{Args, Subcommand};

use paksmith_core::error::ProfileFault;
use paksmith_core::profile::GameProfile;
use paksmith_core::{PaksmithError, ProfileStore};

use crate::output::OutputFormat;

#[derive(Subcommand)]
pub(crate) enum ProfileCmd {
    /// Create a new profile
    Add(AddArgs),
    /// List stored profiles
    List,
    /// Show one profile
    Show(ShowArgs),
    /// Delete a profile
    Remove(RemoveArgs),
}

#[derive(Args)]
pub(crate) struct AddArgs {
    /// Profile id (used by `--game`)
    pub(crate) id: String,
    /// Display name
    #[arg(long)]
    pub(crate) name: String,
    /// Engine version, e.g. 5.3
    #[arg(long)]
    pub(crate) engine_version: Option<String>,
}

#[derive(Args)]
pub(crate) struct ShowArgs {
    /// Profile id
    pub(crate) id: String,
    /// Reveal key hex (default: redacted)
    #[arg(long)]
    pub(crate) show_keys: bool,
}

#[derive(Args)]
pub(crate) struct RemoveArgs {
    /// Profile id
    pub(crate) id: String,
}

pub(crate) fn run(cmd: &ProfileCmd, _format: OutputFormat) -> paksmith_core::Result<u8> {
    match cmd {
        ProfileCmd::Add(a) => add(a),
        ProfileCmd::List => list(),
        ProfileCmd::Show(a) => show(a),
        ProfileCmd::Remove(a) => remove(a),
    }
}

fn add(a: &AddArgs) -> paksmith_core::Result<u8> {
    let mut store = ProfileStore::load()?;
    if store.profiles.contains_key(&a.id) {
        return Err(PaksmithError::InvalidArgument {
            arg: "id",
            reason: format!("profile `{}` already exists", a.id),
        });
    }
    store.profiles.insert(
        a.id.clone(),
        GameProfile { name: a.name.clone(), engine_version: a.engine_version.clone(), keys: Default::default() },
    );
    store.save()?;
    println!("added profile `{}`", a.id);
    Ok(0)
}

fn list() -> paksmith_core::Result<u8> {
    let store = ProfileStore::load()?;
    if store.profiles.is_empty() {
        println!("no profiles");
        return Ok(0);
    }
    for (id, p) in &store.profiles {
        let engine = p.engine_version.as_deref().unwrap_or("-");
        println!("{id}\t{}\t{engine}\t{} key(s)", p.name, p.keys.len());
    }
    Ok(0)
}

fn show(a: &ShowArgs) -> paksmith_core::Result<u8> {
    let store = ProfileStore::load()?;
    let p = store.profiles.get(&a.id).ok_or_else(|| PaksmithError::Profile {
        fault: ProfileFault::ProfileNotFound { id: a.id.clone() },
    })?;
    println!("id: {}", a.id);
    println!("name: {}", p.name);
    println!("engine_version: {}", p.engine_version.as_deref().unwrap_or("-"));
    println!("keys:");
    for guid in p.keys.keys() {
        if a.show_keys {
            // Reveal: only here is a key rendered. `keys[guid]` is an AesKey;
            // use the profile module's hex via a public accessor added in Task 6
            // (`profile::key_hex`). Until then, render the guid + a redacted marker.
            println!("  {} = {}", guid.to_hex(), paksmith_core::profile::key_hex(&p.keys[guid]));
        } else {
            println!("  {} = <redacted>", guid.to_hex());
        }
    }
    Ok(0)
}

fn remove(a: &RemoveArgs) -> paksmith_core::Result<u8> {
    let mut store = ProfileStore::load()?;
    if store.profiles.remove(&a.id).is_none() {
        return Err(PaksmithError::Profile {
            fault: ProfileFault::ProfileNotFound { id: a.id.clone() },
        });
    }
    store.save()?;
    println!("removed profile `{}`", a.id);
    Ok(0)
}
```

NOTE: `paksmith_core::profile::key_hex(&AesKey) -> String` is a thin public wrapper over the crate-internal `AesKey::to_hex`, added so `--show-keys` can render a key WITHOUT exposing a general key-stringify on `AesKey`. Add it in `profile/mod.rs` in THIS task (small): `pub fn key_hex(key: &AesKey) -> String { key.to_hex() }` with a doc-comment that it is the deliberate, single reveal path (used by `profile show --show-keys` and `profile key add` echo). The `ProfileFault::ProfileNotFound` path must map to exit 2 — confirm the CLI's top-level error mapping sends `PaksmithError::Profile` and `InvalidArgument` to `ExitCode::from(2)` (it already maps all non-BrokenPipe errors to 2; `add_duplicate_id` + `show_unknown` rely on this).

- [ ] **Step 4: Register the subcommand** — in `crates/paksmith-cli/src/commands/mod.rs`: add `pub(crate) mod profile;`, a `Profile(profile::ProfileCmd)` variant to `enum Command` (with a doc comment `/// Manage game profiles and AES keys`), and in `run` add `Self::Profile(cmd) => profile::run(cmd, format),` (note: `profile::run` returns `u8` already, so no `.map(|()| 0)`).

- [ ] **Step 5: Run tests** — `cargo test -p paksmith-cli --test profile_cli 2>&1 | tail -15` (all PASS) and `cargo build -p paksmith-cli` (clap wiring compiles).

- [ ] **Step 6: Commit**

```bash
git add crates/paksmith-cli crates/paksmith-core
git commit -m "feat(cli): add profile add/list/show/remove subcommands"
```

---

### Task 6: CLI `profile key add|remove` + `profile test`

Key-level management + the try-decrypt key test.

**Files:**
- Modify: `crates/paksmith-cli/src/commands/profile.rs` (add `Key` + `Test` variants + handlers)

**Interfaces:**
- Consumes: `AesKey::from_hex`, `KeyGuid::{ZERO,from_hex}`, `profile::key_test::{test_key, KeyTestOutcome}`, `PakReader::read_footer_guid`, `resolve_key`, `profile::key_hex`.
- Produces: `ProfileCmd::Key(KeyCmd)` (`Add`/`Remove`) and `ProfileCmd::Test(TestArgs)`.

- [ ] **Step 1: Write the failing tests** — append to `crates/paksmith-cli/tests/profile_cli.rs`:

```rust
const KEY: &str = "94d25bc3aeb420e0be914edc9d5435a1eaab5f2864e09e94019ac205b727a7de";

fn fixture(name: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent().unwrap().parent().unwrap()
        .join("tests/fixtures").join(name)
}

#[test]
fn key_add_then_show_redacts_then_reveals() {
    let cfg = tempdir().unwrap();
    paksmith(cfg.path()).args(["profile", "add", "g", "--name", "G"]).assert().success();
    // add a default (zero-guid) key
    paksmith(cfg.path()).args(["profile", "key", "add", "g", "--key", KEY]).assert().success();
    // show redacts by default
    let red = paksmith(cfg.path()).args(["profile", "show", "g"]).assert().success();
    let rtxt = String::from_utf8(red.get_output().stdout.clone()).unwrap();
    assert!(rtxt.contains("<redacted>"), "default show redacts: {rtxt}");
    assert!(!rtxt.contains(KEY), "default show must not leak the key: {rtxt}");
    // --show-keys reveals
    let rev = paksmith(cfg.path()).args(["profile", "show", "g", "--show-keys"]).assert().success();
    let vtxt = String::from_utf8(rev.get_output().stdout.clone()).unwrap();
    assert!(vtxt.contains(KEY), "--show-keys reveals: {vtxt}");
}

#[test]
fn profile_test_reports_verified_for_correct_key() {
    let cfg = tempdir().unwrap();
    paksmith(cfg.path()).args(["profile", "add", "g", "--name", "G"]).assert().success();
    paksmith(cfg.path()).args(["profile", "key", "add", "g", "--key", KEY]).assert().success();
    let out = paksmith(cfg.path())
        .args(["profile", "test", "g"])
        .arg(fixture("real_v8b_encrypted_index.pak"))
        .assert()
        .success();
    let txt = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(txt.to_lowercase().contains("verified"), "correct key reports verified: {txt}");
}

#[test]
fn key_add_bad_hex_exits_2() {
    let cfg = tempdir().unwrap();
    paksmith(cfg.path()).args(["profile", "add", "g", "--name", "G"]).assert().success();
    paksmith(cfg.path()).args(["profile", "key", "add", "g", "--key", "nothex"]).assert().code(2);
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p paksmith-cli --test profile_cli 2>&1 | tail -15`
Expected: FAIL — `key` / `test` subcommands don't exist.

- [ ] **Step 3: Implement** — in `profile.rs`, add the variants + args + handlers:

```rust
#[derive(Subcommand)]
pub(crate) enum KeyCmd {
    /// Add (or replace) a key for a GUID
    Add(KeyAddArgs),
    /// Remove a key by GUID
    Remove(KeyRemoveArgs),
}

#[derive(Args)]
pub(crate) struct KeyAddArgs {
    /// Profile id
    pub(crate) id: String,
    /// AES-256 key, 64 hex chars (optional 0x prefix)
    #[arg(long)]
    pub(crate) key: String,
    /// Encryption-key GUID, 32 hex chars. Defaults to the all-zero default.
    #[arg(long)]
    pub(crate) guid: Option<String>,
}

#[derive(Args)]
pub(crate) struct KeyRemoveArgs {
    /// Profile id
    pub(crate) id: String,
    /// Encryption-key GUID, 32 hex chars
    #[arg(long)]
    pub(crate) guid: String,
}

#[derive(Args)]
pub(crate) struct TestArgs {
    /// Profile id
    pub(crate) id: String,
    /// Pak to test the resolved key against
    pub(crate) pak: std::path::PathBuf,
}
```

Add `Key(KeyCmd)` and `Test(TestArgs)` to `ProfileCmd`, and dispatch them in `run`. Handlers:

```rust
fn key_add(a: &KeyAddArgs) -> paksmith_core::Result<u8> {
    use paksmith_core::{AesKey, KeyGuid};
    let key = AesKey::from_hex(&a.key).map_err(|e| PaksmithError::InvalidArgument {
        arg: "--key",
        reason: e.to_string(),
    })?;
    let guid = match &a.guid {
        Some(g) => KeyGuid::from_hex(g).map_err(|e| PaksmithError::InvalidArgument {
            arg: "--guid",
            reason: e.to_string(),
        })?,
        None => KeyGuid::ZERO,
    };
    let mut store = ProfileStore::load()?;
    let p = store.profiles.get_mut(&a.id).ok_or_else(|| PaksmithError::Profile {
        fault: ProfileFault::ProfileNotFound { id: a.id.clone() },
    })?;
    p.keys.insert(guid, key);
    store.save()?;
    println!("added key for GUID {} to `{}`", guid.to_hex(), a.id);
    Ok(0)
}

fn key_remove(a: &KeyRemoveArgs) -> paksmith_core::Result<u8> {
    use paksmith_core::KeyGuid;
    let guid = KeyGuid::from_hex(&a.guid).map_err(|e| PaksmithError::InvalidArgument {
        arg: "--guid",
        reason: e.to_string(),
    })?;
    let mut store = ProfileStore::load()?;
    let p = store.profiles.get_mut(&a.id).ok_or_else(|| PaksmithError::Profile {
        fault: ProfileFault::ProfileNotFound { id: a.id.clone() },
    })?;
    if p.keys.remove(&guid).is_none() {
        return Err(PaksmithError::Profile {
            fault: ProfileFault::NoKeyForGuid { id: a.id.clone(), guid: guid.to_hex() },
        });
    }
    store.save()?;
    println!("removed key for GUID {} from `{}`", guid.to_hex(), a.id);
    Ok(0)
}

fn test(a: &TestArgs) -> paksmith_core::Result<u8> {
    use paksmith_core::container::pak::PakReader;
    use paksmith_core::profile::key_test::{test_key, KeyTestOutcome};
    use paksmith_core::profile::resolve_key;
    let store = ProfileStore::load()?;
    let p = store.profiles.get(&a.id).ok_or_else(|| PaksmithError::Profile {
        fault: ProfileFault::ProfileNotFound { id: a.id.clone() },
    })?;
    let guid = PakReader::read_footer_guid(&a.pak)?;
    let key = resolve_key(p, guid.as_ref()).ok_or_else(|| PaksmithError::Profile {
        fault: ProfileFault::NoKeyForGuid {
            id: a.id.clone(),
            guid: guid.map(|g| KeyGuid::from_bytes(g).to_hex()).unwrap_or_else(|| "default".into()),
        },
    })?;
    let outcome = test_key(&a.pak, key);
    let label = match outcome {
        KeyTestOutcome::Verified => "verified",
        KeyTestOutcome::Decrypted => "decrypted (no index hash to verify)",
        KeyTestOutcome::WrongKey => "wrong key",
        KeyTestOutcome::Unsupported => "unsupported pak layout (key may be correct)",
    };
    println!("{}: {label}", a.id);
    // exit 1 if the key didn't work, 0 if it did
    Ok(u8::from(!matches!(outcome, KeyTestOutcome::Verified | KeyTestOutcome::Decrypted)))
}
```

Add the needed `use` for `KeyGuid` at the top of `profile.rs` (`use paksmith_core::KeyGuid;`).

- [ ] **Step 4: Run tests** — `cargo test -p paksmith-cli --test profile_cli 2>&1 | tail -15` (all PASS).

- [ ] **Step 5: Commit**

```bash
git add crates/paksmith-cli
git commit -m "feat(cli): add profile key add/remove + profile test"
```

---

### Task 7: `--game` global flag + shared key resolution

Wire `--game <id>` into the four container commands via one shared resolver. `--aes-key` wins on conflict.

**Files:**
- Create: `crates/paksmith-cli/src/commands/key_resolve.rs`
- Modify: `crates/paksmith-cli/src/main.rs` (`--game` flag; pass `game` through `Command::run`)
- Modify: `crates/paksmith-cli/src/commands/mod.rs` (thread `game: Option<&str>` into each command `run`)
- Modify: `crates/paksmith-cli/src/commands/{list,inspect,extract,search}.rs` (use the resolver)

**Interfaces:**
- Consumes: `AesKey`, `ProfileStore`, `resolve_key`, `PakReader::read_footer_guid`, `ProfileFault`.
- Produces: `pub(crate) fn resolve_pak_key(path: &Path, aes_key: Option<&AesKey>, game: Option<&str>) -> paksmith_core::Result<Option<AesKey>>` — if `aes_key` is `Some`, returns a clone of it (precedence, with a `debug!` when `game` is also set); else if `game` is `Some`, loads the store + profile (unknown id → `ProfileNotFound`), reads the pak's footer GUID, `resolve_key` (miss → `NoKeyForGuid`), returns the cloned key; else `None`.

- [ ] **Step 1: Write the failing CLI test** — append to `crates/paksmith-cli/tests/profile_cli.rs`:

```rust
#[test]
fn game_flag_opens_encrypted_pak_via_profile() {
    let cfg = tempdir().unwrap();
    paksmith(cfg.path()).args(["profile", "add", "g", "--name", "G"]).assert().success();
    paksmith(cfg.path()).args(["profile", "key", "add", "g", "--key", KEY]).assert().success();
    // --game resolves the key and `list` succeeds on the encrypted-index fixture
    let out = paksmith(cfg.path())
        .args(["--game", "g", "list"])
        .arg(fixture("real_v8b_encrypted_index.pak"))
        .assert()
        .success();
    let txt = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(txt.contains("test.txt"), "encrypted entries listed via --game: {txt}");
}

#[test]
fn game_unknown_profile_exits_2() {
    let cfg = tempdir().unwrap();
    paksmith(cfg.path())
        .args(["--game", "nope", "list"])
        .arg(fixture("real_v8b_encrypted_index.pak"))
        .assert()
        .code(2);
}

#[test]
fn aes_key_overrides_game() {
    let cfg = tempdir().unwrap();
    // profile `g` has the WRONG key; --aes-key supplies the RIGHT one and wins.
    paksmith(cfg.path()).args(["profile", "add", "g", "--name", "G"]).assert().success();
    paksmith(cfg.path()).args(["profile", "key", "add", "g", "--key", &"00".repeat(32)]).assert().success();
    paksmith(cfg.path())
        .args(["--game", "g", "--aes-key", KEY, "list"])
        .arg(fixture("real_v8b_encrypted_index.pak"))
        .assert()
        .success();
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p paksmith-cli --test profile_cli 2>&1 | tail -15`
Expected: FAIL — no `--game` flag (clap rejects the unknown arg → exit 2 for the wrong reason; the `success()` assertions fail).

- [ ] **Step 3: Implement the resolver** — create `crates/paksmith-cli/src/commands/key_resolve.rs`:

```rust
use std::path::Path;

use paksmith_core::container::pak::PakReader;
use paksmith_core::error::ProfileFault;
use paksmith_core::profile::resolve_key;
use paksmith_core::{AesKey, KeyGuid, PaksmithError, ProfileStore};

/// Resolve the AES key for a pak from `--aes-key` (wins) or `--game` (profile
/// lookup via the pak's footer GUID). Returns `None` when neither is set.
pub(crate) fn resolve_pak_key(
    path: &Path,
    aes_key: Option<&AesKey>,
    game: Option<&str>,
) -> paksmith_core::Result<Option<AesKey>> {
    if let Some(k) = aes_key {
        if game.is_some() {
            tracing::debug!("--aes-key overrides --game");
        }
        return Ok(Some(k.clone()));
    }
    let Some(id) = game else { return Ok(None) };
    let store = ProfileStore::load()?;
    let profile = store.profiles.get(id).ok_or_else(|| PaksmithError::Profile {
        fault: ProfileFault::ProfileNotFound { id: id.to_string() },
    })?;
    let guid = PakReader::read_footer_guid(path)?;
    let key = resolve_key(profile, guid.as_ref()).ok_or_else(|| PaksmithError::Profile {
        fault: ProfileFault::NoKeyForGuid {
            id: id.to_string(),
            guid: guid.map(|g| KeyGuid::from_bytes(g).to_hex()).unwrap_or_else(|| "default".into()),
        },
    })?;
    Ok(Some(key.clone()))
}
```

Register `pub(crate) mod key_resolve;` in `commands/mod.rs`.

- [ ] **Step 4: Add the `--game` flag + thread it** — in `main.rs`, add to `struct Cli` (sibling of `aes_key`):

```rust
    /// Resolve the AES key from a stored profile id (see `paksmith profile`).
    /// Ignored if `--aes-key` is also given (explicit key wins).
    #[arg(long, global = true, value_name = "ID")]
    game: Option<String>,
```

Change `Command::run` (in `commands/mod.rs`) to `run(&self, format, aes_key: Option<&AesKey>, game: Option<&str>)`, threading both into each container command's `run` (the `Profile` arm ignores them). In `main`, update the dispatch:

```rust
    let result = cli
        .aes_key
        .as_deref()
        .map(parse_aes_key)
        .transpose()
        .and_then(|key| cli.command.run(cli.format, key.as_ref(), cli.game.as_deref()));
```

- [ ] **Step 5: Use the resolver in each container command** — change each of `list/inspect/extract/search` `run` to take `aes_key: Option<&AesKey>, game: Option<&str>` and replace the `match key { ... }` open with:

```rust
    let resolved = crate::commands::key_resolve::resolve_pak_key(&args.path, aes_key, game)?;
    let reader = match &resolved {
        Some(k) => PakReader::open_with_key(&args.path, k.clone())?,
        None => PakReader::open(&args.path)?,
    };
```

(For `extract`/`search`/`inspect` use their path field name — `args.pak` — and their existing `Arc::new(...)` / `read_from_reader` wrapping. `inspect` keeps its 5a `Arc<PakReader>` + `read_from_reader` shape; just swap how the key is obtained.) Update the `mod.rs` dispatch arms to pass `aes_key, game` (e.g. `Self::List(args) => list::run(args, format, aes_key, game).map(|()| 0)`).

- [ ] **Step 6: Run tests** — `cargo test -p paksmith-cli --all-features 2>&1 | tail -20` (the new `--game` tests + ALL existing CLI tests, including 5a's `--aes-key` ones, PASS — the `--aes-key`-only path still works because `resolve_pak_key` returns it directly).

- [ ] **Step 7: Commit**

```bash
git add crates/paksmith-cli
git commit -m "feat(cli): add global --game flag resolving keys from profiles"
```

---

### Task 8: ROADMAP note + full gate chain

**Files:**
- Modify: `docs/plans/ROADMAP.md`

- [ ] **Step 1: ROADMAP** — in `docs/plans/ROADMAP.md`'s Phase 5 status block, note that **5b (local game profiles + AES key management + `--game` resolution)** has shipped, and that 5c (remote registry) and 5d (auto-detection) remain planned. Factual, brief, no engine-source references.

- [ ] **Step 2: Full gate chain** — run each UNPIPED; fix any failure in-scope:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
typos .
cargo deny check
```

Confirm the new `toml` + `dirs` deps pass `cargo deny` (licenses/bans/sources) and `Minimal versions` (set version floors that actually resolve — `toml = "0.8"`, `dirs = "5"`; bump if minimal-versions rejects a too-loose floor). MSRV: `cargo +1.88 check -p paksmith-core -p paksmith-cli` if installed.

- [ ] **Step 3: Verify the fixture-count gate is untouched** — 5b adds NO `.pak` fixtures; confirm `find tests/fixtures -maxdepth 1 -name '*.pak' | wc -l` is unchanged from the count `.github/workflows/ci.yml` expects.

- [ ] **Step 4: Commit**

```bash
git add docs/plans/ROADMAP.md
git commit -m "docs(roadmap): mark phase 5b (profiles + key management) shipped"
```

---

## Review & Push

- Adversarial whole-branch panel with **mandatory security specialist** (secrets-at-rest: `0600` + redaction + no-key-in-logs/Debug; the `to_hex`/`key_hex` reveal paths; `PAKSMITH_CONFIG_DIR` handling; untrusted `profiles.toml` parsing) + code-reviewer + architect + simplifier. Add a **deep-impact tracer** (the `Command::run` signature change ripples to all 4 commands + the `read_footer_guid` extraction touches the open path).
- Cycle to convergence; re-dispatch the full panel after each fix commit.
- Touch the convergence marker (separate Bash call), push, open PR (`gh --body-file`), Monitor CI to green (watch **Minimal versions** + **cargo-deny** for the new deps, and **cargo-mutants** for accessor/boundary gaps in the new code). Do NOT merge — the user merges.

---

## Self-Review (plan vs spec)

**Spec coverage:**
- guid→key map + zero-GUID default → Task 2 (`resolve_key`). ✓
- TOML store, `<config_dir>/paksmith/profiles.toml`, `PAKSMITH_CONFIG_DIR`, atomic + `0600` → Task 3. ✓
- key-testing (try-decrypt + verify) → Task 4 (`test_key`). ✓
- profile CRUD CLI → Tasks 5–6. ✓
- `--game` resolution across all 4 commands, `--aes-key` precedence → Task 7. ✓
- `show` redaction default + `--show-keys` → Tasks 5–6. ✓
- `AesKey` non-`Serialize`, serialization via crate-internal `to_hex`, single public reveal `key_hex` → Tasks 1, 2, 5. ✓
- `ProfileFault` + `PaksmithError::Profile` → Task 3. ✓
- no new `.pak` fixtures (reuse 5a) → Tasks 4–7 + Task 8 gate check. ✓
- deps `toml` + `dirs`, no `reqwest` → Tasks 2, 3. ✓
- engine_version field → Task 2. ✓

**Type consistency:** `AesKey::from_hex`/`to_hex`/`AesKeyHexError` (T1); `KeyGuid::{ZERO,from_bytes,as_bytes,to_hex,from_hex}` (T2); `GameProfile { name, engine_version, keys }` (no id field — map key is id) (T2); `resolve_key(&GameProfile, Option<&[u8;16]>) -> Option<&AesKey>` (T2/6/7); `ProfileStore::{config_path,load,save,load_from,save_to}` (T3); `ProfileFault::{NoConfigDir,CorruptStore,Io,ProfileNotFound,NoKeyForGuid,MalformedKey}` (T3); `PakReader::read_footer_guid -> Result<Option<[u8;16]>>` (T4); `test_key -> KeyTestOutcome{Verified,Decrypted,WrongKey,Unsupported}` (T4); `profile::key_hex(&AesKey) -> String` (T5); `resolve_pak_key(&Path, Option<&AesKey>, Option<&str>)` (T7) — referenced identically across tasks.

**Open implementation points (resolve against live code, each has a crisp deliverable + test):**
- `read_footer_only` extraction vs inline footer read in `read_footer_guid` (T4) — either is fine; NO index parse/decrypt.
- `toml::de::Error::message()` vs `to_string()` (T3) — use whichever the resolved `toml` 0.8 exposes.
- `VerifyOutcome` variant names / `verify_index` return type (T4) — adapt the match to the live 5a API; contract is Verified / SkippedNoHash / wrong-key.
- Each container command's path field name (`path` vs `pak`) and its `Arc`/`read_from_reader` wrapping (T7) — preserve the 5a shape, swap only key acquisition.
