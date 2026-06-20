# Phase 5b — Game Profiles + AES Key Management Design

**Status:** approved (brainstorming), pre-implementation
**Date:** 2026-06-19
**Roadmap:** Phase 5 (Game Profiles) — sub-phase 5b (local profiles + key management)

## Context

Phase 5 (Game Profiles) decomposes into **5a AES decryption → 5b profiles +
key management → 5c registry (async/network) → 5d auto-detection**, each its
own spec → plan → cycle. This document specifies **5b only**.

5a shipped the decryption primitive: `paksmith_core::AesKey`,
`PakReader::open_with_key`, and a global `--aes-key <hex>` CLI flag. Today a
user must paste a 64-hex key on every command. 5b makes keys **persistent and
named**: a local profile store maps games to their AES keys, paksmith resolves
the right key from the pak's encryption-key GUID, and a `--game <id>` flag
replaces `--aes-key` for stored games.

5a already parses the pak's encryption-key GUID:
`footer.encryption_key_guid() -> Option<&[u8; 16]>` (present in v7+/UE4.22+
archives). 5b uses this to pick the exact key from a profile's guid→key map —
no reader changes required.

## Goals / non-goals

- **Goal:** a local, persistent, named key store (game profiles) with
  guid→key resolution, key-testing, a `paksmith profile ...` management CLI,
  and a global `--game <id>` flag that resolves a stored key into the existing
  `open_with_key` path across all four container commands.
- **Non-goal:** any network/registry fetch (5c), auto-detection of a game from
  a directory (5d), key *cracking*/brute-force, IoStore (.utoc/.ucas) keys
  (Phase 8). No GUI (Phase 6).

## Key facts (from 5a + the codebase)

- `footer.encryption_key_guid()` returns `Option<&[u8; 16]>`. The **all-zero
  GUID** is the UE convention for the "default" encryption key; pre-4.22 paks
  and single-key paks use it.
- `PakReader::open_with_key(path, AesKey)` decrypts + parses; wrong key →
  `PaksmithError::Decryption`. `PakReader::verify_index()` confirms the index
  SHA-1 over the decrypted plaintext (the 5a decrypt-before-hash path).
- `AesKey` is `ZeroizeOnDrop`, redacted `Debug`, no `Display`, re-exported as
  `paksmith_core::AesKey`. The CLI's `parse_aes_key` (64 hex, optional `0x`,
  case-insensitive) is the existing hex decoder.

## Data model

```rust
/// 16-byte encryption-key GUID. All-zero = the default key.
pub struct KeyGuid([u8; 16]);

/// One game's stored keys + light metadata. The profile's **id is the
/// `ProfileStore` map key**, not a struct field — single source of truth,
/// and it matches the TOML `[profiles.<id>]` table name (no `id =` line).
pub struct GameProfile {
    pub name: String,                  // display name
    pub engine_version: Option<String>,// e.g. "5.3"; feeds 5d + the UE5.2/5.3 texture gap
    pub keys: BTreeMap<KeyGuid, AesKey>,// guid → key
}

/// The whole on-disk document.
pub struct ProfileStore {
    pub profiles: BTreeMap<String, GameProfile>,  // id → profile
}
```

- **Resolution:** `resolve_key(profile, pak_guid: Option<&[u8;16]>) ->
  Option<&AesKey>` — an exact GUID hit returns that key; a pak with no GUID or
  the all-zero GUID returns the zero-GUID default key; a miss returns `None`.
- `BTreeMap` (not `HashMap`) for deterministic TOML output + stable test
  snapshots.

## Storage

- One TOML file at `<config_dir>/paksmith/profiles.toml`, where `config_dir`
  comes from the `dirs` crate (XDG / AppData / Library). Keys hex-encoded.
- **`PAKSMITH_CONFIG_DIR` environment variable overrides** the base dir (powers
  tests + private/portable setups). When set, it is used verbatim.
- On write: create the dir if missing, write atomically (temp file + rename),
  set `0600` permissions on unix (best-effort / documented no-op elsewhere).
- TOML shape:

```toml
[profiles.fortnite]
name = "Fortnite"
engine_version = "5.3"

[profiles.fortnite.keys]
"00000000000000000000000000000000" = "0x94d25bc3...a7de"   # default key
"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6" = "0x3c1e..."           # a dynamic key
```

## Architecture

```
crates/paksmith-core/src/profile/mod.rs        # CREATE: KeyGuid, GameProfile, ProfileStore, resolve_key
crates/paksmith-core/src/profile/store.rs      # CREATE: TOML load/save, atomic+0600 write, hex codec, errors
crates/paksmith-core/src/profile/key_test.rs   # CREATE: test_key(pak, key) -> KeyTestOutcome (open_with_key + verify_index)
crates/paksmith-core/src/lib.rs                # MODIFY: register `profile` module + re-exports
crates/paksmith-core/Cargo.toml                # MODIFY: add toml, dirs
crates/paksmith-cli/src/main.rs                # MODIFY: global --game flag + key resolution
crates/paksmith-cli/src/commands/profile.rs    # CREATE: `profile` subcommand (list/show/add/remove/key/test)
crates/paksmith-cli/src/commands/{list,inspect,extract,search}.rs  # MODIFY: accept a resolved key from --game
```

Core is load-bearing (profile model, store I/O, resolution, key-test); the CLI
is a thin presentation layer (argument parsing + the `profile` command +
`--game` wiring). The hex codec currently in `paksmith-cli`'s `parse_aes_key`
is lifted to a shared core helper (e.g. `AesKey::from_hex(&str)`) so both the
CLI flag and the TOML loader decode keys through one tested path.

### Component 1 — `profile/mod.rs` (pure model + resolution)

`KeyGuid` (with hex parse/format, `Ord` for the BTreeMap, a `ZERO`
constant/`is_zero`), `GameProfile`, `ProfileStore`, and the pure
`resolve_key` function. serde derives drive TOML (custom ser/de for `KeyGuid`
as a 32-hex string and `AesKey` as a hex string — `AesKey` itself stays
non-`Serialize` to avoid accidental key leakage elsewhere; serialization lives
in the profile module's de/ser adapters).

### Component 2 — `profile/store.rs` (disk I/O)

`ProfileStore::load() -> Result<ProfileStore>` (missing file → empty store,
not an error; corrupt TOML → typed `ProfileError::Corrupt`), `save(&self)`
(atomic temp+rename, `0600` on unix), and `config_path()` honoring
`PAKSMITH_CONFIG_DIR`. Hex decode/encode for keys + GUIDs, returning typed
errors on malformed input.

### Component 3 — `profile/key_test.rs`

`test_key(pak_path, &AesKey) -> Result<KeyTestOutcome>` where `KeyTestOutcome`
is `Verified` / `Decrypted` (opened but no index hash to verify) /
`WrongKey` / `Unsupported`. Implemented via `open_with_key` then
`verify_index`. The 5a vendored encrypted fixtures
(`real_v8b_encrypted_index.pak` + `FIXTURE_AES_KEY`) are the oracle.

### Component 4 — CLI `profile` command + `--game`

```
paksmith profile list                                  # id, name, engine, key-count
paksmith profile show <id> [--show-keys]               # keys REDACTED by default; --show-keys reveals hex
paksmith profile add <id> --name <name> [--engine-version <v>]
paksmith profile remove <id>
paksmith profile key add <id> --key <hex> [--guid <hex>]   # guid defaults to all-zero (the default key)
paksmith profile key remove <id> --guid <hex>
paksmith profile test <id> <pak>                       # resolve via the pak's GUID, try-decrypt + verify, report
```

`--game <id>` is a `#[arg(long, global = true)]` flag (sibling of `--aes-key`).
Resolution in `main`: load the store → load profile `<id>` (unknown id →
`InvalidArgument`, exit 2) → open enough of the pak to read
`encryption_key_guid()` → `resolve_key` → pass the resolved `AesKey` into the
command's existing key-aware open path.

**Precedence:** if both `--aes-key` and `--game` are supplied, **`--aes-key`
wins** (an explicit key overrides the stored profile), with a `debug!` noting
the override. `--game` on an unencrypted pak is harmless (key unused). A
profile that has no key for the pak's GUID → a clear error naming the id + the
GUID hex.

A subtlety: the four commands already open the pak with `open_with_key`. To
read the GUID for resolution, `main` needs the pak path before dispatch.
Resolve at implementation against the live command structs — either (a) a tiny
core helper `PakReader::read_footer_guid(path) -> Result<Option<[u8;16]>>` that
reads just the footer, or (b) resolve the key inside each command after the
pak is opened (open once, read guid, look up, re-key). Option (a) keeps `main`
the single resolution site and avoids a double open; prefer it unless the
command structure makes (b) cleaner.

## Error handling / exit codes

- A new `PaksmithError::Profile { fault: ProfileFault }` variant carrying a
  typed `ProfileFault` sub-enum (matching the existing `IndexParseFault` /
  `DecompressionFault` pattern) for: corrupt store, profile-not-found,
  key-for-guid-not-found, malformed hex (key/guid), store I/O. Wire-stable
  `Display` per variant.
- No key material in any error/log/Debug. `profile show` redacts by default.
- CLI: bad hex / unknown id / unknown guid → `InvalidArgument` (exit 2); other
  errors exit 1; existing 0/2/BrokenPipe discipline unchanged.

## Security

- AES keys are secrets. Stored plaintext-hex in `profiles.toml` with `0600`
  perms (unix) — the standard for local extractor tools (FModel/CUE4Parse).
  Not encrypted at rest; documented. No OS keychain in 5b.
- `AesKey` keeps zeroize-on-drop + redacted Debug; `show` redacts unless
  `--show-keys`; keys never logged.
- `PAKSMITH_CONFIG_DIR` is read from the environment; the resolved path is used
  for store I/O only (no command execution, no traversal beyond joining the
  fixed `paksmith/profiles.toml` tail).
- Untrusted `profiles.toml` (user-editable): parse defensively — malformed hex,
  wrong-length GUID/key, unknown fields → typed errors, never panic.

## Testing

- **Unit (core):** `KeyGuid` hex round-trip + zero detection; `GameProfile` /
  `ProfileStore` TOML round-trip (BTreeMap → deterministic output);
  `resolve_key` (exact GUID hit, zero-GUID default, miss → None); `store`
  load-missing → empty, save→load fidelity, `0600` perms on unix, corrupt-TOML
  → typed error; `test_key` against the 5a vendored fixtures (correct key →
  `Verified`; wrong key → `WrongKey`).
- **CLI:** `profile add/list/show/remove`, `key add/remove`, `profile test`
  end-to-end against a temp `PAKSMITH_CONFIG_DIR`; `show` redaction default +
  `--show-keys`; `--game` resolves the key and `list` lists the encrypted
  fixture's entries; `--game` + `--aes-key` precedence; unknown profile /
  unknown GUID exit codes; bad-hex on `key add` → exit 2.
- Reuses the 5a encrypted fixtures — **no new `.pak` fixtures**, so the CI
  fixture-count gate is untouched.

## Build notes / open implementation points

- The hex codec: lift `parse_aes_key`'s decode into a core `AesKey::from_hex`
  (+ a `to_hex` used only by the profile serializer, kept `pub(crate)` or
  behind the profile module to avoid a general key-stringify foot-gun). The CLI
  flag then calls the core helper.
- GUID read for `--game`: prefer the thin `read_footer_guid(path)` core helper
  (single resolution site in `main`, no double open). Confirm against the live
  footer reader at implementation.
- `dirs` vs `directories` crate: use `dirs` (smaller, the ROADMAP's choice).
  Confirm cargo-deny licenses at implementation.
- Windows `0600`: `std::fs` perms differ; document best-effort (the file lands
  in the user's AppData, already user-scoped).

## Scope boundary

5b ships local, named, persistent key management end-to-end (`--game` resolves
a stored key via the pak's GUID). The remote registry + caching (5c) and
auto-detection from a directory (5d) are out of scope and get their own
spec → plan → cycle.
