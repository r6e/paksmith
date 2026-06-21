# Phase 5d — Game Auto-Detection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Identify the game for a directory via declarative marker-path + file-content rules stored on profiles, exposed as `paksmith profile detect <dir>` and a `--detect <dir>` resolution flag. Completes Phase 5.

**Architecture:** A new `paksmith-core/src/profile/detection.rs` holds `DetectRules`/`ContainsRule` + a read-only, path-traversal-guarded, size-capped matcher (`rules_match`). `GameProfile` and `RegistryProfile` gain an optional `detect` field (so the registry ships rules). The CLI gets a `profile detect <dir>` query (lists all matches) and a global `--detect <dir>` flag that resolves the single detected game's key through the existing 5b/5c `--game` resolution.

**Tech Stack:** Rust 2024 (MSRV 1.88), `std::fs` only (no new deps), `serde`/`toml`/`serde_json`. Builds on 5b (`GameProfile`/`ProfileStore`/`resolve_within`) + 5c (`RegistryProfile`/`validate_caps`/`RegistryCache`/`load_cache_lenient`/`resolve_profile_layered`/`resolve_pak_key`).

## Global Constraints

- MSRV 1.88; edition 2024; **no new dependencies**. No panics in `paksmith-core` — `Result`/`Option` everywhere. `thiserror` + wire-stable `Display`; `tracing` (no `println!` in core; CLI prints user output).
- **Detection reads the filesystem at a user/registry-supplied path — security is mandatory:** rule paths (`require_paths`, `contains.path`) are **relative**; reject absolute, root, drive-prefix, or any `..` parent component (a malicious registry rule must not read outside the target dir). An invalid-path rule **fails to match** (it does not error detection, never escapes the dir). `contains` reads are bounded to `MAX_CONTAINS_READ = 1 MiB` (no multi-GB slurp), read-only. A profile with **no** rules is **never** auto-detected.
- **Match = logical AND:** a profile matches iff ALL `require_paths` exist (file OR dir) AND ALL `contains` rules pass.
- **Untrusted-registry parse caps (extend 5c `validate_caps`):** cap the `detect` field on the fetch + cache-load paths — `require_paths.len() ≤ MAX_REQUIRE_PATHS`, `contains.len() ≤ MAX_CONTAINS`, each path/substring `≤ MAX_STR` (256).
- **`detect` field is additive + optional:** `#[serde(default, skip_serializing_if = "Option::is_none")]` so existing `profiles.toml` / registry JSON round-trip unchanged.
- **Precedence:** `--aes-key` > `--game` > `--detect` (explicit beats auto). Ambiguous detection (0 or >1 matches) errors for resolution; the `detect` query lists all (0/1/many) and exits 0.
- No AES key material in any detection error/log. Conventional commits; one logical change per commit. Run `cargo fmt --all` + `cargo fmt --all --check` (verify exit 0), `clippy --workspace --all-targets --all-features -D warnings`, `test --workspace --all-features`, `doc -D warnings`, `typos` before declaring a task done. Do NOT bump any `Cargo.toml` `version =`.
- Before the final push: `cargo mutants --in-diff $(git merge-base origin/main HEAD)..HEAD --all-features` → 0 missed (the PR-diff job is not in the local gate chain).

## File Structure

- `crates/paksmith-core/src/profile/detection.rs` — CREATE: `DetectRules`/`ContainsRule`, caps, `safe_join`, `rules_match`.
- `crates/paksmith-core/src/profile/mod.rs` — MODIFY: `GameProfile` gains `detect`; register `pub mod detection`; re-export the new types.
- `crates/paksmith-core/src/profile/registry.rs` — MODIFY: `RegistryProfile` gains `detect`; `validate_caps` covers it.
- `crates/paksmith-core/src/error.rs` — MODIFY: `ProfileFault::{DetectionNoMatch, DetectionAmbiguous}`.
- `crates/paksmith-cli/src/commands/detect.rs` — CREATE: the `profile detect` handler + a shared `detect_matches` helper (over local + cached profiles).
- `crates/paksmith-cli/src/commands/profile.rs` — MODIFY: add the `Detect` subcommand.
- `crates/paksmith-cli/src/commands/key_resolve.rs` — MODIFY: `--detect` → detected id → existing resolution.
- `crates/paksmith-cli/src/commands/mod.rs` + `crates/paksmith-cli/src/main.rs` — MODIFY: `--detect` global flag threaded through `Command::run`.
- `docs/plans/ROADMAP.md` — MODIFY (final task): mark 5d shipped / Phase 5 complete.

---

### Task 1: Detection schema (`DetectRules`) + `detect` field on both profiles

**Files:**
- Create: `crates/paksmith-core/src/profile/detection.rs`
- Modify: `crates/paksmith-core/src/profile/mod.rs` (GameProfile.detect + `pub mod detection` + re-exports)
- Modify: `crates/paksmith-core/src/profile/registry.rs` (RegistryProfile.detect)

**Interfaces:**
- Produces: `pub struct DetectRules { pub require_paths: Vec<String>, pub contains: Vec<ContainsRule> }` (`Serialize, Deserialize, Clone, Debug, Default`, `#[serde(deny_unknown_fields)]`); `pub struct ContainsRule { pub path: String, pub substring: String }` (same derives + deny_unknown_fields). Caps: `pub(crate) const MAX_REQUIRE_PATHS: usize = 64; pub(crate) const MAX_CONTAINS: usize = 64; pub(crate) const MAX_CONTAINS_READ: usize = 1024 * 1024;`. `GameProfile`/`RegistryProfile` gain `pub detect: Option<DetectRules>`.

- [ ] **Step 1: Write the failing test** — create `detection.rs` with only a test module first:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::GameProfile;

    #[test]
    fn detect_rules_toml_roundtrip() {
        let mut p = GameProfile::default();
        p.name = "G".into();
        p.detect = Some(DetectRules {
            require_paths: vec!["Game/Content/Paks".into()],
            contains: vec![ContainsRule { path: "Game/Game.uproject".into(), substring: "Game".into() }],
        });
        let text = toml::to_string_pretty(&p).unwrap();
        assert!(text.contains("require_paths"));
        let back: GameProfile = toml::from_str(&text).unwrap();
        let d = back.detect.unwrap();
        assert_eq!(d.require_paths, vec!["Game/Content/Paks".to_string()]);
        assert_eq!(d.contains[0].substring, "Game");
    }

    #[test]
    fn absent_detect_is_omitted_from_toml() {
        let p = GameProfile { name: "G".into(), engine_version: None, keys: Default::default(), detect: None };
        let text = toml::to_string_pretty(&p).unwrap();
        assert!(!text.contains("detect"), "absent detect must not serialize: {text}");
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p paksmith-core --all-features profile::detection 2>&1 | tail -12`
Expected: FAIL — `DetectRules`/`ContainsRule` not found; `GameProfile` has no `detect` field.

- [ ] **Step 3: Implement the schema** — prepend to `detection.rs`:

```rust
//! Declarative game auto-detection: rules stored on a profile that recognise a
//! game's install directory. Read-only, path-traversal-guarded, size-capped.
//! Network registry (5c) ships these rules so detection works for known games.

use serde::{Deserialize, Serialize};

/// Maximum number of `require_paths` / `contains` rules accepted from the
/// untrusted registry (enforced by `validate_caps`).
pub(crate) const MAX_REQUIRE_PATHS: usize = 64;
pub(crate) const MAX_CONTAINS: usize = 64;
/// Cap on the bytes read from a `contains` target file before substring search.
pub(crate) const MAX_CONTAINS_READ: usize = 1024 * 1024;

/// Rules that recognise a game's install directory. All present rules must
/// pass (logical AND). A profile with no rules is never auto-detected.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectRules {
    /// Relative paths (file OR dir) that must ALL exist under the target dir.
    #[serde(default)]
    pub require_paths: Vec<String>,
    /// "file contains substring" rules; all must pass.
    #[serde(default)]
    pub contains: Vec<ContainsRule>,
}

/// A single "the file at `path` contains `substring`" rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainsRule {
    /// Relative path to a file under the target dir.
    pub path: String,
    /// Substring the file must contain (within the first `MAX_CONTAINS_READ` bytes).
    pub substring: String,
}
```

- [ ] **Step 4: Add the `detect` field to both profiles.** In `profile/mod.rs`, add `pub mod detection;` and re-export `pub use profile::detection::{DetectRules, ContainsRule};` in `lib.rs`. Add to `GameProfile`:

```rust
    /// Optional auto-detection rules (matched against a game install dir).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detect: Option<detection::DetectRules>,
```

In `registry.rs`, add the same field to `RegistryProfile`:

```rust
    /// Optional auto-detection rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detect: Option<crate::profile::detection::DetectRules>,
```

Update EVERY `GameProfile { .. }` / `RegistryProfile { .. }` struct literal in the codebase (tests + `profile add` in `commands/profile.rs`) to add `detect: None` (grep `GameProfile {` and `RegistryProfile {` — the compiler will list each missing-field site). NOTE: `GameProfile` derives `Default`, so `GameProfile::default()` works in new tests; existing literals need the field.

- [ ] **Step 5: Run tests** — `cargo test -p paksmith-core --all-features profile:: 2>&1 | tail -10` (new detection tests + all existing 5b/5c profile tests pass — confirm the literal updates compile). Add `assert_send_sync::<DetectRules>()` + `<ContainsRule>()` to lib.rs `send_sync_assertions`.

- [ ] **Step 6: Commit**

```bash
git add crates/paksmith-core
git commit -m "feat(profile): add DetectRules schema + optional detect field on profiles"
```

---

### Task 2: `safe_join` + `rules_match` matcher (security core)

**Files:**
- Modify: `crates/paksmith-core/src/profile/detection.rs`

**Interfaces:**
- Produces: `pub fn rules_match(dir: &std::path::Path, rules: &DetectRules) -> bool` (read-only, bounded, traversal-guarded). `fn safe_join(dir, rel) -> Option<PathBuf>` (private; rejects absolute / root / drive-prefix / `..` / empty).

- [ ] **Step 1: Write the failing tests** — add to `detection.rs` tests:

```rust
    use std::path::Path;

    fn write(dir: &Path, rel: &str, body: &[u8]) {
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }

    #[test]
    fn matches_when_all_paths_present() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "Game/Content/Paks/x.pak", b"x");
        std::fs::create_dir_all(d.path().join("Game/Binaries")).unwrap();
        let rules = DetectRules {
            require_paths: vec!["Game/Content/Paks".into(), "Game/Binaries".into()],
            contains: vec![],
        };
        assert!(rules_match(d.path(), &rules));
    }

    #[test]
    fn no_match_when_a_path_missing() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("Game/Content/Paks")).unwrap();
        let rules = DetectRules {
            require_paths: vec!["Game/Content/Paks".into(), "Game/Missing".into()],
            contains: vec![],
        };
        assert!(!rules_match(d.path(), &rules));
    }

    #[test]
    fn contains_rule_passes_and_fails() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "Game/Game.uproject", b"{\"name\":\"FortniteGame\"}");
        let pass = DetectRules { require_paths: vec![], contains: vec![ContainsRule { path: "Game/Game.uproject".into(), substring: "FortniteGame".into() }] };
        assert!(rules_match(d.path(), &pass));
        let fail = DetectRules { require_paths: vec![], contains: vec![ContainsRule { path: "Game/Game.uproject".into(), substring: "NotPresent".into() }] };
        assert!(!rules_match(d.path(), &fail));
        let missing = DetectRules { require_paths: vec![], contains: vec![ContainsRule { path: "Game/Nope".into(), substring: "x".into() }] };
        assert!(!rules_match(d.path(), &missing));
    }

    #[test]
    fn path_traversal_and_absolute_rules_do_not_match_or_escape() {
        let d = tempfile::tempdir().unwrap();
        // a real file OUTSIDE the dir that a traversal rule might try to reach
        let outside = d.path().parent().unwrap().join("secret.txt");
        std::fs::write(&outside, b"top secret").ok();
        for bad in ["../secret.txt", "../../etc/passwd", "/etc/passwd", "", "Game/../../escape"] {
            let rules = DetectRules { require_paths: vec![bad.to_string()], contains: vec![] };
            assert!(!rules_match(d.path(), &rules), "traversal/abs path `{bad}` must not match");
        }
        std::fs::remove_file(&outside).ok();
    }

    #[test]
    fn empty_rules_never_match() {
        let d = tempfile::tempdir().unwrap();
        assert!(!rules_match(d.path(), &DetectRules::default()));
    }

    #[test]
    fn contains_read_is_bounded() {
        let d = tempfile::tempdir().unwrap();
        // substring placed BEYOND the 1 MiB cap → not found.
        let mut body = vec![b'.'; MAX_CONTAINS_READ + 16];
        body.extend_from_slice(b"PAST_CAP");
        write(d.path(), "big.bin", &body);
        let rules = DetectRules { require_paths: vec![], contains: vec![ContainsRule { path: "big.bin".into(), substring: "PAST_CAP".into() }] };
        assert!(!rules_match(d.path(), &rules), "substring beyond the read cap must not match");
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p paksmith-core --all-features profile::detection 2>&1 | tail -12`
Expected: FAIL — `rules_match` not found.

- [ ] **Step 3: Implement** — add to `detection.rs`:

```rust
use std::path::{Component, Path, PathBuf};

/// Join a rule's RELATIVE path onto `dir`, rejecting any escape. Returns `None`
/// for an absolute path, a root/drive prefix, a `..` parent component, or an
/// empty string — such a rule can never match and triggers no FS access on an
/// out-of-bounds path.
fn safe_join(dir: &Path, rel: &str) -> Option<PathBuf> {
    if rel.is_empty() {
        return None;
    }
    let mut out = dir.to_path_buf();
    for comp in Path::new(rel).components() {
        match comp {
            Component::Normal(c) => out.push(c),
            Component::CurDir => {}                                  // "." — harmless
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(out)
}

/// True iff `rules` match the install directory `dir`. Read-only, bounded, and
/// traversal-guarded. A profile with no rules never matches.
pub fn rules_match(dir: &Path, rules: &DetectRules) -> bool {
    if rules.require_paths.is_empty() && rules.contains.is_empty() {
        return false;
    }
    for rel in &rules.require_paths {
        match safe_join(dir, rel) {
            Some(p) if p.exists() => {}
            _ => return false,
        }
    }
    for rule in &rules.contains {
        let Some(p) = safe_join(dir, &rule.path) else {
            return false;
        };
        if !file_contains(&p, &rule.substring) {
            return false;
        }
    }
    true
}

/// Whether the first `MAX_CONTAINS_READ` bytes of `path` contain `needle`.
/// Missing/unreadable file → false. An empty needle is trivially contained.
fn file_contains(path: &Path, needle: &str) -> bool {
    use std::io::Read as _;
    if needle.is_empty() {
        return true;
    }
    let Ok(file) = std::fs::File::open(path) else {
        return false;
    };
    let mut buf = Vec::new();
    if file
        .take(MAX_CONTAINS_READ as u64)
        .read_to_end(&mut buf)
        .is_err()
    {
        return false;
    }
    buf.windows(needle.len()).any(|w| w == needle.as_bytes())
}
```

- [ ] **Step 4: Run tests** — `cargo test -p paksmith-core --all-features profile::detection 2>&1 | tail -12` (all pass, incl. traversal + bounded-read).

- [ ] **Step 5: Commit**

```bash
git add crates/paksmith-core/src/profile/detection.rs
git commit -m "feat(profile): add traversal-guarded, bounded rules_match detection engine"
```

---

### Task 3: Extend `validate_caps` to cover `detect` (untrusted registry)

**Files:**
- Modify: `crates/paksmith-core/src/profile/registry.rs`

**Interfaces:**
- Consumes: `MAX_REQUIRE_PATHS`/`MAX_CONTAINS` (Task 1), `MAX_STR` (5c), the existing `validate_caps`.

- [ ] **Step 1: Write the failing test** — in `registry.rs` tests, add (reuse the `assert_registry_parse_err` helper if present, else `parse_registry(..).is_err()`):

```rust
    #[test]
    fn rejects_too_many_require_paths() {
        let paths: Vec<String> = (0..=crate::profile::detection::MAX_REQUIRE_PATHS)
            .map(|i| format!(r#""p{i}""#)).collect();
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
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p paksmith-core --all-features profile::registry 2>&1 | tail -12`
Expected: FAIL — the oversized-detect cases parse OK (caps not yet enforced).

- [ ] **Step 3: Implement** — in `validate_caps`'s per-profile loop (registry.rs), after the existing key-count check, add:

```rust
        if let Some(d) = &p.detect {
            if d.require_paths.len() > crate::profile::detection::MAX_REQUIRE_PATHS {
                return Err(format!("too many require_paths in `{}`", p.id));
            }
            if d.contains.len() > crate::profile::detection::MAX_CONTAINS {
                return Err(format!("too many contains rules in `{}`", p.id));
            }
            if d.require_paths.iter().any(|s| s.len() > MAX_STR)
                || d.contains.iter().any(|c| c.path.len() > MAX_STR || c.substring.len() > MAX_STR)
            {
                return Err(format!("detect string field exceeds cap in `{}`", p.id));
            }
        }
```

- [ ] **Step 4: Run tests** — `cargo test -p paksmith-core --all-features profile:: 2>&1 | tail -8` (new caps tests + all prior pass).

- [ ] **Step 5: Commit**

```bash
git add crates/paksmith-core/src/profile/registry.rs
git commit -m "feat(profile): cap registry detect rules in validate_caps"
```

---

### Task 4: CLI `profile detect <dir>` + shared `detect_matches` helper

**Files:**
- Create: `crates/paksmith-cli/src/commands/detect.rs`
- Modify: `crates/paksmith-cli/src/commands/profile.rs` (add the `Detect` subcommand + dispatch)
- Modify: `crates/paksmith-cli/src/commands/mod.rs` (`pub(crate) mod detect;`)

**Interfaces:**
- Consumes: `paksmith_core::profile::detection::rules_match`, `ProfileStore`, `RegistryCache` (via `load_cache_lenient` from key_resolve.rs).
- Produces: `pub(crate) struct DetectMatch { pub id: String, pub name: String, pub source: &'static str }`; `pub(crate) fn detect_matches(dir: &Path) -> paksmith_core::Result<Vec<DetectMatch>>` (loads local store + cached registry, runs `rules_match` over every profile WITH detect rules, dedups by id with LOCAL winning, returns all matches); `pub(crate) fn run(dir: &Path) -> paksmith_core::Result<u8>` (the `profile detect` handler).

- [ ] **Step 1: Write the failing CLI test** — create `crates/paksmith-cli/tests/detect_cli.rs`:

```rust
//! Integration tests for `profile detect` + `--detect`.
#![allow(missing_docs)]
use assert_cmd::Command;
use tempfile::tempdir;

fn paksmith(cfg: &std::path::Path) -> Command {
    let mut c = Command::cargo_bin("paksmith").unwrap();
    let _ = c.env("PAKSMITH_CONFIG_DIR", cfg);
    c
}

// Write a local profile with detect rules into the store, the slow way: add the
// profile, then hand-write the detect table into profiles.toml (no add-rule CLI).
fn seed_profile_with_detect(cfg: &std::path::Path, marker: &str) {
    paksmith(cfg).args(["profile", "add", "fortnite", "--name", "Fortnite"]).assert().success();
    let store = cfg.join("paksmith/profiles.toml");
    let mut s = std::fs::read_to_string(&store).unwrap();
    s.push_str(&format!("\n[profiles.fortnite.detect]\nrequire_paths = [\"{marker}\"]\n"));
    std::fs::write(&store, s).unwrap();
}

#[test]
fn detect_lists_matching_local_profile() {
    let cfg = tempdir().unwrap();
    let game = tempdir().unwrap();
    std::fs::create_dir_all(game.path().join("FortniteGame/Content/Paks")).unwrap();
    seed_profile_with_detect(cfg.path(), "FortniteGame/Content/Paks");
    let out = paksmith(cfg.path()).args(["profile", "detect"]).arg(game.path()).assert().success();
    let txt = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(txt.contains("fortnite"), "detect lists the matched id: {txt}");
}

#[test]
fn detect_no_match_is_success_with_message() {
    let cfg = tempdir().unwrap();
    let game = tempdir().unwrap();
    seed_profile_with_detect(cfg.path(), "FortniteGame/Content/Paks"); // marker NOT created in game dir
    let out = paksmith(cfg.path()).args(["profile", "detect"]).arg(game.path()).assert().success();
    let txt = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(txt.to_lowercase().contains("no profiles matched"), "no-match message: {txt}");
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p paksmith-cli --test detect_cli 2>&1 | tail -12`
Expected: FAIL — no `profile detect` subcommand.

- [ ] **Step 3: Implement the helper + handler** — create `crates/paksmith-cli/src/commands/detect.rs`:

```rust
use std::path::Path;

use paksmith_core::profile::detection::rules_match;
use paksmith_core::ProfileStore;

use crate::commands::key_resolve::load_cache_lenient;

/// One profile that matched a directory.
pub(crate) struct DetectMatch {
    pub id: String,
    pub name: String,
    pub source: &'static str, // "local" | "registry"
}

/// Detect which stored/cached profiles match `dir`. Local profiles win over a
/// cached registry entry with the same id (deduped). Only profiles that carry
/// detect rules can match.
pub(crate) fn detect_matches(dir: &Path) -> paksmith_core::Result<Vec<DetectMatch>> {
    let store = ProfileStore::load()?;
    let cache = load_cache_lenient();
    let mut out = Vec::new();
    let mut seen = std::collections::BTreeSet::new();

    for (id, p) in &store.profiles {
        if let Some(rules) = &p.detect {
            if rules_match(dir, rules) {
                let _ = seen.insert(id.clone());
                out.push(DetectMatch { id: id.clone(), name: p.name.clone(), source: "local" });
            } else {
                let _ = seen.insert(id.clone()); // local id shadows a cached one even on no-match? NO — only on match.
            }
        }
    }
    // Correction: only a MATCHED or PRESENT local id should shadow the cache.
    // A local id (matched or not) shadows the cache entry of the same id, so
    // rebuild `seen` from all local ids:
    let local_ids: std::collections::BTreeSet<&String> = store.profiles.keys().collect();
    if let Some(c) = &cache {
        for p in &c.doc.profiles {
            if local_ids.contains(&p.id) {
                continue; // local wins (shown above iff it matched)
            }
            if let Some(rules) = &p.detect {
                if rules_match(dir, rules) {
                    out.push(DetectMatch { id: p.id.clone(), name: p.name.clone(), source: "registry" });
                }
            }
        }
    }
    let _ = seen; // (see note) — local shadowing handled via local_ids
    Ok(out)
}

/// `paksmith profile detect <dir>` — list every matching profile (0/1/many).
pub(crate) fn run(dir: &Path) -> paksmith_core::Result<u8> {
    let matches = detect_matches(dir)?;
    if matches.is_empty() {
        println!("no profiles matched {}", dir.display());
        return Ok(0);
    }
    println!("matched {} profile(s):", matches.len());
    for m in &matches {
        println!("  {}\t{}\t[{}]", m.id, m.name, m.source);
    }
    Ok(0)
}
```

IMPL NOTE: the `seen`/shadowing logic above is intentionally written then corrected inline — clean it up at implementation: the rule is simply "iterate local profiles (emit matches as `local`); then iterate cached profiles whose id is NOT a local id (emit matches as `registry`)." Use `let local_ids: BTreeSet<&String> = store.profiles.keys().collect();` and skip cached ids in that set. Remove the `seen` scaffolding.

Add to `commands/profile.rs`: a `Detect(DetectArgs)` variant on `ProfileCmd` with `#[derive(Args)] struct DetectArgs { dir: std::path::PathBuf }`, and dispatch `ProfileCmd::Detect(a) => crate::commands::detect::run(&a.dir)`. Register `pub(crate) mod detect;` in `commands/mod.rs`.

- [ ] **Step 4: Run tests** — `cargo test -p paksmith-cli --test detect_cli 2>&1 | tail -12` (both pass).

- [ ] **Step 5: Commit**

```bash
git add crates/paksmith-cli/src/commands crates/paksmith-cli/tests/detect_cli.rs
git commit -m "feat(cli): add profile detect <dir> command"
```

---

### Task 5: `--detect <dir>` resolution flag

**Files:**
- Modify: `crates/paksmith-cli/src/main.rs` (Cli `detect` flag + thread through dispatch)
- Modify: `crates/paksmith-cli/src/commands/mod.rs` (`Command::run` gains `detect` param → each command)
- Modify: `crates/paksmith-cli/src/commands/key_resolve.rs` (`resolve_pak_key` gains `detect` → detected id)
- Modify: `crates/paksmith-core/src/error.rs` (`ProfileFault::{DetectionNoMatch, DetectionAmbiguous}`)
- Modify: `crates/paksmith-cli/src/commands/{list,inspect,extract,search}.rs` (pass `detect` to `resolve_pak_key`)

**Interfaces:**
- Consumes: `detect_matches` (Task 4), `resolve_pak_key` (extended).
- Produces: `Command::run(&self, format, aes_key: Option<&AesKey>, game: Option<&str>, detect: Option<&Path>)`; `resolve_pak_key(path, aes_key, game, detect)`.
- Produces (error): `ProfileFault::DetectionNoMatch { dir: String }`, `ProfileFault::DetectionAmbiguous { dir: String, ids: String }`.

- [ ] **Step 1: Write the failing CLI tests** — append to `detect_cli.rs` (reuse `seed_profile_with_detect`; KEY = the v8b fixture key so the detected profile can decrypt it):

```rust
const KEY: &str = "94d25bc3aeb420e0be914edc9d5435a1eaab5f2864e09e94019ac205b727a7de";
fn fixture(name: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap()
        .join("tests/fixtures").join(name)
}

#[test]
fn detect_flag_resolves_single_match_key() {
    let cfg = tempdir().unwrap();
    let game = tempdir().unwrap();
    std::fs::create_dir_all(game.path().join("FortniteGame/Content/Paks")).unwrap();
    seed_profile_with_detect(cfg.path(), "FortniteGame/Content/Paks");
    // give the profile the fixture's default key so --detect can decrypt it
    paksmith(cfg.path()).args(["profile", "key", "add", "fortnite", "--key", KEY]).assert().success();
    // --detect <game-dir> list <encrypted-index fixture> → succeeds + lists entries
    let out = paksmith(cfg.path()).args(["--detect"]).arg(game.path()).arg("list").arg(fixture("real_v8b_encrypted_index.pak"))
        .assert().success();
    assert!(String::from_utf8(out.get_output().stdout.clone()).unwrap().contains("test.txt"));
}

#[test]
fn detect_flag_no_match_exits_nonzero() {
    let cfg = tempdir().unwrap();
    let game = tempdir().unwrap();
    seed_profile_with_detect(cfg.path(), "FortniteGame/Content/Paks"); // marker absent
    let _ = paksmith(cfg.path()).args(["--detect"]).arg(game.path()).arg("list").arg(fixture("real_v8b_encrypted_index.pak"))
        .assert().failure();
}

#[test]
fn detect_flag_ambiguous_exits_nonzero() {
    let cfg = tempdir().unwrap();
    let game = tempdir().unwrap();
    std::fs::create_dir_all(game.path().join("Common")).unwrap();
    // two local profiles, both matching "Common"
    for id in ["g1", "g2"] {
        paksmith(cfg.path()).args(["profile", "add", id, "--name", id]).assert().success();
    }
    let store = cfg.path().join("paksmith/profiles.toml");
    let mut s = std::fs::read_to_string(&store).unwrap();
    s.push_str("\n[profiles.g1.detect]\nrequire_paths = [\"Common\"]\n[profiles.g2.detect]\nrequire_paths = [\"Common\"]\n");
    std::fs::write(&store, s).unwrap();
    let _ = paksmith(cfg.path()).args(["--detect"]).arg(game.path()).arg("list").arg(fixture("real_v8b_encrypted_index.pak"))
        .assert().failure();
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p paksmith-cli --test detect_cli 2>&1 | tail -12`
Expected: FAIL — no `--detect` flag.

- [ ] **Step 3: Add the error variants** — in `error.rs` `ProfileFault`:

```rust
    /// `--detect` matched no game for the directory.
    #[error("no game profile matched directory `{dir}`")]
    DetectionNoMatch {
        /// The directory that was probed.
        dir: String,
    },
    /// `--detect` matched more than one game; the user must disambiguate.
    #[error("directory `{dir}` matched multiple game profiles: {ids}; pass --game to choose")]
    DetectionAmbiguous {
        /// The directory that was probed.
        dir: String,
        /// Comma-separated matched ids.
        ids: String,
    },
```

- [ ] **Step 4: Thread `--detect` + extend resolution.** In `main.rs` `Cli`, add (sibling of `game`):

```rust
    /// Auto-detect the game (and its key) from an install directory. Ignored if
    /// `--aes-key` or `--game` is given.
    #[arg(long, global = true, value_name = "DIR")]
    detect: Option<std::path::PathBuf>,
```

Thread it: `main.rs` dispatch → `cli.command.run(cli.format, key.as_ref(), cli.game.as_deref(), cli.detect.as_deref())`. `Command::run` (commands/mod.rs) gains `detect: Option<&Path>` and passes it to each container command's `run`; the `Profile` arm ignores it. Each container command's `run` gains `detect: Option<&Path>` and passes it to `resolve_pak_key`.

In `key_resolve.rs`, change `resolve_pak_key` to `(path, aes_key, game, detect: Option<&Path>)` and resolve the effective id at the top (keep everything below it identical, operating on `id`):

```rust
    if let Some(k) = aes_key {
        if game.is_some() || detect.is_some() {
            tracing::debug!("--aes-key overrides --game/--detect");
        }
        return Ok(Some(k.clone()));
    }
    // Effective profile id: --game (explicit) wins over --detect (auto).
    let id: String = if let Some(g) = game {
        if detect.is_some() {
            tracing::debug!("--game overrides --detect");
        }
        g.to_string()
    } else if let Some(dir) = detect {
        let mut matches = crate::commands::detect::detect_matches(dir)?;
        match matches.len() {
            0 => return Err(PaksmithError::Profile { fault: ProfileFault::DetectionNoMatch { dir: dir.display().to_string() } }),
            1 => matches.remove(0).id,
            _ => return Err(PaksmithError::Profile { fault: ProfileFault::DetectionAmbiguous {
                dir: dir.display().to_string(),
                ids: matches.iter().map(|m| m.id.as_str()).collect::<Vec<_>>().join(", "),
            } }),
        }
    } else {
        return Ok(None);
    };
    let id = id.as_str();
    // ... existing body unchanged from here (store load, local-wins, cache, fetch, resolve) ...
```

(The existing body already takes `id: &str` shape — keep it. Update the four container commands' `resolve_pak_key(...)` call sites to pass `detect`.)

- [ ] **Step 5: Run tests** — `cargo test -p paksmith-cli --all-features 2>&1 | tail -16` (new `--detect` tests + ALL existing CLI incl 5b/5c `--game`/`--aes-key`/auto-fetch green — the signature ripple touched all four commands). `cargo fmt --all && cargo fmt --all --check` (verify exit 0). `cargo clippy --workspace --all-targets --all-features -- -D warnings`.

- [ ] **Step 6: Commit**

```bash
git add crates/paksmith-cli crates/paksmith-core/src/error.rs
git commit -m "feat(cli): add --detect <dir> resolving a game key by auto-detection"
```

---

### Task 6: ROADMAP (Phase 5 complete) + full gate chain

**Files:**
- Modify: `docs/plans/ROADMAP.md`

- [ ] **Step 1: ROADMAP** — mark **5d (game auto-detection: `profile detect` + `--detect`)** shipped and note **Phase 5 (Game Profiles) is now complete** (5a–5d all shipped). Update the Phase 5 status line/table accordingly. Factual; no engine-source references.

- [ ] **Step 2: Full gate chain (each UNPIPED; fix in-scope failures)**

```bash
cargo fmt --all && cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
typos .
cargo deny check
cargo +1.88 check -p paksmith-core -p paksmith-cli   # MSRV
```
(No new deps → `cargo deny` + Minimal versions should be unaffected; confirm.)

- [ ] **Step 3: cargo-mutants to 0-missed** — `git diff $(git merge-base origin/main HEAD)..HEAD > /tmp/pr.diff && cargo mutants --in-diff /tmp/pr.diff --no-shuffle -j 2 --all-features 2>&1 | tail -25` → **0 missed**. Kill survivors with unit tests (the `safe_join` component-match arms, `rules_match` AND-logic, the caps, the detect-id resolution branches); refactor equivalents; add documented `.cargo/mutants.toml` excludes only for genuine residue (e.g. CLI env-wrappers per the 5b/5c precedent).

- [ ] **Step 4: Fixture-count gate** — 5d adds NO `.pak` fixtures (synthetic dirs are tempdirs). Confirm `find tests/fixtures -maxdepth 1 -name '*.pak' | wc -l` == the `expected=` in `.github/workflows/ci.yml`.

- [ ] **Step 5: Commit**

```bash
git add docs/plans/ROADMAP.md
git commit -m "docs(roadmap): mark phase 5d (auto-detection) shipped; phase 5 complete"
```

---

## Review & Push

- Adversarial whole-branch panel with a **mandatory security specialist** (the traversal guard `safe_join`: absolute/`..`/root/drive rejection + no-escape; the bounded `contains` read; the untrusted-registry detect caps; no-key-in-logs) + code-reviewer + architect + simplifier + a **deep-impact tracer** (the `Command::run`/`resolve_pak_key` signature ripple to all four commands; the new public API + `ProfileFault` variants; the `detect` field on both profile structs).
- Cycle to convergence; re-dispatch the full panel after each fix commit.
- Verify gates personally; run cargo-mutants to 0-missed; touch the convergence marker (separate Bash call); push; open PR (`gh --body-file`); Monitor CI to green. Do NOT merge — the user merges.

---

## Self-Review (plan vs spec)

**Spec coverage:**
- `DetectRules { require_paths, contains }` + `ContainsRule` schema → Task 1. ✓
- `detect` field on `GameProfile` + `RegistryProfile`, additive/optional serde → Task 1. ✓
- AND match semantics; no-rules→never-match → Task 2. ✓
- Path-traversal/absolute rejection (`safe_join`) → Task 2. ✓
- Bounded `contains` read (`MAX_CONTAINS_READ`) → Task 2. ✓
- Untrusted-registry detect caps in `validate_caps` → Task 3. ✓
- `profile detect <dir>` lists all matches (0/1/many) → Task 4. ✓
- `--detect <dir>` resolution, exactly-one, precedence `--aes-key`>`--game`>`--detect` → Task 5. ✓
- `DetectionNoMatch`/`DetectionAmbiguous` typed errors → Task 5. ✓
- no new deps / no `.pak` fixtures → Tasks 1–6 + Task 6 gate checks. ✓
- ROADMAP + Phase 5 complete → Task 6. ✓

**Type consistency:** `DetectRules{require_paths,contains}` + `ContainsRule{path,substring}` (T1); `rules_match(&Path,&DetectRules)->bool` + `safe_join` (T2); caps `MAX_REQUIRE_PATHS`/`MAX_CONTAINS`/`MAX_CONTAINS_READ`/`MAX_STR` (T1/T3); `detect: Option<DetectRules>` on both profiles (T1); `detect_matches(&Path)->Result<Vec<DetectMatch>>` + `DetectMatch{id,name,source}` (T4); `resolve_pak_key(path,aes_key,game,detect)` + `Command::run(...,detect)` (T5); `ProfileFault::{DetectionNoMatch{dir},DetectionAmbiguous{dir,ids}}` (T5) — referenced identically across tasks.

**Open implementation points (resolve against live code; crisp deliverable + test each):**
- The `detect_matches` local-over-registry dedup (T4) — iterate locals (emit matches), then cached whose id ∉ local ids; the plan's inline `seen` scaffolding is to be cleaned to that shape.
- Every `GameProfile {..}`/`RegistryProfile {..}` literal needs `detect: None` (T1) — the compiler enumerates them.
- The `resolve_pak_key` body below the new id-resolution block is unchanged from 5c (T5) — keep it operating on `id: &str`.
