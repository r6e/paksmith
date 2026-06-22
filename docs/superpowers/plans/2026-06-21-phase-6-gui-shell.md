# Phase 6 — GUI Shell Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a polished, native-feeling Iced desktop shell (`paksmith-gui`) that opens `.pak` archives (including encrypted, via the full Phase 5 resolution) and navigates them in a virtualized lazy file tree with a two-pane Explorer + Detail layout.

**Architecture:** Iced's functional Elm architecture (`iced::application(state, update, view)`), with a strict split between **pure, unit-tested state models** (`state/`, no Iced types) and thin view code (`panels/`, `widgets/`). A cross-cutting first step extracts the Phase 5 key-resolution orchestration from the CLI into `paksmith-core` as an `async fn` both frontends call (CLI via `block_on`, GUI via `Task::perform`). Maximal native integration: real native window (winit), native menus (`muda`), native dialogs (`rfd`), auto OS light/dark, and per-OS system accent.

**Tech Stack:** Rust 2024 (MSRV 1.88), `iced` 0.14 (wgpu renderer, functional API), `rfd` (native dialogs), `muda` (native menus), `dark-light` (OS theme), per-OS accent crates (`windows` / `objc2`+`objc2-app-kit` / a Linux xdg-desktop-portal crate), `paksmith-core`.

## Global Constraints

- MSRV 1.88; edition 2024. No panics on runtime paths — `Result`/`Option` everywhere; `unwrap`/`expect` only in tests. `thiserror` errors, `tracing` logging (the GUI may render user-facing strings, but no `println!` debugging).
- **`paksmith-gui` depends ONLY on `paksmith-core`** — never on `paksmith-cli` (CLAUDE.md: CLI and GUI never share code directly). The shared key-resolution logic lives in `paksmith-core`.
- Pin **`iced = "0.14"`** via `cargo add iced` at scaffold time; reconcile any view-code signature in this plan against the actually-resolved 0.14 API (`cargo doc -p iced --open` / the iced repo `examples/`) — the functional `iced::application(state, update, view).theme(...).run()` + `Task::perform(future, Message::Variant)` shape is confirmed, but exact widget builder method names may differ slightly; adapt and keep the behavior.
- All new dependencies are permissive (MIT/Apache); `cargo deny check` must pass. Add a **scoped, documented** `[licenses]`/`[bans]`/`[sources]` exception in `deny.toml` ONLY for a genuinely-needed case (consistent with prior phases) — never a blanket allow.
- `gui` stays in `[workspace] default-members` (tier-1 feature) — accept the iced build cost.
- Do NOT edit any `Cargo.toml` `version =` field (release-please owns versions). Conventional commits; one logical change per commit.
- **Per-OS code** (`theme/accent.rs`) uses `#[cfg(target_os = "...")]` with a fallback arm that compiles on every target; CI's ubuntu/macOS/windows matrix builds all three.
- Before every push: full gate chain — `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace --all-features`, `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features`, `typos .`, `cargo deny check`, and `cargo mutants --in-diff $(git merge-base origin/main HEAD)..HEAD --all-features` to **0 missed**.
- **Review protocol (binding):** every PR's panel includes a **UI/UX design reviewer** as a standing, blocking member (visual hierarchy, spacing rhythm, affordance/feedback clarity, keyboard navigation, WCAG-AA contrast in both themes, native-convention adherence, complete empty/loading/locked/error states). "Looks amateur" is a blocking finding. Plus the usual code/architect/simplifier/security, and deep-impact (Task 1/2 signature ripple) and performance (Task 9 virtualized renderer) specialists when triggered.

## File Structure

**`paksmith-core` (refactor — Tasks 1–2):**
- `crates/paksmith-core/src/profile/resolve.rs` — CREATE: `DetectMatch`, `detect_matches` (sync), `resolve_pak_key` (async), helpers. The frontend-agnostic resolution home.
- `crates/paksmith-core/src/profile/mod.rs` — MODIFY: `pub mod resolve;` + re-exports.
- `crates/paksmith-cli/src/commands/key_resolve.rs` — MODIFY: becomes a thin `block_on` wrapper over `core::profile::resolve::resolve_pak_key`.
- `crates/paksmith-cli/src/commands/detect.rs` — MODIFY: `profile detect` handler calls `core::profile::resolve::detect_matches`; local `detect_matches`/`DetectMatch` removed.

**`paksmith-gui` (Tasks 3–12):**
- `crates/paksmith-gui/Cargo.toml` — MODIFY: add deps per task.
- `crates/paksmith-gui/src/main.rs` — entry; `iced::application(...).run()`, window + menu wiring.
- `crates/paksmith-gui/src/app.rs` — `App` state, `Message`, `update`, top-level `view`.
- `crates/paksmith-gui/src/theme/{mod.rs,tokens.rs,accent.rs}` — palette, design tokens, per-OS accent.
- `crates/paksmith-gui/src/state/{archive.rs,tree.rs,keyflow.rs}` — PURE models.
- `crates/paksmith-gui/src/panels/{toolbar.rs,sidebar.rs,detail.rs,status_bar.rs,key_prompt.rs}` — view panels.
- `crates/paksmith-gui/src/widgets/file_tree.rs` — virtualized tree widget.
- `crates/paksmith-gui/src/task/open.rs` — async open pipeline.
- `crates/paksmith-gui/src/menu.rs` — `muda` native menu bar.

**Docs (Task 13):** `docs/plans/ROADMAP.md`.

---

### Task 1: Core — move `detect_matches` into `paksmith-core`

**Files:**
- Create: `crates/paksmith-core/src/profile/resolve.rs`
- Modify: `crates/paksmith-core/src/profile/mod.rs` (`pub mod resolve;`)
- Modify: `crates/paksmith-core/src/lib.rs` (re-export `DetectMatch`)
- Modify: `crates/paksmith-cli/src/commands/detect.rs` (use core's `detect_matches`; delete the local copy)

**Interfaces:**
- Produces: `pub struct DetectMatch { pub id: String, pub name: String, pub source: &'static str }`; `pub fn detect_matches(dir: &std::path::Path) -> crate::Result<Vec<DetectMatch>>` (loads store+cache, delegates); `pub(crate) fn detect_in(store: &ProfileStore, cache: Option<&RegistryCache>, dir: &std::path::Path) -> Vec<DetectMatch>` (PURE — the unit-tested core, no env/I/O); `pub(crate) fn load_cache_lenient() -> Option<crate::profile::cache::RegistryCache>` (moved from CLI, now in core).
- Consumes: `ProfileStore`, `GameProfile`, `profile::detection::rules_match`, `profile::cache::RegistryCache` (all in core).
- **Test seam (matches the codebase pattern):** core unit tests do NOT set `PAKSMITH_CONFIG_DIR` (the project forbids `std::env::set_var` under `-D unsafe-code` and uses injectable seams like `config_base_dir_from_env`/`load_from` instead). So the detection logic is tested through `detect_in` with a hand-built `ProfileStore`/`RegistryCache` — no env, no `temp_env` dependency.

- [ ] **Step 1: Write the failing test** — create `resolve.rs` with the function stubbed `unimplemented!()` and this test module. It seeds a local profile store via `PAKSMITH_CONFIG_DIR` (the same override the store honors) and asserts a marker dir matches:

```rust
//! Frontend-agnostic key/profile resolution: shared by the CLI and GUI so the
//! Phase 5 `--game`/`--detect` logic lives in exactly one place.

use std::path::Path;

use crate::ProfileStore;
use crate::profile::cache::RegistryCache;
use crate::profile::detection::rules_match;

/// One profile that matched a directory scan.
pub struct DetectMatch {
    /// Profile id.
    pub id: String,
    /// Human-readable display name.
    pub name: String,
    /// Where the profile came from: `"local"` or `"registry"`.
    pub source: &'static str,
}

/// Load the registry cache, degrading a corrupt/unreadable cache to `None`.
pub(crate) fn load_cache_lenient() -> Option<RegistryCache> {
    match RegistryCache::load() {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "ignoring unreadable registry cache");
            None
        }
    }
}

/// Detect which stored/cached profiles match `dir` (loads store + cache, then
/// delegates to the pure `detect_in`).
pub fn detect_matches(dir: &Path) -> crate::Result<Vec<DetectMatch>> {
    let store = ProfileStore::load()?;
    let cache = load_cache_lenient();
    Ok(detect_in(&store, cache.as_ref(), dir))
}

/// Pure detection over an already-loaded store + cache — no env reads, no I/O
/// beyond `rules_match`'s bounded filesystem checks. Local profiles are emitted
/// first and shadow a cached registry entry of the same id (match or not). Only
/// profiles that carry detect rules can match. This is the unit-tested core.
pub(crate) fn detect_in(
    store: &ProfileStore,
    cache: Option<&RegistryCache>,
    dir: &Path,
) -> Vec<DetectMatch> {
    let mut out = Vec::new();
    for (id, p) in &store.profiles {
        let Some(rules) = &p.detect else { continue };
        if rules_match(dir, rules) {
            out.push(DetectMatch { id: id.clone(), name: p.name.clone(), source: "local" });
        }
    }
    let Some(c) = cache else { return out };
    for p in &c.doc.profiles {
        if store.profiles.contains_key(&p.id) {
            continue;
        }
        let Some(rules) = &p.detect else { continue };
        if rules_match(dir, rules) {
            out.push(DetectMatch { id: p.id.clone(), name: p.name.clone(), source: "registry" });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GameProfile;
    use crate::profile::detection::DetectRules;

    #[test]
    fn detect_in_local_marker_matches() {
        let game = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(game.path().join("Game/Paks")).unwrap();
        let mut store = ProfileStore::default();
        store.profiles.insert(
            "demo".into(),
            GameProfile {
                name: "Demo".into(),
                engine_version: None,
                keys: Default::default(),
                detect: Some(DetectRules { require_paths: vec!["Game/Paks".into()], contains: vec![] }),
            },
        );
        let got = detect_in(&store, None, game.path());
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].id, "demo");
        assert_eq!(got[0].source, "local");
    }

    #[test]
    fn detect_in_local_shadows_registry_same_id() {
        let game = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(game.path().join("Game/Paks")).unwrap();
        let rules = DetectRules { require_paths: vec!["Game/Paks".into()], contains: vec![] };
        let mut store = ProfileStore::default();
        store.profiles.insert(
            "demo".into(),
            GameProfile { name: "Local".into(), engine_version: None, keys: Default::default(), detect: Some(rules.clone()) },
        );
        let cache = RegistryCache {
            fetched_at_unix: 0,
            doc: crate::profile::registry::RegistryDoc {
                profiles: vec![crate::profile::registry::RegistryProfile {
                    id: "demo".into(),
                    name: "Registry".into(),
                    engine_version: None,
                    keys: Default::default(),
                    detect: Some(rules),
                }],
            },
        };
        let got = detect_in(&store, Some(&cache), game.path());
        // "demo" appears ONCE (local shadows the registry entry of the same id).
        assert_eq!(got.iter().filter(|m| m.id == "demo").count(), 1);
        assert_eq!(got[0].source, "local");
    }
}
```

(No `temp_env` / env-setting: the detection logic is tested via `detect_in` with hand-built `ProfileStore`/`RegistryCache`, matching the codebase's injectable-seam testing convention. Verify the `GameProfile`/`RegistryProfile` literal fields against the actual structs before relying on the snippet — add `detect: …` etc. exactly as defined.)

- [ ] **Step 2: Run to verify the move compiles + test passes** — `cargo test -p paksmith-core --all-features profile::resolve` (the function is real, not stubbed — this step verifies the moved code + the seeding test). Register `pub mod resolve;` in `profile/mod.rs` and `pub use profile::resolve::DetectMatch;` in `lib.rs` first, or the test won't compile.

- [ ] **Step 3: Rewire the CLI to use core's `detect_matches`.** In `crates/paksmith-cli/src/commands/detect.rs`, delete the local `DetectMatch` struct and `detect_matches` fn; change the `profile detect` handler to call `paksmith_core::profile::resolve::detect_matches(dir)` and read `m.id/m.name/m.source` (identical fields). The CLI's `load_cache_lenient` is still referenced by `key_resolve.rs` (handled in Task 2) — leave that copy for now; the detect.rs handler no longer needs it.

- [ ] **Step 4: Run the CLI detect tests** — `cargo test -p paksmith-cli --test detect_cli` (the `profile detect` integration tests must still pass against the core-backed handler). Then `cargo test -p paksmith-core --all-features profile::resolve`.

- [ ] **Step 5: Gates + commit**

```bash
cargo fmt --all && cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
git add crates/paksmith-core crates/paksmith-cli
git commit -m "refactor(profile): move detect_matches into paksmith-core profile::resolve"
```

---

### Task 2: Core — move `resolve_pak_key` into core as an `async fn`; CLI `block_on` wrapper

**Files:**
- Modify: `crates/paksmith-core/src/profile/resolve.rs` (add `resolve_pak_key` async + helpers)
- Modify: `crates/paksmith-cli/src/commands/key_resolve.rs` (thin `block_on` wrapper; delete moved code)

**Interfaces:**
- Produces (core): `pub async fn resolve_pak_key(path: &Path, aes_key: Option<&AesKey>, game: Option<&str>, detect: Option<&Path>) -> crate::Result<Option<AesKey>>`.
- Produces (CLI, unchanged signature so the 4 container commands don't change): `pub(crate) fn resolve_pak_key(path: &Path, aes_key: Option<&AesKey>, game: Option<&str>, detect: Option<&Path>) -> paksmith_core::Result<Option<AesKey>>`.
- **Why async:** the registry fetch (`RegistryClient::fetch`) is async. Making the core fn `async` lets the GUI `.await` it inside `Task::perform` (Iced runs on tokio — a `block_on` there would panic), while the CLI wraps it in its existing `block_on`. This is the load-bearing reason for the async signature; do not collapse it to sync.

- [ ] **Step 1: Write the failing test (core)** — add to `resolve.rs` tests. It verifies `--aes-key` short-circuits (no profile store / network touched) via a `#[tokio::test]` (core already has `tokio` with `rt` for tests):

```rust
    #[tokio::test]
    async fn aes_key_short_circuits_resolution() {
        // A bogus path that doesn't exist — proves we never read it when --aes-key wins.
        let key = crate::AesKey::from_hex(&"ab".repeat(32)).unwrap();
        let got = resolve_pak_key(
            Path::new("/nonexistent/x.pak"),
            Some(&key),
            None,
            None,
        ).await.unwrap();
        assert_eq!(got, Some(key));
    }

    #[tokio::test]
    async fn no_flags_returns_none() {
        let got = resolve_pak_key(Path::new("/nonexistent/x.pak"), None, None, None)
            .await
            .unwrap();
        assert!(got.is_none());
    }
```

- [ ] **Step 2: Run to verify it fails** — `cargo test -p paksmith-core --all-features profile::resolve` → FAIL (`resolve_pak_key` not found).

- [ ] **Step 3: Implement `resolve_pak_key` (async) + helpers in core.** Move the body from the CLI verbatim, converting the fetch to a direct `await` (drop the CLI `block_on`). Add these to `resolve.rs`:

```rust
use std::collections::BTreeMap;

use crate::container::pak::PakReader;
use crate::error::ProfileFault;
use crate::profile::config::{RegistryConfig, ensure_key_matches_registry};
use crate::profile::registry::RegistryClient;
use crate::{AesKey, KeyGuid, PaksmithError, ResolvedProfile, display_guid, resolve_profile_layered};

/// Resolve the AES key for a pak: `--aes-key` (wins) > `--game` (explicit id) >
/// `--detect` (auto-detect from an install dir). `None` when no selector is set.
pub async fn resolve_pak_key(
    path: &Path,
    aes_key: Option<&AesKey>,
    game: Option<&str>,
    detect: Option<&Path>,
) -> crate::Result<Option<AesKey>> {
    if let Some(k) = aes_key {
        if game.is_some() {
            tracing::debug!("--aes-key overrides --game");
        } else if detect.is_some() {
            tracing::debug!("--aes-key overrides --detect");
        }
        return Ok(Some(k.clone()));
    }
    let id: String = if let Some(g) = game {
        if detect.is_some() {
            tracing::debug!("--game overrides --detect");
        }
        g.to_string()
    } else if let Some(dir) = detect {
        if !dir.is_dir() {
            return Err(PaksmithError::InvalidArgument {
                arg: "--detect",
                reason: format!("not a directory: {}", dir.display()),
            });
        }
        let mut matches = detect_matches(dir)?;
        match matches.len() {
            0 => {
                return Err(PaksmithError::Profile {
                    fault: ProfileFault::DetectionNoMatch { dir: dir.display().to_string() },
                });
            }
            1 => matches.remove(0).id,
            _ => {
                return Err(PaksmithError::Profile {
                    fault: ProfileFault::DetectionAmbiguous {
                        dir: dir.display().to_string(),
                        ids: matches.iter().map(|m| m.id.as_str()).collect::<Vec<_>>().join(", "),
                    },
                });
            }
        }
    } else {
        return Ok(None);
    };
    let id = id.as_str();

    let store = ProfileStore::load()?;
    let pak_guid = PakReader::read_footer_guid(path)?;

    if let Some(profile) = store.profiles.get(id) {
        return resolve_within(&profile.keys, id, pak_guid);
    }

    let mut cache = load_cache_lenient();
    let cfg = RegistryConfig::load()?;
    let now = now_unix()?;
    let fresh = cache
        .as_ref()
        .is_some_and(|c| !c.is_stale(now, cfg.staleness_hours) && c.get(id).is_some());

    if !fresh {
        match try_fetch(&cfg, now).await {
            Ok(fetched) => {
                let _ = fetched.save();
                cache = Some(fetched);
            }
            Err(e) => {
                tracing::warn!(error = %e, "registry fetch failed; using cached profiles if available");
            }
        }
    }

    match resolve_profile_layered(&store, cache.as_ref(), id) {
        Some(ResolvedProfile::Local(p)) => resolve_within(&p.keys, id, pak_guid),
        Some(ResolvedProfile::Registry(p)) => resolve_within(&p.keys, id, pak_guid),
        None => Err(PaksmithError::Profile {
            fault: ProfileFault::ProfileNotFound { id: id.to_string() },
        }),
    }
}

async fn try_fetch(cfg: &RegistryConfig, now: u64) -> crate::Result<RegistryCache> {
    ensure_key_matches_registry(&cfg.url, &cfg.public_key_hex)?;
    let client = RegistryClient::new()?;
    let doc = client.fetch(&cfg.url, &cfg.public_key_hex).await?;
    Ok(RegistryCache { fetched_at_unix: now, doc })
}

fn now_unix() -> crate::Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| PaksmithError::InvalidArgument { arg: "clock", reason: e.to_string() })
}

fn resolve_within(
    keys: &BTreeMap<KeyGuid, AesKey>,
    id: &str,
    pak_guid: Option<[u8; 16]>,
) -> crate::Result<Option<AesKey>> {
    let guid = pak_guid.map_or(KeyGuid::ZERO, KeyGuid::from_bytes);
    let key = keys
        .get(&guid)
        .or_else(|| keys.get(&KeyGuid::ZERO))
        .ok_or_else(|| PaksmithError::Profile {
            fault: ProfileFault::NoKeyForGuid { id: id.to_string(), guid: display_guid(pak_guid) },
        })?;
    Ok(Some(key.clone()))
}
```

Verify every imported path exists at the shown location (grep: `ensure_key_matches_registry`, `RegistryConfig`, `RegistryClient`, `resolve_profile_layered`, `ResolvedProfile`, `display_guid`, `KeyGuid::ZERO`, `KeyGuid::from_bytes`). They were all in core as of Phase 5c/5b; if a path differs, fix the `use`.

- [ ] **Step 4: Rewire the CLI wrapper.** Replace `crates/paksmith-cli/src/commands/key_resolve.rs`'s body: delete the moved `resolve_pak_key` body, `try_fetch`, `now_unix`, `resolve_within`, `load_cache_lenient` (now in core), and make the public CLI fn a thin wrapper:

```rust
use std::path::Path;

use paksmith_core::AesKey;

/// CLI-side resolution: block_on the async core orchestration so the four
/// container commands keep a synchronous call site.
pub(crate) fn resolve_pak_key(
    path: &Path,
    aes_key: Option<&AesKey>,
    game: Option<&str>,
    detect: Option<&Path>,
) -> paksmith_core::Result<Option<AesKey>> {
    crate::block_on(paksmith_core::profile::resolve::resolve_pak_key(path, aes_key, game, detect))
}
```

Grep for any other CLI references to the deleted helpers (`now_unix`, `load_cache_lenient`, `resolve_within`, `try_fetch`) and repoint or remove them (e.g. if a test referenced `now_unix`, use `paksmith_core` or delete the test if it duplicated a core test). The 4 container commands call `resolve_pak_key` unchanged.

- [ ] **Step 5: Run tests** — `cargo test -p paksmith-core --all-features profile::resolve`, then `cargo test -p paksmith-cli` (the existing resolution/integration tests — list/inspect/extract/search + detect_cli + any key-resolve tests — must all pass unchanged). Personally run `cargo fmt --all --check` (verify exit 0).

- [ ] **Step 6: Gates + commit**

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
git add crates/paksmith-core crates/paksmith-cli
git commit -m "refactor(profile): move async resolve_pak_key into core; CLI block_on wrapper"
```

---

### Task 3: GUI scaffold — runnable Iced window + empty state

**Files:**
- Modify: `crates/paksmith-gui/Cargo.toml` (add `iced`, `paksmith-core`)
- Modify: `crates/paksmith-gui/src/main.rs`
- Create: `crates/paksmith-gui/src/app.rs`

**Interfaces:**
- Produces: `App` (state struct), `Message` enum (starts with `Message::Noop`/window events), `fn update(&mut App, Message) -> iced::Task<Message>`, `fn view(&App) -> iced::Element<'_, Message>`.

- [ ] **Step 1: Add deps.** `cd crates/paksmith-gui && cargo add iced@0.14 && cargo add paksmith-core --path ../paksmith-core` (use the workspace path dependency form the repo already uses for cross-crate deps — check `paksmith-cli/Cargo.toml` for the exact `paksmith-core.workspace = true` or `path` style and match it). Confirm the crate still builds: `cargo build -p paksmith-gui`.

- [ ] **Step 2: Write a smoke test** — Iced `view`/`update` are hard to unit-test, but the `App::default()` state and a no-op `update` ARE testable. Add to `app.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_app_has_no_archive() {
        let app = App::default();
        assert!(app.archive.is_none());
    }
}
```

- [ ] **Step 3: Run to verify it fails** — `cargo test -p paksmith-gui` → FAIL (`App` not defined).

- [ ] **Step 4: Implement the scaffold.** `app.rs`:

```rust
//! Top-level application state, messages, and the update/view cycle.

use iced::widget::{container, text};
use iced::{Element, Length, Task};

/// Root application state.
#[derive(Default)]
pub struct App {
    /// The currently-open archive, if any (populated in later tasks).
    pub archive: Option<()>, // replaced by `state::archive::LoadedArchive` in Task 7
}

/// Every state transition flows through one of these.
#[derive(Debug, Clone)]
pub enum Message {
    /// Placeholder so the enum is non-empty until real messages land.
    Noop,
}

pub fn update(_app: &mut App, message: Message) -> Task<Message> {
    match message {
        Message::Noop => Task::none(),
    }
}

pub fn view(_app: &App) -> Element<'_, Message> {
    container(text("Open a .pak to begin").size(18))
        .center_x(Length::Fill)
        .center_y(Length::Fill)
        .into()
}
```

`main.rs`:

```rust
//! Paksmith GUI — native-feeling explorer for Unreal Engine game assets.

mod app;

fn main() -> iced::Result {
    iced::application("paksmith", app::update, app::view)
        .theme(|_| iced::Theme::Dark) // replaced by system light/dark in Task 4
        .run()
}
```

Reconcile the `iced::application(title, update, view)` builder + `.theme(...)`/`.run()` against the resolved iced 0.14 API (the title arg may be a `&str`, a closure, or set via `.title(...)` — adapt; the functional 3-arg form is confirmed). The window must open and show the centered empty-state text.

- [ ] **Step 5: Run test + manual smoke** — `cargo test -p paksmith-gui` (PASS), then `cargo run -p paksmith-gui` shows a window with "Open a .pak to begin". (Manual; note it in the report.)

- [ ] **Step 6: Gates + commit**

```bash
cargo fmt --all && cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo deny check
git add crates/paksmith-gui Cargo.lock
git commit -m "feat(gui): scaffold iced application with empty-state window"
```

---

### Task 4: Theme system — design tokens + auto light/dark

**Files:**
- Create: `crates/paksmith-gui/src/theme/mod.rs`, `crates/paksmith-gui/src/theme/tokens.rs`
- Modify: `crates/paksmith-gui/src/main.rs` (`.theme(...)` reads the system preference), `app.rs` (store the active `Theme` mode in `App`)
- Modify: `crates/paksmith-gui/Cargo.toml` (add `dark-light`)

**Interfaces:**
- Produces: `theme::tokens::{SPACE_XS, SPACE_SM, SPACE_MD, SPACE_LG, RADIUS, TEXT_SM, TEXT_MD, TEXT_LG}` (pure `f32`/`u16` consts); `theme::Mode` (`Light`/`Dark`); `fn theme::detect_mode() -> Mode` (reads OS pref, defaults `Dark`); `fn theme::iced_theme(mode: Mode) -> iced::Theme`.

- [ ] **Step 1: Write failing tests** — `tokens.rs` constants and the mode mapping are pure. `theme/mod.rs` tests:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dark_mode_maps_to_iced_dark() {
        assert!(matches!(iced_theme(Mode::Dark), iced::Theme::Dark));
        assert!(matches!(iced_theme(Mode::Light), iced::Theme::Light));
    }

    #[test]
    fn tokens_are_a_consistent_scale() {
        use crate::theme::tokens::*;
        assert!(SPACE_XS < SPACE_SM && SPACE_SM < SPACE_MD && SPACE_MD < SPACE_LG);
    }
}
```

- [ ] **Step 2: Run to verify it fails** — `cargo test -p paksmith-gui theme` → FAIL.

- [ ] **Step 3: Implement.** Add `dark-light`: `cd crates/paksmith-gui && cargo add dark-light`. `tokens.rs`:

```rust
//! Design tokens: one source of truth for spacing, radius, and type scale.
pub const SPACE_XS: f32 = 4.0;
pub const SPACE_SM: f32 = 8.0;
pub const SPACE_MD: f32 = 12.0;
pub const SPACE_LG: f32 = 20.0;
pub const RADIUS: f32 = 6.0;
pub const TEXT_SM: u16 = 12;
pub const TEXT_MD: u16 = 14;
pub const TEXT_LG: u16 = 18;
```

`theme/mod.rs`:

```rust
//! Theme: maps the OS light/dark preference (and, in Task 5, the system accent)
//! onto an Iced theme + the design tokens.
pub mod tokens;

/// Light or dark appearance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Light,
    Dark,
}

/// Read the OS appearance preference, defaulting to Dark when unknown.
pub fn detect_mode() -> Mode {
    match dark_light::detect() {
        Ok(dark_light::Mode::Light) => Mode::Light,
        Ok(dark_light::Mode::Dark) | Ok(dark_light::Mode::Unspecified) => Mode::Dark,
        Err(_) => Mode::Dark,
    }
}

/// The Iced base theme for a mode.
pub fn iced_theme(mode: Mode) -> iced::Theme {
    match mode {
        Mode::Light => iced::Theme::Light,
        Mode::Dark => iced::Theme::Dark,
    }
}
```

Reconcile `dark_light::detect()`'s exact return type against the resolved version (older `dark-light` returns a bare `Mode` enum, newer returns `Result<Mode, _>` and uses `Unspecified`) — adapt the match arms; the behavior (Light→Light, else→Dark) is the contract. Store `mode: theme::Mode` in `App` (default `detect_mode()`), and in `main.rs` use `.theme(|app| theme::iced_theme(app.mode))`. Register `mod theme;` in `main.rs`.

- [ ] **Step 4: Run tests** — `cargo test -p paksmith-gui theme` (PASS).

- [ ] **Step 5: Gates + commit**

```bash
cargo fmt --all && cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo deny check
git add crates/paksmith-gui Cargo.lock
git commit -m "feat(gui): theme tokens + auto OS light/dark detection"
```

---

### Task 5: System accent color (per-OS)

**Files:**
- Create: `crates/paksmith-gui/src/theme/accent.rs`
- Modify: `crates/paksmith-gui/src/theme/mod.rs` (`pub mod accent;`)
- Modify: `crates/paksmith-gui/Cargo.toml` (per-OS deps under `[target.'cfg(...)'.dependencies]`)

**Interfaces:**
- Produces: `theme::accent::DEFAULT_ACCENT: iced::Color`; `fn theme::accent::system_accent() -> iced::Color` (per-OS read, falls back to `DEFAULT_ACCENT`).

- [ ] **Step 1: Write failing test** — the fallback is always testable; the per-OS read returns *some* valid color:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accent_is_a_valid_opaque_color() {
        let c = system_accent();
        assert!((0.0..=1.0).contains(&c.r) && (0.0..=1.0).contains(&c.g) && (0.0..=1.0).contains(&c.b));
        assert_eq!(c.a, 1.0);
    }

    #[test]
    fn default_accent_is_opaque() {
        assert_eq!(DEFAULT_ACCENT.a, 1.0);
    }
}
```

- [ ] **Step 2: Run to verify it fails** — `cargo test -p paksmith-gui theme::accent` → FAIL.

- [ ] **Step 3: Implement.** `accent.rs`:

```rust
//! System accent color. Each platform reads the user's accent and falls back to
//! `DEFAULT_ACCENT` when unavailable. The accent drives selection/focus styling.

use iced::Color;

/// Fallback accent (a calm blue) used when the OS accent can't be read.
pub const DEFAULT_ACCENT: Color = Color::from_rgb(0.36, 0.55, 0.93);

/// The user's system accent color, or `DEFAULT_ACCENT`.
pub fn system_accent() -> Color {
    platform_accent().unwrap_or(DEFAULT_ACCENT)
}

#[cfg(target_os = "windows")]
fn platform_accent() -> Option<Color> {
    // windows crate: UISettings.GetColorValue(UIColorType::Accent) → SRGB u8s.
    use windows::UI::ViewManagement::{UIColorType, UISettings};
    let settings = UISettings::new().ok()?;
    let c = settings.GetColorValue(UIColorType::Accent).ok()?;
    Some(Color::from_rgb8(c.R, c.G, c.B))
}

#[cfg(target_os = "macos")]
fn platform_accent() -> Option<Color> {
    // objc2-app-kit: NSColor.controlAccentColor → sRGB components.
    // Implement with objc2; convert to sRGB color space before reading rgba.
    // Return None on any failure to fall back.
    macos_accent()
}

#[cfg(target_os = "linux")]
fn platform_accent() -> Option<Color> {
    // xdg-desktop-portal org.freedesktop.portal.Settings "accent-color" (newer
    // portals). Return None when the portal/key is unavailable → fallback.
    linux_portal_accent()
}

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
fn platform_accent() -> Option<Color> {
    None
}
```

For macOS (`macos_accent`) and Linux (`linux_portal_accent`): implement against `objc2`+`objc2-app-kit` and a portal crate (`ashpd`) respectively, each returning `Option<Color>` and swallowing every error into `None`. Add the deps target-scoped in `Cargo.toml`:

```toml
[target.'cfg(target_os = "windows")'.dependencies]
windows = { version = "...", features = ["UI_ViewManagement"] }

[target.'cfg(target_os = "macos")'.dependencies]
objc2 = "..."
objc2-app-kit = { version = "...", features = ["NSColor"] }

[target.'cfg(target_os = "linux")'.dependencies]
ashpd = "..."
```

Pin exact versions via `cargo add` at implementation time. **If the macOS/Linux native read proves fiddly within this task's scope, ship the platform fn as `None` (→ `DEFAULT_ACCENT` fallback) and note it as a follow-up — a correct fallback that compiles and tests on all three OSes is the bar; do NOT block the task on a flaky native read, and do NOT leave it half-wired.** Register `pub mod accent;` in `theme/mod.rs`. Reconcile each platform read against the resolved crate APIs.

- [ ] **Step 4: Run tests** — `cargo test -p paksmith-gui theme::accent` (PASS on the dev OS). Confirm it compiles for all three via `cargo clippy --workspace --all-targets --all-features` (CI's matrix builds each OS).

- [ ] **Step 5: Gates + commit**

```bash
cargo fmt --all && cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo deny check    # new platform deps — add scoped exceptions if flagged
git add crates/paksmith-gui Cargo.lock deny.toml
git commit -m "feat(gui): per-OS system accent color with fallback"
```

---

### Task 6: Tree model (pure, virtualization core)

**Files:**
- Create: `crates/paksmith-gui/src/state/tree.rs`
- Create: `crates/paksmith-gui/src/state/mod.rs` (`pub mod tree;`)

**Interfaces:**
- Produces: `state::tree::Tree` with `Tree::from_paths(paths: impl IntoIterator<Item = String>) -> Tree`; `fn visible_rows(&self) -> &[VisibleRow]`; `fn toggle(&mut self, row: usize)`; `fn select(&mut self, row: usize)`; `fn selected(&self) -> Option<&str>`; `fn set_filter(&mut self, query: &str)`; `fn len(&self) -> usize` (total entries). `pub struct VisibleRow { pub depth: usize, pub label: String, pub is_dir: bool, pub expanded: bool, pub full_path: Option<String> }` (`full_path` = `Some` for files, `None` for dirs).

- [ ] **Step 1: Write failing tests** — this is the pure heart; test it hard:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn demo() -> Tree {
        Tree::from_paths([
            "Content/Char/Hero.uasset".to_string(),
            "Content/Char/Hero.uexp".to_string(),
            "Content/Maps/A.umap".to_string(),
            "README.txt".to_string(),
        ])
    }

    #[test]
    fn collapsed_root_shows_only_top_level() {
        let t = demo();
        let labels: Vec<_> = t.visible_rows().iter().map(|r| r.label.as_str()).collect();
        assert_eq!(labels, vec!["Content", "README.txt"]); // dirs before files, sorted
    }

    #[test]
    fn expanding_reveals_children_lazily() {
        let mut t = demo();
        t.toggle(0); // expand Content
        let labels: Vec<_> = t.visible_rows().iter().map(|r| r.label.as_str()).collect();
        assert_eq!(labels, vec!["Content", "Char", "Maps", "README.txt"]);
        // grandchildren NOT shown until their dir expands
        assert!(!labels.contains(&"Hero.uasset"));
    }

    #[test]
    fn deep_expand_then_collapse_restores() {
        let mut t = demo();
        t.toggle(0); // Content
        t.toggle(1); // Char
        assert!(t.visible_rows().iter().any(|r| r.label == "Hero.uasset"));
        t.toggle(0); // collapse Content — grandchildren vanish too
        let labels: Vec<_> = t.visible_rows().iter().map(|r| r.label.as_str()).collect();
        assert_eq!(labels, vec!["Content", "README.txt"]);
    }

    #[test]
    fn select_a_file_exposes_its_full_path() {
        let mut t = demo();
        t.toggle(0); t.toggle(1);
        let hero = t.visible_rows().iter().position(|r| r.label == "Hero.uasset").unwrap();
        t.select(hero);
        assert_eq!(t.selected(), Some("Content/Char/Hero.uasset"));
    }

    #[test]
    fn filter_keeps_only_matching_paths_and_their_ancestors() {
        let mut t = demo();
        t.set_filter("umap");
        let labels: Vec<_> = t.visible_rows().iter().map(|r| r.label.as_str()).collect();
        assert!(labels.contains(&"A.umap"));
        assert!(!labels.iter().any(|l| *l == "Hero.uasset"));
        assert!(labels.contains(&"Content") && labels.contains(&"Maps")); // ancestors kept
    }

    #[test]
    fn len_counts_files_not_dirs() {
        assert_eq!(demo().len(), 4);
    }
}
```

- [ ] **Step 2: Run to verify it fails** — `cargo test -p paksmith-gui state::tree` → FAIL.

- [ ] **Step 3: Implement the model.** Build an arena of nodes (`Vec<Node>` with parent/child indices) from the slash-split paths; keep a sorted child order (dirs first, then files, each alphabetical). Maintain an `expanded: HashSet<usize>` and `selected: Option<usize>`. `visible_rows()` is a depth-first walk emitting a `VisibleRow` per node whose ancestors are all expanded; recompute it (or cache + invalidate on mutation) into a `Vec<VisibleRow>`. `set_filter` computes the set of nodes on a path to any file whose full path contains the query (case-insensitive) and restricts the walk to that set (and auto-expands matched ancestors). Keep the public API exactly as in the Interfaces block. Write complete, idiomatic code — this module is pure and must have no Iced imports. (The implementer authors the full arena + walk; the tests above pin every behavior.)

- [ ] **Step 4: Run tests** — `cargo test -p paksmith-gui state::tree` (all PASS). Register `pub mod state;`/`pub mod tree;`.

- [ ] **Step 5: Gates + commit**

```bash
cargo fmt --all && cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
git add crates/paksmith-gui
git commit -m "feat(gui): pure virtualized file-tree model (expand/collapse/select/filter)"
```

---

### Task 7: Archive open — async pipeline + native file dialog

**Files:**
- Create: `crates/paksmith-gui/src/state/archive.rs`
- Create: `crates/paksmith-gui/src/task/open.rs`, `crates/paksmith-gui/src/task/mod.rs`
- Modify: `crates/paksmith-gui/src/app.rs` (real `archive` field, `Message::{OpenRequested, ArchiveOpened}`, wire `update`), `state/mod.rs` (`pub mod archive;`)
- Modify: `crates/paksmith-gui/Cargo.toml` (add `rfd`)

**Interfaces:**
- Consumes: `paksmith_core::profile::resolve::resolve_pak_key` (async, Task 2), `paksmith_core::container::pak::PakReader`, `state::tree::Tree` (Task 6).
- Produces: `state::archive::LoadedArchive { pub path: std::path::PathBuf, pub entry_count: usize, pub decrypted: bool, pub tree: state::tree::Tree }`; `state::archive::OpenError` (thiserror, wraps `PaksmithError` + a `Locked` variant carrying the path); `async fn task::open::run(path: PathBuf) -> Result<LoadedArchive, OpenError>`.

- [ ] **Step 1: Write failing tests** — `OpenError` classification + `LoadedArchive` construction are testable without a window. Use an existing committed fixture (grep `tests/fixtures/*.pak`; a plain unencrypted one):

```rust
// in state/archive.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn open_plain_fixture_populates_tree() {
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent().unwrap().parent().unwrap()
            .join("tests/fixtures/real_v8b_multi.pak"); // plain (unencrypted) multi-entry fixture
        let loaded = crate::task::open::run(fixture).await.unwrap();
        assert!(loaded.entry_count > 0);
        assert_eq!(loaded.tree.len(), loaded.entry_count);
    }
}
```

`real_v8b_multi.pak` is a committed plain (unencrypted) multi-entry fixture used by the CLI `list` tests. For Task 8's manual encrypted check, use `tests/fixtures/real_v8b_encrypted_index.pak` with key `94d25bc3aeb420e0be914edc9d5435a1eaab5f2864e09e94019ac205b727a7de`.

- [ ] **Step 2: Run to verify it fails** — `cargo test -p paksmith-gui task::open` (or `state::archive`) → FAIL.

- [ ] **Step 3: Implement.** Add `rfd`: `cargo add rfd`. `state/archive.rs` defines `LoadedArchive` + `OpenError` (`#[derive(thiserror::Error)]`, variants `Core(#[from] PaksmithError)` and `Locked { path: PathBuf }`). `task/open.rs`:

```rust
//! Async archive-open pipeline: resolve key → open reader → build tree model.

use std::path::PathBuf;

use paksmith_core::container::ContainerReader;
use paksmith_core::container::pak::PakReader;

use crate::state::archive::{LoadedArchive, OpenError};
use crate::state::tree::Tree;

/// Open `path`, auto-resolving an encrypted pak's key via the Phase 5 logic.
pub async fn run(path: PathBuf) -> Result<LoadedArchive, OpenError> {
    // No explicit --aes-key/--game/--detect from the GUI's default open path;
    // resolution falls back to the active profile context (wired in Task 12).
    let key = paksmith_core::profile::resolve::resolve_pak_key(&path, None, None, None).await?;
    let reader = match &key {
        Some(k) => PakReader::open_with_key(&path, k.clone())?,
        None => PakReader::open(&path)?,
    };
    let paths: Vec<String> = reader.entries().map(|e| e.path().to_string()).collect();
    let entry_count = paths.len();
    let tree = Tree::from_paths(paths);
    Ok(LoadedArchive { path, entry_count, decrypted: key.is_some(), tree })
}
```

Reconcile `reader.entries()` / `e.path()` against the actual `ContainerReader`/entry API (grep `fn entries`, `fn path` in `container/pak/`). In `app.rs`: change `archive: Option<LoadedArchive>`; add `Message::OpenRequested` (spawns `rfd` async file picker → `Message::OpenPathChosen(Option<PathBuf>)`) and `Message::ArchiveOpened(Result<LoadedArchive, OpenError>)`; `update` runs `Task::perform(task::open::run(path), Message::ArchiveOpened)`. On `Ok`, store the archive; on `Err(OpenError::Locked{..})`, enter the key-flow (Task 8); on other `Err`, store an error banner string. Use `rfd::AsyncFileDialog` with a `.pak` filter.

- [ ] **Step 4: Run tests** — `cargo test -p paksmith-gui` (the open-fixture test PASS). Manual: `cargo run`, File→Open a plain pak → tree appears (tree rendering lands in Tasks 9–10; for now assert via the test + a debug count in the status area).

- [ ] **Step 5: Gates + commit**

```bash
cargo fmt --all && cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo deny check
git add crates/paksmith-gui Cargo.lock
git commit -m "feat(gui): async archive-open pipeline with native file dialog"
```

---

### Task 8: Encrypted-pak key flow (pure state machine) + key-prompt panel

**Files:**
- Create: `crates/paksmith-gui/src/state/keyflow.rs`, `crates/paksmith-gui/src/panels/key_prompt.rs`, `crates/paksmith-gui/src/panels/mod.rs`
- Modify: `crates/paksmith-gui/src/app.rs` (key-flow messages + integrate), `state/mod.rs`

**Interfaces:**
- Produces: `state::keyflow::KeyFlow` enum (`Idle`, `Resolving`, `Locked { path: PathBuf, error: Option<String> }`, `Unlocked`); methods `fn begin(path)`, `fn lock(path)`, `fn unlock()`, `fn is_locked(&self) -> Option<&Path>`. `panels::key_prompt::view(flow, &str hex_input) -> Element<Message>`.

- [ ] **Step 1: Write failing tests (pure)** — keyflow transitions:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn locks_then_unlocks() {
        let mut f = KeyFlow::Idle;
        f.begin(PathBuf::from("a.pak"));
        assert!(matches!(f, KeyFlow::Resolving));
        f.lock(PathBuf::from("a.pak"));
        assert!(f.is_locked().is_some());
        f.unlock();
        assert!(matches!(f, KeyFlow::Unlocked));
        assert!(f.is_locked().is_none());
    }
}
```

- [ ] **Step 2: Run to verify it fails** — `cargo test -p paksmith-gui state::keyflow` → FAIL.

- [ ] **Step 3: Implement** the pure `KeyFlow` enum + transitions (no Iced). Then `panels/key_prompt.rs::view` renders the Locked-state inline panel: a 🔒 heading, a hex `text_input` (64 chars), a "Use key" button (→ `Message::KeySubmitted`), a "Pick profile…" affordance (→ opens the profile selector from Task 12), and a "Choose install dir…" button (→ `rfd` dir picker → re-run resolution with `detect`). Show `error` text when present. In `app.rs`: add `Message::{KeyInputChanged(String), KeySubmitted, KeyDirChosen(Option<PathBuf>)}`; on submit, parse `AesKey::from_hex`, re-run `task::open::run`-equivalent with the key, transition keyflow. When `OpenError::Locked` arrives (Task 7), `keyflow.lock(path)` and render `key_prompt` over the detail pane.

- [ ] **Step 4: Run tests** — `cargo test -p paksmith-gui state::keyflow` (PASS). Manual: open an encrypted fixture with no matching profile → the locked panel appears; paste the fixture key → it unlocks and the tree populates.

- [ ] **Step 5: Gates + commit**

```bash
cargo fmt --all && cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
git add crates/paksmith-gui
git commit -m "feat(gui): encrypted-pak key-flow state machine + inline key prompt"
```

---

### Task 9: Virtualized file-tree widget

**Files:**
- Create: `crates/paksmith-gui/src/widgets/file_tree.rs`, `crates/paksmith-gui/src/widgets/mod.rs`
- Modify: `crates/paksmith-gui/src/app.rs` (tree messages)

**Interfaces:**
- Consumes: `state::tree::Tree`/`VisibleRow` (Task 6), `theme` (Tasks 4–5).
- Produces: `widgets::file_tree::view(tree: &Tree, accent: iced::Color) -> Element<Message>` emitting `Message::{RowToggled(usize), RowSelected(usize)}`; keyboard handling via `Message::TreeKey(key)`.

- [ ] **Step 1: Behavior test on the model already exists (Task 6).** The widget itself is view code; add a thin test that the row→message mapping helper is correct if you extract one (e.g. a pure `fn row_indent(depth: usize) -> f32` using `tokens::SPACE_MD`):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn indent_grows_with_depth() {
        assert!(row_indent(2) > row_indent(1) && row_indent(1) > row_indent(0));
    }
}
```

- [ ] **Step 2: Run to verify it fails** — `cargo test -p paksmith-gui widgets::file_tree` → FAIL.

- [ ] **Step 3: Implement.** Render the tree as a `scrollable` `column` of rows built from `tree.visible_rows()`. **Virtualization:** for the Phase 6 scope, render the visible-rows `Vec` (already only-expanded nodes, so it's bounded by what's on screen plus expanded siblings); if a single expanded directory can still produce a very large row list, slice to the scroll viewport — wire Iced's `scrollable` viewport/offset (`scrollable::Viewport`) so only the on-screen slice is built into widgets. Each row: indent by `row_indent(depth)`, a folder/file glyph, the `label`, a `button`/`mouse_area` emitting `RowToggled` (dirs) or `RowSelected` (files); the selected row gets an accent-tinted background. Keyboard nav via a `subscription` on key presses → `Message::TreeKey` (Up/Down move selection, Left/Right collapse/expand, Enter select). Reconcile `scrollable`/`mouse_area`/`keyboard::on_key_press` against iced 0.14. Keep `row_indent` (and any other pure helper) unit-tested.

- [ ] **Step 4: Run tests** — `cargo test -p paksmith-gui widgets` (PASS). Manual: open a pak → tree scrolls smoothly; expand/collapse/select work by mouse and keyboard.

- [ ] **Step 5: Gates + commit**

```bash
cargo fmt --all && cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
git add crates/paksmith-gui
git commit -m "feat(gui): virtualized file-tree widget with keyboard navigation"
```

---

### Task 10: Panels + two-pane layout

**Files:**
- Create: `crates/paksmith-gui/src/panels/{toolbar.rs,sidebar.rs,detail.rs,status_bar.rs}`
- Modify: `crates/paksmith-gui/src/app.rs` (`view` composes the layout; `sidebar_ratio` state + resize message)

**Interfaces:**
- Consumes: all prior view modules + `LoadedArchive`/`Tree`.
- Produces: `panels::toolbar::view`, `panels::sidebar::view`, `panels::detail::view`, `panels::status_bar::view`; `Message::SidebarResized(f32)`.

- [ ] **Step 1: Write failing test** — extract the detail-pane metadata formatting as a pure helper and test it (so the panel has a tested core):

```rust
// panels/detail.rs
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn formats_size_human_readable() {
        assert_eq!(human_size(2_400_000), "2.4 MB");
        assert_eq!(human_size(512), "512 B");
    }
}
```

- [ ] **Step 2: Run to verify it fails** — `cargo test -p paksmith-gui panels::detail` → FAIL.

- [ ] **Step 3: Implement.** `detail.rs` exposes `human_size(bytes: u64) -> String` (tested) and `view(selected_meta) -> Element` showing path/size/compression/offset/SHA1/encryption for the selected entry (metadata only — Phase 7 fills the preview). `toolbar.rs`: Open button (→ `OpenRequested`), a decryption-status pill (🔒/🔓 from `LoadedArchive.decrypted`), and a filter `text_input` (→ `Message::FilterChanged` → `tree.set_filter`). `status_bar.rs`: file name, `entry_count`, selected summary, and memory usage (a best-effort process-RSS read; if no cheap cross-platform source exists, omit memory and note it — don't add a heavy dep for it). `sidebar.rs`: hosts the `file_tree` widget with a draggable divider — track `sidebar_ratio: f32` in `App`, a `mouse_area`/drag on the divider emits `SidebarResized`. `app.rs` `view`: a `column![ menu-area, toolbar, row![ sidebar (ratio), detail (1-ratio) ], status_bar ]`. Empty/locked/error states render in the detail area. Reconcile widgets against iced 0.14.

- [ ] **Step 4: Run tests** — `cargo test -p paksmith-gui panels` (PASS). Manual: the full two-pane shell renders; sidebar resizes; selecting an entry shows its metadata; filter narrows the tree.

- [ ] **Step 5: Gates + commit**

```bash
cargo fmt --all && cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
git add crates/paksmith-gui
git commit -m "feat(gui): two-pane explorer+detail layout (toolbar, sidebar, detail, status bar)"
```

---

### Task 11: Native menu bar (muda)

**Files:**
- Create: `crates/paksmith-gui/src/menu.rs`
- Modify: `crates/paksmith-gui/src/main.rs` (build the menu, route events), `app.rs` (menu → messages)
- Modify: `crates/paksmith-gui/Cargo.toml` (add `muda`)

**Interfaces:**
- Produces: `menu::build() -> muda::Menu`; a mapping from `muda::MenuId` → `Message` (File→Open, File→Quit, View→Toggle Theme, Help→About).

- [ ] **Step 1: Write failing test** — the id→message mapping is pure:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn open_id_maps_to_open_message() {
        assert!(matches!(message_for(MenuAction::Open), crate::app::Message::OpenRequested));
    }
}
```

(Define a small `MenuAction` enum so the mapping is testable without constructing real `muda` ids.)

- [ ] **Step 2: Run to verify it fails** — `cargo test -p paksmith-gui menu` → FAIL.

- [ ] **Step 3: Implement.** Add `muda`: `cargo add muda`. Build a `muda::Menu` with File (Open ⌘/Ctrl-O, Quit), View (Toggle Theme), Help (About). On macOS, `muda` installs the global menu bar (init in `main` before the event loop / via the winit hook muda documents for the platform); on Windows/Linux attach it to the window. Route `muda::MenuEvent` → `MenuAction` → `crate::app::Message` (use a `subscription` or the muda event channel bridged into Iced messages). Keep `message_for(MenuAction) -> Message` pure + tested. Reconcile muda's Iced/winit integration against the resolved versions (muda exposes a global `MenuEvent::receiver()`; bridge it via an Iced `subscription` that polls/streams the channel).

- [ ] **Step 4: Run tests** — `cargo test -p paksmith-gui menu` (PASS). Manual: the native menu bar appears (global bar on macOS), File→Open works, ⌘O / Ctrl-O works, Toggle Theme flips light/dark.

- [ ] **Step 5: Gates + commit**

```bash
cargo fmt --all && cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo deny check
git add crates/paksmith-gui Cargo.lock
git commit -m "feat(gui): native menu bar via muda"
```

---

### Task 12: Game-profile selector in the toolbar

**Files:**
- Modify: `crates/paksmith-gui/src/panels/toolbar.rs` (profile dropdown), `app.rs` (active-profile state + plumb into open/resolution)
- Create: `crates/paksmith-gui/src/state/profiles.rs` (load the selectable profile list)

**Interfaces:**
- Consumes: `paksmith_core::ProfileStore`, `paksmith_core::profile::resolve::{detect_matches}` / cached registry.
- Produces: `state::profiles::available() -> Vec<ProfileChoice>` (`ProfileChoice { id: String, name: String }`, local + cached registry, deduped local-wins); `App.active_game: Option<String>`; the open pipeline passes `active_game` as the `game` arg to `resolve_pak_key`.

- [ ] **Step 1: Write failing test** — the dedup/merge of local + cached registry profiles must be tested through a PURE seam (no env-setting — same convention as Task 1's `detect_in`). Add a core helper `pub fn available_profiles() -> crate::Result<Vec<DetectMatch>>` that loads store+cache and delegates to a pure `pub(crate) fn available_in(store: &ProfileStore, cache: Option<&RegistryCache>) -> Vec<DetectMatch>` (reusing `DetectMatch{id,name,source}` — every stored/cached profile, local shadowing registry by id; NOT filtered by detect rules, unlike `detect_in`). Test `available_in` with a hand-built `ProfileStore`/`RegistryCache`:

```rust
// in paksmith-core profile/resolve.rs tests
#[test]
fn available_in_lists_local_then_unshadowed_registry() {
    use crate::GameProfile;
    let mut store = ProfileStore::default();
    store.profiles.insert("local1".into(), GameProfile { name: "L1".into(), engine_version: None, keys: Default::default(), detect: None });
    store.profiles.insert("shared".into(), GameProfile { name: "Local".into(), engine_version: None, keys: Default::default(), detect: None });
    let cache = RegistryCache {
        fetched_at_unix: 0,
        doc: crate::profile::registry::RegistryDoc { profiles: vec![
            crate::profile::registry::RegistryProfile { id: "shared".into(), name: "Reg".into(), engine_version: None, keys: Default::default(), detect: None },
            crate::profile::registry::RegistryProfile { id: "reg1".into(), name: "R1".into(), engine_version: None, keys: Default::default(), detect: None },
        ]},
    };
    let got = available_in(&store, Some(&cache));
    let ids: Vec<_> = got.iter().map(|m| m.id.as_str()).collect();
    assert!(ids.contains(&"local1") && ids.contains(&"reg1"));
    assert_eq!(got.iter().filter(|m| m.id == "shared").count(), 1); // local shadows registry
}
```

The GUI's `state::profiles::available()` then calls `paksmith_core::profile::resolve::available_profiles()` and maps to `ProfileChoice{id,name}` — no cache internals leak to the GUI.

- [ ] **Step 2: Run to verify it fails** — `cargo test -p paksmith-gui state::profiles` → FAIL.

- [ ] **Step 3: Implement** `available()` (load `ProfileStore` + `load_cache_lenient` analog via core; emit `ProfileChoice`s, local shadowing registry by id — same rule as `detect_matches`). Add a `pick_list` (or styled dropdown) to the toolbar bound to `App.active_game` → `Message::GameSelected(Option<String>)`. Thread `active_game` into `task::open::run` (add a `game: Option<String>` param) so resolution uses the selected profile; the key-prompt's "Pick profile…" also sets `active_game` and re-resolves. Expose a core helper if `load_cache_lenient` must be reachable (it's `pub(crate)` in core — add a thin `pub fn available_profiles()` in `profile::resolve` returning `Vec<(String, String)>` rather than leaking cache internals to the GUI). Prefer adding `pub fn available_profiles() -> crate::Result<Vec<DetectMatch>>`-style API to core and consuming that.

- [ ] **Step 4: Run tests** — `cargo test -p paksmith-gui state::profiles` (PASS) + `cargo test -p paksmith-core` (if a core helper was added). Manual: the dropdown lists profiles; selecting one and opening an encrypted pak for that game unlocks it automatically.

- [ ] **Step 5: Gates + commit**

```bash
cargo fmt --all && cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
git add crates/paksmith-gui crates/paksmith-core
git commit -m "feat(gui): game-profile selector wired into key resolution"
```

---

### Task 13: ROADMAP + full gate chain + mutants

**Files:**
- Modify: `docs/plans/ROADMAP.md`

- [ ] **Step 1: ROADMAP.** Mark **Phase 6 (GUI Shell)** shipped; update the summary-table row to ✓ complete and the Phase 6 section's status to describe what landed (native Iced shell, two-pane explorer, virtualized lazy tree, auto light/dark + system accent, native menus/dialogs, Phase 5 key flow). Factual; no engine-source references. (If the Phase 4 row is still stale per earlier note, leave it unless the user asked — keep this PR scoped.)

- [ ] **Step 2: Full gate chain (each UNPIPED)**

```bash
cargo fmt --all && cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
typos .
cargo deny check
cargo +1.88 check -p paksmith-gui -p paksmith-core   # MSRV
```

- [ ] **Step 3: cargo-mutants to 0-missed** — `git diff $(git merge-base origin/main HEAD)..HEAD > /tmp/pr.diff && cargo mutants --in-diff /tmp/pr.diff --no-shuffle -j 2 --all-features 2>&1 | tail -25` → 0 missed. The pure models (`tree`, `keyflow`, accent fallback, `human_size`, `row_indent`, the core resolve helpers) are where mutants bite — kill survivors with unit tests; document any genuinely-equivalent exclusion in `.cargo/mutants.toml`. View-only code that cargo-mutants can't meaningfully mutate needs no test.

- [ ] **Step 4: Fixture-count gate** — Phase 6 adds NO `.pak` fixtures (it reuses existing ones). Confirm `find tests/fixtures -maxdepth 1 -name '*.pak' | wc -l` equals the `expected=` in `.github/workflows/ci.yml`.

- [ ] **Step 5: Commit**

```bash
git add docs/plans/ROADMAP.md
git commit -m "docs(roadmap): mark phase 6 (GUI shell) shipped"
```

---

## Review & Push

- Adversarial whole-branch panel with a **standing UI/UX design reviewer** (visual hierarchy, spacing rhythm, affordance/feedback, keyboard nav, WCAG-AA contrast in both themes, native-convention adherence, complete empty/loading/locked/error states — "looks amateur" blocks) + code-reviewer + architect + simplifier + security (the open pipeline reads user-chosen files; the key flow handles AES material — no key in logs/UI beyond the single intentional hex field) + a **deep-impact tracer** (the Task 1/2 `resolve_pak_key` async signature ripple across the CLI's four commands + the new public core API) + a **performance** reviewer (the virtualized tree render path).
- Cycle to convergence; re-dispatch the full panel after each fix commit.
- Verify gates personally; run cargo-mutants to 0-missed; touch the convergence marker (separate Bash call); push; open PR (`gh --body-file`); Monitor CI to green (watch the ubuntu/macOS/windows matrix — the per-OS accent code builds on each). Do NOT merge — the user merges.

---

## Self-Review (plan vs spec)

**Spec coverage:**
- Two-pane Explorer+Detail layout → Task 10. ✓
- Native, platform-adaptive (maximal): native window (iced/winit, free) → Task 3; native menus (muda) → Task 11; native dialogs (rfd) → Task 7; auto light/dark → Task 4; per-OS system accent → Task 5; system fonts/spacing → Tasks 4/10. ✓
- Auto-resolve-then-prompt key flow → Tasks 7 (resolve) + 8 (locked prompt) + 12 (profile selector). ✓
- Virtualized lazy file tree (pure model) → Task 6 (model) + Task 9 (widget). ✓
- Detail pane = metadata only (Phase 7 host) → Task 10. ✓
- Core refactor (extract resolve orchestration, async, CLI thin wrapper) → Tasks 1–2. ✓
- Resizable sidebar + filter field → Task 10. ✓
- Pure/testable state-model architecture → Tasks 6/8/12 (pure), reducers in app.rs. ✓
- Error handling: no blank screens, typed errors, encrypted-is-a-state → Tasks 7/8/10. ✓
- UI/UX reviewer standing + per-OS CI coverage + gate chain + mutants → Task 13 + Review section. ✓
- gui in default-members, deny review, no version bumps → Global Constraints + per-task deny steps. ✓
- ROADMAP / Phase 6 complete → Task 13. ✓

**Type consistency:** `DetectMatch{id,name,source}` (T1) reused (T12); `resolve_pak_key(path,aes_key,game,detect)->Result<Option<AesKey>>` async core (T2) / sync CLI wrapper (T2) / consumed by `task::open::run` (T7,T12); `Tree`/`VisibleRow` (T6) consumed by widget (T9) + archive (T7); `KeyFlow` (T8); `LoadedArchive{path,entry_count,decrypted,tree}` (T7) consumed by panels (T10); `Message` grows additively per task (Noop→Open/Archive→Key→Tree→Filter/Resize→Menu→Game) — each task names the variants it adds.

**Open reconciliation points (flagged in-task, resolve against resolved deps — do NOT guess):** the exact iced 0.14 widget/builder API (every view task says "reconcile"); `dark_light::detect()` return shape (T4); the per-OS accent crate APIs + versions (T5); `reader.entries()/e.path()` (T7); muda↔Iced/winit event bridging (T11); the `PAKSMITH_CONFIG_DIR` test-seeding mechanism (T1 — mirror the existing repo pattern). These are framework-surface specifics the implementer pins at build time; the interfaces, message flow, and pure-model behavior are fully specified here.
