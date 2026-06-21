# Phase 5d — Game Auto-Detection Design

**Status:** approved (brainstorming), pre-implementation
**Date:** 2026-06-20
**Roadmap:** Phase 5 (Game Profiles) — sub-phase 5d (auto-detection). **Completes Phase 5.**

## Context

Phase 5 decomposes into **5a AES decryption → 5b local profiles + key management
→ 5c remote signed registry → 5d auto-detection**. 5a–5c have shipped: a profile
store (`GameProfile`), guid→key resolution, the `profile` CLI, a global `--game`
flag, and a signed remote registry with an offline-degrading cache. This document
specifies **5d only** — the last sub-phase.

A `GameProfile`/`RegistryProfile` today holds `{name, engine_version, keys}`. It
has no way to recognise its own game on disk: the user must know the profile id
and pass `--game <id>`. 5d adds **declarative detection rules** to the profile
schema and an engine that, given a game-install directory, reports which
profile(s) match — exposed as `paksmith profile detect <dir>` and a `--detect
<dir>` resolution flag. Because detection rules live on the profile, the
community registry **ships** them, so `profile fetch` makes auto-detect work
out-of-the-box for known games.

## Goals / non-goals

- **Goal:** identify the game for a directory via declarative marker-path +
  file-content rules; a `profile detect <dir>` query (lists all matches) and a
  `--detect <dir>` flag that resolves the detected game's key (exactly-one
  match required).
- **Non-goal:** executable binary-signature scanning (fragile across game
  updates, heavy, an arbitrary-binary-read surface — deferred); a CLI to *set*
  local detection rules (hand-edit `profiles.toml` or rely on the registry —
  `profile add` is unchanged); confidence ranking / auto-picking among ambiguous
  matches (resolution requires a single unambiguous match); any further Phase 5
  work (5d completes Phase 5).

## Decisions (from brainstorming)

- **Rule kinds:** marker `require_paths` (relative file/dir paths that must ALL
  exist) + optional `contains` rules (a relative file must exist and hold a
  substring). No exe-signatures.
- **Match semantics:** a profile matches iff **all** `require_paths` exist AND
  **all** `contains` rules pass (logical AND). No rules → never auto-detected.
- **Exposure:** `profile detect <dir>` (lists every match) + a global
  `--detect <dir>` flag (resolution; requires exactly one match).
- **Ambiguity:** the query lists 0/1/many; resolution errors on 0 ("no game
  matched") or >1 ("matched N games: …; pass --game"). Never silently guesses.
- **Precedence:** `--aes-key` > `--game` > `--detect` (explicit beats auto).

## Security (mandatory security-reviewer surface)

Detection rules come partly from the **untrusted registry**, and detection
**reads the filesystem** at a user-supplied directory. The threats + defenses:

- **Path traversal / absolute escape:** `require_paths` and `contains.path` are
  **relative** and joined onto the target dir. Reject any rule whose path is
  absolute or contains a `..` component (a parent-dir reference) or a root/drive
  prefix — a malicious registry rule must not be able to test for `/etc/passwd`
  or read `../../secret`. Normalize + validate each path component before any FS
  access; a rule with an invalid path **fails to match** (it does not error the
  whole detection, and never escapes the dir).
- **Unbounded read on `contains`:** reading a file to substring-search is capped
  — read at most a bounded prefix (e.g. `MAX_CONTAINS_READ = 1 MiB`) and search
  within it (do not slurp a multi-GB file). Read-only; a missing/unreadable file
  → the rule does not match (not an error).
- **Strict registry parse caps (extends 5c):** the new `detect` field is
  size-capped on the untrusted fetch + cache-load paths: bounded
  `require_paths` count, `contains` count, and per-string length (id/path/
  substring), consistent with the existing `MAX_PROFILES`/`MAX_STR` caps.
- **No symlink escape:** detection uses ordinary `std::fs` existence/read on the
  joined path; document that symlinks inside the target dir are followed as the
  OS would (the target dir is user-chosen, within the user's trust boundary —
  the registry rule only supplies the *relative tail*, which is traversal-
  guarded). No `..`-based escape is possible after the path-component validation.
- No AES key material is involved in detection; the existing `AesKey` redaction
  invariants are untouched.

## Data model

```rust
/// Declarative rules that recognise a game's install directory. All present
/// (AND); a profile with no rules is never auto-detected.
pub struct DetectRules {
    /// Relative paths (file OR dir) that must ALL exist under the target dir.
    pub require_paths: Vec<String>,
    /// Optional "file contains substring" rules; all must pass.
    pub contains: Vec<ContainsRule>,
}
pub struct ContainsRule {
    /// Relative path to a file under the target dir.
    pub path: String,
    /// Substring that file must contain (within the first MAX_CONTAINS_READ bytes).
    pub substring: String,
}
```

- Added as `detect: Option<DetectRules>` on both `GameProfile` (mod.rs) and
  `RegistryProfile` (registry.rs). `#[serde(default, skip_serializing_if =
  "Option::is_none")]` so existing profiles round-trip unchanged.
- Caps (consts): `MAX_REQUIRE_PATHS`, `MAX_CONTAINS`, reuse `MAX_STR` (256) for
  path/substring length; `MAX_CONTAINS_READ = 1 MiB`.

## Architecture

```
crates/paksmith-core/src/profile/detection.rs   # CREATE: DetectRules/ContainsRule + matcher + path validation
crates/paksmith-core/src/profile/mod.rs          # MODIFY: GameProfile gains `detect`; register `pub mod detection`
crates/paksmith-core/src/profile/registry.rs     # MODIFY: RegistryProfile gains `detect`; validate_caps covers it
crates/paksmith-core/src/error.rs                # MODIFY: ProfileFault detection variants (if any beyond reuse)
crates/paksmith-cli/src/commands/profile.rs       # MODIFY: `profile detect <dir>` subcommand
crates/paksmith-cli/src/commands/key_resolve.rs   # MODIFY: `--detect` → detected id → existing resolution
crates/paksmith-cli/src/main.rs                   # MODIFY: global `--detect <dir>` flag
docs/plans/ROADMAP.md                             # MODIFY: mark 5d shipped / Phase 5 complete
```

### Component 1 — `detection.rs` (engine, core)

```rust
/// True iff `rules` match the install directory `dir`. Read-only, bounded.
pub fn rules_match(dir: &Path, rules: &DetectRules) -> bool;

/// Validate + join a rule's relative path onto `dir`. Returns `None` if the
/// path is absolute, has a `..`/root component, or is empty — such a rule
/// cannot match (no FS access on an invalid path).
fn safe_join(dir: &Path, rel: &str) -> Option<PathBuf>;
```

- `rules_match`: every `require_paths` entry → `safe_join` then `Path::exists`
  (file or dir); every `contains` → `safe_join`, read ≤ `MAX_CONTAINS_READ`
  bytes, substring search. Any invalid-path / missing-file / cap-miss → that
  rule fails → no match. Empty `require_paths` AND empty `contains` → does NOT
  match (a profile with no rules is never auto-detected — guard this).
- A CLI-facing helper to run detection across a profile set:
  `detect_matches<'a>(dir, locals: &'a [(id, &GameProfile)], cached: &'a [&RegistryProfile]) -> Vec<DetectMatch<'a>>` returning the matched ids + display names (local + registry, deduped by id, local wins) — or the CLI assembles this from `rules_match` over the layered profile set (resolve at implementation; reuse 5c's `ResolvedProfile`/cache where natural).

### Component 2 — CLI `profile detect <dir>`

`paksmith profile detect <dir>`: load local `ProfileStore` + the cached registry
(via the 5c `load_cache_lenient`); for each profile with `detect` rules, run
`rules_match`; print every match (`<id>\t<name>\t[local|registry]`), or "no
profiles matched". Exit 0 (a no-match query is not an error).

### Component 3 — `--detect <dir>` resolution

A `#[arg(long, global = true)]` `detect: Option<PathBuf>` on `Cli` (sibling of
`--game`/`--aes-key`). In `resolve_pak_key` (key_resolve.rs), after the existing
`--aes-key` (wins) and `--game` (explicit id) handling: if `--detect <dir>` is
set and `--game`/`--aes-key` are not, run detection; **exactly one** match → feed
that id into the existing `--game` resolution path (local → cache → auto-fetch →
key); **zero** → a clear `Profile`/`InvalidArgument` error ("no game matched
`<dir>`"); **>1** → an error listing the matches ("matched N games: a, b — pass
--game to disambiguate"). `--game` + `--detect` together → `--game` wins (a
`debug!` notes the override), consistent with `--aes-key` > `--game`.

## Error handling / exit codes

- New typed `ProfileFault` variants as needed: `DetectionAmbiguous { dir, ids }`,
  `DetectionNoMatch { dir }` (Display lists ids / the dir; no secrets). Bad
  `--detect` path that doesn't exist → `InvalidArgument` (exit 2). Resolution
  failures exit non-zero; the `detect` query exits 0 even on no match.
- No key material in any detection error/log.

## Testing

- **Unit (`detection.rs`):** `rules_match` over `tempfile::tempdir()` synthetic
  trees — all markers present → match; one missing → no match; `contains` pass /
  file-missing / substring-absent; **path-traversal (`../x`, `/abs`, `C:\\x`,
  empty) rejected → rule fails (no escape, no panic)**; oversized `contains`
  file → bounded read (substring beyond the cap not found); empty rules → never
  matches; `safe_join` validation table.
- **Registry caps:** the strict-parse + `validate_caps` reject an oversized
  `detect` (too many require_paths/contains, overlong strings) on fetch AND
  cache-load.
- **Serde:** `GameProfile`/`RegistryProfile` with + without `detect` round-trip
  (TOML + JSON); absent `detect` omitted from output.
- **CLI:** `profile detect <dir>` lists local + registry matches (synthetic dir +
  a profile with rules; via `PAKSMITH_CONFIG_DIR`); ambiguous → both listed;
  `--detect <dir>` resolves a single match's key (decrypts the v8b fixture via a
  profile whose default key is the fixture key), errors on zero / ambiguous,
  `--game` overrides `--detect`, `--detect` on a non-existent dir → exit 2.
- Reuses existing fixtures (synthetic dirs are tempdirs, not `.pak` fixtures) →
  the CI fixture-count gate is untouched.

## Build notes / risks

- **No new deps** (pure `std::fs` + the existing serde/toml). No MSRV concern.
- `validate_caps` (5c) must be extended to cover `detect` on both
  `GameProfile`-via-store and `RegistryProfile` paths — keep the cap logic in
  one place.
- Run `cargo mutants --in-diff` to 0-missed locally before the final push (the
  PR-diff job is not in the local gate chain — it surfaced post-push on
  5a/5b/5c). Expect survivors on the path-validation + match logic; kill via
  unit tests, exclude only genuine equivalents.
- The 5c `--detect` precedence threads through the same `resolve_pak_key`
  signature change touched in 5b/5c — a deep-impact surface (all four container
  commands) to re-verify.

## Scope boundary

5d ships declarative path/content auto-detection + `profile detect` + `--detect`,
completing Phase 5. Executable-signature detection and a local-rule-authoring CLI
are explicitly out of scope; if ever wanted they are additive follow-ups.
