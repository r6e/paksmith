# Phase 4c — `paksmith search` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `paksmith search <pak>` — a fast index-only entry query with composable AND predicates (`--type` extension, `--name` basename glob, `--regex` full-path regex, `--min/--max-size`), reusing `list`'s entry renderer. No asset parsing.

**Architecture:** A thin `commands/search.rs` (args + `run`) builds a pure `Predicates` (from `search/mod.rs`), walks `reader.entries()` keeping matches, and prints them via the existing `crate::output::print_entries`. `paksmith-core` is untouched.

**Tech Stack:** Rust, `clap`, `glob` (existing), `regex` (new), `serde_json`; tests via `assert_cmd`, `predicates`, `tempfile`.

**Spec:** `docs/superpowers/specs/2026-06-19-phase-4c-search-design.md`

## Global Constraints

- **MSRV:** workspace `rust-version` (1.88). No newer/unstable syntax — `let-else`, not `if let` match guards.
- **`paksmith-core` is NOT modified.** Search is a pure index walk — no asset parsing.
- **No panics in core** (CLI-only; CLI uses typed `PaksmithError`; no `unwrap`/`expect` on fallible paths).
- **Predicates AND-combine**; `--type` is repeatable with OR-within; no predicates = all entries.
- **`--name` globs the BASENAME; `--regex` matches the FULL path (unanchored).** Sizes filter **uncompressed** size, accept human units (`1MB`=10⁶, `1MiB`=2²⁰, bare int = bytes), integers only.
- **Exit codes:** `0` success (including zero matches); `2` usage errors (bad glob/regex, unparsable size, `--min-size` > `--max-size`). BrokenPipe clean-exit (via `print_entries` + `?`).
- **`search::run` returns `paksmith_core::Result<()>`**, wrapped by `Self::Search(args) => search::run(args, format).map(|()| 0)` in `commands/mod.rs`.
- **Only ONE new dependency:** `regex` (size parsing is internal `parse_size`, no `bytesize` crate). `cargo deny` must stay green.
- **Conventional commits**, one logical change each.
- **Pre-push gates:** `cargo fmt --all`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace --all-features`, `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features`, `typos .`.
- **Review:** adversarial multi-agent panel (≥3 + specialists) to convergence before push. No new `.pak` fixture (CI fixture-count gate untouched).

---

## File Structure

```
crates/paksmith-cli/Cargo.toml               # MODIFY: add regex
crates/paksmith-cli/src/main.rs              # MODIFY: add `mod search;`
crates/paksmith-cli/src/commands/mod.rs      # MODIFY: register Search subcommand
crates/paksmith-cli/src/commands/search.rs   # CREATE: SearchArgs + run()
crates/paksmith-cli/src/search/mod.rs         # CREATE: Predicates, matches(), parse_size(), extension_of()
crates/paksmith-cli/tests/search_cli.rs       # CREATE: integration tests
```

---

## Task 1: Add `regex` + `search` subcommand skeleton

**Files:**
- Modify: `crates/paksmith-cli/Cargo.toml` (add `regex`)
- Modify: `crates/paksmith-cli/src/main.rs` (add `mod search;`)
- Modify: `crates/paksmith-cli/src/commands/mod.rs` (register `Search`)
- Create: `crates/paksmith-cli/src/commands/search.rs` (args + stub run)
- Create: `crates/paksmith-cli/src/search/mod.rs` (empty module placeholder)
- Create: `crates/paksmith-cli/tests/search_cli.rs` (--help test)

**Interfaces:**
- Produces: `commands::search::SearchArgs` (clap `Args`) and `commands::search::run(args: &SearchArgs, format: OutputFormat) -> paksmith_core::Result<()>`.

- [ ] **Step 1: Add the dependency**

In `crates/paksmith-cli/Cargo.toml` `[dependencies]`, append:

```toml
regex = "1"
```

- [ ] **Step 2: Write the failing --help test**

Create `crates/paksmith-cli/tests/search_cli.rs`:

```rust
#![allow(missing_docs)]
use assert_cmd::Command;

#[test]
fn search_help_lists_flags() {
    let assert = Command::cargo_bin("paksmith").unwrap()
        .args(["search", "--help"]).assert().success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    for flag in ["--type", "--name", "--regex", "--min-size", "--max-size"] {
        assert!(out.contains(flag), "help missing {flag}");
    }
}
```

- [ ] **Step 3: Run — verify it fails**

Run: `cargo test -p paksmith-cli --test search_cli search_help_lists_flags`
Expected: FAIL — `search` subcommand does not exist.

- [ ] **Step 4: Create the args + stub run**

Create `crates/paksmith-cli/src/commands/search.rs`:

```rust
//! `paksmith search <pak>` — query archive entries by extension, name
//! (basename glob), full-path regex, and uncompressed size range. Index-only;
//! no asset parsing.

use std::path::PathBuf;

use clap::Args;

use crate::output::OutputFormat;

#[derive(Args)]
pub(crate) struct SearchArgs {
    /// Path to the .pak file.
    pub(crate) pak: PathBuf,

    /// Match entries whose file extension is any of these (repeatable,
    /// case-insensitive, no leading dot). e.g. `--type uasset --type umap`.
    #[arg(long, value_name = "EXT")]
    pub(crate) r#type: Vec<String>,

    /// Glob matched against the entry BASENAME (filename), e.g. `Hero*`.
    #[arg(long, value_name = "GLOB")]
    pub(crate) name: Option<String>,

    /// Regex matched against the FULL virtual path (unanchored).
    #[arg(long, value_name = "RE")]
    pub(crate) regex: Option<String>,

    /// Minimum uncompressed size (e.g. `1MB`, `512KiB`, `1048576`).
    #[arg(long, value_name = "SIZE")]
    pub(crate) min_size: Option<String>,

    /// Maximum uncompressed size (e.g. `10MB`).
    #[arg(long, value_name = "SIZE")]
    pub(crate) max_size: Option<String>,
}

#[allow(clippy::unnecessary_wraps, reason = "stub; real logic + fallible ops land in Task 4")]
pub(crate) fn run(_args: &SearchArgs, _format: OutputFormat) -> paksmith_core::Result<()> {
    Ok(())
}
```

(`r#type` is the raw identifier for the reserved word `type`; clap derives the flag name `--type` from it.)

- [ ] **Step 5: Register the subcommand + module**

In `crates/paksmith-cli/src/main.rs`, add alongside the other `mod` lines:

```rust
mod search;
```

Create `crates/paksmith-cli/src/search/mod.rs` (placeholder, filled in Tasks 2-3):

```rust
//! Search predicate compilation + matching (pure; no I/O).
```

In `crates/paksmith-cli/src/commands/mod.rs`:

```rust
pub(crate) mod extract;
pub(crate) mod inspect;
pub(crate) mod list;
pub(crate) mod search;

use clap::Subcommand;

use crate::output::OutputFormat;

#[derive(Subcommand)]
pub(crate) enum Command {
    /// List archive contents
    List(list::ListArgs),
    /// Dump a uasset's structural header as JSON
    Inspect(inspect::InspectArgs),
    /// Extract and convert archive contents to disk
    Extract(extract::ExtractArgs),
    /// Query archive entries by type, name, regex, and size
    Search(search::SearchArgs),
}

impl Command {
    pub(crate) fn run(&self, format: OutputFormat) -> paksmith_core::Result<u8> {
        match self {
            Self::List(args) => list::run(args, format).map(|()| 0),
            Self::Inspect(args) => inspect::run(args, format).map(|()| 0),
            Self::Extract(args) => extract::run(args, format),
            Self::Search(args) => search::run(args, format).map(|()| 0),
        }
    }
}
```

- [ ] **Step 6: Run — verify it passes**

Run: `cargo test -p paksmith-cli --test search_cli` and `cargo test -p paksmith-cli` (existing tests unaffected).
Expected: PASS.

- [ ] **Step 7: fmt + clippy + deny**

Run: `cargo fmt --all`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`; if `cargo deny` is available, `cargo deny check 2>&1 | tail -20` and report any new license/advisory flag from `regex`'s transitive deps as a concern (regex = MIT/Apache; typically clean).

- [ ] **Step 8: Commit**

```bash
git add crates/paksmith-cli/Cargo.toml crates/paksmith-cli/src/main.rs \
        crates/paksmith-cli/src/commands/mod.rs crates/paksmith-cli/src/commands/search.rs \
        crates/paksmith-cli/src/search/mod.rs crates/paksmith-cli/tests/search_cli.rs
git commit -m "feat(cli): add search subcommand skeleton + regex dep"
```

---

## Task 2: `parse_size` (human size → bytes)

**Files:**
- Modify: `crates/paksmith-cli/src/search/mod.rs`

**Interfaces:**
- Produces: `pub(crate) fn parse_size(s: &str) -> Result<u64, String>`

- [ ] **Step 1: Write the failing unit tests**

Append to `crates/paksmith-cli/src/search/mod.rs`:

```rust
#[cfg(test)]
mod parse_size_tests {
    use super::*;

    #[test]
    fn bare_integer_is_bytes() {
        assert_eq!(parse_size("1048576").unwrap(), 1_048_576);
        assert_eq!(parse_size("0").unwrap(), 0);
    }

    #[test]
    fn decimal_units_are_powers_of_1000() {
        assert_eq!(parse_size("1KB").unwrap(), 1_000);
        assert_eq!(parse_size("1MB").unwrap(), 1_000_000);
        assert_eq!(parse_size("2GB").unwrap(), 2_000_000_000);
    }

    #[test]
    fn binary_units_are_powers_of_1024() {
        assert_eq!(parse_size("1KiB").unwrap(), 1_024);
        assert_eq!(parse_size("1MiB").unwrap(), 1_048_576);
    }

    #[test]
    fn case_and_space_insensitive() {
        assert_eq!(parse_size("1 mb").unwrap(), 1_000_000);
        assert_eq!(parse_size("512kib").unwrap(), 512 * 1024);
        assert_eq!(parse_size("1B").unwrap(), 1);
    }

    #[test]
    fn rejects_bad_input() {
        assert!(parse_size("").is_err());
        assert!(parse_size("MB").is_err());        // no number
        assert!(parse_size("1.5MB").is_err());     // decimals not supported
        assert!(parse_size("1ZB").is_err());       // unknown unit
        assert!(parse_size("abc").is_err());
    }

    #[test]
    fn overflow_errors() {
        assert!(parse_size("99999999999999999999TiB").is_err());
    }
}
```

- [ ] **Step 2: Run — verify it fails**

Run: `cargo test -p paksmith-cli parse_size`
Expected: FAIL — `parse_size` not defined.

- [ ] **Step 3: Implement `parse_size`**

Add above the test module:

```rust
/// Parse a human-readable size into bytes. Accepts a bare integer (bytes),
/// decimal units `KB`/`MB`/`GB`/`TB` (powers of 1000), and binary units
/// `KiB`/`MiB`/`GiB`/`TiB` (powers of 1024). Case-insensitive; an optional
/// space is allowed before the unit. Integers only (no decimals).
pub(crate) fn parse_size(s: &str) -> Result<u64, String> {
    let t = s.trim();
    if t.is_empty() {
        return Err("empty size".to_string());
    }
    // The numeric prefix is leading ASCII digits; the rest is the unit.
    let split = t.find(|c: char| !c.is_ascii_digit()).unwrap_or(t.len());
    let (num_str, unit_raw) = t.split_at(split);
    if num_str.is_empty() {
        return Err(format!("size '{s}' has no numeric value"));
    }
    let unit = unit_raw.trim().to_ascii_lowercase();
    let multiplier: u64 = match unit.as_str() {
        "" | "b" => 1,
        "kb" => 1_000,
        "mb" => 1_000_000,
        "gb" => 1_000_000_000,
        "tb" => 1_000_000_000_000,
        "kib" => 1 << 10,
        "mib" => 1 << 20,
        "gib" => 1 << 30,
        "tib" => 1 << 40,
        other => return Err(format!("size '{s}' has unknown unit '{other}'")),
    };
    let value: u64 = num_str
        .parse()
        .map_err(|_| format!("size '{s}' has an invalid number '{num_str}'"))?;
    value
        .checked_mul(multiplier)
        .ok_or_else(|| format!("size '{s}' overflows u64"))
}
```

- [ ] **Step 4: Run — verify it passes**

Run: `cargo test -p paksmith-cli parse_size`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/paksmith-cli/src/search/mod.rs
git commit -m "feat(cli): add human-readable size parser for search"
```

---

## Task 3: `Predicates` — compile + match

**Files:**
- Modify: `crates/paksmith-cli/src/search/mod.rs`

**Interfaces:**
- Consumes: `commands::search::SearchArgs`; `paksmith_core::container::EntryMetadata`; `parse_size`.
- Produces:
  - `pub(crate) struct Predicates { ... }`
  - `pub(crate) fn Predicates::from_args(args: &SearchArgs) -> Result<Self, (&'static str, String)>`
  - `pub(crate) fn Predicates::matches(&self, e: &EntryMetadata) -> bool`
  - `fn extension_of(basename: &str) -> Option<String>` (leading-dot-aware, lowercased)

- [ ] **Step 1: Write the failing unit tests**

Append to `crates/paksmith-cli/src/search/mod.rs`:

```rust
#[cfg(test)]
mod predicate_tests {
    use super::*;
    use paksmith_core::container::{EntryFlags, EntryMetadata};

    // EntryMetadata constructor (see paksmith_core::container) — confirm the
    // exact ctor/builder against the source; this mirrors how `list` builds
    // them. If `EntryMetadata::new(path, compressed, uncompressed, flags)`
    // differs, adapt these helpers.
    fn entry(path: &str, uncompressed: u64) -> EntryMetadata {
        EntryMetadata::new(
            path.to_string(),
            uncompressed,            // compressed size (irrelevant here)
            uncompressed,            // uncompressed size
            EntryFlags { compressed: false, encrypted: false },
        )
    }

    fn args() -> crate::commands::search::SearchArgs {
        // Build via the public fields; all-None/empty = match-all.
        crate::commands::search::SearchArgs {
            pak: std::path::PathBuf::new(),
            r#type: vec![],
            name: None,
            regex: None,
            min_size: None,
            max_size: None,
        }
    }

    #[test]
    fn empty_predicates_match_all() {
        let p = Predicates::from_args(&args()).unwrap();
        assert!(p.matches(&entry("Game/Maps/Hero.uasset", 10)));
        assert!(p.matches(&entry("Config/Game.ini", 10)));
    }

    #[test]
    fn type_matches_extension_case_insensitive_or_within() {
        let mut a = args();
        a.r#type = vec!["uasset".into(), "umap".into()];
        let p = Predicates::from_args(&a).unwrap();
        assert!(p.matches(&entry("A.uasset", 1)));
        assert!(p.matches(&entry("B.UMAP", 1)));      // case-insensitive
        assert!(!p.matches(&entry("C.ini", 1)));
        assert!(!p.matches(&entry("noext", 1)));
        assert!(!p.matches(&entry("Game/.uasset", 1))); // leading-dot dotfile = no ext
    }

    #[test]
    fn name_globs_basename() {
        let mut a = args();
        a.name = Some("Hero*".into());
        let p = Predicates::from_args(&a).unwrap();
        assert!(p.matches(&entry("Game/Maps/Hero.uasset", 1))); // basename match
        assert!(!p.matches(&entry("Game/Maps/Villain.uasset", 1)));
    }

    #[test]
    fn regex_matches_full_path_unanchored() {
        let mut a = args();
        a.regex = Some(r"Maps/.*\.uasset$".into());
        let p = Predicates::from_args(&a).unwrap();
        assert!(p.matches(&entry("Game/Maps/Hero.uasset", 1)));
        assert!(!p.matches(&entry("Game/UI/Button.uasset", 1)));
    }

    #[test]
    fn size_bounds_are_inclusive_on_uncompressed() {
        let mut a = args();
        a.min_size = Some("100".into());
        a.max_size = Some("200".into());
        let p = Predicates::from_args(&a).unwrap();
        assert!(!p.matches(&entry("a", 99)));
        assert!(p.matches(&entry("a", 100)));   // inclusive
        assert!(p.matches(&entry("a", 200)));   // inclusive
        assert!(!p.matches(&entry("a", 201)));
    }

    #[test]
    fn predicates_and_combine() {
        let mut a = args();
        a.r#type = vec!["uasset".into()];
        a.name = Some("Hero*".into());
        a.min_size = Some("50".into());
        let p = Predicates::from_args(&a).unwrap();
        assert!(p.matches(&entry("Game/Hero.uasset", 60)));
        assert!(!p.matches(&entry("Game/Hero.uasset", 10)));  // fails size
        assert!(!p.matches(&entry("Game/Hero.ini", 60)));     // fails type
        assert!(!p.matches(&entry("Game/Villain.uasset", 60))); // fails name
    }

    #[test]
    fn from_args_rejects_bad_inputs() {
        let mut bad_glob = args();
        bad_glob.name = Some("[".into());
        assert_eq!(Predicates::from_args(&bad_glob).unwrap_err().0, "--name");

        let mut bad_re = args();
        bad_re.regex = Some("(".into());
        assert_eq!(Predicates::from_args(&bad_re).unwrap_err().0, "--regex");

        let mut bad_size = args();
        bad_size.min_size = Some("1ZB".into());
        assert_eq!(Predicates::from_args(&bad_size).unwrap_err().0, "--min-size");

        let mut inverted = args();
        inverted.min_size = Some("10".into());
        inverted.max_size = Some("5".into());
        assert_eq!(Predicates::from_args(&inverted).unwrap_err().0, "--min-size");
    }
}
```

- [ ] **Step 2: Run — verify it fails**

Run: `cargo test -p paksmith-cli predicate_tests`
Expected: FAIL — `Predicates`/`extension_of` not defined. (Also confirms the `EntryMetadata::new` ctor + `SearchArgs` public fields compile; if `EntryMetadata::new`'s signature differs, fix the `entry` helper per the source before proceeding.)

- [ ] **Step 3: Implement `Predicates` + `extension_of`**

Add above the test modules (the `use` lines go at the top of the file):

```rust
use paksmith_core::container::EntryMetadata;

use crate::commands::search::SearchArgs;

/// Extension of a basename, lowercased — `None` for no-extension or a
/// leading-dot dotfile (matches 4a `extract`'s `classify` semantics).
fn extension_of(basename: &str) -> Option<String> {
    basename
        .rfind('.')
        .filter(|&i| i > 0)
        .map(|i| basename[i + 1..].to_ascii_lowercase())
}

/// Compiled, AND-combined search predicates. Construct via [`Self::from_args`].
pub(crate) struct Predicates {
    types: Vec<String>, // lowercased extensions; empty = any
    name: Option<glob::Pattern>,
    regex: Option<regex::Regex>,
    min_size: Option<u64>,
    max_size: Option<u64>,
}

impl Predicates {
    /// Compile/parse from CLI args. `Err((arg, reason))` names the offending
    /// flag so the caller can build a `PaksmithError::InvalidArgument`.
    pub(crate) fn from_args(args: &SearchArgs) -> Result<Self, (&'static str, String)> {
        let types = args.r#type.iter().map(|t| t.to_ascii_lowercase()).collect();

        let name = match &args.name {
            Some(g) => Some(glob::Pattern::new(g).map_err(|e| ("--name", e.to_string()))?),
            None => None,
        };
        let regex = match &args.regex {
            Some(r) => Some(regex::Regex::new(r).map_err(|e| ("--regex", e.to_string()))?),
            None => None,
        };
        let min_size = match &args.min_size {
            Some(s) => Some(parse_size(s).map_err(|e| ("--min-size", e))?),
            None => None,
        };
        let max_size = match &args.max_size {
            Some(s) => Some(parse_size(s).map_err(|e| ("--max-size", e))?),
            None => None,
        };
        if let (Some(min), Some(max)) = (min_size, max_size) {
            if min > max {
                return Err(("--min-size", format!("--min-size {min} exceeds --max-size {max}")));
            }
        }
        Ok(Self { types, name, regex, min_size, max_size })
    }

    /// True iff `e` satisfies every supplied predicate (AND). Pure; no I/O.
    pub(crate) fn matches(&self, e: &EntryMetadata) -> bool {
        let path = e.path();
        let basename = path.rsplit('/').next().unwrap_or(path);

        if !self.types.is_empty() {
            let Some(ext) = extension_of(basename) else {
                return false;
            };
            if !self.types.iter().any(|t| *t == ext) {
                return false;
            }
        }
        if let Some(g) = &self.name {
            if !g.matches(basename) {
                return false;
            }
        }
        if let Some(re) = &self.regex {
            if !re.is_match(path) {
                return false;
            }
        }
        let size = e.uncompressed_size();
        if self.min_size.is_some_and(|min| size < min) {
            return false;
        }
        if self.max_size.is_some_and(|max| size > max) {
            return false;
        }
        true
    }
}
```

(`is_some_and` is stable on 1.88. Confirm `EntryMetadata::uncompressed_size()` + `path()` accessor names against `crates/paksmith-core/src/container/mod.rs` — they are `path() -> &str` and `uncompressed_size() -> u64`.)

- [ ] **Step 4: Run — verify it passes**

Run: `cargo test -p paksmith-cli predicate_tests parse_size`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/paksmith-cli/src/search/mod.rs
git commit -m "feat(cli): add search predicates (type/name/regex/size, AND-combined)"
```

---

## Task 4: Wire `run` + integration tests

**Files:**
- Modify: `crates/paksmith-cli/src/commands/search.rs` (real `run`)
- Modify: `crates/paksmith-cli/tests/search_cli.rs`

**Interfaces:**
- Consumes: `search::Predicates`; `paksmith_core::container::pak::PakReader`; `crate::output::{print_entries, OutputFormat, ResolvedFormat}`.

- [ ] **Step 1: Write the failing integration tests**

Append to `crates/paksmith-cli/tests/search_cli.rs` (use the repo-root fixtures; `real_v8b_mixed_paths.pak` has multiple entries with paths/sizes — confirm it exists, else pick another multi-entry fixture from `tests/fixtures/`):

```rust
use std::path::PathBuf;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent().unwrap().parent().unwrap()
        .join("tests/fixtures").join(name)
}

const PAK: &str = "real_v8b_mixed_paths.pak";

#[test]
fn search_no_predicates_lists_all_as_json() {
    let assert = Command::cargo_bin("paksmith").unwrap()
        .args(["--format", "json", "search"]).arg(fixture(PAK))
        .assert().success();
    let v: serde_json::Value =
        serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert!(v.as_array().is_some_and(|a| !a.is_empty()), "expected non-empty JSON array");
}

#[test]
fn search_type_filters_to_extension() {
    let assert = Command::cargo_bin("paksmith").unwrap()
        .args(["--format", "json", "search"]).arg(fixture(PAK))
        .args(["--type", "uasset"])
        .assert().success();
    let v: serde_json::Value =
        serde_json::from_slice(&assert.get_output().stdout).unwrap();
    // Every returned entry's path ends with .uasset (case-insensitive).
    for e in v.as_array().unwrap() {
        let p = e["path"].as_str().unwrap().to_ascii_lowercase();
        assert!(p.ends_with(".uasset"), "non-uasset in --type uasset results: {p}");
    }
}

#[test]
fn search_zero_match_is_exit_0_empty_array() {
    let assert = Command::cargo_bin("paksmith").unwrap()
        .args(["--format", "json", "search"]).arg(fixture(PAK))
        .args(["--name", "definitely-no-such-entry-xyz"])
        .assert().success();   // zero matches is NOT an error
    let v: serde_json::Value =
        serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_eq!(v.as_array().unwrap().len(), 0);
}

#[test]
fn search_bad_regex_exits_2() {
    Command::cargo_bin("paksmith").unwrap()
        .args(["search"]).arg(fixture(PAK)).args(["--regex", "("])
        .assert().code(2);
}

#[test]
fn search_bad_size_exits_2() {
    Command::cargo_bin("paksmith").unwrap()
        .args(["search"]).arg(fixture(PAK)).args(["--min-size", "1ZB"])
        .assert().code(2);
}

#[test]
fn search_min_gt_max_exits_2() {
    Command::cargo_bin("paksmith").unwrap()
        .args(["search"]).arg(fixture(PAK)).args(["--min-size", "10", "--max-size", "5"])
        .assert().code(2);
}
```

- [ ] **Step 2: Run — verify they fail**

Run: `cargo test -p paksmith-cli --test search_cli`
Expected: FAIL — `run` is still the stub (emits nothing; JSON parse fails / exit codes wrong).

- [ ] **Step 3: Implement `run`**

Replace the stub `run` in `commands/search.rs` (and add imports):

```rust
use paksmith_core::PaksmithError;
use paksmith_core::container::ContainerReader;
use paksmith_core::container::pak::PakReader;

use crate::output::{OutputFormat, ResolvedFormat};
use crate::search::Predicates;

pub(crate) fn run(args: &SearchArgs, format: OutputFormat) -> paksmith_core::Result<()> {
    let predicates = Predicates::from_args(args)
        .map_err(|(arg, reason)| PaksmithError::InvalidArgument { arg, reason })?;

    let reader = PakReader::open(&args.pak)?;
    let matches: Vec<_> = reader.entries().filter(|e| predicates.matches(e)).collect();

    let resolved = format.resolve();
    // Mirror `list`: warn when Auto silently became JSON because stdout
    // isn't a TTY, so users piping into head/jq aren't surprised.
    if matches!(format, OutputFormat::Auto) && matches!(resolved, ResolvedFormat::Json) {
        eprintln!(
            "note: stdout is not a terminal — emitting JSON. Pass --format table to force table output."
        );
    }
    crate::output::print_entries(&matches, resolved)?;
    Ok(())
}
```

Remove the `#[allow(clippy::unnecessary_wraps)]` from the stub (real fallible ops now present).

- [ ] **Step 4: Run — verify they pass**

Run: `cargo test -p paksmith-cli --test search_cli`
Expected: PASS (all 7 incl. the help test).

- [ ] **Step 5: Commit**

```bash
git add crates/paksmith-cli/src/commands/search.rs crates/paksmith-cli/tests/search_cli.rs
git commit -m "feat(cli): wire search run() over the entry index"
```

---

## Task 5: ROADMAP + full gate chain

**Files:**
- Modify: `docs/plans/ROADMAP.md`

- [ ] **Step 1: Update ROADMAP**

In `docs/plans/ROADMAP.md` Phase 4 section, note 4c `search` shipped and that **Phase 4 (Full CLI) is now complete** (extract + inspect + search), mirroring the 4a/4b notes. Factual, brief; no engine-source references.

- [ ] **Step 2: Full gate chain (each UNPIPED; fix any failure)**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
typos .
```
Expected: all exit 0. If `cargo test --workspace --all-features` shows ANY failure anywhere, report it precisely — do not mark DONE with a red suite.

- [ ] **Step 3: Commit**

```bash
git add docs/plans/ROADMAP.md
git commit -m "docs(phase-4c): mark search shipped; Phase 4 CLI complete"
```

---

## Review & Push

- [ ] Adversarial multi-agent panel (≥3 + specialists; the untrusted-input predicate compilation — regex/glob on user args — and the index-walk warrant a security + correctness lens). Brief cold; pass the diff.
- [ ] Cycle to convergence (re-dispatch full panel after each fix commit). Stop only when all reviewers APPROVE.
- [ ] Touch the convergence marker (separate Bash call from the push), then push + open PR:
  ```bash
  touch "$(git rev-parse --git-dir)/REVIEW_CONVERGED_OK"
  git push -u origin feat/phase-4c-search
  ```
- [ ] Open PR (`gh ... --body-file`), Monitor CI to green. Do NOT merge — the user merges via UI.

---

## Self-Review (plan vs spec)

**Spec coverage:**
- `--type <ext>` repeatable, OR-within, case-insensitive, extension-based → Task 3 (`matches` + `extension_of`) + Task 1 (arg). ✓
- `--name` basename glob → Task 3. ✓
- `--regex` full-path unanchored → Task 3. ✓
- `--min/--max-size` human units, uncompressed, inclusive → Task 2 (`parse_size`) + Task 3 (`matches`). ✓
- AND-combine; no predicates = all → Task 3. ✓
- Output reuses `print_entries` (table/JSON, auto-note) → Task 4. ✓
- Exit codes 0 (incl. zero match) / 2 (bad glob/regex/size, min>max) → Task 3 (`from_args` errors) + Task 4 (map to InvalidArgument) + tests. ✓
- Only `regex` added; internal `parse_size` → Task 1 (dep) + Task 2. ✓
- No new `.pak`; reuse fixtures → Task 4. ✓
- Phase 4 complete note → Task 5. ✓

**Type consistency:** `SearchArgs` (with `r#type`), `Predicates`/`from_args(-> Result<Self,(&'static str,String)>)`/`matches`, `parse_size(-> Result<u64,String>)`, `extension_of`, and `run(-> Result<()>)` are referenced identically across tasks. `commands/mod.rs` dispatch uses `.map(|()| 0)`.

**Verification flags — RESOLVED (confirmed against the codebase):**
- `EntryMetadata::new(path: String, compressed_size: u64, uncompressed_size: u64, flags: EntryFlags)` — the Task 3 test helper's 4-arg call (`path.to_string()`, compressed, uncompressed, `EntryFlags { compressed, encrypted }`) matches exactly. `EntryFlags` is `{ compressed: bool, encrypted: bool }`. Accessors: `path() -> &str`, `uncompressed_size() -> u64`.
- `tests/fixtures/real_v8b_mixed_paths.pak` confirmed: 3 entries — `Content/Subdir/Deep/nested.uasset`, `Content/a.uasset`, `root.txt`. So `--type uasset` → 2 matches; no-predicate → 3; a nonsense `--name` → 0. The integration tests hold.
- `Option::is_some_and` is stable ≥1.82 (fine on 1.88).
