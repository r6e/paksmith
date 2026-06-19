# Phase 4a — `paksmith extract` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `paksmith extract <pak> -o <dir>` — a resilient, parallel batch exporter that converts assets via the Phase 3 handler registry, copies non-asset entries raw, and reports a stable JSON/table summary.

**Architecture:** A thin `commands/extract.rs` parses args and drives an `extract/` submodule: classify each pak entry, parse assets through a shared `Arc<PakReader>` (new core `Package::read_from_reader`), select an export + handler, derive a zip-slip-safe output path, write, and accumulate per-entry outcomes into an `ExtractSummary`. `rayon` parallelizes the CPU-bound decode/encode; `indicatif` shows progress on stderr.

**Tech Stack:** Rust (workspace MSRV), `clap` (derive), `rayon`, `indicatif`, `glob`, `comfy-table`, `serde`/`serde_json`; tests via `assert_cmd`, `predicates`, `insta`, `tempfile`.

**Spec:** `docs/superpowers/specs/2026-06-18-phase-4a-extract-design.md`

## Global Constraints

- **MSRV:** workspace `rust-version` (1.88). No newer/unstable syntax — `if let` match guards are NOT 1.88; use `let-else`. Verify before push.
- **No panics in `paksmith-core`** — all fallible core ops return `Result<T, PaksmithError>`. (CLI may use `?`/typed errors; avoid `unwrap`/`expect` on fallible paths.)
- **`thiserror` for error types, `tracing` for structured logging** (no `println!` debugging). CLI top-level user errors use the existing `eprintln!("paksmith: error: …")` path in `main.rs`.
- **Conventional commits**, one logical change per commit: `feat:`, `fix:`, `chore:`, `test:`, `docs:`.
- **Pre-push gate chain:** `cargo fmt --all`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace --all-features`, `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features`, `typos .`. Run all before requesting review/push.
- **Untrusted input:** pak entry paths are attacker-controlled. Every disk write derives its path through the `safe_path` sanitizer (Task 3). No exceptions, including `--flat`.
- **Review:** every PR gets the adversarial multi-agent panel (≥3 + specialists; security specialist is mandatory for Tasks 1, 3, 6, 7) and runs to convergence before push. New `.pak` fixtures bump CI's hardcoded fixture-count gate in `.github/workflows/ci.yml`.

---

## File Structure

```
crates/paksmith-core/src/asset/package.rs   # MODIFY: extract read_from_reader from read_from_pak
crates/paksmith-cli/Cargo.toml               # MODIFY: add rayon, indicatif
crates/paksmith-cli/src/main.rs              # MODIFY: run() -> ExitCode plumbing
crates/paksmith-cli/src/commands/mod.rs      # MODIFY: register Extract, run() returns u8
crates/paksmith-cli/src/commands/extract.rs  # CREATE: ExtractArgs, run(), arg→config
crates/paksmith-cli/src/extract/mod.rs       # CREATE: ExtractJob, ExtractConfig, walk
crates/paksmith-cli/src/extract/classify.rs  # CREATE: EntryClass classification
crates/paksmith-cli/src/extract/safe_path.rs # CREATE: zip-slip-safe path derivation
crates/paksmith-cli/src/extract/select.rs    # CREATE: format prefs + handler/export selection
crates/paksmith-cli/src/extract/summary.rs   # CREATE: EntryOutcome, ExtractSummary, render
crates/paksmith-cli/tests/extract_cli.rs     # CREATE: assert_cmd + insta integration tests
crates/paksmith-cli/tests/fixtures/          # CREATE: extract test paks (if not reusable)
```

---

## Task 1: Core — `Package::read_from_reader`

**Files:**
- Modify: `crates/paksmith-core/src/asset/package.rs` (`read_from_pak`, ~lines 850–905)
- Test: `crates/paksmith-core/src/asset/package.rs` (in-source `#[cfg(test)]`) or existing integration suite

**Interfaces:**
- Produces: `pub fn Package::read_from_reader(reader: std::sync::Arc<crate::container::pak::PakReader>, virtual_path: &str, mappings: Option<&Usmap>) -> crate::Result<Package>`
- `read_from_pak` keeps its existing signature and delegates to `read_from_reader`.

- [ ] **Step 1: Write the failing test** (in `package.rs` tests module, or wherever `read_from_pak` is currently tested — mirror that location)

```rust
#[test]
fn read_from_reader_matches_read_from_pak() {
    // Use the same fixture an existing read_from_pak test uses.
    let pak_path = test_pak_path("<existing fixture>.pak");
    let virtual_path = "<existing asset path in that fixture>";

    let via_path = Package::read_from_pak(&pak_path, virtual_path, None).unwrap();

    use std::sync::Arc;
    use crate::container::pak::PakReader;
    let reader = Arc::new(PakReader::open(&pak_path).unwrap());
    let via_reader = Package::read_from_reader(reader, virtual_path, None).unwrap();

    // Payload count + summary identity is enough to prove the same parse ran.
    assert_eq!(via_reader.payloads.len(), via_path.payloads.len());
}
```

(Locate an existing `read_from_pak` test for the exact fixture path + asset path; reuse them verbatim.)

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p paksmith-core --all-features read_from_reader_matches_read_from_pak`
Expected: FAIL — `read_from_reader` does not exist (compile error).

- [ ] **Step 3: Refactor `read_from_pak` to delegate**

Replace the body of `read_from_pak` (everything after opening the reader) by moving it into a new `read_from_reader`:

```rust
pub fn read_from_pak<P: AsRef<std::path::Path>>(
    pak_path: P,
    virtual_path: &str,
    mappings: Option<&Usmap>,
) -> crate::Result<Self> {
    let reader = Arc::new(crate::container::pak::PakReader::open(pak_path)?);
    Self::read_from_reader(reader, virtual_path, mappings)
}

/// Parse the UAsset at `virtual_path` from an already-open pak reader.
///
/// Identical to [`Self::read_from_pak`] but reuses a caller-provided
/// `Arc<PakReader>` instead of opening (and re-parsing the index of)
/// the pak on every call. The real `Arc<PakReader>`-backed
/// `.ubulk` / `.uptnl` bulk loaders are wired exactly as in
/// `read_from_pak`, so streaming-tier bulk resolution works.
///
/// Batch callers (the CLI `extract` command, the future GUI) open the
/// pak once and share the `Arc` across worker threads (`PakReader` is
/// `Send + Sync`).
///
/// # Errors
/// Same as [`Self::read_from_pak`], minus the open step.
pub fn read_from_reader(
    reader: Arc<crate::container::pak::PakReader>,
    virtual_path: &str,
    mappings: Option<&Usmap>,
) -> crate::Result<Self> {
    use crate::container::ContainerReader;

    let uasset_bytes = reader.read_entry(virtual_path)?;

    let uexp_path = derive_companion_path(virtual_path, ".uexp");
    let uexp_bytes = match reader.read_entry(&uexp_path) {
        Ok(bytes) => Some(bytes),
        Err(PaksmithError::EntryNotFound { .. }) => None,
        Err(e) => return Err(e),
    };

    let ubulk_loader = pak_companion_loader(
        Arc::clone(&reader),
        derive_companion_path(virtual_path, ".ubulk"),
        virtual_path.to_string(),
        CompanionFileKind::Ubulk,
    );
    let uptnl_loader = pak_companion_loader(
        Arc::clone(&reader),
        derive_companion_path(virtual_path, ".uptnl"),
        virtual_path.to_string(),
        CompanionFileKind::Uptnl,
    );

    Self::read_from_inner(
        &uasset_bytes,
        uexp_bytes.as_deref(),
        mappings,
        virtual_path,
        ubulk_loader,
        uptnl_loader,
    )
}
```

(This is a pure move — copy the existing `read_from_pak` body verbatim into `read_from_reader`; do not rewrite it. Keep the original explanatory comments.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p paksmith-core --all-features read_from_reader_matches_read_from_pak`
Expected: PASS.

- [ ] **Step 5: Verify no regression in existing pak-parse tests**

Run: `cargo test -p paksmith-core --all-features read_from_pak`
Expected: all existing `read_from_pak` tests still PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/paksmith-core/src/asset/package.rs
git commit -m "feat(asset): add Package::read_from_reader for shared-reader parsing"
```

---

## Task 2: CLI plumbing — `extract` subcommand skeleton + exit-code contract

**Files:**
- Modify: `crates/paksmith-cli/Cargo.toml` (add `rayon`, `indicatif`)
- Modify: `crates/paksmith-cli/src/main.rs` (run dispatch → `ExitCode`)
- Modify: `crates/paksmith-cli/src/commands/mod.rs` (add `Extract`, change `run` return type)
- Create: `crates/paksmith-cli/src/commands/extract.rs` (args + stub `run`)

**Interfaces:**
- Produces: `commands::Command::run(&self, format: OutputFormat) -> paksmith_core::Result<u8>` (exit code: `0` ok, `1` partial failures; `Err` → `2` via `main`).
- Produces: `commands::extract::ExtractArgs` (clap `Args`) and `commands::extract::run(args: &ExtractArgs, format: OutputFormat) -> paksmith_core::Result<u8>`.

- [ ] **Step 1: Add dependencies**

In `crates/paksmith-cli/Cargo.toml` `[dependencies]`, append:

```toml
rayon = "1"
indicatif = "0.18"
```

- [ ] **Step 2: Write the failing CLI test**

Create `crates/paksmith-cli/tests/extract_cli.rs`:

```rust
use assert_cmd::Command;

#[test]
fn extract_help_lists_flags() {
    let mut cmd = Command::cargo_bin("paksmith").unwrap();
    let assert = cmd.args(["extract", "--help"]).assert().success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    for flag in ["--output", "--filter", "--flat", "--dry-run", "--overwrite",
                 "--audio-format", "--datatable-format", "--jobs", "--game"] {
        assert!(out.contains(flag), "help missing {flag}");
    }
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test -p paksmith-cli --test extract_cli extract_help_lists_flags`
Expected: FAIL — `extract` subcommand does not exist.

- [ ] **Step 4: Create the args + stub run**

Create `crates/paksmith-cli/src/commands/extract.rs`:

```rust
//! `paksmith extract <pak> -o <dir>` — batch export pak contents.

use std::path::PathBuf;

use clap::{Args, ValueEnum};

use crate::output::OutputFormat;

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum AudioFormat {
    Ogg,
    Wav,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum DataTableFormat {
    Csv,
    Json,
}

#[derive(Args)]
pub(crate) struct ExtractArgs {
    /// Path to the .pak file.
    pub(crate) pak: PathBuf,

    /// Output directory (created if absent).
    #[arg(short, long)]
    pub(crate) output: PathBuf,

    /// Only extract entries whose path matches this glob.
    #[arg(long)]
    pub(crate) filter: Option<String>,

    /// Strip directories; write basenames into the output root.
    #[arg(long)]
    pub(crate) flat: bool,

    /// Parse and report would-be outputs without writing anything.
    #[arg(long)]
    pub(crate) dry_run: bool,

    /// Overwrite existing output files (and resolve --flat collisions
    /// last-writer-wins). Without it, an existing target is an error.
    #[arg(long)]
    pub(crate) overwrite: bool,

    /// Output format for USoundWave assets.
    #[arg(long, value_enum, default_value_t = AudioFormat::Ogg)]
    pub(crate) audio_format: AudioFormat,

    /// Output format for UDataTable assets.
    #[arg(long, value_enum, default_value_t = DataTableFormat::Csv)]
    pub(crate) datatable_format: DataTableFormat,

    /// Worker-thread cap (default: CPU count).
    #[arg(long)]
    pub(crate) jobs: Option<usize>,

    /// Game profile id. Reserved for Phase 5; not yet supported.
    #[arg(long, value_name = "ID")]
    pub(crate) game: Option<String>,
}

pub(crate) fn run(_args: &ExtractArgs, _format: OutputFormat) -> paksmith_core::Result<u8> {
    // Filled in by later tasks.
    Ok(0)
}
```

- [ ] **Step 5: Register the subcommand + change `run` return type**

In `crates/paksmith-cli/src/commands/mod.rs`:

```rust
pub(crate) mod extract;
pub(crate) mod inspect;
pub(crate) mod list;

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
}

impl Command {
    pub(crate) fn run(&self, format: OutputFormat) -> paksmith_core::Result<u8> {
        match self {
            Self::List(args) => list::run(args, format).map(|()| 0),
            Self::Inspect(args) => inspect::run(args, format).map(|()| 0),
            Self::Extract(args) => extract::run(args, format),
        }
    }
}
```

- [ ] **Step 6: Map the exit code in `main.rs`**

In `crates/paksmith-cli/src/main.rs`, change the match arm:

```rust
match cli.command.run(cli.format) {
    Ok(code) => ExitCode::from(code),
    Err(PaksmithError::Io(e)) if e.kind() == io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
    Err(e) => {
        eprintln!("paksmith: error: {e}");
        ExitCode::from(2)
    }
}
```

(Keep the existing comment block above the `Err(e)` arm.)

- [ ] **Step 7: Run test to verify it passes**

Run: `cargo test -p paksmith-cli --test extract_cli extract_help_lists_flags`
Expected: PASS.

- [ ] **Step 8: Verify existing CLI tests still pass**

Run: `cargo test -p paksmith-cli`
Expected: all PASS (list/inspect unaffected by the `run` return-type change).

- [ ] **Step 9: Commit**

```bash
git add crates/paksmith-cli/Cargo.toml crates/paksmith-cli/src/main.rs \
        crates/paksmith-cli/src/commands/mod.rs \
        crates/paksmith-cli/src/commands/extract.rs \
        crates/paksmith-cli/tests/extract_cli.rs
git commit -m "feat(cli): add extract subcommand skeleton and exit-code plumbing"
```

---

## Task 3: `safe_path` — zip-slip-safe output path derivation

**Files:**
- Create: `crates/paksmith-cli/src/extract/mod.rs` (module declaration only, this task)
- Create: `crates/paksmith-cli/src/extract/safe_path.rs`
- Modify: `crates/paksmith-cli/src/main.rs` (add `mod extract;`)

**Interfaces:**
- Produces: `pub(crate) fn safe_join(output_root: &Path, entry_path: &str, flat: bool) -> Result<PathBuf, SafePathError>`
- Produces: `pub(crate) enum SafePathError { Escapes(String), Empty }` with `Display`.

**Security note:** This is the security-critical surface. The sanitizer is **lexical** (it never canonicalizes, because targets don't exist yet and canonicalize is TOCTOU-prone). It rejects `..`, absolute roots, and drive/UNC prefixes, then asserts the joined path stays under `output_root` lexically. `output_root` itself is trusted (user-supplied `-o`); symlink-following inside it is out of scope.

- [ ] **Step 1: Declare the module and write the failing test**

Create `crates/paksmith-cli/src/extract/mod.rs`:

```rust
pub(crate) mod safe_path;
```

Add to `crates/paksmith-cli/src/main.rs` (alongside `mod commands;`):

```rust
mod extract;
```

Create `crates/paksmith-cli/src/extract/safe_path.rs` with the test first:

```rust
use std::path::{Component, Path, PathBuf};

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn root() -> PathBuf {
        PathBuf::from("/out")
    }

    #[test]
    fn normal_path_mirrors_under_root() {
        let p = safe_join(&root(), "Game/Hero.uasset", false).unwrap();
        assert_eq!(p, PathBuf::from("/out/Game/Hero.uasset"));
    }

    #[test]
    fn flat_keeps_only_basename() {
        let p = safe_join(&root(), "Game/Sub/Hero.uasset", true).unwrap();
        assert_eq!(p, PathBuf::from("/out/Hero.uasset"));
    }

    #[test]
    fn rejects_parent_traversal() {
        assert!(matches!(
            safe_join(&root(), "../../etc/passwd", false),
            Err(SafePathError::Escapes(_))
        ));
    }

    #[test]
    fn rejects_embedded_parent() {
        assert!(matches!(
            safe_join(&root(), "Game/../../etc/passwd", false),
            Err(SafePathError::Escapes(_))
        ));
    }

    #[test]
    fn rejects_posix_absolute() {
        assert!(matches!(
            safe_join(&root(), "/etc/passwd", false),
            Err(SafePathError::Escapes(_))
        ));
    }

    #[test]
    fn rejects_windows_drive_and_unc() {
        for evil in ["C:\\Windows\\system32", "\\\\server\\share\\x"] {
            assert!(
                matches!(safe_join(&root(), evil, false), Err(SafePathError::Escapes(_))),
                "accepted {evil}"
            );
        }
    }

    #[test]
    fn rejects_empty() {
        assert!(matches!(safe_join(&root(), "", false), Err(SafePathError::Empty)));
        assert!(matches!(safe_join(&root(), "../..", true), Err(SafePathError::Escapes(_))));
    }

    #[test]
    fn handles_mixed_separators() {
        // Backslash is a path char on Unix but a separator on Windows;
        // we normalize backslashes to forward slashes before splitting
        // so a Windows-style entry can't smuggle a traversal.
        assert!(matches!(
            safe_join(&root(), "Game\\..\\..\\etc", false),
            Err(SafePathError::Escapes(_))
        ));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p paksmith-cli safe_path`
Expected: FAIL — `safe_join` / `SafePathError` not defined.

- [ ] **Step 3: Implement the sanitizer**

Add above the test module in `safe_path.rs`:

```rust
/// Why a pak entry path could not be safely mapped under the output root.
#[derive(Debug)]
pub(crate) enum SafePathError {
    /// The entry path escaped the output root (`..`, absolute, drive/UNC),
    /// or flattening left nothing. Carries the offending entry path.
    Escapes(String),
    /// The entry path was empty.
    Empty,
}

impl std::fmt::Display for SafePathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Escapes(p) => write!(f, "entry path escapes output directory: {p}"),
            Self::Empty => write!(f, "empty entry path"),
        }
    }
}

/// Map an untrusted pak `entry_path` to a path strictly under `output_root`.
///
/// Lexical only — never canonicalizes (targets don't exist yet; canonicalize
/// is TOCTOU-prone). Backslashes are normalized to `/` so Windows-style
/// separators can't smuggle traversal. Rejects `..`, absolute roots, and
/// Windows drive/UNC prefixes.
pub(crate) fn safe_join(
    output_root: &Path,
    entry_path: &str,
    flat: bool,
) -> Result<PathBuf, SafePathError> {
    if entry_path.is_empty() {
        return Err(SafePathError::Empty);
    }

    let normalized = entry_path.replace('\\', "/");

    // Reject POSIX-absolute and Windows drive/UNC up front.
    if normalized.starts_with('/') {
        return Err(SafePathError::Escapes(entry_path.to_string()));
    }
    let bytes = normalized.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        return Err(SafePathError::Escapes(entry_path.to_string())); // C:
    }

    // Collect clean components; reject any `..` or rooted component.
    let mut parts: Vec<&str> = Vec::new();
    for seg in normalized.split('/') {
        match seg {
            "" | "." => continue,
            ".." => return Err(SafePathError::Escapes(entry_path.to_string())),
            other => parts.push(other),
        }
    }

    let chosen: &[&str] = if flat {
        match parts.last() {
            Some(name) => std::slice::from_ref(name),
            None => return Err(SafePathError::Escapes(entry_path.to_string())),
        }
    } else {
        &parts
    };

    if chosen.is_empty() {
        return Err(SafePathError::Escapes(entry_path.to_string()));
    }

    let mut candidate = output_root.to_path_buf();
    for part in chosen {
        candidate.push(part);
    }

    // Defensive: confirm no component re-introduced a parent escape.
    debug_assert!(
        !candidate.components().any(|c| matches!(c, Component::ParentDir)),
        "sanitized path still contains ParentDir"
    );

    Ok(candidate)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p paksmith-cli safe_path`
Expected: PASS (all 8 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/paksmith-cli/src/main.rs crates/paksmith-cli/src/extract/mod.rs \
        crates/paksmith-cli/src/extract/safe_path.rs
git commit -m "feat(cli): add zip-slip-safe output path derivation for extract"
```

---

## Task 4: `classify` — entry classification

**Files:**
- Create: `crates/paksmith-cli/src/extract/classify.rs`
- Modify: `crates/paksmith-cli/src/extract/mod.rs` (add `pub(crate) mod classify;`)

**Interfaces:**
- Produces: `pub(crate) enum EntryClass { Asset, Companion, Raw }`
- Produces: `pub(crate) fn classify(entry_path: &str) -> EntryClass`

- [ ] **Step 1: Write the failing test**

Create `crates/paksmith-cli/src/extract/classify.rs`:

```rust
//! Classify a pak entry by extension to choose its extract path.

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum EntryClass {
    /// `.uasset` / `.umap` — parse + convert via the handler registry.
    Asset,
    /// `.uexp` / `.ubulk` / `.uptnl` — consumed by the asset parse; never emitted.
    Companion,
    /// Anything else — copy raw.
    Raw,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_assets() {
        assert_eq!(classify("Game/Hero.uasset"), EntryClass::Asset);
        assert_eq!(classify("Game/Level.umap"), EntryClass::Asset);
        assert_eq!(classify("HERO.UASSET"), EntryClass::Asset); // case-insensitive
    }

    #[test]
    fn classifies_companions() {
        for p in ["Hero.uexp", "Hero.ubulk", "Hero.uptnl"] {
            assert_eq!(classify(p), EntryClass::Companion, "{p}");
        }
    }

    #[test]
    fn classifies_raw() {
        for p in ["Config.ini", "Strings.locres", "noext", "data.bin"] {
            assert_eq!(classify(p), EntryClass::Raw, "{p}");
        }
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p paksmith-cli classify`
Expected: FAIL — `classify` not defined.

- [ ] **Step 3: Implement `classify`**

Add above the test module:

```rust
pub(crate) fn classify(entry_path: &str) -> EntryClass {
    let ext = entry_path
        .rsplit('.')
        .next()
        .filter(|e| !e.contains('/') && *e != entry_path)
        .map(str::to_ascii_lowercase);

    match ext.as_deref() {
        Some("uasset" | "umap") => EntryClass::Asset,
        Some("uexp" | "ubulk" | "uptnl") => EntryClass::Companion,
        _ => EntryClass::Raw,
    }
}
```

Register in `crates/paksmith-cli/src/extract/mod.rs`:

```rust
pub(crate) mod classify;
pub(crate) mod safe_path;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p paksmith-cli classify`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/paksmith-cli/src/extract/classify.rs crates/paksmith-cli/src/extract/mod.rs
git commit -m "feat(cli): classify pak entries for extract dispatch"
```

---

## Task 5: `select` — export + handler selection with format prefs

**Files:**
- Create: `crates/paksmith-cli/src/extract/select.rs`
- Modify: `crates/paksmith-cli/src/extract/mod.rs` (add `pub(crate) mod select;`)

**Interfaces:**
- Consumes: `commands::extract::{AudioFormat, DataTableFormat}`; `paksmith_core::asset::Asset`; `paksmith_core::export::{HandlerRegistry, FormatHandler}`.
- Produces: `pub(crate) struct FormatPrefs { pub audio: AudioFormat, pub datatable: DataTableFormat }`
- Produces: `pub(crate) fn preferred_extension(asset: &Asset, prefs: &FormatPrefs) -> Option<&'static str>`
- Produces: `pub(crate) fn resolve_handler<'r>(asset: &Asset, registry: &'r HandlerRegistry, prefs: &FormatPrefs) -> Option<&'r dyn FormatHandler>`
- Produces: `pub(crate) fn select_export<'r>(payloads: &[Asset], registry: &'r HandlerRegistry, prefs: &FormatPrefs) -> Option<(usize, &'r dyn FormatHandler)>`

**Rule:** a parsed-but-untyped export is `Asset::Generic`; extract does NOT JSON-dump it (that's `inspect`'s job in 4b). `select_export` returns the first **non-`Generic`** payload that has a handler; `None` → caller does the raw `.uasset` fallback.

- [ ] **Step 1: Write the failing test**

Create `crates/paksmith-cli/src/extract/select.rs`:

```rust
//! Pick which export to convert and which handler converts it.

use paksmith_core::asset::Asset;
use paksmith_core::export::{FormatHandler, HandlerRegistry};

use crate::commands::extract::{AudioFormat, DataTableFormat};

#[derive(Copy, Clone)]
pub(crate) struct FormatPrefs {
    pub(crate) audio: AudioFormat,
    pub(crate) datatable: DataTableFormat,
}

#[cfg(test)]
mod tests {
    use super::*;
    use paksmith_core::asset::{Asset, DataTableData, SoundWaveData, Texture2DData};
    use paksmith_core::asset::property::bag::PropertyBag;

    fn prefs(audio: AudioFormat, datatable: DataTableFormat) -> FormatPrefs {
        FormatPrefs { audio, datatable }
    }

    #[test]
    fn preferred_extension_maps_domains() {
        let p = prefs(AudioFormat::Wav, DataTableFormat::Json);
        assert_eq!(
            preferred_extension(&Asset::SoundWave(SoundWaveData::empty()), &p),
            Some("wav")
        );
        assert_eq!(
            preferred_extension(&Asset::DataTable(DataTableData::empty()), &p),
            Some("json")
        );
        assert_eq!(
            preferred_extension(&Asset::Texture2D(Texture2DData::empty()), &p),
            None
        );
    }

    #[test]
    fn select_skips_generic_and_picks_typed() {
        let reg = HandlerRegistry::all_default_handlers();
        let p = prefs(AudioFormat::Ogg, DataTableFormat::Csv);
        let payloads = vec![
            Asset::Generic(PropertyBag::opaque(Vec::new())),
            Asset::DataTable(DataTableData::empty()),
        ];
        let (idx, handler) = select_export(&payloads, &reg, &p).unwrap();
        assert_eq!(idx, 1);
        assert_eq!(handler.output_extension(), "csv");
    }

    #[test]
    fn select_returns_none_when_all_generic() {
        let reg = HandlerRegistry::all_default_handlers();
        let p = prefs(AudioFormat::Ogg, DataTableFormat::Csv);
        let payloads = vec![Asset::Generic(PropertyBag::opaque(Vec::new()))];
        assert!(select_export(&payloads, &reg, &p).is_none());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p paksmith-cli select`
Expected: FAIL — functions not defined.

- [ ] **Step 3: Implement selection**

Add above the test module:

```rust
pub(crate) fn preferred_extension(asset: &Asset, prefs: &FormatPrefs) -> Option<&'static str> {
    match asset {
        Asset::SoundWave(_) => Some(match prefs.audio {
            AudioFormat::Ogg => "ogg",
            AudioFormat::Wav => "wav",
        }),
        Asset::DataTable(_) => Some(match prefs.datatable {
            DataTableFormat::Csv => "csv",
            DataTableFormat::Json => "json",
        }),
        _ => None,
    }
}

/// Resolve the handler for `asset`: honor the per-domain preferred
/// extension if one exists for the asset AND a handler serves it,
/// otherwise fall back to the variant default (`find_handler`).
/// The fallback also covers raw-codec audio (e.g. BINKA), whose only
/// handler is a `RawSoundHandler` that no preferred extension selects.
pub(crate) fn resolve_handler<'r>(
    asset: &Asset,
    registry: &'r HandlerRegistry,
    prefs: &FormatPrefs,
) -> Option<&'r dyn FormatHandler> {
    if let Some(ext) = preferred_extension(asset, prefs) {
        if let Some(h) = registry.find_handler_by_extension(ext, asset) {
            return Some(h);
        }
    }
    registry.find_handler(asset)
}

/// First non-`Generic` payload that has a handler. `Generic` exports
/// are skipped — extract emits raw bytes for untyped assets rather
/// than a JSON property dump (that is `inspect`'s role).
pub(crate) fn select_export<'r>(
    payloads: &[Asset],
    registry: &'r HandlerRegistry,
    prefs: &FormatPrefs,
) -> Option<(usize, &'r dyn FormatHandler)> {
    payloads
        .iter()
        .enumerate()
        .filter(|(_, a)| !matches!(a, Asset::Generic(_)))
        .find_map(|(idx, a)| resolve_handler(a, registry, prefs).map(|h| (idx, h)))
}
```

Register in `extract/mod.rs`:

```rust
pub(crate) mod classify;
pub(crate) mod safe_path;
pub(crate) mod select;
```

**Note:** confirm the import path for `PropertyBag::opaque` and the `*Data::empty()` constructors compile (they are used in `export/mod.rs::all_default_handlers`). Adjust the `use` paths in the test if the re-export differs.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p paksmith-cli select`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/paksmith-cli/src/extract/select.rs crates/paksmith-cli/src/extract/mod.rs
git commit -m "feat(cli): select export + handler with per-domain format prefs"
```

---

## Task 6: `summary` — outcomes + stable JSON/table rendering

**Files:**
- Create: `crates/paksmith-cli/src/extract/summary.rs`
- Modify: `crates/paksmith-cli/src/extract/mod.rs` (add `pub(crate) mod summary;`)

**Interfaces:**
- Produces: `pub(crate) enum EntryOutcome { Converted { entry: String, output: String, handler: String }, RawCopied { entry: String, output: String }, SkippedCompanion { entry: String }, Failed { entry: String, error: String } }`
- Produces: `pub(crate) struct ExtractSummary` with `pub(crate) fn from_outcomes(pak: String, output_dir: String, dry_run: bool, outcomes: Vec<EntryOutcome>) -> Self`, `pub(crate) fn had_failures(&self) -> bool`, `pub(crate) fn render(&self, format: ResolvedFormat, w: &mut dyn Write) -> io::Result<()>`.
- The serde shape MUST match the spec's §"Summary JSON schema".

- [ ] **Step 1: Write the failing test**

Create `crates/paksmith-cli/src/extract/summary.rs`:

```rust
//! Per-entry outcomes + the stable extract summary (JSON / table).

use std::io::{self, Write};

use serde::Serialize;

use crate::output::ResolvedFormat;

#[derive(Debug, Clone)]
pub(crate) enum EntryOutcome {
    Converted { entry: String, output: String, handler: String },
    RawCopied { entry: String, output: String },
    SkippedCompanion { entry: String },
    Failed { entry: String, error: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ExtractSummary {
        ExtractSummary::from_outcomes(
            "Game.pak".into(),
            "out".into(),
            false,
            vec![
                EntryOutcome::Converted {
                    entry: "A.uasset".into(),
                    output: "out/A.png".into(),
                    handler: "png".into(),
                },
                EntryOutcome::RawCopied { entry: "C.ini".into(), output: "out/C.ini".into() },
                EntryOutcome::SkippedCompanion { entry: "A.uexp".into() },
                EntryOutcome::Failed { entry: "B.uasset".into(), error: "boom".into() },
            ],
        )
    }

    #[test]
    fn counts_are_bucketed() {
        let s = sample();
        assert_eq!(s.counts.converted, 1);
        assert_eq!(s.counts.raw_copied, 1);
        assert_eq!(s.counts.skipped_companion, 1);
        assert_eq!(s.counts.failed, 1);
        assert!(s.had_failures());
    }

    #[test]
    fn json_shape_matches_spec() {
        let s = sample();
        let mut buf = Vec::new();
        s.render(ResolvedFormat::Json, &mut buf).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(v["pak"], "Game.pak");
        assert_eq!(v["counts"]["converted"], 1);
        assert_eq!(v["failures"][0]["entry"], "B.uasset");
        assert_eq!(v["outputs"].as_array().unwrap().len(), 2); // converted + raw_copied
        assert_eq!(v["outputs"][0]["kind"], "converted");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p paksmith-cli summary`
Expected: FAIL — `ExtractSummary` not defined.

- [ ] **Step 3: Implement the summary**

Add above the test module:

```rust
#[derive(Debug, Default, Serialize)]
pub(crate) struct Counts {
    pub(crate) converted: usize,
    pub(crate) raw_copied: usize,
    pub(crate) skipped_companion: usize,
    pub(crate) failed: usize,
}

#[derive(Debug, Serialize)]
pub(crate) struct OutputRecord {
    pub(crate) entry: String,
    pub(crate) output: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) handler: Option<String>,
    pub(crate) kind: &'static str,
}

#[derive(Debug, Serialize)]
pub(crate) struct FailureRecord {
    pub(crate) entry: String,
    pub(crate) error: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct ExtractSummary {
    pub(crate) pak: String,
    pub(crate) output_dir: String,
    pub(crate) dry_run: bool,
    pub(crate) counts: Counts,
    pub(crate) failures: Vec<FailureRecord>,
    pub(crate) outputs: Vec<OutputRecord>,
}

impl ExtractSummary {
    pub(crate) fn from_outcomes(
        pak: String,
        output_dir: String,
        dry_run: bool,
        outcomes: Vec<EntryOutcome>,
    ) -> Self {
        let mut counts = Counts::default();
        let mut failures = Vec::new();
        let mut outputs = Vec::new();
        for o in outcomes {
            match o {
                EntryOutcome::Converted { entry, output, handler } => {
                    counts.converted += 1;
                    outputs.push(OutputRecord { entry, output, handler: Some(handler), kind: "converted" });
                }
                EntryOutcome::RawCopied { entry, output } => {
                    counts.raw_copied += 1;
                    outputs.push(OutputRecord { entry, output, handler: None, kind: "raw_copied" });
                }
                EntryOutcome::SkippedCompanion { .. } => counts.skipped_companion += 1,
                EntryOutcome::Failed { entry, error } => {
                    counts.failed += 1;
                    failures.push(FailureRecord { entry, error });
                }
            }
        }
        // Deterministic ordering regardless of parallel completion order.
        outputs.sort_by(|a, b| a.entry.cmp(&b.entry));
        failures.sort_by(|a, b| a.entry.cmp(&b.entry));
        Self { pak, output_dir, dry_run, counts, failures, outputs }
    }

    pub(crate) fn had_failures(&self) -> bool {
        self.counts.failed > 0
    }

    pub(crate) fn render(&self, format: ResolvedFormat, w: &mut dyn Write) -> io::Result<()> {
        match format {
            ResolvedFormat::Json => {
                serde_json::to_writer_pretty(&mut *w, self)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                writeln!(w)
            }
            ResolvedFormat::Table => {
                writeln!(w, "extracted from {}", self.pak)?;
                writeln!(w, "  converted:         {}", self.counts.converted)?;
                writeln!(w, "  raw copied:        {}", self.counts.raw_copied)?;
                writeln!(w, "  skipped companion: {}", self.counts.skipped_companion)?;
                writeln!(w, "  failed:            {}", self.counts.failed)?;
                for f in &self.failures {
                    writeln!(w, "  FAILED {}: {}", f.entry, f.error)?;
                }
                Ok(())
            }
        }
    }
}
```

Register in `extract/mod.rs`:

```rust
pub(crate) mod classify;
pub(crate) mod safe_path;
pub(crate) mod select;
pub(crate) mod summary;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p paksmith-cli summary`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/paksmith-cli/src/extract/summary.rs crates/paksmith-cli/src/extract/mod.rs
git commit -m "feat(cli): add extract summary with stable JSON/table rendering"
```

---

## Task 7: `ExtractJob` — sequential walk, write logic, `run()` wiring

**Files:**
- Modify: `crates/paksmith-cli/src/extract/mod.rs` (add `ExtractConfig`, `ExtractJob`, `extract_entry`, free `write_output` + its unit tests)
- Modify: `crates/paksmith-cli/src/commands/extract.rs` (`run` builds config + job, renders summary, returns exit code; `--game` stub)

**Interfaces:**
- Consumes: Tasks 1, 3, 4, 5, 6 (`read_from_reader`, `safe_join`, `classify`, `select_export`, `EntryOutcome`/`ExtractSummary`).
- Produces: `pub(crate) struct ExtractConfig { output_dir: PathBuf, flat: bool, dry_run: bool, overwrite: bool, prefs: select::FormatPrefs }`
- Produces: `pub(crate) struct ExtractJob<'a> { reader: Arc<PakReader>, registry: &'a HandlerRegistry, cfg: &'a ExtractConfig }`
- Produces: `pub(crate) fn ExtractJob::extract_entry(&self, entry_path: &str) -> EntryOutcome`
- Produces: `pub(crate) fn ExtractJob::run_sequential(&self, entries: &[String]) -> Vec<EntryOutcome>`
- Produces (free fn): `fn write_output(cfg: &ExtractConfig, entry_path: &str, new_ext: Option<&str>, bytes: &[u8]) -> Result<String, String>` — reader-free, unit-tested in Step 3b.

- [ ] **Step 1: Write the failing integration test**

Append to `crates/paksmith-cli/tests/extract_cli.rs`:

```rust
use std::fs;
use tempfile::tempdir;

// The repo's only asset-bearing pak holds a Phase-2-era *generic* asset
// (`Game/Maps/Demo.uasset` → `Asset::Generic`), which extract raw-copies
// (no typed handler). There is NO typed cooked-asset pak fixture (the 3d–3h
// handlers are tested with in-memory `*Data` structs, not packed paks), so
// integration tests assert the RAW + summary + flag mechanics, not a typed
// conversion. The typed convert path is unit-tested in `extract/mod.rs`
// (`write_output`) + Task 5 (`select_export`) + the core handler tests. See
// the "Coverage limitation" note at the end of this plan.
//
// Path is repo-root tests/fixtures (two parents up from the crate manifest),
// matching `inspect_cli.rs`'s `fixture_path` helper.
fn fixture_pak() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent().unwrap().parent().unwrap()
        .join("tests/fixtures/real_v8b_uasset.pak")
}

#[test]
fn extract_writes_outputs_and_reports_summary() {
    let out = tempdir().unwrap();
    let mut cmd = assert_cmd::Command::cargo_bin("paksmith").unwrap();
    let assert = cmd
        .args(["--format", "json", "extract"])
        .arg(fixture_pak())
        .arg("-o").arg(out.path())
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    // Generic asset → raw fallback; every emitted entry lands in `outputs`.
    assert!(v["counts"]["raw_copied"].as_u64().unwrap() >= 1);
    assert_eq!(v["counts"]["failed"].as_u64().unwrap(), 0);
    // At least one output file exists on disk.
    let any = v["outputs"][0]["output"].as_str().unwrap();
    assert!(fs::metadata(any).is_ok(), "output not written: {any}");
}

#[test]
fn extract_dry_run_writes_nothing() {
    let out = tempdir().unwrap();
    assert_cmd::Command::cargo_bin("paksmith")
        .unwrap()
        .arg("extract").arg(fixture_pak()).arg("--dry-run")
        .arg("-o").arg(out.path())
        .assert()
        .success();
    assert_eq!(fs::read_dir(out.path()).unwrap().count(), 0);
}

#[test]
fn extract_game_flag_is_rejected() {
    assert_cmd::Command::cargo_bin("paksmith")
        .unwrap()
        .arg("extract").arg(fixture_pak())
        .args(["--game", "fortnite", "-o", "/tmp/x"])
        .assert()
        .failure()
        .code(2);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p paksmith-cli --test extract_cli extract_writes_outputs_and_reports_summary`
Expected: FAIL — `run` is still the stub returning `Ok(0)` with no output.

- [ ] **Step 3: Implement the job in `extract/mod.rs`**

Add to `crates/paksmith-cli/src/extract/mod.rs` (after the `mod` lines):

```rust
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use paksmith_core::asset::Package;
use paksmith_core::asset::mappings::Usmap;
use paksmith_core::container::ContainerReader;
use paksmith_core::container::pak::PakReader;
use paksmith_core::export::HandlerRegistry;

use self::classify::{classify, EntryClass};
use self::select::{select_export, FormatPrefs};
use self::summary::EntryOutcome;

pub(crate) struct ExtractConfig {
    pub(crate) output_dir: PathBuf,
    pub(crate) flat: bool,
    pub(crate) dry_run: bool,
    pub(crate) overwrite: bool,
    pub(crate) prefs: FormatPrefs,
}

pub(crate) struct ExtractJob<'a> {
    pub(crate) reader: Arc<PakReader>,
    pub(crate) registry: &'a HandlerRegistry,
    pub(crate) cfg: &'a ExtractConfig,
}

impl ExtractJob<'_> {
    /// Extract one entry, mapping every error into a `Failed` outcome so
    /// the batch never aborts.
    pub(crate) fn extract_entry(&self, entry_path: &str) -> EntryOutcome {
        match classify(entry_path) {
            EntryClass::Companion => EntryOutcome::SkippedCompanion { entry: entry_path.to_string() },
            EntryClass::Raw => self.extract_raw(entry_path),
            EntryClass::Asset => self.extract_asset(entry_path),
        }
    }

    fn extract_asset(&self, entry_path: &str) -> EntryOutcome {
        let pkg = match Package::read_from_reader(Arc::clone(&self.reader), entry_path, None) {
            Ok(p) => p,
            Err(e) => return EntryOutcome::Failed { entry: entry_path.to_string(), error: e.to_string() },
        };
        match select_export(&pkg.payloads, self.registry, &self.cfg.prefs) {
            Some((idx, handler)) => self.convert(entry_path, &pkg, idx, handler),
            None => self.extract_raw(entry_path), // untyped → raw .uasset
        }
    }

    fn convert(
        &self,
        entry_path: &str,
        pkg: &Package,
        idx: usize,
        handler: &dyn paksmith_core::export::FormatHandler,
    ) -> EntryOutcome {
        let bulk = match pkg.resolve_bulk_for_export(idx) {
            Ok(b) => b,
            Err(e) => return EntryOutcome::Failed { entry: entry_path.to_string(), error: e.to_string() },
        };
        let bytes = match handler.export(&pkg.payloads[idx], bulk) {
            Ok(b) => b,
            Err(e) => return EntryOutcome::Failed { entry: entry_path.to_string(), error: e.to_string() },
        };
        let ext = handler.output_extension();
        match write_output(self.cfg, entry_path, Some(ext), &bytes) {
            Ok(output) => EntryOutcome::Converted {
                entry: entry_path.to_string(),
                output,
                handler: ext.to_string(),
            },
            Err(e) => EntryOutcome::Failed { entry: entry_path.to_string(), error: e },
        }
    }

    fn extract_raw(&self, entry_path: &str) -> EntryOutcome {
        let bytes = match self.reader.read_entry(entry_path) {
            Ok(b) => b,
            Err(e) => return EntryOutcome::Failed { entry: entry_path.to_string(), error: e.to_string() },
        };
        match write_output(self.cfg, entry_path, None, &bytes) {
            Ok(output) => EntryOutcome::RawCopied { entry: entry_path.to_string(), output },
            Err(e) => EntryOutcome::Failed { entry: entry_path.to_string(), error: e },
        }
    }

    pub(crate) fn run_sequential(&self, entries: &[String]) -> Vec<EntryOutcome> {
        entries.iter().map(|e| self.extract_entry(e)).collect()
    }
}

/// Derive the safe output path, replacing the extension when `new_ext` is
/// `Some` (converted) or keeping it (raw). Honors `--dry-run` (no write) and
/// `--overwrite`. Returns the output path as a String, or a human error
/// string. Free function (no reader/registry dependency) so the entire
/// write / dry-run / overwrite / extension-swap surface is unit-testable
/// without a pak — see the `#[cfg(test)]` block below.
fn write_output(
    cfg: &ExtractConfig,
    entry_path: &str,
    new_ext: Option<&str>,
    bytes: &[u8],
) -> Result<String, String> {
    let mut path = safe_path::safe_join(&cfg.output_dir, entry_path, cfg.flat)
        .map_err(|e| e.to_string())?;
    if let Some(ext) = new_ext {
        path.set_extension(ext);
    }
    let display = path.to_string_lossy().into_owned();

    if cfg.dry_run {
        return Ok(display);
    }
    if path.exists() && !cfg.overwrite {
        return Err(format!("output exists (use --overwrite): {display}"));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create dir {}: {e}", parent.display()))?;
    }
    let mut f = fs::File::create(&path).map_err(|e| format!("create {display}: {e}"))?;
    f.write_all(bytes).map_err(|e| format!("write {display}: {e}"))?;
    Ok(display)
}
```

Append the `mod` block at the top of `extract/mod.rs` so it reads:

```rust
pub(crate) mod classify;
pub(crate) mod safe_path;
pub(crate) mod select;
pub(crate) mod summary;
```

**Note:** `--flat` collision handling falls out of `write_output`: two entries → same path → second hits the `path.exists() && !overwrite` guard → `Failed`. With `--overwrite`, last-writer-wins (matches spec).

- [ ] **Step 3b: Unit-test `write_output` directly (no pak needed)**

This is where the write/dry-run/overwrite/extension-swap surface gets its own coverage (the typed-conversion path through a packed pak is a documented 4a gap — see "Coverage limitation"). Add a `#[cfg(test)]` module to `extract/mod.rs`:

```rust
#[cfg(test)]
mod write_output_tests {
    use super::*;
    use crate::commands::extract::{AudioFormat, DataTableFormat};

    fn cfg(dir: &std::path::Path, flat: bool, dry_run: bool, overwrite: bool) -> ExtractConfig {
        ExtractConfig {
            output_dir: dir.to_path_buf(),
            flat,
            dry_run,
            overwrite,
            prefs: FormatPrefs { audio: AudioFormat::Ogg, datatable: DataTableFormat::Csv },
        }
    }

    #[test]
    fn writes_converted_with_swapped_extension() {
        let dir = tempfile::tempdir().unwrap();
        let c = cfg(dir.path(), false, false, false);
        let out = write_output(&c, "Game/Hero.uasset", Some("png"), b"PNGDATA").unwrap();
        assert!(out.ends_with("Game/Hero.png"), "got {out}");
        assert_eq!(std::fs::read(&out).unwrap(), b"PNGDATA");
    }

    #[test]
    fn raw_keeps_extension() {
        let dir = tempfile::tempdir().unwrap();
        let c = cfg(dir.path(), false, false, false);
        let out = write_output(&c, "Config/Game.ini", None, b"[x]").unwrap();
        assert!(out.ends_with("Config/Game.ini"), "got {out}");
        assert_eq!(std::fs::read(&out).unwrap(), b"[x]");
    }

    #[test]
    fn dry_run_writes_nothing_but_reports_path() {
        let dir = tempfile::tempdir().unwrap();
        let c = cfg(dir.path(), false, true, false);
        let out = write_output(&c, "Game/Hero.uasset", Some("png"), b"X").unwrap();
        assert!(out.ends_with("Game/Hero.png"));
        assert!(!std::path::Path::new(&out).exists());
    }

    #[test]
    fn overwrite_guard_then_allow() {
        let dir = tempfile::tempdir().unwrap();
        let guard = cfg(dir.path(), false, false, false);
        write_output(&guard, "A.bin", None, b"1").unwrap();
        assert!(write_output(&guard, "A.bin", None, b"2").is_err()); // exists, no overwrite
        let force = cfg(dir.path(), false, false, true);
        write_output(&force, "A.bin", None, b"2").unwrap(); // last-writer-wins
        let out = dir.path().join("A.bin");
        assert_eq!(std::fs::read(out).unwrap(), b"2");
    }

    #[test]
    fn flat_uses_basename() {
        let dir = tempfile::tempdir().unwrap();
        let c = cfg(dir.path(), true, false, false);
        let out = write_output(&c, "Deep/Nested/Hero.uasset", Some("png"), b"X").unwrap();
        assert_eq!(std::path::Path::new(&out), dir.path().join("Hero.png"));
    }

    #[test]
    fn rejects_traversal_entry() {
        let dir = tempfile::tempdir().unwrap();
        let c = cfg(dir.path(), false, false, false);
        assert!(write_output(&c, "../../evil", None, b"X").is_err());
    }
}
```

Run: `cargo test -p paksmith-cli write_output_tests`
Expected: PASS (6 tests). These cover the write surface that the integration tests (which only see a generic→raw asset) cannot exercise for the converted extension-swap.

- [ ] **Step 4: Implement `run()` in `commands/extract.rs`**

Replace the stub `run`:

```rust
use std::io::{self, Write};
use std::sync::Arc;

use paksmith_core::PaksmithError;
use paksmith_core::container::ContainerReader;
use paksmith_core::container::pak::PakReader;
use paksmith_core::export::HandlerRegistry;

use crate::extract::select::FormatPrefs;
use crate::extract::summary::ExtractSummary;
use crate::extract::{ExtractConfig, ExtractJob};

pub(crate) fn run(args: &ExtractArgs, format: OutputFormat) -> paksmith_core::Result<u8> {
    if args.game.is_some() {
        return Err(PaksmithError::InvalidArgument {
            arg: "--game",
            reason: "game profiles are not supported until Phase 5".into(),
        });
    }

    let reader = Arc::new(PakReader::open(&args.pak)?);

    let pattern = match &args.filter {
        Some(p) => Some(glob::Pattern::new(p).map_err(|e| PaksmithError::InvalidArgument {
            arg: "--filter",
            reason: e.to_string(),
        })?),
        None => None,
    };

    let entries: Vec<String> = reader
        .entries()
        .filter(|e| pattern.as_ref().is_none_or(|pat| pat.matches(e.path())))
        .map(|e| e.path().to_string())
        .collect();

    let registry = HandlerRegistry::all_default_handlers();
    let cfg = ExtractConfig {
        output_dir: args.output.clone(),
        flat: args.flat,
        dry_run: args.dry_run,
        overwrite: args.overwrite,
        prefs: FormatPrefs { audio: args.audio_format, datatable: args.datatable_format },
    };
    let job = ExtractJob { reader: Arc::clone(&reader), registry: &registry, cfg: &cfg };

    let outcomes = job.run_sequential(&entries);
    let summary = ExtractSummary::from_outcomes(
        args.pak.display().to_string(),
        args.output.display().to_string(),
        args.dry_run,
        outcomes,
    );

    let resolved = format.resolve();
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    summary.render(resolved, &mut out)?;
    out.flush()?;

    Ok(u8::from(summary.had_failures()))
}
```

(`is_none_or` is stable on 1.88 — confirm; if MSRV rejects it, use `pattern.as_ref().map_or(true, |pat| pat.matches(e.path()))`.)

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p paksmith-cli --test extract_cli`
Expected: PASS (writes-outputs, dry-run-writes-nothing, game-flag-rejected, help).

- [ ] **Step 6: Commit**

```bash
git add crates/paksmith-cli/src/extract/mod.rs crates/paksmith-cli/src/commands/extract.rs \
        crates/paksmith-cli/tests/extract_cli.rs
git commit -m "feat(cli): wire sequential extract job, write logic, and run()"
```

---

## Task 8: Parallelism — `rayon` over a shared reader + `--jobs`

**Files:**
- Modify: `crates/paksmith-cli/src/extract/mod.rs` (`run_parallel`)
- Modify: `crates/paksmith-cli/src/commands/extract.rs` (`--jobs` → thread pool; call `run_parallel`)

**Interfaces:**
- Produces: `pub(crate) fn ExtractJob::run_parallel(&self, entries: &[String]) -> Vec<EntryOutcome>` (requires `&self: Sync` — `Arc<PakReader>` + `&HandlerRegistry` + `&ExtractConfig` are all `Sync`).

- [ ] **Step 1: Write the failing test (parallel determinism)**

Append to `crates/paksmith-cli/tests/extract_cli.rs`:

```rust
#[test]
fn extract_summary_is_stable_across_jobs() {
    fn summary_json(jobs: &str) -> serde_json::Value {
        let out = tempfile::tempdir().unwrap();
        let assert = assert_cmd::Command::cargo_bin("paksmith")
            .unwrap()
            .args(["--format", "json", "extract"])
            .arg(fixture_pak())
            .args(["--jobs", jobs])
            .arg("-o").arg(out.path())
            .assert()
            .success();
        let s = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
        serde_json::from_str(&s).unwrap()
    }
    let one = summary_json("1");
    let four = summary_json("4");
    assert_eq!(one["counts"], four["counts"]);
    assert_eq!(one["outputs"], four["outputs"]); // sorted in from_outcomes
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p paksmith-cli --test extract_cli extract_summary_is_stable_across_jobs`
Expected: FAIL — `--jobs` is parsed but unused (still sequential); test may pass spuriously if sequential, so ALSO assert the method exists by switching `run()` to `run_parallel` in Step 4 and confirming the build. (If it passes at this step because sequential output already matches, that's acceptable — the determinism contract is what matters; proceed to wire parallelism.)

- [ ] **Step 3: Implement `run_parallel`**

Add to `extract/mod.rs` (add `use rayon::prelude::*;` at top):

```rust
impl ExtractJob<'_> {
    pub(crate) fn run_parallel(&self, entries: &[String]) -> Vec<EntryOutcome> {
        entries.par_iter().map(|e| self.extract_entry(e)).collect()
    }
}
```

(`par_iter().map().collect()` preserves input order in the returned `Vec`; `from_outcomes` sorts anyway. Reads serialize on `PakReader`'s internal `Mutex`; decode/encode run concurrently.)

- [ ] **Step 4: Wire `--jobs` + call `run_parallel` in `commands/extract.rs`**

Replace `let outcomes = job.run_sequential(&entries);` with:

```rust
let outcomes = if let Some(n) = args.jobs {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(n)
        .build()
        .map_err(|e| PaksmithError::InvalidArgument { arg: "--jobs", reason: e.to_string() })?;
    pool.install(|| job.run_parallel(&entries))
} else {
    job.run_parallel(&entries)
};
```

(Keep `run_sequential` — it stays useful for unit tests and is the single-threaded reference.)

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p paksmith-cli --test extract_cli`
Expected: PASS (including determinism + a `--jobs 1` path).

- [ ] **Step 6: Commit**

```bash
git add crates/paksmith-cli/src/extract/mod.rs crates/paksmith-cli/src/commands/extract.rs
git commit -m "feat(cli): parallelize extract with rayon over a shared reader"
```

---

## Task 9: Progress — `indicatif` on stderr

**Files:**
- Modify: `crates/paksmith-cli/src/extract/mod.rs` (`run_parallel` ticks a progress bar)
- Modify: `crates/paksmith-cli/src/commands/extract.rs` (construct/own the bar)

**Interfaces:**
- Produces: `pub(crate) fn ExtractJob::run_with_progress(&self, entries: &[String], progress: &indicatif::ProgressBar) -> Vec<EntryOutcome>`

- [ ] **Step 1: Write the failing test**

Append to `crates/paksmith-cli/tests/extract_cli.rs`:

```rust
#[test]
fn extract_progress_goes_to_stderr_not_stdout_json() {
    let out = tempfile::tempdir().unwrap();
    let assert = assert_cmd::Command::cargo_bin("paksmith")
        .unwrap()
        .args(["--format", "json", "extract"])
        .arg(fixture_pak())
        .arg("-o").arg(out.path())
        .assert()
        .success();
    // stdout must be pure JSON (parseable) — no progress bytes mixed in.
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    serde_json::from_str::<serde_json::Value>(&stdout)
        .expect("stdout is not clean JSON — progress leaked to stdout");
}
```

- [ ] **Step 2: Run test to verify it fails or passes**

Run: `cargo test -p paksmith-cli --test extract_cli extract_progress_goes_to_stderr_not_stdout_json`
Expected: PASS already (no progress yet) — this is a guard test that must KEEP passing after Step 3 wires the bar. Note it now; re-run after Step 3.

- [ ] **Step 3: Implement progress**

In `extract/mod.rs`:

```rust
use indicatif::ProgressBar;

impl ExtractJob<'_> {
    pub(crate) fn run_with_progress(
        &self,
        entries: &[String],
        progress: &ProgressBar,
    ) -> Vec<EntryOutcome> {
        let out = entries
            .par_iter()
            .map(|e| {
                let outcome = self.extract_entry(e);
                progress.inc(1);
                outcome
            })
            .collect();
        progress.finish_and_clear();
        out
    }
}
```

In `commands/extract.rs`, replace the outcomes block:

```rust
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};

let progress = ProgressBar::with_draw_target(
    Some(entries.len() as u64),
    ProgressDrawTarget::stderr(), // never stdout — keeps JSON clean
);
progress.set_style(
    ProgressStyle::with_template("{bar:40} {pos}/{len} {msg}")
        .unwrap_or_else(|_| ProgressStyle::default_bar()),
);

let outcomes = if let Some(n) = args.jobs {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(n)
        .build()
        .map_err(|e| PaksmithError::InvalidArgument { arg: "--jobs", reason: e.to_string() })?;
    pool.install(|| job.run_with_progress(&entries, &progress))
} else {
    job.run_with_progress(&entries, &progress)
};
```

(`ProgressDrawTarget::stderr()` guarantees the bar never contaminates stdout JSON. `indicatif` is `Sync`, so `&progress` crosses rayon threads.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p paksmith-cli --test extract_cli`
Expected: PASS (stdout-clean-JSON guard still green; all extract tests pass).

- [ ] **Step 5: Commit**

```bash
git add crates/paksmith-cli/src/extract/mod.rs crates/paksmith-cli/src/commands/extract.rs
git commit -m "feat(cli): add stderr progress bar to extract"
```

---

## Task 10: Integration coverage, fixtures, docs, CI gate

**Files:**
- Modify: `crates/paksmith-cli/tests/extract_cli.rs` (snapshots + error cases)
- Create (if needed): `crates/paksmith-cli/tests/fixtures/*.pak`
- Modify: `.github/workflows/ci.yml` (fixture-count gate, only if a new `.pak` was added)
- Modify: `docs/plans/ROADMAP.md` (mark 4a `extract` shipped under Phase 4)

**Interfaces:** none (test/docs only).

- [ ] **Step 1: Fixture (decided — no new fixture in 4a)**

Use the existing repo-root `tests/fixtures/real_v8b_uasset.pak` (the `fixture_pak()` helper added in Task 7). It contains `Game/Maps/Demo.uasset`, a Phase-2-era **generic** asset that extract raw-copies — which is all the integration tests assert (raw/summary/flags/exit-codes). Do **not** generate a new fixture: the repo has no typed cooked-asset pak, and producing one is out of 4a scope (see "Coverage limitation"). No `.pak` is added, so the CI fixture-count gate is untouched.

- [ ] **Step 2: Add error-case + overwrite + insta snapshot tests**

Append to `extract_cli.rs`:

```rust
#[test]
fn extract_overwrite_guard() {
    let out = tempfile::tempdir().unwrap();
    let mut first = assert_cmd::Command::cargo_bin("paksmith").unwrap();
    first.arg("extract").arg(fixture_pak()).arg("-o").arg(out.path()).assert().success();
    // Second run without --overwrite: existing files → failures → exit 1.
    assert_cmd::Command::cargo_bin("paksmith")
        .unwrap()
        .arg("extract").arg(fixture_pak()).arg("-o").arg(out.path())
        .assert()
        .code(1);
    // With --overwrite: success.
    assert_cmd::Command::cargo_bin("paksmith")
        .unwrap()
        .arg("extract").arg(fixture_pak()).arg("--overwrite").arg("-o").arg(out.path())
        .assert()
        .success();
}

#[test]
fn extract_missing_pak_is_fatal() {
    assert_cmd::Command::cargo_bin("paksmith")
        .unwrap()
        .args(["extract", "/no/such.pak", "-o", "/tmp/x"])
        .assert()
        .code(2);
}

#[test]
fn extract_summary_snapshot() {
    let out = tempfile::tempdir().unwrap();
    let assert = assert_cmd::Command::cargo_bin("paksmith")
        .unwrap()
        .args(["--format", "json", "extract"])
        .arg(fixture_pak())
        .arg("--dry-run").arg("-o").arg(out.path())
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let mut v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    // Redact host-specific paths so the snapshot is portable.
    v["output_dir"] = serde_json::Value::String("<tmp>".into());
    if let Some(outs) = v["outputs"].as_array_mut() {
        for o in outs {
            o["output"] = serde_json::Value::String("<tmp>/redacted".into());
        }
    }
    insta::assert_json_snapshot!(v);
}
```

- [ ] **Step 3: Run the tests; accept the snapshot**

Run: `cargo test -p paksmith-cli --test extract_cli`
Then: `cargo insta review` (or `INSTA_UPDATE=always cargo test -p paksmith-cli --test extract_cli`) to accept the snapshot.
Expected: all PASS; snapshot file committed under `crates/paksmith-cli/tests/snapshots/`.

- [ ] **Step 4: Update ROADMAP**

In `docs/plans/ROADMAP.md` Phase 4 section, note that 4a `extract` shipped (mirror the Phase 2/3 sub-phase convention). Keep it factual; no engine-source references.

- [ ] **Step 5: Full gate chain**

Run, fixing any failure:
```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
typos .
```
Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add crates/paksmith-cli/tests/extract_cli.rs \
        crates/paksmith-cli/tests/snapshots/ docs/plans/ROADMAP.md \
        .github/workflows/ci.yml 2>/dev/null
git commit -m "test(cli): integration + snapshot coverage for extract; mark 4a shipped"
```

---

## Review & Push

- [ ] Run the adversarial multi-agent review panel (≥3 reviewers + **security specialist** for the path/parse/write surface, + wire-format/deep-impact as the panel judges). Brief reviewers cold; pass the diff.
- [ ] Cycle to convergence (R2, R3, …) — fix-forward, re-dispatch the full panel after each fix commit. Stop only when every reviewer APPROVES with no open findings.
- [ ] Touch the convergence marker, then push + open PR:
  ```bash
  touch "$(git rev-parse --git-dir)/REVIEW_CONVERGED_OK"
  git push -u origin feat/phase-4a-extract
  ```
- [ ] Open the PR (`gh ... --body-file`), then Monitor CI to green. Do NOT merge — the user merges via UI.

---

## Self-Review (plan vs spec)

**Spec coverage:**
- Batch walk + `--filter` → Task 7 (run). ✓
- Mirror tree / `--flat` → Task 3 (safe_join flat) + Task 7. ✓
- `--dry-run` (parse-accurate) → Task 7 (free `write_output` dry_run; parses then skips write) + Step 3b unit test. ✓
- `--overwrite` + collision policy → Task 7 (free `write_output`) + Step 3b unit test + Task 10 (integration). ✓
- Per-domain format flags → Task 2 (args) + Task 5 (select). ✓
- Raw fallback / companion skip / convert → Task 4 (classify) + Task 5/7. ✓
- Multi-export rule (first non-Generic) → Task 5 (select_export). ✓
- `rayon` parallelism + `--jobs` → Task 8. ✓
- `indicatif` progress on stderr → Task 9. ✓
- Continue-on-error + summary → Task 6 (summary) + Task 7 (errors → Failed). ✓
- Stable JSON schema → Task 6. ✓
- Exit codes 0/1/2 → Task 2 (plumbing) + Task 7 (had_failures → 1; Err → 2). ✓
- Zip-slip safety → Task 3 (dedicated). ✓
- Core `read_from_reader` → Task 1. ✓
- `--game` stub → Task 2 (arg) + Task 7 (reject). ✓
- Testing approach (assert_cmd, insta, tempdir, adversarial, determinism) → Tasks 3/6/7/8/10. ✓

**Type consistency:** `EntryOutcome` variants, `ExtractSummary`/`Counts`/`OutputRecord`/`FailureRecord`, `FormatPrefs`, `ExtractConfig`/`ExtractJob`, `select_export` signature, and `read_from_reader` signature are referenced identically across Tasks 5–9. `run` returns `paksmith_core::Result<u8>` consistently (Task 2 contract; Task 7 fills it).

**Open verification flags for the implementer (resolve at the task, don't guess):**
- Fixture: **resolved** — `tests/fixtures/real_v8b_uasset.pak`, asset `Game/Maps/Demo.uasset` (confirmed `Asset::Generic` via `paksmith inspect`). The `fixture_pak()` helper (Task 7) points at it; no new fixture in 4a.
- `PropertyBag::opaque` / `*Data::empty()` import paths (Task 5 test) — mirror `export/mod.rs::all_default_handlers` (which uses `crate::asset::property::bag::PropertyBag` and `crate::asset::{DataTableData, Texture2DData, …}::empty()`). Confirm the re-export path from the CLI crate.
- `is_none_or` MSRV availability on 1.88 (Task 7) — fallback `map_or` given inline.
- `PaksmithError::InvalidArgument` field shape (`arg: &'static str, reason: String`) — confirmed used in `list.rs`/`inspect.rs`.
- `pkg.payloads` is a `pub` field on `Package` (confirmed) — read directly from the CLI crate.

## Coverage limitation (documented, not silent)

**True end-to-end typed conversion through a packed pak is NOT covered in 4a.**
The repository has no `.pak` fixture containing a *typed* cooked asset — the
Phase 3 handlers (3d–3h) are tested with in-memory `*Data` structs, and the
only asset-bearing pak (`real_v8b_uasset.pak`) holds a `Generic` asset that
extract raw-copies. Producing a typed cooked-asset pak (cooked
Texture2D/DataTable bytes + companions, packed via `paksmith-fixture-gen`) is
non-trivial and out of 4a scope.

What IS covered, and why this is acceptable:
- `select_export` (Generic-skip, typed-pick, per-domain prefs) — unit (Task 5).
- `handler.export(asset, bulk)` correctness — existing core handler tests.
- `write_output` (extension swap for converted, dry-run, overwrite, flat,
  traversal reject) — unit (Task 7 Step 3b), exercising the *converted*
  extension-swap branch that integration can't reach.
- End-to-end walk / raw fallback / companion skip / exit codes / determinism /
  progress-to-stderr / `--game` / missing-pak — integration (Tasks 7–10).

The only untested glue is the ~6-line `convert()` delegation
(`resolve_bulk_for_export` → `export` → `write_output`), all of whose parts are
tested independently. A typed-asset pak fixture enabling a full
pak→png/csv assertion is a tracked **4a follow-up** (and a natural shared
asset for 4b/4c). Flag it in the PR body; do not fake it.
