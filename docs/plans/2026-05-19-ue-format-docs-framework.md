# UE Format Documentation Framework — PR 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land PR 1 from the framework spec — the `docs/formats/` scaffold (root README, TEMPLATE, CONVENTIONS, 12 family READMEs), a new `paksmith-doc-lint` workspace crate hosting the required-headings + status-enum linters, a CI workflow that runs them on every PR, plus the PR-template checkbox and CONTRIBUTING.md attribution line.

**Architecture:** New workspace member `paksmith-doc-lint` excluded from `default-members` (mirrors `paksmith-fixture-gen`). Single binary with two subcommands: `required-headings <dir>` and `status-enum <readme.md>`. Both exit non-zero on failure, printing line-pointed diagnostics. CI invokes them via `cargo run -p paksmith-doc-lint --`. Linter implementations use only stdlib + `walkdir` (already in tree via dev-deps if present, otherwise added) — no markdown parser dependency. Format-docs themselves are pure prose, no rows yet in the inventory.

**Tech Stack:** Rust 1.88+ (workspace MSRV), `walkdir` for directory traversal, `anyhow` for top-level CLI error reporting, `assert_cmd` + `predicates` for binary integration tests. No new Rust runtime dependencies beyond what the workspace already pins where possible.

**Spec reference:** `docs/design/2026-05-19-ue-format-docs.md` (commit `72b364e`). Branch: `docs/ue-format-docs-framework`.

---

## File structure

**New files (28):**

- `crates/paksmith-doc-lint/Cargo.toml` — manifest, `[[bin]]` declaration
- `crates/paksmith-doc-lint/src/main.rs` — CLI dispatch (clap or manual arg parsing — manual is fine, two subcommands)
- `crates/paksmith-doc-lint/src/lib.rs` — re-exports for tests
- `crates/paksmith-doc-lint/src/required_headings.rs` — required-headings linter
- `crates/paksmith-doc-lint/src/status_enum.rs` — inventory status-enum linter
- `crates/paksmith-doc-lint/tests/required_headings.rs` — integration tests for the headings linter
- `crates/paksmith-doc-lint/tests/status_enum.rs` — integration tests for the inventory linter
- `crates/paksmith-doc-lint/tests/cli.rs` — assert_cmd tests for the binary surface
- `docs/formats/README.md` — front door + schema doc + empty inventory section
- `docs/formats/TEMPLATE.md` — canonical per-doc skeleton (the eight H2 sections)
- `docs/formats/CONVENTIONS.md` — hex-anchor format, citation style, allowed inspection commands
- `docs/formats/container/README.md` — family overview (narrative only)
- `docs/formats/asset/README.md`
- `docs/formats/property/README.md`
- `docs/formats/primitive/README.md`
- `docs/formats/texture/README.md`
- `docs/formats/mesh/README.md`
- `docs/formats/audio/README.md`
- `docs/formats/animation/README.md`
- `docs/formats/material/README.md`
- `docs/formats/data/README.md`
- `docs/formats/compression/README.md`
- `docs/formats/crypto/README.md`
- `.github/workflows/format-docs.yml` — runs the two linters on PRs that touch `docs/formats/**` or `crates/paksmith-doc-lint/**`

**Modified files (3):**

- `Cargo.toml` (workspace root) — add `crates/paksmith-doc-lint` to `members`, exclude from `default-members`
- `.github/pull_request_template.md` — add "Touched a parser? Updated its format doc?" line to Pre-flight checklist
- `CONTRIBUTING.md` — add a Documentation section noting the no-EpicGames-source attribution rule for `docs/formats/`

**File responsibilities at a glance:**

- `main.rs` is dispatch only; logic lives in the per-linter modules so tests don't have to shell out for every assertion.
- `required_headings.rs` walks a directory, ignores configured filenames, parses H2 lines from each remaining `.md`, and diffs against the expected ordered sequence.
- `status_enum.rs` parses one markdown file (the inventory README), finds the inventory table, validates each row's status columns against fixed enum sets, and emits smell warnings for known-bad combinations.
- Tests in `tests/` use inline string fixtures (`tempfile` for the directory-walking test). No shared test fixtures on disk — each test is self-contained.

---

## Task 1: Bootstrap the workspace crate

**Files:**
- Create: `crates/paksmith-doc-lint/Cargo.toml`
- Create: `crates/paksmith-doc-lint/src/main.rs`
- Create: `crates/paksmith-doc-lint/src/lib.rs`
- Modify: `Cargo.toml` (workspace root)

- [ ] **Step 1: Read the workspace root manifest to see existing `members` and `default-members` shape**

Run: `cat Cargo.toml | head -60`
Expected: a `[workspace]` table with `members = [...]` and `default-members = [...]`. Note exact list so the edit preserves ordering.

- [ ] **Step 2: Add the new crate to `[workspace] members` (alphabetically), keep it out of `default-members`**

Use the Edit tool. The exact `old_string`/`new_string` depends on what Step 1 printed — DO NOT replace the whole `[workspace]` block, only insert one line in the `members` array.

The new crate goes after `"crates/paksmith-core-tests"` and before `"crates/paksmith-fixture-gen"` (or whichever crate sorts immediately after `paksmith-core-tests` and before `paksmith-fixture-gen` alphabetically).

Concretely, use Edit with:

- `old_string`: the line `    "crates/paksmith-core-tests",` (including its trailing comma and the leading indentation as printed in Step 1)
- `new_string`: that same line, followed by `\n    "crates/paksmith-doc-lint",`

Do NOT add the crate to `default-members` — it's a dev-only tool, mirroring `paksmith-fixture-gen`. If `paksmith-bench` or any other unrelated crate appears in either list, leave it untouched.

- [ ] **Step 3: Create the crate's `Cargo.toml`**

Write `crates/paksmith-doc-lint/Cargo.toml`:

```toml
[package]
name = "paksmith-doc-lint"
version = "0.0.0"
edition = "2021"
rust-version.workspace = true
publish = false
description = "Internal lint tool: validates docs/formats/ structure"

[[bin]]
name = "paksmith-doc-lint"
path = "src/main.rs"

[lib]
path = "src/lib.rs"

[dependencies]
walkdir = "2"
anyhow = "1"

[dev-dependencies]
assert_cmd = "2"
predicates = "3"
tempfile = "3"
```

If `rust-version.workspace = true` doesn't resolve (the workspace doesn't pin `rust-version` in `[workspace.package]`), replace with `rust-version = "1.88"`. Check with `grep "rust-version" Cargo.toml`.

- [ ] **Step 4: Create a stub `src/lib.rs`**

Write `crates/paksmith-doc-lint/src/lib.rs`:

```rust
pub mod required_headings;
pub mod status_enum;
```

This will fail to compile until Tasks 2 and 3 add the modules, which is intentional — Task 2 creates `required_headings.rs` next.

- [ ] **Step 5: Create a stub `src/main.rs`**

Write `crates/paksmith-doc-lint/src/main.rs`:

```rust
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("required-headings") => {
            let dir = match args.get(2) {
                Some(d) => d,
                None => {
                    eprintln!("usage: paksmith-doc-lint required-headings <dir>");
                    return ExitCode::from(2);
                }
            };
            match paksmith_doc_lint::required_headings::check_dir(std::path::Path::new(dir)) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("{e}");
                    ExitCode::FAILURE
                }
            }
        }
        Some("status-enum") => {
            let file = match args.get(2) {
                Some(f) => f,
                None => {
                    eprintln!("usage: paksmith-doc-lint status-enum <readme.md>");
                    return ExitCode::from(2);
                }
            };
            match paksmith_doc_lint::status_enum::check_file(std::path::Path::new(file)) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("{e}");
                    ExitCode::FAILURE
                }
            }
        }
        _ => {
            eprintln!("usage: paksmith-doc-lint <required-headings|status-enum> <path>");
            ExitCode::from(2)
        }
    }
}
```

- [ ] **Step 6: Create stub module files so the crate compiles**

Write `crates/paksmith-doc-lint/src/required_headings.rs`:

```rust
use anyhow::Result;
use std::path::Path;

pub fn check_dir(_dir: &Path) -> Result<()> {
    anyhow::bail!("not yet implemented")
}
```

Write `crates/paksmith-doc-lint/src/status_enum.rs`:

```rust
use anyhow::Result;
use std::path::Path;

pub fn check_file(_file: &Path) -> Result<()> {
    anyhow::bail!("not yet implemented")
}
```

- [ ] **Step 7: Verify the workspace builds**

Run: `cargo build -p paksmith-doc-lint`
Expected: builds cleanly, two warnings about unused parameters which Task 2 will resolve.

Run: `cargo build` (no `-p`)
Expected: builds default-members only — does NOT include `paksmith-doc-lint`. Verifies the exclusion landed.

- [ ] **Step 8: Commit**

```bash
git add Cargo.toml crates/paksmith-doc-lint/
git commit -m "$(cat <<'EOF'
chore(doc-lint): bootstrap paksmith-doc-lint workspace crate

Adds a new workspace member that will host CI lint tools for
docs/formats/. Excluded from default-members so routine `cargo build`
and `cargo test` skip it (mirrors paksmith-fixture-gen). Subcommand
skeleton in place; linter bodies land in subsequent commits.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Implement the required-headings linter

**Files:**
- Modify: `crates/paksmith-doc-lint/src/required_headings.rs`
- Create: `crates/paksmith-doc-lint/tests/required_headings.rs`

The linter enforces that every `.md` file under `docs/formats/` (excluding `README.md`, `TEMPLATE.md`, `CONVENTIONS.md`) contains these eight H2 headings in this exact order:

1. `## Overview`
2. `## Versions`
3. `## Wire layout`
4. `## Variants`
5. `## Caps & limits`
6. `## Verification`
7. `## Paksmith implementation`
8. `## References`

The lint must NOT trip on file presence / absence — it's a content lint, not a manifest lint.

- [ ] **Step 1: Write the failing test for a well-formed doc**

Create `crates/paksmith-doc-lint/tests/required_headings.rs`:

```rust
use paksmith_doc_lint::required_headings::check_dir;
use std::fs;
use tempfile::TempDir;

const WELL_FORMED: &str = "\
# Some format

## Overview
text
## Versions
text
## Wire layout
text
## Variants
text
## Caps & limits
text
## Verification
text
## Paksmith implementation
text
## References
text
";

#[test]
fn accepts_well_formed_doc() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("some-format.md"), WELL_FORMED).unwrap();
    check_dir(dir.path()).expect("well-formed doc should pass");
}
```

- [ ] **Step 2: Run the test, verify it fails because impl is stubbed**

Run: `cargo test -p paksmith-doc-lint --test required_headings accepts_well_formed_doc`
Expected: FAIL — the `bail!("not yet implemented")` stub trips.

- [ ] **Step 3: Write the minimal impl that passes Step 1**

Replace `crates/paksmith-doc-lint/src/required_headings.rs` body:

```rust
use anyhow::{Context, Result, bail};
use std::path::Path;
use walkdir::WalkDir;

const REQUIRED: &[&str] = &[
    "## Overview",
    "## Versions",
    "## Wire layout",
    "## Variants",
    "## Caps & limits",
    "## Verification",
    "## Paksmith implementation",
    "## References",
];

const EXCLUDED_FILENAMES: &[&str] = &["README.md", "TEMPLATE.md", "CONVENTIONS.md"];

pub fn check_dir(dir: &Path) -> Result<()> {
    let mut failures: Vec<String> = Vec::new();
    for entry in WalkDir::new(dir).into_iter().filter_map(Result::ok) {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("md") {
            continue;
        }
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if EXCLUDED_FILENAMES.contains(&name) {
            continue;
        }
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;
        if let Err(msg) = check_content(&content) {
            failures.push(format!("{}: {msg}", path.display()));
        }
    }
    if !failures.is_empty() {
        bail!("required-headings lint failed:\n  - {}", failures.join("\n  - "));
    }
    Ok(())
}

fn check_content(content: &str) -> Result<(), String> {
    let h2s: Vec<&str> = content
        .lines()
        .filter(|l| l.starts_with("## "))
        .collect();
    if h2s.len() < REQUIRED.len() {
        return Err(format!(
            "missing required headings: found {}, expected {}",
            h2s.len(),
            REQUIRED.len()
        ));
    }
    for (i, expected) in REQUIRED.iter().enumerate() {
        if h2s.get(i) != Some(expected) {
            return Err(format!(
                "heading at position {} is {:?}, expected {:?}",
                i + 1,
                h2s.get(i).copied().unwrap_or(""),
                expected
            ));
        }
    }
    Ok(())
}
```

- [ ] **Step 4: Run the test, verify it now passes**

Run: `cargo test -p paksmith-doc-lint --test required_headings accepts_well_formed_doc`
Expected: PASS.

- [ ] **Step 5: Add failing test for a doc with missing heading**

Append to `crates/paksmith-doc-lint/tests/required_headings.rs`:

```rust
const MISSING_REFERENCES: &str = "\
# Some format

## Overview
text
## Versions
text
## Wire layout
text
## Variants
text
## Caps & limits
text
## Verification
text
## Paksmith implementation
text
";

#[test]
fn rejects_doc_missing_references_section() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("some-format.md"), MISSING_REFERENCES).unwrap();
    let err = check_dir(dir.path()).expect_err("should fail");
    assert!(err.to_string().contains("missing required headings") ||
            err.to_string().contains("expected"),
            "unexpected error: {err}");
}
```

- [ ] **Step 6: Run it, verify it passes against the existing impl**

Run: `cargo test -p paksmith-doc-lint --test required_headings rejects_doc_missing_references_section`
Expected: PASS (the impl already covers missing-heading case).

- [ ] **Step 7: Add failing test for out-of-order headings**

Append:

```rust
const REORDERED: &str = "\
# Some format

## Overview
text
## Wire layout
text
## Versions
text
## Variants
text
## Caps & limits
text
## Verification
text
## Paksmith implementation
text
## References
text
";

#[test]
fn rejects_doc_with_headings_in_wrong_order() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("some-format.md"), REORDERED).unwrap();
    let err = check_dir(dir.path()).expect_err("should fail");
    assert!(err.to_string().contains("position 2"),
            "expected error to name position 2 (Versions vs Wire layout swap), got: {err}");
}
```

- [ ] **Step 8: Run it, verify it passes**

Run: `cargo test -p paksmith-doc-lint --test required_headings rejects_doc_with_headings_in_wrong_order`
Expected: PASS.

- [ ] **Step 9: Add test that excluded filenames are skipped**

Append:

```rust
#[test]
fn skips_readme_template_conventions() {
    let dir = TempDir::new().unwrap();
    // These would fail required-headings if they were checked.
    fs::write(dir.path().join("README.md"), "# Front door\n\nNo H2s here.\n").unwrap();
    fs::write(dir.path().join("TEMPLATE.md"), "# Skeleton\n\nNo H2s.\n").unwrap();
    fs::write(dir.path().join("CONVENTIONS.md"), "# Conventions\n\nNone.\n").unwrap();
    check_dir(dir.path()).expect("excluded files should be skipped");
}
```

- [ ] **Step 10: Run it, verify it passes**

Run: `cargo test -p paksmith-doc-lint --test required_headings skips_readme_template_conventions`
Expected: PASS.

- [ ] **Step 11: Add test for recursive descent into subdirectories**

Append:

```rust
#[test]
fn descends_into_family_subdirectories() {
    let dir = TempDir::new().unwrap();
    let sub = dir.path().join("container");
    fs::create_dir(&sub).unwrap();
    fs::write(sub.join("pak.md"), "# Pak\n\nNo H2s — should fail.\n").unwrap();
    let err = check_dir(dir.path()).expect_err("subdir doc should be checked");
    assert!(err.to_string().contains("pak.md"),
            "error should reference pak.md, got: {err}");
}
```

- [ ] **Step 12: Run it, verify it passes**

Run: `cargo test -p paksmith-doc-lint --test required_headings descends_into_family_subdirectories`
Expected: PASS.

- [ ] **Step 13: Run the full test file plus fmt+clippy**

Run: `cargo test -p paksmith-doc-lint --test required_headings`
Expected: 5 tests pass.

Run: `cargo fmt --all -- --check`
Expected: clean.

Run: `cargo clippy -p paksmith-doc-lint --all-targets -- -D warnings`
Expected: clean.

- [ ] **Step 14: Commit**

```bash
git add crates/paksmith-doc-lint/src/required_headings.rs \
        crates/paksmith-doc-lint/tests/required_headings.rs
git commit -m "$(cat <<'EOF'
feat(doc-lint): add required-headings linter

Enforces the eight-section template from docs/design/2026-05-19-ue-format-docs.md
on every .md under docs/formats/ except README.md, TEMPLATE.md, and
CONVENTIONS.md. Catches missing sections, out-of-order sections, and
descends into family subdirectories.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Implement the status-enum + consistency linter

**Files:**
- Modify: `crates/paksmith-doc-lint/src/status_enum.rs`
- Create: `crates/paksmith-doc-lint/tests/status_enum.rs`

The linter targets exactly one file (the inventory `docs/formats/README.md`). It:

1. Finds the inventory table by looking for the header row `| Doc | Doc status | Parser status | Parser module | Reference oracle | Last verified |`.
2. For each data row beneath the header/separator, extracts the Doc status and Parser status cells.
3. Validates each against its enum set: doc ∈ {`stub`, `partial`, `complete`}, parser ∈ {`not impl`, `partial`, `complete`}.
4. Emits warnings (to stderr; does not fail) for smell combinations: doc=`complete` + parser=`not impl`, and parser=`complete` + doc=`stub`.
5. Fails on invalid enum values or rows with the wrong column count.

The empty-inventory case (table header + separator + zero data rows) must pass.

- [ ] **Step 1: Write the failing test for an empty inventory**

Create `crates/paksmith-doc-lint/tests/status_enum.rs`:

```rust
use paksmith_doc_lint::status_enum::check_file;
use std::fs;
use tempfile::TempDir;

const EMPTY_INVENTORY: &str = "\
# docs/formats inventory

## Inventory

| Doc | Doc status | Parser status | Parser module | Reference oracle | Last verified |
|-----|------------|---------------|----------------|-------------------|---------------|
";

#[test]
fn accepts_empty_inventory() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("README.md");
    fs::write(&path, EMPTY_INVENTORY).unwrap();
    check_file(&path).expect("empty inventory should pass");
}
```

- [ ] **Step 2: Run it, verify it fails**

Run: `cargo test -p paksmith-doc-lint --test status_enum accepts_empty_inventory`
Expected: FAIL — the `bail!("not yet implemented")` stub.

- [ ] **Step 3: Write the minimal impl**

Replace `crates/paksmith-doc-lint/src/status_enum.rs`:

```rust
use anyhow::{Context, Result, bail};
use std::path::Path;

const HEADER_PREFIX: &str = "| Doc | Doc status | Parser status | Parser module |";
const DOC_STATUSES: &[&str] = &["stub", "partial", "complete"];
const PARSER_STATUSES: &[&str] = &["not impl", "partial", "complete"];

pub fn check_file(file: &Path) -> Result<()> {
    let content = std::fs::read_to_string(file)
        .with_context(|| format!("reading {}", file.display()))?;

    let lines: Vec<&str> = content.lines().collect();
    let header_idx = lines
        .iter()
        .position(|l| l.trim_start().starts_with(HEADER_PREFIX))
        .ok_or_else(|| anyhow::anyhow!(
            "{}: inventory table header row not found (expected line starting with {:?})",
            file.display(),
            HEADER_PREFIX,
        ))?;

    // Header row is followed by a separator row (|---|---|...|). Data rows start two lines later.
    let mut failures: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    for (offset, raw) in lines.iter().enumerate().skip(header_idx + 2) {
        let trimmed = raw.trim();
        if !trimmed.starts_with('|') {
            // Table ended (blank line or other content).
            break;
        }
        let cells: Vec<&str> = trimmed
            .trim_start_matches('|')
            .trim_end_matches('|')
            .split('|')
            .map(str::trim)
            .collect();
        if cells.len() != 6 {
            failures.push(format!(
                "line {}: expected 6 cells, found {} ({:?})",
                offset + 1,
                cells.len(),
                trimmed,
            ));
            continue;
        }
        let doc_status = cells[1];
        let parser_status = cells[2];
        if !DOC_STATUSES.contains(&doc_status) {
            failures.push(format!(
                "line {}: doc status {:?} not in {:?}",
                offset + 1, doc_status, DOC_STATUSES,
            ));
        }
        if !PARSER_STATUSES.contains(&parser_status) {
            failures.push(format!(
                "line {}: parser status {:?} not in {:?}",
                offset + 1, parser_status, PARSER_STATUSES,
            ));
        }
        // Smell warnings (do not fail).
        if doc_status == "complete" && parser_status == "not impl" {
            warnings.push(format!(
                "line {}: doc marked complete but parser not impl",
                offset + 1,
            ));
        }
        if doc_status == "stub" && parser_status == "complete" {
            warnings.push(format!(
                "line {}: parser complete but doc still stub",
                offset + 1,
            ));
        }
    }

    for w in &warnings {
        eprintln!("warning: {}: {w}", file.display());
    }
    if !failures.is_empty() {
        bail!(
            "status-enum lint failed for {}:\n  - {}",
            file.display(),
            failures.join("\n  - "),
        );
    }
    Ok(())
}
```

- [ ] **Step 4: Run the empty-inventory test, verify it passes**

Run: `cargo test -p paksmith-doc-lint --test status_enum accepts_empty_inventory`
Expected: PASS.

- [ ] **Step 5: Add test for valid populated inventory**

Append:

```rust
const VALID_INVENTORY: &str = "\
# docs/formats inventory

## Inventory

| Doc | Doc status | Parser status | Parser module | Reference oracle | Last verified |
|-----|------------|---------------|----------------|-------------------|---------------|
| `container/pak.md` | complete | complete | `container/pak/` | repak @ `abc123` | `def456` |
| `container/iostore-utoc.md` | stub | not impl | — | CUE4Parse @ `ghi789` | n/a |
";

#[test]
fn accepts_valid_populated_inventory() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("README.md");
    fs::write(&path, VALID_INVENTORY).unwrap();
    check_file(&path).expect("valid rows should pass");
}
```

- [ ] **Step 6: Run, verify pass**

Run: `cargo test -p paksmith-doc-lint --test status_enum accepts_valid_populated_inventory`
Expected: PASS.

- [ ] **Step 7: Add test for invalid doc-status value**

Append:

```rust
const INVALID_DOC_STATUS: &str = "\
# docs/formats inventory

## Inventory

| Doc | Doc status | Parser status | Parser module | Reference oracle | Last verified |
|-----|------------|---------------|----------------|-------------------|---------------|
| `container/pak.md` | done | complete | `container/pak/` | repak @ `abc123` | `def456` |
";

#[test]
fn rejects_invalid_doc_status_value() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("README.md");
    fs::write(&path, INVALID_DOC_STATUS).unwrap();
    let err = check_file(&path).expect_err("invalid value should fail");
    assert!(err.to_string().contains("doc status"), "got: {err}");
    assert!(err.to_string().contains("done"), "got: {err}");
}
```

- [ ] **Step 8: Run, verify pass**

Run: `cargo test -p paksmith-doc-lint --test status_enum rejects_invalid_doc_status_value`
Expected: PASS.

- [ ] **Step 9: Add test for invalid parser-status value**

Append:

```rust
const INVALID_PARSER_STATUS: &str = "\
# docs/formats inventory

## Inventory

| Doc | Doc status | Parser status | Parser module | Reference oracle | Last verified |
|-----|------------|---------------|----------------|-------------------|---------------|
| `container/pak.md` | complete | shipped | `container/pak/` | repak @ `abc123` | `def456` |
";

#[test]
fn rejects_invalid_parser_status_value() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("README.md");
    fs::write(&path, INVALID_PARSER_STATUS).unwrap();
    let err = check_file(&path).expect_err("invalid value should fail");
    assert!(err.to_string().contains("parser status"), "got: {err}");
    assert!(err.to_string().contains("shipped"), "got: {err}");
}
```

- [ ] **Step 10: Run, verify pass**

Run: `cargo test -p paksmith-doc-lint --test status_enum rejects_invalid_parser_status_value`
Expected: PASS.

- [ ] **Step 11: Add test for malformed row (wrong column count)**

Append:

```rust
const WRONG_COLUMN_COUNT: &str = "\
# docs/formats inventory

## Inventory

| Doc | Doc status | Parser status | Parser module | Reference oracle | Last verified |
|-----|------------|---------------|----------------|-------------------|---------------|
| `container/pak.md` | complete | complete | `container/pak/` |
";

#[test]
fn rejects_row_with_wrong_column_count() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("README.md");
    fs::write(&path, WRONG_COLUMN_COUNT).unwrap();
    let err = check_file(&path).expect_err("malformed row should fail");
    assert!(err.to_string().contains("expected 6 cells"), "got: {err}");
}
```

- [ ] **Step 12: Run, verify pass**

Run: `cargo test -p paksmith-doc-lint --test status_enum rejects_row_with_wrong_column_count`
Expected: PASS.

- [ ] **Step 13: Add test for missing header row entirely**

Append:

```rust
const NO_INVENTORY_TABLE: &str = "\
# docs/formats inventory

Some narrative here, but no inventory table at all.
";

#[test]
fn rejects_file_with_no_inventory_table() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("README.md");
    fs::write(&path, NO_INVENTORY_TABLE).unwrap();
    let err = check_file(&path).expect_err("missing table should fail");
    assert!(err.to_string().contains("inventory table header row not found"), "got: {err}");
}
```

- [ ] **Step 14: Run, verify pass**

Run: `cargo test -p paksmith-doc-lint --test status_enum rejects_file_with_no_inventory_table`
Expected: PASS.

- [ ] **Step 15: Run full status_enum suite + fmt + clippy**

Run: `cargo test -p paksmith-doc-lint --test status_enum`
Expected: 6 tests pass.

Run: `cargo fmt --all -- --check`
Expected: clean.

Run: `cargo clippy -p paksmith-doc-lint --all-targets -- -D warnings`
Expected: clean.

- [ ] **Step 16: Commit**

```bash
git add crates/paksmith-doc-lint/src/status_enum.rs \
        crates/paksmith-doc-lint/tests/status_enum.rs
git commit -m "$(cat <<'EOF'
feat(doc-lint): add status-enum + consistency linter

Validates the inventory table in docs/formats/README.md: doc status ∈
{stub, partial, complete}, parser status ∈ {not impl, partial,
complete}. Fails on invalid enum values or malformed rows. Warns
(does not fail) on doc=complete+parser=not impl and doc=stub+parser=
complete smell combinations.

Empty-inventory case (header + separator only) is the expected steady
state for PR 1.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Add CLI integration tests for the binary

**Files:**
- Create: `crates/paksmith-doc-lint/tests/cli.rs`

Tests the binary surface (subcommand dispatch, exit codes, usage messages) end-to-end via `assert_cmd`. This catches main.rs regressions that pure-library tests miss.

- [ ] **Step 1: Write the failing test for usage on no args**

Create `crates/paksmith-doc-lint/tests/cli.rs`:

```rust
use assert_cmd::Command;
use predicates::str::contains;

#[test]
fn prints_usage_with_no_args() {
    let mut cmd = Command::cargo_bin("paksmith-doc-lint").unwrap();
    cmd.assert()
        .failure()
        .code(2)
        .stderr(contains("usage: paksmith-doc-lint"));
}
```

- [ ] **Step 2: Run, verify pass (impl already exists)**

Run: `cargo test -p paksmith-doc-lint --test cli prints_usage_with_no_args`
Expected: PASS.

- [ ] **Step 3: Add test for required-headings subcommand exit-zero on valid dir**

Append:

```rust
use std::fs;
use tempfile::TempDir;

const VALID_DOC: &str = "\
# Some format

## Overview
text
## Versions
text
## Wire layout
text
## Variants
text
## Caps & limits
text
## Verification
text
## Paksmith implementation
text
## References
text
";

#[test]
fn required_headings_subcommand_exits_zero_on_valid_dir() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("pak.md"), VALID_DOC).unwrap();
    let mut cmd = Command::cargo_bin("paksmith-doc-lint").unwrap();
    cmd.arg("required-headings")
        .arg(dir.path())
        .assert()
        .success();
}
```

- [ ] **Step 4: Run, verify pass**

Run: `cargo test -p paksmith-doc-lint --test cli required_headings_subcommand_exits_zero_on_valid_dir`
Expected: PASS.

- [ ] **Step 5: Add test for status-enum subcommand exit-one on invalid file**

Append:

```rust
const INVALID_INVENTORY: &str = "\
# Inventory

## Inventory

| Doc | Doc status | Parser status | Parser module | Reference oracle | Last verified |
|-----|------------|---------------|----------------|-------------------|---------------|
| `x.md` | done | complete | — | — | n/a |
";

#[test]
fn status_enum_subcommand_exits_nonzero_on_invalid_value() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("README.md");
    fs::write(&path, INVALID_INVENTORY).unwrap();
    let mut cmd = Command::cargo_bin("paksmith-doc-lint").unwrap();
    cmd.arg("status-enum")
        .arg(&path)
        .assert()
        .failure()
        .stderr(contains("status-enum lint failed"));
}
```

- [ ] **Step 6: Run, verify pass**

Run: `cargo test -p paksmith-doc-lint --test cli status_enum_subcommand_exits_nonzero_on_invalid_value`
Expected: PASS.

- [ ] **Step 7: Run full crate tests + fmt + clippy**

Run: `cargo test -p paksmith-doc-lint`
Expected: all tests pass (3 CLI + 5 required-headings + 6 status-enum = 14 tests).

Run: `cargo fmt --all -- --check && cargo clippy -p paksmith-doc-lint --all-targets -- -D warnings`
Expected: clean.

- [ ] **Step 8: Commit**

```bash
git add crates/paksmith-doc-lint/tests/cli.rs
git commit -m "$(cat <<'EOF'
test(doc-lint): integration tests for binary surface

Covers no-arg usage path, required-headings success path, and
status-enum failure path end-to-end via assert_cmd so main.rs dispatch
regressions surface in CI.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Author the docs/formats/ scaffold

**Files:**
- Create: `docs/formats/README.md`
- Create: `docs/formats/TEMPLATE.md`
- Create: `docs/formats/CONVENTIONS.md`
- Create: `docs/formats/{container,asset,property,primitive,texture,mesh,audio,animation,material,data,compression,crypto}/README.md` (12 files)

This task creates real content the linters will run against in CI. Each family README is narrative-only (2–4 short paragraphs); no inventory, no per-doc status — per the spec, the inventory lives only at the root.

- [ ] **Step 1: Create `docs/formats/README.md`**

Write `docs/formats/README.md`:

```markdown
# Paksmith format reference

This directory documents every Unreal-Engine-specific binary format paksmith
parses (or intends to parse). Each format gets one document, layered for two
readers from the same content:

- **External UE-format researchers** building a parser in any language. Read
  the `Versions`, `Wire layout`, `Variants`, and `Caps & limits` sections.
- **Paksmith contributors**. Read the same wire content for orientation, then
  the `Paksmith implementation` sidebar for parser module, fixtures, and
  caps.

See `docs/design/2026-05-19-ue-format-docs.md` for the design that produced
this directory. See `TEMPLATE.md` for the per-doc skeleton and `CONVENTIONS.md`
for hex-anchor + citation conventions.

## Families

- [`container/`](container/README.md) — archive formats (`.pak`, IoStore)
- [`asset/`](asset/README.md) — package format (`.uasset`, `.uexp`, `.ubulk`)
- [`property/`](property/README.md) — tagged and unversioned property
  serialization
- [`primitive/`](primitive/README.md) — `FString`, `FName`, `FGuid`,
  `FPackageIndex`, custom-version / engine-version records
- [`texture/`](texture/README.md) — `Texture2D`, pixel formats, mips
- [`mesh/`](mesh/README.md) — static / skeletal mesh, skeleton, vertex
  formats
- [`audio/`](audio/README.md) — `SoundWave`, audio codec framing
- [`animation/`](animation/README.md) — `AnimSequence`
- [`material/`](material/README.md) — `Material`, `MaterialInstance`
- [`data/`](data/README.md) — `DataAsset`, `DataTable`, `Locres`
- [`compression/`](compression/README.md) — pak block framing, zlib, Oodle
- [`crypto/`](crypto/README.md) — AES-256 pak encryption

## Inventory

The table below is the single source of truth for which formats have docs,
which docs are complete, and which parsers are wired up. There are no rows
yet — they accrete as per-family PRs land. See the design spec section
"Format inventory" for column semantics.

| Doc | Doc status | Parser status | Parser module | Reference oracle | Last verified |
|-----|------------|---------------|----------------|-------------------|---------------|

Status enums (the `paksmith-doc-lint status-enum` check enforces these):

- **Doc status:** `stub` · `partial` · `complete`
- **Parser status:** `not impl` · `partial` · `complete`
- **Last verified:** commit SHA where the doc was last cross-checked against
  oracle + fixtures, or `n/a` if not yet verified.
```

- [ ] **Step 2: Create `docs/formats/TEMPLATE.md`**

Write `docs/formats/TEMPLATE.md`:

````markdown
# <Format name> (`.ext` / `FStructName`)

> One-line summary: what this is and where it appears in a UE pak.

## Overview

What this format encodes, where it sits in the bigger picture, what other docs
to read first.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| `FileVersionUE4 ≥ NNN` | … | `<community-project>@<sha>` |

Anchor for every conditional in later sections. Each row cites the community
implementation + commit SHA where the change was first documented.

## Wire layout

Byte-by-byte reference. One subsection per top-level record. Each field
listed as:

| offset | size | endian | name | type | semantics |
|--------|------|--------|------|------|-----------|

Optionally include `### Worked example` subsections with annotated hex blocks
from a named fixture. Hex blocks follow `CONVENTIONS.md`.

## Variants

Per-version, per-platform, per-game variants. Each variant gets a named
subsection that references back to the Versions table.

## Caps & limits

What paksmith refuses to parse and why. Cross-link to
`docs/security/allocation-caps.md`. **Required even if the answer is "none"** —
the section header must be present so readers can rely on the absence of caps
being intentional.

## Verification

How a reader can verify the spec is correct against a real file:

- Fixture path in `tests/fixtures/` (or `(none yet)` with a tracking issue
  link)
- Hex anchor commands (e.g. `xxd -s 0x40 -l 32 tests/fixtures/<file>`)
- Cross-validation oracle (community impl name + version)
- Known divergences between oracle and engine-cooked output

## Paksmith implementation

Audience-switch sidebar. Names the parser module, the error variants, the
cap constants, the test files. Status: `not implemented` / `partial` /
`complete`. Links to the phase plan that owns the work.

## References

1. `<community-project>/<path>@<sha>` — one-line description of what's cited.
````

- [ ] **Step 3: Create `docs/formats/CONVENTIONS.md`**

Write `docs/formats/CONVENTIONS.md`:

````markdown
# Conventions

Format-doc-wide conventions. Per-format quirks belong inside individual
docs, not here.

## Hex-anchor blocks

Inside `### Worked example` subsections, embed a reproducible shell command
and the expected output verbatim. CI runs the command against the current
fixture and diffs against the embedded output; drift fails the build.

Format:

````markdown
### Worked example: pak v8 footer

```bash
xxd -s -44 -l 44 tests/fixtures/real_v8b_split.pak
```

```
00012345: 0123 4567 89ab cdef 0123 4567 89ab cdef  ........ ........
00012355: ...
```
````

**Allowed commands** (must be deterministic, read-only, and available on
the CI runners or installed by the workflow):

- `xxd`
- `hexdump`
- `od`
- `wc`
- `sha1sum`

Adding a new inspection tool to this list is a PR in its own right — update
this section AND ensure the CI workflow has the tool available.

## Citation format

Inline footnote markers in `## Wire layout`, `## Versions`, and `## Variants`.
Resolve to entries in `## References` of the form:

```markdown
1. `<project>/<path>@<sha>` — one-line description.
```

SHAs (not branch names) so links don't rot. Required oracle priority when
multiple sources cover a claim:

1. CUE4Parse — broadest coverage; default for asset internals.
2. repak — pak-specific; default for container claims.
3. FModel — UI/struct insights.
4. UE4SS — runtime RE; cite for behavior not visible in cooked output.
5. unreal_asset — Rust API; cite when triangulating a Rust-perspective view.

## Version-marker syntax

When citing a UE version constant, use the exact name from the engine
(`FileVersionUE4 ≥ 507`, `EUnrealEngineObjectUE5Version::INITIAL_VERSION`,
etc.) and link the constant to its definition in
`crates/paksmith-core/src/asset/version.rs` if paksmith pins it.

## Attribution boundary

Per `CONTRIBUTING.md`, format docs cite community implementations
(CUE4Parse, repak, FModel, UE4SS, unreal_asset). Plain-prose engine facts
are fine; URLs to engine-source repositories are not.
````

- [ ] **Step 4: Create the 12 family READMEs**

For each family, write `docs/formats/<family>/README.md` with 2–4 paragraphs of narrative-only overview. Below is the content for each. Each file ends with a newline.

`docs/formats/container/README.md`:

```markdown
# Container formats

Archive formats that hold cooked UE content on disk. A paksmith run starts
here — the container reader yields entries, which the asset layer then
deserializes.

Two top-level formats are in scope:

- **`.pak`** — the legacy archive format. One file. Eleven on-disk versions
  (V1 through V11) covering UE 4.0 through UE 5.x. Paksmith's primary
  container today.
- **IoStore** (`.utoc` + `.ucas` + optional `.uptnl`) — UE4.27+ replacement
  for `.pak` aimed at faster shipped-game IO. Three coupled files per
  container.

Encryption, compression, and on-disk integrity are documented separately:
see `../crypto/README.md` and `../compression/README.md`.
```

`docs/formats/asset/README.md`:

```markdown
# Asset formats

Files that encode one UE package — the unit of `UObject` serialization. A
package always lives across at least one file (`.uasset`) and often two or
three (`.uexp`, `.ubulk`).

- **`.uasset`** — header, name table, import/export tables, optional
  inlined export bodies for older versions.
- **`.uexp`** — export bodies split out from the header for newer versions
  (UE 4.16+ by default).
- **`.ubulk`** — bulk-data payloads (large texture mips, audio bodies)
  streamed separately from the main package.

`companion-resolution.md` documents how paksmith locates the `.uexp` and
`.ubulk` companions given a `.uasset` path.
```

`docs/formats/property/README.md`:

```markdown
# Property serialization

Inside every `UObject` export body is a stream of properties. UE has two
serialization modes, and which one a package uses depends on its build:

- **Tagged properties** (UE3 → present, the default for editor builds and
  most cooked builds). Each property carries a name + type tag on the wire,
  so the reader can iterate without a schema.
- **Unversioned properties** (UE5 cooked shipping builds opting in). The
  schema lives in the engine; the wire form is a compact bitstream + raw
  bodies that only decode when paired with the originating class layout.

The `primitives.md`, `containers.md`, `struct.md`, and `text.md` docs cover
the per-type wire bodies that both serialization modes share once a property
has been located.
```

`docs/formats/primitive/README.md`:

```markdown
# Primitive types

The smallest reusable record shapes that every UE format builds on.
Everything in `container/`, `asset/`, and `property/` references these.

- **`FString`** — variable-length string with a sign-encoded length prefix
  (positive = ASCII, negative = UTF-16, always NUL-terminated).
- **`FName`** — an index + suffix number resolved against a per-package
  name table.
- **`FGuid`** — 128-bit identifier, two endianness conventions in the wild.
- **`FPackageIndex`** — signed index into the package's import or export
  table (positive = export, negative = import, zero = null).
- **`FCustomVersion`** — per-engine-feature version tag carried in the
  package summary.
- **`FEngineVersion`** — major/minor/patch/build/branch record, present in
  some headers.
```

`docs/formats/texture/README.md`:

```markdown
# Texture formats

Cooked texture payloads — mostly platform-specific compressed pixel data
wrapped in a thin UE record. Lives under `Texture2D` plus a handful of
specialized variants (cube, volume, render-target).

- **`texture2d.md`** — the `Texture2D` record itself.
- **`pixel-formats.md`** — the `EPixelFormat` enum and the on-disk layout
  for each format paksmith intends to decode (DXT/BC family, ASTC, ETC2,
  PVRTC, uncompressed RGBA8/BGRA8).
- **`mips-and-streaming.md`** — how mip chains are split between the
  `.uasset` body and the `.ubulk` companion, and how streaming priorities
  are encoded.
```

`docs/formats/mesh/README.md`:

```markdown
# Mesh formats

Static and skeletal mesh payloads. Both are dense binary records with
heavy version-conditional branching — the wire layout has changed meaningfully
across UE 4.20, 4.25, 4.27, and the UE5 line.

- **`static-mesh.md`** — `StaticMesh` LODs, vertex buffers, index buffers,
  per-LOD section metadata.
- **`skeletal-mesh.md`** — `SkeletalMesh` LODs, skin weights, bone influence
  records.
- **`skeleton.md`** — the `Skeleton` asset that `SkeletalMesh` references.
- **`vertex-formats.md`** — packed-vertex layouts shared across both mesh
  types.
```

`docs/formats/audio/README.md`:

```markdown
# Audio formats

Sound payloads, both the UE wrapper records and the third-party codec
framing they contain.

- **`sound-wave.md`** — the `SoundWave` record and its bulk-data layout.
- **`audio-codecs.md`** — Vorbis, Opus, ADPCM, and platform-specific
  encodings as they appear in cooked sound bulk data.
```

`docs/formats/animation/README.md`:

```markdown
# Animation formats

- **`anim-sequence.md`** — `AnimSequence` raw and compressed tracks. The
  compressed codec set has expanded significantly across UE4 minor versions
  and again in UE5; the doc enumerates the codecs paksmith decodes.

Animation blueprints, montages, and runtime state machines are out of scope
for paksmith — only the on-disk asset shapes that hold baked keyframes are
documented here.
```

`docs/formats/material/README.md`:

```markdown
# Material formats

Material graphs are conceptually large but their on-disk presence in cooked
content is mostly just shader-map references and parameter overrides — the
actual shader code lives in DDC / shader cache, which is out of paksmith's
extraction scope.

- **`material.md`** — `Material` record and shader-map references.
- **`material-instance.md`** — `MaterialInstance` parameter overrides and
  the inheritance chain back to the parent material.
```

`docs/formats/data/README.md`:

```markdown
# Data assets

Pure-data UE assets — no runtime behavior, just structured payloads.

- **`data-asset.md`** — the generic `DataAsset` shape.
- **`data-table.md`** — `DataTable` row layouts and the row-struct
  reference.
- **`locres.md`** — `.locres` localization tables. Not technically a UE
  package, but a sibling format produced by the same cooker.
```

`docs/formats/compression/README.md`:

```markdown
# Compression backends

How paksmith decompresses entry payloads after the container reader has
located them.

- **`pak-block-framing.md`** — how `.pak` slices an entry into compressed
  blocks before applying the backend.
- **`zlib.md`** — zlib block layout and the deflate dictionary defaults UE
  uses.
- **`oodle.md`** — Oodle Data (LZ4, Mermaid, Kraken, Selkie, Leviathan).
  Notes on licensing: the Oodle decompressor is not redistributable;
  paksmith links against a system-provided shared library at runtime.
```

`docs/formats/crypto/README.md`:

```markdown
# Cryptography

Encryption schemes UE uses on cooked content.

- **`aes-pak.md`** — AES-256 ECB encryption for `.pak` index and per-entry
  encryption (UE 4.20+). Documents the key-derivation path, the
  `Crypto.json` file format the cooker emits, and paksmith's handling of
  missing keys (refusal to parse vs partial decode).

IoStore encryption shares the same AES-256 ECB primitive but applies it
at a different granularity; that will be covered in
`../container/iostore-utoc.md` when the IoStore doc lands.
```

- [ ] **Step 5: Sanity-check by running both linters against the new scaffold**

Run: `cargo run -p paksmith-doc-lint -- required-headings docs/formats/`
Expected: exits 0 (no non-excluded docs exist yet, so no headings to check).

Run: `cargo run -p paksmith-doc-lint -- status-enum docs/formats/README.md`
Expected: exits 0 (inventory table is empty but well-formed).

- [ ] **Step 6: Commit**

```bash
git add docs/formats/
git commit -m "$(cat <<'EOF'
docs(formats): scaffold the docs/formats/ tree

Establishes the framework defined in docs/design/2026-05-19-ue-format-docs.md:
- Root README with empty inventory table + status enum reference
- TEMPLATE.md with the canonical eight-section per-doc skeleton
- CONVENTIONS.md with hex-anchor format, citation rules, allowed commands
- Narrative-only README in each of the 12 family directories

No format docs are populated yet; per-family PRs land them when their
phases open.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: Wire the linters into CI

**Files:**
- Create: `.github/workflows/format-docs.yml`

Pattern match against the existing `typos.yml` workflow: same triggers,
same concurrency group, pinned action SHAs.

- [ ] **Step 1: Look up the current SHA pin for `actions/checkout`**

Run: `grep -h "actions/checkout@" .github/workflows/*.yml | sort -u`
Expected: shows one or more `actions/checkout@<sha>` lines. Copy the SHA
that appears most often (this is the canonical pin for the repo).

- [ ] **Step 2: Write the workflow**

Create `.github/workflows/format-docs.yml` using the SHA from Step 1 (the
example below uses the SHA observed in `ci.yml` at planning time; if
`grep` showed a different one, use that instead):

```yaml
name: Format docs

on:
  push:
    branches: [main]
    paths:
      - 'docs/formats/**'
      - 'crates/paksmith-doc-lint/**'
      - '.github/workflows/format-docs.yml'
  pull_request:
    branches: [main]
    paths:
      - 'docs/formats/**'
      - 'crates/paksmith-doc-lint/**'
      - '.github/workflows/format-docs.yml'
  workflow_dispatch:

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: ${{ github.event_name == 'pull_request' }}

permissions:
  contents: read

jobs:
  lint:
    name: Lint docs/formats/
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
      - uses: ./.github/actions/setup-rust
      - name: Build linter
        run: cargo build -p paksmith-doc-lint --release
      - name: Required-headings lint
        run: cargo run -p paksmith-doc-lint --release -- required-headings docs/formats/
      - name: Status-enum lint
        run: cargo run -p paksmith-doc-lint --release -- status-enum docs/formats/README.md
```

**Heads-up on the ruleset gotcha** (from project memory): once this
workflow's `name:` + job `name:` pair lands on `main`, GitHub Actions
publishes a check named `Format docs / Lint docs/formats/`. If we later
rename either, the ruleset's `required_status_checks` list points at a
ghost and every PR blocks. If anyone subsequently adds this check to
the required list via ruleset, document the exact string in a follow-up.

- [ ] **Step 3: Validate the workflow locally with `act` (optional but recommended)**

If `act` is installed:

Run: `act -W .github/workflows/format-docs.yml pull_request -n`
Expected: dry-run prints the plan without errors. If `act` isn't installed,
skip — CI will catch syntax errors when the branch pushes.

- [ ] **Step 4: Smoke-test that the linters would actually fail CI on a regression**

Temporarily modify `docs/formats/README.md` to corrupt the inventory header (e.g., change `Doc status` to `doc_status`), then:

Run: `cargo run -p paksmith-doc-lint -- status-enum docs/formats/README.md`
Expected: exits non-zero with "inventory table header row not found".

Revert the change:

Run: `git checkout docs/formats/README.md`

Temporarily add `docs/formats/container/test.md` with `# Test\n\nNo H2s.\n`, then:

Run: `cargo run -p paksmith-doc-lint -- required-headings docs/formats/`
Expected: exits non-zero with a `container/test.md` failure.

Clean up:

Run: `rm docs/formats/container/test.md`

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/format-docs.yml
git commit -m "$(cat <<'EOF'
ci(format-docs): run paksmith-doc-lint on docs/formats changes

Triggers on docs/formats/**, crates/paksmith-doc-lint/**, or the
workflow itself. Runs both linters in release mode (fast enough to
not warrant debug). Does NOT add the check to the ruleset's required
list yet — flip required-status-checks in a follow-up once the
workflow has run green on a few merges.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: Update PR template and CONTRIBUTING.md

**Files:**
- Modify: `.github/pull_request_template.md`
- Modify: `CONTRIBUTING.md`

The PR template gets a checkbox for trigger 1 from the design spec's
maintenance triggers. CONTRIBUTING.md gets a Documentation section
covering the attribution rule for `docs/formats/`.

- [ ] **Step 1: Read the current PR template Pre-flight checklist**

Run: `cat .github/pull_request_template.md`

Locate the `## Pre-flight checklist` section and the existing checkbox list.

- [ ] **Step 2: Add the format-doc checkbox to Pre-flight checklist**

In `.github/pull_request_template.md`, add a new line at the END of the
Pre-flight checklist (after the `No unsafe introduced` line):

```markdown
- [ ] Touched a parser in `crates/paksmith-core/src/{asset,container}/`? Updated its `docs/formats/` doc (or marked the format inventory row's `Last verified` SHA)?
```

Use the Edit tool to insert this line. Find the existing line:

```markdown
- [ ] No `unsafe` introduced (workspace lint denies it; if needed, justify here)
```

Replace with:

```markdown
- [ ] No `unsafe` introduced (workspace lint denies it; if needed, justify here)
- [ ] Touched a parser in `crates/paksmith-core/src/{asset,container}/`? Updated its `docs/formats/` doc (or marked the format inventory row's `Last verified` SHA)?
```

- [ ] **Step 3: Read CONTRIBUTING.md to find the right insertion point**

Run: `cat CONTRIBUTING.md`

Locate the `## Architecture` heading (near end) — the Documentation section goes before it.

- [ ] **Step 4: Add the Documentation section to CONTRIBUTING.md**

Use the Edit tool to insert a new section before `## Architecture`. Find:

```markdown
## Architecture
```

Replace with:

```markdown
## Documentation

Format documentation lives in `docs/formats/` (see
`docs/design/2026-05-19-ue-format-docs.md` for the framework design).
Two rules apply to every contribution that touches that tree:

1. **Cite community implementations only** — CUE4Parse, repak, FModel,
   UE4SS, and unreal_asset. Plain-prose engine facts are fine; URLs to
   engine-source repositories are not.
2. **Keep parser docs in sync with parser code** — when modifying a
   parser, update the matching `docs/formats/` entry (or bump its
   `Last verified` row in the inventory) in the same PR. The PR
   template has a checkbox for this.

The `paksmith-doc-lint` CI check enforces the per-doc template and the
inventory's status-enum values. Other rules (citation policy, parser
sync) are enforced by PR review.

## Architecture
```

- [ ] **Step 5: Verify both files**

Run: `grep -A 1 "Touched a parser" .github/pull_request_template.md`
Expected: shows the new checkbox line.

Run: `grep -A 2 "^## Documentation" CONTRIBUTING.md`
Expected: shows the new section heading + first paragraph.

- [ ] **Step 6: Commit**

```bash
git add .github/pull_request_template.md CONTRIBUTING.md
git commit -m "$(cat <<'EOF'
docs(contributing): wire docs/formats/ rules into PR template + CONTRIBUTING

PR template gains a Pre-flight checkbox so parser PRs explicitly
confirm whether the matching format doc moved with the code.
CONTRIBUTING gains a Documentation section that names the
community-only citation rule and the parser-sync expectation —
mechanical checks (template + status-enum) ship in the
paksmith-doc-lint crate; this section covers the human-enforced
half.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: Final verification + push

**Files:** (none modified — verification + push only)

- [ ] **Step 1: Run the full workspace test suite (matches CI)**

Run: `cargo test --workspace --all-features`
Expected: all tests pass, including the new `paksmith-doc-lint` suite.

- [ ] **Step 2: Run the clippy invocation that mirrors CI**

Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings`
Expected: clean.

- [ ] **Step 3: Run fmt check**

Run: `cargo fmt --all -- --check`
Expected: clean.

- [ ] **Step 4: Run rustdoc lints (`cargo doc -D warnings` per project memory)**

Run: `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features`
Expected: clean.

- [ ] **Step 5: Re-run both linters against the actual scaffold one last time**

Run: `cargo run -p paksmith-doc-lint -- required-headings docs/formats/`
Expected: exits 0.

Run: `cargo run -p paksmith-doc-lint -- status-enum docs/formats/README.md`
Expected: exits 0.

- [ ] **Step 6: Inspect the commit log**

Run: `git log --oneline main..HEAD`
Expected: 7 commits, one per task (Task 8 has no commit of its own):

```
<sha> docs(contributing): wire docs/formats/ rules into PR template + CONTRIBUTING
<sha> ci(format-docs): run paksmith-doc-lint on docs/formats changes
<sha> docs(formats): scaffold the docs/formats/ tree
<sha> test(doc-lint): integration tests for binary surface
<sha> feat(doc-lint): add status-enum + consistency linter
<sha> feat(doc-lint): add required-headings linter
<sha> chore(doc-lint): bootstrap paksmith-doc-lint workspace crate
```

If anything is out of order or a commit is missing, stop here — do not
push until the log is right.

- [ ] **Step 7: Push the branch and open the PR**

The spec commit (`docs(design): add UE format documentation framework spec`) is
already on this branch from the brainstorming step. Push the whole branch:

Run: `git push -u origin docs/ue-format-docs-framework`

Then open the PR using `gh pr create --body-file <(...)` per the project
convention (never inline `--body "$(cat <<EOF ...)"` — backticks get eaten).
Title: `docs(formats): scaffold UE format documentation framework`
(lowercase verb-first per project convention).

Suggested body (write to a tempfile first, then pass via `--body-file`):

```markdown
## Summary

Lands PR 1 of the UE format documentation framework defined in
`docs/design/2026-05-19-ue-format-docs.md`:

- Scaffolds `docs/formats/` (root README + TEMPLATE + CONVENTIONS + 12
  family READMEs).
- Adds `paksmith-doc-lint` workspace crate (excluded from default-members)
  hosting the required-headings and status-enum linters.
- New `.github/workflows/format-docs.yml` runs both linters on PRs that
  touch `docs/formats/**` or the linter crate.
- PR template + CONTRIBUTING.md updated for the parser-sync expectation
  and the community-only citation rule.

Per-family content PRs each get their own implementation plan and land
subsequently.

## Linked issue

(none — design spec is itself the tracking artifact)

## Test plan

- [x] New tests added: 14 in `crates/paksmith-doc-lint/tests/`
- [x] `cargo test --workspace --all-features` passes locally
- [x] Both linters exit 0 against the new scaffold

## Pre-flight checklist

- [x] PR title is a Conventional Commit (`docs(formats): ...`)
- [x] Branch name follows `<type>/<kebab-case>` (`docs/ue-format-docs-framework`)
- [x] `cargo fmt --all` is clean
- [x] `cargo clippy --workspace --all-targets --all-features -- -D warnings` is clean
- [x] Documentation updated (this PR IS documentation)
- [x] No `unsafe` introduced
- [x] Touched a parser? N/A — no parser code changed.

## Security considerations

None — pure docs/CI scaffolding, no parser code.

## Notes for reviewers

- The `format-docs` workflow is NOT added to the ruleset's required-status-checks
  list yet. Flip that in a follow-up once the workflow has run green on a few
  merges.
- The hex-anchor and reference-link checks listed in the spec are deferred to
  follow-up PRs as designed; not in scope here.
```

Use `--body-file` per project convention. Do NOT inline the body via
heredoc into `--body` (backticks get eaten — see project memory
`feedback_pr_body_no_backtick_escaping.md`).

- [ ] **Step 8: Run the standard reviewer panel against the PR**

Per project memory (`feedback_always_run_review_panel.md` +
`feedback_parallel_full_review_panel.md`), dispatch the full review panel
in a SINGLE message with multiple Agent tool calls:

- code-reviewer (general quality)
- code-architect (design coherence vs the spec)
- code-simplifier (over-engineered linter logic?)

Address any issues raised, re-run the panel on the fix commit, repeat
until every reviewer says APPROVED (per
`feedback_review_until_convergence.md`).

---

## Done criteria

- All 7 commits land on `docs/ue-format-docs-framework`.
- `cargo test --workspace --all-features` is green.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` is green.
- `cargo fmt --all -- --check` is green.
- `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features` is green.
- Both `paksmith-doc-lint` subcommands exit 0 against the scaffold.
- Reviewer panel has converged (no unresolved feedback).
- PR is open with `--body-file`-generated body and the title follows
  lowercase-verb-first convention.
