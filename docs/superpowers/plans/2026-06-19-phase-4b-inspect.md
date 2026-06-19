# Phase 4b — `paksmith inspect` Enhancements Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a versioned output wrapper (`schema_version`), selection (`--export <idx|name>`, `--path <dotted>`), and a human `--format table` tree view to `paksmith inspect` — all CLI-side, `paksmith-core` untouched.

**Architecture:** Promote `commands/inspect.rs` into an `inspect/` submodule. Serialize the parsed `Package` with a generic `flatten` wrapper that prepends `schema_version` (direct `to_writer` for the full/`--export` JSON so field order is preserved without serde_json `preserve_order`). `--export`/`--path` operate on a `serde_json::Value` (export names are already resolved in the serialized shape). `--format table` is a separate presentation renderer with compact typed formatting.

**Tech Stack:** Rust, `clap`, `serde`/`serde_json`; tests via `assert_cmd`, `predicates`, `insta`, `tempfile`.

**Spec:** `docs/superpowers/specs/2026-06-19-phase-4b-inspect-design.md`

## Global Constraints

- **MSRV:** workspace `rust-version` (1.88). No newer/unstable syntax — use `let-else`, not `if let` match guards.
- **`paksmith-core` is NOT modified.** Typed structs keep their canonical serde shape (`{x,y,z}`, `{r,g,b,a}`); compact forms (`[x,y,z]`, `#hex`) appear ONLY in the `--format table` view.
- **No panics in core** (this is CLI-only; CLI uses typed `PaksmithError`; no `unwrap`/`expect` on fallible paths).
- **`schema_version` value is `1`**, emitted as the FIRST key of the JSON document (full and `--export`).
- **`--path` implies structured output** — `--path` + `--format table` is rejected (`InvalidArgument`, exit 2).
- **Exit codes:** `0` success; `2` usage/selection errors (bad `--export`, unresolved `--path`, `--path`+table). `BrokenPipe` on stdout exits cleanly.
- **`inspect::run` keeps returning `paksmith_core::Result<()>`** (wrapped by the existing `Self::Inspect(args) => inspect::run(args, format).map(|()| 0)` in `commands/mod.rs` — do NOT change that dispatch).
- **Conventional commits**, one logical change each.
- **Pre-push gates:** `cargo fmt --all`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace --all-features`, `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features`, `typos .`.
- **Review:** adversarial multi-agent panel (≥3 + specialists) to convergence before push. No new `.pak` fixture (CI fixture-count gate untouched).

---

## File Structure

```
crates/paksmith-cli/src/main.rs               # MODIFY: add `mod inspect;`
crates/paksmith-cli/src/commands/inspect.rs   # MODIFY: thin — InspectArgs + run() dispatch
crates/paksmith-cli/src/inspect/mod.rs         # CREATE: InspectOutput wrapper + emit() orchestration
crates/paksmith-cli/src/inspect/select.rs      # CREATE: resolve_export + navigate (Value-based)
crates/paksmith-cli/src/inspect/tree.rs        # CREATE: table renderer + compact typed formatters
crates/paksmith-cli/tests/inspect_cli.rs       # MODIFY: snapshots + selection/table/error tests
```

`commands/inspect.rs` keeps `InspectArgs` + `load_mappings` + a thin `run()` that parses the `Package` and delegates to `inspect::emit(&pkg, &args, format)`. The `inspect/` module owns wrapping, selection, and rendering.

---

## Task 1: Promote `inspect` to a submodule (no behavior change)

**Files:**
- Modify: `crates/paksmith-cli/src/main.rs` (add `mod inspect;`)
- Modify: `crates/paksmith-cli/src/commands/inspect.rs` (extract emit logic)
- Create: `crates/paksmith-cli/src/inspect/mod.rs`

**Interfaces:**
- Produces: `pub(crate) fn inspect::emit(pkg: &Package, args: &crate::commands::inspect::InspectArgs, format: OutputFormat) -> paksmith_core::Result<()>`
- `commands::inspect::run` parses the package + mappings (as today) then calls `inspect::emit`.

- [ ] **Step 1: Add the module + move the emit logic**

In `crates/paksmith-cli/src/main.rs`, add alongside the other `mod` lines:

```rust
mod inspect;
```

Create `crates/paksmith-cli/src/inspect/mod.rs`:

```rust
//! `inspect` output assembly: versioned JSON wrapper, selection, and the
//! human `--format table` view. Core `Package` serde is never modified here —
//! the JSON shape is the `Package`'s own, with `schema_version` prepended.

use std::io::{self, Write};

use serde::Serialize;

use paksmith_core::asset::Package;

use crate::commands::inspect::InspectArgs;
use crate::output::{serde_json_to_io, OutputFormat};

/// The stable inspect JSON schema version. Bump on any breaking shape change.
const SCHEMA_VERSION: u32 = 1;

/// Versioned wrapper. `schema_version` is declared first so serde emits it as
/// the first key; `body` is flattened inline after it. `T` must serialize as a
/// map (`&Package` or a `serde_json::Value::Object`).
#[derive(Serialize)]
struct InspectOutput<T: Serialize> {
    schema_version: u32,
    #[serde(flatten)]
    body: T,
}

/// Assemble and emit inspect output for `pkg` per `args` + `format`.
pub(crate) fn emit(
    pkg: &Package,
    _args: &InspectArgs,
    _format: OutputFormat,
) -> paksmith_core::Result<()> {
    // Task 1: behavior-preserving — emit the wrapped full package as JSON.
    // (schema_version is added in Task 2; selection/table in Tasks 3-5.)
    write_json(&InspectOutput { schema_version: SCHEMA_VERSION, body: pkg })
}

/// Serialize `value` as pretty JSON to stdout through a `BufWriter`, preserving
/// `BrokenPipe` via `serde_json_to_io` (so `main.rs`'s clean-pipe-exit fires).
fn write_json<T: Serialize>(value: &T) -> paksmith_core::Result<()> {
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    serde_json::to_writer_pretty(&mut out, value).map_err(serde_json_to_io)?;
    writeln!(out)?;
    out.flush()?;
    Ok(())
}
```

Wait — Task 1 must be *behavior-preserving* (no `schema_version` yet, to keep the existing inspect_cli test green). Use this `emit` body for Task 1 instead:

```rust
pub(crate) fn emit(
    pkg: &Package,
    _args: &InspectArgs,
    _format: OutputFormat,
) -> paksmith_core::Result<()> {
    write_json(pkg) // Task 1: identical output to the old inline serializer.
}
```

Keep `InspectOutput`/`SCHEMA_VERSION` defined but `#[allow(dead_code)]` until Task 2 consumes them (or omit them in Task 1 and add in Task 2 — implementer's choice; if omitted, drop the unused `Serialize` import too).

- [ ] **Step 2: Make `commands/inspect.rs::run` delegate**

Replace the body of `run` in `commands/inspect.rs` (keep `InspectArgs`, `load_mappings`, imports) so it parses then delegates. Remove the `OutputFormat::Table` rejection here — `emit` will own format handling (Task 3+); for Task 1, move the SAME rejection into `emit` temporarily so behavior is identical:

`commands/inspect.rs::run`:

```rust
pub(crate) fn run(args: &InspectArgs, format: OutputFormat) -> paksmith_core::Result<()> {
    let usmap = args.mappings.as_deref().map(load_mappings).transpose()?;
    let pkg = Package::read_from_pak(&args.pak, &args.asset, usmap.as_ref())?;
    crate::inspect::emit(&pkg, args, format)
}
```

In `inspect/mod.rs::emit` (Task 1), preserve the existing table-rejection so no behavior changes:

```rust
pub(crate) fn emit(pkg: &Package, _args: &InspectArgs, format: OutputFormat) -> paksmith_core::Result<()> {
    if matches!(format, OutputFormat::Table) {
        return Err(paksmith_core::PaksmithError::InvalidArgument {
            arg: "--format",
            reason: "table format is not yet supported for `inspect`; use `json` or `auto`".into(),
        });
    }
    write_json(pkg)
}
```

(Task 5 removes this rejection when the table renderer lands.)

- [ ] **Step 3: Run existing inspect tests — behavior unchanged**

Run: `cargo test -p paksmith-cli --test inspect_cli`
Expected: all existing tests PASS (output byte-identical).

- [ ] **Step 4: fmt + clippy**

Run: `cargo fmt --all` and `cargo clippy --workspace --all-targets --all-features -- -D warnings`
Expected: clean (add a narrow `#[allow(dead_code)]` only if `InspectOutput` is defined-but-unused this task).

- [ ] **Step 5: Commit**

```bash
git add crates/paksmith-cli/src/main.rs crates/paksmith-cli/src/commands/inspect.rs \
        crates/paksmith-cli/src/inspect/mod.rs
git commit -m "refactor(cli): promote inspect to a submodule (no behavior change)"
```

---

## Task 2: `schema_version` wrapper

**Files:**
- Modify: `crates/paksmith-cli/src/inspect/mod.rs`
- Modify: `crates/paksmith-cli/tests/inspect_cli.rs` (snapshot)

**Interfaces:**
- Consumes: `InspectOutput<T>`, `SCHEMA_VERSION` from Task 1.
- Produces: full-package JSON wrapped as `{ "schema_version": 1, <package fields...> }`.

- [ ] **Step 1: Write the failing snapshot/assertion test**

Add to `crates/paksmith-cli/tests/inspect_cli.rs`:

```rust
#[test]
fn inspect_json_has_schema_version_first() {
    let pak = fixture_path("real_v8b_uasset.pak");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_paksmith"))
        .args(["inspect", pak.to_str().unwrap(), "Game/Maps/Demo.uasset"])
        .output()
        .expect("run inspect");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["schema_version"], 1);
    assert_eq!(v["asset_path"], "Game/Maps/Demo.uasset"); // package fields still present
    // schema_version must be the FIRST key in the raw output.
    let first_key = stdout.find("\"schema_version\"").unwrap();
    let asset_path_key = stdout.find("\"asset_path\"").unwrap();
    assert!(first_key < asset_path_key, "schema_version must precede package fields");
}
```

- [ ] **Step 2: Run — verify it fails**

Run: `cargo test -p paksmith-cli --test inspect_cli inspect_json_has_schema_version_first`
Expected: FAIL (`schema_version` absent — Task 1 emitted the bare package).

- [ ] **Step 3: Wrap the full-package output**

In `inspect/mod.rs::emit`, change the JSON emit from `write_json(pkg)` to the wrapper:

```rust
    write_json(&InspectOutput { schema_version: SCHEMA_VERSION, body: pkg })
```

(`body: &Package` flattens inline after `schema_version`; serialized directly via `to_writer_pretty`, so the package's declaration-order fields are preserved.) Remove any `#[allow(dead_code)]` added in Task 1.

- [ ] **Step 4: Run — verify it passes**

Run: `cargo test -p paksmith-cli --test inspect_cli`
Expected: PASS. (If a pre-existing snapshot pinned the exact old JSON, update it: `INSTA_UPDATE=always cargo test -p paksmith-cli --test inspect_cli`, confirm only `schema_version` was added.)

- [ ] **Step 5: Verify `flatten` over `&Package` compiled**

If `#[serde(flatten)] body: &Package` failed to compile (rare borrow/trait snag), fall back: build `serde_json::Value` via `serde_json::to_value(pkg)`, and emit `InspectOutput { schema_version, body: value }` (accept alphabetized package fields; update the order assertion in the test to only check `v["schema_version"] == 1`). Note which path was taken in the commit body.

- [ ] **Step 6: Commit**

```bash
git add crates/paksmith-cli/src/inspect/mod.rs crates/paksmith-cli/tests/inspect_cli.rs
git commit -m "feat(cli): add schema_version to inspect JSON output"
```

---

## Task 3: `--path` navigation

**Files:**
- Create: `crates/paksmith-cli/src/inspect/select.rs`
- Modify: `crates/paksmith-cli/src/inspect/mod.rs` (wire `--path`, add `pub(crate) mod select;`)
- Modify: `crates/paksmith-cli/src/commands/inspect.rs` (add `--path` arg)
- Modify: `crates/paksmith-cli/tests/inspect_cli.rs`

**Interfaces:**
- Produces: `pub(crate) fn select::navigate<'v>(root: &'v serde_json::Value, path: &str) -> Result<&'v serde_json::Value, String>`
- New `InspectArgs.path: Option<String>`.

- [ ] **Step 1: Write the failing unit tests for `navigate`**

Create `crates/paksmith-cli/src/inspect/select.rs`:

```rust
//! `--export` resolution and `--path` navigation, both over the serialized
//! inspect document (a `serde_json::Value`).

use serde_json::Value;

/// Navigate `root` by a dotted `path` (object keys + numeric array indices),
/// returning the located sub-value. `Err` describes the failing segment.
pub(crate) fn navigate<'v>(root: &'v Value, path: &str) -> Result<&'v Value, String> {
    let mut cur = root;
    for seg in path.split('.').filter(|s| !s.is_empty()) {
        cur = match cur {
            Value::Object(map) => map
                .get(seg)
                .ok_or_else(|| format!("no key '{seg}' in path '{path}'"))?,
            Value::Array(arr) => {
                let idx: usize = seg
                    .parse()
                    .map_err(|_| format!("path segment '{seg}' is not an array index in '{path}'"))?;
                arr.get(idx)
                    .ok_or_else(|| format!("index {idx} out of range in path '{path}'"))?
            }
            _ => return Err(format!("cannot descend into scalar at '{seg}' in path '{path}'")),
        };
    }
    Ok(cur)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn doc() -> Value {
        json!({
            "schema_version": 1,
            "summary": { "guid": "abc", "name_count": 3 },
            "exports": [ { "object_name": "Root", "asset": { "Generic": { "kind": "opaque" } } } ]
        })
    }

    #[test]
    fn navigates_object_key() {
        assert_eq!(navigate(&doc(), "summary.guid").unwrap(), &json!("abc"));
    }

    #[test]
    fn navigates_array_index_and_nested() {
        assert_eq!(navigate(&doc(), "exports.0.object_name").unwrap(), &json!("Root"));
    }

    #[test]
    fn navigates_to_subtree() {
        assert_eq!(navigate(&doc(), "summary").unwrap(), &doc()["summary"]);
    }

    #[test]
    fn root_path_returns_whole_doc() {
        assert_eq!(navigate(&doc(), "").unwrap(), &doc());
    }

    #[test]
    fn missing_key_errors() {
        assert!(navigate(&doc(), "summary.nope").is_err());
    }

    #[test]
    fn bad_array_index_errors() {
        assert!(navigate(&doc(), "exports.9").is_err());
        assert!(navigate(&doc(), "exports.x").is_err());
    }

    #[test]
    fn descend_into_scalar_errors() {
        assert!(navigate(&doc(), "schema_version.x").is_err());
    }
}
```

- [ ] **Step 2: Run — verify it fails**

Run: `cargo test -p paksmith-cli navigate`
Expected: FAIL (module not declared / not wired). Add `pub(crate) mod select;` to `inspect/mod.rs`, then it compiles and tests run.

- [ ] **Step 3: Add the `--path` arg + wire it in `emit`**

In `commands/inspect.rs` `InspectArgs`, add:

```rust
    /// Emit only the value at this dotted path (e.g. `summary.guid`,
    /// `exports.0.asset`). Implies structured output; cannot combine with
    /// `--format table`.
    #[arg(long, value_name = "DOTTED")]
    pub(crate) path: Option<String>,
```

In `inspect/mod.rs`, declare the module and handle `--path` in `emit`:

```rust
pub(crate) mod select;

pub(crate) fn emit(pkg: &Package, args: &InspectArgs, format: OutputFormat) -> paksmith_core::Result<()> {
    // `--path` drills into the wrapped document and implies structured output.
    if let Some(path) = args.path.as_deref() {
        if matches!(format, OutputFormat::Table) {
            return Err(invalid("--format", "--path cannot be combined with --format table"));
        }
        let doc = serde_json::to_value(InspectOutput { schema_version: SCHEMA_VERSION, body: pkg })
            .map_err(serde_json_to_io)?;
        let found = select::navigate(&doc, path).map_err(|reason| invalid("--path", reason))?;
        return write_json(found);
    }

    // Table handling lands in Task 5; full JSON otherwise.
    if matches!(format, OutputFormat::Table) {
        return Err(invalid(
            "--format",
            "table format is not yet supported for `inspect`; use `json` or `auto`".into(),
        ));
    }
    write_json(&InspectOutput { schema_version: SCHEMA_VERSION, body: pkg })
}

fn invalid(arg: &'static str, reason: impl Into<String>) -> paksmith_core::PaksmithError {
    paksmith_core::PaksmithError::InvalidArgument { arg, reason: reason.into() }
}
```

(Note the `to_value` round-trip here is for `--path` only — the default full output in the last line stays a direct `to_writer`, order-preserved. The `--path` doc may be alphabetized; acceptable per spec.)

- [ ] **Step 4: Add integration tests for `--path`**

Add to `inspect_cli.rs`:

```rust
#[test]
fn inspect_path_drills_to_value() {
    let pak = fixture_path("real_v8b_uasset.pak");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_paksmith"))
        .args(["inspect", pak.to_str().unwrap(), "Game/Maps/Demo.uasset", "--path", "schema_version"])
        .output().unwrap();
    assert!(out.status.success());
    assert_eq!(String::from_utf8(out.stdout).unwrap().trim(), "1");
}

#[test]
fn inspect_path_unresolved_exits_2() {
    let pak = fixture_path("real_v8b_uasset.pak");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_paksmith"))
        .args(["inspect", pak.to_str().unwrap(), "Game/Maps/Demo.uasset", "--path", "nope.nope"])
        .output().unwrap();
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn inspect_path_with_table_exits_2() {
    let pak = fixture_path("real_v8b_uasset.pak");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_paksmith"))
        .args(["inspect", pak.to_str().unwrap(), "Game/Maps/Demo.uasset", "--path", "summary", "--format", "table"])
        .output().unwrap();
    assert_eq!(out.status.code(), Some(2));
}
```

- [ ] **Step 5: Run all inspect tests**

Run: `cargo test -p paksmith-cli navigate && cargo test -p paksmith-cli --test inspect_cli`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/paksmith-cli/src/inspect/select.rs crates/paksmith-cli/src/inspect/mod.rs \
        crates/paksmith-cli/src/commands/inspect.rs crates/paksmith-cli/tests/inspect_cli.rs
git commit -m "feat(cli): add --path drill-down to inspect"
```

---

## Task 4: `--export` selection

**Files:**
- Modify: `crates/paksmith-cli/src/inspect/select.rs` (add `resolve_export`)
- Modify: `crates/paksmith-cli/src/inspect/mod.rs` (wire `--export`)
- Modify: `crates/paksmith-cli/src/commands/inspect.rs` (add `--export` arg)
- Modify: `crates/paksmith-cli/tests/inspect_cli.rs`

**Interfaces:**
- Produces: `pub(crate) fn select::resolve_export(exports: &serde_json::Value, selector: &str) -> Result<usize, String>`
- New `InspectArgs.export: Option<String>`.
- Export body: the `exports[idx]` subtree (already includes that export's `asset`), wrapped with `schema_version`.

- [ ] **Step 1: Write the failing unit tests for `resolve_export`**

Add to `select.rs`:

```rust
/// Resolve an `--export` selector against the serialized `exports` array.
/// Numeric → array index; otherwise → match `object_name`. Errors on
/// out-of-range index, unknown name, or an ambiguous (multi-match) name.
pub(crate) fn resolve_export(exports: &Value, selector: &str) -> Result<usize, String> {
    let arr = exports
        .as_array()
        .ok_or_else(|| "no exports array in document".to_string())?;
    if let Ok(idx) = selector.parse::<usize>() {
        if idx < arr.len() {
            return Ok(idx);
        }
        return Err(format!("export index {idx} out of range (0..{})", arr.len()));
    }
    let matches: Vec<usize> = arr
        .iter()
        .enumerate()
        .filter(|(_, e)| e.get("object_name").and_then(Value::as_str) == Some(selector))
        .map(|(i, _)| i)
        .collect();
    match matches.as_slice() {
        [i] => Ok(*i),
        [] => Err(format!("no export named '{selector}'")),
        many => Err(format!("export name '{selector}' is ambiguous ({} matches)", many.len())),
    }
}
```

Add tests in `select.rs`'s `mod tests`:

```rust
    fn exports() -> Value {
        json!([
            { "object_name": "Root" },
            { "object_name": "Mesh" },
            { "object_name": "Mesh" }
        ])
    }

    #[test]
    fn resolve_by_index() {
        assert_eq!(resolve_export(&exports(), "0").unwrap(), 0);
    }

    #[test]
    fn resolve_by_unique_name() {
        assert_eq!(resolve_export(&exports(), "Root").unwrap(), 0);
    }

    #[test]
    fn resolve_index_out_of_range_errors() {
        assert!(resolve_export(&exports(), "9").is_err());
    }

    #[test]
    fn resolve_unknown_name_errors() {
        assert!(resolve_export(&exports(), "Nope").is_err());
    }

    #[test]
    fn resolve_ambiguous_name_errors() {
        assert!(resolve_export(&exports(), "Mesh").is_err());
    }
```

- [ ] **Step 2: Run — verify it fails**

Run: `cargo test -p paksmith-cli resolve_export`
Expected: FAIL (function undefined).

- [ ] **Step 3: Add the `--export` arg + wire selection in `emit`**

In `commands/inspect.rs` `InspectArgs`:

```rust
    /// Emit only a single export: a numeric export-table index, or an export
    /// object name. Errors on an unknown/ambiguous name or out-of-range index.
    #[arg(long, value_name = "IDX|NAME")]
    pub(crate) export: Option<String>,
```

In `inspect/mod.rs::emit`, compute the body once (full package Value or the selected export subtree), then apply `--path`/format. Restructure `emit`:

```rust
pub(crate) fn emit(pkg: &Package, args: &InspectArgs, format: OutputFormat) -> paksmith_core::Result<()> {
    let table = matches!(format, OutputFormat::Table);

    // `--export` narrows the body to one export subtree (needs a Value to match
    // resolved names + slice the subtree).
    let selected_body: Option<serde_json::Value> = match args.export.as_deref() {
        Some(sel) => {
            let pkg_val = serde_json::to_value(pkg).map_err(serde_json_to_io)?;
            let idx = select::resolve_export(&pkg_val["exports"], sel)
                .map_err(|reason| invalid("--export", reason))?;
            Some(pkg_val["exports"][idx].clone())
        }
        None => None,
    };

    if let Some(path) = args.path.as_deref() {
        if table {
            return Err(invalid("--format", "--path cannot be combined with --format table"));
        }
        // Wrap whichever body is active, then drill.
        let doc = match &selected_body {
            Some(b) => serde_json::to_value(InspectOutput { schema_version: SCHEMA_VERSION, body: b })
                .map_err(serde_json_to_io)?,
            None => serde_json::to_value(InspectOutput { schema_version: SCHEMA_VERSION, body: pkg })
                .map_err(serde_json_to_io)?,
        };
        let found = select::navigate(&doc, path).map_err(|reason| invalid("--path", reason))?;
        return write_json(found);
    }

    if table {
        // Task 5 fills this in (full package or single export).
        return Err(invalid(
            "--format",
            "table format is not yet supported for `inspect`; use `json` or `auto`",
        ));
    }

    // JSON: wrapped full package (direct, order-preserved) or wrapped export subtree.
    match selected_body {
        Some(b) => write_json(&InspectOutput { schema_version: SCHEMA_VERSION, body: b }),
        None => write_json(&InspectOutput { schema_version: SCHEMA_VERSION, body: pkg }),
    }
}
```

- [ ] **Step 4: Integration tests for `--export`**

Add to `inspect_cli.rs`:

```rust
#[test]
fn inspect_export_by_index() {
    let pak = fixture_path("real_v8b_uasset.pak");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_paksmith"))
        .args(["inspect", pak.to_str().unwrap(), "Game/Maps/Demo.uasset", "--export", "0"])
        .output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["schema_version"], 1);
    assert!(v.get("asset").is_some(), "single-export body must carry its asset");
    assert!(v.get("exports").is_none(), "single-export body is not the whole package");
}

#[test]
fn inspect_export_bad_index_exits_2() {
    let pak = fixture_path("real_v8b_uasset.pak");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_paksmith"))
        .args(["inspect", pak.to_str().unwrap(), "Game/Maps/Demo.uasset", "--export", "99"])
        .output().unwrap();
    assert_eq!(out.status.code(), Some(2));
}
```

- [ ] **Step 5: Run all inspect tests**

Run: `cargo test -p paksmith-cli resolve_export && cargo test -p paksmith-cli --test inspect_cli`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/paksmith-cli/src/inspect/select.rs crates/paksmith-cli/src/inspect/mod.rs \
        crates/paksmith-cli/src/commands/inspect.rs crates/paksmith-cli/tests/inspect_cli.rs
git commit -m "feat(cli): add --export selection to inspect"
```

---

## Task 5: `--format table` human tree view + compact typed formatters

**Files:**
- Create: `crates/paksmith-cli/src/inspect/tree.rs`
- Modify: `crates/paksmith-cli/src/inspect/mod.rs` (wire table; add `pub(crate) mod tree;`)
- Modify: `crates/paksmith-cli/tests/inspect_cli.rs`

**Interfaces:**
- Consumes: `paksmith_core::asset::Package`, the property-bag/struct types.
- Produces: `pub(crate) fn tree::render(pkg: &Package, export: Option<usize>, w: &mut dyn std::io::Write) -> io::Result<()>`
- Produces compact formatters: `pub(crate) fn fmt_vector(v: &FVector) -> String`, `fmt_color(c: &FColor) -> String`, `fmt_linear_color(c: &FLinearColor) -> String`.

**Note on payload depth:** before writing, the implementer inspects the actual `PropertyBag` / `Asset` API (`crates/paksmith-core/src/asset/property/bag.rs`, `asset/mod.rs`, `asset/structs/{vector,color}.rs`) to wire the property-tree walk to the REAL enum shapes. The formatters below have fixed signatures; the tree walk adapts to the live `PropertyBag` variants.

- [ ] **Step 1: Write failing unit tests for the compact formatters**

Create `crates/paksmith-cli/src/inspect/tree.rs`:

```rust
//! Human-readable `--format table` renderer. Compact typed formatting
//! (`[x,y,z]`, `#hex`) lives ONLY here — JSON keeps the canonical object shape.

use std::io::{self, Write};

use paksmith_core::asset::Package;
use paksmith_core::asset::structs::color::{FColor, FLinearColor};
use paksmith_core::asset::structs::vector::FVector;

/// `FVector` → `[x, y, z]` with trimmed floats.
pub(crate) fn fmt_vector(v: &FVector) -> String {
    format!("[{}, {}, {}]", trim(v.x), trim(v.y), trim(v.z))
}

/// 8-bit `FColor` → `#RRGGBB` (or `#RRGGBBAA` when alpha != 255).
pub(crate) fn fmt_color(c: &FColor) -> String {
    if c.a == 0xFF {
        format!("#{:02X}{:02X}{:02X}", c.r, c.g, c.b)
    } else {
        format!("#{:02X}{:02X}{:02X}{:02X}", c.r, c.g, c.b, c.a)
    }
}

/// Float `FLinearColor` → `#RRGGBB(AA)` via 0..=255 quantization.
pub(crate) fn fmt_linear_color(c: &FLinearColor) -> String {
    let q = |f: f32| (f.clamp(0.0, 1.0) * 255.0).round() as u8;
    fmt_color(&FColor { r: q(c.r), g: q(c.g), b: q(c.b), a: q(c.a) })
}

/// Trim a float to a compact decimal (no trailing zeros, but keep `0`).
fn trim(f: f64) -> String {
    let s = format!("{f}");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vector_compact() {
        assert_eq!(fmt_vector(&FVector { x: 1.0, y: 2.5, z: -3.0 }), "[1, 2.5, -3]");
    }

    #[test]
    fn color_opaque_is_rrggbb() {
        assert_eq!(fmt_color(&FColor { r: 0xFF, g: 0x88, b: 0x00, a: 0xFF }), "#FF8800");
    }

    #[test]
    fn color_with_alpha_is_rrggbbaa() {
        assert_eq!(fmt_color(&FColor { r: 0x10, g: 0x20, b: 0x30, a: 0x40 }), "#10203040");
    }

    #[test]
    fn linear_color_quantizes() {
        assert_eq!(fmt_linear_color(&FLinearColor { r: 1.0, g: 0.0, b: 0.0, a: 1.0 }), "#FF0000");
    }
}
```

(Verify `FColor`/`FVector`/`FLinearColor` field names + module paths against the source before relying on them — `vector.rs`/`color.rs` show `pub x/y/z`, `pub r/g/b/a`. Adjust the `use` paths to the real public re-export, e.g. `paksmith_core::asset::structs::...`.)

- [ ] **Step 2: Run — verify it fails (or compile-errors on import path)**

Run: `cargo test -p paksmith-cli --lib fmt_vector`
Expected: FAIL/compile error until the module is declared + import paths correct. Add `pub(crate) mod tree;` to `inspect/mod.rs`.

- [ ] **Step 3: Implement `tree::render` (header + per-export + property walk)**

Add `render` to `tree.rs`. Walk the REAL `Package` API: header summary line (engine version, name/import/export counts, GUID), then per-export lines. For each export, print `[idx] <object_name> : <class>` and a payload-shape line; for `Generic` opaque → `opaque (N bytes)`, for `Generic` tree → walk properties with indentation, applying `fmt_vector`/`fmt_color` where a property value is a typed struct, and resolving enum/byte names. Respect the optional `export: Option<usize>` to render one export only.

(The implementer writes this against the live `PropertyBag`/`Asset`/`PropertyValue` enums — exact match arms are determined by reading `asset/property/bag.rs` + `asset/mod.rs`. Keep the function focused; if the property walk grows past ~40 lines, extract a `fn render_properties(...)` helper in the same file.)

- [ ] **Step 4: Wire the table branch in `emit`**

In `inspect/mod.rs::emit`, replace the table-rejection branch with the renderer:

```rust
    if table {
        let export_idx = match (&args.export, &selected_body) {
            (Some(sel), _) => {
                let pkg_val = serde_json::to_value(pkg).map_err(serde_json_to_io)?;
                Some(select::resolve_export(&pkg_val["exports"], sel)
                    .map_err(|reason| invalid("--export", reason))?)
            }
            _ => None,
        };
        let stdout = io::stdout();
        let mut out = io::BufWriter::new(stdout.lock());
        tree::render(pkg, export_idx, &mut out)?;
        out.flush()?;
        return Ok(());
    }
```

(If `--export` was already resolved above for the JSON path, reuse that index rather than re-resolving — implementer dedups cleanly; the key requirement is table honors `--export`.)

- [ ] **Step 5: Integration snapshot for the table view**

Add to `inspect_cli.rs`:

```rust
#[test]
fn inspect_table_renders_human_tree() {
    let pak = fixture_path("real_v8b_uasset.pak");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_paksmith"))
        .args(["inspect", pak.to_str().unwrap(), "Game/Maps/Demo.uasset", "--format", "table"])
        .output().unwrap();
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8(out.stdout).unwrap();
    // Stable, host-independent assertions (avoid pinning the whole layout).
    assert!(stdout.contains("Game/Maps/Demo.uasset") || stdout.contains("Demo"));
    assert!(stdout.contains("export"));
    // Must NOT be JSON.
    assert!(serde_json::from_str::<serde_json::Value>(&stdout).is_err());
}
```

- [ ] **Step 6: Run all tests + verify no JSON regression**

Run: `cargo test -p paksmith-cli`
Expected: PASS (formatters + table integration + all prior).

- [ ] **Step 7: Commit**

```bash
git add crates/paksmith-cli/src/inspect/tree.rs crates/paksmith-cli/src/inspect/mod.rs \
        crates/paksmith-cli/tests/inspect_cli.rs
git commit -m "feat(cli): add --format table human tree view to inspect"
```

---

## Task 6: Snapshots, ROADMAP, full gate chain

**Files:**
- Modify: `crates/paksmith-cli/tests/inspect_cli.rs` (insta snapshots)
- Modify: `docs/plans/ROADMAP.md`

- [ ] **Step 1: Add `insta` snapshots (redacted, portable)**

Add snapshot tests for the wrapped full JSON, a `--export 0` body, and a `--path summary` subtree. Redact host/GUID-volatile fields before snapshotting (mirror 4a's `extract_summary_snapshot` redaction pattern — replace `guid`, engine-version strings, and any path with placeholders). Accept snapshots: `INSTA_UPDATE=always cargo test -p paksmith-cli --test inspect_cli`; confirm each contains `"schema_version": 1` first and commit the `.snap` files under `crates/paksmith-cli/tests/snapshots/`.

- [ ] **Step 2: Update ROADMAP**

In `docs/plans/ROADMAP.md` Phase 4 section, note 4b `inspect` enhancements shipped (versioned wrapper, `--export`/`--path`, `--format table`), mirroring the 4a note. Factual, brief, no engine-source references.

- [ ] **Step 3: Full gate chain (each UNPIPED, fix any failure)**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
typos .
```
Expected: all exit 0.

- [ ] **Step 4: Commit**

```bash
git add crates/paksmith-cli/tests/inspect_cli.rs crates/paksmith-cli/tests/snapshots/ docs/plans/ROADMAP.md
git commit -m "test(cli): snapshot coverage for inspect; mark 4b shipped"
```

---

## Review & Push

- [ ] Adversarial multi-agent panel (≥3 + specialists; the `navigate`/`resolve_export` untrusted-path handling and the serde wrapper warrant a security + a correctness lens). Brief cold; pass the diff.
- [ ] Cycle to convergence (re-dispatch full panel after each fix commit). Stop only when all reviewers APPROVE.
- [ ] Touch the convergence marker, then push + open PR:
  ```bash
  touch "$(git rev-parse --git-dir)/REVIEW_CONVERGED_OK"   # separate Bash call from the push
  git push -u origin feat/phase-4b-inspect
  ```
- [ ] Open PR (`gh ... --body-file`), Monitor CI to green. Do NOT merge — the user merges via UI.

---

## Self-Review (plan vs spec)

**Spec coverage:**
- Output wrapper + `schema_version` (first key) → Task 1 (skeleton) + Task 2. ✓
- `--export <idx|name>` (index, name, ambiguous/unknown/oob errors) → Task 4. ✓
- `--path <dotted>` (object/array nav, leaf, missing, scalar-descend, implies-JSON, rejects table) → Task 3. ✓
- `--format table` human tree + compact typed rendering (vector/color/enum) → Task 5. ✓
- Compact forms ONLY in table; JSON canonical → Task 5 (formatters in `tree.rs` only; JSON paths never call them). ✓
- Core untouched → all tasks are CLI-side; no `crates/paksmith-core` edits. ✓
- Exit codes 0/2 + BrokenPipe → `invalid()` → `Err` → exit 2 (existing `main.rs` map); `write_json` preserves BrokenPipe. ✓
- Module promotion → Task 1. ✓
- Testing (insta + assert_cmd + unit nav/resolve/formatters) → Tasks 3/4/5/6. ✓
- Coverage limitation (typed table rendering not e2e through a packed pak) → formatters unit-tested; documented in spec; integration table test uses the Generic fixture. ✓

**Type consistency:** `InspectOutput<T>`, `SCHEMA_VERSION`, `emit(pkg, args, format)`, `navigate(&Value, &str) -> Result<&Value,String>`, `resolve_export(&Value, &str) -> Result<usize,String>`, `tree::render(pkg, Option<usize>, &mut dyn Write)`, `fmt_vector/fmt_color/fmt_linear_color` are referenced identically across tasks. `inspect::run` stays `Result<()>`.

**Open verification flags for the implementer (resolve at the task):**
- `#[serde(flatten)] body: &Package` compiling (Task 2 Step 5 gives the `to_value` fallback).
- Exact public module paths for `FVector`/`FColor`/`FLinearColor` (`paksmith_core::asset::structs::{vector,color}`) and field names — confirmed `pub x/y/z`, `pub r/g/b/a` in source; verify the re-export path resolves from the CLI crate.
- The live `PropertyBag`/`Asset`/`PropertyValue` enum arms for the Task 5 property walk — read `asset/property/bag.rs` + `asset/mod.rs` before writing the walk.
- `trim()` float formatting: the test expects `1.0 → "1"`, `2.5 → "2.5"`. Plain `format!("{f}")` yields `"1"` for `1.0_f64`? Confirm Rust's default `f64` Display (`1.0_f64` formats as `"1"`). If it yields `"1"`, the test passes; if `"1.0"`, adjust the formatter or the expected values at the task.
