# Paksmith Phase 2e: Companion Files & Object Resolution

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable parsing of split assets (`.uasset` header + `.uexp` payload pair stored as separate pak entries), and resolve `ObjectProperty` package indices to human-readable names using the import/export tables.

**Architecture:** `Package::read_from` gains an `Option<uexp: &[u8]>` parameter; if `Some`, the bytes are concatenated before parsing so the existing cursor-seek logic works without change. After the header is parsed (which gives `total_header_size`), four states are handled: split-and-stitched (proceed), split-but-missing-uexp (error), monolithic-and-extra-uexp (warn+ignore), monolithic-no-uexp (proceed). `Package::read_from_pak` looks up the `.uexp` and `.ubulk` siblings from the pak; `.ubulk` is detected and warned but not stitched. A new `resolve_package_index` helper in `primitives.rs` resolves a typed `PackageIndex` through `AssetContext.imports`/`.exports` to a `String`; `PropertyValue::Object` migrates from Phase 2d's `Object(PackageIndex)` tuple variant to `Object { kind: PackageIndex, name: String }` — `kind` preserves the typed import/export/null disambiguator, `name` is the resolved string. The `build_minimal_ue4_27_split` fixture splits the header and payload into two separate byte slices; `paksmith-fixture-gen` stores them as distinct pak entries and cross-validates through `unreal_asset`'s `Asset::new(asset_data, Some(bulk_data), ...)` form.

**Tech Stack:** Same as Phase 2d — Rust 1.85, `thiserror`, `byteorder` (LE), `serde`, `tracing`, `proptest`, `unreal_asset` (fixture-gen oracle, pinned to `f4df5d8e`). No new crate dependencies.

---

## Deliverable

`paksmith inspect <pak> <virtual/path>` now resolves object references to names and transparently handles split assets. Example JSON:

```json
{
  "asset_path": "Game/Data/Hero.uasset",
  "exports": [
    {
      "object_name": "Hero",
      "properties": [
        {
          "name": "MeshRef",
          "value": {
            "Object": { "kind": "Import(0)", "name": "StaticMesh" }
          }
        },
        {
          "name": "NullRef",
          "value": { "Object": { "kind": "Null", "name": "" } }
        }
      ]
    }
  ]
}
```

The embedded `kind` string is the bare `Display` form of [`PackageIndex`] (`"Null"`, `"Import(N)"`, `"Export(N)"`) — pinned by the serialization tests at `crates/paksmith-core/src/asset/property/primitives.rs:734-750`. `PackageIndex::Serialize` uses `serializer.collect_str(self)` over its `Display` impl, so the `kind` field embeds as the bare string rather than a nested tagged object. `name` is the bare `object_name` FName of the target import or export (e.g. `"StaticMesh"`, `"Hero"`); the resolution helper does NOT synthesize a SoftObjectPath-style full path because `ObjectImport`/`ObjectExport` don't carry one.

The split-asset pak (`tests/fixtures/real_v8b_split.pak`) has `Game/Maps/Demo.uasset` (header only) and `Game/Maps/Demo.uexp` (payload) as separate entries. `paksmith inspect real_v8b_split.pak Game/Maps/Demo.uasset` parses identically to the monolithic fixture.

## Scope vs. deferred work

**In scope (this plan):**

- `.uexp` companion file detection and byte stitching
- `AssetParseFault::MissingCompanionFile { kind: CompanionFileKind }` — fires when any export's `serial_offset >= total_header_size` but no `.uexp` was found in the pak
- `CompanionFileKind` enum: `Uexp` (and `Ubulk` for display-completeness, even though ubulk is not stitched)
- `.ubulk` detection in `read_from_pak` → `tracing::warn!` only; bytes not stitched
- Four-state companion logic in `Package::read_from` (after header parse):
  - Missing uexp, export needs it → `MissingCompanionFile` error
  - Has uexp, export needs it → stitch + proceed
  - Has uexp, no export needs it → `tracing::warn!` + proceed (extra bytes ignored)
  - No uexp, no export needs it → monolithic, proceed unchanged
- `resolve_package_index(kind, ctx, asset_path)` helper in `primitives.rs` (takes a typed `PackageIndex`)
- `PropertyValue::Object` migration from Phase 2d's `Object(PackageIndex)` tuple to `Object { kind: PackageIndex, name: String }` struct
- `read_primitive_value` and `read_element_value` both call `resolve_package_index` for ObjectProperty
- `build_minimal_ue4_27_split() -> (Vec<u8>, Vec<u8>)` test fixture (uasset header bytes + uexp payload bytes)
- `MinimalPackage.total_header_size: usize` to support the split builder
- `tests/fixtures/real_v8b_split.pak` — generated fixture with two entries
- fixture-gen oracle cross-validation for split assets using `Asset::new(Some(bulk_data))`
- Integration tests: 4 companion states + ObjectProperty null/import/export/OOB resolution

**Note on CLI snapshot coverage:** The Phase 2c-era snapshot at `crates/paksmith-cli/tests/snapshots/inspect_cli__inspect_json_snapshot.snap` uses `real_v8b_uasset.pak`, whose single export decodes to `PropertyBag::Opaque` (no tagged-property iteration, no `Object` value). Phase 2e does NOT add a new snapshot fixture for the `Object { kind, name }` shape — the six integration tests in Task 6 own that coverage. Task 7 (snapshot update) is deliberately omitted; see Self-review for the rationale.

**Explicitly deferred:**

- `.ubulk` payload stitching — moved to Phase 3; bulk data (texture mips, mesh LODs) has no consumer until the export pipeline lands, and the chunk-offset arithmetic belongs alongside the handlers that actually read it
- `StructProperty` as a collection element — wire format requires a separate empirical verification pass (see `memory/feedback_verify_wire_format_claims.md`)
- Unversioned properties (`PKG_UnversionedProperties`) — Phase 2f

## Design decisions locked here

1. **`PropertyValue::Object` delta:** Phase 2d defines `Object(PackageIndex)` as a typed tuple variant wrapping the [`PackageIndex`] enum from `crate::asset::package_index`. Phase 2e migrates it to `Object { kind: PackageIndex, name: String }`. `kind` preserves the typed import/export/null disambiguator from `PackageIndex::try_from_raw` (so the typed wire-decode that Phase 2d shipped is not undone); `name` is the operator-visible resolved string. `kind == PackageIndex::Null` always resolves to `name: ""`. `kind == PackageIndex::Import(N)` resolves to the import's bare `object_name` FName via `resolve_fname`; `kind == PackageIndex::Export(N)` likewise. The resolver does NOT synthesize a SoftObjectPath-style full path (`<class_package>.<object_name>`) because `ObjectImport`/`ObjectExport` don't carry one — bare `object_name` is the simplest and most useful form that's structurally available from header-only data.

2. **`resolve_package_index` lives in `primitives.rs`**, not a new `objects.rs`. One helper function doesn't justify a new module (YAGNI). `objects.rs` can be created if/when Phase 2f or later introduces multiple distinct object-type helpers.

3. **Byte concatenation is allocation-free for monolithic case:** The Rust idiom `let combined: Vec<u8>; let bytes = match uexp { Some(d) => { combined = [...].concat(); &combined } None => uasset };` avoids allocation and copy when `uexp.is_none()`.

4. **`MissingCompanionFile` is a variant of `AssetParseFault`**, not a new top-level `PaksmithError`. The failure is logically a parse-time failure (we have the header, know we need more bytes, and can't continue). The display string "missing required .uexp companion file" accurately describes the failure site.

5. **Wire-format claim verification:** The claim that `combined = [uasset || uexp]` and `serial_offset` indexes naturally into it (because `uasset.len() == total_header_size` for split assets by UE convention) is verified empirically by the fixture-gen oracle task (Task 5). `unreal_asset::Asset::new(asset_reader, Some(uexp_reader), ...)` uses the separate-file form; paksmith uses the concatenated form. Agreement between both on the same fixture proves the layout assumption.

6. **`derive_companion_path` is `pub(super)` in `package.rs`** — only `read_from_pak` uses it; no need for wider visibility.

---

## File structure

| File                                                    | Action | Responsibility                                                                                                                    |
| ------------------------------------------------------- | ------ | --------------------------------------------------------------------------------------------------------------------------------- |
| `crates/paksmith-core/src/error.rs`                     | Modify | Add `MissingCompanionFile` + `CompanionFileKind` enum with Display pins                                                           |
| `crates/paksmith-core/src/asset/property/primitives.rs` | Modify | Add `resolve_package_index`; migrate `PropertyValue::Object(PackageIndex)` → `Object { kind, name }`; update read functions       |
| `crates/paksmith-core/src/asset/package.rs`             | Modify | Change `read_from(uasset, uexp, path)` signature; four-state companion logic; add `derive_companion_path`; update `read_from_pak` |
| `crates/paksmith-core/src/testing/uasset.rs`            | Modify | Add `total_header_size` to `MinimalPackage`; add `build_minimal_ue4_27_split() -> (Vec<u8>, Vec<u8>)`                             |
| `crates/paksmith-core/tests/companion_integration.rs`   | Create | 6 integration tests (4 companion states + 2 ObjectProperty resolution)                                                            |
| `crates/paksmith-fixture-gen/src/uasset.rs`             | Modify | Split-asset fixture generation + oracle cross-validation block                                                                    |
| `tests/fixtures/real_v8b_split.pak`                     | Create | Generated split-asset fixture (two pak entries)                                                                                   |

---

## PR workflow

Each task lands as its own PR. Workflow per task:

- **Branch name:** `<type>/<kebab-case>` matching conventional-commit prefixes (`feat/uexp-stitching`, `feat/object-name-resolution`, `test/companion-integration`, etc.). Do NOT use `phase-2e-task-N` or `worktree-*`; the convention is verb-first per `memory/feedback_branch_naming_convention.md`.
- **PR title:** lowercase, verb-first, no "Phase 2e" prefix. E.g. `feat(asset): resolve ObjectProperty package index to name`. The "Phase 2e Task N of M" cross-reference goes in the PR body, not the subject. See `memory/feedback_pr_title_lowercase_verb_first.md`.
- **PR body:** write to a tempfile via heredoc, then `gh pr create --body-file <tempfile>`. Inline `--body "$(cat <<EOF ...)"` mangles backticks (see `memory/feedback_pr_body_no_backtick_escaping.md`).
- **Reviewer panel:** dispatch ≥3 complementary reviewers in parallel (code-quality + security + simplifier; +architect for structural changes) — one tool-call message, not sequential. Per `memory/feedback_parallel_full_review_panel.md` and `feedback_always_run_review_panel.md`, the panel runs for every PR (refactor/docs/polish included) without asking permission. Convergence: re-run the panel on every fix commit until every reviewer reports APPROVED (see `feedback_review_until_convergence.md`).
- **Commit trailer:** every commit ends with `Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>` (or the operator's CLI default).
- **No force-push.** Add follow-up commits instead of amending after push, per `memory/feedback_no_force_push_feature_branches.md`.

## Tooling notes

- **Do NOT rely on `| tail -N` for cargo gate exit codes.** `tail` returns 0 regardless of the upstream command's status; piping `cargo test` / `cargo clippy` / `cargo build` through `tail` hides red builds. Run cargo gates unpiped for the exit-code signal, OR enable `set -o pipefail` in the shell first. The `| tail -N` invocations sprinkled throughout this plan are for limiting log volume during interactive review — they are NOT pass/fail gates.
- **Pre-commit hook:** `git config core.hooksPath .githooks` per clone enables the fmt+clippy hook. CI runs both regardless; the hook just gets the feedback locally.

---

### Task 1: Error types for companion file faults

**Files:**

- Modify: `crates/paksmith-core/src/error.rs`

- [ ] **Step 1: Write failing Display pin tests**

Find the `#[cfg(test)] mod tests` block in `error.rs` (the block containing `asset_parse_display_*` tests from Phase 2a–2d) and add:

```rust
#[test]
fn asset_parse_display_missing_companion_file_uexp() {
    let err = PaksmithError::AssetParse {
        asset_path: "Game/Sword.uasset".to_string(),
        fault: AssetParseFault::MissingCompanionFile {
            kind: CompanionFileKind::Uexp,
        },
    };
    assert_eq!(
        format!("{err}"),
        "asset deserialization failed for `Game/Sword.uasset`: \
         missing required .uexp companion file"
    );
}

#[test]
fn companion_file_kind_display_uexp() {
    assert_eq!(CompanionFileKind::Uexp.to_string(), "uexp");
}

#[test]
fn companion_file_kind_display_ubulk() {
    assert_eq!(CompanionFileKind::Ubulk.to_string(), "ubulk");
}
```

- [ ] **Step 2: Run tests to confirm compile error**

```bash
cargo test -p paksmith-core --lib error::tests::asset_parse_display_missing_companion 2>&1 | tail -10
```

Expected: compile error — `CompanionFileKind` not found.

- [ ] **Step 3: Add the `MissingCompanionFile` variant**

`AssetParseFault` in `error.rs:2117` is NOT `#[derive(thiserror::Error)]` — it has a hand-rolled `impl fmt::Display for AssetParseFault` at `error.rs:2403`. Adding a `#[error("...")]` attribute would compile (the attribute is silently ignored) but produce no Display output for the variant. Instead, add the variant declaration alone, then add a matching arm in the manual `Display` impl (Step 3b below).

Find `pub enum AssetParseFault` and add after the last existing variant (last Phase 2d addition was `UnsupportedSoftObjectPathLayout`):

```rust
/// A required companion file was not present in the pak when the asset
/// header's export table indicated it was needed.
///
/// For `.uexp`: fired when any export has `serial_offset >= total_header_size`
/// but no `.uexp` entry was found in the pak.
MissingCompanionFile {
    /// Which companion file type was missing.
    kind: CompanionFileKind,
},
```

- [ ] **Step 3b: Add the Display arm for `MissingCompanionFile`**

Find `impl fmt::Display for AssetParseFault` at `error.rs:2403`. After the `UnsupportedSoftObjectPathLayout` arm (the last existing arm, ending around `error.rs:2534`), add:

```rust
Self::MissingCompanionFile { kind } => {
    write!(f, "missing required .{kind} companion file")
}
```

This arm relies on `CompanionFileKind` implementing `Display` (added in Step 4).

- [ ] **Step 4: Add the `CompanionFileKind` enum and its `Display` impl**

Place this AFTER `AssetParseFault` and its `Display` impl — matching the existing discriminator-enum convention (`AssetWireField` at line 2547, `AssetOverflowSite` at 2738, `AssetAllocationContext` at 2807, `CollectionKind` at 2776, `CompressionInSummarySite` at 2881 all live AFTER `AssetParseFault`):

```rust
/// Identifies which companion file type is referenced in
/// [`AssetParseFault::MissingCompanionFile`].
///
/// `#[non_exhaustive]` because additional companion file types
/// (e.g., `.uexpbulk` in IoStore) may be added in future phases.
/// `Display` produces the raw extension string so the parent error
/// message reads `.uexp` or `.ubulk` naturally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CompanionFileKind {
    /// `.uexp` — export payload bytes split out of the `.uasset` header.
    Uexp,
    /// `.ubulk` — additional bulk data (texture mips, etc.), detected but not
    /// yet stitched (Phase 2e warns; full support deferred).
    Ubulk,
}

impl fmt::Display for CompanionFileKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Uexp => "uexp",
            Self::Ubulk => "ubulk",
        })
    }
}
```

- [ ] **Step 5: Run Display pin tests**

```bash
cargo test -p paksmith-core --lib error::tests
```

Expected: all tests pass, including the 3 new pin tests.

- [ ] **Step 6: Run workspace fmt, clippy, and rustdoc**

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
```

Expected: all three clean.

- [ ] **Step 7: Commit**

```bash
git add crates/paksmith-core/src/error.rs
git commit -m "$(cat <<'EOF'
feat(error): MissingCompanionFile + CompanionFileKind for Phase 2e

Fires when an asset's export table requires a .uexp companion that
wasn't found in the pak. CompanionFileKind::Ubulk is defined for
display completeness; bulk stitching is deferred past Phase 2e.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: `resolve_package_index` + `PropertyValue::Object` migration

**Files:**

- Modify: `crates/paksmith-core/src/asset/property/primitives.rs`

This task adds the resolution helper, migrates `PropertyValue::Object(PackageIndex)` (the Phase 2d tuple variant at `primitives.rs:185`) to `Object { kind: PackageIndex, name: String }`, and updates both `read_primitive_value` (`primitives.rs:393-405`) and `read_element_value` (`containers.rs:159-171`) to resolve eagerly.

**Context:** `AssetContext` (from `crates/paksmith-core/src/asset/mod.rs`) carries `imports: Arc<ImportTable>` and `exports: Arc<ExportTable>`. `ImportTable` has a field `pub imports: Vec<ObjectImport>`; `ExportTable` has `pub exports: Vec<ObjectExport>`. `ObjectImport::object_name` and `ObjectExport::object_name` are both `u32` FName indices (NOT pre-resolved strings) — the helper walks them through `ctx.names` via `resolve_fname` from Phase 2b. `AssetParseFault::PackageIndexOob` (Phase 2a) is reused for the OOB case. The `i32::MIN` underflow case does NOT need handling inside `resolve_package_index` — it's already caught at decode time by `PackageIndex::try_from_raw` in both wire-read arms (see `primitives.rs:397` and `containers.rs:163`), surfacing as `AssetParseFault::PackageIndexUnderflow` before the resolver runs.

- [ ] **Step 1: Write failing unit tests**

Find the `#[cfg(test)]` block in `primitives.rs` and add:

```rust
#[test]
fn resolve_package_index_null_is_empty_string() {
    let ctx = make_test_ctx_with_import("/Game/Mesh.Mesh");
    let name = resolve_package_index(PackageIndex::Null, &ctx, "x.uasset").unwrap();
    assert_eq!(name, "");
}

#[test]
fn resolve_package_index_import_ref() {
    let ctx = make_test_ctx_with_import("/Game/Mesh.Mesh");
    let name = resolve_package_index(PackageIndex::Import(0), &ctx, "x.uasset").unwrap();
    assert_eq!(name, "/Game/Mesh.Mesh");
}

#[test]
fn resolve_package_index_export_ref() {
    let ctx = make_test_ctx_with_export("Hero");
    let name = resolve_package_index(PackageIndex::Export(0), &ctx, "x.uasset").unwrap();
    assert_eq!(name, "Hero");
}

#[test]
fn resolve_package_index_import_oob() {
    let ctx = make_test_ctx_with_import("/Game/Mesh.Mesh");
    // imports has 1 entry; Import(100) is far past the end.
    let err = resolve_package_index(PackageIndex::Import(100), &ctx, "x.uasset").unwrap_err();
    assert!(matches!(
        err,
        PaksmithError::AssetParse {
            fault: AssetParseFault::PackageIndexOob { .. },
            ..
        }
    ));
}

#[test]
fn resolve_package_index_export_oob() {
    let ctx = make_test_ctx_with_import("/Game/Mesh.Mesh"); // no exports
    let err = resolve_package_index(PackageIndex::Export(0), &ctx, "x.uasset").unwrap_err();
    assert!(matches!(
        err,
        PaksmithError::AssetParse {
            fault: AssetParseFault::PackageIndexOob { .. },
            ..
        }
    ));
}
```

> **No `i32::MIN` test needed.** `PackageIndex::try_from_raw(i32::MIN)` already returns `Err(PackageIndexError::ImportIndexUnderflow)` (pinned at `package_index.rs:201-206`); both call sites — `read_primitive_value` (`primitives.rs:397-403`) and `read_element_value` (`containers.rs:163-170`) — map that into `AssetParseFault::PackageIndexUnderflow` BEFORE `resolve_package_index` is invoked. The resolver only sees `PackageIndex::Null | Import(u32) | Export(u32)`; the underflow path is unreachable from inside it.

Also add the two helper constructors used by the tests (these are private test helpers, not test functions themselves — put them before the test functions).

Phase 2a's `ObjectImport` and `ObjectExport` store `object_name` as a `u32` FName index, not a `String`. The helpers below build a small NameTable, then reference its entries by index. `resolve_package_index` will follow these indices through `ctx.names` to produce the resolved string.

> **ObjectExport shape note:** Phase 2a's `ObjectExport` (verified at `export_table.rs:122-186`) carries `package_guid: Option<FGuid>` (the typed wrapper from `crate::asset::guid`, NOT a raw `[u8; 16]`) and includes two `Option<i64>` fields — `script_serialization_start_offset` and `script_serialization_end_offset` — that are required for the struct literal to type-check. Both default to `None` for the synthetic UE 4.27 helper context (UE5 1010+ only).

```rust
#[cfg(test)]
fn make_test_ctx_with_import(import_name: &str) -> AssetContext {
    use std::sync::Arc;
    use crate::asset::{
        import_table::{ImportTable, ObjectImport},
        export_table::ExportTable,
        name_table::{FName, NameTable},
        package_index::PackageIndex,
        version::AssetVersion,
        AssetContext,
    };
    // Names: 0="None", 1="Class", 2="/Script/CoreUObject", 3=<import_name>.
    let names = NameTable {
        names: vec![
            FName::new("None"),
            FName::new("Class"),
            FName::new("/Script/CoreUObject"),
            FName::new(import_name),
        ],
    };
    AssetContext {
        names: Arc::new(names),
        imports: Arc::new(ImportTable {
            imports: vec![ObjectImport {
                class_package_name: 2,
                class_package_number: 0,
                class_name: 1,
                class_name_number: 0,
                outer_index: PackageIndex::Null,
                object_name: 3,
                object_name_number: 0,
                import_optional: None,
            }],
        }),
        exports: Arc::new(ExportTable { exports: vec![] }),
        version: AssetVersion {
            legacy_file_version: -7,
            file_version_ue4: 522,
            file_version_ue5: None,
            file_version_licensee_ue4: 0,
        },
    }
}

#[cfg(test)]
fn make_test_ctx_with_export(export_name: &str) -> AssetContext {
    use std::sync::Arc;
    use crate::asset::{
        export_table::{ExportTable, ObjectExport},
        guid::FGuid,
        import_table::ImportTable,
        name_table::{FName, NameTable},
        package_index::PackageIndex,
        version::AssetVersion,
        AssetContext,
    };
    // Names: 0="None", 1=<export_name>.
    let names = NameTable {
        names: vec![FName::new("None"), FName::new(export_name)],
    };
    AssetContext {
        names: Arc::new(names),
        imports: Arc::new(ImportTable { imports: vec![] }),
        exports: Arc::new(ExportTable {
            exports: vec![ObjectExport {
                class_index: PackageIndex::Null,
                super_index: PackageIndex::Null,
                template_index: PackageIndex::Null,
                outer_index: PackageIndex::Null,
                object_name: 1,
                object_name_number: 0,
                object_flags: 0,
                serial_size: 0,
                serial_offset: 0,
                forced_export: false,
                not_for_client: false,
                not_for_server: false,
                package_guid: Some(FGuid::from_bytes([0u8; 16])),
                is_inherited_instance: None,
                package_flags: 0,
                not_always_loaded_for_editor_game: false,
                is_asset: true,
                generate_public_hash: None,
                script_serialization_start_offset: None,
                script_serialization_end_offset: None,
                first_export_dependency: -1,
                serialization_before_serialization_count: 0,
                create_before_serialization_count: 0,
                serialization_before_create_count: 0,
                create_before_create_count: 0,
            }],
        }),
        version: AssetVersion {
            legacy_file_version: -7,
            file_version_ue4: 522,
            file_version_ue5: None,
            file_version_licensee_ue4: 0,
        },
    }
}
```

> **DRY note:** The 30+-line boilerplate above duplicates `crate::asset::property::test_utils::make_ctx` (defined at `property/test_utils.rs:31`), which already builds an `AssetContext` with empty imports/exports. The Task 2 helpers extend that with one import/export populated. Consider extracting `make_ctx_with_import(name)` / `make_ctx_with_export(name)` into `test_utils.rs` as a shared follow-up if Task 6's tests need similar one-import/one-export contexts — or keep these as Task-2-local helpers since they're the only callers right now. Controller decides.

- [ ] **Step 2: Run tests to confirm compile error**

```bash
cargo test -p paksmith-core --lib asset::property::primitives::tests::resolve_package_index 2>&1 | tail -10
```

Expected: compile error — `resolve_package_index` not found.

- [ ] **Step 3: Add `resolve_package_index`**

Add inside `primitives.rs`, alongside the other `read_*` helpers (before the `#[cfg(test)]` block):

```rust
/// Resolve a typed UE package index to a human-readable object name.
///
/// | `kind`        | Meaning                              | Source            |
/// |---------------|--------------------------------------|-------------------|
/// | `Null`        | Null reference                       | Returns `""`      |
/// | `Import(N)`   | Import reference: `imports[N]`       | `ImportTable`     |
/// | `Export(N)`   | Export reference: `exports[N]`       | `ExportTable`     |
///
/// The `i32::MIN` underflow case is handled at wire-decode time by
/// [`PackageIndex::try_from_raw`] (see `package_index.rs:60`) and surfaced
/// as [`AssetParseFault::PackageIndexUnderflow`] BEFORE this helper runs.
/// That's why the signature takes the already-decoded typed
/// [`PackageIndex`] enum, not a raw `i32`.
///
/// Phase 2a stores `ObjectImport::object_name` and `ObjectExport::object_name`
/// as `u32` FName indices. This helper resolves them through `ctx.names`
/// (and applies the `_N` suffix from `object_name_number`) via the
/// existing [`resolve_fname`](crate::asset::property::tag::resolve_fname)
/// helper from Phase 2b. The resolved name is the BARE `object_name` (e.g.
/// `"StaticMesh"`, `"Hero"`); the helper does NOT synthesize a
/// SoftObjectPath-style `<class_package>.<object_name>` form because
/// `ObjectImport`/`ObjectExport` don't carry a full asset path.
///
/// OOB indices return `PackageIndexOob` with `field: AssetWireField::ObjectPropertyIndex`.
/// `index` is reported as the 0-based table position; `table_size` is the table length.
pub(super) fn resolve_package_index(
    kind: PackageIndex,
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<String> {
    use crate::asset::property::tag::resolve_fname;
    use crate::error::{AssetParseFault, AssetWireField};
    match kind {
        PackageIndex::Null => Ok(String::new()),
        PackageIndex::Import(n) => {
            let idx = n as usize;
            let imp = ctx.imports.imports.get(idx).ok_or_else(|| {
                PaksmithError::AssetParse {
                    asset_path: asset_path.to_string(),
                    fault: AssetParseFault::PackageIndexOob {
                        field: AssetWireField::ObjectPropertyIndex,
                        index: n,
                        table_size: ctx.imports.imports.len() as u32,
                    },
                }
            })?;
            resolve_fname(
                imp.object_name as i32,
                imp.object_name_number as i32,
                ctx,
                asset_path,
                AssetWireField::ObjectPropertyIndex,
            )
        }
        PackageIndex::Export(n) => {
            let idx = n as usize;
            let exp = ctx.exports.exports.get(idx).ok_or_else(|| {
                PaksmithError::AssetParse {
                    asset_path: asset_path.to_string(),
                    fault: AssetParseFault::PackageIndexOob {
                        field: AssetWireField::ObjectPropertyIndex,
                        index: n,
                        table_size: ctx.exports.exports.len() as u32,
                    },
                }
            })?;
            resolve_fname(
                exp.object_name as i32,
                exp.object_name_number as i32,
                ctx,
                asset_path,
                AssetWireField::ObjectPropertyIndex,
            )
        }
    }
}
```

> **Accessor note:** `AssetContext.imports` is `Arc<ImportTable>` and `.exports` is `Arc<ExportTable>`; both deref via `Arc<T> → &T` so `ctx.imports.imports` works directly.

- [ ] **Step 4: Run the resolution tests**

```bash
cargo test -p paksmith-core --lib asset::property::primitives::tests::resolve_package_index
```

Expected: 5 tests pass (the `i32::MIN` underflow test was dropped — that path is unreachable from the resolver post-Group E).

- [ ] **Step 5: Migrate `PropertyValue::Object` and update both read functions**

Find the `PropertyValue::Object` variant definition in `primitives.rs:177-185` (Phase 2d tuple form). Change:

```rust
/// `ObjectProperty` — a hard object reference as a typed
/// [`PackageIndex`].
///
/// The wire is a single `i32` decoded via `PackageIndex::try_from_raw`:
/// `0 → Null`, positive → `Export(n-1)`, negative → `Import(-n-1)`,
/// `i32::MIN` → `AssetParseFault::PackageIndexUnderflow`. Resolution
/// of the index to a named object (walking the import/export table)
/// is deferred to Phase 2e+.
Object(PackageIndex),
```

to:

```rust
/// `ObjectProperty` — a hard object reference with the typed
/// [`PackageIndex`] disambiguator and a resolved name.
///
/// The wire is a single `i32` decoded via `PackageIndex::try_from_raw`
/// (so `kind` preserves the Phase 2d typed shape: `Null`, `Import(N)`,
/// or `Export(N)`; `i32::MIN` is rejected at decode time as
/// `AssetParseFault::PackageIndexUnderflow`). `name` is the resolved
/// `object_name` FName from the import/export table — empty string when
/// `kind == PackageIndex::Null`; bare FName (not a SoftObjectPath
/// `<package>.<object>` form) otherwise. See [`resolve_package_index`].
Object {
    /// Typed package-index discriminator from `PackageIndex::try_from_raw`.
    kind: PackageIndex,
    /// Resolved name string from `resolve_package_index`. Empty for `Null`;
    /// out-of-bounds indices return `AssetParseFault::PackageIndexOob`
    /// rather than synthesizing a fallback string.
    name: String,
},
```

Then in `read_primitive_value`, find the `"ObjectProperty"` arm at `primitives.rs:393-405`:

```rust
"ObjectProperty" => {
    let raw = reader
        .read_i32::<LittleEndian>()
        .map_err(|_| unexpected_eof(asset_path, AssetWireField::ObjectPropertyIndex))?;
    PropertyValue::Object(PackageIndex::try_from_raw(raw).map_err(|_| {
        PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::PackageIndexUnderflow {
                field: AssetWireField::ObjectPropertyIndex,
            },
        }
    })?)
}
```

Replace with:

```rust
"ObjectProperty" => {
    let raw = reader
        .read_i32::<LittleEndian>()
        .map_err(|_| unexpected_eof(asset_path, AssetWireField::ObjectPropertyIndex))?;
    let kind = PackageIndex::try_from_raw(raw).map_err(|_| {
        PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::PackageIndexUnderflow {
                field: AssetWireField::ObjectPropertyIndex,
            },
        }
    })?;
    let name = resolve_package_index(kind, ctx, asset_path)?;
    PropertyValue::Object { kind, name }
}
```

Then in `read_element_value` (containers.rs), find the `"ObjectProperty"` arm at `containers.rs:159-171`:

```rust
"ObjectProperty" => {
    let raw = reader
        .read_i32::<LittleEndian>()
        .map_err(|_| unexpected_eof(asset_path, body_field))?;
    PropertyValue::Object(PackageIndex::try_from_raw(raw).map_err(|_| {
        PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::PackageIndexUnderflow {
                field: AssetWireField::ObjectPropertyIndex,
            },
        }
    })?)
}
```

Replace with:

```rust
"ObjectProperty" => {
    let raw = reader
        .read_i32::<LittleEndian>()
        .map_err(|_| unexpected_eof(asset_path, body_field))?;
    let kind = PackageIndex::try_from_raw(raw).map_err(|_| {
        PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::PackageIndexUnderflow {
                field: AssetWireField::ObjectPropertyIndex,
            },
        }
    })?;
    let name = resolve_package_index(kind, ctx, asset_path)?;
    PropertyValue::Object { kind, name }
}
```

- [ ] **Step 6: Update every pinned test site that asserts on `PropertyValue::Object`**

The migration from `Object(PackageIndex)` (tuple) to `Object { kind, name }` (struct) is observable through the serde JSON shape AND through every `assert_eq!`/`matches!` on the variant. Concrete sites to update:

**Serialization pin tests** (`primitives.rs:732-751`):

The three existing tests assert the Phase 2d tuple shape:

```rust
// primitives.rs:732-737 (current)
fn property_value_object_import_serializes() {
    let v = PropertyValue::Object(PackageIndex::Import(2));
    let json = serde_json::to_string(&v).unwrap();
    assert_eq!(json, r#"{"Object":"Import(2)"}"#);
}
```

After Phase 2e the JSON shape changes to a nested object with `kind` (still a bare `PackageIndex` Display string via `collect_str`) plus `name`. Rewrite each:

```rust
fn property_value_object_import_serializes() {
    let v = PropertyValue::Object {
        kind: PackageIndex::Import(2),
        name: "SomeImport".to_string(),
    };
    let json = serde_json::to_string(&v).unwrap();
    assert_eq!(json, r#"{"Object":{"kind":"Import(2)","name":"SomeImport"}}"#);
}

fn property_value_object_null_serializes() {
    let v = PropertyValue::Object {
        kind: PackageIndex::Null,
        name: String::new(),
    };
    let json = serde_json::to_string(&v).unwrap();
    assert_eq!(json, r#"{"Object":{"kind":"Null","name":""}}"#);
}

fn property_value_object_export_serializes() {
    let v = PropertyValue::Object {
        kind: PackageIndex::Export(1),
        name: "SomeExport".to_string(),
    };
    let json = serde_json::to_string(&v).unwrap();
    assert_eq!(json, r#"{"Object":{"kind":"Export(1)","name":"SomeExport"}}"#);
}
```

**`read_primitive_value` tests** (`primitives.rs:795-823`): `object_property_null_index`, `object_property_import_index`, and `object_property_export_index` all assert the Phase 2d tuple form. Each needs the assertion rewritten to the struct form. For these tests, the existing `ctx` is built via `make_ctx(&["None"])` — i.e., zero imports/zero exports — so the non-null cases will now fail at the OOB check in `resolve_package_index` instead of producing a value. Adjust by EITHER (a) building a context with one import / one export populated so resolution succeeds, asserting the expected resolved name, OR (b) keeping `make_ctx(&["None"])` and asserting the OOB error path instead of an `Ok(PropertyValue)`. Option (a) is consistent with Task 2 Step 1's helpers; pick it.

**`read_element_value` test** (`containers.rs:1490-1504`): `element_object_property_import` similarly asserts the tuple form with an empty-imports ctx. Same fix as above.

**Integration test** (`crates/paksmith-core/tests/extended_types_integration.rs:54-58`): `parse_object_property` currently asserts `PropertyValue::Object(PackageIndex::Import(0))`. The `build_minimal_ue4_27_with_extended_types` fixture (`testing/uasset.rs:973-984`) has one import with `object_name = 2` pointing to FName index 2 = `"Default__Object"`. Update the assertion to:

```rust
assert!(matches!(
    &prop.value,
    PropertyValue::Object {
        kind: PackageIndex::Import(0),
        name,
    } if name == "Default__Object"
));
```

After updating, run `cargo test --workspace --all-features` and let the compiler/test failures identify any sites this enumeration missed.

- [ ] **Step 7: Run all primitives + container tests**

```bash
cargo test -p paksmith-core --lib asset::property
```

Expected: every test in `asset::property::primitives::tests`, `asset::property::containers::tests`, and the integration test in `extended_types_integration.rs` passes.

- [ ] **Step 8: Run workspace fmt, clippy, and rustdoc**

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
```

Expected: all three clean.

- [ ] **Step 9: Commit**

```bash
git add \
  crates/paksmith-core/src/asset/property/primitives.rs \
  crates/paksmith-core/src/asset/property/containers.rs \
  crates/paksmith-core/tests/extended_types_integration.rs
git commit -m "$(cat <<'EOF'
feat(property): resolve ObjectProperty package index to name

PropertyValue::Object migrates from Phase 2d's Object(PackageIndex)
tuple to Object { kind: PackageIndex, name: String }. kind preserves
the typed wire-decode disambiguator; name is the resolved bare
object_name FName from the import/export table.

resolve_package_index maps Null→"", Import(N)→imports[N].object_name,
Export(N)→exports[N].object_name; OOB→PackageIndexOob. The i32::MIN
underflow case is already caught at decode time by
PackageIndex::try_from_raw, so the resolver only sees the three
valid PackageIndex variants.

Both read_primitive_value and read_element_value resolve eagerly.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: `Package::read_from` — companion detection and byte stitching

**Files:**

- Modify: `crates/paksmith-core/src/asset/package.rs`

**Context:** `Package::read_from` currently has signature `(bytes: &[u8], asset_path: &str) -> crate::Result<Self>`. After this task it becomes `(uasset: &[u8], uexp: Option<&[u8]>, asset_path: &str)`. All callers (unit tests inside `package.rs` and integration tests) must be updated.

- [ ] **Step 1: Write failing tests for all four companion states**

Find the `#[cfg(test)]` block in `package.rs` and add:

```rust
#[test]
fn read_from_monolithic_no_uexp_succeeds() {
    // Standard monolithic fixture: all export payloads within total_header_size bytes.
    let pkg = build_minimal_ue4_27();
    let result = Package::read_from(&pkg.bytes, None, "test.uasset");
    assert!(result.is_ok(), "monolithic parse failed: {result:?}");
}

#[test]
fn read_from_split_with_uexp_succeeds() {
    // Split fixture: header bytes + uexp bytes. Stitch and parse.
    let (uasset, uexp) = build_minimal_ue4_27_split();
    let result = Package::read_from(&uasset, Some(&uexp), "test.uasset");
    assert!(result.is_ok(), "split parse failed: {result:?}");
}

#[test]
fn read_from_split_missing_uexp_errors() {
    // Split fixture header with no uexp provided → MissingCompanionFile.
    let (uasset, _uexp) = build_minimal_ue4_27_split();
    let err = Package::read_from(&uasset, None, "test.uasset").unwrap_err();
    assert!(
        matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::MissingCompanionFile {
                    kind: CompanionFileKind::Uexp,
                },
                ..
            }
        ),
        "unexpected error: {err:?}"
    );
}

#[test]
fn read_from_monolithic_with_extra_uexp_warns_and_succeeds() {
    // Monolithic fixture (no export needs .uexp) but we pass Some(uexp) anyway.
    // Should warn and succeed (no error).
    let pkg = build_minimal_ue4_27();
    let dummy_uexp: Vec<u8> = vec![0xDE, 0xAD]; // arbitrary extra bytes
    let result = Package::read_from(&pkg.bytes, Some(&dummy_uexp), "test.uasset");
    // The warn-and-ignore path: result should be Ok.
    assert!(result.is_ok(), "extra-uexp warn path failed: {result:?}");
}
```

> **Note:** `build_minimal_ue4_27_split` is added in Task 5. These tests will fail at compile time until that task is done. The pattern is: write the tests here (Task 3), implement the API change here, stub `build_minimal_ue4_27_split` temporarily if needed.
>
> **Temporary stub:** If Task 5 hasn't landed yet, add at the top of the `#[cfg(test)]` block:
>
> ```rust
> // Temporary stub until Task 5 implements the real split builder.
> fn build_minimal_ue4_27_split() -> (Vec<u8>, Vec<u8>) {
>     let pkg = build_minimal_ue4_27();
>     let split_at = pkg.total_header_size;
>     (pkg.bytes[..split_at].to_vec(), pkg.bytes[split_at..].to_vec())
> }
> ```
>
> Remove this stub after Task 5 lands (it duplicates the real implementation).

- [ ] **Step 2: Update `read_from` signature**

Find `pub fn read_from` in `impl Package`. Change its signature from:

```rust
pub fn read_from(bytes: &[u8], asset_path: &str) -> crate::Result<Self> {
```

to:

```rust
pub fn read_from(uasset: &[u8], uexp: Option<&[u8]>, asset_path: &str) -> crate::Result<Self> {
```

At the top of the function body, add the byte stitching logic:

Add a structural cap on the `.uexp` size — without it, a malicious pak entry could supply a multi-GiB `.uexp` slice that paksmith concatenates into a buffer twice its size:

```rust
/// Hard cap on the `.uexp` companion file size. `total_header_size`
/// already caps the `.uasset` at 256 MiB; the export-body section in
/// `.uexp` is typically smaller. 1 GiB is generous headroom; bigger
/// would already be suspicious for an UE-cooked asset.
pub const MAX_UEXP_SIZE: usize = 1024 * 1024 * 1024;
```

Then in `Package::read_from`:

```rust
    // Stitch .uasset and optional .uexp into one contiguous buffer.
    // For monolithic assets (uexp = None), borrow uasset directly (zero-copy).
    let combined_owned: Vec<u8>;
    let bytes: &[u8] = match uexp {
        Some(uexp_data) => {
            // Cap the .uexp size before allocating a combined buffer
            // sized to `uasset.len() + uexp_data.len()`. Without this
            // guard a malicious pak entry could force a multi-GiB
            // allocation by claiming a huge .uexp payload.
            if uexp_data.len() > MAX_UEXP_SIZE {
                return Err(PaksmithError::AssetParse {
                    asset_path: asset_path.to_string(),
                    fault: AssetParseFault::BoundsExceeded {
                        field: AssetWireField::UexpSize,
                        value: uexp_data.len() as u64,
                        limit: MAX_UEXP_SIZE as u64,
                        unit: BoundsUnit::Bytes,
                    },
                });
            }
            // Defensive: use try_reserve_exact so an OOM here surfaces
            // as a typed error instead of aborting the process.
            let total = uasset.len()
                .checked_add(uexp_data.len())
                .ok_or_else(|| PaksmithError::AssetParse {
                    asset_path: asset_path.to_string(),
                    fault: AssetParseFault::U64ArithmeticOverflow {
                        operation: AssetOverflowSite::SplitAssetConcatExtent,
                    },
                })?;
            let mut buf: Vec<u8> = Vec::new();
            buf.try_reserve_exact(total).map_err(|source| PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::AllocationFailed {
                    context: AssetAllocationContext::SplitAssetCombined,
                    requested: total,
                    source,
                },
            })?;
            buf.extend_from_slice(uasset);
            buf.extend_from_slice(uexp_data);
            combined_owned = buf;
            &combined_owned
        }
        None => uasset,
    };
    let mut reader = Cursor::new(bytes);
```

> **Shape contracts** — verified against `crates/paksmith-core/src/error.rs`:
>
> - `AssetParseFault::BoundsExceeded` has FOUR fields: `field`, `value`, `limit`, `unit: BoundsUnit` (see `error.rs:2184-2193`). Construct sites MUST set `unit`; the manual Display arm at `error.rs:2440-2447` consumes it. Import `BoundsUnit` from `crate::error` (already in the use list at `package.rs:30`).
> - `AssetParseFault::AllocationFailed` has THREE fields: `context`, `requested`, `source` (see `error.rs:2290-2299`). Do NOT add a `unit` field — the Display arm at `error.rs:2477-2485` derives the unit from `context.unit()` via [`AssetAllocationContext::unit`]. Adding a literal `unit:` field to the struct literal will not compile.
>
> Remove the old `let mut reader = Cursor::new(bytes);` line that the function previously used.

This step also requires three new error-enum variants. Each is gated as its own sub-step so the pin tables and Display arms can't be forgotten:

- [ ] **Step 2a: Add `AssetWireField::UexpSize`**

In `error.rs`:

1. Add the variant to `pub enum AssetWireField` (the enum starts at `error.rs:2547`). Place it after `ObjectPropertyIndex` (the last Phase 2d addition):

   ```rust
   /// Byte size of the `.uexp` companion file slice passed to
   /// [`Package::read_from`]. Capped by `MAX_UEXP_SIZE` at the stitch
   /// boundary; oversized values surface as `BoundsExceeded` before
   /// any allocation runs.
   UexpSize,
   ```

2. Add the Display arm to `impl fmt::Display for AssetWireField` (the match at `error.rs:2672-2731`). Place after the matching position in the enum:

   ```rust
   Self::UexpSize => "uexp_size",
   ```

3. Extend the pin test `asset_wire_field_display_tokens_are_wire_stable` (`error.rs:~4718-4810`) with a new row:

   ```rust
   (AssetWireField::UexpSize, "uexp_size"),
   ```

- [ ] **Step 2b: Add `AssetOverflowSite::SplitAssetConcatExtent`**

In `error.rs`:

1. Add the variant to `pub enum AssetOverflowSite` (`error.rs:2738`):

   ```rust
   /// `uasset.len() + uexp.len()` overflowed during the Phase 2e
   /// companion-file stitch.
   SplitAssetConcatExtent,
   ```

2. Add the Display arm to `impl fmt::Display for AssetOverflowSite` (`error.rs:2749`):

   ```rust
   Self::SplitAssetConcatExtent => "split-asset concat extent computation",
   ```

3. Extend the pin test `asset_overflow_site_display_tokens_are_wire_stable` (`error.rs:~4817-4839`) with:

   ```rust
   (
       AssetOverflowSite::SplitAssetConcatExtent,
       "split-asset concat extent computation",
   ),
   ```

- [ ] **Step 2c: Add `AssetAllocationContext::SplitAssetCombined`**

In `error.rs`:

1. Add the variant to `pub enum AssetAllocationContext` (`error.rs:2807`):

   ```rust
   /// `Vec<u8>` for the concatenated `.uasset` + `.uexp` buffer built
   /// in [`Package::read_from`] for split assets.
   SplitAssetCombined,
   ```

2. Add the variant to the `impl AssetAllocationContext::unit()` match at `error.rs:2837-2849` — it's a byte buffer, so it returns `BoundsUnit::Bytes`. Add it to the `Bytes` arm:

   ```rust
   Self::ExportPayloadBytes
   | Self::UnknownPropertyBytes
   | Self::UnknownFTextBytes
   | Self::SplitAssetCombined => BoundsUnit::Bytes,
   ```

3. Add the Display arm to `impl fmt::Display for AssetAllocationContext` (`error.rs:2853`):

   ```rust
   Self::SplitAssetCombined => "combined .uasset+.uexp buffer",
   ```

4. Extend the pin test `asset_allocation_context_display_tokens_are_wire_stable` (`error.rs:~4846-4877`) with:

   ```rust
   (
       AssetAllocationContext::SplitAssetCombined,
       "combined .uasset+.uexp buffer",
   ),
   ```

5. Extend the unit-mapping pin test `asset_allocation_context_unit_mapping_is_pinned` (`error.rs:~4883`) so the new variant's `unit()` is also pinned.

- [ ] **Step 3: Add the four-state companion detection**

After the export table has been parsed (after `let exports = ExportTable::read_from(&mut reader, &summary, &names, asset_path)?;`), add:

```rust
    // Four-state companion detection.
    let needs_uexp = exports
        .exports
        .iter()
        .any(|e| e.serial_offset >= i64::from(summary.total_header_size));

    if needs_uexp && uexp.is_none() {
        return Err(PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::MissingCompanionFile {
                kind: crate::error::CompanionFileKind::Uexp,
            },
        });
    }

    if !needs_uexp && uexp.is_some() {
        tracing::warn!(
            asset_path = asset_path,
            "'.uexp' companion bytes provided but no export has serial_offset \
             >= total_header_size ({}); ignoring companion",
            summary.total_header_size
        );
    }

    // Verify the load-bearing invariant: when split, the `.uasset` file
    // contains exactly the header bytes (everything before the export
    // payload region). UE writes split assets with this layout by
    // convention, but a pathological writer could break it (e.g. by
    // appending AssetRegistryData past `total_header_size` in `.uasset`).
    // If `uasset.len() != total_header_size`, then `serial_offset` —
    // which points into the logical full-asset byte stream — does NOT
    // index naturally into `[uasset || uexp]`. Fire a clear error
    // instead of silently misparsing.
    if needs_uexp && uasset.len() as i64 != i64::from(summary.total_header_size) {
        return Err(PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::SplitAssetSizeMismatch {
                uasset_len: uasset.len(),
                total_header_size: summary.total_header_size,
            },
        });
    }
```

> **New error variant** — add to `error.rs`. As noted in Task 1, `AssetParseFault` uses a hand-rolled `impl fmt::Display` (not `thiserror`-derived), so the `#[error("...")]` attribute is silently ignored. Add the variant + a Display arm separately.
>
> Variant (place after `MissingCompanionFile` from Task 1):
>
> ```rust
> /// A split asset's `.uasset` file does not have length equal to
> /// `total_header_size`. Phase 2e's `[uasset || uexp]` concatenation
> /// relies on this UE-convention invariant; pathological writers that
> /// embed trailing data in `.uasset` after the header region would
> /// produce misaligned serial offsets.
> SplitAssetSizeMismatch {
>     uasset_len: usize,
>     total_header_size: i32,
> },
> ```
>
> Display arm — add to `impl fmt::Display for AssetParseFault` (`error.rs:2403`) after the `MissingCompanionFile` arm:
>
> ```rust
> Self::SplitAssetSizeMismatch {
>     uasset_len,
>     total_header_size,
> } => write!(
>     f,
>     "split-asset size invariant violated: uasset length {uasset_len} \
>      != total_header_size {total_header_size}"
> ),
> ```

- [ ] **Step 4: Update all existing callers of `Package::read_from`**

Update each occurrence by adding `None` as the second argument and shifting `asset_path` to third (`Package::read_from(&bytes, virtual_path)` → `Package::read_from(&bytes, None, virtual_path)`). Known call sites (enumerated; re-run the grep before editing to catch any added since this plan was written):

```bash
grep -rn 'Package::read_from(' crates/
```

Expected sites:

- `crates/paksmith-core/src/asset/package.rs:357` — the `read_from_pak` body calls `Self::read_from(&bytes, virtual_path)`. Update to `Self::read_from(&bytes, None, virtual_path)` here (Task 4 will replace the `None` with real `.uexp` bytes).
- `crates/paksmith-core/src/asset/package.rs` unit tests at approx lines 501, 514, 561, 581, 595, 636 (`#[cfg(test)] mod tests`).
- `crates/paksmith-core/src/asset/mod.rs` header round-trip tests at approx lines 117 and 138.
- `crates/paksmith-core/tests/extended_types_integration.rs` — calls `Package::read_from` for the property-decode round-trip.
- Any other crate-test file that calls `Package::read_from` (run the grep to confirm).
- `crates/paksmith-fixture-gen/src/uasset.rs:644, 703, ...` — the `write_minimal_ue4_27_with_*` self-tests call `Package::read_from(&bytes, path)`.

> **Tip:** The compiler will identify every call site that doesn't match the new arity. Fix them one by one rather than doing a blind search-replace — sites in fixture-gen pass a `&str` from a `to_string_lossy()` and the borrow lifetime matters.

- [ ] **Step 5: Run the four-state tests**

```bash
cargo test -p paksmith-core --lib asset::package::tests
```

Expected: all four new tests pass plus all pre-existing `package::tests` pass.

- [ ] **Step 6: Run full test suite**

```bash
cargo test --workspace --all-features
```

Expected: no regressions. The call-site updates in Step 4 should cover all breaks.

- [ ] **Step 7: Run workspace fmt, clippy, and rustdoc**

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
```

Expected: all three clean.

- [ ] **Step 8: Commit**

```bash
git add crates/paksmith-core/src/asset/package.rs crates/paksmith-core/src/error.rs
git commit -m "$(cat <<'EOF'
feat(asset): Package::read_from accepts optional .uexp companion bytes

Signature change: read_from(uasset, uexp: Option<&[u8]>, path).
Stitches header + uexp before parsing (zero-copy for monolithic).
Four-state companion detection: missing-uexp errors with
MissingCompanionFile; extra-uexp warns via tracing::warn! and proceeds.

Adds AssetParseFault::SplitAssetSizeMismatch for the
uasset.len() != total_header_size invariant violation case, plus
AssetWireField::UexpSize, AssetOverflowSite::SplitAssetConcatExtent,
and AssetAllocationContext::SplitAssetCombined for the new error
construction sites.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: `Package::read_from_pak` — companion file lookup

**Files:**

- Modify: `crates/paksmith-core/src/asset/package.rs`

- [ ] **Step 1: Write a failing integration test for the split-pak round-trip**

Add to `package.rs` tests (or to `tests/asset_integration.rs` — whichever hosts the `read_from_pak` round-trip tests from Phase 2a Task 15). This test uses the split fixture pak generated in Task 5. Write it now so Task 5 has a target:

```rust
#[test]
fn read_from_pak_split_asset_round_trip() {
    // Depends on tests/fixtures/real_v8b_split.pak produced by fixture-gen (Task 5).
    // The split pak has Game/Maps/Demo.uasset (header only) and Game/Maps/Demo.uexp (payload).
    let pak = std::path::Path::new(
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/real_v8b_split.pak")
    );
    // Skip if fixture not yet generated.
    if !pak.exists() {
        eprintln!("skipping: real_v8b_split.pak not yet generated");
        return;
    }
    let pkg = Package::read_from_pak(pak, "Game/Maps/Demo.uasset")
        .expect("split asset parse failed");
    // `Package` exposes direct `pub` fields (see `package.rs:60-78`); there
    // are no `.exports()` / `.export_properties()` accessor methods.
    assert!(!pkg.exports.exports.is_empty());
}
```

Run to confirm it compiles but skips (fixture doesn't exist yet):

```bash
cargo test -p paksmith-core --test asset_integration read_from_pak_split_asset_round_trip 2>&1 | tail -10
```

Expected: test runs and prints "skipping" (or compiles and skips).

- [ ] **Step 2: Add `derive_companion_path`**

Inside `crates/paksmith-core/src/asset/package.rs`, above `impl Package`, add:

```rust
/// Derive a companion file path from an asset path by swapping the extension.
///
/// `"Game/Weapon/Sword.uasset"` + `".uexp"` → `"Game/Weapon/Sword.uexp"`.
/// If `base` does not end in `.uasset`, appends `new_ext` directly (should
/// not happen for well-formed pak entries but avoids panics on edge inputs).
pub(super) fn derive_companion_path(base: &str, new_ext: &str) -> String {
    match base.strip_suffix(".uasset") {
        Some(stem) => format!("{stem}{new_ext}"),
        None => format!("{base}{new_ext}"),
    }
}
```

Add a unit test immediately after (in the `#[cfg(test)]` block):

```rust
#[test]
fn derive_companion_path_strips_uasset() {
    assert_eq!(
        derive_companion_path("Game/Weapon/Sword.uasset", ".uexp"),
        "Game/Weapon/Sword.uexp"
    );
}

#[test]
fn derive_companion_path_non_uasset_appends() {
    assert_eq!(
        derive_companion_path("Game/raw", ".uexp"),
        "Game/raw.uexp"
    );
}
```

Run:

```bash
cargo test -p paksmith-core --lib asset::package::tests::derive_companion_path 2>&1 | tail -10
```

Expected: 2 tests pass.

- [ ] **Step 3: Update `read_from_pak` to look up companions**

Find the current `read_from_pak` implementation (post-Task-3: Task 3 Step 4 already updated this body to pass `None` to the new 3-arg `read_from`). The pre-Phase-2e baseline at `package.rs:350` is:

```rust
pub fn read_from_pak<P: AsRef<std::path::Path>>(
    pak_path: P,
    virtual_path: &str,
) -> crate::Result<Self> {
    use crate::container::ContainerReader;
    let reader = crate::container::pak::PakReader::open(pak_path)?;
    let bytes = reader.read_entry(virtual_path)?;
    Self::read_from(&bytes, virtual_path)  // 2-arg pre-Phase-2e
}
```

After Task 3 it reads (this is the version Task 4 mutates):

```rust
pub fn read_from_pak<P: AsRef<std::path::Path>>(
    pak_path: P,
    virtual_path: &str,
) -> crate::Result<Self> {
    use crate::container::ContainerReader;
    let pak = crate::container::pak::PakReader::open(pak_path)?;
    let bytes = pak.read_entry(virtual_path)?;
    Self::read_from(&bytes, None, virtual_path)
}
```

Replace with:

```rust
pub fn read_from_pak<P: AsRef<std::path::Path>>(
    pak_path: P,
    virtual_path: &str,
) -> crate::Result<Self> {
    use crate::container::ContainerReader;
    let pak = crate::container::pak::PakReader::open(pak_path)?;

    let uasset_bytes = pak.read_entry(virtual_path)?;

    // Look up .uexp companion (absent for monolithic assets).
    let uexp_path = derive_companion_path(virtual_path, ".uexp");
    let uexp_bytes = match pak.read_entry(&uexp_path) {
        Ok(b) => Some(b),
        Err(PaksmithError::EntryNotFound { .. }) => None,
        Err(e) => return Err(e),
    };

    // Detect .ubulk; not stitched in Phase 2e.
    let ubulk_path = derive_companion_path(virtual_path, ".ubulk");
    if pak.read_entry(&ubulk_path).is_ok() {
        tracing::warn!(
            asset_path = virtual_path,
            ".ubulk companion found but bulk data stitching is not yet supported; \
             bulk data will be absent from the parsed asset"
        );
    }

    Self::read_from(&uasset_bytes, uexp_bytes.as_deref(), virtual_path)
}
```

- [ ] **Step 4: Run tests**

```bash
cargo test --workspace --all-features
```

Expected: no regressions. The split-pak round-trip test still skips (fixture not yet generated).

- [ ] **Step 5: Run workspace fmt, clippy, and rustdoc**

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
```

Expected: all three clean.

- [ ] **Step 6: Commit**

```bash
git add crates/paksmith-core/src/asset/package.rs
git commit -m "$(cat <<'EOF'
feat(asset): read_from_pak loads .uexp and detects .ubulk companion

Looks up <stem>.uexp from the pak; EntryNotFound→None (monolithic),
other errors propagate. Passes uexp bytes to read_from for stitching.
Detects .ubulk and emits tracing::warn; stitching deferred to Phase 2f.
derive_companion_path strips .uasset and appends the new extension.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: Split-asset fixture builder and fixture-gen oracle cross-validation

**Files:**

- Modify: `crates/paksmith-core/src/testing/uasset.rs`
- Modify: `crates/paksmith-fixture-gen/src/uasset.rs`

**Output artifact:** `tests/fixtures/real_v8b_split.pak`

- [ ] **Step 1: Extend `MinimalPackage` with `total_header_size`**

`MinimalPackage` in `testing/uasset.rs:65-94` is an 8-field struct (`bytes`, `summary`, `names`, `imports`, `exports`, `payload`, `payloads`, `package_flags_offset`) — do NOT replace it with a 2-field shape. ADD `total_header_size: usize` as the 9th field:

```rust
pub struct MinimalPackage {
    pub bytes: Vec<u8>,
    pub summary: PackageSummary,
    pub names: NameTable,
    pub imports: ImportTable,
    pub exports: ExportTable,
    pub payload: Vec<u8>,
    pub payloads: Vec<Vec<u8>>,
    pub package_flags_offset: usize,
    /// Byte length of the header portion (= `summary.total_header_size`).
    /// Used by `build_minimal_ue4_27_split` to cut bytes at the right
    /// boundary between `.uasset` header and `.uexp` payload region.
    pub total_header_size: usize,
}
```

`build_minimal` (`testing/uasset.rs:263`) is the single construction site (the named-field builders `build_minimal_ue4_27`, `build_minimal_ue4_27_with_properties`, etc. all delegate to it). At the `MinimalPackage { ... }` literal around `testing/uasset.rs:467-476`, add the new field:

```rust
MinimalPackage {
    bytes,
    summary,
    names,
    imports,
    exports,
    payload: payload_first,
    payloads,
    package_flags_offset,
    total_header_size: summary.total_header_size as usize,
}
```

Watch for `summary` having been moved into the struct — capture `total_header_size` BEFORE constructing the literal (`let total_header_size = summary.total_header_size as usize;`) if rustc complains about move-after-borrow.

Run to verify no regressions:

```bash
cargo test --workspace --all-features
```

Expected: all tests pass. Any code that destructures `MinimalPackage` exhaustively (e.g. `MinimalPackage { bytes, .. }` is fine; full-field destructuring would break) needs the new field added.

- [ ] **Step 2: Write a failing test for `build_minimal_ue4_27_split`**

Add to `testing/uasset.rs`'s test block:

```rust
#[test]
fn split_plus_monolithic_produce_identical_parse() {
    use crate::asset::Package;

    let monolithic = build_minimal_ue4_27();
    let (uasset, uexp) = build_minimal_ue4_27_split();

    // Both forms should parse to an equivalent package.
    let pkg_mono = Package::read_from(&monolithic.bytes, None, "test.uasset")
        .expect("monolithic parse failed");
    let pkg_split = Package::read_from(&uasset, Some(&uexp), "test.uasset")
        .expect("split parse failed");

    // Structural equivalence: same number of exports, same export names.
    // `Package` exposes direct pub fields (`package.rs:60-78`); no accessor.
    assert_eq!(pkg_mono.exports.exports.len(), pkg_split.exports.exports.len());
    for (m, s) in pkg_mono.exports.exports.iter().zip(pkg_split.exports.exports.iter()) {
        assert_eq!(m.object_name, s.object_name);
    }
}
```

Run to confirm it fails (function not found):

```bash
cargo test -p paksmith-core --lib testing::uasset::tests::split_plus_monolithic_produce_identical_parse 2>&1 | tail -10
```

Expected: compile error — `build_minimal_ue4_27_split` not found.

- [ ] **Step 3: Implement `build_minimal_ue4_27_split`**

Add to `testing/uasset.rs`. The whole `testing` module is `#[cfg(feature = "__test_utils")]`-gated in `lib.rs:37-38`, so per-function `#[cfg]` attributes are redundant — match the existing siblings (`build_minimal_ue4_27`, `build_minimal_ue4_27_with_properties` at `testing/uasset.rs:497, 592`) which use `#[must_use]` only:

```rust
/// Returns `(uasset_header_bytes, uexp_payload_bytes)` — the split form of the
/// standard Phase 2a minimal fixture.
///
/// `uasset_header_bytes.len() == pkg.total_header_size`. The two slices
/// concatenated produce identical bytes to `build_minimal_ue4_27().bytes`, so
/// parsing `read_from(uasset, Some(uexp), _)` gives the same result as
/// `read_from(&full, None, _)`.
#[must_use]
pub fn build_minimal_ue4_27_split() -> (Vec<u8>, Vec<u8>) {
    let pkg = build_minimal_ue4_27();
    let split_at = pkg.total_header_size;
    debug_assert!(
        split_at <= pkg.bytes.len(),
        "total_header_size {split_at} > bytes.len() {} — builder bug",
        pkg.bytes.len()
    );
    (pkg.bytes[..split_at].to_vec(), pkg.bytes[split_at..].to_vec())
}
```

- [ ] **Step 4: Run the equivalence test**

```bash
cargo test -p paksmith-core --lib testing::uasset::tests::split_plus_monolithic_produce_identical_parse
```

Expected: PASS.

- [ ] **Step 5: Add split fixture generation to `paksmith-fixture-gen`**

Mirror the established pattern at `crates/paksmith-fixture-gen/src/uasset.rs:816-873` (the `write_minimal_pak_with_uasset` writer for `real_v8b_uasset.pak`). The current `repak` API uses `PakBuilder::new().writer(file, Version::V8B, MOUNT_POINT.to_string(), None)` to get a writer, then `writer.write_file(virtual_path, false, &bytes)` for each entry, then `writer.write_index()` — NOT the older `add_entry().write()` form. Add a new writer `write_minimal_pak_with_split_uasset` modeled on the existing one, then wire it into `main.rs` alongside the other fixture writers (look at how `write_minimal_pak_with_uasset` is called).

```rust
/// Write `tests/fixtures/real_v8b_split.pak` — a pak with two entries:
/// - `Game/Maps/Demo.uasset` (header bytes only)
/// - `Game/Maps/Demo.uexp`   (export payload bytes only)
///
/// Cross-validates the split form against `unreal_asset` using its
/// `Asset::new(asset_data, Some(bulk_data), ...)` two-reader API, which
/// is the discriminating check that proves paksmith's concat-and-seek
/// layout assumption matches the reference implementation.
pub fn write_minimal_pak_with_split_uasset(path: &Path) -> anyhow::Result<()> {
    use paksmith_core::testing::uasset::build_minimal_ue4_27_split;

    let (uasset_bytes, uexp_bytes) = build_minimal_ue4_27_split();

    // Cross-validate with unreal_asset before writing the fixture.
    cross_validate_split_with_unreal_asset(&uasset_bytes, &uexp_bytes)?;

    // Atomic write via .tmp + rename, mirroring `write_minimal_pak_with_uasset`.
    let tmp = path.with_file_name(format!(
        "{}.tmp",
        path.file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| anyhow::anyhow!("path has no filename: {}", path.display()))?
    ));
    {
        let file = File::create(&tmp)?;
        let mut writer =
            PakBuilder::new().writer(file, Version::V8B, super::MOUNT_POINT.to_string(), None);
        writer
            .write_file("Game/Maps/Demo.uasset", false, &uasset_bytes)
            .map_err(|e| anyhow::anyhow!("repak write_file uasset: {e}"))?;
        writer
            .write_file("Game/Maps/Demo.uexp", false, &uexp_bytes)
            .map_err(|e| anyhow::anyhow!("repak write_file uexp: {e}"))?;
        let _ = writer
            .write_index()
            .map_err(|e| anyhow::anyhow!("repak write_index: {e}"))?;
    }
    fs::rename(&tmp, path)?;

    // Self-test: re-open and assert both entries are present.
    let mut reader_file = File::open(path)?;
    let pak_reader = PakBuilder::new()
        .reader(&mut reader_file)
        .map_err(|e| anyhow::anyhow!("repak reader: {e}"))?;
    let files = pak_reader.files();
    anyhow::ensure!(
        files.len() == 2,
        "expected 2 entries in {}, got {}",
        path.display(),
        files.len()
    );
    anyhow::ensure!(
        files.iter().any(|f| f == "Game/Maps/Demo.uasset"),
        "missing .uasset entry"
    );
    anyhow::ensure!(
        files.iter().any(|f| f == "Game/Maps/Demo.uexp"),
        "missing .uexp entry"
    );
    Ok(())
}

fn cross_validate_split_with_unreal_asset(
    uasset_bytes: &[u8],
    uexp_bytes: &[u8],
) -> anyhow::Result<()> {
    use std::io::Cursor;
    use unreal_asset::engine_version::EngineVersion;
    use unreal_asset::Asset;

    // unreal_asset's Asset::new takes: asset_data reader, optional bulk_data reader
    // (.uexp), engine version, optional .usmap mappings.
    let asset = Asset::new(
        Cursor::new(uasset_bytes.to_vec()),
        Some(Cursor::new(uexp_bytes.to_vec())),
        EngineVersion::VER_UE4_27,
        None,
    )
    .map_err(|e| anyhow::anyhow!("unreal_asset split parse failed: {e}"))?;

    let name_count = asset.get_name_map().get_ref().get_name_map_index_list().len();
    anyhow::ensure!(
        name_count == 3,
        "unreal_asset saw {name_count} names in split fixture; expected 3"
    );
    anyhow::ensure!(
        asset.imports.len() == 1,
        "unreal_asset saw {} imports in split fixture; expected 1",
        asset.imports.len()
    );
    anyhow::ensure!(
        asset.asset_data.exports.len() == 1,
        "unreal_asset saw {} exports in split fixture; expected 1",
        asset.asset_data.exports.len()
    );

    // Also verify the monolithic concat form gives the same result.
    let combined: Vec<u8> = [uasset_bytes, uexp_bytes].concat();
    let asset_concat = Asset::new(
        Cursor::new(combined),
        None, // monolithic — no separate bulk_data
        EngineVersion::VER_UE4_27,
        None,
    )
    .map_err(|e| anyhow::anyhow!("unreal_asset concat-form parse failed: {e}"))?;

    anyhow::ensure!(
        asset_concat.asset_data.exports.len() == asset.asset_data.exports.len(),
        "split form and concat form export counts differ"
    );

    Ok(())
}
```

Call `write_minimal_pak_with_split_uasset` from `main.rs` alongside the existing fixture writers (look at how `write_minimal_pak_with_uasset` is invoked). The output goes to `tests/fixtures/real_v8b_split.pak` (paksmith's standard fixture path).

- [ ] **Step 6: Regenerate fixtures**

```bash
cargo run -p paksmith-fixture-gen
```

Expected: a line for the new fixture printed. File exists at `tests/fixtures/real_v8b_split.pak`. Confirm:

```bash
ls -lh tests/fixtures/real_v8b_split.pak
```

Expected: file exists, reasonable size (< 1 KB for the synthetic fixture).

- [ ] **Step 7: Re-run the split round-trip test (no longer skips)**

```bash
cargo test -p paksmith-core --test asset_integration read_from_pak_split_asset_round_trip
```

Expected: PASS (no longer skips).

- [ ] **Step 8: Run full test suite + fmt + clippy + rustdoc**

```bash
cargo test --workspace --all-features
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
```

Expected: all clean.

- [ ] **Step 9: Commit**

```bash
git add \
  crates/paksmith-core/src/testing/uasset.rs \
  crates/paksmith-fixture-gen/src/uasset.rs \
  crates/paksmith-fixture-gen/src/main.rs \
  tests/fixtures/real_v8b_split.pak
git commit -m "$(cat <<'EOF'
feat(fixture): split-asset fixture + unreal_asset oracle cross-validation

build_minimal_ue4_27_split() splits the monolithic Phase 2a fixture at
total_header_size into (uasset_header, uexp_payload). MinimalPackage
gains a total_header_size field for the split (added as the 9th
field; the struct's existing 8 fields are preserved).

fixture-gen writes real_v8b_split.pak with two entries
(Game/Maps/Demo.uasset + Game/Maps/Demo.uexp) and cross-validates:
  - unreal_asset's two-reader form (Asset::new(asset, Some(uexp), ...))
  - unreal_asset's concat-monolithic form
both must agree, proving paksmith's layout assumption.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 6: Integration tests — all four companion states + ObjectProperty resolution

**Files:**

- Create: `crates/paksmith-core/tests/companion_integration.rs`

- [ ] **Step 1: Write all six tests**

Create `crates/paksmith-core/tests/companion_integration.rs`:

```rust
//! Integration tests for Phase 2e: companion file loading and
//! ObjectProperty resolution.

use paksmith_core::asset::Package;
use paksmith_core::asset::package_index::PackageIndex;
use paksmith_core::asset::property::PropertyBag;
use paksmith_core::error::{AssetParseFault, CompanionFileKind, PaksmithError};

// ── Companion file states ────────────────────────────────────────────────────

/// State 1: monolithic asset (no .uexp), no export outside total_header_size.
#[test]
fn monolithic_asset_parses_without_uexp() {
    use paksmith_core::testing::uasset::build_minimal_ue4_27;
    let pkg = build_minimal_ue4_27();
    let result = Package::read_from(&pkg.bytes, None, "test.uasset");
    assert!(result.is_ok(), "{result:?}");
}

/// State 2: split asset, .uasset header + .uexp payload both provided.
#[test]
fn split_asset_stitches_and_parses() {
    use paksmith_core::testing::uasset::build_minimal_ue4_27_split;
    let (uasset, uexp) = build_minimal_ue4_27_split();
    let result = Package::read_from(&uasset, Some(&uexp), "test.uasset");
    assert!(result.is_ok(), "{result:?}");
    let pkg = result.unwrap();
    // `Package` exposes direct pub fields (`package.rs:60-78`); no accessor.
    assert!(!pkg.exports.exports.is_empty());
}

/// State 3: split asset header, .uexp not provided → MissingCompanionFile.
#[test]
fn split_asset_without_uexp_errors() {
    use paksmith_core::testing::uasset::build_minimal_ue4_27_split;
    let (uasset, _uexp) = build_minimal_ue4_27_split();
    let err = Package::read_from(&uasset, None, "Game/Sword.uasset").unwrap_err();
    assert!(
        matches!(
            &err,
            PaksmithError::AssetParse {
                asset_path,
                fault: AssetParseFault::MissingCompanionFile {
                    kind: CompanionFileKind::Uexp,
                },
            } if asset_path == "Game/Sword.uasset"
        ),
        "unexpected error variant: {err:?}"
    );
}

/// State 4: monolithic asset (no export needs .uexp), but .uexp bytes provided.
/// Should warn and succeed.
#[test]
fn monolithic_with_excess_uexp_succeeds() {
    use paksmith_core::testing::uasset::build_minimal_ue4_27;
    let pkg = build_minimal_ue4_27();
    let dummy_uexp = vec![0xFF, 0xFE]; // irrelevant extra bytes
    let result = Package::read_from(&pkg.bytes, Some(&dummy_uexp), "test.uasset");
    assert!(result.is_ok(), "{result:?}");
}

// ── ObjectProperty resolution ────────────────────────────────────────────────

/// ObjectProperty with wire i32 = -1 (PackageIndex::Import(0)) resolves to
/// the first import's bare object_name.
#[test]
fn object_property_resolves_import_name() {
    use paksmith_core::asset::property::primitives::PropertyValue;
    use paksmith_core::testing::uasset::build_minimal_ue4_27_with_object_ref;

    // build_minimal_ue4_27_with_object_ref returns (bytes, expected_name).
    // The fixture has one import (object_name = expected_name) and one
    // ObjectProperty ("ObjRef") with wire i32 = -1 → PackageIndex::Import(0).
    let (pkg_bytes, expected_name) = build_minimal_ue4_27_with_object_ref();
    let pkg = Package::read_from(&pkg_bytes, None, "test.uasset").unwrap();

    // `Package.exports` and `Package.payloads` are direct pub fields; payloads[i]
    // is a PropertyBag aligned with exports.exports[i].
    let bag = &pkg.payloads[0];
    let props = match bag {
        PropertyBag::Tree { properties } => properties,
        PropertyBag::Opaque { .. } => panic!("expected PropertyBag::Tree, got Opaque"),
        other => panic!("unexpected PropertyBag variant: {other:?}"),
    };
    let obj_prop = props
        .iter()
        .find(|p| p.name == "ObjRef")
        .expect("ObjRef property not found");

    assert!(
        matches!(
            &obj_prop.value,
            PropertyValue::Object {
                kind: PackageIndex::Import(0),
                name,
            } if name == &expected_name
        ),
        "unexpected value: {:?}",
        obj_prop.value
    );
}

/// ObjectProperty with wire i32 = 0 (PackageIndex::Null) resolves to "".
#[test]
fn object_property_null_index_resolves_empty() {
    use paksmith_core::asset::property::primitives::PropertyValue;
    use paksmith_core::testing::uasset::build_minimal_ue4_27_with_null_object_ref;

    let pkg_bytes = build_minimal_ue4_27_with_null_object_ref();
    let pkg = Package::read_from(&pkg_bytes, None, "test.uasset").unwrap();

    let bag = &pkg.payloads[0];
    let props = match bag {
        PropertyBag::Tree { properties } => properties,
        PropertyBag::Opaque { .. } => panic!("expected PropertyBag::Tree, got Opaque"),
        other => panic!("unexpected PropertyBag variant: {other:?}"),
    };
    let obj_prop = props
        .iter()
        .find(|p| p.name == "NullRef")
        .expect("NullRef property not found");

    assert!(
        matches!(
            &obj_prop.value,
            PropertyValue::Object {
                kind: PackageIndex::Null,
                name,
            } if name.is_empty()
        ),
        "unexpected value: {:?}",
        obj_prop.value
    );
}
```

- [ ] **Step 2: Add the two fixture helpers used by tests 5 and 6**

Add to `crates/paksmith-core/src/testing/uasset.rs`. The whole module is `#[cfg(feature = "__test_utils")]`-gated in `lib.rs:37-38`, so per-function `#[cfg]` attributes are redundant — match the existing siblings (`build_minimal_ue4_27_with_properties` at `testing/uasset.rs:592`) which use `#[must_use]` only.

Prefer wiring these as `MinimalPackageSpec`-based builders: `MinimalPackageSpec` (at `testing/uasset.rs:108`) accepts custom `names: NameTable`, `imports: ImportTable`, `exports: ExportTable`, and `payloads: Vec<Vec<u8>>`, then `build_minimal(spec)` handles all the offset patching + summary write. This is the same pattern `build_minimal_ue4_27_with_properties` uses (`testing/uasset.rs:592-671`); modeling the new builders on it eliminates the need for a separate `build_with_payload_and_import` helper.

```rust
/// Returns `(bytes, expected_resolved_name)` where:
/// - The export payload has one `ObjectProperty` named `"ObjRef"` with wire i32 = -1
/// - The name table includes `"/Game/Data/Mesh.StaticMesh"` as an FName
/// - The import table has one entry whose `object_name` points to that FName
/// - `expected_resolved_name = "/Game/Data/Mesh.StaticMesh"` (the bare FName,
///   not a SoftObjectPath-style composite — see Task 2's `resolve_package_index`
///   doc comment)
#[must_use]
pub fn build_minimal_ue4_27_with_object_ref() -> (Vec<u8>, String) {
    // Name table layout (chosen so the import's object_name resolves cleanly):
    //   0 = "/Script/CoreUObject"   3 = "ObjRef"
    //   1 = "Package"               4 = "ObjectProperty"
    //   2 = "/Game/Data/Mesh.StaticMesh"
    //
    // FPropertyTag for the single ObjectProperty:
    //   Name FName (index=3, number=0):   03 00 00 00  00 00 00 00  ("ObjRef")
    //   Type FName (index=4, number=0):   04 00 00 00  00 00 00 00  ("ObjectProperty")
    //   Size i64 = 4:                     04 00 00 00  00 00 00 00
    //   ArrayIndex i32 = 0:               00 00 00 00
    //   has_property_guid u8 = 0:         00
    //   Value i32 = -1:                   FF FF FF FF             (wire -1 → PackageIndex::Import(0))
    // None terminator (0, 0):             00 00 00 00  00 00 00 00 (FName index 0 = "/Script/CoreUObject" — this is fine as a "None" sentinel in the Phase 2b property iterator, which terminates on FName index 0 regardless of the resolved string)
    let payload = vec![
        0x03, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, // name FName (3, 0)
        0x04, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, // type FName (4, 0)
        0x04, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, // size i64 = 4
        0x00, 0x00, 0x00, 0x00,                           // array_index i32 = 0
        0x00,                                             // has_property_guid = 0
        0xFF, 0xFF, 0xFF, 0xFF,                           // value i32 = -1
        0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, // None terminator
    ];
    let import_name = "/Game/Data/Mesh.StaticMesh".to_string();

    // Match Phase 2b's pattern: build a NameTable + ImportTable + ExportTable
    // explicitly, then push them through MinimalPackageSpec. This matches
    // build_minimal_ue4_27_with_properties at testing/uasset.rs:592-671.
    let names = NameTable {
        names: vec![
            FName::new("/Script/CoreUObject"),
            FName::new("Package"),
            FName::new(&import_name),
            FName::new("ObjRef"),
            FName::new("ObjectProperty"),
        ],
    };
    let imports = ImportTable {
        imports: vec![ObjectImport {
            class_package_name: 0, // "/Script/CoreUObject"
            class_package_number: 0,
            class_name: 1, // "Package"
            class_name_number: 0,
            outer_index: PackageIndex::Null,
            object_name: 2, // "/Game/Data/Mesh.StaticMesh"
            object_name_number: 0,
            import_optional: None,
        }],
    };
    // The export's class_index = Import(0) so unreal_asset (if cross-validated
    // later) sees a NormalExport with property iteration. The export's
    // object_name points anywhere in the name table (use index 0 for simplicity).
    let exports = ExportTable {
        exports: vec![ObjectExport {
            class_index: PackageIndex::Import(0),
            super_index: PackageIndex::Null,
            template_index: PackageIndex::Null,
            outer_index: PackageIndex::Null,
            object_name: 0,
            object_name_number: 0,
            object_flags: 0,
            serial_size: payload.len() as i64,
            serial_offset: 0,
            forced_export: false,
            not_for_client: false,
            not_for_server: false,
            package_guid: Some(FGuid::from_bytes([0u8; 16])),
            is_inherited_instance: None,
            package_flags: 0,
            not_always_loaded_for_editor_game: false,
            is_asset: true,
            generate_public_hash: None,
            script_serialization_start_offset: None,
            script_serialization_end_offset: None,
            first_export_dependency: -1,
            serialization_before_serialization_count: 0,
            create_before_serialization_count: 0,
            serialization_before_create_count: 0,
            create_before_create_count: 0,
        }],
    };

    let pkg = build_minimal(MinimalPackageSpec {
        names,
        imports,
        exports,
        payloads: vec![payload],
        ..MinimalPackageSpec::default()
    });
    (pkg.bytes, import_name)
}

/// Returns bytes for a package with one `ObjectProperty` named `"NullRef"` with
/// wire i32 = 0 (PackageIndex::Null). No imports needed — null doesn't resolve.
#[must_use]
pub fn build_minimal_ue4_27_with_null_object_ref() -> Vec<u8> {
    // Name table layout:
    //   0 = "/Script/CoreUObject"   3 = "NullRef"
    //   1 = "Package"               4 = "ObjectProperty"
    //   2 = "Default__Object"
    let payload = vec![
        0x03, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, // name FName (3, 0)
        0x04, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, // type FName (4, 0)
        0x04, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, // size i64 = 4
        0x00, 0x00, 0x00, 0x00,                           // array_index i32 = 0
        0x00,                                             // has_property_guid = 0
        0x00, 0x00, 0x00, 0x00,                           // value i32 = 0 (null)
        0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, // None terminator
    ];
    let names = NameTable {
        names: vec![
            FName::new("/Script/CoreUObject"),
            FName::new("Package"),
            FName::new("Default__Object"),
            FName::new("NullRef"),
            FName::new("ObjectProperty"),
        ],
    };
    let exports = ExportTable {
        exports: vec![ObjectExport {
            class_index: PackageIndex::Import(0),
            super_index: PackageIndex::Null,
            template_index: PackageIndex::Null,
            outer_index: PackageIndex::Null,
            object_name: 2,
            object_name_number: 0,
            object_flags: 0,
            serial_size: payload.len() as i64,
            serial_offset: 0,
            forced_export: false,
            not_for_client: false,
            not_for_server: false,
            package_guid: Some(FGuid::from_bytes([0u8; 16])),
            is_inherited_instance: None,
            package_flags: 0,
            not_always_loaded_for_editor_game: false,
            is_asset: true,
            generate_public_hash: None,
            script_serialization_start_offset: None,
            script_serialization_end_offset: None,
            first_export_dependency: -1,
            serialization_before_serialization_count: 0,
            create_before_serialization_count: 0,
            serialization_before_create_count: 0,
            create_before_create_count: 0,
        }],
    };
    build_minimal(MinimalPackageSpec {
        names,
        exports,
        payloads: vec![payload],
        ..MinimalPackageSpec::default()
    })
    .bytes
}
```

> **Impl note:** Both helpers thread their custom tables through `MinimalPackageSpec` + `build_minimal` — the same pattern as `build_minimal_ue4_27_with_properties`. No new lower-level builder is needed; the existing `build_minimal` already accepts arbitrary name/import/export/payload combinations and handles offset patching internally.

- [ ] **Step 3: Run tests to confirm compile errors (expected at this point)**

```bash
cargo test -p paksmith-core --test companion_integration
```

Expected: compile errors — `build_minimal_ue4_27_with_object_ref` and `build_minimal_ue4_27_with_null_object_ref` are not yet in scope (Step 2 added them but they may need re-export through `testing/mod.rs` if a `pub use` re-export pattern is used). This is the failing-test phase.

- [ ] **Step 4: Run integration tests**

```bash
cargo test -p paksmith-core --test companion_integration
```

Expected: all 6 tests pass.

- [ ] **Step 5: Run full test suite + fmt + clippy + rustdoc**

```bash
cargo test --workspace --all-features
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
```

Expected: all clean.

- [ ] **Step 6: Commit**

```bash
git add \
  crates/paksmith-core/tests/companion_integration.rs \
  crates/paksmith-core/src/testing/uasset.rs
git commit -m "$(cat <<'EOF'
test(companion): 6 integration tests for companion file states + ObjectProperty

Four companion states: monolithic-ok, split-ok, split-missing-uexp-error,
monolithic-with-excess-uexp-warns-ok. Two ObjectProperty tests: null index
(PackageIndex::Null) resolves to "", import ref (PackageIndex::Import(0))
resolves to bare object_name from ImportTable.

build_minimal_ue4_27_with_object_ref and
build_minimal_ue4_27_with_null_object_ref are added as
MinimalPackageSpec-based builders following the
build_minimal_ue4_27_with_properties pattern; no new lower-level builder
is needed because build_minimal already accepts arbitrary
name/import/export/payload combinations.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 7: CLI snapshot — INTENTIONALLY DROPPED

**Decision: Phase 2e does not add a new CLI snapshot.**

The existing CLI snapshot lives at `crates/paksmith-cli/tests/snapshots/inspect_cli__inspect_json_snapshot.snap` (NOT `src/commands/snapshots/`), driven by `crates/paksmith-cli/tests/inspect_cli.rs`. The test exercises `real_v8b_uasset.pak`, whose single export decodes to `PropertyBag::Opaque` (see snapshot line 90: `"payload_bytes": 16`). The Opaque payload is raw bytes — it is never iterated as `FPropertyTag`, so no `PropertyValue::Object` (or any other typed `PropertyValue`) appears in the snapshot at all. The Phase 2e migration from `Object(PackageIndex)` → `Object { kind, name }` is therefore invisible to this snapshot.

Phase 2c hit this exact trap (the snapshot "passes" without exercising the new code) so we are explicit about not repeating it. Two options were considered:

1. **Add a NEW snapshot test** wired to a Phase 2e-relevant fixture (e.g., `real_v8b_split.pak` from Task 5, or a new `real_v8b_object_ref.pak` that exposes a resolved `Object { kind, name }` JSON). This requires: a new fixture in fixture-gen, a new CLI test in `tests/inspect_cli.rs`, and a new `.snap` file. Real new work.
2. **Drop Task 7 entirely.** The six integration tests in Task 6 already cover the `Object { kind, name }` shape end-to-end. The existing snapshot's coverage of opaque/header content is unchanged.

Phase 2e picks option 2. If/when a future task adds a CLI fixture whose payloads decode to a property tree containing an `ObjectProperty`, that task can add the snapshot. Path-corrected reference for that future task: `crates/paksmith-cli/tests/snapshots/`, not `src/commands/snapshots/`.

---

## Self-review

### Spec coverage

| Deferred item from prior plans                      | Covered in Phase 2e?                                    |
| --------------------------------------------------- | ------------------------------------------------------- |
| `.uexp` companion file stitching (Phase 2a, 2b, 2c) | Yes — Tasks 3, 4, 5                                     |
| `ObjectProperty` name resolution (Phase 2d)         | Yes — Tasks 2, 6                                        |
| `.ubulk` detection (Phase 2b)                       | Yes — Task 4 (warn only; stitching deferred to Phase 3) |
| CLI snapshot of `Object { kind, name }` shape       | No — deliberately omitted (see Task 7)                  |
| `StructProperty` as collection element              | No — deferred; empirical wire-format verification needed |
| Unversioned properties                              | No — deferred to Phase 2f                               |

### Placeholder scan

- No `todo!` macros remain in the plan. Task 6's `build_minimal_ue4_27_with_object_ref` and `build_minimal_ue4_27_with_null_object_ref` are spec'd as `MinimalPackageSpec`-based builders (Group I refactor), eliminating the need for a separate `build_with_payload_and_import` helper or any intermediate `todo!`-stub.

### Type consistency

- `PropertyValue::Object { kind: PackageIndex, name: String }` — defined in Task 2 Step 5 (replacing Phase 2d's `Object(PackageIndex)` tuple); used in Task 6 tests with the struct-variant `matches!` pattern.
- `CompanionFileKind::Uexp` — defined in Task 1 Step 4 (after `AssetParseFault`'s Display impl), matched in Task 3 Step 3 and Task 6 test 3.
- `AssetParseFault::MissingCompanionFile { kind }` — defined in Task 1 Step 3 (variant) and Step 3b (Display arm). No `#[error("...")]` attribute because `AssetParseFault` uses hand-rolled `impl fmt::Display`.
- `AssetParseFault::SplitAssetSizeMismatch { uasset_len, total_header_size }` — defined in Task 3 alongside its Display arm.
- `resolve_package_index(kind: PackageIndex, ctx: &AssetContext, asset_path: &str) -> crate::Result<String>` — defined in Task 2 Step 3 (takes typed `PackageIndex`, not raw `i32`; `i32::MIN` underflow handled at decode time by `PackageIndex::try_from_raw`).
- `derive_companion_path(base: &str, new_ext: &str) -> String` — defined in Task 4 Step 2, called in Task 4 Step 3.
- `build_minimal_ue4_27_split() -> (Vec<u8>, Vec<u8>)` — defined in Task 5 Step 3, used in Task 3 Step 1 (stub) and Task 6.
- `MinimalPackage.total_header_size: usize` — added as 9th field in Task 5 Step 1 (the existing 8 fields are preserved), used in Task 5 Step 3.
- `AssetWireField::UexpSize`, `AssetOverflowSite::SplitAssetConcatExtent`, `AssetAllocationContext::SplitAssetCombined` — added in Task 3 Step 2a/2b/2c, each with Display arms and pin-table extensions.

### Lint gate

Every task ends with THREE checks:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
```

- `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets --all-features -- -D warnings` mirror what CI's `Lint` job runs (per `MEMORY.md` `ghas_clippy_extra_lints.md` and the recent `feedback_run_fmt_and_clippy.md` note — clippy passing does NOT imply fmt is clean).
- `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features` catches broken intra-doc links and missing crate-level docs that neither fmt nor clippy surface. Required because every error-variant doc string and every helper added by Phase 2e is doc-linked from at least one other site.

The `.githooks/pre-commit` hook enforces fmt + clippy when wired up via `git config core.hooksPath .githooks` (one-time per clone). The rustdoc check is currently only enforced at the CI gate, not the hook — run it manually before pushing if the PR adds new public docs.
