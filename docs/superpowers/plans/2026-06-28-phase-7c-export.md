# Phase 7c PR3 — Export As… + core export façade Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the Phase 3 export pipeline into the GUI: right-click a file row → **Export As…** → pick a format (or raw bytes) → native save dialog → file written, with a result toast — backed by a small new public `paksmith-core::export` façade so the GUI can enumerate + run exports without duplicating the CLI's orchestration.

**Architecture:** Two core additions (`available_formats`, `export_payload`, `ExportFormat`) read existing internals (`Package.payloads`, `resolve_bulk_for_export`, `FormatHandler`) unchanged. The GUI adds a path-keyed inline picker that supersedes the PR2 action strip: a synchronous fast-path enumerates formats from an already-open parsed tab, and an async cold-path parses unopened entries off-thread. A new `task/export.rs` opens the save dialog and writes the export; its dialog-free core (`write_export`) is integration-tested.

**Tech Stack:** Rust (workspace), `paksmith-core` (library), `paksmith-gui` (iced 0.14 binary crate), `rfd 0.17` (already a direct dep), `thiserror`, `tracing`.

## Global Constraints

- **MSRV 1.88** — no let-chains / if-let match guards. Use two-guard (`if let … { if … }` with `#[allow(clippy::collapsible_if)]`) or let-else forms, matching the surrounding code.
- **Never edit `version =` in any `Cargo.toml`** — release-please owns version bumps.
- **Conventional commits**, one logical change per commit: `feat(core): …`, `feat(gui): …`.
- **No panics in core** — every fallible path returns `Result<T, PaksmithError>`. Reuse `PaksmithError::InvalidArgument { arg: &'static str, reason: String }` for the two new export failure modes; **do not add a new error variant**.
- **Binary-crate dead_code trap (paksmith-gui):** a `Message` variant matched (arm) but never *constructed*, an enum variant never constructed, or a helper used only by `#[cfg(test)]` code is a `dead_code` **error** under `clippy -D warnings` (CI runs `--all-targets`). Every new symbol must be wired to a real consumer in the **same commit**. This forces the GUI feature (Task 3) into **one commit** — partial wiring will not compile clean. Core (Tasks 1–2) commit separately and first.
- **Same registry everywhere:** both enumeration (`available_formats`) and execution (`export_payload`, `write_export`) build `HandlerRegistry::all_default_handlers()` — the canonical constructor — so the picker never offers an extension the export path can't dispatch.
- **Path-keying:** every async GUI result keys by entry path (like `AssetLoaded` / `TextureDecoded`), never by a row index captured at dispatch (the tree can reshuffle). The Export As… picker is keyed by path; its render *position* derives from the live `context_row`.
- **Gates before every commit:** `cargo fmt --all`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace --all-features`, `cargo doc --workspace --no-deps` (`-D warnings`), `typos .`.
- **cargo-mutants `--in-diff` 0-missed** scoped to the changed package(s) before push; final full-PR scope `origin/main...HEAD`.
- **Adversarial review panel to convergence** before any push (≥3 + specialists: this PR adds a **public core API** → deep-impact tracer, and does **file I/O to a user-chosen path** → security pass). **Do not push or open a PR without explicit user permission.**

---

## File Structure

- **Modify** `crates/paksmith-core/src/export/mod.rs` — add `ExportFormat`, `formats_for_payloads` (private), `available_formats`, `export_payload`, tests.
- **Modify** `crates/paksmith-core/src/lib.rs` — re-export `ExportFormat`, `available_formats`, `export_payload`.
- **Create** `crates/paksmith-gui/src/state/export.rs` — pure picker model: `ExportChoice`, `ExportMenu`, `export_choices`, `choice_label`, `default_export_filename` (+ tests).
- **Create** `crates/paksmith-gui/src/task/export.rs` — async `available`, `run`, dialog-free `write_export`, `ExportOutcome` (+ integration tests).
- **Create** `crates/paksmith-gui/src/widgets/inline_band.rs` — thin `#[mutants::skip]` `band` wrapper shared by the action strip and the picker.
- **Create** `crates/paksmith-gui/src/widgets/export_picker.rs` — thin `#[mutants::skip]` `picker_strip`.
- **Modify** `crates/paksmith-gui/src/widgets/file_tree.rs` — replace `show_strip_after` with `RowMenu` + `row_menu_after`; render picker vs. action strip; thread `export_menu`.
- **Modify** `crates/paksmith-gui/src/widgets/context_menu.rs` — add the **Export As…** button to `action_strip`.
- **Modify** `crates/paksmith-gui/src/state/tabs.rs` — add `Tabs::parsed_package`.
- **Modify** `crates/paksmith-gui/src/state/mod.rs`, `widgets/mod.rs`, `task/mod.rs` — `pub mod` the new files.
- **Modify** `crates/paksmith-gui/src/panels/sidebar.rs` — thread `export_menu` into `file_tree::view`.
- **Modify** `crates/paksmith-gui/src/app.rs` — `App.export_menu` field; 5 `Message` arms; `dismiss_row_menus`; clear-site refactor; view threading; update-arm tests.

---

## Task 1: Core — `ExportFormat` + format enumeration

**Files:**
- Modify: `crates/paksmith-core/src/export/mod.rs`
- Modify: `crates/paksmith-core/src/lib.rs:108`
- Test: `crates/paksmith-core/src/export/mod.rs` (in `mod tests`, no feature gate)

**Interfaces:**
- Consumes: `HandlerRegistry` (private `by_variant` — same module), `Asset`, `Package`, `FormatHandler::{supports, output_extension}`.
- Produces:
  - `pub struct ExportFormat { pub payload_idx: usize, pub extension: &'static str }` (`Copy`).
  - `pub fn available_formats(package: &Package, registry: &HandlerRegistry) -> Vec<ExportFormat>`.
  - private `fn formats_for_payloads(registry: &HandlerRegistry, payloads: &[Asset]) -> Vec<ExportFormat>`.

- [ ] **Step 1: Add the `Package` import**

In `crates/paksmith-core/src/export/mod.rs`, next to the existing `use crate::asset::Asset;` (line 52), add:

```rust
use crate::asset::Package;
```

- [ ] **Step 2: Write the failing enumeration tests**

Add to the existing `mod tests` block in `export/mod.rs` (it already defines `MockHandler` and `generic_sentinel()`):

```rust
    #[test]
    fn formats_for_payloads_empty_when_no_handler() {
        // Empty registry → no payload has a handler → empty list.
        let reg = HandlerRegistry::new();
        assert!(formats_for_payloads(&reg, &[generic_sentinel()]).is_empty());
    }

    #[test]
    fn formats_for_payloads_single_handler() {
        let mut reg = HandlerRegistry::new();
        let disc = std::mem::discriminant(&generic_sentinel());
        reg.register(disc, Box::new(MockHandler { ext: "json", supports_value: true }));
        assert_eq!(
            formats_for_payloads(&reg, &[generic_sentinel()]),
            vec![ExportFormat { payload_idx: 0, extension: "json" }]
        );
    }

    #[test]
    fn formats_for_payloads_orders_by_payload_then_registration() {
        // Two handlers for the variant, two payloads → payload-major, then
        // registration order within each payload.
        let mut reg = HandlerRegistry::new();
        let disc = std::mem::discriminant(&generic_sentinel());
        reg.register(disc, Box::new(MockHandler { ext: "csv", supports_value: true }));
        reg.register(disc, Box::new(MockHandler { ext: "json", supports_value: true }));
        let payloads = [generic_sentinel(), generic_sentinel()];
        assert_eq!(
            formats_for_payloads(&reg, &payloads),
            vec![
                ExportFormat { payload_idx: 0, extension: "csv" },
                ExportFormat { payload_idx: 0, extension: "json" },
                ExportFormat { payload_idx: 1, extension: "csv" },
                ExportFormat { payload_idx: 1, extension: "json" },
            ]
        );
    }

    #[test]
    fn formats_for_payloads_dedups_same_extension_within_payload() {
        // Two handlers emitting the same extension for one payload → one entry
        // (first wins) so a format menu never shows a duplicate button.
        let mut reg = HandlerRegistry::new();
        let disc = std::mem::discriminant(&generic_sentinel());
        reg.register(disc, Box::new(MockHandler { ext: "json", supports_value: true }));
        reg.register(disc, Box::new(MockHandler { ext: "json", supports_value: true }));
        assert_eq!(
            formats_for_payloads(&reg, &[generic_sentinel()]),
            vec![ExportFormat { payload_idx: 0, extension: "json" }]
        );
    }

    #[test]
    fn formats_for_payloads_skips_supports_false() {
        let mut reg = HandlerRegistry::new();
        let disc = std::mem::discriminant(&generic_sentinel());
        reg.register(disc, Box::new(MockHandler { ext: "json", supports_value: false }));
        assert!(formats_for_payloads(&reg, &[generic_sentinel()]).is_empty());
    }
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test -p paksmith-core formats_for_payloads`
Expected: FAIL — `cannot find type ExportFormat` / `cannot find function formats_for_payloads`.

- [ ] **Step 4: Implement `ExportFormat`, `formats_for_payloads`, `available_formats`**

In `export/mod.rs`, after the `impl HandlerRegistry { … }` block (and its `find_handler_by_extension`, ending near line 328) and before `impl Default for HandlerRegistry`, add:

```rust
/// One exportable `(payload, format)` pair: the payload at `payload_idx` in a
/// [`Package`] can be written as a file with extension `extension` by a
/// registered [`FormatHandler`]. `Copy` so it rides a GUI `Message` freely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportFormat {
    /// Index into [`Package::payloads`].
    pub payload_idx: usize,
    /// Output extension (no leading dot), e.g. `"png"`, `"csv"`, `"json"`.
    pub extension: &'static str,
}

/// Every `(payload index, output extension)` pair that `registry` can export
/// from `payloads`, in payload order then handler-registration order.
///
/// Within one payload an extension appears at most once (first registered
/// handler wins), so a caller building a format menu never shows a duplicate
/// entry — matching [`HandlerRegistry::find_handler_by_extension`]'s
/// first-match dispatch. Empty when no payload has a supporting handler.
fn formats_for_payloads(registry: &HandlerRegistry, payloads: &[Asset]) -> Vec<ExportFormat> {
    let mut out = Vec::new();
    for (payload_idx, asset) in payloads.iter().enumerate() {
        let disc = std::mem::discriminant(asset);
        let Some(bucket) = registry.by_variant.get(&disc) else {
            continue;
        };
        let mut seen: Vec<&'static str> = Vec::new();
        for handler in bucket {
            if !handler.supports(asset) {
                continue;
            }
            let ext = handler.output_extension();
            if !seen.contains(&ext) {
                seen.push(ext);
                out.push(ExportFormat { payload_idx, extension: ext });
            }
        }
    }
    out
}

/// Every exportable `(payload, format)` pair for `package` under `registry`.
///
/// The GUI's Export As… picker is built from this; the CLI's `extract` selects
/// one payload via its own preference logic and does not call this.
#[must_use]
pub fn available_formats(package: &Package, registry: &HandlerRegistry) -> Vec<ExportFormat> {
    formats_for_payloads(registry, &package.payloads)
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p paksmith-core formats_for_payloads`
Expected: PASS (5 tests).

- [ ] **Step 6: Re-export from the crate root**

In `crates/paksmith-core/src/lib.rs`, change the export re-export line (currently line 108):

```rust
pub use export::{BulkData, FormatHandler, GenericHandler, HandlerRegistry};
```

to:

```rust
pub use export::{
    BulkData, ExportFormat, FormatHandler, GenericHandler, HandlerRegistry, available_formats,
};
```

(`export_payload` is added to this line in Task 2.)

- [ ] **Step 7: Gates + commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test -p paksmith-core
git add crates/paksmith-core/src/export/mod.rs crates/paksmith-core/src/lib.rs
git commit -m "feat(core): add available_formats + ExportFormat export enumeration"
```

Expected: clippy clean, tests pass.

---

## Task 2: Core — `export_payload`

**Files:**
- Modify: `crates/paksmith-core/src/export/mod.rs`
- Modify: `crates/paksmith-core/src/lib.rs` (the re-export line from Task 1)
- Test: `crates/paksmith-core/src/export/mod.rs` (new `#[cfg(feature = "__test_utils")]` test block — needs a real parsed `Package`)

**Interfaces:**
- Consumes: `Package::{payloads, resolve_bulk_for_export}`, `HandlerRegistry::find_handler_by_extension`, `FormatHandler::export`, `PaksmithError::InvalidArgument`.
- Produces: `pub fn export_payload(package: &Package, payload_idx: usize, extension: &str, registry: &HandlerRegistry) -> crate::Result<Vec<u8>>`.

- [ ] **Step 1: Write the failing tests**

The enumeration logic (Task 1) tested over hand-built `&[Asset]`. `export_payload` needs a real `Package` (for `resolve_bulk_for_export`), so its tests use the `__test_utils` builders that the `package.rs` tests already use (`build_minimal_ue4_27` → exactly one `Asset::Generic` payload). Add a **new gated block** at the end of `export/mod.rs` (after the existing `mod tests`):

```rust
#[cfg(all(test, feature = "__test_utils"))]
mod facade_tests {
    use super::*;
    use crate::asset::Package;

    /// A real package with a single `Asset::Generic` payload (json handler).
    fn generic_pkg() -> Package {
        let mp = crate::testing::uasset::build_minimal_ue4_27();
        Package::read_from(&mp.bytes, None, None, "Game/Foo.uasset")
            .expect("build_minimal_ue4_27 must parse")
    }

    #[test]
    fn export_payload_generic_to_json_ok() {
        let pkg = generic_pkg();
        let reg = HandlerRegistry::all_default_handlers();
        let bytes = export_payload(&pkg, 0, "json", &reg).expect("generic→json");
        assert!(!bytes.is_empty(), "json export must produce bytes");
    }

    #[test]
    fn export_payload_out_of_range_idx_is_invalid_argument() {
        let pkg = generic_pkg();
        let reg = HandlerRegistry::all_default_handlers();
        let err = export_payload(&pkg, 99, "json", &reg).unwrap_err();
        assert!(
            matches!(err, crate::PaksmithError::InvalidArgument { arg: "payload_idx", .. }),
            "out-of-range index must be InvalidArgument(payload_idx), got {err:?}"
        );
    }

    #[test]
    fn export_payload_unhandled_extension_is_invalid_argument() {
        let pkg = generic_pkg();
        let reg = HandlerRegistry::all_default_handlers();
        // A Generic payload only exports json; png has no handler for it.
        let err = export_payload(&pkg, 0, "png", &reg).unwrap_err();
        assert!(
            matches!(err, crate::PaksmithError::InvalidArgument { arg: "extension", .. }),
            "unhandled extension must be InvalidArgument(extension), got {err:?}"
        );
    }

    #[test]
    fn available_formats_generic_pkg_offers_json() {
        // Package-level smoke for the Task-1 enumerator. Tolerant of extra
        // payloads (exact ordering/dedup are pinned in formats_for_payloads
        // unit tests); asserts the json entry for payload 0 is present.
        let pkg = generic_pkg();
        let reg = HandlerRegistry::all_default_handlers();
        let formats = available_formats(&pkg, &reg);
        assert!(
            formats.iter().any(|f| f.payload_idx == 0 && f.extension == "json"),
            "generic package must offer json for payload 0, got {formats:?}"
        );
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p paksmith-core --features __test_utils facade_tests`
Expected: FAIL — `cannot find function export_payload`.

- [ ] **Step 3: Implement `export_payload`**

In `export/mod.rs`, immediately after `available_formats` (from Task 1), add:

```rust
/// Resolve the bulk for `payload_idx` and run the handler that produces
/// `extension`, returning the exported file bytes.
///
/// Errors (all [`crate::PaksmithError`], never panics):
/// - `InvalidArgument { arg: "payload_idx", .. }` — index past the end of
///   `package.payloads`.
/// - `InvalidArgument { arg: "extension", .. }` — no registered handler both
///   `supports` the payload and emits `extension`.
/// - bulk-resolution / handler errors propagate unchanged.
///
/// The caller must build `registry` with [`HandlerRegistry::all_default_handlers`]
/// (the same registry used to enumerate via [`available_formats`]) so a
/// successfully-enumerated `(payload_idx, extension)` always dispatches here.
pub fn export_payload(
    package: &Package,
    payload_idx: usize,
    extension: &str,
    registry: &HandlerRegistry,
) -> crate::Result<Vec<u8>> {
    let asset = package
        .payloads
        .get(payload_idx)
        .ok_or_else(|| crate::PaksmithError::InvalidArgument {
            arg: "payload_idx",
            reason: format!(
                "no payload at index {payload_idx} (package has {} payload(s))",
                package.payloads.len()
            ),
        })?;
    let handler = registry
        .find_handler_by_extension(extension, asset)
        .ok_or_else(|| crate::PaksmithError::InvalidArgument {
            arg: "extension",
            reason: format!("no handler exports `{extension}` for this payload"),
        })?;
    let bulk = package.resolve_bulk_for_export(payload_idx)?;
    handler.export(asset, bulk)
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p paksmith-core --features __test_utils facade_tests`
Expected: PASS (4 tests).

- [ ] **Step 5: Add `export_payload` to the re-export**

In `crates/paksmith-core/src/lib.rs`, extend the Task-1 re-export line to:

```rust
pub use export::{
    BulkData, ExportFormat, FormatHandler, GenericHandler, HandlerRegistry, available_formats,
    export_payload,
};
```

- [ ] **Step 6: cargo-mutants on the core delta**

Run: `cargo mutants --in-diff <(git diff origin/main...HEAD) -p paksmith-core -- --all-features`
Expected: 0 missed (caught or unviable). If a survivor appears (e.g. the dedup `!seen.contains`), add a targeted test that distinguishes the mutant.

- [ ] **Step 7: Gates + commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo doc --workspace --no-deps
git add crates/paksmith-core/src/export/mod.rs crates/paksmith-core/src/lib.rs
git commit -m "feat(core): add export_payload bulk-resolve + handler dispatch façade"
```

Expected: all gates clean.

---

## Task 3: GUI — Export As… (one commit)

**Why one commit:** the binary-crate dead_code rule (Global Constraints) forbids a clean partial commit — the new `Message` variants, `ExportChoice` variants, and helpers only compile under `-D warnings` once every one is wired to a real constructor. The PR2 retrospective established this. All sub-steps below land in **one `feat(gui)` commit**. Each sub-step is still TDD (write the helper's failing test, run, implement, run) so the test suite is green at the commit.

**Files:** all GUI files in the File Structure section.

**Interfaces:**
- Consumes (core, from Tasks 1–2): `ExportFormat`, `available_formats`, `export_payload`, `HandlerRegistry::all_default_handlers`, `Package::read_from_reader`, `ContainerReader::read_entry_to`.
- Consumes (GUI): `App.{archive, archive_generation, context_row, tabs, toasts}`, `open_path_for_row`, `push_toast`, `toggle_context_row`, `Message::OpenAssetByRow` pattern, `state::toast::Severity`, `theme::tokens::{RADIUS, SPACE_SM, SPACE_XS, TEXT_SM}`.
- Produces:
  - `state::export::{ExportChoice, ExportMenu, export_choices, choice_label, default_export_filename}`.
  - `task::export::{available, run, ExportOutcome}` + private `write_export`.
  - `widgets::export_picker::picker_strip`.
  - `widgets::file_tree::{RowMenu, row_menu_after}` (replaces `show_strip_after`).
  - `Tabs::parsed_package`.
  - `App.export_menu` + 5 `Message` variants + `dismiss_row_menus`.

### Sub-step 3.1 — `Tabs::parsed_package`

- [ ] Write the failing test in `crates/paksmith-gui/src/state/tabs.rs` `mod tests` (reuse `ready_ok_tab` / `ready_err_tab` helpers already there):

```rust
    #[test]
    fn parsed_package_some_for_ready_ok_none_otherwise() {
        let mut t = ready_ok_tab("a.uasset");
        assert!(t.parsed_package("a.uasset").is_some(), "Ready+Ok → Some");
        assert!(t.parsed_package("missing.uasset").is_none(), "absent → None");

        let e = ready_err_tab("b.uasset");
        assert!(e.parsed_package("b.uasset").is_none(), "Ready+Err → None");

        let _ = t.open_or_activate("loading.uasset"); // Loading content
        assert!(t.parsed_package("loading.uasset").is_none(), "Loading → None");
    }
```

- [ ] Run: `cargo test -p paksmith-gui parsed_package` → FAIL (no method).
- [ ] Implement in `tabs.rs` `impl Tabs` (after `active_tab_mut`):

```rust
    /// The parsed `Package` for the open tab at `path`, if that tab exists and
    /// parsed successfully. Lets Export As… enumerate formats synchronously
    /// when the asset is already open (the common case), avoiding a re-parse.
    #[must_use]
    pub fn parsed_package(&self, path: &str) -> Option<&Arc<Package>> {
        self.open
            .iter()
            .find(|t| t.path == path)
            .and_then(|t| match &t.content {
                TabContent::Ready { parsed: Ok(arc), .. } => Some(arc),
                _ => None,
            })
    }
```

- [ ] Run: `cargo test -p paksmith-gui parsed_package` → PASS.

### Sub-step 3.2 — `state/export.rs` pure model

- [ ] Create `crates/paksmith-gui/src/state/export.rs`:

```rust
//! Pure model for the Export As… inline picker. No iced imports — unit + mutation
//! tested. The picker is keyed by entry path (see [`ExportMenu`]).

use paksmith_core::export::ExportFormat;

/// One choice in the Export As… picker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportChoice {
    /// Export payload `payload_idx` as a file with `extension` via its handler.
    Typed { payload_idx: usize, extension: &'static str },
    /// Write the entry's raw decompressed bytes verbatim (no parse, no handler).
    Raw,
}

/// The open Export As… picker, keyed by entry **path** (not row index) so a tree
/// reshuffle between the async enumerate and its result can't mis-target it —
/// the same path-keying every async result in `app.rs` uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportMenu {
    /// Archive entry path the picker exports.
    pub path: String,
    /// Format buttons, in order, always ending with [`ExportChoice::Raw`].
    pub choices: Vec<ExportChoice>,
}

/// Map enumerated formats to picker choices: one [`ExportChoice::Typed`] per
/// [`ExportFormat`] (order preserved), then a trailing [`ExportChoice::Raw`].
/// Raw is always present — it works even when nothing parsed or no handler
/// matched.
#[must_use]
pub fn export_choices(formats: &[ExportFormat]) -> Vec<ExportChoice> {
    let mut choices: Vec<ExportChoice> = formats
        .iter()
        .map(|f| ExportChoice::Typed { payload_idx: f.payload_idx, extension: f.extension })
        .collect();
    choices.push(ExportChoice::Raw);
    choices
}

/// Button label: the uppercased extension for a typed format, `"Raw bytes"`
/// for the raw entry.
#[must_use]
pub fn choice_label(choice: &ExportChoice) -> String {
    match choice {
        ExportChoice::Typed { extension, .. } => extension.to_uppercase(),
        ExportChoice::Raw => "Raw bytes".to_string(),
    }
}

/// Default file name the save dialog opens with, derived from the entry path.
/// Typed → `<stem>.<extension>`; Raw → the entry's own basename (raw bytes are
/// the entry's own content, so its name is the natural default).
#[must_use]
pub fn default_export_filename(path: &str, choice: &ExportChoice) -> String {
    let basename = path.rsplit('/').next().unwrap_or(path);
    match choice {
        ExportChoice::Typed { extension, .. } => {
            let stem = basename.rsplit_once('.').map_or(basename, |(s, _)| s);
            format!("{stem}.{extension}")
        }
        ExportChoice::Raw => basename.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fmt(idx: usize, ext: &'static str) -> ExportFormat {
        ExportFormat { payload_idx: idx, extension: ext }
    }

    #[test]
    fn export_choices_maps_then_appends_raw() {
        let choices = export_choices(&[fmt(0, "png"), fmt(1, "json")]);
        assert_eq!(
            choices,
            vec![
                ExportChoice::Typed { payload_idx: 0, extension: "png" },
                ExportChoice::Typed { payload_idx: 1, extension: "json" },
                ExportChoice::Raw,
            ]
        );
    }

    #[test]
    fn export_choices_empty_formats_is_raw_only() {
        assert_eq!(export_choices(&[]), vec![ExportChoice::Raw]);
    }

    #[test]
    fn choice_label_uppercases_extension_and_names_raw() {
        assert_eq!(choice_label(&ExportChoice::Typed { payload_idx: 0, extension: "png" }), "PNG");
        assert_eq!(choice_label(&ExportChoice::Raw), "Raw bytes");
    }

    #[test]
    fn default_filename_typed_swaps_extension_on_stem() {
        let c = ExportChoice::Typed { payload_idx: 0, extension: "png" };
        assert_eq!(default_export_filename("Game/Tex/T_Rock.uasset", &c), "T_Rock.png");
        // No directory and no dot: stem is the whole basename.
        assert_eq!(default_export_filename("Rock", &c), "Rock.png");
    }

    #[test]
    fn default_filename_raw_keeps_entry_basename() {
        let c = ExportChoice::Raw;
        assert_eq!(default_export_filename("Game/Tex/T_Rock.uasset", &c), "T_Rock.uasset");
        assert_eq!(default_export_filename("loose.bin", &c), "loose.bin");
    }
}
```

- [ ] Register the module: in `crates/paksmith-gui/src/state/mod.rs` add `pub mod export;` (alphabetical with the other `pub mod`s).
- [ ] Run: `cargo test -p paksmith-gui state::export` → all PASS.

### Sub-step 3.3 — `file_tree.rs`: `RowMenu` + `row_menu_after` (replaces `show_strip_after`)

- [ ] In `crates/paksmith-gui/src/widgets/file_tree.rs`, **delete** `show_strip_after` (line 58–60) and its five tests (the `// ── show_strip_after ──` block, ~lines 411–445). Add the replacement helper near where `show_strip_after` was:

```rust
/// What to render in the inline band beneath a right-clicked file row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowMenu {
    /// Nothing (not the context row, or a dir / pathless row).
    None,
    /// The Open / Copy Path / Export As… action strip.
    Actions,
    /// The Export As… format picker (Export As… was chosen for this row).
    Picker,
}

/// Decide the inline band for visible row `row_idx`.
///
/// Both menus hang off the single right-clicked row (`context_row`). When an
/// `ExportMenu` is open for *this row's path* (`export_menu_path`), the picker
/// supersedes the action strip; otherwise the action strip shows. Directory
/// rows and rows without a resolvable path never get a menu. The path match (not
/// just `context_row == row_idx`) guards against a stale picker after a tree
/// reshuffle moved the path off the context row.
#[must_use]
pub fn row_menu_after(
    context_row: Option<usize>,
    export_menu_path: Option<&str>,
    row_idx: usize,
    row: &VisibleRow,
) -> RowMenu {
    if context_row != Some(row_idx) || row.is_dir || row.full_path.is_none() {
        return RowMenu::None;
    }
    if export_menu_path.is_some() && export_menu_path == row.full_path.as_deref() {
        RowMenu::Picker
    } else {
        RowMenu::Actions
    }
}
```

- [ ] Add the replacement tests (in the same `mod tests`, reusing the existing `file_row()`, `dir_row(_)` helpers):

```rust
    // ── row_menu_after ────────────────────────────────────────────────────────

    #[test]
    fn row_menu_none_when_not_context_row() {
        assert_eq!(row_menu_after(Some(1), None, 0, &file_row()), RowMenu::None);
        assert_eq!(row_menu_after(None, None, 0, &file_row()), RowMenu::None);
    }

    #[test]
    fn row_menu_none_for_dir_or_pathless_row() {
        assert_eq!(row_menu_after(Some(0), None, 0, &dir_row(false)), RowMenu::None);
        let mut r = file_row();
        r.full_path = None;
        assert_eq!(row_menu_after(Some(0), None, 0, &r), RowMenu::None);
    }

    #[test]
    fn row_menu_actions_when_no_picker_open() {
        // file_row()'s full_path must be Some for this to be Actions.
        assert_eq!(row_menu_after(Some(0), None, 0, &file_row()), RowMenu::Actions);
    }

    #[test]
    fn row_menu_picker_when_export_menu_path_matches() {
        let r = file_row();
        let p = r.full_path.as_deref();
        assert_eq!(row_menu_after(Some(0), p, 0, &r), RowMenu::Picker);
    }

    #[test]
    fn row_menu_actions_when_export_menu_path_differs() {
        // Picker open for a different path (stale) → fall back to Actions, not Picker.
        assert_eq!(
            row_menu_after(Some(0), Some("Other/Different.uasset"), 0, &file_row()),
            RowMenu::Actions
        );
    }
```

> If `file_row()` builds a row whose `full_path` is not the literal used in `row_menu_picker_when_export_menu_path_matches`, derive `p` from the row (as written above) so the test stays correct regardless of the fixture's path string.

- [ ] Run: `cargo test -p paksmith-gui row_menu_after` → all PASS. (The crate won't fully build yet — `view` still calls the deleted `show_strip_after`; that's fixed in 3.7. Run just this test module, or proceed and let 3.7 restore the build.)

### Sub-step 3.4 — `task/export.rs`: async export + dialog-free `write_export`

- [ ] Create `crates/paksmith-gui/src/task/export.rs`:

```rust
//! Async Export As… pipeline: enumerate formats for a cold (unopened) entry,
//! and run a chosen export to a user-selected path off the UI thread.
//!
//! The dialog-bearing [`run`] can't be tested headlessly; its dialog-free core
//! [`write_export`] is integration-tested with a real pak fixture.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use paksmith_core::asset::Package;
use paksmith_core::container::ContainerReader as _;
use paksmith_core::container::pak::PakReader;
use paksmith_core::export::{ExportFormat, HandlerRegistry, available_formats, export_payload};

use crate::state::export::{ExportChoice, default_export_filename};

/// Parse `path` and enumerate its exportable formats. Used only for the cold
/// path (no open parsed tab); a parse failure yields an empty list (the picker
/// then offers Raw only). Builds `all_default_handlers()` so the offered formats
/// match exactly what [`write_export`] can dispatch.
#[allow(clippy::unused_async, reason = "async required by iced Task::perform")]
pub async fn available(reader: Arc<PakReader>, path: String) -> Vec<ExportFormat> {
    match Package::read_from_reader(&reader, &path, None) {
        Ok(pkg) => available_formats(&pkg, &HandlerRegistry::all_default_handlers()),
        Err(_) => Vec::new(),
    }
}

/// Outcome of an export run, kept `Clone` so it can ride a `Message`.
#[derive(Debug, Clone)]
pub enum ExportOutcome {
    /// File written to this path.
    Written(PathBuf),
    /// User cancelled the save dialog — no toast.
    Cancelled,
    /// Export failed; stringified reason for the error toast.
    Failed(String),
}

/// Open a save dialog (default name from `src_path` + `choice`), then write the
/// export to the chosen path. Untestable headlessly (the dialog); the work is
/// [`write_export`].
pub async fn run(reader: Arc<PakReader>, src_path: String, choice: ExportChoice) -> ExportOutcome {
    let default_name = default_export_filename(&src_path, &choice);
    let Some(handle) = rfd::AsyncFileDialog::new()
        .set_file_name(default_name)
        .save_file()
        .await
    else {
        return ExportOutcome::Cancelled;
    };
    let dest = handle.path().to_path_buf();
    match write_export(reader.as_ref(), &src_path, &choice, &dest) {
        Ok(()) => ExportOutcome::Written(dest),
        Err(e) => ExportOutcome::Failed(e.to_string()),
    }
}

/// Dialog-free export work: write the chosen export of `src_path` to `dest`.
///
/// Raw streams the decompressed entry straight to the file — **no size cap, no
/// parse** (it must not reuse `task::asset::load`, which caps at `HEX_BYTES_CAP`
/// for the hex preview). Typed parses the package and runs the matching handler.
fn write_export(
    reader: &PakReader,
    src_path: &str,
    choice: &ExportChoice,
    dest: &Path,
) -> Result<(), paksmith_core::PaksmithError> {
    match choice {
        ExportChoice::Raw => {
            let mut file = std::fs::File::create(dest)?;
            reader.read_entry_to(src_path, &mut file)?;
            Ok(())
        }
        ExportChoice::Typed { payload_idx, extension } => {
            let pkg = Package::read_from_reader(reader, src_path, None)?;
            let registry = HandlerRegistry::all_default_handlers();
            let bytes = export_payload(&pkg, *payload_idx, extension, &registry)?;
            std::fs::write(dest, bytes)?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("tests/fixtures")
            .join(name)
    }

    /// Unique temp path per test (no tempfile dep); caller removes it.
    fn tmp_dest(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("paksmith_export_{}_{}.out", tag, std::process::id()))
    }

    #[test]
    fn write_export_raw_writes_the_full_uncapped_entry() {
        let reader = PakReader::open(fixture("real_v8b_uasset.pak")).unwrap();
        let path = "Game/Maps/Demo.uasset";
        let dest = tmp_dest("raw");
        write_export(&reader, path, &ExportChoice::Raw, &dest).expect("raw export");

        let written = std::fs::read(&dest).unwrap();
        let mut expected = Vec::new();
        reader.read_entry_to(path, &mut expected).unwrap();
        let _ = std::fs::remove_file(&dest);

        assert!(!written.is_empty(), "raw export must produce bytes");
        assert_eq!(written, expected, "raw export must be the full entry, uncapped");
    }

    #[tokio::test]
    async fn write_export_typed_writes_handler_output() {
        let reader = Arc::new(PakReader::open(fixture("real_v8b_uasset.pak")).unwrap());
        let path = "Game/Maps/Demo.uasset".to_string();
        // Discover a real format for this entry (also exercises `available`).
        let formats = available(reader.clone(), path.clone()).await;
        let fmt = formats
            .first()
            .copied()
            .expect("Demo.uasset must offer at least one typed format");
        let dest = tmp_dest("typed");
        write_export(
            reader.as_ref(),
            &path,
            &ExportChoice::Typed { payload_idx: fmt.payload_idx, extension: fmt.extension },
            &dest,
        )
        .expect("typed export");
        let written = std::fs::read(&dest).unwrap();
        let _ = std::fs::remove_file(&dest);
        assert!(!written.is_empty(), "typed export must produce bytes");
    }
}
```

- [ ] Register the module: in `crates/paksmith-gui/src/task/mod.rs` add `pub mod export;`.
- [ ] Run: `cargo test -p paksmith-gui task::export` → both PASS.

> If `Demo.uasset` offers **no** typed format (the `.expect` fires), pick a fixture/entry that yields one — search the existing GUI/CLI tests for a pak whose entry parses to a `Generic`/`DataTable`/`Texture2D` payload — and update both the path and the test name's fixture. Do **not** weaken the assertion to a conditional skip.

### Sub-step 3.5 — shared `band` helper + `widgets/export_picker.rs`

The action strip (PR2) and the picker render the **same** full-width styled band. Per the project's DRY-on-second-occurrence rule, extract the band into a shared helper that both call (this refactors the PR2 `action_strip` too — in scope, PR3 already edits that file in 3.6).

- [ ] Create `crates/paksmith-gui/src/widgets/inline_band.rs`:

```rust
//! Shared inline-menu band for the row context menu (`action_strip`) and the
//! Export As… picker (`picker_strip`), so both read as the same surface: a
//! full-width, subtly-filled, rounded container.

use iced::widget::container;
use iced::{Background, Border, Element, Length};

use crate::app::Message;
use crate::theme::tokens::{RADIUS, SPACE_SM, SPACE_XS};

/// Wrap `content` in the full-width inline-menu band (background.weak fill +
/// RADIUS corners). The single source of truth for the band's surface style.
#[mutants::skip] // pure iced view composition
pub fn band<'a>(content: impl Into<Element<'a, Message>>) -> Element<'a, Message> {
    container(content)
        .width(Length::Fill)
        .padding([SPACE_XS, SPACE_SM])
        .style(|theme: &iced::Theme| {
            let palette = theme.extended_palette();
            container::Style {
                background: Some(Background::Color(palette.background.weak.color)),
                border: Border { radius: RADIUS.into(), ..Default::default() },
                ..Default::default()
            }
        })
        .into()
}
```

- [ ] Create `crates/paksmith-gui/src/widgets/export_picker.rs`:

```rust
//! Thin inline format-picker strip shown when Export As… is chosen for a row.
//! Rendering only; all decisions live in `app::update` + `state/export.rs`.
//! Visually identical band to the action strip (background.weak + RADIUS) so the
//! two read as the same inline menu surface.

use iced::Element;
use iced::widget::{button, row, text};

use crate::app::Message;
use crate::state::export::{ExportMenu, choice_label};
use crate::theme::tokens::{SPACE_SM, SPACE_XS, TEXT_SM};
use crate::widgets::inline_band::band;

/// The format-picker band for `menu`: one button per choice (label =
/// [`choice_label`]) plus a Cancel that returns to the action strip.
#[mutants::skip] // pure iced view composition; logic is in update + state::export
pub fn picker_strip<'a>(menu: &ExportMenu) -> Element<'a, Message> {
    let mut items: Vec<Element<'a, Message>> = Vec::with_capacity(menu.choices.len() + 1);
    for choice in &menu.choices {
        items.push(
            button(text(choice_label(choice)).size(f32::from(TEXT_SM)))
                .style(iced::widget::button::text)
                .padding([SPACE_XS, SPACE_SM])
                .on_press(Message::ExportChoiceSelected {
                    path: menu.path.clone(),
                    choice: choice.clone(),
                })
                .into(),
        );
    }
    items.push(
        button(text("Cancel").size(f32::from(TEXT_SM)))
            .style(iced::widget::button::text)
            .padding([SPACE_XS, SPACE_SM])
            .on_press(Message::ExportMenuCancelled)
            .into(),
    );

    band(row(items).spacing(SPACE_SM).align_y(iced::Alignment::Center))
}
```

> `row(items)` is `iced::widget::row` taking an iterator of `Element` (iced 0.14). If the compiler rejects the function form for a `Vec`, use `iced::widget::Row::with_children(items)` — mirror exactly how `file_tree::view` assembles its `Vec<Element>` into a container.

- [ ] Register: in `crates/paksmith-gui/src/widgets/mod.rs` add `pub mod export_picker;` and `pub mod inline_band;`.

### Sub-step 3.6 — `context_menu.rs`: add the Export As… button + use the shared band

- [ ] In `crates/paksmith-gui/src/widgets/context_menu.rs`, add the Export As… button **and** delegate the band surface to the shared `band` helper (removing the duplicated `container(...).style(...)` block). Replace the imports:

```rust
use iced::Element;
use iced::widget::{button, row, text};

use crate::app::Message;
use crate::theme::tokens::{SPACE_SM, SPACE_XS, TEXT_SM};
use crate::widgets::inline_band::band;
```

and replace the whole `action_strip` body:

```rust
/// The inline action strip (Open / Copy Path / Export As…) for the file row at
/// visible index `row_idx`, rendered as the shared inline-menu band.
#[mutants::skip] // pure iced view composition; logic is in update + show helpers
pub fn action_strip<'a>(row_idx: usize) -> Element<'a, Message> {
    let open = button(text("Open").size(f32::from(TEXT_SM)))
        .style(iced::widget::button::text)
        .padding([SPACE_XS, SPACE_SM])
        .on_press(Message::OpenAssetByRow(row_idx));

    let copy = button(text("Copy Path").size(f32::from(TEXT_SM)))
        .style(iced::widget::button::text)
        .padding([SPACE_XS, SPACE_SM])
        .on_press(Message::CopyPathRequested(row_idx));

    let export = button(text("Export As\u{2026}").size(f32::from(TEXT_SM)))
        .style(iced::widget::button::text)
        .padding([SPACE_XS, SPACE_SM])
        .on_press(Message::ExportAsRequested(row_idx));

    band(row![open, copy, export]
        .spacing(SPACE_SM)
        .align_y(iced::Alignment::Center))
}
```

(Update the module doc comment's `(Open / Copy Path)` to `(Open / Copy Path / Export As…)`.)

### Sub-step 3.7 — `app.rs`: state field, Message variants, update arms, clear-site refactor

- [ ] **App field.** In `struct App` (near `context_row`, line 82), add:

```rust
    /// The open Export As… format picker, if any. Path-keyed; rendered beneath
    /// the current `context_row`. `None` ⇒ the action strip (or nothing) shows.
    pub export_menu: Option<crate::state::export::ExportMenu>,
```

In the `Default` impl (near `context_row: None`, line 112) add `export_menu: None,`.

- [ ] **Message variants.** In `enum Message` (after `CopyPathRequested(usize)`, line 223) add:

```rust
    /// Right-clicked row chose "Export As…": open the format picker for the file
    /// at this visible-row index.
    ExportAsRequested(usize),
    /// Async format enumeration for a cold (unopened) entry resolved.
    ExportFormatsReady {
        path: String,
        formats: Vec<paksmith_core::export::ExportFormat>,
        generation: u64,
    },
    /// Cancel in the picker: return to the action strip.
    ExportMenuCancelled,
    /// A picker format was chosen: open the save dialog + export.
    ExportChoiceSelected {
        path: String,
        choice: crate::state::export::ExportChoice,
    },
    /// Export run finished (or was cancelled).
    ExportCompleted {
        outcome: crate::task::export::ExportOutcome,
        generation: u64,
    },
```

- [ ] **`dismiss_row_menus` helper.** Add near `toggle_context_row` (line 968):

```rust
/// Clear both inline row menus (the action strip and the Export As… picker).
/// Used at every site that dismisses the menu, so a dismissing gesture (nav,
/// archive swap, a committed export) never leaves a stale picker visible.
fn dismiss_row_menus(app: &mut App) {
    app.context_row = None;
    app.export_menu = None;
}
```

- [ ] **Refactor PR2 clear sites.** Replace the standalone `app.context_row = None;` with `dismiss_row_menus(app);` at these arms where it is the first statement (no conflicting borrow): `RowToggled` (375), `RowSelected` (390), `FilterChanged`, `ArchiveOpened` Ok (265), `ArchiveOpened` Locked (278), `OpenAsset` (463), and the `CopyPathRequested` success branch (the `app.context_row = None` before the `Task::batch`). **Exceptions (write both fields inline, do not call the helper — a live `app.archive` borrow is held):**
  - `handle_tree_key` (827): change `app.context_row = None;` to two lines:
    ```rust
    app.context_row = None;
    app.export_menu = None;
    ```
  - `RowContextOpened` arm: after `app.context_row = toggle_context_row(app.context_row, i);`, add `app.export_menu = None;` (a fresh right-click always returns to the action strip).

- [ ] **The five new update arms.** Add to the `match message` in `update` (alongside the other arms, e.g. after `OpenAssetByRow`):

```rust
        Message::ExportAsRequested(row) => {
            let Some(path) = open_path_for_row(app, row) else {
                return Task::none();
            };
            // Hybrid: enumerate synchronously from an already-open parsed tab
            // (instant picker, no re-parse — the common case of exporting what
            // you're viewing); else enumerate off-thread (cold path). The map
            // closure ends the `app.tabs` borrow before we write `app.export_menu`.
            let sync_choices = app.tabs.parsed_package(&path).map(|arc| {
                let registry = paksmith_core::export::HandlerRegistry::all_default_handlers();
                let formats = paksmith_core::export::available_formats(arc, &registry);
                crate::state::export::export_choices(&formats)
            });
            if let Some(choices) = sync_choices {
                app.export_menu = Some(crate::state::export::ExportMenu { path, choices });
                Task::none()
            } else if let Some(archive) = &app.archive {
                let reader = archive.reader.clone();
                let generation = app.archive_generation;
                Task::perform(
                    crate::task::export::available(reader, path.clone()),
                    move |formats| Message::ExportFormatsReady {
                        path: path.clone(),
                        formats,
                        generation,
                    },
                )
            } else {
                Task::none()
            }
        }
        Message::ExportFormatsReady { path, formats, generation } => {
            // Fence: drop a stale enumeration from a previous archive.
            if generation != app.archive_generation {
                return Task::none();
            }
            // Apply only if the right-clicked row still resolves to this path —
            // the tree may have reshuffled (filter/collapse) since dispatch.
            let still_targeted = app
                .context_row
                .and_then(|row| open_path_for_row(app, row))
                .is_some_and(|p| p == path);
            if !still_targeted {
                return Task::none();
            }
            let choices = crate::state::export::export_choices(&formats);
            app.export_menu = Some(crate::state::export::ExportMenu { path, choices });
            Task::none()
        }
        Message::ExportMenuCancelled => {
            // Back to the action strip; context_row stays so the strip reappears.
            app.export_menu = None;
            Task::none()
        }
        Message::ExportChoiceSelected { path, choice } => {
            // Commit to exporting this entry: collapse both inline menus and run
            // the save dialog + export off-thread. Capture the reader + generation
            // now so a mid-dialog archive swap can't redirect the export.
            dismiss_row_menus(app);
            if let Some(archive) = &app.archive {
                let reader = archive.reader.clone();
                let generation = app.archive_generation;
                Task::perform(
                    crate::task::export::run(reader, path, choice),
                    move |outcome| Message::ExportCompleted { outcome, generation },
                )
            } else {
                Task::none()
            }
        }
        Message::ExportCompleted { outcome, generation } => {
            // Fence like other async results; a completed export of a now-closed
            // archive drops its toast (the file was still written).
            if generation != app.archive_generation {
                return Task::none();
            }
            use crate::state::toast::Severity;
            use crate::task::export::ExportOutcome;
            match outcome {
                ExportOutcome::Written(dest) => {
                    let name = dest
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("file")
                        .to_string();
                    push_toast(app, Severity::Success, format!("Exported {name}"))
                }
                ExportOutcome::Failed(msg) => {
                    push_toast(app, Severity::Error, format!("Export failed: {msg}"))
                }
                ExportOutcome::Cancelled => Task::none(),
            }
        }
```

- [ ] **View threading.** In `view` (line 1163 region), pass the export menu down. Change the `sidebar::view(...)` call (1169) to also pass `app.export_menu.as_ref()`:

```rust
        let context_row = app.context_row;
        let export_menu = app.export_menu.as_ref();
        // ...
                PaneKind::Sidebar => sidebar::view(tree, accent, selected_row, context_row, export_menu),
```

- [ ] **`sidebar::view`** (`panels/sidebar.rs:29`): add a parameter and forward it:

```rust
pub fn view(
    tree: &Tree,
    accent: iced::Color,
    selected_row: Option<usize>,
    context_row: Option<usize>,
    export_menu: Option<&crate::state::export::ExportMenu>,
) -> Element<'_, Message> {
    let tree_view = file_tree::view(tree, accent, selected_row, context_row, export_menu);
    // ...unchanged...
}
```

- [ ] **`file_tree::view`** (line 99): add the parameter and switch the per-row band on `row_menu_after`:

```rust
pub fn view(
    rows: &Tree,
    accent: iced::Color,
    selected_row: Option<usize>,
    context_row: Option<usize>,
    export_menu: Option<&crate::state::export::ExportMenu>,
) -> Element<'_, Message> {
    let rows = rows.visible_rows();
    let mut items: Vec<Element<'_, Message>> = Vec::with_capacity(rows.len() + 1);
    let export_menu_path = export_menu.map(|m| m.path.as_str());
    for (i, row) in rows.iter().enumerate() {
        items.push(build_row(i, row, accent, selected_row, context_row));
        match row_menu_after(context_row, export_menu_path, i, row) {
            RowMenu::Actions => items.push(crate::widgets::context_menu::action_strip(i)),
            RowMenu::Picker => {
                // Picker ⇒ export_menu is Some (row_menu_after guarantees it).
                if let Some(menu) = export_menu {
                    items.push(crate::widgets::export_picker::picker_strip(menu));
                }
            }
            RowMenu::None => {}
        }
    }
    // ...unchanged container/scrollable assembly...
}
```

> Keep `view`'s existing `#[mutants::skip]` and the rest of its body (the `column`/`scrollable` wrap) exactly as-is — only the loop body changes.

- [ ] **Compile check.** Run: `cargo build -p paksmith-gui` → clean (all variants now constructed + matched; `show_strip_after` gone).

### Sub-step 3.8 — `app.rs` update-arm tests

- [ ] Add to `app.rs` `mod tests`. A helper for the synchronous parsed-tab path (the existing `app_with_ready_tab` sets `parsed: Err`, so add an Ok variant):

```rust
    fn app_with_parsed_tab() -> App {
        let mut app = app_with_paths(&["a.uasset"]);
        let _ = update(&mut app, Message::OpenAsset("a.uasset".into()));
        // Parse a known-good fixture so parsed_package returns Some.
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent().unwrap().parent().unwrap()
            .join("tests/fixtures/minimal_uasset_v5.uasset");
        let bytes = std::fs::read(&fixture).expect("read minimal_uasset_v5.uasset");
        let pkg = paksmith_core::asset::Package::read_from(&bytes, None, None, "a.uasset")
            .expect("parse minimal_uasset_v5.uasset");
        app.tabs.set_content(
            "a.uasset",
            crate::state::tabs::TabContent::Ready {
                bytes,
                truncated: false,
                parsed: Ok(std::sync::Arc::new(pkg)),
            },
        );
        app
    }

    #[test]
    fn export_as_open_parsed_tab_opens_picker_synchronously() {
        let mut app = app_with_parsed_tab();
        app.context_row = Some(0);
        let _ = update(&mut app, Message::ExportAsRequested(0));
        let menu = app.export_menu.expect("picker must open for a parsed open tab");
        assert_eq!(menu.path, "a.uasset");
        assert_eq!(
            menu.choices.last(),
            Some(&crate::state::export::ExportChoice::Raw),
            "the picker must always end with Raw"
        );
    }

    #[test]
    fn export_formats_ready_stale_generation_dropped() {
        let mut app = App::default();
        let _ = update(
            &mut app,
            Message::ExportFormatsReady {
                path: "x.uasset".into(),
                formats: vec![],
                generation: 99, // != default 0
            },
        );
        assert!(app.export_menu.is_none(), "stale-generation enumeration must be dropped");
    }

    #[test]
    fn export_formats_ready_applies_when_row_still_targets_path() {
        let mut app = app_with_paths(&["a.uasset"]);
        app.context_row = Some(0); // resolves to "a.uasset"
        let _ = update(
            &mut app,
            Message::ExportFormatsReady {
                path: "a.uasset".into(),
                formats: vec![],
                generation: app.archive_generation,
            },
        );
        let menu = app.export_menu.expect("matching path must open the picker");
        assert_eq!(menu.choices, vec![crate::state::export::ExportChoice::Raw]);
    }

    #[test]
    fn export_formats_ready_dropped_when_path_no_longer_targeted() {
        let mut app = app_with_paths(&["a.uasset"]);
        app.context_row = Some(0); // resolves to "a.uasset", not "other"
        let _ = update(
            &mut app,
            Message::ExportFormatsReady {
                path: "other.uasset".into(),
                formats: vec![],
                generation: app.archive_generation,
            },
        );
        assert!(app.export_menu.is_none(), "non-targeted path must be dropped");
    }

    #[test]
    fn export_menu_cancelled_clears_picker_keeps_context_row() {
        let mut app = App::default();
        app.context_row = Some(2);
        app.export_menu = Some(crate::state::export::ExportMenu {
            path: "a.uasset".into(),
            choices: vec![crate::state::export::ExportChoice::Raw],
        });
        let _ = update(&mut app, Message::ExportMenuCancelled);
        assert!(app.export_menu.is_none(), "Cancel clears the picker");
        assert_eq!(app.context_row, Some(2), "Cancel keeps the action strip's row");
    }

    #[test]
    fn export_choice_selected_dismisses_both_menus() {
        let mut app = App::default(); // archive None → no task dispatched
        app.context_row = Some(1);
        app.export_menu = Some(crate::state::export::ExportMenu {
            path: "a.uasset".into(),
            choices: vec![crate::state::export::ExportChoice::Raw],
        });
        let _ = update(
            &mut app,
            Message::ExportChoiceSelected {
                path: "a.uasset".into(),
                choice: crate::state::export::ExportChoice::Raw,
            },
        );
        assert!(app.context_row.is_none(), "choosing a format dismisses the action strip");
        assert!(app.export_menu.is_none(), "choosing a format dismisses the picker");
    }

    #[test]
    fn export_completed_written_pushes_success_toast() {
        let mut app = App::default();
        let _ = update(
            &mut app,
            Message::ExportCompleted {
                outcome: crate::task::export::ExportOutcome::Written("/tmp/T_Rock.png".into()),
                generation: app.archive_generation,
            },
        );
        assert_eq!(app.toasts.items().len(), 1);
        assert_eq!(app.toasts.items()[0].severity, Severity::Success);
        assert!(app.toasts.items()[0].message.contains("T_Rock.png"));
    }

    #[test]
    fn export_completed_failed_pushes_error_toast() {
        let mut app = App::default();
        let _ = update(
            &mut app,
            Message::ExportCompleted {
                outcome: crate::task::export::ExportOutcome::Failed("disk full".into()),
                generation: app.archive_generation,
            },
        );
        assert_eq!(app.toasts.items().len(), 1);
        assert_eq!(app.toasts.items()[0].severity, Severity::Error);
        assert!(app.toasts.items()[0].message.contains("disk full"));
    }

    #[test]
    fn export_completed_cancelled_pushes_no_toast() {
        let mut app = App::default();
        let _ = update(
            &mut app,
            Message::ExportCompleted {
                outcome: crate::task::export::ExportOutcome::Cancelled,
                generation: app.archive_generation,
            },
        );
        assert!(app.toasts.is_empty(), "a cancelled export shows no toast");
    }

    #[test]
    fn export_completed_stale_generation_dropped() {
        let mut app = App::default();
        let _ = update(
            &mut app,
            Message::ExportCompleted {
                outcome: crate::task::export::ExportOutcome::Written("/tmp/x".into()),
                generation: 99, // != default 0
            },
        );
        assert!(app.toasts.is_empty(), "stale-generation completion drops its toast");
    }
```

> If `Severity` isn't already imported in `app.rs` `mod tests`, the existing toast tests (lines ~1401, 1580) reference it — reuse that import path. If `minimal_uasset_v5.uasset` does not parse via `Package::read_from`, use the same fixture the `tabs.rs` `ready_ok_tab` helper uses (it parses `minimal_uasset_v5.uasset`) — keep them consistent.

- [ ] Run: `cargo test -p paksmith-gui` → all PASS (new + existing).

### Sub-step 3.9 — full gates

- [ ] `cargo fmt --all`
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings` → clean
- [ ] `cargo test --workspace --all-features` → all pass (run **without** `| tail` — a pipe masks cargo's exit code)
- [ ] `cargo doc --workspace --no-deps` (with `RUSTDOCFLAGS="-D warnings"` if that's the project's convention) → clean
- [ ] `typos .` → clean

### Sub-step 3.10 — cargo-mutants + commit

- [ ] Mutants on the GUI delta:

```bash
cargo mutants --in-diff <(git diff origin/main...HEAD) -p paksmith-gui -- --all-features
```

Expected: 0 missed. Likely survivors to pre-empt with a test:
  - `row_menu_after`'s `export_menu_path == row.full_path.as_deref()` (the path-match) — covered by `row_menu_picker_when_export_menu_path_matches` + `row_menu_actions_when_export_menu_path_differs`.
  - `export_choices` trailing `push(Raw)` — covered by `export_choices_empty_formats_is_raw_only`.
  - the `formats_for_payloads` dedup (`!seen.contains`) — covered in Task 1.
  - `ExportFormatsReady` `still_targeted` — covered by the applies/dropped pair.
  `#[mutants::skip]` view fns (`picker_strip`) produce no mutants by construction.

- [ ] Commit (one commit for the whole GUI feature):

```bash
git add crates/paksmith-gui/
git commit -m "feat(gui): add Export As… inline picker + save dialog + export task"
```

---

## Self-Review (run after the plan is written; fix inline)

**1. Spec coverage** (`docs/superpowers/specs/2026-06-27-phase-7c-gui-chrome-design.md` §3 + Core API):
- Core `available_formats` / `export_payload` / `ExportFormat` → Tasks 1–2. ✓
- Picker entries = one per `ExportFormat` (uppercased ext) + always-present Raw → `export_choices` + `choice_label` (3.2). ✓
- Export As… replaces the action strip with the format list; Cancel returns → `row_menu_after` Picker/Actions + `ExportMenuCancelled` (3.3, 3.7). ✓
- Save flow `rfd … set_file_name(stem.ext) … save_file()` → `task::export::run` (3.4). ✓
- On-demand parse for unopened rows; Raw needs no parse → cold path `available` + Raw streams via `read_entry_to` (3.4, 3.7). ✓
- Generation-fenced completion → `ExportCompleted` fence (3.7). ✓
- Errors → readable Error toast; never panics; never removes a tab → `ExportOutcome::Failed` + `InvalidArgument` (Task 2, 3.4, 3.7). ✓

**2. Placeholder scan:** every code step has complete code; no "TBD"/"add error handling". The three `>` callouts are explicit contingencies (fixture choice, `row(items)` form, `Severity` import) with concrete fallbacks, not deferrals. ✓

**3. Type consistency:** `ExportFormat { payload_idx, extension }`, `ExportChoice::Typed { payload_idx, extension }`, `ExportMenu { path, choices }`, `ExportOutcome::{Written,Cancelled,Failed}`, `RowMenu::{None,Actions,Picker}` — names used identically across tasks. `available_formats(package, registry)` / `export_payload(package, idx, ext, registry)` / `write_export(reader, src_path, choice, dest)` signatures match every call site. `Tabs::parsed_package(&self, path) -> Option<&Arc<Package>>` matches its use in `ExportAsRequested`. ✓

**4. Known traps wired in:** path-keying (no row in `ExportMenu`), `dismiss_row_menus` at all clear sites incl. `RowContextOpened` + inline at `handle_tree_key`, Raw uses uncapped `read_entry_to` (not `task::asset::load`), same `all_default_handlers()` for enumerate + export, binary-crate dead_code → GUI is one commit. ✓
