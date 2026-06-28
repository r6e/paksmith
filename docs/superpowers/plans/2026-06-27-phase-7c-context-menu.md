# Phase 7c — Context Menu (PR2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Right-click a file row in the explorer to reveal an inline action strip (Open / Copy Path) rendered beneath that row, with Copy Path writing the path to the clipboard and confirming via a success toast.

**Architecture:** Mirrors the established GUI split. A single `context_row: Option<usize>` field on `App` (a *visible-row* index, exactly like `selected_row`) drives an inline strip rendered by `file_tree::view`. A `mouse_area::on_right_press` on each **file** row emits `Message::RowContextOpened(i)`, which toggles `context_row` via a pure helper. Two pure helpers — `toggle_context_row` (in `app.rs`) and `show_strip_after` (in `file_tree.rs`) — carry all the testable decision logic; the strip widget is a thin `#[mutants::skip]` view. Open reuses the existing `Message::OpenAssetByRow`; Copy Path adds `Message::CopyPathRequested(i)` that resolves the path via the existing `open_path_for_row` helper, batches `iced::clipboard::write` with a `Severity::Success` toast (PR1 infra), and closes the menu. `context_row` is cleared on every spec'd trigger so a stale index can never address the wrong row.

**Tech Stack:** Rust, iced 0.14 (`mouse_area::on_right_press`, `Task::batch`, `iced::clipboard::write`, `stack`), `tokio` (toast auto-dismiss timer, PR1).

## Global Constraints

- GUI-only — **no `paksmith-core` changes** in this PR (the core export façade is PR3).
- No new dependencies (toasts/menu use iced built-ins; PR1's `tokio` timer already wired).
- No panics; `Result`/`Option` throughout. Out-of-range visible-row indices are silent no-ops (mirror `open_path_for_row` / `clamp_selected_row`).
- MSRV 1.88 — no let-chains, no `if let` match guards. Use the two-guard / `let … else` / plain-boolean `&&` forms already in `app.rs`. (`a == Some(i) && b.is_some()` is a plain boolean `&&`, NOT a let-chain — allowed.)
- TDD: write the failing test first, watch it fail, implement minimally, watch it pass, commit. One logical change per commit. Conventional commits (`feat:` / `test:`).
- Thin widgets are `#[mutants::skip]`; all testable logic is extracted to pure helpers with unit + mutation coverage. `cargo mutants --in-diff` to 0-missed before push.
- `paksmith-gui` is a **binary crate** → test with `cargo test -p paksmith-gui` (no `--lib`).
- Scope: **Open + Copy Path only.** "Export As…" is PR3 — do not add it here.

---

## File map

- **Modify** `crates/paksmith-gui/src/app.rs`
  - `App.context_row: Option<usize>` field + `Default` init.
  - `Message::RowContextOpened(usize)`, `Message::CopyPathRequested(usize)`.
  - `toggle_context_row` private helper (unit tested).
  - `update` arms: `RowContextOpened`, `CopyPathRequested`; clears in `RowToggled`, `RowSelected`, `FilterChanged`, `ArchiveOpened(Ok)`, `OpenAsset`.
  - `handle_tree_key`: clear `context_row` at the top (covers arrows / Enter / Escape).
  - `view`: capture `context_row` local; pass to `sidebar::view`.
- **Create** `crates/paksmith-gui/src/widgets/context_menu.rs` — thin `action_strip(row_idx, indent)` (Open + Copy Path).
- **Modify** `crates/paksmith-gui/src/widgets/mod.rs` — `pub mod context_menu;`.
- **Modify** `crates/paksmith-gui/src/widgets/file_tree.rs`
  - `show_strip_after` private predicate (unit tested).
  - `view` signature gains `context_row: Option<usize>`; loop inserts the strip after the owning row.
  - `build_row` file-row branch gains `.on_right_press(Message::RowContextOpened(i))`.
- **Modify** `crates/paksmith-gui/src/panels/sidebar.rs` — `view` gains `context_row`, forwards to `file_tree::view`.

---

## Task 1: `context_row` state, toggle helper, and right-press message

**Files:**
- Modify: `crates/paksmith-gui/src/app.rs` (`App` struct + `Default`, `Message`, `update`, new helper + tests)

**Interfaces:**
- Produces:
  - `App.context_row: Option<usize>` — visible-row index whose inline strip is shown.
  - `Message::RowContextOpened(usize)` — emitted by a right-press on a file row.
  - `fn toggle_context_row(current: Option<usize>, clicked: usize) -> Option<usize>` — pure.
- Consumes: nothing new.

- [ ] **Step 1: Write the failing unit tests for `toggle_context_row`**

Add inside `mod tests` in `crates/paksmith-gui/src/app.rs` (near `clamp_selected_row` tests):

```rust
// ── toggle_context_row ────────────────────────────────────────────────────
#[test]
fn toggle_context_row_from_none_opens_clicked() {
    assert_eq!(toggle_context_row(None, 3), Some(3));
}

#[test]
fn toggle_context_row_from_other_moves_to_clicked() {
    // Right-clicking a different row moves the menu there (not a toggle-off).
    assert_eq!(toggle_context_row(Some(2), 3), Some(3));
}

#[test]
fn toggle_context_row_same_row_closes() {
    // Second right-press on the same row closes it. Kills `== with !=`.
    assert_eq!(toggle_context_row(Some(3), 3), None);
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p paksmith-gui toggle_context_row`
Expected: FAIL — `cannot find function toggle_context_row`.

- [ ] **Step 3: Implement `toggle_context_row`**

Add near `clamp_selected_row` in `crates/paksmith-gui/src/app.rs`:

```rust
/// The new `context_row` after a right-press on visible row `clicked`.
///
/// Right-pressing the row that already owns the inline menu closes it (toggle);
/// right-pressing any other row moves the menu to that row.
fn toggle_context_row(current: Option<usize>, clicked: usize) -> Option<usize> {
    if current == Some(clicked) {
        None
    } else {
        Some(clicked)
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p paksmith-gui toggle_context_row`
Expected: PASS (3 tests).

- [ ] **Step 5: Add the `context_row` field**

In the `App` struct (after the `toasts` field) in `crates/paksmith-gui/src/app.rs`:

```rust
    /// Visible-row index whose inline context-menu strip (Open / Copy Path) is
    /// currently shown, or `None`. A *visible-row* index like
    /// [`App::selected_row`]; cleared on every tree-mutating or selection path
    /// so a stale index can never address the wrong row.
    pub context_row: Option<usize>,
```

In `impl Default for App` (after `toasts: …`):

```rust
            context_row: None,
```

- [ ] **Step 6: Write the failing test for the `RowContextOpened` arm**

Add inside `mod tests`:

```rust
// ── Message::RowContextOpened ─────────────────────────────────────────────
#[test]
fn row_context_opened_toggles_the_strip() {
    let mut app = app_with_paths(&["file.txt"]);
    let _ = update(&mut app, Message::RowContextOpened(0));
    assert_eq!(app.context_row, Some(0), "first right-press opens the strip");
    let _ = update(&mut app, Message::RowContextOpened(0));
    assert_eq!(app.context_row, None, "second right-press on same row closes it");
}
```

- [ ] **Step 7: Run it to verify it fails**

Run: `cargo test -p paksmith-gui row_context_opened`
Expected: FAIL — `no variant named RowContextOpened`.

- [ ] **Step 8: Add the message variant and the update arm**

In `enum Message` (after `ToastDismissed(u64)`):

```rust
    /// A file row was right-clicked — toggle its inline context-menu strip.
    /// Carries the *visible-row* index (no coordinates: `on_right_press` gives
    /// none, and the inline strip needs none).
    RowContextOpened(usize),
```

In `update`'s match (after the `ToastDismissed` arm):

```rust
        Message::RowContextOpened(i) => {
            app.context_row = toggle_context_row(app.context_row, i);
            Task::none()
        }
```

- [ ] **Step 9: Run the tests to verify they pass**

Run: `cargo test -p paksmith-gui`
Expected: PASS (all existing + new). NOTE: `Message` lives in a **binary** crate, so a variant that is matched but never *constructed* is flagged `dead_code` under `clippy -D warnings`. `RowContextOpened` is matched here but not yet constructed — so its constructor (the `on_right_press` wiring) must land in **this same commit** (Step 10) rather than in the render task.

- [ ] **Step 10: Wire the right-press trigger in `build_row`**

In `crates/paksmith-gui/src/widgets/file_tree.rs`, in `build_row`'s file-row `else` branch (the `mouse_area(btn)` wrapper), add `.on_right_press`:

```rust
        mouse_area(btn)
            .on_double_click(Message::OpenAssetByRow(i))
            .on_right_press(Message::RowContextOpened(i))
            .into()
```

(`build_row` is `#[mutants::skip]`; the inner `button` captures only LEFT clicks, so the right-press falls through to the `mouse_area`. Directory rows are a plain `button` with no `mouse_area`, so they get no menu.)

- [ ] **Step 11: Lint + commit**

```bash
cargo fmt --all
cargo clippy -p paksmith-gui --all-targets --all-features -- -D warnings
git add crates/paksmith-gui/src/app.rs crates/paksmith-gui/src/widgets/file_tree.rs
git commit -m "feat(gui): add context_row state and right-press toggle (phase 7c)"
```

---

## Task 2: Clear `context_row` on every dismissal trigger

**Files:**
- Modify: `crates/paksmith-gui/src/app.rs` (`update` arms + `handle_tree_key` + tests)

**Interfaces:**
- Consumes: `App.context_row` (Task 1).
- Produces: the invariant "a tree-mutating or selection action clears the inline menu."

Spec clear triggers: opening any asset, selecting a row, archive swap, filter change, tree toggle, Escape, keyboard navigation. (Second right-press on the same row is handled by `toggle_context_row` in Task 1.)

- [ ] **Step 1: Write the failing tests**

Add inside `mod tests`:

```rust
// ── context_row clear triggers ────────────────────────────────────────────
#[test]
fn row_toggled_clears_context_row() {
    let mut app = app_with_paths(&["Dir/file.txt"]);
    app.context_row = Some(0);
    let _ = update(&mut app, Message::RowToggled(0));
    assert_eq!(app.context_row, None, "toggling a dir clears the menu");
}

#[test]
fn row_selected_clears_context_row() {
    let mut app = app_with_paths(&["file.txt"]);
    app.context_row = Some(0);
    let _ = update(&mut app, Message::RowSelected(0));
    assert_eq!(app.context_row, None, "selecting a row clears the menu");
}

#[test]
fn filter_changed_clears_context_row() {
    let mut app = app_with_paths(&["file.txt"]);
    app.context_row = Some(0);
    let _ = update(&mut app, Message::FilterChanged("f".to_string()));
    assert_eq!(app.context_row, None, "filtering clears the menu");
}

#[test]
fn open_asset_clears_context_row() {
    let mut app = app_with_paths(&["file.txt"]);
    app.context_row = Some(0);
    let _ = update(&mut app, Message::OpenAsset("file.txt".to_string()));
    assert_eq!(app.context_row, None, "opening an asset clears the menu");
}

#[test]
fn archive_opened_ok_clears_context_row() {
    let mut app = app_with_paths(&["old.uasset"]);
    app.context_row = Some(0);
    // Move a freshly-built loaded archive out of a throwaway App and swap it in.
    let new_archive = app_with_paths(&["new.uasset"]).archive.unwrap();
    let _ = update(&mut app, Message::ArchiveOpened(Box::new(Ok(new_archive))));
    assert_eq!(app.context_row, None, "archive swap clears the menu");
}

#[test]
fn archive_opened_locked_clears_context_row() {
    // Opening a locked pak keeps the old archive but enters the key flow; the
    // stale menu index must still be cleared (the "archive swap" trigger covers
    // both the Ok and the Locked transition).
    let mut app = app_with_paths(&["old.uasset"]);
    app.context_row = Some(0);
    let _ = update(
        &mut app,
        Message::ArchiveOpened(Box::new(Err(OpenError::Locked {
            path: PathBuf::from("locked.pak"),
        }))),
    );
    assert_eq!(app.context_row, None, "entering the key flow clears the menu");
}

#[test]
fn arrow_down_clears_context_row() {
    let mut app = app_with_paths(&["a.txt", "b.txt"]);
    app.context_row = Some(0);
    let _ = handle_tree_key(&mut app, &named_key(Named::ArrowDown));
    assert_eq!(app.context_row, None, "keyboard navigation clears the menu");
}

#[test]
fn escape_clears_context_row() {
    let mut app = app_with_paths(&["file.txt"]);
    app.context_row = Some(0);
    let _ = handle_tree_key(&mut app, &named_key(Named::Escape));
    assert_eq!(app.context_row, None, "Escape clears the menu");
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test -p paksmith-gui clears_context_row`
Expected: FAIL — each asserts `None` but `context_row` is still `Some(0)`.
(Run `escape_clears_context_row` and `arrow_down_clears_context_row` too: `cargo test -p paksmith-gui context_row` covers the set.)

- [ ] **Step 3: Add the clears to the `update` arms**

In `Message::ArchiveOpened` → `Ok(loaded)` arm, beside `app.selected_row = None;`:

```rust
                app.selected_row = None;
                app.context_row = None;
```

In `Message::ArchiveOpened` → `Err(OpenError::Locked { path })` arm, beside `app.tabs.clear();` (the old archive is kept while the key prompt shows, so the stale menu index must be cleared too):

```rust
                app.context_row = None;
                // Clear any stale tabs from a previously-open archive.
                app.tabs.clear();
```

At the **top** of `Message::RowToggled(i)` (before `if let Some(archive) = &mut app.archive`):

```rust
        Message::RowToggled(i) => {
            app.context_row = None;
            if let Some(archive) = &mut app.archive {
```

At the **top** of `Message::RowSelected(i)`:

```rust
        Message::RowSelected(i) => {
            app.context_row = None;
            if let Some(archive) = &mut app.archive {
```

At the **top** of `Message::FilterChanged(query)`:

```rust
        Message::FilterChanged(query) => {
            app.context_row = None;
            app.filter.clone_from(&query);
```

At the **top** of `Message::OpenAsset(path)` (before `let was_open = …`):

```rust
        Message::OpenAsset(path) => {
            app.context_row = None;
            // Re-opening an already-open asset only reactivates its tab; …
            let was_open = app.tabs.is_open(&path);
```

- [ ] **Step 4: Add the clear to `handle_tree_key`**

In `handle_tree_key`, immediately after the `let named = *named;` line (and before `let prev_selected = …`):

```rust
    let named = *named;

    // Any tree-key navigation (arrows, Enter, Escape, or any other key) dismisses
    // the inline context menu. This is load-bearing, not just cosmetic: the strip
    // inserts an extra row that shifts the Y of every row below it, which would
    // desync the keyboard auto-scroll's `row_idx * row_height` math at the bottom
    // of this function. Clearing here (before that scroll offset is computed)
    // keeps row height uniform. Disjoint-field write — `archive` borrows
    // `app.archive`, this writes `app.context_row` (same pattern as the
    // `app.selected_row = …` writes below).
    app.context_row = None;

    let prev_selected = app.selected_row;
```

(No new `Escape` match arm is needed: the clear above runs for every key, and `Escape` then falls through the existing `_ => {}` arm to `return None`.)

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p paksmith-gui`
Expected: PASS (all existing + 7 new). Existing arrow/Enter tests still pass — clearing `context_row` (which they leave `None`) is invisible to them.

- [ ] **Step 6: Lint + commit**

```bash
cargo fmt --all
cargo clippy -p paksmith-gui --all-targets --all-features -- -D warnings
git add crates/paksmith-gui/src/app.rs
git commit -m "feat(gui): clear context_row on tree mutation and navigation (phase 7c)"
```

---

## Task 3: Copy Path action — clipboard write + success toast

> **Shared commit with Task 4.** `Message::CopyPathRequested` is *matched* by the arm below but *constructed* only by Task 4's "Copy Path" button. In this binary crate, a variant matched-but-never-constructed is a `dead_code` error under `clippy -D warnings`. So **do not commit at the end of Task 3** — implement Task 3's code, then Task 4's code, and commit once (Task 4's final commit covers both). Tests for both can run together at the end.

**Files:**
- Modify: `crates/paksmith-gui/src/app.rs` (`Message`, `update` arm, tests)

**Interfaces:**
- Consumes: `open_path_for_row(app, i) -> Option<String>` (existing), `push_toast(app, Severity, String) -> Task<Message>` (PR1), `App.context_row`.
- Produces: `Message::CopyPathRequested(usize)` — copies the file path for visible row `i`.

- [ ] **Step 1: Write the failing tests**

Add inside `mod tests`:

```rust
// ── Message::CopyPathRequested ────────────────────────────────────────────
#[test]
fn copy_path_requested_pushes_success_toast_and_closes_menu() {
    let mut app = app_with_paths(&["file.txt"]);
    app.context_row = Some(0);
    let _ = update(&mut app, Message::CopyPathRequested(0));
    assert_eq!(app.toasts.items().len(), 1, "one success toast pushed");
    assert_eq!(app.toasts.items()[0].severity, Severity::Success);
    assert!(
        app.toasts.items()[0].message.contains("Copied"),
        "toast confirms the copy"
    );
    assert_eq!(app.context_row, None, "copy closes the menu");
}

#[test]
fn copy_path_requested_oob_does_nothing() {
    // An index with no resolvable path is a silent no-op — no toast, no panic.
    let mut app = app_with_paths(&["file.txt"]);
    let _ = update(&mut app, Message::CopyPathRequested(999));
    assert!(app.toasts.is_empty(), "no toast when the row has no path");
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test -p paksmith-gui copy_path_requested`
Expected: FAIL — `no variant named CopyPathRequested`.

- [ ] **Step 3: Add the message variant and the update arm**

In `enum Message` (after `RowContextOpened(usize)`):

```rust
    /// Copy the path of the file at visible-row index to the clipboard. The path
    /// is resolved in `update` via `open_path_for_row` so the per-frame view
    /// never clones a path String.
    CopyPathRequested(usize),
```

In `update`'s match (after the `RowContextOpened` arm):

```rust
        Message::CopyPathRequested(i) => match open_path_for_row(app, i) {
            Some(path) => {
                // The action completes here, so close the inline menu.
                app.context_row = None;
                Task::batch([
                    iced::clipboard::write::<Message>(path),
                    push_toast(
                        app,
                        crate::state::toast::Severity::Success,
                        "Copied path".to_string(),
                    ),
                ])
            }
            // No resolvable path (out-of-range, or a dir row) — silent no-op.
            None => Task::none(),
        },
```

- [ ] **Step 4: Build (do NOT commit yet — variant has no constructor until Task 4)**

Run: `cargo build -p paksmith-gui`
Expected: builds, but `cargo clippy -- -D warnings` would fail with `variant CopyPathRequested is never constructed` — that constructor arrives in Task 4. The CopyPathRequested tests will pass once compiled; run them with the Task 4 suite. Proceed directly to Task 4 and commit both together.

---

## Task 4: Inline strip widget + file-tree render (commits Task 3 + Task 4)

**Files:**
- Create: `crates/paksmith-gui/src/widgets/context_menu.rs`
- Modify: `crates/paksmith-gui/src/widgets/mod.rs`
- Modify: `crates/paksmith-gui/src/widgets/file_tree.rs` (`show_strip_after` + tests, `view` signature/loop, `build_row` right-press)
- Modify: `crates/paksmith-gui/src/panels/sidebar.rs` (`view` signature)
- Modify: `crates/paksmith-gui/src/app.rs` (`view` call site)

**Interfaces:**
- Consumes: `Message::RowContextOpened(usize)` (Task 1), `Message::OpenAssetByRow(usize)` (existing), `Message::CopyPathRequested(usize)` (Task 3), `VisibleRow`, `row_indent`, `file_row_indent`.
- Produces:
  - `context_menu::action_strip<'a>(row_idx: usize, indent: f32) -> Element<'a, Message>`.
  - `fn show_strip_after(context_row: Option<usize>, row_idx: usize, row: &VisibleRow) -> bool` (private, in `file_tree.rs`).
  - `file_tree::view(tree, accent, selected_row, context_row)` (signature change).
  - `sidebar::view(tree, accent, selected_row, context_row)` (signature change).

- [ ] **Step 1: Write the failing tests for `show_strip_after`**

Add inside `mod tests` in `crates/paksmith-gui/src/widgets/file_tree.rs` (reuse the existing `dir_row` / `file_row` helpers already defined there):

```rust
// ── show_strip_after ──────────────────────────────────────────────────────
#[test]
fn show_strip_after_owning_file_row_is_true() {
    assert!(show_strip_after(Some(0), 0, &file_row()));
}

#[test]
fn show_strip_after_other_row_is_false() {
    // context_row points elsewhere — kills `== with !=`.
    assert!(!show_strip_after(Some(1), 0, &file_row()));
}

#[test]
fn show_strip_after_none_is_false() {
    assert!(!show_strip_after(None, 0, &file_row()));
}

#[test]
fn show_strip_after_dir_row_is_false() {
    // Directories never get a menu — kills `delete !` / `&& with ||`.
    assert!(!show_strip_after(Some(0), 0, &dir_row(false)));
}

#[test]
fn show_strip_after_file_without_path_is_false() {
    // A file row carrying no path can't be acted on — kills `is_some -> is_none`.
    let row = VisibleRow {
        depth: 1,
        label: "x".to_string(),
        is_dir: false,
        expanded: false,
        full_path: None,
    };
    assert!(!show_strip_after(Some(0), 0, &row));
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test -p paksmith-gui show_strip_after`
Expected: FAIL — `cannot find function show_strip_after`.

- [ ] **Step 3: Implement `show_strip_after`**

Add to the "pure helpers" section of `crates/paksmith-gui/src/widgets/file_tree.rs` (near `row_is_selected`):

```rust
/// Whether to render the inline context-menu strip immediately after visible
/// row `row_idx`. The strip belongs only to the file row that currently owns
/// the menu; directory rows and path-less rows never get one.
fn show_strip_after(context_row: Option<usize>, row_idx: usize, row: &VisibleRow) -> bool {
    context_row == Some(row_idx) && !row.is_dir && row.full_path.is_some()
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p paksmith-gui show_strip_after`
Expected: PASS (5 tests).

- [ ] **Step 5: Create the thin strip widget**

Create `crates/paksmith-gui/src/widgets/context_menu.rs`:

```rust
//! Thin inline context-menu strip rendered beneath a right-clicked file row.
//!
//! All decision logic lives in `app::update` and `file_tree::show_strip_after`;
//! this is rendering only. The buttons carry only the row index — the path is
//! resolved in `update` so the per-frame view never clones a path String.

use iced::widget::{button, row, text, Space};
use iced::{Element, Length};

use crate::app::Message;
use crate::theme::tokens::{SPACE_SM, SPACE_XS, TEXT_SM};

/// The inline action strip (Open / Copy Path) for the file row at visible index
/// `row_idx`. `indent` is the leading pixel offset so the strip lines up under
/// the file label.
#[mutants::skip] // pure iced view composition; logic is in update + show_strip_after
pub fn action_strip<'a>(row_idx: usize, indent: f32) -> Element<'a, Message> {
    let open = button(text("Open").size(f32::from(TEXT_SM)))
        .style(iced::widget::button::text)
        .padding([SPACE_XS, SPACE_SM])
        .on_press(Message::OpenAssetByRow(row_idx));

    let copy = button(text("Copy Path").size(f32::from(TEXT_SM)))
        .style(iced::widget::button::text)
        .padding([SPACE_XS, SPACE_SM])
        .on_press(Message::CopyPathRequested(row_idx));

    row![Space::new().width(indent), open, copy]
        .spacing(SPACE_SM)
        .align_y(iced::Alignment::Center)
        .width(Length::Fill)
        .into()
}
```

- [ ] **Step 6: Register the module**

In `crates/paksmith-gui/src/widgets/mod.rs`, add (keeping the list alphabetical):

```rust
pub mod context_menu;
```

- [ ] **Step 7: Thread `context_row` through `file_tree::view`**

Replace the body of `view` in `crates/paksmith-gui/src/widgets/file_tree.rs`. Update the signature and doc to add `context_row`, and build the items with a loop that inserts the strip after the owning row:

```rust
/// Renders `tree.visible_rows()` as a scrollable column of interactive rows.
///
/// # Arguments
///
/// * `tree` — the pure tree model.
/// * `accent` — the system accent color; used for the selection highlight.
/// * `selected_row` — the keyboard cursor (visible-row index), or `None`.
/// * `context_row` — the visible-row index whose inline action strip is shown,
///   or `None`. The strip is rendered immediately after that row.
///
/// Each row emits:
/// * `Message::RowToggled(i)` when a directory row is clicked.
/// * `Message::RowSelected(i)` when a file row is clicked.
/// * `Message::RowContextOpened(i)` when a file row is right-clicked.
pub fn view(
    tree: &Tree,
    accent: Color,
    selected_row: Option<usize>,
    context_row: Option<usize>,
) -> Element<'_, Message> {
    let rows = tree.visible_rows();
    let mut items: Vec<Element<'_, Message>> = Vec::with_capacity(rows.len());
    for (i, row) in rows.iter().enumerate() {
        items.push(build_row(i, row, accent, selected_row));
        if show_strip_after(context_row, i, row) {
            let indent = file_row_indent(row_indent(row.depth));
            items.push(crate::widgets::context_menu::action_strip(i, indent));
        }
    }

    scrollable(column(items).width(Length::Fill))
        .id(TREE_SCROLL_ID.clone())
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}
```

- [ ] **Step 8: (Right-press wiring already done in Task 1)**

The `.on_right_press(Message::RowContextOpened(i))` on the file-row `mouse_area` was added in Task 1 Step 10 (it had to ship with the variant to avoid the binary-crate `dead_code` error). Nothing to do here — verify it's present in `build_row`.

- [ ] **Step 9: Update `sidebar::view`**

In `crates/paksmith-gui/src/panels/sidebar.rs`, add `context_row` to the signature and forward it (update the doc comment's argument list too):

```rust
pub fn view(
    tree: &Tree,
    accent: iced::Color,
    selected_row: Option<usize>,
    context_row: Option<usize>,
) -> Element<'_, Message> {
    let header = text("EXPLORER")
        .size(f32::from(TEXT_SM))
        .style(|theme: &iced::Theme| iced::widget::text::Style {
            color: Some(theme.palette().text.scale_alpha(TEXT_MUTED_ALPHA)),
        });

    let tree_view = file_tree::view(tree, accent, selected_row, context_row);
```

(The rest of `sidebar::view` is unchanged.)

- [ ] **Step 10: Update the `app::view` call site**

In `crates/paksmith-gui/src/app.rs`, in `view`, capture the local beside `selected_row` and pass it to `sidebar::view`:

```rust
        let selected_row = app.selected_row;
        let context_row = app.context_row;
```

```rust
                PaneKind::Sidebar => sidebar::view(tree, accent, selected_row, context_row),
```

- [ ] **Step 11: Build + run the full GUI test suite**

Run: `cargo test -p paksmith-gui`
Expected: PASS (all tests, including the 5 new `show_strip_after` tests **and** Task 3's 2 `copy_path_requested` tests). The build is green — `context_row` is now read end-to-end (`view` → `sidebar::view` → `file_tree::view` → `show_strip_after`) and `CopyPathRequested` is now constructed by `action_strip`.

- [ ] **Step 12: Lint + commit (Task 3 + Task 4 together)**

```bash
cargo fmt --all
cargo clippy -p paksmith-gui --all-targets --all-features -- -D warnings
git add crates/paksmith-gui/src/widgets/context_menu.rs \
        crates/paksmith-gui/src/widgets/mod.rs \
        crates/paksmith-gui/src/widgets/file_tree.rs \
        crates/paksmith-gui/src/panels/sidebar.rs \
        crates/paksmith-gui/src/app.rs
git commit -m "feat(gui): render inline context-menu strip with Copy Path (phase 7c)"
```

---

## Final verification (before review panel)

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [ ] `cargo test -p paksmith-gui`
- [ ] `cargo doc -p paksmith-gui --no-deps` with `RUSTDOCFLAGS="-D warnings"`
- [ ] `typos .`
- [ ] `cargo mutants --in-diff <(git diff origin/main...HEAD) -p paksmith-gui` → **0 missed**. Expected mutant surface: `toggle_context_row` (`== / Some / None`), `show_strip_after` (`== / && / ! / is_some`) — all covered by the unit tests above. Thin widget + `view` carry no testable operators (`view` reads `Vec::with_capacity(rows.len())` and function calls only — no arithmetic). If `cargo-mutants` surfaces an unkillable mutant inside `view`, mark `view` `#[mutants::skip]` with a rationale matching `build_row`'s (cosmetic/opaque-`Element`; testable logic is in `show_strip_after`) — do **not** invent a test that doesn't assert real behavior.
- [ ] Manual smoke (macOS): open a pak, right-click a file → strip appears beneath it with Open + Copy Path; Open opens a tab; Copy Path shows a "Copied path" toast; right-click the same row again closes it; pressing a key / selecting another row / toggling a dir / filtering closes it.

## Self-review notes (plan vs. spec)

- **Spec coverage:** Trigger (`on_right_press` → `RowContextOpened`) — Task 1/4. State (`context_row: Option<usize>`, all clears) — Task 1/2. Render (inline strip after the owning file row; file rows only) — Task 4. Actions: Open (`OpenAssetByRow`, existing) — Task 4; Copy Path (`clipboard::write` + Success toast) — Task 3. Second-right-press toggle — Task 1 (`toggle_context_row`). Export As… is explicitly **out of scope** for PR2 (PR3) — omitted by design.
- **Type consistency:** `context_row: Option<usize>` and `toggle_context_row(Option<usize>, usize) -> Option<usize>` used identically across tasks; `show_strip_after(Option<usize>, usize, &VisibleRow) -> bool`; `action_strip<'a>(usize, f32) -> Element<'a, Message>`; `file_tree::view`/`sidebar::view` both gain a trailing `context_row: Option<usize>`.
- **No placeholders:** every code step is complete and copy-pasteable.

## R2 review revisions (post-panel, commit `381875e`)

The first review panel (code-reviewer ✅, simplifier ✅, architect ⚠️, UI/UX ⚠️) surfaced two blocking items; both fixed, and the panel re-converged (all four APPROVED). Deltas from the plan above:

- **`action_strip` no longer takes `indent`** and is no longer indented to the owning file's depth. It now renders a distinct full-width `container` band (`extended_palette().background.weak.color` fill + `RADIUS` rounding, `[SPACE_XS, SPACE_SM]` padding) so it reads as an *actions surface* attached to the row above rather than two faux child rows (UI/UX F1). The same change fixes deep-indent + narrow-pane clipping (UI/UX F6). Final signature: `action_strip<'a>(row_idx: usize) -> Element<'a, Message>`; `file_tree::view` calls `action_strip(i)`.
- **`file_tree::view` is `#[mutants::skip]`** (architect F1), matching the sibling `tab_bar`/`hex_view`/`property_tree` view fns now that it carries a conditional. The strip-insertion decision stays covered by the unit-tested `show_strip_after`. (Empirically `cargo mutants --in-diff` was 0-missed both before and after — cargo-mutants doesn't mutate function-call conditions — so this is convention/defense, not a coverage fix.)
- **`handle_tree_key` comment** clarified that only *named* keys reach the `context_row` clear (bare character keys early-return).
- **Declined:** simplifier's optional `open_path_for_row` → `file_path_for_row` rename (pre-existing public symbol; keeping the PR scoped).
- **Manual smoke is the only verification of the `on_right_press` trigger** (it lives in the `#[mutants::skip]` widget and can't be unit-tested) — flagged for a human before merge.

## R3 review revisions (post-panel, commit `42bc45d`)

Of the four UI/UX items the R2 panel had marked non-blocking, the user directed: fix the cheap one now, track the rest as real issues (a PR-body note is not tracking).

- **F2 (owner-row highlight) — FIXED** in `42bc45d`. `build_row` takes `context_row`, computes `is_context_owner = row_is_selected(i, context_row)` (reusing the tested predicate), and the file-row style closure paints the owner with `extended_palette().background.weak.color` — the same surface as the strip band, so row + strip read as one block. No accent border (reserved for the keyboard cursor). Full panel re-dispatched (R3) → all four APPROVED.
- **F3 / F4 / F5 — filed as tracked GitHub issues** (not deferred-in-prose): #618 (scroll the strip into view when it opens near the bottom), #616 (keyboard Copy Path shortcut), #617 (dismiss on outside/background click). Each links back to this PR. Optional UI/UX polish (per-button hover affordance, a small top margin on the band) folded into the relevant issues' scope.
