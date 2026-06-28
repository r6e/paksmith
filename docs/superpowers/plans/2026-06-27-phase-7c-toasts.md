# Phase 7c PR1 — Toast Notifications Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a non-blocking toast-notification overlay to the GUI and route the first real consumer — open-failure-while-an-archive-is-loaded, which is currently swallowed — into an Error toast.

**Architecture:** Mirrors the established Phase 7a/7b split: pure iced-free state in `state/toast.rs` (unit + mutation tested), a thin `#[mutants::skip]` overlay widget in `widgets/toast.rs`, and wiring in `app.rs` (one state field, one message, one helper, one consumer). Toasts render as a bottom-trailing `stack` layer over the root column; auto-dismiss is a delayed `Task` per toast.

**Tech Stack:** Rust, iced 0.14 (`stack`, `container`, `button`), tokio `time` (already enabled via iced's `tokio` feature; used in `menu.rs`), `mutants` (`#[mutants::skip]`, already a dep).

**Scope note:** This is PR1 of the four-PR Phase 7c (see `docs/superpowers/specs/2026-06-27-phase-7c-gui-chrome-design.md`). It is the foundation the context-menu (PR2) and Export As… (PR3) consume. PR2–PR4 get their own plans when started.

## Global Constraints

Copied verbatim from the spec; every task implicitly includes these.

- GUI-only — **no `paksmith-core` changes** in this PR (the export façade is PR3).
- No new dependencies (toasts use iced built-ins; tokio `time` + `mutants` already present).
- No panics in core; `thiserror`/`Result` throughout (no core touched here regardless).
- MSRV 1.88 — no let-chains, no `if let` match guards. Use the two-guard / `let … else` forms already in `app.rs`.
- The full-area error banner (empty-state "open failed, no archive" + retry CTA) is **kept**; toasts handle transient, in-session feedback only.
- Toast severities are **Success and Error only** — no `Info` (no agreed trigger produces one).
- Auto-dismiss durations: Success `4s`, Error `8s` (named constants).
- Conventional commits (`feat(gui): …`); one logical change per commit.
- Before the PR's final push: `cargo fmt --all`, `cargo clippy --workspace --all-targets --all-features -D warnings`, `cargo test`, `cargo doc`, `typos .`, `cargo mutants --in-diff` to 0-missed, and the standing adversarial review panel + UI/UX reviewer to convergence. (These are PR-level gates; per-task steps run the focused subset.)

---

### Task 1: Pure toast state (`state/toast.rs`)

**Files:**
- Create: `crates/paksmith-gui/src/state/toast.rs`
- Modify: `crates/paksmith-gui/src/state/mod.rs` (add `pub mod toast;`)
- Test: in-file `#[cfg(test)] mod tests` (matches the crate's convention — see `state/hex_view.rs`, `state/tabs.rs`)

**Interfaces:**
- Consumes: nothing (leaf module; `std::time::Duration` only).
- Produces:
  - `Severity` (`Copy`): `Severity::Success`, `Severity::Error`; `Severity::ttl(self) -> std::time::Duration`.
  - consts `SUCCESS_TTL: Duration` (4s), `ERROR_TTL: Duration` (8s).
  - `Toast { pub id: u64, pub severity: Severity, pub message: String }` (`Clone`).
  - `Toasts` (`Default`): `push(&mut self, Severity, String) -> u64`, `remove(&mut self, u64)`, `items(&self) -> &[Toast]`, `is_empty(&self) -> bool`.

- [ ] **Step 1: Write the failing tests**

Create `crates/paksmith-gui/src/state/toast.rs` with only the test module first (the types come in Step 3):

```rust
//! Pure toast-notification state: a list of transient notifications with
//! per-severity auto-dismiss durations. iced-free; unit + mutation tested.

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn push_assigns_increasing_distinct_ids() {
        let mut toasts = Toasts::default();
        let a = toasts.push(Severity::Success, "one".to_string());
        let b = toasts.push(Severity::Error, "two".to_string());
        assert_ne!(a, b, "each toast gets a distinct id");
        assert!(b > a, "ids increase monotonically");
    }

    #[test]
    fn push_appends_in_order_and_preserves_fields() {
        let mut toasts = Toasts::default();
        let _ = toasts.push(Severity::Success, "first".to_string());
        let _ = toasts.push(Severity::Error, "second".to_string());
        let items = toasts.items();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].message, "first");
        assert_eq!(items[0].severity, Severity::Success);
        assert_eq!(items[1].message, "second");
        assert_eq!(items[1].severity, Severity::Error);
    }

    #[test]
    fn remove_removes_only_the_matching_id() {
        let mut toasts = Toasts::default();
        let keep = toasts.push(Severity::Success, "keep".to_string());
        let drop = toasts.push(Severity::Error, "drop".to_string());
        toasts.remove(drop);
        let items = toasts.items();
        assert_eq!(items.len(), 1, "exactly one toast removed");
        assert_eq!(items[0].id, keep, "the non-matching toast survives");
        assert_eq!(items[0].message, "keep");
    }

    #[test]
    fn remove_absent_id_is_a_noop() {
        let mut toasts = Toasts::default();
        let only = toasts.push(Severity::Success, "only".to_string());
        toasts.remove(only.wrapping_add(999)); // never issued
        assert_eq!(toasts.items().len(), 1, "removing an absent id changes nothing");
    }

    #[test]
    fn is_empty_reflects_contents() {
        let mut toasts = Toasts::default();
        assert!(toasts.is_empty(), "a fresh list is empty");
        let id = toasts.push(Severity::Error, "x".to_string());
        assert!(!toasts.is_empty(), "non-empty after a push");
        toasts.remove(id);
        assert!(toasts.is_empty(), "empty again after removing the last toast");
    }

    #[test]
    fn ttl_is_severity_specific_and_error_outlasts_success() {
        // Pins the exact constants AND that the match maps each arm correctly —
        // a swapped/duplicated arm would make these equal or wrong.
        assert_eq!(Severity::Success.ttl(), Duration::from_secs(4));
        assert_eq!(Severity::Error.ttl(), Duration::from_secs(8));
        assert!(
            Severity::Error.ttl() > Severity::Success.ttl(),
            "errors stay up longer than successes"
        );
    }
}
```

- [ ] **Step 2: Run tests to verify they fail (do not compile)**

Run: `cargo test -p paksmith-gui state::toast`
Expected: FAIL — `cannot find type 'Toasts'`, `'Severity'` (types not defined yet). Also add `pub mod toast;` to `crates/paksmith-gui/src/state/mod.rs` now (alphabetical position: `toast` sorts after `texture_view`; `cargo fmt` enforces this) or the module isn't compiled — without it the test target won't even see the file.

`crates/paksmith-gui/src/state/mod.rs` after edit:

```rust
pub mod archive;
pub mod hex_view;
pub mod keyflow;
pub mod profiles;
pub mod property_view;
pub mod tabs;
pub mod texture_view;
pub mod toast;
pub mod tree;
```

- [ ] **Step 3: Write the minimal implementation**

Prepend to `crates/paksmith-gui/src/state/toast.rs` (above the test module):

```rust
use std::time::Duration;

/// Auto-dismiss delay for a success toast.
pub const SUCCESS_TTL: Duration = Duration::from_secs(4);
/// Auto-dismiss delay for an error toast — longer, so failures can be read.
pub const ERROR_TTL: Duration = Duration::from_secs(8);

/// Toast severity — drives tint and auto-dismiss duration. No `Info`: no
/// agreed trigger produces one (see the Phase 7c design spec).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Success,
    Error,
}

impl Severity {
    /// How long a toast of this severity stays up before auto-expiring.
    #[must_use]
    pub fn ttl(self) -> Duration {
        match self {
            Severity::Success => SUCCESS_TTL,
            Severity::Error => ERROR_TTL,
        }
    }
}

/// A single transient notification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Toast {
    /// Stable id used to schedule auto-expiry and to target manual dismissal.
    pub id: u64,
    pub severity: Severity,
    pub message: String,
}

/// The app's live toast list plus its monotonic id source.
#[derive(Debug, Default)]
pub struct Toasts {
    items: Vec<Toast>,
    next_id: u64,
}

impl Toasts {
    /// Push a new toast; returns its id so the caller can schedule auto-expiry.
    pub fn push(&mut self, severity: Severity, message: String) -> u64 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.items.push(Toast { id, severity, message });
        id
    }

    /// Remove the toast with `id` if present (no-op otherwise). Used by both
    /// manual dismiss and auto-expiry, so it is idempotent — a late expiry after
    /// a manual dismiss does nothing.
    pub fn remove(&mut self, id: u64) {
        self.items.retain(|t| t.id != id);
    }

    /// The current toasts, oldest first.
    #[must_use]
    pub fn items(&self) -> &[Toast] {
        &self.items
    }

    /// Whether there are any toasts (so `view` can skip the overlay layer).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p paksmith-gui state::toast`
Expected: PASS — 6 tests.

- [ ] **Step 5: fmt + clippy + commit**

```bash
cargo fmt --all
cargo clippy -p paksmith-gui --all-targets --all-features -- -D warnings
git add crates/paksmith-gui/src/state/toast.rs crates/paksmith-gui/src/state/mod.rs
git commit -m "feat(gui): add pure toast-notification state (phase 7c)"
```

---

### Task 2: App wiring — field, message, push helper, and the swallowed-error consumer (`app.rs`)

**Files:**
- Modify: `crates/paksmith-gui/src/app.rs` — add the `toasts` field + default; add `Message::ToastDismissed(u64)`; add `push_toast` helper; add the `ToastDismissed` update arm; change the `ArchiveOpened(Err(OpenError::Core(_)))` arm.
- Test: `app.rs`'s existing `#[cfg(test)] mod tests`.

**Interfaces:**
- Consumes (from Task 1): `crate::state::toast::{Severity, Toasts}`, `Toasts::push`, `Toasts::remove`, `Toasts::items`, `Severity::ttl`.
- Produces (for Task 3): `App.toasts: crate::state::toast::Toasts`; `Message::ToastDismissed(u64)`.

- [ ] **Step 1: Write the failing tests**

Add to the `tests` module at the bottom of `crates/paksmith-gui/src/app.rs` (it already has `use super::*;` and `use crate::state::archive::{EntryMeta, LoadedArchive};`):

```rust
// ── toast consumer: open-failure-while-loaded ─────────────────────────────

use crate::state::archive::OpenError;
use crate::state::toast::Severity;

#[test]
fn open_error_while_archive_loaded_pushes_error_toast_not_banner() {
    // An archive is already open. A failed open of another file would set
    // `app.error`, but `view` shows the archive (the Some(archive) branch wins),
    // so the banner never renders — the error is swallowed. It must become a toast.
    let mut app = app_with_paths(&["Game/A.uasset"]);
    let _ = update(
        &mut app,
        Message::ArchiveOpened(Box::new(Err(OpenError::Core("boom".to_string())))),
    );
    assert_eq!(app.toasts.items().len(), 1, "one error toast pushed");
    assert_eq!(app.toasts.items()[0].severity, Severity::Error);
    assert!(
        app.toasts.items()[0].message.contains("boom"),
        "toast carries the core error message"
    );
    assert!(
        app.error.is_none(),
        "no full-area banner when an archive is open"
    );
}

#[test]
fn open_error_with_no_archive_uses_banner_not_toast() {
    // Empty state: the full-area banner (with the retry CTA) is the right home,
    // so no toast and `app.error` is set.
    let mut app = App::default();
    let _ = update(
        &mut app,
        Message::ArchiveOpened(Box::new(Err(OpenError::Core("nope".to_string())))),
    );
    assert!(app.toasts.is_empty(), "no toast in the empty state");
    assert_eq!(app.error.as_deref(), Some("nope"), "banner error is set");
}

#[test]
fn open_error_mid_keyflow_sets_keyflow_error_no_toast() {
    // Mid key-entry (wrong manual key): the error belongs inside the key panel.
    let mut app = App::default();
    app.keyflow.lock(PathBuf::from("locked.pak"));
    let _ = update(
        &mut app,
        Message::ArchiveOpened(Box::new(Err(OpenError::Core("bad key".to_string())))),
    );
    assert!(app.toasts.is_empty(), "no toast during the key flow");
    assert!(app.error.is_none(), "no banner during the key flow");
}

#[test]
fn toast_dismissed_removes_the_targeted_toast() {
    let mut app = App::default();
    let id = app.toasts.push(Severity::Error, "x".to_string());
    let _ = update(&mut app, Message::ToastDismissed(id));
    assert!(app.toasts.is_empty(), "dismiss removes the toast");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p paksmith-gui app::tests::open_error_while_archive_loaded_pushes_error_toast_not_banner`
Expected: FAIL — `no field 'toasts' on type '&App'` / `no variant 'ToastDismissed'`.

- [ ] **Step 3: Add the `toasts` field + default**

In `crates/paksmith-gui/src/app.rs`, add the field to `struct App` (after `archive_generation: u64,`):

```rust
    /// Live transient notifications (errors + action feedback), rendered as a
    /// non-blocking overlay. See `state::toast`.
    pub toasts: crate::state::toast::Toasts,
```

And initialize it in `impl Default for App` (after `archive_generation: 0,`):

```rust
            toasts: crate::state::toast::Toasts::default(),
```

- [ ] **Step 4: Add the message variant**

In `enum Message`, add (after `OpenAsset(String)` or anywhere in the enum — group it logically near the end):

```rust
    /// Remove the toast with this id — used by both the `×` button and the
    /// scheduled auto-expiry task.
    ToastDismissed(u64),
```

- [ ] **Step 5: Add the `push_toast` helper**

Add near the other free helpers in `app.rs` (e.g. just below `copy_from_active_hex`):

```rust
/// Push a toast and return the task that auto-dismisses it after its severity's
/// TTL. The scheduled message reuses [`Message::ToastDismissed`], so it is a
/// no-op if the user already dismissed the toast manually.
fn push_toast(
    app: &mut App,
    severity: crate::state::toast::Severity,
    message: String,
) -> Task<Message> {
    let id = app.toasts.push(severity, message);
    let ttl = severity.ttl();
    Task::perform(
        async move { tokio::time::sleep(ttl).await },
        move |()| Message::ToastDismissed(id),
    )
}
```

- [ ] **Step 6: Add the `ToastDismissed` update arm**

In `update`'s `match message`, add an arm (e.g. after `Message::DismissAbout`):

```rust
        Message::ToastDismissed(id) => {
            app.toasts.remove(id);
            Task::none()
        }
```

- [ ] **Step 7: Route the swallowed open-error into a toast**

Replace the existing `Err(OpenError::Core(msg))` arm inside `Message::ArchiveOpened(boxed)` (currently lines ~259–268):

```rust
            Err(OpenError::Core(msg)) => {
                if app.keyflow.is_locked().is_some() {
                    // Mid-key-flow (e.g. wrong manual key) — show inside the panel.
                    app.keyflow.set_error(msg);
                    Task::none()
                } else if app.archive.is_some() {
                    // An archive is already open, so the full-area error banner in
                    // `view` would never render (the `Some(archive)` branch wins).
                    // Surface the failure as a non-blocking toast instead.
                    push_toast(
                        app,
                        crate::state::toast::Severity::Error,
                        format!("Couldn't open file: {msg}"),
                    )
                } else {
                    // No archive: the empty-state banner (with retry CTA) is right.
                    app.error = Some(msg);
                    Task::none()
                }
            }
```

- [ ] **Step 8: Run the new tests + the full gui lib tests**

Run: `cargo test -p paksmith-gui`
Expected: PASS — the 4 new tests plus all pre-existing tests (≥ 296 + 6 from Task 1 + 4 here).

- [ ] **Step 9: fmt + clippy + commit**

```bash
cargo fmt --all
cargo clippy -p paksmith-gui --all-targets --all-features -- -D warnings
git add crates/paksmith-gui/src/app.rs
git commit -m "feat(gui): surface open-while-loaded errors as toasts (phase 7c)"
```

---

### Task 3: Toast overlay widget + view integration (`widgets/toast.rs`, `app.rs`)

**Files:**
- Create: `crates/paksmith-gui/src/widgets/toast.rs`
- Modify: `crates/paksmith-gui/src/widgets/mod.rs` (add `pub mod toast;`)
- Modify: `crates/paksmith-gui/src/app.rs` — wrap the root `column!` in a `stack` overlay in `view`.

**Interfaces:**
- Consumes: `crate::state::toast::{Severity, Toasts}`, `Toasts::items`, `Toasts::is_empty`; `crate::app::Message::ToastDismissed`.
- Produces: `crate::widgets::toast::overlay(&Toasts) -> iced::Element<'_, Message>`.

This task is a thin view layer — `#[mutants::skip]`, no unit tests (matches every other widget in the crate; all testable logic lives in `state/toast.rs`). It is verified by compile + clippy + a manual run + the standing UI/UX reviewer.

- [ ] **Step 1: Create the overlay widget**

Create `crates/paksmith-gui/src/widgets/toast.rs`:

```rust
//! Thin toast-overlay widget: renders the live toast list as a bottom-trailing
//! stack of cards. All logic lives in `state/toast.rs`; this is rendering only.
//! Exact card/button colours are cosmetic and tuned under the UI/UX review.

use iced::widget::{button, column, container, row, text};
use iced::{Element, Length};

use crate::app::Message;
use crate::state::toast::{Severity, Toasts};
use crate::theme::tokens::{RADIUS, SPACE_MD, SPACE_SM, TEXT_SM};

/// Bottom-trailing toast overlay for the `stack` layer. The container fills the
/// area but is click-through (a plain container ignores mouse events it does not
/// handle, so they pass to the layer below); only each card's `×` button
/// captures clicks.
#[mutants::skip] // pure iced view composition; logic lives in state/toast.rs
pub fn overlay(toasts: &Toasts) -> Element<'_, Message> {
    let cards = toasts
        .items()
        .iter()
        .fold(column![].spacing(SPACE_SM), |col, t| {
            col.push(card(t.id, t.severity, &t.message))
        });
    container(cards)
        .align_right(Length::Fill)
        .align_bottom(Length::Fill)
        .padding(SPACE_MD)
        .into()
}

#[mutants::skip]
fn card(id: u64, severity: Severity, message: &str) -> Element<'static, Message> {
    let dismiss = button(text("\u{00d7}").size(f32::from(TEXT_SM)))
        .padding([0.0, SPACE_SM])
        .style(iced::widget::button::text)
        .on_press(Message::ToastDismissed(id));

    let body = row![
        text(message.to_owned()).size(f32::from(TEXT_SM)),
        dismiss,
    ]
    .spacing(SPACE_SM)
    .align_y(iced::Alignment::Center);

    container(body)
        .padding([SPACE_SM, SPACE_MD])
        .style(move |theme: &iced::Theme| {
            let palette = theme.extended_palette();
            let pair = match severity {
                Severity::Success => palette.success.base,
                Severity::Error => palette.danger.base,
            };
            iced::widget::container::Style {
                background: Some(iced::Background::Color(pair.color)),
                text_color: Some(pair.text),
                border: iced::Border {
                    radius: RADIUS.into(),
                    ..Default::default()
                },
                ..Default::default()
            }
        })
        .into()
}
```

- [ ] **Step 2: Register the module**

Add to `crates/paksmith-gui/src/widgets/mod.rs` (alphabetical, after `pub mod tab_bar;`):

```rust
pub mod toast;
```

- [ ] **Step 3: Wrap the root view in the overlay**

In `crates/paksmith-gui/src/app.rs`, at the end of `view`, replace the final compose block:

```rust
    // ── compose ───────────────────────────────────────────────────────────────
    let root = column![toolbar_view, body, status_view]
        .width(Length::Fill)
        .height(Length::Fill);

    if app.toasts.is_empty() {
        root.into()
    } else {
        iced::widget::stack([
            root.into(),
            crate::widgets::toast::overlay(&app.toasts),
        ])
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
    }
```

(`view` is already `#[mutants::skip]`, so this rendering branch needs no mutation coverage; `Toasts::is_empty` is covered in Task 1.)

- [ ] **Step 4: Build + clippy + full lib tests**

Run:
```bash
cargo build -p paksmith-gui
cargo clippy -p paksmith-gui --all-targets --all-features -- -D warnings
cargo test -p paksmith-gui
```
Expected: builds clean, no clippy warnings, all tests pass.

- [ ] **Step 5: Manual verification**

Run the GUI (`cargo run -p paksmith-gui`), open a valid `.pak`, then use File → Open (or the toolbar Open) to open a **non-pak / corrupt** file. Expected: a red toast "Couldn't open file: …" appears bottom-right over the still-interactive explorer, and auto-dismisses after ~8s; the `×` button dismisses it immediately. The previously-open archive stays visible (no full-area banner). Confirm the rest of the UI remains clickable while a toast is showing.

- [ ] **Step 6: Commit**

```bash
cargo fmt --all
git add crates/paksmith-gui/src/widgets/toast.rs crates/paksmith-gui/src/widgets/mod.rs crates/paksmith-gui/src/app.rs
git commit -m "feat(gui): render toast overlay in the app view (phase 7c)"
```

---

## PR-level finish (after Task 3)

- [ ] Run the full local gate (matches CI):
  ```bash
  cargo fmt --all --check
  cargo clippy --workspace --all-targets --all-features -- -D warnings
  cargo test
  cargo doc --workspace --no-deps
  typos .
  ```
- [ ] `cargo mutants --in-diff <(git diff origin/main...HEAD)` scoped to `paksmith-gui` → 0 missed. (`state/toast.rs` carries the mutated logic; the widget + view are `#[mutants::skip]`.)
- [ ] Dispatch the standing adversarial review panel (≥3: general / architect / simplifier) + a UI/UX reviewer on the toast widget, briefed cold. Cycle to convergence (every reviewer APPROVED, no unresolved findings).
- [ ] Push the branch to `feat/phase-7c-toasts` and open the PR (with explicit user go-ahead — never push without it).

## Self-Review (performed against the spec)

**Spec coverage (PR1 scope only):** Toast state + lifecycle (Task 1) ✓; `stack` overlay, bottom-trailing, severity tint, `×` dismiss (Task 3) ✓; auto-dismiss via delayed `Task`, Success 4s / Error 8s (Tasks 1+2) ✓; one real consumer = open-while-loaded error (Task 2) ✓; banner kept for empty state (Task 2) ✓; no `Info` severity ✓; GUI-only, no new deps ✓. Context menu / Export As… / debug console are out of PR1 scope (PR2–PR4).

**Placeholder scan:** none — every code step shows complete code; every run step shows the command + expected result.

**Type consistency:** `Severity`, `Toasts`, `push`/`remove`/`items`/`is_empty`, `ttl`, `Message::ToastDismissed(u64)`, and `push_toast` signatures match across Tasks 1–3. The widget consumes exactly the names Task 1 produces and the message Task 2 produces.
