# Phase 7c PR4 — Debug Console Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an in-app, filterable debug console to the Paksmith GUI that captures `tracing` events into a bounded ring buffer and renders them with min-level / target / search filters, Clear, and Copy-all, toggled by F12 or the View menu.

**Architecture:** A `tracing_subscriber::Layer` (`RingBufferLayer`) writes every event into a shared, cap-bounded `LogBuffer` (`Arc<Mutex<VecDeque<LogRecord>>>`) installed once in `main`. The GUI reads a snapshot of that ring each frame and filters it through pure functions in `state/console.rs`. The console panel is a thin `#[mutants::skip]` view; all decision logic lives in unit+mutation-tested pure helpers. A `console_visible`-gated timer subscription drives live refresh, since background ring mutation does not itself trigger an iced re-render.

**Tech Stack:** Rust, iced 0.14 (Elm-style), `tracing` 0.1, `tracing-subscriber` 0.3 (`env-filter` feature), `muda` 0.19 (native menu).

## Global Constraints

- **GUI-scoped, plus one manifest hoist.** All code changes are in `crates/paksmith-gui`. The single exception: `tracing-subscriber` becomes a second occurrence (already a direct dep of `paksmith-cli`), so it is hoisted to `[workspace.dependencies]` and both crates switch to `workspace = true`. This touches `Cargo.toml` and `crates/paksmith-cli/Cargo.toml` (manifest only, no logic). Deliberate, per the DRY-on-second-occurrence convention.
- **No new core surface.** Unlike PR3, PR4 adds no `paksmith-core` API.
- **Never bump `Cargo.toml` `version =` fields** (release-please owns them). The hoist edits dependency tables, not package versions.
- **MSRV 1.88.** No let-chains, no if-let match guards. `std::sync::LazyLock` is allowed (stable 1.80). `is_some_and` is allowed (stable 1.70).
- **No panics in GUI paths that touch the ring.** `LogBuffer` lock acquisition recovers from poisoning (`unwrap_or_else(|e| e.into_inner())`); the console must never panic the app.
- **Pure / thin / async split** (established Phase 7 convention): pure logic in `state/` (unit+mutation tested); thin rendering in `panels/` and `widgets/` marked `#[mutants::skip]`; `Message` arms in `app.rs::update`. A `Message` variant that is *matched* but never *constructed* is a `dead_code` ERROR under `clippy -D warnings --all-targets`; every variant ships in the same commit as its constructor.
- **TDD:** failing test first, watch it fail, implement, watch it pass, commit.
- **Capture floor matches the level selector.** The min-level `pick_list` offers all five `tracing::Level` values; the default capture filter is `warn,paksmith_*=debug` (RUST_LOG-overridable) so DEBUG is a live option, not a dead one, while dependency INFO chatter stays out of the ring.
- **Conventional commits:** `feat(gui): …`, `test(gui): …`, `chore(deps): …`.
- **Local gates before any push (controller-run, CI-matching):** `cargo fmt --all`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace --all-features`, `cargo doc --workspace --no-deps` with `-D warnings`, `typos .`, `cargo minimal-versions check --direct --all-features`, and `cargo mutants --in-diff` against `origin/main...HEAD` with **0 missed**.

---

## File Structure

**Create:**
- `crates/paksmith-gui/src/state/log_buffer.rs` — `LogRecord`, `LogBuffer` (bounded ring + monotonic seq), `RingBufferLayer` (the tracing `Layer`) + `MessageVisitor`, `init_console_tracing`. Pure ring logic is unit+mutation tested; the `Layer` is integration-tested via a scoped subscriber.
- `crates/paksmith-gui/src/state/console.rs` — `ConsoleFilters`, `LEVEL_CHOICES`, `matches`, `displayed`, `copy_all`, `format_line`, `at_bottom`. All pure, unit+mutation tested.
- `crates/paksmith-gui/src/panels/console.rs` — thin `#[mutants::skip]` `view`, `SCROLL_ID`. Renders the filtered ring snapshot.

**Modify:**
- `Cargo.toml` — add `tracing-subscriber` to `[workspace.dependencies]`.
- `crates/paksmith-cli/Cargo.toml` — switch its `tracing-subscriber` line to `workspace = true`.
- `crates/paksmith-gui/Cargo.toml` — add `tracing-subscriber.workspace = true`.
- `crates/paksmith-gui/src/state/mod.rs` — add `pub mod console;` and `pub mod log_buffer;`.
- `crates/paksmith-gui/src/panels/mod.rs` — add `pub mod console;`.
- `crates/paksmith-gui/src/main.rs` — install the subscriber and inject `LogBuffer` into `App` via a boot closure.
- `crates/paksmith-gui/src/menu.rs` — add `MenuAction::ToggleConsole`, `ID_TOGGLE_CONSOLE`, the View "Debug Console" item, and tests.
- `crates/paksmith-gui/src/app.rs` — `App` fields (`console_visible`, `log_buffer`, `console_follow`, `console_filters`); `Message` variants; `update` arms; `subscription()` rewrite (F12 listener, tick, tree-F12 exclusion); `handle_tree_key` F12 guard; `view()` root insertion.

---

## Notable design decisions (surfaced for approval)

These are deliberate choices a reviewer might otherwise question — confirm before execution:

1. **F12 is an always-on listener, a conscious deviation from the spec.** The spec (§4) says F12 is "added to the existing key subscription." That subscription is gated on an open archive, so F12 wouldn't work before opening a pak — exactly when startup/open-error logs matter most. Instead F12 gets its own `listen_with` that is always active, and is explicitly *excluded* from the archive-gated tree-key listener (which clears the context/export menus on any named key — see `app.rs:981`). A `handle_tree_key` F12 no-op guard backs this as a tested safety net.
2. **Live refresh via a `console_visible`-gated timer.** Background ring writes from worker threads do not trigger an iced re-render; without a tick the console would only update when the user clicks something. A ~300ms `iced::time::every` tick runs only while the console is visible.
3. **The `tracing-subscriber` workspace hoist** touches `paksmith-cli/Cargo.toml` (manifest only). It's the one non-GUI file in the PR.
4. **Capture floor `warn,paksmith_*=debug`** (RUST_LOG-overridable) so the DEBUG pick_list option shows real records while dependency (wgpu/naga/iced) INFO chatter stays out of the ring. TRACE is offered but yields no extra records unless RUST_LOG widens capture — documented, not dead.

---

## Task 1: Pure log buffer and console filtering

The load-bearing, fully-testable core. Lands independently: `mod state` is `#[allow(dead_code)]`, so these `pub` items compile clean with no GUI wiring. No `Message`/`App` changes.

**Files:**
- Modify: `Cargo.toml` (workspace deps)
- Modify: `crates/paksmith-cli/Cargo.toml`
- Modify: `crates/paksmith-gui/Cargo.toml`
- Modify: `crates/paksmith-gui/src/state/mod.rs`
- Create: `crates/paksmith-gui/src/state/log_buffer.rs`
- Create: `crates/paksmith-gui/src/state/console.rs`

**Interfaces:**
- Produces (consumed by Tasks 2–3):
  - `crate::state::log_buffer::LogBuffer` — `Clone + Default`; `push(&self, level: tracing::Level, target: String, message: String)`, `clear(&self)`, `snapshot(&self) -> Vec<LogRecord>`.
  - `crate::state::log_buffer::LogRecord` — `{ seq: u64, level: tracing::Level, target: String, message: String }`, `Clone`.
  - `crate::state::log_buffer::RingBufferLayer` — `new(LogBuffer) -> Self`, `impl Layer`.
  - `crate::state::log_buffer::init_console_tracing(buffer: LogBuffer)`.
  - `crate::state::console::ConsoleFilters` — `{ min_level: tracing::Level, target_filter: String, search: String }`, `Clone + Default`.
  - `crate::state::console::LEVEL_CHOICES: [tracing::Level; 5]`.
  - `crate::state::console::displayed<'a>(&'a [LogRecord], &ConsoleFilters) -> Vec<&'a LogRecord>`.
  - `crate::state::console::copy_all(&[LogRecord], &ConsoleFilters) -> String`.
  - `crate::state::console::format_line(&LogRecord) -> String`.
  - `crate::state::console::at_bottom(relative_y: f32) -> bool`.

- [ ] **Step 1: Hoist `tracing-subscriber` to the workspace and add the GUI dep**

In `Cargo.toml`, under `[workspace.dependencies]`, add after the `tracing = "0.1.40"` line:

```toml
tracing = "0.1.40"
# Used by paksmith-cli (fmt subscriber) and paksmith-gui (ring-buffer Layer for
# the debug console). `env-filter` provides EnvFilter for RUST_LOG-driven
# capture levels. Single workspace floor keeps Minimal-versions resolution
# consistent across both consumers.
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
```

In `crates/paksmith-cli/Cargo.toml`, replace:

```toml
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
```

with:

```toml
tracing-subscriber.workspace = true
```

In `crates/paksmith-gui/Cargo.toml`, add to `[dependencies]` next to the existing `tracing.workspace = true` line:

```toml
tracing.workspace = true
tracing-subscriber.workspace = true
```

- [ ] **Step 2: Verify the manifests resolve unchanged**

Run: `cargo build -p paksmith-cli -p paksmith-gui`
Expected: builds clean; `Cargo.lock` still pins `tracing-subscriber 0.3.23` (no resolution change — the floor and features are identical to cli's prior direct line).

- [ ] **Step 3: Register the two new state modules**

In `crates/paksmith-gui/src/state/mod.rs`, add the two modules in alphabetical position:

```rust
pub mod archive;
pub mod console;
pub mod export;
pub mod hex_view;
pub mod keyflow;
pub mod log_buffer;
pub mod profiles;
pub mod property_view;
pub mod tabs;
pub mod texture_view;
pub mod toast;
pub mod tree;
```

- [ ] **Step 4: Write the failing `log_buffer` tests**

Create `crates/paksmith-gui/src/state/log_buffer.rs` with ONLY the test module first (the rest is added in Step 6). Put this at the bottom of the file:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tracing::Level;

    #[test]
    fn push_assigns_monotonic_seq_from_zero() {
        let b = LogBuffer::default();
        b.push(Level::INFO, "t".into(), "a".into());
        b.push(Level::WARN, "t".into(), "b".into());
        b.push(Level::ERROR, "t".into(), "c".into());
        let seqs: Vec<u64> = b.snapshot().iter().map(|r| r.seq).collect();
        assert_eq!(seqs, vec![0, 1, 2]);
    }

    #[test]
    fn ring_is_full_predicate_is_exact_at_capacity_boundary() {
        assert!(!ring_is_full(CONSOLE_RING_CAPACITY - 1));
        assert!(ring_is_full(CONSOLE_RING_CAPACITY));
        assert!(ring_is_full(CONSOLE_RING_CAPACITY + 1));
    }

    #[test]
    fn ring_evicts_oldest_beyond_capacity() {
        let b = LogBuffer::default();
        for i in 0..(CONSOLE_RING_CAPACITY + 5) {
            b.push(Level::INFO, "t".into(), format!("m{i}"));
        }
        let r = b.snapshot();
        assert_eq!(r.len(), CONSOLE_RING_CAPACITY);
        // First 5 evicted: oldest retained is m5 at seq 5; newest is the last push.
        assert_eq!(r.first().unwrap().message, "m5");
        assert_eq!(r.first().unwrap().seq, 5);
        assert_eq!(
            r.last().unwrap().message,
            format!("m{}", CONSOLE_RING_CAPACITY + 4)
        );
    }

    #[test]
    fn clear_empties_but_seq_stays_monotonic() {
        let b = LogBuffer::default();
        b.push(Level::INFO, "t".into(), "a".into());
        b.clear();
        assert!(b.snapshot().is_empty());
        b.push(Level::INFO, "t".into(), "b".into());
        let r = b.snapshot();
        assert_eq!(r.len(), 1);
        // Continues from before the clear (1), never reused back to 0.
        assert_eq!(r[0].seq, 1);
    }

    #[test]
    fn ring_layer_captures_level_target_and_message() {
        use tracing_subscriber::layer::SubscriberExt as _;
        let buffer = LogBuffer::default();
        let subscriber =
            tracing_subscriber::registry().with(RingBufferLayer::new(buffer.clone()));
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: "paksmith_test", "hello {}", "world");
        });
        let r = buffer.snapshot();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].level, Level::INFO);
        assert_eq!(r[0].target, "paksmith_test");
        assert_eq!(r[0].message, "hello world");
    }
}
```

- [ ] **Step 5: Run the tests to verify they fail**

Run: `cargo test -p paksmith-gui log_buffer`
Expected: FAIL to compile — `LogBuffer`, `ring_is_full`, `RingBufferLayer`, `CONSOLE_RING_CAPACITY` are not defined.

- [ ] **Step 6: Implement `log_buffer`**

Insert this ABOVE the `#[cfg(test)]` module in `crates/paksmith-gui/src/state/log_buffer.rs`:

```rust
//! Bounded in-memory ring buffer of `tracing` events for the debug console.
//!
//! A [`RingBufferLayer`] (installed once in `main`) writes every event into a
//! shared [`LogBuffer`]; the GUI reads a [`LogBuffer::snapshot`] each frame.
//! Pure ring logic is unit + mutation tested; the `Layer`/`Visit` glue is
//! integration-tested via a scoped subscriber.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, Layer};

/// Maximum number of records retained. Oldest are evicted first.
const CONSOLE_RING_CAPACITY: usize = 2000;

/// One captured log event.
#[derive(Debug, Clone)]
pub struct LogRecord {
    /// Monotonic sequence number assigned at capture (stable ordering key).
    pub seq: u64,
    /// Severity level.
    pub level: Level,
    /// Event target (module path or an explicit `target:`).
    pub target: String,
    /// Rendered message: the `message` field plus any `key=value` fields.
    pub message: String,
}

#[derive(Default)]
struct RingState {
    records: VecDeque<LogRecord>,
    next_seq: u64,
}

/// A cloneable handle to the shared, bounded log ring.
///
/// Cloning shares the same underlying buffer (`Arc`). The tracing `Layer`
/// holds one clone (writer); the GUI `App` holds another (reader).
#[derive(Clone, Default)]
pub struct LogBuffer {
    inner: Arc<Mutex<RingState>>,
}

/// True when a ring holding `len` records is at capacity and must evict before
/// the next push. Extracted as a pure predicate so the boundary is
/// mutation-tested on both sides, independent of the push path's invariant.
fn ring_is_full(len: usize) -> bool {
    len >= CONSOLE_RING_CAPACITY
}

impl LogBuffer {
    /// Append a record, evicting the oldest if at capacity, and assign the next
    /// sequence number. The lock is held only for the push — never across an
    /// `.await`.
    pub fn push(&self, level: Level, target: String, message: String) {
        // A poisoned lock means a prior holder panicked mid-mutation; recover
        // the guard and continue. We only append, so losing atomicity is
        // harmless, and a debug console must never panic the app.
        let mut state = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let seq = state.next_seq;
        state.next_seq += 1;
        if ring_is_full(state.records.len()) {
            state.records.pop_front();
        }
        state.records.push_back(LogRecord {
            seq,
            level,
            target,
            message,
        });
    }

    /// Remove all records. Sequence numbering continues (monotonic across
    /// clears) so a later record never reuses an earlier seq.
    pub fn clear(&self) {
        let mut state = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        state.records.clear();
    }

    /// Snapshot the current records (oldest first) for rendering. Clones the
    /// retained records (≤ capacity); called only while the console is visible.
    pub fn snapshot(&self) -> Vec<LogRecord> {
        let state = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        state.records.iter().cloned().collect()
    }
}

/// A `tracing` layer that records every event into a [`LogBuffer`].
pub struct RingBufferLayer {
    buffer: LogBuffer,
}

impl RingBufferLayer {
    pub fn new(buffer: LogBuffer) -> Self {
        Self { buffer }
    }
}

impl<S: Subscriber> Layer<S> for RingBufferLayer {
    // Event-wiring glue: needs a live tracing dispatcher to exercise, covered
    // by `ring_layer_captures_*` via `with_default`, not mutation-tested.
    #[mutants::skip]
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);
        self.buffer.push(
            *meta.level(),
            meta.target().to_string(),
            visitor.into_message(),
        );
    }
}

/// Collects the `message` field and appends any other fields as ` key=value`.
#[derive(Default)]
struct MessageVisitor {
    message: String,
    fields: String,
}

impl MessageVisitor {
    fn into_message(self) -> String {
        if self.fields.is_empty() {
            self.message
        } else if self.message.is_empty() {
            self.fields.trim_start().to_string()
        } else {
            format!("{}{}", self.message, self.fields)
        }
    }
}

impl Visit for MessageVisitor {
    // All typed `record_*` default to `record_debug`, so overriding this one
    // captures every field. Trait glue — integration-tested, not mutated.
    #[mutants::skip]
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}");
        } else {
            self.fields
                .push_str(&format!(" {}={:?}", field.name(), value));
        }
    }
}

/// Install a global tracing subscriber that records events into `buffer`.
///
/// Capture floor defaults to `warn` for dependencies plus `debug` for the
/// paksmith crates, overridable via `RUST_LOG`. The `warn` floor keeps
/// wgpu/naga/iced INFO chatter out of the bounded ring so the console reads as
/// paksmith-focused. A no-op if a subscriber is already installed (e.g. in
/// tests) — never panics.
#[mutants::skip] // global one-shot subscriber install; not unit-testable
pub fn init_console_tracing(buffer: LogBuffer) {
    use tracing_subscriber::EnvFilter;
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new("warn,paksmith_core=debug,paksmith_gui=debug")
    });
    let _ = tracing_subscriber::registry()
        .with(RingBufferLayer::new(buffer))
        .with(filter)
        .try_init();
}
```

- [ ] **Step 7: Run the `log_buffer` tests to verify they pass**

Run: `cargo test -p paksmith-gui log_buffer`
Expected: PASS (5 tests).

- [ ] **Step 8: Write the failing `console` tests**

Create `crates/paksmith-gui/src/state/console.rs` with ONLY the test module first:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::log_buffer::LogRecord;
    use tracing::Level;

    fn rec(level: Level, target: &str, message: &str) -> LogRecord {
        LogRecord {
            seq: 0,
            level,
            target: target.into(),
            message: message.into(),
        }
    }

    #[test]
    fn min_level_warn_shows_error_and_warn_hides_less_severe() {
        let f = ConsoleFilters {
            min_level: Level::WARN,
            ..Default::default()
        };
        assert!(matches(&rec(Level::ERROR, "t", "m"), &f), "ERROR more severe");
        assert!(matches(&rec(Level::WARN, "t", "m"), &f), "WARN at threshold");
        assert!(!matches(&rec(Level::INFO, "t", "m"), &f), "INFO less severe");
        assert!(!matches(&rec(Level::DEBUG, "t", "m"), &f));
        assert!(!matches(&rec(Level::TRACE, "t", "m"), &f));
    }

    #[test]
    fn default_filters_show_every_level() {
        let f = ConsoleFilters::default();
        for lvl in LEVEL_CHOICES {
            assert!(matches(&rec(lvl, "t", "m"), &f), "{lvl} should pass default");
        }
    }

    #[test]
    fn target_and_search_are_substring_filters() {
        let ft = ConsoleFilters {
            target_filter: "core".into(),
            ..Default::default()
        };
        assert!(matches(&rec(Level::INFO, "paksmith_core::pak", "m"), &ft));
        assert!(!matches(&rec(Level::INFO, "paksmith_gui::app", "m"), &ft));

        let fs = ConsoleFilters {
            search: "decode".into(),
            ..Default::default()
        };
        assert!(matches(&rec(Level::INFO, "t", "texture decode ok"), &fs));
        assert!(!matches(&rec(Level::INFO, "t", "open ok"), &fs));
    }

    #[test]
    fn displayed_keeps_capture_order_after_filtering() {
        let records = vec![
            rec(Level::INFO, "a", "1"),
            rec(Level::DEBUG, "b", "2"),
            rec(Level::ERROR, "c", "3"),
        ];
        let f = ConsoleFilters {
            min_level: Level::INFO,
            ..Default::default()
        };
        let shown = displayed(&records, &f);
        let targets: Vec<&str> = shown.iter().map(|r| r.target.as_str()).collect();
        assert_eq!(targets, vec!["a", "c"]); // DEBUG dropped, order preserved
    }

    #[test]
    fn level_label_covers_all_five_levels() {
        assert_eq!(level_label(Level::ERROR), "ERROR");
        assert_eq!(level_label(Level::WARN), "WARN");
        assert_eq!(level_label(Level::INFO), "INFO");
        assert_eq!(level_label(Level::DEBUG), "DEBUG");
        assert_eq!(level_label(Level::TRACE), "TRACE");
    }

    #[test]
    fn format_line_is_padded_level_target_message() {
        assert_eq!(
            format_line(&rec(Level::WARN, "paksmith_core", "low disk")),
            "WARN  paksmith_core low disk"
        );
        assert_eq!(format_line(&rec(Level::ERROR, "x", "boom")), "ERROR x boom");
    }

    #[test]
    fn copy_all_joins_displayed_lines_with_newlines() {
        let records = vec![
            rec(Level::INFO, "a", "first"),
            rec(Level::TRACE, "b", "skipme"),
            rec(Level::ERROR, "c", "second"),
        ];
        let f = ConsoleFilters {
            min_level: Level::INFO,
            ..Default::default()
        };
        assert_eq!(copy_all(&records, &f), "INFO  a first\nERROR c second");
    }

    #[test]
    fn at_bottom_is_exact_at_the_follow_threshold() {
        assert!(at_bottom(1.0));
        assert!(at_bottom(0.999));
        assert!(!at_bottom(0.99));
        assert!(!at_bottom(0.3));
        assert!(!at_bottom(0.0));
    }
}
```

- [ ] **Step 9: Run the tests to verify they fail**

Run: `cargo test -p paksmith-gui console`
Expected: FAIL to compile — `ConsoleFilters`, `matches`, `displayed`, `level_label`, `format_line`, `copy_all`, `at_bottom`, `LEVEL_CHOICES` undefined.

- [ ] **Step 10: Implement `console`**

Insert ABOVE the `#[cfg(test)]` module in `crates/paksmith-gui/src/state/console.rs`:

```rust
//! Pure filtering and formatting for the debug-console log view.
//!
//! No iced, no `Mutex`, no I/O — operates on slices of [`LogRecord`] so every
//! decision is unit + mutation tested.

use tracing::Level;

use crate::state::log_buffer::LogRecord;

/// The levels offered in the min-level selector, most severe first.
pub const LEVEL_CHOICES: [Level; 5] = [
    Level::ERROR,
    Level::WARN,
    Level::INFO,
    Level::DEBUG,
    Level::TRACE,
];

/// At/above this relative vertical scroll offset (1.0 = very bottom), the
/// console is "following the tail" and auto-scrolls on new records.
const FOLLOW_THRESHOLD: f32 = 0.999;

/// Filter predicates applied before display.
#[derive(Debug, Clone)]
pub struct ConsoleFilters {
    /// Minimum severity to show: a record passes when it is at least as severe
    /// as this (e.g. `WARN` shows WARN+ERROR, hides INFO/DEBUG/TRACE).
    pub min_level: Level,
    /// Case-sensitive substring the target must contain (empty = match any).
    pub target_filter: String,
    /// Case-sensitive substring the message must contain (empty = match any).
    pub search: String,
}

impl Default for ConsoleFilters {
    fn default() -> Self {
        Self {
            // TRACE is least severe; "at least TRACE" shows everything captured.
            min_level: Level::TRACE,
            target_filter: String::new(),
            search: String::new(),
        }
    }
}

/// True when `level` is at least as severe as `min`.
///
/// `tracing::Level` orders ERROR < WARN < INFO < DEBUG < TRACE (ERROR is the
/// smallest), so "at least as severe" is `level <= min`. Pinned by behaviour in
/// `min_level_warn_shows_error_and_warn_hides_less_severe`, not by this comment.
fn level_at_least(level: Level, min: Level) -> bool {
    level <= min
}

/// True when `record` passes all active filters. An empty target/search string
/// matches any record because `str::contains("")` is always true — so no
/// redundant `is_empty()` short-circuit is needed.
pub fn matches(record: &LogRecord, filters: &ConsoleFilters) -> bool {
    level_at_least(record.level, filters.min_level)
        && record.target.contains(filters.target_filter.as_str())
        && record.message.contains(filters.search.as_str())
}

/// The records to display, in capture order, after filtering.
pub fn displayed<'a>(records: &'a [LogRecord], filters: &ConsoleFilters) -> Vec<&'a LogRecord> {
    records.iter().filter(|r| matches(r, filters)).collect()
}

/// Fixed-width five-char label for a level (deterministic copy output).
fn level_label(level: Level) -> &'static str {
    match level {
        Level::ERROR => "ERROR",
        Level::WARN => "WARN",
        Level::INFO => "INFO",
        Level::DEBUG => "DEBUG",
        Level::TRACE => "TRACE",
    }
}

/// One formatted line: `LEVEL target message` (level left-padded to 5 columns).
pub fn format_line(record: &LogRecord) -> String {
    format!(
        "{:<5} {} {}",
        level_label(record.level),
        record.target,
        record.message
    )
}

/// All currently-displayed records joined into one clipboard string, one
/// formatted line each.
pub fn copy_all(records: &[LogRecord], filters: &ConsoleFilters) -> String {
    displayed(records, filters)
        .iter()
        .map(|r| format_line(r))
        .collect::<Vec<_>>()
        .join("\n")
}

/// True when a scrollable's relative vertical offset is close enough to the
/// bottom to count as following the tail.
pub fn at_bottom(relative_y: f32) -> bool {
    relative_y >= FOLLOW_THRESHOLD
}
```

- [ ] **Step 11: Run the `console` tests to verify they pass**

Run: `cargo test -p paksmith-gui console`
Expected: PASS (8 tests).

- [ ] **Step 12: Lint, format, and verify the minimal-versions floor**

Run: `cargo fmt --all && cargo clippy -p paksmith-gui --all-targets --all-features -- -D warnings`
Expected: clean.

Run: `cargo minimal-versions check --direct -p paksmith-gui -p paksmith-cli`
Expected: builds at the 0.3.0 floor (the registry/`Layer`/`Visit`/`EnvFilter` APIs are all 0.3.0-era). If it fails to compile at the floor, raise the `[workspace.dependencies]` `tracing-subscriber` floor to the lowest version that compiles and re-run — do NOT widen features.

- [ ] **Step 13: Commit**

```bash
git add Cargo.toml crates/paksmith-cli/Cargo.toml crates/paksmith-gui/Cargo.toml \
  crates/paksmith-gui/src/state/mod.rs \
  crates/paksmith-gui/src/state/log_buffer.rs \
  crates/paksmith-gui/src/state/console.rs
git commit -m "feat(gui): add log-buffer ring and console filter logic (phase 7c)"
```

---

## Task 2: Capture install, toggle, and the live console panel

Wires the pure core into a working, openable, live-updating console showing all captured logs with follow-tail. One commit: the three new `Message` variants each ship with their constructor (dead_code trap).

**Files:**
- Modify: `crates/paksmith-gui/src/main.rs`
- Modify: `crates/paksmith-gui/src/menu.rs`
- Modify: `crates/paksmith-gui/src/panels/mod.rs`
- Create: `crates/paksmith-gui/src/panels/console.rs`
- Modify: `crates/paksmith-gui/src/app.rs` (fields, `Message`, `update`, `subscription`, `handle_tree_key`, `view`)

**Interfaces:**
- Consumes from Task 1: `LogBuffer`, `init_console_tracing`, `console::{displayed, format_line, at_bottom, ConsoleFilters}`.
- Produces (consumed by Task 3): `App.console_visible`, `App.log_buffer`, `App.console_follow`, `App.console_filters`; `crate::panels::console::SCROLL_ID`.

- [ ] **Step 1: Write the failing `update`/`menu`/`handle_tree_key` tests**

Add to the `#[cfg(test)] mod tests` in `crates/paksmith-gui/src/app.rs`:

```rust
    #[test]
    fn console_toggled_flips_visibility_and_arms_follow() {
        let mut app = super::App::default();
        // Diverge from the open-branch's effect so the `console_follow = true`
        // assignment is observable: `App::default()` already sets it true, which
        // would mask a deleted/mutated assignment (see the PR #620 lesson on
        // divergent test inputs).
        app.console_follow = false;
        assert!(!app.console_visible);
        let _ = super::update(&mut app, super::Message::ConsoleToggled);
        assert!(app.console_visible);
        assert!(app.console_follow, "opening re-arms tail-follow");
        let _ = super::update(&mut app, super::Message::ConsoleToggled);
        assert!(!app.console_visible);
    }

    #[test]
    fn console_scrolled_tracks_follow_from_offset() {
        let mut app = super::App::default();
        let _ = super::update(&mut app, super::Message::ConsoleScrolled(0.3));
        assert!(!app.console_follow, "scrolled up ⇒ stop following");
        let _ = super::update(&mut app, super::Message::ConsoleScrolled(1.0));
        assert!(app.console_follow, "back at bottom ⇒ follow again");
    }

    #[test]
    fn f12_is_a_noop_in_handle_tree_key_and_preserves_menus() {
        // Reuse the populated-tree fixture used by the arrow-key tests in this
        // module (an App with an open archive and a non-empty visible tree).
        let mut app = open_archive_app_with_rows();
        app.context_row = Some(0);
        app.export_menu = Some(minimal_export_menu());
        let r = super::handle_tree_key(&mut app, &Key::Named(Named::F12));
        assert!(r.is_none(), "F12 produces no scroll task");
        assert_eq!(app.context_row, Some(0), "F12 must not clear context row");
        assert!(app.export_menu.is_some(), "F12 must not clear export menu");
    }
```

Add to `crates/paksmith-gui/src/menu.rs` `#[cfg(test)] mod tests`:

```rust
    #[test]
    fn toggle_console_maps_to_console_toggled_message() {
        assert!(matches!(
            message_for(MenuAction::ToggleConsole),
            Message::ConsoleToggled
        ));
    }
```

And extend the existing `action_for_known_ids` cases array with:

```rust
            (ID_TOGGLE_CONSOLE, MenuAction::ToggleConsole),
```

> Note on the `app.rs` test: `open_archive_app_with_rows()` and `minimal_export_menu()` are the existing helpers used by the arrow-key `handle_tree_key` tests and the export tests. If their names differ in the current file, reuse whatever fixture those tests already build — the requirement is "an `App` with an open archive and ≥1 visible row, plus a set `context_row`/`export_menu`."

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p paksmith-gui console_ ; cargo test -p paksmith-gui f12_is_a_noop ; cargo test -p paksmith-gui toggle_console`
Expected: FAIL to compile — `Message::ConsoleToggled`, `Message::ConsoleScrolled`, `App.console_visible`, `App.console_follow`, `MenuAction::ToggleConsole`, `ID_TOGGLE_CONSOLE`, the F12 guard are all undefined.

- [ ] **Step 3: Add the `App` fields and `Default` values**

In `crates/paksmith-gui/src/app.rs`, add to the `App` struct after `export_menu`:

```rust
    pub export_menu: Option<crate::state::export::ExportMenu>,
    /// Whether the debug-console panel is shown (toggled by F12 / View menu).
    pub console_visible: bool,
    /// Shared ring of captured `tracing` events feeding the debug console.
    /// Injected at boot from `main`; `Default` yields an empty, unshared buffer.
    pub log_buffer: crate::state::log_buffer::LogBuffer,
    /// Whether the console auto-scrolls to the newest line. Set on open/clear;
    /// cleared when the user scrolls up away from the bottom.
    pub console_follow: bool,
    /// Active debug-console filter predicates (min level / target / search).
    pub console_filters: crate::state::console::ConsoleFilters,
```

And to `Default for App`, after `export_menu: None,`:

```rust
            export_menu: None,
            console_visible: false,
            log_buffer: crate::state::log_buffer::LogBuffer::default(),
            console_follow: true,
            console_filters: crate::state::console::ConsoleFilters::default(),
```

- [ ] **Step 4: Add the three `Message` variants**

In `crates/paksmith-gui/src/app.rs`, add inside `enum Message`, after `ExportCompleted { … }` (the last variant, before the closing `}`):

```rust
    /// Toggle the debug-console panel (F12 or the View menu).
    ConsoleToggled,
    /// Periodic tick while the console is visible, so freshly captured records
    /// render without requiring other UI activity.
    ConsoleTick,
    /// The console scroll position changed; carries the relative vertical
    /// offset (0.0 = top, 1.0 = bottom) so the follow decision is testable
    /// without constructing a non-public `scrollable::Viewport`.
    ConsoleScrolled(f32),
```

- [ ] **Step 5: Add the three `update` arms**

In `crates/paksmith-gui/src/app.rs::update`, add before the closing `}` of the `match message`:

```rust
        Message::ConsoleToggled => {
            app.console_visible = !app.console_visible;
            if app.console_visible {
                app.console_follow = true;
                iced::widget::scrollable::snap_to(
                    crate::panels::console::SCROLL_ID.clone(),
                    iced::widget::scrollable::RelativeOffset::END,
                )
            } else {
                Task::none()
            }
        }
        Message::ConsoleTick => {
            // Processing any message rebuilds the view, refreshing the list from
            // the ring. Follow the tail only when the user hasn't scrolled up.
            if app.console_follow {
                iced::widget::scrollable::snap_to(
                    crate::panels::console::SCROLL_ID.clone(),
                    iced::widget::scrollable::RelativeOffset::END,
                )
            } else {
                Task::none()
            }
        }
        Message::ConsoleScrolled(relative_y) => {
            app.console_follow = crate::state::console::at_bottom(relative_y);
            Task::none()
        }
```

- [ ] **Step 6: Add the `handle_tree_key` F12 guard**

In `crates/paksmith-gui/src/app.rs::handle_tree_key`, insert immediately after `let named = *named;` (currently line ~969) and BEFORE the `app.context_row = None;` clear:

```rust
    let named = *named;

    // F12 is the debug-console toggle, routed via its own always-on
    // subscription and excluded from the tree-key listener. Guard here too so a
    // direct call (or any future routing change) can never let F12 disturb tree
    // state or dismiss the context/export menus.
    if named == Named::F12 {
        return None;
    }
```

- [ ] **Step 7: Rewrite `subscription()` for F12 + tick + tree-F12 exclusion**

In `crates/paksmith-gui/src/app.rs`, add a tick-interval constant near the other top-level consts (e.g. after `DEFAULT_SIDEBAR_RATIO`):

```rust
/// Debug-console live-refresh tick interval (ms), active only while visible.
const CONSOLE_TICK_MS: u64 = 300;
```

Replace the body of `subscription()` (the `#[mutants::skip] pub fn subscription` at ~1178–1206) with:

```rust
#[mutants::skip]
pub fn subscription(app: &App) -> Subscription<Message> {
    let menu_sub = crate::menu::subscription();

    // F12 toggles the debug console. Always active — even with no archive open —
    // so startup/open-error logs are reachable. Kept OFF the tree-key listener
    // below so it never doubles as a TreeKey that would dismiss menus.
    let console_toggle_sub = iced::event::listen_with(|event, _status, _window| match event {
        Event::Keyboard(KeyboardEvent::KeyPressed {
            key: iced::keyboard::Key::Named(Named::F12),
            ..
        }) => Some(Message::ConsoleToggled),
        _ => None,
    });

    // While the console is visible, tick a few times a second so freshly
    // captured records render without requiring other UI activity.
    let console_tick_sub = if app.console_visible {
        iced::time::every(std::time::Duration::from_millis(CONSOLE_TICK_MS))
            .map(|_| Message::ConsoleTick)
    } else {
        Subscription::none()
    };

    if app.archive.is_none() {
        return Subscription::batch([menu_sub, console_toggle_sub, console_tick_sub]);
    }

    // Tree navigation keys — but NOT F12 (handled above; routing it here too
    // would fire TreeKey(F12) and clear the context/export menus).
    let tree_key_sub = iced::event::listen_with(|event, _status, _window| match event {
        Event::Keyboard(KeyboardEvent::KeyPressed {
            key: iced::keyboard::Key::Named(Named::F12),
            ..
        }) => None,
        Event::Keyboard(KeyboardEvent::KeyPressed { key, .. }) => Some(Message::TreeKey(key)),
        _ => None,
    });

    // Only subscribe to left-button-release when a Hex tab is active. Drag can
    // only start inside a Hex view, so firing this app-wide would cause spurious
    // update+view rebuilds on every click elsewhere.
    let hex_drag_sub = if hex_drag_listener_active(app) {
        iced::event::listen_with(|event, _status, _window| match event {
            Event::Mouse(iced::mouse::Event::ButtonReleased(iced::mouse::Button::Left)) => {
                Some(Message::HexDragEnded)
            }
            _ => None,
        })
    } else {
        Subscription::none()
    };

    Subscription::batch([
        menu_sub,
        console_toggle_sub,
        console_tick_sub,
        tree_key_sub,
        hex_drag_sub,
    ])
}
```

- [ ] **Step 8: Register and create the console panel**

In `crates/paksmith-gui/src/panels/mod.rs`, add `pub mod console;` in alphabetical position.

Create `crates/paksmith-gui/src/panels/console.rs`:

```rust
//! Debug-console panel: a bounded, filterable view of captured tracing events.
//!
//! Thin rendering only — every decision lives in `crate::state::console` /
//! `crate::state::log_buffer`, which are unit + mutation tested.

use std::sync::LazyLock;

use iced::widget::{column, container, scrollable, text};
use iced::{Element, Length};

use crate::app::{App, Message};
use crate::state::console::{self, format_line};
use crate::theme::tokens::{SPACE_SM, TEXT_SM};

/// Stable id so `update` can issue snap-to-bottom scroll tasks.
pub static SCROLL_ID: LazyLock<scrollable::Id> =
    LazyLock::new(|| scrollable::Id::new("paksmith-console-scroll"));

/// Fixed height of the console panel (px).
const CONSOLE_HEIGHT: f32 = 200.0;

#[mutants::skip] // thin view glue: rendering isn't unit-testable
pub fn view(app: &App) -> Element<'_, Message> {
    let records = app.log_buffer.snapshot();
    let shown = console::displayed(&records, &app.console_filters);

    let mut list = column![].spacing(2);
    for record in shown {
        list = list.push(text(format_line(record)).size(f32::from(TEXT_SM)));
    }

    let body = scrollable(list.width(Length::Fill))
        .id(SCROLL_ID.clone())
        .on_scroll(|viewport| Message::ConsoleScrolled(viewport.relative_offset().y))
        .width(Length::Fill)
        .height(Length::Fill);

    container(body)
        .padding(SPACE_SM)
        .width(Length::Fill)
        .height(Length::Fixed(CONSOLE_HEIGHT))
        .style(|theme: &iced::Theme| container::Style {
            background: Some(iced::Background::Color(
                theme.extended_palette().background.weak.color,
            )),
            ..Default::default()
        })
        .into()
}
```

> If `scrollable::Viewport::relative_offset()` or `.on_scroll`/`.id` differ from the locked iced 0.14 API, adapt the call but keep `Message::ConsoleScrolled(f32)` — the panel is the only place the `Viewport` is touched.

- [ ] **Step 9: Insert the console into the root view**

In `crates/paksmith-gui/src/app.rs::view` (~1482), replace:

```rust
    let root = column![toolbar_view, body, status_view]
        .width(Length::Fill)
        .height(Length::Fill);
```

with:

```rust
    let mut root = column![toolbar_view, body];
    if app.console_visible {
        root = root.push(crate::panels::console::view(app));
    }
    let root = root
        .push(status_view)
        .width(Length::Fill)
        .height(Length::Fill);
```

- [ ] **Step 10: Add the View-menu "Debug Console" item**

In `crates/paksmith-gui/src/menu.rs`:

Add to `enum MenuAction`:

```rust
pub enum MenuAction {
    Open,
    ToggleTheme,
    ToggleConsole,
    About,
}
```

Add to `message_for`:

```rust
        MenuAction::ToggleConsole => Message::ConsoleToggled,
```

Add the id constant next to the others:

```rust
const ID_TOGGLE_CONSOLE: &str = "paksmith.view.toggle_console";
```

Add to `action_for_id`:

```rust
        ID_TOGGLE_CONSOLE => Some(MenuAction::ToggleConsole),
```

In `build()`, replace the View submenu construction:

```rust
    let toggle_theme_item = MenuItem::with_id(ID_TOGGLE_THEME, "Toggle Theme", true, None);
    let toggle_console_item = MenuItem::with_id(ID_TOGGLE_CONSOLE, "Debug Console", true, None);

    let view_menu = Submenu::with_items("View", true, &[&toggle_theme_item, &toggle_console_item])?;
```

(Plain `MenuItem`, no accelerator — F12 is handled by the subscription, and a no-checkmark toggle item is the deliberate v1.)

- [ ] **Step 11: Install the subscriber and inject the buffer in `main`**

In `crates/paksmith-gui/src/main.rs`, at the very top of `fn main()` (before `menu::build`, so the menu-build warning is captured):

```rust
fn main() -> iced::Result {
    // Capture tracing events into a bounded ring for the in-app debug console.
    // Install before building the menu so the menu-build path's own warnings
    // are captured. `try_init` (inside) is a no-op if a subscriber already
    // exists.
    let log_buffer = state::log_buffer::LogBuffer::default();
    state::log_buffer::init_console_tracing(log_buffer.clone());

    // ... existing `let _menu = match menu::build() { … };` unchanged ...
```

And replace the `iced::application(App::default, …)` call with a boot closure that injects the shared buffer:

```rust
    iced::application(
        move || {
            let mut app = App::default();
            app.log_buffer = log_buffer.clone();
            app
        },
        app::update,
        app::view,
    )
    .title("Paksmith")
    .theme(|app: &App| theme::iced_theme(app.mode))
    .subscription(app::subscription)
    .run()
}
```

- [ ] **Step 12: Run the new and existing tests**

Run: `cargo test -p paksmith-gui`
Expected: PASS — the Step-1 tests now pass; the existing menu/handle_tree_key/subscription tests still pass.

- [ ] **Step 13: Lint, format, doc**

Run: `cargo fmt --all && cargo clippy -p paksmith-gui --all-targets --all-features -- -D warnings && cargo doc -p paksmith-gui --no-deps`
Expected: clean — in particular no `dead_code` on the three new variants (each is constructed: `ConsoleToggled` by the menu + F12 listener, `ConsoleTick` by the timer, `ConsoleScrolled` by `on_scroll`).

- [ ] **Step 14: Commit**

```bash
git add crates/paksmith-gui/src/main.rs crates/paksmith-gui/src/menu.rs \
  crates/paksmith-gui/src/panels/mod.rs crates/paksmith-gui/src/panels/console.rs \
  crates/paksmith-gui/src/app.rs
git commit -m "feat(gui): wire debug-console capture, F12/menu toggle, live panel (phase 7c)"
```

---

## Task 3: Filter controls — min-level, target, search, Clear, Copy-all

Adds the control header to the panel and the five `Message` variants that drive it. One commit (dead_code trap: each variant ships with the widget that constructs it). No new `App` fields — the controls mutate `console_filters` / `log_buffer` / `console_follow` added in Task 2.

**Files:**
- Modify: `crates/paksmith-gui/src/app.rs` (`Message`, `update`)
- Modify: `crates/paksmith-gui/src/panels/console.rs` (control header)

**Interfaces:**
- Consumes: `App.console_filters`, `App.log_buffer`, `App.console_follow`, `console::{LEVEL_CHOICES, copy_all}`, `panels::console::SCROLL_ID`.

- [ ] **Step 1: Write the failing `update` tests**

Add to `crates/paksmith-gui/src/app.rs` `#[cfg(test)] mod tests`:

```rust
    #[test]
    fn console_min_level_changed_sets_filter() {
        let mut app = super::App::default();
        let _ = super::update(
            &mut app,
            super::Message::ConsoleMinLevelChanged(tracing::Level::WARN),
        );
        assert_eq!(app.console_filters.min_level, tracing::Level::WARN);
    }

    #[test]
    fn console_target_and_search_changed_set_filters() {
        let mut app = super::App::default();
        let _ = super::update(
            &mut app,
            super::Message::ConsoleTargetFilterChanged("core".into()),
        );
        assert_eq!(app.console_filters.target_filter, "core");
        let _ = super::update(
            &mut app,
            super::Message::ConsoleSearchChanged("decode".into()),
        );
        assert_eq!(app.console_filters.search, "decode");
    }

    #[test]
    fn console_cleared_empties_buffer_and_rearms_follow() {
        let mut app = super::App::default();
        app.log_buffer
            .push(tracing::Level::INFO, "t".into(), "x".into());
        app.console_follow = false;
        let _ = super::update(&mut app, super::Message::ConsoleCleared);
        assert!(app.log_buffer.snapshot().is_empty());
        assert!(app.console_follow, "clearing re-arms tail-follow");
    }
```

> `Message::ConsoleCopyAll` returns an `iced::clipboard::write` task; the clipboard content is produced by the already-tested `console::copy_all`, so no separate `update` assertion is added for it (the arm is a thin delegation, exercised by the `copy_all` unit tests + manual smoke).

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p paksmith-gui console_min_level ; cargo test -p paksmith-gui console_target ; cargo test -p paksmith-gui console_cleared`
Expected: FAIL to compile — the four `Message` variants are undefined.

- [ ] **Step 3: Add the five `Message` variants**

In `crates/paksmith-gui/src/app.rs`, after `ConsoleScrolled(f32),`:

```rust
    /// The console min-level selector changed.
    ConsoleMinLevelChanged(tracing::Level),
    /// The console target-filter text changed.
    ConsoleTargetFilterChanged(String),
    /// The console message-search text changed.
    ConsoleSearchChanged(String),
    /// Clear all captured log records.
    ConsoleCleared,
    /// Copy all currently-displayed records to the clipboard.
    ConsoleCopyAll,
```

- [ ] **Step 4: Add the five `update` arms**

In `crates/paksmith-gui/src/app.rs::update`, after the `Message::ConsoleScrolled` arm:

```rust
        Message::ConsoleMinLevelChanged(level) => {
            app.console_filters.min_level = level;
            Task::none()
        }
        Message::ConsoleTargetFilterChanged(value) => {
            app.console_filters.target_filter = value;
            Task::none()
        }
        Message::ConsoleSearchChanged(value) => {
            app.console_filters.search = value;
            Task::none()
        }
        Message::ConsoleCleared => {
            app.log_buffer.clear();
            app.console_follow = true;
            iced::widget::scrollable::snap_to(
                crate::panels::console::SCROLL_ID.clone(),
                iced::widget::scrollable::RelativeOffset::END,
            )
        }
        Message::ConsoleCopyAll => {
            let records = app.log_buffer.snapshot();
            let payload = crate::state::console::copy_all(&records, &app.console_filters);
            iced::clipboard::write(payload)
        }
```

- [ ] **Step 5: Add the control header to the panel**

In `crates/paksmith-gui/src/panels/console.rs`, extend the imports:

```rust
use iced::widget::{button, column, container, pick_list, row, scrollable, text, text_input};
use iced::{Element, Length};

use crate::app::{App, Message};
use crate::state::console::{self, LEVEL_CHOICES, format_line};
use crate::theme::tokens::{SPACE_SM, TEXT_SM};
```

Build a controls row and prepend it to the panel. Replace the `container(body)` return with:

```rust
    let controls = row![
        pick_list(
            LEVEL_CHOICES.to_vec(),
            Some(app.console_filters.min_level),
            Message::ConsoleMinLevelChanged,
        )
        .text_size(f32::from(TEXT_SM)),
        text_input("target…", &app.console_filters.target_filter)
            .on_input(Message::ConsoleTargetFilterChanged)
            .size(f32::from(TEXT_SM))
            .width(Length::FillPortion(2)),
        text_input("search…", &app.console_filters.search)
            .on_input(Message::ConsoleSearchChanged)
            .size(f32::from(TEXT_SM))
            .width(Length::FillPortion(3)),
        button(text("Clear").size(f32::from(TEXT_SM)))
            .style(iced::widget::button::secondary)
            .on_press(Message::ConsoleCleared),
        button(text("Copy").size(f32::from(TEXT_SM)))
            .style(iced::widget::button::secondary)
            .on_press(Message::ConsoleCopyAll),
    ]
    .spacing(SPACE_SM)
    .align_y(iced::Alignment::Center);

    container(column![controls, body].spacing(SPACE_SM))
        .padding(SPACE_SM)
        .width(Length::Fill)
        .height(Length::Fixed(CONSOLE_HEIGHT))
        .style(|theme: &iced::Theme| container::Style {
            background: Some(iced::Background::Color(
                theme.extended_palette().background.weak.color,
            )),
            ..Default::default()
        })
        .into()
```

> `pick_list` requires its item type to be `Clone + ToString (Display) + PartialEq + 'static`; `tracing::Level` satisfies all four, and `LEVEL_CHOICES.to_vec()` provides an owned `Vec<Level>` (`Level: Copy`, so cheap). If `pick_list`/`text_input` builder names differ in the locked iced 0.14, adapt the calls but keep the `Message` constructors intact.

- [ ] **Step 6: Run tests**

Run: `cargo test -p paksmith-gui`
Expected: PASS — Step-1 tests pass; nothing else regresses.

- [ ] **Step 7: Lint, format, doc**

Run: `cargo fmt --all && cargo clippy -p paksmith-gui --all-targets --all-features -- -D warnings && cargo doc -p paksmith-gui --no-deps`
Expected: clean — no `dead_code` on the five variants (each constructed by a control in the header).

- [ ] **Step 8: Commit**

```bash
git add crates/paksmith-gui/src/app.rs crates/paksmith-gui/src/panels/console.rs
git commit -m "feat(gui): add console min-level/target/search filters, clear, copy-all (phase 7c)"
```

---

## Final gates (controller-run, before review/push)

Run the full CI-matching suite from the worktree root and confirm each is green:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo doc --workspace --no-deps        # with RUSTDOCFLAGS="-D warnings"
typos .
cargo minimal-versions check --direct --all-features
cargo mutants --in-diff <(git diff origin/main...HEAD) --package paksmith-gui   # expect 0 missed
```

Then the adversarial review panel (≥3 + specialists) to convergence, then push — per the repository review protocol.

---

## Manual smoke checklist (rendering is `#[mutants::skip]`, unit-untestable)

Before merge, run `cargo run -p paksmith-gui` and verify:

1. **F12 with no archive open** toggles the console; it shows startup logs. F12 again hides it.
2. **View menu → Debug Console** (macOS) toggles the same panel.
3. With an archive open, **F12 does NOT dismiss an open right-click context/export menu** (the double-dispatch guard).
4. Open a pak so new logs stream in: the console **follows the tail**; scrolling up **stops** auto-follow; scrolling back to the bottom **resumes** it.
5. **Min-level = WARN** hides INFO/DEBUG lines; **DEBUG** shows them again.
6. **target** and **search** inputs filter live.
7. **Clear** empties the list and snaps to bottom; **Copy** puts the filtered lines on the clipboard.

---

## Self-review (spec coverage)

- Spec §4 RingBufferLayer + LogRecord{seq,level,target,message} + Arc<Mutex<VecDeque>> cap 2000 evict-oldest → Task 1 `log_buffer.rs`. ✅
- Lock never across await → `push`/`clear`/`snapshot` hold the guard only for the synchronous body; documented. ✅
- `registry().with(ring_layer).with(env_filter).try_init()` → Task 1 `init_console_tracing`. ✅ (capture floor made permissive per the advisor so DEBUG is live.)
- Pure `state/console.rs` `displayed`/`copy_all` → Task 1. ✅ (plus `matches`/`format_line`/`at_bottom`.)
- Thin `panels/…console.rs` → Task 2/3. ✅
- `App.console_visible` + F12/View-menu toggle → Task 2. ✅ (F12 always-on — documented deviation.)
- `column![toolbar, body, console?, status]` → Task 2 Step 9. ✅
- Controls: min-level pick_list, target text_input, search text_input, Clear, Copy-all (`iced::clipboard::write`), scrollable newest-at-bottom auto-scrolled → Task 3 + Task 2 follow-tail. ✅
- Tracking-deps constraint (only `tracing-subscriber` added) → satisfied; hoisted to workspace per DRY (documented). ✅
- Live-refresh tick (NOT in the spec, required for correctness) → Task 2. ✅ (added; flagged.)
