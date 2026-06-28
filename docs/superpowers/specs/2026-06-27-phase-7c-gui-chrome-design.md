# Phase 7c: GUI Chrome — Toasts, Context Menu, Export As…, Debug Console — Design

**Status:** Approved (2026-06-27)
**Phase:** 7c — third slice of Phase 7 (GUI Asset Viewers)
**Depends on:** Phase 7a (tabbed content host, async-load + generation-fence plumbing — PR #594), Phase 7b (texture viewer, async-task pattern — PR #614), Phase 3 (export pipeline: `FormatHandler` / `HandlerRegistry`), Phase 6 (GUI shell)
**Builds toward:** 7d (AudioPlayer — split out of this slice)

## Goal

Close out the non-viewer Phase 7 deliverables with the GUI "chrome" that makes the
explorer feel finished: **non-blocking toast notifications**, a **file-tree context
menu** (Open / Copy Path / **Export As…**), and a **toggleable debug console** backed
by a `tracing` ring buffer. Export As… additionally wires the existing Phase 3 export
pipeline into the GUI for the first time, so the GUI can extract/convert assets to
disk — not just view them.

## Scope

### In scope (four separable units)

1. **Toast notifications** — a non-blocking overlay surfacing action feedback
   (Export succeeded/failed, Copy Path done) and transient errors that occur while an
   archive is open (e.g. an asset load/decode failure that 7a/7b currently swallow).
2. **File-tree context menu** — right-click a file row to reveal **Open**, **Copy
   Path**, and **Export As…**, rendered as an inline expansion of the row (no floating
   overlay).
3. **Export As…** — a format picker (every output format applicable to the asset, plus
   raw bytes) → native save dialog → async export → result toast. Requires a small new
   public surface in `paksmith-core::export`.
4. **Debug console** — a toggleable bottom panel showing a bounded `tracing` ring
   buffer with a min-level dropdown, per-target substring filter, message text search,
   **Clear**, and **Copy-all**.

### Out of scope (deferred)

- **AudioPlayer** — moved to its own phase (**7d**). It introduces a real-time
  audio-output dependency (`cpal`/`rodio`), is platform-dependent and hard to
  unit-test, and leans on the audio-decode correctness follow-up still unmerged on
  `docs/roadmap-audio-decode-phases`. It does not belong in a chrome slice. (See the
  ROADMAP's Phase 7 deliverable list — AudioPlayer was bundled there; 7c/7d split it
  out.)
- Persisting toast history, console scrollback, or console filter state across
  sessions.
- A true floating/cursor-anchored popup menu (see *Context menu* below for why).
- Wiring a chosen PNG compression level / export options through the GUI export path
  (the registry's default handler config is used, matching the CLI's
  registry-driven path; per-export options remain the CLI's `extract`-options
  concern).
- Bulk / multi-select export, drag-and-drop export.

## Decomposition into PRs

Full Export As… (with a core API) plus a rich console (a `tracing` layer + four
filter/format controls) is more than a "tight chrome trio." To respect the
<200-line-PR norm and the per-PR adversarial-review protocol, the phase ships as an
ordered sequence of independently-reviewable PRs. `writing-plans` owns the final
slicing; the natural cut is:

- **PR1 — Toast infrastructure (foundation).** `state/toast.rs` (pure), the `stack`
  overlay, auto-dismiss timer wiring, and one real consumer: route a currently-silent
  asset-load failure into a toast. The spec + plan land with this PR (matching the 7b
  precedent where spec/plan/impl shared a branch).
- **PR2 — Context menu + Open / Copy Path.** Inline row expansion, right-click
  plumbing, Copy Path (clipboard + success toast), Open (reuses the existing message).
  Depends on PR1 for the success toast.
- **PR3 — Export As… + core façade.** The `paksmith-core::export` additions, the GUI
  format picker, save dialog, async export task, and result toast. Depends on PR1
  (toast) and PR2 (the menu entry point).
- **PR4 — Debug console.** The `tracing-subscriber` ring-buffer layer, global init,
  toggle, and the rich panel. Independent of PR1–PR3.

Each PR follows the established split — pure `state/` (unit + mutation tested), thin
`#[mutants::skip]` `widgets/`, async `task/`, `Message` arms in `app.rs` — and each
gets its own review panel to convergence before push.

## Architecture

Mirrors the Phase 7a/7b layout: pure `state/` · thin `widgets/` · async `task/` ·
composition in `panels/` · messages in `app.rs`.

```
paksmith-core/src/export/
  mod.rs                  # + available_formats() + export_payload() + ExportFormat

paksmith-gui/src/
  state/toast.rs          # PURE: Toast, ToastList (push/dismiss/expire), severity,
                          #       auto-dismiss durations. Unit + mutation tested.
  state/console.rs        # PURE: LogRecord, filter/search predicate, display formatting,
                          #       copy-all rendering. Unit + mutation tested.
  state/log_buffer.rs     # RingBuffer handle (Arc<Mutex<VecDeque<LogRecord>>>) +
                          #       the tracing_subscriber Layer impl. Bounded, evict-oldest.
  widgets/toast.rs        # THIN #[mutants::skip]: a toast card column for the stack overlay.
  widgets/context_menu.rs # THIN #[mutants::skip]: inline action strip (Open/Copy/Export As…).
  widgets/export_picker.rs# THIN #[mutants::skip]: the format-choice list (also inline).
  panels/debug_console.rs # THIN #[mutants::skip]: the console panel (filters + list + buttons).
  widgets/file_tree.rs    # +on_right_press wiring + inline context strip + picker render.
  task/export.rs          # async: ensure-parsed + export_payload (or raw) + write to path.
  app.rs                  # + state fields, + Message arms, + stack overlay, + console panel
                          #   in the column, + auto-dismiss/expire tasks.
  menu.rs                 # + View → Toggle Debug Console item (macOS native menu).
  main.rs                 # + install the tracing ring-buffer subscriber (try_init).
```

## Core API (the one core-touching unit — Export As…, PR3)

The Phase 3 registry resolves only a *single* handler (`find_handler` first-match,
`find_handler_by_extension` by-extension). A format *picker* needs the full set of
applicable formats, and the export-to-bytes orchestration (bulk resolution + dispatch)
currently lives in the CLI's `extract/` module — which the GUI cannot reuse
(CLI/GUI never share code; they depend only on core). Phase 7c promotes a minimal,
tested façade into `paksmith-core::export`, reusing the existing `Package.payloads`,
`resolve_bulk_for_export`, and `FormatHandler::export` internals unchanged:

1. **Enumerate** —
   `available_formats(registry: &HandlerRegistry, package: &Package) -> Vec<ExportFormat>`,
   where `ExportFormat { payload_idx: usize, extension: &'static str }`. Returns every
   `(payload index, output extension)` pair for which a registered handler's
   `supports()` is true, in registration order. Empty when no payload has a handler
   (the GUI then offers raw-only).

2. **Export** —
   `export_payload(package: &Package, payload_idx: usize, extension: &str, registry: &HandlerRegistry) -> Result<Vec<u8>, PaksmithError>`.
   Resolves the payload's bulk internally (via the existing
   `resolve_bulk_for_export(payload_idx)`), selects the handler by
   `(supports && output_extension == extension)`, and returns the exported bytes.
   Errors (no such payload, no handler for that extension, handler failure) are
   `PaksmithError` variants — no panics.

The exact factoring (free functions vs. `HandlerRegistry` methods, where `ExportFormat`
lives) is a plan-level detail; the contract above is fixed. **No other core changes**
— the other three units are GUI-only.

## The four units in detail

### 1. Toasts (PR1)

- **State (`state/toast.rs`, pure).** `Toast { id: u64, severity: Severity, message:
  String }` with `Severity ∈ { Success, Error }` (Success for action confirmations,
  Error for failures; they differ in tint and auto-dismiss duration — no `Info`
  variant, as no agreed trigger produces one). The app holds a `toasts: Vec<Toast>`
  and a monotonic `next_toast_id: u64`. Pure helpers: `push(severity, msg) -> id`,
  `dismiss(id)`, `expire(id)` (expire == dismiss but only if still present —
  idempotent against a manual dismiss that already removed it). Auto-dismiss durations
  are named constants: Success `4s`, Error `8s`.
- **Lifecycle.** `update`'s toast-pushing path returns a
  `Task::perform(tokio sleep(duration), move |()| Message::ToastExpired(id))`
  alongside any other task (use `Task::batch`). `ToastExpired(id)` removes by id;
  `ToastDismissed(id)` (the `×` button) removes immediately. IDs make expiry safe
  against reordering / earlier manual dismissal.
- **Render.** `iced::widget::stack![ body, toast_overlay ]` where `toast_overlay` is a
  bottom-trailing-aligned `column` of toast cards. `stack` layers by alignment, so no
  cursor/scroll coordinates are needed. Each card: severity-tinted background,
  message text, `×` dismiss button. The widget is thin (`#[mutants::skip]`); all
  logic is in `state/toast.rs`.
- **First consumer.** Route at least one currently-invisible failure — e.g. an
  entry-read failure in `task::asset::load`, which today has no user-facing surface —
  into an Error toast, so PR1 ships visible behavior rather than dead scaffolding.
  (Parse failures are *not* errors: 7a intentionally degrades them to Hex-only, so
  they are not the consumer.)
- *Rejected:* a custom absolute-positioned overlay widget — `stack` corner-alignment
  suffices and keeps the built-ins-only discipline.

### 2. Context menu — inline row expansion (PR2)

- **Trigger.** `mouse_area::on_right_press` on a file row →
  `Message::RowContextOpened(visible_row_idx)`. (`on_right_press` carries no
  coordinates; iced 0.14 has no popup widget, and the tree's scroll offset is not
  available in `view()` — so a cursor/row-anchored floating menu is not cleanly
  achievable. Inline expansion sidesteps all of that.)
- **State.** `context_row: Option<usize>` (a *visible-row* index). Cleared on: opening
  any asset, selecting a row, archive swap, filter change, tree toggle, Escape, and a
  second right-press on the same row (toggle). Every tree-mutating path that already
  clamps `selected_row` also clears `context_row` (same call sites), so a stale index
  can never address the wrong row.
- **Render.** When `context_row == Some(i)`, `file_tree` renders, immediately beneath
  row `i`, an inline action strip: **Open**, **Copy Path**, **Export As…**. File rows
  only — directory rows toggle on click and get no menu.
- **Actions.** Open → `Message::OpenAsset(path)` (existing). Copy Path →
  `iced::clipboard::write(path)` + `Message::ToastPushed(Success, "Copied path")`.
  Export As… → opens the format picker (unit 3).
- *Rejected:* `iced_aw::ContextMenu` (new dep, lags iced versions) and a custom overlay
  widget (fights the built-ins-only discipline and needs scroll-offset tracking the
  framework doesn't expose).

### 3. Export As… (PR3)

- **Picker entries.** From the parsed `Package`, compute `available_formats(®istry,
  package)`; the picker shows one entry per `ExportFormat` (label = uppercased
  extension, e.g. `PNG`, `GLB`, `CSV`, `JSON`, `WAV`, `OGG`) **plus a "Raw bytes"**
  entry that is always present (writes the entry's decompressed bytes — works even for
  entries with no handler or that failed to parse). Choosing **Export As…** replaces
  the three action buttons in the inline strip with the format list (a second-level
  strip); a Cancel entry returns to the action strip. Same inline-expansion mechanism
  — no new overlay.
- **Save + export flow.** Choosing a format opens
  `rfd::AsyncFileDialog::new().set_file_name("<stem>.<ext>").add_filter(<EXT>, &["ext"]).save_file()`
  (same crate/pattern as `Message::OpenRequested`). On a chosen path, an async
  `task/export.rs` holds the tab's `Arc<Package>` and runs `export_payload(...)` (or
  uses the raw bytes), then writes the file. Completion →
  `Message::ExportCompleted { result }` → Success/Error toast. The result is
  generation-fenced like other async results (drop if the archive changed).
- **On-demand parse.** Export As… may be invoked on a row whose tab is not open / not
  parsed. The export task loads + parses on demand by reusing `task::asset::load`
  before calling the façade; "Raw bytes" needs only the decompressed entry bytes (no
  parse).
- **Errors.** No applicable handler for the chosen extension, a handler failure, or a
  write error → Error toast with a readable reason. Never panics; never removes a tab.

### 4. Debug console (PR4)

- **Capture (`state/log_buffer.rs`).** A `RingBufferLayer` implementing
  `tracing_subscriber::Layer<S>` pushes `LogRecord { seq: u64, level: Level, target:
  String, message: String }` into a bounded `Arc<Mutex<VecDeque<LogRecord>>>` (capacity
  ~2000, evict-oldest). `on_event` formats the event's message + fields synchronously
  and pushes — **the lock is never held across an `await`** (it is a synchronous push;
  decode/export emit events from tokio worker threads, so the lock must be short and
  await-free). `seq` gives a stable monotonic order independent of wall-clock.
- **Install (`main.rs`).** `tracing_subscriber::registry().with(ring_layer).with(env_filter).try_init()`.
  `try_init()` (not `init()`) so test binaries that already installed a subscriber do
  not double-install/panic. The `Arc` ring handle is cloned into `App` so `view()` can
  read it. Always-on from startup → history exists when the console is first opened.
  `tracing-subscriber` (0.3.x) is already a transitive dependency that compiles on MSRV
  1.88; promoting it to a direct dep does not change resolution and is cargo-deny-clear.
- **State (`state/console.rs`, pure).** Filter/search state: `min_level: Level`,
  `target_filter: String` (substring), `search: String` (substring over message).
  Pure `displayed(records, filters) -> Vec<&LogRecord>` and a `copy_all(records,
  filters) -> String` formatter. Unit + mutation tested with golden inputs.
- **UI (`panels/debug_console.rs`, thin).** `App.console_visible: bool`, toggled by a
  View-menu item (macOS native menu) and an `F12` key (added to the existing key
  subscription). Rendered as a bottom panel inserted into the root
  `column![toolbar, body, console?, status]`. Controls: a min-level `pick_list`, a
  target-filter text input, a search text input, **Clear** (empties the ring buffer),
  **Copy-all** (`iced::clipboard::write(copy_all(...))`). The log list is a
  `scrollable` of formatted lines (newest at bottom, auto-scrolled).

## Error handling & fallback

- All new core paths return `Result<_, PaksmithError>`; the GUI stringifies for
  display (consistent with 7a/7b's `Result<_, String>` task results).
- Export failures and load/decode failures surface as Error toasts, never panics, and
  never tear down a tab or the archive.
- The full-area error banner (empty-state "open failed, no archive" + retry CTA) is
  **kept** — toasts handle transient, in-session feedback; the banner remains the
  empty-state landing.
- A non-decodable / handler-less / unparsed entry still offers "Raw bytes" export; it
  never offers a format it cannot produce.
- Console capture degrades safely: if `try_init` finds an existing subscriber (tests),
  the ring layer is simply not the global subscriber — the GUI still renders an (empty)
  console rather than failing.

## Testing

- **Pure state.** Toast lifecycle (push assigns increasing ids; dismiss/expire remove
  the right id; expire-after-manual-dismiss is a no-op; per-severity durations).
  Context-row transitions (right-press sets/toggles; every clear trigger clears).
  Console filter/search predicate + display + copy-all golden tests (level threshold,
  target substring, message substring, combined; empty-result). Ring buffer eviction
  (cap boundary: push N+1 drops the oldest; `seq` monotonic).
- **Core façade.** `available_formats` over Phase-3 fixtures (texture → `png`; data
  table → `csv`,`json`; mesh → `glb`; sound → the registered set; non-handled → empty);
  `export_payload` round-trips one fixture per family (asserting non-empty / expected
  magic bytes), plus bounds/no-handler/unknown-extension error paths.
- **Thin widgets / panels.** `#[mutants::skip]`; all testable logic extracted to
  `state/`.
- **Standing UI/UX reviewer** on each new widget per the Phase 6+ mandate (toast
  contrast + dismissal affordance, context-strip discoverability + keyboard access,
  console legibility + control labels).
- `cargo mutants --in-diff` to 0-missed before each push, per the standing gate.

## Constraints (carried from prior phases)

- GUI-only **plus** the single `paksmith-core::export` façade addition (PR3) — no other
  core changes.
- New direct dependency: `tracing-subscriber` (already transitive; MSRV-1.88-safe;
  cargo-deny-clear). No others — toasts/menu/console use iced built-ins; export reuses
  existing core + `rfd` (already a dep).
- No panics in core; `thiserror`/`Result` throughout.
- MSRV 1.88 (no let-chains, no `if let` match guards — use the two-guard / let-else
  forms already established in `app.rs`).
- Conventional commits; the standing adversarial review panel + UI/UX reviewer;
  convergence before push; one logical change per commit; PRs under the size norm.
