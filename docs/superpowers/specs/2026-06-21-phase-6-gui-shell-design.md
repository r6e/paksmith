# Phase 6 — GUI Shell Design

**Status:** approved (brainstorming), pre-implementation
**Date:** 2026-06-21
**Roadmap:** Phase 6 (GUI Shell). Depends on Phase 1 (PakReader) and Phase 5 (profiles / `--game` / `--detect`, shipped in #592). Phase 7 (asset viewers) builds on this shell.

## Context

`paksmith-gui` is currently a 5-line `println!` placeholder (Iced is not yet a
dependency). Phase 6 builds the real GUI shell: a native-feeling desktop
application that opens `.pak` archives (including encrypted ones, via the full
Phase 5 key resolution) and lets the user navigate their contents in a
virtualized file tree. This is the GUI **foundation** — navigation and
inspection, **not** asset rendering (that is Phase 7).

The user requirement is explicit and binding: the application must follow
modern UI/UX best-practices, look professional and polished, and **not** feel
like an amateur, hacked-together app. A **UI/UX design reviewer is a standing
member of every Phase 6 review panel** (see Review Protocol).

We commit to **Iced** (already chosen in the ROADMAP) deliberately: Phase 7
(asset viewers) and Phase 9 (a wgpu 3D viewport) need a custom GPU renderer, which
a native toolkit (Cocoa/Win32/GTK/Qt) would fight. The trade-off is that Iced
draws its own widgets — it does not host OS-native controls — so "native" here
means **native-respecting**: real native window + native menus + auto
light/dark + system accent + system fonts, with Iced-drawn content styled to
each platform's conventions.

## Decisions (from brainstorming)

- **Scope:** a polished, browse-only **vertical slice** — depth of finish over
  breadth (one complete, beautiful workflow), not a wide-but-shallow shell.
- **Layout:** **two-pane Explorer + Detail** — file tree on the left, a wide
  detail/preview pane on the right (the seat Phase 7 viewers will fill), with a
  menu bar (top), toolbar, and status bar (bottom).
- **Visual language:** **native, platform-adaptive** — the app adopts the look
  of the OS it runs on.
- **Native integration depth:** **maximal** — native window chrome + native
  menu bar + auto OS light/dark + system UI fonts + **per-platform system
  accent-color reading** (Windows / macOS / Linux-portal, each with a fallback).
- **Encrypted-pak key flow:** **auto-resolve, prompt on failure** — on open,
  transparently run the Phase 5 resolution (active profile → auto-detect); only
  if the pak stays locked does an inline "Encrypted — provide a key" panel
  appear (pick a profile / paste a 64-hex key / point at an install dir).

## Goals / non-goals

- **Goal:** a native-feeling Iced shell that opens any `.pak` (incl. encrypted
  via Phase 5), navigates 100k+ entries smoothly in a virtualized lazy tree,
  shows per-entry metadata in a detail pane, with complete app chrome, auto
  light/dark + system accent, a resizable sidebar, and a live tree filter.
- **Non-goal (deferred to a later sub-phase):** multi-archive tabs, extract-from-GUI,
  cross-entry search (beyond the simple visible-tree filter), a settings/preferences
  window, IoStore containers.
- **Non-goal (Phase 7):** any asset *preview rendering* — the detail pane shows
  metadata only in Phase 6; Phase 7 fills it with texture/mesh/audio/data viewers.

## Architecture

Iced's functional Elm architecture: a single `App` state, a `Message` enum,
`update(&mut State, Message) -> Task<Message>`, `view(&State) -> Element`. The
current stable Iced API is the functional builder
`iced::application(State::default, update, view).theme(...).run()`; async work
uses `Task::perform(future, Message::Variant)`; theming uses `.theme(|state| …)`
returning an Iced `Theme`, with per-widget `.style(closure)` for custom styling.
(Exact Iced version — the 0.13.x line — pinned at implementation time.)

The design's spine is a strict separation between **pure, testable state
models** (no Iced types) and **thin view code**.

```
paksmith-gui/src/
├── main.rs              # iced::application(...).theme(...).run(); window + menu wiring
├── app.rs               # App state, Message enum, update(), top-level view()
├── menu.rs              # muda native menu bar; menu events → Message
├── theme/
│   ├── mod.rs           # Iced Theme/palette derived from system theme + accent + tokens
│   ├── accent.rs        # per-OS system accent read (#[cfg] win/mac/linux + fallback)
│   └── tokens.rs        # spacing, typography, density constants
├── state/               # PURE — no Iced types, heavily unit-tested
│   ├── archive.rs       # LoadedArchive: path, entry count, decryption status
│   ├── tree.rs          # tree node model + expansion set + visible-row virtualization + selection
│   └── keyflow.rs       # encrypted-pak resolution state machine (Resolving → Locked → Unlocked)
├── panels/              # view composition (thin)
│   ├── toolbar.rs       # Open, game-profile selector, decryption-status pill, filter field
│   ├── sidebar.rs       # file-tree panel + drag-resize handle
│   ├── detail.rs        # selected-entry metadata pane (Phase 7 viewer host)
│   ├── status_bar.rs    # file name · entry count · selected info · memory
│   └── key_prompt.rs    # inline "Encrypted — provide a key" panel
├── widgets/
│   └── file_tree.rs     # the virtualized tree widget
└── task/
    └── open.rs          # async: open reader + resolve key + build tree model
```

### Cross-cutting core refactor (approved)

The `resolve_pak_key` orchestration (footer-GUID → local store → cache → fetch →
detect → key) currently lives in the **CLI** crate (`commands/key_resolve.rs`),
but CLAUDE.md forbids CLI↔GUI code sharing. We **extract it into
`paksmith-core`** (a new `profile::resolve` module exposing a
frontend-agnostic resolution entry point) so both frontends call the same logic;
the CLI's `key_resolve.rs` becomes a thin wrapper over the core function. This is
a small, behavior-preserving extraction that improves the architecture and is the
only way the GUI gets the real Phase 5 resolution without duplication. The CLI's
existing resolution tests must continue to pass unchanged.

## Native integration (maximal)

- **Native window** — Iced uses winit, giving the real OS title bar / traffic
  lights / min-max-close / resize / snap. Free.
- **Native menu bar** — `muda`: a true global menu bar on macOS, native menus on
  Windows/Linux. Menu events are mapped to `Message`s in `menu.rs`.
- **Native file dialogs** — `rfd` for the OS open picker (and save dialogs when
  extract lands in a later sub-phase).
- **Auto light/dark** — read the OS preference (`dark-light` or equivalent) →
  `Theme::Dark`/`Theme::Light`; live-update on system change where the platform
  supports it.
- **System accent color** — per-OS read behind `#[cfg(target_os = "…")]`:
  - Windows: `UISettings.GetColorValue(UIColorType::Accent)` (via the `windows`
    crate).
  - macOS: `NSColor.controlAccentColor` (via `objc2` + `objc2-app-kit`).
  - Linux: xdg-desktop-portal `org.freedesktop.portal.Settings` accent-color
    (via a portal crate), with a graceful fallback when unavailable.
  - A tasteful built-in default accent is the fallback on every platform. The
    accent drives selection highlights, focus rings, the profile pill, etc.
- **System UI font** per platform (SF Pro / Segoe UI / system default) +
  platform-appropriate spacing/density tokens.

## Components

### State models (pure, `state/`)

- **`archive.rs` — `LoadedArchive`:** the opened archive's identity and status:
  source path, total entry count, decryption status (plain / decrypted /
  verified), and the handle needed to read entry metadata. No Iced types.
- **`tree.rs` — the tree model (the hard part):** the directory/file node
  structure plus an **expansion set** and a **selection**. From these it
  materializes a **flat list of currently-visible rows** (only expanded branches
  contribute rows). Lazy: a folder's children are not materialized into the
  visible-row list until the folder is expanded. A live filter narrows the
  visible-row set by path substring/glob. Fully unit-testable: expand → assert
  the visible-row set; collapse → assert it shrinks; filter → assert subset;
  select → assert the highlighted row. No rendering involved.
- **`keyflow.rs` — encrypted-pak resolution state machine:** `Resolving`
  (running the Phase 5 resolution off-thread) → `Unlocked` (key found, archive
  open) or `Locked` (no key; the inline prompt is shown). Transitions are driven
  by `Message`s; pure and unit-tested.

### View panels (`panels/`) — thin

- **`toolbar.rs`** — Open button, game-profile selector (dropdown over the Phase
  5 `ProfileStore` + cached registry), a decryption-status pill (🔒/🔓), and a
  live filter field.
- **`sidebar.rs`** — hosts the file-tree widget plus a draggable resize handle
  (split position tracked as a percentage in `App` state).
- **`detail.rs`** — the selected entry's metadata: full path, size, compressed
  size, compression method, offset, SHA1 verification status, encryption flag.
  This pane is the Phase 7 viewer host.
- **`status_bar.rs`** — loaded file name, total entry count, selected-entry
  summary, process memory usage.
- **`key_prompt.rs`** — the inline Locked-state panel: pick a profile, paste a
  64-hex key, or point at an install dir to auto-detect; re-runs resolution.

### Widget (`widgets/file_tree.rs`)

The virtualized tree widget. It renders only the rows of the model's
visible-row list that intersect the current viewport (scroll offset → row-index
slice), so render cost and memory stay flat regardless of total entry count. It
is keyboard-navigable (up/down/left-collapse/right-expand/enter-select) and
emits expand/collapse/select `Message`s.

### Async (`task/open.rs`)

`Task::perform` runs the open pipeline on a background thread so the UI never
blocks on a large parse: open the `PakReader` (with the resolved key if any),
run the Phase 5 key resolution, and build the tree model. It returns
`Message::ArchiveOpened(Result<LoadedArchive, OpenError>)`.

## Data flow

- **Open:** menu/toolbar → `rfd` native picker → `Message::OpenRequested(path)`
  → `update` spawns `Task::perform(task::open::run(path, profile_ctx))` →
  `Message::ArchiveOpened(result)`.
  - **Success (plain or key resolved):** populate the tree model; set status.
  - **Encrypted but unresolved:** not an error — enter `keyflow::Locked` and
    render `key_prompt`. User action re-runs resolution.
  - **Error:** show an error banner with the `PaksmithError` `Display`.
- **Tree interaction:** expand / collapse / select / filter are `Message`s that
  mutate the pure tree model; `view` re-renders only the visible slice.
- **Theme:** resolved at startup from system theme + accent, and updated on
  system change where supported.

## Error handling

No panics — every core call returns `Result<_, PaksmithError>`; the GUI maps
errors to inline banners/dialogs using the error's `Display`. Background-task
work is wrapped so a fault becomes a typed `OpenError` message, never a process
crash. "Encrypted, no key" is a **state**, not an error. Every non-content
state — empty (no archive open), loading, locked, error — gets a deliberately
designed view; no blank screens (a hallmark of polish, and a UI/UX review
checkpoint).

## Testing

- **Pure state models** (`tree`, `keyflow`, `archive`) — TDD, heavy unit
  coverage; this is the bulk of the test suite (expand/collapse/filter/select on
  the tree; the key-flow transitions; archive status).
- **`update()` reducers** — construct `App` state, send `Message`s, assert the
  resulting state and which `Task` kind is emitted (logic extracted from view to
  stay testable).
- **Per-OS accent/theme reads** — smoke-tested behind their `#[cfg]`, with the
  fallback path asserted; CI's ubuntu/macOS/windows matrix exercises all three.
- **View / native polish** — not unit-testable; validated by manual run and the
  UI/UX review panel. The standard gate chain applies: fmt, clippy, test, doc,
  typos, cargo-deny, minimal-versions, and cargo-mutants `--in-diff` to
  0-missed before push.

## Review Protocol (binding for every Phase 6 PR)

Every Phase 6 PR adds a **UI/UX design reviewer** as a standing panel member,
alongside the usual code-reviewer / architect / simplifier / security set (plus
deep-impact / performance specialists when those triggers fire — e.g. the
signature ripple of the core refactor, the hot-path virtualized renderer). The
UI/UX reviewer evaluates against modern best-practices:

- Visual hierarchy, spacing rhythm, alignment, and typographic scale.
- Affordance and feedback clarity (does every control look interactive; is every
  action acknowledged).
- **Keyboard navigation** and focus order (full keyboard operability).
- **Accessibility / contrast** (WCAG AA contrast in both light and dark themes;
  hit-target sizes).
- Native-platform convention adherence (menu structure, shortcuts, window
  behavior).
- Complete empty / loading / locked / error states — no blank or dead-end
  screens.
- Consistency of the design-token system (spacing, color, type) across panels.

"Looks amateur / hacked-together" is a **blocking** finding, not a nitpick.
Convergence requires the UI/UX reviewer's APPROVED alongside the others.

## Dependencies / build notes / risks

- **New dependencies** (all permissive — MIT/Apache — reputable and actively
  maintained): `iced` (+ its wgpu stack), `rfd` (native dialogs), `muda` (native
  menus), a system light/dark detector (`dark-light` or equivalent), and the
  per-OS accent crates (`windows`; `objc2` + `objc2-app-kit`; a Linux portal
  crate). `cargo-deny` must accept these; any genuinely-needed license/source
  exception is scoped and documented (consistent with prior phases).
- **Build-time weight:** iced + wgpu is a heavy dependency tree. `gui` stays in
  `default-members` (a tier-1 feature, per decision), so every `cargo build`
  compiles it — an accepted cost.
- **macOS distribution:** paksmith has no Apple Developer account; ad-hoc
  codesigning + the Gatekeeper workaround is the permanent strategy. This is a
  distribution concern, **not** a Phase 6 development blocker — no Developer-ID
  flow is introduced.
- **The virtualized tree** is the highest-risk component; it gets the deepest
  test coverage (pure model) and a performance-specialist review.

## Scope boundary

Phase 6 ships a polished, native-feeling, browse-only shell: open (incl.
encrypted via Phase 5) → virtualized lazy tree → select → metadata detail pane →
full native chrome → auto light/dark + system accent → resizable sidebar →
filter. Multi-archive tabs, extract-from-GUI, cross-entry search, a preferences
window, and all asset preview rendering are explicitly out of scope (later
sub-phases / Phase 7).
