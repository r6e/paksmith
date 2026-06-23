# Phase 7a: Tabbed Content + Property/Hex Viewers — Design

**Status:** Approved (2026-06-21)
**Phase:** 7a — first slice of Phase 7 (GUI Asset Viewers)
**Depends on:** Phase 6 (GUI shell, two-pane explorer — PR #593), Phase 2/3 (asset parsing, property system)
**Builds toward:** 7b (TextureViewer), 7c (AudioPlayer + chrome: toasts, context menu, debug console)

## Goal

Turn the Phase 6 browse-only shell into a tabbed asset inspector: open assets into closeable tabs, each with an in-tab `Properties | Hex | Info` view switcher. Ship two data-driven viewers that need no GPU and no new core work — a type-aware PropertyInspector and a virtualized HexView with selection + copy.

## Why this is the first slice

Phase 7 as written in the ROADMAP bundles eight deliverables across four independent subsystems (tabs, GPU texture viewer, audio playback, UX chrome). That is too large and too tech-risk-diverse for one spec. The agreed decomposition is 7a/7b/7c, each its own brainstorm → spec → plan → PR cycle (mirroring Phase 5's 5a–5d). 7a is the foundation every later viewer plugs into, and it is the only slice that requires neither GPU programming nor the audio runtime.

## Scope

### In scope

- **Tab infrastructure** — one tab per opened asset; closeable (× button + middle-click); horizontal-scroll overflow when the strip exceeds the content width.
- **Content host** — replaces the Phase 6 Detail pane in the right side of the `pane_grid`. Hosts the tab bar + the active tab's body. Empty state when no tab is open (reuse the Phase 6 empty-state styling).
- **In-tab view switcher** — a segmented control toggling `Properties | Hex | Info` for the active tab. Designed so 7b/7c add `Texture` / `Audio` options for the relevant asset types without restructuring.
- **PropertyInspector** — an expandable, type-aware tree over a parsed `Package`'s exports and their tagged properties.
- **HexView** — a virtualized hex dump (offset gutter • hex columns • ASCII column) with click/drag byte-range selection synced across the hex and ASCII columns, and copy: the primary copy action (Cmd/Ctrl-C, or a copy button on the selection) writes the selected bytes as a hex string; a secondary "Copy as ASCII" action writes the ASCII rendering. With no selection, copy is a no-op.
- **Info view** — absorbs the Phase 6 metadata content (path, uncompressed/compressed size, ratio, compressed/encrypted flags) and adds package-summary stats when the asset parsed (export count, name count, file version).

### Deferred (named, not dropped)

- **TextureViewer** → 7b (GPU/wgpu vs CPU-image decision belongs to that spec).
- **AudioPlayer** → 7c. **Opus playback stays blocked** — UE ships Opus in a custom UE4OPUS framing (not Ogg-Opus) with no oracle and no fixture; Phase 3 left it as raw passthrough. The 7c player will play only what the export pipeline already decodes (PCM/ADPCM/Vorbis).
- **Toast notifications, tree context menu (Open / Export As / Copy Path), debug console** → 7c.
- **`.usmap` loading UI** — not in 7a. Assets that require a mapping fall back gracefully (see Error handling).

## Architecture

### No core changes

The GUI calls the existing public core API:

```rust
paksmith_core::asset::Package::read_from_reader(
    reader: &Arc<paksmith_core::container::pak::PakReader>,
    virtual_path: &str,
    mappings: Option<&Usmap>,   // 7a always passes None
) -> paksmith_core::Result<Package>
```

This function already (a) resolves the `.uexp` companion internally (`EntryNotFound → None` = monolithic asset), (b) wires the `.ubulk`/`.uptnl` lazy bulk-data loaders, and (c) captures `Arc<PakReader>` clones so the returned work is `Send + Sync + 'static` and safe across the `Task::perform` boundary. Its own doc names "the future GUI" as an intended caller. **There is no core-extraction task in 7a** (contrast Phase 6, which had to extract `resolve_pak_key`).

`Package`, `PropertyBag`, `Property`, and `PropertyValue` are already public, read-only core types. The CLI's `inspect/tree.rs` is text-only presentation with `pub(crate)` formatters — CLI-private and not reused. Per the codebase convention (CLI and GUI depend only on core, never on each other), the GUI writes its **own** view-layer formatters (color → swatch widget, vector → formatted text, enum → resolved name, object-ref → name + index, array/map → element count + expansion).

### Pure / view / task split (same as Phase 6)

- **`state/` — pure, no `iced`, unit-tested:**
  - `state/tabs.rs` — tab collection model: open/close/activate, active index, per-tab view mode (`Properties | Hex | Info`), overflow-independent ordering. Pure functions for open (dedupe: opening an already-open asset activates its tab rather than duplicating), close (re-pick active), activate, set-view.
  - `state/property_view.rs` — flattens a `Package` into a row model (export → properties → nested struct/array/map children), with per-row expand/collapse and visible-row computation. Plus the value → display-string formatters (the testable part of "type-aware rendering").
  - `state/hex_view.rs` — 16-byte row chunking, visible-window math (first/last visible row from scroll offset + viewport height), selection range (anchor..cursor, normalized), hex↔ASCII index mapping, and copy formatting (hex string / ASCII).
- **`widgets/` + `panels/` — thin view, `#[mutants::skip]`:**
  - `widgets/tab_bar.rs` — scrollable tab strip; active highlight via the Phase 6 system-accent tokens; × close + middle-click close.
  - `widgets/property_tree.rs` — virtualized tree rendering (same approach as `widgets/file_tree.rs`) with type-aware row widgets.
  - `widgets/hex_view.rs` — virtualized row rendering with selection highlight.
  - `panels/content.rs` — the tab host: tab bar + view switcher + active tab body, or the empty state.
- **`task/` + `state/archive.rs` — async + retained reader:**
  - `state/archive.rs` `LoadedArchive` gains an `Arc<PakReader>` field (Phase 6 currently drops the reader after listing the index). Open once, reuse for every tab-open.
  - `task/` gains an async open-asset pipeline (read entry bytes + parse `Package`) dispatched via `Task::perform`.

### Layout

The Phase 6 `pane_grid` is `sidebar | detail`. In 7a the right pane becomes the content host (`panels/content.rs`). The sidebar file tree is unchanged. The metadata that lived in `panels/detail.rs` moves into the Info view.

## Data flow

1. Double-click on a tree row, or Enter on a selected **file** row, → `Message::OpenAsset(path)`. Enter on a **folder** row keeps its Phase 6 meaning (expand/collapse); a file row has no children to toggle, so Enter→open does not conflict with the existing tree keyboard nav. Single-click still only selects in the tree, as in Phase 6. No context menu in 7a.
2. `update` dispatches `Task::perform(async move { Package::read_from_reader(&arc, &path, None) }, move |res| Message::AssetParsed(path, res))`, using the `Arc<PakReader>` retained in `LoadedArchive`. The tab is created immediately in a **loading** state.
3. Raw bytes for the Hex/Info views come from `reader.read_entry(path)` (cheap; same retained reader).
4. `Message::AssetParsed(path, Result<Package>)` stores the parsed `Package` (or the parse error) plus the raw bytes in the tab's state.
5. Switching view mode or switching tabs is instant — all data lives in tab state; nothing is re-read or re-parsed.
6. **Tab invalidation:** opening a different archive, or closing the archive, clears all open tabs (they reference entries in the old container's reader).

## Error handling & edge cases

- **Parse failure** (including `UnversionedWithoutMappings` for `.usmap`-dependent unversioned assets) is **not** a crash and **not** a toast (toasts are 7c). The tab still opens; the Properties view shows a clean *"Not a parseable asset — see Hex"* state with the reason string. **Hex and Info always work.**
- **Non-`.uasset` entries** (raw files, textures, audio, etc.) skip the parse attempt entirely → Hex + Info only; the Properties tab shows the same graceful "no properties" state.
- **Large entries:** virtualization bounds rendering to the visible window. `read_from_reader` and `read_entry` already enforce core's existing size caps; 7a adds no new unbounded buffers.
- **Empty / closed:** closing the last tab returns the content host to the empty state.

## Global Constraints

- **No new dependencies.** Tab bar, tree, hex grid, segmented control, and scrolling use `iced` built-ins (`scrollable`, `button`, `container`, `text`, `row`/`column`). Clipboard copy uses `iced::clipboard::write` (built-in). No core dependency changes.
- **No core changes.** 7a is GUI-only; it consumes existing public core APIs. If a genuine need to change core surfaces during implementation, stop and escalate — it is out of scope by default.
- **Pure model, thin view.** All decision logic lives in `state/` pure functions with unit tests. View functions (`widgets/`, `panels/`) carry `#[mutants::skip]`; any real logic inside a view is extracted to a tested pure helper first (Phase 6 discipline — `readable_text_on`, `tree_scroll_offset`, etc.).
- **`Message` stays `Clone`.** Parse errors are stringified into the message (`PaksmithError` is not `Clone`), matching the Phase 6 `OpenError` pattern.
- **Reader retention is `Arc`-shared,** never cloned-by-value; the resolved AES key already lives behind the reader and is not surfaced or re-stored by 7a.
- **cargo-mutants `--in-diff` to 0-missed before push.** Carry the Phase 6 mutants playbook verbatim: `#[mutants::skip]` for struct-field-genus view mutants (the `mutants` crate is already a dep), `exclude_re` only for env-IO/equivalent residue, value-pinned consts, boundary-ACCEPTED tests.
- **Standing UI/UX design reviewer.** Every review panel for 7a (per-task UI-rendering tasks and the final whole-branch panel) includes the UI/UX design reviewer as a **blocking** member, alongside code / architect / security / simplifier. This is the user's binding Phase 6+ requirement and persists for all GUI work: the result must look professional and polished, follow modern UI/UX conventions (WCAG-AA contrast, keyboard navigability, clear affordances), and never feel amateur or hacked-together.

## Testing approach

- **`state/tabs.rs`:** open (new + dedupe-to-existing), close (active re-pick from each position), activate, set-view-mode; order preservation.
- **`state/property_view.rs`:** flattening a known `Package`/`PropertyBag` into the expected row sequence; expand/collapse visible-row recomputation; each value → display-string formatter (color hex/swatch input, vector, enum name, object-ref name+index, array/map counts) with boundary inputs.
- **`state/hex_view.rs`:** row chunking (including a final short row), visible-window math, selection normalization (forward and backward drags), hex↔ASCII index mapping, copy formatting (hex string and ASCII).
- **Open pipeline:** an integration-style test that opens a fixture pak, opens an asset tab, and asserts the parsed-vs-error tab state and that Hex bytes match `read_entry`.
- Keyboard navigability and contrast are verified by the standing UI/UX reviewer against the rendered widgets (visual review was explicitly deferred from Phase 6 to Phase 7).

## Out of scope / explicitly not doing

- No GPU/wgpu code (7b).
- No audio runtime (7c).
- No toasts, context menu, or debug console (7c).
- No `.usmap` selection UI.
- No new tree interactions beyond open-on-double-click/Enter.
- No persistence of open tabs across sessions.
