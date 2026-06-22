# Phase 7a: Tabbed Content + Property/Hex Viewers — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the Phase 6 browse-only GUI into a tabbed asset inspector: open assets into closeable tabs, each with an in-tab `Properties | Hex | Info` switcher, backed by a type-aware PropertyInspector and a virtualized HexView with selection + copy.

**Architecture:** GUI-only — no core changes. The GUI calls the existing public `paksmith_core::asset::Package::read_from_reader(&Arc<PakReader>, path, None)` (self-resolves `.uexp`, `Send+Sync+'static`). Same Phase 6 split: pure `state/` (no `iced`, unit-tested) + thin `widgets/`/`panels/` view (`#[mutants::skip]`, real logic extracted to tested pure helpers) + async `task/`. One `App`, one `Message`, `update`/`view`.

**Tech Stack:** Rust, `iced` 0.14 (functional Elm API; `mouse_area`, `scrollable`, `pane_grid`, `clipboard::write`), `paksmith-core`.

## Global Constraints

- **No new dependencies.** Use `iced` built-ins only (`mouse_area`, `scrollable`, `button`, `container`, `text`, `row`/`column`; `iced::clipboard::write` for copy). No `Cargo.toml` dependency additions, no `version =` bumps (release-please owns versions).
- **No core changes.** Consume existing public core APIs only. If a genuine core change seems required, stop and escalate — it is out of scope.
- **Pure model, thin view.** All decision logic lives in `state/` pure functions with unit tests. View functions (`widgets/`, `panels/`) carry `#[mutants::skip]`; extract any real logic into a tested pure helper first.
- **`Message` stays `Clone + Debug`.** Everything a `Message` variant carries must be `Clone + Debug`. Parse errors are stringified (`PaksmithError` is not `Clone`). Box large payloads (`Box<Package>`, `Box<AssetLoad>`), mirroring the existing `Message::ArchiveOpened(Box<...>)`.
- **`LoadedArchive` stays `Clone + Debug`** (it rides inside `Message::ArchiveOpened`). `PakReader` is **not** `Debug` and **not** `Clone`-by-value; store it as `Arc<PakReader>` (Arc is `Clone`) and provide a **manual `Debug` impl** for `LoadedArchive` — do **not** add a derive to core's `PakReader`.
- **MSRV 1.88.** No let-chains (`if let … && …`), no `if let` match guards. Use the two-guard / let-else forms already in the codebase (see `app.rs::clamp_selected_row`).
- **cargo-mutants `--in-diff` to 0-missed before push.** `#[mutants::skip]` on view fns (the `mutants` crate is already a dep); `exclude_re` in `.cargo/mutants.toml` only for env-IO/equivalent residue; value-pin consts; boundary-ACCEPTED tests.
- **Standing UI/UX design reviewer.** Every review panel (per-task UI-rendering tasks and the final whole-branch panel) includes the UI/UX design reviewer as a **blocking** member, alongside code / architect / security / simplifier. The result must look professional and polished: WCAG-AA contrast (use `tokens::TEXT_MUTED_ALPHA` for secondary text), keyboard navigability, clear affordances. Never amateur.
- **Stay in the worktree.** All work happens in `.claude/worktrees/feat+phase-7a-tabbed-viewers`. Use relative paths from there; never reach into the main checkout.
- **Local gate chain before each commit:** `cargo fmt --all`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test -p paksmith-gui`. Run `RUSTDOCFLAGS="-D warnings" cargo doc -p paksmith-gui --no-deps` when public docs change.

## Reference material (read before implementing)

- **Phase 6 patterns to mirror:** `crates/paksmith-gui/src/app.rs` (App/Message/update/view, `accent_button`, `readable_text_on`, `#[mutants::skip]` + extracted helpers, two-guard MSRV forms), `crates/paksmith-gui/src/widgets/file_tree.rs` (virtualized scrollable list, pure helpers + `#[mutants::skip]` row builder), `crates/paksmith-gui/src/state/tree.rs` (pure model shape), `crates/paksmith-gui/src/panels/detail.rs` (`human_size`, `compression_ratio` — reused by Info), `crates/paksmith-gui/src/theme/tokens.rs`.
- **Core property data shape:** `crates/paksmith-core/src/asset/property/primitives.rs` (the `PropertyValue` enum — all variants), `crates/paksmith-core/src/asset/property/bag.rs` (`PropertyBag::{Tree{properties:Vec<Property>}, Opaque{bytes}}`, `#[non_exhaustive]`).
- **The canonical "walk a parsed Package" example:** `crates/paksmith-cli/src/inspect/tree.rs` — `render` / `render_export` / `render_bag` / `typed_variant_bag` / `class_name`. The GUI writes its **own** view-model + widgets (CLI/GUI never share code) but the *walk structure* is identical.

### Core facts the plan relies on (verbatim)

- `Package::read_from_reader(reader: &Arc<paksmith_core::container::pak::PakReader>, virtual_path: &str, mappings: Option<&paksmith_core::asset::mappings::Usmap>) -> paksmith_core::Result<Package>`. 7a always passes `mappings = None`.
- `Package` (`Debug + Clone`) fields: `asset_path: String`, `summary: PackageSummary`, `names: Arc<NameTable>`, `imports: Arc<ImportTable>`, `exports: Arc<ExportTable>`, `payloads: Vec<paksmith_core::asset::Asset>`.
- `pkg.exports.exports: Vec<Export>`; `Export { class_index: PackageIndex, object_name: u32, object_name_number: u32, .. }`.
- Name resolution: `pkg.names.resolve(object_name: u32, object_name_number: u32) -> String`.
- `pkg.payloads.get(idx) -> Option<&Asset>`. `Asset` (`#[non_exhaustive]`, `Debug + Clone + PartialEq`): `Asset::Generic(PropertyBag)` plus typed variants. A payload's tagged-property bag is obtained exactly as the CLI's `typed_variant_bag` does:
  ```rust
  fn payload_bag(asset: &paksmith_core::asset::Asset) -> Option<&paksmith_core::asset::PropertyBag> {
      use paksmith_core::asset::Asset;
      match asset {
          Asset::Generic(bag) => Some(bag),
          Asset::DataTable(d) => Some(&d.class_properties),
          Asset::Texture2D(t) => Some(&t.properties),
          Asset::SoundWave(s) => Some(&s.properties),
          Asset::StaticMesh(m) => Some(&m.properties),
          Asset::SkeletalMesh(m) => Some(&m.properties),
          _ => None,
      }
  }
  ```
- `PropertyBag` (`#[non_exhaustive]`): `PropertyBag::Tree { properties: Vec<Property> }` | `PropertyBag::Opaque { bytes: Vec<u8> }`. Always include a catch-all arm.
- `Property { fn name(&self) -> &str, array_index: i32, guid: Option<[u8;16]>, value: PropertyValue }`.
- `PropertyValue` (`#[non_exhaustive]`) variants: `Bool(bool)`, `Byte(u8)`, `Int8(i8)`, `Int16(i16)`, `Int(i32)`, `Int64(i64)`, `UInt16(u16)`, `UInt32(u32)`, `UInt64(u64)`, `Float(f32)`, `Double(f64)`, `Str(String)`, `Name(Arc<str>)`, `Enum { type_name: Arc<str>, value: Arc<str> }`, `Text(FText)`, `Unknown { type_name: String, skipped_bytes: usize }`, `Array { inner_type: Arc<str>, elements: Vec<PropertyValue> }`, `Struct { struct_name: Arc<str>, properties: Vec<Property> }`, `TypedStruct(Box<TypedStructValue>)`, `Map { key_type: Arc<str>, value_type: Arc<str>, entries: Vec<MapEntry> }`, `Set { inner_type: Arc<str>, elements: Vec<PropertyValue> }`, `SoftObjectPath { asset_path: String, sub_path: String }`, `SoftClassPath { asset_path: String, sub_path: String }`, `Object { kind: PackageIndex, name: String }`. `MapEntry { key: PropertyValue, value: PropertyValue }`. Always include a catch-all arm (`#[non_exhaustive]`).
- `ContainerReader::read_entry(&self, path: &str) -> paksmith_core::Result<Vec<u8>>` (import `paksmith_core::container::ContainerReader`).
- **Test fixtures** (under repo `tests/fixtures/`, reached from the gui crate via `env!("CARGO_MANIFEST_DIR")/../../tests/fixtures`):
  - `real_v8b_uasset.pak` — single entry `Game/Maps/Demo.uasset` → parses to `Asset::Generic` (use for parse-success + property-tree tests).
  - `real_v8b_multi.pak` — multi-entry plain pak (tree / multi-tab tests).
  - `real_v8b_encrypted_index.pak` — encrypted (key `94d25bc3aeb420e0be914edc9d5435a1eaab5f2864e09e94019ac205b727a7de`).

### Shared interface summary (lock these names across tasks)

```rust
// crate::state::tabs
pub enum ViewMode { Properties, Hex, Info }          // Debug, Clone, Copy, PartialEq, Eq
pub enum TabContent {                                 // Debug, Clone
    Loading,
    Ready { bytes: Vec<u8>, parsed: Result<Box<paksmith_core::asset::Package>, String> },
}
pub struct Tab {                                      // Debug, Clone
    pub path: String,                                 // full entry path = tab identity
    pub view: ViewMode,
    pub content: TabContent,
    // added by Task 4: pub hex: crate::state::hex_view::HexState,
    // added by Task 5: pub expanded: std::collections::HashSet<crate::state::property_view::NodeId>,
}
pub struct Tabs { pub open: Vec<Tab>, pub active: Option<usize> }   // Debug, Clone, Default

// crate::task::asset
pub struct AssetLoad {                                // Debug, Clone
    pub bytes: Vec<u8>,
    pub parsed: Result<Box<paksmith_core::asset::Package>, String>,
}
pub async fn load(reader: std::sync::Arc<PakReader>, path: String) -> AssetLoad;

// crate::state::hex_view
pub struct Selection { pub anchor: usize, pub cursor: usize }       // Debug, Clone, Copy, PartialEq, Eq
pub struct HexState { pub selection: Option<Selection>, pub dragging: bool }  // Debug, Clone, Default

// crate::state::property_view
pub type NodeId = u64;                                // stable per-row id from the flatten walk
pub struct PropRow { pub depth, label, value, is_expandable, expanded, node_id, kind }
```

New `Message` variants (added in Task 7): `OpenAsset(String)`, `AssetLoaded { path: String, load: Box<crate::task::asset::AssetLoad> }`, `TabActivated(usize)`, `TabClosed(usize)`, `ViewModeSet(crate::state::tabs::ViewMode)`, `PropToggled(crate::state::property_view::NodeId)`, `HexBytePressed(usize)`, `HexByteEntered(usize)`, `HexDragEnded`, `HexCopyRequested`, `HexCopyAsciiRequested`.

---

### Task 1: Retain `Arc<PakReader>` in `LoadedArchive`

**Files:**
- Modify: `crates/paksmith-gui/src/state/archive.rs` (the `LoadedArchive` struct + derives)
- Modify: `crates/paksmith-gui/src/task/open.rs:104-146` (`build_loaded`)

**Interfaces:**
- Produces: `LoadedArchive.reader: std::sync::Arc<paksmith_core::container::pak::PakReader>` — the open reader, reused by the asset-load task (Task 2) and the open-asset dispatch (Task 7).

- [ ] **Step 1: Write the failing test** — append to the `tests` module in `crates/paksmith-gui/src/task/open.rs`:

```rust
    #[tokio::test]
    async fn loaded_archive_retains_reader_for_entry_reads() {
        use paksmith_core::container::ContainerReader as _;
        let path = fixture_path("real_v8b_uasset.pak");
        let loaded = run(path, None).await.unwrap();
        // The retained reader must be able to read an entry's bytes on demand.
        let bytes = loaded.reader.read_entry("Game/Maps/Demo.uasset").unwrap();
        assert!(!bytes.is_empty(), "retained reader must read entry bytes");
    }
```

- [ ] **Step 2: Run it, verify it fails** — `cargo test -p paksmith-gui loaded_archive_retains_reader` → FAIL (`no field reader on LoadedArchive`).

- [ ] **Step 3: Add the field + manual Debug** in `crates/paksmith-gui/src/state/archive.rs`. Change `#[derive(Debug, Clone)]` on `LoadedArchive` to `#[derive(Clone)]`, add the field, and add a manual `Debug`:

```rust
use std::sync::Arc;
use paksmith_core::container::pak::PakReader;

/// A successfully opened archive and its derived state.
#[derive(Clone)]
pub struct LoadedArchive {
    pub path: PathBuf,
    pub entry_count: usize,
    pub decrypted: bool,
    pub tree: Tree,
    pub entries: BTreeMap<String, EntryMeta>,
    /// The open pak reader, retained so asset tabs can read + parse entries on
    /// demand. `Arc` so the async asset-load task can share it across the
    /// `Task::perform` boundary (`PakReader` is `Send + Sync`).
    pub reader: Arc<PakReader>,
}

// `PakReader` does not implement `Debug`; format it as an opaque marker so
// `LoadedArchive` (and therefore `Message`) keeps its `Debug` bound without
// touching core.
impl std::fmt::Debug for LoadedArchive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadedArchive")
            .field("path", &self.path)
            .field("entry_count", &self.entry_count)
            .field("decrypted", &self.decrypted)
            .field("tree", &self.tree)
            .field("entries", &self.entries)
            .field("reader", &"<PakReader>")
            .finish()
    }
}
```

- [ ] **Step 4: Populate it** in `build_loaded` (`task/open.rs`). Wrap the reader in `Arc` before collecting entries, then store the `Arc` in the struct:

```rust
    // (replace `let reader = match open_result { ... }` tail and the struct build)
    let reader = match open_result {
        Ok(r) => std::sync::Arc::new(r),
        Err(PaksmithError::Decryption { .. }) if resolved_key.is_none() => {
            return Err(OpenError::Locked { path });
        }
        Err(e) => return Err(e.into()),
    };

    let raw_entries: Vec<_> = reader.entries().collect();   // Arc<PakReader> derefs to &PakReader
    let entry_count = raw_entries.len();
    let mut entries = std::collections::BTreeMap::new();
    let mut paths: Vec<String> = Vec::with_capacity(entry_count);
    for e in raw_entries {
        let path_str = e.path().to_string();
        let _ = entries.insert(path_str.clone(), EntryMeta {
            uncompressed_size: e.uncompressed_size(),
            compressed_size: e.compressed_size(),
            is_compressed: e.is_compressed(),
            is_encrypted: e.is_encrypted(),
        });
        paths.push(path_str);
    }
    let tree = Tree::from_paths(paths);
    Ok(LoadedArchive { path, entry_count, decrypted: resolved_key.is_some(), tree, entries, reader })
```

Update the `app_with_paths` test helper in `app.rs` (Task 1 touches it because it constructs `LoadedArchive` literally): add `reader: std::sync::Arc::new(...)`. Since constructing a real `PakReader` in that unit helper is heavy, instead open the smallest fixture once: replace the literal `LoadedArchive { .. }` build in `app.rs`'s `app_with_paths` with a field added via opening `real_v8b_uasset.pak` is overkill — instead, keep `app_with_paths` synchronous by having it build the reader from the same fixture with `PakReader::open`. Simpler: change `app_with_paths` to also open `real_v8b_uasset.pak` for the `reader` field:

```rust
        let reader = std::sync::Arc::new(
            paksmith_core::container::pak::PakReader::open(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .parent().unwrap().parent().unwrap()
                    .join("tests/fixtures/real_v8b_uasset.pak"),
            ).expect("open fixture for test reader"),
        );
        let archive = LoadedArchive { path: PathBuf::from("test.pak"), entry_count, decrypted: false, tree, entries, reader };
```

- [ ] **Step 5: Run tests + gates** — `cargo test -p paksmith-gui` → PASS (existing open tests + new reader test + keyboard-nav tests). Then `cargo fmt --all` + `cargo clippy --workspace --all-targets --all-features -- -D warnings`.

- [ ] **Step 6: Commit** — `git add -A && git commit -m "feat(gui): retain Arc<PakReader> in LoadedArchive for on-demand asset reads"`

---

### Task 2: Async asset-load task

**Files:**
- Create: `crates/paksmith-gui/src/task/asset.rs`
- Modify: `crates/paksmith-gui/src/task/mod.rs` (add `pub mod asset;`)

**Interfaces:**
- Consumes: `LoadedArchive.reader` (Task 1); `Package::read_from_reader`; `ContainerReader::read_entry`.
- Produces: `AssetLoad { bytes: Vec<u8>, parsed: Result<Box<Package>, String> }` (`Debug + Clone`); `async fn load(reader: Arc<PakReader>, path: String) -> AssetLoad`; pure `fn should_attempt_parse(path: &str) -> bool`.

- [ ] **Step 1: Write the failing tests** in `crates/paksmith-gui/src/task/asset.rs`:

```rust
//! Async asset-load pipeline: read an entry's raw bytes (for Hex/Info) and
//! parse it as a UAsset `Package` (for Properties), both off the UI thread.

use std::sync::Arc;

use paksmith_core::asset::Package;
use paksmith_core::container::ContainerReader as _;
use paksmith_core::container::pak::PakReader;

/// Result of loading one asset entry: the raw bytes (always present on a
/// successful entry read) plus the parse outcome (`Ok` for parseable UAssets,
/// `Err(reason)` otherwise — the Hex/Info views still work from `bytes`).
#[derive(Debug, Clone)]
pub struct AssetLoad {
    pub bytes: Vec<u8>,
    pub parsed: Result<Box<Package>, String>,
}

/// Whether `path` looks like a parseable UAsset header (so we attempt a parse).
/// Non-UAsset entries (`.uexp`, `.ubulk`, textures, raw files) skip the parse —
/// they have no standalone property bag — and render Hex + Info only.
pub fn should_attempt_parse(path: &str) -> bool {
    let lower = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    lower.ends_with(".uasset") || lower.ends_with(".umap")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture(name: &str) -> PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent().unwrap().parent().unwrap()
            .join("tests/fixtures").join(name)
    }

    #[test]
    fn should_attempt_parse_only_for_uasset_umap() {
        assert!(should_attempt_parse("Game/Maps/Demo.uasset"));
        assert!(should_attempt_parse("Game/Maps/Level.umap"));
        assert!(should_attempt_parse("A/B/UPPER.UASSET")); // case-insensitive
        assert!(!should_attempt_parse("Game/Maps/Demo.uexp"));
        assert!(!should_attempt_parse("Game/T_Rock.ubulk"));
        assert!(!should_attempt_parse("readme.txt"));
    }

    #[tokio::test]
    async fn load_parses_uasset_fixture() {
        let reader = Arc::new(PakReader::open(fixture("real_v8b_uasset.pak")).unwrap());
        let out = load(reader, "Game/Maps/Demo.uasset".to_string()).await;
        assert!(!out.bytes.is_empty(), "raw bytes must be present");
        assert!(out.parsed.is_ok(), "Demo.uasset must parse: {:?}", out.parsed.err());
    }

    #[tokio::test]
    async fn load_missing_entry_is_err_with_empty_bytes() {
        let reader = Arc::new(PakReader::open(fixture("real_v8b_uasset.pak")).unwrap());
        let out = load(reader, "Game/Does/Not/Exist.uasset".to_string()).await;
        assert!(out.bytes.is_empty(), "missing entry yields no bytes");
        assert!(out.parsed.is_err(), "missing entry must be a parse error");
    }
}
```

- [ ] **Step 2: Run, verify fail** — `cargo test -p paksmith-gui asset::` → FAIL (`load` not defined).

- [ ] **Step 3: Implement `load`** (append above the test module):

```rust
/// Read `path`'s raw bytes and, when it looks like a UAsset, parse it.
///
/// `bytes` is whatever `read_entry` returns (empty on a read error). `parsed`
/// is `Ok` only when the entry both looks parseable and parses cleanly; every
/// failure path is stringified so the result stays `Clone` for `Message`.
pub async fn load(reader: Arc<PakReader>, path: String) -> AssetLoad {
    let bytes = reader.read_entry(&path).unwrap_or_default();

    let parsed = if should_attempt_parse(&path) {
        // `mappings = None`: 7a does not load `.usmap`. Unversioned assets that
        // require a mapping return `UnversionedWithoutMappings`, surfaced here
        // as a stringified parse error → Properties view shows the reason.
        Package::read_from_reader(&reader, &path, None)
            .map(Box::new)
            .map_err(|e| e.to_string())
    } else {
        Err(format!("{path} is not a UAsset — showing raw bytes"))
    };

    AssetLoad { bytes, parsed }
}
```

- [ ] **Step 4: Run tests** — `cargo test -p paksmith-gui asset::` → PASS.

- [ ] **Step 5: Gates** — `cargo fmt --all` + clippy.

- [ ] **Step 6: Commit** — `git add -A && git commit -m "feat(gui): add async asset-load task (bytes + Package parse)"`

---

### Task 3: `state/tabs.rs` — pure tab model

**Files:**
- Create: `crates/paksmith-gui/src/state/tabs.rs`
- Modify: `crates/paksmith-gui/src/state/mod.rs` (add `pub mod tabs;`)

**Interfaces:**
- Produces: `ViewMode`, `TabContent`, `Tab`, `Tabs` (see shared summary) + ops: `Tabs::open_or_activate(path) -> usize`, `Tabs::close(idx)`, `Tabs::activate(idx)`, `Tabs::set_view(idx, ViewMode)`, `Tabs::set_content(path, TabContent)`, `Tabs::clear()`, `Tabs::active_tab(&self) -> Option<&Tab>`.

- [ ] **Step 1: Write the failing tests** (representative — include all):

```rust
//! Pure tab-collection model for the content host. No `iced` imports.

use paksmith_core::asset::Package;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewMode { Properties, Hex, Info }

#[derive(Debug, Clone)]
pub enum TabContent {
    Loading,
    Ready { bytes: Vec<u8>, parsed: Result<Box<Package>, String> },
}

#[derive(Debug, Clone)]
pub struct Tab {
    pub path: String,
    pub view: ViewMode,
    pub content: TabContent,
}

#[derive(Debug, Clone, Default)]
pub struct Tabs {
    pub open: Vec<Tab>,
    pub active: Option<usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loading_tabs(paths: &[&str]) -> Tabs {
        let mut t = Tabs::default();
        for p in paths { let _ = t.open_or_activate(p); }
        t
    }

    #[test]
    fn open_new_path_appends_and_activates() {
        let mut t = Tabs::default();
        let i = t.open_or_activate("A.uasset");
        assert_eq!(i, 0);
        assert_eq!(t.open.len(), 1);
        assert_eq!(t.active, Some(0));
        assert!(matches!(t.open[0].content, TabContent::Loading));
        assert_eq!(t.open[0].view, ViewMode::Properties); // default view
    }

    #[test]
    fn open_existing_path_activates_without_duplicating() {
        let mut t = loading_tabs(&["A", "B"]);
        let i = t.open_or_activate("A"); // already open at 0
        assert_eq!(i, 0);
        assert_eq!(t.open.len(), 2, "must not duplicate");
        assert_eq!(t.active, Some(0));
    }

    #[test]
    fn close_active_repicks_previous() {
        let mut t = loading_tabs(&["A", "B", "C"]); // active = 2
        t.close(2);
        assert_eq!(t.open.len(), 2);
        assert_eq!(t.active, Some(1), "closing active tail re-picks the new last");
    }

    #[test]
    fn close_before_active_shifts_active_index_down() {
        let mut t = loading_tabs(&["A", "B", "C"]);
        t.activate(2);
        t.close(0); // removed before active → active shifts 2→1
        assert_eq!(t.active, Some(1));
        assert_eq!(t.open[t.active.unwrap()].path, "C");
    }

    #[test]
    fn close_last_remaining_clears_active() {
        let mut t = loading_tabs(&["A"]);
        t.close(0);
        assert!(t.open.is_empty());
        assert_eq!(t.active, None);
    }

    #[test]
    fn close_out_of_bounds_is_noop() {
        let mut t = loading_tabs(&["A"]);
        t.close(99);
        assert_eq!(t.open.len(), 1);
    }

    #[test]
    fn set_view_changes_only_target_tab() {
        let mut t = loading_tabs(&["A", "B"]);
        t.set_view(0, ViewMode::Hex);
        assert_eq!(t.open[0].view, ViewMode::Hex);
        assert_eq!(t.open[1].view, ViewMode::Properties);
    }

    #[test]
    fn set_content_targets_by_path_not_index() {
        let mut t = loading_tabs(&["A", "B"]);
        t.set_content("A", TabContent::Ready { bytes: vec![1, 2], parsed: Err("x".into()) });
        assert!(matches!(t.open[0].content, TabContent::Ready { .. }));
        assert!(matches!(t.open[1].content, TabContent::Loading));
    }

    #[test]
    fn set_content_for_closed_path_is_noop() {
        // A late async result for an already-closed tab must not panic or reopen.
        let mut t = loading_tabs(&["A"]);
        t.close(0);
        t.set_content("A", TabContent::Ready { bytes: vec![], parsed: Err("x".into()) });
        assert!(t.open.is_empty());
    }

    #[test]
    fn clear_empties_all() {
        let mut t = loading_tabs(&["A", "B"]);
        t.clear();
        assert!(t.open.is_empty());
        assert_eq!(t.active, None);
    }

    #[test]
    fn activate_out_of_bounds_is_noop() {
        let mut t = loading_tabs(&["A"]);
        t.activate(5);
        assert_eq!(t.active, Some(0));
    }
}
```

- [ ] **Step 2: Run, verify fail** — `cargo test -p paksmith-gui tabs::` → FAIL (methods undefined).

- [ ] **Step 3: Implement** (insert `impl Tabs` above the tests):

```rust
impl Tabs {
    /// Open `path` in a new Loading tab and activate it, or just activate the
    /// existing tab if `path` is already open. Returns the active index.
    pub fn open_or_activate(&mut self, path: &str) -> usize {
        if let Some(i) = self.open.iter().position(|t| t.path == path) {
            self.active = Some(i);
            return i;
        }
        self.open.push(Tab { path: path.to_string(), view: ViewMode::Properties, content: TabContent::Loading });
        let i = self.open.len() - 1;
        self.active = Some(i);
        i
    }

    /// Close the tab at `idx` (no-op if out of bounds), re-picking `active`.
    pub fn close(&mut self, idx: usize) {
        if idx >= self.open.len() { return; }
        let _ = self.open.remove(idx);
        if self.open.is_empty() {
            self.active = None;
            return;
        }
        self.active = Some(match self.active {
            Some(a) if a > idx => a - 1,          // active shifted left
            Some(a) if a < idx => a,              // active unaffected
            _ => idx.min(self.open.len() - 1),    // closed the active tab → clamp
        });
    }

    /// Activate the tab at `idx` (no-op if out of bounds).
    pub fn activate(&mut self, idx: usize) {
        if idx < self.open.len() { self.active = Some(idx); }
    }

    /// Set the view mode of the tab at `idx` (no-op if out of bounds).
    pub fn set_view(&mut self, idx: usize, view: ViewMode) {
        if let Some(t) = self.open.get_mut(idx) { t.view = view; }
    }

    /// Replace the content of the tab identified by `path` (no-op if closed).
    pub fn set_content(&mut self, path: &str, content: TabContent) {
        if let Some(t) = self.open.iter_mut().find(|t| t.path == path) { t.content = content; }
    }

    /// Drop all tabs (called when the archive changes).
    pub fn clear(&mut self) {
        self.open.clear();
        self.active = None;
    }

    /// The currently active tab, if any.
    pub fn active_tab(&self) -> Option<&Tab> {
        self.active.and_then(|i| self.open.get(i))
    }
}
```

- [ ] **Step 4: Run** — `cargo test -p paksmith-gui tabs::` → PASS.
- [ ] **Step 5: Gates** — fmt + clippy.
- [ ] **Step 6: Commit** — `git commit -am "feat(gui): add pure tab-collection model (state/tabs)"`

---

### Task 4: `state/hex_view.rs` — pure hex model (rows, selection, copy)

**Files:**
- Create: `crates/paksmith-gui/src/state/hex_view.rs`
- Modify: `crates/paksmith-gui/src/state/mod.rs` (`pub mod hex_view;`)
- Modify: `crates/paksmith-gui/src/state/tabs.rs` (add `pub hex: crate::state::hex_view::HexState` to `Tab`, defaulting to `HexState::default()` in `open_or_activate`)

**Interfaces:**
- Produces: `BYTES_PER_ROW: usize = 16`; `fn total_rows(len: usize) -> usize`; `fn row_bytes(bytes: &[u8], row: usize) -> &[u8]`; `Selection { anchor, cursor }` with `fn range(&self) -> (usize, usize)` (normalized inclusive) and `fn contains(&self, i: usize) -> bool`; `HexState { selection: Option<Selection>, dragging: bool }` with `press(i)`, `enter(i)`, `end_drag()`; `fn copy_hex(bytes, sel) -> String`; `fn copy_ascii(bytes, sel) -> String`.

- [ ] **Step 1: Write the failing tests**:

```rust
//! Pure hex-view model: row math, click-drag selection, copy formatting.
//! No `iced` imports.

pub const BYTES_PER_ROW: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Selection { pub anchor: usize, pub cursor: usize }

#[derive(Debug, Clone, Default)]
pub struct HexState { pub selection: Option<Selection>, pub dragging: bool }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn total_rows_ceil_divides() {
        assert_eq!(total_rows(0), 0);
        assert_eq!(total_rows(1), 1);
        assert_eq!(total_rows(16), 1);
        assert_eq!(total_rows(17), 2);
        assert_eq!(total_rows(32), 2);
    }

    #[test]
    fn row_bytes_returns_short_final_row() {
        let data: Vec<u8> = (0..20).collect();
        assert_eq!(row_bytes(&data, 0).len(), 16);
        assert_eq!(row_bytes(&data, 1), &[16, 17, 18, 19]); // short tail
        assert_eq!(row_bytes(&data, 5), &[] as &[u8]);      // out of range → empty
    }

    #[test]
    fn selection_range_normalizes_backward_drag() {
        assert_eq!(Selection { anchor: 2, cursor: 7 }.range(), (2, 7));
        assert_eq!(Selection { anchor: 7, cursor: 2 }.range(), (2, 7)); // backward
        assert_eq!(Selection { anchor: 4, cursor: 4 }.range(), (4, 4)); // single byte
    }

    #[test]
    fn selection_contains_is_inclusive() {
        let s = Selection { anchor: 7, cursor: 2 };
        assert!(s.contains(2) && s.contains(7) && s.contains(5));
        assert!(!s.contains(1) && !s.contains(8));
    }

    #[test]
    fn drag_press_starts_selection_and_dragging() {
        let mut h = HexState::default();
        h.press(5);
        assert_eq!(h.selection, Some(Selection { anchor: 5, cursor: 5 }));
        assert!(h.dragging);
    }

    #[test]
    fn drag_enter_extends_only_while_dragging() {
        let mut h = HexState::default();
        h.press(5);
        h.enter(9);
        assert_eq!(h.selection.unwrap().range(), (5, 9));
        h.end_drag();
        assert!(!h.dragging);
        h.enter(0); // not dragging → ignored
        assert_eq!(h.selection.unwrap().range(), (5, 9));
    }

    #[test]
    fn copy_hex_formats_uppercase_space_separated() {
        let data = vec![0x00, 0xC1, 0x2A, 0xFF];
        let sel = Selection { anchor: 1, cursor: 3 }; // bytes 1..=3
        assert_eq!(copy_hex(&data, sel), "C1 2A FF");
    }

    #[test]
    fn copy_ascii_uses_dot_for_nonprintable() {
        let data = vec![b'A', 0x00, b'z', 0x7f];
        let sel = Selection { anchor: 0, cursor: 3 };
        assert_eq!(copy_ascii(&data, sel), "A.z."); // 0x00 and 0x7f → '.'
    }

    #[test]
    fn copy_clamps_range_to_data_len() {
        let data = vec![0xAA, 0xBB];
        let sel = Selection { anchor: 0, cursor: 99 }; // cursor past end
        assert_eq!(copy_hex(&data, sel), "AA BB"); // clamped, no panic
    }
}
```

- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement**:

```rust
#[must_use]
pub fn total_rows(len: usize) -> usize { len.div_ceil(BYTES_PER_ROW) }

#[must_use]
pub fn row_bytes(bytes: &[u8], row: usize) -> &[u8] {
    let start = row * BYTES_PER_ROW;
    if start >= bytes.len() { return &[]; }
    let end = (start + BYTES_PER_ROW).min(bytes.len());
    &bytes[start..end]
}

impl Selection {
    #[must_use]
    pub fn range(&self) -> (usize, usize) {
        (self.anchor.min(self.cursor), self.anchor.max(self.cursor))
    }
    #[must_use]
    pub fn contains(&self, i: usize) -> bool {
        let (lo, hi) = self.range();
        i >= lo && i <= hi
    }
}

impl HexState {
    pub fn press(&mut self, i: usize) {
        self.selection = Some(Selection { anchor: i, cursor: i });
        self.dragging = true;
    }
    pub fn enter(&mut self, i: usize) {
        if self.dragging {
            if let Some(s) = self.selection.as_mut() { s.cursor = i; }
        }
    }
    pub fn end_drag(&mut self) { self.dragging = false; }
}

/// Selected bytes as uppercase, space-separated hex (`"C1 2A FF"`). Empty when
/// the range lies entirely past the data.
#[must_use]
pub fn copy_hex(bytes: &[u8], sel: Selection) -> String {
    let (lo, hi) = clamped_range(bytes.len(), sel);
    if lo > hi { return String::new(); }
    bytes[lo..=hi].iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ")
}

/// Selected bytes as ASCII, non-printable → `'.'`.
#[must_use]
pub fn copy_ascii(bytes: &[u8], sel: Selection) -> String {
    let (lo, hi) = clamped_range(bytes.len(), sel);
    if lo > hi { return String::new(); }
    bytes[lo..=hi].iter()
        .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' })
        .collect()
}

/// Inclusive [lo, hi] clamped to `[0, len)`. Returns `(1, 0)` (lo>hi) when empty.
fn clamped_range(len: usize, sel: Selection) -> (usize, usize) {
    if len == 0 { return (1, 0); }
    let (lo, hi) = sel.range();
    (lo.min(len - 1), hi.min(len - 1))
}
```

Then add `hex: HexState` to `Tab` (Task 3 file) and set `hex: crate::state::hex_view::HexState::default()` in `open_or_activate`.

- [ ] **Step 4: Run** `cargo test -p paksmith-gui hex_view::` + `tabs::` → PASS.
- [ ] **Step 5: Gates.**
- [ ] **Step 6: Commit** — `git commit -am "feat(gui): add pure hex-view model (rows, drag selection, copy)"`

---

### Task 5: `state/property_view.rs` — flatten + expansion + scalar display

**Files:**
- Create: `crates/paksmith-gui/src/state/property_view.rs`
- Modify: `crates/paksmith-gui/src/state/mod.rs` (`pub mod property_view;`)
- Modify: `crates/paksmith-gui/src/state/tabs.rs` (add `pub expanded: std::collections::HashSet<crate::state::property_view::NodeId>` to `Tab`, default empty)

**Interfaces:**
- Consumes: `Package`, `Asset`, `PropertyBag`, `Property`, `PropertyValue`, `MapEntry` (core); the `payload_bag` helper (copy it into this module — it's a few lines, see Reference).
- Produces: `type NodeId = u64`; `enum PropKind { Branch, Leaf }`; `struct PropRow { depth: usize, label: String, value: Option<String>, node_id: NodeId, is_expandable: bool, expanded: bool, kind: PropKind }`; `fn flatten(pkg: &Package, expanded: &HashSet<NodeId>) -> Vec<PropRow>`; `fn scalar_display(v: &PropertyValue) -> Option<String>` (this task: scalars + a count summary for containers; Task 6 enriches).

**Design notes for the implementer:**
- `NodeId` is a **stable hash of the path-from-root** (export index + property-name/array-index chain), so expand/collapse survives re-flattening. Build it by hashing the parent `NodeId` together with the current segment (`std::hash::Hasher`); seed the root with the export index. Two sibling properties with the same name but different `array_index` must get different ids — fold `array_index` into the hash.
- Top level = one Branch row per export: label `"[{idx}] {object_name} : {class}"` (resolve via `pkg.names.resolve(..)` and a `class_name`-style match on `export.class_index` — copy the structure from `cli/src/inspect/tree.rs::class_name`). Its children are the export's property bag rows (only when `expanded` contains the export's id).
- Expandable `PropertyValue`s: `Struct { properties }`, `Array { elements }`, `Set { elements }`, `Map { entries }`. Leaf scalars get `value = Some(scalar_display(..))`. `Opaque { bytes }` bags render a single leaf row `"<opaque N bytes>"`. Always handle the `#[non_exhaustive]` catch-all (`_ => Some("<unhandled>".into())`).
- Bound recursion defensively with a depth cap constant `const MAX_RENDER_DEPTH: usize = 64;` (value-pin it in a test) even though core already caps parse depth.

- [ ] **Step 1: Write failing tests** — use a hand-built `Package` is heavy; instead load the real fixture and assert structural invariants, plus pure-unit tests on `scalar_display`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use paksmith_core::asset::property::primitives::PropertyValue;
    use std::collections::HashSet;
    use std::sync::Arc;

    fn demo_package() -> paksmith_core::asset::Package {
        use paksmith_core::container::pak::PakReader;
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent().unwrap().parent().unwrap()
            .join("tests/fixtures/real_v8b_uasset.pak");
        let reader = Arc::new(PakReader::open(p).unwrap());
        *paksmith_core::asset::Package::read_from_reader(&reader, "Game/Maps/Demo.uasset", None)
            .unwrap()
    }

    #[test]
    fn scalar_display_renders_primitives() {
        assert_eq!(scalar_display(&PropertyValue::Bool(true)).as_deref(), Some("true"));
        assert_eq!(scalar_display(&PropertyValue::Int(42)).as_deref(), Some("42"));
        assert_eq!(scalar_display(&PropertyValue::Float(1.5)).as_deref(), Some("1.5"));
        assert_eq!(scalar_display(&PropertyValue::Str("hi".into())).as_deref(), Some("\"hi\""));
    }

    #[test]
    fn flatten_collapsed_shows_only_export_rows() {
        let pkg = demo_package();
        let rows = flatten(&pkg, &HashSet::new());
        assert!(!rows.is_empty(), "at least one export row");
        assert!(rows.iter().all(|r| r.depth == 0), "collapsed = only top-level export rows");
    }

    #[test]
    fn flatten_expanding_export_reveals_children() {
        let pkg = demo_package();
        let collapsed = flatten(&pkg, &HashSet::new());
        let first = collapsed[0].node_id;
        assert!(collapsed[0].is_expandable, "export row must be expandable");
        let mut exp = HashSet::new();
        exp.insert(first);
        let expanded = flatten(&pkg, &exp);
        assert!(expanded.len() >= collapsed.len(), "expanding never removes rows");
        assert!(expanded.iter().any(|r| r.depth == 1), "expanded export shows child rows");
    }

    #[test]
    fn node_ids_are_stable_across_flattens() {
        let pkg = demo_package();
        let a = flatten(&pkg, &HashSet::new());
        let b = flatten(&pkg, &HashSet::new());
        let ids_a: Vec<_> = a.iter().map(|r| r.node_id).collect();
        let ids_b: Vec<_> = b.iter().map(|r| r.node_id).collect();
        assert_eq!(ids_a, ids_b, "node ids must be deterministic");
    }

    #[test]
    fn max_render_depth_is_64() {
        assert_eq!(MAX_RENDER_DEPTH, 64);
    }
}
```

- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** `flatten`, `scalar_display`, `NodeId` hashing, `PropRow`, `PropKind`, the copied `payload_bag` + `class_name` helpers, and `MAX_RENDER_DEPTH`. Walk: for each export → push a Branch row; if its id ∈ `expanded`, recurse into `payload_bag(payload)` rows at depth+1. For each `Property`: expandable variants push a Branch row (label = `prop.name()`, plus a count suffix like `" [N]"` for arrays/maps/sets) and recurse when expanded; scalars push a Leaf row with `value = scalar_display(&prop.value)`. Use an explicit recursion-depth guard against `MAX_RENDER_DEPTH`.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Gates.**
- [ ] **Step 6: Commit** — `git commit -am "feat(gui): add property-tree flatten model with stable node ids"`

---

### Task 6: `state/property_view.rs` — rich type-aware formatters

**Files:**
- Modify: `crates/paksmith-gui/src/state/property_view.rs`

**Interfaces:**
- Produces: `fn as_color(v: &PropertyValue) -> Option<[f32; 4]>` (RGBA 0..=1 for color-like typed structs, else `None`); enriched `scalar_display` for `Enum`, `Name`, `Object`, `SoftObjectPath`, `SoftClassPath`, `Byte`, `Text`, and `TypedStruct` (vector/rotator/etc. via a compact formatter). The widget (Task 10) renders a swatch when `as_color` is `Some`.

**Design notes:**
- `as_color` inspects `PropertyValue::TypedStruct(b)` for `FColor`/`FLinearColor` variants of `TypedStructValue` (see `crates/paksmith-core/src/asset/structs/color.rs` — mirror `cli/src/inspect/tree.rs::fmt_color`/`fmt_linear_color` for the field access; `FColor` is `u8` RGBA → divide by 255.0; `FLinearColor` is `f32` RGBA → clamp 0..=1). Return `None` for every non-color value.
- `scalar_display` enrichment: `Enum { type_name, value }` → `"{type}::{value}"` (or just `value` when `type_name` is empty); `Name(s)` → the string; `Object { name, .. }` → `name` (or `"<null>"` when empty); `SoftObjectPath { asset_path, .. }` → `asset_path`; `Byte(b)` → decimal; `Text(t)` → its display string; `TypedStruct(b)` → a compact one-line form (e.g. vectors `"(x, y, z)"`) reusing the same `{}`-not-`{:?}` whole-float style as `cli/.../tree.rs::fmt_vector`.

- [ ] **Step 1: Write failing tests** for `as_color` (build `PropertyValue::TypedStruct` with an `FColor`/`FLinearColor` — copy the construction pattern from a core test in `asset/structs/color.rs`) and for the enriched `scalar_display` arms (`Enum`, `Object` null vs named, `SoftObjectPath`). Assert exact strings and that `as_color` returns `None` for `Int`, `Str`, etc. Add channel-pinning asserts for `as_color` (an `FColor` of `(255, 0, 0, 255)` → `[1.0, 0.0, 0.0, 1.0]`) to kill arithmetic mutants on the `/255.0` conversions.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** the formatters.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Gates.**
- [ ] **Step 6: Commit** — `git commit -am "feat(gui): add type-aware property formatters + color detection"`

---

### Task 7: `app.rs` integration — tabs state, messages, open-on-open, content host wiring

**Files:**
- Modify: `crates/paksmith-gui/src/app.rs` (App field, Message variants, update arms, view content-host wiring, Enter-to-open, archive-change clears tabs)
- Modify: `crates/paksmith-gui/src/widgets/file_tree.rs` (file rows → `mouse_area` with `on_press`=select, `on_double_click`=`OpenAsset`)
- Create: `crates/paksmith-gui/src/panels/content.rs` (content host: view switcher + Info view real; Properties/Hex are simple text placeholders replaced in Tasks 9/10)
- Modify: `crates/paksmith-gui/src/panels/mod.rs` (`pub mod content;`)

**Interfaces:**
- Consumes: `Tabs`, `ViewMode`, `TabContent` (Task 3); `AssetLoad`, `load` (Task 2); `LoadedArchive.reader` (Task 1); `panels::detail::{human_size, compression_ratio}` (Info view).
- Produces: the new `Message` variants (see shared summary); `App.tabs: Tabs`.

**Design notes:**
- Add `pub tabs: crate::state::tabs::Tabs` to `App` (default `Tabs::default()`).
- `Message::OpenAsset(path)`: `let i = app.tabs.open_or_activate(&path);` then dispatch the async load using the retained reader — `let reader = app.archive.as_ref().unwrap().reader.clone();` (guard `if let Some(archive)`), `Task::perform(crate::task::asset::load(reader, path.clone()), move |load| Message::AssetLoaded { path, load: Box::new(load) })`.
- `Message::AssetLoaded { path, load }`: `app.tabs.set_content(&path, TabContent::Ready { bytes: load.bytes, parsed: load.parsed });` (no-op if the tab was closed meanwhile — `set_content` handles it).
- `Message::TabActivated(i)`→`activate`; `TabClosed(i)`→`close`; `ViewModeSet(v)`→`set_view(active, v)`.
- `PropToggled(id)`: toggle membership in the active tab's `expanded` set. `HexBytePressed/Entered/DragEnded/Copy*`: mutate the active tab's `hex: HexState` and, for copy, return `iced::clipboard::write(crate::state::hex_view::copy_hex(bytes, sel))` (similarly `copy_ascii`). Guard all on `app.tabs.active` + a `Ready` tab.
- **Archive lifecycle:** in the existing `Message::ArchiveOpened(Ok(loaded))` arm and the `Locked` arm, call `app.tabs.clear()` so tabs never reference a stale reader. (Add to the `Ok` arm right after resetting `selected_row`.)
- **Enter-to-open:** in `handle_tree_key`'s `Named::Enter` file branch, instead of only `archive.tree.select(i)`, also return an `OpenAsset` task for the file path. Since `handle_tree_key` returns `Option<Task<Message>>`, build `Some(Task::done(Message::OpenAsset(path)))` for the file case (keep `select` for highlight). Use `iced::Task::done` (verify the exact constructor in iced 0.14 — it is `Task::done(message)`).
- **Double-click-open (mouse):** in `file_tree.rs::build_row`, wrap the file-row content in `iced::widget::mouse_area(...).on_press(Message::RowSelected(i)).on_double_click(Message::OpenAsset(path))`. Keep dir rows as the existing `button` (toggle on press). Preserve the selection highlight: put the existing styled `container`/row inside the `mouse_area`. Note the hover-tint tradeoff for the UI/UX reviewer (mouse_area has no built-in hover; add a subtle `container` hover style if needed).
- **view wiring:** replace the `PaneKind::Detail => detail::view(selected_meta)` arm with `PaneKind::Detail => content::view(&archive.tabs?, ...)` — actually tabs live on `App`, not the archive. Because the `pane_grid` closure cannot borrow `app`, capture `let tabs = &app.tabs;` alongside the existing `tree`/`accent` locals and use `content::view(tabs, accent)` in the `Detail` arm.
- **content host** (`panels/content.rs`): if `tabs.open.is_empty()` → reuse a muted empty state ("Open a file to inspect it"); else render the tab bar (Task 8 will move it to a widget — here, a simple inline row of buttons is fine as a placeholder), the `Properties|Hex|Info` segmented switcher (three `button`s; active one styled via `accent_button`), and the active tab body: `TabContent::Loading` → "Loading…" (muted); `Ready` → match `tab.view`: `Info` → render via the **real** Info view (below); `Properties`/`Hex` → text placeholder `"(properties view — Task 10)"` / `"(hex view — Task 9)"`.
- **Info view** (real, in `content.rs`): show `Path`, `Size`, `Compressed`, `Encrypted` rows exactly like `detail::view` (reuse `human_size`/`compression_ratio` and the `kv_row` style — extract `kv_row` to `pub(crate)` in `detail.rs` if convenient, or replicate), plus, when `parsed` is `Ok(pkg)`, summary rows: `Exports` = `pkg.exports.exports.len()`, `Names` = `pkg.names.names.len()`, `Engine` from `pkg.summary` (mirror the `summary` line in `cli/.../tree.rs::render`). When `parsed` is `Err(reason)`, show a muted `Properties unavailable: {reason}` note in the Info view too. Look up the tab's `EntryMeta` from `archive.entries` — pass it into `content::view` (extend the signature to take `&BTreeMap<String, EntryMeta>`).

- [ ] **Step 1: Write failing tests** (update/state-level, no rendering) in `app.rs` tests:

```rust
    #[tokio::test]
    async fn open_asset_creates_loading_tab_then_ready() {
        // Build an App with the uasset fixture opened.
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent().unwrap().parent().unwrap()
            .join("tests/fixtures/real_v8b_uasset.pak");
        let loaded = crate::task::open::run(fixture, None).await.unwrap();
        let mut app = App { archive: Some(loaded), ..App::default() };

        let _ = update(&mut app, Message::OpenAsset("Game/Maps/Demo.uasset".into()));
        assert_eq!(app.tabs.open.len(), 1);
        assert!(matches!(app.tabs.open[0].content, crate::state::tabs::TabContent::Loading));

        // Simulate the async result.
        let reader = app.archive.as_ref().unwrap().reader.clone();
        let load = crate::task::asset::load(reader, "Game/Maps/Demo.uasset".into()).await;
        let _ = update(&mut app, Message::AssetLoaded { path: "Game/Maps/Demo.uasset".into(), load: Box::new(load) });
        assert!(matches!(app.tabs.open[0].content, crate::state::tabs::TabContent::Ready { .. }));
    }

    #[test]
    fn view_mode_set_changes_active_tab_view() {
        let mut app = app_with_paths(&["a.uasset"]);
        let _ = update(&mut app, Message::OpenAsset("a.uasset".into())); // tab 0 active (load will error async; fine)
        let _ = update(&mut app, Message::ViewModeSet(crate::state::tabs::ViewMode::Hex));
        assert_eq!(app.tabs.open[0].view, crate::state::tabs::ViewMode::Hex);
    }

    #[tokio::test]
    async fn opening_new_archive_clears_tabs() {
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent().unwrap().parent().unwrap()
            .join("tests/fixtures/real_v8b_uasset.pak");
        let loaded = crate::task::open::run(fixture.clone(), None).await.unwrap();
        let mut app = App { archive: Some(loaded), ..App::default() };
        let _ = update(&mut app, Message::OpenAsset("Game/Maps/Demo.uasset".into()));
        assert_eq!(app.tabs.open.len(), 1);
        // Re-open (same fixture) → tabs cleared.
        let reloaded = crate::task::open::run(fixture, None).await.unwrap();
        let _ = update(&mut app, Message::ArchiveOpened(Box::new(Ok(reloaded))));
        assert!(app.tabs.open.is_empty(), "opening an archive must clear stale tabs");
    }

    #[test]
    fn tab_closed_out_of_bounds_is_noop() {
        let mut app = app_with_paths(&["a.uasset"]);
        let _ = update(&mut app, Message::OpenAsset("a.uasset".into()));
        let _ = update(&mut app, Message::TabClosed(99));
        assert_eq!(app.tabs.open.len(), 1);
    }
```

- [ ] **Step 2: Run, verify fail** (Message variants / `tabs` field undefined).
- [ ] **Step 3: Implement** the App field, Message variants, update arms, `file_tree` `mouse_area` change, `panels/content.rs`, and the view wiring per the design notes. Keep the `#[mutants::skip]` discipline on `view`, `content::view`, and `build_row`.
- [ ] **Step 4: Run** `cargo test -p paksmith-gui` → PASS.
- [ ] **Step 5: Gates** — fmt + clippy + `cargo test -p paksmith-gui`.
- [ ] **Step 6: Commit** — `git commit -am "feat(gui): wire tabbed content host, open-asset flow, Info view"`

---

### Task 8: `widgets/tab_bar.rs` — polished tab strip

**Files:**
- Create: `crates/paksmith-gui/src/widgets/tab_bar.rs`
- Modify: `crates/paksmith-gui/src/widgets/mod.rs` (`pub mod tab_bar;`)
- Modify: `crates/paksmith-gui/src/panels/content.rs` (use `tab_bar::view` instead of the inline placeholder strip)

**Interfaces:**
- Consumes: `Tabs` (Task 3); `accent_button`/`readable_text_on` (app.rs); `tokens`.
- Produces: `fn view(tabs: &Tabs, accent: Color) -> Element<'_, Message>`; pure `fn tab_label(path: &str) -> &str` (basename — last `/`-segment).

- [ ] **Step 1: Write failing tests** — pure `tab_label`:

```rust
    #[test]
    fn tab_label_is_basename() {
        assert_eq!(tab_label("Game/Maps/Demo.uasset"), "Demo.uasset");
        assert_eq!(tab_label("top.uasset"), "top.uasset");
        assert_eq!(tab_label(""), "");
    }
```

- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** `tab_label` (pure) + `view` (`#[mutants::skip]`): a horizontal `scrollable` row of per-tab elements. Each tab = a `mouse_area` (`on_press`=`Message::TabActivated(i)`, `on_middle_press`=`Message::TabClosed(i)`) wrapping a styled `row![ text(tab_label(&t.path)), close_button ]`; the close `button` (a small "×") emits `Message::TabClosed(i)`. The active tab gets the accent underline/background (reuse the selection styling pattern from `file_tree::build_row`); inactive tabs are muted. Use `tokens` spacing. Tab text uses the full theme `palette().text` (not muted) so labels are legible.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Gates.**
- [ ] **Step 6: Commit** — `git commit -am "feat(gui): add polished tab-bar widget (activate, middle/×-close, overflow scroll)"`

---

### Task 9: `widgets/hex_view.rs` — virtualized hex dump + selection + copy

**Files:**
- Create: `crates/paksmith-gui/src/widgets/hex_view.rs`
- Modify: `crates/paksmith-gui/src/widgets/mod.rs` (`pub mod hex_view;`)
- Modify: `crates/paksmith-gui/src/panels/content.rs` (Hex body → `hex_view::view`)
- Modify: `crates/paksmith-gui/src/app.rs` (`subscription`: add a left-button-release listener → `Message::HexDragEnded`, only while a Ready hex tab is active)

**Interfaces:**
- Consumes: `state::hex_view::{total_rows, row_bytes, BYTES_PER_ROW, Selection, HexState}` (Task 4).
- Produces: `fn view(bytes: &[u8], hex: &HexState) -> Element<'_, Message>`; pure `fn offset_label(row: usize) -> String` (`"{:08X}"` of `row*16`); pure `fn byte_cell_text(b: u8) -> String` (`"{:02X}"`); pure `fn ascii_cell_char(b: u8) -> char`.

- [ ] **Step 1: Write failing tests** for the pure helpers:

```rust
    #[test]
    fn offset_label_is_8_digit_hex_of_row_start() {
        assert_eq!(offset_label(0), "00000000");
        assert_eq!(offset_label(1), "00000010"); // row 1 → byte 16
        assert_eq!(offset_label(16), "00000100");
    }
    #[test]
    fn ascii_cell_char_dots_nonprintable() {
        assert_eq!(ascii_cell_char(b'A'), 'A');
        assert_eq!(ascii_cell_char(0x00), '.');
        assert_eq!(ascii_cell_char(0x7f), '.');
    }
    #[test]
    fn byte_cell_text_is_two_digit_upper() {
        assert_eq!(byte_cell_text(0x0a), "0A");
        assert_eq!(byte_cell_text(0xff), "FF");
    }
```

- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** the pure helpers + `view` (`#[mutants::skip]`). Virtualize to `total_rows(bytes.len())` rows inside a `scrollable`+`column`; each row = `row![ offset_gutter, hex_cells, ascii_cells ]`. Each byte cell (hex and ascii) is a `mouse_area` (`on_press`=`Message::HexBytePressed(byte_idx)`, `on_enter`=`Message::HexByteEntered(byte_idx)`) wrapping a monospaced `text`; cells whose `byte_idx` is in `hex.selection` (use `Selection::contains`) get an accent-tint background. Use a fixed-width font sizing so columns align (set `text.font(iced::Font::MONOSPACE)`). Add a small "Copy hex"/"Copy ASCII" button pair above the grid emitting `HexCopyRequested`/`HexCopyAsciiRequested` (disabled when no selection). Provide the same virtualization caveat comment as `file_tree.rs`.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Gates.**
- [ ] **Step 6: Commit** — `git commit -am "feat(gui): add virtualized hex-view widget with drag-selection + copy"`

---

### Task 10: `widgets/property_tree.rs` — virtualized property inspector

**Files:**
- Create: `crates/paksmith-gui/src/widgets/property_tree.rs`
- Modify: `crates/paksmith-gui/src/widgets/mod.rs` (`pub mod property_tree;`)
- Modify: `crates/paksmith-gui/src/panels/content.rs` (Properties body → `property_tree::view`)

**Interfaces:**
- Consumes: `state::property_view::{flatten, PropRow, PropKind, NodeId, as_color}` (Tasks 5/6); the active tab's `expanded` set + parsed `Package`.
- Produces: `fn view<'a>(pkg: &'a Package, expanded: &HashSet<NodeId>, accent: Color) -> Element<'a, Message>`; pure `fn row_indent(depth: usize) -> f32` (reuse `tokens::TREE_INDENT` — or call `file_tree::row_indent`).

- [ ] **Step 1: Write failing test** — pure indent reuse (if a new helper) or a thin test that `flatten` is wired (skip if reusing `file_tree::row_indent`, which is already tested). At minimum add a `#[test]` asserting the module compiles a row for a known `PropRow` is not feasible without rendering; instead test any new pure helper this widget introduces. If it introduces none (reusing `file_tree::row_indent`), this task's tests are covered by Tasks 5/6 — note that explicitly and skip Step 1's new test.
- [ ] **Step 2: (n/a if no new pure helper).**
- [ ] **Step 3: Implement** `view` (`#[mutants::skip]`): `let rows = flatten(pkg, expanded);` render as a `scrollable`+`column`. Each row: indent spacer (`row_indent(depth)`), then for Branch rows a chevron (`▸`/`▾` from `row.expanded`) wrapped in a `button`/`mouse_area` emitting `Message::PropToggled(row.node_id)`; the label `text`; for Leaf rows the `value` text in muted color. When `as_color(..)` would apply (the model exposes a color row — surface this via `PropRow` carrying an optional `[f32;4]`, OR have the widget re-derive it; prefer adding `pub color: Option<[f32;4]>` to `PropRow` in Task 6 to keep the widget pure-data-driven), render a small fixed-size `container` swatch (accent-independent, the literal color) before the value text. Use `palette().text` for labels, `TEXT_MUTED_ALPHA` for values. Same virtualization caveat comment.
   - **Note for Task 6 coordination:** add `pub color: Option<[f32; 4]>` to `PropRow` and populate it in `flatten` via `as_color(&prop.value)` so this widget stays data-driven (no core types leaking into the render decision). Adjust Task 5's `PropRow` definition accordingly and re-run Task 5/6 tests.
- [ ] **Step 4: Run** `cargo test -p paksmith-gui` → PASS.
- [ ] **Step 5: Gates.**
- [ ] **Step 6: Commit** — `git commit -am "feat(gui): add virtualized property-tree widget (type-aware rows + swatches)"`

---

### Task 11: Polish, retire dead detail view, docs, final mutants sweep

**Files:**
- Modify: `crates/paksmith-gui/src/panels/detail.rs` (remove the now-unused `view`/`empty_detail`/`entry_detail` if fully replaced by the Info view; keep `human_size`/`compression_ratio`/`kv_row` as the shared helpers Info uses). If removing `view` orphans nothing else, delete it; otherwise leave a doc note.
- Modify: `docs/plans/ROADMAP.md` (mark Phase 7a complete; add a one-paragraph status note: tabbed content + Property/Hex/Info viewers shipped; TextureViewer→7b, AudioPlayer+chrome→7c).
- Modify: `.cargo/mutants.toml` (add any Phase 7a env-IO/equivalent `exclude_re` residue discovered by the in-diff run — only equivalents).

- [ ] **Step 1:** Run `cargo clippy --workspace --all-targets --all-features -- -D warnings` and remove any dead-code warnings (the retired `detail::view`). Confirm `cargo fmt --all --check` clean.
- [ ] **Step 2:** Run the full mutants gate on the diff: `cargo mutants --in-diff <merge-base>..HEAD --all-features -p paksmith-gui`. For each missed mutant: if it's in a pure helper, add a killing test; if it's a struct-field-genus mutant in a `#[mutants::skip]`'d view fn, confirm the skip covers it; if it's an env-IO/equivalent, add a justified `exclude_re`. Iterate to **0 missed**.
- [ ] **Step 3:** `RUSTDOCFLAGS="-D warnings" cargo doc -p paksmith-gui --no-deps` → clean.
- [ ] **Step 4:** Update `docs/plans/ROADMAP.md` Phase 7a status.
- [ ] **Step 5:** Full local gate chain: `cargo fmt --all --check && cargo clippy --workspace --all-targets --all-features -- -D warnings && cargo test -p paksmith-gui`.
- [ ] **Step 6: Commit** — `git commit -am "chore(gui): retire dead detail view, mark Phase 7a complete, mutants 0-missed"`

---

## Self-Review

**Spec coverage:** Tabs (T3,T7,T8) ✓; content host replacing detail pane (T7) ✓; `Properties|Hex|Info` switcher (T7) ✓; PropertyInspector type-aware tree (T5,T6,T10) ✓; HexView selection+copy (T4,T9) ✓; Info view absorbing metadata + summary (T7) ✓; `Arc<PakReader>` retention (T1) ✓; async load (T2) ✓; double-click + Enter open (T7) ✓; middle-click/× tab close (T8) ✓; parse-failure graceful + non-uasset Hex-only (T2,T7) ✓; tab invalidation on archive change (T7) ✓; no core changes / no new deps / mutants / UI-UX reviewer (Global Constraints + T11) ✓. Deferred (texture/audio/toasts/context-menu/debug-console/.usmap) correctly absent.

**Placeholder scan:** Task 10 Step 1 legitimately notes "no new pure helper → covered by Tasks 5/6" — this is a reasoned test-coverage statement, not a TODO. Task 7 and the view tasks carry full design notes + real code for the load-bearing logic; view assembly mirrors the referenced Phase 6 files (the `#[mutants::skip]` cosmetic surface), consistent with how Phase 6 was planned. No "TBD"/"implement later".

**Type consistency:** `ViewMode`/`TabContent`/`Tab`/`Tabs` defined in T3, extended (added fields `hex`, `expanded`, and `PropRow.color`) in T4/T5/T6/T10 with explicit cross-references. `AssetLoad`/`load` (T2) consumed verbatim in T7. `Selection`/`HexState` (T4) consumed in T9. `flatten`/`PropRow`/`NodeId`/`as_color` (T5/T6) consumed in T10. `Message` variant names listed once in the shared summary and used identically in T7–T10.
