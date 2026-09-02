# Paksmith — Design Spec

> **Status: frozen historical spec.** This document captures the original Phase 1 design intent. The implementation diverged in several places — read the code, not this spec, for the current shape:
>
> - **`ContainerReader` API:** the trait now uses `entries() -> Box<dyn Iterator<Item = EntryMetadata>>`, `read_entry_to(path, writer) -> Result<u64>` (streaming primitive), and `read_entry(path) -> Result<Vec<u8>>` (collected wrapper). The pre-Phase-1 sketch's `list_entries() -> Vec` shape has been retired.
> - **`PaksmithError` variants:** the live error set in `crates/paksmith-core/src/error.rs` includes additional variants not enumerated here — `HashMismatch { target, expected, actual }`, `IntegrityStripped { target }`, `EntryNotFound { path }`, plus structured `InvalidIndex { fault: IndexParseFault }` / `InvalidFooter { fault: InvalidFooterFault }` sub-enums (issues #28, #48, #64, #76, #77).
> - **Test-utils surface:** the `__test_utils` cargo feature exposes `paksmith_core::testing` for cross-crate fixture sharing; not described here.
> - **Exit codes (amended, issue #653):** the "0 success, 1 user error, 2 runtime error" scheme in the Design Principles below never shipped. The implemented contract — pinned by the CLI integration suite and codified in `docs/plans/ROADMAP.md` §Phase 4 (4a) — is: **0** success, including BrokenPipe on stdout (`paksmith list … | head` exits 0); **2** for every other error, user and runtime alike, printed as `paksmith: error: …` on stderr (`crates/paksmith-cli/src/main.rs` maps every non-BrokenPipe `PaksmithError` to this single path); **1** for completed-with-negative-outcome — `extract` ran but one or more entries failed (`ExtractSummary::had_failures`; per-entry detail in the JSON summary), and `profile test` ran but the key could not be confirmed — wrong key OR an untestable layout (`KeyTestOutcome` handling in `crates/paksmith-cli/src/commands/profile.rs`; a key that decrypts without an index hash to check exits 0). BrokenPipe takes precedence over the partial-failure code, on BOTH of its surfaces: a consumer that stops reading `extract`'s stdout masks exit 1 as 0 (and truncates the summary with it), and since issue #658 item 2 the same holds for `profile test`, whose wrong-key 1 is masked as 0 by a closed stdout — when gating on integrity, consume the full stream and check the summary's `counts.failed` or the test document's `ok`.
> - **`GameProfile.engine_version` (consumed, issue #656):** the sketch's typed `EngineVersion` field ships as `Option<String>` on the wire — a strict serde type would turn one hand-edited value into a whole-store `CorruptStore`, and the ed25519-signed registry schema (which has always carried `engine_version`) can never change shape. It is parsed leniently at RESOLUTION into `asset::UeVersion` (`major.minor[.patch]`) and reaches the parser as `AssetContext::engine_version_hint` via `ReadOptions`. Distinct from `asset::EngineVersion`, the wire `FEngineVersion` read from a package summary. The hint only REFINES gates the package's own object versions leave ambiguous (UE 5.2 vs 5.3 `bSerializeMipData`); it never raises the UE 4.13+ asset floor, and an unhinted parse is byte-identical to pre-#656.
> - **`GameProfile.pak_paths` (shipped, issue #655):** the Game Profile System sketch's `pak_paths: Vec<PathBuf>` shipped as `pak_paths: Vec<String>` — glob patterns, stored as opaque strings in the local profile store only. Core does no matching; the CLI expands them (absolute patterns stand alone, relative patterns resolve against the `--detect` install dir). The field is deliberately NOT on `RegistryProfile` — the registry document is `deny_unknown_fields` + ed25519-signed (same schema-version story as `mappings`), registry-supplied patterns would feed untrusted input into a backtracking glob matcher, and install layouts are per-user. **Recorded exception (issue #658 item 3):** `DetectRules.byte_signatures` DID take that registry hazard, deliberately and once, while `DEFAULT_REGISTRY_URL` is still a `.invalid` placeholder — see `detection::DetectRules` for the deadline that window closes on and `docs/plans/ROADMAP.md` for the argument. The container commands' `<path>` positional is accordingly now optional (`inspect` takes the asset as its single positional in that form).
> - **GUI archive-level failures (amended, issue #663):** the Error Handling paragraph below prescribes a *modal* for archive-level failures. None ships. The case that would need one is an open that fails while another archive is already loaded — and there a modal is the wrong shape, since it would block the loaded archive to report a failure that usually concerns a different file (nothing forces that: re-picking the currently-open path lands in the same arm). What ships is three surfaces, all in `crates/paksmith-gui`: a full-content-area key prompt when the archive is locked (`state::keyflow`), a full-content-area error banner with a retry CTA when no archive is loaded (`App::error`), and, when one IS loaded, an error toast that stays until the user dismisses it — by its `x` or by a spare Escape — one with no row menu, About panel or key prompt open (two widget-tree caveats the app cannot see: an open `pick_list` dropdown does not claim the press, and a focused text input captures it, costing one extra press) (`state::toast::Lifetime::UntilDismissed`, pushed from the `OpenError::Core` arm of `Message::ArchiveOpened`; a failure for a *different* file landing while the key prompt is up gets the same card — over the prompt, whose state is untouched — instead of misattributing itself to the prompt's file, so the toast can also appear with no archive loaded). At most one is live at a time: a newer one replaces it, and a later COMPLETED open attempt on the file it names supersedes it — success or reaching the key prompt — while an attempt on a different file leaves it standing (the card carries its subject path and retirement matches on it, so a slow earlier open's success cannot clear a newer file's card; a slow earlier open's *failure* still claims the single slot, replacing it). Nothing retires it on a timer. This also widens the paragraph's FIRST sentence, which scopes toasts to *recoverable* errors: the toast is now also the archive-level surface, in a persistent form that the transient one (export failures, audio-device loss) does not use. None of the three blocks input — the toolbar stays interactive behind all of them and the status bar (text only) stays visible, and since #663 the toast overlay is scoped to the body, so it no longer covers the status bar or the debug console. The remaining two sentences are accurate and unamended: per-tab inline error states still serve bad assets (`panels::content`), and the app still does not crash on one.
>
> Do not write new code against the snippets in this document — they reflect pre-implementation shapes. Use the current modules under `crates/paksmith-core/src/{error,container/pak,digest,testing}.rs`.

A cross-platform (Windows, Linux, macOS) Rust rewrite of FModel for exploring and extracting Unreal Engine game assets. Full feature parity with FModel is the long-term goal, delivered incrementally.

## Architecture

Cargo workspace with three crates:

```plaintext
paksmith/
├── crates/
│   ├── paksmith-core/    # Library: format parsing, extraction, plugin traits
│   ├── paksmith-cli/     # Binary: rich command set, JSON output, pipeline-friendly
│   └── paksmith-gui/     # Binary: Iced-based GUI with custom widgets
├── registry/             # Local fallback game profile data (bundled)
├── docs/
└── Cargo.toml            # Workspace root
```

**Core** is the load-bearing crate. CLI and GUI depend on it exclusively and never share code directly. The core exposes:

- Container I/O (pak, IoStore)
- Asset deserialization (uasset, uexp, ubulk)
- Format handlers behind a `FormatHandler` trait (the future plugin boundary)
- Game profile system (registry fetch, local cache, user overrides)
- Renderer-agnostic asset data model

CLI and GUI are thin presentation-layer frontends with no format knowledge.

## Core Library

### Container Layer

```rust
pub trait ContainerReader: Send + Sync {
    fn list_entries(&self) -> Vec<EntryMetadata>;
    fn read_entry(&self, path: &str) -> Result<Vec<u8>>;
    fn supports_format(&self) -> ContainerFormat;
}
```

Implementations: `PakReader` (.pak v1–v11), `IoStoreReader` (.utoc/.ucas). Each handles decompression (zlib, oodle, lz4) and decryption (AES-256) internally. The trait boundary means adding a new container format doesn't touch existing code.

### Format Handler Trait

```rust
pub trait FormatHandler: Send + Sync {
    fn can_handle(&self, asset: &AssetHeader) -> bool;
    fn deserialize(&self, data: &[u8], context: &AssetContext) -> Result<Asset>;
    fn export_formats(&self) -> &[ExportFormat];
    fn export(&self, asset: &Asset, format: ExportFormat, writer: &mut dyn Write) -> Result<()>;
}
```

This is the future plugin boundary. Built-in handlers cover: textures (DDS/BC7/ASTC → PNG), meshes (→ glTF), audio (WEM → OGG/WAV), localization tables, data tables, and a fallback property-viewer for unrecognized types.

### Asset Data Model

Renderer-agnostic domain types consumed by both frontends:

```rust
pub enum Asset {
    Texture(TextureAsset),
    StaticMesh(MeshAsset),
    SkeletalMesh(SkeletalAsset),
    Animation(AnimationAsset),
    Sound(SoundAsset),
    DataTable(DataTableAsset),
    Generic(PropertyBag),
}
```

The 3D viewport (added later) reads `MeshAsset`/`SkeletalAsset` directly — no re-parsing.

### Game Profile System

```rust
pub struct GameProfile {
    pub name: String,
    pub engine_version: EngineVersion,
    pub encryption_keys: Vec<AesKey>,
    pub pak_paths: Vec<PathBuf>,
    pub mappings: Option<MappingsSource>,
}
```

Resolution priority: user overrides → local cache → remote registry fetch. Async client (reqwest), cached to disk. Fully functional offline from cache.

## CLI

### Commands

```shell
paksmith list <path>          # List archive contents (JSON or table)
paksmith extract <path>       # Extract assets to disk
paksmith inspect <path>       # Dump asset properties (table on TTY, JSON when piped)
paksmith search <path>        # Query by type/name/path/regex
paksmith profile list         # Show available game profiles
paksmith profile fetch        # Update profiles from remote registry
paksmith profile add          # Add user-defined profile
```

### Common Flags

```shell
--game <name>         # Use a game profile (keys, version, mappings)
--key <hex>           # Manual AES key
--format json|table   # Output format (default: table for TTY, json for pipes)
--output <dir>        # Extraction target directory
--filter <glob>       # Path filter
--mappings <file>     # Explicit .usmap file
--verbose / --quiet   # Logging verbosity
--dry-run             # Preview without writing
```

### Design Principles

- Exit codes: 0 success, 1 user error, 2 runtime error.
- JSON output is stable and structured for piping to `jq` or CI scripts.
- Table output uses column alignment and color when TTY-attached, plain when piped.
- Progress on stderr; stdout stays clean for piping.
- Dependencies: `clap` (derive), `serde_json`. Async/progress-bar
  deps (`tokio`, `indicatif`) were scoped out of Phase 1 and will
  be added when an actual async-I/O or long-running workload lands
  (Phase 4 extract command, Phase 5 registry fetch).

## GUI

### Layout

```plaintext
┌─────────────────────────────────────────────────────────┐
│  Menu Bar (File, View, Tools, Help)                     │
├────────────────┬────────────────────────────────────────┤
│                │  Tab Bar (open assets)                  │
│  File Tree     ├────────────────────────────────────────┤
│  (archive      │                                        │
│   contents)    │  Asset Viewer                           │
│                │  (texture preview, property inspector,  │
│                │   hex view, future: 3D viewport)        │
│                │                                        │
├────────────────┼────────────────────────────────────────┤
│  Search / Filter panel                                  │
├─────────────────────────────────────────────────────────┤
│  Status Bar (loaded archive, entry count, memory)       │
└─────────────────────────────────────────────────────────┘
```

### Custom Widgets (Iced `Widget` trait)

- **FileTree** — virtualized (100k+ entries), lazy expansion, keyboard nav, context menus.
- **TextureViewer** — wgpu-backed, zoom/pan, channel isolation, mip level selection.
- **PropertyInspector** — tree view for UE property bags, type-aware display.
- **HexView** — virtualized hex dump with offset gutters, ASCII sidebar, selection.
- **TabBar** — tabbed container for multiple open assets.

### State Architecture (Elm)

```rust
struct App {
    profiles: ProfileManager,
    archive: Option<OpenArchive>,
    file_tree: FileTreeState,
    open_tabs: Vec<TabState>,
    active_tab: usize,
    search: SearchState,
    status: StatusInfo,
}

enum Message {
    ProfileSelected(String),
    ArchiveOpened(Result<OpenArchive>),
    TreeNodeExpanded(NodeId),
    AssetSelected(EntryPath),
    AssetLoaded(Result<Asset>),
    TabClosed(usize),
    SearchQueryChanged(String),
    ExportRequested(EntryPath, ExportFormat),
}
```

Heavy work runs on background tasks via `Command::perform`. The UI thread never blocks.

### 3D Viewport (Future)

Architected for but shipped later. Drops in as another custom wgpu widget. The renderer-agnostic asset data model means no core refactoring is needed.

## Plugin System

The `FormatHandler` trait is the plugin boundary. All built-in format handlers implement it. Dynamic loading (Rust FFI, WASM, or both) is deferred until the trait interface stabilizes through real use. The trait boundary is the architectural commitment; the loading mechanism is an implementation detail.

## Error Handling

### Core

```rust
#[derive(Debug, thiserror::Error)]
pub enum PaksmithError {
    #[error("decryption failed{}: invalid or missing AES key", path_for_display(path))]
    Decryption { path: Option<String> },
    #[error("unsupported pak version {version}")]
    UnsupportedVersion { version: u32 },
    #[error("decompression failed: {method} block at offset {offset}")]
    Decompression { method: CompressionMethod, offset: u64 },
    #[error("asset deserialization failed: {reason}")]
    AssetParse { reason: String, asset_path: String },
    #[error("registry fetch failed: {source}")]
    Registry { source: reqwest::Error },
}
```

No panics. Every fallible operation returns `Result<T, PaksmithError>`.

### CLI

Core errors → user-facing messages + exit codes. `--verbose` adds debug context. Structured logging via `tracing` with JSON output available.

### GUI

Non-blocking toast notifications for recoverable errors. Modal for archive-level failures. Per-tab inline error states for bad assets. The app never crashes on a bad asset.

### Logging

- `tracing` throughout (structured, leveled, async-compatible).
- Core emits spans for expensive operations (useful for profiling).
- CLI: `fmt` layer (human) or `json` layer.
- GUI: ring buffer feeding a toggleable debug console panel.

## Testing

### Core

- Unit tests per format parser: known-good binary fixtures, round-trip verification.
- Integration tests: container open → entry read → deserialize → export.
- Property-based tests (`proptest`) for compression/encryption round-trips.
- Fixtures: small synthetic files committed to `tests/fixtures/`. No real game assets (legal). Optional CI-only private corpus.

### CLI

- Snapshot tests (`insta`) on command output against fixture archives.
- Integration tests via `assert_cmd` as subprocess.

### GUI

- State logic tests: construct state → send Message → assert result. No rendering needed.
- Visual/interaction tests deferred until widgets stabilize.

### CI (GitHub Actions)

- Matrix: Linux, macOS, Windows.
- `cargo clippy --deny warnings`
- `cargo fmt --check`
- Coverage target: 80%+ on core crate.

## Non-Goals (for now)

- Dynamic plugin loading (trait boundary exists; mechanism deferred)
- 3D viewport rendering (data model ready; widget deferred)
- TUI/interactive CLI (GUI handles browsing; CLI is non-interactive)
- Bundled game database (registry-fetched + user-provided)
