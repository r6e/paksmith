# Paksmith Implementation Roadmap

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Full-featured cross-platform Unreal Engine asset explorer and extractor, achieving FModel parity incrementally.

**Architecture:** Cargo workspace — `paksmith-core` (library), `paksmith-cli` (binary), `paksmith-gui` (binary), `paksmith-fixture-gen` (internal dev tool, not in `default-members`). Core does all heavy lifting; frontends are thin presentation layers.

**Tech Stack:** Rust 1.85+, Iced (GUI, planned), wgpu (rendering, planned), clap (CLI), thiserror, tracing, serde, byteorder, sha1, flate2. Async runtime (tokio or otherwise) deferred until Phase 5 introduces network fetch — no async deps in Phase 1.

---

## Phase Overview

| Phase | Name                     | Status                       | Depends On | Deliverable                                      |
| ----- | ------------------------ | ---------------------------- | ---------- | ------------------------------------------------ |
| 1     | Foundation & Pak Reading | ✓ complete                   | —          | `paksmith list` reads .pak files                 |
| 2     | UAsset Parsing           | ✓ complete                   | 1          | Property system, asset deserialization           |
| 3     | Export Pipeline          | planned                      | 2          | Texture/mesh/audio export to standard formats    |
| 4     | Full CLI                 | planned                      | 2, 3       | extract, inspect, search commands                |
| 5     | Game Profiles            | planned                      | 1          | Registry fetch, AES key management, profile CRUD |
| 6     | GUI Shell                | planned                      | 1, 5       | Iced app with file tree, archive browsing        |
| 7     | GUI Asset Viewers        | planned                      | 2, 3, 6    | Texture viewer, property inspector, hex view     |
| 8     | IoStore Support          | planned                      | 1          | .utoc/.ucas container reading                    |
| 9     | 3D Viewport              | planned                      | 3, 7       | wgpu mesh/skeleton renderer                      |

---

## Phase 1: Foundation & Pak Reading ✓

**Status:** Complete — see `phase-1-foundation.md` (frozen historical spec; implementation has diverged).

**Scope:** Workspace scaffolding, PaksmithError, PakVersion, footer/index parsing, ContainerReader trait, PakReader, `paksmith list` command, CI.

---

## Phase 2: UAsset Parsing ✓

**Status:** Complete across seven shipped sub-phases. Each plan doc
under `docs/plans/phase-2{a..g}-*.md` is the frozen historical spec
for its sub-phase; the implementation has diverged from a few of
those projections (e.g. companion stitching lives inside `package.rs`
rather than a dedicated `companion.rs`).

- **2a** — UAsset header parsing: summary, name/import/export tables,
  custom versions, engine version. (`phase-2a-uasset-header.md`)
- **2b** — Tagged-property iteration over primitives: Bool, Int
  variants, Float, Double, Str, Name; container types skipped via
  `tag.size` and landed as `PropertyValue::Unknown` until 2c.
  (`phase-2b-tagged-properties.md`)
- **2c** — Container properties: `Array`/`Set` of primitives, `Map`
  with primitive key + value, `Struct` of primitives.
  (`phase-2c-container-properties.md`)
- **2d** — Extended property types: `SoftObjectProperty` /
  `SoftClassProperty`, `ObjectProperty` resolution, `ByteProperty` /
  `EnumProperty` (incl. inside containers), `TextProperty`.
  (`phase-2d-extended-property-types.md`)
- **2e** — Companion files: `.uexp` stitching at parse time,
  `Package::read_from_pak` pak-aware companion detection,
  `MissingCompanionFile` typed fault. `.ubulk` access is detected
  but deferred to Phase 3. (`phase-2e-companion-files.md`)
- **2f** — Unversioned properties: `.usmap` schema parser, schema-
  driven decode, `--mappings` CLI flag. (`phase-2f-unversioned-properties.md`)
- **2g** — Collection-of-struct: `Array<Struct>` per-element catch,
  `Map<Struct, *>` / `Map<*, Struct>` and `Set<Struct>` collection-
  level bail. (`phase-2g-collection-of-struct.md`)

Two known deferrals remain on the Phase 3+ list, both scoped at
Phase 2 time and intentionally not blocking Phase 2 closure:
`.ubulk` byte access (Phase 3, when format handlers need it) and
typed binary struct decoders (Phase 3+, to replace Phase 2g's
empty-struct fallback for `FVector`/`FRotator`/etc.).

**Goal:** Deserialize .uasset/.uexp files into the structured `Asset` data model. This is the largest and most complex phase — UE's serialization format is deeply nested, version-dependent, and poorly documented.

**Key deliverables:**

- UAsset header parser (magic, versions, name table, import/export tables)
- UE property system (FProperty deserialization — bools, ints, floats, strings, arrays, maps, structs, soft/hard object references)
- PropertyBag: the generic fallback representation for any asset
- Asset enum with initial variants: `Generic(PropertyBag)` as the universal fallback
- AssetContext: carries name table, import table, engine version — needed by property deserializers

**Architecture:**

Phase 2a shipped a flat `asset/` module — one file per logical
header sub-record. Phase 2b–2g layer the property system on top
without disturbing this skeleton.

```plaintext
paksmith-core/src/asset/          (Phase 2a — shipped)
├── mod.rs                         # Asset enum, AssetContext, public re-exports
├── package.rs                     # Package + read_from / read_from_pak orchestration
├── summary.rs                     # FPackageFileSummary parser + bounds
├── name_table.rs                  # FName pool (CityHash16 pair, Arc<str> interning)
├── import_table.rs                # FObjectImport records
├── export_table.rs                # FObjectExport records
├── package_index.rs               # Typed i32 import/export reference (Null/Import/Export)
├── custom_version.rs              # FCustomVersion container
├── engine_version.rs              # FEngineVersion record
├── guid.rs                        # FGuid (16-byte UUID)
├── version.rs                     # AssetVersion bundle + VER_UE4_*/VER_UE5_* constants
├── property_bag.rs                # PropertyBag::Opaque (carries raw payload bytes)
├── fstring.rs                     # FString reader (UTF-8 / UTF-16LE)
└── wire.rs                        # Shared wire helpers (read_bool32, write_bool32)
```

```plaintext
paksmith-core/src/asset/          (Phase 2b–2g — shipped; layout
                                   diverged from the original
                                   projection — see each
                                   phase-2{b..g}-*.md plan doc for
                                   the as-shipped contract)
├── property/
│   ├── mod.rs                    # read_properties orchestration (2b)
│   ├── tag.rs                    # FPropertyTag header + read_tag (2b)
│   ├── primitives.rs             # Primitive-type read_primitive_value (2b/2d)
│   ├── containers.rs             # Array/Map/Set/Struct + Phase 2g
│   │                             #   collection-of-struct catches (2c/2d/2g)
│   ├── text.rs                   # FText + history variants (2d)
│   ├── unversioned.rs            # FUnversionedHeader + schema decode (2f)
│   ├── bag.rs                    # PropertyBag::Tree / ::Opaque (2b)
│   └── test_utils.rs             # __test_utils-gated shared test scaffolding
└── mappings.rs                   # .usmap parser (2f)
                                  # `.uexp` stitching lives inline in
                                  #  `package.rs::read_from`. `.ubulk`
                                  #  detection in `read_from_pak`;
                                  #  bytes deferred to Phase 3.
```

**Key design decisions:**

- Properties are the core abstraction. Every UE asset is ultimately a tree of typed properties. Getting this right unlocks everything downstream.
- The property parser is recursive (structs contain properties which contain structs). Use an explicit stack or bounded recursion with a depth limit.
- Engine version affects property layout (field ordering, optional fields). AssetContext carries this so parsers can branch.
- Unknown property types don't panic — they skip by reading the serialized size and storing raw bytes in a `PropertyBag::Unknown` variant.

**Testing approach:**

- Unit tests per property type with hand-crafted binary payloads
- A fixture generator that builds synthetic .uasset files with known property trees
- Round-trip tests: deserialize → inspect → verify against expected structure
- Property-based tests for primitive encoding/decoding

**Risks:**

- UE's serialization has many undocumented edge cases (versioned structs, tagged vs untagged properties, class-specific custom serialization)
- FModel's C# source and UE's C++ source are the only reliable references
- Some asset types use custom serialization that bypasses the property system entirely

**Dependencies:** Phase 1 (PakReader provides raw bytes to feed into the asset parser)

---

## Phase 3: Export Pipeline

**Goal:** Convert parsed assets into standard interchange formats. This is where the `FormatHandler` trait gets its first real implementations beyond the generic fallback.

**Key deliverables:**

- `.ubulk` companion file stitching: chunk-offset arithmetic to locate bulk data relative to the export. Phase 2e will detect `.ubulk` sibling entries during `Package::read_from_pak` and emit a warning; Phase 3 will add full byte access so texture/mesh handlers can read mip and LOD data.
- TextureAsset type (dimensions, pixel format, mip chain, raw data)
- Texture export: DDS/BC1-BC7/ASTC → PNG/TGA
- MeshAsset type (vertices, indices, UVs, normals, LODs, material slots)
- Static mesh export → glTF 2.0
- SoundAsset type (codec, sample rate, channels, raw audio)
- Audio export: WEM → OGG (via ww2ogg approach), raw PCM → WAV
- DataTableAsset → CSV/JSON
- FormatHandler registry: given an asset, find the right handler

**Architecture:**

```plaintext
paksmith-core/src/
├── export/
│   ├── mod.rs              # FormatHandler trait, HandlerRegistry
│   ├── texture.rs          # TextureAsset, DDS/BC decode, PNG export
│   ├── mesh.rs             # MeshAsset, glTF writer
│   ├── audio.rs            # SoundAsset, WEM/OGG/WAV export
│   └── data_table.rs       # DataTableAsset, CSV/JSON export
```

**Key design decisions:**

- `.ubulk` stitching: Phase 2e will detect the sibling entry in `read_from_pak` and emit a warning. Phase 3 will extend it to read the bytes and supply them to format handlers via a new `bulk_data: Option<&[u8]>` parameter on `FormatHandler::export`. Chunk-offset arithmetic (serial offset relative to the combined `.uasset`+`.uexp`+`.ubulk` logical stream) will be handled in `Package::read_from_pak` before the handler is invoked.
- Each handler is stateless — receives asset data and optional bulk data, produces output bytes. No shared mutable state.
- Texture decoding uses block compression algorithms (BC1-BC7). Consider wrapping an existing C library (e.g., `texture2ddecoder`) via FFI, or find a pure-Rust implementation. Pure Rust preferred but not at the cost of correctness.
- glTF export via the `gltf` crate's builder API. One mesh per file initially; scene-level export later.
- Audio: WEM (Wwise) is essentially OGG Vorbis with a custom header. The conversion is well-documented.
- The HandlerRegistry dispatches based on asset class name from the export table. Handlers register themselves at startup.

**Testing approach:**

- Golden file tests: export known assets, compare output byte-for-byte against reference files
- For textures: generate a known pixel pattern, encode as BC7, decode, verify pixel accuracy within tolerance
- For glTF: validate output against the glTF validator
- For audio: verify WAV header correctness, sample count matches expected

**Dependencies:** Phase 2 (parsed assets feed into export handlers)

---

## Phase 4: Full CLI

**Goal:** Complete the CLI command surface — extract, inspect, search — making paksmith a fully scriptable tool for batch operations.

**Key deliverables:**

- `paksmith extract` — bulk export with format selection, output directory structure, progress bars, dry-run
- `paksmith inspect` — dump asset properties as JSON (the full property tree)
- `paksmith search` — query entries by type, name pattern, size range, regex
- `--game` flag integration (once Phase 5 lands; stub until then)
- Exit code discipline (0/1/2), stable JSON schemas, piping-friendly behavior
- Progress reporting via indicatif on stderr

**Architecture:**

```plaintext
paksmith-cli/src/commands/
├── mod.rs
├── list.rs         # (exists from Phase 1)
├── extract.rs      # Bulk extraction with format negotiation
├── inspect.rs      # Property tree dump
└── search.rs       # Entry queries
```

**Key design decisions:**

- `extract` walks entries, finds the appropriate FormatHandler, exports to the chosen format. Falls back to raw bytes if no handler matches.
- Output directory mirrors the archive's internal path structure by default. `--flat` option strips directories.
- `inspect` serializes the PropertyBag/Asset to JSON using serde. Custom serialization for types that don't map naturally to JSON (vectors → `[x, y, z]`, colors → `"#RRGGBB"`).
- `search` supports combining predicates: `--type Texture2D --name "hero*" --min-size 1MB`
- All commands work with both .pak and IoStore (once Phase 8 lands) via the ContainerReader trait — command implementations never reference a specific container type.

**Testing approach:**

- Snapshot tests (insta) for each command's JSON output
- Integration tests via assert_cmd for flag combinations, error cases, exit codes
- Extraction tests: extract to a temp dir, verify file contents match

**Dependencies:** Phase 2 (inspect needs property deserialization), Phase 3 (extract needs export handlers)

---

## Phase 5: Game Profiles

**Goal:** Automatic game detection, AES key management, and community registry integration. This is a UX multiplier — users select a game and everything just works.

**Key deliverables:**

- GameProfile struct and serialization (TOML on disk)
- Profile resolution: user overrides → local cache → remote registry
- Registry client: async fetch from a community endpoint, cache to disk
- AES key management: per-game key storage, key testing (try decrypt, verify)
- Auto-detection: given a directory, identify which game it belongs to via known paths/signatures
- CLI: `paksmith profile list|fetch|add|remove`
- Offline mode: works entirely from cache when network unavailable

**Architecture:**

```plaintext
paksmith-core/src/
├── profile/
│   ├── mod.rs              # GameProfile, ProfileManager
│   ├── registry.rs         # Remote registry client (reqwest)
│   ├── cache.rs            # Local cache read/write (XDG dirs)
│   ├── detection.rs        # Auto-detect game from directory
│   └── encryption.rs       # AES key validation and storage
```

**Key design decisions:**

- Profiles stored as TOML in platform-appropriate config dirs (`dirs` crate for XDG/AppData/Library paths)
- Registry endpoint is configurable (default to a community URL, overridable for private registries)
- The registry response format is a JSON array of profile objects. Fetched atomically, cached as a single file with a timestamp. Staleness check on startup (re-fetch if > 24h old, configurable).
- AES keys stored hex-encoded. Key testing: decrypt a known block from the pak, check for valid structure.
- Auto-detection uses a set of heuristics: known subdirectory patterns, binary signatures in executables, .ini file contents.

**Testing approach:**

- Unit tests for profile serialization round-trips
- Registry client tests with a mock HTTP server (wiremock or similar)
- Detection tests with synthetic directory structures
- Offline fallback tests: remove network, verify cache serves correctly

**Dependencies:** Phase 1 (PakReader needs keys for encrypted paks; profile system provides them)

---

## Phase 6: GUI Shell

**Goal:** A working Iced application with the panel layout, file tree widget, and basic archive browsing. This is the GUI foundation — no asset rendering yet, just navigation.

**Key deliverables:**

- Iced application scaffolding (App struct, Message enum, update/view cycle)
- Panel layout: menu bar, resizable sidebar, main content area, status bar
- FileTree custom widget: virtualized, lazy-expanding, keyboard navigable
- Archive opening: File → Open dialog, loads via PakReader, populates tree
- Game profile selector in toolbar (dropdown, uses ProfileManager)
- Status bar: loaded file name, entry count, memory usage
- Basic theming (dark mode default, consistent with modern tool aesthetics)

**Architecture:**

```plaintext
paksmith-gui/src/
├── main.rs                 # Entry point, App::run()
├── app.rs                  # App struct, Message, update(), view()
├── theme.rs                # Color palette, spacing, typography
├── widgets/
│   ├── mod.rs
│   ├── file_tree.rs        # Virtualized tree widget
│   └── status_bar.rs       # Status bar widget
├── panels/
│   ├── mod.rs
│   ├── sidebar.rs          # File tree panel with resize handle
│   └── toolbar.rs          # Menu bar and game profile selector
└── state/
    ├── mod.rs
    ├── archive.rs           # Loaded archive state
    └── tree.rs              # File tree node model
```

**Key design decisions:**

- The FileTree widget is the hardest piece. Virtualization is non-negotiable — games have 100k+ files. Only visible rows are rendered; scroll position drives which slice of the tree is materialized.
- Tree nodes are lazily expanded: clicking a directory doesn't load children until needed. This keeps memory flat.
- The Iced Elm architecture means all state changes go through Message → update(). No interior mutability, no shared mutable state. Heavy work (opening archives) dispatches via `Command::perform` to a background thread.
- Resizable panels: track split position as a percentage, handle drag events on the divider.

**Testing approach:**

- State logic tests: send messages, assert state changes (no rendering)
- Tree model tests: expand/collapse/filter operations on the node structure
- Visual testing deferred to Phase 7 when there's more to look at

**Dependencies:** Phase 1 (PakReader for loading), Phase 5 (ProfileManager for game selection)

---

## Phase 7: GUI Asset Viewers

**Goal:** Rich asset preview within the GUI — textures, property trees, hex dumps, all within a tabbed interface.

**Key deliverables:**

- TabBar widget: multiple open assets, closeable tabs, tab overflow
- TextureViewer widget: wgpu texture display, zoom/pan, channel isolation (R/G/B/A), mip level selector
- PropertyInspector widget: expandable tree for UE property bags, type-aware rendering (colors as swatches, vectors formatted, enums resolved)
- HexView widget: virtualized hex dump with offset gutters, ASCII column, selection, copy
- Context menu on file tree: "Open", "Export As...", "Copy Path"
- Toast notifications for errors (non-blocking)
- Debug console panel (toggleable, shows tracing ring buffer)

**Architecture:**

```plaintext
paksmith-gui/src/
├── widgets/
│   ├── tab_bar.rs          # Tab container widget
│   ├── texture_viewer.rs   # wgpu texture display
│   ├── property_tree.rs    # Property inspector tree
│   ├── hex_view.rs         # Hex dump viewer
│   └── toast.rs            # Toast notification overlay
├── panels/
│   ├── content.rs          # Main content area (tab host)
│   └── debug_console.rs    # Tracing log viewer
```

**Key design decisions:**

- TextureViewer is a custom Iced widget that owns a wgpu texture. On asset load, decode the texture data (via Phase 3's texture decoder) and upload to GPU. Render as a textured quad with zoom/pan transform.
- Channel isolation: render with a shader that masks channels. Mip selection: upload specific mip level.
- PropertyInspector reuses the virtualized tree approach from FileTree but with richer row rendering (icons per type, inline color swatches, formatted numbers).
- HexView is another virtualized list — only renders visible rows. Selection state tracks byte ranges for copy.
- Tab state: each tab holds an `Asset` variant and the viewer state for that asset type. Tab switching is instant (data stays in memory).

**Testing approach:**

- State logic tests for each viewer's interaction model (zoom levels, selection ranges, tree expand/collapse)
- PropertyInspector rendering tests with known PropertyBag inputs → expected display strings
- HexView tests: selection math, scroll offset calculations, copy formatting

**Dependencies:** Phase 2 (property data), Phase 3 (texture decoding), Phase 6 (GUI shell and tab infrastructure)

---

## Phase 8: IoStore Support

**Goal:** Read UE5's IoStore container format (.utoc/.ucas) — the modern replacement for .pak files used by most current-gen games.

**Key deliverables:**

- IoStoreReader implementing ContainerReader trait
- .utoc parser (table of contents: chunk IDs, offsets, sizes, compression)
- .ucas reader (content addressable storage: reads chunks by ID)
- Compression support: Zlib, LZ4, Oodle (Oodle via system library or bundled)
- Partition support (IoStore splits across multiple .ucas files)
- Seamless integration: CLI and GUI work with IoStore exactly as they do with .pak (trait polymorphism)

**Architecture:**

```plaintext
paksmith-core/src/container/
├── mod.rs                  # ContainerReader trait (exists)
├── pak/                    # (exists)
└── iostore/
    ├── mod.rs              # IoStoreReader public API
    ├── toc.rs              # .utoc format parser
    ├── cas.rs              # .ucas chunk reader
    ├── compression.rs      # Decompression dispatch (zlib, lz4, oodle)
    └── partition.rs        # Multi-file partition handling
```

**Key design decisions:**

- IoStore is chunk-based, not file-based. The .utoc maps logical paths → chunk IDs → physical offsets in .ucas files. The ContainerReader trait's `list_entries`/`read_entry` interface maps cleanly: entries are logical paths, reading an entry resolves through the chunk table.
- Oodle decompression is the main challenge. Oodle is proprietary (RAD Game Tools). Options: (a) load the system's oodle DLL/dylib at runtime if present, (b) require users to provide it, (c) pure-Rust reimplementation (legally risky). FModel uses option (a). We should too.
- Compression is per-chunk. A single entry may span multiple compressed chunks that must be decompressed and concatenated.
- Partitions: large games split .ucas into multiple numbered files. The .utoc references partition indices.

**Testing approach:**

- Synthetic .utoc/.ucas fixture generator (similar to Phase 1's pak fixture)
- Integration tests: open IoStore → list entries → read entry → verify content
- Compression round-trip tests for zlib and lz4 (oodle tested only when library available)

**Dependencies:** Phase 1 (ContainerReader trait, error types, container module structure)

---

## Phase 9: 3D Viewport (Future)

**Goal:** Render static meshes, skeletal meshes, and animations in a wgpu-based viewport embedded as a custom Iced widget.

**Key deliverables:**

- wgpu render pipeline: vertex/fragment shaders, depth buffer, MSAA
- PBR material system: albedo, normal, metallic/roughness maps
- Static mesh rendering: load MeshAsset → GPU buffers → draw
- Skeletal mesh: bone hierarchy, skinning weights, bind pose display
- Animation playback: bone track interpolation, timeline scrubber
- Orbit camera: mouse drag rotation, scroll zoom, pan
- Grid floor and axis gizmo for orientation

**Architecture:**

```plaintext
paksmith-gui/src/
├── viewport/
│   ├── mod.rs              # Viewport widget (Iced Widget impl)
│   ├── renderer.rs         # wgpu pipeline setup, draw calls
│   ├── camera.rs           # Orbit camera controller
│   ├── mesh.rs             # MeshAsset → GPU buffer upload
│   ├── skeleton.rs         # Bone hierarchy rendering
│   ├── material.rs         # PBR material binding
│   ├── animation.rs        # Playback controller
│   └── shaders/
│       ├── mesh.wgsl       # PBR vertex/fragment shader
│       └── grid.wgsl       # Grid overlay shader
```

**Key design decisions:**

- The viewport is a custom Iced widget that requests a wgpu surface. Iced already uses wgpu internally — the widget hooks into the same device/queue.
- Rendering is decoupled from asset loading. The viewport receives a "scene" (meshes + materials + skeleton) and renders it. Loading/preparing the scene happens in core.
- PBR shading: metallic-roughness workflow, matching UE's material model closely enough for visual accuracy. Not a game engine — doesn't need to be real-time at 60fps for complex scenes, just responsive for inspection.
- Skeletal animation: CPU-side bone transform computation, upload bone matrices as a uniform buffer per frame.

**Dependencies:** Phase 3 (MeshAsset, TextureAsset for materials), Phase 7 (GUI widget infrastructure)

**Note:** This phase is the lowest priority and highest complexity. The tool is fully useful without it — export to glTF and preview in Blender/other tools covers the use case adequately in the interim.

---

## Phase Ordering & Parallelism

```plaintext
Phase 1 ─┬─ Phase 2 ─── Phase 3 ─┬─ Phase 4
          │                        │
          ├─ Phase 5 ──────────────┼─ Phase 6 ─── Phase 7 ─── Phase 9
          │                        │
          └─ Phase 8 ──────────────┘
```

- Phases 2, 5, and 8 can be worked in parallel after Phase 1
- Phase 3 requires Phase 2
- Phase 4 requires Phases 2 and 3
- Phase 6 requires Phases 1 and 5
- Phase 7 requires Phases 2, 3, and 6
- Phase 9 requires Phases 3 and 7

---

## Milestone Targets

| Milestone | Phases Complete | What Users Can Do                                     |
| --------- | --------------- | ----------------------------------------------------- |
| **Alpha** | 1, 2, 3, 4, 5   | Full CLI extraction and inspection with game profiles |
| **Beta**  | + 6, 7, 8       | GUI browsing with asset preview, IoStore support      |
| **1.0**   | + 9             | 3D viewport, full FModel feature parity               |

---

## Cross-Cutting Concerns (All Phases)

**Performance:**

- Memory-map large files where possible (memmap2 crate)
- Lazy parsing: don't deserialize assets until requested
- Parallelize bulk operations (rayon for extraction, tokio for network)

**Error resilience:**

- One bad asset never takes down the whole operation
- Bulk operations log failures and continue (report summary at end)
- GUI shows per-asset errors inline, never crashes

**Logging:**

- tracing spans around every expensive operation from Phase 1 onward
- Performance profiling via tracing-flame when needed

**Documentation:**

- Each public type and trait gets doc comments as written
- ARCHITECTURE.md after Phase 1 establishes module boundaries
- CONTRIBUTING.md after Phase 4 when external contributors might arrive
