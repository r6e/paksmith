# Architecture

Paksmith is a Cargo workspace of seven crates, following a core-library + thin-frontends pattern.

## Crate Dependency Graph

```plaintext
paksmith-cli ──┐
               ├──▶ paksmith-core
paksmith-gui ──┘

paksmith-core-tests   ──▶ paksmith-core (heavyweight integration suite, __test_utils)
paksmith-bench        ──▶ paksmith-core (criterion benchmark harness)
paksmith-fixture-gen  ──▶ paksmith-core (+ trumank/repak as a cross-parser oracle)
paksmith-doc-lint     (standalone — validates docs/formats/ structure)
```

CLI and GUI depend exclusively on core. They never share code directly.
`default-members` is `paksmith-core`, `paksmith-cli`, and `paksmith-gui`; the
other four crates are excluded so a routine `cargo build` stays lean:

- `paksmith-fixture-gen` — emits synthetic pak archives for the test suite and
  cross-validates them against `trumank/repak`; excluded so the main library
  stays free of its git-sourced oracle dependency (see `Cargo.toml`).
- `paksmith-core-tests` — the heavyweight integration suite (gated on the
  `__test_utils` feature); excluded so `cargo build` skips the test compile.
- `paksmith-bench` — criterion-based benchmark harness for core hot paths.
- `paksmith-doc-lint` — internal lint tool that validates `docs/formats/`
  structure.

## paksmith-core

The load-bearing library. All format knowledge, parsing logic, and data models live here.

### Modules — current

- `container/` — archive format readers. Each format implements the
  `ContainerReader` trait. Currently ships `pak` only; `iostore` is planned.
  - `container/pak/` — UE pak format reader, versions v3 through v11. Streaming
    `read_entry_to`, opt-in SHA-1 verification (`verify`, `verify_entry`,
    `verify_index`, including FDI/PHI region hashing on v10+), zlib and
    LZ4 decompression. Bounded against decompression bombs and adversarial input
    via fallible reservation (`try_reserve_exact`) and structural caps.
  - `container/pak/index/` — index parsing split per format generation:
    `flat.rs` (v3-v9 sequential index), `path_hash.rs` (v10/v11 FDI + PHI),
    `entry_header.rs` (`PakEntryHeader` with structurally-distinct `Inline`
    and `Encoded` variants), `compression.rs` (`CompressionMethod`),
    `fstring.rs` (UE FString reader with bounded-length rejection).
- `asset/` — UAsset deserialization. The structural header parser
  (`PackageSummary`, `NameTable` with dual CityHash16 trailer,
  `ImportTable`, `ExportTable`, and the `AssetContext` bundle threaded
  through downstream parsers) feeds the `asset/property/` submodule,
  which decodes `FPropertyTag` streams into a typed
  `PropertyBag::Tree { properties: Vec<Property> }`. Property support is
  full: primitives (Bool, Int variants, Float, Double, Str, Name, Enum,
  Text), containers (`containers.rs` — Array/Map/Set/Struct), object
  references, typed engine structs (`asset/structs/` — `FVector`,
  `FRotator`, `FQuat`, `FColor`, `FTransform`, …), and unversioned /
  `.usmap` schema-driven properties (`unversioned.rs`, `mappings.rs`).
  `.uexp` companion bodies are stitched in `Package::read_from_pak`.
  Typed export readers live under `asset/exports/` (texture, mesh,
  audio, data-table), dispatched by class name. Security caps:
  `MAX_TAGS_PER_EXPORT = 65_536`, `MAX_PROPERTY_TAG_SIZE = 16 MiB`,
  `MAX_PROPERTY_DEPTH = 128`; a cursor-mismatch invariant
  (`actual_pos == value_start + tag.size`) fires after every value
  read. Parse errors mid-iteration fall back to `PropertyBag::Opaque`
  with a `tracing::warn!` event so one corrupt export doesn't lose the
  whole package.
- `export/` — `FormatHandler` implementations that turn typed assets
  into standard files: `PngHandler` (textures, with BCn/ASTC/ETC mip
  decode), `GltfStaticMeshHandler` / `GltfSkeletalMeshHandler` (glTF
  2.0), the WAV/OGG audio handlers (`Wav`/`Ogg`/`Vorbis`/`RawSound`),
  and `DataTableCsvHandler` / `DataTableJsonHandler`, selected via a
  `HandlerRegistry`. `FByteBulkData` resolution (`bulk_data.rs`) supplies
  inline / `.uexp` / `.ubulk` / `.uptnl` payloads to the handlers.
- `error.rs` — `PaksmithError` enum + typed sub-enums. Phase 1
  container faults: `DecompressionFault`, `IndexParseFault`,
  `InvalidFooterFault`, `EncodedFault`, `FStringFault`, `OverflowSite`,
  `BoundsUnit`, `BlockBoundsKind`, `OffsetPastFileSizeKind`,
  `HashTarget`. Phase 2a asset faults: `AssetParseFault`,
  `AssetWireField`, `AssetOverflowSite`, `AssetAllocationContext`,
  `CompressionInSummarySite`. All fault-discriminator strings have
  wire-stable `Display` impls pinned by per-variant unit tests so
  operator log greps and downstream regression tests are stable.
- `digest.rs` — `Sha1Digest` newtype with byte-equality semantics; explicitly
  not constant-time (suitable for local file integrity, not network
  attestation).
- `testing/` — `__test_utils`-feature-gated test infrastructure: `v10` (v10+
  fixture builder), `oom` (RAII-guarded thread-local OOM injection seams used
  by integration tests in `tests/oom_pak.rs` and `tests/oom_asset.rs`).

### Modules — planned

- `container/iostore` — IoStore container reader (Phase 8 per ROADMAP).
- `profile/` — game profile management; AES key registry, version routing
  (Phase 5).

### Key Traits

- `ContainerReader` — uniform interface for listing and reading archive entries
  regardless of container format.
- `FormatHandler` — the export plugin boundary (`output_extension`, `supports`,
  `export`). Handlers are registered in a `HandlerRegistry` keyed by asset
  variant; `find_handler` / `find_handler_by_extension` select one for a parsed
  asset.

## paksmith-cli

Thin binary crate. Dispatches subcommands to core library functions and
formats output (table or JSON, auto-selected by stdout terminal-ness). Ships
`paksmith list` and `paksmith inspect` (the parsed structural header plus each
export's decoded property tree and typed export data, as JSON). The library's
export pipeline is not yet CLI-exposed; `extract` and the rest of the command
surface land in Phase 4. No format knowledge — only presentation logic.

## paksmith-gui

Iced-based GUI using the Elm architecture (state + messages + update/view
cycle). Currently a `not yet implemented` stub; full implementation lands in
Phase 6. Custom widgets for file trees, texture viewing, property inspection.
Heavy work dispatched to background tasks; the UI thread never blocks.

## paksmith-fixture-gen

Internal developer tool (not published, excluded from `default-members`).
Generates synthetic pak fixtures for the cross-validation test suite by
constructing archives via paksmith's own writers and parsing them back with
`trumank/repak` to catch generator/parser-shared bugs. Run via
`cargo run -p paksmith-fixture-gen`.

## Design Principles

- **Core owns all logic** — frontends are presentation-only.
- **Trait boundaries for extensibility** — new container formats or asset
  handlers plug in without touching existing code.
- **No panics in library code** — errors are values, propagated via `Result`.
  Untrusted-input arithmetic uses `checked_*`; bulk allocations use
  `try_reserve_exact`; structural caps gate every wire-format size before
  allocation.
- **Renderer-agnostic data model** — asset types carry domain data (vertices,
  pixels, properties), not GPU resources.
- **Lazy by default** — archives are indexed on open, but assets are only
  deserialized when accessed.
- **Wire-stable error Display** — operator log greps and downstream
  regression tests pin against the exact strings in fault `Display` impls.
- **Cross-parser fixtures** — synthetic test archives are validated against
  an external parser (`trumank/repak`) to catch generator/parser-shared
  bugs.
