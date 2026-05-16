# Architecture

Paksmith is a Cargo workspace of five crates, following a core-library + thin-frontends pattern.

## Crate Dependency Graph

```plaintext
paksmith-cli ──┐
               ├──▶ paksmith-core
paksmith-gui ──┘

paksmith-fixture-gen ──▶ paksmith-core (+ trumank/repak as a cross-parser oracle)
```

CLI and GUI depend exclusively on core. They never share code directly.

`paksmith-fixture-gen` is a developer tool (not in workspace `default-members`)
that emits synthetic pak archives for the test suite and cross-validates them
against `trumank/repak`. Excluded from routine builds so the main library stays
free of git-sourced dependencies — see `Cargo.toml` for the rationale.

## paksmith-core

The load-bearing library. All format knowledge, parsing logic, and data models live here.

### Modules — current

- `container/` — archive format readers. Each format implements the
  `ContainerReader` trait. Currently ships `pak` only; `iostore` is planned.
  - `container/pak/` — UE pak format reader, versions v3 through v11. Streaming
    `read_entry_to`, opt-in SHA-1 verification (`verify`, `verify_entry`,
    `verify_index`, including FDI/PHI region hashing on v10+), zlib
    decompression. Bounded against decompression bombs and adversarial input
    via fallible reservation (`try_reserve_exact`) and structural caps.
  - `container/pak/index/` — index parsing split per format generation:
    `flat.rs` (v3-v9 sequential index), `path_hash.rs` (v10/v11 FDI + PHI),
    `entry_header.rs` (`PakEntryHeader` with structurally-distinct `Inline`
    and `Encoded` variants), `compression.rs` (`CompressionMethod`),
    `fstring.rs` (UE FString reader with bounded-length rejection).
- `asset/` — UAsset deserialization. Phase 2a ships the structural
  header parser: `PackageSummary` (FPackageFileSummary equivalent),
  `NameTable` (FName pool with dual CityHash16 trailer), `ImportTable`,
  `ExportTable`, plus the `AssetContext` bundle threaded through
  downstream property parsers. Property bodies are carried as opaque
  byte payloads via `PropertyBag::Opaque`; tagged-property iteration
  lands in Phase 2b.
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
  by integration tests in `tests/oom_pak.rs`).

### Modules — planned

- `container/iostore` — IoStore container reader (Phase 8 per ROADMAP).
- `export/` — `FormatHandler` trait implementations: PNG, glTF, WAV, etc.
  (Phase 3+).
- `profile/` — game profile management; AES key registry, version routing
  (Phase 5).

### Key Traits

- `ContainerReader` — uniform interface for listing and reading archive entries
  regardless of container format.
- `FormatHandler` (planned) — plugin boundary. Decides if it can handle an
  asset, deserializes it, and exports to standard formats.

## paksmith-cli

Thin binary crate. Dispatches subcommands to core library functions and
formats output (table or JSON, auto-selected by stdout terminal-ness). Ships
`paksmith list` (Phase 1) and `paksmith inspect` (Phase 2a — dumps a
parsed UAsset header as JSON); additional subcommands (`extract`,
`verify`) land alongside the corresponding core capabilities. No format
knowledge — only presentation logic.

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
