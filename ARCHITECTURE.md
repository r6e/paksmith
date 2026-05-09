# Architecture

Paksmith is a Cargo workspace with three crates, following a core-library + thin-frontends pattern.

## Crate Dependency Graph

```
paksmith-cli ──┐
               ├──▶ paksmith-core
paksmith-gui ──┘
```

CLI and GUI depend exclusively on core. They never share code directly.

## paksmith-core

The load-bearing library. All format knowledge, parsing logic, and data models live here.

### Modules

- `container/` — Archive format readers. Each format (`.pak`, IoStore) implements a shared `ContainerReader` trait. Handles decompression and decryption internally.
- `asset/` (planned) — UAsset deserialization. Parses the UE property system into a renderer-agnostic `Asset` data model.
- `export/` (planned) — Format handlers implementing `FormatHandler` trait. Converts parsed assets to standard interchange formats (PNG, glTF, WAV).
- `profile/` (planned) — Game profile management. Remote registry fetch, local cache, AES key storage.
- `error.rs` — `PaksmithError` enum. No panics in this crate; every fallible op returns `Result`.

### Key Traits

- `ContainerReader` — uniform interface for listing and reading archive entries regardless of container format.
- `FormatHandler` (planned) — plugin boundary. Decides if it can handle an asset, deserializes it, and exports to standard formats.

## paksmith-cli

Thin binary crate. Dispatches subcommands to core library functions and formats output (JSON or table). No format knowledge — only presentation logic.

## paksmith-gui

Iced-based GUI using the Elm architecture (state + messages + update/view cycle). Custom widgets for file trees, texture viewing, property inspection. Heavy work dispatched to background tasks; the UI thread never blocks.

## Design Principles

- **Core owns all logic** — frontends are presentation-only.
- **Trait boundaries for extensibility** — new container formats or asset handlers plug in without touching existing code.
- **No panics in library code** — errors are values, propagated via `Result`.
- **Renderer-agnostic data model** — asset types carry domain data (vertices, pixels, properties), not GPU resources.
- **Lazy by default** — archives are indexed on open, but assets are only deserialized when accessed.
