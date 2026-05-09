# Paksmith

Cross-platform Rust rewrite of FModel for exploring and extracting Unreal Engine game assets.

## Build

- `cargo build` — build all crates
- `cargo test` — run all tests
- `cargo run -p paksmith-cli -- <args>` — run the CLI
- `cargo clippy --workspace -- -D warnings` — lint
- `cargo fmt --all` — format

## Architecture

Cargo workspace with three crates:

- `paksmith-core` — library: container I/O, asset parsing, format handlers, game profiles
- `paksmith-cli` — binary: command-line interface (`paksmith`)
- `paksmith-gui` — binary: Iced-based GUI

Core is the load-bearing crate. CLI and GUI are thin presentation-layer frontends that depend exclusively on core and never share code directly.

## Conventions

- TDD: write failing test first, then implement
- `thiserror` for error types, `tracing` for structured logging
- No panics in core — all fallible operations return `Result<T, PaksmithError>`
- `byteorder` for binary parsing (little-endian unless explicitly noted)
- Conventional commits: `feat:`, `fix:`, `chore:`, `test:`, `docs:`
- One logical change per commit

## Module Layout (core)

- `container/` — archive format readers (pak, iostore). Each implements `ContainerReader` trait.
- `asset/` — UAsset deserialization, property system (planned)
- `export/` — format handlers implementing `FormatHandler` trait (planned)
- `profile/` — game profile management and registry (planned)
