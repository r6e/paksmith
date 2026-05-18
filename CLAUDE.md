# Paksmith

Cross-platform Rust rewrite of FModel for exploring and extracting Unreal Engine game assets.

## Build

- `cargo build` — build default-members (core, cli, gui)
- `cargo test` — run default-members tests (paksmith-core unit + cli + gui). Skips the `paksmith-core-tests` integration suite and the `__test_utils`-gated in-source tests in `paksmith-core`.
- `cargo test --workspace --all-features` — run the full suite (matches CI). Includes the heavyweight `paksmith-core-tests` integration suite and paksmith-core's `__test_utils`-gated in-source tests, both excluded from default-members.
- `cargo run -p paksmith-cli -- <args>` — run the CLI
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` — lint (mirrors CI; the workspace-default invocation misses the `__test_utils` surface and integration tests, see MEMORY)
- `cargo fmt --all` — format
- `cargo run -p paksmith-fixture-gen` — regenerate test fixtures (excluded from `default-members` because it depends on a git-sourced parser oracle)

## Architecture

Cargo workspace with five crates:

- `paksmith-core` — library: container I/O, asset parsing (planned), format handlers (planned), game profiles (planned)
- `paksmith-cli` — binary: command-line interface (`paksmith`)
- `paksmith-gui` — binary: Iced-based GUI (Phase 6 stub)
- `paksmith-fixture-gen` — internal dev tool: generates synthetic pak fixtures, cross-validates against `trumank/repak`. Excluded from `default-members`.
- `paksmith-core-tests` — heavyweight integration tests for paksmith-core that require the `__test_utils` feature. Excluded from `default-members` so routine `cargo build` skips the test compile; CI uses `cargo test --workspace`.

Core is the load-bearing crate. CLI and GUI are thin presentation-layer frontends that depend exclusively on core and never share code directly.

## Conventions

- TDD: write failing test first, then implement
- `thiserror` for error types, `tracing` for structured logging
- No panics in core — all fallible operations return `Result<T, PaksmithError>`
- `byteorder` for binary parsing (little-endian unless explicitly noted)
- Conventional commits: `feat:`, `fix:`, `chore:`, `test:`, `docs:`
- One logical change per commit
- Each cap constant exposes a `#[cfg(feature = "__test_utils")]` accessor so boundary tests read the live value. See `max_uncompressed_entry_bytes`, `max_index_bytes`, `max_fdi_bytes`, `max_flat_index_entries`.

## Module Layout (core)

- `container/` — archive format readers. Each implements `ContainerReader` trait.
  - `container/pak/` — UE pak v3-v11 reader (current, Phase 1)
  - `container/iostore/` — IoStore container reader (planned, Phase 8)
- `asset/` — UAsset deserialization. Phase 2a ships the structural header parser (`PackageSummary`, `NameTable`, `ImportTable`, `ExportTable`, `Package`, `AssetContext`); property bodies carried as `PropertyBag::Opaque` pending Phase 2b tagged-property iteration.
- `export/` — format handlers implementing `FormatHandler` trait (planned, Phase 3+)
- `profile/` — game profile management and registry (planned, Phase 5)
- `error.rs` — `PaksmithError` + typed fault sub-enums with wire-stable `Display` impls
- `digest.rs` — `Sha1Digest` (byte-equality, NOT constant-time)
- `testing/` — `__test_utils`-feature-gated test infrastructure (`v10` fixtures, `oom` injection seams)
