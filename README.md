# Paksmith

[![CI](https://github.com/r6e/paksmith/actions/workflows/ci.yml/badge.svg)](https://github.com/r6e/paksmith/actions/workflows/ci.yml)
[![Security Audit](https://github.com/r6e/paksmith/actions/workflows/audit.yml/badge.svg)](https://github.com/r6e/paksmith/actions/workflows/audit.yml)
[![cargo-deny](https://github.com/r6e/paksmith/actions/workflows/deny.yml/badge.svg)](https://github.com/r6e/paksmith/actions/workflows/deny.yml)
[![CodeQL](https://github.com/r6e/paksmith/actions/workflows/codeql.yml/badge.svg)](https://github.com/r6e/paksmith/actions/workflows/codeql.yml)
[![Clippy SARIF](https://github.com/r6e/paksmith/actions/workflows/clippy-sarif.yml/badge.svg)](https://github.com/r6e/paksmith/actions/workflows/clippy-sarif.yml)

A cross-platform tool for exploring and extracting Unreal Engine game assets. Written in Rust.

## Status

**Phase 1 — pak container reader.** Parses UE pak archives v3 through v11 with
opt-in SHA-1 verification (entry payloads + main-index, FDI, and PHI regions on
v10+). Supports zlib decompression. Ships a working `paksmith list` CLI.

Phase 2 (UAsset deserialization, property system, export handlers) and later
phases (game profile registry, IoStore container, Iced GUI) are not yet started.
See [`docs/plans/ROADMAP.md`](docs/plans/ROADMAP.md) for the phased plan.

## Building

```sh
cargo build      # builds the default workspace members (core, cli, gui)
cargo test       # runs all tests
```

The fixture-generation crate (`paksmith-fixture-gen`) is intentionally excluded
from `default-members` because it depends on a git-sourced parser used as a
cross-validation oracle. To regenerate test fixtures explicitly:

```sh
cargo run -p paksmith-fixture-gen
```

## Running

List the entries in a pak archive:

```sh
cargo run -p paksmith-cli -- list path/to/archive.pak
```

`paksmith list` auto-detects whether stdout is a terminal — emits a human-readable
table interactively, JSON when piped or redirected. Override with `--format
table` or `--format json`.

## Testing

```sh
cargo test                                                 # routine
cargo clippy --workspace --all-targets --all-features -- -D warnings   # lint (mirrors CI)
cargo fmt --all -- --check                                 # format check
```

## License

MIT
