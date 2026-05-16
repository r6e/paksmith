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

**Phase 2a — UAsset structural header.** Parses `.uasset` headers
(`PackageSummary`, name/import/export tables) and exposes a working
`paksmith inspect` CLI that dumps the parsed header as JSON. Property
bodies are carried as opaque byte payloads in this phase; tagged-property
iteration lands in Phase 2b.

Later phases (full property decoding, export handlers, game profile registry,
IoStore container, Iced GUI) are not yet started. See
[`docs/plans/ROADMAP.md`](docs/plans/ROADMAP.md) for the phased plan.

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

### `paksmith inspect`

Dump a uasset's structural header (summary, name table, import/export
tables) as JSON. Property bodies are carried as opaque byte counts
in this phase; full property decoding lands in Phase 2b.

```sh
cargo run -p paksmith-cli -- inspect path/to/archive.pak Game/Maps/Demo.uasset
```

### macOS first-run note

The `aarch64-apple-darwin` binaries shipped to GitHub Releases are ad-hoc codesigned but **not Apple-notarized**. On first run, macOS Gatekeeper blocks with *"`paksmith` cannot be opened because the developer cannot be verified."* It's one-time per binary.

Verify the binary against the SHA256SUMS file published with the release before clearing the quarantine attribute:

```sh
shasum -a 256 -c SHA256SUMS-aarch64-apple-darwin.txt
xattr -d com.apple.quarantine /path/to/paksmith
```

Or via Finder: right-click the binary → **Open** → confirm in the dialog.

Background: notarization is permanently off the roadmap ([#168](https://github.com/r6e/paksmith/issues/168)).

## Testing

```sh
cargo test                                                 # routine
cargo clippy --workspace --all-targets --all-features -- -D warnings   # lint (mirrors CI)
cargo fmt --all -- --check                                 # format check
```

## License

MIT
