# Paksmith

[![CI](https://github.com/r6e/paksmith/actions/workflows/ci.yml/badge.svg)](https://github.com/r6e/paksmith/actions/workflows/ci.yml)
[![Security Audit](https://github.com/r6e/paksmith/actions/workflows/audit.yml/badge.svg)](https://github.com/r6e/paksmith/actions/workflows/audit.yml)
[![cargo-deny](https://github.com/r6e/paksmith/actions/workflows/deny.yml/badge.svg)](https://github.com/r6e/paksmith/actions/workflows/deny.yml)
[![CodeQL](https://github.com/r6e/paksmith/actions/workflows/codeql.yml/badge.svg)](https://github.com/r6e/paksmith/actions/workflows/codeql.yml)
[![Clippy SARIF](https://github.com/r6e/paksmith/actions/workflows/clippy-sarif.yml/badge.svg)](https://github.com/r6e/paksmith/actions/workflows/clippy-sarif.yml)

A cross-platform tool for exploring and extracting Unreal Engine game assets. Written in Rust.

## Status

**Core library — Phases 1–3 complete.**

- **Phase 1 — pak container reader.** Parses UE pak archives v3 through
  v11 with opt-in SHA-1 verification (entry payloads + main-index, FDI,
  and PHI regions on v10+) and zlib decompression.
- **Phase 2 — UAsset parsing.** Full `.uasset` deserialization: package
  summary, name/import/export tables, and `FPropertyTag` streams decoded
  into a typed property tree — primitives, containers
  (Array/Map/Set/Struct), object references, and typed engine structs
  (`FVector`, `FTransform`, …). Includes `.uexp` companion stitching and
  unversioned/`.usmap` schema-driven properties.
- **Phase 3 — export pipeline.** Typed export readers plus format
  handlers: textures → PNG (BCn/ASTC/ETC decode, virtual textures),
  static and skeletal meshes → glTF 2.0 (skin weights, multiple LODs),
  audio → WAV/OGG (ADPCM, Vorbis), and data tables → CSV/JSON — with
  `FByteBulkData` resolution across all storage tiers.

**CLI surface — `list` and `inspect`.** The export pipeline above lives
in the `paksmith-core` library; wiring it to an `extract` subcommand is
Phase 4. The remaining phases — game profile registry (5), Iced GUI
(6–7), IoStore container reading (8), and a wgpu 3D viewport (9) — are
not yet started. See [`docs/plans/ROADMAP.md`](docs/plans/ROADMAP.md)
for the phased plan.

## Building

```sh
cargo build      # builds the default workspace members (core, cli, gui)
cargo test       # default-member tests (the integration suite + __test_utils
                 # surface need `cargo test --workspace --all-features`)
```

Four crates are excluded from `default-members` (`paksmith-fixture-gen`,
`paksmith-core-tests`, `paksmith-bench`, `paksmith-doc-lint`) so a routine
`cargo build` stays lean. The fixture-generation crate in particular depends on
a git-sourced parser used as a cross-validation oracle; to regenerate test
fixtures explicitly:

```sh
cargo run -p paksmith-fixture-gen
```

## Installation

Pre-built binaries are published on the [GitHub Releases page](https://github.com/r6e/paksmith/releases). Each release ships per-target archives plus a sibling `SHA256SUMS-<target>.txt` file:

| Platform | Asset | Checksum |
|---|---|---|
| Linux (x86_64) | `paksmith-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz` | `SHA256SUMS-x86_64-unknown-linux-gnu.txt` |
| macOS (Apple Silicon) | `paksmith-vX.Y.Z-aarch64-apple-darwin.tar.gz` | `SHA256SUMS-aarch64-apple-darwin.txt` |
| Windows (x86_64) | `paksmith-vX.Y.Z-x86_64-pc-windows-msvc.zip` | `SHA256SUMS-x86_64-pc-windows-msvc.txt` |

Each archive contains the `paksmith` CLI and the `paksmith-gui` stub (the GUI is a Phase 6 deliverable; today it prints a banner). Extract the archive, then move `paksmith` somewhere on your `PATH`.

Verify the download against the published checksum file before running:

```sh
shasum -a 256 -c SHA256SUMS-<target>.txt
```

### macOS first-run note

The `aarch64-apple-darwin` binaries shipped to GitHub Releases are ad-hoc codesigned but **not Apple-notarized**. On first run, macOS Gatekeeper blocks with *"`paksmith` cannot be opened because the developer cannot be verified."* It's one-time per binary.

After verifying with `shasum` above, clear the quarantine attribute:

```sh
xattr -d com.apple.quarantine /path/to/paksmith
```

Or via Finder: right-click the binary → **Open** → confirm in the dialog.

Background: notarization is permanently off the roadmap ([#168](https://github.com/r6e/paksmith/issues/168)).

## Running

The commands below run paksmith from a source checkout (`cargo run -p paksmith-cli`). If you installed a pre-built binary, substitute `paksmith` for `cargo run -p paksmith-cli --`.

List the entries in a pak archive:

```sh
cargo run -p paksmith-cli -- list path/to/archive.pak
```

`paksmith list` auto-detects whether stdout is a terminal — emits a human-readable
table interactively, JSON when piped or redirected. Override with `--format
table` or `--format json`.

### `paksmith inspect`

Dump a uasset's structural header (summary, name table, import/export
tables) plus each export's decoded property tree as JSON. Properties
decode to typed values — primitives, containers (Array/Map/Set/Struct),
object references, and typed engine structs — and recognized export
classes (textures, meshes, data tables, sound waves) additionally
surface their typed export data.

```sh
cargo run -p paksmith-cli -- inspect path/to/archive.pak Game/Maps/Demo.uasset
```

## Testing

```sh
cargo test                                                 # routine
cargo clippy --workspace --all-targets --all-features -- -D warnings   # lint (mirrors CI)
cargo fmt --all -- --check                                 # format check
```

## License

MIT
