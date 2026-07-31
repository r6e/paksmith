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

Record the archive locations on the profile once:

```sh
cargo run -p paksmith-cli -- profile add hero --name Hero --pak-path '/games/hero/Paks/*.pak'
```

Then the path argument can be omitted — every matching archive is listed, with
per-entry `source` provenance:

```sh
cargo run -p paksmith-cli -- --game hero list
```

`paksmith list` auto-detects whether stdout is a terminal — emits a human-readable
table (with color; set `NO_COLOR` to disable) interactively, JSON when piped or
redirected. Override with `--format table` or `--format json`. `--quiet` silences
advisory notes and drops logging to error-level (errors still print). The JSON shape is
a versioned envelope shared with `search`:

```json
{ "schema_version": 1, "entries": [ { "path": "...", "size": 123, "...": "..." } ] }
```

### `paksmith profile`

Every `profile` subcommand honours `--format`, resolving `auto` the same way
`list` does — table on a terminal, JSON when piped or redirected. **Piping
`profile list` therefore yields JSON, not the tab-separated table.** Pass
`--format table` to keep the human shape in a script.

One change reaches the human output too: when a registry document repeats a
profile id, `list` and `detect` now report it once rather than once per
occurrence, in both formats. The first occurrence wins, matching which profile
`--game` and `show` already resolved. The GUI's profile selector dedupes with
them, and any `--detect` resolution — the global flag on any command, the
`profile detect` subcommand, or the GUI selector's loader — logs one warning
per genuinely repeated id; `list` collapses silently, so absent that warning
the signal is the `fetch.profile_count` comparison described below.

Each read surface carries its own `schema_version` — no two return the same
document — and the four mutations share one, because they share one shape:

| command | shape |
|---|---|
| `list` | `{schema_version, profiles: [{id, name, engine_version, key_count, source}]}` |
| `show` | `{schema_version, id, source, name, engine_version, mappings, pak_paths, keys}` |
| `detect` | `{schema_version, dir, matches: [{id, name, source}]}` |
| `test` | `{schema_version, id, outcome, ok}` |
| `fetch` | `{schema_version, fetched, profile_count}` |
| `add`, `remove`, `key add`, `key remove` | `{schema_version, action, id, guid?}` |

`source` is `local` or `registry`. `test.outcome` is a stable token —
`verified`, `decrypted`, `wrong_key` or `unsupported` — deliberately not the
table's prose, which reads "decrypted (no index hash to verify)"; branch on
`ok`, and treat an unrecognised `outcome` as informational.
`fetch.fetched` is false when a fresh cache short-circuited the network, so a
script can tell "already current" from "downloaded". `fetch.profile_count` is
how many profiles the registry document carries — deliberately not spelled
`profiles`, which on `list` is an array. To detect collapsed entries, compare
it with the number of `source: "registry"` rows `list` returns — not `list`'s
total, which counts local rows too; any gap is entries collapsed by shadowing
or repetition, and the counts alone cannot say which. The mutations return an
`action` of `added`, `removed`, `key_added` or `key_removed`; the two `key`
subcommands also report the `guid` slot they acted on, which `add` and `remove`
omit because they have none. It is normalised to lowercase hex rather than
echoed, so compare case-insensitively against a `--guid` you passed.

`show` renders key material only under `--show-keys`; when redacted the `key`
field is **omitted entirely** rather than set to a placeholder, so the presence
of the field is itself the signal.

Exit codes: **2** is a real error — `paksmith: error: …` on stderr, stdout
empty, no document in either format. There is no JSON error envelope. **1** is
not an error but `profile test` reporting a key that did not open the archive
(`outcome` `wrong_key` or `unsupported`); the document is still written, so
branch on `ok` rather than treating non-zero as failure. A stdout that closes
before the document is written masks the 1 as **0** — BrokenPipe takes
precedence. Note this is not what `| head -1` does here: the `test` document is
small enough to fit the pipe buffer, so the write succeeds and the 1 stands.
Reaching the masked case takes a reader that closes before the write; `| true`
usually does, but that is a race rather than a guarantee, so do not rely on
either shell recipe — rely on `ok`.

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
