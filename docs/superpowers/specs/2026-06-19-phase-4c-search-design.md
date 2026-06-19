# Phase 4c — `paksmith search` Design

**Status:** approved (brainstorming), pre-implementation
**Date:** 2026-06-19
**Roadmap:** Phase 4 (Full CLI) — `search` sub-phase (4a `extract` #586, 4b `inspect` #587 shipped)

## Context

Phase 4 (Full CLI) = **4a extract → 4b inspect → 4c search**. 4a and 4b shipped.
This document specifies **4c only**, the final Phase 4 sub-phase.

`paksmith search <pak>` is a fast, **index-only** entry query — conceptually
"`list` with composable predicates." It walks the pak's entry index and prints
the matching entries using the same renderer as `list`. It does **not** parse
assets: `--type` matches the entry's file extension, not the UE asset class.
(Asset-class search — `--type Texture2D` — would require parsing every
`.uasset` header and is explicitly out of scope here; a possible future
enhancement.) `paksmith-core` is **not** modified.

## Goals / non-goals

- **Goal:** compose name (glob), full-path (regex), extension, and size
  predicates over the entry index; print matches like `list`.
- **Non-goal:** asset-class/type filtering (no parsing), content search,
  ranking/sorting beyond the index's natural order. No new output schema.

## CLI surface

```
paksmith search <pak>
  [--type <ext>]...     # repeatable; entry extension ∈ set (case-insensitive, no leading dot)
  [--name <glob>]       # glob against the entry BASENAME (filename component)
  [--regex <re>]        # regex against the FULL virtual path (unanchored)
  [--min-size <SIZE>]   # uncompressed_size >= SIZE
  [--max-size <SIZE>]   # uncompressed_size <= SIZE
```

- An entry matches iff it satisfies **every** supplied predicate (logical AND).
  With no predicates, all entries match (same as `list`).
- `--type` is repeatable; within it the semantics are OR (entry matches if its
  extension is any of the given types), e.g. `--type uasset --type umap`.
- `--name` globs the **basename** so `--name 'Hero*'` matches
  `Game/Maps/Hero.uasset`. `--regex` matches the **full virtual path**
  (unanchored, standard `regex::Regex::is_match`) for path-aware queries.
  Both may be supplied together (AND).
- **Sizes** accept human units via an internal `parse_size`: decimal
  `KB`/`MB`/`GB`/`TB` = 10³ⁿ bytes, binary `KiB`/`MiB`/`GiB`/`TiB` = 2¹⁰ⁿ
  bytes, a bare integer = bytes. Case-insensitive suffix; optional space
  (`1MB`, `1 mb`, `512KiB`, `1048576`). Sizes filter on **uncompressed** size.

## Architecture

```
crates/paksmith-cli/src/commands/search.rs   # CREATE: SearchArgs (clap) + run()
crates/paksmith-cli/src/search/mod.rs          # CREATE: Predicates, matches(), parse_size()
crates/paksmith-cli/src/main.rs                # MODIFY: add `mod search;`
crates/paksmith-cli/src/commands/mod.rs        # MODIFY: register Search subcommand
crates/paksmith-cli/Cargo.toml                 # MODIFY: add `regex`
```

`commands::search::run`:
1. `PakReader::open(&args.pak)?`.
2. `Predicates::from_args(args)?` — compiles the glob, compiles the regex,
   parses min/max sizes, and validates `min <= max`. Any failure →
   `PaksmithError::InvalidArgument { arg, reason }` (exit 2).
3. Walk `reader.entries()`, retain entries where `predicates.matches(&entry)`.
4. Render via the existing `crate::output::print_entries(&matches, resolved)`
   (identical table/JSON output to `list`; `--format auto` resolves the same
   way, including `list`'s stderr note when auto→JSON on a non-TTY).

`run` returns `paksmith_core::Result<()>`, wrapped by
`Self::Search(args) => search::run(args, format).map(|()| 0)` in
`commands/mod.rs` (matching `list`/`inspect`).

### `search/mod.rs` units (pure, independently testable)

```rust
pub(crate) struct Predicates {
    types: Vec<String>,          // lowercased extensions; empty = any
    name: Option<glob::Pattern>, // matched against basename
    regex: Option<regex::Regex>, // matched against full path
    min_size: Option<u64>,
    max_size: Option<u64>,
}

impl Predicates {
    /// Compile/parse from args; fallible → InvalidArgument-shaped error.
    pub(crate) fn from_args(args: &SearchArgs) -> Result<Self, (& 'static str, String)>;
    /// Pure predicate over one entry (no I/O).
    pub(crate) fn matches(&self, e: &EntryMetadata) -> bool;
}

/// Parse a human size ("1MB", "512KiB", "2048", "1 gb") → bytes.
pub(crate) fn parse_size(s: &str) -> Result<u64, String>;
```

`from_args` returns `Result<_, (&'static str arg, String reason)>` so `run`
maps it to `PaksmithError::InvalidArgument { arg, reason }` at one site.
`matches` and `parse_size` are pure and get exhaustive unit tests.

**Basename extraction** for `--type`/`--name`: split the entry path on `/`,
take the last component; extension is the substring after its last `.` (only
when that dot is not the first byte of the basename — a leading-dot dotfile has
no extension, mirroring 4a's `classify`). This keeps `--type` consistent with
how `extract` classified entries.

## Error handling / exit codes

- `0` — success, **including zero matches** (an empty result is not an error;
  print nothing in table mode beyond an empty set / `[]` in JSON).
- `2` — usage errors: bad glob, bad regex, unparsable `--min-size`/`--max-size`,
  or `--min-size` > `--max-size`.
- BrokenPipe on stdout exits cleanly via the existing `print_entries` path.

## Dependencies

Adds `regex` (crates.io, MIT/Apache-2.0, widely used + maintained) to
`paksmith-cli`. `glob` is already a dependency. No size-parsing crate — the
internal `parse_size` keeps the new-dependency surface to just `regex`.
`cargo deny` must stay green (regex's transitive deps are permissively
licensed; confirm at implementation).

## Testing

- **Unit (`parse_size`):** bytes, each decimal + binary unit, case/space
  variants, bad suffix, empty, overflow (saturate or error — error), and
  `KB`(1000) ≠ `KiB`(1024).
- **Unit (`matches`):** each predicate in isolation; AND combinations;
  empty predicates = all; `--type` OR-within + case-insensitive; `--name`
  basename semantics (`Hero*` matches a nested path); `--regex` full-path
  unanchored; size boundary (inclusive `>=` / `<=`).
- **Integration (`assert_cmd`):** `--type`, `--name`, `--regex`, size range,
  combined predicates against existing multi-entry fixtures
  (`real_v8b_mixed_paths.pak` / `real_v6_multi.pak` etc.); zero-match → exit 0
  + empty output; bad regex / bad size / min>max → exit 2; JSON output is a
  valid array of entry records matching `list`'s shape.
- Reuses existing pak fixtures — **no new `.pak`** (CI fixture-count gate
  untouched). Search needs no typed assets, so the 4a/4b typed-asset coverage
  gap does not apply.

## Implementation sequencing (for the plan)

1. Add `regex` dep + `search` subcommand skeleton (`SearchArgs`, registered,
   stub `run` returning `Ok(())`) + a `--help` flag test.
2. `parse_size` (pure) + unit tests.
3. `Predicates` (`from_args` + `matches`) + unit tests (incl. basename/ext).
4. Wire `run` (open → from_args → walk → print_entries) + integration tests
   (predicates, combinations, exit codes, JSON).
5. ROADMAP note (Phase 4 complete: extract + inspect + search) + full gate chain.
