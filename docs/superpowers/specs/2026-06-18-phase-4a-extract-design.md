# Phase 4a — `paksmith extract` Design

**Status:** approved (brainstorming), pre-implementation
**Date:** 2026-06-18
**Roadmap:** Phase 4 (Full CLI) — `docs/plans/ROADMAP.md` §"Phase 4: Full CLI"

## Context

Phase 4 (Full CLI) completes the command surface — `extract`, `inspect`,
`search`. It decomposes into three sub-phases, each its own
spec → plan → PRs cycle:

- **4a — `extract`** (this doc): batch export via the Phase 3 handler registry.
- **4b — `inspect`**: full property-tree JSON. Mostly schema-stabilization —
  `inspect` already serializes the full typed `Package` (header + per-export
  `Asset` payloads) via serde.
- **4c — `search`**: entry queries by type / name / size / regex.

Sequencing: **4a → 4b → 4c**. `extract` leads because it exercises the entire
export registry end-to-end and is the headline deliverable.

This document specifies **4a only**.

## Goals

`paksmith extract <pak> -o <dir> [flags]` — walk a pak, convert assets to
standard formats via the export registry, and mirror the archive's internal
path tree (or flatten it) into an output directory. Resilient (one bad asset
never aborts the batch), parallel, scriptable (stable JSON summary, disciplined
exit codes).

This is the "full roadmap" cut: `--flat`, `--dry-run`, `indicatif` progress on
stderr, `rayon` parallelism, per-domain format negotiation, raw-bytes fallback,
and continue-on-error with an end-of-run summary all land in 4a.

## Non-goals (4a)

- `inspect` / `search` (→ 4b / 4c).
- IoStore containers (→ Phase 8; the design stays container-agnostic via
  `ContainerReader` where practical, but 4a targets `.pak`).
- Game-profile resolution (→ Phase 5; `--game` is a stub, see below).
- New export formats or handler behavior — 4a *drives* the existing Phase 3
  registry, it does not add handlers.

## Architecture

### New files

```
paksmith-cli/src/commands/extract.rs   # arg struct, run(), wires the job + summary render
paksmith-cli/src/extract/mod.rs         # ExtractJob orchestration (walk → dispatch → write)
paksmith-cli/src/extract/safe_path.rs   # zip-slip-safe output-path derivation
paksmith-cli/src/extract/summary.rs     # ExtractSummary + stable serde JSON schema
```

`commands/extract.rs` stays thin (parse args, build an `ExtractJob`, run it,
render the summary). The `extract/` submodule holds the logic so each unit is
independently testable.

### Core addition

`Package::read_from_reader(reader: Arc<PakReader>, virtual_path: &str, mappings: Option<&Usmap>) -> Result<Package>`

Today `read_from_pak(path, …)` opens the pak and re-parses the index on **every
call**. For batch extract over a large pak (100k+ entries) that is wasteful.
`read_from_reader` takes an **already-open** `Arc<PakReader>` and wires the same
real `Arc<PakReader>`-backed `.ubulk`/`.uptnl` bulk loaders that `read_from_pak`
uses (bulk data is mandatory for texture/mesh/audio export — `read_from`'s stub
loaders error on streaming tiers, so extract cannot use `read_from`).

`read_from_pak` is refactored to: open the pak → wrap in `Arc` →
delegate to `read_from_reader`. This is a small, additive, separately-TDD'd and
separately-reviewed core change, landing as an early 4a task. It is reusable by
4b, 4c, and the future GUI (Phases 6–7).

### Reader / parallelism model

`PakReader` is `Send + Sync` (internal `Mutex<Box<dyn PakReadSeek>>`). Extract
opens the pak **once**, wraps it in `Arc<PakReader>`, and shares the `Arc`
across `rayon` workers. Entry-byte reads serialize on the reader's `Mutex`;
the CPU-bound work (asset parse, BC decode, PNG/glTF/WAV encode) runs
concurrently — which is where the per-asset cost actually lives.

`--jobs N` caps the rayon thread count (default = rayon's CPU-count default).

## The extract pipeline (per entry)

1. **Classify** by extension:
   - `.uasset` / `.umap` → **asset** path.
   - `.uexp` / `.ubulk` / `.uptnl` → **skipped** (companions consumed by the
     asset parse; never emitted separately). Counted as `skipped_companion`.
   - everything else (`.ini`, `.locres`, loose files) → **raw passthrough**.
2. **Asset path:**
   `read_from_reader` → select export (see multi-export rule) →
   `find_handler` (or per-domain extension override) →
   `resolve_bulk_for_export` → `handler.export(asset, bulk)` →
   write `<stem>.<handler-extension>`.
3. **Multi-export rule:** a `Package` carries `payloads: Vec<Asset>` (one per
   export). Iterate them; **the first export whose resolved handler is not the
   `Generic` passthrough wins**. If none is convertible → raw `.uasset`
   fallback. If more than one is convertible → first wins; the rest are logged
   (debug) and not emitted.
4. **Raw path:** unhandled asset class, or a non-asset entry → copy the entry
   bytes verbatim under the original filename. (For an unhandled `.uasset`,
   that means the original `.uasset` bytes.)
5. **Failure isolation:** any parse/convert/write error on a single entry is
   recorded in the summary and **never aborts the batch**.

## CLI surface

```
paksmith extract <pak> -o/--output <dir>
  [--filter <glob>]              # same glob engine as `list`
  [--flat]                       # strip directories; basename only
  [--dry-run]                    # plan without writing (parse-accurate; see below)
  [--overwrite]                  # permit overwriting existing output files
  [--audio-format ogg|wav]       # default: ogg
  [--datatable-format csv|json]  # default: csv
  [--jobs N]                     # rayon thread cap; default = CPU count
  [--game <id>]                  # Phase 5 stub (see below)
```

- Texture (`png`) and mesh (`glb`) are single-format today; per-domain flags
  are added as those variants grow alternatives.
- The **global** `--format table|json|auto` flag governs the **end-of-run
  summary** rendering — *not* file output. `auto` → table on a TTY, JSON when
  piped (matching `list`).

### Decided defaults

- **Overwrite:** error if an output file already exists, unless `--overwrite`.
- **`--flat` collisions:** two assets collapsing to the same basename is a
  collision, handled like overwrite — error unless `--overwrite`, which then
  applies last-writer-wins with a warning.
- **`--dry-run`:** **parse-accurate** — fully parses each asset to report the
  *true* output extension and would-be path, but writes nothing. Slower than a
  guess, but honest.
- **`--game`:** accepted; if a value is passed, errors
  `--game is not supported until Phase 5 (game profiles)`. Absent = no-op.
  Reserves the flag name without faking behavior.

### Exit codes

- `0` — all entries succeeded.
- `1` — completed, but ≥1 entry failed (failures listed in the summary).
- `2` — fatal: bad/unreadable pak, invalid arguments, output-directory error.

(`2` matches the existing top-level error path in `main.rs`.)

## Path safety (zip-slip) — non-negotiable, in 4a

Pak entry paths are **untrusted input** (opening unknown paks is the whole
point of the tool). `output_dir.join(entry_path)` is a zip-slip vulnerability,
and Rust's `Path::join` silently discards the left side when the right side is
absolute (`out.join("/etc/x") == "/etc/x"`).

`extract/safe_path.rs` derives every output path through a sanitizer that:

- rejects / strips `..` components,
- rejects leading `/` (POSIX absolute) and Windows drive (`C:\`) / UNC prefixes,
- normalizes separators,
- resolves the candidate against the **canonicalized output root** and **errors
  if the final path escapes** the root.

Applies to **both** mirrored and `--flat` modes (`--flat` still derives a name
from the untrusted entry). Backed by a dedicated adversarial test set
(`../../etc/passwd`, `C:\Windows\…`, absolute paths, mixed `\`/`/` separators,
embedded `..`).

The container layer is read/lookup-only — there is no existing write-path
helper to reuse, so this is new code and a mandatory security-reviewer surface.

## Summary JSON schema (stable)

Emitted on `--format json` (and to a file/stdout); anchors `insta` snapshots
and gives 4b/4c a consistent output contract.

```json
{
  "pak": "Game.pak",
  "output_dir": "out",
  "dry_run": false,
  "counts": {
    "converted": 412,
    "raw_copied": 88,
    "skipped_companion": 412,
    "failed": 3
  },
  "failures": [
    { "entry": "Path/To.uasset", "error": "..." }
  ],
  "outputs": [
    { "entry": "Path/To.uasset", "output": "out/Path/To.png", "handler": "png", "kind": "converted" }
  ]
}
```

`kind` ∈ `{ "converted", "raw_copied" }` for `outputs`. Skipped companions and
failures are tracked in their own buckets, not in `outputs`.

## Error handling & resilience

- Per-entry errors are caught, recorded (`failures[]`), and the batch
  continues — aligning with the ROADMAP cross-cutting "one bad asset never
  takes down the whole operation."
- Fatal setup errors (pak won't open, output dir uncreatable, bad args) abort
  before the walk and return exit `2`.
- `BrokenPipe` on summary output exits cleanly (existing `main.rs` convention).
- Progress + diagnostics go to **stderr** (`indicatif`); the summary (when
  JSON) goes to **stdout**, keeping pipelines clean.

## Testing

- **`assert_cmd`** integration tests: flag combinations, exit codes (0/1/2),
  error cases (missing pak, bad glob, existing output without `--overwrite`).
- **`insta`** snapshots of the summary JSON across representative paks.
- **Extraction-to-tempdir** with content assertions (converted bytes match a
  golden; raw copies match source bytes; companions absent from output).
- **Zip-slip adversarial suite** against `safe_path` (unit-level).
- **Parallel determinism:** summary counts/outputs stable regardless of
  `--jobs` (sort outputs for deterministic comparison).
- New `.pak` fixtures bump CI's hardcoded fixture-count gate
  (`.github/workflows/ci.yml`).

## Risks / open items

- **Index re-parse vs shared reader:** mitigated by `read_from_reader` (open
  once, share `Arc`). If the core refactor proves larger than expected, the
  fallback is per-asset `read_from_pak` (correct but slower) — to be surfaced,
  not silently chosen.
- **Mutex-serialized I/O** caps I/O concurrency; acceptable because decode/encode
  dominates per-asset cost. A positioned-read (`pread`) refactor is a possible
  future optimization, out of scope for 4a.
- **`--flat` ergonomics:** collision-as-error may surprise users with
  flat-heavy paks; `--overwrite` is the escape hatch. Revisit if painful.

## Sub-phase boundary

4a ships `extract` end-to-end. Anything not listed here (e.g. resume/manifest
re-extraction, IoStore, profile-driven `--game`) is out of scope and tracked
under its named target phase.
