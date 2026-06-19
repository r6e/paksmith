# Phase 4b — `paksmith inspect` Enhancements Design

**Status:** approved (brainstorming), pre-implementation
**Date:** 2026-06-19
**Roadmap:** Phase 4 (Full CLI) — `inspect` sub-phase (4a `extract` shipped in PR #586)

## Context

Phase 4 (Full CLI) decomposes into **4a extract → 4b inspect → 4c search**. 4a
shipped. This document specifies **4b only**.

`paksmith inspect <pak> <asset>` already serializes the *entire* `Package` to
JSON via serde: the full header (summary + name/import/export tables) **and**
each export's typed `Asset` payload under `"asset"`. The roadmap's core 4b
deliverable — "dump asset properties as JSON (the full property tree)" — is
therefore already met. 4b adds three enhancements on top, all CLI-side:

1. **Output wrapper + `schema_version`** — make the JSON a stable, versioned contract.
2. **Selection** — `--export <idx|name>` and `--path <dotted>` to narrow output.
3. **Human tree view** — implement `--format table` (currently rejected) with type-aware compact rendering.

`paksmith-core` is **not** modified. Typed structs (`FVector`, `FColor`, …)
keep their canonical self-documenting serde shape (`{"x","y","z"}`,
`{"r","g","b","a"}`); compact forms (`[x,y,z]`, `#RRGGBB`) appear *only* in the
human tree view.

## Goals / non-goals

- **Goal:** a versioned, selectable, human-readable `inspect`.
- **Non-goal:** changing the canonical JSON shape of any core type (compact
  rendering is presentation-only). No new asset parsing. `search` is 4c.
- **Non-goal:** a full GUI property inspector (Phase 7).

## Architecture

`commands/inspect.rs` is promoted to an `inspect/` submodule (it is about to
carry three distinct concerns):

```
crates/paksmith-cli/src/commands/inspect.rs  # MODIFY → thin: args + run() dispatch
crates/paksmith-cli/src/inspect/mod.rs        # CREATE: InspectOutput wrapper + orchestration
crates/paksmith-cli/src/inspect/select.rs     # CREATE: --export resolution + --path Value navigation
crates/paksmith-cli/src/inspect/tree.rs       # CREATE: human tree renderer + compact typed formatting
crates/paksmith-cli/src/main.rs               # MODIFY: add `mod inspect;`
```

The pipeline: parse the `Package` (existing `Package::read_from_pak`) → build
the `InspectOutput` body (full package, or a selected export) → serialize once
to `serde_json::Value` → apply `--path` navigation if present → emit as JSON,
or render the (pre-serialization) `Package` as a table.

### Component 1 — output wrapper + `schema_version`

A generic `flatten` wrapper, serialized **directly** (not via `serde_json::Value`)
for the full and `--export` outputs so field order is preserved without needing
serde_json's `preserve_order` feature:

```rust
#[derive(Serialize)]
struct InspectOutput<T: Serialize> {
    schema_version: u32,   // declared first → emitted first
    #[serde(flatten)]
    body: T,               // T serializes as a map: `&Package` or a `Value::Object`
}
```

Serde emits struct fields in declaration order, and `flatten` inlines the
flattened map's fields after `schema_version`. Per mode:

- **Default (no selection):** `to_writer_pretty(&InspectOutput { schema_version: 1, body: &package })`.
  The flattened `&Package` keeps its current **declaration-order** shape — the
  only change vs. today's output is the prepended `schema_version`. (No
  `to_value` round-trip, so no reordering.)
- **`--export <idx>`:** serialize the full `Package` to a `Value` once, take the
  `["exports"][idx]` subtree (already includes that export's `asset`), and emit
  `InspectOutput { schema_version: 1, body: <that Value::Object> }`. Fields
  within the export subtree may be alphabetized (it passed through `to_value`);
  this is cosmetic and acceptable for the focused view. `schema_version` is
  still first.
- **`--path`:** see Component 2 — navigation is read-only over the wrapped
  document and emits the located sub-`Value` directly.

`flatten` requires `T` to serialize as a map; both `&Package` (a struct) and
`Value::Object` satisfy this. Core `Package` serde is untouched. (Implementer
note: confirm `flatten` over `&Package` compiles cleanly; if a borrow/lifetime
snag appears, wrap an owned `Value` body uniformly and accept alphabetized
full output, updating the snapshot accordingly.)

### Component 2 — selection (`--export`, `--path`)

New `InspectArgs` fields:
- `--export <VALUE>`: `Option<String>`. Numeric → export-table index; else →
  match `ObjectExport::object_name`. Resolves to exactly one export; ambiguous
  name (multiple matches) or out-of-range index / unknown name → typed
  `InvalidArgument` (exit 2).
- `--path <DOTTED>`: `Option<String>`. Dotted segments navigate the serialized
  `serde_json::Value`: object keys and numeric array indices
  (`exports.0.asset`). A leaf emits the bare JSON value. Missing/!navigable
  path → `InvalidArgument` (exit 2).

Composition: `--export` selects the body first; `--path` drills into the
serialized wrapped document. `--path` **implies structured output** — combining
`--path` with `--format table` is rejected with `InvalidArgument` (you cannot
path-drill a table).

`select.rs` exposes:
- `resolve_export(pkg: &Package, selector: &str) -> Result<usize>` (index-or-name → export index).
- `navigate<'v>(root: &'v Value, path: &str) -> Result<&'v Value>` (dotted-path lookup).

### Component 3 — human tree view (`--format table`)

`tree.rs` renders a `Package` to an indented, readable text tree on stdout:

- **Header:** one summary line — engine version (`saved_by_engine_version`),
  export/import/name counts, package GUID.
- **Per-export:** `[idx] <object_name> : <class>` then a one-line payload
  shape — `opaque (<N> bytes)`, `tree (<N> properties)`, or the typed variant
  name with a few key fields.
- **Property tree:** for `PropertyBag::Tree`, an indented key/value tree.
  **Type-aware compact rendering applies here only:** `FVector`/`FVector2D`/
  `FVector4` → `[x, y, z(, w)]`; `FColor`/`FLinearColor` → `#RRGGBB` (or
  `#RRGGBBAA` when alpha ≠ opaque); enum/byte properties → resolved name.

`--format auto` resolves to table on a TTY and JSON when piped (matches `list`
and the existing inspect auto-fallthrough). `--export` works in both formats;
table for a single export shows just that export's block.

`tree.rs` formatters are pure functions over the typed values
(`fn fmt_vector(&FVector) -> String`, `fn fmt_color(&FColor) -> String`, …),
unit-testable without a pak.

## CLI surface (summary)

```
paksmith inspect <pak> <asset>
  [--mappings <PATH>]        # unchanged
  [--export <idx|name>]      # NEW: single export
  [--path <dotted>]          # NEW: drill into the JSON (implies structured; rejects --format table)
  --format json|table|auto   # table NOW IMPLEMENTED (was rejected)
```

## Error handling / exit codes

Reuses 4a's `commands::Command::run -> Result<u8>` contract: `0` success;
`2` for usage/selection failures — bad `--export` (index out of range, unknown
or ambiguous name), `--path` that doesn't resolve, and `--path` + `--format
table`. `BrokenPipe` on stdout still exits cleanly (existing `main.rs` path).
`--mappings` errors are unchanged.

## Testing

- **`insta` snapshots:** wrapped full-package JSON (asserts `schema_version: 1`
  first); `--export` single-export JSON; `--path summary.guid` (leaf) and
  `--path exports.0` (subtree); the `--format table` rendering. Host-specific
  values redacted for portability.
- **`assert_cmd`:** flag combinations and error exit codes — bad index, unknown
  name, ambiguous name, unresolved path, `--path`+`--format table` → exit 2.
- **Unit tests:** `navigate` (object key, array index, nested, leaf, missing,
  non-navigable-through-scalar); `resolve_export` (numeric, name, out-of-range,
  unknown, ambiguous); compact formatters (`fmt_vector` incl. `FVector2D`/`4`,
  `fmt_color` opaque vs alpha, enum resolution).
- Reuses existing fixtures; **no new `.pak`** (CI fixture-count gate untouched).

## Coverage limitation (documented, not silent)

As in 4a, no `.pak` fixture bundles a *typed* cooked asset, so the table view's
typed-payload rendering (vector/color compaction, typed key-field lines) is not
exercised end-to-end against a packed asset — it is unit-tested via constructed
`FVector`/`FColor`/typed values, and the integration table test runs against the
existing `Generic` asset (opaque + header rendering). A typed-asset pak fixture
remains a tracked follow-up shared with 4a/4c.

## Implementation sequencing (for the plan)

1. Promote `inspect.rs` → `inspect/` module skeleton; add `mod inspect;`.
2. `InspectOutput` wrapper + `schema_version` (JSON unchanged otherwise) + snapshot.
3. `--path` navigation (`select.rs::navigate`) + `--path`/table rejection.
4. `--export` resolution (`select.rs::resolve_export`) + single-export body.
5. `--format table` renderer (`tree.rs`) + compact formatters.
6. Integration snapshots + error-exit tests + ROADMAP note + full gate chain.
