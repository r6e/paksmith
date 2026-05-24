# DataTable (`UDataTable`)

> Row-oriented data container — each row is a tagged-property body
> keyed by `FName`, with the per-row schema given by the table's
> `RowStruct` reference. Common for game databases (item lists,
> ability tables, dialogue tables).

## Overview

`UDataTable` is UE's row-indexed data structure. Each table:

1. References a `UScriptStruct` via `RowStruct: ObjectProperty` —
   the type definition that all rows conform to.
2. Stores rows as a `TMap<FName, RowStruct*>` — keys are row names
   (`"Weapon_Sword"`, `"Ability_Fireball"`); values are heap-
   allocated instances of the row struct.

On disk, after the standard tagged-property segment, the table
serializes its rows as a custom blob: an `i32` row count followed
by `(FName key, tagged-property-stream value)` pairs. The
"tagged-property-stream value" is the row's `RowStruct` instance
serialized as a tagged-property sequence terminated by `"None"`.

This is one of paksmith's higher-priority Phase 3+ targets because
DataTables are how game studios ship configurable content (every
item, ability, NPC stat block, dialogue line). Extracting them is
often the single most-requested asset-extraction capability.

**Status: not yet implemented in paksmith.** Phase 3+ deliverable.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| UE 4.0+ | `UDataTable` + custom row serialization introduced. Per-row tagged-property bodies use the standard iteration. | `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Exports/Engine/UDataTable.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d`[^1] |
| UE 4.21+ | `bStripFromClientBuilds` / `bStripFromDedicatedServerBuilds` strip flags added; affect cooked-content variant inclusion. | Same[^1] |

## Wire layout

### Segment 1: tagged-property stream

`UDataTable` calls `base.Deserialize()` first — the standard
tagged-property iteration reads the class properties and terminates
at `"None"`. Common properties:

| Property name | Type | Semantics |
|---------------|------|-----------|
| `RowStruct` | `ObjectProperty` (`UScriptStruct`) | The struct type all rows must conform to. |
| `bStripFromClientBuilds` | `BoolProperty` | UE 4.21+. If `1`, cooked client builds strip the table's rows. |
| `bStripFromDedicatedServerBuilds` | `BoolProperty` | UE 4.21+. If `1`, cooked dedicated-server builds strip. |
| `bIgnoreExtraFields` | `BoolProperty` | If `1`, rows with fields not in `RowStruct` are accepted silently. |
| `bIgnoreMissingFields` | `BoolProperty` | If `1`, rows missing `RowStruct` fields are accepted with defaults. |

### Segment 2: serialized rows

After the property terminator, `UDataTable` writes the row data
as a custom non-tagged blob:

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `NumRows` | 4 | LE | `i32` | Number of rows that follow. |
| `Rows` | variable | — | `(FName key, tagged-property stream)[]` | Per-row pairs; length is `NumRows`. |

Per-row pair:

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `RowName` | 8 | LE | `FName` | Row's identifier (e.g. `"Weapon_Sword"`). Resolved via the package's name table. |
| `RowBody` | variable | — | tagged-property stream | The row's struct fields serialized exactly as a `StructProperty` body would be. Terminated by `"None"`. |

The structural elegance: each row is essentially a recursive
`StructProperty` body without the outer tag, since
`tag.struct_name` is implied by the table's `RowStruct` reference.

### Worked example

`(none yet — Phase 3 deliverable)`.

## Variants

### Empty tables

`NumRows == 0` is legal and common in cooked content — some tables
get fully stripped when a build platform doesn't need them, but the
table asset itself remains for type-stability. Parse and emit an
empty row map.

### Strip flags

`bStripFromClientBuilds` / `bStripFromDedicatedServerBuilds` cause
the cooker to write `NumRows = 0` for matching platforms. The
property values are still present on disk; the row data is omitted.

### RowStruct resolution failure

If `RowStruct` resolves to an Import paksmith doesn't have a schema
for, the row bodies are still parseable — the tagged-property
iteration is self-describing. The consumer just doesn't know the
row struct's intended shape; fields surface with their wire names
and types but without semantic context.

### Custom-serialized row structs

Some row structs use native binary serialization rather than tagged
properties — same problem as
[`../property/struct.md`](../property/struct.md). When the row
body decode hits non-tag bytes, the per-row read errors and paksmith
falls back to opaque per-row bytes (exact fallback behavior is a
Phase 3 design decision).

### `UCompositeDataTable`

`UCompositeDataTable` is a subclass that inherits rows from one or
more parent tables via the engine's runtime composite layer. For standard (non-game-specific) builds at this oracle SHA, its on-disk wire shape is identical to `UDataTable` (the `UCompositeDataTable.Deserialize` constructor calls `base.Deserialize` with no additional pre-reads outside a `GAME_HonorofKingsWorld`-specific `CustomGameData` array); the composite merging happens at runtime, not on disk.[^1]

## Caps & limits

Phase 3+ deferred work. Cap values for `MAX_ROWS_PER_DATATABLE` and
per-row limits will be determined when the Phase 3 reader lands.
Per-row caps are inherited from the property system — see
[`../property/tagged.md`](../property/tagged.md).

- **`NumRows` (`i32`) cap (required wire invariant, not deferred):** Sign-check (`>= 0`) is mandatory; additionally, a conservative cap of `2^20 = 1,048,576` rows is sufficient to prevent allocation DoS while remaining well above any production data-table file. A negative `NumRows` cast to `usize` produces `usize::MAX`-adjacent values; immediate OOM or panic on allocation. Phase 3 SHOULD tighten via `MAX_ROWS_PER_DATATABLE` once usage patterns are established.
- **`RowName` (`FName`) name-table index bounds-check:** Per the standard FName resolution rules (see [`../primitive/fname.md`](../primitive/fname.md)), the name-table index in any FName MUST be validated against the package's name-table size before resolution. OOB indexes are a UDataTable-specific hazard distinct from the property-system caps: a crafted RowName can index past the name table to read garbage bytes or panic on `usize` cast.

## Verification

- **Fixture:** `(none yet — Phase 3 deliverable)`.
- **Hex anchor commands:** `(none yet — Phase 3 deliverable)`.
- **Cross-validation oracle:** CUE4Parse[^1] (primary). Covers the
  row-serialization shape and the strip-flag handling.
- **Known divergences:**
  - Custom-serialized row structs — same fallback shape as
    StructProperty native-struct bodies. Documented in
    [`../property/struct.md`](../property/struct.md).

## Paksmith implementation

**Parser module:** not yet implemented.

**Status:** `not impl`.

**Phase plan:** See `docs/plans/ROADMAP.md` for the Phase 3 and
Phase 4 work that will add row iteration and CLI integration.
DataTables are a high-value extraction target — game studios ship
configurable content (items, abilities, NPC stats) this way, and
bulk extraction is a frequently requested capability.

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Exports/Engine/UDataTable.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` — primary oracle. Covers the row-serialization shape, strip-flag handling, and the `UCompositeDataTable` subclass.
