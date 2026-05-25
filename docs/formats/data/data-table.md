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
serialized as a tagged-property sequence terminated by `"None"` —
the same per-property byte structure documented in
[`../property/tagged.md`](../property/tagged.md).

This is one of the highest-priority extraction targets in the
corpus because DataTables are how game studios ship configurable
content (every item, ability, NPC stat block, dialogue line).

**Document status: complete.** Wire format documented in full
against CUE4Parse[^1] with a hand-computed segment-2 worked
example below. No binary fixture is committed because synthesizing
a full `.uasset` file (with `PackageFileSummary`, name table,
import / export tables, etc.) is out of scope for a per-format
doc — the standalone synthesis tooling for `.uasset` files is a
Phase 3 deliverable. The per-property byte structure inside row
bodies is the property-system spec
([`../property/tagged.md`](../property/tagged.md)) — DataTable's
wire contribution is the row-iteration wrapper documented here.

**Paksmith parser status: not yet implemented.** Phase 3+
deliverable.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| UE 4.0+ | `UDataTable` + custom row serialization introduced. Per-row tagged-property bodies use the standard property-iteration. | `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Exports/Engine/UDataTable.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d`[^1] |
| UE 4.21+ | `bStripFromClientBuilds` / `bStripFromDedicatedServerBuilds` strip flags added as tagged properties; affect cooked-content variant inclusion. No wire-format break in the row-iteration segment. | Same[^1] |

The wire format has been stable since UE 4.0. The strip-flag
additions are tagged-property additions and don't change the
row-iteration shape.

## Wire layout

### Segment 1: tagged-property stream

`UDataTable` calls `base.Deserialize()` first — the standard
tagged-property iteration reads the class properties and terminates
at `"None"`. Common properties:

| Property name | Type | Semantics |
|---------------|------|-----------|
| `RowStruct` | `ObjectProperty` (`UScriptStruct`) | The struct type all rows must conform to. Resolves through the import table. |
| `bStripFromClientBuilds` | `BoolProperty` | UE 4.21+. If `1`, cooked client builds strip the table's rows. |
| `bStripFromDedicatedServerBuilds` | `BoolProperty` | UE 4.21+. If `1`, cooked dedicated-server builds strip. |
| `bIgnoreExtraFields` | `BoolProperty` | If `1`, rows with fields not in `RowStruct` are accepted silently. |
| `bIgnoreMissingFields` | `BoolProperty` | If `1`, rows missing `RowStruct` fields are accepted with defaults. |

Per-property byte structure follows
[`../property/tagged.md`](../property/tagged.md).

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
| `RowName` | 8 | LE | `FName` | Row's identifier (e.g. `"Weapon_Sword"`). Resolved via the package's name table — see [`../primitive/fname.md`](../primitive/fname.md) for the `(name_index: i32, number: i32)` wire layout. |
| `RowBody` | variable | — | tagged-property stream | The row's struct fields serialized exactly as a `StructProperty` body would be. Terminated by the `"None"` tag. Per-property byte structure per [`../property/tagged.md`](../property/tagged.md). |

The structural elegance: each row is essentially a recursive
`StructProperty` body without the outer tag, since
`tag.struct_name` is implied by the table's `RowStruct` reference.

### Worked example

A binary DataTable fixture is not committed — synthesizing a full
`.uasset` (with PackageFileSummary, name table, import / export
tables) is out of scope. The segment-2 byte layout below is
hand-computed and exhaustive for the wrapper that DataTable
contributes; per-property body bytes follow
[`../property/tagged.md`](../property/tagged.md) and are not
re-documented here.

**Synthetic example.** Suppose a `UDataTable` with
`RowStruct = FItemRow` (definition: `Value: FloatProperty`), and
two rows:

| Row name | `Value` |
|----------|---------|
| `row_alpha` | `1.5` |
| `row_beta` | `2.5` |

Assume the package's name table has been pre-populated such that
`"row_alpha"` is at name-index `N₁`, `"row_beta"` is at `N₂`,
`"Value"` is at `N_V`, `"FloatProperty"` is at `N_FP`, and
`"None"` is at `N_None`. Each `FName.number` field is `0` in
this example. (Name-table layout and indexing is the containing
`.uasset`'s responsibility — see
[`../asset/uasset.md`](../asset/uasset.md).)

Segment 2 byte sequence:

```
Offset  Bytes (LE)                                          Field
------  --------------------------------------------------  -----------------------------
+0      02 00 00 00                                         NumRows = 2 (i32)

# Row 1: RowName = "row_alpha"
+4      <N₁ as i32 LE> <0x00 0x00 0x00 0x00>                RowName: FName{ index=N₁, number=0 }
+12     <Row 1 body: variable; ends with "None" tag>        Row body — tagged-property
                                                             stream per ../property/tagged.md
                                                             For a single FloatProperty
                                                             "Value" = 1.5, body is
                                                             approximately 36 bytes
                                                             (28-byte tag + 8-byte "None").

# Row 2: RowName = "row_beta"
+48     <N₂ as i32 LE> <0x00 0x00 0x00 0x00>                RowName: FName{ index=N₂, number=0 }
+56     <Row 2 body: variable>                              Same shape as Row 1.
```

The "row body ends with `None` tag" rule is the key parser
contract: after reading `NumRows`, the reader iterates exactly
`NumRows` times, and for each iteration reads an `FName` then runs
the standard property iterator until it hits the `"None"` tag.
The property iterator's stopping position becomes the start of the
next row (or the post-segment-2 boundary if it was the last row).

For a single `FloatProperty` "Value" = 1.5, the per-row body
bytes are (per [`../property/tagged.md`](../property/tagged.md)):

```
+0      <N_V as i32 LE> <0x00 0x00 0x00 0x00>                Property tag.name = FName{ N_V, 0 }
+8      <N_FP as i32 LE> <0x00 0x00 0x00 0x00>               Property tag.type = FName{ N_FP, 0 }
+16     04 00 00 00                                          Property tag.size = 4 (i32; size of value)
+20     00 00 00 00                                          Property tag.array_index = 0 (i32)
+24     00 00 C0 3F                                          Property value = 1.5 (f32 LE; IEEE 754)
+28     <N_None as i32 LE> <0x00 0x00 0x00 0x00>             Property terminator = FName{ N_None, 0 }
+36                                                          (end of row body)
```

Total: 8-byte `RowName` + 36-byte row body = 44 bytes per row in
this example; full segment 2 = 4 + 2 × 44 = 92 bytes.

The 28-byte tag header is the standard tag size for "simple"
property types (Float / Int / Bool with no extra tag-data bytes).
Property types with additional tag data (`StructProperty`,
`ArrayProperty`, `BoolProperty`, etc.) add bytes per
[`../property/tagged.md`](../property/tagged.md)'s per-type tag
rules — DataTable's wire layout doesn't change; the row body just
gets longer.

## Variants

### Empty tables

`NumRows == 0` is legal and common in cooked content — some tables
get fully stripped when a build platform doesn't need them, but the
table asset itself remains for type-stability. The reader reads the
`i32` count, sees `0`, and emits an empty row map. No row-pair
bytes follow.

### Strip flags

`bStripFromClientBuilds` / `bStripFromDedicatedServerBuilds` cause
the cooker to write `NumRows = 0` for matching platforms. The
strip-flag property values are still present in segment 1; segment
2 contains just the 4-byte zero count, no row data.

### RowStruct resolution failure

If `RowStruct` resolves to an Import the reader doesn't have a
schema for, the row bodies are still parseable — the tagged-property
iteration is self-describing. The consumer just doesn't know the
row struct's intended shape; fields surface with their wire names
and types but without semantic context (no "this is an item-damage
value" mapping). Recover gracefully by emitting the row map with
`RowName → property_bag` entries.

### Custom-serialized row structs

Some row structs use native binary serialization rather than tagged
properties — same fallback shape as
[`../property/struct.md`](../property/struct.md). When the row
body decode hits non-tag bytes, the per-row read errors and the
reader falls back to opaque per-row bytes. The reader must record
the byte boundary it stopped at, because the next row's `RowName`
starts there — without that boundary, the rest of segment 2 is
unparsable.

### `UCompositeDataTable`

`UCompositeDataTable` is a subclass that inherits rows from one or
more parent tables via the engine's runtime composite layer. For
standard (non-game-specific) builds at this oracle SHA, its
on-disk wire shape is identical to `UDataTable` (the
`UCompositeDataTable.Deserialize` constructor calls
`base.Deserialize` with no additional pre-reads outside a
`GAME_HonorofKingsWorld`-specific `CustomGameData` array); the
composite merging happens at runtime, not on disk.[^1]

## Caps & limits

### Format-defined limits (wire-imposed)

- `NumRows` is `i32`, so a single DataTable can hold at most
  `i32::MAX = 2_147_483_647` rows.
- Per-row `RowName` is `FName`, bounded by the containing
  `.uasset`'s name-table size (see
  [`../primitive/fname.md`](../primitive/fname.md)).
- Per-row body is a tagged-property stream, bounded by the standard
  property-system limits (FString length, tag count per body,
  recursion depth — see
  [`../property/tagged.md`](../property/tagged.md)).
- Total segment-2 size: bounded only by the containing `.uasset`'s
  export-table `serial_size` for this export.

### Implementation hardening (recommended for any parser)

- **`NumRows` (`i32`) sign-check + allocation cap (required wire
  invariant, not deferred):** MUST be validated `>= 0` before
  allocating the rows map. A negative cast to `usize` produces
  `usize::MAX`-adjacent values; immediate OOM or panic. Additionally:
  a conservative cap of `2^20 = 1_048_576` rows is sufficient to
  prevent allocation DoS while remaining well above any production
  data-table file. Phase 3 SHOULD tighten via
  `MAX_ROWS_PER_DATATABLE` once usage patterns are established.
- **`RowName` (`FName`) name-table index bounds-check:** Per the
  standard `FName` resolution rules (see
  [`../primitive/fname.md`](../primitive/fname.md)), the
  name-table index in any `FName` MUST be validated against the
  package's name-table size before resolution. OOB indexes are a
  UDataTable-specific hazard distinct from the property-system
  caps: a crafted `RowName` can index past the name table to read
  garbage bytes or panic on `usize` cast.
- **Row-body stopping position MUST advance the cursor:** Each row
  iteration MUST advance the read cursor by exactly the body's
  serialized length (up to and including the `"None"` terminator).
  A parser that fails to advance — e.g., one that decodes
  properties into a structure but doesn't track byte position —
  will mis-parse the next row's `RowName`. This is the same class
  of hazard as the locres seek-and-return contract: position is a
  wire-format invariant, not an implementation choice.
- **Custom-serialized row recovery:** When per-row decoding fails
  (custom-serialized native struct, unknown property type), the
  reader MUST either (a) reject the file or (b) advance to the
  next row using a byte-length-based skip (which requires
  per-row-size pre-knowledge that the wire format does not
  provide). In practice (b) is impossible for an unknown row
  shape, so the safe behavior is (a): reject. The format does not
  encode per-row sizes; an unrecoverable parse error on row N
  means rows N+1..NumRows-1 are unreachable.

## Verification

- **Fixture:** none committed. Synthesizing a minimal `.uasset`
  with a `UDataTable` export requires emitting a full
  `PackageFileSummary` + name table + import / export tables —
  out of scope for a per-format doc. The Worked example above
  documents the segment-2 wrapper exhaustively; per-property
  body bytes follow [`../property/tagged.md`](../property/tagged.md).
  Phase 3 work that produces real DataTable fixtures should add
  one or two committed `.uasset` examples (a 0-row table for the
  strip-flag case; a 2-row table for the full row-iteration case).
- **Hex anchor commands:** none today (no committed fixture). When
  Phase 3 adds DataTable fixtures, the hex-anchor commands will
  use the standard `xxd -s <serial_offset> -l <serial_size>`
  pattern to extract the export bytes from the containing
  `.uasset`, then `xxd -s <serial_offset + segment_1_end>` to
  isolate segment 2.
- **Cross-validation oracle:** CUE4Parse[^1] (primary). Covers
  the row-serialization shape and the strip-flag handling.
- **Known divergences:**
  - Custom-serialized row structs — same fallback shape as
    StructProperty native-struct bodies. Documented in
    [`../property/struct.md`](../property/struct.md).
  - `GAME_HonorofKingsWorld`-specific `CustomGameData` array in
    `UCompositeDataTable.Deserialize` — game-profile concern,
    out of scope for general-purpose `UDataTable` parsing.

## Paksmith implementation

**Parser module:** not yet implemented.

**Parser status:** `not impl`.

**Phase plan:** see `docs/plans/ROADMAP.md` for the Phase 3 and
Phase 4 work. DataTables are a high-value extraction target —
game studios ship configurable content (items, abilities, NPC
stats) this way, and bulk extraction is a frequently requested
capability.

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Exports/Engine/UDataTable.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` — primary oracle. Covers the row-serialization shape, strip-flag handling, and the `UCompositeDataTable` subclass. The implementation reads `NumRows` as `Ar.Read<int>()` (i32), then iterates `NumRows` times reading `(FName key, FStructFallback row body)` pairs where `FStructFallback` runs the standard tagged-property iteration until the `"None"` terminator.
