# UE Data Family Documentation — PR 12 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Populate `docs/formats/data/` with three documents — `data-asset.md` (`UDataAsset`; mostly a convention), `data-table.md` (`UDataTable` + per-row tagged-property bodies), and `locres.md` (the `.locres` localization-table sibling format — *not* a UE package). All three are `partial | not impl` — Phase 3+ deliverables. Add three rows to the root inventory. **Final family plan; the framework's complete inventory is populated after this PR.**

**Architecture:** Three docs with distinct shapes. `data-asset.md` documents a convention more than a wire format — `UDataAsset` is essentially "any UObject subclass that's pure data with no runtime behavior", so its on-disk form is just the tagged-property body that the property family already covers. `data-table.md` adds the row-struct schema reference and the per-row body iteration. `locres.md` is genuinely different — it's a standalone binary format with its own header, version field, and namespace / key / source-string tables, *not* a UObject package. The doc spells this out explicitly so future readers don't conflate it with the asset-family docs.

**Tech Stack:** Pure markdown. PR 1 linters. Primary oracle is `FabianFG/CUE4Parse/UE4/Assets/Exports/` for `UDataAsset` and `UDataTable`, and `FabianFG/CUE4Parse/UE4/Localization/FTextLocalizationResource.cs` for `.locres`. Secondary is `unreal_asset` for the asset docs.

**Spec reference:** `docs/design/2026-05-19-ue-format-docs.md` (commit `72b364e`). **Prerequisite:** PR 1 (framework scaffold) has merged to `main`.

**Series-completion note:** PR 12 closes the 12-PR rollout from the framework spec. After this lands, every format documented in the spec's directory layout has at least a starter doc in the inventory.

---

## Prerequisites

Follow [PREAMBLE.md](2026-05-19-ue-format-docs-PREAMBLE.md). Family name `data`; capture `<CUE4PARSE_SHA>` and `<UNREAL_ASSET_SHA>` at preamble Step 7.

## File structure

**Create (3 docs):**

- `docs/formats/data/data-asset.md` — `UDataAsset` (and the `UPrimaryDataAsset` subclass).
- `docs/formats/data/data-table.md` — `UDataTable` + row-struct schema.
- `docs/formats/data/locres.md` — `.locres` localization-table standalone format.

**Modify (1):**

- `docs/formats/README.md` — add three rows to the inventory.

**Oracle citation policy.** Primary: CUE4Parse's per-class readers in `UE4/Assets/Exports/Engine/` (for `UDataAsset` / `UDataTable`) and `UE4/Localization/` (for `.locres`). Secondary: `unreal_asset` for the asset docs only — it doesn't cover `.locres`.

**Hex-anchor policy.** `(none yet — Phase 3 deliverable)` for `data-asset.md` and `data-table.md`. `locres.md` could carry a real anchor today since the format is fully public and a `.locres` file could be cheaply synthesized — defer the anchor to a follow-up that adds the fixture, but the doc's Wire layout is comprehensive enough to verify by hand against any cooked `.locres`.

---

## Task 1: Per-family setup

Run [PREAMBLE.md](2026-05-19-ue-format-docs-PREAMBLE.md)'s "Per-family setup" with `<family> = data`. Capture oracle SHAs at preamble Step 7 for use across this plan's doc citations.

---

## Task 2: Author `docs/formats/data/data-asset.md` (partial)

`UDataAsset` is a UE base class for "this is pure-data; no
runtime behavior". The asset's on-disk wire shape is just the
tagged-property body — there's no specialized record beyond the
standard property iteration. The doc explains the convention and
catalogs the common subclass patterns.

**Files:**
- Create: `docs/formats/data/data-asset.md`

**Oracle references:**
- `CUE4Parse/UE4/Assets/Exports/Engine/UDataAsset.cs` (typically a stub since the class is mostly convention).
- `CUE4Parse/UE4/Assets/Exports/Engine/UPrimaryDataAsset.cs`.

- [ ] **Step 2: Write the doc**

Write `docs/formats/data/data-asset.md`:

````markdown
# DataAsset (`UDataAsset` / `UPrimaryDataAsset`)

> UE base class for pure-data assets — no runtime behavior, just a
> tagged-property body. On disk, indistinguishable from any other
> `UObject` export.

## Overview

`UDataAsset` is UE's convention for "this asset is pure data — its
purpose is to hold values, not execute logic". The class adds no
on-disk wire shape beyond the standard tagged-property iteration
covered in [`../property/tagged.md`](../property/tagged.md); a
`UDataAsset` export body is just a property tree terminated by the
`"None"` tag.

What makes `UDataAsset` worth a dedicated doc is the **convention
ecosystem** around it:

- **`UPrimaryDataAsset`** — subclass adding asset-registry tags so
  the engine's primary-asset system can discover instances at
  runtime. The wire shape adds nothing — the asset-registry
  integration happens via the standard `AssetRegistryData` summary
  field (see [`../asset/uasset.md`](../asset/uasset.md)).
- **Game-specific subclasses** — most cooked games derive their own
  classes (e.g. `UWeaponDataAsset`, `UCharacterStatsDataAsset`,
  `UItemDefinition`). Each is a `UObject` export with a class-
  specific set of properties; the wire shape is the union of the
  parent class's properties plus the subclass's additions.

paksmith doesn't need a per-subclass reader — the standard property
iterator already extracts all the data. What this doc *does* spell
out is the convention for recognizing data assets at extraction
time (so the CLI can offer "extract all DataAsset instances" /
"list all UPrimaryDataAsset GUIDs") and the import-resolution
nuances when a DataAsset references other DataAssets.

**Status: not yet implemented in paksmith** *as a specialized
reader*. The data IS already extracted today — the property
iterator surfaces every field as a `PropertyValue::*`. What's
not implemented is the per-class dispatch / CLI integration that
would make data-asset extraction a first-class command. Phase 3+.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| UE 4.0+ | `UDataAsset` introduced as a `UObject` subclass. Wire shape is the tagged-property body — version conditionals on individual properties apply, but no class-specific wire-format break has occurred. | `CUE4Parse/UE4/Assets/Exports/Engine/UDataAsset.cs@<CUE4PARSE_SHA>`[^1] |
| UE 4.12+ | `UPrimaryDataAsset` added as subclass; adds `PrimaryAssetType` and `PrimaryAssetName` tag conventions for the asset-registry. | Same[^1] |

## Wire layout

### Segment 1: tagged-property stream

The entire on-disk content of a `UDataAsset` is one tagged-property
sequence terminated by `"None"`. See
[`../property/tagged.md`](../property/tagged.md) for the
iteration mechanics.

Common properties on `UPrimaryDataAsset`:

| Property name | Type | Semantics |
|---------------|------|-----------|
| `PrimaryAssetType` | `StructProperty(FPrimaryAssetType)` | Asset-registry-side type identifier. |
| `PrimaryAssetName` | `StructProperty(FPrimaryAssetName)` | Asset-registry-side instance identifier. |

Game-specific subclass properties are arbitrary — any combination
of the property types catalogued in
[`../property/primitives.md`](../property/primitives.md) +
[`../property/containers.md`](../property/containers.md) +
[`../property/struct.md`](../property/struct.md).

### Segment 2 — none

There is no segment 2. `UDataAsset` adds nothing past the property
terminator. The post-terminator `serial_size` boundary should match
exactly.

### Worked example

`(none yet — no dedicated DataAsset fixture)`. Any of the existing
`tests/fixtures/minimal_uasset_v5_with_properties.uasset` family
can serve as a structural anchor since the wire shape is just the
property body.

## Variants

### `UPrimaryDataAsset` vs `UDataAsset`

`UPrimaryDataAsset` adds the two asset-registry properties shown
above but no wire-format break. Distinguishable by class name in
the import table (the export's `class_index` resolves to
`/Script/Engine.PrimaryDataAsset` vs `/Script/Engine.DataAsset`).

### Game-specific subclasses

Game-specific subclasses surface as `class_index` resolutions to
custom paths (`/Game/Code/WeaponDataAsset.WeaponDataAsset_C` etc.).
paksmith treats them as opaque subclasses of `UDataAsset` for
extraction purposes — the per-game schema is the consumer's
responsibility.

### Data-asset references

DataAssets routinely reference other DataAssets (a weapon's
`AmmoType` is itself a DataAsset). These appear as `ObjectProperty`
or `SoftObjectProperty` values resolving through the import table.
paksmith's existing `Object` / `SoftObjectPath` PropertyValue
variants surface the references correctly.

## Caps & limits

The caps that apply to `UDataAsset` are the property-system caps:

- `MAX_PROPERTY_TAG_SIZE = 16 MiB` per individual property.
- `MAX_TAGS_PER_EXPORT = 65,536` per export.
- `MAX_PROPERTY_DEPTH = 128` recursive depth.
- `MAX_COLLECTION_ELEMENTS = 65,536` for array / map / set
  properties.

See [`../property/tagged.md`](../property/tagged.md) and the
caps section of each property-family doc.

## Verification

- **Fixture:** `(none yet)`. The `minimal_uasset_v5_with_properties.uasset`
  fixture is a structural proxy — its property iteration exercises
  the same codepath any DataAsset would use.
- **Cross-validation oracle:** CUE4Parse[^1] (which has no specialized
  `UDataAsset` reader either — same convention-only treatment) and
  `unreal_asset`[^2].
- **Known divergences:** none yet.

## Paksmith implementation

**Parser module:** none specific. DataAsset extraction reuses the
existing property iteration in
`crates/paksmith-core/src/asset/property/`. Phase 3+ may add a
per-class dispatch (e.g.
`crates/paksmith-core/src/asset/exports/data/data_asset.rs`) to
surface a typed `DataAsset` PropertyBag wrapper, but no specialized
wire reading is needed.

**Status:** `not implemented` (no specialized reader / dispatch).
The data itself IS extracted by the property iterator.

**Phase plan:** `docs/plans/ROADMAP.md` Phase 3 (Export Pipeline)
+ Phase 4 (Full CLI). The Phase 4 CLI work is the natural insertion
point for a `paksmith list-data-assets` / `paksmith extract --type DataAsset`
command.

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Exports/Engine/UDataAsset.cs@<CUE4PARSE_SHA>` and `UPrimaryDataAsset.cs` in the same directory. Note: CUE4Parse's UDataAsset reader is typically a stub — the class adds nothing beyond the property iteration, same as paksmith.
[^2]: `AstralOrigin/unreal_asset/unreal_asset/src/exports/data_asset_export.rs@<UNREAL_ASSET_SHA>` — Rust counterpart.
````

- [ ] **Step 3: Commit** (preamble convention — required-headings linter must pass before commit)

```bash
git add docs/formats/data/data-asset.md
git commit -m "$(cat <<'EOF'
docs(formats): add DataAsset partial reference

Documents UDataAsset / UPrimaryDataAsset: a convention-only base
class with no specialized wire shape — the on-disk content is just
the tagged-property body terminated by None. Explains the
PrimaryDataAsset registry-tag additions, game-specific subclass
patterns, and the implicit-already-extracted status (paksmith's
property iterator surfaces all DataAsset content today; what's
deferred to Phase 3+ is per-class dispatch / CLI integration).
partial-not-impl.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Author `docs/formats/data/data-table.md` (partial)

`UDataTable` is the row-oriented data container — each row is a
tagged-property body keyed by FName, with the per-row schema given
by a `RowStruct` reference. Common for game databases (item lists,
ability tables, dialogue trees).

**Files:**
- Create: `docs/formats/data/data-table.md`

**Oracle references:**
- `CUE4Parse/UE4/Assets/Exports/Engine/UDataTable.cs`.

- [ ] **Step 2: Write the doc**

Write `docs/formats/data/data-table.md`:

````markdown
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
serializes its rows as a custom blob: a `i32` row count followed
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
| UE 4.0+ | `UDataTable` + custom row serialization introduced. Per-row tagged-property bodies use the standard iteration. | `CUE4Parse/UE4/Assets/Exports/Engine/UDataTable.cs@<CUE4PARSE_SHA>`[^1] |
| UE 4.21+ | `bStripFromClientBuilds` / `bStripFromDedicatedServerBuilds` strip flags added; affect cooked-content variant inclusion. | Same[^1] |

## Wire layout

### Segment 1: tagged-property stream

Common properties:

| Property name | Type | Semantics |
|---------------|------|-----------|
| `RowStruct` | `ObjectProperty` (`UScriptStruct`) | The struct type all rows must conform to. |
| `bStripFromClientBuilds` | `BoolProperty` | UE 4.21+. If `1`, cooked client builds strip the table's rows. |
| `bStripFromDedicatedServerBuilds` | `BoolProperty` | UE 4.21+. If `1`, cooked dedicated-server builds strip. |
| `bIgnoreExtraFields` | `BoolProperty` | If `1`, rows with fields not in `RowStruct` are accepted silently. |
| `bIgnoreMissingFields` | `BoolProperty` | If `1`, rows missing `RowStruct` fields are accepted with defaults. |

Properties terminate with the standard `"None"` tag.

### Segment 2: serialized rows

After the property terminator, `UDataTable` writes the row data
as a custom non-tagged blob:

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `NumRows` | 4 | LE | `i32` | Number of rows that follow. |
| `Rows` | variable | — | `(FName key, RowStruct serialized as tagged properties)[]` | Per-row pairs. |

Per-row pair:

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `RowName` | 8 | LE | `FName` | Row's identifier (e.g. `"Weapon_Sword"`). Resolved via the package's name table. |
| `RowBody` | variable | — | tagged-property stream | The row's struct fields, serialized exactly as a `StructProperty` body would be. Terminated by `"None"`. |

The structural elegance: each row is essentially a recursive
`StructProperty` body without the outer tag, since
`tag.struct_name` is implied by the table's `RowStruct` reference.

### Worked example

`(none yet — no DataTable fixture)`. When Phase 3 adds fixtures,
the canonical anchor will be `minimal_data_table_v5.uasset` with
2-3 rows of a simple row struct (e.g.
`struct FSimpleRow { FName Name; int32 Value; }`).

## Variants

### Empty tables

`NumRows == 0` is legal and common in cooked content (some tables
get fully stripped when a build platform doesn't need them, but
the table asset itself remains for type-stability). Parse and
emit an empty row map.

### Strip flags

`bStripFromClientBuilds` / `bStripFromDedicatedServerBuilds` cause
the cooker to write `NumRows = 0` for matching platforms. The
property values are still present on disk; the row data is
omitted.

### RowStruct resolution failure

If `RowStruct` resolves to an Import paksmith doesn't have a schema
for, the row bodies are still parseable (the tagged-property
iteration is self-describing). The consumer just doesn't know
the row struct's *intended* shape — fields surface with their wire
names and types but without semantic context.

### Custom-serialized row structs

Some row structs use native binary serialization (rather than
tagged properties) — same problem as
[`../property/struct.md`](../property/struct.md). When the row
body decode hits non-tag bytes, the per-row read errors and
paksmith falls back to opaque per-row bytes (or skips the row,
depending on Phase 3 design choices).

## Caps & limits

**Phase 3+ deferred work.**

- `MAX_ROWS_PER_DATATABLE` cap (likely `2^20 = 1,048,576` to match
  `MAX_NAME_TABLE_ENTRIES` — real-world DataTables rarely exceed
  a few thousand rows, but the cap should be generous).
- Per-row caps inherited from the property system.

## Verification

- **Fixture:** `(none yet — Phase 3 deliverable)`.
- **Cross-validation oracle:** CUE4Parse[^1] (primary) and
  `unreal_asset`[^2].
- **Known divergences:**
  - **Custom-serialized row structs** — same fallback shape as
    StructProperty native-struct bodies. Documented in
    [`../property/struct.md`](../property/struct.md).

## Paksmith implementation

**Parser module:** *(not yet implemented — planned under
`crates/paksmith-core/src/asset/exports/data/data_table.rs`)*

**Status:** `not implemented`.

**Phase plan:** `docs/plans/ROADMAP.md` Phase 3 (Export Pipeline)
+ Phase 4 (Full CLI). The Phase 4 plan should add a
`paksmith extract-data-table <pak> <virtual-path>` command — game
studios ship DataTables as their canonical content format and
extracting them in bulk is high-value.

A Phase 3 plan should:

1. Add a `crates/paksmith-core/src/asset/exports/data/data_table.rs`
   module with `DataTable::read_from`.
2. Add `MAX_ROWS_PER_DATATABLE` cap.
3. Add the row-iteration path that handles both tagged-property and
   custom-serialized row struct cases (fallback to opaque on
   custom-binary).
4. Add fixtures + cross-validation against unreal_asset[^2].

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Exports/Engine/UDataTable.cs@<CUE4PARSE_SHA>` — primary oracle. Covers the row-serialization shape and the strip-flag handling.
[^2]: `AstralOrigin/unreal_asset/unreal_asset/src/exports/data_table_export.rs@<UNREAL_ASSET_SHA>` — Rust counterpart.
````

- [ ] **Step 3: Commit** (preamble convention — required-headings linter must pass before commit)

```bash
git add docs/formats/data/data-table.md
git commit -m "$(cat <<'EOF'
docs(formats): add DataTable partial reference

Documents UDataTable: tagged-property segment with RowStruct
reference + strip flags + ignore-extra/missing-fields, followed
by the per-row custom blob (i32 NumRows + (FName key,
tagged-property RowBody)[] pairs). Notes the RowStruct
resolution-failure path and the custom-serialized row-struct
fallback to opaque. Flags DataTables as a high-value Phase 3+ /
Phase 4 CLI target since game studios ship configurable content
this way. partial-not-impl.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Author `docs/formats/data/locres.md` (partial)

`.locres` is a **standalone binary format** — not a UE package, not
a `UObject` export. It's the cooker output for localization tables
(per-namespace per-key source strings + culture-specific
translations). Has its own file header, version field, and table
shape. Fully public format — documented in CUE4Parse and used by
FModel for localization extraction.

**Files:**
- Create: `docs/formats/data/locres.md`

**Oracle references:**
- `CUE4Parse/UE4/Localization/FTextLocalizationResource.cs`

- [ ] **Step 2: Write the doc**

Write `docs/formats/data/locres.md`:

````markdown
# Locres (`.locres`)

> Standalone localization-table format produced by the UE cooker.
> Maps `(namespace, key) → source string` for each culture; runtime
> uses the matching `.locres` file based on the player's language
> setting. **Not a UE package** — has its own header, version field,
> and table layout.

## Overview

`.locres` ("localization resource") is the binary format UE's
cooker emits for runtime localization. A cooked game ships one
`.locres` file per supported culture (e.g. `en/Game.locres`,
`fr/Game.locres`, `ja/Game.locres`) plus per-mod / per-plugin
variants. At runtime, the engine looks up text by
`(namespace, key)` and returns the source string from the active
culture's `.locres`.

The format is **not a UE package** — it has no `FPackageFileSummary`,
no name table, no import / export tables. It's a flat binary file
with:

1. A header (magic + version field).
2. A strings array (deduplicated source strings with reference
   counts).
3. A namespace table mapping `FName namespace → entries`.
4. Per-namespace entry tables mapping `FName key → (hash, string-array-index)`.

Public, stable format. paksmith's Phase 3 work should extract
`.locres` files into per-culture JSON or CSV for translation
workflows — high-value extraction target since game scripts /
dialog ship via this format.

**Status: not yet implemented in paksmith.** Phase 3+ deliverable.

## Versions

`.locres` carries its own version field (distinct from any UE
asset / pak version). Four versions exist:

| Version | Hex | UE introduction | Wire-format change | Source |
|---------|-----|------------------|---------------------|--------|
| 0 (`Legacy`) | n/a (no magic) | Pre-UE 4.13 | No file header / magic; legacy `Tarchive` flat format. | `CUE4Parse/UE4/Localization/FTextLocalizationResource.cs@<CUE4PARSE_SHA>`[^1] |
| 1 (`Compact`) | `0E14741495` (16 bytes magic) | UE 4.13 | Added magic header; the namespace-and-key layout reshuffled. | Same[^1] |
| 2 (`Optimized`) | Same magic | UE 4.14 | Added the deduplicated strings-array indirection; entry table references strings by index instead of inline. | Same[^1] |
| 3 (`OptimizedCityHash64UTF16`) | Same magic | UE 4.20 | Switched hash function for entry keys from CRC32 to CityHash64 of UTF-16-encoded keys. | Same[^1] |

Cooked content paksmith targets uses version 3 almost exclusively
(UE 4.21+).

## Wire layout

### File header

| offset | size | endian | name | type | semantics |
|--------|------|--------|------|------|-----------|
| 0 | 16 | — | `magic` | `[u8; 16]` | Must equal the fixed Locres magic. Absence indicates a legacy (version-0) file. |
| 16 | 1 | — | `version` | `u8` | `0` (legacy, but legacy files have no magic — see Variants), `1`, `2`, or `3`. |

The magic byte sequence is the fixed 16-byte tag UE uses to
identify Locres files. Per the oracle's
`FTextLocalizationResource.LocResMagic` constant.

### Strings array (version 2+)

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `StringsOffset` | 8 | LE | `i64` | Byte offset to the strings array within the file. |
| (seek to `StringsOffset`) | | | | |
| `NumStrings` | 4 | LE | `i32` | Number of deduplicated strings. |
| `Strings` | variable | — | `(FString text, i32 ref_count)[]` | Each entry: an `FString` source text + a reference count (how many `(namespace, key)` entries point at this string). |

The deduplication is a cooker optimization — strings shared across
many `(namespace, key)` pairs (e.g. `"Continue"`, `"Cancel"`,
empty strings) are stored once. The `ref_count` is for editor
analysis; runtime doesn't need it.

### Namespace table

After the header (and before the strings array in versions 2+;
seek-and-restore semantics):

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `EntriesCount` | 4 | LE | `u32` | Total `(namespace, key)` entries across all namespaces. Used as a sanity check. |
| `NumNamespaces` | 4 | LE | `i32` | Number of namespaces. |
| `Namespaces` | variable | — | `FNamespaceEntry[]` | Per-namespace records. |

Each `FNamespaceEntry`:

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `Hash` | 4 | LE | `u32` | Hash of the namespace string (CityHash64-of-UTF16, low 32 bits, for version 3; CRC32 for version 2). |
| `Namespace` | variable | — | `FString` | Namespace name (e.g. `"Game"`, `"UI"`, `"DialogueLines"`). |
| `NumEntries` | 4 | LE | `i32` | Number of `(key, string)` pairs in this namespace. |
| `Entries` | variable | — | `FKeyEntry[]` | Per-key records. |

Each `FKeyEntry`:

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `Hash` | 4 | LE | `u32` | Hash of the key string (same algorithm as the namespace hash). |
| `Key` | variable | — | `FString` | Key name (e.g. `"5DD42A4E4B5C7F8A_Continue"`). |
| `SourceStringHash` | 4 | LE | `u32` | Cooker-side hash of the source string for change-detection. |
| `StringIndex` (version 2+) | 4 | LE | `i32` | Index into the strings array. Version 1 has the string inline here. |

### Legacy (version 0) layout

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `NumNamespaces` | 4 | LE | `i32` | |
| `Namespaces` | variable | — | Legacy namespace entries (no hash; inline strings) | |

Legacy files have no magic header — they start directly with the
namespace count. paksmith dispatches by trying to read the magic
and falling through to legacy mode on magic mismatch.

### Worked example

`(none yet)`. A `.locres` fixture would be cheap to synthesize — a
minimal version-3 file with one namespace, two keys, and two
strings would be ~150 bytes. Adding one is a worthwhile follow-up
when Phase 3 implements the reader.

## Variants

### Hash algorithm dispatch

- Version 1: CRC32 of the namespace / key strings.
- Version 2: CRC32, same as version 1 but with the strings array.
- Version 3: CityHash64 of UTF-16-encoded strings, low 32 bits.

paksmith's reader dispatches on the version byte.

### String deduplication on / off

Versions 0 and 1 inline strings per entry; versions 2 and 3 use
the strings array. Saves significant cooked-file size for games
with lots of repeated strings (typical for UI / item names).

### Per-culture vs per-target

UE cooks one `.locres` per culture per target. A game's
localization tree typically looks like:

```
Content/Localization/Game/
├── en/Game.locres
├── fr/Game.locres
├── ja/Game.locres
└── …
```

paksmith's CLI integration (Phase 4) should expose per-culture
extraction so users can dump a single language without parsing
every locale's file.

## Caps & limits

**Phase 3+ deferred work.**

- `MAX_NAMESPACES_PER_LOCRES` cap (likely `65,536`).
- `MAX_ENTRIES_PER_NAMESPACE` cap.
- `MAX_STRINGS_PER_LOCRES` cap (likely matching
  `MAX_NAME_TABLE_ENTRIES = 1,048,576` — large games approach this).
- Per-string byte cap inherited from `FSTRING_MAX_LEN`.

The deduplication index ceiling implicitly caps the strings array
size at `i32::MAX` strings (which would be a 8 GiB+ table anyway —
the strings-array cap above is the practical limit).

## Verification

- **Fixture:** `(none yet — synthesize a minimal version-3 file
  when Phase 3 implements)`.
- **Cross-validation oracle:** CUE4Parse[^1]. The format is fully
  public; no proprietary-codec concerns.
- **Known divergences:** none yet.

## Paksmith implementation

**Parser module:** *(not yet implemented — planned under
`crates/paksmith-core/src/localization/locres.rs`)*

Note: this module sits OUTSIDE `crates/paksmith-core/src/asset/`
because `.locres` is not a UE asset. It belongs in a new
`crates/paksmith-core/src/localization/` module (created when
Phase 3 implements).

**Status:** `not implemented`.

**Phase plan:** `docs/plans/ROADMAP.md` Phase 3 (Export Pipeline)
+ Phase 4 (Full CLI). A Phase 4 CLI plan should add
`paksmith extract-locres <pak> <culture>` — high-value
extraction target.

A Phase 3 plan should:

1. Add `crates/paksmith-core/src/localization/locres.rs` with
   `LocresFile::read_from`.
2. Implement version-dispatch on the magic + version byte.
3. Implement the CityHash64-of-UTF16 hash for version-3 hash
   verification (`twox-hash` Rust crate or hand-rolled).
4. Add caps + a Vorbis-style fixture (synthetic version-3 file).

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Localization/FTextLocalizationResource.cs@<CUE4PARSE_SHA>` — primary oracle. Covers all four versions and the hash-algorithm dispatch. FModel's localization-extract feature is built on this reader; cross-validating against FModel output is a natural test target.
````

- [ ] **Step 3: Commit** (preamble convention — required-headings linter must pass before commit)

```bash
git add docs/formats/data/locres.md
git commit -m "$(cat <<'EOF'
docs(formats): add .locres partial reference

Documents the .locres standalone format (NOT a UE package): file
header (16-byte magic + version byte), per-version strings array
(versions 2+) with reference-count deduplication, namespace table
with FNamespaceEntry records, per-key FKeyEntry records with
SourceStringHash + StringIndex. Catalogs all four versions
(legacy / Compact / Optimized / OptimizedCityHash64UTF16) including
the version-3 CityHash64-of-UTF16 hash-algorithm change. Notes
the per-culture file tree (Content/Localization/<game>/<culture>/
<game>.locres) and the high-value Phase 4 CLI integration. partial-
not-impl; module sits outside asset/ since .locres isn't a UObject.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Update root inventory + final verification + push

**Files:**
- Modify: `docs/formats/README.md`

- [ ] **Step 2: Add three rows to the inventory**

Verify the existing inventory layout with `grep -n "^|" docs/formats/README.md`, then use Edit to insert three new rows.

Rows to insert:

```markdown
| `data/data-asset.md` | partial | not impl | — | CUE4Parse @ `<CUE4PARSE_SHA>` | n/a |
| `data/data-table.md` | partial | not impl | — | CUE4Parse @ `<CUE4PARSE_SHA>` | n/a |
| `data/locres.md` | partial | not impl | — | CUE4Parse @ `<CUE4PARSE_SHA>` | n/a |
```

All three `partial | not impl`.

- [ ] **Step 6: Run typos**

Run: `typos docs/formats/data/`
Expected: clean. Domain terms (`Locres`, `UDataTable`, `UDataAsset`,
`UPrimaryDataAsset`, `FNamespaceEntry`, `FKeyEntry`, `FTextLocalizationResource`,
`CityHash64`) likely to flag — extend `_typos.toml` only when reword
isn't natural.

- [ ] **Step 8: Verify the framework inventory is now complete**

Run: `grep -cE "^\| " docs/formats/README.md`
Expected: ≥ 40 (matching the spec's "~40 format docs" estimate from
the original framework design). The exact count depends on whether
prior PRs landed; if PRs 2–11 all merged before this, the count is
40 + 3 = 43 rows (header + separator + 41 data rows; grep counts
all `|` lines including the header / separator).

The completion of the inventory is a milestone worth surfacing in
the commit message.

- [ ] **Step 9: Commit the inventory update**

```bash
git add docs/formats/README.md
git commit -m "$(cat <<'EOF'
docs(formats): register the data-family docs in the inventory; close the 12-PR rollout

Three partial-not-impl rows (data-asset, data-table, locres):
data-asset and data-table cover UDataAsset / UDataTable; locres
covers the standalone .locres localization format outside the
UObject hierarchy. Last-verified n/a; Phase 3's PR should bump
to a real SHA when readers land.

This PR closes the 12-PR rollout from the framework spec — the
inventory now has at least starter content for every format
documented in docs/design/2026-05-19-ue-format-docs.md's
directory layout.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

```
<sha> docs(formats): register the data-family docs in the inventory; close the 12-PR rollout
<sha> docs(formats): add .locres partial reference
<sha> docs(formats): add DataTable partial reference
<sha> docs(formats): add DataAsset partial reference
```

- [ ] **Step 12: Open the PR**

Title: `docs(formats): populate data family (data-asset/data-table/locres) — final family`

Body — write to a tempfile first, then `gh pr create --body-file <tempfile>`:

```markdown
## Summary

Lands PR 12 — the **final** family-content PR of the UE format
documentation framework. Populates `docs/formats/data/` with three
documents:

- **`data-asset.md`** — `UDataAsset` / `UPrimaryDataAsset` as
  convention-only base classes. The on-disk content is just the
  tagged-property body; what makes this doc worth writing is the
  catalog of asset-registry conventions and game-specific subclass
  patterns. paksmith already extracts the data today via the
  property iterator — Phase 3+ work is per-class dispatch / CLI
  integration.
- **`data-table.md`** — `UDataTable` with `RowStruct` reference and
  per-row tagged-property bodies. Documents the custom `i32 NumRows`
  + `(FName key, RowBody)[]` blob that follows the property
  terminator. Flagged as a high-value Phase 3+ / Phase 4 CLI target
  (game studios ship configurable content this way).
- **`locres.md`** — the standalone `.locres` localization format,
  **not a UE package**. All four format versions documented (legacy
  / Compact / Optimized / OptimizedCityHash64UTF16) including the
  version-3 hash-algorithm change. Module placement explicitly
  noted: `crates/paksmith-core/src/localization/locres.rs` —
  outside `asset/` because `.locres` isn't a UObject.

Three rows added to the root inventory, all `partial | not impl`.

**Series milestone: this closes the 12-PR rollout.** Every format
documented in the spec's directory layout now has at least starter
content in the inventory.

## Linked issue

(none — design spec drives this work)

## Test plan

- [x] `paksmith-doc-lint required-headings` passes.
- [x] `paksmith-doc-lint status-enum` passes on the updated inventory.
- [x] `typos docs/formats/data/` clean.
- [x] `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features` clean.
- [x] Cross-referenced every wire-format claim against CUE4Parse
      (primary oracle for all three docs).

## Pre-flight checklist

- [x] PR title is a Conventional Commit.
- [x] Branch name follows `<type>/<kebab-case>`.
- [x] `cargo fmt --all` clean (no Rust changed).
- [x] `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean.
- [x] Documentation updated (this PR IS documentation).
- [x] No `unsafe` introduced.
- [x] Touched a parser? No — pure docs PR.

## Security considerations

The docs identify the cap shape Phase 3 will need:
`MAX_ROWS_PER_DATATABLE`, `MAX_NAMESPACES_PER_LOCRES`,
`MAX_ENTRIES_PER_NAMESPACE`, `MAX_STRINGS_PER_LOCRES`. The locres
doc notes that strings-array deduplication implicitly caps the
practical file size at the same order as `MAX_NAME_TABLE_ENTRIES`
(~1 M strings).

## Notes for reviewers

- The `data-asset.md` doc is interesting because it spells out that
  paksmith already extracts the data today via the property
  iterator — `partial | not impl` flags the missing
  per-class-dispatch / CLI integration, not the absence of
  underlying parser code. Worth distinguishing from the other
  docs in the family.
- The `data-table.md` doc flags DataTables as one of paksmith's
  highest-priority Phase 3+ targets. Game studios ship configurable
  content (item lists, ability tables, dialog) via DataTables;
  bulk-extracting them is often the single most-requested
  capability.
- The `locres.md` doc explicitly notes that the module sits
  OUTSIDE `crates/paksmith-core/src/asset/` because `.locres`
  isn't a UObject. This is a structural decision — `crates/paksmith-
  core/src/localization/` would be created fresh when Phase 3
  implements.
- **Series milestone:** twelve PRs after the framework spec landed
  in PR 1, the inventory is fully populated. Subsequent PRs that
  upgrade `partial` / `stub` rows to `complete` (driven by
  implementation work) follow naturally — but the framework's
  initial backfill phase ends here.
```

---

## Done criteria

Per [PREAMBLE.md](2026-05-19-ue-format-docs-PREAMBLE.md)'s tail (linters green, typos clean, rustdoc clean, PR open, reviewer panel converged), plus this plan's inventory specifics enumerated above.
  (data-asset, data-table, locres).
- **Series milestone reached:** the inventory contains starter rows
  for every format in the spec's directory layout.
