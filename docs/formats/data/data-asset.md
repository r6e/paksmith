# DataAsset (`UDataAsset` / `UPrimaryDataAsset`)

> UE base class for pure-data assets — no runtime behavior, just a
> tagged-property body. On disk, indistinguishable from any other
> `UObject` export. This doc documents the **convention** rather
> than a distinct wire format.

## Overview

`UDataAsset` is UE's convention for "this asset is pure data — its
purpose is to hold values, not execute logic." The class adds no
on-disk wire shape beyond the standard tagged-property iteration
covered in [`../property/tagged.md`](../property/tagged.md): a
`UDataAsset` export body is just a property tree terminated by the
`"None"` tag. No segment 2, no custom blob, no post-property bytes.

What makes `UDataAsset` worth a dedicated doc is the **convention
ecosystem** around it:

- **`UPrimaryDataAsset`** — subclass adding asset-registry tags so
  the engine's primary-asset system can discover instances at
  runtime. The wire shape adds nothing — the asset-registry
  integration happens via the standard `AssetRegistryData` summary
  field (see [`../asset/uasset.md`](../asset/uasset.md)).
- **Game-specific subclasses** — most cooked games derive their own
  classes (`UWeaponDataAsset`, `UCharacterStatsDataAsset`,
  `UItemDefinition`, etc.). Each is a `UObject` export with a
  class-specific set of properties; the wire shape is the union of
  the parent class's properties plus the subclass's additions.

A reader does not need a per-subclass module — the standard
tagged-property iterator extracts every field as a typed
`PropertyValue::*`. What a DataAsset reader DOES need is class-name
dispatch (to recognize these exports for CLI commands like "list all
DataAssets") and import-resolution rigor (DataAssets routinely
reference other DataAssets via `ObjectProperty`).

**Document status: complete.** The format is fully specified by
cross-reference to [`../property/tagged.md`](../property/tagged.md)
and [`../asset/uasset.md`](../asset/uasset.md) — there is no
DataAsset-specific wire shape to specify beyond the convention
itself. This doc is also "complete" in a stricter sense than
formats with their own wire shape: anything more would be
documenting `property/tagged.md` and `asset/uasset.md` content
twice.

**Paksmith parser status: not yet implemented** *as a specialized
reader*. The data IS already extracted today — the property
iterator surfaces every field as a `PropertyValue::*`. What's
not implemented is the per-class dispatch / CLI integration that
would make DataAsset extraction a first-class command. Phase 3+.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| UE 4.0+ | `UDataAsset` introduced as a `UObject` subclass. Wire shape is the tagged-property body — version conditionals on individual properties apply, but no class-specific wire-format break has occurred. | No specialized reader in the oracle — convention only.[^1] |
| UE 4.12+ | `UPrimaryDataAsset` added as subclass; adds `PrimaryAssetType` and `PrimaryAssetName` tag conventions for the asset-registry. | Same — no specialized oracle reader.[^1] |

The "no class-specific wire-format break" claim is validated by the
absence of `UDataAsset.cs` or `UPrimaryDataAsset.cs` in the
CUE4Parse oracle at the cited SHA — neither class needs custom
deserialization logic.

## Wire layout

### Segment 1: tagged-property stream

The entire on-disk content of a `UDataAsset` is one tagged-property
sequence terminated by `"None"`. See
[`../property/tagged.md`](../property/tagged.md) for the iteration
mechanics — every detail there applies verbatim.

Common properties on `UPrimaryDataAsset`:

| Property name | Type | Semantics |
|---------------|------|-----------|
| `PrimaryAssetType` | `StructProperty(FPrimaryAssetType)` | Asset-registry-side type identifier (e.g. `Weapon`, `Ability`). |
| `PrimaryAssetName` | `StructProperty(FPrimaryAssetName)` | Asset-registry-side instance identifier (e.g. `WeaponSword`). |

Game-specific subclass properties are arbitrary — any combination
of the property types catalogued in
[`../property/primitives.md`](../property/primitives.md),
[`../property/containers.md`](../property/containers.md), and
[`../property/struct.md`](../property/struct.md).

### Segment 2: none

There is no segment 2. `UDataAsset` adds nothing past the property
terminator. The post-terminator `serial_size` boundary (recorded
in the export-table entry per
[`../asset/uasset.md`](../asset/uasset.md)) MUST match the
property-iterator's stopping position exactly. A mismatch indicates
either file corruption or a class-specific post-property blob the
parser doesn't know how to skip — in either case the reader MUST
reject the export rather than silently emit a truncated property
bag.

This is the structural distinction between DataAsset and DataTable
([`data-table.md`](data-table.md)): DataAsset has only segment 1;
DataTable has segment 1 + a custom row blob in segment 2.

### Worked example

Any existing UAsset fixture in `tests/fixtures/` exercises the same
property-iteration codepath any DataAsset would use, since DataAsset
adds no class-specific wire content. The
`tests/fixtures/minimal_uasset_v5_with_properties.uasset` fixture
is the canonical "tagged-property body" example.

The property segment within any UObject export starts at the
export's `serial_offset` (recorded in the export-table entry from
the package summary) and runs through to the `"None"` tag. For
fixture-specific property bytes, decode the package summary first
to locate the export's `serial_offset`, then walk per
[`../property/tagged.md`](../property/tagged.md). Worked-example
byte walks for specific property types live in their respective
property-family docs ([`../property/primitives.md`](../property/primitives.md),
[`../property/containers.md`](../property/containers.md),
[`../property/struct.md`](../property/struct.md)) — DataAsset
inherits those examples wholesale.

A "DataAsset-specific" hex walk would just be a property-segment
walk with a comment that the containing class happens to be
`UDataAsset` — no DataAsset-specific bytes to anchor against.

## Variants

### `UPrimaryDataAsset` vs `UDataAsset`

`UPrimaryDataAsset` adds the two asset-registry properties shown
above but no wire-format break. Distinguishable by class name in
the import table (the export's `class_index` resolves to
`/Script/Engine.PrimaryDataAsset` vs `/Script/Engine.DataAsset`).

### Game-specific subclasses

Game-specific subclasses surface as `class_index` resolutions to
custom paths (`/Game/Code/WeaponDataAsset.WeaponDataAsset_C` etc.).
A reader treats them as opaque subclasses of `UDataAsset` for
extraction purposes — the per-game schema is the consumer's
responsibility.

### Data-asset references

DataAssets routinely reference other DataAssets (a weapon's
`AmmoType` is itself a DataAsset). These appear as `ObjectProperty`
or `SoftObjectProperty` values resolving through the import table.
The `Object` / `SoftObjectPath` PropertyValue variants surface the
references with the import-table path intact for the consumer to
follow.

## Caps & limits

### Format-defined limits (wire-imposed)

DataAsset inherits all format-defined limits from the tagged-property
system, since it has no wire shape of its own:

- `FName` index bounds: per [`../primitive/fname.md`](../primitive/fname.md).
- `FString` length: `i32` per [`../primitive/fstring.md`](../primitive/fstring.md).
- Property tag `size: i32` per [`../property/tagged.md`](../property/tagged.md).

The property tree's nesting depth is NOT format-imposed — the wire
format permits arbitrary recursion via nested `StructProperty` /
`ArrayProperty` / `MapProperty` / `SetProperty`. Depth bounding is
strictly an implementation-hardening concern (see below).

No DataAsset-specific wire-imposed limit exists.

### Implementation hardening (recommended for any parser)

Property-system hardening applies wholesale — see
[`../property/tagged.md`](../property/tagged.md) Caps & limits for
the cross-format invariants (signed-i32 cast safety, FName index
bounds, etc.). DataAsset-specific additions:

- **Class-name recognition**: A robust DataAsset-extraction tool
  SHOULD recognize all known subclasses (`UDataAsset`,
  `UPrimaryDataAsset`, and any project-configured subclasses) by
  `class_index` resolution against the import table. The path
  format `/Script/Engine.DataAsset` (engine base) vs
  `/Game/...` (project-derived) distinguishes engine subclasses
  from project ones.
- **Reference-chain depth**: A DataAsset that references other
  DataAssets via `ObjectProperty` can form arbitrarily deep
  reference chains. A consumer that recursively materializes the
  referenced assets MUST bound the recursion depth (e.g.,
  `MAX_DATAASSET_REFERENCE_DEPTH = 16`) to prevent stack overflow
  on cyclic or pathologically deep reference graphs.
- **Reference-chain fan-out**: depth bounding alone doesn't cover
  the width-explosion case — a single DataAsset with 100
  `ObjectProperty` fields each pointing to a different DataAsset
  triggers O(N) pak reads for an eager bulk-export consumer
  (e.g., a `paksmith export --data-assets` CLI command). A robust
  consumer SHOULD additionally bound total-references-visited
  (e.g., `MAX_DATAASSET_REFERENCES_PER_EXPORT = 4096`) and
  rate-limit pak I/O during recursive walks.

## Verification

- **Fixture:** any existing UAsset fixture in `tests/fixtures/`
  exercises the same property-iteration codepath. The canonical
  property-bearing example is
  `tests/fixtures/minimal_uasset_v5_with_properties.uasset`.
  No DataAsset-specific fixture exists or is needed — DataAsset
  has no wire shape distinct from its containing UObject.
- **Hex anchor commands:**
  ```
  # Dump full file:
  xxd tests/fixtures/minimal_uasset_v5_with_properties.uasset

  # Property iteration bytes per ../property/tagged.md — locate
  # export's serial_offset by walking the package summary +
  # export table first, then walk properties from that offset.
  ```
- **Cross-validation oracle:** No specialized `UDataAsset` reader
  exists in CUE4Parse at the cited SHA — verified by listing
  `CUE4Parse/UE4/Assets/Exports/Engine/` (contains `UDataTable.cs`,
  `UCurveTable.cs`, etc., but no `UDataAsset.cs` /
  `UPrimaryDataAsset.cs`).[^1] The convention-only treatment is
  the correct documentation strategy.
- **Known divergences:** None. The format spec is the property-system
  spec.

## Paksmith implementation

**Parser module:** none specific. DataAsset extraction reuses the
existing property iteration in
`crates/paksmith-core/src/asset/property/`.

**Parser status:** `not impl` (no specialized reader / dispatch).
The data itself IS extracted by the property iterator.

**Phase plan:** see `docs/plans/ROADMAP.md` for the Phase 3 work
that adds per-class dispatch and the Phase 4 CLI integration
("`paksmith ls --class UDataAsset`" / "`paksmith export
--data-assets`").

## References

[^1]: The CUE4Parse oracle at `cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` contains no `UDataAsset.cs` or `UPrimaryDataAsset.cs` in `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Exports/Engine/` (verified via directory listing; 12 files present, none for DataAsset). The class adds nothing beyond the property iteration, so no specialized reader is warranted. The neighboring `UDataTable.cs` in the same directory illustrates the pattern for classes that *do* add post-property blob data.
