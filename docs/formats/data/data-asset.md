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
iterator already extracts all the data. What this doc does spell
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
| UE 4.0+ | `UDataAsset` introduced as a `UObject` subclass. Wire shape is the tagged-property body — version conditionals on individual properties apply, but no class-specific wire-format break has occurred. | No specialized reader exists in the oracle — convention only.[^1] |
| UE 4.12+ | `UPrimaryDataAsset` added as subclass; adds `PrimaryAssetType` and `PrimaryAssetName` tag conventions for the asset-registry. | Same — no specialized oracle reader.[^1] |

## Wire layout

### Segment 1 — tagged-property stream

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
[`../property/primitives.md`](../property/primitives.md),
[`../property/containers.md`](../property/containers.md), and
[`../property/struct.md`](../property/struct.md).

### Segment 2 — none

There is no segment 2. `UDataAsset` adds nothing past the property
terminator. The post-terminator `serial_size` boundary should match
exactly.

### Worked example

`(none yet — Phase 3 deliverable)`. Any of the existing
`tests/fixtures/` UAsset fixtures can serve as a structural anchor
since the wire shape is just the property body.

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

- `MAX_PROPERTY_TAG_SIZE` per individual property.
- `MAX_TAGS_PER_EXPORT` per export.
- `MAX_PROPERTY_DEPTH` recursive depth.
- `MAX_COLLECTION_ELEMENTS` for array / map / set properties.

See [`../property/tagged.md`](../property/tagged.md) and the
caps section of each property-family doc.

## Verification

- **Fixture:** `(none yet)`. The existing UAsset fixtures are a
  structural proxy — property iteration exercises the same codepath
  any DataAsset would use.
- **Hex anchor commands:** `(none yet — Phase 3 deliverable)`.
- **Cross-validation oracle:** No specialized `UDataAsset` reader
  exists in CUE4Parse at this SHA — same convention-only treatment.
  See the Engine/ directory listing[^1].
- **Known divergences:** none yet.

## Paksmith implementation

**Parser module:** none specific. DataAsset extraction reuses the
existing property iteration in `crates/paksmith-core/src/asset/property/`.

**Status:** `not impl` (no specialized reader / dispatch).
The data itself IS extracted by the property iterator.

**Phase plan:** See `docs/plans/ROADMAP.md` for the Phase 3 and
Phase 4 work that will add per-class dispatch and CLI integration.

## References

[^1]: The CUE4Parse oracle at `cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` contains no `UDataAsset.cs` or `UPrimaryDataAsset.cs` in `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Exports/Engine/` — the class adds nothing beyond the property iteration, so no specialized reader is warranted. The neighboring `UDataTable.cs` in the same directory illustrates the pattern for classes that *do* add post-property blob data.
