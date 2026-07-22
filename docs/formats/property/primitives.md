# Primitive property types

> Property types whose body is a fixed shape decoded in place — no
> sub-property iteration, no struct recursion, no text history. Covers
> roughly two-thirds of the property types in a typical cooked asset.

## Overview

After the `FPropertyTag` header (see [`tagged.md`](tagged.md)), each
property body has a per-type wire shape. The primitive types — `Int`,
`Float`, `Bool`, `Name`, `Str`, `Enum`, `Object`, `SoftObject` — all
decode in a single read with no recursion. This doc enumerates them
and their wire shapes; recursive types (Array, Map, Set, Struct, Text)
live in sibling docs.

Paksmith's `PropertyValue` enum is the parser-side surface; each
variant below maps to one or more UE property types. The names match
CUE4Parse's `FProperty` subclass names for cross-reference.

**Document status: complete.** Wire format documented in full for
the primitive property types: `BoolProperty` (zero-body, value in
tag-extras), integer family (`Int8` / `Int16` / `Int` / `Int64` +
`Byte` / `UInt16` / `UInt32` / `UInt64`), floating-point (`Float` /
`Double`), string types (`StrProperty` FString-bodied + `NameProperty`
FName-bodied), enum dispatch (`EnumProperty` + `ByteProperty` with
`tag.enum_name` set), `ObjectProperty` `FPackageIndex`-keyed,
soft-reference types (`SoftObjectProperty` / `SoftClassProperty`,
including the UE5 ≥ 1007 `FTopLevelAssetPath` layout), and the
`Unknown { type_name, skipped_bytes }` fallback. The UE5 ≥ 1008
index-serialized SoftObject form is fail-closed — see
§*Known divergences*.

**Paksmith parser status: `complete`.** Phase 2b / 2d deliverable;
ships as `paksmith-core/src/asset/property/primitives.rs`.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| `FileVersionUE4 ≥ 504` | All primitive shapes stable. | `CUE4Parse/UE4/Assets/Objects/Properties/*.cs@ecc4878950336126f125af0747190edf474b2a21`[^1] |
| `FileVersionUE5 ≥ 1007` | `SoftObjectProperty` / `SoftClassProperty` wire shape changes (`FTopLevelAssetPath` replaces the leading FName). | Same[^1] |
| `FileVersionUE5 ≥ 1008` | `SoftObjectProperty` becomes an `i32` index into the summary's `SoftObjectPaths` list. | Same[^1] |

Paksmith decodes the UE5 ≥ 1007 `FTopLevelAssetPath` form inline
(PackageName FName + AssetName FName, joined `Package.Asset`). The UE5
≥ 1008 index-serialized encoding — a leading `i32` index into the
summary's `SoftObjectPaths` list — is fail-closed with
`AssetParseFault::UnsupportedSoftObjectPathLayout { ue5_version }`
rather than mis-decoded. That form is gated by
`!PKG_FilterEditorOnly && soft_object_paths_count > 0` and is
unreachable for any well-formed cooked asset (uncooked assets are
rejected at the summary boundary), so it only fires for a
version-inconsistent crafted asset.

## Wire layout

### Boolean (`BoolProperty`)

BoolProperty wire body is zero bytes; the boolean value is carried in `tag.bool_val` — see [`tagged.md`](tagged.md) §*Type extras dispatch*.

### Integer types

| `Type` (FName) | Body bytes | LE? | `PropertyValue` variant |
|----------------|------------|-----|--------------------------|
| `Int8Property` | 1 | — | `Int8(i8)` |
| `ByteProperty` (tag.enum_name is `""` or `"None"`) | 1 | — | `Byte(u8)` |
| `Int16Property` | 2 | LE | `Int16(i16)` |
| `UInt16Property` | 2 | LE | `UInt16(u16)` |
| `IntProperty` | 4 | LE | `Int(i32)` |
| `UInt32Property` | 4 | LE | `UInt32(u32)` |
| `Int64Property` | 8 | LE | `Int64(i64)` |
| `UInt64Property` | 8 | LE | `UInt64(u64)` |

### Floating-point types

| `Type` (FName) | Body bytes | `PropertyValue` variant |
|----------------|------------|--------------------------|
| `FloatProperty` | 4 | `Float(f32)` |
| `DoubleProperty` | 8 | `Double(f64)` |

### String types

| `Type` (FName) | Body wire shape | `PropertyValue` variant |
|----------------|-----------------|--------------------------|
| `StrProperty` | `FString`[^2] | `Str(String)` |
| `NameProperty` | `FName`[^3] (8 bytes: index + number) resolved at parse time | `Name(String)` |

### Enum types

| `Type` (FName) | Body wire shape | `PropertyValue` variant |
|----------------|-----------------|--------------------------|
| `EnumProperty` (tag.enum_name set) | `FName` value | `Enum { type_name, value }` where `type_name = tag.enum_name`, `value = resolved FName` |
| `ByteProperty` (tag.enum_name not `""` or `"None"`) | `FName` value | Same — `Enum { type_name, value }` |

`Enum.type_name` may be empty if the upstream encoder omitted
`tag.enum_name` for an `EnumProperty`. The wire is still consumable
(the variant FName is still present); the variant doc on
`PropertyValue::Enum` calls this out.

### Object reference (`ObjectProperty`)

Wire body: 4 bytes (`i32` decoded as `FPackageIndex`[^4]).

| `PackageIndex` decode | `PropertyValue::Object` |
|------------------------|--------------------------|
| `0` → `Null` | `Object { kind: Null, name: "" }` |
| `n > 0` → `Export(n-1)` | `Object { kind: Export(idx), name: <resolved object_name> }` |
| `n < 0`, `n > i32::MIN` → `Import(-n-1)` | `Object { kind: Import(idx), name: <resolved object_name> }` |
| `i32::MIN` | **Reject** — `AssetParseFault::PackageIndexUnderflow { field: ObjectPropertyIndex }` |

The resolved `name` is the bare FName (not the `<package>.<object>`
form) from the import or export table's `object_name` slot. Empty for
`Null`; out-of-bounds export/import indices surface as
`AssetParseFault::PackageIndexOob`.

### Soft references

Wire body (UE4 / UE5 < 1007): `FName asset_path` (8 bytes) + `FString
sub_path`. At UE5 ≥ 1007 the leading slot is an `FTopLevelAssetPath`
(PackageName FName + AssetName FName, 16 bytes), which paksmith joins to
the same `Package.Asset` string the single-FName form produced, per
`FTopLevelAssetPath::ToString`: empty **only** when PackageName is
`None`; PackageName alone (no trailing dot) when AssetName is `None`;
otherwise `Package.Asset`. The UE5 ≥ 1008 index-serialized form is
fail-closed (see the *Versions* note above).

| `Type` (FName) | `PropertyValue` variant |
|----------------|--------------------------|
| `SoftObjectProperty` | `SoftObjectPath { asset_path, sub_path }` |
| `SoftClassProperty` | `SoftClassPath { asset_path, sub_path }` |

`sub_path` is usually empty in cooked assets (the `.SubObject`
component of `/Game/Path.MainObject.SubObject`).

### Unknown / skipped (`Unknown`)

Any type the primitive reader doesn't recognize and the container /
struct / text readers also don't claim. The body is skipped via
`tag.size` and the value surfaces as `Unknown { type_name, skipped_bytes }`.

### Worked example

*(none yet — pending fixture-stability follow-up; the precise offset depends on per-export layout. A primitive-focused fixture is tracked in [#347](https://github.com/r6e/paksmith/issues/347).)*

## Variants

Each primitive's per-version wire shape and dispatch rules live in
Wire layout above; the table cells call out the variants inline
(`ByteProperty`'s raw-u8 vs FName dispatch on `tag.enum_name`,
`EnumProperty`'s permissive empty-`type_name` decode, `ObjectProperty`'s
`i32::MIN` rejection at the FPackageIndex layer — see
[`../primitive/fpackage-index.md`](../primitive/fpackage-index.md)).

## Caps & limits

### Format-defined limits (wire-imposed)

- Per-type body widths fixed by the Wire layout tables: `Int8` 1 byte, `Int16` / `UInt16` 2 bytes, `IntProperty` / `UInt32Property` 4 bytes, `Int64` / `UInt64` 8 bytes, `FloatProperty` 4 bytes, `DoubleProperty` 8 bytes, `BoolProperty` 0 bytes (value in tag-extras), `NameProperty` 8 bytes (`FName`), `ObjectProperty` 4 bytes (`FPackageIndex`).
- **`StrProperty` body**: `FString` per [`../primitive/fstring.md`](../primitive/fstring.md); bounded by `FSTRING_MAX_LEN = 65,536`.
- **`SoftObjectProperty` / `SoftClassProperty` body**: `FName asset_path` + `FString sub_path` (UE4 / UE5 < 1007), or `FTopLevelAssetPath` (2 FNames) + `FString sub_path` (UE5 ≥ 1007); the UE5 ≥ 1008 index-serialized form is fail-closed at parse time.

### Implementation hardening (recommended for any parser)

- **`MAX_PROPERTY_TAG_SIZE = 16 MiB`** (inherited from the tag layer).
  Bodies that declare a larger size are rejected before any allocation
  runs.
- **Per-body `try_reserve_exact`** — any allocation a primitive reader
  performs (rare; `StrProperty`'s FString reader is the main one)
  surfaces as `AssetParseFault::AllocationFailed`.
- **No collection-cap exposure** — primitive readers don't iterate.

## Verification

- **Fixtures:**
  - `tests/fixtures/minimal_uasset_v5_with_properties.uasset` —
    exercises Bool/Float/Str/Name/Enum/Object primitive types in
    a single export.
  - `tests/fixtures/minimal_uasset_v5_with_extended_types.uasset` —
    exercises Int8/Int16/UInt16/UInt32/Int64/UInt64/Double/Soft types
    added in Phase 2d.
- **Hex anchor commands:** `(none yet — see [#347](https://github.com/r6e/paksmith/issues/347))`.
- **Cross-validation oracle:** CUE4Parse[^1] and `unreal_asset`[^5].
- **Known divergences:**
  - **UE5 1008+ index-serialized SoftObjectPath.** Paksmith decodes the
    ≥ 1007 inline `FTopLevelAssetPath` form but fail-closes the ≥ 1008
    `i32`-index-into-summary-list form (it does not parse that list);
    CUE4Parse reads the index. Unreachable for well-formed cooked
    assets — see the *Versions* note ([#638](https://github.com/r6e/paksmith/issues/638)).
  - **`PackageIndex::ImportIndexUnderflow`** rejection on `i32::MIN`
    — see [`../primitive/fpackage-index.md`](../primitive/fpackage-index.md).

## Paksmith implementation

**Parser module:** `crates/paksmith-core/src/asset/property/primitives.rs`.

**Status:** `complete`.

**Public surface:**
- `pub struct Property { pub name: String, pub array_index: i32, pub guid: Option<[u8; 16]>, pub value: PropertyValue }`.
- `pub struct MapEntry { pub key: PropertyValue, pub value: PropertyValue }`.
- `pub enum PropertyValue` (`#[non_exhaustive]`) — every variant
  enumerated above.
- `pub fn read_primitive_value<R: Read + Seek>(tag: &PropertyTag, reader: &mut R, ctx: &AssetContext, asset_path: &str) -> Result<Option<PropertyValue>>` —
  returns `None` for non-primitive types (the caller falls through to
  the container/struct/text readers, then to `Unknown`).

**Error variants:**
- `AssetParseFault::UnexpectedEof { field }`.
- `AssetParseFault::UnsupportedSoftObjectPathLayout { ue5_version }`.
- `AssetParseFault::PackageIndexUnderflow { field }`.
- `AssetParseFault::PackageIndexOob { field, value }`.
- `AssetParseFault::FStringMalformed { kind }` (from `StrProperty`).

**Phase plan:**
- Core primitives: `docs/plans/phase-2b-tagged-properties.md` (Tasks 1–5).
- Extended types (Int8/16/UInt16/32/Int64/UInt64/Double/Soft):
  `docs/plans/phase-2d-extended-property-types.md`.

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Objects/Properties/*.cs@ecc4878950336126f125af0747190edf474b2a21` — per-type primary oracle.
[^2]: See [`../primitive/fstring.md`](../primitive/fstring.md).
[^3]: See [`../primitive/fname.md`](../primitive/fname.md).
[^4]: See [`../primitive/fpackage-index.md`](../primitive/fpackage-index.md).
[^5]: `AstroTechies/unrealmodding/unreal_asset/unreal_asset_properties/src/lib.rs@f4df5d8e75b1e184832384d1865f0b696b90a614` — Rust oracle; paksmith's PropertyValue surface mirrors unreal_asset's `Property` enum closely.
