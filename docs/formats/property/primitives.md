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

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| `FileVersionUE4 ≥ 504` | All primitive shapes stable. | `CUE4Parse/UE4/Assets/Objects/Properties/*.cs@ecc4878950336126f125af0747190edf474b2a21`[^1] |
| `FileVersionUE5 ≥ 1007` | `SoftObjectProperty` / `SoftClassProperty` wire shape changes (`FTopLevelAssetPath` replaces the leading FName). | Same[^1] |
| `FileVersionUE5 ≥ 1008` | `SoftObjectProperty` becomes an `i32` index into the summary's `SoftObjectPaths` list. | Same[^1] |

Paksmith rejects UE5 ≥ 1007 SoftObject reads with
`AssetParseFault::UnsupportedSoftObjectPathLayout { ue5_version }`
rather than mis-decoding; the UE5 1008+ index encoding requires
summary-side support deferred to Phase 2g.

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

Wire body: `FName asset_path` (8 bytes) + `FString sub_path`. Paksmith
rejects UE5 ≥ 1007 because the leading slot changes shape.

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
  - **UE5 1007+ SoftObjectPath rejection.** Paksmith rejects the
    wire-shape change; CUE4Parse and unreal_asset handle it. Phase 2g
    will unblock.
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
