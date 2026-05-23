# Container property types

> ArrayProperty, MapProperty, SetProperty — counted homogeneous (or
> two-typed, for Map) collections of property values.

## Overview

Three property types build a collection from per-element bodies:

- **ArrayProperty** — ordered list of same-typed elements.
- **SetProperty** — unordered list of unique same-typed elements.
- **MapProperty** — list of `(key, value)` pairs with the key type and
  value type independent.

All three carry a `i32 count` prefix immediately after the
`FPropertyTag` header (see [`tagged.md`](tagged.md)). Each element
body is decoded via the same per-type dispatch the primitive reader
uses, with one twist: container elements use the **element-form**
wire shape (no nested `FPropertyTag` headers for the body's
sub-properties — the type is fixed by the parent's `inner_type` /
`value_type` extras).

MapProperty additionally carries a `num_keys_to_remove` prefix (a
delta-serialization marker for the `TMap::AddPaired` operation);
paksmith parses and discards these entries to consume the bytes, then
reads the main `count` block.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| `FileVersionUE4 ≥ 504` | Container shapes stable. | `CUE4Parse/UE4/Assets/Objects/Properties/{Array,Map,Set}Property.cs@ecc4878950336126f125af0747190edf474b2a21`[^1] |

No UE5 changes to container shapes within paksmith's accepted range.

## Wire layout

### ArrayProperty

| field | size | type | semantics |
|-------|------|------|-----------|
| `count` | 4 | `i32` LE | Element count. Capped at `MAX_COLLECTION_ELEMENTS = 65,536`. |
| `elements` | variable | `T[count]` | Per-element bodies; element type is `tag.inner_type`. |

Element body shape: per-type (see Element-form section below).

**Array of StructProperty.** When `tag.inner_type == "StructProperty"`,
an `FPropertyTag` inline header (`inner_header`) precedes all element
bodies. This header is present for `FileVersionUE4 ≥ 500`
(`VER_UE4_INNER_ARRAY_TAG_INFO`), always true for paksmith's UE4 floor
of 504. The `inner_header.size` field holds the **total byte count for
all N element bodies combined**, not a per-element size — per CUE4Parse
`UScriptArray.cs` spec (PR #390 cross-validated this). Paksmith parses
`inner_header` (enforcing the 16 MiB `MAX_PROPERTY_TAG_SIZE` cap) then
ignores `inner_header.size`; element delimitation comes from each struct
body's own tagged-property `None` terminator. Errors propagate rather
than being caught per-element (see §Variants for contrast with Map/Set).

Extended wire layout for `Array<StructProperty>`:

| field | size | type | semantics |
|-------|------|------|-----------|
| `count` | 4 | `i32` LE | Element count (same guard as above). |
| `inner_header` | variable | `FPropertyTag` | Struct name, GUID, and TOTAL size across all elements. `inner_header.size` unused as a per-element bound. |
| `elements` | variable | `Struct[count]` | Tagged-property trees, each terminated by a `None` property tag. |

### SetProperty

Same shape as ArrayProperty for the live entries, plus a
`num_elements_to_remove` prefix:

| field | size | type | semantics |
|-------|------|------|-----------|
| `num_elements_to_remove` | 4 | `i32` LE | Delta-serialization prefix; parsed and discarded. Capped at `MAX_COLLECTION_ELEMENTS`. |
| `removed_elements` | variable | `T[num_elements_to_remove]` | Element bodies for the to-remove entries; bytes consumed and discarded. |
| `count` | 4 | `i32` LE | Live element count. Capped at `MAX_COLLECTION_ELEMENTS`. |
| `elements` | variable | `T[count]` | Element bodies for the live entries. |

### MapProperty

| field | size | type | semantics |
|-------|------|------|-----------|
| `num_keys_to_remove` | 4 | `i32` LE | Delta-serialization prefix; parsed and discarded. Capped at `MAX_COLLECTION_ELEMENTS`. |
| `removed_keys` | variable | `K[num_keys_to_remove]` | Key bodies for to-remove entries; bytes consumed and discarded. |
| `count` | 4 | `i32` LE | Live entry count. Capped at `MAX_COLLECTION_ELEMENTS`. |
| `entries` | variable | `(K, V)[count]` | Key body + value body per entry. |

Key type is `tag.inner_type`; value type is `tag.value_type`.

### Element-form

Container elements use a wire shape that omits the per-property tag —
the type is already known from the parent's `inner_type` /
`value_type`. The per-type element bodies are:

| Element type | Body shape |
|--------------|------------|
| `BoolProperty` | 1 byte (`u8`). Non-zero = true. Distinct from direct `BoolProperty` which reads `tag.bool_val` with zero payload bytes. |
| `Int8Property` | 1 byte (`i8`). |
| `Int16Property` | 2 LE bytes (`i16`). |
| `IntProperty` | 4 LE bytes (`i32`). |
| `Int64Property` | 8 LE bytes (`i64`). |
| `UInt16Property` | 2 LE bytes (`u16`). |
| `UInt32Property` | 4 LE bytes (`u32`). |
| `UInt64Property` | 8 LE bytes (`u64`). |
| `FloatProperty` | 4 LE bytes (`f32`). |
| `DoubleProperty` | 8 LE bytes (`f64`). |
| `StrProperty` | `FString`. |
| `NameProperty` | 8 bytes `FName` (index + number). |
| `ByteProperty` | 1 byte (`u8`). |
| `EnumProperty` | 8 bytes `FName` (enum variant name). |
| `SoftObjectProperty` | `FName asset_path` + `FString sub_path`. |
| `SoftClassProperty` | `FName asset_path` + `FString sub_path`. |
| `ObjectProperty` | 4 LE bytes (`FPackageIndex`). |
| `TextProperty` | `FText` body (see [`text.md`](text.md)). |
| `StructProperty` | Recursive tagged-property tree (see §Container of StructProperty). |
| (every other type) | **Not handled** — the container reader returns `Ok(None)` and the caller skips via `tag.size`. |

The `is_handled_element_type` predicate inside `containers.rs` gates
whether the container reader produces a typed `Array` / `Map` / `Set`
value or falls through to `Unknown { type_name: "ArrayProperty", … }`
with a skipped-bytes count.

### Worked example

*(none yet — pending fixture-stability follow-up; the precise offset depends on per-export layout. A primitive-focused fixture is tracked in [#347](https://github.com/r6e/paksmith/issues/347).)*

## Variants

### Container of StructProperty

When `tag.inner_type == "StructProperty"` (Array), or
`tag.value_type == "StructProperty"` / `tag.inner_type ==
"StructProperty"` (Map/Set), the element body is a recursive
tagged-property tree terminated by a `None` property tag.

**Array<Struct>** writes a full `FPropertyTag` inline header
(`inner_header`) before all element bodies; the struct name comes from
`inner_header.struct_name`. `inner_header.size` is the TOTAL byte span
across all elements, not a per-element bound (PR #390). Element
delimitation relies on each body's `None` terminator, not on
`inner_header.size`.

**Map<Struct, *>** / **Map<*, Struct>** / **Set<Struct>** carry no inline
element header. The struct name on these slots is empty (`""`); there is
no source for the struct type on the wire without `.usmap` schema
mappings. Element bodies are bounded only by the outer tag's
`expected_end`.

Paksmith handles all cases via `read_struct_value` recursion through
`super::read_properties`. Recursive StructProperty parsing is documented in detail in [`struct.md`](struct.md).

### Container of TextProperty

When the inner type is `TextProperty`, the element body is an `FText`
(history-discriminated; see [`text.md`](text.md)). Paksmith handles
the `None` and `Base` history variants typed; other variants return
`Err(AssetParseFault::TextHistoryUnsupportedInElement { history_type })`
rather than falling through to `Unknown`.

### Delta-serialization prefixes

`MapProperty::num_keys_to_remove` and
`SetProperty::num_elements_to_remove` are real-world non-zero in
some assets (cooked patches, dynamically-updated content). Paksmith
must consume the bytes to keep downstream fields aligned; the
discarded data isn't surfaced to consumers.

Cooked games almost always have both prefixes at zero; non-zero
appears mostly in delta-update artifacts.

### Collection-level bail for Map/Set with struct elements

When Map or Set contains `StructProperty` elements and a recoverable
wire-shape error occurs inside an element (bogus FName index, truncated
body, tag size mismatch, etc.), paksmith performs a collection-level
bail: emit one `tracing::warn!`, seek to the outer tag's `expected_end`,
and return the partial collection decoded so far. This matches
`unreal_asset`'s discard behavior. See `bail_map_partial` /
`bail_set_partial` in `containers.rs`.

Array<Struct> does **not** do this: errors from `Array<StructProperty>`
elements propagate (post PR #357). The asymmetry exists because Map/Set
have no per-entry byte boundary on the wire, making the outer
`expected_end` the only sound recovery anchor; Array<Struct> has each
struct body naturally delimited by its `None` terminator, so there is no
need to absorb errors at the collection level.

## Caps & limits

- **`MAX_COLLECTION_ELEMENTS = 65_536`**
  (`crates/paksmith-core/src/asset/property/mod.rs:106`). Applied to
  every counted field: `count`, `num_keys_to_remove`,
  `num_elements_to_remove`. Surfaces as
  `AssetParseFault::CollectionElementCountExceeded { collection, count, limit }`
  where `collection` is a `CollectionKind` discriminant
  (`Array`, `Map`, `MapNumToRemove`, `Set`, `SetNumToRemove`).
- **`MAX_PROPERTY_DEPTH = 128`** — applies through `StructProperty`
  element recursion.
- **`try_reserve_asset`** on every element-vec allocation; failure
  surfaces as `AssetParseFault::AllocationFailed`.

## Verification

- **Fixture:** `tests/fixtures/minimal_uasset_v5_with_containers.uasset`
  carries ArrayProperty + MapProperty + SetProperty in a single export.
- **Hex anchor commands:** `(none yet — see [#347](https://github.com/r6e/paksmith/issues/347))`.
- **Cross-validation oracle:** CUE4Parse[^1] and `unreal_asset`[^2].
- **Known divergences:**
  - **Delta-prefix discard.** Paksmith parses and discards
    `num_keys_to_remove` / `num_elements_to_remove` entries to consume
    bytes. CUE4Parse surfaces them as a separate collection in the
    decoded value; `unreal_asset` discards similarly to paksmith. The
    decision affects API ergonomics, not wire-format correctness.
  - **Array<Struct> inner_header.size semantics.** CUE4Parse treats
    `inner_header.size` as the TOTAL byte count across all elements;
    paksmith reads and bounds-checks the field via `MAX_PROPERTY_TAG_SIZE`
    then ignores it as a per-element bound (PR #390).

## Paksmith implementation

**Parser module:** `crates/paksmith-core/src/asset/property/containers.rs`.

**Status:** `complete`.

**Public surface:**
- `pub fn read_container_value<R: Read + Seek>(tag, reader, ctx, depth, body_end, asset_path) -> Result<Option<PropertyValue>>` —
  the dispatch entry; returns `None` for tag types this module
  doesn't claim.
- `PropertyValue::Array { inner_type, elements }`.
- `PropertyValue::Map { key_type, value_type, entries }`.
- `PropertyValue::Set { inner_type, elements }`.
- `PropertyValue::Struct { struct_name, properties }`.

**Error variants:**
- `AssetParseFault::CollectionElementCountExceeded { collection, count, limit }`.
- `AssetParseFault::PropertyDepthExceeded { depth, limit }`.
- `AssetParseFault::AllocationFailed { context: CollectionElements, … }`.
- `AssetParseFault::UnexpectedEof { field: MapKey | MapEntryCount | … }`.
- `AssetParseFault::TextHistoryUnsupportedInElement { history_type }` — raised
  when a `TextProperty` element body contains an unsupported FText history type.

**Phase plan:** `docs/plans/phase-2c-container-properties.md`.

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Objects/Properties/{Array,Map,Set}Property.cs@ecc4878950336126f125af0747190edf474b2a21` — primary oracle for each container type.
[^2]: `AstroTechies/unrealmodding/unreal_asset/unreal_asset_properties/src/{array,map,set}_property.rs@f4df5d8e75b1e184832384d1865f0b696b90a614` — Rust oracle. paksmith's discard-delta-prefix behavior matches.
