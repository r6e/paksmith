# Tagged property serialization (`FPropertyTag`)

> Per-property wire header that prefixes every property body in a UE
> export. Carries the property's name, type, body size, array index,
> type-specific extras, and an optional per-property GUID.

## Overview

UE has two property-serialization modes (see
[`unversioned.md`](unversioned.md) for the other). The default —
used by editor builds, by every default-cooked archive, and by every
UE4 game — is **tagged**: each property's body is preceded by an
`FPropertyTag` that publishes everything the reader needs to either
decode the body or skip it intact.

A tagged-property stream is a flat sequence of `(tag, body)` pairs
terminated by a sentinel tag whose name resolves to `"None"`. The
reader iterates: read tag, read tag-sized body (or dispatch to a
typed reader), read next tag, until the terminator. No length prefix
on the stream itself — `total_header_size` (in the package summary)
publishes the byte boundary, and the terminator publishes the
end-of-properties signal.

The tag's `Size` field is the load-bearing safety net: every body has
a declared byte size, so a reader that doesn't recognize the property
type can skip exactly `Size` bytes and continue parsing. Paksmith uses
this property aggressively — primitive types decode in-place,
container types decode in-place, every other type skips via `Size`
and emits a `PropertyValue::Unknown { type_name, skipped_bytes }`.

**Document status: complete.** Wire format documented in full for
the `(tag, body)` stream terminated by the `"None"` sentinel, the
`FPropertyTag` header (`Name`, `Type`, `Size`, `ArrayIndex`,
optional Bool / Struct / Enum / Array / Set / Map type-extras, and
the `HasPropertyGuid` + optional `PropertyGuid`), the size-based
skip safety net, the `PropertyValue::Unknown` fallback contract,
and the per-export iteration loop with cursor-invariant checks.
Per-type body wire shapes live in the sibling docs
([`primitives.md`](primitives.md), [`containers.md`](containers.md),
[`struct.md`](struct.md), [`text.md`](text.md)). UE5 ≥ 1011
(`PROPERTY_TAG_EXTENSION_AND_OVERRIDABLE_SERIALIZATION`) and ≥ 1012
(`PROPERTY_TAG_COMPLETE_TYPE_NAME`) are explicitly rejected at the
summary level — see §*Versions*.

**Paksmith parser status: `complete`.** Phase 2b deliverable; ships
as `paksmith-core/src/asset/property/tag.rs`.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| `FileVersionUE4 ≥ 504` (UE 4.21+) | Current shape. `VER_UE4_STRUCT_GUID_IN_PROPERTY_TAG (441)` and `VER_UE4_PROPERTY_GUID_IN_PROPERTY_TAG (503)` are both below 504, so `struct_guid` and the optional `PropertyGuid` are unconditionally present. | `CUE4Parse/UE4/Assets/Objects/FPropertyTag.cs@ecc4878950336126f125af0747190edf474b2a21`[^1] |
| `FileVersionUE5 ∈ [1000, 1010]` | Same as UE4 ≥ 504; no UE5 changes to the tag header within paksmith's accepted range. | Same[^1] |
| `FileVersionUE5 ≥ 1011` `PROPERTY_TAG_EXTENSION_AND_OVERRIDABLE_SERIALIZATION` | Adds a new byte after `HasPropertyGuid` (overridable-serialization flag) — **paksmith rejects archives at this version**, see [`uasset.md`](../asset/uasset.md). | Same[^1] |
| `FileVersionUE5 ≥ 1012` `PROPERTY_TAG_COMPLETE_TYPE_NAME` | Replaces the legacy FName-typed `Type` with a tree-based type-name representation — also rejected. | Same[^1] |

## Wire layout

### Tag header

| field | size | type | semantics |
|-------|------|------|-----------|
| `Name` | 8 | `FName`[^2] | `(u32 index, u32 number)` per [`../primitive/fname.md`](../primitive/fname.md). Resolved against the name table. `index == 0 && number == 0` → `"None"` sentinel that terminates iteration. |
| `Type` | 8 | `FName`[^2] | Property type (e.g. `"IntProperty"`, `"BoolProperty"`, `"StructProperty"`). |
| `Size` | 4 | `i32` LE | Body size in bytes. **`0` for `BoolProperty`** (value carried in the type extras). Capped at `MAX_PROPERTY_TAG_SIZE = 16 MiB`. |
| `ArrayIndex` | 4 | `i32` LE | Element index for array-of-T at the schema level (typically `0`). |
| `[type extras]` | variable | — | Conditional on `Type` — see the dispatch table below. |
| `HasPropertyGuid` | 1 | `u8` | `0` = no per-property GUID; non-zero = read the next 16 bytes as `PropertyGuid`. |
| `[PropertyGuid]` | 16 | `[u8; 16]` | Present iff `HasPropertyGuid != 0`. Per-property identifier for delta-merging. |

Tag header size depends on `Type`:

- Minimum (no extras, no GUID): 25 bytes (`8 + 8 + 4 + 4 + 1`).
- Maximum (MapProperty + GUID): 57 bytes (`8 + 8 + 4 + 4 + 16 + 1 + 16`), where
  the 16-byte extras slot is two 8-byte FNames for `inner_type` and `value_type`.

### Type extras dispatch

After `ArrayIndex`, the tag reader dispatches on `Type` to read the
type-specific extra fields:

| `Type` (resolved FName) | Extras read | Wire bytes |
|--------------------------|-------------|------------|
| `BoolProperty` | `bool_val: u8` | 1 |
| `StructProperty` | `struct_name: FName` + `struct_guid: [u8; 16]` | 8 + 16 = 24 |
| `ByteProperty` / `EnumProperty` | `enum_name: FName` | 8 |
| `ArrayProperty` / `SetProperty` | `inner_type: FName` | 8 |
| `MapProperty` | `inner_type: FName` + `value_type: FName` | 16 |
| any other type | (no extras) | 0 |

These fields are populated on every tag regardless of whether the
matching value reader is implemented — Phase 2c's container readers
rely on `inner_type` being resolved at tag-read time.

### Iteration

```rust
loop {
    // Stop if the cursor is already at or past the declared export end.
    if pos >= export_end { break; }

    let Some(tag) = read_tag(reader, ctx, asset_path)? else {
        break; // "None" terminator
    };

    let value_start = reader.stream_position()?;
    let expected_end = value_start + tag.size as u64;

    // Reject before reading: tag claims bytes past the export boundary.
    if expected_end > export_end {
        return Err(PropertyTagSizeMismatch { expected_end, actual_pos: export_end });
    }

    let value = read_value(&tag, reader, ctx, depth, expected_end, asset_path)?;

    // Cursor-invariant check.
    let actual_pos = reader.stream_position()?;
    if actual_pos != expected_end {
        return Err(PropertyTagSizeMismatch { expected_end, actual_pos });
    }

    props.push(Property { name: tag.name, array_index: tag.array_index, guid: tag.guid, value });
}
```

The error variant carries both `expected_end` and `actual_pos` for
operator-readable diagnostics.

### Worked example

*(none yet — pending fixture-stability follow-up; the precise offset depends on per-export layout. A primitive-focused fixture is tracked in [#347](https://github.com/r6e/paksmith/issues/347).)*

## Variants

The wire shape is uniform across all property types; per-type variance lives in the *Type extras dispatch* (Wire layout §*Type extras dispatch*) and the per-version tag-tail conditionals (Versions table). The `None`-tag sentinel terminator (`name = "None"`) is documented in *Iteration* under Wire layout. The `HasPropertyGuid` byte and `struct_guid` slot are unconditional at paksmith's UE 4.21+ floor — see the Versions table.

## Caps & limits

### Format-defined limits (wire-imposed)

- **`FPropertyTag` header**: variable size (min 25 bytes, max 57 bytes — see Wire layout §*Tag header* for the per-`Type` extras dispatch).
- **`Size`**: `i32` LE. `0` is wire-valid only for `BoolProperty` (value carried in tag-extras).
- **`ArrayIndex`**: `i32` LE.
- **`HasPropertyGuid`**: `u8`; non-zero triggers the following 16-byte `PropertyGuid` read.
- **`PropertyGuid`**: fixed 16 bytes.
- **`Type` extras** widths per Wire layout §*Type extras dispatch*: 0 bytes (most types), 1 byte (`BoolProperty`), 8 bytes (`ByteProperty`/`EnumProperty`/`ArrayProperty`/`SetProperty`), 16 bytes (`MapProperty`), 24 bytes (`StructProperty`).

### Implementation hardening (recommended for any parser)

- **`MAX_PROPERTY_TAG_SIZE = 16 MiB`**
  (`crates/paksmith-core/src/asset/property/tag.rs`). Tag `Size`
  cap. Bounds the maximum bytes a single `Unknown`-type skip
  allocates. `Size < 0` surfaces as `AssetParseFault::NegativeValue { field: PropertyTagSize }`;
  `Size > MAX_PROPERTY_TAG_SIZE` surfaces as
  `AssetParseFault::BoundsExceeded { field: PropertyTagSize, unit: Bytes }`.
- **`MAX_TAGS_PER_EXPORT = 65_536`**
  (`crates/paksmith-core/src/asset/property/mod.rs`). Hard cap on
  the number of tags `read_properties` will iterate inside a single
  export body. Surfaces as `AssetParseFault::PropertyTagCountExceeded { limit }`.
- **`MAX_PROPERTY_DEPTH = 128`**
  (`crates/paksmith-core/src/asset/property/bag.rs`). Maximum
  nesting depth for recursive structs / containers. Surfaces as
  `AssetParseFault::PropertyDepthExceeded { depth, limit }`.

See `docs/security/allocation-caps.md` for the broader policy.

## Verification

- **Fixtures:**
  - `tests/fixtures/minimal_uasset_v5_with_properties.uasset` — single
    export carrying primitive tagged properties + the "None" terminator.
  - `tests/fixtures/minimal_uasset_v5_with_containers.uasset` —
    container-type tags (Array/Map/Set) exercising the type-extras
    dispatch.
  - `tests/fixtures/minimal_uasset_v5_with_extended_types.uasset` —
    extended types (Phase 2d) exercising every type-extras branch.
- **Hex anchor commands:** `(none yet — see [#347](https://github.com/r6e/paksmith/issues/347))`.
- **Cross-validation oracle:** CUE4Parse[^1] and `unreal_asset`[^3].
- **Known divergences:**
  - **UE5 1011+ rejection.** The
    `PROPERTY_TAG_EXTENSION_AND_OVERRIDABLE_SERIALIZATION` extension
    byte after `HasPropertyGuid` is not handled by paksmith's
    `read_tag`; paksmith rejects archives at this version at the
    summary level (see [`../asset/uasset.md`](../asset/uasset.md)).
    CUE4Parse and unreal_asset handle 1011+.
  - **Parse-error → Opaque fallback.** If `read_properties` returns
    an error mid-iteration (malformed tag, unknown encoding, depth
    violation, cursor mismatch), the caller
    (`Package::read_payloads`) catches the error, emits a
    `tracing::warn!` event, and substitutes `PropertyBag::Opaque`
    with the raw export bytes. CUE4Parse propagates the error; the
    paksmith design favors partial parsing because one corrupt
    export shouldn't fail the whole package.

## Paksmith implementation

**Parser module:**
`crates/paksmith-core/src/asset/property/tag.rs` (`read_tag`,
`PropertyTag`, `MAX_PROPERTY_TAG_SIZE`).
`crates/paksmith-core/src/asset/property/mod.rs` (`read_properties`
iteration loop, the two outer caps).
`crates/paksmith-core/src/asset/property/bag.rs` (`PropertyBag::Tree`,
`PropertyBag::Opaque`, `MAX_PROPERTY_DEPTH`).

**Status:** `complete`.

**Public surface:**
- `pub struct PropertyTag` — every field as `pub`.
- `pub fn read_tag<R: Read>(reader, ctx, asset_path) -> Result<Option<PropertyTag>>` —
  returns `Ok(None)` for the "None" terminator.
- `pub fn resolve_fname(index, number, ctx, asset_path, field) -> Result<String>` —
  shared FName resolver used by the tag and value readers.
- `pub fn read_properties<R: Read + Seek>(reader, ctx, depth, export_end, asset_path) -> Result<Vec<Property>>` —
  the iteration loop.
- `pub const MAX_PROPERTY_TAG_SIZE: i32 = 16 * 1024 * 1024`.
- `pub const MAX_TAGS_PER_EXPORT: usize = 65_536`.

**Error variants:**
- `AssetParseFault::NegativeValue { field: PropertyTagSize, value }` — `Size < 0`.
- `AssetParseFault::BoundsExceeded { field: PropertyTagSize, unit: Bytes, .. }` — `Size > MAX_PROPERTY_TAG_SIZE`.
- `AssetParseFault::PropertyTagCountExceeded { limit }` — iteration exceeded `MAX_TAGS_PER_EXPORT`.
- `AssetParseFault::PropertyDepthExceeded { depth, limit }` — nesting exceeded `MAX_PROPERTY_DEPTH`.
- `AssetParseFault::PropertyTagSizeMismatch { expected_end, actual_pos }` — cursor
  out of sync after a value read, or tag claims bytes past `export_end`.
- `AssetParseFault::UnexpectedEof { field: AssetWireField }` for every
  wire-field shorthand the property iteration touches.
- `AssetParseFault::PackageIndexUnderflow`, `AssetParseFault::PackageIndexOob` —
  forwarded from FName resolution on out-of-range name-table indexes.

**Phase plan:** `docs/plans/phase-2b-tagged-properties.md`.

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Objects/FPropertyTag.cs@ecc4878950336126f125af0747190edf474b2a21` — primary oracle for the tag header layout, including the version-conditional UE5 1011/1012 extensions paksmith rejects.
[^2]: See [`../primitive/fname.md`](../primitive/fname.md) for FName wire shape and `(index, number)` resolution.
[^3]: `AstroTechies/unrealmodding/unreal_asset/unreal_asset_properties/src/lib.rs@f4df5d8e75b1e184832384d1865f0b696b90a614` — Rust oracle for the per-type property dispatch.
