# UE Property Family Documentation — PR 5 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Populate `docs/formats/property/` with six documents: `tagged.md` (FPropertyTag wire reader, `complete | complete`), `unversioned.md` (UE5 schema-driven serialization, `partial | not impl` — Phase 2f deliverable; see Task 7 for the partial-vs-stub rationale), `primitives.md` (Int/Bool/Float/Name/Str/Object/Enum/etc., `complete | complete`), `containers.md` (Array/Map/Set, `complete | complete`), `struct.md` (StructProperty, `partial | partial` — tagged-property struct bodies work, native binary structs fall through), `text.md` (FText, `partial | partial` — None/Base handled, other history variants → Unknown). Add six rows to the root inventory.

**Architecture:** Five of the six docs reflect Phase 2b–2d work that already shipped, so the prose mirrors real cap constants, PropertyValue variants, and error variants. `unversioned.md` is `partial | not impl` because Phase 2f hasn't opened and paksmith currently *rejects* `PKG_UnversionedProperties` packages at the summary level — the doc fills every H2 section with prose-form TODOs (matching the spec's `partial` definition), not the 1–2-paragraph stub shape. The two `partial | partial` docs (`struct.md`, `text.md`) reflect honest scope: their parsers handle the common case but fall back gracefully on out-of-scope variants.

**Tech Stack:** Pure markdown. PR 1 linters. Primary oracle is CUE4Parse (the `FPropertyTag.cs` family); secondary is `unreal_asset` for fixture cross-validation.

**Spec reference:** `docs/design/2026-05-19-ue-format-docs.md` (commit `72b364e`). **Prerequisite:** PR 1 (framework scaffold) has merged to `main`. PRs 2–4 are not prerequisites but their inventory rows simplify the editing target in Task 7.

---

## Prerequisites

Follow [PREAMBLE.md](2026-05-19-ue-format-docs-PREAMBLE.md). Family name `property`; capture `<CUE4PARSE_SHA>` and `<UNREAL_ASSET_SHA>` at preamble Step 7.

## File structure

**Create (6 docs):**

- `docs/formats/property/tagged.md` — FPropertyTag wire reader.
- `docs/formats/property/unversioned.md` — schema-driven serialization (stub).
- `docs/formats/property/primitives.md` — Int/Bool/Float/Name/Str/Object/Enum/SoftObject/etc.
- `docs/formats/property/containers.md` — ArrayProperty / MapProperty / SetProperty.
- `docs/formats/property/struct.md` — StructProperty (partial — tagged-body handled, native-binary falls through).
- `docs/formats/property/text.md` — FText (partial — None/Base handled, other histories → Unknown).

**Modify (1):**

- `docs/formats/README.md` — add six rows to the inventory.

**Oracle citation policy.** Primary: CUE4Parse's `FPropertyTag.cs` family (`UE4/Assets/Objects/Properties/`). Secondary: `unreal_asset/src/properties/` for Rust-side triangulation. Both are needed because paksmith's tag reader matches CUE4Parse closely but the PropertyValue surface matches unreal_asset more closely.

**Hex-anchor policy.** `tests/fixtures/minimal_uasset_v5_with_properties.uasset` is the cleanest single-export-body fixture for `tagged.md` and `primitives.md`. `minimal_uasset_v5_with_containers.uasset` anchors `containers.md`. `minimal_uasset_v5_with_extended_types.uasset` anchors `struct.md` and `text.md`. `unversioned.md` uses `(none yet — Phase 2f deliverable)`.

---

## Task 1: Per-family setup

Run [PREAMBLE.md](2026-05-19-ue-format-docs-PREAMBLE.md)'s "Per-family setup" with `<family> = property`. Capture oracle SHAs at preamble Step 7 for use across this plan's doc citations.

---

## Task 2: Author `docs/formats/property/tagged.md`

The keystone doc of this PR. `FPropertyTag` is the per-property wire header that gates every primitive/container/struct/text read. The doc must document the header layout, the type-extras dispatch, the `HasPropertyGuid` byte, and the iteration termination ("None"-named tag).

**Files:**
- Create: `docs/formats/property/tagged.md`

**Ground truth references:**
- `crates/paksmith-core/src/asset/property/tag.rs` (445 lines) — `PropertyTag`, `read_tag`, `MAX_PROPERTY_TAG_SIZE`.
- `crates/paksmith-core/src/asset/property/mod.rs` (525 lines) — `read_properties` iteration loop, `MAX_TAGS_PER_EXPORT`, `MAX_COLLECTION_ELEMENTS`.
- `crates/paksmith-core/src/asset/property/bag.rs` (239 lines) — `PropertyBag::{Tree, Opaque}`, `MAX_PROPERTY_DEPTH`.

- [ ] **Step 1: Read the parsers**

Run: `cat crates/paksmith-core/src/asset/property/tag.rs`
Run: `head -200 crates/paksmith-core/src/asset/property/mod.rs`
Run: `cat crates/paksmith-core/src/asset/property/bag.rs`

The module-level comments at the top of `tag.rs` and `mod.rs` carry the most-quoted facts; the cap constants are at the top of each module.

- [ ] **Step 3: Capture a fresh hex anchor**

Run: `xxd -s 0x40 -l 64 tests/fixtures/minimal_uasset_v5_with_properties.uasset`
Note the bytes near the first export body's start. The first FPropertyTag begins with `i32 name_index` and `i32 name_number` (the name FName). Use these bytes verbatim in the worked-example block.

- [ ] **Step 4: Write the doc**

Write `docs/formats/property/tagged.md`:

````markdown
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

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| `FileVersionUE4 ≥ 504` (UE 4.21+) | Current shape. `VER_UE4_STRUCT_GUID_IN_PROPERTY_TAG (441)` and `VER_UE4_PROPERTY_GUID_IN_PROPERTY_TAG (503)` are both below 504, so `struct_guid` and the optional `PropertyGuid` are unconditionally present. | `CUE4Parse/UE4/Assets/Objects/FPropertyTag.cs@<CUE4PARSE_SHA>`[^1] |
| `FileVersionUE5 ∈ [1000, 1010]` | Same as UE4 ≥ 504; no UE5 changes to the tag header within paksmith's accepted range. | Same[^1] |
| `FileVersionUE5 ≥ 1011` `PROPERTY_TAG_EXTENSION_AND_OVERRIDABLE_SERIALIZATION` | Adds a new byte after `HasPropertyGuid` (overridable-serialization flag) — **paksmith rejects archives at this version**, see [`uasset.md`](../asset/uasset.md). | Same[^1] |
| `FileVersionUE5 ≥ 1012` `PROPERTY_TAG_COMPLETE_TYPE_NAME` | Replaces the legacy FName-typed `Type` with a tree-based type-name representation — also rejected. | Same[^1] |

## Wire layout

### Tag header

| field | size | type | semantics |
|-------|------|------|-----------|
| `Name` | 8 | `FName`[^2] | `(i32 index, i32 number)`. Resolved against the name table. `index == 0 && number == 0` → `"None"` sentinel that terminates iteration. |
| `Type` | 8 | `FName`[^2] | Property type (e.g. `"IntProperty"`, `"BoolProperty"`, `"StructProperty"`). |
| `Size` | 4 | `i32` LE | Body size in bytes. **`0` for `BoolProperty`** (value carried in the type extras). Capped at `MAX_PROPERTY_TAG_SIZE = 16 MiB`. |
| `ArrayIndex` | 4 | `i32` LE | Element index for array-of-T at the schema level (typically `0`). |
| `[type extras]` | variable | — | Conditional on `Type` — see the dispatch table below. |
| `HasPropertyGuid` | 1 | `u8` | `0` = no per-property GUID; non-zero = read the next 16 bytes as `PropertyGuid`. |
| `[PropertyGuid]` | 16 | `[u8; 16]` | Present iff `HasPropertyGuid != 0`. Per-property identifier for delta-merging. |

Tag header size depends on `Type`:

- Minimum (no extras, no GUID): 25 bytes (`8 + 8 + 4 + 4 + 1`).
- Maximum observed (MapProperty with both inner types named + GUID): 56 bytes
  (`8 + 8 + 4 + 4 + 8 + 8 + 1 + 16 = 57` — but `HasPropertyGuid` and `PropertyGuid` together are 17, not 25).

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
    let tag = read_tag(reader, ctx, asset_path)?;
    if tag.name == "None" {
        break;
    }
    let body_end = reader.stream_position() + tag.size as u64;
    let value = read_value(&tag, reader, ctx, depth, body_end, asset_path)?;
    properties.push(Property { tag, value });
    reader.seek(SeekFrom::Start(body_end))?;  // Always re-anchor for unknown types.
}
```

The `body_end` re-anchor is load-bearing: even if a typed reader
successfully decodes the body, paksmith re-seeks to `body_end` to
guarantee the next tag reads from the declared end-of-body offset.
Same mechanism handles unknown types — they don't consume any bytes,
and the seek snaps to the declared body end.

### Worked example

```bash
# First FPropertyTag in the first export body
xxd -s 0x40 -l 64 tests/fixtures/minimal_uasset_v5_with_properties.uasset
```

The first 8 bytes are the property name FName (resolved against the
name table at `name_offset`). The next 8 bytes are the type FName.
The next 4 bytes are `Size` (LE i32). The next 4 bytes are
`ArrayIndex`. Type-specific extras follow, then `HasPropertyGuid`,
then the optional GUID.

*(Re-run Step 3 to capture the actual bytes from the fixture; the
hex-anchor CI check will eventually enforce this verbatim.)*

## Variants

### Sentinel termination

The terminator is not a separate "end of stream" byte — it's a
regular `FPropertyTag` whose name FName has `(index=0, number=0)`,
which by convention always resolves to `"None"` in the name table.
A malformed asset whose name table happens not to map `(0, 0)` to
`"None"` would either:
1. Loop until `body_end` (the `expected_end` parameter of
   `read_properties`) is reached and return naturally, or
2. Trip `MAX_TAGS_PER_EXPORT` and reject.

UE writers always seed the name table with `"None"` at index 0; the
"safety net via the upper bound" behavior covers the corrupt-asset
path.

### `HasPropertyGuid` byte

UE introduced per-property GUIDs at `VER_UE4_PROPERTY_GUID_IN_PROPERTY_TAG`
(version 503), below paksmith's UE4 floor (504). The byte is therefore
unconditionally present in every tag paksmith parses. Most cooked
properties carry `HasPropertyGuid == 0`; the non-zero case appears for
properties that participate in delta-merging.

### `StructProperty`'s `struct_guid`

Likewise introduced below paksmith's floor, so always present. Most
struct types have a zero GUID (the struct type is identified by
`struct_name`). Non-zero `struct_guid` appears for engine-specific
struct deltas — read but currently unused.

## Caps & limits

- **`MAX_PROPERTY_TAG_SIZE = 16 MiB`**
  (`crates/paksmith-core/src/asset/property/tag.rs:35`). Tag `Size`
  cap. Bounds the maximum bytes a single `Unknown`-type skip
  allocates. Surfaces as `AssetParseFault::BoundsExceeded { field: PropertyTagSize, … }`.
- **`MAX_TAGS_PER_EXPORT = 65_536`**
  (`crates/paksmith-core/src/asset/property/mod.rs:88`). Hard cap on
  the number of tags `read_properties` will iterate inside a single
  export body. Surfaces as `AssetParseFault::TooManyTagsPerExport`.
- **`MAX_PROPERTY_DEPTH = 128`**
  (`crates/paksmith-core/src/asset/property/bag.rs:28`). Maximum
  nesting depth for recursive structs / containers. Surfaces as
  `AssetParseFault::PropertyDepthExceeded`.

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
- **Cross-validation oracle:** CUE4Parse[^1] and `unreal_asset`[^3].
- **Known divergences:**
  - **UE5 1011+ rejection.** The
    `PROPERTY_TAG_EXTENSION_AND_OVERRIDABLE_SERIALIZATION` extension
    byte after `HasPropertyGuid` is not handled by paksmith's
    `read_tag`; paksmith rejects archives at this version at the
    summary level (see [`../asset/uasset.md`](../asset/uasset.md)).
    CUE4Parse and unreal_asset handle 1011+.
  - **Parse-error → Opaque fallback.** If `read_properties` errors
    mid-iteration (malformed tag, unknown encoding, depth violation),
    the enclosing export's `PropertyBag` falls back to `Opaque` with
    a `tracing::warn!` event. CUE4Parse propagates the error; the
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
- `pub fn read_tag<R: Read>(reader, ctx, asset_path) -> Result<PropertyTag>`.
- `pub fn resolve_fname(reader, ctx, asset_path, field) -> Result<String>` —
  shared FName resolver used by the tag and value readers.
- `pub fn read_properties<R: Read + Seek>(reader, ctx, depth, expected_end, asset_path) -> Result<Vec<Property>>` —
  the iteration loop.
- `pub const MAX_PROPERTY_TAG_SIZE: i32 = 16 * 1024 * 1024`.
- `pub const MAX_TAGS_PER_EXPORT: usize = 65_536`.
- `pub const MAX_COLLECTION_ELEMENTS: usize = 65_536`.

**Error variants:**
- `AssetParseFault::BoundsExceeded { field: PropertyTagSize, … }`.
- `AssetParseFault::TooManyTagsPerExport`.
- `AssetParseFault::PropertyDepthExceeded { depth, limit }`.
- `AssetParseFault::UnexpectedEof { field: AssetWireField }` for every
  wire-field shorthand the property iteration touches.
- `AssetParseFault::FStringMalformed`, `AssetParseFault::PackageIndexUnderflow`,
  etc. — forwarded from sub-readers.

**Phase plan:** `docs/plans/phase-2b-tagged-properties.md`.

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Objects/FPropertyTag.cs@<CUE4PARSE_SHA>` — primary oracle for the tag header layout, including the version-conditional UE5 1011/1012 extensions paksmith rejects.
[^2]: See [`../primitive/fname.md`](../primitive/fname.md) for FName wire shape and `(index, number)` resolution.
[^3]: `AstralOrigin/unreal_asset/unreal_asset/src/properties/mod.rs@<UNREAL_ASSET_SHA>` — Rust oracle for the iteration loop + per-type dispatch.
````

- [ ] **Step 5: Commit** (preamble convention — required-headings linter must pass before commit)

```bash
git add docs/formats/property/tagged.md
git commit -m "$(cat <<'EOF'
docs(formats): add FPropertyTag tagged-serialization reference

Documents the per-property wire header (Name + Type + Size +
ArrayIndex + type-extras + HasPropertyGuid + optional GUID), the
type-extras dispatch table, the iteration loop with its
body_end re-anchor pattern, the three caps (MAX_PROPERTY_TAG_SIZE,
MAX_TAGS_PER_EXPORT, MAX_PROPERTY_DEPTH), and the parse-error →
Opaque fallback design choice.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Author `docs/formats/property/primitives.md`

The catalog of property types that decode in place (no container, no
struct, no text). Each entry: type name, wire body shape, PropertyValue
variant, version conditionals.

**Files:**
- Create: `docs/formats/property/primitives.md`

**Ground truth references:**
- `crates/paksmith-core/src/asset/property/primitives.rs` (1121 lines) — `Property`, `PropertyValue` (~20 variants), `read_primitive_value`, `read_soft_path_payload`, `resolve_package_index`.

- [ ] **Step 1: Read the parser**

Run: `cat crates/paksmith-core/src/asset/property/primitives.rs | head -250`

Note especially the `PropertyValue` enum variants (lines 57+) and the
type-dispatch in `read_primitive_value` (lines 267+).

- [ ] **Step 3: Capture a fresh hex anchor**

Run: `xxd tests/fixtures/minimal_uasset_v5_with_properties.uasset | head -25`
Locate the first integer-property body and note its bytes for the
worked-example block.

- [ ] **Step 4: Write the doc**

Write `docs/formats/property/primitives.md`:

````markdown
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
| `FileVersionUE4 ≥ 504` | All primitive shapes stable. | `CUE4Parse/UE4/Assets/Objects/Properties/*.cs@<CUE4PARSE_SHA>`[^1] |
| `FileVersionUE5 ≥ 1007` | `SoftObjectProperty` / `SoftClassProperty` wire shape changes (`FTopLevelAssetPath` replaces the leading FName). | Same[^1] |
| `FileVersionUE5 ≥ 1008` | `SoftObjectProperty` becomes an `i32` index into the summary's `SoftObjectPaths` list. | Same[^1] |

Paksmith rejects UE5 ≥ 1007 SoftObject reads with
`AssetParseFault::UnsupportedSoftObjectPathLayout { ue5_version }`
rather than mis-decoding; the UE5 1008+ index encoding requires
summary-side support deferred to Phase 2g.

## Wire layout

### Boolean (`BoolProperty`)

Wire body: 0 bytes. The bool value lives in the tag's type-extras
(`bool_val: u8`); `tag.size == 0` for every BoolProperty.

`PropertyValue::Bool(bool)`.

### Integer types

| `Type` (FName) | Body bytes | LE? | `PropertyValue` variant |
|----------------|------------|-----|--------------------------|
| `Int8Property` | 1 | — | `Int8(i8)` |
| `ByteProperty` (tag.enum_name == "") | 1 | — | `Byte(u8)` |
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
| `ByteProperty` (tag.enum_name set) | `FName` value | Same — `Enum { type_name, value }` |

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

### Worked example: first integer property body

```bash
xxd tests/fixtures/minimal_uasset_v5_with_properties.uasset | head -25
```

The first integer-property body lives at the byte offset published by
the tag header; for the minimal fixture the first `IntProperty` body
is 4 LE bytes immediately following its 25-byte tag header.

*(Re-run Step 3 to capture the actual offset and bytes.)*

## Variants

### `ByteProperty` dual interpretation

`ByteProperty` is either a raw `u8` (when `tag.enum_name == ""`) or an
`FName`-shaped enum variant (when `tag.enum_name != ""`). The
dispatch on `tag.enum_name` is paksmith's; the wire layouts are
mutually exclusive — a raw byte vs an 8-byte FName.

### `EnumProperty` with empty `type_name`

Modern encoders always emit `tag.enum_name` for `EnumProperty`, but
the iterator is permissive: an empty `type_name` still produces a
valid `Enum { type_name: "", value }` because the variant FName is
present. Downstream consumers should treat empty `type_name` as
"unknown enum" and either skip or consult a type registry.

### `ObjectProperty` `i32::MIN` rejection

Paksmith rejects `i32::MIN` at the `FPackageIndex` decode layer (see
[`../primitive/fpackage-index.md`](../primitive/fpackage-index.md)).
CUE4Parse wraps the overflow; the practical impact is nil (UE never
writes `i32::MIN`).

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
    exercises Bool/Int/Float/Str/Name/Enum/Object primitive types in
    a single export.
  - `tests/fixtures/minimal_uasset_v5_with_extended_types.uasset` —
    exercises Int8/Int16/UInt16/UInt32/Int64/UInt64/Double/Soft types
    added in Phase 2d.
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
- `pub struct Property { pub tag: PropertyTag, pub value: PropertyValue }`.
- `pub struct MapEntry { pub key: PropertyValue, pub value: PropertyValue }`.
- `pub enum PropertyValue` (`#[non_exhaustive]`) — every variant
  enumerated above.
- `pub fn read_primitive_value<R: Read + Seek>(tag, reader, ctx, depth, body_end, asset_path) -> Result<Option<PropertyValue>>` —
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

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Objects/Properties/*.cs@<CUE4PARSE_SHA>` — per-type primary oracle.
[^2]: See [`../primitive/fstring.md`](../primitive/fstring.md).
[^3]: See [`../primitive/fname.md`](../primitive/fname.md).
[^4]: See [`../primitive/fpackage-index.md`](../primitive/fpackage-index.md).
[^5]: `AstralOrigin/unreal_asset/unreal_asset/src/properties/*.rs@<UNREAL_ASSET_SHA>` — Rust oracle; paksmith's PropertyValue surface mirrors unreal_asset's `Property` enum closely.
````

- [ ] **Step 5: Commit** (preamble convention — required-headings linter must pass before commit)

```bash
git add docs/formats/property/primitives.md
git commit -m "$(cat <<'EOF'
docs(formats): add primitive property reference

Enumerates ~16 primitive property types (Bool, integer family,
float family, Str/Name/Enum/Object/Soft*) with wire body shapes,
PropertyValue variants, and version conditionals. Documents the
ByteProperty raw-vs-enum dual interpretation, the UE5 1007+ Soft
rejection, and the i32::MIN ObjectProperty rejection.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Author `docs/formats/property/containers.md`

ArrayProperty, MapProperty, SetProperty. Each has a `i32 count` prefix
and a per-element body decoded via `read_element_value`. MapProperty has
the additional `num_keys_to_remove` delta-serialization prefix.

**Files:**
- Create: `docs/formats/property/containers.md`

**Ground truth references:**
- `crates/paksmith-core/src/asset/property/containers.rs` (1599 lines) — `read_container_value`, `read_array_value`, `read_map_value`, `read_set_value`, `read_struct_value`.

- [ ] **Step 1: Read the parser**

Run: `head -100 crates/paksmith-core/src/asset/property/containers.rs`
Run: `sed -n '200,500p' crates/paksmith-core/src/asset/property/containers.rs`

Note the `MAX_COLLECTION_ELEMENTS = 65,536` cap; the `num_keys_to_remove`
delta prefix on Map; the `is_handled_element_type` predicate that gates
the typed-decode vs `Unknown` fallback.

- [ ] **Step 3: Capture a fresh hex anchor**

Run: `xxd tests/fixtures/minimal_uasset_v5_with_containers.uasset | head -30`
Locate the first ArrayProperty's `i32 count` prefix.

- [ ] **Step 4: Write the doc**

Write `docs/formats/property/containers.md`:

````markdown
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
| `FileVersionUE4 ≥ 504` | Container shapes stable. | `CUE4Parse/UE4/Assets/Objects/Properties/{Array,Map,Set}Property.cs@<CUE4PARSE_SHA>`[^1] |

No UE5 changes to container shapes within paksmith's accepted range.

## Wire layout

### ArrayProperty

| field | size | type | semantics |
|-------|------|------|-----------|
| `count` | 4 | `i32` LE | Element count. Capped at `MAX_COLLECTION_ELEMENTS = 65,536`. |
| `elements` | variable | `T[count]` | Per-element bodies; element type is `tag.inner_type`. |

Element body shape: per-type (see Element-form section below).

### SetProperty

Same as ArrayProperty plus an additional `num_elements_to_remove` prefix:

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
| `IntProperty` | 4 LE bytes (i32). |
| `BoolProperty` | 1 byte (u8). |
| `FloatProperty` | 4 LE bytes (f32). |
| `StrProperty` | `FString`. |
| `NameProperty` | 8 bytes `FName`. |
| `EnumProperty` / `ByteProperty` (with enum_name) | 8 bytes `FName`. |
| `ObjectProperty` | 4 LE bytes (`FPackageIndex`). |
| `SoftObjectProperty` / `SoftClassProperty` | `FName asset_path` + `FString sub_path`. |
| `StructProperty` | Recursive tagged-property tree (see [`struct.md`](struct.md)). |
| `TextProperty` | `FText` body (see [`text.md`](text.md)). |
| (every other type) | **Not handled** — the container reader returns `Ok(None)` and the caller skips via `tag.size`. |

The `is_handled_element_type` predicate inside `containers.rs` gates
whether the container reader produces a typed `Array` / `Map` / `Set`
value or falls through to `Unknown { type_name: "ArrayProperty", … }`
with a skipped-bytes count.

### Worked example: first ArrayProperty body

```bash
xxd tests/fixtures/minimal_uasset_v5_with_containers.uasset | head -30
```

The first ArrayProperty body begins with `i32 count` (LE). After
that, `count` element bodies follow per the table above.

*(Re-run Step 3 to capture the exact bytes and offset.)*

## Variants

### Container of StructProperty

When `tag.inner_type == "StructProperty"` (or `tag.value_type` for
Map), the element body is itself a recursive tagged-property tree —
NOT a plain element-form body. See [`struct.md`](struct.md). Paksmith
handles this via `read_struct_value` recursion through
`super::read_properties`.

### Container of TextProperty

When the inner type is `TextProperty`, the element body is an `FText`
(history-discriminated; see [`text.md`](text.md)). Paksmith handles
the `None` and `Base` history variants typed; other variants fall
through to `Unknown` with a skipped count.

### Delta-serialization prefixes

`MapProperty::num_keys_to_remove` and
`SetProperty::num_elements_to_remove` are real-world non-zero in
some assets (cooked patches, dynamically-updated content). Paksmith
must consume the bytes to keep downstream fields aligned; the
discarded data isn't surfaced to consumers.

Cooked games almost always have both prefixes at zero; non-zero
appears mostly in delta-update artifacts.

## Caps & limits

- **`MAX_COLLECTION_ELEMENTS = 65_536`**
  (`crates/paksmith-core/src/asset/property/mod.rs:96`). Applied to
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
- **Cross-validation oracle:** CUE4Parse[^1] and `unreal_asset`[^2].
- **Known divergences:**
  - **Delta-prefix discard.** Paksmith parses and discards
    `num_keys_to_remove` / `num_elements_to_remove` entries to consume
    bytes. CUE4Parse surfaces them as a separate collection in the
    decoded value; `unreal_asset` discards similarly to paksmith. The
    decision affects API ergonomics, not wire-format correctness.

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

**Phase plan:** `docs/plans/phase-2c-container-properties.md`.

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Objects/Properties/{Array,Map,Set}Property.cs@<CUE4PARSE_SHA>` — primary oracle for each container type.
[^2]: `AstralOrigin/unreal_asset/unreal_asset/src/properties/{array,map,set}_property.rs@<UNREAL_ASSET_SHA>` — Rust oracle. paksmith's discard-delta-prefix behavior matches.
````

- [ ] **Step 5: Commit** (preamble convention — required-headings linter must pass before commit)

```bash
git add docs/formats/property/containers.md
git commit -m "$(cat <<'EOF'
docs(formats): add container property reference

Documents ArrayProperty / MapProperty / SetProperty wire shapes
including the num_keys_to_remove / num_elements_to_remove
delta-serialization prefixes paksmith parses and discards. Spells
out the element-form vs tagged-form distinction, the
is_handled_element_type gating to Unknown, and the
MAX_COLLECTION_ELEMENTS = 65,536 cap with its five CollectionKind
discriminants.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Author `docs/formats/property/struct.md` (partial)

StructProperty's wire shape splits two ways depending on the struct
type. User-defined struct types serialize as a recursive tagged-property
tree (which paksmith handles). Native UE structs (FVector, FRotator,
FQuat, FLinearColor, FGameplayTag, FTransform, FGuid-as-property, etc.)
have CUSTOM binary serialization defined by their `StructOps`. Paksmith
recurses into native struct bodies hoping for a tagged sequence; when
it hits non-tag bytes the inner `read_properties` errors and the
enclosing export falls back to `Opaque`.

**Files:**
- Create: `docs/formats/property/struct.md`

**Ground truth references:**
- `crates/paksmith-core/src/asset/property/containers.rs:282–303` — `read_struct_value`.
- `crates/paksmith-core/src/asset/property/primitives.rs:128–135` — `PropertyValue::Struct { struct_name, properties }`.

- [ ] **Step 1: Read the parsers**

Run: `sed -n '270,310p' crates/paksmith-core/src/asset/property/containers.rs`
Run: `sed -n '120,140p' crates/paksmith-core/src/asset/property/primitives.rs`

- [ ] **Step 3: Capture a fresh hex anchor (optional, partial doc)**

Run: `xxd tests/fixtures/minimal_uasset_v5_with_extended_types.uasset | head -30`
A StructProperty with the inner properties visible after the tag
header is the cleanest anchor — or use `(none yet — pending native-
struct fixture)`.

- [ ] **Step 4: Write the doc**

Write `docs/formats/property/struct.md`:

````markdown
# StructProperty

> Property type whose body is the bytes of one struct — either a
> recursive tagged-property tree (user-defined structs) or a custom
> binary blob (native UE structs).

## Overview

`StructProperty` is the property type for nested struct values. The
tag's type-extras include `struct_name: FName` (the struct's type
name, e.g. `"Vector"`, `"Rotator"`, `"GameplayTag"`,
`"MyUserStruct"`) and `struct_guid: [u8; 16]` (a per-type identifier,
typically zero except for engine-specific struct deltas).

The body's wire shape depends on the struct type:

- **User-defined structs** (`USTRUCT()` in C++ / Blueprint struct
  assets) serialize as a recursive tagged-property tree — the same
  shape as the parent export body, terminated by a `"None"` tag. This
  is the case paksmith handles via `read_struct_value`.
- **Native UE structs** with custom `StructOps::SerializeNative` —
  `FVector`, `FRotator`, `FQuat`, `FLinearColor`, `FColor`,
  `FGameplayTag`, `FGuid` (as a property), `FTransform`,
  `FBox`/`FBoxSphereBounds`, etc. — serialize as **custom binary
  payloads** that are NOT a tagged-property sequence.

**Paksmith status: `partial`.** The tagged-tree case is handled
completely; native-struct bodies cause `read_properties` to error on
the first invalid name lookup, which bubbles to the enclosing export
and triggers the `PropertyBag::Tree → Opaque` fallback (with a
`tracing::warn!` event). The asset still parses; the property tree
just isn't materialized when a native struct is involved.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| `FileVersionUE4 ≥ 504` | `StructProperty` shape stable. | `CUE4Parse/UE4/Assets/Objects/Properties/StructProperty.cs@<CUE4PARSE_SHA>`[^1] |

Native struct binary layouts have changed across UE versions
(notably FVector / FRotator / FQuat moved from f32 to f64 in UE 5.0
via `LWC_FLOAT_AND_VECTOR`). When paksmith specializes native
structs (deferred work), each native type will document its own
version-conditional shape.

## Wire layout

### Tag-side (from `FPropertyTag`)

| field | size | source | semantics |
|-------|------|--------|-----------|
| `struct_name` | 8 | tag.struct_name (FName) | Struct type name (e.g. `"Vector"`, `"MyStruct"`). |
| `struct_guid` | 16 | tag.struct_guid | Per-type identifier; zero for most structs. |

### Body — user-defined struct case

The body is a tagged-property sequence terminated by a `"None"` tag,
identical in shape to the parent export body's tagged stream. See
[`tagged.md`](tagged.md) for the iteration mechanics. Recursion is
bounded by `MAX_PROPERTY_DEPTH = 128` and by the struct's declared
`tag.size` (the `expected_end` parameter of `read_properties`).

### Body — native struct case

The body is a custom binary blob whose layout is defined by the
engine's `StructOps::SerializeNative` for the struct type. Common
native types and their canonical binary shapes:

| `struct_name` | Wire bytes | Source |
|---------------|------------|--------|
| `Vector` | 3 × `f32` (UE4) or 3 × `f64` (UE5 LWC) = 12 or 24 bytes | `CUE4Parse/UE4/Objects/Core/Math/FVector.cs`[^1] |
| `Rotator` | 3 × `f32` / `f64` | Same[^1] |
| `Quat` | 4 × `f32` / `f64` | Same[^1] |
| `Vector2D` | 2 × `f32` / `f64` | Same[^1] |
| `Vector4` | 4 × `f32` / `f64` | Same[^1] |
| `Transform` | `Quat rotation + Vector translation + Vector scale` | Same[^1] |
| `Color` | 4 × `u8` (B, G, R, A) | Same[^1] |
| `LinearColor` | 4 × `f32` (R, G, B, A) | Same[^1] |
| `Box` | 2 × `Vector` + `u8` IsValid | Same[^1] |
| `Guid` | 4 × `u32` (16 bytes) | See [`../primitive/fguid.md`](../primitive/fguid.md). |
| `GameplayTag` | `FName` tag_name (8 bytes) | `CUE4Parse/UE4/Objects/GameplayTags/FGameplayTag.cs`[^1] |
| `IntPoint` | 2 × `i32` | Same[^1] |
| `IntVector` | 3 × `i32` | Same[^1] |

(This table is **reference material**, not what paksmith currently
parses. Native-struct specialization is deferred — see Caps & limits
and Paksmith implementation.)

## Variants

### User-defined struct body (current paksmith coverage)

```rust
read_struct_value(tag, reader, ctx, depth, expected_end, asset_path):
    read_properties(reader, ctx, depth + 1, expected_end, asset_path)
        // → Vec<Property> until "None" terminator
```

`expected_end = value_start + tag.size`. Recursion depth bounded by
`MAX_PROPERTY_DEPTH`.

### Native-struct body (paksmith fallback)

When `read_properties` enters a native struct body, the first
"property tag" it tries to decode is actually the first u64 of the
native binary payload (e.g. FVector's X component). The decoded
name FName usually points OOB or to a garbage name; either way,
the iterator errors with `AssetParseFault::PackageIndexOob` (FName
lookup) or `AssetParseFault::FStringMalformed` (if the FName
resolution path reads bytes downstream).

The export's `PropertyBag::Tree` build aborts, the export's bag
becomes `Opaque`, and a `tracing::warn!` is emitted with the
struct's `struct_name` so operators can see which native type
caused the fallback.

## Caps & limits

- **`MAX_PROPERTY_DEPTH = 128`** — applies to user-struct recursion.
- **`MAX_PROPERTY_TAG_SIZE = 16 MiB`** — applies to the enclosing
  tag's `Size` field; native-struct bodies that fit a struct (~tens
  of bytes typically) never approach this cap.
- **No native-struct-specific caps** because no native-struct reader
  is implemented yet.

## Verification

- **Fixtures:**
  - `tests/fixtures/minimal_uasset_v5_with_extended_types.uasset` —
    exercises a user-defined struct (Phase 2c).
  - `(none yet)` for native-struct coverage — pending Phase 3+ work
    on native-struct specialization.
- **Cross-validation oracle:** CUE4Parse[^1] and `unreal_asset`[^2].
  Both handle the full native-struct catalog. paksmith's user-struct
  decode round-trips against both; the native-struct fallback is a
  paksmith-specific limitation.
- **Known divergences:**
  - **Native-struct fallback to Opaque.** Documented above. The
    nearest UE-version analog: this paksmith behavior is closest to
    "every struct treated as USTRUCT" in older CUE4Parse releases
    before the native-struct catalog was filled in; modern CUE4Parse
    and unreal_asset both specialize the natives.

## Paksmith implementation

**Parser module:** `crates/paksmith-core/src/asset/property/containers.rs`
(`read_struct_value`).

**Status:** `partial`. User-defined struct bodies decode completely;
native-struct bodies trigger the export-level `Tree → Opaque`
fallback.

**Public surface:**
- `PropertyValue::Struct { struct_name: String, properties: Vec<Property> }`.
- `read_container_value` dispatches to internal `read_struct_value`
  when `tag.type_name == "StructProperty"`.

**Error variants:**
- Indirect: native-struct bodies trigger upstream errors
  (`AssetParseFault::PackageIndexOob`, `FStringMalformed`, etc.)
  that the export's catch-fallback turns into `Opaque`.
- `AssetParseFault::PropertyDepthExceeded` for user-struct recursion.

**Phase plan:**
- User-struct support (current): `docs/plans/phase-2c-container-properties.md`.
- Native-struct specialization: deferred, no phase plan yet. Likely
  Phase 3+ alongside texture / mesh / animation handlers that need
  FVector / FTransform / FQuat for cooked content.

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Objects/Properties/StructProperty.cs@<CUE4PARSE_SHA>` plus the per-native-type files in `CUE4Parse/UE4/Objects/Core/Math/` and `CUE4Parse/UE4/Objects/GameplayTags/`. These are the references the native-struct specialization work will cite once implemented.
[^2]: `AstralOrigin/unreal_asset/unreal_asset/src/properties/struct_property.rs@<UNREAL_ASSET_SHA>` — Rust oracle. Specializes the native catalog; paksmith's user-struct decode is consistent with the non-native path.
````

- [ ] **Step 5: Commit** (preamble convention — required-headings linter must pass before commit)

```bash
git add docs/formats/property/struct.md
git commit -m "$(cat <<'EOF'
docs(formats): add StructProperty partial reference

Documents the two struct body shapes: user-defined structs as a
recursive tagged-property tree (handled), and native UE structs
with custom binary serialization (fall through to export-level
Opaque). Catalogs the common native types (Vector/Rotator/Quat/
Color/LinearColor/Transform/GameplayTag/Guid/...) as reference
material for the deferred Phase 3+ native-struct specialization.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: Author `docs/formats/property/text.md` (partial)

FText is a history-discriminated localization record. Paksmith handles
`ETextHistoryType::None` and `::Base`; other history types fall through
to `FTextHistory::Unknown { history_type, skipped_bytes }`.

**Files:**
- Create: `docs/formats/property/text.md`

**Ground truth references:**
- `crates/paksmith-core/src/asset/property/text.rs` (265 lines) — `FText`, `FTextHistory`, `read_ftext`.

- [ ] **Step 1: Read the parser**

Run: `cat crates/paksmith-core/src/asset/property/text.rs`

- [ ] **Step 3: Capture a fresh hex anchor**

Run: `xxd tests/fixtures/minimal_uasset_v5_with_extended_types.uasset | head -30`
Find the FText body (begins with `u32 flags` + `i8 history_type` after
the tag header).

- [ ] **Step 4: Write the doc**

Write `docs/formats/property/text.md`:

````markdown
# TextProperty (`FText`)

> UE's localization-aware text property — a discriminated union over
> `ETextHistoryType` carrying a namespace / key / source string for
> localized content, an invariant string for non-localized content, or
> a more complex history record (formatted text, ordered-argument
> substitution, etc.) for derived text.

## Overview

`FText` is UE's text-with-localization-context type. Unlike `FString`
(see [`../primitive/fstring.md`](../primitive/fstring.md)), FText
carries the metadata needed to look up the displayed string in the
runtime localization tables: namespace, key, and the raw source
string that serves as a fallback if localization data is missing.

The wire shape is a `u32 flags` field followed by an `i8 history_type`
discriminant, followed by a history-specific body. Paksmith handles
the two most common variants — `None` (culture-invariant string) and
`Base` (the canonical namespace/key/source triple). Other variants
(`NamedFormat`, `OrderedFormat`, `ArgumentFormat`, `AsNumber`,
`AsPercent`, `AsCurrency`, `AsDate`, `AsTime`, `AsDateTime`,
`Transform`, `StringTableEntry`, `TextGenerator`) are stored as
`FTextHistory::Unknown { history_type, skipped_bytes }` — the wire is
consumed so downstream fields stay aligned, but the value isn't
decoded.

**Paksmith status: `partial`.** `None` and `Base` cover the vast
majority of cooked content; the unhandled variants appear mostly for
UI text with runtime formatting (player names interpolated into
dialog, dates rendered for the user's locale, etc.). Phase 3+ work
may specialize the format variants as part of UI / dialog asset
support.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| `FileVersionUE4 ≥ 504` | `(u32 flags, i8 history_type, body)` shape stable. | `CUE4Parse/UE4/Objects/Core/i18N/FText.cs@<CUE4PARSE_SHA>`[^1] |

Some history-variant bodies have version-conditional fields (e.g.
`AsNumber` formatting options); paksmith doesn't decode those
bodies, so the version conditionals don't bite within the supported
range.

## Wire layout

### Outer record

| field | size | type | semantics |
|-------|------|------|-----------|
| `flags` | 4 | `u32` LE | `ETextFlag` mask — Transient, CultureInvariant, ConvertedProperty, Immutable, InitializedFromString. Stored but mostly informational. |
| `history_type` | 1 | `i8` | `ETextHistoryType` discriminant. `-1` → `None`, `0` → `Base`, other values → variants paksmith doesn't decode. |
| `body` | variable | — | History-specific body; layout depends on `history_type`. |

### `history_type == -1` (`None`)

| field | size | type | semantics |
|-------|------|------|-----------|
| `has_culture_invariant` | 4 | `i32` LE | Non-zero → read `culture_invariant`. (Some FText writers emit `1`, some emit no body at all when there's no invariant string.) |
| `culture_invariant` | variable | `FString` | Present iff `has_culture_invariant != 0`. |

`PropertyValue::Text(FText { flags, history: FTextHistory::None { culture_invariant: Option<String> } })`.

### `history_type == 0` (`Base`)

| field | size | type | semantics |
|-------|------|------|-----------|
| `namespace` | variable | `FString` | Localization namespace (often empty for non-localized strings). |
| `key` | variable | `FString` | Localization key. |
| `source_string` | variable | `FString` | The raw source string (the English original by convention). |

`PropertyValue::Text(FText { flags, history: FTextHistory::Base { namespace, key, source_string } })`.

### Other `history_type` values

Body parsed as `tag_size - <bytes_already_consumed>` opaque bytes and
discarded; surfaces as `FTextHistory::Unknown { history_type, skipped_bytes }`.

The discriminants and their UE names (for reference; paksmith doesn't
decode them):

| Value | Name |
|-------|------|
| 1 | `NamedFormat` |
| 2 | `OrderedFormat` |
| 3 | `ArgumentFormat` |
| 4 | `AsNumber` |
| 5 | `AsPercent` |
| 6 | `AsCurrency` |
| 7 | `AsDate` |
| 8 | `AsTime` |
| 9 | `AsDateTime` |
| 10 | `Transform` |
| 11 | `StringTableEntry` |
| 12 | `TextGenerator` |

### Worked example: first FText body

```bash
xxd tests/fixtures/minimal_uasset_v5_with_extended_types.uasset | head -30
```

The first TextProperty body begins with `u32 flags` followed by
`i8 history_type`. The history-specific body follows; the easiest
anchor is a `Base`-history text (most cooked content) starting with
an FString namespace.

*(Re-run Step 3 to capture exact bytes.)*

## Variants

See the Wire layout section's discriminant breakdown.

### Empty culture-invariant string

`history_type == -1` with `has_culture_invariant == 0` is the most
compact FText — 5 bytes total (`u32 flags + i8 history_type`). Common
for editor-side default values that don't carry localization context.

## Caps & limits

- **`tag.size`** — the enclosing tag publishes the FText body's byte
  size; `read_ftext` accepts it as a hard cap on how many bytes
  history-body reads can consume. An unknown history that declares a
  body larger than `tag.size - 5` is rejected before the skip
  consumes bytes past the property boundary.
- **`FSTRING_MAX_LEN = 65,536`** — applies to each FString field
  inside the FText body (namespace, key, source_string, culture
  invariant).

## Verification

- **Fixture:** `tests/fixtures/minimal_uasset_v5_with_extended_types.uasset`
  carries `Base`-history TextProperty entries (Phase 2d coverage).
- **Cross-validation oracle:** CUE4Parse[^1] and `unreal_asset`[^2].
  Both handle the full history-type catalog. Paksmith's
  None+Base coverage round-trips against both; the
  Unknown-history fallback is a paksmith-specific limitation.
- **Known divergences:**
  - **History-variant coverage.** Paksmith decodes `None` and `Base`
    typed; the other 12 variants surface as `Unknown { history_type, skipped_bytes }`.
    CUE4Parse and unreal_asset specialize the format variants.
    Practical impact: gameplay text (`Base`) and editor defaults
    (`None`) decode; runtime-formatted UI text doesn't.

## Paksmith implementation

**Parser module:** `crates/paksmith-core/src/asset/property/text.rs`.

**Status:** `partial`. `FTextHistory::None` and `Base` decode typed;
other variants → `FTextHistory::Unknown`.

**Public surface:**
- `pub struct FText { pub flags: u32, pub history: FTextHistory }`.
- `pub enum FTextHistory` (`#[non_exhaustive]`) — `None`, `Base`,
  `Unknown`.
- `pub fn read_ftext<R: Read + Seek>(reader, ctx, asset_path, tag_size) -> Result<FText>`.

**Error variants:**
- `AssetParseFault::UnexpectedEof { field }`.
- `AssetParseFault::FStringMalformed { kind }` (from any FString field).

**Phase plan:**
- None + Base: `docs/plans/phase-2b-tagged-properties.md` (Task 5).
- Other history variants: deferred, no phase plan yet. Likely
  Phase 3+ alongside UI / dialog asset handlers.

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Objects/Core/i18N/FText.cs@<CUE4PARSE_SHA>` — primary oracle. Documents every `ETextHistoryType` variant's body layout.
[^2]: `AstralOrigin/unreal_asset/unreal_asset/src/properties/text_property.rs@<UNREAL_ASSET_SHA>` — Rust oracle.
````

- [ ] **Step 5: Commit** (preamble convention — required-headings linter must pass before commit)

```bash
git add docs/formats/property/text.md
git commit -m "$(cat <<'EOF'
docs(formats): add TextProperty partial reference

Documents the FText outer record (u32 flags + i8 history_type +
history-specific body) and paksmith's None+Base coverage of the
ETextHistoryType variants. Catalogs the 12 unhandled variants
(NamedFormat through TextGenerator) as reference material for the
deferred specialization work. Cooked-content TextProperty entries
overwhelmingly use Base; unhandled variants surface as
FTextHistory::Unknown.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: Author `docs/formats/property/unversioned.md` (partial)

UE5's schema-driven property serialization. Paksmith rejects packages
with `PKG_UnversionedProperties` at the summary level. Phase 2f scopes
the unversioned reader + `.usmap` mapping-file loader. Every H2 section
is present with prose, but Wire layout / Variants / Caps explicitly mark
unimplemented with "To be authored alongside the Phase 2f parser" —
that matches `partial`, not `stub`, per the spec's status enum.

**Files:**
- Create: `docs/formats/property/unversioned.md`

**Oracle:** `CUE4Parse/UE4/Assets/Readers/FUnversionedReader.cs` (primary). `trumank/repak` doesn't parse asset content; `unreal_asset` partially handles unversioned with mappings (referenced for the Phase 2f planning).

- [ ] **Step 2: Write the doc**

Write `docs/formats/property/unversioned.md`:

````markdown
# Unversioned property serialization

> UE5 schema-driven property serialization — properties encoded as a
> compact bitstream of "which fields are present" + raw bodies, with
> the field schema living in a sibling `.usmap` mapping file.

## Overview

UE5 cooked shipping builds may opt into **unversioned** property
serialization (via the `PKG_UnversionedProperties = 0x2000` package
flag) instead of the tagged scheme (see [`tagged.md`](tagged.md)).
In unversioned mode, each export body is a tightly-packed bitstream
of fragments — each fragment publishing a `(skip_count, value_count,
has_zero, is_last)` 4-tuple — followed by raw per-property bodies
in declared order. The reader needs the class schema to know what
each body's wire shape is; the schema is not on disk in the asset
itself but in a sibling `.usmap` file produced by an engine
commandlet.

**Paksmith status: `partial`.** Phase 2f scopes both the `.usmap`
loader and the unversioned bitstream reader. Until that work lands,
paksmith rejects packages with `PKG_UnversionedProperties` at the
summary level with
`AssetParseFault::UnversionedPropertiesUnsupported`.

This doc reserves the inventory slot and sketches the high-level
shape; Wire layout / Variants / Caps sections carry explicit TODO
markers pending the Phase 2f implementation.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| `FileVersionUE5 ≥ 1000` | Unversioned serialization introduced as an opt-in. | `CUE4Parse/UE4/Assets/Readers/FUnversionedReader.cs@<CUE4PARSE_SHA>`[^1] |

## Wire layout

To be authored alongside the Phase 2f parser. Sketch:

- Fragment header sequence — each fragment a packed 16-bit value
  encoding `(skip_count, value_count, has_zero, is_last)`.
- Per-property value bodies — wire shape per property type, in the
  order published by the `.usmap` for the export's class.
- Sparse-encoding: properties with zero values are recorded as
  "has_zero" but emit no body.

The `.usmap` mapping file has its own wire format (header + enum
table + class table with per-property type descriptors); that
format will be documented as a sibling doc or as a section of this
doc when the loader lands.

## Variants

To be authored. Known variants include early-UE5 (1000–1004) vs
later-UE5 fragment-header encoding tweaks; specifics live in
CUE4Parse[^1].

## Caps & limits

To be defined alongside the Phase 2f reader. The pak-side and
tagged-side cap discipline (per-export property count, allocation
caps, depth caps) will carry over with appropriate name changes
(`MAX_FRAGMENTS_PER_EXPORT` likely, mirroring `MAX_TAGS_PER_EXPORT`).

## Verification

- **Fixture:** `(none yet — Phase 2f deliverable)`.
- **Cross-validation oracle:** CUE4Parse[^1] (primary) and
  `unreal_asset`[^2]. Phase 2f will cross-validate paksmith against
  both.
- **Known divergences:** none yet — no implementation to diverge.

## Paksmith implementation

**Parser module:** *(not yet implemented — planned under
`crates/paksmith-core/src/asset/property/unversioned.rs` + a new
`crates/paksmith-core/src/asset/mappings/` module for the `.usmap`
loader).*

**Status:** `not impl`. Packages with
`PKG_UnversionedProperties` are rejected at the summary level
(`AssetParseFault::UnversionedPropertiesUnsupported`).

**Phase plan:** `docs/plans/phase-2f-unversioned-properties.md`.

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Readers/FUnversionedReader.cs@<CUE4PARSE_SHA>` — primary oracle for the unversioned bitstream layout. Phase 2f will cite specific subfiles (`FFragment`, `FUsmapMap`, etc.) when this doc fills in.
[^2]: `AstralOrigin/unreal_asset/unreal_asset/src/unversioned/mod.rs@<UNREAL_ASSET_SHA>` — Rust oracle; partially handles unversioned with mappings, used as the Phase 2f planning reference.
````

- [ ] **Step 3: Commit** (preamble convention — required-headings linter must pass before commit)

```bash
git add docs/formats/property/unversioned.md
git commit -m "$(cat <<'EOF'
docs(formats): add unversioned-property partial doc

All eight H2 sections present (linter requirement); Wire layout,
Variants, and Caps carry explicit TODO markers — partial, not
stub, per the spec's status enum. Sketches the fragment-header
bitstream shape and the .usmap dependency; full byte-level detail
deferred to the Phase 2f implementation PR.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: Update root inventory + final verification + push

**Files:**
- Modify: `docs/formats/README.md`

- [ ] **Step 2: Add six rows to the inventory**

Verify the existing inventory layout with `grep -n "^|" docs/formats/README.md`, then use the Edit tool to insert six new rows.

Rows to insert:

```markdown
| `property/tagged.md` | complete | complete | `asset/property/tag.rs` | CUE4Parse @ `<CUE4PARSE_SHA>` | `<SHA>` |
| `property/primitives.md` | complete | complete | `asset/property/primitives.rs` | CUE4Parse @ `<CUE4PARSE_SHA>` | `<SHA>` |
| `property/containers.md` | complete | complete | `asset/property/containers.rs` | CUE4Parse @ `<CUE4PARSE_SHA>` | `<SHA>` |
| `property/struct.md` | partial | partial | `asset/property/containers.rs` | CUE4Parse @ `<CUE4PARSE_SHA>` | `<SHA>` |
| `property/text.md` | partial | partial | `asset/property/text.rs` | CUE4Parse @ `<CUE4PARSE_SHA>` | `<SHA>` |
| `property/unversioned.md` | partial | not impl | — | CUE4Parse @ `<CUE4PARSE_SHA>` | n/a |
```

Three `complete | complete`, two `partial | partial`, one `partial | not impl`.

- [ ] **Step 8: Commit the inventory update**

```bash
git add docs/formats/README.md
git commit -m "$(cat <<'EOF'
docs(formats): register the property-family docs in the inventory

Six rows: three complete-complete (tagged, primitives, containers),
two partial-partial (struct — user-tagged handled, native falls
through; text — None+Base handled, other history variants Unknown),
and one partial-not-impl (unversioned — Phase 2f scopes the reader
+ .usmap loader). Last-verified anchor for the five-implemented
docs is this branch's HEAD.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

```
<sha> docs(formats): register the property-family docs in the inventory
<sha> docs(formats): add unversioned-property stub
<sha> docs(formats): add TextProperty partial reference
<sha> docs(formats): add StructProperty partial reference
<sha> docs(formats): add container property reference
<sha> docs(formats): add primitive property reference
<sha> docs(formats): add FPropertyTag tagged-serialization reference
```

- [ ] **Step 11: Open the PR**

Title: `docs(formats): populate property family (tagged/unversioned/primitives/containers/struct/text)`

Body — write to a tempfile first, then `gh pr create --body-file <tempfile>`:

```markdown
## Summary

Lands PR 5 of the UE format documentation framework. Populates
`docs/formats/property/` with six documents:

- **`tagged.md`** — `FPropertyTag` wire reader (Name + Type + Size +
  ArrayIndex + type-extras + HasPropertyGuid + optional GUID), the
  iteration loop, the three caps, the parse-error → Opaque fallback.
- **`primitives.md`** — ~16 primitive property types with body
  shapes, PropertyValue variants, and the UE5 1007+ SoftObject
  rejection.
- **`containers.md`** — Array/Map/Set with the delta-prefix discard
  behavior and the MAX_COLLECTION_ELEMENTS = 65,536 cap.
- **`struct.md`** *(partial)* — user-tagged structs decode
  completely; native UE structs (FVector/FRotator/FQuat/...) cause
  export-level Opaque fallback. Native-type catalog included as
  reference material for the deferred Phase 3+ specialization work.
- **`text.md`** *(partial)* — FText with None+Base history typed;
  the other 12 ETextHistoryType variants surface as Unknown.
- **`unversioned.md`** *(partial)* — Phase 2f deliverable; the doc
  reserves the inventory slot and sketches the fragment-bitstream +
  .usmap-loader shape. Wire layout / Variants / Caps carry explicit
  TODO markers pending implementation.

Six rows added to the root inventory: three `complete | complete`,
two `partial | partial`, one `partial | not impl`.

## Linked issue

(none — design spec drives this work)

## Test plan

- [x] `paksmith-doc-lint required-headings` passes on all docs.
- [x] `paksmith-doc-lint status-enum` passes on the updated inventory.
- [x] `typos docs/formats/property/` clean.
- [x] `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features` clean.
- [x] Cross-validated every wire-format claim against CUE4Parse + unreal_asset.

## Pre-flight checklist

- [x] PR title is a Conventional Commit.
- [x] Branch name follows `<type>/<kebab-case>`.
- [x] `cargo fmt --all` clean (no Rust changed).
- [x] `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean.
- [x] Documentation updated (this PR IS documentation).
- [x] No `unsafe` introduced.
- [x] Touched a parser? No — pure docs PR.

## Security considerations

None directly — pure documentation. Each doc spells out paksmith's
security posture:
- `tagged.md`: every cap (`MAX_PROPERTY_TAG_SIZE`, `MAX_TAGS_PER_EXPORT`,
  `MAX_PROPERTY_DEPTH`) referenced.
- `containers.md`: `MAX_COLLECTION_ELEMENTS` and its five CollectionKind
  discriminants.
- `primitives.md`: SoftObject and ObjectProperty rejection paths.
- `struct.md` / `text.md`: graceful-fallback behavior documented (no
  attacker-controlled overread on unhandled variants — the parent
  tag's `Size` bounds the skip).
- `unversioned.md`: explicit "rejected at summary level" today; no
  attack surface until the Phase 2f reader lands.

## Notes for reviewers

- `struct.md` and `text.md` are `partial | partial` — the
  most-honest pairing given paksmith's actual coverage. The wire
  shape is partially documented (user-tagged structs / None+Base
  history) and the parser is partial in the same way.
- `unversioned.md` is `partial | not impl`. The Caps and Wire
  layout sections explicitly note "To be authored alongside the
  Phase 2f parser" — those prose-form TODOs make this `partial`
  rather than `stub` per the spec's status enum (a true stub would
  be 1–2 paragraphs + references; this doc has all 8 sections
  filled with TODO-marked content).
- The `tagged.md` worked-example block uses
  `tests/fixtures/minimal_uasset_v5_with_properties.uasset`. The
  `containers.md` example uses `_with_containers.uasset`. The
  `struct.md` and `text.md` examples both use
  `_with_extended_types.uasset` (Phase 2d coverage).
```

---

## Done criteria

Per [PREAMBLE.md](2026-05-19-ue-format-docs-PREAMBLE.md)'s tail (linters green, typos clean, rustdoc clean, PR open, reviewer panel converged), plus this plan's inventory specifics enumerated above.
  (tagged, primitives, containers), two `partial | partial` (struct,
  text), one `partial | not impl` (unversioned).
