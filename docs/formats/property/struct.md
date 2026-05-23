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
| `FileVersionUE4 ≥ 504` | `StructProperty` shape stable. | `CUE4Parse/UE4/Assets/Objects/Properties/StructProperty.cs@ecc4878950336126f125af0747190edf474b2a21`[^1] |

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

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Objects/Properties/StructProperty.cs@ecc4878950336126f125af0747190edf474b2a21` plus the per-native-type files in `CUE4Parse/UE4/Objects/Core/Math/` and `CUE4Parse/UE4/Objects/GameplayTags/`. These are the references the native-struct specialization work will cite once implemented.
[^2]: `AstralOrigin/unreal_asset/unreal_asset/src/properties/struct_property.rs@f4df5d8e75b1e184832384d1865f0b696b90a614` — Rust oracle. Specializes the native catalog; paksmith's user-struct decode is consistent with the non-native path.
