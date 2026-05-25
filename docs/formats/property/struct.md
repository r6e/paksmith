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

**Document status: complete.** Wire format documented in full
against CUE4Parse[^1] with worked examples below covering both the
user-defined (tagged-tree) case and the native-struct case (FVector).

**Paksmith parser status: `partial`.** The tagged-tree case is
handled completely; native-struct bodies cause `read_properties` to
error on the first invalid name lookup, which bubbles to the
enclosing export and triggers the `PropertyBag::Tree → Opaque`
fallback (with a `tracing::warn!` event). The asset still parses;
the property tree just isn't materialized when a native struct is
involved.

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

The tag-side `struct_name: FName` + `struct_guid: [u8; 16]` fields are documented in [`tagged.md`](tagged.md) §*Type extras dispatch*.

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

### Worked example — native `FVector` struct body (UE4)

Suppose a `StructProperty` named `Location` with `struct_name = "Vector"`
holding `FVector(1.0, 2.0, 3.0)` in UE4 (single-precision). The full
property record is the tag header + tag's type-extras (`struct_name` +
`struct_guid`) + body bytes. The body itself is 12 bytes:

```
Offset (within body)  Bytes (LE)              Field
--------------------  ----------------------  ---------------------
+0                    00 00 80 3F             X = 1.0 (f32 LE; IEEE 754)
+4                    00 00 00 40             Y = 2.0 (f32 LE)
+8                    00 00 40 40             Z = 3.0 (f32 LE)
+12                                            (end of body — 12 bytes)
```

The enclosing tag's `Size = 12`. Under UE5 LWC the same `FVector`
serializes as 24 bytes (3 × f64); the tag's `Size` field publishes
this to the reader.

### Worked example — user-defined struct body

Suppose a user-defined `USTRUCT()` named `FItemRow` with fields
`Value: float` and `Name: FString`, holding `{ Value = 1.5,
Name = "Iron" }`. The body is a tagged-property sequence terminated
by `"None"`:

```
+0                    <Property tag for "Value": FloatProperty>      25-byte tag header (see ../property/tagged.md)
+25                   00 00 C0 3F                                    f32 value = 1.5
+29                   <Property tag for "Name": StrProperty>         25-byte tag header
+54                   05 00 00 00 49 72 6F 6E 00                     FString len=5, "Iron\0"
+63                   <"None" terminator: 8-byte FName>              FName{ index=N_None, number=0 }
+71                                                                   (end of body — 71 bytes)
```

The enclosing tag's `Size = 71`. The recursive iteration is the
standard tagged-property mechanism — see
[`tagged.md`](tagged.md) for the per-tag byte structure.

## Variants

### User-defined struct body (current paksmith coverage)

See Wire layout §*Body — user-defined struct case*.

### Native-struct body (paksmith fallback)

The key failure-chain pivot: an out-of-bounds FName index (`PackageIndexOob`) or `FStringMalformed` error from mis-reading native binary payload as a tag name causes `PropertyBag::Tree` to abort and collapse to `Opaque`, with a `tracing::warn!` identifying the `struct_name`.

## Caps & limits

### Format-defined limits (wire-imposed)

- **Body size** is bounded by the enclosing tag's `Size: i32` field
  (`MAX_PROPERTY_TAG_SIZE = 16 MiB` per [`tagged.md`](tagged.md)).
- **Native-struct body sizes** are determined by the struct's
  `SerializeNative` impl — typically tens of bytes (FVector 12/24,
  FQuat 16/32, FTransform 40/80, FColor 4, FLinearColor 16).
- **User-struct recursion depth** is bounded only by the recursive
  arrangement of `StructProperty<StructProperty<...>>` —
  format-imposed maximum is whatever fits in the body's
  `tag.size` byte budget. No per-format depth cap.

### Implementation hardening (recommended for any parser)

- **Recursion depth cap.** User-defined struct bodies can nest
  arbitrarily deep. A robust parser MUST bound recursion to prevent
  stack overflow on adversarial input. Paksmith uses
  `MAX_PROPERTY_DEPTH = 128`. Surfaces as
  `AssetParseFault::PropertyDepthExceeded`.
- **Native-struct dispatch table.** Implementations that decode the
  native catalog (see Wire layout §*Body — native struct case* for
  the per-type byte counts) MUST gate the dispatch on `struct_name:
  FName` resolution AND validate the body byte count against the
  tag's declared `Size`. A mismatch indicates either an unknown
  native struct (fall through to user-struct or opaque) or a
  corrupted body — never silently truncate or over-read.
- **`tag.size` body-bound enforcement.** The body MUST be parsed
  within `[body_start, body_start + tag.size)`. Reading past the
  body bound is a wire-format violation; reading short of it leaves
  garbage bytes that the next property tag will misparse. Paksmith
  tracks `expected_end` and compares against `reader.stream_position()`
  at body end.
- **`Tree → Opaque` fallback policy.** A parser that doesn't yet
  cover native structs has two recovery strategies: (a) skip the
  unknown native struct's body by `tag.size` and continue, surfacing
  the property as `Unknown { struct_name }`; (b) collapse the entire
  enclosing export to opaque bytes (paksmith's current strategy).
  Strategy (a) preserves more of the property tree but is safe ONLY
  when `tag.size` has already been validated against
  `MAX_PROPERTY_TAG_SIZE` upstream (see
  [`tagged.md`](tagged.md) §*Caps & limits*); without that
  precondition an attacker-controlled `tag.size` could drive the
  cursor past export boundaries. Strategy (b) is safer when the
  parser cannot rely on the upstream cap.

## Verification

- **Fixtures:**
  - `tests/fixtures/minimal_uasset_v5_with_extended_types.uasset` —
    exercises a user-defined struct (Phase 2c).
  - Native-struct coverage uses the Worked example above; no
    separate fixture is needed (a 12-byte FVector body is small
    enough that the synthetic example IS the spec).
- **Hex anchor commands:**
  ```
  # Synthesize the FVector(1.0, 2.0, 3.0) body from the Worked example:
  printf '\x00\x00\x80\x3F\x00\x00\x00\x40\x00\x00\x40\x40' | xxd
  ```
  Any conformant parser fed these 12 bytes MUST decode them as
  `FVector { x: 1.0, y: 2.0, z: 3.0 }`.
- **Cross-validation oracle:** CUE4Parse[^1] and `unreal_asset`[^2].
  Both handle the full native-struct catalog. Paksmith's user-struct
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
(`read_struct_value`). StructProperty parsing lives in `containers.rs` alongside Array/Map/Set readers — see [`containers.md`](containers.md) for the dispatch entry point and collection-level interaction.

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

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Objects/Properties/StructProperty.cs@ecc4878950336126f125af0747190edf474b2a21` plus the per-native-type files in `CUE4Parse/UE4/Objects/Core/Math/` and `CUE4Parse/UE4/Objects/GameplayTags/`.
[^2]: `AstroTechies/unrealmodding/unreal_asset/unreal_asset_properties/src/struct_property.rs@f4df5d8e75b1e184832384d1865f0b696b90a614` — Rust oracle. Specializes the native catalog; paksmith's user-struct decode is consistent with the non-native path.
