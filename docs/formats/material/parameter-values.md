# Parameter value structs (`FTextureParameterValue` / `FScalarParameterValue` / `FVectorParameterValue`)

> The three concrete per-parameter override structs a
> `UMaterialInstanceConstant` carries in its tagged-property
> arrays — texture, scalar (float), and vector (RGBA color)
> overrides. These are the dynamic-parameter counterparts to
> `FStaticParameterSet` entries: changing them does NOT require new
> shader compilation, only a runtime parameter rebind.

## Overview

A `UMaterialInstanceConstant` (the cooked-content
`UMaterialInstance` subclass) carries three tagged-property
arrays of parameter overrides:

- **`TextureParameterValues`** (`ArrayProperty<StructProperty(FTextureParameterValue)>`)
  — texture-asset references that override the parent material's
  default texture parameter samplers.
- **`ScalarParameterValues`** (`ArrayProperty<StructProperty(FScalarParameterValue)>`)
  — `f32` value overrides for scalar parameters (intensity, roughness
  multipliers, etc.).
- **`VectorParameterValues`** (`ArrayProperty<StructProperty(FVectorParameterValue)>`)
  — `FLinearColor` (RGBA × `f32`) overrides for vector parameters
  (tint colors, modulation vectors).

Each entry pairs a parameter identifier (`FMaterialParameterInfo` —
the shared 8-or-13-byte `FName + Association + Index` triple, see
[`static-parameter-set.md`](static-parameter-set.md)) with a
type-specific value plus an `ExpressionGuid` that ties back to
the parent material's expression-graph node.

These structs ALSO carry a legacy `FName ParameterName` field that
predates `FMaterialParameterInfo` but is still serialized in some
toolchains. CUE4Parse reads both and picks `ParameterName.IsNone`
to choose between them when displaying — both are valid name
sources on the wire, but only one is meaningful per entry.

The wire path is the standard tagged-property arrays — `ArrayProperty`
counted prefix + per-entry `StructProperty(<value-type>)` records
via the `[StructFallback]` constructor. Each StructFallback in turn
unwraps to the binary read documented below; CUE4Parse also exposes
direct binary constructors (`FArchive`-based) for paths that
bypass the property iterator.

**Document status: complete.** Wire format documented in full for
all three parameter-value structs (direct binary path) and the
two name-source fallback (`ParameterName` legacy FName vs
`ParameterInfo.Name`). The tagged-property path is mechanically
identical via the `[StructFallback]` constructor.

**Paksmith parser status: `not impl`.** Phase 3+ deliverable.
`UMaterialInstanceConstant` exports surface these arrays as inner
`PropertyBag::Tree` entries today; per-entry struct decoding is
not yet implemented.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| UE 4.0+ | All three structs introduced with a legacy `FName ParameterName` identifier. | `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Exports/Material/FTextureParameterValue.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d`[^1] |
| UE 4.24+ (`FRenderingObjectVersion::MaterialAttributeLayerParameters`) | `FMaterialParameterInfo` becomes the primary identifier (replacing the loose `ParameterName`). Wire shape gains an 8-byte `FName + EMaterialParameterAssociation (u8) + Index (i32)` triple = 13 bytes total. The legacy `ParameterName` field remains in the tagged-property surface but is empty in modern cooked content; the binary constructor reads ONLY `ParameterInfo`, not `ParameterName`. | Same[^1] |

The per-value field types (`FPackageIndex`, `f32`, `FLinearColor`)
have not changed across UE's lifetime.

## Wire layout

All three structs share a common binary-constructor pattern (the
shape used by direct `FArchive` reads as opposed to tagged-property
StructFallback reads):

```
ParameterInfo (13 bytes post-MaterialAttributeLayerParameters, 8 bytes pre)
+ <value-type-specific bytes>
+ ExpressionGUID (16 bytes FGuid)
```

The legacy `FName ParameterName` is NOT read by the binary
constructors — it only appears in the tagged-property `StructFallback`
path via `fallback.GetOrDefault<FName>("ParameterName")`.

### `FTextureParameterValue` (33 bytes binary path)

| order | field | size | endian | type | semantics |
|-------|-------|------|--------|------|-----------|
| 1 | `ParameterInfo` | 13 | LE | `FMaterialParameterInfo` | Always 13 bytes — see *FMaterialParameterInfo width note* below. |
| 2 | `ParameterValue` | 4 | LE | `FPackageIndex` | Reference to a `UTexture` import/export per [`../primitive/fpackage-index.md`](../primitive/fpackage-index.md). |
| 3 | `ExpressionGUID` | 16 | LE | `FGuid` | 4-u32-LE layout per [`../primitive/fguid.md`](../primitive/fguid.md). |

Total: 13 + 4 + 16 = **33 bytes**.

### `FScalarParameterValue` (33 bytes binary path)

| order | field | size | endian | type | semantics |
|-------|-------|------|--------|------|-----------|
| 1 | `ParameterInfo` | 13 | LE | `FMaterialParameterInfo` | Always 13 bytes — see *FMaterialParameterInfo width note* below. |
| 2 | `ParameterValue` | 4 | LE | `f32` | The override float value (e.g. `0.5` for half-intensity). |
| 3 | `ExpressionGUID` | 16 | LE | `FGuid` | |

Total: 13 + 4 + 16 = **33 bytes**.

### `FVectorParameterValue` (45 bytes binary path)

| order | field | size | endian | type | semantics |
|-------|-------|------|--------|------|-----------|
| 1 | `ParameterInfo` | 13 | LE | `FMaterialParameterInfo` | Always 13 bytes — see *FMaterialParameterInfo width note* below. |
| 2 | `ParameterValue` | 16 | LE | `FLinearColor` | 4 × `f32` RGBA. Stored as `(R, G, B, A)` in that order; each component is unbounded `f32` (typical tint colors are in `[0, 1]` but HDR values exceed `1.0`). |
| 3 | `ExpressionGUID` | 16 | LE | `FGuid` | |

Total: 13 + 16 + 16 = **45 bytes**.

#### `FMaterialParameterInfo` width note

Unlike the `FStaticParameterBase`-derived parameter structs (which
inherit a `FRenderingObjectVersion::MaterialAttributeLayerParameters`
version gate via `base(Ar)`), the three value-struct binary
constructors call `new FMaterialParameterInfo(Ar)` directly. That
constructor reads `Name + Association + Index` unconditionally —
no version gate. The binary path therefore ALWAYS produces a
13-byte `FMaterialParameterInfo`, regardless of UE version.

Pre-`MaterialAttributeLayerParameters` cooked content used a
legacy `FName ParameterName` field (per §*Versions* above) that
serialized through the tagged-property `StructFallback` path, not
via the binary constructor. A reader using the binary path doesn't
need a width-vs-version dispatch; a reader using the tagged-property
path consults the dual-name-source fallback (see below).

### Legacy `ParameterName` vs `ParameterInfo.Name` (tagged-property path)

The tagged-property `StructFallback` constructors of all three
structs read BOTH `ParameterName` (loose `FName`) and
`ParameterInfo` (`FMaterialParameterInfo`). The `Name` property
exposed by each struct resolves to:

```
Name = !ParameterName.IsNone ? ParameterName.Text : ParameterInfo.Name.Text
```

— in other words, the legacy `ParameterName` wins when present;
otherwise the `ParameterInfo.Name` is used. Modern (post-
`MaterialAttributeLayerParameters`) cooked content typically writes
only `ParameterInfo`; the `ParameterName` slot is left as
`FName::None` (which `IsNone` detects via the empty-FName
convention per [`../primitive/fname.md`](../primitive/fname.md)).

The binary-constructor path (`FArchive`-based) reads ONLY
`ParameterInfo` — there is no `ParameterName` read on that path.
A parser using the binary path doesn't need to handle the
fallback; the tagged-property path does.

### Worked example — `FScalarParameterValue` (33 bytes, post-refactor binary)

A scalar parameter override for an opaquely-named parameter
(`MyScalar`) with value `0.5` and zero `ExpressionGUID`:

```
Offset (within entry)  Bytes (LE)                                       Field
---------------------  -----------------------------------------------  --------------------
+0                     <"MyScalar" FName: 8 bytes opaque per fname.md>  ParameterInfo.Name
+8                     02                                                ParameterInfo.Association = 2 (GlobalParameter; u8)
+9                     FF FF FF FF                                      ParameterInfo.Index = -1 (i32 LE; global)
+13                    00 00 00 3F                                      ParameterValue = 0.5 (f32 LE; 0x3F000000)
+17                    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ExpressionGUID = zero (16 bytes FGuid)
+33                                                                      (end of entry)
```

(`0x3F000000` LE = f32 `0.5`; the IEEE-754 representation. See
[`../primitive/fcustom-version.md`](../primitive/fcustom-version.md)
for similar binary float anchors.)

The `FTextureParameterValue` 33-byte and `FVectorParameterValue`
45-byte examples follow the same prefix + value + GUID pattern;
substitute a 4-byte `FPackageIndex` (texture import index) or a
16-byte `FLinearColor` (4 × f32 RGBA) respectively for bytes
`+13..` in the worked example.

## Variants

### Binary vs tagged-property serialization

Per the §*Overview*, both paths exist:

- **Binary read** (`FArchive`-based constructor) — used when an
  outer reader chooses to decode the struct directly (rare in the
  `UMaterialInstanceConstant` cooked content path; the tagged-
  property path dominates). Reads ONLY `ParameterInfo` + `ParameterValue`
  + `ExpressionGUID`.
- **Tagged-property read** (`StructFallback` constructor) — the
  dominant path. Reads both `ParameterName` (legacy) and
  `ParameterInfo`; the `Name` resolution prefers `ParameterName`
  when not-none.

### Pre- vs post-`MaterialAttributeLayerParameters` (`ParameterInfo` width)

The same axis documented in
[`static-parameter-set.md`](static-parameter-set.md) §*Pre- vs
post-MaterialAttributeLayerParameters*. Affects every per-entry
struct by 5 bytes (8 → 13).

### Per-value type axis

The three structs share their layout shape but differ in the
`ParameterValue` field's type and width:

| Struct | `ParameterValue` type | Width |
|--------|----------------------|-------|
| `FTextureParameterValue` | `FPackageIndex` | 4 bytes |
| `FScalarParameterValue` | `f32` | 4 bytes |
| `FVectorParameterValue` | `FLinearColor` | 16 bytes |

Total struct widths: 33 / 33 / 45 bytes via the binary path
(unconditional — the value-struct binary constructors don't gate
on `MaterialAttributeLayerParameters`; see §*FMaterialParameterInfo
width note* above).

## Caps & limits

### Format-defined limits (wire-imposed)

- **`FMaterialParameterInfo`**: 13 bytes on the binary path (the
  value-struct binary constructors call `new FMaterialParameterInfo(Ar)`
  directly, no version gate — see §*FMaterialParameterInfo width
  note* above). On the tagged-property `StructFallback` path, the
  width matches whatever the property serializer emitted — pre-refactor
  cooked content typically writes the legacy `ParameterName` field
  instead of `ParameterInfo` entirely. See
  [`static-parameter-set.md`](static-parameter-set.md)
  §*FMaterialParameterInfo* for the broader 8-vs-13 picture (that
  axis applies to the static-parameter sub-structs, not to these
  value structs).
- **`FPackageIndex` (`FTextureParameterValue.ParameterValue`)**:
  4 bytes `i32`; max representable `i32::MAX`. Negative values
  refer to import-table entries; positive values to export-table
  entries (per [`../primitive/fpackage-index.md`](../primitive/fpackage-index.md)).
- **`f32` (`FScalarParameterValue.ParameterValue`)**: 4 bytes IEEE
  754 single-precision; any value is wire-valid (including `NaN`
  and `±inf`).
- **`FLinearColor` (`FVectorParameterValue.ParameterValue`)**: 16
  bytes (4 × `f32`); RGBA order. HDR values (components `> 1.0`)
  are valid; negative values are valid but unusual for tint colors.
- **`ExpressionGUID`**: fixed 16 bytes (`FGuid` per
  [`../primitive/fguid.md`](../primitive/fguid.md)).
- **Outer array prefixes** (`TextureParameterValues`,
  `ScalarParameterValues`, `VectorParameterValues`): tagged
  `ArrayProperty<StructProperty>` per
  [`../property/tagged.md`](../property/tagged.md); count prefix is
  `i32` LE inherited from the tagged-array convention.

### Implementation hardening (recommended for any parser)

A parameter-value reader (paksmith does not yet have one) MUST:

- **Cap outer array lengths** at `MAX_COLLECTION_ELEMENTS` (see
  `docs/security/allocation-caps.md`) — a malicious instance with
  `u32::MAX` `TextureParameterValues` would otherwise drive a
  33-byte × ~4 GB allocation before bounds-checking kicks in.
- **Verify the `i32` array count prefix is non-negative** before
  any cast to `usize` (sign-extension attack surface).
- **Validate `FPackageIndex` values** against the parent package's
  import/export table sizes before resolving the reference. An
  out-of-range package index is a wire-format-invalid texture
  reference; surface a typed `AssetParseFault::OutOfRangePackageIndex`
  rather than letting the lookup propagate an undefined object.
- **Treat `f32` values defensively**: `NaN` and `±inf` are
  wire-valid in `FScalarParameterValue.ParameterValue` and in any
  `FLinearColor` component, but downstream rendering / extraction
  code may panic on them. A reader SHOULD NOT reject these values
  at parse time but downstream consumers SHOULD normalize to a
  safe default before use.
- **Handle the dual-name-source fallback** (tagged-property path
  only): `Name = !ParameterName.IsNone ? ParameterName : ParameterInfo.Name`.
  A reader that uses one without falling back to the other will
  silently extract empty names for instances that write only one
  of the two name sources.
- **Validate `EMaterialParameterAssociation` and `Index` ranges**
  per the rules in [`static-parameter-set.md`](static-parameter-set.md)
  §*Implementation hardening*.

See `docs/security/allocation-caps.md` for the broader policy.

## Verification

- **Fixture:** The 33-byte `FScalarParameterValue` Worked example
  above is byte-exact and self-contained (with the FName component
  treated as opaque per [`../primitive/fname.md`](../primitive/fname.md)).
  Real-cooked `UMaterialInstanceConstant` fixtures with parameter
  overrides are Phase 3 deliverables.
- **Hex anchor commands:**
  ```
  # Synthesize the post-refactor 33-byte FScalarParameterValue from
  # the Worked example (ParameterValue=0.5, zero ExpressionGUID,
  # GlobalParameter association, Index=-1, FName placeholder):
  printf '\x00\x00\x00\x00\x00\x00\x00\x00\x02\xFF\xFF\xFF\xFF\x00\x00\x00\x3F\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' | xxd
  ```
  (First 8 bytes = opaque FName placeholder per fname.md; bytes
  +8..+12 are the 13-byte FMaterialParameterInfo's Association +
  Index; bytes +13..+16 are f32 LE `0.5` = `0x3F000000`; remaining
  16 bytes are the zero FGuid.) A conformant
  `FScalarParameterValue` parser fed these 33 bytes MUST decode
  them as the values shown in the Worked example.
- **Cross-validation oracle:** CUE4Parse[^1] — the per-struct
  constructors row-for-row in §*Wire layout* above.
- **Known divergences:** none — no paksmith implementation to
  diverge.

## Paksmith implementation

**Parser module:** *(not yet implemented — planned under
`crates/paksmith-core/src/asset/exports/material/parameter_values.rs`)*

**Status:** `not impl`. `UMaterialInstanceConstant` exports today
surface the parameter-value arrays as inner `PropertyBag::Tree`
entries (the outer `ArrayProperty<StructProperty>` is parsed by
the generic tagged-property iterator); per-entry struct decoding
into typed `FTextureParameterValue` / `FScalarParameterValue` /
`FVectorParameterValue` records is not yet implemented.

**Phase plan:** `docs/plans/ROADMAP.md` Phase 3 (Export Pipeline).
The parameter-value readers land as part of the
`UMaterialInstance` Phase 3 work; the public surface exposes the
parameter name + value triple for each entry without (yet)
resolving the `FPackageIndex` texture references to their actual
`UTexture` exports.

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Exports/Material/FTextureParameterValue.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d`, `FScalarParameterValue.cs`, and `FVectorParameterValue.cs` in the same directory — primary oracles for the per-struct binary + `StructFallback` constructors. `FMaterialParameterInfo.cs` at the same SHA covers the shared 8-or-13-byte parameter-info prefix.
