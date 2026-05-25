# Static parameter set (`FStaticParameterSet`)

> The bundle of static-permutation parameter overrides a material
> instance carries — boolean switches, RGBA component-mask flags,
> terrain-layer weight selectors, and material-layer stack overrides.
> Each "static" parameter, when changed from its parent's default,
> forces a new shader compilation (unlike dynamic parameter values
> which can be flipped at runtime).

## Overview

`FStaticParameterSet` is the binary-wire structure UE serializes
into `UMaterialInstance` exports for static-permutation overrides.
Each entry inside the set describes one parameter the instance has
chosen to override from its parent's default, gated by an
`bOverride` flag — and because changing any of them produces
different compiled shader bytecode, the instance must also carry
its own shader-map blob (`bHasStaticPermutationResource = true` in
the parent `UMaterialInstance`).

The set has four sub-arrays, each holding a different parameter
type:

1. **`StaticSwitchParameters`** (`FStaticSwitchParameter[]`) — boolean
   on/off switches (typically used to gate optional shader graph
   branches).
2. **`StaticComponentMaskParameters`** (`FStaticComponentMaskParameter[]`)
   — RGBA per-component-mask booleans (e.g. selecting which channel
   of a texture parameter to read).
3. **`TerrainLayerWeightParameters`** (`FStaticTerrainLayerWeightParameter[]`)
   — per-terrain-layer weightmap index overrides.
4. **`MaterialLayersParameters`** (`FStaticMaterialLayersParameter[]`,
   optional, gated by `FReleaseObjectVersion::MaterialLayersParameterSerializationRefactor`)
   — material-layer stack overrides.

Each per-parameter struct shares a common `FStaticParameterBase`
prefix (`ParameterInfo` + `bOverride` + `ExpressionGuid`) plus
type-specific value fields documented below.

The wire-format dispatch — direct binary read vs tagged-property
read — is gated by `FRenderingObjectVersion::MaterialAttributeLayerParameters`:

- **Pre-`MaterialAttributeLayerParameters`**: `FStaticParameterSet`
  serializes directly from the binary archive when
  `bHasStaticPermutationResource && Ver >= PURGED_FMATERIAL_COMPILE_OUTPUTS`
  (per [`material-instance.md`](material-instance.md) §*Segment 3*).
- **Post-`MaterialAttributeLayerParameters`**: `StaticParameters` is
  a tagged property (`StructProperty(FStaticParameterSet)`) inside
  the standard property stream, read via the `[StructFallback]`
  constructor (also valid for the `"StaticParametersRuntime"` alias
  property).

This doc covers the binary-read wire format; the tagged-property
read is mechanically identical to other StructProperty entries
(see [`../property/tagged.md`](../property/tagged.md) for the
property-iteration mechanics).

**Document status: complete.** Wire format documented in full for
the outer `FStaticParameterSet` (4 counted arrays with version-
conditional gating on the `MaterialLayersParameters` array), all 4
per-parameter sub-types, the shared `FStaticParameterBase` prefix,
and the underlying `FMaterialParameterInfo` (with its own
pre-vs-post-`MaterialAttributeLayerParameters` wire split). The
deeply-nested `FMaterialLayersFunctions` value inside
`FStaticMaterialLayersParameter` is identified by name; it carries
a single deprecated `KeyString: FString` field per CUE4Parse — a
parser implementer can decode it via the `FString` primitive
(see [`../primitive/fstring.md`](../primitive/fstring.md)).

**Paksmith parser status: `not impl`.** Phase 3+ deliverable. The
material-instance parser doesn't yet read the binary
`FStaticParameterSet`, and tagged-property surfaces of
`StaticParameters` fall through to `PropertyBag::Tree` carrying
opaque inner property bags.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| UE 4.0+ | `FStaticParameterSet` introduced with `StaticSwitchParameters` + `StaticComponentMaskParameters` + `TerrainLayerWeightParameters` arrays. Each entry's `ParameterInfo` is just an `FName` (8 bytes). | `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Exports/Material/UMaterialInstance.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d`[^1] |
| UE 4.18+ (`FReleaseObjectVersion::MaterialLayersParameterSerializationRefactor`) | Adds optional `MaterialLayersParameters` array tail; each entry's `FStaticMaterialLayersParameter` gains a serialized `FMaterialLayersFunctions Value`. | Same[^1] |
| UE 4.24+ (`FRenderingObjectVersion::MaterialAttributeLayerParameters`) | `FMaterialParameterInfo` widens from `FName` (8 bytes) to `FName + EMaterialParameterAssociation (u8) + Index (i32)` (13 bytes). The whole `FStaticParameterSet` also shifts to tagged-property serialization (`StaticParameters` / `StaticParametersRuntime` BoolProperty) — the direct binary read remains the wire path for pre-refactor content with `bHasStaticPermutationResource`. | `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Exports/Material/Parameters/FStaticParameterBase.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d`[^1] |
| Fortnite-main-branch (`FFortniteMainBranchObjectVersion::StaticParameterTerrainLayerWeightBlendType`) | `FStaticTerrainLayerWeightParameter` gains a leading `bWeightBasedBlend: bool` (4 bytes, UE archive convention) before `WeightmapIndex`. | `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Exports/Material/Parameters/FStaticTerrainLayerWeightParameter.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d`[^1] |

## Wire layout

### `FStaticParameterSet` (outer container)

| order | field | type | semantics |
|-------|-------|------|-----------|
| 1 | `StaticSwitchParameters` | `FStaticSwitchParameter[]` (counted) | i32 length prefix + per-entry records. |
| 2 | `StaticComponentMaskParameters` | `FStaticComponentMaskParameter[]` (counted) | Same shape; per-entry RGBA-component-mask records. |
| 3 | `TerrainLayerWeightParameters` | `FStaticTerrainLayerWeightParameter[]` (counted) | Per-terrain-layer weight overrides. |
| 4 | `MaterialLayersParameters` | `FStaticMaterialLayersParameter[]` (counted, optional) | Present only when `FReleaseObjectVersion >= MaterialLayersParameterSerializationRefactor`. |

Each array uses the standard `ReadArray` count-prefix pattern:
4-byte `i32` count followed by `count` × per-entry records. Counts
MUST be verified `>= 0` before cast to `usize` (see §*Implementation
hardening*).

### `FMaterialParameterInfo` (shared prefix sub-record)

| order | field | size | endian | type | semantics |
|-------|-------|------|--------|------|-----------|
| 1 | `Name` | 8 | LE | `FName` | Parameter name (see [`../primitive/fname.md`](../primitive/fname.md)). |
| 2 | `Association` (post-refactor only) | 1 | — | `u8` (`EMaterialParameterAssociation`) | `0` = `LayerParameter`, `1` = `BlendParameter`, `2` = `GlobalParameter`. |
| 3 | `Index` (post-refactor only) | 4 | LE | `i32` | Sub-index for layer/blend parameters; `-1` for global. |

Pre-`MaterialAttributeLayerParameters`: only `Name` (8 bytes total).
Post-`MaterialAttributeLayerParameters`: 13 bytes total.

### `FStaticParameterBase` (binary base for per-parameter records)

The base constructor reads only `ParameterInfo`; the `bOverride` and
`ExpressionGuid` fields appear in the per-subclass constructors,
serialized AFTER the type-specific value fields:

| order | field | type | semantics |
|-------|-------|------|-----------|
| 1 | `ParameterInfo` | `FMaterialParameterInfo` | 8 bytes pre-refactor / 13 bytes post-refactor (see table above). |

(`bOverride` and `ExpressionGuid` are documented in each subclass
below, after the type-specific value fields they follow.)

### `FStaticSwitchParameter` (post-refactor: 37 bytes)

| order | field | size | endian | type | semantics |
|-------|-------|------|--------|------|-----------|
| 1 | `ParameterInfo` | 13 (8 pre-refactor) | LE | `FMaterialParameterInfo` | See table above. |
| 2 | `Value` | 4 | LE | `bool` (UE archive convention via `Ar.ReadBoolean()` — reads `i32`, accepts only `0` or `1`) | The static switch value override. |
| 3 | `bOverride` | 4 | LE | `bool` (same convention) | Whether this entry actually overrides (some entries may be present but inactive). |
| 4 | `ExpressionGuid` | 16 | LE | `FGuid` | Identifies the source material expression node; 4-u32-LE layout per [`../primitive/fguid.md`](../primitive/fguid.md). |

Post-refactor total: 13 + 4 + 4 + 16 = **37 bytes**.

### `FStaticComponentMaskParameter` (post-refactor: 49 bytes)

| order | field | size | endian | type | semantics |
|-------|-------|------|--------|------|-----------|
| 1 | `ParameterInfo` | 13 (8 pre-refactor) | LE | `FMaterialParameterInfo` | See table above. |
| 2 | `R` | 4 | LE | `bool` | Red-channel mask. |
| 3 | `G` | 4 | LE | `bool` | Green-channel mask. |
| 4 | `B` | 4 | LE | `bool` | Blue-channel mask. |
| 5 | `A` | 4 | LE | `bool` | Alpha-channel mask. |
| 6 | `bOverride` | 4 | LE | `bool` | |
| 7 | `ExpressionGuid` | 16 | LE | `FGuid` | |

Post-refactor total: 13 + 4×4 + 4 + 16 = **49 bytes**. Each
component bool decodes to a 0/1 float when projected via
`ToFLinearColor()` (CUE4Parse helper); the wire shape is 4 × 4-byte
UE archive bools.

### `FStaticTerrainLayerWeightParameter` (post-refactor + Fortnite gate: 41 bytes)

| order | field | size | endian | type | semantics |
|-------|-------|------|--------|------|-----------|
| 1 | `ParameterInfo` | 13 (8 pre-refactor) | LE | `FMaterialParameterInfo` | See table above. |
| 2 | `bWeightBasedBlend` | 4 | LE | `bool` | **Conditional:** present only when `FFortniteMainBranchObjectVersion >= StaticParameterTerrainLayerWeightBlendType`. |
| 3 | `WeightmapIndex` | 4 | LE | `i32` | Index into the parent landscape's weightmap stack. |
| 4 | `bOverride` | 4 | LE | `bool` | |
| 5 | `ExpressionGuid` | 16 | LE | `FGuid` | |

Post-refactor + Fortnite-gate total: 13 + 4 + 4 + 4 + 16 = **41 bytes**.
Without the Fortnite gate: 13 + 4 + 4 + 16 = **37 bytes**.

### `FStaticMaterialLayersParameter` (33 + FString bytes when LayersFunctions gate active)

Note the constructor is structurally distinct from the other
`FStaticParameterBase` subclasses: it reads `ParameterInfo`,
`bOverride`, `ExpressionGuid` itself (not via the base constructor's
ParameterInfo-only path) before the conditional `Value`. Because it
does NOT call `base(Ar)`, it bypasses the version gate inside
`FStaticParameterBase(FArchive)` — the `ParameterInfo` width is
ALWAYS 13 bytes (the constructor calls
`new FMaterialParameterInfo(Ar)` directly, with no internal
version gate).

| order | field | size | endian | type | semantics |
|-------|-------|------|--------|------|-----------|
| 1 | `ParameterInfo` | 13 | LE | `FMaterialParameterInfo` | Always 13 bytes (no pre-refactor 8-byte path on this struct — `base(Ar)` is NOT called). |
| 2 | `bOverride` | 4 | LE | `bool` | |
| 3 | `ExpressionGuid` | 16 | LE | `FGuid` | |
| 4 | `Value` | variable | LE | `FMaterialLayersFunctions` | **Conditional:** present only when `FReleaseObjectVersion >= MaterialLayersParameterSerializationRefactor`. Reads `KeyString: FString` (deprecated; carries an opaque layer-functions identifier; see [`../primitive/fstring.md`](../primitive/fstring.md) for the FString primitive layout). |

Post-LayersFunctions-gate total: 13 + 4 + 16 + `FString
size` = **33 + FString bytes** (typically ~37-100+ bytes depending
on the `KeyString` length).

### Worked example — `FStaticSwitchParameter` (37 bytes, post-refactor)

A static switch entry overriding a parameter named (opaquely)
`MyParam` (8-byte FName placeholder), with `Value = true`,
`bOverride = true`, and a zero `ExpressionGuid`:

```
Offset (within entry)  Bytes (LE)                                       Field
---------------------  -----------------------------------------------  --------------------
+0                     <"MyParam" FName: 8 bytes opaque per fname.md>   ParameterInfo.Name
+8                     02                                                ParameterInfo.Association = 2 (GlobalParameter; u8)
+9                     FF FF FF FF                                      ParameterInfo.Index = -1 (i32 LE; global)
+13                    01 00 00 00                                      Value = 1 (u32 bool; ReadBoolean reads i32; switch ON)
+17                    01 00 00 00                                      bOverride = 1 (u32 bool; entry is active)
+21                    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ExpressionGuid = zero (16 bytes FGuid)
+37                                                                      (end of entry)
```

The pre-refactor variant (no `Association` + `Index`) is 32 bytes:
just `Name` (8 bytes) + `Value` (4) + `bOverride` (4) + `ExpressionGuid`
(16). A reader dispatches on `FRenderingObjectVersion` to choose
between the two paths.

## Variants

### Pre- vs post-`MaterialAttributeLayerParameters` (`FMaterialParameterInfo` width)

The most consequential variant axis. Pre-refactor: `ParameterInfo`
is just an 8-byte `FName`. Post-refactor: 13 bytes (`FName` + `u8` +
`i32`). Affects every per-parameter sub-record's offset table.

### Pre- vs post-`MaterialLayersParameterSerializationRefactor` (`MaterialLayersParameters` presence)

Pre-`MaterialLayersParameterSerializationRefactor`: `FStaticParameterSet`
has 3 arrays. Post: 4 arrays (with `MaterialLayersParameters` as
the 4th). The same gate also controls whether
`FStaticMaterialLayersParameter` reads its trailing `Value: FMaterialLayersFunctions`.

### Pre- vs post-`StaticParameterTerrainLayerWeightBlendType` (`bWeightBasedBlend` presence)

Affects `FStaticTerrainLayerWeightParameter` only. Pre: 33-37 bytes
depending on the `MaterialAttributeLayerParameters` gate. Post:
37-41 bytes with the extra leading bool.

### Binary vs tagged-property serialization

Per the §*Overview*, the outer `FStaticParameterSet` follows two
serialization paths gated on `FRenderingObjectVersion::MaterialAttributeLayerParameters`:

- **Direct binary read** — used pre-refactor when
  `bHasStaticPermutationResource == true` (the wire format
  documented in this doc).
- **Tagged-property read** — used post-refactor; the same
  `FStaticParameterSet` struct is invoked via `[StructFallback]`
  through the property-iterator pipeline. Same logical fields; the
  on-wire bytes are wrapped in `FPropertyTag` records per
  [`../property/tagged.md`](../property/tagged.md).

## Caps & limits

### Format-defined limits (wire-imposed)

- **Outer `FStaticParameterSet` array prefixes**: `i32` count
  prefix on each of the 4 (or 3) arrays.
- **`FMaterialParameterInfo.Name`**: 8 bytes (`FName` per
  [`../primitive/fname.md`](../primitive/fname.md)).
- **`FMaterialParameterInfo.Association`**: `u8`; documented values
  `0..=2` (`LayerParameter`, `BlendParameter`, `GlobalParameter`).
  Other values are wire-valid but undefined.
- **`FMaterialParameterInfo.Index`**: `i32`.
- **Per-parameter `bool` fields** (`Value`, `bOverride`, `R`/`G`/`B`/`A`,
  `bWeightBasedBlend`): 4 bytes each (UE archive convention via
  `Ar.ReadBoolean()` — reads `i32`, accepts only `0` or `1`).
- **`ExpressionGuid`**: fixed 16 bytes (`FGuid` per
  [`../primitive/fguid.md`](../primitive/fguid.md)).
- **`FStaticTerrainLayerWeightParameter.WeightmapIndex`**: `i32`.
- **`FStaticMaterialLayersParameter.Value.KeyString`**: variable-
  length `FString` capped at `FSTRING_MAX_LEN = 65,536` characters
  per [`../primitive/fstring.md`](../primitive/fstring.md).

### Implementation hardening (recommended for any parser)

A `FStaticParameterSet` reader (paksmith does not yet have one)
MUST:

- **Verify all `i32` array count prefixes are non-negative** before
  any cast to `usize` or use as loop counter. The 4 outer arrays
  (`StaticSwitchParameters`, `StaticComponentMaskParameters`,
  `TerrainLayerWeightParameters`, `MaterialLayersParameters`) and
  `FStaticTerrainLayerWeightParameter.WeightmapIndex` are all
  signed on the wire and MUST be `>= 0`. Negative `i32 → usize`
  cast produces `usize::MAX`-adjacent values that bypass
  per-collection sanity checks.
- **Cross-validate `FMaterialParameterInfo.(Association, Index)`
  as a pair.** `Index` is `i32` and accepts `-1` as the sentinel
  for `GlobalParameter` (`Association == 2`); the doc's worked
  example uses exactly this combination. The correct rule is:
  when `Association == 0` (`LayerParameter`) or `Association == 1`
  (`BlendParameter`), `Index` MUST be `>= 0` (it's a sub-layer or
  blend-layer index). When `Association == 2` (`GlobalParameter`),
  `Index` MUST be `-1`. A reader that blindly rejects negative
  `Index` would false-reject every valid GlobalParameter entry;
  a reader that accepts negative `Index` without correlating
  against `Association` would let an attacker spoof a global
  parameter inside a layer-parameter slot.
- **Cap each array length** at `MAX_COLLECTION_ELEMENTS` (see
  `docs/security/allocation-caps.md`) — a malicious instance with
  `u32::MAX` `StaticSwitchParameters` would otherwise drive a
  37-byte × 4 GB allocation before bounds-checking kicks in.
- **Reject `Ar.ReadBoolean()` values outside `{0, 1}`** at every
  bool read site (`Value`, `bOverride`, `R`/`G`/`B`/`A`,
  `bWeightBasedBlend`). CUE4Parse's `ReadBoolean` throws
  `ParserException` on other values — paksmith should do the same.
  (UE's archive-level `ReadBoolean` is strict; some tagged-property
  `BoolProperty` paths accept any non-zero as true, but the binary
  reads documented in this doc use the strict archive convention.)
- **Validate `EMaterialParameterAssociation`** (`u8`) against the
  documented `{0, 1, 2}` set. Values `3..=255` SHOULD surface a
  typed warning (forward-compat — UE may add new association types
  without bumping the version constant).
- **Parent material-instance chain cycles** are detected at the
  `UMaterialInstance.Parent` chain layer, not here.
  `FStaticMaterialLayersParameter.Value` is an opaque
  `FMaterialLayersFunctions` with a single deprecated `KeyString:
  FString` field — flat, non-traversable, no recursive lookup
  involved. The cycle-detection MUST that previously appeared here
  was misplaced; the actual cycle hazard lives at
  [`material-instance.md`](material-instance.md) §*Implementation
  hardening* (the `Parent` package-index chain). No parse-time
  cycle work is required at this level.
- **For each per-parameter record**: track the cumulative byte
  count and verify the per-record total matches the expected
  per-version formula (37 / 49 / 41 / 33+ depending on subtype +
  version gates) before accepting the record. A drift indicates
  either corrupt input or an unsupported version-conditional field
  the parser doesn't know about.

See `docs/security/allocation-caps.md` for the broader policy.

## Verification

- **Fixture:** The 37-byte `FStaticSwitchParameter` Worked example
  above is byte-exact and self-contained (with the FName component
  treated as opaque per [`../primitive/fname.md`](../primitive/fname.md)).
  Real-cooked `FStaticParameterSet` fixtures with the full 4-array
  set are Phase 3 deliverables.
- **Hex anchor commands:**
  ```
  # Synthesize the post-refactor 37-byte FStaticSwitchParameter from
  # the Worked example (Value=true, bOverride=true, Association=
  # GlobalParameter, Index=-1, zero ExpressionGuid, FName placeholder):
  printf '\x00\x00\x00\x00\x00\x00\x00\x00\x02\xFF\xFF\xFF\xFF\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' | xxd
  ```
  (First 8 bytes = opaque FName placeholder per fname.md; remainder
  matches the Worked example table byte-for-byte.) A conformant
  `FStaticSwitchParameter` parser fed these 37 bytes MUST decode
  them as the values shown in the Worked example.
- **Cross-validation oracle:** CUE4Parse[^1] — the per-subclass
  constructors row-for-row in §*Wire layout* above.
- **Known divergences:** none — no paksmith implementation to
  diverge.

## Paksmith implementation

**Parser module:** *(not yet implemented — planned under
`crates/paksmith-core/src/asset/exports/material/static_parameter_set.rs`)*

**Status:** `not impl`. Encounters of `UMaterialInstance` exports
today parse the tagged-property segment; when the
`StaticParameters` property appears as an inner `StructProperty`,
it surfaces as a `PropertyBag::Tree` carrying opaque inner property
bags. The direct-binary-read path (pre-`MaterialAttributeLayerParameters`)
isn't reached because the parent material-instance parser falls
back to `PropertyBag::Opaque` before encountering it.

**Phase plan:** `docs/plans/ROADMAP.md` Phase 3 (Export Pipeline).
The `FStaticParameterSet` reader implementation lands as part of
the `UMaterialInstance` Phase 3 work; cross-references resolve to
the parameter-info `FName` and the source material expression's
`FGuid`.

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Exports/Material/UMaterialInstance.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` (defines `FStaticParameterSet` with the 4-array constructor and the `bHasStaticPermutationResource` direct-binary-read gate at `Deserialize`). Per-subtype constructors in the `Parameters/` subdirectory at the same SHA: `FStaticParameterBase.cs`, `FStaticSwitchParameter.cs`, `FStaticComponentMaskParameter.cs`, `FStaticTerrainLayerWeightParameter.cs`, `FStaticMaterialLayersParameter.cs`. `FMaterialParameterInfo.cs` in `Assets/Exports/Material/` covers the shared 8-or-13-byte parameter-info prefix.
