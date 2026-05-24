# MaterialInstance (`UMaterialInstance` / `UMaterialInstanceConstant`)

> Cooked-content delta layer on top of a parent `UMaterial` —
> overrides specific parameter values, inherits everything else.

## Overview

A `UMaterialInstance` lets the same parent `UMaterial`'s shader graph
serve many visual variants without compiling new shaders. The instance
carries:

1. A reference to the parent `UMaterial` (or to another
   `UMaterialInstance`, supporting chains).
2. Per-parameter override entries (Texture / Scalar / Vector).
3. Base-property overrides (`BasePropertyOverrides` — locally
   overriding flags like `BlendMode`, `OpacityMaskClipValue`, etc.).
4. Static-parameter overrides (`StaticParameters` — static switches
   and component-mask overrides that DO require new shader compilation).

The shader graph is **not** duplicated — `UMaterialInstance` always
defers to its parent's compiled shader bytecode for rendering. This
is what makes instances cheap; instead of compiling a new shader for
each color variant, the engine uses the same shader with different
parameter binds.

The concrete subclass `UMaterialInstanceConstant` represents authored
static instances (the editor's "Create Material Instance Constant").
The parameter-override arrays (`TextureParameterValues`,
`ScalarParameterValues`, `VectorParameterValues`) live on
`UMaterialInstanceConstant`, not on `UMaterialInstance` itself.
`UMaterialInstanceDynamic` instances are runtime-created and don't
exist in cooked content.

**Status: not yet implemented in paksmith.** Phase 3+ deliverable.

## Versions

> Note: UE version numbers in the table are derived from community
> knowledge (UE release history). The oracle names gating constants
> (`EUnrealEngineObjectUE4Version.PURGED_FMATERIAL_COMPILE_OUTPUTS`,
> `FRenderingObjectVersion::MaterialAttributeLayerParameters`,
> `FUE5MainStreamObjectVersion::MaterialSavedCachedData`, etc.)
> but not their UE-release version. Phase 3 implementation should
> anchor against the named constants, not the version numbers.

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| UE 4.0+ | `UMaterialInstance` + `UMaterialInstanceConstant` introduced. Parameter-override wire shape stable. | `CUE4Parse/UE4/Assets/Exports/Material/UMaterialInstance.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d`[^1] |
| UE 4.0+ (pre-`MaterialAttributeLayerParameters`) | `FStaticParameterSet` serialized directly from binary archive when `bHasStaticPermutationResource`; switches to tagged-property path after `MaterialAttributeLayerParameters`. | Same[^1] |
| UE 4.25+ | When `bHasStaticPermutationResource` is true, inline shader-map blob added (`DeserializeInlineShaderMaps` path — same mechanism as `UMaterial`). | Same[^1] |
| UE 5.0+ (`MaterialSavedCachedData`) | `bSavedCachedData` bool read before shader maps; if set, a `MaterialInstanceCachedData` struct blob follows. | Same[^1] |

## Wire layout

A serialized `UMaterialInstance` / `UMaterialInstanceConstant` export
body has a tagged-property stream, an optional cached-data blob, and
(for the static-permutation case) an optional inline shader-map blob.

### Segment 1: tagged-property stream

Properties come from both `UMaterialInstance` (base) and
`UMaterialInstanceConstant` (subclass). All are read via
`GetOrDefault`:

**From `UMaterialInstance`:**

| Property name | Type | Semantics |
|---------------|------|-----------|
| `Parent` | `ObjectProperty` (`FPackageIndex → UUnrealMaterial`) | Parent `UMaterial` or `UMaterialInstance`; the inheritance source. |
| `bHasStaticPermutationResource` | `BoolProperty` | If `true`, the instance has its own compiled shaders for static-parameter variants. |
| `BasePropertyOverrides` | `StructProperty(FMaterialInstanceBasePropertyOverrides)` | Per-flag overrides (`BlendMode`, `OpacityMaskClipValue`, `TwoSided`, etc.). |
| `StaticParameters` | `StructProperty(FStaticParameterSet)` | Static-switch / static-component-mask overrides that require new shader compilation. Also checked as `StaticParametersRuntime`. |

**From `UMaterialInstanceConstant` (concrete subclass):**

| Property name | Type | Semantics |
|---------------|------|-----------|
| `TextureParameterValues` | `ArrayProperty<StructProperty(FTextureParameterValue)>` | Texture overrides. |
| `ScalarParameterValues` | `ArrayProperty<StructProperty(FScalarParameterValue)>` | Scalar (float) overrides. |
| `VectorParameterValues` | `ArrayProperty<StructProperty(FVectorParameterValue)>` | Linear-color overrides. |

Per-parameter struct entries (`FTextureParameterValue`,
`FScalarParameterValue`, `FVectorParameterValue`) are defined in
dedicated files in the `Parameters/` subdirectory. Each entry carries
at minimum a `Name` (the parameter's string identifier) and a
`ParameterValue` (the override value).

Properties terminate with the standard `"None"` tag.

### Segment 2: cached data blob (UE 5.0+, conditional)

When `FUE5MainStreamObjectVersion >= MaterialSavedCachedData`,
a `bool bSavedCachedData` is read directly. If `true`, a
`MaterialInstanceCachedData` struct blob (`FStructFallback`)
follows. paksmith Phase 3 should read the bool and skip the blob.

### Segment 3: inline shader-map blob (static-permutation case)

When `bHasStaticPermutationResource == true` AND
`Ar.Ver >= PURGED_FMATERIAL_COMPILE_OUTPUTS`:

- For pre-`MaterialAttributeLayerParameters` versions: `FStaticParameterSet`
  is read directly from the binary archive (not the tagged stream),
  then shader maps follow.
- For UE 4.25+ with `ReadShaderMaps` enabled: `DeserializeInlineShaderMaps`
  runs the same `FMaterialResourceProxyReader` mechanism as `UMaterial`
  (see [`material.md`](material.md) Segment 2).

In the common case (`bHasStaticPermutationResource == false`), there
is no shader-map blob — the instance defers entirely to the parent's
compiled shaders.

### Worked example

`(none yet — Phase 3 deliverable)`.

## Variants

### `UMaterialInstanceConstant` vs `UMaterialInstanceDynamic`

Cooked content carries only `UMaterialInstanceConstant` instances.
Dynamic instances are runtime-created and do not exist as standalone
cooked assets.

### Static-permutation case

Instances overriding static parameters (`StaticSwitchParameter`,
`StaticComponentMaskParameter`) require their own compiled shaders.
This is the `bHasStaticPermutationResource == true` path; the
instance behaves more like a sibling `UMaterial` than a pure
parameter delta, and includes the same skip-the-shader-bytes
discipline described in [`material.md`](material.md).

### Material-instance chains

An instance's `Parent` can be another instance, not just a root
`UMaterial`. paksmith's parameter-resolution logic (when Phase 3
implements) needs to walk the chain to root to collect all parameter
defaults.

## Caps & limits

**Phase 3+ deferred work.**

- Cap on parameter overrides per instance (matching
  `MAX_COLLECTION_ELEMENTS` — see `docs/security/allocation-caps.md`).
- Cap on instance-chain depth (cooked instances rarely chain more
  than 3-4 deep in practice; a cap of 16 is a reasonable starting
  point).

## Verification

- **Fixture:** `(none yet — Phase 3 deliverable)`.
- **Hex anchor commands:** `(none yet — Phase 3 deliverable)`.
- **Cross-validation oracle:** CUE4Parse[^1] (sole oracle — no Rust
  counterpart for the material family).
- **Known divergences:** same as `UMaterial` — paksmith skips the
  compiled shader bytes in the static-permutation case; see
  [`material.md`](material.md) Known divergences.

## Paksmith implementation

**Parser module:** *(not yet implemented — planned under
`crates/paksmith-core/src/asset/exports/material/material_instance.rs`)*

**Status:** `not impl`.

**Phase plan:** `docs/plans/ROADMAP.md` Phase 3 (Export Pipeline).

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Exports/Material/UMaterialInstance.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` — primary oracle for `UMaterialInstance`. `UMaterialInstanceConstant.cs` in the same directory for the concrete subclass (parameter-value arrays). Supporting files: `FMaterialInstanceBasePropertyOverrides.cs`, `FMaterialResourceProxyReader.cs` (shader-map skip), `MaterialResourceTypes.cs` (`FMaterialResource`/`FMaterial`/`FMaterialShaderMap`), and the `Parameters/` subdirectory (`FStaticSwitchParameter.cs`, `FStaticComponentMaskParameter.cs`, `FStaticParameterBase.cs`, etc.).
