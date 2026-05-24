# Material (`UMaterial`)

> Root material asset — defines a shader graph at authoring time and
> a set of texture / scalar / vector parameter defaults at cook time.
> The compiled shader bytecode lives in shader cache / DDC, which
> paksmith does not extract.

## Overview

`UMaterial` is a UE asset describing a complete shader graph: node
inputs (`BaseColor`, `Metallic`, `Roughness`, `Normal`, ...) wired
together into expressions evaluated per-pixel by the GPU. The shader
graph itself only exists in editor builds; in cooked content the
graph has been compiled to platform-specific shader bytecode and
serialized into a separate shader cache (or DDC entry) keyed by the
platform / quality / feature-level the cooker built for.

What paksmith CAN extract from a cooked `UMaterial` asset:

1. **Default parameter values** — `Texture2D` / `Scalar` / `Vector`
   parameters with their defaults, exposed via the standard
   tagged-property mechanism.
2. **Material flags** — `BlendMode`, `ShadingModel`, `TwoSided`, etc.
3. **Referenced textures** — `ObjectProperty` references that resolve
   through the asset's import table.

What paksmith CANNOT extract from a cooked `UMaterial`:

- **The shader graph itself** — gone at cook time.
- **Compiled shader bytecode** — lives in shader cache / DDC, a
  separate extraction problem.
- **Material expression nodes** — editor-only, stripped from cooked.

**Status: not yet implemented in paksmith.** Phase 3+ deliverable.

## Versions

> Note: UE version numbers in the table are derived from community
> knowledge (UE release history). The oracle (`UMaterial.cs`) names
> gating constants (`EUnrealEngineObjectUE4Version.PURGED_FMATERIAL_COMPILE_OUTPUTS`,
> `FUE5MainStreamObjectVersion::MaterialSavedCachedData`, etc.)
> but not their UE-release version. Phase 3 implementation should
> anchor against the named constants, not the version numbers.

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| UE 4.0+ | `UMaterial` introduced. Parameter wire shape stable. | `CUE4Parse/UE4/Assets/Exports/Material/UMaterial.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d`[^1] |
| UE 4.25+ | `PURGED_FMATERIAL_COMPILE_OUTPUTS`: inline shader-map blob added when `ReadShaderMaps` is enabled. `CachedExpressionData` and referenced-texture extraction added. | Same[^1] |
| UE 5.0+ | `MaterialSavedCachedData` / `MaterialInterfaceSavedCachedData` version gates for saved expression-data blob. | Same[^1] |

## Wire layout

A serialized `UMaterial` export body has two segments: a
tagged-property stream and an optional inline shader-map blob.

### Segment 1: tagged-property stream

`UMaterial::Deserialize` calls `base.Deserialize` (via `UMaterialInterface`
→ `UUnrealMaterial` → `UObject`), which reads the standard tagged-property
stream. CUE4Parse reads a specific subset of named fields via
`GetOrDefault`; other properties may appear in the tagged stream and
are accessible through the generic property iterator.

Oracle-verified named fields at this SHA:

| Property name | Type | Semantics |
|---------------|------|-----------|
| `TwoSided` | `BoolProperty` | Both faces rendered. |
| `bDisableDepthTest` | `BoolProperty` | Depth test disabled (translucent materials). |
| `bIsMasked` | `BoolProperty` | Opacity mask applied (masked blend mode). |
| `Expressions` | `ArrayProperty<ObjectProperty>` (`FPackageIndex[]`) | Material expression node references (editor; often empty in cooked). |
| `BlendMode` | `ByteProperty` / `EnumProperty` (`EBlendMode`) | `BLEND_Opaque` / `Masked` / `Translucent` / etc. |
| `TranslucencyLightingMode` | `ByteProperty` / `EnumProperty` (`ETranslucencyLightingMode`) | Lighting model for translucent surfaces. |
| `ShadingModel` | `ByteProperty` / `EnumProperty` (`EMaterialShadingModel`) | `MSM_DefaultLit` / `Unlit` / `Subsurface` / etc. |
| `OpacityMaskClipValue` | `FloatProperty` | Threshold for masked blend mode; default `0.333`. |

`UMaterialInterface::Deserialize` (parent) additionally reads:

| Property name | Type | Semantics |
|---------------|------|-----------|
| `TextureStreamingData` | `ArrayProperty<StructProperty(FMaterialTextureInfo)>` | Texture-streaming metadata array. |

Properties terminate with the standard `"None"` tag.

Additional UE-defined tagged properties commonly present in cooked
`UMaterial` assets that paksmith may encounter in the generic
property bag (not extracted as named fields by CUE4Parse at this
SHA):

- `MaterialDomain` (`ByteProperty` / `EnumProperty` `EMaterialDomain`) — `MD_Surface` / `DeferredDecal` / `LightFunction` / `PostProcess` / etc.
- `bUsedAsSpecialEngineMaterial`, `bUsedWithSkeletalMesh`, `bUsedWithStaticLighting`, `bUsedWithLandscape`, `bUsedWithParticleSystem`, `bUsedWithFoliage`, `bUsedWithNanite` (UE 5+) — bool usage flags that drive cooker shader permutations.
- `TextureParameterValues`, `ScalarParameterValues`, `VectorParameterValues` — parameter default arrays (see format details in [`material-instance.md`](material-instance.md)).

These are plausible tagged properties available through the standard
property iterator; Phase 3 should verify each against the named
oracle fields when implementing.

### Segment 2: inline shader-map blob (UE 4.25+, conditional)

After the property terminator, when `Ar.Ver >= PURGED_FMATERIAL_COMPILE_OUTPUTS`
and the reader has `ReadShaderMaps` enabled, `DeserializeInlineShaderMaps`
deserializes an inline shader-map blob via `FMaterialResourceProxyReader`.

`FMaterialResourceProxyReader` is a wrapper archive that reads its
own name map (`FNameEntrySerialized[]`), a locs table
(`FMaterialResourceLocOnDisk[]` — each entry is `Offset: u32` +
`FeatureLevel: u8` + `QualityLevel: u8`), and a `NumBytes: u32`
before proxying the inner shader-map reads. Inside, `FMaterial::DeserializeInlineShaderMap`
reads a `bCooked: bool` (gated by `Ar.Ver > INLINE_SHADERS`); if
cooked and valid, an `FMaterialShaderMap` follows with frozen
shader content.

paksmith's Phase 3 implementation should:

1. Read the property segment and surface the parameter defaults.
2. When encountering the `PURGED_FMATERIAL_COMPILE_OUTPUTS` version
   gate, detect the `FMaterialResourceProxyReader` header (name-map
   + locs + NumBytes) and advance past the entire shader-map blob via
   the published `NumBytes` size. `NumBytes` must be bounds-checked
   against the remaining archive length before advancing — a corrupted
   pak could provide an oversized value to cause an out-of-bounds seek.
3. NOT attempt to interpret shader bytecode — per-platform shader
   formats (`SF_VULKAN_SM5`, `SF_METAL_*`, `SF_PCD3D_SM5`, etc.) are
   outside paksmith's scope.

### Worked example

`(none yet — Phase 3 deliverable)`.

## Variants

### Material domains

The `MaterialDomain` property splits materials into subtypes
(`Surface`, `DeferredDecal`, `LightFunction`, `Volume`,
`PostProcess`, `UserInterface`, `Virtual`). Each has slightly
different cooked shader-map shapes but the outer tagged-property
stream is the same.

### Substrate (UE 5.1+)

Substrate is UE's new shading-system replacing the legacy shading
model enum. Cooked Substrate materials use separate UObject classes
outside this doc; only the legacy `UMaterial` class is covered here.

### Material functions

`UMaterialFunction` is a separate class for reusable sub-graphs.
In cooked content, function references resolve through normal
`ObjectProperty` mechanisms; the function's own asset is parsed via
a different export specialization (not covered in this doc).

## Caps & limits

**Phase 3+ deferred work.**

- Cap on parameters per material (matching `MAX_COLLECTION_ELEMENTS`
  — see `docs/security/allocation-caps.md`).
- Cap on shader maps per material (cooked builds rarely exceed a few
  hundred quality/platform combinations).

## Verification

- **Fixture:** `(none yet — Phase 3 deliverable)`.
- **Hex anchor commands:** `(none yet — Phase 3 deliverable)`.
- **Cross-validation oracle:** CUE4Parse[^1] (sole oracle — no Rust
  counterpart for the material family).
- **Known divergences:**
  - **Shader bytecode unread.** CUE4Parse can parse the inline
    shader-map blob (it has per-platform shader-format readers);
    paksmith deliberately skips the compiled-shader bytes via the
    published size. Aligns with paksmith's "extract data assets"
    focus vs CUE4Parse's broader "decompile shader graphs" remit.
    Both projects agree on the parameter-default extraction.

## Paksmith implementation

**Parser module:** *(not yet implemented — planned under
`crates/paksmith-core/src/asset/exports/material/material.rs`)*

**Status:** `not impl`.

**Phase plan:** `docs/plans/ROADMAP.md` Phase 3 (Export Pipeline).

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Exports/Material/UMaterial.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` — primary oracle. Supporting files in the same directory: `UMaterialInterface.cs` (parent class; reads `TextureStreamingData` + `CachedExpressionData`), `UUnrealMaterial.cs` (grandparent), `MaterialResourceTypes.cs` (`FMaterial`, `FMaterialResource : FMaterial`, `FMaterialShaderMap` — all defined in this file), `FMaterialResourceProxyReader.cs` (the inner archive wrapper for shader-map deserialization), `EBlendMode.cs`, `EMaterialShadingModel.cs`.
