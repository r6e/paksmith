# Material (`UMaterial`)

> Root material asset — defines a shader graph at authoring time and
> a set of texture / scalar / vector parameter defaults at cook time.

## Overview

`UMaterial` is a UE asset describing a complete shader graph: node
inputs (`BaseColor`, `Metallic`, `Roughness`, `Normal`, ...) wired
together into expressions evaluated per-pixel by the GPU. In cooked
content the graph has been compiled to platform-specific shader
bytecode.

What paksmith CAN extract from a cooked `UMaterial` asset
(Substrate and Material functions are separate classes, out of scope):

1. **Default parameter values** — `Texture2D` / `Scalar` / `Vector`
   parameters with their defaults, exposed via the standard
   tagged-property mechanism.
2. **Material flags** — `BlendMode`, `ShadingModel`, `TwoSided`, etc.
3. **Referenced textures** — `ObjectProperty` references that resolve
   through the asset's import table.

What paksmith CANNOT extract from a cooked `UMaterial`:

- **The shader graph itself** — gone at cook time.
- **Material expression nodes** — editor-only, stripped from cooked.

**Document status: complete.** Wire format documented for
the `UMaterial` export body: the tagged-property stream
(named fields read by CUE4Parse plus the broader set commonly
present as generic tagged properties) and the conditional inline
shader-map blob (gated on
`PURGED_FMATERIAL_COMPILE_OUTPUTS`). The
`FMaterialResourceProxyReader` inner-archive mechanism is
documented. Substrate, Material functions, and shader bytecode
itself are explicitly out of scope; the doc tells a parser
implementer what to extract (parameter defaults, material flags,
referenced textures) and what to skip (compiled shader bytecode).

**Paksmith parser status: `not impl`.** Phase 3+ deliverable.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| UE 5.0+ | `MaterialSavedCachedData` / `MaterialInterfaceSavedCachedData` version gates for saved expression-data blob. | `CUE4Parse/UE4/Assets/Exports/Material/UMaterial.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d`[^1] |

## Wire layout

A serialized `UMaterial` export body contains a tagged-property
stream and an optional inline shader-map blob.

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

### Segment 2: inline shader-map blob (conditional)

Segment 2's version gate is `Ar.Ver >= PURGED_FMATERIAL_COMPILE_OUTPUTS`[^1].
It follows the reads that step 1 below lists. CUE4Parse decodes it
only for `GAME_UE4_25`+ with `ReadShaderMaps` set.
`DeserializeInlineShaderMaps` reads `numLoadedResources: i32` and, if
it is above 0, the `FMaterialResourceProxyReader` header and
`numLoadedResources` material-resource records; `UMaterial` then makes
the deprecated cached-expression-data reads (packages without
`PKG_FilterEditorOnly`) and, when
`FRenderingObjectVersion >= NaniteForceMaterialUsage`, reads a
`bForceNaniteUsage` bool. Without the decode, CUE4Parse seeks to the
export end.

`FMaterialResourceProxyReader` reads its own name map and steps over a
locs table (`FMaterialResourceLocOnDisk[]`) and a 4-byte `NumBytes`, then proxies
all subsequent inner shader-map reads through the inner archive. The
oracle does NOT advance past the blob via `NumBytes` — it reads through
the proxy reader directly.

paksmith's Phase 3 implementation should:

1. Read the property segment, then what precedes the shader-map
   gate: the object-GUID tail, which CUE4Parse reads only when the
   export is not flagged `RF_ClassDefaultObject`, and, when
   `FUE5ReleaseStreamObjectVersion >= MaterialInterfaceSavedCachedData`,
   `UMaterialInterface`'s bool and optional `MaterialCachedExpressionData`
   struct. Surface the parameter defaults and referenced textures
   from the properties and from that struct, where CUE4Parse also
   finds them.
2. When `Ar.Ver >= PURGED_FMATERIAL_COMPILE_OUTPUTS`, seek to the
   export end instead of reading Segment 2, as CUE4Parse does when it
   skips the decode.

## Variants

### Material domains

The `MaterialDomain` property splits materials into subtypes
(`Surface`, `DeferredDecal`, `LightFunction`, `Volume`,
`PostProcess`, `UserInterface`, `Virtual`).

## Caps & limits

### Format-defined limits (wire-imposed)

- **Tagged-property fields** (`TwoSided`, `BlendMode`,
  `ShadingModel`, `OpacityMaskClipValue`, etc.) follow the standard
  tag header / type-extras / value layouts per
  [`../property/tagged.md`](../property/tagged.md). All
  enum-discriminant fields are `u8` byte values per the UE
  `ByteProperty` / `EnumProperty` convention.
- **`Expressions` array prefix**: `i32` count (variable-length array
  of `FPackageIndex` per the property's `ArrayProperty<ObjectProperty>`
  shape).

### Implementation hardening (recommended for any parser)

A `UMaterial` reader (paksmith does not yet have one) MUST:

- **Cap parameters per material** at `MAX_COLLECTION_ELEMENTS`
  (see `docs/security/allocation-caps.md`).
- **Cap shader maps per material** at a project-defined ceiling when
  decoding them.
- **Validate enum-discriminant property values** (`EBlendMode`,
  `EMaterialShadingModel`, `EMaterialDomain`,
  `ETranslucencyLightingMode`) against the documented value sets
  per `EBlendMode.cs` / `EMaterialShadingModel.cs`. Unknown
  discriminants SHOULD surface a typed parse warning (cooked
  content may carry forward-compat enum values that older parsers
  don't recognize; reject would over-narrow paksmith's UE-version
  range).
- **Skip-not-parse compiled shader bytecode**: a parser without a
  shader-map reader MUST stop at the shader-map gate point and seek
  to the export end rather than attempting to interpret the bytes.
- **Inherit per-export caps** from
  `MAX_UNCOMPRESSED_ENTRY_BYTES` / `MAX_UEXP_SIZE`.

See `docs/security/allocation-caps.md` for the broader policy.

## Verification

- **Fixture:** none committed.
- **Cross-validation oracle:** CUE4Parse[^1].
- **Known divergences:** none — no paksmith implementation to
  diverge.

## Paksmith implementation

**Parser module:** *(not yet implemented — planned under
`crates/paksmith-core/src/asset/exports/material/material.rs`)*

**Status:** `not impl`.

**Phase plan:** `docs/plans/ROADMAP.md` Phase 3 (Export Pipeline).

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Exports/Material/UMaterial.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` — primary oracle (Segment 2: L61-L101). Supporting files in the same directory: `UMaterialInterface.cs` (parent class; reads `TextureStreamingData` + `CachedExpressionData`, L43-L49, and holds `DeserializeInlineShaderMaps`, L171-L195), `UUnrealMaterial.cs` (grandparent), `MaterialResourceTypes.cs` (`FMaterial`, `FMaterialResource : FMaterial`, `FMaterialShaderMap` — all defined in this file), `FMaterialResourceProxyReader.cs` (the inner archive wrapper for shader-map deserialization), `EBlendMode.cs`, `EMaterialShadingModel.cs`. At the same SHA, `CUE4Parse/UE4/Assets/Exports/UObject.cs` L145-L148 reads the object-GUID tail and `CUE4Parse/UE4/Assets/Readers/FAssetArchive.cs` L28 ties `IsFilterEditorOnly` to `PKG_FilterEditorOnly`.
