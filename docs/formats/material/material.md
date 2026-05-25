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
- **Compiled shader bytecode** — lives in shader cache / DDC, a
  separate extraction problem.
- **Material expression nodes** — editor-only, stripped from cooked.

**Document status: complete.** Wire format documented in full for
the two-segment `UMaterial` export body: the tagged-property stream
(named fields read by CUE4Parse plus the broader set commonly
present as generic tagged properties) and the conditional inline
shader-map blob (gated on
`PURGED_FMATERIAL_COMPILE_OUTPUTS` + `ReadShaderMaps`). The
`FMaterialResourceProxyReader` inner-archive mechanism is
documented along with the paksmith-specific skip-via-`NumBytes`
strategy. Substrate, Material functions, and shader bytecode
itself are explicitly out of scope; the doc tells a parser
implementer what to extract (parameter defaults, material flags,
referenced textures) and what to skip (compiled shader bytecode,
per-platform shader formats).

**Paksmith parser status: `not impl`.** Phase 3+ deliverable.

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

`FMaterialResourceProxyReader` reads its own name map, a locs table
(`FMaterialResourceLocOnDisk[]`), and a `NumBytes: u32`, then proxies
all subsequent inner shader-map reads through the inner archive. The
oracle does NOT advance past the blob via `NumBytes` — it reads through
the proxy reader directly.

paksmith's Phase 3 implementation should:

1. Read the property segment and surface the parameter defaults.
2. When encountering the `PURGED_FMATERIAL_COMPILE_OUTPUTS` version
   gate, detect the `FMaterialResourceProxyReader` header (name-map
   + locs + NumBytes). For implementations without a proxy-reader
   architecture, advance past the shader-map blob using the published
   `NumBytes` size (bounds-check against remaining archive length
   first). Note: this skip-via-NumBytes approach is an implementation
   strategy for paksmith — the oracle uses a proxy-reader and does not
   perform this skip itself.
3. NOT attempt to interpret shader bytecode — per-platform shader
   formats (`SF_VULKAN_SM5`, `SF_METAL_*`, `SF_PCD3D_SM5`, etc.) are
   outside paksmith's scope.

### Worked example — post-property gate point (skip-via-NumBytes strategy)

A cooked `UMaterial`'s export body is dominated by the tagged-property
stream and an optional opaque shader-map blob. The interesting
byte-exact surface for an extraction-focused parser is the gate
point between them. Suppose a UE 4.25+ cooked `UMaterial` at the
point immediately after the property `"None"` terminator, with
`ReadShaderMaps` enabled and a (placeholder) 0x100-byte shader map:

```
Offset (within material export, relative to post-"None")  Bytes (LE)        Field
--------------------------------------------------------  ---------------   --------------------
+0                                                        00 00              FStripDataFlags = 0x0000 (no strip flags — both GlobalStripFlags and ClassStripFlags zero)
+2                                                        <FMaterialResourceProxyReader name-map + locs — variable>
+?                                                        00 01 00 00        NumBytes = 0x00000100 = 256 (u32 LE; total proxy-archive byte count)
+?+4                                                      <256 opaque shader-map bytes — paksmith skips via cursor += 256>
+?+4+256                                                  <next export, or end of .uexp segment>
```

For an extraction-focused parser (paksmith's posture), the
`NumBytes` u32 is the cursor-advance value: read 4 bytes, then
`cursor += NumBytes` to skip the opaque shader-map. The
intervening `FMaterialResourceProxyReader` name-map and locs table
are variable-size structures that a full parser would walk
(CUE4Parse does this through its proxy reader), but the skip
strategy only requires bounds-checking `NumBytes` against the
remaining archive length before advancing.

A `UMaterial` without `PURGED_FMATERIAL_COMPILE_OUTPUTS` (pre-UE-4.25)
ends after the `FStripDataFlags`; no shader-map blob follows.

## Variants

### Material domains

The `MaterialDomain` property splits materials into subtypes
(`Surface`, `DeferredDecal`, `LightFunction`, `Volume`,
`PostProcess`, `UserInterface`, `Virtual`). Each has slightly
different cooked shader-map shapes but the outer tagged-property
stream is the same.

## Caps & limits

### Format-defined limits (wire-imposed)

- **`FMaterialResourceProxyReader.NumBytes`**: `u32` LE; total
  byte count of the proxy-archive shader-map blob. Max representable
  `u32::MAX = 4 GiB`.
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
- **Cap shader maps per material** at a project-defined ceiling
  (cooked builds rarely exceed a few hundred quality / platform
  combinations).
- **Bounds-check `FMaterialResourceProxyReader.NumBytes`** against
  the remaining archive length before advancing the cursor (skip
  strategy) or before allocating the proxy-archive buffer.
- **Use `checked_add`** on `current_cursor + NumBytes` to defeat
  near-`u64::MAX` wraparound when computing the post-skip cursor
  position.
- **Validate enum-discriminant property values** (`EBlendMode`,
  `EMaterialShadingModel`, `EMaterialDomain`,
  `ETranslucencyLightingMode`) against the documented value sets
  per `EBlendMode.cs` / `EMaterialShadingModel.cs`. Unknown
  discriminants SHOULD surface a typed parse warning (cooked
  content may carry forward-compat enum values that older parsers
  don't recognize; reject would over-narrow paksmith's UE-version
  range).
- **Skip-not-parse compiled shader bytecode**: a parser without a
  per-platform shader-format reader (paksmith's posture) MUST stop
  at the shader-map gate point and skip via `NumBytes` rather than
  attempting to interpret the bytes.
- **Inherit per-export caps** from
  `MAX_UNCOMPRESSED_ENTRY_BYTES` / `MAX_UEXP_SIZE`.

See `docs/security/allocation-caps.md` for the broader policy.

## Verification

- **Fixture:** The Worked example above is partially byte-exact
  (the `FStripDataFlags` 2-byte marker and the `NumBytes` u32 are
  concrete; the intervening `FMaterialResourceProxyReader`
  name-map and locs structures are variable-size and described
  symbolically). Real-cooked `UMaterial` fixtures are Phase 3
  deliverables.
- **Hex anchor commands:**
  ```
  # Synthesize the 2-byte zero FStripDataFlags + 4-byte NumBytes header
  # for the post-property gate point from the Worked example:
  printf '\x00\x00\x00\x01\x00\x00' | xxd
  ```
  (First 2 bytes = `FStripDataFlags` with both bytes zero; last
  4 bytes = `NumBytes = 256` as u32 LE.) A paksmith-style extractor
  parser fed these 6 bytes at the gate point — plus the intervening
  proxy-reader header that brings the cursor up to the `NumBytes`
  field — MUST advance the cursor by 256 bytes after reading
  `NumBytes` to skip the opaque shader map.
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
