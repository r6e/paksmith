# UE Animation + Material Family Documentation — PR 11 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Populate `docs/formats/animation/` with one document (`anim-sequence.md`) and `docs/formats/material/` with two documents (`material.md`, `material-instance.md`). All three are `partial | not impl` — Phase 3+ deliverables. Add three rows to the root inventory.

**Architecture:** Two family directories combined in one PR per the spec rollout (PR 11). Animation and material share the "tagged-property body referencing other UObjects + format-specific bulk payload" structural pattern but otherwise have nothing in common — they're bundled for shipping cadence, not because they share content. The animation doc focuses on the compressed-keyframe codec dispatch; the material docs focus on shader-map references and the parameter-override delta system, with explicit notes about which content is out of paksmith's scope (compiled shader bytecode lives in shader cache / DDC and paksmith doesn't extract those today).

**Tech Stack:** Pure markdown. PR 1 linters. Primary oracle is `FabianFG/CUE4Parse/UE4/Assets/Exports/Animation/` and `Material/`; secondary is `AstralOrigin/unreal_asset/unreal_asset/src/exports/`.

**Spec reference:** `docs/design/2026-05-19-ue-format-docs.md` (commit `72b364e`). **Prerequisite:** PR 1 (framework scaffold) has merged to `main`.

---

## Prerequisites

- PR 1 (`docs/ue-format-docs-framework`) has merged to `main`.
- Working in a worktree under `.claude/worktrees/docs+ue-format-docs-animation-material/`.
- `cargo build -p paksmith-doc-lint --release` succeeds.

## File structure

**Create (3 docs):**

- `docs/formats/animation/anim-sequence.md` — `UAnimSequence`.
- `docs/formats/material/material.md` — `UMaterial`.
- `docs/formats/material/material-instance.md` — `UMaterialInstance` (and its `UMaterialInstanceConstant` subclass).

**Modify (1):**

- `docs/formats/README.md` — add three rows to the inventory.

**Oracle citation policy.** Primary: CUE4Parse's per-class readers in
`UE4/Assets/Exports/Animation/` and `Material/`. Secondary:
`unreal_asset` counterparts. The compiled-shader-bytecode side of
materials is explicitly out of scope; the docs note this and don't
cite the relevant CUE4Parse files because paksmith won't decode them
even when Phase 3 lands.

**Hex-anchor policy.** `(none yet — Phase 3 deliverable)` for all
three docs.

---

## Task 1: Create worktree + verify prerequisites

**Files:** (environment setup only)

- [ ] **Step 1: Confirm PR 1 has merged**

Run: `git fetch origin && git log origin/main --oneline | grep -c "format documentation framework"`
Expected: ≥ 1.

- [ ] **Step 2: Create the worktree from origin/main**

From the primary checkout root:

Run: `git worktree add .claude/worktrees/docs+ue-format-docs-animation-material -b docs/ue-format-docs-animation-material origin/main`

- [ ] **Step 3: Switch session cwd into the worktree**

Run: `cd .claude/worktrees/docs+ue-format-docs-animation-material && pwd && git branch --show-current`
Expected: prints the worktree path and `docs/ue-format-docs-animation-material`.

- [ ] **Step 4: Verify the framework scaffold is present**

Run: `ls docs/formats/animation/README.md docs/formats/material/README.md docs/formats/TEMPLATE.md docs/formats/CONVENTIONS.md`
Expected: all four files listed.

- [ ] **Step 5: Build the linter binary**

Run: `cargo build -p paksmith-doc-lint --release`
Expected: clean.

- [ ] **Step 6: Linter smoke-test**

Run: `cargo run -p paksmith-doc-lint --release -- required-headings docs/formats/`
Expected: exits 0.

Run: `cargo run -p paksmith-doc-lint --release -- status-enum docs/formats/README.md`
Expected: exits 0.

- [ ] **Step 7: Confirm no animation/material parser exists**

Run: `find crates/paksmith-core/src -iname "*anim*" -o -iname "*material*"`
Expected: no output.

Run: `grep -rln "UAnimSequence\|UMaterial::\|UMaterialInstance::" crates/paksmith-core/src`
Expected: no output.

No commit — environment setup only.

---

## Task 2: Author `docs/formats/animation/anim-sequence.md` (partial)

`UAnimSequence` is the asset holding baked keyframe animation data
for a `USkeleton`. Tagged-property segment with anim settings +
references to the target Skeleton + bulk-data records carrying the
compressed per-bone-track keyframes.

**Files:**
- Create: `docs/formats/animation/anim-sequence.md`

**Oracle references:**
- `CUE4Parse/UE4/Assets/Exports/Animation/UAnimSequence.cs`
- `CUE4Parse/UE4/Assets/Exports/Animation/FCompressedAnimSequence.cs`

- [ ] **Step 1: Look up oracle SHAs**

Run: `git ls-remote https://github.com/FabianFG/CUE4Parse HEAD | cut -f1` — `<CUE4PARSE_SHA>`.
Run: `git ls-remote https://github.com/AstralOrigin/unreal_asset HEAD | cut -f1` — `<UNREAL_ASSET_SHA>`.

- [ ] **Step 2: Write the doc**

Write `docs/formats/animation/anim-sequence.md`:

````markdown
# AnimSequence (`UAnimSequence`)

> Baked keyframe animation data for a `USkeleton` — per-bone-track
> rotation / translation / scale curves, compressed via one of
> several codecs.

## Overview

`UAnimSequence` is the asset type for a single animation clip — a
walk cycle, an attack swing, a facial-expression blend shape. On
disk: a tagged-property segment with the target `USkeleton`
reference plus playback settings, followed by an
`FCompressedAnimSequence` payload carrying the per-bone-track
compressed keyframes.

The compressed-keyframe codec set has expanded significantly across
UE4 minor versions and again in UE5. UE4 ships at minimum:

- **`ACF_None`** — uncompressed per-bone-track keyframes.
- **`ACF_Float96NoW`** — quaternion as 3 × `f32` (W reconstructed
  from sign).
- **`ACF_Fixed48NoW`** — quaternion as 3 × `i16` mapped to `[-1, 1]`.
- **`ACF_IntervalFixed32NoW`** — quaternion as 3 × `u10` packed into
  a single `u32` with per-track min/max.
- **`ACF_Fixed32NoW`** — quaternion as 3 × `u10` with global range.
- **`ACF_Float32NoW`** — quaternion as 3 × `f32` (full precision
  legacy variant).
- **`ACF_Identity`** — track has no animation (single key,
  zero-bytes).

UE 4.21+ added the `FACLCompressedAnimSequence` ACL-codec variant
(Animation Compression Library by Nicholas Frechette); UE 5.0+
expanded with curve-only and per-bone-mask compression schemes.

**Status: not yet implemented in paksmith.** Phase 3+ deliverable.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| UE 4.0+ | `UAnimSequence` + `FCompressedAnimSequence` introduced with the seven legacy codecs. | `CUE4Parse/UE4/Assets/Exports/Animation/UAnimSequence.cs@<CUE4PARSE_SHA>`[^1] |
| UE 4.21+ | ACL codec (`FACLCompressedAnimSequence`) added as the recommended default. | Same[^1] |
| UE 4.25+ | Per-bone-mask compression added. | Same[^1] |
| UE 5.0+ | Curve-only compression streams added; bone weights expanded to 16-bit-index form (matching SkeletalMesh). | Same[^1] |

## Wire layout

### Segment 1: tagged-property stream

Common properties:

| Property name | Type | Semantics |
|---------------|------|-----------|
| `Skeleton` | `ObjectProperty` (`USkeleton`) | Target skeleton — must match the indices the per-track keys reference. See [`../mesh/skeleton.md`](../mesh/skeleton.md). |
| `SequenceLength` | `FloatProperty` | Seconds. |
| `RateScale` | `FloatProperty` | Playback rate multiplier; usually `1.0`. |
| `bLoop` | `BoolProperty` | |
| `RawCurveData` | `StructProperty(FRawCurveTracks)` | Editor-only-in-cooked; mostly empty. |
| `Notifies` | `ArrayProperty<StructProperty(FAnimNotifyEvent)>` | Time-coded notify-events. |
| `KeyEncodingFormat` | `ByteProperty` / `EnumProperty` (`AnimationKeyFormat`) | Codec for translation / scale tracks. |
| `TranslationCompressionFormat` | `ByteProperty` / `EnumProperty` (`AnimationCompressionFormat`) | Codec for translation. |
| `RotationCompressionFormat` | `ByteProperty` / `EnumProperty` (`AnimationCompressionFormat`) | Codec for rotation (one of the ACF_* listed above). |
| `ScaleCompressionFormat` | `ByteProperty` / `EnumProperty` (`AnimationCompressionFormat`) | Codec for scale. |
| `CompressedTrackOffsets` | `ArrayProperty<IntProperty>` | Per-bone-track byte offsets into the compressed payload. |
| `BoneCompressionSettings` | `ObjectProperty` (`UAnimBoneCompressionSettings`) | UE 4.25+; bone-mask + codec settings. |

### Segment 2: `FCompressedAnimSequence`

The compressed keyframe payload. Two main variants:

**Legacy codec variant** (UE 4.0+, still supported):

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `CompressedRawDataSize` | 4 | LE | `i32` | Original uncompressed-data byte size; sanity-check metric. |
| `CompressedNumberOfFrames` | 4 | LE | `i32` | Total frame count. |
| `CompressedByteStream` | variable | — | `u8[]` | Codec-dependent per-track keyframe bytes. |
| `CompressedTrackOffsets` | variable | — | `i32[]` | Per-track byte-offset table. |
| `CompressedScaleOffsets` | variable | — | `FCompressedOffsetData` | Scale-track byte offsets. |
| `KeyEncodingFormat` | 1 | — | `u8` (enum) | Translation/scale codec. |
| `TranslationCompressionFormat` | 1 | — | `u8` (enum) | Translation codec. |
| `RotationCompressionFormat` | 1 | — | `u8` (enum) | Rotation codec. |
| `ScaleCompressionFormat` | 1 | — | `u8` (enum) | Scale codec. |

**ACL codec variant** (UE 4.21+):

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `Version` | 4 | LE | `u32` | ACL bitstream version. |
| `AlgorithmHash` | 4 | LE | `u32` | Compression-algorithm-config fingerprint. |
| `CompressedData` | variable | — | `u8[]` | ACL-compressed bitstream; the ACL library decodes. |

Decoding the ACL variant requires the upstream
[Animation Compression Library](https://github.com/nfrechette/acl)
or its Rust binding (`acl-rs` or similar — to be evaluated when
Phase 3 implements).

### Per-codec key wire shapes (legacy)

Each rotation track encodes one quaternion per key. Per-codec
per-key sizes:

| Codec | Per-key bytes | Encoding |
|-------|---------------|----------|
| `ACF_None` | 16 | 4 × f32 (full Q). |
| `ACF_Float96NoW` | 12 | 3 × f32; W reconstructed (sign carried in upper bit of X). |
| `ACF_Fixed48NoW` | 6 | 3 × i16 in `[-32768, 32767]` → quaternion components. |
| `ACF_IntervalFixed32NoW` | 4 | 3 × u10 packed into u32 + per-track min/max scale stored at track header. |
| `ACF_Fixed32NoW` | 4 | 3 × u10 packed into u32 + global range. |
| `ACF_Float32NoW` | 4 | 3 × f32 (W reconstructed). Legacy. |
| `ACF_Identity` | 0 | Single keyframe = identity quaternion. |

Translation and scale tracks use the same enum but typically
`ACF_None` or `ACF_Float96NoW` (translations are less amenable to
quantization than rotations).

### Worked example

`(none yet — no animation fixture)`. When Phase 3 adds fixtures,
the canonical anchor will be a minimal 2-bone walk-cycle
animation using `ACF_None` rotation (so the byte layout is the
simplest possible: 16 bytes per key per track).

## Variants

### ACL codec

UE 4.21+ recommends ACL; cooked content from modern engines almost
exclusively uses ACL. Decoding requires the ACL bitstream library;
without it paksmith can detect the codec but cannot extract
keyframes. Phase 3+ should evaluate `acl-rs` / similar Rust
bindings.

### Per-bone-mask compression (UE 4.25+)

`UAnimBoneCompressionSettings` lets per-bone curves use different
codecs (e.g. high-precision for the spine, low-precision for the
fingers). Wire format adds a `FBoneAnimationTrack[]` indirection
table.

### Curve compression (UE 5+)

Curves (e.g. facial-blend-shape weights, IK targets) compress
separately from bone tracks. Adds an `FCompressedCurveTrackData`
payload after the bone-track block.

### Compositing / additive sequences

UE supports composite sequences (`UAnimComposite`) and additive
sequences (delta-on-top-of-base). These are separate UObject classes
(`UAnimComposite`, `UAnimMontage`) outside this doc; only the
`UAnimSequence` class itself is covered here.

## Caps & limits

**Phase 3+ deferred work.** When the AnimSequence reader lands:

- `MAX_FRAMES_PER_ANIM` cap (likely `65,536` — long animations are
  typically split into clips at the asset level rather than packed
  into one sequence).
- `MAX_TRACKS_PER_ANIM` cap (one per bone; bounded by the
  `MAX_BONES_PER_SKELETON` cap from
  [`../mesh/skeleton.md`](../mesh/skeleton.md)).
- Per-codec wire-byte caps inherited from `MAX_UNCOMPRESSED_ENTRY_BYTES`.

## Verification

- **Fixture:** `(none yet — Phase 3 deliverable)`.
- **Cross-validation oracle:** CUE4Parse[^1] (primary) and
  `unreal_asset`[^2].
- **Known divergences:** none yet.

## Paksmith implementation

**Parser module:** *(not yet implemented — planned under
`crates/paksmith-core/src/asset/exports/animation/anim_sequence.rs`)*

**Status:** `not implemented`.

**Phase plan:** `docs/plans/ROADMAP.md` Phase 3 (Export Pipeline).
A Phase 3 plan should:

1. Add a `crates/paksmith-core/src/asset/exports/animation/anim_sequence.rs`
   module with `AnimSequence::read_from`.
2. Add per-codec key decoders for the legacy ACF_* set.
3. Detect ACL codec; defer decoding to a follow-up if Rust ACL
   bindings aren't yet mature.
4. Add fixtures + cross-validation against unreal_asset[^2].

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Exports/Animation/UAnimSequence.cs@<CUE4PARSE_SHA>` plus `FCompressedAnimSequence.cs` and the per-codec readers in the same directory.
[^2]: `AstralOrigin/unreal_asset/unreal_asset/src/exports/animation_export.rs@<UNREAL_ASSET_SHA>` — Rust counterpart.
[^3]: `nfrechette/acl` (the upstream ACL library) — primary reference for the ACL bitstream format. Cited by repo name; the actual bitstream documentation lives in the library's source tree.
````

- [ ] **Step 3: Lint check**

Run: `cargo run -p paksmith-doc-lint --release -- required-headings docs/formats/`
Expected: exits 0.

- [ ] **Step 4: Commit**

```bash
git add docs/formats/animation/anim-sequence.md
git commit -m "$(cat <<'EOF'
docs(formats): add AnimSequence partial reference

Documents UAnimSequence: tagged-property segment with the Skeleton
reference + playback settings, FCompressedAnimSequence payload with
the legacy ACF_* codec set (None / Float96NoW / Fixed48NoW /
IntervalFixed32NoW / Fixed32NoW / Float32NoW / Identity) and the UE
4.21+ ACL codec variant. Notes per-bone-mask compression (UE 4.25+)
and curve-only compression (UE 5+). partial-not-impl; Phase 3 work
scoped.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Author `docs/formats/material/material.md` (partial)

`UMaterial` is the root material asset — defines a shader graph at
authoring time, but in cooked content paksmith only sees parameter
defaults + shader-map references. The compiled shader bytecode lives
in shader cache / DDC, which paksmith does not extract.

**Files:**
- Create: `docs/formats/material/material.md`

**Oracle references:**
- `CUE4Parse/UE4/Assets/Exports/Material/UMaterial.cs`
- `CUE4Parse/UE4/Assets/Exports/Material/FMaterialResource.cs`

- [ ] **Step 1: Look up oracle SHAs**

Run: `git ls-remote https://github.com/FabianFG/CUE4Parse HEAD | cut -f1` — `<CUE4PARSE_SHA>`.
Run: `git ls-remote https://github.com/AstralOrigin/unreal_asset HEAD | cut -f1` — `<UNREAL_ASSET_SHA>`.

- [ ] **Step 2: Write the doc**

Write `docs/formats/material/material.md`:

````markdown
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
serialized into a separate **shader cache** (or DDC entry) keyed by
the platform / quality / feature-level the cooker built for.

What paksmith CAN extract from a cooked `UMaterial` asset:

1. **Default parameter values** — `Texture2D` / `Scalar` / `Vector`
   parameters with their defaults, exposed via the standard
   tagged-property mechanism.
2. **Material flags** — `bUsedAsSpecialEngineMaterial`, `BlendMode`,
   `ShadingModel`, `TwoSided`, etc.
3. **Referenced textures** — `ObjectProperty` references that
   resolve through the asset's import table.
4. **Shader-map references** — `FMaterialResource` pointer to the
   platform shader map (which paksmith does NOT follow).

What paksmith CANNOT extract from a cooked `UMaterial`:

- **The shader graph itself** — gone at cook time.
- **Compiled shader bytecode** — lives in shader cache / DDC, a
  separate extraction problem.
- **Material expression nodes** — editor-only, stripped from cooked.

**Status: not yet implemented in paksmith.** Phase 3+ deliverable.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| UE 4.0+ | `UMaterial` + `FMaterialResource` introduced. Parameter wire shape stable. | `CUE4Parse/UE4/Assets/Exports/Material/UMaterial.cs@<CUE4PARSE_SHA>`[^1] |
| UE 4.25+ | `FMaterialShaderMapId` packing changes; expanded quality/feature-level matrix. | Same[^1] |
| UE 5.0+ | Strata shading-model field added; lots of tagged-property additions but underlying structure stable. | Same[^1] |
| UE 5.1+ | Substrate material system introduced as opt-in (separate `USubstrate*` classes). | Same[^1] |

## Wire layout

### Segment 1: tagged-property stream

Common properties paksmith will encounter:

| Property name | Type | Semantics |
|---------------|------|-----------|
| `BlendMode` | `ByteProperty` / `EnumProperty` (`EBlendMode`) | `BLEND_Opaque` / `Masked` / `Translucent` / etc. |
| `ShadingModel` | `ByteProperty` / `EnumProperty` (`EMaterialShadingModel`) | `MSM_DefaultLit` / `Unlit` / `Subsurface` / etc. |
| `TwoSided` | `BoolProperty` | |
| `bDisableDepthTest` | `BoolProperty` | |
| `OpacityMaskClipValue` | `FloatProperty` | Threshold for masked blend mode. |
| `MaterialDomain` | `ByteProperty` / `EnumProperty` (`EMaterialDomain`) | `MD_Surface` / `DeferredDecal` / `LightFunction` / `PostProcess` / etc. |
| `bUsedAsSpecialEngineMaterial` | `BoolProperty` | Engine reserves this material for built-in features. |
| `bUsedWithSkeletalMesh` | `BoolProperty` | Cooker compiles for SkeletalMesh-attached usage. |
| `bUsedWithStaticLighting` | `BoolProperty` | Cooker compiles light-map variants. |
| `bUsedWithLandscape` | `BoolProperty` | |
| `bUsedWithParticleSystem` | `BoolProperty` | |
| `bUsedWithFoliage` | `BoolProperty` | |
| `bUsedWithNanite` (UE 5+) | `BoolProperty` | |
| `MaterialAttributes` | `StructProperty(FMaterialAttributesInput)` | Editor-only-stripped from cooked. |
| `TextureParameterValues` | `ArrayProperty<StructProperty(FTextureParameterValue)>` | Editor-side defaults; cooked content carries them for runtime parameter overrides. |
| `ScalarParameterValues` | `ArrayProperty<StructProperty(FScalarParameterValue)>` | Same. |
| `VectorParameterValues` | `ArrayProperty<StructProperty(FVectorParameterValue)>` | Same. |

Properties terminate with the standard `"None"` tag.

### Segment 2: `FMaterialResource` shader-map references

After the property terminator, an `FMaterialResource` blob carries
the platform shader-map identifiers:

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `bCooked` | 4 | LE | `u32` (bool) | Expected `1`. |
| `NumLoadedShaderMaps` | 4 | LE | `i32` | Shader-map count for this material. |
| `LoadedShaderMaps` | variable | — | `FMaterialShaderMap[]` | One per platform/quality/feature-level cooked. |

Each `FMaterialShaderMap`:

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `ShaderMapId` | variable | — | `FMaterialShaderMapId` | Identifier: feature-level + quality + platform + content hash. |
| `Code` | variable | — | (skipped) | Compiled shader bytecode — paksmith reads the size and skips the bytes. |
| `EngineVersion` | variable | — | `FEngineVersion`[^4] | Engine version that compiled the shaders. |

paksmith's Phase 3 implementation should:

1. Read the property segment and surface the parameter defaults.
2. Detect the `FMaterialResource` blob but skip the compiled-shader
   bytes via the published size.
3. NOT attempt to interpret the shader bytecode — that requires
   per-platform shader-format knowledge (`SF_VULKAN_SM5`,
   `SF_METAL_*`, `SF_PCD3D_SM5`, etc.) that's out of scope.

### Worked example

`(none yet — no material fixture)`. When Phase 3 adds fixtures, the
canonical anchor will be a minimal `UMaterial` with one
TextureParameterValue (a default base-color texture reference).

## Variants

### Material domains

The `MaterialDomain` property splits materials into 5+ subtypes
(`Surface`, `DeferredDecal`, `LightFunction`, `Volume`,
`PostProcess`, `UserInterface`, `Virtual`). Each has slightly
different cooked shader-map shapes but the outer `FMaterialResource`
wire structure is the same.

### Substrate (UE 5.1+)

Substrate is UE's new shading-system replacing the legacy shading
model enum with a more compositional approach. Cooked Substrate
materials use separate UObject classes (`USubstrateMaterial`,
`USubstrateLayer`) outside this doc; only the legacy `UMaterial`
class is covered here.

### Material functions

`UMaterialFunction` is a separate class for reusable sub-graphs.
In cooked content, function references resolve through normal
ObjectProperty mechanisms; the function's own asset is parsed via
a different export specialization (not covered in this doc).

## Caps & limits

**Phase 3+ deferred work.**

- `MAX_SHADER_MAPS_PER_MATERIAL` cap (likely `1,024` — cooked
  builds rarely exceed a few hundred).
- `MAX_PARAMETERS_PER_MATERIAL` cap (likely matching
  `MAX_COLLECTION_ELEMENTS = 65,536`).

## Verification

- **Fixture:** `(none yet — Phase 3 deliverable)`.
- **Cross-validation oracle:** CUE4Parse[^1] (primary) and
  `unreal_asset`[^2].
- **Known divergences:**
  - **Shader bytecode unread.** CUE4Parse can parse the
    `FMaterialResource` shader bytecode (it has per-platform shader-
    format readers); paksmith deliberately won't. Aligns with
    paksmith's "extract data assets" focus vs CUE4Parse's broader
    "decompile shader graphs" remit. Both projects agree on the
    parameter-default extraction.

## Paksmith implementation

**Parser module:** *(not yet implemented — planned under
`crates/paksmith-core/src/asset/exports/material/material.rs`)*

**Status:** `not implemented`.

**Phase plan:** `docs/plans/ROADMAP.md` Phase 3.

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Exports/Material/UMaterial.cs@<CUE4PARSE_SHA>` plus `FMaterialResource.cs`, `FMaterialShaderMap.cs` in the same directory.
[^2]: `AstralOrigin/unreal_asset/unreal_asset/src/exports/material_export.rs@<UNREAL_ASSET_SHA>` — Rust counterpart.
[^3]: See [`material-instance.md`](material-instance.md) for the override-delta system that lets one `UMaterial` parent many runtime variants.
[^4]: See [`../primitive/fengine-version.md`](../primitive/fengine-version.md).
````

- [ ] **Step 3: Lint check**

Run: `cargo run -p paksmith-doc-lint --release -- required-headings docs/formats/`
Expected: exits 0.

- [ ] **Step 4: Commit**

```bash
git add docs/formats/material/material.md
git commit -m "$(cat <<'EOF'
docs(formats): add Material partial reference

Documents UMaterial: tagged-property segment with the parameter-
default arrays (TextureParameterValues, ScalarParameterValues,
VectorParameterValues) and the material-flag set (BlendMode /
ShadingModel / MaterialDomain / bUsedWith*), and the
FMaterialResource shader-map references. Spells out the
deliberate scope split: paksmith extracts parameter defaults
and texture references but does NOT decompile shader bytecode
(that lives in shader cache / DDC, separate extraction problem).
partial-not-impl; Phase 3 work scoped.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Author `docs/formats/material/material-instance.md` (partial)

`UMaterialInstance` (and its concrete subclass `UMaterialInstanceConstant`)
is the cooked-content delta layer on top of `UMaterial`. Override
values for specific parameters; inherit everything else.

**Files:**
- Create: `docs/formats/material/material-instance.md`

**Oracle references:**
- `CUE4Parse/UE4/Assets/Exports/Material/UMaterialInstance.cs`
- `CUE4Parse/UE4/Assets/Exports/Material/UMaterialInstanceConstant.cs`

- [ ] **Step 1: Look up oracle SHAs**

Run: `git ls-remote https://github.com/FabianFG/CUE4Parse HEAD | cut -f1` — `<CUE4PARSE_SHA>`.
Run: `git ls-remote https://github.com/AstralOrigin/unreal_asset HEAD | cut -f1` — `<UNREAL_ASSET_SHA>`.

- [ ] **Step 2: Write the doc**

Write `docs/formats/material/material-instance.md`:

````markdown
# MaterialInstance (`UMaterialInstance` / `UMaterialInstanceConstant`)

> Cooked-content delta layer on top of a parent `UMaterial` —
> overrides specific parameter values, inherits everything else.

## Overview

A `UMaterialInstance` lets the same parent `UMaterial`'s shader graph
serve many visual variants without compiling new shaders. The
instance carries:

1. A reference to the parent `UMaterial` (or to another
   `UMaterialInstance`, supporting chains).
2. Per-parameter override entries (Texture / Scalar / Vector).
3. Per-material-flag overrides (`OverriddenProperties`, a bitmask
   indicating which inherited flags are locally overridden).

The shader graph is **not** duplicated — `UMaterialInstance` always
defers to its parent's compiled shader bytecode for the actual
rendering. This is what makes instances cheap; instead of compiling
a new shader for each color variant, the engine uses the same
shader with different parameter binds.

The concrete subclass `UMaterialInstanceConstant` represents
authored static instances (the editor's "Create Material Instance
Constant"). `UMaterialInstanceDynamic` instances are runtime-
created and don't exist in cooked content.

**Status: not yet implemented in paksmith.** Phase 3+ deliverable.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| UE 4.0+ | `UMaterialInstance` + `UMaterialInstanceConstant` introduced. Parameter-override wire shape stable. | `CUE4Parse/UE4/Assets/Exports/Material/UMaterialInstance.cs@<CUE4PARSE_SHA>`[^1] |
| UE 4.25+ | `OverriddenProperties` bitmask widened to track more flags. | Same[^1] |
| UE 5.0+ | Strata-shading instance overrides. | Same[^1] |

## Wire layout

### Segment 1: tagged-property stream

| Property name | Type | Semantics |
|---------------|------|-----------|
| `Parent` | `ObjectProperty` (`UMaterialInterface`) | Parent `UMaterial` or `UMaterialInstance`; the inheritance source. |
| `PhysMaterial` | `ObjectProperty` (`UPhysicalMaterial`) | Override; otherwise inherits from parent. |
| `TextureParameterValues` | `ArrayProperty<StructProperty(FTextureParameterValue)>` | Texture overrides. |
| `ScalarParameterValues` | `ArrayProperty<StructProperty(FScalarParameterValue)>` | Scalar overrides. |
| `VectorParameterValues` | `ArrayProperty<StructProperty(FVectorParameterValue)>` | Vector overrides. |
| `FontParameterValues` | `ArrayProperty<StructProperty(FFontParameterValue)>` | Font overrides (rare). |
| `RuntimeVirtualTextureParameterValues` | `ArrayProperty<StructProperty(FRuntimeVirtualTextureParameterValue)>` | UE 4.23+. |
| `BasePropertyOverrides` | `StructProperty(FMaterialInstanceBasePropertyOverrides)` | Per-flag overrides (`BlendMode`, `OpacityMaskClipValue`, `TwoSided`, etc.). |
| `OverriddenProperties` | `IntProperty` (bitmask) / `StructProperty(FStaticParameterSet)` | Tracks which inherited flags are locally overridden. |
| `bHasStaticPermutationResource` | `BoolProperty` | UE 4.25+; if `true`, the instance has its own compiled shaders for static-parameter-permutation variants. |
| `StaticParameters` | `StructProperty(FStaticParameterSet)` | Static-switch / static-component-mask overrides that DO require new shader compilation. |

Per-parameter struct entries (`FTextureParameterValue`,
`FScalarParameterValue`, `FVectorParameterValue`) look like:

| Field | Type | Semantics |
|-------|------|-----------|
| `ParameterInfo` | `StructProperty(FMaterialParameterInfo)` | Name + association + group. |
| `ParameterValue` | (per-type) | The override value. |
| `ExpressionGUID` | `StructProperty(FGuid)` | Editor-tracking ID (often zero in cooked content). |

### Segment 2: `FMaterialResource` (UE 4.25+ static-permutation case)

When `bHasStaticPermutationResource == true`, the instance carries
its own `FMaterialResource` shader-map references (same wire shape
as `UMaterial`'s — see [`material.md`](material.md)). This happens
when the static parameter overrides change shader output (different
static switches or component masks).

In the common case (`bHasStaticPermutationResource == false`), the
instance has no shader-map blob — it defers entirely to the parent's
compiled shaders.

### Worked example

`(none yet — no material-instance fixture)`. When Phase 3 adds
fixtures, the canonical anchor will be a minimal
`UMaterialInstanceConstant` overriding one TextureParameterValue
to swap a base-color texture.

## Variants

### `UMaterialInstanceConstant` vs `UMaterialInstanceDynamic`

Cooked content carries only `UMaterialInstanceConstant` instances.
Dynamic instances are runtime-created.

### Static-permutation case

Instances overriding static parameters (`StaticSwitchParameter`,
`StaticComponentMaskParameter`) require their own compiled shaders.
This is the `bHasStaticPermutationResource == true` path; the
instance behaves more like a sibling `UMaterial` than a pure delta.

### Material-instance chains

An instance's parent can be another instance, not just a root
`UMaterial`. paksmith's parameter-resolution logic (when Phase 3
implements) needs to walk the chain to root.

## Caps & limits

**Phase 3+ deferred work.**

- `MAX_PARAMETERS_PER_INSTANCE` cap (matching `MAX_COLLECTION_ELEMENTS`).
- `MAX_INSTANCE_CHAIN_DEPTH` cap (likely 16 — cooked instances
  rarely chain more than 3-4 deep in practice).

## Verification

- **Fixture:** `(none yet — Phase 3 deliverable)`.
- **Cross-validation oracle:** CUE4Parse[^1] (primary) and
  `unreal_asset`[^2].
- **Known divergences:** same as `UMaterial` — paksmith won't
  decompile any per-instance shader bytecode (the static-permutation
  case).

## Paksmith implementation

**Parser module:** *(not yet implemented — planned under
`crates/paksmith-core/src/asset/exports/material/material_instance.rs`)*

**Status:** `not implemented`.

**Phase plan:** `docs/plans/ROADMAP.md` Phase 3. Likely ships
together with `UMaterial` since they share the parameter-override
struct readers.

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Exports/Material/UMaterialInstance.cs@<CUE4PARSE_SHA>` plus `UMaterialInstanceConstant.cs`, `FMaterialInstanceBasePropertyOverrides.cs`, `FStaticParameterSet.cs` in the same directory.
[^2]: `AstralOrigin/unreal_asset/unreal_asset/src/exports/material_instance_export.rs@<UNREAL_ASSET_SHA>` — Rust counterpart.
````

- [ ] **Step 3: Lint check**

Run: `cargo run -p paksmith-doc-lint --release -- required-headings docs/formats/`
Expected: exits 0.

- [ ] **Step 4: Commit**

```bash
git add docs/formats/material/material-instance.md
git commit -m "$(cat <<'EOF'
docs(formats): add MaterialInstance partial reference

Documents UMaterialInstance / UMaterialInstanceConstant: parent
reference, per-parameter override arrays (Texture / Scalar / Vector
/ Font / RuntimeVirtualTexture), BasePropertyOverrides + bitmask
of overridden flags, and the bHasStaticPermutationResource case
that triggers per-instance shader compilation. Notes
material-instance chains and the cooked-only UMaterialInstanceConstant
vs runtime UMaterialInstanceDynamic split. partial-not-impl;
Phase 3 work scoped.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Update root inventory + final verification + push

**Files:**
- Modify: `docs/formats/README.md`

- [ ] **Step 1: Capture branch HEAD + oracle SHAs**

Run: `git rev-parse --short HEAD` — note as `<SHA>`.
Run: `git ls-remote https://github.com/FabianFG/CUE4Parse HEAD | cut -f1` — `<CUE4PARSE_SHA>`.

- [ ] **Step 2: Add three rows to the inventory**

Verify the existing inventory layout with `grep -n "^|" docs/formats/README.md`, then use Edit to insert three new rows.

Rows to insert:

```markdown
| `animation/anim-sequence.md` | partial | not impl | — | CUE4Parse @ `<CUE4PARSE_SHA>` | n/a |
| `material/material.md` | partial | not impl | — | CUE4Parse @ `<CUE4PARSE_SHA>` | n/a |
| `material/material-instance.md` | partial | not impl | — | CUE4Parse @ `<CUE4PARSE_SHA>` | n/a |
```

All three `partial | not impl`.

- [ ] **Step 3: Run the status-enum linter**

Run: `cargo run -p paksmith-doc-lint --release -- status-enum docs/formats/README.md`
Expected: exits 0.

- [ ] **Step 4: Run the required-headings linter**

Run: `cargo run -p paksmith-doc-lint --release -- required-headings docs/formats/`
Expected: exits 0.

- [ ] **Step 5: Verify the file tree matches the inventory**

Run: `ls docs/formats/animation/*.md docs/formats/material/*.md | sort`
Expected:
```
docs/formats/animation/README.md
docs/formats/animation/anim-sequence.md
docs/formats/material/README.md
docs/formats/material/material-instance.md
docs/formats/material/material.md
```

- [ ] **Step 6: Run typos**

Run: `typos docs/formats/animation/ docs/formats/material/`
Expected: clean. Domain terms (`ACF`, `ACL`, `Frechette`, `Substrate`,
`USubstrate`, `UMaterialInstanceConstant`, `UMaterialInstanceDynamic`,
`FMaterialResource`, `FMaterialShaderMap`, `RuntimeVirtualTextureParameterValues`)
likely to flag — extend `_typos.toml` only when reword isn't natural.

- [ ] **Step 7: Run `cargo doc -D warnings`**

Run: `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features`
Expected: clean.

- [ ] **Step 8: Commit the inventory update**

```bash
git add docs/formats/README.md
git commit -m "$(cat <<'EOF'
docs(formats): register the animation + material docs in the inventory

Three partial-not-impl rows (anim-sequence, material,
material-instance): wire format documented from CUE4Parse +
unreal_asset oracles, paksmith implementation deferred to Phase 3.
Last-verified n/a; Phase 3's PR should bump to a real SHA when the
readers land. Two family directories share one PR per the spec
rollout's PR 11.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 9: Inspect the commit log**

Run: `git log --oneline origin/main..HEAD`
Expected: 4 commits (newest first):

```
<sha> docs(formats): register the animation + material docs in the inventory
<sha> docs(formats): add MaterialInstance partial reference
<sha> docs(formats): add Material partial reference
<sha> docs(formats): add AnimSequence partial reference
```

- [ ] **Step 10: Push the branch**

Run: `git push -u origin docs/ue-format-docs-animation-material`

- [ ] **Step 11: Open the PR**

Title: `docs(formats): populate animation + material families (anim-sequence/material/material-instance)`

Body — write to a tempfile first, then `gh pr create --body-file <tempfile>`:

```markdown
## Summary

Lands PR 11 of the UE format documentation framework. Two family
directories bundled per the spec rollout. Populates
`docs/formats/animation/` and `docs/formats/material/` with three
documents:

- **`animation/anim-sequence.md`** — `UAnimSequence` baked keyframe
  animation. Documents the seven legacy ACF_* codecs (None /
  Float96NoW / Fixed48NoW / IntervalFixed32NoW / Fixed32NoW /
  Float32NoW / Identity) with their per-key byte sizes and
  encoding rules, plus the UE 4.21+ ACL codec variant.
- **`material/material.md`** — `UMaterial` root material. Documents
  the parameter-default arrays (Texture / Scalar / Vector), the
  material-flag tagged properties (BlendMode / ShadingModel /
  MaterialDomain / bUsedWith*), and the `FMaterialResource`
  shader-map references. Spells out the deliberate scope split:
  paksmith extracts parameter defaults but does NOT decompile
  shader bytecode.
- **`material/material-instance.md`** — `UMaterialInstance` /
  `UMaterialInstanceConstant` delta layer. Documents the
  parent-reference inheritance, the per-parameter overrides, the
  `OverriddenProperties` bitmask, the `bHasStaticPermutationResource`
  case that triggers per-instance shader compilation, and the
  material-instance chains.

All three `partial | not impl`. Three rows added to the root
inventory.

## Linked issue

(none — design spec drives this work)

## Test plan

- [x] `paksmith-doc-lint required-headings` passes.
- [x] `paksmith-doc-lint status-enum` passes on the updated inventory.
- [x] `typos docs/formats/animation/ docs/formats/material/` clean.
- [x] `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features` clean.
- [x] Cross-referenced every wire-format claim against CUE4Parse +
      unreal_asset.

## Pre-flight checklist

- [x] PR title is a Conventional Commit.
- [x] Branch name follows `<type>/<kebab-case>`.
- [x] `cargo fmt --all` clean (no Rust changed).
- [x] `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean.
- [x] Documentation updated (this PR IS documentation).
- [x] No `unsafe` introduced.
- [x] Touched a parser? No — pure docs PR.

## Security considerations

The docs identify the cap shape Phase 3 will need
(`MAX_FRAMES_PER_ANIM`, `MAX_TRACKS_PER_ANIM`,
`MAX_SHADER_MAPS_PER_MATERIAL`, `MAX_PARAMETERS_PER_MATERIAL`,
`MAX_INSTANCE_CHAIN_DEPTH`). The material doc spells out the
"compiled shader bytecode skipped via published size" defense:
paksmith reads the size, advances past the bytes, and never
interprets the bytecode itself — a Phase-3 invariant flagged here.

## Notes for reviewers

- Bundling two family directories in one PR matches the spec
  rollout's PR 11 (`docs/design/2026-05-19-ue-format-docs.md`).
  Animation and material are unrelated content-wise; they share a
  PR for shipping cadence, not topical reasons.
- The `material.md` doc deliberately scopes paksmith to "parameter
  defaults + texture references", explicitly leaving the
  shader-bytecode decode to a future task (or to CUE4Parse). This
  is a design choice worth flagging — paksmith's remit is data
  extraction, not shader decompilation.
- The `anim-sequence.md` doc identifies ACL (Nicholas Frechette's
  Animation Compression Library) as the natural follow-up Phase 3
  deliverable once a Rust binding to ACL matures. The legacy ACF_*
  codecs are documented in enough detail to implement decoders
  directly from this doc.
- All three Worked Example sections are `(none yet)` — no fixtures
  exist. Phase 3 plans should add `minimal_anim_sequence_v5.uasset`,
  `minimal_material_v5.uasset`, and `minimal_material_instance_v5.uasset`.
```

- [ ] **Step 12: Run the standard reviewer panel**

Dispatch in a SINGLE message with multiple Agent tool calls:

- code-reviewer (general quality + spec adherence + factual
  accuracy against CUE4Parse references)
- code-architect (the scope split for materials is honest, the
  ACF_* codec catalog is correct, the material-instance inheritance
  model is correctly characterized)
- code-simplifier (per-codec key-size table isn't over-explained,
  per-parameter struct shape is appropriately compact)

Address issues, re-run on the fix commit, repeat until APPROVED.

---

## Done criteria

- 4 commits on `docs/ue-format-docs-animation-material` (three
  docs + inventory).
- `paksmith-doc-lint required-headings docs/formats/` exits 0.
- `paksmith-doc-lint status-enum docs/formats/README.md` exits 0.
- `typos docs/formats/animation/ docs/formats/material/` clean.
- `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features` clean.
- PR open with `--body-file`-generated body and lowercase verb-first title.
- Reviewer panel converged.
- Three rows present in inventory: `partial | not impl` × 3
  (anim-sequence, material, material-instance).
