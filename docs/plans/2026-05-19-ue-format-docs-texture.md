# UE Texture Family Documentation — PR 8 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Populate `docs/formats/texture/` with three documents — `texture2d.md` (the `Texture2D` UObject + `FTexturePlatformData` payload), `pixel-formats.md` (`EPixelFormat` enum + per-format on-disk layout), and `mips-and-streaming.md` (mip-chain partitioning across `.uasset` / `.uexp` / `.ubulk`). All three are `partial | not impl`: paksmith has zero texture parser code yet (Phase 3+ deliverable). Add three rows to the root inventory.

**Architecture:** Every doc fills the full per-doc template with prose-form content but explicitly marks Caps & limits and Verification as Phase 3+ deferred work (matching the `partial | not impl` status semantic established by `iostore-*.md` in PR 3 and `unversioned.md` in PR 5). Wire format content draws from CUE4Parse and unreal_asset; paksmith-implementation sections name the planned module location (`crates/paksmith-core/src/asset/exports/texture/`) and the Phase 3 plan.

**Tech Stack:** Pure markdown. PR 1 linters. Primary oracle is `FabianFG/CUE4Parse/UE4/Assets/Exports/Texture/`; secondary is `AstralOrigin/unreal_asset/unreal_asset/src/exports/`. Both ship Rust-or-C# texture readers and are the natural cross-validation targets when Phase 3 lands.

**Spec reference:** `docs/design/2026-05-19-ue-format-docs.md` (commit `72b364e`). **Prerequisite:** PR 1 (framework scaffold) has merged to `main`.

---

## Prerequisites

- PR 1 (`docs/ue-format-docs-framework`) has merged to `main`.
- Working in a worktree under `.claude/worktrees/docs+ue-format-docs-texture/`.
- `cargo build -p paksmith-doc-lint --release` succeeds.

## File structure

**Create (3 docs):**

- `docs/formats/texture/texture2d.md` — `Texture2D` UObject + platform-data payload.
- `docs/formats/texture/pixel-formats.md` — `EPixelFormat` enum catalog.
- `docs/formats/texture/mips-and-streaming.md` — mip-chain partitioning + streaming.

**Modify (1):**

- `docs/formats/README.md` — add three rows to the inventory.

**Oracle citation policy.** Primary: `CUE4Parse/UE4/Assets/Exports/Texture/` (covers `UTexture2D`, `FTexturePlatformData`, `EPixelFormat`, `FTexture2DMipMap` end-to-end). Secondary: `unreal_asset/src/exports/texture_export.rs` (Rust counterpart; will be a natural cross-validation oracle when paksmith implements).

**Hex-anchor policy.** `(none yet — Phase 3 deliverable)` for all three docs. paksmith has no texture fixtures because there's no texture parser to test against. A Phase 3 plan should add a `tests/fixtures/minimal_texture2d_*.uasset` fixture set when work opens.

---

## Task 1: Create worktree + verify prerequisites

**Files:** (environment setup only)

- [ ] **Step 1: Confirm PR 1 has merged**

Run: `git fetch origin && git log origin/main --oneline | grep -c "format documentation framework"`
Expected: ≥ 1.

- [ ] **Step 2: Create the worktree from origin/main**

From the primary checkout root:

Run: `git worktree add .claude/worktrees/docs+ue-format-docs-texture -b docs/ue-format-docs-texture origin/main`

- [ ] **Step 3: Switch session cwd into the worktree**

Run: `cd .claude/worktrees/docs+ue-format-docs-texture && pwd && git branch --show-current`
Expected: prints the worktree path and `docs/ue-format-docs-texture`.

- [ ] **Step 4: Verify the framework scaffold is present**

Run: `ls docs/formats/texture/README.md docs/formats/TEMPLATE.md docs/formats/CONVENTIONS.md`
Expected: all three files listed.

- [ ] **Step 5: Build the linter binary**

Run: `cargo build -p paksmith-doc-lint --release`
Expected: clean.

- [ ] **Step 6: Linter smoke-test**

Run: `cargo run -p paksmith-doc-lint --release -- required-headings docs/formats/`
Expected: exits 0.

Run: `cargo run -p paksmith-doc-lint --release -- status-enum docs/formats/README.md`
Expected: exits 0.

- [ ] **Step 7: Confirm no texture parser exists**

Run: `find crates/paksmith-core/src -name "texture*" -o -path "*export*texture*"`
Expected: no output. If anything turns up, Phase 3 has started — the `partial | not impl` status of every doc in this PR needs to be reconsidered.

No commit — environment setup only.

---

## Task 2: Author `docs/formats/texture/texture2d.md` (partial)

The most-common texture type. `UTexture2D` is a `UObject` that derives from `UTexture`; its serialized form is a tagged-property body (paksmith's [`../property/tagged.md`](../property/tagged.md) covers the per-property mechanics) followed by an `FTexturePlatformData` blob with the actual mip chain.

**Files:**
- Create: `docs/formats/texture/texture2d.md`

**Oracle references:**
- `CUE4Parse/UE4/Assets/Exports/Texture/UTexture2D.cs`
- `CUE4Parse/UE4/Assets/Exports/Texture/FTexturePlatformData.cs`

- [ ] **Step 1: Look up oracle SHAs**

Run: `git ls-remote https://github.com/FabianFG/CUE4Parse HEAD | cut -f1` — `<CUE4PARSE_SHA>`.
Run: `git ls-remote https://github.com/AstralOrigin/unreal_asset HEAD | cut -f1` — `<UNREAL_ASSET_SHA>`.

- [ ] **Step 2: Write the doc**

Write `docs/formats/texture/texture2d.md`:

````markdown
# Texture2D (`UTexture2D`)

> 2D texture asset — the most-common UE texture type. A
> `UObject`-derived tagged-property body followed by an
> `FTexturePlatformData` payload with the actual mip chain.

## Overview

`UTexture2D` is the UE class for 2D images: UI assets, material
diffuse / normal / metallic maps, sprite sheets, virtual-texture
tiles, light-cookies. On disk a `Texture2D` is a serialized
`UObject` whose export body is the tagged-property stream (see
[`../property/tagged.md`](../property/tagged.md) for the
mechanics) plus a trailing `FTexturePlatformData` blob — the
properties carry the texture's settings (compression, sRGB,
addressing mode, etc.) and the platform-data blob carries the
actual pixel bytes split into a mip chain.

The mip chain itself is partitioned across the `.uasset`, `.uexp`,
and `.ubulk` files using a tiered streaming layout — see
[`mips-and-streaming.md`](mips-and-streaming.md). The pixel format
that governs how each mip's bytes are interpreted is enumerated in
[`pixel-formats.md`](pixel-formats.md).

**Status: not yet implemented in paksmith.** This doc fills in the
wire format from CUE4Parse references but Caps & limits and
Verification are explicitly Phase 3+ deferred work. The doc is
`partial`, not `stub`, because every H2 section carries substantive
prose with TODO markers in the implementation-dependent sections.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| UE 4.0+ | `UTexture2D` introduced; serialized as tagged properties + `FTexturePlatformData`. | `CUE4Parse/UE4/Assets/Exports/Texture/UTexture2D.cs@<CUE4PARSE_SHA>`[^1] |
| UE 4.23+ | Virtual-texturing fields (`VirtualTextureBuildSettings`, etc.) added; mostly tagged properties so no wire-format break. | Same[^1] |
| UE 5.0+ | Optional `FStripDataFlags` prefix to several embedded structs; the structural shape doesn't change. | Same[^1] |

Within paksmith's accepted UE range, the `Texture2D` wire shape is
governed by the underlying tagged-property iteration plus the
`FTexturePlatformData` blob; per-version variance lives inside the
blob rather than at the `Texture2D` outer layer.

## Wire layout

A serialized `UTexture2D` export body has two segments:

### Segment 1: tagged-property stream

Standard `FPropertyTag` iteration (see [`../property/tagged.md`](../property/tagged.md)).
Common property names paksmith will encounter:

| Property name | Type | Semantics |
|---------------|------|-----------|
| `SRGB` | `BoolProperty` | Apply sRGB encoding on sample. |
| `CompressionSettings` | `ByteProperty` / `EnumProperty` (`TextureCompressionSettings`) | DXT / BC / ASTC / etc. — drives the cooker's choice of `EPixelFormat`. |
| `Filter` | `ByteProperty` / `EnumProperty` (`TextureFilter`) | Nearest / Linear / Anisotropic sampling. |
| `AddressX`, `AddressY` | `ByteProperty` / `EnumProperty` (`TextureAddress`) | Wrap / Clamp / Mirror. |
| `MipGenSettings` | `ByteProperty` / `EnumProperty` (`TextureMipGenSettings`) | Mip-generation algorithm chosen at cook time. |
| `LODBias` | `IntProperty` | Mip-level bias applied at runtime. |
| `NumCinematicMipLevels` | `IntProperty` | Cinematic-quality streaming reservation. |
| `NeverStream` | `BoolProperty` | If true, all mips inline in `.uasset` / `.uexp`. |
| `bUseLegacyGamma` | `BoolProperty` | Legacy gamma curve flag. |
| `LightingGuid` | `StructProperty` (`Guid`) | Editor-only consistency token. |

The properties terminate with the standard `"None"` tag.

### Segment 2: `FTexturePlatformData`

Immediately after the property terminator, an `FTexturePlatformData`
blob serializes. The blob carries the cooked mip chain plus the
metadata to interpret it.

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `SizeX` | 4 | LE | `i32` | Top-mip width in pixels (or blocks for compressed formats). |
| `SizeY` | 4 | LE | `i32` | Top-mip height. |
| `PackedData` | 4 | LE | `u32` | Bit-packed: low bits = `NumSlices` (depth for array textures), high bits = flags including "is-cubemap". |
| `PixelFormatString` | variable | — | `FString` | Name of the `EPixelFormat` variant (e.g. `"PF_DXT5"`). See [`pixel-formats.md`](pixel-formats.md). |
| `FirstMipToSerialize` | 4 | LE | `i32` | Top-mip skip-count (cooking optimization for downscaled platforms). |
| `Mips` | variable | — | `FTexture2DMipMap[]` | Counted-array prefix + per-mip records; see [`mips-and-streaming.md`](mips-and-streaming.md). |
| `bIsVirtual` | 4 | LE | `u32` | `0` = standard mip chain; `1` = virtual texture (different layout follows). |

A few asset versions add fields between `FirstMipToSerialize` and
`Mips` (`OptData`, `NumMipsInTail`, etc.). To be enumerated here when
Phase 3 implementation lands.

## Variants

### Virtual textures

When `bIsVirtual == 1`, the trailing data isn't a flat mip array but
an `FVirtualTextureBuiltData` record (page table + tile chunks). Far
less common in cooked content than streaming `Texture2D`; deferred.

### Texture cube / 2D array / volume

Cubemaps (`UTextureCube`), 2D arrays (`UTexture2DArray`), and volume
textures (`UVolumeTexture`) share most of the `Texture2D` wire shape
with extra slice / face metadata. Each will get its own doc when
Phase 3 specializes.

### Stripped editor-only data

When `PKG_FilterEditorOnly` is set on the package (typical for cooked
content), several `FStripDataFlags` markers gate editor-only fields
inside the platform-data blob. paksmith's existing summary check
already verifies the editor-only-stripped state.

## Caps & limits

**Phase 3+ deferred work.** When the texture reader lands, paksmith
will enforce caps mirroring the rest of the codebase:

- A per-texture `MAX_TEXTURE_DIMENSION` cap on `SizeX` / `SizeY` to
  prevent attacker-controlled-multi-GB allocations from a corrupted
  dimension field.
- A `MAX_MIP_COUNT` cap on the mip array prefix.
- A per-mip-byte cap inherited from the surrounding
  `MAX_UNCOMPRESSED_ENTRY_BYTES` (8 GiB) and `MAX_UEXP_SIZE` (1 GiB)
  in the parent pak + uexp layers.

See `docs/security/allocation-caps.md` for the broader policy.

## Verification

- **Fixture:** `(none yet — Phase 3 deliverable)`. Phase 3 will add
  `tests/fixtures/minimal_texture2d_uncompressed.uasset` /
  `_dxt5.uasset` / `_bc7.uasset` covering the dominant pixel formats.
- **Cross-validation oracle:** CUE4Parse[^1] (primary) and
  `unreal_asset`[^2]. Both decode the full Texture2D wire surface;
  paksmith will cross-validate against both when implementing.
- **Known divergences:** none yet — no implementation to diverge.

## Paksmith implementation

**Parser module:** *(not yet implemented — planned under
`crates/paksmith-core/src/asset/exports/texture/`)*

**Status:** `not implemented`. Encounters of `Texture2D` exports today
parse through the generic tagged-property iterator (the property
stream decodes successfully, surfacing as a `PropertyBag::Tree`);
the trailing `FTexturePlatformData` blob causes the iteration to
read past the "None" terminator into platform-data bytes, the read
errors, and the export falls back to `PropertyBag::Opaque` with a
`tracing::warn!` event. No actual mip bytes are recoverable until
the parser lands.

**Phase plan:** `docs/plans/ROADMAP.md` Phase 3 (Export Pipeline).
A Phase 3 plan should:

1. Add a `crates/paksmith-core/src/asset/exports/texture/` module
   with `Texture2D::read_from`.
2. Hook a per-export dispatch by class name (the export table's
   `class_index` resolves to the `Texture2D` import → trigger the
   specialized reader).
3. Add cap constants (`MAX_TEXTURE_DIMENSION`, `MAX_MIP_COUNT`).
4. Add fixtures + cross-validation against unreal_asset[^2].

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Exports/Texture/UTexture2D.cs@<CUE4PARSE_SHA>` and `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Exports/Texture/FTexturePlatformData.cs@<CUE4PARSE_SHA>` — primary oracle. Covers every version-conditional field paksmith will need.
[^2]: `AstralOrigin/unreal_asset/unreal_asset/src/exports/texture_export.rs@<UNREAL_ASSET_SHA>` — Rust counterpart. Will be paksmith's fixture-gen cross-validation oracle when Phase 3 lands.
````

- [ ] **Step 3: Lint check**

Run: `cargo run -p paksmith-doc-lint --release -- required-headings docs/formats/`
Expected: exits 0.

- [ ] **Step 4: Commit**

```bash
git add docs/formats/texture/texture2d.md
git commit -m "$(cat <<'EOF'
docs(formats): add Texture2D partial reference

Documents the UTexture2D wire shape: tagged-property segment with
the common properties (SRGB / CompressionSettings / Filter /
AddressX|Y / MipGenSettings / LODBias / NeverStream / bUseLegacyGamma /
LightingGuid) followed by an FTexturePlatformData blob with SizeX /
SizeY / PackedData / PixelFormatString / FirstMipToSerialize / Mips /
bIsVirtual fields. Notes the virtual-texture / cube / array / volume
variants and the editor-only-strip discipline. partial-not-impl;
Phase 3 work scoped.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Author `docs/formats/texture/pixel-formats.md` (partial)

The `EPixelFormat` enum — UE's catalog of GPU pixel layouts. Documents the dominant cooked-content formats (DXT/BC family for desktop, ASTC for mobile, ETC2 for some mobile, uncompressed RGBA/BGRA for special cases) with their block sizes, bytes-per-block, and the canonical decoding logic.

**Files:**
- Create: `docs/formats/texture/pixel-formats.md`

**Oracle references:**
- `CUE4Parse/UE4/Assets/Objects/PixelFormat.cs` (the enum + per-format metadata).
- `CUE4Parse/UE4/Assets/Exports/Texture/Bitmap.cs` (per-format decoders).

- [ ] **Step 1: Look up oracle SHAs**

Run: `git ls-remote https://github.com/FabianFG/CUE4Parse HEAD | cut -f1` — `<CUE4PARSE_SHA>`.
Run: `git ls-remote https://github.com/AstralOrigin/unreal_asset HEAD | cut -f1` — `<UNREAL_ASSET_SHA>`.

- [ ] **Step 2: Write the doc**

Write `docs/formats/texture/pixel-formats.md`:

````markdown
# Pixel formats (`EPixelFormat`)

> UE's enum of GPU pixel layouts — every variant a `Texture2D` /
> `TextureCube` / `Texture2DArray` etc. might use on disk. The
> `FString PixelFormatString` field in `FTexturePlatformData` names
> one of these variants; the decoded variant drives mip-byte
> interpretation.

## Overview

`EPixelFormat` is UE's tagged catalog of pixel layouts that the GPU
sampler hardware can address natively. Each variant is a small
enum-like constant with a known block size (in pixels), bytes per
block, and decoding rules.

In cooked content, the dominant formats per platform are:

- **Desktop**: `PF_DXT1` (legacy diffuse), `PF_DXT5` (alpha-diffuse),
  `PF_BC4` (single-channel — height maps, masks), `PF_BC5` (two-
  channel — normal maps), `PF_BC6H` (HDR), `PF_BC7` (high-quality
  RGB / RGBA).
- **Mobile (Android, mid-tier)**: `PF_ETC2_RGB`, `PF_ETC2_RGBA`.
- **Mobile (iOS / high-tier Android / desktop fallback)**:
  `PF_ASTC_4x4` through `PF_ASTC_12x12` (variable block-size).
- **Special**: `PF_R8G8B8A8`, `PF_B8G8R8A8`, `PF_FloatRGBA` (HDR),
  `PF_G8` (grayscale), `PF_G16` (16-bit grayscale).

paksmith will document the dominant set first; less-common variants
(PVRTC for older iOS, ETC1 for legacy Android, ASTC HDR variants) get
added when Phase 3+ encounters real-world cooked content using them.

**Status: not yet implemented in paksmith.** The texture exporter
(Phase 3+) will need per-format decoders to produce viewable image
output (PNG/EXR/etc.). This doc enumerates the formats and their
block-level wire shapes; the decoders themselves live with Phase 3+
work.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| All UE4 + UE5 | `EPixelFormat` evolves additively — new variants get appended; existing variants don't change semantics. UE5 added some HDR formats; the dominant cooked-content set is stable across UE 4.21–5.x. | `CUE4Parse/UE4/Assets/Objects/PixelFormat.cs@<CUE4PARSE_SHA>`[^1] |

UE serializes `EPixelFormat` by name (FString) in
`FTexturePlatformData`, not by discriminant value, so additive
changes don't break older parsers — they just produce "unknown
format" errors for new variants.

## Wire layout

`EPixelFormat` isn't a wire layout by itself — the variant *name*
is on the wire (an `FString` inside `FTexturePlatformData`); the
variant *semantics* are the bytes-per-block and per-block decoding
rules below.

### Block-compressed formats (DXT / BC family)

| Variant | Block size (pixels) | Bytes per block | Encoded channels | Common use |
|---------|---------------------|------------------|-------------------|------------|
| `PF_DXT1` | 4×4 | 8 | RGB (no alpha; 1-bit alpha variant exists) | Diffuse / albedo (legacy). |
| `PF_DXT3` | 4×4 | 16 | RGBA (4-bit explicit alpha) | Rarely used in cooked UE content. |
| `PF_DXT5` | 4×4 | 16 | RGBA (interpolated alpha) | Diffuse-with-alpha. |
| `PF_BC4` | 4×4 | 8 | Single-channel (R only) | Height maps, masks. |
| `PF_BC5` | 4×4 | 16 | Two-channel (RG) | Normal maps (X+Y; Z reconstructed). |
| `PF_BC6H` | 4×4 | 16 | RGB float | HDR. |
| `PF_BC7` | 4×4 | 16 | RGBA | High-quality diffuse / albedo. |

For all BC-family formats, mip dimensions are rounded up to
multiples of 4 (the block size). A 17×17 mip serializes as 5×5
blocks = 25 blocks. The wire-byte size of a mip is
`ceil(width / 4) × ceil(height / 4) × bytes_per_block`.

### ASTC family

| Variant | Block size (pixels) | Bytes per block | Encoded channels | Common use |
|---------|---------------------|------------------|-------------------|------------|
| `PF_ASTC_4x4` | 4×4 | 16 | RGBA | Highest quality. |
| `PF_ASTC_6x6` | 6×6 | 16 | RGBA | Medium quality. |
| `PF_ASTC_8x8` | 8×8 | 16 | RGBA | Lower quality. |
| `PF_ASTC_10x10` | 10×10 | 16 | RGBA | Very compressed. |
| `PF_ASTC_12x12` | 12×12 | 16 | RGBA | Smallest. |

ASTC always uses 16-byte blocks; the block dimension varies. Mip
size: `ceil(width / blockX) × ceil(height / blockY) × 16`.

### ETC2 family

| Variant | Block size (pixels) | Bytes per block | Encoded channels |
|---------|---------------------|------------------|-------------------|
| `PF_ETC2_RGB` | 4×4 | 8 | RGB. |
| `PF_ETC2_RGBA` | 4×4 | 16 | RGBA. |

### Uncompressed formats

| Variant | Bytes per pixel | Channels | Notes |
|---------|------------------|----------|-------|
| `PF_R8G8B8A8` | 4 | RGBA | Linear or sRGB depending on `SRGB` property. |
| `PF_B8G8R8A8` | 4 | BGRA | Direct-X-friendly byte order. |
| `PF_R8` / `PF_G8` | 1 | Grayscale | Mask / height. |
| `PF_R16F` / `PF_G16` | 2 | 16-bit single-channel | Precision-sensitive. |
| `PF_R16G16B16A16` | 8 | RGBA 16-bit | HDR cinematic. |
| `PF_FloatRGB` | 12 | RGB float | HDR. |
| `PF_FloatRGBA` | 16 | RGBA float | HDR with alpha. |

For uncompressed formats, mip wire-byte size is
`width × height × bytes_per_pixel`.

### Worked example

`(none yet — no texture fixture)`. When Phase 3 adds fixtures, the
canonical anchor will be the first mip's bytes of a `PF_DXT5`
texture — the first 4×4 block (16 bytes) starts with two
`u16` color endpoints (alpha curve) followed by 6 bytes of alpha
indices, then two `u16` color endpoints (RGB) followed by 4 bytes
of color indices.

## Variants

The "unknown format" case: when `PixelFormatString` resolves to a
variant paksmith doesn't recognize (e.g. a new UE5 HDR format added
after this doc was last updated), the reader should produce
`AssetParseFault::UnsupportedPixelFormat { name }` rather than
attempting to decode bytes per a guessed format. Forward-compatibility
follows the same shape as the `CompressionMethod::UnknownByName`
pattern in [`../compression/oodle.md`](../compression/oodle.md).

### Format-family conversions

The Phase 3 texture exporter will likely convert all formats to a
common intermediate (uncompressed RGBA8) before writing PNG/EXR/etc.
The per-format decoders (`detex`-equivalent or hand-written) live
with the exporter, not with the format-detection layer documented
here.

## Caps & limits

**Phase 3+ deferred work.** When the texture decoder lands:

- Per-mip byte cap inherited from `MAX_UNCOMPRESSED_ENTRY_BYTES` / `MAX_UEXP_SIZE`.
- A per-decoded-pixel cap on the intermediate RGBA8 buffer (the
  decoded form is typically 4× the compressed form, so a 1 GiB
  compressed mip becomes a 4 GiB intermediate buffer — this is the
  attack surface decoded-pixel caps need to bound).

## Verification

- **Fixture:** `(none yet — Phase 3 deliverable)`.
- **Cross-validation oracle:** CUE4Parse[^1] for the enum +
  per-format decoders; `unreal_asset`[^2] for the Rust counterpart.
- **Known divergences:** none yet.

## Paksmith implementation

**Parser module:** *(not yet implemented — planned under
`crates/paksmith-core/src/asset/exports/texture/pixel_format.rs`)*

**Status:** `not implemented`. Even the enum representation isn't
in paksmith's code today — `PixelFormatString` is just an `FString`
that the property reader surfaces as a string.

**Phase plan:** `docs/plans/ROADMAP.md` Phase 3 (Export Pipeline).
The Phase 3 plan should:

1. Add a Rust `PixelFormat` enum mirroring CUE4Parse's coverage
   (with `Unknown(String)` for forward-compatibility).
2. Add per-format `decode_block` functions for the dominant set.
3. Add a `MAX_DECODED_TEXTURE_BYTES` cap.

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Objects/PixelFormat.cs@<CUE4PARSE_SHA>` and `CUE4Parse/UE4/Assets/Exports/Texture/Bitmap.cs` — primary oracle for the enum + decoders.
[^2]: `AstralOrigin/unreal_asset/unreal_asset/src/exports/texture_export.rs@<UNREAL_ASSET_SHA>` — Rust counterpart.
````

- [ ] **Step 3: Lint check**

Run: `cargo run -p paksmith-doc-lint --release -- required-headings docs/formats/`
Expected: exits 0.

- [ ] **Step 4: Commit**

```bash
git add docs/formats/texture/pixel-formats.md
git commit -m "$(cat <<'EOF'
docs(formats): add pixel-formats partial reference

Catalogs EPixelFormat: DXT/BC family for desktop (DXT1/3/5/BC4/5/
6H/7), ASTC family for mobile (4x4 through 12x12), ETC2 family for
Android, and uncompressed formats (R8G8B8A8 / B8G8R8A8 / grayscale /
float). Documents block size, bytes-per-block, and mip-byte size
formula per format. partial-not-impl; Phase 3 decoder work scoped.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Author `docs/formats/texture/mips-and-streaming.md` (partial)

The mip-chain layout. Each mip is one of three storage tiers:

- **Inline** — bytes in the `.uasset` body itself (rare; usually only top mip of small textures).
- **`.uexp`-resident** — bytes in the export-body sidecar (common for medium textures or "always inline" texture mips).
- **`.ubulk`-streaming** — bytes in the bulk-data sidecar, demand-loaded by the runtime streaming system.

The `FTexture2DMipMap` record per mip publishes a `BulkData` field whose flags identify which tier it's in.

**Files:**
- Create: `docs/formats/texture/mips-and-streaming.md`

**Oracle references:**
- `CUE4Parse/UE4/Assets/Exports/Texture/FTexture2DMipMap.cs`.
- `CUE4Parse/UE4/Assets/Exports/Texture/FByteBulkData.cs`.

- [ ] **Step 1: Look up oracle SHAs**

Run: `git ls-remote https://github.com/FabianFG/CUE4Parse HEAD | cut -f1` — `<CUE4PARSE_SHA>`.
Run: `git ls-remote https://github.com/AstralOrigin/unreal_asset HEAD | cut -f1` — `<UNREAL_ASSET_SHA>`.

- [ ] **Step 2: Write the doc**

Write `docs/formats/texture/mips-and-streaming.md`:

````markdown
# Texture mip chains and streaming

> How a texture's mip chain is partitioned across the `.uasset`,
> `.uexp`, and `.ubulk` files, and how the runtime streaming system
> decides which mips to load.

## Overview

A UE texture isn't a single image — it's a **mip chain**: the full-
resolution top mip plus a sequence of progressively-halved-resolution
downsamples (mip 0 = full, mip 1 = half-each-axis, mip 2 = quarter-
each-axis, etc.). The chain stops when one dimension reaches 1
pixel.

On disk, mips are stored in three storage tiers depending on cooker
decisions and the texture's streaming settings:

- **Inline** in the `.uasset`: the top mip(s) of small textures
  (UI icons, etc.) or any texture with `NeverStream = true`. Cheapest
  to load because no companion file lookup.
- **In `.uexp`**: most textures' inline mips. The `.uexp` sidecar
  carries them as part of the export body (see
  [`../asset/uexp.md`](../asset/uexp.md)).
- **Streaming, in `.ubulk`**: the bottom (high-resolution) mips of
  larger textures. The runtime streaming system demand-loads these
  based on camera proximity / texture LOD settings (see
  [`../asset/ubulk.md`](../asset/ubulk.md)).

Each per-mip `FTexture2DMipMap` record contains an `FByteBulkData`
field whose flags identify which tier the mip's bytes live in plus
their offset / size within that tier's file.

**Status: not yet implemented in paksmith.** Phase 2e detects
`.ubulk` siblings (see [`../asset/ubulk.md`](../asset/ubulk.md)) but
doesn't stitch their bytes. Phase 3+ work — driven by the texture
exporter — will implement per-mip resolution.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| UE 4.0+ | Three-tier (inline / uexp / ubulk) streaming introduced. | `CUE4Parse/UE4/Assets/Exports/Texture/FByteBulkData.cs@<CUE4PARSE_SHA>`[^1] |
| UE 4.26+ | `FByteBulkData::BulkDataFlags` widened from `u32` to `i64` (older `u32` form still appears in cooked content). | Same[^1] |
| UE 5.0+ | `FBulkDataCookedIndex` introduced for some bulk-data records; mostly applies to runtime-virtual-texture chunks. | Same[^1] |

## Wire layout

### `FTexture2DMipMap` (per-mip record)

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `bCooked` | 4 | LE | `u32` | Bool encoded as u32; expected `1` for cooked content. |
| `BulkData` | variable | — | `FByteBulkData` | The actual mip byte payload + tier metadata. |
| `SizeX` | 4 | LE | `i32` | Mip width in pixels (block units for compressed). |
| `SizeY` | 4 | LE | `i32` | Mip height. |
| `SizeZ` | 4 | LE | `i32` | Mip depth (1 for `Texture2D`; >1 for `Texture2DArray` / `VolumeTexture`). |

Note the unusual ordering: `BulkData` is serialized **between**
`bCooked` and the `SizeX/Y/Z` triple, not after them.

### `FByteBulkData`

The per-storage-tier record.

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `BulkDataFlags` | 4 or 8 | LE | `u32` (pre-UE 4.26) or `i64` (4.26+) | Bitfield publishing the storage tier + flags. See bit catalog below. |
| `ElementCount` | 4 or 8 | LE | `i32` or `i64` | Number of elements (bytes for byte bulk data). The width matches `BulkDataFlags`. |
| `BulkDataSizeOnDisk` | 4 or 8 | LE | `i32` or `i64` | Stored byte size (post-compression if applicable). |
| `BulkDataOffsetInFile` | 8 | LE | `i64` | Byte offset within the containing file (which file depends on the tier flags). |

The "containing file" is whichever of `.uasset` / `.uexp` / `.ubulk`
the flags identify.

### `BulkDataFlags` bit catalog

| Bit name | Hex | Meaning |
|----------|-----|---------|
| `BULKDATA_PayloadAtEndOfFile` | `0x0001` | Payload bytes are at `BulkDataOffsetInFile` of the *parent file* (`.uasset` for inline, `.uexp` for uexp-resident). |
| `BULKDATA_SerializeCompressedZLIB` | `0x0002` | Payload zlib-compressed; decompress before use. |
| `BULKDATA_ForceSingleElementSerialization` | `0x0004` | Element-by-element serialization (rare for textures). |
| `BULKDATA_SingleUse` | `0x0008` | Discard after first read. |
| `BULKDATA_Unused` | `0x0020` | Legacy. |
| `BULKDATA_ForceInlinePayload` | `0x0040` | Inline regardless of streaming settings. |
| `BULKDATA_SerializeCompressed` | `0x0100` | Compression-method-method-table-driven (UE 4.20+); reads the actual method from the `FArchive`. |
| `BULKDATA_ForceStreamPayload` | `0x0200` | Force streaming (use `.ubulk`). |
| `BULKDATA_PayloadInSeperateFile` | `0x0400` | Payload is in a separate file (`.ubulk`). |
| `BULKDATA_SerializeCompressedBitWindow` | `0x0800` | Uses a custom bit window for compression. |
| `BULKDATA_OptionalPayload` | `0x0800` | Payload may not be present at all (`.uptnl` companion). |
| `BULKDATA_MemoryMappedPayload` | `0x1000` | Memory-mapped on supported platforms. |
| `BULKDATA_Size64Bit` | `0x2000` | Sizes are 64-bit (always set on UE 4.26+). |
| `BULKDATA_DuplicateNonOptionalPayload` | `0x4000` | Duplicated for redundancy. |
| `BULKDATA_BadDataVersion` | `0x8000` | Sentinel for older bad data. |
| `BULKDATA_NoOffsetFixUp` | `0x0001_0000` | Don't apply offset fix-up. |
| `BULKDATA_WorkspaceDomainPayload` | `0x0002_0000` | Editor-domain payload. |

### Tier dispatch

The tier the bytes live in is determined by `BulkDataFlags`:

| Flag combination | Tier | File |
|------------------|------|------|
| `BULKDATA_PayloadAtEndOfFile` only | Inline | The `.uasset` itself; `BulkDataOffsetInFile` is from the `.uasset`'s start. |
| `BULKDATA_PayloadAtEndOfFile` + (in `.uexp` region) | uexp-resident | `.uexp`; offset is from `.uasset` start (after stitching, that's `total_header_size + uexp_offset`). |
| `BULKDATA_PayloadInSeperateFile` | Streaming | `.ubulk`; offset is from `.ubulk`'s start. |
| `BULKDATA_OptionalPayload` + `BULKDATA_PayloadInSeperateFile` | Optional streaming | `.uptnl`. |

The distinction between "inline" and "uexp-resident" comes down to
whether `BulkDataOffsetInFile` falls within `[0, total_header_size)`
(inline) or `[total_header_size, …)` (uexp-resident). Both use the
same flag (`BULKDATA_PayloadAtEndOfFile`); the offset disambiguates.

### Worked example

`(none yet — no texture fixture)`. When Phase 3 lands, a `PF_DXT5`
512×512 texture's mip chain would publish 10 mips (`512×512` →
`256×256` → … → `1×1`); the top 3-5 might be in `.ubulk`-streaming
tier while the bottom (downsampled) ones live in `.uexp`-resident
tier.

## Variants

### Cubemaps and texture arrays

Cubemap textures have 6 face mip chains; `SizeZ = 6` (or
`6 × num_array_slices` for cube arrays). The per-mip records carry
all faces concatenated.

### Virtual textures

Virtual textures don't use the three-tier mip system — they use a
page-table-and-tile-chunks scheme published by
`FVirtualTextureBuiltData`. Documented in `texture2d.md`'s Variants
section.

### `BULKDATA_SerializeCompressed` per-mip compression

Texture mips can be compressed at the `FByteBulkData` layer (in
addition to per-block compression from the pak layer). The mip's
post-decompression bytes are the actual pixel data. paksmith's
existing zlib decompressor handles this when the bulk data is
zlib-compressed; Oodle-compressed mip bulk data is gated on the
same SDK integration as the pak-side Oodle work (see
[`../compression/oodle.md`](../compression/oodle.md)).

## Caps & limits

**Phase 3+ deferred work.** When the mip resolver lands:

- A `MAX_MIPS_PER_TEXTURE` cap (UE never cooks more than ~16
  mips for any reasonable resolution — 16,384px max width / height).
- The per-mip byte caps inherited from the underlying file's caps
  (`MAX_UNCOMPRESSED_ENTRY_BYTES` for pak-resident bytes,
  `MAX_UEXP_SIZE` for `.uexp` bytes, future `.ubulk` cap).

## Verification

- **Fixture:** `(none yet — Phase 3 deliverable)`.
- **Cross-validation oracle:** CUE4Parse[^1] and `unreal_asset`[^2].
- **Known divergences:** none yet.

## Paksmith implementation

**Parser module:** *(not yet implemented — planned under
`crates/paksmith-core/src/asset/exports/texture/mip_resolver.rs`)*

**Status:** `not implemented`. paksmith's Phase 2e companion
detection identifies that a `.ubulk` exists but doesn't read its
bytes (see [`../asset/ubulk.md`](../asset/ubulk.md)). Phase 3 will
add the mip resolver that combines the `.uasset` / `.uexp` / `.ubulk`
into a per-mip byte lookup.

**Phase plan:** `docs/plans/ROADMAP.md` Phase 3 (Export Pipeline).
The Phase 3 plan should:

1. Add an `FByteBulkData` reader with the flag-bit catalog.
2. Add a `MipResolver` that takes a `(Package, ubulk_bytes)` pair
   and returns per-mip byte slices.
3. Hook the resolver into the planned Phase 3 texture exporter.

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Exports/Texture/FTexture2DMipMap.cs@<CUE4PARSE_SHA>` and `CUE4Parse/UE4/Assets/Exports/Texture/FByteBulkData.cs@<CUE4PARSE_SHA>` — primary oracle for the per-mip + bulk-data records and the flag-bit catalog.
[^2]: `AstralOrigin/unreal_asset/unreal_asset/src/exports/bulk_data.rs@<UNREAL_ASSET_SHA>` — Rust counterpart.
````

- [ ] **Step 3: Lint check**

Run: `cargo run -p paksmith-doc-lint --release -- required-headings docs/formats/`
Expected: exits 0.

- [ ] **Step 4: Commit**

```bash
git add docs/formats/texture/mips-and-streaming.md
git commit -m "$(cat <<'EOF'
docs(formats): add mips-and-streaming partial reference

Documents the three-tier mip storage (inline / uexp-resident /
ubulk-streaming) with the FTexture2DMipMap and FByteBulkData record
shapes, the bulk-data flag-bit catalog including the .uptnl
optional-payload bit, and the tier-dispatch logic (offset within
[0, total_header_size) → inline; >= total_header_size →
uexp-resident; BULKDATA_PayloadInSeperateFile → ubulk). partial-
not-impl; Phase 3 mip-resolver scoped.

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
| `texture/texture2d.md` | partial | not impl | — | CUE4Parse @ `<CUE4PARSE_SHA>` | n/a |
| `texture/pixel-formats.md` | partial | not impl | — | CUE4Parse @ `<CUE4PARSE_SHA>` | n/a |
| `texture/mips-and-streaming.md` | partial | not impl | — | CUE4Parse @ `<CUE4PARSE_SHA>` | n/a |
```

All three `partial | not impl`. `Last verified` is `n/a` because
there's no implementation to verify against — when Phase 3 lands and
implements a texture reader, the Phase 3 PR should bump `Last verified`
to a real SHA at the same time it changes the parser-status to
`partial` or `complete`.

- [ ] **Step 3: Run the status-enum linter**

Run: `cargo run -p paksmith-doc-lint --release -- status-enum docs/formats/README.md`
Expected: exits 0. `partial | not impl` doesn't trip any smell warns
(`complete | not impl` warns; `stub | complete` warns; the
intermediate combinations are clean).

- [ ] **Step 4: Run the required-headings linter**

Run: `cargo run -p paksmith-doc-lint --release -- required-headings docs/formats/`
Expected: exits 0.

- [ ] **Step 5: Verify the file tree matches the inventory**

Run: `ls docs/formats/texture/*.md | sort`
Expected:
```
docs/formats/texture/README.md
docs/formats/texture/mips-and-streaming.md
docs/formats/texture/pixel-formats.md
docs/formats/texture/texture2d.md
```

- [ ] **Step 6: Run typos**

Run: `typos docs/formats/texture/`
Expected: clean. Domain terms (DXT, BC4, BC5, BC6H, BC7, ASTC, ETC2,
PVRTC, mipmap, FTexture2DMipMap, EPixelFormat, FByteBulkData) likely
to flag — extend `_typos.toml` only when reword isn't natural.

- [ ] **Step 7: Run `cargo doc -D warnings`**

Run: `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features`
Expected: clean.

- [ ] **Step 8: Commit the inventory update**

```bash
git add docs/formats/README.md
git commit -m "$(cat <<'EOF'
docs(formats): register the texture-family docs in the inventory

Three partial-not-impl rows (texture2d, pixel-formats, mips-and-
streaming): wire format documented from CUE4Parse + unreal_asset
oracles, paksmith implementation deferred to Phase 3. Last-verified
n/a because there's no parser to verify against; Phase 3's PR
should bump to a real SHA when the texture reader lands.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 9: Inspect the commit log**

Run: `git log --oneline origin/main..HEAD`
Expected: 4 commits (newest first):

```
<sha> docs(formats): register the texture-family docs in the inventory
<sha> docs(formats): add mips-and-streaming partial reference
<sha> docs(formats): add pixel-formats partial reference
<sha> docs(formats): add Texture2D partial reference
```

- [ ] **Step 10: Push the branch**

Run: `git push -u origin docs/ue-format-docs-texture`

- [ ] **Step 11: Open the PR**

Title: `docs(formats): populate texture family (texture2d/pixel-formats/mips-and-streaming)`

Body — write to a tempfile first, then `gh pr create --body-file <tempfile>`:

```markdown
## Summary

Lands PR 8 of the UE format documentation framework. Populates
`docs/formats/texture/` with three documents:

- **`texture2d.md`** — `UTexture2D` tagged-property segment +
  `FTexturePlatformData` payload (SizeX / SizeY / PackedData /
  PixelFormatString / FirstMipToSerialize / Mips / bIsVirtual).
  Calls out virtual-texture / cube / array / volume variants and
  the editor-only-strip discipline.
- **`pixel-formats.md`** — `EPixelFormat` catalog: DXT / BC family
  for desktop, ASTC family for mobile, ETC2 family for Android,
  uncompressed formats. Per-format block size, bytes-per-block,
  and mip-byte-size formula documented.
- **`mips-and-streaming.md`** — three-tier mip storage (inline /
  uexp-resident / ubulk-streaming) with the `FByteBulkData`
  flag-bit catalog and the tier-dispatch logic.

All three are `partial | not impl`: wire format is documented from
CUE4Parse and unreal_asset oracles, paksmith implementation is
Phase 3+ deferred work.

Three rows added to the root inventory, all `partial | not impl`.

## Linked issue

(none — design spec drives this work)

## Test plan

- [x] `paksmith-doc-lint required-headings` passes.
- [x] `paksmith-doc-lint status-enum` passes on the updated inventory.
- [x] `typos docs/formats/texture/` clean.
- [x] `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features` clean.
- [x] Cross-referenced every wire-format claim against CUE4Parse +
      unreal_asset (no paksmith-side parser exists to triangulate against).

## Pre-flight checklist

- [x] PR title is a Conventional Commit.
- [x] Branch name follows `<type>/<kebab-case>`.
- [x] `cargo fmt --all` clean (no Rust changed).
- [x] `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean.
- [x] Documentation updated (this PR IS documentation).
- [x] No `unsafe` introduced.
- [x] Touched a parser? No — pure docs PR.

## Security considerations

The docs document the cap shape Phase 3 will need
(`MAX_TEXTURE_DIMENSION`, `MAX_MIP_COUNT`, `MAX_DECODED_TEXTURE_BYTES`)
and explicitly note that decoded uncompressed buffers are typically
4× the compressed form — i.e. an attacker can amplify a 1 GiB
compressed mip into a 4 GiB intermediate decode buffer. The cap on
decoded bytes is a Phase-3 deliverable but flagged in `pixel-formats.md`
as a known attack surface.

## Notes for reviewers

- All three docs are `partial | not impl`. The status combination
  matches the pattern established by `iostore-*.md` in PR 3 and
  `unversioned.md` in PR 5 — wire format sketched, paksmith side
  explicitly absent. Phase 3's PR should both implement the parser
  and bump the status fields to `partial` (then later `complete`)
  in the same PR.
- The `pixel-formats.md` worked example is `(none yet)` because no
  texture fixture exists. Adding one is a Phase 3 deliverable.
- The `mips-and-streaming.md` doc cross-references
  `compression/oodle.md` for the case where per-mip `BulkData` is
  Oodle-compressed — the same SDK-loading constraint applies. This
  isn't an additional ask; it's just acknowledging that the
  Phase 3 texture work won't fully decode Oodle-compressed mips
  until the Oodle SDK integration also lands.
```

- [ ] **Step 12: Run the standard reviewer panel**

Dispatch in a SINGLE message with multiple Agent tool calls:

- code-reviewer (general quality + spec adherence + factual accuracy
  against CUE4Parse references)
- code-architect (status-pair coherence, the partial-not-impl labels
  honest given the spec's enum semantics, the Phase 3 insertion
  points correctly identified)
- code-simplifier (the pixel-format tables aren't over-explained, the
  flag-bit catalog is appropriately compact)

Address issues, re-run on the fix commit, repeat until APPROVED.

---

## Done criteria

- 4 commits on `docs/ue-format-docs-texture` (three docs + inventory).
- `paksmith-doc-lint required-headings docs/formats/` exits 0.
- `paksmith-doc-lint status-enum docs/formats/README.md` exits 0.
- `typos docs/formats/texture/` clean.
- `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features` clean.
- PR open with `--body-file`-generated body and lowercase verb-first title.
- Reviewer panel converged.
- Three rows present in inventory: three `partial | not impl`
  (texture2d, pixel-formats, mips-and-streaming).
