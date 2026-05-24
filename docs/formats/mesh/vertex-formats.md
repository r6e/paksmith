# Packed vertex formats

> Per-vertex packed binary layouts used by `UStaticMesh` and
> `USkeletalMesh`: positions, normals + tangents, UVs, colors. The
> packing choices trade GPU memory for sample precision.

## Overview

UE's mesh vertex data is **packed** for GPU efficiency. A
single vertex in a cooked mesh isn't a flat `(position, normal,
tangent, uv0, uv1, color)` struct — each component lives in its
own buffer (Structure-of-Arrays layout), and within each buffer
the per-vertex bytes use a packed encoding chosen at cook time
based on the LOD's quality target.

This doc catalogs the buffer-level wire shapes shared across
`static-mesh.md` and `skeletal-mesh.md`. Per-buffer details:

- **Position buffer** — always full f32 precision (UE5 LWC upgrades
  to f64).
- **Normal-tangent buffer** — typically packed (4 × 8-bit or
  4 × 16-bit), with a "high precision" override for f16-per-component.
- **UV buffer** — typically `f16` halves; "high precision" override
  for `f32`. 0–4 UV channels per vertex.
- **Color buffer** — `FColor` (4 × `u8`) when present; entire buffer
  omitted otherwise.

**Status: not yet implemented in paksmith.** Phase 3+ deliverable.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| UE 4.0+ | Packed vertex formats introduced. | `CUE4Parse/UE4/Objects/Meshes/FPositionVertexBuffer.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d`[^1] |
| UE 4.12+ | `bUseHighPrecisionTangentBasis` opt-in added to `FStaticMeshVertexBuffer`. | Same[^1] |
| UE 4.19+ | `FStaticMeshVertexBuffer` `Stride` field dropped from the wire; tangents and UV coords serialized as separate bulk arrays. | Same[^1] |
| UE 4.20+ | High-precision-UV opt-in (`bUseFullPrecisionUVs`) | Same[^1] |
| UE 5.0+ | LWC widens `FPositionVertexBuffer` vertex positions from f32 to f64. | Same[^1] |

The 10-10-10-2 vs 8-8-8-8 normal-tangent split is the most-impactful
version-conditional in this doc.

## Wire layout

### `FPositionVertexBuffer`

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `Stride` | 4 | LE | `i32` | Bytes per vertex; typically `12` (UE4 f32 vector) or `24` (UE5 LWC f64 vector). |
| `NumVertices` | 4 | LE | `i32` | Vertex count. |
| `Vertices` | `Stride × NumVertices` | LE | f32 or f64 vec3 | Per-vertex positions (bulk array). |

UE5 LWC content carries f64 positions; the `Stride` field
disambiguates without paksmith having to read the parent asset's
version explicitly.

### `FStaticMeshVertexBuffer` — normal-tangent + UV layout

The most-complex vertex buffer. Encodes per-vertex normal + tangent
(2 vectors) and 1–4 UV channels.[^1]

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `NumTexCoords` | 4 | LE | `i32` | UV channel count (1–4). |
| `Stride` (pre-UE4.19 only) | 4 | LE | `i32` | Bytes per vertex in the legacy combined layout; set to -1 and absent for UE4.19+ (read as separate bulk arrays). |
| `NumVertices` | 4 | LE | `i32` | |
| `bUseFullPrecisionUVs` | 4 | LE | `u32` (bool) | If `1`, UVs are `f32`; otherwise `f16` halves. |
| `bUseHighPrecisionTangentBasis` (UE4.12+) | 4 | LE | `u32` (bool) | If `1`, normal+tangent are `f16` halves (16 bytes per vertex pair); otherwise packed (8 bytes per vertex pair). |
| `TangentsData` | variable | — | per-vertex packed normal+tangent bulk array | See packing dispatch below. |
| `TexCoordData` | variable | — | per-vertex UV × NumTexCoords bulk array | f16 or f32 per UV component. |

Per-vertex tangent-basis packing dispatch:

| `bUseHighPrecisionTangentBasis` | UE version | Tangent + Normal encoding | Bytes per vertex pair |
|----------------------------------|------------|----------------------------|-----------------------|
| `false` | UE 4.0–4.24 | `FPackedNormal × 2` (4 × u8 each) | 8 |
| `false` | UE 4.25+ | `FPackedRGBA16N × 2` (10-10-10-2 u32 each) | 8 |
| `true` | UE 4.12+ | `FFloat16 × 8` (f16 per component, 4 per vector × 2 vectors) | 16 |

(The two `false` cases share the same 8-byte size but different
encodings — the asset version disambiguates. Phase 3 will need to
key off `FRenderingObjectVersion.IncreaseNormalPrecision` to
distinguish the 8-bit and 10-bit variants.)

### `FPackedNormal` (4 × u8 normal-tangent component)

4 bytes total; each component `u8 / 127.5 - 1.0` → `[-1, 1]`.[^1]

| offset | size | name | semantics |
|--------|------|------|-----------|
| 0 | 1 | `X` | X component: `(byte & 0xFF) / 127.5 - 1`. |
| 1 | 1 | `Y` | Y component. |
| 2 | 1 | `Z` | Z component. |
| 3 | 1 | `W` | W component (sign bit for tangent handedness). |

Total: 4 bytes per normal or tangent. Two `FPackedNormal` values
(normal + tangent) = 8 bytes per vertex in the low-precision path.

### `FPackedRGBA16N` (10-10-10-2 normal-tangent component)

A `u32` packed with 4 fields:

| bits | size | name | semantics |
|------|------|------|-----------|
| 0–9 | 10 | `X` | X component as `u10 / 511 - 1` mapped to `[-1, 1]`. |
| 10–19 | 10 | `Y` | Y component. |
| 20–29 | 10 | `Z` | Z component. |
| 30–31 | 2 | `W` | 2-bit sign for tangent handedness. |

Total: 4 bytes per normal or tangent. Provides ~2× the precision of
the 8-bit variant for the same byte cost.

### `FColorVertexBuffer`

Prefixed by `FStripDataFlags` (controls whether visual data is
present), then:[^1]

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `Stride` | 4 | LE | `i32` | Typically `4` (FColor = 4 × u8). |
| `NumVertices` | 4 | LE | `i32` | |
| `Colors` | `Stride × NumVertices` | LE | `FColor` (4 × `u8`) | BGRA order. Omitted when `FStripDataFlags.IsAudioVisualDataStripped()` or `NumVertices == 0`. |

The whole buffer is omitted when the LOD has no vertex colors —
typically signaled by `bHasVertexColors == 0` on the parent
`FStaticMeshRenderData` or `USkeletalMesh`.

### `FRawStaticIndexBuffer` / `FMultisizeIndexContainer`

Index buffers — records the triangles' vertex references.

**`FRawStaticIndexBuffer` (static mesh):**[^1]

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `is32bit` | 4 | LE | `u32` (bool) | If `1`, indices are 32-bit; otherwise 16-bit. |
| `Data` | variable | — | bulk `u8[]` | Raw index bytes; parsed as `u16[]` or `u32[]` per `is32bit`. |

Note: for older content (pre-`SUPPORT_32BIT_STATIC_MESH_INDICES`),
the buffer is a plain bulk `u16[]` with no `is32bit` prefix.

**`FMultisizeIndexContainer` (skeletal mesh):**

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `ElementSize` | 1 | — | `u8` | `2` or `4` (bytes per index). |
| `Indices` | variable | — | bulk `u16[]` or `u32[]` | Per-triangle vertex indices, 3 per triangle. |

UE picks 16-bit when the LOD's `MaxVertexIndex < 65,535` (most
production assets); 32-bit only when the LOD exceeds the cap.

### Worked example

`(none yet — no mesh fixture)`. When Phase 3 adds fixtures, the
canonical anchor will be the cube's `FPositionVertexBuffer`:
`Stride = 12, NumVertices = 8, Vertices = [-0.5, -0.5, -0.5, ...]`
giving 4-byte stride header + 4-byte count + 96 bytes of f32 vertex
data.

## Variants

### LWC positions (UE 5.x)

When `FPositionVertexBuffer::Stride == 24`, positions are `f64`
triples (LWC). Phase 3 readers must check stride rather than
hardcoding `f32`.

### High-precision UVs

When `bUseFullPrecisionUVs == 1`, UVs are full `f32` (8 bytes per
UV channel) instead of `f16` halves (4 bytes per channel). Visible
in the buffer's per-vertex `Stride` field.

### 10-10-10-2 vs 4 × 8-bit tangent basis

`bUseHighPrecisionTangentBasis == 0` is the common case;
`== 1` is rare in cooked content. Within the `== 0` case, the
disambiguation between 4 × 8-bit (older) and 10-10-10-2 (newer)
relies on `FRenderingObjectVersion.IncreaseNormalPrecision`.

## Caps & limits

**Phase 3+ deferred work.** Per-buffer:

- `Stride × NumVertices` must fit in the parent file's residual
  bytes (caps inherited from `MAX_UNCOMPRESSED_ENTRY_BYTES` /
  `MAX_UEXP_SIZE`).
- A future `MAX_VERTICES_PER_LOD` cap (in addition to the cap above)
  to bound per-LOD allocator amplification.

## Verification

- **Fixture:** `(none yet — Phase 3 deliverable)`.
- **Cross-validation oracle:** CUE4Parse[^1] (sole oracle —
  `AstroTechies/unrealmodding` doesn't ship mesh exports; verified
  HTTP 404 on `unreal_asset/src/exports/{static_mesh,skeletal_mesh,skeleton,mesh_vertex_buffers}_export.rs`).
- **Known divergences:** none yet.

## Paksmith implementation

**Parser module:** *(not yet implemented — planned under
`crates/paksmith-core/src/asset/exports/mesh/vertex_formats.rs`,
shared by both `static_mesh.rs` and `skeletal_mesh.rs`)*

**Status:** `not impl`.

**Phase plan:** `docs/plans/2026-05-19-ue-format-docs-mesh.md` Phase 3.

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Objects/Meshes/FPositionVertexBuffer.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` (position buffer); `CUE4Parse/UE4/Assets/Exports/StaticMesh/FStaticMeshVertexBuffer.cs` (normal-tangent + UV buffer); `CUE4Parse/UE4/Objects/Meshes/FColorVertexBuffer.cs` (color buffer); `CUE4Parse/UE4/Assets/Exports/StaticMesh/FRawStaticIndexBuffer.cs` (index buffer); `CUE4Parse/UE4/Objects/RenderCore/FPackedNormal.cs` (bit-packing). Note: `FPositionVertexBuffer` and `FColorVertexBuffer` live under `UE4/Objects/Meshes/`, not `StaticMesh/` as the plan originally stated; `FPackedNormal` lives under `UE4/Objects/RenderCore/`, not `Core/Math/`.
