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
  4 × 16-bit per component), with a "high precision" override.
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
| UE 4.19+ | `FStaticMeshVertexBuffer` `Strides` field dropped from the wire; tangents and UV coords serialized as separate bulk arrays. | Same[^1] |
| UE 4.20+ | `FPackedNormal` raw `u32` XORed with `0x80808080` before component extraction (`FRenderingObjectVersion.IncreaseNormalPrecision` gate). `FPackedRGBA16N` each `u16` XORed with `0x8000`. High-precision-UV opt-in (`bUseFullPrecisionUVs`). | Same[^1] |
| UE 5.0+ | LWC widens `FPositionVertexBuffer` vertex positions from f32 to f64. | Same[^1] |

## Wire layout

### `FPositionVertexBuffer`

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `Stride` | 4 | LE | `i32` | Bytes per vertex; typically `12` (UE4 f32 vector) or `24` (UE5 LWC f64 vector). |
| `NumVertices` | 4 | LE | `i32` | Vertex count. Signed; implementations must verify `≥ 0` before using in allocation math. |
| `Vertices` | `Stride × NumVertices` | LE | f32 or f64 vec3 | Per-vertex positions (bulk array). |

UE5 LWC content carries f64 positions; the `Stride` field
disambiguates without paksmith having to read the parent asset's
version explicitly.

### `FStaticMeshVertexBuffer` — normal-tangent + UV layout

The most-complex vertex buffer. Encodes per-vertex normal + tangent
(2 wire reads; bitangent synthesized by GPU) and 1–4 UV channels.[^1]

The field named `Strides` (plural) in CUE4Parse reflects the oracle
class member name; the semantics are "bytes per vertex in the legacy
combined layout."

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `stripDataFlags` | variable | — | `FStripDataFlags` | Editor/audio-visual strip flags. Gates AV-data presence (UV array) downstream. |
| `NumTexCoords` | 4 | LE | `i32` | UV channel count (1–4). |
| `Strides` (pre-UE4.19 only) | 4 | LE | `i32` | Bytes per vertex in the legacy combined layout. Not present in the wire stream for UE4.19+; CUE4Parse synthesizes `-1` in-memory but no bytes are consumed. |
| `NumVertices` | 4 | LE | `i32` | Vertex count. Signed; implementations must verify `≥ 0` before any allocation multiplication (`Strides × NumVertices` overflows if `NumVertices` is negative). |
| `bUseFullPrecisionUVs` | 4 | LE | `u32` (bool) | If `1`, UVs are `f32`; otherwise `f16` halves. |
| `bUseHighPrecisionTangentBasis` (UE4.12+) | 4 | LE | `u32` (bool) | If `1`, normal+tangent are `FPackedRGBA16N` (4 × u16); otherwise `FPackedNormal` (4 × u8). |
| `TangentsData` | variable | — | per-vertex packed normal+tangent bulk array | See packing dispatch below. |
| `TexCoordData` | variable | — | per-vertex UV × NumTexCoords bulk array | f16 or f32 per UV component. |

Per-vertex tangent-basis packing dispatch:

| `bUseHighPrecisionTangentBasis` | Encoding per wire read | Wire reads per vertex | Bytes per vertex |
|----------------------------------|------------------------|-----------------------|-----------------|
| `false` | `FPackedNormal` (4 × u8 = 4 bytes) | 2 (TangentX + TangentZ) | 8 |
| `true` | `FPackedRGBA16N` (4 × u16 = 8 bytes) | 2 (TangentX + TangentZ) | 16 |

`SerializeTangents` returns a 3-element array `[TangentX, TangentY, TangentZ]`,
but for all UE4+ content the middle element (`TangentY`) is `FPackedNormal(0)` —
no bytes are read from the wire. TangentY is the bitangent, which the GPU
reconstructs via `cross(TangentZ, TangentX)`. The `Ar.Ver < AddedRemovedNormal`
gate that would read TangentY from wire is a UE3-era path (`AddedRemovedNormal = 477` in UE3 versioning); all UE4+ assets bypass it.[^1]

### `FPackedNormal` (4 × u8 normal-tangent component)

4 bytes total. One `u32` is read; for UE 4.20+ the raw `u32` is XORed with
`0x80808080` before component extraction (`FRenderingObjectVersion.IncreaseNormalPrecision`
gate).[^1]

| offset | size | name | semantics |
|--------|------|------|-----------|
| 0 | 1 | `X` | X component: `(byte & 0xFF) / 127.5 - 1` → `[-1, 1]`. |
| 1 | 1 | `Y` | Y component. |
| 2 | 1 | `Z` | Z component. |
| 3 | 1 | `W` | W component (sign bit for tangent handedness). |

Two `FPackedNormal` values (TangentX + TangentZ) = 8 bytes per vertex in the
low-precision path.

### `FPackedRGBA16N` (4 × u16 normal-tangent component)

8 bytes total. Four `ushort` reads (X, Y, Z, W). For UE 4.20+, each
raw ushort is XORed with `0x8000` after reading.[^1]

| field | size | name | semantics |
|-------|------|------|-----------|
| read 1 | 2 | `X` | Raw u16; XOR `0x8000` (UE4.20+). Decode: `(value - 32767.5) / 32767.5` → `[-1, 1]`. |
| read 2 | 2 | `Y` | Same decode. |
| read 3 | 2 | `Z` | Same decode. |
| read 4 | 2 | `W` | Same decode (tangent handedness). |

Two `FPackedRGBA16N` values (TangentX + TangentZ) = 16 bytes per vertex in
the high-precision path.

### `FColorVertexBuffer`

Prefixed by `FStripDataFlags` (controls whether visual data is
present), then:[^1]

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `Stride` | 4 | LE | `i32` | Typically `4` (FColor = 4 × u8). |
| `NumVertices` | 4 | LE | `i32` | Signed; implementations must verify `≥ 0`. |
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
| `elementSize` | 4 | LE | `i32` | Always `1` (byte-sized element). Emitted by `ReadBulkArray<byte>`. |
| `byteCount` | 4 | LE | `i32` | Total payload bytes (NOT index count). Index count is derived: `byteCount / 4` if `is32bit`, else `byteCount / 2`. Sign-extension guard required (see Caps). Implementations must validate `byteCount % indexSize == 0` before division. |
| `Data` | `byteCount` | — | bulk `u8[]` | Raw index bytes; parsed as `u16[]` or `u32[]` per `is32bit`. |
| `bShouldExpandTo32Bit` (UE 4.25+) | 4 | LE | `u32` (bool) | Whether the buffer should be expanded to 32-bit at load. Present when `RawIndexBuffer.HasShouldExpandTo32Bit` (UE 4.25+; absent in Delta Force). Reads from the main archive AFTER the `Data` bulk payload, not from within it. |

Note: the index count is **derived**, not stored on the wire. For older
content (pre-`SUPPORT_32BIT_STATIC_MESH_INDICES`), the buffer is a
plain bulk `u16[]` with no `is32bit` prefix. The `bShouldExpandTo32Bit`
field is appended after the bulk `Data` payload in the main archive
stream — it is not part of the embedded byte archive used to parse
`Data`.

**`FMultisizeIndexContainer` (skeletal mesh):**

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `ElementSize` | 1 | — | `u8` | `2` or `4` (bytes per index). Reader MUST reject any other value: `0` causes division-by-zero on payload-size-to-count derivation; `1`/`3` produce misaligned strides; `255` produces wildly over-sized allocations. |
| `NumIndices` | 4 | LE | `i32` | Counted-prefix for `Indices`. Sign-extension guard required (see Caps). |
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

UVs are 16-bit halves by default; see the `FStaticMeshVertexBuffer` section above.
When `bUseFullPrecisionUVs == 1`, UVs are full `f32`.

### High-precision tangent basis

`bUseHighPrecisionTangentBasis == 0` is the common case;
`== 1` is rare in cooked content. Both paths read exactly 2 tangent
components from wire (TangentX + TangentZ); the bitangent is synthesized
by the GPU.

## Caps & limits

**Phase 3+ deferred work.** Per-buffer:

- `NumVertices` is a signed `i32`. Implementations must verify `NumVertices ≥ 0`
  before any allocation multiplication: `Strides × NumVertices` becomes negative
  (and overflows allocation sizing) if `NumVertices` is `-1`. This is a
  sign-extension attack surface; guard at every read site.
- `Stride × NumVertices` must fit in the parent file's residual
  bytes (caps inherited from `MAX_UNCOMPRESSED_ENTRY_BYTES` /
  `MAX_UEXP_SIZE`).
- A future `MAX_VERTICES_PER_LOD` cap (in addition to the cap above)
  to bound per-LOD allocator amplification.
- `FMultisizeIndexContainer.ElementSize` must be validated against
  `{2, 4}` before use. Any other value indicates corrupt or hostile content.
- `FRawStaticIndexBuffer.byteCount` is a signed `i32` that MUST be verified
  `≥ 0` before use. The derived index count (`byteCount / indexSize`) is not
  stored on wire; implementations must also verify `byteCount % indexSize == 0`
  before the division. Bound `byteCount` against file-residual-byte budgets
  before allocation.
- `FMultisizeIndexContainer` count prefix (`i32`) must be bounded by
  file-residual-byte budgets before allocation.

See `docs/security/allocation-caps.md` for the broader policy.

## Verification

- **Fixture:** `(none yet — Phase 3 deliverable)`.
- **Cross-validation oracle:** CUE4Parse[^1] (sole oracle; see [`static-mesh.md`](static-mesh.md) Verification for details on why no Rust counterpart exists).
- **Known divergences:** none yet.
- **Hex anchor commands:** (none yet — Phase 3 deliverable).

## Paksmith implementation

**Parser module:** *(not yet implemented — planned under
`crates/paksmith-core/src/asset/exports/mesh/vertex_formats.rs`,
shared by both `static_mesh.rs` and `skeletal_mesh.rs`)*

**Status:** `not impl`.

**Phase plan:** `docs/plans/ROADMAP.md` Phase 3.

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Objects/Meshes/FPositionVertexBuffer.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` (position buffer); `CUE4Parse/UE4/Assets/Exports/StaticMesh/FStaticMeshVertexBuffer.cs` and `FStaticMeshUVItem.cs` (normal-tangent + UV buffer); `CUE4Parse/UE4/Objects/Meshes/FColorVertexBuffer.cs` (color buffer); `CUE4Parse/UE4/Assets/Exports/StaticMesh/FRawStaticIndexBuffer.cs` (index buffer); `CUE4Parse/UE4/Objects/RenderCore/FPackedNormal.cs` and `FPackedRGBA16N.cs` (bit-packing). Note: `FPositionVertexBuffer` and `FColorVertexBuffer` live under `UE4/Objects/Meshes/`; `FPackedNormal` and `FPackedRGBA16N` live under `UE4/Objects/RenderCore/`; `FStaticMeshVertexBuffer` and `FStaticMeshUVItem` live under `UE4/Assets/Exports/StaticMesh/`.
