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
  for `f32`. 1–4 UV channels per vertex.
- **Color buffer** — `FColor` (4 × `u8`) when present; entire buffer
  omitted otherwise.

**Document status: complete.** Wire format documented in full for
the buffer-level shapes (`FPositionVertexBuffer`,
`FStaticMeshVertexBuffer`, `FColorVertexBuffer`,
`FSkeletalMeshVertexBuffer`, `FRawStaticIndexBuffer`,
`FMultisizeIndexContainer`) and the component-level packed
encodings (`FPackedNormal` with the UE 4.20+ `0x80808080` XOR;
`FPackedRGBA16N` with the UE 4.20+ per-component `0x8000` XOR).
The per-vertex `FGPUVertHalf` / `FGPUVertFloat` record structure
(the contents of `FSkeletalMeshVertexBuffer`'s bulk vertex array)
is identified by name and deferred to Phase 3 implementation work
alongside the modern separate-buffer path.

**Paksmith parser status: `not impl`.** Phase 3+ deliverable.

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

TangentY (bitangent) is reconstructed from the cross-product on the GPU, not read from wire.

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

### `FSkeletalMeshVertexBuffer` — pre-`SplitModelAndRenderData` merged buffer

Skeletal-merged buffer containing per-vertex positions + tangent
basis + UVs in a single bulk array. Used by skeletal-mesh LODs
serialized BEFORE `FSkeletalMeshCustomVersion::SplitModelAndRenderData`
(see [`skeletal-mesh.md`](skeletal-mesh.md) §*FStaticLODModel*);
modern cooked content uses the separate `FPositionVertexBuffer` +
`FStaticMeshVertexBuffer` + `FSkinWeightVertexBuffer` triple
documented above + in `skeletal-mesh.md`. This buffer carries
quantization parameters (`MeshExtension` / `MeshOrigin`) that the
modern separate-buffer path doesn't need — the legacy GPU-skin
pipeline reconstructed vertex positions via
`pos = compressed_pos × MeshExtension + MeshOrigin`.[^1]

| order | field | size | endian | type | semantics |
|-------|-------|------|--------|------|-----------|
| 1 | `stripDataFlags` | 2 | LE | `FStripDataFlags` | Strip-flags marker; the `STATIC_SKELETAL_MESH_SERIALIZATION_FIX` UE4 object version is passed to the constructor. |
| 2 | `NumTexCoords` | 4 | LE | `i32` | UV channel count (typically 1-4). |
| 3 | `bUseFullPrecisionUVs` | 4 | LE | `u32` (bool) | If `1`, UVs are `f32` (`FMeshUVFloat`); otherwise `f16` halves (`FMeshUVHalf`). Present when `Ar.Ver >= EUnrealEngineObjectUE3Version.AddedFullPrecisionUV` (always true in UE4-cooked content). |
| 4 | `bExtraBoneInfluences` | 4 | LE | `u32` (bool) | If `1`, vertices carry 8 bone influences; otherwise 4. **Conditional:** present when `Ar.Ver >= SUPPORT_GPUSKINNING_8_BONE_INFLUENCES` AND `FSkeletalMeshCustomVersion < UseSeparateSkinWeightBuffer` (the latter gate excludes modern cooked content where skin weights moved to a separate buffer). |
| 5 | `MeshExtension` | 12 (UE4) / 24 (UE5 LWC) | LE | `FVector` (3 × f32 / 3 × f64) | Bounding-box extension for quantized vertex decompression. |
| 6 | `MeshOrigin` | 12 (UE4) / 24 (UE5 LWC) | LE | `FVector` (3 × f32 / 3 × f64) | Bounding-box origin for quantized vertex decompression. |
| 7 | `VertsHalf` or `VertsFloat` | variable | LE | `FGPUVertHalf[]` or `FGPUVertFloat[]` (bulk array) | Per-vertex records dispatched on `bUseFullPrecisionUVs`. Each entry is `FSkelMeshVertexBase` (position + packed tangent basis + skin weights) + UV array of size `NumTexCoords`. |

Fixed-position header total (UE 4.x, all bools present, both
gates fire): 2 + 4 + 4 + 4 + 12 + 12 = **38 bytes** before the
bulk vertex array. Under UE5 LWC the `MeshExtension` + `MeshOrigin`
widen to 24 bytes each, giving 2 + 4 + 4 + 4 + 24 + 24 =
**62 bytes**.

The per-vertex `FGPUVertHalf` / `FGPUVertFloat` records — the
contents of the bulk array — are a deferred sub-format; the modern
separate-buffer path (Position + StaticMesh + SkinWeight) has been
documented in this doc and `skeletal-mesh.md`, and Phase 3
implementation work will catalog the per-vertex legacy record
shape when the pre-`SplitModelAndRenderData` reader lands.

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

**`FMultisizeIndexContainer` (skeletal mesh):**

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `ElementSize` | 1 | — | `u8` | `2` or `4` (bytes per index). Reader MUST reject any other value: `0` causes division-by-zero on payload-size-to-count derivation; `1`/`3` produce misaligned strides; `255` produces wildly over-sized allocations. |
| `NumIndices` | 4 | LE | `i32` | Counted-prefix for `Indices`. Sign-extension guard required (see Caps). |
| `Indices` | variable | — | bulk `u16[]` or `u32[]` | Per-triangle vertex indices, 3 per triangle. |

UE picks 16-bit when the LOD's `MaxVertexIndex < 65,535` (most
production assets); 32-bit only when the LOD exceeds the cap.

### Worked example — `FPackedNormal` Z-up normal (4 bytes, UE 4.20+)

A surface normal pointing along the +Z axis (`X=0, Y=0, Z=1, W=0`)
encoded as `FPackedNormal` at UE 4.20+ (which applies the
`0x80808080` XOR after reading). For the post-XOR decoded
byte values to be `(128, 128, 255, 128)` (giving `(0, 0, 1, 0)`
under the `byte/127.5 - 1` decode formula), the pre-XOR (on-wire)
bytes must be `(128, 128, 255, 128) ^ 0x80 = (0, 0, 127, 0)`:

```
Offset (within record)  Bytes (LE)        Field
----------------------  ---------------   --------------------
+0                      00 00 7F 00       Raw u32 LE = 0x007F0000 (pre-XOR; X=0 Y=0 Z=0x7F W=0 byte-positions)
+4                                          (end of FPackedNormal record)
```

Reader logic:
1. Read u32 LE: `Data = 0x00 | (0x00 << 8) | (0x7F << 16) | (0x00 << 24) = 0x007F0000`.
2. UE 4.20+ XOR: `Data ^= 0x80808080` → `Data = 0x80FF8080` (per-byte: `0x00^0x80=0x80`, `0x00^0x80=0x80`, `0x7F^0x80=0xFF`, `0x00^0x80=0x80`).
3. Extract bytes from `Data = 0x80FF8080`: `X = Data & 0xFF = 0x80 (128)`; `Y = (Data >> 8) & 0xFF = 0x80`; `Z = (Data >> 16) & 0xFF = 0xFF (255)`; `W = (Data >> 24) & 0xFF = 0x80`.
4. Decode: `X = 128/127.5 − 1 ≈ 0`; `Y ≈ 0`; `Z = 255/127.5 − 1 = 1.0`; `W ≈ 0`.

For pre-UE-4.20 content (no XOR), the same `(0, 0, 1, 0)` decoded normal requires wire bytes `80 80 FF 80` (already in post-XOR byte positions).

### Worked example — `FPositionVertexBuffer` with 3 vertices (44 bytes)

A position buffer carrying 3 vertices at the origin, (1, 0, 0), and (0, 1, 0) under UE4 single-precision:

```
Offset (within buffer)  Bytes (LE)                                       Field
----------------------  -----------------------------------------------  --------------------
+0                      0C 00 00 00                                      Stride = 12 (i32; f32 vec3 = 12 bytes per vertex)
+4                      03 00 00 00                                      NumVertices = 3 (i32)
+8                      00 00 00 00 00 00 00 00 00 00 00 00              Vertex[0] = (0, 0, 0) (3 × f32 LE)
+20                     00 00 80 3F 00 00 00 00 00 00 00 00              Vertex[1] = (1, 0, 0) (0x3F800000 = 1.0)
+32                     00 00 00 00 00 00 80 3F 00 00 00 00              Vertex[2] = (0, 1, 0)
+44                                                                       (end of buffer)
```

Under UE5 LWC (`Stride = 24`), the same 3-vertex buffer would be
`4 + 4 + 3 × 24 = 80 bytes` with f64 components — a parser dispatches
on the `Stride` field rather than hard-coding `f32`.

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

### Format-defined limits (wire-imposed)

- **`FPositionVertexBuffer.Stride`**: `i32`; typically `12` (UE4 f32 vec3) or `24` (UE5 LWC f64 vec3).
- **`FPositionVertexBuffer.NumVertices`**: `i32`.
- **`FStaticMeshVertexBuffer.NumTexCoords`**: `i32`; UE engines cook 1-4 UV channels per vertex.
- **`FStaticMeshVertexBuffer.Strides`** (pre-UE 4.19 only): `i32`.
- **`FStaticMeshVertexBuffer.bUseFullPrecisionUVs` / `bUseHighPrecisionTangentBasis`**: `u32` (bool).
- **`FColorVertexBuffer.Stride`**: `i32`; typically `4` (`FColor` = 4 × `u8`).
- **`FPackedNormal`**: fixed 4 bytes (u32); decoded via `byte / 127.5 − 1`. UE 4.20+ applies `0x80808080` XOR after wire read.
- **`FPackedRGBA16N`**: fixed 8 bytes (4 × `u16`); decoded via `(value − 32767.5) / 32767.5`. UE 4.20+ applies per-component `0x8000` XOR.
- **`FRawStaticIndexBuffer.is32bit`**: `u32` (bool) — `1` = 32-bit indices, `0` = 16-bit.
- **`FRawStaticIndexBuffer.elementSize`**: `i32`; always `1` (emitted by `ReadBulkArray<byte>`).
- **`FRawStaticIndexBuffer.byteCount`**: `i32`; total payload bytes (index count derived).
- **`FMultisizeIndexContainer.ElementSize`**: `u8`; only `2` or `4` are semantically valid.

### Implementation hardening (recommended for any parser)

A vertex-format reader (paksmith does not yet have one) MUST:

- **Verify all `i32` count prefixes are non-negative** before any allocation arithmetic. `NumVertices`, `byteCount`, and count prefixes are all signed `i32` on wire; sign-extension attacks via negative values would either underflow allocation sizing or produce `usize::MAX`-adjacent capacities on cast.
- **Validate `FPositionVertexBuffer.Stride`, `FColorVertexBuffer.Stride`, and `FStaticMeshVertexBuffer.Strides`** (pre-UE 4.19, when present) as `> 0` before any allocation multiplication. The LWC-detection dispatch on `Stride` values (`12`/`24`) does NOT protect against attacker-supplied negative values, which would fall through to an undefined branch.
- **Cap `FStaticMeshVertexBuffer.NumTexCoords`** at `1 ≤ NumTexCoords ≤ 4`. The `TexCoordData` payload is sized `NumVertices × NumTexCoords × bytesPerUV`; values outside the documented range either produce overflow or unbounded allocation.
- **Cap `Stride × NumVertices`** against the parent file's residual bytes (inherit from `MAX_UNCOMPRESSED_ENTRY_BYTES` / `MAX_UEXP_SIZE`). Use `checked_mul` to defeat overflow at the multiplication step.
- **Apply a `MAX_VERTICES_PER_LOD` cap** (in addition to the byte-residual cap) to bound per-LOD allocator amplification.
- **Validate `FMultisizeIndexContainer.ElementSize`** against `{2, 4}` before use. Any other value indicates corrupt or hostile content — `0` causes divide-by-zero on payload-size-to-count derivation, `1` / `3` produce misaligned strides, `255` produces wildly over-sized allocations.
- **Validate `FRawStaticIndexBuffer.byteCount % indexSize == 0`** before deriving index count via division. The remainder check rejects truncated payloads that would otherwise produce a partial trailing index.
- **Bound `byteCount`** against file-residual-byte budgets before allocation.
- **Coerce `u32` booleans as `!= 0` → true** for `is32bit` / `bUseFullPrecisionUVs` / `bUseHighPrecisionTangentBasis`. Per UE archive convention, only `0` is false; any non-zero value is true. UE writers always emit `0` or `1`, but a parser that *rejects* values outside `{0, 1}` would fail on edge-case toolchain output that's otherwise valid. The format is forgiving on this point.

See `docs/security/allocation-caps.md` for the broader policy.

## Verification

- **Fixture:** The 4-byte `FPackedNormal` and 44-byte `FPositionVertexBuffer` Worked examples above are byte-exact and self-contained. Full mesh fixtures exercising the cooked LOD payload (per `static-mesh.md` and `skeletal-mesh.md`) are Phase 3 deliverables.
- **Hex anchor commands:**
  ```
  # Synthesize the 4-byte FPackedNormal (+Z normal, UE 4.20+ XOR'd):
  printf '\x00\x00\x7F\x00' | xxd
  # Synthesize the 44-byte FPositionVertexBuffer (3 vertices at origin, +X, +Y):
  printf '\x0C\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x3F\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x3F\x00\x00\x00\x00' | xxd
  ```
  A conformant vertex-format parser fed these bytes MUST decode them as the values shown in the Worked examples — a +Z surface normal and a 3-vertex position buffer respectively.
- **Cross-validation oracle:** CUE4Parse[^1] (sole oracle; see [`static-mesh.md`](static-mesh.md) Verification for details on why no Rust counterpart exists).
- **Known divergences:** none — no paksmith implementation to diverge.

## Paksmith implementation

**Parser module:** *(not yet implemented — planned under
`crates/paksmith-core/src/asset/exports/mesh/vertex_formats.rs`,
shared by both `static_mesh.rs` and `skeletal_mesh.rs`)*

**Status:** `not impl`.

**Phase plan:** `docs/plans/ROADMAP.md` Phase 3.

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Objects/Meshes/FPositionVertexBuffer.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` (position buffer); `CUE4Parse/UE4/Assets/Exports/StaticMesh/FStaticMeshVertexBuffer.cs` and `FStaticMeshUVItem.cs` (normal-tangent + UV buffer); `CUE4Parse/UE4/Objects/Meshes/FColorVertexBuffer.cs` (color buffer); `CUE4Parse/UE4/Assets/Exports/StaticMesh/FRawStaticIndexBuffer.cs` (index buffer); `CUE4Parse/UE4/Objects/RenderCore/FPackedNormal.cs` and `FPackedRGBA16N.cs` (bit-packing). Note: `FPositionVertexBuffer` and `FColorVertexBuffer` live under `UE4/Objects/Meshes/`; `FPackedNormal` and `FPackedRGBA16N` live under `UE4/Objects/RenderCore/`; `FStaticMeshVertexBuffer` and `FStaticMeshUVItem` live under `UE4/Assets/Exports/StaticMesh/`.
