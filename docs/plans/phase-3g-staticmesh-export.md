# Paksmith Phase 3g: StaticMesh → glTF 2.0 export (architecture overview)

> **For agentic workers:** This is an **overview** plan. Crate selection (`gltf` vs `gltf-json`) settles at kickoff. May split into 3g1 (parse) + 3g2 (glTF lower) like Phase 2's 2c → 2g spawn. Once locked, rewritten Phase-2g-style with full TDD steps.

**Goal:** Decode `UStaticMesh` exports into glTF 2.0 files. MVP: single-LOD non-Nanite mesh, classic LOD payload, glTF accessors / bufferViews / scene hierarchy. Nanite (`FNaniteResources`) parsing is in scope as a tracked follow-up.

**Depends on:** 3a (FormatHandler), 3b (FByteBulkData resolver — vertex / index buffers may be uexp-resident OR streaming), 3c (typed engine struct decoders — `FVector` for positions, `FQuat` for bone transforms via shared code paths, `FBox` for bounds).

**Architecture:**

```plaintext
crates/paksmith-core/src/
├── asset/exports/mesh/
│   ├── mod.rs                # static_mesh::read_from dispatcher (3h shares this dir)
│   ├── static_mesh.rs        # UStaticMesh parser
│   ├── render_data.rs        # FStaticMeshRenderData (LOD array + Nanite + distance fields + bounds)
│   ├── lod.rs                # FStaticMeshLODResources (sections + vertex/index buffers)
│   ├── section.rs            # FStaticMeshSection (per-draw-call ranges)
│   ├── vertex_buffers.rs     # FPositionVertexBuffer, FStaticMeshVertexBuffer, FColorVertexBuffer
│   └── index_buffer.rs       # FRawStaticIndexBuffer
└── export/
    └── static_mesh.rs        # GltfStaticMeshHandler impl
```

`Asset::StaticMesh { lods: Vec<StaticMeshLod>, bounds: FBoxSphereBounds, materials: Vec<MaterialSlotRef>, nanite: Option<NaniteResources> }`. `bounds` uses 3c's `FBoxSphereBounds` typed decoder (in-scope after 3c's 11th-decoder promotion).

**Per-LOD vertex data is STRUCTURE-OF-ARRAYS, not array-of-structs** — for a million-vertex mesh, the AoS layout would mean 1M tiny `Vec<FVector2D>` allocations for the per-vertex `uvs` field. SoA also matches glTF's stride-based accessor layout, so glTF lowering becomes a straight memcpy per attribute rather than a per-vertex scatter pass.

```rust
pub struct StaticMeshLod {
    pub sections: Vec<MeshSection>,
    /// Per-vertex positions. f64 carries UE5 LWC values without
    /// loss; UE4 f32 sources widen via 3c's FVector decoder.
    pub positions: Vec<FVector>,
    /// Per-vertex normal (decoded from FPackedNormal or
    /// FPackedRGBA16N depending on bUseHighPrecisionTangentBasis).
    pub normals: Vec<FVector>,
    /// Per-vertex tangent: **4-component** (FVector4 with W as the
    /// tangent handedness sign, +1.0 or -1.0). glTF expects VEC4
    /// tangent accessors. Dropping the W component (as a 3-float
    /// FVector) would lose the handedness bit needed for correct
    /// normal-mapping shader evaluation.
    pub tangents: Vec<FVector4>,
    /// Per-texcoord-channel UVs. Maximum 4 channels per UE
    /// convention (NumTexCoords validated 1..=4 at parse time per
    /// vertex-formats.md:205). `None` slots = channel not present.
    pub uvs: [Option<Vec<FVector2D>>; 4],
    /// Optional per-vertex color (FColorVertexBuffer); `None` when
    /// stripped or NumVertices == 0.
    pub colors: Option<Vec<FColor>>,
    /// Per-triangle vertex indices (16-bit or 32-bit on-wire,
    /// always materialized as u32 for glTF compatibility).
    pub indices: Vec<u32>,
}
```

---

## Scope (3g proper):

- **Parser:** UStaticMesh's two-segment body: tagged-property segment (StaticMaterials array, BodySetup, LightMap settings, NaniteSettings, etc.) + cooked render-data segment (`FStripDataFlags` + `bCooked` flag + `BodySetup` ref + `FStaticMeshRenderData`).
- **`FStaticMeshRenderData`**: per-LOD `FStaticMeshLODResources[]`, UE 4.23+ `numInlinedLODs: u8`, UE 5.0+ `FNaniteResources` blob (parsed-and-carried; export deferred), distance-field block (gated on strip flags), Bounds (FBoxSphereBounds — uses 3c's FVector + FSphere or fallback), `bLODsShareStaticLighting`, ScreenSize[].
- **`FStaticMeshLODResources`**: sections array, MaxDeviation, vertex buffers, index buffer, adjacency/wireframe buffers (skipped if absent in cooked).
- **Vertex buffer family**:
  - `FPositionVertexBuffer`: `Stride` (12 for UE4 f32, 24 for UE5 LWC f64) + `NumVertices` + `Vertices[]`. Stride-based dispatch (NOT version-based — the stride field disambiguates without reading the asset's version).
  - `FStaticMeshVertexBuffer`: `stripDataFlags`, `NumTexCoords` (validated 1..=4 per `vertex-formats.md:205`), **pre-UE-4.19 only: `Strides: i32`** (legacy combined-layout bytes-per-vertex; paksmith's UE 4.4+ floor → this branch IS reachable; CUE4Parse synthesizes `-1` in-memory but the wire bytes ARE present and MUST be consumed per `vertex-formats.md:64-67`), `NumVertices`, `bUseFullPrecisionUVs`, `bUseHighPrecisionTangentBasis`, then `TangentsData` (per-vertex 8 bytes if low-precision, 16 bytes if high-precision — `FPackedNormal` × 2 or `FPackedRGBA16N` × 2) + `TexCoordData` (per-vertex `NumTexCoords × bytesPerUV`).
    - **Version-dispatch:** the legacy `Strides` field is gated on `Ar.Ver < VER_UE4_19_STATIC_MESH_VERTEX_BUFFER_STRIDES_REMOVED` (or the equivalent CUE4Parse version constant). Paksmith MUST consume the 4 bytes on the pre-4.19 branch and skip cleanly on 4.19+.
  - `FColorVertexBuffer`: optional `FColor` per vertex; omitted via stripDataFlags or `NumVertices == 0`.
- **`FPackedNormal` decoder**: 4 × u8, XOR 0x80808080 for UE 4.20+ (`IncreaseNormalPrecision` gate), decode per byte to `[-1, 1]`.
- **`FPackedRGBA16N` decoder**: 4 × u16, XOR 0x8000 for UE 4.20+, decode per ushort.
- **`FRawStaticIndexBuffer` reader**: `is32bit: u32` flag + `elementSize: i32` (=1) + `byteCount: i32` + bulk `u8[]` + UE 4.25+ `bShouldExpandTo32Bit` flag. Indices materialize as `u32[]` regardless of on-wire width.
- **Per-section ranges**: `FStaticMeshSection` carries `MaterialIndex`, `FirstIndex`, `NumTriangles`, `MinVertexIndex`, `MaxVertexIndex`, bool flags.
- **`GltfStaticMeshHandler`** (`FormatHandler` impl): output extension `"gltf"` (.gltf + .bin) or `"glb"` (binary self-contained). Recommended: GLB for self-containment.
- **glTF lower-path**: per-LOD glTF mesh with one primitive per section. Position / normal / tangent / texcoord_0..N accessors. Index accessor (16-bit vs 32-bit per source). Materials reference UE materials by slot (resolution TBD — likely placeholder materials in 3g; full PBR material binding is a 3g follow-up).
- **Caps**: `MAX_LODS_PER_MESH = 8`, `MAX_SECTIONS_PER_LOD = 64`, `MAX_VERTICES_PER_LOD = 4_194_304` (4M; conservative), `MAX_INDICES_PER_LOD = MAX_VERTICES_PER_LOD * 6` (matches max-triangle-count from worst-case vertex sharing).
- **Error variants**: `MeshLodCountExceeded`, `MeshSectionCountExceeded`, `MeshVertexCountExceeded`, `MeshNumTexCoordsOob` (per format doc — MUST be 1..=4), `IndexBufferElementSizeInvalid` (must be 2 or 4), `IndexBufferByteCountMismatch` (byteCount % indexSize != 0), `VertexBufferStrideInvalid`, `NaniteEnabledExportNotSupported` (3g MVP emits classic LOD; this fires only if classic LOD is also stripped, which is rare).

## Out of scope (named target phases / follow-ups):

- **`USkeletalMesh` export** → **Phase 3h** (separate sub-phase per master index). Shares the vertex-buffer + index-buffer readers from 3g; adds skin weights + bone hierarchy + bind pose.
- **Nanite full export** (`FNaniteResources` page-table → flattened mesh) — parsed by 3g, export is a 3g follow-up (the classic LOD payload is always present per the format doc; MVP exports that).
- **Vertex / index buffer compression** (`bCompressBuffers` cooker option) — rare in cooked PC content; → **Phase 3 follow-up** when a real-world fixture surfaces.
- **`FBoxSphereBounds`** with proper `SphereRadius` extraction → folded into Phase 3c follow-up (add `FBoxSphereBounds` as the 11th typed struct).
- **PBR material binding** (resolving `UMaterialInterface` slots to actual textures + shading model) — UE materials don't translate cleanly to glTF's metallic-roughness model; the conversion needs research. → **3g follow-up or Phase 3+ "material baking" sub-phase.** 3g MVP emits glTF with placeholder materials referenced by slot index; the user binds textures manually in Blender/etc.
- **Distance fields and AdjacencyIndexBuffer / WireframeIndexBuffer** — editor-only data; typically stripped from cooked. → no-op in cooked path; if encountered, gate-skip per stripDataFlags.

---

## Crate-selection candidates (decide at kickoff)

| Component | Candidate | Notes |
|-----------|-----------|-------|
| glTF write | `gltf` (~v1.x) | Full reader+writer; ~25 transitive deps. Heavy but handles GLB containerization. |
| glTF write alt. | `gltf-json` only | Just the JSON layer; we write the binary buffer manually. Slimmer but more code. Recommended if the `gltf` crate's dep footprint is unwelcome. |
| glTF write alt. (most-minimal) | Hand-rolled GLB writer (~300 lines) | Avoids ALL glTF crate deps; chunked GLB output. Recommended only if dep audit blocks both above. |
| glTF validator (test-only) | shell out to `gltf-validator` binary | Official Khronos validator. Used in 3g-N integration tests for correctness gate. |

---

## Milestone breakdown (proposed; may split into 3g1+3g2)

**3g1 — Parser (no glTF):**

1. **3g1-1: Variant + tagged-property segment + dispatch wiring.** UStaticMesh class name routes.
2. **3g1-2: UStaticMesh::Deserialize level — strip flags + bCooked + BodySetup ref.**
3. **3g1-3: FStaticMeshRenderData skeleton — LOD array prefix + numInlinedLODs + bounds + ScreenSize[].** Distance-field + inlineDataRepresentations stubbed (gate-skip + log warn).
4. **3g1-4: FStaticMeshLODResources — sections + vertex buffers + index buffer.**
5. **3g1-5: FPositionVertexBuffer + FStaticMeshVertexBuffer + FColorVertexBuffer readers.** Plus FPackedNormal / FPackedRGBA16N tangent-basis decoders.
6. **3g1-6: FRawStaticIndexBuffer reader.** is32bit dispatch, byteCount validation, UE 4.25+ bShouldExpandTo32Bit.
7. **3g1-7: FStaticMeshSection per-section ranges.**

**3g2 — glTF lower + handler + integration:**

8. **3g2-1: `GltfStaticMeshHandler` skeleton.** Emits a minimum glTF 2.0 envelope (asset version, scene 0 → node 0 → mesh 0 → empty primitive). Validates against gltf-validator.
9. **3g2-2: Position accessor.** Per-LOD vertex positions → glTF FLOAT VEC3 accessor; bufferView pointing into the binary GLB chunk.
10. **3g2-3: Normal + tangent accessors.** Decoded `FPackedNormal` / `FPackedRGBA16N` into FLOAT VEC3 (normal) + FLOAT VEC4 (tangent + handedness W).
11. **3g2-4: UV accessors.** Per-texcoord-channel FLOAT VEC2 accessor (or f16 if `bUseFullPrecisionUVs == false`).
12. **3g2-5: Color accessor (optional).** When `FColorVertexBuffer` present; UNSIGNED_BYTE VEC4 normalized.
13. **3g2-6: Index accessor.** UNSIGNED_SHORT or UNSIGNED_INT per source format. One primitive per `FStaticMeshSection`.
14. **3g2-7: Material slot binding** (placeholder). One glTF material per StaticMaterials slot; just a named placeholder.
15. **3g2-8: Integration tests + cube fixture.** Single-LOD 8-vertex cube → glTF → gltf-validator passes → Blender opens.

If 3g lands as a unified plan: total 15 tasks. The split decision happens at kickoff based on plan-doc length (estimated > 2000 lines for unified; 2 × ~1000 lines if split).

---

## Fixture-count gate

3g's TDD conversion adds ~4-6 fixtures (minimal cube, single-LOD multi-section, multi-LOD, UE4 f32 + UE5 LWC f64 positions, pre-4.19 `Strides`-bearing buffer, optional UE 4.25+ `bShouldExpandTo32Bit`). Bump `.github/workflows/ci.yml`'s fixture-count constant per `feedback_fixture_count_gate.md`.

## Contract callouts for TDD conversion

- **`TypedReaderFn` returns `Result<(Asset, Vec<FByteBulkData>)>`** (per 3a R3 fix). The static-mesh reader collects per-LOD vertex / index buffer `FByteBulkData` records and returns them in the second tuple element; the dispatch caller drives `insert_bulk_records`. Typed reader signature: `pub(crate) fn read_typed(payload: &[u8], ctx: &AssetContext, asset_path: &str) -> crate::Result<(Asset, Vec<FByteBulkData>)>`.

## Open questions for kickoff

1. **glTF crate finalist.** `gltf` (heavy) vs `gltf-json` (slim + hand-rolled binary) vs hand-rolled GLB.
2. **3g1 + 3g2 split decision.** Lock at kickoff based on first-draft plan-doc word count.
3. **Material slot strategy.** Placeholder name-only material vs attempt-at-PBR-baking (HARD; defer).
4. **Nanite-only assets** (where classic LOD is stripped). Format doc says classic LOD is always present in cooked; verify with a real Lyra-pre-cooked asset before deciding.
5. **LWC stride dispatch.** Position buffer stride disambiguates f32 (UE4) vs f64 (UE5 LWC) WITHOUT consulting the version table. But what if a corrupt asset declares stride = 16? Need explicit allow-list (`stride ∈ {12, 24}` for position; anything else → typed error).
6. **Per-section vertex range validation.** Sections carry `MinVertexIndex` / `MaxVertexIndex`; verify these against `vertices.len()` to catch corrupt cooks before glTF lowering.

---

## Review panel (when 3g enters TDD)

- Wire-format pass — MANDATORY (large surface; per-vertex / per-index / per-section).
- Security pass — MANDATORY (`NumVertices`, `Strides`, `byteCount`, `NumTexCoords`, `is32bit` all sign-extension hazards per format doc §Caps).
- Performance — RECOMMENDED (large meshes; vertex buffer reads are hot).
- Deep-impact tracer — MANDATORY (adds `Asset::StaticMesh` variant + shared vertex-buffer module that 3h will reuse).

5-6 reviewers per task PR.

---

## References

- Wire-format references:
  - [`../formats/mesh/static-mesh.md`](../formats/mesh/static-mesh.md) — UStaticMesh / FStaticMeshRenderData / FStaticMeshLODResources / FStaticMeshSection.
  - [`../formats/mesh/vertex-formats.md`](../formats/mesh/vertex-formats.md) — vertex buffer family + tangent packing + index buffer.
- Master index: [`phase-3-export-pipeline.md`](phase-3-export-pipeline.md).
- Phase 3c (typed structs): [`phase-3c-typed-binary-structs.md`](phase-3c-typed-binary-structs.md) — supplies FVector for positions, FBox for bounds.
- glTF 2.0 spec: <https://registry.khronos.org/glTF/specs/2.0/glTF-2.0.html>.
