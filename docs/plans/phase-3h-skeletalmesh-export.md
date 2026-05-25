# Paksmith Phase 3h: SkeletalMesh → glTF 2.0 export (architecture overview)

> **For agentic workers:** This is an **overview** plan. Animation-track scope (anim sequences, blend shapes) settles at kickoff. Once locked, rewritten Phase-2g-style with full TDD steps.

**Goal:** Decode `USkeletalMesh` exports into glTF 2.0 files with bone hierarchy + skin matrices + bind pose. MVP: single-LOD skeletal mesh with one section, 4-influence skin weights, bind-pose rendering only. Animation track playback (`UAnimSequence`) is **out of scope for 3h**.

**Depends on:** 3a (FormatHandler), 3b (FByteBulkData resolver), 3c (typed engine structs — `FTransform` is load-bearing for bone bind poses + `FVector`/`FQuat` for positions/rotations), **3g** (vertex / index buffer family is shared via `asset/exports/mesh/vertex_buffers.rs` + `index_buffer.rs`).

**Architecture:**

```plaintext
crates/paksmith-core/src/
├── asset/exports/mesh/
│   ├── mod.rs                 # (3g)
│   ├── static_mesh.rs         # (3g)
│   ├── skeletal_mesh.rs       # 3h: USkeletalMesh parser
│   ├── skeleton.rs            # 3h: FReferenceSkeleton + bone hierarchy
│   ├── skin_weights.rs        # 3h: FSkinWeightVertexBuffer + per-vertex influences
│   ├── render_data.rs         # (3g; possibly shared)
│   ├── lod.rs                 # (3g; possibly extended)
│   ├── section.rs             # (3g; FSkelMeshSection differs from FStaticMeshSection)
│   ├── vertex_buffers.rs      # (3g; shared)
│   └── index_buffer.rs        # (3g; shared — handles both static + skeletal)
└── export/
    └── skeletal_mesh.rs       # GltfSkeletalMeshHandler impl
```

`Asset::SkeletalMesh { lods: Vec<SkeletalMeshLod>, skeleton: ReferenceSkeleton, materials, bounds: FBoxSphereBounds, ... }`. `bounds` uses 3c's `FBoxSphereBounds` typed decoder. `ReferenceSkeleton { bones: Vec<BoneInfo>, bind_pose: Vec<FTransform> }`.

**Per-LOD vertex data is SoA (same layout discipline as 3g):**

```rust
pub struct SkeletalMeshLod {
    pub sections: Vec<SkelMeshSection>,
    pub positions: Vec<FVector>,
    pub normals: Vec<FVector>,
    pub tangents: Vec<FVector4>,           // VEC4 with handedness W
    pub uvs: [Option<Vec<FVector2D>>; 4],
    pub colors: Option<Vec<FColor>>,
    pub indices: Vec<u32>,
    /// Per-vertex bone influences. Maximum 8 influences per vertex
    /// (validated against `MAX_INFLUENCES_PER_VERTEX = 8`).
    /// Indices are LOD-local; remap via `bone_map` to global
    /// skeleton indices before emitting to glTF JOINTS_* accessors.
    /// Cooked vertices typically carry 4 or 8 influences, padded
    /// with zero-weight entries to a fixed per-LOD count.
    pub bone_indices: Vec<[u16; 8]>,
    pub bone_weights: Vec<[u8; 8]>,
    /// LOD-local-to-global bone index translation. Per-section
    /// also carries its own bone_map (`FSkelMeshSection.bone_map`);
    /// the LOD-level map is the union.
    pub bone_map: Vec<u16>,
}
```

---

## Scope (3h proper):

- **Parser:** `USkeletalMesh.Deserialize` — tagged-property segment (Skeleton ObjectProperty, Materials, LODInfo, PhysicsAsset, Sockets, ...) + segment-2 cooked LOD payload (`FStripDataFlags`, `ImportedBounds`, `SkeletalMaterials`, `FReferenceSkeleton`, `bCooked` flag, per-LOD `FStaticLODModel`).
- **`FReferenceSkeleton` reader** ([`skeleton.md`](../formats/mesh/skeleton.md)): bone count prefix, per-bone `FMeshBoneInfo` (name, parent_index, export_name), bind-pose `FTransform[]`, name → index lookup map. Uses 3c's `FTransform` decoder.
- **`FStaticLODModel` for skeletal meshes** (different shape from static-mesh version): `FStripDataFlags`, `FSkelMeshSection[]` sections (full field list below with version gates), `Indices: FMultisizeIndexContainer`, `ActiveBoneIndices: u16[]`, `RequiredBones: u16[]`, vertex buffer + skin-weight buffer + color buffer (optional).
- **`FSkelMeshSection` per-section record** (significantly differs from `FStaticMeshSection`; version gates are CUSTOM-VERSION-keyed, not UE-version-keyed). The field order below matches `skeletal-mesh.md:122-148` **exactly**; the TDD plan MUST read fields in this sequence:

  1. `FStripDataFlags` (variable bytes — strip-flags struct).
  2. `MaterialIndex: i16` (2 bytes — wire-doc says `short`).
  3. **(legacy) `ChunkIndex: u16`** dummy — read and discard. Present only when `skelMeshVer < CombineSectionWithChunk`. Modern paksmith-range content skips this branch.
  4. `BaseIndex: i32` (wire-doc says `int`, NOT `u32`) — gated on `!IsAudioVisualDataStripped()`.
  5. `NumTriangles: i32` (wire-doc says `int`) — gated on `!IsAudioVisualDataStripped()`.
  6. **(legacy) triangle-sorting `u8` dummy** — present only when `skelMeshVer < RemoveTriangleSorting`. Read and discard.
  7. **(legacy) APEX Cloth flags** — variable-byte version-gated block.
  8. `bRecomputeTangent: u32 (bool)` — gate: `FRecomputeTangentCustomVersion ≥ RuntimeRecomputeTangent`.
  9. `RecomputeTangentsVertexMaskChannel: u8` — gate: `FRecomputeTangentCustomVersion ≥ RecomputeTangentVertexColorMask`. (NOTE the order: this MUST come BEFORE bCastShadow, not after as R1 had it.)
  10. `bCastShadow: u32 (bool)` — gate: `FEditorObjectVersion ≥ RefactorMeshEditorMaterials`.
  11. `bVisibleInRayTracing: u32 (bool)` — gate: `FUE5MainStreamObjectVersion ≥ SkelMeshSectionVisibleInRayTracingFlagAdded` (a UE5 custom-version gate; the R1 "UE 4.27+" label was wrong).
  12. `BaseVertexIndex: u32` (wire-doc says `uint`) — gated on `skelMeshVer ≥ CombineSectionWithChunk` && AV data not stripped.
  13. **`SoftVertices: FSoftSkinVertex[]`** — editor-only data. Gate: presence is controlled by `FStripDataFlags::IsClassDataStripped(SoftVertexBufferStrip)` (or whichever flag the version-table marks for editor-data presence; pin the exact `FStripDataFlags` bit during TDD kickoff against `skeletal-mesh.md:136`). For cooked content (paksmith's target), this flag is set → block is stripped → ZERO bytes consumed. For non-cooked content paksmith encounters (rare; mostly editor-side asset bundling), the wire reader MUST consume a counted-prefix `int` + `count × ~64 bytes` per `FSoftSkinVertex` (position + tangent + UVs + bone indices + weights — exact per-vertex byte count depends on UE version; pin during TDD). Defense-in-depth: cap the count at `MAX_VERTICES_PER_LOD` even though cooked content never reaches this branch.
  14. `bUse16BitBoneIndex: u32 (bool)` — gate: `FAnimObjectVersion ≥ IncreaseBoneIndexLimitPerChunk` (UE 4.24, not UE 4.27 as R1 had it). Present here in `FSkelMeshSection` AND in `FSkinWeightVertexBuffer`.
  15. `bone_map: Vec<u16>` (counted `ushort[]`). LOD-local-to-global bone index translation. Counted-prefix is `i32`: (a) sign-check ≥ 0, (b) cap-check `<= MAX_BONE_MAP_ENTRIES_PER_SECTION` BEFORE `Vec::with_capacity` (per the master cap table — fires `BoneMapCountExceeded`). Validate every entry post-read: `bone_map[i] < skeleton.bones.len()` (fires `BoneMapOob`, per H12 above).
  16. `NumVertices: i32` (wire-doc says `int`) — gate: `skelMeshVer ≥ SaveNumVertices`. Sign-check ≥ 0.
  17. `MaxBoneInfluences: i32` (wire-doc says `int`, NOT `u32`) — **no version gate** (always present per the format doc; R1's "UE 4.27+" gate was wrong). Sign-check ≥ 0; cap at `MAX_INFLUENCES_PER_VERTEX = 8`.
  18. `ClothMappingDataLODs: Vec<Vec<FMeshToMeshVertData>>` — nested array. Outer is LOD-bias counts; gated on `FUE5ReleaseStreamObjectVersion ≥ AddClothMappingLODBias` (otherwise outer is implicit single-element wrap). Typically empty in cooked non-cloth content; cap **BOTH** counted-prefix levels BEFORE `Vec::with_capacity`: outer prefix `<= MAX_CLOTH_LOD_BIAS_LEVELS` (fires `ClothLodBiasCountExceeded`); each inner element's prefix `<= MAX_CLOTH_VERTS_PER_LOD` (fires `ClothVertCountExceeded`). Per master cap table.
  19. `CorrespondClothAssetIndex: i16` (wire-doc says `short`). Cloth-asset slot.
  20. **`ClothingData: 20 bytes`** — `FClothingSectionData` = `FGuid AssetGuid (16) + i32 AssetLodIndex (4)`. Gate: `skelMeshVer ≥ NewClothingSystemAdded` (UE 4.16+). Paksmith's pak v3+ floor (UE 4.4+) means this gate is reachable; cooked content uses this layout. **R1 omitted this field entirely** — without it, every section after the first misaligns by 20 bytes.
  21. `OverlappingVertices: HashMap<i32, Vec<i32>>` — gate: `FOverlappingVerticesCustomVersion ≥ DetectOVerlappingVertices`. Counted map. Cap **BOTH** levels BEFORE `HashMap::with_capacity` / `Vec::with_capacity`: map-count prefix `<= MAX_OVERLAPPING_VERTEX_MAP_ENTRIES` (fires `OverlappingVerticesMapExceeded`); each per-key value's Vec prefix `<= MAX_OVERLAPPING_VERTICES_PER_KEY` (fires `OverlappingVerticesKeyExceeded`). Per master cap table. **Note hash-flooding surface:** keys are attacker-controllable i32s; consider `HashMap` with a hash-DoS-resistant hasher (the std default uses RandomState which is sufficient) — verify at TDD kickoff.
  22. `bDisabled: u32 (bool)` — gate: `FReleaseObjectVersion ≥ AddSkeletalMeshSectionDisable`.
  23. `GenerateUpToLodIndex: i32` — gate: `skelMeshVer ≥ SectionIgnoreByReduceAdded`.
  24. `OriginalDataSectionIndex: i32` — gate: `FEditorObjectVersion ≥ SkeletalMeshBuildRefactor`. (R1's "UE 4.26+" UE-version label was wrong; it's a custom-version gate.)
  25. `ChunkedParentSectionIndex: i32` — same gate as 24.

  **Version gates use custom-version constants, NOT UE-version labels.** Paksmith's custom-version dispatch (`AssetContext::custom_versions`) is the source of truth at runtime. The TDD plan MUST enumerate each gate against its named constant and exercise both branches in tests.
- **`FSkinWeightVertexBuffer` reader (TWO paths, version-dispatched)** per `skeletal-mesh.md:152-179`:
  - **Legacy path** (`!bNewWeightFormat`, pre-UE-4.25): per-vertex `MaxBoneInfluences` (typically 4 or 8), `bUse16BitBoneIndex` flag, `bExtraBoneInfluences` (pre-UE 4.24) variant. Each vertex carries `[u8|u16; MaxBoneInfluences]` bone indices + `[u8; MaxBoneInfluences]` weights (normalized 0-255).
  - **New-format path** (`bNewWeightFormat = FAnimObjectVersion ≥ UnlimitedBoneInfluences`, UE 4.25+): fields are different. Read in order per `skeletal-mesh.md:166-178`:
    1. `FStripDataFlags` (variable bytes).
    2. `bVariableBonesPerVertex: u32 (bool)`.
    3. `MaxBoneInfluences: u32` (wire-doc says `uint` — unsigned; cap at `MAX_INFLUENCES_PER_VERTEX = 8`).
    4. `NumBones: u32` (wire-doc says `uint`).
    5. `NumVertices: u32` (wire-doc says `uint` — NOT `i32`; no sign check needed; range-cap against `MAX_VERTICES_PER_LOD` instead).
    6. `bUse16BitBoneIndex: u32 (bool)`.
    7. `bUse16BitBoneWeight: u32 (bool)`.
    8. `WeightData: byte[]` (flat byte array). Per-vertex stride = `MaxBoneInfluences × (index_size + weight_size)` where `index_size = if bUse16BitBoneIndex { 2 } else { 1 }` and `weight_size = if bUse16BitBoneWeight { 2 } else { 1 }`. **Use `checked_mul`** at every step: `let stride = MaxBoneInfluences.checked_mul(index_size).and_then(|s| s.checked_add(MaxBoneInfluences.checked_mul(weight_size)?))`; `let total = stride.checked_mul(NumVertices)`. **Verify `total == wire_byte_array_len`** (the byte array's own counted prefix); reject on mismatch — a wire-claim larger than the computed stride is wire corruption, smaller is a parser bug. Fires `BulkDataElementCountNegative`-style typed error (new variant `SkinWeightStrideMismatch` if needed; pin during TDD).
    9. **(gated on `bVariableBonesPerVertex == true`)** trailing lookup table: `FStripDataFlags` + `uint[]` (counted array) for variable-influence-count remap.
  - Modern UE 4.25+ cooked content lands on the new-format path. The TDD plan MUST encode the dispatch as a version-gated `if` with explicit test coverage on both paths.
- **`GltfSkeletalMeshHandler`** (`FormatHandler` impl): output extension `"glb"` (binary glTF for self-containment). Produces glTF 2.0 with:
  - Node hierarchy: one node per bone, plus a root mesh node.
  - `skin`: bone-count `joints` array + `inverseBindMatrices` accessor (computed from FReferenceSkeleton bind pose).
  - Mesh primitives: position / normal / tangent / texcoord accessors (shared 3g path) PLUS `JOINTS_0` (`UNSIGNED_BYTE` or `UNSIGNED_SHORT` VEC4) + `WEIGHTS_0` (`UNSIGNED_BYTE`/`FLOAT` VEC4 normalized).
  - 8-influence variants split into JOINTS_0 + JOINTS_1 + WEIGHTS_0 + WEIGHTS_1.
- **Bone-map remap with explicit OOB check sites**: per-section LOD-local bone indices must be remapped to global skeleton indices via the section's `bone_map: u16[]` before emitting to glTF. Critical for correct skinning AND for security (bone indices are attacker-influenced u8/u16 on the wire). The TDD plan MUST pin TWO check sites:
  1. **Per-vertex influence check** (inside the skin-weight read loop): for each `bone_indices[k]` (per-vertex influence index, `k in 0..MaxBoneInfluences`), verify `bone_indices[k] < bone_map.len()` BEFORE the indirect read. Out-of-bounds → fire `BoneIndexOob { influence_idx, vertex_idx, bone_map_len }` and abort the LOD parse.
  2. **Per-section bone_map check** (inside the bone-map read loop): for each `bone_map[i]` (LOD-local index into the global skeleton bones array), verify `bone_map[i] < skeleton.bones.len()` BEFORE storing. Out-of-bounds → fire `BoneMapOob { local_idx, global_idx, skeleton_len }` and abort.

  Both checks happen at PARSE time (not at glTF emit time), so corrupt assets reject early before downstream processing sees garbage.
- **`MaxBoneInfluences` validation**: `FSkelMeshSection.MaxBoneInfluences` is `i32` on wire (sign-check ≥ 0 required) while `FSkinWeightVertexBuffer` new-format-path `MaxBoneInfluences` is `u32` (no sign check). Both MUST cap at `MAX_INFLUENCES_PER_VERTEX = 8` BEFORE any `as usize` cast or per-vertex iteration.
- **Caps**: `MAX_BONES_PER_SKELETON = 65_535` (matches the 16-bit bone index limit), `MAX_SKELETAL_LODS_PER_MESH = 8`, `MAX_INFLUENCES_PER_VERTEX = 8`, `MAX_BONE_MAP_ENTRIES_PER_SECTION = MAX_BONES_PER_SKELETON`.
- **Error variants**: `SkeletonBoneCountExceeded { count, cap }`, `BoneIndexOob { influence_idx, vertex_idx, bone_map_len }`, `BoneMapOob { local_idx, global_idx, skeleton_len }`, `InfluenceCountInvalid { count, cap }`, `InfluenceCountNegative { count }` (new-format path's `MaxBoneInfluences` is `u32` but the legacy path's was `i32` — defensive check on the legacy branch), `SkeletalLodCountExceeded { count, cap }`.

## Out of scope (named target phases / follow-ups):

- **`UAnimSequence` export** (animation tracks → glTF `animations` array). → **Phase 3 follow-up sub-phase (3i) OR fold into Phase 9 (3D Viewport).** Animation export is itself a complex sub-problem: per-bone compressed track data, multiple compression schemes (ACL, raw, etc.), key-frame interpolation. 3h MVP ships static bind-pose meshes; the timeline scrubber + animation playback are Phase 7 GUI / Phase 9 viewport concerns.
- **`UMorphTarget` blend shapes** → 3h follow-up. The format-doc lists MorphTargets as a tagged property; the cooked vertex-delta payload requires its own per-blend-shape parser. Defer to follow-up.
- **Cloth simulation data** (`MeshClothingAssets`) → 3h follow-up. UE 4.16+ feature; not blocking MVP.
- **Physics asset (UPhysicsAsset) export** → not a Phase 3 concern; physics is runtime, not export. Could land in a future "physics assets" sub-phase if user demand emerges.
- **Sockets** → 3h follow-up. Sockets are attachment points (per-bone named transforms); easy to add as glTF extras once MVP lands.

---

## Crate-selection candidates (decide at kickoff)

Same as 3g — `gltf` vs `gltf-json` vs hand-rolled GLB. Coordinate with 3g's decision; pick the same crate to avoid two glTF dependencies.

---

## Milestone breakdown (proposed)

1. **3h-1: Variant + tagged-property segment + dispatch wiring.** `USkeletalMesh` class name routes.
2. **3h-2: `FReferenceSkeleton` reader.** Bone hierarchy + bind pose via 3c's `FTransform`. Validates bone indices, builds parent-child tree.
3. **3h-3: Segment-2 prefix: strip-flags + ImportedBounds + SkeletalMaterials.** Reuses 3c FBoxSphereBounds (or fallback).
4. **3h-4: `FStaticLODModel` (skeletal variant) — sections + index buffer.** `FSkelMeshSection` differs from `FStaticMeshSection`; differential parser.
5. **3h-5: `FSkinWeightVertexBuffer` reader.** `bUse16BitBoneIndex` dispatch, `bExtraBoneInfluences` legacy variant, per-vertex influences.
6. **3h-6: Vertex buffer reuse from 3g.** Position + normal + tangent + UV come from `vertex_buffers.rs`; just add skin-weight overlay.
7. **3h-7: Bone-map remap.** Per-section LOD-local → global bone index translation.
8. **3h-8: `GltfSkeletalMeshHandler` skeleton.** Mesh + skin + joints + inverseBindMatrices.
9. **3h-9: 4-influence path.** Single JOINTS_0 + WEIGHTS_0 vec4.
10. **3h-10: 8-influence path** (split into JOINTS_0/1 + WEIGHTS_0/1).
11. **3h-11: Integration test + fixture.** 5-bone skeleton, single-LOD skinned cube; gltf-validator + Blender renders bind pose.

---

## Fixture-count gate

3h's TDD conversion adds ~5-7 fixtures (5-bone skeleton, single-LOD skinned, legacy `FSkinWeightVertexBuffer` path, new-format `bNewWeightFormat` path with `bVariableBonesPerVertex`, 4-influence + 8-influence variants, multi-section). Bump `.github/workflows/ci.yml`'s fixture-count constant per `feedback_fixture_count_gate.md`.

## Contract callouts for TDD conversion

- **`TypedReaderFn` returns `Result<(Asset, Vec<FByteBulkData>)>`** (per 3a R3 fix). The skeletal-mesh reader collects per-LOD `FStaticLODModel` vertex / index / skin-weight buffer `FByteBulkData` records and returns them in the second tuple element; the dispatch caller drives `insert_bulk_records`. Typed reader signature: `pub(crate) fn read_typed(payload: &[u8], ctx: &AssetContext, asset_path: &str) -> crate::Result<(Asset, Vec<FByteBulkData>)>`.

## Open questions for kickoff

1. **`UAnimSequence` decision.** Confirm OUT of scope for 3h. If included, 3h grows substantially.
2. **MaxBoneInfluences dispatch.** Engine cooks 4 or 8 influences per vertex; verify which Lyra / Manta / shipping games actually use. The format doc notes both variants exist.
3. **`bExtraBoneInfluences` deprecation.** Pre-UE 4.24 split skin weights into "main" and "extra" buffers; UE 4.24+ unified. Decide whether to support the legacy split path; recommendation: yes (the wire is documented; ~50 lines extra).
4. **glTF inverse-bind-matrices computation.** Need to invert each bone's world-space bind pose. Use a small dependency (e.g. `glam`) or hand-rolled 4×4 matrix inverse?
5. **Cloth + morph targets.** Confirm both deferred to follow-up.
6. **3h's dependency on 3g.** If 3g splits into 3g1 + 3g2, 3h depends only on 3g1 (the parser). Lock at 3g kickoff.

---

## Review panel (when 3h enters TDD)

- Wire-format pass — MANDATORY (`FReferenceSkeleton` + `FSkinWeightVertexBuffer` + `FSkelMeshSection` — dense per-version conditionals).
- Security pass — MANDATORY (bone-index OOB, influence-count OOB, bone-map OOB — every per-vertex value is attacker-influenced).
- Performance — RECOMMENDED (skinned meshes have larger vertex buffers than static).
- Deep-impact tracer — MANDATORY (adds `Asset::SkeletalMesh` + `ReferenceSkeleton` types that downstream Phase 7 / Phase 9 consumers will lean on).

5-6 reviewers per task PR.

---

## References

- Wire-format references:
  - [`../formats/mesh/skeletal-mesh.md`](../formats/mesh/skeletal-mesh.md) — USkeletalMesh / FStaticLODModel / FSkelMeshSection / FSkinWeightVertexBuffer.
  - [`../formats/mesh/skeleton.md`](../formats/mesh/skeleton.md) — FReferenceSkeleton / FMeshBoneInfo / bind pose.
  - [`../formats/mesh/vertex-formats.md`](../formats/mesh/vertex-formats.md) — shared with 3g.
- Master index: [`phase-3-export-pipeline.md`](phase-3-export-pipeline.md).
- 3g (StaticMesh): [`phase-3g-staticmesh-export.md`](phase-3g-staticmesh-export.md) — shared mesh module + vertex/index buffers.
- 3c (typed engine structs): [`phase-3c-typed-binary-structs.md`](phase-3c-typed-binary-structs.md) — supplies FTransform for bind poses.
- glTF 2.0 skin spec: <https://registry.khronos.org/glTF/specs/2.0/glTF-2.0.html#skins>.
