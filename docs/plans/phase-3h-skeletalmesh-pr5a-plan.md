# Phase 3h PR5a — single inlined-LOD streamed-blob parse — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax. Design: [`phase-3h-skeletalmesh-design.md`](phase-3h-skeletalmesh-design.md); wire ref: [`../formats/mesh/skeletal-mesh.md`](../formats/mesh/skeletal-mesh.md).

**Goal:** Parse the cooked `FStaticLODModel::SerializeStreamedData` blob **structurally** for **one inlined LOD[0]**, filling its geometry: indices, positions, normals, tangents, UVs, colors, and per-vertex bone indices/weights.

**Architecture:** A new `read_streamed_data` orchestrates the blob in oracle order — reusing the 3g static-mesh vertex/color buffer readers, adding a new `FMultisizeIndexContainer` reader (skeletal index) and the new `FSkinWeightVertexBuffer` reader (both legacy UE4.24 + new UE4.25+ paths — the headline risk). `read_typed` parses the blob for LOD[0] only when `bInlined`; non-inlined LODs and all of LOD[1..] are PR5b.

**Tech Stack:** Rust; reuse `vertex_buffers::{read_position_buffer, read_static_mesh_vertex_buffer, read_color_buffer}`, `read::{read_bulk_array_header, read_capped_count, ensure_bulk_count, read_u32, read_u8, read_i32}`, `wire::{read_strip_data_flags, read_bool32, is_av_data_stripped, is_class_data_stripped}`, `index_buffer::MAX_INDICES_PER_LOD`, `vertex_buffers::MAX_VERTICES_PER_LOD`, `custom_version::version_for`.

**PR-series (now 7):** PR1-4 + off-by-one merged. **PR5 sub-split → PR5a (this) = single inlined-LOD blob; PR5b = multi-LOD iteration + post-loop tail + non-inlined + bone-map remap.** PR6 = `GltfSkeletalMeshHandler`. (Tell the user.)

## ORACLE-VERIFIED `SerializeStreamedData` order (UE4.24–4.27 inlined; Task 1 re-derives — 53→54 / bCooked-gate lessons)
After the LOD header's `BuffersSize` (PR4), when `bInlined`:
1. inner `FStripDataFlags` (2×u8 global+class — KEEP `class` for the adjacency gate).
2. `Indices` = `FMultisizeIndexContainer` (NEW `read_multisize_index_container`). → `lod.indices`.
3. `PositionVertexBuffer` (REUSE `read_position_buffer → Vec<FVector>`). → `lod.positions`.
4. `StaticMeshVertexBuffer` (REUSE `read_static_mesh_vertex_buffer → StaticMeshVertexData{normals, tangents, uvs, num_tex_coords}`). → `lod.normals/tangents/uvs`.
5. `FSkinWeightVertexBuffer` (NEW `read_skin_weight_vertex_buffer`, both paths). → `lod.bone_indices/bone_weights`.
6. `ColorVertexBuffer` — **only if `bHasVertexColors`** (segment-1 tagged property; REUSE `read_color_buffer → Option<Vec<FColor>>`). → `lod.colors`.
7. `AdjacencyIndexBuffer` = `FMultisizeIndexContainer`, **read-and-discard**, gated `version_for(UE5_RELEASE_STREAM_GUID).is_none_or(|v| v < RemovingTessellation) && !is_class_data_stripped(class, CDSF_ADJACENCY_DATA)` (UE4 → version absent → present iff not class-stripped).
8. `ClothVertexBuffer` — **skip**, gated `HasClothData()` = any parsed section's `correspond_cloth_asset_index >= 0`. (Task 1 pins the skippable shape.)
9. `FSkinWeightProfilesData` — **UNCONDITIONAL** structural handling (`ReadMap(FName, FRuntimeSkinWeightProfileData)` = i32 count + N entries; cooked-norm count 0). (Task 1 pins the per-entry shape; PR5a may handle count==0 + reject count>0 as `UnsupportedFeature` if the per-entry parse is heavy — Task 1 decides.)
10. ray-tracing tail — **skip**, gated `HasRayTracingData` (UE4.27/4.25_Plus): `SkipFixedArray(1)` = i32 count + count×1. (morph/vertex-attribute/half-edge tails are UE5-only → never fire for UE4.)

## NEW custom-version dependency
`FAnimObjectVersion` is NOT in `custom_version.rs`. Add GUID `new(0xAF43A65D,0x7FD34947,0x98733E8E,0xD9C1BB05)` + `UnlimitedBoneInfluences` + `IncreaseBoneIndexLimitPerChunk` positions (Task 1 verifies, expected 5 + 4). `bNewWeightFormat = FAnimObjectVersion >= UnlimitedBoneInfluences`. Also `FUE5MainStreamObjectVersion::IncreasedSkinWeightPrecision` position (UE5-only; the GUID already exists).

---

## File structure
- **Modify** `crates/paksmith-core/src/asset/custom_version.rs` — `ANIM_OBJECT_VERSION_GUID` + positions + `MATERIAL...`/`INCREASED_SKIN_WEIGHT_PRECISION`; pin tests.
- **Modify** `crates/paksmith-core/src/asset/wire.rs` — `STRIP_FLAG_ADJACENCY_DATA` (Task-1 value).
- **Create** `crates/paksmith-core/src/asset/exports/mesh/skin_weights.rs` — `read_skin_weight_vertex_buffer` (both paths) + `read_multisize_index_container` (or put the index reader in skeletal_mesh.rs; keep skin weights focused). Add `pub(crate) mod skin_weights;` to `mesh/mod.rs`.
- **Modify** `crates/paksmith-core/src/asset/exports/mesh/skeletal_mesh.rs` — `read_streamed_data`, the `bHasVertexColors` helper, the `read_typed`/`read_static_lod_model` wiring.
- **Modify** `crates/paksmith-core/src/error.rs` — new faults + wire-fields.
- **Modify** `docs/formats/mesh/skeletal-mesh.md` — the streamed-blob structure.

All work in `.claude/worktrees/feat+phase-3h-lod-buffers/` (branch `feat/phase-3h-lod-buffers`).

---

## Task 1: Oracle re-verification (no code — record verified facts; surface complexity)

- [ ] **Step 1 — SerializeStreamedData order.** Re-fetch CUE4Parse `FStaticLODModel.cs` `SerializeStreamedData` @ `cf74fc32`. Confirm the 10-item order above verbatim (esp.: skin-weights BEFORE color; color gated on the `bHasVertexColors` tagged property; `FSkinWeightProfilesData` UNCONDITIONAL; the adjacency `RemovingTessellation && !CDSF_AdjacencyData` gate). Confirm the inner `FStripDataFlags` `class` byte drives the adjacency gate and pin `CDSF_AdjacencyData`'s value (=1? distinct byte from the section's strip flags).
- [ ] **Step 2 — FMultisizeIndexContainer.** Fetch `FMultisizeIndexContainer.cs`. Confirm `DataSize(u8: 2/4) + ReadBulkArray(elementSize i32 + elementCount i32 + count×width)`; `bOldNeedsCPUAccess` absent for 4.24+.
- [ ] **Step 3 — FSkinWeightVertexBuffer BOTH paths.** Fetch `FSkinWeightVertexBuffer.cs` + `FSkinWeightInfo.cs`. Pin the LEGACY metadata (`bExtraBoneInfluences` + the `SplitModelAndRenderData` stride skip + `numVertices`) + the per-vertex `FSkinWeightInfo` (BoneIndex[N]u8 + BoneWeight[N]u8, N=4/8). Pin the NEW metadata (`bVariableBonesPerVertex`/`maxBoneInfluences`/`numBones`/`numVertices` + `bUse16BitBoneIndex` + `bUse16BitBoneWeight`) + the influence-data layout (`newData = ReadBulkArray<byte>` + lookup block). **CRITICAL: pin how per-vertex influences are decoded from `newData` (fixed stride when `!bVariableBonesPerVertex`; offset-indexed via the lookup table when variable). If the variable-bones decode is materially complex, SAY SO — PR5a will parse fixed-stride + defer variable-bones to a documented limitation (`UnsupportedFeature` or empty bone data + flag).** Pin `FAnimObjectVersion` GUID byte-array + `UnlimitedBoneInfluences`/`IncreaseBoneIndexLimitPerChunk` positions + `FUE5MainStreamObjectVersion.IncreasedSkinWeightPrecision` position.
- [ ] **Step 4 — bHasVertexColors source.** Confirm CUE4Parse reads `bHasVertexColors` via `USkeletalMesh` `GetOrDefault<bool>("bHasVertexColors")` (default false) — a tagged property, NOT a wire field.
- [ ] **Step 5 — FSkinWeightProfilesData + cloth + ray-tracing skips.** Pin `FRuntimeSkinWeightProfileData`'s per-entry shape (4.26+ vs pre-4.26) + the `FSkeletalMeshVertexClothBuffer` skippable structure + the ray-tracing `SkipFixedArray(1)` shape. Decide PR5a's profiles approach (full parse vs count==0-only).

No commit. Surfaced complexity supersedes the plan; if the new-format decode is heavier than assumed, the controller re-scopes before Task 4/5.

---

## Task 2: New custom-version constants + adjacency strip flag

**Files:** `custom_version.rs`, `wire.rs`

- [ ] **Step 1: Pin tests (failing)** for `ANIM_OBJECT_VERSION_GUID` bytes + `UNLIMITED_BONE_INFLUENCES`/`INCREASE_BONE_INDEX_LIMIT_PER_CHUNK`/`INCREASED_SKIN_WEIGHT_PRECISION` positions (Task-1 values), mirroring `skeletal_material_gate_guids_and_positions`.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Add the consts** (GUID byte-array style with `// A = 0x... (LE)` comments; doc-cite + anchor):
```rust
pub const ANIM_OBJECT_VERSION_GUID: FGuid = FGuid::from_bytes([ /* Task-1 LE bytes of 0xAF43A65D,0x7FD34947,0x98733E8E,0xD9C1BB05 */ ]);
pub const UNLIMITED_BONE_INFLUENCES: i32 = 5;            // verify
pub const INCREASE_BONE_INDEX_LIMIT_PER_CHUNK: i32 = 4;  // verify
pub const INCREASED_SKIN_WEIGHT_PRECISION: i32 = /* Task-1, FUE5MainStream */;
```
- [ ] **Step 4: Adjacency strip flag** (wire.rs): `pub(crate) const STRIP_FLAG_ADJACENCY_DATA: u8 = /* Task-1 value */;` + a pin test (its value + that it's the class-flag bit the blob's adjacency gate checks).
- [ ] **Step 5: Run** → PASS. **Step 6: Commit** `feat(asset): FAnimObjectVersion + adjacency strip flag for skeletal streamed data (3h)`.

---

## Task 3: `read_multisize_index_container`

**Files:** `crates/paksmith-core/src/asset/exports/mesh/skin_weights.rs` (new module) + `mesh/mod.rs`

- [ ] **Step 1: Failing test.** `multisize_index_container_16bit`: bytes = `DataSize=2(u8)` + bulk header (`elementSize=2 i32`, `elementCount=3 i32`) + `3×u16 [1,2,3]` → `read_multisize_index_container` returns `vec![1u32,2,3]` + full consumption. Plus `..._32bit` (DataSize=4, u32 elements).
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** `pub(crate) fn read_multisize_index_container<R: Read + ?Sized>(r: &mut R, asset_path: &str, field: AssetWireField) -> crate::Result<Vec<u32>>`: read `DataSize` u8 (must be 2 or 4 → else typed fault); `(elem_size, count) = read::read_bulk_array_header(r, asset_path, field, MAX_INDICES_PER_LOD)`; read `count` elements of width `DataSize` (u16 or u32 LE) into `Vec<u32>` (widen u16). EOF-bound (each element read returns typed EOF on truncation). (Optionally cross-check `elem_size == DataSize`.)
- [ ] **Step 4: Run** → PASS. **Step 5: Commit** `feat(asset): FMultisizeIndexContainer reader (3h)`.

---

## Task 4: `read_skin_weight_vertex_buffer` — LEGACY path (UE4.24)

**Files:** `skin_weights.rs`

- [ ] **Step 1: Failing test.** `skin_weights_legacy_4_influences`: a ctx with `FAnimObjectVersion < UnlimitedBoneInfluences` (legacy) + `FSkeletalMeshCustomVersion >= SplitModelAndRenderData`. Bytes: `FStripDataFlags(2u8, not AV-stripped)` + `bExtraBoneInfluences=0(bool32)` + `stride(4 bytes, skipped)` + `numVertices=2(u32)` + Weights bulk header (`elementSize`, `elementCount=2`) + `2 × FSkinWeightInfo` where each = `4×u8 bone` + `4×u8 weight`. Assert `bone_indices == [[b0,b1,b2,b3,0,0,0,0], ...]` (u8 widened to u16, padded to 8) + `bone_weights == [[w0..w3,0,0,0,0], ...]`. RED.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** the legacy branch of `pub(crate) fn read_skin_weight_vertex_buffer<R: Read + ?Sized>(r, ctx, asset_path) -> crate::Result<(Vec<[u16;8]>, Vec<[u8;8]>)>`: gate on `version_for(ANIM_OBJECT_VERSION_GUID).is_some_and(|v| v >= UNLIMITED_BONE_INFLUENCES)` → false = legacy. Legacy: read meta strip flags (keep global), `bExtraBoneInfluences` bool32, `if version_for(SKELETAL_MESH_CUSTOM_VERSION_GUID) >= SPLIT_MODEL_AND_RENDER_DATA: skip 4`, `numVertices` u32 (capped ≤ MAX_VERTICES_PER_LOD). `n = bExtraBoneInfluences ? 8 : 4`. If `!is_av_data_stripped(meta_global)`: `(_, count) = read_bulk_array_header(.. MAX_VERTICES_PER_LOD)`; per vertex read `n×u8` bone + `n×u8` weight → `[u16;8]` (widen+pad) + `[u8;8]` (pad). Else empty.
- [ ] **Step 4: Run** → PASS. Add `skin_weights_legacy_8_influences` (bExtraBoneInfluences=1). **Step 5: Commit** `feat(asset): FSkinWeightVertexBuffer legacy path (3h)`.

---

## Task 5: `read_skin_weight_vertex_buffer` — NEW path (UE4.25+)

**Files:** `skin_weights.rs`

**TASK-1 CORRECTIONS (verified vs CUE4Parse@cf74fc32 — supersede the original sketch):** (1) the per-vertex influence count is **`num_skel = (maxBoneInfluences > 4 ? 8 : 4)`** — i.e. `bExtraBoneInfluences = maxBoneInfluences > 4`, then 8 or 4. **NOT `maxBoneInfluences × width`** (that desyncs for maxBoneInfluences ∈ {5,6,7}). (2) Per vertex: read `num_skel` bone INDICES first, then `num_skel` WEIGHTS (each u8 for UE4; u16 only if `bUse16BitBoneIndex`/`bUse16BitBoneWeight`). (3) The lookup block is read in two parts with DIFFERENT gates: `newData = ReadBulkArray<byte>` is gated on the **data** strip flags' AV bit; then the lookup HEADER (`lookupStripFlags` 2×u8 + `numLookupVertices` i32) is read **UNCONDITIONALLY**, and `LookupData = ReadBulkArray<uint>` is gated on **`lookupStripFlags`' OWN** AV bit (not the data strip flags). (4) `bUse16BitBoneIndex` is ALWAYS present in the new branch (IncreaseBoneIndexLimitPerChunk=4 < UnlimitedBoneInfluences=5). (5) `bUse16BitBoneWeight` is ALWAYS absent for UE4 (UE5-only gate). (6) Variable-bones (`bVariableBonesPerVertex==true`) is DEFER-SAFE: `newData`/`LookupData` are self-describing bulk arrays consumed off the main cursor, and CUE4Parse decodes influences on a SEPARATE temp archive over `newData` — so reading both bulk arrays + the lookup header fully advances the main cursor regardless of whether PR5a decodes the influences. **PR5a: decode `!bVariableBonesPerVertex` (sequential fixed) only; `bVariableBonesPerVertex==true` → consume newData+lookup (stay aligned) but leave bone_indices/bone_weights EMPTY + a one-line `tracing::warn!` + document the limitation.** (7) The `!UseNewCookedFormat` metadata branch is DEAD for UE4.24+ (UseNewCookedFormat always true) — do NOT implement it.

- [ ] **Step 1: Failing test.** `skin_weights_new_fixed_stride`: ctx with `FAnimObjectVersion >= UnlimitedBoneInfluences(5)`. Bytes per the NEW metadata: `FStripDataFlags(2u8, not AV-stripped)` + `bVariableBonesPerVertex=0(bool32)` + `maxBoneInfluences=4(u32)` + `numBones=N(u32)` + `numVertices=2(u32)` + `bUse16BitBoneIndex=0(bool32)` + `newData` bulk (`elementSize=1 i32`, `elementCount = 2 verts × num_skel(=4) × 2(idx+wt) = 16`) of raw influence bytes (per vertex: 4×u8 bone-idx then 4×u8 weight) + lookup block (`FStripDataFlags(2u8)` + `numLookupVertices=0(i32)`). Assert `bone_indices == [[b0..b3,0,0,0,0], ...]` (u8→u16 widened, padded to 8) + `bone_weights == [[w0..w3,0,0,0,0], ...]` + full consumption. RED.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** the new branch: read meta (`bVariableBonesPerVertex` bool32, `maxBoneInfluences`/`numBones`/`numVertices` u32 capped, `bUse16BitBoneIndex` bool32 if `version_for(ANIM_OBJECT_VERSION_GUID) >= INCREASE_BONE_INDEX_LIMIT_PER_CHUNK(4)`, `bUse16BitBoneWeight` bool32 if `version_for(UE5_MAIN_STREAM_GUID) >= INCREASED_SKIN_WEIGHT_PRECISION`). `num_skel = if maxBoneInfluences > 4 { 8 } else { 4 }`. `newData`: if `!is_av_data_stripped(data_global)` → `read_bulk_array_header + count bytes` (capped). Lookup block: `lookupStripFlags = read_strip_data_flags`; `numLookupVertices = read_i32`; `if !is_av_data_stripped(lookup_global)` → `read_bulk_array_header + count×u32` (LookupData). Decode: if `!bVariableBonesPerVertex` → iterate `numVertices`, each reads `num_skel` indices (u16 or u8→u16) then `num_skel` weights (u8 or u16→clamp to u8 per the [u8;8] note) from `newData`, widen+pad to `[u16;8]`/`[u8;8]`. If `bVariableBonesPerVertex` → leave empty + `tracing::warn!` + a tracked limitation. (newData already consumed → cursor stays aligned either way.) `boneIdxSize = if bUse16BitBoneIndex {2} else {1}`; `weightSize = if bUse16BitBoneWeight {2} else {1}` (UE4: both 1).
- [ ] **Step 4: Run** → PASS. Add `skin_weights_new_16bit_bone_index`. **Step 5: Commit** `feat(asset): FSkinWeightVertexBuffer new path (3h)`.

---

## Task 6: `read_streamed_data` orchestration + bHasVertexColors helper

**Files:** `skeletal_mesh.rs`

- [ ] **Step 1: bHasVertexColors helper + failing test.** Add `fn property_bool(props: &[Property], name: &str) -> bool` returning true iff a `Property` named `name` has `PropertyValue::Bool(true)` (default false). Test it on a small property list.
- [ ] **Step 2: Failing test for `read_streamed_data`.** Build a full inlined blob (inner strip flags + multisize index + position buffer + static-mesh-vertex buffer + skin-weight buffer (legacy) + NO color [bHasVertexColors=false] + adjacency [present, discard] + no cloth [no section has cloth] + FSkinWeightProfilesData count=0 + no ray-tracing [UE4.24 ctx]) using the 3g buffer byte-builders. Assert the returned/filled `SkeletalMeshLod` has indices/positions/normals/tangents/uvs/bone_indices/bone_weights populated + the SoA length invariant (positions.len()==normals.len()==bone_indices.len()). RED.
- [ ] **Step 3: Implement** `fn read_streamed_data<R: Read + ?Sized>(r, ctx, asset_path, b_has_vertex_colors: bool, sections: &[SkelMeshSection], lod: &mut SkeletalMeshLod) -> crate::Result<()>`:
  - inner `read_strip_data_flags` (keep class); `lod.indices = read_multisize_index_container(.. MeshIndex field)`; `lod.positions = read_position_buffer(...)`; `let v = read_static_mesh_vertex_buffer(r, ctx, asset_path)?; lod.normals = v.normals; lod.tangents = v.tangents; lod.uvs = v.uvs;`; `(lod.bone_indices, lod.bone_weights) = read_skin_weight_vertex_buffer(r, ctx, asset_path)?;`
  - `if b_has_vertex_colors { lod.colors = read_color_buffer(r, asset_path)?; }`
  - adjacency (Task-1 pins: `RemovingTessellation`=3 in FUE5ReleaseStreamObjectVersion, `CDSF_AdjacencyData`=1): `if version_for(UE5_RELEASE_STREAM_OBJECT_VERSION_GUID).is_none_or(|v| v < REMOVING_TESSELLATION) && !is_class_data_stripped(class, STRIP_FLAG_ADJACENCY_DATA)` → `let _ = read_multisize_index_container(...)` (discard).
  - cloth (Task-1: `FSkeletalMeshVertexClothBuffer` = inner FStripDataFlags(2u8) → if AV-stripped return; else SkipBulkArrayData + [if FSkeletalMeshCustomVersion≥CompactClothVertexBuffer(=10, always for 4.24+): ClothIndexMapping = i32 count + count×u64]): `if sections.iter().any(|s| s.correspond_cloth_asset_index >= 0) { skip per that shape }`.
  - `FSkinWeightProfilesData` (UNCONDITIONAL): read i32 count; **count==0 → done; count>0 → `UnsupportedFeature`** (the per-entry `FRuntimeSkinWeightProfileData` is version-forked + rare on cooked; defer).
  - ray-tracing tail (Task-1: gate `HasRayTracingData` = Game≥UE4.27/4.25_Plus; for paksmith approximate via `ctx.version.is_ue4_27_or_later()` — confirm the existing helper): `if has_ray_tracing { skip SkipFixedArray(1) = i32 count + count×1 byte }`.
  - SoA length checks (mirror 3g lod.rs `positions.len()==normals.len()` + `ensure_bulk_count` for colors/bone arrays).
- [ ] **Step 4: Run** → PASS. **Step 5: Commit** `feat(asset): skeletal streamed-data orchestration (3h)`.

(Note: `RemovingTessellation` position in FUE5ReleaseStreamObjectVersion — Task 1 pins it; the GUID already exists as `UE5_RELEASE_STREAM_OBJECT_VERSION_GUID`.)

---

## Task 7: Wire LOD-0 blob into `read_typed`

**Files:** `skeletal_mesh.rs`

- [ ] **Step 1: Failing test.** Extend `read_typed_parses_lod0` (PR4) so the inlined LOD-0 has a full streamed blob; assert `lods[0]` now has populated geometry (positions/indices/bone_indices non-empty). RED (currently read_typed stops at blob-start).
- [ ] **Step 2: Implement.** Restructure so `read_static_lod_model` RETURNS `(SkeletalMeshLod, bool /*inlined*/)` (or a struct) stopping at blob-start, and `read_typed` (which has `properties` + the parsed sections via the LOD) computes `b_has_vertex_colors = property_bool(&properties, "bHasVertexColors")` and, when the LOD is inlined and AV-present, calls `read_streamed_data(&mut cur, ctx, asset_path, b_has_vertex_colors, &lod.sections, &mut lod)`. Non-inlined → leave geometry empty (PR5b). Only LOD[0] (PR5b iterates). Keep the PR4 4.24/bCooked gates.
- [ ] **Step 3: Run** → PASS. **Step 4: Commit** `feat(asset): parse inlined LOD-0 streamed blob in read_typed (3h)`.

---

## Task 8: Hardening

**Files:** `skin_weights.rs`, `skeletal_mesh.rs` (tests + guards)

- [ ] Caps: over-cap index count / vertex count / skin-weight count → typed `Err` (boundary tests).
- [ ] DataSize ∉ {2,4} → typed fault. Legacy 4-vs-8 influence boundary (bExtraBoneInfluences). New-path `bUse16BitBoneIndex` present/absent pair. The `bNewWeightFormat` gate boundary (FAnimObjectVersion `UnlimitedBoneInfluences-1` legacy vs `=5` new).
- [ ] bHasVertexColors true → color read; false → skipped (cursor/length differs). adjacency present/class-stripped pair. cloth present (a section with `correspond_cloth_asset_index >= 0`) → skip path. profiles count==0 vs count>0 (per Task-1 outcome).
- [ ] SoA mismatch (positions.len() != bone_indices.len()) → typed fault. Truncation mid-blob → typed Err, no panic.
- [ ] **Commit** `test(asset): skeletal streamed-data hardening (3h)`.

---

## Task 9: Gate chain + in-diff cargo-mutants

- [ ] `cargo fmt --all`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`; `cargo test --workspace --all-features`; `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features`; `typos .`; `cargo deny check` — all green.
- [ ] `git diff origin/main -- > /tmp/pr_3h5a.diff && cargo mutants --in-diff /tmp/pr_3h5a.diff --no-shuffle -j 4 --all-features` → **0 missed, 0 timeout**. Pin survivors (the DataSize match, the bNewWeightFormat gate, the influence-count/stride math, the bHasVertexColors/adjacency/cloth gates, the widen/pad logic).
- [ ] Commit pins.

---

## Task 10: Doc — the streamed-blob structure

**Files:** `docs/formats/mesh/skeletal-mesh.md`

- [ ] Document `SerializeStreamedData` (the 10-item order), `FMultisizeIndexContainer`, the `FSkinWeightVertexBuffer` legacy-vs-new fork (the 4.24/4.25 boundary, the influence layouts), `bHasVertexColors` as a tagged-property gate, and the skipped/deferred parts (cloth, profiles>0, ray-tracing, variable-bones if deferred). Note PR5a = single inlined LOD[0]; PR5b = iteration + post-loop tail + non-inlined + remap. Cite CUE4Parse only.
- [ ] `typos docs/`. **Commit** `docs(mesh): document FStaticLODModel streamed-data + FSkinWeightVertexBuffer (3h)`.

---

## Task 11: Review panel to convergence, then PR

- [ ] **≥5-reviewer panel** on `git diff main..HEAD`: **wire-format** (MUST independently re-derive the SerializeStreamedData order + the skin-weight two-path fork incl. the influence decode + the FAnimObjectVersion GUID/positions + the bHasVertexColors gate + the adjacency/cloth/ray-tracing/profiles gates vs CUE4Parse@cf74fc32 — NOT inherit Task 1), **security** (every count capped before alloc; the newData/lookup bulk arrays bounded; no panic; the influence-decode stride math no-overflow; SoA-mismatch → Err), **deep-impact** (the new skin_weights module + the read_static_lod_model signature change + read_typed plumbing + the bHasVertexColors property query + the PR5b seam), **code-reviewer**, **simplifier**. Brief adversarially (conf ≥ 70, hunt cold; emphasize the legacy-vs-new fork + the influence decode + the bHasVertexColors plumbing). Re-run the FULL panel each fix round to convergence.
- [ ] **Push + PR.** Marker at the worktree git-dir (SEPARATE Bash call from push; another before `gh pr create`). Title: `feat(asset): parse inlined skeletal LOD-0 streamed buffers (Phase 3h PR5a)`. PR body: the single-inlined-LOD scope, the skin-weight two-path fork, the deferred parts (PR5b: iteration/tail/non-inlined/remap; cloth/profiles>0/variable-bones if deferred). Monitor `gh pr checks`. **User merges.** No `.pak` fixtures.
- [ ] **Post-merge** — remove worktree + branch, sync main; PR5b gets a fresh worktree + writing-plans pass.

---

## Self-review notes (coverage)
- Oracle re-verification (order + index container + both skin paths + GUID/positions + bHasVertexColors + skips) → Task 1, per [[feedback_verify_wire_format_claims]]; wire-format reviewer re-derives in Task 11.
- FAnimObjectVersion + adjacency flag → Task 2. FMultisizeIndexContainer → Task 3. Skin-weight legacy → Task 4, new → Task 5. Orchestration + bHasVertexColors → Task 6; read_typed wiring → Task 7; hardening → Task 8; gates+mutants → Task 9; doc → Task 10; panel+PR → Task 11.
- Reuse: 3g `read_position_buffer`/`read_static_mesh_vertex_buffer`/`read_color_buffer` (positions/normals/tangents/uvs/colors), `read_bulk_array_header`, `ensure_bulk_count`, the SoA-length-check pattern from 3g `lod.rs`.
- Deferred to PR5b: multi-LOD iteration, the post-loop tail (dummyObjs + numInlinedLODs/numNonOptionalLODs + UV-channel skip), non-inlined FByteBulkData, bone-map LOD-local→global remap. To PR6: the glTF exporter. Limitations (Task-1-dependent): variable-bones decode, non-empty skin-weight profiles, UE5 u16 weights into `[u8;8]` — documented.
- **Deferred to PR5b — ray-tracing tail version gate (UNVERIFIED).** The item-10 ray-tracing tail is gated on `is_ue4_27_or_later()` (`file_version_ue4 ≥ 522`), but 522 covers BOTH UE4.26 and UE4.27, so the gate over-approximates: a 4.26 cooked mesh has no ray-tracing tail but would read one. Benign for PR5a's single inlined LOD[0] (a spurious tail read hits EOF → property-bag fallback, no silent corruption), but a **multi-LOD silent-misparse hazard** (a wrong tail read desyncs the cursor for the next LOD). PR5b MUST resolve this — the real `HasRayTracingData` serialization condition is likely a custom-version gate, not the object-version proxy.
