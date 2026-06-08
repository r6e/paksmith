# Phase 3h PR3 — `FSkelMeshSection` cooked reader — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax. Design: [`phase-3h-skeletalmesh-design.md`](phase-3h-skeletalmesh-design.md); wire ref: [`../formats/mesh/skeletal-mesh.md`](../formats/mesh/skeletal-mesh.md).

**Goal:** A standalone, unit-tested reader for one cooked `FSkelMeshSection` (the `SerializeRenderItem` render-section path — the path paksmith's editor-data-stripped cooked assets actually hit), plus the custom-version constants, caps, and error variants it needs. The `FStaticLODModel` wiring that calls it (strip flags + `Sections[]` + index buffer + active/required bones + `read_typed` integration) is PR4.

**Architecture:** A new `read_skel_mesh_section_render` in `asset/exports/mesh/skeletal_mesh.rs`, decoding the 18-field cooked render section. Attacker-controlled counts (bone_map, cloth nested arrays, dup-vert arrays) are capped before allocation/skip. The reader is `#[allow(dead_code)]` until PR4. Cloth + dup-vert data is consumed-not-stored (paksmith defers cloth).

**Tech Stack:** Rust; reuse `wire::{read_strip_data_flags, is_editor_data_stripped, read_bool32}`, `read::read_capped_count`, `package_index`/`read_fname_pair` (not needed here), `custom_version::version_for`, `byteorder` LE.

**PR-series re-split note (tell the user):** the design's PR3 bundled the whole `FStaticLODModel`. This plan scopes PR3 to the `FSkelMeshSection` reader only (it's the densest, most security-critical sub-unit). PR4 = `FStaticLODModel` wiring + `FMultisizeIndexContainer` + active/required bones + integration; PR5 = skin/vertex buffers + bone-map remap; PR6 = `GltfSkeletalMeshHandler`. **3h is now ~6 PRs.**

**KEY ORACLE FINDING (verified):** there are TWO `FSkelMeshSection` deserializers — the **editor** constructor (the 25-field list in the overview/format docs) and **`SerializeRenderItem`** (the cooked render path). `USkeletalMesh.Deserialize`'s `bCooked` branch, for editor-data-stripped content (paksmith's PR2-gated target), calls `FStaticLODModel.SerializeRenderItem → Sections[i].SerializeRenderItem`. So PR3 implements `SerializeRenderItem` (below). Task 9 corrects the docs.

**Cooked `SerializeRenderItem` field order (oracle-verified; bool32 = 4-byte int via `ReadBoolean`):**
1. `FStripDataFlags` → keep `(global, class)`. 2. `MaterialIndex` i16. 3. `BaseIndex` i32. 4. `NumTriangles` i32.
5. `bRecomputeTangent` bool32 **(unconditional)**. 6. `RecomputeTangentsVertexMaskChannel` u8 — gate `FRecomputeTangentCustomVersion ≥ RecomputeTangentVertexColorMask(2)`, else default 3 (`None`). 7. `bCastShadow` bool32 — gate `FEditorObjectVersion ≥ RefactorMeshEditorMaterials(8)`, else default `true`. 8. `bVisibleInRayTracing` bool32 — gate `FUE5MainStreamObjectVersion ≥ SkelMeshSectionVisibleInRayTracingFlagAdded(53)`, else default `true`. 9. `BaseVertexIndex` u32 **(unconditional)**.
10. `ClothMappingDataLODs` — `< FUE5ReleaseStreamObjectVersion::AddClothMappingLODBias(15)` → one inner `FMeshToMeshVertData[]`; else outer `[][]`. Each element = **64 bytes, skipped**.
11. `BoneMap` — i32 count + N×u16. 12. `NumVertices` i32 **(unconditional)**. 13. `MaxBoneInfluences` i32 **(unconditional)**. 14. `CorrespondClothAssetIndex` i16. 15. `ClothingData` = `FGuid(16)+i32(4)` = 20 bytes **(unconditional, consume)**.
16. `DupVertData` (i32 count + count×4, **skip**) + 17. `DupVertIndexData` (i32 count + count×8, **skip**) — gate `(file_version_ue4 < 517) OR !is_class_data_stripped(class, DUPLICATED_VERTICES=0x01)`. 18. `bDisabled` bool32 — gate `FReleaseObjectVersion ≥ AddSkeletalMeshSectionDisable(12)`, else `false`.

`FMeshToMeshVertData` is a constant **64 bytes** in BOTH `FReleaseObjectVersion` branches (only the last 8 bytes' meaning differs), so it is *skipped*, not parsed — no `WeightFMeshToMeshVertData` constant needed.

---

## File structure
- **Modify** `crates/paksmith-core/src/asset/custom_version.rs` — 4 new GUID consts + 4 position consts + pin tests.
- **Modify** `crates/paksmith-core/src/asset/wire.rs` — `is_class_data_stripped(class, flag)` + a `DUPLICATED_VERTICES`/class-flag const.
- **Modify** `crates/paksmith-core/src/asset/version.rs` — `is_ue4_23_or_later` helper IF absent (else reuse).
- **Modify** `crates/paksmith-core/src/asset/mod.rs` — extend `SkelMeshSection`; reconcile `SkeletalMeshLod.bone_map`.
- **Modify** `crates/paksmith-core/src/error.rs` — new `AssetParseFault` variants.
- **Modify** `crates/paksmith-core/src/asset/exports/mesh/skeletal_mesh.rs` — `read_skel_mesh_section_render` + caps + tests.
- **Modify** `docs/plans/phase-3h-skeletalmesh-export.md` + `docs/formats/mesh/skeletal-mesh.md` — editor-vs-cooked clarification.

All work in `.claude/worktrees/feat+phase-3h-lod-model/` (branch `feat/phase-3h-lod-model`).

---

## Task 1: Oracle re-verification (no code — record verified facts)

- [ ] **Step 1: Confirm the path + field order.** Re-fetch CUE4Parse `FSkelMeshSection.cs` (`SerializeRenderItem`) + `FStaticLODModel.cs` (`SerializeRenderItem`) + `USkeletalMesh.cs` @ `cf74fc32` (GitHub MCP). Confirm the control flow (bCooked + editor-data-stripped → `FStaticLODModel.SerializeRenderItem → Sections[i].SerializeRenderItem`) and the 18-field order above verbatim. Confirm `FMeshToMeshVertData` is 64 bytes both branches and `FClothingSectionData` = 20 bytes.
- [ ] **Step 2: Confirm GUID bytes + positions.** For each of `FRecomputeTangentCustomVersion`, `FUE5MainStreamObjectVersion`, `FUE5ReleaseStreamObjectVersion`, `FReleaseObjectVersion`: re-derive the 16 LE bytes from the `new FGuid(A,B,C,D)` words and the named member's 0-based ordinal (anchor against a named sibling; watch for `= N`). Expected (verify, don't trust): FRecomputeTangent GUID `0x5579F886,0x933A4C1F,0x83BA087B,0x6361B92F`, RecomputeTangentVertexColorMask=2; FUE5MainStream GUID `0x697DD581,0xE64F41AB,0xAA4A51EC,0xBEB7B628`, SkelMeshSectionVisibleInRayTracingFlagAdded=53 (between RayTracedShadowsType=52 and AnimGraphNodeTaggingAdded=54); FUE5ReleaseStream GUID `0xD89B5E42,0x24BD4D46,0x8412ACA8,0xDF641779`, AddClothMappingLODBias=15; FReleaseObject GUID `0x9C54D522,0xA8264FBE,0x94210746,0x61B482D0`, AddSkeletalMeshSectionDisable=12.
- [ ] **Step 3: Confirm the UE4.23 threshold + the DupVert class-strip bit.** Confirm `Game < UE4_23` maps to `file_version_ue4 < 517` (paksmith's `VER_UE4_GAME_UE4_23_OBJECT_PROXY = 517`; the doc says GAME_UE4_23 → FileVersionUE4 517) and check whether `version.rs` already has `is_ue4_23_or_later` (grep). Confirm the `IsClassDataStripped` flag value used for DuplicatedVertices is `1` (0x01).

No commit (verification only). If any value differs, the differing value supersedes the "expected" above in the later tasks.

---

## Task 2: New custom-version constants

**Files:** Modify `crates/paksmith-core/src/asset/custom_version.rs`

- [ ] **Step 1: Pin tests (failing).** Add a test asserting each new GUID's bytes + each position, using the Task-1 values. Mirror the existing `skeletal_material_gate_guids_and_positions` test shape.
- [ ] **Step 2: Run** `cargo test -p paksmith-core --all-features custom_version` → FAIL.
- [ ] **Step 3: Add the consts** (match existing GUID-const byte-array style + doc-cite-with-anchor):

```rust
pub const RECOMPUTE_TANGENT_CUSTOM_VERSION_GUID: FGuid = FGuid::from_bytes([ /* Task-1 LE bytes of 0x5579F886,0x933A4C1F,0x83BA087B,0x6361B92F */ ]);
pub const RECOMPUTE_TANGENT_VERTEX_COLOR_MASK: i32 = 2;
pub const UE5_MAIN_STREAM_OBJECT_VERSION_GUID: FGuid = FGuid::from_bytes([ /* 0x697DD581,0xE64F41AB,0xAA4A51EC,0xBEB7B628 */ ]);
pub const SKEL_MESH_SECTION_VISIBLE_IN_RAY_TRACING_FLAG_ADDED: i32 = 53;
pub const UE5_RELEASE_STREAM_OBJECT_VERSION_GUID: FGuid = FGuid::from_bytes([ /* 0xD89B5E42,0x24BD4D46,0x8412ACA8,0xDF641779 */ ]);
pub const ADD_CLOTH_MAPPING_LOD_BIAS: i32 = 15;
pub const RELEASE_OBJECT_VERSION_GUID: FGuid = FGuid::from_bytes([ /* 0x9C54D522,0xA8264FBE,0x94210746,0x61B482D0 */ ]);
pub const ADD_SKELETAL_MESH_SECTION_DISABLE: i32 = 12;
```
(Fill the byte arrays from Task 1, each commented `// A = 0x... (LE)` like the existing consts. Also add a position const for `FSkeletalMeshCustomVersion` if any of the unconditional-on-cooked fields turn out gated — per Task 1 they don't, so none needed here.)
- [ ] **Step 4: Run** → PASS. **Step 5: Commit** `feat(asset): custom-version GUIDs for FSkelMeshSection render gates (3h)`.

---

## Task 3: `is_class_data_stripped` helper + UE4.23 version helper

**Files:** Modify `crates/paksmith-core/src/asset/wire.rs` (+ `version.rs` if needed)

- [ ] **Step 1: Failing tests.**
```rust
#[test]
fn is_class_data_stripped_checks_the_given_bit() {
    assert!(is_class_data_stripped(0x01, 0x01));      // DuplicatedVertices set
    assert!(!is_class_data_stripped(0x00, 0x01));     // unset
    assert!(!is_class_data_stripped(0x02, 0x01));     // a different bit set → still unset for 0x01
    assert!(is_class_data_stripped(0x03, 0x01));      // bits 0+1
}
```
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** (mirror `is_editor_data_stripped`):
```rust
/// `FStripDataFlags::IsClassDataStripped(flag)` — true when `flag`'s bit is set
/// in the CLASS strip-flags byte (the 2nd element of [`read_strip_data_flags`]).
pub(crate) fn is_class_data_stripped(class: u8, flag: u8) -> bool {
    class & flag != 0
}
/// The `DuplicatedVertices` class-strip flag (gates the cooked section's
/// DupVertData/DupVertIndexData arrays).
pub(crate) const STRIP_FLAG_DUPLICATED_VERTICES: u8 = 0x01;
```
- [ ] **Step 4:** If `version.rs` lacks `is_ue4_23_or_later`, add it mirroring `is_ue4_20_or_later` (`self.file_version_ue4 >= VER_UE4_GAME_UE4_23_OBJECT_PROXY` (517)) + a pin test; else note the existing helper to use.
- [ ] **Step 5: Run** → PASS. **Step 6: Commit** `feat(asset): is_class_data_stripped + UE4.23 version helper (3h)`.

---

## Task 4: Extend `SkelMeshSection` + caps + error variants

**Files:** Modify `crates/paksmith-core/src/asset/mod.rs`, `crates/paksmith-core/src/error.rs`, and add the caps to `skeletal_mesh.rs`.

- [ ] **Step 1: Extend `SkelMeshSection`** (add to the existing PR1 struct; keep `#[non_exhaustive]` + derives):
```rust
    /// Per-section bone-index remap (LOD-local → skeleton). Authoritative
    /// per-section map; the LOD-level union is derivable.
    pub bone_map: Vec<u16>,
    /// Recompute-tangent-at-runtime flag.
    pub recompute_tangent: bool,
    /// Vertex-color channel driving runtime tangent recompute (UE default 3 = None).
    pub recompute_tangents_vertex_mask_channel: u8,
    pub cast_shadow: bool,
    pub visible_in_ray_tracing: bool,
    pub disabled: bool,
    /// Cloth-asset slot (`-1` when none).
    pub correspond_cloth_asset_index: i16,
```
(Keep `Default` derive working — all new fields are `Default`.) **Reconcile `SkeletalMeshLod.bone_map`:** the per-section `bone_map` is authoritative; keep the LOD-level `SkeletalMeshLod.bone_map` for PR4/PR5 to populate as the union (document: "union of section bone_maps; populated in PR4"). Update its doc comment accordingly. Add a test constructing a `SkelMeshSection` with the new fields.
- [ ] **Step 2: Error variants** in `error.rs` (match the hand-written `Display` style): `BoneMapCountExceeded { count: i64, cap: usize }`, `ClothLodBiasCountExceeded { count: i64, cap: usize }`, `ClothVertCountExceeded { count: i64, cap: usize }`, `DupVertCountExceeded { count: i64, cap: usize }`, `SectionInfluenceCountInvalid { count: i32, cap: usize }`, `SectionCountNegative { field: &'static str, count: i32 }` (generic negative-count for the section's i32 prefixes). Add `AssetWireField` variants for each read site (`SkelSectionMaterialIndex`, `SkelSectionBoneMapCount`, `SkelSectionClothLodCount`, `SkelSectionClothVertCount`, `SkelSectionDupVertCount`, `SkelSectionNumVertices`, `SkelSectionMaxBoneInfluences`, `SkelSectionClothingData`, ...). Add Display pin tests.
- [ ] **Step 3: Caps** (in `skeletal_mesh.rs`, with NOTE comments per the sibling no-`__test_utils`-accessor convention):
```rust
pub(crate) const MAX_BONE_MAP_ENTRIES_PER_SECTION: usize = MAX_BONES_PER_SKELETON; // 65_536
pub(crate) const MAX_CLOTH_LOD_BIAS_LEVELS: usize = 64;
pub(crate) const MAX_CLOTH_VERTS_PER_LOD: usize = 4_194_304;   // = MAX_VERTICES_PER_LOD-scale
pub(crate) const MAX_DUP_VERTS_PER_SECTION: usize = 4_194_304;
pub(crate) const MAX_INFLUENCES_PER_VERTEX: usize = 8;
```
(Reuse `MAX_BONES_PER_SKELETON` from skeleton.rs; if `MAX_VERTICES_PER_LOD` exists in `vertex_buffers.rs`, reuse its value or import. Pin each cap with a value test.)
- [ ] **Step 4: Commit** `feat(asset): extend SkelMeshSection + section caps + faults (3h)`.

---

## Task 5: `read_skel_mesh_section_render` — happy path

**Files:** Modify `crates/paksmith-core/src/asset/exports/mesh/skeletal_mesh.rs`

- [ ] **Step 1: Failing test (a minimal modern-UE5-cooked section).** Build a byte payload for one section with all gates ON (a ctx seeding `FRecomputeTangent≥2`, `FEditorObjectVersion≥8`, `FUE5MainStream≥53`, `FUE5ReleaseStream≥15`, `FReleaseObject≥12`, `file_version_ue4 ≥ 517`, and strip flags with `STRIP_FLAG_DUPLICATED_VERTICES` set so the dup arrays are skipped). Use a `section_ctx(...)` helper extending the PR2 `skel_custom_versions` to seed these 5 versions. Assert the decoded `SkelMeshSection` fields (material_index, base_index, num_triangles, recompute_tangent, recompute_tangents_vertex_mask_channel, cast_shadow, visible_in_ray_tracing, base_vertex_index, bone_map, num_vertices, max_bone_influences, correspond_cloth_asset_index, disabled) and **full byte consumption** (`cur.position() == bytes.len()`). Include 1 cloth LOD with 1 vert (64 bytes skipped) + an empty dup-vert pair (gate makes them skipped since class-stripped + ue4≥517 → NOT read; OR include them — pick the class-stripped path so dup arrays are absent, and a separate Task-6 test covers the present case).
- [ ] **Step 2: Run** → FAIL (fn undefined).
- [ ] **Step 3: Implement.** Signature `pub(crate) fn read_skel_mesh_section_render<R: Read + ?Sized>(r: &mut R, ctx: &AssetContext, asset_path: &str) -> crate::Result<SkelMeshSection>`. Read the 18 fields in order, each gate via `ctx.custom_versions.version_for(GUID).is_some_and(|v| v >= POS)`. Helpers:
  - bool32 via `wire::read_bool32`; u8/i16/i32/u32 via `byteorder` LE with `eof`-mapping (reuse the `read_i32_or_eof`/`eof` patterns already in skeleton.rs/skeletal_mesh.rs — extract a shared `read_u32_or_eof`/`read_i16_or_eof` if needed).
  - `bone_map`: `let n = read::read_capped_count(r, asset_path, AssetWireField::SkelSectionBoneMapCount, MAX_BONE_MAP_ENTRIES_PER_SECTION as u32)?;` then read N×u16 into a Vec.
  - `MaxBoneInfluences`: read i32, sign-check ≥ 0, cap ≤ `MAX_INFLUENCES_PER_VERTEX` → `SectionInfluenceCountInvalid`.
  - `NumVertices`: i32 sign-check ≥ 0.
  - `ClothingData`: skip 20 bytes (consume).
  - cloth/dup-vert: see Task 6 (skip helpers). For the happy path with the gate making dup absent, only the cloth skip runs.
  - skip helper: `fn skip_bytes<R: Read + ?Sized>(r: &mut R, n: u64, asset_path: &str, field: AssetWireField) -> crate::Result<()> { std::io::copy(&mut r.take(n), &mut std::io::sink()).map_err(...)?; ... verify n consumed }` (or read in a bounded buffer loop). Add it.
- [ ] **Step 4: Run** → PASS. **Step 5:** `#[allow(dead_code)]` + "wired by PR4" on `read_skel_mesh_section_render`. **Step 6: Commit** `feat(asset): FSkelMeshSection cooked render reader — happy path (3h)`.

---

## Task 6: Cloth + dup-vert consume paths + caps

**Files:** Modify `crates/paksmith-core/src/asset/exports/mesh/skeletal_mesh.rs`

- [ ] **Step 1: Cloth nested-array consume + caps.** Implement `ClothMappingDataLODs` per the gate:
  - `FUE5ReleaseStream < AddClothMappingLODBias(15)` → ONE inner array: `n = read_capped_count(.. MAX_CLOTH_VERTS_PER_LOD)`; skip `n * 64` bytes.
  - else → outer `m = read_capped_count(.. MAX_CLOTH_LOD_BIAS_LEVELS)`; for each, inner `n = read_capped_count(.. MAX_CLOTH_VERTS_PER_LOD)`; skip `n * 64` bytes.
  Use `checked_mul`/saturating for `n*64`. Tests: legacy-shape (single array) + new-shape (array-of-arrays); each consumes exactly `count*64 + prefixes`; an over-cap inner count → `ClothVertCountExceeded` before skipping; over-cap outer → `ClothLodBiasCountExceeded`.
- [ ] **Step 2: DupVert skip + gate + caps.** Implement fields 16-17 gated on `(!ctx.version.is_ue4_23_or_later()) || !wire::is_class_data_stripped(class, STRIP_FLAG_DUPLICATED_VERTICES)`: `dup = read_capped_count(.. MAX_DUP_VERTS_PER_SECTION)`; skip `dup*4`; `dupidx = read_capped_count(..)`; skip `dupidx*8`. Tests: (a) class-stripped + ue4≥517 → dup arrays NOT read (cursor doesn't advance for them); (b) NOT class-stripped → dup arrays read+skipped; (c) ue4<517 → read even when class-stripped; (d) over-cap dup count → `DupVertCountExceeded`.
- [ ] **Step 3: Commit** `feat(asset): cloth + dup-vert consume paths + caps (3h)`.

---

## Task 7: Gate + sign-check hardening

**Files:** Modify `crates/paksmith-core/src/asset/exports/mesh/skeletal_mesh.rs` (tests + any guard fixes)

Each gate must be pinned with an adjacent OFF/ON boundary pair (per the project gate-coverage standard, so cargo-mutants kills the `>=`→`>` mutant):
- [ ] `RecomputeTangentVertexColorMask` gate: version 1 (off → field absent, default 3) vs 2 (on → u8 read). Assert byte consumption differs.
- [ ] `RefactorMeshEditorMaterials` (bCastShadow): 7 vs 8.
- [ ] `SkelMeshSectionVisibleInRayTracingFlagAdded` (bVisibleInRayTracing): 52 vs 53.
- [ ] `AddSkeletalMeshSectionDisable` (bDisabled): 11 vs 12.
- [ ] `AddClothMappingLODBias` (cloth shape): 14 (single array) vs 15 (array-of-arrays).
- [ ] Sign-checks: negative bone_map count → `BoneMapCountExceeded`/`SectionCountNegative`; negative NumVertices → negative fault; negative/over-8 MaxBoneInfluences → `SectionInfluenceCountInvalid`.
- [ ] Truncation mid-section → typed `Err`, no panic.
- [ ] **Commit** `test(asset): FSkelMeshSection gate + sign-check hardening (3h)`.

---

## Task 8: Gate chain + in-diff cargo-mutants

- [ ] **Step 1:** `cargo fmt --all`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`; `cargo test --workspace --all-features`; `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features`; `typos .`; `cargo deny check` — all green.
- [ ] **Step 2:** `git diff origin/main -- > /tmp/pr_3h3.diff && cargo mutants --in-diff /tmp/pr_3h3.diff --no-shuffle -j 4 --all-features` → **0 missed, 0 timeout**. Pin survivors (the gate `>=` boundaries, the caps `>`, the `n*64`/`*4`/`*8` multipliers, the dup-gate `||`/`!`) with literal-value tests; reformulate any equivalent mutant to a literal.
- [ ] **Step 3:** Commit any pins.

---

## Task 9: Doc correction (editor vs cooked FSkelMeshSection)

**Files:** Modify `docs/plans/phase-3h-skeletalmesh-export.md`, `docs/formats/mesh/skeletal-mesh.md`

- [ ] **Step 1:** In both docs, relabel the 25-field `FSkelMeshSection` table as the **editor `FSkeletalMeshLODModel` constructor** path, and add a section documenting the **cooked `SerializeRenderItem`** 18-field path (the one paksmith implements), noting: `bRecomputeTangent`/`BaseVertexIndex`/`NumVertices`/`MaxBoneInfluences`/`ClothingData` are unconditional on the cooked path; the `DupVertData`/`DupVertIndexData` skip pair (gated on `Game<UE4.23 || !IsClassDataStripped(DuplicatedVertices)`); cloth as nested `FMeshToMeshVertData[][]` (64-byte elements); and that the editor-only fields (SoftVertices, OverlappingVertices, GenerateUpToLodIndex, etc.) do NOT appear on the cooked path. Keep citations CUE4Parse-only.
- [ ] **Step 2:** `typos docs/`. **Step 3: Commit** `docs(mesh): document cooked FSkelMeshSection SerializeRenderItem path (3h)`.

---

## Task 10: Review panel to convergence, then PR

- [ ] **Step 1: ≥5-reviewer panel** on `git diff main..HEAD`: **wire-format** (the 18-field order + the 4 GUIDs/positions + cloth/dup sizes + the dup-vert UE4.23/class-strip gate vs oracle — MANDATORY; independently re-derive ≥1 GUID + the path), **security** (every count capped before alloc/skip; `n*64`/`*4`/`*8` no-overflow; no panic on truncation; the skip helpers bounded — MANDATORY), **deep-impact** (the `SkelMeshSection` struct growth + the 4 new pub custom-version consts + the `SkeletalMeshLod.bone_map` reconciliation + PR4 seam — MANDATORY), **code-reviewer**, **simplifier**. Brief adversarially (conf ≥ 70, hunt cold). Re-run the FULL panel each fix round to convergence.
- [ ] **Step 2: Push + PR.** Marker at the worktree git-dir (SEPARATE call from push; another before `gh pr create`). Title: `feat(asset): add FSkelMeshSection cooked render-section reader (Phase 3h PR3)`. Monitor `gh pr checks`. **User merges.** No `.pak` fixtures.
- [ ] **Step 3: Post-merge** — remove worktree + branch, sync main; PR4 (`FStaticLODModel` wiring) gets a fresh worktree + writing-plans pass.

---

## Self-review notes (coverage)
- Oracle re-verification (path + 18 fields + GUIDs/positions + sizes + UE4.23 threshold) → Task 1, per [[feedback_verify_wire_format_claims]].
- 4 new custom-version consts → Task 2. `is_class_data_stripped` + UE4.23 helper → Task 3. `SkelMeshSection` extension + caps + faults → Task 4. The 18-field reader (happy path) → Task 5; cloth/dup-vert consume + caps → Task 6; gate/sign-check hardening → Task 7. Gates + 0-missed mutants → Task 8. Doc correction (editor vs cooked) → Task 9. Panel + PR → Task 10.
- `FMeshToMeshVertData` consumed as a constant 64 bytes (no Weight gate needed). Cloth/dup data consumed-not-stored. Reader `#[allow(dead_code)]` until PR4. Reuses `read_capped_count`, `wire::read_bool32`, the strip-flag helpers.
- Deferred (documented): `FStaticLODModel` wiring + `FMultisizeIndexContainer` + active/required bones + `read_typed` integration → PR4; skin/vertex buffers + bone-map remap → PR5; exporter → PR6.
