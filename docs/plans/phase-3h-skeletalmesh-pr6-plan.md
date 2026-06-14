# Phase 3h PR6 — `GltfSkeletalMeshHandler` (skinned glTF export) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Export a parsed `Asset::SkeletalMesh` as a skinned glTF 2.0 binary (`.glb`) — bone hierarchy, skin, inverse-bind-matrices, and per-vertex JOINTS/WEIGHTS — that opens in Blender in its **bind pose**.

**Architecture:** Extract the private 3g2 glTF primitives from `static_mesh.rs` into a `pub(crate)` `export/gltf_common.rs` (zero behavior change, guarded by the existing static-mesh tests), then add `GltfSkeletalMeshHandler` on top: bone nodes + skin + IBM via a UE→glTF **change-of-basis conjugation** (so the skin stays aligned with 3g2's baked-`B` geometry), plus the LOD-local→global **bone-map remap at emit**.

**Tech Stack:** Rust (edition 2024, MSRV 1.88), `gltf` 1.4.1 (write via `gltf::json` + `gltf::binary::Glb`), **new dep `glam`** (f64 `DMat4`/`DQuat`/`DVec3` for the bind-matrix compose+invert), `serde_json`.

---

## PR-series

PR1 (#543) + PR2 (#544) + PR3 (#546) + PR4 (#547) + PR5a (#551) + PR5b (#552) + PR5c (#553) **MERGED** — the skeletal-mesh **parser is complete**. Off-by-one (#545) MERGED. The exporter-numbering renumber (PR7→PR6) is docs PR #554 (open; this branch is off pre-#554 `main`, so rebase onto `main` before finalizing — see Task 12). **PR6 (this) = the `GltfSkeletalMeshHandler` — the final 3h PR.** Scope decision (user-confirmed): extraction **+** handler in **one** PR.

## Critical correctness facts (locked — verified by derivation + the advisor, NOT by the wire oracle)

glTF *emission* is **not** a wire format — do **not** byte-match CUE4Parse/SharpGLTF matrices. Verification is the numerical **bind-pose-identity test** (Task 6) + `gltf-validator` when present.

- **Change-of-basis `B`:** 3g2's `convert_position(v) = [v.x, v.z, v.y] * 0.01` is the linear map `B = 0.01·P`, where `P` swaps the Y and Z axes (`P = Pᵀ = P⁻¹`, `det P = −1`) and `0.01` is cm→m. As a 4×4 affine: linear part `0.01·P3`, no translation. `B⁻¹` has linear part `100·P3`.
- **Per-bone transforms:** `L_i` = bone `i`'s `FTransform` (`rotation`,`translation`,`scale_3d`) as a 4×4 (UE space). Global bind `G_i = G_parent(i) · L_i` (root: `G_i = L_i`).
- **Emit (the whole skinning result hinges on these two lines):**
  - bone node **local** matrix = `B · L_i · B⁻¹` (telescopes → node-global = `B · G_i · B⁻¹`)
  - `IBM_i = (B · G_i · B⁻¹)⁻¹ = B · G_i⁻¹ · B⁻¹`
  - ⇒ `jointGlobal_i · IBM_i = I` in bind pose, so a vertex emitted at `B·v` (3g2 geometry) skins to `B·v`. Bone `i`'s origin lands at `0.01·P·t_i = convert_position(t_i)` — joints coincide with the geometry.
- **The skinned mesh node MUST be identity-transformed.** glTF skinning is `inverse(meshNodeGlobal)·jointGlobal·IBM`; `jointGlobal·IBM = I` only collapses correctly when `meshNodeGlobal = I`. Keep the mesh+skin node at scene root with no transform (3g2's `..Node::default()` is already identity) — never parent it under a transformed node.
- **`node.matrix` validity:** the linear part of `B·L·B⁻¹` is `(P·R·P)·(P·S·P)` = proper-rotation · positive-diagonal-scale → TRS-decomposable, no shear. Emit `node.matrix` (column-major `[f32;16]`, glam `to_cols_array()`); both `node.matrix` and MAT4 accessors are column-major.
- **Weights:** glTF requires per-vertex `Σ WEIGHTS ≈ 1.0` (gltf-validator: a bad sum is an **error**). UE u8 weights sum to 255 for present influences (zero padding OK). **Policy: renormalize each vertex's emitted u8 weights to sum exactly 255** (fold the residual into the largest weight); a vertex with sum 0 (degenerate/unskinned) → bind 100% to joint 0 `(255,0,0,0)` (renders at rest since `jointMatrix·IBM = I`). Emit `WEIGHTS_*` with `normalized: true`, `JOINTS_*` with `normalized: false`.
- **Bone-map remap:** per-vertex `bone_indices[v][i]` index into the **owning section's** `bone_map` (the section whose `[base_vertex_index, base_vertex_index+num_vertices)` contains `v`), NOT the LOD-union `bone_map`. `JOINTS` value = `section.bone_map[bone_indices[v][i]]` = global skeleton index. `skin.joints[k]` = node for skeleton bone `k` (skeleton order) ⇒ a JOINTS value is the global bone index directly; `IBM` accessor index `k` aligns with `skin.joints[k]`. Default every vertex to `JOINTS=[0,0,0,0]/WEIGHTS=[255,0,0,0]` (root, rest) then overwrite per section — so vertices outside all sections stay glTF-valid.
- **>4 influences:** emit `JOINTS_1`/`WEIGHTS_1` only when any vertex in the LOD uses influence slots 4..8 (i.e. `max_bone_influences > 4` across sections); otherwise omit (keep the common 4-influence file minimal).
- **JOINTS component type:** `UNSIGNED_SHORT` (VEC4) when `skeleton.bones.len() > 256`, else `UNSIGNED_BYTE`. (Indices are into `skin.joints`, length = bone count.)

## Caps / OOB (security — every per-vertex/bone value is attacker-influenced; checked before any `with_capacity`)

- `MAX_BONES_PER_SKELETON = 65_536`, `MAX_SKELETAL_LODS_PER_MESH = 8`, `MAX_INFLUENCES_PER_VERTEX = 8` (reuse existing parser caps where present — grep first; only add what's missing, pinned via error-path tests, no `__test_utils` accessor).
- OOB sites (export time, fail-fast → typed `Result`, never panic): `bone_indices[v][i] < section.bone_map.len()`; `section.bone_map[..] < skeleton.bones.len()`; `skeleton.bones.len() == skeleton.bind_pose.len()`; `parent_index ∈ {−1} ∪ [0, bones.len())` and `< i` (no forward/cyclic parent) for the parent-chain walk; reuse 3g2's `enforce_export_cap` / finiteness pattern for positions. New fault variants only if no existing one fits (`BoneIndexOob`, `BoneMapOob`, `SkeletonBoneCountExceeded`, `SkeletonMalformed` — name against the live `error.rs` enum at TDD kickoff; some may already exist from the parser PRs).

---

## Task 1: Add the `glam` dependency

**Files:**
- Modify: `Cargo.toml` (workspace `[workspace.dependencies]`)
- Modify: `crates/paksmith-core/Cargo.toml` (`[dependencies]`)

- [ ] **Step 1: Add to the workspace dependency table.** In the root `Cargo.toml`, alongside the other pinned deps:

```toml
glam = { version = "0.30", default-features = false, features = ["std"] }
```

(Pin to the latest 0.30.x that satisfies MSRV 1.88 — verify with `cargo update -p glam --dry-run` / check `glam`'s `rust-version`. If 0.30 needs >1.88, step down to the highest 0.2x that builds on 1.88. `std` feature on, no `scalar-math`/`debug-glam-assert` extras.)

- [ ] **Step 2: Reference it from paksmith-core.** In `crates/paksmith-core/Cargo.toml` `[dependencies]`:

```toml
glam.workspace = true
```

- [ ] **Step 3: cargo-deny + MSRV.** Run `cargo deny check` (glam is MIT/Apache-2.0, crates.io — no `allow-git`/`version=` dance needed; if `[bans]` flags a duplicate transitive `glam`, note it). Then confirm the MSRV build: `cargo +1.88 build -p paksmith-core` (or the repo's MSRV harness). Expected: both green.

- [ ] **Step 4: Commit.** `chore(export): add glam dependency for skeletal bind-matrix math`.

## Task 2: Extract the shared glTF primitives into `export/gltf_common.rs`

**Files:**
- Create: `crates/paksmith-core/src/export/gltf_common.rs`
- Modify: `crates/paksmith-core/src/export/mod.rs` (add `mod gltf_common;`)
- Modify: `crates/paksmith-core/src/export/static_mesh.rs` (import from `gltf_common`, delete the moved items)

**Pure refactor — ZERO behavior change. The existing `static_mesh.rs` tests are the guard: they must pass unchanged with no edits to their bodies.**

- [ ] **Step 1: Move the primitives.** Cut from `static_mesh.rs` into `gltf_common.rs`, each made `pub(crate)`: `struct GltfDoc` + its `new`/`align_to_4`/`push_accessor`/`into_parts`; `fn finish_glb`; `fn encode_f32_le`; `fn convert_position`; `fn normalize_xyz`; `fn convert_dir`; `fn convert_tangent`; `fn reverse_winding`; `const UE_CM_TO_M`; `const MAX_GLB_BIN_BYTES`. Keep `MAX_MESH_MATERIALS`, `build_materials`, `push_primitives`, `enforce_export_cap`, `positions_all_finite` and all static-mesh-specific code in `static_mesh.rs`. Re-export nothing publicly (these stay `pub(crate)`).

- [ ] **Step 2: Wire imports.** Add `mod gltf_common;` to `export/mod.rs`. In `static_mesh.rs`, `use crate::export::gltf_common::{GltfDoc, finish_glb, encode_f32_le, convert_position, convert_dir, convert_tangent, reverse_winding, MAX_GLB_BIN_BYTES};` (and `normalize_xyz`/`UE_CM_TO_M` if referenced there). Move any unit tests that test ONLY a moved primitive (e.g. a `reverse_winding` test) into `gltf_common.rs`; leave integration-style export tests in `static_mesh.rs`.

- [ ] **Step 2.5: Confirm `push_accessor` visibility suffices.** `GltfDoc::push_accessor` + its `root`/`bin` fields are used by both modules — fields stay private to `gltf_common`; expose only the methods needed (`new`, `push_accessor`, `into_parts`, and a `pub(crate) fn root_mut(&mut self) -> &mut gltf::json::Root` if `static_mesh.rs`/the new handler push nodes/meshes/materials directly via `doc.root.push(...)`). Prefer a thin accessor over making `root` public.

- [ ] **Step 3: Build + test.** Run `cargo test -p paksmith-core --all-features export::static_mesh` — expected: every pre-existing static-mesh test PASSES unchanged. Then `cargo clippy -p paksmith-core --all-targets --all-features -- -D warnings`.

- [ ] **Step 4: Commit.** `refactor(export): extract shared glTF primitives into gltf_common`.

## Task 3: `gltf_common` skin/joint/weight accessor helpers

**Files:**
- Modify: `crates/paksmith-core/src/export/gltf_common.rs`
- Test: in-module `#[cfg(test)]`

Add `pub(crate)` accessor helpers (mirroring `push_accessor` conventions) so the handler stays thin:

- [ ] **Step 1: Failing tests** for: `push_joints(doc, &[[u16;4]], use_short: bool)` → VEC4 accessor, componentType `UNSIGNED_SHORT` iff `use_short` else `UNSIGNED_BYTE`, `normalized:false`, `target: ArrayBuffer`, correct count; `push_weights(doc, &[[u8;4]])` → VEC4 `UNSIGNED_BYTE`, `normalized:true`; `push_mat4(doc, &[[f32;16]])` → MAT4 `F32`, `normalized:false`, `target:None` (IBM accessors have no buffer target). Assert componentType/type/normalized/count by parsing back via `into_parts()` + inspecting `root.accessors`.

- [ ] **Step 2: Implement** the three helpers using `encode_*` + `push_accessor`. `[u16;4]` → little-endian u16 bytes; `[u8;4]` → raw bytes; `[f32;16]` → `encode_f32_le`. (4-influence VEC4 only here; the `_1` overflow attributes reuse the same helpers.)

- [ ] **Step 3: Run tests** (`cargo test -p paksmith-core --all-features gltf_common`) → PASS. **Step 4: Commit** `feat(export): add glTF skin/weight/mat4 accessor helpers`.

## Task 4: The basis change-of-basis matrix + `FTransform`→glam helpers

**Files:**
- Create: `crates/paksmith-core/src/export/skeletal_mesh.rs`
- Modify: `crates/paksmith-core/src/export/mod.rs` (`mod skeletal_mesh;`)
- Test: in-module `#[cfg(test)]`

- [ ] **Step 1: Failing tests** for the basis helpers:
  - `ue_to_gltf_basis() -> glam::DMat4` returns `B`: assert `B.transform_point3(DVec3::new(x,y,z)) == DVec3::new(x*0.01, z*0.01, y*0.01)` for a sample point, and that `(B * B.inverse())` ≈ identity.
  - `ftransform_to_dmat4(&FTransform) -> glam::DMat4` composes T·R·S: for a known FTransform assert `m.transform_point3(p)` equals the hand-computed `R*(S*p)+T` (quaternion from `DQuat::from_xyzw(rot.x,rot.y,rot.z,rot.w)`).

- [ ] **Step 2: Implement.**

```rust
use glam::{DMat4, DQuat, DVec3};
use crate::asset::structs::transform::FTransform;

/// `B = 0.01·P` (cm→m + UE Z-up LH → glTF Y-up RH axis swap), matching
/// `gltf_common::convert_position`. Column-major DMat4.
pub(crate) fn ue_to_gltf_basis() -> DMat4 {
    // Maps (x,y,z) -> 0.01*(x, z, y). Columns are images of the basis vectors.
    DMat4::from_cols(
        DVec3::new(0.01, 0.0, 0.0).extend(0.0), // e_x -> (0.01, 0, 0)
        DVec3::new(0.0, 0.0, 0.01).extend(0.0), // e_y -> (0, 0, 0.01)  (y -> 3rd glTF axis)
        DVec3::new(0.0, 0.01, 0.0).extend(0.0), // e_z -> (0, 0.01, 0)  (z -> 2nd glTF axis)
        glam::DVec4::new(0.0, 0.0, 0.0, 1.0),
    )
}

pub(crate) fn ftransform_to_dmat4(t: &FTransform) -> DMat4 {
    let rot = DQuat::from_xyzw(t.rotation.x, t.rotation.y, t.rotation.z, t.rotation.w)
        .normalize(); // guard against denormalized wire quats
    DMat4::from_scale_rotation_translation(
        DVec3::new(t.scale_3d.x, t.scale_3d.y, t.scale_3d.z),
        rot,
        DVec3::new(t.translation.x, t.translation.y, t.translation.z),
    )
}
```

  Verify the column mapping against `convert_position` numerically in the test (this is the single most error-prone line — a wrong column = a silently rotated skeleton).

- [ ] **Step 3: Run tests** → PASS. **Step 4: Commit** `feat(export): add UE→glTF basis + FTransform→DMat4 helpers`.

## Task 5: Bone nodes + skin (joints) + the skeleton hierarchy

**Files:**
- Modify: `crates/paksmith-core/src/export/skeletal_mesh.rs`

- [ ] **Step 1: Failing test** `builds_one_node_per_bone_with_skin`: a 3-bone skeleton (root → child → grandchild, each a distinct `FTransform`); call the (to-be-written) `build_skeleton(doc, &skeleton) -> SkeletonOut { joints: Vec<Index<Node>>, skin: Index<Skin>, root_nodes: Vec<Index<Node>> }`; export via `into_parts()`; assert `root.nodes.len() >= 3`, each non-root bone appears in exactly one parent's `children`, `root.skins[0].joints.len() == 3`, and `skin.inverse_bind_matrices` is `Some` (filled in Task 6 — here assert the accessor exists with count 3).

- [ ] **Step 2: Implement** `build_skeleton`:
  - Validate: `bones.len() == bind_pose.len()`, `bones.len() <= MAX_BONES_PER_SKELETON`, every `parent_index ∈ {−1} ∪ [0, i)` (parents precede children — UE ref skeletons are topologically ordered root-first; reject otherwise → `SkeletonMalformed`).
  - Create one `gltf::json::Node` per bone (skeleton order) with `name: Some(bone.name)`, `matrix: Some((B * L_i * B_inv).to_cols_array().map(|x| x as f32))` where `L_i = ftransform_to_dmat4(&bind_pose[i])`. Store the `Index<Node>` in `joints[i]`.
  - Second pass: for each bone with `parent_index >= 0`, push `joints[i]` into `joints[parent].children`. (Build children vecs separately then assign, to avoid borrow issues.)
  - `root_nodes` = nodes whose `parent_index == -1`.
  - Push a `gltf::json::Skin { joints: joints.clone(), inverse_bind_matrices: Some(<Task 6 accessor>), skeleton: Some(first root), ... }`. (Wire the IBM accessor in Task 6; here a placeholder MAT4 of identities keeps the test honest about shape.)

- [ ] **Step 3: Run test** → PASS. **Step 4: Commit** `feat(export): build glTF bone nodes + skin joints`.

## Task 6: Inverse-bind-matrices + the BIND-POSE-IDENTITY gating test (the real verification)

**Files:**
- Modify: `crates/paksmith-core/src/export/skeletal_mesh.rs`

- [ ] **Step 1: THE gating failing test** `bind_pose_skins_to_identity` — **this is the test that proves the basis math; write it first and make it strict:**
  - Skeleton: root → child → grandchild, where **at least one bone has a non-axis-aligned rotation (e.g. 37° about (1,1,0)-normalized) AND non-uniform scale (e.g. (2.0, 0.5, 1.5)) AND non-zero translation** (a pure-translation bone would pass even with a transposed rotation — useless).
  - Build the full handler output for a tiny mesh: a few vertices each bound 100% to one specific bone (`WEIGHTS=[255,0,0,0]`, `JOINTS=[k,0,0,0]`), positions arbitrary finite.
  - Export to `.glb`; parse back with the `gltf` crate. Walk the node tree to recompose each joint's **global** matrix `jointGlobal[k]` (product of `node.matrix` down the parent chain). Read the `IBM[k]` from the inverseBindMatrices accessor.
  - Assert `jointGlobal[k] · IBM[k] ≈ I` (per-element abs diff < 1e-4) for every bone.
  - Assert, for each test vertex `v` bound to bone `k`: `jointGlobal[k] · IBM[k] · (convert_position(v_ue) as homogeneous) ≈ convert_position(v_ue)` (skins to its emitted rest position).

- [ ] **Step 2: Implement** `inverse_bind_matrices(skeleton) -> Vec<[f32;16]>`:

```rust
let b = ue_to_gltf_basis();
let b_inv = b.inverse();
// global bind per bone (parents precede children → single forward pass)
let mut global: Vec<DMat4> = Vec::with_capacity(skeleton.bones.len());
for (i, bone) in skeleton.bones.iter().enumerate() {
    let local = ftransform_to_dmat4(&skeleton.bind_pose[i]);
    let g = if bone.parent_index < 0 {
        local
    } else {
        global[bone.parent_index as usize] * local // parent_index < i guaranteed
    };
    global.push(g);
}
// IBM_i = (B · G_i · B⁻¹)⁻¹ = B · G_i⁻¹ · B⁻¹
global.iter()
    .map(|g| (b * *g * b_inv).inverse().to_cols_array().map(|x| x as f32))
    .collect()
```

  Wire the resulting MAT4 accessor (Task 3 `push_mat4`) into `skin.inverse_bind_matrices` (replace the Task 5 placeholder). Confirm bone `node.matrix` uses `B · L_i · B⁻¹` (Task 5) so node-global telescopes to `B · G_i · B⁻¹`, making `jointGlobal·IBM=I`.

- [ ] **Step 3: Run the gating test** → PASS. If it fails, the bug is in the column mapping of `B` (Task 4), the `node.matrix` conjugation (Task 5), or column/row-major — do NOT weaken the test tolerance to pass. **Step 4: Commit** `feat(export): compute inverse-bind-matrices via basis conjugation`.

## Task 7: Per-vertex JOINTS/WEIGHTS with bone-map remap + weight renormalization

**Files:**
- Modify: `crates/paksmith-core/src/export/skeletal_mesh.rs`

- [ ] **Step 1: Failing tests:**
  - `remaps_bone_indices_via_section_bone_map`: two sections with distinct `bone_map`s + distinct vertex ranges; assert a vertex in section 1 maps `bone_indices[v][i]` through **section 1's** map (not section 0's, not the LOD union).
  - `renormalizes_weights_to_255`: a vertex with raw influences summing to 254 and one to 256 → emitted weights each sum to exactly 255; `weights_sum_zero_binds_to_joint0`: a vertex with all-zero weights → `(255,0,0,0)`, joint 0.
  - `vertex_outside_all_sections_defaults_to_root`: a position-buffer vertex covered by no section → `JOINTS=[0,0,0,0]/WEIGHTS=[255,0,0,0]`.
  - `bone_index_oob_errors` / `bone_map_oob_errors`: `bone_indices[v][i] >= section.bone_map.len()` and `section.bone_map[x] >= skeleton.bones.len()` each → typed `Result::Err` (no panic).

- [ ] **Step 2: Implement** `build_skin_attributes(lod, skeleton) -> Result<SkinAttrs>` where `SkinAttrs { joints0: Vec<[u16;4]>, weights0: Vec<[u8;4]>, joints1: Option<Vec<[u16;4]>>, weights1: Option<Vec<[u8;4]>> }`:
  - Init every vertex to `joints0=[0,0,0,0]`, `weights0=[255,0,0,0]` (root/rest default), `_1=[0;4]/[0;4]`.
  - Build a per-vertex→section index (iterate sections, mark `[base_vertex_index, base_vertex_index+num_vertices)`; bounds-check the range against `positions.len()`).
  - For each section's vertices: for `i in 0..8`, `let local = lod.bone_indices[v][i]`; if the slot's weight is 0 skip; check `local < section.bone_map.len()` (→ `BoneIndexOob`); `let global = section.bone_map[local]`; check `(global as usize) < skeleton.bones.len()` (→ `BoneMapOob`); place `global` into `joints0`/`joints1` slot `i` (i<4 → 0, else 1) and the weight into `weights0`/`weights1`.
  - Renormalize each vertex: sum the 8 emitted weights; if `sum == 0` → set `(255,0,0,0)` joint-0; else fold `255 - sum` (as i32) into the largest-weight slot (saturating to `[0,255]`); assert the final sum is 255.
  - Set `joints1`/`weights1` to `Some(..)` only if any vertex used slot ≥4 (else `None`).

- [ ] **Step 3: Run tests** → PASS. **Step 4: Commit** `feat(export): remap + renormalize per-vertex skin attributes`.

## Task 8: The `GltfSkeletalMeshHandler` `FormatHandler` + registry wiring

**Files:**
- Modify: `crates/paksmith-core/src/export/skeletal_mesh.rs`
- Modify: `crates/paksmith-core/src/export/mod.rs` (registry + `pub use`)

- [ ] **Step 1: Failing tests:**
  - `registry_selects_skeletal_handler`: `HandlerRegistry::all_default_handlers().find_handler(&Asset::SkeletalMesh(data_with_lods))` returns a handler whose `output_extension()=="glb"`; `supports` is `false` for an empty-lods `SkeletalMeshData` (degrade) and `true` with ≥1 non-empty LOD.
  - `exports_minimal_skinned_glb`: a 5-bone skeleton + single-LOD single-section skinned tri → `export` returns bytes starting `b"glTF"`, parses via `gltf::Glb::from_slice`, has 1 skin, `nodes` ≥ bones+1 (bones + mesh node), the mesh primitive has `JOINTS_0`+`WEIGHTS_0`, and the mesh node has `skin: Some`.

- [ ] **Step 2: Implement** the handler:

```rust
#[derive(Debug, Default, Clone, Copy)]
pub struct GltfSkeletalMeshHandler;

impl FormatHandler for GltfSkeletalMeshHandler {
    fn output_extension(&self) -> &'static str { "glb" }
    fn supports(&self, asset: &Asset) -> bool {
        matches!(asset, Asset::SkeletalMesh(d) if d.lods.iter().any(|l| !l.positions.is_empty()))
    }
    fn export(&self, asset: &Asset, _bulk: &[BulkData]) -> crate::Result<Vec<u8>> {
        let Asset::SkeletalMesh(data) = asset else { /* Internal err */ };
        // 1. caps: data.lods.len() <= MAX_SKELETAL_LODS_PER_MESH; reuse the 3g2
        //    aggregate-output cap pattern over positions+indices; reject non-finite
        //    converted positions (mirror positions_all_finite).
        // 2. build_skeleton(doc, &data.skeleton) -> joints/skin (Task 5/6).
        // 3. per LOD with non-empty positions: push position/normal/tangent/uv/color
        //    accessors (REUSE the 3g2 push_primitives lowering — extract the shared
        //    vertex-attribute part into gltf_common if push_primitives is static-mesh
        //    -shaped; otherwise replicate the position/normal/tangent/uv/color calls),
        //    + build_skin_attributes -> JOINTS_0/WEIGHTS_0(+_1) accessors merged into
        //    each primitive's attribute map. Index buffer via the same reverse_winding
        //    path. material slots via a skeletal build_materials (data.materials.len()).
        // 4. one mesh node per LOD (IDENTITY transform) carrying mesh + skin = Some(skin).
        //    Scene = mesh nodes + skeleton root nodes.
        // 5. into_parts + finish_glb.
    }
}
```

  - **Note on `push_primitives` reuse:** if `static_mesh::push_primitives` is tightly coupled to `StaticMeshLod`, extract its vertex-attribute lowering (position/normal/tangent/uv/color → accessor indices) into a `gltf_common` helper taking slices, and have BOTH handlers call it (DRY). Keep index/material specifics per-handler. Decide at implementation; do not duplicate the position/normal/tangent encode logic.

- [ ] **Step 3: Register.** In `export/mod.rs::all_default_handlers()`:

```rust
let skel_sentinel = Asset::SkeletalMesh(crate::asset::SkeletalMeshData::empty());
reg.register(std::mem::discriminant(&skel_sentinel), Box::new(skeletal_mesh::GltfSkeletalMeshHandler));
```

  and `pub use skeletal_mesh::GltfSkeletalMeshHandler;`.

- [ ] **Step 4: Run tests** → PASS. **Step 5: Commit** `feat(export): add GltfSkeletalMeshHandler + registry wiring`.

## Task 9: Hardening + the 8-influence + multi-section + multi-LOD coverage

**Files:**
- Modify: `crates/paksmith-core/src/export/skeletal_mesh.rs`

- [ ] **Step 1:** Add tests (then make them pass / confirm they already do): 8-influence mesh emits `JOINTS_1`+`WEIGHTS_1` with correct split; a >256-bone skeleton uses `UNSIGNED_SHORT` JOINTS (and ≤256 uses `UNSIGNED_BYTE`); multi-section single-LOD remaps each section independently; multi-LOD emits one mesh+node per non-empty LOD all referencing the one skin; the LOD/bone caps each fire a typed error (literal-value pins). A `gltf-validator` round-trip behind `#[cfg(feature=...)]`/an env probe if the repo already has that harness (else skip — the bind-pose-identity test + the `gltf` reader round-trip are the gates).

- [ ] **Step 2:** Fix any gaps. **Step 3: Commit** `test(export): cover 8-influence / multi-section / multi-LOD / caps`.

## Task 10: Gates + in-diff cargo-mutants

- [ ] **Step 1:** Full chain — `cargo fmt --all`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`; `cargo test --workspace --all-features`; `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features`; `typos .`; `cargo deny check`. (Run cargo gates unpiped or with `pipefail` — `| tail` masks exit codes.)
- [ ] **Step 2:** `cargo mutants -p paksmith-core --file crates/paksmith-core/src/export/skeletal_mesh.rs --file crates/paksmith-core/src/export/gltf_common.rs --all-features` → **0 missed / 0 timeout**. Accessor-style + the renormalize/remap arithmetic are prime mutant sites — add pin-tests for any survivor (e.g. the `255 - sum` fold, the `i<4` slot split, the `> 256` component-type boundary, the `B` column values). **Step 3: Commit** any test additions.

## Task 11: Docs

**Files:**
- Modify: `docs/formats/mesh/skeletal-mesh.md` (add/extend an Export section: the glTF skin mapping — bone nodes, the basis conjugation in plain prose, IBM, JOINTS/WEIGHTS, the bone-map remap, weight renormalization; community-cite only, NO EpicGames source)
- Modify: `docs/plans/phase-3h-skeletalmesh-design.md` (mark Execution item 8 / PR6 done)

- [ ] **Step 1:** Write the export-section docs + flip the design Execution status. Run `paksmith-doc-lint required-headings docs/formats/` + `typos`. **Step 2: Commit** `docs(formats): document the skeletal-mesh glTF export mapping`.

## Task 12: Rebase, adversarial panel, PR

- [ ] **Step 1: Rebase onto `main`.** Once docs PR #554 (PR7→PR6 renumber) has merged, `git fetch origin && git rebase origin/main`. Resolve the design-doc conflict (both #554 and Task 11 touch the Execution PR6 line — keep "PR6", merged-status). If #554 has NOT merged yet, proceed and rebase before the PR is mergeable; flag it in the PR body.
- [ ] **Step 2: ≥5-reviewer adversarial panel** on `git diff main..HEAD`, dispatched in ONE message, briefed to hunt cold (conf ≥ 70, no "already addressed" summaries):
  - **security** (MANDATORY): every per-vertex/bone value attacker-influenced — the bone-index/bone-map OOB checks fire before the indirect reads; all `i32`/`u32` counts validated; `with_capacity` only after caps; `checked_mul` on accessor byte sizes; the aggregate GLB cap holds; the parent-chain walk can't recurse/overflow on a malformed `parent_index`; non-finite positions rejected; no panic on any corrupt `SkeletalMeshData`.
  - **deep-impact** (MANDATORY): the `gltf_common` extraction — does every moved item keep identical behavior, do ALL static-mesh tests still pass, are there other `export/` callers? The new `Asset::SkeletalMesh` handler in the registry; the `push_primitives` reuse/extraction; visibility widening (`pub(crate)`).
  - **wire-format/correctness** (MANDATORY): re-derive the basis conjugation `B·L·B⁻¹` / `IBM = B·G⁻¹·B⁻¹` independently; confirm column-major emission; confirm the bone-map remap uses the **owning section's** map; confirm weights renormalize to a glTF-valid sum and the JOINTS/WEIGHTS `normalized` flags; confirm the mesh+skin node is identity. (Note: glTF emission is NOT oracle-checked — the reviewer verifies the math + the bind-pose-identity test's strictness, not byte-matching CUE4Parse.)
  - **code-reviewer** + **simplifier** + **performance** (the skinned buffers are the largest export payloads — check allocation/copy patterns).
- [ ] **Step 3:** Fix-forward every finding in THIS PR; **re-run the FULL panel each round to convergence** (every reviewer APPROVED, zero unresolved). cargo-mutants/fmt/clippy are NOT a substitute for re-review.
- [ ] **Step 4: Push + PR.** Marker at the worktree git-dir (SEPARATE Bash call from push; another before `gh pr create`). Title: `feat(export): add GltfSkeletalMeshHandler for skinned glTF (Phase 3h PR6)`. Body via `--body-file` heredoc (backtick-safe): the extraction + handler scope, the basis-conjugation correctness summary + the bind-pose-identity verification, the weight-renormalization + bone-map-remap policies, the deferrals (animation/morph/sockets/cloth-surface per the design). Monitor `gh pr checks`. **User merges — never `gh pr merge`.**
- [ ] **Step 5: Post-merge** — remove this worktree + branch, sync main. **Phase 3h is COMPLETE** (parser + skinned glTF exporter). Update the 3h state memory: PR6 merged, 3h done.

## Self-review notes (anti-drift)

- **The bind-pose-identity test (Task 6) is the gate, not shape assertions.** A sign flip / transpose / major-order slip passes every accessor-shape test and ships a broken pose. Use a bone with non-axis-aligned rotation + non-uniform scale + translation.
- **Mesh+skin node = identity transform** (glTF folds in `inverse(meshNodeGlobal)`).
- **`WEIGHTS` `normalized:true`, `JOINTS` `normalized:false`** — do not cross them.
- **Bone-map remap uses the owning section's `bone_map`**, never the LOD union.
- **glTF emission is verified empirically** (identity test + gltf-validator), NOT against the wire oracle.
- **`gltf_common` extraction is zero-behavior-change** — existing static-mesh tests are the guard; don't edit their bodies.
