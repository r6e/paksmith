# Phase 3h PR2 — dispatch + `USkeletalMesh` segment-2 prefix — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax. Design: [`phase-3h-skeletalmesh-design.md`](phase-3h-skeletalmesh-design.md); wire refs: [`../formats/mesh/skeletal-mesh.md`](../formats/mesh/skeletal-mesh.md), [`../formats/mesh/skeleton.md`](../formats/mesh/skeleton.md).

**Goal:** Make `USkeletalMesh` actually parse + dispatch. `read_typed` decodes the tagged-property segment + the segment-2 *prefix* (strip flags → `ImportedBounds` → `SkeletalMaterials` → `ReferenceSkeleton` → `bCooked`) and returns `Asset::SkeletalMesh` with `skeleton`/`bounds`/`materials` populated and **empty `lods`**. The per-LOD `FStaticLODModel` (sections, index buffer, vertex/skin buffers) is the next PRs.

**Architecture:** A new `asset/exports/mesh/skeletal_mesh.rs` mirrors `static_mesh.rs`'s `read_typed` shape. It consumes the `SkeletalMaterials` array (a new `FSkeletalMaterial` reader, itself needing a new `FMeshUVChannelInfo` reader + three new custom-version constants), then calls PR1's `read_reference_skeleton`. Dispatch is wired in `dispatch.rs`.

**Tech Stack:** Rust; reuse `wire::read_strip_data_flags`, `structs::bounds::FBoxSphereBounds`, `skeleton::read_reference_skeleton`, `property::{read_properties, read_object_guid_tail, read_fname_pair}`, `package_index::read_package_index`, `mesh::read::read_capped_count`, `custom_version::{CustomVersionContainer::version_for, *_GUID}`.

**PR-series re-split note (tell the user):** the design's "PR2" bundled the segment-2 prefix *with* `FStaticLODModel` sections/index. This plan scopes PR2 to **prefix + dispatch only** (it's already sizable — it adds `FSkeletalMaterial` + `FMeshUVChannelInfo` + 3 custom-version constants). The ~25-field `FSkelMeshSection` + `FMultisizeIndexContainer` + LOD records move to **PR3**; skin/vertex buffers + bone-map to **PR4**; the `GltfSkeletalMeshHandler` to **PR5**. (The 4-PR series becomes 5 for reviewability.)

**Oracle-verified (confirmed before planning):**
- `USkeletalMesh.Deserialize` segment-2 order: `FStripDataFlags` → `ImportedBounds` (FBoxSphereBounds) → `SkeletalMaterials = ReadArray(FSkeletalMaterial)` → `ReferenceSkeleton` → `bCooked` (bool32) → LODs.
- `FSkeletalMaterial` (cooked) read order + gates: `Material` (FPackageIndex i32) → `MaterialSlotName` (FName, gate `FEditorObjectVersion ≥ RefactorMeshEditorMaterials`) → `bSerializeImportedMaterialSlotName` (bool, gate `FCoreObjectVersion ≥ SkeletalMaterialEditorDataStripping`) [+ `ImportedMaterialSlotName` FName **skipped in cooked** via `PKG_FilterEditorOnly`] → `UVChannelData` (FMeshUVChannelInfo, gate `FRenderingObjectVersion ≥ TextureStreamingMeshUVChannelData`) → `OverlayMaterialInterface` (FPackageIndex, gate `FFortniteMainBranchObjectVersion ≥ MeshMaterialSlotOverlayMaterialAdded`, UE5).
- `read_typed` pattern (from `static_mesh.rs`): `read_properties(&mut cur, ctx, 0, total_len, asset_path)` → `read_object_guid_tail(&mut cur, total_len, asset_path)` → binary segment → `Ok((StaticMeshData, bulk))`; public `read_typed -> Ok((Asset::X(data), bulk))`.

**NOT yet pinned — Task 1 verifies against the oracle before any reader code:** `FMeshUVChannelInfo`'s exact byte layout (bool widths + float count) and the four custom-version **enum integer positions** (`RefactorMeshEditorMaterials`, `SkeletalMaterialEditorDataStripping`, `TextureStreamingMeshUVChannelData`, `MeshMaterialSlotOverlayMaterialAdded`) + the three missing version **GUIDs**.

---

## File structure

- **Create** `crates/paksmith-core/src/asset/exports/mesh/skeletal_mesh.rs` — `read_typed` + `FSkeletalMaterial`/`FMeshUVChannelInfo` readers + tests.
- **Modify** `crates/paksmith-core/src/asset/exports/mesh/mod.rs` — `pub(crate) mod skeletal_mesh;`.
- **Modify** `crates/paksmith-core/src/asset/exports/mesh/skeleton.rs` — remove `#[allow(dead_code)]` from `read_reference_skeleton` (now called).
- **Modify** `crates/paksmith-core/src/asset/custom_version.rs` — 3 new GUID consts + 4 enum-position consts.
- **Modify** `crates/paksmith-core/src/asset/exports/dispatch.rs` — register `SkeletalMesh`; flip the `is_none()` test.
- **Modify** `crates/paksmith-core/src/asset/mod.rs` — if `SkeletalMeshData.materials` needs a richer element than `Vec<String>` (decide in Task 5; PR1 declared `Vec<String>` slot names — keep unless a reason emerges).
- **Modify** docs comments enumerating handled classes (`package.rs`, `asset/mod.rs`) to add `SkeletalMesh`.

All work in `.claude/worktrees/feat+phase-3h-lod-sections/` (branch `feat/phase-3h-lod-sections`).

---

## Task 1: Oracle verification (no code — record verified facts)

**Files:** none (records facts used by Tasks 2–4).

- [ ] **Step 1: Pin `FMeshUVChannelInfo`**

Fetch the oracle `FMeshUVChannelInfo` deserializer at SHA `cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` (try the GitHub MCP `get_file_contents` / `search_code` for `FMeshUVChannelInfo` in `FabianFG/CUE4Parse` — the raw path is not under `UE4/Objects/Engine/`; locate it). Record: `bInitialized` + `bOverrideDensities` wire widths (1-byte `bool` vs 4-byte `u32`), and `LocalUVDensities` element count (MAX_TEXCOORDS — 4 or 8) read as a fixed-size `float[]` with NO count prefix. Compute the total byte size. Write the verified layout into the `FMeshUVChannelInfo` doc comment in Task 3.

- [ ] **Step 2: Pin the four custom-version enum positions + GUIDs**

From the oracle's `FEditorObjectVersion`, `FCoreObjectVersion`, `FRenderingObjectVersion`, `FFortniteMainBranchObjectVersion` enums (CUE4Parse `UE4/Versions/`), record the **integer position** of: `RefactorMeshEditorMaterials`, `SkeletalMaterialEditorDataStripping`, `TextureStreamingMeshUVChannelData`, `MeshMaterialSlotOverlayMaterialAdded` — and the 16-byte **GUID** of `FCoreObjectVersion`, `FRenderingObjectVersion`, `FFortniteMainBranchObjectVersion` (FEditorObjectVersion's GUID already exists as `EDITOR_OBJECT_VERSION_GUID`). Per [[feedback_version_constants_anchor_against_paksmith]]: anchor each position by counting from a NAMED sibling in the same enum (not from zero) and sanity-check from a second anchor; per [[feedback_no_ue_source_attribution_in_public_docs]] cite CUE4Parse, never EpicGames, in any committed comment.

- [ ] **Step 3: Confirm the codebase plumbing**

Confirm: `CustomVersionContainer::version_for(guid) -> Option<i32>` (custom_version.rs:164); `read_package_index(r, asset_path, AssetWireField::X)` (package_index.rs:189); `read::read_capped_count(r, asset_path, field, max)` for the `SkeletalMaterials` array count; `read_strip_data_flags` (wire.rs:76); `FBoxSphereBounds::read_from` signature; how `static_mesh.rs read_typed` computes `total_len` + calls `read_properties`/`read_object_guid_tail`. Note `ctx.custom_versions` is `Arc<CustomVersionContainer>`.

No commit (verification only; facts flow into Tasks 2–5).

---

## Task 2: Custom-version constants (GUIDs + positions)

**Files:** Modify `crates/paksmith-core/src/asset/custom_version.rs`
**Reference:** the existing `EDITOR_OBJECT_VERSION_GUID` / `FRAMEWORK_OBJECT_VERSION_GUID` const style (custom_version.rs:33,50) + their position-const doc comments.

- [ ] **Step 1: Write failing pin tests**

Add tests asserting each new GUID's bytes + each position const's value (the values recorded in Task 1). Example shape (fill with Task-1 values):

```rust
#[test]
fn rendering_object_version_guid_and_positions() {
    assert_eq!(RENDERING_OBJECT_VERSION_GUID, FGuid::from_bytes([/* Task 1 */]));
    assert_eq!(TEXTURE_STREAMING_MESH_UV_CHANNEL_DATA, /* Task 1 position */);
}
```

- [ ] **Step 2: Run to verify failure** — `cargo test -p paksmith-core --all-features custom_version` → FAIL (consts undefined).

- [ ] **Step 3: Add the consts**

Add `pub const CORE_OBJECT_VERSION_GUID`, `RENDERING_OBJECT_VERSION_GUID`, `FORTNITE_MAIN_BRANCH_OBJECT_VERSION_GUID` (FGuid, Task-1 bytes), and `pub const REFACTOR_MESH_EDITOR_MATERIALS: i32`, `SKELETAL_MATERIAL_EDITOR_DATA_STRIPPING: i32`, `TEXTURE_STREAMING_MESH_UV_CHANNEL_DATA: i32`, `MESH_MATERIAL_SLOT_OVERLAY_MATERIAL_ADDED: i32` (Task-1 positions), each with a doc comment citing the CUE4Parse enum + the anchor it was counted from. Match the existing GUID-const byte-array format.

- [ ] **Step 4: Run to verify pass** — `cargo test -p paksmith-core --all-features custom_version` → PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/paksmith-core/src/asset/custom_version.rs
git commit -m "feat(asset): custom-version GUIDs + positions for FSkeletalMaterial gates (3h)"
```

---

## Task 3: `FMeshUVChannelInfo` reader

**Files:** Create the reader in `crates/paksmith-core/src/asset/exports/mesh/skeletal_mesh.rs` (+ `pub(crate) mod skeletal_mesh;` in `mesh/mod.rs`).

- [ ] **Step 1: Write the failing test (byte-exact, Task-1 layout)**

Add `skeletal_mesh.rs` with the module doc + a test feeding the exact bytes for an initialized `FMeshUVChannelInfo` (bools + N×f32 per Task 1) and asserting full consumption. (No need to store the values — the reader just consumes the struct to stay aligned; return `()` or a minimal struct.)

```rust
#[test]
fn reads_mesh_uv_channel_info_consumes_exact_bytes() {
    // bytes per Task-1 layout (e.g. 2 one-byte bools + 4 f32 = 18 bytes, OR
    // 2 u32 bools + 4 f32 = 24 bytes — use the verified width)
    let bytes = /* Task-1 exact bytes */;
    let mut cur = std::io::Cursor::new(bytes);
    read_mesh_uv_channel_info(&mut cur, "T.uasset").expect("decode");
    assert_eq!(cur.position() as usize, bytes.len());
}
```

- [ ] **Step 2: Run to verify failure.**

- [ ] **Step 3: Implement `read_mesh_uv_channel_info`** consuming exactly the Task-1-verified bytes (bool widths + the fixed `LocalUVDensities` float count, no count prefix), mapping EOF to a typed fault. It needs no return data (consume-to-stay-aligned), but document the fields. Use `byteorder` LE.

- [ ] **Step 4: Run to verify pass.**

- [ ] **Step 5: Commit**

```bash
git add crates/paksmith-core/src/asset/exports/mesh/skeletal_mesh.rs crates/paksmith-core/src/asset/exports/mesh/mod.rs
git commit -m "feat(asset): FMeshUVChannelInfo reader (3h)"
```

---

## Task 4: `FSkeletalMaterial` reader

**Files:** Modify `crates/paksmith-core/src/asset/exports/mesh/skeletal_mesh.rs`

- [ ] **Step 1: Write the failing tests**

Build an `AssetContext` whose `custom_versions` set the four gates ON (UE4 cooked: all four predate/meet the gate except the UE5 OverlayMaterial — test BOTH a UE4 ctx without OverlayMaterial and a UE5 ctx with it). Reuse the test-ctx builder pattern from `skeleton.rs` tests, extended to seed custom versions (see how `custom_version` tests build a container). Assert: `read_skeletal_material` returns the `MaterialSlotName` (the slot name string) and consumes the exact bytes (FPackageIndex 4 + FName 8 + bool + FMeshUVChannelInfo + optionally FPackageIndex 4), for UE4-cooked (no overlay) and UE5 (overlay present).

```rust
#[test]
fn reads_skeletal_material_ue4_cooked() {
    let ctx = test_ctx_with_versions(/* RefactorMeshEditorMaterials, SkeletalMaterialEditorDataStripping,
                                        TextureStreamingMeshUVChannelData all met; no overlay */);
    let bytes = /* FPackageIndex(0) + FName("Mat0") + bSerializeImported=0 + FMeshUVChannelInfo */;
    let mut cur = std::io::Cursor::new(bytes);
    let name = read_skeletal_material(&mut cur, &ctx, "T.uasset").expect("decode");
    assert_eq!(name.as_deref(), Some("Mat0"));
    assert_eq!(cur.position() as usize, bytes.len());
}
```

- [ ] **Step 2: Run to verify failure.**

- [ ] **Step 3: Implement `read_skeletal_material(r, ctx, asset_path) -> crate::Result<Option<String>>`**

Read in the verified order with the Task-2 gates via `ctx.custom_versions.version_for(GUID).map_or(false, |v| v >= POSITION)`:
- `Material`: `read_package_index(r, asset_path, AssetWireField::SkeletalMaterialInterface)` (add the wire-field variant).
- if `FEditorObjectVersion ≥ RefactorMeshEditorMaterials`: `MaterialSlotName = read_fname_pair(...)` (the returned slot name).
- if `FCoreObjectVersion ≥ SkeletalMaterialEditorDataStripping`: read `bSerializeImportedMaterialSlotName` (bool32). The `ImportedMaterialSlotName` FName is editor-only → **NOT read in cooked** (paksmith only parses cooked; document that we skip it, matching `!PKG_FilterEditorOnly`).
- if `FRenderingObjectVersion ≥ TextureStreamingMeshUVChannelData`: `read_mesh_uv_channel_info(...)`.
- if `FFortniteMainBranchObjectVersion ≥ MeshMaterialSlotOverlayMaterialAdded`: `OverlayMaterialInterface = read_package_index(...)`.
Return the slot name (`Option<String>`).

Note the bool32 read helper: reuse the crate's bool32 reader (grep `read_bool32` in `wire.rs` — the mesh code used `wire::read_bool32`). Confirm + use it.

- [ ] **Step 4: Run to verify pass.**

- [ ] **Step 5: Commit**

```bash
git add crates/paksmith-core/src/asset/exports/mesh/skeletal_mesh.rs crates/paksmith-core/src/error.rs
git commit -m "feat(asset): FSkeletalMaterial cooked reader (3h)"
```

---

## Task 5: `read_typed` — segment-2 prefix → `Asset::SkeletalMesh`

**Files:** Modify `crates/paksmith-core/src/asset/exports/mesh/skeletal_mesh.rs`, `skeleton.rs` (drop the dead_code allow)
**Reference:** `static_mesh.rs` `read_typed` (the `total_len` / `read_properties` / `read_object_guid_tail` / `Ok((Asset::X(data), bulk))` shape).

- [ ] **Step 1: Write the failing end-to-end test**

Assemble a minimal cooked `USkeletalMesh` payload: an empty tagged-property stream (just the `None` terminator) + the object-GUID tail (bSerializeGuid=0) + `FStripDataFlags` (2 bytes) + `ImportedBounds` (FBoxSphereBounds, UE4 28 bytes) + `SkeletalMaterials` (i32 count 1 + one `FSkeletalMaterial`) + `FReferenceSkeleton` (the PR1 2-bone worked example, 140 bytes) + `bCooked` (1). Feed `read_typed`; assert the returned `Asset::SkeletalMesh` has `skeleton.bones.len() == 2`, `materials == ["Mat0"]`, `cooked == true`, `lods.is_empty()`, and the bulk Vec is empty.

```rust
#[test]
fn read_typed_parses_prefix_through_skeleton() { /* assemble + assert as above */ }
```

- [ ] **Step 2: Run to verify failure.**

- [ ] **Step 3: Implement `read_typed`**

```rust
pub(crate) fn read_typed(
    payload: &[u8],
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<(Asset, Vec<FByteBulkData>)> {
    let total_len = payload.len() as u64;
    let mut cur = std::io::Cursor::new(payload);
    let properties = read_properties(&mut cur, ctx, 0, total_len, asset_path)?;
    let _object_guid = read_object_guid_tail(&mut cur, total_len, asset_path)?;
    let _strip = wire::read_strip_data_flags(&mut cur, asset_path)?;
    let bounds = FBoxSphereBounds::read_from(&mut cur, ctx, /* expected_end */, asset_path)?;
    let mat_count = read::read_capped_count(&mut cur, asset_path, AssetWireField::SkeletalMaterialCount, MAX_SKELETAL_MATERIALS)?;
    let mut materials = Vec::with_capacity(mat_count);
    for _ in 0..mat_count {
        materials.push(read_skeletal_material(&mut cur, ctx, asset_path)?.unwrap_or_default());
    }
    let skeleton = read_reference_skeleton(&mut cur, ctx, asset_path)?;
    let cooked = wire::read_bool32(&mut cur, asset_path, AssetWireField::SkeletalMeshCooked)?;
    let mut data = SkeletalMeshData::empty();
    data.properties = properties;
    data.cooked = cooked;
    data.bounds = bounds;
    data.materials = materials;
    data.skeleton = skeleton;
    Ok((Asset::SkeletalMesh(data), Vec::new()))
}
```
Adapt: `FBoxSphereBounds::read_from`'s `expected_end` per its real signature (grep it — like `FTransform`, compute `start + FBoxSphereBounds::wire_size(ctx)` or it may take the slice differently). Add `MAX_SKELETAL_MATERIALS` cap const (e.g. 256 — match a sibling material/section cap; NOTE-deferral accessor convention) + the `SkeletalMaterialCount`/`SkeletalMeshCooked` `AssetWireField` variants. Remove `#[allow(dead_code)]` from `read_reference_skeleton`.

- [ ] **Step 4: Run to verify pass.**

- [ ] **Step 5: Add a public `Asset`-returning wrapper if the dispatch expects it** — confirm the dispatch table's fn type (it stores `read_typed` directly per `static_mesh.rs`); the signature above already returns `(Asset, Vec<FByteBulkData>)`, matching. 

- [ ] **Step 6: Commit**

```bash
git add crates/paksmith-core/src/asset/exports/mesh/skeletal_mesh.rs crates/paksmith-core/src/asset/exports/mesh/skeleton.rs crates/paksmith-core/src/error.rs crates/paksmith-core/src/asset/mod.rs
git commit -m "feat(asset): USkeletalMesh read_typed prefix -> Asset::SkeletalMesh (3h)"
```

---

## Task 6: Dispatch wiring + class enumerations

**Files:** Modify `crates/paksmith-core/src/asset/exports/dispatch.rs`, plus `package.rs`/`asset/mod.rs` doc comments listing handled classes.

- [ ] **Step 1: Flip the dispatch test (TDD)**

In `dispatch.rs`, change the test `assert!(class_dispatch().get("SkeletalMesh").is_none())` to `assert!(class_dispatch().get("SkeletalMesh").is_some())`, and bump any `class_dispatch().len() == N` count assertion by 1 (grep for it — there's a length pin). Run → FAIL (not yet registered).

- [ ] **Step 2: Register the handler**

Uncomment/replace the stub (dispatch.rs:105) with `table.insert("SkeletalMesh", crate::asset::exports::mesh::skeletal_mesh::read_typed);` (match the exact insert form the other entries use). Update the doc comments in `package.rs` / `asset/mod.rs` that enumerate handled export classes to include `SkeletalMesh`.

- [ ] **Step 3: Run to verify pass** — `cargo test -p paksmith-core --all-features dispatch` → PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/paksmith-core/src/asset/exports/dispatch.rs crates/paksmith-core/src/asset/package.rs crates/paksmith-core/src/asset/mod.rs
git commit -m "feat(asset): wire SkeletalMesh dispatch (3h)"
```

---

## Task 7: Hardening + version coverage

**Files:** Modify `crates/paksmith-core/src/asset/exports/mesh/skeletal_mesh.rs` (tests + guards)

- [ ] **Step 1: Materials cap** — a `SkeletalMaterials` count over `MAX_SKELETAL_MATERIALS` → typed error before allocation (test).
- [ ] **Step 2: UE5 path** — a UE5 ctx (`OverlayMaterialInterface` gate on) → `read_skeletal_material` consumes the extra FPackageIndex; `read_typed` still lands on the skeleton. Test.
- [ ] **Step 3: Gate-off paths** — a ctx where `FRenderingObjectVersion < TextureStreamingMeshUVChannelData` (no UVChannelData) → reader skips it + stays aligned. Test (pins the gate `>=` boundary).
- [ ] **Step 4: Truncation** — a payload truncated mid-prefix → typed `Err`, no panic. Test.
- [ ] **Step 5: Commit**

```bash
git add crates/paksmith-core/src/asset/exports/mesh/skeletal_mesh.rs
git commit -m "test(asset): skeletal-mesh prefix hardening + version coverage (3h)"
```

---

## Task 8: Gate chain + in-diff cargo-mutants

- [ ] **Step 1:** `cargo fmt --all`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`; `cargo test --workspace --all-features`; `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features`; `typos .`; `cargo deny check` — all green.
- [ ] **Step 2:** `git diff origin/main -- > /tmp/pr_3h2.diff && cargo mutants --in-diff /tmp/pr_3h2.diff --no-shuffle -j 4 --all-features` → **0 missed, 0 timeout**. Pin survivors (the version-gate `>=` boundaries, the materials cap, the slot-name extraction) with literal-value tests; for an equivalent mutant prefer a literal.
- [ ] **Step 3:** Commit any pins.

---

## Task 9: Review panel to convergence, then PR

- [ ] **Step 1: ≥5-reviewer panel** on `git diff main..HEAD`: **wire-format** (FSkeletalMaterial gate order + FMeshUVChannelInfo bytes + the segment-2 prefix order + the new custom-version positions vs oracle — MANDATORY), **security** (the materials cap, every gate read, no panic on truncation, FPackageIndex bounds — MANDATORY), **deep-impact** (the new custom-version consts + dispatch registration + `Asset::SkeletalMesh` now produced, ripple into package walker / inspect CLI — MANDATORY), **code-reviewer**, **simplifier** (DRY across the four gate checks). Brief adversarially (conf ≥ 70, hunt cold). Re-run the FULL panel each fix round to convergence.
- [ ] **Step 2: Push + PR + monitor CI.** Marker at the worktree git-dir (`touch "$(git rev-parse --git-dir)/REVIEW_CONVERGED_OK"`, a SEPARATE Bash call from push; another fresh marker before `gh pr create`). Title (lowercase verb-first): `feat(asset): wire USkeletalMesh dispatch + parse segment-2 prefix (Phase 3h PR2)`. Monitor `gh pr checks`. **User merges.** No `.pak` fixtures → fixture-count gate untouched.
- [ ] **Step 3: Post-merge** — remove worktree + branch, sync main; PR3 (`FStaticLODModel` sections + `FSkelMeshSection` + `FMultisizeIndexContainer`) gets a fresh worktree + its own writing-plans pass.

---

## Self-review notes (coverage)

- Oracle verification first (Task 1) — FMeshUVChannelInfo bytes + the 4 enum positions/GUIDs pinned before any reader code, per [[feedback_verify_wire_format_claims]].
- Custom-version consts → Task 2 (anchored + pin-tested). FMeshUVChannelInfo → Task 3. FSkeletalMaterial (4 gates, cooked) → Task 4. read_typed prefix → Task 5 (reuses read_properties/object-guid-tail/strip-flags/bounds/skeleton; removes the PR1 dead_code allow). Dispatch + class enums → Task 6. Hardening (cap/UE5/gate-off/truncation) → Task 7. Gates + 0-missed mutants → Task 8. Panel + PR → Task 9.
- Deferred (documented): `FStaticLODModel` sections / `FSkelMeshSection` / `FMultisizeIndexContainer` → PR3; skin/vertex buffers + bone-map → PR4; exporter → PR5.
- Reuses the object-GUID-tail invariant ([[project_typed_reader_object_guid_tail]]) and the no-`.pak`-fixture discipline.
