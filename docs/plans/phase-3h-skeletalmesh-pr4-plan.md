# Phase 3h PR4 — cooked `FStaticLODModel` LOD-0 wiring — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax. Design: [`phase-3h-skeletalmesh-design.md`](phase-3h-skeletalmesh-design.md); wire ref: [`../formats/mesh/skeletal-mesh.md`](../formats/mesh/skeletal-mesh.md).

**Goal:** Wire the cooked `FStaticLODModel::SerializeRenderItem` **LOD[0]** record into `read_typed`, filling `Asset::SkeletalMesh.lods` with the highest-detail LOD's sections + active/required bones (the structure read needs only the header — everything before the streamed blob). The blob (index/vertex/skin buffers) and multi-LOD iteration are deferred to PR5, which parses the blob structurally.

**Scope decision (LOD-0-first):** Task 1's independent oracle re-verification found the all-LODs path rests on an oracle-unbacked `BuffersSize` skip + an unreliable 4.24 gate for unversioned packages + a `dummyObjs` trailing read. Reliable iteration needs structural blob parsing (PR5's work). So PR4 reads **only LOD[0]'s header region and stops at blob-start** — no `BuffersSize` skip, no iteration, no `dummyObjs`/landing-net, no `FNanite` tail. PR5 resumes by parsing the blob structurally and iterating from there. LOD0 is the highest-detail mesh — exactly what a usable skinned glTF needs.

**Architecture:** A new `read_static_lod_model` reads one LOD's header (`FStripDataFlags → bIsLODCookedOut → bInlined → RequiredBones → [if AV-present] Sections → ActiveBoneIndices → BuffersSize`) and returns a `SkeletalMeshLod` with sections + bones; the cursor stops at blob-start. `read_typed` gates on the UE4.24 new-cooked-format boundary (degrade pre-4.24 legacy), reads the `LODModels` count, parses LOD[0] (when count ≥ 1), and returns `lods = [lod0]`. Like PR2, it leaves the rest of the payload unconsumed — no full-consumption requirement (the object-GUID tail was consumed early at line 602).

**Tech Stack:** Rust; reuse `read_skel_mesh_section_render` (PR3), `read::read_capped_count`, `wire::{read_strip_data_flags, read_bool32, is_av_data_stripped(new)}`, `custom_version::version_for` (FRenderingObjectVersion GUID already in `custom_version.rs` from PR2).

**PR-series:** PR1 (#543), PR2 (#544), PR3 (#546) merged; off-by-one (#545) merged. PR4 (this) = LOD-0 wiring; PR5 = blob contents + multi-LOD iteration (structural); PR6 = `GltfSkeletalMeshHandler`.

## ORACLE-VERIFIED cooked `SerializeRenderItem` header (Task 1, both CUE4Parse@cf74fc32 + UEViewer; re-derive again in Task 8 panel)
Per-LOD, bool32 = 4-byte strict {0,1} (`ReadBoolean`):
1. `FStripDataFlags` (2×u8: global, class — keep global for the AV gate).
2. `bIsLODCookedOut` (bool32, strict).
3. `bInlined` (bool32, strict).
4. `RequiredBones` (i32 count + N×i16 / short, capped) — **before Sections**.
5. **Gated** `!is_av_data_stripped(global) && !bIsLODCookedOut`:
   - a. `Sections` (i32 count + N × `read_skel_mesh_section_render`, capped).
   - b. `ActiveBoneIndices` (i32 count + N×i16, capped).
   - c. `BuffersSize` (u32) — read it (marks blob-start) and **STOP**. The blob follows; PR4 does not read it.
`LODModels = i32 count + N × SerializeRenderItem` (USkeletalMesh.cs cooked branch — the branch `read_typed` reaches after `bCooked`). PR4 reads the count and parses index 0 only.

## 4.24 gate (the one real hazard left)
`SerializeRenderItem` is the format ONLY for Game ≥ UE4.24; 4.16–4.23 cooked is `SerializeRenderItem_Legacy` (a different header — no `bIsLODCookedOut`/`bInlined`). Discriminator (Task 1): **`FRenderingObjectVersion ≥ MaterialShaderMapIdSerialization`** (4.24); `FSkeletalMeshCustomVersion` is identical across 4.23/4.24/4.25 and CANNOT discriminate. Behavior:
- `FRenderingObjectVersion` present and `< MaterialShaderMapIdSerialization` → `UnsupportedFeature` (pre-4.24 legacy cooked LOD layout).
- present and `≥` → proceed (new format).
- **absent (unversioned package — the shipping-game norm)** → proceed (attempt new format); the **natural backstop** is the strict bool32 reads (`bIsLODCookedOut`/`bInlined`) + the PR3 section reader's caps/strict-bools, which reject a legacy-as-new mis-parse with a typed `Err` (→ `Generic`) in the common case. Document this limitation.

---

## File structure
- **Modify** `crates/paksmith-core/src/asset/wire.rs` — `is_av_data_stripped(global)`.
- **Modify** `crates/paksmith-core/src/asset/custom_version.rs` — `MATERIAL_SHADER_MAP_ID_SERIALIZATION` position const (FRenderingObjectVersion GUID already present) + pin test.
- **Modify** `crates/paksmith-core/src/asset/mod.rs` — `SkeletalMeshLod` += `active_bone_indices: Vec<u16>`, `required_bones: Vec<u16>`.
- **Modify** `crates/paksmith-core/src/error.rs` — new wire-field variants (+ reuse `UnsupportedFeature` for the legacy degrade).
- **Modify** `crates/paksmith-core/src/asset/exports/mesh/skeletal_mesh.rs` — `read_static_lod_model`, the LOD-0 read in `read_typed`, caps.
- **Modify** `docs/formats/mesh/skeletal-mesh.md` — the cooked `FStaticLODModel` header + the 4.24 boundary + the LOD-0/PR5 split.

All work in `.claude/worktrees/feat+phase-3h-lod-wiring/` (branch `feat/phase-3h-lod-wiring`).

---

## Task 1: Oracle re-verification — DONE
Independently re-derived (CUE4Parse@cf74fc32 + UEViewer): header order confirmed (RequiredBones before Sections; bIsLODCookedOut/bInlined strict bool32; i16 bone arrays; BuffersSize u32 before the blob; AV-gate `!AVstripped && !bIsLODCookedOut`). 4.24 discriminator = `FRenderingObjectVersion ≥ MaterialShaderMapIdSerialization` (NOT FSkeletalMeshCustomVersion). The all-LODs hazards (BuffersSize skip / dummyObjs / availability-info) are deferred to PR5 by the LOD-0-first scope. **Task 8's wire-format reviewer re-derives the header order + the 4.24 position independently** (53→54 lesson — don't inherit).

---

## Task 2: Scaffolding — helper, struct fields, 4.24 gate, caps, wire-fields

**Files:** `wire.rs`, `custom_version.rs`, `mod.rs`, `error.rs`, `skeletal_mesh.rs`

- [ ] **Step 1 — `is_av_data_stripped`** (wire.rs, mirror `is_editor_data_stripped`):
```rust
/// `FStripDataFlags::IsAudioVisualDataStripped` — AV-data bit (0x02) in the
/// GLOBAL strip-flags byte. A cooked skeletal LOD's section/bone block is
/// absent when this is set.
pub(crate) fn is_av_data_stripped(global: u8) -> bool {
    global & STRIP_FLAG_AV_DATA != 0
}
```
Test: bit set/unset, editor-bit-only → false, both → true.
- [ ] **Step 2 — 4.24 gate const** (custom_version.rs). VERIFY the 0-based ordinal of `MaterialShaderMapIdSerialization` in `FRenderingObjectVersion` @ cf74fc32 (it follows `VirtualTexturedLightmapsV2`=4.23) — anchor-count it, don't guess. Add `pub const MATERIAL_SHADER_MAP_ID_SERIALIZATION: i32 = <verified>;` (doc-cite + anchor) + a pin test. (Reuse the existing `RENDERING_OBJECT_VERSION_GUID`.)
- [ ] **Step 3 — `SkeletalMeshLod` fields** (mod.rs): add `pub active_bone_indices: Vec<u16>,` and `pub required_bones: Vec<u16>,` (doc; keep `#[non_exhaustive]` + Default). Update the `bone_map` doc ("union of section bone_maps, populated here in PR4"). Construction test.
- [ ] **Step 4 — caps** (skeletal_mesh.rs, value-pinned, NOTE-comment per sibling convention): `MAX_LODS_PER_MESH: usize = 64` (caps the LODModels count), `MAX_REQUIRED_BONES: usize = MAX_BONES_PER_SKELETON`, `MAX_ACTIVE_BONES: usize = MAX_BONES_PER_SKELETON` (+ `_U32` companions for `read_capped_count`).
- [ ] **Step 5 — wire-fields** (error.rs): `AssetWireField`: `SkelLodCount`, `SkelLodCookedOut`, `SkelLodInlined`, `SkelLodRequiredBonesCount`, `SkelLodSectionCount`, `SkelLodActiveBonesCount`, `SkelLodBuffersSize`. Display pin tests. (Legacy degrade reuses `UnsupportedFeature`.)
- [ ] **Step 6 — commit** `feat(asset): scaffolding for FStaticLODModel LOD-0 wiring (3h)`.

---

## Task 3: `read_static_lod_model` — LOD-0 header reader

**Files:** `skeletal_mesh.rs`

- [ ] **Step 1 — failing test.** Build one LOD payload: strip flags (global=0x01 editor-stripped, NOT AV-stripped; class=0x00) + bIsLODCookedOut=0(bool32) + bInlined=1(bool32) + RequiredBones(count=2 + 2×i16) + Sections(count=1 + one section via the PR3 byte layout, using the `section_ctx` gate helper) + ActiveBoneIndices(count=2 + 2×i16) + BuffersSize(u32). Call `read_static_lod_model(&mut cur, ctx, asset_path)`. Assert the returned `SkeletalMeshLod`: sections.len()==1, required_bones==[..], active_bone_indices==[..], bone_map == dedup-union of the section's bone_map, AND the cursor stopped right after BuffersSize (blob-start). RED (fn undefined).
- [ ] **Step 2 — implement** `pub(crate) fn read_static_lod_model<R: Read + ?Sized>(r: &mut R, ctx: &AssetContext, asset_path: &str) -> crate::Result<SkeletalMeshLod>`:
  - read strip flags (keep `global`); `bIsLODCookedOut` = `read_bool32`; `bInlined` = `read_bool32` (read + discard — value only matters for the blob, which PR4 doesn't read; but read it to reach RequiredBones).
  - `RequiredBones`: `read_capped_count(.. SkelLodRequiredBonesCount, MAX_REQUIRED_BONES_U32)` then N×i16 → `Vec<u16>` (bone indices; read i16 LE, `u16::from_ne_bytes`/`as u16` — confirm: UE stores them as `int16` indices; widen losslessly via `i16 as u16` bit-cast OR `u16::try_from` — they're non-negative indices, but match UE's raw i16; store the raw bits as u16 like ActiveBones, document).
  - if `!is_av_data_stripped(global) && !bIsLODCookedOut`: `Sections` (capped count + `read_skel_mesh_section_render` loop), `ActiveBoneIndices` (capped i16 array → Vec<u16>), `BuffersSize` = read u32 (consume; not stored). Else: leave sections/active empty.
  - `bone_map` = dedup-union of the sections' `bone_map`s (stable order).
  - Return the `SkeletalMeshLod` (positions/normals/.../indices/bone_indices/bone_weights stay empty — PR5). `#[allow(dead_code)]` until Task 4.
- [ ] **Step 3** — run → GREEN. **Step 4 — commit** `feat(asset): FStaticLODModel LOD-0 header reader (3h)`.

---

## Task 4: Wire LOD-0 into `read_typed` + 4.24 gate

**Files:** `skeletal_mesh.rs`

- [ ] **Step 1 — failing test.** Extend a full `read_typed` payload (the PR2 prefix through `bCooked`) with `LODModels`: count=1 + one inlined LOD (header only, blob bytes may follow but PR4 ignores them). ctx seeded with `FRenderingObjectVersion ≥ MaterialShaderMapIdSerialization`. Assert `Asset::SkeletalMesh.lods.len() == 1` with populated sections/bones. A second test: ctx with `FRenderingObjectVersion < MaterialShaderMapIdSerialization` → `read_typed` returns `Err(UnsupportedFeature)` (pre-4.24 legacy). A third: `LODModels` count==0 → `lods` empty, `Ok`. RED.
- [ ] **Step 2 — implement** in `read_typed`, replacing the `lods: Vec::new()` after `bCooked`:
  - **4.24 gate:** `let rendering_ver = ctx.custom_versions.version_for(RENDERING_OBJECT_VERSION_GUID);` `if rendering_ver.is_some_and(|v| v < MATERIAL_SHADER_MAP_ID_SERIALIZATION) { return Err(UnsupportedFeature { context: "pre-UE4.24 legacy cooked skeletal LOD layout not supported" }) }` (absent → proceed, per the documented backstop).
  - `let lod_count = read_capped_count(.. SkelLodCount, MAX_LODS_PER_MESH_U32)?;`
  - `let mut lods = Vec::new(); if lod_count >= 1 { lods.push(read_static_lod_model(&mut cur, ctx, asset_path)?); }` — **LOD-0 only** (do NOT iterate; the remaining LODs + blob are left unconsumed, like PR2).
  - `data.lods = lods;`
- [ ] **Step 3** — run → GREEN. **Step 4 — commit** `feat(asset): parse LOD-0 in USkeletalMesh read_typed (3h)`.

---

## Task 5: Hardening

**Files:** `skeletal_mesh.rs` (tests + any guard fixes)

- [ ] Caps: over-cap LODModels count, required-bones count, active-bones count → typed `Err` (boundary tests at the cap).
- [ ] Gate pairs: AV-stripped LOD (`global` has 0x02) → sections/active-bones empty, only required_bones read (cursor stops after RequiredBones). `bIsLODCookedOut=1` → same (block absent). Present/absent pairs for both gates.
- [ ] 4.24 gate: `FRenderingObjectVersion` exactly `MaterialShaderMapIdSerialization-1` → `UnsupportedFeature`; exactly `MaterialShaderMapIdSerialization` → proceeds (boundary pair). Absent → proceeds.
- [ ] Strict-bool backstop: a `bIsLODCookedOut`/`bInlined` wire value of 2 → `read_bool32` rejects → typed `Err` (documents the legacy-as-new safety).
- [ ] Truncation mid-LOD → typed `Err`, no panic.
- [ ] **Commit** `test(asset): FStaticLODModel LOD-0 hardening (3h)`.

---

## Task 6: Gate chain + in-diff cargo-mutants

- [ ] `cargo fmt --all`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`; `cargo test --workspace --all-features`; `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features`; `typos .`; `cargo deny check` — all green.
- [ ] `git diff origin/main -- > /tmp/pr_3h4.diff && cargo mutants --in-diff /tmp/pr_3h4.diff --no-shuffle -j 4 --all-features` → **0 missed, 0 timeout**. Pin survivors (the AV/cookedout gate booleans, the 4.24 `<`/`>=` boundary, the caps, the `lod_count >= 1` guard, the bone-array widenings) with literal-value tests.
- [ ] Commit pins.

---

## Task 7: Doc — cooked `FStaticLODModel` header

**Files:** `docs/formats/mesh/skeletal-mesh.md`

- [ ] Document the cooked `SerializeRenderItem` header (the field order above), the inline/bulk `bInlined` flag + `BuffersSize` marking blob-start, the UE4.24 `UseNewCookedFormat` boundary (`FRenderingObjectVersion ≥ MaterialShaderMapIdSerialization`, with the unversioned-package caveat), and the LOD-0/PR5 split (PR4 reads LOD[0]'s sections + bones; the blob contents + multi-LOD iteration are PR5). Note the all-LODs deferral + why (BuffersSize has no oracle-skip backing; iteration needs structural parsing). Cite CUE4Parse/UEViewer only.
- [ ] `typos docs/`. **Commit** `docs(mesh): document cooked FStaticLODModel header + LOD-0 scope (3h)`.

---

## Task 8: Review panel to convergence, then PR

- [ ] **≥5-reviewer panel** on `git diff main..HEAD`: **wire-format** (MUST independently re-derive the header order + the `MaterialShaderMapIdSerialization` ordinal + the AV-gate vs CUE4Parse@cf74fc32 — NOT inherit Task 1), **security** (every count capped before alloc; no panic; truncation → Err), **deep-impact** (`SkeletalMeshLod` struct growth + the new wire-fields + the `read_typed` extension + the 4.24-gate ripple + the PR5 seam — PR5 re-parses from scratch, so PR4 leaving the cursor mid-payload is fine), **code-reviewer**, **simplifier**. Brief adversarially (conf ≥ 70, hunt cold; emphasize the 4.24-gate-for-unversioned limitation + the strict-bool backstop). Re-run the FULL panel each fix round to convergence.
- [ ] **Push + PR.** Marker at the worktree git-dir (SEPARATE Bash call from push; another before `gh pr create`). Title: `feat(asset): wire cooked FStaticLODModel LOD-0 into USkeletalMesh (Phase 3h PR4)`. PR body: LOD-0-first scope + why (Task 1's all-LODs findings), the 4.24 gate + unversioned-package limitation, the PR5 deferral (blob contents + iteration). Monitor `gh pr checks`. **User merges.** No `.pak` fixtures.
- [ ] **Post-merge** — remove worktree + branch, sync main; PR5 (blob contents + multi-LOD, structural) gets a fresh worktree + writing-plans pass.

---

## Self-review notes (coverage)
- Oracle re-verification → Task 1 (DONE); wire-format reviewer re-derives independently in Task 8.
- `is_av_data_stripped` + 4.24 const + struct fields + caps + wire-fields → Task 2. LOD-0 header reader → Task 3; wire into read_typed + 4.24 gate → Task 4; hardening → Task 5; gates + 0-missed mutants → Task 6; doc → Task 7; panel + PR → Task 8.
- **LOD-0-first**: reads LOD[0]'s sections + active/required bones (all in the header); stops at blob-start. No blob skip, no iteration, no landing-net, no dummyObjs/FNanite tail — all deferred to PR5 (structural blob parse + iteration). The strict-bool/cap backstop guards legacy-as-new mis-parse where the 4.24 gate can't (unversioned packages).
- Deferred to PR5: streamed blob CONTENTS (index container + vertex + skin buffers), multi-LOD iteration; PR6: exporter.
- Limitations documented: pre-4.24 legacy cooked → `UnsupportedFeature`; unversioned packages can't be cleanly 4.24-gated (rely on strict-bool backstop); only LOD-0 parsed (PR5 adds the rest).
