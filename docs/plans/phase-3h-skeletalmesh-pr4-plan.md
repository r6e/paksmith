# Phase 3h PR4 — cooked `FStaticLODModel` LOD-model wiring — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax. Design: [`phase-3h-skeletalmesh-design.md`](phase-3h-skeletalmesh-design.md); wire ref: [`../formats/mesh/skeletal-mesh.md`](../formats/mesh/skeletal-mesh.md).

**Goal:** Wire the cooked `FStaticLODModel::SerializeRenderItem` LOD records into `read_typed`, filling `Asset::SkeletalMesh.lods` with each LOD's sections + active/required bones for **all LODs**, skipping each LOD's streamed-buffer blob to iterate (PR5 parses the blob contents).

**Architecture:** A new `read_static_lod_model` reads one LOD's *header region* (sections + bones are all ahead of the blob, so fully readable), then skips the blob — inlined LODs by `BuffersSize`, non-inlined by `FByteBulkData` header + a computed availability-info metadata skip. `read_typed` loops `LODModels`, consumes the post-loop tail, and **validates the cursor lands exactly at `total_len`** (the object-GUID tail was already consumed at line 602, so the cooked render data runs to the payload end) — any mismatch → `UnsupportedFeature` (dispatch degrades to `Asset::Generic`) rather than emit a desynced mesh. This cursor-landing check is what makes the unverifiable inlined-`BuffersSize` contract safe: a wrong skip is *detected*, never silently mis-decoded.

**Tech Stack:** Rust; reuse `read_skel_mesh_section_render` (PR3), `FByteBulkData::read_from` (`bulk_data.rs`), `read::read_capped_count`, `wire::{read_strip_data_flags, read_bool32, is_av_data_stripped(new)}`, `custom_version::version_for`, the 4.24 gate (Task 1).

**PR-series:** PR1 (#543), PR2 (#544), PR3 (#546) merged; off-by-one (#545) merged. PR4 (this) = LOD wiring; PR5 = blob contents (index container + vertex + skin buffers, replacing the skip); PR6 = `GltfSkeletalMeshHandler`.

## CRITICAL — the cooked `SerializeRenderItem` order (oracle-verified @ cf74fc32; Task 1 MUST independently re-derive — a single-source 53→54 miss happened last PR)

Per-LOD `FStaticLODModel::SerializeRenderItem` (bool32 = 4-byte int):
1. `FStripDataFlags` (2×u8: global, class — keep both).
2. `bIsLODCookedOut` (bool32).
3. `bInlined` (bool32).
4. `RequiredBones` (i32 count + N×i16, capped).
5. **Gated** on `!wire::is_av_data_stripped(global) && !bIsLODCookedOut`:
   - a. `Sections` (i32 count + N × `read_skel_mesh_section_render`, capped).
   - b. `ActiveBoneIndices` (i32 count + N×i16, capped).
   - c. `BuffersSize` (u32, read **unconditionally** before the inline/bulk split).
   - d. the streamed blob — **SKIP** to iterate: `bInlined` → skip `BuffersSize` bytes; else → `FByteBulkData::read_from` (header; external payload not in-stream) + the computed availability-info metadata skip (Task 1 pins the formula). Sections + bones are all in the header BEFORE the blob, so they're stored for every LOD regardless of inline/bulk.

`LODModels = i32 count + N × SerializeRenderItem` (USkeletalMesh.cs Deserialize, cooked editor-data-stripped branch — the branch `read_typed` already reaches after `bCooked`). Post-loop tail (still in the cooked block, before the payload end): `FNaniteResources` (UE5.5+ — Task 1 pins the gate), then if `UseNewCookedFormat`: `numInlinedLODs` (u8) + `numNonOptionalLODs` (u8).

## THREE load-bearing hazards (Task 1 pins each; no reader code until pinned)
- **(A) UE4.24 `UseNewCookedFormat` gate.** `SerializeRenderItem` is the format ONLY for Game ≥ UE4.24; 4.16–4.23 cooked is `SerializeRenderItem_Legacy` (different layout). `read_typed` admits cooked from ~4.16 (`SplitModelAndRenderData`), so PR4 MUST gate 4.24 and degrade 4.16–4.23 → `UnsupportedFeature`. paksmith's file-version proxies are coarse (`VER_UE4_GAME_UE4_23_OBJECT_PROXY=517`, `_25_=518` — no 4.24). Task 1 pins the discriminator (likely a custom-version, e.g. `FSkeletalMeshCustomVersion` / `FRenderingObjectVersion`, NOT a file-version) against CUE4Parse `VersionContainer.cs`.
- **(B) non-inlined availability-info skip.** Task 1 pins the exact metadata-skip formula (gildor UEViewer `SkipBytes` / CUE4Parse `SerializeAvailabilityInfo`: ~`5 [+5 adjacency if !stripped] + 16 static-vtx + 8 position + 8 color + skin-weight-metadata + cloth-tail`, version-gated).
- **(C) inlined skip-by-`BuffersSize` is UNVERIFIABLE from community source** (may/may-not cover the UE5.x version-gated streamed tail) and paksmith has no real cooked fixture (synthetic → circular). **Deliberate UNVERIFIED contract**, flagged for later real-fixture verification ([[feedback_dont_port_oracle_bugs]] framing). The cursor-landing net (below) is the safety valve.

## SAFETY NET — cursor-landing check
`read_object_guid_tail` is consumed at `read_typed` line ~602 (early), so the cooked render data is the LAST thing in the payload. After the LOD loop + post-loop tail, **`cur.position()` MUST == `total_len`**. If not → `UnsupportedFeature` ("skeletal LOD cursor desync") → dispatch degrades to `Asset::Generic`. Task 1 confirms nothing trails the post-loop tail in the cooked `USkeletalMesh::Serialize` (so `total_len` is the exact target). Layered defenses: an over-skip → EOF → typed `Err`; a mid-iteration desync → the PR3 section reader's strict-bool/cap/sign checks reject → typed `Err`. All → `Generic`, never garbage.

---

## File structure
- **Modify** `crates/paksmith-core/src/asset/wire.rs` — `is_av_data_stripped(global)`.
- **Modify** `crates/paksmith-core/src/asset/version.rs` OR `custom_version.rs` — the 4.24 `UseNewCookedFormat` gate (Task 1 decides which).
- **Modify** `crates/paksmith-core/src/asset/mod.rs` — `SkeletalMeshLod` += `active_bone_indices: Vec<u16>`, `required_bones: Vec<u16>`.
- **Modify** `crates/paksmith-core/src/error.rs` — new faults + wire-field variants.
- **Modify** `crates/paksmith-core/src/asset/exports/mesh/skeletal_mesh.rs` — `read_static_lod_model`, the LOD loop + post-loop tail + cursor-landing net in `read_typed`, caps.
- **Modify** `docs/formats/mesh/skeletal-mesh.md` — the cooked `FStaticLODModel::SerializeRenderItem` record.

All work in `.claude/worktrees/feat+phase-3h-lod-wiring/` (branch `feat/phase-3h-lod-wiring`).

---

## Task 1: Oracle re-verification (no code — record verified facts)

- [ ] **Step 1 — header order (INDEPENDENT re-derive, don't inherit prior passes).** Fetch CUE4Parse `FStaticLODModel.cs` `SerializeRenderItem` + `USkeletalMesh.cs` Deserialize (cooked branch) @ `cf74fc32`. Confirm verbatim: `FStripDataFlags → bIsLODCookedOut(bool32) → bInlined(bool32) → RequiredBones(i32+N×i16) → [if !AVstripped && !cookedOut: Sections(i32+N×section) → ActiveBoneIndices(i32+N×i16) → BuffersSize(u32) → blob]`. Confirm `RequiredBones` is BEFORE `Sections`, `RequiredBones`/`ActiveBoneIndices` are `short`(i16) i32-count arrays, `BuffersSize` is u32 read unconditionally before the inline/bulk split, and `LODModels = i32 count + N`.
- [ ] **Step 2 — hazard A (4.24 gate).** From CUE4Parse `VersionContainer.cs`: `SkeletalMesh.UseNewCookedFormat = Game >= GAME_UE4_24`. Pin how paksmith distinguishes 4.23-legacy from 4.24-new (the 4.24 boundary falls between paksmith's 517/518 proxies). Report the chosen discriminator: a custom-version (which GUID + member) or a new file-version proxy. Confirm what 4.16–4.23 cooked does (degrade).
- [ ] **Step 3 — hazard B (non-inlined availability-info skip).** Pin the exact post-`FByteBulkData`-header metadata skip for a non-inlined LOD: list each addend + its version gate (index meta, adjacency, static-vtx, position, color, skin-weight metadata, cloth tail). Cite gildor UEViewer `UnMesh4.cpp` `SkipBytes` + CUE4Parse `SerializeAvailabilityInfo`. If it can't be pinned confidently, say so (the plan falls back to degrading non-inlined LODs).
- [ ] **Step 4 — post-loop tail + landing target.** Confirm the after-loop sequence (FNaniteResources gate = which custom-version/UE5.5; numInlinedLODs u8 + numNonOptionalLODs u8 when UseNewCookedFormat) AND that NOTHING in the cooked `USkeletalMesh::Serialize` follows it before the payload end (so the cursor-landing target is `total_len`). If something trails, report it.
- [ ] **Step 5 — hazard C.** Confirm `BuffersSize` is the inline streamed-blob byte length; document it can't be proven to cover the UE5.x tail (deliberate unverified contract + the cursor-landing net is the guard).

No commit (verification). The pinned values supersede any "expected" below.

---

## Task 2: Scaffolding — helper, struct fields, 4.24 gate, caps, faults

**Files:** `wire.rs`, `mod.rs`, `version.rs`/`custom_version.rs`, `error.rs`, `skeletal_mesh.rs`

- [ ] **Step 1 — `is_av_data_stripped`** (wire.rs, mirror `is_editor_data_stripped`):
```rust
/// `FStripDataFlags::IsAudioVisualDataStripped` — true when the AV-data bit is
/// set in the GLOBAL strip-flags byte (the cooked skeletal LOD's section/bone
/// block is absent when this is set).
pub(crate) fn is_av_data_stripped(global: u8) -> bool {
    global & STRIP_FLAG_AV_DATA != 0
}
```
Test: bit set/unset, editor-bit-only → false, both → true.
- [ ] **Step 2 — `SkeletalMeshLod` fields** (mod.rs): add `pub active_bone_indices: Vec<u16>,` and `pub required_bones: Vec<u16>,` (doc each; keep `#[non_exhaustive]` + Default). Update the `bone_map` doc ("union of section bone_maps, populated here in PR4"). Add a construction test.
- [ ] **Step 3 — the 4.24 gate** per Task 1: add the const + an `AssetVersion`/ctx helper `uses_new_cooked_format(&ctx)` (or a custom-version check) returning bool, + a pin test.
- [ ] **Step 4 — caps** (skeletal_mesh.rs, value-pinned, NOTE-comment per sibling convention): `MAX_LODS_PER_MESH: usize = 64`, `MAX_REQUIRED_BONES: usize = MAX_BONES_PER_SKELETON`, `MAX_ACTIVE_BONES: usize = MAX_BONES_PER_SKELETON`, `MAX_BUFFERS_SIZE_BYTES: u64 = 512 * 1024 * 1024` (+ `_U32` companions where used by `read_capped_count`).
- [ ] **Step 5 — faults** (error.rs, hand-written Display style): `SkeletalLodCursorDesync { expected: u64, actual: u64 }`, `UnsupportedLegacyCookedSkeletalMesh` (or reuse `UnsupportedFeature`), `BuffersSizeExceeded { size: u64, cap: u64 }`. `AssetWireField`: `SkelLodCount`, `SkelLodRequiredBonesCount`, `SkelLodSectionCount`, `SkelLodActiveBonesCount`, `SkelLodBuffersSize`, `SkelLodCookedOut`, `SkelLodInlined`, `SkelLodNumInlined`, `SkelLodNumNonOptional`. Display pin tests.
- [ ] **Step 6 — commit** `feat(asset): scaffolding for FStaticLODModel wiring (3h)`.

---

## Task 3: `read_static_lod_model` — header + sections + bones (no blob yet)

**Files:** `skeletal_mesh.rs`

- [ ] **Step 1 — failing test.** Build a single inlined LOD payload (strip flags global=0x01 editor-stripped + class, bIsLODCookedOut=0, bInlined=1, RequiredBones[2], then AV-present block: Sections[1] (a minimal section via the PR3 byte layout), ActiveBoneIndices[2], BuffersSize=N, + N blob bytes). Call `read_static_lod_model(&mut cur, ctx, asset_path)` (a `section_ctx`-style ctx with the gates + 4.24-new). Assert the returned `SkeletalMeshLod` has the expected sections.len(), required_bones, active_bone_indices, bone_map (union of section bone_maps) AND full consumption of the LOD record (cursor at end). RED (fn undefined).
- [ ] **Step 2 — implement** `pub(crate) fn read_static_lod_model<R: Read + ?Sized>(r: &mut R, ctx: &AssetContext, asset_path: &str) -> crate::Result<SkeletalMeshLod>`: read strip flags (keep global), `bIsLODCookedOut`=read_bool32, `bInlined`=read_bool32, `RequiredBones`=capped i16 array → Vec<u16> (via `i32::from`/`u16` cast — they're bone indices, store as u16 like ActiveBones; confirm signedness handling in Task 1, UE uses them as indices). If `!is_av_data_stripped(global) && !bIsLODCookedOut`: read `Sections` (capped count + `read_skel_mesh_section_render` loop), `ActiveBoneIndices` (capped i16 array), `BuffersSize` (u32, capped ≤ MAX_BUFFERS_SIZE_BYTES), then the blob skip (Task 4). Populate `bone_map` = dedup-union of the sections' `bone_map`s. Return the LOD. `#[allow(dead_code)]` until Task 5 wires the loop.
- [ ] **Step 3** — run → GREEN. **Step 4 — commit** `feat(asset): FStaticLODModel header + sections + bones reader (3h)`.

---

## Task 4: Blob skip — inlined (`BuffersSize`) + non-inlined (`FByteBulkData` + availability-info)

**Files:** `skeletal_mesh.rs`

- [ ] **Step 1 — inlined skip test.** A LOD with `bInlined=1`, `BuffersSize=K`, K blob bytes → `read_static_lod_model` consumes exactly through the K bytes (cursor at LOD end). Assert. (Reuse the Task-3 `skip_bytes` helper from PR3.)
- [ ] **Step 2 — non-inlined skip test.** A LOD with `bInlined=0`: after `BuffersSize`, a `FByteBulkData` header (build via the `bulk_data.rs` layout: flags with external/non-inline payload so no inline bytes follow) + the availability-info metadata bytes (per Task 1's formula). Assert the cursor consumes header + availability-info and lands at the LOD end. (If Task 1 found the availability-info skip un-pinnable, this task instead implements: non-inlined LOD → return a sentinel/error that Task 5 maps to whole-asset `UnsupportedFeature`; write that test instead and document the bulk-LOD limitation.)
- [ ] **Step 3 — implement** the blob skip inside `read_static_lod_model`: `if bInlined { skip_bytes(r, u64::from(buffers_size), ...) } else { FByteBulkData::read_from(r, asset_path)?; skip_bytes(r, availability_info_size(ctx), ...) }`. `availability_info_size(ctx)` computes the Task-1 formula (version-gated addends). Cap-guard `buffers_size` before the skip.
- [ ] **Step 4** — run → GREEN. **Step 5 — commit** `feat(asset): FStaticLODModel blob skip (inlined + bulk) (3h)`.

---

## Task 5: LOD loop + post-loop tail + 4.24 gate + cursor-landing net in `read_typed`

**Files:** `skeletal_mesh.rs`

- [ ] **Step 1 — failing test.** Extend a full `read_typed` payload (the PR2 prefix through `bCooked`) with `LODModels` (count=2, two inlined LODs) + the post-loop tail (numInlinedLODs, numNonOptionalLODs; FNanite absent for UE4) so the cursor lands at `total_len`. Assert `Asset::SkeletalMesh.lods.len() == 2` with populated sections/bones, AND a separate test where the bytes don't land (an injected wrong `BuffersSize`) → `read_typed` returns `Err(UnsupportedFeature)` (→ Generic). RED.
- [ ] **Step 2 — implement** in `read_typed`, replacing the `lods: Vec::new()` return after `bCooked`:
  - **4.24 gate:** if `!uses_new_cooked_format(ctx)` → `return Err(UnsupportedFeature { context: "pre-UE4.24 legacy cooked skeletal LOD format not supported" })`.
  - `let lod_count = read_capped_count(.. SkelLodCount, MAX_LODS_PER_MESH_U32)?;` loop `read_static_lod_model` → `lods`.
  - post-loop tail: `FNaniteResources` per Task 1 (skip/degrade), `numInlinedLODs`=u8, `numNonOptionalLODs`=u8 (when uses_new_cooked_format).
  - **cursor-landing net:** `if cur.position() != total_len { return Err(UnsupportedFeature { context: "skeletal LOD cursor desync (unverified streamed-blob layout)" }) }` (or the typed `SkeletalLodCursorDesync` fault). Populate `data.lods = lods`.
- [ ] **Step 3** — run → GREEN. **Step 4 — commit** `feat(asset): wire FStaticLODModel LOD loop into read_typed (3h)`.

---

## Task 6: Hardening (gates, caps, degradation, truncation)

**Files:** `skeletal_mesh.rs` (tests + any guard fixes)

- [ ] LOD-count cap, required-bones cap, active-bones cap, BuffersSize cap → each over-cap → typed `Err` (boundary tests).
- [ ] AV-data-stripped LOD (`global` has 0x02) and `bIsLODCookedOut=1` → the section/bone block is absent; the LOD has empty sections/active-bones (just required_bones); cursor consumes only the header. Pin both gates with present/absent pairs.
- [ ] 4.24 degrade: a ctx below the UseNewCookedFormat boundary → `read_typed` → `UnsupportedFeature` (not a mis-parse). 
- [ ] cursor-landing net: an under-skip (wrong small BuffersSize) leaving the cursor < total_len → desync `Err`; an over-skip → EOF `Err`. Both → not an `Ok(SkeletalMesh)`.
- [ ] non-inlined LOD path (Task 4 outcome): either the availability-info skip lands correctly, or → `UnsupportedFeature`. Test it.
- [ ] truncation mid-LOD-record → typed `Err`, no panic.
- [ ] **Commit** `test(asset): FStaticLODModel hardening (3h)`.

---

## Task 7: Gate chain + in-diff cargo-mutants

- [ ] `cargo fmt --all`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`; `cargo test --workspace --all-features`; `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features`; `typos .`; `cargo deny check` — all green.
- [ ] `git diff origin/main -- > /tmp/pr_3h4.diff && cargo mutants --in-diff /tmp/pr_3h4.diff --no-shuffle -j 4 --all-features` → **0 missed, 0 timeout**. Pin survivors (the gate booleans, the caps `>`, the cursor-landing `!=`, the BuffersSize skip multiplier, the post-loop tail u8 reads) with literal-value tests.
- [ ] Commit pins.

---

## Task 8: Doc — cooked `FStaticLODModel::SerializeRenderItem` record

**Files:** `docs/formats/mesh/skeletal-mesh.md`

- [ ] Document the cooked LOD-model record (the field order above), the inline-vs-bulk blob, `BuffersSize`, the post-loop tail, the UE4.24 `UseNewCookedFormat` boundary, and the unverified inlined-`BuffersSize` contract + the cursor-landing guard. Note PR4 stores sections + active/required bones; the blob contents (index/vertex/skin buffers) are PR5. Cite CUE4Parse/UEViewer only (no EpicGames).
- [ ] `typos docs/`. **Commit** `docs(mesh): document cooked FStaticLODModel SerializeRenderItem record (3h)`.

---

## Task 9: Review panel to convergence, then PR

- [ ] **≥5-reviewer panel** on `git diff main..HEAD`: **wire-format** (MUST independently re-derive the header order + the 4.24 gate + both skip formulas + the post-loop tail vs oracle — NOT inherit Task 1), **security** (every count/`BuffersSize` capped before alloc/skip; `skip_bytes` bounded; `FByteBulkData` reuse sound; no panic; the cursor-landing net actually prevents garbage), **deep-impact** (`SkeletalMeshLod` struct growth + the new faults/wire-fields + the `read_typed` extension + the 4.24-gate ripple + the PR5 seam), **code-reviewer**, **simplifier**. Brief adversarially (conf ≥ 70, hunt cold; emphasize the unverified `BuffersSize` contract + whether the landing net is airtight). Re-run the FULL panel each fix round to convergence.
- [ ] **Push + PR.** Marker at the worktree git-dir (SEPARATE Bash call from push; another before `gh pr create`). Title: `feat(asset): wire cooked FStaticLODModel LOD records into USkeletalMesh (Phase 3h PR4)`. PR body notes the all-LODs scope, the unverified inlined-`BuffersSize` contract + the cursor-landing guard, and the bulk-LOD/legacy-4.23 degradations. Monitor `gh pr checks`. **User merges.** No `.pak` fixtures.
- [ ] **Post-merge** — remove worktree + branch, sync main; PR5 (blob contents) gets a fresh worktree + writing-plans pass.

---

## Self-review notes (coverage)
- Oracle re-verification (header order + hazards A/B/C + post-loop tail + landing target) → Task 1, per [[feedback_verify_wire_format_claims]]; the wire-format reviewer re-derives independently (Task 9) given the 53→54 lesson.
- `is_av_data_stripped` + struct fields + 4.24 gate + caps + faults → Task 2. Header+sections+bones reader → Task 3; blob skip (inlined + non-inlined) → Task 4; LOD loop + tail + 4.24 gate + cursor-landing net → Task 5; hardening → Task 6; gates + 0-missed mutants → Task 7; doc → Task 8; panel + PR → Task 9.
- **All-LODs** honored: inlined LODs via `BuffersSize`, non-inlined via `FByteBulkData` + availability-info (or degrade per Task 1). The cursor-landing net + the PR3 section-reader hardening make the unverified `BuffersSize` contract safe-by-detection (desync → `Generic`, never garbage).
- Deferred: blob CONTENTS (index container + vertex + skin buffers) → PR5 (replaces the skip with parse, `BuffersSize` in hand); exporter → PR6.
- Limitations documented: pre-4.24 legacy cooked → `UnsupportedFeature`; (if Task 1 so decides) non-inlined/bulk LOD streaming → `UnsupportedFeature`; the inlined-`BuffersSize` UE5.x-tail coverage is unverified (guarded by the landing net).
