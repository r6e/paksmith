# Phase 3h PR5c — non-inlined (bulk) skeletal LOD path — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax. Design: [`phase-3h-skeletalmesh-design.md`](phase-3h-skeletalmesh-design.md); wire ref: [`../formats/mesh/skeletal-mesh.md`](../formats/mesh/skeletal-mesh.md).

**Goal:** Handle the non-inlined (`bInlined == false`) cooked skeletal LOD — read its `FByteBulkData` header + the `SerializeAvailabilityInfo` metadata skip — so mixed inline/bulk meshes iterate and **parse** (inlined LODs get geometry; bulk LODs are consumed-but-empty) instead of degrading to `Generic`.

**Architecture:** `read_typed`'s non-inlined branch (today: `UnsupportedFeature`) reads `FByteBulkData::read_from` (already consumes the header + any inline payload correctly), and — when `element_count > 0` — skips a byte-exact `SerializeAvailabilityInfo` block off the main archive to land on the next LOD. The bulk LOD's geometry stays empty (external `.ubulk` is genuinely unavailable). The PR5b cursor-landing sentinel still guards the whole-asset total.

**Tech Stack:** Rust; reuse `bulk_data::FByteBulkData::read_from`, `read::{read_capped_count, skip_bytes}`, `wire::is_class_data_stripped` + `STRIP_FLAG_ADJACENCY_DATA`, the version consts (`REMOVING_TESSELLATION`, `ANIM_OBJECT_VERSION_GUID`+`UNLIMITED_BONE_INFLUENCES`/`INCREASE_BONE_INDEX_LIMIT_PER_CHUNK`, `UE5_MAIN_STREAM_OBJECT_VERSION_GUID`+`INCREASED_SKIN_WEIGHT_PRECISION`, `UE5_RELEASE_STREAM_OBJECT_VERSION_GUID`+`ADD_CLOTH_MAPPING_LOD_BIAS`).

**PR-series:** PR1-4 + PR5a + PR5b merged. **PR5c (this) = the non-inlined/bulk LOD path — the LAST parser PR.** PR6 = `GltfSkeletalMeshHandler` (the glTF export + the bone-map remap-at-emit).

## ORACLE-VERIFIED — the non-inlined branch (oracle-BACKED; Task 1 re-derives byte-by-byte)
`FStaticLODModel.cs` `SerializeRenderItem`, the `else`(bInlined==false) branch:
```
var bulk = new FByteBulkData(Ar);                     // header + inline payload (ForceInlinePayload/LazyLoadable/None)
if (bulk.Header.ElementCount > 0 && bulk.Data != null) {
    SerializeStreamedData(tempAr over bulk.Data);     // geometry — paksmith SKIPS (external .ubulk / not captured)
    SerializeAvailabilityInfo(Ar, !IsClassDataStripped(CDSF_AdjacencyData));   // off the MAIN archive
}
```
- **`bulk.Data != null` is FILE-RESOLVABILITY (not wire)** — paksmith can't evaluate it. paksmith gates on **`element_count > 0` ALONE** — a deliberate **UNVERIFIED** contract choice (no non-inlined fixture; the cooker writes availability-info on `ElementCount > 0`, the `&& Data != null` is CUE4Parse's VFS-robustness artifact). Guarded by the PR5b sentinel (a wrong gate → desync → `Generic`, never garbage). Frame honestly ([[feedback_dont_port_oracle_bugs]]).
- **`FByteBulkData::read_from` already does the header + inline-payload consumption** (verified bit-for-bit vs `TBulkData`: header always; `+= SizeOnDisk` iff `ForceInlinePayload`/exact-`LazyLoadable`/exact-`None`). So PR5c's ONLY net-new in-stream work is `SerializeAvailabilityInfo`.
- **Geometry stays EMPTY for bulk LODs** (external `.ubulk` unavailable; the rare inline-payload case needs a `read_from` payload-capture change — a future enhancement, out of scope).

## `SerializeAvailabilityInfo` — byte-EXACT (no seek to re-sync; must be exact or the next LOD desyncs → sentinel → Generic)
**Constant `bytes_to_skip`:** `5` (FMultiSizeIndexContainer index meta `1+4`) + [if `version_for(UE5_RELEASE_STREAM_OBJECT_VERSION_GUID).is_none_or(|v| v < REMOVING_TESSELLATION)` (UE4: absent → true) `&& !is_class_data_stripped(lod_class, STRIP_FLAG_ADJACENCY_DATA)`: `5` (adjacency meta)] + `16` (FStaticMeshVertexBuffer meta) + `8` (FPositionVertexBuffer meta) + `8` (FColorVertexBuffer meta) + `skin_weight_metadata_size(ctx)`.
- **`skin_weight_metadata_size`** (derive from the SAME custom-version comparisons `read_skin_weight_vertex_buffer` uses — anti-drift, NOT a UE-version table): `new = version_for(ANIM_OBJECT_VERSION_GUID) >= UNLIMITED_BONE_INFLUENCES(5)`. `!new` → **12** (UE4.24). `new` → `16 + (version_for(ANIM_OBJECT_VERSION_GUID) >= INCREASE_BONE_INDEX_LIMIT_PER_CHUNK(4) ? 4 : 0) + (version_for(UE5_MAIN_STREAM_OBJECT_VERSION_GUID) >= INCREASED_SKIN_WEIGHT_PRECISION(90) ? 4 : 0) + 4` → **24** for UE4.25-4.27 (the UE5 precision term is +0). (The `!UseNewCookedFormat → 8` branch can't fire — the 4.24 gate passed — omit it.)

**Then LIVE count-driven reads (off the main archive, capped before each skip):**
1. **Cloth** — gated `sections.iter().any(|s| s.has_cloth_data)`: `num = read_capped_count(.. MAX_CLOTH_VERTS_PER_LOD)`; `skip num*8`; `skip 8`; `if version_for(UE5_RELEASE_STREAM_OBJECT_VERSION_GUID) >= ADD_CLOTH_MAPPING_LOD_BIAS(15): skip 4*num` (UE5-only, never UE4).
2. **SkinWeightProfiles** — UNCONDITIONAL: `count = read_capped_count(.. MAX_SKIN_PROFILES)`; `skip count*8` (N×FName = NameIndex i32 + Number i32).
3. **ray-tracing** — `HasRayTracingData && Game≥UE5.6` → never fires for UE4; OMIT (a UE5.6 asset reaching here desyncs → sentinel → Generic).

`bAdjacencyData` uses the LOD **outer-strip CLASS byte** — `read_static_lod_model` reads `(global, _class)` and discards `_class`; PR5c surfaces it.

---

## File structure
- **Modify** `crates/paksmith-core/src/asset/exports/mesh/skeletal_mesh.rs` — `LodHeader` += `class_strip`; `read_static_lod_model` surfaces it; `skip_availability_info`; the non-inlined branch in `read_typed`.
- **Modify** `crates/paksmith-core/src/error.rs` — new wire-field variants + a `MAX_SKIN_PROFILES` cap.
- **Modify** `docs/formats/mesh/skeletal-mesh.md` — the non-inlined branch + the availability-info skip + the empty-geometry/ElementCount limitations.

All work in `.claude/worktrees/feat+phase-3h-lod-bulk/` (branch `feat/phase-3h-lod-bulk`).

---

## Task 1: Oracle re-verification (no code)

- [ ] **Step 1 — the non-inlined branch + the ElementCount gate.** Re-fetch CUE4Parse `FStaticLODModel.cs` `SerializeRenderItem` else-branch + the `TBulkData`/`FByteBulkData` ctor @ `cf74fc32`. Confirm: `SerializeAvailabilityInfo` is inside `if (ElementCount > 0 && Data != null)`; `Data != null` is file-resolvability; `read_from`'s in-stream advance matches `TBulkData` (header always; `+= SizeOnDisk` only for the inline-payload flags). Confirm paksmith's `element_count > 0`-only gate framing.
- [ ] **Step 2 — `SerializeAvailabilityInfo` byte formula.** Fetch the verbatim method. Confirm every addend (5 / [5 adj] / 16 / 8 / 8 / MetadataSize) + the live cloth block (`num*8 + 8 [+ 4*num UE5]`) + the unconditional profiles FName array (`count` + `count*8`) + the UE5.6 ray-tracing `6*4`. Confirm the adjacency gate (`FUE5ReleaseStreamObjectVersion < RemovingTessellation && bAdjacencyData`).
- [ ] **Step 3 — `FSkinWeightVertexBuffer.MetadataSize`.** Fetch verbatim. Confirm `!UseNewCookedFormat → 8` (never fires), `!bNewWeightFormat → 12`, `bNewWeightFormat → 16 + IncreaseBoneIndexLimit?4 + IncreasedSkinWeightPrecision?4 + 4`. Confirm UE4.24 = 12, UE4.25-4.27 = 24. Confirm the bytes do NOT include the strip-flag pairs (metadata-only).
- [ ] **Step 4 — class-byte + FName size.** Confirm `bAdjacencyData = !stripDataFlags.IsClassDataStripped(CDSF_AdjacencyData=1)` (the LOD outer-strip class byte) + that a serialized `FName` here is 8 bytes (NameIndex i32 + Number i32).

No commit. Surfaced facts supersede the plan.

---

## Task 2: Surface the LOD class byte into `LodHeader`

**Files:** `skeletal_mesh.rs`

- [ ] **Step 1: Failing test.** Update a `read_static_lod_model_*` test to assert `header.class_strip` equals the class byte written in its strip-flags. RED (field doesn't exist).
- [ ] **Step 2: Implement.** Add `pub class_strip: u8` to `LodHeader`; in `read_static_lod_model` keep the strip-flags `class` byte (rename `_class` → `class_strip`) and set it on the returned header (it's read at the top regardless of `block_present`). Update all callers/tests.
- [ ] **Step 3: Run** → PASS. **Step 4: Commit** `refactor(asset): surface LOD class strip byte from the header reader (3h)`.

---

## Task 3: `skip_availability_info`

**Files:** `skeletal_mesh.rs`, `error.rs`

- [ ] **Step 1: Faults/cap.** error.rs: `AssetWireField::{SkelLodBulkClothCount, SkelLodSkinProfileCount}` (snake_case Display + pin tests). skeletal_mesh.rs: `MAX_SKIN_PROFILES: usize = 256` (+ `_U32`), value-pinned (mirror the sibling cap convention).
- [ ] **Step 2: Failing test.** `skip_availability_info_modern_no_cloth`: build the exact availability-info bytes for a UE4.25+ ctx (new format), NO cloth section: `bytes_to_skip = 5 + 5(adjacency, class=0 not stripped, UE4) + 16 + 8 + 8 + 24 = 66` constant bytes, then profiles `count=0` (i32). Call `skip_availability_info(&mut cur, ctx, asset_path, &[], 0)` and assert the cursor consumed exactly `66 + 4`. RED (fn undefined).
- [ ] **Step 3: Implement** `fn skip_availability_info<R: Read + ?Sized>(r: &mut R, ctx: &AssetContext, asset_path: &str, sections: &[SkelMeshSection], lod_class: u8) -> crate::Result<()>`:
  - compute `bytes_to_skip` per the formula (with `skin_weight_metadata_size(ctx)` as a small helper using the `version_for` comparisons); `read::skip_bytes(r, bytes_to_skip as u64, ...)`.
  - cloth: `if sections.iter().any(|s| s.has_cloth_data) { let num = read::read_capped_count(.. SkelLodBulkClothCount, MAX_CLOTH_VERTS_PER_LOD_U32)?; read::skip_bytes(r, u64::from(num)*8 + 8, ...)?; if version_for(UE5_RELEASE..) >= ADD_CLOTH_MAPPING_LOD_BIAS { read::skip_bytes(r, u64::from(num)*4, ...)?; } }`.
  - profiles: `let count = read::read_capped_count(.. SkelLodSkinProfileCount, MAX_SKIN_PROFILES_U32)?; read::skip_bytes(r, u64::from(count)*8, ...)?;`
  - (no ray-tracing; UE5.6-only.) `#[allow(dead_code)]` until Task 4 wires it.
- [ ] **Step 4: Run** → PASS. Add `skip_availability_info_legacy_metadata_12` (UE4.24 → metadata 12) + `_with_cloth` (a section with `has_cloth_data` → the cloth block consumed) + `_adjacency_class_stripped` (class has 0x01 → the 5 adjacency bytes ABSENT). **Step 5: Commit** `feat(asset): FStaticLODModel SerializeAvailabilityInfo skip (3h)`.

---

## Task 4: Wire the non-inlined branch in `read_typed`

**Files:** `skeletal_mesh.rs`

- [ ] **Step 1: Failing test.** Build a multi-LOD payload: LOD[0] inlined (geometry), LOD[1] NON-INLINED (`bInlined=0`, block present) = header + FByteBulkData header (element_count>0, external/non-inline payload flags so no inline bytes) + the availability-info bytes, then the post-loop tail landing at total_len. Assert `lods.len()==2`, LOD[0] geometry populated, LOD[1] geometry EMPTY (positions/indices empty) but sections/bones present, `Ok`. RED (currently `UnsupportedFeature`).
- [ ] **Step 2: Implement.** Replace the non-inlined `return Err(UnsupportedFeature{...})` with:
```rust
} else {
    // Non-inlined (bulk) LOD: FByteBulkData header (+ inline payload, handled by
    // read_from), then SerializeAvailabilityInfo when the bulk is non-empty. The
    // streamed geometry is in the bulk payload (external .ubulk / not captured) →
    // this LOD's geometry stays empty. The `element_count > 0` gate is paksmith's
    // wire-deterministic subset of CUE4Parse's `ElementCount > 0 && Data != null`
    // (see the UNVERIFIED note); the post-loop sentinel guards a wrong skip.
    let bulk = FByteBulkData::read_from(&mut cur, asset_path)?;
    if bulk.element_count > 0 {
        skip_availability_info(&mut cur, ctx, asset_path, &header.lod.sections, header.class_strip)?;
    }
}
```
(`header.lod.sections` — the inlined branch clones it for read_streamed_data; here a borrow is fine since read_streamed_data isn't called. Confirm the borrow checker is happy; clone if needed.)
- [ ] **Step 3: Run** → PASS. **Step 4: Commit** `feat(asset): parse non-inlined (bulk) skeletal LODs via availability-info skip (3h)`.

---

## Task 5: Hardening

**Files:** `skeletal_mesh.rs` (tests + guards)

- [ ] `skin_weight_metadata_size` version cases: UE4.24 (12) vs UE4.25+ (24) — boundary pins (FAnimObjectVersion `UnlimitedBoneInfluences-1` vs `=5`); the IncreaseBoneIndexLimit term.
- [ ] The adjacency gate: class-stripped (0x01 set) → 5 fewer bytes; not-stripped → +5. Present/absent pair.
- [ ] Cloth: a section with `has_cloth_data` → the cloth block consumed (num*8+8); no cloth section → skipped. Over-cap cloth `num` → typed `Err`.
- [ ] Profiles: count==0 (4 bytes) vs count>0 (4 + count*8); over-cap count → `Err`.
- [ ] `element_count == 0` bulk → header-only, NO availability-info (cursor stops after the header).
- [ ] Multi-LOD: an inlined + a non-inlined LOD both parse; the post-loop sentinel still lands at total_len; a wrong availability-info skip (inject extra bytes) → desync `Err` → Generic.
- [ ] Truncation mid-availability-info → typed `Err`, no panic.
- [ ] **Commit** `test(asset): non-inlined LOD + availability-info hardening (3h)`.

---

## Task 6: Gate chain + in-diff cargo-mutants

- [ ] `cargo fmt --all`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`; `cargo test --workspace --all-features`; `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features`; `typos .`; `cargo deny check` — all green.
- [ ] `git diff origin/main -- > /tmp/pr_3h5c.diff && cargo mutants --in-diff /tmp/pr_3h5c.diff --no-shuffle -j 4 --all-features` → **0 missed, 0 timeout**. Pin survivors (the metadata-size version branches, the adjacency `&&`/gate, the `num*8`/`count*8` multipliers, the `element_count > 0` guard, the cloth `any` predicate).
- [ ] Commit pins.

---

## Task 7: Doc

**Files:** `docs/formats/mesh/skeletal-mesh.md`

- [ ] Document the non-inlined LOD branch: `FByteBulkData` header + (when `element_count > 0`) `SerializeAvailabilityInfo` (the byte-exact constant + the cloth/profiles live reads + `MetadataSize` 12/24). Note: paksmith gates on `element_count > 0` alone (CUE4Parse's `&& Data != null` is file-resolvability — an UNVERIFIED contract guarded by the sentinel); bulk-LOD geometry stays empty (external `.ubulk` unavailable; inline-payload geometry parse is a future enhancement). Cite CUE4Parse only.
- [ ] `typos docs/`. **Commit** `docs(mesh): document non-inlined skeletal LOD + availability-info skip (3h)`.

---

## Task 8: Review panel to convergence, then PR

- [ ] **≥5-reviewer panel** on `git diff main..HEAD`: **wire-format** (MUST independently re-derive the SerializeAvailabilityInfo byte formula + MetadataSize 12/24 + the cloth/profiles live reads + the adjacency class-byte gate + the ElementCount-gate framing vs CUE4Parse@cf74fc32 — NOT inherit Task 1; this skip is byte-exact + oracle-backed, so verify every addend), **security** (cloth `num` + profiles `count` capped before each skip; `num*8`/`count*8` no-overflow (checked/u64); `skip_bytes` bounded; the FByteBulkData header caps hold; truncation → Err; no panic/OOM; the sentinel catches a wrong skip), **deep-impact** (the `LodHeader.class_strip` addition + callers; the non-inlined branch replacing UnsupportedFeature — observable: bulk-LOD meshes now parse-empty instead of Generic, is that the right call + documented?; the ElementCount-unverified-gate honesty; the PR6 seam), **code-reviewer**, **simplifier**. Brief adversarially (conf ≥ 70, hunt cold; emphasize the byte-exact formula + the ElementCount-unverified gate). Re-run the FULL panel each fix round to convergence.
- [ ] **Push + PR.** Marker at the worktree git-dir (SEPARATE Bash call from push; another before `gh pr create`). Title: `feat(asset): parse non-inlined (bulk) skeletal LODs (Phase 3h PR5c)`. PR body: the non-inlined scope, the byte-exact oracle-backed availability-info skip, the `element_count > 0` UNVERIFIED gate + sentinel guard, the empty-bulk-geometry + inline-payload-deferred limitations, the completeness win (mixed inline/bulk meshes parse). Monitor `gh pr checks`. **User merges.** No `.pak` fixtures.
- [ ] **Post-merge** — remove worktree + branch, sync main; PR6 (the glTF exporter — the payoff) gets a fresh worktree + writing-plans pass. **The skeletal-mesh PARSER is complete after PR5c.**

---

## Self-review notes (coverage)
- Oracle re-verification (the byte-exact formula + MetadataSize + the ElementCount gate + the class byte) → Task 1, per [[feedback_verify_wire_format_claims]]; wire-format reviewer re-derives every addend in Task 8.
- `LodHeader.class_strip` → Task 2. `skip_availability_info` → Task 3. The non-inlined wiring → Task 4. Hardening → Task 5; gates + 0-missed mutants → Task 6; doc → Task 7; panel + PR → Task 8.
- The availability-info skip is **byte-exact + oracle-backed** (every addend is a constant or a capped live count with an explicit span); the ONLY unverified bit is the `element_count > 0` gate (vs CUE4Parse's `&& Data != null` file-resolvability) — documented + sentinel-guarded.
- Deferred (documented): bulk-LOD geometry stays empty (external `.ubulk`); inline-payload bulk geometry parse needs a `read_from` payload-capture change → a future enhancement. The bone-map remap + the glTF exporter → PR6. **PR5c completes the skeletal-mesh parser.**
