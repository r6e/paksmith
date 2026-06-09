# Phase 3h PR5b — multi-LOD iteration (inlined) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax. Design: [`phase-3h-skeletalmesh-design.md`](phase-3h-skeletalmesh-design.md); wire ref: [`../formats/mesh/skeletal-mesh.md`](../formats/mesh/skeletal-mesh.md).

**Goal:** Iterate and parse **all inlined LODs** of a cooked `USkeletalMesh` (PR5a parsed only LOD[0]), consume the post-loop tail, and validate a cursor-landing sentinel — so `Asset::SkeletalMesh.lods` carries every inlined LOD's geometry.

**Architecture:** `read_typed` loops over `LODModels`. For each inlined LOD it records `blob_start`, parses the streamed blob through `FSkinWeightProfilesData` (`read_streamed_data` stops there — it does NOT read the version-gated ray-tracing / UE5 tail, whose gate is out-of-band and can't be parsed reliably), then **seeks `blob_start + BuffersSize`** to reach the next LOD — the seek skips the unread tail, re-syncing for both 4.26 (no tail) and 4.27 (tail present). After the loop it consumes the tail (`numInlinedLODs`/`numNonOptionalLODs` + `dummyObjs`) and asserts `cursor == total_len`; any mismatch → degrade to `Generic`. Non-inlined LODs → `UnsupportedFeature` (PR5c).

**Tech Stack:** Rust; the seek happens in `read_typed` (holds a `Cursor`, which is `Seek`); the readers stay `R: Read`. Reuse `read::{read_capped_count, read_u8, read_i32}`, `package_index::read_package_index`, `custom_version::version_for`.

**PR-series (now ~8):** PR1-4 + PR5a + off-by-one merged. **PR5b (this) = inlined multi-LOD iteration; PR5c = the non-inlined (FByteBulkData) path; PR7 = `GltfSkeletalMeshHandler`** (the bone-map LOD-local→global remap happens at glTF emit). Tell the user.

## THE BuffersSize SEEK (user-accepted, unverified, sentinel-guarded)
CUE4Parse reads the inlined blob off the main archive and relies on structurally-correct parsing — including the version-gated ray-tracing tail — to land on LOD[i+1]. That tail gate (`HasRayTracingData = Game≥UE4.27/UE4.25_Plus`) is **out-of-band**: UE4.26 and 4.27 share `file_version_ue4 = 522`, so paksmith can't gate it correctly in-band. So instead of relying on a correct tail parse, paksmith **seeks `blob_start + BuffersSize`** to reach the next LOD. The streamed geometry buffers come BEFORE the fragile tail, so `read_streamed_data` still populates them; the seek then re-syncs regardless of tail-parse fragility. **`BuffersSize`-as-blob-length is UNVERIFIED** (CUE4Parse discards it; paksmith has no real cooked fixture) — a deliberate contract guarded by the cursor-landing sentinel: a wrong seek desyncs → `Generic`, never garbage. ([[feedback_dont_port_oracle_bugs]] framing.)

## POST-LOOP TAIL (UE4.24-4.27, oracle-verified order; Task 1 re-confirms)
After the LOD loop, before the payload end (the object-GUID tail was consumed EARLY at read_typed line ~1076, so segment-2 runs to `total_len`):
1. `numInlinedLODs` (u8) + `numNonOptionalLODs` (u8) — gated `useNewCookedFormat` (always true; the 4.24 gate passed). Read + discard 2 bytes.
2. `dummyObjs` — `i32 count` (capped) + `count × FPackageIndex` (`read_package_index`, discard).
3. UV-channel skip — `if version_for(RENDERING_OBJECT_VERSION_GUID).is_some_and(|v| v < TEXTURE_STREAMING_MESH_UV_CHANNEL_DATA(10))` → `SkipFixedArray(4)` (i32 count + count×4). **Use `is_some_and`, NOT `is_none_or`** (absent → don't fire, matching CUE4Parse's cooked Game-map fallback ≥10). The 4.24 gate guarantees present→≥36>10, so this is effectively a **no-op** for paksmith's range — kept for cursor-math completeness.
4. `FNaniteResources` [Game≥UE5.5] — does NOT fire for UE4. A UE5.5+ asset → the sentinel catches the desync → `Generic`. Don't read it.

## CURSOR-LANDING SENTINEL
After the loop + tail: `if cur.position() != total_len { return Err(<SkeletalLodCursorDesync / UnsupportedFeature>) }` → dispatch degrades to `Asset::Generic`. The safety net for the unverified seek + tail fragility.

---

## File structure
- **Modify** `crates/paksmith-core/src/asset/exports/mesh/skeletal_mesh.rs` — `read_static_lod_model` return → a `LodHeader` struct surfacing `buffers_size`/`inlined`/`block_present`; the LOD loop + seek + post-loop tail + sentinel in `read_typed`; the ray-tracing note.
- **Modify** `crates/paksmith-core/src/error.rs` — new faults + wire-fields.
- **Modify** `docs/formats/mesh/skeletal-mesh.md` — the LOD loop + the BuffersSize seek + the post-loop tail + the ray-tracing note update.

All work in `.claude/worktrees/feat+phase-3h-lod-iteration/` (branch `feat/phase-3h-lod-iteration`).

---

## Task 1: Oracle re-verification (no code)

- [ ] **Step 1 — the LOD loop + tail order.** Re-fetch CUE4Parse `USkeletalMesh.cs` Deserialize (cooked branch) @ `cf74fc32`. Confirm `LODModels = i32 count; for each SerializeRenderItem`, and the post-loop order: `numInlinedLODs`(u8)+`numNonOptionalLODs`(u8) [useNewCookedFormat] → `dummyObjs`(i32+N×FPackageIndex) → UV-channel `SkipFixedArray(4)` [FRenderingObjectVersion < TextureStreamingMeshUVChannelData] → `FNaniteResources`[Game≥UE5.5]. Confirm which fire for UE4.24-4.27 (only numInlined/numNonOptional + dummyObjs).
- [ ] **Step 2 — the BuffersSize seek.** Confirm `BuffersSize` (the u32 read at FStaticLODModel.cs after ActiveBoneIndices, before the inline/bulk split) is the inlined streamed-blob byte length — note it CANNOT be proven from source (CUE4Parse discards it via `Ar.Position += 4` and parses structurally). Frame as a deliberate UNVERIFIED contract guarded by the sentinel. Confirm the inlined blob is the same data whether read structurally or seeked-past.
- [ ] **Step 3 — the sentinel target.** Confirm nothing in the cooked `USkeletalMesh::Serialize` follows the post-loop tail before the export payload end (so `total_len` is the sentinel target; the object-GUID tail is consumed early in paksmith). If something trails, report it.
- [ ] **Step 4 — the ray-tracing gate (resolution).** Confirm `HasRayTracingData` is Game-enum-gated (UE4.26/4.27 share file-version 522 → not in-band distinguishable). PR5b R1 REMOVED the in-blob ray-tracing read entirely: `read_streamed_data` stops after `FSkinWeightProfilesData` and does NOT read the version-gated tail; the `blob_start + BuffersSize` seek skips it, re-syncing for BOTH 4.26 (no tail → no-op seek) and 4.27 (tail present → seek jumps it). Keeping a version-gated read would mis-fire on 4.26 (which lacks the tail) → mis-read the next LOD's header as a spurious count → desync.
- [ ] **Step 5 — non-inlined degrade.** Confirm a non-inlined LOD (`bInlined==false`, block present) is the FByteBulkData path (PR5c); PR5b degrades the whole asset to `UnsupportedFeature`.

No commit. Surfaced facts supersede the plan.

---

## Task 2: `read_static_lod_model` → `LodHeader` (surface buffers_size + inlined + block_present)

**Files:** `crates/paksmith-core/src/asset/exports/mesh/skeletal_mesh.rs`

- [ ] **Step 1: Failing test.** Update an existing `read_static_lod_model_*` test to destructure the new return and assert `header.buffers_size` (for the inlined case, the u32 written) + `header.inlined` + `header.block_present`. RED (struct doesn't exist / tuple shape changed).
- [ ] **Step 2: Implement.** Add:
```rust
/// Header-region result of [`read_static_lod_model`]: the partial LOD plus the
/// signals `read_typed` needs to iterate (inline/bulk split + the blob byte
/// length for the BuffersSize seek).
pub(crate) struct LodHeader {
    pub lod: SkeletalMeshLod,
    /// `bInlined` — the streamed blob is inline (vs an external `FByteBulkData`).
    pub inlined: bool,
    /// `!IsAudioVisualDataStripped && !bIsLODCookedOut` — the section/bone block
    /// (and `BuffersSize` + the blob) are on the wire.
    pub block_present: bool,
    /// `BuffersSize` — the inlined streamed-blob byte length (0 when no block).
    pub buffers_size: u32,
}
```
Change `read_static_lod_model` to return `crate::Result<LodHeader>`: keep `buffers_size` (read at the current `_buffers_size` site → store it; 0 when no block); `inlined` (already read); `block_present = !av_stripped && !is_lod_cooked_out`. (`blob_present` = `inlined && block_present` is now computed at the call site.) Update ALL callers (read_typed + the `read_static_lod_model_*` tests) to the struct.
- [ ] **Step 3: Run** → PASS. **Step 4: Commit** `refactor(asset): surface BuffersSize + inline/block flags from LOD header reader (3h)`.

---

## Task 3: The LOD loop + seek + non-inlined degrade in `read_typed`

**Files:** `skeletal_mesh.rs`

- [ ] **Step 1: Failing test.** Extend a full `read_typed` payload with `LODModels` count=2 + two inlined LOD records (each: header + a full streamed blob whose byte length == the LOD's `BuffersSize`) + the post-loop tail (so the cursor lands at `total_len`). Assert `lods.len() == 2` with BOTH LODs' geometry populated (positions/indices/bone_indices). RED (read_typed reads only LOD[0]).
- [ ] **Step 2: Implement** the loop in `read_typed` (replace the single LOD[0] read after `lod_count`):
```rust
use std::io::{Seek, SeekFrom};
let mut lods = Vec::with_capacity(0); // grow; lod_count already capped
for _ in 0..lod_count {
    let mut header = read_static_lod_model(&mut cur, ctx, asset_path)?;
    if header.block_present {
        if header.inlined {
            let blob_start = cur.position();
            let sections = header.lod.sections.clone();
            read_streamed_data(&mut cur, ctx, asset_path, b_has_vertex_colors, &sections, &mut header.lod)?;
            // Re-sync to the next LOD via the (unverified) BuffersSize bound,
            // bounded by total_len so a hostile size can't seek past the payload.
            let target = blob_start
                .checked_add(u64::from(header.buffers_size))
                .filter(|t| *t <= total_len)
                .ok_or_else(|| read::fault(asset_path, AssetParseFault::SkeletalLodCursorDesync { position: blob_start, expected: total_len }))?;
            cur.seek(SeekFrom::Start(target)).map_err(|_| read::fault(asset_path, AssetParseFault::SkeletalLodCursorDesync { position: blob_start, expected: total_len }))?;
        } else {
            return Err(PaksmithError::UnsupportedFeature {
                context: "non-inlined (bulk) skeletal LOD streaming not yet supported".into(),
            });
        }
    }
    lods.push(header.lod);
}
data.lods = lods;
```
(`b_has_vertex_colors` is already computed above the loop. The seek target is bounded `≤ total_len` — not a wild seek.)
- [ ] **Step 3: Run** → PASS. Add a test: a non-inlined LOD (`bInlined=0`, block present) → `Err(UnsupportedFeature)`. **Step 4: Commit** `feat(asset): iterate all inlined skeletal LODs via BuffersSize seek (3h)`.

---

## Task 4: Post-loop tail + cursor-landing sentinel

**Files:** `skeletal_mesh.rs`

- [ ] **Step 1: Failing test.** The Task-3 multi-LOD test's payload must include the tail (`numInlinedLODs` u8 + `numNonOptionalLODs` u8 + `dummyObjs` i32 count + N×FPackageIndex) so the cursor lands at `total_len`. Add a test where the bytes DON'T land (a wrong `BuffersSize`) → `read_typed` returns `Err` (→ Generic). RED if the tail/sentinel aren't implemented.
- [ ] **Step 2: Implement** after the loop, before `Ok(...)`:
```rust
// Post-loop tail (cooked, UseNewCookedFormat). FNaniteResources (UE5.5+) does
// not fire for UE4.24-4.27; a UE5.5+ asset desyncs into the sentinel below.
let _num_inlined = read::read_u8(&mut cur, asset_path, AssetWireField::SkelLodNumInlined)?;
let _num_non_optional = read::read_u8(&mut cur, asset_path, AssetWireField::SkelLodNumNonOptional)?;
let dummy_count = read::read_capped_count(&mut cur, asset_path, AssetWireField::SkelDummyObjCount, MAX_LODS_PER_MESH_U32 /* a sane bound; dummyObjs is tiny on cooked */)?;
for _ in 0..dummy_count {
    let _ = package_index::read_package_index(&mut cur, asset_path)?;
}
// UV-channel skip: only when FRenderingObjectVersion is PRESENT and < 10 (the
// 4.24 gate already guarantees present => >=36, so this never fires for our
// range; is_some_and so absent does not fire either). Kept for cursor-math.
if ctx.custom_versions.version_for(RENDERING_OBJECT_VERSION_GUID)
    .is_some_and(|v| v < TEXTURE_STREAMING_MESH_UV_CHANNEL_DATA)
{
    let n = read::read_capped_count(&mut cur, asset_path, AssetWireField::SkelUvChannelSkipCount, MAX_LODS_PER_MESH_U32)?;
    let _ = read::skip_bytes(&mut cur, u64::from(n) * 4, asset_path, AssetWireField::SkelUvChannelSkipCount)?;
}
// Sentinel: segment-2 runs to the payload end (object-GUID tail consumed early).
if cur.position() != total_len {
    return Err(read::fault(asset_path, AssetParseFault::SkeletalLodCursorDesync { position: cur.position(), expected: total_len }));
}
```
(Pick a real cap for `dummyObjs`; `read_package_index` discards. `read::skip_bytes` exists (PR5a relocated it). `TEXTURE_STREAMING_MESH_UV_CHANNEL_DATA = 10` exists from PR2.)
- [ ] **Step 3: Run** → PASS. **Step 4: Commit** `feat(asset): consume skeletal post-loop tail + cursor-landing sentinel (3h)`.

---

## Task 5: Faults/wire-fields + the ray-tracing note update

**Files:** `error.rs`, `skeletal_mesh.rs`, `docs/formats/mesh/skeletal-mesh.md`

- [ ] **Step 1: Faults/wire-fields.** Add `AssetParseFault::SkeletalLodCursorDesync { position: u64, expected: u64 }` (hand-written Display) + `AssetWireField` variants `SkelLodNumInlined`, `SkelLodNumNonOptional`, `SkelDummyObjCount`, `SkelUvChannelSkipCount`. Display pin tests for each.
- [ ] **Step 2: Ray-tracing note.** Update the UNVERIFIED ray-tracing-gate comment in `read_streamed_data` (skeletal_mesh.rs) + the `skeletal-mesh.md` ray-tracing row: it's NO LONGER a desync hazard for iteration — the BuffersSize seek re-syncs past it; the in-blob best-effort parse only affects (unused) tail bytes, never the geometry. Keep the "is_ue4_27_or_later over-approximates 4.26" note but reframe as "harmless under the seek".
- [ ] **Step 3: Commit** `feat(asset): cursor-desync fault + reframe ray-tracing note under the seek (3h)`.

---

## Task 6: Hardening

**Files:** `skeletal_mesh.rs` (tests + guards)

- [ ] LOD-count cap (over-cap → Err); `dummyObjs` cap; the seek bound (`buffers_size` making `blob_start + size > total_len` → `SkeletalLodCursorDesync`, NOT a wild seek).
- [ ] Multi-LOD: count==1 (one LOD), count==2 (both geometry populated), count==0 (empty `lods`, tail still consumed). An av-stripped/cooked-out LOD mid-list (no blob, no seek) → empty geometry, iteration continues.
- [ ] Non-inlined LOD → `UnsupportedFeature`.
- [ ] Sentinel: under-skip (cursor < total_len, trailing bytes) → desync `Err`; over-skip / wrong BuffersSize (cursor overshoots or seek target > total_len) → `Err`. Both → not `Ok(SkeletalMesh)`.
- [ ] The seek re-sync: a LOD whose streamed blob is mis-parsed in the (unread) tail region but whose `BuffersSize` is correct → iteration still lands on the next LOD (the seek ignores the tail). A test that proves the seek, not the structural parse, drives iteration.
- [ ] Truncation mid-loop / mid-tail → typed `Err`, no panic.
- [ ] **Commit** `test(asset): multi-LOD iteration + seek + sentinel hardening (3h)`.

---

## Task 7: Gate chain + in-diff cargo-mutants

- [ ] `cargo fmt --all`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`; `cargo test --workspace --all-features`; `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features`; `typos .`; `cargo deny check` — all green.
- [ ] `git diff origin/main -- > /tmp/pr_3h5b.diff && cargo mutants --in-diff /tmp/pr_3h5b.diff --no-shuffle -j 4 --all-features` → **0 missed, 0 timeout**. Pin survivors (the seek bound `<= total_len`, the sentinel `!=`, the loop guard, the is_some_and UV gate, the block_present/inlined branch, the tail u8 reads).
- [ ] Commit pins.

---

## Task 8: Doc

**Files:** `docs/formats/mesh/skeletal-mesh.md`

- [ ] Document the LOD loop (`LODModels` = i32 count + N records), the BuffersSize seek (with the UNVERIFIED contract + the sentinel), the post-loop tail (numInlined/numNonOptional + dummyObjs + the no-op UV skip + FNanite), and the cursor-landing sentinel. Note PR5b = inlined LODs; non-inlined → PR5c; bone-map remap → PR7. Cite CUE4Parse/UEViewer only.
- [ ] `typos docs/`. **Commit** `docs(mesh): document skeletal multi-LOD iteration + BuffersSize seek (3h)`.

---

## Task 9: Review panel to convergence, then PR

- [ ] **≥5-reviewer panel** on `git diff main..HEAD`: **wire-format** (MUST independently re-derive the LOD loop + the post-loop tail order + the sentinel target + the BuffersSize-seek framing vs CUE4Parse@cf74fc32 — NOT inherit Task 1; confirm the UV-skip `is_some_and` gate + that nothing trails the tail), **security** (the seek is bounded `≤ total_len` — no wild/backward seek; every count capped; the sentinel actually catches desync → Generic; no panic/OOM; truncation → Err), **deep-impact** (the `LodHeader` struct return + all callers; the read_typed loop replacing the single read; the new faults; the PR5c/PR7 seam; the unverified-contract framing is honest), **code-reviewer**, **simplifier**. Brief adversarially (conf ≥ 70, hunt cold; emphasize the unverified BuffersSize seek + whether the sentinel is airtight). Re-run the FULL panel each fix round to convergence.
- [ ] **Push + PR.** Marker at the worktree git-dir (SEPARATE Bash call from push; another before `gh pr create`). Title: `feat(asset): iterate all inlined skeletal LODs (Phase 3h PR5b)`. PR body: the multi-LOD scope, the BuffersSize-seek unverified contract + the cursor-landing sentinel, the ray-tracing-gate resolution (neutralized by the seek), the deferrals (PR5c non-inlined, PR7 remap+exporter). Monitor `gh pr checks`. **User merges.** No `.pak` fixtures.
- [ ] **Post-merge** — remove worktree + branch, sync main; PR5c (non-inlined) or PR7 (exporter) gets a fresh worktree + writing-plans pass.

---

## Self-review notes (coverage)
- Oracle re-verification (loop + tail + seek + sentinel + non-inlined degrade) → Task 1, per [[feedback_verify_wire_format_claims]]; wire-format reviewer re-derives in Task 9.
- `LodHeader` surfacing buffers_size → Task 2. The loop + seek + non-inlined degrade → Task 3. The post-loop tail + sentinel → Task 4. Faults + the ray-tracing note → Task 5. Hardening → Task 6; gates + 0-missed mutants → Task 7; doc → Task 8; panel + PR → Task 9.
- The BuffersSize seek is bounded `≤ total_len` (no wild seek); the sentinel (`cursor == total_len`) degrades a wrong total skip to `Generic`; the seek neutralizes the out-of-band ray-tracing gate for iteration.
- Deferred: non-inlined FByteBulkData path → PR5c; bone-map LOD-local→global remap + the glTF exporter → PR7. The unverified BuffersSize contract is documented + sentinel-guarded ([[feedback_dont_port_oracle_bugs]]).
