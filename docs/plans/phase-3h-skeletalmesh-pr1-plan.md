# Phase 3h PR1 — `FReferenceSkeleton` reader + type scaffolding — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax. Design: [`phase-3h-skeletalmesh-design.md`](phase-3h-skeletalmesh-design.md); wire reference: [`../formats/mesh/skeleton.md`](../formats/mesh/skeleton.md).

**Goal:** Land the Phase 3h foundation — the `Asset::SkeletalMesh` type scaffolding and a fully-tested `FReferenceSkeleton` reader (`skeleton.rs`) — without yet wiring dispatch. The reader is unit-tested standalone against skeleton.md's byte-exact worked example; PR2 wires it into `USkeletalMesh.read_typed` alongside the segment-2 prefix (`FSkeletalMaterial` etc.).

**Architecture:** A new `asset/exports/mesh/skeleton.rs` holds `read_reference_skeleton`, decoding the post-properties `FReferenceSkeleton` blob: `FinalRefBoneInfo[]` (count + per-bone `FMeshBoneInfo`), `FinalRefBonePose[]` (count + per-bone `FTransform` via 3c's LWC-aware decoder), and the `FinalNameToIndexMap` (consumed + validated). New SoA types in `asset/mod.rs`. The reader is `#[allow(dead_code)]`-gated until PR2 calls it.

**Tech Stack:** Rust; `byteorder` LE; reuse `crate::asset::property::read_fname_pair`, `crate::asset::structs::transform::FTransform`, `FQuat::wire_size`/`FVector::wire_size`.

**Scope re-split note:** the design doc listed dispatch + `read_typed` under PR1; this plan defers them to PR2 (they need `FSkeletalMaterial` + `FMeshUVChannelInfo`, a 4-custom-version-gated native struct disproportionate to the skeleton foundation). PR1 = types + errors + skeleton reader + docs.

**Oracle-verified facts (already confirmed; do not re-derive — re-confirm only if a test contradicts):**
- `USkeletalMesh.Deserialize` segment-2 order: `FStripDataFlags` → `ImportedBounds` → `SkeletalMaterials = ReadArray(FSkeletalMaterial)` → **`ReferenceSkeleton`** → `bCooked` → LODs. (Verified against `USkeletalMesh.cs@cf74fc32`.)
- `FReferenceSkeleton`: `FinalRefBoneInfo` (`i32` count + N×`FMeshBoneInfo`), `FinalRefBonePose` (`i32` count + N×`FTransform`), `FinalNameToIndexMap` (`i32` count + N×(`FName`+`i32`)). The map is present for paksmith's range (UE 4.13+ floor is post-`REFERENCE_SKELETON_REFACTOR`/UE 4.12).
- `FMeshBoneInfo` (cooked, UE 4.13+): `Name: FName` (8 bytes), `ParentIndex: i32`. No `BoneColor` (pre-4.12 only), no `ExportName` (editor-only, stripped in cooked).
- `FTransform`: UE4 = 40 bytes (FQuat 16 + FVector 12 + FVector 12); UE5 LWC = 80 bytes (f64). Handled by `FTransform::read_from` via `ctx`.

---

## File structure

- **Modify** `crates/paksmith-core/src/asset/mod.rs` — add `Asset::SkeletalMesh(SkeletalMeshData)` + the `SkeletalMeshData` / `ReferenceSkeleton` / `BoneInfo` / `SkeletalMeshLod` types + `SkeletalMeshData::empty()`.
- **Create** `crates/paksmith-core/src/asset/exports/mesh/skeleton.rs` — `read_reference_skeleton` + `MAX_BONES_PER_SKELETON` + unit tests.
- **Modify** `crates/paksmith-core/src/asset/exports/mesh/mod.rs` — `pub(crate) mod skeleton;`.
- **Modify** `crates/paksmith-core/src/error.rs` — new `AssetParseFault` variants + `AssetWireField` skeleton variants.
- **Add** the design + this plan doc to the PR (already committed on the branch).

All work in the worktree `.claude/worktrees/feat+phase-3h-reference-skeleton/` (branch `feat/phase-3h-reference-skeleton`). Run commands from there.

---

## Task 1: Error variants + wire-field tags

**Files:** Modify `crates/paksmith-core/src/error.rs`

- [ ] **Step 1: Read the existing fault patterns**

Read `crates/paksmith-core/src/error.rs` around `AssetParseFault` and `AssetWireField` (grep for `MeshBulkArrayCountMismatch` and a recent mesh field) to match the exact enum style, `#[error(...)]` `Display` format, and `#[non_exhaustive]` usage.

- [ ] **Step 2: Add the skeleton fault variants**

Add to `AssetParseFault` (match the surrounding field-order + Display style; keep messages wire-stable and lowercase-noun-phrase like siblings):

```rust
/// Skeleton bone count prefix was negative.
#[error("skeleton bone count {count} is negative")]
SkeletonBoneCountNegative { count: i32 },
/// Skeleton bone count exceeded the cap.
#[error("skeleton bone count {count} exceeds cap {cap}")]
SkeletonBoneCountExceeded { count: i64, cap: usize },
/// FinalRefBonePose / FinalNameToIndexMap length disagreed with the bone count.
#[error("skeleton array length {got} does not match bone count {expected} ({which})")]
SkeletonArrayLengthMismatch { which: &'static str, got: i64, expected: usize },
/// A bone's parent index was neither root (-1) nor a strictly-earlier bone.
#[error("bone {bone} parent index {parent} is invalid (must be -1 or < {bone})")]
BoneParentIndexInvalid { bone: usize, parent: i32 },
/// A FinalNameToIndexMap value was out of [0, bone_count).
#[error("name-to-index map value {value} out of range for {bone_count} bones")]
NameToIndexValueOob { value: i32, bone_count: usize },
```

Add to `AssetWireField` (used by `read_fname_pair` / read helpers for error context): `SkeletonBoneName`, `SkeletonBoneCount`, `SkeletonBoneParent`, `SkeletonBonePoseCount`, `SkeletonNameMapCount`, `SkeletonNameMapKey`, `SkeletonNameMapValue`. Match the existing `AssetWireField` Display/strings convention.

- [ ] **Step 3: Build + Display pin test**

Add a `#[test]` (in error.rs's test module, matching the existing fault-Display pin tests) asserting one representative `Display` string per new variant (wire-stable). Run: `cargo test -p paksmith-core --all-features error::` → PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/paksmith-core/src/error.rs
git commit -m "feat(asset): skeleton parse-fault + wire-field variants (3h)"
```

---

## Task 2: `Asset::SkeletalMesh` variant + type scaffolding

**Files:** Modify `crates/paksmith-core/src/asset/mod.rs`
**Reference:** the `StaticMeshData` / `StaticMeshLod` definitions in the same file (match their derives, `#[non_exhaustive]`, doc style, and `empty()` pattern).

- [ ] **Step 1: Write the failing test**

In `asset/mod.rs` tests:

```rust
#[test]
fn skeletal_mesh_empty_is_constructible_and_matches_variant() {
    let asset = Asset::SkeletalMesh(SkeletalMeshData::empty());
    assert!(matches!(asset, Asset::SkeletalMesh(_)));
    let Asset::SkeletalMesh(d) = asset else { unreachable!() };
    assert!(d.skeleton.bones.is_empty());
    assert!(d.lods.is_empty());
    assert!(!d.cooked);
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p paksmith-core --all-features asset::tests::skeletal_mesh_empty`
Expected: FAIL — `Asset::SkeletalMesh` / `SkeletalMeshData` not defined.

- [ ] **Step 3: Add the variant + types**

Add `SkeletalMesh(SkeletalMeshData)` to the `Asset` enum (next to `StaticMesh`). Add (match `StaticMeshData`'s derives: `#[derive(Debug, Clone, PartialEq, serde::Serialize)] #[non_exhaustive]`):

```rust
/// Parsed `USkeletalMesh` (Phase 3h). LOD/skin data is populated by later 3h PRs.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[non_exhaustive]
pub struct SkeletalMeshData {
    pub properties: property::bag::PropertyBag,
    pub cooked: bool,
    pub skeleton: ReferenceSkeleton,
    pub materials: Vec<String>,             // material slot names; populated in PR2
    pub bounds: structs::bounds::FBoxSphereBounds,
    pub lods: Vec<SkeletalMeshLod>,         // populated in PR2/PR3
}

/// Reference skeleton: bone hierarchy + bind pose (`FReferenceSkeleton`).
#[derive(Debug, Clone, PartialEq, serde::Serialize, Default)]
#[non_exhaustive]
pub struct ReferenceSkeleton {
    pub bones: Vec<BoneInfo>,
    pub bind_pose: Vec<structs::transform::FTransform>,
}

/// One bone's metadata (`FMeshBoneInfo`, cooked subset).
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[non_exhaustive]
pub struct BoneInfo {
    pub name: String,
    /// Parent index into the bone array; `-1` for root.
    pub parent_index: i32,
}

/// Per-LOD skeletal geometry (SoA). Fields declared here; populated in PR2/PR3.
#[derive(Debug, Clone, PartialEq, serde::Serialize, Default)]
#[non_exhaustive]
pub struct SkeletalMeshLod {
    pub sections: Vec<SkelMeshSection>,
    pub positions: Vec<structs::vector::FVector>,
    pub normals: Vec<structs::vector::FVector>,
    pub tangents: Vec<structs::vector::FVector4>,
    pub uvs: [Option<Vec<structs::vector::FVector2D>>; 4],
    pub colors: Option<Vec<structs::color::FColor>>,
    pub indices: Vec<u32>,
    pub bone_indices: Vec<[u16; 8]>,
    pub bone_weights: Vec<[u8; 8]>,
    pub bone_map: Vec<u16>,
}

/// One `FSkelMeshSection` draw-call record. Fields populated in PR2.
#[derive(Debug, Clone, PartialEq, serde::Serialize, Default)]
#[non_exhaustive]
pub struct SkelMeshSection {
    pub material_index: i32,
    pub base_index: i32,
    pub num_triangles: i32,
    pub base_vertex_index: u32,
    pub num_vertices: i32,
    pub max_bone_influences: i32,
}
```

Add `SkeletalMeshData::empty()`:

```rust
impl SkeletalMeshData {
    /// An empty skeletal mesh — used as the `HandlerRegistry` discriminant sentinel.
    pub fn empty() -> Self {
        Self {
            properties: property::bag::PropertyBag::opaque(Vec::new()),
            cooked: false,
            skeleton: ReferenceSkeleton::default(),
            materials: Vec::new(),
            bounds: structs::bounds::FBoxSphereBounds::default(),
            lods: Vec::new(),
        }
    }
}
```

Verify `FBoxSphereBounds`, `FVector`, `FVector4`, `FVector2D`, `FColor`, `FTransform` impl the derives used (`Default` on `FBoxSphereBounds`/`FTransform` — if not, construct the zero value explicitly in `empty()` and drop `Default` from `ReferenceSkeleton`/`SkeletalMeshLod`, deriving it manually or via an explicit ctor). Use the exact module paths the file already uses (match `StaticMeshData`'s imports).

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p paksmith-core --all-features asset::tests::skeletal_mesh_empty`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/paksmith-core/src/asset/mod.rs
git commit -m "feat(asset): Asset::SkeletalMesh variant + SoA type scaffolding (3h)"
```

---

## Task 3: `MAX_BONES_PER_SKELETON` cap + module wiring

**Files:** Create `crates/paksmith-core/src/asset/exports/mesh/skeleton.rs`; Modify `crates/paksmith-core/src/asset/exports/mesh/mod.rs`

- [ ] **Step 1: Create the module with the cap + a value pin test**

`skeleton.rs`:

```rust
//! `FReferenceSkeleton` reader — bone hierarchy + bind pose for `USkeletalMesh`
//! (Phase 3h). Wire reference: `docs/formats/mesh/skeleton.md`. Wired into
//! `USkeletalMesh::read_typed` by PR2.

/// Maximum bones per skeleton. Matches the 16-bit bone-index ceiling
/// (`2^16`) used by `FStaticLODModel` / `FSkinWeightVertexBuffer`.
///
/// NOTE: no `#[cfg(feature = "__test_utils")]` accessor — per the sibling
/// mesh-cap convention (`vertex_buffers.rs` / `texture2d.rs`), the cap is pinned
/// via the in-source over-cap error-path test below; an integration-test
/// consumer would add the accessor when one exists.
pub(crate) const MAX_BONES_PER_SKELETON: usize = 1 << 16; // 65_536

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_bones_cap_value() {
        assert_eq!(MAX_BONES_PER_SKELETON, 65_536);
    }
}
```

In `mesh/mod.rs`, add `pub(crate) mod skeleton;` next to the other `mod` lines (alphabetical).

- [ ] **Step 2: Run**

Run: `cargo test -p paksmith-core --all-features mesh::skeleton`
Expected: PASS (the value pin).

- [ ] **Step 3: Commit**

```bash
git add crates/paksmith-core/src/asset/exports/mesh/skeleton.rs crates/paksmith-core/src/asset/exports/mesh/mod.rs
git commit -m "feat(asset): skeleton module scaffold + MAX_BONES_PER_SKELETON (3h)"
```

---

## Task 4: `read_reference_skeleton` — happy path (2-bone worked example)

**Files:** Modify `crates/paksmith-core/src/asset/exports/mesh/skeleton.rs`
**Reference:** skeleton.md "Worked example — minimal 2-bone `FReferenceSkeleton` body (112 bytes)"; an existing typed-reader test for the `AssetContext` + name-table byte-assembly pattern (e.g. `asset/exports/data_table.rs` `fname`/`write_fname` test helpers, or the `testing` infra).

- [ ] **Step 1: Write the failing test (byte-exact 112-byte body)**

Add to `skeleton.rs` tests. Build a minimal `AssetContext` whose name table contains "Root" and "Hip" at known indices, assemble the 112-byte single-precision body, and assert the decode:

```rust
// Build using the crate's test name-table + AssetContext helpers (match the
// pattern in data_table.rs / sound_wave.rs tests). The name table maps
// index 0->"Root", 1->"Hip". FName on wire = i32 name_index + i32 number.
#[test]
fn reads_two_bone_reference_skeleton_ue4_single_precision() {
    let ctx = test_ctx_ue4(&["Root", "Hip"]); // helper: UE4 (non-LWC) ctx + names
    let mut body: Vec<u8> = Vec::new();
    // FinalRefBoneInfo count = 2
    body.extend_from_slice(&2i32.to_le_bytes());
    // bone 0: name "Root" (index 0, number 0), parent -1
    body.extend_from_slice(&0i32.to_le_bytes()); body.extend_from_slice(&0i32.to_le_bytes());
    body.extend_from_slice(&(-1i32).to_le_bytes());
    // bone 1: name "Hip" (index 1, number 0), parent 0
    body.extend_from_slice(&1i32.to_le_bytes()); body.extend_from_slice(&0i32.to_le_bytes());
    body.extend_from_slice(&0i32.to_le_bytes());
    // FinalRefBonePose count = 2 + two identity FTransforms (40 bytes each)
    body.extend_from_slice(&2i32.to_le_bytes());
    body.extend_from_slice(&identity_ftransform_ue4());
    body.extend_from_slice(&identity_ftransform_ue4());
    // FinalNameToIndexMap count = 2 + ("Root"->0, "Hip"->1)
    body.extend_from_slice(&2i32.to_le_bytes());
    body.extend_from_slice(&0i32.to_le_bytes()); body.extend_from_slice(&0i32.to_le_bytes()); body.extend_from_slice(&0i32.to_le_bytes());
    body.extend_from_slice(&1i32.to_le_bytes()); body.extend_from_slice(&0i32.to_le_bytes()); body.extend_from_slice(&1i32.to_le_bytes());

    let mut cur = std::io::Cursor::new(body);
    let skel = read_reference_skeleton(&mut cur, &ctx, "Test.uasset").expect("decode");
    assert_eq!(skel.bones.len(), 2);
    assert_eq!(skel.bones[0].name, "Root");
    assert_eq!(skel.bones[0].parent_index, -1);
    assert_eq!(skel.bones[1].name, "Hip");
    assert_eq!(skel.bones[1].parent_index, 0);
    assert_eq!(skel.bind_pose.len(), 2);
    // identity transform: scale (1,1,1)
    assert_eq!(skel.bind_pose[0].scale_3d, crate::asset::structs::vector::FVector { x: 1.0, y: 1.0, z: 1.0 });
    // whole body consumed
    assert_eq!(cur.position(), 112);
}
```

Provide the `identity_ftransform_ue4()` helper (40 bytes: Quat(0,0,0,1) + Vec(0,0,0) + Vec(1,1,1)) per skeleton.md's identity-FTransform worked example, and a `test_ctx_ue4(names)` helper building a non-LWC `AssetContext` with those names. If the crate already exposes test-ctx/name-table builders (check `testing/` + sibling export tests), reuse them rather than hand-rolling.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p paksmith-core --all-features mesh::skeleton::tests::reads_two_bone`
Expected: FAIL — `read_reference_skeleton` not defined.

- [ ] **Step 3: Implement `read_reference_skeleton`**

```rust
use std::io::{Read, Seek};

use byteorder::{LittleEndian, ReadBytesExt};

use crate::asset::property::read_fname_pair;
use crate::asset::structs::transform::FTransform;
use crate::asset::structs::vector::{FQuat, FVector};
use crate::asset::AssetContext;
use crate::asset::AssetWireField;
use crate::error::AssetParseFault;

/// Decode a `FReferenceSkeleton` (post-properties blob): `FinalRefBoneInfo`,
/// `FinalRefBonePose`, and the validated `FinalNameToIndexMap`.
pub(crate) fn read_reference_skeleton<R: Read + Seek + ?Sized>(
    r: &mut R,
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<crate::asset::ReferenceSkeleton> {
    // --- FinalRefBoneInfo ---
    let bone_count_i32 = r
        .read_i32::<LittleEndian>()
        .map_err(|e| eof(e, AssetWireField::SkeletonBoneCount, asset_path))?;
    if bone_count_i32 < 0 {
        return Err(AssetParseFault::SkeletonBoneCountNegative { count: bone_count_i32 }.into());
    }
    let bone_count = bone_count_i32 as usize;
    if bone_count > MAX_BONES_PER_SKELETON {
        return Err(AssetParseFault::SkeletonBoneCountExceeded {
            count: bone_count_i32 as i64,
            cap: MAX_BONES_PER_SKELETON,
        }
        .into());
    }
    let mut bones = Vec::with_capacity(bone_count);
    for i in 0..bone_count {
        let name = read_fname_pair(r, ctx, asset_path, AssetWireField::SkeletonBoneName)?;
        let parent_index = r
            .read_i32::<LittleEndian>()
            .map_err(|e| eof(e, AssetWireField::SkeletonBoneParent, asset_path))?;
        // Root (-1) or a strictly-earlier bone: rejects cycles + forward refs.
        if parent_index != -1 && !(0..i as i32).contains(&parent_index) {
            return Err(AssetParseFault::BoneParentIndexInvalid { bone: i, parent: parent_index }.into());
        }
        bones.push(crate::asset::BoneInfo { name, parent_index });
    }

    // --- FinalRefBonePose (parity with bone_count) ---
    let pose_count = read_count_eq(r, bone_count, "FinalRefBonePose", AssetWireField::SkeletonBonePoseCount, asset_path)?;
    let ft_size = FQuat::wire_size(ctx) + 2 * FVector::wire_size(ctx);
    let mut bind_pose = Vec::with_capacity(pose_count);
    for _ in 0..pose_count {
        let start = stream_pos(r, asset_path)?;
        bind_pose.push(FTransform::read_from(r, ctx, start + ft_size, asset_path)?);
    }

    // --- FinalNameToIndexMap (present for UE 4.13+; consume + validate) ---
    let map_count = read_count_eq(r, bone_count, "FinalNameToIndexMap", AssetWireField::SkeletonNameMapCount, asset_path)?;
    for _ in 0..map_count {
        let _key = read_fname_pair(r, ctx, asset_path, AssetWireField::SkeletonNameMapKey)?;
        let value = r
            .read_i32::<LittleEndian>()
            .map_err(|e| eof(e, AssetWireField::SkeletonNameMapValue, asset_path))?;
        if value < 0 || value as usize >= bone_count {
            return Err(AssetParseFault::NameToIndexValueOob { value, bone_count }.into());
        }
    }

    Ok(crate::asset::ReferenceSkeleton { bones, bind_pose })
}
```

Add small private helpers: `read_count_eq` (reads an `i32`, sign-checks, and requires it equals `bone_count` else `SkeletonArrayLengthMismatch { which, got, expected }`), `eof` (maps an `io::Error` to the EOF fault with the given `AssetWireField` — copy the exact pattern sibling readers use, e.g. `on_eof` in `data_table.rs`), and `stream_pos` (reuse the crate helper the transform decoder uses, or `r.stream_position()` mapped to a fault). Match the exact EOF-mapping + `stream_pos` helpers already used in `static_mesh.rs` / `transform.rs`.

Confirm `FQuat::wire_size`/`FVector::wire_size` are `pub(crate)`-visible here; if not, widen visibility (small, in-crate) or compute via the `ctx` LWC flag the same way `FTransform::read_from` does.

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p paksmith-core --all-features mesh::skeleton::tests::reads_two_bone`
Expected: PASS. If `read_fname_pair`'s return type isn't `String` (e.g. it returns an `FName`/`Arc<str>`), adapt `BoneInfo.name`'s type or `.to_string()` at the call site to match, and adjust the Task-2 `BoneInfo` accordingly (keep them consistent).

- [ ] **Step 5: Add `#[allow(dead_code)]` until PR2 wires it**

`read_reference_skeleton` has no non-test caller yet → add `#[allow(dead_code)]` (+ `// wired into read_typed by PR2`) on the fn, mirroring the 3g incremental-helper precedent.

- [ ] **Step 6: Commit**

```bash
git add crates/paksmith-core/src/asset/exports/mesh/skeleton.rs
git commit -m "feat(asset): FReferenceSkeleton happy-path reader (3h)"
```

---

## Task 5: Hardening + version coverage (caps / parity / parent / OOB / LWC)

**Files:** Modify `crates/paksmith-core/src/asset/exports/mesh/skeleton.rs` (tests + any guard fixes)

Each step adds a test that must FAIL without the corresponding guard from Task 4 (run it, confirm it exercises the guard), then PASS with the guard. These are the mutation pins for the cap/validation logic.

- [ ] **Step 1: Negative bone count → `SkeletonBoneCountNegative`**

```rust
#[test]
fn negative_bone_count_is_rejected() {
    let ctx = test_ctx_ue4(&[]);
    let body = (-1i32).to_le_bytes().to_vec();
    let err = read_reference_skeleton(&mut std::io::Cursor::new(body), &ctx, "T").unwrap_err();
    assert!(matches!(err, crate::PaksmithError::AssetParse(crate::error::AssetParseFault::SkeletonBoneCountNegative { count: -1 }, ..)));
}
```
(Match the crate's actual `PaksmithError`→`AssetParseFault` matching shape — copy from a sibling fault-path test.) Run → PASS.

- [ ] **Step 2: Over-cap bone count → `SkeletonBoneCountExceeded`**

A body with count = `MAX_BONES_PER_SKELETON as i32 + 1` (note: `65_537` fits `i32`) → `SkeletonBoneCountExceeded`. Assert the error BEFORE any large allocation (the check precedes `Vec::with_capacity`). Run → PASS.

- [ ] **Step 3: Pose-count parity mismatch → `SkeletonArrayLengthMismatch`**

A valid 1-bone `FinalRefBoneInfo` but `FinalRefBonePose` count = 2 → `SkeletonArrayLengthMismatch { which: "FinalRefBonePose", .. }`. Run → PASS.

- [ ] **Step 4: Name-map parity mismatch → `SkeletonArrayLengthMismatch`**

1 bone, correct pose count 1, but `FinalNameToIndexMap` count = 0 → `SkeletonArrayLengthMismatch { which: "FinalNameToIndexMap", .. }`. Run → PASS.

- [ ] **Step 5: Invalid parent index → `BoneParentIndexInvalid`**

A single bone with `parent_index = 0` (== own index, a self/forward ref) → `BoneParentIndexInvalid { bone: 0, parent: 0 }`. And a second case: bone 0 with `parent_index = 5` (forward ref) → same fault. Run → PASS. (These pin the `parent != -1 && !(0..i).contains(parent)` guard against `<`→`<=` and range mutants.)

- [ ] **Step 6: Name-map value OOB → `NameToIndexValueOob`**

1 bone, pose 1, name-map count 1 with value = 1 (== bone_count, out of `[0,1)`) → `NameToIndexValueOob { value: 1, bone_count: 1 }`. And value = -1 → same fault. Run → PASS.

- [ ] **Step 7: UE5 LWC path (80-byte transform)**

```rust
#[test]
fn reads_reference_skeleton_ue5_lwc_double_precision() {
    let ctx = test_ctx_ue5_lwc(&["Root"]); // helper: ctx with file_version_ue5 >= LARGE_WORLD_COORDINATES
    let mut body = Vec::new();
    body.extend_from_slice(&1i32.to_le_bytes());          // 1 bone
    body.extend_from_slice(&0i32.to_le_bytes()); body.extend_from_slice(&0i32.to_le_bytes()); // name "Root"
    body.extend_from_slice(&(-1i32).to_le_bytes());        // parent -1
    body.extend_from_slice(&1i32.to_le_bytes());          // pose count 1
    body.extend_from_slice(&identity_ftransform_ue5_lwc()); // 80 bytes (f64)
    body.extend_from_slice(&1i32.to_le_bytes());          // name-map count 1
    body.extend_from_slice(&0i32.to_le_bytes()); body.extend_from_slice(&0i32.to_le_bytes()); body.extend_from_slice(&0i32.to_le_bytes()); // "Root"->0
    let mut cur = std::io::Cursor::new(body);
    let skel = read_reference_skeleton(&mut cur, &ctx, "T").expect("decode");
    assert_eq!(skel.bones.len(), 1);
    assert_eq!(skel.bind_pose.len(), 1);
    assert_eq!(skel.bind_pose[0].scale_3d, crate::asset::structs::vector::FVector { x: 1.0, y: 1.0, z: 1.0 });
}
```
Provide `identity_ftransform_ue5_lwc()` (80 bytes: 4×f64 quat 0,0,0,1 + 3×f64 zero + 3×f64 one) and `test_ctx_ue5_lwc`. This pins that the reader picks up `ctx`-driven LWC widths via `FTransform`. Run → PASS.

- [ ] **Step 8: Commit**

```bash
git add crates/paksmith-core/src/asset/exports/mesh/skeleton.rs
git commit -m "test(asset): skeleton reader hardening + LWC coverage (3h)"
```

---

## Task 6: Gate chain + in-diff cargo-mutants

- [ ] **Step 1: Full gate chain (from the worktree)**

```bash
cargo fmt --all
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
typos .
cargo deny check
```
All must pass. Fix any clippy lints (e.g. an `as i64`/`as usize` cast may need `#[allow(clippy::cast_possible_truncation)]` with a reason, or prefer `i64::from` / `usize::try_from`). `#[allow(dead_code)]` on `read_reference_skeleton` is expected (PR2 wires it).

- [ ] **Step 2: In-diff cargo-mutants → 0 missed, 0 timeout**

```bash
git diff origin/main -- > /tmp/pr_3h1.diff
cargo mutants --in-diff /tmp/pr_3h1.diff --no-shuffle -j 4 --all-features
```
Expected: `0 missed`, `0 timeout`. Likely survivors to pin if any slip through: the parent-index range bound (`0..i` vs `0..=i`), the parity comparisons in `read_count_eq` (`!=` vs `==`), the cap `>` boundary, the name-map OOB `>=`/`<` bounds, the `bone_count as usize`. The Task-5 tests should already cover these; add a literal-value pin for any survivor. For an equivalent mutant from a derived expression, prefer a plain literal (per the 3g `wire.rs` precedent).

- [ ] **Step 3: Commit any added pins**

```bash
git add -A
git commit -m "test(asset): pin skeleton reader mutants (3h)"
```

---

## Task 7: Review panel to convergence, then PR

- [ ] **Step 1: Dispatch the adversarial panel (single message, parallel)**

≥5 reviewers on `git -C <worktree> diff main..HEAD`:
- **wire-format (MANDATORY)** — `FReferenceSkeleton` field order / counts / FName / FTransform width vs skeleton.md + the oracle (`USkeletalMesh.cs` / `FReferenceSkeleton` @ `cf74fc32`); the UE4 vs UE5-LWC dispatch; the FinalNameToIndexMap consume+validate.
- **security (MANDATORY)** — every count prefix is attacker-controlled: sign-checks, the cap-before-`with_capacity`, parity invariants (count-amplification + cross-array confusion), parent-index cycle/forward-ref guard, name-map value OOB. Confirm no panic / unbounded alloc on hostile input.
- **deep-impact (MANDATORY)** — the new `Asset::SkeletalMesh` + `ReferenceSkeleton`/`SkeletalMeshData`/`SkeletalMeshLod` public types that Phase 7/9 + later 3h PRs lean on; the new error variants; that `empty()` suits the (future) `HandlerRegistry` sentinel.
- **code-reviewer** — bugs/logic; **simplifier** — DRY across the count-read helpers.

Brief adversarially (hunt cold, severity floor conf 70, no "already addressed" summaries).

- [ ] **Step 2: Fix-forward to convergence**

Apply fixes; re-run the FULL panel on each fix HEAD until every reviewer APPROVES. Re-run the gate chain + in-diff mutants after each round. Do NOT touch the convergence marker until convergence.

- [ ] **Step 3: Push + PR + monitor CI**

Touch the marker from the worktree (`touch "$(git rev-parse --git-dir)/REVIEW_CONVERGED_OK"`, a SEPARATE call) then `git push -u origin feat/phase-3h-reference-skeleton`. Open the PR via `gh pr create --body-file` (fresh marker before that call too). Title (lowercase verb-first): `feat(asset): add FReferenceSkeleton reader + SkeletalMesh scaffolding (Phase 3h PR1)`. Monitor `gh pr checks` until CI converges. **User merges — do not self-merge.** No `.pak` fixtures added → fixture-count gate untouched.

- [ ] **Step 4: Post-merge cleanup**

After merge: remove the worktree + `target/`, delete the local branch, sync main. PR2 (segment-2 prefix + `FSkeletalMaterial` + dispatch) gets a fresh worktree + its own writing-plans pass (verify `FSkeletalMaterial` / `FMeshUVChannelInfo` / `FSkelMeshSection` against the oracle at that time).

---

## Self-review notes (coverage vs the PR1 scope)

- Types + variant + `empty()` → Task 2. Error variants → Task 1. Cap → Task 3.
- `FReferenceSkeleton` reader (FinalRefBoneInfo / FinalRefBonePose / FinalNameToIndexMap) → Task 4; happy path pins names, parents, bind-pose, full consumption.
- Hardening (negative / over-cap / parity ×2 / parent-invalid / name-map OOB) + UE5 LWC → Task 5 (each a mutation pin).
- Reuse: `read_fname_pair`, `FTransform::read_from` (LWC), `FQuat`/`FVector::wire_size`. No new deps (glam is PR4).
- Deferred to PR2 (documented): dispatch wiring + `read_typed` + `FSkeletalMaterial`/`FMeshUVChannelInfo` + segment-2 prefix; PR3: LOD/sections/skin/vertex buffers; PR4: exporter.
- Gates + 0-missed mutants → Task 6; panel + PR → Task 7.
