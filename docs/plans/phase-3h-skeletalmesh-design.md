# Paksmith Phase 3h: `USkeletalMesh` → glTF 2.0 (`.glb`) — design

> Finalized design/spec for Phase 3h, superseding the "Open questions for
> kickoff" in [`phase-3h-skeletalmesh-export.md`](phase-3h-skeletalmesh-export.md)
> (the architecture overview, still the wire-format reference). The 3g static-mesh
> parser (#541) + glTF handler (#542) are merged; 3h reuses their shared mesh
> module + the 3g2 lowering helpers. Wire-format reference:
> [`../formats/mesh/skeletal-mesh.md`](../formats/mesh/skeletal-mesh.md) and
> [`../formats/mesh/skeleton.md`](../formats/mesh/skeleton.md).

## Goal

Parse a cooked `USkeletalMesh` (UE 4.x **and** UE5) into `Asset::SkeletalMesh`,
then export a skinned glTF 2.0 binary (`.glb`) that opens in Blender showing the
mesh in its **bind pose** with a working bone hierarchy + skin weights, so a user
can inspect / retarget it.

## Kickoff decisions (locked)

1. **Whole 3h in one design/plan** (parser + exporter), but **executed as a
   sequence of convergence-reviewed PRs** (see *Execution* below) — a single
   branch this size would violate the project's small-PR convention and be
   unreviewable.
2. **Engine range: UE 4.x and UE5 cooked.** CUE4Parse models both with the same
   `FStaticLODModel` reader (no separate `FSkeletalMeshLODRenderData` container at
   the oracle SHA); UE5 differences are custom-version-gated branches *within* one
   reader (`bVisibleInRayTracing`, `ClothMappingDataLODs` nested array,
   `bUse16BitBoneWeight`, the optional `Stride` field) plus **LWC** f64 widening
   of `ImportedBounds` + bind-pose `FTransform` (handled by 3c's LWC-aware
   decoders). Editor-only / non-cooked / unsupported layouts →
   `UnsupportedFeature` (degrades to `Asset::Generic`).
3. **Both skin-weight paths:** the legacy pre-4.25 `FSkinWeightVertexBuffer`
   (`bExtraBoneInfluences` split) and the 4.25+ new-format
   (`bNewWeightFormat = FAnimObjectVersion ≥ UnlimitedBoneInfluences`) path,
   version-dispatched, each with test coverage.
4. **`glam` crate** for the exporter's bind-matrix math (compose each bone's
   global bind transform from its `FTransform` parent chain, then invert for the
   glTF `inverseBindMatrices`). Added with `default-features` minimized; cleared
   through `cargo deny` (license / bans / sources).
5. **Oracle:** pin the SHA referenced by `skeletal-mesh.md`
   (`FabianFG/CUE4Parse` `USkeletalMesh.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d`
   + `FStaticLODModel.cs` / `FSkelMeshSection.cs` / `FSkinWeightVertexBuffer.cs`).
   Every field order / width / version gate is verified against it before
   implementing (TDD; see [[feedback_verify_wire_format_claims]]).

## Out of scope (deferred to later sub-phases)

- **`UAnimSequence`** animation tracks (→ glTF `animations`). 3h ships the bind
  pose only.
- **Morph targets** (`UMorphTarget` blend shapes).
- **Sockets** (per-bone attachment points; easy glTF `extras` later) and
  **`UPhysicsAsset`** (non-export).
- **Cloth** is not *surfaced* in `Asset::SkeletalMesh`, but the parser **must
  byte-skip the cloth wire blocks** (`ClothMappingDataLODs`, `ClothingData`,
  `OverlappingVertices`) correctly to stay cursor-aligned on real cooked assets.

## Parser

### New public types (`asset/mod.rs`)

```rust
pub enum Asset { /* … */ SkeletalMesh(SkeletalMeshData) }

#[non_exhaustive] // + Debug/Clone/PartialEq/Serialize, empty() ctor for the
                  // discriminant sentinel used in HandlerRegistry
pub struct SkeletalMeshData {
    pub properties: PropertyBag,
    pub cooked: bool,
    pub skeleton: ReferenceSkeleton,
    pub materials: Vec<…>,          // SkeletalMaterials slot list
    pub bounds: FBoxSphereBounds,   // 3c typed; LWC-aware
    pub lods: Vec<SkeletalMeshLod>,
}

#[non_exhaustive]
pub struct ReferenceSkeleton {
    pub bones: Vec<BoneInfo>,       // BoneInfo { name: String, parent_index: i32 }
    pub bind_pose: Vec<FTransform>, // 3c FTransform; one per bone, parent-relative
}

#[non_exhaustive]
pub struct SkeletalMeshLod {
    pub sections: Vec<SkelMeshSection>,
    pub positions: Vec<FVector>,
    pub normals: Vec<FVector>,
    pub tangents: Vec<FVector4>,    // W = handedness
    pub uvs: [Option<Vec<FVector2D>>; 4],
    pub colors: Option<Vec<FColor>>,
    pub indices: Vec<u32>,
    pub bone_indices: Vec<[u16; 8]>, // per-vertex, padded to 8
    pub bone_weights: Vec<[u8; 8]>,  // normalized 0–255, padded to 8
    pub bone_map: Vec<u16>,          // LOD-local → global skeleton index
}
```

### Modules (`asset/exports/mesh/`)

- `skeleton.rs` — `FReferenceSkeleton`: bone-count prefix, per-bone
  `FMeshBoneInfo` (name, parent_index), bind-pose `FTransform[]` via 3c
  (LWC-aware), name→index map. Validates `parent_index` and bone count.
- `skin_weights.rs` — `FSkinWeightVertexBuffer` legacy + new-format dispatch on
  `bNewWeightFormat`; per-vertex influences into `[u16;8]`/`[u8;8]`; `checked_mul`
  stride == declared byte length.
- `skeletal_mesh.rs` — `USkeletalMesh.Deserialize`: segment 1 (tagged properties:
  Skeleton/Materials/LODInfo/…) → segment 2 (strip flags, `ImportedBounds`,
  `SkeletalMaterials`, `FReferenceSkeleton`, `bCooked`, per-LOD `FStaticLODModel`).
  `read_typed(payload, ctx, asset_path) -> Result<(Asset, Vec<FByteBulkData>)>`.
- `section.rs` — extend for `FSkelMeshSection` (~25 version-gated fields; gates are
  **custom-version** constants, not UE-version labels). `FSkelMeshSection` differs
  from `FStaticMeshSection`; keep them as distinct readers in the same module.
- **Reuse from 3g:** `vertex_buffers.rs` (position/normal/tangent/UV/color),
  `index_buffer.rs` (`FMultisizeIndexContainer`), `lod.rs`/`render_data.rs` where
  the layout genuinely overlaps; do not force-share where the skeletal shape
  differs.

### Dispatch + invariants

- `asset/exports/dispatch.rs`: replace the commented stub with
  `table.insert("SkeletalMesh", skeletal_mesh::read_typed)` and flip the
  `class_dispatch().get("SkeletalMesh").is_none()` test to `is_some()`.
- **Object-GUID-tail invariant** ([[project_typed_reader_object_guid_tail]]): the
  top-level reader calls `read_object_guid_tail` after its top-level
  `read_properties`. 3h must honor it like the other typed readers.
- `package.rs` / docs comments that enumerate handled classes get `SkeletalMesh`
  added.

## Exporter

`export/skeletal_mesh.rs` — `GltfSkeletalMeshHandler` (`FormatHandler`,
`output_extension() = "glb"`), reusing 3g2's `GltfDoc` / `convert_position` /
`convert_dir` / `convert_tangent` / `encode_f32_le` / `reverse_winding` and the
`MAX_GLB_BIN_BYTES` cap. On top of the 3g2 mesh lowering it adds:

- **Skeleton nodes:** one glTF node per bone, parented per `parent_index`, TRS
  from the bind-pose `FTransform` (converted to glTF basis).
- **Skin:** a `skin` with `joints` (the bone-node indices) + an
  `inverseBindMatrices` accessor — compose each bone's **global** bind transform
  from the parent chain (glam `Mat4`/`Affine3A`), invert, convert to glTF basis,
  emit as MAT4 f32.
- **Skin attributes:** `JOINTS_0` (VEC4, `UNSIGNED_BYTE` or `UNSIGNED_SHORT` by
  bone count) + `WEIGHTS_0` (VEC4, `UNSIGNED_BYTE` normalized). >4 influences →
  also `JOINTS_1` / `WEIGHTS_1`. Bone indices are **remapped LOD-local → global**
  via `bone_map` before emit.
- Same UE→glTF coordinate basis, winding, and tangent-w handling as 3g2.

## Security (panel-mandatory — every per-vertex/bone wire value is attacker-influenced)

- **Caps (checked before any `with_capacity`):** `MAX_BONES_PER_SKELETON = 65_536`
  (16-bit index limit), `MAX_SKELETAL_LODS_PER_MESH = 8`,
  `MAX_INFLUENCES_PER_VERTEX = 8`, `MAX_BONE_MAP_ENTRIES_PER_SECTION`,
  cloth/overlapping-vertex nested-prefix caps. Cap accessor convention follows the
  sibling mesh caps (no `__test_utils` accessor; pinned via error-path tests).
- **OOB check sites (at parse time, fail-fast):** per-vertex influence index
  `< bone_map.len()`; `bone_map[i] < skeleton.bones.len()`; every signed `i32`
  count prefix `≥ 0`; `MaxBoneInfluences` ≤ cap on both skin paths; new-format
  `checked_mul` stride `== declared byte length`.
- No panics; corrupt / unsupported → typed `Result` error (`UnsupportedFeature`
  or a new variant). New error variants: `SkeletonBoneCountExceeded`,
  `BoneIndexOob`, `BoneMapOob`, `InfluenceCountInvalid`, `InfluenceCountNegative`,
  `SkeletalLodCountExceeded`, plus cloth/overlapping-vertex cap variants (named at
  TDD kickoff against the master cap table).

## Dependency

Add `glam` to the workspace (`default-features` minimized) for the exporter's
matrix compose+invert. `cargo deny check` after adding (MIT/Apache, crates.io —
no `allow-git` needed). Used only in `export/skeletal_mesh.rs`.

## Testing

- **In-source byte-assembly fixtures + oracle cross-validation** (the 3g parser
  approach) — **no committed `.pak` files, so the CI fixture-count gate is not
  touched.** If any `.pak` fixture is later required, bump the gate per
  [[feedback_fixture_count_gate]].
- **Parser coverage:** UE4 *and* UE5 version branches (the UE5 custom-version
  fields present/absent), legacy *and* new-format skin paths, 4- and 8-influence,
  multi-section, bone-map remap, the cloth/editor byte-skip alignment, and every
  cap / OOB error path (literal-value pins).
- **Exporter coverage:** in-memory `SkeletalMeshData` → `.glb`; round-trip parse
  with the `gltf` reader (skin/joints/weights/IBM counts + shapes, bone-node
  hierarchy, JOINTS/WEIGHTS split at >4 influences); `gltf-validator` as an
  optional gate when present.
- **Per PR:** full gate chain (fmt / clippy `--all-targets --all-features` / test
  `--workspace --all-features` / doc `-D warnings` / typos / cargo-deny) + in-diff
  `cargo-mutants` **0-missed / 0-timeout**.
- **Review:** ≥5-reviewer adversarial panel per PR — wire-format + security +
  deep-impact are MANDATORY (dense per-version conditionals; all-attacker-input;
  new `Asset::SkeletalMesh`/`ReferenceSkeleton` types downstream Phase 7/9 lean
  on), plus code + simplifier (+ performance for the larger skinned buffers).

## Execution (PR-series, each to convergence; user merges)

1. **PR1 — `FReferenceSkeleton` reader + type scaffolding.** `Asset::SkeletalMesh`
   + `ReferenceSkeleton`/`SkeletalMeshData`/`SkeletalMeshLod`/`SkelMeshSection`
   type scaffolding + the skeleton parse-fault variants, and `skeleton.rs`
   (`read_reference_skeleton`, unit-tested standalone). No dispatch wiring yet —
   the reader is `#[allow(dead_code)]` until PR2 calls it. (This design + the PR1
   implementation plan land here.)
2. **PR2 — dispatch + segment-2 prefix (modern-cooked only).** `read_typed`
   (tagged properties + `read_object_guid_tail` + segment-2 prefix: strip flags,
   `ImportedBounds`, `SkeletalMaterials` via `FSkeletalMaterial` +
   `FMeshUVChannelInfo`, the PR1 skeleton reader, then `bCooked` **gated on
   `FSkeletalMeshCustomVersion >= SplitModelAndRenderData` AND
   `IsEditorDataStripped()`**), dispatch wiring + the
   `class_dispatch().get("SkeletalMesh")` test flip (`is_none()` → `is_some()`).
   Yields `Asset::SkeletalMesh` with empty `lods`. Legacy
   (pre-`SplitModelAndRenderData`) and non-cooked (editor LOD data present)
   meshes return `UnsupportedFeature` (degrade to a generic property bag); the
   `FStaticLODModel` parse is deferred to PR3.
3. **PR3 — `FSkelMeshSection` cooked render-section reader (only).**
   A standalone, unit-tested `read_skel_mesh_section_render` decoding one cooked
   `FSkelMeshSection` via `SerializeRenderItem` (the 18-field render path
   editor-data-stripped cooked assets hit), plus the custom-version constants,
   caps, and parse-fault variants it needs. The reader is `#[allow(dead_code)]`
   until PR4 wires it. No `FStaticLODModel` / `read_typed` integration yet.
4. **PR4 — `FStaticLODModel` LOD-0 header wiring (sections + bone arrays).** The
   cooked `FStaticLODModel.SerializeRenderItem` **header** reader that calls PR3's
   section reader (strip flags + `Sections[]` loop) plus `ActiveBoneIndices` /
   `RequiredBones`, and `read_typed` integration so the cooked LOD-model array's
   LOD-0 header populates `Asset::SkeletalMesh`. The `bCooked`-gated LOD read
   stops at blob-start (right after `BuffersSize`); the streamed blob contents
   are PR5 (LOD-0-first re-scope).
5. **PR5 — streamed LOD blob + multi-LOD iteration + bone-map remap.**
   `FMultisizeIndexContainer` (index buffer) + vertex buffers +
   `FSkinWeightVertexBuffer` (both paths) + bone-map remap; multi-LOD iteration;
   completes the parsed `SkeletalMeshLod`; end-to-end parser fixture.
6. **PR6 — `GltfSkeletalMeshHandler`.** glam dep, skin/joints/weights/IBM, bone
   nodes, JOINTS/WEIGHTS split; end-to-end skinned-cube `.glb`.

(3h is ~6 PRs after the re-split — see the pr3-plan's re-split note.)

## References

- [`phase-3h-skeletalmesh-export.md`](phase-3h-skeletalmesh-export.md) — wire
  overview + full `FSkelMeshSection` field list.
- [`../formats/mesh/skeletal-mesh.md`](../formats/mesh/skeletal-mesh.md),
  [`../formats/mesh/skeleton.md`](../formats/mesh/skeleton.md),
  [`../formats/mesh/vertex-formats.md`](../formats/mesh/vertex-formats.md).
- [`phase-3g2-gltf-export.md`](phase-3g2-gltf-export.md) — reused lowering helpers.
- glTF 2.0 skins: <https://registry.khronos.org/glTF/specs/2.0/glTF-2.0.html#skins>.
