# Paksmith Phase 3g2: `UStaticMesh` → glTF 2.0 (`.glb`) export — design

> Design/spec for the `GltfStaticMeshHandler`. The 3g1 parser is merged
> (`UStaticMesh` → `StaticMeshData` / `StaticMeshRenderData` / `StaticMeshLod`,
> PR #541). This sub-phase lowers that parsed geometry into a glTF 2.0 binary
> (`.glb`) the user opens in Blender. Supersedes the "Open questions for kickoff"
> in [`phase-3g-staticmesh-export.md`](phase-3g-staticmesh-export.md); the
> decisions taken at kickoff are recorded below.

## Goal

A `FormatHandler` that converts a cooked, inlined `UStaticMesh` (UE 4.23–4.27,
the parser's supported range) into a single self-contained `.glb` that opens
upright, correctly-scaled, and correctly-wound in Blender, with per-section
material slots the user can bind textures to manually.

## Kickoff decisions

1. **Container: GLB.** `FormatHandler::export` returns a single `Vec<u8>`; GLB is
   the self-contained single-file glTF container (12-byte header + JSON chunk +
   BIN chunk), so it maps to the return type exactly. No sidecar `.bin`.
2. **Writer: the `gltf` crate.** Use `gltf::json` for the schema types (serde
   `Serialize`) and `gltf::binary::Glb` for GLB containerization, pulled in with
   `default-features = false` + the minimal feature set needed for writing. The
   exact write API (`gltf::json::Root`, `gltf::binary::Glb { header, json, bin }`
   + its `to_vec`) is pinned in the first implementation task against docs.rs,
   and `cargo deny check` is run after adding the dep (license / bans / sources).
   *Fallback (only if the `gltf` crate's writer is unusable):* `gltf-json` +
   a ~80-line hand-rolled GLB chunk writer; flagged explicitly if taken.
3. **LODs: all, as separate named nodes.** Every parsed LOD becomes its own
   mesh + node named `LOD0`..`LODn` under scene 0. No glTF LOD extension (Blender
   ignores `MSFT_lod`); the user hides/deletes extra LOD nodes.
4. **Coordinates: convert to glTF convention.** UE is left-handed, Z-up,
   centimetres; glTF is right-handed, Y-up, metres. Apply the basis change +
   cm→m scale to positions, the basis change (no scale) to normals/tangents, and
   reverse triangle winding so faces stay front-facing (CCW). See
   *Coordinate conversion* below.
5. **Materials: placeholder, one per slot.** One glTF material per
   `StaticMaterials` slot, name-only; primitives reference by index. No texture /
   PBR baking.

## Architecture

```text
crates/paksmith-core/src/export/
├── mod.rs            # FormatHandler trait + HandlerRegistry (register here)
└── static_mesh.rs    # GltfStaticMeshHandler + glTF lowering (NEW)
```

- `GltfStaticMeshHandler` is a unit struct implementing `FormatHandler`:
  - `output_extension(&self) -> &'static str` → `"glb"`.
  - `supports(&self, asset) -> bool` → `matches!(asset, Asset::StaticMesh(d) if d.render_data.is_some())`. Uncooked / no-render-data meshes are degraded to `Asset::Generic` by the parser upstream, so this handler never receives them. (Were such a mesh to reach the registry, `find_handler` would return `None` for the unsupported `StaticMesh` — it would NOT route to the generic handler.)
  - `export(&self, asset, _bulk) -> crate::Result<Vec<u8>>` → builds the GLB. The inlined geometry lives in `StaticMeshData`, not in bulk records, so `bulk` is unused (asserted empty is not required).
- Registered in `HandlerRegistry::all_default_handlers()` under
  `std::mem::discriminant(&Asset::StaticMesh(StaticMeshData::empty()))` as the
  sole static-mesh handler.

The lowering is internal free functions in `static_mesh.rs`, each with one job
(coordinate transform, attribute → accessor, section → primitive, LOD → node,
material table, GLB assembly), so each is unit-testable in isolation.

## glTF structure produced

- **One BIN buffer** holding every accessor's bytes, little-endian, 4-byte
  aligned per the glTF spec.
- **Scene 0** → one node per LOD (`LOD0`..`LODn`) → one mesh per node.
- **Per LOD**, vertex accessors shared by all of that LOD's primitives:
  | glTF attribute | type | component | source |
  |---|---|---|---|
  | `POSITION` | VEC3 | f32 | `lod.positions` (converted); accessor carries required `min`/`max` |
  | `NORMAL` | VEC3 | f32 | `lod.normals` (basis-rotated, renormalized) |
  | `TANGENT` | VEC4 | f32 | `lod.tangents` (xyz basis-rotated; **w handedness negated** (`T_gltf.w = −T_ue.w`; det−1 basis flips tangent-space handedness)) |
  | `TEXCOORD_0..k` | VEC2 | f32 | `lod.uvs[0..k]` (present channels only) |
  | `COLOR_0` | VEC4 | u8 (normalized) | `lod.colors` when `Some` |
- **One primitive per `MeshSection`** (mode `TRIANGLES`): shares the LOD's vertex
  accessors, plus its own index accessor — a sub-range
  `[first_index, first_index + 3·num_triangles)` of the LOD's index buffer — and
  `material` = the section's `material_index` (clamped to the material table
  size; out-of-range → a typed error).
- **Index component width:** `UNSIGNED_SHORT` when the LOD vertex count
  ≤ 65 535, else `UNSIGNED_INT`. (Indices are materialized `u32` at parse; they
  narrow on write when safe.)
- **Materials:** `material_count = max(StaticMaterials slot count, 1 + max section.material_index)`; each named from the slot if resolvable from `properties`, else `Material_<i>`.

## Coordinate conversion

UE → glTF, applied per vertex:

- **Position:** a fixed basis change + ×`0.01` (cm→m). The exact axis map and
  sign are **pinned in the implementation against a reference UE→glTF exporter**
  (CUE4Parse's glTF/mesh exporter) rather than guessed, and must satisfy three
  checkable constraints: UE Z-up maps to glTF Y-up; the frame goes left-handed →
  right-handed (an odd number of axis negations, basis determinant −1); and the
  cube fixture renders **upright and solid** (not inside-out) in Blender. The
  Blender render of the cube fixture is the acceptance oracle for "correct."
- **Normal / Tangent.xyz:** same basis, **no scale**; renormalize after.
  Tangent.w (handedness ±1) is **negated** (`T_gltf.w = −T_ue.w`), the tangent-space counterpart of the winding reversal (both follow from the det−1 basis).
- **Winding:** the handedness flip inverts triangle facing, so each triangle's
  index triple is reversed (`[a,b,c]` → `[a,c,b]`) to keep front faces CCW.
- **Bounds:** `POSITION` accessor `min`/`max` are computed from the converted
  positions (required by the glTF spec for `POSITION`); `StaticMeshRenderData.bounds`
  is not separately emitted.

## Error handling & limits

- Defensive `let-else` on `Asset::StaticMesh`; a non-matching variant →
  `PaksmithError::Internal` (contract violation — `supports()` gates this).
- A cooked mesh whose `render_data` is `None` is filtered by `supports()`; if
  `export` is somehow reached without render data → typed error.
- A section `material_index` outside the material table → typed error
  (`MeshSectionMaterialIndexOob` or reuse of an existing bounds fault — decided
  in the impl task that adds it).
- Per-LOD vertex / index / section counts are already capped at parse time, so
  lowering allocations are bounded; accessor byte offsets use checked arithmetic.
- No panics; non-finite source floats are passed through (they originate in the
  asset, and rejecting them is out of scope for export).
- Scope: classic inlined LODs only. Nanite, the pre-4.23 legacy format,
  non-inlined LODs, and distance-field data never reach this handler — the parser
  already degrades those to `Asset::Generic` upstream, so this handler never
  receives them. (`find_handler` would otherwise return `None` for an
  unsupported `StaticMesh`, not route to the generic handler.)

## Testing

- **In-memory fixtures only** (no `.pak`, to avoid the CI fixture-count gate):
  build `StaticMeshData` values directly.
  - Unit cube: 8 vertices, 12 triangles, 1 section, 1 LOD, with normals + UV0.
  - Multi-section single LOD (two materials), multi-LOD, and a vertex-color case.
- **Assertions:** valid GLB magic + chunk framing; round-trip parse with the
  `gltf` reader (LOD/node count, primitive count, attribute presence + counts,
  material count, index component type); the converted cube's bounding box is
  Y-up and metre-scaled; winding is CCW (cross-product of the first triangle
  points outward).
- **`gltf-validator`** as a CI correctness gate when the binary is available
  (skip-with-warning otherwise; never a hard local dependency).
- **Mutation:** in-diff `cargo-mutants` 0-missed on the new module; pin the
  coordinate-transform signs and the index-width threshold with literal-value
  assertions.
- **Review panel:** ≥5 reviewers — glTF-spec/wire-format (accessor layout,
  alignment, component types), security (the dep addition + any
  attacker-influenced sizing in accessor math), performance (large-mesh memcpy),
  deep-impact (new dep + `export/` surface + 3h reuse), simplifier.

## Out of scope (tracked follow-ups)

- PBR material baking (UMaterialInterface → textures) — needs research; the user
  binds textures manually for now.
- Nanite export (parsed-but-deferred upstream).
- A CLI `export` subcommand — export is currently a library API
  (`HandlerRegistry::find_handler` + `FormatHandler::export`); CLI wiring is a
  separate task if/when the CLI grows an export command.
- `USkeletalMesh` glTF (Phase 3h; will reuse this handler's lowering helpers).

## References

- glTF 2.0 spec: <https://registry.khronos.org/glTF/specs/2.0/glTF-2.0.html>
- [`../formats/mesh/static-mesh.md`](../formats/mesh/static-mesh.md),
  [`../formats/mesh/vertex-formats.md`](../formats/mesh/vertex-formats.md)
- [`phase-3g-staticmesh-export.md`](phase-3g-staticmesh-export.md) (overview;
  3g1 parser milestones).
