# Mesh formats

Static and skeletal mesh payloads. Both are dense binary records with
heavy version-conditional branching — the wire layout has changed meaningfully
across UE 4.20, 4.25, 4.27, and the UE5 line.

- **`static-mesh.md`** — `StaticMesh` LODs, vertex buffers, index buffers,
  per-LOD section metadata.
- **`skeletal-mesh.md`** — `SkeletalMesh` LODs, skin weights, bone influence
  records.
- **`skeleton.md`** — the `Skeleton` asset that `SkeletalMesh` references.
- **`vertex-formats.md`** — packed-vertex layouts shared across both mesh
  types.
