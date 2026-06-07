//! `UStaticMesh` (and the Phase-3h `USkeletalMesh`, which will share this dir)
//! export parsing — Phase 3g.
//!
//! Wire-format reference: `docs/formats/mesh/static-mesh.md` (oracle
//! `FabianFG/CUE4Parse` `UStaticMesh.cs`). The `UStaticMesh` export body is a
//! tagged-property stream, the `UObject::Serialize` object-GUID tail, then
//! `UStaticMesh.Deserialize`'s binary fields: an `FStripDataFlags` pair,
//! `bCooked`, `BodySetup`, several more fields (`NavCollision`, `LightingGuid`,
//! `Sockets`, …), and finally the `bCooked`-gated `FStaticMeshRenderData`
//! (per-LOD vertex / index buffers).
//!
//! Phase 3g parses the whole `UStaticMesh.Deserialize` chain through the
//! `bCooked`-gated [`render_data`] geometry (UE 4.23–4.27 new-cooked, inlined
//! LODs; see [`crate::asset::StaticMeshData`] for the scope boundary). The glTF
//! `FormatHandler` that exports it is a later 3g milestone.

// Render-data parser, built bottom-up: the leaf readers (`read` helpers, vertex
// / index / section buffers) feed the `lod` / `render_data` orchestration, which
// `static_mesh.rs` reaches through the full `UStaticMesh.Deserialize` walk.
pub(crate) mod index_buffer;
pub(crate) mod lod;
mod read;
pub(crate) mod render_data;
pub(crate) mod section;
pub(crate) mod skeleton;
pub(crate) mod vertex_buffers;

pub(crate) mod static_mesh;
