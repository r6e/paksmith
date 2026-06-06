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
//! 3g1 parses through `BodySetup`; the intervening fields, the render-data
//! geometry, and the glTF `FormatHandler` land in later 3g milestones.

// The render-data parser is built bottom-up: the leaf readers (`read` helpers,
// vertex / index / section buffers) land before the `lod` / `render_data`
// orchestration that calls them and the `static_mesh.rs` continuation that
// reaches the whole tree — so they are unreachable (dead) until that wiring
// lands later in this PR. The `allow(dead_code)` is removed once wired.
#[allow(
    dead_code,
    reason = "render-data leaf readers wired by static_mesh.rs later in this PR"
)]
pub(crate) mod index_buffer;
#[allow(
    dead_code,
    reason = "render-data leaf readers wired by static_mesh.rs later in this PR"
)]
mod read;
#[allow(
    dead_code,
    reason = "render-data leaf readers wired by static_mesh.rs later in this PR"
)]
pub(crate) mod vertex_buffers;

pub(crate) mod static_mesh;
