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

pub(crate) mod static_mesh;
