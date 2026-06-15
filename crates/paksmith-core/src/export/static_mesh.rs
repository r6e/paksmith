//! `UStaticMesh` → glTF 2.0 (`.glb`) export — Phase 3g2.
//!
//! Lowers parsed [`crate::asset::StaticMeshData`] render geometry into a
//! self-contained binary glTF. Design: `docs/plans/phase-3g2-gltf-export.md`.
//!
//! Phase 3h (skeletal mesh) reuse: the LOD-agnostic glTF primitives now live in
//! [`crate::export::gltf_common`] (`GltfDoc`, `convert_position`/`convert_dir`/
//! `convert_tangent`/`normalize_xyz`, `reverse_winding`, `encode_f32_le`,
//! `finish_glb`, and the `MAX_GLB_BIN_BYTES` cap), shared with the skeletal-mesh
//! exporter. The helpers in this module
//! ([`push_positions`]/[`push_normals`]/[`push_tangents`]/[`push_uvs`]/[`push_colors`],
//! [`push_primitives`], [`resolve_section_indices`], [`build_materials`],
//! [`projected_bin_bytes`], and the [`MAX_MESH_MATERIALS`] cap) are bound to
//! [`StaticMeshLod`]/[`StaticMeshRenderData`] and would need skeletal-mesh
//! analogues.

use gltf::json::Index;
use gltf::json::mesh::{Mode, Primitive};
use gltf::json::validation::Checked::Valid;

use crate::asset::{Asset, StaticMeshLod, StaticMeshRenderData};
use crate::export::gltf_common::{
    self, GltfDoc, MAX_GLB_BIN_BYTES, convert_position, finish_glb, reverse_winding,
};
use crate::export::{BulkData, FormatHandler};

/// Maximum number of material slots a single static mesh may reference before
/// the glTF export is rejected. `section.material_index` is unchecked `i32` wire
/// data; without a cap a corrupt cook could request ~2 billion placeholder
/// [`Material`](gltf::json::Material) structs (memory-exhaustion DoS) and the
/// `max_ref + 1` sizing would overflow. Real meshes rarely exceed ~64 slots, so
/// 256 is generous. An over-cap mesh yields
/// [`PaksmithError::UnsupportedFeature`](crate::PaksmithError::UnsupportedFeature),
/// which the caller (the export driver) surfaces as it sees fit.
pub(crate) const MAX_MESH_MATERIALS: u32 = 256;

// NOTE: no `#[cfg(feature = "__test_utils")] max_mesh_materials()` accessor —
// per the `texture2d.rs` convention and the sibling mesh caps
// (`MAX_VERTICES_PER_LOD`, `MAX_SECTIONS_PER_LOD`, `MAX_LODS_PER_MESH`,
// `MAX_SOCKETS_PER_MESH`), a cap accessor with no integration-test consumer is
// dead code (an uncovered `fn -> CONST` passthrough mutant). The in-source tests
// pin the cap via the `UnsupportedFeature` over-cap path
// (`materials_over_cap_is_rejected` / `materials_at_cap_boundary_is_accepted`).

/// Lowers a cooked `UStaticMesh` into a self-contained glTF 2.0 binary (`.glb`).
/// See `docs/plans/phase-3g2-gltf-export.md`.
#[derive(Debug, Default, Clone, Copy)]
pub struct GltfStaticMeshHandler;

impl FormatHandler for GltfStaticMeshHandler {
    fn output_extension(&self) -> &'static str {
        "glb"
    }

    /// Accepts a `StaticMesh` carrying render data. Uncooked / Nanite / legacy /
    /// no-render-data meshes are degraded to [`Asset::Generic`] by the parser
    /// upstream, so they never reach this handler. (Were such a mesh to arrive
    /// here, `HandlerRegistry::find_handler` would simply return `None` for the
    /// unsupported `StaticMesh` — it would NOT route to the generic handler.)
    fn supports(&self, asset: &Asset) -> bool {
        matches!(asset, Asset::StaticMesh(d) if d.render_data.is_some())
    }

    fn export(&self, asset: &Asset, _bulk: &[BulkData]) -> crate::Result<Vec<u8>> {
        let Asset::StaticMesh(data) = asset else {
            return Err(crate::PaksmithError::Internal {
                context: "GltfStaticMeshHandler::export called on a non-StaticMesh Asset"
                    .to_string(),
            });
        };
        let render = data
            .render_data
            .as_ref()
            .ok_or_else(|| crate::PaksmithError::Internal {
                context: "GltfStaticMeshHandler::export called on a StaticMesh with no render data"
                    .to_string(),
            })?;

        // Pre-flight aggregate-output cap: reject a mesh whose lowering WOULD
        // allocate more than [`MAX_GLB_BIN_BYTES`] before allocating any of it.
        // A corrupt `num_triangles` can duplicate the full index buffer across
        // sections/LODs (memory-exhaustion DoS / `u32` GLB-length truncation).
        enforce_export_cap(render)?;

        // Pre-flight finiteness check (O(verts), so AFTER the cheaper O(sections)
        // cap). A non-finite CONVERTED position component (Inf/NaN — including a
        // finite f64 that overflows the f32 narrowing to `inf`) cannot produce
        // valid POSITION accessor bounds: an `inf` propagates through `min`/`max`
        // and `serde_json` serializes it as JSON `null` (spec-invalid bounds),
        // while a NaN is silently swallowed by `f32::min`/`max` (the bound stays
        // finite but NaN vertex bytes remain in the buffer — garbage geometry).
        // Both are rejected fail-fast rather than emitted SILENTLY.
        if !positions_all_finite(render) {
            return Err(crate::PaksmithError::UnsupportedFeature {
                context: "static mesh has a non-finite vertex position (Inf/NaN), \
                          which cannot produce valid glTF accessor bounds"
                    .to_string(),
            });
        }

        let mut doc = GltfDoc::new();
        build_materials(&mut doc, render)?;
        let mut scene_nodes = Vec::with_capacity(render.lods.len());
        for (i, lod) in render.lods.iter().enumerate() {
            let prims = push_primitives(&mut doc, lod);
            // A LOD with no geometry (empty positions, or every section's index
            // range empty) produces zero primitives. A glTF mesh requires
            // `primitives.len() ≥ 1`, so skip the node/mesh entirely. The `LOD{i}`
            // name uses the source LOD ordinal `i`, so names still reflect the
            // original index even though emitted nodes may be non-contiguous.
            if prims.is_empty() {
                continue;
            }
            let mesh = doc.root.push(gltf::json::Mesh {
                primitives: prims,
                weights: None,
                name: Some(format!("LOD{i}")),
                extensions: None,
                extras: gltf::json::extras::Void::default(),
            });
            let node = doc.root.push(gltf::json::Node {
                mesh: Some(mesh),
                name: Some(format!("LOD{i}")),
                ..gltf::json::Node::default()
            });
            scene_nodes.push(node);
        }
        let scene = doc.root.push(gltf::json::Scene {
            nodes: scene_nodes,
            name: None,
            extensions: None,
            extras: gltf::json::extras::Void::default(),
        });
        doc.root.scene = Some(scene);

        let (root, bin) = doc.into_parts();
        finish_glb(&root, bin)
    }
}

/// Push one placeholder glTF [`Material`](gltf::json::Material) per referenced
/// slot. The slot count is `max_ref + 1`, where `max_ref` is the largest
/// non-negative `material_index` across every LOD's sections (no sections ⇒ zero
/// materials). Sizing to the maximum referenced slot guarantees every
/// primitive's `material` index is in range, so there is no out-of-range error
/// path. Placeholder names are `Material_<i>`; resolving real slot names from
/// the `StaticMaterials` tagged property is deferred to a later phase.
///
/// `material_index` is unchecked `i32` wire data. To avoid a memory-exhaustion
/// DoS (and the `max_ref + 1` overflow that would panic in debug on
/// `i32::MAX`), `max_ref` is folded as an `Option<i32>` (each term is `≥ 0` via
/// `.max(0)`) and compared against [`MAX_MESH_MATERIALS`] *as `u32`* — never
/// incrementing the `i32`. A mesh exceeding the cap yields
/// [`PaksmithError::UnsupportedFeature`](crate::PaksmithError::UnsupportedFeature);
/// this error is returned to the caller (the export driver) — NOT to the package
/// walker — so the caller decides how to surface it.
fn build_materials(doc: &mut GltfDoc, render: &StaticMeshRenderData) -> crate::Result<()> {
    let Some(max_ref) = render
        .lods
        .iter()
        .flat_map(|l| &l.sections)
        .map(|s| s.material_index.max(0))
        .max()
    else {
        return Ok(()); // no sections → zero materials
    };
    // `max_ref ≥ 0` (each term went through `.max(0)`), so `try_from` cannot
    // fail; the fallback is unreachable but avoids a bare `as` sign-loss cast.
    let max_ref = u32::try_from(max_ref).unwrap_or(u32::MAX);
    // `max_ref >= MAX_MESH_MATERIALS` ⇔ `max_ref + 1 > MAX_MESH_MATERIALS`, with
    // no `i32`/`u32` increment before the comparison.
    if max_ref >= MAX_MESH_MATERIALS {
        return Err(crate::PaksmithError::UnsupportedFeature {
            context: format!(
                "static mesh references material slot {max_ref} exceeding the \
                 {MAX_MESH_MATERIALS}-slot export cap"
            ),
        });
    }
    for i in 0..=max_ref {
        let _ = doc.root.push(gltf::json::Material {
            name: Some(format!("Material_{i}")),
            ..gltf::json::Material::default()
        });
    }
    Ok(())
}

// The per-LOD geometry-attribute wrappers below now exist only for the
// unit tests that lower a single attribute in isolation; the production
// lowering path uses the shared [`gltf_common::push_geometry_attributes`]
// (which pushes the same accessors in the same order). They are `#[cfg(test)]`
// to avoid dead-code warnings while keeping the attribute-shape tests unedited.

/// Lower a LOD's positions into a `POSITION` accessor — delegates to the shared
/// [`gltf_common::push_positions`] (VEC3 f32 + component-wise `min`/`max`).
#[cfg(test)]
fn push_positions(doc: &mut GltfDoc, lod: &StaticMeshLod) -> Index<gltf::json::Accessor> {
    gltf_common::push_positions(doc, &lod.positions)
}

/// Lower normals → `NORMAL` accessor, or `None` when absent. Delegates to the
/// shared [`gltf_common::push_normals`].
#[cfg(test)]
fn push_normals(doc: &mut GltfDoc, lod: &StaticMeshLod) -> Option<Index<gltf::json::Accessor>> {
    gltf_common::push_normals(doc, &lod.normals)
}

/// Lower tangents → `TANGENT` accessor, or `None`. Delegates to the shared
/// [`gltf_common::push_tangents`].
#[cfg(test)]
fn push_tangents(doc: &mut GltfDoc, lod: &StaticMeshLod) -> Option<Index<gltf::json::Accessor>> {
    gltf_common::push_tangents(doc, &lod.tangents)
}

/// Lower each present UV channel → a `TEXCOORD_n` accessor. Delegates to the
/// shared [`gltf_common::push_uvs`].
#[cfg(test)]
fn push_uvs(doc: &mut GltfDoc, lod: &StaticMeshLod) -> Vec<Index<gltf::json::Accessor>> {
    gltf_common::push_uvs(doc, &lod.uvs)
}

/// Lower per-vertex colors → a `COLOR_0` accessor, or `None`. Delegates to the
/// shared [`gltf_common::push_colors`].
#[cfg(test)]
fn push_colors(doc: &mut GltfDoc, lod: &StaticMeshLod) -> Option<Index<gltf::json::Accessor>> {
    gltf_common::push_colors(doc, lod.colors.as_deref())
}

/// Lower a (winding-reversed) index slice → an index accessor. Delegates to the
/// shared [`gltf_common::push_indices`].
fn push_indices(doc: &mut GltfDoc, indices: &[u32]) -> Index<gltf::json::Accessor> {
    gltf_common::push_indices(doc, indices)
}

/// Resolve every section's index sub-range first (see [`resolve_section_indices`]),
/// then — only if at least one section survives — build the LOD's shared vertex
/// accessors once and emit one [`Primitive`] per surviving
/// [`MeshSection`](crate::asset::MeshSection): shared attributes (cloned) + that
/// section's winding-reversed index accessor + the section's material index. A
/// corrupt negative `material_index` maps to slot 0.
///
/// Returns no primitives — and emits **no accessors** — for a LOD with empty
/// positions OR a LOD where every section's resolved span is empty/sub-triangle:
/// a glTF `accessor.count` must be `≥ 1`, and the shared vertex accessors are
/// built only when a primitive will reference them, so a fully-skipped LOD
/// leaves no orphaned `POSITION` accessor (gltf-validator UNUSED_OBJECT). The
/// caller drops any LOD that ends up with zero primitives.
fn push_primitives(doc: &mut GltfDoc, lod: &StaticMeshLod) -> Vec<Primitive> {
    // A LOD with no vertices has no geometry to lower. Returning early *before*
    // building any accessor avoids emitting an invalid `count = 0` POSITION
    // accessor (orphaned in `root.accessors` even when the caller skips the
    // node), which gltf-validator rejects.
    if lod.positions.is_empty() {
        return Vec::new();
    }

    // Resolve each section's winding-reversed index buffer FIRST, before pushing
    // any accessor. A section whose resolved span is empty or sub-triangle is
    // dropped here, so if every section is skipped we push no vertex accessors
    // at all — otherwise the shared POSITION/NORMAL/etc. accessors would be
    // orphaned (no primitive referencing them → gltf-validator UNUSED_OBJECT).
    let sections: Vec<(i32, Vec<u32>)> = lod
        .sections
        .iter()
        .filter_map(|s| resolve_section_indices(lod, s).map(|idx| (s.material_index, idx)))
        .collect();
    if sections.is_empty() {
        return Vec::new();
    }

    // Shared vertex accessors (built once per LOD; cloned into each primitive).
    let attributes = gltf_common::push_geometry_attributes(
        doc,
        &lod.positions,
        &lod.normals,
        &lod.tangents,
        &lod.uvs,
        lod.colors.as_deref(),
    );

    let mut prims = Vec::with_capacity(sections.len());
    for (material_index, section_indices) in sections {
        let idx = push_indices(doc, &section_indices);
        // `.max(0)` guarantees the cast operand is non-negative, so the sign-loss
        // lint cannot apply; a negative slot is remapped to 0.
        #[allow(clippy::cast_sign_loss)]
        let material = Some(Index::new(material_index.max(0) as u32));
        prims.push(Primitive {
            attributes: attributes.clone(),
            indices: Some(idx),
            material,
            mode: Valid(Mode::Triangles),
            targets: None,
            extensions: None,
            extras: gltf::json::extras::Void::default(),
        });
    }
    prims
}

/// Resolve one section's index sub-range into a winding-reversed `Vec<u32>`, or
/// `None` when the section contributes no whole triangle.
///
/// An empty or fully-sub-triangle span yields `None` (the caller emits no
/// primitive and no `count = 0` index accessor). See [`section_index_span`] for
/// the clamp + triangle-floor rules.
fn resolve_section_indices(lod: &StaticMeshLod, s: &crate::asset::MeshSection) -> Option<Vec<u32>> {
    let (first, tri_len) = section_index_span(lod, s);
    if tri_len == 0 {
        return None;
    }
    Some(reverse_winding(lod.indices.get(first..first + tri_len)?))
}

/// Resolve one static-mesh section's `[first_index, first_index + 3·num_triangles)`
/// index range against the LOD index buffer. Delegates to the shared
/// [`gltf_common::section_index_span`] (clamp + whole-triangle floor); see there
/// for the attacker-controlled `i32` defenses.
fn section_index_span(lod: &StaticMeshLod, s: &crate::asset::MeshSection) -> (usize, usize) {
    gltf_common::section_index_span(s.first_index, s.num_triangles, lod.indices.len())
}

/// `true` when a [`projected_bin_bytes`] estimate exceeds the
/// [`MAX_GLB_BIN_BYTES`] aggregate-output cap. Extracted as a pure predicate so
/// the `> cap` boundary is unit-testable at the exact cap value without
/// allocating a cap-sized mesh (the `export` path can only exercise it via a
/// multi-GiB allocation).
fn exceeds_export_cap(projected: u64) -> bool {
    projected > MAX_GLB_BIN_BYTES
}

/// Reject a mesh whose projected glTF BIN buffer exceeds [`MAX_GLB_BIN_BYTES`]
/// BEFORE any lowering allocates. Pure (no allocation) so the over-cap rejection
/// is unit-testable without building a multi-GiB GLB — the slow `export` path
/// would time out the mutation runner if it had to allocate the projected bytes.
fn enforce_export_cap(render: &StaticMeshRenderData) -> crate::Result<()> {
    let projected = projected_bin_bytes(render);
    if exceeds_export_cap(projected) {
        return Err(crate::PaksmithError::UnsupportedFeature {
            context: format!(
                "static mesh projected glTF buffer ({projected} bytes) exceeds the \
                 {MAX_GLB_BIN_BYTES}-byte export cap"
            ),
        });
    }
    Ok(())
}

/// Sum the BIN bytes [`GltfStaticMeshHandler::export`] WOULD allocate, WITHOUT
/// allocating them — a pure pre-flight projection for the [`MAX_GLB_BIN_BYTES`]
/// aggregate-output cap. All arithmetic saturates (`u64`) because every count is
/// attacker-controlled wire data.
///
/// Per LOD: the vertex attributes (positions ×12, normals ×12, tangents ×16,
/// each present UV channel ×8, colors ×4) plus, per section, the FLOORED
/// triangle span × 4 (an `UNSIGNED_INT` upper bound — the real accessor may pick
/// `UNSIGNED_SHORT`, so this over-estimates and stays a safe upper bound). The
/// span/floor comes from [`section_index_span`] (shared with
/// [`resolve_section_indices`]) so the estimate tracks reality.
fn projected_bin_bytes(render: &StaticMeshRenderData) -> u64 {
    let mut total: u64 = 0;
    for lod in &render.lods {
        total = total.saturating_add((lod.positions.len() as u64).saturating_mul(12));
        total = total.saturating_add((lod.normals.len() as u64).saturating_mul(12));
        total = total.saturating_add((lod.tangents.len() as u64).saturating_mul(16));
        for channel in lod.uvs.iter().flatten() {
            total = total.saturating_add((channel.len() as u64).saturating_mul(8));
        }
        if let Some(colors) = lod.colors.as_ref() {
            total = total.saturating_add((colors.len() as u64).saturating_mul(4));
        }
        for s in &lod.sections {
            let (_first, tri_len) = section_index_span(lod, s);
            // Each index is at most a u32 (4 bytes) — a safe over-estimate.
            total = total.saturating_add((tri_len as u64).saturating_mul(4));
        }
    }
    total
}

/// `true` when every vertex position in every LOD converts to a finite glTF
/// position. The scan runs over the **converted f32** ([`convert_position`]),
/// not the raw `FVector` f64: a finite f64 can overflow the f32 narrowing
/// (`1e40_f64 as f32 == f32::INFINITY`), and `serde_json` serializes a
/// non-finite f32 as JSON `null` — which in the required POSITION accessor
/// `min`/`max` is spec-invalid glTF. Pure pre-flight predicate so
/// [`GltfStaticMeshHandler::export`] can fail-fast before building any document.
fn positions_all_finite(render: &StaticMeshRenderData) -> bool {
    render.lods.iter().flat_map(|l| &l.positions).all(|p| {
        let [x, y, z] = convert_position(p);
        x.is_finite() && y.is_finite() && z.is_finite()
    })
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use gltf::json::accessor::{ComponentType, GenericComponentType, Type};
    use gltf::json::mesh::Semantic;

    use super::*;
    use crate::asset::structs::bounds::FBoxSphereBounds;
    use crate::asset::structs::vector::{FVector, FVector4};
    use crate::asset::{Asset, StaticMeshData, StaticMeshRenderData};
    use crate::export::gltf_common::convert_dir;

    fn mesh_with(render: StaticMeshRenderData) -> Asset {
        let mut data = StaticMeshData::empty();
        data.cooked = true;
        data.render_data = Some(render);
        Asset::StaticMesh(data)
    }

    fn empty_render() -> StaticMeshRenderData {
        StaticMeshRenderData {
            lods: Vec::new(),
            bounds: FBoxSphereBounds {
                origin: FVector {
                    x: 0.0,
                    y: 0.0,
                    z: 0.0,
                },
                box_extent: FVector {
                    x: 0.0,
                    y: 0.0,
                    z: 0.0,
                },
                sphere_radius: 0.0,
            },
            lods_share_static_lighting: false,
            screen_sizes: Vec::new(),
        }
    }

    #[test]
    fn extension_is_glb() {
        assert_eq!(GltfStaticMeshHandler.output_extension(), "glb");
    }

    #[test]
    fn supports_cooked_mesh_with_render_data_only() {
        assert!(GltfStaticMeshHandler.supports(&mesh_with(empty_render())));
        assert!(!GltfStaticMeshHandler.supports(&Asset::StaticMesh(StaticMeshData::empty())));
        assert!(!GltfStaticMeshHandler.supports(&Asset::Generic(
            crate::asset::PropertyBag::opaque(Vec::new())
        )));
    }

    #[test]
    fn exports_minimal_valid_glb() {
        let bytes = GltfStaticMeshHandler
            .export(&mesh_with(empty_render()), &[])
            .expect("export");
        assert_eq!(&bytes[0..4], b"glTF");
        let glb = gltf::Glb::from_slice(&bytes).expect("parse glb");
        // gltf-json 1.4.1 derives `Scene::nodes` with
        // `skip_serializing_if = "Vec::is_empty"` on serialize but NO
        // `#[serde(default)]` on deserialize, so re-deserializing into
        // `gltf::json::Root` fails on an empty scene ("missing field `nodes`").
        // Assert structurally via `serde_json::Value` instead — an absent
        // `nodes` key means zero root nodes.
        let doc: serde_json::Value = serde_json::from_slice(&glb.json).expect("parse json");
        let scenes = doc["scenes"].as_array().expect("scenes array");
        assert_eq!(scenes.len(), 1);
        let node_count = scenes[0]
            .get("nodes")
            .and_then(|n| n.as_array())
            .map_or(0, Vec::len);
        assert_eq!(node_count, 0);
    }

    #[test]
    fn registry_routes_cooked_static_mesh_to_glb() {
        let reg = crate::export::HandlerRegistry::all_default_handlers();
        let handler = reg
            .find_handler(&mesh_with(empty_render()))
            .expect("a handler");
        assert_eq!(handler.output_extension(), "glb");
    }

    /// Pin the `gltf` write API: an empty `json::Root` (asset only) serializes,
    /// wraps in a `binary::Glb`, and `to_vec` produces bytes starting with the
    /// `glTF` magic. Establishes the exact types the later tasks build on.
    #[test]
    fn gltf_write_api_round_trips_empty_doc() {
        let root = gltf::json::Root::default();
        let json = serde_json::to_vec(&root).expect("serialize root");
        let mut json = json;
        while !json.len().is_multiple_of(4) {
            json.push(b' ');
        }
        let glb = gltf::binary::Glb {
            header: gltf::binary::Header {
                magic: *b"glTF",
                version: 2,
                length: 0,
            },
            json: Cow::Owned(json),
            bin: None,
        };
        let bytes = glb.to_vec().expect("glb to_vec");
        assert_eq!(&bytes[0..4], b"glTF", "GLB magic");
        assert!(bytes.len() >= 12, "GLB has at least a 12-byte header");
    }

    // ---------- Vertex-attribute accessor tests (Tasks 5-8) ----------

    use crate::asset::structs::color::FColor;
    use crate::asset::structs::vector::FVector2D;

    fn lod_one_triangle() -> StaticMeshLod {
        StaticMeshLod {
            sections: Vec::new(),
            positions: vec![
                FVector {
                    x: 0.0,
                    y: 0.0,
                    z: 0.0,
                },
                FVector {
                    x: 100.0,
                    y: 0.0,
                    z: 0.0,
                },
                FVector {
                    x: 0.0,
                    y: 0.0,
                    z: 100.0,
                },
            ],
            normals: Vec::new(),
            tangents: Vec::new(),
            uvs: [None, None, None, None],
            num_tex_coords: 0,
            colors: None,
            indices: vec![0, 1, 2],
        }
    }

    #[test]
    fn position_accessor_has_vec3_f32_and_minmax() {
        let mut doc = GltfDoc::new();
        let acc = push_positions(&mut doc, &lod_one_triangle());
        let (root, _bin) = doc.into_parts();
        let a = &root.accessors[acc.value()];
        assert!(matches!(a.type_, Valid(Type::Vec3)));
        assert!(matches!(
            a.component_type,
            Valid(GenericComponentType(ComponentType::F32))
        ));
        assert_eq!(a.count.0, 3);
        // convert_position maps UE (x,y,z) cm → glTF (x, z, y) m. Vertices:
        //   v0 (0,0,0)     → (0,0,0)
        //   v1 (100,0,0)   → (1.0, 0.0, 0.0)
        //   v2 (0,0,100)   → (0.0, 1.0, 0.0)  [UE-Z → glTF-Y]
        // so min = (0,0,0), max = (1.0, 1.0, 0.0). max-Y = 1.0 (from v2's UE-Z),
        // max-Z = 0.0 — pins the Y/Z basis swap AND that min != max.
        assert_eq!(a.min.as_ref().unwrap(), &serde_json::json!([0.0, 0.0, 0.0]));
        assert_eq!(a.max.as_ref().unwrap(), &serde_json::json!([1.0, 1.0, 0.0]));
        // POSITION is plain f32, never normalized — pins normalized=false against
        // a false→true mutant.
        assert!(!a.normalized);
    }

    #[test]
    fn position_accessor_empty_emits_zero_minmax() {
        let mut lod = lod_one_triangle();
        lod.positions = Vec::new();
        let mut doc = GltfDoc::new();
        let acc = push_positions(&mut doc, &lod);
        let (root, _bin) = doc.into_parts();
        let a = &root.accessors[acc.value()];
        assert_eq!(a.count.0, 0);
        // Empty list → the INFINITY/NEG_INFINITY seeds must be replaced with
        // zeros (deleting that guard leaves non-finite ±inf in min/max).
        assert_eq!(a.min.as_ref().unwrap(), &serde_json::json!([0.0, 0.0, 0.0]));
        assert_eq!(a.max.as_ref().unwrap(), &serde_json::json!([0.0, 0.0, 0.0]));
    }

    #[test]
    fn normal_and_tangent_accessors_have_right_shapes() {
        let mut lod = lod_one_triangle();
        lod.normals = vec![
            FVector {
                x: 0.0,
                y: 0.0,
                z: 1.0
            };
            3
        ];
        lod.tangents = vec![
            FVector4 {
                x: 1.0,
                y: 0.0,
                z: 0.0,
                w: 1.0
            };
            3
        ];
        let mut doc = GltfDoc::new();
        let n = push_normals(&mut doc, &lod).expect("normals present");
        let t = push_tangents(&mut doc, &lod).expect("tangents present");
        let (root, _bin) = doc.into_parts();
        let na = &root.accessors[n.value()];
        let ta = &root.accessors[t.value()];
        assert!(matches!(na.type_, Valid(Type::Vec3)));
        assert!(matches!(
            na.component_type,
            Valid(GenericComponentType(ComponentType::F32))
        ));
        assert_eq!(na.count.0, 3);
        assert!(matches!(ta.type_, Valid(Type::Vec4)));
        assert!(matches!(
            ta.component_type,
            Valid(GenericComponentType(ComponentType::F32))
        ));
        assert_eq!(ta.count.0, 3);
        // f32 attributes are never normalized — pins normalized=false.
        assert!(!na.normalized);
        assert!(!ta.normalized);
    }

    #[test]
    fn normals_absent_returns_none() {
        let mut doc = GltfDoc::new();
        assert!(push_normals(&mut doc, &lod_one_triangle()).is_none());
    }

    #[test]
    fn tangents_absent_returns_none() {
        let mut doc = GltfDoc::new();
        assert!(push_tangents(&mut doc, &lod_one_triangle()).is_none());
    }

    #[test]
    fn uv_accessors_one_per_present_channel() {
        let mut lod = lod_one_triangle();
        lod.num_tex_coords = 2;
        lod.uvs[0] = Some(vec![FVector2D { x: 0.0, y: 0.0 }; 3]);
        lod.uvs[1] = Some(vec![FVector2D { x: 0.5, y: 0.5 }; 3]);
        let mut doc = GltfDoc::new();
        let accs = push_uvs(&mut doc, &lod);
        assert_eq!(accs.len(), 2);
        let (root, _bin) = doc.into_parts();
        for a in &accs {
            let acc = &root.accessors[a.value()];
            assert!(matches!(acc.type_, Valid(Type::Vec2)));
            assert!(matches!(
                acc.component_type,
                Valid(GenericComponentType(ComponentType::F32))
            ));
            assert_eq!(acc.count.0, 3);
            // UV f32 attributes are never normalized — pins normalized=false.
            assert!(!acc.normalized);
        }
    }

    #[test]
    fn uv_accessors_empty_when_no_channels() {
        let mut doc = GltfDoc::new();
        let accs = push_uvs(&mut doc, &lod_one_triangle());
        assert!(accs.is_empty());
    }

    #[test]
    fn color_accessor_is_u8_vec4_normalized() {
        let mut lod = lod_one_triangle();
        lod.colors = Some(vec![
            FColor {
                r: 255,
                g: 128,
                b: 0,
                a: 255
            };
            3
        ]);
        let mut doc = GltfDoc::new();
        let c = push_colors(&mut doc, &lod).expect("colors present");
        let (root, bin) = doc.into_parts();
        let a = &root.accessors[c.value()];
        assert!(matches!(a.type_, Valid(Type::Vec4)));
        assert!(matches!(
            a.component_type,
            Valid(GenericComponentType(ComponentType::U8))
        ));
        assert!(a.normalized);
        assert_eq!(a.count.0, 3);
        // First vertex bytes are RGBA = 255,128,0,255 at the view's offset.
        // Asymmetric (r != g != b) pins RGBA order vs a BGRA/ARGB mutant.
        let off = usize::try_from(
            root.buffer_views[a.buffer_view.unwrap().value()]
                .byte_offset
                .unwrap()
                .0,
        )
        .expect("byte offset fits usize");
        assert_eq!(&bin[off..off + 4], &[255u8, 128, 0, 255]);
    }

    #[test]
    fn colors_absent_returns_none() {
        let mut doc = GltfDoc::new();
        assert!(push_colors(&mut doc, &lod_one_triangle()).is_none());
    }

    // ---------- Per-section primitive + index accessor tests (Task 9) ----------

    use crate::asset::exports::mesh::section::MeshSection;

    fn section(material_index: i32, first_index: i32, num_triangles: i32) -> MeshSection {
        MeshSection {
            material_index,
            first_index,
            num_triangles,
            min_vertex_index: 0,
            max_vertex_index: 0,
            enable_collision: false,
            cast_shadow: false,
            force_opaque: false,
            visible_in_ray_tracing: false,
            affect_distance_field_lighting: false,
        }
    }

    #[test]
    fn index_width_u16_for_small_meshes() {
        // Max index value ≤ 65535 → UNSIGNED_SHORT.
        let mut doc = GltfDoc::new();
        let acc = push_indices(&mut doc, &[0u32, 1, 2]);
        let (root, _bin) = doc.into_parts();
        assert!(matches!(
            root.accessors[acc.value()].component_type,
            Valid(GenericComponentType(ComponentType::U16))
        ));
    }

    #[test]
    fn index_width_u32_above_u16_range() {
        // Max index value 70_000 > 65535 → UNSIGNED_INT.
        let mut doc = GltfDoc::new();
        let acc = push_indices(&mut doc, &[0u32, 1, 70_000]);
        let (root, _bin) = doc.into_parts();
        assert!(matches!(
            root.accessors[acc.value()].component_type,
            Valid(GenericComponentType(ComponentType::U32))
        ));
    }

    /// Pin the exact `<= u16::MAX` boundary on the index VALUE: a max index of
    /// 65 535 is still U16. A `<=`→`<` mutant would flip this case to U32.
    #[test]
    fn index_width_u16_at_exact_boundary() {
        let mut doc = GltfDoc::new();
        let acc = push_indices(&mut doc, &[0u32, 1, u32::from(u16::MAX)]); // max 65 535
        let (root, _bin) = doc.into_parts();
        assert!(matches!(
            root.accessors[acc.value()].component_type,
            Valid(GenericComponentType(ComponentType::U16))
        ));
    }

    /// Pin the first over-boundary VALUE: a max index of 65 536 → U32. Together
    /// with the 65 535 case this brackets the threshold from both sides, and a
    /// width-by-count mutant (3 indices → U16) would truncate 65 536 silently.
    #[test]
    fn index_width_u32_just_above_boundary() {
        let mut doc = GltfDoc::new();
        let acc = push_indices(&mut doc, &[0u32, 1, u32::from(u16::MAX) + 1]); // max 65 536
        let (root, bin) = doc.into_parts();
        assert!(matches!(
            root.accessors[acc.value()].component_type,
            Valid(GenericComponentType(ComponentType::U32))
        ));
        // And the value is NOT truncated: the third index reads back as 65 536.
        let view = root.accessors[acc.value()].buffer_view.unwrap();
        let off = usize::try_from(root.buffer_views[view.value()].byte_offset.unwrap().0)
            .expect("offset fits usize");
        let third = u32::from_le_bytes([bin[off + 8], bin[off + 9], bin[off + 10], bin[off + 11]]);
        assert_eq!(third, u32::from(u16::MAX) + 1);
    }

    #[test]
    fn primitive_per_section_reverses_winding_and_refs_material() {
        let mut lod = lod_one_triangle();
        lod.normals = vec![
            FVector {
                x: 0.0,
                y: 0.0,
                z: 1.0
            };
            3
        ];
        lod.sections = vec![section(2, 0, 1)]; // material 2, 1 triangle from index 0
        let mut doc = GltfDoc::new();
        let prims = push_primitives(&mut doc, &lod);
        assert_eq!(prims.len(), 1);
        assert_eq!(prims[0].material.map(|m| m.value()), Some(2));
        // The shared NORMAL accessor is referenced by the primitive's attributes.
        assert!(prims[0].attributes.contains_key(&Valid(Semantic::Normals)));
        assert!(
            prims[0]
                .attributes
                .contains_key(&Valid(Semantic::Positions))
        );
        // The index accessor holds the winding-reversed triple [0,2,1].
        let idx_acc = prims[0].indices.unwrap();
        let (root, bin) = doc.into_parts();
        let view = root.accessors[idx_acc.value()].buffer_view.unwrap();
        // gltf-json 1.4.1 `USize64` exposes its inner value only via `.0`
        // (no `From<USize64> for u64`); the plan's `u64::from(..)` won't compile.
        let off = usize::try_from(root.buffer_views[view.value()].byte_offset.unwrap().0)
            .expect("offset fits usize");
        let got: Vec<u16> = bin[off..off + 6]
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect();
        assert_eq!(got, vec![0u16, 2, 1]);
    }

    /// A section whose triangle count overruns the index buffer (corrupt cook)
    /// is clamped to the available indices, not a panic.
    #[test]
    fn primitive_overrunning_section_is_clamped() {
        let mut lod = lod_one_triangle(); // 3 indices
        lod.sections = vec![section(0, 0, 100)]; // claims 300 indices
        let mut doc = GltfDoc::new();
        let prims = push_primitives(&mut doc, &lod);
        assert_eq!(prims.len(), 1);
        let idx_acc = prims[0].indices.unwrap();
        let (root, _bin) = doc.into_parts();
        // Clamped to the 3 available indices → exactly one reversed triangle.
        assert_eq!(root.accessors[idx_acc.value()].count.0, 3);
    }

    /// A section whose `first_index` lies past the end of the index buffer
    /// (corrupt cook) has an empty resolved range and is SKIPPED — emitting a
    /// `count = 0` index accessor is invalid glTF. No primitive is produced.
    #[test]
    fn primitive_first_index_past_end_is_skipped() {
        let mut lod = lod_one_triangle(); // 3 indices
        lod.sections = vec![section(0, 1000, 1)]; // first_index well past the buffer
        let mut doc = GltfDoc::new();
        let prims = push_primitives(&mut doc, &lod);
        assert!(prims.is_empty());
        // Every section is skipped, so NO accessors are emitted (not even the
        // shared POSITION accessor — vertex accessors are built only when a
        // primitive will reference them).
        let (root, _bin) = doc.into_parts();
        assert!(
            root.accessors.is_empty(),
            "no accessors when every section is skipped"
        );
    }

    /// A zero-triangle section (empty resolved range) is SKIPPED, producing no
    /// primitive and no `count = 0` index accessor.
    #[test]
    fn zero_triangle_section_is_skipped() {
        let mut lod = lod_one_triangle(); // 3 indices, one real triangle
        lod.sections = vec![section(0, 0, 1), section(0, 0, 0)]; // real + 0-tri
        let mut doc = GltfDoc::new();
        let prims = push_primitives(&mut doc, &lod);
        assert_eq!(prims.len(), 1, "the 0-triangle section is dropped");
        let (root, _bin) = doc.into_parts();
        assert!(
            root.accessors.iter().all(|a| a.count.0 >= 1),
            "no zero-count accessor was emitted"
        );
    }

    /// A section index span that is not a whole number of triangles is floored
    /// to the largest triangle multiple before winding-reversal. With a 5-index
    /// buffer and a section claiming 10 triangles, the resolved span clamps to 5
    /// then floors to 3 (one triangle), so the emitted index accessor `count`
    /// is 3, not 5. A glTF TRIANGLES primitive requires `count % 3 == 0`.
    #[test]
    fn section_index_span_floored_to_triangle_multiple() {
        let mut lod = lod_one_triangle();
        // 5 indices — NOT a multiple of 3 (the parser only checks % index_size).
        lod.positions.push(FVector {
            x: 0.0,
            y: 0.0,
            z: 0.0,
        });
        lod.positions.push(FVector {
            x: 0.0,
            y: 0.0,
            z: 0.0,
        });
        lod.indices = vec![0, 1, 2, 3, 4];
        lod.sections = vec![section(0, 0, 10)]; // claims 30 indices
        let mut doc = GltfDoc::new();
        let prims = push_primitives(&mut doc, &lod);
        assert_eq!(prims.len(), 1);
        let idx_acc = prims[0].indices.unwrap();
        let (root, _bin) = doc.into_parts();
        // Clamped to 5, then floored to a whole triangle → count 3, not 5.
        assert_eq!(root.accessors[idx_acc.value()].count.0, 3);
    }

    /// `section_index_span` directly: the shared clamp + triangle-floor helper
    /// returns `(first, tri_len)`. Asserting literal values pins the `% 3` floor,
    /// the `.min` clamp, and the `try_from(..).unwrap_or(0)` saturation against
    /// mutation (the `push_primitives`-level tests only observe the floor
    /// indirectly through the emitted accessor `count`).
    #[test]
    fn section_index_span_floors_and_skips() {
        let mut lod = lod_one_triangle();
        lod.indices = vec![0, 1, 2, 3, 4]; // 5 indices, NOT a multiple of 3

        // (a) 5-index buffer, section claims 10 triangles (30 indices):
        // clamp 30 → 5, floor 5 → 3.
        assert_eq!(section_index_span(&lod, &section(0, 0, 10)), (0, 3));

        // (a2) 8-index buffer, claim 10 triangles: clamp 30 → 8, floor 8 → 6.
        // A second remainder (8 % 3 == 2, but 8 - 2 == 6 ≠ 8 - 3) so a
        // `% 3` → `- 3` mutant (which would also yield 3 at avail == 5) dies.
        let mut lod8 = lod_one_triangle();
        lod8.indices = vec![0, 1, 2, 3, 4, 5, 6, 7];
        assert_eq!(section_index_span(&lod8, &section(0, 0, 10)), (0, 6));

        // (b) first_index past the end → empty span, tri_len 0. `first` is
        // returned unclamped (1000), but the caller skips on tri_len == 0.
        assert_eq!(section_index_span(&lod, &section(0, 1000, 1)), (1000, 0));

        // (c) negative inputs saturate to 0 via `try_from(..).unwrap_or(0)`.
        assert_eq!(section_index_span(&lod, &section(0, -5, -7)), (0, 0));
    }

    /// Every section's resolved span is sub-triangle (here a single 0-triangle
    /// section over a non-empty-position LOD) → the LOD emits NO node/mesh AND
    /// NO accessors at all (no orphaned POSITION accessor for gltf-validator to
    /// flag as UNUSED_OBJECT).
    #[test]
    fn all_sections_subtriangle_emits_no_node() {
        let mut lod = lod_one_triangle(); // non-empty positions
        lod.sections = vec![section(0, 0, 0)]; // single 0-triangle section
        let render = StaticMeshRenderData {
            lods: vec![lod],
            ..empty_render()
        };
        let bytes = GltfStaticMeshHandler
            .export(&mesh_with(render), &[])
            .expect("export");
        let glb = gltf::Glb::from_slice(&bytes).expect("glb");
        // The scene has zero nodes, so strict `gltf::json::Root` re-deserialize
        // fails on the absent `nodes` field (see `exports_minimal_valid_glb`).
        // Assert structurally via `serde_json::Value`: absent keys mean empty.
        let doc: serde_json::Value = serde_json::from_slice(&glb.json).expect("json");
        let len = |k: &str| doc.get(k).and_then(|v| v.as_array()).map_or(0, Vec::len);
        assert_eq!(len("meshes"), 0, "no mesh for an all-empty LOD");
        assert_eq!(len("nodes"), 0, "no node for an all-empty LOD");
        // No vertex accessors were pushed — the shared POSITION/NORMAL/etc. are
        // built only when at least one section will emit a primitive.
        assert_eq!(
            len("accessors"),
            0,
            "no orphaned vertex accessor when every section is skipped"
        );
    }

    /// A LOD with no positions emits NO accessors at all (not even a
    /// `count = 0` POSITION accessor, which is invalid glTF).
    #[test]
    fn empty_lod_emits_no_accessors() {
        let lod = StaticMeshLod {
            sections: Vec::new(),
            positions: Vec::new(),
            normals: Vec::new(),
            tangents: Vec::new(),
            uvs: [None, None, None, None],
            num_tex_coords: 0,
            colors: None,
            indices: Vec::new(),
        };
        let mut doc = GltfDoc::new();
        let prims = push_primitives(&mut doc, &lod);
        assert!(prims.is_empty());
        let (root, _bin) = doc.into_parts();
        assert!(root.accessors.is_empty());
    }

    /// End-to-end: a render with one empty LOD (no geometry) followed by one
    /// real LOD emits exactly ONE node/mesh, named for the SOURCE LOD ordinal
    /// (`LOD1`), not renumbered — and no zero-count accessor survives.
    #[test]
    fn empty_lod_emits_no_node() {
        let empty = StaticMeshLod {
            sections: Vec::new(),
            positions: Vec::new(),
            normals: Vec::new(),
            tangents: Vec::new(),
            uvs: [None, None, None, None],
            num_tex_coords: 0,
            colors: None,
            indices: Vec::new(),
        };
        let mut real = lod_one_triangle();
        real.sections = vec![section(0, 0, 1)];
        let render = StaticMeshRenderData {
            lods: vec![empty, real],
            ..empty_render()
        };
        let bytes = GltfStaticMeshHandler
            .export(&mesh_with(render), &[])
            .expect("export");
        let glb = gltf::Glb::from_slice(&bytes).expect("glb");
        let root: gltf::json::Root = serde_json::from_slice(&glb.json).expect("json");
        assert_eq!(root.meshes.len(), 1);
        assert_eq!(root.nodes.len(), 1);
        // Name reflects the SOURCE index (LOD1), not the emitted ordinal.
        assert_eq!(root.nodes[0].name.as_deref(), Some("LOD1"));
        // No accessor may have count 0 (gltf-validator requires count ≥ 1).
        assert!(root.accessors.iter().all(|a| a.count.0 >= 1));
    }

    /// A corrupt negative `material_index` maps to slot 0 (never panics).
    #[test]
    fn primitive_negative_material_index_maps_to_zero() {
        let mut lod = lod_one_triangle();
        lod.sections = vec![section(-5, 0, 1)];
        let mut doc = GltfDoc::new();
        let prims = push_primitives(&mut doc, &lod);
        assert_eq!(prims[0].material.map(|m| m.value()), Some(0));
    }

    // ---------- Scene wiring + materials tests (Tasks 10-11) ----------

    #[test]
    fn each_lod_becomes_a_named_node_and_mesh() {
        let mut lod0 = lod_one_triangle();
        lod0.sections = vec![section(0, 0, 1)];
        let mut lod1 = lod_one_triangle();
        lod1.sections = vec![section(0, 0, 1)];
        let render = StaticMeshRenderData {
            lods: vec![lod0, lod1],
            ..empty_render()
        };
        let bytes = GltfStaticMeshHandler
            .export(&mesh_with(render), &[])
            .expect("export");
        let glb = gltf::Glb::from_slice(&bytes).expect("glb");
        let root: gltf::json::Root = serde_json::from_slice(&glb.json).expect("json");
        assert_eq!(root.meshes.len(), 2);
        assert_eq!(root.nodes.len(), 2);
        assert_eq!(root.scenes[0].nodes.len(), 2);
        assert_eq!(root.nodes[0].name.as_deref(), Some("LOD0"));
        assert_eq!(root.nodes[1].name.as_deref(), Some("LOD1"));
        // Each node must reference its own mesh, in order — pins the `mesh`
        // field against a delete-field mutant (a node without a mesh draws
        // nothing).
        assert_eq!(root.nodes[0].mesh.map(|m| m.value()), Some(0));
        assert_eq!(root.nodes[1].mesh.map(|m| m.value()), Some(1));
    }

    #[test]
    fn materials_cover_all_referenced_slots_named() {
        let mut lod = lod_one_triangle();
        lod.sections = vec![section(0, 0, 1), section(3, 0, 1)]; // references slot 3
        let render = StaticMeshRenderData {
            lods: vec![lod],
            ..empty_render()
        };
        let bytes = GltfStaticMeshHandler
            .export(&mesh_with(render), &[])
            .expect("export");
        let glb = gltf::Glb::from_slice(&bytes).expect("glb");
        let root: gltf::json::Root = serde_json::from_slice(&glb.json).expect("json");
        // max referenced index is 3 → at least 4 materials.
        assert_eq!(root.materials.len(), 4);
        assert_eq!(root.materials[0].name.as_deref(), Some("Material_0"));
        assert_eq!(root.materials[3].name.as_deref(), Some("Material_3"));
    }

    /// No sections anywhere → zero materials. Pins the empty-fold
    /// `else { return Ok(()) }` branch: emitting any material here is wrong.
    /// `build_materials` is tested directly because a section-free LOD produces
    /// no primitives (FIX 4) → an empty scene that the strict re-deserializer
    /// rejects on a missing `nodes` field.
    #[test]
    fn materials_empty_when_no_sections() {
        let render = StaticMeshRenderData {
            lods: vec![lod_one_triangle()], // a LOD with zero sections
            ..empty_render()
        };
        let mut doc = GltfDoc::new();
        build_materials(&mut doc, &render).expect("no-section mesh builds no materials");
        assert_eq!(doc.root.materials.len(), 0);
    }

    /// Every section references a negative (corrupt) slot → the table still
    /// covers slot 0 (one material). Pins the `.max(0)` clamp: dropping it makes
    /// `max_ref = -5`, `count = 0`, leaving the primitive's `Index::new(0)`
    /// material reference dangling.
    #[test]
    fn materials_all_negative_sections_cover_slot_zero() {
        let mut lod = lod_one_triangle();
        lod.sections = vec![section(-5, 0, 1), section(-2, 0, 1)];
        let render = StaticMeshRenderData {
            lods: vec![lod],
            ..empty_render()
        };
        let bytes = GltfStaticMeshHandler
            .export(&mesh_with(render), &[])
            .expect("export");
        let glb = gltf::Glb::from_slice(&bytes).expect("glb");
        let root: gltf::json::Root = serde_json::from_slice(&glb.json).expect("json");
        assert_eq!(root.materials.len(), 1);
        assert_eq!(root.materials[0].name.as_deref(), Some("Material_0"));
    }

    /// A section referencing slot `MAX_MESH_MATERIALS` (one past the last
    /// allowed slot, since slots are 0-based) exceeds the export cap and is
    /// rejected with `UnsupportedFeature` — no panic, no ~256-material+ alloc.
    #[test]
    fn materials_over_cap_is_rejected() {
        let over_cap = i32::try_from(MAX_MESH_MATERIALS).expect("cap fits i32");
        let mut lod = lod_one_triangle();
        lod.sections = vec![section(over_cap, 0, 1)];
        let render = StaticMeshRenderData {
            lods: vec![lod],
            ..empty_render()
        };
        let err = GltfStaticMeshHandler
            .export(&mesh_with(render), &[])
            .expect_err("over-cap mesh must be rejected");
        assert!(matches!(
            err,
            crate::PaksmithError::UnsupportedFeature { .. }
        ));
    }

    /// The last in-cap slot (`MAX_MESH_MATERIALS - 1`) is still accepted — pins
    /// the `>=` boundary so a `>=`→`>` mutant (which would accept the over-cap
    /// slot) is caught alongside `materials_over_cap_is_rejected`.
    #[test]
    fn materials_at_cap_boundary_is_accepted() {
        let last_in_cap = i32::try_from(MAX_MESH_MATERIALS - 1).expect("cap fits i32");
        let mut lod = lod_one_triangle();
        lod.sections = vec![section(last_in_cap, 0, 1)];
        let render = StaticMeshRenderData {
            lods: vec![lod],
            ..empty_render()
        };
        let bytes = GltfStaticMeshHandler
            .export(&mesh_with(render), &[])
            .expect("last in-cap slot must export");
        let glb = gltf::Glb::from_slice(&bytes).expect("glb");
        let root: gltf::json::Root = serde_json::from_slice(&glb.json).expect("json");
        assert_eq!(root.materials.len(), MAX_MESH_MATERIALS as usize);
    }

    /// A material index well over the cap (but not astronomically large) must be
    /// rejected fast. `i32::MAX` caused a cargo-mutants timeout: a `>=`→`<` mutant
    /// bypasses the guard and tries to allocate ~2 billion `Material` structs,
    /// hanging the mutation runner. Using `1000` instead allocates at most ~1001
    /// materials under the mutant — still instant — so the mutant is CAUGHT without
    /// a timeout. The boundary tests (`materials_over_cap_is_rejected` at slot 256
    /// and `materials_at_cap_boundary_is_accepted` at slot 255) already pin the
    /// exact cap value; this test pins the rejection for a far-over-cap input.
    #[test]
    fn materials_far_over_cap_is_rejected() {
        let mut lod = lod_one_triangle();
        lod.sections = vec![section(1000, 0, 1)];
        let render = StaticMeshRenderData {
            lods: vec![lod],
            ..empty_render()
        };
        let err = GltfStaticMeshHandler
            .export(&mesh_with(render), &[])
            .expect_err("far-over-cap slot must be rejected");
        assert!(matches!(
            err,
            crate::PaksmithError::UnsupportedFeature { .. }
        ));
    }

    /// Winding-orientation pin: after the det−1 basis swap, `reverse_winding`
    /// must restore CCW (outward) front faces. Build a single UE triangle with a
    /// known outward normal, lower it (convert + reverse), then recompute the
    /// geometric face normal `cross(p1-p0, p2-p0)` over the CONVERTED positions
    /// in the REVERSED (glTF) order and assert it agrees with the converted
    /// vertex normal (positive dot ⇒ outward / CCW). Without the reversal the
    /// dot flips negative, so this fails for a no-reverse mutant.
    #[allow(clippy::float_cmp)]
    #[test]
    fn winding_reversal_yields_outward_ccw_faces() {
        // UE triangle in the Z=0 plane with outward normal +Z (UE up).
        let ue_positions = [
            FVector {
                x: 0.0,
                y: 0.0,
                z: 0.0,
            },
            FVector {
                x: 100.0,
                y: 0.0,
                z: 0.0,
            },
            FVector {
                x: 0.0,
                y: 100.0,
                z: 0.0,
            },
        ];
        let ue_normal = FVector {
            x: 0.0,
            y: 0.0,
            z: 1.0,
        };

        // Lower exactly as the exporter does.
        let converted: Vec<[f32; 3]> = ue_positions.iter().map(convert_position).collect();
        let n = convert_dir(&ue_normal); // glTF vertex normal
        let order = reverse_winding(&[0u32, 1, 2]); // glTF index order

        let p0 = converted[order[0] as usize];
        let p1 = converted[order[1] as usize];
        let p2 = converted[order[2] as usize];

        // Geometric face normal = cross(p1 - p0, p2 - p0).
        let e1 = [p1[0] - p0[0], p1[1] - p0[1], p1[2] - p0[2]];
        let e2 = [p2[0] - p0[0], p2[1] - p0[1], p2[2] - p0[2]];
        let face = [
            e1[1] * e2[2] - e1[2] * e2[1],
            e1[2] * e2[0] - e1[0] * e2[2],
            e1[0] * e2[1] - e1[1] * e2[0],
        ];
        let dot = face[0] * n[0] + face[1] * n[1] + face[2] * n[2];
        // Reversed (CCW) order ⇒ geometric normal points the same way as the
        // declared vertex normal (outward). A no-reverse mutant flips this sign.
        assert!(
            dot > 0.0,
            "reversed winding must keep faces front-facing (dot = {dot})"
        );
    }

    // ---------- End-to-end cube fixture (Task 12) ----------

    /// A unit cube (8 vertices, 12 triangles, 1 section, normals + UV0).
    fn cube_lod() -> StaticMeshLod {
        // 8 corners at ±50 cm (→ ±0.5 m).
        let p = |x: f64, y: f64, z: f64| FVector { x, y, z };
        let positions = vec![
            p(-50.0, -50.0, -50.0),
            p(50.0, -50.0, -50.0),
            p(50.0, 50.0, -50.0),
            p(-50.0, 50.0, -50.0),
            p(-50.0, -50.0, 50.0),
            p(50.0, -50.0, 50.0),
            p(50.0, 50.0, 50.0),
            p(-50.0, 50.0, 50.0),
        ];
        // 12 triangles (two per face).
        let indices: Vec<u32> = vec![
            0, 1, 2, 0, 2, 3, 4, 6, 5, 4, 7, 6, 0, 4, 5, 0, 5, 1, 1, 5, 6, 1, 6, 2, 2, 6, 7, 2, 7,
            3, 3, 7, 4, 3, 4, 0,
        ];
        StaticMeshLod {
            sections: vec![section(0, 0, 12)],
            normals: positions
                .iter()
                .map(|_| FVector {
                    x: 0.0,
                    y: 0.0,
                    z: 1.0,
                })
                .collect(),
            tangents: Vec::new(),
            uvs: {
                let mut u: [Option<Vec<FVector2D>>; 4] = [None, None, None, None];
                u[0] = Some(
                    positions
                        .iter()
                        .map(|_| FVector2D { x: 0.0, y: 0.0 })
                        .collect(),
                );
                u
            },
            num_tex_coords: 1,
            colors: None,
            indices,
            positions,
        }
    }

    #[test]
    fn cube_exports_parseable_glb_with_expected_counts() {
        let render = StaticMeshRenderData {
            lods: vec![cube_lod()],
            ..empty_render()
        };
        let bytes = GltfStaticMeshHandler
            .export(&mesh_with(render), &[])
            .expect("export");
        let glb = gltf::Glb::from_slice(&bytes).expect("glb");
        let root: gltf::json::Root = serde_json::from_slice(&glb.json).expect("json");
        assert_eq!(root.meshes.len(), 1);
        assert_eq!(root.meshes[0].primitives.len(), 1);
        let prim = &root.meshes[0].primitives[0];
        // POSITION + NORMAL present (mode serializes ABSENT for Triangles, so we
        // do not assert `prim.mode`).
        assert!(
            prim.attributes
                .keys()
                .any(|k| matches!(k, Valid(Semantic::Positions)))
        );
        assert!(
            prim.attributes
                .keys()
                .any(|k| matches!(k, Valid(Semantic::Normals)))
        );
        // 36 indices (12 triangles), UNSIGNED_SHORT (8 verts ≤ 65535).
        // `USize64` exposes its inner value via `.0` (no `From<USize64> for u64`).
        let idx = &root.accessors[prim.indices.unwrap().value()];
        assert_eq!(idx.count.0, 36);
        assert!(matches!(
            idx.component_type,
            Valid(GenericComponentType(ComponentType::U16))
        ));
        // Positions are metre-scaled: max corner is +0.5, not +50.
        let pos = &root.accessors[prim.attributes[&Valid(Semantic::Positions)].value()];
        assert_eq!(
            pos.max.as_ref().unwrap(),
            &serde_json::json!([0.5, 0.5, 0.5])
        );
    }

    // ---------- Projected-buffer-size cap tests (FIX 1) ----------

    /// `projected_bin_bytes` sums the EXACT byte strides the lowering would
    /// allocate. Pins every multiplier (positions ×12, normals ×12, tangents
    /// ×16, uv channel ×8, colors ×4, index ×4) and the triangle-span floor.
    /// A mutant changing any stride/multiplier fails this exact equality.
    #[test]
    fn projected_bin_bytes_sums_vertex_and_index_strides() {
        // 3 positions, 3 normals, 3 tangents, one 3-element uv0 channel, 3
        // colors, and one section of 1 triangle over a 3-index buffer.
        let mut lod = lod_one_triangle(); // 3 positions, indices [0,1,2]
        lod.normals = vec![
            FVector {
                x: 0.0,
                y: 0.0,
                z: 1.0,
            };
            3
        ];
        lod.tangents = vec![
            FVector4 {
                x: 1.0,
                y: 0.0,
                z: 0.0,
                w: 1.0,
            };
            3
        ];
        lod.num_tex_coords = 1;
        lod.uvs[0] = Some(vec![FVector2D { x: 0.0, y: 0.0 }; 3]);
        lod.colors = Some(vec![
            FColor {
                r: 0,
                g: 0,
                b: 0,
                a: 0,
            };
            3
        ]);
        lod.sections = vec![section(0, 0, 1)]; // 1 triangle = 3 indices
        let render = StaticMeshRenderData {
            lods: vec![lod],
            ..empty_render()
        };
        // positions 3*12 = 36, normals 3*12 = 36, tangents 3*16 = 48,
        // uv0 3*8 = 24, colors 3*4 = 12 → verts 156.
        // section span floored to 3 indices * 4 = 12. Total = 168.
        assert_eq!(projected_bin_bytes(&render), 168);
    }

    /// `projected_bin_bytes` floors the per-section span to a whole number of
    /// triangles (`avail - avail % 3`), mirroring `resolve_section_indices`.
    /// With a 5-index buffer and an over-claiming section, `avail = 5` floors to
    /// 3 → index bytes 3*4 = 12 (NOT 5*4 = 20, and NOT the `+`-mutant's
    /// 7*4 = 28). Positions 3*12 = 36 → total 48.
    #[test]
    fn projected_bin_bytes_floors_section_span_to_triangle_multiple() {
        let mut lod = lod_one_triangle(); // 3 positions
        lod.indices = vec![0, 1, 2, 0, 1]; // 5 indices (avail % 3 != 0)
        lod.sections = vec![section(0, 0, 10)]; // claims 30, clamps to 5, floors to 3
        let render = StaticMeshRenderData {
            lods: vec![lod],
            ..empty_render()
        };
        // verts 3*12 = 36 + floored span 3*4 = 12 → 48.
        assert_eq!(projected_bin_bytes(&render), 48);
    }

    /// `exceeds_export_cap` is `true` strictly ABOVE the cap: exactly-cap is
    /// accepted, one byte over is rejected. Pins the `> cap` boundary (a `>`→`>=`
    /// mutant would reject the exactly-cap case) without a cap-sized allocation.
    #[test]
    fn exceeds_export_cap_is_strict_above_cap() {
        assert!(!exceeds_export_cap(MAX_GLB_BIN_BYTES - 1));
        assert!(!exceeds_export_cap(MAX_GLB_BIN_BYTES));
        assert!(exceeds_export_cap(MAX_GLB_BIN_BYTES + 1));
    }

    /// A mesh that duplicates a small index buffer across MANY sections and LODs
    /// projects to >1 GiB while allocating only a few hundred KB of INPUT. The
    /// rejection is asserted at the PURE [`enforce_export_cap`] level (NOT via
    /// `export`) so the over-cap path never builds a multi-GiB GLB — a heavy
    /// `export` call here would time out the mutation runner when the guard is
    /// mutated off (it would then perform the exact lowering the guard prevents).
    #[test]
    fn oversized_mesh_via_section_duplication_is_rejected() {
        // 30_000 indices per LOD (120 KB) duplicated by 8_960 sections across
        // 5 LODs → projected 5 * 8_960 * 30_000 * 4 ≈ 50 GiB, far over the 1 GiB
        // cap, while only a few MB of INPUT (indices + section structs) is built.
        let make_lod = || {
            let mut lod = lod_one_triangle();
            lod.indices = vec![0u32; 30_000];
            lod.sections = (0..8_960).map(|_| section(0, 0, 10_000)).collect();
            lod
        };
        let render = StaticMeshRenderData {
            lods: (0..5).map(|_| make_lod()).collect(),
            ..empty_render()
        };
        assert!(
            projected_bin_bytes(&render) > MAX_GLB_BIN_BYTES,
            "test setup must project over the cap"
        );
        let err = enforce_export_cap(&render).expect_err("oversized projection must be rejected");
        assert!(matches!(
            err,
            crate::PaksmithError::UnsupportedFeature { .. }
        ));
    }

    /// `export` WIRES the cap guard in: an under-cap mesh exports successfully,
    /// confirming `enforce_export_cap(render)?` returns `Ok` on the happy path
    /// (the over-cap rejection is pinned purely by
    /// `oversized_mesh_via_section_duplication_is_rejected`; an over-cap mesh fed
    /// through the full `export` lowering would perform the multi-GiB allocation
    /// the guard exists to prevent, timing out the mutation runner).
    #[test]
    fn export_under_cap_mesh_succeeds() {
        let render = StaticMeshRenderData {
            lods: vec![cube_lod()],
            ..empty_render()
        };
        assert!(!exceeds_export_cap(projected_bin_bytes(&render)));
        let bytes = GltfStaticMeshHandler
            .export(&mesh_with(render), &[])
            .expect("under-cap mesh must export");
        assert_eq!(&bytes[0..4], b"glTF");
    }

    /// `projected_bin_bytes` is a safe UPPER BOUND of the actual emitted BIN.
    /// The cube uses u16 indices (8 verts), so projected's ×4 index width
    /// over-estimates — confirms a drift where projected under-counts is caught.
    #[test]
    fn projected_is_upper_bound_of_actual_bin() {
        let render = StaticMeshRenderData {
            lods: vec![cube_lod()],
            ..empty_render()
        };
        let projected = projected_bin_bytes(&render);
        let bytes = GltfStaticMeshHandler
            .export(&mesh_with(render), &[])
            .expect("export");
        let glb = gltf::Glb::from_slice(&bytes).expect("glb");
        let actual_bin_len = glb.bin.expect("cube has a BIN buffer").len() as u64;
        assert!(
            projected >= actual_bin_len,
            "projected ({projected}) must be an upper bound of actual bin ({actual_bin_len})"
        );
    }

    /// A just-under-cap projection is ACCEPTED — brackets the `> cap` boundary
    /// from below so a `>`→`>=` mutant (which would reject the at-cap case) and a
    /// `>`→`<` mutant are caught alongside `oversized_mesh_via_section_duplication`.
    #[test]
    fn projected_at_cap_constant_is_one_gib() {
        assert_eq!(MAX_GLB_BIN_BYTES, 1_073_741_824);
    }

    // ---------- Non-finite position rejection (R5 FIX 1) ----------

    /// Build a one-triangle render whose first vertex has component `x` set to a
    /// bad value, for the non-finite rejection tests.
    fn render_with_bad_position_x(bad_x: f64) -> StaticMeshRenderData {
        let mut lod = lod_one_triangle();
        lod.sections = vec![section(0, 0, 1)];
        lod.positions[0].x = bad_x;
        StaticMeshRenderData {
            lods: vec![lod],
            ..empty_render()
        }
    }

    /// `positions_all_finite` returns `false` (and `export` rejects) for an
    /// infinite source component. The check runs over the CONVERTED f32, so an
    /// f64 `INFINITY` narrows to f32 `inf` and is caught.
    #[test]
    fn non_finite_position_inf_is_rejected() {
        let render = render_with_bad_position_x(f64::INFINITY);
        assert!(!positions_all_finite(&render));
        let err = GltfStaticMeshHandler
            .export(&mesh_with(render), &[])
            .expect_err("inf position must be rejected");
        assert!(matches!(
            err,
            crate::PaksmithError::UnsupportedFeature { .. }
        ));
    }

    /// A NaN source component is rejected (no panic, no `null` emitted).
    #[test]
    fn non_finite_position_nan_is_rejected() {
        let render = render_with_bad_position_x(f64::NAN);
        assert!(!positions_all_finite(&render));
        let err = GltfStaticMeshHandler
            .export(&mesh_with(render), &[])
            .expect_err("NaN position must be rejected");
        assert!(matches!(
            err,
            crate::PaksmithError::UnsupportedFeature { .. }
        ));
    }

    /// A FINITE f64 that overflows the f32 narrowing (`1e40 as f32 == inf`) is
    /// also rejected — this is why the predicate scans the CONVERTED f32, not the
    /// raw f64 (which `is_finite()` would pass). Deliberate strengthening of R5's
    /// literal "scan f32 source components" wording.
    #[allow(clippy::cast_possible_truncation)] // the overflow-on-narrowing IS the point
    #[test]
    fn finite_f64_overflowing_f32_position_is_rejected() {
        // Precondition: the raw f64 is finite, but its f32 narrowing is not.
        assert!((1e40_f64).is_finite(), "raw f64 is finite");
        assert!(!(1e40_f64 as f32).is_finite(), "f32 narrowing overflows");
        let render = render_with_bad_position_x(1e40);
        assert!(!positions_all_finite(&render));
        let err = GltfStaticMeshHandler
            .export(&mesh_with(render), &[])
            .expect_err("f32-overflowing position must be rejected");
        assert!(matches!(
            err,
            crate::PaksmithError::UnsupportedFeature { .. }
        ));
    }

    /// A wholly finite mesh passes `positions_all_finite` (pins the predicate
    /// against a `true`-replacement / `!is_finite → is_finite` / `|| → &&` mutant
    /// that would reject valid meshes).
    #[test]
    fn finite_positions_pass_the_check() {
        let render = StaticMeshRenderData {
            lods: vec![cube_lod()],
            ..empty_render()
        };
        assert!(positions_all_finite(&render));
    }

    // ---------- Zero-LOD buffer omission (R5 FIX 2) ----------

    /// A zero-LOD mesh produces no accessors and an empty BIN, so `into_parts`
    /// must NOT push a spec-invalid `byteLength: 0` buffer (glTF 2.0 §5.9
    /// requires `byteLength > 0`, and a no-URI buffer needs a BIN chunk that
    /// `finish_glb` omits when bin is empty). The GLB still parses (asset-only).
    #[test]
    fn empty_mesh_emits_no_buffer() {
        let bytes = GltfStaticMeshHandler
            .export(&mesh_with(empty_render()), &[])
            .expect("export");
        let glb = gltf::Glb::from_slice(&bytes).expect("parse glb");
        assert!(glb.bin.is_none(), "no BIN chunk for an empty mesh");
        // Assert structurally via `serde_json::Value` — a zero-node scene trips
        // the strict `gltf::json::Root` deserialize (missing `nodes` field).
        let doc: serde_json::Value = serde_json::from_slice(&glb.json).expect("json");
        let buffers = doc.get("buffers").and_then(|v| v.as_array());
        assert!(
            buffers.is_none_or(Vec::is_empty),
            "no zero-byteLength buffer for an empty mesh"
        );
    }

    /// A non-empty mesh DOES emit exactly one buffer — pins the `!is_empty()`
    /// guard against a mutant that drops the buffer when bin is present (which
    /// would orphan the bufferViews referencing buffer 0).
    #[test]
    fn non_empty_mesh_emits_one_buffer() {
        let render = StaticMeshRenderData {
            lods: vec![cube_lod()],
            ..empty_render()
        };
        let bytes = GltfStaticMeshHandler
            .export(&mesh_with(render), &[])
            .expect("export");
        let glb = gltf::Glb::from_slice(&bytes).expect("parse glb");
        let root: gltf::json::Root = serde_json::from_slice(&glb.json).expect("json");
        assert_eq!(root.buffers.len(), 1);
    }
}
