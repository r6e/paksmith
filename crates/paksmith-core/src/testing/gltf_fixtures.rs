//! Exportable mesh fixtures for the glTF-validator integration (issue #564).
//!
//! `__test_utils`-gated public builders so the `emit_gltf_validation_fixtures`
//! example (run from a CI shell) and integration tests can construct an
//! exportable cube static mesh and a 5-bone skinned mesh from OUTSIDE the
//! `#[cfg(test)]` fixture modules in `export/`. The handlers lower these into
//! `.glb` bytes that the Khronos `gltf_validator` then checks for spec errors.
//!
//! These mirror the in-crate `#[cfg(test)]` fixtures (`lod_one_triangle`,
//! `skinned_triangle_data`) but are deliberately separate: moving those to
//! `__test_utils` would break the default `cargo test` build (their consumers run
//! without the feature).

use crate::asset::exports::mesh::section::MeshSection;
use crate::asset::structs::bounds::FBoxSphereBounds;
use crate::asset::structs::quat::FQuat;
use crate::asset::structs::transform::FTransform;
use crate::asset::structs::vector::FVector;
use crate::asset::{
    Asset, BoneInfo, BoneWeights, ReferenceSkeleton, SkelMeshSection, SkeletalMeshData,
    SkeletalMeshLod, StaticMeshData, StaticMeshLod, StaticMeshRenderData,
};

/// A unit cube static mesh (8 corner vertices at ±50 cm, 12 triangles in one
/// section) ready for `GltfStaticMeshHandler::export`. Carries the full vertex
/// attribute set — POSITION + NORMAL + TANGENT (VEC4 w-handedness) + TEXCOORD_0 +
/// COLOR_0 — so the CI `gltf_validator` exercises every static-mesh accessor type
/// (not just POSITION + indices). See `static_mesh_index_boundary` for the U32
/// index-width path.
#[must_use]
pub fn cube_static_mesh() -> Asset {
    let c = 50.0_f64;
    let corner = |x: f64, y: f64, z: f64| FVector { x, y, z };
    // 0-3 = bottom (z=-c), 4-7 = top (z=+c).
    let positions = vec![
        corner(-c, -c, -c),
        corner(c, -c, -c),
        corner(c, c, -c),
        corner(-c, c, -c),
        corner(-c, -c, c),
        corner(c, -c, c),
        corner(c, c, c),
        corner(-c, c, c),
    ];
    // 12 triangles (36 indices) over the 6 faces; all indices < 8.
    let indices = vec![
        0, 2, 1, 0, 3, 2, // bottom
        4, 5, 6, 4, 6, 7, // top
        0, 1, 5, 0, 5, 4, // front
        2, 3, 7, 2, 7, 6, // back
        0, 4, 7, 0, 7, 3, // left
        1, 2, 6, 1, 6, 5, // right
    ];
    let section = MeshSection {
        material_index: 0,
        first_index: 0,
        num_triangles: 12,
        min_vertex_index: 0,
        max_vertex_index: 7,
        enable_collision: false,
        cast_shadow: false,
        force_opaque: false,
        visible_in_ray_tracing: false,
        affect_distance_field_lighting: false,
    };
    // Per-corner attributes. Normals point outward from the centre (unit length →
    // no `ACCESSOR_VECTOR3_NON_UNIT` warning); tangents are a unit +X with `w = 1`
    // handedness; UVs map the corner's X/Y sign to the unit square; colors vary.
    let inv = 1.0 / 3.0_f64.sqrt();
    let normals: Vec<FVector> = positions
        .iter()
        .map(|p| FVector {
            x: p.x.signum() * inv,
            y: p.y.signum() * inv,
            z: p.z.signum() * inv,
        })
        .collect();
    let tangents: Vec<crate::asset::structs::vector::FVector4> = positions
        .iter()
        .map(|_| crate::asset::structs::vector::FVector4 {
            x: 1.0,
            y: 0.0,
            z: 0.0,
            w: 1.0,
        })
        .collect();
    let uv0: Vec<crate::asset::structs::vector::FVector2D> = positions
        .iter()
        .map(|p| crate::asset::structs::vector::FVector2D {
            x: f64::from(u8::from(p.x > 0.0)),
            y: f64::from(u8::from(p.y > 0.0)),
        })
        .collect();
    let colors: Vec<crate::asset::structs::color::FColor> = positions
        .iter()
        .enumerate()
        .map(|(i, _)| crate::asset::structs::color::FColor {
            #[allow(clippy::cast_possible_truncation)]
            r: (i * 32) as u8,
            g: 128,
            b: 0,
            a: 255,
        })
        .collect();
    let lod = StaticMeshLod {
        sections: vec![section],
        positions,
        normals,
        tangents,
        uvs: [Some(uv0), None, None, None],
        num_tex_coords: 1,
        colors: Some(colors),
        indices,
    };
    let zero = FVector {
        x: 0.0,
        y: 0.0,
        z: 0.0,
    };
    let render = StaticMeshRenderData {
        lods: vec![lod],
        bounds: FBoxSphereBounds {
            origin: zero,
            box_extent: FVector { x: c, y: c, z: c },
            sphere_radius: c * 3.0_f64.sqrt(), // half-diagonal of the cube
        },
        lods_share_static_lighting: false,
        screen_sizes: Vec::new(),
    };
    let mut data = StaticMeshData::empty();
    data.cooked = true;
    data.render_data = Some(render);
    Asset::StaticMesh(data)
}

/// A static mesh whose highest referenced vertex index is exactly 65 535
/// (`0xFFFF`): 65 536 vertices on a line, one section, one triangle
/// `(0, 1, 65535)`. Lowering MUST promote the index accessor to `UNSIGNED_INT` —
/// glTF 2.0 forbids the reserved primitive-restart value `0xFFFF` in a
/// `UNSIGNED_SHORT` index buffer (validator `ACCESSOR_INDEX_PRIMITIVE_RESTART`).
/// This is the end-to-end regression for the Phase 3 audit B1 index-width bug:
/// the previous `≤ 0xFFFF` gate emitted a U16 buffer containing `0xFFFF` here.
#[must_use]
pub fn static_mesh_index_boundary() -> Asset {
    const N: u32 = 65_536; // vertices 0..=65_535
    let positions: Vec<FVector> = (0..N)
        .map(|i| FVector {
            x: f64::from(i) * 0.01,
            y: 0.0,
            z: 0.0,
        })
        .collect();
    let indices = vec![0, 1, N - 1]; // references the boundary vertex 65 535
    let section = MeshSection {
        material_index: 0,
        first_index: 0,
        num_triangles: 1,
        min_vertex_index: 0,
        max_vertex_index: 65_535, // N - 1, as i32
        enable_collision: false,
        cast_shadow: false,
        force_opaque: false,
        visible_in_ray_tracing: false,
        affect_distance_field_lighting: false,
    };
    let lod = StaticMeshLod {
        sections: vec![section],
        positions,
        normals: Vec::new(),
        tangents: Vec::new(),
        uvs: [None, None, None, None],
        num_tex_coords: 0,
        colors: None,
        indices,
    };
    let zero = FVector {
        x: 0.0,
        y: 0.0,
        z: 0.0,
    };
    let render = StaticMeshRenderData {
        lods: vec![lod],
        bounds: FBoxSphereBounds {
            origin: zero,
            box_extent: FVector {
                x: f64::from(N) * 0.01,
                y: 1.0,
                z: 1.0,
            },
            sphere_radius: f64::from(N) * 0.01,
        },
        lods_share_static_lighting: false,
        screen_sizes: Vec::new(),
    };
    let mut data = StaticMeshData::empty();
    data.cooked = true;
    data.render_data = Some(render);
    Asset::StaticMesh(data)
}

/// A 5-bone skinned mesh (root + 4 children) with one LOD: a single skinned
/// triangle (3 verts), each vertex 100 %-weighted to its section-local bone 0
/// (→ global bone 1 via the bone_map `[1, 2, 3]`). Ready for
/// `GltfSkeletalMeshHandler::export`. Mirrors the in-crate `skinned_triangle_data`
/// fixture but uses pure-translation bind-pose transforms (identity rotation, unit
/// scale) so the inverse-bind matrices are trivially invertible and finite.
#[must_use]
pub fn five_bone_skinned_mesh() -> Asset {
    let bone = |name: &str, parent: i32| BoneInfo {
        name: name.to_string(),
        parent_index: parent,
    };
    // Pure-translation bind pose: identity rotation, unit scale → invertible IBM.
    let bind = |i: f64| FTransform {
        rotation: FQuat {
            x: 0.0,
            y: 0.0,
            z: 0.0,
            w: 1.0,
        },
        translation: FVector {
            x: i,
            y: i * 2.0,
            z: i * 3.0,
        },
        scale_3d: FVector {
            x: 1.0,
            y: 1.0,
            z: 1.0,
        },
    };
    let skeleton = ReferenceSkeleton {
        bones: vec![
            bone("root", -1),
            bone("b1", 0),
            bone("b2", 0),
            bone("b3", 1),
            bone("b4", 1),
        ],
        bind_pose: (1..=5).map(|i| bind(f64::from(i))).collect(),
    };
    // Only the non-default fields are set explicitly; material_index / base_index /
    // base_vertex_index are 0 (the `SkelMeshSection::default()` value) for this
    // single-section, index-0 triangle, so they come from `..default()` rather than
    // a redundant literal (a redundant `field: 0` is an equivalent mutation target).
    let section = SkelMeshSection {
        num_triangles: 1,
        num_vertices: 3,
        bone_map: vec![1, 2, 3],
        ..SkelMeshSection::default()
    };
    let lod = SkeletalMeshLod {
        sections: vec![section],
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
        indices: vec![0, 1, 2],
        bone_indices: vec![[0u16; 8]; 3],
        bone_weights: BoneWeights::U8(vec![[255, 0, 0, 0, 0, 0, 0, 0]; 3]),
        ..SkeletalMeshLod::default()
    };
    let mut data = SkeletalMeshData::empty();
    data.cooked = true;
    data.skeleton = skeleton;
    data.lods = vec![lod];
    Asset::SkeletalMesh(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::export::{FormatHandler, GltfSkeletalMeshHandler, GltfStaticMeshHandler};

    /// The cube fixture lowers through the real static handler to a GLB whose
    /// single mesh primitive carries the FULL attribute set: POSITION + NORMAL +
    /// TANGENT + TEXCOORD_0 + COLOR_0 + indices over the 8 vertices. (The Khronos
    /// `gltf_validator` checks the actual accessor data in the `gltf-validation`
    /// CI job; this pins the in-process export path + attribute presence.)
    #[test]
    fn cube_exports_to_valid_glb() {
        let bytes = GltfStaticMeshHandler
            .export(&cube_static_mesh(), &[])
            .expect("cube export");
        assert_eq!(&bytes[0..4], b"glTF");
        let glb = gltf::Glb::from_slice(&bytes).expect("parse glb");
        let doc: serde_json::Value = serde_json::from_slice(&glb.json).expect("parse json");
        let prim = &doc["meshes"][0]["primitives"][0];
        let attrs = prim["attributes"].as_object().expect("attributes");
        for key in ["POSITION", "NORMAL", "TANGENT", "TEXCOORD_0", "COLOR_0"] {
            assert!(attrs.contains_key(key), "cube primitive has {key}");
        }
        assert!(prim.get("indices").is_some(), "cube primitive is indexed");
    }

    /// The boundary fixture lowers to a GLB whose index accessor is `UNSIGNED_INT`
    /// (component type 5125): a max index value of 65 535 (`0xFFFF`) must NOT be
    /// emitted as `UNSIGNED_SHORT` (it is the reserved primitive-restart value).
    /// End-to-end regression for the Phase 3 audit B1 bug.
    #[test]
    fn index_boundary_exports_with_u32_indices() {
        let bytes = GltfStaticMeshHandler
            .export(&static_mesh_index_boundary(), &[])
            .expect("boundary export");
        let glb = gltf::Glb::from_slice(&bytes).expect("parse glb");
        let doc: serde_json::Value = serde_json::from_slice(&glb.json).expect("parse json");
        let idx_acc = doc["meshes"][0]["primitives"][0]["indices"]
            .as_u64()
            .expect("index accessor ref");
        let idx_acc = usize::try_from(idx_acc).expect("accessor index fits usize");
        let component_type = doc["accessors"][idx_acc]["componentType"]
            .as_u64()
            .expect("componentType");
        assert_eq!(
            component_type, 5125,
            "0xFFFF max index → UNSIGNED_INT (5125)"
        );
    }

    /// The 5-bone skinned fixture lowers to a GLB with a 5-joint skin and a
    /// primitive carrying POSITION + JOINTS_0 + WEIGHTS_0.
    #[test]
    fn five_bone_mesh_exports_to_skinned_glb() {
        let bytes = GltfSkeletalMeshHandler
            .export(&five_bone_skinned_mesh(), &[])
            .expect("skeletal export");
        assert_eq!(&bytes[0..4], b"glTF");
        let glb = gltf::Glb::from_slice(&bytes).expect("parse glb");
        let doc: serde_json::Value = serde_json::from_slice(&glb.json).expect("parse json");
        let joints = doc["skins"][0]["joints"].as_array().expect("joints");
        assert_eq!(joints.len(), 5, "5-bone skeleton → 5 skin joints");
        let attrs = doc["meshes"][0]["primitives"][0]["attributes"]
            .as_object()
            .expect("attributes");
        for key in ["POSITION", "JOINTS_0", "WEIGHTS_0"] {
            assert!(attrs.contains_key(key), "skinned primitive has {key}");
        }
    }

    /// Pin the cube builder's literal field values that the export-shape tests
    /// above don't read (the geometry data is verified by the CI `gltf_validator`
    /// run, not here). Kills arithmetic / value mutations in the builder.
    #[test]
    fn cube_fixture_values_pinned() {
        let Asset::StaticMesh(d) = cube_static_mesh() else {
            panic!("expected StaticMesh");
        };
        let render = d.render_data.expect("render data");
        // `sphere_radius = c * sqrt(3)` ≈ 86.6 — pins the `*` (a `+` mutant gives
        // ≈51.7, a `/` mutant ≈28.9, both far outside this tolerance).
        assert!((render.bounds.sphere_radius - 50.0_f64 * 3.0_f64.sqrt()).abs() < 1e-9);
        let lod = &render.lods[0];
        assert_eq!(lod.positions.len(), 8, "cube has 8 corners");
        assert_eq!(lod.indices.len(), 36, "12 triangles → 36 indices");
        assert!(
            lod.indices.iter().all(|&i| i < 8),
            "every index references a real corner"
        );
        // Full attribute set, one value per corner.
        assert_eq!(lod.normals.len(), 8, "one normal per corner");
        assert_eq!(lod.tangents.len(), 8, "one tangent per corner");
        assert_eq!(lod.num_tex_coords, 1, "one UV channel");
        assert_eq!(
            lod.uvs[0].as_ref().map(Vec::len),
            Some(8),
            "UV channel 0 has one coord per corner"
        );
        assert_eq!(
            lod.colors.as_ref().map(Vec::len),
            Some(8),
            "one color per corner"
        );
        // Corner normals are unit length (outward diagonal).
        let n0 = &lod.normals[0];
        assert!(
            (n0.x * n0.x + n0.y * n0.y + n0.z * n0.z - 1.0).abs() < 1e-9,
            "corner normal is unit length"
        );
        let sec = &lod.sections[0];
        assert_eq!(sec.first_index, 0);
        assert_eq!(sec.num_triangles, 12);
    }

    /// Pin the skinned builder's literal field values (bind-pose translations, the
    /// section counts + bone_map) that the export-shape test doesn't read.
    #[test]
    fn five_bone_fixture_values_pinned() {
        let Asset::SkeletalMesh(d) = five_bone_skinned_mesh() else {
            panic!("expected SkeletalMesh");
        };
        assert_eq!(d.skeleton.bones.len(), 5);
        assert_eq!(d.skeleton.bind_pose.len(), 5, "one bind transform per bone");
        // bind_pose[0] = bind(1.0): translation (1, 1*2, 1*3) = (1, 2, 3). i=1 makes
        // `i*2` ≠ `i+2` and `i*3` ≠ `i+3`/`i/3`, so this kills the `*` mutants.
        let t = &d.skeleton.bind_pose[0].translation;
        assert_eq!((t.x, t.y, t.z), (1.0, 2.0, 3.0));
        let sec = &d.lods[0].sections[0];
        assert_eq!(sec.num_triangles, 1);
        assert_eq!(sec.num_vertices, 3);
        assert_eq!(
            sec.bone_map,
            vec![1, 2, 3],
            "section-local → global bone map"
        );
    }
}
