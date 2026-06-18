//! `__test_utils`-gated accessors and builders for the `paksmith-bench`
//! Phase 3 benchmark suite.
//!
//! The bench crate is external, so it cannot reach the crate-internal hot
//! functions (`decode_mip`, `decompress_zlib`) or struct-literal the
//! `#[non_exhaustive]` asset types. These thin wrappers expose the hot paths
//! through public types (strings + byte vecs) and synthesize realistic large
//! inputs. Same pattern/precedent as [`crate::export::max_audio_decoded_bytes`]
//! and [`super::gltf_fixtures`].
//!
//! The builders use deliberately MINIMAL per-vertex/per-cell arithmetic
//! (`f64::from(i)` + constants, not formulas): the benches measure throughput,
//! not values, so the emitted attribute values are arbitrary filler — keeping
//! the arithmetic minimal keeps the builders simple and their contract
//! (structural: counts, in-range indices, non-degenerate) pinnable by the tests
//! below. The few structural expressions that do matter (`n - n % 3`, `n / 3`,
//! `n - 1`) are asserted there.
//!
//! **Stability:** `__test_utils` only — not a downstream API.

use crate::asset::bulk_data::decompress_zlib;
use crate::asset::exports::mesh::section::MeshSection;
use crate::asset::exports::texture::pixel_format::{PixelFormat, decode_mip};
use crate::asset::property::primitives::{Property, PropertyValue};
use crate::asset::structs::bounds::FBoxSphereBounds;
use crate::asset::structs::color::FColor;
use crate::asset::structs::quat::FQuat;
use crate::asset::structs::transform::FTransform;
use crate::asset::structs::vector::{FVector, FVector2D, FVector4};
use crate::asset::{
    Asset, BoneInfo, BoneWeights, DataTableData, DataTableRow, ReferenceSkeleton, SkelMeshSection,
    SkeletalMeshData, SkeletalMeshLod, StaticMeshData, StaticMeshLod, StaticMeshRenderData,
};

/// A unit normal + a unit +X tangent, constant across every vertex (the
/// per-vertex conversion work is value-independent).
const UNIT_NORMAL: FVector = FVector {
    x: 1.0,
    y: 0.0,
    z: 0.0,
};
const UNIT_TANGENT: FVector4 = FVector4 {
    x: 1.0,
    y: 0.0,
    z: 0.0,
    w: 1.0,
};

/// Decode one texture mip to RGBA8 and return the pixel bytes. Resolves
/// `format_name` (`"PF_BC7"`, `"PF_DXT1"`, …) via `PixelFormat::from_name`,
/// then runs the crate-internal `decode_mip`. `encoded` must be the correctly
/// sized block buffer for `width`×`height` in that format (the caller sizes it).
/// Isolates the per-block decode hot path from the surrounding parse + PNG encode.
///
/// # Errors
/// Propagates `decode_mip` errors (unsupported format, short encoded buffer).
pub fn decode_texture_mip(
    format_name: &str,
    encoded: &[u8],
    width: u32,
    height: u32,
) -> crate::Result<Vec<u8>> {
    let format = PixelFormat::from_name(format_name);
    Ok(decode_mip(&format, encoded, width, height, false, "bench")?.rgba)
}

/// Decompress a zlib-compressed bulk payload to `expected_size` bytes. Isolates
/// the decompression hot path (the highest-volume byte path in the resolver).
///
/// # Errors
/// Propagates `decompress_zlib` errors (size mismatch, corrupt stream).
pub fn zlib_decompress(compressed: &[u8], expected_size: i64) -> crate::Result<Vec<u8>> {
    decompress_zlib(compressed, expected_size, "bench")
}

/// Build a cooked `UStaticMesh` with one LOD of `num_vertices` vertices carrying
/// the full attribute set (positions + normals + tangents + UV0 + colors) and a
/// triangle-soup index buffer (`num_vertices / 3` triangles). Drives
/// `GltfStaticMeshHandler::export`'s per-vertex lowering hot path.
///
/// `num_vertices` is rounded down to a multiple of 3 so every index references a
/// valid vertex.
///
/// # Panics
/// Panics if `num_vertices < 3` (a mesh needs at least one triangle; the bench
/// callers pass hundreds of thousands).
#[must_use]
pub fn large_static_mesh(num_vertices: u32) -> Asset {
    assert!(num_vertices >= 3, "large_static_mesh needs >= 3 vertices");
    let n = num_vertices - (num_vertices % 3);
    let mut positions = Vec::with_capacity(n as usize);
    let mut normals = Vec::with_capacity(n as usize);
    let mut tangents = Vec::with_capacity(n as usize);
    let mut uv0 = Vec::with_capacity(n as usize);
    let mut colors = Vec::with_capacity(n as usize);
    for i in 0..n {
        // Distinct, non-degenerate positions along +X; the per-vertex conversion
        // cost is identical regardless of the coordinate values.
        positions.push(FVector {
            x: f64::from(i),
            y: 1.0,
            z: 2.0,
        });
        normals.push(UNIT_NORMAL);
        tangents.push(UNIT_TANGENT);
        uv0.push(FVector2D { x: 0.0, y: 0.0 });
        #[allow(clippy::cast_possible_truncation)] // arbitrary filler color
        colors.push(FColor {
            r: i as u8,
            g: 128,
            b: 0,
            a: 255,
        });
    }
    let indices: Vec<u32> = (0..n).collect(); // triangle soup, every index < n
    let section = MeshSection {
        material_index: 0,
        first_index: 0,
        #[allow(clippy::cast_possible_wrap)]
        num_triangles: (n / 3) as i32,
        min_vertex_index: 0,
        #[allow(clippy::cast_possible_wrap)]
        max_vertex_index: (n - 1) as i32,
        enable_collision: false,
        cast_shadow: false,
        force_opaque: false,
        visible_in_ray_tracing: false,
        affect_distance_field_lighting: false,
    };
    let mut lod = StaticMeshLod::with_sections(vec![section]);
    lod.positions = positions;
    lod.normals = normals;
    lod.tangents = tangents;
    lod.uvs = [Some(uv0), None, None, None];
    lod.num_tex_coords = 1;
    lod.colors = Some(colors);
    lod.indices = indices;
    let render = StaticMeshRenderData {
        lods: vec![lod],
        bounds: FBoxSphereBounds {
            origin: FVector {
                x: 0.0,
                y: 0.0,
                z: 0.0,
            },
            box_extent: FVector {
                x: f64::from(n),
                y: 1.0,
                z: 2.0,
            },
            sphere_radius: f64::from(n),
        },
        lods_share_static_lighting: false,
        screen_sizes: Vec::new(),
    };
    let mut data = StaticMeshData::empty();
    data.cooked = true;
    data.render_data = Some(render);
    Asset::StaticMesh(data)
}

/// Build a cooked `USkeletalMesh` with one LOD of `num_vertices` vertices, each
/// with 4 bone influences, skinned to a `num_bones`-bone skeleton (a root plus
/// `num_bones - 1` direct children; one section whose bone map covers every
/// bone). Drives `GltfSkeletalMeshHandler::export`'s per-vertex skin-attribute
/// build: the owning-section lookup + bone-map remap + weight renormalization +
/// JOINTS_0/WEIGHTS_0 packing.
///
/// # Panics
/// Panics if `num_vertices < 3` or `num_bones < 4` (each vertex carries 4
/// influences, so the skeleton needs at least 4 bones).
#[must_use]
pub fn large_skeletal_mesh(num_vertices: u32, num_bones: u16) -> Asset {
    assert!(num_vertices >= 3, "large_skeletal_mesh needs >= 3 vertices");
    assert!(num_bones >= 4, "large_skeletal_mesh needs >= 4 bones");
    let n = num_vertices - (num_vertices % 3);
    // Bone 0 is the root; every other bone is a direct child of the root.
    let bones = (0..num_bones)
        .map(|i| BoneInfo {
            name: format!("bone{i}"),
            parent_index: if i == 0 { -1 } else { 0 },
        })
        .collect();
    let bind_pose = (0..num_bones)
        .map(|i| FTransform {
            rotation: FQuat {
                x: 0.0,
                y: 0.0,
                z: 0.0,
                w: 1.0,
            },
            translation: FVector {
                x: f64::from(i),
                y: 0.0,
                z: 0.0,
            },
            scale_3d: FVector {
                x: 1.0,
                y: 1.0,
                z: 1.0,
            },
        })
        .collect();
    let skeleton = ReferenceSkeleton { bones, bind_pose };
    // Section-local bone map = identity over every bone.
    let bone_map: Vec<u16> = (0..num_bones).collect();
    let mut positions = Vec::with_capacity(n as usize);
    for i in 0..n {
        positions.push(FVector {
            x: f64::from(i),
            y: 1.0,
            z: 2.0,
        });
    }
    // Constant 4 influences (section-local bones 0..=3, valid since num_bones>=4)
    // with weights summing to 255. The per-vertex remap + renormalization runs
    // identically for every vertex.
    let bone_indices = vec![[0u16, 1, 2, 3, 0, 0, 0, 0]; n as usize];
    let weights = vec![[64u8, 64, 64, 63, 0, 0, 0, 0]; n as usize];
    let indices: Vec<u32> = (0..n).collect();
    #[allow(clippy::cast_possible_wrap)]
    let section = SkelMeshSection {
        num_triangles: (n / 3) as i32,
        num_vertices: n as i32,
        bone_map,
        ..SkelMeshSection::default()
    };
    let lod = SkeletalMeshLod {
        sections: vec![section],
        positions,
        indices,
        bone_indices,
        bone_weights: BoneWeights::U8(weights),
        ..SkeletalMeshLod::default()
    };
    let mut data = SkeletalMeshData::empty();
    data.cooked = true;
    data.skeleton = skeleton;
    data.lods = vec![lod];
    Asset::SkeletalMesh(data)
}

/// Build a `UDataTable` with `rows` rows each carrying `cols` `Float` columns
/// sharing one schema (`"Col0".."Col{cols-1}"`). Drives the CSV column-union +
/// per-cell lookup hot path (the O(rows × cols²) surface).
#[must_use]
pub fn large_data_table(rows: usize, cols: usize) -> Asset {
    let col_names: Vec<String> = (0..cols).map(|c| format!("Col{c}")).collect();
    let mut table_rows = Vec::with_capacity(rows);
    for r in 0..rows {
        let properties = col_names
            .iter()
            .enumerate()
            .map(|(c, name)| Property {
                name: std::sync::Arc::from(name.as_str()),
                array_index: 0,
                guid: None,
                #[allow(clippy::cast_precision_loss)] // arbitrary filler value
                value: PropertyValue::Float(c as f32),
            })
            .collect();
        table_rows.push(DataTableRow {
            name: format!("Row{r}"),
            properties,
        });
    }
    let mut data = DataTableData::empty();
    data.row_struct = "BenchRow".to_string();
    data.rows = table_rows;
    Asset::DataTable(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn decode_texture_mip_returns_rgba_for_a_bc1_block() {
        // 4×4 = one BC1 block (8 bytes) → 4·4·4 = 64 RGBA bytes. Kills the
        // body-replacement mutants (Ok(vec![]) / Ok(vec![0]) / Ok(vec![1])).
        let out = decode_texture_mip("PF_DXT1", &[0u8; 8], 4, 4).expect("bc1 decode");
        assert_eq!(out.len(), 64, "4x4 RGBA8 = 64 bytes");
    }

    #[test]
    fn zlib_decompress_round_trips() {
        let original: Vec<u8> = (0..200u32).map(|i| (i % 251) as u8).collect();
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&original).expect("zlib write");
        let compressed = enc.finish().expect("zlib finish");
        let expected = i64::try_from(original.len()).expect("len fits i64");
        let out = zlib_decompress(&compressed, expected).expect("decompress");
        assert_eq!(out, original, "decompress recovers the original bytes");
    }

    /// Pin the static builder's structural contract. The `n = num_vertices -
    /// num_vertices % 3`, `n / 3`, and `n - 1` expressions are the only ones that
    /// matter; `301` exercises the `% 3` round-down (→ 300) so the count
    /// assertions kill the `-`/`%`/`/` mutants.
    #[test]
    fn large_static_mesh_structural_contract() {
        let Asset::StaticMesh(d) = large_static_mesh(301) else {
            panic!("expected StaticMesh");
        };
        let lod = &d.render_data.expect("render data").lods[0];
        assert_eq!(lod.positions.len(), 300, "301 rounds down to 300 vertices");
        assert_eq!(lod.indices.len(), 300, "one index per vertex");
        assert_eq!(lod.normals.len(), 300);
        assert_eq!(lod.tangents.len(), 300);
        assert_eq!(lod.colors.as_ref().map(Vec::len), Some(300));
        assert_eq!(lod.uvs[0].as_ref().map(Vec::len), Some(300));
        assert_eq!(lod.num_tex_coords, 1);
        // Every index references a valid vertex (the OOB guard must not drop it).
        assert!(
            lod.indices
                .iter()
                .all(|&i| (i as usize) < lod.positions.len())
        );
        // colors[5].r = 5 (i as u8) pins the color cast.
        assert_eq!(lod.colors.as_ref().expect("colors")[5].r, 5);
        let sec = &lod.sections[0];
        assert_eq!(sec.num_triangles, 100, "300 / 3 = 100 triangles");
        assert_eq!(sec.max_vertex_index, 299, "n - 1");
        assert_eq!(sec.first_index, 0);
    }

    #[test]
    fn large_skeletal_mesh_structural_contract() {
        let Asset::SkeletalMesh(d) = large_skeletal_mesh(301, 8) else {
            panic!("expected SkeletalMesh");
        };
        assert_eq!(d.skeleton.bones.len(), 8, "8 bones");
        assert_eq!(d.skeleton.bind_pose.len(), 8, "one bind transform per bone");
        // Root parents to -1, every other bone to 0.
        assert_eq!(d.skeleton.bones[0].parent_index, -1);
        assert_eq!(d.skeleton.bones[7].parent_index, 0);
        let lod = &d.lods[0];
        assert_eq!(lod.positions.len(), 300, "301 rounds down to 300");
        assert_eq!(lod.indices.len(), 300);
        assert_eq!(lod.bone_indices.len(), 300);
        // Influences reference valid section-local bones.
        assert_eq!(lod.bone_indices[0], [0u16, 1, 2, 3, 0, 0, 0, 0]);
        // Weights are set (not left to the LOD default) and sum to 255 so
        // renormalization runs. Pins the `bone_weights` field assignment.
        match &lod.bone_weights {
            BoneWeights::U8(w) => {
                assert_eq!(w.len(), 300, "one weight set per vertex");
                assert_eq!(w[0], [64u8, 64, 64, 63, 0, 0, 0, 0]);
            }
            other => panic!("expected U8 weights, got {other:?}"),
        }
        let sec = &lod.sections[0];
        assert_eq!(sec.num_triangles, 100, "300 / 3");
        assert_eq!(sec.num_vertices, 300);
        assert_eq!(sec.bone_map, (0..8u16).collect::<Vec<_>>());
    }

    #[test]
    fn large_data_table_structural_contract() {
        let Asset::DataTable(d) = large_data_table(4, 3) else {
            panic!("expected DataTable");
        };
        assert_eq!(d.rows.len(), 4, "4 rows");
        assert_eq!(d.row_struct, "BenchRow");
        for row in &d.rows {
            assert_eq!(row.properties.len(), 3, "3 columns per row");
        }
        assert_eq!(d.rows[0].properties[0].name(), "Col0");
        assert_eq!(d.rows[0].properties[2].name(), "Col2");
        // Cell value is the column index as f32.
        assert!(matches!(
            d.rows[0].properties[2].value,
            PropertyValue::Float(v) if (v - 2.0).abs() < f32::EPSILON
        ));
    }
}
