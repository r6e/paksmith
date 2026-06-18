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
//! **Stability:** `__test_utils` only — not a downstream API.

use crate::asset::bulk_data::decompress_zlib;
use crate::asset::exports::mesh::section::MeshSection;
use crate::asset::exports::texture::pixel_format::{PixelFormat, decode_mip};
use crate::asset::property::primitives::{Property, PropertyValue};
use crate::asset::structs::bounds::FBoxSphereBounds;
use crate::asset::structs::color::FColor;
use crate::asset::structs::vector::{FVector, FVector2D, FVector4};
use crate::asset::{
    Asset, DataTableData, DataTableRow, StaticMeshData, StaticMeshLod, StaticMeshRenderData,
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
#[must_use]
pub fn large_static_mesh(num_vertices: u32) -> Asset {
    let n = num_vertices - (num_vertices % 3);
    let inv = 1.0 / 3.0_f64.sqrt();
    let mut positions = Vec::with_capacity(n as usize);
    let mut normals = Vec::with_capacity(n as usize);
    let mut tangents = Vec::with_capacity(n as usize);
    let mut uv0 = Vec::with_capacity(n as usize);
    let mut colors = Vec::with_capacity(n as usize);
    for i in 0..n {
        let f = f64::from(i);
        positions.push(FVector {
            x: f * 0.1,
            y: (f * 0.017).sin() * 50.0,
            z: (f * 0.013).cos() * 50.0,
        });
        normals.push(FVector {
            x: inv,
            y: inv,
            z: inv,
        });
        tangents.push(FVector4 {
            x: 1.0,
            y: 0.0,
            z: 0.0,
            w: 1.0,
        });
        uv0.push(FVector2D {
            x: f64::from(i % 2),
            y: f64::from((i / 2) % 2),
        });
        #[allow(clippy::cast_possible_truncation)]
        colors.push(FColor {
            r: (i % 256) as u8,
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
                x: f64::from(n) * 0.1,
                y: 50.0,
                z: 50.0,
            },
            sphere_radius: f64::from(n) * 0.1,
        },
        lods_share_static_lighting: false,
        screen_sizes: Vec::new(),
    };
    let mut data = StaticMeshData::empty();
    data.cooked = true;
    data.render_data = Some(render);
    Asset::StaticMesh(data)
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
                #[allow(clippy::cast_precision_loss)]
                value: PropertyValue::Float((r * cols + c) as f32),
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
