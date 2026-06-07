//! `UStaticMesh` → glTF 2.0 (`.glb`) export — Phase 3g2.
//!
//! Lowers parsed [`crate::asset::StaticMeshData`] render geometry into a
//! self-contained binary glTF. Design: `docs/plans/phase-3g2-gltf-export.md`.

use std::borrow::Cow;

use gltf::json::Index;
use gltf::json::accessor::{ComponentType, GenericComponentType, Type};
use gltf::json::buffer::Target;
use gltf::json::validation::Checked::Valid;
use gltf::json::validation::USize64;

use crate::asset::structs::vector::{FVector, FVector4};
use crate::asset::{Asset, StaticMeshLod};
use crate::export::{BulkData, FormatHandler};

/// Lowers a cooked `UStaticMesh` into a self-contained glTF 2.0 binary (`.glb`).
/// See `docs/plans/phase-3g2-gltf-export.md`.
#[derive(Debug, Default, Clone, Copy)]
pub struct GltfStaticMeshHandler;

impl FormatHandler for GltfStaticMeshHandler {
    fn output_extension(&self) -> &'static str {
        "glb"
    }

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
        let _ = render;
        let mut root = gltf::json::Root::default();
        let scene = root.push(gltf::json::Scene {
            extensions: Option::default(),
            extras: gltf::json::extras::Void::default(),
            name: None,
            nodes: Vec::new(),
        });
        root.scene = Some(scene);
        finish_glb(&root, Vec::new())
    }
}

/// Accumulates the single glTF BIN buffer + the `json::Root` under construction.
/// Each `push_accessor` 4-byte-aligns the buffer, emits a `buffer::View` and an
/// `accessor::Accessor`, and returns the accessor index for primitive wiring.
// Wired into `export` by later Phase 3g2 tasks (LOD/primitive emission); until
// then it is exercised only by unit tests.
#[allow(dead_code)]
struct GltfDoc {
    root: gltf::json::Root,
    bin: Vec<u8>,
}

#[allow(dead_code)]
impl GltfDoc {
    fn new() -> Self {
        Self {
            root: gltf::json::Root::default(),
            bin: Vec::new(),
        }
    }

    /// Append `data` as a new bufferView + accessor. `min`/`max` are the
    /// glTF-required position bounds (or `None`); `target` distinguishes vertex
    /// (`ArrayBuffer`) from index (`ElementArrayBuffer`) views.
    #[allow(clippy::too_many_arguments)]
    fn push_accessor(
        &mut self,
        data: &[u8],
        component_type: ComponentType,
        type_: Type,
        count: usize,
        target: Option<Target>,
        min: Option<serde_json::Value>,
        max: Option<serde_json::Value>,
        normalized: bool,
    ) -> Index<gltf::json::Accessor> {
        // 4-byte-align the start of every view (covers u8 index buffers etc.).
        while !self.bin.len().is_multiple_of(4) {
            self.bin.push(0);
        }
        let byte_offset = self.bin.len();
        self.bin.extend_from_slice(data);

        let view = self.root.push(gltf::json::buffer::View {
            buffer: Index::new(0),
            byte_length: USize64::from(data.len()),
            byte_offset: Some(USize64::from(byte_offset)),
            byte_stride: None,
            name: None,
            target: target.map(Valid),
            extensions: None,
            extras: gltf::json::extras::Void::default(),
        });

        self.root.push(gltf::json::Accessor {
            buffer_view: Some(view),
            byte_offset: Some(USize64(0)),
            count: USize64::from(count),
            component_type: Valid(GenericComponentType(component_type)),
            type_: Valid(type_),
            name: None,
            min,
            max,
            normalized,
            sparse: None,
            extensions: None,
            extras: gltf::json::extras::Void::default(),
        })
    }

    /// Finalize: register the single buffer (4-aligned) and return `(root, bin)`.
    fn into_parts(mut self) -> (gltf::json::Root, Vec<u8>) {
        while !self.bin.len().is_multiple_of(4) {
            self.bin.push(0);
        }
        // A self-contained GLB buffer carries no `uri`. Its index is fixed at 0
        // (no other buffer is created), so the returned `Index` is discarded.
        let _ = self.root.push(gltf::json::Buffer {
            byte_length: USize64::from(self.bin.len()),
            name: None,
            uri: None,
            extensions: None,
            extras: gltf::json::extras::Void::default(),
        });
        (self.root, self.bin)
    }
}

/// Serialize `root` + the BIN `buffer` into GLB bytes.
fn finish_glb(root: &gltf::json::Root, mut bin: Vec<u8>) -> crate::Result<Vec<u8>> {
    let mut json = serde_json::to_vec(root).map_err(|e| crate::PaksmithError::Internal {
        context: format!("glTF JSON serialization failed: {e}"),
    })?;
    while !json.len().is_multiple_of(4) {
        json.push(b' ');
    }
    while !bin.len().is_multiple_of(4) {
        bin.push(0);
    }
    let bin = if bin.is_empty() {
        None
    } else {
        Some(Cow::Owned(bin))
    };
    let glb = gltf::binary::Glb {
        header: gltf::binary::Header {
            magic: *b"glTF",
            version: 2,
            length: 0,
        },
        json: Cow::Owned(json),
        bin,
    };
    glb.to_vec().map_err(|e| crate::PaksmithError::Internal {
        context: format!("GLB container assembly failed: {e}"),
    })
}

/// UE → glTF metres-per-centimetre scale.
const UE_CM_TO_M: f32 = 0.01;

/// Map a UE position (left-handed, Z-up, cm) to glTF (right-handed, Y-up, m).
/// Swapping Y and Z moves Z-up to Y-up AND flips handedness (basis det = −1);
/// positions also scale cm→m.
///
/// Matches CUE4Parse's glTF exporter `Gltf.cs` (`FabianFG/CUE4Parse`,
/// `CUE4Parse-Conversion/Meshes/glTF/Gltf.cs`): `SwapYZ(pos * 0.01f)` where
/// `SwapYZ(v) = new FVector(v.X, v.Z, v.Y)` — `(x, z, y)`, no negation. The
/// Blender cube oracle (Task 12) is the final visual confirmation.
//
// Wired into `export` by Task 5+ (POSITION accessor); until then it is
// exercised only by unit tests.
#[allow(dead_code)]
#[allow(clippy::cast_possible_truncation)]
// glTF FLOAT accessors are 32-bit; UE5 LWC f64 precision is intentionally
// narrowed for export.
fn convert_position(v: &FVector) -> [f32; 3] {
    [
        v.x as f32 * UE_CM_TO_M,
        v.z as f32 * UE_CM_TO_M,
        v.y as f32 * UE_CM_TO_M,
    ]
}

/// Normalize an `(x, y, z)` triple to unit length, matching CUE4Parse's
/// post-`SwapYZ` `Normalize`. glTF requires unit-length `NORMAL`/`TANGENT`.
///
/// Degenerate guard: if the magnitude is zero or non-finite (NaN/∞), the input
/// is returned unchanged rather than dividing by zero and producing NaN.
fn normalize_xyz([x, y, z]: [f32; 3]) -> [f32; 3] {
    let len = (x * x + y * y + z * z).sqrt();
    if len > 0.0 && len.is_finite() {
        [x / len, y / len, z / len]
    } else {
        [x, y, z]
    }
}

/// Map a UE unit direction (normal) — same `(x, z, y)` basis as
/// [`convert_position`], no scale, then renormalize to unit length.
///
/// Matches CUE4Parse's `SwapYZAndNormalize`: the `(x, z, y)` basis swap followed
/// by a `Normalize`. glTF requires unit-length `NORMAL`; decoded values may not
/// be exactly unit after dequantization, so [`normalize_xyz`] enforces it (with
/// a zero/non-finite guard).
//
// Wired into `export` by Task 6+ (NORMAL accessor); until then it is
// exercised only by unit tests.
#[allow(dead_code)]
#[allow(clippy::cast_possible_truncation)]
// glTF FLOAT accessors are 32-bit; UE5 LWC f64 precision is intentionally
// narrowed for export.
fn convert_dir(v: &FVector) -> [f32; 3] {
    normalize_xyz([v.x as f32, v.z as f32, v.y as f32])
}

/// Map a UE tangent (`FVector4`): xyz like a direction (basis-swapped and
/// renormalized to unit length), w (handedness ±1) copied unchanged.
///
/// Matches CUE4Parse's `SwapYZAndNormalize(Vector4)`: `(x, z, y)` swap +
/// `Normalize` on the xyz, with `w` preserved. glTF requires unit-length
/// `TANGENT.xyz`; see [`convert_dir`] for the zero/non-finite guard.
//
// Wired into `export` by Task 6+ (TANGENT accessor); until then it is
// exercised only by unit tests.
#[allow(dead_code)]
#[allow(clippy::cast_possible_truncation)]
// glTF FLOAT accessors are 32-bit; UE5 LWC f64 precision is intentionally
// narrowed for export.
fn convert_tangent(v: &FVector4) -> [f32; 4] {
    let [x, y, z] = normalize_xyz([v.x as f32, v.z as f32, v.y as f32]);
    [x, y, z, v.w as f32]
}

/// Reverse triangle winding (`[a,b,c]` → `[a,c,b]`) to restore CCW front faces
/// after the handedness-flipping basis change. `indices.len()` is a multiple of
/// 3 (triangle list); a trailing partial triangle is copied verbatim.
///
/// DELIBERATE DIVERGENCE FROM CUE4Parse — UNVERIFIED. CUE4Parse's `Gltf.cs`
/// does NOT reverse winding; it emits explicit NORMAL attributes and relies on
/// viewers not back-face-culling. paksmith reverses so the CCW front-face
/// convention agrees with the basis flip (det = −1). This is a paksmith
/// contract choice, not a reference-confirmed behavior; the Blender cube render
/// (Task 12) is the oracle that confirms or refutes it.
//
// Wired into `export` by Task 7+ (index accessor); until then it is
// exercised only by unit tests.
#[allow(dead_code)]
fn reverse_winding(indices: &[u32]) -> Vec<u32> {
    let mut out = Vec::with_capacity(indices.len());
    let mut tri = indices.chunks_exact(3);
    for c in &mut tri {
        out.extend_from_slice(&[c[0], c[2], c[1]]);
    }
    out.extend_from_slice(tri.remainder());
    out
}

/// Lower a LOD's positions into a `POSITION` accessor (VEC3 f32) with the
/// glTF-required component-wise `min`/`max`.
//
// Wired by Task 9 (push_primitives); until then it is exercised only by unit
// tests.
#[allow(dead_code)]
fn push_positions(doc: &mut GltfDoc, lod: &StaticMeshLod) -> Index<gltf::json::Accessor> {
    let mut bytes = Vec::with_capacity(lod.positions.len() * 12);
    let mut min = [f32::INFINITY; 3];
    let mut max = [f32::NEG_INFINITY; 3];
    for p in &lod.positions {
        let c = convert_position(p);
        for i in 0..3 {
            min[i] = min[i].min(c[i]);
            max[i] = max[i].max(c[i]);
        }
        for f in c {
            bytes.extend_from_slice(&f.to_le_bytes());
        }
    }
    // Empty position list → no finite min/max; emit zeros (degenerate but valid).
    if lod.positions.is_empty() {
        min = [0.0; 3];
        max = [0.0; 3];
    }
    doc.push_accessor(
        &bytes,
        ComponentType::F32,
        Type::Vec3,
        lod.positions.len(),
        Some(Target::ArrayBuffer),
        Some(serde_json::json!(min)),
        Some(serde_json::json!(max)),
        false,
    )
}

/// Lower normals → `NORMAL` accessor (VEC3 f32), or `None` when absent.
//
// Wired by Task 9 (push_primitives); until then it is exercised only by unit
// tests.
#[allow(dead_code)]
fn push_normals(doc: &mut GltfDoc, lod: &StaticMeshLod) -> Option<Index<gltf::json::Accessor>> {
    if lod.normals.is_empty() {
        return None;
    }
    let mut bytes = Vec::with_capacity(lod.normals.len() * 12);
    for n in &lod.normals {
        for f in convert_dir(n) {
            bytes.extend_from_slice(&f.to_le_bytes());
        }
    }
    Some(doc.push_accessor(
        &bytes,
        ComponentType::F32,
        Type::Vec3,
        lod.normals.len(),
        Some(Target::ArrayBuffer),
        None,
        None,
        false,
    ))
}

/// Lower tangents → `TANGENT` accessor (VEC4 f32, w = handedness), or `None`.
//
// Wired by Task 9 (push_primitives); until then it is exercised only by unit
// tests.
#[allow(dead_code)]
fn push_tangents(doc: &mut GltfDoc, lod: &StaticMeshLod) -> Option<Index<gltf::json::Accessor>> {
    if lod.tangents.is_empty() {
        return None;
    }
    let mut bytes = Vec::with_capacity(lod.tangents.len() * 16);
    for t in &lod.tangents {
        for f in convert_tangent(t) {
            bytes.extend_from_slice(&f.to_le_bytes());
        }
    }
    Some(doc.push_accessor(
        &bytes,
        ComponentType::F32,
        Type::Vec4,
        lod.tangents.len(),
        Some(Target::ArrayBuffer),
        None,
        None,
        false,
    ))
}

/// Lower each present UV channel → a `TEXCOORD_n` accessor (VEC2 f32), in
/// channel order. Returns the accessor indices (`accs[n]` is `TEXCOORD_n`).
/// glTF V flips relative to UE (top-left vs bottom-left origin) is NOT applied —
/// UE UVs are already top-left-origin like glTF, so they map directly.
//
// Wired by Task 9 (push_primitives); until then it is exercised only by unit
// tests.
#[allow(dead_code)]
#[allow(clippy::cast_possible_truncation)]
// glTF FLOAT accessors are 32-bit; UV f64 precision is intentionally narrowed.
fn push_uvs(doc: &mut GltfDoc, lod: &StaticMeshLod) -> Vec<Index<gltf::json::Accessor>> {
    let mut out = Vec::new();
    for channel in lod.uvs.iter().flatten() {
        let mut bytes = Vec::with_capacity(channel.len() * 8);
        for uv in channel {
            bytes.extend_from_slice(&(uv.x as f32).to_le_bytes());
            bytes.extend_from_slice(&(uv.y as f32).to_le_bytes());
        }
        out.push(doc.push_accessor(
            &bytes,
            ComponentType::F32,
            Type::Vec2,
            channel.len(),
            Some(Target::ArrayBuffer),
            None,
            None,
            false,
        ));
    }
    out
}

/// Lower per-vertex colors → a `COLOR_0` accessor (VEC4 u8, normalized), or
/// `None`. paksmith stores `FColor` as RGBA already, matching glTF's RGBA order.
//
// Wired by Task 9 (push_primitives); until then it is exercised only by unit
// tests.
#[allow(dead_code)]
fn push_colors(doc: &mut GltfDoc, lod: &StaticMeshLod) -> Option<Index<gltf::json::Accessor>> {
    let colors = lod.colors.as_ref()?;
    let mut bytes = Vec::with_capacity(colors.len() * 4);
    for c in colors {
        bytes.extend_from_slice(&[c.r, c.g, c.b, c.a]);
    }
    Some(doc.push_accessor(
        &bytes,
        ComponentType::U8,
        Type::Vec4,
        colors.len(),
        Some(Target::ArrayBuffer),
        None,
        None,
        true,
    ))
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::*;
    use crate::asset::structs::bounds::FBoxSphereBounds;
    use crate::asset::{Asset, StaticMeshData, StaticMeshRenderData};

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

    #[test]
    fn gltf_doc_push_accessor_aligns_and_indexes() {
        let mut doc = GltfDoc::new();
        // 3 f32 = 12 bytes, already 4-aligned.
        let a = doc.push_accessor(
            &[1.0f32, 2.0, 3.0]
                .iter()
                .flat_map(|f| f.to_le_bytes())
                .collect::<Vec<u8>>(),
            gltf::json::accessor::ComponentType::F32,
            gltf::json::accessor::Type::Scalar,
            3,
            None,
            None,
            None,
            false,
        );
        // 1 byte → padded to 4 before the next view starts.
        let b = doc.push_accessor(
            &[0xAAu8],
            gltf::json::accessor::ComponentType::U8,
            gltf::json::accessor::Type::Scalar,
            1,
            Some(gltf::json::buffer::Target::ElementArrayBuffer),
            None,
            None,
            false,
        );
        // Third push starts at bin len 13 (un-aligned) → push_accessor's own
        // alignment loop must pad 13 → 16 before this view. This is the
        // assertion that exercises the in-method loop; deleting it makes the
        // view start at 13 (a surviving mutant otherwise).
        let c = doc.push_accessor(
            &[0xBBu8, 0xCC],
            gltf::json::accessor::ComponentType::U8,
            gltf::json::accessor::Type::Scalar,
            2,
            Some(gltf::json::buffer::Target::ElementArrayBuffer),
            None,
            None,
            false,
        );
        assert_eq!(a.value(), 0);
        assert_eq!(b.value(), 1);
        assert_eq!(c.value(), 2);
        let (root, bin) = doc.into_parts();
        assert_eq!(root.accessors.len(), 3);
        assert_eq!(root.buffer_views.len(), 3);
        assert_eq!(root.buffers.len(), 1);
        // View 0 at offset 0 (len 12); view 1 starts at 12 (12 already aligned).
        // gltf-json 1.4.1 `USize64` is a `pub u64` tuple struct with no
        // `Into<u64>`; read the inner value via `.0`.
        assert_eq!(root.buffer_views[1].byte_offset.unwrap().0, 12);
        // View 2 starts at 16 — push_accessor padded 13 → 16 itself.
        assert_eq!(root.buffer_views[2].byte_offset.unwrap().0, 16);
        // BIN length is the final 4-aligned total (16 + 2 → padded to 20).
        assert_eq!(bin.len(), 20);
        assert_eq!(root.buffers[0].byte_length.0, 20);
    }

    // ---------- Coordinate-conversion tests (Task 4) ----------

    // Exact equality is correct here: the inputs and the ×0.01 products
    // (1.0/2.0/3.0/0.0/-1.0) are all exactly representable in f32, so there
    // is no rounding to tolerate.
    #[allow(clippy::float_cmp)]
    #[test]
    fn convert_position_swaps_y_z_and_scales_cm_to_m() {
        // UE (100, 200, 300) cm → glTF Y-up metres. Y/Z swap + ×0.01.
        let p = convert_position(&FVector {
            x: 100.0,
            y: 200.0,
            z: 300.0,
        });
        assert_eq!(p, [1.0f32, 3.0, 2.0]); // (x, z, y) * 0.01
    }

    #[allow(clippy::float_cmp)] // exact representable values; see above
    #[test]
    fn convert_dir_swaps_y_z_without_scale() {
        let d = convert_dir(&FVector {
            x: 0.0,
            y: 0.0,
            z: 1.0,
        }); // UE +Z (up)
        assert_eq!(d, [0.0f32, 1.0, 0.0]); // glTF +Y (up), unit length preserved
    }

    #[allow(clippy::float_cmp)] // exact representable values; see above
    #[test]
    fn convert_tangent_swaps_xyz_and_keeps_w_handedness() {
        let t = convert_tangent(&FVector4 {
            x: 1.0,
            y: 0.0,
            z: 0.0,
            w: -1.0,
        });
        assert_eq!(t, [1.0f32, 0.0, 0.0, -1.0]); // xyz basis-mapped, w copied
    }

    #[allow(clippy::float_cmp)] // exact representable values; see above
    #[test]
    fn convert_dir_normalizes_non_unit_input() {
        // Non-unit axis vector: (0,0,2) → swap (0,2,0) → normalize → (0,1,0).
        let d = convert_dir(&FVector {
            x: 0.0,
            y: 0.0,
            z: 2.0,
        });
        assert!((d[0] - 0.0).abs() < 1e-6);
        assert!((d[1] - 1.0).abs() < 1e-6);
        assert!((d[2] - 0.0).abs() < 1e-6);

        // Diagonal 3-4-5 triple: (3,0,4) → swap (3,4,0) → normalize (0.6,0.8,0).
        let d = convert_dir(&FVector {
            x: 3.0,
            y: 0.0,
            z: 4.0,
        });
        assert!((d[0] - 0.6).abs() < 1e-6);
        assert!((d[1] - 0.8).abs() < 1e-6);
        assert!((d[2] - 0.0).abs() < 1e-6);
    }

    #[allow(clippy::float_cmp)] // w is an exact representable value
    #[test]
    fn convert_tangent_normalizes_xyz_keeps_w() {
        // Non-unit xyz (0,0,2) → swap (0,2,0) → normalize (0,1,0); w copied.
        let t = convert_tangent(&FVector4 {
            x: 0.0,
            y: 0.0,
            z: 2.0,
            w: -1.0,
        });
        assert!((t[0] - 0.0).abs() < 1e-6);
        assert!((t[1] - 1.0).abs() < 1e-6);
        assert!((t[2] - 0.0).abs() < 1e-6);
        assert_eq!(t[3], -1.0f32); // handedness preserved exactly
    }

    #[test]
    fn reverse_winding_swaps_second_and_third_of_each_triangle() {
        let src = [0u32, 1, 2, 3, 4, 5];
        assert_eq!(reverse_winding(&src), vec![0u32, 2, 1, 3, 5, 4]);
    }

    /// Feed a zero vector to `convert_dir` and assert the result is exactly
    /// `[0.0, 0.0, 0.0]` with every component finite.
    ///
    /// Without the `len > 0.0` guard in `normalize_xyz`, dividing by `len=0`
    /// yields NaN; `is_finite()` and the exact-equality assert both catch the
    /// mutant.
    #[allow(clippy::float_cmp)] // zero is exactly representable; guard returns input unchanged
    #[test]
    fn convert_dir_zero_vector_does_not_nan() {
        let d = convert_dir(&FVector {
            x: 0.0,
            y: 0.0,
            z: 0.0,
        });
        assert_eq!(d, [0.0f32, 0.0, 0.0]);
        assert!(d[0].is_finite());
        assert!(d[1].is_finite());
        assert!(d[2].is_finite());
    }

    /// Feed a 7-element slice (two full triangles + one trailing index) to
    /// `reverse_winding` and assert the two triangles are reversed and the
    /// trailing index is copied verbatim.
    ///
    /// Exercises the `chunks_exact(3).remainder()` path; a mutant that drops
    /// `out.extend_from_slice(tri.remainder())` would produce a 6-element
    /// result missing the trailing `9`.
    #[test]
    fn reverse_winding_copies_trailing_partial_triangle() {
        let src = [0u32, 1, 2, 3, 4, 5, 9];
        assert_eq!(reverse_winding(&src), vec![0u32, 2, 1, 3, 5, 4, 9]);
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
}
