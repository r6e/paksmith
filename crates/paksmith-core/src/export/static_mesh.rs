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

use crate::asset::Asset;
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

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::*;
    use crate::asset::structs::bounds::FBoxSphereBounds;
    use crate::asset::structs::vector::FVector;
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
}
