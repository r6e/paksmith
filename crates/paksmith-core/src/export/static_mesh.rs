//! `UStaticMesh` → glTF 2.0 (`.glb`) export — Phase 3g2.
//!
//! Lowers parsed [`crate::asset::StaticMeshData`] render geometry into a
//! self-contained binary glTF. Design: `docs/plans/phase-3g2-gltf-export.md`.

use std::borrow::Cow;

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
}
