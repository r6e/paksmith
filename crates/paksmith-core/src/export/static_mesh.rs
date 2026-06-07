//! `UStaticMesh` → glTF 2.0 (`.glb`) export — Phase 3g2.
//!
//! Lowers parsed [`crate::asset::StaticMeshData`] render geometry into a
//! self-contained binary glTF. Design: `docs/plans/phase-3g2-gltf-export.md`.

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    /// Pin the `gltf` write API: an empty `json::Root` (asset only) serializes,
    /// wraps in a `binary::Glb`, and `to_vec` produces bytes starting with the
    /// `glTF` magic. Establishes the exact types the later tasks build on.
    #[test]
    fn gltf_write_api_round_trips_empty_doc() {
        let root = gltf::json::Root::default();
        let json = serde_json::to_vec(&root).expect("serialize root");
        let mut json = json;
        while json.len() % 4 != 0 {
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
