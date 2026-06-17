//! Emit the glTF-validator fixtures (#564).
//!
//! Exports the cube static mesh and the 5-bone skinned mesh (from
//! `paksmith_core::testing::gltf_fixtures`) through the real glTF handlers and
//! writes `<out_dir>/cube.glb` and `<out_dir>/skeletal.glb`. The `gltf-validation`
//! CI job runs this, then runs the Khronos `gltf_validator` on the two `.glb`
//! files and asserts zero spec errors.
//!
//! Requires `--features __test_utils` (the fixtures live behind that gate).
//! Run: `cargo run -p paksmith-core --example emit_gltf_validation_fixtures \
//!       --features __test_utils -- <out_dir>`

use std::path::PathBuf;

use paksmith_core::export::{FormatHandler, GltfSkeletalMeshHandler, GltfStaticMeshHandler};
use paksmith_core::testing::gltf_fixtures::{cube_static_mesh, five_bone_skinned_mesh};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = PathBuf::from(
        std::env::args()
            .nth(1)
            .ok_or("usage: emit_gltf_validation_fixtures <out_dir>")?,
    );
    std::fs::create_dir_all(&out_dir)?;

    let cube = GltfStaticMeshHandler.export(&cube_static_mesh(), &[])?;
    std::fs::write(out_dir.join("cube.glb"), &cube)?;

    let skeletal = GltfSkeletalMeshHandler.export(&five_bone_skinned_mesh(), &[])?;
    std::fs::write(out_dir.join("skeletal.glb"), &skeletal)?;

    eprintln!(
        "wrote cube.glb ({} bytes) + skeletal.glb ({} bytes) to {}",
        cube.len(),
        skeletal.len(),
        out_dir.display(),
    );
    Ok(())
}
