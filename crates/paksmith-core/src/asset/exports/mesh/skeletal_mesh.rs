//! `USkeletalMesh` export parsing (Phase 3h). Wire reference:
//! `docs/formats/mesh/skeletal-mesh.md`.
//!
//! PR2 scope is the `FMeshUVChannelInfo` leaf reader (consumed by
//! `FSkeletalMaterial`); the `FSkeletalMaterial` reader, the segment-2 prefix,
//! and dispatch wiring land in later steps/PRs of the 3h series.

use std::io::Read;

use crate::asset::wire::read_bool32;
use crate::error::AssetWireField;

use super::read;

/// `FMeshUVChannelInfo::MAX_TEXCOORDS` — the fixed `LocalUVDensities` element
/// count (oracle `FMeshUVChannelInfo.cs` @ `cf74fc32`). Read as a fixed-size
/// `float[]` with NO count prefix.
#[allow(
    dead_code,
    reason = "consumed by the FSkeletalMaterial reader (next 3h step)"
)]
const MAX_TEXCOORDS: usize = 4;

/// Consume an `FMeshUVChannelInfo` (24 bytes), staying cursor-aligned.
///
/// Wire layout (oracle `FMeshUVChannelInfo.cs` @ `cf74fc32`, cooked):
/// `bInitialized` (4-byte strict `0/1` int-bool via `Ar.ReadBoolean`) +
/// `bOverrideDensities` (4-byte strict int-bool) + `LocalUVDensities`
/// (`MAX_TEXCOORDS` × `f32`, no count prefix) = `4 + 4 + 4·4 = 24` bytes.
///
/// The struct carries no data paksmith needs downstream — it exists only to
/// keep the surrounding `FSkeletalMaterial`/`FStaticMaterial` cursor aligned —
/// so the floats are read (validating length / EOF) and discarded.
///
/// # Errors
/// - [`crate::error::AssetParseFault::InvalidBool32`] if either bool is not 0/1.
/// - [`crate::PaksmithError::Io`] if a bool32 read hits EOF (propagated from
///   [`read_bool32`], which surfaces EOF as `Io`).
/// - [`crate::error::AssetParseFault::UnexpectedEof`] if a `LocalUVDensities`
///   float runs short.
#[allow(
    dead_code,
    reason = "called by the FSkeletalMaterial reader (next 3h step)"
)]
pub(super) fn read_mesh_uv_channel_info<R: Read + ?Sized>(
    r: &mut R,
    asset_path: &str,
) -> crate::Result<()> {
    let _initialized = read_bool32(r, asset_path, AssetWireField::MeshUvChannelInfo)?;
    let _override_densities = read_bool32(r, asset_path, AssetWireField::MeshUvChannelInfo)?;
    for _ in 0..MAX_TEXCOORDS {
        let _density = read::read_f32(r, asset_path, AssetWireField::MeshUvChannelInfo)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PaksmithError;
    use crate::error::AssetParseFault;
    use std::io::Cursor;

    #[test]
    fn reads_mesh_uv_channel_info_consumes_24_bytes() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1i32.to_le_bytes()); // bInitialized = 1
        bytes.extend_from_slice(&0i32.to_le_bytes()); // bOverrideDensities = 0
        bytes.extend_from_slice(&[0u8; 16]); // 4 × f32 = 0.0
        assert_eq!(bytes.len(), 24);

        let mut cur = Cursor::new(bytes.as_slice());
        read_mesh_uv_channel_info(&mut cur, "T.uasset").expect("decode");
        assert_eq!(cur.position(), 24);
    }

    #[test]
    fn rejects_non_strict_initialized_bool() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&2i32.to_le_bytes()); // bInitialized = 2 → invalid
        bytes.extend_from_slice(&0i32.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 16]);

        let mut cur = Cursor::new(bytes.as_slice());
        let err = read_mesh_uv_channel_info(&mut cur, "T.uasset").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::InvalidBool32 {
                    field: AssetWireField::MeshUvChannelInfo,
                    observed: 2,
                },
                ..
            }
        ));
    }

    #[test]
    fn truncated_bool_region_is_io_eof() {
        // A cut inside the bool32 region propagates as PaksmithError::Io (the
        // documented read_bool32 EOF behavior), not AssetParseFault::UnexpectedEof.
        let bytes = 1i32.to_le_bytes(); // only bInitialized; bOverrideDensities truncated
        let mut cur = Cursor::new(bytes.as_slice());
        let err = read_mesh_uv_channel_info(&mut cur, "T.uasset").unwrap_err();
        assert!(
            matches!(err, PaksmithError::Io(_)),
            "expected Io, got {err:?}"
        );
    }

    #[test]
    fn truncated_mesh_uv_channel_info_is_eof() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1i32.to_le_bytes());
        bytes.extend_from_slice(&0i32.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 8]); // only 2 of 4 floats

        let mut cur = Cursor::new(bytes.as_slice());
        let err = read_mesh_uv_channel_info(&mut cur, "T.uasset").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::UnexpectedEof {
                    field: AssetWireField::MeshUvChannelInfo,
                },
                ..
            }
        ));
    }
}
