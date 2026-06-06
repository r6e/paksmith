//! `FStaticMeshSection` reader (Phase 3g render data).
//!
//! A section is one draw call: a material + a contiguous index range + render
//! flags. Wire-format reference: `docs/formats/mesh/static-mesh.md`
//! §`FStaticMeshSection`; oracle `FabianFG/CUE4Parse` `FStaticMeshSection.cs`.

use std::io::Read;

use crate::asset::AssetContext;
use crate::asset::version::VER_UE5_ADD_SOFTOBJECTPATH_LIST;
use crate::error::AssetWireField;

use super::read;

/// A per-draw-call `FStaticMeshSection`: material index + the `[FirstIndex,
/// FirstIndex + 3·NumTriangles)` slice of the LOD index buffer + render flags.
/// The version-gated bools default to `false` on versions that don't serialize
/// them.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "each bool is a distinct FStaticMeshSection wire field, mirrored 1:1 from the oracle"
)]
#[non_exhaustive]
pub struct MeshSection {
    /// Index into `UStaticMesh::StaticMaterials`.
    pub material_index: i32,
    /// First index (into the LOD index buffer) this section draws.
    pub first_index: i32,
    /// Triangle count.
    pub num_triangles: i32,
    /// Inclusive lower vertex-index bound.
    pub min_vertex_index: i32,
    /// Inclusive upper vertex-index bound.
    pub max_vertex_index: i32,
    /// `bEnableCollision`.
    pub enable_collision: bool,
    /// `bCastShadow`.
    pub cast_shadow: bool,
    /// `bForceOpaque` (UE 4.25+; `false` below).
    pub force_opaque: bool,
    /// `bVisibleInRayTracing` (UE 4.27+; `false` below).
    pub visible_in_ray_tracing: bool,
    /// `bAffectDistanceFieldLighting` (UE 5.1+; `false` below).
    pub affect_distance_field_lighting: bool,
}

/// Read one `FStaticMeshSection`.
///
/// Wire: `MaterialIndex`, `FirstIndex`, `NumTriangles`, `MinVertexIndex`,
/// `MaxVertexIndex` (5 × `i32`), then the lax-bool (`ReadBoolean` = `int != 0`)
/// render flags: `bEnableCollision`, `bCastShadow` (always), then
/// `bForceOpaque` (UE 4.25+), `bVisibleInRayTracing` (UE 4.27+),
/// `bAffectDistanceFieldLighting` (UE 5.1+). Stock-UE layout — the oracle's
/// game-specific skips (PUBG / BlueProtocol / …) are out of scope.
pub(crate) fn read_section<R: Read>(
    reader: &mut R,
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<MeshSection> {
    let field = AssetWireField::MeshSection;
    let material_index = read::read_i32(reader, asset_path, field)?;
    let first_index = read::read_i32(reader, asset_path, field)?;
    let num_triangles = read::read_i32(reader, asset_path, field)?;
    let min_vertex_index = read::read_i32(reader, asset_path, field)?;
    let max_vertex_index = read::read_i32(reader, asset_path, field)?;
    let enable_collision = read::read_lax_bool32(reader, asset_path, field)?;
    let cast_shadow = read::read_lax_bool32(reader, asset_path, field)?;

    let force_opaque = if ctx.version.is_ue4_25_or_later() {
        read::read_lax_bool32(reader, asset_path, field)?
    } else {
        false
    };
    let visible_in_ray_tracing = if ctx.version.is_ue4_27_or_later() {
        read::read_lax_bool32(reader, asset_path, field)?
    } else {
        false
    };
    // `bAffectDistanceFieldLighting` is gated on the *engine* version (UE 5.1+);
    // `ADD_SOFTOBJECTPATH_LIST` (1008) is a 5.1-era package-version anchor that
    // cleanly separates UE5.0 (≤ 1006) from UE5.1+ — exact-boundary-approximate.
    let affect_distance_field_lighting =
        if ctx.version.ue5_at_least(VER_UE5_ADD_SOFTOBJECTPATH_LIST) {
            read::read_lax_bool32(reader, asset_path, field)?
        } else {
            false
        };

    Ok(MeshSection {
        material_index,
        first_index,
        num_triangles,
        min_vertex_index,
        max_vertex_index,
        enable_collision,
        cast_shadow,
        force_opaque,
        visible_in_ray_tracing,
        affect_distance_field_lighting,
    })
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::asset::property::test_utils::make_ctx_with_version;

    /// Append five `i32` section ranges + `n` lax-bool32 flags (`1`).
    fn section_bytes(n_flags: usize) -> Vec<u8> {
        let mut b = Vec::new();
        for v in [7i32, 0, 12, 3, 40] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        for _ in 0..n_flags {
            b.extend_from_slice(&1i32.to_le_bytes());
        }
        b
    }

    /// UE4.24: only `bEnableCollision` + `bCastShadow` (no later bools).
    #[test]
    fn section_ue4_24_two_bools() {
        let ctx = make_ctx_with_version(514, None);
        let s = read_section(&mut Cursor::new(section_bytes(2)), &ctx, "T").unwrap();
        assert_eq!(s.material_index, 7);
        assert_eq!(s.num_triangles, 12);
        assert_eq!(s.max_vertex_index, 40);
        assert!(s.enable_collision && s.cast_shadow);
        assert!(!s.force_opaque && !s.visible_in_ray_tracing);
        assert!(!s.affect_distance_field_lighting);
    }

    /// UE4.27: + `bForceOpaque` + `bVisibleInRayTracing` (4 bools).
    #[test]
    fn section_ue4_27_four_bools() {
        let ctx = make_ctx_with_version(522, None);
        let s = read_section(&mut Cursor::new(section_bytes(4)), &ctx, "T").unwrap();
        assert!(s.force_opaque && s.visible_in_ray_tracing);
        assert!(!s.affect_distance_field_lighting);
    }

    /// UE5.1: + `bAffectDistanceFieldLighting` (5 bools).
    #[test]
    fn section_ue5_1_five_bools() {
        let ctx = make_ctx_with_version(522, Some(VER_UE5_ADD_SOFTOBJECTPATH_LIST));
        let s = read_section(&mut Cursor::new(section_bytes(5)), &ctx, "T").unwrap();
        assert!(s.force_opaque && s.visible_in_ray_tracing);
        assert!(s.affect_distance_field_lighting);
    }

    /// UE5.0 (package version 1004) does NOT read the distance-field bool.
    #[test]
    fn section_ue5_0_no_distance_field_bool() {
        let ctx = make_ctx_with_version(522, Some(1004));
        // Only 4 bools present (collision, shadow, force_opaque, raytracing).
        let s = read_section(&mut Cursor::new(section_bytes(4)), &ctx, "T").unwrap();
        assert!(!s.affect_distance_field_lighting);
    }

    /// A truncated section (EOF mid-field) errors rather than panicking.
    #[test]
    fn section_truncated_is_eof() {
        let ctx = make_ctx_with_version(514, None);
        let err = read_section(&mut Cursor::new(vec![0u8; 6]), &ctx, "T").unwrap_err();
        assert!(matches!(
            err,
            crate::error::PaksmithError::AssetParse {
                fault: crate::error::AssetParseFault::UnexpectedEof { .. },
                ..
            }
        ));
    }
}
