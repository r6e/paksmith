//! Skinned-mesh glTF export — math foundation.
//!
//! Phase 3h's skeletal exporter must place the skeleton's bone
//! transforms in the SAME coordinate frame as the geometry. The
//! geometry path ([`super::gltf_common::convert_position`]) maps a UE
//! vertex `(x, y, z)` to glTF `(0.01x, 0.01z, 0.01y)` — centimetres to
//! metres plus the Y↔Z axis swap. The bind matrices therefore have to
//! be expressed through the matching change-of-basis `B`, or the skin
//! ends up silently rotated relative to the mesh.
//!
//! This module supplies that basis (`B = 0.01·P`) and the
//! `FTransform` → column-major affine `DMat4` helper used to build
//! bone-local matrices, both on `glam`'s f64 types.

use glam::{DMat4, DQuat, DVec3, DVec4};

use crate::asset::structs::transform::FTransform;

/// UE→glTF change-of-basis `B = 0.01·P` (cm→m + Y↔Z axis swap), matching
/// [`super::gltf_common::convert_position`]. Column-major; pure linear (no
/// translation).
#[allow(dead_code)] // consumed by PR6 Tasks 5–8
pub(crate) fn ue_to_gltf_basis() -> DMat4 {
    // B maps (x,y,z) -> (0.01x, 0.01z, 0.01y). Columns = images of e_x, e_y, e_z.
    //   e_x=(1,0,0) -> (0.01, 0,    0   )
    //   e_y=(0,1,0) -> (0,    0,    0.01)   (UE y -> glTF 3rd axis)
    //   e_z=(0,0,1) -> (0,    0.01, 0   )   (UE z -> glTF 2nd axis)
    DMat4::from_cols(
        DVec4::new(0.01, 0.0, 0.0, 0.0),
        DVec4::new(0.0, 0.0, 0.01, 0.0),
        DVec4::new(0.0, 0.01, 0.0, 0.0),
        DVec4::new(0.0, 0.0, 0.0, 1.0),
    )
}

/// Compose an [`FTransform`] (rotation·scale + translation) into a column-major
/// affine [`DMat4`]. The wire quaternion is normalized defensively.
#[allow(dead_code)] // consumed by PR6 Tasks 5–8
pub(crate) fn ftransform_to_dmat4(t: &FTransform) -> DMat4 {
    let rot = DQuat::from_xyzw(t.rotation.x, t.rotation.y, t.rotation.z, t.rotation.w).normalize();
    DMat4::from_scale_rotation_translation(
        DVec3::new(t.scale_3d.x, t.scale_3d.y, t.scale_3d.z),
        rot,
        DVec3::new(t.translation.x, t.translation.y, t.translation.z),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::structs::quat::FQuat;
    use crate::asset::structs::vector::FVector;

    /// The anti-drift guard against [`super::super::gltf_common::convert_position`]:
    /// `B · (x,y,z)` must equal `(0.01x, 0.01z, 0.01y)` for arbitrary points.
    /// A wrong column would silently rotate the whole skeleton while still
    /// passing shape-only tests, so this is the load-bearing check.
    #[test]
    fn basis_matches_convert_position() {
        let b = ue_to_gltf_basis();
        for (x, y, z) in [(3.0, 5.0, 7.0), (-1.0, 2.0, -4.0), (0.0, 0.0, 0.0)] {
            let got = b.transform_point3(DVec3::new(x, y, z));
            let want = DVec3::new(x * 0.01, z * 0.01, y * 0.01);
            assert!(
                (got.x - want.x).abs() < 1e-12
                    && (got.y - want.y).abs() < 1e-12
                    && (got.z - want.z).abs() < 1e-12,
                "basis drift at ({x}, {y}, {z}): got {got:?}, want {want:?}"
            );
        }
    }

    /// `B · B⁻¹ ≈ I` — the basis is invertible (no degenerate column).
    #[test]
    fn basis_inverse_round_trips() {
        let b = ue_to_gltf_basis();
        let id = b * b.inverse();
        let id_cols = id.to_cols_array();
        let expected = DMat4::IDENTITY.to_cols_array();
        for (i, (got, want)) in id_cols.iter().zip(expected.iter()).enumerate() {
            assert!(
                (got - want).abs() < 1e-12,
                "B·B⁻¹ element {i} = {got}, expected {want}"
            );
        }
    }

    /// `ftransform_to_dmat4` composes scale→rotate→translate (glam's
    /// `from_scale_rotation_translation` order). Expected is computed
    /// independently via `rot * (scale * p) + translation` — NOT via a
    /// second `from_scale_rotation_translation`, so the test isn't circular.
    #[test]
    fn ftransform_to_dmat4_applies_srt() {
        // Non-axis-aligned rotation: 37° about normalized (1,1,0).
        let q = DQuat::from_axis_angle(DVec3::new(1.0, 1.0, 0.0).normalize(), 37f64.to_radians());
        let t = FTransform {
            rotation: FQuat {
                x: q.x,
                y: q.y,
                z: q.z,
                w: q.w,
            },
            translation: FVector {
                x: 10.0,
                y: 20.0,
                z: 30.0,
            },
            scale_3d: FVector {
                x: 2.0,
                y: 0.5,
                z: 1.5,
            },
        };
        let m = ftransform_to_dmat4(&t);

        let scale = DVec3::new(2.0, 0.5, 1.5);
        let translation = DVec3::new(10.0, 20.0, 30.0);
        for p in [
            DVec3::new(1.0, 0.0, 0.0),
            DVec3::new(0.0, 1.0, 0.0),
            DVec3::new(-3.0, 4.0, 5.0),
        ] {
            let got = m.transform_point3(p);
            // Independent SRT: scale component-wise, rotate, then translate.
            let want = q * (scale * p) + translation;
            assert!(
                (got - want).length() < 1e-9,
                "SRT mismatch at {p:?}: got {got:?}, want {want:?}"
            );
        }
    }
}
