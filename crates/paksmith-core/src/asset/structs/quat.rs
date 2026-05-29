//! `FQuat` decoder — UE4 = 4 × f32 (16 bytes); UE5 LWC = 4 × f64
//! (32 bytes).
//!
//! Wire-format reference: CUE4Parse `FQuat.cs` at
//! `cf74fc32fe1b40e9fd3440032508c5e1d50cf58d`. Wire order is
//! `(x, y, z, w)` — the imaginary components precede the real
//! component, matching the i/j/k/scalar convention common in
//! game-engine quaternion serialization (and distinct from the
//! `(w, x, y, z)` order some math libraries use).
//!
//! Components are stored as `f64` (UE4 f32 losslessly widened on
//! decode), matching [`super::vector::FVector`].

use std::io::{Read, Seek};

use crate::asset::AssetContext;
use crate::asset::structs::{TypedStructValue, read_components, verify_at_end};

/// Quaternion — 4 floats in `(x, y, z, w)` wire order. The
/// identity quaternion (no rotation) is `(0, 0, 0, 1)`.
///
/// UE4 = f32×4 (16 bytes); UE5 LWC = f64×4 (32 bytes).
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct FQuat {
    /// X (imaginary i) component — wire position 0.
    pub x: f64,
    /// Y (imaginary j) component — wire position 1.
    pub y: f64,
    /// Z (imaginary k) component — wire position 2.
    pub z: f64,
    /// W (real / scalar) component — wire position 3.
    pub w: f64,
}

impl FQuat {
    /// Decode an `FQuat` from `reader`. Component width per
    /// `ctx.version.is_lwc()` — same dispatch as
    /// [`super::vector::FVector`].
    ///
    /// # Errors
    /// - [`crate::error::AssetParseFault::UnexpectedEof`] with
    ///   `field = TypedStructComponent { struct_name: "FQuat" }`
    ///   if any component read hits EOF.
    /// - Trailing-bytes / overrun faults per `verify_at_end`.
    pub fn read_from<R: Read + Seek + ?Sized>(
        reader: &mut R,
        ctx: &AssetContext,
        expected_end: u64,
        asset_path: &str,
    ) -> crate::Result<Self> {
        let [x, y, z, w] = read_components::<R, 4>(reader, ctx, "FQuat", asset_path)?;
        verify_at_end(reader, expected_end, "FQuat", asset_path)?;
        Ok(Self { x, y, z, w })
    }

    /// Wire byte size of an `FQuat` under `ctx`'s LWC width: 16 (UE4
    /// f32×4) or 32 (UE5 LWC f64×4). The composing
    /// [`FTransform`](super::transform::FTransform) decoder calls this
    /// to bound its nested `FQuat` read — the 4-component count lives
    /// here, on the type that owns it, rather than at the composition
    /// site. Mirrors [`super::vector::FVector::wire_size`].
    #[must_use]
    pub(crate) fn wire_size(ctx: &AssetContext) -> u64 {
        4 * crate::asset::structs::lwc_component_width(ctx)
    }
}

/// Registry-compatible decoder shim. The function pointer stored
/// in `structs::registry()` takes `&mut dyn Read+Seek` instead of
/// a generic `R: Read+Seek` (function pointers can't be generic).
pub(crate) fn read_fquat(
    reader: &mut dyn crate::asset::structs::ReadAndSeek,
    ctx: &AssetContext,
    expected_end: u64,
    asset_path: &str,
) -> crate::Result<TypedStructValue> {
    let q = FQuat::read_from(reader, ctx, expected_end, asset_path)?;
    Ok(TypedStructValue::Quat(q))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PaksmithError;
    use crate::asset::property::test_utils::make_ctx_with_version;
    use crate::asset::structs::test_utils::{f32_bytes, f64_bytes};
    use crate::error::{AssetParseFault, AssetWireField};
    use std::io::Cursor;

    #[test]
    fn identity_quaternion_decodes_correctly() {
        // Identity = (0, 0, 0, 1) — the no-rotation reference value.
        // This pins the wire order: a `(w, x, y, z)` swap would
        // surface as `x == 1.0, w == 0.0`.
        let bytes = f32_bytes(&[0.0, 0.0, 0.0, 1.0]);
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(bytes.as_slice());
        let q = FQuat::read_from(&mut cur, &ctx, 16, "test.uasset").expect("read");
        assert!(
            q.x.abs() < f64::EPSILON,
            "identity x must be 0, got {}",
            q.x
        );
        assert!(
            q.y.abs() < f64::EPSILON,
            "identity y must be 0, got {}",
            q.y
        );
        assert!(
            q.z.abs() < f64::EPSILON,
            "identity z must be 0, got {}",
            q.z
        );
        assert!(
            (q.w - 1.0).abs() < f64::EPSILON,
            "identity w must be 1, got {}",
            q.w
        );
    }

    #[test]
    fn ue4_quat_decodes_16_bytes() {
        // Use values that ARE exactly representable in both f32
        // and f64 (powers-of-two fractions) so EPSILON-based
        // comparison is meaningful — `0.1_f32` widens to a slightly
        // different f64 than `0.1_f64`, which would force a
        // looser tolerance and obscure the wire-order assertion.
        let bytes = f32_bytes(&[0.25, 0.5, 0.75, 1.0]);
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(bytes.as_slice());
        let q = FQuat::read_from(&mut cur, &ctx, 16, "test.uasset").expect("read");
        assert!((q.x - 0.25).abs() < f64::EPSILON);
        assert!((q.y - 0.5).abs() < f64::EPSILON);
        assert!((q.z - 0.75).abs() < f64::EPSILON);
        assert!((q.w - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn ue5_lwc_quat_decodes_32_bytes() {
        // UE5 LWC gate at 1004 — same boundary as FVector.
        let bytes = f64_bytes(&[0.1, 0.2, 0.3, 0.9]);
        let ctx = make_ctx_with_version(510, Some(1004));
        let mut cur = Cursor::new(bytes.as_slice());
        let q = FQuat::read_from(&mut cur, &ctx, 32, "test.uasset").expect("read");
        assert!((q.x - 0.1).abs() < f64::EPSILON);
        assert!((q.y - 0.2).abs() < f64::EPSILON);
        assert!((q.z - 0.3).abs() < f64::EPSILON);
        assert!((q.w - 0.9).abs() < f64::EPSILON);
    }

    #[test]
    fn pre_lwc_ue5_quat_uses_f32_width() {
        // UE5 below the LWC gate (1003) — still f32 width.
        let bytes = f32_bytes(&[0.0, 0.0, 0.0, 1.0]);
        let ctx = make_ctx_with_version(510, Some(1003));
        let mut cur = Cursor::new(bytes.as_slice());
        let q = FQuat::read_from(&mut cur, &ctx, 16, "test.uasset").expect("read");
        assert!((q.w - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn quat_eof_during_decode_rejected() {
        // 12 bytes — enough for x, y, z as f32 but w hits EOF.
        let bytes = f32_bytes(&[0.0, 0.0, 0.0]);
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(bytes.as_slice());
        let err = FQuat::read_from(&mut cur, &ctx, 16, "test.uasset").unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::UnexpectedEof {
                        field: AssetWireField::TypedStructComponent {
                            struct_name: "FQuat"
                        },
                    },
                    ..
                }
            ),
            "expected UnexpectedEof(TypedStructComponent(FQuat)), got {err:?}"
        );
    }

    #[test]
    fn quat_trailing_bytes_rejected() {
        let mut bytes = f32_bytes(&[0.0, 0.0, 0.0, 1.0]);
        bytes.extend_from_slice(&[0u8; 4]);
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(bytes.as_slice());
        let err = FQuat::read_from(&mut cur, &ctx, 20, "test.uasset").unwrap_err();
        match err {
            PaksmithError::AssetParse {
                fault:
                    AssetParseFault::TypedStructTrailingBytes {
                        struct_name,
                        trailing,
                    },
                ..
            } => {
                assert_eq!(struct_name, "FQuat");
                assert_eq!(trailing, 4u64);
            }
            other => panic!("expected TypedStructTrailingBytes(FQuat), got {other:?}"),
        }
    }

    #[test]
    fn quat_overrun_rejected() {
        // 16 wire bytes (UE4 f32×4) but expected_end = 12.
        let bytes = f32_bytes(&[0.0, 0.0, 0.0, 1.0]);
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(bytes.as_slice());
        let err = FQuat::read_from(&mut cur, &ctx, 12, "test.uasset").unwrap_err();
        match err {
            PaksmithError::AssetParse {
                fault:
                    AssetParseFault::TypedStructOverrun {
                        struct_name,
                        overrun,
                    },
                ..
            } => {
                assert_eq!(struct_name, "FQuat");
                assert_eq!(overrun, 4u64);
            }
            other => panic!("expected TypedStructOverrun(FQuat), got {other:?}"),
        }
    }

    #[test]
    fn fquat_wire_size_matches_lwc_width() {
        // Direct pin on the composer-facing `wire_size` contract
        // (FTransform bounds its nested FQuat read by this). UE4 =
        // 4×f32 = 16; UE5 LWC = 4×f64 = 32. Mirrors the FVector
        // wire_size pins in vector.rs.
        assert_eq!(FQuat::wire_size(&make_ctx_with_version(510, None)), 16);
        assert_eq!(
            FQuat::wire_size(&make_ctx_with_version(510, Some(1004))),
            32
        );
    }

    #[test]
    fn read_fquat_shim_returns_typed_struct_quat() {
        let bytes = f32_bytes(&[0.5, 0.5, 0.5, 0.5]);
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(bytes.as_slice());
        let value = read_fquat(&mut cur, &ctx, 16, "test.uasset").expect("read");
        match value {
            TypedStructValue::Quat(q) => {
                assert!((q.x - 0.5).abs() < f64::EPSILON);
                assert!((q.w - 0.5).abs() < f64::EPSILON);
            }
            other => panic!("expected TypedStructValue::Quat, got {other:?}"),
        }
    }
}
