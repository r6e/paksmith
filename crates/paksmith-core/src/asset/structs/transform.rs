//! `FTransform` decoder — a rigid-body-plus-scale transform composing
//! the [`FQuat`] + [`FVector`] decoders.
//!
//! Wire-format reference: CUE4Parse `FTransform.cs` at
//! `cf74fc32fe1b40e9fd3440032508c5e1d50cf58d`. The archive
//! constructor reads three components in order, with **no trailing
//! pad byte**:
//!
//! ```text
//! Rotation    : FQuat   (x, y, z, w)
//! Translation : FVector (x, y, z)
//! Scale3D     : FVector (x, y, z)
//! ```
//!
//! UE4 = 16 + 12 + 12 = 40 bytes; UE5 LWC = 32 + 24 + 24 = 80 bytes.
//! The nested decoders LWC-widen internally ([`FQuat::read_from`] /
//! [`FVector::read_from`] dispatch f32-vs-f64 on
//! `ctx.version.is_lwc()`), so `FTransform` inherits the widening for
//! free — same composition pattern as [`super::box_::FBox`].
//!
//! # NOT a registry-dispatched StructProperty
//!
//! Unlike the other Phase 3c decoders, `FTransform` is **not**
//! registered in the `lookup` dispatch table. A `"Transform"`
//! `StructProperty` serializes as *tagged sub-properties*
//! (`Rotation` / `Translation` / `Scale3D`, each a nested property),
//! **not** a raw quat+vec+vec binary blob — so it must fall through
//! to Phase 2g's tagged-property iteration. Registering a binary
//! decoder under `"Transform"` would silently misparse real tagged
//! Transforms once Task 10 wires `lookup` into the dispatcher.
//!
//! This was verified against two independent reference parsers:
//! CUE4Parse's `FScriptStruct` dispatch (pinned SHA) routes a bare
//! `"Transform"` to its `FStructFallback` default arm (tagged
//! iteration) — its only binary Transform arm is the explicit-float
//! `"Transform3f"` (a blittable raw-array read); and UAssetAPI ships
//! binary `PropertyData` for every sibling math type
//! (`Vector`/`Quat`/`Rotator`/`Box`/…) but none for `Transform`.
//!
//! The binary layout decoded here **is** real — it's how
//! `FTransform` appears in *native-serialized arrays* (skeletal-mesh
//! bone poses, instanced-static-mesh transform buffers), matching
//! CUE4Parse's `new FTransform(Ar)` constructor. Phase 3g/3h read
//! those via [`FTransform::read_from`] directly, which is why this
//! decoder ships now as a building block (and as the
//! [`super::TypedStructValue::Transform`] variant 3g/3h can emit) even
//! though nothing registers it.

use std::io::{Read, Seek};

use crate::asset::AssetContext;
use crate::asset::structs::quat::FQuat;
use crate::asset::structs::vector::FVector;
use crate::asset::structs::{stream_pos, verify_at_end};

/// Rigid-body transform with non-uniform scale: a rotation
/// quaternion, a translation vector, and a per-axis scale vector.
///
/// UE4 = 40 bytes (f32 components), UE5 LWC = 80 bytes (f64
/// components). The identity transform is
/// `rotation = (0, 0, 0, 1)`, `translation = (0, 0, 0)`,
/// `scale_3d = (1, 1, 1)`.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct FTransform {
    /// Rotation quaternion (wire position 0).
    pub rotation: FQuat,
    /// Translation / position (wire position 1).
    pub translation: FVector,
    /// Per-axis scale (wire position 2). UE's field is `Scale3D`.
    pub scale_3d: FVector,
}

impl FTransform {
    /// Decode an `FTransform` from `reader`. Reads `rotation: FQuat`,
    /// `translation: FVector`, then `scale_3d: FVector` in that wire
    /// order. Each nested read is bounded to its own `expected_end`
    /// (the transform's start offset plus the running per-component
    /// width), so a short nested read surfaces as that child's
    /// `TypedStructComponent` error (FQuat / FVector), not FTransform.
    ///
    /// # Errors
    /// - Any error from the nested [`FQuat::read_from`] /
    ///   [`FVector::read_from`] reads (each owns its own
    ///   `TypedStructComponent` EOF tag).
    /// - [`crate::error::AssetParseFault::TypedStructTrailingBytes`] /
    ///   [`crate::error::AssetParseFault::TypedStructOverrun`] if the
    ///   post-decode stream position doesn't match `expected_end`.
    pub fn read_from<R: Read + Seek + ?Sized>(
        reader: &mut R,
        ctx: &AssetContext,
        expected_end: u64,
        asset_path: &str,
    ) -> crate::Result<Self> {
        let quat_size = FQuat::wire_size(ctx);
        let vec_size = FVector::wire_size(ctx);
        let start = stream_pos(reader, asset_path)?;
        let rotation = FQuat::read_from(reader, ctx, start + quat_size, asset_path)?;
        let translation =
            FVector::read_from(reader, ctx, start + quat_size + vec_size, asset_path)?;
        let scale_3d =
            FVector::read_from(reader, ctx, start + quat_size + 2 * vec_size, asset_path)?;
        verify_at_end(reader, expected_end, "FTransform", asset_path)?;
        Ok(Self {
            rotation,
            translation,
            scale_3d,
        })
    }
}

// NOTE: no `read_ftransform` registry shim. Every other decoder module
// ships a `read_f*` shim *because the registry needs a `DecoderFn`-shaped
// entry point* — `FTransform` is deliberately unregistered (see module
// docs), so a shim would be permanently dead code. Phase 3g/3h build the
// `TypedStructValue::Transform` variant by calling `FTransform::read_from`
// and wrapping the result inline.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PaksmithError;
    use crate::asset::property::test_utils::make_ctx_with_version;
    use crate::asset::structs::test_utils::{f32_bytes, f64_bytes};
    use crate::error::{AssetParseFault, AssetWireField};
    use std::io::Cursor;

    /// Build a UE4 `FTransform` wire payload: quat f32×4, translation
    /// f32×3, scale f32×3.
    fn ftransform_ue4_bytes(rot: [f32; 4], trans: [f32; 3], scale: [f32; 3]) -> Vec<u8> {
        let mut bytes = f32_bytes(&rot);
        bytes.extend(f32_bytes(&trans));
        bytes.extend(f32_bytes(&scale));
        bytes
    }

    #[test]
    fn ue4_ftransform_decodes_40_bytes() {
        // Identity rotation, distinct translation/scale so the field
        // order (rotation, translation, scale_3d) is pinned: a swap
        // would surface as translation/scale mismatch.
        let bytes = ftransform_ue4_bytes([0.0, 0.0, 0.0, 1.0], [1.0, 2.0, 3.0], [4.0, 5.0, 6.0]);
        assert_eq!(bytes.len(), 40);
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(bytes.as_slice());
        let t = FTransform::read_from(&mut cur, &ctx, 40, "test.uasset").expect("read");
        assert!((t.rotation.w - 1.0).abs() < f64::EPSILON);
        assert!(t.rotation.x.abs() < f64::EPSILON);
        assert!((t.translation.x - 1.0).abs() < f64::EPSILON);
        assert!((t.translation.z - 3.0).abs() < f64::EPSILON);
        assert!((t.scale_3d.x - 4.0).abs() < f64::EPSILON);
        assert!((t.scale_3d.z - 6.0).abs() < f64::EPSILON);
    }

    #[test]
    fn ue5_lwc_ftransform_decodes_80_bytes() {
        // UE5 LWC gate at 1004 — all three nested types widen to f64.
        let mut bytes = f64_bytes(&[0.0, 0.0, 0.0, 1.0]);
        bytes.extend(f64_bytes(&[1.0, 2.0, 3.0]));
        bytes.extend(f64_bytes(&[4.0, 5.0, 6.0]));
        assert_eq!(bytes.len(), 80);
        let ctx = make_ctx_with_version(510, Some(1004));
        let mut cur = Cursor::new(bytes.as_slice());
        let t = FTransform::read_from(&mut cur, &ctx, 80, "test.uasset").expect("read");
        assert!((t.rotation.w - 1.0).abs() < f64::EPSILON);
        assert!((t.translation.y - 2.0).abs() < f64::EPSILON);
        assert!((t.scale_3d.y - 5.0).abs() < f64::EPSILON);
    }

    #[test]
    fn ftransform_eof_in_nested_rotation_routes_to_fquat() {
        // 12 bytes — the rotation FQuat (needs 16) hits EOF mid-read.
        // The nested FQuat::read_from owns this error, so it surfaces
        // as TypedStructComponent(FQuat), NOT FTransform.
        let bytes = f32_bytes(&[0.0, 0.0, 0.0]);
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(bytes.as_slice());
        let err = FTransform::read_from(&mut cur, &ctx, 40, "test.uasset").unwrap_err();
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
            "expected nested UnexpectedEof(TypedStructComponent(FQuat)), got {err:?}"
        );
    }

    #[test]
    fn ftransform_eof_in_nested_translation_routes_to_fvector() {
        // 20 bytes — rotation (16) present, but the translation
        // FVector (needs 12) hits EOF after 4 bytes. Routes to the
        // nested FVector, NOT FTransform.
        let mut bytes = f32_bytes(&[0.0, 0.0, 0.0, 1.0]);
        bytes.extend(f32_bytes(&[1.0]));
        assert_eq!(bytes.len(), 20);
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(bytes.as_slice());
        let err = FTransform::read_from(&mut cur, &ctx, 40, "test.uasset").unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::UnexpectedEof {
                        field: AssetWireField::TypedStructComponent {
                            struct_name: "FVector"
                        },
                    },
                    ..
                }
            ),
            "expected nested UnexpectedEof(TypedStructComponent(FVector)), got {err:?}"
        );
    }

    #[test]
    fn ftransform_eof_in_nested_scale_routes_to_fvector() {
        // 28 bytes — rotation (16) + translation (12) present, but the
        // scale_3d FVector hits EOF immediately. Still routes to the
        // nested FVector (the third read), NOT FTransform — distinct
        // from the translation case by byte length.
        let mut bytes = f32_bytes(&[0.0, 0.0, 0.0, 1.0]);
        bytes.extend(f32_bytes(&[1.0, 2.0, 3.0]));
        assert_eq!(bytes.len(), 28);
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(bytes.as_slice());
        let err = FTransform::read_from(&mut cur, &ctx, 40, "test.uasset").unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::UnexpectedEof {
                        field: AssetWireField::TypedStructComponent {
                            struct_name: "FVector"
                        },
                    },
                    ..
                }
            ),
            "expected nested UnexpectedEof(TypedStructComponent(FVector)), got {err:?}"
        );
    }

    #[test]
    fn ftransform_trailing_bytes_rejected() {
        let mut bytes =
            ftransform_ue4_bytes([0.0, 0.0, 0.0, 1.0], [1.0, 2.0, 3.0], [1.0, 1.0, 1.0]);
        bytes.extend_from_slice(&[0u8; 4]);
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(bytes.as_slice());
        let err = FTransform::read_from(&mut cur, &ctx, 44, "test.uasset").unwrap_err();
        match err {
            PaksmithError::AssetParse {
                fault:
                    AssetParseFault::TypedStructTrailingBytes {
                        struct_name,
                        trailing,
                    },
                ..
            } => {
                assert_eq!(struct_name, "FTransform");
                assert_eq!(trailing, 4u64);
            }
            other => panic!("expected TypedStructTrailingBytes(FTransform), got {other:?}"),
        }
    }

    #[test]
    fn ftransform_overrun_rejected() {
        // 40 wire bytes but expected_end = 36 (mid-scale). The
        // FTransform consumes its full 40 bytes; verify_at_end sees
        // the 4-byte overrun.
        let bytes = ftransform_ue4_bytes([0.0, 0.0, 0.0, 1.0], [1.0, 2.0, 3.0], [1.0, 1.0, 1.0]);
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(bytes.as_slice());
        let err = FTransform::read_from(&mut cur, &ctx, 36, "test.uasset").unwrap_err();
        match err {
            PaksmithError::AssetParse {
                fault:
                    AssetParseFault::TypedStructOverrun {
                        struct_name,
                        overrun,
                    },
                ..
            } => {
                assert_eq!(struct_name, "FTransform");
                assert_eq!(overrun, 4u64);
            }
            other => panic!("expected TypedStructOverrun(FTransform), got {other:?}"),
        }
    }
}
