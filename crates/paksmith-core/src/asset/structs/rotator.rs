//! `FRotator` decoder — UE4 = 3 × f32 (12 bytes); UE5 LWC = 3 × f64
//! (24 bytes).
//!
//! Wire-format reference: CUE4Parse `FRotator.cs` at
//! `cf74fc32fe1b40e9fd3440032508c5e1d50cf58d`. **Wire order is
//! pitch, yaw, roll** — NOT roll-first or yaw-first, despite some
//! older UE docs / community references. Verified empirically
//! against CUE4Parse's `FRotator(FArchive Ar)` constructor.
//!
//! Components are stored as `f64` (UE4 f32 losslessly widened on
//! decode), matching [`super::vector::FVector`].

use std::io::{Read, Seek};

use crate::asset::AssetContext;
use crate::asset::structs::{TypedStructValue, read_components, verify_at_end};

/// Euler-angle rotation (degrees). Wire order: `pitch`, `yaw`,
/// `roll`. UE4 = f32×3 (12 bytes); UE5 LWC = f64×3 (24 bytes).
///
/// **Pitch first, NOT roll** — community documentation occasionally
/// claims roll-first; the wire format and CUE4Parse both put pitch
/// first.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct FRotator {
    /// Pitch component (degrees) — wire position 0.
    pub pitch: f64,
    /// Yaw component (degrees) — wire position 1.
    pub yaw: f64,
    /// Roll component (degrees) — wire position 2.
    pub roll: f64,
}

impl FRotator {
    /// Decode an `FRotator` from `reader`. Component width per
    /// `ctx.version.is_lwc()` — same dispatch as
    /// [`super::vector::FVector`].
    ///
    /// # Errors
    /// - [`crate::error::AssetParseFault::UnexpectedEof`] with
    ///   `field = TypedStructComponent { struct_name: "FRotator" }`
    ///   if any component read hits EOF.
    /// - Trailing-bytes / overrun faults per `verify_at_end`.
    pub fn read_from<R: Read + Seek + ?Sized>(
        reader: &mut R,
        ctx: &AssetContext,
        expected_end: u64,
        asset_path: &str,
    ) -> crate::Result<Self> {
        let [pitch, yaw, roll] = read_components::<R, 3>(reader, ctx, "FRotator", asset_path)?;
        verify_at_end(reader, expected_end, "FRotator", asset_path)?;
        Ok(Self { pitch, yaw, roll })
    }

    /// Wire byte size of an `FRotator` under `ctx`'s LWC width:
    /// 12 (UE4 f32×3) or 24 (UE5 LWC f64×3). Used by the unversioned
    /// typed-struct dispatch to bound the natural-width read (#640).
    #[must_use]
    pub(crate) fn wire_size(ctx: &AssetContext) -> u64 {
        3 * crate::asset::structs::lwc_component_width(ctx)
    }
}

/// Registry-compatible decoder shim. The function pointer stored
/// in `structs::registry()` takes `&mut dyn Read+Seek` instead of
/// a generic `R: Read+Seek` (function pointers can't be generic).
pub(crate) fn read_frotator(
    reader: &mut dyn crate::asset::structs::ReadAndSeek,
    ctx: &AssetContext,
    expected_end: u64,
    asset_path: &str,
) -> crate::Result<TypedStructValue> {
    let r = FRotator::read_from(reader, ctx, expected_end, asset_path)?;
    Ok(TypedStructValue::Rotator(r))
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
    fn frotator_wire_size_matches_lwc_width() {
        assert_eq!(FRotator::wire_size(&make_ctx_with_version(510, None)), 12);
        assert_eq!(
            FRotator::wire_size(&make_ctx_with_version(510, Some(1004))),
            24
        );
    }

    #[test]
    fn ue4_rotator_decodes_12_bytes() {
        // Wire order pin: (pitch=10, yaw=20, roll=30). The
        // assertion checks field NAMES, so a swap (e.g. roll-first)
        // would surface as a value mismatch on every field.
        let bytes = f32_bytes(&[10.0, 20.0, 30.0]);
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(bytes.as_slice());
        let r = FRotator::read_from(&mut cur, &ctx, 12, "test.uasset").expect("read");
        assert!((r.pitch - 10.0).abs() < f64::EPSILON);
        assert!((r.yaw - 20.0).abs() < f64::EPSILON);
        assert!((r.roll - 30.0).abs() < f64::EPSILON);
    }

    #[test]
    fn ue5_lwc_rotator_decodes_24_bytes() {
        // UE5 LWC gate at 1004 — same boundary as FVector.
        let bytes = f64_bytes(&[45.5, 90.5, 180.5]);
        let ctx = make_ctx_with_version(510, Some(1004));
        let mut cur = Cursor::new(bytes.as_slice());
        let r = FRotator::read_from(&mut cur, &ctx, 24, "test.uasset").expect("read");
        assert!((r.pitch - 45.5).abs() < f64::EPSILON);
        assert!((r.yaw - 90.5).abs() < f64::EPSILON);
        assert!((r.roll - 180.5).abs() < f64::EPSILON);
    }

    #[test]
    fn pre_lwc_ue5_rotator_uses_f32_width() {
        // UE5 below the LWC gate (1003) — still f32 width.
        // Pins the `>=` boundary at 1004 vs 1003 for FRotator.
        let bytes = f32_bytes(&[10.0, 20.0, 30.0]);
        let ctx = make_ctx_with_version(510, Some(1003));
        let mut cur = Cursor::new(bytes.as_slice());
        let r = FRotator::read_from(&mut cur, &ctx, 12, "test.uasset").expect("read");
        assert!((r.pitch - 10.0).abs() < f64::EPSILON);
        assert!((r.roll - 30.0).abs() < f64::EPSILON);
    }

    #[test]
    fn rotator_eof_during_decode_rejected() {
        // 8 bytes — enough for pitch and yaw as f32, but roll hits EOF.
        // Pins the TypedStructComponent { struct_name: "FRotator" }
        // field routing.
        let bytes = f32_bytes(&[10.0, 20.0]);
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(bytes.as_slice());
        let err = FRotator::read_from(&mut cur, &ctx, 12, "test.uasset").unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::UnexpectedEof {
                        field: AssetWireField::TypedStructComponent {
                            struct_name: "FRotator"
                        },
                    },
                    ..
                }
            ),
            "expected UnexpectedEof(TypedStructComponent(FRotator)), got {err:?}"
        );
    }

    #[test]
    fn rotator_trailing_bytes_rejected() {
        let mut bytes = f32_bytes(&[10.0, 20.0, 30.0]);
        bytes.extend_from_slice(&[0u8; 4]);
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(bytes.as_slice());
        let err = FRotator::read_from(&mut cur, &ctx, 16, "test.uasset").unwrap_err();
        match err {
            PaksmithError::AssetParse {
                fault:
                    AssetParseFault::TypedStructTrailingBytes {
                        struct_name,
                        trailing,
                    },
                ..
            } => {
                assert_eq!(struct_name, "FRotator");
                assert_eq!(trailing, 4u64);
            }
            other => panic!("expected TypedStructTrailingBytes(FRotator), got {other:?}"),
        }
    }

    #[test]
    fn rotator_overrun_rejected() {
        // 12 wire bytes (UE4 f32×3) but expected_end = 8. The
        // decoder consumes 12 bytes, leaving pos=12 > expected_end=8.
        let bytes = f32_bytes(&[10.0, 20.0, 30.0]);
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(bytes.as_slice());
        let err = FRotator::read_from(&mut cur, &ctx, 8, "test.uasset").unwrap_err();
        match err {
            PaksmithError::AssetParse {
                fault:
                    AssetParseFault::TypedStructOverrun {
                        struct_name,
                        overrun,
                    },
                ..
            } => {
                assert_eq!(struct_name, "FRotator");
                assert_eq!(overrun, 4u64);
            }
            other => panic!("expected TypedStructOverrun(FRotator), got {other:?}"),
        }
    }

    #[test]
    fn read_frotator_shim_returns_typed_struct_rotator() {
        let bytes = f32_bytes(&[1.0, 2.0, 3.0]);
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(bytes.as_slice());
        let value = read_frotator(&mut cur, &ctx, 12, "test.uasset").expect("read");
        match value {
            TypedStructValue::Rotator(r) => {
                assert!((r.pitch - 1.0).abs() < f64::EPSILON);
                assert!((r.yaw - 2.0).abs() < f64::EPSILON);
                assert!((r.roll - 3.0).abs() < f64::EPSILON);
            }
            other => panic!("expected TypedStructValue::Rotator, got {other:?}"),
        }
    }
}
