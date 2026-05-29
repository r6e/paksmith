//! `FBox` + `FBox2D` decoders — axis-aligned bounding boxes.
//!
//! Wire-format reference: CUE4Parse `FBox.cs` / `FBox2D.cs` at
//! `cf74fc32fe1b40e9fd3440032508c5e1d50cf58d`.
//!
//! Both compose nested vector-family decoders:
//! - `FBox` = `min: FVector` + `max: FVector` + `is_valid: u8`.
//!   UE4 = 12 + 12 + 1 = 25 bytes; UE5 LWC = 24 + 24 + 1 = 49.
//! - `FBox2D` = `min: FVector2D` + `max: FVector2D` + `is_valid: u8`.
//!   UE4 = 8 + 8 + 1 = 17 bytes; UE5 LWC = 16 + 16 + 1 = 33.
//!
//! The nested vector reads delegate to
//! [`FVector::read_from`](super::vector::FVector::read_from) /
//! [`FVector2D::read_from`](super::vector::FVector2D::read_from),
//! each bounded to its own `expected_end` (computed from the box's
//! start offset + the LWC-dependent per-vector width). This keeps
//! the FVector wire shape a single source of truth — 3g/3h consume
//! the same `min`/`max` vectors directly.

use std::io::{Read, Seek};

use crate::asset::AssetContext;
use crate::asset::structs::vector::{FVector, FVector2D};
use crate::asset::structs::{TypedStructValue, read_bool_u8, stream_pos, verify_at_end};

/// Axis-aligned 3D bounding box: `min` + `max` corners + an
/// `is_valid` flag. UE4 = 25 bytes (f32 vectors), UE5 LWC = 49
/// bytes (f64 vectors).
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct FBox {
    /// Minimum corner.
    pub min: FVector,
    /// Maximum corner.
    pub max: FVector,
    /// Whether the box has been initialized to a meaningful extent
    /// (UE's `FBox::IsValid`). Wire is a `u8`; any non-zero byte is
    /// `true`.
    pub is_valid: bool,
}

impl FBox {
    /// Decode an `FBox` from `reader`. Reads `min: FVector`,
    /// `max: FVector`, then a trailing `u8` `is_valid` flag. The
    /// two nested `FVector` reads are each bounded to their own
    /// `expected_end` (start + per-vector width).
    ///
    /// # Errors
    /// - Any error from the nested [`FVector::read_from`] reads.
    /// - [`crate::error::AssetParseFault::UnexpectedEof`] with
    ///   `field = TypedStructComponent { struct_name: "FBox" }`
    ///   if the trailing `is_valid` byte read hits EOF.
    /// - Trailing-bytes / overrun faults per `verify_at_end`.
    pub fn read_from<R: Read + Seek + ?Sized>(
        reader: &mut R,
        ctx: &AssetContext,
        expected_end: u64,
        asset_path: &str,
    ) -> crate::Result<Self> {
        let vec_size = FVector::wire_size(ctx);
        let start = stream_pos(reader, asset_path)?;
        let min = FVector::read_from(reader, ctx, start + vec_size, asset_path)?;
        let max = FVector::read_from(reader, ctx, start + 2 * vec_size, asset_path)?;
        let is_valid = read_bool_u8(reader, "FBox", asset_path)?;
        verify_at_end(reader, expected_end, "FBox", asset_path)?;
        Ok(Self { min, max, is_valid })
    }
}

/// Axis-aligned 2D bounding box (UV-space): `min` + `max` corners +
/// an `is_valid` flag. UE4 = 17 bytes (f32 vectors), UE5 LWC = 33
/// bytes (f64 vectors).
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct FBox2D {
    /// Minimum corner.
    pub min: FVector2D,
    /// Maximum corner.
    pub max: FVector2D,
    /// Whether the box has been initialized. Wire is a `u8`; any
    /// non-zero byte is `true`.
    pub is_valid: bool,
}

impl FBox2D {
    /// Decode an `FBox2D` from `reader`. Reads `min: FVector2D`,
    /// `max: FVector2D`, then a trailing `u8` `is_valid` flag.
    ///
    /// # Errors
    /// - Any error from the nested [`FVector2D::read_from`] reads.
    /// - [`crate::error::AssetParseFault::UnexpectedEof`] with
    ///   `field = TypedStructComponent { struct_name: "FBox2D" }`
    ///   if the trailing `is_valid` byte read hits EOF.
    /// - Trailing-bytes / overrun faults per `verify_at_end`.
    pub fn read_from<R: Read + Seek + ?Sized>(
        reader: &mut R,
        ctx: &AssetContext,
        expected_end: u64,
        asset_path: &str,
    ) -> crate::Result<Self> {
        let vec_size = FVector2D::wire_size(ctx);
        let start = stream_pos(reader, asset_path)?;
        let min = FVector2D::read_from(reader, ctx, start + vec_size, asset_path)?;
        let max = FVector2D::read_from(reader, ctx, start + 2 * vec_size, asset_path)?;
        let is_valid = read_bool_u8(reader, "FBox2D", asset_path)?;
        verify_at_end(reader, expected_end, "FBox2D", asset_path)?;
        Ok(Self { min, max, is_valid })
    }
}

/// Registry-compatible decoder shim for [`FBox`].
pub(crate) fn read_fbox(
    reader: &mut dyn crate::asset::structs::ReadAndSeek,
    ctx: &AssetContext,
    expected_end: u64,
    asset_path: &str,
) -> crate::Result<TypedStructValue> {
    let b = FBox::read_from(reader, ctx, expected_end, asset_path)?;
    Ok(TypedStructValue::Box(b))
}

/// Registry-compatible decoder shim for [`FBox2D`].
pub(crate) fn read_fbox2d(
    reader: &mut dyn crate::asset::structs::ReadAndSeek,
    ctx: &AssetContext,
    expected_end: u64,
    asset_path: &str,
) -> crate::Result<TypedStructValue> {
    let b = FBox2D::read_from(reader, ctx, expected_end, asset_path)?;
    Ok(TypedStructValue::Box2D(b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PaksmithError;
    use crate::asset::property::test_utils::make_ctx_with_version;
    use crate::asset::structs::test_utils::{f32_bytes, f64_bytes};
    use crate::error::{AssetParseFault, AssetWireField};
    use std::io::Cursor;

    /// Build a UE4 `FBox` wire payload: min f32×3, max f32×3, u8.
    fn fbox_ue4_bytes(min: [f32; 3], max: [f32; 3], is_valid: u8) -> Vec<u8> {
        let mut bytes = f32_bytes(&min);
        bytes.extend(f32_bytes(&max));
        bytes.push(is_valid);
        bytes
    }

    /// Build a UE4 `FBox2D` wire payload: min f32×2, max f32×2, u8.
    fn fbox2d_ue4_bytes(min: [f32; 2], max: [f32; 2], is_valid: u8) -> Vec<u8> {
        let mut bytes = f32_bytes(&min);
        bytes.extend(f32_bytes(&max));
        bytes.push(is_valid);
        bytes
    }

    #[test]
    fn ue4_fbox_decodes_25_bytes() {
        let bytes = fbox_ue4_bytes([-1.0, -2.0, -3.0], [1.0, 2.0, 3.0], 1);
        assert_eq!(bytes.len(), 25);
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(bytes.as_slice());
        let b = FBox::read_from(&mut cur, &ctx, 25, "test.uasset").expect("read");
        assert!((b.min.x - -1.0).abs() < f64::EPSILON);
        assert!((b.min.z - -3.0).abs() < f64::EPSILON);
        assert!((b.max.x - 1.0).abs() < f64::EPSILON);
        assert!((b.max.z - 3.0).abs() < f64::EPSILON);
        assert!(b.is_valid);
    }

    #[test]
    fn ue5_lwc_fbox_decodes_49_bytes() {
        let mut bytes = f64_bytes(&[-1.0, -2.0, -3.0]);
        bytes.extend(f64_bytes(&[1.0, 2.0, 3.0]));
        bytes.push(0); // is_valid = false
        assert_eq!(bytes.len(), 49);
        let ctx = make_ctx_with_version(510, Some(1004));
        let mut cur = Cursor::new(bytes.as_slice());
        let b = FBox::read_from(&mut cur, &ctx, 49, "test.uasset").expect("read");
        assert!((b.min.y - -2.0).abs() < f64::EPSILON);
        assert!((b.max.y - 2.0).abs() < f64::EPSILON);
        assert!(!b.is_valid);
    }

    #[test]
    fn fbox_is_valid_nonzero_byte_is_true() {
        // Any non-zero is_valid byte decodes as `true` (UE's
        // permissive bool convention), not just 0x01.
        let bytes = fbox_ue4_bytes([0.0, 0.0, 0.0], [0.0, 0.0, 0.0], 0xFF);
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(bytes.as_slice());
        let b = FBox::read_from(&mut cur, &ctx, 25, "test.uasset").expect("read");
        assert!(b.is_valid);
    }

    #[test]
    fn fbox_eof_on_trailing_is_valid_rejected() {
        // 24 bytes — both FVectors present (UE4), but the trailing
        // is_valid u8 hits EOF. Routes to TypedStructComponent(FBox).
        let mut bytes = f32_bytes(&[1.0, 2.0, 3.0]);
        bytes.extend(f32_bytes(&[4.0, 5.0, 6.0]));
        assert_eq!(bytes.len(), 24);
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(bytes.as_slice());
        let err = FBox::read_from(&mut cur, &ctx, 25, "test.uasset").unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::UnexpectedEof {
                        field: AssetWireField::TypedStructComponent {
                            struct_name: "FBox"
                        },
                    },
                    ..
                }
            ),
            "expected UnexpectedEof(TypedStructComponent(FBox)), got {err:?}"
        );
    }

    #[test]
    fn fbox_eof_in_nested_max_vector_routes_to_fvector() {
        // 12 bytes — only the min FVector present; the max FVector
        // read hits EOF mid-decode. The nested FVector::read_from
        // owns this error, so it surfaces as
        // TypedStructComponent(FVector), NOT FBox.
        let bytes = f32_bytes(&[1.0, 2.0, 3.0]);
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(bytes.as_slice());
        let err = FBox::read_from(&mut cur, &ctx, 25, "test.uasset").unwrap_err();
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
    fn fbox_trailing_bytes_rejected() {
        let mut bytes = fbox_ue4_bytes([1.0, 2.0, 3.0], [4.0, 5.0, 6.0], 1);
        bytes.extend_from_slice(&[0u8; 3]);
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(bytes.as_slice());
        let err = FBox::read_from(&mut cur, &ctx, 28, "test.uasset").unwrap_err();
        match err {
            PaksmithError::AssetParse {
                fault:
                    AssetParseFault::TypedStructTrailingBytes {
                        struct_name,
                        trailing,
                    },
                ..
            } => {
                assert_eq!(struct_name, "FBox");
                assert_eq!(trailing, 3u64);
            }
            other => panic!("expected TypedStructTrailingBytes(FBox), got {other:?}"),
        }
    }

    #[test]
    fn read_fbox_shim_returns_typed_struct_box() {
        let bytes = fbox_ue4_bytes([1.0, 2.0, 3.0], [4.0, 5.0, 6.0], 1);
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(bytes.as_slice());
        let value = read_fbox(&mut cur, &ctx, 25, "test.uasset").expect("read");
        match value {
            TypedStructValue::Box(b) => {
                assert!((b.min.x - 1.0).abs() < f64::EPSILON);
                assert!((b.max.z - 6.0).abs() < f64::EPSILON);
                assert!(b.is_valid);
            }
            other => panic!("expected TypedStructValue::Box, got {other:?}"),
        }
    }

    #[test]
    fn ue4_fbox2d_decodes_17_bytes() {
        let bytes = fbox2d_ue4_bytes([-1.0, -2.0], [1.0, 2.0], 1);
        assert_eq!(bytes.len(), 17);
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(bytes.as_slice());
        let b = FBox2D::read_from(&mut cur, &ctx, 17, "test.uasset").expect("read");
        assert!((b.min.x - -1.0).abs() < f64::EPSILON);
        assert!((b.max.y - 2.0).abs() < f64::EPSILON);
        assert!(b.is_valid);
    }

    #[test]
    fn ue5_lwc_fbox2d_decodes_33_bytes() {
        let mut bytes = f64_bytes(&[-1.0, -2.0]);
        bytes.extend(f64_bytes(&[1.0, 2.0]));
        bytes.push(0);
        assert_eq!(bytes.len(), 33);
        let ctx = make_ctx_with_version(510, Some(1004));
        let mut cur = Cursor::new(bytes.as_slice());
        let b = FBox2D::read_from(&mut cur, &ctx, 33, "test.uasset").expect("read");
        assert!((b.min.y - -2.0).abs() < f64::EPSILON);
        assert!(!b.is_valid);
    }

    #[test]
    fn fbox2d_eof_in_nested_max_vector_routes_to_fvector2d() {
        // 8 bytes — only the min FVector2D present; the max read
        // hits EOF mid-decode. The nested FVector2D::read_from owns
        // this error, so it surfaces as TypedStructComponent(FVector2D),
        // NOT FBox2D. Mirrors `fbox_eof_in_nested_max_vector_routes_to_fvector`.
        let bytes = f32_bytes(&[1.0, 2.0]);
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(bytes.as_slice());
        let err = FBox2D::read_from(&mut cur, &ctx, 17, "test.uasset").unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::UnexpectedEof {
                        field: AssetWireField::TypedStructComponent {
                            struct_name: "FVector2D"
                        },
                    },
                    ..
                }
            ),
            "expected nested UnexpectedEof(TypedStructComponent(FVector2D)), got {err:?}"
        );
    }

    #[test]
    fn fbox2d_overrun_rejected() {
        // 17 wire bytes but expected_end = 13 (mid-max-vector). The
        // FBox2D consumes its full 17 bytes; verify_at_end sees the
        // overrun.
        let bytes = fbox2d_ue4_bytes([1.0, 2.0], [3.0, 4.0], 1);
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(bytes.as_slice());
        let err = FBox2D::read_from(&mut cur, &ctx, 13, "test.uasset").unwrap_err();
        match err {
            PaksmithError::AssetParse {
                fault:
                    AssetParseFault::TypedStructOverrun {
                        struct_name,
                        overrun,
                    },
                ..
            } => {
                assert_eq!(struct_name, "FBox2D");
                assert_eq!(overrun, 4u64);
            }
            other => panic!("expected TypedStructOverrun(FBox2D), got {other:?}"),
        }
    }

    #[test]
    fn read_fbox2d_shim_returns_typed_struct_box2d() {
        let bytes = fbox2d_ue4_bytes([1.0, 2.0], [3.0, 4.0], 1);
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(bytes.as_slice());
        let value = read_fbox2d(&mut cur, &ctx, 17, "test.uasset").expect("read");
        match value {
            TypedStructValue::Box2D(b) => {
                assert!((b.min.x - 1.0).abs() < f64::EPSILON);
                assert!((b.max.y - 4.0).abs() < f64::EPSILON);
                assert!(b.is_valid);
            }
            other => panic!("expected TypedStructValue::Box2D, got {other:?}"),
        }
    }
}
