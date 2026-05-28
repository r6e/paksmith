//! `FVector` decoder — UE4 = 3 × f32 (12 bytes); UE5 LWC = 3 × f64
//! (24 bytes).
//!
//! Wire-format reference: CUE4Parse `FVector.cs` at
//! `cf74fc32fe1b40e9fd3440032508c5e1d50cf58d`. The
//! [`AssetVersion::is_lwc`](crate::asset::AssetVersion::is_lwc)
//! check matches CUE4Parse's `UE5.LargeWorldCoordinates` dispatch
//! on the same wire-version gate (1004).
//!
//! `FVector::x` / `y` / `z` are stored as `f64` in both UE4 and
//! UE5 LWC: pre-LWC `f32` values are losslessly widened on
//! decode, so downstream consumers (3g `StaticMesh`, 3h
//! `SkeletalMesh`) have one type to work with.

use std::io::{Read, Seek};

use byteorder::{LittleEndian, ReadBytesExt};

use crate::PaksmithError;
use crate::asset::AssetContext;
use crate::asset::structs::{TypedStructValue, verify_at_end};
use crate::error::{AssetParseFault, AssetWireField};

/// 3D vector. Decoded by [`FVector::read_from`] from the
/// `StructProperty` body of an `FVector`-typed property.
///
/// Components are always `f64` in the typed surface; UE4 wire
/// bytes (f32) are losslessly widened on decode so consumers
/// don't have to branch on width.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct FVector {
    /// X component.
    pub x: f64,
    /// Y component.
    pub y: f64,
    /// Z component.
    pub z: f64,
}

impl FVector {
    /// Decode an `FVector` from `reader`. Component width is f32
    /// (UE4, 4 bytes each) or f64 (UE5 LWC, 8 bytes each) per
    /// `ctx.version.is_lwc()`.
    ///
    /// `expected_end` is the absolute stream position the parent
    /// property's `tag.size` declared as the struct's payload
    /// boundary. The decoder verifies-at-end: trailing bytes
    /// produce [`AssetParseFault::TypedStructTrailingBytes`]
    /// (soft — version mismatch), overrun produces
    /// [`AssetParseFault::TypedStructOverrun`] (hard — corrupted
    /// property bounds).
    ///
    /// # Errors
    /// - [`AssetParseFault::UnexpectedEof`] with `field =
    ///   FVectorComponent` if any component read hits EOF.
    /// - [`AssetParseFault::TypedStructTrailingBytes`] /
    ///   [`AssetParseFault::TypedStructOverrun`] if the post-decode
    ///   stream position doesn't match `expected_end`.
    pub fn read_from<R: Read + Seek + ?Sized>(
        reader: &mut R,
        ctx: &AssetContext,
        expected_end: u64,
        asset_path: &str,
    ) -> crate::Result<Self> {
        let (x, y, z) = if ctx.version.is_lwc() {
            let x = read_f64(reader, asset_path)?;
            let y = read_f64(reader, asset_path)?;
            let z = read_f64(reader, asset_path)?;
            (x, y, z)
        } else {
            let x = f64::from(read_f32(reader, asset_path)?);
            let y = f64::from(read_f32(reader, asset_path)?);
            let z = f64::from(read_f32(reader, asset_path)?);
            (x, y, z)
        };
        verify_at_end(reader, expected_end, "FVector", asset_path)?;
        Ok(Self { x, y, z })
    }
}

/// Registry-compatible decoder shim. The function pointer stored
/// in `structs::registry()` takes `&mut dyn Read+Seek` instead of
/// a generic `R: Read+Seek` (function pointers can't be generic).
pub(crate) fn read_fvector(
    reader: &mut dyn crate::asset::structs::ReadAndSeek,
    ctx: &AssetContext,
    expected_end: u64,
    asset_path: &str,
) -> crate::Result<TypedStructValue> {
    let v = FVector::read_from(reader, ctx, expected_end, asset_path)?;
    Ok(TypedStructValue::Vector(v))
}

fn read_f32<R: Read + ?Sized>(reader: &mut R, asset_path: &str) -> crate::Result<f32> {
    reader
        .read_f32::<LittleEndian>()
        .map_err(|_| eof(asset_path))
}

fn read_f64<R: Read + ?Sized>(reader: &mut R, asset_path: &str) -> crate::Result<f64> {
    reader
        .read_f64::<LittleEndian>()
        .map_err(|_| eof(asset_path))
}

fn eof(asset_path: &str) -> PaksmithError {
    PaksmithError::AssetParse {
        asset_path: asset_path.to_string(),
        fault: AssetParseFault::UnexpectedEof {
            field: AssetWireField::FVectorComponent,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::property::test_utils::make_ctx_with_version;
    use std::io::Cursor;

    /// Build the 12-byte UE4 f32×3 wire-form for a 3-component
    /// vector. Compresses the per-test boilerplate.
    fn f32_bytes(x: f32, y: f32, z: f32) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(12);
        bytes.extend_from_slice(&x.to_le_bytes());
        bytes.extend_from_slice(&y.to_le_bytes());
        bytes.extend_from_slice(&z.to_le_bytes());
        bytes
    }

    /// Build the 24-byte UE5 LWC f64×3 wire-form.
    fn f64_bytes(x: f64, y: f64, z: f64) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(24);
        bytes.extend_from_slice(&x.to_le_bytes());
        bytes.extend_from_slice(&y.to_le_bytes());
        bytes.extend_from_slice(&z.to_le_bytes());
        bytes
    }

    #[test]
    fn ue4_vector_decodes_12_bytes() {
        let bytes = f32_bytes(1.5, 2.5, 3.5);
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(bytes.as_slice());
        let v = FVector::read_from(&mut cur, &ctx, 12, "test.uasset").expect("read");
        assert!((v.x - 1.5).abs() < f64::EPSILON);
        assert!((v.y - 2.5).abs() < f64::EPSILON);
        assert!((v.z - 3.5).abs() < f64::EPSILON);
    }

    #[test]
    fn ue5_lwc_vector_decodes_24_bytes() {
        // UE5 LWC gate is at 1004; use 1004 exactly to pin the
        // boundary against any future `>=` vs `>` mutation.
        let bytes = f64_bytes(1.5, 2.5, 3.5);
        let ctx = make_ctx_with_version(510, Some(1004));
        let mut cur = Cursor::new(bytes.as_slice());
        let v = FVector::read_from(&mut cur, &ctx, 24, "test.uasset").expect("read");
        assert!((v.x - 1.5).abs() < f64::EPSILON);
        assert!((v.y - 2.5).abs() < f64::EPSILON);
        assert!((v.z - 3.5).abs() < f64::EPSILON);
    }

    #[test]
    fn pre_lwc_ue5_uses_f32_width() {
        // UE5 below the LWC gate (1003) — still f32 width.
        // Pins the `>=` boundary at 1004 vs 1003.
        let bytes = f32_bytes(1.5, 2.5, 3.5);
        let ctx = make_ctx_with_version(510, Some(1003));
        let mut cur = Cursor::new(bytes.as_slice());
        let v = FVector::read_from(&mut cur, &ctx, 12, "test.uasset").expect("read");
        assert!((v.x - 1.5).abs() < f64::EPSILON);
    }

    #[test]
    fn vector_trailing_bytes_rejected() {
        // 12 wire bytes (UE4 f32×3) + 4 trailing — expected_end = 16.
        // The 4 trailing bytes surface as TypedStructTrailingBytes.
        let mut bytes = f32_bytes(1.5, 2.5, 3.5);
        bytes.extend_from_slice(&[0u8; 4]);
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(bytes.as_slice());
        let err = FVector::read_from(&mut cur, &ctx, 16, "test.uasset").unwrap_err();
        match err {
            PaksmithError::AssetParse {
                fault:
                    AssetParseFault::TypedStructTrailingBytes {
                        struct_name,
                        trailing,
                    },
                ..
            } => {
                assert_eq!(struct_name, "FVector");
                assert_eq!(trailing, 4u64);
            }
            other => panic!("expected TypedStructTrailingBytes, got {other:?}"),
        }
    }

    #[test]
    fn vector_overrun_rejected() {
        // 12 wire bytes (UE4 f32×3) but expected_end = 8. The
        // decoder consumes 12 bytes, leaving pos=12 > expected_end=8.
        // Pins the `Ordering::Greater` branch of `verify_at_end`
        // against the `trailing` arm (Less) and the happy path (Equal).
        let bytes = f32_bytes(1.5, 2.5, 3.5);
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(bytes.as_slice());
        let err = FVector::read_from(&mut cur, &ctx, 8, "test.uasset").unwrap_err();
        match err {
            PaksmithError::AssetParse {
                fault:
                    AssetParseFault::TypedStructOverrun {
                        struct_name,
                        overrun,
                    },
                ..
            } => {
                assert_eq!(struct_name, "FVector");
                assert_eq!(overrun, 4u64);
            }
            other => panic!("expected TypedStructOverrun, got {other:?}"),
        }
    }

    #[test]
    fn vector_eof_during_decode_rejected() {
        // 8 bytes — enough for x and y as f32, but z hits EOF.
        let mut bytes = Vec::with_capacity(8);
        bytes.extend_from_slice(&1.5f32.to_le_bytes());
        bytes.extend_from_slice(&2.5f32.to_le_bytes());
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(bytes.as_slice());
        let err = FVector::read_from(&mut cur, &ctx, 12, "test.uasset").unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::UnexpectedEof {
                        field: AssetWireField::FVectorComponent,
                    },
                    ..
                }
            ),
            "expected UnexpectedEof(FVectorComponent), got {err:?}"
        );
    }

    #[test]
    fn read_fvector_shim_returns_typed_struct_vector() {
        // Registry shim — `read_fvector` wraps the decoded
        // FVector into `TypedStructValue::Vector`. Pin the
        // wrapping behavior so a future refactor doesn't
        // silently re-route through a sibling variant.
        let bytes = f32_bytes(7.0, 8.0, 9.0);
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(bytes.as_slice());
        let value = read_fvector(&mut cur, &ctx, 12, "test.uasset").expect("read");
        match value {
            TypedStructValue::Vector(v) => {
                assert!((v.x - 7.0).abs() < f64::EPSILON);
                assert!((v.y - 8.0).abs() < f64::EPSILON);
                assert!((v.z - 9.0).abs() < f64::EPSILON);
            }
        }
    }
}
