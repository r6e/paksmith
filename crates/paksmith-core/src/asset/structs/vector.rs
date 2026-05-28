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
        let [x, y, z] =
            read_lwc_components::<R, 3>(reader, ctx, AssetWireField::FVectorComponent, asset_path)?;
        verify_at_end(reader, expected_end, "FVector", asset_path)?;
        Ok(Self { x, y, z })
    }
}

/// 2D vector. UE4 = f32×2 (8 bytes); UE5 LWC = f64×2 (16 bytes).
/// Used for UVs, screen positions. Components always stored as
/// `f64` (UE4 widened on decode), mirroring [`FVector`].
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct FVector2D {
    /// X component.
    pub x: f64,
    /// Y component.
    pub y: f64,
}

impl FVector2D {
    /// Decode an `FVector2D` from `reader`. Component width per
    /// `ctx.version.is_lwc()` — same dispatch as [`FVector`].
    ///
    /// # Errors
    /// - [`AssetParseFault::UnexpectedEof`] with `field =
    ///   FVector2DComponent` if any component read hits EOF.
    /// - Trailing-bytes / overrun faults per `verify_at_end`.
    pub fn read_from<R: Read + Seek + ?Sized>(
        reader: &mut R,
        ctx: &AssetContext,
        expected_end: u64,
        asset_path: &str,
    ) -> crate::Result<Self> {
        let [x, y] = read_lwc_components::<R, 2>(
            reader,
            ctx,
            AssetWireField::FVector2DComponent,
            asset_path,
        )?;
        verify_at_end(reader, expected_end, "FVector2D", asset_path)?;
        Ok(Self { x, y })
    }
}

/// 4D vector. UE4 = f32×4 (16 bytes); UE5 LWC = f64×4 (32 bytes).
/// Used for tangents, colors-as-vec4. Components always stored as
/// `f64`, mirroring [`FVector`].
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct FVector4 {
    /// X component.
    pub x: f64,
    /// Y component.
    pub y: f64,
    /// Z component.
    pub z: f64,
    /// W component.
    pub w: f64,
}

impl FVector4 {
    /// Decode an `FVector4` from `reader`. Component width per
    /// `ctx.version.is_lwc()` — same dispatch as [`FVector`].
    ///
    /// # Errors
    /// - [`AssetParseFault::UnexpectedEof`] with `field =
    ///   FVector4Component` if any component read hits EOF.
    /// - Trailing-bytes / overrun faults per `verify_at_end`.
    pub fn read_from<R: Read + Seek + ?Sized>(
        reader: &mut R,
        ctx: &AssetContext,
        expected_end: u64,
        asset_path: &str,
    ) -> crate::Result<Self> {
        let [x, y, z, w] = read_lwc_components::<R, 4>(
            reader,
            ctx,
            AssetWireField::FVector4Component,
            asset_path,
        )?;
        verify_at_end(reader, expected_end, "FVector4", asset_path)?;
        Ok(Self { x, y, z, w })
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

/// Registry shim for [`FVector2D`] — same shape as [`read_fvector`].
pub(crate) fn read_fvector2d(
    reader: &mut dyn crate::asset::structs::ReadAndSeek,
    ctx: &AssetContext,
    expected_end: u64,
    asset_path: &str,
) -> crate::Result<TypedStructValue> {
    let v = FVector2D::read_from(reader, ctx, expected_end, asset_path)?;
    Ok(TypedStructValue::Vector2D(v))
}

/// Registry shim for [`FVector4`] — same shape as [`read_fvector`].
pub(crate) fn read_fvector4(
    reader: &mut dyn crate::asset::structs::ReadAndSeek,
    ctx: &AssetContext,
    expected_end: u64,
    asset_path: &str,
) -> crate::Result<TypedStructValue> {
    let v = FVector4::read_from(reader, ctx, expected_end, asset_path)?;
    Ok(TypedStructValue::Vector4(v))
}

/// Read `N` little-endian components from `reader`, dispatched by
/// `ctx.version.is_lwc()`: UE5 LWC reads `f64` (8 bytes each), UE4
/// reads `f32` (4 bytes each) and widens losslessly. Shared by every
/// vector-family decoder (Tasks 2-9) — centralizes the `is_lwc`
/// branch so the mutation surface is one site, not N.
///
/// Components are returned in wire order. Caller destructures into
/// named fields (e.g. `let [x, y, z] = read_lwc_components::<R, 3>(...)?`).
fn read_lwc_components<R: Read + ?Sized, const N: usize>(
    reader: &mut R,
    ctx: &AssetContext,
    field: AssetWireField,
    asset_path: &str,
) -> crate::Result<[f64; N]> {
    let mut out = [0.0_f64; N];
    if ctx.version.is_lwc() {
        for slot in &mut out {
            *slot = read_f64(reader, field, asset_path)?;
        }
    } else {
        for slot in &mut out {
            *slot = f64::from(read_f32(reader, field, asset_path)?);
        }
    }
    Ok(out)
}

fn read_f32<R: Read + ?Sized>(
    reader: &mut R,
    field: AssetWireField,
    asset_path: &str,
) -> crate::Result<f32> {
    reader
        .read_f32::<LittleEndian>()
        .map_err(|_| eof(field, asset_path))
}

fn read_f64<R: Read + ?Sized>(
    reader: &mut R,
    field: AssetWireField,
    asset_path: &str,
) -> crate::Result<f64> {
    reader
        .read_f64::<LittleEndian>()
        .map_err(|_| eof(field, asset_path))
}

fn eof(field: AssetWireField, asset_path: &str) -> PaksmithError {
    PaksmithError::AssetParse {
        asset_path: asset_path.to_string(),
        fault: AssetParseFault::UnexpectedEof { field },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::property::test_utils::make_ctx_with_version;
    use std::io::Cursor;

    /// Build the wire-form bytes for a UE4 f32 vector of any arity.
    /// Slice-taking: scales across vector-family decoders without
    /// adding a new arity-specific helper per task.
    fn f32_bytes(components: &[f32]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(components.len() * 4);
        for c in components {
            bytes.extend_from_slice(&c.to_le_bytes());
        }
        bytes
    }

    /// Build the wire-form bytes for a UE5 LWC f64 vector of any
    /// arity. Sibling of [`f32_bytes`].
    fn f64_bytes(components: &[f64]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(components.len() * 8);
        for c in components {
            bytes.extend_from_slice(&c.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn ue4_vector_decodes_12_bytes() {
        let bytes = f32_bytes(&[1.5, 2.5, 3.5]);
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
        let bytes = f64_bytes(&[1.5, 2.5, 3.5]);
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
        let bytes = f32_bytes(&[1.5, 2.5, 3.5]);
        let ctx = make_ctx_with_version(510, Some(1003));
        let mut cur = Cursor::new(bytes.as_slice());
        let v = FVector::read_from(&mut cur, &ctx, 12, "test.uasset").expect("read");
        assert!((v.x - 1.5).abs() < f64::EPSILON);
    }

    #[test]
    fn vector_trailing_bytes_rejected() {
        // 12 wire bytes (UE4 f32×3) + 4 trailing — expected_end = 16.
        // The 4 trailing bytes surface as TypedStructTrailingBytes.
        let mut bytes = f32_bytes(&[1.5, 2.5, 3.5]);
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
        let bytes = f32_bytes(&[1.5, 2.5, 3.5]);
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
        let bytes = f32_bytes(&[7.0, 8.0, 9.0]);
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(bytes.as_slice());
        let value = read_fvector(&mut cur, &ctx, 12, "test.uasset").expect("read");
        match value {
            TypedStructValue::Vector(v) => {
                assert!((v.x - 7.0).abs() < f64::EPSILON);
                assert!((v.y - 8.0).abs() < f64::EPSILON);
                assert!((v.z - 9.0).abs() < f64::EPSILON);
            }
            other => panic!("expected TypedStructValue::Vector, got {other:?}"),
        }
    }

    // ---------- FVector2D tests (Phase 3c Task 3) ----------

    #[test]
    fn ue4_vector2d_decodes_8_bytes() {
        let bytes = f32_bytes(&[1.5, 2.5]);
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(bytes.as_slice());
        let v = FVector2D::read_from(&mut cur, &ctx, 8, "test.uasset").expect("read");
        assert!((v.x - 1.5).abs() < f64::EPSILON);
        assert!((v.y - 2.5).abs() < f64::EPSILON);
    }

    #[test]
    fn ue5_lwc_vector2d_decodes_16_bytes() {
        let bytes = f64_bytes(&[1.5, 2.5]);
        let ctx = make_ctx_with_version(510, Some(1004));
        let mut cur = Cursor::new(bytes.as_slice());
        let v = FVector2D::read_from(&mut cur, &ctx, 16, "test.uasset").expect("read");
        assert!((v.x - 1.5).abs() < f64::EPSILON);
        assert!((v.y - 2.5).abs() < f64::EPSILON);
    }

    #[test]
    fn pre_lwc_ue5_vector2d_uses_f32_width() {
        // UE5 below the LWC gate (1003) — still f32 width.
        // Pins the `>=` boundary at 1004 vs 1003 for FVector2D
        // (the shared `is_lwc()` gate is exercised at FVector
        // too, but per-decoder pins catch a regression where
        // FVector2D might diverge — e.g. if someone parameterized
        // the LWC threshold per-struct in a future refactor).
        let bytes = f32_bytes(&[1.5, 2.5]);
        let ctx = make_ctx_with_version(510, Some(1003));
        let mut cur = Cursor::new(bytes.as_slice());
        let v = FVector2D::read_from(&mut cur, &ctx, 8, "test.uasset").expect("read");
        assert!((v.x - 1.5).abs() < f64::EPSILON);
        assert!((v.y - 2.5).abs() < f64::EPSILON);
    }

    #[test]
    fn vector2d_overrun_rejected() {
        // 8 wire bytes (UE4 f32×2) but expected_end = 4. The
        // decoder consumes 8 bytes, leaving pos=8 > expected_end=4.
        // Pins the `Ordering::Greater` branch with the FVector2D
        // struct_name token.
        let bytes = f32_bytes(&[1.5, 2.5]);
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(bytes.as_slice());
        let err = FVector2D::read_from(&mut cur, &ctx, 4, "test.uasset").unwrap_err();
        match err {
            PaksmithError::AssetParse {
                fault:
                    AssetParseFault::TypedStructOverrun {
                        struct_name,
                        overrun,
                    },
                ..
            } => {
                assert_eq!(struct_name, "FVector2D");
                assert_eq!(overrun, 4u64);
            }
            other => panic!("expected TypedStructOverrun(FVector2D), got {other:?}"),
        }
    }

    #[test]
    fn vector2d_eof_during_decode_rejected() {
        // 4 bytes — enough for x as f32, but y hits EOF. Pins
        // the FVector2D-specific `FVector2DComponent` field
        // routing (not the FVector one).
        let mut bytes = Vec::with_capacity(4);
        bytes.extend_from_slice(&1.5f32.to_le_bytes());
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(bytes.as_slice());
        let err = FVector2D::read_from(&mut cur, &ctx, 8, "test.uasset").unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::UnexpectedEof {
                        field: AssetWireField::FVector2DComponent,
                    },
                    ..
                }
            ),
            "expected UnexpectedEof(FVector2DComponent), got {err:?}"
        );
    }

    #[test]
    fn vector2d_trailing_bytes_rejected() {
        // 8 wire bytes (UE4 f32×2) + 4 trailing — expected_end = 12.
        let mut bytes = f32_bytes(&[1.5, 2.5]);
        bytes.extend_from_slice(&[0u8; 4]);
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(bytes.as_slice());
        let err = FVector2D::read_from(&mut cur, &ctx, 12, "test.uasset").unwrap_err();
        match err {
            PaksmithError::AssetParse {
                fault:
                    AssetParseFault::TypedStructTrailingBytes {
                        struct_name,
                        trailing,
                    },
                ..
            } => {
                assert_eq!(struct_name, "FVector2D");
                assert_eq!(trailing, 4u64);
            }
            other => panic!("expected TypedStructTrailingBytes(FVector2D), got {other:?}"),
        }
    }

    #[test]
    fn read_fvector2d_shim_returns_typed_struct_vector2d() {
        let bytes = f32_bytes(&[7.0, 8.0]);
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(bytes.as_slice());
        let value = read_fvector2d(&mut cur, &ctx, 8, "test.uasset").expect("read");
        match value {
            TypedStructValue::Vector2D(v) => {
                assert!((v.x - 7.0).abs() < f64::EPSILON);
                assert!((v.y - 8.0).abs() < f64::EPSILON);
            }
            other => panic!("expected TypedStructValue::Vector2D, got {other:?}"),
        }
    }

    // ---------- FVector4 tests (Phase 3c Task 3) ----------

    #[test]
    fn ue4_vector4_decodes_16_bytes() {
        let bytes = f32_bytes(&[1.5, 2.5, 3.5, 4.5]);
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(bytes.as_slice());
        let v = FVector4::read_from(&mut cur, &ctx, 16, "test.uasset").expect("read");
        assert!((v.x - 1.5).abs() < f64::EPSILON);
        assert!((v.y - 2.5).abs() < f64::EPSILON);
        assert!((v.z - 3.5).abs() < f64::EPSILON);
        assert!((v.w - 4.5).abs() < f64::EPSILON);
    }

    #[test]
    fn ue5_lwc_vector4_decodes_32_bytes() {
        let bytes = f64_bytes(&[1.5, 2.5, 3.5, 4.5]);
        let ctx = make_ctx_with_version(510, Some(1004));
        let mut cur = Cursor::new(bytes.as_slice());
        let v = FVector4::read_from(&mut cur, &ctx, 32, "test.uasset").expect("read");
        assert!((v.x - 1.5).abs() < f64::EPSILON);
        assert!((v.y - 2.5).abs() < f64::EPSILON);
        assert!((v.z - 3.5).abs() < f64::EPSILON);
        assert!((v.w - 4.5).abs() < f64::EPSILON);
    }

    #[test]
    fn vector4_eof_during_decode_rejected() {
        // 12 bytes — enough for x, y, z as f32, but w hits EOF.
        let mut bytes = Vec::with_capacity(12);
        bytes.extend_from_slice(&1.5f32.to_le_bytes());
        bytes.extend_from_slice(&2.5f32.to_le_bytes());
        bytes.extend_from_slice(&3.5f32.to_le_bytes());
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(bytes.as_slice());
        let err = FVector4::read_from(&mut cur, &ctx, 16, "test.uasset").unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::UnexpectedEof {
                        field: AssetWireField::FVector4Component,
                    },
                    ..
                }
            ),
            "expected UnexpectedEof(FVector4Component), got {err:?}"
        );
    }

    #[test]
    fn pre_lwc_ue5_vector4_uses_f32_width() {
        // UE5 below the LWC gate (1003) — still f32 width.
        // Pins the `>=` boundary at 1004 vs 1003 for FVector4.
        let bytes = f32_bytes(&[1.5, 2.5, 3.5, 4.5]);
        let ctx = make_ctx_with_version(510, Some(1003));
        let mut cur = Cursor::new(bytes.as_slice());
        let v = FVector4::read_from(&mut cur, &ctx, 16, "test.uasset").expect("read");
        assert!((v.x - 1.5).abs() < f64::EPSILON);
        assert!((v.w - 4.5).abs() < f64::EPSILON);
    }

    #[test]
    fn vector4_overrun_rejected() {
        // 16 wire bytes (UE4 f32×4) but expected_end = 12.
        // Pins the `Ordering::Greater` branch with the FVector4
        // struct_name token.
        let bytes = f32_bytes(&[1.5, 2.5, 3.5, 4.5]);
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(bytes.as_slice());
        let err = FVector4::read_from(&mut cur, &ctx, 12, "test.uasset").unwrap_err();
        match err {
            PaksmithError::AssetParse {
                fault:
                    AssetParseFault::TypedStructOverrun {
                        struct_name,
                        overrun,
                    },
                ..
            } => {
                assert_eq!(struct_name, "FVector4");
                assert_eq!(overrun, 4u64);
            }
            other => panic!("expected TypedStructOverrun(FVector4), got {other:?}"),
        }
    }

    #[test]
    fn read_fvector4_shim_returns_typed_struct_vector4() {
        let bytes = f32_bytes(&[7.0, 8.0, 9.0, 10.0]);
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(bytes.as_slice());
        let value = read_fvector4(&mut cur, &ctx, 16, "test.uasset").expect("read");
        match value {
            TypedStructValue::Vector4(v) => {
                assert!((v.x - 7.0).abs() < f64::EPSILON);
                assert!((v.y - 8.0).abs() < f64::EPSILON);
                assert!((v.z - 9.0).abs() < f64::EPSILON);
                assert!((v.w - 10.0).abs() < f64::EPSILON);
            }
            other => panic!("expected TypedStructValue::Vector4, got {other:?}"),
        }
    }
}
