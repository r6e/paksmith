//! `FColor` + `FLinearColor` decoders.
//!
//! Wire-format reference: CUE4Parse `FColor.cs` / `FLinearColor.cs`
//! at `cf74fc32fe1b40e9fd3440032508c5e1d50cf58d`.
//!
//! **Neither struct is LWC-widened.** `FColor` is a fixed 4 × u8
//! (BGRA on the wire); `FLinearColor` is a fixed 4 × f32 (RGBA on
//! the wire), unchanged between UE4 and UE5. They therefore bypass
//! the `read_lwc_components` helper (which dispatches f32-vs-f64 on
//! `is_lwc`) and read their fixed byte shapes directly.
//!
//! ## `FColor` BGRA → RGBA swizzle
//!
//! UE serializes `FColor` in **BGRA** byte order on the wire
//! (`B`, `G`, `R`, `A`) — a Win32 / D3D `COLORREF` legacy. paksmith
//! stores the struct in the natural **RGBA** field order
//! (`r`, `g`, `b`, `a`), swizzling on decode so downstream
//! consumers don't have to remember the wire quirk.

use std::io::{Read, Seek};

use byteorder::{LittleEndian, ReadBytesExt};

use crate::asset::AssetContext;
use crate::asset::structs::{TypedStructValue, component_eof, verify_at_end};
use crate::error::AssetWireField;

/// 32-bit sRGB color, 4 × u8. Stored RGBA; **wire order is BGRA**
/// (swizzled on decode — see module docs). Fixed 4 bytes in both
/// UE4 and UE5 (NOT LWC-widened).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FColor {
    /// Red channel (wire position 2).
    pub r: u8,
    /// Green channel (wire position 1).
    pub g: u8,
    /// Blue channel (wire position 0).
    pub b: u8,
    /// Alpha channel (wire position 3).
    pub a: u8,
}

impl FColor {
    /// Decode an `FColor` from `reader`. Reads 4 bytes in wire
    /// order `B, G, R, A` and stores them as `r, g, b, a`.
    ///
    /// # Errors
    /// - [`crate::error::AssetParseFault::UnexpectedEof`] with
    ///   `field = TypedStructComponent { struct_name: "FColor" }`
    ///   if any channel byte read hits EOF.
    /// - Trailing-bytes / overrun faults per `verify_at_end`.
    pub fn read_from<R: Read + Seek + ?Sized>(
        reader: &mut R,
        _ctx: &AssetContext,
        expected_end: u64,
        asset_path: &str,
    ) -> crate::Result<Self> {
        let field = AssetWireField::TypedStructComponent {
            struct_name: "FColor",
        };
        // Wire order: B, G, R, A.
        let b = reader
            .read_u8()
            .map_err(|_| component_eof(field, asset_path))?;
        let g = reader
            .read_u8()
            .map_err(|_| component_eof(field, asset_path))?;
        let r = reader
            .read_u8()
            .map_err(|_| component_eof(field, asset_path))?;
        let a = reader
            .read_u8()
            .map_err(|_| component_eof(field, asset_path))?;
        verify_at_end(reader, expected_end, "FColor", asset_path)?;
        Ok(Self { r, g, b, a })
    }

    /// Wire byte size of an `FColor`: fixed 4 bytes (4 × u8, NOT
    /// LWC-widened). Used by the unversioned typed-struct dispatch to
    /// bound the natural-width read (#640).
    #[must_use]
    pub(crate) fn wire_size(_ctx: &AssetContext) -> u64 {
        4
    }
}

/// Linear-space color, 4 × f32 in wire order `R, G, B, A`. Used by
/// materials and lighting. Fixed 16 bytes in both UE4 and UE5
/// (NOT LWC-widened — linear colors stay f32).
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct FLinearColor {
    /// Red channel (linear).
    pub r: f32,
    /// Green channel (linear).
    pub g: f32,
    /// Blue channel (linear).
    pub b: f32,
    /// Alpha channel (linear).
    pub a: f32,
}

impl FLinearColor {
    /// Decode an `FLinearColor` from `reader`. Reads 4 × f32 LE in
    /// wire order `R, G, B, A`. NOT LWC-widened — the components
    /// stay f32 in both UE4 and UE5.
    ///
    /// # Errors
    /// - [`crate::error::AssetParseFault::UnexpectedEof`] with
    ///   `field = TypedStructComponent { struct_name: "FLinearColor" }`
    ///   if any channel read hits EOF.
    /// - Trailing-bytes / overrun faults per `verify_at_end`.
    pub fn read_from<R: Read + Seek + ?Sized>(
        reader: &mut R,
        _ctx: &AssetContext,
        expected_end: u64,
        asset_path: &str,
    ) -> crate::Result<Self> {
        let field = AssetWireField::TypedStructComponent {
            struct_name: "FLinearColor",
        };
        let r = reader
            .read_f32::<LittleEndian>()
            .map_err(|_| component_eof(field, asset_path))?;
        let g = reader
            .read_f32::<LittleEndian>()
            .map_err(|_| component_eof(field, asset_path))?;
        let b = reader
            .read_f32::<LittleEndian>()
            .map_err(|_| component_eof(field, asset_path))?;
        let a = reader
            .read_f32::<LittleEndian>()
            .map_err(|_| component_eof(field, asset_path))?;
        verify_at_end(reader, expected_end, "FLinearColor", asset_path)?;
        Ok(Self { r, g, b, a })
    }

    /// Wire byte size of an `FLinearColor`: fixed 16 bytes (4 × f32,
    /// NOT LWC-widened). Used by the unversioned typed-struct dispatch
    /// to bound the natural-width read (#640).
    #[must_use]
    pub(crate) fn wire_size(_ctx: &AssetContext) -> u64 {
        16
    }
}

/// Registry-compatible decoder shim for [`FColor`].
pub(crate) fn read_fcolor(
    reader: &mut dyn crate::asset::structs::ReadAndSeek,
    ctx: &AssetContext,
    expected_end: u64,
    asset_path: &str,
) -> crate::Result<TypedStructValue> {
    let c = FColor::read_from(reader, ctx, expected_end, asset_path)?;
    Ok(TypedStructValue::Color(c))
}

/// Registry-compatible decoder shim for [`FLinearColor`].
pub(crate) fn read_flinearcolor(
    reader: &mut dyn crate::asset::structs::ReadAndSeek,
    ctx: &AssetContext,
    expected_end: u64,
    asset_path: &str,
) -> crate::Result<TypedStructValue> {
    let c = FLinearColor::read_from(reader, ctx, expected_end, asset_path)?;
    Ok(TypedStructValue::LinearColor(c))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PaksmithError;
    use crate::asset::property::test_utils::make_ctx_with_version;
    use crate::asset::structs::test_utils::f32_bytes;
    use crate::error::AssetParseFault;
    use std::io::Cursor;

    #[test]
    fn color_wire_sizes_are_fixed() {
        // FColor (4 × u8) and FLinearColor (4 × f32) are NOT
        // LWC-widened: identical at UE4 and UE5 LWC.
        for ctx in [
            make_ctx_with_version(510, None),
            make_ctx_with_version(510, Some(1004)),
        ] {
            assert_eq!(FColor::wire_size(&ctx), 4);
            assert_eq!(FLinearColor::wire_size(&ctx), 16);
        }
    }

    #[test]
    fn fcolor_bgra_wire_swizzles_to_rgba_struct() {
        // Wire: b=0x10, g=0x20, r=0x30, a=0xFF. The struct fields
        // must come back as r=0x30, g=0x20, b=0x10, a=0xFF — i.e.
        // the BGRA wire order swizzled into RGBA. A missing/reversed
        // swizzle would surface as r==0x10 (the wire's first byte).
        let bytes = [0x10u8, 0x20, 0x30, 0xFF];
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(&bytes[..]);
        let c = FColor::read_from(&mut cur, &ctx, 4, "test.uasset").expect("read");
        assert_eq!(c.r, 0x30);
        assert_eq!(c.g, 0x20);
        assert_eq!(c.b, 0x10);
        assert_eq!(c.a, 0xFF);
    }

    #[test]
    fn fcolor_width_is_4_bytes_regardless_of_lwc() {
        // FColor is NOT LWC-widened — a UE5-LWC context still reads
        // exactly 4 bytes (the `_ctx` param is ignored). Pins that
        // the decoder doesn't accidentally route through is_lwc.
        let bytes = [0x01u8, 0x02, 0x03, 0x04];
        let ctx = make_ctx_with_version(510, Some(1004));
        let mut cur = Cursor::new(&bytes[..]);
        let c = FColor::read_from(&mut cur, &ctx, 4, "test.uasset").expect("read");
        assert_eq!(c.r, 0x03);
        assert_eq!(c.g, 0x02);
        assert_eq!(c.b, 0x01);
        assert_eq!(c.a, 0x04);
    }

    #[test]
    fn fcolor_eof_during_decode_rejected() {
        // 2 bytes — enough for B and G, but R hits EOF.
        let bytes = [0x10u8, 0x20];
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(&bytes[..]);
        let err = FColor::read_from(&mut cur, &ctx, 4, "test.uasset").unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::UnexpectedEof {
                        field: AssetWireField::TypedStructComponent {
                            struct_name: "FColor"
                        },
                    },
                    ..
                }
            ),
            "expected UnexpectedEof(TypedStructComponent(FColor)), got {err:?}"
        );
    }

    #[test]
    fn fcolor_trailing_bytes_rejected() {
        let bytes = [0x10u8, 0x20, 0x30, 0xFF, 0x00, 0x00];
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(&bytes[..]);
        let err = FColor::read_from(&mut cur, &ctx, 6, "test.uasset").unwrap_err();
        match err {
            PaksmithError::AssetParse {
                fault:
                    AssetParseFault::TypedStructTrailingBytes {
                        struct_name,
                        trailing,
                    },
                ..
            } => {
                assert_eq!(struct_name, "FColor");
                assert_eq!(trailing, 2u64);
            }
            other => panic!("expected TypedStructTrailingBytes(FColor), got {other:?}"),
        }
    }

    #[test]
    fn read_fcolor_shim_returns_typed_struct_color() {
        let bytes = [0x10u8, 0x20, 0x30, 0xFF];
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(&bytes[..]);
        let value = read_fcolor(&mut cur, &ctx, 4, "test.uasset").expect("read");
        match value {
            TypedStructValue::Color(c) => {
                // Assert all four channels so a shim mutant that
                // dropped g/a would be caught here, not just by the
                // direct read_from tests.
                assert_eq!(c.r, 0x30);
                assert_eq!(c.g, 0x20);
                assert_eq!(c.b, 0x10);
                assert_eq!(c.a, 0xFF);
            }
            other => panic!("expected TypedStructValue::Color, got {other:?}"),
        }
    }

    #[test]
    fn flinearcolor_rgba_decodes_16_bytes() {
        // Wire order R, G, B, A (no swizzle, unlike FColor).
        let bytes = f32_bytes(&[0.25, 0.5, 0.75, 1.0]);
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(bytes.as_slice());
        let c = FLinearColor::read_from(&mut cur, &ctx, 16, "test.uasset").expect("read");
        assert!((c.r - 0.25).abs() < f32::EPSILON);
        assert!((c.g - 0.5).abs() < f32::EPSILON);
        assert!((c.b - 0.75).abs() < f32::EPSILON);
        assert!((c.a - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn flinearcolor_width_is_16_bytes_regardless_of_lwc() {
        // FLinearColor is NOT LWC-widened — a UE5-LWC context still
        // reads exactly 16 bytes (4 × f32), NOT 32 (4 × f64).
        let bytes = f32_bytes(&[0.1, 0.2, 0.3, 0.4]);
        let ctx = make_ctx_with_version(510, Some(1004));
        let mut cur = Cursor::new(bytes.as_slice());
        let c = FLinearColor::read_from(&mut cur, &ctx, 16, "test.uasset").expect("read");
        assert!((c.r - 0.1).abs() < f32::EPSILON);
        assert!((c.a - 0.4).abs() < f32::EPSILON);
    }

    #[test]
    fn flinearcolor_eof_during_decode_rejected() {
        // 12 bytes — enough for R, G, B but A hits EOF.
        let bytes = f32_bytes(&[0.1, 0.2, 0.3]);
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(bytes.as_slice());
        let err = FLinearColor::read_from(&mut cur, &ctx, 16, "test.uasset").unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::UnexpectedEof {
                        field: AssetWireField::TypedStructComponent {
                            struct_name: "FLinearColor"
                        },
                    },
                    ..
                }
            ),
            "expected UnexpectedEof(TypedStructComponent(FLinearColor)), got {err:?}"
        );
    }

    #[test]
    fn flinearcolor_overrun_rejected() {
        // 16 wire bytes but expected_end = 12.
        let bytes = f32_bytes(&[0.1, 0.2, 0.3, 0.4]);
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(bytes.as_slice());
        let err = FLinearColor::read_from(&mut cur, &ctx, 12, "test.uasset").unwrap_err();
        match err {
            PaksmithError::AssetParse {
                fault:
                    AssetParseFault::TypedStructOverrun {
                        struct_name,
                        overrun,
                    },
                ..
            } => {
                assert_eq!(struct_name, "FLinearColor");
                assert_eq!(overrun, 4u64);
            }
            other => panic!("expected TypedStructOverrun(FLinearColor), got {other:?}"),
        }
    }

    #[test]
    fn read_flinearcolor_shim_returns_typed_struct_linear_color() {
        let ctx = make_ctx_with_version(510, None);
        // Distinct per-channel values so a shim mutant that dropped
        // g/b would be caught here.
        let bytes = f32_bytes(&[0.25, 0.5, 0.75, 1.0]);
        let mut cur = Cursor::new(bytes.as_slice());
        let value = read_flinearcolor(&mut cur, &ctx, 16, "test.uasset").expect("read");
        match value {
            TypedStructValue::LinearColor(c) => {
                assert!((c.r - 0.25).abs() < f32::EPSILON);
                assert!((c.g - 0.5).abs() < f32::EPSILON);
                assert!((c.b - 0.75).abs() < f32::EPSILON);
                assert!((c.a - 1.0).abs() < f32::EPSILON);
            }
            other => panic!("expected TypedStructValue::LinearColor, got {other:?}"),
        }
    }
}
