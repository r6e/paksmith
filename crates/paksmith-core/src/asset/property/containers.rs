//! Container property readers: ArrayProperty, StructProperty, MapProperty, SetProperty.
//!
//! Phase 2c Task 3 ships the primitive [`read_element_value`] only.
//! Tasks 4-7 add `read_array_value`, `read_struct_value`,
//! `read_map_value`, `read_set_value`, and the public
//! `read_container_value` dispatcher.

use std::io::{Read, Seek};

use byteorder::{LittleEndian, ReadBytesExt};

use crate::asset::AssetContext;
use crate::asset::property::primitives::PropertyValue;
use crate::asset::read_asset_fstring;
use crate::error::AssetWireField;

use super::{read_fname_pair, unexpected_eof};

/// Reads a single primitive element value for Array/Map/Set contents.
///
/// Returns `None` for types not decoded in Phase 2c (StructProperty,
/// ByteProperty, EnumProperty, TextProperty, or any other
/// unrecognised type). Tasks 4-6 use the returned `None` to fall back
/// to `Unknown { skipped_bytes }` via the outer `tag.size`.
///
/// **BoolProperty:** reads a raw `u8` — byte 0 = false, non-zero =
/// true. This is distinct from direct BoolProperty which reads
/// `tag.bool_val` with zero payload bytes.
///
/// `body_field` lets the caller name the wire context for EOF errors
/// (`ArrayElementBody` for arrays, `SetElement` for sets, `MapKey` /
/// `MapValue` for map entries) so operators can distinguish a
/// truncated array body from a truncated set body in diagnostics.
#[allow(
    dead_code,
    reason = "Phase 2c Task 4-6 callers added in subsequent tasks"
)]
fn read_element_value<R: Read + Seek>(
    type_name: &str,
    body_field: AssetWireField,
    reader: &mut R,
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<Option<PropertyValue>> {
    use PropertyValue as PV;
    Ok(Some(match type_name {
        "BoolProperty" => {
            let b = reader
                .read_u8()
                .map_err(|_| unexpected_eof(asset_path, body_field))?;
            PV::Bool(b != 0)
        }
        "Int8Property" => PV::Int8(
            reader
                .read_i8()
                .map_err(|_| unexpected_eof(asset_path, body_field))?,
        ),
        "Int16Property" => PV::Int16(
            reader
                .read_i16::<LittleEndian>()
                .map_err(|_| unexpected_eof(asset_path, body_field))?,
        ),
        "IntProperty" => PV::Int(
            reader
                .read_i32::<LittleEndian>()
                .map_err(|_| unexpected_eof(asset_path, body_field))?,
        ),
        "Int64Property" => PV::Int64(
            reader
                .read_i64::<LittleEndian>()
                .map_err(|_| unexpected_eof(asset_path, body_field))?,
        ),
        "UInt16Property" => PV::UInt16(
            reader
                .read_u16::<LittleEndian>()
                .map_err(|_| unexpected_eof(asset_path, body_field))?,
        ),
        "UInt32Property" => PV::UInt32(
            reader
                .read_u32::<LittleEndian>()
                .map_err(|_| unexpected_eof(asset_path, body_field))?,
        ),
        "UInt64Property" => PV::UInt64(
            reader
                .read_u64::<LittleEndian>()
                .map_err(|_| unexpected_eof(asset_path, body_field))?,
        ),
        "FloatProperty" => PV::Float(
            reader
                .read_f32::<LittleEndian>()
                .map_err(|_| unexpected_eof(asset_path, body_field))?,
        ),
        "DoubleProperty" => PV::Double(
            reader
                .read_f64::<LittleEndian>()
                .map_err(|_| unexpected_eof(asset_path, body_field))?,
        ),
        "StrProperty" => {
            // Asset-side wrapper: accepts len=0 as "" (CUE4Parse
            // semantics) and re-categorizes pak-side FStringMalformed
            // faults with asset_path context.
            PV::Str(read_asset_fstring(reader, asset_path)?)
        }
        "NameProperty" => PV::Name(read_fname_pair(reader, ctx, asset_path, body_field)?),
        _ => return Ok(None),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::property::primitives::PropertyValue;
    use crate::asset::property::test_utils::make_ctx;
    use std::io::Cursor;

    #[test]
    fn element_bool_false() {
        let ctx = make_ctx(&[]);
        let mut r = Cursor::new(vec![0u8]);
        let v = read_element_value(
            "BoolProperty",
            AssetWireField::ArrayElementBody,
            &mut r,
            &ctx,
            "x.uasset",
        )
        .unwrap()
        .unwrap();
        assert_eq!(v, PropertyValue::Bool(false));
    }

    #[test]
    fn element_bool_true() {
        let ctx = make_ctx(&[]);
        let mut r = Cursor::new(vec![1u8]);
        let v = read_element_value(
            "BoolProperty",
            AssetWireField::ArrayElementBody,
            &mut r,
            &ctx,
            "x.uasset",
        )
        .unwrap()
        .unwrap();
        assert_eq!(v, PropertyValue::Bool(true));
    }

    #[test]
    fn element_bool_nonzero_is_true() {
        let ctx = make_ctx(&[]);
        let mut r = Cursor::new(vec![0xFFu8]);
        let v = read_element_value(
            "BoolProperty",
            AssetWireField::ArrayElementBody,
            &mut r,
            &ctx,
            "x.uasset",
        )
        .unwrap()
        .unwrap();
        assert_eq!(v, PropertyValue::Bool(true));
    }

    #[test]
    fn element_int32() {
        let ctx = make_ctx(&[]);
        let mut r = Cursor::new(42i32.to_le_bytes().to_vec());
        let v = read_element_value(
            "IntProperty",
            AssetWireField::ArrayElementBody,
            &mut r,
            &ctx,
            "x.uasset",
        )
        .unwrap()
        .unwrap();
        assert_eq!(v, PropertyValue::Int(42));
    }

    #[test]
    fn element_int64() {
        let ctx = make_ctx(&[]);
        let mut r = Cursor::new(i64::MIN.to_le_bytes().to_vec());
        let v = read_element_value(
            "Int64Property",
            AssetWireField::ArrayElementBody,
            &mut r,
            &ctx,
            "x.uasset",
        )
        .unwrap()
        .unwrap();
        assert_eq!(v, PropertyValue::Int64(i64::MIN));
    }

    #[test]
    fn element_uint32() {
        let ctx = make_ctx(&[]);
        let mut r = Cursor::new(0xDEAD_BEEFu32.to_le_bytes().to_vec());
        let v = read_element_value(
            "UInt32Property",
            AssetWireField::ArrayElementBody,
            &mut r,
            &ctx,
            "x.uasset",
        )
        .unwrap()
        .unwrap();
        assert_eq!(v, PropertyValue::UInt32(0xDEAD_BEEF));
    }

    #[test]
    fn element_float() {
        let ctx = make_ctx(&[]);
        let mut r = Cursor::new(1.5f32.to_le_bytes().to_vec());
        let v = read_element_value(
            "FloatProperty",
            AssetWireField::ArrayElementBody,
            &mut r,
            &ctx,
            "x.uasset",
        )
        .unwrap()
        .unwrap();
        assert_eq!(v, PropertyValue::Float(1.5));
    }

    #[test]
    fn element_double() {
        let ctx = make_ctx(&[]);
        let mut r = Cursor::new(2.5f64.to_le_bytes().to_vec());
        let v = read_element_value(
            "DoubleProperty",
            AssetWireField::ArrayElementBody,
            &mut r,
            &ctx,
            "x.uasset",
        )
        .unwrap()
        .unwrap();
        assert_eq!(v, PropertyValue::Double(2.5));
    }

    #[test]
    fn element_str() {
        let ctx = make_ctx(&[]);
        // FString: i32 length (including null) + bytes + null
        let mut bytes = 3i32.to_le_bytes().to_vec();
        bytes.extend_from_slice(b"hi\0");
        let mut r = Cursor::new(bytes);
        let v = read_element_value(
            "StrProperty",
            AssetWireField::ArrayElementBody,
            &mut r,
            &ctx,
            "x.uasset",
        )
        .unwrap()
        .unwrap();
        assert_eq!(v, PropertyValue::Str("hi".to_string()));
    }

    #[test]
    fn element_name() {
        // Name table: ["None", "Hero"]
        let ctx = make_ctx(&["None", "Hero"]);
        let mut bytes = 1i32.to_le_bytes().to_vec(); // index 1 -> "Hero"
        bytes.extend_from_slice(&0i32.to_le_bytes()); // number 0 -> no suffix
        let mut r = Cursor::new(bytes);
        let v = read_element_value(
            "NameProperty",
            AssetWireField::ArrayElementBody,
            &mut r,
            &ctx,
            "x.uasset",
        )
        .unwrap()
        .unwrap();
        assert_eq!(v, PropertyValue::Name("Hero".to_string()));
    }

    #[test]
    fn element_name_with_suffix() {
        // FName (index=1, number=3) -> "Hero_2"
        let ctx = make_ctx(&["None", "Hero"]);
        let mut bytes = 1i32.to_le_bytes().to_vec();
        bytes.extend_from_slice(&3i32.to_le_bytes()); // number 3 -> _2 suffix
        let mut r = Cursor::new(bytes);
        let v = read_element_value(
            "NameProperty",
            AssetWireField::ArrayElementBody,
            &mut r,
            &ctx,
            "x.uasset",
        )
        .unwrap()
        .unwrap();
        assert_eq!(v, PropertyValue::Name("Hero_2".to_string()));
    }

    #[test]
    fn element_struct_type_returns_none() {
        let ctx = make_ctx(&[]);
        let mut r = Cursor::new(vec![]);
        let v = read_element_value(
            "StructProperty",
            AssetWireField::ArrayElementBody,
            &mut r,
            &ctx,
            "x.uasset",
        )
        .unwrap();
        assert!(v.is_none());
    }

    #[test]
    fn element_enum_type_returns_none() {
        let ctx = make_ctx(&[]);
        let mut r = Cursor::new(vec![]);
        let v = read_element_value(
            "EnumProperty",
            AssetWireField::ArrayElementBody,
            &mut r,
            &ctx,
            "x.uasset",
        )
        .unwrap();
        assert!(v.is_none());
    }

    #[test]
    fn element_byte_type_returns_none() {
        let ctx = make_ctx(&[]);
        let mut r = Cursor::new(vec![]);
        let v = read_element_value(
            "ByteProperty",
            AssetWireField::ArrayElementBody,
            &mut r,
            &ctx,
            "x.uasset",
        )
        .unwrap();
        assert!(v.is_none());
    }

    #[test]
    fn element_unknown_type_returns_none() {
        let ctx = make_ctx(&[]);
        let mut r = Cursor::new(vec![]);
        let v = read_element_value(
            "UnknownXProperty",
            AssetWireField::ArrayElementBody,
            &mut r,
            &ctx,
            "x.uasset",
        )
        .unwrap();
        assert!(v.is_none());
    }
}
