//! `Property` and `PropertyValue` types + primitive property readers.
//!
//! [`read_primitive_value`] dispatches by `tag.type_name` and reads the
//! value payload from the stream. Returns `Ok(None)` for unrecognised
//! types (Array/Map/Set/Struct/SoftObjectPath/etc.) — the caller is
//! responsible for the `MAX_PROPERTY_TAG_SIZE`-bounded skip and
//! constructing [`PropertyValue::Unknown`].

use std::io::{Read, Seek};

use byteorder::{LittleEndian, ReadBytesExt};
use serde::Serialize;

use crate::asset::AssetContext;
use crate::asset::read_asset_fstring;
use crate::error::AssetWireField;

use super::tag::PropertyTag;
use super::text::{FText, read_ftext};
use super::{read_fname_pair, unexpected_eof};

/// One decoded property entry in an export's property stream.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Property {
    /// Resolved property name.
    pub name: String,
    /// Array element index (0 for non-array properties).
    pub array_index: i32,
    /// Optional per-property GUID carried by the tag header.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guid: Option<[u8; 16]>,
    /// The decoded property value.
    pub value: PropertyValue,
}

/// A single key-value entry in a decoded `MapProperty`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MapEntry {
    /// The decoded key value.
    pub key: PropertyValue,
    /// The decoded value paired with `key`.
    pub value: PropertyValue,
}

/// Decoded property value.
///
/// `#[non_exhaustive]` — Phase 2c will add Array/Map/Set/Struct
/// variants; Phase 2d will add SoftObjectPath/ObjectReference.
/// [`PropertyValue::Unknown`] is the catch-all for types Phase 2b
/// does not decode; it carries `skipped_bytes` (the count) rather than
/// the raw bytes so JSON output stays compact.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[non_exhaustive]
pub enum PropertyValue {
    /// `BoolProperty` — value carried in the tag header.
    Bool(bool),
    /// `ByteProperty` with `tag.enum_name == ""` — a raw u8.
    Byte(u8),
    /// `Int8Property`.
    Int8(i8),
    /// `Int16Property`.
    Int16(i16),
    /// `IntProperty` (i32).
    Int(i32),
    /// `Int64Property`.
    Int64(i64),
    /// `UInt16Property`.
    UInt16(u16),
    /// `UInt32Property`.
    UInt32(u32),
    /// `UInt64Property`.
    UInt64(u64),
    /// `FloatProperty`.
    Float(f32),
    /// `DoubleProperty`.
    Double(f64),
    /// `StrProperty` — an FString.
    Str(String),
    /// `NameProperty` — an FName resolved to a String at parse time
    /// (no `&AssetContext` dependency at serialization time).
    Name(String),
    /// `EnumProperty` (or `ByteProperty` with `tag.enum_name != ""`):
    /// the enum type name plus the resolved variant name.
    ///
    /// **`type_name` may be empty** if an upstream encoder omitted
    /// `tag.enum_name` for an `EnumProperty` (uncommon — modern
    /// encoders always emit it, but the iterator is permissive). The
    /// wire is still consumable (the variant FName is still present),
    /// so the iterator returns it rather than rejecting. Downstream
    /// consumers that need the enum type should treat `type_name ==
    /// ""` as "unknown enum" and either skip or fall back to a type
    /// registry.
    Enum {
        /// The enum type name from `tag.enum_name`; may be empty if
        /// the encoder omitted it (see variant docs).
        type_name: String,
        /// The enum variant name resolved from the payload FName.
        value: String,
    },
    /// `TextProperty`.
    Text(FText),
    /// Unknown or container type — value bytes were skipped per
    /// `tag.size`. Stored as a `(type_name, count)` pair rather than
    /// raw bytes so JSON output of large container payloads stays
    /// compact.
    Unknown {
        /// Resolved type name string (e.g. `"ArrayProperty"`).
        type_name: String,
        /// Number of bytes skipped past the tag header.
        skipped_bytes: usize,
    },
    /// `ArrayProperty` with a handled primitive inner type.
    ///
    /// Arrays with `StructProperty`, `ByteProperty`, `EnumProperty`,
    /// or `TextProperty` inner types fall back to `Unknown { skipped_bytes }`
    /// in Phase 2c.
    Array {
        /// Resolved inner element type name (e.g. `"IntProperty"`).
        inner_type: String,
        /// Decoded array elements, each of type `inner_type`.
        elements: Vec<PropertyValue>,
    },

    /// `StructProperty` — recursive tagged property tree.
    ///
    /// Recursion is bounded by `MAX_PROPERTY_DEPTH`.
    Struct {
        /// Resolved struct type name from `FPropertyTag::struct_name`.
        struct_name: String,
        /// Decoded child tagged properties.
        properties: Vec<Property>,
    },

    /// `MapProperty` with handled primitive key and value types.
    Map {
        /// Resolved key type name.
        key_type: String,
        /// Resolved value type name.
        value_type: String,
        /// Decoded key-value entries.
        entries: Vec<MapEntry>,
    },

    /// `SetProperty` with a handled primitive inner type.
    Set {
        /// Resolved inner element type name.
        inner_type: String,
        /// Decoded set elements, each of type `inner_type`.
        elements: Vec<PropertyValue>,
    },
}

/// Read a primitive property value for `tag`, consuming exactly
/// `tag.size` bytes (except for `BoolProperty`, whose value lives in
/// the tag header and consumes zero payload bytes).
///
/// Returns `Ok(None)` for types Phase 2b does not handle (container
/// types, `SoftObjectPath`, `ObjectReference`, etc.) — the caller
/// must perform the skip and build [`PropertyValue::Unknown`].
///
/// The `Read + Seek` bound is required by the `TextProperty` arm —
/// [`read_ftext`] uses `stream_position()` to compute remaining bytes
/// for unknown-history-type skips. The caller in `read_properties` is
/// already `Read + Seek`, so the widening is free.
///
/// # Errors
///
/// - [`crate::PaksmithError::Io`] / [`crate::error::AssetParseFault::UnexpectedEof`]
///   on short reads.
/// - [`crate::error::AssetParseFault::FStringMalformed`] for malformed FStrings.
/// - Any error from [`super::resolve_fname`] for `NameProperty` / `EnumProperty`.
#[allow(
    clippy::too_many_lines,
    reason = "primitive property type dispatch — one arm per UE primitive type with explicit \
              wire reads; splitting would obscure the per-type byte structure"
)]
pub fn read_primitive_value<R: Read + Seek>(
    tag: &PropertyTag,
    reader: &mut R,
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<Option<PropertyValue>> {
    let val = match tag.type_name.as_str() {
        "BoolProperty" => PropertyValue::Bool(tag.bool_val),

        "ByteProperty" => {
            if tag.enum_name.is_empty() || tag.enum_name == "None" {
                let b = reader
                    .read_u8()
                    .map_err(|_| unexpected_eof(asset_path, AssetWireField::PropertyTagSize))?;
                PropertyValue::Byte(b)
            } else {
                let value =
                    read_fname_pair(reader, ctx, asset_path, AssetWireField::PropertyTagEnumName)?;
                PropertyValue::Enum {
                    type_name: tag.enum_name.clone(),
                    value,
                }
            }
        }

        "Int8Property" => {
            let v = reader
                .read_i8()
                .map_err(|_| unexpected_eof(asset_path, AssetWireField::PropertyTagSize))?;
            PropertyValue::Int8(v)
        }

        "Int16Property" => {
            let v = reader
                .read_i16::<LittleEndian>()
                .map_err(|_| unexpected_eof(asset_path, AssetWireField::PropertyTagSize))?;
            PropertyValue::Int16(v)
        }

        "IntProperty" => {
            let v = reader
                .read_i32::<LittleEndian>()
                .map_err(|_| unexpected_eof(asset_path, AssetWireField::PropertyTagSize))?;
            PropertyValue::Int(v)
        }

        "Int64Property" => {
            let v = reader
                .read_i64::<LittleEndian>()
                .map_err(|_| unexpected_eof(asset_path, AssetWireField::PropertyTagSize))?;
            PropertyValue::Int64(v)
        }

        "UInt16Property" => {
            let v = reader
                .read_u16::<LittleEndian>()
                .map_err(|_| unexpected_eof(asset_path, AssetWireField::PropertyTagSize))?;
            PropertyValue::UInt16(v)
        }

        "UInt32Property" => {
            let v = reader
                .read_u32::<LittleEndian>()
                .map_err(|_| unexpected_eof(asset_path, AssetWireField::PropertyTagSize))?;
            PropertyValue::UInt32(v)
        }

        "UInt64Property" => {
            let v = reader
                .read_u64::<LittleEndian>()
                .map_err(|_| unexpected_eof(asset_path, AssetWireField::PropertyTagSize))?;
            PropertyValue::UInt64(v)
        }

        "FloatProperty" => {
            let v = reader
                .read_f32::<LittleEndian>()
                .map_err(|_| unexpected_eof(asset_path, AssetWireField::PropertyTagSize))?;
            PropertyValue::Float(v)
        }

        "DoubleProperty" => {
            let v = reader
                .read_f64::<LittleEndian>()
                .map_err(|_| unexpected_eof(asset_path, AssetWireField::PropertyTagSize))?;
            PropertyValue::Double(v)
        }

        "StrProperty" => {
            // Asset-side wrapper: accepts len=0 as "" (CUE4Parse
            // semantics) and re-categorizes pak-side FStringMalformed
            // errors as AssetParseFault::FStringMalformed with
            // asset_path context. See `asset/fstring.rs`.
            let s = read_asset_fstring(reader, asset_path)?;
            PropertyValue::Str(s)
        }

        "NameProperty" => {
            let name = read_fname_pair(reader, ctx, asset_path, AssetWireField::PropertyTagName)?;
            PropertyValue::Name(name)
        }

        "EnumProperty" => {
            let value =
                read_fname_pair(reader, ctx, asset_path, AssetWireField::PropertyTagEnumName)?;
            PropertyValue::Enum {
                type_name: tag.enum_name.clone(),
                value,
            }
        }

        "TextProperty" => {
            #[allow(
                clippy::cast_sign_loss,
                reason = "tag.size has been rejected if < 0 by read_tag; safe widening"
            )]
            let text = read_ftext(reader, ctx, asset_path, tag.size as u64)?;
            PropertyValue::Text(text)
        }

        _ => return Ok(None),
    };

    Ok(Some(val))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::property::test_utils::make_ctx;
    use std::io::Cursor;

    fn make_tag(type_name: &str, size: i32) -> PropertyTag {
        PropertyTag {
            name: "Prop".to_string(),
            type_name: type_name.to_string(),
            size,
            array_index: 0,
            bool_val: false,
            struct_name: String::new(),
            struct_guid: [0u8; 16],
            enum_name: String::new(),
            inner_type: String::new(),
            value_type: String::new(),
            guid: None,
        }
    }

    fn make_bool_tag(val: bool) -> PropertyTag {
        let mut t = make_tag("BoolProperty", 0);
        t.bool_val = val;
        t
    }

    fn make_byte_enum_tag(enum_name: &str) -> PropertyTag {
        let mut t = make_tag("ByteProperty", 8);
        t.enum_name = enum_name.to_string();
        t
    }

    #[test]
    fn bool_true() {
        let tag = make_bool_tag(true);
        let ctx = make_ctx(&["None"]);
        let val = read_primitive_value(&tag, &mut Cursor::new(&[][..]), &ctx, "x")
            .unwrap()
            .unwrap();
        assert_eq!(val, PropertyValue::Bool(true));
    }

    #[test]
    fn bool_false() {
        let tag = make_bool_tag(false);
        let ctx = make_ctx(&["None"]);
        let val = read_primitive_value(&tag, &mut Cursor::new(&[][..]), &ctx, "x")
            .unwrap()
            .unwrap();
        assert_eq!(val, PropertyValue::Bool(false));
    }

    #[test]
    fn byte_raw() {
        let tag = make_tag("ByteProperty", 1);
        let ctx = make_ctx(&["None"]);
        let buf = [42u8];
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf[..]), &ctx, "x")
            .unwrap()
            .unwrap();
        assert_eq!(val, PropertyValue::Byte(42));
    }

    #[test]
    fn byte_as_enum() {
        let tag = make_byte_enum_tag("EMyEnum");
        let ctx = make_ctx(&["None", "EMyEnum__Val"]);
        let mut buf = Vec::new();
        buf.extend_from_slice(&1i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf[..]), &ctx, "x")
            .unwrap()
            .unwrap();
        assert_eq!(
            val,
            PropertyValue::Enum {
                type_name: "EMyEnum".to_string(),
                value: "EMyEnum__Val".to_string(),
            }
        );
    }

    #[test]
    fn int8_value() {
        let tag = make_tag("Int8Property", 1);
        let ctx = make_ctx(&["None"]);
        let buf = [0xFEu8];
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf[..]), &ctx, "x")
            .unwrap()
            .unwrap();
        assert_eq!(val, PropertyValue::Int8(-2i8));
    }

    #[test]
    fn int16_value() {
        let tag = make_tag("Int16Property", 2);
        let ctx = make_ctx(&["None"]);
        let buf = (-1000i16).to_le_bytes();
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf[..]), &ctx, "x")
            .unwrap()
            .unwrap();
        assert_eq!(val, PropertyValue::Int16(-1000));
    }

    #[test]
    fn int_value() {
        let tag = make_tag("IntProperty", 4);
        let ctx = make_ctx(&["None"]);
        let buf = 42i32.to_le_bytes();
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf[..]), &ctx, "x")
            .unwrap()
            .unwrap();
        assert_eq!(val, PropertyValue::Int(42));
    }

    #[test]
    fn int64_value() {
        let tag = make_tag("Int64Property", 8);
        let ctx = make_ctx(&["None"]);
        let buf = i64::MAX.to_le_bytes();
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf[..]), &ctx, "x")
            .unwrap()
            .unwrap();
        assert_eq!(val, PropertyValue::Int64(i64::MAX));
    }

    #[test]
    fn uint16_value() {
        let tag = make_tag("UInt16Property", 2);
        let ctx = make_ctx(&["None"]);
        let buf = 60_000u16.to_le_bytes();
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf[..]), &ctx, "x")
            .unwrap()
            .unwrap();
        assert_eq!(val, PropertyValue::UInt16(60_000));
    }

    #[test]
    fn uint32_value() {
        let tag = make_tag("UInt32Property", 4);
        let ctx = make_ctx(&["None"]);
        let buf = 0xDEAD_BEEFu32.to_le_bytes();
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf[..]), &ctx, "x")
            .unwrap()
            .unwrap();
        assert_eq!(val, PropertyValue::UInt32(0xDEAD_BEEF));
    }

    #[test]
    fn uint64_value() {
        let tag = make_tag("UInt64Property", 8);
        let ctx = make_ctx(&["None"]);
        let buf = u64::MAX.to_le_bytes();
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf[..]), &ctx, "x")
            .unwrap()
            .unwrap();
        assert_eq!(val, PropertyValue::UInt64(u64::MAX));
    }

    #[test]
    fn float_value() {
        let tag = make_tag("FloatProperty", 4);
        let ctx = make_ctx(&["None"]);
        let buf = 1500.0f32.to_le_bytes();
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf[..]), &ctx, "x")
            .unwrap()
            .unwrap();
        assert_eq!(val, PropertyValue::Float(1500.0));
    }

    #[test]
    fn double_value() {
        let tag = make_tag("DoubleProperty", 8);
        let ctx = make_ctx(&["None"]);
        let buf = 12345.6789f64.to_le_bytes();
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf[..]), &ctx, "x")
            .unwrap()
            .unwrap();
        assert_eq!(val, PropertyValue::Double(12345.6789));
    }

    #[test]
    fn str_value() {
        let tag = make_tag("StrProperty", 10);
        let ctx = make_ctx(&["None"]);
        let mut buf = Vec::new();
        buf.extend_from_slice(&6i32.to_le_bytes());
        buf.extend_from_slice(b"Hello\0");
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf[..]), &ctx, "x")
            .unwrap()
            .unwrap();
        assert_eq!(val, PropertyValue::Str("Hello".to_string()));
    }

    #[test]
    fn name_value() {
        let tag = make_tag("NameProperty", 8);
        let ctx = make_ctx(&["None", "MyName"]);
        let mut buf = Vec::new();
        buf.extend_from_slice(&1i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf[..]), &ctx, "x")
            .unwrap()
            .unwrap();
        assert_eq!(val, PropertyValue::Name("MyName".to_string()));
    }

    #[test]
    fn enum_property_value() {
        let mut tag = make_tag("EnumProperty", 8);
        tag.enum_name = "EDirection".to_string();
        let ctx = make_ctx(&["None", "EDirection__Forward"]);
        let mut buf = Vec::new();
        buf.extend_from_slice(&1i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf[..]), &ctx, "x")
            .unwrap()
            .unwrap();
        assert_eq!(
            val,
            PropertyValue::Enum {
                type_name: "EDirection".to_string(),
                value: "EDirection__Forward".to_string(),
            }
        );
    }

    #[test]
    fn unknown_type_returns_none() {
        let tag = make_tag("ArrayProperty", 42);
        let ctx = make_ctx(&["None"]);
        let val = read_primitive_value(&tag, &mut Cursor::new(&[][..]), &ctx, "x").unwrap();
        assert!(val.is_none());
    }

    #[test]
    fn property_value_array_serializes() {
        let v = PropertyValue::Array {
            inner_type: "IntProperty".to_string(),
            elements: vec![PropertyValue::Int(1), PropertyValue::Int(2)],
        };
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(
            json,
            r#"{"Array":{"inner_type":"IntProperty","elements":[{"Int":1},{"Int":2}]}}"#
        );
    }

    #[test]
    fn property_value_struct_serializes() {
        let v = PropertyValue::Struct {
            struct_name: "MyStruct".to_string(),
            properties: vec![],
        };
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(
            json,
            r#"{"Struct":{"struct_name":"MyStruct","properties":[]}}"#
        );
    }

    #[test]
    fn property_value_map_serializes() {
        let v = PropertyValue::Map {
            key_type: "StrProperty".to_string(),
            value_type: "IntProperty".to_string(),
            entries: vec![MapEntry {
                key: PropertyValue::Str("k".to_string()),
                value: PropertyValue::Int(42),
            }],
        };
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(
            json,
            r#"{"Map":{"key_type":"StrProperty","value_type":"IntProperty","entries":[{"key":{"Str":"k"},"value":{"Int":42}}]}}"#
        );
    }

    #[test]
    fn property_value_set_serializes() {
        let v = PropertyValue::Set {
            inner_type: "NameProperty".to_string(),
            elements: vec![PropertyValue::Name("Tag_A".to_string())],
        };
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(
            json,
            r#"{"Set":{"inner_type":"NameProperty","elements":[{"Name":"Tag_A"}]}}"#
        );
    }
}
