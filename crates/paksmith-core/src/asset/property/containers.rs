//! Container property readers: ArrayProperty, StructProperty, MapProperty, SetProperty.
//!
//! Primitive elements are decoded by an internal `read_element_value`
//! helper. Per-collection readers (`read_array_value`,
//! `read_struct_value`, `read_map_value`, `read_set_value`) are
//! private and dispatched through the public [`read_container_value`]
//! entry point.

use std::io::{Read, Seek};

use byteorder::{LittleEndian, ReadBytesExt};

use crate::asset::AssetContext;
use crate::asset::property::primitives::{MapEntry, PropertyValue};
use crate::asset::property::tag::PropertyTag;
use crate::asset::read_asset_fstring;
use crate::error::{
    AssetAllocationContext, AssetParseFault, AssetWireField, CollectionKind, PaksmithError,
    try_reserve_asset,
};

use super::{MAX_COLLECTION_ELEMENTS, read_fname_pair, unexpected_eof};

/// Reads a single primitive element value for Array/Map/Set contents.
///
/// Returns `None` for types not yet decoded (`StructProperty`,
/// `TextProperty`, or any other unrecognised type). The caller falls
/// back to `Unknown { skipped_bytes }` via the outer `tag.size`.
///
/// **BoolProperty:** reads a raw `u8` — byte 0 = false, non-zero =
/// true. This is distinct from direct BoolProperty which reads
/// `tag.bool_val` with zero payload bytes.
///
/// `body_field` lets the caller name the wire context for EOF errors
/// (`ArrayElementBody` for arrays, `SetElement` for sets, `MapKey` /
/// `MapValue` for map entries) so operators can distinguish a
/// truncated array body from a truncated set body in diagnostics.
///
/// **Keep the match arms here in sync with [`is_handled_element_type`].**
/// Adding a new primitive requires updating both — the predicate
/// gates Array/Map/Set callers before consuming bytes, and any drift
/// between the two lists either fires the caller's `.expect` invariant
/// (predicate true but reader returns `None`) or silently skips the
/// new type (predicate false but reader would have handled it).
fn read_element_value<R: Read + Seek>(
    type_name: &str,
    body_field: AssetWireField,
    reader: &mut R,
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<Option<PropertyValue>> {
    Ok(Some(match type_name {
        "BoolProperty" => {
            let b = reader
                .read_u8()
                .map_err(|_| unexpected_eof(asset_path, body_field))?;
            PropertyValue::Bool(b != 0)
        }
        "Int8Property" => PropertyValue::Int8(
            reader
                .read_i8()
                .map_err(|_| unexpected_eof(asset_path, body_field))?,
        ),
        "Int16Property" => PropertyValue::Int16(
            reader
                .read_i16::<LittleEndian>()
                .map_err(|_| unexpected_eof(asset_path, body_field))?,
        ),
        "IntProperty" => PropertyValue::Int(
            reader
                .read_i32::<LittleEndian>()
                .map_err(|_| unexpected_eof(asset_path, body_field))?,
        ),
        "Int64Property" => PropertyValue::Int64(
            reader
                .read_i64::<LittleEndian>()
                .map_err(|_| unexpected_eof(asset_path, body_field))?,
        ),
        "UInt16Property" => PropertyValue::UInt16(
            reader
                .read_u16::<LittleEndian>()
                .map_err(|_| unexpected_eof(asset_path, body_field))?,
        ),
        "UInt32Property" => PropertyValue::UInt32(
            reader
                .read_u32::<LittleEndian>()
                .map_err(|_| unexpected_eof(asset_path, body_field))?,
        ),
        "UInt64Property" => PropertyValue::UInt64(
            reader
                .read_u64::<LittleEndian>()
                .map_err(|_| unexpected_eof(asset_path, body_field))?,
        ),
        "FloatProperty" => PropertyValue::Float(
            reader
                .read_f32::<LittleEndian>()
                .map_err(|_| unexpected_eof(asset_path, body_field))?,
        ),
        "DoubleProperty" => PropertyValue::Double(
            reader
                .read_f64::<LittleEndian>()
                .map_err(|_| unexpected_eof(asset_path, body_field))?,
        ),
        "StrProperty" => {
            // Asset-side wrapper: accepts len=0 as "" (CUE4Parse
            // semantics) and re-categorizes pak-side FStringMalformed
            // faults with asset_path context.
            PropertyValue::Str(read_asset_fstring(reader, asset_path)?)
        }
        "NameProperty" => {
            PropertyValue::Name(read_fname_pair(reader, ctx, asset_path, body_field)?)
        }
        "ByteProperty" => {
            let b = reader
                .read_u8()
                .map_err(|_| unexpected_eof(asset_path, body_field))?;
            PropertyValue::Byte(b)
        }
        "EnumProperty" => {
            let value = read_fname_pair(reader, ctx, asset_path, body_field)?;
            PropertyValue::Enum {
                type_name: String::new(),
                value,
            }
        }
        _ => return Ok(None),
    }))
}

/// Returns true if `type_name` is a primitive element type handled
/// by [`read_element_value`]. Used to gate Array/Map/Set reads
/// before consuming any bytes — the [`read_element_value`] match
/// arm for `BoolProperty` reads a `u8`, so a zero-length probe via
/// the reader would EOF and give a false negative.
///
/// **Keep this list in sync with [`read_element_value`]'s match
/// arms.** Adding a primitive requires updating both: dropping it
/// here makes Array/Map/Set callers skip the type entirely; dropping
/// it from the match fires the caller's `.expect` invariant.
fn is_handled_element_type(type_name: &str) -> bool {
    matches!(
        type_name,
        "BoolProperty"
            | "Int8Property"
            | "Int16Property"
            | "IntProperty"
            | "Int64Property"
            | "UInt16Property"
            | "UInt32Property"
            | "UInt64Property"
            | "FloatProperty"
            | "DoubleProperty"
            | "StrProperty"
            | "NameProperty"
            | "ByteProperty"
            | "EnumProperty"
    )
}

/// Reads an `ArrayProperty` body and returns `PropertyValue::Array`.
///
/// Returns `Ok(None)` if `tag.inner_type` is not handled (e.g.
/// `StructProperty`, `TextProperty`). No bytes are consumed in that
/// case; the caller skips the body via the outer `tag.size`.
///
/// Wire format: `i32 count` followed by `count` inline element
/// payloads (no per-element tag header). Bool elements read a raw
/// `u8`, distinct from direct `BoolProperty` which reads
/// `tag.bool_val`.
///
/// Guards:
/// - [`AssetParseFault::CollectionElementCountExceeded`] if the
///   on-wire count is negative or exceeds [`MAX_COLLECTION_ELEMENTS`].
/// - [`AssetParseFault::AllocationFailed`] via [`try_reserve_asset`]
///   if the element-vector reservation fails.
#[allow(
    clippy::cast_sign_loss,
    reason = "i32 -> usize casts on `count` are guarded by the `count < 0` short-circuit and the MAX_COLLECTION_ELEMENTS upper bound before they fire"
)]
fn read_array_value<R: Read + Seek>(
    tag: &PropertyTag,
    reader: &mut R,
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<Option<PropertyValue>> {
    if !is_handled_element_type(&tag.inner_type) {
        return Ok(None);
    }

    let count = reader
        .read_i32::<LittleEndian>()
        .map_err(|_| unexpected_eof(asset_path, AssetWireField::ArrayElementCount))?;

    if count < 0 || count as usize > MAX_COLLECTION_ELEMENTS {
        return Err(PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::CollectionElementCountExceeded {
                collection: CollectionKind::Array,
                count,
                limit: MAX_COLLECTION_ELEMENTS,
            },
        });
    }

    let count_usize = count as usize;
    let mut elements: Vec<PropertyValue> = Vec::new();
    try_reserve_asset(
        &mut elements,
        count_usize,
        asset_path,
        AssetAllocationContext::CollectionElements,
    )?;

    for _ in 0..count_usize {
        let elem = read_element_value(
            &tag.inner_type,
            AssetWireField::ArrayElementBody,
            reader,
            ctx,
            asset_path,
        )?
        .expect("inner_type was validated above by is_handled_element_type");
        elements.push(elem);
    }

    Ok(Some(PropertyValue::Array {
        inner_type: tag.inner_type.clone(),
        elements,
    }))
}

/// Reads a `StructProperty` body and returns `PropertyValue::Struct`.
///
/// Recurses into `super::read_properties` with `depth + 1`. The
/// recursive call is bounded by both `MAX_PROPERTY_DEPTH` (inside
/// `read_properties`) and `expected_end` (the struct's byte boundary
/// derived from `value_start + tag.size`), so a maliciously nested
/// struct tree can't blow the stack and a runaway tagged stream
/// can't read past the struct's declared size.
fn read_struct_value<R: Read + Seek>(
    tag: &PropertyTag,
    reader: &mut R,
    ctx: &AssetContext,
    depth: usize,
    expected_end: u64,
    asset_path: &str,
) -> crate::Result<PropertyValue> {
    let properties = super::read_properties(reader, ctx, depth + 1, expected_end, asset_path)?;
    Ok(PropertyValue::Struct {
        struct_name: tag.struct_name.clone(),
        properties,
    })
}

/// Reads a `MapProperty` body and returns `PropertyValue::Map`.
///
/// Returns `Ok(None)` if `tag.inner_type` (key type) or
/// `tag.value_type` is unhandled. No bytes are consumed in that
/// case; the caller skips via `tag.size`.
///
/// Wire format: `i32 num_keys_to_remove` + `num_keys_to_remove × key
/// body` + `i32 count` + `count × (key body + value body)`. The
/// "keys to remove" entries are parsed (their bytes are consumed)
/// and discarded — they represent delta-serialization information
/// that paksmith doesn't surface. Cooked assets normally have
/// `num_keys_to_remove == 0`, but the non-zero case is real and
/// must consume the bytes or downstream fields misalign.
///
/// Guards: per-prefix cap checks via
/// [`AssetParseFault::CollectionElementCountExceeded`]
/// (`CollectionKind::MapNumToRemove` / `CollectionKind::Map`);
/// `Vec<MapEntry>` reservation via [`try_reserve_asset`].
#[allow(
    clippy::cast_sign_loss,
    reason = "i32 -> usize casts on counts are guarded by the < 0 short-circuit and the MAX_COLLECTION_ELEMENTS upper bound before they fire"
)]
fn read_map_value<R: Read + Seek>(
    tag: &PropertyTag,
    reader: &mut R,
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<Option<PropertyValue>> {
    if !is_handled_element_type(&tag.inner_type) || !is_handled_element_type(&tag.value_type) {
        return Ok(None);
    }

    // num_keys_to_remove: delta-serialization prefix. The keys
    // themselves follow as parsed bodies and MUST be consumed
    // (not skipped as zero bytes). Cooked assets usually have
    // this at 0, but real-world non-zero cases must still parse.
    let num_keys_to_remove = reader
        .read_i32::<LittleEndian>()
        .map_err(|_| unexpected_eof(asset_path, AssetWireField::MapNumToRemove))?;
    if num_keys_to_remove < 0 || num_keys_to_remove as usize > MAX_COLLECTION_ELEMENTS {
        return Err(PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::CollectionElementCountExceeded {
                collection: CollectionKind::MapNumToRemove,
                count: num_keys_to_remove,
                limit: MAX_COLLECTION_ELEMENTS,
            },
        });
    }
    for _ in 0..(num_keys_to_remove as usize) {
        // Parse and discard. The key body uses the same wire format
        // as the keys that follow in the main count loop. EOF here
        // is tagged MapKey because the discarded entries share the
        // same byte shape as live keys.
        let _ = read_element_value(
            &tag.inner_type,
            AssetWireField::MapKey,
            reader,
            ctx,
            asset_path,
        )?
        .expect("key type was validated above by is_handled_element_type");
    }

    let count = reader
        .read_i32::<LittleEndian>()
        .map_err(|_| unexpected_eof(asset_path, AssetWireField::MapEntryCount))?;

    if count < 0 || count as usize > MAX_COLLECTION_ELEMENTS {
        return Err(PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::CollectionElementCountExceeded {
                collection: CollectionKind::Map,
                count,
                limit: MAX_COLLECTION_ELEMENTS,
            },
        });
    }

    let count_usize = count as usize;
    let mut entries: Vec<MapEntry> = Vec::new();
    try_reserve_asset(
        &mut entries,
        count_usize,
        asset_path,
        AssetAllocationContext::CollectionElements,
    )?;

    for _ in 0..count_usize {
        let key = read_element_value(
            &tag.inner_type,
            AssetWireField::MapKey,
            reader,
            ctx,
            asset_path,
        )?
        .expect("key type was validated above by is_handled_element_type");
        let value = read_element_value(
            &tag.value_type,
            AssetWireField::MapValue,
            reader,
            ctx,
            asset_path,
        )?
        .expect("value type was validated above by is_handled_element_type");
        entries.push(MapEntry { key, value });
    }

    Ok(Some(PropertyValue::Map {
        key_type: tag.inner_type.clone(),
        value_type: tag.value_type.clone(),
        entries,
    }))
}

/// Reads a `SetProperty` body and returns `PropertyValue::Set`.
///
/// Returns `Ok(None)` if `tag.inner_type` is unhandled. Wire format
/// matches MapProperty's shape but with a single element body
/// instead of a key/value pair: `i32 num_elements_to_remove` +
/// `num_elements_to_remove × element body` + `i32 count` + `count ×
/// element body`. The "elements to remove" entries are parsed (bytes
/// consumed) and discarded.
///
/// Guards: cap checks via
/// [`AssetParseFault::CollectionElementCountExceeded`]
/// (`CollectionKind::SetNumToRemove` / `CollectionKind::Set`);
/// `Vec<PropertyValue>` reservation via [`try_reserve_asset`].
#[allow(
    clippy::cast_sign_loss,
    reason = "i32 -> usize casts on counts are guarded by the < 0 short-circuit and the MAX_COLLECTION_ELEMENTS upper bound before they fire"
)]
fn read_set_value<R: Read + Seek>(
    tag: &PropertyTag,
    reader: &mut R,
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<Option<PropertyValue>> {
    if !is_handled_element_type(&tag.inner_type) {
        return Ok(None);
    }

    let num_elements_to_remove = reader
        .read_i32::<LittleEndian>()
        .map_err(|_| unexpected_eof(asset_path, AssetWireField::SetNumToRemove))?;
    if num_elements_to_remove < 0 || num_elements_to_remove as usize > MAX_COLLECTION_ELEMENTS {
        return Err(PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::CollectionElementCountExceeded {
                collection: CollectionKind::SetNumToRemove,
                count: num_elements_to_remove,
                limit: MAX_COLLECTION_ELEMENTS,
            },
        });
    }
    for _ in 0..(num_elements_to_remove as usize) {
        let _ = read_element_value(
            &tag.inner_type,
            AssetWireField::SetElement,
            reader,
            ctx,
            asset_path,
        )?
        .expect("inner_type was validated above by is_handled_element_type");
    }

    let count = reader
        .read_i32::<LittleEndian>()
        .map_err(|_| unexpected_eof(asset_path, AssetWireField::SetElementCount))?;

    if count < 0 || count as usize > MAX_COLLECTION_ELEMENTS {
        return Err(PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::CollectionElementCountExceeded {
                collection: CollectionKind::Set,
                count,
                limit: MAX_COLLECTION_ELEMENTS,
            },
        });
    }

    let count_usize = count as usize;
    let mut elements: Vec<PropertyValue> = Vec::new();
    try_reserve_asset(
        &mut elements,
        count_usize,
        asset_path,
        AssetAllocationContext::CollectionElements,
    )?;

    for _ in 0..count_usize {
        let elem = read_element_value(
            &tag.inner_type,
            AssetWireField::SetElement,
            reader,
            ctx,
            asset_path,
        )?
        .expect("inner_type was validated above by is_handled_element_type");
        elements.push(elem);
    }

    Ok(Some(PropertyValue::Set {
        inner_type: tag.inner_type.clone(),
        elements,
    }))
}

/// Public entry point for container property reading.
///
/// Dispatches to the appropriate reader based on `tag.type_name`:
/// - `"ArrayProperty"` → `read_array_value`
/// - `"StructProperty"` → `read_struct_value` (always returns `Some`)
/// - `"MapProperty"` → `read_map_value`
/// - `"SetProperty"` → `read_set_value`
/// - anything else → `Ok(None)`
///
/// Returns `Ok(None)` when the container type is unknown OR when the
/// inner type(s) are unhandled. In both cases the caller falls back
/// to `PropertyValue::Unknown { skipped_bytes }` via `tag.size`.
///
/// `depth` and `expected_end` are forwarded to `read_struct_value`
/// so its recursion into `super::read_properties` inherits the
/// caller's `MAX_PROPERTY_DEPTH` and byte-boundary guards.
pub fn read_container_value<R: Read + Seek>(
    tag: &PropertyTag,
    reader: &mut R,
    ctx: &AssetContext,
    depth: usize,
    expected_end: u64,
    asset_path: &str,
) -> crate::Result<Option<PropertyValue>> {
    match tag.type_name.as_str() {
        "ArrayProperty" => read_array_value(tag, reader, ctx, asset_path),
        "StructProperty" => {
            read_struct_value(tag, reader, ctx, depth, expected_end, asset_path).map(Some)
        }
        "MapProperty" => read_map_value(tag, reader, ctx, asset_path),
        "SetProperty" => read_set_value(tag, reader, ctx, asset_path),
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::property::primitives::PropertyValue;
    use crate::asset::property::test_utils::make_ctx;
    use std::io::Cursor;

    fn make_array_tag(inner_type: &str, size: i32) -> PropertyTag {
        PropertyTag {
            name: "Prop".to_string(),
            type_name: "ArrayProperty".to_string(),
            size,
            array_index: 0,
            bool_val: false,
            struct_name: String::new(),
            struct_guid: [0u8; 16],
            enum_name: String::new(),
            inner_type: inner_type.to_string(),
            value_type: String::new(),
            guid: None,
        }
    }

    fn make_struct_tag(struct_name: &str, size: i32) -> PropertyTag {
        PropertyTag {
            name: "Prop".to_string(),
            type_name: "StructProperty".to_string(),
            size,
            array_index: 0,
            bool_val: false,
            struct_name: struct_name.to_string(),
            struct_guid: [0u8; 16],
            enum_name: String::new(),
            inner_type: String::new(),
            value_type: String::new(),
            guid: None,
        }
    }

    fn make_map_tag(key_type: &str, value_type: &str, size: i32) -> PropertyTag {
        PropertyTag {
            name: "Prop".to_string(),
            type_name: "MapProperty".to_string(),
            size,
            array_index: 0,
            bool_val: false,
            struct_name: String::new(),
            struct_guid: [0u8; 16],
            enum_name: String::new(),
            inner_type: key_type.to_string(),
            value_type: value_type.to_string(),
            guid: None,
        }
    }

    fn make_set_tag(inner_type: &str, size: i32) -> PropertyTag {
        PropertyTag {
            name: "Prop".to_string(),
            type_name: "SetProperty".to_string(),
            size,
            array_index: 0,
            bool_val: false,
            struct_name: String::new(),
            struct_guid: [0u8; 16],
            enum_name: String::new(),
            inner_type: inner_type.to_string(),
            value_type: String::new(),
            guid: None,
        }
    }

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
    fn element_byte_reads_u8() {
        let ctx = make_ctx(&[]);
        let mut r = Cursor::new(vec![0xABu8]);
        let v = read_element_value(
            "ByteProperty",
            AssetWireField::ArrayElementBody,
            &mut r,
            &ctx,
            "x.uasset",
        )
        .unwrap()
        .unwrap();
        assert_eq!(v, PropertyValue::Byte(0xAB));
    }

    #[test]
    fn element_enum_reads_fname() {
        // EnumProperty element: FName (index=1, number=0) → "EColor__Red"
        // type_name is empty because no per-element tag carries the enum class name.
        let ctx = make_ctx(&["None", "EColor__Red"]);
        let mut bytes = 1i32.to_le_bytes().to_vec();
        bytes.extend_from_slice(&0i32.to_le_bytes());
        let mut r = Cursor::new(bytes);
        let v = read_element_value(
            "EnumProperty",
            AssetWireField::ArrayElementBody,
            &mut r,
            &ctx,
            "x.uasset",
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            v,
            PropertyValue::Enum {
                type_name: String::new(),
                value: "EColor__Red".to_string(),
            }
        );
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

    #[test]
    fn element_int8() {
        let ctx = make_ctx(&[]);
        let mut r = Cursor::new(vec![0xFFu8]); // -1 as i8
        let v = read_element_value(
            "Int8Property",
            AssetWireField::ArrayElementBody,
            &mut r,
            &ctx,
            "x.uasset",
        )
        .unwrap()
        .unwrap();
        assert_eq!(v, PropertyValue::Int8(-1));
    }

    #[test]
    fn element_int16() {
        let ctx = make_ctx(&[]);
        let mut r = Cursor::new(i16::MIN.to_le_bytes().to_vec());
        let v = read_element_value(
            "Int16Property",
            AssetWireField::ArrayElementBody,
            &mut r,
            &ctx,
            "x.uasset",
        )
        .unwrap()
        .unwrap();
        assert_eq!(v, PropertyValue::Int16(i16::MIN));
    }

    #[test]
    fn element_uint16() {
        let ctx = make_ctx(&[]);
        let mut r = Cursor::new(u16::MAX.to_le_bytes().to_vec());
        let v = read_element_value(
            "UInt16Property",
            AssetWireField::ArrayElementBody,
            &mut r,
            &ctx,
            "x.uasset",
        )
        .unwrap()
        .unwrap();
        assert_eq!(v, PropertyValue::UInt16(u16::MAX));
    }

    #[test]
    fn element_uint64() {
        let ctx = make_ctx(&[]);
        let mut r = Cursor::new(u64::MAX.to_le_bytes().to_vec());
        let v = read_element_value(
            "UInt64Property",
            AssetWireField::ArrayElementBody,
            &mut r,
            &ctx,
            "x.uasset",
        )
        .unwrap()
        .unwrap();
        assert_eq!(v, PropertyValue::UInt64(u64::MAX));
    }

    #[test]
    fn eof_tags_body_field() {
        use crate::error::{AssetParseFault, PaksmithError};
        let ctx = make_ctx(&[]);
        let mut r = Cursor::new(vec![]);
        let err = read_element_value(
            "IntProperty",
            AssetWireField::MapKey,
            &mut r,
            &ctx,
            "x.uasset",
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::UnexpectedEof {
                        field: AssetWireField::MapKey
                    },
                    ..
                }
            ),
            "expected UnexpectedEof tagged MapKey, got {err:?}",
        );
    }

    #[test]
    fn array_of_int32s() {
        let ctx = make_ctx(&[]);
        let mut bytes = 3i32.to_le_bytes().to_vec();
        bytes.extend_from_slice(&10i32.to_le_bytes());
        bytes.extend_from_slice(&20i32.to_le_bytes());
        bytes.extend_from_slice(&30i32.to_le_bytes());
        let mut r = Cursor::new(bytes);
        let tag = make_array_tag("IntProperty", 4 + 3 * 4);
        let v = read_array_value(&tag, &mut r, &ctx, "x.uasset")
            .unwrap()
            .unwrap();
        assert_eq!(
            v,
            PropertyValue::Array {
                inner_type: "IntProperty".to_string(),
                elements: vec![
                    PropertyValue::Int(10),
                    PropertyValue::Int(20),
                    PropertyValue::Int(30)
                ],
            }
        );
    }

    #[test]
    fn array_empty() {
        let ctx = make_ctx(&[]);
        let mut r = Cursor::new(0i32.to_le_bytes().to_vec());
        let tag = make_array_tag("FloatProperty", 4);
        let v = read_array_value(&tag, &mut r, &ctx, "x.uasset")
            .unwrap()
            .unwrap();
        assert_eq!(
            v,
            PropertyValue::Array {
                inner_type: "FloatProperty".to_string(),
                elements: vec![],
            }
        );
    }

    #[test]
    fn array_of_bools_reads_u8_not_tag_bool_val() {
        let ctx = make_ctx(&[]);
        let mut bytes = 2i32.to_le_bytes().to_vec();
        bytes.push(0x01);
        bytes.push(0x00);
        let mut r = Cursor::new(bytes);
        let tag = make_array_tag("BoolProperty", 4 + 2);
        let v = read_array_value(&tag, &mut r, &ctx, "x.uasset")
            .unwrap()
            .unwrap();
        assert_eq!(
            v,
            PropertyValue::Array {
                inner_type: "BoolProperty".to_string(),
                elements: vec![PropertyValue::Bool(true), PropertyValue::Bool(false)],
            }
        );
    }

    #[test]
    fn array_struct_inner_type_returns_none() {
        let ctx = make_ctx(&[]);
        let mut r = Cursor::new(vec![]);
        let tag = make_array_tag("StructProperty", 64);
        let v = read_array_value(&tag, &mut r, &ctx, "x.uasset").unwrap();
        assert!(v.is_none());
        // Confirm zero bytes consumed.
        assert_eq!(r.position(), 0);
    }

    #[test]
    fn array_negative_count_rejected() {
        use crate::error::{AssetParseFault, CollectionKind, PaksmithError};
        let ctx = make_ctx(&[]);
        let mut r = Cursor::new((-1i32).to_le_bytes().to_vec());
        let tag = make_array_tag("IntProperty", 4);
        let err = read_array_value(&tag, &mut r, &ctx, "x.uasset").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::CollectionElementCountExceeded {
                    collection: CollectionKind::Array,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn array_count_exceeds_cap_rejected() {
        use crate::asset::property::MAX_COLLECTION_ELEMENTS;
        use crate::error::{AssetParseFault, CollectionKind, PaksmithError};
        let ctx = make_ctx(&[]);
        let over_cap = i32::try_from(MAX_COLLECTION_ELEMENTS + 1).expect("cap + 1 fits in i32");
        let mut r = Cursor::new(over_cap.to_le_bytes().to_vec());
        let tag = make_array_tag("IntProperty", 4 + over_cap * 4);
        let err = read_array_value(&tag, &mut r, &ctx, "x.uasset").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::CollectionElementCountExceeded {
                    collection: CollectionKind::Array,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn struct_with_one_int_property() {
        // names: 0=None, 1=MyStruct, 2=IntProperty, 3=Count
        let ctx = make_ctx(&["None", "MyStruct", "IntProperty", "Count"]);

        let mut bytes: Vec<u8> = Vec::new();

        // FPropertyTag for "Count: IntProperty":
        // Name FName(3, 0) = "Count"
        bytes.extend_from_slice(&3i32.to_le_bytes());
        bytes.extend_from_slice(&0i32.to_le_bytes());
        // Type FName(2, 0) = "IntProperty"
        bytes.extend_from_slice(&2i32.to_le_bytes());
        bytes.extend_from_slice(&0i32.to_le_bytes());
        bytes.extend_from_slice(&4i32.to_le_bytes()); // Size: 4
        bytes.extend_from_slice(&0i32.to_le_bytes()); // ArrayIndex: 0
        bytes.push(0u8); // HasPropertyGuid: 0
        bytes.extend_from_slice(&99i32.to_le_bytes()); // Value: i32 = 99

        // "None" terminator (FName index=0, number=0)
        bytes.extend_from_slice(&0i32.to_le_bytes());
        bytes.extend_from_slice(&0i32.to_le_bytes());

        let total_size = i32::try_from(bytes.len()).expect("body fits in i32");
        let expected_end = bytes.len() as u64;
        let mut r = Cursor::new(bytes);

        let tag = make_struct_tag("MyStruct", total_size);
        let v = read_struct_value(&tag, &mut r, &ctx, 0, expected_end, "x.uasset").unwrap();

        assert_eq!(
            v,
            PropertyValue::Struct {
                struct_name: "MyStruct".to_string(),
                properties: vec![crate::asset::property::primitives::Property {
                    name: "Count".to_string(),
                    array_index: 0,
                    guid: None,
                    value: PropertyValue::Int(99),
                }],
            }
        );
    }

    #[test]
    fn struct_empty() {
        let ctx = make_ctx(&["None"]);
        // Just the "None" terminator
        let mut bytes = 0i32.to_le_bytes().to_vec();
        bytes.extend_from_slice(&0i32.to_le_bytes());
        let expected_end = bytes.len() as u64;
        let mut r = Cursor::new(bytes);
        let tag = make_struct_tag("EmptyStruct", 8);
        let v = read_struct_value(&tag, &mut r, &ctx, 0, expected_end, "x.uasset").unwrap();
        assert_eq!(
            v,
            PropertyValue::Struct {
                struct_name: "EmptyStruct".to_string(),
                properties: vec![],
            }
        );
    }

    #[test]
    fn map_int_to_int() {
        use crate::asset::property::primitives::MapEntry;
        let ctx = make_ctx(&[]);
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&0i32.to_le_bytes()); // num_to_remove
        bytes.extend_from_slice(&2i32.to_le_bytes()); // count
        bytes.extend_from_slice(&10i32.to_le_bytes()); // key 0
        bytes.extend_from_slice(&100i32.to_le_bytes()); // value 0
        bytes.extend_from_slice(&20i32.to_le_bytes()); // key 1
        bytes.extend_from_slice(&200i32.to_le_bytes()); // value 1
        let mut r = Cursor::new(bytes);
        let tag = make_map_tag("IntProperty", "IntProperty", 8 + 2 * 8);
        let v = read_map_value(&tag, &mut r, &ctx, "x.uasset")
            .unwrap()
            .unwrap();
        assert_eq!(
            v,
            PropertyValue::Map {
                key_type: "IntProperty".to_string(),
                value_type: "IntProperty".to_string(),
                entries: vec![
                    MapEntry {
                        key: PropertyValue::Int(10),
                        value: PropertyValue::Int(100)
                    },
                    MapEntry {
                        key: PropertyValue::Int(20),
                        value: PropertyValue::Int(200)
                    },
                ],
            }
        );
    }

    #[test]
    fn map_nonzero_num_to_remove_consumes_keys() {
        let ctx = make_ctx(&[]);
        // num_keys_to_remove=2, then 2 × i32 key bodies (parsed and discarded),
        // then count=0.
        let mut bytes = 2i32.to_le_bytes().to_vec();
        bytes.extend_from_slice(&42i32.to_le_bytes()); // discarded key 0
        bytes.extend_from_slice(&43i32.to_le_bytes()); // discarded key 1
        bytes.extend_from_slice(&0i32.to_le_bytes()); // count = 0
        let mut r = Cursor::new(bytes);
        let tag = make_map_tag("IntProperty", "IntProperty", 16);
        let v = read_map_value(&tag, &mut r, &ctx, "x.uasset")
            .unwrap()
            .unwrap();
        assert_eq!(
            v,
            PropertyValue::Map {
                key_type: "IntProperty".to_string(),
                value_type: "IntProperty".to_string(),
                entries: vec![],
            }
        );
        // All 16 bytes should have been consumed (4 + 2×4 + 4 = 16).
        assert_eq!(r.position(), 16);
    }

    #[test]
    fn map_struct_key_type_returns_none() {
        let ctx = make_ctx(&[]);
        let mut r = Cursor::new(vec![]);
        let tag = make_map_tag("StructProperty", "IntProperty", 32);
        let v = read_map_value(&tag, &mut r, &ctx, "x.uasset").unwrap();
        assert!(v.is_none());
        assert_eq!(r.position(), 0);
    }

    #[test]
    fn map_struct_value_type_returns_none() {
        let ctx = make_ctx(&[]);
        let mut r = Cursor::new(vec![]);
        let tag = make_map_tag("IntProperty", "StructProperty", 32);
        let v = read_map_value(&tag, &mut r, &ctx, "x.uasset").unwrap();
        assert!(v.is_none());
        assert_eq!(r.position(), 0);
    }

    #[test]
    fn map_negative_count_rejected() {
        use crate::error::{AssetParseFault, CollectionKind, PaksmithError};
        let ctx = make_ctx(&[]);
        let mut bytes = 0i32.to_le_bytes().to_vec(); // num_to_remove
        bytes.extend_from_slice(&(-5i32).to_le_bytes()); // count
        let mut r = Cursor::new(bytes);
        let tag = make_map_tag("IntProperty", "IntProperty", 8);
        let err = read_map_value(&tag, &mut r, &ctx, "x.uasset").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::CollectionElementCountExceeded {
                    collection: CollectionKind::Map,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn set_of_names() {
        // names: 0=None, 1=Tag_A, 2=Tag_B
        let ctx = make_ctx(&["None", "Tag_A", "Tag_B"]);
        let mut bytes = 0i32.to_le_bytes().to_vec(); // num_to_remove
        bytes.extend_from_slice(&2i32.to_le_bytes()); // count
        bytes.extend_from_slice(&1i32.to_le_bytes()); // FName index for Tag_A
        bytes.extend_from_slice(&0i32.to_le_bytes()); // FName number
        bytes.extend_from_slice(&2i32.to_le_bytes()); // FName index for Tag_B
        bytes.extend_from_slice(&0i32.to_le_bytes()); // FName number
        let mut r = Cursor::new(bytes);
        let tag = make_set_tag("NameProperty", 8 + 2 * 8);
        let v = read_set_value(&tag, &mut r, &ctx, "x.uasset")
            .unwrap()
            .unwrap();
        assert_eq!(
            v,
            PropertyValue::Set {
                inner_type: "NameProperty".to_string(),
                elements: vec![
                    PropertyValue::Name("Tag_A".to_string()),
                    PropertyValue::Name("Tag_B".to_string()),
                ],
            }
        );
    }

    #[test]
    fn set_struct_inner_type_returns_none() {
        let ctx = make_ctx(&[]);
        let mut r = Cursor::new(vec![]);
        let tag = make_set_tag("StructProperty", 32);
        let v = read_set_value(&tag, &mut r, &ctx, "x.uasset").unwrap();
        assert!(v.is_none());
        assert_eq!(r.position(), 0);
    }

    #[test]
    fn set_negative_count_rejected() {
        use crate::error::{AssetParseFault, CollectionKind, PaksmithError};
        let ctx = make_ctx(&[]);
        let mut bytes = 0i32.to_le_bytes().to_vec(); // num_to_remove
        bytes.extend_from_slice(&(-1i32).to_le_bytes());
        let mut r = Cursor::new(bytes);
        let tag = make_set_tag("IntProperty", 8);
        let err = read_set_value(&tag, &mut r, &ctx, "x.uasset").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::CollectionElementCountExceeded {
                    collection: CollectionKind::Set,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn map_num_to_remove_exceeds_cap_rejected() {
        use crate::asset::property::MAX_COLLECTION_ELEMENTS;
        use crate::error::{AssetParseFault, CollectionKind, PaksmithError};
        let ctx = make_ctx(&[]);
        let over_cap = i32::try_from(MAX_COLLECTION_ELEMENTS + 1).expect("cap + 1 fits in i32");
        let bytes = over_cap.to_le_bytes().to_vec();
        let mut r = Cursor::new(bytes);
        let tag = make_map_tag("IntProperty", "IntProperty", 4);
        let err = read_map_value(&tag, &mut r, &ctx, "x.uasset").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::CollectionElementCountExceeded {
                    collection: CollectionKind::MapNumToRemove,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn set_num_to_remove_exceeds_cap_rejected() {
        use crate::asset::property::MAX_COLLECTION_ELEMENTS;
        use crate::error::{AssetParseFault, CollectionKind, PaksmithError};
        let ctx = make_ctx(&[]);
        let over_cap = i32::try_from(MAX_COLLECTION_ELEMENTS + 1).expect("cap + 1 fits in i32");
        let bytes = over_cap.to_le_bytes().to_vec();
        let mut r = Cursor::new(bytes);
        let tag = make_set_tag("IntProperty", 4);
        let err = read_set_value(&tag, &mut r, &ctx, "x.uasset").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::CollectionElementCountExceeded {
                    collection: CollectionKind::SetNumToRemove,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn set_nonzero_num_to_remove_consumes_elements() {
        let ctx = make_ctx(&[]);
        // num_elements_to_remove=2, then 2 × i32 element bodies (parsed
        // and discarded), then count=0.
        let mut bytes = 2i32.to_le_bytes().to_vec();
        bytes.extend_from_slice(&7i32.to_le_bytes()); // discarded element 0
        bytes.extend_from_slice(&8i32.to_le_bytes()); // discarded element 1
        bytes.extend_from_slice(&0i32.to_le_bytes()); // count = 0
        let mut r = Cursor::new(bytes);
        let tag = make_set_tag("IntProperty", 16);
        let v = read_set_value(&tag, &mut r, &ctx, "x.uasset")
            .unwrap()
            .unwrap();
        assert_eq!(
            v,
            PropertyValue::Set {
                inner_type: "IntProperty".to_string(),
                elements: vec![],
            }
        );
        // All 16 bytes consumed: 4 (num_to_remove) + 2×4 (discarded) + 4 (count).
        assert_eq!(r.position(), 16);
    }

    #[test]
    fn container_value_dispatches_array() {
        let ctx = make_ctx(&[]);
        // count=1, element=42
        let mut bytes = 1i32.to_le_bytes().to_vec();
        bytes.extend_from_slice(&42i32.to_le_bytes());
        let expected_end = bytes.len() as u64;
        let mut r = Cursor::new(bytes);
        let tag = make_array_tag("IntProperty", 4 + 4);
        let v = read_container_value(&tag, &mut r, &ctx, 0, expected_end, "x.uasset")
            .unwrap()
            .unwrap();
        assert_eq!(
            v,
            PropertyValue::Array {
                inner_type: "IntProperty".to_string(),
                elements: vec![PropertyValue::Int(42)],
            }
        );
    }

    #[test]
    fn container_value_unknown_type_returns_none() {
        let ctx = make_ctx(&[]);
        let mut r = Cursor::new(vec![]);
        let tag = PropertyTag {
            name: "X".to_string(),
            type_name: "SoftObjectPath".to_string(),
            size: 0,
            array_index: 0,
            bool_val: false,
            struct_name: String::new(),
            struct_guid: [0u8; 16],
            enum_name: String::new(),
            inner_type: String::new(),
            value_type: String::new(),
            guid: None,
        };
        let v = read_container_value(&tag, &mut r, &ctx, 0, 0, "x.uasset").unwrap();
        assert!(v.is_none());
    }
}
