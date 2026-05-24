//! `FPropertyTag` wire reader.
//!
//! Phase 2b layout (UE 4.21+, `FileVersionUE4 ≥ 504`):
//!
//! ```text
//! Name:            FName (i32 index, i32 number)
//!                  → None terminator when index==0 && number==0
//! Type:            FName
//! Size:            i32   (payload bytes; 0 for BoolProperty)
//! ArrayIndex:      i32
//! [type extras]    (BoolProperty: u8 boolVal;
//!                   StructProperty: FName struct_name + [u8; 16] struct_guid;
//!                   ByteProperty|EnumProperty: FName enum_name;
//!                   ArrayProperty|SetProperty: FName inner_type;
//!                   MapProperty: FName inner_type + FName value_type)
//! HasPropertyGuid: u8
//! [PropertyGuid]:  [u8; 16] if HasPropertyGuid != 0
//! ```
//!
//! `VER_UE4_STRUCT_GUID_IN_PROPERTY_TAG` (441) and
//! `VER_UE4_PROPERTY_GUID_IN_PROPERTY_TAG` (503) are both below
//! Phase 2a's floor of 504, so both are always present.

use std::io::Read;

use byteorder::{LittleEndian, ReadBytesExt};

use crate::asset::AssetContext;
use crate::error::{AssetParseFault, AssetWireField, BoundsUnit, PaksmithError};

use super::{read_fname_pair, unexpected_eof};

/// Maximum allowed size for a single property value payload.
/// Caps the per-tag discard budget so a single `Unknown`-type skip
/// cannot drain more than 16 MiB from the reader. (The previous
/// `Vec`-based skip path allocated that buffer; #366 switched to
/// `io::copy` → `io::sink` so the cap now bounds the I/O budget
/// rather than the heap.)
pub const MAX_PROPERTY_TAG_SIZE: i32 = 16 * 1024 * 1024;

/// Decoded `FPropertyTag` header.
///
/// All type-specific fields (`struct_name`, `enum_name`, etc.) are
/// populated during tag reading regardless of whether the type is
/// handled — Phase 2c's container readers rely on `inner_type`
/// already being resolved.
#[derive(Debug, Clone)]
pub struct PropertyTag {
    /// Resolved property name (FName base + optional `_N` suffix).
    pub(crate) name: String,
    /// Resolved type name (e.g. `"BoolProperty"`, `"IntProperty"`).
    pub(crate) type_name: String,
    /// Serialized value size in bytes (0 for `BoolProperty`).
    pub size: i32,
    /// Array element index (0 for non-array properties).
    pub array_index: i32,
    /// Boolean value for `BoolProperty`; `false` otherwise.
    pub bool_val: bool,
    /// Struct type name for `StructProperty`; empty string otherwise.
    pub(crate) struct_name: String,
    /// Struct type GUID for `StructProperty`; zeroed otherwise.
    pub struct_guid: [u8; 16],
    /// Enum type name for `ByteProperty` / `EnumProperty`; empty otherwise.
    pub(crate) enum_name: String,
    /// Inner element type for `ArrayProperty` / `SetProperty` /
    /// `MapProperty` key.
    pub(crate) inner_type: String,
    /// Value type for `MapProperty`; empty otherwise.
    pub(crate) value_type: String,
    /// Optional per-property GUID (`HasPropertyGuid` byte was non-zero).
    pub guid: Option<[u8; 16]>,
}

impl PropertyTag {
    /// Resolved property name (FName base + optional `_N` suffix).
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Resolved type name (e.g. `"BoolProperty"`, `"IntProperty"`).
    #[must_use]
    pub fn type_name(&self) -> &str {
        &self.type_name
    }
    /// Struct type name for `StructProperty`; empty for other types.
    #[must_use]
    pub fn struct_name(&self) -> &str {
        &self.struct_name
    }
    /// Enum type name for `ByteProperty` / `EnumProperty`; empty otherwise.
    #[must_use]
    pub fn enum_name(&self) -> &str {
        &self.enum_name
    }
    /// Inner element type for `ArrayProperty` / `SetProperty` /
    /// `MapProperty` key.
    #[must_use]
    pub fn inner_type(&self) -> &str {
        &self.inner_type
    }
    /// Value type for `MapProperty`; empty otherwise.
    #[must_use]
    pub fn value_type(&self) -> &str {
        &self.value_type
    }
}

/// Test-only construction of a `PropertyTag` from raw field values.
/// Gated behind `__test_utils` because `PropertyTag` is otherwise
/// `pub(crate)`-constructed via the wire-format parser; tests that
/// need to drive readers with synthetic tags use this builder.
///
/// `Default` is implemented and exposed under the same feature flag
/// so callers can `..PropertyTag::default()` spread only the fields
/// they care about.
///
/// **Caution:** prefer the [`PropertyTag::for_test`] +`.with_*`
/// builder chain for the string fields (`name`, `enum_name`,
/// `struct_name`, `inner_type`, `value_type`). Those are the
/// migration target for issue #365 (`String → Arc<str>`);
/// spreading `..Default::default()` to fill them bypasses the
/// builder's type-indirection layer and forces a caller-side change
/// when the field types flip.
#[cfg(any(test, feature = "__test_utils"))]
impl Default for PropertyTag {
    fn default() -> Self {
        Self {
            name: String::new(),
            type_name: String::new(),
            size: 0,
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
}

#[cfg(any(test, feature = "__test_utils"))]
impl PropertyTag {
    /// Test-only builder. Sets `name` and `type_name`; defaults
    /// everything else. Use the `.with_*` chainable setters for
    /// additional fields.
    ///
    /// The setter family has two rationales:
    /// - String fields (`with_name`, `with_struct_name`,
    ///   `with_enum_name`, `with_inner_type`, `with_value_type`) sit
    ///   between the test sites and the field types so issue #365's
    ///   `String → Arc<str>` migration is invisible to callers.
    /// - Non-string ergonomic setters (`with_bool_val` for the
    ///   `BoolProperty`-only inline payload) just avoid post-
    ///   construction field-assignment ceremony.
    #[must_use]
    pub fn for_test(name: &str, type_name: &str, size: i32) -> Self {
        Self {
            name: name.to_string(),
            type_name: type_name.to_string(),
            size,
            ..Self::default()
        }
    }

    /// Test-only chainable setter for `struct_name`.
    #[must_use]
    pub fn with_struct_name(mut self, struct_name: &str) -> Self {
        self.struct_name = struct_name.to_string();
        self
    }

    /// Test-only chainable setter for `enum_name`.
    #[must_use]
    pub fn with_enum_name(mut self, enum_name: &str) -> Self {
        self.enum_name = enum_name.to_string();
        self
    }

    /// Test-only chainable setter for `inner_type`.
    #[must_use]
    pub fn with_inner_type(mut self, inner_type: &str) -> Self {
        self.inner_type = inner_type.to_string();
        self
    }

    /// Test-only chainable setter for `value_type`.
    #[must_use]
    pub fn with_value_type(mut self, value_type: &str) -> Self {
        self.value_type = value_type.to_string();
        self
    }

    /// Test-only chainable setter for `bool_val` (the
    /// `BoolProperty`-only inline payload that lives on the tag
    /// header rather than the value body).
    #[must_use]
    pub fn with_bool_val(mut self, bool_val: bool) -> Self {
        self.bool_val = bool_val;
        self
    }

    /// Test-only chainable setter for `name`. Lets a helper-factory-
    /// built tag (which seeds `name` from a defaulted source like
    /// `make_array_tag("StructProperty", ...)`) override the property
    /// name without dropping back to direct field mutation — required
    /// to keep the test surface insulated from the field-type changes
    /// tracked in #365 (`String` → `Arc<str>`).
    #[must_use]
    pub fn with_name(mut self, name: &str) -> Self {
        self.name = name.to_string();
        self
    }
}

/// Resolve a wire-format `(index, number)` FName pair to a `String`.
///
/// `number <= 0` → no suffix; `number > 0` → `"Base_N"` where
/// `N = number − 1` (UE stores the suffix offset by `+1` so that `0`
/// means "no suffix" without losing the `_0` case).
///
/// Intentionally distinct from [`NameTable::resolve`](crate::asset::NameTable::resolve):
/// the header-side resolve takes `u32`s and renders OOB as a tolerant
/// `<oob:{index}>` placeholder, because at header-read time an OOB
/// index is at worst a Phase-2a parser bug surfacing visibly. At
/// property-tag-iteration time an `i32::MIN` `nameIndex` is real
/// attacker-controllable input that must produce a structured error
/// (`PackageIndexUnderflow`) rather than a placeholder string.
///
/// # Errors
///
/// - [`AssetParseFault::PackageIndexUnderflow`] for `index < 0`.
/// - [`AssetParseFault::PackageIndexOob`] for `index` past the name table.
pub fn resolve_fname(
    index: i32,
    number: i32,
    ctx: &AssetContext,
    asset_path: &str,
    field: AssetWireField,
) -> crate::Result<String> {
    if index < 0 {
        return Err(PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::PackageIndexUnderflow { field },
        });
    }
    #[allow(
        clippy::cast_sign_loss,
        reason = "the `index < 0` branch above returns; the cast is non-negative"
    )]
    let idx = index as u32;
    let fname = ctx
        .names
        .get(idx)
        .ok_or_else(|| PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::PackageIndexOob {
                field,
                index: idx,
                table_size: u32::try_from(ctx.names.names.len()).unwrap_or(u32::MAX),
            },
        })?;
    if number <= 0 {
        Ok(fname.as_str().to_string())
    } else {
        Ok(format!("{}_{}", fname.as_str(), number - 1))
    }
}

/// Read one `FPropertyTag` from `reader`, resolving FNames via `ctx`.
///
/// Returns `Ok(None)` when the "None" terminator is reached (either
/// `name_index == 0 && name_number == 0` or the resolved name equals
/// `"None"`).
///
/// # Errors
///
/// - [`AssetParseFault::NegativeValue`] with `field: AssetWireField::PropertyTagSize`
///   if `Size < 0`. Reuses the shared signed-negative variant Phase 2a uses for
///   `NameCount`/`ImportCount`/`ExportSerialSize`.
/// - [`AssetParseFault::BoundsExceeded`] with `field: AssetWireField::PropertyTagSize`,
///   `unit: BoundsUnit::Bytes` if `Size > MAX_PROPERTY_TAG_SIZE`. Reuses the
///   shared cap-overflow variant Phase 2a uses for `TotalHeaderSize`/`NameOffset`.
/// - [`AssetParseFault::PackageIndexUnderflow`] / [`AssetParseFault::PackageIndexOob`]
///   for out-of-range FName indexes.
/// - [`AssetParseFault::UnexpectedEof`] on short reads.
///
/// The `Read`-only bound is intentional — `read_tag` does sequential
/// `read_*` calls only; no `stream_position`/`seek`. The caller
/// (`read_properties` in `mod.rs`) is `Read + Seek` and bubbles the
/// stronger bound up to where it's used.
#[allow(
    clippy::too_many_lines,
    reason = "FPropertyTag's wire layout reads sequentially with type-specific extras dispatched \
              by name; splitting would obscure the byte-by-byte mirror of CUE4Parse's \
              FPropertyTag.Serialize"
)]
pub fn read_tag<R: Read>(
    reader: &mut R,
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<Option<PropertyTag>> {
    // Read the Name pair manually (not via `read_fname_pair`) so the
    // index==0 && number==0 None-terminator probe runs before the
    // PackageIndex* resolve step — a literal `(0, 0)` pair must NOT
    // emit an OOB error when the name table happens to be empty.
    let name_index = reader
        .read_i32::<LittleEndian>()
        .map_err(|_| unexpected_eof(asset_path, AssetWireField::PropertyTagName))?;
    let name_number = reader
        .read_i32::<LittleEndian>()
        .map_err(|_| unexpected_eof(asset_path, AssetWireField::PropertyTagName))?;
    if name_index == 0 && name_number == 0 {
        return Ok(None);
    }
    let name = resolve_fname(
        name_index,
        name_number,
        ctx,
        asset_path,
        AssetWireField::PropertyTagName,
    )?;
    // Defensive fallback for exotic encoders that spell "None"
    // differently (e.g. number > 0 but the base name == "None").
    if name == "None" {
        return Ok(None);
    }

    let type_name = read_fname_pair(reader, ctx, asset_path, AssetWireField::PropertyTagType)?;

    let size = reader
        .read_i32::<LittleEndian>()
        .map_err(|_| unexpected_eof(asset_path, AssetWireField::PropertyTagSize))?;
    if size < 0 {
        return Err(PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::NegativeValue {
                field: AssetWireField::PropertyTagSize,
                value: i64::from(size),
            },
        });
    }
    if size > MAX_PROPERTY_TAG_SIZE {
        #[allow(
            clippy::cast_sign_loss,
            reason = "both casts are post the `size < 0` rejection above; \
                      MAX_PROPERTY_TAG_SIZE is a positive compile-time const"
        )]
        return Err(PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::BoundsExceeded {
                field: AssetWireField::PropertyTagSize,
                value: size as u64,
                limit: MAX_PROPERTY_TAG_SIZE as u64,
                unit: BoundsUnit::Bytes,
            },
        });
    }

    let array_index = reader
        .read_i32::<LittleEndian>()
        .map_err(|_| unexpected_eof(asset_path, AssetWireField::PropertyTagArrayIndex))?;

    // Type-specific extras.
    let mut bool_val = false;
    let mut struct_name = String::new();
    let mut struct_guid = [0u8; 16];
    let mut enum_name = String::new();
    let mut inner_type = String::new();
    let mut value_type = String::new();

    match type_name.as_str() {
        "BoolProperty" => {
            let bv = reader
                .read_u8()
                .map_err(|_| unexpected_eof(asset_path, AssetWireField::PropertyTagBoolVal))?;
            bool_val = bv != 0;
        }
        "StructProperty" => {
            struct_name = read_fname_pair(
                reader,
                ctx,
                asset_path,
                AssetWireField::PropertyTagStructName,
            )?;
            reader
                .read_exact(&mut struct_guid)
                .map_err(|_| unexpected_eof(asset_path, AssetWireField::PropertyTagStructGuid))?;
        }
        "ByteProperty" | "EnumProperty" => {
            enum_name =
                read_fname_pair(reader, ctx, asset_path, AssetWireField::PropertyTagEnumName)?;
        }
        "ArrayProperty" | "SetProperty" => {
            inner_type = read_fname_pair(
                reader,
                ctx,
                asset_path,
                AssetWireField::PropertyTagInnerType,
            )?;
        }
        "MapProperty" => {
            inner_type = read_fname_pair(
                reader,
                ctx,
                asset_path,
                AssetWireField::PropertyTagInnerType,
            )?;
            value_type = read_fname_pair(
                reader,
                ctx,
                asset_path,
                AssetWireField::PropertyTagValueType,
            )?;
        }
        _ => {}
    }

    let has_guid = reader
        .read_u8()
        .map_err(|_| unexpected_eof(asset_path, AssetWireField::PropertyTagHasGuid))?;
    let guid = if has_guid != 0 {
        let mut g = [0u8; 16];
        reader
            .read_exact(&mut g)
            .map_err(|_| unexpected_eof(asset_path, AssetWireField::PropertyTagGuid))?;
        Some(g)
    } else {
        None
    };

    Ok(Some(PropertyTag {
        name,
        type_name,
        size,
        array_index,
        bool_val,
        struct_name,
        struct_guid,
        enum_name,
        inner_type,
        value_type,
        guid,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::property::test_utils::{make_ctx, write_fname};
    use std::io::Cursor;

    #[test]
    fn none_terminator_returns_none() {
        let ctx = make_ctx(&["None"]);
        let buf: Vec<u8> = vec![0, 0, 0, 0, 0, 0, 0, 0];
        let tag = read_tag(&mut Cursor::new(&buf[..]), &ctx, "x.uasset").unwrap();
        assert!(tag.is_none());
    }

    #[test]
    fn bool_property_tag_decoded() {
        let ctx = make_ctx(&["None", "bEnabled", "BoolProperty"]);
        let mut buf = Vec::new();
        write_fname(&mut buf, 1, 0);
        write_fname(&mut buf, 2, 0);
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.push(1u8);
        buf.push(0u8);
        let tag = read_tag(&mut Cursor::new(&buf[..]), &ctx, "x.uasset")
            .unwrap()
            .unwrap();
        assert_eq!(tag.name, "bEnabled");
        assert_eq!(tag.type_name, "BoolProperty");
        assert_eq!(tag.size, 0);
        assert!(tag.bool_val);
        assert!(tag.guid.is_none());
    }

    #[test]
    fn int_property_tag_decoded() {
        let ctx = make_ctx(&["None", "MaxHP", "IntProperty"]);
        let mut buf = Vec::new();
        write_fname(&mut buf, 1, 0);
        write_fname(&mut buf, 2, 0);
        buf.extend_from_slice(&4i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.push(0u8);
        let tag = read_tag(&mut Cursor::new(&buf[..]), &ctx, "x.uasset")
            .unwrap()
            .unwrap();
        assert_eq!(tag.name, "MaxHP");
        assert_eq!(tag.type_name, "IntProperty");
        assert_eq!(tag.size, 4);
    }

    #[test]
    fn negative_size_is_rejected() {
        let ctx = make_ctx(&["None", "Foo", "IntProperty"]);
        let mut buf = Vec::new();
        write_fname(&mut buf, 1, 0);
        write_fname(&mut buf, 2, 0);
        buf.extend_from_slice(&(-1i32).to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.push(0u8);
        let err = read_tag(&mut Cursor::new(&buf[..]), &ctx, "x.uasset").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::NegativeValue {
                    field: AssetWireField::PropertyTagSize,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn size_exceeding_cap_is_rejected() {
        let ctx = make_ctx(&["None", "Foo", "StrProperty"]);
        let mut buf = Vec::new();
        write_fname(&mut buf, 1, 0);
        write_fname(&mut buf, 2, 0);
        buf.extend_from_slice(&(MAX_PROPERTY_TAG_SIZE + 1).to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.push(0u8);
        let err = read_tag(&mut Cursor::new(&buf[..]), &ctx, "x.uasset").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::BoundsExceeded {
                    field: AssetWireField::PropertyTagSize,
                    unit: BoundsUnit::Bytes,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn name_suffix_number_appended() {
        let ctx = make_ctx(&["None", "Foo", "IntProperty"]);
        let mut buf = Vec::new();
        write_fname(&mut buf, 1, 2);
        write_fname(&mut buf, 2, 0);
        buf.extend_from_slice(&4i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.push(0u8);
        let tag = read_tag(&mut Cursor::new(&buf[..]), &ctx, "x.uasset")
            .unwrap()
            .unwrap();
        assert_eq!(tag.name, "Foo_1");
    }

    #[test]
    fn struct_property_tag_reads_struct_name_and_guid() {
        let ctx = make_ctx(&["None", "Transform", "StructProperty"]);
        let mut buf = Vec::new();
        write_fname(&mut buf, 1, 0);
        write_fname(&mut buf, 2, 0);
        buf.extend_from_slice(&60i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        write_fname(&mut buf, 1, 0);
        buf.extend_from_slice(&[0xAB; 16]);
        buf.push(0u8);
        let tag = read_tag(&mut Cursor::new(&buf[..]), &ctx, "x.uasset")
            .unwrap()
            .unwrap();
        assert_eq!(tag.struct_name, "Transform");
        assert_eq!(tag.struct_guid, [0xABu8; 16]);
    }

    #[test]
    fn property_guid_decoded_when_present() {
        let ctx = make_ctx(&["None", "Count", "IntProperty"]);
        let mut buf = Vec::new();
        write_fname(&mut buf, 1, 0);
        write_fname(&mut buf, 2, 0);
        buf.extend_from_slice(&4i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.push(1u8);
        buf.extend_from_slice(&[0x11; 16]);
        let tag = read_tag(&mut Cursor::new(&buf[..]), &ctx, "x.uasset")
            .unwrap()
            .unwrap();
        assert_eq!(tag.guid, Some([0x11u8; 16]));
    }
}
