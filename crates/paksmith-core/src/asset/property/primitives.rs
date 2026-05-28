//! `Property` and `PropertyValue` types + primitive property readers.
//!
//! [`read_primitive_value`] dispatches by `tag.type_name` and reads the
//! value payload from the stream. Returns `Ok(None)` for unrecognised
//! types (Array/Map/Set/Struct/SoftObjectPath/etc.) — the caller is
//! responsible for the `MAX_PROPERTY_TAG_SIZE`-bounded skip and
//! constructing [`PropertyValue::Unknown`].

use std::io::{Read, Seek};
use std::sync::Arc;

use byteorder::{LittleEndian, ReadBytesExt};
use serde::{Deserialize, Serialize};

use crate::asset::AssetContext;
use crate::asset::package_index::PackageIndex;
use crate::asset::read_asset_fstring;
use crate::error::{AssetParseFault, AssetWireField, PaksmithError};

use super::tag::PropertyTag;
use super::text::{FText, read_ftext};
use super::{read_fname_pair, unexpected_eof};

/// One decoded property entry in an export's property stream.
///
/// `name` is `Arc<str>` rather than `String` (#365): the FName pool's
/// backing is already `Arc<str>`, so the bridge from `PropertyTag` to
/// `Property` is a refcount-bump clone instead of a heap copy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Property {
    /// Resolved property name.
    pub(crate) name: Arc<str>,
    /// Array element index (0 for non-array properties).
    pub array_index: i32,
    /// Optional per-property GUID carried by the tag header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guid: Option<[u8; 16]>,
    /// The decoded property value.
    pub value: PropertyValue,
}

impl Property {
    /// Resolved property name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// A single key-value entry in a decoded `MapProperty`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MapEntry {
    /// The decoded key value.
    pub key: PropertyValue,
    /// The decoded value paired with `key`.
    pub value: PropertyValue,
}

/// Decoded property value.
///
/// `#[non_exhaustive]` — Phase 2b variants cover primitives; Phase 2c
/// adds Array/Map/Set/Struct; Phase 2d adds
/// SoftObjectPath/SoftClassPath/Object.
/// [`PropertyValue::Unknown`] is the catch-all for types still not
/// decoded (e.g., a collection with a `StructProperty` element type
/// is skipped wholesale); it carries `skipped_bytes` (the count)
/// rather than the raw bytes so JSON output stays compact.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    /// `NameProperty` — an FName resolved to an `Arc<str>` at parse
    /// time (no `&AssetContext` dependency at serialization time).
    /// `Arc<str>` is the FName pool's native backing — clones are
    /// refcount bumps, not heap copies (#365).
    Name(Arc<str>),
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
        type_name: Arc<str>,
        /// The enum variant name resolved from the payload FName.
        value: Arc<str>,
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
    /// Arrays with `StructProperty` or `TextProperty` inner types still
    /// fall back to `Unknown { skipped_bytes }`.
    Array {
        /// Resolved inner element type name (e.g. `"IntProperty"`).
        inner_type: Arc<str>,
        /// Decoded array elements, each of type `inner_type`.
        elements: Vec<PropertyValue>,
    },

    /// `StructProperty` — recursive tagged property tree.
    ///
    /// Recursion is bounded by `MAX_PROPERTY_DEPTH`.
    Struct {
        /// Resolved struct type name from `FPropertyTag::struct_name`.
        struct_name: Arc<str>,
        /// Decoded child tagged properties.
        properties: Vec<Property>,
    },

    /// `StructProperty` decoded via a typed engine-struct decoder
    /// (Phase 3c — `FVector`, `FQuat`, `FBox`, etc.). The registry
    /// in `crate::asset::structs` (crate-private) dispatches the
    /// struct name to a custom-binary decoder; on hit, the payload
    /// bytes are decoded into a typed [`TypedStructValue`] rather
    /// than recursing through Phase 2g's tagged-property iteration.
    ///
    /// **`Box<TypedStructValue>` is load-bearing.** Inlining the
    /// largest variant (`FTransform` at 80 bytes UE5 LWC) would
    /// inflate every `PropertyValue` (including `Int(42)`) to ~96
    /// bytes. Boxing pays one allocation per typed-struct property
    /// in exchange for a ~3× smaller `PropertyValue`.
    ///
    /// [`TypedStructValue`]: crate::asset::structs::TypedStructValue
    TypedStruct(Box<crate::asset::structs::TypedStructValue>),

    /// `MapProperty` with handled primitive key and value types.
    Map {
        /// Resolved key type name.
        key_type: Arc<str>,
        /// Resolved value type name.
        value_type: Arc<str>,
        /// Decoded key-value entries.
        entries: Vec<MapEntry>,
    },

    /// `SetProperty` with a handled primitive inner type.
    Set {
        /// Resolved inner element type name.
        inner_type: Arc<str>,
        /// Decoded set elements, each of type `inner_type`.
        elements: Vec<PropertyValue>,
    },

    /// `SoftObjectProperty` — a non-owning soft reference to an asset by path.
    ///
    /// Wire format: `FName asset_path` (resolved through the name table) +
    /// `FString sub_path`. Sub-path is usually empty in cooked assets.
    /// The `asset_path` field below holds the resolved string, not the raw
    /// FName indices.
    SoftObjectPath {
        /// Primary asset path (e.g. `/Game/Data/Hero.Hero`).
        asset_path: String,
        /// Sub-object path within the asset; empty string for none.
        sub_path: String,
    },

    /// `SoftClassProperty` — a soft reference to a class by path.
    ///
    /// Identical wire format to `SoftObjectPath`.
    SoftClassPath {
        /// Primary class path (e.g. `/Game/BP/HeroClass.HeroClass_C`).
        asset_path: String,
        /// Sub-object path; empty string for none.
        sub_path: String,
    },

    /// `ObjectProperty` — a hard object reference with the typed
    /// [`PackageIndex`] disambiguator and a resolved name.
    ///
    /// The wire is a single `i32` decoded via `PackageIndex::try_from_raw`
    /// (so `kind` preserves the Phase 2d typed shape: `Null`, `Import(N)`,
    /// or `Export(N)`; `i32::MIN` is rejected at decode time as
    /// `AssetParseFault::PackageIndexUnderflow`). `name` is the resolved
    /// `object_name` FName from the import/export table — empty string when
    /// `kind == PackageIndex::Null`; bare FName (not a SoftObjectPath
    /// `<package>.<object>` form) otherwise. See `resolve_package_index`
    /// in this module for the resolution rules.
    Object {
        /// Typed package-index discriminator from `PackageIndex::try_from_raw`.
        kind: PackageIndex,
        /// Resolved name string from `resolve_package_index`. Empty for `Null`;
        /// out-of-bounds indices return `AssetParseFault::PackageIndexOob`
        /// rather than synthesizing a fallback string.
        name: String,
    },
}

/// Reads an `FSoftObjectPath` payload: FName `asset_path` + FString
/// `sub_path`. Shared by `read_primitive_value` (direct
/// SoftObjectProperty / SoftClassProperty) and by `read_element_value`
/// (the same types as collection elements).
///
/// Returns `(asset_path, sub_path)` so the caller can wrap the pair
/// into the right `PropertyValue` variant.
///
/// Phase 2d only handles the UE4 / UE5 < 1007 wire shape. UE5 ≥ 1007
/// switches the first slot to `FTopLevelAssetPath` (2 FNames) and UE5
/// ≥ 1008 changes the entire payload to an `i32` index into the
/// summary's `SoftObjectPaths` list; both require summary-side support
/// deferred to Phase 2g, so this function returns
/// `UnsupportedSoftObjectPathLayout` at UE5 ≥ 1007 rather than
/// mis-decoding silently.
///
/// `pub(super)` so `containers.rs` can reuse this for element reads.
///
/// # Errors
///
/// - [`AssetParseFault::UnsupportedSoftObjectPathLayout`] when the
///   asset declares `file_version_ue5 >= 1007`.
/// - Any error surfaced by [`super::read_fname_pair`] for the
///   `asset_path` FName.
/// - [`crate::error::AssetParseFault::FStringMalformed`] for a malformed
///   `sub_path` FString.
pub(super) fn read_soft_path_payload<R: Read>(
    reader: &mut R,
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<(String, String)> {
    if let Some(v) = ctx.version.file_version_ue5
        && v >= 1007
    {
        return Err(PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::UnsupportedSoftObjectPathLayout { ue5_version: v },
        });
    }
    let obj_path =
        super::read_fname_pair(reader, ctx, asset_path, AssetWireField::SoftObjectAssetPath)?;
    let sub = crate::asset::read_asset_fstring(reader, asset_path)?;
    // SoftObjectPath / SoftClassPath still store `asset_path: String`
    // (out of #365's scope — those variants weren't on the issue's
    // explicit field list). One allocation per soft-path read; cold
    // relative to the per-property hot path.
    Ok((obj_path.to_string(), sub))
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
    // Arm order: high-frequency property types first (Int / Float /
    // Bool / Str / Name / Object) so the branch-predicted
    // string-compare ladder short-circuits on the common case before
    // walking past the rarer arms. Real cooked Blueprint assets
    // overwhelmingly hit the first six arms. Issue #371.
    let val = match tag.type_name.as_ref() {
        "IntProperty" => {
            let v = reader
                .read_i32::<LittleEndian>()
                .map_err(|_| unexpected_eof(asset_path, AssetWireField::PropertyTagSize))?;
            PropertyValue::Int(v)
        }

        "FloatProperty" => {
            let v = reader
                .read_f32::<LittleEndian>()
                .map_err(|_| unexpected_eof(asset_path, AssetWireField::PropertyTagSize))?;
            PropertyValue::Float(v)
        }

        "BoolProperty" => PropertyValue::Bool(tag.bool_val),

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

        "ObjectProperty" => {
            let raw = reader
                .read_i32::<LittleEndian>()
                .map_err(|_| unexpected_eof(asset_path, AssetWireField::ObjectPropertyIndex))?;
            let kind = PackageIndex::try_from_raw(raw).map_err(|_| PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::PackageIndexUnderflow {
                    field: AssetWireField::ObjectPropertyIndex,
                },
            })?;
            let name = resolve_package_index(kind, ctx, asset_path)?;
            PropertyValue::Object { kind, name }
        }

        "EnumProperty" => {
            let value =
                read_fname_pair(reader, ctx, asset_path, AssetWireField::PropertyTagEnumName)?;
            PropertyValue::Enum {
                type_name: tag.enum_name.clone(),
                value,
            }
        }

        "ByteProperty" => {
            if tag.enum_name.is_empty() || tag.enum_name.as_ref() == "None" {
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

        "DoubleProperty" => {
            let v = reader
                .read_f64::<LittleEndian>()
                .map_err(|_| unexpected_eof(asset_path, AssetWireField::PropertyTagSize))?;
            PropertyValue::Double(v)
        }

        "TextProperty" => {
            #[allow(
                clippy::cast_sign_loss,
                reason = "tag.size has been rejected if < 0 by read_tag; safe widening"
            )]
            let text = read_ftext(reader, ctx, asset_path, tag.size as u64)?;
            PropertyValue::Text(text)
        }

        "Int64Property" => {
            let v = reader
                .read_i64::<LittleEndian>()
                .map_err(|_| unexpected_eof(asset_path, AssetWireField::PropertyTagSize))?;
            PropertyValue::Int64(v)
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

        "SoftObjectProperty" => {
            let (obj_path, sub) = read_soft_path_payload(reader, ctx, asset_path)?;
            PropertyValue::SoftObjectPath {
                asset_path: obj_path,
                sub_path: sub,
            }
        }

        "SoftClassProperty" => {
            let (obj_path, sub) = read_soft_path_payload(reader, ctx, asset_path)?;
            PropertyValue::SoftClassPath {
                asset_path: obj_path,
                sub_path: sub,
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

        "UInt16Property" => {
            let v = reader
                .read_u16::<LittleEndian>()
                .map_err(|_| unexpected_eof(asset_path, AssetWireField::PropertyTagSize))?;
            PropertyValue::UInt16(v)
        }

        _ => return Ok(None),
    };

    Ok(Some(val))
}

/// Resolve a typed UE package index to a human-readable object name.
///
/// | `kind`        | Meaning                              | Source            |
/// |---------------|--------------------------------------|-------------------|
/// | `Null`        | Null reference                       | Returns `""`      |
/// | `Import(N)`   | Import reference: `imports[N]`       | `ImportTable`     |
/// | `Export(N)`   | Export reference: `exports[N]`       | `ExportTable`     |
///
/// The `i32::MIN` underflow case is handled at wire-decode time by
/// [`PackageIndex::try_from_raw`] (see `package_index.rs`) and surfaced
/// as [`AssetParseFault::PackageIndexUnderflow`] BEFORE this helper runs.
/// That's why the signature takes the already-decoded typed
/// [`PackageIndex`] enum, not a raw `i32`.
///
/// Phase 2a stores `ObjectImport::object_name` and `ObjectExport::object_name`
/// as `u32` FName indices. This helper resolves them through `ctx.names`
/// (and applies the `_N` suffix from `object_name_number`) via the
/// existing [`resolve_fname`](crate::asset::property::tag::resolve_fname)
/// helper from Phase 2b. The resolved name is the BARE `object_name` (e.g.
/// `"StaticMesh"`, `"Hero"`); the helper does NOT synthesize a
/// SoftObjectPath-style `<class_package>.<object_name>` form because
/// `ObjectImport`/`ObjectExport` don't carry a full asset path.
///
/// OOB indices return `PackageIndexOob` with `field: AssetWireField::ObjectPropertyIndex`.
/// `index` is reported as the 0-based table position; `table_size` is the table length.
///
/// # Errors
///
/// - [`AssetParseFault::PackageIndexOob`] when `Import(N)` / `Export(N)` indexes past
///   the corresponding table.
/// - Any error surfaced by [`resolve_fname`](crate::asset::property::tag::resolve_fname)
///   when the import/export's `object_name` index falls outside `ctx.names`.
pub(crate) fn resolve_package_index(
    kind: PackageIndex,
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<String> {
    use crate::asset::property::tag::resolve_fname;
    match kind {
        PackageIndex::Null => Ok(String::new()),
        PackageIndex::Import(n) => {
            let idx = n as usize;
            let imp = ctx
                .imports
                .imports
                .get(idx)
                .ok_or_else(|| PaksmithError::AssetParse {
                    asset_path: asset_path.to_string(),
                    fault: AssetParseFault::PackageIndexOob {
                        field: AssetWireField::ObjectPropertyIndex,
                        index: n,
                        table_size: u32::try_from(ctx.imports.imports.len()).unwrap_or(u32::MAX),
                    },
                })?;
            // PropertyValue::Object.name is `String` (out of #365
            // scope); convert from Arc<str>. One alloc per Object
            // property.
            resolve_fname(
                i32::try_from(imp.object_name).unwrap_or(i32::MAX),
                i32::try_from(imp.object_name_number).unwrap_or(i32::MAX),
                ctx,
                asset_path,
                AssetWireField::ObjectPropertyIndex,
            )
            .map(|arc| arc.to_string())
        }
        PackageIndex::Export(n) => {
            let idx = n as usize;
            let exp = ctx
                .exports
                .exports
                .get(idx)
                .ok_or_else(|| PaksmithError::AssetParse {
                    asset_path: asset_path.to_string(),
                    fault: AssetParseFault::PackageIndexOob {
                        field: AssetWireField::ObjectPropertyIndex,
                        index: n,
                        table_size: u32::try_from(ctx.exports.exports.len()).unwrap_or(u32::MAX),
                    },
                })?;
            resolve_fname(
                i32::try_from(exp.object_name).unwrap_or(i32::MAX),
                i32::try_from(exp.object_name_number).unwrap_or(i32::MAX),
                ctx,
                asset_path,
                AssetWireField::ObjectPropertyIndex,
            )
            .map(|arc| arc.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::property::test_utils::{make_ctx, make_ctx_with_import};
    use std::io::Cursor;

    fn make_test_ctx_with_export(export_name: &str) -> AssetContext {
        use crate::asset::{
            AssetContext,
            export_table::{ExportTable, ObjectExport},
            guid::FGuid,
            import_table::ImportTable,
            name_table::{FName, NameTable},
            package_index::PackageIndex,
            version::AssetVersion,
        };
        use std::sync::Arc;
        // Names: 0="None", 1=<export_name>.
        let names = NameTable {
            names: vec![FName::new("None"), FName::new(export_name)],
        };
        AssetContext {
            names: Arc::new(names),
            imports: Arc::new(ImportTable { imports: vec![] }),
            exports: Arc::new(ExportTable {
                exports: vec![ObjectExport {
                    class_index: PackageIndex::Null,
                    super_index: PackageIndex::Null,
                    template_index: PackageIndex::Null,
                    outer_index: PackageIndex::Null,
                    object_name: 1,
                    object_name_number: 0,
                    object_flags: 0,
                    serial_size: 0,
                    serial_offset: 0,
                    forced_export: false,
                    not_for_client: false,
                    not_for_server: false,
                    package_guid: Some(FGuid::from_bytes([0u8; 16])),
                    is_inherited_instance: None,
                    package_flags: 0,
                    not_always_loaded_for_editor_game: false,
                    is_asset: true,
                    generate_public_hash: None,
                    script_serialization_start_offset: None,
                    script_serialization_end_offset: None,
                    first_export_dependency: -1,
                    serialization_before_serialization_count: 0,
                    create_before_serialization_count: 0,
                    serialization_before_create_count: 0,
                    create_before_create_count: 0,
                }],
            }),
            version: AssetVersion {
                legacy_file_version: -7,
                file_version_ue4: 522,
                file_version_ue5: None,
                file_version_licensee_ue4: 0,
            },
            custom_versions: Arc::new(
                crate::asset::custom_version::CustomVersionContainer::default(),
            ),
            mappings: None,
        }
    }

    #[test]
    fn resolve_package_index_null_is_empty_string() {
        let ctx = make_ctx_with_import("/Game/Mesh.Mesh");
        let name = resolve_package_index(PackageIndex::Null, &ctx, "x.uasset").unwrap();
        assert_eq!(name, "");
    }

    #[test]
    fn resolve_package_index_import_ref() {
        let ctx = make_ctx_with_import("/Game/Mesh.Mesh");
        let name = resolve_package_index(PackageIndex::Import(0), &ctx, "x.uasset").unwrap();
        assert_eq!(name, "/Game/Mesh.Mesh");
    }

    #[test]
    fn resolve_package_index_export_ref() {
        let ctx = make_test_ctx_with_export("Hero");
        let name = resolve_package_index(PackageIndex::Export(0), &ctx, "x.uasset").unwrap();
        assert_eq!(name, "Hero");
    }

    #[test]
    fn resolve_package_index_import_oob() {
        let ctx = make_ctx_with_import("/Game/Mesh.Mesh");
        // imports has 1 entry; Import(100) is far past the end.
        let err = resolve_package_index(PackageIndex::Import(100), &ctx, "x.uasset").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::PackageIndexOob { .. },
                ..
            }
        ));
    }

    #[test]
    fn resolve_package_index_export_oob() {
        let ctx = make_ctx_with_import("/Game/Mesh.Mesh"); // no exports
        let err = resolve_package_index(PackageIndex::Export(0), &ctx, "x.uasset").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::PackageIndexOob { .. },
                ..
            }
        ));
    }

    fn make_tag(type_name: &str, size: i32) -> PropertyTag {
        PropertyTag::for_test("Prop", type_name, size)
    }

    fn make_bool_tag(val: bool) -> PropertyTag {
        make_tag("BoolProperty", 0).with_bool_val(val)
    }

    fn make_byte_enum_tag(enum_name: &str) -> PropertyTag {
        make_tag("ByteProperty", 8).with_enum_name(enum_name)
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
                type_name: Arc::from("EMyEnum"),
                value: Arc::from("EMyEnum__Val"),
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
        assert_eq!(val, PropertyValue::Name(Arc::from("MyName")));
    }

    #[test]
    fn enum_property_value() {
        let tag = make_tag("EnumProperty", 8).with_enum_name("EDirection");
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
                type_name: Arc::from("EDirection"),
                value: Arc::from("EDirection__Forward"),
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
            inner_type: Arc::from("IntProperty"),
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
            struct_name: Arc::from("MyStruct"),
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
            key_type: Arc::from("StrProperty"),
            value_type: Arc::from("IntProperty"),
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
            inner_type: Arc::from("NameProperty"),
            elements: vec![PropertyValue::Name(Arc::from("Tag_A"))],
        };
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(
            json,
            r#"{"Set":{"inner_type":"NameProperty","elements":[{"Name":"Tag_A"}]}}"#
        );
    }

    #[test]
    fn property_value_soft_object_path_serializes() {
        let v = PropertyValue::SoftObjectPath {
            asset_path: "/Game/Data/Hero.Hero".to_string(),
            sub_path: String::new(),
        };
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(
            json,
            r#"{"SoftObjectPath":{"asset_path":"/Game/Data/Hero.Hero","sub_path":""}}"#
        );
    }

    #[test]
    fn property_value_soft_class_path_serializes() {
        let v = PropertyValue::SoftClassPath {
            asset_path: "/Game/BP/HeroClass.HeroClass_C".to_string(),
            sub_path: "SubObject".to_string(),
        };
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(
            json,
            r#"{"SoftClassPath":{"asset_path":"/Game/BP/HeroClass.HeroClass_C","sub_path":"SubObject"}}"#
        );
    }

    #[test]
    fn property_value_object_import_serializes() {
        let v = PropertyValue::Object {
            kind: PackageIndex::Import(2),
            name: "SomeImport".to_string(),
        };
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(
            json,
            r#"{"Object":{"kind":"Import(2)","name":"SomeImport"}}"#
        );
    }

    #[test]
    fn property_value_object_null_serializes() {
        let v = PropertyValue::Object {
            kind: PackageIndex::Null,
            name: String::new(),
        };
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(json, r#"{"Object":{"kind":"Null","name":""}}"#);
    }

    #[test]
    fn property_value_object_export_serializes() {
        let v = PropertyValue::Object {
            kind: PackageIndex::Export(1),
            name: "SomeExport".to_string(),
        };
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(
            json,
            r#"{"Object":{"kind":"Export(1)","name":"SomeExport"}}"#
        );
    }

    #[test]
    fn soft_object_property_value() {
        let tag = make_tag("SoftObjectProperty", 13);
        let ctx = make_ctx(&["None", "/Game/Data/Hero.Hero"]);
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&1i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.extend_from_slice(&1i32.to_le_bytes());
        buf.push(b'\0');
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf), &ctx, "x")
            .unwrap()
            .unwrap();
        assert_eq!(
            val,
            PropertyValue::SoftObjectPath {
                asset_path: "/Game/Data/Hero.Hero".to_string(),
                sub_path: String::new(),
            }
        );
    }

    #[test]
    fn soft_class_property_value() {
        let tag = make_tag("SoftClassProperty", 13);
        let ctx = make_ctx(&["None", "/Game/BP/HeroClass.HeroClass_C"]);
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&1i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.extend_from_slice(&1i32.to_le_bytes());
        buf.push(b'\0');
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf), &ctx, "x")
            .unwrap()
            .unwrap();
        assert_eq!(
            val,
            PropertyValue::SoftClassPath {
                asset_path: "/Game/BP/HeroClass.HeroClass_C".to_string(),
                sub_path: String::new(),
            }
        );
    }

    #[test]
    fn object_property_null_index() {
        let tag = make_tag("ObjectProperty", 4);
        let ctx = make_ctx(&["None"]);
        let val = read_primitive_value(&tag, &mut Cursor::new(&0i32.to_le_bytes()), &ctx, "x")
            .unwrap()
            .unwrap();
        assert_eq!(
            val,
            PropertyValue::Object {
                kind: PackageIndex::Null,
                name: String::new(),
            }
        );
    }

    #[test]
    fn object_property_import_index() {
        let tag = make_tag("ObjectProperty", 4);
        let ctx = make_ctx_with_import("/Game/Mesh.Mesh");
        // wire i32 -1 -> Import(0); the helper populates imports[0].object_name = 3 ("/Game/Mesh.Mesh").
        let val = read_primitive_value(&tag, &mut Cursor::new(&(-1i32).to_le_bytes()), &ctx, "x")
            .unwrap()
            .unwrap();
        assert_eq!(
            val,
            PropertyValue::Object {
                kind: PackageIndex::Import(0),
                name: "/Game/Mesh.Mesh".to_string(),
            }
        );
    }

    #[test]
    fn object_property_export_index() {
        let tag = make_tag("ObjectProperty", 4);
        let ctx = make_test_ctx_with_export("Hero");
        // wire i32 1 -> Export(0); the helper populates exports[0].object_name = 1 ("Hero").
        let val = read_primitive_value(&tag, &mut Cursor::new(&1i32.to_le_bytes()), &ctx, "x")
            .unwrap()
            .unwrap();
        assert_eq!(
            val,
            PropertyValue::Object {
                kind: PackageIndex::Export(0),
                name: "Hero".to_string(),
            }
        );
    }

    #[test]
    fn soft_object_property_ue5_post_1007_rejected() {
        let tag = make_tag("SoftObjectProperty", 16);
        let mut ctx = make_ctx(&["None", "/Game/Data/Hero.Hero"]);
        ctx.version.file_version_ue5 = Some(1007);
        let buf = vec![0u8; 16];
        let err = read_primitive_value(&tag, &mut Cursor::new(&buf), &ctx, "x").unwrap_err();
        assert!(matches!(
            err,
            crate::PaksmithError::AssetParse {
                fault: crate::error::AssetParseFault::UnsupportedSoftObjectPathLayout {
                    ue5_version: 1007
                },
                ..
            }
        ));
    }
}
