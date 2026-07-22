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
use crate::asset::version::{
    VER_UE4_ADDED_SOFT_OBJECT_PATH, VER_UE5_FSOFTOBJECTPATH_REMOVE_ASSET_PATH_FNAMES,
};
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
/// Wire shape by version (`asset_path` slot + `FString sub_path`):
/// - UE4 >= 514 / UE5 < 1007: a single `FName`.
/// - UE5 >= 1007 (`FSOFTOBJECTPATH_REMOVE_ASSET_PATH_FNAMES`): an
///   `FTopLevelAssetPath` — `FName PackageName` + `FName AssetName`,
///   reconstructed to the same `Package.Asset` string the pre-1007
///   single-FName form produced (see the join below).
///
/// Two layouts are fail-closed (paksmith rejects rather than mis-decode):
/// - **UE4 < 514** (`ADDED_SOFT_OBJECT_PATH`): the payload is a single
///   `FString` (CUE4Parse splits it on the last `.`), a lossy,
///   version-inconsistent decomposition with no in-scope oracle fixture —
///   [`PaksmithError::UnsupportedFeature`]. #694.
/// - **UE5 >= 1008 index form** (leading `i32` index into the summary's
///   `SoftObjectPaths` list) — via `ctx.soft_object_paths_indexed`,
///   unreachable for any well-formed asset (see
///   [`AssetContext::soft_object_paths_indexed`]).
///
/// `pub(super)` so `containers.rs` can reuse this for element reads.
///
/// # Errors
///
/// - [`PaksmithError::UnsupportedFeature`] for the UE4 < 514 single-FString
///   layout.
/// - [`AssetParseFault::UnsupportedSoftObjectPathLayout`] when the asset
///   uses the index-serialized form (`ctx.soft_object_paths_indexed`).
/// - Any error surfaced by [`super::read_fname_pair`] for either FName.
/// - [`crate::error::AssetParseFault::FStringMalformed`] for a malformed
///   `sub_path` FString.
///
/// [`AssetContext::soft_object_paths_indexed`]: crate::asset::AssetContext
/// [`PaksmithError::UnsupportedFeature`]: crate::PaksmithError::UnsupportedFeature
pub(super) fn read_soft_path_payload<R: Read>(
    reader: &mut R,
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<(String, String)> {
    // Index-serialized form (UE5 >= 1008): the leading slot is an `i32`
    // index into the summary's `SoftObjectPaths` list, which paksmith
    // does not parse. `soft_object_paths_indexed` (precomputed from the
    // summary as `!PKG_FilterEditorOnly && count != 0`) is only ever true
    // for a version-inconsistent crafted asset — a well-formed UE5 asset
    // has `file_version_ue4 == 522`, and an uncooked asset at
    // `file_version_ue4 >= 520` is already rejected as `UncookedAsset` at
    // the summary boundary. Fail closed rather than mis-decode the index
    // as an FName. See `AssetContext::soft_object_paths_indexed`. #638.
    if ctx.soft_object_paths_indexed {
        return Err(PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::UnsupportedSoftObjectPathLayout {
                ue5_version: ctx.version.file_version_ue5.unwrap_or_default(),
            },
        });
    }

    // UE4 < 514 (`ADDED_SOFT_OBJECT_PATH`): the pre-514 `FSoftObjectPath`
    // is a single `FString` (CUE4Parse splits it on the last `.` into
    // asset-path / sub-path), not the `FName + FString` shape below. That
    // split is a lossy, version-inconsistent decomposition (the same
    // reference decodes to a different `asset_path` than the 514+ form)
    // and no in-scope fixture anchors it, so paksmith fails closed rather
    // than mis-read the single FString as an FName. `file_version_ue4` is
    // gated ALONE (not `&& ue5.is_none()`): a well-formed asset never has
    // `ue4 < 514` — real UE4 packages with a soft path are >= 514, and UE5
    // packages carry `ue4 == 522` — so this fires only for a genuine
    // pre-514 UE4 asset or a version-inconsistent crafted one (e.g.
    // `ue4=510` with `ue5=Some(_)`, which the summary reads as independent
    // fields), both of which must fail closed rather than mis-decode. #694.
    if ctx.version.file_version_ue4 < VER_UE4_ADDED_SOFT_OBJECT_PATH {
        return Err(PaksmithError::UnsupportedFeature {
            context: format!(
                "FSoftObjectPath pre-514 single-FString layout at \
                 file_version_ue4={} ({asset_path}); soft paths require \
                 file_version_ue4 >= {VER_UE4_ADDED_SOFT_OBJECT_PATH} \
                 (ADDED_SOFT_OBJECT_PATH)",
                ctx.version.file_version_ue4
            ),
        });
    }

    let obj_path = if ctx
        .version
        .ue5_at_least(VER_UE5_FSOFTOBJECTPATH_REMOVE_ASSET_PATH_FNAMES)
    {
        // UE5 >= 1007: `FTopLevelAssetPath` (PackageName FName +
        // AssetName FName). Reconstruct `FTopLevelAssetPath::ToString`:
        // empty when PackageName is `None`; otherwise PackageName, with
        // `.AssetName` appended only when AssetName is not `None` (no
        // trailing dot). This reproduces the exact `asset_path` string
        // the pre-1007 single-FName form emitted (e.g. `/Game/Foo.Foo`).
        let package =
            super::read_fname_pair(reader, ctx, asset_path, AssetWireField::SoftObjectAssetPath)?;
        let asset =
            super::read_fname_pair(reader, ctx, asset_path, AssetWireField::SoftObjectAssetPath)?;
        if package.as_ref() == "None" {
            String::new()
        } else if asset.as_ref() == "None" {
            package.to_string()
        } else {
            format!("{package}.{asset}")
        }
    } else {
        // UE4 >= 514 / UE5 < 1007: a single `FName AssetPathName` (the
        // pre-514 single-FString layout is fail-closed above). Apply the
        // same `AssetPathName.IsNone → ""` rule `FSoftObjectPath::ToString`
        // uses uniformly, so a null reference decodes to "" here exactly
        // as the >= 1007 None-package case does — the two branches agree.
        let name =
            super::read_fname_pair(reader, ctx, asset_path, AssetWireField::SoftObjectAssetPath)?;
        if name.as_ref() == "None" {
            String::new()
        } else {
            name.to_string()
        }
    };
    // FString `SubPathString`. On very recent engine builds this slot is
    // an `FUtf8String` (gated on a custom FFortniteMainBranchObjectVersion,
    // not the UE5 object version); an empty sub_path — the common cooked
    // case — is byte-identical in both encodings, so the FString read is
    // correct for the vast majority of content. Non-empty UTF-8 sub_paths
    // on those builds are unhandled (#638 limitation).
    let sub = crate::asset::read_asset_fstring(reader, asset_path)?;
    // SoftObjectPath / SoftClassPath still store `asset_path: String`
    // (out of #365's scope — those variants weren't on the issue's
    // explicit field list). One allocation per soft-path read; cold
    // relative to the per-property hot path.
    Ok((obj_path, sub))
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
    depth: usize,
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
            let text = read_ftext(reader, ctx, asset_path, tag.size as u64, depth)?;
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
            bulk_resolver: None,
            soft_object_paths_indexed: false,
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
        let val = read_primitive_value(&tag, &mut Cursor::new(&[][..]), &ctx, "x", 0)
            .unwrap()
            .unwrap();
        assert_eq!(val, PropertyValue::Bool(true));
    }

    #[test]
    fn bool_false() {
        let tag = make_bool_tag(false);
        let ctx = make_ctx(&["None"]);
        let val = read_primitive_value(&tag, &mut Cursor::new(&[][..]), &ctx, "x", 0)
            .unwrap()
            .unwrap();
        assert_eq!(val, PropertyValue::Bool(false));
    }

    #[test]
    fn byte_raw() {
        let tag = make_tag("ByteProperty", 1);
        let ctx = make_ctx(&["None"]);
        let buf = [42u8];
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf[..]), &ctx, "x", 0)
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
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf[..]), &ctx, "x", 0)
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
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf[..]), &ctx, "x", 0)
            .unwrap()
            .unwrap();
        assert_eq!(val, PropertyValue::Int8(-2i8));
    }

    #[test]
    fn int16_value() {
        let tag = make_tag("Int16Property", 2);
        let ctx = make_ctx(&["None"]);
        let buf = (-1000i16).to_le_bytes();
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf[..]), &ctx, "x", 0)
            .unwrap()
            .unwrap();
        assert_eq!(val, PropertyValue::Int16(-1000));
    }

    #[test]
    fn int_value() {
        let tag = make_tag("IntProperty", 4);
        let ctx = make_ctx(&["None"]);
        let buf = 42i32.to_le_bytes();
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf[..]), &ctx, "x", 0)
            .unwrap()
            .unwrap();
        assert_eq!(val, PropertyValue::Int(42));
    }

    #[test]
    fn int64_value() {
        let tag = make_tag("Int64Property", 8);
        let ctx = make_ctx(&["None"]);
        let buf = i64::MAX.to_le_bytes();
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf[..]), &ctx, "x", 0)
            .unwrap()
            .unwrap();
        assert_eq!(val, PropertyValue::Int64(i64::MAX));
    }

    #[test]
    fn uint16_value() {
        let tag = make_tag("UInt16Property", 2);
        let ctx = make_ctx(&["None"]);
        let buf = 60_000u16.to_le_bytes();
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf[..]), &ctx, "x", 0)
            .unwrap()
            .unwrap();
        assert_eq!(val, PropertyValue::UInt16(60_000));
    }

    #[test]
    fn uint32_value() {
        let tag = make_tag("UInt32Property", 4);
        let ctx = make_ctx(&["None"]);
        let buf = 0xDEAD_BEEFu32.to_le_bytes();
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf[..]), &ctx, "x", 0)
            .unwrap()
            .unwrap();
        assert_eq!(val, PropertyValue::UInt32(0xDEAD_BEEF));
    }

    #[test]
    fn uint64_value() {
        let tag = make_tag("UInt64Property", 8);
        let ctx = make_ctx(&["None"]);
        let buf = u64::MAX.to_le_bytes();
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf[..]), &ctx, "x", 0)
            .unwrap()
            .unwrap();
        assert_eq!(val, PropertyValue::UInt64(u64::MAX));
    }

    #[test]
    fn float_value() {
        let tag = make_tag("FloatProperty", 4);
        let ctx = make_ctx(&["None"]);
        let buf = 1500.0f32.to_le_bytes();
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf[..]), &ctx, "x", 0)
            .unwrap()
            .unwrap();
        assert_eq!(val, PropertyValue::Float(1500.0));
    }

    #[test]
    fn double_value() {
        let tag = make_tag("DoubleProperty", 8);
        let ctx = make_ctx(&["None"]);
        let buf = 12345.6789f64.to_le_bytes();
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf[..]), &ctx, "x", 0)
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
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf[..]), &ctx, "x", 0)
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
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf[..]), &ctx, "x", 0)
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
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf[..]), &ctx, "x", 0)
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
        let val = read_primitive_value(&tag, &mut Cursor::new(&[][..]), &ctx, "x", 0).unwrap();
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

    /// `TextProperty` dispatches through `read_primitive_value` to
    /// `read_ftext` and yields a decoded `PropertyValue::Text` — pins the
    /// match arm itself (a deleted arm would fall through to `Ok(None)`
    /// and lossy-skip every TextProperty). #641.
    #[test]
    fn text_property_value_decodes_base_history() {
        use crate::asset::property::text::FTextHistory;
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&0u32.to_le_bytes()); // flags
        buf.push(0u8); // Base
        for s in ["NS", "K", "Hi"] {
            let bytes = s.as_bytes();
            buf.extend_from_slice(&i32::try_from(bytes.len() + 1).unwrap().to_le_bytes());
            buf.extend_from_slice(bytes);
            buf.push(0u8);
        }
        let tag = make_tag("TextProperty", i32::try_from(buf.len()).unwrap());
        let ctx = make_ctx(&["None"]);
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf), &ctx, "x", 0)
            .unwrap()
            .unwrap();
        match val {
            PropertyValue::Text(t) => assert!(matches!(
                t.history,
                FTextHistory::Base { ref source_string, .. } if source_string == "Hi"
            )),
            other => panic!("expected Text, got {other:?}"),
        }
    }

    #[test]
    fn soft_object_property_value() {
        let tag = make_tag("SoftObjectProperty", 13);
        let mut ctx = make_ctx(&["None", "/Game/Data/Hero.Hero"]);
        ctx.version.file_version_ue4 = 522; // UE4.27, >= ADDED_SOFT_OBJECT_PATH
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&1i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.extend_from_slice(&1i32.to_le_bytes());
        buf.push(b'\0');
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf), &ctx, "x", 0)
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
        let mut ctx = make_ctx(&["None", "/Game/BP/HeroClass.HeroClass_C"]);
        ctx.version.file_version_ue4 = 522; // UE4.27, >= ADDED_SOFT_OBJECT_PATH
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&1i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.extend_from_slice(&1i32.to_le_bytes());
        buf.push(b'\0');
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf), &ctx, "x", 0)
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
        let val = read_primitive_value(&tag, &mut Cursor::new(&0i32.to_le_bytes()), &ctx, "x", 0)
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
        let val =
            read_primitive_value(&tag, &mut Cursor::new(&(-1i32).to_le_bytes()), &ctx, "x", 0)
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
        let val = read_primitive_value(&tag, &mut Cursor::new(&1i32.to_le_bytes()), &ctx, "x", 0)
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

    /// UE5 >= 1007 (`FSOFTOBJECTPATH_REMOVE_ASSET_PATH_FNAMES`): the
    /// first slot is an `FTopLevelAssetPath` (PackageName FName +
    /// AssetName FName), joined `Package.Asset` per
    /// `FTopLevelAssetPath::ToString`, then the FString sub_path.
    #[test]
    fn soft_object_property_ue5_1007_toplevel_asset_path() {
        let tag = make_tag("SoftObjectProperty", 21);
        let mut ctx = make_ctx(&["None", "/Game/Data/Hero", "Hero"]);
        ctx.version.file_version_ue4 = 522; // UE5 packages carry ue4 == 522
        ctx.version.file_version_ue5 = Some(1007);
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&1i32.to_le_bytes()); // PackageName index
        buf.extend_from_slice(&0i32.to_le_bytes()); // PackageName number
        buf.extend_from_slice(&2i32.to_le_bytes()); // AssetName index
        buf.extend_from_slice(&0i32.to_le_bytes()); // AssetName number
        buf.extend_from_slice(&1i32.to_le_bytes()); // sub_path FString len (empty)
        buf.push(b'\0');
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf), &ctx, "x", 0)
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

    /// AssetName resolves to `None` → `asset_path` is PackageName alone,
    /// with NO trailing dot (`FTopLevelAssetPath::ToString` appends the
    /// dot only together with a non-`None` AssetName).
    #[test]
    fn soft_object_property_ue5_1007_empty_asset_name() {
        let tag = make_tag("SoftObjectProperty", 21);
        let mut ctx = make_ctx(&["None", "/Game/Data/Hero"]);
        ctx.version.file_version_ue4 = 522; // UE5 packages carry ue4 == 522
        ctx.version.file_version_ue5 = Some(1007);
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&1i32.to_le_bytes()); // PackageName index 1
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes()); // AssetName index 0 = None
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.extend_from_slice(&1i32.to_le_bytes()); // empty sub_path
        buf.push(b'\0');
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf), &ctx, "x", 0)
            .unwrap()
            .unwrap();
        assert_eq!(
            val,
            PropertyValue::SoftObjectPath {
                asset_path: "/Game/Data/Hero".to_string(),
                sub_path: String::new(),
            }
        );
    }

    /// PackageName resolves to `None` → the entire `asset_path` is empty
    /// (`FTopLevelAssetPath::ToString` early-returns `""` when
    /// `PackageName.IsNone`), even though both FNames are consumed.
    #[test]
    fn soft_object_property_ue5_1007_none_package_name() {
        let tag = make_tag("SoftObjectProperty", 21);
        let mut ctx = make_ctx(&["None", "Hero"]);
        ctx.version.file_version_ue4 = 522; // UE5 packages carry ue4 == 522
        ctx.version.file_version_ue5 = Some(1007);
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&0i32.to_le_bytes()); // PackageName index 0 = None
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.extend_from_slice(&1i32.to_le_bytes()); // AssetName index 1 = "Hero"
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.extend_from_slice(&1i32.to_le_bytes()); // empty sub_path
        buf.push(b'\0');
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf), &ctx, "x", 0)
            .unwrap()
            .unwrap();
        assert_eq!(
            val,
            PropertyValue::SoftObjectPath {
                asset_path: String::new(),
                sub_path: String::new(),
            }
        );
    }

    /// A non-empty `sub_path` FString is preserved alongside the joined
    /// FTopLevelAssetPath.
    #[test]
    fn soft_object_property_ue5_1007_nonempty_subpath() {
        let tag = make_tag("SoftObjectProperty", 24);
        let mut ctx = make_ctx(&["None", "/Game/Data/Hero", "Hero"]);
        ctx.version.file_version_ue4 = 522; // UE5 packages carry ue4 == 522
        ctx.version.file_version_ue5 = Some(1007);
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&1i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.extend_from_slice(&2i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.extend_from_slice(&4i32.to_le_bytes()); // sub_path len = 4 ("sub\0")
        buf.extend_from_slice(b"sub\0");
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf), &ctx, "x", 0)
            .unwrap()
            .unwrap();
        assert_eq!(
            val,
            PropertyValue::SoftObjectPath {
                asset_path: "/Game/Data/Hero.Hero".to_string(),
                sub_path: "sub".to_string(),
            }
        );
    }

    /// Boundary: at UE5 1006 (below the change) the leading slot is still
    /// a single FName + FString, not an FTopLevelAssetPath.
    #[test]
    fn soft_object_property_ue5_1006_boundary_single_fname() {
        let tag = make_tag("SoftObjectProperty", 13);
        let mut ctx = make_ctx(&["None", "/Game/Data/Hero.Hero"]);
        ctx.version.file_version_ue4 = 522; // UE5 packages carry ue4 == 522
        ctx.version.file_version_ue5 = Some(1006);
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&1i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.extend_from_slice(&1i32.to_le_bytes());
        buf.push(b'\0');
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf), &ctx, "x", 0)
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

    /// `SoftClassProperty` shares the FTopLevelAssetPath wire format at
    /// >= 1007.
    #[test]
    fn soft_class_property_ue5_1007() {
        let tag = make_tag("SoftClassProperty", 21);
        let mut ctx = make_ctx(&["None", "/Game/BP/HeroClass", "HeroClass_C"]);
        ctx.version.file_version_ue4 = 522; // UE5 packages carry ue4 == 522
        ctx.version.file_version_ue5 = Some(1007);
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&1i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.extend_from_slice(&2i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.extend_from_slice(&1i32.to_le_bytes());
        buf.push(b'\0');
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf), &ctx, "x", 0)
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

    /// A null single-FName soft path (`< 1007`, FName index 0 = `None`)
    /// yields an empty `asset_path`, matching `FSoftObjectPath::ToString`'s
    /// uniform `AssetPathName.IsNone → ""` rule — the same result the
    /// >= 1007 None-package case produces, so the two branches agree.
    #[test]
    fn soft_object_property_pre_1007_none_maps_to_empty() {
        let tag = make_tag("SoftObjectProperty", 13);
        let mut ctx = make_ctx(&["None"]);
        ctx.version.file_version_ue4 = 522; // UE4.27, >= ADDED_SOFT_OBJECT_PATH
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&0i32.to_le_bytes()); // FName index 0 = None
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.extend_from_slice(&1i32.to_le_bytes()); // empty sub_path
        buf.push(b'\0');
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf), &ctx, "x", 0)
            .unwrap()
            .unwrap();
        assert_eq!(
            val,
            PropertyValue::SoftObjectPath {
                asset_path: String::new(),
                sub_path: String::new(),
            }
        );
    }

    /// The version-inconsistent index-serialized form
    /// (`soft_object_paths_indexed == true`, only reachable for a crafted
    /// asset — see `AssetContext::soft_object_paths_indexed`) fails closed
    /// with `UnsupportedSoftObjectPathLayout` rather than mis-decoding the
    /// `i32` index as an FName.
    #[test]
    fn soft_object_property_index_form_rejected() {
        let tag = make_tag("SoftObjectProperty", 16);
        let mut ctx = make_ctx(&["None", "/Game/Data/Hero"]);
        ctx.version.file_version_ue5 = Some(1008);
        ctx.soft_object_paths_indexed = true;
        let buf = vec![0u8; 16];
        let err = read_primitive_value(&tag, &mut Cursor::new(&buf), &ctx, "x", 0).unwrap_err();
        assert!(matches!(
            err,
            crate::PaksmithError::AssetParse {
                fault: crate::error::AssetParseFault::UnsupportedSoftObjectPathLayout {
                    ue5_version: 1008
                },
                ..
            }
        ));
    }

    /// UE4 < 514 (`ADDED_SOFT_OBJECT_PATH`): `FSoftObjectPath` is a single
    /// `FString` that CUE4Parse splits on the last `.` — a lossy,
    /// version-inconsistent decomposition with no in-scope oracle fixture.
    /// paksmith fails closed with `UnsupportedFeature` rather than
    /// mis-reading the single FString as FName + FString. #694.
    #[test]
    fn soft_object_property_pre_514_unsupported() {
        let tag = make_tag("SoftObjectProperty", 13);
        let mut ctx = make_ctx(&["None", "/Game/Data/Hero.Hero"]);
        ctx.version.file_version_ue4 = 510; // below ADDED_SOFT_OBJECT_PATH (514)
        let buf = vec![0u8; 13];
        let err = read_primitive_value(&tag, &mut Cursor::new(&buf), &ctx, "x", 0).unwrap_err();
        assert!(
            matches!(err, crate::PaksmithError::UnsupportedFeature { .. }),
            "expected UnsupportedFeature for pre-514 soft path, got {err:?}"
        );
    }

    /// The pre-514 guard is gated on `file_version_ue4` ALONE, not
    /// `&& ue5.is_none()`: a version-inconsistent crafted asset (`ue4 < 514`
    /// with a UE5 version set — the summary reads the two as independent
    /// fields) must STILL fail closed, not fall through to the single-FName
    /// read and mis-decode the pre-514 single-FString wire shape. #694.
    #[test]
    fn soft_object_property_pre_514_version_inconsistent_rejected() {
        let tag = make_tag("SoftObjectProperty", 13);
        let mut ctx = make_ctx(&["None", "/Game/Data/Hero.Hero"]);
        ctx.version.file_version_ue4 = 510; // below 514 ...
        ctx.version.file_version_ue5 = Some(1007); // ... but a UE5 version is set (crafted)
        let buf = vec![0u8; 13];
        let err = read_primitive_value(&tag, &mut Cursor::new(&buf), &ctx, "x", 0).unwrap_err();
        assert!(
            matches!(err, crate::PaksmithError::UnsupportedFeature { .. }),
            "pre-514 guard must fire regardless of file_version_ue5, got {err:?}"
        );
    }

    /// Boundary: at exactly UE4 514 (`ADDED_SOFT_OBJECT_PATH`) the
    /// single-`FName` form applies — NOT the pre-514 fail-close. Pins the
    /// guard's `< 514` against a `<= 514` off-by-one. #694.
    #[test]
    fn soft_object_property_ue4_514_boundary_reads_single_fname() {
        let tag = make_tag("SoftObjectProperty", 13);
        let mut ctx = make_ctx(&["None", "/Game/Data/Hero.Hero"]);
        ctx.version.file_version_ue4 = 514; // exactly ADDED_SOFT_OBJECT_PATH
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&1i32.to_le_bytes()); // FName index 1
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.extend_from_slice(&1i32.to_le_bytes()); // empty sub_path
        buf.push(b'\0');
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf), &ctx, "x", 0)
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
}
