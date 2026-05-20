//! Container property readers: ArrayProperty, StructProperty, MapProperty, SetProperty.
//!
//! Primitive elements are decoded by an internal `read_element_value`
//! helper. Per-collection readers (`read_array_value`,
//! `read_struct_value`, `read_map_value`, `read_set_value`) are
//! private and dispatched through the public [`read_container_value`]
//! entry point.

use std::io::{Read, Seek, SeekFrom};

use byteorder::{LittleEndian, ReadBytesExt};
use tracing::{debug, warn};

use crate::asset::AssetContext;
use crate::asset::package_index::PackageIndex;
use crate::asset::property::primitives::{MapEntry, PropertyValue, read_soft_path_payload};
use crate::asset::property::tag::PropertyTag;
use crate::asset::property::text::{FTextHistory, read_ftext};
use crate::asset::read_asset_fstring;
use crate::error::{
    AssetAllocationContext, AssetParseFault, AssetWireField, CollectionKind, PaksmithError,
    try_reserve_asset,
};

use super::{MAX_COLLECTION_ELEMENTS, read_fname_pair, read_tag, unexpected_eof};

/// Reads a single primitive element value for Array/Map/Set contents.
///
/// Returns `None` for types not yet decoded (`StructProperty` or
/// any other unrecognised type). The caller falls back to
/// `Unknown { skipped_bytes }` via the outer `tag.size`.
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
#[allow(
    clippy::too_many_lines,
    reason = "primitive element-type dispatch — one arm per UE element type with explicit \
              wire reads; splitting would obscure the per-type byte structure"
)]
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
        "TextProperty" => {
            // tag_size=0: None/Base histories are self-delimiting so this is safe.
            // Unknown history would skip 0 bytes; detect it and error instead.
            let text = read_ftext(reader, ctx, asset_path, 0)?;
            if let FTextHistory::Unknown { history_type, .. } = text.history {
                return Err(PaksmithError::AssetParse {
                    asset_path: asset_path.to_string(),
                    fault: AssetParseFault::TextHistoryUnsupportedInElement { history_type },
                });
            }
            PropertyValue::Text(text)
        }
        "SoftObjectProperty" => {
            let (asset_p, sub) = read_soft_path_payload(reader, ctx, asset_path)?;
            PropertyValue::SoftObjectPath {
                asset_path: asset_p,
                sub_path: sub,
            }
        }
        "SoftClassProperty" => {
            let (asset_p, sub) = read_soft_path_payload(reader, ctx, asset_path)?;
            PropertyValue::SoftClassPath {
                asset_path: asset_p,
                sub_path: sub,
            }
        }
        "ObjectProperty" => {
            let raw = reader
                .read_i32::<LittleEndian>()
                .map_err(|_| unexpected_eof(asset_path, body_field))?;
            let kind = PackageIndex::try_from_raw(raw).map_err(|_| PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::PackageIndexUnderflow {
                    field: AssetWireField::ObjectPropertyIndex,
                },
            })?;
            let name = super::primitives::resolve_package_index(kind, ctx, asset_path)?;
            PropertyValue::Object { kind, name }
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
            | "TextProperty"
            | "SoftObjectProperty"
            | "SoftClassProperty"
            | "ObjectProperty"
    )
}

/// Reads an `ArrayProperty` body and returns `PropertyValue::Array`.
///
/// Returns `Ok(None)` if `tag.inner_type` is not handled (e.g.
/// `StructProperty`). No bytes are consumed in that case; the caller
/// skips the body via the outer `tag.size`.
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
    depth: usize,
    asset_path: &str,
) -> crate::Result<Option<PropertyValue>> {
    let is_struct = tag.inner_type == "StructProperty";

    // Unhandled inner types short-circuit WITHOUT consuming bytes so
    // the caller's `tag.size` fallback in `mod.rs::read_properties`
    // lands at the right offset. StructProperty bypasses this guard —
    // it has its own dedicated decode below.
    if !is_struct && !is_handled_element_type(&tag.inner_type) {
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

    if is_struct {
        // Struct elements take a dedicated path: each element is
        // bounded by the per-element size from an inline FPropertyTag
        // header, not by a primitive-element wire layout. See Design
        // Decision #4 in docs/plans/phase-2g-collection-of-struct.md.
        return read_array_of_struct(tag, reader, ctx, depth, count_usize, asset_path);
    }

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

/// Returns `true` when `e` is a wire-shape mismatch *inside* a struct
/// element body that Design Decision #8 of the Phase 2g plan permits
/// us to swallow at the per-element boundary: substituting an empty
/// `PropertyValue::Struct` and reseating the cursor to `element_end`.
///
/// This is an **inclusion list**: only the listed `AssetParseFault`
/// variants are recoverable. Every other variant — and the entire
/// `PaksmithError::Io` family — propagates. New fault variants added
/// to `AssetParseFault` therefore default to safe-propagate; they
/// must be explicitly opted in here.
///
/// Recoverable (wire-shape mismatch on a tagged stream — typical of a
/// custom-binary struct like `FVector` being read as tagged):
/// - `BoundsExceeded`, `NegativeValue` — wire fields with out-of-range values
/// - `PackageIndexOob`, `PackageIndexUnderflow` — bogus FName indices
///   (the canonical "first 8 bytes of a custom-binary body" failure)
/// - `FStringMalformed` — string field inside the element body
/// - `UnexpectedEof` — element body shorter than its declared size
/// - `PropertyTagSizeMismatch` — cursor desync within the element; the
///   re-seat to `element_end` is the correct recovery
/// - `UnversionedTypeNotSupported`, `UnversionedSchemaMissing` —
///   mapping-driven decode hit a gap inside the element body
/// - `TextHistoryUnsupportedInElement`, `UnsupportedSoftObjectPathLayout`
///   — wire-shape inside the element
///
/// Propagated (security caps, system failures, header-level faults
/// that did NOT originate inside the element body):
/// - `PropertyDepthExceeded`, `PropertyTagCountExceeded`,
///   `CollectionElementCountExceeded` — caps must abort, not be
///   silently absorbed
/// - `AllocationFailed` — system memory failure
/// - `PaksmithError::Io` — every variant; underlying I/O is a
///   structural concern, not a wire-shape one
/// - Everything else not listed above
fn is_recoverable_struct_element_error(e: &PaksmithError) -> bool {
    let PaksmithError::AssetParse { fault, .. } = e else {
        return false;
    };
    matches!(
        fault,
        AssetParseFault::BoundsExceeded { .. }
            | AssetParseFault::NegativeValue { .. }
            | AssetParseFault::PackageIndexOob { .. }
            | AssetParseFault::PackageIndexUnderflow { .. }
            | AssetParseFault::FStringMalformed { .. }
            | AssetParseFault::UnexpectedEof { .. }
            | AssetParseFault::PropertyTagSizeMismatch { .. }
            | AssetParseFault::UnversionedTypeNotSupported { .. }
            | AssetParseFault::UnversionedSchemaMissing { .. }
            | AssetParseFault::TextHistoryUnsupportedInElement { .. }
            | AssetParseFault::UnsupportedSoftObjectPathLayout { .. }
    )
}

/// Decodes `Array<StructProperty>` element bodies via the inner
/// FPropertyTag header that UE writes immediately after the element
/// count.
///
/// Wire layout (versioned UE4 ≥ `VER_UE4_INNER_ARRAY_TAG_INFO = 500`,
/// always met for paksmith's UE4 floor of 504): full `FPropertyTag`
/// describing the element struct's name + GUID + per-element size +
/// `count × struct_body`. `count_usize` is read and bound-checked by
/// the caller in `read_array_value`.
///
/// Per-element tagged-iteration failures (typically a custom-binary
/// engine struct like `FVector` whose first FName read OOBs because
/// it's not actually tagged) yield `Struct { struct_name, properties:
/// vec![] }` with the cursor reseated to `element_end`. The catch
/// arm is scoped via [`is_recoverable_struct_element_error`]: security
/// caps (`PropertyDepthExceeded`, `AllocationFailed`, etc.) and I/O
/// errors propagate; only wire-shape mismatches inside the element
/// body are absorbed. This implements Design Decision #8: localising
/// the catch at the element boundary preserves the surrounding array
/// shape and lets adjacent elements still decode, instead of bubbling
/// Err up and reverting the whole export to `PropertyBag::Opaque`.
/// Phase 3+ will replace these empties with typed binary decoders.
///
/// Tasks 4 and 5 (`Map<Struct, *>` / `Set<Struct>`) bail at *collection*
/// level instead — they have no per-element re-anchor point because
/// the wire format omits an inline header. The
/// [`is_recoverable_struct_element_error`] predicate, however, is
/// shared with those callers.
#[allow(
    clippy::cast_sign_loss,
    reason = "inner_header.size is rejected if negative by read_tag"
)]
fn read_array_of_struct<R: Read + Seek>(
    tag: &PropertyTag,
    reader: &mut R,
    ctx: &AssetContext,
    depth: usize,
    count_usize: usize,
    asset_path: &str,
) -> crate::Result<Option<PropertyValue>> {
    let inner_header =
        read_tag(reader, ctx, asset_path)?.ok_or_else(|| PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::ArrayOfStructHeaderMissing {
                array_name: tag.name.clone(),
            },
        })?;

    let mut elements: Vec<PropertyValue> = Vec::new();
    try_reserve_asset(
        &mut elements,
        count_usize,
        asset_path,
        AssetAllocationContext::CollectionElements,
    )?;

    let mut failed_count: usize = 0;

    for i in 0..count_usize {
        let element_start = reader
            .stream_position()
            .map_err(|_| unexpected_eof(asset_path, AssetWireField::ArrayElementBody))?;
        let element_end = element_start.saturating_add(inner_header.size as u64);

        let elem = match read_struct_value(
            &inner_header.struct_name,
            reader,
            ctx,
            depth,
            element_end,
            asset_path,
        ) {
            Ok(value) => {
                // Symmetry with the Err arm: enforce the per-element
                // boundary established by Design Decision #3. If
                // `read_properties` stopped at the None terminator
                // before `element_end` (e.g., a struct body shorter
                // than its declared size due to trailing
                // version-dependent payload), the next iteration's
                // `element_start` MUST be `element_end`, not the
                // current cursor position. Seeking unconditionally
                // also guards against a parser off-by-one inside
                // `read_properties` from desyncing the loop.
                let _ = reader
                    .seek(SeekFrom::Start(element_end))
                    .map_err(|_| unexpected_eof(asset_path, AssetWireField::ArrayElementBody))?;
                value
            }
            Err(e) if is_recoverable_struct_element_error(&e) => {
                failed_count += 1;
                debug!(
                    asset = asset_path,
                    array = tag.name.as_str(),
                    struct_name = inner_header.struct_name.as_str(),
                    index = i,
                    error = %e,
                    "struct element decode failed (likely custom-binary engine \
                     struct); substituting empty properties to preserve array shape"
                );
                let _ = reader
                    .seek(SeekFrom::Start(element_end))
                    .map_err(|_| unexpected_eof(asset_path, AssetWireField::ArrayElementBody))?;
                PropertyValue::Struct {
                    struct_name: inner_header.struct_name.clone(),
                    properties: Vec::new(),
                }
            }
            Err(e) => return Err(e),
        };
        elements.push(elem);
    }

    if failed_count > 0 {
        // One summary log per array, regardless of how many elements
        // failed. Prevents log-volume amplification when an attacker
        // crafts `count = MAX_COLLECTION_ELEMENTS` with every element
        // designed to hit the catch arm. Per-element detail still
        // available at `debug` for operators investigating a specific
        // failure.
        warn!(
            asset = asset_path,
            array = tag.name.as_str(),
            struct_name = inner_header.struct_name.as_str(),
            failed = failed_count,
            total = count_usize,
            "struct element decode substituted empty properties — Phase 3+ adds typed binary decoders"
        );
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
///
/// `struct_name` is taken as `&str` (not a borrowed `PropertyTag`) so
/// this helper can serve both the top-level `StructProperty` dispatch
/// (`&tag.struct_name`) AND Phase 2g's collection-of-struct element
/// decoders, which derive the struct name from a separate source
/// (`Array<Struct>` reads it from an inline header; `Map<Struct, *>`
/// / `Set<Struct>` get `""` because the wire carries no source for
/// the struct type without `.usmap` mappings).
fn read_struct_value<R: Read + Seek>(
    struct_name: &str,
    reader: &mut R,
    ctx: &AssetContext,
    depth: usize,
    expected_end: u64,
    asset_path: &str,
) -> crate::Result<PropertyValue> {
    let properties = super::read_properties(reader, ctx, depth + 1, expected_end, asset_path)?;
    Ok(PropertyValue::Struct {
        struct_name: struct_name.to_string(),
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
    // Plumbed in Task 2 ahead of Task 4's `Map<Struct, *>` /
    // `Map<*, Struct>` branches. `depth` is forwarded into the
    // struct decode's `read_properties` recursion; `expected_end`
    // bounds the per-entry struct decode (no per-element header on
    // the wire — the outer tag's end is the only stopping point).
    // Both unused on the primitive-only path Phase 2c ships.
    _depth: usize,
    _expected_end: u64,
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
    // Plumbed in Task 2 ahead of Task 5's `Set<Struct>` branch.
    // Same role as the matching parameters on `read_map_value`.
    _depth: usize,
    _expected_end: u64,
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
        "ArrayProperty" => read_array_value(tag, reader, ctx, depth, asset_path),
        "StructProperty" => read_struct_value(
            &tag.struct_name,
            reader,
            ctx,
            depth,
            expected_end,
            asset_path,
        )
        .map(Some),
        "MapProperty" => read_map_value(tag, reader, ctx, depth, expected_end, asset_path),
        "SetProperty" => read_set_value(tag, reader, ctx, depth, expected_end, asset_path),
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::property::primitives::PropertyValue;
    use crate::asset::property::test_utils::make_ctx;
    use std::io::Cursor;

    /// One-import test context for `ObjectProperty` element tests.
    ///
    /// Duplicated from `primitives::tests::make_test_ctx_with_import` to keep
    /// the helper test-module-local and avoid exposing a populated-context
    /// builder through `test_utils.rs` for the sole `element_object_property_import`
    /// caller. Names: 0=`"None"`, 1=`"Class"`, 2=`"/Script/CoreUObject"`, 3=<import_name>.
    fn make_test_ctx_with_import(import_name: &str) -> AssetContext {
        use crate::asset::{
            export_table::ExportTable,
            import_table::{ImportTable, ObjectImport},
            name_table::{FName, NameTable},
            version::AssetVersion,
        };
        use std::sync::Arc;
        let names = NameTable {
            names: vec![
                FName::new("None"),
                FName::new("Class"),
                FName::new("/Script/CoreUObject"),
                FName::new(import_name),
            ],
        };
        AssetContext {
            names: Arc::new(names),
            imports: Arc::new(ImportTable {
                imports: vec![ObjectImport {
                    class_package_name: 2,
                    class_package_number: 0,
                    class_name: 1,
                    class_name_number: 0,
                    outer_index: PackageIndex::Null,
                    object_name: 3,
                    object_name_number: 0,
                    import_optional: None,
                }],
            }),
            exports: Arc::new(ExportTable { exports: vec![] }),
            version: AssetVersion {
                legacy_file_version: -7,
                file_version_ue4: 522,
                file_version_ue5: None,
                file_version_licensee_ue4: 0,
            },
            mappings: None,
        }
    }

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
        let v = read_array_value(&tag, &mut r, &ctx, 0, "x.uasset")
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
        let v = read_array_value(&tag, &mut r, &ctx, 0, "x.uasset")
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
        let v = read_array_value(&tag, &mut r, &ctx, 0, "x.uasset")
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
    fn array_negative_count_rejected() {
        use crate::error::{AssetParseFault, CollectionKind, PaksmithError};
        let ctx = make_ctx(&[]);
        let mut r = Cursor::new((-1i32).to_le_bytes().to_vec());
        let tag = make_array_tag("IntProperty", 4);
        let err = read_array_value(&tag, &mut r, &ctx, 0, "x.uasset").unwrap_err();
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
        let err = read_array_value(&tag, &mut r, &ctx, 0, "x.uasset").unwrap_err();
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
        let v =
            read_struct_value(&tag.struct_name, &mut r, &ctx, 0, expected_end, "x.uasset").unwrap();

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
        let v =
            read_struct_value(&tag.struct_name, &mut r, &ctx, 0, expected_end, "x.uasset").unwrap();
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
        let v = read_map_value(&tag, &mut r, &ctx, 0, 0, "x.uasset")
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
        let v = read_map_value(&tag, &mut r, &ctx, 0, 0, "x.uasset")
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
        let v = read_map_value(&tag, &mut r, &ctx, 0, 0, "x.uasset").unwrap();
        assert!(v.is_none());
        assert_eq!(r.position(), 0);
    }

    #[test]
    fn map_struct_value_type_returns_none() {
        let ctx = make_ctx(&[]);
        let mut r = Cursor::new(vec![]);
        let tag = make_map_tag("IntProperty", "StructProperty", 32);
        let v = read_map_value(&tag, &mut r, &ctx, 0, 0, "x.uasset").unwrap();
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
        let err = read_map_value(&tag, &mut r, &ctx, 0, 0, "x.uasset").unwrap_err();
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
        let v = read_set_value(&tag, &mut r, &ctx, 0, 0, "x.uasset")
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
        let v = read_set_value(&tag, &mut r, &ctx, 0, 0, "x.uasset").unwrap();
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
        let err = read_set_value(&tag, &mut r, &ctx, 0, 0, "x.uasset").unwrap_err();
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
        let err = read_map_value(&tag, &mut r, &ctx, 0, 0, "x.uasset").unwrap_err();
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
        let err = read_set_value(&tag, &mut r, &ctx, 0, 0, "x.uasset").unwrap_err();
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
        let v = read_set_value(&tag, &mut r, &ctx, 0, 0, "x.uasset")
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
    fn element_text_none_history() {
        use crate::asset::property::text::FText;
        let ctx = make_ctx(&[]);
        // FText wire: flags(u32=0) + history_type(i8=-1) + bHasCultureInvariant(u8=0)
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&0u32.to_le_bytes()); // flags
        bytes.push(0xFFu8); // history_type = -1 (i8::from_le_bytes([0xFF]))
        bytes.push(0u8); // bHasCultureInvariantString = false
        let mut r = Cursor::new(bytes);
        let v = read_element_value(
            "TextProperty",
            AssetWireField::ArrayElementBody,
            &mut r,
            &ctx,
            "x.uasset",
        )
        .unwrap()
        .unwrap();
        assert!(matches!(
            v,
            PropertyValue::Text(FText {
                history: FTextHistory::None {
                    culture_invariant: None
                },
                ..
            })
        ));
    }

    #[test]
    fn element_text_unknown_history_errors() {
        use crate::error::{AssetParseFault, PaksmithError};
        let ctx = make_ctx(&[]);
        // history_type=3 is unknown. read_ftext(tag_size=0) returns
        // FTextHistory::Unknown { skipped_bytes: 0 } — cursor uncorrupted but
        // caller cannot proceed safely. Must return TextHistoryUnsupportedInElement.
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&0u32.to_le_bytes()); // flags
        bytes.push(3u8); // history_type = 3
        let mut r = Cursor::new(bytes);
        let err = read_element_value(
            "TextProperty",
            AssetWireField::ArrayElementBody,
            &mut r,
            &ctx,
            "x.uasset",
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::TextHistoryUnsupportedInElement { history_type: 3 },
                    ..
                }
            ),
            "expected TextHistoryUnsupportedInElement, got {err:?}",
        );
    }

    #[test]
    fn element_soft_object_path() {
        let ctx = make_ctx(&["None", "/Game/Hero.Hero"]);
        let mut bytes: Vec<u8> = Vec::new();
        // FName asset_path: index=1, number=0
        bytes.extend_from_slice(&1i32.to_le_bytes());
        bytes.extend_from_slice(&0i32.to_le_bytes());
        // FString sub_path: empty (len=1 + b'\0')
        bytes.extend_from_slice(&1i32.to_le_bytes());
        bytes.push(0u8);
        let mut r = Cursor::new(bytes);
        let v = read_element_value(
            "SoftObjectProperty",
            AssetWireField::ArrayElementBody,
            &mut r,
            &ctx,
            "x.uasset",
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            v,
            PropertyValue::SoftObjectPath {
                asset_path: "/Game/Hero.Hero".to_string(),
                sub_path: String::new(),
            }
        );
    }

    #[test]
    fn element_soft_class_path() {
        let ctx = make_ctx(&["None", "/Game/BP/Hero.Hero_C"]);
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&1i32.to_le_bytes());
        bytes.extend_from_slice(&0i32.to_le_bytes());
        bytes.extend_from_slice(&1i32.to_le_bytes());
        bytes.push(0u8);
        let mut r = Cursor::new(bytes);
        let v = read_element_value(
            "SoftClassProperty",
            AssetWireField::ArrayElementBody,
            &mut r,
            &ctx,
            "x.uasset",
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            v,
            PropertyValue::SoftClassPath {
                asset_path: "/Game/BP/Hero.Hero_C".to_string(),
                sub_path: String::new(),
            }
        );
    }

    #[test]
    fn element_object_property_import() {
        let ctx = make_test_ctx_with_import("/Game/Mesh.Mesh");
        let mut r = Cursor::new((-1i32).to_le_bytes().to_vec());
        let v = read_element_value(
            "ObjectProperty",
            AssetWireField::ArrayElementBody,
            &mut r,
            &ctx,
            "x.uasset",
        )
        .unwrap()
        .unwrap();
        // wire i32 -1 -> Import(0); helper's imports[0].object_name = 3 ("/Game/Mesh.Mesh").
        assert_eq!(
            v,
            PropertyValue::Object {
                kind: PackageIndex::Import(0),
                name: "/Game/Mesh.Mesh".to_string(),
            }
        );
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

    #[test]
    fn array_of_struct_inner_header_decodes_two_elements() {
        // Wire bytes: count(2) + inner FPropertyTag header + 2 minimal
        // struct bodies (each = single IntProperty + None terminator).
        //
        // Name table indices used:
        //   0: "None",      1: "Inventory",  2: "StructProperty",
        //   3: "InventorySlot", 4: "ItemId", 5: "IntProperty"
        // Index 0 MUST be "None" — `read_tag` short-circuits `(0, 0)`
        // FName pairs as the None terminator before any name lookup,
        // so a non-None at index 0 would never be reachable.
        let ctx = make_ctx(&[
            "None",
            "Inventory",
            "StructProperty",
            "InventorySlot",
            "ItemId",
            "IntProperty",
        ]);

        let mut bytes: Vec<u8> = Vec::new();
        // count = 2
        bytes.extend_from_slice(&2i32.to_le_bytes());

        // Inner FPropertyTag (49 bytes for a StructProperty tag):
        //   name = "Inventory" (idx 1, num 0)
        //   type = "StructProperty" (idx 2, num 0)
        //   size = <per-element body length, patched below>
        //   array_index = 0
        //   struct_name = "InventorySlot" (idx 3, num 0)
        //   struct_guid = [0; 16]
        //   has_property_guid = 0
        bytes.extend_from_slice(&1i32.to_le_bytes()); // name idx
        bytes.extend_from_slice(&0i32.to_le_bytes()); // name num
        bytes.extend_from_slice(&2i32.to_le_bytes()); // type idx
        bytes.extend_from_slice(&0i32.to_le_bytes()); // type num
        let inner_size_offset = bytes.len();
        bytes.extend_from_slice(&0i32.to_le_bytes()); // size placeholder
        bytes.extend_from_slice(&0i32.to_le_bytes()); // array_index
        bytes.extend_from_slice(&3i32.to_le_bytes()); // struct_name idx
        bytes.extend_from_slice(&0i32.to_le_bytes()); // struct_name num
        bytes.extend_from_slice(&[0u8; 16]); // struct_guid
        bytes.push(0u8); // has_property_guid

        // Per-element body: FPropertyTag for "ItemId: IntProperty=val"
        // + None terminator. Each body is 37 bytes (25-byte primitive
        // tag header + 4-byte i32 value + 8-byte (0,0) None pair).
        let mut elem_body = |val: i32| {
            let start = bytes.len();
            bytes.extend_from_slice(&4i32.to_le_bytes()); // name idx ItemId
            bytes.extend_from_slice(&0i32.to_le_bytes()); // name num
            bytes.extend_from_slice(&5i32.to_le_bytes()); // type idx IntProperty
            bytes.extend_from_slice(&0i32.to_le_bytes()); // type num
            bytes.extend_from_slice(&4i32.to_le_bytes()); // size = 4
            bytes.extend_from_slice(&0i32.to_le_bytes()); // array_index
            bytes.push(0u8); // has_property_guid
            bytes.extend_from_slice(&val.to_le_bytes()); // i32 value
            // None terminator: (0, 0) FName pair
            bytes.extend_from_slice(&0i32.to_le_bytes());
            bytes.extend_from_slice(&0i32.to_le_bytes());
            bytes.len() - start
        };
        // Closure writes a fixed 37-byte sequence per call (varying `val`
        // only patches 4 of those bytes), so the first body's length is
        // the canonical per-element size; the second call's length is
        // structurally identical and not separately used.
        let body_len = elem_body(42);
        let _ = elem_body(99);

        // Patch the inner-header `size` field with the per-element body length.
        let body_len_i32 = i32::try_from(body_len).expect("body within i32");
        bytes[inner_size_offset..inner_size_offset + 4]
            .copy_from_slice(&body_len_i32.to_le_bytes());

        let outer_tag = make_array_tag(
            "StructProperty",
            i32::try_from(bytes.len()).expect("buffer within i32"),
        );
        let buffer_len = bytes.len() as u64;
        let mut cur = Cursor::new(bytes);
        let value = read_array_value(&outer_tag, &mut cur, &ctx, 0, "test")
            .expect("read_array_value")
            .expect("Array<Struct> should decode, not return Ok(None)");

        // The Array<Struct> reader must leave the cursor at the end of
        // the buffer; production code's `actual_pos != expected_end`
        // guard relies on this invariant.
        assert_eq!(
            cur.position(),
            buffer_len,
            "cursor should sit at end of buffer"
        );

        match value {
            PropertyValue::Array {
                inner_type,
                elements,
            } => {
                assert_eq!(inner_type, "StructProperty");
                assert_eq!(elements.len(), 2);
                for (i, expected_val) in [42i32, 99i32].iter().enumerate() {
                    match &elements[i] {
                        PropertyValue::Struct {
                            struct_name,
                            properties,
                        } => {
                            assert_eq!(struct_name, "InventorySlot");
                            assert_eq!(properties.len(), 1, "element {i}");
                            assert_eq!(properties[0].name, "ItemId");
                            assert!(matches!(properties[0].value,
                                PropertyValue::Int(v) if v == *expected_val));
                        }
                        other => panic!("element {i}: expected Struct, got {other:?}"),
                    }
                }
            }
            other => panic!("expected Array, got {other:?}"),
        }
    }

    /// Builds an outer Array<Struct> buffer whose inner FPropertyTag
    /// header advertises `inner_header.size = body_len`, followed by
    /// `element_bodies` concatenated (each must be exactly `body_len`
    /// bytes). The name table layout is fixed: 0=None, 1=Inventory,
    /// 2=StructProperty, 3=InventorySlot, 4=ItemId, 5=IntProperty.
    fn build_array_of_struct_buffer(body_len: usize, element_bodies: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();
        let count = i32::try_from(element_bodies.len()).expect("count fits i32");
        bytes.extend_from_slice(&count.to_le_bytes());
        // Inner FPropertyTag (49 bytes — same layout as the happy-path test).
        bytes.extend_from_slice(&1i32.to_le_bytes()); // name "Inventory"
        bytes.extend_from_slice(&0i32.to_le_bytes());
        bytes.extend_from_slice(&2i32.to_le_bytes()); // type "StructProperty"
        bytes.extend_from_slice(&0i32.to_le_bytes());
        let size_i32 = i32::try_from(body_len).expect("body_len fits i32");
        bytes.extend_from_slice(&size_i32.to_le_bytes()); // size
        bytes.extend_from_slice(&0i32.to_le_bytes()); // array_index
        bytes.extend_from_slice(&3i32.to_le_bytes()); // struct_name "InventorySlot"
        bytes.extend_from_slice(&0i32.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 16]); // struct_guid
        bytes.push(0u8); // has_property_guid
        for body in element_bodies {
            assert_eq!(body.len(), body_len, "every element body must be body_len");
            bytes.extend_from_slice(body);
        }
        bytes
    }

    /// Returns 37 bytes encoding `ItemId: IntProperty = val` + `(0,0)`
    /// None terminator, matching the name-table layout from
    /// `build_array_of_struct_buffer`.
    fn good_struct_body(val: i32) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&4i32.to_le_bytes()); // ItemId idx
        body.extend_from_slice(&0i32.to_le_bytes());
        body.extend_from_slice(&5i32.to_le_bytes()); // IntProperty idx
        body.extend_from_slice(&0i32.to_le_bytes());
        body.extend_from_slice(&4i32.to_le_bytes()); // size = 4
        body.extend_from_slice(&0i32.to_le_bytes()); // array_index
        body.push(0u8); // has_property_guid
        body.extend_from_slice(&val.to_le_bytes());
        body.extend_from_slice(&0i32.to_le_bytes()); // None terminator
        body.extend_from_slice(&0i32.to_le_bytes());
        assert_eq!(body.len(), 37);
        body
    }

    /// Returns 37 bytes whose first FName index is far out of range,
    /// causing `read_struct_value` to fire `PackageIndexOob`. The
    /// remaining bytes are junk that the catch arm's seek-to-element_end
    /// must skip past.
    fn bad_struct_body() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&99_999i32.to_le_bytes()); // OOB name idx
        body.extend_from_slice(&0i32.to_le_bytes());
        body.resize(37, 0xFF);
        body
    }

    #[test]
    fn array_of_struct_missing_inner_header_fires_typed_error() {
        // count = 1, then immediately a (0,0) FName pair where the
        // inner FPropertyTag header should be: `read_tag` returns
        // Ok(None), which the new code maps to ArrayOfStructHeaderMissing.
        let ctx = make_ctx(&["None", "Inventory", "StructProperty"]);
        let mut bytes = 1i32.to_le_bytes().to_vec();
        bytes.extend_from_slice(&0i32.to_le_bytes()); // header name idx 0 (None terminator)
        bytes.extend_from_slice(&0i32.to_le_bytes()); // header name num 0

        let outer_tag = make_array_tag(
            "StructProperty",
            i32::try_from(bytes.len()).expect("fits i32"),
        );
        // Outer tag name must match what the fault payload pins.
        let mut outer_tag = outer_tag;
        outer_tag.name = "Inventory".to_string();
        let err = read_array_value(&outer_tag, &mut Cursor::new(bytes), &ctx, 0, "test.uasset")
            .expect_err("missing inner header must fire typed error");
        match err {
            PaksmithError::AssetParse {
                fault: AssetParseFault::ArrayOfStructHeaderMissing { array_name },
                ..
            } => {
                assert_eq!(array_name, "Inventory");
            }
            other => panic!("expected ArrayOfStructHeaderMissing, got {other:?}"),
        }
    }

    #[test]
    fn array_of_struct_catch_arm_preserves_array_shape_good_bad_good() {
        // 3-element array: good-bad-good. Verifies (a) the bad element
        // becomes Struct { properties: vec![] } via the recoverable
        // catch arm, (b) the cursor reseats to element_end so the
        // trailing good element decodes correctly, (c) shape and order
        // of surrounding elements is preserved.
        let ctx = make_ctx(&[
            "None",
            "Inventory",
            "StructProperty",
            "InventorySlot",
            "ItemId",
            "IntProperty",
        ]);
        let bodies = vec![
            good_struct_body(42),
            bad_struct_body(),
            good_struct_body(99),
        ];
        let bytes = build_array_of_struct_buffer(37, &bodies);
        let outer_tag = make_array_tag(
            "StructProperty",
            i32::try_from(bytes.len()).expect("fits i32"),
        );
        let buffer_len = bytes.len() as u64;
        let mut cur = Cursor::new(bytes);
        let value = read_array_value(&outer_tag, &mut cur, &ctx, 0, "test.uasset")
            .expect("read_array_value")
            .expect("should decode, not return Ok(None)");
        assert_eq!(cur.position(), buffer_len, "cursor at end of buffer");
        match value {
            PropertyValue::Array { elements, .. } => {
                assert_eq!(elements.len(), 3);
                // Element 0: good with val=42
                let PropertyValue::Struct {
                    properties: ref p0, ..
                } = elements[0]
                else {
                    panic!("element 0: expected Struct")
                };
                assert_eq!(p0.len(), 1);
                assert!(matches!(p0[0].value, PropertyValue::Int(42)));
                // Element 1: bad — caught, substituted empty
                let PropertyValue::Struct {
                    ref struct_name,
                    properties: ref p1,
                } = elements[1]
                else {
                    panic!("element 1: expected Struct")
                };
                assert_eq!(struct_name, "InventorySlot");
                assert!(p1.is_empty(), "bad element should have empty properties");
                // Element 2: good with val=99 — proves re-anchor worked
                let PropertyValue::Struct {
                    properties: ref p2, ..
                } = elements[2]
                else {
                    panic!("element 2: expected Struct")
                };
                assert_eq!(p2.len(), 1);
                assert!(matches!(p2[0].value, PropertyValue::Int(99)));
            }
            other => panic!("expected Array, got {other:?}"),
        }
    }

    #[test]
    fn is_recoverable_struct_element_error_predicate_table() {
        // Each row pins one variant against the predicate. Recoverable
        // variants are the inclusion list documented on the predicate;
        // every other variant — and the entire PaksmithError::Io family
        // — must propagate.
        use crate::error::{AssetWireField, BoundsUnit, FStringFault};

        let asset = || "x.uasset".to_string();
        let parse = |fault| PaksmithError::AssetParse {
            asset_path: asset(),
            fault,
        };
        let alloc_err = Vec::<u8>::new()
            .try_reserve_exact(usize::MAX)
            .expect_err("usize::MAX reservation must fail");

        // Recoverable inclusion list.
        let recoverable = [
            parse(AssetParseFault::BoundsExceeded {
                field: AssetWireField::PropertyTagSize,
                value: 1,
                limit: 1,
                unit: BoundsUnit::Bytes,
            }),
            parse(AssetParseFault::NegativeValue {
                field: AssetWireField::PropertyTagSize,
                value: -1,
            }),
            parse(AssetParseFault::PackageIndexOob {
                field: AssetWireField::PropertyTagName,
                index: 9_999_999,
                table_size: 1,
            }),
            parse(AssetParseFault::PackageIndexUnderflow {
                field: AssetWireField::PropertyTagName,
            }),
            parse(AssetParseFault::FStringMalformed {
                kind: FStringFault::LengthIsZero,
            }),
            parse(AssetParseFault::UnexpectedEof {
                field: AssetWireField::ArrayElementBody,
            }),
            parse(AssetParseFault::PropertyTagSizeMismatch {
                expected_end: 100,
                actual_pos: 110,
            }),
            parse(AssetParseFault::UnversionedTypeNotSupported {
                type_byte: 99,
                property_name: "bar".to_string(),
            }),
            parse(AssetParseFault::UnversionedSchemaMissing {
                class_name: "Foo".to_string(),
            }),
            parse(AssetParseFault::TextHistoryUnsupportedInElement { history_type: 1 }),
            parse(AssetParseFault::UnsupportedSoftObjectPathLayout { ue5_version: 100 }),
        ];
        for e in &recoverable {
            assert!(
                is_recoverable_struct_element_error(e),
                "expected recoverable: {e:?}"
            );
        }

        // Propagated: security caps + system + header-level + Io.
        let propagated = [
            parse(AssetParseFault::PropertyDepthExceeded {
                depth: 999,
                limit: 999,
            }),
            parse(AssetParseFault::PropertyTagCountExceeded { limit: 999 }),
            parse(AssetParseFault::CollectionElementCountExceeded {
                collection: CollectionKind::Array,
                count: 999,
                limit: 999,
            }),
            parse(AssetParseFault::AllocationFailed {
                context: AssetAllocationContext::CollectionElements,
                requested: 1,
                source: alloc_err,
            }),
            parse(AssetParseFault::ArrayOfStructHeaderMissing {
                array_name: "Inv".to_string(),
            }),
            PaksmithError::Io(std::io::Error::other("synthetic")),
        ];
        for e in &propagated {
            assert!(
                !is_recoverable_struct_element_error(e),
                "expected propagated: {e:?}"
            );
        }
    }
}
