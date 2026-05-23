//! Unversioned (schema-driven) property decoder.
//!
//! When a package's `PKG_UnversionedProperties` flag is set, the
//! `FPropertyTag` sequence Phase 2b decodes is replaced with a
//! schema-driven layout:
//!
//! 1. An [`UnversionedHeader`] of `u16` fragments + an optional
//!    zero-mask byte run, describing which schema slots have
//!    serialised values vs. zero/default.
//! 2. For each serialised slot, a raw value of the schema-declared
//!    type — no per-property tag, no name, no size hint.
//!
//! The schema comes from a `.usmap` mappings file ([`Usmap`]), loaded
//! by the caller and threaded through [`AssetContext`].
//!
//! Wire format constants come from the oracle
//! `unreal_asset_base::unversioned::header::UnversionedHeaderFragment`.

use std::io::{Cursor, Read};

use byteorder::{LE, ReadBytesExt};
use tracing::warn;

use crate::asset::AssetContext;
use crate::asset::package_index::PackageIndex;
use crate::asset::property::bag::MAX_PROPERTY_DEPTH;
use crate::asset::property::primitives::{
    PropertyValue, read_soft_path_payload, resolve_package_index,
};
use crate::asset::property::text::{FTextHistory, read_ftext};
use crate::asset::property::{MAX_COLLECTION_ELEMENTS, Property, read_fname_pair};
use crate::asset::read_asset_fstring;
use crate::error::{
    AssetAllocationContext, AssetParseFault, AssetWireField, BoundsUnit, CollectionKind,
    PaksmithError, try_reserve_asset,
};

use super::super::mappings::{MappedProperty, MappedPropertyType, Usmap};

// Bit masks from oracle unreal_asset_base::unversioned::header::UnversionedHeaderFragment.
const SKIP_NUM_MASK: u16 = 0x007f;
const HAS_ZEROS_MASK: u16 = 0x0080;
const IS_LAST_MASK: u16 = 0x0100;
const VALUE_NUM_SHIFT: u16 = 9;

/// Maximum fragment count per `FUnversionedHeader`. The header's
/// `first_num`/`cumulative_first` cursors are `u16`, so no legitimate
/// header addresses more than `u16::MAX` schema slots and therefore
/// can't legitimately need more than `u16::MAX` fragments. Without
/// this cap, an export payload filled with `is_last=0` `u16`s grows
/// the fragments vector unbounded — at `MAX_PAYLOAD_BYTES = 256 MiB`
/// that's ~128M fragments × ~8 bytes each ≈ 1 GiB heap, a clean OOM
/// vector. Caught by Task 5 R1 security review.
///
/// Exposed to integration tests via [`max_fragments_per_header`] so
/// boundary tests can read the live value rather than hard-coding the
/// literal — matches the cap-constant convention CLAUDE.md mandates
/// (see `max_uncompressed_entry_bytes` and siblings).
const MAX_FRAGMENTS_PER_HEADER: usize = u16::MAX as usize;

/// Test-only accessor for `MAX_FRAGMENTS_PER_HEADER`, for
/// cross-crate boundary tests in `paksmith-core-tests`. Re-exported
/// at `asset::property` (see `property/mod.rs`) so the path
/// `paksmith_core::asset::property::max_fragments_per_header` is
/// reachable from outside the crate. In-source tests reference the
/// constant directly (same module).
#[cfg(feature = "__test_utils")]
pub fn max_fragments_per_header() -> usize {
    MAX_FRAGMENTS_PER_HEADER
}

/// One `u16` fragment from an unversioned-property header.
///
/// `first_num` is the schema index of the fragment's first VALUE
/// slot (post-skip); `value_num` value slots follow contiguously.
/// `skip_num` and `is_last` are recorded for round-trip-debug
/// transparency even though [`UnversionedHeader::read`] is the only
/// consumer of `is_last` (loop exit) and nothing reads `skip_num`
/// outside tests — keeping them documents the wire layout.
#[derive(Debug, Clone)]
#[allow(
    dead_code,
    reason = "skip_num/is_last document the fragment wire layout; tests assert them"
)]
pub(super) struct Fragment {
    pub skip_num: u8,
    pub value_num: u8,
    pub first_num: u16,
    pub has_zeros: bool,
    pub is_last: bool,
}

/// Parsed `FUnversionedHeader`: a list of fragments + the raw
/// zero-mask byte run (Lsb0 bit ordering, indexed across `has_zeros`
/// fragments in encounter order).
#[derive(Debug, Clone)]
pub(super) struct UnversionedHeader {
    pub fragments: Vec<Fragment>,
    /// Raw zero-mask bytes. Bit ordering is Lsb0: bit 0 of byte 0 is
    /// the first `has_zeros`-fragment value slot.
    pub zero_mask: Vec<u8>,
}

impl UnversionedHeader {
    /// Read fragments until `is_last`, then the zero-mask bytes (if any).
    pub fn read(cur: &mut Cursor<&[u8]>, asset_path: &str) -> crate::Result<Self> {
        let mut fragments: Vec<Fragment> = Vec::new();
        let mut cumulative_first: u16 = 0;
        let mut total_zero_count: u16 = 0;

        loop {
            let packed = cur
                .read_u16::<LE>()
                .map_err(|_| truncated_at(asset_path, AssetWireField::UnversionedFragment))?;
            let skip_num = (packed & SKIP_NUM_MASK) as u8;
            let has_zeros = (packed & HAS_ZEROS_MASK) != 0;
            let is_last = (packed & IS_LAST_MASK) != 0;
            let value_num = (packed >> VALUE_NUM_SHIFT) as u8;
            let first_num = cumulative_first.saturating_add(u16::from(skip_num));
            cumulative_first =
                cumulative_first.saturating_add(u16::from(skip_num) + u16::from(value_num));

            if has_zeros {
                total_zero_count = total_zero_count.saturating_add(u16::from(value_num));
            }

            fragments.push(Fragment {
                skip_num,
                value_num,
                first_num,
                has_zeros,
                is_last,
            });

            if is_last {
                break;
            }
            if fragments.len() >= MAX_FRAGMENTS_PER_HEADER {
                return Err(PaksmithError::AssetParse {
                    asset_path: asset_path.to_string(),
                    fault: AssetParseFault::BoundsExceeded {
                        field: AssetWireField::UnversionedFragment,
                        value: fragments.len() as u64,
                        limit: MAX_FRAGMENTS_PER_HEADER as u64,
                        unit: BoundsUnit::Items,
                    },
                });
            }
        }

        let zero_mask = if total_zero_count > 0 {
            let byte_count = if total_zero_count <= 8 {
                1usize
            } else if total_zero_count <= 16 {
                2usize
            } else {
                usize::from(total_zero_count).div_ceil(32) * 4
            };
            let mut mask = vec![0u8; byte_count];
            cur.read_exact(&mut mask)
                .map_err(|_| truncated_at(asset_path, AssetWireField::UnversionedZeroMask))?;
            mask
        } else {
            Vec::new()
        };

        Ok(UnversionedHeader {
            fragments,
            zero_mask,
        })
    }

    /// Returns `true` if the property at `schema_idx` has a serialised
    /// value (not zero / default).
    ///
    /// `zero_mask_idx` and `frag_idx` are sequential-access cursors —
    /// pass by mutable reference so the caller can advance through
    /// consecutive schema indices in one pass.
    pub fn is_serialized(
        &self,
        schema_idx: u16,
        zero_mask_idx: &mut usize,
        frag_idx: &mut usize,
    ) -> bool {
        while *frag_idx < self.fragments.len() {
            let frag = &self.fragments[*frag_idx];
            let value_start = frag.first_num;
            // saturating_add: `first_num` is `u16`, `value_num` is `u8`; an
            // adversarial header with `first_num` near u16::MAX could overflow
            // a plain `+` in debug. Saturating to u16::MAX keeps the check
            // structurally correct (schema_idx < u16::MAX is the same
            // disjunction we want).
            let value_end = frag.first_num.saturating_add(u16::from(frag.value_num));

            if schema_idx < value_start {
                return false; // in the skip range before this fragment
            }
            if schema_idx < value_end {
                if frag.has_zeros {
                    let bit_idx = *zero_mask_idx;
                    *zero_mask_idx += 1;
                    let byte = self.zero_mask.get(bit_idx / 8).copied().unwrap_or(0);
                    let bit = (byte >> (bit_idx % 8)) & 1;
                    return bit == 0; // 0 = non-zero = serialised; 1 = zero = default
                }
                return true;
            }
            *frag_idx += 1;
        }
        false
    }
}

/// Decode all unversioned properties for an export whose class is
/// `class_name`.
///
/// **Partial-tree contract.** If decoding hits
/// [`AssetParseFault::UnversionedTypeNotSupported`] at any depth
/// (Map / Set / Delegate / Interface / FieldPath are not yet
/// supported), the recursion unwinds back to this function, which
/// logs at `warn` and returns the partial `Vec<Property>` collected
/// so far. Subsequent properties — whose offsets depend on the
/// failed read's byte count — are NOT decoded; the alternative is
/// silent misparse.
///
/// All other errors propagate to the caller.
pub(crate) fn read_unversioned_properties(
    cur: &mut Cursor<&[u8]>,
    class_name: &str,
    usmap: &Usmap,
    ctx: &AssetContext,
    asset_path: &str,
    depth: usize,
) -> crate::Result<Vec<Property>> {
    if depth > MAX_PROPERTY_DEPTH {
        return Err(PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::PropertyDepthExceeded {
                depth,
                limit: MAX_PROPERTY_DEPTH,
            },
        });
    }

    let all_props = usmap.get_all_properties(class_name);
    if all_props.is_empty() {
        // At depth 0 the export simply has no schema — log and emit an
        // empty bag (the outermost class lookup may resolve to `""` for
        // `PackageIndex::Null`, which we treat as "skip this export"
        // rather than a hard error).
        //
        // At depth > 0 we are inside a nested `StructProperty` whose
        // length is schema-defined; returning Ok here would leave the
        // outer cursor parked at the struct's payload start and every
        // subsequent property would mis-decode. Surface the missing
        // schema as a typed error and let the outermost frame's catch
        // arm stop the walk cleanly.
        if depth > 0 {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::UnversionedSchemaMissing {
                    class_name: class_name.to_string(),
                },
            });
        }
        warn!(
            asset_path,
            class_name, "no schema found for class; skipping unversioned properties"
        );
        return Ok(Vec::new());
    }

    let header = UnversionedHeader::read(cur, asset_path)?;

    // `is_serialized`'s `frag_idx` / `zero_mask_idx` cursors only
    // advance forward; calling it with non-monotonically-increasing
    // slot index would mis-resolve the header. `get_all_properties`
    // returns properties with child-first-concat absolute indices
    // (per CUE4Parse `MappingsSchema.Struct.TryGetValue`), which IS
    // the monotonic ordering the header consumes — but we still sort
    // defensively so an adversarial `.usmap` with out-of-order
    // per-class schema entries doesn't silently drop or mis-decode
    // slots. Sort is stable to preserve relative order on ties.
    //
    // Latent bug that this sort does NOT resolve, tracked separately:
    //   - #392: `zero_mask_idx` drifts when a single `has_zeros=true`
    //     fragment covers a sparse schema; needs header-driven walk
    //     (or per-slot bit indexing) — the architectural inversion to
    //     `FIterator`-driven iteration that matches CUE4Parse's
    //     `UObject.DeserializePropertiesUsmap`.
    let mut all_props = all_props;
    all_props.sort_by_key(|rp| rp.absolute_index);

    let mut result: Vec<Property> = Vec::new();
    let mut zero_mask_idx = 0usize;
    let mut frag_idx = 0usize;

    for resolved in &all_props {
        // `absolute_index` is the wire absolute slot index after the
        // child-first-concat inheritance offset (see
        // [`Usmap::get_all_properties`]). The unversioned wire
        // stream's `FUnversionedHeader` fragments address these same
        // absolute indices — using `resolved.property.schema_index`
        // directly would mis-decode every inherited class where
        // child + parent overlap at the same per-class index.
        let schema_idx = resolved.absolute_index;
        if !header.is_serialized(schema_idx, &mut zero_mask_idx, &mut frag_idx) {
            continue;
        }
        let mapped_prop = resolved.property;

        match read_unversioned_value(cur, mapped_prop, usmap, ctx, asset_path, depth) {
            Ok(value) => {
                result.push(Property {
                    name: mapped_prop.name.clone(),
                    array_index: mapped_prop.array_index,
                    guid: None,
                    value,
                });
            }
            // Only catch at the outermost frame. Catching at any inner
            // frame (nested struct, array element) would return a
            // partial subtree with the cursor parked mid-payload —
            // subsequent properties would then read garbage off the
            // tail bytes of the failed read. Propagating through inner
            // frames lets the outermost decoder break cleanly *for the
            // whole export* the moment any nested decode aborts.
            //
            // Both `UnversionedTypeNotSupported` (Map/Set/Delegate/...)
            // and `UnversionedSchemaMissing` (nested struct whose schema
            // isn't in the .usmap) trigger the same partial-tree stop:
            // each represents "cannot safely advance the cursor".
            Err(e) if is_partial_tree_stop(&e) && depth == 0 => {
                warn!(
                    asset_path,
                    class_name,
                    property = mapped_prop.name.as_str(),
                    error = %e,
                    "unversioned property cannot be decoded; stopping read"
                );
                break;
            }
            Err(e) => return Err(e),
        }
    }

    Ok(result)
}

fn is_partial_tree_stop(e: &PaksmithError) -> bool {
    matches!(
        e,
        PaksmithError::AssetParse {
            fault: AssetParseFault::UnversionedTypeNotSupported { .. }
                | AssetParseFault::UnversionedSchemaMissing { .. }
                | AssetParseFault::TextHistoryUnsupportedInElement { .. },
            ..
        }
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "single match arm per MappedPropertyType variant; splitting per arm would scatter the per-type wire-format mapping across multiple files"
)]
fn read_unversioned_value(
    cur: &mut Cursor<&[u8]>,
    prop: &MappedProperty,
    usmap: &Usmap,
    ctx: &AssetContext,
    asset_path: &str,
    depth: usize,
) -> crate::Result<PropertyValue> {
    use MappedPropertyType as MT;
    // Depth gate for the array recursion path (struct nesting hits the
    // mirror gate at the top of `read_unversioned_properties`). Without
    // this, an adversarial `Array<Array<Array<...>>>` chain could blow
    // the Rust stack — each level here is a regular function call that
    // never hits the schema-walk gate.
    if depth > MAX_PROPERTY_DEPTH {
        return Err(PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::PropertyDepthExceeded {
                depth,
                limit: MAX_PROPERTY_DEPTH,
            },
        });
    }
    let value_eof = || truncated_at(asset_path, AssetWireField::UnversionedValue);
    Ok(match &prop.prop_type {
        MT::Bool => PropertyValue::Bool(cur.read_u8().map_err(|_| value_eof())? != 0),
        MT::Int8 => PropertyValue::Int8(cur.read_i8().map_err(|_| value_eof())?),
        MT::Int16 => PropertyValue::Int16(cur.read_i16::<LE>().map_err(|_| value_eof())?),
        MT::Int32 => PropertyValue::Int(cur.read_i32::<LE>().map_err(|_| value_eof())?),
        MT::Int64 => PropertyValue::Int64(cur.read_i64::<LE>().map_err(|_| value_eof())?),
        MT::UInt8 => PropertyValue::Byte(cur.read_u8().map_err(|_| value_eof())?),
        MT::UInt16 => PropertyValue::UInt16(cur.read_u16::<LE>().map_err(|_| value_eof())?),
        MT::UInt32 => PropertyValue::UInt32(cur.read_u32::<LE>().map_err(|_| value_eof())?),
        MT::UInt64 => PropertyValue::UInt64(cur.read_u64::<LE>().map_err(|_| value_eof())?),
        MT::Float => PropertyValue::Float(cur.read_f32::<LE>().map_err(|_| value_eof())?),
        MT::Double => PropertyValue::Double(cur.read_f64::<LE>().map_err(|_| value_eof())?),
        MT::Str => PropertyValue::Str(read_asset_fstring(cur, asset_path)?),
        MT::Name => PropertyValue::Name(read_fname_pair(
            cur,
            ctx,
            asset_path,
            AssetWireField::PropertyTagName,
        )?),
        MT::Text => {
            // Mirror containers.rs:133-143: `read_ftext` (Phase 2b) is
            // size-permissive at `tag_size = 0` for None / Base histories,
            // but `FTextHistory::Unknown` cannot be decoded without a size
            // hint and would silently swallow subsequent bytes. Reject
            // explicitly so the partial-tree contract surfaces the issue.
            let text = read_ftext(cur, ctx, asset_path, 0)?;
            if let FTextHistory::Unknown { history_type, .. } = text.history {
                return Err(PaksmithError::AssetParse {
                    asset_path: asset_path.to_string(),
                    fault: AssetParseFault::TextHistoryUnsupportedInElement { history_type },
                });
            }
            PropertyValue::Text(text)
        }
        MT::Enum { enum_name } => {
            // Per CUE4Parse's EnumProperty constructor (`HasUnversionedProperties
            // && type == NORMAL`): a single u8 ordinal — the default ByteProperty
            // storage. Non-byte underlying types are rare and deferred.
            let idx = cur.read_u8().map_err(|_| value_eof())?;
            let value = usmap
                .enums
                .get(enum_name)
                .and_then(|values| values.get(&u64::from(idx)))
                .cloned()
                .unwrap_or_else(|| format!("{enum_name}::{idx}"));
            PropertyValue::Enum {
                type_name: enum_name.clone(),
                value,
            }
        }
        MT::Object => {
            // ObjectProperty wire format is identical in versioned and
            // unversioned modes: a raw i32 package index. The typed `kind`
            // preserves Null / Import(N) / Export(N) discrimination.
            let raw = cur.read_i32::<LE>().map_err(|_| value_eof())?;
            let kind = PackageIndex::try_from_raw(raw).map_err(|_| PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::PackageIndexUnderflow {
                    field: AssetWireField::ObjectPropertyIndex,
                },
            })?;
            let name = resolve_package_index(kind, ctx, asset_path).unwrap_or_default();
            PropertyValue::Object { kind, name }
        }
        MT::SoftObject => {
            // FSoftObjectPath wire format = FName + FString (per CUE4Parse).
            let (asset_path_str, sub_path) = read_soft_path_payload(cur, ctx, asset_path)?;
            PropertyValue::SoftObjectPath {
                asset_path: asset_path_str,
                sub_path,
            }
        }
        MT::Struct { struct_name } => {
            let nested =
                read_unversioned_properties(cur, struct_name, usmap, ctx, asset_path, depth + 1)?;
            PropertyValue::Struct {
                struct_name: struct_name.clone(),
                properties: nested,
            }
        }
        MT::Array { inner } => {
            let count_i32 = cur
                .read_i32::<LE>()
                .map_err(|_| truncated_at(asset_path, AssetWireField::ArrayElementCount))?;
            let count = usize::try_from(count_i32)
                .ok()
                .filter(|&n| n <= MAX_COLLECTION_ELEMENTS);
            let Some(count) = count else {
                return Err(PaksmithError::AssetParse {
                    asset_path: asset_path.to_string(),
                    fault: AssetParseFault::CollectionElementCountExceeded {
                        collection: CollectionKind::Array,
                        count: count_i32,
                        limit: MAX_COLLECTION_ELEMENTS,
                    },
                });
            };
            let mut elements: Vec<PropertyValue> = Vec::new();
            try_reserve_asset(
                &mut elements,
                count,
                asset_path,
                AssetAllocationContext::CollectionElements,
            )?;
            let synthetic = MappedProperty {
                name: String::new(),
                schema_index: 0,
                array_index: 0,
                prop_type: (**inner).clone(),
            };
            // depth + 1 so MAX_PROPERTY_DEPTH is enforced for nested
            // `Array<Array<...>>` chains; without the increment the
            // recursion can grow unbounded along the array axis.
            for _ in 0..count {
                elements.push(read_unversioned_value(
                    cur,
                    &synthetic,
                    usmap,
                    ctx,
                    asset_path,
                    depth + 1,
                )?);
            }
            PropertyValue::Array {
                inner_type: mapped_type_wire_name(inner).to_string(),
                elements,
            }
        }
        MT::Unknown(byte) => {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::UnversionedTypeNotSupported {
                    type_byte: *byte,
                    property_name: prop.name.clone(),
                },
            });
        }
    })
}

/// Map a [`MappedPropertyType`] back to its UE wire-format type name
/// (e.g. `"IntProperty"`, `"FloatProperty"`) for storage in
/// [`PropertyValue::Array::inner_type`]. Inverse of the byte → type
/// mapping in `mappings.rs::read_mapped_type`.
fn mapped_type_wire_name(t: &MappedPropertyType) -> &'static str {
    match t {
        MappedPropertyType::Bool => "BoolProperty",
        MappedPropertyType::Int8 => "Int8Property",
        MappedPropertyType::Int16 => "Int16Property",
        MappedPropertyType::Int32 => "IntProperty",
        MappedPropertyType::Int64 => "Int64Property",
        MappedPropertyType::UInt8 => "ByteProperty",
        MappedPropertyType::UInt16 => "UInt16Property",
        MappedPropertyType::UInt32 => "UInt32Property",
        MappedPropertyType::UInt64 => "UInt64Property",
        MappedPropertyType::Float => "FloatProperty",
        MappedPropertyType::Double => "DoubleProperty",
        MappedPropertyType::Str => "StrProperty",
        MappedPropertyType::Name => "NameProperty",
        MappedPropertyType::Text => "TextProperty",
        MappedPropertyType::Enum { .. } => "EnumProperty",
        MappedPropertyType::Struct { .. } => "StructProperty",
        MappedPropertyType::Object => "ObjectProperty",
        MappedPropertyType::SoftObject => "SoftObjectProperty",
        MappedPropertyType::Array { .. } => "ArrayProperty",
        MappedPropertyType::Unknown(_) => "Unknown",
    }
}

fn truncated_at(asset_path: &str, field: AssetWireField) -> PaksmithError {
    PaksmithError::AssetParse {
        asset_path: asset_path.to_string(),
        fault: AssetParseFault::UnexpectedEof { field },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::Cursor;

    use crate::asset::mappings::ClassSchema;
    use crate::asset::property::primitives::PropertyValue;
    use crate::asset::property::test_utils::make_ctx;

    fn two_prop_header_bytes() -> Vec<u8> {
        // Fragment: skip=0, has_zeros=false, is_last=true, value_num=2
        // packed = 0x0100 | (2u16 << 9) = 0x0100 | 0x0400 = 0x0500
        vec![0x00u8, 0x05]
    }

    #[test]
    fn header_no_zeros_two_props() {
        let bytes = two_prop_header_bytes();
        let mut cur = Cursor::new(bytes.as_slice());
        let hdr = UnversionedHeader::read(&mut cur, "test.uasset").unwrap();
        assert_eq!(hdr.fragments.len(), 1);
        assert_eq!(hdr.fragments[0].first_num, 0);
        assert_eq!(hdr.fragments[0].value_num, 2);
        assert!(!hdr.fragments[0].has_zeros);
        assert!(hdr.fragments[0].is_last);
        assert!(hdr.zero_mask.is_empty());
    }

    #[test]
    fn header_is_serialized_all_present() {
        let bytes = two_prop_header_bytes();
        let mut cur = Cursor::new(bytes.as_slice());
        let hdr = UnversionedHeader::read(&mut cur, "test.uasset").unwrap();
        let mut zi = 0usize;
        let mut fi = 0usize;
        assert!(hdr.is_serialized(0, &mut zi, &mut fi));
        assert!(hdr.is_serialized(1, &mut zi, &mut fi));
        assert!(!hdr.is_serialized(2, &mut zi, &mut fi)); // past end → default
    }

    #[test]
    fn header_with_skip() {
        // Fragment: skip=1, has_zeros=false, is_last=true, value_num=1
        // packed = 1 | 0x0100 | (1u16 << 9) = 1 | 0x0100 | 0x0200 = 0x0301
        let bytes = vec![0x01u8, 0x03];
        let mut cur = Cursor::new(bytes.as_slice());
        let hdr = UnversionedHeader::read(&mut cur, "test.uasset").unwrap();
        assert_eq!(hdr.fragments[0].first_num, 1);
        assert_eq!(hdr.fragments[0].value_num, 1);
        let mut zi = 0usize;
        let mut fi = 0usize;
        // schema index 0 is in skip range → not serialised
        assert!(!hdr.is_serialized(0, &mut zi, &mut fi));
        // schema index 1 is the one value → serialised
        assert!(hdr.is_serialized(1, &mut zi, &mut fi));
    }

    #[test]
    fn header_with_zero_mask() {
        // Fragment: skip=0, has_zeros=true, is_last=true, value_num=2
        // packed = 0x0080 | 0x0100 | (2u16 << 9) = 0x0580
        // zero_mask: 2 bits in 1 byte; bit0=0 (non-zero), bit1=1 (zero) → 0x02
        let bytes = vec![0x80u8, 0x05, 0x02u8];
        let mut cur = Cursor::new(bytes.as_slice());
        let hdr = UnversionedHeader::read(&mut cur, "test.uasset").unwrap();
        assert_eq!(hdr.zero_mask.len(), 1);
        let mut zi = 0usize;
        let mut fi = 0usize;
        assert!(hdr.is_serialized(0, &mut zi, &mut fi));
        assert!(!hdr.is_serialized(1, &mut zi, &mut fi));
    }

    #[test]
    fn read_unversioned_properties_uses_wire_schema_index_for_sparse_schema() {
        // Build a Usmap with one class `Hero` whose two serializable
        // properties are declared at WIRE schema_indices 0 and 2
        // (sparse — slot 1 is absent from the schema, e.g. transient
        // or editor-only in the originating UE class).
        //
        // Witness for the wire-as-absolute-index convention:
        //   CUE4Parse `UsmapProperties.ParseStruct` writes
        //   `properties[propInfo.Index + j] = clone` keyed by the
        //   wire-declared index; `UObject.DeserializePropertiesUsmap`
        //   walks `FIterator(header)` and calls
        //   `propMappings.TryGetValue(slot_idx, ...)` with the
        //   header's emitted slot indices.
        let hero = ClassSchema {
            name: "Hero".to_string(),
            super_type: None,
            // 3 wire-declared total slots: Health@0, transient@1, Color@2.
            // `serial_count` (the size of `properties`) is 2.
            prop_count: 3,
            properties: vec![
                MappedProperty {
                    name: "Health".to_string(),
                    schema_index: 0,
                    array_index: 0,
                    prop_type: MappedPropertyType::Int32,
                },
                MappedProperty {
                    name: "Color".to_string(),
                    schema_index: 2,
                    array_index: 0,
                    prop_type: MappedPropertyType::Int32,
                },
            ],
        };
        let mut schemas = HashMap::new();
        let _ = schemas.insert("Hero".to_string(), hero);
        let usmap = Usmap {
            schemas,
            enums: HashMap::new(),
        };

        // Wire bytes:
        //   Fragment 0: skip=0, value_num=1, has_zeros=false, is_last=false
        //     packed = 0 | 0 | 0 | (1 << 9) = 0x0200
        //   Fragment 1: skip=1, value_num=1, has_zeros=false, is_last=true
        //     packed = 1 | 0x0100 | (1 << 9) = 0x0301
        //   Followed by two i32 LE values: Health=42, Color=99.
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&0x0200u16.to_le_bytes()); // fragment 0
        bytes.extend_from_slice(&0x0301u16.to_le_bytes()); // fragment 1
        bytes.extend_from_slice(&42i32.to_le_bytes()); // Health value
        bytes.extend_from_slice(&99i32.to_le_bytes()); // Color value

        let ctx = make_ctx(&[]);
        let mut cur = Cursor::new(bytes.as_slice());
        let props = read_unversioned_properties(&mut cur, "Hero", &usmap, &ctx, "test", 0)
            .expect("read_unversioned_properties");

        assert_eq!(
            props.len(),
            2,
            "sparse schema should decode both slots — bug substitutes Color with nothing"
        );
        let health = props.iter().find(|p| p.name == "Health").expect("Health");
        assert!(
            matches!(health.value, PropertyValue::Int(42)),
            "Health should be Int(42), got {:?}",
            health.value
        );
        let color = props.iter().find(|p| p.name == "Color").expect("Color");
        assert!(
            matches!(color.value, PropertyValue::Int(99)),
            "Color should be Int(99) — under the bug it gets the wrong fragment or never decodes"
        );
    }

    #[test]
    fn read_unversioned_properties_sorts_out_of_order_schema_indices() {
        // Adversarial `.usmap`: the schema declares two properties
        // whose wire-declared `schema_index` values appear in
        // descending order (Color at 2 first, then Health at 0). The
        // wire stream still encodes values in ascending slot order
        // (Health at slot 0, Color at slot 2) — that's the asset's
        // FUnversionedHeader convention. Without the defensive sort
        // in `read_unversioned_properties`, the `is_serialized`
        // cursor would advance past slot 0 on the first iteration
        // and reject the second call as in-the-skip-range.
        let hero = ClassSchema {
            name: "Hero".to_string(),
            super_type: None,
            // 3 wire-declared total slots (Health@0, transient@1, Color@2);
            // `serial_count` (the size of `properties`) is 2.
            prop_count: 3,
            properties: vec![
                MappedProperty {
                    name: "Color".to_string(),
                    schema_index: 2,
                    array_index: 0,
                    prop_type: MappedPropertyType::Int32,
                },
                MappedProperty {
                    name: "Health".to_string(),
                    schema_index: 0,
                    array_index: 0,
                    prop_type: MappedPropertyType::Int32,
                },
            ],
        };
        let mut schemas = HashMap::new();
        let _ = schemas.insert("Hero".to_string(), hero);
        let usmap = Usmap {
            schemas,
            enums: HashMap::new(),
        };

        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&0x0200u16.to_le_bytes()); // skip=0, val=1, is_last=0
        bytes.extend_from_slice(&0x0301u16.to_le_bytes()); // skip=1, val=1, is_last=1
        bytes.extend_from_slice(&42i32.to_le_bytes()); // Health (slot 0)
        bytes.extend_from_slice(&99i32.to_le_bytes()); // Color (slot 2)

        let ctx = make_ctx(&[]);
        let mut cur = Cursor::new(bytes.as_slice());
        let props = read_unversioned_properties(&mut cur, "Hero", &usmap, &ctx, "test", 0)
            .expect("read_unversioned_properties");

        assert_eq!(props.len(), 2);
        let health = props.iter().find(|p| p.name == "Health").expect("Health");
        assert!(matches!(health.value, PropertyValue::Int(42)));
        let color = props.iter().find(|p| p.name == "Color").expect("Color");
        assert!(matches!(color.value, PropertyValue::Int(99)));
    }

    #[test]
    fn read_unversioned_properties_decodes_inherited_class_with_overlapping_indices() {
        // Bug pinned: a `.usmap` with `Child : Parent` where both
        // classes declare a per-class slot 0 must produce a flattened
        // wire absolute slot mapping of `Child.y@0`, `Parent.x@1`
        // (child-first concat per CUE4Parse `MappingsSchema.Struct.
        // TryGetValue`). The previous parent-first walk surfaced each
        // per-class `schema_index` as if it were absolute and silently
        // mis-decoded inherited classes whose child and parent slots
        // collided at the same per-class index.
        //
        // Witness: CUE4Parse `MappingsProvider/Usmap/MappingsSchema.cs`:
        //   if (!Properties.TryGetValue(i, out info)) {
        //     return i >= PropertyCount && Super.Value != null &&
        //       Super.Value.TryGetValue(i - PropertyCount, out info);
        //   }
        let parent = ClassSchema {
            name: "Parent".to_string(),
            super_type: None,
            prop_count: 1,
            properties: vec![MappedProperty {
                name: "x".to_string(),
                schema_index: 0, // per-class
                array_index: 0,
                prop_type: MappedPropertyType::Int32,
            }],
        };
        let child = ClassSchema {
            name: "Child".to_string(),
            super_type: Some("Parent".to_string()),
            prop_count: 1, // child's own count, NOT parent + child
            properties: vec![MappedProperty {
                name: "y".to_string(),
                schema_index: 0, // per-class
                array_index: 0,
                prop_type: MappedPropertyType::Int32,
            }],
        };
        let mut schemas = HashMap::new();
        let _ = schemas.insert("Parent".to_string(), parent);
        let _ = schemas.insert("Child".to_string(), child);
        let usmap = Usmap {
            schemas,
            enums: HashMap::new(),
        };

        // Wire bytes: single fragment skip=0, value_num=2, has_zeros=false, is_last=true
        // packed = 0 | 0x0100 | (2 << 9) = 0x0500
        // Followed by two i32: y=7 (slot 0, child's), x=42 (slot 1, parent's).
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&0x0500u16.to_le_bytes());
        bytes.extend_from_slice(&7i32.to_le_bytes());
        bytes.extend_from_slice(&42i32.to_le_bytes());

        let ctx = make_ctx(&[]);
        let mut cur = Cursor::new(bytes.as_slice());
        let props = read_unversioned_properties(&mut cur, "Child", &usmap, &ctx, "test", 0)
            .expect("read_unversioned_properties");

        assert_eq!(props.len(), 2, "must decode both inherited and own slots");
        let y = props.iter().find(|p| p.name == "y").expect("y");
        assert!(
            matches!(y.value, PropertyValue::Int(7)),
            "child's `y` must decode the first wire i32 (slot 0); got {:?}",
            y.value
        );
        let x = props.iter().find(|p| p.name == "x").expect("x");
        assert!(
            matches!(x.value, PropertyValue::Int(42)),
            "parent's `x` must decode the second wire i32 (slot 1, offset by Child.PropertyCount); got {:?}",
            x.value
        );
    }

    #[test]
    fn read_unversioned_properties_decodes_three_level_inheritance_chain() {
        // Multi-level inheritance: Grandchild : Child : Parent.
        // Every class declares its own slot 0 — adversarial overlap on
        // the per-class index across THREE levels. Wire absolute slot
        // map (child-first concat):
        //   Grandchild's `z` @ per-class 0 → absolute 0
        //   Child's      `y` @ per-class 0 → absolute 1 (offset += Grandchild.prop_count)
        //   Parent's     `x` @ per-class 0 → absolute 2 (offset += Child.prop_count)
        // A regression that resets `offset` per class (e.g.
        // `offset = u32::from(prop_count)` instead of `+=`) would
        // produce Parent.x @ absolute 1, colliding with Child.y; this
        // test catches it.
        let parent = ClassSchema {
            name: "Parent".to_string(),
            super_type: None,
            prop_count: 1,
            properties: vec![MappedProperty {
                name: "x".to_string(),
                schema_index: 0,
                array_index: 0,
                prop_type: MappedPropertyType::Int32,
            }],
        };
        let child = ClassSchema {
            name: "Child".to_string(),
            super_type: Some("Parent".to_string()),
            prop_count: 1,
            properties: vec![MappedProperty {
                name: "y".to_string(),
                schema_index: 0,
                array_index: 0,
                prop_type: MappedPropertyType::Int32,
            }],
        };
        let grandchild = ClassSchema {
            name: "Grandchild".to_string(),
            super_type: Some("Child".to_string()),
            prop_count: 1,
            properties: vec![MappedProperty {
                name: "z".to_string(),
                schema_index: 0,
                array_index: 0,
                prop_type: MappedPropertyType::Int32,
            }],
        };
        let mut schemas = HashMap::new();
        let _ = schemas.insert("Parent".to_string(), parent);
        let _ = schemas.insert("Child".to_string(), child);
        let _ = schemas.insert("Grandchild".to_string(), grandchild);
        let usmap = Usmap {
            schemas,
            enums: HashMap::new(),
        };

        // Wire bytes: skip=0, value_num=3, has_zeros=false, is_last=true
        // packed = 0 | 0x0100 | (3 << 9) = 0x0700
        // Followed by three i32: z=1 (slot 0), y=2 (slot 1), x=3 (slot 2).
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&0x0700u16.to_le_bytes());
        bytes.extend_from_slice(&1i32.to_le_bytes());
        bytes.extend_from_slice(&2i32.to_le_bytes());
        bytes.extend_from_slice(&3i32.to_le_bytes());

        let ctx = make_ctx(&[]);
        let mut cur = Cursor::new(bytes.as_slice());
        let props = read_unversioned_properties(&mut cur, "Grandchild", &usmap, &ctx, "test", 0)
            .expect("read_unversioned_properties");

        assert_eq!(props.len(), 3, "all three inherited slots must decode");
        let z = props.iter().find(|p| p.name == "z").expect("z");
        assert!(matches!(z.value, PropertyValue::Int(1)));
        let y = props.iter().find(|p| p.name == "y").expect("y");
        assert!(matches!(y.value, PropertyValue::Int(2)));
        let x = props.iter().find(|p| p.name == "x").expect("x");
        assert!(matches!(x.value, PropertyValue::Int(3)));
    }

    #[test]
    fn header_rejects_unbounded_fragment_stream() {
        // Pack `cap + N` fragments with `is_last=0` to verify the
        // MAX_FRAGMENTS_PER_HEADER cap fires before `fragments` grows
        // past the cap. Each 2-byte u16 with no bits set encodes a
        // `skip=0, value_num=0, is_last=0, has_zeros=0` fragment — the
        // worst-case attacker shape (every iteration pushes one
        // fragment, never exits via `is_last`). The read loop must
        // surface `BoundsExceeded { field: UnversionedFragment }`
        // rather than letting the Vec grow unbounded.
        //
        // Uses `MAX_FRAGMENTS_PER_HEADER` directly (same module). The
        // `max_fragments_per_header()` accessor is for cross-crate
        // boundary tests in `paksmith-core-tests`; using the constant
        // here keeps this OOM-security test on plain `cargo test`
        // (no `__test_utils` required).
        let bytes = vec![0u8; (MAX_FRAGMENTS_PER_HEADER + 1000) * 2];
        let mut cur = Cursor::new(bytes.as_slice());
        let err = UnversionedHeader::read(&mut cur, "test.uasset").unwrap_err();
        match err {
            PaksmithError::AssetParse {
                fault:
                    AssetParseFault::BoundsExceeded {
                        field: AssetWireField::UnversionedFragment,
                        limit,
                        ..
                    },
                ..
            } => {
                assert_eq!(limit, MAX_FRAGMENTS_PER_HEADER as u64);
            }
            other => panic!("expected BoundsExceeded UnversionedFragment, got {other:?}"),
        }
    }
}
