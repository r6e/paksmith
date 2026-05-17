//! Tagged property system for UAsset export bodies.
//!
//! Phase 2a shipped [`PropertyBag`]'s `Opaque` variant; Phase 2b adds
//! a `Tree` variant (lands in Task 7) populated by the tagged-property
//! iterator [`read_properties`].
//!
//! Sub-modules:
//! - [`bag`] — `PropertyBag` enum (migrated from `property_bag`)
//! - [`tag`] — `PropertyTag` wire reader
//! - [`primitives`] — `Property`, `PropertyValue`, primitive readers
//! - [`text`] — `FText` + `FTextHistory`

use std::io::{Read, Seek};

use crate::asset::AssetContext;
use crate::error::{AssetAllocationContext, AssetParseFault, AssetWireField, PaksmithError};

pub mod bag;
pub mod primitives;
pub mod tag;
pub mod text;

pub use bag::PropertyBag;
pub use primitives::{Property, PropertyValue};
pub use tag::{MAX_PROPERTY_TAG_SIZE, PropertyTag, read_tag, resolve_fname};
// `MAX_PROPERTY_DEPTH` stays `pub(crate)` in `bag` (matching every other
// in-crate parser cap — see bag.rs). The iterator below references
// `bag::MAX_PROPERTY_DEPTH` directly; Phase 2c's recursive container
// readers in sibling sub-modules reach it via
// `super::bag::MAX_PROPERTY_DEPTH`. Re-exporting a `pub(crate)` item as
// `pub` from here would be a privacy error (E0364).

/// Maximum number of `FPropertyTag` entries per export stream.
/// Guards against a missing "None" terminator causing the iterator to
/// loop forever on attacker-controlled or version-skewed bytes.
pub const MAX_TAGS_PER_EXPORT: usize = 65_536;

/// Read all `FPropertyTag` entries from `reader` until the "None"
/// terminator, `export_end`, or [`MAX_TAGS_PER_EXPORT`], whichever
/// comes first.
///
/// `depth` is the current recursion depth (0 for top-level export
/// bodies; Phase 2c's struct reader will increment it for nested
/// payloads). Errors immediately if `depth > MAX_PROPERTY_DEPTH`.
///
/// Unknown/container property types skip exactly `tag.size` bytes and
/// are stored as [`PropertyValue::Unknown`]. After every value read
/// (including the skip path), the cursor MUST be at
/// `value_start + tag.size`; a mismatch returns
/// [`AssetParseFault::PropertyTagSizeMismatch`] — see Decision #5 in
/// `docs/plans/phase-2b-tagged-properties.md`.
///
/// # Errors
///
/// - [`AssetParseFault::PropertyDepthExceeded`] if `depth > MAX_PROPERTY_DEPTH`.
/// - [`AssetParseFault::PropertyTagCountExceeded`] if the tag count
///   hits [`MAX_TAGS_PER_EXPORT`] without a terminator.
/// - [`AssetParseFault::PropertyTagSizeMismatch`] on cursor mismatch.
/// - Any error from [`read_tag`] or the primitive/text readers.
pub fn read_properties<R: Read + Seek>(
    reader: &mut R,
    ctx: &AssetContext,
    depth: usize,
    export_end: u64,
    asset_path: &str,
) -> crate::Result<Vec<Property>> {
    if depth > bag::MAX_PROPERTY_DEPTH {
        return Err(PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::PropertyDepthExceeded {
                depth,
                limit: bag::MAX_PROPERTY_DEPTH,
            },
        });
    }

    let mut props: Vec<Property> = Vec::new();

    for _ in 0..MAX_TAGS_PER_EXPORT {
        let pos = reader.stream_position().map_err(PaksmithError::Io)?;
        if pos >= export_end {
            break;
        }

        let Some(tag) = read_tag(reader, ctx, asset_path)? else {
            break;
        };

        let value_start = reader.stream_position().map_err(PaksmithError::Io)?;
        #[allow(
            clippy::cast_sign_loss,
            reason = "tag.size has been rejected if < 0 by read_tag"
        )]
        let expected_end = value_start + tag.size as u64;

        let value =
            if let Some(v) = primitives::read_primitive_value(&tag, reader, ctx, asset_path)? {
                v
            } else {
                #[allow(
                    clippy::cast_sign_loss,
                    reason = "tag.size has been rejected if < 0 by read_tag"
                )]
                let n = tag.size as usize;
                let mut skip = Vec::new();
                skip.try_reserve_exact(n)
                    .map_err(|source| PaksmithError::AssetParse {
                        asset_path: asset_path.to_string(),
                        fault: AssetParseFault::AllocationFailed {
                            context: AssetAllocationContext::UnknownPropertyBytes,
                            requested: n,
                            source,
                        },
                    })?;
                skip.resize(n, 0);
                reader
                    .read_exact(&mut skip)
                    .map_err(|_| PaksmithError::AssetParse {
                        asset_path: asset_path.to_string(),
                        fault: AssetParseFault::UnexpectedEof {
                            field: AssetWireField::PropertyTagSize,
                        },
                    })?;
                PropertyValue::Unknown {
                    type_name: tag.type_name.clone(),
                    skipped_bytes: n,
                }
            };

        let actual_pos = reader.stream_position().map_err(PaksmithError::Io)?;
        if actual_pos != expected_end {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::PropertyTagSizeMismatch {
                    expected_end,
                    actual_pos,
                },
            });
        }

        props.push(Property {
            name: tag.name,
            array_index: tag.array_index,
            guid: tag.guid,
            value,
        });
    }

    // Loop exhausted without hitting None / export_end → cap trip.
    if props.len() == MAX_TAGS_PER_EXPORT {
        let pos = reader.stream_position().map_err(PaksmithError::Io)?;
        if pos < export_end {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::PropertyTagCountExceeded {
                    limit: MAX_TAGS_PER_EXPORT,
                },
            });
        }
    }

    Ok(props)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::{
        AssetContext,
        export_table::ExportTable,
        import_table::ImportTable,
        name_table::{FName, NameTable},
        version::AssetVersion,
    };
    use std::io::Cursor;
    use std::sync::Arc;

    fn make_ctx(names: &[&str]) -> AssetContext {
        let table = NameTable {
            names: names.iter().map(|n| FName::new(n)).collect(),
        };
        AssetContext {
            names: Arc::new(table),
            imports: Arc::new(ImportTable::default()),
            exports: Arc::new(ExportTable::default()),
            version: AssetVersion::default(),
        }
    }

    fn bool_property_then_none() -> (Vec<u8>, AssetContext) {
        let ctx = make_ctx(&["None", "bEnabled", "BoolProperty"]);
        let mut buf = Vec::new();
        // Name: bEnabled (index=1)
        buf.extend_from_slice(&1i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        // Type: BoolProperty (index=2)
        buf.extend_from_slice(&2i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        // Size: 0, ArrayIndex: 0
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        // boolVal: 1, HasPropertyGuid: 0
        buf.push(1u8);
        buf.push(0u8);
        // None terminator
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        (buf, ctx)
    }

    #[test]
    fn reads_bool_property() {
        let (buf, ctx) = bool_property_then_none();
        let export_end = buf.len() as u64;
        let props =
            read_properties(&mut Cursor::new(&buf[..]), &ctx, 0, export_end, "x.uasset").unwrap();
        assert_eq!(props.len(), 1);
        assert_eq!(props[0].name, "bEnabled");
        assert_eq!(props[0].value, PropertyValue::Bool(true));
    }

    #[test]
    fn stops_at_export_end() {
        let ctx = make_ctx(&["None"]);
        let buf: Vec<u8> = Vec::new();
        let props = read_properties(&mut Cursor::new(&buf[..]), &ctx, 0, 0, "x.uasset").unwrap();
        assert!(props.is_empty());
    }

    #[test]
    fn unknown_type_stored_as_unknown_variant() {
        let ctx = make_ctx(&["None", "Tags", "ArrayProperty", "IntProperty"]);
        let mut buf = Vec::new();
        buf.extend_from_slice(&1i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.extend_from_slice(&2i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.extend_from_slice(&8i32.to_le_bytes()); // Size: 8
        buf.extend_from_slice(&0i32.to_le_bytes()); // ArrayIndex
        // InnerType: IntProperty
        buf.extend_from_slice(&3i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.push(0u8); // HasPropertyGuid
        buf.extend_from_slice(&[0u8; 8]); // value payload
        // None terminator
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        let export_end = buf.len() as u64;
        let props =
            read_properties(&mut Cursor::new(&buf[..]), &ctx, 0, export_end, "x.uasset").unwrap();
        assert_eq!(props.len(), 1);
        assert_eq!(props[0].name, "Tags");
        assert!(matches!(
            props[0].value,
            PropertyValue::Unknown {
                ref type_name,
                skipped_bytes: 8
            } if type_name == "ArrayProperty"
        ));
    }

    #[test]
    fn depth_guard_rejects_depth_over_limit() {
        let (buf, ctx) = bool_property_then_none();
        let export_end = buf.len() as u64;
        let err = read_properties(
            &mut Cursor::new(&buf[..]),
            &ctx,
            bag::MAX_PROPERTY_DEPTH + 1,
            export_end,
            "x.uasset",
        )
        .unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::PropertyDepthExceeded { .. },
                ..
            }
        ));
    }

    /// Cursor-mismatch invariant (Decision #5). IntProperty claims
    /// Size=8 but only 4 bytes of payload follow before the next tag.
    /// read_primitive_value consumes 4 bytes (correct for Int); the
    /// cursor check fires because actual_pos (=value_start+4) !=
    /// expected_end (=value_start+8).
    #[test]
    fn size_mismatch_after_value_read_is_rejected() {
        let ctx = make_ctx(&["None", "Foo", "IntProperty"]);
        let mut buf = Vec::new();
        buf.extend_from_slice(&1i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.extend_from_slice(&2i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.extend_from_slice(&8i32.to_le_bytes()); // Size: 8 (lying)
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.push(0u8);
        buf.extend_from_slice(&42i32.to_le_bytes()); // 4-byte int payload
        buf.extend_from_slice(&[0u8; 4]); // filler the reader won't consume
        buf.extend_from_slice(&0i32.to_le_bytes()); // None terminator (unreachable)
        buf.extend_from_slice(&0i32.to_le_bytes());

        let export_end = buf.len() as u64;
        let err = read_properties(&mut Cursor::new(&buf[..]), &ctx, 0, export_end, "x.uasset")
            .unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::PropertyTagSizeMismatch { .. },
                    ..
                }
            ),
            "expected PropertyTagSizeMismatch; got: {err:?}"
        );
    }

    /// MAX_TAGS_PER_EXPORT cap. Write MAX+1 valid-shaped 0-byte
    /// BoolProperty tags (header is 18 bytes each; no payload, no
    /// terminator). The iterator hits the count cap before encountering
    /// a None terminator → PropertyTagCountExceeded.
    ///
    /// ~1.18 MiB buffer — small enough for a unit test.
    #[test]
    fn tag_count_cap_is_rejected() {
        let ctx = make_ctx(&["None", "p", "BoolProperty"]);
        let mut buf = Vec::with_capacity(20 * (MAX_TAGS_PER_EXPORT + 1));
        for _ in 0..=MAX_TAGS_PER_EXPORT {
            buf.extend_from_slice(&1i32.to_le_bytes());
            buf.extend_from_slice(&0i32.to_le_bytes());
            buf.extend_from_slice(&2i32.to_le_bytes());
            buf.extend_from_slice(&0i32.to_le_bytes());
            buf.extend_from_slice(&0i32.to_le_bytes());
            buf.extend_from_slice(&0i32.to_le_bytes());
            buf.push(0u8);
            buf.push(0u8);
        }
        let export_end = buf.len() as u64;
        let err = read_properties(&mut Cursor::new(&buf[..]), &ctx, 0, export_end, "x.uasset")
            .unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::PropertyTagCountExceeded { .. },
                    ..
                }
            ),
            "expected PropertyTagCountExceeded; got: {err:?}"
        );
    }
}
