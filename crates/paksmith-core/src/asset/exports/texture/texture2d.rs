//! `UTexture2D` export reader (Phase 3e).
//!
//! Wire-format reference: `docs/formats/texture/texture2d.md` (oracle
//! `FabianFG/CUE4Parse` `UTexture2D.cs` / `FTexturePlatformData.cs` @
//! `cf74fc32`). The export payload has two back-to-back segments:
//!
//! 1. **Tagged-property stream** — the standard None-terminated
//!    `FPropertyTag` stream (`SRGB`, `CompressionSettings`, `Filter`,
//!    `LODBias`, …), decoded by the existing
//!    [`read_properties`](crate::asset::property::read_properties).
//! 2. **`FTexturePlatformData` blob** — `SizeX`/`SizeY`, the
//!    `PackedData` bit field, the `PixelFormat` name, optional
//!    `OptData`/`CPUCopy` sub-records, and the `FTexture2DMipMap[]`
//!    mip chain.
//!
//! **3e-1 scope: segment 1 only.** [`read_from`] decodes the
//! tagged-property stream and stops at its `"None"` terminator; the
//! trailing `FTexturePlatformData` blob is intentionally left unread.
//! The dispatch caller (`Package::read_payloads`) carves each export
//! by `serial_offset`/`serial_size` and never inspects how many bytes
//! a typed reader consumed, so leaving segment 2 unread is structurally
//! harmless — the next export is still located correctly. Parsing the
//! platform-data header (and collecting the per-mip `FByteBulkData`
//! records into the `read_typed` tuple's second element) lands in 3e-2+.

use std::io::Cursor;

use crate::asset::bulk_data::FByteBulkData;
use crate::asset::property::bag::PropertyBag;
use crate::asset::property::read_properties;
use crate::asset::{Asset, AssetContext, Texture2DData};

/// Parse a `UTexture2D` export payload into [`Texture2DData`].
///
/// `payload` is the export's `serial_size`-bounded byte slice. As of
/// 3e-1 only **segment 1** (the tagged-property stream) is decoded;
/// see the module docs for why the trailing `FTexturePlatformData`
/// blob is deferred to 3e-2.
///
/// # Errors
/// Any tagged-property fault from the nested [`read_properties`] read
/// (`PropertyTagSizeMismatch`, `UnexpectedEof`, `PackageIndexOob`, …).
pub(crate) fn read_from(
    payload: &[u8],
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<Texture2DData> {
    let mut cur = Cursor::new(payload);
    let total_len = payload.len() as u64;

    // Segment 1: tagged properties (None-terminated). Stops at the
    // "None" tag; segment 2 (FTexturePlatformData) is read in 3e-2.
    let properties = read_properties(&mut cur, ctx, 0, total_len, asset_path)?;

    Ok(Texture2DData {
        properties: PropertyBag::Tree { properties },
    })
}

/// Registry-compatible shim ([`crate::asset::exports::dispatch::TypedReaderFn`]).
/// Wraps [`read_from`]'s [`Texture2DData`] in the typed
/// [`Asset::Texture2D`] variant. 3e-1 collects no bulk-data records
/// (the per-mip `FByteBulkData` records are parsed from segment 2 in
/// 3e-3), so the companion-records vec is empty for now.
pub(crate) fn read_typed(
    payload: &[u8],
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<(Asset, Vec<FByteBulkData>)> {
    let data = read_from(payload, ctx, asset_path)?;
    Ok((Asset::Texture2D(data), Vec::new()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::property::primitives::PropertyValue;
    use crate::asset::property::test_utils::make_ctx;

    // --- wire-byte builders (kept explicit so the fixture bytes are
    // independently auditable against the format doc, not circular
    // with the parser; mirrors data_table.rs's test helpers) ---

    /// Append an FName pair `(index, number=0)`.
    fn fname(buf: &mut Vec<u8>, index: i32) {
        buf.extend_from_slice(&index.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
    }

    /// Append the `(0, 0)` "None" terminator.
    fn none(buf: &mut Vec<u8>) {
        fname(buf, 0);
    }

    /// Append a UE4.27 `IntProperty` FPropertyTag + its i32 value.
    fn int_property(buf: &mut Vec<u8>, name_idx: i32, type_idx: i32, value: i32) {
        fname(buf, name_idx); // Name
        fname(buf, type_idx); // Type ("IntProperty")
        buf.extend_from_slice(&4i32.to_le_bytes()); // Size
        buf.extend_from_slice(&0i32.to_le_bytes()); // ArrayIndex
        buf.push(0u8); // HasPropertyGuid
        buf.extend_from_slice(&value.to_le_bytes()); // value
    }

    fn props_of(data: &Texture2DData) -> &[crate::asset::property::primitives::Property] {
        match &data.properties {
            PropertyBag::Tree { properties } => properties,
            other => panic!("expected Tree, got {other:?}"),
        }
    }

    #[test]
    fn read_from_decodes_segment_1_properties() {
        // Name table: 0=None, 1=LODBias, 2=IntProperty.
        let ctx = make_ctx(&["None", "LODBias", "IntProperty"]);
        let mut bytes = Vec::new();
        int_property(&mut bytes, 1, 2, 3); // LODBias = 3
        none(&mut bytes);

        let data = read_from(&bytes, &ctx, "tex.uasset").expect("parse");
        let props = props_of(&data);
        assert_eq!(props.len(), 1);
        assert_eq!(props[0].name(), "LODBias");
        assert_eq!(props[0].value, PropertyValue::Int(3));
    }

    #[test]
    fn read_from_stops_at_none_ignoring_platform_data() {
        // Pins the 3e-1/3e-2 boundary: segment 1 ends at "None"; any
        // trailing FTexturePlatformData bytes are NOT read (and MUST
        // NOT cause a parse error). Here a bogus 32-byte tail stands in
        // for the platform-data blob.
        let ctx = make_ctx(&["None", "LODBias", "IntProperty"]);
        let mut bytes = Vec::new();
        int_property(&mut bytes, 1, 2, 7);
        none(&mut bytes);
        bytes.extend_from_slice(&[0xABu8; 32]); // garbage "platform data"

        let data = read_from(&bytes, &ctx, "tex.uasset").expect("parse");
        let props = props_of(&data);
        assert_eq!(props.len(), 1, "only segment-1 props; tail ignored");
        assert_eq!(props[0].value, PropertyValue::Int(7));
    }

    #[test]
    fn empty_property_stream_parses_to_empty_tree() {
        // A bare "None" (no properties before it) yields an empty Tree.
        let ctx = make_ctx(&["None"]);
        let mut bytes = Vec::new();
        none(&mut bytes);
        let data = read_from(&bytes, &ctx, "tex.uasset").expect("parse");
        assert!(props_of(&data).is_empty());
    }

    #[test]
    fn read_typed_wraps_in_texture2d_variant_with_no_bulk_records() {
        let ctx = make_ctx(&["None", "LODBias", "IntProperty"]);
        let mut bytes = Vec::new();
        int_property(&mut bytes, 1, 2, 1);
        none(&mut bytes);

        let (asset, records) = read_typed(&bytes, &ctx, "tex.uasset").expect("parse");
        assert!(records.is_empty(), "3e-1 collects no per-mip records yet");
        match asset {
            Asset::Texture2D(data) => assert_eq!(props_of(&data).len(), 1),
            other => panic!("expected Asset::Texture2D, got {other:?}"),
        }
    }
}
