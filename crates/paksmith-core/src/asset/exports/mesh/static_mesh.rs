//! `UStaticMesh` typed reader — Phase 3g1.
//!
//! Parses the tagged-property segment, the `UObject::Serialize` object-GUID tail
//! ([`read_object_guid_tail`]), then the leading `UStaticMesh.Deserialize` fields.
//! The order and widths are verified against CUE4Parse `UStaticMesh.Deserialize`:
//!
//! 1. `FStripDataFlags` pair (2 × `u8`) — shared [`read_strip_data_flags`].
//! 2. `bCooked` (`u32`-encoded bool) — gates whether the render data follows.
//! 3. `BodySetup` (`FPackageIndex`) — the collision `UBodySetup` reference.
//!
//! Parsing stops after `BodySetup`. `FStaticMeshRenderData` does **not** follow
//! directly: several more `UStaticMesh.Deserialize` fields precede it —
//! `NavCollision`, the editor-thumbnail block, `LightingGuid`, the `Sockets`
//! array, `SpeedTreeWind`, etc. (their exact order / version gating is 3g1-3's
//! to verify against the oracle) — and only then the `bCooked`-gated
//! `FStaticMeshRenderData` (per-LOD vertex / index geometry) + `Bounds`
//! (`FBoxSphereBounds`). All of that is a later 3g milestone, so the trailing
//! payload is intentionally left unconsumed.

use std::io::Cursor;

use crate::asset::bulk_data::FByteBulkData;
use crate::asset::property::bag::PropertyBag;
use crate::asset::property::{read_object_guid_tail, read_properties};
use crate::asset::wire::{read_bool32, read_strip_data_flags};
use crate::asset::{Asset, AssetContext, StaticMeshData, read_package_index};
use crate::error::AssetWireField;

/// Parse a `UStaticMesh` export `payload` into [`StaticMeshData`] (3g1: the
/// tagged-property segment + the `Deserialize` fields through `BodySetup`).
///
/// The second tuple element is the export's `FByteBulkData` records; 3g1 reads
/// none (the vertex / index buffers live in the not-yet-parsed render data), so
/// it is always empty here.
///
/// # Errors
/// [`crate::PaksmithError`] from the tagged-property parse or a corrupt /
/// truncated `Deserialize` field (strip flags, `bCooked`, `BodySetup`).
pub(crate) fn read_from(
    payload: &[u8],
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<(StaticMeshData, Vec<FByteBulkData>)> {
    let mut cur = Cursor::new(payload);
    let total_len = payload.len() as u64;

    // Segment 1: the tagged-property stream (None-terminated), then the
    // `UObject::Serialize` object-GUID tail (bSerializeGuid + optional FGuid)
    // that precedes any class-specific fields.
    let properties = read_properties(&mut cur, ctx, 0, total_len, asset_path)?;
    let _object_guid = read_object_guid_tail(&mut cur, total_len, asset_path)?;

    // Segment 2 (`UStaticMesh.Deserialize`), through `BodySetup`.
    let _strip = read_strip_data_flags(&mut cur, asset_path, AssetWireField::StaticMeshStripFlags)?;
    let cooked = read_bool32(&mut cur, asset_path, AssetWireField::StaticMeshBCooked)?;
    let body_setup = read_package_index(&mut cur, asset_path, AssetWireField::StaticMeshBodySetup)?;

    Ok((
        StaticMeshData {
            properties: PropertyBag::tree(properties),
            cooked,
            body_setup,
        },
        Vec::new(),
    ))
}

/// Dispatch wrapper: [`read_from`] → [`Asset::StaticMesh`].
///
/// # Errors
/// Propagates [`read_from`].
pub(crate) fn read_typed(
    payload: &[u8],
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<(Asset, Vec<FByteBulkData>)> {
    let (data, bulk) = read_from(payload, ctx, asset_path)?;
    Ok((Asset::StaticMesh(data), bulk))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::package_index::PackageIndex;
    use crate::asset::property::primitives::PropertyValue;
    use crate::asset::property::test_utils::{make_ctx, write_int_property, write_none_tag};
    use crate::asset::wire::write_bool32;
    use crate::error::{AssetParseFault, PaksmithError};

    /// The object-GUID tail (bSerializeGuid = 0, no FGuid) + `FStripDataFlags`
    /// (2 bytes) + `bCooked` + `BodySetup` — everything after the property None.
    fn deserialize_tail(buf: &mut Vec<u8>, cooked: bool, body_setup_raw: i32) {
        write_bool32(buf, false).unwrap(); // bSerializeGuid = 0 (no object FGuid)
        buf.push(0x00); // GlobalStripFlags
        buf.push(0x00); // ClassStripFlags
        write_bool32(buf, cooked).unwrap();
        buf.extend_from_slice(&body_setup_raw.to_le_bytes()); // BodySetup FPackageIndex
    }

    #[test]
    fn parses_empty_props_then_deserialize_fields() {
        let ctx = make_ctx(&["None"]);
        let mut payload = Vec::new();
        write_none_tag(&mut payload); // empty tagged-property segment
        deserialize_tail(&mut payload, true, 0); // cooked, BodySetup = Null
        let (data, bulk) = read_from(&payload, &ctx, "Mesh.uasset").expect("parse");
        assert!(data.cooked);
        assert_eq!(data.body_setup, PackageIndex::Null);
        assert!(bulk.is_empty(), "3g1 reads no bulk records");
        assert_eq!(data.properties.len(), 0, "empty property tree");
    }

    #[test]
    fn carries_tagged_properties_before_the_binary_segment() {
        // names: 0="None", 1="LightMapResolution", 2="IntProperty".
        let ctx = make_ctx(&["None", "LightMapResolution", "IntProperty"]);
        let mut payload = Vec::new();
        write_int_property(&mut payload, 1, 2, 64); // LightMapResolution = 64
        write_none_tag(&mut payload);
        deserialize_tail(&mut payload, true, 0);
        let (data, _) = read_from(&payload, &ctx, "Mesh.uasset").expect("parse");
        // The property survived; the binary segment after it still parsed.
        let props = data.properties.as_tree().expect("tree");
        assert_eq!(props.len(), 1);
        assert_eq!(props[0].name(), "LightMapResolution");
        assert!(matches!(props[0].value, PropertyValue::Int(64)));
        assert!(data.cooked);
    }

    #[test]
    fn non_cooked_flag_parses_and_still_reads_body_setup() {
        // bCooked = 0 still has a BodySetup after it (it precedes the
        // bCooked-gated render data, which 3g1 doesn't read).
        let ctx = make_ctx(&["None"]);
        let mut payload = Vec::new();
        write_none_tag(&mut payload);
        deserialize_tail(&mut payload, false, -3); // not cooked, BodySetup import
        let (data, _) = read_from(&payload, &ctx, "Mesh.uasset").expect("parse");
        assert!(!data.cooked);
        assert_eq!(data.body_setup, PackageIndex::Import(2)); // raw -3 → Import(2)
    }

    #[test]
    fn read_typed_wraps_in_static_mesh_variant() {
        let ctx = make_ctx(&["None"]);
        let mut payload = Vec::new();
        write_none_tag(&mut payload);
        deserialize_tail(&mut payload, true, 0);
        let (asset, _) = read_typed(&payload, &ctx, "Mesh.uasset").expect("parse");
        assert!(matches!(asset, Asset::StaticMesh(_)));
    }

    #[test]
    fn consumes_object_guid_when_serialized() {
        // bSerializeGuid = 1 + a 16-byte FGuid sit between the props and the
        // strip flags; the reader must skip all 20 bytes and still parse the
        // Deserialize fields correctly.
        let ctx = make_ctx(&["None"]);
        let mut payload = Vec::new();
        write_none_tag(&mut payload);
        write_bool32(&mut payload, true).unwrap(); // bSerializeGuid = 1
        payload.extend_from_slice(&[0xAB; 16]); // object FGuid
        payload.push(0x00); // GlobalStripFlags
        payload.push(0x00); // ClassStripFlags
        write_bool32(&mut payload, true).unwrap(); // bCooked
        payload.extend_from_slice(&0i32.to_le_bytes()); // BodySetup = Null
        let (data, _) = read_from(&payload, &ctx, "Mesh.uasset").expect("parse");
        assert!(data.cooked);
        assert_eq!(data.body_setup, PackageIndex::Null);
    }

    #[test]
    fn truncated_strip_flags_errors_at_strip_field() {
        // Props + object-guid tail + a single strip byte → EOF on the 2nd byte.
        let ctx = make_ctx(&["None"]);
        let mut payload = Vec::new();
        write_none_tag(&mut payload);
        write_bool32(&mut payload, false).unwrap(); // bSerializeGuid = 0
        payload.push(0x00); // only ONE of the two FStripDataFlags bytes
        let err = read_from(&payload, &ctx, "Mesh.uasset").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::UnexpectedEof {
                    field: AssetWireField::StaticMeshStripFlags
                },
                ..
            }
        ));
    }

    #[test]
    fn non_bool_cooked_value_errors_at_bcooked_field() {
        // bCooked = 2 is neither 0 nor 1 → InvalidBool32 on StaticMeshBCooked.
        let ctx = make_ctx(&["None"]);
        let mut payload = Vec::new();
        write_none_tag(&mut payload);
        write_bool32(&mut payload, false).unwrap(); // bSerializeGuid = 0
        payload.push(0x00);
        payload.push(0x00); // strip flags
        payload.extend_from_slice(&2i32.to_le_bytes()); // bCooked = 2 (non-bool)
        payload.extend_from_slice(&0i32.to_le_bytes()); // BodySetup (unreached)
        let err = read_from(&payload, &ctx, "Mesh.uasset").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::InvalidBool32 {
                    field: AssetWireField::StaticMeshBCooked,
                    observed: 2,
                },
                ..
            }
        ));
    }
}
