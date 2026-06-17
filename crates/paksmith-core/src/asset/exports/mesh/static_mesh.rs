//! `UStaticMesh` typed reader — Phase 3g.
//!
//! Parses the tagged-property segment, the `UObject::Serialize` object-GUID tail
//! ([`read_object_guid_tail`]), then the `UStaticMesh.Deserialize` binary
//! fields. The order and widths are verified against CUE4Parse
//! `UStaticMesh.Deserialize` (`ca637ae`):
//!
//! 1. `FStripDataFlags` pair (2 × `u8`) — shared [`read_strip_data_flags`].
//! 2. `bCooked` (`u32` bool) — gates whether the render data follows.
//! 3. `BodySetup` (`FPackageIndex`) — the collision `UBodySetup` reference.
//! 4. `NavCollision` (`FPackageIndex`) — gated on
//!    `Ar.Versions["StaticMesh.HasNavCollision"]` =
//!    `Ver >= STATIC_MESH_STORE_NAV_COLLISION`. That object version sits *below*
//!    paksmith's 504 floor, so `NavCollision` is **always present** here (no
//!    `!bCooked` gate — the memory-flagged discrepancy resolves to "always").
//! 5. editor-data block — gated `!IsEditorDataStripped()`; its inner reads are
//!    further gated on pre-4.x object/custom versions that 4.23+ assets are well
//!    past, so for the supported range it consumes **nothing** (and cooked
//!    assets strip editor data regardless).
//! 6. `LightingGuid` (`FGuid`, 16 bytes).
//! 7. `Sockets` (`i32` count + `FPackageIndex[]`).
//! 8. if `bCooked`: [`super::render_data`] (`FStaticMeshRenderData`).
//!
//! Parsing stops after the render data. The `UStaticMesh.Deserialize` tail that
//! follows (occluder data, the SpeedTree-wind flag, the `StaticMaterials`
//! array) is intentionally left unconsumed — the export framework dispatches the
//! next export by table offset, not cursor position, and decoding
//! `FStaticMaterial` is a later milestone. See [`StaticMeshData`] for the
//! render-data scope boundary: pre-4.23 legacy (UNVERIFIED, see
//! [`super::lod::read_lod_legacy`]) + UE 4.23–4.27 (full) + UE 5.0–5.3
//! (geometry-only, the classic LOD geometry without the un-decoded Nanite tail).
//! UE5.4+ degrades to a generic property bag. A non-inlined LOD's streamed
//! geometry is resolved from its companion `.ubulk` (degrading to a property bag
//! only when the record is unresolvable); a distance-field-present UE4 mesh is
//! parsed (the `FDistanceFieldVolumeData` is validated-skipped) and still exports
//! its geometry.

use std::io::Cursor;

use crate::asset::bulk_data::FByteBulkData;
use crate::asset::property::bag::PropertyBag;
use crate::asset::property::{read_object_guid_tail, read_properties};
use crate::asset::wire::{read_bool32, read_strip_data_flags};
use crate::asset::{Asset, AssetContext, FGuid, StaticMeshData, read_package_index};
use crate::error::AssetWireField;

use super::{read, render_data};

/// Max `UStaticMeshSocket` references per mesh — a generous ceiling enforced
/// before the socket-array read. Stock meshes have a handful.
pub(crate) const MAX_SOCKETS_PER_MESH: u32 = 4096;

/// Parse a `UStaticMesh` export `payload` into [`StaticMeshData`].
///
/// The second tuple element is the export's `FByteBulkData` records, returned to
/// the package-level resolver. It is always empty for static meshes: inlined LOD
/// geometry carries its buffers in-stream, and a non-inlined LOD's streamed
/// geometry is resolved in place during the read (via `ctx.bulk_resolver`),
/// not deferred — so no record is surfaced for later resolution.
///
/// # Errors
/// [`crate::PaksmithError`] from the tagged-property parse, a corrupt /
/// truncated `Deserialize` field, or an unsupported render-data variant
/// ([`crate::error::PaksmithError::UnsupportedFeature`]) — all of which the
/// package walker degrades to a generic property bag (see
/// `Package::read_payloads`).
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

    // Segment 2 (`UStaticMesh.Deserialize`).
    let _strip = read_strip_data_flags(&mut cur, asset_path, AssetWireField::StaticMeshStripFlags)?;
    let cooked = read_bool32(&mut cur, asset_path, AssetWireField::StaticMeshBCooked)?;
    let body_setup = read_package_index(&mut cur, asset_path, AssetWireField::StaticMeshBodySetup)?;
    let nav_collision =
        read_package_index(&mut cur, asset_path, AssetWireField::StaticMeshNavCollision)?;
    // editor-data block: no-op for the supported range (see module docs).
    let lighting_guid = FGuid::read_from(&mut cur)
        .map_err(|_| read::eof(asset_path, AssetWireField::StaticMeshLightingGuid))?;
    let socket_count = read::read_capped_count(
        &mut cur,
        asset_path,
        AssetWireField::StaticMeshSocketCount,
        MAX_SOCKETS_PER_MESH,
    )?;
    let mut sockets = Vec::with_capacity(socket_count as usize);
    for _ in 0..socket_count {
        sockets.push(read_package_index(
            &mut cur,
            asset_path,
            AssetWireField::StaticMeshSocketEntry,
        )?);
    }

    let render_data = if cooked {
        Some(render_data::read_render_data(&mut cur, ctx, asset_path)?)
    } else {
        None
    };

    Ok((
        StaticMeshData {
            properties: PropertyBag::tree(properties),
            cooked,
            body_setup,
            nav_collision,
            lighting_guid,
            sockets,
            render_data,
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
    use super::super::lod::test_support::{inlined_lod_ue5_0, ue5_release_ctx};
    use super::*;
    use crate::asset::custom_version::REMOVING_TESSELLATION;
    use crate::asset::package_index::PackageIndex;
    use crate::asset::property::primitives::PropertyValue;
    use crate::asset::property::test_utils::{
        make_ctx, make_ctx_with_version, write_int_property, write_none_tag,
    };
    use crate::asset::wire::write_bool32;
    use crate::error::{AssetParseFault, PaksmithError};

    /// The object-GUID tail (bSerializeGuid = 0, no FGuid) + the
    /// `UStaticMesh.Deserialize` fields through `Sockets`: strip flags, `bCooked`,
    /// `BodySetup`, `NavCollision`, `LightingGuid`, and an empty `Sockets` array.
    /// Stops before the `bCooked`-gated render data.
    fn deserialize_tail(buf: &mut Vec<u8>, cooked: bool, body_setup_raw: i32) {
        write_bool32(buf, false).unwrap(); // bSerializeGuid = 0 (no object FGuid)
        buf.push(0x00); // GlobalStripFlags
        buf.push(0x00); // ClassStripFlags
        write_bool32(buf, cooked).unwrap();
        buf.extend_from_slice(&body_setup_raw.to_le_bytes()); // BodySetup FPackageIndex
        buf.extend_from_slice(&0i32.to_le_bytes()); // NavCollision = Null
        buf.extend_from_slice(&[0u8; 16]); // LightingGuid
        buf.extend_from_slice(&0i32.to_le_bytes()); // Sockets count = 0
    }

    /// A minimal `FStaticMeshRenderData` with **zero LODs** (the per-LOD
    /// geometry is exercised in `render_data` / `lod` tests). Order: LOD count,
    /// numInlinedLODs, distance-field strip (no per-LOD bool — 0 LODs), Bounds
    /// (28-byte UE4 `FBoxSphereBounds`), bLODsShareStaticLighting, 8 ×
    /// `FPerPlatformFloat`.
    fn empty_render_data(buf: &mut Vec<u8>) {
        buf.extend_from_slice(&0i32.to_le_bytes()); // LOD count = 0
        buf.push(0x00); // numInlinedLODs = 0
        buf.push(0x00); // distance-field GlobalStripFlags
        buf.push(0x00); // distance-field ClassStripFlags
        buf.extend_from_slice(&[0u8; 28]); // Bounds (origin/extent f32x3 + radius f32)
        write_bool32(buf, true).unwrap(); // bLODsShareStaticLighting
        for _ in 0..8 {
            write_bool32(buf, true).unwrap(); // FPerPlatformFloat bCooked
            buf.extend_from_slice(&0.5f32.to_le_bytes()); // FPerPlatformFloat Value
        }
    }

    #[test]
    fn parses_empty_props_then_deserialize_fields() {
        let ctx = make_ctx(&["None"]);
        let mut payload = Vec::new();
        write_none_tag(&mut payload); // empty tagged-property segment
        deserialize_tail(&mut payload, false, 0); // not cooked, BodySetup = Null
        let (data, bulk) = read_from(&payload, &ctx, "Mesh.uasset").expect("parse");
        assert!(!data.cooked);
        assert_eq!(data.body_setup, PackageIndex::Null);
        assert_eq!(data.nav_collision, PackageIndex::Null);
        assert!(data.sockets.is_empty());
        assert!(data.render_data.is_none(), "no render data when not cooked");
        assert!(bulk.is_empty(), "inlined geometry carries no bulk records");
        assert_eq!(data.properties.len(), 0, "empty property tree");
    }

    #[test]
    fn carries_tagged_properties_before_the_binary_segment() {
        // names: 0="None", 1="LightMapResolution", 2="IntProperty".
        let ctx = make_ctx(&["None", "LightMapResolution", "IntProperty"]);
        let mut payload = Vec::new();
        write_int_property(&mut payload, 1, 2, 64); // LightMapResolution = 64
        write_none_tag(&mut payload);
        deserialize_tail(&mut payload, false, 0);
        let (data, _) = read_from(&payload, &ctx, "Mesh.uasset").expect("parse");
        // The property survived; the binary segment after it still parsed.
        let props = data.properties.as_tree().expect("tree");
        assert_eq!(props.len(), 1);
        assert_eq!(props[0].name(), "LightMapResolution");
        assert!(matches!(props[0].value, PropertyValue::Int(64)));
    }

    #[test]
    fn reads_nav_collision_and_sockets() {
        // BodySetup import + NavCollision import + 2 sockets.
        let ctx = make_ctx(&["None"]);
        let mut payload = Vec::new();
        write_none_tag(&mut payload);
        write_bool32(&mut payload, false).unwrap(); // bSerializeGuid = 0
        payload.push(0x00);
        payload.push(0x00); // strip flags
        write_bool32(&mut payload, false).unwrap(); // not cooked
        payload.extend_from_slice(&(-3i32).to_le_bytes()); // BodySetup import → Import(2)
        payload.extend_from_slice(&(-5i32).to_le_bytes()); // NavCollision import → Import(4)
        payload.extend_from_slice(&[0xAB; 16]); // LightingGuid
        payload.extend_from_slice(&2i32.to_le_bytes()); // Sockets count = 2
        payload.extend_from_slice(&7i32.to_le_bytes()); // socket export → Export(6)
        payload.extend_from_slice(&8i32.to_le_bytes()); // socket export → Export(7)
        let (data, _) = read_from(&payload, &ctx, "Mesh.uasset").expect("parse");
        assert_eq!(data.body_setup, PackageIndex::Import(2));
        assert_eq!(data.nav_collision, PackageIndex::Import(4));
        assert_eq!(data.sockets.len(), 2);
        assert_eq!(data.sockets[0], PackageIndex::Export(6));
        assert_eq!(data.sockets[1], PackageIndex::Export(7));
        assert!(data.render_data.is_none());
    }

    #[test]
    fn cooked_reads_render_data_and_ignores_trailing_tail() {
        // The full read_from path: props → Deserialize tail → render data.
        // Trailing `UStaticMesh.Deserialize` bytes (occluder / SpeedTree /
        // StaticMaterials) are deliberately NOT consumed — they must not error.
        let ctx = make_ctx_with_version(522, None); // UE4.27
        let mut payload = Vec::new();
        write_none_tag(&mut payload);
        deserialize_tail(&mut payload, true, 0); // cooked
        empty_render_data(&mut payload);
        payload.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // trailing tail garbage
        let (data, _) = read_from(&payload, &ctx, "Mesh.uasset").expect("parse");
        assert!(data.cooked);
        let rd = data.render_data.expect("cooked → render data");
        assert!(rd.lods.is_empty(), "0-LOD render data");
        assert!(rd.lods_share_static_lighting);
        assert_eq!(rd.screen_sizes.len(), 8);
        assert!((rd.screen_sizes[0] - 0.5).abs() < 1e-6);
    }

    #[test]
    fn ue5_cooked_static_mesh_decodes_geometry() {
        // Full read_from for a UE5.0 cooked UStaticMesh: tagged-property
        // terminator → Deserialize tail → the UE5 render data (classic LOD
        // geometry followed by the un-decoded FNaniteResources blob). Proves the
        // export pipeline yields typed geometry for UE5.0–5.3 rather than
        // degrading to a property bag, and that the trailing Nanite blob is left
        // untouched.
        let ctx = ue5_release_ctx(REMOVING_TESSELLATION);
        let mut payload = Vec::new();
        write_none_tag(&mut payload);
        deserialize_tail(&mut payload, true, 0); // cooked
        payload.extend_from_slice(&1i32.to_le_bytes()); // LOD count = 1
        payload.extend_from_slice(&inlined_lod_ue5_0());
        payload.push(0x00); // numInlinedLODs
        payload.extend_from_slice(&[0xAB; 32]); // FNaniteResources blob (ignored)
        let (data, bulk) = read_from(&payload, &ctx, "Mesh.uasset").expect("parse");
        assert!(data.cooked);
        let rd = data.render_data.expect("cooked → render data");
        assert_eq!(rd.lods.len(), 1);
        assert_eq!(rd.lods[0].positions.len(), 3);
        assert_eq!(rd.lods[0].indices, vec![0, 1, 2]);
        assert!(bulk.is_empty(), "inlined geometry carries no bulk records");
    }

    #[test]
    fn read_typed_wraps_in_static_mesh_variant() {
        let ctx = make_ctx(&["None"]);
        let mut payload = Vec::new();
        write_none_tag(&mut payload);
        deserialize_tail(&mut payload, false, 0);
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
        write_bool32(&mut payload, false).unwrap(); // bCooked = 0
        payload.extend_from_slice(&0i32.to_le_bytes()); // BodySetup = Null
        payload.extend_from_slice(&0i32.to_le_bytes()); // NavCollision = Null
        payload.extend_from_slice(&[0u8; 16]); // LightingGuid
        payload.extend_from_slice(&0i32.to_le_bytes()); // Sockets count = 0
        let (data, _) = read_from(&payload, &ctx, "Mesh.uasset").expect("parse");
        assert!(!data.cooked);
        assert_eq!(data.body_setup, PackageIndex::Null);
    }

    #[test]
    fn socket_count_over_cap_is_rejected() {
        let ctx = make_ctx(&["None"]);
        let mut payload = Vec::new();
        write_none_tag(&mut payload);
        write_bool32(&mut payload, false).unwrap(); // bSerializeGuid = 0
        payload.push(0x00);
        payload.push(0x00); // strip flags
        write_bool32(&mut payload, false).unwrap(); // not cooked
        payload.extend_from_slice(&0i32.to_le_bytes()); // BodySetup
        payload.extend_from_slice(&0i32.to_le_bytes()); // NavCollision
        payload.extend_from_slice(&[0u8; 16]); // LightingGuid
        payload
            .extend_from_slice(&(i32::try_from(MAX_SOCKETS_PER_MESH).unwrap() + 1).to_le_bytes()); // over cap
        let err = read_from(&payload, &ctx, "Mesh.uasset").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::BoundsExceeded {
                    field: AssetWireField::StaticMeshSocketCount,
                    limit,
                    ..
                },
                ..
            } if limit == u64::from(MAX_SOCKETS_PER_MESH)
        ));
    }

    #[test]
    fn truncated_lighting_guid_errors_at_lighting_guid_field() {
        // Props + object-guid tail + strip + bCooked + BodySetup + NavCollision,
        // then only 15 of the 16 LightingGuid bytes → EOF tagged at the GUID.
        let ctx = make_ctx(&["None"]);
        let mut payload = Vec::new();
        write_none_tag(&mut payload);
        write_bool32(&mut payload, false).unwrap(); // bSerializeGuid = 0
        payload.push(0x00);
        payload.push(0x00); // strip flags
        write_bool32(&mut payload, false).unwrap(); // bCooked = 0
        payload.extend_from_slice(&0i32.to_le_bytes()); // BodySetup
        payload.extend_from_slice(&0i32.to_le_bytes()); // NavCollision
        payload.extend_from_slice(&[0xAB; 15]); // only 15 of 16 GUID bytes
        let err = read_from(&payload, &ctx, "Mesh.uasset").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::UnexpectedEof {
                    field: AssetWireField::StaticMeshLightingGuid
                },
                ..
            }
        ));
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
