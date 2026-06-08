//! `USkeletalMesh` export parsing (Phase 3h). Wire reference:
//! `docs/formats/mesh/skeletal-mesh.md`.
//!
//! PR2 ships the segment-2 prefix reader ([`read_typed`]) — tagged properties,
//! object-GUID tail, strip flags, `ImportedBounds`, `SkeletalMaterials`, and the
//! `FReferenceSkeleton` — wired into the class dispatch. The per-LOD skin
//! geometry beyond `bCooked` lands in later PRs of the 3h series.

use std::io::{Cursor, Read};

use crate::asset::bulk_data::FByteBulkData;
use crate::asset::custom_version::{
    CORE_OBJECT_VERSION_GUID, EDITOR_OBJECT_VERSION_GUID, FORTNITE_MAIN_BRANCH_OBJECT_VERSION_GUID,
    MESH_MATERIAL_SLOT_OVERLAY_MATERIAL_ADDED, REFACTOR_MESH_EDITOR_MATERIALS,
    RENDERING_OBJECT_VERSION_GUID, SKELETAL_MATERIAL_EDITOR_DATA_STRIPPING,
    TEXTURE_STREAMING_MESH_UV_CHANNEL_DATA,
};
use crate::asset::property::bag::PropertyBag;
use crate::asset::property::{read_fname_pair, read_object_guid_tail, read_properties};
use crate::asset::structs::bounds::FBoxSphereBounds;
use crate::asset::wire::{read_bool32, read_strip_data_flags};
use crate::asset::{Asset, AssetContext, SkeletalMeshData, read_package_index};
use crate::error::AssetWireField;

use super::read;
use super::skeleton::read_reference_skeleton;

/// Max `FSkeletalMaterial` slots per mesh — a generous ceiling enforced before
/// the `SkeletalMaterials` array read. Stock meshes have a handful.
///
/// NOTE: no `#[cfg(feature = "__test_utils")]` accessor — per the sibling
/// mesh-cap convention ([`super::static_mesh::MAX_SOCKETS_PER_MESH`] /
/// `MAX_BONES_PER_SKELETON`), the cap is pinned via an over-cap error-path
/// test (Phase 3h Task 7) rather than read live by an integration consumer.
pub(crate) const MAX_SKELETAL_MATERIALS: u32 = 256;

/// `FMeshUVChannelInfo::MAX_TEXCOORDS` — the fixed `LocalUVDensities` element
/// count (oracle `FMeshUVChannelInfo.cs` @ `cf74fc32`). Read as a fixed-size
/// `float[]` with NO count prefix.
const MAX_TEXCOORDS: usize = 4;

/// Consume an `FMeshUVChannelInfo` (24 bytes), staying cursor-aligned.
///
/// Wire layout (oracle `FMeshUVChannelInfo.cs` @ `cf74fc32`, cooked):
/// `bInitialized` (4-byte strict `0/1` int-bool via `Ar.ReadBoolean`) +
/// `bOverrideDensities` (4-byte strict int-bool) + `LocalUVDensities`
/// (`MAX_TEXCOORDS` × `f32`, no count prefix) = `4 + 4 + 4·4 = 24` bytes.
///
/// The struct carries no data paksmith needs downstream — it exists only to
/// keep the surrounding `FSkeletalMaterial`/`FStaticMaterial` cursor aligned —
/// so the floats are read (validating length / EOF) and discarded.
///
/// # Errors
/// - [`crate::error::AssetParseFault::InvalidBool32`] if either bool is not 0/1.
/// - [`crate::PaksmithError::Io`] if a bool32 read hits EOF (propagated from
///   [`read_bool32`], which surfaces EOF as `Io`).
/// - [`crate::error::AssetParseFault::UnexpectedEof`] if a `LocalUVDensities`
///   float runs short.
pub(super) fn read_mesh_uv_channel_info<R: Read + ?Sized>(
    r: &mut R,
    asset_path: &str,
) -> crate::Result<()> {
    let _initialized = read_bool32(r, asset_path, AssetWireField::MeshUvChannelInfo)?;
    let _override_densities = read_bool32(r, asset_path, AssetWireField::MeshUvChannelInfo)?;
    for _ in 0..MAX_TEXCOORDS {
        let _density = read::read_f32(r, asset_path, AssetWireField::MeshUvChannelInfo)?;
    }
    Ok(())
}

/// Consume one cooked `FSkeletalMaterial`, returning its `MaterialSlotName`.
///
/// Wire layout (oracle `FSkeletalMaterial.cs` @ `cf74fc32`, cooked), each
/// field gated on a per-plugin custom version:
///
/// 1. **`Material`** — `FPackageIndex` (always present). Consumed and
///    discarded; PR2 does not resolve the referenced material object.
/// 2. **`MaterialSlotName`** — `FName`, present iff
///    `FEditorObjectVersion >= RefactorMeshEditorMaterials (8)`. This is the
///    value returned.
/// 3. **`bSerializeImportedMaterialSlotName`** — `u32` bool, present iff
///    `FCoreObjectVersion >= SkeletalMaterialEditorDataStripping (3)`. The
///    following `ImportedMaterialSlotName` `FName` is editor-only — CUE4Parse
///    gates it on `!PKG_FilterEditorOnly`, and paksmith parses cooked
///    archives (which set `PKG_FilterEditorOnly`), so the `FName` is NOT on
///    the wire. We read the bool only. (`AssetContext` carries no
///    package-flags field, so the cooked-skip is unconditional here rather
///    than gated on a live flag — no new ctx plumbing for PR2.)
/// 4. **`UVChannelData`** — `FMeshUVChannelInfo` (24 bytes), present iff
///    `FRenderingObjectVersion >= TextureStreamingMeshUVChannelData (10)`.
/// 5. **`OverlayMaterial`** — `FPackageIndex`, present iff
///    `FFortniteMainBranchObjectVersion >=
///    MeshMaterialSlotOverlayMaterialAdded (196)` (UE5). Consumed and
///    discarded.
///
/// # Errors
/// - [`crate::error::AssetParseFault::PackageIndexUnderflow`] if a package
///   index is unrepresentable (propagated from [`read_package_index`]).
/// - [`crate::error::AssetParseFault::InvalidBool32`] if
///   `bSerializeImportedMaterialSlotName` is not 0/1.
/// - [`crate::error::AssetParseFault::PackageIndexOob`] /
///   [`crate::error::AssetParseFault::PackageIndexUnderflow`] for an
///   out-of-range slot-name `FName` (propagated from [`read_fname_pair`]).
/// - [`crate::PaksmithError::Io`] / [`crate::error::AssetParseFault::UnexpectedEof`]
///   on a short read of any field.
pub(super) fn read_skeletal_material<R: Read + ?Sized>(
    r: &mut R,
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<Option<String>> {
    let version_for = |guid| ctx.custom_versions.version_for(guid);

    // 1. Material: FPackageIndex (always present); consumed, not resolved.
    let _material = read_package_index(r, asset_path, AssetWireField::SkeletalMaterialInterface)?;

    // 2. MaterialSlotName: FName, gated on FEditorObjectVersion.
    let slot = if version_for(EDITOR_OBJECT_VERSION_GUID)
        .is_some_and(|v| v >= REFACTOR_MESH_EDITOR_MATERIALS)
    {
        let name = read_fname_pair(r, ctx, asset_path, AssetWireField::SkeletalMaterialSlotName)?;
        Some(name.to_string())
    } else {
        None
    };

    // 3. bSerializeImportedMaterialSlotName: u32 bool, gated on
    //    FCoreObjectVersion. The trailing editor-only ImportedMaterialSlotName
    //    FName is NOT present in cooked content (see fn docs) — read the bool
    //    only.
    if version_for(CORE_OBJECT_VERSION_GUID)
        .is_some_and(|v| v >= SKELETAL_MATERIAL_EDITOR_DATA_STRIPPING)
    {
        let _serialize_imported = read_bool32(
            r,
            asset_path,
            AssetWireField::SkeletalMaterialSerializeImportedSlotName,
        )?;
    }

    // 4. UVChannelData: FMeshUVChannelInfo, gated on FRenderingObjectVersion.
    if version_for(RENDERING_OBJECT_VERSION_GUID)
        .is_some_and(|v| v >= TEXTURE_STREAMING_MESH_UV_CHANNEL_DATA)
    {
        read_mesh_uv_channel_info(r, asset_path)?;
    }

    // 5. OverlayMaterial: FPackageIndex (UE5), gated on
    //    FFortniteMainBranchObjectVersion; consumed, not resolved.
    if version_for(FORTNITE_MAIN_BRANCH_OBJECT_VERSION_GUID)
        .is_some_and(|v| v >= MESH_MATERIAL_SLOT_OVERLAY_MATERIAL_ADDED)
    {
        let _overlay = read_package_index(
            r,
            asset_path,
            AssetWireField::SkeletalMaterialOverlayInterface,
        )?;
    }

    Ok(slot)
}

/// Parse a `USkeletalMesh` export `payload` into [`Asset::SkeletalMesh`].
///
/// Segment 1 is the tagged-property stream ([`read_properties`]) plus the
/// `UObject::Serialize` object-GUID tail ([`read_object_guid_tail`]). Segment 2
/// (`USkeletalMesh.Deserialize`) then yields, in wire order:
///
/// 1. `FStripDataFlags` (`2 × u8`) — read and discarded.
/// 2. `ImportedBounds` — native [`FBoxSphereBounds`] (UE4 28 bytes / UE5 LWC 56).
/// 3. `SkeletalMaterials` — `i32` count (capped at [`MAX_SKELETAL_MATERIALS`]) + N×`FSkeletalMaterial` ([`read_skeletal_material`]); each slot name is retained (an unnamed slot becomes the empty string).
/// 4. `FReferenceSkeleton` — bone hierarchy + bind pose ([`read_reference_skeleton`]).
/// 5. `bCooked` (`u32` bool).
///
/// The per-LOD skin geometry beyond `bCooked` is left unparsed in this PR
/// (`data.lods` stays empty). The second tuple element — the export's
/// [`FByteBulkData`] records — is always empty here (no out-of-line buffers are
/// resolved yet).
///
/// # Errors
/// [`crate::PaksmithError`] from the tagged-property parse, the object-GUID
/// tail, a short / corrupt segment-2 field, an over-cap `SkeletalMaterials`
/// count, or a nested `FSkeletalMaterial` / `FReferenceSkeleton` fault — all of
/// which the package walker degrades to a generic property bag (see
/// `Package::read_payloads`).
pub(crate) fn read_typed(
    payload: &[u8],
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<(Asset, Vec<FByteBulkData>)> {
    let total_len = payload.len() as u64;
    let mut cur = Cursor::new(payload);

    // Segment 1: tagged-property stream + UObject object-GUID tail.
    let properties = read_properties(&mut cur, ctx, 0, total_len, asset_path)?;
    let _object_guid = read_object_guid_tail(&mut cur, total_len, asset_path)?;

    // Segment 2 (`USkeletalMesh.Deserialize`).
    let _strip =
        read_strip_data_flags(&mut cur, asset_path, AssetWireField::SkeletalMeshStripFlags)?;
    let bounds_end = cur.position() + FBoxSphereBounds::wire_size(ctx);
    let bounds = FBoxSphereBounds::read_from(&mut cur, ctx, bounds_end, asset_path)?;

    let mat_count = read::read_capped_count(
        &mut cur,
        asset_path,
        AssetWireField::SkeletalMaterialCount,
        MAX_SKELETAL_MATERIALS,
    )?;
    let mut materials = Vec::with_capacity(mat_count as usize);
    for _ in 0..mat_count {
        materials.push(read_skeletal_material(&mut cur, ctx, asset_path)?.unwrap_or_default());
    }

    let skeleton = read_reference_skeleton(&mut cur, ctx, asset_path)?;
    let cooked = read_bool32(&mut cur, asset_path, AssetWireField::SkeletalMeshCooked)?;

    let mut data = SkeletalMeshData::empty();
    data.properties = PropertyBag::tree(properties);
    data.cooked = cooked;
    data.bounds = bounds;
    data.materials = materials;
    data.skeleton = skeleton;
    Ok((Asset::SkeletalMesh(data), Vec::new()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PaksmithError;
    use crate::asset::custom_version::{CustomVersion, CustomVersionContainer};
    use crate::asset::export_table::ExportTable;
    use crate::asset::import_table::ImportTable;
    use crate::asset::name_table::{FName, NameTable};
    use crate::asset::version::AssetVersion;
    use crate::error::AssetParseFault;
    use std::io::Cursor;
    use std::sync::Arc;

    /// Build an `AssetContext` whose `custom_versions` stamp the four
    /// `FSkeletalMaterial` gate plugins at the requested versions, with
    /// `names` populating the FName pool for the slot-name resolution.
    fn skel_mat_ctx(
        names: &[&str],
        editor: i32,
        core: i32,
        rendering: i32,
        fortnite: i32,
    ) -> AssetContext {
        let table = NameTable {
            names: names.iter().map(|n| FName::new(n)).collect(),
        };
        let custom_versions = CustomVersionContainer {
            versions: vec![
                CustomVersion {
                    guid: EDITOR_OBJECT_VERSION_GUID,
                    version: editor,
                },
                CustomVersion {
                    guid: CORE_OBJECT_VERSION_GUID,
                    version: core,
                },
                CustomVersion {
                    guid: RENDERING_OBJECT_VERSION_GUID,
                    version: rendering,
                },
                CustomVersion {
                    guid: FORTNITE_MAIN_BRANCH_OBJECT_VERSION_GUID,
                    version: fortnite,
                },
            ],
        };
        AssetContext::new(
            Arc::new(table),
            Arc::new(ImportTable::default()),
            Arc::new(ExportTable::default()),
            AssetVersion {
                legacy_file_version: -7,
                file_version_ue4: 518,
                file_version_ue5: None,
                file_version_licensee_ue4: 0,
            },
            Arc::new(custom_versions),
            None,
        )
    }

    /// Append an `FName` pair `(index, number=0)` (8 bytes).
    fn fname(buf: &mut Vec<u8>, index: i32) {
        buf.extend_from_slice(&index.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
    }

    /// 24-byte `FMeshUVChannelInfo`: bInitialized=0, bOverrideDensities=0,
    /// 4×f32 zero.
    fn mesh_uv_channel_info(buf: &mut Vec<u8>) {
        buf.extend_from_slice(&0i32.to_le_bytes()); // bInitialized
        buf.extend_from_slice(&0i32.to_le_bytes()); // bOverrideDensities
        buf.extend_from_slice(&[0u8; 16]); // 4 × f32
    }

    #[test]
    fn reads_skeletal_material_ue4_cooked() {
        // editor=8, core=3, rendering=10 → all three gates ON;
        // fortnite below 196 → no OverlayMaterial.
        let ctx = skel_mat_ctx(&["Mat0"], 8, 3, 10, 100);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0i32.to_le_bytes()); // Material FPackageIndex (4)
        fname(&mut bytes, 0); // MaterialSlotName "Mat0" (8)
        bytes.extend_from_slice(&0i32.to_le_bytes()); // bSerializeImported = 0 (4)
        mesh_uv_channel_info(&mut bytes); // FMeshUVChannelInfo (24)
        assert_eq!(bytes.len(), 40);

        let mut cur = Cursor::new(bytes.as_slice());
        let name = read_skeletal_material(&mut cur, &ctx, "T.uasset").expect("decode");
        assert_eq!(name.as_deref(), Some("Mat0"));
        assert_eq!(cur.position(), bytes.len() as u64);
    }

    #[test]
    fn reads_skeletal_material_ue5_with_overlay() {
        // fortnite=196 → OverlayMaterial FPackageIndex present (4 extra bytes).
        let ctx = skel_mat_ctx(&["Mat0"], 8, 3, 10, 196);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0i32.to_le_bytes()); // Material FPackageIndex (4)
        fname(&mut bytes, 0); // MaterialSlotName "Mat0" (8)
        bytes.extend_from_slice(&0i32.to_le_bytes()); // bSerializeImported = 0 (4)
        mesh_uv_channel_info(&mut bytes); // FMeshUVChannelInfo (24)
        bytes.extend_from_slice(&0i32.to_le_bytes()); // OverlayMaterial FPackageIndex (4)
        assert_eq!(bytes.len(), 44);

        let mut cur = Cursor::new(bytes.as_slice());
        let name = read_skeletal_material(&mut cur, &ctx, "T.uasset").expect("decode");
        assert_eq!(name.as_deref(), Some("Mat0"));
        assert_eq!(cur.position(), bytes.len() as u64);
    }

    #[test]
    fn skeletal_material_gate_off_skips_uvchannel() {
        // rendering below 10 → no FMeshUVChannelInfo read. Pins the rendering
        // `>=` gate: only FPackageIndex + FName + bool32 = 16 bytes consumed.
        let ctx = skel_mat_ctx(&["Mat0"], 8, 3, 9, 100);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0i32.to_le_bytes()); // Material FPackageIndex (4)
        fname(&mut bytes, 0); // MaterialSlotName "Mat0" (8)
        bytes.extend_from_slice(&0i32.to_le_bytes()); // bSerializeImported = 0 (4)
        assert_eq!(bytes.len(), 16);

        let mut cur = Cursor::new(bytes.as_slice());
        let name = read_skeletal_material(&mut cur, &ctx, "T.uasset").expect("decode");
        assert_eq!(name.as_deref(), Some("Mat0"));
        assert_eq!(cur.position(), bytes.len() as u64);
    }

    #[test]
    fn skeletal_material_pre_refactor_returns_no_slot_name() {
        // editor<8, core<3, rendering<10, fortnite<196 → every gate OFF, so only
        // the Material FPackageIndex is on the wire. Pins the editor-`>=` and
        // core-`>=` gates (the only ones whose OFF branch the other tests don't
        // exercise) and the `None`-slot return.
        let ctx = skel_mat_ctx(&["Mat0"], 7, 2, 9, 100);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0i32.to_le_bytes()); // Material FPackageIndex (4)

        let mut cur = Cursor::new(bytes.as_slice());
        let name = read_skeletal_material(&mut cur, &ctx, "T.uasset").expect("decode");
        assert_eq!(name, None);
        assert_eq!(cur.position(), 4);
    }

    #[test]
    fn skeletal_material_fortnite_just_below_threshold_no_overlay() {
        // fortnite=195 is one below the >= 196 gate — pins `>= 196` against
        // a `> 196` mutant. No OverlayMaterial bytes on the wire; the reader
        // must consume exactly 40 bytes (same layout as the UE4-cooked test).
        let ctx = skel_mat_ctx(&["Mat0"], 8, 3, 10, 195);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0i32.to_le_bytes()); // Material FPackageIndex (4)
        fname(&mut bytes, 0); // MaterialSlotName "Mat0" (8)
        bytes.extend_from_slice(&0i32.to_le_bytes()); // bSerializeImported = 0 (4)
        mesh_uv_channel_info(&mut bytes); // FMeshUVChannelInfo (24)
        assert_eq!(bytes.len(), 40);

        let mut cur = Cursor::new(bytes.as_slice());
        let name = read_skeletal_material(&mut cur, &ctx, "T.uasset").expect("decode");
        assert_eq!(name.as_deref(), Some("Mat0"));
        assert_eq!(cur.position(), 40);
    }

    #[test]
    fn reads_mesh_uv_channel_info_consumes_24_bytes() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1i32.to_le_bytes()); // bInitialized = 1
        bytes.extend_from_slice(&0i32.to_le_bytes()); // bOverrideDensities = 0
        bytes.extend_from_slice(&[0u8; 16]); // 4 × f32 = 0.0
        assert_eq!(bytes.len(), 24);

        let mut cur = Cursor::new(bytes.as_slice());
        read_mesh_uv_channel_info(&mut cur, "T.uasset").expect("decode");
        assert_eq!(cur.position(), 24);
    }

    #[test]
    fn rejects_non_strict_initialized_bool() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&2i32.to_le_bytes()); // bInitialized = 2 → invalid
        bytes.extend_from_slice(&0i32.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 16]);

        let mut cur = Cursor::new(bytes.as_slice());
        let err = read_mesh_uv_channel_info(&mut cur, "T.uasset").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::InvalidBool32 {
                    field: AssetWireField::MeshUvChannelInfo,
                    observed: 2,
                },
                ..
            }
        ));
    }

    #[test]
    fn truncated_bool_region_is_io_eof() {
        // A cut inside the bool32 region propagates as PaksmithError::Io (the
        // documented read_bool32 EOF behavior), not AssetParseFault::UnexpectedEof.
        let bytes = 1i32.to_le_bytes(); // only bInitialized; bOverrideDensities truncated
        let mut cur = Cursor::new(bytes.as_slice());
        let err = read_mesh_uv_channel_info(&mut cur, "T.uasset").unwrap_err();
        assert!(
            matches!(err, PaksmithError::Io(_)),
            "expected Io, got {err:?}"
        );
    }

    #[test]
    fn truncated_mesh_uv_channel_info_is_eof() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1i32.to_le_bytes());
        bytes.extend_from_slice(&0i32.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 8]); // only 2 of 4 floats

        let mut cur = Cursor::new(bytes.as_slice());
        let err = read_mesh_uv_channel_info(&mut cur, "T.uasset").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::UnexpectedEof {
                    field: AssetWireField::MeshUvChannelInfo,
                },
                ..
            }
        ));
    }

    // ===== Task 7: read_typed hardening (cap / truncation / UE5 end-to-end) =====

    /// Build an `AssetContext` whose `custom_versions` stamp all four gate
    /// plugins at UE5-overlay levels (`fortnite >= 196`), with `file_version_ue5
    /// = Some(1004)` (LWC). Used by [`read_typed_ue5_overlay_end_to_end`].
    fn skel_mat_ctx_ue5(names: &[&str]) -> AssetContext {
        let table = NameTable {
            names: names.iter().map(|n| FName::new(n)).collect(),
        };
        let custom_versions = CustomVersionContainer {
            versions: vec![
                CustomVersion {
                    guid: EDITOR_OBJECT_VERSION_GUID,
                    version: 8,
                },
                CustomVersion {
                    guid: CORE_OBJECT_VERSION_GUID,
                    version: 3,
                },
                CustomVersion {
                    guid: RENDERING_OBJECT_VERSION_GUID,
                    version: 10,
                },
                CustomVersion {
                    guid: FORTNITE_MAIN_BRANCH_OBJECT_VERSION_GUID,
                    version: 196,
                },
            ],
        };
        AssetContext::new(
            Arc::new(table),
            Arc::new(ImportTable::default()),
            Arc::new(ExportTable::default()),
            AssetVersion {
                legacy_file_version: -8,
                file_version_ue4: 522,
                file_version_ue5: Some(1004),
                file_version_licensee_ue4: 0,
            },
            Arc::new(custom_versions),
            None,
        )
    }

    /// Build the segment-1 + segment-2 prefix through `ImportedBounds` for the
    /// given `ctx`. Returns the bytes that every `read_typed` hardening test
    /// shares:
    ///
    /// ```text
    /// [segment-1]  write_object_end  (12 bytes: None-tag 8B + bSerializeGuid 4B)
    /// [seg-2]      FStripDataFlags   (2 bytes: global, class)
    /// [seg-2]      ImportedBounds    (28 bytes UE4 / 56 bytes UE5 LWC)
    /// ```
    ///
    /// Each test then appends its own perturbation immediately after.
    fn build_prefix_through_bounds(ctx: &AssetContext) -> Vec<u8> {
        let mut buf = Vec::new();
        // Segment 1: empty tagged-property stream + object-GUID tail.
        crate::asset::property::test_utils::write_object_end(&mut buf);
        // FStripDataFlags: global=0, class=0.
        buf.extend_from_slice(&[0x00u8, 0x00]);
        // ImportedBounds: all values 1.0 regardless of precision —
        // each test that parses successfully verifies these fields separately;
        // here they just need to be syntactically valid.
        let bounds_bytes = usize::try_from(FBoxSphereBounds::wire_size(ctx))
            .expect("bounds size fits usize on any supported target");
        if bounds_bytes == 28 {
            // UE4: 7 × f32.
            for _ in 0..7 {
                buf.extend_from_slice(&1.0f32.to_le_bytes());
            }
        } else {
            // UE5 LWC: 7 × f64.
            for _ in 0..7 {
                buf.extend_from_slice(&1.0f64.to_le_bytes());
            }
        }
        // write_object_end = 8 (None FName) + 4 (bSerializeGuid) = 12;
        // strip = 2; bounds = bounds_bytes.
        debug_assert_eq!(buf.len(), 12 + 2 + bounds_bytes);
        buf
    }

    /// Reject a `SkeletalMaterials` count of `MAX_SKELETAL_MATERIALS + 1`
    /// (`257`) before any allocation. Pins `BoundsExceeded { value: 257,
    /// limit: 256 }` — failing if the cap changes without updating this test.
    #[test]
    fn read_typed_materials_count_over_cap_is_rejected() {
        // UE4 ctx with no name pool needed (the cap fires before any FName read).
        let ctx = skel_mat_ctx(&[], 8, 3, 10, 100);
        let mut payload = build_prefix_through_bounds(&ctx);
        // Over-cap count — no material body bytes follow; the cap fires on the
        // i32 alone.
        let over_cap = (MAX_SKELETAL_MATERIALS + 1).cast_signed();
        payload.extend_from_slice(&over_cap.to_le_bytes());

        let err = read_typed(&payload, &ctx, "Mesh.uasset").unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::BoundsExceeded {
                        field: AssetWireField::SkeletalMaterialCount,
                        value: 257,
                        limit: 256,
                        ..
                    },
                    ..
                }
            ),
            "expected BoundsExceeded(257 > 256) for SkeletalMaterialCount, got {err:?}"
        );
    }

    /// Truncated payloads surface as typed errors, never as panics.
    ///
    /// Four truncation points spanning the full segment-2 prefix:
    /// (a) inside `ImportedBounds` (first f32-vector region) — exercises the
    ///     `FBoxSphereBounds::read_from` EOF path.
    /// (b) strip flags complete, zero bounds bytes — immediate bounds EOF.
    /// (c) bounds complete, `SkeletalMaterials` count truncated — exercises the
    ///     `read_capped_count` EOF path (no mat count i32 bytes present).
    /// (d) bounds + mat_count complete, truncated mid-first-material — exercises
    ///     the `read_skeletal_material` EOF path (count says 1, zero body bytes).
    ///
    /// None must panic.
    #[test]
    fn read_typed_truncated_mid_prefix_is_typed_error() {
        let ctx = skel_mat_ctx(&[], 8, 3, 10, 100);

        // (a) segment-1 complete, strip bytes present, ImportedBounds truncated
        //     half-way through (14 of 28 bytes). The truncated f32-vector read
        //     surfaces as an AssetParse / Io error, not a panic.
        {
            let mut payload = Vec::new();
            crate::asset::property::test_utils::write_object_end(&mut payload);
            payload.extend_from_slice(&[0x00u8, 0x00]); // FStripDataFlags
            payload.extend_from_slice(&[0x00u8; 14]); // half of 28-byte UE4 bounds
            let err = read_typed(&payload, &ctx, "Mesh.uasset").unwrap_err();
            // Any typed error is acceptable — no panic.
            assert!(
                matches!(err, PaksmithError::AssetParse { .. } | PaksmithError::Io(_)),
                "truncation-a must return typed error, got {err:?}"
            );
        }

        // (b) segment-1 complete, FStripDataFlags complete, zero bounds bytes.
        //     The very first byte of ImportedBounds is missing.
        {
            let mut payload = Vec::new();
            crate::asset::property::test_utils::write_object_end(&mut payload);
            payload.extend_from_slice(&[0x00u8, 0x00]); // FStripDataFlags only
            let err = read_typed(&payload, &ctx, "Mesh.uasset").unwrap_err();
            assert!(
                matches!(err, PaksmithError::AssetParse { .. } | PaksmithError::Io(_)),
                "truncation-b must return typed error, got {err:?}"
            );
        }

        // (c) bounds complete, SkeletalMaterials count field completely absent —
        //     exercises the read_capped_count EOF path.
        {
            let payload = build_prefix_through_bounds(&ctx);
            // payload ends right after bounds; no mat_count i32 present.
            let err = read_typed(&payload, &ctx, "Mesh.uasset").unwrap_err();
            assert!(
                matches!(err, PaksmithError::AssetParse { .. } | PaksmithError::Io(_)),
                "truncation-c must return typed error, got {err:?}"
            );
        }

        // (d) bounds + mat_count (i32=1) complete, zero material body bytes —
        //     exercises the read_skeletal_material EOF path (count says 1, but
        //     the first FPackageIndex i32 is absent).
        {
            let mut payload = build_prefix_through_bounds(&ctx);
            payload.extend_from_slice(&1i32.to_le_bytes()); // mat_count = 1
            // no FPackageIndex bytes follow
            let err = read_typed(&payload, &ctx, "Mesh.uasset").unwrap_err();
            assert!(
                matches!(err, PaksmithError::AssetParse { .. } | PaksmithError::Io(_)),
                "truncation-d must return typed error, got {err:?}"
            );
        }
    }

    /// Full `read_typed` end-to-end with a UE5 LWC context (`file_version_ue5 =
    /// Some(1004)`) and `FFortniteMainBranchObjectVersion >= 196` so each
    /// `FSkeletalMaterial` carries the `OverlayMaterial` `FPackageIndex`.
    ///
    /// Verifies that `read_typed` stays cursor-aligned through the LWC
    /// `FBoxSphereBounds` (56 B), the UE5 material variant (44 B per slot),
    /// the LWC `FReferenceSkeleton` (f64 `FTransform`s), and `bCooked`.
    #[test]
    fn read_typed_ue5_overlay_end_to_end() {
        // Name table: 0="None" (property-stream terminator), 1="Mat0"
        // (material slot name), 2="Root" (single bone).
        let ctx = skel_mat_ctx_ue5(&["None", "Mat0", "Root"]);

        // Segment 1 + FStripDataFlags + ImportedBounds (56B UE5 LWC) via shared helper.
        let mut payload = build_prefix_through_bounds(&ctx);

        // SkeletalMaterials: count = 1.
        payload.extend_from_slice(&1i32.to_le_bytes());
        // One FSkeletalMaterial (UE5 with OverlayMaterial, 44 bytes):
        //   Material FPackageIndex (4) + MaterialSlotName "Mat0" (8) +
        //   bSerializeImported=0 (4) + FMeshUVChannelInfo (24) +
        //   OverlayMaterial FPackageIndex (4) = 44 bytes.
        payload.extend_from_slice(&0i32.to_le_bytes()); // Material = Null
        fname(&mut payload, 1); // MaterialSlotName "Mat0"
        payload.extend_from_slice(&0i32.to_le_bytes()); // bSerializeImported = 0
        mesh_uv_channel_info(&mut payload); // 24 bytes
        payload.extend_from_slice(&0i32.to_le_bytes()); // OverlayMaterial = Null

        // FReferenceSkeleton: 1 bone "Root", UE5 LWC (80-byte FTransform).
        // FinalRefBoneInfo: count 1 + (name FName, parent i32).
        payload.extend_from_slice(&1i32.to_le_bytes());
        fname(&mut payload, 2); // "Root"
        payload.extend_from_slice(&(-1i32).to_le_bytes()); // parent = root
        // FinalRefBonePose: count 1 + one 80-byte identity FTransform (f64).
        payload.extend_from_slice(&1i32.to_le_bytes());
        for v in [0.0f64, 0.0, 0.0, 1.0] {
            payload.extend_from_slice(&v.to_le_bytes()); // Quat x,y,z,w
        }
        for v in [0.0f64, 0.0, 0.0] {
            payload.extend_from_slice(&v.to_le_bytes()); // Translation
        }
        for v in [1.0f64, 1.0, 1.0] {
            payload.extend_from_slice(&v.to_le_bytes()); // Scale3D
        }
        // FinalNameToIndexMap: count 1 + (key FName, value i32).
        payload.extend_from_slice(&1i32.to_le_bytes());
        fname(&mut payload, 2); // "Root"
        payload.extend_from_slice(&0i32.to_le_bytes()); // index 0

        // bCooked = true.
        payload.extend_from_slice(&1i32.to_le_bytes());

        let (asset, bulk) = read_typed(&payload, &ctx, "Mesh.uasset").expect("UE5 parse");
        assert!(bulk.is_empty(), "no out-of-line bulk records");
        let Asset::SkeletalMesh(data) = asset else {
            panic!("expected Asset::SkeletalMesh, got {asset:?}");
        };
        assert_eq!(data.skeleton.bones.len(), 1);
        assert_eq!(data.skeleton.bones[0].name, "Root");
        assert_eq!(data.materials, vec!["Mat0".to_string()]);
        assert!(data.cooked, "bCooked must be true");
        assert!(data.lods.is_empty());
    }

    // ===== Task 5: read_typed end-to-end =====

    /// 40-byte identity `FTransform` (UE4 single-precision): Quat(0,0,0,1),
    /// Translation(0,0,0), Scale3D(1,1,1) — mirrors `skeleton.rs`'s worked
    /// example so the bind-pose decodes to the unit identity.
    fn identity_ftransform_ue4(buf: &mut Vec<u8>) {
        for v in [0.0f32, 0.0, 0.0, 1.0] {
            buf.extend_from_slice(&v.to_le_bytes()); // Quat x,y,z,w
        }
        for v in [0.0f32, 0.0, 0.0] {
            buf.extend_from_slice(&v.to_le_bytes()); // Translation
        }
        for v in [1.0f32, 1.0, 1.0] {
            buf.extend_from_slice(&v.to_le_bytes()); // Scale3D
        }
    }

    /// Append the PR1 2-bone `FReferenceSkeleton` worked example, with the bone
    /// names at FName indices `bone0_idx` / `bone1_idx` (shifted from the
    /// skeleton.rs example's 0/1 because the read_typed fixture forces
    /// `"None"` to index 0). 140 bytes.
    fn two_bone_reference_skeleton(buf: &mut Vec<u8>, bone0_idx: i32, bone1_idx: i32) {
        let start = buf.len();
        // FinalRefBoneInfo: count 2 + (name, parent) per bone.
        buf.extend_from_slice(&2i32.to_le_bytes());
        fname(buf, bone0_idx); // bone 0 name
        buf.extend_from_slice(&(-1i32).to_le_bytes()); // parent -1 (root)
        fname(buf, bone1_idx); // bone 1 name
        buf.extend_from_slice(&0i32.to_le_bytes()); // parent 0
        // FinalRefBonePose: count 2 + two identity transforms (40 bytes each).
        buf.extend_from_slice(&2i32.to_le_bytes());
        identity_ftransform_ue4(buf);
        identity_ftransform_ue4(buf);
        // FinalNameToIndexMap: count 2 + (key, value) per bone.
        buf.extend_from_slice(&2i32.to_le_bytes());
        fname(buf, bone0_idx);
        buf.extend_from_slice(&0i32.to_le_bytes());
        fname(buf, bone1_idx);
        buf.extend_from_slice(&1i32.to_le_bytes());
        debug_assert_eq!(buf.len() - start, 140);
    }

    #[test]
    fn read_typed_parses_prefix_through_skeleton() {
        // Name table: 0="None" (the empty-property None terminator), 1="Mat0"
        // (material slot), 2="Root" / 3="Hip" (bones). UE4-cooked material gates
        // ON (editor=8/core=3/rendering=10), fortnite below the UE5 overlay
        // gate. ue5=None → FBoxSphereBounds=28B, FTransform=40B.
        let ctx = skel_mat_ctx(&["None", "Mat0", "Root", "Hip"], 8, 3, 10, 100);

        let mut payload = Vec::new();
        // Segment 1: empty tagged-property stream (None tag) + object-GUID tail.
        crate::asset::property::test_utils::write_object_end(&mut payload);
        // Segment 2 prefix.
        payload.extend_from_slice(&[0x00, 0x00]); // FStripDataFlags (global, class)
        // ImportedBounds (UE4 FBoxSphereBounds, 28B): distinct non-zero
        // origin / box_extent / sphere_radius so the `data.bounds = bounds`
        // assignment is mutation-visible against the all-zero `empty()` default.
        for v in [1.0f32, 2.0, 3.0] {
            payload.extend_from_slice(&v.to_le_bytes()); // origin x,y,z
        }
        for v in [4.0f32, 5.0, 6.0] {
            payload.extend_from_slice(&v.to_le_bytes()); // box_extent x,y,z
        }
        payload.extend_from_slice(&7.0f32.to_le_bytes()); // sphere_radius
        // SkeletalMaterials: count 1 + one UE4-cooked FSkeletalMaterial (40B):
        // Material FPackageIndex (4) + MaterialSlotName "Mat0" (8) +
        // bSerializeImported=0 (4) + FMeshUVChannelInfo (24).
        payload.extend_from_slice(&1i32.to_le_bytes());
        payload.extend_from_slice(&0i32.to_le_bytes()); // Material FPackageIndex = Null
        fname(&mut payload, 1); // MaterialSlotName "Mat0"
        payload.extend_from_slice(&0i32.to_le_bytes()); // bSerializeImported = 0
        mesh_uv_channel_info(&mut payload);
        // FReferenceSkeleton (2 bones at FName 2/3).
        two_bone_reference_skeleton(&mut payload, 2, 3);
        // bCooked = true.
        payload.extend_from_slice(&1i32.to_le_bytes());

        let (asset, bulk) = read_typed(&payload, &ctx, "Mesh.uasset").expect("parse");
        assert!(bulk.is_empty(), "no out-of-line bulk records");
        let Asset::SkeletalMesh(data) = asset else {
            panic!("expected Asset::SkeletalMesh, got {asset:?}");
        };
        assert_eq!(data.skeleton.bones.len(), 2);
        assert_eq!(data.skeleton.bones[0].name, "Root");
        assert_eq!(data.skeleton.bones[1].name, "Hip");
        assert_eq!(data.materials, vec!["Mat0".to_string()]);
        // Bounds round-trip — distinct non-zero values pin the assignment
        // against an empty()-default (all-zero) mutant.
        assert!((data.bounds.origin.x - 1.0).abs() < f64::EPSILON);
        assert!((data.bounds.box_extent.z - 6.0).abs() < f64::EPSILON);
        assert!((data.bounds.sphere_radius - 7.0).abs() < f64::EPSILON);
        assert!(data.cooked);
        assert!(data.lods.is_empty());
    }
}
