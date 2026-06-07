//! `USkeletalMesh` export parsing (Phase 3h). Wire reference:
//! `docs/formats/mesh/skeletal-mesh.md`.
//!
//! PR2 scope is the `FMeshUVChannelInfo` leaf reader and the
//! `FSkeletalMaterial` reader that consumes it; the segment-2 prefix and
//! dispatch wiring land in later steps/PRs of the 3h series.

use std::io::{Read, Seek};

use crate::asset::AssetContext;
use crate::asset::custom_version::{
    CORE_OBJECT_VERSION_GUID, EDITOR_OBJECT_VERSION_GUID, FORTNITE_MAIN_BRANCH_OBJECT_VERSION_GUID,
    MESH_MATERIAL_SLOT_OVERLAY_MATERIAL_ADDED, REFACTOR_MESH_EDITOR_MATERIALS,
    RENDERING_OBJECT_VERSION_GUID, SKELETAL_MATERIAL_EDITOR_DATA_STRIPPING,
    TEXTURE_STREAMING_MESH_UV_CHANNEL_DATA,
};
use crate::asset::property::read_fname_pair;
use crate::asset::read_package_index;
use crate::asset::wire::read_bool32;
use crate::error::AssetWireField;

use super::read;

/// `FMeshUVChannelInfo::MAX_TEXCOORDS` — the fixed `LocalUVDensities` element
/// count (oracle `FMeshUVChannelInfo.cs` @ `cf74fc32`). Read as a fixed-size
/// `float[]` with NO count prefix.
#[allow(
    dead_code,
    reason = "consumed by the FSkeletalMaterial reader (next 3h step)"
)]
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
#[allow(
    dead_code,
    reason = "called by the FSkeletalMaterial reader (next 3h step)"
)]
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
#[allow(
    dead_code,
    reason = "wired into USkeletalMesh::read_typed in the next 3h step (Task 5)"
)]
pub(super) fn read_skeletal_material<R: Read + Seek + ?Sized>(
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
        let _overlay =
            read_package_index(r, asset_path, AssetWireField::SkeletalMaterialInterface)?;
    }

    Ok(slot)
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
}
