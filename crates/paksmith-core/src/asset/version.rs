//! UE engine-version constants and the [`AssetVersion`] bundle.
//!
//! Source of truth: UE's `EUnrealEngineObjectUE4Version`,
//! `EUnrealEngineObjectUE5Version`, `EPackageFileTag` enums (in
//! `Engine/Source/Runtime/Core/Public/UObject/ObjectVersion.h` and
//! `ObjectVersionUE5.h`). Each `VER_UE4_*` / `VER_UE5_*` constant
//! below is a wire-format gate — a field is read only when the
//! file's reported version is ≥ the constant.
//!
//! Phase 2a accepts `LegacyFileVersion ∈ {-7, -8}` and
//! `FileVersionUE4 ≥ VER_UE4_NAME_HASHES_SERIALIZED`. Narrower
//! windows can be widened by Phase 2b+ without changing this file's
//! shape; the constants here are stable.

use serde::Serialize;

/// UE package magic (`'\x9E*\x83\xC1'`). First 4 bytes of every
/// `.uasset` file.
pub const PACKAGE_FILE_TAG: u32 = 0x9E2A_83C1;

/// Byte-swapped magic, used by UE itself for cross-endian detection.
/// Rejected by paksmith — we don't support BE-encoded uassets.
pub const PACKAGE_FILE_TAG_SWAPPED: u32 = 0xC183_2A9E;

/// Phase 2a lower bound for `FileVersionUE4`. Below this, the name
/// table doesn't carry the dual CityHash16 hash pair we require.
/// (UE4.21 = 503, this constant = 504.)
pub const VER_UE4_NAME_HASHES_SERIALIZED: i32 = 504;

/// UE 4.x: `LocalizationId` FString added to the package summary
/// (editor-only — present only when `PKG_FilterEditorOnly` is NOT set).
pub const VER_UE4_ADDED_PACKAGE_SUMMARY_LOCALIZATION_ID: i32 = 516;

/// UE 4.x: `OwnerPersistentGuid` (FGuid) added to summary. Lives
/// between `ADDED_PACKAGE_OWNER` and `NON_OUTER_PACKAGE_IMPORT` only
/// — UE removed it immediately. Editor-only.
pub const VER_UE4_ADDED_PACKAGE_OWNER: i32 = 518;

/// UE 4.x: `OwnerPersistentGuid` retired (was added at 518, removed
/// here at 520). Phase 2a always reads `LegacyFileVersion ≤ -7`
/// (UE 4.21+ = 520+), so `OwnerPersistentGuid` is never in the wire
/// stream we accept.
pub const VER_UE4_NON_OUTER_PACKAGE_IMPORT: i32 = 520;

/// UE 5.0+: `FileVersionUE5` is present when `LegacyFileVersion ≤ -8`.
/// Values are sequential from this base; the canonical numbering is
/// verified against CUE4Parse's `EUnrealEngineObjectUE5Version`
/// (`CUE4Parse/UE4/Versions/ObjectVersion.cs`) and the `unreal_asset`
/// oracle's `ObjectVersionUE5` enum.
pub const VER_UE5_INITIAL_VERSION: i32 = 1000;

/// UE 5.0+: enables stripping names not referenced from export data —
/// a name-table optimisation. Gates `names_referenced_from_export_data_count`
/// in the summary.
pub const VER_UE5_NAMES_REFERENCED_FROM_EXPORT_DATA: i32 = 1001;

/// UE 5.0+: `payload_toc_offset` (i64) added to the summary.
pub const VER_UE5_PAYLOAD_TOC: i32 = 1002;

/// UE 5.0+: `bImportOptional` (i32 bool, NOT u8) appended to
/// `FObjectImport`; `generate_public_hash` (i32 bool) appended to
/// `FObjectExport`.
pub const VER_UE5_OPTIONAL_RESOURCES: i32 = 1003;

/// UE 5.0+: large-world-coordinates (no wire-format impact for the
/// fields Phase 2a reads).
pub const VER_UE5_LARGE_WORLD_COORDINATES: i32 = 1004;

/// UE 5.0+: `package_guid` FGuid removed from `FObjectExport`.
/// Below this version, the export carries 16 GUID bytes; at or above,
/// it does not.
pub const VER_UE5_REMOVE_OBJECT_EXPORT_PACKAGE_GUID: i32 = 1005;

/// UE 5.0+: `is_inherited_instance` (i32 bool) added to `FObjectExport`.
pub const VER_UE5_TRACK_OBJECT_EXPORT_IS_INHERITED: i32 = 1006;

/// UE 5.0+: `SoftObjectPath` list added to the summary
/// (`soft_object_paths_count` + `soft_object_paths_offset`).
pub const VER_UE5_ADD_SOFTOBJECTPATH_LIST: i32 = 1008;

/// UE 5.0+: `data_resource_offset` (i32) added to the summary.
pub const VER_UE5_DATA_RESOURCES: i32 = 1009;

/// Resolved version snapshot for one parsed asset. Threaded by `&` or
/// `Copy` into every downstream parser. Cheap to copy (5 × i32).
///
/// `Default` returns the zero version (legacy=0, ue4=0, ue5=None,
/// licensee=0) — useful only for test fixtures that don't exercise
/// version-gated branches. Real callers must construct explicitly via
/// `PackageSummary::read_from`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub struct AssetVersion {
    /// The `LegacyFileVersion` field from the start of the summary.
    /// Phase 2a accepts `-7` (UE 4.21–4.27) and `-8` (UE 5.0+).
    pub legacy_file_version: i32,
    /// `FileVersionUE4` (`EUnrealEngineObjectUE4Version`).
    pub file_version_ue4: i32,
    /// `FileVersionUE5`. `None` when `legacy_file_version > -8`.
    pub file_version_ue5: Option<i32>,
    /// `FileVersionLicenseeUE4` (project-specific licensee version).
    pub file_version_licensee_ue4: i32,
}

impl AssetVersion {
    /// True iff the asset's reported version is ≥ `floor` for UE4.
    #[must_use]
    pub fn ue4_at_least(self, floor: i32) -> bool {
        self.file_version_ue4 >= floor
    }

    /// True iff the asset's reported UE5 version is ≥ `floor`.
    /// Returns `false` when no UE5 version is present (pre-UE5 asset).
    #[must_use]
    pub fn ue5_at_least(self, floor: i32) -> bool {
        self.file_version_ue5.is_some_and(|v| v >= floor)
    }
}
