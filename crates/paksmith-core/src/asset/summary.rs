//! `FPackageFileSummary` — the asset header at byte 0 of every `.uasset`.
//!
//! The orchestrating reader for Phase 2a. Reads the legacy/UE4/UE5/
//! licensee version block, the [`CustomVersionContainer`], the header
//! size + folder name, every table offset/count needed by Tasks 6–8
//! (name/import/export and friends), two `FGuid` slots, the generation
//! list (rows discarded — see "lossy round-trip" below), two
//! [`EngineVersion`] stamps, the in-summary compression slots (rejected
//! non-zero), `package_source`, asset-registry/bulk-data/world-tile/
//! chunk-id/preload-dependency offsets, and three UE5-only trailers
//! (`names_referenced_from_export_data_count`, `payload_toc_offset`,
//! `data_resource_offset`).
//!
//! Verified against CUE4Parse's `FPackageFileSummary` reader
//! (`CUE4Parse/UE4/Objects/UObject/FPackageFileSummary.cs`). Cross-
//! validation via the `unreal_asset` oracle is deferred to Task 12
//! (fixture-gen), which adds `unreal_asset` as a fixture-gen dev-dep.

use std::io::Read;
#[cfg(any(test, feature = "__test_utils"))]
use std::io::Write;

#[cfg(any(test, feature = "__test_utils"))]
use byteorder::WriteBytesExt;
use byteorder::{LittleEndian, ReadBytesExt};
use serde::Serialize;

use crate::asset::FGuid;
use crate::asset::custom_version::CustomVersionContainer;
use crate::asset::engine_version::EngineVersion;
use crate::asset::read_asset_fstring;
use crate::asset::version::{
    AssetVersion, PACKAGE_FILE_TAG, VER_UE4_ADDED_PACKAGE_OWNER,
    VER_UE4_ADDED_PACKAGE_SUMMARY_LOCALIZATION_ID, VER_UE4_ADDED_SEARCHABLE_NAMES,
    VER_UE4_NAME_HASHES_SERIALIZED, VER_UE4_NON_OUTER_PACKAGE_IMPORT,
    VER_UE4_PRELOAD_DEPENDENCIES_IN_COOKED_EXPORTS, VER_UE5_ADD_SOFTOBJECTPATH_LIST,
    VER_UE5_DATA_RESOURCES, VER_UE5_NAMES_REFERENCED_FROM_EXPORT_DATA, VER_UE5_PAYLOAD_TOC,
};
#[cfg(any(test, feature = "__test_utils"))]
use crate::asset::write_asset_fstring;
use crate::error::{AssetParseFault, AssetWireField, BoundsUnit, PaksmithError};

/// Hard cap on the wire-claimed `total_header_size`. Phase 2a rejects
/// header-claimed sizes above 256 MiB — UE writers never approach this
/// limit, and an over-cap claim signals a malicious or corrupted asset.
const MAX_TOTAL_HEADER_SIZE: i32 = 256 * 1024 * 1024;

/// Hard cap on the wire-claimed generation count. UE assets in the
/// wild typically have <10 generations; cap is generous and bounds
/// the CPU loop on malformed input.
const MAX_GENERATION_COUNT: i32 = 1_024;

/// Hard cap on the wire-claimed `additional_packages_to_cook` count.
/// Each entry is a discarded FString read; cap bounds the CPU loop.
const MAX_ADDITIONAL_PACKAGES_TO_COOK_COUNT: i32 = 4_096;

/// Hard cap on the wire-claimed chunk-id count. Each entry is a
/// discarded i32; cap bounds the CPU loop.
const MAX_CHUNK_ID_COUNT: i32 = 65_536;

/// Phase 2a ceiling on `FileVersionUE5` (exclusive). Verified against
/// CUE4Parse's `EUnrealEngineObjectUE5Version` enum
/// (`CUE4Parse/UE4/Versions/ObjectVersion.cs`):
///
/// - `PROPERTY_TAG_EXTENSION_AND_OVERRIDABLE_SERIALIZATION = 1011`
///   adds a new byte after `HasPropertyGuid` in `FPropertyTag`.
///   Phase 2b's tag reader does not handle this and would misparse.
/// - `PROPERTY_TAG_COMPLETE_TYPE_NAME = 1012` replaces the legacy
///   FName-typed tag with a tree-based type-name representation.
///   Phase 2b's tag reader does not handle this at all.
/// - `PACKAGE_SAVED_HASH = 1016` replaces the summary's `FGuid` with
///   an `FIoHash` (different size + shape).
///
/// The earliest UE5 version that breaks Phase 2's readers is therefore
/// `PROPERTY_TAG_EXTENSION_AND_OVERRIDABLE_SERIALIZATION = 1011` (an
/// FPropertyTag wire-format break, not an export break as a prior draft
/// of this plan asserted). Accept versions 1000–1010 inclusive; reject
/// 1011+. The `ObjectExport.package_guid` removal at version 1005, the
/// `is_inherited_instance` addition at 1006, the `generate_public_hash`
/// addition at 1003, the `data_resource_offset` summary addition at
/// 1009, etc. are all WITHIN the accepted range and are handled with
/// conditional reads (see Tasks 7–9).
pub const FIRST_UNSUPPORTED_UE5_VERSION: i32 = 1011;

/// `PKG_FilterEditorOnly` — UE's `EPackageFlags` bit for "this archive
/// was cooked and stripped of editor-only state". Cooked game archives
/// (paksmith's primary input) almost always have this set.
const PKG_FILTER_EDITOR_ONLY: u32 = 0x8000_0000;

/// `PKG_UnversionedProperties` — UE's `EPackageFlags` bit for "uses
/// unversioned property serialization instead of versioned tagged
/// property serialization". Source: CUE4Parse
/// `CUE4Parse/UE4/Objects/UObject/EPackageFlags.cs` HEAD. Consumed by
/// the export-table reader to gate the UE5 1010
/// `ScriptSerializationStartOffset`/`EndOffset` reads.
pub(crate) const PKG_UNVERSIONED_PROPERTIES: u32 = 0x0000_2000;

/// Parsed `FPackageFileSummary` (UE's name; paksmith uses snake_case).
///
/// Every field below corresponds 1:1 with a UE wire-format field; the
/// names follow `snake_case` rather than UE's `PascalCase`. Fields that
/// reference table offsets/counts are typed as `i32` (wire-faithful);
/// the validation that they're non-negative happens at the dependent
/// reader's seek site rather than here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PackageSummary {
    /// Resolved version snapshot (legacy + UE4 + optional UE5 + licensee).
    pub version: AssetVersion,
    /// Parsed custom-version container.
    pub custom_versions: CustomVersionContainer,
    /// Total byte size of the header (sum of summary + name/import/
    /// export tables + dependent regions).
    pub total_header_size: i32,
    /// `FolderName` FString. Typically `"None"` for cooked content.
    pub folder_name: String,
    /// `PackageFlags` (`EPackageFlags` u32 mask).
    pub package_flags: u32,
    /// Number of rows in the name table.
    pub name_count: i32,
    /// Byte offset of the first name-table record.
    pub name_offset: i32,
    /// `soft_object_paths_count` — `None` when `FileVersionUE5 < ADD_SOFTOBJECTPATH_LIST (1008)`.
    pub soft_object_paths_count: Option<i32>,
    /// `soft_object_paths_offset` — `None` when same gate as above.
    pub soft_object_paths_offset: Option<i32>,
    /// `LocalizationId` — only present when `FileVersionUE4 >=
    /// ADDED_PACKAGE_SUMMARY_LOCALIZATION_ID (516)` AND the
    /// `PKG_FilterEditorOnly` package flag is NOT set. Cooked game
    /// archives almost always have `PKG_FilterEditorOnly` set, so
    /// expect `None` in practice. Verified against CUE4Parse's
    /// `FPackageFileSummary` reader.
    pub localization_id: Option<String>,
    /// `GatherableTextDataCount`.
    pub gatherable_text_data_count: i32,
    /// `GatherableTextDataOffset`.
    pub gatherable_text_data_offset: i32,
    /// Number of rows in the export table.
    pub export_count: i32,
    /// Byte offset of the first export-table record.
    pub export_offset: i32,
    /// Number of rows in the import table.
    pub import_count: i32,
    /// Byte offset of the first import-table record.
    pub import_offset: i32,
    /// `DependsOffset`.
    pub depends_offset: i32,
    /// `SoftPackageReferencesCount`.
    pub soft_package_references_count: i32,
    /// `SoftPackageReferencesOffset`.
    pub soft_package_references_offset: i32,
    /// `SearchableNamesOffset` — `None` when `file_version_ue4 <
    /// VER_UE4_ADDED_SEARCHABLE_NAMES (510)`. Verified against
    /// CUE4Parse's `FPackageFileSummary` reader: the i32 is gated on
    /// `FileVersionUE >= ADDED_SEARCHABLE_NAMES`; below the gate the
    /// field is absent from the wire stream (CUE4Parse defaults the
    /// in-memory value to `0`). Reading/writing it unconditionally — as
    /// a prior draft did — misaligns 4 bytes on assets at UE4 504–509.
    pub searchable_names_offset: Option<i32>,
    /// `ThumbnailTableOffset`.
    pub thumbnail_table_offset: i32,
    /// Per-save `FGuid` identifier. UE writers generate a fresh GUID on
    /// every save.
    pub guid: FGuid,
    /// `PersistentGuid` — stable across saves (UE 4.27+). Editor-only:
    /// present on the wire iff BOTH `PKG_FilterEditorOnly` is clear in
    /// `package_flags` AND `file_version_ue4 >= VER_UE4_ADDED_PACKAGE_OWNER (518)`.
    /// Verified against CUE4Parse's `FPackageFileSummary` reader
    /// (`CUE4Parse/UE4/Objects/UObject/FPackageFileSummary.cs` HEAD,
    /// lines 326-336): the `PersistentGuid` is gated on
    /// `!PKG_FilterEditorOnly && FileVersionUE >= ADDED_PACKAGE_OWNER`.
    /// Cooked game assets almost always have the flag set, so this
    /// typically resolves to `None`. Writing it unconditionally — as a
    /// prior draft did — corrupted every subsequent offset on
    /// cross-parser round-trip (caught by Task 12's `unreal_asset`
    /// oracle).
    pub persistent_guid: Option<FGuid>,
    /// `OwnerPersistentGuid` — UE4-only, retired at version 520.
    /// Present on the wire iff `!PKG_FilterEditorOnly` AND
    /// `file_version_ue4 ∈ [ADDED_PACKAGE_OWNER (518), NON_OUTER_PACKAGE_IMPORT (520))`.
    /// CUE4Parse reads this as a separate `FGuid` immediately after
    /// `PersistentGuid`. Always `None` for cooked game assets and for
    /// uncooked assets outside the narrow `[518, 520)` window.
    /// Verified against CUE4Parse's `FPackageFileSummary` reader
    /// (lines 338-342 of `FPackageFileSummary.cs` HEAD).
    pub owner_persistent_guid: Option<FGuid>,
    /// Number of `FGenerationInfo` rows that followed the summary on
    /// disk. The rows themselves are discarded by [`Self::read_from`]
    /// — see the lossy-round-trip note on `read_from`.
    pub generation_count: i32,
    /// `FEngineVersion` recorded at save time.
    pub saved_by_engine_version: EngineVersion,
    /// `FEngineVersion` declaring runtime compatibility.
    pub compatible_with_engine_version: EngineVersion,
    /// `PackageSource` (u32; deprecated in modern UE but still on the wire).
    pub package_source: u32,
    /// `AssetRegistryDataOffset`.
    pub asset_registry_data_offset: i32,
    /// `BulkDataStartOffset` (i64).
    pub bulk_data_start_offset: i64,
    /// `WorldTileInfoDataOffset`.
    pub world_tile_info_data_offset: i32,
    /// `PreloadDependencyCount` — `None` when `file_version_ue4 <
    /// VER_UE4_PRELOAD_DEPENDENCIES_IN_COOKED_EXPORTS (507)`. Verified
    /// against CUE4Parse's `FPackageFileSummary` reader: below the gate
    /// the i32 pair is absent from the wire stream (CUE4Parse defaults
    /// the in-memory value to `-1`). Surfaced as `None` here to mirror
    /// the existing optional-on-the-wire pattern (`localization_id`,
    /// `persistent_guid`, `searchable_names_offset`) — "absent" is
    /// semantically distinct from "present but zero".
    pub preload_dependency_count: Option<i32>,
    /// `PreloadDependencyOffset` — `None` under the same gate as
    /// `preload_dependency_count`. CUE4Parse defaults to `0` below the
    /// gate; surfaced as `None` here for the same reason.
    pub preload_dependency_offset: Option<i32>,
    /// `NamesReferencedFromExportDataCount` — UE5 trailer; `None` when
    /// `FileVersionUE5 < NAMES_REFERENCED_FROM_EXPORT_DATA (1001)`.
    pub names_referenced_from_export_data_count: Option<i32>,
    /// `PayloadTocOffset` (i64) — UE5 trailer; `None` when
    /// `FileVersionUE5 < PAYLOAD_TOC (1002)`.
    pub payload_toc_offset: Option<i64>,
    /// `DataResourceOffset` — UE5 trailer; `None` when `FileVersionUE5
    /// < DATA_RESOURCES (1009)`.
    pub data_resource_offset: Option<i32>,
}

impl PackageSummary {
    /// Read the summary from byte 0 of `reader`.
    ///
    /// # Errors
    /// - [`AssetParseFault::InvalidMagic`] if the first 4 bytes aren't
    ///   [`PACKAGE_FILE_TAG`].
    /// - [`AssetParseFault::UnsupportedLegacyFileVersion`] if
    ///   `legacy_file_version` isn't `-7` or `-8`.
    /// - [`AssetParseFault::UnsupportedFileVersionUE4`] if
    ///   `file_version_ue4 < VER_UE4_NAME_HASHES_SERIALIZED` (504).
    /// - [`AssetParseFault::UnsupportedFileVersionUE5`] if
    ///   `file_version_ue5 >= FIRST_UNSUPPORTED_UE5_VERSION` (1011).
    /// - [`AssetParseFault::NegativeValue`] (with field
    ///   [`AssetWireField::TotalHeaderSize`], [`AssetWireField::GenerationCount`],
    ///   [`AssetWireField::AdditionalPackagesToCookCount`], or
    ///   [`AssetWireField::ChunkIdCount`]) when the corresponding wire-read
    ///   `i32` is negative.
    /// - [`AssetParseFault::BoundsExceeded`] (with field
    ///   [`AssetWireField::TotalHeaderSize`], [`AssetWireField::GenerationCount`],
    ///   [`AssetWireField::AdditionalPackagesToCookCount`], or
    ///   [`AssetWireField::ChunkIdCount`]) when the corresponding wire-claimed
    ///   value exceeds its structural cap.
    /// - [`AssetParseFault::UncookedAsset`] when the asset lacks
    ///   `PKG_FilterEditorOnly` at `file_version_ue4 >= 520` (see
    ///   "Preconditions" below).
    /// - [`AssetParseFault::UnsupportedCompressionInSummary`] if either
    ///   `compression_flags` or `compressed_chunks_count` is non-zero.
    /// - [`AssetParseFault::FStringMalformed`] if any embedded FString
    ///   (`folder_name`, `localization_id`, engine-version `branch`, or
    ///   any `additional_packages_to_cook` entry) is malformed.
    /// - Errors from [`CustomVersionContainer::read_from`],
    ///   [`FGuid::read_from`], and [`EngineVersion::read_from`]
    ///   propagated.
    /// - [`PaksmithError::Io`] on EOF or other I/O failures.
    ///
    /// # Preconditions
    ///
    /// Phase 2a's downstream readers (`ObjectImport::read_from`,
    /// `ObjectExport::read_from`) assume the asset was cooked
    /// (`package_flags & PKG_FilterEditorOnly != 0`). For uncooked
    /// editor assets at `file_version_ue4 >= VER_UE4_NON_OUTER_PACKAGE_IMPORT (520)`,
    /// `FObjectImport` carries an additional `PackageName` FName that
    /// paksmith's import reader does not consume; silent mis-alignment
    /// would result.
    ///
    /// `read_from` enforces this precondition at the summary boundary:
    /// uncooked assets at the version gate are rejected via
    /// [`AssetParseFault::UncookedAsset`]. Pak-extracted (cooked)
    /// assets, which are paksmith's primary target, are unaffected
    /// (`PKG_FilterEditorOnly` is set by UE's cooker).
    ///
    /// # Lossy round-trip on discarded fields
    ///
    /// Phase 2a discards several wire-format collections on read:
    /// - `FGenerationInfo` rows (the count is preserved via
    ///   `generation_count`; the rows themselves are dropped)
    /// - `additional_packages_to_cook` FStrings (count and rows both
    ///   dropped — `write_to` always emits count=0)
    /// - `chunk_ids` i32 array (count and rows both dropped — same)
    ///
    /// `write_to` synthesizes the rows: generations as `generation_count`
    /// zero `(export_count, name_count)` pairs; additional packages and
    /// chunk-ids both as count=0 + no rows. Matches UE's writer output
    /// for a fresh asset but NOT preserving the original asset's values.
    /// Phase 2a JSON output doesn't surface any of these fields.
    #[allow(
        clippy::too_many_lines,
        reason = "FPackageFileSummary's ~35 wire-format fields are read sequentially; \
                  splitting into sub-functions would obscure the byte-by-byte structure \
                  this code mirrors from UE/CUE4Parse"
    )]
    pub fn read_from<R: Read>(reader: &mut R, asset_path: &str) -> crate::Result<Self> {
        // Magic
        let tag = reader.read_u32::<LittleEndian>()?;
        if tag != PACKAGE_FILE_TAG {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::InvalidMagic {
                    observed: tag,
                    expected: PACKAGE_FILE_TAG,
                },
            });
        }
        // Versions. Accepted window: -7 (UE 4.21-4.27), -8 (UE 5.0-5.3),
        // -9 (UE 5.4+). Per CUE4Parse's FPackageFileSummary.cs HEAD
        // (lines 115-125), -9 introduces a contract that loaders may
        // need to early-exit on FileVersionTooNew; the wire-format
        // changes that ride at -9 (notably PACKAGE_SAVED_HASH at UE5
        // 1015 swapping the summary's FGuid for an FIoHash) are gated
        // by FileVersionUE5 floors well above Phase 2a's 1010 ceiling.
        // -9 is therefore wire-compatible with -8 within paksmith's
        // accepted UE5 range; widening the window is forward-compat
        // only (no behavior change for existing -7/-8 inputs).
        let legacy_file_version = reader.read_i32::<LittleEndian>()?;
        if !matches!(legacy_file_version, -9..=-7) {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::UnsupportedLegacyFileVersion {
                    version: legacy_file_version,
                },
            });
        }
        let _legacy_ue3_version = reader.read_i32::<LittleEndian>()?;
        let file_version_ue4 = reader.read_i32::<LittleEndian>()?;
        if file_version_ue4 < VER_UE4_NAME_HASHES_SERIALIZED {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::UnsupportedFileVersionUE4 {
                    version: file_version_ue4,
                    minimum: VER_UE4_NAME_HASHES_SERIALIZED,
                },
            });
        }
        let file_version_ue5 = if legacy_file_version <= -8 {
            Some(reader.read_i32::<LittleEndian>()?)
        } else {
            None
        };
        if let Some(v) = file_version_ue5
            && v >= FIRST_UNSUPPORTED_UE5_VERSION
        {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::UnsupportedFileVersionUE5 {
                    version: v,
                    first_unsupported: FIRST_UNSUPPORTED_UE5_VERSION,
                },
            });
        }
        let file_version_licensee_ue4 = reader.read_i32::<LittleEndian>()?;
        let version = AssetVersion {
            legacy_file_version,
            file_version_ue4,
            file_version_ue5,
            file_version_licensee_ue4,
        };

        // Custom versions
        let custom_versions = CustomVersionContainer::read_from(reader, asset_path)?;

        // Header size + folder
        let total_header_size = reader.read_i32::<LittleEndian>()?;
        if total_header_size < 0 {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::NegativeValue {
                    field: AssetWireField::TotalHeaderSize,
                    value: i64::from(total_header_size),
                },
            });
        }
        if total_header_size > MAX_TOTAL_HEADER_SIZE {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::BoundsExceeded {
                    field: AssetWireField::TotalHeaderSize,
                    value: total_header_size as u64,
                    limit: MAX_TOTAL_HEADER_SIZE as u64,
                    unit: BoundsUnit::Bytes,
                },
            });
        }
        let folder_name = read_asset_fstring(reader, asset_path)?;
        let package_flags = reader.read_u32::<LittleEndian>()?;

        // Cooked-only enforcement: uncooked editor assets at
        // file_version_ue4 >= 520 carry an extra FObjectImport.PackageName
        // FName that paksmith's import reader doesn't consume. Reject
        // at the summary boundary before downstream readers mis-align.
        if (package_flags & PKG_FILTER_EDITOR_ONLY) == 0
            && version.ue4_at_least(VER_UE4_NON_OUTER_PACKAGE_IMPORT)
        {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::UncookedAsset {
                    package_flags,
                    file_version_ue4: version.file_version_ue4,
                },
            });
        }

        // Table offsets/counts
        let name_count = reader.read_i32::<LittleEndian>()?;
        let name_offset = reader.read_i32::<LittleEndian>()?;
        // soft_object_paths_count/offset only present when UE5 >= ADD_SOFTOBJECTPATH_LIST (1008).
        // Verified against CUE4Parse's FPackageFileSummary reader (FabianFG/CUE4Parse,
        // CUE4Parse/UE4/Objects/UObject/FPackageFileSummary.cs).
        let (soft_object_paths_count, soft_object_paths_offset) =
            if version.ue5_at_least(VER_UE5_ADD_SOFTOBJECTPATH_LIST) {
                let c = reader.read_i32::<LittleEndian>()?;
                let o = reader.read_i32::<LittleEndian>()?;
                (Some(c), Some(o))
            } else {
                (None, None)
            };
        // LocalizationId is editor-only — present iff UE4 >= 516 AND NOT PKG_FilterEditorOnly.
        // Cooked game assets almost always have the flag set, so this typically resolves to
        // None. Reading it unconditionally — as a prior draft did — corrupts every subsequent
        // offset for cooked-asset inputs.
        let localization_id = if version.ue4_at_least(VER_UE4_ADDED_PACKAGE_SUMMARY_LOCALIZATION_ID)
            && (package_flags & PKG_FILTER_EDITOR_ONLY) == 0
        {
            Some(read_asset_fstring(reader, asset_path)?)
        } else {
            None
        };
        let gatherable_text_data_count = reader.read_i32::<LittleEndian>()?;
        let gatherable_text_data_offset = reader.read_i32::<LittleEndian>()?;
        let export_count = reader.read_i32::<LittleEndian>()?;
        let export_offset = reader.read_i32::<LittleEndian>()?;
        let import_count = reader.read_i32::<LittleEndian>()?;
        let import_offset = reader.read_i32::<LittleEndian>()?;
        let depends_offset = reader.read_i32::<LittleEndian>()?;
        let soft_package_references_count = reader.read_i32::<LittleEndian>()?;
        let soft_package_references_offset = reader.read_i32::<LittleEndian>()?;
        // SearchableNamesOffset only present at UE4 >= ADDED_SEARCHABLE_NAMES (510).
        // Below the gate the field is absent from the wire stream;
        // CUE4Parse defaults the in-memory value to `0` but we surface
        // the absence faithfully as `None` to match the existing
        // optional-on-the-wire pattern (localization_id, persistent_guid).
        let searchable_names_offset = if version.ue4_at_least(VER_UE4_ADDED_SEARCHABLE_NAMES) {
            Some(reader.read_i32::<LittleEndian>()?)
        } else {
            None
        };
        let thumbnail_table_offset = reader.read_i32::<LittleEndian>()?;

        // GUIDs. Per CUE4Parse's FPackageFileSummary reader
        // (FPackageFileSummary.cs HEAD lines 326-343):
        //
        //   if (!PackageFlags.HasFlag(PKG_FilterEditorOnly))
        //   {
        //       if (FileVersionUE >= ADDED_PACKAGE_OWNER (518))
        //           PersistentGuid = Ar.Read<FGuid>();
        //       if (FileVersionUE >= ADDED_PACKAGE_OWNER &&
        //           FileVersionUE < NON_OUTER_PACKAGE_IMPORT (520))
        //           ownerPersistentGuid = Ar.Read<FGuid>();
        //   }
        //
        // Both GUIDs are skipped entirely on cooked-game input (the
        // common case for paksmith); `OwnerPersistentGuid` is further
        // restricted to a narrow uncooked window.
        let guid = FGuid::read_from(reader)?;
        let editor_only_section = (package_flags & PKG_FILTER_EDITOR_ONLY) == 0;
        let persistent_guid =
            if editor_only_section && version.ue4_at_least(VER_UE4_ADDED_PACKAGE_OWNER) {
                Some(FGuid::read_from(reader)?)
            } else {
                None
            };
        let owner_persistent_guid = if editor_only_section
            && version.ue4_at_least(VER_UE4_ADDED_PACKAGE_OWNER)
            && !version.ue4_at_least(VER_UE4_NON_OUTER_PACKAGE_IMPORT)
        {
            Some(FGuid::read_from(reader)?)
        } else {
            None
        };

        // Generations (count + 8 bytes per record; we discard the rows —
        // see the "lossy round-trip" note on this method's doc-comment).
        let generation_count = reader.read_i32::<LittleEndian>()?;
        if generation_count < 0 {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::NegativeValue {
                    field: AssetWireField::GenerationCount,
                    value: i64::from(generation_count),
                },
            });
        }
        if generation_count > MAX_GENERATION_COUNT {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::BoundsExceeded {
                    field: AssetWireField::GenerationCount,
                    value: generation_count as u64,
                    limit: MAX_GENERATION_COUNT as u64,
                    unit: BoundsUnit::Items,
                },
            });
        }
        for _ in 0..generation_count {
            let _ = reader.read_i32::<LittleEndian>()?;
            let _ = reader.read_i32::<LittleEndian>()?;
        }

        // Engine versions
        let saved_by_engine_version = EngineVersion::read_from(reader, asset_path)?;
        let compatible_with_engine_version = EngineVersion::read_from(reader, asset_path)?;

        // Compression — must be zero+empty (Phase 2a rejects in-summary compression).
        let compression_flags = reader.read_u32::<LittleEndian>()?;
        if compression_flags != 0 {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::UnsupportedCompressionInSummary {
                    site: crate::error::CompressionInSummarySite::CompressionFlags,
                    observed: i64::from(compression_flags),
                },
            });
        }
        let compressed_chunks_count = reader.read_i32::<LittleEndian>()?;
        if compressed_chunks_count != 0 {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::UnsupportedCompressionInSummary {
                    site: crate::error::CompressionInSummarySite::CompressedChunksCount,
                    observed: i64::from(compressed_chunks_count),
                },
            });
        }

        let package_source = reader.read_u32::<LittleEndian>()?;

        // additional_packages_to_cook: i32 count + N FStrings — discard.
        let additional_count = reader.read_i32::<LittleEndian>()?;
        if additional_count < 0 {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::NegativeValue {
                    field: AssetWireField::AdditionalPackagesToCookCount,
                    value: i64::from(additional_count),
                },
            });
        }
        if additional_count > MAX_ADDITIONAL_PACKAGES_TO_COOK_COUNT {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::BoundsExceeded {
                    field: AssetWireField::AdditionalPackagesToCookCount,
                    value: additional_count as u64,
                    limit: MAX_ADDITIONAL_PACKAGES_TO_COOK_COUNT as u64,
                    unit: BoundsUnit::Items,
                },
            });
        }
        for _ in 0..additional_count {
            let _ = read_asset_fstring(reader, asset_path)?;
        }

        let asset_registry_data_offset = reader.read_i32::<LittleEndian>()?;
        let bulk_data_start_offset = reader.read_i64::<LittleEndian>()?;
        let world_tile_info_data_offset = reader.read_i32::<LittleEndian>()?;

        // chunk_ids: discard
        let chunk_id_count = reader.read_i32::<LittleEndian>()?;
        if chunk_id_count < 0 {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::NegativeValue {
                    field: AssetWireField::ChunkIdCount,
                    value: i64::from(chunk_id_count),
                },
            });
        }
        if chunk_id_count > MAX_CHUNK_ID_COUNT {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::BoundsExceeded {
                    field: AssetWireField::ChunkIdCount,
                    value: chunk_id_count as u64,
                    limit: MAX_CHUNK_ID_COUNT as u64,
                    unit: BoundsUnit::Items,
                },
            });
        }
        for _ in 0..chunk_id_count {
            let _ = reader.read_i32::<LittleEndian>()?;
        }

        // PreloadDependencyCount/Offset only present at UE4 >=
        // PRELOAD_DEPENDENCIES_IN_COOKED_EXPORTS (507). Below the gate,
        // both i32s are absent from the wire stream — CUE4Parse defaults
        // them to `-1` / `0` in-memory; paksmith surfaces the absence as
        // `None` to match the existing optional-on-the-wire pattern.
        let (preload_dependency_count, preload_dependency_offset) =
            if version.ue4_at_least(VER_UE4_PRELOAD_DEPENDENCIES_IN_COOKED_EXPORTS) {
                let c = reader.read_i32::<LittleEndian>()?;
                let o = reader.read_i32::<LittleEndian>()?;
                (Some(c), Some(o))
            } else {
                (None, None)
            };

        // UE5-only trailing fields, each gated on its own version constant.
        // Verified against CUE4Parse FPackageFileSummary reader. Cross-
        // validation via the unreal_asset oracle is deferred to Task 12
        // (fixture-gen). The version constants are:
        //   - NAMES_REFERENCED_FROM_EXPORT_DATA = 1001 (NOT 1009 as a prior
        //     draft asserted; 1009 is DATA_RESOURCES and unrelated)
        //   - PAYLOAD_TOC = 1002
        //   - DATA_RESOURCES = 1009
        let names_referenced_from_export_data_count =
            if version.ue5_at_least(VER_UE5_NAMES_REFERENCED_FROM_EXPORT_DATA) {
                Some(reader.read_i32::<LittleEndian>()?)
            } else {
                None
            };
        let payload_toc_offset = if version.ue5_at_least(VER_UE5_PAYLOAD_TOC) {
            Some(reader.read_i64::<LittleEndian>()?)
        } else {
            None
        };
        let data_resource_offset = if version.ue5_at_least(VER_UE5_DATA_RESOURCES) {
            Some(reader.read_i32::<LittleEndian>()?)
        } else {
            None
        };

        Ok(Self {
            version,
            custom_versions,
            total_header_size,
            folder_name,
            package_flags,
            name_count,
            name_offset,
            soft_object_paths_count,
            soft_object_paths_offset,
            localization_id,
            gatherable_text_data_count,
            gatherable_text_data_offset,
            export_count,
            export_offset,
            import_count,
            import_offset,
            depends_offset,
            soft_package_references_count,
            soft_package_references_offset,
            searchable_names_offset,
            thumbnail_table_offset,
            guid,
            persistent_guid,
            owner_persistent_guid,
            generation_count,
            saved_by_engine_version,
            compatible_with_engine_version,
            package_source,
            asset_registry_data_offset,
            bulk_data_start_offset,
            world_tile_info_data_offset,
            preload_dependency_count,
            preload_dependency_offset,
            names_referenced_from_export_data_count,
            payload_toc_offset,
            data_resource_offset,
        })
    }

    /// Write — matches `read_from` field-for-field. Test- and
    /// fixture-gen-only via the `__test_utils` feature; release builds
    /// drop this method.
    ///
    /// # Errors
    /// Returns [`std::io::Error`] if writes fail or if any embedded
    /// FString length exceeds `i32::MAX`.
    ///
    /// # Panics
    /// Panics if `version` satisfies a gate-fire-with-None mismatch on
    /// any of:
    /// - `VER_UE4_ADDED_SEARCHABLE_NAMES` (UE4 ≥ 510) with
    ///   `searchable_names_offset == None`
    /// - `VER_UE4_PRELOAD_DEPENDENCIES_IN_COOKED_EXPORTS` (UE4 ≥ 507)
    ///   with `preload_dependency_count` or `_offset == None`
    ///
    /// `read_from` always populates these fields under their gate, so
    /// a `None` at gate-fire is a hand-built-struct programmer error.
    /// Mirrors the analogous `ObjectExport::write_to` precedent for
    /// `script_serialization_{start,end}_offset` at UE5 ≥ 1010.
    #[cfg(any(test, feature = "__test_utils"))]
    pub fn write_to<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_u32::<LittleEndian>(PACKAGE_FILE_TAG)?;
        writer.write_i32::<LittleEndian>(self.version.legacy_file_version)?;
        writer.write_i32::<LittleEndian>(-1)?; // legacy_ue3_version
        writer.write_i32::<LittleEndian>(self.version.file_version_ue4)?;
        if let Some(v) = self.version.file_version_ue5 {
            writer.write_i32::<LittleEndian>(v)?;
        }
        writer.write_i32::<LittleEndian>(self.version.file_version_licensee_ue4)?;
        self.custom_versions.write_to(writer)?;
        writer.write_i32::<LittleEndian>(self.total_header_size)?;
        write_asset_fstring(writer, &self.folder_name)?;
        writer.write_u32::<LittleEndian>(self.package_flags)?;
        writer.write_i32::<LittleEndian>(self.name_count)?;
        writer.write_i32::<LittleEndian>(self.name_offset)?;
        if let Some(c) = self.soft_object_paths_count {
            writer.write_i32::<LittleEndian>(c)?;
            writer.write_i32::<LittleEndian>(self.soft_object_paths_offset.unwrap_or(0))?;
        }
        if let Some(ref s) = self.localization_id {
            write_asset_fstring(writer, s)?;
        }
        writer.write_i32::<LittleEndian>(self.gatherable_text_data_count)?;
        writer.write_i32::<LittleEndian>(self.gatherable_text_data_offset)?;
        writer.write_i32::<LittleEndian>(self.export_count)?;
        writer.write_i32::<LittleEndian>(self.export_offset)?;
        writer.write_i32::<LittleEndian>(self.import_count)?;
        writer.write_i32::<LittleEndian>(self.import_offset)?;
        writer.write_i32::<LittleEndian>(self.depends_offset)?;
        writer.write_i32::<LittleEndian>(self.soft_package_references_count)?;
        writer.write_i32::<LittleEndian>(self.soft_package_references_offset)?;
        // SearchableNamesOffset is gated on UE4 >= ADDED_SEARCHABLE_NAMES
        // (510). Emit iff Some(_); panic on misuse where the gate fires
        // but the field is None (mirrors the script_serialization_offset
        // precedent from PR #224's 146f3cc — gate disagreement between
        // writer state and version is a programming error, not a runtime
        // condition the writer should silently paper over).
        if self.version.ue4_at_least(VER_UE4_ADDED_SEARCHABLE_NAMES) {
            let v = self.searchable_names_offset.expect(
                "searchable_names_offset must be Some(_) at UE4 >= ADDED_SEARCHABLE_NAMES (510); \
                 write_to caller passed None at gate-fire",
            );
            writer.write_i32::<LittleEndian>(v)?;
        }
        writer.write_i32::<LittleEndian>(self.thumbnail_table_offset)?;
        self.guid.write_to(writer)?;
        // `persistent_guid` and `owner_persistent_guid` are editor-only
        // and version-gated — see the field doc-comments for the
        // CUE4Parse reference. write_to honors the Option<FGuid> shape:
        // emit iff `Some(_)`. The reader's gate is the authoritative
        // contract; tests construct payloads matching both sides.
        if let Some(ref g) = self.persistent_guid {
            g.write_to(writer)?;
        }
        if let Some(ref g) = self.owner_persistent_guid {
            g.write_to(writer)?;
        }
        writer.write_i32::<LittleEndian>(self.generation_count)?;
        for _ in 0..self.generation_count.max(0) {
            writer.write_i32::<LittleEndian>(self.export_count)?;
            writer.write_i32::<LittleEndian>(self.name_count)?;
        }
        self.saved_by_engine_version.write_to(writer)?;
        self.compatible_with_engine_version.write_to(writer)?;
        writer.write_u32::<LittleEndian>(0)?; // compression_flags
        writer.write_i32::<LittleEndian>(0)?; // compressed_chunks_count
        writer.write_u32::<LittleEndian>(self.package_source)?;
        writer.write_i32::<LittleEndian>(0)?; // additional_packages_to_cook count
        writer.write_i32::<LittleEndian>(self.asset_registry_data_offset)?;
        writer.write_i64::<LittleEndian>(self.bulk_data_start_offset)?;
        writer.write_i32::<LittleEndian>(self.world_tile_info_data_offset)?;
        writer.write_i32::<LittleEndian>(0)?; // chunk_id_count
        // PreloadDependencyCount/Offset are gated on UE4 >=
        // PRELOAD_DEPENDENCIES_IN_COOKED_EXPORTS (507). Emit iff
        // Some(_); panic on misuse where the gate fires but either
        // field is None (mirrors the searchable_names_offset and
        // script_serialization_offset precedents).
        if self
            .version
            .ue4_at_least(VER_UE4_PRELOAD_DEPENDENCIES_IN_COOKED_EXPORTS)
        {
            let c = self.preload_dependency_count.expect(
                "preload_dependency_count must be Some(_) at UE4 >= \
                 PRELOAD_DEPENDENCIES_IN_COOKED_EXPORTS (507); write_to caller \
                 passed None at gate-fire",
            );
            let o = self.preload_dependency_offset.expect(
                "preload_dependency_offset must be Some(_) at UE4 >= \
                 PRELOAD_DEPENDENCIES_IN_COOKED_EXPORTS (507); write_to caller \
                 passed None at gate-fire",
            );
            writer.write_i32::<LittleEndian>(c)?;
            writer.write_i32::<LittleEndian>(o)?;
        }
        if let Some(c) = self.names_referenced_from_export_data_count {
            writer.write_i32::<LittleEndian>(c)?;
        }
        if let Some(o) = self.payload_toc_offset {
            writer.write_i64::<LittleEndian>(o)?;
        }
        if let Some(o) = self.data_resource_offset {
            writer.write_i32::<LittleEndian>(o)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn minimal_ue4_27_summary() -> PackageSummary {
        PackageSummary {
            version: AssetVersion {
                legacy_file_version: -7,
                file_version_ue4: 522,
                file_version_ue5: None,
                file_version_licensee_ue4: 0,
            },
            custom_versions: CustomVersionContainer::default(),
            total_header_size: 0,
            folder_name: "None".to_string(),
            // PKG_FilterEditorOnly: matches cooked-game inputs and (per
            // the UE4 >= 516 + editor-only gate) suppresses the optional
            // localization_id FString — keeping the fixture symmetric
            // between `read_from` and `write_to` (write_to emits the
            // string only when `Some`, so `None` here requires the flag).
            package_flags: 0x8000_0000,
            name_count: 0,
            name_offset: 0,
            soft_object_paths_count: None,
            soft_object_paths_offset: None,
            localization_id: None,
            gatherable_text_data_count: 0,
            gatherable_text_data_offset: 0,
            export_count: 0,
            export_offset: 0,
            import_count: 0,
            import_offset: 0,
            depends_offset: 0,
            soft_package_references_count: 0,
            soft_package_references_offset: 0,
            // UE 4.27 (= UE4 522) is past ADDED_SEARCHABLE_NAMES (510),
            // so the field is present on the wire. Below the gate (e.g.
            // a UE4 504 fixture), this must be None.
            searchable_names_offset: Some(0),
            thumbnail_table_offset: 0,
            guid: FGuid::from_bytes([0u8; 16]),
            // PKG_FilterEditorOnly is set above, so `persistent_guid`
            // and `owner_persistent_guid` are both suppressed from the
            // wire stream — same symmetry as `localization_id` (see
            // the field doc-comments).
            persistent_guid: None,
            owner_persistent_guid: None,
            generation_count: 0,
            saved_by_engine_version: EngineVersion {
                major: 4,
                minor: 27,
                patch: 2,
                changelist: 0,
                branch: "++UE4+Release-4.27".to_string(),
            },
            compatible_with_engine_version: EngineVersion {
                major: 4,
                minor: 27,
                patch: 0,
                changelist: 0,
                branch: "++UE4+Release-4.27".to_string(),
            },
            package_source: 0,
            asset_registry_data_offset: 0,
            bulk_data_start_offset: 0,
            world_tile_info_data_offset: 0,
            // UE 4.27 (= UE4 522) is past
            // PRELOAD_DEPENDENCIES_IN_COOKED_EXPORTS (507), so both
            // i32s are present on the wire. Below the gate they must
            // be None.
            preload_dependency_count: Some(0),
            preload_dependency_offset: Some(0),
            names_referenced_from_export_data_count: None,
            payload_toc_offset: None,
            data_resource_offset: None,
        }
    }

    #[test]
    fn ue4_27_minimal_round_trip() {
        let s = minimal_ue4_27_summary();
        let mut buf = Vec::new();
        s.write_to(&mut buf).unwrap();
        let parsed = PackageSummary::read_from(&mut Cursor::new(&buf), "x.uasset").unwrap();
        assert_eq!(parsed, s);
    }

    #[test]
    fn ue5_1_minimal_round_trip() {
        let mut s = minimal_ue4_27_summary();
        s.version.legacy_file_version = -8;
        s.version.file_version_ue5 = Some(1009);
        // UE5 1008+ adds SoftObjectPath list; UE5 1001+ adds
        // names_referenced_from_export_data_count; 1002+ adds
        // payload_toc_offset; 1009+ adds data_resource_offset.
        s.soft_object_paths_count = Some(0);
        s.soft_object_paths_offset = Some(0);
        s.names_referenced_from_export_data_count = Some(0);
        s.payload_toc_offset = Some(0);
        s.data_resource_offset = Some(0);
        let mut buf = Vec::new();
        s.write_to(&mut buf).unwrap();
        let parsed = PackageSummary::read_from(&mut Cursor::new(&buf), "x.uasset").unwrap();
        assert_eq!(parsed, s);
    }

    /// `legacy_file_version = -9` is the UE 5.4+ marker. Within
    /// paksmith's accepted UE5 ceiling (< 1011), -9 introduces no
    /// new wire fields beyond what -8 emits (PACKAGE_SAVED_HASH is at
    /// 1015, above the ceiling). Round-trip must accept the value.
    #[test]
    fn ue5_legacy_minus_nine_round_trip() {
        let mut s = minimal_ue4_27_summary();
        s.version.legacy_file_version = -9;
        s.version.file_version_ue5 = Some(1010); // Phase 2a max
        s.soft_object_paths_count = Some(0);
        s.soft_object_paths_offset = Some(0);
        s.names_referenced_from_export_data_count = Some(0);
        s.payload_toc_offset = Some(0);
        s.data_resource_offset = Some(0);
        let mut buf = Vec::new();
        s.write_to(&mut buf).unwrap();
        let parsed = PackageSummary::read_from(&mut Cursor::new(&buf), "x.uasset").unwrap();
        assert_eq!(parsed.version.legacy_file_version, -9);
        assert_eq!(parsed, s);
    }

    /// Exercises the `Some(persistent_guid) + Some(owner_persistent_guid)`
    /// branch: `PKG_FilterEditorOnly` clear AND `file_version_ue4 ∈
    /// [ADDED_PACKAGE_OWNER (518), NON_OUTER_PACKAGE_IMPORT (520))`,
    /// which avoids the uncooked-asset rejection. UE4 519 sits inside
    /// that window. Per CUE4Parse, both GUIDs are emitted back-to-back
    /// in this range. The other gated optional (`localization_id`)
    /// shares the same editor-only gate, so it must also be `Some(...)`
    /// for write/read symmetry.
    #[test]
    fn persistent_guid_and_owner_round_trip_in_addition_window() {
        let mut s = minimal_ue4_27_summary();
        s.version.file_version_ue4 = 519; // ∈ [518, 520)
        s.package_flags = 0; // PKG_FilterEditorOnly clear
        s.localization_id = Some(String::new()); // gated identically — required for write/read symmetry
        s.persistent_guid = Some(FGuid::from_bytes([0xBB; 16]));
        s.owner_persistent_guid = Some(FGuid::from_bytes([0xCC; 16]));
        let mut buf = Vec::new();
        s.write_to(&mut buf).unwrap();
        let parsed = PackageSummary::read_from(&mut Cursor::new(&buf), "x.uasset").unwrap();
        assert_eq!(parsed.persistent_guid, Some(FGuid::from_bytes([0xBB; 16])));
        assert_eq!(
            parsed.owner_persistent_guid,
            Some(FGuid::from_bytes([0xCC; 16]))
        );
        assert_eq!(parsed, s);
    }

    /// Exercises the `Some(persistent_guid) + None(owner_persistent_guid)`
    /// branch: at UE4 < ADDED_PACKAGE_OWNER (518), neither GUID is on
    /// the wire even with PKG_FilterEditorOnly clear. Tests the lower
    /// boundary of the new gate.
    #[test]
    fn persistent_guid_absent_below_added_package_owner() {
        let mut s = minimal_ue4_27_summary();
        s.version.file_version_ue4 = 517; // < ADDED_PACKAGE_OWNER (518)
        s.package_flags = 0; // PKG_FilterEditorOnly clear
        s.localization_id = Some(String::new());
        s.persistent_guid = None; // absent per CUE4Parse gate
        s.owner_persistent_guid = None;
        let mut buf = Vec::new();
        s.write_to(&mut buf).unwrap();
        let parsed = PackageSummary::read_from(&mut Cursor::new(&buf), "x.uasset").unwrap();
        assert_eq!(parsed.persistent_guid, None);
        assert_eq!(parsed.owner_persistent_guid, None);
        assert_eq!(parsed, s);
    }

    #[test]
    fn rejects_wrong_magic() {
        let mut buf = vec![];
        buf.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        let err = PackageSummary::read_from(&mut Cursor::new(&buf), "x.uasset").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::InvalidMagic {
                    observed: 0xDEAD_BEEF,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn rejects_unsupported_legacy_version() {
        let mut buf = vec![];
        buf.extend_from_slice(&PACKAGE_FILE_TAG.to_le_bytes());
        buf.extend_from_slice(&(-6i32).to_le_bytes());
        let err = PackageSummary::read_from(&mut Cursor::new(&buf), "x.uasset").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::UnsupportedLegacyFileVersion { version: -6 },
                ..
            }
        ));
    }

    /// Upper boundary of the accepted legacy window. `-10` is unsigned
    /// in UE's writer at the time of writing; paksmith refuses to
    /// parse it rather than guess at a divergent layout.
    #[test]
    fn rejects_legacy_minus_ten() {
        let mut buf = vec![];
        buf.extend_from_slice(&PACKAGE_FILE_TAG.to_le_bytes());
        buf.extend_from_slice(&(-10i32).to_le_bytes());
        let err = PackageSummary::read_from(&mut Cursor::new(&buf), "x.uasset").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::UnsupportedLegacyFileVersion { version: -10 },
                ..
            }
        ));
    }

    #[test]
    fn rejects_too_old_ue4_version() {
        let mut buf = vec![];
        buf.extend_from_slice(&PACKAGE_FILE_TAG.to_le_bytes());
        buf.extend_from_slice(&(-7i32).to_le_bytes()); // legacy
        buf.extend_from_slice(&(-1i32).to_le_bytes()); // ue3
        buf.extend_from_slice(&(503i32).to_le_bytes()); // file_version_ue4 < 504
        let err = PackageSummary::read_from(&mut Cursor::new(&buf), "x.uasset").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::UnsupportedFileVersionUE4 { version: 503, .. },
                ..
            }
        ));
    }

    #[test]
    fn rejects_ue5_above_ceiling() {
        let mut buf = vec![];
        buf.extend_from_slice(&PACKAGE_FILE_TAG.to_le_bytes());
        buf.extend_from_slice(&(-8i32).to_le_bytes());
        buf.extend_from_slice(&(-1i32).to_le_bytes());
        buf.extend_from_slice(&(522i32).to_le_bytes()); // ue4
        buf.extend_from_slice(&(1011i32).to_le_bytes()); // ue5 — first unsupported
        let err = PackageSummary::read_from(&mut Cursor::new(&buf), "x.uasset").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::UnsupportedFileVersionUE5 { version: 1011, .. },
                ..
            }
        ));
    }

    /// Cooked-only enforcement (Fix 1): an uncooked asset
    /// (PKG_FilterEditorOnly clear in package_flags) at
    /// file_version_ue4 >= VER_UE4_NON_OUTER_PACKAGE_IMPORT (520) must
    /// be rejected at the summary boundary, before the ImportTable
    /// reader silently mis-aligns by 8 bytes per record.
    #[test]
    fn rejects_uncooked_asset() {
        // Build a minimal summary buffer through the package_flags
        // field with: legacy=-7, ue4=522 (past the cook gate),
        // package_flags=0 (PKG_FilterEditorOnly clear). Should reject.
        let mut buf = vec![];
        buf.extend_from_slice(&PACKAGE_FILE_TAG.to_le_bytes());
        buf.extend_from_slice(&(-7i32).to_le_bytes()); // legacy
        buf.extend_from_slice(&(-1i32).to_le_bytes()); // ue3
        buf.extend_from_slice(&(522i32).to_le_bytes()); // ue4
        buf.extend_from_slice(&(0i32).to_le_bytes()); // licensee
        buf.extend_from_slice(&(0i32).to_le_bytes()); // custom-version count
        buf.extend_from_slice(&(0i32).to_le_bytes()); // total_header_size
        // folder_name FString: len=1, single null byte (empty string).
        buf.extend_from_slice(&(1i32).to_le_bytes());
        buf.extend_from_slice(&[0u8]);
        buf.extend_from_slice(&(0u32).to_le_bytes()); // package_flags = 0 (uncooked!)
        let err = PackageSummary::read_from(&mut Cursor::new(&buf), "x.uasset").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::UncookedAsset {
                    package_flags: 0,
                    file_version_ue4: 522,
                },
                ..
            }
        ));
    }

    /// Hand-craft a summary prefix that reaches the `total_header_size`
    /// check with an over-cap value. The compression-flag and
    /// compressed-chunks-count rejection paths are exercised at the
    /// integration-test layer (Task 15); byte-crafting that deep into
    /// the summary at the unit-test layer is fragile.
    #[test]
    fn rejects_total_header_size_over_cap() {
        let mut buf = vec![];
        buf.extend_from_slice(&PACKAGE_FILE_TAG.to_le_bytes());
        buf.extend_from_slice(&(-7i32).to_le_bytes()); // legacy
        buf.extend_from_slice(&(-1i32).to_le_bytes()); // ue3
        buf.extend_from_slice(&(522i32).to_le_bytes()); // ue4
        buf.extend_from_slice(&(0i32).to_le_bytes()); // licensee
        buf.extend_from_slice(&(0i32).to_le_bytes()); // custom-version count
        buf.extend_from_slice(&(MAX_TOTAL_HEADER_SIZE + 1).to_le_bytes()); // over cap
        let err = PackageSummary::read_from(&mut Cursor::new(&buf), "x.uasset").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::BoundsExceeded {
                    field: AssetWireField::TotalHeaderSize,
                    unit: BoundsUnit::Bytes,
                    ..
                },
                ..
            }
        ));
    }

    /// Parallel coverage for the sign-violation arm of total_header_size.
    /// Split from the BoundsExceeded path in Fix 4 to surface an
    /// operator-meaningful value on negative input rather than a
    /// misleading `value: 0`.
    #[test]
    fn rejects_total_header_size_negative() {
        let mut buf = vec![];
        buf.extend_from_slice(&PACKAGE_FILE_TAG.to_le_bytes());
        buf.extend_from_slice(&(-7i32).to_le_bytes()); // legacy
        buf.extend_from_slice(&(-1i32).to_le_bytes()); // ue3
        buf.extend_from_slice(&(522i32).to_le_bytes()); // ue4
        buf.extend_from_slice(&(0i32).to_le_bytes()); // licensee
        buf.extend_from_slice(&(0i32).to_le_bytes()); // custom-version count
        buf.extend_from_slice(&(-1i32).to_le_bytes()); // total_header_size negative
        let err = PackageSummary::read_from(&mut Cursor::new(&buf), "x.uasset").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::NegativeValue {
                    field: AssetWireField::TotalHeaderSize,
                    value: -1,
                },
                ..
            }
        ));
    }

    /// Pin the JSON shape's key fields. Full-shape pin is deferred to
    /// the Task 14 integration tests; here we spot-check that the
    /// downstream `inspect` consumer's keys are spelled the way they
    /// expect (snake_case field names, string-rendered FGuid/
    /// EngineVersion).
    #[test]
    fn serialize_includes_key_fields() {
        let s = minimal_ue4_27_summary();
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains(r#""folder_name":"None""#), "got: {json}");
        // PKG_FilterEditorOnly = 0x80000000 = 2147483648 (decimal).
        assert!(
            json.contains(r#""package_flags":2147483648"#),
            "got: {json}"
        );
        assert!(
            json.contains(r#""guid":"00000000-0000-0000-0000-000000000000""#),
            "got: {json}"
        );
        assert!(
            json.contains(r#""saved_by_engine_version":"4.27.2-0+++UE4+Release-4.27""#),
            "got: {json}"
        );
        assert!(json.contains(r#""file_version_ue4":522"#), "got: {json}");
    }

    /// Hand-craft a minimum-viable UE4 cooked `FPackageFileSummary`
    /// byte stream at the requested `file_version_ue4`, mirroring
    /// CUE4Parse's `FPackageFileSummary.cs` wire order. This is a
    /// **parallel writer** to paksmith's `write_to` — every byte is
    /// emitted by this helper directly, NOT through `PackageSummary`'s
    /// own serializer. The hand-crafted bytes are the load-bearing
    /// reference; if paksmith's reader is buggy at one of the gates
    /// being exercised, the assertion comparing structural fields
    /// will fail.
    ///
    /// Gates exercised:
    /// - `VER_UE4_PRELOAD_DEPENDENCIES_IN_COOKED_EXPORTS = 507`
    /// - `VER_UE4_ADDED_SEARCHABLE_NAMES = 510`
    ///
    /// Other gates relevant to a cooked legacy=-7 asset (SoftPackage,
    /// GatherableTextData, EngineVersionObject, etc.) all fire at
    /// versions well below 504 (paksmith's floor) — see the matching
    /// commit message for the verification trace against CUE4Parse's
    /// `EUnrealEngineObjectUE4Version` enum.
    ///
    /// All zero counts (custom-versions, generations, additional-
    /// packages-to-cook, chunk-ids) keep the buffer minimal.
    /// `PKG_FilterEditorOnly` is set so the editor-only branches
    /// (LocalizationId, PersistentGuid, OwnerPersistentGuid) are
    /// suppressed at every UE4 version.
    fn craft_minimal_ue4_summary_bytes(file_version_ue4: i32) -> Vec<u8> {
        use byteorder::WriteBytesExt;
        const PKG_FILTER_EDITOR_ONLY: u32 = 0x8000_0000;
        let mut b = Vec::<u8>::new();
        // Magic + version block (legacy=-7 → no UE5 field).
        b.write_u32::<LittleEndian>(PACKAGE_FILE_TAG).unwrap();
        b.write_i32::<LittleEndian>(-7).unwrap(); // legacy_file_version
        b.write_i32::<LittleEndian>(-1).unwrap(); // legacy_ue3_version (CUE4Parse: read iff legacy != -4)
        b.write_i32::<LittleEndian>(file_version_ue4).unwrap();
        b.write_i32::<LittleEndian>(0).unwrap(); // file_version_licensee_ue4
        // CustomVersionContainer: i32 count = 0.
        b.write_i32::<LittleEndian>(0).unwrap();
        // total_header_size (zero is in-range; we don't gate on it
        // being self-consistent with the byte layout here).
        b.write_i32::<LittleEndian>(0).unwrap();
        // folder_name FString: "None\0" → len = 5.
        let folder = b"None\0";
        b.write_i32::<LittleEndian>(folder.len() as i32).unwrap();
        b.extend_from_slice(folder);
        // package_flags = PKG_FilterEditorOnly (cooked).
        b.write_u32::<LittleEndian>(PKG_FILTER_EDITOR_ONLY).unwrap();
        // name_count, name_offset.
        b.write_i32::<LittleEndian>(0).unwrap();
        b.write_i32::<LittleEndian>(0).unwrap();
        // SoftObjectPaths{Count,Offset}: UE5>=1008 only — skip.
        // LocalizationId: UE4>=516 AND !filtereditoronly — skip (cooked).
        // GatherableTextData{Count,Offset}: always present at >=504.
        b.write_i32::<LittleEndian>(0).unwrap(); // gatherable_text_data_count
        b.write_i32::<LittleEndian>(0).unwrap(); // gatherable_text_data_offset
        // export/import counts + offsets.
        b.write_i32::<LittleEndian>(0).unwrap(); // export_count
        b.write_i32::<LittleEndian>(0).unwrap(); // export_offset
        b.write_i32::<LittleEndian>(0).unwrap(); // import_count
        b.write_i32::<LittleEndian>(0).unwrap(); // import_offset
        // CellExport/Import + MetaDataOffset: UE5 only — skip.
        b.write_i32::<LittleEndian>(0).unwrap(); // depends_offset
        // SoftPackageReferences{Count,Offset}: ADD_STRING_ASSET_REFERENCES_MAP = 384,
        // always present at our >=504 floor.
        b.write_i32::<LittleEndian>(0).unwrap();
        b.write_i32::<LittleEndian>(0).unwrap();
        // SearchableNamesOffset: GATED on UE4 >= 510.
        if file_version_ue4 >= 510 {
            b.write_i32::<LittleEndian>(0).unwrap();
        }
        b.write_i32::<LittleEndian>(0).unwrap(); // thumbnail_table_offset
        // ImportTypeHierarchies: UE5 only — skip.
        // FGuid (16 bytes), all zero. PACKAGE_SAVED_HASH (UE5 1016) not
        // reached, so the legacy FGuid form is used.
        b.extend_from_slice(&[0u8; 16]);
        // PersistentGuid / OwnerPersistentGuid: !filtereditoronly +
        // version gates — skip (cooked).
        // Generations: i32 count = 0.
        b.write_i32::<LittleEndian>(0).unwrap();
        // EngineVersion (saved + compatible): u16 major,minor,patch +
        // u32 changelist + FString branch. Use 4.x.0.0 with empty
        // branch (FString len = 1 for the null terminator alone).
        for _ in 0..2 {
            b.write_u16::<LittleEndian>(4).unwrap(); // major
            b.write_u16::<LittleEndian>(0).unwrap(); // minor
            b.write_u16::<LittleEndian>(0).unwrap(); // patch
            b.write_u32::<LittleEndian>(0).unwrap(); // changelist
            b.write_i32::<LittleEndian>(1).unwrap(); // FString len (just the null)
            b.write_u8(0).unwrap();
        }
        // CompressionFlags u32 = 0, CompressedChunks count i32 = 0.
        b.write_u32::<LittleEndian>(0).unwrap();
        b.write_i32::<LittleEndian>(0).unwrap();
        // PackageSource u32 = 0.
        b.write_u32::<LittleEndian>(0).unwrap();
        // AdditionalPackagesToCook: i32 count = 0.
        b.write_i32::<LittleEndian>(0).unwrap();
        // NumTextureAllocations: legacy > -7 only (we use -7) — skip.
        // AssetRegistryDataOffset, BulkDataStartOffset (i64),
        // WorldTileInfoDataOffset — all always present at our floor.
        b.write_i32::<LittleEndian>(0).unwrap();
        b.write_i64::<LittleEndian>(0).unwrap();
        b.write_i32::<LittleEndian>(0).unwrap();
        // ChunkIds: i32 count = 0.
        b.write_i32::<LittleEndian>(0).unwrap();
        // PreloadDependency{Count,Offset}: GATED on UE4 >= 507.
        if file_version_ue4 >= 507 {
            b.write_i32::<LittleEndian>(0).unwrap();
            b.write_i32::<LittleEndian>(0).unwrap();
        }
        // UE5-only trailers: skipped (no UE5 at legacy=-7).
        b
    }

    /// Hand-crafted UE4 504 boundary test. Both gates (507 + 510)
    /// **not yet fired**: searchable_names_offset, preload_dependency_*
    /// all absent from the wire stream. Parses successfully and the
    /// gated fields surface as `None`. Independent of paksmith's
    /// `write_to` — fails if Bug A or Bug B regresses.
    #[test]
    fn ue4_504_summary_byte_level_parses_correctly() {
        let bytes = craft_minimal_ue4_summary_bytes(504);
        let parsed = PackageSummary::read_from(&mut Cursor::new(&bytes), "x.uasset").unwrap();
        assert_eq!(parsed.version.file_version_ue4, 504);
        assert_eq!(
            parsed.searchable_names_offset, None,
            "UE4 504 < ADDED_SEARCHABLE_NAMES (510): field must be absent"
        );
        assert_eq!(
            parsed.preload_dependency_count, None,
            "UE4 504 < PRELOAD_DEPENDENCIES_IN_COOKED_EXPORTS (507): field must be absent"
        );
        assert_eq!(parsed.preload_dependency_offset, None);
        // Sanity: a structural field below the gate parses normally.
        assert_eq!(parsed.folder_name, "None");
        assert_eq!(parsed.package_flags, 0x8000_0000);
    }

    /// Hand-crafted UE4 506 boundary test — one tick below the
    /// preload-deps gate. Same assertion shape as the 504 case; pins
    /// the exact gate boundary at 507 (not 506).
    #[test]
    fn ue4_506_summary_byte_level_no_preload_no_searchable() {
        let bytes = craft_minimal_ue4_summary_bytes(506);
        let parsed = PackageSummary::read_from(&mut Cursor::new(&bytes), "x.uasset").unwrap();
        assert_eq!(parsed.version.file_version_ue4, 506);
        assert_eq!(parsed.searchable_names_offset, None);
        assert_eq!(parsed.preload_dependency_count, None);
        assert_eq!(parsed.preload_dependency_offset, None);
    }

    /// Hand-crafted UE4 507 boundary test. preload-deps gate
    /// **fires**, searchable-names gate **does not** (still at 510).
    /// Tests the lower edge of the preload-deps gate independently.
    #[test]
    fn ue4_507_summary_has_preload_deps_no_searchable_names() {
        let bytes = craft_minimal_ue4_summary_bytes(507);
        let parsed = PackageSummary::read_from(&mut Cursor::new(&bytes), "x.uasset").unwrap();
        assert_eq!(parsed.version.file_version_ue4, 507);
        assert_eq!(
            parsed.searchable_names_offset, None,
            "UE4 507 < ADDED_SEARCHABLE_NAMES (510): field must be absent"
        );
        assert_eq!(
            parsed.preload_dependency_count,
            Some(0),
            "UE4 507 >= PRELOAD_DEPENDENCIES_IN_COOKED_EXPORTS: field must be present"
        );
        assert_eq!(parsed.preload_dependency_offset, Some(0));
    }

    /// Hand-crafted UE4 509 boundary test — one tick below the
    /// searchable-names gate. preload-deps present, searchable-names
    /// absent. Pins the exact gate boundary at 510 (not 509).
    #[test]
    fn ue4_509_summary_has_preload_deps_no_searchable_names() {
        let bytes = craft_minimal_ue4_summary_bytes(509);
        let parsed = PackageSummary::read_from(&mut Cursor::new(&bytes), "x.uasset").unwrap();
        assert_eq!(parsed.version.file_version_ue4, 509);
        assert_eq!(parsed.searchable_names_offset, None);
        assert_eq!(parsed.preload_dependency_count, Some(0));
        assert_eq!(parsed.preload_dependency_offset, Some(0));
    }

    /// Hand-crafted UE4 510 boundary test — both gates **fire**.
    /// searchable-names and preload-deps all present on the wire and
    /// parse as `Some(0)`. Pins the upper edge of the searchable-
    /// names gate.
    #[test]
    fn ue4_510_summary_has_both_fields() {
        let bytes = craft_minimal_ue4_summary_bytes(510);
        let parsed = PackageSummary::read_from(&mut Cursor::new(&bytes), "x.uasset").unwrap();
        assert_eq!(parsed.version.file_version_ue4, 510);
        assert_eq!(
            parsed.searchable_names_offset,
            Some(0),
            "UE4 510 == ADDED_SEARCHABLE_NAMES: field must be present"
        );
        assert_eq!(parsed.preload_dependency_count, Some(0));
        assert_eq!(parsed.preload_dependency_offset, Some(0));
    }
}
