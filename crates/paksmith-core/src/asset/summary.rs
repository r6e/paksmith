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
    AssetVersion, PACKAGE_FILE_TAG, VER_UE4_ADDED_PACKAGE_SUMMARY_LOCALIZATION_ID,
    VER_UE4_NAME_HASHES_SERIALIZED, VER_UE4_NON_OUTER_PACKAGE_IMPORT,
    VER_UE5_ADD_SOFTOBJECTPATH_LIST, VER_UE5_DATA_RESOURCES,
    VER_UE5_NAMES_REFERENCED_FROM_EXPORT_DATA, VER_UE5_PAYLOAD_TOC,
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
    /// `SearchableNamesOffset`.
    pub searchable_names_offset: i32,
    /// `ThumbnailTableOffset`.
    pub thumbnail_table_offset: i32,
    /// Per-save `FGuid` identifier. UE writers generate a fresh GUID on
    /// every save.
    pub guid: FGuid,
    /// `PersistentGuid` — stable across saves (UE 4.27+).
    pub persistent_guid: FGuid,
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
    /// `PreloadDependencyCount`.
    pub preload_dependency_count: i32,
    /// `PreloadDependencyOffset`.
    pub preload_dependency_offset: i32,
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
        // Versions
        let legacy_file_version = reader.read_i32::<LittleEndian>()?;
        if !matches!(legacy_file_version, -7 | -8) {
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
        let searchable_names_offset = reader.read_i32::<LittleEndian>()?;
        let thumbnail_table_offset = reader.read_i32::<LittleEndian>()?;

        // GUIDs
        let guid = FGuid::read_from(reader)?;
        let persistent_guid = FGuid::read_from(reader)?;

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
                    observed: u64::from(compression_flags),
                },
            });
        }
        let compressed_chunks_count = reader.read_i32::<LittleEndian>()?;
        if compressed_chunks_count != 0 {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::UnsupportedCompressionInSummary {
                    site: crate::error::CompressionInSummarySite::CompressedChunksCount,
                    observed: compressed_chunks_count.max(0) as u64,
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

        let preload_dependency_count = reader.read_i32::<LittleEndian>()?;
        let preload_dependency_offset = reader.read_i32::<LittleEndian>()?;

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
        writer.write_i32::<LittleEndian>(self.searchable_names_offset)?;
        writer.write_i32::<LittleEndian>(self.thumbnail_table_offset)?;
        self.guid.write_to(writer)?;
        self.persistent_guid.write_to(writer)?;
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
        writer.write_i32::<LittleEndian>(self.preload_dependency_count)?;
        writer.write_i32::<LittleEndian>(self.preload_dependency_offset)?;
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
            searchable_names_offset: 0,
            thumbnail_table_offset: 0,
            guid: FGuid::from_bytes([0u8; 16]),
            persistent_guid: FGuid::from_bytes([0u8; 16]),
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
            preload_dependency_count: 0,
            preload_dependency_offset: 0,
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
}
