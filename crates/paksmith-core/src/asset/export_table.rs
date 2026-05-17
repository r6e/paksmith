//! `FObjectExport` table.
//!
//! Wire shape per record (UE 4.21+ baseline, with UE4/UE5 conditional
//! fields). Verified against CUE4Parse's export reader
//! (`CUE4Parse/UE4/Objects/UObject/ObjectResource.cs`); cross-validation
//! via the unreal_asset oracle is deferred to Task 12 (fixture-gen),
//! which adds unreal_asset as a fixture-gen dev-dep.
//!
//! ```text
//! i32     class_index           // PackageIndex
//! i32     super_index           // PackageIndex
//! i32     template_index        // PackageIndex — only if UE4 >= TEMPLATE_INDEX_IN_COOKED_EXPORTS (508)
//! i32     outer_index           // PackageIndex
//! FName   object_name           // 2 × u32 (name_index + number)
//! u32     object_flags
//! i32/i64 serial_size           // i64 if UE4 >= 64BIT_EXPORTMAP_SERIALSIZES (511), else i32 widened
//! i32/i64 serial_offset         // same width as serial_size
//! i32     forced_export         // bool32
//! i32     not_for_client        // bool32
//! i32     not_for_server        // bool32
//! FGuid   package_guid          // 16 bytes — only if UE5 < REMOVE_OBJECT_EXPORT_PACKAGE_GUID (1005)
//! i32     is_inherited_instance // bool32 — only if UE5 >= TRACK_OBJECT_EXPORT_IS_INHERITED (1006)
//! u32     package_flags
//! i32     not_always_loaded_for_editor_game  // bool32
//! i32     is_asset              // bool32
//! i32     generate_public_hash  // bool32 — only if UE5 >= OPTIONAL_RESOURCES (1003)
//! 2× i64  script_serialization_{start,end}_offset
//!                               // only if UE5 >= SCRIPT_SERIALIZATION_OFFSET (1010)
//!                               // AND !PKG_UnversionedProperties (0x2000)
//! 5× i32  first_export_dependency + 4 dep counts
//!                               // only if UE4 >= PRELOAD_DEPENDENCIES_IN_COOKED_EXPORTS (507);
//!                               // absent → defaults: first=-1, counts=0
//! ```
//!
//! All bool32 fields are signed `i32` on the wire (same bit pattern
//! as `u32` but the writer side must use `i32`).

#[cfg(any(test, feature = "__test_utils"))]
use std::io::Write;
use std::io::{Read, Seek, SeekFrom};

#[cfg(any(test, feature = "__test_utils"))]
use byteorder::WriteBytesExt;
use byteorder::{LittleEndian, ReadBytesExt};
use serde::Serialize;

use crate::asset::FGuid;
use crate::asset::package_index::PackageIndex;
use crate::asset::read_bool32;
use crate::asset::read_package_index;
use crate::asset::summary::PKG_UNVERSIONED_PROPERTIES;
use crate::asset::version::{
    AssetVersion, VER_UE4_64BIT_EXPORTMAP_SERIALSIZES,
    VER_UE4_PRELOAD_DEPENDENCIES_IN_COOKED_EXPORTS, VER_UE4_TEMPLATE_INDEX_IN_COOKED_EXPORTS,
    VER_UE5_OPTIONAL_RESOURCES, VER_UE5_REMOVE_OBJECT_EXPORT_PACKAGE_GUID,
    VER_UE5_SCRIPT_SERIALIZATION_OFFSET, VER_UE5_TRACK_OBJECT_EXPORT_IS_INHERITED,
};
#[cfg(any(test, feature = "__test_utils"))]
use crate::asset::write_bool32;
use crate::error::{
    AssetAllocationContext, AssetParseFault, AssetWireField, BoundsUnit, PaksmithError,
};

/// Hard cap on the wire-claimed export count.
const MAX_EXPORT_TABLE_ENTRIES: u32 = 524_288;

/// Whether `FObjectExport` carries the trailing
/// `script_serialization_{start,end}_offset` i64 pair on the wire.
///
/// Per CUE4Parse's `ObjectResource.cs`: UE5 ≥ 1010 with versioned
/// properties (i.e. `!HasUnversionedProperties` on the owning
/// package). Used at both `read_from` and `write_to` to keep the
/// gate symmetric — drifting copies would resurface the round-trip
/// asymmetry that motivated extracting this helper.
#[inline]
fn emits_script_serialization_tail(version: AssetVersion, summary_package_flags: u32) -> bool {
    version.ue5_at_least(VER_UE5_SCRIPT_SERIALIZATION_OFFSET)
        && (summary_package_flags & PKG_UNVERSIONED_PROPERTIES) == 0
}

/// Wire size of one export record at Phase 2a's UE 4.27 floor (no UE5
/// optional fields). Computed as:
///
/// ```text
///   4×i32 (class/super/template/outer)            = 16
/// + 2×u32 (object_name idx + number)              =  8
/// + u32 object_flags                              =  4
/// + 2×i64 (serial_size/serial_offset)             = 16
/// + 3×i32 (forced/not_for_client/not_for_server)  = 12
/// + 16-byte FGuid package_guid                    = 16
/// + u32 package_flags                             =  4
/// + 2×i32 (not_always_loaded, is_asset)           =  8
/// + 5×i32 (1 dep offset + 4 dep counts)           = 20
/// = 104 bytes
/// ```
///
/// For UE5 assets at our accepted range (1000..=1010), the size may
/// differ (no `package_guid` once UE5 >= 1005, plus optional
/// `is_inherited_instance`/`generate_public_hash`). Don't use this
/// constant as a structural cap — it's a UE 4.27 fixture-test pin.
#[cfg(any(test, feature = "__test_utils"))]
#[allow(
    dead_code,
    reason = "consumed by the in-module record_size_pinned_ue4_27 test today; \
              Task 9's PackageSummary integration test will use it to compute \
              the export-table extent"
)]
pub(crate) const EXPORT_RECORD_SIZE_UE4_27: usize = 104;

/// One row in the export table. Phase 2a stores the raw name index
/// (not yet resolved against a NameTable); resolution happens at
/// JSON rendering time so a malformed name reference fails the inspect
/// command rather than the parse.
#[allow(
    clippy::struct_excessive_bools,
    reason = "FObjectExport's wire layout dictates 6 bool32 flag fields \
              (forced/not_for_client/not_for_server/not_always_loaded/is_asset/is_inherited_instance) — \
              they're independent UE engine flags, not a state machine"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ObjectExport {
    /// Class of the exported object (typically an import).
    pub class_index: PackageIndex,
    /// Super class (export or import).
    pub super_index: PackageIndex,
    /// Template archetype (export or import).
    pub template_index: PackageIndex,
    /// Owning outer object.
    pub outer_index: PackageIndex,
    /// Name-table index of the object's name.
    pub object_name: u32,
    /// Disambiguator for `object_name`.
    pub object_name_number: u32,
    /// UE `EObjectFlags` bitmask.
    pub object_flags: u32,
    /// Length in bytes of the export's serialized data.
    pub serial_size: i64,
    /// Byte offset (relative to start of the asset file) of the
    /// export's serialized data.
    pub serial_offset: i64,
    /// `bForcedExport` (i32 bool32 on the wire; preserved as bool).
    pub forced_export: bool,
    /// `bNotForClient`.
    pub not_for_client: bool,
    /// `bNotForServer`.
    pub not_for_server: bool,
    /// `PackageGuid` (16 bytes). `None` when `FileVersionUE5 >=
    /// REMOVE_OBJECT_EXPORT_PACKAGE_GUID (1005)` — UE5 removed the
    /// field at that version. Always `Some` for UE4 assets and for
    /// UE5 assets < 1005.
    pub package_guid: Option<FGuid>,
    /// `bIsInheritedInstance` (i32 bool). `None` when `FileVersionUE5
    /// < TRACK_OBJECT_EXPORT_IS_INHERITED (1006)`.
    pub is_inherited_instance: Option<bool>,
    /// Package-level flags.
    pub package_flags: u32,
    /// `bNotAlwaysLoadedForEditorGame`.
    pub not_always_loaded_for_editor_game: bool,
    /// `bIsAsset` (always present at our floor).
    pub is_asset: bool,
    /// `bGeneratePublicHash` (i32 bool). `None` when `FileVersionUE5
    /// < OPTIONAL_RESOURCES (1003)`.
    pub generate_public_hash: Option<bool>,
    /// `ScriptSerializationStartOffset` (i64). `None` unless
    /// `FileVersionUE5 >= SCRIPT_SERIALIZATION_OFFSET (1010)` AND
    /// `!PKG_UnversionedProperties`. Source: CUE4Parse
    /// `ObjectResource.cs` —
    /// `if (!Ar.HasUnversionedProperties && Ar.Ver >=
    ///     EUnrealEngineObjectUE5Version.SCRIPT_SERIALIZATION_OFFSET)
    ///  { ScriptSerializationStartOffset = Ar.Read<long>(); ... }`
    pub script_serialization_start_offset: Option<i64>,
    /// `ScriptSerializationEndOffset` (i64). Gated identically to
    /// [`Self::script_serialization_start_offset`].
    pub script_serialization_end_offset: Option<i64>,
    /// First export-dependency index. `-1` means "none".
    pub first_export_dependency: i32,
    /// Number of `serialization-before-serialization` dependencies.
    pub serialization_before_serialization_count: i32,
    /// Number of `create-before-serialization` dependencies.
    pub create_before_serialization_count: i32,
    /// Number of `serialization-before-create` dependencies.
    pub serialization_before_create_count: i32,
    /// Number of `create-before-create` dependencies.
    pub create_before_create_count: i32,
}

impl ObjectExport {
    /// Read one record. The wire shape is version-dependent for UE5
    /// fields; pass the resolved [`AssetVersion`] from the package
    /// summary.
    ///
    /// # Preconditions
    ///
    /// Assumes the asset was cooked. [`crate::asset::PackageSummary::read_from`]
    /// enforces the cooked precondition at the summary boundary —
    /// uncooked assets at `file_version_ue4 >= VER_UE4_NON_OUTER_PACKAGE_IMPORT`
    /// are rejected via [`AssetParseFault::UncookedAsset`] before this
    /// reader runs (the parallel concern for `FObjectImport` is the
    /// load-bearing one; `FObjectExport`'s editor-only fields are not
    /// affected, but rejection happens earlier in the parse pipeline).
    ///
    /// Phase 2a's accepted UE5 range is 1000..=1010 — at UE5 version
    /// 1011 (`PROPERTY_TAG_EXTENSION_AND_OVERRIDABLE_SERIALIZATION`),
    /// UE adds a byte to `FPropertyTag` that Phase 2b's tagged-property
    /// reader cannot decode. The export-table reader itself is shape-
    /// stable across the entire 1000-1010 range and beyond: the per-export
    /// `package_guid` was removed at 1005 (already handled here via
    /// `Option<FGuid>`); the summary-level FGuid migrates to FIoHash at
    /// 1016 (above the ceiling). [`crate::asset::PackageSummary::read_from`]
    /// rejects out-of-range UE5 assets at the summary boundary via
    /// [`AssetParseFault::UnsupportedFileVersionUE5`] before downstream
    /// readers misparse. This reader does NOT version-gate internally.
    ///
    /// # Errors
    /// - [`AssetParseFault::PackageIndexUnderflow`] if any of class/
    ///   super/template/outer index is `i32::MIN`.
    /// - [`AssetParseFault::NegativeValue`] if `serial_size < 0` or
    ///   `serial_offset < 0`.
    /// - [`PaksmithError::Io`] on EOF or other I/O failures.
    #[allow(
        clippy::too_many_lines,
        reason = "FObjectExport's ~20 wire-format fields are read sequentially with version \
                  gates; splitting into sub-functions would obscure the byte-by-byte structure \
                  mirroring CUE4Parse"
    )]
    pub fn read_from<R: Read>(
        reader: &mut R,
        version: AssetVersion,
        summary_package_flags: u32,
        asset_path: &str,
    ) -> crate::Result<Self> {
        let class_index = read_package_index(reader, asset_path, AssetWireField::ExportClassIndex)?;
        let super_index = read_package_index(reader, asset_path, AssetWireField::ExportSuperIndex)?;
        // TemplateIndex was added at UE4 TEMPLATE_INDEX_IN_COOKED_EXPORTS
        // (508). Below that, the record skips the slot — read no bytes
        // and default to PackageIndex::Null. CUE4Parse:
        // `TemplateIndex = Ar.Ver >= TemplateIndex_IN_COOKED_EXPORTS ?
        //     new FPackageIndex(Ar) : new FPackageIndex();`
        let template_index = if version.ue4_at_least(VER_UE4_TEMPLATE_INDEX_IN_COOKED_EXPORTS) {
            read_package_index(reader, asset_path, AssetWireField::ExportTemplateIndex)?
        } else {
            PackageIndex::Null
        };
        let outer_index = read_package_index(reader, asset_path, AssetWireField::ExportOuterIndex)?;

        let object_name = reader.read_u32::<LittleEndian>()?;
        let object_name_number = reader.read_u32::<LittleEndian>()?;
        let object_flags = reader.read_u32::<LittleEndian>()?;
        // serial_size / serial_offset widened from i32 to i64 at UE4
        // 64BIT_EXPORTMAP_SERIALSIZES (511). Below that, read i32 and
        // widen in-memory. CUE4Parse:
        // `if (Ar.Ver < e64BIT_EXPORTMAP_SERIALSIZES) { SerialSize =
        //     Ar.Read<int>(); SerialOffset = Ar.Read<int>(); }
        //  else { ... long ... }`
        let (serial_size, serial_offset) =
            if version.ue4_at_least(VER_UE4_64BIT_EXPORTMAP_SERIALSIZES) {
                (
                    reader.read_i64::<LittleEndian>()?,
                    reader.read_i64::<LittleEndian>()?,
                )
            } else {
                (
                    i64::from(reader.read_i32::<LittleEndian>()?),
                    i64::from(reader.read_i32::<LittleEndian>()?),
                )
            };
        // All bool32 fields are i32 on the wire (signed), per UE source.
        // read_bool32 strict-rejects values other than 0 or 1 — matches
        // CUE4Parse's `FArchive.ReadBoolean`.
        let forced_export = read_bool32(reader, asset_path, AssetWireField::ExportForcedExport)?;
        let not_for_client = read_bool32(reader, asset_path, AssetWireField::ExportNotForClient)?;
        let not_for_server = read_bool32(reader, asset_path, AssetWireField::ExportNotForServer)?;

        // package_guid: 16 bytes, present only when UE5 < REMOVE_OBJECT_EXPORT_PACKAGE_GUID (1005).
        let package_guid = if version.ue5_at_least(VER_UE5_REMOVE_OBJECT_EXPORT_PACKAGE_GUID) {
            None
        } else {
            Some(FGuid::read_from(reader)?)
        };

        // is_inherited_instance: i32 bool, added at UE5 1006.
        let is_inherited_instance =
            if version.ue5_at_least(VER_UE5_TRACK_OBJECT_EXPORT_IS_INHERITED) {
                Some(read_bool32(
                    reader,
                    asset_path,
                    AssetWireField::ExportIsInheritedInstance,
                )?)
            } else {
                None
            };

        let package_flags = reader.read_u32::<LittleEndian>()?;
        let not_always_loaded_for_editor_game = read_bool32(
            reader,
            asset_path,
            AssetWireField::ExportNotAlwaysLoadedForEditorGame,
        )?;
        let is_asset = read_bool32(reader, asset_path, AssetWireField::ExportIsAsset)?;

        // generate_public_hash: i32 bool, added at UE5 1003.
        let generate_public_hash = if version.ue5_at_least(VER_UE5_OPTIONAL_RESOURCES) {
            Some(read_bool32(
                reader,
                asset_path,
                AssetWireField::ExportGeneratePublicHash,
            )?)
        } else {
            None
        };

        // Preload-dependency tail: 5 × i32 added at UE4
        // PRELOAD_DEPENDENCIES_IN_COOKED_EXPORTS (507). Below that, the
        // record terminates here (modulo the SCRIPT_SERIALIZATION_OFFSET
        // tail below); in-memory defaults follow UE convention
        // (first=-1 means "no preload deps", counts=0). CUE4Parse reads
        // these only when `Ar.Ver >= PRELOAD_DEPENDENCIES_IN_COOKED_EXPORTS`.
        let (
            first_export_dependency,
            serialization_before_serialization_count,
            create_before_serialization_count,
            serialization_before_create_count,
            create_before_create_count,
        ) = if version.ue4_at_least(VER_UE4_PRELOAD_DEPENDENCIES_IN_COOKED_EXPORTS) {
            (
                reader.read_i32::<LittleEndian>()?,
                reader.read_i32::<LittleEndian>()?,
                reader.read_i32::<LittleEndian>()?,
                reader.read_i32::<LittleEndian>()?,
                reader.read_i32::<LittleEndian>()?,
            )
        } else {
            (-1, 0, 0, 0, 0)
        };

        // Script-serialization tail: 2 × i64 added at UE5
        // SCRIPT_SERIALIZATION_OFFSET (1010), but ONLY for versioned
        // packages (PKG_UnversionedProperties clear). The fields are
        // emitted AFTER the preload-dep tail, per CUE4Parse
        // (ObjectResource.cs lines 288-292). Below threshold (or for
        // unversioned packages at threshold), defaults to None — these
        // bytes are not in the wire stream.
        // Note: the gate uses the SUMMARY's package_flags
        // (`summary_package_flags`), not the per-export `package_flags`
        // read at line above. CUE4Parse's `Ar.HasUnversionedProperties`
        // (FAssetArchive.cs) resolves to the owning package's
        // PKG_UnversionedProperties bit.
        let (script_serialization_start_offset, script_serialization_end_offset) =
            if emits_script_serialization_tail(version, summary_package_flags) {
                (
                    Some(reader.read_i64::<LittleEndian>()?),
                    Some(reader.read_i64::<LittleEndian>()?),
                )
            } else {
                (None, None)
            };

        if serial_size < 0 {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::NegativeValue {
                    field: AssetWireField::ExportSerialSize,
                    value: serial_size,
                },
            });
        }
        if serial_offset < 0 {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::NegativeValue {
                    field: AssetWireField::ExportSerialOffset,
                    value: serial_offset,
                },
            });
        }

        Ok(Self {
            class_index,
            super_index,
            template_index,
            outer_index,
            object_name,
            object_name_number,
            object_flags,
            serial_size,
            serial_offset,
            forced_export,
            not_for_client,
            not_for_server,
            package_guid,
            is_inherited_instance,
            package_flags,
            not_always_loaded_for_editor_game,
            is_asset,
            generate_public_hash,
            script_serialization_start_offset,
            script_serialization_end_offset,
            first_export_dependency,
            serialization_before_serialization_count,
            create_before_serialization_count,
            serialization_before_create_count,
            create_before_create_count,
        })
    }

    /// Write one record. Test- and fixture-gen-only via the
    /// `__test_utils` feature; release builds drop this method.
    /// Matches `read_from` field order, including version-gated
    /// `package_guid`, `is_inherited_instance`, and
    /// `generate_public_hash` tail fields.
    ///
    /// # Errors
    /// Returns [`std::io::Error`] if writes fail.
    ///
    /// # Panics
    /// Panics if `version` and `summary_package_flags` satisfy the
    /// SCRIPT_SERIALIZATION_OFFSET gate (UE5 ≥ 1010 with
    /// `!PKG_UnversionedProperties`) but either
    /// `script_serialization_start_offset` or
    /// `script_serialization_end_offset` is `None`. read_from always
    /// populates these under the gate, so a `None` at gate-fire is a
    /// hand-built-struct programmer error.
    #[cfg(any(test, feature = "__test_utils"))]
    pub fn write_to<W: Write>(
        &self,
        writer: &mut W,
        version: AssetVersion,
        summary_package_flags: u32,
    ) -> std::io::Result<()> {
        writer.write_i32::<LittleEndian>(self.class_index.to_raw())?;
        writer.write_i32::<LittleEndian>(self.super_index.to_raw())?;
        // TemplateIndex absent below UE4 508; skip the slot entirely
        // (do not emit zero bytes — that would mis-align the cursor).
        if version.ue4_at_least(VER_UE4_TEMPLATE_INDEX_IN_COOKED_EXPORTS) {
            writer.write_i32::<LittleEndian>(self.template_index.to_raw())?;
        }
        writer.write_i32::<LittleEndian>(self.outer_index.to_raw())?;
        writer.write_u32::<LittleEndian>(self.object_name)?;
        writer.write_u32::<LittleEndian>(self.object_name_number)?;
        writer.write_u32::<LittleEndian>(self.object_flags)?;
        // serial_size / serial_offset width matches read_from's gate.
        // Truncating i64→i32 is acceptable for synthesized fixtures
        // because we only set values within the i32 domain when
        // targeting pre-511 versions; production assets at this floor
        // are bytes-tiny.
        if version.ue4_at_least(VER_UE4_64BIT_EXPORTMAP_SERIALSIZES) {
            writer.write_i64::<LittleEndian>(self.serial_size)?;
            writer.write_i64::<LittleEndian>(self.serial_offset)?;
        } else {
            writer.write_i32::<LittleEndian>(self.serial_size as i32)?;
            writer.write_i32::<LittleEndian>(self.serial_offset as i32)?;
        }
        // bool32 fields written as i32 on the wire.
        write_bool32(writer, self.forced_export)?;
        write_bool32(writer, self.not_for_client)?;
        write_bool32(writer, self.not_for_server)?;
        if let Some(g) = self.package_guid {
            g.write_to(writer)?;
        }
        if let Some(b) = self.is_inherited_instance {
            write_bool32(writer, b)?;
        }
        writer.write_u32::<LittleEndian>(self.package_flags)?;
        write_bool32(writer, self.not_always_loaded_for_editor_game)?;
        write_bool32(writer, self.is_asset)?;
        if let Some(b) = self.generate_public_hash {
            write_bool32(writer, b)?;
        }
        // Preload-dep tail: absent below UE4 507. Don't emit defaults —
        // that would lengthen the record.
        if version.ue4_at_least(VER_UE4_PRELOAD_DEPENDENCIES_IN_COOKED_EXPORTS) {
            writer.write_i32::<LittleEndian>(self.first_export_dependency)?;
            writer.write_i32::<LittleEndian>(self.serialization_before_serialization_count)?;
            writer.write_i32::<LittleEndian>(self.create_before_serialization_count)?;
            writer.write_i32::<LittleEndian>(self.serialization_before_create_count)?;
            writer.write_i32::<LittleEndian>(self.create_before_create_count)?;
        }
        // Script-serialization tail: emit iff UE5 >= 1010 AND the
        // SUMMARY's PKG_UnversionedProperties is clear. Symmetric with
        // read_from's gate via `emits_script_serialization_tail`.
        //
        // INVARIANT: when the gate fires, both Option fields MUST be
        // `Some(_)`. read_from always populates them under this gate,
        // so any ObjectExport reaching write_to with `None` at gate-fire
        // is a programmer error (hand-built struct in tests/fixture-gen
        // that forgot the wire-required fields). Panicking here keeps
        // the wire shape symmetric: an `unwrap_or(0)` would silently
        // round-trip `None` → wire(0) → `Some(0)`, breaking
        // `read_from(write_to(x)) == x` for `x.script_serialization_*
        // == None`. write_to is `#[cfg(any(test, feature =
        // "__test_utils"))]` so panic-on-misuse is appropriate.
        if emits_script_serialization_tail(version, summary_package_flags) {
            let start = self.script_serialization_start_offset.expect(
                "script_serialization_start_offset must be Some when \
                 SCRIPT_SERIALIZATION_OFFSET gate fires (UE5 >= 1010, \
                 !PKG_UnversionedProperties)",
            );
            let end = self.script_serialization_end_offset.expect(
                "script_serialization_end_offset must be Some when \
                 SCRIPT_SERIALIZATION_OFFSET gate fires (UE5 >= 1010, \
                 !PKG_UnversionedProperties)",
            );
            writer.write_i64::<LittleEndian>(start)?;
            writer.write_i64::<LittleEndian>(end)?;
        }
        Ok(())
    }
}

/// `TArray<FObjectExport>` from the summary's `ExportOffset/Count`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ExportTable {
    /// Exports in wire order.
    pub exports: Vec<ObjectExport>,
}

impl ExportTable {
    /// Look up by 0-based index.
    #[must_use]
    pub fn get(&self, index: u32) -> Option<&ObjectExport> {
        self.exports.get(index as usize)
    }

    /// Read the table by seeking to `offset` and decoding `count`
    /// records. `version` controls the conditional UE5 fields in each
    /// record.
    ///
    /// # Errors
    /// - [`AssetParseFault::NegativeValue`] if `offset < 0` or
    ///   `count < 0`.
    /// - [`AssetParseFault::BoundsExceeded`] if
    ///   `count > MAX_EXPORT_TABLE_ENTRIES`.
    /// - [`AssetParseFault::AllocationFailed`] on reservation failure.
    /// - Errors from [`ObjectExport::read_from`] propagated per record.
    /// - [`PaksmithError::Io`] on seek/read failures.
    pub fn read_from<R: Read + Seek>(
        reader: &mut R,
        offset: i64,
        count: i32,
        version: AssetVersion,
        summary_package_flags: u32,
        asset_path: &str,
    ) -> crate::Result<Self> {
        if offset < 0 {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::NegativeValue {
                    field: AssetWireField::ExportOffset,
                    value: offset,
                },
            });
        }
        if count < 0 {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::NegativeValue {
                    field: AssetWireField::ExportCount,
                    value: i64::from(count),
                },
            });
        }
        let count_u32 = count as u32;
        if u64::from(count_u32) > u64::from(MAX_EXPORT_TABLE_ENTRIES) {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::BoundsExceeded {
                    field: AssetWireField::ExportCount,
                    value: u64::from(count_u32),
                    limit: u64::from(MAX_EXPORT_TABLE_ENTRIES),
                    unit: BoundsUnit::Items,
                },
            });
        }
        // expression-statement; seek's u64 return is discarded
        let _ = reader.seek(SeekFrom::Start(offset as u64))?;
        let mut exports: Vec<ObjectExport> = Vec::new();
        exports
            .try_reserve_exact(count_u32 as usize)
            .map_err(|source| PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::AllocationFailed {
                    context: AssetAllocationContext::ExportTable,
                    requested: count_u32 as usize,
                    source,
                },
            })?;
        for _ in 0..count_u32 {
            exports.push(ObjectExport::read_from(
                reader,
                version,
                summary_package_flags,
                asset_path,
            )?);
        }
        Ok(Self { exports })
    }

    /// Write the table. Test- and fixture-gen-only via the
    /// `__test_utils` feature; release builds drop this method.
    ///
    /// # Errors
    /// Returns [`std::io::Error`] if writes fail.
    #[cfg(any(test, feature = "__test_utils"))]
    pub fn write_to<W: Write>(
        &self,
        writer: &mut W,
        version: AssetVersion,
        summary_package_flags: u32,
    ) -> std::io::Result<()> {
        for e in &self.exports {
            e.write_to(writer, version, summary_package_flags)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn ue4_27() -> AssetVersion {
        AssetVersion {
            legacy_file_version: -7,
            file_version_ue4: 522,
            file_version_ue5: None,
            file_version_licensee_ue4: 0,
        }
    }

    fn ue5_1() -> AssetVersion {
        AssetVersion {
            legacy_file_version: -8,
            file_version_ue4: 522,
            file_version_ue5: Some(1009),
            file_version_licensee_ue4: 0,
        }
    }

    /// `PKG_FilterEditorOnly` (the cooked-asset bit). Mirrors the
    /// summary's flag value used by `build_minimal_ue4_27`. Threaded
    /// into write_to / read_from where the wire format is unaffected at
    /// UE4 / UE5 ≤ 1009 — the SCRIPT_SERIALIZATION_OFFSET gate only
    /// activates at UE5 ≥ 1010 + !PKG_UnversionedProperties.
    const TEST_COOKED_FLAGS: u32 = 0x8000_0000;

    fn sample_export_ue4_27() -> ObjectExport {
        ObjectExport {
            class_index: PackageIndex::Import(0),
            super_index: PackageIndex::Null,
            template_index: PackageIndex::Null,
            outer_index: PackageIndex::Null,
            object_name: 5,
            object_name_number: 0,
            object_flags: 0x0008_0000,
            serial_size: 84,
            serial_offset: 1280,
            forced_export: false,
            not_for_client: false,
            not_for_server: false,
            package_guid: Some(FGuid::from_bytes([0u8; 16])),
            is_inherited_instance: None,
            package_flags: 0,
            not_always_loaded_for_editor_game: false,
            is_asset: true,
            generate_public_hash: None,
            script_serialization_start_offset: None,
            script_serialization_end_offset: None,
            first_export_dependency: -1,
            serialization_before_serialization_count: 0,
            create_before_serialization_count: 0,
            serialization_before_create_count: 0,
            create_before_create_count: 0,
        }
    }

    fn sample_export_ue5_1() -> ObjectExport {
        ObjectExport {
            class_index: PackageIndex::Import(0),
            super_index: PackageIndex::Null,
            template_index: PackageIndex::Null,
            outer_index: PackageIndex::Null,
            object_name: 5,
            object_name_number: 0,
            object_flags: 0,
            serial_size: 84,
            serial_offset: 1280,
            forced_export: false,
            not_for_client: false,
            not_for_server: false,
            package_guid: None,                 // UE5 >= 1005 removes this
            is_inherited_instance: Some(false), // UE5 >= 1006 adds this
            package_flags: 0,
            not_always_loaded_for_editor_game: false,
            is_asset: true,
            generate_public_hash: Some(false), // UE5 >= 1003 adds this
            script_serialization_start_offset: None, // UE5 1009 < 1010
            script_serialization_end_offset: None,
            first_export_dependency: -1,
            serialization_before_serialization_count: 0,
            create_before_serialization_count: 0,
            serialization_before_create_count: 0,
            create_before_create_count: 0,
        }
    }

    #[test]
    fn record_size_pinned_ue4_27() {
        let e = sample_export_ue4_27();
        let mut buf = Vec::new();
        e.write_to(&mut buf, ue4_27(), TEST_COOKED_FLAGS).unwrap();
        assert_eq!(buf.len(), EXPORT_RECORD_SIZE_UE4_27);
    }

    #[test]
    fn round_trip_one_record() {
        let e = sample_export_ue4_27();
        let v = ue4_27();
        let mut buf = Vec::new();
        e.write_to(&mut buf, v, TEST_COOKED_FLAGS).unwrap();
        let parsed =
            ObjectExport::read_from(&mut Cursor::new(&buf), v, TEST_COOKED_FLAGS, "x.uasset")
                .unwrap();
        assert_eq!(parsed, e);
    }

    #[test]
    fn table_round_trip() {
        let v = ue4_27();
        let table = ExportTable {
            exports: vec![sample_export_ue4_27(), sample_export_ue4_27()],
        };
        let mut buf = Vec::new();
        table.write_to(&mut buf, v, TEST_COOKED_FLAGS).unwrap();
        let parsed = ExportTable::read_from(
            &mut Cursor::new(buf),
            0,
            2,
            v,
            TEST_COOKED_FLAGS,
            "x.uasset",
        )
        .unwrap();
        assert_eq!(parsed, table);
    }

    #[test]
    fn rejects_negative_serial_size() {
        let mut e = sample_export_ue4_27();
        let v = ue4_27();
        e.serial_size = -1;
        let mut buf = Vec::new();
        e.write_to(&mut buf, v, TEST_COOKED_FLAGS).unwrap();
        let err = ObjectExport::read_from(&mut Cursor::new(&buf), v, TEST_COOKED_FLAGS, "x.uasset")
            .unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::NegativeValue {
                    field: AssetWireField::ExportSerialSize,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn rejects_negative_serial_offset() {
        let mut e = sample_export_ue4_27();
        let v = ue4_27();
        e.serial_offset = -1;
        let mut buf = Vec::new();
        e.write_to(&mut buf, v, TEST_COOKED_FLAGS).unwrap();
        let err = ObjectExport::read_from(&mut Cursor::new(&buf), v, TEST_COOKED_FLAGS, "x.uasset")
            .unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::NegativeValue {
                    field: AssetWireField::ExportSerialOffset,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn rejects_negative_offset() {
        let v = ue4_27();
        let mut cursor = Cursor::new(Vec::<u8>::new());
        let err = ExportTable::read_from(&mut cursor, -1, 0, v, TEST_COOKED_FLAGS, "x.uasset")
            .unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::NegativeValue {
                    field: AssetWireField::ExportOffset,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn rejects_negative_count() {
        let v = ue4_27();
        let mut cursor = Cursor::new(Vec::<u8>::new());
        let err = ExportTable::read_from(&mut cursor, 0, -1, v, TEST_COOKED_FLAGS, "x.uasset")
            .unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::NegativeValue {
                    field: AssetWireField::ExportCount,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn rejects_count_over_cap() {
        let v = ue4_27();
        let mut cursor = Cursor::new(Vec::<u8>::new());
        let err = ExportTable::read_from(
            &mut cursor,
            0,
            MAX_EXPORT_TABLE_ENTRIES as i32 + 1,
            v,
            TEST_COOKED_FLAGS,
            "x.uasset",
        )
        .unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::BoundsExceeded {
                    field: AssetWireField::ExportCount,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn package_index_underflow_on_class_index() {
        // Craft an export whose first PackageIndex (class_index) is
        // i32::MIN. The reader bails before consuming the remaining
        // bytes, so we only need the first 4.
        let v = ue4_27();
        let mut buf = Vec::new();
        buf.extend_from_slice(&i32::MIN.to_le_bytes());
        let err = ObjectExport::read_from(&mut Cursor::new(&buf), v, TEST_COOKED_FLAGS, "x.uasset")
            .unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::PackageIndexUnderflow {
                    field: AssetWireField::ExportClassIndex,
                },
                ..
            }
        ));
    }

    #[test]
    fn ue5_round_trip() {
        let v = ue5_1();
        let original = sample_export_ue5_1();
        let mut buf = Vec::new();
        original.write_to(&mut buf, v, TEST_COOKED_FLAGS).unwrap();
        // UE5 1009 record size:
        //   UE4 baseline (104) - 16 (no package_guid)
        //   + 4 (is_inherited_instance) + 4 (generate_public_hash) = 96.
        assert_eq!(buf.len(), 96);
        let parsed =
            ObjectExport::read_from(&mut Cursor::new(&buf), v, TEST_COOKED_FLAGS, "x.uasset")
                .unwrap();
        assert_eq!(parsed, original);
    }

    /// UE5 1010 with PKG_UnversionedProperties CLEAR — the two
    /// script-serialization i64s are written AFTER the preload-dep tail
    /// (per CUE4Parse `ObjectResource.cs` lines 288-292). Round-trip
    /// preserves the offsets.
    #[test]
    fn round_trip_ue5_1010_script_serialization_offsets_present() {
        let v = AssetVersion {
            legacy_file_version: -8,
            file_version_ue4: 522,
            file_version_ue5: Some(1010),
            file_version_licensee_ue4: 0,
        };
        // PKG_FilterEditorOnly only (no PKG_UnversionedProperties =
        // 0x2000 bit) — so the script-serialization fields are written.
        let summary_flags = 0x8000_0000u32;
        let mut original = sample_export_ue5_1();
        original.script_serialization_start_offset = Some(0xDEAD_BEEF);
        original.script_serialization_end_offset = Some(0xFEED_F00D);
        let mut buf = Vec::new();
        original.write_to(&mut buf, v, summary_flags).unwrap();
        // 96 (UE5 1009 baseline) + 16 (2 × i64) = 112.
        assert_eq!(buf.len(), 112);
        let parsed =
            ObjectExport::read_from(&mut Cursor::new(&buf), v, summary_flags, "x.uasset").unwrap();
        assert_eq!(parsed, original);
        assert_eq!(parsed.script_serialization_start_offset, Some(0xDEAD_BEEF));
        assert_eq!(parsed.script_serialization_end_offset, Some(0xFEED_F00D));
    }

    /// Programmer-error invariant: when the SCRIPT_SERIALIZATION_OFFSET
    /// gate fires (UE5 ≥ 1010, !PKG_UnversionedProperties), both
    /// script_serialization_{start,end}_offset MUST be `Some(_)`. A
    /// `None` at gate-fire means a hand-built struct skipped a
    /// wire-required field. Pins Option A from the Phase 2a R2 panel
    /// — write_to panics rather than silently emitting `0` and
    /// asymmetrically round-tripping `None` → `Some(0)`.
    #[test]
    #[should_panic(expected = "script_serialization_start_offset must be Some")]
    fn write_to_panics_when_gate_fires_but_start_offset_is_none() {
        let v = AssetVersion {
            legacy_file_version: -8,
            file_version_ue4: 522,
            file_version_ue5: Some(1010),
            file_version_licensee_ue4: 0,
        };
        let summary_flags = 0x8000_0000u32; // PKG_FilterEditorOnly, no PKG_UnversionedProperties
        let mut e = sample_export_ue5_1();
        // Hand-built struct: gate fires but the field is left None.
        e.script_serialization_start_offset = None;
        e.script_serialization_end_offset = Some(0);
        let mut buf = Vec::new();
        let _ = e.write_to(&mut buf, v, summary_flags);
    }

    /// UE5 1010 with PKG_UnversionedProperties SET — the gate
    /// suppresses the two script-serialization i64s. Round-trip leaves
    /// them as None.
    #[test]
    fn round_trip_ue5_1010_unversioned_properties_suppresses_script_offsets() {
        let v = AssetVersion {
            legacy_file_version: -8,
            file_version_ue4: 522,
            file_version_ue5: Some(1010),
            file_version_licensee_ue4: 0,
        };
        // PKG_FilterEditorOnly | PKG_UnversionedProperties.
        let summary_flags = 0x8000_2000u32;
        let original = sample_export_ue5_1();
        let mut buf = Vec::new();
        original.write_to(&mut buf, v, summary_flags).unwrap();
        // 96 — same as UE5 1009; the gate suppresses both i64s.
        assert_eq!(buf.len(), 96);
        let parsed =
            ObjectExport::read_from(&mut Cursor::new(&buf), v, summary_flags, "x.uasset").unwrap();
        assert_eq!(parsed.script_serialization_start_offset, None);
        assert_eq!(parsed.script_serialization_end_offset, None);
        assert_eq!(parsed, original);
    }

    #[test]
    fn object_export_serializes_with_all_fields() {
        // Serialize-shape pin. Spot-check a few key fields rather than
        // pinning the full string — the field set is large and order
        // matters less than presence.
        let e = sample_export_ue5_1();
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains(r#""class_index":"Import(0)""#), "got: {json}");
        assert!(json.contains(r#""package_guid":null"#), "got: {json}");
        assert!(json.contains(r#""is_asset":true"#), "got: {json}");
        assert!(
            json.contains(r#""is_inherited_instance":false"#),
            "got: {json}"
        );
        assert!(
            json.contains(r#""generate_public_hash":false"#),
            "got: {json}"
        );
    }

    /// UE4 504..=506 (below PRELOAD_DEPENDENCIES (507) and
    /// TEMPLATE_INDEX (508), still using i32 serial_size/offset).
    /// The wire record omits TemplateIndex, the 5 preload-dep i32s,
    /// and downgrades the two serial-size i64s to i32s. Round-trip
    /// must reconstruct the in-memory defaults.
    #[test]
    fn round_trip_pre_preload_pre_template_pre_64bit() {
        let v = AssetVersion {
            legacy_file_version: -7,
            file_version_ue4: 504, // below 507, 508, and 511
            file_version_ue5: None,
            file_version_licensee_ue4: 0,
        };
        let original = ObjectExport {
            class_index: PackageIndex::Import(0),
            super_index: PackageIndex::Null,
            template_index: PackageIndex::Null, // absent on wire → default Null
            outer_index: PackageIndex::Null,
            object_name: 5,
            object_name_number: 0,
            object_flags: 0,
            serial_size: 84, // fits in i32
            serial_offset: 1280,
            forced_export: false,
            not_for_client: false,
            not_for_server: false,
            package_guid: Some(FGuid::from_bytes([0u8; 16])),
            is_inherited_instance: None,
            package_flags: 0,
            not_always_loaded_for_editor_game: false,
            is_asset: true,
            generate_public_hash: None,
            script_serialization_start_offset: None,
            script_serialization_end_offset: None,
            first_export_dependency: -1, // absent on wire → default -1
            serialization_before_serialization_count: 0,
            create_before_serialization_count: 0,
            serialization_before_create_count: 0,
            create_before_create_count: 0,
        };
        let mut buf = Vec::new();
        original.write_to(&mut buf, v, TEST_COOKED_FLAGS).unwrap();
        // UE4 baseline (104) — 4 (no template_index) — 8 (i32 serial
        // pair instead of i64 pair, -8 from i64→i32 ×2 = -8) — 20
        // (no 5 preload-dep i32s) = 72 bytes.
        assert_eq!(buf.len(), 72);
        let parsed =
            ObjectExport::read_from(&mut Cursor::new(&buf), v, TEST_COOKED_FLAGS, "x.uasset")
                .unwrap();
        assert_eq!(parsed, original);
    }

    /// UE4 510 — preload-deps + TemplateIndex present, but
    /// serial-size/offset still 32-bit. Exercises the
    /// 508-included-but-511-not-yet boundary.
    #[test]
    fn round_trip_ue4_510_template_present_serial_still_32bit() {
        let v = AssetVersion {
            legacy_file_version: -7,
            file_version_ue4: 510, // >= 507 (preload), >= 508 (template), < 511 (64-bit)
            file_version_ue5: None,
            file_version_licensee_ue4: 0,
        };
        let original = ObjectExport {
            class_index: PackageIndex::Import(0),
            super_index: PackageIndex::Null,
            template_index: PackageIndex::Import(1), // PRESENT
            outer_index: PackageIndex::Null,
            object_name: 5,
            object_name_number: 0,
            object_flags: 0,
            serial_size: 84,
            serial_offset: 1280,
            forced_export: false,
            not_for_client: false,
            not_for_server: false,
            package_guid: Some(FGuid::from_bytes([0u8; 16])),
            is_inherited_instance: None,
            package_flags: 0,
            not_always_loaded_for_editor_game: false,
            is_asset: true,
            generate_public_hash: None,
            script_serialization_start_offset: None,
            script_serialization_end_offset: None,
            first_export_dependency: -1,
            serialization_before_serialization_count: 1,
            create_before_serialization_count: 2,
            serialization_before_create_count: 3,
            create_before_create_count: 4,
        };
        let mut buf = Vec::new();
        original.write_to(&mut buf, v, TEST_COOKED_FLAGS).unwrap();
        // UE4 baseline (104) — 8 (i32 serial pair instead of i64) = 96.
        assert_eq!(buf.len(), 96);
        let parsed =
            ObjectExport::read_from(&mut Cursor::new(&buf), v, TEST_COOKED_FLAGS, "x.uasset")
                .unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn export_table_serializes_as_bare_array() {
        // #[serde(transparent)] container: the wrapping JSON is just
        // the inner Vec, not {"exports": [...]}.
        let t = ExportTable {
            exports: vec![sample_export_ue4_27()],
        };
        let json = serde_json::to_string(&t).unwrap();
        assert!(json.starts_with('['), "expected array, got: {json}");
        assert!(json.ends_with(']'), "expected array, got: {json}");
        assert!(!json.starts_with(r#"{"exports":"#), "got: {json}");
    }
}
