//! Minimal UE 4.27 `.uasset` byte synthesizer for Phase-2a tests.
//!
//! Promoted out of `asset::package`'s test block so that:
//! 1. Phase 2a's integration test (`tests/asset_integration.rs`) and
//!    the unit test inside `asset::package` share one builder rather
//!    than maintaining parallel copies.
//! 2. `paksmith-fixture-gen` can reach this builder via the
//!    `__test_utils` feature without duplicating the wire-format
//!    assembly (mirrors the [`v10`] precedent for the pak FDI).
//!
//! **Stability:** gated behind the `__test_utils` feature; do not
//! depend on this from downstream crates.
//!
//! [`v10`]: super::v10

#![allow(clippy::missing_panics_doc)]

use crate::asset::custom_version::CustomVersionContainer;
use crate::asset::engine_version::EngineVersion;
use crate::asset::export_table::{EXPORT_RECORD_SIZE_UE4_27, ExportTable, ObjectExport};
use crate::asset::guid::FGuid;
use crate::asset::import_table::{ImportTable, ObjectImport};
use crate::asset::name_table::{FName, NameTable};
use crate::asset::package_index::PackageIndex;
use crate::asset::summary::PackageSummary;
use crate::asset::version::AssetVersion;

/// Materialized minimal package — bytes plus the structurally-equal
/// `PackageSummary` / `NameTable` / `ImportTable` / `ExportTable` the
/// bytes encode. Tests compare against these tables verbatim; the
/// caller does not need to rebuild them in test code.
pub struct MinimalPackage {
    /// Serialized .uasset blob: summary, name table, import table,
    /// export table records, then the export payload.
    pub bytes: Vec<u8>,
    /// `PackageSummary` structurally equal to what re-parsing `bytes`
    /// produces — including the offsets patched in during assembly.
    pub summary: PackageSummary,
    /// 3-entry name table embedded in `bytes`.
    pub names: NameTable,
    /// 1-entry import table embedded in `bytes`.
    pub imports: ImportTable,
    /// 1-entry export table embedded in `bytes` (record's
    /// `serial_offset` is patched to point at `payload`'s start).
    pub exports: ExportTable,
    /// Opaque 16-byte export payload (`[0xAA; 16]`).
    pub payload: Vec<u8>,
}

/// Build a minimal UE 4.27 .uasset blob: 3 names
/// (`"/Script/CoreUObject"`, `"Package"`, `"Default__Object"`), 1
/// import (`/Script/CoreUObject Package Default__Object`, Null outer),
/// 1 export (class = Import(0), 16-byte opaque payload).
///
/// Offset layout is computed up front using
/// `EXPORT_RECORD_SIZE_UE4_27` for the export-table extent (locked at 104
/// bytes by Task 8); the summary is written once with placeholders,
/// measured, then rewritten with the patched offsets — its byte
/// length is invariant under offset patching because every offset is
/// a fixed-width i32.
#[must_use]
#[allow(
    clippy::too_many_lines,
    reason = "test-only wire-format synthesizer: PackageSummary and ObjectExport \
              are 40+- and 20+-field struct literals respectively, and the \
              offset-patching narrative reads more clearly as one linear function \
              than split across helpers that would each need to thread the \
              partially-built state back through"
)]
pub fn build_minimal_ue4_27() -> MinimalPackage {
    let version = AssetVersion {
        legacy_file_version: -7,
        file_version_ue4: 522,
        file_version_ue5: None,
        file_version_licensee_ue4: 0,
    };
    let names = NameTable {
        names: vec![
            FName::new("/Script/CoreUObject"),
            FName::new("Package"),
            FName::new("Default__Object"),
        ],
    };
    let imports = ImportTable {
        imports: vec![ObjectImport {
            class_package_name: 0,
            class_package_number: 0,
            class_name: 1,
            class_name_number: 0,
            outer_index: PackageIndex::Null,
            object_name: 2,
            object_name_number: 0,
            import_optional: None,
        }],
    };
    let payload: Vec<u8> = vec![0xAA; 16];

    let mut exports = ExportTable {
        exports: vec![ObjectExport {
            class_index: PackageIndex::Import(0),
            super_index: PackageIndex::Null,
            template_index: PackageIndex::Null,
            outer_index: PackageIndex::Null,
            object_name: 2,
            object_name_number: 0,
            object_flags: 0,
            serial_size: payload.len() as i64,
            serial_offset: 0,
            forced_export: false,
            not_for_client: false,
            not_for_server: false,
            package_guid: Some(FGuid::from_bytes([0u8; 16])),
            is_inherited_instance: None,
            package_flags: 0,
            not_always_loaded_for_editor_game: false,
            is_asset: true,
            generate_public_hash: None,
            first_export_dependency: -1,
            serialization_before_serialization_count: 0,
            create_before_serialization_count: 0,
            serialization_before_create_count: 0,
            create_before_create_count: 0,
        }],
    };

    let mut summary = PackageSummary {
        version,
        custom_versions: CustomVersionContainer::default(),
        total_header_size: 0,
        folder_name: "None".to_string(),
        // Cooked-game flag — turns off LocalizationId and the
        // FObjectImport.PackageName field in the wire stream.
        // Required for the cooked-only enforcement in PackageSummary.
        package_flags: 0x8000_0000,
        name_count: names.names.len() as i32,
        name_offset: 0,
        soft_object_paths_count: None,
        soft_object_paths_offset: None,
        // UE 4.27 (= UE4 522) is past LOCALIZATION_ID (516), but
        // PKG_FilterEditorOnly is set above, so the field is omitted
        // from the wire stream.
        localization_id: None,
        gatherable_text_data_count: 0,
        gatherable_text_data_offset: 0,
        export_count: exports.exports.len() as i32,
        export_offset: 0,
        import_count: imports.imports.len() as i32,
        import_offset: 0,
        depends_offset: 0,
        soft_package_references_count: 0,
        soft_package_references_offset: 0,
        searchable_names_offset: 0,
        thumbnail_table_offset: 0,
        guid: FGuid::from_bytes([0u8; 16]),
        persistent_guid: FGuid::from_bytes([0u8; 16]),
        generation_count: 1,
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
    };

    // Pre-pass: measure the summary wire size with zero offsets. Every
    // offset slot is fixed-width i32, so size is invariant under
    // offset patching.
    let mut sum_buf = Vec::new();
    summary.write_to(&mut sum_buf).unwrap();
    let summary_end = i32::try_from(sum_buf.len()).unwrap();

    let mut names_buf = Vec::new();
    names.write_to(&mut names_buf).unwrap();
    let mut imports_buf = Vec::new();
    imports.write_to(&mut imports_buf, version).unwrap();
    let exports_size = i32::try_from(EXPORT_RECORD_SIZE_UE4_27 * exports.exports.len()).unwrap();

    summary.name_offset = summary_end;
    summary.import_offset = summary_end + names_buf.len() as i32;
    summary.export_offset = summary.import_offset + imports_buf.len() as i32;
    summary.total_header_size = summary.export_offset + exports_size;

    exports.exports[0].serial_offset = i64::from(summary.total_header_size);

    sum_buf.clear();
    summary.write_to(&mut sum_buf).unwrap();
    assert_eq!(
        i32::try_from(sum_buf.len()).unwrap(),
        summary_end,
        "summary byte size must be stable under offset patching"
    );
    let mut exports_buf = Vec::new();
    exports.write_to(&mut exports_buf, version).unwrap();
    assert_eq!(
        exports_buf.len() as i32,
        exports_size,
        "export records must match EXPORT_RECORD_SIZE_UE4_27"
    );

    let mut bytes = sum_buf;
    bytes.extend_from_slice(&names_buf);
    bytes.extend_from_slice(&imports_buf);
    bytes.extend_from_slice(&exports_buf);
    bytes.extend_from_slice(&payload);

    MinimalPackage {
        bytes,
        summary,
        names,
        imports,
        exports,
        payload,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Sanity test: build the package, then re-parse the summary from
    /// the produced bytes and confirm the structurally-equal summary
    /// matches. Round-trip integrity is the key contract — Tasks 11
    /// and 13 rely on this builder producing byte-perfect outputs.
    #[test]
    fn round_trip_parses_back_to_equal_summary() {
        let pkg = build_minimal_ue4_27();
        let parsed =
            PackageSummary::read_from(&mut Cursor::new(&pkg.bytes), "minimal.uasset").unwrap();
        assert_eq!(parsed, pkg.summary);
    }

    /// Pin the offset-patching contract: every offset in the summary
    /// (name_offset / import_offset / export_offset, plus per-export
    /// serial_offset) must actually point at the corresponding table
    /// data in the produced bytes. The builder's most important
    /// invariant. Catches an offset-arithmetic regression.
    #[test]
    fn patched_offsets_point_at_valid_table_data() {
        let pkg = build_minimal_ue4_27();
        let version = pkg.summary.version;

        let mut cur = Cursor::new(&pkg.bytes);
        let names = NameTable::read_from(
            &mut cur,
            i64::from(pkg.summary.name_offset),
            pkg.summary.name_count,
            "minimal.uasset",
        )
        .unwrap();
        assert_eq!(names, pkg.names);

        let imports = ImportTable::read_from(
            &mut cur,
            i64::from(pkg.summary.import_offset),
            pkg.summary.import_count,
            version,
            "minimal.uasset",
        )
        .unwrap();
        assert_eq!(imports, pkg.imports);

        let exports = ExportTable::read_from(
            &mut cur,
            i64::from(pkg.summary.export_offset),
            pkg.summary.export_count,
            version,
            "minimal.uasset",
        )
        .unwrap();
        assert_eq!(exports, pkg.exports);

        // serial_offset points at payload start.
        let payload_start = exports.exports[0].serial_offset as usize;
        let payload_size = exports.exports[0].serial_size as usize;
        assert_eq!(
            &pkg.bytes[payload_start..payload_start + payload_size],
            &pkg.payload[..]
        );
    }

    /// Determinism: two invocations produce byte-identical output. The
    /// builder uses no HashMap iteration or wall-clock, so this is true
    /// by construction — pinning it explicitly catches any future
    /// nondeterminism (e.g., a contributor adding HashMap-keyed name
    /// resolution) before it makes downstream tests flaky.
    #[test]
    fn build_is_deterministic() {
        assert_eq!(build_minimal_ue4_27().bytes, build_minimal_ue4_27().bytes);
    }
}
