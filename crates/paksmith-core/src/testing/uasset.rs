//! Minimal UE `.uasset` byte synthesizer for Phase-2a tests + the
//! cross-parser fixture matrix.
//!
//! Promoted out of `asset::package`'s test block so that:
//! 1. Phase 2a's integration test (`tests/asset_integration.rs`) and
//!    the unit test inside `asset::package` share one builder rather
//!    than maintaining parallel copies.
//! 2. `paksmith-fixture-gen` can reach this builder via the
//!    `__test_utils` feature without duplicating the wire-format
//!    assembly (mirrors the [`v10`] precedent for the pak FDI).
//!
//! ## Single-builder, multi-fixture
//!
//! Originally hand-tuned for UE 4.27 only. Issue #243 widened the
//! coverage matrix to 13+ boundary / shape / licensee fixtures —
//! enumerated via parameterized [`MinimalPackageSpec`] (see the
//! per-fixture builders [`build_minimal_ue4_27`], [`build_minimal_ue4_504`],
//! etc. below). The wire-format assembly lives in [`build_minimal`];
//! every fixture is one construction of [`MinimalPackageSpec`] +
//! a delegation to that single point.
//!
//! **Stability:** gated behind the `__test_utils` feature; do not
//! depend on this from downstream crates.
//!
//! [`v10`]: super::v10

// All three cast lints allowed module-wide: this is wire-format
// synthesis code for test fixtures. Casts are `usize → u32/i32`
// for length prefixes, `u32 → i32` for the sign-prefixed FString
// shape, and `i32 → u32` for offsets known non-negative by
// construction. Test inputs are compile-time-bounded; the truncation/
// wrap/sign-loss only triggers at fixture sizes far beyond any
// realistic test case (`> u32::MAX` entries, etc.). Per-site
// `#[allow]`s would all repeat the same "test-fixture synthesis,
// caller-bounded" reasoning.
#![allow(
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

use crate::asset::custom_version::{CustomVersion, CustomVersionContainer};
use crate::asset::engine_version::EngineVersion;
use crate::asset::export_table::{EXPORT_RECORD_SIZE_UE4_27, ExportTable, ObjectExport};
use crate::asset::guid::FGuid;
use crate::asset::import_table::{ImportTable, ObjectImport};
use crate::asset::name_table::{FName, NameTable};
use crate::asset::package_index::PackageIndex;
use crate::asset::summary::PackageSummary;
use crate::asset::version::AssetVersion;

/// Sentinel value substituted for `summary.package_flags` during the
/// summary pre-pass in [`build_minimal`]. The probe writes the
/// summary with this value, scans the buffer for the unique 4-byte
/// pattern to capture `package_flags_offset`, then restores the real
/// flags. `0xDEAD_BEEF` is chosen to be vanishingly unlikely to
/// collide with any other u32 field in FPackageFileSummary.
const PACKAGE_FLAGS_SENTINEL: u32 = 0xDEAD_BEEF;

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
    /// Name table embedded in `bytes`.
    pub names: NameTable,
    /// Import table embedded in `bytes`.
    pub imports: ImportTable,
    /// Export table embedded in `bytes` (each record's `serial_offset`
    /// is patched to point at the corresponding payload start within
    /// the concatenated payload region).
    pub exports: ExportTable,
    /// First export's opaque payload (preserved for back-compat with
    /// the original 1-export builder). When `spec.export_count > 1`,
    /// each export shares this same payload value but is laid out
    /// sequentially in the bytes — see `payloads` for the full set.
    pub payload: Vec<u8>,
    /// All export payloads, in wire order. Always length =
    /// `exports.exports.len()`.
    pub payloads: Vec<Vec<u8>>,
    /// Byte offset of `FPackageFileSummary::PackageFlags` within
    /// `bytes`. Computed during the two-pass header write via a
    /// sentinel-substitution probe in [`build_minimal`]. Phase 2b's
    /// `unversioned_flag_is_rejected` integration test (Task 10) flips
    /// the `0x0000_2000` bit at this offset to assert rejection.
    pub package_flags_offset: usize,
    /// Byte length of the header portion (= `summary.total_header_size`).
    /// Used by [`build_minimal_ue4_27_split`] to cut bytes at the right
    /// boundary between `.uasset` header and `.uexp` payload region.
    pub total_header_size: usize,
}

/// Parameterized package spec — every field maps 1:1 onto a wire-
/// format decision in [`build_minimal`]. Construct via
/// [`MinimalPackageSpec::default`] (which returns the UE 4.27 cooked
/// canonical defaults) and override fields named:
///
/// ```ignore
/// MinimalPackageSpec { file_version_ue4: 504, ..MinimalPackageSpec::default() }
/// ```
///
/// Each new fixture in the issue #243 matrix is one such literal +
/// a thin builder wrapper that delegates to [`build_minimal`].
#[derive(Debug, Clone)]
pub struct MinimalPackageSpec {
    /// `LegacyFileVersion`. UE 4.x = -7; UE 5.0-5.3 = -8; UE 5.4+ = -9.
    pub legacy_file_version: i32,
    /// `FileVersionUE4` wire value (default 522 = UE 4.27).
    pub file_version_ue4: i32,
    /// `FileVersionUE5` wire value. `None` for UE4-only assets
    /// (`legacy_file_version > -8`); `Some(_)` for UE5.
    pub file_version_ue5: Option<i32>,
    /// `FileVersionLicenseeUE4` — non-zero only for licensee
    /// (private-fork) builds.
    pub file_version_licensee_ue4: i32,
    /// Summary-level package flags. Default `0x8000_0000`
    /// (PKG_FilterEditorOnly) — the cooked-game bit.
    pub package_flags: u32,
    /// Names in wire order. Default 3 entries —
    /// `/Script/CoreUObject`, `Package`, `Default__Object`.
    pub names: NameTable,
    /// Imports in wire order. Default 1 entry referencing the default
    /// name table.
    pub imports: ImportTable,
    /// Exports in wire order. Default 1 entry. Each export's
    /// `serial_size` is honored verbatim; `serial_offset` is patched
    /// by [`build_minimal`].
    pub exports: ExportTable,
    /// Custom-version container — usually empty. Set to a non-empty
    /// `CustomVersionContainer` to exercise the populated-container
    /// fixture.
    pub custom_versions: CustomVersionContainer,
    /// `saved_by_engine_version`. Defaults to a `0.0.0-0+""` empty
    /// engine version (matches the original UE 4.27 fixture's
    /// equivalent of an empty cooked stamp).
    pub saved_by_engine_version: EngineVersion,
    /// `compatible_with_engine_version`. Same default as above.
    pub compatible_with_engine_version: EngineVersion,
    /// `PersistentGuid` — only emitted at UE4 ≥ 518 with
    /// `!PKG_FilterEditorOnly`. The builder validates the gate state.
    pub persistent_guid: Option<FGuid>,
    /// `OwnerPersistentGuid` — only emitted at UE4 ∈ [518, 520) with
    /// `!PKG_FilterEditorOnly`.
    pub owner_persistent_guid: Option<FGuid>,
    /// `LocalizationId` — only at UE4 ≥ 516 with `!PKG_FilterEditorOnly`.
    pub localization_id: Option<String>,
    /// Per-export opaque payload bytes. Each entry is one export's
    /// payload; length must match `exports.exports.len()`. Each
    /// export's `serial_size` should equal `payloads[i].len()`.
    pub payloads: Vec<Vec<u8>>,
}

impl Default for MinimalPackageSpec {
    /// Canonical UE 4.27 cooked baseline. Equivalent to the original
    /// hand-coded `build_minimal_ue4_27()` output.
    fn default() -> Self {
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
        let exports = ExportTable {
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
                script_serialization_start_offset: None,
                script_serialization_end_offset: None,
                first_export_dependency: -1,
                serialization_before_serialization_count: 0,
                create_before_serialization_count: 0,
                serialization_before_create_count: 0,
                create_before_create_count: 0,
            }],
        };

        Self {
            legacy_file_version: -7,
            file_version_ue4: 522,
            file_version_ue5: None,
            file_version_licensee_ue4: 0,
            package_flags: 0x8000_0000,
            names,
            imports,
            exports,
            custom_versions: CustomVersionContainer::default(),
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
            persistent_guid: None,
            owner_persistent_guid: None,
            localization_id: None,
            payloads: vec![payload],
        }
    }
}

/// Construct the parameterized package and serialize to bytes.
///
/// Layout:
/// 1. Summary (versioned, every offset patched).
/// 2. Name table.
/// 3. Import table.
/// 4. Export table records (each `serial_offset` patched to point at
///    the corresponding payload offset).
/// 5. Per-export payload bytes (concatenated in wire order).
///
/// # Panics
/// - If `spec.payloads.len() != spec.exports.exports.len()`.
/// - If any `spec.exports.exports[i].serial_size != spec.payloads[i].len()`.
#[must_use]
#[allow(
    clippy::too_many_lines,
    reason = "test-only wire-format synthesizer: summary + table assembly + \
              offset patching reads more clearly as one linear function than \
              split across helpers that would each need to thread the \
              partially-built state back through"
)]
pub fn build_minimal(spec: MinimalPackageSpec) -> MinimalPackage {
    assert_eq!(
        spec.payloads.len(),
        spec.exports.exports.len(),
        "payloads.len() must equal exports.exports.len()"
    );
    for (i, (export, payload)) in spec
        .exports
        .exports
        .iter()
        .zip(spec.payloads.iter())
        .enumerate()
    {
        assert_eq!(
            export.serial_size as usize,
            payload.len(),
            "exports[{i}].serial_size ({}) must equal payloads[{i}].len() ({})",
            export.serial_size,
            payload.len()
        );
    }

    let version = AssetVersion {
        legacy_file_version: spec.legacy_file_version,
        file_version_ue4: spec.file_version_ue4,
        file_version_ue5: spec.file_version_ue5,
        file_version_licensee_ue4: spec.file_version_licensee_ue4,
    };

    let mut exports = spec.exports;
    let names = spec.names;
    let imports = spec.imports;
    let payloads = spec.payloads;
    let payload_first = payloads.first().cloned().unwrap_or_default();

    // Gate-derived optional fields in the summary. Setting `Some(0)` /
    // `None` symmetrically to read_from's gate avoids the writer's
    // gate-fire panic and keeps the round-trip property structurally
    // exact. Numeric gate floors are inlined here rather than imported
    // from `crate::asset::version` because most of those constants are
    // `pub(crate)`-visible only in core; duplicating the four floors
    // we need keeps this builder buildable from `paksmith-core::testing`
    // without expanding the public surface.
    let searchable_names_offset = if version.ue4_at_least(510) {
        Some(0)
    } else {
        None
    };
    let (preload_dependency_count, preload_dependency_offset) = if version.ue4_at_least(507) {
        (Some(0), Some(0))
    } else {
        (None, None)
    };
    let names_referenced_from_export_data_count = if version.ue5_at_least(1001) {
        Some(0)
    } else {
        None
    };
    let payload_toc_offset = if version.ue5_at_least(1002) {
        Some(0i64)
    } else {
        None
    };
    let data_resource_offset = if version.ue5_at_least(1009) {
        Some(0)
    } else {
        None
    };
    let (soft_object_paths_count, soft_object_paths_offset) = if version.ue5_at_least(1008) {
        (Some(0), Some(0))
    } else {
        (None, None)
    };

    let mut summary = PackageSummary {
        version,
        custom_versions: spec.custom_versions,
        total_header_size: 0,
        folder_name: "None".to_string(),
        package_flags: spec.package_flags,
        name_count: names.names.len() as i32,
        name_offset: 0,
        soft_object_paths_count,
        soft_object_paths_offset,
        localization_id: spec.localization_id,
        gatherable_text_data_count: 0,
        gatherable_text_data_offset: 0,
        export_count: exports.exports.len() as i32,
        export_offset: 0,
        import_count: imports.imports.len() as i32,
        import_offset: 0,
        depends_offset: 0,
        soft_package_references_count: 0,
        soft_package_references_offset: 0,
        searchable_names_offset,
        thumbnail_table_offset: 0,
        guid: FGuid::from_bytes([0u8; 16]),
        persistent_guid: spec.persistent_guid,
        owner_persistent_guid: spec.owner_persistent_guid,
        generation_count: 1,
        saved_by_engine_version: spec.saved_by_engine_version,
        compatible_with_engine_version: spec.compatible_with_engine_version,
        package_source: 0,
        asset_registry_data_offset: 0,
        bulk_data_start_offset: 0,
        world_tile_info_data_offset: 0,
        preload_dependency_count,
        preload_dependency_offset,
        names_referenced_from_export_data_count,
        payload_toc_offset,
        data_resource_offset,
    };

    // Pre-pass: measure the summary wire size with zero offsets. Every
    // offset slot is fixed-width i32, so size is invariant under
    // offset patching.
    //
    // The `package_flags` u32 offset is captured via a sentinel
    // substitution: write the summary with a unique sentinel in
    // `package_flags`, scan the buffer for it, then restore the real
    // value. This keeps the offset computation robust against
    // FPackageFileSummary layout changes that could happen between
    // versions.
    let real_package_flags = summary.package_flags;
    summary.package_flags = PACKAGE_FLAGS_SENTINEL;
    let mut sum_buf = Vec::new();
    summary.write_to(&mut sum_buf).unwrap();
    let sentinel_bytes = PACKAGE_FLAGS_SENTINEL.to_le_bytes();
    let package_flags_offset = sum_buf
        .windows(4)
        .position(|w| w == sentinel_bytes)
        .expect("package_flags sentinel must appear in summary bytes");
    // Verify uniqueness — `0xDEAD_BEEF` is chosen to be vanishingly
    // unlikely to clash with other summary u32 fields, but assert it
    // so a future field addition that accidentally matches surfaces
    // immediately rather than producing a silently-wrong offset.
    let other = sum_buf
        .windows(4)
        .enumerate()
        .filter(|(_, w)| *w == sentinel_bytes)
        .count();
    assert_eq!(
        other, 1,
        "package_flags sentinel collided with another summary field; pick a fresh sentinel"
    );
    summary.package_flags = real_package_flags;
    sum_buf.clear();
    summary.write_to(&mut sum_buf).unwrap();
    let summary_end = i32::try_from(sum_buf.len()).unwrap();

    let mut names_buf = Vec::new();
    names.write_to(&mut names_buf).unwrap();
    let mut imports_buf = Vec::new();
    imports.write_to(&mut imports_buf, version).unwrap();

    // Each export record's wire size depends on the version gates; we
    // measure once by serializing with placeholder serial_offsets, then
    // re-serialize after patching. The pre-pass mirrors the summary
    // pre-pass: total size is invariant under offset patching (every
    // serial_offset slot is fixed-width).
    let mut probe_exports_buf = Vec::new();
    exports
        .write_to(&mut probe_exports_buf, version, summary.package_flags)
        .unwrap();
    let exports_size = i32::try_from(probe_exports_buf.len()).unwrap();

    summary.name_offset = summary_end;
    summary.import_offset = summary_end + names_buf.len() as i32;
    summary.export_offset = summary.import_offset + imports_buf.len() as i32;
    summary.total_header_size = summary.export_offset + exports_size;

    // Patch per-export serial_offset to point at the corresponding
    // payload's start within the post-header payload region.
    let mut running_payload_offset = i64::from(summary.total_header_size);
    for (export, payload) in exports.exports.iter_mut().zip(payloads.iter()) {
        export.serial_offset = running_payload_offset;
        running_payload_offset += payload.len() as i64;
    }

    sum_buf.clear();
    summary.write_to(&mut sum_buf).unwrap();
    assert_eq!(
        i32::try_from(sum_buf.len()).unwrap(),
        summary_end,
        "summary byte size must be stable under offset patching"
    );
    let mut exports_buf = Vec::new();
    exports
        .write_to(&mut exports_buf, version, summary.package_flags)
        .unwrap();
    assert_eq!(
        exports_buf.len() as i32,
        exports_size,
        "export records must match measured pre-pass size",
    );

    let mut bytes = sum_buf;
    bytes.extend_from_slice(&names_buf);
    bytes.extend_from_slice(&imports_buf);
    bytes.extend_from_slice(&exports_buf);
    for payload in &payloads {
        bytes.extend_from_slice(payload);
    }

    let total_header_size = summary.total_header_size as usize;
    MinimalPackage {
        bytes,
        summary,
        names,
        imports,
        exports,
        payload: payload_first,
        payloads,
        package_flags_offset,
        total_header_size,
    }
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
///
/// Thin wrapper over [`build_minimal`] for backward-compat with call
/// sites that don't care about variation. The output bytes are
/// byte-identical to the pre-#243 builder (pinned by
/// `crates/paksmith-core/tests/fixture_anchor.rs`'s SHA1 anchor on
/// `real_v8b_uasset.pak`, which embeds this fixture).
#[must_use]
pub fn build_minimal_ue4_27() -> MinimalPackage {
    let pkg = build_minimal(MinimalPackageSpec::default());
    // Sanity: pre-#243 builder always produced a 104-byte export
    // record at UE 4.27 cooked. Keep the assertion here so a future
    // change to `MinimalPackageSpec::default()` that violates the
    // baseline shape trips this rather than a downstream anchor test.
    debug_assert_eq!(
        pkg.exports.exports.len(),
        1,
        "UE 4.27 canonical fixture must have exactly 1 export"
    );
    let _ = EXPORT_RECORD_SIZE_UE4_27;
    pkg
}

/// Returns `(uasset_header_bytes, uexp_payload_bytes)` — the split form of the
/// standard Phase 2a minimal fixture.
///
/// `uasset_header_bytes.len() == pkg.total_header_size`. The two slices
/// concatenated produce identical bytes to `build_minimal_ue4_27().bytes`, so
/// parsing `read_from(uasset, Some(uexp), _)` gives the same result as
/// `read_from(&full, None, _)`.
#[must_use]
pub fn build_minimal_ue4_27_split() -> (Vec<u8>, Vec<u8>) {
    let pkg = build_minimal_ue4_27();
    let split_at = pkg.total_header_size;
    debug_assert!(
        split_at <= pkg.bytes.len(),
        "total_header_size {split_at} > bytes.len() {} — builder bug",
        pkg.bytes.len()
    );
    (
        pkg.bytes[..split_at].to_vec(),
        pkg.bytes[split_at..].to_vec(),
    )
}

// ─── FPropertyTag wire-format write helpers (Phase 2b Task 9) ────────
//
// Indices into the property-bearing name table (set by
// `build_minimal_ue4_27_with_properties`). The first three entries
// match the canonical fixture (so the cooked Package import can
// resolve through `unreal_asset`), and the rest are the property
// type/name FNames the iterator references.
//
//   0 = "/Script/CoreUObject"   3 = "Hero"
//   1 = "Package"               4 = "bEnabled"
//   2 = "Default__Object"       5 = "BoolProperty"
//                               6 = "MaxSpeed"
//                               7 = "FloatProperty"
//                               8 = "ObjectName"
//                               9 = "StrProperty"

/// Write a wire-format FName `(index, number)` pair to `buf`.
fn write_fname_pair(buf: &mut Vec<u8>, index: i32, number: i32) {
    buf.extend_from_slice(&index.to_le_bytes());
    buf.extend_from_slice(&number.to_le_bytes());
}

/// Write a `BoolProperty` FPropertyTag (header carries `boolVal`; no
/// payload bytes follow because `tag.size == 0`).
fn write_bool_property_tag(buf: &mut Vec<u8>, name_idx: i32, type_idx: i32, value: bool) {
    write_fname_pair(buf, name_idx, 0); // Name
    write_fname_pair(buf, type_idx, 0); // Type: BoolProperty
    buf.extend_from_slice(&0i32.to_le_bytes()); // Size: 0
    buf.extend_from_slice(&0i32.to_le_bytes()); // ArrayIndex: 0
    buf.push(u8::from(value)); // boolVal
    buf.push(0u8); // HasPropertyGuid: 0
}

/// Write a `FloatProperty` FPropertyTag + 4-byte LE payload.
fn write_float_property_tag(buf: &mut Vec<u8>, name_idx: i32, type_idx: i32, value: f32) {
    write_fname_pair(buf, name_idx, 0);
    write_fname_pair(buf, type_idx, 0);
    buf.extend_from_slice(&4i32.to_le_bytes()); // Size: 4
    buf.extend_from_slice(&0i32.to_le_bytes()); // ArrayIndex: 0
    buf.push(0u8); // HasPropertyGuid: 0
    buf.extend_from_slice(&value.to_le_bytes()); // payload
}

/// Write a `StrProperty` FPropertyTag + FString payload.
fn write_str_property_tag(buf: &mut Vec<u8>, name_idx: i32, type_idx: i32, value: &str) {
    let bytes = value.as_bytes();
    // FString wire: i32 length-incl-null + bytes + null terminator
    let fstring_size = 4 + bytes.len() + 1;
    write_fname_pair(buf, name_idx, 0);
    write_fname_pair(buf, type_idx, 0);
    buf.extend_from_slice(&i32::try_from(fstring_size).unwrap().to_le_bytes()); // Size
    buf.extend_from_slice(&0i32.to_le_bytes()); // ArrayIndex
    buf.push(0u8); // HasPropertyGuid
    buf.extend_from_slice(&i32::try_from(bytes.len() + 1).unwrap().to_le_bytes());
    buf.extend_from_slice(bytes);
    buf.push(0u8); // null terminator
}

/// Write the `"None"` FPropertyTag terminator (`(0, 0)` FName).
fn write_none_terminator(buf: &mut Vec<u8>) {
    buf.extend_from_slice(&0i32.to_le_bytes()); // index 0 = "None"
    buf.extend_from_slice(&0i32.to_le_bytes()); // number 0
}

/// Write an `ObjectProperty` FPropertyTag + 4-byte LE `PackageIndex` payload.
///
/// The wire layout matches `read_tag` in `property/tag.rs` and the other
/// `write_*_property_tag` helpers in this module:
/// - Name FName (8 bytes: i32 index, i32 number)
/// - Type FName (8 bytes)
/// - Size **i32** = 4 (not i64; `read_tag` uses `read_i32`)
/// - ArrayIndex i32 = 0
/// - HasPropertyGuid u8 = 0
/// - Value i32 = `raw_index` (the wire `PackageIndex` value: `-1` = `Import(0)`,
///   `0` = `Null`, `+1` = `Export(0)`)
fn write_object_property_tag(buf: &mut Vec<u8>, name_idx: i32, type_idx: i32, raw_index: i32) {
    write_fname_pair(buf, name_idx, 0); // Name
    write_fname_pair(buf, type_idx, 0); // Type: ObjectProperty
    buf.extend_from_slice(&4i32.to_le_bytes()); // Size: 4 (i32, not i64)
    buf.extend_from_slice(&0i32.to_le_bytes()); // ArrayIndex: 0
    buf.push(0u8); // HasPropertyGuid: 0
    buf.extend_from_slice(&raw_index.to_le_bytes()); // PackageIndex i32
}

/// Build a minimal UE 4.27 package whose single export's payload is a
/// real tagged-property stream of three known primitives:
///
/// - `bEnabled = true` (`BoolProperty`)
/// - `MaxSpeed = 1500.0` (`FloatProperty`)
/// - `ObjectName = "Hero_C"` (`StrProperty`)
///
/// The name table is extended to 8 entries (the property type/name
/// FNames must exist in the pool for `resolve_fname` to find them).
/// The export's `serial_size` is set to the constructed payload's
/// byte length, so the iterator's `export_end` bound is honoured.
///
/// Returns a [`MinimalPackage`] whose `payloads[0]` will decode under
/// `Package::read_from` as `PropertyBag::Tree` with exactly three
/// `Property` entries (Phase 2b).
#[must_use]
pub fn build_minimal_ue4_27_with_properties() -> MinimalPackage {
    // Build the property payload first so we can derive serial_size.
    // Property name indices reference the 10-entry name table below.
    let mut payload = Vec::new();
    write_bool_property_tag(&mut payload, 4, 5, true); // bEnabled (4) : BoolProperty (5)
    write_float_property_tag(&mut payload, 6, 7, 1500.0); // MaxSpeed (6) : FloatProperty (7)
    write_str_property_tag(&mut payload, 8, 9, "Hero_C"); // ObjectName (8) : StrProperty (9)
    write_none_terminator(&mut payload);

    let names = NameTable {
        names: vec![
            FName::new("/Script/CoreUObject"),
            FName::new("Package"),
            FName::new("Default__Object"),
            FName::new("Hero"),
            FName::new("bEnabled"),
            FName::new("BoolProperty"),
            FName::new("MaxSpeed"),
            FName::new("FloatProperty"),
            FName::new("ObjectName"),
            FName::new("StrProperty"),
        ],
    };

    // Keep the canonical 1-import shape so `unreal_asset` can classify
    // the export as a NormalExport (which is what carries the
    // properties Vec). With a Null class, unreal_asset falls back to a
    // RawExport variant that has no `properties` field, which would
    // make cross-validation impossible.
    let imports = ImportTable {
        imports: vec![ObjectImport {
            class_package_name: 0, // "/Script/CoreUObject"
            class_package_number: 0,
            class_name: 1, // "Package"
            class_name_number: 0,
            outer_index: PackageIndex::Null,
            object_name: 2, // "Default__Object"
            object_name_number: 0,
            import_optional: None,
        }],
    };

    let exports = ExportTable {
        exports: vec![ObjectExport {
            class_index: PackageIndex::Import(0),
            super_index: PackageIndex::Null,
            template_index: PackageIndex::Null,
            outer_index: PackageIndex::Null,
            object_name: 3, // "Hero"
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
            script_serialization_start_offset: None,
            script_serialization_end_offset: None,
            first_export_dependency: -1,
            serialization_before_serialization_count: 0,
            create_before_serialization_count: 0,
            serialization_before_create_count: 0,
            create_before_create_count: 0,
        }],
    };

    build_minimal(MinimalPackageSpec {
        names,
        imports,
        exports,
        payloads: vec![payload],
        ..MinimalPackageSpec::default()
    })
}

/// Build a minimal UE 4.27 package whose single export carries one
/// `ObjectProperty` named `"ObjRef"` with wire `i32 = -1`
/// (`PackageIndex::Import(0)`). Returns `(bytes, expected_resolved_name)`
/// where the expected name is the import's bare `object_name` FName —
/// the same string `resolve_package_index` returns from `Phase 2e`'s
/// `PropertyValue::Object { name, .. }` (see `property/primitives.rs`).
///
/// The name table places the import target string at index 2 so the
/// import's `object_name` resolves to `"/Game/Data/Mesh.StaticMesh"`.
#[must_use]
pub fn build_minimal_ue4_27_with_object_ref() -> (Vec<u8>, String) {
    // Name table layout:
    //   0 = "/Script/CoreUObject"   3 = "ObjRef"
    //   1 = "Package"               4 = "ObjectProperty"
    //   2 = "/Game/Data/Mesh.StaticMesh"
    let mut payload: Vec<u8> = Vec::new();
    // Wire i32 = -1 → PackageIndex::Import(0). The property iterator
    // resolves this against ImportTable[0].object_name (index 2).
    write_object_property_tag(&mut payload, 3, 4, -1);
    write_none_terminator(&mut payload);

    let import_name = "/Game/Data/Mesh.StaticMesh".to_string();

    let names = NameTable {
        names: vec![
            FName::new("/Script/CoreUObject"),
            FName::new("Package"),
            FName::new(&import_name),
            FName::new("ObjRef"),
            FName::new("ObjectProperty"),
        ],
    };
    let imports = ImportTable {
        imports: vec![ObjectImport {
            class_package_name: 0, // "/Script/CoreUObject"
            class_package_number: 0,
            class_name: 1, // "Package"
            class_name_number: 0,
            outer_index: PackageIndex::Null,
            object_name: 2, // "/Game/Data/Mesh.StaticMesh"
            object_name_number: 0,
            import_optional: None,
        }],
    };
    let exports = ExportTable {
        exports: vec![ObjectExport {
            class_index: PackageIndex::Import(0),
            super_index: PackageIndex::Null,
            template_index: PackageIndex::Null,
            outer_index: PackageIndex::Null,
            object_name: 0,
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
            script_serialization_start_offset: None,
            script_serialization_end_offset: None,
            first_export_dependency: -1,
            serialization_before_serialization_count: 0,
            create_before_serialization_count: 0,
            serialization_before_create_count: 0,
            create_before_create_count: 0,
        }],
    };

    let pkg = build_minimal(MinimalPackageSpec {
        names,
        imports,
        exports,
        payloads: vec![payload],
        ..MinimalPackageSpec::default()
    });
    (pkg.bytes, import_name)
}

/// Build a minimal UE 4.27 package whose single export carries one
/// `ObjectProperty` named `"NullRef"` with wire `i32 = 0`
/// (`PackageIndex::Null`). The resolved `name` field on the decoded
/// `PropertyValue::Object` is the empty string per
/// `resolve_package_index`'s null-handling contract.
///
/// The import table is inherited from `MinimalPackageSpec::default()`
/// (one entry referencing names 0/1/2, which line up with this builder's
/// name table). The export's `class_index = Import(0)` resolves against
/// that default import.
#[must_use]
pub fn build_minimal_ue4_27_with_null_object_ref() -> Vec<u8> {
    // Name table layout (default import expects names 0/1/2 here):
    //   0 = "/Script/CoreUObject"   3 = "NullRef"
    //   1 = "Package"               4 = "ObjectProperty"
    //   2 = "Default__Object"
    let mut payload: Vec<u8> = Vec::new();
    // Wire i32 = 0 → PackageIndex::Null. The resolved `name` is "".
    write_object_property_tag(&mut payload, 3, 4, 0);
    write_none_terminator(&mut payload);

    let names = NameTable {
        names: vec![
            FName::new("/Script/CoreUObject"),
            FName::new("Package"),
            FName::new("Default__Object"),
            FName::new("NullRef"),
            FName::new("ObjectProperty"),
        ],
    };
    let exports = ExportTable {
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
            script_serialization_start_offset: None,
            script_serialization_end_offset: None,
            first_export_dependency: -1,
            serialization_before_serialization_count: 0,
            create_before_serialization_count: 0,
            serialization_before_create_count: 0,
            create_before_create_count: 0,
        }],
    };

    build_minimal(MinimalPackageSpec {
        names,
        exports,
        payloads: vec![payload],
        ..MinimalPackageSpec::default()
    })
    .bytes
}

/// Builds a synthetic UAsset (UE 4.27, fileVersionUE4=522) whose
/// single export body contains four container properties followed
/// by a None terminator.
///
/// Export property layout:
/// - `Tags: ArrayProperty<IntProperty>` = `[10, 20]`
/// - `Stats: StructProperty<StatStruct>` = `{ Speed: FloatProperty = 600.0 }`
/// - `Lookup: MapProperty<StrProperty, IntProperty>` = `{ "alpha" -> 1 }`
/// - `Flags: SetProperty<NameProperty>` = `{ "Tag_A", "Tag_B" }`
/// - None terminator
#[must_use]
#[allow(
    clippy::too_many_lines,
    reason = "hand-written wire-format construction for four container shapes + 19-entry name table + import/export records; splitting per-property would obscure the layout"
)]
pub fn build_minimal_ue4_27_with_containers() -> MinimalPackage {
    let mut body: Vec<u8> = Vec::new();

    // Inline FString writer for map keys (no tag header).
    let write_fstring = |buf: &mut Vec<u8>, s: &str| {
        let with_null = format!("{s}\0");
        let len = i32::try_from(with_null.len()).expect("fixture FString fits in i32");
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(with_null.as_bytes());
    };

    // --- Property 1: Tags: ArrayProperty<IntProperty> = [10, 20] ---
    write_fname_pair(&mut body, 3, 0); // Name: Tags
    write_fname_pair(&mut body, 4, 0); // Type: ArrayProperty
    body.extend_from_slice(&12i32.to_le_bytes()); // Size: 4 (count) + 2*4 (elements)
    body.extend_from_slice(&0i32.to_le_bytes()); // ArrayIndex
    write_fname_pair(&mut body, 5, 0); // InnerType: IntProperty
    body.push(0u8); // HasPropertyGuid
    body.extend_from_slice(&2i32.to_le_bytes()); // count
    body.extend_from_slice(&10i32.to_le_bytes());
    body.extend_from_slice(&20i32.to_le_bytes());

    // --- Property 2: Stats: StructProperty<StatStruct> = { Speed: 600.0 } ---
    let mut struct_body: Vec<u8> = Vec::new();
    write_float_property_tag(&mut struct_body, 15, 16, 600.0);
    write_none_terminator(&mut struct_body);
    let struct_body_size = i32::try_from(struct_body.len()).expect("struct body fits in i32");

    write_fname_pair(&mut body, 6, 0); // Name: Stats
    write_fname_pair(&mut body, 7, 0); // Type: StructProperty
    body.extend_from_slice(&struct_body_size.to_le_bytes()); // Size
    body.extend_from_slice(&0i32.to_le_bytes()); // ArrayIndex
    write_fname_pair(&mut body, 8, 0); // StructName: StatStruct
    body.extend_from_slice(&[0u8; 16]); // StructGuid (zeroed)
    body.push(0u8); // HasPropertyGuid
    body.extend_from_slice(&struct_body);

    // --- Property 3: Lookup: MapProperty<StrProperty, IntProperty> = { "alpha" -> 1 } ---
    let mut map_body: Vec<u8> = Vec::new();
    map_body.extend_from_slice(&0i32.to_le_bytes()); // num_to_remove
    map_body.extend_from_slice(&1i32.to_le_bytes()); // count
    write_fstring(&mut map_body, "alpha"); // key
    map_body.extend_from_slice(&1i32.to_le_bytes()); // value
    let map_body_size = i32::try_from(map_body.len()).expect("map body fits in i32");

    write_fname_pair(&mut body, 9, 0); // Name: Lookup
    write_fname_pair(&mut body, 10, 0); // Type: MapProperty
    body.extend_from_slice(&map_body_size.to_le_bytes());
    body.extend_from_slice(&0i32.to_le_bytes()); // ArrayIndex
    write_fname_pair(&mut body, 11, 0); // InnerType (key): StrProperty
    write_fname_pair(&mut body, 5, 0); // ValueType: IntProperty
    body.push(0u8); // HasPropertyGuid
    body.extend_from_slice(&map_body);

    // --- Property 4: Flags: SetProperty<NameProperty> = { "Tag_A", "Tag_B" } ---
    let mut set_body: Vec<u8> = Vec::new();
    set_body.extend_from_slice(&0i32.to_le_bytes()); // num_to_remove
    set_body.extend_from_slice(&2i32.to_le_bytes()); // count
    write_fname_pair(&mut set_body, 17, 0); // Tag_A
    write_fname_pair(&mut set_body, 18, 0); // Tag_B
    let set_body_size = i32::try_from(set_body.len()).expect("set body fits in i32");

    write_fname_pair(&mut body, 12, 0); // Name: Flags
    write_fname_pair(&mut body, 13, 0); // Type: SetProperty
    body.extend_from_slice(&set_body_size.to_le_bytes());
    body.extend_from_slice(&0i32.to_le_bytes()); // ArrayIndex
    write_fname_pair(&mut body, 14, 0); // InnerType: NameProperty
    body.push(0u8); // HasPropertyGuid
    body.extend_from_slice(&set_body);

    // None terminator for the export
    write_none_terminator(&mut body);

    let names = NameTable {
        names: vec![
            FName::new("/Script/CoreUObject"),
            FName::new("Package"),
            FName::new("Default__Object"),
            FName::new("Tags"),
            FName::new("ArrayProperty"),
            FName::new("IntProperty"),
            FName::new("Stats"),
            FName::new("StructProperty"),
            FName::new("StatStruct"),
            FName::new("Lookup"),
            FName::new("MapProperty"),
            FName::new("StrProperty"),
            FName::new("Flags"),
            FName::new("SetProperty"),
            FName::new("NameProperty"),
            FName::new("Speed"),
            FName::new("FloatProperty"),
            FName::new("Tag_A"),
            FName::new("Tag_B"),
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

    let serial_size = i64::try_from(body.len()).expect("body fits in i64");
    let exports = ExportTable {
        exports: vec![ObjectExport {
            class_index: PackageIndex::Import(0),
            super_index: PackageIndex::Null,
            template_index: PackageIndex::Null,
            outer_index: PackageIndex::Null,
            object_name: 3,
            object_name_number: 0,
            object_flags: 0,
            serial_size,
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
            script_serialization_start_offset: None,
            script_serialization_end_offset: None,
            first_export_dependency: -1,
            serialization_before_serialization_count: 0,
            create_before_serialization_count: 0,
            serialization_before_create_count: 0,
            create_before_create_count: 0,
        }],
    };

    build_minimal(MinimalPackageSpec {
        names,
        imports,
        exports,
        payloads: vec![body],
        ..MinimalPackageSpec::default()
    })
}

/// Builds a synthetic UAsset (UE 4.27, fileVersionUE4=522) whose single
/// export body contains six properties covering Phase 2d extended types,
/// followed by a None terminator.
///
/// Export property layout:
/// - `SoftRef: SoftObjectProperty` = `("/Game/Data/Hero.Hero", "")`
/// - `SoftClass: SoftClassProperty` = `("/Game/BP/HeroClass.HeroClass_C", "")`
/// - `ObjRef: ObjectProperty` = `-1` (decodes to `PackageIndex::Import(0)`)
/// - `Tags: ArrayProperty<ByteProperty>` = `[10, 20]`
/// - `Flags: ArrayProperty<EnumProperty>` = `["EColor__Red"]`
/// - `Desc: ArrayProperty<TextProperty>` = `[FText::None]`
///
/// Name table (indices 0..=2 reserved for the cooked-Package import):
///   0=/Script/CoreUObject, 1=Package, 2=Default__Object,
///   3=SoftRef, 4=SoftObjectProperty, 5=/Game/Data/Hero.Hero,
///   6=SoftClass, 7=SoftClassProperty, 8=/Game/BP/HeroClass.HeroClass_C,
///   9=ObjRef, 10=ObjectProperty, 11=Tags, 12=ArrayProperty,
///   13=ByteProperty, 14=Flags, 15=EnumProperty, 16=EColor__Red,
///   17=Desc, 18=TextProperty, 19=Hero
#[must_use]
#[allow(
    clippy::too_many_lines,
    reason = "hand-written wire-format construction for six property shapes + 20-entry name table + import/export records; splitting per-property would obscure the layout"
)]
pub fn build_minimal_ue4_27_with_extended_types() -> MinimalPackage {
    let mut body: Vec<u8> = Vec::new();

    // --- Property 1: SoftRef: SoftObjectProperty
    // payload = FName(asset_path) [8 bytes] + FString("") [4+1=5 bytes] = 13 bytes
    {
        write_fname_pair(&mut body, 3, 0); // Name: SoftRef
        write_fname_pair(&mut body, 4, 0); // Type: SoftObjectProperty
        body.extend_from_slice(&13i32.to_le_bytes()); // Size
        body.extend_from_slice(&0i32.to_le_bytes()); // ArrayIndex
        body.push(0u8); // HasPropertyGuid
        // FName asset_path = "/Game/Data/Hero.Hero" (idx 5)
        write_fname_pair(&mut body, 5, 0);
        // FString sub_path = ""
        body.extend_from_slice(&1i32.to_le_bytes());
        body.push(0u8);
    }

    // --- Property 2: SoftClass: SoftClassProperty (same shape, idx 8)
    {
        write_fname_pair(&mut body, 6, 0); // Name: SoftClass
        write_fname_pair(&mut body, 7, 0); // Type: SoftClassProperty
        body.extend_from_slice(&13i32.to_le_bytes());
        body.extend_from_slice(&0i32.to_le_bytes());
        body.push(0u8);
        write_fname_pair(&mut body, 8, 0); // FName asset_path
        body.extend_from_slice(&1i32.to_le_bytes());
        body.push(0u8);
    }

    // --- Property 3: ObjRef: ObjectProperty = -1
    {
        write_fname_pair(&mut body, 9, 0); // Name: ObjRef
        write_fname_pair(&mut body, 10, 0); // Type: ObjectProperty
        body.extend_from_slice(&4i32.to_le_bytes()); // Size: 4
        body.extend_from_slice(&0i32.to_le_bytes()); // ArrayIndex
        body.push(0u8); // HasPropertyGuid
        body.extend_from_slice(&(-1i32).to_le_bytes()); // raw -1 → Import(0)
    }

    // --- Property 4: Tags: ArrayProperty<ByteProperty> = [10, 20]
    // payload = i32 count + 2*u8 = 6 bytes
    {
        write_fname_pair(&mut body, 11, 0); // Name: Tags
        write_fname_pair(&mut body, 12, 0); // Type: ArrayProperty
        body.extend_from_slice(&6i32.to_le_bytes());
        body.extend_from_slice(&0i32.to_le_bytes());
        write_fname_pair(&mut body, 13, 0); // InnerType: ByteProperty
        body.push(0u8); // HasPropertyGuid
        body.extend_from_slice(&2i32.to_le_bytes()); // count
        body.push(10u8);
        body.push(20u8);
    }

    // --- Property 5: Flags: ArrayProperty<EnumProperty> = ["EColor__Red"]
    // payload = i32 count + FName(8 bytes) = 12 bytes
    {
        write_fname_pair(&mut body, 14, 0); // Name: Flags
        write_fname_pair(&mut body, 12, 0); // Type: ArrayProperty
        body.extend_from_slice(&12i32.to_le_bytes());
        body.extend_from_slice(&0i32.to_le_bytes());
        write_fname_pair(&mut body, 15, 0); // InnerType: EnumProperty
        body.push(0u8); // HasPropertyGuid
        body.extend_from_slice(&1i32.to_le_bytes()); // count
        write_fname_pair(&mut body, 16, 0); // EColor__Red
    }

    // --- Property 6: Desc: ArrayProperty<TextProperty> = [FText::None]
    // FText element = u32 flags + i8 history_type + u8 has_culture = 6 bytes
    // payload = i32 count + 6 = 10 bytes
    {
        write_fname_pair(&mut body, 17, 0); // Name: Desc
        write_fname_pair(&mut body, 12, 0); // Type: ArrayProperty
        body.extend_from_slice(&10i32.to_le_bytes());
        body.extend_from_slice(&0i32.to_le_bytes());
        write_fname_pair(&mut body, 18, 0); // InnerType: TextProperty
        body.push(0u8); // HasPropertyGuid
        body.extend_from_slice(&1i32.to_le_bytes()); // count
        body.extend_from_slice(&0u32.to_le_bytes()); // flags
        body.push(0xFFu8); // history_type = -1 (None)
        body.push(0u8); // bHasCultureInvariantString = false
    }

    // None terminator
    write_none_terminator(&mut body);

    let names = NameTable {
        names: vec![
            FName::new("/Script/CoreUObject"),
            FName::new("Package"),
            FName::new("Default__Object"),
            FName::new("SoftRef"),
            FName::new("SoftObjectProperty"),
            FName::new("/Game/Data/Hero.Hero"),
            FName::new("SoftClass"),
            FName::new("SoftClassProperty"),
            FName::new("/Game/BP/HeroClass.HeroClass_C"),
            FName::new("ObjRef"),
            FName::new("ObjectProperty"),
            FName::new("Tags"),
            FName::new("ArrayProperty"),
            FName::new("ByteProperty"),
            FName::new("Flags"),
            FName::new("EnumProperty"),
            FName::new("EColor__Red"),
            FName::new("Desc"),
            FName::new("TextProperty"),
            FName::new("Hero"),
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

    let serial_size = i64::try_from(body.len()).expect("body fits in i64");
    let exports = ExportTable {
        exports: vec![ObjectExport {
            class_index: PackageIndex::Import(0),
            super_index: PackageIndex::Null,
            template_index: PackageIndex::Null,
            outer_index: PackageIndex::Null,
            object_name: 19, // "Hero"
            object_name_number: 0,
            object_flags: 0,
            serial_size,
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
            script_serialization_start_offset: None,
            script_serialization_end_offset: None,
            first_export_dependency: -1,
            serialization_before_serialization_count: 0,
            create_before_serialization_count: 0,
            serialization_before_create_count: 0,
            create_before_create_count: 0,
        }],
    };

    build_minimal(MinimalPackageSpec {
        names,
        imports,
        exports,
        payloads: vec![body],
        ..MinimalPackageSpec::default()
    })
}

/// Build a single 1-export `ExportTable` + payload for a UE4 boundary
/// fixture — the shape is shared across the UE4 504/507/510 builders
/// (which only differ in `file_version_ue4`). Keeping the per-record
/// literal in one place keeps the boundary builders to 2-3 lines each.
fn ue4_boundary_single_export(payload: Vec<u8>) -> (ExportTable, Vec<Vec<u8>>) {
    let exports = ExportTable {
        exports: vec![ObjectExport {
            class_index: PackageIndex::Import(0),
            super_index: PackageIndex::Null,
            // template_index defaults to Null. At UE4 < 508 it's absent
            // on the wire (Null in memory); at UE4 ≥ 508 it's emitted
            // (also Null here — matches the default fixture).
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
            script_serialization_start_offset: None,
            script_serialization_end_offset: None,
            // first_export_dependency defaults to -1. At UE4 < 507 the
            // five preload-dep i32s are absent on the wire; at UE4 ≥ 507
            // they're present.
            first_export_dependency: -1,
            serialization_before_serialization_count: 0,
            create_before_serialization_count: 0,
            serialization_before_create_count: 0,
            create_before_create_count: 0,
        }],
    };
    (exports, vec![payload])
}

/// Build a single 1-export `ExportTable` + 1-import `ImportTable` for
/// the UE5 boundary builders. UE5 ≥ 1003 / 1005 / 1006 / 1010 gate the
/// `import_optional`, `package_guid` removal, `is_inherited_instance`,
/// and `script_serialization_*` fields.
fn ue5_1010_export_import(payload: Vec<u8>) -> (ExportTable, ImportTable, Vec<Vec<u8>>) {
    let exports = ExportTable {
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
            // UE5 ≥ 1005 removes per-export package_guid.
            package_guid: None,
            // UE5 ≥ 1006 adds is_inherited_instance.
            is_inherited_instance: Some(false),
            package_flags: 0,
            not_always_loaded_for_editor_game: false,
            is_asset: true,
            // UE5 ≥ 1003 adds generate_public_hash.
            generate_public_hash: Some(false),
            // UE5 1010 + !PKG_UnversionedProperties: both must be Some(_).
            script_serialization_start_offset: Some(0),
            script_serialization_end_offset: Some(0),
            first_export_dependency: -1,
            serialization_before_serialization_count: 0,
            create_before_serialization_count: 0,
            serialization_before_create_count: 0,
            create_before_create_count: 0,
        }],
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
            // UE5 ≥ 1003 adds bImportOptional.
            import_optional: Some(false),
        }],
    };
    (exports, imports, vec![payload])
}

/// UE4 504 — `NAME_HASHES_SERIALIZED` floor. Below the preload-deps,
/// template-index, 64-bit serial-sizes, and searchable-names gates.
/// Validates the lowest accepted UE4 version end-to-end through the
/// summary + export-table readers.
#[must_use]
pub fn build_minimal_ue4_504() -> MinimalPackage {
    let (exports, payloads) = ue4_boundary_single_export(vec![0xAA; 16]);
    build_minimal(MinimalPackageSpec {
        file_version_ue4: 504,
        exports,
        payloads,
        ..MinimalPackageSpec::default()
    })
}

/// UE4 507 — `PRELOAD_DEPENDENCIES_IN_COOKED_EXPORTS` gate fires.
/// Searchable-names (510) and template-index (508) gates still NOT
/// fired. Validates the lower edge of the preload-deps gate
/// independently of higher gates.
#[must_use]
pub fn build_minimal_ue4_507() -> MinimalPackage {
    let (exports, payloads) = ue4_boundary_single_export(vec![0xAA; 16]);
    build_minimal(MinimalPackageSpec {
        file_version_ue4: 507,
        exports,
        payloads,
        ..MinimalPackageSpec::default()
    })
}

/// UE4 510 — `ADDED_SEARCHABLE_NAMES` gate fires (boundary of PR #230).
/// Preload-deps (507) and template-index (508) gates also fire. 64-bit
/// serial-sizes (511) still NOT fired — serial_size/_offset are i32 on
/// the wire.
#[must_use]
pub fn build_minimal_ue4_510() -> MinimalPackage {
    let (exports, payloads) = ue4_boundary_single_export(vec![0xAA; 16]);
    build_minimal(MinimalPackageSpec {
        file_version_ue4: 510,
        exports,
        payloads,
        ..MinimalPackageSpec::default()
    })
}

/// UE4 516 — `ADDED_PACKAGE_SUMMARY_LOCALIZATION_ID` gate fires.
/// Still cooked (`PKG_FilterEditorOnly` set), so the LocalizationId
/// FString is suppressed by the editor-only side of the gate — the
/// fixture validates that the version gate alone doesn't activate the
/// wire field when the cook flag is set.
#[must_use]
pub fn build_minimal_ue4_516() -> MinimalPackage {
    build_minimal(MinimalPackageSpec {
        file_version_ue4: 516,
        // package_flags stays at the cooked default (0x8000_0000) so
        // localization_id is suppressed despite the version gate firing.
        ..MinimalPackageSpec::default()
    })
}

/// UE4 519 — `ADDED_PACKAGE_OWNER` window (`[518, 520)`) — both
/// `PersistentGuid` and `OwnerPersistentGuid` fire (PR #224 boundary).
/// Must be uncooked (`!PKG_FilterEditorOnly`) for the editor-only side
/// of the gate to activate. UE4 519 < 520 keeps the `UncookedAsset`
/// rejection from firing.
#[must_use]
pub fn build_minimal_ue4_519_uncooked() -> MinimalPackage {
    build_minimal(MinimalPackageSpec {
        file_version_ue4: 519,
        package_flags: 0, // PKG_FilterEditorOnly CLEAR
        // localization_id shares the same editor-only gate, so emit
        // Some(_) for round-trip symmetry under UE4 ≥ 516 + uncooked.
        localization_id: Some(String::new()),
        persistent_guid: Some(FGuid::from_bytes([0xBB; 16])),
        owner_persistent_guid: Some(FGuid::from_bytes([0xCC; 16])),
        ..MinimalPackageSpec::default()
    })
}

/// UE5 1010 — `SCRIPT_SERIALIZATION_OFFSET` path (PR #224 fix).
/// `legacy_file_version = -8` with `file_version_ue5 = Some(1010)`
/// and `PKG_UnversionedProperties` CLEAR — exercises the two per-
/// export `script_serialization_{start,end}_offset` i64 fields.
#[must_use]
pub fn build_minimal_ue5_1010() -> MinimalPackage {
    let (exports, imports, payloads) = ue5_1010_export_import(vec![0xAA; 16]);
    let engine = EngineVersion {
        major: 5,
        minor: 0,
        patch: 0,
        changelist: 0,
        branch: "++UE5+Release-5.0".to_string(),
    };
    build_minimal(MinimalPackageSpec {
        legacy_file_version: -8,
        file_version_ue5: Some(1010),
        // file_version_ue4 stays at 522 (UE 4.27) — UE5 packages still
        // carry a UE4 version field for the legacy reader path.
        // PKG_UnversionedProperties = 0x2000 CLEAR by default (only
        // PKG_FilterEditorOnly = 0x8000_0000 is set), so the gate fires.
        exports,
        imports,
        payloads,
        saved_by_engine_version: engine.clone(),
        compatible_with_engine_version: engine,
        ..MinimalPackageSpec::default()
    })
}

/// UE5 with `legacy_file_version = -9` (UE 5.4+ forward-compat).
/// PR #234 widened the accepted window from `{-7, -8}` to
/// `{-7, -8, -9}`; this fixture validates that -9 + UE5 1010 wire
/// bytes are accepted.
#[must_use]
pub fn build_minimal_ue5_legacy_neg9() -> MinimalPackage {
    let (exports, imports, payloads) = ue5_1010_export_import(vec![0xAA; 16]);
    // Same UE5 export-table shape as build_minimal_ue5_1010 — the
    // wire-format differences -9 introduces are at UE5 ≥ 1015 (PACKAGE_SAVED_HASH),
    // above paksmith's Phase 2a ceiling.
    let engine = EngineVersion {
        major: 5,
        minor: 4,
        patch: 0,
        changelist: 0,
        branch: "++UE5+Release-5.4".to_string(),
    };
    build_minimal(MinimalPackageSpec {
        legacy_file_version: -9,
        file_version_ue5: Some(1010),
        exports,
        imports,
        payloads,
        saved_by_engine_version: engine.clone(),
        compatible_with_engine_version: engine,
        ..MinimalPackageSpec::default()
    })
}

// ---------- Shape variation fixtures (UE 4.27, fixtures 8-12) ----------

/// 5-import fixture — each import's `outer_index` points at the next
/// import in the chain, forming a dependency tree terminating in
/// `PackageIndex::Null`. Tests the import-table allocation + multi-
/// record cross-validation paths.
#[must_use]
pub fn build_minimal_multi_import() -> MinimalPackage {
    let names = NameTable {
        names: vec![
            FName::new("/Script/CoreUObject"),
            FName::new("Package"),
            FName::new("Default__Object"),
            FName::new("OuterA"),
            FName::new("OuterB"),
            FName::new("OuterC"),
            FName::new("OuterD"),
        ],
    };
    // 5 imports, chained: Import(0)→Import(1)→Import(2)→Import(3)→Import(4)→Null.
    let imports_vec = (0..5)
        .map(|i| ObjectImport {
            class_package_name: 0,
            class_package_number: 0,
            class_name: 1,
            class_name_number: 0,
            outer_index: if i + 1 < 5 {
                PackageIndex::Import((i + 1) as u32)
            } else {
                PackageIndex::Null
            },
            object_name: (i + 2) as u32, // name indexes 2..=6
            object_name_number: 0,
            import_optional: None,
        })
        .collect();
    build_minimal(MinimalPackageSpec {
        names,
        imports: ImportTable {
            imports: imports_vec,
        },
        ..MinimalPackageSpec::default()
    })
}

/// 5-export fixture — each export's `outer_index` points at the
/// previous export in wire order, with `Export(0).outer_index = Null`.
/// Each export carries a distinct 16-byte payload.
#[must_use]
pub fn build_minimal_multi_export() -> MinimalPackage {
    // 5 distinct payloads, each 16 bytes with a sentinel byte.
    let payloads: Vec<Vec<u8>> = (0..5).map(|i| vec![0xA0u8 | (i as u8); 16]).collect();
    let exports_vec = (0..5)
        .map(|i| ObjectExport {
            class_index: PackageIndex::Import(0),
            super_index: PackageIndex::Null,
            template_index: PackageIndex::Null,
            outer_index: if i == 0 {
                PackageIndex::Null
            } else {
                PackageIndex::Export((i - 1) as u32)
            },
            object_name: 2,
            object_name_number: i as u32,
            object_flags: 0,
            serial_size: payloads[i].len() as i64,
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
            script_serialization_start_offset: None,
            script_serialization_end_offset: None,
            first_export_dependency: -1,
            serialization_before_serialization_count: 0,
            create_before_serialization_count: 0,
            serialization_before_create_count: 0,
            create_before_create_count: 0,
        })
        .collect();
    build_minimal(MinimalPackageSpec {
        exports: ExportTable {
            exports: exports_vec,
        },
        payloads,
        ..MinimalPackageSpec::default()
    })
}

/// Non-empty engine-version branch — exercises the `++UE4+Release-4.27`
/// branch FString in both `saved_by_engine_version` and
/// `compatible_with_engine_version` with a non-zero changelist (the
/// default fixture already has the branch string but the changelist is
/// zero). Validates the non-trivial branch-FString path under
/// independent oracle reading.
#[must_use]
pub fn build_minimal_engine_branch_nonempty() -> MinimalPackage {
    build_minimal(MinimalPackageSpec {
        saved_by_engine_version: EngineVersion {
            major: 4,
            minor: 27,
            patch: 2,
            changelist: 18_319_896,
            branch: "++UE4+Release-4.27".to_string(),
        },
        compatible_with_engine_version: EngineVersion {
            major: 4,
            minor: 27,
            patch: 0,
            changelist: 0,
            branch: "++UE4+Release-4.27".to_string(),
        },
        ..MinimalPackageSpec::default()
    })
}

/// Custom-version container populated with three plausible plugin
/// GUIDs (taken from CUE4Parse's `FCoreObjectVersion`,
/// `FReleaseObjectVersion`, and `FEditorObjectVersion` keys — real
/// GUIDs in UE's source tree). Validates the `CustomVersionContainer`
/// wire path under multi-record load.
#[must_use]
pub fn build_minimal_custom_versions_populated() -> MinimalPackage {
    let custom_versions = CustomVersionContainer {
        versions: vec![
            // FCoreObjectVersion (UE source: CoreObjectVersion.cpp).
            CustomVersion {
                guid: FGuid::from_bytes([
                    0x37, 0x5E, 0xC1, 0x37, 0x6F, 0x12, 0x44, 0x10, 0x84, 0x57, 0x1F, 0xFE, 0x4D,
                    0xC5, 0x9F, 0xA5,
                ]),
                version: 3,
            },
            // FReleaseObjectVersion (UE source: ReleaseObjectVersion.cpp).
            CustomVersion {
                guid: FGuid::from_bytes([
                    0x9C, 0x54, 0xD5, 0x22, 0xA8, 0x26, 0x4F, 0xBE, 0x94, 0x21, 0x07, 0x46, 0x10,
                    0xBF, 0x29, 0xA0,
                ]),
                version: 30,
            },
            // FEditorObjectVersion (UE source: EditorObjectVersion.cpp).
            CustomVersion {
                guid: FGuid::from_bytes([
                    0xE4, 0xB0, 0x68, 0xED, 0xF4, 0x94, 0x42, 0xE9, 0xA2, 0x31, 0xDA, 0x0B, 0x2E,
                    0x46, 0xBB, 0x41,
                ]),
                version: 40,
            },
        ],
    };
    build_minimal(MinimalPackageSpec {
        custom_versions,
        ..MinimalPackageSpec::default()
    })
}

/// `PKG_FilterEditorOnly` CLEAR + non-zero `persistent_guid` at UE4 519
/// — the uncooked-editor-only path. Mirrors `build_minimal_ue4_519_uncooked`
/// but with distinct GUID byte patterns to exercise the field
/// independently of the boundary-version fixture.
#[must_use]
pub fn build_minimal_persistent_guid_nonzero() -> MinimalPackage {
    build_minimal(MinimalPackageSpec {
        file_version_ue4: 519, // ∈ [518, 520) — both GUID gates fire
        package_flags: 0,      // PKG_FilterEditorOnly CLEAR
        localization_id: Some(String::new()),
        // Distinct from the 0xBB/0xCC patterns in build_minimal_ue4_519_uncooked.
        persistent_guid: Some(FGuid::from_bytes([
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
            0xFF, 0x00,
        ])),
        owner_persistent_guid: Some(FGuid::from_bytes([
            0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
            0x11, 0x00,
        ])),
        ..MinimalPackageSpec::default()
    })
}

// ---------- Licensee fixture (PR #234 coverage) ----------

/// Engine-version with the licensee high bit (`0x8000_0000`) set on
/// `changelist`. paksmith's `EngineVersion::masked_changelist()` and
/// `is_licensee_version()` accessors render this as the underlying CL
/// number with the flag exposed separately (see PR #234). The fixture
/// proves the masking works on actual wire bytes (not just unit tests
/// on synthesized `EngineVersion` structs).
#[must_use]
pub fn build_minimal_licensee_engine_version() -> MinimalPackage {
    // 0x8012_3456 = licensee bit set + CL 0x0012_3456 (1193046).
    let cl = 0x8012_3456u32;
    build_minimal(MinimalPackageSpec {
        saved_by_engine_version: EngineVersion {
            major: 4,
            minor: 27,
            patch: 2,
            changelist: cl,
            branch: "++UE4+Release-4.27".to_string(),
        },
        compatible_with_engine_version: EngineVersion {
            major: 4,
            minor: 27,
            patch: 0,
            changelist: cl,
            branch: "++UE4+Release-4.27".to_string(),
        },
        ..MinimalPackageSpec::default()
    })
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
            pkg.summary.package_flags,
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

    /// Every boundary / shape / licensee fixture must round-trip
    /// through paksmith's full `Package::read_from` pipeline — not
    /// just the summary. The two uncooked-PersistentGuid fixtures (#5
    /// and #12) are NOT cross-parser-oracle-validated (see the
    /// `TODO(unreal_asset API gap)` comments in
    /// `crates/paksmith-fixture-gen/src/uasset.rs`); they rely
    /// EXCLUSIVELY on this test for end-to-end validation. Calling
    /// `Package::read_from` (instead of just `PackageSummary::read_from`)
    /// is therefore load-bearing: a wrong cursor position after
    /// reading PersistentGuid + OwnerPersistentGuid would mis-align the
    /// name/import/export table reads downstream, which only the full
    /// pipeline exercises.
    #[test]
    fn matrix_fixtures_round_trip_through_paksmith() {
        use crate::asset::Package;

        for (name, pkg) in [
            ("ue4_504", build_minimal_ue4_504()),
            ("ue4_507", build_minimal_ue4_507()),
            ("ue4_510", build_minimal_ue4_510()),
            ("ue4_516", build_minimal_ue4_516()),
            ("ue4_519_uncooked", build_minimal_ue4_519_uncooked()),
            ("ue5_1010", build_minimal_ue5_1010()),
            ("ue5_legacy_neg9", build_minimal_ue5_legacy_neg9()),
            ("multi_import", build_minimal_multi_import()),
            ("multi_export", build_minimal_multi_export()),
            (
                "engine_branch_nonempty",
                build_minimal_engine_branch_nonempty(),
            ),
            (
                "custom_versions_populated",
                build_minimal_custom_versions_populated(),
            ),
            (
                "persistent_guid_nonzero",
                build_minimal_persistent_guid_nonzero(),
            ),
            (
                "licensee_engine_version",
                build_minimal_licensee_engine_version(),
            ),
        ] {
            let parsed = Package::read_from(&pkg.bytes, None, name)
                .unwrap_or_else(|e| panic!("paksmith Package::read_from for `{name}` failed: {e}"));
            assert_eq!(
                parsed.summary, pkg.summary,
                "summary round-trip mismatch for `{name}`"
            );
            assert_eq!(
                parsed.names, pkg.names,
                "name table round-trip mismatch for `{name}`"
            );
            assert_eq!(
                parsed.imports, pkg.imports,
                "import table round-trip mismatch for `{name}`"
            );
            assert_eq!(
                parsed.exports, pkg.exports,
                "export table round-trip mismatch for `{name}`"
            );
            assert_eq!(
                parsed.payloads.len(),
                pkg.payloads.len(),
                "payload count mismatch for `{name}`"
            );
        }
    }

    /// `build_minimal_ue4_27_with_properties` produces a payload that
    /// `Package::read_from` decodes as `PropertyBag::Tree` with three
    /// known primitive properties (Bool/Float/Str). Pinning this here
    /// catches fixture-builder drift before fixture-gen's cross-
    /// validator runs.
    #[test]
    fn minimal_ue4_27_with_properties_decodes_to_tree() {
        use crate::asset::Package;
        use crate::asset::property::{PropertyBag, PropertyValue};

        let pkg = build_minimal_ue4_27_with_properties();
        let parsed = Package::read_from(&pkg.bytes, None, "test_props.uasset").unwrap();
        assert_eq!(parsed.payloads.len(), 1);
        let props = match &parsed.payloads[0] {
            PropertyBag::Tree { properties } => properties,
            other => panic!("expected PropertyBag::Tree, got {other:?}"),
        };
        assert_eq!(props.len(), 3, "expected 3 properties; got {props:?}");

        let by_name: std::collections::HashMap<&str, &PropertyValue> =
            props.iter().map(|p| (p.name.as_str(), &p.value)).collect();
        assert_eq!(by_name["bEnabled"], &PropertyValue::Bool(true));
        assert_eq!(by_name["MaxSpeed"], &PropertyValue::Float(1500.0));
        assert_eq!(
            by_name["ObjectName"],
            &PropertyValue::Str("Hero_C".to_string())
        );
    }

    /// The split form (header + uexp payload, as two separate byte
    /// vectors) and the monolithic form (concatenated header+payload as
    /// one blob) must produce structurally equivalent parses through
    /// `Package::read_from`. This is the contract `build_minimal_ue4_27_split`
    /// is built around — split at `total_header_size`, the two slices
    /// stitched back together are byte-identical to the monolithic form.
    #[test]
    fn split_plus_monolithic_produce_identical_parse() {
        use crate::asset::Package;

        let monolithic = build_minimal_ue4_27();
        let (uasset, uexp) = build_minimal_ue4_27_split();

        // Both forms should parse to an equivalent package.
        let pkg_mono = Package::read_from(&monolithic.bytes, None, "test.uasset")
            .expect("monolithic parse failed");
        let pkg_split =
            Package::read_from(&uasset, Some(&uexp), "test.uasset").expect("split parse failed");

        // Structural equivalence: same number of exports, same export names.
        // `Package` exposes direct pub fields (`package.rs:60-78`); no accessor.
        assert_eq!(
            pkg_mono.exports.exports.len(),
            pkg_split.exports.exports.len()
        );
        for (m, s) in pkg_mono
            .exports
            .exports
            .iter()
            .zip(pkg_split.exports.exports.iter())
        {
            assert_eq!(m.object_name, s.object_name);
        }
    }

    /// `package_flags_offset` points at the canonical
    /// `0x8000_0000` cooked-game flag value in the assembled bytes,
    /// regardless of the per-spec layout variations.
    #[test]
    fn package_flags_offset_points_at_flag_bytes() {
        let pkg = build_minimal_ue4_27();
        let off = pkg.package_flags_offset;
        let bytes = &pkg.bytes[off..off + 4];
        let observed = u32::from_le_bytes(bytes.try_into().unwrap());
        assert_eq!(
            observed, pkg.summary.package_flags,
            "package_flags_offset must point at the flag bytes (expected \
             {:#010x}, got {:#010x})",
            pkg.summary.package_flags, observed
        );
    }
}
