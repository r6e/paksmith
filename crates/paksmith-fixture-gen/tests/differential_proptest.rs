//! Differential proptest: paksmith writer × paksmith reader × `unreal_asset` reader.
//!
//! Sweeps random `MinimalPackageSpec` combinations through `build_minimal`
//! (paksmith's writer) and asserts the resulting bytes parse identically
//! under paksmith and `unreal_asset` via the cross-parser oracle
//! [`cross_validate_with_unreal_asset`]. A failing case means the two
//! parsers disagree on field values for paksmith-written bytes — a
//! wire-format divergence to investigate.
//!
//! ## What's differentiated
//!
//! Three independent code paths must agree:
//! 1. paksmith's writer (`build_minimal` + `*::write_to`)
//! 2. paksmith's reader (`Package::read_from`)
//! 3. `unreal_asset`'s reader (`Asset::new`)
//!
//! Hand-crafted fixtures pin specific (ue4, ue5, package_flags, shape)
//! tuples. This proptest sweeps the cross-product, catching field-
//! combination corner cases neither fixture-by-fixture nor real-asset
//! fixtures would reach.
//!
//! ## Strategy bias
//!
//! - **`PKG_FilterEditorOnly` always set.** Avoids issue #256 Gap 1
//!   (paksmith reads `PersistentGuid` / `OwnerPersistentGuid` at UE4
//!   ≥ 518 with `!PKG_FilterEditorOnly`; `unreal_asset` does not — a
//!   32-byte cursor skew). With the flag set, the editor-only side of
//!   every gate suppresses these fields and the two parsers agree.
//! - **`file_version_ue4` biased toward 522** (UE 4.27, most-tested
//!   path) with excursions to known gate boundaries: 504, 507, 510,
//!   511, 516, 517, 519, 522. Skips 518 (paired with editor-only side
//!   of the GUID gate) and 520-521 (Gap 1 trigger combined with
//!   uncooked, which we don't generate anyway).
//! - **`file_version_ue5` ∈ \{None, Some(1010)\}.** None mostly; the
//!   1010 case exercises the `SCRIPT_SERIALIZATION_OFFSET` path. Higher
//!   values are rejected by paksmith (`FIRST_UNSUPPORTED_UE5_VERSION =
//!   1011`); lower values would need shape variants on each export's
//!   `Option<_>` fields that the strategy doesn't currently emit.
//! - **`legacy_file_version`** paired to `ue5` presence: -7 ↔ None;
//!   -8 / -9 ↔ Some(1010). Required by paksmith's wire-format
//!   consistency (the summary reader reads ue5 only when
//!   `legacy_file_version ≤ -8`).
//! - **Export / import shape branches on `ue5_versioned`.** UE5 1010
//!   requires `package_guid: None`, `is_inherited_instance: Some(_)`,
//!   `generate_public_hash: Some(_)`, `script_serialization_*_offset:
//!   Some(_)` on every export plus `import_optional: Some(_)` on every
//!   import. UE4 requires the inverse. Mismatched shapes cause the
//!   writer to panic (script_serialization gate) or misalign the
//!   reader's cursor.
//! - **`export_count = 1` when `ue5_versioned`.** `unreal_asset`'s
//!   pinned revision does not consume the 16-byte per-export
//!   `script_serialization_{start,end}_offset` tail at UE5 ≥ 1010
//!   (asset.rs:144-160 ends after preload-deps). For 1 export, the
//!   unconsumed tail is harmless; for 2+ exports, it skews the reader
//!   onto export[1]'s prefix → "Cannot read FName, index: -1". New
//!   `unreal_asset` API gap, sibling to the existing one documented in
//!   `cross_validate_with_unreal_asset` — issue #256 follow-up.
//! - **`file_version_ue4 = 522` forced when `ue5_versioned`.** Real
//!   UE5 packages pin the legacy UE4 slot at 522 (UE 4.27 ceiling);
//!   combinations like `(ue4=504, ue5=Some(1010))` are malformed and
//!   would cause cross-parser disagreement that masks real bugs.
//! - **`import_count ≥ 1`.** Every generated export references
//!   `class_index = PackageIndex::Import(0)`; `unreal_asset`'s
//!   `get_import` (asset.rs:834) has an off-by-one bound (`index >
//!   len`) and panics on `imports[0]` when `imports.len() == 0`. Not
//!   a paksmith bug; a structural invariant the strategy respects.
//!
//! ## Cases
//!
//! 64 cases — differential fuzzing is expensive (each case spawns an
//! `unreal_asset::Asset::new` parse on top of paksmith's parse), and the
//! audit recommended this floor. Empirically well under 5s wall-clock
//! locally; if it overruns 30s in CI, investigate the slow-shrink path
//! rather than blindly raising the cap.

#![allow(missing_docs)]

use paksmith_core::asset::custom_version::{CustomVersion, CustomVersionContainer};
use paksmith_core::asset::engine_version::EngineVersion;
use paksmith_core::asset::export_table::{ExportTable, ObjectExport};
use paksmith_core::asset::guid::FGuid;
use paksmith_core::asset::import_table::{ImportTable, ObjectImport};
use paksmith_core::asset::name_table::{FName, NameTable};
use paksmith_core::asset::package_index::PackageIndex;
use paksmith_core::testing::uasset::{MinimalPackageSpec, build_minimal};
use paksmith_fixture_gen::uasset::cross_validate_with_unreal_asset;
use proptest::prelude::*;

/// `PKG_FilterEditorOnly` — the cooked-game bit. Always set in this
/// strategy to suppress `PersistentGuid` / `OwnerPersistentGuid` /
/// `LocalizationId` (the editor-only-side of those gates), avoiding
/// issue #256 Gap 1.
const PKG_FILTER_EDITOR_ONLY: u32 = 0x8000_0000;

/// Build an `ObjectExport` whose `Option<_>` fields match the wire-
/// format gates for the given UE5 version. Mismatched shapes either
/// panic in the writer (script_serialization gate) or misalign the
/// reader.
///
/// Only `file_version_ue5` is currently consulted — every export-
/// shape gate the strategy varies over is on the UE5 side. A future
/// extension that sweeps UE4-side export-shape gates (e.g. pre-507
/// records with the preload-dep tail absent) would add a
/// `file_version_ue4` parameter at the two call sites.
fn make_export(file_version_ue5: Option<i32>, payload_len: i64) -> ObjectExport {
    let ue5_at_least = |gate: i32| file_version_ue5.is_some_and(|v| v >= gate);
    ObjectExport {
        class_index: PackageIndex::Import(0),
        super_index: PackageIndex::Null,
        // Read independent of Option — wire emits iff ue4 ≥ 508. Null
        // is fine at any version.
        template_index: PackageIndex::Null,
        outer_index: PackageIndex::Null,
        object_name: 2,
        object_name_number: 0,
        object_flags: 0,
        serial_size: payload_len,
        serial_offset: 0,
        forced_export: false,
        not_for_client: false,
        not_for_server: false,
        // package_guid removed at UE5 ≥ 1005.
        package_guid: if ue5_at_least(1005) {
            None
        } else {
            Some(FGuid::from_bytes([0u8; 16]))
        },
        // is_inherited_instance added at UE5 ≥ 1006.
        is_inherited_instance: if ue5_at_least(1006) {
            Some(false)
        } else {
            None
        },
        package_flags: 0,
        not_always_loaded_for_editor_game: false,
        is_asset: true,
        // generate_public_hash added at UE5 ≥ 1003.
        generate_public_hash: if ue5_at_least(1003) {
            Some(false)
        } else {
            None
        },
        // script_serialization_* added at UE5 ≥ 1010, gated on
        // `!PKG_UnversionedProperties`. PKG_FilterEditorOnly is the
        // ONLY flag the strategy sets, so the gate fires when ue5
        // ≥ 1010. Writer panics if the field is None at gate-fire.
        script_serialization_start_offset: if ue5_at_least(1010) { Some(0) } else { None },
        script_serialization_end_offset: if ue5_at_least(1010) { Some(0) } else { None },
        // Preload-deps tail: 5 i32s present at ue4 ≥ 507. Below the
        // gate the writer emits nothing; in-memory defaults follow UE
        // convention (first = -1 = "no preload deps"). At ue4 ≥ 507
        // we still default to -1 because the cross-parser oracle
        // compares this field only when ue4 ≥ 507 (see issue #256
        // Gap 2), and -1 round-trips through both parsers.
        first_export_dependency: -1,
        serialization_before_serialization_count: 0,
        create_before_serialization_count: 0,
        serialization_before_create_count: 0,
        create_before_create_count: 0,
    }
}

/// Build an `ObjectImport` whose `Option<_>` field matches the wire-
/// format gate for the given version. `import_optional` added at UE5
/// ≥ 1003.
fn make_import(
    file_version_ue5: Option<i32>,
    class_pkg: u32,
    class_name: u32,
    object_name: u32,
) -> ObjectImport {
    let ue5_at_least_1003 = file_version_ue5.is_some_and(|v| v >= 1003);
    ObjectImport {
        class_package_name: class_pkg,
        class_package_number: 0,
        class_name,
        class_name_number: 0,
        outer_index: PackageIndex::Null,
        object_name,
        object_name_number: 0,
        import_optional: if ue5_at_least_1003 { Some(false) } else { None },
    }
}

prop_compose! {
    /// Strategy for `MinimalPackageSpec`. See the module-level docs for
    /// the bias rationale.
    fn arb_minimal_package_spec()(
        // Versions: biased toward UE 4.27 (522) with excursions to
        // known gate boundaries. UE5 versioned in ~25% of cases.
        file_version_ue4 in prop::sample::select(
            &[504i32, 507, 510, 511, 516, 517, 519, 522, 522, 522]
        ),
        ue5_versioned in prop::bool::weighted(0.25),
        // Names: 3-16 ASCII identifiers. The 3-floor preserves the
        // default fixture's name layout (CoreUObject / Package /
        // Default__Object) at indexes 0-2 which the imports/exports
        // reference.
        name_extras in proptest::collection::vec(
            "[a-zA-Z][a-zA-Z0-9_]{0,15}",
            0usize..14,
        ),
        // Imports: 1-6. Floor of 1 because every generated export's
        // `class_index = PackageIndex::Import(0)` references the first
        // import; with `imports.len() == 0`, `unreal_asset`'s
        // `get_import` (asset.rs:834) panics on the `imports[0]` index
        // (its bound check is `index > len`, off-by-one). Not a wire-
        // format bug in paksmith — a structural invariant the strategy
        // must respect.
        import_count in 1u32..6,
        // Exports: 1-3. Floor of 1 because the export-payload region
        // patches off the summary; zero exports would change the
        // builder's invariant.
        export_count in 1u32..4,
        // Engine-version: vary branch + changelist independently.
        branch in "[a-zA-Z0-9+\\-_.]{0,32}",
        licensee_bit in any::<bool>(),
        cl_low in any::<u32>(),
        major in any::<u16>(),
        minor in any::<u16>(),
        patch in any::<u16>(),
        // Custom versions: 0-3 entries with random GUIDs + i32 versions.
        custom_versions in proptest::collection::vec(
            (any::<[u8; 16]>(), any::<i32>()),
            0..3,
        ),
        // Legacy file version on the UE4 side: -7 only when ue5 is None.
        // The pairing with ue5 happens below; here we just pick one of
        // the UE5-valid legacies (-8 / -9) which will get overridden
        // back to -7 in the UE4 case.
        legacy_ue5 in prop::sample::select(&[-8i32, -9]),
    ) -> MinimalPackageSpec {
        let file_version_ue5 = if ue5_versioned { Some(1010) } else { None };
        let legacy_file_version = if file_version_ue5.is_some() { legacy_ue5 } else { -7 };
        // UE5-versioned packages always carry `file_version_ue4 = 522`
        // (the UE 4.27 ceiling — UE5's wire format keeps the legacy
        // UE4 version slot pinned at the highest UE4 value). The
        // `build_minimal_ue5_1010` reference fixture does the same.
        // Overriding the strategy-picked ue4 here keeps the sweep
        // generating valid UE5 payloads instead of malformed
        // `(ue4=504, ue5=Some(1010))` combinations that paksmith and
        // `unreal_asset` parse differently.
        let file_version_ue4 = if file_version_ue5.is_some() {
            522
        } else {
            file_version_ue4
        };
        // UE5 1010 + `!PKG_UnversionedProperties` requires the per-
        // export `script_serialization_{start,end}_offset` i64 tail
        // (16 bytes per export). paksmith writes the tail; the pinned
        // `unreal_asset` revision DOES NOT consume those 16 bytes from
        // the wire (asset.rs lines 144-160 stop after the preload-deps
        // tail — no script_serialization read). For a single export
        // the unconsumed 16 bytes land beyond the last record's bytes
        // and unreal_asset moves on; for multi-export, the unconsumed
        // tail of export[0] becomes the prefix of export[1] in
        // unreal_asset's reader → cursor skew → "Cannot read FName,
        // index: -1" on the second record. Pin export_count to 1 in
        // the UE5 case until either unreal_asset gains
        // script_serialization support or paksmith ships its own
        // multi-export UE5 1010 oracle. NEW issue #256-class gap
        // (Gap 3) — file as #256 follow-up.
        let export_count = if file_version_ue5.is_some() { 1 } else { export_count };

        // Build the name table: 3 mandatory + extras.
        let mut names = vec![
            FName::new("/Script/CoreUObject"),
            FName::new("Package"),
            FName::new("Default__Object"),
        ];
        for extra in &name_extras {
            names.push(FName::new(extra));
        }
        let name_table = NameTable { names };
        let name_count = u32::try_from(name_table.names.len())
            .expect("strategy bounds name table size well below u32::MAX");

        // Build imports: each references object_name = (i + 2) % name_count
        // so the index stays in-bounds for any name_count.
        let imports_vec: Vec<ObjectImport> = (0..import_count)
            .map(|i| {
                let obj_name = (i + 2) % name_count;
                make_import(file_version_ue5, 0, 1, obj_name)
            })
            .collect();
        let imports = ImportTable { imports: imports_vec };

        // Build exports: each carries a 16-byte payload. payload bytes
        // are sentinel-stamped so cross-parser disagreement on offsets
        // surfaces immediately.
        let payloads: Vec<Vec<u8>> = (0..export_count)
            .map(|i| {
                // export_count is bounded to 1..=4 by the strategy, so
                // `i` always fits in u8 with margin.
                let sentinel = 0xA0u8
                    | u8::try_from(i).expect("strategy bounds export_count to fit in u8");
                vec![sentinel; 16]
            })
            .collect();
        let exports_vec: Vec<ObjectExport> = (0..usize::try_from(export_count)
            .expect("u32 export_count fits in usize on supported targets"))
            .map(|i| {
                // payloads[i] is the 16-byte sentinel vec built above;
                // i64::from_usize would panic on >i64::MAX (~9.2e18 bytes),
                // far above any payload we synthesize.
                let payload_len = i64::try_from(payloads[i].len())
                    .expect("synthesized payload size fits in i64");
                let mut exp = make_export(file_version_ue5, payload_len);
                // Distinct object_name per export to keep diagnostics
                // unambiguous if comparison fails on a particular index.
                exp.object_name = 2;
                exp.object_name_number = u32::try_from(i)
                    .expect("strategy bounds export_count to fit in u32");
                exp
            })
            .collect();
        let exports = ExportTable { exports: exports_vec };

        // Engine version: licensee high-bit optionally set on changelist.
        let cl = if licensee_bit { cl_low | 0x8000_0000 } else { cl_low & 0x7FFF_FFFF };
        let saved_engine = EngineVersion {
            major,
            minor,
            patch,
            changelist: cl,
            branch: branch.clone(),
        };
        // Compatible mirrors saved in shape but with a zero CL — the
        // canonical default does this and `unreal_asset` accepts it.
        let compat_engine = EngineVersion {
            major,
            minor,
            patch,
            changelist: 0,
            branch,
        };

        let custom_versions = CustomVersionContainer {
            versions: custom_versions
                .into_iter()
                .map(|(g, v)| CustomVersion { guid: FGuid::from_bytes(g), version: v })
                .collect(),
        };

        MinimalPackageSpec {
            legacy_file_version,
            file_version_ue4,
            file_version_ue5,
            // Licensee version field: stays zero — paksmith doesn't
            // branch on it currently and the cross-parser comparison
            // doesn't reach `file_licensee_version` past the wire.
            file_version_licensee_ue4: 0,
            // PKG_FilterEditorOnly ALWAYS set — see module docs.
            package_flags: PKG_FILTER_EDITOR_ONLY,
            names: name_table,
            imports,
            exports,
            custom_versions,
            saved_by_engine_version: saved_engine,
            compatible_with_engine_version: compat_engine,
            // PersistentGuid / OwnerPersistentGuid / LocalizationId all
            // gated on `!PKG_FilterEditorOnly` — the strategy always
            // sets the flag, so these three stay None.
            persistent_guid: None,
            owner_persistent_guid: None,
            localization_id: None,
            payloads,
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        // Differential fuzzing is expensive (paksmith parse + unreal_asset
        // parse + field-by-field comparison per case). 64 is the floor
        // recommended by the audit; expect well under 5s wall-clock.
        cases: 64,
        ..ProptestConfig::default()
    })]

    /// Paksmith writer × cross-parser oracle round-trip.
    ///
    /// For every `MinimalPackageSpec` the strategy produces:
    /// 1. `build_minimal(spec)` writes wire bytes.
    /// 2. Both paksmith and `unreal_asset` parse those bytes.
    /// 3. Field-by-field comparison passes (oracle returns Ok).
    ///
    /// A failure means paksmith's writer produced bytes that the two
    /// parsers interpret differently. Either:
    /// - a wire-format bug in paksmith's writer, or
    /// - a wire-format bug in paksmith's reader, or
    /// - a new `unreal_asset` API gap (file as #256 follow-up).
    ///
    /// Proptest minimizes the failing case automatically; the
    /// diagnostic prints the shrunken `PackageSummary` for triage.
    #[test]
    fn paksmith_round_trips_via_cross_parser_oracle(
        spec in arb_minimal_package_spec()
    ) {
        // Snapshot the gate-controlling versions before `build_minimal`
        // consumes the spec — needed for the engine_version mapping
        // and the diagnostic.
        let ue4 = spec.file_version_ue4;
        let ue5 = spec.file_version_ue5;
        let legacy = spec.legacy_file_version;

        let pkg = build_minimal(spec);

        // Map paksmith's wire version onto `unreal_asset`'s fallback
        // EngineVersion enum. The arg is a FALLBACK for unversioned
        // assets — our fixtures are always versioned, so the wire
        // value overrides — but `unreal_asset`'s
        // `set_engine_version` runs accessor side-effects, so pick
        // an approximate match.
        let engine_version = match ue5 {
            Some(_) => unreal_asset::engine_version::EngineVersion::VER_UE5_2,
            None => match ue4 {
                v if v >= 522 => unreal_asset::engine_version::EngineVersion::VER_UE4_27,
                v if v >= 518 => unreal_asset::engine_version::EngineVersion::VER_UE4_25,
                v if v >= 516 => unreal_asset::engine_version::EngineVersion::VER_UE4_23,
                v if v >= 510 => unreal_asset::engine_version::EngineVersion::VER_UE4_22,
                v if v >= 507 => unreal_asset::engine_version::EngineVersion::VER_UE4_14,
                _ => unreal_asset::engine_version::EngineVersion::VER_UE4_12,
            },
        };

        let result = cross_validate_with_unreal_asset(&pkg.bytes, engine_version);
        prop_assert!(
            result.is_ok(),
            "cross-parser oracle disagreed: ue4={ue4}, ue5={ue5:?}, legacy={legacy}, \
             names={}, imports={}, exports={}, custom_versions={}, error={:?}",
            pkg.names.names.len(),
            pkg.imports.imports.len(),
            pkg.exports.exports.len(),
            pkg.summary.custom_versions.versions.len(),
            result.err(),
        );
    }
}
