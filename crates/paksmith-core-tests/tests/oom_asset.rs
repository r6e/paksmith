//! Integration tests for typed OOM-failure variants on the asset
//! parser surface (issue #276).
//!
//! Mirror of `oom_pak.rs` for the asset side. Each test drives a
//! `Package::read_from` call against an arming
//! `SeamSite::Asset(AssetSeam::*)` seam — synthesizing a
//! `TryReserveError` at the targeted `try_reserve_asset` call site
//! and asserting that
//! [`paksmith_core::error::AssetParseFault::AllocationFailed`]
//! surfaces with the matching `AssetAllocationContext`.
//!
//! The asset surface had `try_reserve_asset` HELPER coverage (see
//! `paksmith-core/src/error.rs::tests::try_reserve_asset_routes_*`)
//! but no seam-driven integration tests like the pak side's
//! `oom_pak.rs` until #276, which added one per `AssetSeam` (the
//! `DataTableRows` seam's test was added with the Phase 3d parser).
//!
//! **Naming convention** matches `oom_pak.rs`:
//! `read_<scope>_surfaces_allocation_failed_under_oom`. The input
//! isn't malformed — it's a valid asset whose typed-error path we
//! surface via injected allocator failure.

#![allow(missing_docs)]

use paksmith_core::PaksmithError;
use paksmith_core::asset::Package;
use paksmith_core::error::{AssetAllocationContext, AssetParseFault};
use paksmith_core::testing::oom::{AssetSeam, SeamSite, arm_at};
use paksmith_core::testing::uasset::{
    build_minimal_custom_versions_populated, build_minimal_ue4_27, build_minimal_ue4_27_split,
    build_minimal_ue4_27_with_array_of_struct, build_minimal_ue4_27_with_data_table,
    build_minimal_ue5_1010_with_data_resources,
};

/// Arm `AssetSeam::NameTable` → `Package::read_from`'s name-table
/// reservation surfaces `AssetParseFault::AllocationFailed{NameTable}`.
/// NameTable is read first in the summary-driven parse pipeline, so
/// the seam fires before any other reservation.
#[test]
fn read_asset_name_table_surfaces_allocation_failed_under_oom() {
    let pkg = build_minimal_ue4_27();
    let _guard = arm_at(SeamSite::Asset(AssetSeam::NameTable), 0);
    let err = Package::read_from(&pkg.bytes, None, None, "Game/Test.uasset").unwrap_err();
    assert!(
        matches!(
            &err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::AllocationFailed {
                    context: AssetAllocationContext::NameTable,
                    ..
                },
                ..
            }
        ),
        "expected AllocationFailed{{NameTable}}; got {err:?}"
    );
}

/// Arm `AssetSeam::ImportTable` → `Package::read_from`'s import-table
/// reservation surfaces `AssetParseFault::AllocationFailed{ImportTable}`.
#[test]
fn read_asset_import_table_surfaces_allocation_failed_under_oom() {
    let pkg = build_minimal_ue4_27();
    let _guard = arm_at(SeamSite::Asset(AssetSeam::ImportTable), 0);
    let err = Package::read_from(&pkg.bytes, None, None, "Game/Test.uasset").unwrap_err();
    assert!(
        matches!(
            &err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::AllocationFailed {
                    context: AssetAllocationContext::ImportTable,
                    ..
                },
                ..
            }
        ),
        "expected AllocationFailed{{ImportTable}}; got {err:?}"
    );
}

/// Arm `AssetSeam::ExportTable` → `Package::read_from`'s export-table
/// reservation surfaces `AssetParseFault::AllocationFailed{ExportTable}`.
#[test]
fn read_asset_export_table_surfaces_allocation_failed_under_oom() {
    let pkg = build_minimal_ue4_27();
    let _guard = arm_at(SeamSite::Asset(AssetSeam::ExportTable), 0);
    let err = Package::read_from(&pkg.bytes, None, None, "Game/Test.uasset").unwrap_err();
    assert!(
        matches!(
            &err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::AllocationFailed {
                    context: AssetAllocationContext::ExportTable,
                    ..
                },
                ..
            }
        ),
        "expected AllocationFailed{{ExportTable}}; got {err:?}"
    );
}

/// Arm `AssetSeam::CustomVersionContainer` → the cv-container reservation
/// surfaces `AssetParseFault::AllocationFailed{CustomVersionContainer}`.
/// Uses `build_minimal_custom_versions_populated` so `cv_count > 0`
/// reaches the helper call (the minimal v4.27 fixture has zero
/// custom versions and skips the reservation).
#[test]
fn read_asset_custom_version_container_surfaces_allocation_failed_under_oom() {
    let pkg = build_minimal_custom_versions_populated();
    let _guard = arm_at(SeamSite::Asset(AssetSeam::CustomVersionContainer), 0);
    let err = Package::read_from(&pkg.bytes, None, None, "Game/Test.uasset").unwrap_err();
    assert!(
        matches!(
            &err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::AllocationFailed {
                    context: AssetAllocationContext::CustomVersionContainer,
                    ..
                },
                ..
            }
        ),
        "expected AllocationFailed{{CustomVersionContainer}}; got {err:?}"
    );
}

/// Arm `AssetSeam::ExportPayloads` → the per-export `PropertyBag` vec
/// reservation surfaces `AssetParseFault::AllocationFailed{ExportPayloads}`.
#[test]
fn read_asset_export_payloads_surfaces_allocation_failed_under_oom() {
    let pkg = build_minimal_ue4_27();
    let _guard = arm_at(SeamSite::Asset(AssetSeam::ExportPayloads), 0);
    let err = Package::read_from(&pkg.bytes, None, None, "Game/Test.uasset").unwrap_err();
    assert!(
        matches!(
            &err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::AllocationFailed {
                    context: AssetAllocationContext::ExportPayloads,
                    ..
                },
                ..
            }
        ),
        "expected AllocationFailed{{ExportPayloads}}; got {err:?}"
    );
}

/// Arm `AssetSeam::ExportPayloadBytes` → the Opaque-fallback export-bytes
/// reservation surfaces
/// `AssetParseFault::AllocationFailed{ExportPayloadBytes}`. The
/// minimal v4.27 fixture has no property-decoder path (no Phase 2b
/// tagged-property tree) so `read_payloads` falls into the Opaque
/// arm and reserves the export's raw bytes.
#[test]
fn read_asset_export_payload_bytes_surfaces_allocation_failed_under_oom() {
    let pkg = build_minimal_ue4_27();
    let _guard = arm_at(SeamSite::Asset(AssetSeam::ExportPayloadBytes), 0);
    let err = Package::read_from(&pkg.bytes, None, None, "Game/Test.uasset").unwrap_err();
    assert!(
        matches!(
            &err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::AllocationFailed {
                    context: AssetAllocationContext::ExportPayloadBytes,
                    ..
                },
                ..
            }
        ),
        "expected AllocationFailed{{ExportPayloadBytes}}; got {err:?}"
    );
}

/// Arm `AssetSeam::CollectionElements` → an Array/Map/Set element-vec
/// reservation fires inside the tagged-property iterator, which is
/// then caught by `read_payloads`'s Tree/Opaque fallback (swallowing
/// the typed error and emitting a warn log; no panic, no abort).
/// The test pins the **observable consequence**: a fixture that
/// normally decodes to `PropertyBag::Tree` returns `PropertyBag::Opaque`
/// when this seam is armed. Without the seam armed, the same fixture
/// returns Tree (pinned by
/// `collection_of_struct_integration::array_of_struct_decodes_two_elements`).
/// Tree→Opaque is therefore evidence the seam fired.
///
/// Asymmetric vs the other tests in this file (which assert the
/// typed error variant directly) because the Tree/Opaque fallback at
/// `package.rs:read_payloads` swallows iteration errors by design
/// (one corrupt export shouldn't lose every other export's data).
/// A future test could use `tracing_test::traced_test` to assert the
/// warn-log fired, but the Tree→Opaque flip is already an
/// unambiguous signal at this layer.
#[test]
fn read_asset_collection_elements_surfaces_allocation_failed_under_oom() {
    use paksmith_core::asset::property::PropertyBag;
    let pkg = build_minimal_ue4_27_with_array_of_struct();
    let _guard = arm_at(SeamSite::Asset(AssetSeam::CollectionElements), 0);
    let parsed =
        Package::read_from(&pkg.bytes, None, None, "Game/Test.uasset").expect("parse succeeds");
    assert_eq!(parsed.payloads.len(), 1, "expected one export");
    assert!(
        matches!(
            &parsed.payloads[0],
            paksmith_core::Asset::Generic(PropertyBag::Opaque { .. })
        ),
        "armed AssetSeam::CollectionElements seam must flip Tree→Opaque (fallback fired); got {:?}",
        parsed.payloads[0]
    );
}

/// Arm `AssetSeam::SplitAssetCombined` → the (uasset + uexp) concat-buffer
/// reservation surfaces
/// `AssetParseFault::AllocationFailed{SplitAssetCombined}`. The seam
/// is a DIRECT `try_reserve_exact` call wired via inline
/// `seam_check!` (not the helper), so this also pins that the macro
/// expansion path is reachable from the asset surface.
#[test]
fn read_asset_split_asset_combined_surfaces_allocation_failed_under_oom() {
    let (uasset, uexp) = build_minimal_ue4_27_split();
    let _guard = arm_at(SeamSite::Asset(AssetSeam::SplitAssetCombined), 0);
    let err = Package::read_from(&uasset, Some(&uexp), None, "Game/Test.uasset").unwrap_err();
    assert!(
        matches!(
            &err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::AllocationFailed {
                    context: AssetAllocationContext::SplitAssetCombined,
                    ..
                },
                ..
            }
        ),
        "expected AllocationFailed{{SplitAssetCombined}}; got {err:?}"
    );
}

/// Arm `AssetSeam::DataTableRows` → a `UDataTable` export's row-vec
/// reservation surfaces
/// `AssetParseFault::AllocationFailed{DataTableRows}`. The fixture's
/// export class resolves to `"DataTable"`, routing it through the
/// `data_table::read_typed` dispatch; the row-vec `try_reserve_asset`
/// call runs even for the fixture's `NumRows = 0` (a count-0
/// `try_reserve_exact` still hits the armed seam).
///
/// The typed dispatch FALLS THROUGH to the generic parse on a malformed
/// body, but `AllocationFailed` is an environmental out-of-memory
/// condition, so it PROPAGATES (libraries fail fast) — which is exactly
/// what this test pins through the `Package::read_from` surface. (Phase
/// 3d Task 2 — the end-to-end counterpart to the in-source unit test in
/// `asset/exports/data_table.rs`.)
#[test]
fn read_asset_data_table_rows_surfaces_allocation_failed_under_oom() {
    let pkg = build_minimal_ue4_27_with_data_table();
    let _guard = arm_at(SeamSite::Asset(AssetSeam::DataTableRows), 0);
    let err = Package::read_from(&pkg.bytes, None, None, "Game/Test.uasset").unwrap_err();
    assert!(
        matches!(
            &err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::AllocationFailed {
                    context: AssetAllocationContext::DataTableRows,
                    ..
                },
                ..
            }
        ),
        "expected AllocationFailed{{DataTableRows}}; got {err:?}"
    );
}

/// Arm `AssetSeam::DataResourceTable` → a UE5.2+ package's populated
/// `FObjectDataResource` table entries-vec reservation surfaces
/// `AssetParseFault::AllocationFailed{DataResourceTable}` through the
/// `Package::read_from` surface (#642). The fixture's 2-entry table
/// reaches the `try_reserve_asset` call (a count-0 table early-returns
/// before the reserve, so a populated fixture is required). (The
/// end-to-end counterpart to the in-source unit test in
/// `asset/data_resource.rs`.)
#[test]
fn read_asset_data_resource_table_surfaces_allocation_failed_under_oom() {
    let pkg = build_minimal_ue5_1010_with_data_resources();
    let _guard = arm_at(SeamSite::Asset(AssetSeam::DataResourceTable), 0);
    let err = Package::read_from(&pkg.bytes, None, None, "Game/Test.uasset").unwrap_err();
    assert!(
        matches!(
            &err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::AllocationFailed {
                    context: AssetAllocationContext::DataResourceTable,
                    ..
                },
                ..
            }
        ),
        "expected AllocationFailed{{DataResourceTable}}; got {err:?}"
    );
}
