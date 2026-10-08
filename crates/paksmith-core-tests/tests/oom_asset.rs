//! Integration tests for typed OOM-failure variants on the asset
//! parser surface (issue #276).
//!
//! Mirror of `oom_pak.rs` for the asset side. Each test drives a
//! `Package::read_from` call (or, for the bulk-data seams,
//! `BulkDataResolver::resolve`, and for the UTF-16 FString seam,
//! `EngineVersion::read_from`) against an arming
//! `SeamSite::Asset(AssetSeam::*)` seam — synthesizing a
//! `TryReserveError` at the targeted reservation
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
//! `read_<scope>_surfaces_allocation_failed_under_oom`, or
//! `resolve_<scope>_…` for the bulk-data seams. The input isn't
//! malformed — it's a valid asset or bulk record whose typed-error
//! path we surface via injected allocator failure.

#![allow(missing_docs)]

use paksmith_core::PaksmithError;
use paksmith_core::asset::bulk_data::{BulkDataFlags, BulkDataResolver, FByteBulkData};
use paksmith_core::asset::{EngineVersion, Package};
use paksmith_core::error::{AssetAllocationContext, AssetParseFault};
use paksmith_core::testing::bench::zlib_compress_framed;
use paksmith_core::testing::oom::{AssetSeam, SeamSite, arm_at};
use paksmith_core::testing::uasset::{
    build_minimal_custom_versions_populated, build_minimal_ue4_27, build_minimal_ue4_27_split,
    build_minimal_ue4_27_unversioned, build_minimal_ue4_27_with_array_of_struct,
    build_minimal_ue4_27_with_data_table, build_minimal_ue5_1010_with_data_resources,
};
use paksmith_core::testing::usmap::{
    build_hero_usmap_with_enum_speed, build_hero_usmap_with_struct_speed,
};
use paksmith_core::testing::wire::write_fstring_utf16;

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
/// reservation inside the tagged-property iterator surfaces
/// `AssetParseFault::AllocationFailed{CollectionElements}`, which ends
/// the package read rather than degrading the export to `Opaque`.
#[test]
fn read_asset_collection_elements_surfaces_allocation_failed_under_oom() {
    let pkg = build_minimal_ue4_27_with_array_of_struct();
    let _guard = arm_at(SeamSite::Asset(AssetSeam::CollectionElements), 0);
    let err = Package::read_from(&pkg.bytes, None, None, "Game/Test.uasset").unwrap_err();
    assert!(
        matches!(
            &err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::AllocationFailed {
                    context: AssetAllocationContext::CollectionElements,
                    ..
                },
                ..
            }
        ),
        "expected AllocationFailed{{CollectionElements}}; got {err:?}"
    );
}

/// Arm `AssetSeam::SplitAssetCombined` → the (uasset + uexp) concat-buffer
/// reservation surfaces
/// `AssetParseFault::AllocationFailed{SplitAssetCombined}`.
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

/// `BULKDATA_PayloadAtEndOfFile` (bit 0), private in `bulk_data.rs`.
const PAYLOAD_AT_END_OF_FILE: u32 = 0x0000_0001;
/// `BULKDATA_SerializeCompressedZLIB` (bit 1), private in `bulk_data.rs`.
const SERIALIZE_COMPRESSED_ZLIB: u32 = 0x0000_0002;

/// Resolve one Inline-tier record storing `stored` with `seam` armed;
/// return the `AllocationFailed` fault's context and requested size.
fn resolve_bulk_under_oom(
    seam: AssetSeam,
    flags: u32,
    stored: &[u8],
    element_count: i64,
) -> (AssetAllocationContext, usize) {
    let mut uasset = vec![0u8; 64];
    uasset.extend_from_slice(stored);
    let header_len = uasset.len() as u64;
    let resolver = BulkDataResolver::new_for_test(uasset, header_len, 0);
    let record = FByteBulkData::for_test(
        BulkDataFlags::from(flags),
        element_count,
        stored.len() as u64,
        64,
    );
    let _guard = arm_at(SeamSite::Asset(seam), 0);
    match resolver.resolve(&record, "Game/Test.uasset") {
        Err(PaksmithError::AssetParse {
            fault:
                AssetParseFault::AllocationFailed {
                    context, requested, ..
                },
            ..
        }) => (context, requested),
        other => panic!("expected AllocationFailed; got {other:?}"),
    }
}

/// Arm `AssetSeam::BulkDataBytes` → the copy of an uncompressed bulk
/// record surfaces `AllocationFailed{BulkDataBytes}` for its full size.
#[test]
fn resolve_bulk_data_bytes_surfaces_allocation_failed_under_oom() {
    let payload = [0xAB; 32];
    assert_eq!(
        resolve_bulk_under_oom(
            AssetSeam::BulkDataBytes,
            PAYLOAD_AT_END_OF_FILE,
            &payload,
            32
        ),
        (AssetAllocationContext::BulkDataBytes, payload.len())
    );
}

/// Arm `AssetSeam::DecompressedBulkDataBytes` → a zlib record's output
/// pre-size surfaces `AllocationFailed{DecompressedBulkDataBytes}` for
/// the compressed length.
#[test]
fn resolve_decompressed_bulk_data_bytes_surfaces_allocation_failed_under_oom() {
    let payload = [0xAB; 4096];
    let framed = zlib_compress_framed(&payload);
    assert_eq!(
        resolve_bulk_under_oom(
            AssetSeam::DecompressedBulkDataBytes,
            PAYLOAD_AT_END_OF_FILE | SERIALIZE_COMPRESSED_ZLIB,
            &framed,
            4096,
        ),
        (
            AssetAllocationContext::DecompressedBulkDataBytes,
            framed.len()
        )
    );
}

/// Arm `AssetSeam::EnumTableMemo` → the per-read enum-table memo's growth
/// for an unversioned `Speed` enum surfaces
/// `AllocationFailed{EnumTableMemo}`, ending the package read.
#[test]
fn read_asset_enum_table_memo_surfaces_allocation_failed_under_oom() {
    let usmap = std::sync::Arc::new(
        paksmith_core::asset::Usmap::from_bytes(&build_hero_usmap_with_enum_speed(
            "Difficulty",
            &["Easy", "Normal"],
        ))
        .unwrap(),
    );
    // One fragment, last, two values: Health 100 and Speed 1.
    let mut payload = 0x0500u16.to_le_bytes().to_vec();
    payload.extend_from_slice(&100i32.to_le_bytes());
    payload.push(1);
    let pkg = build_minimal_ue4_27_unversioned("Hero", payload);
    let _guard = arm_at(SeamSite::Asset(AssetSeam::EnumTableMemo), 0);
    let err = Package::read_from(&pkg.bytes, None, Some(&usmap), "Game/Test.uasset").unwrap_err();
    assert!(
        matches!(
            &err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::AllocationFailed {
                    context: AssetAllocationContext::EnumTableMemo,
                    requested: 1,
                    ..
                },
                ..
            }
        ),
        "expected AllocationFailed{{EnumTableMemo}}; got {err:?}"
    );
}

/// Arm `AssetSeam::StructLayoutMemo` → the per-read struct-layout memo's
/// growth for an unversioned `Speed` struct surfaces
/// `AllocationFailed{StructLayoutMemo}`, ending the package read.
/// Unarmed, the same bytes read (`unversioned_integration.rs`'s
/// `nested_struct_with_missing_schema_returns_partial_tree`).
#[test]
fn read_asset_struct_layout_memo_surfaces_allocation_failed_under_oom() {
    let usmap = std::sync::Arc::new(
        paksmith_core::asset::Usmap::from_bytes(&build_hero_usmap_with_struct_speed("StatsBlock"))
            .unwrap(),
    );
    // One fragment, last, two values: Health 100, then the Speed struct.
    let mut payload = 0x0500u16.to_le_bytes().to_vec();
    payload.extend_from_slice(&100i32.to_le_bytes());
    let pkg = build_minimal_ue4_27_unversioned("Hero", payload);
    let _guard = arm_at(SeamSite::Asset(AssetSeam::StructLayoutMemo), 0);
    let err = Package::read_from(&pkg.bytes, None, Some(&usmap), "Game/Test.uasset").unwrap_err();
    assert!(
        matches!(
            &err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::AllocationFailed {
                    context: AssetAllocationContext::StructLayoutMemo,
                    requested: 1,
                    ..
                },
                ..
            }
        ),
        "expected AllocationFailed{{StructLayoutMemo}}; got {err:?}"
    );
}

/// Arm `AssetSeam::FStringUtf8Bytes` → the summary's folder name, the
/// first asset FString, surfaces `AllocationFailed{FStringUtf8Bytes}`
/// for its 5 bytes ("None" and the NUL).
#[test]
fn read_asset_fstring_utf8_bytes_surfaces_allocation_failed_under_oom() {
    let pkg = build_minimal_ue4_27();
    let _guard = arm_at(SeamSite::Asset(AssetSeam::FStringUtf8Bytes), 0);
    let err = Package::read_from(&pkg.bytes, None, None, "Game/Test.uasset").unwrap_err();
    assert!(
        matches!(
            &err,
            PaksmithError::AssetParse {
                asset_path,
                fault: AssetParseFault::AllocationFailed {
                    context: AssetAllocationContext::FStringUtf8Bytes,
                    requested: 5,
                    ..
                },
            } if asset_path == "Game/Test.uasset"
        ),
        "expected AllocationFailed{{FStringUtf8Bytes}}; got {err:?}"
    );
}

/// Arm `AssetSeam::FStringUtf16CodeUnits` → a UTF-16 engine-version
/// branch surfaces `AllocationFailed{FStringUtf16CodeUnits}` counting
/// its 6 code units ("++UE5" and the NUL), not its 12 bytes.
#[test]
fn read_asset_fstring_utf16_code_units_surfaces_allocation_failed_under_oom() {
    let mut bytes = [4u16, 27, 2]
        .iter()
        .flat_map(|v| v.to_le_bytes())
        .collect::<Vec<u8>>();
    bytes.extend_from_slice(&0u32.to_le_bytes());
    write_fstring_utf16(&mut bytes, "++UE5");
    let _guard = arm_at(SeamSite::Asset(AssetSeam::FStringUtf16CodeUnits), 0);
    let err =
        EngineVersion::read_from(&mut std::io::Cursor::new(bytes), "Game/Test.uasset").unwrap_err();
    assert!(
        matches!(
            &err,
            PaksmithError::AssetParse {
                asset_path,
                fault: AssetParseFault::AllocationFailed {
                    context: AssetAllocationContext::FStringUtf16CodeUnits,
                    requested: 6,
                    ..
                },
            } if asset_path == "Game/Test.uasset"
        ),
        "expected AllocationFailed{{FStringUtf16CodeUnits}}; got {err:?}"
    );
}
