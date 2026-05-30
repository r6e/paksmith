//! Phase 3d end-to-end integration: a synthetic `UDataTable` UAsset is
//! parsed through the full `Package::read_from` → export-class dispatch
//! pipeline into an `Asset::DataTable`, then handed to the default
//! [`HandlerRegistry`] for CSV / JSON export.
//!
//! This is the cross-crate capstone for the per-handler unit tests in
//! `paksmith-core/src/export/data_table.rs` and the parser unit tests in
//! `paksmith-core/src/asset/exports/data_table.rs`: it proves the
//! class-name dispatch (`"DataTable"` → `read_typed`), the CSV-first
//! registration order, and the exact serialized bytes all hold against
//! a *real asset's* wire bytes, not a hand-built `DataTableData`.
//!
//! Parse-correctness of the builder itself is pinned in-source by
//! `testing::uasset::tests::data_table_rows_fixture_round_trips` (so
//! `cargo-mutants`, which skips this crate, still kills the builder
//! mutants); this file owns only the cross-crate export surface.
//!
//! Required feature: `__test_utils` (the `testing::uasset` builders are
//! gated behind it; only this sibling crate enables it).

#![allow(missing_docs)]

use paksmith_core::Asset;
use paksmith_core::asset::Package;
use paksmith_core::export::HandlerRegistry;
use paksmith_core::testing::uasset::build_minimal_ue4_27_with_data_table_rows;

/// Parse the two-row DataTable fixture through the full pipeline and
/// return the typed `Asset::DataTable`.
fn parse_weapons_table() -> Asset {
    let pkg = build_minimal_ue4_27_with_data_table_rows();
    let parsed = Package::read_from(&pkg.bytes, None, None, "Game/Weapons.uasset")
        .expect("parse weapons data-table fixture");
    parsed
        .payloads
        .into_iter()
        .next()
        .expect("one export payload")
}

#[test]
fn data_table_dispatches_to_typed_two_row_asset() {
    // The "DataTable"-class export must route through the typed reader
    // (not the Generic fallback) and carry both rows with their bodies.
    match parse_weapons_table() {
        Asset::DataTable(data) => {
            assert_eq!(data.rows.len(), 2);
            assert_eq!(data.rows[0].name, "Weapon_Sword");
            assert_eq!(data.rows[1].name, "Weapon_Bow");
        }
        other => panic!("expected Asset::DataTable, got {other:?}"),
    }
}

#[test]
fn csv_is_the_default_handler_for_data_table() {
    // CSV is registered first in `all_default_handlers`, so the
    // extension-agnostic `find_handler` returns it for a DataTable —
    // the format doc's "rows are the high-priority extraction target".
    let asset = parse_weapons_table();
    let reg = HandlerRegistry::all_default_handlers();
    let handler = reg
        .find_handler(&asset)
        .expect("a default DataTable handler");
    assert_eq!(handler.output_extension(), "csv");
}

#[test]
fn two_row_data_table_exports_to_csv() {
    let asset = parse_weapons_table();
    let reg = HandlerRegistry::all_default_handlers();
    let handler = reg
        .find_handler_by_extension("csv", &asset)
        .expect("csv handler");
    let bytes = handler.export(&asset, None).expect("csv export");
    let csv = std::str::from_utf8(&bytes).expect("utf-8");
    // Column union is order-preserving (Damage before Cost, both at
    // array_index 0 → bare names); LF terminator; integer cells render
    // as plain decimals.
    assert_eq!(
        csv,
        "Name,Damage,Cost\nWeapon_Sword,10,100\nWeapon_Bow,8,120\n"
    );
}

#[test]
fn two_row_data_table_exports_to_json() {
    let asset = parse_weapons_table();
    let reg = HandlerRegistry::all_default_handlers();
    let handler = reg
        .find_handler_by_extension("json", &asset)
        .expect("json handler");
    let bytes = handler.export(&asset, None).expect("json export");
    let json = std::str::from_utf8(&bytes).expect("utf-8");
    // Pretty-printed serde shape of the full Asset::DataTable tree.
    assert!(json.contains("\"row_struct\": \"\""), "got: {json}");
    assert!(json.contains("\"name\": \"Weapon_Sword\""), "got: {json}");
    assert!(json.contains("\"name\": \"Weapon_Bow\""), "got: {json}");
    assert!(json.contains("\"Int\": 120"), "got: {json}");
}
