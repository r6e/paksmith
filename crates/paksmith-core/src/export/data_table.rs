//! `UDataTable` export handlers (Phase 3d).
//!
//! - [`DataTableJsonHandler`] emits the typed
//!   `{ row_struct, rows: [{ name, properties }…], class_properties }`
//!   shape `DataTableData` derives via serde, pretty-printed.
//! - [`DataTableCsvHandler`] emits an RFC-4180 table: a `Name` column
//!   plus the order-preserving union of all rows' property names, one
//!   row per `DataTableRow`. Complex (non-primitive) cell values are
//!   JSON-inlined; class-level metadata is dropped (CSV has no schema
//!   for it).
//!
//! Both are registered for the `Asset::DataTable` discriminant in
//! [`crate::export::HandlerRegistry::all_default_handlers`] — CSV
//! first (the default for `find_handler`), JSON via
//! `find_handler_by_extension("json", …)`.

use crate::asset::Asset;
use crate::asset::property::primitives::PropertyValue;

use super::{BulkData, FormatHandler};

/// JSON [`FormatHandler`] for `UDataTable` exports. Stateless unit
/// struct; `Send + Sync` trivially.
///
/// Output is `DataTableData`'s serde shape, pretty-printed — the
/// row-keyed table plus its class-level metadata, matching the
/// `paksmith inspect --format json` precedent.
#[derive(Debug, Default, Clone, Copy)]
pub struct DataTableJsonHandler;

impl FormatHandler for DataTableJsonHandler {
    fn output_extension(&self) -> &'static str {
        "json"
    }

    fn supports(&self, asset: &Asset) -> bool {
        // Explicit variant match (vs `GenericHandler`'s unconditional
        // `true`): the registry keys by `Discriminant<Asset>` first, so
        // both this and the upcoming CSV handler share the `DataTable`
        // bucket and return the same `supports`; selection between them
        // is by output extension, not `supports`. The match keeps this
        // a self-consistent predicate for direct callers. (The loud
        // guard against an actual mis-route is `export`'s let-else.)
        matches!(asset, Asset::DataTable(_))
    }

    fn export(&self, asset: &Asset, _bulk: &[BulkData]) -> crate::Result<Vec<u8>> {
        // The dispatch table must only route an `Asset::DataTable`
        // here; any other variant is an internal routing bug, not user
        // input — same registry-contract guard as `GenericHandler`.
        let Asset::DataTable(data) = asset else {
            return Err(crate::PaksmithError::Internal {
                context: "DataTableJsonHandler::export called on non-DataTable Asset".to_string(),
            });
        };
        serde_json::to_vec_pretty(data).map_err(|e| crate::PaksmithError::Internal {
            context: format!("DataTableJsonHandler JSON serialize: {e}"),
        })
    }
}

/// CSV [`FormatHandler`] for `UDataTable` exports. Stateless unit
/// struct; `Send + Sync` trivially.
///
/// Emits a header row (`Name` + the order-preserving union of every
/// row's property columns — first-seen order) and one record per
/// `DataTableRow`. A cell is empty when a row lacks that column.
/// Columns are keyed by `(property name, array_index)` so UE
/// static-array fields stay lossless (`Foo`, `Foo[1]`, `Foo[2]`).
/// Primitive + enum values render directly; complex values JSON-inline
/// (the `csv` writer quotes/escapes as needed). Class-level metadata is
/// dropped — CSV has no schema for it (see
/// [`crate::asset::DataTableData`]). A property literally named `Name`
/// collides with the row-key column and is warned (not renamed).
#[derive(Debug, Default, Clone, Copy)]
pub struct DataTableCsvHandler;

impl FormatHandler for DataTableCsvHandler {
    fn output_extension(&self) -> &'static str {
        "csv"
    }

    fn supports(&self, asset: &Asset) -> bool {
        matches!(asset, Asset::DataTable(_))
    }

    fn export(&self, asset: &Asset, _bulk: &[BulkData]) -> crate::Result<Vec<u8>> {
        let Asset::DataTable(data) = asset else {
            return Err(crate::PaksmithError::Internal {
                context: "DataTableCsvHandler::export called on non-DataTable Asset".to_string(),
            });
        };

        // Order-preserving column union across all rows, keyed by
        // (name, array_index): first-seen wins. UE static-array struct
        // fields (e.g. `int32 Tiers[3]`) serialize as N properties
        // sharing a name with array_index 0..N-1 — keying on the pair
        // keeps every element a distinct column (lossless) rather than
        // collapsing them into one cell. (Rows share a RowStruct but the
        // decoded property set can still vary, e.g. defaulted fields
        // omitted, so a row may not carry every column.)
        let mut columns: Vec<(&str, i32)> = Vec::new();
        for row in &data.rows {
            for prop in &row.properties {
                let key = (prop.name(), prop.array_index);
                if !columns.contains(&key) {
                    columns.push(key);
                }
            }
        }

        // The row's own FName key occupies the leading "Name" column.
        // Warn (don't silently mangle) if a property is ALSO named
        // "Name": the output then has a duplicate "Name" header, which
        // CSV permits but consumers suffix. A reserved-name scheme is
        // left to a follow-up.
        if columns
            .iter()
            .any(|(name, idx)| *idx == 0 && *name == "Name")
        {
            tracing::warn!(
                "DataTable has a property named \"Name\" colliding with the CSV \
                 row-key column; output has a duplicate \"Name\" header"
            );
        }

        // LF line endings, set explicitly (csv's default is also LF, but
        // pinning it keeps the output stable if that changes). UE asset
        // paths are Unix-style; LF is diff/fixture-friendly. Both LF and
        // CRLF are RFC-4180 valid.
        let mut writer = csv::WriterBuilder::new()
            .terminator(csv::Terminator::Any(b'\n'))
            .from_writer(Vec::new());

        let header: Vec<String> = std::iter::once("Name".to_string())
            .chain(columns.iter().map(|(name, idx)| column_header(name, *idx)))
            .collect();
        writer
            .write_record(&header)
            .map_err(|e| crate::PaksmithError::Internal {
                context: format!("DataTableCsvHandler header: {e}"),
            })?;

        for row in &data.rows {
            let mut record: Vec<String> = Vec::with_capacity(columns.len() + 1);
            record.push(row.name.clone());
            for (name, idx) in &columns {
                let cell = row
                    .properties
                    .iter()
                    .find(|p| p.name() == *name && p.array_index == *idx)
                    .map(|p| value_to_csv_cell(&p.value))
                    .unwrap_or_default();
                record.push(cell);
            }
            writer
                .write_record(&record)
                .map_err(|e| crate::PaksmithError::Internal {
                    context: format!("DataTableCsvHandler row: {e}"),
                })?;
        }

        writer
            .into_inner()
            .map_err(|e| crate::PaksmithError::Internal {
                context: format!("DataTableCsvHandler finish: {e}"),
            })
    }
}

/// Render a [`PropertyValue`] as a single CSV cell. Primitive scalar
/// types format directly (numbers, bools, strings); every complex /
/// structured type is JSON-inlined via serde (the `csv` writer
/// handles quoting). The match is exhaustive — a new `PropertyValue`
/// variant won't compile until it's classified here.
fn value_to_csv_cell(value: &PropertyValue) -> String {
    match value {
        PropertyValue::Bool(b) => b.to_string(),
        PropertyValue::Byte(n) => n.to_string(),
        PropertyValue::Int8(n) => n.to_string(),
        PropertyValue::Int16(n) => n.to_string(),
        PropertyValue::Int(n) => n.to_string(),
        PropertyValue::Int64(n) => n.to_string(),
        PropertyValue::UInt16(n) => n.to_string(),
        PropertyValue::UInt32(n) => n.to_string(),
        PropertyValue::UInt64(n) => n.to_string(),
        PropertyValue::Float(f) => f.to_string(),
        PropertyValue::Double(d) => d.to_string(),
        PropertyValue::Str(s) => s.clone(),
        PropertyValue::Name(s) => s.to_string(),
        // Enum renders as the bare variant string (e.g. `EColor__Red`),
        // like `Bool`/`Name` — what a CSV/spreadsheet consumer expects
        // for an enum column, NOT a JSON object.
        PropertyValue::Enum { value, .. } => value.to_string(),
        // Complex / structured values: JSON-inline. One arm so a new
        // structured variant joins here by default.
        PropertyValue::Text(_)
        | PropertyValue::Unknown { .. }
        | PropertyValue::Array { .. }
        | PropertyValue::Struct { .. }
        | PropertyValue::TypedStruct(_)
        | PropertyValue::Map { .. }
        | PropertyValue::Set { .. }
        | PropertyValue::SoftObjectPath { .. }
        | PropertyValue::SoftClassPath { .. }
        | PropertyValue::Object { .. } => {
            serde_json::to_string(value).unwrap_or_else(|_| "<error>".to_string())
        }
    }
}

/// CSV column header for a property `name` at `array_index`: the bare
/// `name` for a scalar / the 0th static-array element, `name[i]` for
/// element `i > 0`. Keeps static-array elements as distinct, lossless
/// columns.
fn column_header(name: &str, array_index: i32) -> String {
    if array_index == 0 {
        name.to_string()
    } else {
        format!("{name}[{array_index}]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::property::bag::PropertyBag;
    use crate::asset::property::primitives::{Property, PropertyValue};
    use crate::asset::{DataTableData, DataTableRow};

    fn prop(name: &str, value: PropertyValue) -> Property {
        Property {
            name: std::sync::Arc::from(name),
            array_index: 0,
            guid: None,
            value,
        }
    }

    fn sample_data_table() -> DataTableData {
        DataTableData {
            row_struct: "ItemRow".to_string(),
            rows: vec![DataTableRow {
                name: "Weapon_Sword".to_string(),
                properties: vec![prop("Damage", PropertyValue::Int(10))],
            }],
            class_properties: PropertyBag::tree(Vec::new()),
        }
    }

    #[test]
    fn json_handler_extension_is_json() {
        assert_eq!(DataTableJsonHandler.output_extension(), "json");
    }

    #[test]
    fn json_handler_supports_data_table_only() {
        assert!(DataTableJsonHandler.supports(&Asset::DataTable(sample_data_table())));
        // A non-DataTable asset must NOT be supported.
        assert!(!DataTableJsonHandler.supports(&Asset::Generic(PropertyBag::opaque(Vec::new()))));
    }

    #[test]
    fn json_handler_emits_data_table_shape() {
        let asset = Asset::DataTable(sample_data_table());
        let bytes = DataTableJsonHandler.export(&asset, &[]).expect("export");
        let json = std::str::from_utf8(&bytes).expect("utf-8 json");
        assert!(
            json.contains("\"row_struct\": \"ItemRow\""),
            "expected row_struct; got: {json}"
        );
        assert!(
            json.contains("\"name\": \"Weapon_Sword\""),
            "expected row name; got: {json}"
        );
        assert!(
            json.contains("\"Int\": 10"),
            "expected externally-tagged Int value; got: {json}"
        );
    }

    #[test]
    fn json_handler_ignores_bulk_argument() {
        use crate::asset::bulk_data::{BulkDataTier, make_zero_record};
        let asset = Asset::DataTable(sample_data_table());
        let bulk = BulkData {
            bytes: vec![0xAA; 4],
            record: make_zero_record(),
            tier: BulkDataTier::Inline,
        };
        let none_result = DataTableJsonHandler.export(&asset, &[]).expect("none");
        let some_result = DataTableJsonHandler
            .export(&asset, std::slice::from_ref(&bulk))
            .expect("some");
        assert_eq!(
            none_result, some_result,
            "bulk argument must not affect DataTable JSON output"
        );
    }

    #[test]
    fn json_handler_export_on_wrong_variant_is_internal_error() {
        // Defensive guard: export must never be routed a non-DataTable
        // asset, but if it is, it returns an Internal fault (not a
        // panic / mis-serialize). Pins the let-else branch.
        let asset = Asset::Generic(PropertyBag::opaque(Vec::new()));
        match DataTableJsonHandler.export(&asset, &[]) {
            Err(crate::PaksmithError::Internal { context }) => {
                assert!(context.contains("non-DataTable"), "got: {context}");
            }
            other => panic!("expected Internal error, got {other:?}"),
        }
    }

    // --- CSV handler ---

    #[test]
    fn csv_handler_extension_is_csv() {
        assert_eq!(DataTableCsvHandler.output_extension(), "csv");
        assert!(DataTableCsvHandler.supports(&Asset::DataTable(sample_data_table())));
        assert!(!DataTableCsvHandler.supports(&Asset::Generic(PropertyBag::opaque(Vec::new()))));
    }

    #[test]
    fn csv_handler_emits_header_and_rows() {
        let data = DataTableData {
            row_struct: "ItemRow".to_string(),
            rows: vec![
                DataTableRow {
                    name: "Weapon_Sword".to_string(),
                    properties: vec![
                        prop("Damage", PropertyValue::Int(10)),
                        prop("Cost", PropertyValue::Int(100)),
                    ],
                },
                DataTableRow {
                    name: "Weapon_Bow".to_string(),
                    properties: vec![
                        prop("Damage", PropertyValue::Int(8)),
                        prop("Cost", PropertyValue::Int(120)),
                    ],
                },
            ],
            class_properties: PropertyBag::tree(Vec::new()),
        };
        let bytes = DataTableCsvHandler
            .export(&Asset::DataTable(data), &[])
            .expect("export");
        let csv = std::str::from_utf8(&bytes).expect("utf-8");
        // LF line endings; column order = first-seen union; Name first.
        assert_eq!(
            csv,
            "Name,Damage,Cost\nWeapon_Sword,10,100\nWeapon_Bow,8,120\n"
        );
    }

    #[test]
    fn csv_handler_column_union_fills_missing_cells_empty() {
        // Row 1 has {A}, row 2 has {A, B}: the union is [A, B] (first-
        // seen order), and row 1's B cell is empty.
        let data = DataTableData {
            row_struct: String::new(),
            rows: vec![
                DataTableRow {
                    name: "r1".to_string(),
                    properties: vec![prop("A", PropertyValue::Int(1))],
                },
                DataTableRow {
                    name: "r2".to_string(),
                    properties: vec![
                        prop("A", PropertyValue::Int(2)),
                        prop("B", PropertyValue::Int(3)),
                    ],
                },
            ],
            class_properties: PropertyBag::tree(Vec::new()),
        };
        let bytes = DataTableCsvHandler
            .export(&Asset::DataTable(data), &[])
            .expect("export");
        let csv = std::str::from_utf8(&bytes).expect("utf-8");
        assert_eq!(csv, "Name,A,B\nr1,1,\nr2,2,3\n");
    }

    #[test]
    fn csv_handler_export_on_wrong_variant_is_internal_error() {
        let asset = Asset::Generic(PropertyBag::opaque(Vec::new()));
        match DataTableCsvHandler.export(&asset, &[]) {
            Err(crate::PaksmithError::Internal { context }) => {
                assert!(context.contains("non-DataTable"), "got: {context}");
            }
            other => panic!("expected Internal error, got {other:?}"),
        }
    }

    #[test]
    fn value_to_csv_cell_renders_each_primitive_directly() {
        // One assert per primitive arm so each `x.to_string()` arm is
        // mutation-pinned (a deleted/blanked arm fails here).
        assert_eq!(value_to_csv_cell(&PropertyValue::Bool(true)), "true");
        assert_eq!(value_to_csv_cell(&PropertyValue::Byte(7)), "7");
        assert_eq!(value_to_csv_cell(&PropertyValue::Int8(-8)), "-8");
        assert_eq!(value_to_csv_cell(&PropertyValue::Int16(-16)), "-16");
        assert_eq!(value_to_csv_cell(&PropertyValue::Int(-32)), "-32");
        assert_eq!(value_to_csv_cell(&PropertyValue::Int64(-64)), "-64");
        assert_eq!(value_to_csv_cell(&PropertyValue::UInt16(16)), "16");
        assert_eq!(value_to_csv_cell(&PropertyValue::UInt32(32)), "32");
        assert_eq!(value_to_csv_cell(&PropertyValue::UInt64(64)), "64");
        assert_eq!(value_to_csv_cell(&PropertyValue::Float(1.5)), "1.5");
        assert_eq!(value_to_csv_cell(&PropertyValue::Double(2.25)), "2.25");
        assert_eq!(
            value_to_csv_cell(&PropertyValue::Str("hi".to_string())),
            "hi"
        );
        assert_eq!(
            value_to_csv_cell(&PropertyValue::Name(std::sync::Arc::from("n"))),
            "n"
        );
        // Enum renders the bare variant string, not a JSON object.
        assert_eq!(
            value_to_csv_cell(&PropertyValue::Enum {
                type_name: std::sync::Arc::from("EColor"),
                value: std::sync::Arc::from("EColor__Red"),
            }),
            "EColor__Red"
        );
    }

    #[test]
    fn value_to_csv_cell_json_inlines_complex_values() {
        use crate::asset::structs::{TypedStructValue, vector::FVector};
        // A typed FVector struct (Phase 3c) takes the JSON-inline arm —
        // confirms TypedStruct is classified complex, not left unhandled.
        let v = PropertyValue::TypedStruct(Box::new(TypedStructValue::Vector(FVector {
            x: 1.0,
            y: 2.0,
            z: 3.0,
        })));
        let cell = value_to_csv_cell(&v);
        // serde_json of the externally-tagged value: {"TypedStruct":{"type":"Vector",...}}.
        assert!(cell.contains("TypedStruct"), "got: {cell}");
        assert!(cell.contains("\"type\":\"Vector\""), "got: {cell}");

        // A second complex variant (Object) also JSON-inlines — pins the
        // shared arm body beyond TypedStruct.
        let obj = PropertyValue::Object {
            kind: crate::asset::PackageIndex::Import(0),
            name: "ItemRow".to_string(),
        };
        let obj_cell = value_to_csv_cell(&obj);
        assert!(obj_cell.contains("Object"), "got: {obj_cell}");
        assert!(obj_cell.contains("ItemRow"), "got: {obj_cell}");
    }

    #[test]
    fn csv_handler_static_array_columns_are_lossless() {
        // A static-array field serializes as N props sharing a name with
        // array_index 0..N-1. Columns must be Tiers, Tiers[1], Tiers[2]
        // — every element preserved, not collapsed to one cell.
        let data = DataTableData {
            row_struct: String::new(),
            rows: vec![DataTableRow {
                name: "r".to_string(),
                properties: vec![
                    Property {
                        name: std::sync::Arc::from("Tiers"),
                        array_index: 0,
                        guid: None,
                        value: PropertyValue::Int(10),
                    },
                    Property {
                        name: std::sync::Arc::from("Tiers"),
                        array_index: 1,
                        guid: None,
                        value: PropertyValue::Int(20),
                    },
                    Property {
                        name: std::sync::Arc::from("Tiers"),
                        array_index: 2,
                        guid: None,
                        value: PropertyValue::Int(30),
                    },
                ],
            }],
            class_properties: PropertyBag::tree(Vec::new()),
        };
        let bytes = DataTableCsvHandler
            .export(&Asset::DataTable(data), &[])
            .expect("export");
        let csv = std::str::from_utf8(&bytes).expect("utf-8");
        assert_eq!(csv, "Name,Tiers,Tiers[1],Tiers[2]\nr,10,20,30\n");
    }

    #[test]
    fn csv_handler_property_named_name_produces_duplicate_header() {
        // A property literally named "Name" collides with the row-key
        // column. The output keeps both (duplicate header) — warned, not
        // silently dropped.
        let data = DataTableData {
            row_struct: String::new(),
            rows: vec![DataTableRow {
                name: "row_key".to_string(),
                properties: vec![prop("Name", PropertyValue::Str("Display".to_string()))],
            }],
            class_properties: PropertyBag::tree(Vec::new()),
        };
        let bytes = DataTableCsvHandler
            .export(&Asset::DataTable(data), &[])
            .expect("export");
        let csv = std::str::from_utf8(&bytes).expect("utf-8");
        // Both the row key and the "Name" property value survive.
        assert_eq!(csv, "Name,Name\nrow_key,Display\n");
    }

    #[tracing_test::traced_test]
    #[test]
    fn csv_handler_warns_on_name_collision() {
        // A "Name" property (array_index 0) fires the collision warn.
        // Pins the predicate's `== 0` + `== "Name"` halves (output alone
        // can't — the warn is a side-effect).
        let with_name = DataTableData {
            row_struct: String::new(),
            rows: vec![DataTableRow {
                name: "r".to_string(),
                properties: vec![prop("Name", PropertyValue::Str("x".to_string()))],
            }],
            class_properties: PropertyBag::tree(Vec::new()),
        };
        let _ = DataTableCsvHandler
            .export(&Asset::DataTable(with_name), &[])
            .expect("export");
        assert!(
            logs_contain("colliding with the CSV row-key column"),
            "a property named \"Name\" must warn"
        );
    }

    #[tracing_test::traced_test]
    #[test]
    fn csv_handler_no_warn_for_normal_table() {
        // A normal table (only a "Damage" property) must NOT warn —
        // guards the predicate's `&&` against firing too eagerly.
        let _ = DataTableCsvHandler
            .export(&Asset::DataTable(sample_data_table()), &[])
            .expect("export");
        assert!(
            !logs_contain("colliding with the CSV row-key column"),
            "a table without a \"Name\" property must NOT warn"
        );
    }

    #[test]
    fn registry_routes_data_table_csv_first_json_by_extension() {
        // all_default_handlers registers CSV before JSON for the
        // DataTable bucket: find_handler returns CSV (the default);
        // find_handler_by_extension picks JSON explicitly.
        let reg = crate::export::HandlerRegistry::all_default_handlers();
        let asset = Asset::DataTable(sample_data_table());
        assert_eq!(
            reg.find_handler(&asset)
                .expect("a handler")
                .output_extension(),
            "csv",
            "CSV must be the find_handler default for a DataTable"
        );
        assert_eq!(
            reg.find_handler_by_extension("json", &asset)
                .expect("a json handler")
                .output_extension(),
            "json"
        );
    }
}
