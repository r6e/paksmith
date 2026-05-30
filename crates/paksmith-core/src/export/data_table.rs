//! `UDataTable` JSON export handler (Phase 3d).
//!
//! Emits an [`Asset::DataTable`] as pretty-printed JSON — the typed
//! `{ row_struct, rows: [{ name, properties }…], class_properties }`
//! shape that `DataTableData` derives via serde. Registered for the
//! `Asset::DataTable` discriminant in a later task; until then it's a
//! directly-callable building block (the CSV sibling lands in Task 4).

use crate::asset::Asset;

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

    fn export(&self, asset: &Asset, _bulk: Option<&BulkData>) -> crate::Result<Vec<u8>> {
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
        let bytes = DataTableJsonHandler.export(&asset, None).expect("export");
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
        let none_result = DataTableJsonHandler.export(&asset, None).expect("none");
        let some_result = DataTableJsonHandler
            .export(&asset, Some(&bulk))
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
        match DataTableJsonHandler.export(&asset, None) {
            Err(crate::PaksmithError::Internal { context }) => {
                assert!(context.contains("non-DataTable"), "got: {context}");
            }
            other => panic!("expected Internal error, got {other:?}"),
        }
    }
}
