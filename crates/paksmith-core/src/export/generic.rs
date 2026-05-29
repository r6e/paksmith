//! Generic passthrough handler — the universal fallback for
//! `Asset::Generic` exports. Emits the parsed property tree as
//! pretty-printed JSON.

use crate::asset::Asset;

use super::{BulkData, FormatHandler};

/// Passthrough handler: emits the asset's parsed property tree as
/// pretty-printed JSON. Matches every `Asset::Generic` variant;
/// never matches typed Phase 3d-3h variants (they get their own
/// handlers registered under different `Discriminant<Asset>` keys).
///
/// The output is JSON because the generic case is "we parsed the
/// properties but don't know the class shape" — emitting structured
/// JSON keeps the output human-inspectable and matches the existing
/// `paksmith inspect` precedent.
///
/// Stateless unit struct. Safe to share across threads (`Send + Sync`
/// trivially).
#[derive(Debug, Default, Clone, Copy)]
pub struct GenericHandler;

impl FormatHandler for GenericHandler {
    fn output_extension(&self) -> &'static str {
        "json"
    }

    fn supports(&self, _asset: &Asset) -> bool {
        // Unconditional `true`: `HandlerRegistry::find_handler` keys
        // by `Discriminant<Asset>` before consulting `supports`, so
        // this is only ever called with `Asset::Generic`. Phase 3d-3h
        // typed variants reach their own per-discriminant buckets.
        true
    }

    fn export(&self, asset: &Asset, _bulk: Option<&BulkData>) -> crate::Result<Vec<u8>> {
        // `let Asset::Generic(bag) = asset else` is irrefutable
        // today (Asset is single-variant in Phase 2 closure +
        // Phase 3a) and is now refutable since Phase 3d added
        // `Asset::DataTable`. The defensive `else` branch is the
        // registry-contract violation guard documented at
        // PaksmithError::Internal: the dispatch table must only route
        // an `Asset::Generic` payload to this handler, so any other
        // variant here is an internal routing bug, not user input.
        let Asset::Generic(bag) = asset else {
            return Err(crate::PaksmithError::Internal {
                context: "GenericHandler::export called on non-Generic Asset".to_string(),
            });
        };
        serde_json::to_vec_pretty(bag).map_err(|e| crate::PaksmithError::Internal {
            context: format!("GenericHandler JSON serialize: {e}"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::property::bag::PropertyBag;

    #[test]
    fn generic_handler_extension_is_json() {
        assert_eq!(GenericHandler.output_extension(), "json");
    }

    #[test]
    fn generic_handler_supports_generic_variant() {
        let asset = Asset::Generic(PropertyBag::opaque(Vec::new()));
        assert!(GenericHandler.supports(&asset));
    }

    #[test]
    fn generic_handler_export_opaque_emits_kind_and_bytes() {
        // Opaque bag with 42 bytes serializes (lossily, per
        // PropertyBag::opaque's documented contract) as
        // {"kind": "opaque", "bytes": 42} after pretty-print.
        let asset = Asset::Generic(PropertyBag::opaque(vec![0u8; 42]));
        let bytes = GenericHandler.export(&asset, None).expect("export");
        let json = std::str::from_utf8(&bytes).expect("utf-8 json");
        assert!(
            json.contains("\"kind\": \"opaque\""),
            "expected opaque kind tag; got: {json}"
        );
        assert!(
            json.contains("\"bytes\": 42"),
            "expected byte count 42; got: {json}"
        );
    }

    #[test]
    fn generic_handler_export_tree_emits_properties_array() {
        // Tree bag with empty properties serializes as
        // {"kind": "tree", "properties": []}.
        let asset = Asset::Generic(PropertyBag::tree(Vec::new()));
        let bytes = GenericHandler.export(&asset, None).expect("export");
        let json = std::str::from_utf8(&bytes).expect("utf-8 json");
        assert!(
            json.contains("\"kind\": \"tree\""),
            "expected tree kind tag; got: {json}"
        );
        assert!(
            json.contains("\"properties\": []"),
            "expected empty properties array; got: {json}"
        );
    }

    #[test]
    fn generic_handler_export_ignores_bulk_argument() {
        // GenericHandler must accept any `Option<&BulkData>` and
        // never inspect it. 3a tested this against the unit-struct
        // stub; 3b Task 4 widened `BulkData` to fields-bearing
        // (`bytes`, `record`, `tier`) — same contract, richer type.
        use crate::asset::bulk_data::{BulkDataTier, make_zero_record};
        let asset = Asset::Generic(PropertyBag::opaque(Vec::new()));
        let bulk = BulkData {
            bytes: vec![0xAA; 4],
            record: make_zero_record(),
            tier: BulkDataTier::Inline,
        };

        let none_result = GenericHandler.export(&asset, None);
        let some_result = GenericHandler.export(&asset, Some(&bulk));
        assert!(none_result.is_ok());
        assert!(some_result.is_ok());
        assert_eq!(
            none_result.unwrap(),
            some_result.unwrap(),
            "GenericHandler must produce identical output regardless of bulk argument"
        );
    }
}
