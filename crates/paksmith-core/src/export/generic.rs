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

    fn supports(&self, asset: &Asset) -> bool {
        // Match only the Generic variant. Phase 3d-3h's typed
        // variants register their own handlers under distinct
        // discriminants; GenericHandler must not claim them.
        matches!(asset, Asset::Generic(_))
    }

    fn export(&self, asset: &Asset, _bulk: Option<&BulkData>) -> crate::Result<Vec<u8>> {
        // `let Asset::Generic(bag) = asset else` is irrefutable
        // today (Asset is single-variant in Phase 2 closure +
        // Phase 3a) and becomes refutable when Phase 3d-3h add
        // typed variants (DataTable, Texture2D, etc.). The
        // defensive `else` branch is the registry-contract
        // violation guard documented at PaksmithError::Internal.
        // `#[allow(irrefutable_let_patterns)]` suppresses the
        // current-Phase warning without dropping the
        // forward-compat guard.
        //
        // TODO(phase-3d): remove the `#[allow]` once Asset gains a
        // second variant — the let-else becomes refutable and the
        // attribute becomes silently dead.
        #[allow(irrefutable_let_patterns)]
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
        // 3a's BulkData is a unit struct stub; GenericHandler must
        // accept any value (including None) and never inspect it.
        let asset = Asset::Generic(PropertyBag::opaque(Vec::new()));
        let none_result = GenericHandler.export(&asset, None);
        let some_result = GenericHandler.export(&asset, Some(&BulkData));
        assert!(none_result.is_ok());
        assert!(some_result.is_ok());
        assert_eq!(
            none_result.unwrap(),
            some_result.unwrap(),
            "GenericHandler must produce identical output regardless of bulk argument"
        );
    }
}
