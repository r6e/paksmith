//! Decoded property body for one export.
//!
//! Phase 2a shipped only the [`PropertyBag::Opaque`] variant — the
//! export's serialized bytes are carried verbatim. Phase 2b adds
//! [`PropertyBag::Tree`], a decoded property list produced by the
//! tagged-property iterator [`super::read_properties`]. Phase 2c will
//! land the container properties whose recursive parsing is bounded
//! by `MAX_PROPERTY_DEPTH`.

use std::fmt;

use serde::Serialize;

use super::primitives::Property;

/// Hard cap on nested struct/array/map depth in the property tree.
/// Defined here in Phase 2a even though only Phase 2c references it,
/// to lock the contract before downstream parsers are written. Value
/// chosen to match FModel's nesting bound; UE assets in practice
/// never nest beyond ~12.
///
/// Visibility is `pub(crate)` because every other Phase 2a structural
/// cap (`MAX_NAME_TABLE_ENTRIES`, `MAX_IMPORT_TABLE_ENTRIES`, etc.) is
/// private — this is a defensive bound for in-crate parsers, not a
/// semantic compatibility boundary like `FIRST_UNSUPPORTED_UE5_VERSION`.
/// Phase 2b's `read_properties` iterator consumes it; the Phase 2a
/// `#[allow(dead_code)]` is no longer needed.
pub(crate) const MAX_PROPERTY_DEPTH: usize = 128;

/// Decoded body for one export.
///
/// `#[non_exhaustive]` so future Phases can add variants without
/// source-breaking downstream `match` arms.
///
/// **`Eq` is intentionally NOT derived** because the `Tree` variant
/// contains `Vec<Property>`, which contains `PropertyValue::Float(f32)`
/// and `PropertyValue::Double(f64)` — neither of which implements
/// `Eq` (NaN ≠ NaN). `PartialEq` remains for tests and
/// snapshot-comparison purposes.
///
/// `Debug` is hand-rolled to elide payload content (mirrors the
/// `Serialize` impl). The derived `Debug` would emit the entire
/// `Vec<u8>` for `Opaque` and the full property list for `Tree`; for
/// large exports, that blows up any `dbg!`/`tracing::debug!`/panic
/// dump.
#[derive(Clone, PartialEq, Serialize)]
#[non_exhaustive]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PropertyBag {
    /// Phase 2a: raw bytes carved out of the asset's payload region.
    /// Also the fallback if Phase 2b's tagged-property iterator
    /// errors mid-parse (the iterator's `warn!` fallback path
    /// re-reads the export bytes verbatim).
    Opaque {
        /// The export's serialized bytes (length matches
        /// `ObjectExport::serial_size`).
        #[serde(serialize_with = "serialize_byte_count")]
        bytes: Vec<u8>,
    },
    /// Phase 2b: decoded FPropertyTag sequence.
    Tree {
        /// The decoded property list (one entry per FPropertyTag).
        properties: Vec<Property>,
    },
}

impl fmt::Debug for PropertyBag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Opaque { bytes } => f
                .debug_struct("Opaque")
                .field("bytes", &format_args!("<{} bytes>", bytes.len()))
                .finish(),
            Self::Tree { properties } => f
                .debug_struct("Tree")
                .field(
                    "properties",
                    &format_args!("<{} entries>", properties.len()),
                )
                .finish(),
        }
    }
}

impl PropertyBag {
    /// Convenience constructor for the Phase-2a opaque variant.
    #[must_use]
    pub fn opaque(bytes: Vec<u8>) -> Self {
        Self::Opaque { bytes }
    }

    /// Convenience constructor for the Phase-2b tree variant.
    #[must_use]
    pub fn tree(properties: Vec<Property>) -> Self {
        Self::Tree { properties }
    }

    /// Number of payload units in the bag.
    ///
    /// For `Opaque`, returns the raw byte count. For `Tree`, returns
    /// the property count — units differ by variant. Callers that need
    /// the byte count specifically should match the variant.
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Self::Opaque { bytes } => bytes.len(),
            Self::Tree { properties } => properties.len(),
        }
    }

    /// `true` if the bag holds no payload (zero bytes for `Opaque`,
    /// zero properties for `Tree`).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Serialize `bytes` as just its length, not its content. Asset
/// payloads can be megabytes; serializing them inline would blow up
/// `inspect` JSON output. The `Tree` variant serializes the decoded
/// property structure instead.
#[allow(
    clippy::ptr_arg,
    reason = "serde's #[serialize_with] requires &Vec<u8> exactly — it doesn't auto-deref to &[u8]"
)]
fn serialize_byte_count<S: serde::Serializer>(
    bytes: &Vec<u8>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_u64(bytes.len() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::property::primitives::{Property, PropertyValue};

    #[test]
    fn opaque_len() {
        let bag = PropertyBag::opaque(vec![0u8; 84]);
        assert_eq!(bag.len(), 84);
    }

    #[test]
    fn serialize_renders_byte_count_not_payload() {
        let bag = PropertyBag::opaque(vec![1, 2, 3, 4, 5]);
        let json = serde_json::to_string(&bag).unwrap();
        assert_eq!(json, r#"{"kind":"opaque","bytes":5}"#);
    }

    #[test]
    fn max_depth_constant_is_locked() {
        assert_eq!(MAX_PROPERTY_DEPTH, 128);
    }

    #[test]
    fn debug_elides_byte_content() {
        let bag = PropertyBag::opaque(vec![0u8; 1_048_576]);
        let debug_output = format!("{bag:?}");
        assert!(
            !debug_output.contains("0, 0, 0"),
            "Debug should not emit byte content; got: {debug_output}"
        );
        assert!(
            debug_output.contains("1048576 bytes"),
            "Debug should emit byte count; got: {debug_output}"
        );
    }

    #[test]
    fn tree_variant_serializes_properties_array() {
        let bag = PropertyBag::tree(vec![Property {
            name: "bEnabled".to_string(),
            array_index: 0,
            guid: None,
            value: PropertyValue::Bool(true),
        }]);
        let json = serde_json::to_string(&bag).unwrap();
        // Internally-tagged enum (kind = tree) with the inner struct
        // flattened. Pinned literally so a future shape change is
        // forced through this assertion.
        assert!(
            json.contains(r#""kind":"tree""#),
            "expected internally-tagged kind=tree; got: {json}"
        );
        assert!(
            json.contains(r#""properties":["#),
            "expected nested properties array; got: {json}"
        );
        assert!(json.contains("bEnabled"), "got: {json}");
        assert!(json.contains("Bool"), "got: {json}");
    }

    #[test]
    fn tree_len_returns_property_count() {
        let props = vec![
            Property {
                name: "a".into(),
                array_index: 0,
                guid: None,
                value: PropertyValue::Bool(true),
            },
            Property {
                name: "b".into(),
                array_index: 0,
                guid: None,
                value: PropertyValue::Int(42),
            },
        ];
        let bag = PropertyBag::tree(props);
        // For Tree, len() returns property count (not raw bytes — the
        // tree is decoded). Pinned so the semantic stays explicit.
        assert_eq!(bag.len(), 2);
    }

    #[test]
    fn tree_debug_elides_property_list() {
        let props: Vec<Property> = (0..1000)
            .map(|i| Property {
                name: format!("p{i}"),
                array_index: 0,
                guid: None,
                value: PropertyValue::Int(i),
            })
            .collect();
        let bag = PropertyBag::tree(props);
        let debug_output = format!("{bag:?}");
        assert!(
            debug_output.contains("1000 entries"),
            "Debug should emit property count; got: {debug_output}"
        );
        // No individual property names should appear in the elided debug.
        assert!(
            !debug_output.contains("p500"),
            "Debug should elide property contents; got: {debug_output}"
        );
    }
}
