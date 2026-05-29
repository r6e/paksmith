//! Decoded property body for one export.
//!
//! Phase 2a shipped only the [`PropertyBag::Opaque`] variant — the
//! export's serialized bytes are carried verbatim. Phase 2b adds
//! [`PropertyBag::Tree`], a decoded property list produced by the
//! tagged-property iterator [`super::read_properties`]. Phase 2c will
//! land the container properties whose recursive parsing is bounded
//! by `MAX_PROPERTY_DEPTH`.

use std::fmt;
#[cfg(test)]
use std::sync::Arc;

use serde::{Deserialize, Serialize};

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
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PropertyBag {
    /// Phase 2a: raw bytes carved out of the asset's payload region.
    /// Also the fallback if Phase 2b's tagged-property iterator
    /// errors mid-parse (the iterator's `warn!` fallback path
    /// re-reads the export bytes verbatim).
    ///
    /// **Round-trip note:** serialization is intentionally lossy
    /// (only the byte count appears in JSON; see
    /// `serialize_byte_count`). Deserialization reads the byte count
    /// back via `deserialize_byte_count` and reconstructs an
    /// **all-zero** `Vec<u8>` of that length. The reconstructed
    /// `Opaque` therefore matches the original on `.len()` but NOT
    /// on byte content. Consumers needing true byte fidelity must
    /// keep the source asset; the JSON surface is for diagnostics.
    Opaque {
        /// The export's serialized bytes (length matches
        /// `ObjectExport::serial_size`).
        #[serde(
            serialize_with = "serialize_byte_count",
            deserialize_with = "deserialize_byte_count"
        )]
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

    /// Returns the decoded property list when this is [`Tree`], or
    /// `None` when [`Opaque`].
    ///
    /// Lets Phase 3+ format handlers avoid the per-call
    /// `match { Tree { properties } => ... }` boilerplate:
    ///
    /// ```ignore
    /// if let Some(props) = bag.as_tree() {
    ///     for prop in props { /* ... */ }
    /// }
    /// ```
    ///
    /// [`Tree`]: PropertyBag::Tree
    /// [`Opaque`]: PropertyBag::Opaque
    #[must_use]
    pub fn as_tree(&self) -> Option<&[Property]> {
        match self {
            Self::Tree { properties } => Some(properties),
            Self::Opaque { .. } => None,
        }
    }

    /// Returns `true` if the export's property tree was successfully
    /// decoded ([`Tree`]); `false` if the iterator fell back to
    /// [`Opaque`].
    ///
    /// [`Tree`]: PropertyBag::Tree
    /// [`Opaque`]: PropertyBag::Opaque
    #[must_use]
    pub fn is_tree(&self) -> bool {
        matches!(self, Self::Tree { .. })
    }

    /// Iterator over decoded properties; empty when [`Opaque`].
    ///
    /// Lets handlers write `for prop in bag.iter_properties() { … }`
    /// uniformly across both variants — `Opaque` exports
    /// contribute no entries.
    ///
    /// [`Opaque`]: PropertyBag::Opaque
    pub fn iter_properties(&self) -> impl Iterator<Item = &Property> {
        self.as_tree().into_iter().flatten()
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

/// Hard cap on `PropertyBag::Opaque` byte counts accepted by the
/// JSON deserializer. Mirrors the wire-side ceiling
/// `package::MAX_PAYLOAD_BYTES` (256 MiB) — a malicious JSON could
/// otherwise claim `u64::MAX` bytes and OOM the allocator. The cap
/// kept module-local because it bounds a JSON-side decision, not a
/// wire-format constraint.
const MAX_OPAQUE_DESERIALIZE_BYTES: u64 = 256 * 1024 * 1024;

/// Deserialize the Opaque byte count back into a same-length zero-
/// filled `Vec<u8>`. The original bytes are unrecoverable from JSON
/// — the count alone preserves `.len()`. See the variant docstring
/// for the lossy-round-trip contract.
///
/// Rejects counts above [`MAX_OPAQUE_DESERIALIZE_BYTES`] before any
/// allocation runs; uses `try_reserve_exact` so even a same-host
/// pathological count surfaces as a serde error rather than a panic.
fn deserialize_byte_count<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<u8>, D::Error> {
    let count = u64::deserialize(deserializer)?;
    if count > MAX_OPAQUE_DESERIALIZE_BYTES {
        return Err(serde::de::Error::custom(format!(
            "Opaque byte count {count} exceeds MAX_OPAQUE_DESERIALIZE_BYTES \
             ({MAX_OPAQUE_DESERIALIZE_BYTES})"
        )));
    }
    let count: usize = count
        .try_into()
        .map_err(|_| serde::de::Error::custom("Opaque byte count exceeds usize::MAX"))?;
    let mut v = Vec::new();
    v.try_reserve_exact(count)
        .map_err(|e| serde::de::Error::custom(format!("Opaque allocation failed: {e}")))?;
    v.resize(count, 0u8);
    Ok(v)
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
    fn opaque_round_trips_byte_count_through_json() {
        // Opaque is intentionally lossy: bytes-out is a u64 count;
        // bytes-in reconstructs a zero-filled Vec of that length.
        // `.len()` is preserved; payload content is gone by design.
        let original = PropertyBag::opaque(vec![1, 2, 3, 4, 5]);
        let json = serde_json::to_string(&original).unwrap();
        let parsed: PropertyBag = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), original.len());
        match parsed {
            PropertyBag::Opaque { bytes } => {
                assert_eq!(bytes, vec![0u8; 5]);
            }
            other => panic!("expected Opaque, got {other:?}"),
        }
    }

    #[test]
    fn opaque_rejects_count_exceeding_cap() {
        // A claim above MAX_OPAQUE_DESERIALIZE_BYTES surfaces as a
        // serde error BEFORE the allocator gets the request — pins
        // the DoS defense for hostile JSON.
        let input = r#"{"kind":"opaque","bytes":18446744073709551615}"#; // u64::MAX
        let result: Result<PropertyBag, _> = serde_json::from_str(input);
        assert!(
            result.is_err(),
            "u64::MAX byte count must be rejected, got: {result:?}"
        );
    }

    #[test]
    fn opaque_at_cap_boundary_proceeds() {
        // A small bounded value pins that the normal-input path is
        // unaffected by the cap check.
        let input = r#"{"kind":"opaque","bytes":3}"#;
        let parsed: PropertyBag = serde_json::from_str(input).unwrap();
        assert_eq!(parsed.len(), 3);
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
            name: Arc::from("bEnabled"),
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

    // Variant fixtures kept inline rather than extracted to a helper
    // so each variant's expected shape is grep-able in one place.
    #[allow(clippy::too_many_lines)]
    #[test]
    fn tree_round_trips_through_json() {
        // Pin the contract for `PropertyBag::Tree`: every PropertyValue
        // variant the iterator can emit (except StructProperty inner
        // arrays which fall back to Unknown) survives a
        // serde_json::to_string → from_str round-trip. The Opaque
        // variant is intentionally lossy (byte-count Serialize) and
        // therefore not part of this contract.
        use crate::asset::property::primitives::{MapEntry, Property, PropertyValue};
        use crate::asset::property::text::{FText, FTextHistory};

        let original = PropertyBag::tree(vec![
            Property {
                name: "bEnabled".into(),
                array_index: 0,
                guid: None,
                value: PropertyValue::Bool(true),
            },
            Property {
                name: "Counter".into(),
                array_index: 0,
                guid: Some([0xAB; 16]),
                value: PropertyValue::Int(42),
            },
            Property {
                name: "Speed".into(),
                array_index: 1,
                guid: None,
                value: PropertyValue::Float(3.5),
            },
            Property {
                name: "Label".into(),
                array_index: 0,
                guid: None,
                value: PropertyValue::Str("hello".into()),
            },
            Property {
                name: "Color".into(),
                array_index: 0,
                guid: None,
                value: PropertyValue::Enum {
                    type_name: "EColor".into(),
                    value: "Red".into(),
                },
            },
            Property {
                name: "Localized".into(),
                array_index: 0,
                guid: None,
                value: PropertyValue::Text(FText {
                    flags: 0,
                    history: FTextHistory::Base {
                        namespace: "ns".into(),
                        key: "k".into(),
                        source_string: "Hi".into(),
                    },
                }),
            },
            Property {
                name: "Numbers".into(),
                array_index: 0,
                guid: None,
                value: PropertyValue::Array {
                    inner_type: "IntProperty".into(),
                    elements: vec![PropertyValue::Int(1), PropertyValue::Int(2)],
                },
            },
            Property {
                name: "Stats".into(),
                array_index: 0,
                guid: None,
                value: PropertyValue::Struct {
                    struct_name: "Vector".into(),
                    properties: vec![Property {
                        name: "X".into(),
                        array_index: 0,
                        guid: None,
                        value: PropertyValue::Float(1.0),
                    }],
                },
            },
            Property {
                // Phase 3c Task 10 — `TypedStruct` is now emitted at
                // runtime (a registered StructProperty decodes to it),
                // so pin its JSON round-trip here too.
                name: "Origin".into(),
                array_index: 0,
                guid: None,
                value: PropertyValue::TypedStruct(Box::new(
                    crate::asset::structs::TypedStructValue::Vector(
                        crate::asset::structs::vector::FVector {
                            x: 1.0,
                            y: 2.0,
                            z: 3.0,
                        },
                    ),
                )),
            },
            Property {
                name: "Lookup".into(),
                array_index: 0,
                guid: None,
                value: PropertyValue::Map {
                    key_type: "StrProperty".into(),
                    value_type: "IntProperty".into(),
                    entries: vec![MapEntry {
                        key: PropertyValue::Str("k1".into()),
                        value: PropertyValue::Int(7),
                    }],
                },
            },
            Property {
                name: "Tags".into(),
                array_index: 0,
                guid: None,
                value: PropertyValue::Set {
                    inner_type: "NameProperty".into(),
                    elements: vec![PropertyValue::Name("Foo".into())],
                },
            },
            Property {
                name: "Skipped".into(),
                array_index: 0,
                guid: None,
                value: PropertyValue::Unknown {
                    type_name: "DelegateProperty".into(),
                    skipped_bytes: 16,
                },
            },
            Property {
                name: "SoftRef".into(),
                array_index: 0,
                guid: None,
                value: PropertyValue::SoftObjectPath {
                    asset_path: "/Game/Data/Hero.Hero".into(),
                    sub_path: String::new(),
                },
            },
            Property {
                name: "SoftCls".into(),
                array_index: 0,
                guid: None,
                value: PropertyValue::SoftClassPath {
                    asset_path: "/Game/BP/HC.HC_C".into(),
                    sub_path: "sub".into(),
                },
            },
            // `Object` variant carries `PackageIndex` — exercises the
            // hand-rolled string-form PackageIndex Deserialize inside
            // a tree traversal (the typed Import/Export shape and the
            // Null sentinel are both pinned).
            Property {
                name: "ObjRef".into(),
                array_index: 0,
                guid: None,
                value: PropertyValue::Object {
                    kind: crate::asset::PackageIndex::Import(2),
                    name: "SomeMesh".into(),
                },
            },
            Property {
                name: "NullObj".into(),
                array_index: 0,
                guid: None,
                value: PropertyValue::Object {
                    kind: crate::asset::PackageIndex::Null,
                    name: String::new(),
                },
            },
        ]);

        let json = serde_json::to_string(&original).expect("serialize");
        let parsed: PropertyBag = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, original);
    }

    #[test]
    fn tree_debug_elides_property_list() {
        let props: Vec<Property> = (0..1000)
            .map(|i| Property {
                name: Arc::from(format!("p{i}")),
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

    fn sample_property(name: &str) -> Property {
        Property {
            name: Arc::from(name),
            array_index: 0,
            guid: None,
            value: PropertyValue::Bool(true),
        }
    }

    #[test]
    fn as_tree_returns_some_for_tree_variant() {
        let bag = PropertyBag::tree(vec![sample_property("a"), sample_property("b")]);
        let props = bag.as_tree().expect("Tree variant should yield Some");
        assert_eq!(props.len(), 2);
        assert_eq!(props[0].name.as_ref(), "a");
        assert_eq!(props[1].name.as_ref(), "b");
    }

    #[test]
    fn as_tree_returns_none_for_opaque_variant() {
        let bag = PropertyBag::opaque(vec![1, 2, 3]);
        assert!(bag.as_tree().is_none());
    }

    #[test]
    fn is_tree_discriminates_variants() {
        assert!(PropertyBag::tree(vec![sample_property("x")]).is_tree());
        assert!(!PropertyBag::opaque(vec![0u8; 10]).is_tree());
    }

    #[test]
    fn iter_properties_yields_for_tree() {
        let bag = PropertyBag::tree(vec![sample_property("a"), sample_property("b")]);
        let names: Vec<&str> = bag.iter_properties().map(|p| p.name.as_ref()).collect();
        assert_eq!(names, vec!["a", "b"]);
    }

    #[test]
    fn iter_properties_is_empty_for_opaque() {
        let bag = PropertyBag::opaque(vec![1, 2, 3]);
        assert_eq!(bag.iter_properties().count(), 0);
    }
}
