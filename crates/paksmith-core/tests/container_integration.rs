//! Phase 2c end-to-end container-property integration tests.
//!
//! Builds the in-memory `build_minimal_ue4_27_with_containers`
//! fixture and asserts the property tree the iterator decodes for
//! Array / Struct / Map / Set bodies.

#![allow(missing_docs)]

#[cfg(feature = "__test_utils")]
mod tests {
    use paksmith_core::asset::Package;
    use paksmith_core::asset::property::primitives::{MapEntry, Property};
    use paksmith_core::asset::property::{PropertyBag, PropertyValue};
    use paksmith_core::testing::uasset::build_minimal_ue4_27_with_containers;

    fn decode_properties() -> Vec<Property> {
        let pkg = build_minimal_ue4_27_with_containers();
        let parsed = Package::read_from(&pkg.bytes, None, None, "Game/Data/Test.uasset")
            .expect("Package::read_from failed");
        assert_eq!(parsed.payloads.len(), 1, "expected one export");
        match parsed.payloads.into_iter().next().unwrap() {
            PropertyBag::Tree { properties } => properties,
            other => panic!("expected PropertyBag::Tree on the container fixture; got {other:?}"),
        }
    }

    #[test]
    fn parse_array_of_int_properties() {
        let props = decode_properties();
        let tags = props
            .iter()
            .find(|p| p.name() == "Tags")
            .expect("Tags property missing");
        assert_eq!(
            tags.value,
            PropertyValue::Array {
                inner_type: "IntProperty".to_string(),
                elements: vec![PropertyValue::Int(10), PropertyValue::Int(20)],
            }
        );
    }

    #[test]
    fn parse_struct_property() {
        let props = decode_properties();
        let stats = props
            .iter()
            .find(|p| p.name() == "Stats")
            .expect("Stats property missing");
        match &stats.value {
            PropertyValue::Struct {
                struct_name,
                properties,
            } => {
                assert_eq!(struct_name, "StatStruct");
                assert_eq!(properties.len(), 1);
                assert_eq!(properties[0].name(), "Speed");
                assert_eq!(properties[0].value, PropertyValue::Float(600.0));
            }
            other => panic!("expected Struct, got {other:?}"),
        }
    }

    #[test]
    fn parse_map_property() {
        let props = decode_properties();
        let lookup = props
            .iter()
            .find(|p| p.name() == "Lookup")
            .expect("Lookup property missing");
        assert_eq!(
            lookup.value,
            PropertyValue::Map {
                key_type: "StrProperty".to_string(),
                value_type: "IntProperty".to_string(),
                entries: vec![MapEntry {
                    key: PropertyValue::Str("alpha".to_string()),
                    value: PropertyValue::Int(1),
                }],
            }
        );
    }

    #[test]
    fn parse_set_property() {
        let props = decode_properties();
        let flags = props
            .iter()
            .find(|p| p.name() == "Flags")
            .expect("Flags property missing");
        assert_eq!(
            flags.value,
            PropertyValue::Set {
                inner_type: "NameProperty".to_string(),
                elements: vec![
                    PropertyValue::Name("Tag_A".to_string()),
                    PropertyValue::Name("Tag_B".to_string()),
                ],
            }
        );
    }
}
