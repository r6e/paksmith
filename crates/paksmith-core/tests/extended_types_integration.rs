//! Integration tests for Phase 2d extended property types.

#![allow(missing_docs)]

#[cfg(feature = "__test_utils")]
mod tests {
    use paksmith_core::asset::Package;
    use paksmith_core::asset::package_index::PackageIndex;
    use paksmith_core::asset::property::primitives::Property;
    use paksmith_core::asset::property::text::{FText, FTextHistory};
    use paksmith_core::asset::property::{PropertyBag, PropertyValue};
    use paksmith_core::testing::uasset::build_minimal_ue4_27_with_extended_types;

    fn decode_properties() -> Vec<Property> {
        let pkg = build_minimal_ue4_27_with_extended_types();
        let parsed = Package::read_from(&pkg.bytes, None, None, "Game/Data/Test.uasset")
            .expect("Package::read_from failed");
        assert_eq!(parsed.payloads.len(), 1, "expected one export");
        match parsed.payloads.into_iter().next().unwrap() {
            PropertyBag::Tree { properties } => properties,
            other => {
                panic!("expected PropertyBag::Tree on extended-types fixture; got {other:?}")
            }
        }
    }

    #[test]
    fn parse_soft_object_property() {
        let props = decode_properties();
        let prop = props.iter().find(|p| p.name == "SoftRef").unwrap();
        assert_eq!(
            prop.value,
            PropertyValue::SoftObjectPath {
                asset_path: "/Game/Data/Hero.Hero".to_string(),
                sub_path: String::new(),
            }
        );
    }

    #[test]
    fn parse_soft_class_property() {
        let props = decode_properties();
        let prop = props.iter().find(|p| p.name == "SoftClass").unwrap();
        assert_eq!(
            prop.value,
            PropertyValue::SoftClassPath {
                asset_path: "/Game/BP/HeroClass.HeroClass_C".to_string(),
                sub_path: String::new(),
            }
        );
    }

    #[test]
    fn parse_object_property() {
        let props = decode_properties();
        let prop = props.iter().find(|p| p.name == "ObjRef").unwrap();
        assert!(matches!(
            &prop.value,
            PropertyValue::Object {
                kind: PackageIndex::Import(0),
                name,
            } if name == "Default__Object"
        ));
    }

    #[test]
    fn parse_array_of_byte_properties() {
        let props = decode_properties();
        let prop = props.iter().find(|p| p.name == "Tags").unwrap();
        assert_eq!(
            prop.value,
            PropertyValue::Array {
                inner_type: "ByteProperty".to_string(),
                elements: vec![PropertyValue::Byte(10), PropertyValue::Byte(20)],
            }
        );
    }

    #[test]
    fn parse_array_of_enum_properties() {
        let props = decode_properties();
        let prop = props.iter().find(|p| p.name == "Flags").unwrap();
        assert_eq!(
            prop.value,
            PropertyValue::Array {
                inner_type: "EnumProperty".to_string(),
                elements: vec![PropertyValue::Enum {
                    type_name: String::new(),
                    value: "EColor__Red".to_string(),
                }],
            }
        );
    }

    #[test]
    fn parse_array_of_text_properties() {
        let props = decode_properties();
        let prop = props.iter().find(|p| p.name == "Desc").unwrap();
        assert_eq!(
            prop.value,
            PropertyValue::Array {
                inner_type: "TextProperty".to_string(),
                elements: vec![PropertyValue::Text(FText {
                    flags: 0,
                    history: FTextHistory::None {
                        culture_invariant: None,
                    },
                })],
            }
        );
    }
}
