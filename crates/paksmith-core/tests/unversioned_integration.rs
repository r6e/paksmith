//! Phase 2f integration tests: unversioned-property decode + `.usmap`
//! parsing against the dispatch boundary in `Package::read_from`.
//!
//! Complements the in-source unit tests at
//! `asset/property/unversioned::tests` (FUnversionedHeader bit packing,
//! cap firing) and `testing/usmap::tests` (hex pin, paksmith
//! self-decode round-trip) by exercising the cross-crate public API
//! that `paksmith-fixture-gen`, downstream consumers, and the CLI will
//! reach for.

#![allow(missing_docs)]

#[cfg(feature = "__test_utils")]
mod tests {
    use paksmith_core::PaksmithError;
    use paksmith_core::asset::Package;
    use paksmith_core::asset::mappings::Usmap;
    use paksmith_core::asset::property::primitives::PropertyValue;
    use paksmith_core::asset::property::{Property, PropertyBag};
    use paksmith_core::error::AssetParseFault;
    use paksmith_core::testing::uasset::{MinimalPackage, build_minimal_ue4_27_unversioned};
    use paksmith_core::testing::usmap::{
        MINIMAL_UNVERSIONED_PAYLOAD_HEX, build_hero_usmap_bytes, build_hero_usmap_with_enum_speed,
        build_hero_usmap_with_struct_speed, build_minimal_unversioned_uasset_bytes,
        build_minimal_usmap_bytes,
    };

    fn hero_usmap() -> Usmap {
        Usmap::from_bytes(&build_minimal_usmap_bytes()).expect("Usmap::from_bytes failed")
    }

    fn prop_tree(pkg: &Package) -> &[Property] {
        assert_eq!(
            pkg.payloads.len(),
            1,
            "dispatch must yield exactly one payload per export"
        );
        match &pkg.payloads[0] {
            PropertyBag::Tree { properties } => properties,
            other => panic!("expected PropertyBag::Tree, got {other:?}"),
        }
    }

    /// Asset payload for tests that need a 2-slot fragment +
    /// `Health = 100i32` + a 1-byte Speed value (Enum ordinal or any
    /// other single-byte primitive). Shared by the two EnumProperty
    /// tests; a future single-byte-Speed test can call this without
    /// re-stating the 6 shared bytes.
    fn fragment_health_and_u8_speed(speed_byte: u8) -> Vec<u8> {
        vec![
            0x00, 0x05, // FUnversionedHeader fragment (value_num=2)
            0x64, 0x00, 0x00, 0x00,       // Health = 100i32 LE
            speed_byte, // Speed = u8 (Enum ordinal, etc.)
        ]
    }

    /// `Package::read_from` on a Phase 2f-flagged asset with no `.usmap`
    /// supplied must surface the typed `UnversionedWithoutMappings`
    /// fault — not panic, not fall through to the tagged-property
    /// iterator.
    ///
    /// Complements `property_integration::unversioned_flag_is_rejected`
    /// which hand-flips the flag on the Phase 2a fixture; this drives
    /// the dedicated Phase 2f fixture through the same path.
    #[test]
    fn phase2f_fixture_without_mappings_errors() {
        let bytes = build_minimal_unversioned_uasset_bytes();
        let err =
            Package::read_from(&bytes, None, None, "test/Hero.uasset").expect_err("should error");
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::UnversionedWithoutMappings,
                    ..
                }
            ),
            "expected UnversionedWithoutMappings, got: {err:?}"
        );
    }

    /// When the `.usmap` has no schema for the export's class, the
    /// decoder logs a `warn` and returns an empty `PropertyBag::Tree`
    /// rather than erroring. Drives the path through `Package::
    /// read_from` (not just `Usmap::get_all_properties`) so the
    /// outermost-frame "empty schema" branch in
    /// `read_unversioned_properties` is exercised end-to-end.
    #[test]
    fn unversioned_unknown_class_returns_empty_tree() {
        // Pair the "Hero"-only usmap with an asset whose class is
        // "UnknownClass". `build_minimal_ue4_27_unversioned` updates
        // `imports[0].object_name` to the class index (which Task 4's
        // dispatch resolves through), so the usmap's `Hero` schema
        // won't match.
        let payload = MINIMAL_UNVERSIONED_PAYLOAD_HEX.to_vec();
        let MinimalPackage { bytes, .. } =
            build_minimal_ue4_27_unversioned("UnknownClass", payload);
        let usmap = hero_usmap();
        let pkg = Package::read_from(&bytes, None, Some(&usmap), "test/Unknown.uasset")
            .expect("Package::read_from");
        let props = prop_tree(&pkg);
        assert!(
            props.is_empty(),
            "expected empty Tree for unknown class, got {} properties",
            props.len()
        );
    }

    /// `Usmap::get_all_properties` walks the inheritance chain. The
    /// minimal Hero schema has `super_type: None` (the parser maps the
    /// wire "None" sentinel to `None`), so the walk stops after Hero's
    /// two properties — verifying the terminator behaviour on top of
    /// the property count + name ordering already pinned by the
    /// in-source parser test.
    #[test]
    fn usmap_get_all_properties_walks_hero_schema() {
        let usmap = hero_usmap();
        let props = usmap.get_all_properties("Hero");
        assert_eq!(props.len(), 2, "expected 2 properties on Hero");
        assert_eq!(props[0].property.name, "Health");
        assert_eq!(props[1].property.name, "Speed");
    }

    /// Pins the cross-crate visibility chain for the
    /// `max_fragments_per_header` accessor. The Task 5 R3 architect
    /// review flagged that the accessor's `pub fn` inside
    /// `pub(crate) mod unversioned` was unreachable cross-crate; the
    /// `pub use unversioned::max_fragments_per_header;` re-export in
    /// `property/mod.rs` fixes that.
    ///
    /// This test's contract is "the re-export survives" — a
    /// compile-time property. The call below stops resolving if the
    /// re-export ever regresses. No value assertion (the cap's
    /// numeric value is already pinned in-source by the cap-firing
    /// test in `unversioned.rs::tests` against the same constant).
    #[test]
    fn max_fragments_per_header_accessor_is_reachable() {
        let _cap = paksmith_core::asset::property::max_fragments_per_header();
    }

    /// Asset-level pin for the partial-tree-stop contract: when the
    /// schema declares an unsupported `EPropertyType` byte (here `24` =
    /// `MapProperty`, which maps to `MappedPropertyType::Unknown` per
    /// `mappings.rs::read_mapped_type`), the decoder must walk the
    /// fragment header, decode every supported property at lower
    /// schema indices, then break cleanly on the unsupported slot —
    /// returning the partial `PropertyBag::Tree` rather than a hard
    /// `Err` and rather than mis-decoding subsequent bytes against the
    /// failed slot's tail.
    ///
    /// Uses a Hero schema whose first slot is `Health: IntProperty`
    /// (decodes) and second slot is `Speed: MapProperty` (unsupported
    /// byte). The asset bytes are the canonical Phase 2f payload —
    /// fragment + Health=100 + Speed=600.0f32 — but the decoder will
    /// never read past Health.
    #[test]
    fn partial_tree_stops_on_unsupported_type_byte() {
        let usmap = Usmap::from_bytes(&build_hero_usmap_bytes(24u8)).expect("Usmap parse");
        let asset_bytes = build_minimal_unversioned_uasset_bytes();
        let pkg = Package::read_from(&asset_bytes, None, Some(&usmap), "test/Hero.uasset")
            .expect("Package::read_from should return partial tree, not Err");
        let props = prop_tree(&pkg);
        assert_eq!(
            props.len(),
            1,
            "expected partial tree with Health only; got {:?}",
            props.iter().map(Property::name).collect::<Vec<_>>()
        );
        assert_eq!(props[0].name(), "Health");
        assert!(
            matches!(props[0].value, PropertyValue::Int(100)),
            "Health decoded as {:?}, expected Int(100)",
            props[0].value
        );
    }

    /// Asset-level pin for the unversioned `EnumProperty` decode
    /// path: the wire stream stores a single `u8` ordinal, and the
    /// decoder resolves it via `Usmap::enums[enum_name]`. Builds a
    /// `.usmap` whose `Speed` slot is `EnumProperty(HeroDifficulty)`
    /// with values `["Easy", "Normal", "Hard"]`. The asset payload
    /// encodes ordinal 1 in the Speed slot — should resolve to
    /// `"Normal"`.
    ///
    /// Closes the EnumProperty coverage gap Phase 2f's threat model
    /// called out: the `MT::Enum` arm in
    /// `read_unversioned_value` previously had no test at any layer.
    #[test]
    fn enum_property_decodes_in_range_ordinal() {
        let usmap_bytes =
            build_hero_usmap_with_enum_speed("HeroDifficulty", &["Easy", "Normal", "Hard"]);
        let usmap = Usmap::from_bytes(&usmap_bytes).expect("Usmap parse");

        let payload = fragment_health_and_u8_speed(0x01); // Speed = ordinal 1 → "Normal"
        let MinimalPackage { bytes, .. } = build_minimal_ue4_27_unversioned("Hero", payload);

        let pkg = Package::read_from(&bytes, None, Some(&usmap), "test/Hero.uasset")
            .expect("Package::read_from");
        let props = prop_tree(&pkg);
        assert_eq!(props.len(), 2);
        let speed = props
            .iter()
            .find(|p| p.name() == "Speed")
            .expect("Speed missing");
        match &speed.value {
            PropertyValue::Enum { type_name, value } => {
                assert_eq!(type_name, "HeroDifficulty");
                assert_eq!(value, "Normal");
            }
            other => panic!("expected Enum, got {other:?}"),
        }
    }

    /// `EnumProperty` ordinal that exceeds the enum's value count
    /// must produce the typed fallback string `"<enum_name>::<idx>"`
    /// rather than panicking or returning Err. Pins the
    /// `unwrap_or_else` branch at
    /// `unversioned.rs::read_unversioned_value::MT::Enum` — the only
    /// path through which a misconfigured `.usmap` surfaces as
    /// decoded output rather than an error.
    #[test]
    fn enum_property_falls_back_on_out_of_range_ordinal() {
        let usmap_bytes =
            build_hero_usmap_with_enum_speed("HeroDifficulty", &["Easy", "Normal", "Hard"]);
        let usmap = Usmap::from_bytes(&usmap_bytes).expect("Usmap parse");

        // Ordinal 99 is past the end of the 3-value enum.
        let payload = fragment_health_and_u8_speed(0x63); // 99 → out of range
        let MinimalPackage { bytes, .. } = build_minimal_ue4_27_unversioned("Hero", payload);

        let pkg = Package::read_from(&bytes, None, Some(&usmap), "test/Hero.uasset")
            .expect("Package::read_from");
        let props = prop_tree(&pkg);
        let speed = props
            .iter()
            .find(|p| p.name() == "Speed")
            .expect("Speed missing");
        match &speed.value {
            PropertyValue::Enum { type_name, value } => {
                assert_eq!(type_name, "HeroDifficulty");
                assert_eq!(
                    value, "HeroDifficulty::99",
                    "fallback format should be `<enum_name>::<ordinal>`"
                );
            }
            other => panic!("expected Enum, got {other:?}"),
        }
    }

    /// Asset-level pin for the depth-1 `UnversionedSchemaMissing`
    /// branch. When the schema declares a nested `StructProperty`
    /// whose `struct_name` has no entry in the `.usmap`'s schema
    /// table, `read_unversioned_properties` recurses into the struct
    /// slot at `depth = 1`, finds `all_props.is_empty()` for the
    /// missing class, and (because `depth > 0`) errors with
    /// `UnversionedSchemaMissing` BEFORE consuming any struct
    /// payload bytes. The error propagates back to the outermost
    /// frame's `is_partial_tree_stop` catch arm and yields a partial
    /// tree containing only the properties decoded before the Struct
    /// slot.
    ///
    /// Distinct from `unversioned_unknown_class_returns_empty_tree`:
    /// that test exercises the depth-0 empty-schema branch (warn +
    /// `Ok(Vec::new())`); this test exercises the depth>0
    /// error-and-propagate branch through the same catch arm.
    #[test]
    fn nested_struct_with_missing_schema_returns_partial_tree() {
        let usmap_bytes = build_hero_usmap_with_struct_speed("StatsBlock");
        let usmap = Usmap::from_bytes(&usmap_bytes).expect("Usmap parse");

        // Payload: fragment(value_num=2) + Health i32. No struct body
        // — the depth-1 error fires before reading the Struct slot's
        // own header.
        let payload: Vec<u8> = vec![
            0x00, 0x05, // FUnversionedHeader fragment (value_num=2)
            0x64, 0x00, 0x00, 0x00, // Health = 100i32 LE
        ];
        let MinimalPackage { bytes, .. } = build_minimal_ue4_27_unversioned("Hero", payload);

        let pkg = Package::read_from(&bytes, None, Some(&usmap), "test/Hero.uasset")
            .expect("Package::read_from should return partial tree, not Err");
        let props = prop_tree(&pkg);
        assert_eq!(
            props.len(),
            1,
            "expected partial tree with Health only; got {:?}",
            props.iter().map(Property::name).collect::<Vec<_>>()
        );
        assert_eq!(props[0].name(), "Health");
        assert!(
            matches!(props[0].value, PropertyValue::Int(100)),
            "Health decoded as {:?}, expected Int(100)",
            props[0].value
        );
    }
}
