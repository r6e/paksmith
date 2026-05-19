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
        build_minimal_unversioned_uasset_bytes, build_minimal_usmap_bytes,
    };

    fn hero_usmap() -> Usmap {
        Usmap::from_bytes(&build_minimal_usmap_bytes()).expect("Usmap::from_bytes failed")
    }

    fn prop_tree(pkg: &Package) -> &[Property] {
        match &pkg.payloads[0] {
            PropertyBag::Tree { properties } => properties,
            other => panic!("expected PropertyBag::Tree, got {other:?}"),
        }
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

    /// Cross-boundary happy path: a Phase 2f asset paired with the
    /// matching `.usmap` decodes both schema-declared properties.
    #[test]
    fn phase2f_fixture_with_mappings_decodes_two_props() {
        let usmap = hero_usmap();
        let bytes = build_minimal_unversioned_uasset_bytes();
        let pkg = Package::read_from(&bytes, None, Some(&usmap), "test/Hero.uasset")
            .expect("Package::read_from");
        let props = prop_tree(&pkg);
        assert_eq!(props.len(), 2, "expected 2 decoded properties");

        let health = props
            .iter()
            .find(|p| p.name == "Health")
            .expect("Health missing");
        assert!(
            matches!(health.value, PropertyValue::Int(100)),
            "Health decoded as {:?}, expected Int(100)",
            health.value
        );

        let speed = props
            .iter()
            .find(|p| p.name == "Speed")
            .expect("Speed missing");
        assert!(
            matches!(speed.value, PropertyValue::Float(v) if (v - 600.0f32).abs() < f32::EPSILON),
            "Speed decoded as {:?}, expected Float(600.0)",
            speed.value
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
        let payload = paksmith_core::testing::usmap::MINIMAL_UNVERSIONED_PAYLOAD_HEX.to_vec();
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

    /// `Usmap::from_bytes` rejects a tampered magic byte with the
    /// typed `MappingsParseFault::InvalidMagic` variant — pins the
    /// cross-crate error shape downstream consumers will match on.
    #[test]
    fn usmap_invalid_magic_error() {
        let mut bytes = build_minimal_usmap_bytes();
        bytes[0] = 0xFF;
        let err = Usmap::from_bytes(&bytes).expect_err("should reject bad magic");
        assert!(
            matches!(
                err,
                PaksmithError::MappingsParse {
                    fault: paksmith_core::error::MappingsParseFault::InvalidMagic { .. }
                }
            ),
            "expected MappingsParseFault::InvalidMagic, got: {err:?}"
        );
    }

    /// `Usmap::get_all_properties` walks the inheritance chain. The
    /// minimal Hero schema has empty `super_type` (`""`), so the walk
    /// stops after Hero's two properties — verifying the terminator
    /// behaviour on top of the property count + name ordering already
    /// pinned by the in-source parser test.
    #[test]
    fn usmap_get_all_properties_walks_hero_schema() {
        let usmap = hero_usmap();
        let props = usmap.get_all_properties("Hero");
        assert_eq!(props.len(), 2, "expected 2 properties on Hero");
        assert_eq!(props[0].name, "Health");
        assert_eq!(props[1].name, "Speed");
    }

    /// Pins the cross-crate visibility chain for the
    /// `max_fragments_per_header` accessor. The Task 5 R3 architect
    /// review flagged that the accessor's `pub fn` inside
    /// `pub(crate) mod unversioned` was unreachable cross-crate; the
    /// `pub use unversioned::max_fragments_per_header;` re-export in
    /// `property/mod.rs` fixes that. This test compiles only when the
    /// re-export survives — drop the `pub use` and the call below
    /// stops resolving.
    #[test]
    fn max_fragments_per_header_accessor_is_reachable() {
        let cap = paksmith_core::asset::property::max_fragments_per_header();
        assert_eq!(
            cap,
            u16::MAX as usize,
            "MAX_FRAGMENTS_PER_HEADER should match u16::MAX (the u16 cursor's natural ceiling)"
        );
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
    ///
    /// Closes the asset-level coverage gap the Task 5 hex-pin doc
    /// committed paksmith to delivering in Task 6.
    #[test]
    fn partial_tree_stops_on_unsupported_type_byte() {
        let usmap_bytes = build_hero_usmap_with_map_speed();
        let usmap = Usmap::from_bytes(&usmap_bytes).expect("Usmap parse");
        let asset_bytes = build_minimal_unversioned_uasset_bytes();
        let pkg = Package::read_from(&asset_bytes, None, Some(&usmap), "test/Hero.uasset")
            .expect("Package::read_from should return partial tree, not Err");
        let props = prop_tree(&pkg);
        assert_eq!(
            props.len(),
            1,
            "expected partial tree with Health only; got {:?}",
            props.iter().map(|p| p.name.as_str()).collect::<Vec<_>>()
        );
        assert_eq!(props[0].name, "Health");
        assert!(
            matches!(props[0].value, PropertyValue::Int(100)),
            "Health decoded as {:?}, expected Int(100)",
            props[0].value
        );
    }

    /// Build a `.usmap` for class `Hero` with two props: `Health` as
    /// `IntProperty` (EPropertyType byte 2) and `Speed` as
    /// `MapProperty` (byte 24, which `mappings.rs::read_mapped_type`
    /// maps to `MappedPropertyType::Unknown(24)`). Same name table
    /// layout as `build_minimal_usmap_bytes`; only the second prop's
    /// type byte differs. Inlined here because this is a
    /// test-specific adversarial shape, not a shareable builder.
    fn build_hero_usmap_with_map_speed() -> Vec<u8> {
        let mut data: Vec<u8> = Vec::new();
        // Name table: ["Hero", "", "Health", "Speed"]
        data.extend_from_slice(&4u32.to_le_bytes());
        for (s, name) in [(5u8, "Hero"), (1u8, ""), (7u8, "Health"), (6u8, "Speed")] {
            data.push(s);
            data.extend_from_slice(name.as_bytes());
        }
        // Empty enum table
        data.extend_from_slice(&0u32.to_le_bytes());
        // One schema
        data.extend_from_slice(&1u32.to_le_bytes());
        // Schema "Hero" {name=0, super=1 (""), prop_count=2, serial_count=2}
        data.extend_from_slice(&0i32.to_le_bytes());
        data.extend_from_slice(&1i32.to_le_bytes());
        data.extend_from_slice(&2u16.to_le_bytes());
        data.extend_from_slice(&2u16.to_le_bytes());
        // Prop 0: Health, IntProperty (byte 2)
        data.extend_from_slice(&0u16.to_le_bytes()); // schema_index
        data.push(1u8); // array_size
        data.extend_from_slice(&2i32.to_le_bytes()); // name idx = "Health"
        data.push(2u8); // IntProperty
        // Prop 1: Speed, MapProperty (byte 24) — unsupported
        data.extend_from_slice(&1u16.to_le_bytes());
        data.push(1u8);
        data.extend_from_slice(&3i32.to_le_bytes()); // name idx = "Speed"
        data.push(24u8); // MapProperty → MappedPropertyType::Unknown(24)

        let data_len = u32::try_from(data.len()).expect("usmap data within u32");
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(&[0x30u8, 0xC4u8]); // magic LE
        out.push(0u8); // version = Initial
        out.push(0u8); // compression = None
        out.extend_from_slice(&data_len.to_le_bytes()); // compressed_size
        out.extend_from_slice(&data_len.to_le_bytes()); // decompressed_size
        out.extend_from_slice(&data);
        out
    }
}
