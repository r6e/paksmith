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
        build_minimal_usmap_bytes, build_sparse_schema_usmap_bytes,
    };
    use proptest::prelude::*;

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
            paksmith_core::Asset::Generic(PropertyBag::Tree { properties }) => properties,
            other => panic!("expected Asset::Generic(PropertyBag::Tree), got {other:?}"),
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
        assert_eq!(props[0].property.name.as_ref(), "Health");
        assert_eq!(props[1].property.name.as_ref(), "Speed");
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
                assert_eq!(type_name.as_ref(), "HeroDifficulty");
                assert_eq!(value.as_ref(), "Normal");
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
                assert_eq!(type_name.as_ref(), "HeroDifficulty");
                assert_eq!(
                    value.as_ref(),
                    "HeroDifficulty::99",
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
    /// FUnversionedHeader fragment u16 layout (oracle
    /// `UnversionedHeaderFragment`):
    /// - bits 0-6: skip_num
    /// - bit 7: has_zeros
    /// - bit 8: is_last
    /// - bits 9-15: value_num
    ///
    /// Helper for the sparse-schema tests below.
    fn fragment_bytes(skip_num: u8, value_num: u8, is_last: bool) -> [u8; 2] {
        let mut packed = u16::from(skip_num) & 0x007f;
        if is_last {
            packed |= 0x0100;
        }
        packed |= (u16::from(value_num) & 0x007f) << 9;
        packed.to_le_bytes()
    }

    /// Schema with a single serializable property at `schema_index = 3`
    /// (non-zero, non-contiguous). The decoder must address the wire-
    /// declared index, not the property's position in
    /// `get_all_properties` (which is `0` for the only element). The
    /// audit-flagged bug #358 used `enumerate()` position; a regression
    /// to that shape would call `is_serialized(0, ..)` against a
    /// fragment whose first slot is `3`, return `false`, and silently
    /// drop the property.
    ///
    /// This test would have failed when #358 was live; the existing
    /// Hero fixture's `[0, 1]` indices made it pass anyway. Closing
    /// the gap is #379's whole point.
    #[test]
    fn unversioned_property_at_nonzero_schema_index_decodes_correctly() {
        // prop_count=4 (Health@3 plus 3 transient/editor-only fillers).
        let usmap_bytes = build_sparse_schema_usmap_bytes(
            "Sparse",
            4,
            &[(3u16, "Health", 2u8)], // IntProperty
        );
        let usmap = Usmap::from_bytes(&usmap_bytes).expect("Usmap parse");

        // Fragment: skip=3, value=1, is_last → first_num=3 covers slot 3.
        let mut payload: Vec<u8> = Vec::new();
        payload.extend_from_slice(&fragment_bytes(3, 1, true));
        payload.extend_from_slice(&100i32.to_le_bytes());
        let MinimalPackage { bytes, .. } = build_minimal_ue4_27_unversioned("Sparse", payload);

        let pkg = Package::read_from(&bytes, None, Some(&usmap), "test/Sparse.uasset")
            .expect("Package::read_from");
        let props = prop_tree(&pkg);
        assert_eq!(props.len(), 1, "expected Health to decode");
        assert_eq!(props[0].name(), "Health");
        assert!(
            matches!(props[0].value, PropertyValue::Int(100)),
            "Health decoded as {:?}, expected Int(100)",
            props[0].value
        );
    }

    /// Schema with serializable properties at indices `[0, 2, 4]`
    /// (gaps). Tests that the decoder correctly maps each wire value
    /// to its declared `schema_index` slot when consecutive
    /// serializable indices skip over filler slots.
    #[test]
    fn unversioned_property_with_gap_decodes_correctly() {
        // prop_count=5 — five class properties total, three
        // serializable at indices 0, 2, 4 (slots 1 and 3 are
        // non-serializable filler).
        let usmap_bytes = build_sparse_schema_usmap_bytes(
            "Gapped",
            5,
            &[
                (0u16, "Alpha", 2u8), // IntProperty
                (2u16, "Beta", 2u8),
                (4u16, "Gamma", 2u8),
            ],
        );
        let usmap = Usmap::from_bytes(&usmap_bytes).expect("Usmap parse");

        // Three fragments: (skip=0, val=1), (skip=1, val=1), (skip=1, val=1, last)
        // → first_num = 0, 2, 4 in cumulative order.
        let mut payload: Vec<u8> = Vec::new();
        payload.extend_from_slice(&fragment_bytes(0, 1, false));
        payload.extend_from_slice(&fragment_bytes(1, 1, false));
        payload.extend_from_slice(&fragment_bytes(1, 1, true));
        payload.extend_from_slice(&10i32.to_le_bytes()); // Alpha @ slot 0
        payload.extend_from_slice(&20i32.to_le_bytes()); // Beta @ slot 2
        payload.extend_from_slice(&30i32.to_le_bytes()); // Gamma @ slot 4
        let MinimalPackage { bytes, .. } = build_minimal_ue4_27_unversioned("Gapped", payload);

        let pkg = Package::read_from(&bytes, None, Some(&usmap), "test/Gapped.uasset")
            .expect("Package::read_from");
        let props = prop_tree(&pkg);
        assert_eq!(props.len(), 3, "expected all 3 sparse props to decode");
        let by_name = |needle: &str| -> &Property {
            props
                .iter()
                .find(|p| p.name() == needle)
                .unwrap_or_else(|| {
                    panic!(
                        "{needle} missing; got {:?}",
                        props.iter().map(Property::name).collect::<Vec<_>>()
                    )
                })
        };
        assert!(matches!(by_name("Alpha").value, PropertyValue::Int(10)));
        assert!(matches!(by_name("Beta").value, PropertyValue::Int(20)));
        assert!(matches!(by_name("Gamma").value, PropertyValue::Int(30)));
    }

    /// Schema declares serializable properties in **non-monotonic**
    /// order (`[2, 0, 4]`) — Beta is declared first despite having a
    /// higher `schema_index` than Alpha. The wire format itself
    /// always emits fragments in ascending slot order (`[0, 2, 4]`),
    /// but `Usmap::get_all_properties` returns
    /// declaration-order — so the decoder must sort by
    /// `absolute_index` before walking the header's forward-only
    /// cursor. Without the defensive sort inside
    /// `read_unversioned_properties`, `is_serialized`'s `frag_idx`
    /// would land past the slot the caller is asking about and
    /// silently drop properties.
    ///
    /// This is the adversarial case the wire format can't normally
    /// produce, but a hand-crafted `.usmap` can. Regression coverage
    /// for the sort guard.
    #[test]
    fn unversioned_property_with_non_increasing_index_decodes_correctly() {
        // Same wire shape as the gap test, but the schema declares
        // properties in [2, 0, 4] order instead of [0, 2, 4]. The
        // payload is identical; only the schema declaration order
        // differs.
        let usmap_bytes = build_sparse_schema_usmap_bytes(
            "OutOfOrder",
            5,
            &[
                (2u16, "Beta", 2u8),
                (0u16, "Alpha", 2u8),
                (4u16, "Gamma", 2u8),
            ],
        );
        let usmap = Usmap::from_bytes(&usmap_bytes).expect("Usmap parse");

        let mut payload: Vec<u8> = Vec::new();
        payload.extend_from_slice(&fragment_bytes(0, 1, false));
        payload.extend_from_slice(&fragment_bytes(1, 1, false));
        payload.extend_from_slice(&fragment_bytes(1, 1, true));
        payload.extend_from_slice(&10i32.to_le_bytes()); // Alpha @ slot 0
        payload.extend_from_slice(&20i32.to_le_bytes()); // Beta @ slot 2
        payload.extend_from_slice(&30i32.to_le_bytes()); // Gamma @ slot 4
        let MinimalPackage { bytes, .. } = build_minimal_ue4_27_unversioned("OutOfOrder", payload);

        let pkg = Package::read_from(&bytes, None, Some(&usmap), "test/OutOfOrder.uasset")
            .expect("Package::read_from");
        let props = prop_tree(&pkg);
        assert_eq!(
            props.len(),
            3,
            "all 3 props should decode under defensive sort"
        );
        let by_name = |needle: &str| -> &Property {
            props
                .iter()
                .find(|p| p.name() == needle)
                .unwrap_or_else(|| {
                    panic!(
                        "{needle} missing; got {:?}",
                        props.iter().map(Property::name).collect::<Vec<_>>()
                    )
                })
        };
        assert!(matches!(by_name("Alpha").value, PropertyValue::Int(10)));
        assert!(matches!(by_name("Beta").value, PropertyValue::Int(20)));
        assert!(matches!(by_name("Gamma").value, PropertyValue::Int(30)));
    }

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

    // Property-based test that closes #378's third recommended
    // proptest (deferred when #441 landed because the sparse-schema
    // builder #379 hadn't merged yet).
    //
    // Strategy: generate 3-8 unique `schema_index` values in
    // `[0, 32)` (non-contiguous, possibly non-zero-start). Build a
    // `.usmap` declaring serializable properties at those wire
    // indices — each named `"P<idx>"` (unique) and typed
    // `IntProperty`. Build a paired `.uasset` whose
    // `FUnversionedHeader` fragment stream addresses the same
    // sorted slots, each with value `<idx> * 100i32` so the wire
    // index can be recovered from the decoded value. Drive
    // `Package::read_from` and assert each decoded property's name
    // (which encodes its wire `schema_index`) matches its value
    // (which encodes the same wire `schema_index`). A regression
    // to `enumerate()` position (#358) would fail this for any
    // non-`[0, 1, 2, ...]` index set.
    proptest! {
        // 64 cases is enough: the strategy space is tiny
        // (`btree_set(1u16..32, 3..=8)` is ~C(31, 3..=8) ≈ a few
        // hundred thousand combinations), and the bug class this
        // pins (enumerate() position vs wire schema_index) fails
        // on any single non-`[0,1,..,N-1]` draw — which is every
        // draw, since the lower bound is 1.
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn unversioned_decode_uses_wire_schema_index(
            // 3-8 unique u16 indices in [1, 32). BTreeSet gives
            // uniqueness + ascending order for free. Lower bound 1
            // (not 0) so `indices[0] >= 1` always — a regression to
            // `enumerate()` position (#358) makes wire idx N decode
            // at position N-1, never matching for any draw. Drawing
            // from `[0, ...)` would allow `{0,1,..,N-1}` contiguous-
            // from-zero degenerate sets where enumerate() == idx and
            // the bug is invisible.
            raw_indices in prop::collection::btree_set(1u16..32, 3..=8),
        ) {
            // BTreeSet iteration is sorted. The wire fragments emit
            // in sorted order regardless of schema declaration order
            // — the defensive sort in `read_unversioned_properties`
            // handles either.
            let indices: Vec<u16> = raw_indices.into_iter().collect();
            let prop_count: u16 = indices.last().copied().unwrap_or(0).saturating_add(1);
            // `P<idx>` names — `&str` borrowed from `name_strings`.
            let name_strings: Vec<String> = indices
                .iter()
                .map(|i| format!("P{i}"))
                .collect();
            let triples: Vec<(u16, &str, u8)> = indices
                .iter()
                .zip(name_strings.iter())
                .map(|(idx, name)| (*idx, name.as_str(), 2u8)) // 2 = IntProperty
                .collect();

            let usmap_bytes =
                build_sparse_schema_usmap_bytes("Sparse", prop_count, &triples);
            let usmap = Usmap::from_bytes(&usmap_bytes).expect("Usmap parse");

            // FUnversionedHeader fragments addressing the sorted
            // slots. Cumulative-skip encoding: each fragment's
            // skip_num = idx - prev_cumulative.
            let mut payload: Vec<u8> = Vec::new();
            let mut cumulative: u16 = 0;
            for (i, &idx) in indices.iter().enumerate() {
                let skip = idx - cumulative;
                let is_last = i + 1 == indices.len();
                // `try_from` panics loudly if a future range
                // expansion (`1u16..32` → larger) overflows u8;
                // silently truncating with `as u8` would emit a
                // malformed fragment stream that still parses but
                // tests a different property.
                let skip_u8 = u8::try_from(skip).expect("gap fits in u8");
                payload.extend_from_slice(&fragment_bytes(skip_u8, 1, is_last));
                cumulative = idx + 1;
            }
            // Each slot's value: `idx * 100i32` — recoverable from
            // the decoded PropertyValue.
            for &idx in &indices {
                let value = i32::from(idx) * 100;
                payload.extend_from_slice(&value.to_le_bytes());
            }
            let MinimalPackage { bytes, .. } =
                build_minimal_ue4_27_unversioned("Sparse", payload);

            let pkg = Package::read_from(&bytes, None, Some(&usmap), "fuzz.uasset")
                .expect("Package::read_from on sparse-schema fixture");
            // Routes through the shared `prop_tree` helper for the
            // payload-count check (1 export per fixture).
            let props = prop_tree(&pkg);
            prop_assert_eq!(props.len(), indices.len());
            // For each declared index, find the property named
            // "P<idx>" and verify its value is `idx * 100`. A
            // regression to enumerate() position would either drop
            // a property or assign it the wrong value.
            for &idx in &indices {
                let want_name = format!("P{idx}");
                let want_value = i32::from(idx) * 100;
                let prop = props
                    .iter()
                    .find(|p| p.name() == want_name)
                    .unwrap_or_else(|| panic!("property {want_name} missing"));
                match prop.value {
                    PropertyValue::Int(v) => prop_assert_eq!(v, want_value),
                    ref other => panic!("property {want_name}: expected Int, got {other:?}"),
                }
            }
        }
    }
}
