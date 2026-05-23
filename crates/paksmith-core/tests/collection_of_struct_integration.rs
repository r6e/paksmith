//! Phase 2g end-to-end integration tests for collection-of-struct
//! decoding.
//!
//! Drives every decode path through the public `Package::read_from`
//! entry point or `read_container_value` directly — the per-collection
//! in-source unit tests in `containers.rs::tests` exercise the inner
//! decoders against hand-built byte buffers; this file pins the full
//! pipeline so wire-format drift in the dispatch layer is caught
//! independently.

#![allow(missing_docs)]

#[cfg(feature = "__test_utils")]
mod tests {
    use std::io::Cursor;

    use paksmith_core::asset::Package;
    use paksmith_core::asset::property::primitives::PropertyValue;
    use paksmith_core::asset::property::{
        PropertyBag, PropertyTag, read_container_value, read_properties,
    };
    use paksmith_core::asset::{AssetContext, name_table::FName, name_table::NameTable};
    use paksmith_core::error::{AssetParseFault, PaksmithError};
    use paksmith_core::testing::uasset::{
        MinimalPackage, build_minimal_ue4_27_with_array_of_struct,
    };

    /// Helper: build an `AssetContext` whose name table is the given
    /// list of strings in wire order. Index 0 MUST be "None" —
    /// `read_tag` short-circuits `(0, 0)` FName pairs as the None
    /// terminator before any name lookup.
    fn make_ctx(names: &[&str]) -> AssetContext {
        use paksmith_core::asset::{
            export_table::ExportTable, import_table::ImportTable, version::AssetVersion,
        };
        use std::sync::Arc;
        debug_assert!(
            matches!(names.first(), Some(&"None")),
            "test name tables MUST start with \"None\" at index 0 — otherwise a \
             literal (0, 0) None-terminator FName pair resolves to whatever name \
             sits at index 0 and the wire stream mis-terminates with a cryptic \
             PackageIndexOob much later in the parse"
        );
        let table = NameTable {
            names: names.iter().map(|n| FName::new(n)).collect(),
        };
        AssetContext {
            names: Arc::new(table),
            imports: Arc::new(ImportTable::default()),
            exports: Arc::new(ExportTable::default()),
            version: AssetVersion::default(),
            mappings: None,
        }
    }

    fn write_fname_pair(buf: &mut Vec<u8>, idx: i32, num: i32) {
        buf.extend_from_slice(&idx.to_le_bytes());
        buf.extend_from_slice(&num.to_le_bytes());
    }

    /// Write a single IntProperty FPropertyTag + 4-byte payload to `buf`.
    /// `name_idx` / `type_idx` reference the test's name table.
    fn write_int_property(buf: &mut Vec<u8>, name_idx: i32, type_idx: i32, value: i32) {
        write_fname_pair(buf, name_idx, 0);
        write_fname_pair(buf, type_idx, 0);
        buf.extend_from_slice(&4i32.to_le_bytes()); // size
        buf.extend_from_slice(&0i32.to_le_bytes()); // array_index
        buf.push(0u8); // has_property_guid
        buf.extend_from_slice(&value.to_le_bytes());
    }

    fn write_none_terminator(buf: &mut Vec<u8>) {
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
    }

    /// Build a `Map<NameProperty, StructProperty>` outer tag for tests
    /// 2 and 7. `name`, `inner_type`, `value_type` indices reference
    /// the caller's name table; `body_len` is the on-wire size of the
    /// Map body.
    fn make_map_tag(name: &str, key_type: &str, value_type: &str, body_len: usize) -> PropertyTag {
        PropertyTag {
            name: name.to_string(),
            type_name: "MapProperty".to_string(),
            size: i32::try_from(body_len).expect("body within i32"),
            array_index: 0,
            bool_val: false,
            struct_name: String::new(),
            struct_guid: [0u8; 16],
            enum_name: String::new(),
            inner_type: key_type.to_string(),
            value_type: value_type.to_string(),
            guid: None,
        }
    }

    fn make_set_tag(name: &str, inner_type: &str, body_len: usize) -> PropertyTag {
        PropertyTag {
            name: name.to_string(),
            type_name: "SetProperty".to_string(),
            size: i32::try_from(body_len).expect("body within i32"),
            array_index: 0,
            bool_val: false,
            struct_name: String::new(),
            struct_guid: [0u8; 16],
            enum_name: String::new(),
            inner_type: inner_type.to_string(),
            value_type: String::new(),
            guid: None,
        }
    }

    // ---------- Test 4 (depth-cap) builder helpers ----------

    /// Wrap `payload_bytes` (a property's serialised FPropertyTag +
    /// value bytes) in a struct body terminated by `(0, 0)`. Used to
    /// build the per-level struct body in the test 4 chain.
    fn wrap_struct_body(payload_bytes: &[u8]) -> Vec<u8> {
        let mut body = payload_bytes.to_vec();
        body.extend_from_slice(&0i32.to_le_bytes());
        body.extend_from_slice(&0i32.to_le_bytes());
        body
    }

    /// Build an `Array<Struct>` body with 1 element whose struct body
    /// is `inner_struct_body`. Inner-array-tag-info `size` is patched
    /// from the inner body's length. The name table is the one
    /// established by the depth-cap test (`NESTED_NAMES`); indices
    /// 1, 3, 4 are hardcoded to match.
    fn build_nested_array_of_struct_body(inner_struct_body: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&1i32.to_le_bytes()); // count = 1
        // Inner FPropertyTag (StructProperty: 49 bytes).
        body.extend_from_slice(&1i32.to_le_bytes()); // name idx (Inner)
        body.extend_from_slice(&0i32.to_le_bytes());
        body.extend_from_slice(&3i32.to_le_bytes()); // type idx (StructProperty)
        body.extend_from_slice(&0i32.to_le_bytes());
        let size_offset = body.len();
        body.extend_from_slice(&0i32.to_le_bytes()); // size placeholder
        body.extend_from_slice(&0i32.to_le_bytes()); // array_index
        body.extend_from_slice(&4i32.to_le_bytes()); // struct_name idx (NestedSlot)
        body.extend_from_slice(&0i32.to_le_bytes());
        body.extend_from_slice(&[0u8; 16]); // struct_guid
        body.push(0u8); // has_property_guid
        let element_start = body.len();
        body.extend_from_slice(inner_struct_body);
        let element_size =
            i32::try_from(body.len() - element_start).expect("element body fits in i32");
        body[size_offset..size_offset + 4].copy_from_slice(&element_size.to_le_bytes());
        body
    }

    /// Build an FPropertyTag for `Inner: Array<StructProperty>` whose
    /// body is `array_body`. The result is the per-level wrapped
    /// payload that the next outer layer's `wrap_struct_body` ingests.
    fn wrap_inner_array_tag(array_body: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        // FPropertyTag (ArrayProperty: 8+8+4+4+8+1 = 33 bytes).
        buf.extend_from_slice(&1i32.to_le_bytes()); // name idx (Inner)
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.extend_from_slice(&2i32.to_le_bytes()); // type idx (ArrayProperty)
        buf.extend_from_slice(&0i32.to_le_bytes());
        let size_offset = buf.len();
        buf.extend_from_slice(&0i32.to_le_bytes()); // size placeholder
        buf.extend_from_slice(&0i32.to_le_bytes()); // array_index
        buf.extend_from_slice(&3i32.to_le_bytes()); // inner_type idx (StructProperty)
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.push(0u8); // has_property_guid
        let body_start = buf.len();
        buf.extend_from_slice(array_body);
        let body_size = i32::try_from(buf.len() - body_start).expect("array body fits in i32");
        buf[size_offset..size_offset + 4].copy_from_slice(&body_size.to_le_bytes());
        buf
    }

    fn make_array_tag(name: &str, inner_type: &str, body_len: usize) -> PropertyTag {
        PropertyTag {
            name: name.to_string(),
            type_name: "ArrayProperty".to_string(),
            size: i32::try_from(body_len).expect("body within i32"),
            array_index: 0,
            bool_val: false,
            struct_name: String::new(),
            struct_guid: [0u8; 16],
            enum_name: String::new(),
            inner_type: inner_type.to_string(),
            value_type: String::new(),
            guid: None,
        }
    }

    /// Phase 2g Task 7 test 1: end-to-end `Package::read_from` of the
    /// Task 6 Array<Struct> fixture. Pins the full pipeline (summary
    /// parse, name/import/export table parse, payload property-tree
    /// decode, `PropertyBag::Tree` aggregation), not just the
    /// containers helper.
    #[test]
    fn array_of_struct_decodes_two_elements() {
        let MinimalPackage { bytes, .. } = build_minimal_ue4_27_with_array_of_struct();
        let pkg = Package::read_from(&bytes, None, None, "Game/Data/Inv.uasset")
            .expect("Package::read_from on Array<Struct> fixture");
        assert_eq!(pkg.payloads.len(), 1, "expected one export");
        let properties = match &pkg.payloads[0] {
            PropertyBag::Tree { properties } => properties,
            other => panic!("expected PropertyBag::Tree, got {other:?}"),
        };
        assert_eq!(properties.len(), 1, "expected one Inventory property");
        let inventory = &properties[0];
        assert_eq!(inventory.name, "Inventory");
        let (inner_type, elements) = match &inventory.value {
            PropertyValue::Array {
                inner_type,
                elements,
            } => (inner_type, elements),
            other => panic!("expected Array, got {other:?}"),
        };
        assert_eq!(inner_type, "StructProperty");
        assert_eq!(elements.len(), 2);
        for (i, (expected_id, expected_count)) in [(11i32, 100i32), (22, 200)].iter().enumerate() {
            let (struct_name, props) = match &elements[i] {
                PropertyValue::Struct {
                    struct_name,
                    properties,
                } => (struct_name, properties),
                other => panic!("element {i}: expected Struct, got {other:?}"),
            };
            assert_eq!(struct_name, "InventorySlot");
            assert_eq!(props.len(), 2);
            let item_id = props.iter().find(|p| p.name == "ItemId").unwrap();
            assert!(matches!(item_id.value, PropertyValue::Int(v) if v == *expected_id));
            let count = props.iter().find(|p| p.name == "Count").unwrap();
            assert!(matches!(count.value, PropertyValue::Int(v) if v == *expected_count));
        }
    }

    /// Phase 2g Task 7 test 2: `Map<NameProperty, StructProperty>` —
    /// 2 entries decoded via `read_container_value`. Drives the public
    /// container dispatcher; key is a primitive Name, value is the
    /// new struct-aware path that lands in `read_struct_value("")`.
    #[test]
    fn map_of_name_to_struct_decodes() {
        // Names: 0=None, 1=Slots, 2=ItemId, 3=IntProperty, 4=first, 5=second.
        let ctx = make_ctx(&["None", "Slots", "ItemId", "IntProperty", "first", "second"]);

        let mut body: Vec<u8> = Vec::new();
        body.extend_from_slice(&0i32.to_le_bytes()); // num_keys_to_remove
        body.extend_from_slice(&2i32.to_le_bytes()); // count
        // Entry 0: key "first" + struct value { ItemId: 42, None }.
        write_fname_pair(&mut body, 4, 0);
        write_int_property(&mut body, 2, 3, 42);
        write_none_terminator(&mut body);
        // Entry 1: key "second" + struct value { ItemId: 99, None }.
        write_fname_pair(&mut body, 5, 0);
        write_int_property(&mut body, 2, 3, 99);
        write_none_terminator(&mut body);

        let body_len = body.len();
        let tag = make_map_tag("Slots", "NameProperty", "StructProperty", body_len);
        let mut cur = Cursor::new(body);
        let value = read_container_value(&tag, &mut cur, &ctx, 0, body_len as u64, "test.uasset")
            .expect("read_container_value Map<Name, Struct>")
            .expect("not Ok(None)");
        assert_eq!(cur.position(), body_len as u64);

        match value {
            PropertyValue::Map {
                key_type,
                value_type,
                entries,
            } => {
                assert_eq!(key_type, "NameProperty");
                assert_eq!(value_type, "StructProperty");
                assert_eq!(entries.len(), 2);
                for (i, (expected_key, expected_val)) in
                    [("first", 42i32), ("second", 99)].iter().enumerate()
                {
                    let key = match &entries[i].key {
                        PropertyValue::Name(k) => k.as_str(),
                        other => panic!("entry {i} key: {other:?}"),
                    };
                    assert_eq!(key, *expected_key);
                    let (struct_name, props) = match &entries[i].value {
                        PropertyValue::Struct {
                            struct_name,
                            properties,
                        } => (struct_name, properties),
                        other => panic!("entry {i} value: {other:?}"),
                    };
                    assert!(struct_name.is_empty(), "Map struct_name is wire-unknown");
                    assert_eq!(props.len(), 1);
                    assert_eq!(props[0].name, "ItemId");
                    assert!(matches!(props[0].value, PropertyValue::Int(v) if v == *expected_val));
                }
            }
            other => panic!("expected Map, got {other:?}"),
        }
    }

    /// Phase 2g Task 7 test 3: `Set<StructProperty>` — 2 elements
    /// decoded via `read_container_value`. Mirrors test 2's shape
    /// without the key slot.
    #[test]
    fn set_of_struct_decodes() {
        // Names: 0=None, 1=Slots, 2=ItemId, 3=IntProperty.
        let ctx = make_ctx(&["None", "Slots", "ItemId", "IntProperty"]);

        let mut body: Vec<u8> = Vec::new();
        body.extend_from_slice(&0i32.to_le_bytes()); // num_elements_to_remove
        body.extend_from_slice(&2i32.to_le_bytes()); // count
        for val in [42i32, 99] {
            write_int_property(&mut body, 2, 3, val);
            write_none_terminator(&mut body);
        }

        let body_len = body.len();
        let tag = make_set_tag("Slots", "StructProperty", body_len);
        let mut cur = Cursor::new(body);
        let value = read_container_value(&tag, &mut cur, &ctx, 0, body_len as u64, "test.uasset")
            .expect("read_container_value Set<Struct>")
            .expect("not Ok(None)");
        assert_eq!(cur.position(), body_len as u64);

        match value {
            PropertyValue::Set {
                inner_type,
                elements,
            } => {
                assert_eq!(inner_type, "StructProperty");
                assert_eq!(elements.len(), 2);
                for (i, expected_val) in [42i32, 99].iter().enumerate() {
                    let (struct_name, props) = match &elements[i] {
                        PropertyValue::Struct {
                            struct_name,
                            properties,
                        } => (struct_name, properties),
                        other => panic!("element {i}: {other:?}"),
                    };
                    assert!(struct_name.is_empty(), "Set struct_name is wire-unknown");
                    assert_eq!(props.len(), 1);
                    assert!(matches!(props[0].value, PropertyValue::Int(v) if v == *expected_val));
                }
            }
            other => panic!("expected Set, got {other:?}"),
        }
    }

    /// Custom-binary engine structs (e.g., `FVector`) whose body is
    /// raw bytes rather than tagged-property iteration now propagate
    /// the underlying wire-shape error instead of being silently
    /// substituted with empty structs. The prior catch arm was tied
    /// to the per-element `inner_header.size` bound that #357
    /// established was wrong (CUE4Parse treats the field as TOTAL of
    /// all elements, delimited by the per-body None terminator).
    /// Phase 3+ will add a typed registry of binary struct decoders
    /// for these cases.
    #[test]
    fn array_of_custom_binary_struct_propagates_oob() {
        // Name table: 0=None, 1=Translation, 2=ArrayProperty,
        // 3=StructProperty, 4=FVector.
        let ctx = make_ctx(&[
            "None",
            "Translation",
            "ArrayProperty",
            "StructProperty",
            "FVector",
        ]);

        // Crafted bytes that decode as (FName index = 0x00FFFFFF,
        // number = 0) — name idx is well out of the 5-entry table.
        let make_element = || {
            let mut bytes = Vec::with_capacity(12);
            bytes.extend_from_slice(&0x00FF_FFFFi32.to_le_bytes()); // name idx OOB
            bytes.extend_from_slice(&0i32.to_le_bytes()); // name num
            bytes.extend_from_slice(&0u32.to_le_bytes()); // junk padding to 12 bytes
            bytes
        };

        let mut body: Vec<u8> = Vec::new();
        body.extend_from_slice(&2i32.to_le_bytes()); // count = 2
        // Inner FPropertyTag for FVector struct, size = TOTAL (24 = 2 × 12).
        write_fname_pair(&mut body, 1, 0); // Name: Translation
        write_fname_pair(&mut body, 3, 0); // Type: StructProperty
        body.extend_from_slice(&24i32.to_le_bytes()); // Size = TOTAL of both elements
        body.extend_from_slice(&0i32.to_le_bytes()); // ArrayIndex
        write_fname_pair(&mut body, 4, 0); // StructName: FVector
        body.extend_from_slice(&[0u8; 16]); // StructGuid
        body.push(0u8); // HasPropertyGuid
        body.extend_from_slice(&make_element());
        body.extend_from_slice(&make_element());

        let body_len = body.len();
        let tag = make_array_tag("Translation", "StructProperty", body_len);
        let err = read_container_value(
            &tag,
            &mut Cursor::new(body),
            &ctx,
            0,
            body_len as u64,
            "test.uasset",
        )
        .expect_err("OOB FName must propagate after #357 catch-arm removal");
        // The crafted index is well past the name table — the same
        // `PackageIndexOob` the in-source `array_of_struct_propagates_oob_in_element_body`
        // test pins. Asserting the exact variant catches future
        // regressions that swap in a different earlier-layer rejection.
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::PackageIndexOob { .. },
                    ..
                }
            ),
            "expected PackageIndexOob, got {err:?}"
        );
    }

    /// Edge case where the inner-array-tag-info header declares
    /// `size = 0` AND the array body contains no element bytes after
    /// the inner header (`body_len` == inner-header-end). `read_struct_value`
    /// is called with the outer ArrayProperty `expected_end`, which
    /// already equals the cursor position, so `read_properties`'s
    /// top-of-loop `pos >= expected_end` check breaks immediately with
    /// `Ok(Vec::new())`. Each element decodes as
    /// `Struct { struct_name, properties: vec![] }` — no None terminator
    /// needed. Cursor advances by zero bytes per element.
    #[test]
    fn array_of_struct_with_zero_size_elements() {
        // Name table: 0=None, 1=Markers, 2=StructProperty, 3=Empty.
        // The inner FPropertyTag's `type_name` MUST resolve to
        // "StructProperty" for `read_tag` to follow the Struct-extras
        // branch (struct_name + struct_guid). Wrong type name lands in
        // the `_ => {}` arm and the 24 extras bytes are not consumed,
        // leaving the cursor mid-buffer for the per-element loop.
        let ctx = make_ctx(&["None", "Markers", "StructProperty", "Empty"]);

        let mut body: Vec<u8> = Vec::new();
        body.extend_from_slice(&2i32.to_le_bytes()); // count = 2
        // Inner FPropertyTag for Empty struct, size = 0.
        write_fname_pair(&mut body, 1, 0); // Name: Markers
        write_fname_pair(&mut body, 2, 0); // Type: StructProperty
        body.extend_from_slice(&0i32.to_le_bytes()); // Size = 0 per element
        body.extend_from_slice(&0i32.to_le_bytes()); // ArrayIndex
        write_fname_pair(&mut body, 3, 0); // StructName: Empty
        body.extend_from_slice(&[0u8; 16]); // StructGuid
        body.push(0u8); // HasPropertyGuid
        // Zero bytes per element — nothing more to write.

        let body_len = body.len();
        let tag = make_array_tag("Markers", "StructProperty", body_len);
        let mut cur = Cursor::new(body);
        let value = read_container_value(&tag, &mut cur, &ctx, 0, body_len as u64, "test.uasset")
            .expect("read_container_value Array<Empty> size=0")
            .expect("not Ok(None)");
        assert_eq!(
            cur.position(),
            body_len as u64,
            "cursor must sit at body end after zero-size elements"
        );

        match value {
            PropertyValue::Array {
                inner_type,
                elements,
            } => {
                assert_eq!(inner_type, "StructProperty");
                assert_eq!(elements.len(), 2);
                for (i, elem) in elements.iter().enumerate() {
                    let (struct_name, props) = match elem {
                        PropertyValue::Struct {
                            struct_name,
                            properties,
                        } => (struct_name, properties),
                        other => panic!("element {i}: {other:?}"),
                    };
                    assert_eq!(struct_name, "Empty");
                    assert!(props.is_empty(), "zero-size element has no properties");
                }
            }
            other => panic!("expected Array, got {other:?}"),
        }
    }

    /// Phase 2g Task 7 test 7: pins Design Decision #8's Map-side
    /// collection-level bail + the cursor-reseat-unblocks-downstream
    /// invariant.
    ///
    /// Construct a property stream containing TWO properties:
    /// 1. `Slots: Map<NameProperty, StructProperty>` — entry 0 is a
    ///    valid tagged struct, entry 1 is custom-binary FVector bytes
    ///    that trip `PackageIndexOob` in `read_struct_value`.
    /// 2. `Sentinel: IntProperty = i32::from_le_bytes(0xDEAD_BEEFu32.to_le_bytes())` — must
    ///    decode cleanly AFTER the Map bails, proving the bail's
    ///    seek to `expected_end` reseats the cursor so downstream
    ///    properties parse correctly.
    /// 3. None terminator.
    ///
    /// Drive via the public `read_properties` so the entire stream is
    /// consumed as a single sequence.
    #[test]
    fn map_with_custom_binary_struct_value_bails_partial_and_unblocks_downstream() {
        // Name table:
        //   0=None, 1=Slots, 2=MapProperty, 3=NameProperty,
        //   4=StructProperty, 5=ItemId, 6=IntProperty,
        //   7=first, 8=second, 9=Sentinel.
        let ctx = make_ctx(&[
            "None",
            "Slots",
            "MapProperty",
            "NameProperty",
            "StructProperty",
            "ItemId",
            "IntProperty",
            "first",
            "second",
            "Sentinel",
        ]);

        // Build the Map body: 2 entries.
        // Entry 0 = valid tagged struct ({ItemId: 42, None}).
        // Entry 1 = raw custom-binary FVector value: first 8 bytes
        // crafted to OOB the name table in `read_tag`, plus 4 bytes
        // of junk so the bail logic runs at least one read_tag attempt
        // before hitting the collection-level catch.
        let mut map_body: Vec<u8> = Vec::new();
        map_body.extend_from_slice(&0i32.to_le_bytes()); // num_keys_to_remove
        map_body.extend_from_slice(&2i32.to_le_bytes()); // count = 2
        write_fname_pair(&mut map_body, 7, 0); // key: "first"
        write_int_property(&mut map_body, 5, 6, 42); // ItemId=42
        write_none_terminator(&mut map_body);
        write_fname_pair(&mut map_body, 8, 0); // key: "second"
        map_body.extend_from_slice(&0x00FF_FFFFi32.to_le_bytes()); // bad FName idx
        map_body.extend_from_slice(&0i32.to_le_bytes());
        map_body.extend_from_slice(&[0xAAu8; 4]); // junk padding

        // Stitch the outer property stream:
        //   Slots tag header + map_body + Sentinel IntProperty + None terminator.
        let map_body_len = map_body.len();
        let mut stream: Vec<u8> = Vec::new();
        // Slots outer FPropertyTag (MapProperty).
        write_fname_pair(&mut stream, 1, 0); // Name: Slots
        write_fname_pair(&mut stream, 2, 0); // Type: MapProperty
        stream.extend_from_slice(&i32::try_from(map_body_len).unwrap().to_le_bytes());
        stream.extend_from_slice(&0i32.to_le_bytes()); // ArrayIndex
        write_fname_pair(&mut stream, 3, 0); // InnerType (key): NameProperty
        write_fname_pair(&mut stream, 4, 0); // ValueType: StructProperty
        stream.push(0u8); // HasPropertyGuid
        stream.extend_from_slice(&map_body);

        // Sentinel: IntProperty = 0xDEADBEEF.
        let sentinel_value = i32::from_le_bytes(0xDEAD_BEEFu32.to_le_bytes());
        write_int_property(&mut stream, 9, 6, sentinel_value); // Sentinel=9, IntProperty=6

        // Outer None terminator.
        write_none_terminator(&mut stream);

        // Decode via `read_properties` so the entire stream is
        // consumed in one pass — the bail's cursor reseat is the
        // ONLY thing that lets the Sentinel decode after Map fails.
        let expected_end = stream.len() as u64;
        let mut cur = Cursor::new(stream);
        let properties = read_properties(&mut cur, &ctx, 0, expected_end, "test.uasset")
            .expect("read_properties");
        assert_eq!(cur.position(), expected_end);
        assert_eq!(
            properties.len(),
            2,
            "stream contains 2 properties (Slots + Sentinel); both must decode"
        );

        // Property 0: Map<Name, Struct> with 1 entry (entry 1 bailed).
        assert_eq!(properties[0].name, "Slots");
        match &properties[0].value {
            PropertyValue::Map {
                entries,
                value_type,
                ..
            } => {
                assert_eq!(value_type, "StructProperty");
                assert_eq!(
                    entries.len(),
                    1,
                    "Map must contain 1 entry — the bad 2nd entry triggers bail"
                );
                match &entries[0].key {
                    PropertyValue::Name(k) => assert_eq!(k, "first"),
                    other => panic!("entry 0 key: {other:?}"),
                }
                match &entries[0].value {
                    PropertyValue::Struct { properties, .. } => {
                        assert_eq!(properties.len(), 1);
                        assert!(matches!(properties[0].value, PropertyValue::Int(42)));
                    }
                    other => panic!("entry 0 value: {other:?}"),
                }
            }
            other => panic!("property 0: expected Map, got {other:?}"),
        }

        // Property 1: Sentinel IntProperty — proves the cursor reseat
        // unblocked downstream parsing.
        assert_eq!(properties[1].name, "Sentinel");
        assert!(matches!(
            properties[1].value,
            PropertyValue::Int(v) if v == sentinel_value
        ));
    }

    /// `MAX_PROPERTY_DEPTH = 128`; each Array<Struct> nest adds +1
    /// to the depth passed into the next `read_properties`. With
    /// 129 nests, the deepest call hits depth 129 and trips the
    /// `depth > MAX_PROPERTY_DEPTH` guard.
    const NESTING_LAYERS: usize = 129;

    /// Phase 2g Task 7 test 4: pins the depth cap on nested
    /// `Array<Struct{Inner: Array<Struct{...}>}>` recursion. Each
    /// `Array<Struct>` layer adds +1 to the `depth` passed into the
    /// next `read_properties` call (via `read_struct_value`'s
    /// `depth + 1`). With [`NESTING_LAYERS`] = 129, the deepest
    /// `read_properties` is invoked at depth 129 and trips
    /// `AssetParseFault::PropertyDepthExceeded`.
    ///
    /// The nested-builder helpers ([`wrap_struct_body`],
    /// [`build_nested_array_of_struct_body`], [`wrap_inner_array_tag`])
    /// are private to this test file because the structure is
    /// single-use; they don't belong in `testing/uasset.rs`'s shared
    /// fixture surface.
    #[test]
    fn nested_array_of_struct_respects_depth_cap() {
        // Name table:
        //   0=None, 1=Inner, 2=ArrayProperty, 3=StructProperty,
        //   4=NestedSlot, 5=Leaf, 6=IntProperty.
        // Every Array<Struct> layer reuses these indices — the bytes
        // are identical at each layer except the trailing leaf at the
        // innermost level.
        let ctx = make_ctx(&[
            "None",
            "Inner",
            "ArrayProperty",
            "StructProperty",
            "NestedSlot",
            "Leaf",
            "IntProperty",
        ]);

        // Innermost level: a struct body containing one IntProperty
        // ("Leaf: i32 = 0") + None terminator. The base case of the
        // nesting — depth bottoms out here.
        let leaf_payload = {
            let mut buf = Vec::new();
            buf.extend_from_slice(&5i32.to_le_bytes()); // name idx (Leaf)
            buf.extend_from_slice(&0i32.to_le_bytes());
            buf.extend_from_slice(&6i32.to_le_bytes()); // type idx (IntProperty)
            buf.extend_from_slice(&0i32.to_le_bytes());
            buf.extend_from_slice(&4i32.to_le_bytes()); // size = 4
            buf.extend_from_slice(&0i32.to_le_bytes()); // array_index
            buf.push(0u8); // has_property_guid
            buf.extend_from_slice(&0i32.to_le_bytes()); // value = 0
            buf
        };

        // Iteratively wrap N-1 outer Array<Struct> layers around the
        // leaf. Each wrap adds one ArrayProperty depth (via
        // `read_array_of_struct` → `read_struct_value` →
        // `read_properties(depth+1)`).
        let mut current_struct_body = wrap_struct_body(&leaf_payload);
        for _ in 0..(NESTING_LAYERS - 1) {
            let array_body = build_nested_array_of_struct_body(&current_struct_body);
            let inner_array_tag_bytes = wrap_inner_array_tag(&array_body);
            current_struct_body = wrap_struct_body(&inner_array_tag_bytes);
        }
        // Build the outermost ArrayProperty body wrapping the chain.
        let outer_array_body = build_nested_array_of_struct_body(&current_struct_body);
        let outer_tag = make_array_tag("Inner", "StructProperty", outer_array_body.len());

        let mut cur = Cursor::new(outer_array_body.clone());
        let expected_end = outer_array_body.len() as u64;
        let err = read_container_value(&outer_tag, &mut cur, &ctx, 0, expected_end, "test.uasset")
            .expect_err("129-deep Array<Struct> must trip PropertyDepthExceeded");
        match err {
            PaksmithError::AssetParse {
                fault: AssetParseFault::PropertyDepthExceeded { .. },
                ..
            } => {}
            other => panic!("expected PropertyDepthExceeded, got {other:?}"),
        }
    }
}
