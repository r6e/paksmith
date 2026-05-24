//! Phase 2c container-decoder proptests.
//!
//! Gated on `__test_utils` because every test constructs `PropertyTag`
//! values via `PropertyTag::for_test`, which lives behind the same
//! feature. Runs under `cargo test --workspace --all-features` (the
//! command CI uses).

#![cfg(feature = "__test_utils")]
#![allow(missing_docs)]

use std::io::Cursor;

use paksmith_core::asset::property::test_utils::make_ctx;
use paksmith_core::asset::property::{MAX_COLLECTION_ELEMENTS, PropertyTag, read_container_value};
use paksmith_core::error::{AssetParseFault, CollectionKind, PaksmithError};
use proptest::prelude::*;

fn array_tag_with_count_bytes(inner_type: &str, count: i32) -> (PropertyTag, Vec<u8>) {
    // tag.size is unused: the cap check at the top of read_array_value
    // short-circuits on the count i32 before any element reads, so the
    // size never has to match the body length.
    let size = 4i32;
    let tag = PropertyTag::for_test("X", "ArrayProperty", size).with_inner_type(inner_type);
    let bytes = count.to_le_bytes().to_vec();
    (tag, bytes)
}

proptest! {
    #[test]
    fn array_negative_count_always_rejected(count in i32::MIN..0i32) {
        let ctx = make_ctx(&[]);
        let (tag, bytes) = array_tag_with_count_bytes("IntProperty", count);
        let mut r = Cursor::new(bytes);
        let err = read_container_value(&tag, &mut r, &ctx, 0, 0, "x.uasset")
            .unwrap_err();
        let ok = matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::CollectionElementCountExceeded {
                    collection: CollectionKind::Array, ..
                },
                ..
            }
        );
        prop_assert!(ok, "unexpected error variant for count {count}");
    }

    #[test]
    fn array_over_cap_always_rejected(excess in 1usize..=1_000_000usize) {
        let count_usize = MAX_COLLECTION_ELEMENTS.saturating_add(excess);
        let Ok(count) = i32::try_from(count_usize) else {
            return Ok(());
        };
        let ctx = make_ctx(&[]);
        let (tag, bytes) = array_tag_with_count_bytes("IntProperty", count);
        let mut r = Cursor::new(bytes);
        let err = read_container_value(&tag, &mut r, &ctx, 0, 0, "x.uasset")
            .unwrap_err();
        let ok = matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::CollectionElementCountExceeded {
                    collection: CollectionKind::Array, ..
                },
                ..
            }
        );
        prop_assert!(ok, "unexpected error variant for count {count}");
    }
}

#[test]
fn depth_exceeded_fires_at_limit() {
    // MAX_PROPERTY_DEPTH = 128 in bag.rs is `pub(crate)` and not
    // reachable here; mirror the literal-128 pattern used elsewhere
    // in the property proptest suite (a `bag::tests` unit test pins
    // the constant to 128, so drift trips that anchor first).
    const DEPTH_CAP: usize = 128;
    let ctx = make_ctx(&["None", "X", "IntProperty"]);

    // Struct body: one IntProperty followed by None terminator.
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(&1i32.to_le_bytes()); // Name FName index = "X"
    body.extend_from_slice(&0i32.to_le_bytes()); // Name FName number
    body.extend_from_slice(&2i32.to_le_bytes()); // Type FName = "IntProperty"
    body.extend_from_slice(&0i32.to_le_bytes());
    body.extend_from_slice(&4i32.to_le_bytes()); // Size
    body.extend_from_slice(&0i32.to_le_bytes()); // ArrayIndex
    body.push(0u8); // HasPropertyGuid
    body.extend_from_slice(&42i32.to_le_bytes()); // Value
    body.extend_from_slice(&0i32.to_le_bytes()); // None terminator: index 0
    body.extend_from_slice(&0i32.to_le_bytes()); // None terminator: number 0

    let body_size = i32::try_from(body.len()).expect("body fits in i32");
    let tag =
        PropertyTag::for_test("S", "StructProperty", body_size).with_struct_name("TestStruct");

    let expected_end = body.len() as u64;
    let mut r = Cursor::new(body);

    // The guard in `read_properties` is `if depth > MAX_PROPERTY_DEPTH`
    // (strict greater-than). `read_struct_value` calls
    // `read_properties(depth + 1)`, so passing `depth = DEPTH_CAP`
    // here fires the guard on the inner call.
    let err =
        read_container_value(&tag, &mut r, &ctx, DEPTH_CAP, expected_end, "x.uasset").unwrap_err();
    assert!(
        matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::PropertyDepthExceeded { .. },
                ..
            }
        ),
        "expected PropertyDepthExceeded, got {err:?}"
    );
}
