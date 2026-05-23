//! Phase 2b property-decoder proptests.
//!
//! Covers: primitive round-trips across full value range, security
//! cap rejections (negative-size, over-cap size, depth), and the
//! Float NaN bit-comparison path. Hand-written tests at the unit
//! level pin specific values; these widen the range across i32::MIN ..=
//! i32::MAX (and equivalent for other widths) plus every 4-byte
//! pattern as f32 (NaN inclusive).

#![allow(missing_docs)]

use std::io::Cursor;
use std::sync::Arc;

use paksmith_core::asset::property::tag::MAX_PROPERTY_TAG_SIZE;
use paksmith_core::asset::property::{
    PropertyTag,
    primitives::{PropertyValue, read_primitive_value},
    read_properties,
};
use paksmith_core::asset::{
    AssetContext,
    custom_version::CustomVersionContainer,
    export_table::ExportTable,
    import_table::ImportTable,
    name_table::{FName, NameTable},
    version::AssetVersion,
};
use paksmith_core::error::{AssetParseFault, AssetWireField, BoundsUnit, PaksmithError};
use proptest::prelude::*;

// Local `make_ctx` — the shared `paksmith_core::asset::property::test_utils::make_ctx`
// is gated on `__test_utils` so integration tests would need to opt in
// to use it. Keeping this file default-runnable matches the existing
// `cargo test` convention (no `--all-features` required for proptests).
fn make_ctx(names: &[&str]) -> AssetContext {
    let table = NameTable {
        names: names.iter().map(|n| FName::new(n)).collect(),
    };
    AssetContext::new(
        Arc::new(table),
        Arc::new(ImportTable::default()),
        Arc::new(ExportTable::default()),
        AssetVersion::default(),
        Arc::new(CustomVersionContainer::default()),
        None,
    )
}

fn make_tag(type_name: &str, size: i32) -> PropertyTag {
    PropertyTag::for_test("Prop", type_name, size)
}

proptest! {
    #[test]
    fn int_property_round_trip(v in i32::MIN..=i32::MAX) {
        let tag = make_tag("IntProperty", 4);
        let ctx = make_ctx(&["None"]);
        let buf = v.to_le_bytes();
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf[..]), &ctx, "x")
            .unwrap()
            .unwrap();
        prop_assert_eq!(val, PropertyValue::Int(v));
    }

    #[test]
    fn int64_property_round_trip(v in i64::MIN..=i64::MAX) {
        let tag = make_tag("Int64Property", 8);
        let ctx = make_ctx(&["None"]);
        let buf = v.to_le_bytes();
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf[..]), &ctx, "x")
            .unwrap()
            .unwrap();
        prop_assert_eq!(val, PropertyValue::Int64(v));
    }

    #[test]
    fn uint32_property_round_trip(v in 0u32..=u32::MAX) {
        let tag = make_tag("UInt32Property", 4);
        let ctx = make_ctx(&["None"]);
        let buf = v.to_le_bytes();
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf[..]), &ctx, "x")
            .unwrap()
            .unwrap();
        prop_assert_eq!(val, PropertyValue::UInt32(v));
    }

    #[test]
    fn float_property_round_trip_bitwise(bits in 0u32..=u32::MAX) {
        // Any 4-byte pattern is a valid f32 (NaN, ±inf, subnormals
        // included). Compare bit patterns so NaN bit-equality holds —
        // `f32::NaN == f32::NaN` is false by spec, so a direct value
        // compare would spuriously fail on every NaN draw.
        let v = f32::from_bits(bits);
        let tag = make_tag("FloatProperty", 4);
        let ctx = make_ctx(&["None"]);
        let buf = v.to_le_bytes();
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf[..]), &ctx, "x")
            .unwrap()
            .unwrap();
        if let PropertyValue::Float(got) = val {
            prop_assert_eq!(got.to_bits(), v.to_bits());
        } else {
            return Err(TestCaseError::fail("expected Float variant"));
        }
    }

    #[test]
    fn bool_property_round_trip(v in any::<bool>()) {
        let mut tag = make_tag("BoolProperty", 0);
        tag.bool_val = v;
        let ctx = make_ctx(&["None"]);
        let val = read_primitive_value(&tag, &mut Cursor::new(&[][..]), &ctx, "x")
            .unwrap()
            .unwrap();
        prop_assert_eq!(val, PropertyValue::Bool(v));
    }
}

#[test]
fn negative_size_rejected_in_read_properties() {
    // names: 0=None, 1=Foo, 2=IntProperty
    let ctx = make_ctx(&["None", "Foo", "IntProperty"]);
    let mut buf = Vec::new();
    buf.extend_from_slice(&1i32.to_le_bytes()); // Name: Foo
    buf.extend_from_slice(&0i32.to_le_bytes());
    buf.extend_from_slice(&2i32.to_le_bytes()); // Type: IntProperty
    buf.extend_from_slice(&0i32.to_le_bytes());
    buf.extend_from_slice(&(-5i32).to_le_bytes()); // Size: -5
    buf.extend_from_slice(&0i32.to_le_bytes());
    buf.push(0u8);
    let export_end = buf.len() as u64 + 4;
    let err = read_properties(&mut Cursor::new(&buf[..]), &ctx, 0, export_end, "x").unwrap_err();
    assert!(matches!(
        err,
        PaksmithError::AssetParse {
            fault: AssetParseFault::NegativeValue {
                field: AssetWireField::PropertyTagSize,
                ..
            },
            ..
        }
    ));
}

#[test]
fn oversized_property_rejected() {
    let ctx = make_ctx(&["None", "Foo", "StrProperty"]);
    let mut buf = Vec::new();
    buf.extend_from_slice(&1i32.to_le_bytes());
    buf.extend_from_slice(&0i32.to_le_bytes());
    buf.extend_from_slice(&2i32.to_le_bytes());
    buf.extend_from_slice(&0i32.to_le_bytes());
    buf.extend_from_slice(&(MAX_PROPERTY_TAG_SIZE + 1).to_le_bytes());
    buf.extend_from_slice(&0i32.to_le_bytes());
    buf.push(0u8);
    let export_end = (buf.len() + MAX_PROPERTY_TAG_SIZE as usize + 2) as u64;
    let err = read_properties(&mut Cursor::new(&buf[..]), &ctx, 0, export_end, "x").unwrap_err();
    assert!(matches!(
        err,
        PaksmithError::AssetParse {
            fault: AssetParseFault::BoundsExceeded {
                field: AssetWireField::PropertyTagSize,
                unit: BoundsUnit::Bytes,
                ..
            },
            ..
        }
    ));
}

#[test]
fn depth_exceeded_is_rejected() {
    // MAX_PROPERTY_DEPTH = 128 (pub(crate) in bag.rs); 129 is over.
    // Test uses the literal here rather than importing the const
    // because the const is intentionally not pub.
    let ctx = make_ctx(&["None"]);
    let err = read_properties(&mut Cursor::new(&[][..]), &ctx, 129, 0, "x").unwrap_err();
    assert!(matches!(
        err,
        PaksmithError::AssetParse {
            fault: AssetParseFault::PropertyDepthExceeded {
                depth: 129,
                limit: 128
            },
            ..
        }
    ));
}
