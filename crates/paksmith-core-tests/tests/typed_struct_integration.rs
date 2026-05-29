//! Phase 3c end-to-end integration: a synthetic UAsset carrying one
//! custom-binary `StructProperty` per registered typed decoder is
//! parsed through the full `Package::read_from` → property-tree
//! pipeline, and each property is asserted to decode to the right
//! `PropertyValue::TypedStruct(TypedStructValue::*)` variant.
//!
//! This is the integration counterpart to the per-decoder unit tests
//! in `paksmith-core/src/asset/structs/*` and the dispatch unit tests
//! in `containers.rs`: it proves the registry wiring (Task 10) fires
//! against a *real asset's* wire bytes, not a hand-fed cursor.
//!
//! **Scope note:** only the **9 registered** structs decode typed
//! (`Vector`, `Vector2D`, `Vector4`, `Rotator`, `Quat`, `Color`,
//! `LinearColor`, `Box`, `Box2D`). `FTransform` / `FBoxSphereBounds`
//! are unregistered (tagged-serialized under their bare wire names —
//! see Tasks 8/9), so the fixture also carries one unregistered
//! `"Transform"` StructProperty and asserts it falls through to a
//! tagged `PropertyValue::Struct`. UE4 (non-LWC, f32) coverage; the
//! f64 LWC width plumbing is pinned by
//! `containers::tests::struct_property_vector_decodes_lwc_widened`.
//!
//! Required feature: `__test_utils` (the `testing::uasset` builders
//! are gated behind it; only this sibling crate enables it).

#![allow(missing_docs)]

use std::collections::HashMap;

use paksmith_core::asset::Package;
use paksmith_core::asset::property::primitives::PropertyValue;
use paksmith_core::asset::structs::TypedStructValue as TSV;
use paksmith_core::testing::uasset::build_minimal_ue4_27_with_engine_structs;
use paksmith_core::{Asset, PropertyBag};

/// Parse the engine-structs fixture and return its export property
/// tree keyed by property name.
fn decode_engine_structs() -> Vec<paksmith_core::asset::property::primitives::Property> {
    let pkg = build_minimal_ue4_27_with_engine_structs();
    let parsed = Package::read_from(&pkg.bytes, None, None, "Game/EngineStructs.uasset")
        .expect("parse engine-structs fixture");
    match parsed.payloads.into_iter().next().expect("one export") {
        Asset::Generic(PropertyBag::Tree { properties }) => properties,
        other => panic!("expected decoded property Tree, got {other:?}"),
    }
}

fn eps(a: f64, b: f64) {
    assert!((a - b).abs() < f64::EPSILON, "got {a}, want {b}");
}

#[test]
fn registered_engine_structs_decode_typed_end_to_end() {
    let props = decode_engine_structs();
    let by_name: HashMap<&str, &PropertyValue> =
        props.iter().map(|p| (p.name(), &p.value)).collect();

    let typed = |name: &str| -> &TSV {
        match by_name.get(name) {
            Some(PropertyValue::TypedStruct(b)) => b.as_ref(),
            other => panic!("`{name}`: expected TypedStruct, got {other:?}"),
        }
    };

    match typed("Position") {
        TSV::Vector(v) => {
            eps(v.x, 1.5);
            eps(v.y, 2.5);
            eps(v.z, 3.5);
        }
        o => panic!("Position: expected Vector, got {o:?}"),
    }
    match typed("UV") {
        TSV::Vector2D(v) => {
            eps(v.x, 0.25);
            eps(v.y, 0.75);
        }
        o => panic!("UV: expected Vector2D, got {o:?}"),
    }
    match typed("Tangent") {
        TSV::Vector4(v) => {
            eps(v.x, 1.0);
            eps(v.y, 2.0);
            eps(v.z, 3.0);
            eps(v.w, 4.0);
        }
        o => panic!("Tangent: expected Vector4, got {o:?}"),
    }
    match typed("Rotation") {
        TSV::Rotator(r) => {
            eps(r.pitch, 10.0);
            eps(r.yaw, 20.0);
            eps(r.roll, 30.0);
        }
        o => panic!("Rotation: expected Rotator, got {o:?}"),
    }
    match typed("Orientation") {
        TSV::Quat(q) => {
            eps(q.x, 0.25);
            eps(q.y, 0.5);
            eps(q.z, 0.75);
            eps(q.w, 1.0);
        }
        o => panic!("Orientation: expected Quat, got {o:?}"),
    }
    // FColor wire order is BGRA — bytes [0x10, 0x20, 0x30, 0xFF]
    // decode to stored RGBA r=0x30, g=0x20, b=0x10, a=0xFF.
    match typed("Tint") {
        TSV::Color(c) => assert_eq!(
            (c.r, c.g, c.b, c.a),
            (0x30, 0x20, 0x10, 0xFF),
            "FColor BGRA→RGBA swizzle"
        ),
        o => panic!("Tint: expected Color, got {o:?}"),
    }
    // FLinearColor is f32 RGBA, NOT LWC-widened.
    match typed("Emissive") {
        TSV::LinearColor(c) => {
            assert!((c.r - 0.25).abs() < f32::EPSILON);
            assert!((c.g - 0.5).abs() < f32::EPSILON);
            assert!((c.b - 0.75).abs() < f32::EPSILON);
            assert!((c.a - 1.0).abs() < f32::EPSILON);
        }
        o => panic!("Emissive: expected LinearColor, got {o:?}"),
    }
    match typed("Bounds") {
        TSV::Box(b) => {
            eps(b.min.x, -1.0);
            eps(b.min.z, -3.0);
            eps(b.max.x, 1.0);
            eps(b.max.z, 3.0);
            assert!(b.is_valid);
        }
        o => panic!("Bounds: expected Box, got {o:?}"),
    }
    match typed("UVBounds") {
        TSV::Box2D(b) => {
            eps(b.min.x, -1.0);
            eps(b.min.y, -2.0);
            eps(b.max.x, 3.0);
            eps(b.max.y, 4.0);
            assert!(b.is_valid);
        }
        o => panic!("UVBounds: expected Box2D, got {o:?}"),
    }
}

#[test]
fn unregistered_transform_struct_property_falls_through_to_tagged() {
    // `FTransform` is NOT registered (tagged-serialized under the bare
    // "Transform" wire name — Task 8). A "Transform" StructProperty
    // must therefore decode to the Phase 2g tagged `PropertyValue::Struct`,
    // NOT a `TypedStruct`. The fixture gives it a bare-None-terminator
    // body, so the tagged path yields an empty Struct.
    let props = decode_engine_structs();
    let xform = props
        .iter()
        .find(|p| p.name() == "Xform")
        .expect("Xform property present");
    match &xform.value {
        PropertyValue::Struct {
            struct_name,
            properties,
        } => {
            assert_eq!(&**struct_name, "Transform");
            assert!(
                properties.is_empty(),
                "bare-None-terminator body → empty tagged Struct"
            );
        }
        other => panic!("Xform: expected tagged Struct(Transform), got {other:?}"),
    }
}
