//! Parse-success integration tests against externally-produced
//! `.usmap` fixtures (issue #376).
//!
//! The fixtures live at `tests/fixtures/external_minimal_v{0,4}.usmap`
//! and are built by raw byte writes following CUE4Parse spec — see
//! `crates/paksmith-fixture-gen/src/external_usmap.rs`. The whole point
//! is that they round-trip the parser's wire-format claims against
//! something other than paksmith's own writer, breaking the
//! shared-bug failure mode that let #352/#353/#356 ship to main.

#![allow(missing_docs)]

use std::path::PathBuf;

use paksmith_core::asset::mappings::{MappedPropertyType, Usmap};

fn fixture_path(name: &str) -> PathBuf {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir.join("../../tests/fixtures").join(name)
}

fn load_external_usmap(name: &str) -> Usmap {
    let bytes = std::fs::read(fixture_path(name))
        .unwrap_or_else(|e| panic!("read external fixture `{name}`: {e}"));
    Usmap::from_bytes(&bytes).unwrap_or_else(|e| panic!("Usmap::from_bytes(`{name}`) failed: {e}"))
}

#[test]
fn external_v0_usmap_parses_hero_schema() {
    let usmap = load_external_usmap("external_minimal_v0.usmap");
    let hero = usmap
        .schemas
        .get("Hero")
        .expect("Hero schema present in v0 fixture");
    assert_eq!(hero.properties.len(), 2, "Hero has two properties");
    let health = hero
        .properties
        .iter()
        .find(|p| p.name.as_ref() == "Health")
        .expect("Health property");
    assert_eq!(
        health.prop_type,
        MappedPropertyType::Int32,
        "Health is IntProperty"
    );
    let speed = hero
        .properties
        .iter()
        .find(|p| p.name.as_ref() == "Speed")
        .expect("Speed property");
    assert_eq!(
        speed.prop_type,
        MappedPropertyType::Float,
        "Speed is FloatProperty"
    );
}

#[test]
fn external_v4_usmap_parses_hero_schema_with_explicit_enum_values() {
    let usmap = load_external_usmap("external_minimal_v4.usmap");
    let hero = usmap
        .schemas
        .get("Hero")
        .expect("Hero schema present in v4 fixture");
    assert_eq!(hero.properties.len(), 2);
    assert!(
        hero.properties.iter().any(|p| p.name.as_ref() == "Health"),
        "Health property present"
    );
    let color = hero
        .properties
        .iter()
        .find(|p| p.name.as_ref() == "Color")
        .expect("Color property");
    let MappedPropertyType::Enum { enum_name } = &color.prop_type else {
        panic!("Color must be EnumProperty, got {:?}", color.prop_type);
    };
    assert_eq!(enum_name.as_ref(), "EColor");

    // The v4 fixture encodes EColor with sparse ordinals: Red=0, Blue=2.
    // A reader that stores values positionally (the v0-v3 layout) would
    // mis-resolve Blue to value index 1 (empty) or drop it. The explicit
    // u64-keyed map is the only correct representation.
    let ecolor = usmap.enums.get("EColor").expect("EColor enum present");
    assert_eq!(
        ecolor.get(&0).map(AsRef::as_ref),
        Some("Red"),
        "EColor::Red at ordinal 0"
    );
    assert_eq!(
        ecolor.get(&2).map(AsRef::as_ref),
        Some("Blue"),
        "EColor::Blue at ordinal 2 (sparse — would mis-resolve positionally)"
    );
    assert_eq!(
        ecolor.get(&1),
        None,
        "EColor has no ordinal 1 (gap in explicit values)"
    );
}
