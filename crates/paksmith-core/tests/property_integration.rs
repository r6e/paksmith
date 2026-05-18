//! Phase 2b end-to-end property-decoding integration tests.
//!
//! Loads the `minimal_uasset_v5_with_properties.uasset` fixture
//! produced by `paksmith-fixture-gen` (Task 9) and asserts the
//! property tree the iterator decodes from its bytes. Also covers the
//! `PKG_UnversionedProperties` rejection path and the
//! `PropertyBag::Opaque` fallback on a truncated payload.

#![allow(missing_docs)]

use std::path::{Path, PathBuf};

use paksmith_core::asset::Package;
use paksmith_core::asset::property::{PropertyBag, PropertyValue};

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

fn assert_fixture_present(path: &Path) {
    assert!(
        path.exists(),
        "fixture {} is missing — run `cargo run -p paksmith-fixture-gen`. \
         SHA1-pinned in fixture_anchor.rs so CI fails loud here regardless.",
        path.display()
    );
}

#[test]
fn uasset_decodes_three_primitive_properties() {
    let asset = fixture_path("minimal_uasset_v5_with_properties.uasset");
    assert_fixture_present(&asset);
    let bytes = std::fs::read(&asset).expect("fixture read failed");

    let pkg = Package::read_from(&bytes, "minimal_uasset_v5_with_properties.uasset")
        .expect("Package::read_from failed");
    assert_eq!(pkg.payloads.len(), 1, "expected one export");

    let props = match &pkg.payloads[0] {
        PropertyBag::Tree { properties } => properties,
        other => panic!(
            "expected PropertyBag::Tree on the property fixture; got {other:?} — \
             the iterator should have decoded the FPropertyTag stream rather \
             than falling back to Opaque"
        ),
    };
    assert_eq!(
        props.len(),
        3,
        "expected 3 decoded properties; got {props:?}"
    );

    let by_name: std::collections::HashMap<&str, &PropertyValue> =
        props.iter().map(|p| (p.name.as_str(), &p.value)).collect();
    assert_eq!(
        by_name.get("bEnabled"),
        Some(&&PropertyValue::Bool(true)),
        "bEnabled missing or wrong value"
    );
    assert_eq!(
        by_name.get("MaxSpeed"),
        Some(&&PropertyValue::Float(1500.0)),
        "MaxSpeed missing or wrong value"
    );
    assert_eq!(
        by_name.get("ObjectName"),
        Some(&&PropertyValue::Str("Hero_C".to_string())),
        "ObjectName missing or wrong value"
    );
}

#[cfg(feature = "__test_utils")]
#[test]
fn unversioned_flag_is_rejected() {
    use paksmith_core::error::{AssetParseFault, PaksmithError};
    use paksmith_core::testing::uasset::build_minimal_ue4_27;

    // Task 9 added `package_flags_offset` to MinimalPackage,
    // populated during the summary write via a sentinel-substitution
    // probe. Flipping the 0x0000_2000 bit at that offset turns the
    // canonical cooked fixture into one that Package::read_from must
    // reject before any export iteration (Decision #6).
    let pkg = build_minimal_ue4_27();
    let mut pkg_bytes = pkg.bytes.clone();
    let off = pkg.package_flags_offset;

    let mut flags = u32::from_le_bytes(pkg_bytes[off..off + 4].try_into().unwrap());
    flags |= 0x0000_2000; // PKG_UnversionedProperties
    pkg_bytes[off..off + 4].copy_from_slice(&flags.to_le_bytes());

    let err = Package::read_from(&pkg_bytes, "x.uasset").unwrap_err();
    assert!(
        matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::UnversionedPropertiesUnsupported,
                ..
            }
        ),
        "expected UnversionedPropertiesUnsupported; got: {err:?}"
    );
}

#[cfg(feature = "__test_utils")]
#[test]
fn opaque_fallback_for_corrupt_property_payload() {
    // The minimal fixture's 0xAA filler payload is already adversarial
    // from the property iterator's perspective: the first 4-byte read
    // is i32::from_le_bytes([0xAA; 4]) = 0xAAAA_AAAA as i32, which is
    // negative. resolve_fname rejects with PackageIndexUnderflow, the
    // iterator returns Err, and read_payloads falls back to
    // PropertyBag::Opaque(buf) with a warn! event. This pins the
    // fallback contract — one corrupt export must not abort the
    // package.
    use paksmith_core::testing::uasset::build_minimal_ue4_27;

    let pkg = build_minimal_ue4_27();
    let parsed = Package::read_from(&pkg.bytes, "x.uasset").unwrap();
    assert_eq!(parsed.payloads.len(), 1);
    assert!(
        matches!(parsed.payloads[0], PropertyBag::Opaque { .. }),
        "expected Opaque fallback for the negative-FName payload; got {:?}",
        parsed.payloads[0]
    );
}
