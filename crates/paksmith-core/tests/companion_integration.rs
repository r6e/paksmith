//! Integration tests for Phase 2e: companion file loading and
//! ObjectProperty resolution.
//!
//! Four companion-file states: monolithic-ok, split-ok,
//! split-missing-uexp-error, monolithic-with-excess-uexp-warns-ok.
//! Two ObjectProperty resolution paths: `PackageIndex::Import(0)`
//! resolves to the import's bare `object_name`, `PackageIndex::Null`
//! resolves to the empty string.

#![allow(missing_docs)]

#[cfg(feature = "__test_utils")]
mod tests {
    use paksmith_core::asset::Package;
    use paksmith_core::asset::package_index::PackageIndex;
    use paksmith_core::asset::property::PropertyBag;
    use paksmith_core::error::{AssetParseFault, CompanionFileKind, PaksmithError};

    // ── Companion file states ────────────────────────────────────────────────

    /// State 1: monolithic asset (no .uexp), no export outside total_header_size.
    #[test]
    fn monolithic_asset_parses_without_uexp() {
        use paksmith_core::testing::uasset::build_minimal_ue4_27;
        let pkg = build_minimal_ue4_27();
        let result = Package::read_from(&pkg.bytes, None, None, "test.uasset");
        assert!(result.is_ok(), "{result:?}");
    }

    /// State 2: split asset, .uasset header + .uexp payload both provided.
    #[test]
    fn split_asset_stitches_and_parses() {
        use paksmith_core::testing::uasset::build_minimal_ue4_27_split;
        let (uasset, uexp) = build_minimal_ue4_27_split();
        let result = Package::read_from(&uasset, Some(&uexp), None, "test.uasset");
        assert!(result.is_ok(), "{result:?}");
        let pkg = result.unwrap();
        // `Package` exposes direct pub fields (`package.rs:60-78`); no accessor.
        assert!(!pkg.exports.exports.is_empty());
    }

    /// State 3: split asset header, .uexp not provided → MissingCompanionFile.
    #[test]
    fn split_asset_without_uexp_errors() {
        use paksmith_core::testing::uasset::build_minimal_ue4_27_split;
        let (uasset, _uexp) = build_minimal_ue4_27_split();
        let err = Package::read_from(&uasset, None, None, "Game/Sword.uasset").unwrap_err();
        assert!(
            matches!(
                &err,
                PaksmithError::AssetParse {
                    asset_path,
                    fault: AssetParseFault::MissingCompanionFile {
                        kind: CompanionFileKind::Uexp,
                    },
                } if asset_path == "Game/Sword.uasset"
            ),
            "unexpected error variant: {err:?}"
        );
    }

    /// State 4: monolithic asset (no export needs .uexp), but .uexp bytes provided.
    /// Should warn and succeed.
    #[test]
    fn monolithic_with_excess_uexp_succeeds() {
        use paksmith_core::testing::uasset::build_minimal_ue4_27;
        let pkg = build_minimal_ue4_27();
        let dummy_uexp = vec![0xFF, 0xFE]; // irrelevant extra bytes
        let result = Package::read_from(&pkg.bytes, Some(&dummy_uexp), None, "test.uasset");
        assert!(result.is_ok(), "{result:?}");
    }

    // ── ObjectProperty resolution ────────────────────────────────────────────

    /// ObjectProperty with wire i32 = -1 (PackageIndex::Import(0)) resolves to
    /// the first import's bare object_name.
    #[test]
    fn object_property_resolves_import_name() {
        use paksmith_core::asset::property::primitives::PropertyValue;
        use paksmith_core::testing::uasset::build_minimal_ue4_27_with_object_ref;

        // build_minimal_ue4_27_with_object_ref returns (bytes, expected_name).
        // The fixture has one import (object_name = expected_name) and one
        // ObjectProperty ("ObjRef") with wire i32 = -1 → PackageIndex::Import(0).
        let (pkg_bytes, expected_name) = build_minimal_ue4_27_with_object_ref();
        let pkg = Package::read_from(&pkg_bytes, None, None, "test.uasset").unwrap();

        // `Package.exports` and `Package.payloads` are direct pub fields;
        // `payloads[i]` is an `Asset` aligned with `exports.exports[i]`.
        // Phase 3: every Phase-2-style payload wraps as Asset::Generic(bag).
        let asset = &pkg.payloads[0];
        let props = match asset {
            paksmith_core::Asset::Generic(PropertyBag::Tree { properties }) => properties,
            paksmith_core::Asset::Generic(PropertyBag::Opaque { .. }) => {
                panic!("expected PropertyBag::Tree, got Opaque")
            }
            other => panic!("unexpected Asset variant: {other:?}"),
        };
        let obj_prop = props
            .iter()
            .find(|p| p.name() == "ObjRef")
            .expect("ObjRef property not found");

        assert!(
            matches!(
                &obj_prop.value,
                PropertyValue::Object {
                    kind: PackageIndex::Import(0),
                    name,
                } if name == &expected_name
            ),
            "unexpected value: {:?}",
            obj_prop.value
        );
    }

    /// ObjectProperty with wire i32 = 0 (PackageIndex::Null) resolves to "".
    #[test]
    fn object_property_null_index_resolves_empty() {
        use paksmith_core::asset::property::primitives::PropertyValue;
        use paksmith_core::testing::uasset::build_minimal_ue4_27_with_null_object_ref;

        let pkg_bytes = build_minimal_ue4_27_with_null_object_ref();
        let pkg = Package::read_from(&pkg_bytes, None, None, "test.uasset").unwrap();

        let asset = &pkg.payloads[0];
        let props = match asset {
            paksmith_core::Asset::Generic(PropertyBag::Tree { properties }) => properties,
            paksmith_core::Asset::Generic(PropertyBag::Opaque { .. }) => {
                panic!("expected PropertyBag::Tree, got Opaque")
            }
            other => panic!("unexpected Asset variant: {other:?}"),
        };
        let obj_prop = props
            .iter()
            .find(|p| p.name() == "NullRef")
            .expect("NullRef property not found");

        assert!(
            matches!(
                &obj_prop.value,
                PropertyValue::Object {
                    kind: PackageIndex::Null,
                    name,
                } if name.is_empty()
            ),
            "unexpected value: {:?}",
            obj_prop.value
        );
    }
}
