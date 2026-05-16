#![allow(missing_docs)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use paksmith_core::asset::{Package, PackageIndex};

fn fixture_path(name: &str) -> PathBuf {
    // Matches the form used by fixture_anchor.rs in the same crate:
    // compile-time `env!` (no runtime var lookup, no `unwrap`) + a
    // relative literal that resolves to <workspace>/tests/fixtures/.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

fn assert_fixture_present(pak: &Path) {
    assert!(
        pak.exists(),
        "fixture {} is missing — run `cargo run -p paksmith-fixture-gen`. \
         Pinned in fixture_anchor.rs so CI fails loud here regardless.",
        pak.display()
    );
}

#[test]
fn round_trip_minimal_pak_uasset() {
    let pak = fixture_path("real_v8b_uasset.pak");
    assert_fixture_present(&pak);

    let pkg = Package::read_from_pak(&pak, "Game/Maps/Demo.uasset")
        .expect("parse minimal uasset from synthetic pak");

    assert_eq!(pkg.asset_path, "Game/Maps/Demo.uasset");
    assert_eq!(pkg.summary.version.legacy_file_version, -7);
    assert_eq!(pkg.summary.version.file_version_ue4, 522);
    assert!(pkg.summary.version.file_version_ue5.is_none());
    assert_eq!(pkg.names.names.len(), 3);
    assert_eq!(pkg.names.names[0].as_str(), "/Script/CoreUObject");
    assert_eq!(pkg.imports.imports.len(), 1);
    assert_eq!(pkg.imports.imports[0].outer_index, PackageIndex::Null);
    assert_eq!(pkg.exports.exports.len(), 1);
    assert_eq!(pkg.exports.exports[0].class_index, PackageIndex::Import(0));
    assert!(pkg.exports.exports[0].is_asset);
    assert_eq!(pkg.exports.exports[0].serial_size, 16);
    assert_eq!(pkg.payloads.len(), 1);
    assert_eq!(pkg.payloads[0].byte_len(), 16);
}

#[test]
fn context_arc_sharing() {
    let pak = fixture_path("real_v8b_uasset.pak");
    assert_fixture_present(&pak);
    let pkg = Package::read_from_pak(&pak, "Game/Maps/Demo.uasset").unwrap();
    let ctx1 = pkg.context();
    let ctx2 = ctx1.clone();
    assert!(Arc::ptr_eq(&ctx1.names, &ctx2.names));
    assert!(Arc::ptr_eq(&ctx1.imports, &ctx2.imports));
    assert!(Arc::ptr_eq(&ctx1.exports, &ctx2.exports));
}
