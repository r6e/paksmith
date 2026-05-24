//! Shared test scaffolding for the `property` sub-modules.
//!
//! `make_ctx`, `make_ctx_with_import`, and `write_fname` show up in
//! every property test file (tag.rs, primitives.rs, text.rs, mod.rs
//! tests, plus the integration tests under `tests/`). Centralizing
//! them here:
//! 1. Removes ~30 lines of identical scaffolding per module.
//! 2. Makes Phase 2c's container reader tests (which also use
//!    `make_ctx` in 30+ sites per the plan) reach the same helper
//!    without copying again.
//!
//! Gated on `#[cfg(any(test, feature = "__test_utils"))]` matching
//! the rest of `paksmith-core::testing` — the helpers are never
//! reachable from release builds.

use std::sync::Arc;

use crate::asset::{
    AssetContext,
    custom_version::CustomVersionContainer,
    export_table::ExportTable,
    import_table::{ImportTable, ObjectImport},
    name_table::{FName, NameTable},
    package_index::PackageIndex,
    version::AssetVersion,
};

/// Build an `AssetContext` whose name table is the given list of
/// strings (in wire order), with empty import/export tables and the
/// default `AssetVersion`. Sufficient for almost every property
/// reader unit test — they only consume `ctx.names` for FName
/// resolution.
///
/// Index 0 MUST be `"None"`. `read_tag` short-circuits `(0, 0)` FName
/// pairs as the None terminator before any name lookup; if index 0
/// holds another name, a literal `(0, 0)` terminator resolves to that
/// name and the wire stream mis-terminates with a cryptic
/// `PackageIndexOob` much later in the parse.
#[must_use]
pub fn make_ctx(names: &[&str]) -> AssetContext {
    debug_assert!(
        names.is_empty() || matches!(names.first(), Some(&"None")),
        "test name tables MUST start with \"None\" at index 0 — otherwise a \
         literal (0, 0) None-terminator FName pair resolves to whatever name \
         sits at index 0 and the wire stream mis-terminates with a cryptic \
         PackageIndexOob much later in the parse"
    );
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

/// Build an `AssetContext` with one `ObjectImport` whose `object_name`
/// resolves to `import_name`. Used by ObjectProperty unit tests that
/// need to drive a non-empty import table.
///
/// Names: `0="None"`, `1="Class"`, `2="/Script/CoreUObject"`,
/// `3=<import_name>`. The single import:
/// `class_package_name=2`, `class_name=1`, `outer_index=Null`,
/// `object_name=3`. UE4.27 wire shape (`legacy_file_version = -7`,
/// `file_version_ue4 = 522`).
#[must_use]
pub fn make_ctx_with_import(import_name: &str) -> AssetContext {
    let names = NameTable {
        names: vec![
            FName::new("None"),
            FName::new("Class"),
            FName::new("/Script/CoreUObject"),
            FName::new(import_name),
        ],
    };
    AssetContext::new(
        Arc::new(names),
        Arc::new(ImportTable {
            imports: vec![ObjectImport {
                class_package_name: 2,
                class_package_number: 0,
                class_name: 1,
                class_name_number: 0,
                outer_index: PackageIndex::Null,
                object_name: 3,
                object_name_number: 0,
                import_optional: None,
            }],
        }),
        Arc::new(ExportTable::default()),
        AssetVersion {
            legacy_file_version: -7,
            file_version_ue4: 522,
            file_version_ue5: None,
            file_version_licensee_ue4: 0,
        },
        Arc::new(CustomVersionContainer::default()),
        None,
    )
}

/// Append a wire-format FName `(index, number)` pair to `buf` — the
/// two-i32-LE little-endian payload `read_fname_pair` expects on the
/// other side of the byte stream.
pub fn write_fname(buf: &mut Vec<u8>, index: i32, number: i32) {
    buf.extend_from_slice(&index.to_le_bytes());
    buf.extend_from_slice(&number.to_le_bytes());
}
