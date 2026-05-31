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
        "test name tables MUST start with \"None\" at index 0 — see `make_ctx` docstring"
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

/// Append the `(0, 0)` "None" FPropertyTag terminator (ends a
/// tagged-property stream / an empty segment 1).
pub fn write_none_tag(buf: &mut Vec<u8>) {
    write_fname(buf, 0, 0);
}

/// Append a UE4.27 `IntProperty` FPropertyTag + its `i32` value:
/// Name FName, Type FName (`type_idx` = `"IntProperty"`), `i32` Size=4,
/// `i32` ArrayIndex=0, `u8` HasPropertyGuid=0, then the value.
pub fn write_int_property(buf: &mut Vec<u8>, name_idx: i32, type_idx: i32, value: i32) {
    write_fname(buf, name_idx, 0);
    write_fname(buf, type_idx, 0);
    buf.extend_from_slice(&4i32.to_le_bytes()); // Size
    buf.extend_from_slice(&0i32.to_le_bytes()); // ArrayIndex
    buf.push(0u8); // HasPropertyGuid
    buf.extend_from_slice(&value.to_le_bytes());
}

/// Append a UE `FString`: `i32` length (UTF-8 byte count incl. the null
/// terminator) + the bytes + the null terminator. The positive-length
/// (UTF-8) form `read_asset_fstring` decodes.
///
/// # Panics
/// If `s.len() + 1` exceeds `i32::MAX` (never for a realistic test
/// string).
pub fn write_fstring(buf: &mut Vec<u8>, s: &str) {
    let len = i32::try_from(s.len() + 1).expect("test FString fits in i32");
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(s.as_bytes());
    buf.push(0);
}

/// Build an `AssetContext` with a custom `(file_version_ue4,
/// file_version_ue5)` pair. Empty name / import / export tables.
/// Used by Phase 3c typed-struct decoder tests to dispatch the
/// UE4-vs-UE5-LWC width branch.
///
/// `ue5: Some(v)` produces an asset with `legacy_file_version = -8`
/// (UE5 cooked); `ue5: None` produces UE4 (`legacy_file_version = -7`).
/// The legacy version is load-bearing for downstream summary
/// parsers that gate on the sign (e.g. `legacy_file_version <= -8`
/// triggers `file_version_ue5` read); the test
/// `make_ctx_with_version_sets_legacy_file_version_correctly`
/// pins the sign.
#[must_use]
pub fn make_ctx_with_version(ue4: i32, ue5: Option<i32>) -> AssetContext {
    let table = NameTable {
        names: vec![FName::new("None")],
    };
    AssetContext::new(
        Arc::new(table),
        Arc::new(ImportTable::default()),
        Arc::new(ExportTable::default()),
        AssetVersion {
            legacy_file_version: if ue5.is_some() { -8 } else { -7 },
            file_version_ue4: ue4,
            file_version_ue5: ue5,
            file_version_licensee_ue4: 0,
        },
        Arc::new(CustomVersionContainer::default()),
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn make_ctx_with_version_sets_legacy_file_version_correctly() {
        // UE4 path: `ue5: None` → `legacy_file_version = -7`.
        // UE5 path: `ue5: Some(_)` → `legacy_file_version = -8`.
        // Pins the sign so the `if-else` doesn't silently degrade
        // (cargo-mutants would otherwise rewrite `-7` → `7` and
        // `-8` → `8` undetected; the FVector decoder tests only
        // touch `file_version_ue5` via `is_lwc()`, not the legacy).
        let ue4 = make_ctx_with_version(510, None);
        assert_eq!(ue4.version.legacy_file_version, -7);
        assert_eq!(ue4.version.file_version_ue4, 510);
        assert_eq!(ue4.version.file_version_ue5, None);

        let ue5 = make_ctx_with_version(522, Some(1004));
        assert_eq!(ue5.version.legacy_file_version, -8);
        assert_eq!(ue5.version.file_version_ue4, 522);
        assert_eq!(ue5.version.file_version_ue5, Some(1004));
    }
}
