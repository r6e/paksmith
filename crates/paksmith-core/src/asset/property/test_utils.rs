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
use std::sync::atomic::AtomicU64;

use crate::asset::{
    AssetContext, DerivedStringBudget, MAX_DECODE_WARNINGS,
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

/// Give `ctx` a fresh derived-string budget of `limit` bytes, so a
/// test reaches the cap with a few short names.
#[must_use]
pub fn with_derived_budget(mut ctx: AssetContext, limit: u64) -> AssetContext {
    ctx.derived_strings = Arc::new(DerivedStringBudget::new(limit));
    ctx
}

/// Give `ctx` a spent decode-time warning budget, past its suppression
/// notice, so a gated warning logs nothing.
#[must_use]
pub fn with_decode_warnings_spent(mut ctx: AssetContext) -> AssetContext {
    ctx.decode_warnings = Arc::new(AtomicU64::new(MAX_DECODE_WARNINGS + 1));
    ctx
}

/// Give `ctx` a bulk resolver serving `ubulk` as its `.ubulk` (the
/// `.uptnl` loader fails, as in `new_for_test_with_ubulk`).
#[cfg(feature = "__test_utils")]
#[must_use]
pub fn with_ubulk(mut ctx: AssetContext, ubulk: Vec<u8>) -> AssetContext {
    let resolver = crate::asset::bulk_data::BulkDataResolver::new_for_test_with_ubulk(
        Vec::<u8>::new(),
        0,
        0,
        ubulk,
    );
    ctx.bulk_resolver = Some(Arc::new(resolver));
    ctx
}

/// Assert `result` is the derived-string budget refusal for `limit`.
///
/// # Panics
///
/// When `result` is anything else.
pub fn assert_derived_budget_exceeded<T: std::fmt::Debug>(result: crate::Result<T>, limit: u64) {
    match result {
        Err(crate::PaksmithError::AssetParse {
            fault: crate::error::AssetParseFault::DerivedStringBudgetExceeded { limit: got },
            ..
        }) => assert_eq!(got, limit),
        other => panic!("expected DerivedStringBudgetExceeded {{ limit: {limit} }}, got {other:?}"),
    }
}

/// Assert `result` is the bulk-read ledger refusal: `charged` bytes
/// against a `source_len`-byte `tier` source.
///
/// # Panics
///
/// When `result` is anything else.
#[cfg(feature = "__test_utils")]
pub fn assert_parse_reads_exceed_source<T: std::fmt::Debug>(
    result: crate::Result<T>,
    tier: crate::asset::bulk_data::BulkDataTier,
    charged: u64,
    source_len: u64,
) {
    let expected = crate::error::AssetParseFault::BulkDataParseReadsExceedSource {
        tier,
        charged,
        source_len,
    };
    match result {
        Err(crate::PaksmithError::AssetParse { fault, .. }) => assert_eq!(fault, expected),
        other => panic!("expected {expected:?}, got {other:?}"),
    }
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

/// Append a **top-level export** object-body terminator: the `None` tag plus the
/// `UObject::Serialize` object-GUID tail (`bSerializeGuid = 0`, no `FGuid`) that
/// every typed reader consumes via `read_object_guid_tail` before its
/// class-specific binary segment. Use this (not [`write_none_tag`]) wherever a
/// fixture ends a top-level export's property stream; nested struct/array `None`
/// terminators still use [`write_none_tag`].
pub fn write_object_end(buf: &mut Vec<u8>) {
    write_none_tag(buf);
    buf.extend_from_slice(&0i32.to_le_bytes()); // bSerializeGuid = 0 (bool32)
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
    #[expect(
        clippy::expect_used,
        reason = "caller-authored test string, far under i32::MAX"
    )]
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
    make_ctx_with_version_and_names(ue4, ue5, &["None"])
}

/// [`make_ctx_with_version`] plus an out-of-band engine-version hint
/// (#656) — for gates that only a profile's declared version can
/// disambiguate (e.g. `bSerializeMipData` at object version 1009,
/// where UE 5.2 and 5.3 are wire-identical).
///
/// # Panics
///
/// If `engine` is not a parseable `major.minor[.patch]` string — a
/// test-authoring error, not a runtime condition.
#[must_use]
pub fn make_ctx_with_version_and_engine(ue4: i32, ue5: Option<i32>, engine: &str) -> AssetContext {
    let hint = crate::asset::UeVersion::parse_lenient(engine);
    assert!(hint.is_some(), "test hint must parse: {engine:?}");
    make_ctx_with_version(ue4, ue5).with_engine_version_hint(hint)
}

/// [`make_ctx_with_version`] with a caller-supplied name table — for
/// version-gated wire shapes whose tests need real FName resolution
/// (e.g. the UE5 ≥ 1011 property-tag forms, #643). Index 0 MUST be
/// `"None"` (same contract as [`make_ctx`]).
#[must_use]
pub fn make_ctx_with_version_and_names(ue4: i32, ue5: Option<i32>, names: &[&str]) -> AssetContext {
    debug_assert!(
        matches!(names.first(), Some(&"None")),
        "test name tables MUST start with \"None\" at index 0 — see `make_ctx` docstring"
    );
    let table = NameTable {
        names: names.iter().map(|n| FName::new(n)).collect(),
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
    #[should_panic(expected = "expected DerivedStringBudgetExceeded")]
    fn assert_derived_budget_exceeded_rejects_a_success() {
        assert_derived_budget_exceeded(Ok(()), 1);
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    #[should_panic(expected = "expected BulkDataParseReadsExceedSource")]
    fn assert_parse_reads_exceed_source_rejects_a_success() {
        assert_parse_reads_exceed_source(
            Ok(()),
            crate::asset::bulk_data::BulkDataTier::Streaming,
            2,
            1,
        );
    }

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
