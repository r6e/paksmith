//! Issue #656 — the engine-version hint travels the PUBLIC read path
//! into the parse context where version gates read it.
//!
//! The gate behaviour itself (a 5.3 profile making `UTexture2D` consume
//! `bSerializeMipData` at the ambiguous object version 1009) is pinned
//! by unit tests next to the reader, which can author the exact
//! ambiguous bytes. What those cannot show is that a caller's hint
//! actually REACHES them through the shipped entry points — that is
//! this file's job, out-of-crate and through `ReadOptions` only.
//!
//! Required feature: `__test_utils` (byte builders).

use std::sync::Arc;

use paksmith_core::asset::{AssetContext, ReadOptions, UeVersion};
use paksmith_core::testing::uasset::build_minimal_ue4_27;
use paksmith_core::{Package, PaksmithError};

fn parse_with(opts: &ReadOptions<'_>) -> Package {
    let pkg = build_minimal_ue4_27();
    Package::read_from_with(&pkg.bytes, None, opts, "Game/Fixture.uasset")
        .expect("the minimal fixture parses")
}

/// A hint supplied to `read_from_with` is the one the parse context
/// carries — the whole point of the plumbing.
#[test]
fn read_options_hint_reaches_the_asset_context() {
    let hint = UeVersion::parse_lenient("5.3");
    assert!(hint.is_some(), "fixture hint must parse");
    let pkg = parse_with(&ReadOptions::new().with_engine_version_hint(hint));
    let ctx: AssetContext = pkg.context();
    assert_eq!(
        ctx.engine_version_hint, hint,
        "the context gates read must see the caller's hint"
    );
}

/// The bare entry points (every pre-#656 call site) stay hint-free, so
/// their parses are unchanged.
#[test]
fn bare_entry_point_carries_no_hint() {
    let pkg = build_minimal_ue4_27();
    let parsed = Package::read_from(&pkg.bytes, None, None, "Game/Fixture.uasset")
        .expect("the minimal fixture parses");
    assert_eq!(
        parsed.context().engine_version_hint,
        None,
        "an unhinted read must stay unhinted"
    );
    // …and is byte-for-byte the same parse as an explicitly empty
    // options set.
    let via_opts = parse_with(&ReadOptions::new());
    assert_eq!(
        parsed.exports.exports.len(),
        via_opts.exports.exports.len(),
        "ReadOptions::new() is the bare path"
    );
    assert_eq!(via_opts.context().engine_version_hint, None);
}

/// `ReadOptions` composes: mappings and the hint are independent, so
/// setting one never clears the other. (Regression guard for a builder
/// that returns `Self::default()` with a single field set.)
#[test]
fn read_options_fields_are_independent() {
    let hint = UeVersion::parse_lenient("4.27");
    let opts = ReadOptions::new().with_engine_version_hint(hint);
    assert_eq!(opts.engine_version_hint, hint);
    assert!(opts.mappings.is_none());

    // Setting mappings afterwards must preserve the hint.
    let usmap: Option<&Arc<paksmith_core::asset::Usmap>> = None;
    let opts = opts.with_mappings(usmap);
    assert_eq!(
        opts.engine_version_hint, hint,
        "with_mappings must not clear the hint"
    );
}

/// The container entry point carries the hint too — the path the CLI's
/// `inspect`/`extract` actually take.
#[test]
fn container_entry_point_carries_the_hint() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/real_v8b_uasset.pak");
    let reader = paksmith_core::container::open(&path, None).expect("fixture pak opens");
    let hint = UeVersion::parse_lenient("5.3");
    let pkg = Package::read_from_reader_with(
        &reader,
        "Game/Maps/Demo.uasset",
        &ReadOptions::new().with_engine_version_hint(hint),
    )
    .expect("fixture asset parses");
    assert_eq!(pkg.context().engine_version_hint, hint);
}

/// A hint never rescues a genuinely broken package: it refines version
/// gates, it does not relax validation.
#[test]
fn hint_does_not_soften_a_malformed_package() {
    let hint = UeVersion::parse_lenient("5.3");
    let err = Package::read_from_with(
        &[0u8; 32],
        None,
        &ReadOptions::new().with_engine_version_hint(hint),
        "Game/Bad.uasset",
    )
    .expect_err("garbage must still fail");
    assert!(
        matches!(err, PaksmithError::AssetParse { .. }),
        "got {err:?}"
    );
}
