//! Synthetic UAsset fixture generator + parser cross-validation.
//!
//! Mirrors the trumank/repak cross-parser pattern: every uasset this
//! module emits is parsed back through `unreal_asset` (AstroTechies)
//! to catch bugs that would otherwise pass paksmith's
//! generator-and-parser-share-the-bug blind spot.

use std::fs;
use std::path::Path;

use paksmith_core::asset::Package;
use paksmith_core::testing::uasset::{MinimalPackage, build_minimal_ue4_27};

/// Emit a known-good minimal UE 4.27 uasset to `path`.
///
/// Round-trips the result through paksmith's parser and asserts the
/// re-parse matches the source structure. Cross-validates the emitted
/// bytes against `unreal_asset`'s parser (see
/// [`cross_validate_with_unreal_asset`] below).
pub fn write_minimal_ue4_27(path: &Path) -> anyhow::Result<()> {
    let MinimalPackage { bytes, .. } = build_minimal_ue4_27();
    fs::write(path, &bytes)?;

    // Self-test: paksmith re-parses what paksmith wrote.
    let parsed = Package::read_from(&bytes, path.to_string_lossy().as_ref())
        .map_err(|e| anyhow::anyhow!("paksmith re-parse failed: {e}"))?;
    anyhow::ensure!(parsed.names.names.len() == 3, "expected 3 names");
    anyhow::ensure!(parsed.imports.imports.len() == 1, "expected 1 import");
    anyhow::ensure!(parsed.exports.exports.len() == 1, "expected 1 export");

    cross_validate_with_unreal_asset(&bytes)?;
    Ok(())
}

/// Parse `bytes` through `unreal_asset` and assert the structural
/// fields match what paksmith would produce.
///
/// API verified against `unreal_asset` revision
/// `f4df5d8e75b1e184832384d1865f0b696b90a614` (2025-11-28, workspace
/// version 0.1.16):
/// - `Asset::new(asset_data, bulk_data, engine_version, mappings)`
///   takes the .uasset reader, an optional .uexp reader, the engine
///   version enum, and an optional `.usmap` mappings file. The
///   constructor performs the parse — no separate `parse_data()` call.
/// - `asset.imports: Vec<Import>` is a public field.
/// - `asset.asset_data.exports: Vec<Export<PackageIndex>>` is reached
///   through the public `asset_data` field.
/// - `asset.get_name_map().get_ref().get_name_map_index_list()`
///   returns the parsed name list.
///
/// Phase 2a's synthetic fixture embeds the export payload bytes
/// directly after `total_header_size`, so `bulk_data` (the `.uexp`
/// reader) is `None`.
fn cross_validate_with_unreal_asset(bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::Cursor;
    use unreal_asset::Asset;
    use unreal_asset::engine_version::EngineVersion;

    let asset = Asset::new(Cursor::new(bytes), None, EngineVersion::VER_UE4_27, None)
        .map_err(|e| anyhow::anyhow!("unreal_asset parse failed: {e}"))?;

    let name_count = asset
        .get_name_map()
        .get_ref()
        .get_name_map_index_list()
        .len();
    anyhow::ensure!(
        name_count == 3,
        "unreal_asset saw {name_count} names; paksmith wrote 3"
    );
    anyhow::ensure!(
        asset.imports.len() == 1,
        "unreal_asset saw {} imports; paksmith wrote 1",
        asset.imports.len()
    );
    anyhow::ensure!(
        asset.asset_data.exports.len() == 1,
        "unreal_asset saw {} exports; paksmith wrote 1",
        asset.asset_data.exports.len()
    );
    Ok(())
}
