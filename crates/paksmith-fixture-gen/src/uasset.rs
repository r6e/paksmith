//! Synthetic UAsset fixture generator + parser cross-validation.
//!
//! Mirrors the trumank/repak cross-parser pattern: every uasset this
//! module emits is parsed back through `unreal_asset` (AstroTechies)
//! to catch bugs that would otherwise pass paksmith's
//! generator-and-parser-share-the-bug blind spot.

use std::fs;
use std::fs::File;
use std::path::Path;

use paksmith_core::asset::Package;
use paksmith_core::testing::uasset::{MinimalPackage, build_minimal_ue4_27};
use repak::{PakBuilder, Version};

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

/// Emit `tests/fixtures/real_v8b_uasset.pak` — a synthetic v8b pak
/// containing one uncompressed entry, the minimal UE 4.27 uasset.
///
/// Uses `repak::PakBuilder` directly (mirroring the existing
/// `write_fixture` helper in `main.rs`) rather than the data-driven
/// `Fixture` table, because the uasset payload is paksmith-synthesized
/// at runtime — the `Fixture` table assumes `&'static [u8]` payloads.
///
/// Version v8b is the default for Phase 2a's integration test because
/// it's the modern shape (FName-based compression slot table, u32
/// compression byte) — the asset reader is version-independent past
/// the entry-read, so the choice here only matters for the pak layer.
pub fn write_minimal_pak_with_uasset(path: &Path) -> anyhow::Result<()> {
    let MinimalPackage {
        bytes: uasset_bytes,
        ..
    } = build_minimal_ue4_27();

    // Atomic write via .tmp + rename, mirroring `write_fixture`'s
    // crash-safety pattern.
    let tmp = path.with_file_name(format!(
        "{}.tmp",
        path.file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| anyhow::anyhow!("path has no filename: {}", path.display()))?
    ));
    {
        let file = File::create(&tmp)?;
        let mut writer =
            PakBuilder::new().writer(file, Version::V8B, "../../../".to_string(), None);
        writer
            .write_file("Game/Maps/Demo.uasset", false, &uasset_bytes)
            .map_err(|e| anyhow::anyhow!("repak write_file: {e}"))?;
        // `write_index` returns the open file for further use; we
        // discard it here because the file is closed via the enclosing
        // scope's Drop before the atomic rename. Mirrors the
        // `let _ = ...` suppression in `main.rs::write_fixture`.
        let _ = writer
            .write_index()
            .map_err(|e| anyhow::anyhow!("repak write_index: {e}"))?;
    }
    std::fs::rename(&tmp, path)?;

    // Self-test: re-open via repak's reader and assert structural facts.
    // Mirrors `write_minimal_ue4_27`'s parser cross-check pattern — if
    // the just-written pak fails to parse, or its single entry's name
    // doesn't round-trip, fail loudly at generation time rather than
    // burying the bug in a downstream integration test.
    let mut reader_file = File::open(path)?;
    let pak_reader = PakBuilder::new()
        .reader(&mut reader_file)
        .map_err(|e| anyhow::anyhow!("repak reader: {e}"))?;
    let files = pak_reader.files();
    anyhow::ensure!(
        files.len() == 1,
        "expected 1 entry in {}, got {}",
        path.display(),
        files.len()
    );
    anyhow::ensure!(
        files[0] == "Game/Maps/Demo.uasset",
        "expected entry path 'Game/Maps/Demo.uasset', got '{}'",
        files[0]
    );
    Ok(())
}
