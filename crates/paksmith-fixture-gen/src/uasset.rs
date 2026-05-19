//! Synthetic UAsset fixture generator + parser cross-validation.
//!
//! Mirrors the trumank/repak cross-parser pattern: every uasset this
//! module emits is parsed back through `unreal_asset` (AstroTechies)
//! to catch bugs that would otherwise pass paksmith's
//! generator-and-parser-share-the-bug blind spot.
//!
//! Fixture-generation crate (excluded from default-members): casts
//! between `usize`/`u32`/`i32`/`i64` for wire-format assembly are
//! against test-controlled inputs.
#![allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]

use std::fs;
use std::fs::File;
use std::path::Path;

use paksmith_core::asset::{
    ExportTable, FGuid, FName, ImportTable, NameTable, ObjectExport, ObjectImport, Package,
    PackageIndex,
};
use paksmith_core::testing::uasset::{
    MinimalPackage, MinimalPackageSpec, build_minimal, build_minimal_ue4_27,
};
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
    let parsed = Package::read_from(&bytes, None, None, path.to_string_lossy().as_ref())
        .map_err(|e| anyhow::anyhow!("paksmith re-parse failed: {e}"))?;
    anyhow::ensure!(parsed.names.names.len() == 3, "expected 3 names");
    anyhow::ensure!(parsed.imports.imports.len() == 1, "expected 1 import");
    anyhow::ensure!(parsed.exports.exports.len() == 1, "expected 1 export");

    cross_validate_with_unreal_asset(
        &bytes,
        unreal_asset::engine_version::EngineVersion::VER_UE4_27,
    )?;
    Ok(())
}

/// Parse `bytes` through BOTH paksmith and `unreal_asset` and compare
/// the resulting structures field-by-field.
///
/// Cross-parser agreement on every parsed field is a much stronger
/// signal than the prior 3-count check: if either parser misreads a
/// wire field, the two diverge here and this function returns a
/// diagnostic naming the field + both values. Writer-canonicalization
/// differences (which would defeat a byte-equality oracle) are
/// invisible to this check because both parsers consume the same
/// input bytes.
///
/// API verified against `unreal_asset` revision
/// `f4df5d8e75b1e184832384d1865f0b696b90a614` (2025-11-28, workspace
/// version 0.1.16):
/// - `Asset::new(asset_data, bulk_data, engine_version, mappings)`
///   takes the .uasset reader, an optional .uexp reader, the engine
///   version enum, and an optional `.usmap` mappings file. The
///   constructor performs the parse — no separate `parse_data()`
///   call.
/// - `asset.get_name_map().get_ref().get_name_map_index_list()`
///   returns `&[String]` of parsed names in wire order.
/// - `asset.imports: Vec<Import>` — each [`Import`](unreal_asset::Import)
///   exposes `class_package: FName`, `class_name: FName`,
///   `outer_index: PackageIndex`, `object_name: FName`, `optional:
///   bool`.
/// - `asset.asset_data.exports: Vec<Export<PackageIndex>>`. Every
///   variant satisfies `ExportBaseTrait::get_base_export() ->
///   &BaseExport`, which exposes the wire scalars (`class_index`,
///   `super_index`, `template_index`, `outer_index`, `object_name`,
///   `object_flags: EObjectFlags`, `serial_size`, `serial_offset`,
///   flag bools, `package_guid: Guid`, the four
///   `*_dependencies: Vec<PackageIndex>` lists).
/// - `asset.asset_data.summary: PackageFileSummary` exposes
///   `package_flags: EPackageFlags` (`bits()` for raw u32),
///   `export_count: i32`, `import_count: i32`,
///   `file_licensee_version: i32`, `custom_versions:
///   Vec<CustomVersion>` (each carries `guid: Guid` and
///   `version: i32`).
///
/// Phase 2a's synthetic fixture embeds the export payload bytes
/// directly after `total_header_size`, so `bulk_data` (the `.uexp`
/// reader) is `None`.
///
/// # Documented unreal_asset API gaps
///
/// Some fields paksmith parses are not externally reachable from
/// `unreal_asset` at the pinned revision; those comparisons are
/// skipped with `// TODO(unreal_asset API gap): ...` comments inline
/// below. Skipped today:
/// - `header_offset` (== paksmith's `total_header_size`): private
///   field on `Asset`, no accessor on `ArchiveTrait`.
/// - `engine_version_recorded` / `_compatible` (FEngineVersion):
///   pub field on `Asset`, but the major/minor/patch/build/branch
///   fields are `pub(crate)` — no external getters.
/// - `script_serialization_start_offset` /
///   `script_serialization_end_offset`: not present in
///   `BaseExport`. UE5-only on the wire; UE4.27 fixture has these
///   as `None` on paksmith's side so the gap is moot here.
#[allow(
    clippy::too_many_lines,
    reason = "comparison oracle: every wire field is one ensure! block, and \
              splitting them across helpers would either lose the \
              `ensure!` diagnostic format-string ergonomics or thread \
              paksmith/oracle pairs through helper signatures with no \
              shared structure to extract — the linear shape reads as \
              one comparison checklist"
)]
pub fn cross_validate_with_unreal_asset(
    bytes: &[u8],
    engine_version: unreal_asset::engine_version::EngineVersion,
) -> anyhow::Result<()> {
    use std::io::Cursor;

    use unreal_asset::Asset;
    use unreal_asset::exports::ExportBaseTrait;

    // Parse via unreal_asset (the oracle). The `engine_version` arg is
    // a FALLBACK for unversioned assets — for versioned input (paksmith
    // fixtures emit `FileVersionUE4`/`FileVersionUE5` directly), the wire
    // value overrides the fallback (see unreal_asset's `parse_header`:
    // `self.asset_data.object_version = file_version` on line 564).
    // Callers should still pass an appropriate version close to the
    // fixture's wire version — both for forward-compat if unreal_asset
    // adds wire-required defaults at construction time and for the
    // FEngineVersion-related accessor side-effects of `set_engine_version`.
    let oracle = Asset::new(Cursor::new(bytes), None, engine_version, None)
        .map_err(|e| anyhow::anyhow!("unreal_asset parse failed: {e}"))?;

    // Parse via paksmith (the system under test).
    let pkg = Package::read_from(bytes, None, None, "cross_validate")
        .map_err(|e| anyhow::anyhow!("paksmith parse failed: {e}"))?;

    // 1. Names: count + per-entry string content.
    //
    // unreal_asset stores names as bare `&str` in its NameMap.
    // paksmith stores `FName(Arc<str>)`. Compare the underlying
    // string content directly — the wire-format invariant is that
    // the name pool is a flat list, no implicit number suffix.
    // The name map is reached through a SharedResource guard; cloning
    // each entry into a Vec<String> is cheaper than threading the
    // guard lifetime through the surrounding comparisons (the fixture
    // is tiny — handful of names).
    let oracle_name_map = oracle.get_name_map();
    let oracle_names: Vec<String> = oracle_name_map.get_ref().get_name_map_index_list().to_vec();
    anyhow::ensure!(
        pkg.names.names.len() == oracle_names.len(),
        "name count mismatch: paksmith={}, unreal_asset={}",
        pkg.names.names.len(),
        oracle_names.len()
    );
    for (i, (paksmith_name, oracle_name)) in
        pkg.names.names.iter().zip(oracle_names.iter()).enumerate()
    {
        anyhow::ensure!(
            paksmith_name.as_str() == oracle_name.as_str(),
            "name[{i}] string mismatch: paksmith={:?}, unreal_asset={:?}",
            paksmith_name.as_str(),
            oracle_name
        );
    }

    // 2. Imports: count + per-import resolved field content.
    //
    // paksmith stores raw u32 indices into the name table for the
    // FName fields; resolve via `pkg.names` to compare against
    // unreal_asset's already-resolved FNames. unreal_asset's
    // `outer_index: PackageIndex` is a struct{index: i32}; paksmith's
    // is an enum. Compare via `to_raw()` / `.index` so both sides
    // reduce to the wire `i32`.
    anyhow::ensure!(
        pkg.imports.imports.len() == oracle.imports.len(),
        "import count mismatch: paksmith={}, unreal_asset={}",
        pkg.imports.imports.len(),
        oracle.imports.len()
    );
    for (i, (paksmith_imp, oracle_imp)) in pkg
        .imports
        .imports
        .iter()
        .zip(oracle.imports.iter())
        .enumerate()
    {
        // Bare-content + instance-number cross-check. paksmith's
        // `resolve()` already folds the disambiguator suffix; here we
        // sidestep that and compare the raw name string + number
        // separately so the diagnostic stays unambiguous when the
        // disagreement is on the number rather than the string.
        let paksmith_class_pkg = pkg
            .names
            .get(paksmith_imp.class_package_name)
            .map(|n| n.as_str().to_string())
            .unwrap_or_default();
        let oracle_class_pkg = oracle_imp.class_package.get_owned_content();
        anyhow::ensure!(
            paksmith_class_pkg == oracle_class_pkg,
            "import[{i}].class_package mismatch: paksmith={paksmith_class_pkg:?}, \
             unreal_asset={oracle_class_pkg:?}"
        );
        anyhow::ensure!(
            paksmith_imp.class_package_number as i32 == oracle_imp.class_package.get_number(),
            "import[{i}].class_package_number mismatch: paksmith={}, unreal_asset={}",
            paksmith_imp.class_package_number,
            oracle_imp.class_package.get_number()
        );

        let paksmith_class_name = pkg
            .names
            .get(paksmith_imp.class_name)
            .map(|n| n.as_str().to_string())
            .unwrap_or_default();
        let oracle_class_name = oracle_imp.class_name.get_owned_content();
        anyhow::ensure!(
            paksmith_class_name == oracle_class_name,
            "import[{i}].class_name mismatch: paksmith={paksmith_class_name:?}, \
             unreal_asset={oracle_class_name:?}"
        );
        anyhow::ensure!(
            paksmith_imp.class_name_number as i32 == oracle_imp.class_name.get_number(),
            "import[{i}].class_name_number mismatch: paksmith={}, unreal_asset={}",
            paksmith_imp.class_name_number,
            oracle_imp.class_name.get_number()
        );

        anyhow::ensure!(
            paksmith_imp.outer_index.to_raw() == oracle_imp.outer_index.index,
            "import[{i}].outer_index mismatch: paksmith={} (raw {}), unreal_asset={}",
            paksmith_imp.outer_index,
            paksmith_imp.outer_index.to_raw(),
            oracle_imp.outer_index.index
        );

        let paksmith_obj_name = pkg
            .names
            .get(paksmith_imp.object_name)
            .map(|n| n.as_str().to_string())
            .unwrap_or_default();
        let oracle_obj_name = oracle_imp.object_name.get_owned_content();
        anyhow::ensure!(
            paksmith_obj_name == oracle_obj_name,
            "import[{i}].object_name mismatch: paksmith={paksmith_obj_name:?}, \
             unreal_asset={oracle_obj_name:?}"
        );
        anyhow::ensure!(
            paksmith_imp.object_name_number as i32 == oracle_imp.object_name.get_number(),
            "import[{i}].object_name_number mismatch: paksmith={}, unreal_asset={}",
            paksmith_imp.object_name_number,
            oracle_imp.object_name.get_number()
        );

        // `import_optional` is UE5 ≥ 1003 only; for UE4.27 paksmith
        // emits None. unreal_asset defaults the `optional: bool` to
        // false. Treat None as false for the cross-check so the
        // gating asymmetry doesn't false-positive.
        let paksmith_optional = paksmith_imp.import_optional.unwrap_or(false);
        anyhow::ensure!(
            paksmith_optional == oracle_imp.optional,
            "import[{i}].optional mismatch: paksmith={paksmith_optional} (raw \
             {:?}), unreal_asset={}",
            paksmith_imp.import_optional,
            oracle_imp.optional
        );
    }

    // 3. Exports: count + per-export base fields.
    anyhow::ensure!(
        pkg.exports.exports.len() == oracle.asset_data.exports.len(),
        "export count mismatch: paksmith={}, unreal_asset={}",
        pkg.exports.exports.len(),
        oracle.asset_data.exports.len()
    );
    for (i, (paksmith_exp, oracle_exp)) in pkg
        .exports
        .exports
        .iter()
        .zip(oracle.asset_data.exports.iter())
        .enumerate()
    {
        let oracle_base = oracle_exp.get_base_export();

        anyhow::ensure!(
            paksmith_exp.class_index.to_raw() == oracle_base.class_index.index,
            "export[{i}].class_index mismatch: paksmith={} (raw {}), unreal_asset={}",
            paksmith_exp.class_index,
            paksmith_exp.class_index.to_raw(),
            oracle_base.class_index.index
        );
        anyhow::ensure!(
            paksmith_exp.super_index.to_raw() == oracle_base.super_index.index,
            "export[{i}].super_index mismatch: paksmith={} (raw {}), unreal_asset={}",
            paksmith_exp.super_index,
            paksmith_exp.super_index.to_raw(),
            oracle_base.super_index.index
        );
        anyhow::ensure!(
            paksmith_exp.template_index.to_raw() == oracle_base.template_index.index,
            "export[{i}].template_index mismatch: paksmith={} (raw {}), unreal_asset={}",
            paksmith_exp.template_index,
            paksmith_exp.template_index.to_raw(),
            oracle_base.template_index.index
        );
        anyhow::ensure!(
            paksmith_exp.outer_index.to_raw() == oracle_base.outer_index.index,
            "export[{i}].outer_index mismatch: paksmith={} (raw {}), unreal_asset={}",
            paksmith_exp.outer_index,
            paksmith_exp.outer_index.to_raw(),
            oracle_base.outer_index.index
        );

        let paksmith_obj_name = pkg
            .names
            .get(paksmith_exp.object_name)
            .map(|n| n.as_str().to_string())
            .unwrap_or_default();
        let oracle_obj_name = oracle_base.object_name.get_owned_content();
        anyhow::ensure!(
            paksmith_obj_name == oracle_obj_name,
            "export[{i}].object_name mismatch: paksmith={paksmith_obj_name:?}, \
             unreal_asset={oracle_obj_name:?}"
        );
        anyhow::ensure!(
            paksmith_exp.object_name_number as i32 == oracle_base.object_name.get_number(),
            "export[{i}].object_name_number mismatch: paksmith={}, unreal_asset={}",
            paksmith_exp.object_name_number,
            oracle_base.object_name.get_number()
        );

        anyhow::ensure!(
            paksmith_exp.object_flags == oracle_base.object_flags.bits(),
            "export[{i}].object_flags mismatch: paksmith=0x{:08x}, unreal_asset=0x{:08x}",
            paksmith_exp.object_flags,
            oracle_base.object_flags.bits()
        );
        anyhow::ensure!(
            paksmith_exp.serial_size == oracle_base.serial_size,
            "export[{i}].serial_size mismatch: paksmith={}, unreal_asset={}",
            paksmith_exp.serial_size,
            oracle_base.serial_size
        );
        anyhow::ensure!(
            paksmith_exp.serial_offset == oracle_base.serial_offset,
            "export[{i}].serial_offset mismatch: paksmith={}, unreal_asset={}",
            paksmith_exp.serial_offset,
            oracle_base.serial_offset
        );
        anyhow::ensure!(
            paksmith_exp.forced_export == oracle_base.forced_export,
            "export[{i}].forced_export mismatch: paksmith={}, unreal_asset={}",
            paksmith_exp.forced_export,
            oracle_base.forced_export
        );
        anyhow::ensure!(
            paksmith_exp.not_for_client == oracle_base.not_for_client,
            "export[{i}].not_for_client mismatch: paksmith={}, unreal_asset={}",
            paksmith_exp.not_for_client,
            oracle_base.not_for_client
        );
        anyhow::ensure!(
            paksmith_exp.not_for_server == oracle_base.not_for_server,
            "export[{i}].not_for_server mismatch: paksmith={}, unreal_asset={}",
            paksmith_exp.not_for_server,
            oracle_base.not_for_server
        );

        // package_guid: paksmith stores Option<FGuid> (None when the
        // wire gate suppresses the field); unreal_asset stores a
        // bare Guid (defaults to all-zero). Treat None as
        // all-zero-bytes for the cross-check — both are how the
        // "field absent" case shows up.
        let paksmith_guid_bytes: [u8; 16] = paksmith_exp
            .package_guid
            .as_ref()
            .map_or([0u8; 16], |g| *g.as_bytes());
        anyhow::ensure!(
            paksmith_guid_bytes == oracle_base.package_guid.0,
            "export[{i}].package_guid mismatch: paksmith={paksmith_guid_bytes:02x?}, \
             unreal_asset={:02x?}",
            oracle_base.package_guid.0
        );

        // is_inherited_instance, generate_public_hash: UE5-only on
        // paksmith's side (Option<bool>); unreal_asset stores plain
        // bool defaulting to false. None ↔ false for the cross-check.
        let paksmith_is_inherited = paksmith_exp.is_inherited_instance.unwrap_or(false);
        anyhow::ensure!(
            paksmith_is_inherited == oracle_base.is_inherited_instance,
            "export[{i}].is_inherited_instance mismatch: paksmith={paksmith_is_inherited} \
             (raw {:?}), unreal_asset={}",
            paksmith_exp.is_inherited_instance,
            oracle_base.is_inherited_instance
        );
        anyhow::ensure!(
            paksmith_exp.package_flags == oracle_base.package_flags,
            "export[{i}].package_flags mismatch: paksmith=0x{:08x}, unreal_asset=0x{:08x}",
            paksmith_exp.package_flags,
            oracle_base.package_flags
        );
        anyhow::ensure!(
            paksmith_exp.not_always_loaded_for_editor_game
                == oracle_base.not_always_loaded_for_editor_game,
            "export[{i}].not_always_loaded_for_editor_game mismatch: paksmith={}, \
             unreal_asset={}",
            paksmith_exp.not_always_loaded_for_editor_game,
            oracle_base.not_always_loaded_for_editor_game
        );
        anyhow::ensure!(
            paksmith_exp.is_asset == oracle_base.is_asset,
            "export[{i}].is_asset mismatch: paksmith={}, unreal_asset={}",
            paksmith_exp.is_asset,
            oracle_base.is_asset
        );
        let paksmith_gen_hash = paksmith_exp.generate_public_hash.unwrap_or(false);
        anyhow::ensure!(
            paksmith_gen_hash == oracle_base.generate_public_hash,
            "export[{i}].generate_public_hash mismatch: paksmith={paksmith_gen_hash} (raw \
             {:?}), unreal_asset={}",
            paksmith_exp.generate_public_hash,
            oracle_base.generate_public_hash
        );

        // Dependency-list scalars. paksmith stores four flat `i32`
        // counts plus `first_export_dependency`. unreal_asset
        // materialized each as a `Vec<PackageIndex>` whose `.len()`
        // is the count; the offset field is exposed directly.
        //
        // TODO(unreal_asset API gap): below
        // `VER_UE4_PRELOAD_DEPENDENCIES_IN_COOKED_EXPORTS` (507), the
        // 5-i32 preload-dep tail is absent from the wire stream — neither
        // parser reads any bytes for these fields. paksmith defaults
        // `first_export_dependency = -1` (matches CUE4Parse's
        // `EUnrealEngineObjectUE4Version` semantics: "first=-1 means no
        // preload deps"); unreal_asset defaults to `0` (matches its own
        // `BaseExport::default()`). Both are correct for the absent-on-
        // wire case but disagree on the in-memory representation. Skip
        // the comparison at the gate floor — the actual wire bytes are
        // identical (zero of them). See issue #256 (Gap 2).
        if pkg.summary.version.file_version_ue4 >= 507 {
            anyhow::ensure!(
                paksmith_exp.first_export_dependency == oracle_base.first_export_dependency_offset,
                "export[{i}].first_export_dependency mismatch: paksmith={}, unreal_asset={}",
                paksmith_exp.first_export_dependency,
                oracle_base.first_export_dependency_offset
            );
            anyhow::ensure!(
                paksmith_exp.serialization_before_serialization_count as usize
                    == oracle_base
                        .serialization_before_serialization_dependencies
                        .len(),
                "export[{i}].serialization_before_serialization_count mismatch: paksmith={}, \
                 unreal_asset={}",
                paksmith_exp.serialization_before_serialization_count,
                oracle_base
                    .serialization_before_serialization_dependencies
                    .len()
            );
            anyhow::ensure!(
                paksmith_exp.create_before_serialization_count as usize
                    == oracle_base.create_before_serialization_dependencies.len(),
                "export[{i}].create_before_serialization_count mismatch: paksmith={}, \
                 unreal_asset={}",
                paksmith_exp.create_before_serialization_count,
                oracle_base.create_before_serialization_dependencies.len()
            );
            anyhow::ensure!(
                paksmith_exp.serialization_before_create_count as usize
                    == oracle_base.serialization_before_create_dependencies.len(),
                "export[{i}].serialization_before_create_count mismatch: paksmith={}, \
                 unreal_asset={}",
                paksmith_exp.serialization_before_create_count,
                oracle_base.serialization_before_create_dependencies.len()
            );
            anyhow::ensure!(
                paksmith_exp.create_before_create_count as usize
                    == oracle_base.create_before_create_dependencies.len(),
                "export[{i}].create_before_create_count mismatch: paksmith={}, unreal_asset={}",
                paksmith_exp.create_before_create_count,
                oracle_base.create_before_create_dependencies.len()
            );
        }

        // TODO(unreal_asset API gap): script_serialization_start_offset
        // and script_serialization_end_offset are not present on
        // unreal_asset's BaseExport at this revision. UE5-only on the
        // wire (object version ≥ 1010); UE4.27 fixture has both as
        // None on paksmith's side, so this gap costs no coverage here.
    }

    // 4. Summary-level scalars: package_flags, export/import counts.
    //
    // TODO(unreal_asset API gap): `total_header_size` — unreal_asset
    // reads this into a private `header_offset` field with no
    // accessor on `ArchiveTrait`. Cannot cross-compare.
    anyhow::ensure!(
        pkg.summary.package_flags == oracle.asset_data.summary.package_flags.bits(),
        "summary.package_flags mismatch: paksmith=0x{:08x}, unreal_asset=0x{:08x}",
        pkg.summary.package_flags,
        oracle.asset_data.summary.package_flags.bits()
    );
    anyhow::ensure!(
        pkg.summary.export_count == oracle.asset_data.summary.export_count,
        "summary.export_count mismatch: paksmith={}, unreal_asset={}",
        pkg.summary.export_count,
        oracle.asset_data.summary.export_count
    );
    anyhow::ensure!(
        pkg.summary.import_count == oracle.asset_data.summary.import_count,
        "summary.import_count mismatch: paksmith={}, unreal_asset={}",
        pkg.summary.import_count,
        oracle.asset_data.summary.import_count
    );
    anyhow::ensure!(
        pkg.summary.generation_count as usize == oracle.generations.len(),
        "summary.generation_count mismatch: paksmith={}, unreal_asset={}",
        pkg.summary.generation_count,
        oracle.generations.len()
    );
    anyhow::ensure!(
        pkg.summary.package_source == oracle.package_source,
        "summary.package_source mismatch: paksmith=0x{:08x}, unreal_asset=0x{:08x}",
        pkg.summary.package_source,
        oracle.package_source
    );
    anyhow::ensure!(
        pkg.summary.folder_name == oracle.folder_name,
        "summary.folder_name mismatch: paksmith={:?}, unreal_asset={:?}",
        pkg.summary.folder_name,
        oracle.folder_name
    );
    anyhow::ensure!(
        pkg.summary.bulk_data_start_offset == oracle.bulk_data_start_offset,
        "summary.bulk_data_start_offset mismatch: paksmith={}, unreal_asset={}",
        pkg.summary.bulk_data_start_offset,
        oracle.bulk_data_start_offset
    );
    anyhow::ensure!(
        pkg.summary.version.legacy_file_version == oracle.legacy_file_version,
        "summary.legacy_file_version mismatch: paksmith={}, unreal_asset={}",
        pkg.summary.version.legacy_file_version,
        oracle.legacy_file_version
    );

    // 5. Custom versions: subset check (paksmith's wire-parsed set ⊆
    // unreal_asset's set).
    //
    // unreal_asset's reader does NOT report a wire-faithful view of
    // the custom-versions container: after reading the on-wire entries
    // it merges in the engine-default container populated by
    // `set_engine_version` (six entries for VER_UE4_27). paksmith
    // reads exactly what is on the wire and nothing else.
    //
    // A strict count/zip equality therefore fails on any well-formed
    // input where paksmith's wire view differs from unreal_asset's
    // wire+defaults view — including the canonical fixture (paksmith
    // writes 0, unreal_asset reports 6).
    //
    // The actionable cross-check that still catches a paksmith
    // misread of the wire-format custom-versions array is: every
    // (guid, version) pair paksmith parsed must also appear in
    // unreal_asset's reported set. If paksmith hallucinates a bogus
    // version from misaligned wire bytes, that entry's guid is
    // overwhelmingly unlikely to appear in unreal_asset's
    // {wire ∪ defaults} set, so the divergence still surfaces.
    for (i, paksmith_cv) in pkg.summary.custom_versions.versions.iter().enumerate() {
        let paksmith_guid_bytes = *paksmith_cv.guid.as_bytes();
        let matching = oracle
            .asset_data
            .summary
            .custom_versions
            .iter()
            .find(|oracle_cv| oracle_cv.guid.0 == paksmith_guid_bytes);
        match matching {
            Some(oracle_cv) => {
                anyhow::ensure!(
                    paksmith_cv.version == oracle_cv.version,
                    "custom_versions[{i}] version mismatch for guid {:02x?}: paksmith={}, \
                     unreal_asset={}",
                    paksmith_guid_bytes,
                    paksmith_cv.version,
                    oracle_cv.version
                );
            }
            None => anyhow::bail!(
                "custom_versions[{i}] guid {:02x?} appears in paksmith's parse but not in \
                 unreal_asset's set (paksmith parsed {} version(s); unreal_asset reports {})",
                paksmith_guid_bytes,
                pkg.summary.custom_versions.versions.len(),
                oracle.asset_data.summary.custom_versions.len()
            ),
        }
    }

    // TODO(unreal_asset API gap): FEngineVersion fields
    // (major/minor/patch/build/branch) are `pub(crate)` on the
    // pinned revision. paksmith parses these into its own
    // EngineVersion struct; the cross-parser comparison can't read
    // unreal_asset's parsed values back out without upstream
    // accessor support. Skipping this comparison; the comparison
    // above of `legacy_file_version` and `custom_versions` covers
    // adjacent wire fields, so a misread of the engine-version
    // record would still likely surface as a custom-versions /
    // licensee-version divergence one field over.

    Ok(())
}

/// Emit a UE 4.27 uasset with three known primitive properties
/// (`bEnabled = true`, `MaxSpeed = 1500.0`, `ObjectName = "Hero_C"`)
/// to `path`, then cross-validate against `unreal_asset`.
///
/// The cross-parser oracle covers structural-header equivalence only —
/// `unreal_asset`'s NormalExport classifier requires resolved
/// `class_name` strings that match a small allowlist (Level, World,
/// UserDefinedStruct, …, BlueprintGeneratedClass, anything-ending-in-Property,
/// and a default NormalExport fall-through). Synthetic fixtures with
/// `class_name == "Package"` (the canonical cooked-Package import the
/// rest of paksmith's fixtures use) hit the default arm but
/// `NormalExport::from_base` then attempts to walk our `FPropertyTag`
/// stream with its own `Property::new` reader, which carries
/// additional schema/ancestry assumptions (`UnversionedHeader`,
/// `get_class_type_for_ancestry`) that fail on the minimal synthetic
/// shape. The reader's outer `Err(_) => RawExport` fallback then
/// downgrades the variant — making property-level cross-validation
/// against `unreal_asset` impractical at this fixture's complexity.
/// Property-decode correctness is instead pinned by paksmith's own
/// `read_primitive_value`/`read_properties` unit tests and the
/// `minimal_ue4_27_with_properties_decodes_to_tree` round-trip in
/// `testing/uasset.rs`.
pub fn write_minimal_ue4_27_with_properties(path: &Path) -> anyhow::Result<()> {
    use paksmith_core::asset::property::PropertyBag;
    use paksmith_core::testing::uasset::build_minimal_ue4_27_with_properties;

    let MinimalPackage { bytes, .. } = build_minimal_ue4_27_with_properties();
    fs::write(path, &bytes)?;

    // Self-test: paksmith re-parses and decodes the property tree.
    let parsed = Package::read_from(&bytes, None, None, path.to_string_lossy().as_ref())
        .map_err(|e| anyhow::anyhow!("paksmith re-parse failed: {e}"))?;
    anyhow::ensure!(parsed.exports.exports.len() == 1, "expected 1 export");
    match &parsed.payloads[0] {
        PropertyBag::Tree { properties } => {
            anyhow::ensure!(
                properties.len() == 3,
                "paksmith decoded {} properties; expected 3",
                properties.len()
            );
        }
        PropertyBag::Opaque { .. } => {
            anyhow::bail!(
                "paksmith fell back to PropertyBag::Opaque on the property fixture — \
                 the iterator should have decoded the FPropertyTag stream"
            );
        }
        // PropertyBag is `#[non_exhaustive]` to leave room for Phase
        // 2c container variants (Array/Map/Set/Struct). Should one
        // appear here, the fixture builder is producing a payload it
        // shouldn't.
        other => anyhow::bail!("unexpected PropertyBag variant: {other:?}"),
    }

    // Header-level cross-validation (names + imports + exports
    // baseline fields). Property-list cross-validation is skipped per
    // the doc comment above; the paksmith-side decode is pinned by
    // unit tests.
    cross_validate_with_unreal_asset(
        &bytes,
        unreal_asset::engine_version::EngineVersion::VER_UE4_27,
    )?;

    Ok(())
}

/// Emit a UE 4.27 uasset with four known container properties
/// (`Array<Int>` = [10, 20], `Struct<StatStruct>` = {Speed: 600.0},
/// `Map<Str, Int>` = {"alpha" -> 1}, `Set<Name>` = {Tag_A, Tag_B}) to
/// `path`, then cross-validate against `unreal_asset`.
///
/// The cross-parser oracle covers structural-header equivalence only,
/// for the same reasons documented on
/// [`write_minimal_ue4_27_with_properties`] — `unreal_asset`'s
/// `NormalExport::from_base` walks the FPropertyTag stream with its
/// own `Property::new` reader, which carries schema/ancestry
/// assumptions that fail on the minimal synthetic shape and fall
/// through to `RawExport`. Property-decode correctness is pinned by
/// paksmith's own unit tests, `tests/container_integration.rs`, and
/// the re-parse self-test below.
pub fn write_minimal_ue4_27_with_containers(path: &Path) -> anyhow::Result<()> {
    use paksmith_core::asset::property::PropertyBag;
    use paksmith_core::asset::property::primitives::{MapEntry, PropertyValue};
    use paksmith_core::testing::uasset::build_minimal_ue4_27_with_containers;

    let MinimalPackage { bytes, .. } = build_minimal_ue4_27_with_containers();
    fs::write(path, &bytes)?;

    // Self-test: paksmith re-parses and decodes the property tree.
    let parsed = Package::read_from(&bytes, None, None, path.to_string_lossy().as_ref())
        .map_err(|e| anyhow::anyhow!("paksmith re-parse failed: {e}"))?;
    anyhow::ensure!(parsed.exports.exports.len() == 1, "expected 1 export");
    let properties = match &parsed.payloads[0] {
        PropertyBag::Tree { properties } => properties,
        PropertyBag::Opaque { .. } => {
            anyhow::bail!(
                "paksmith fell back to PropertyBag::Opaque on the container fixture — \
                 the iterator should have decoded the FPropertyTag stream"
            );
        }
        other => anyhow::bail!("unexpected PropertyBag variant: {other:?}"),
    };
    anyhow::ensure!(
        properties.len() == 4,
        "paksmith decoded {} properties; expected 4 (Tags, Stats, Lookup, Flags)",
        properties.len()
    );

    let by_name: std::collections::HashMap<&str, &PropertyValue> = properties
        .iter()
        .map(|p| (p.name.as_str(), &p.value))
        .collect();

    let expected_tags = PropertyValue::Array {
        inner_type: "IntProperty".to_string(),
        elements: vec![PropertyValue::Int(10), PropertyValue::Int(20)],
    };
    anyhow::ensure!(
        by_name.get("Tags") == Some(&&expected_tags),
        "Tags decoded mismatch: got {:?}",
        by_name.get("Tags")
    );

    match by_name.get("Stats") {
        Some(PropertyValue::Struct {
            struct_name,
            properties: nested,
        }) => {
            anyhow::ensure!(
                struct_name == "StatStruct",
                "Stats struct_name mismatch: got {struct_name:?}"
            );
            anyhow::ensure!(
                nested.len() == 1,
                "Stats nested property count mismatch: got {}",
                nested.len()
            );
            anyhow::ensure!(
                nested[0].name == "Speed",
                "Stats nested property name mismatch: got {:?}",
                nested[0].name
            );
            anyhow::ensure!(
                nested[0].value == PropertyValue::Float(600.0),
                "Stats.Speed value mismatch: got {:?}",
                nested[0].value
            );
        }
        None => anyhow::bail!("Stats property missing from decoded tree"),
        other => anyhow::bail!("Stats decoded as wrong variant: {other:?}"),
    }

    let expected_lookup = PropertyValue::Map {
        key_type: "StrProperty".to_string(),
        value_type: "IntProperty".to_string(),
        entries: vec![MapEntry {
            key: PropertyValue::Str("alpha".to_string()),
            value: PropertyValue::Int(1),
        }],
    };
    anyhow::ensure!(
        by_name.get("Lookup") == Some(&&expected_lookup),
        "Lookup decoded mismatch: got {:?}",
        by_name.get("Lookup")
    );

    let expected_flags = PropertyValue::Set {
        inner_type: "NameProperty".to_string(),
        elements: vec![
            PropertyValue::Name("Tag_A".to_string()),
            PropertyValue::Name("Tag_B".to_string()),
        ],
    };
    anyhow::ensure!(
        by_name.get("Flags") == Some(&&expected_flags),
        "Flags decoded mismatch: got {:?}",
        by_name.get("Flags")
    );

    // Header-level cross-validation with unreal_asset oracle (names,
    // imports, exports baseline fields). Property-level oracle
    // comparison is skipped per the doc comment.
    cross_validate_with_unreal_asset(
        &bytes,
        unreal_asset::engine_version::EngineVersion::VER_UE4_27,
    )?;

    Ok(())
}

/// Emit a UE 4.27 uasset with six Phase 2d extended-type properties to
/// `path`, then cross-validate the header against `unreal_asset`.
///
/// See `write_minimal_ue4_27_with_properties` for why oracle parity is
/// limited to the header (`unreal_asset`'s `NormalExport` classifier
/// downgrades minimal synthetic exports to `RawExport`, so property-list
/// comparison is impractical at this fixture complexity). Property-decode
/// correctness is pinned by paksmith's own
/// `tests/extended_types_integration.rs`.
pub fn write_minimal_ue4_27_with_extended_types(path: &Path) -> anyhow::Result<()> {
    use paksmith_core::asset::property::PropertyBag;
    use paksmith_core::asset::property::primitives::PropertyValue;
    use paksmith_core::testing::uasset::build_minimal_ue4_27_with_extended_types;

    let MinimalPackage { bytes, .. } = build_minimal_ue4_27_with_extended_types();
    fs::write(path, &bytes)?;

    let parsed = paksmith_core::asset::Package::read_from(
        &bytes,
        None,
        None,
        path.to_string_lossy().as_ref(),
    )
    .map_err(|e| anyhow::anyhow!("paksmith re-parse failed: {e}"))?;
    anyhow::ensure!(parsed.exports.exports.len() == 1, "expected 1 export");
    let properties = match &parsed.payloads[0] {
        PropertyBag::Tree { properties } => properties,
        PropertyBag::Opaque { .. } => anyhow::bail!(
            "paksmith fell back to PropertyBag::Opaque on the extended-types fixture — \
             the iterator should have decoded the FPropertyTag stream"
        ),
        other => anyhow::bail!("unexpected PropertyBag variant: {other:?}"),
    };
    anyhow::ensure!(
        properties.len() == 6,
        "paksmith decoded {} properties; expected 6",
        properties.len()
    );

    let soft = properties
        .iter()
        .find(|p| p.name == "SoftRef")
        .ok_or_else(|| anyhow::anyhow!("SoftRef property missing"))?;
    anyhow::ensure!(
        matches!(&soft.value, PropertyValue::SoftObjectPath { .. }),
        "SoftRef decoded to {:?}; expected SoftObjectPath",
        soft.value
    );

    let tags = properties
        .iter()
        .find(|p| p.name == "Tags")
        .ok_or_else(|| anyhow::anyhow!("Tags property missing"))?;
    anyhow::ensure!(
        matches!(&tags.value, PropertyValue::Array { inner_type, .. } if inner_type == "ByteProperty"),
        "Tags decoded to {:?}; expected Array<ByteProperty>",
        tags.value
    );

    cross_validate_with_unreal_asset(
        &bytes,
        unreal_asset::engine_version::EngineVersion::VER_UE4_27,
    )?;

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
            PakBuilder::new().writer(file, Version::V8B, super::MOUNT_POINT.to_string(), None);
        // In-pak entries can use either the `Content/` or `Game/` root
        // prefix; `Game/` mirrors how UE writes paths in cooked builds
        // (the project's mount root). Every other fixture in this
        // generator uses `Content/...`; this one uses `Game/...` so
        // Task 15's integration test exercises the alternate convention
        // before real-game paks land.
        writer
            .write_file("Game/Maps/Demo.uasset", false, &uasset_bytes)
            .map_err(|e| anyhow::anyhow!("repak write_file: {e}"))?;
        // `write_index` consumes the writer and returns the inner File;
        // `let _` drops it here, closing the file before the rename.
        let _ = writer
            .write_index()
            .map_err(|e| anyhow::anyhow!("repak write_index: {e}"))?;
    }
    fs::rename(&tmp, path)?;

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

/// Write `tests/fixtures/real_v8b_split.pak` — a pak with two entries:
/// - `Game/Maps/Demo.uasset` (header bytes only)
/// - `Game/Maps/Demo.uexp`   (export payload bytes only)
///
/// Cross-validates the split form against `unreal_asset` using its
/// `Asset::new(asset_data, Some(bulk_data), ...)` two-reader API, which
/// is the discriminating check that proves paksmith's concat-and-seek
/// layout assumption matches the reference implementation.
pub fn write_minimal_pak_with_split_uasset(path: &Path) -> anyhow::Result<()> {
    use paksmith_core::testing::uasset::build_minimal_ue4_27_split;

    let (uasset_bytes, uexp_bytes) = build_minimal_ue4_27_split();

    // Cross-validate with unreal_asset before writing the fixture.
    cross_validate_split_with_unreal_asset(&uasset_bytes, &uexp_bytes)?;

    // Atomic write via .tmp + rename, mirroring `write_minimal_pak_with_uasset`.
    let tmp = path.with_file_name(format!(
        "{}.tmp",
        path.file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| anyhow::anyhow!("path has no filename: {}", path.display()))?
    ));
    {
        let file = File::create(&tmp)?;
        let mut writer =
            PakBuilder::new().writer(file, Version::V8B, super::MOUNT_POINT.to_string(), None);
        writer
            .write_file("Game/Maps/Demo.uasset", false, &uasset_bytes)
            .map_err(|e| anyhow::anyhow!("repak write_file uasset: {e}"))?;
        writer
            .write_file("Game/Maps/Demo.uexp", false, &uexp_bytes)
            .map_err(|e| anyhow::anyhow!("repak write_file uexp: {e}"))?;
        let _ = writer
            .write_index()
            .map_err(|e| anyhow::anyhow!("repak write_index: {e}"))?;
    }
    fs::rename(&tmp, path)?;

    // Self-test: re-open and assert both entries are present.
    let mut reader_file = File::open(path)?;
    let pak_reader = PakBuilder::new()
        .reader(&mut reader_file)
        .map_err(|e| anyhow::anyhow!("repak reader: {e}"))?;
    let files = pak_reader.files();
    anyhow::ensure!(
        files.len() == 2,
        "expected 2 entries in {}, got {}",
        path.display(),
        files.len()
    );
    anyhow::ensure!(
        files.iter().any(|f| f == "Game/Maps/Demo.uasset"),
        "missing .uasset entry"
    );
    anyhow::ensure!(
        files.iter().any(|f| f == "Game/Maps/Demo.uexp"),
        "missing .uexp entry"
    );
    Ok(())
}

/// Verify the split-form fixture against `unreal_asset`'s two-reader
/// `Asset::new(asset, Some(uexp), ...)` API — the reference parser's
/// dedicated split-asset path. Also re-runs the concat form (header +
/// uexp stitched into one blob, `bulk_data = None`) and asserts both
/// agree on export count. The double check pins paksmith's layout
/// assumption: stitching at `total_header_size` produces a wire-equivalent
/// monolithic blob.
fn cross_validate_split_with_unreal_asset(
    uasset_bytes: &[u8],
    uexp_bytes: &[u8],
) -> anyhow::Result<()> {
    use std::io::Cursor;
    use unreal_asset::Asset;
    use unreal_asset::engine_version::EngineVersion;

    // unreal_asset's Asset::new takes: asset_data reader, optional bulk_data reader
    // (.uexp), engine version, optional .usmap mappings.
    let asset = Asset::new(
        Cursor::new(uasset_bytes.to_vec()),
        Some(Cursor::new(uexp_bytes.to_vec())),
        EngineVersion::VER_UE4_27,
        None,
    )
    .map_err(|e| anyhow::anyhow!("unreal_asset split parse failed: {e}"))?;

    let name_count = asset
        .get_name_map()
        .get_ref()
        .get_name_map_index_list()
        .len();
    anyhow::ensure!(
        name_count == 3,
        "unreal_asset saw {name_count} names in split fixture; expected 3"
    );
    anyhow::ensure!(
        asset.imports.len() == 1,
        "unreal_asset saw {} imports in split fixture; expected 1",
        asset.imports.len()
    );
    anyhow::ensure!(
        asset.asset_data.exports.len() == 1,
        "unreal_asset saw {} exports in split fixture; expected 1",
        asset.asset_data.exports.len()
    );

    // Also verify the monolithic concat form gives the same result.
    let combined: Vec<u8> = [uasset_bytes, uexp_bytes].concat();
    let asset_concat = Asset::new(
        Cursor::new(combined),
        None, // monolithic — no separate bulk_data
        EngineVersion::VER_UE4_27,
        None,
    )
    .map_err(|e| anyhow::anyhow!("unreal_asset concat-form parse failed: {e}"))?;

    anyhow::ensure!(
        asset_concat.asset_data.exports.len() == asset.asset_data.exports.len(),
        "split form and concat form export counts differ"
    );

    Ok(())
}

/// Parameterized synthesizer for bench fixtures.
///
/// Builds a UE 4.27-shape uasset with `name_count` distinct names,
/// `import_count` imports, `export_count` exports, and a
/// `payload_size`-byte opaque payload per export. The output is
/// deterministic given the inputs: same arguments produce
/// byte-identical bytes across runs, so cached fixtures under
/// `target/bench-fixtures/` are reproducible.
///
/// Sizing is the caller's responsibility:
///
/// | Tier   | names | imports | exports | payload | approx total |
/// |--------|-------|---------|---------|---------|--------------|
/// | Tiny   |     3 |       1 |       1 |     16B |         447B |
/// | Small  |    50 |      20 |       5 |    1KiB |       ~10KiB |
/// | Medium |   500 |     200 |      50 |   20KiB |        ~1MiB |
/// | Large  |  2000 |    1000 |     200 |  500KiB |      ~100MiB |
///
/// The bench's lazy-cache scheme keys the cached file by these four
/// inputs so the same `(name_count, import_count, export_count,
/// payload_size)` tuple regenerates exactly once per `target/` tree.
///
/// # Field-pointer cycling
///
/// Every FName index on the imports/exports cycles through the names
/// pool via `i % name_count`, so the bytes always satisfy the parser's
/// "all name indices in bounds" invariant. `outer_index` is set to
/// `PackageIndex::Null` on every record — the parser doesn't traverse
/// the outer chain at read time, so this is structurally valid even
/// for benches that exercise the largest tables.
///
/// # Panics
///
/// - If `name_count == 0` (the synthesizer needs at least one name to
///   point class/object references at; cycling with `% 0` would
///   divide by zero).
/// - If `name_count`, `import_count`, or `export_count` would overflow
///   `i32` when cast for the wire-format count fields. `u32` inputs
///   accept up to `i32::MAX` (≈ 2.1B); the bench tiers max at ~2000.
/// - Indirectly via [`build_minimal`] on the assembly invariants
///   it checks.
#[must_use]
pub fn synthesize_uasset(
    name_count: u32,
    import_count: u32,
    export_count: u32,
    payload_size: u32,
) -> Vec<u8> {
    assert!(
        name_count > 0,
        "synthesize_uasset: name_count must be > 0 (need at least 1 name to point references at)"
    );

    // Build a names pool of distinct strings. Format pins the index in
    // the name so a divergence in the names array surfaces obviously
    // in any hex-dump. The 0th name doubles as the class_package /
    // object_name target for every reference, mirroring the canonical
    // fixture's "Default__Object" shape.
    let names = NameTable {
        names: (0..name_count)
            .map(|i| FName::new(&format!("Name_{i}")))
            .collect(),
    };

    // Imports point class_package / class_name / object_name at
    // cycling slots in the names pool so larger benches exercise more
    // of the table. outer_index = Null on every import — the parser
    // doesn't walk the outer chain at read time, so a flat shape is
    // structurally valid.
    let imports = ImportTable {
        imports: (0..import_count)
            .map(|i| ObjectImport {
                class_package_name: i % name_count,
                class_package_number: 0,
                class_name: (i + 1) % name_count,
                class_name_number: 0,
                outer_index: PackageIndex::Null,
                object_name: (i + 2) % name_count,
                object_name_number: 0,
                import_optional: None,
            })
            .collect(),
    };

    let payload: Vec<u8> = vec![
        0xAA;
        usize::try_from(payload_size)
            .expect("payload_size fits in usize on this platform")
    ];
    let payload_len_i64 =
        i64::try_from(payload.len()).expect("payload_size fits in i64 — u32::MAX < i64::MAX");

    let exports = ExportTable {
        exports: (0..export_count)
            .map(|i| ObjectExport {
                // First import is a reasonable class anchor when
                // import_count > 0; fall back to a Null class when the
                // bench is exports-only (a degenerate but valid shape).
                class_index: if import_count > 0 {
                    PackageIndex::Import(0)
                } else {
                    PackageIndex::Null
                },
                super_index: PackageIndex::Null,
                template_index: PackageIndex::Null,
                outer_index: PackageIndex::Null,
                object_name: i % name_count,
                object_name_number: 0,
                object_flags: 0,
                serial_size: payload_len_i64,
                serial_offset: 0,
                forced_export: false,
                not_for_client: false,
                not_for_server: false,
                package_guid: Some(FGuid::from_bytes([0u8; 16])),
                is_inherited_instance: None,
                package_flags: 0,
                not_always_loaded_for_editor_game: false,
                is_asset: true,
                generate_public_hash: None,
                script_serialization_start_offset: None,
                script_serialization_end_offset: None,
                first_export_dependency: -1,
                serialization_before_serialization_count: 0,
                create_before_serialization_count: 0,
                serialization_before_create_count: 0,
                create_before_create_count: 0,
            })
            .collect(),
    };

    // Each export gets its own clone of the payload bytes — the
    // builder's offset patching layers them sequentially in wire
    // order.
    let payloads: Vec<Vec<u8>> = (0..export_count).map(|_| payload.clone()).collect();

    let spec = MinimalPackageSpec {
        names,
        imports,
        exports,
        payloads,
        ..MinimalPackageSpec::default()
    };
    let MinimalPackage { bytes, .. } = build_minimal(spec);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the canonical-fixture smoke check on the cross-parser
    /// oracle outside `cargo run`.
    ///
    /// `cargo run -p paksmith-fixture-gen` already exercises the
    /// oracle as a side effect of regenerating fixtures, but the
    /// generator binary only runs on demand. A test-target invocation
    /// keeps the oracle in the default `cargo test` matrix so that
    /// any future change to either parser surfaces here, not just on
    /// the next fixture-regen.
    ///
    /// Note on a deliberate gap: the original plan called for a
    /// mutation-based regression test (e.g. flip a byte inside a
    /// name and expect the oracle to flag the divergence). That test
    /// was prototyped and dropped — because both parsers consume the
    /// same input bytes, a mutation that keeps both parsers accepting
    /// the input causes them to agree on the new (mutated) parse, not
    /// disagree. Constructing a deterministic mutation that survives
    /// in one parser but flips a field in the other requires an
    /// actual wire-format bug to exploit; without one, the test is
    /// not constructible. The smoke test below is the available
    /// signal — the canonical fixture must pass the upgraded oracle.
    #[test]
    fn oracle_accepts_canonical_minimal_ue4_27_fixture() {
        let MinimalPackage { bytes, .. } = build_minimal_ue4_27();
        cross_validate_with_unreal_asset(
            &bytes,
            unreal_asset::engine_version::EngineVersion::VER_UE4_27,
        )
        .expect("upgraded oracle must accept the canonical minimal UE 4.27 fixture");
    }

    // ---- Issue #243 boundary fixtures ----

    /// UE4 504 (`NAME_HASHES_SERIALIZED` floor) round-trips through
    /// the oracle. Pre-preload-deps (507), pre-template-index (508),
    /// pre-64bit-serial-sizes (511), pre-searchable-names (510): the
    /// most heavily-gated UE4 boundary. Independent verification that
    /// paksmith's reader agrees with `unreal_asset` on every field at
    /// the lowest accepted version.
    #[test]
    fn oracle_accepts_ue4_504_fixture() {
        use paksmith_core::testing::uasset::build_minimal_ue4_504;
        let MinimalPackage { bytes, .. } = build_minimal_ue4_504();
        cross_validate_with_unreal_asset(
            &bytes,
            unreal_asset::engine_version::EngineVersion::VER_UE4_12,
        )
        .expect("oracle must accept the UE4 504 boundary fixture");
    }

    /// UE4 507 — `PRELOAD_DEPENDENCIES_IN_COOKED_EXPORTS` gate fires.
    #[test]
    fn oracle_accepts_ue4_507_fixture() {
        use paksmith_core::testing::uasset::build_minimal_ue4_507;
        let MinimalPackage { bytes, .. } = build_minimal_ue4_507();
        cross_validate_with_unreal_asset(
            &bytes,
            unreal_asset::engine_version::EngineVersion::VER_UE4_14,
        )
        .expect("oracle must accept the UE4 507 boundary fixture");
    }

    /// UE4 510 — `ADDED_SEARCHABLE_NAMES` gate fires (PR #230 boundary).
    #[test]
    fn oracle_accepts_ue4_510_fixture() {
        use paksmith_core::testing::uasset::build_minimal_ue4_510;
        let MinimalPackage { bytes, .. } = build_minimal_ue4_510();
        cross_validate_with_unreal_asset(
            &bytes,
            unreal_asset::engine_version::EngineVersion::VER_UE4_15,
        )
        .expect("oracle must accept the UE4 510 boundary fixture");
    }

    /// UE4 516 — `ADDED_PACKAGE_SUMMARY_LOCALIZATION_ID` gate fires
    /// (cooked, so the localization-id field is still suppressed by
    /// the editor-only side of the gate).
    #[test]
    fn oracle_accepts_ue4_516_fixture() {
        use paksmith_core::testing::uasset::build_minimal_ue4_516;
        let MinimalPackage { bytes, .. } = build_minimal_ue4_516();
        cross_validate_with_unreal_asset(
            &bytes,
            unreal_asset::engine_version::EngineVersion::VER_UE4_19,
        )
        .expect("oracle must accept the UE4 516 boundary fixture");
    }

    // build_minimal_ue4_519_uncooked oracle test omitted by design.
    //
    // TODO(unreal_asset API gap): unreal_asset's `parse_header`
    // (asset.rs:641-644 at the pinned rev f4df5d8) reads the always-
    // present 16-byte `package_guid` and IMMEDIATELY reads
    // `generations_count`, never consuming the editor-only
    // `PersistentGuid` + `OwnerPersistentGuid` fields that CUE4Parse
    // emits at UE4 ≥ 518 with `!PKG_FilterEditorOnly`. The 32 bytes of
    // the two GUIDs cause unreal_asset to interpret the first 4 bytes
    // of `PersistentGuid` as `generations_count` and bail with
    // "Invalid string size <random>".
    //
    // paksmith's writer is correct (verified against CUE4Parse
    // `FPackageFileSummary.cs` HEAD lines 326-343 and the existing
    // `persistent_guid_and_owner_round_trip_in_addition_window` test in
    // `crates/paksmith-core/src/asset/summary.rs`). The paksmith-side
    // round-trip in `matrix_fixtures_round_trip_through_paksmith` (in
    // paksmith-core's testing module) covers this fixture. Tracked in
    // issue #256 (Gap 1) for upstream-fix or workaround follow-up.

    /// UE5 1010 — `SCRIPT_SERIALIZATION_OFFSET` path (PR #224 fix).
    /// Both per-export i64s are on the wire under
    /// `!PKG_UnversionedProperties`. paksmith-side parses these;
    /// `unreal_asset` has an API gap (the fields aren't reachable on
    /// `BaseExport`) — the oracle skips that comparison per the
    /// existing `TODO(unreal_asset API gap):` marker. The oracle still
    /// validates every OTHER per-export field.
    #[test]
    fn oracle_accepts_ue5_1010_fixture() {
        use paksmith_core::testing::uasset::build_minimal_ue5_1010;
        let MinimalPackage { bytes, .. } = build_minimal_ue5_1010();
        cross_validate_with_unreal_asset(
            &bytes,
            unreal_asset::engine_version::EngineVersion::VER_UE5_2,
        )
        .expect("oracle must accept the UE5 1010 SCRIPT_SERIALIZATION_OFFSET fixture");
    }

    /// UE5 `legacy_file_version = -9` (UE 5.4+ forward-compat,
    /// PR #234). Same wire shape as UE5 1010 for paksmith's accepted
    /// ceiling (PACKAGE_SAVED_HASH at UE5 1015 is above the ceiling).
    #[test]
    fn oracle_accepts_ue5_legacy_neg9_fixture() {
        use paksmith_core::testing::uasset::build_minimal_ue5_legacy_neg9;
        let MinimalPackage { bytes, .. } = build_minimal_ue5_legacy_neg9();
        cross_validate_with_unreal_asset(
            &bytes,
            unreal_asset::engine_version::EngineVersion::VER_UE5_2,
        )
        .expect("oracle must accept the UE5 legacy=-9 fixture");
    }

    // ---- Issue #243 shape variation fixtures (UE 4.27) ----

    /// 5-import chain — `outer_index` traversal under multi-record
    /// load.
    #[test]
    fn oracle_accepts_multi_import_fixture() {
        use paksmith_core::testing::uasset::build_minimal_multi_import;
        let MinimalPackage { bytes, .. } = build_minimal_multi_import();
        cross_validate_with_unreal_asset(
            &bytes,
            unreal_asset::engine_version::EngineVersion::VER_UE4_27,
        )
        .expect("oracle must accept the multi-import fixture");
    }

    /// 5-export chain — `outer_index` traversal + multi-payload
    /// `serial_offset` patching.
    #[test]
    fn oracle_accepts_multi_export_fixture() {
        use paksmith_core::testing::uasset::build_minimal_multi_export;
        let MinimalPackage { bytes, .. } = build_minimal_multi_export();
        cross_validate_with_unreal_asset(
            &bytes,
            unreal_asset::engine_version::EngineVersion::VER_UE4_27,
        )
        .expect("oracle must accept the multi-export fixture");
    }

    /// Non-empty engine-version branch FString — exercises the
    /// branch-FString read path under a real value.
    #[test]
    fn oracle_accepts_engine_branch_nonempty_fixture() {
        use paksmith_core::testing::uasset::build_minimal_engine_branch_nonempty;
        let MinimalPackage { bytes, .. } = build_minimal_engine_branch_nonempty();
        cross_validate_with_unreal_asset(
            &bytes,
            unreal_asset::engine_version::EngineVersion::VER_UE4_27,
        )
        .expect("oracle must accept the engine-branch-nonempty fixture");
    }

    /// Custom-version container with 3 known plugin GUIDs. Stress-
    /// tests the multi-record `CustomVersionContainer` wire path
    /// under cross-parser load.
    #[test]
    fn oracle_accepts_custom_versions_populated_fixture() {
        use paksmith_core::testing::uasset::build_minimal_custom_versions_populated;
        let MinimalPackage { bytes, .. } = build_minimal_custom_versions_populated();
        cross_validate_with_unreal_asset(
            &bytes,
            unreal_asset::engine_version::EngineVersion::VER_UE4_27,
        )
        .expect("oracle must accept the custom-versions-populated fixture");
    }

    // build_minimal_persistent_guid_nonzero oracle test omitted by
    // design — same `unreal_asset` parser gap as
    // `build_minimal_ue4_519_uncooked` (PersistentGuid +
    // OwnerPersistentGuid not consumed). See the comment block above
    // that fixture for the root-cause analysis. Paksmith-side round-
    // trip in `matrix_fixtures_round_trip_through_paksmith` covers it.

    // ---- Issue #243 licensee fixture (PR #234) ----

    /// Engine-version with licensee bit set on `changelist`. The
    /// oracle's cross-validator has a documented `unreal_asset` API
    /// gap on `engine_version_recorded` / `_compatible` (`pub(crate)`
    /// fields) — the oracle still ACCEPTS the bytes; the licensee-
    /// specific assertions live in paksmith-side checks below.
    #[test]
    fn oracle_accepts_licensee_engine_version_fixture() {
        use paksmith_core::testing::uasset::build_minimal_licensee_engine_version;
        let MinimalPackage { bytes, .. } = build_minimal_licensee_engine_version();
        cross_validate_with_unreal_asset(
            &bytes,
            unreal_asset::engine_version::EngineVersion::VER_UE4_27,
        )
        .expect("oracle must accept the licensee engine-version fixture");
    }

    /// Paksmith-side assertion that the licensee fixture's
    /// `EngineVersion` round-trips with the high bit preserved on
    /// `changelist` and masked off on `masked_changelist()` /
    /// surfaced separately on `is_licensee_version()`. The cross-
    /// parser oracle's FEngineVersion gap (see
    /// `TODO(unreal_asset API gap)` in `cross_validate_with_unreal_asset`)
    /// means this is the ONLY validation path that proves the wire-
    /// format licensee-bit handling — keep it explicit.
    #[test]
    fn paksmith_parses_licensee_changelist_correctly() {
        use paksmith_core::testing::uasset::build_minimal_licensee_engine_version;
        let MinimalPackage { bytes, .. } = build_minimal_licensee_engine_version();
        let pkg = Package::read_from(&bytes, None, None, "licensee.uasset").unwrap();
        let saved = &pkg.summary.saved_by_engine_version;
        assert!(
            saved.is_licensee_version(),
            "saved_by_engine_version should report licensee bit set, raw changelist=0x{:08x}",
            saved.changelist
        );
        assert_eq!(
            saved.masked_changelist(),
            0x0012_3456,
            "masked_changelist must strip the licensee bit; raw=0x{:08x}",
            saved.changelist
        );
        assert_eq!(
            saved.changelist, 0x8012_3456,
            "raw changelist preserved verbatim"
        );
        // Pin the Display path end-to-end: wire bytes → Package::read_from →
        // EngineVersion::Display must render the masked changelist. Unit
        // tests in asset/engine_version.rs cover the hand-constructed case;
        // this asserts the full wire pipeline matches PR #234's contract.
        assert_eq!(format!("{saved}"), "4.27.2-1193046+++UE4+Release-4.27");
    }

    // ---- Issue #245 bench-fixture synthesis ----

    /// `synthesize_uasset` output must round-trip through paksmith's
    /// parser. Without this test, the bench-fixture synthesis is
    /// untrusted — a silently-broken synthesizer would produce numbers
    /// that don't reflect parsing real wire-format bytes.
    ///
    /// Picks the "small" tier (10 names, 5 imports, 3 exports, 256-byte
    /// payload) — large enough to exercise the cycling index logic +
    /// multi-payload offset patching, small enough to keep the test
    /// fast.
    #[test]
    fn synthesize_uasset_small_round_trips_through_paksmith() {
        let bytes = synthesize_uasset(10, 5, 3, 256);
        let pkg = Package::read_from(&bytes, None, None, "synthesize_uasset_small")
            .expect("paksmith must parse synthesized bench fixture");
        assert_eq!(pkg.names.names.len(), 10, "name count round-trip");
        assert_eq!(pkg.imports.imports.len(), 5, "import count round-trip");
        assert_eq!(pkg.exports.exports.len(), 3, "export count round-trip");
        // Each export's serial_size must match the requested payload
        // size; if the synthesizer mis-set the byte layout, the parser
        // would either misread serial_size or trip its OOB checks.
        for (i, exp) in pkg.exports.exports.iter().enumerate() {
            assert_eq!(
                exp.serial_size, 256,
                "export[{i}].serial_size must round-trip payload size"
            );
        }
    }

    /// Determinism property: same inputs ⇒ byte-identical output.
    /// The lazy-cache scheme in the bench harness relies on this —
    /// without determinism, every `cargo bench` regenerates the
    /// fixture and the cached file's hash drifts.
    #[test]
    fn synthesize_uasset_is_deterministic() {
        let a = synthesize_uasset(50, 20, 5, 1024);
        let b = synthesize_uasset(50, 20, 5, 1024);
        assert_eq!(a, b, "same inputs must produce byte-identical output");
    }
}
