//! UE engine-version constants and the [`AssetVersion`] bundle.
//!
//! Source of truth: UE's `EUnrealEngineObjectUE4Version`,
//! `EUnrealEngineObjectUE5Version`, `EPackageFileTag` enums (in
//! `Engine/Source/Runtime/Core/Public/UObject/ObjectVersion.h` and
//! `ObjectVersionUE5.h`). Each `VER_UE4_*` / `VER_UE5_*` constant
//! below is a wire-format gate — a field is read only when the
//! file's reported version is ≥ the constant.
//!
//! Phase 2a accepts `LegacyFileVersion ∈ {-7, -8, -9}` and
//! `FileVersionUE4 ≥ VER_UE4_NAME_HASHES_SERIALIZED`. Narrower
//! windows can be widened by Phase 2b+ without changing this file's
//! shape; the constants here are stable.
//!
//! ## Wire-format support vs fixture-validated support
//!
//! Paksmith's accepted version range is defined by the `VER_UE4_*` /
//! `VER_UE5_*` gates in this module plus `FIRST_UNSUPPORTED_UE5_VERSION`
//! in [`crate::asset::summary`]. Within that range, the parsers
//! implement CUE4Parse's reader logic.
//!
//! Issue #243 expanded the cross-parser-validated fixture matrix from
//! the original single UE 4.27 cooked fixture to a parameterized
//! 13-fixture suite via
//! [`crate::testing::uasset::MinimalPackageSpec`] / [`crate::testing::uasset::build_minimal`].
//! Each fixture is parsed by paksmith and (where the `unreal_asset`
//! API permits — see the gaps note below) by `unreal_asset`, with
//! field-level disagreement on any per-record scalar surfaced as a
//! test failure.
//!
//! **Cross-parser-oracle-validated** points (`unreal_asset` ACCEPTS
//! the bytes; every wire field paksmith and `unreal_asset` both expose
//! is compared field-by-field):
//!
//! - UE 4.27 cooked canonical (`FileVersionUE4 = 522`,
//!   `PKG_FilterEditorOnly` set) — `tests/fixtures/real_v8b_uasset.pak`
//!   + the matrix `build_minimal_ue4_27` fixture
//! - **UE4 504** — `NAME_HASHES_SERIALIZED` floor (`build_minimal_ue4_504`)
//! - **UE4 507** — `PRELOAD_DEPENDENCIES_IN_COOKED_EXPORTS` gate fires
//!   (`build_minimal_ue4_507`)
//! - **UE4 510** — `ADDED_SEARCHABLE_NAMES` gate fires (PR #230 boundary)
//!   (`build_minimal_ue4_510`)
//! - **UE4 516** — `ADDED_PACKAGE_SUMMARY_LOCALIZATION_ID` gate fires
//!   (cooked, so editor-only side suppresses; `build_minimal_ue4_516`)
//! - **UE5 1010** — `SCRIPT_SERIALIZATION_OFFSET` path (PR #224 fix)
//!   (`build_minimal_ue5_1010`)
//! - **`LegacyFileVersion == -9`** — UE 5.4+ forward-compat (PR #234)
//!   (`build_minimal_ue5_legacy_neg9`)
//! - Shape variations (`build_minimal_multi_import`,
//!   `build_minimal_multi_export`, `build_minimal_engine_branch_nonempty`,
//!   `build_minimal_custom_versions_populated`)
//! - **Licensee engine-version** — `changelist` with bit 31 set
//!   (PR #234) (`build_minimal_licensee_engine_version`)
//!
//! **Paksmith-side-only validated** (paksmith round-trips its own
//! emitted bytes through its own reader; `unreal_asset` has a parser
//! gap that prevents cross-parser comparison):
//!
//! - **UE4 518–519 uncooked** (`OwnerPersistentGuid` window, PR #224
//!   boundary). `unreal_asset`'s `parse_header` does not consume the
//!   editor-only `PersistentGuid` / `OwnerPersistentGuid` fields at
//!   the pinned revision (verified at `unreal_asset/src/asset.rs:
//!   641-644`); the bytes are still correct per CUE4Parse, but the
//!   oracle can't cross-validate them. See the inline
//!   `TODO(unreal_asset API gap)` markers in
//!   `crates/paksmith-fixture-gen/src/uasset.rs`.
//!
//! Even the cross-parser-validated fixtures are **synthetic** — paksmith
//! emits the bytes via its own writer, then both parsers re-read them.
//! A subtle paksmith-side wire-format bug shared between the writer and
//! reader could still pass; the `unreal_asset` cross-check catches the
//! wire-shape disagreement, but a true ground-truth check needs UE-
//! cooked output (real game assets), tracked under a future
//! "fixture-validated against real UE-cooked assets" follow-up (issue
//! #245 / long-term).
//!
//! Some `VER_*` constants are wire-format gates for fields that the
//! Phase 2a header parser doesn't yet consume (Phase 2b+ will wire
//! them in). The module-level `#[expect(dead_code)]` suppresses
//! warnings while constants sit unused; because the form is `expect`
//! (not `allow`), `rustc` raises `unfulfilled_lint_expectations` the
//! moment *every* constant gains a referent, prompting removal of the
//! suppression as the final cleanup nudge.

#![expect(
    dead_code,
    reason = "Module-wide dead_code suppression while some VER_* constants are still \
              waiting on Phase 2b+ consumers. `expect` (not `allow`) surfaces an \
              unfulfilled-lint warning once every constant is referenced, signalling \
              the attribute should be removed."
)]

use serde::Serialize;

/// UE package magic (`'\x9E*\x83\xC1'`). First 4 bytes of every
/// `.uasset` file.
pub const PACKAGE_FILE_TAG: u32 = 0x9E2A_83C1;

/// Byte-swapped magic, used by UE itself for cross-endian detection.
/// Rejected by paksmith — we don't support BE-encoded uassets.
pub const PACKAGE_FILE_TAG_SWAPPED: u32 = 0xC183_2A9E;

/// Phase 2a lower bound for `FileVersionUE4`. Below this, the name
/// table doesn't carry the dual CityHash16 hash pair we require.
/// (UE4.21 = 503, this constant = 504.)
pub(crate) const VER_UE4_NAME_HASHES_SERIALIZED: i32 = 504;

/// UE 4.x: cooked files began emitting the 5 preload-dependency
/// `i32` fields (`first_export_dependency` + 4 dep counts) at the
/// tail of `FObjectExport`. Below this version, the export record
/// terminates before those fields and defaults are `-1` / `0`.
/// Source: CUE4Parse `EUnrealEngineObjectUE4Version`,
/// `ObjectVersion.cs` → `PRELOAD_DEPENDENCIES_IN_COOKED_EXPORTS`.
pub(crate) const VER_UE4_PRELOAD_DEPENDENCIES_IN_COOKED_EXPORTS: i32 = 507;

/// UE 4.x: cooked files began emitting `FObjectExport::TemplateIndex`
/// (a `PackageIndex`). Below this version, the record skips this slot
/// and the parsed value defaults to `PackageIndex::Null`. Source:
/// CUE4Parse `EUnrealEngineObjectUE4Version` → `TemplateIndex_IN_COOKED_EXPORTS`.
pub(crate) const VER_UE4_TEMPLATE_INDEX_IN_COOKED_EXPORTS: i32 = 508;

/// UE 4.x: `FObjectExport::SerialSize` and `SerialOffset` widened
/// from `i32` to `i64`. Below this version, both fields are 32-bit
/// on the wire (we widen to `i64` in memory). Source: CUE4Parse
/// `EUnrealEngineObjectUE4Version` → `e64BIT_EXPORTMAP_SERIALSIZES`.
pub(crate) const VER_UE4_64BIT_EXPORTMAP_SERIALSIZES: i32 = 511;

/// UE 4.x: `SearchableNamesOffset` (i32) added to `FPackageFileSummary`.
/// Below this version, the field is absent from the wire stream and
/// CUE4Parse defaults it to `0`. Source: CUE4Parse
/// `EUnrealEngineObjectUE4Version` (ObjectVersion.cs) →
/// `ADDED_SEARCHABLE_NAMES`. Note the enum doc-comment "Added
/// SearchableNames to the package summary and asset registry" — the
/// gate applies in both places.
pub(crate) const VER_UE4_ADDED_SEARCHABLE_NAMES: i32 = 510;

/// UE 4.x: `LocalizationId` FString added to the package summary
/// (editor-only — present only when `PKG_FilterEditorOnly` is NOT set).
pub(crate) const VER_UE4_ADDED_PACKAGE_SUMMARY_LOCALIZATION_ID: i32 = 516;

/// UE 4.x: `PackageOwner` machinery added — `FPackageFileSummary`
/// now emits an editor-only `PersistentGuid` (gated on
/// `!PKG_FilterEditorOnly`). Below this version, neither
/// `PersistentGuid` nor `OwnerPersistentGuid` is on the wire.
/// Source: CUE4Parse `EUnrealEngineObjectUE4Version` →
/// `ADDED_PACKAGE_OWNER`.
pub(crate) const VER_UE4_ADDED_PACKAGE_OWNER: i32 = 518;

/// UE 4.x: `OwnerPersistentGuid` retired (was added at 518, removed
/// here at 520). At versions in `[ADDED_PACKAGE_OWNER (518),
/// NON_OUTER_PACKAGE_IMPORT (520))` with `!PKG_FilterEditorOnly`,
/// `FPackageFileSummary` emits a second editor-only `FGuid` slot
/// right after `PersistentGuid`. Also gates editor-only
/// `FObjectImport.PackageName` per CUE4Parse: at `Ar.Ver >=
/// VER_UE4_NON_OUTER_PACKAGE_IMPORT && !Ar.IsFilterEditorOnly`,
/// imports carry an extra `PackageName` FName that paksmith's
/// import reader doesn't consume. Task 9's `PackageSummary` uses
/// this constant to enforce cooked-only input.
pub(crate) const VER_UE4_NON_OUTER_PACKAGE_IMPORT: i32 = 520;

/// UE 5.0+: enables stripping names not referenced from export data —
/// a name-table optimisation. Gates `names_referenced_from_export_data_count`
/// in the summary.
pub(crate) const VER_UE5_NAMES_REFERENCED_FROM_EXPORT_DATA: i32 = 1001;

/// UE 5.0+: `payload_toc_offset` (i64) added to the summary.
pub(crate) const VER_UE5_PAYLOAD_TOC: i32 = 1002;

/// UE 5.0+: `bImportOptional` (i32 bool, NOT u8) appended to
/// `FObjectImport`; `generate_public_hash` (i32 bool) appended to
/// `FObjectExport`.
pub(crate) const VER_UE5_OPTIONAL_RESOURCES: i32 = 1003;

/// UE 5.0+: large-world-coordinates (no wire-format impact for the
/// fields Phase 2a reads).
pub(crate) const VER_UE5_LARGE_WORLD_COORDINATES: i32 = 1004;

/// UE 5.0+: `package_guid` FGuid removed from `FObjectExport`.
/// Below this version, the export carries 16 GUID bytes; at or above,
/// it does not.
pub(crate) const VER_UE5_REMOVE_OBJECT_EXPORT_PACKAGE_GUID: i32 = 1005;

/// UE 5.0+: `is_inherited_instance` (i32 bool) added to `FObjectExport`.
pub(crate) const VER_UE5_TRACK_OBJECT_EXPORT_IS_INHERITED: i32 = 1006;

/// UE 5.0+: `SoftObjectPath` list added to the summary
/// (`soft_object_paths_count` + `soft_object_paths_offset`).
pub(crate) const VER_UE5_ADD_SOFTOBJECTPATH_LIST: i32 = 1008;

/// UE 5.0+: `data_resource_offset` (i32) added to the summary.
pub(crate) const VER_UE5_DATA_RESOURCES: i32 = 1009;

/// UE 5.0+: per-export `ScriptSerializationStartOffset` and
/// `ScriptSerializationEndOffset` (both `i64`) added to
/// `FObjectExport` for saved, versioned packages. The fields are
/// emitted only when `!PKG_UnversionedProperties` AND
/// `FileVersionUE5 >= SCRIPT_SERIALIZATION_OFFSET`. Source:
/// CUE4Parse `EUnrealEngineObjectUE5Version` (ObjectVersion.cs) →
/// `SCRIPT_SERIALIZATION_OFFSET`.
pub(crate) const VER_UE5_SCRIPT_SERIALIZATION_OFFSET: i32 = 1010;

/// Resolved version snapshot for one parsed asset. Threaded by `&` or
/// `Copy` into every downstream parser. Cheap to copy (5 × i32).
///
/// `Default` returns the zero version (legacy=0, ue4=0, ue5=None,
/// licensee=0) — useful only for test fixtures that don't exercise
/// version-gated branches. Real callers must construct explicitly via
/// `PackageSummary::read_from`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub struct AssetVersion {
    /// The `LegacyFileVersion` field from the start of the summary.
    /// Phase 2a accepts `-7` (UE 4.21–4.27), `-8` (UE 5.0–5.3), and
    /// `-9` (UE 5.4+).
    pub legacy_file_version: i32,
    /// `FileVersionUE4` (`EUnrealEngineObjectUE4Version`).
    pub file_version_ue4: i32,
    /// `FileVersionUE5`. `None` when `legacy_file_version > -8`.
    pub file_version_ue5: Option<i32>,
    /// `FileVersionLicenseeUE4` (project-specific licensee version).
    pub file_version_licensee_ue4: i32,
}

impl AssetVersion {
    /// True iff the asset's reported version is ≥ `floor` for UE4.
    #[must_use]
    pub fn ue4_at_least(self, floor: i32) -> bool {
        self.file_version_ue4 >= floor
    }

    /// True iff the asset's reported UE5 version is ≥ `floor`.
    /// Returns `false` when no UE5 version is present (pre-UE5 asset).
    #[must_use]
    pub fn ue5_at_least(self, floor: i32) -> bool {
        self.file_version_ue5.is_some_and(|v| v >= floor)
    }
}
