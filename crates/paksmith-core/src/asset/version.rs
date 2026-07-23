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

use serde::{Deserialize, Serialize};

/// UE package magic (`'\x9E*\x83\xC1'`). First 4 bytes of every
/// `.uasset` file.
pub const PACKAGE_FILE_TAG: u32 = 0x9E2A_83C1;

/// Byte-swapped magic, used by UE itself for cross-endian detection.
/// Rejected by paksmith — we don't support BE-encoded uassets.
pub const PACKAGE_FILE_TAG_SWAPPED: u32 = 0xC183_2A9E;

/// UE 4.12 historical gate (file_version_ue4 = 482): when an
/// `ArrayProperty` declares `inner_type == "StructProperty"`, the
/// element stream is preceded by a one-shot `FPropertyTag` header
/// (the "inner-array-tag-info" block) carrying the struct's name,
/// per-element size, struct GUID, and `has_property_guid` flag.
/// Before this version, the same shape used an external
/// per-game `array_struct_type_override` table to discover the
/// struct type — paksmith does not support that path (out of range).
///
/// paksmith's accepted UE4 floor is `VER_UE4_NAME_HASHES_SERIALIZED
/// = 504`, well above this gate; the inner header is structurally
/// always present for in-range versioned `Array<Struct>` reads. The
/// constant exists so Phase 2g's `Array<Struct>` decoder can document
/// the version-gated branch intent in code, even though the
/// false-branch path is unreachable for any asset paksmith accepts.
pub(crate) const VER_UE4_INNER_ARRAY_TAG_INFO: i32 = 500;

/// Phase 2a lower bound for `FileVersionUE4`. Below this, the name
/// table doesn't carry the dual CityHash16 hash pair we require.
///
/// Per CUE4Parse's `EGame`→`FileVersionUE4` map, `504` is `GAME_UE4_12`'s
/// object version (`< GAME_UE4_13 => 504`), so paksmith's UE4 floor is
/// **~UE4.12, NOT UE4.21** — it deliberately parses UE4.13–4.27 cooked
/// assets (see the `build_minimal_ue4_504`/`_516` fixtures, cross-validated
/// against the repak/`unreal_asset` oracle). The few UE 4.20+ wire
/// differences (texture per-mip `SizeZ`, platform-data `skipOffset` width)
/// are gated separately via [`AssetVersion::is_ue4_20_or_later`].
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

/// `ADDED_SOFT_OBJECT_PATH` (`file_version_ue4` 514): `FSoftObjectPath`
/// gains its split `FName AssetPathName` + `FString SubPathString`
/// fields. BELOW this
/// version the payload is a single `FString` that CUE4Parse splits on the
/// last `.` into (asset path, sub-path). paksmith decodes the 514+ shape
/// only; the pre-514 single-`FString` layout is unsupported (see
/// `read_soft_path_payload`) — its split produces a lossy, version-
/// inconsistent decomposition and no in-scope fixture anchors it (#694).
/// Source: CUE4Parse `EUnrealEngineObjectUE4Version::ADDED_SOFT_OBJECT_PATH`
/// (`ObjectVersion.cs`) and `FSoftObjectPath.cs`.
pub(crate) const VER_UE4_ADDED_SOFT_OBJECT_PATH: i32 = 514;

/// UE 4.x: `LocalizationId` FString added to the package summary
/// (editor-only — present only when `PKG_FilterEditorOnly` is NOT set).
pub(crate) const VER_UE4_ADDED_PACKAGE_SUMMARY_LOCALIZATION_ID: i32 = 516;

/// Object-version proxy for CUE4Parse's engine boundary `Ar.Game >=
/// GAME_UE4_20` (`GAME_UE4_20 → FileVersionUE4 516` per the `EGame` map).
/// **Not** a distinct object-version feature — the changes it gates (the
/// texture per-mip `SizeZ` field and the `FTexturePlatformData`
/// `skipOffset` width) are engine-gated in CUE4Parse; this is the closest
/// object-version proxy. `GAME_UE4_19` also maps to `516`, so a genuine
/// UE4.19 asset is indistinguishable and treated as 4.20+ — see
/// [`AssetVersion::is_ue4_20_or_later`]. Coincidentally equal in value to
/// [`VER_UE4_ADDED_PACKAGE_SUMMARY_LOCALIZATION_ID`] (an unrelated feature).
pub(crate) const VER_UE4_GAME_UE4_20_OBJECT_PROXY: i32 = 516;

/// Object-version proxy for CUE4Parse's feature flag
/// `Ar.Versions["VirtualTextures"]` (introduced `Ar.Game >= GAME_UE4_23`),
/// which gates the trailing `bIsVirtual` flag + `FVirtualTextureBuiltData`
/// payload on a `UTexture2D` (`GAME_UE4_23 → FileVersionUE4 517` per the
/// `EGame` map; anchored against the `516`/`GAME_UE4_20` proxy above, one
/// object version higher). **Known imperfection — a wider span than the
/// feature:** per the `EGame` map `FileVersionUE4 517` spans exactly
/// `{GAME_UE4_21, 4.22, 4.23}` (4.24 maps to `518`), so a `>= 517` gate also
/// fires for 4.21/4.22, where VirtualTextures is OFF — those are the **only**
/// two false-positive versions (4.23+ are correct fires). `517` is the unique
/// tightest threshold: 4.23 itself is `517`, so no object-version cutoff can
/// admit 4.23 (feature on) while excluding 4.22 (feature off) — `>= 517` has
/// zero false NEGATIVES, which is the gate's real justification. A genuine
/// 4.21/4.22 (pre-VirtualTextures) cooked texture therefore reads a spurious
/// 4-byte `bIsVirtual` from its trailing bytes — *believed* benign in the
/// common single-platform case (the trailing `None`-FName terminator's `i32`
/// index `0` decodes as `bIsVirtual == 0`), though paksmith has no 4.21/4.22
/// (object `517`) fixture to confirm it; the worst case is fail-loud — a
/// multi-platform-data 4.21/4.22 texture mis-reads a non-zero `bIsVirtual` and
/// degrades to `Generic`. paksmith has no engine version (Phase 5 game
/// profiles), so the object version is the only available proxy; `517` is
/// the closest, same class of over-approximation as the `516`/4.19-4.20
/// collision. See [`AssetVersion::is_virtual_textures_or_later`].
pub(crate) const VER_UE4_GAME_UE4_23_OBJECT_PROXY: i32 = 517;

/// Object-version proxy for CUE4Parse's engine boundary `Ar.Game >=
/// GAME_UE4_25`. Per the `EGame.GetVersion()` first-match map, `FileVersionUE4
/// 518` spans **`GAME_UE4_24` and `GAME_UE4_25`** (`< GAME_UE4_25 => 518`
/// catches 4.24; `< GAME_UE4_26 => 518` catches 4.25), so `>= 518` is the
/// tightest available proxy — exact from 4.25 up, with a **false positive on
/// `GAME_UE4_24`** (4.24 and 4.25 are indistinguishable by object version, like
/// the `517` proxy's 4.21/4.22 false positives). Proxies the stock default of
/// `Ar.Versions["SoundWave.UseAudioStreaming"]` (= `Game >= GAME_UE4_25 &&
/// OverrideUseAudioStreaming()`; the per-game `OverrideUseAudioStreaming`
/// refinement is a Phase-5 game-profile concern). `USoundWave` (3f-2) consults
/// this for its initial `bStreaming` default — a 4.24 false positive (default
/// `true` instead of `false`) is corrected by the 3f-5 streaming-flip retry.
/// Shares the `518` object version with [`VER_UE4_ADDED_PACKAGE_OWNER`] (an
/// unrelated feature at the same boundary). See [`AssetVersion::is_ue4_25_or_later`].
pub(crate) const VER_UE4_GAME_UE4_25_OBJECT_PROXY: i32 = 518;

/// Object-version proxy for CUE4Parse's engine boundary `Ar.Game >=
/// GAME_UE4_27` (`GAME_UE4_27 → FileVersionUE4 522` per the `EGame` map —
/// `522` is the final UE4 object version, and UE5 packages carry it too).
/// Gates `FVirtualTextureDataChunk::CodecPayloadOffset` widening from `u16`
/// (pre-4.27) to `u32` (4.27+/UE5). Anchored two object versions above the
/// `517`/`GAME_UE4_23` proxy. Per the `EGame` first-match map `522` spans
/// `{GAME_UE4_26, GAME_UE4_27}` (`< GAME_UE4_27 => 522` catches 4.26;
/// `GAME_UE4_27 => 522` itself), with the intermediate `519`-`521` unassigned
/// to a stock game. The `is_ue4_27_or_later` proxy therefore over-approximates
/// onto 4.26 (a false positive, like the `517`/`518` proxies). **This false
/// positive is NOT benign for the gated field, and is unrecoverable.**
/// CUE4Parse keys `CodecPayloadOffset` on the *engine* version
/// (`Ar.Game >= GAME_UE4_27 ? u32 : u16`), not the object version — precisely
/// because the `u16`→`u32` widening falls *inside* object version `522`
/// (4.26 and 4.27 both report `522`). An object-version proxy therefore cannot
/// split them: for genuine `GAME_UE4_26` VT content paksmith reads `u32` where
/// CUE4Parse reads `u16`, a 2-byte-per-layer desync with no recovery point.
/// **UNVERIFIED** — paksmith has no `GAME_UE4_26` VT fixture and no
/// engine-version input until Phase 5 game profiles, so whether stock 4.26 VT
/// content is reachable here (and on-disk `u16`) is untested; `>= 522` is the
/// tightest object-version threshold available and is exact from 4.27 up.
/// See [`AssetVersion::is_ue4_27_or_later`].
pub(crate) const VER_UE4_GAME_UE4_27_OBJECT_PROXY: i32 = 522;

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

/// UE 5.1+ (`FSOFTOBJECTPATH_REMOVE_ASSET_PATH_FNAMES`): the leading
/// slot of `FSoftObjectPath` changes from a single `FName AssetPathName`
/// to an `FTopLevelAssetPath` (`FName PackageName` + `FName AssetName`),
/// followed by the unchanged `FString SubPathString`. Source: CUE4Parse
/// `EUnrealEngineObjectUE5Version::FSOFTOBJECTPATH_REMOVE_ASSET_PATH_FNAMES`
/// (`ObjectVersion.cs`) and `FSoftObjectPath.cs` (the
/// `Ar.Ver >= FSOFTOBJECTPATH_REMOVE_ASSET_PATH_FNAMES` branch).
pub(crate) const VER_UE5_FSOFTOBJECTPATH_REMOVE_ASSET_PATH_FNAMES: i32 = 1007;

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

/// UE 5.4+ (`PROPERTY_TAG_EXTENSION_AND_OVERRIDABLE_SERIALIZATION`):
/// the tagged-property wire gains (a) a per-tag `u8`
/// `EPropertyTagExtension` flags byte immediately after the
/// `HasPropertyGuid` byte (+ optional guid), with a conditional
/// 5-byte payload (u8 op + bool32) when `OverridableInformation`
/// (0x02) is set, and
/// (b) a per-OBJECT `u8 EClassSerializationControlExtension` byte
/// before the whole tagged stream of an export root (never before
/// struct-fallback bodies). Never ships standalone: UE releases jump
/// 1009 (5.2/5.3) → 1012 (5.4). Source: CUE4Parse
/// `EUnrealEngineObjectUE5Version` (ObjectVersion.cs), `FPropertyTag.cs`
/// (the `< PROPERTY_TAG_COMPLETE_TYPE_NAME` branch), `UObject.cs`
/// `DeserializePropertiesTagged` (the `!isStruct` pre-byte).
pub(crate) const VER_UE5_PROPERTY_TAG_EXTENSION: i32 = 1011;

/// UE 5.4+ (`PROPERTY_TAG_COMPLETE_TYPE_NAME`): the tag's single
/// `FName` Type (+ per-type extras + standalone `ArrayIndex` +
/// guid-presence byte) is replaced by a recursive
/// `FPropertyTypeName` tree of `(FName, i32 inner_count)` nodes,
/// then `i32 Size`, then a `u8 EPropertyTagFlags` byte whose bits
/// gate `ArrayIndex` / `PropertyGuid` / the 1011 extension byte, with
/// `BoolTrue` replacing the bool payload byte. Also elides the inner
/// `FPropertyTag` of array-of-struct bodies (type data comes from the
/// outer tag's tree). UE 5.4 ships exactly this version. Source:
/// CUE4Parse `FPropertyTag.cs` / `FPropertyTagData.cs` /
/// `UScriptArray.cs`.
pub(crate) const VER_UE5_PROPERTY_TAG_COMPLETE_TYPE_NAME: i32 = 1012;

/// UE 5.5 (`ASSETREGISTRY_PACKAGEBUILDDEPENDENCIES`): changes only
/// the asset-registry data blob (which paksmith does not parse) —
/// zero summary/tag/export wire impact; the constant exists so the
/// ceiling rationale can name what 1013 is. UE 5.5 ships exactly
/// this version. Source: CUE4Parse `EUnrealEngineObjectUE5Version`
/// (referenced nowhere else in that codebase).
pub(crate) const VER_UE5_ASSETREGISTRY_PACKAGEBUILDDEPENDENCIES: i32 = 1013;

/// Resolved version snapshot for one parsed asset. Threaded by `&` or
/// `Copy` into every downstream parser. Cheap to copy (5 × i32).
///
/// `Default` returns the zero version (legacy=0, ue4=0, ue5=None,
/// licensee=0) — useful only for test fixtures that don't exercise
/// version-gated branches. Real callers must construct explicitly via
/// `PackageSummary::read_from`.
// `#[non_exhaustive]` deferred: struct-literal-constructed by
// `paksmith-core-tests::tests::asset_proptest`, `paksmith-fixture-gen`,
// and several `paksmith-core` test fixtures. Adding it requires a
// parallel constructor refactor across those sites.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
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

    /// True iff this asset's UE5 version meets the Large World
    /// Coordinates gate (`VER_UE5_LARGE_WORLD_COORDINATES = 1004`,
    /// crate-private): vector / rotator / transform components are
    /// f64 (24 bytes each for `FVector`) instead of f32 (12 bytes).
    /// Phase 3c decoders consult this to dispatch the per-component
    /// width. Returns `false` for pre-UE5 assets (no
    /// `file_version_ue5`).
    #[must_use]
    pub fn is_lwc(self) -> bool {
        self.ue5_at_least(VER_UE5_LARGE_WORLD_COORDINATES)
    }

    /// True iff the asset carries a UE5 file version (`file_version_ue5` is
    /// present) — i.e. it was cooked by UE5.0 or later. Used by readers that
    /// gate UE5-only wire behaviour (e.g. the Phase 3g `FStaticMeshRenderData`
    /// reader returns geometry-only for UE5.0–5.3, stopping before the
    /// un-decoded `FNaniteResources` tail).
    #[must_use]
    pub fn is_ue5(self) -> bool {
        self.file_version_ue5.is_some()
    }

    /// True iff the asset uses the UE 4.20+ texture-platform-data wire
    /// layout — any UE5 asset, or a UE4 asset at the
    /// `VER_UE4_GAME_UE4_20_OBJECT_PROXY` (`516`, crate-private) boundary or
    /// above.
    ///
    /// CUE4Parse gates the per-mip `SizeZ` field (present iff `Ar.Game >=
    /// GAME_UE4_20`) and the `FTexturePlatformData` `skipOffset` width
    /// (`i64` iff `>= GAME_UE4_20`, else `i32`) on the engine version;
    /// paksmith has no engine version, so it proxies with the object
    /// version. **Known imperfection:** `GAME_UE4_19` and `GAME_UE4_20`
    /// both serialize object version `516`, so a genuine UE4.19 texture is
    /// treated as 4.20+ here (reads `SizeZ` + an `i64` `skipOffset` it
    /// doesn't have → 4-byte desync → the export degrades to `Generic`).
    /// paksmith picks the `516` boundary to parse UE4.20 textures
    /// correctly; the inverse (`517`) would instead misclassify UE4.20.
    /// Used by the `UTexture2D` reader.
    #[must_use]
    pub fn is_ue4_20_or_later(self) -> bool {
        self.file_version_ue5.is_some() || self.ue4_at_least(VER_UE4_GAME_UE4_20_OBJECT_PROXY)
    }

    /// True iff this asset is recent enough to carry the trailing
    /// `UTexture2D` `bIsVirtual` flag (+ optional `FVirtualTextureBuiltData`):
    /// any UE5 asset, or a UE4 asset at the
    /// `VER_UE4_GAME_UE4_23_OBJECT_PROXY` (`517`, crate-private) boundary or
    /// above. Proxies CUE4Parse's `Ar.Versions["VirtualTextures"]` feature
    /// flag (engine boundary `GAME_UE4_23`); see that constant for the
    /// 4.21/4.22 over-approximation caveat. The `UTexture2D` reader consults
    /// this to decide whether to read `bIsVirtual` after the mip records.
    #[must_use]
    pub fn is_virtual_textures_or_later(self) -> bool {
        self.file_version_ue5.is_some() || self.ue4_at_least(VER_UE4_GAME_UE4_23_OBJECT_PROXY)
    }

    /// True iff the asset is UE 4.27+ (or any UE5): any UE5 asset, or a UE4
    /// asset at the `VER_UE4_GAME_UE4_27_OBJECT_PROXY` (`522`, crate-private)
    /// boundary or above. Proxies CUE4Parse's `Ar.Game >= GAME_UE4_27` — the
    /// boundary at which `FVirtualTextureDataChunk::CodecPayloadOffset` widens
    /// from `u16` to `u32`. The `FVirtualTextureDataChunk` reader (3e-VT-b2)
    /// consults this for the per-layer offset width.
    #[must_use]
    pub fn is_ue4_27_or_later(self) -> bool {
        self.file_version_ue5.is_some() || self.ue4_at_least(VER_UE4_GAME_UE4_27_OBJECT_PROXY)
    }

    /// Whether the asset is at the `VER_UE4_GAME_UE4_25_OBJECT_PROXY` (`518`,
    /// crate-private) boundary or above. Proxies CUE4Parse's `Ar.Game >=
    /// GAME_UE4_25` — the stock default of `Ar.Versions["SoundWave.UseAudioStreaming"]`.
    /// `USoundWave` (3f-2) consults this for its initial `bStreaming` default
    /// (overridden by a tagged `bStreaming` / `LoadingBehavior` property, and a
    /// wrong guess is corrected by the 3f-5 streaming-flip retry).
    #[must_use]
    pub fn is_ue4_25_or_later(self) -> bool {
        self.file_version_ue5.is_some() || self.ue4_at_least(VER_UE4_GAME_UE4_25_OBJECT_PROXY)
    }

    /// True iff the asset is UE 4.23+ (or any UE5): any UE5 asset, or a UE4
    /// asset at the `VER_UE4_GAME_UE4_23_OBJECT_PROXY` (`517`, crate-private)
    /// boundary or above. Proxies CUE4Parse's
    /// `Ar.Versions["StaticMesh.UseNewCookedFormat"]` (engine boundary
    /// `GAME_UE4_23`), which selects the per-LOD `bIsLODCookedOut` / `bInlined`
    /// "new cooked" `FStaticMeshLODResources` layout over the pre-4.23 legacy
    /// one. Shares the 4.21/4.22 over-approximation caveat documented on
    /// [`Self::is_virtual_textures_or_later`] (same `517` proxy). The Phase 3g
    /// `FStaticMeshRenderData` reader consults this to select the legacy vs
    /// new-cooked LOD path (`false` → the UNVERIFIED legacy `read_lod_legacy`).
    #[must_use]
    pub fn is_ue4_23_or_later(self) -> bool {
        self.file_version_ue5.is_some() || self.ue4_at_least(VER_UE4_GAME_UE4_23_OBJECT_PROXY)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(ue4: i32, ue5: Option<i32>) -> AssetVersion {
        AssetVersion {
            legacy_file_version: if ue5.is_some() { -8 } else { -7 },
            file_version_ue4: ue4,
            file_version_ue5: ue5,
            file_version_licensee_ue4: 0,
        }
    }

    /// Pair-anchors the UE 5.4/5.5 constants against the two
    /// established neighbours (1009/1010) and each other — the enum is
    /// consecutive in `EUnrealEngineObjectUE5Version`, so any
    /// transcription slip breaks an equality here. #643.
    #[test]
    fn ue54_version_constants_anchor_consecutively() {
        assert_eq!(VER_UE5_DATA_RESOURCES, 1009);
        assert_eq!(VER_UE5_SCRIPT_SERIALIZATION_OFFSET, 1010);
        assert_eq!(
            VER_UE5_PROPERTY_TAG_EXTENSION,
            VER_UE5_SCRIPT_SERIALIZATION_OFFSET + 1
        );
        assert_eq!(
            VER_UE5_PROPERTY_TAG_COMPLETE_TYPE_NAME,
            VER_UE5_PROPERTY_TAG_EXTENSION + 1
        );
        assert_eq!(
            VER_UE5_ASSETREGISTRY_PACKAGEBUILDDEPENDENCIES,
            VER_UE5_PROPERTY_TAG_COMPLETE_TYPE_NAME + 1
        );
    }

    #[test]
    fn is_ue4_20_or_later_pins_the_516_boundary() {
        // 515 is below the GAME_UE4_20 proxy; 516 is at it.
        assert!(!version(515, None).is_ue4_20_or_later());
        assert!(version(VER_UE4_GAME_UE4_20_OBJECT_PROXY, None).is_ue4_20_or_later());
        assert!(version(522, None).is_ue4_20_or_later());
        // The floor (504) is below 4.20.
        assert!(!version(VER_UE4_NAME_HASHES_SERIALIZED, None).is_ue4_20_or_later());
    }

    #[test]
    fn is_ue4_20_or_later_true_for_any_ue5_even_with_low_ue4() {
        // A UE5 asset is always 4.20+ via the `is_some()` branch, even when
        // its UE4 object version is below the 516 proxy.
        assert!(version(400, Some(1009)).is_ue4_20_or_later());
    }

    #[test]
    fn is_ue4_27_or_later_pins_the_522_boundary() {
        // 518 (GAME_UE4_24/25) is below the GAME_UE4_27 proxy; 522 is at it.
        assert!(!version(518, None).is_ue4_27_or_later());
        assert!(version(VER_UE4_GAME_UE4_27_OBJECT_PROXY, None).is_ue4_27_or_later());
        // The 4.23 VirtualTextures proxy (517) is below 4.27.
        assert!(!version(VER_UE4_GAME_UE4_23_OBJECT_PROXY, None).is_ue4_27_or_later());
        // Any UE5 asset is 4.27+ via the is_some() branch.
        assert!(version(400, Some(1009)).is_ue4_27_or_later());
    }

    #[test]
    fn is_ue4_25_or_later_pins_the_518_boundary() {
        // 517 (GAME_UE4_23) is below the GAME_UE4_25 proxy; 518 (4.24/4.25) is
        // at it — 4.24 is an over-approximation false positive, indistinguishable
        // from 4.25 by object version. 522 (4.27) is above.
        assert!(!version(VER_UE4_GAME_UE4_23_OBJECT_PROXY, None).is_ue4_25_or_later());
        assert!(version(VER_UE4_GAME_UE4_25_OBJECT_PROXY, None).is_ue4_25_or_later());
        assert!(version(522, None).is_ue4_25_or_later());
        // Any UE5 asset is above via the is_some() branch.
        assert!(version(400, Some(1009)).is_ue4_25_or_later());
    }

    #[test]
    fn is_virtual_textures_or_later_pins_the_517_boundary() {
        // 516 (GAME_UE4_20) is below the VirtualTextures proxy; 517
        // (GAME_UE4_23) is at it. 522 (UE 4.27) is above.
        assert!(!version(516, None).is_virtual_textures_or_later());
        assert!(version(VER_UE4_GAME_UE4_23_OBJECT_PROXY, None).is_virtual_textures_or_later());
        assert!(version(522, None).is_virtual_textures_or_later());
        // Any UE5 asset is virtual-texture-capable via the `is_some()` branch,
        // even with a low UE4 object version.
        assert!(version(400, Some(1009)).is_virtual_textures_or_later());
    }

    #[test]
    fn is_ue4_23_or_later_pins_the_517_boundary() {
        // 516 (GAME_UE4_20) is below the UseNewCookedFormat proxy; 517
        // (GAME_UE4_23) is at it. 522 (UE 4.27) is above.
        assert!(!version(516, None).is_ue4_23_or_later());
        assert!(version(VER_UE4_GAME_UE4_23_OBJECT_PROXY, None).is_ue4_23_or_later());
        assert!(version(522, None).is_ue4_23_or_later());
        // Any UE5 asset is new-cooked-format via the `is_some()` branch.
        assert!(version(400, Some(1009)).is_ue4_23_or_later());
    }
}
