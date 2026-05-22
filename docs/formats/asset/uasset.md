# UAsset (`.uasset`)

> The primary file of a UE package: header, custom-version table, name
> pool, import table, export table, dependency offsets, and (for
> monolithic assets) the export bodies themselves.

## Overview

A `.uasset` file is the entry point for any UE package on disk. It always
contains the package summary (`FPackageFileSummary`), the name pool, the
import table, the export table, and ancillary offset tables for
dependencies and gatherable text. The package may be **monolithic** (export
bodies inline) or **split** (bodies in a sibling `.uexp`) — see
[`companion-resolution.md`](companion-resolution.md) for the discriminator
and [`uexp.md`](uexp.md) for the sidecar wire shape.

Paksmith parses the header + tables synchronously at `Package::read_from`
time, then walks per-export payloads. The summary's `total_header_size`
field divides "header region" from "payload region" in either layout.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| `LegacyFileVersion ∈ {-7, -8, -9}` | Paksmith's accepted legacy-version floor; pre-`-7` archives have a different summary shape and are rejected at parse time. | `CUE4Parse/UE4/Versions/ObjectVersion.cs@ecc4878950336126f125af0747190edf474b2a21`[^1] |
| `FileVersionUE4 ∈ [504, 522]` (UE 4.21 – 4.27) | Paksmith's accepted UE4 version range. 504 sets the name-table-with-hash-trailers shape; 522 is UE 4.27's latest object-version constant. | Same[^1] |
| `FileVersionUE5 ∈ [1000, 1010]` (UE 5.0 – 5.1+) | Paksmith's accepted UE5 version range. 1011 (`PROPERTY_TAG_EXTENSION_AND_OVERRIDABLE_SERIALIZATION`) introduces an FPropertyTag wire-format break Phase 2b cannot handle. | Same[^1] |
| 1003 `OPTIONAL_RESOURCES` | Adds `generate_public_hash` bool32 to each `ObjectExport` and `bImportOptional` bool32 to each `ObjectImport`. | Same[^1] |
| 1005 `REMOVE_OBJECT_EXPORT_PACKAGE_GUID` | Removes `package_guid` from `ObjectExport`. | Same[^1] |
| 1006 `TRACK_OBJECT_EXPORT_IS_INHERITED` | Adds `is_inherited_instance` bool32 to each `ObjectExport`. | Same[^1] |
| 1008 `ADD_SOFTOBJECTPATH_LIST` | Adds `soft_object_paths_count` + `soft_object_paths_offset` to summary. | Same[^1] |
| 1009 `DATA_RESOURCES` | Adds `data_resource_offset` to summary. | Same[^1] |
| 1010 `SCRIPT_SERIALIZATION_OFFSET` | Adds `script_serialization_start_offset` + `script_serialization_end_offset` to each `ObjectExport` (gated by `PKG_UnversionedProperties` package-flag absence). | Same[^1] |

See `crates/paksmith-core/src/asset/version.rs` and
`crates/paksmith-core/src/asset/summary.rs` (the `FIRST_UNSUPPORTED_UE5_VERSION` constant and its comment) for the
authoritative paksmith range and the rationale for the UE5 cutoff.

## Wire layout

### Package summary (`FPackageFileSummary`)

The summary is the first record in every `.uasset`. Field count varies
across UE versions due to conditional reads; the canonical sequence (UE
4.27, the most-supported case) is:

| offset (cumulative) | size | endian | name | type | semantics |
|---------------------|------|--------|------|------|-----------|
| 0 | 4 | LE | `magic` | `u32` | Must equal `0x9E2A83C1` (`PACKAGE_FILE_TAG`). |
| 4 | 4 | LE | `legacy_file_version` | `i32` | Negative; one of `-7`, `-8`, `-9`. |
| 8 | 4 | LE | `legacy_ue3_version` | `i32` | Always `-1` for paksmith-supported archives. |
| 12 | 4 | LE | `file_version_ue4` | `i32` | 504–522 (UE 4.21 – 4.27). |
| 16 | 4 | LE | `file_version_ue5` | `i32` | 0 (UE4) or 1000–1010 (UE5). Present only if `legacy_file_version ≤ -8`. |
| → varies | 4 | LE | `file_version_licensee_ue4` | `i32` | Game-studio fork version (usually 0). |
| → varies | variable | — | `custom_versions` | `FCustomVersion[]`[^3] | See [`primitive/fcustom-version.md`](../primitive/fcustom-version.md). |
| → varies | 4 | LE | `total_header_size` | `i32` | Total byte length of the header region (everything before payloads). Capped at 256 MiB by paksmith. |
| → varies | variable | — | `folder_name` | `FString`[^4] | Usually `"None"` for cooked content. |
| → varies | 4 | LE | `package_flags` | `u32` | `EPackageFlags` mask. `PKG_FilterEditorOnly = 0x8000_0000` set for cooked. `PKG_UnversionedProperties = 0x2000` rejected at this layer (Phase 2f decision). |
| → varies | 4 | LE | `name_count` | `i32` | Number of rows in the name table. |
| → varies | 4 | LE | `name_offset` | `i32` | Byte offset of the name-table region. |
| (UE5 ≥ 1008) | 4 | LE | `soft_object_paths_count` | `Option<i32>` | UE5 1008+ only. |
| (UE5 ≥ 1008) | 4 | LE | `soft_object_paths_offset` | `Option<i32>` | UE5 1008+ only. |
| (UE4 ≥ 516 & !editor-only-stripped) | variable | — | `localization_id` | `Option<FString>` | UE 4.21+ AND `PKG_FilterEditorOnly` not set. Cooked archives almost never have this. |
| → varies | 4 | LE | `gatherable_text_data_count` | `i32` | |
| → varies | 4 | LE | `gatherable_text_data_offset` | `i32` | |
| → varies | 4 | LE | `export_count` | `i32` | Number of rows in the export table. |
| → varies | 4 | LE | `export_offset` | `i32` | Byte offset of the export-table region. |
| → varies | 4 | LE | `import_count` | `i32` | Number of rows in the import table. |
| → varies | 4 | LE | `import_offset` | `i32` | Byte offset of the import-table region. |
| → varies | 4 | LE | `depends_offset` | `i32` | Byte offset of the per-export dependency-list region. |
| → varies | 4 | LE | `soft_package_references_count` | `i32` | |
| → varies | 4 | LE | `soft_package_references_offset` | `i32` | |
| (UE4 ≥ 510) | 4 | LE | `searchable_names_offset` | `Option<i32>` | Absent below UE4 510; present and unconditional at UE 4.27 (522). |
| → varies | 4 | LE | `thumbnail_table_offset` | `i32` | |
| → varies | 16 | — | `guid` | `FGuid`[^5] | Package identifier. UE5 1016 replaces this with `FIoHash` (outside paksmith's range). |
| (UE4 ≥ 518 & !editor-only-stripped) | 16 | — | `persistent_guid` | `Option<FGuid>` | UE 4.22+ editor builds. |
| (UE4 ∈ [518, 520) & !editor-only-stripped) | 16 | — | `owner_persistent_guid` | `Option<FGuid>` | UE 4.22–4.23 editor builds; removed at UE4 520. |
| → varies | 4 | LE | `generation_count` | `i32` | Capped at 1024. |
| → varies | `generation_count × 8` | — | `generations` | `FGenerationInfo[]` | Each: `export_count: i32 + name_count: i32`. |
| → varies | variable | — | `saved_by_engine_version` | `FEngineVersion`[^6] | |
| → varies | variable | — | `compatible_with_engine_version` | `FEngineVersion`[^6] | |
| → varies | 4 | LE | `compression_flags` | `u32` | Legacy field, always 0 for cooked. |
| → varies | 4 | LE | `compressed_chunks_count` | `i32` | Capped at 0 — paksmith rejects archives with any compressed chunks at the summary level. |
| → varies | 4 | LE | `package_source` | `u32` | Source-control fingerprint. |
| → varies | 4 | LE | `additional_packages_to_cook_count` | `i32` | Capped at 4096. |
| → varies | variable | — | `additional_packages_to_cook` | `FString[]` | Capped at 4096 entries. |
| → varies | 4 | LE | `asset_registry_data_offset` | `i32` | |
| → varies | 8 | LE | `bulk_data_start_offset` | `i64` | Offset where `.ubulk` data begins (in the original file). |
| → varies | 4 | LE | `world_tile_info_data_offset` | `i32` | |
| → varies | 4 | LE | `chunk_id_count` | `i32` | Capped at 65,536. |
| → varies | `chunk_id_count × 4` | LE | `chunk_ids` | `i32[]` | Capped at 65,536 entries. |
| (UE4 ≥ 507) | 4 | LE | `preload_dependency_count` | `Option<i32>` | Absent below UE4 507; present at UE 4.27. |
| (UE4 ≥ 507) | 4 | LE | `preload_dependency_offset` | `Option<i32>` | Absent below UE4 507; present at UE 4.27. |
| (UE5 ≥ 1001) | 4 | LE | `names_referenced_from_export_data_count` | `Option<i32>` | UE5 1001+ only. |
| (UE5 ≥ 1002) | 8 | LE | `payload_toc_offset` | `Option<i64>` | UE5 1002+ only. |
| (UE5 ≥ 1009) | 4 | LE | `data_resource_offset` | `Option<i32>` | UE5 1009+ only. |

The summary's size depends on the version dance above. `total_header_size`
publishes the total byte size of `summary + name_table + import_table + export_table + ancillary tables`.

### Name table

See [`primitive/fname.md`](../primitive/fname.md) for the name-entry wire
shape. The summary publishes `name_offset` and `name_count`; the reader
seeks and reads `name_count` rows.

### Import table (`ObjectImport[]`)

Each `ObjectImport` row at offset `import_offset`:

| offset (within row) | size | endian | name | type | semantics |
|---------------------|------|--------|------|------|-----------|
| 0 | 8 | LE | `class_package` | `FName`[^2] (4+4) | The `UPackage` that hosts the imported class. |
| 8 | 8 | LE | `class_name` | `FName`[^2] | The class of the imported object (e.g. `Texture2D`). |
| 16 | 4 | LE | `outer_index` | `FPackageIndex`[^7] | Reference into import (or export) table; `Null` = top-level import. |
| 20 | 8 | LE | `object_name` | `FName`[^2] | Imported object's name. |
| (UE5 ≥ 1003) | 4 | LE | `bImportOptional` | `Option<bool>` (bool32) | UE5 1003+ only; optional-import flag. Wire type is `i32` (4 bytes). |

Row size: 28 bytes (UE4 baseline) / 32 bytes (UE5 ≥ 1003 with `bImportOptional` bool32).

### Export table (`ObjectExport[]`)

Each `ObjectExport` row at offset `export_offset`. The UE 4.27 record is
**104 bytes** (`EXPORT_RECORD_SIZE_UE4_27 = 104`); UE5 adds and removes
fields conditionally:

| offset (within UE 4.27 row) | size | endian | name | type | semantics |
|-----------------------------|------|--------|------|------|-----------|
| 0 | 4 | LE | `class_index` | `FPackageIndex`[^7] | Class of the export. |
| 4 | 4 | LE | `super_index` | `FPackageIndex`[^7] | Parent class (inheritance). |
| 8 | 4 | LE | `template_index` | `FPackageIndex`[^7] | Default-template object for instantiation. Present only if UE4 ≥ 508; absent below. |
| 12 | 4 | LE | `outer_index` | `FPackageIndex`[^7] | Containing object; `Null` = top-level. |
| 16 | 8 | LE | `object_name` | `FName`[^2] | Export's name. |
| 24 | 4 | LE | `object_flags` | `u32` | `EObjectFlags` mask. |
| 28 | 8 | LE | `serial_size` | `i64` | Byte length of the export's property body. Wire type is `i32` below UE4 511, widened to `i64` in memory. |
| 36 | 8 | LE | `serial_offset` | `i64` | Byte offset of the property body (relative to start of file in monolithic, or stitched buffer in split). Same width rule as `serial_size`. |
| 44 | 4 | LE | `b_forced_export` | `bool` (bool32) | Bool encoded as i32. |
| 48 | 4 | LE | `b_not_for_client` | `bool` (bool32) | |
| 52 | 4 | LE | `b_not_for_server` | `bool` (bool32) | |
| 56 | 16 | — | `package_guid` | `FGuid`[^5] | Present in UE 4.27 (UE5 < 1005). Removed at UE5 1005. |
| (UE5 ≥ 1006) | 4 | LE | `is_inherited_instance` | `Option<bool>` (bool32) | UE5 1006+ only. Wire type is `i32` (4 bytes). |
| 72 | 4 | LE | `package_flags` | `u32` | |
| 76 | 4 | LE | `b_not_always_loaded_for_editor_game` | `bool` (bool32) | |
| 80 | 4 | LE | `b_is_asset` | `bool` (bool32) | |
| (UE5 ≥ 1003) | 4 | LE | `generate_public_hash` | `Option<bool>` (bool32) | UE5 1003+ only. Wire type is `i32` (4 bytes). |
| 84 | 4 | LE | `first_export_dependency` | `i32` | Index into the preload-dependency table; `-1` = none. Present only if UE4 ≥ 507. |
| 88 | 4 | LE | `serialization_before_serialization_dependencies` | `i32` | Dependency-list length. Present only if UE4 ≥ 507. |
| 92 | 4 | LE | `create_before_serialization_dependencies` | `i32` | Present only if UE4 ≥ 507. |
| 96 | 4 | LE | `serialization_before_create_dependencies` | `i32` | Present only if UE4 ≥ 507. |
| 100 | 4 | LE | `create_before_create_dependencies` | `i32` | Present only if UE4 ≥ 507. |
| (UE5 ≥ 1010 & !PKG_UnversionedProperties) | 8 | LE | `script_serialization_start_offset` | `Option<i64>` | UE5 1010+ AND tagged-property serialization. |
| (UE5 ≥ 1010 & !PKG_UnversionedProperties) | 8 | LE | `script_serialization_end_offset` | `Option<i64>` | UE5 1010+ AND tagged-property serialization. |

UE 4.27 row size: 104 bytes (matches `EXPORT_RECORD_SIZE_UE4_27`).

### Worked example: monolithic v4.27 summary head

```bash
xxd -l 64 tests/fixtures/minimal_uasset_v5.uasset
```

Expected output:

```output
00000000: c183 2a9e f9ff ffff ffff ffff 0a02 0000  ..*.............
00000010: 0000 0000 0000 0000 af01 0000 0500 0000  ................
00000020: 4e6f 6e65 0000 0000 8003 0000 00e7 0000  None............
00000030: 0000 0000 0000 0000 0001 0000 0047 0100  .............G..
```

The first 4 bytes are the magic `c1 83 2a 9e` (LE of `0x9E2A83C1`). The
next 4 bytes are the legacy file version (`f9 ff ff ff` = `-7`). The next
4 bytes are the legacy UE3 version (`ff ff ff ff` = `-1`). The next 4
bytes are `file_version_ue4` (`0a 02 00 00` = 522, UE 4.27). The next 4
bytes (offsets 16–19) are `file_version_licensee_ue4` (`00 00 00 00` = 0).
Because `legacy_file_version = -7`, the `file_version_ue5` slot is
**absent** for this archive — bytes 20+ begin the custom-version
container (count + rows).

*(Re-run the command above to verify against the fixture on disk.)*

## Variants

### Monolithic vs split

- **Monolithic** (older / specifically-cooked content): export bodies
  live inline in the `.uasset` after the header region. No `.uexp`
  needed.
- **Split** (UE 4.16+ default): the `.uasset` is truncated at
  `total_header_size`; the export bodies live in a sibling `.uexp` file.
  Stitching is required to materialize the contiguous buffer the
  export-payload reader expects.

The structural discriminator is "does any export's `serial_offset +
serial_size` extend past `uasset.len()`?" — paksmith uses exactly this
check at `Package::read_from`. See
[`companion-resolution.md`](companion-resolution.md) for the four-state
detection logic.

### Versioned vs unversioned property serialization

- **Versioned** (tagged): export bodies are an `FPropertyTag` sequence.
  The dedicated tagged-property doc is planned under
  `docs/formats/property/`.
- **Unversioned** (`PKG_UnversionedProperties` flag set): export bodies
  are a schema-driven bitstream. Paksmith requires the caller to supply
  a `.usmap` schema via the `mappings` parameter; without mappings the
  parse fails with `AssetParseFault::UnversionedWithoutMappings` (Phase
  2f shipped the loader).

### Legacy file version (`-7` / `-8` / `-9`)

- `-7`: omits `file_version_ue5` field (UE4 only).
- `-8`: adds `file_version_ue5` field (introduced UE 5.0).
- `-9`: same shape as `-8`; bumped by Epic for a non-wire change.

Paksmith accepts all three; archives at `< -7` (older legacy summary
shapes) are rejected.

## Caps & limits

paksmith enforces structural caps to prevent attacker-controlled
allocation amplification. Every cap exposes a
`#[cfg(feature = "__test_utils")]` accessor for boundary tests.

- **`MAX_TOTAL_HEADER_SIZE = 256 MiB`**
  (`crates/paksmith-core/src/asset/summary.rs:46`). Largest acceptable
  `total_header_size`. Surfaces as
  `AssetParseFault::BoundsExceeded { field: TotalHeaderSize, … }`.
- **`MAX_PAYLOAD_BYTES = 256 MiB`**
  (`crates/paksmith-core/src/asset/package.rs:45`). Largest single
  per-export payload. Surfaces as
  `AssetParseFault::BoundsExceeded { field: ExportSerialSize, … }`.
- **`MAX_GENERATION_COUNT = 1_024`**
  (`crates/paksmith-core/src/asset/summary.rs:51`).
- **`MAX_ADDITIONAL_PACKAGES_TO_COOK_COUNT = 4_096`**
  (`crates/paksmith-core/src/asset/summary.rs:55`).
- **`MAX_CHUNK_ID_COUNT = 65_536`**
  (`crates/paksmith-core/src/asset/summary.rs:59`).
- **`MAX_NAME_TABLE_ENTRIES = 1_048_576`**
  (`crates/paksmith-core/src/asset/name_table.rs:34`). See
  [`../primitive/fname.md`](../primitive/fname.md).
- **`MAX_IMPORT_TABLE_ENTRIES = 524_288`**
  (`crates/paksmith-core/src/asset/import_table.rs:39`).
- **`MAX_EXPORT_TABLE_ENTRIES = 524_288`**
  (`crates/paksmith-core/src/asset/export_table.rs:66`).
- **`compressed_chunks_count` must be 0.** Paksmith refuses to parse
  archives with any compressed chunks; the field exists for legacy
  format-version compatibility but cooked games never set it.

See `docs/security/allocation-caps.md` for the broader allocation-cap
policy.

## Verification

- **Fixtures:**
  - `tests/fixtures/minimal_uasset_v5.uasset` — monolithic UE 4.27,
    smallest valid `.uasset`.
  - `tests/fixtures/minimal_uasset_v5_with_properties.uasset` —
    monolithic with tagged-property bodies.
  - `tests/fixtures/minimal_uasset_v5_with_containers.uasset` — exercises
    array/map/set property containers.
  - `tests/fixtures/minimal_uasset_v5_with_extended_types.uasset` —
    extended property types (Phase 2d).
  - `tests/fixtures/real_v8b_split.pak` — split-asset fixture (extract
    the `.uasset` entry to see the truncated-header shape).
- **Cross-validation oracle:** `unreal_asset`[^2] (paksmith's primary
  fixture oracle) and CUE4Parse[^1]. Every `minimal_uasset_v5*` fixture
  round-trips through `unreal_asset` at fixture-gen time.
- **Known divergences:**
  - **UE5 1011+ rejection.** Paksmith rejects archives at
    `FileVersionUE5 ≥ 1011` (`PROPERTY_TAG_EXTENSION_AND_OVERRIDABLE_SERIALIZATION`)
    because Phase 2b's `FPropertyTag` reader does not handle the
    extended tag shape. CUE4Parse and unreal_asset both support 1011+.
    Phase 2f's unversioned-property work will unblock this.
  - **`PKG_UnversionedProperties` rejection.** Paksmith rejects packages
    with this flag at the summary level (Phase 2f decision). CUE4Parse
    and unreal_asset both handle unversioned via mappings files.
    Phase 2f scopes the paksmith equivalent.
  - **`compressed_chunks_count ≠ 0` rejection.** Paksmith rejects any
    summary that declares legacy compressed chunks. UE writers never
    set this for cooked content; only old uncooked archives would trip
    it.

## Paksmith implementation

**Parser modules:**
- `crates/paksmith-core/src/asset/summary.rs` — `PackageSummary` + all
  cap constants + the version range.
- `crates/paksmith-core/src/asset/package.rs` — `Package::read_from`
  orchestrator, monolithic/split stitching, payload reading.
- `crates/paksmith-core/src/asset/import_table.rs` — `ObjectImport`,
  `ImportTable`.
- `crates/paksmith-core/src/asset/export_table.rs` — `ObjectExport`,
  `ExportTable`.
- `crates/paksmith-core/src/asset/version.rs` — `AssetVersion` (legacy
  + UE4 + UE5 + licensee snapshot).
- `crates/paksmith-core/src/asset/wire.rs` — shared low-level wire
  helpers.

**Status:** `complete` for the structural header; per-property bodies
covered in the planned property family docs under
`docs/formats/property/`.

**Public surface:**
- `pub struct Package` — `read_from(uasset, uexp, mappings, asset_path)`,
  `read_from_pak(pak_path, virtual_path, mappings)`, `context()`. The
  `mappings: Option<&Usmap>` argument is the unversioned-property schema
  loader (Phase 2f).
- `pub struct PackageSummary` — every field above as `pub`.
- `pub struct ObjectImport` — every field above as `pub`.
- `pub struct ObjectExport` — every field above as `pub`.
- `pub struct ImportTable { pub imports: Vec<ObjectImport> }`.
- `pub struct ExportTable { pub exports: Vec<ObjectExport> }`.
- `pub struct AssetVersion` — `legacy_file_version`, `file_version_ue4`,
  `file_version_ue5`, `file_version_licensee_ue4`.

**Error variants** (selected; see `crates/paksmith-core/src/error.rs`
for the full enum):
- `AssetParseFault::InvalidMagic { observed, expected }`.
- `AssetParseFault::UnsupportedLegacyFileVersion { version }`.
- `AssetParseFault::UnsupportedFileVersionUE4 { version, minimum }`.
- `AssetParseFault::UnsupportedFileVersionUE5 { version, first_unsupported }`.
- `AssetParseFault::BoundsExceeded { field: AssetWireField, … }` — every
  cap above surfaces this with a specific `AssetWireField` discriminant.
- `AssetParseFault::NegativeValue { field, value }`.
- `AssetParseFault::FStringMalformed { kind }`.
- `AssetParseFault::PackageIndexUnderflow { field }`.
- `AssetParseFault::AllocationFailed { context: AssetAllocationContext, … }`.
- `AssetParseFault::UnversionedWithoutMappings` (raised when an unversioned
  package is parsed without `mappings: Some(...)`; Phase 2f's `.usmap`
  loader supplies these).
- `AssetParseFault::UnsupportedCompressionInSummary { site, observed }`
  (raised when the summary's compressed-chunks tail is non-empty —
  paksmith rejects archives with summary-level compression).

**Phase plan:** `docs/plans/phase-2a-uasset-header.md`.

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Objects/UObject/FPackageFileSummary.cs@ecc4878950336126f125af0747190edf474b2a21` — primary oracle. Covers `FPackageFileSummary.Serialize`, `ObjectImport.Serialize`, `ObjectExport.Serialize`, and the UE5 1000–1016 version dispatch.
[^2]: `AstroTechies/unrealmodding/unreal_asset/src/asset.rs@f4df5d8e75b1e184832384d1865f0b696b90a614` — paksmith's fixture-gen oracle. Cross-validated against every `minimal_uasset_v5*` fixture at fixture-gen time.
[^3]: See [`../primitive/fcustom-version.md`](../primitive/fcustom-version.md).
[^4]: See [`../primitive/fstring.md`](../primitive/fstring.md).
[^5]: See [`../primitive/fguid.md`](../primitive/fguid.md).
[^6]: See [`../primitive/fengine-version.md`](../primitive/fengine-version.md).
[^7]: See [`../primitive/fpackage-index.md`](../primitive/fpackage-index.md).
