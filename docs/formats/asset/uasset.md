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

**Document status: complete.** Wire format documented in full for
`FPackageFileSummary` across `LegacyFileVersion ∈ {-7, -8, -9}` +
`FileVersionUE4 ∈ [504, 522]` + `FileVersionUE5 ∈ [1000, 1013]`,
the `NameTable` / `ImportTable` / `ExportTable` counted-array
tables (including the UE4 4.27 104-byte `ObjectExport` record + UE5
1003 / 1005 / 1006 / 1010 conditional fields), the monolithic-vs-split
discriminator, the `total_header_size` partition, and the ancillary
offset tables (dependencies, gatherable text, soft-object paths).
Per-export property-body decode lives in [`uexp.md`](uexp.md) +
[`../property/tagged.md`](../property/tagged.md). UE5 ≥ 1014
(`METADATA_SERIALIZATION_OFFSET`) is explicitly out of paksmith's
accepted range — see §*Variants*.

**Paksmith parser status: `complete`.** Phase 2a deliverable; ships
as `paksmith-core/src/asset/`. Per-property bodies covered separately
in the [`../property/`](../property/) family.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| `LegacyFileVersion ∈ {-7, -8, -9}` | Paksmith's accepted legacy-version floor; pre-`-7` archives have a different summary shape and are rejected at parse time. | `CUE4Parse/UE4/Versions/ObjectVersion.cs@ecc4878950336126f125af0747190edf474b2a21`[^1] |
| `FileVersionUE4 ≥ 504` (UE 4.12+) | Paksmith's UE4 floor; 504 sets the name-table-with-hash-trailers shape. No upper bound is applied: 522 is UE 4.27's latest object-version constant, and versioned UE5 packages record 522 too. The legacy check refuses stock UE 4.12 and 4.13 packages, which write `-6`, so UE 4.14 (508) is the first stock release whose versioned packages paksmith reads.[^11] | Same[^1] |
| `FileVersionUE5 ≤ 1013` (up to UE 5.5) | Paksmith's UE5 ceiling (#643); no lower bound is applied. 1014 (`METADATA_SERIALIZATION_OFFSET`) adds a summary field the reader does not consume. | Same[^1] |
| 1003 `OPTIONAL_RESOURCES` | Adds `generate_public_hash` bool32 to each `ObjectExport` and `bImportOptional` bool32 to each `ObjectImport`. | Same[^1] |
| 1005 `REMOVE_OBJECT_EXPORT_PACKAGE_GUID` | Removes `package_guid` from `ObjectExport`. | Same[^1] |
| 1006 `TRACK_OBJECT_EXPORT_IS_INHERITED` | Adds `is_inherited_instance` bool32 to each `ObjectExport`. | Same[^1] |
| 1008 `ADD_SOFTOBJECTPATH_LIST` | Adds `soft_object_paths_count` + `soft_object_paths_offset` to summary. | Same[^1] |
| 1009 `DATA_RESOURCES` | Adds `data_resource_offset` to summary. | Same[^1] |
| 1010 `SCRIPT_SERIALIZATION_OFFSET` | Adds `script_serialization_start_offset` + `script_serialization_end_offset` to each `ObjectExport` (gated by `PKG_UnversionedProperties` package-flag absence). | Same[^1] |
| 1011 `PROPERTY_TAG_EXTENSION_AND_OVERRIDABLE_SERIALIZATION` | No summary change. Adds the per-tag extension byte + per-object serialization-control byte to versioned tagged-property streams — see [`../property/tagged.md`](../property/tagged.md). Never ships standalone (UE releases jump 1009 → 1012). | Same[^1] |
| 1012 `PROPERTY_TAG_COMPLETE_TYPE_NAME` (UE 5.4) | No summary change. Replaces the tag's FName type with a type-name tree and elides the `Array<Struct>` inner tag — see [`../property/tagged.md`](../property/tagged.md). Also: cooked `USoundWave` gains a cue-point array. | Same[^1] |
| 1013 `ASSETREGISTRY_PACKAGEBUILDDEPENDENCIES` (UE 5.5) | Changes only the asset-registry data blob (not parsed by paksmith); no summary/tag/export wire impact. | Same[^1] |

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
| 12 | 4 | LE | `file_version_ue4` | `i32` | UE4 object version; paksmith requires ≥ 504. 0 in an [unversioned package](#unversioned-packages). |
| 16 | 4 | LE | `file_version_ue5` | `i32` | UE5 object version, from 1000; paksmith refuses ≥ 1014. 0 in an [unversioned package](#unversioned-packages). Present only if `legacy_file_version ≤ -8`. |
| → varies | 4 | LE | `file_version_licensee_ue4` | `i32` | Game-studio fork version (usually 0). |
| → varies | variable | — | `custom_versions` | `FCustomVersion[]`[^3] | See [`primitive/fcustom-version.md`](../primitive/fcustom-version.md). |
| → varies | 4 | LE | `total_header_size` | `i32` | Total byte length of the header region (everything before payloads). Capped at 256 MiB by paksmith. |
| → varies | variable | — | `folder_name` | `FString`[^4] | Usually `"None"` for cooked content. |
| → varies | 4 | LE | `package_flags` | `u32` | `EPackageFlags` mask. `PKG_FilterEditorOnly = 0x8000_0000` set for cooked. `PKG_UnversionedProperties = 0x2000` requires the caller to supply a `mappings: Option<&Arc<Usmap>>` schema. |
| → varies | 4 | LE | `name_count` | `i32` | Number of rows in the name table. |
| → varies | 4 | LE | `name_offset` | `i32` | Byte offset of the name-table region. |
| (UE5 ≥ 1008) | 4 | LE | `soft_object_paths_count` | `Option<i32>` | UE5 1008+ only. |
| (UE5 ≥ 1008) | 4 | LE | `soft_object_paths_offset` | `Option<i32>` | UE5 1008+ only. |
| (UE4 ≥ 516 & !editor-only-stripped) | variable | — | `localization_id` | `Option<FString>` | UE 4.19+[^12] AND `PKG_FilterEditorOnly` not set. Cooked archives almost never have this. |
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
| (UE4 ≥ 518 & !editor-only-stripped) | 16 | — | `persistent_guid` | `Option<FGuid>` | UE 4.24+[^12] editor builds. |
| (UE4 ∈ [518, 520) & !editor-only-stripped) | 16 | — | `owner_persistent_guid` | `Option<FGuid>` | UE 4.24–4.25[^12] editor builds; removed at UE4 520. |
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
| 0 | 8 | LE | `class_package` | `FName`[^8] (4+4) | The `UPackage` that hosts the imported class. |
| 8 | 8 | LE | `class_name` | `FName`[^8] | The class of the imported object (e.g. `Texture2D`). |
| 16 | 4 | LE | `outer_index` | `FPackageIndex`[^7] | Reference into import (or export) table; `Null` = top-level import. |
| 20 | 8 | LE | `object_name` | `FName`[^8] | Imported object's name. |
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
| 16 | 8 | LE | `object_name` | `FName`[^8] | Export's name. |
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

### Unversioned packages

A package cooked unversioned records no object version:
`FileVersionUE4`, `FileVersionUE5` (at `-8` / `-9`) and
`FileVersionLicenseeUE4` are all 0. Its layout is still the cooking
engine's, so a reader must be told which engine that was. CUE4Parse
substitutes its configured version when all three are 0, before it reads
the custom versions;[^9] UEViewer detects `FileVersion == 0 &&
LicenseeVersion == 0` and, when no game is selected, asks the user to
select an engine, or fails.[^10] This is independent of unversioned
property serialization above: a package can be either, or both. Paksmith
refuses an unversioned package with
`AssetParseFault::UnversionedPackage`.

### Legacy file version (`-7` / `-8` / `-9`)

- `-7`: omits `file_version_ue5` field (UE 4.14–4.27).[^11]
- `-8`: adds `file_version_ue5` field (UE 5.0–5.5).
- `-9` (UE 5.6+): same shape as `-8` at the same `FileVersionUE5`; bumped by
  Epic for a non-wire change. UE 5.6's own object version (1017) is already
  past `PACKAGE_SAVED_HASH` (1016) and paksmith's ceiling.

Paksmith accepts all three; archives at `> -7` (older legacy summary
shapes, such as `-6`) or `< -9` are rejected.

## Caps & limits

### Format-defined limits (wire-imposed)

- **`magic`**: fixed `u32` = `0x9E2A83C1` (`PACKAGE_FILE_TAG`).
- **`legacy_file_version`**: `i32` LE; wire-format-wise the field is unbounded (any `i32` could appear on disk). UE writers historically emit a small set of negative discriminants; paksmith's acceptance of `{-7, -8, -9}` is a parser-policy decision — see §*Implementation hardening* below.
- **`file_version_ue4`**: `i32` LE; wire field unbounded. Paksmith's `≥ 504` floor (UE 4.12's object version), with no upper bound, is a parser-policy decision; the Versions table gives the stock floor the legacy check sets.
- **`file_version_ue5`**: `i32` LE; wire field unbounded. Paksmith's `≤ 1013` ceiling, with no lower bound, is a parser-policy decision (rejecting `≥ 1014` because `METADATA_SERIALIZATION_OFFSET` adds a summary field the reader does not consume, with further summary-shape breaks at 1015/1016).
- **`package_flags`**: `u32` LE; `EPackageFlags` mask. `PKG_FilterEditorOnly = 0x8000_0000` set for cooked content; `PKG_UnversionedProperties = 0x2000` requires `.usmap` schema.
- **`ObjectImport` row**: 28 bytes (UE4 baseline) / 32 bytes (UE5 ≥ 1003 with `bImportOptional` bool32).
- **`ObjectExport` row**: 104 bytes (UE 4.27, `EXPORT_RECORD_SIZE_UE4_27`). UE5 conditionally adds / removes fields (1003 `+generate_public_hash`, 1005 `-package_guid`, 1006 `+is_inherited_instance`, 1010 `+script_serialization_*_offset` when not `PKG_UnversionedProperties`).
- **`FPackageIndex`**: `i32` LE; `0` = `Null`, `>0` = `Export`, `<0` = `Import`, `i32::MIN` rejected — see [`../primitive/fpackage-index.md`](../primitive/fpackage-index.md).
- **`FGuid` / `FName` / `FString` / `FCustomVersion` / `FEngineVersion`**: per the linked primitive docs.

### Implementation hardening (recommended for any parser)

paksmith enforces structural caps to prevent attacker-controlled
allocation amplification.

- **`MAX_TOTAL_HEADER_SIZE = 256 MiB`**
  (`crates/paksmith-core/src/asset/summary.rs:46`). Largest acceptable
  `total_header_size`. Surfaces as
  `AssetParseFault::BoundsExceeded { field: TotalHeaderSize, … }`.
- **`MAX_PAYLOAD_BYTES = 256 MiB`**
  (`crates/paksmith-core/src/asset/package.rs`). Largest single
  per-export payload. Surfaces as
  `AssetParseFault::BoundsExceeded { field: ExportSerialSize, … }`.
- **Export sizes must fit the asset**
  (`crates/paksmith-core/src/asset/package.rs`, `check_export_payload_total`).
  The exports' `SerialSize` values may not sum past the bytes they
  address: the `.uasset`, plus the `.uexp` when exports reach into it.
  Disjoint ranges never do, so a larger total implies rows that point at
  the same bytes, which would decode them once per row. Surfaces as
  `AssetParseFault::BoundsExceeded { field: ExportSerialSizeTotal, … }`.
- **`MAX_GENERATION_COUNT = 1_024`**
  (`crates/paksmith-core/src/asset/summary.rs:51`).
- **`MAX_ADDITIONAL_PACKAGES_TO_COOK_COUNT = 4_096`**
  (`crates/paksmith-core/src/asset/summary.rs:55`).
- **`MAX_CHUNK_ID_COUNT = 65_536`**
  (`crates/paksmith-core/src/asset/summary.rs:59`).
- **`MAX_NAME_TABLE_ENTRIES = 1_048_576`**
  (`crates/paksmith-core/src/asset/name_table.rs:32`). See
  [`../primitive/fname.md`](../primitive/fname.md).
- **`MAX_IMPORT_TABLE_ENTRIES = 524_288`**
  (`crates/paksmith-core/src/asset/import_table.rs:37`).
- **`MAX_EXPORT_TABLE_ENTRIES = 524_288`**
  (`crates/paksmith-core/src/asset/export_table.rs:64`).
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
  - **UE5 1014+ rejection.** Paksmith rejects archives at
    `FileVersionUE5 ≥ 1014` (`METADATA_SERIALIZATION_OFFSET`) because
    the summary reader does not consume the new `MetaDataOffset`
    field (1015/1016 add further summary-shape breaks: cell tables,
    `FGuid` → `FIoHash`). The 1011/1012 property-tag shapes are
    handled as of #643; CUE4Parse supports 1014+ while the
    `unreal_asset` oracle's version enum ends at 1009.
  - **`PKG_UnversionedProperties` requires mappings.** Packages with
    unversioned properties are decoded against a `.usmap` schema supplied via the
    `mappings: Option<&Arc<Usmap>>` parameter (Phase 2f's loader shipped).
    Parsing without mappings surfaces as
    `AssetParseFault::UnversionedWithoutMappings`. CUE4Parse and
    unreal_asset use the same mappings-driven approach.
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
  `mappings: Option<&Arc<Usmap>>` argument is the unversioned-property schema
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
- `AssetParseFault::UnversionedPackage { legacy_file_version }`.
- `AssetParseFault::UnsupportedFileVersionUE5 { version, first_unsupported }`.
- `AssetParseFault::BoundsExceeded { field: AssetWireField, … }` — every
  cap above surfaces this with a specific `AssetWireField` discriminant.
- `AssetParseFault::NegativeValue { field, value }`.
- `AssetParseFault::FStringMalformed { kind }`.
- `AssetParseFault::PackageIndexUnderflow { field }`.
- `AssetParseFault::AllocationFailed { context: AssetAllocationContext, … }`.
- `AssetParseFault::UnversionedWithoutMappings` (raised when a package with
  unversioned properties is parsed without `mappings: Some(...)`; Phase 2f's `.usmap`
  loader supplies these).
- `AssetParseFault::UnsupportedCompressionInSummary { site, observed }`
  (raised when the summary's compressed-chunks tail is non-empty —
  paksmith rejects archives with summary-level compression).

**Phase plan:** `docs/plans/phase-2a-uasset-header.md`.

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Objects/UObject/FPackageFileSummary.cs@ecc4878950336126f125af0747190edf474b2a21` — primary oracle. Covers the `FPackageFileSummary` constructor and its UE5 version dispatch up to 1018 (`IMPORT_TYPE_HIERARCHIES`); `FObjectImport` and `FObjectExport` are read in `ObjectResource.cs` in the same directory.
[^2]: `AstroTechies/unrealmodding/unreal_asset/src/asset.rs@f4df5d8e75b1e184832384d1865f0b696b90a614` — paksmith's fixture-gen oracle. Cross-validated against every `minimal_uasset_v5*` fixture at fixture-gen time.
[^3]: See [`../primitive/fcustom-version.md`](../primitive/fcustom-version.md).
[^4]: See [`../primitive/fstring.md`](../primitive/fstring.md).
[^5]: See [`../primitive/fguid.md`](../primitive/fguid.md).
[^6]: See [`../primitive/fengine-version.md`](../primitive/fengine-version.md).
[^7]: See [`../primitive/fpackage-index.md`](../primitive/fpackage-index.md).
[^8]: See [`../primitive/fname.md`](../primitive/fname.md).
[^9]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Objects/UObject/FPackageFileSummary.cs@77b94fa26cde08d34e80be2ced29c8f8885ff0a7` L212-L218 (detection and substitution), L235 (custom versions).
[^10]: `gildor2/UEViewer/Unreal/UnrealPackage/UnPackage4.cpp@a0bfb468d42be831b126632fd8a0ae6b3614f981` L119-L139; `gildor2/UEViewer/UmodelTool/Main.cpp@a0bfb468d42be831b126632fd8a0ae6b3614f981` L548-L556.
[^11]: `gildor2/UEViewer/Unreal/UnrealPackage/UnPackage4.cpp@a0bfb468d42be831b126632fd8a0ae6b3614f981` L84-L95 (`legacyVerToEngineVer`: `-6` from UE 4.11, `-7` from UE 4.14) and `gildor2/UEViewer/Unreal/UE4Version.h@a0bfb468d42be831b126632fd8a0ae6b3614f981` L73-L77 (UE 4.12 = 504, UE 4.14 = 508). The rest of the ranges come from real package headers in `atenfyr/UAssetAPI/UAssetAPI.Tests/TestAssets@b4e8a012939295a6fd890ddc64e57ea78b709b95`: the UE 4.27.2 editor saves in `TestEditorAssets` at `-7`; `TestUE5_1`, `TestUE5_3`, `TestUE5_4` and `TestUE5_5` at `-8`; `TestUE5_6` and `TestUE5_7` at `-9`, as are the UE 5.7.4 editor saves in `TestEditorUE5_7`. `matyalatte/Matya-Uasset-Samples@a7921caec72aca1d1a9cf28e488d702dceaf6f93` adds UE 5.0 samples at `-8`.
[^12]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Versions/ObjectVersion.cs@ecc4878950336126f125af0747190edf474b2a21` L912, L916 and L920 (`ADDED_PACKAGE_SUMMARY_LOCALIZATION_ID` = 516, `ADDED_PACKAGE_OWNER` = 518, `NON_OUTER_PACKAGE_IMPORT` = 520, counted from `OLDEST_LOADABLE_PACKAGE = 214` at L299) and `CUE4Parse/UE4/Versions/EGame.cs` L290-L298 (UE 4.18 → 514; 4.19 → 516; 4.23 → 517; 4.24 and 4.25 → 518; 4.26 → 522).
