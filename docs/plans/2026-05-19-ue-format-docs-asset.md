# UE Asset Family Documentation — PR 4 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Populate `docs/formats/asset/` with four documents: `uasset.md` (header + tables, `complete | complete`), `uexp.md` (export-body sidecar, `complete | complete`), `ubulk.md` (bulk-data sidecar, `partial | partial` — detection only, no stitching yet), and `companion-resolution.md` (how the three pieces find each other, `complete | complete`). Add four rows to the root inventory.

**Architecture:** Three docs reflect work that already shipped (Phase 2a header parsing, Phase 2e companion stitching), so the prose mirrors real cap constants, error variants, and behavior. `ubulk.md` is intentionally `partial` because paksmith currently *detects* a `.ubulk` sibling and warns, but does not yet read its payload (Phase 3+ work). `companion-resolution.md` is the load-bearing cross-cutting doc that explains the four-state detection logic and the path-derivation rules.

**Tech Stack:** Pure markdown. PR 1 linters. The asset doc set cites `CUE4Parse/UE4/Assets/Objects/Package.cs` and `AstralOrigin/unreal_asset/unreal_asset/src/lib.rs` as the two primary oracles; the latter is paksmith's existing fixture-gen oracle so its citations are particularly load-bearing.

**Spec reference:** `docs/design/2026-05-19-ue-format-docs.md` (commit `72b364e`). **Prerequisite:** PR 1 (framework scaffold) has merged to `main`.

---

## Prerequisites

- PR 1 (`docs/ue-format-docs-framework`) has merged to `main`.
- Working in a worktree under `.claude/worktrees/docs+ue-format-docs-asset/`.
- `cargo build -p paksmith-doc-lint --release` succeeds.

## File structure

**Create (4 docs):**

- `docs/formats/asset/uasset.md` — full byte-level reference for the package header + tables.
- `docs/formats/asset/uexp.md` — full byte-level reference for the export-body sidecar.
- `docs/formats/asset/ubulk.md` — partial reference for the bulk-data sidecar (detection only).
- `docs/formats/asset/companion-resolution.md` — cross-file resolution rules.

**Modify (1):**

- `docs/formats/README.md` — add four rows to the inventory table.

**Oracle citation policy.** Primary: CUE4Parse `Assets/Objects/Package.cs`. Secondary: `unreal_asset` (paksmith's fixture-gen oracle, particularly authoritative for UE5 1000–1010 quirks). repak is *not* cited — repak is a `.pak` oracle and does not parse `.uasset` content.

**Hex-anchor policy.** `tests/fixtures/minimal_uasset_v5.uasset` (monolithic v4.27 asset) anchors `uasset.md`. The split-asset fixture `tests/fixtures/real_v8b_split.pak` carries paired `.uasset` + `.uexp` + `.ubulk` entries inside a pak; the executor extracts those entries to anchor `uexp.md`, `ubulk.md`, and `companion-resolution.md`. The three IoStore-style `(none yet)` placeholders are not appropriate here — these are all live formats with real fixtures.

---

## Task 1: Create worktree + verify prerequisites

**Files:** (environment setup only)

- [ ] **Step 1: Confirm PR 1 has merged**

Run: `git fetch origin && git log origin/main --oneline | grep -c "format documentation framework"`
Expected: ≥ 1.

- [ ] **Step 2: Create the worktree from origin/main**

From the primary checkout root:

Run: `git worktree add .claude/worktrees/docs+ue-format-docs-asset -b docs/ue-format-docs-asset origin/main`
Expected: `Preparing worktree (new branch 'docs/ue-format-docs-asset')`.

- [ ] **Step 3: Switch session cwd into the worktree**

Run: `cd .claude/worktrees/docs+ue-format-docs-asset && pwd && git branch --show-current`
Expected: prints the worktree path and `docs/ue-format-docs-asset`.

All subsequent commands run with the worktree as cwd. Do NOT use `git -C` or reach into other worktrees.

- [ ] **Step 4: Verify the framework scaffold is present**

Run: `ls docs/formats/asset/README.md docs/formats/TEMPLATE.md docs/formats/CONVENTIONS.md docs/formats/README.md`
Expected: all four files listed.

- [ ] **Step 5: Build the linter binary**

Run: `cargo build -p paksmith-doc-lint --release`
Expected: clean.

- [ ] **Step 6: Linter smoke-test**

Run: `cargo run -p paksmith-doc-lint --release -- required-headings docs/formats/`
Expected: exits 0.

Run: `cargo run -p paksmith-doc-lint --release -- status-enum docs/formats/README.md`
Expected: exits 0.

- [ ] **Step 7: Extract `.uasset` / `.uexp` / `.ubulk` from the split-asset pak for hex anchoring**

Build the CLI extractor:

Run: `cargo build -p paksmith-cli --release`

List the split-asset pak's entries to confirm the virtual paths:

Run: `cargo run -p paksmith-cli --release -- list tests/fixtures/real_v8b_split.pak`
Expected: shows three entries — the `.uasset`, `.uexp`, and `.ubulk` siblings. Note the virtual paths.

Extract each into a scratch directory for `xxd` reference (the extraction is for executor reference during authoring — these temp files are NOT committed):

Run: `mkdir -p /tmp/paksmith-pr4-fixtures && cargo run -p paksmith-cli --release -- extract tests/fixtures/real_v8b_split.pak /tmp/paksmith-pr4-fixtures`
Expected: extracts three files. Verify with `ls /tmp/paksmith-pr4-fixtures/` — should show the `.uasset`, `.uexp`, `.ubulk` trio.

These extracted files are the reference for the worked-example blocks in Tasks 3, 4, and 6.

No commit — environment setup only.

---

## Task 2: Author `docs/formats/asset/uasset.md`

The flagship of this PR. The summary record alone has ~30 fields with version-conditional reads; the import/export tables are dense records.

**Files:**
- Create: `docs/formats/asset/uasset.md`

**Ground truth references:**
- `crates/paksmith-core/src/asset/summary.rs` (1389 lines) — `PackageSummary`, cap constants, version range, `PKG_UNVERSIONED_PROPERTIES`, `FIRST_UNSUPPORTED_UE5_VERSION`.
- `crates/paksmith-core/src/asset/package.rs` (974 lines) — `Package` orchestration, `MAX_PAYLOAD_BYTES`, `MAX_UEXP_SIZE`, payload reading.
- `crates/paksmith-core/src/asset/import_table.rs` (478 lines) — `ObjectImport`, `ImportTable`, `MAX_IMPORT_TABLE_ENTRIES`.
- `crates/paksmith-core/src/asset/export_table.rs` (1115 lines) — `ObjectExport`, `ExportTable`, `MAX_EXPORT_TABLE_ENTRIES`, `EXPORT_RECORD_SIZE_UE4_27`.
- `crates/paksmith-core/src/asset/version.rs` (236 lines) — `AssetVersion`, the legacy + UE4 + UE5 + licensee version snapshot.

**Oracles:** `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Objects/Package.cs` (primary), `AstralOrigin/unreal_asset/unreal_asset/src/lib.rs` (secondary, paksmith's fixture oracle).

- [ ] **Step 1: Read the parsers for ground truth**

Run: `cat crates/paksmith-core/src/asset/version.rs`
Run: `cat crates/paksmith-core/src/asset/summary.rs | head -200`
Run: `cat crates/paksmith-core/src/asset/import_table.rs | head -100`
Run: `cat crates/paksmith-core/src/asset/export_table.rs | head -150`
Run: `cat crates/paksmith-core/src/asset/package.rs | head -200`

The module-level doc comments carry the most-quoted facts; the cap constants are at the top of each module.

- [ ] **Step 2: Look up oracle SHAs**

Run: `git ls-remote https://github.com/FabianFG/CUE4Parse HEAD | cut -f1` — `<CUE4PARSE_SHA>`.
Run: `git ls-remote https://github.com/AstralOrigin/unreal_asset HEAD | cut -f1` — `<UNREAL_ASSET_SHA>`.

If either repo URL has moved, find the current canonical home via web search.

- [ ] **Step 3: Capture a fresh hex anchor**

Run: `xxd -l 64 tests/fixtures/minimal_uasset_v5.uasset`
Note the first 64 bytes — magic at offset 0, legacy file version at offset 4, then the version snapshot fields. Use these bytes verbatim in the `### Worked example: monolithic v4.27 summary head` block.

- [ ] **Step 4: Write the doc**

Write `docs/formats/asset/uasset.md`:

````markdown
# UAsset (`.uasset`)

> The primary file of a UE package: header, custom-version table, name
> pool, import table, export table, dependency offsets, and (for
> monolithic assets) the export bodies themselves.

## Overview

A `.uasset` file is the entry point for any UE package on disk. It always
contains the package summary (`FPackageFileSummary`), the name pool, the
import table, the export table, and ancillary offset tables for
dependencies and gatherable text. For **monolithic** assets (older UE
versions or specifically-cooked content) it also contains the per-export
property bodies inline. For **split** assets (UE 4.16+ default) the
property bodies live in a sibling `.uexp` file; see
[`companion-resolution.md`](companion-resolution.md) and
[`uexp.md`](uexp.md).

Paksmith parses the header + tables synchronously at `Package::read_from`
time, then walks per-export payloads. The summary's `total_header_size`
field divides "header region" from "payload region" in either layout;
the payload region either lives inline (monolithic) or in the `.uexp`
companion (split).

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| `LegacyFileVersion ∈ {-7, -8, -9}` | Paksmith's accepted legacy-version floor; pre-`-7` archives have a different summary shape and are rejected at parse time. | `CUE4Parse/UE4/Versions/ObjectVersion.cs@<CUE4PARSE_SHA>`[^1] |
| `FileVersionUE4 ∈ [504, 522]` (UE 4.21 – 4.27) | Paksmith's accepted UE4 version range. 504 sets the name-table-with-hash-trailers shape; 522 is UE 4.27's latest object-version constant. | Same[^1] |
| `FileVersionUE5 ∈ [1000, 1010]` (UE 5.0 – 5.1+) | Paksmith's accepted UE5 version range. 1011 (`PROPERTY_TAG_EXTENSION_AND_OVERRIDABLE_SERIALIZATION`) introduces an FPropertyTag wire-format break Phase 2b cannot handle. | Same[^1] |
| 1003 `GENERATE_PUBLIC_HASH` | Adds `generate_public_hash` u32 to each `ObjectExport`. | Same[^1] |
| 1005 `REMOVE_PACKAGE_GUID` | Removes `package_guid` from `ObjectExport`. | Same[^1] |
| 1006 `INHERITED_INSTANCE_DATA_OBJECT` | Adds `is_inherited_instance` bool to each `ObjectExport`. | Same[^1] |
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
| → varies | 4 | LE | `package_flags` | `u32` | `EPackageFlags` mask. `PKG_FilterEditorOnly = 0x8000_0000` set for cooked. `PKG_UnversionedProperties = 0x2000` rejected at this layer (Phase 2b decision). |
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
| → varies | 4 | LE | `searchable_names_offset` | `i32` | |
| → varies | 4 | LE | `thumbnail_table_offset` | `i32` | |
| → varies | 16 | — | `guid` | `FGuid`[^5] | Package identifier. UE5 1016 replaces this with `FIoHash` (outside paksmith's range). |
| (UE4 ≥ 518 & !editor-only-stripped) | 16 | — | `persistent_guid` | `Option<FGuid>` | UE 4.22+ editor builds. |
| (UE4 ∈ [516, 519] & !editor-only-stripped) | 16 | — | `owner_persistent_guid` | `Option<FGuid>` | UE 4.21–4.23 editor builds; removed UE 4.24. |
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
| → varies | 4 | LE | `preload_dependency_count` | `i32` | |
| → varies | 4 | LE | `preload_dependency_offset` | `i32` | |
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
| (UE4 ≥ 520) | 4 | LE | `package_name` | `Option<FName>` | UE 4.26+ only; the package the imported object lives in (replaces `outer` chain walks in some cases). |
| (UE5 ≥ 1007) | 4 | LE | `bImportOptional` | `Option<u8>` | UE5 1007+ only; optional-import flag. |

Row size: 24 bytes (UE4 < 520) / 28 bytes (UE4 ≥ 520) / 29 bytes (UE5 ≥ 1007).

### Export table (`ObjectExport[]`)

Each `ObjectExport` row at offset `export_offset`. The UE 4.27 record is
**104 bytes** (`EXPORT_RECORD_SIZE_UE4_27 = 104`); UE5 adds and removes
fields conditionally:

| offset (within row, UE 4.27) | size | endian | name | type | semantics |
|------------------------------|------|--------|------|------|-----------|
| 0 | 4 | LE | `class_index` | `FPackageIndex`[^7] | Class of the export. |
| 4 | 4 | LE | `super_index` | `FPackageIndex`[^7] | Parent class (inheritance). |
| 8 | 4 | LE | `template_index` | `FPackageIndex`[^7] | Default-template object for instantiation. |
| 12 | 4 | LE | `outer_index` | `FPackageIndex`[^7] | Containing object; `Null` = top-level. |
| 16 | 8 | LE | `object_name` | `FName`[^2] | Export's name. |
| 24 | 4 | LE | `object_flags` | `u32` | `EObjectFlags` mask. |
| 28 | 8 | LE | `serial_size` | `i64` | Byte length of the export's property body. |
| 36 | 8 | LE | `serial_offset` | `i64` | Byte offset of the property body (relative to start of file in monolithic, or stitched buffer in split). |
| 44 | 4 | LE | `b_forced_export` | `u32` | Bool encoded as u32. |
| 48 | 4 | LE | `b_not_for_client` | `u32` | |
| 52 | 4 | LE | `b_not_for_server` | `u32` | |
| (UE5 < 1005) | 16 | — | `package_guid` | `Option<FGuid>`[^5] | Pre-UE5-1005 only; removed at version 1005. |
| 56 | 4 | LE | `package_flags` | `u32` | |
| 60 | 4 | LE | `b_not_always_loaded_for_editor_game` | `u32` | |
| 64 | 4 | LE | `b_is_asset` | `u32` | |
| (UE5 ≥ 1003) | 4 | LE | `generate_public_hash` | `Option<u32>` | UE5 1003+ only. |
| (UE5 ≥ 1006) | 1 | — | `is_inherited_instance` | `Option<u8>` | UE5 1006+ only. |
| 68 | 4 | LE | `first_export_dependency` | `i32` | Index into the preload-dependency table; `-1` = none. |
| 72 | 4 | LE | `serialization_before_serialization_dependencies` | `i32` | Dependency-list length. |
| 76 | 4 | LE | `create_before_serialization_dependencies` | `i32` | |
| 80 | 4 | LE | `serialization_before_create_dependencies` | `i32` | |
| 84 | 4 | LE | `create_before_create_dependencies` | `i32` | |
| (UE5 ≥ 1010 & !PKG_UnversionedProperties) | 8 | LE | `script_serialization_start_offset` | `Option<i64>` | UE5 1010+ AND tagged-property serialization. |
| (UE5 ≥ 1010 & !PKG_UnversionedProperties) | 8 | LE | `script_serialization_end_offset` | `Option<i64>` | UE5 1010+ AND tagged-property serialization. |

UE 4.27 row size: 104 bytes (matches `EXPORT_RECORD_SIZE_UE4_27`).

### Worked example: monolithic v4.27 summary head

```bash
xxd -l 64 tests/fixtures/minimal_uasset_v5.uasset
```

The first 4 bytes are the magic `c1 83 2a 9e` (LE of `0x9E2A83C1`). The
next 4 bytes are the legacy file version (`f9 ff ff ff` = `-7`). The next
4 bytes are the legacy UE3 version (`ff ff ff ff` = `-1`). The next 4
bytes are `file_version_ue4` (`0a 02 00 00` = 522, UE 4.27). The next 4
bytes are `file_version_ue5` (`00 00 00 00` = 0, UE4 archive).

*(Re-run the command in Task 2 Step 3 to capture the bytes; the
hex-anchor CI check will eventually enforce this automatically.)*

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
  See [`../property/tagged.md`](../property/tagged.md).
- **Unversioned** (`PKG_UnversionedProperties` flag set): export bodies
  are a schema-driven bitstream. **Paksmith rejects unversioned packages
  at the summary level** — Phase 2f will introduce a `.usmap` loader and
  unversioned reader.

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
  (`crates/paksmith-core/src/asset/package.rs:43`). Largest single
  per-export payload. Surfaces as
  `AssetParseFault::BoundsExceeded { field: ExportPayloadSize, … }`.
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
    with this flag at the summary level (Phase 2b decision). CUE4Parse
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
covered in [`../property/tagged.md`](../property/tagged.md) and
[`../property/unversioned.md`](../property/unversioned.md).

**Public surface:**
- `pub struct Package` — `read_from(uasset, uexp, asset_path)`,
  `read_from_pak(pak_path, virtual_path)`, `context()`.
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
- `AssetParseFault::UnversionedPropertiesUnsupported` (Phase 2f scopes the fix).
- `AssetParseFault::CompressedChunksUnsupported`.

**Phase plan:** `docs/plans/phase-2a-uasset-header.md`.

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Objects/Package.cs@<CUE4PARSE_SHA>` — primary oracle. Covers `FPackageFileSummary.Serialize`, `ObjectImport.Serialize`, `ObjectExport.Serialize`, and the UE5 1000–1016 version dispatch.
[^2]: `AstralOrigin/unreal_asset/unreal_asset/src/lib.rs@<UNREAL_ASSET_SHA>` — paksmith's fixture-gen oracle. Cross-validated against every `minimal_uasset_v5*` fixture at fixture-gen time.
[^3]: See [`../primitive/fcustom-version.md`](../primitive/fcustom-version.md).
[^4]: See [`../primitive/fstring.md`](../primitive/fstring.md).
[^5]: See [`../primitive/fguid.md`](../primitive/fguid.md).
[^6]: See [`../primitive/fengine-version.md`](../primitive/fengine-version.md).
[^7]: See [`../primitive/fpackage-index.md`](../primitive/fpackage-index.md).
````

- [ ] **Step 5: Lint check**

Run: `cargo run -p paksmith-doc-lint --release -- required-headings docs/formats/`
Expected: exits 0.

- [ ] **Step 6: Commit**

```bash
git add docs/formats/asset/uasset.md
git commit -m "$(cat <<'EOF'
docs(formats): add .uasset reference

Documents the full PackageFileSummary + ImportTable + ExportTable
wire layout, paksmith's version range (UE4 504-522, UE5 1000-1010,
LegacyFileVersion -7/-8/-9), the seven cap constants, and every
known divergence from CUE4Parse + unreal_asset (UE5 1011+ rejection,
PKG_UnversionedProperties rejection, compressed_chunks rejection).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Author `docs/formats/asset/uexp.md`

The export-body sidecar. Wire shape is simple — concatenated tagged-
property streams keyed by the export table's `(serial_offset, serial_size)`
pairs — but the stitching invariant is load-bearing and easy to get wrong.

**Files:**
- Create: `docs/formats/asset/uexp.md`

**Ground truth references:**
- `crates/paksmith-core/src/asset/package.rs:328` — `read_from` stitching.
- `crates/paksmith-core/src/asset/package.rs:43–53` — `MAX_PAYLOAD_BYTES`, `MAX_UEXP_SIZE`.
- `crates/paksmith-core/src/asset/package.rs:414–478` — the four-state companion-detection logic.
- `crates/paksmith-core/src/error.rs:2408+` — `MissingCompanionFile`, `CompanionFileKind`.

- [ ] **Step 1: Read the parser**

Run: `sed -n '270,478p' crates/paksmith-core/src/asset/package.rs`
Note especially the `needs_uexp` computation (line 428), the four-state
table (lines 437–453), and the `SplitAssetSizeMismatch` invariant
(line 465+).

- [ ] **Step 2: Look up oracle SHAs**

Run: `git ls-remote https://github.com/FabianFG/CUE4Parse HEAD | cut -f1` — `<CUE4PARSE_SHA>`.
Run: `git ls-remote https://github.com/AstralOrigin/unreal_asset HEAD | cut -f1` — `<UNREAL_ASSET_SHA>`.

- [ ] **Step 3: Capture a fresh hex anchor**

Run: `xxd -l 32 /tmp/paksmith-pr4-fixtures/Game/Asset.uexp` (substituting the actual virtual path from Task 1 Step 7's `cargo run -- list` output).
Note the first 32 bytes — these begin with the first export's tagged-
property stream. Use them in the worked-example block.

- [ ] **Step 4: Write the doc**

Write `docs/formats/asset/uexp.md`:

````markdown
# UExp (`.uexp`)

> Export-body sidecar for split UE assets — the concatenated property
> streams of every export in a package, keyed by the export table's
> `(serial_offset, serial_size)` pairs.

## Overview

UE 4.16+ default-cooks `.uasset` files **split**: the structural header
(summary + name table + import table + export table + ancillary
offsets) lives in `.uasset` and is truncated at `total_header_size`;
the property bodies of every export are concatenated into a sibling
`.uexp` file.

`.uexp` has no internal structure of its own — it is a flat byte stream.
The export table's `(serial_offset, serial_size)` pairs partition it
into per-export property bodies, which are then decoded by the
tagged-property reader (see [`../property/tagged.md`](../property/tagged.md))
or — eventually — the unversioned-property reader (Phase 2f).

The on-disk file `.uexp` cannot be parsed in isolation: the export
table that names its byte ranges lives in the paired `.uasset`. See
[`companion-resolution.md`](companion-resolution.md) for the
discovery + stitching rules.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| UE 4.16+ | Split-asset cooking introduced; `.uexp` carries the export bodies. Default-on from UE 4.16; some games disable it. | `CUE4Parse/UE4/Assets/Objects/Package.cs@<CUE4PARSE_SHA>`[^1] |

The `.uexp` byte stream's *shape* (concatenated property bodies) is
stable across UE versions; what's *inside* each body changes per the
property-tag and export-table wire-format changes documented under
[`../property/`](../property/README.md) and [`uasset.md`](uasset.md).

## Wire layout

| offset | size | endian | name | type | semantics |
|--------|------|--------|------|------|-----------|
| 0 | filesize | — | `export_bodies` | byte stream | Concatenation of per-export tagged-property streams. Boundaries published by the paired `.uasset`'s export table. |

There is no `.uexp`-level header, magic number, or version field. The
file is purely a payload region.

### Stitching with `.uasset`

Paksmith materializes split assets by concatenating `uasset_bytes ++
uexp_bytes` into a single contiguous buffer. After stitching:

- All export `serial_offset` values point into that combined buffer.
- Offsets in `[0, total_header_size)` resolve inside the `.uasset` half;
  offsets in `[total_header_size, total_header_size + uexp.len())`
  resolve inside the `.uexp` half.
- The reader treats the result identically to a monolithic asset.

The load-bearing invariant: `uasset.len() == total_header_size` for any
split asset. UE writes this exactly. Paksmith verifies it at stitch
time and rejects mismatches as
`AssetParseFault::SplitAssetSizeMismatch { uasset_len, total_header_size }`.

### Worked example: first export body

```bash
# .uexp extracted from tests/fixtures/real_v8b_split.pak
xxd -l 32 /tmp/paksmith-pr4-fixtures/<path-to-uexp>
```

The first bytes are the first export's `FPropertyTag` stream — a tag
name, type name, body size, and the tag's body. See
[`../property/tagged.md`](../property/tagged.md) for the per-tag
decode procedure.

*(Re-run the extraction step in Task 1 Step 7 to materialize the
fixture's `.uexp`; the hex-anchor CI check will eventually enforce
the bytes.)*

## Variants

None on the wire — `.uexp` is structureless. Variation comes from
*what's inside* each export body, which is per-property and is
governed by the property family of docs.

## Caps & limits

- **`MAX_UEXP_SIZE = 1 GiB`**
  (`crates/paksmith-core/src/asset/package.rs:53`). Largest acceptable
  `.uexp` size. Enforced before any allocation runs to prevent a
  malicious pak entry from forcing a multi-GiB combined-buffer
  reservation. Surfaces as
  `AssetParseFault::BoundsExceeded { field: UexpSize, value, limit, unit: Bytes }`.
- **Combined `.uasset + .uexp` size** must fit in `usize` on the host
  platform — protects against 32-bit-target overflow.
- **Per-export payload caps** (`MAX_PAYLOAD_BYTES = 256 MiB`) apply
  to bodies *within* the stitched buffer; they live with the
  `.uasset` doc rather than here.

See `docs/security/allocation-caps.md` for the broader allocation-cap
policy.

## Verification

- **Fixture:** `tests/fixtures/real_v8b_split.pak` contains a
  `.uasset` + `.uexp` + `.ubulk` trio. Extract with
  `paksmith extract tests/fixtures/real_v8b_split.pak <dest>` (see
  Task 1 Step 7 of this PR's plan).
- **Cross-validation oracle:** `unreal_asset`[^2] (split-asset
  fixture-gen confirms paksmith's stitching produces a buffer
  semantically identical to unreal_asset's monolithic-form output) and
  CUE4Parse[^1].
- **Known divergences:** none on the wire — `.uexp` is structureless,
  and paksmith's stitching produces byte-identical input to the
  per-property reader as both oracles do.

## Paksmith implementation

**Parser module:** `.uexp` reading is integrated into
`crates/paksmith-core/src/asset/package.rs` (`Package::read_from`,
`Package::read_from_pak`). There is no standalone `.uexp` parser —
the byte stream is consumed by the stitching step and then by the
per-export payload reader.

**Status:** `complete`.

**Public surface:**
- `Package::read_from(uasset: &[u8], uexp: Option<&[u8]>, asset_path: &str) -> Result<Self>` —
  caller supplies both halves; `uexp` is `None` for monolithic, `Some` for split.
- `Package::read_from_pak(pak_path, virtual_path) -> Result<Self>` —
  convenience wrapper that resolves the `.uexp` companion via the pak
  reader (see [`companion-resolution.md`](companion-resolution.md)).

**Error variants:**
- `AssetParseFault::MissingCompanionFile { kind: CompanionFileKind::Uexp }` —
  any export's payload extends past `uasset.len()` and no `.uexp`
  was provided.
- `AssetParseFault::SplitAssetSizeMismatch { uasset_len, total_header_size }` —
  the invariant `uasset.len() == total_header_size` is violated.
- `AssetParseFault::BoundsExceeded { field: AssetWireField::UexpSize, … }` —
  `.uexp` size exceeds `MAX_UEXP_SIZE`.

**Cap constants:**
- `MAX_UEXP_SIZE: usize = 1 GiB` (`asset/package.rs:53`).

**Phase plan:**
- `.uexp` companion stitching: `docs/plans/phase-2e-companion-files.md`
  (Task 1 — Phase 2e PR #316).
- `.uexp` lookup in pak (`read_from_pak`):
  `docs/plans/phase-2e-companion-files.md` (Task 4 — Phase 2e PR #317).

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Objects/Package.cs@<CUE4PARSE_SHA>` — primary oracle for the split-asset stitching convention.
[^2]: `AstralOrigin/unreal_asset/unreal_asset/src/lib.rs@<UNREAL_ASSET_SHA>` — paksmith's fixture-gen oracle. Confirms stitched-buffer semantic equivalence on every split-asset fixture.
````

- [ ] **Step 5: Lint check**

Run: `cargo run -p paksmith-doc-lint --release -- required-headings docs/formats/`
Expected: exits 0.

- [ ] **Step 6: Commit**

```bash
git add docs/formats/asset/uexp.md
git commit -m "$(cat <<'EOF'
docs(formats): add .uexp reference

Documents the structureless export-body sidecar, the
uasset.len() == total_header_size invariant, the MAX_UEXP_SIZE cap,
and the four error variants Phase 2e introduced
(MissingCompanionFile, SplitAssetSizeMismatch, BoundsExceeded,
plus the implicit usize-overflow guard for the combined buffer).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Author `docs/formats/asset/ubulk.md` (partial)

`.ubulk` carries bulk-data payloads (large texture mips, audio bodies)
streamed separately. Paksmith currently *detects* a `.ubulk` companion
and logs a warning; **reading** the payload is a Phase 3+ deliverable.
This makes the doc `partial`: wire shape and detection are documented,
but caps and full Verification reference unimplemented work.

**Files:**
- Create: `docs/formats/asset/ubulk.md`

**Ground truth references:**
- `crates/paksmith-core/src/asset/package.rs:560–569` — current
  detection + warning behavior in `Package::read_from_pak`.
- `crates/paksmith-core/src/error.rs:2962+` — `CompanionFileKind::Ubulk`.

- [ ] **Step 1: Look up oracle SHAs**

Run: `git ls-remote https://github.com/FabianFG/CUE4Parse HEAD | cut -f1` — `<CUE4PARSE_SHA>`.
Run: `git ls-remote https://github.com/AstralOrigin/unreal_asset HEAD | cut -f1` — `<UNREAL_ASSET_SHA>`.

- [ ] **Step 2: Capture a fresh hex anchor**

Run: `xxd -l 16 /tmp/paksmith-pr4-fixtures/<path-to-ubulk>`
Note the first 16 bytes for the worked-example block. The bytes are
opaque (texture mip data, audio buffer, etc.); the value of the hex
anchor here is "yes, this is unstructured payload bytes — no header
to parse".

- [ ] **Step 3: Write the doc**

Write `docs/formats/asset/ubulk.md`:

````markdown
# UBulk (`.ubulk`)

> Bulk-data sidecar for UE assets — large payloads (texture mips, audio
> bodies, animation streams) that the engine streams separately from
> the main `.uasset` / `.uexp`.

## Overview

`.ubulk` holds the bulk-data payloads referenced by a UE asset:
high-resolution texture mip chains, audio sample buffers, animation
streaming data, anything large enough that the engine wants to demand-
load it rather than carrying it inline. The format is structureless —
a flat byte stream whose interpretation depends entirely on the
asset's bulk-data records (which live in `.uasset`).

Multiple bulk-data records inside one `.uasset` carve `.ubulk` into
per-record byte ranges with `(offset, size, compression-method, flags)`
metadata. The records carry the structure; the file carries the bytes.

**Paksmith status: detection-only** (Phase 2e PR #317). The pak reader
notices when a sibling `.ubulk` exists and emits a `tracing::warn!`
event so operators see the "this asset has bulk data we're not yet
reading" signal. Phase 3+ will replace detection with real bulk-data
stitching and per-record decode (textures, audio, anim).

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| All UE4 + UE5 | Structureless byte stream; the wire shape is "whatever the `.uasset`'s `FByteBulkData` records say". The shape of the records evolves (compression flags, offset width), not the `.ubulk` itself. | `CUE4Parse/UE4/Assets/Objects/Package.cs@<CUE4PARSE_SHA>`[^1] |

`.ubulk` as a file has no version field; record-shape variance lives
inside the parent `.uasset`'s bulk-data records.

## Wire layout

| offset | size | endian | name | type | semantics |
|--------|------|--------|------|------|-----------|
| 0 | filesize | — | `bulk_records` | byte stream | Concatenation of bulk-data record payloads. Boundaries published by the `.uasset`'s bulk-data records, not by any structure in this file. |

A bulk-data record's payload may itself be compression-block-framed
(matching `.pak`'s entry compression — see
[`../compression/pak-block-framing.md`](../compression/pak-block-framing.md))
or AES-encrypted; the per-record flags in `.uasset` drive that decode.

### Worked example: first bytes of a `.ubulk`

```bash
# .ubulk extracted from tests/fixtures/real_v8b_split.pak
xxd -l 16 /tmp/paksmith-pr4-fixtures/<path-to-ubulk>
```

The bytes are opaque payload data — without the parent `.uasset`'s
bulk-data records this stream has no decode procedure. The value of
this anchor is to make the "structureless payload" claim verifiable.

*(Re-run the extraction step in Task 1 Step 7 to materialize the
fixture's `.ubulk`.)*

## Variants

None on the wire — `.ubulk` is structureless. Variation comes from
the bulk-data records inside the parent `.uasset`, which paksmith
will document under `texture/`, `audio/`, etc. as those families
get Phase 3+ implementation work.

## Caps & limits

**Detection only — no caps enforced yet.** Phase 3+ will add caps
mirroring the pak side:
- A per-record uncompressed-size cap (analog to `MAX_UNCOMPRESSED_ENTRY_BYTES`
  in the pak reader).
- A total `.ubulk` file-size cap (analog to `MAX_UEXP_SIZE` for the
  `.uexp` companion).
- Compression-block-framing caps applied to compressed records.

See `docs/security/allocation-caps.md` for the broader policy that
the future caps will follow.

## Verification

- **Fixture:** `tests/fixtures/real_v8b_split.pak` contains a `.ubulk`
  entry alongside the split asset's `.uasset` + `.uexp`. Extract with
  `paksmith extract` (see Task 1 Step 7).
- **Cross-validation oracle:** CUE4Parse[^1] and `unreal_asset`[^2].
  Phase 3+ work will cross-validate paksmith's per-record reader
  against both.
- **Known divergences:**
  - **No paksmith reader yet.** CUE4Parse and unreal_asset read
    `.ubulk` payloads (driven by `FByteBulkData` records). Paksmith
    currently only detects existence and warns; bulk-data records in
    parsed `.uasset` packages carry their `.ubulk` offsets in the
    summary's `bulk_data_start_offset` field but the payloads aren't
    materialized.

## Paksmith implementation

**Parser module:** detection logic in
`crates/paksmith-core/src/asset/package.rs` (`Package::read_from_pak`,
lines ~560–569). No standalone bulk-data reader yet.

**Status:** `partial` (detection ships; payload reading deferred to
Phase 3+).

**Public surface:**
- `Package::read_from_pak(pak_path, virtual_path)` — detects sibling
  `.ubulk` via `PakReader::index_entry()` (O(1) probe; no decompression)
  and emits a `tracing::warn!` event if present. No API exposed for
  reading the bulk-data payload.

**Error variants:**
- `AssetParseFault::MissingCompanionFile { kind: CompanionFileKind::Ubulk }` —
  defined in `crates/paksmith-core/src/error.rs:2962+` for future use.
  Currently inert: detection treats a missing `.ubulk` as expected and
  detection of a present `.ubulk` triggers a warn, not an error.

**Cap constants:** none yet (Phase 3+ deliverable).

**Phase plan:**
- Detection: `docs/plans/phase-2e-companion-files.md` (Task 4 —
  Phase 2e PR #317).
- Payload reading: `docs/plans/ROADMAP.md` Phase 3 (Export Pipeline).

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Objects/Package.cs@<CUE4PARSE_SHA>` — primary oracle. The `FByteBulkData.Serialize` family covers the in-`.uasset` records that drive `.ubulk` decoding.
[^2]: `AstralOrigin/unreal_asset/unreal_asset/src/lib.rs@<UNREAL_ASSET_SHA>` — Rust oracle. Bulk-data reading is supported here; paksmith will cross-validate against it when Phase 3+ implements the reader.
````

- [ ] **Step 4: Lint check**

Run: `cargo run -p paksmith-doc-lint --release -- required-headings docs/formats/`
Expected: exits 0.

- [ ] **Step 5: Commit**

```bash
git add docs/formats/asset/ubulk.md
git commit -m "$(cat <<'EOF'
docs(formats): add .ubulk partial reference

Documents the structureless bulk-data sidecar's wire shape (a flat
byte stream whose decode procedure lives in the parent .uasset's
bulk-data records), paksmith's current detection-only behavior,
and the Phase 3+ work that will replace detection with real
per-record reading. Caps section is intentionally empty pending
Phase 3+, making this partial rather than complete.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Author `docs/formats/asset/companion-resolution.md`

The cross-cutting reference that explains how the three asset files
discover each other. Sits on top of the four-state companion-detection
table inside `Package::read_from`. Phase 2e shipped this end-to-end.

**Files:**
- Create: `docs/formats/asset/companion-resolution.md`

**Ground truth references:**
- `crates/paksmith-core/src/asset/package.rs:274–288` — `derive_companion_path`.
- `crates/paksmith-core/src/asset/package.rs:414–478` — four-state detection table inside `Package::read_from`.
- `crates/paksmith-core/src/asset/package.rs:532–571` — pak-side resolution in `Package::read_from_pak`.

- [ ] **Step 1: Read the parsers**

Run: `sed -n '274,478p' crates/paksmith-core/src/asset/package.rs`
Run: `sed -n '532,571p' crates/paksmith-core/src/asset/package.rs`

- [ ] **Step 2: Look up oracle SHAs**

Run: `git ls-remote https://github.com/FabianFG/CUE4Parse HEAD | cut -f1` — `<CUE4PARSE_SHA>`.

- [ ] **Step 3: Write the doc**

Write `docs/formats/asset/companion-resolution.md`:

````markdown
# Companion file resolution

> How paksmith locates the `.uexp` and `.ubulk` siblings of a `.uasset`
> across loose files, pak entries, and IoStore chunks (planned).

## Overview

A UE package on disk is one to three files:

- `.uasset` — header + tables, always present.
- `.uexp` — export bodies, present for split assets (UE 4.16+ default).
- `.ubulk` — bulk-data payloads, present when the asset has bulk records.

The three siblings share a path prefix and differ only in extension.
Resolution comes down to: take the `.uasset` path, swap the extension,
look up the result in the same container the `.uasset` came from.

Paksmith implements three resolution flows:

1. **In-memory** — caller provides bytes for both `.uasset` and (optional) `.uexp`.
   No file I/O, no path resolution; the caller has already decided which
   buffer is which. This is the lowest-level API.
2. **Pak archive** — caller provides a `PakReader` and a virtual path to a
   `.uasset` entry; paksmith derives sibling virtual paths and looks them
   up in the pak index.
3. **Loose filesystem** *(planned)* — caller provides a `.uasset` path on
   disk; paksmith reads the file and probes for sibling files with the
   same prefix and the `.uexp` / `.ubulk` extensions.

The split-vs-monolithic dispatch and the per-flow lookup are unified by
the same four-state table at the core of `Package::read_from`.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| UE 4.16+ | Split-asset cooking introduced; `.uexp` siblings became expected by default. | `CUE4Parse/UE4/Assets/Objects/Package.cs@<CUE4PARSE_SHA>`[^1] |
| All UE4 + UE5 | `.ubulk` siblings predate the split convention; the path-derivation rules have been stable since UE4 0.0. | Same[^1] |

There is no version-conditional change to the resolution rules
themselves — the path-derivation (swap extension) and the four-state
detection logic are version-agnostic. Per-file wire-format changes
live in [`uasset.md`](uasset.md), [`uexp.md`](uexp.md), and
[`ubulk.md`](ubulk.md).

## Wire layout

There is no on-wire structure to resolution — this doc covers a
procedure that operates on filesystem paths and pak virtual paths.

### Path derivation

```rust
fn derive_companion_path(base: &str, new_ext: &str) -> String
```

Implementation (`crates/paksmith-core/src/asset/package.rs:279`): strip
the trailing `.<ext>` from `base` and append `new_ext`. Examples:

| Input `.uasset` path | Companion ext | Derived path |
|----------------------|---------------|---------------|
| `Game/Weapons/Sword.uasset` | `.uexp` | `Game/Weapons/Sword.uexp` |
| `Game/Weapons/Sword.uasset` | `.ubulk` | `Game/Weapons/Sword.ubulk` |
| `ContentRoot/Map.umap` | `.uexp` | `ContentRoot/Map.uexp` |

UE writers always emit siblings with this exact prefix relationship.
No casing variance, no directory traversal — the derived path is the
companion's path.

### Four-state companion-detection table

Inside `Package::read_from`, the dispatch on `(needs_uexp, uexp_provided)`
yields four cases:

| `needs_uexp` (any export's payload extends past `uasset.len()`) | `uexp_provided` (caller supplied `Some(&uexp)`) | Outcome |
|---|---|---|
| false | None | Monolithic asset. Borrow `uasset` as the single buffer; no stitch. |
| false | Some | **Warn** ("extra `.uexp` provided for a monolithic asset; ignoring") and proceed as monolithic. The extra buffer is dropped. |
| true | Some | Split asset. Stitch `uasset ++ uexp` into a combined buffer; verify `uasset.len() == total_header_size` (`SplitAssetSizeMismatch` if not). |
| true | None | **Reject** with `AssetParseFault::MissingCompanionFile { kind: CompanionFileKind::Uexp }`. |

`needs_uexp` is determined by walking the export table and asking
whether any export's `(serial_offset + serial_size)` extends past
`uasset.len()`. This is the structural discriminator between
monolithic and split; using `total_header_size` would be tautological
(it always equals `uasset.len()` in a split asset by definition).

### Pak-archive resolution flow

`Package::read_from_pak(pak_path, virtual_path)`:

1. Open the pak.
2. Read the `.uasset` entry at `virtual_path`.
3. Derive the `.uexp` sibling path; attempt `read_entry`. Three outcomes:
   - `Ok(bytes)` → pass `Some(&bytes)` to `Package::read_from`.
   - `Err(EntryNotFound)` → pass `None` (monolithic).
   - any other error → propagate.
4. Derive the `.ubulk` sibling path; probe with `index_entry()` (O(1)
   hashmap probe, no decompression).
   - Present → emit `tracing::warn!` ("`.ubulk` present but stitching
     not yet implemented").
   - Absent → silent; monolithic-without-bulk is normal.
5. Hand both buffers (and `virtual_path` as the asset_path tag) to
   `Package::read_from`.

The `.ubulk` probe uses `index_entry` rather than `read_entry`
deliberately — `read_entry` would decompress and allocate the full
bulk payload only to discard it, which is wasteful when all we need
is presence/absence.

## Variants

### Loose filesystem flow (planned)

Paksmith does not yet expose `Package::read_from_path` for loose-file
input. When it lands, the resolution will mirror the pak flow:

1. Read the `.uasset` file.
2. Derive sibling paths via `derive_companion_path`.
3. For each sibling: probe with `std::fs::metadata`; on success, read.
4. Hand the buffers to `Package::read_from`.

The four-state table applies identically.

### IoStore flow (planned)

Phase 8's IoStore support will require its own resolution flow because
IoStore packages are referenced by chunk IDs, not virtual paths. The
TOC publishes a chunk per logical file, with separate `IoChunkType`s
for `ExportBundleData`, `BulkData`, `OptionalBulkData`, etc.
Resolution becomes "look up the matching chunk ID via `EIoChunkType`"
rather than "swap the path extension".

## Caps & limits

- **`MAX_UEXP_SIZE = 1 GiB`** — enforced when a `.uexp` is provided.
  See [`uexp.md`](uexp.md).
- **Combined `uasset.len() + uexp.len()` overflow** — paksmith checks
  for `usize` overflow on the combined-buffer reservation before
  allocating; surfaces as `AssetParseFault::BoundsExceeded` with the
  appropriate field.
- **No `.ubulk` cap yet** — detection-only at present. See
  [`ubulk.md`](ubulk.md).

## Verification

- **Fixtures:**
  - `tests/fixtures/minimal_uasset_v5.uasset` — monolithic case
    (no companion needed).
  - `tests/fixtures/real_v8b_split.pak` — split-asset case (all three
    siblings present inside the pak).
- **Cross-validation oracle:** CUE4Parse[^1] follows the identical
  path-derivation convention (swap extension); the four-state
  detection is paksmith's own elaboration, with the rejection cases
  matching what CUE4Parse implicitly handles (CUE4Parse fails harder
  on `MissingCompanionFile`-equivalent situations by erroring during
  buffer access rather than at a structured detection point).
- **Known divergences:**
  - **Monolithic-with-extra-uexp behavior.** Paksmith warns and
    discards the extra buffer. CUE4Parse and unreal_asset don't
    expose an analog of this call shape (their APIs take a path,
    not buffers), so the divergence is API-shape-only.

## Paksmith implementation

**Parser module:** `crates/paksmith-core/src/asset/package.rs`.

**Status:** `complete` for the in-memory and pak-archive flows.
`partial` overall pending the loose-filesystem and IoStore flows
(both deferred to later phases).

**Public surface:**
- `Package::read_from(uasset: &[u8], uexp: Option<&[u8]>, asset_path: &str) -> Result<Self>` —
  in-memory flow with explicit buffers.
- `Package::read_from_pak<P: AsRef<Path>>(pak_path: P, virtual_path: &str) -> Result<Self>` —
  pak-archive flow.
- `fn derive_companion_path(base: &str, new_ext: &str) -> String` —
  pub(super); helper used by both flows.

**Error variants:**
- `AssetParseFault::MissingCompanionFile { kind: CompanionFileKind }` —
  `Uexp` is live; `Ubulk` is defined but currently inert (detection,
  not error).
- `AssetParseFault::SplitAssetSizeMismatch { uasset_len, total_header_size }`.
- `AssetParseFault::BoundsExceeded { field: AssetWireField::UexpSize, … }`.

**Phase plan:**
- In-memory flow + four-state detection: `docs/plans/phase-2e-companion-files.md`
  (Task 1 — Phase 2e PR #316).
- Pak-archive flow: same plan (Task 4 — Phase 2e PR #317).
- Loose-filesystem flow: not yet planned.
- IoStore flow: `docs/plans/ROADMAP.md` Phase 8.

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Objects/Package.cs@<CUE4PARSE_SHA>` — primary oracle. CUE4Parse's package loader follows the same `(swap-extension, look-up-in-container)` convention paksmith implements.
````

- [ ] **Step 4: Lint check**

Run: `cargo run -p paksmith-doc-lint --release -- required-headings docs/formats/`
Expected: exits 0.

- [ ] **Step 5: Commit**

```bash
git add docs/formats/asset/companion-resolution.md
git commit -m "$(cat <<'EOF'
docs(formats): add companion-resolution reference

Documents the path-derivation (swap-extension) convention, the
four-state companion-detection table at the core of
Package::read_from, and the per-container resolution flows (in-
memory + pak-archive shipped; loose filesystem + IoStore planned).
Explains the .ubulk index_entry probe (vs read_entry) rationale
and the monolithic-with-extra-uexp warn-and-discard behavior.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: Update root inventory + final verification + push

**Files:**
- Modify: `docs/formats/README.md`

- [ ] **Step 1: Capture branch HEAD + oracle SHAs**

Run: `git rev-parse --short HEAD` — note as `<SHA>`.
Run: `git ls-remote https://github.com/FabianFG/CUE4Parse HEAD | cut -f1` — `<CUE4PARSE_SHA>`.
Run: `git ls-remote https://github.com/AstralOrigin/unreal_asset HEAD | cut -f1` — `<UNREAL_ASSET_SHA>`.

Use the same SHAs the per-doc commits cited, so inventory and doc references agree.

- [ ] **Step 2: Add four rows to the inventory table**

Use the Edit tool to insert the four rows. Verify the existing inventory layout first with `grep -n "^|" docs/formats/README.md` and find a suitable insertion anchor.

Rows to insert:

```markdown
| `asset/uasset.md` | complete | complete | `asset/` | unreal_asset @ `<UNREAL_ASSET_SHA>` | `<SHA>` |
| `asset/uexp.md` | complete | complete | `asset/package.rs` | unreal_asset @ `<UNREAL_ASSET_SHA>` | `<SHA>` |
| `asset/ubulk.md` | partial | partial | `asset/package.rs` | CUE4Parse @ `<CUE4PARSE_SHA>` | `<SHA>` |
| `asset/companion-resolution.md` | complete | complete | `asset/package.rs` | CUE4Parse @ `<CUE4PARSE_SHA>` | `<SHA>` |
```

Note: `ubulk.md` is `partial | partial` — doc is partial (Caps section
empty), parser is partial (detection but no payload reading). This is
the most-honest combination given the Phase 2e detection + Phase 3+
deferred reading split.

- [ ] **Step 3: Run the status-enum linter**

Run: `cargo run -p paksmith-doc-lint --release -- status-enum docs/formats/README.md`
Expected: exits 0. The `partial | partial` ubulk row is clean (matched
labels — no smell-warn combinations). The three `complete | complete`
rows are also clean.

- [ ] **Step 4: Run the required-headings linter against all docs**

Run: `cargo run -p paksmith-doc-lint --release -- required-headings docs/formats/`
Expected: exits 0.

- [ ] **Step 5: Verify the file tree matches the inventory**

Run: `ls docs/formats/asset/*.md | sort`
Expected:
```
docs/formats/asset/README.md
docs/formats/asset/companion-resolution.md
docs/formats/asset/ubulk.md
docs/formats/asset/uasset.md
docs/formats/asset/uexp.md
```

Run: `grep -c "asset/uasset.md\|asset/uexp.md\|asset/ubulk.md\|asset/companion-resolution.md" docs/formats/README.md`
Expected: 4.

- [ ] **Step 6: Run typos against the new docs**

Run: `typos docs/formats/asset/`
Expected: clean. Domain terms like `FName`, `FPropertyTag`, `UStruct` are
likely to flag — extend `_typos.toml` only when reword isn't possible.

- [ ] **Step 7: Run `cargo doc -D warnings`**

Run: `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features`
Expected: clean (no Rust changed in this PR).

- [ ] **Step 8: Commit the inventory update**

```bash
git add docs/formats/README.md
git commit -m "$(cat <<'EOF'
docs(formats): register the asset-family docs in the inventory

Three complete-complete rows (uasset, uexp, companion-resolution)
and one partial-partial row (ubulk — detection but no payload
reading yet). Last-verified anchor for all four is this branch's
HEAD; the partial-partial ubulk pairing is the most-honest label
for the Phase 2e detection + Phase 3+ deferred payload split.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 9: Inspect the commit log**

Run: `git log --oneline origin/main..HEAD`
Expected: 5 commits (newest first):

```
<sha> docs(formats): register the asset-family docs in the inventory
<sha> docs(formats): add companion-resolution reference
<sha> docs(formats): add .ubulk partial reference
<sha> docs(formats): add .uexp reference
<sha> docs(formats): add .uasset reference
```

- [ ] **Step 10: Push the branch**

Run: `git push -u origin docs/ue-format-docs-asset`

- [ ] **Step 11: Open the PR**

Title: `docs(formats): populate asset family (.uasset/.uexp/.ubulk/companion-resolution)`

Body — write to a tempfile first, then `gh pr create --body-file <tempfile>`:

```markdown
## Summary

Lands PR 4 of the UE format documentation framework. Populates
`docs/formats/asset/` with four documents:

- **`uasset.md`** — full byte-level reference for `FPackageFileSummary`
  + `ImportTable` + `ExportTable`. Documents the 7 cap constants, the
  accepted version range (UE4 504–522, UE5 1000–1010, LegacyFileVersion
  -7/-8/-9), and every known divergence (UE5 1011+ rejection,
  PKG_UnversionedProperties rejection, compressed_chunks rejection).
- **`uexp.md`** — structureless export-body sidecar. Documents the
  stitching invariant (`uasset.len() == total_header_size`),
  `MAX_UEXP_SIZE = 1 GiB`, and Phase 2e's four error variants.
- **`ubulk.md`** — bulk-data sidecar with **partial** status: the doc
  covers wire shape and Phase 2e's detection-only behavior; Caps and
  full Verification are explicitly Phase 3+ deliverables.
- **`companion-resolution.md`** — cross-file resolution rules. The
  four-state detection table at the core of `Package::read_from`, the
  path-derivation convention, the `.ubulk` `index_entry`-vs-`read_entry`
  rationale, and the planned IoStore + loose-filesystem flows.

Four rows added to the root inventory: three `complete | complete` and
one `partial | partial` (ubulk).

## Linked issue

(none — design spec drives this work)

## Test plan

- [x] `paksmith-doc-lint required-headings` passes on all docs.
- [x] `paksmith-doc-lint status-enum` passes on the updated inventory.
- [x] `typos docs/formats/asset/` clean.
- [x] `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features` clean.
- [x] Cross-validated every wire-format claim against CUE4Parse + unreal_asset.

## Pre-flight checklist

- [x] PR title is a Conventional Commit.
- [x] Branch name follows `<type>/<kebab-case>`.
- [x] `cargo fmt --all` clean (no Rust changed).
- [x] `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean.
- [x] Documentation updated (this PR IS documentation).
- [x] No `unsafe` introduced.
- [x] Touched a parser? No — pure docs PR.

## Security considerations

None directly — pure documentation. Each doc spells out paksmith's
security posture explicitly:
- `uasset.md`: every cap referenced (`MAX_TOTAL_HEADER_SIZE`,
  `MAX_PAYLOAD_BYTES`, `MAX_*_TABLE_ENTRIES`, …) plus the
  `PKG_UnversionedProperties` and `compressed_chunks` rejections.
- `uexp.md`: `MAX_UEXP_SIZE` cap, combined-buffer `usize` overflow
  guard, `SplitAssetSizeMismatch` invariant.
- `ubulk.md`: explicit "no caps yet — Phase 3+ deliverable" note,
  with the future cap shape sketched.
- `companion-resolution.md`: the rationale for `index_entry` over
  `read_entry` on the `.ubulk` probe (decompression-amplification
  avoidance).

## Notes for reviewers

- `ubulk.md` is `partial | partial`. The wire shape is documented; the
  Caps section is explicitly deferred to Phase 3+. This is the most-
  honest label combination — the doc reflects what paksmith currently
  does (detection only), and the parser status matches.
- The `uasset.md` worked-example bytes come from
  `tests/fixtures/minimal_uasset_v5.uasset` (UE 4.27 monolithic). The
  `.uexp` / `.ubulk` examples come from
  `tests/fixtures/real_v8b_split.pak` extracted via `paksmith extract`
  (see Task 1 Step 7 of the implementation plan).
- The `uasset.md` Wire layout section spells out the UE5 version
  conditional reads in dedicated rows (`soft_object_paths_*`,
  `localization_id`, `data_resource_offset`, etc.). This is
  load-bearing: anyone implementing a UE5 parser from this doc must
  see the conditional gates, not be tripped up by them.
```

- [ ] **Step 12: Run the standard reviewer panel**

Dispatch in a SINGLE message with multiple Agent tool calls:

- code-reviewer (general quality + spec adherence + factual accuracy against parser source)
- code-architect (oracle citations sound, version-conditional gates documented correctly, no fabricated UE5 1011+ behavior)
- code-simplifier (Wire layout tables aren't over-explained, prose is tight)

Address issues, re-run the panel on the fix commit, repeat until every
reviewer says APPROVED.

---

## Done criteria

- 5 commits on `docs/ue-format-docs-asset` (one per doc + inventory).
- `paksmith-doc-lint required-headings docs/formats/` exits 0.
- `paksmith-doc-lint status-enum docs/formats/README.md` exits 0.
- `typos docs/formats/asset/` clean.
- `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features` clean.
- PR open with `--body-file`-generated body and lowercase verb-first title.
- Reviewer panel converged.
- Four rows present in `docs/formats/README.md` inventory: three
  `complete | complete` (uasset, uexp, companion-resolution) and one
  `partial | partial` (ubulk).
