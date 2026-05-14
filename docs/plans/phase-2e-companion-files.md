# Paksmith Phase 2e: Companion Files & Object Resolution

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable parsing of split assets (`.uasset` header + `.uexp` payload pair stored as separate pak entries), and resolve `ObjectProperty` package indices to human-readable names using the import/export tables.

**Architecture:** `Package::read_from` gains an `Option<uexp: &[u8]>` parameter; if `Some`, the bytes are concatenated before parsing so the existing cursor-seek logic works without change. After the header is parsed (which gives `total_header_size`), four states are handled: split-and-stitched (proceed), split-but-missing-uexp (error), monolithic-and-extra-uexp (warn+ignore), monolithic-no-uexp (proceed). `Package::read_from_pak` looks up the `.uexp` and `.ubulk` siblings from the pak; `.ubulk` is detected and warned but not stitched. A new `resolve_package_index` helper in `primitives.rs` resolves an `i32` package index through `AssetContext.imports`/`.exports` to a `String`; `PropertyValue::Object` gains a `name: String` field as a delta from Phase 2d's `{ index: i32 }` definition. The `build_minimal_ue4_27_split` fixture splits the header and payload into two separate byte slices; `paksmith-fixture-gen` stores them as distinct pak entries and cross-validates through `unreal_asset`'s `Asset::new(asset_data, Some(bulk_data), ...)` form.

**Tech Stack:** Same as Phase 2d — Rust 1.85, `thiserror`, `byteorder` (LE), `serde`, `tracing`, `proptest`, `unreal_asset` (fixture-gen oracle, pinned to `f4df5d8e`). No new crate dependencies.

---

## Deliverable

`paksmith inspect <pak> <virtual/path>` now resolves object references to names and transparently handles split assets. Example JSON:

```json
{
  "asset_path": "Game/Data/Hero.uasset",
  "exports": [
    {
      "object_name": "Hero",
      "properties": [
        {
          "name": "MeshRef",
          "value": {
            "Object": { "index": -1, "name": "/Game/Meshes/Sword.StaticMesh" }
          }
        },
        {
          "name": "NullRef",
          "value": { "Object": { "index": 0, "name": "" } }
        }
      ]
    }
  ]
}
```

The split-asset pak (`tests/fixtures/real_v8b_split.pak`) has `Game/Maps/Demo.uasset` (header only) and `Game/Maps/Demo.uexp` (payload) as separate entries. `paksmith inspect real_v8b_split.pak Game/Maps/Demo.uasset` parses identically to the monolithic fixture.

## Scope vs. deferred work

**In scope (this plan):**

- `.uexp` companion file detection and byte stitching
- `AssetParseFault::MissingCompanionFile { kind: CompanionFileKind }` — fires when any export's `serial_offset >= total_header_size` but no `.uexp` was found in the pak
- `CompanionFileKind` enum: `Uexp` (and `Ubulk` for display-completeness, even though ubulk is not stitched)
- `.ubulk` detection in `read_from_pak` → `tracing::warn!` only; bytes not stitched
- Four-state companion logic in `Package::read_from` (after header parse):
  - Missing uexp, export needs it → `MissingCompanionFile` error
  - Has uexp, export needs it → stitch + proceed
  - Has uexp, no export needs it → `tracing::warn!` + proceed (extra bytes ignored)
  - No uexp, no export needs it → monolithic, proceed unchanged
- `resolve_package_index(index, ctx, asset_path)` helper in `primitives.rs`
- `PropertyValue::Object` gains `name: String` (migration from Phase 2d's `{ index: i32 }`)
- `read_primitive_value` and `read_element_value` both call `resolve_package_index` for ObjectProperty
- `build_minimal_ue4_27_split() -> (Vec<u8>, Vec<u8>)` test fixture (uasset header bytes + uexp payload bytes)
- `MinimalPackage.total_header_size: usize` to support the split builder
- `tests/fixtures/real_v8b_split.pak` — generated fixture with two entries
- fixture-gen oracle cross-validation for split assets using `Asset::new(Some(bulk_data))`
- Integration tests: 4 companion states + ObjectProperty null/import/export/OOB resolution
- CLI insta snapshot updated for `Object { index, name }` shape

**Explicitly deferred:**

- `.ubulk` payload stitching — moved to Phase 3; bulk data (texture mips, mesh LODs) has no consumer until the export pipeline lands, and the chunk-offset arithmetic belongs alongside the handlers that actually read it
- `StructProperty` as a collection element — wire format requires a separate empirical verification pass (see `memory/feedback_verify_wire_format_claims.md`)
- Unversioned properties (`PKG_UnversionedProperties`) — Phase 2f

## Design decisions locked here

1. **`PropertyValue::Object` delta:** Phase 2d defines `Object { index: i32 }`. Phase 2e changes it to `Object { index: i32, name: String }`. `index` is kept for debug/round-trip; `name` is the operator-visible resolved string. Null (`index == 0`) resolves to `""`. This follows the pattern of all other `PropertyValue` variants using resolved strings rather than raw FName/index values.

2. **`resolve_package_index` lives in `primitives.rs`**, not a new `objects.rs`. One helper function doesn't justify a new module (YAGNI). `objects.rs` can be created if/when Phase 2f or later introduces multiple distinct object-type helpers.

3. **Byte concatenation is allocation-free for monolithic case:** The Rust idiom `let combined: Vec<u8>; let bytes = match uexp { Some(d) => { combined = [...].concat(); &combined } None => uasset };` avoids allocation and copy when `uexp.is_none()`.

4. **`MissingCompanionFile` is a variant of `AssetParseFault`**, not a new top-level `PaksmithError`. The failure is logically a parse-time failure (we have the header, know we need more bytes, and can't continue). The display string "missing required .uexp companion file" accurately describes the failure site.

5. **Wire-format claim verification:** The claim that `combined = [uasset || uexp]` and `serial_offset` indexes naturally into it (because `uasset.len() == total_header_size` for split assets by UE convention) is verified empirically by the fixture-gen oracle task (Task 5). `unreal_asset::Asset::new(asset_reader, Some(uexp_reader), ...)` uses the separate-file form; paksmith uses the concatenated form. Agreement between both on the same fixture proves the layout assumption.

6. **`derive_companion_path` is `pub(super)` in `package.rs`** — only `read_from_pak` uses it; no need for wider visibility.

---

## File structure

| File                                                    | Action | Responsibility                                                                                                                    |
| ------------------------------------------------------- | ------ | --------------------------------------------------------------------------------------------------------------------------------- |
| `crates/paksmith-core/src/error.rs`                     | Modify | Add `MissingCompanionFile` + `CompanionFileKind` enum with Display pins                                                           |
| `crates/paksmith-core/src/asset/property/primitives.rs` | Modify | Add `resolve_package_index`; migrate `PropertyValue::Object { index }` → `{ index, name }`; update read functions                 |
| `crates/paksmith-core/src/asset/package.rs`             | Modify | Change `read_from(uasset, uexp, path)` signature; four-state companion logic; add `derive_companion_path`; update `read_from_pak` |
| `crates/paksmith-core/src/testing/uasset.rs`            | Modify | Add `total_header_size` to `MinimalPackage`; add `build_minimal_ue4_27_split() -> (Vec<u8>, Vec<u8>)`                             |
| `crates/paksmith-core/tests/companion_integration.rs`   | Create | 6 integration tests (4 companion states + 2 ObjectProperty resolution)                                                            |
| `crates/paksmith-fixture-gen/src/uasset.rs`             | Modify | Split-asset fixture generation + oracle cross-validation block                                                                    |
| `crates/paksmith-cli/src/commands/inspect.rs`           | Modify | Update insta snapshot for `Object { index, name }`                                                                                |
| `tests/fixtures/real_v8b_split.pak`                     | Create | Generated split-asset fixture (two pak entries)                                                                                   |

---

### Task 1: Error types for companion file faults

**Files:**

- Modify: `crates/paksmith-core/src/error.rs`

- [ ] **Step 1: Write failing Display pin tests**

Find the `#[cfg(test)] mod tests` block in `error.rs` (the block containing `asset_parse_display_*` tests from Phase 2a–2d) and add:

```rust
#[test]
fn asset_parse_display_missing_companion_file_uexp() {
    let err = PaksmithError::AssetParse {
        asset_path: "Game/Sword.uasset".to_string(),
        fault: AssetParseFault::MissingCompanionFile {
            kind: CompanionFileKind::Uexp,
        },
    };
    assert_eq!(
        format!("{err}"),
        "asset deserialization failed for `Game/Sword.uasset`: \
         missing required .uexp companion file"
    );
}

#[test]
fn companion_file_kind_display_uexp() {
    assert_eq!(CompanionFileKind::Uexp.to_string(), "uexp");
}

#[test]
fn companion_file_kind_display_ubulk() {
    assert_eq!(CompanionFileKind::Ubulk.to_string(), "ubulk");
}
```

- [ ] **Step 2: Run tests to confirm compile error**

```bash
cargo test -p paksmith-core --lib error::tests::asset_parse_display_missing_companion 2>&1 | tail -10
```

Expected: compile error — `CompanionFileKind` not found.

- [ ] **Step 3: Add `CompanionFileKind` enum and `MissingCompanionFile` variant**

Find `pub enum AssetParseFault` and add after the last existing variant (last Phase 2d addition was `TextHistoryUnsupportedInElement`):

```rust
/// A required companion file was not present in the pak when the asset
/// header's export table indicated it was needed.
///
/// For `.uexp`: fired when any export has `serial_offset >= total_header_size`
/// but no `.uexp` entry was found in the pak.
#[error("missing required .{kind} companion file")]
MissingCompanionFile {
    /// Which companion file type was missing.
    kind: CompanionFileKind,
},
```

Then, immediately before `pub enum AssetParseFault` (or after it — the position doesn't matter for compilation), add:

```rust
/// Identifies which companion file type is referenced in
/// [`AssetParseFault::MissingCompanionFile`].
///
/// `#[non_exhaustive]` because additional companion file types
/// (e.g., `.uexpbulk` in IoStore) may be added in future phases.
/// `Display` produces the raw extension string so the parent error
/// message reads `.uexp` or `.ubulk` naturally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CompanionFileKind {
    /// `.uexp` — export payload bytes split out of the `.uasset` header.
    Uexp,
    /// `.ubulk` — additional bulk data (texture mips, etc.), detected but not
    /// yet stitched (Phase 2e warns; full support deferred).
    Ubulk,
}

impl fmt::Display for CompanionFileKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Uexp => "uexp",
            Self::Ubulk => "ubulk",
        })
    }
}
```

- [ ] **Step 4: Run Display pin tests**

```bash
cargo test -p paksmith-core --lib error::tests 2>&1 | tail -20
```

Expected: all tests pass, including the 3 new pin tests.

- [ ] **Step 5: Run workspace clippy**

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add crates/paksmith-core/src/error.rs
git commit -m "$(cat <<'EOF'
feat(error): MissingCompanionFile + CompanionFileKind for Phase 2e

Fires when an asset's export table requires a .uexp companion that
wasn't found in the pak. CompanionFileKind::Ubulk is defined for
display completeness; bulk stitching is deferred past Phase 2e.
EOF
)"
```

---

### Task 2: `resolve_package_index` + `PropertyValue::Object` migration

**Files:**

- Modify: `crates/paksmith-core/src/asset/property/primitives.rs`

This task adds the resolution helper, migrates `PropertyValue::Object { index: i32 }` to `{ index: i32, name: String }`, and updates both `read_primitive_value` and `read_element_value` to resolve eagerly.

**Context:** `AssetContext` (from `crates/paksmith-core/src/asset/mod.rs`) carries `imports: Arc<ImportTable>` and `exports: Arc<ExportTable>`. `ImportTable` has a field `pub imports: Vec<ObjectImport>`; `ExportTable` has `pub exports: Vec<ObjectExport>`. Both `ObjectImport::object_name` and `ObjectExport::object_name` are `String` (resolved at header-parse time from the name table). `AssetParseFault::PackageIndexOob` and `::PackageIndexUnderflow` (defined in Phase 2a) are reused for OOB and `i32::MIN` cases.

- [ ] **Step 1: Write failing unit tests**

Find the `#[cfg(test)]` block in `primitives.rs` and add:

```rust
#[test]
fn resolve_package_index_null_is_empty_string() {
    let ctx = make_test_ctx_with_import("/Game/Mesh.Mesh");
    let name = resolve_package_index(0, &ctx, "x.uasset").unwrap();
    assert_eq!(name, "");
}

#[test]
fn resolve_package_index_import_ref() {
    let ctx = make_test_ctx_with_import("/Game/Mesh.Mesh");
    let name = resolve_package_index(-1, &ctx, "x.uasset").unwrap();
    assert_eq!(name, "/Game/Mesh.Mesh");
}

#[test]
fn resolve_package_index_export_ref() {
    let ctx = make_test_ctx_with_export("Hero");
    let name = resolve_package_index(1, &ctx, "x.uasset").unwrap();
    assert_eq!(name, "Hero");
}

#[test]
fn resolve_package_index_import_oob() {
    let ctx = make_test_ctx_with_import("/Game/Mesh.Mesh");
    // index -2 means imports[1], but only 1 import exists
    let err = resolve_package_index(-2, &ctx, "x.uasset").unwrap_err();
    assert!(matches!(
        err,
        PaksmithError::AssetParse {
            fault: AssetParseFault::PackageIndexOob { .. },
            ..
        }
    ));
}

#[test]
fn resolve_package_index_export_oob() {
    let ctx = make_test_ctx_with_import("/Game/Mesh.Mesh"); // no exports
    let err = resolve_package_index(1, &ctx, "x.uasset").unwrap_err();
    assert!(matches!(
        err,
        PaksmithError::AssetParse {
            fault: AssetParseFault::PackageIndexOob { .. },
            ..
        }
    ));
}

#[test]
fn resolve_package_index_i32_min_underflow() {
    let ctx = make_test_ctx_with_import("/Game/Mesh.Mesh");
    let err = resolve_package_index(i32::MIN, &ctx, "x.uasset").unwrap_err();
    assert!(matches!(
        err,
        PaksmithError::AssetParse {
            fault: AssetParseFault::PackageIndexUnderflow { .. },
            ..
        }
    ));
}
```

Also add the two helper constructors used by the tests (these are private test helpers, not test functions themselves — put them before the test functions).

Phase 2a's `ObjectImport` and `ObjectExport` store `object_name` as a `u32` FName index, not a `String`. The helpers below build a small NameTable, then reference its entries by index. `resolve_package_index` will follow these indices through `ctx.names` to produce the resolved string.

```rust
#[cfg(test)]
fn make_test_ctx_with_import(import_name: &str) -> AssetContext {
    use std::sync::Arc;
    use crate::asset::{
        import_table::{ImportTable, ObjectImport},
        export_table::ExportTable,
        name_table::{FName, NameTable},
        package_index::PackageIndex,
        version::AssetVersion,
        AssetContext,
    };
    // Names: 0="None", 1="Class", 2="/Script/CoreUObject", 3=<import_name>.
    let names = NameTable {
        names: vec![
            FName::new("None"),
            FName::new("Class"),
            FName::new("/Script/CoreUObject"),
            FName::new(import_name),
        ],
    };
    AssetContext {
        names: Arc::new(names),
        imports: Arc::new(ImportTable {
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
        exports: Arc::new(ExportTable { exports: vec![] }),
        version: AssetVersion {
            legacy_file_version: -7,
            file_version_ue4: 522,
            file_version_ue5: None,
            file_version_licensee_ue4: 0,
        },
    }
}

#[cfg(test)]
fn make_test_ctx_with_export(export_name: &str) -> AssetContext {
    use std::sync::Arc;
    use crate::asset::{
        import_table::ImportTable,
        export_table::{ExportTable, ObjectExport},
        name_table::{FName, NameTable},
        package_index::PackageIndex,
        version::AssetVersion,
        AssetContext,
    };
    // Names: 0="None", 1=<export_name>.
    let names = NameTable {
        names: vec![FName::new("None"), FName::new(export_name)],
    };
    AssetContext {
        names: Arc::new(names),
        imports: Arc::new(ImportTable { imports: vec![] }),
        exports: Arc::new(ExportTable {
            exports: vec![ObjectExport {
                class_index: PackageIndex::Null,
                super_index: PackageIndex::Null,
                template_index: PackageIndex::Null,
                outer_index: PackageIndex::Null,
                object_name: 1,
                object_name_number: 0,
                object_flags: 0,
                serial_size: 0,
                serial_offset: 0,
                forced_export: false,
                not_for_client: false,
                not_for_server: false,
                package_guid: Some([0u8; 16]),
                is_inherited_instance: None,
                package_flags: 0,
                not_always_loaded_for_editor_game: false,
                is_asset: true,
                generate_public_hash: None,
                first_export_dependency: -1,
                serialization_before_serialization_count: 0,
                create_before_serialization_count: 0,
                serialization_before_create_count: 0,
                create_before_create_count: 0,
            }],
        }),
        version: AssetVersion {
            legacy_file_version: -7,
            file_version_ue4: 522,
            file_version_ue5: None,
            file_version_licensee_ue4: 0,
        },
    }
}
```

- [ ] **Step 2: Run tests to confirm compile error**

```bash
cargo test -p paksmith-core --lib asset::property::primitives::tests::resolve_package_index 2>&1 | tail -10
```

Expected: compile error — `resolve_package_index` not found.

- [ ] **Step 3: Add `resolve_package_index`**

Add inside `primitives.rs`, alongside the other `read_*` helpers (before the `#[cfg(test)]` block):

```rust
/// Resolve a raw UE package index to a human-readable object name.
///
/// | `index` value | Meaning                                  | Source            |
/// |---------------|------------------------------------------|-------------------|
/// | `0`           | Null reference                           | Returns `""`      |
/// | `i32::MIN`    | Structurally undecodable                 | `PackageIndexUnderflow` error |
/// | `n < 0`       | Import reference: `imports[-n - 1]`      | `ImportTable`     |
/// | `n > 0`       | Export reference: `exports[n - 1]`       | `ExportTable`     |
///
/// Phase 2a stores `ObjectImport::object_name` and `ObjectExport::object_name`
/// as `u32` FName indices. This helper resolves them through `ctx.names`
/// (and applies the `_N` suffix from `object_name_number`) via the
/// existing [`resolve_fname`](crate::asset::property::tag::resolve_fname)
/// helper from Phase 2b.
///
/// OOB indices return `PackageIndexOob` with `field: AssetWireField::ObjectPropertyIndex`.
/// `index` is reported as the 0-based table position; `table_size` is the table length.
pub(super) fn resolve_package_index(
    index: i32,
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<String> {
    use crate::asset::property::tag::resolve_fname;
    use crate::error::{AssetParseFault, AssetWireField};
    match index {
        0 => Ok(String::new()),
        i32::MIN => Err(PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::PackageIndexUnderflow {
                field: AssetWireField::ObjectPropertyIndex,
            },
        }),
        n if n < 0 => {
            let idx = (-n - 1) as usize;
            let imp = ctx.imports.imports.get(idx).ok_or_else(|| {
                PaksmithError::AssetParse {
                    asset_path: asset_path.to_string(),
                    fault: AssetParseFault::PackageIndexOob {
                        field: AssetWireField::ObjectPropertyIndex,
                        index: idx as u32,
                        table_size: ctx.imports.imports.len() as u32,
                    },
                }
            })?;
            resolve_fname(
                imp.object_name as i32,
                imp.object_name_number as i32,
                ctx,
                asset_path,
                AssetWireField::ObjectPropertyIndex,
            )
        }
        n => {
            let idx = (n - 1) as usize;
            let exp = ctx.exports.exports.get(idx).ok_or_else(|| {
                PaksmithError::AssetParse {
                    asset_path: asset_path.to_string(),
                    fault: AssetParseFault::PackageIndexOob {
                        field: AssetWireField::ObjectPropertyIndex,
                        index: idx as u32,
                        table_size: ctx.exports.exports.len() as u32,
                    },
                }
            })?;
            resolve_fname(
                exp.object_name as i32,
                exp.object_name_number as i32,
                ctx,
                asset_path,
                AssetWireField::ObjectPropertyIndex,
            )
        }
    }
}
```

> **Accessor note:** `AssetContext.imports` is `Arc<ImportTable>` and `.exports` is `Arc<ExportTable>`; both deref via `Arc<T> → &T` so `ctx.imports.imports` works directly.

- [ ] **Step 4: Run the resolution tests**

```bash
cargo test -p paksmith-core --lib asset::property::primitives::tests::resolve_package_index 2>&1 | tail -20
```

Expected: 6 tests pass.

- [ ] **Step 5: Migrate `PropertyValue::Object` and update both read functions**

Find the `PropertyValue::Object` variant definition (from Phase 2d). Change:

```rust
/// Raw package index for an `ObjectProperty` or `ObjectProperty` collection element.
/// Negative = import ref, positive = export ref, 0 = null.
/// Resolution deferred to Phase 2e.
Object {
    index: i32,
},
```

to:

```rust
/// An `ObjectProperty` value with its resolved name.
///
/// `index`: raw UE package index (negative = import ref, positive = export ref, 0 = null).
/// `name`: resolved object name from the import/export table (empty string for null).
Object {
    index: i32,
    name: String,
},
```

Then in `read_primitive_value`, find the `"ObjectProperty"` arm:

```rust
"ObjectProperty" => {
    let index = reader
        .read_i32::<LittleEndian>()
        .map_err(|_| PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::UnexpectedEof {
                field: AssetWireField::ObjectPropertyIndex,
            },
        })?;
    PV::Object { index }
}
```

Replace with:

```rust
"ObjectProperty" => {
    let index = reader
        .read_i32::<LittleEndian>()
        .map_err(|_| PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::UnexpectedEof {
                field: AssetWireField::ObjectPropertyIndex,
            },
        })?;
    let name = resolve_package_index(index, ctx, asset_path)?;
    PV::Object { index, name }
}
```

Then in `read_element_value`, find the `"ObjectProperty"` arm (added in Phase 2d):

```rust
"ObjectProperty" => {
    let index = reader
        .read_i32::<LittleEndian>()
        .map_err(|_| PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::UnexpectedEof {
                field: AssetWireField::ObjectPropertyIndex,
            },
        })?;
    PV::Object { index }
}
```

Replace with:

```rust
"ObjectProperty" => {
    let index = reader
        .read_i32::<LittleEndian>()
        .map_err(|_| PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::UnexpectedEof {
                field: AssetWireField::ObjectPropertyIndex,
            },
        })?;
    let name = resolve_package_index(index, ctx, asset_path)?;
    PV::Object { index, name }
}
```

- [ ] **Step 6: Fix all exhaustive match arms on `PropertyValue::Object`**

Search for existing pattern matches on `PropertyValue::Object { index }`:

```bash
grep -rn 'Object { index' crates/
```

Update each match arm to destructure `{ index, name }` (or `{ index, .. }` if `name` is not needed at that match site). The most common locations:

- Serialization code in `primitives.rs` (serde derive handles this automatically if using `#[derive(Serialize)]`)
- Any `matches!` calls in existing tests
- Any explicit `match pv { PropertyValue::Object { index } => ... }` in other files

- [ ] **Step 7: Run all primitives tests**

```bash
cargo test -p paksmith-core --lib asset::property::primitives::tests 2>&1 | tail -30
```

Expected: all tests pass. If any Phase 2d tests assert `PV::Object { index: -1 }`, update them to `PV::Object { index: -1, name: <expected-resolved-name> }`.

- [ ] **Step 8: Run workspace clippy**

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Expected: clean.

- [ ] **Step 9: Commit**

```bash
git add crates/paksmith-core/src/asset/property/primitives.rs
git commit -m "$(cat <<'EOF'
feat(property): resolve ObjectProperty package index to name

PropertyValue::Object gains name: String (delta from Phase 2d's
{ index: i32 }). resolve_package_index maps null→"", import→imports[],
export→exports[], i32::MIN→PackageIndexUnderflow, OOB→PackageIndexOob.
Both read_primitive_value and read_element_value resolve eagerly.
EOF
)"
```

---

### Task 3: `Package::read_from` — companion detection and byte stitching

**Files:**

- Modify: `crates/paksmith-core/src/asset/package.rs`

**Context:** `Package::read_from` currently has signature `(bytes: &[u8], asset_path: &str) -> crate::Result<Self>`. After this task it becomes `(uasset: &[u8], uexp: Option<&[u8]>, asset_path: &str)`. All callers (unit tests inside `package.rs` and integration tests) must be updated.

- [ ] **Step 1: Write failing tests for all four companion states**

Find the `#[cfg(test)]` block in `package.rs` and add:

```rust
#[test]
fn read_from_monolithic_no_uexp_succeeds() {
    // Standard monolithic fixture: all export payloads within total_header_size bytes.
    let pkg = build_minimal_ue4_27();
    let result = Package::read_from(&pkg.bytes, None, "test.uasset");
    assert!(result.is_ok(), "monolithic parse failed: {result:?}");
}

#[test]
fn read_from_split_with_uexp_succeeds() {
    // Split fixture: header bytes + uexp bytes. Stitch and parse.
    let (uasset, uexp) = build_minimal_ue4_27_split();
    let result = Package::read_from(&uasset, Some(&uexp), "test.uasset");
    assert!(result.is_ok(), "split parse failed: {result:?}");
}

#[test]
fn read_from_split_missing_uexp_errors() {
    // Split fixture header with no uexp provided → MissingCompanionFile.
    let (uasset, _uexp) = build_minimal_ue4_27_split();
    let err = Package::read_from(&uasset, None, "test.uasset").unwrap_err();
    assert!(
        matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::MissingCompanionFile {
                    kind: CompanionFileKind::Uexp,
                },
                ..
            }
        ),
        "unexpected error: {err:?}"
    );
}

#[test]
fn read_from_monolithic_with_extra_uexp_warns_and_succeeds() {
    // Monolithic fixture (no export needs .uexp) but we pass Some(uexp) anyway.
    // Should warn and succeed (no error).
    let pkg = build_minimal_ue4_27();
    let dummy_uexp: Vec<u8> = vec![0xDE, 0xAD]; // arbitrary extra bytes
    let result = Package::read_from(&pkg.bytes, Some(&dummy_uexp), "test.uasset");
    // The warn-and-ignore path: result should be Ok.
    assert!(result.is_ok(), "extra-uexp warn path failed: {result:?}");
}
```

> **Note:** `build_minimal_ue4_27_split` is added in Task 5. These tests will fail at compile time until that task is done. The pattern is: write the tests here (Task 3), implement the API change here, stub `build_minimal_ue4_27_split` temporarily if needed.
>
> **Temporary stub:** If Task 5 hasn't landed yet, add at the top of the `#[cfg(test)]` block:
>
> ```rust
> // Temporary stub until Task 5 implements the real split builder.
> fn build_minimal_ue4_27_split() -> (Vec<u8>, Vec<u8>) {
>     let pkg = build_minimal_ue4_27();
>     let split_at = pkg.total_header_size;
>     (pkg.bytes[..split_at].to_vec(), pkg.bytes[split_at..].to_vec())
> }
> ```
>
> Remove this stub after Task 5 lands (it duplicates the real implementation).

- [ ] **Step 2: Update `read_from` signature**

Find `pub fn read_from` in `impl Package`. Change its signature from:

```rust
pub fn read_from(bytes: &[u8], asset_path: &str) -> crate::Result<Self> {
```

to:

```rust
pub fn read_from(uasset: &[u8], uexp: Option<&[u8]>, asset_path: &str) -> crate::Result<Self> {
```

At the top of the function body, add the byte stitching logic:

Add a structural cap on the `.uexp` size — without it, a malicious pak entry could supply a multi-GiB `.uexp` slice that paksmith concatenates into a buffer twice its size:

```rust
/// Hard cap on the `.uexp` companion file size. `total_header_size`
/// already caps the `.uasset` at 256 MiB; the export-body section in
/// `.uexp` is typically smaller. 1 GiB is generous headroom; bigger
/// would already be suspicious for an UE-cooked asset.
pub const MAX_UEXP_SIZE: usize = 1024 * 1024 * 1024;
```

Then in `Package::read_from`:

```rust
    // Stitch .uasset and optional .uexp into one contiguous buffer.
    // For monolithic assets (uexp = None), borrow uasset directly (zero-copy).
    let combined_owned: Vec<u8>;
    let bytes: &[u8] = match uexp {
        Some(uexp_data) => {
            // Cap the .uexp size before allocating a combined buffer
            // sized to `uasset.len() + uexp_data.len()`. Without this
            // guard a malicious pak entry could force a multi-GiB
            // allocation by claiming a huge .uexp payload.
            if uexp_data.len() > MAX_UEXP_SIZE {
                return Err(PaksmithError::AssetParse {
                    asset_path: asset_path.to_string(),
                    fault: AssetParseFault::BoundsExceeded {
                        field: AssetWireField::UexpSize,
                        value: uexp_data.len() as u64,
                        limit: MAX_UEXP_SIZE as u64,
                    },
                });
            }
            // Defensive: use try_reserve_exact so an OOM here surfaces
            // as a typed error instead of aborting the process.
            let total = uasset.len()
                .checked_add(uexp_data.len())
                .ok_or_else(|| PaksmithError::AssetParse {
                    asset_path: asset_path.to_string(),
                    fault: AssetParseFault::U64ArithmeticOverflow {
                        operation: AssetOverflowSite::SplitAssetConcatExtent,
                    },
                })?;
            let mut buf: Vec<u8> = Vec::new();
            buf.try_reserve_exact(total).map_err(|source| PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::AllocationFailed {
                    context: AssetAllocationContext::SplitAssetCombined,
                    requested: total,
                    unit: BoundsUnit::Bytes,
                    source,
                },
            })?;
            buf.extend_from_slice(uasset);
            buf.extend_from_slice(uexp_data);
            combined_owned = buf;
            &combined_owned
        }
        None => uasset,
    };
    let mut reader = Cursor::new(bytes);
```

> **New error-related additions** — extend `error.rs`:
>
> - `AssetWireField::UexpSize` (new variant + Display mapping `"uexp_size"`)
> - `AssetOverflowSite::SplitAssetConcatExtent` (new variant + Display mapping `"split-asset concat extent computation"`)
> - `AssetAllocationContext::SplitAssetCombined` (new variant + Display mapping `"combined .uasset+.uexp buffer"`)

Remove the old `let mut reader = Cursor::new(bytes);` line that the function previously used.

- [ ] **Step 3: Add the four-state companion detection**

After the export table has been parsed (after `let exports = ExportTable::read_from(&mut reader, &summary, &names, asset_path)?;`), add:

```rust
    // Four-state companion detection.
    let needs_uexp = exports
        .exports
        .iter()
        .any(|e| e.serial_offset >= i64::from(summary.total_header_size));

    if needs_uexp && uexp.is_none() {
        return Err(PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::MissingCompanionFile {
                kind: crate::error::CompanionFileKind::Uexp,
            },
        });
    }

    if !needs_uexp && uexp.is_some() {
        tracing::warn!(
            asset_path = asset_path,
            "'.uexp' companion bytes provided but no export has serial_offset \
             >= total_header_size ({}); ignoring companion",
            summary.total_header_size
        );
    }

    // Verify the load-bearing invariant: when split, the `.uasset` file
    // contains exactly the header bytes (everything before the export
    // payload region). UE writes split assets with this layout by
    // convention, but a pathological writer could break it (e.g. by
    // appending AssetRegistryData past `total_header_size` in `.uasset`).
    // If `uasset.len() != total_header_size`, then `serial_offset` —
    // which points into the logical full-asset byte stream — does NOT
    // index naturally into `[uasset || uexp]`. Fire a clear error
    // instead of silently misparsing.
    if needs_uexp && uasset.len() as i64 != i64::from(summary.total_header_size) {
        return Err(PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::SplitAssetSizeMismatch {
                uasset_len: uasset.len(),
                total_header_size: summary.total_header_size,
            },
        });
    }
```

> **New error variant** — add to `error.rs`:
>
> ```rust
> /// A split asset's `.uasset` file does not have length equal to
> /// `total_header_size`. Phase 2e's `[uasset || uexp]` concatenation
> /// relies on this UE-convention invariant; pathological writers that
> /// embed trailing data in `.uasset` after the header region would
> /// produce misaligned serial offsets.
> #[error(
>     "split-asset size invariant violated: uasset length {uasset_len} \
>      != total_header_size {total_header_size}"
> )]
> SplitAssetSizeMismatch {
>     uasset_len: usize,
>     total_header_size: i32,
> },
> ```

- [ ] **Step 4: Update all existing callers of `Package::read_from`**

Search for all call sites:

```bash
grep -rn 'Package::read_from(' crates/ tests/
```

Update each occurrence by adding `None` as the second argument and shifting `asset_path` to third:

- `Package::read_from(&bytes, virtual_path)` → `Package::read_from(&bytes, None, virtual_path)`
- The `read_from_pak` in the same file currently calls `Self::read_from(&bytes, virtual_path)` — update to `Self::read_from(&bytes, None, virtual_path)` for now (Task 4 will supply real `.uexp` bytes).
- Any unit tests from Phase 2a Tasks 11, 12, 15 that call `Package::read_from` directly.
- Any integration tests in `tests/asset_integration.rs`, `tests/extended_types_integration.rs`, etc. that call `Package::read_from` (vs. `Package::read_from_pak`).

> **Tip:** The compiler will identify every call site that doesn't match the new arity. Fix them one by one rather than doing a blind search-replace.

- [ ] **Step 5: Run the four-state tests**

```bash
cargo test -p paksmith-core --lib asset::package::tests 2>&1 | tail -30
```

Expected: all four new tests pass plus all pre-existing `package::tests` pass.

- [ ] **Step 6: Run full test suite**

```bash
cargo test --workspace 2>&1 | tail -30
```

Expected: no regressions. The call-site updates in Step 4 should cover all breaks.

- [ ] **Step 7: Run workspace clippy**

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Expected: clean.

- [ ] **Step 8: Commit**

```bash
git add crates/paksmith-core/src/asset/package.rs
git commit -m "$(cat <<'EOF'
feat(asset): Package::read_from accepts optional .uexp companion bytes

Signature change: read_from(uasset, uexp: Option<&[u8]>, path).
Stitches header + uexp before parsing (zero-copy for monolithic).
Four-state companion detection: missing-uexp errors with
MissingCompanionFile; extra-uexp warns via tracing::warn! and proceeds.
EOF
)"
```

---

### Task 4: `Package::read_from_pak` — companion file lookup

**Files:**

- Modify: `crates/paksmith-core/src/asset/package.rs`

- [ ] **Step 1: Write a failing integration test for the split-pak round-trip**

Add to `package.rs` tests (or to `tests/asset_integration.rs` — whichever hosts the `read_from_pak` round-trip tests from Phase 2a Task 15). This test uses the split fixture pak generated in Task 5. Write it now so Task 5 has a target:

```rust
#[test]
fn read_from_pak_split_asset_round_trip() {
    // Depends on tests/fixtures/real_v8b_split.pak produced by fixture-gen (Task 5).
    // The split pak has Game/Maps/Demo.uasset (header only) and Game/Maps/Demo.uexp (payload).
    let pak = std::path::Path::new(
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/real_v8b_split.pak")
    );
    // Skip if fixture not yet generated.
    if !pak.exists() {
        eprintln!("skipping: real_v8b_split.pak not yet generated");
        return;
    }
    let pkg = Package::read_from_pak(pak, "Game/Maps/Demo.uasset")
        .expect("split asset parse failed");
    assert!(!pkg.exports().exports.is_empty());
}
```

Run to confirm it compiles but skips (fixture doesn't exist yet):

```bash
cargo test -p paksmith-core --test asset_integration read_from_pak_split_asset_round_trip 2>&1 | tail -10
```

Expected: test runs and prints "skipping" (or compiles and skips).

- [ ] **Step 2: Add `derive_companion_path`**

Inside `crates/paksmith-core/src/asset/package.rs`, above `impl Package`, add:

```rust
/// Derive a companion file path from an asset path by swapping the extension.
///
/// `"Game/Weapon/Sword.uasset"` + `".uexp"` → `"Game/Weapon/Sword.uexp"`.
/// If `base` does not end in `.uasset`, appends `new_ext` directly (should
/// not happen for well-formed pak entries but avoids panics on edge inputs).
pub(super) fn derive_companion_path(base: &str, new_ext: &str) -> String {
    match base.strip_suffix(".uasset") {
        Some(stem) => format!("{stem}{new_ext}"),
        None => format!("{base}{new_ext}"),
    }
}
```

Add a unit test immediately after (in the `#[cfg(test)]` block):

```rust
#[test]
fn derive_companion_path_strips_uasset() {
    assert_eq!(
        derive_companion_path("Game/Weapon/Sword.uasset", ".uexp"),
        "Game/Weapon/Sword.uexp"
    );
}

#[test]
fn derive_companion_path_non_uasset_appends() {
    assert_eq!(
        derive_companion_path("Game/raw", ".uexp"),
        "Game/raw.uexp"
    );
}
```

Run:

```bash
cargo test -p paksmith-core --lib asset::package::tests::derive_companion_path 2>&1 | tail -10
```

Expected: 2 tests pass.

- [ ] **Step 3: Update `read_from_pak` to look up companions**

Find the current `read_from_pak` implementation (updated in Task 3 Step 4 to pass `None`):

```rust
pub fn read_from_pak<P: AsRef<std::path::Path>>(
    pak_path: P,
    virtual_path: &str,
) -> crate::Result<Self> {
    use crate::container::ContainerReader;
    let pak = crate::container::pak::PakReader::open(pak_path)?;
    let bytes = pak.read_entry(virtual_path)?;
    Self::read_from(&bytes, None, virtual_path)
}
```

Replace with:

```rust
pub fn read_from_pak<P: AsRef<std::path::Path>>(
    pak_path: P,
    virtual_path: &str,
) -> crate::Result<Self> {
    use crate::container::ContainerReader;
    let pak = crate::container::pak::PakReader::open(pak_path)?;

    let uasset_bytes = pak.read_entry(virtual_path)?;

    // Look up .uexp companion (absent for monolithic assets).
    let uexp_path = derive_companion_path(virtual_path, ".uexp");
    let uexp_bytes = match pak.read_entry(&uexp_path) {
        Ok(b) => Some(b),
        Err(PaksmithError::EntryNotFound { .. }) => None,
        Err(e) => return Err(e),
    };

    // Detect .ubulk; not stitched in Phase 2e.
    let ubulk_path = derive_companion_path(virtual_path, ".ubulk");
    if pak.read_entry(&ubulk_path).is_ok() {
        tracing::warn!(
            asset_path = virtual_path,
            ".ubulk companion found but bulk data stitching is not yet supported; \
             bulk data will be absent from the parsed asset"
        );
    }

    Self::read_from(&uasset_bytes, uexp_bytes.as_deref(), virtual_path)
}
```

- [ ] **Step 4: Run tests**

```bash
cargo test --workspace 2>&1 | tail -20
```

Expected: no regressions. The split-pak round-trip test still skips (fixture not yet generated).

- [ ] **Step 5: Run workspace clippy**

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add crates/paksmith-core/src/asset/package.rs
git commit -m "$(cat <<'EOF'
feat(asset): read_from_pak loads .uexp and detects .ubulk companion

Looks up <stem>.uexp from the pak; EntryNotFound→None (monolithic),
other errors propagate. Passes uexp bytes to read_from for stitching.
Detects .ubulk and emits tracing::warn; stitching deferred to Phase 2f.
derive_companion_path strips .uasset and appends the new extension.
EOF
)"
```

---

### Task 5: Split-asset fixture builder and fixture-gen oracle cross-validation

**Files:**

- Modify: `crates/paksmith-core/src/testing/uasset.rs`
- Modify: `crates/paksmith-fixture-gen/src/uasset.rs`

**Output artifact:** `tests/fixtures/real_v8b_split.pak`

- [ ] **Step 1: Extend `MinimalPackage` to expose `total_header_size`**

Find `struct MinimalPackage` in `testing/uasset.rs`. Add a `total_header_size: usize` field:

```rust
pub struct MinimalPackage {
    pub bytes: Vec<u8>,
    /// Byte length of the header portion (= `summary.total_header_size` from
    /// the builder). Used by `build_minimal_ue4_27_split` to cut at the right
    /// boundary.
    pub total_header_size: usize,
}
```

Update all construction sites of `MinimalPackage { bytes: ... }` to also set `total_header_size`. The builder already computes `summary.total_header_size`; capture it:

```rust
MinimalPackage {
    total_header_size: summary.total_header_size as usize,
    bytes: out,
}
```

Run to verify no regressions:

```bash
cargo test --workspace 2>&1 | tail -20
```

Expected: all tests pass. Existing code that destructures `MinimalPackage` only by `.bytes` will need `total_header_size: _` in any pattern matches, or just ignore it.

- [ ] **Step 2: Write a failing test for `build_minimal_ue4_27_split`**

Add to `testing/uasset.rs`'s test block:

```rust
#[test]
fn split_plus_monolithic_produce_identical_parse() {
    use crate::asset::Package;

    let monolithic = build_minimal_ue4_27();
    let (uasset, uexp) = build_minimal_ue4_27_split();

    // Both forms should parse to an equivalent package.
    let pkg_mono = Package::read_from(&monolithic.bytes, None, "test.uasset")
        .expect("monolithic parse failed");
    let pkg_split = Package::read_from(&uasset, Some(&uexp), "test.uasset")
        .expect("split parse failed");

    // Structural equivalence: same number of exports, same export names.
    assert_eq!(
        pkg_mono.exports().exports.len(),
        pkg_split.exports().exports.len()
    );
    for (m, s) in pkg_mono.exports().exports.iter().zip(pkg_split.exports().exports.iter()) {
        assert_eq!(m.object_name, s.object_name);
    }
}
```

Run to confirm it fails (function not found):

```bash
cargo test -p paksmith-core --lib testing::uasset::tests::split_plus_monolithic_produce_identical_parse 2>&1 | tail -10
```

Expected: compile error — `build_minimal_ue4_27_split` not found.

- [ ] **Step 3: Implement `build_minimal_ue4_27_split`**

Add to `testing/uasset.rs`:

```rust
/// Returns `(uasset_header_bytes, uexp_payload_bytes)` — the split form of the
/// standard Phase 2a minimal fixture.
///
/// `uasset_header_bytes.len() == pkg.total_header_size`. The two slices
/// concatenated produce identical bytes to `build_minimal_ue4_27().bytes`, so
/// parsing `read_from(uasset, Some(uexp), _)` gives the same result as
/// `read_from(&full, None, _)`.
#[cfg(feature = "__test_utils")]
pub fn build_minimal_ue4_27_split() -> (Vec<u8>, Vec<u8>) {
    let pkg = build_minimal_ue4_27();
    let split_at = pkg.total_header_size;
    debug_assert!(
        split_at <= pkg.bytes.len(),
        "total_header_size {split_at} > bytes.len() {} — builder bug",
        pkg.bytes.len()
    );
    (pkg.bytes[..split_at].to_vec(), pkg.bytes[split_at..].to_vec())
}
```

- [ ] **Step 4: Run the equivalence test**

```bash
cargo test -p paksmith-core --lib testing::uasset::tests::split_plus_monolithic_produce_identical_parse 2>&1 | tail -10
```

Expected: PASS.

- [ ] **Step 5: Add split fixture generation to `paksmith-fixture-gen`**

Find `crates/paksmith-fixture-gen/src/uasset.rs`. Locate the existing `write_uasset_fixtures` function (or equivalent entry point that writes `real_v8b_uasset.pak`). Add a new function `write_split_uasset_fixture` after it:

```rust
/// Write `tests/fixtures/real_v8b_split.pak` — a pak with two entries:
/// - `Game/Maps/Demo.uasset` (header bytes only)
/// - `Game/Maps/Demo.uexp`   (export payload bytes only)
///
/// Cross-validates the split form against `unreal_asset` using its
/// `Asset::new(asset_data, Some(bulk_data), ...)` two-reader API, which
/// is the discriminating check that proves paksmith's concat-and-seek
/// layout assumption matches the reference implementation.
pub fn write_split_uasset_fixture(out_dir: &Path) -> anyhow::Result<()> {
    use paksmith_core::testing::uasset::build_minimal_ue4_27_split;

    let (uasset_bytes, uexp_bytes) = build_minimal_ue4_27_split();

    // Cross-validate with unreal_asset before writing the fixture.
    cross_validate_split_with_unreal_asset(&uasset_bytes, &uexp_bytes)?;

    // Write both entries into one pak file.
    let pak_path = out_dir.join("real_v8b_split.pak");
    let mut builder = repak::PakBuilder::new();
    builder.add_entry("Game/Maps/Demo.uasset", uasset_bytes.clone());
    builder.add_entry("Game/Maps/Demo.uexp", uexp_bytes.clone());
    builder.write(&pak_path)?;

    println!("wrote {}", pak_path.display());
    Ok(())
}

fn cross_validate_split_with_unreal_asset(
    uasset_bytes: &[u8],
    uexp_bytes: &[u8],
) -> anyhow::Result<()> {
    use std::io::Cursor;
    use unreal_asset::engine_version::EngineVersion;
    use unreal_asset::Asset;

    // unreal_asset's Asset::new takes: asset_data reader, optional bulk_data reader
    // (.uexp), engine version, optional .usmap mappings.
    let asset = Asset::new(
        Cursor::new(uasset_bytes.to_vec()),
        Some(Cursor::new(uexp_bytes.to_vec())),
        EngineVersion::VER_UE4_27,
        None,
    )
    .map_err(|e| anyhow::anyhow!("unreal_asset split parse failed: {e}"))?;

    let name_count = asset.get_name_map().get_ref().get_name_map_index_list().len();
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
```

> **API note:** The `repak::PakBuilder` API above reflects the version used in Phase 1 fixtures. Adjust the builder calls to match whatever repak version and API the fixture-gen already uses.

Call `write_split_uasset_fixture` from the fixture-gen `main` function alongside the existing fixture writers.

- [ ] **Step 6: Regenerate fixtures**

```bash
cargo run -p paksmith-fixture-gen 2>&1 | tail -20
```

Expected: `wrote tests/fixtures/real_v8b_split.pak` printed. File exists at that path.

```bash
ls -lh tests/fixtures/real_v8b_split.pak
```

Expected: file exists, reasonable size (< 1 KB for the synthetic fixture).

- [ ] **Step 7: Re-run the split round-trip test (no longer skips)**

```bash
cargo test -p paksmith-core --test asset_integration read_from_pak_split_asset_round_trip 2>&1 | tail -10
```

Expected: PASS (no longer skips).

- [ ] **Step 8: Run full test suite**

```bash
cargo test --workspace 2>&1 | tail -20
```

Expected: all tests pass.

- [ ] **Step 9: Commit**

```bash
git add \
  crates/paksmith-core/src/testing/uasset.rs \
  crates/paksmith-fixture-gen/src/uasset.rs \
  tests/fixtures/real_v8b_split.pak
git commit -m "$(cat <<'EOF'
feat(fixture): split-asset fixture + unreal_asset oracle cross-validation

build_minimal_ue4_27_split() splits the monolithic Phase 2a fixture at
total_header_size into (uasset_header, uexp_payload). MinimalPackage
gains total_header_size field for the split.

fixture-gen writes real_v8b_split.pak with two entries
(Game/Maps/Demo.uasset + Game/Maps/Demo.uexp) and cross-validates:
  - unreal_asset's two-reader form (Asset::new(asset, Some(uexp), ...))
  - unreal_asset's concat-monolithic form
both must agree, proving paksmith's layout assumption.
EOF
)"
```

---

### Task 6: Integration tests — all four companion states + ObjectProperty resolution

**Files:**

- Create: `crates/paksmith-core/tests/companion_integration.rs`

- [ ] **Step 1: Write all six tests**

Create `crates/paksmith-core/tests/companion_integration.rs`:

```rust
//! Integration tests for Phase 2e: companion file loading and
//! ObjectProperty resolution.

use paksmith_core::asset::{package::Package, Package as _};
use paksmith_core::error::{AssetParseFault, CompanionFileKind, PaksmithError};

// ── Companion file states ────────────────────────────────────────────────────

/// State 1: monolithic asset (no .uexp), no export outside total_header_size.
#[test]
fn monolithic_asset_parses_without_uexp() {
    use paksmith_core::testing::uasset::build_minimal_ue4_27;
    let pkg = build_minimal_ue4_27();
    let result = Package::read_from(&pkg.bytes, None, "test.uasset");
    assert!(result.is_ok(), "{result:?}");
}

/// State 2: split asset, .uasset header + .uexp payload both provided.
#[test]
fn split_asset_stitches_and_parses() {
    use paksmith_core::testing::uasset::build_minimal_ue4_27_split;
    let (uasset, uexp) = build_minimal_ue4_27_split();
    let result = Package::read_from(&uasset, Some(&uexp), "test.uasset");
    assert!(result.is_ok(), "{result:?}");
    let pkg = result.unwrap();
    assert!(!pkg.exports().exports.is_empty());
}

/// State 3: split asset header, .uexp not provided → MissingCompanionFile.
#[test]
fn split_asset_without_uexp_errors() {
    use paksmith_core::testing::uasset::build_minimal_ue4_27_split;
    let (uasset, _uexp) = build_minimal_ue4_27_split();
    let err = Package::read_from(&uasset, None, "Game/Sword.uasset").unwrap_err();
    assert!(
        matches!(
            &err,
            PaksmithError::AssetParse {
                asset_path,
                fault: AssetParseFault::MissingCompanionFile {
                    kind: CompanionFileKind::Uexp,
                },
            } if asset_path == "Game/Sword.uasset"
        ),
        "unexpected error variant: {err:?}"
    );
}

/// State 4: monolithic asset (no export needs .uexp), but .uexp bytes provided.
/// Should warn and succeed.
#[test]
fn monolithic_with_excess_uexp_succeeds() {
    use paksmith_core::testing::uasset::build_minimal_ue4_27;
    let pkg = build_minimal_ue4_27();
    let dummy_uexp = vec![0xFF, 0xFE]; // irrelevant extra bytes
    let result = Package::read_from(&pkg.bytes, Some(&dummy_uexp), "test.uasset");
    assert!(result.is_ok(), "{result:?}");
}

// ── ObjectProperty resolution ────────────────────────────────────────────────

/// ObjectProperty with index -1 resolves to the first import's object_name.
#[test]
fn object_property_resolves_import_name() {
    use paksmith_core::asset::property::primitives::PropertyValue;
    use paksmith_core::testing::uasset::build_minimal_ue4_27_with_object_ref;

    // build_minimal_ue4_27_with_object_ref returns (bytes, expected_name).
    // The fixture has one import (object_name = expected_name) and one
    // ObjectProperty ("ObjRef") with index = -1.
    let (pkg_bytes, expected_name) = build_minimal_ue4_27_with_object_ref();
    let pkg = Package::read_from(&pkg_bytes, None, "test.uasset").unwrap();

    let export = &pkg.exports().exports[0];
    let props = pkg.export_properties(export).unwrap();
    let obj_prop = props
        .iter()
        .find(|p| p.name == "ObjRef")
        .expect("ObjRef property not found");

    assert!(
        matches!(
            &obj_prop.value,
            PropertyValue::Object { index: -1, name } if name == &expected_name
        ),
        "unexpected value: {:?}",
        obj_prop.value
    );
}

/// ObjectProperty with index 0 resolves to empty string (null reference).
#[test]
fn object_property_null_index_resolves_empty() {
    use paksmith_core::asset::property::primitives::PropertyValue;
    use paksmith_core::testing::uasset::build_minimal_ue4_27_with_null_object_ref;

    let pkg_bytes = build_minimal_ue4_27_with_null_object_ref();
    let pkg = Package::read_from(&pkg_bytes, None, "test.uasset").unwrap();

    let export = &pkg.exports().exports[0];
    let props = pkg.export_properties(export).unwrap();
    let obj_prop = props
        .iter()
        .find(|p| p.name == "NullRef")
        .expect("NullRef property not found");

    assert!(
        matches!(
            &obj_prop.value,
            PropertyValue::Object { index: 0, name } if name.is_empty()
        ),
        "unexpected value: {:?}",
        obj_prop.value
    );
}
```

- [ ] **Step 2: Add the two fixture helpers used by tests 5 and 6**

Add to `crates/paksmith-core/src/testing/uasset.rs`:

```rust
/// Returns `(bytes, expected_resolved_name)` where:
/// - The export payload has one `ObjectProperty` named `"ObjRef"` with `index = -1`
/// - The name table has `["None", "ObjRef", "ObjectProperty"]`
/// - The import table has one entry with `object_name = "/Game/Data/Mesh.StaticMesh"`
/// - `expected_resolved_name = "/Game/Data/Mesh.StaticMesh"`
#[cfg(feature = "__test_utils")]
pub fn build_minimal_ue4_27_with_object_ref() -> (Vec<u8>, String) {
    // Name table: 0=None, 1=ObjRef, 2=ObjectProperty
    // Import[0].object_name = "/Game/Data/Mesh.StaticMesh"
    //
    // FPropertyTag for ObjectProperty:
    //   Name FName (index=1, number=0):   01 00 00 00  00 00 00 00
    //   Type FName (index=2, number=0):   02 00 00 00  00 00 00 00
    //   Size i64 = 4:                     04 00 00 00  00 00 00 00
    //   ArrayIndex i32 = 0:               00 00 00 00
    //   has_property_guid u8 = 0:         00
    //   Value i32 = -1:                   FF FF FF FF
    // None terminator (0, 0):             00 00 00 00  00 00 00 00
    let payload = vec![
        0x01, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, // name FName (1, 0)
        0x02, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, // type FName (2, 0)
        0x04, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, // size i64 = 4
        0x00, 0x00, 0x00, 0x00,                           // array_index i32 = 0
        0x00,                                             // has_property_guid = 0
        0xFF, 0xFF, 0xFF, 0xFF,                           // value i32 = -1
        0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, // None terminator
    ];
    let import_name = "/Game/Data/Mesh.StaticMesh".to_string();
    let pkg = build_with_payload_and_import(
        &["None", "ObjRef", "ObjectProperty"],
        payload,
        &import_name,
    );
    (pkg.bytes, import_name)
}

/// Returns bytes for a package with one `ObjectProperty` named `"NullRef"` with
/// `index = 0` (null reference). No imports needed (null index doesn't resolve).
#[cfg(feature = "__test_utils")]
pub fn build_minimal_ue4_27_with_null_object_ref() -> Vec<u8> {
    // Name table: 0=None, 1=NullRef, 2=ObjectProperty
    // FPropertyTag for ObjectProperty "NullRef" with value 0 (null):
    let payload = vec![
        0x01, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, // name FName (1, 0)
        0x02, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, // type FName (2, 0)
        0x04, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, // size i64 = 4
        0x00, 0x00, 0x00, 0x00,                           // array_index i32 = 0
        0x00,                                             // has_property_guid = 0
        0x00, 0x00, 0x00, 0x00,                           // value i32 = 0 (null)
        0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, // None terminator
    ];
    build_with_payload(&["None", "NullRef", "ObjectProperty"], payload).bytes
}
```

Also add the `build_with_payload_and_import` helper (a variant of Phase 2b's `build_with_payload` that accepts an import name):

```rust
/// Like `build_with_payload` but adds one import whose `object_name` FName
/// resolves to `import_name`. Used by ObjectProperty resolution tests that
/// need a resolvable import ref.
///
/// Wire-format requirement (per Phase 2a): `ObjectImport` stores FName
/// indices (`u32`), not strings. So `import_name` must appear in the
/// name table and the import row references it by index. This helper
/// appends `import_name` to the names slice, then writes one
/// `ObjectImport` whose `object_name` is the new index.
#[cfg(feature = "__test_utils")]
pub fn build_with_payload_and_import(
    names: &[&str],
    export_payload: Vec<u8>,
    import_name: &str,
) -> MinimalPackage {
    // Append the import_name to the name table. The new entry's index is
    // `names.len()` (next slot after the existing names). The "Class" and
    // "/Script/CoreUObject" names are also added — Phase 2a's
    // ObjectImport::write_to emits u32 indices for class_package_name,
    // class_name, and object_name, so all three must be FName-resolvable.
    let mut extended_names: Vec<String> = names.iter().map(|s| s.to_string()).collect();
    let object_name_idx = extended_names.len() as u32;
    extended_names.push(import_name.to_string());
    let class_name_idx = extended_names.len() as u32;
    extended_names.push("Class".to_string());
    let class_package_name_idx = extended_names.len() as u32;
    extended_names.push("/Script/CoreUObject".to_string());

    // Build the standard minimal package using the extended name list, then
    // overwrite its import table with one entry referencing the new indices.
    // `build_with_payload` returns a `MinimalPackage` with the bytes already
    // serialized — to inject an import we need a lower-level builder that
    // accepts an `imports: &[ObjectImport]` parameter.
    //
    // Phase 2a's `build_minimal_ue4_27` is the right level: it accepts the
    // name list, the imports list, the exports list, and the payload. This
    // helper is a thin wrapper that constructs the one-import case.
    use crate::asset::{
        import_table::ObjectImport,
        package_index::PackageIndex,
    };
    let imports = vec![ObjectImport {
        class_package_name: class_package_name_idx,
        class_package_number: 0,
        class_name: class_name_idx,
        class_name_number: 0,
        outer_index: PackageIndex::Null,
        object_name: object_name_idx,
        object_name_number: 0,
        import_optional: None,
    }];
    let extended_refs: Vec<&str> = extended_names.iter().map(String::as_str).collect();
    build_minimal_ue4_27_with_imports_and_payload(&extended_refs, &imports, export_payload)
}
```

> **Impl note:** `build_minimal_ue4_27_with_imports_and_payload` is the lower-level builder that this helper delegates to. If Phase 2a's `build_minimal_ue4_27` doesn't already accept an `imports: &[ObjectImport]` parameter, extend it (or add a sibling function) before calling here. The helper's job is to compute the right FName indices; the actual binary emission lives in the existing builder.

- [ ] **Step 3: Run tests to confirm compile errors (expected at this point)**

```bash
cargo test -p paksmith-core --test companion_integration 2>&1 | tail -20
```

Expected: compile errors for `build_minimal_ue4_27_with_object_ref`, `build_minimal_ue4_27_with_null_object_ref` not yet in scope, or a missing `build_minimal_ue4_27_with_imports_and_payload`. This is the failing-test phase.

- [ ] **Step 4: Implement the import-aware builder**

If Phase 2a's `build_minimal_ue4_27` does not yet accept imports, extend it (or add `build_minimal_ue4_27_with_imports_and_payload`) so the output pak's import table contains the given `ObjectImport` records. The function should:

1. Write the extended name table (all names referenced by the import + the payload).
2. Write the import table with the provided records (using `ObjectImport::write_to` from Phase 2a).
3. Write the export table (one export, `class_index = PackageIndex::Null`, the payload's `serial_offset` and `serial_size` set correctly).
4. Concatenate the summary + tables + payload into the final `bytes`.

The name table and import table offsets/counts in the summary must be updated to match the actual extended layout.

- [ ] **Step 5: Run integration tests**

```bash
cargo test -p paksmith-core --test companion_integration 2>&1 | tail -30
```

Expected: all 6 tests pass.

- [ ] **Step 6: Run full test suite**

```bash
cargo test --workspace 2>&1 | tail -20
```

Expected: no regressions.

- [ ] **Step 7: Run workspace clippy**

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Expected: clean.

- [ ] **Step 8: Commit**

```bash
git add \
  crates/paksmith-core/tests/companion_integration.rs \
  crates/paksmith-core/src/testing/uasset.rs
git commit -m "$(cat <<'EOF'
test(companion): 6 integration tests for companion file states + ObjectProperty

Four companion states: monolithic-ok, split-ok, split-missing-uexp-error,
monolithic-with-excess-uexp-warns-ok. Two ObjectProperty tests: null index
resolves to "", import ref resolves to object_name from ImportTable.
EOF
)"
```

---

### Task 7: CLI snapshot update

**Files:**

- Modify: `crates/paksmith-cli/src/commands/inspect.rs`

The `Object` variant in JSON output has changed from `{ "index": -1 }` to `{ "index": -1, "name": "/Script/Engine" }`. Any insta snapshot that serializes a `PropertyValue::Object` must be updated.

- [ ] **Step 1: Run the failing snapshot tests**

```bash
cargo test -p paksmith-cli 2>&1 | tail -30
```

Expected: insta snapshot failures for any test that contains `"Object"` in the snapshot. The diff will show the `name` field being missing from the saved snapshot.

- [ ] **Step 2: Review the diffs**

```bash
cargo insta review
```

Or check the `.snap.new` files written to `crates/paksmith-cli/src/commands/snapshots/`. Verify the new snapshots contain `"index"` AND `"name"` fields for `Object` variants. The resolved name should be the import/export name from the test fixture's object table.

- [ ] **Step 3: Accept snapshots**

```bash
cargo insta accept
```

- [ ] **Step 4: Run tests to confirm pass**

```bash
cargo test -p paksmith-cli 2>&1 | tail -10
```

Expected: all tests pass.

- [ ] **Step 5: Run workspace clippy**

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add crates/paksmith-cli/src/commands/ crates/paksmith-cli/src/commands/snapshots/
git commit -m "$(cat <<'EOF'
chore(cli): update inspect snapshot for Object { index, name }

PropertyValue::Object now includes resolved name. Snapshot updated to
reflect { "index": N, "name": "..." } shape from Phase 2e.
EOF
)"
```

---

## Self-review

### Spec coverage

| Deferred item from prior plans                      | Covered in Phase 2e?                       |
| --------------------------------------------------- | ------------------------------------------ |
| `.uexp` companion file stitching (Phase 2a, 2b, 2c) | ✓ Tasks 3, 4, 5                            |
| `ObjectProperty` resolution (Phase 2d)              | ✓ Task 2, 6                                |
| `.ubulk` detection (Phase 2b)                       | ✓ Task 4 (warn only; stitching deferred)   |
| `StructProperty` as collection element              | ✗ Deferred — empirical verification needed |
| Unversioned properties                              | ✗ Deferred — Phase 2f                      |

### Placeholder scan

- Task 6 Step 4 contains a `todo!` for `build_with_payload_and_import`. This is intentional — the plan cannot prescribe the exact builder refactor without seeing Phase 2a's implementation. The `todo!` MUST be replaced before committing Task 6.

### Type consistency

- `PropertyValue::Object { index: i32, name: String }` — defined in Task 2 Step 5, used in Task 6 tests.
- `CompanionFileKind::Uexp` — defined in Task 1 Step 3, matched in Task 3 Step 3 and Task 6 test 3.
- `resolve_package_index(index: i32, ctx: &AssetContext, asset_path: &str) -> crate::Result<String>` — defined in Task 2 Step 3, called in Task 2 Step 5 (both read functions).
- `derive_companion_path(base: &str, new_ext: &str) -> String` — defined in Task 4 Step 2, called in Task 4 Step 3.
- `build_minimal_ue4_27_split() -> (Vec<u8>, Vec<u8>)` — defined in Task 5 Step 3, used in Task 3 Step 1 (stub) and Task 6.
- `MinimalPackage.total_header_size: usize` — added in Task 5 Step 1, used in Task 5 Step 3.

### Lint gate

Every task ends with `cargo clippy --workspace --all-targets --all-features -- -D warnings` (per `MEMORY.md` `ghas_clippy_extra_lints.md`) AND `cargo fmt --all -- --check`. CI's `Lint` job runs both; clippy passing locally does NOT imply fmt is clean — see PR #149 follow-up. The `.githooks/pre-commit` hook enforces both when wired up via `git config core.hooksPath .githooks` (one-time per clone).
