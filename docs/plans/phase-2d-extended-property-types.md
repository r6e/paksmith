# Paksmith Phase 2d: Extended Property Types

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Scope revision applied at Phase 2e.** This plan specifies
> `PropertyValue::Object(PackageIndex)` as a tuple variant with name
> resolution explicitly deferred — JSON shape `{"Object":"Import(N)"}`.
> Phase 2e expanded the contract: the as-shipped variant is a struct
> `Object { kind: PackageIndex, name: String }` with eager name
> resolution via `resolve_package_index` at parse time. JSON shape is
> `{"Object":{"kind":"Import(N)","name":"<resolved>"}}`. The pin tests
> and example JSON throughout this Phase 2d plan that show
> `{"Object":"Import(N)"}` are historical; the as-shipped contract is
> in `crates/paksmith-core/src/asset/property/primitives.rs::PropertyValue::Object`
> and pinned by the `extended_types_integration.rs::object_property_resolves_import_name`
> integration test in Phase 2e.

**Goal:** Decode `SoftObjectProperty`, `SoftClassProperty`, and `ObjectProperty` as direct tagged properties, and extend collection element decoding to handle `ByteProperty`, `EnumProperty`, `TextProperty`, `SoftObjectProperty`, `SoftClassProperty`, and `ObjectProperty` inner types — replacing the `Unknown { skipped_bytes }` fallback for these six types inside `ArrayProperty`, `MapProperty`, and `SetProperty`.

**Architecture:** Three new `PropertyValue` variants (`SoftObjectPath`, `SoftClassPath`, `Object`) land in `primitives.rs`. A new `pub(super) fn read_soft_path_payload` helper there is shared by both the direct reader (`read_primitive_value`) and the element reader (`read_element_value`) in `containers.rs`. Two new `AssetParseFault` variants (`TextHistoryUnsupportedInElement` to prevent silent cursor corruption when `read_ftext` encounters an unknown history type with no per-element size available, and `UnsupportedSoftObjectPathLayout` to reject UE5 ≥ 1007 archives where `FSoftObjectPath` switches to `FTopLevelAssetPath` rather than silently mis-decode) land in `error.rs`. Three new `AssetWireField` variants (`SoftObjectAssetPath`, `ObjectPropertyIndex`, `EnumElementFName`) name the new wire-field sites. `is_handled_element_type` grows from 12 to 18 types.

**Tech Stack:** Same as Phase 2c — Rust 1.85, `thiserror`, `byteorder` (LE), `serde`, `tracing`, `proptest`, `unreal_asset` (fixture-gen oracle, pinned to `f4df5d8e`). No new crate dependencies.

---

## Deliverable

`paksmith inspect <pak> <virtual/path>` now renders soft references, object references, and arrays/maps/sets whose elements are bytes, enums, text, soft objects, or object references. Example JSON for a cooked asset with extended property types:

```json
{
  "asset_path": "Game/Data/Hero.uasset",
  "exports": [
    {
      "object_name": "Hero",
      "properties": [
        {
          "name": "SoftRef",
          "value": {
            "SoftObjectPath": {
              "asset_path": "/Game/Data/Mesh.Mesh",
              "sub_path": ""
            }
          }
        },
        {
          "name": "SoftClass",
          "value": {
            "SoftClassPath": {
              "asset_path": "/Game/BP/HeroClass.HeroClass_C",
              "sub_path": ""
            }
          }
        },
        {
          "name": "ObjRef",
          "value": { "Object": "Import(0)" }
        },
        {
          "name": "Tags",
          "value": {
            "Array": {
              "inner_type": "ByteProperty",
              "elements": [{ "Byte": 10 }, { "Byte": 20 }]
            }
          }
        },
        {
          "name": "Flags",
          "value": {
            "Array": {
              "inner_type": "EnumProperty",
              "elements": [
                { "Enum": { "type_name": "", "value": "EColor__Red" } }
              ]
            }
          }
        }
      ]
    }
  ]
}
```

## Scope vs. deferred work

**In scope (this plan):**

- `SoftObjectProperty` and `SoftClassProperty` as direct properties: `FName asset_path` + `FString sub_path` → `PropertyValue::SoftObjectPath` / `PropertyValue::SoftClassPath` (asset_path is resolved through the name table; sub_path is a raw FString)
- `ObjectProperty` as a direct property: raw `i32` decoded into `PackageIndex` (`0 = Null`, positive = export, negative = import) → `PropertyValue::Object(PackageIndex)`. Name resolution to the import/export entry is deferred.
- `ByteProperty` elements inside collections: raw `u8` → `PropertyValue::Byte`
- `EnumProperty` elements inside collections: FName pair → `PropertyValue::Enum { type_name: "".to_string(), value }`
- `TextProperty` elements inside collections: `read_ftext(tag_size=0)` with Unknown-history guard
- `SoftObjectProperty` and `SoftClassProperty` elements inside collections: delegate to `read_soft_path_payload`
- `ObjectProperty` elements inside collections: raw `i32` decoded into `PackageIndex`
- `TextHistoryUnsupportedInElement { history_type: i8 }` fault to prevent cursor corruption on unknown FText history types in element context
- `UnsupportedSoftObjectPathLayout { ue5_version: i32 }` fault rejects UE5 ≥ 1007 archives so the parser errors loudly rather than silently mis-decoding `FSoftObjectPath` (which becomes `FTopLevelAssetPath`-based at that version)
- Three new `AssetWireField` variants: `SoftObjectAssetPath`, `ObjectPropertyIndex`, `EnumElementFName`
- Integration test fixture `build_minimal_ue4_27_with_extended_types` + 6 integration tests
- Fixture-gen cross-validation against `unreal_asset` oracle

**Deferred to Phase 2e+:**

- `StructProperty` as a collection element (wire format requires empirical verification of length-prefix behavior per `feedback_verify_wire_format_claims.md`)
- `ObjectProperty` resolution: mapping the raw `index` to an import/export name requires the full object table
- UInt8/Int8 as enum base types in collection context
- Map key/value types covered by Phase 2d (Soft\*, Object) — already decoded; no extra work needed
- `ByteProperty<EnumName>` in collection element context — direct `ByteProperty` discriminates via `tag.enum_name`, but a collection element has no per-element tag header. Phase 2d decodes raw u8 only; resolving the per-element enum FName requires schema-side support deferred to Phase 2e+.
- `SoftObjectProperty` wire format at UE5 ≥ 1007 (`FTopLevelAssetPath` shape) is rejected with `UnsupportedSoftObjectPathLayout`. UE5 ≥ 1008 changes to a single i32 index into the summary's `SoftObjectPaths` list. Both variants are Phase 2g concerns; until then, the parser errors loudly rather than corrupting silently.

---

## File structure

| File                                                       | Action | Responsibility                                                                                                                                       |
| ---------------------------------------------------------- | ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `crates/paksmith-core/src/error.rs`                        | Modify | Add `TextHistoryUnsupportedInElement` + `UnsupportedSoftObjectPathLayout` faults, 3 `AssetWireField` variants, Display arms, and pin-table extension |
| `crates/paksmith-core/src/asset/property/primitives.rs`    | Modify | Add `SoftObjectPath`, `SoftClassPath`, `Object` variants; `read_soft_path_payload` helper; extend `read_primitive_value`                             |
| `crates/paksmith-core/src/asset/property/containers.rs`    | Modify | Extend `is_handled_element_type` and `read_element_value`; add TextProperty element guard                                                            |
| `crates/paksmith-core/src/testing/uasset.rs`               | Modify | Add `build_minimal_ue4_27_with_extended_types`                                                                                                       |
| `crates/paksmith-core/tests/extended_types_integration.rs` | Create | 6 integration tests                                                                                                                                  |
| `crates/paksmith-fixture-gen/src/uasset.rs`                | Modify | Add `write_minimal_ue4_27_with_extended_types` + oracle cross-validation                                                                             |

---

## PR workflow

Every task here ships as one PR. Per project convention:

- **Branch naming:** `feat/<kebab-case>` (or `test/`, `chore/`, etc. matching the conventional-commit prefix). Never use the EnterWorktree default `worktree-<name>` form — rename before pushing. See `feedback_branch_naming_convention.md`.
- **PR titles:** lowercase verb-first imperative (e.g. `add SoftObjectPath PropertyValue variants`). No `Phase 2d:` prefix in the subject — release-track markers go in the body. See `feedback_pr_title_lowercase_verb_first.md`.
- **PR body:** write to a tempfile via `gh pr create --body-file <tmp>` heredoc; never inline through `--body "$(cat <<EOF ...)"` because backticks get escaped and ship verbatim. See `feedback_pr_body_no_backtick_escaping.md`.
- **Reviewer panel:** every PR (refactor / docs / polish included) gets the standard 3-reviewer panel (code-quality + simplifier + security) dispatched in parallel + a convergence loop until all reviewers say APPROVED. Don't ask permission to run it. See `feedback_always_run_review_panel.md` and `feedback_review_until_convergence.md`.
- **Commit subjects:** conventional-commit prefix + lowercase imperative. Drop any `(Phase 2d)` suffix — the release track lives in the body, not the subject.

---

### Task 1: New error types and wire field variants

**Files:**

- Modify: `crates/paksmith-core/src/error.rs`

- [ ] **Step 1: Write failing Display pin tests**

Find the `#[cfg(test)]` block in `error.rs` (the block containing `asset_parse_display_*` tests added in earlier phases) and add:

```rust
#[test]
fn asset_parse_display_text_history_unsupported_in_element() {
    let s = AssetParseFault::TextHistoryUnsupportedInElement { history_type: 3 }.to_string();
    assert_eq!(s, "text history type 3 is not supported in collection elements");
}

#[test]
fn asset_parse_display_unsupported_soft_object_path_layout() {
    let s = AssetParseFault::UnsupportedSoftObjectPathLayout { ue5_version: 1007 }.to_string();
    assert_eq!(
        s,
        "unsupported FSoftObjectPath wire layout at UE5 version 1007 \
         (FTopLevelAssetPath replaces FName at >= 1007; Phase 2d only \
         decodes UE5 <= 1006)"
    );
}

#[test]
fn asset_wire_field_display_soft_object_asset_path() {
    assert_eq!(AssetWireField::SoftObjectAssetPath.to_string(), "soft_object_asset_path");
}

#[test]
fn asset_wire_field_display_object_property_index() {
    assert_eq!(AssetWireField::ObjectPropertyIndex.to_string(), "object_property_index");
}

#[test]
fn asset_wire_field_display_enum_element_fname() {
    assert_eq!(AssetWireField::EnumElementFName.to_string(), "enum_element_fname");
}
```

- [ ] **Step 2: Run tests to confirm compile error**

```bash
cargo test -p paksmith-core --lib error::tests::asset_parse_display_text_history_unsupported_in_element 2>&1 | tail -10
```

Expected: compile error — `TextHistoryUnsupportedInElement` not found.

- [ ] **Step 3: Add new variants to `AssetParseFault`**

`AssetParseFault` at `error.rs:2117` is NOT `thiserror`-derived — its `Display` impl is hand-rolled at `error.rs:2380`. Adding `#[error("...")]` attributes here would compile (the attribute is silently ignored on a plain enum) but contribute nothing; the Display arm in Step 3b is what actually produces the wire-stable string.

Find `pub enum AssetParseFault` and add after the last existing variant:

```rust
/// A `TextProperty` element inside an Array/Map/Set used an FText
/// history type that cannot be decoded without per-element size info.
///
/// In element context `tag_size` is 0; for `FTextHistory::Unknown` this
/// would skip 0 bytes and silently corrupt the reader cursor. Returning
/// this error prevents that.
TextHistoryUnsupportedInElement {
    /// The unknown history-type discriminant byte (i8) the reader hit.
    history_type: i8,
},
/// The asset's `FileVersionUE5` is at or above
/// `FSOFTOBJECTPATH_REMOVE_ASSET_PATH_FNAMES = 1007`, where
/// `FSoftObjectPath` switches its `asset_path_name` slot from `FName`
/// to `FTopLevelAssetPath` (`FName package + FName asset`). Phase 2d
/// only decodes the UE4-shape (single FName + FString sub_path);
/// reading a 1007+ archive without this guard would mis-align the
/// reader cursor and silently corrupt every subsequent property.
/// Phase 2a accepts UE5 ∈ [1000, 1010], so this guard is meaningful
/// — it carves out 1007..=1010 inside the accepted summary range.
UnsupportedSoftObjectPathLayout {
    /// The `FileVersionUE5` value as read from the asset summary.
    ue5_version: i32,
},
```

- [ ] **Step 3b: Add Display arms for the new `AssetParseFault` variants**

`AssetParseFault` has a hand-rolled `impl fmt::Display` at `error.rs:2380`. Add arms in the `match self { ... }` block (after the `CollectionElementCountExceeded` arm added in Phase 2c):

```rust
Self::TextHistoryUnsupportedInElement { history_type } => write!(
    f,
    "text history type {history_type} is not supported in collection elements"
),
Self::UnsupportedSoftObjectPathLayout { ue5_version } => write!(
    f,
    "unsupported FSoftObjectPath wire layout at UE5 version {ue5_version} \
     (FTopLevelAssetPath replaces FName at >= 1007; Phase 2d only \
     decodes UE5 <= 1006)"
),
```

- [ ] **Step 4: Add 3 new `AssetWireField` variants**

Find `pub enum AssetWireField` and add after the last Phase 2c variant (`SetElement`):

```rust
/// The first slot of an `FSoftObjectPath` payload — the `(index,
/// number)` FName pair naming the asset (UE4 and UE5 < 1007 shape).
SoftObjectAssetPath,
/// The `i32` package index in an `ObjectProperty` payload.
ObjectPropertyIndex,
/// The `(index, number)` FName pair stored in an `EnumProperty` collection element.
EnumElementFName,
```

- [ ] **Step 5: Add Display arms for the new `AssetWireField` variants**

Find `impl fmt::Display for AssetWireField` and add after the last Phase 2c arm:

```rust
            Self::SoftObjectAssetPath => "soft_object_asset_path",
            Self::ObjectPropertyIndex => "object_property_index",
            Self::EnumElementFName => "enum_element_fname",
```

- [ ] **Step 5b: Extend `asset_wire_field_display_tokens_are_wire_stable` pin table**

The pin table at `error.rs:4675` enumerates every `AssetWireField` variant. Append these rows (before the closing `]`):

```rust
(AssetWireField::SoftObjectAssetPath, "soft_object_asset_path"),
(AssetWireField::ObjectPropertyIndex, "object_property_index"),
(AssetWireField::EnumElementFName, "enum_element_fname"),
```

This pin guards against Display-arm typos that would compile and pass clippy but silently break downstream tooling. PR #274 had to retrofit this guard during Phase 2c; do not skip the extension here.

- [ ] **Step 6: Run the Display-stability tests**

```bash
cargo test -p paksmith-core --lib error::tests 2>&1 | tail -20
```

Expected: all tests pass, including the 5 new pin tests and the now-expanded `asset_wire_field_display_tokens_are_wire_stable`.

- [ ] **Step 7: Lint and format gates**

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
```

Expected: all clean. `RUSTDOCFLAGS="-D warnings"` enforces `rustdoc::private_intra_doc_links`, which is a CI gate not covered by `cargo clippy` — see `feedback_run_fmt_and_clippy.md` and `feedback_ci_checks_beyond_pre_commit.md`.

- [ ] **Step 8: Commit**

```bash
git add crates/paksmith-core/src/error.rs
git commit -m "$(cat <<'EOF'
feat(error): add AssetParseFault + AssetWireField variants for extended properties

TextHistoryUnsupportedInElement prevents silent cursor corruption when
an unknown FText history type appears inside a collection element
(tag_size=0 means Unknown would skip 0 bytes).
UnsupportedSoftObjectPathLayout rejects UE5 >= 1007 where FSoftObjectPath
switches to FTopLevelAssetPath, so the parser errors loudly rather than
mis-decoding silently. Three new AssetWireField variants for the new
wire sites (SoftObjectAssetPath / ObjectPropertyIndex / EnumElementFName).
Display strings wire-stable, pinned by new unit tests; the
asset_wire_field_display_tokens_are_wire_stable pin table is extended
to cover the new variants.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: New `PropertyValue` variants (SoftObjectPath, SoftClassPath, Object)

**Files:**

- Modify: `crates/paksmith-core/src/asset/property/primitives.rs`

- [ ] **Step 1: Write failing serialization tests**

`PackageIndex` serializes via `serializer.collect_str(self)` (see `asset/package_index.rs:109-117`) — rendered as `"Null"` / `"Import(N)"` / `"Export(N)"` strings, NOT as a tagged object. So `PropertyValue::Object(PackageIndex)` as a tuple variant emits `{"Object":"Import(N)"}`. Add to the `tests` module in `primitives.rs`:

```rust
#[test]
fn property_value_soft_object_path_serializes() {
    let v = PropertyValue::SoftObjectPath {
        asset_path: "/Game/Data/Hero.Hero".to_string(),
        sub_path: String::new(),
    };
    let json = serde_json::to_string(&v).unwrap();
    assert_eq!(
        json,
        r#"{"SoftObjectPath":{"asset_path":"/Game/Data/Hero.Hero","sub_path":""}}"#
    );
}

#[test]
fn property_value_soft_class_path_serializes() {
    let v = PropertyValue::SoftClassPath {
        asset_path: "/Game/BP/HeroClass.HeroClass_C".to_string(),
        sub_path: "SubObject".to_string(),
    };
    let json = serde_json::to_string(&v).unwrap();
    assert_eq!(
        json,
        r#"{"SoftClassPath":{"asset_path":"/Game/BP/HeroClass.HeroClass_C","sub_path":"SubObject"}}"#
    );
}

#[test]
fn property_value_object_import_serializes() {
    let v = PropertyValue::Object(PackageIndex::Import(2));
    let json = serde_json::to_string(&v).unwrap();
    assert_eq!(json, r#"{"Object":"Import(2)"}"#);
}

#[test]
fn property_value_object_null_serializes() {
    let v = PropertyValue::Object(PackageIndex::Null);
    let json = serde_json::to_string(&v).unwrap();
    assert_eq!(json, r#"{"Object":"Null"}"#);
}

#[test]
fn property_value_object_export_serializes() {
    let v = PropertyValue::Object(PackageIndex::Export(1));
    let json = serde_json::to_string(&v).unwrap();
    assert_eq!(json, r#"{"Object":"Export(1)"}"#);
}
```

Add `use crate::asset::package_index::PackageIndex;` to the test imports if not already in scope (the primitives `tests` module is in-file; verify the existing import block before editing).

- [ ] **Step 2: Run tests to confirm compile error**

```bash
cargo test -p paksmith-core --lib asset::property::primitives::tests::property_value_soft_object_path_serializes 2>&1 | tail -10
```

Expected: compile error — `PropertyValue::SoftObjectPath` not found.

- [ ] **Step 3: Add the three new variants to `PropertyValue`**

The `Object` variant wraps `PackageIndex` directly rather than a raw `i32` because every other asset-side object-table reference in the codebase already uses the typed enum (`ObjectImport.outer_index`, `ObjectExport.class_index`, etc.). Reinventing a raw `i32` here would diverge from the established convention.

Add `use crate::asset::package_index::PackageIndex;` to the top-of-file `use` block if not already imported.

Find `pub enum PropertyValue` and add after `Unknown`:

```rust
    /// `SoftObjectProperty` — a non-owning soft reference to an asset by path.
    ///
    /// Wire format: `FName asset_path` (resolved through the name table) +
    /// `FString sub_path`. Sub-path is usually empty in cooked assets.
    /// The `asset_path` field below holds the resolved string, not the raw
    /// FName indices.
    SoftObjectPath {
        /// Primary asset path (e.g. `/Game/Data/Hero.Hero`).
        asset_path: String,
        /// Sub-object path within the asset; empty string for none.
        sub_path: String,
    },

    /// `SoftClassProperty` — a soft reference to a class by path.
    ///
    /// Identical wire format to `SoftObjectPath`.
    SoftClassPath {
        /// Primary class path (e.g. `/Game/BP/HeroClass.HeroClass_C`).
        asset_path: String,
        /// Sub-object path; empty string for none.
        sub_path: String,
    },

    /// `ObjectProperty` — a hard object reference as a typed
    /// [`PackageIndex`].
    ///
    /// The wire is a single `i32` decoded via `PackageIndex::try_from_raw`:
    /// `0 → Null`, positive → `Export(n-1)`, negative → `Import(-n-1)`,
    /// `i32::MIN` → `AssetParseFault::PackageIndexUnderflow`. Resolution
    /// of the index to a named object (walking the import/export table)
    /// is deferred to Phase 2e+.
    Object(PackageIndex),
```

- [ ] **Step 4: Run serialization tests**

```bash
cargo test -p paksmith-core --lib asset::property::primitives::tests 2>&1 | tail -20
```

Expected: all primitive tests pass, including the 5 new serialization tests.

- [ ] **Step 5: Lint and format gates**

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
```

Expected: all clean.

- [ ] **Step 6: Commit**

```bash
git add crates/paksmith-core/src/asset/property/primitives.rs
git commit -m "$(cat <<'EOF'
feat(property): add SoftObjectPath, SoftClassPath, Object PropertyValue variants

Three new PropertyValue variants for extended property types.
SoftObjectPath and SoftClassPath each carry asset_path + sub_path strings
decoded from one FName + one FString on the wire. Object wraps the
existing PackageIndex enum so JSON output renders as
`{"Object":"Import(N)"}` / `{"Object":"Null"}` / `{"Object":"Export(N)"}`
consistent with the rest of the asset-side object-reference surface.
Serialization shapes pinned by five unit tests.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: `read_soft_path_payload` helper + extend `read_primitive_value`

**Files:**

- Modify: `crates/paksmith-core/src/asset/property/primitives.rs`

- [ ] **Step 1: Write failing tests for the three new direct property reads**

Add to the `tests` module in `primitives.rs`. Tag sizes below are exact byte counts of the payload that follows the tag header — 8 bytes for the FName pair plus 5 bytes for the empty FString (`i32 len=1` + `b'\0'`) = 13 bytes total for the soft path tests.

```rust
#[test]
fn soft_object_property_value() {
    let tag = make_tag("SoftObjectProperty", 13);
    // Name table maps index 1 to the asset path string.
    let ctx = make_ctx(&["None", "/Game/Data/Hero.Hero"]);
    let mut buf: Vec<u8> = Vec::new();
    // FName asset_path: i32 index = 1, i32 number = 0  (8 bytes)
    buf.extend_from_slice(&1i32.to_le_bytes());
    buf.extend_from_slice(&0i32.to_le_bytes());
    // FString sub_path: empty (len = 1 for null terminator only)  (5 bytes)
    buf.extend_from_slice(&1i32.to_le_bytes());
    buf.push(b'\0');
    let val = read_primitive_value(&tag, &mut Cursor::new(&buf), &ctx, "x")
        .unwrap()
        .unwrap();
    assert_eq!(
        val,
        PropertyValue::SoftObjectPath {
            asset_path: "/Game/Data/Hero.Hero".to_string(),
            sub_path: String::new(),
        }
    );
}

#[test]
fn soft_class_property_value() {
    let tag = make_tag("SoftClassProperty", 13);
    let ctx = make_ctx(&["None", "/Game/BP/HeroClass.HeroClass_C"]);
    let mut buf: Vec<u8> = Vec::new();
    // FName asset_path: i32 index = 1, i32 number = 0
    buf.extend_from_slice(&1i32.to_le_bytes());
    buf.extend_from_slice(&0i32.to_le_bytes());
    // FString sub_path: empty
    buf.extend_from_slice(&1i32.to_le_bytes());
    buf.push(b'\0');
    let val = read_primitive_value(&tag, &mut Cursor::new(&buf), &ctx, "x")
        .unwrap()
        .unwrap();
    assert_eq!(
        val,
        PropertyValue::SoftClassPath {
            asset_path: "/Game/BP/HeroClass.HeroClass_C".to_string(),
            sub_path: String::new(),
        }
    );
}

#[test]
fn object_property_null_index() {
    let tag = make_tag("ObjectProperty", 4);
    let ctx = make_ctx(&["None"]);
    let val = read_primitive_value(&tag, &mut Cursor::new(&0i32.to_le_bytes()), &ctx, "x")
        .unwrap()
        .unwrap();
    assert_eq!(val, PropertyValue::Object(PackageIndex::Null));
}

#[test]
fn object_property_import_index() {
    let tag = make_tag("ObjectProperty", 4);
    let ctx = make_ctx(&["None"]);
    let val =
        read_primitive_value(&tag, &mut Cursor::new(&(-3i32).to_le_bytes()), &ctx, "x")
            .unwrap()
            .unwrap();
    // wire i32 -3 → Import(2)
    assert_eq!(val, PropertyValue::Object(PackageIndex::Import(2)));
}

#[test]
fn object_property_export_index() {
    let tag = make_tag("ObjectProperty", 4);
    let ctx = make_ctx(&["None"]);
    let val = read_primitive_value(&tag, &mut Cursor::new(&2i32.to_le_bytes()), &ctx, "x")
        .unwrap()
        .unwrap();
    // wire i32 2 → Export(1)
    assert_eq!(val, PropertyValue::Object(PackageIndex::Export(1)));
}

#[test]
fn soft_object_property_ue5_post_1007_rejected() {
    // Build a SoftObjectProperty tag on a UE5 1007 context — the parser
    // must error rather than silently consume bytes that belong to the
    // FTopLevelAssetPath wire layout.
    let tag = make_tag("SoftObjectProperty", 16);
    let mut ctx = make_ctx(&["None", "/Game/Data/Hero.Hero"]);
    ctx.version.file_version_ue5 = Some(1007);
    let buf = vec![0u8; 16];
    let err = read_primitive_value(&tag, &mut Cursor::new(&buf), &ctx, "x").unwrap_err();
    assert!(matches!(
        err,
        crate::PaksmithError::AssetParse {
            fault: crate::error::AssetParseFault::UnsupportedSoftObjectPathLayout {
                ue5_version: 1007
            },
            ..
        }
    ));
}
```

The `make_ctx` test helper currently builds an `AssetContext` with `file_version_ue5: None`; the UE5-1007 test sets it directly on the returned context. If `make_ctx` does not expose `version` as a public field, add a `make_ctx_with_ue5(names: &[&str], ue5: Option<i32>)` shim in `property/test_utils.rs` and use that.

- [ ] **Step 2: Run tests to confirm compile error**

```bash
cargo test -p paksmith-core --lib asset::property::primitives::tests::soft_object_property_value 2>&1 | tail -10
```

Expected: compile error — `read_soft_path_payload` and new match arms not found.

- [ ] **Step 3: Add `read_soft_path_payload` before `read_primitive_value`**

Wire format (cross-referenced against the CUE4Parse `FSoftObjectPath` constructor):

```text
[UE4 >= ADDED_SOFT_OBJECT_PATH (514), at our floor:]
FName  asset_path_name       (i32 name_index + i32 number = 8 bytes)
FStr   sub_path_string

[UE5 >= FSOFTOBJECTPATH_REMOVE_ASSET_PATH_FNAMES (1007):]
FTopLevelAssetPath asset_path_name   (2 × FName = 16 bytes — package + asset)
FStr   sub_path_string

[UE5 >= ADD_SOFTOBJECTPATH_LIST (1008) with PKG_FilterEditorOnly set:]
i32    index_into_summary.soft_object_paths
```

Phase 2d only decodes the UE4 / UE5 ≤ 1006 shape. The function rejects UE5 ≥ 1007 with `UnsupportedSoftObjectPathLayout` rather than silently misaligning the cursor — Phase 2a accepts UE5 ∈ [1000, 1010] in the summary reader, so 1007..=1010 falls inside the accepted summary window but outside the safe property-parse window.

`AssetWireField` is already imported at module top (`primitives.rs:16`); no inner `use` needed. `unexpected_eof` is also already in scope from the existing `use super::{...}` block. Use `read_fname_pair` (the project-wide helper at `property/mod.rs:64`) and `read_asset_fstring` (already imported at `primitives.rs:15`) rather than calling `resolve_fname` / `read_fstring` directly — both helpers wrap their EOF / FString-malformed errors with `asset_path` context already, so no `extract_fstring_fault` shim is needed.

```rust
/// Reads an `FSoftObjectPath` payload: FName `asset_path` + FString
/// `sub_path`. Shared by `read_primitive_value` (direct
/// SoftObjectProperty / SoftClassProperty) and by `read_element_value`
/// (the same types as collection elements).
///
/// Returns `(asset_path, sub_path)` so the caller can wrap the pair
/// into the right `PropertyValue` variant.
///
/// Phase 2d only handles the UE4 / UE5 < 1007 wire shape. UE5 ≥ 1007
/// switches the first slot to `FTopLevelAssetPath` (2 FNames) and UE5
/// ≥ 1008 changes the entire payload to an `i32` index into the
/// summary's `SoftObjectPaths` list; both require summary-side support
/// deferred to Phase 2g, so this function returns
/// `UnsupportedSoftObjectPathLayout` at UE5 ≥ 1007 rather than
/// mis-decoding silently.
///
/// `pub(super)` so `containers.rs` can reuse this for element reads.
pub(super) fn read_soft_path_payload<R: Read>(
    reader: &mut R,
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<(String, String)> {
    if ctx
        .version
        .file_version_ue5
        .is_some_and(|v| v >= 1007)
    {
        return Err(PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::UnsupportedSoftObjectPathLayout {
                ue5_version: ctx.version.file_version_ue5.unwrap_or(0),
            },
        });
    }
    let obj_path =
        super::read_fname_pair(reader, ctx, asset_path, AssetWireField::SoftObjectAssetPath)?;
    let sub = crate::asset::read_asset_fstring(reader, asset_path)?;
    Ok((obj_path, sub))
}
```

If `PaksmithError` and `AssetParseFault` are not already imported in `primitives.rs`, extend the existing `use crate::error::AssetWireField;` line to:

```rust
use crate::error::{AssetParseFault, AssetWireField, PaksmithError};
```

- [ ] **Step 4: Extend `read_primitive_value` with three new match arms**

Find the `_ => return Ok(None),` arm in `read_primitive_value` and add before it:

```rust
        "SoftObjectProperty" => {
            let (obj_path, sub) = read_soft_path_payload(reader, ctx, asset_path)?;
            PropertyValue::SoftObjectPath {
                asset_path: obj_path,
                sub_path: sub,
            }
        }

        "SoftClassProperty" => {
            let (obj_path, sub) = read_soft_path_payload(reader, ctx, asset_path)?;
            PropertyValue::SoftClassPath {
                asset_path: obj_path,
                sub_path: sub,
            }
        }

        "ObjectProperty" => {
            let raw = reader
                .read_i32::<LittleEndian>()
                .map_err(|_| unexpected_eof(asset_path, AssetWireField::ObjectPropertyIndex))?;
            PropertyValue::Object(PackageIndex::try_from_raw(raw).map_err(|_| {
                PaksmithError::AssetParse {
                    asset_path: asset_path.to_string(),
                    fault: AssetParseFault::PackageIndexUnderflow {
                        field: AssetWireField::ObjectPropertyIndex,
                    },
                }
            })?)
        }
```

- [ ] **Step 5: Run primitive tests**

```bash
cargo test -p paksmith-core --lib asset::property::primitives::tests 2>&1 | tail -20
```

Expected: all tests pass, including the 6 new tests.

- [ ] **Step 6: Lint and format gates**

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
```

Expected: all clean.

- [ ] **Step 7: Commit**

```bash
git add crates/paksmith-core/src/asset/property/primitives.rs
git commit -m "$(cat <<'EOF'
feat(property): add read_soft_path_payload + Soft*/ObjectProperty direct reads

read_soft_path_payload reads `FName asset_path + FString sub_path` and is
pub(super) for reuse in containers.rs. It rejects UE5 >= 1007 with
UnsupportedSoftObjectPathLayout so the parser errors loudly at the
FTopLevelAssetPath boundary rather than silently mis-decoding.
read_primitive_value gains arms for SoftObjectProperty + SoftClassProperty
(delegating to the helper) and ObjectProperty (raw i32 decoded into the
typed PackageIndex enum, surfacing i32::MIN as PackageIndexUnderflow).
Six unit tests cover Null/Import/Export indices, both soft path types, and
the UE5-1007 rejection.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: Extend `read_element_value` for ByteProperty and EnumProperty elements

**Files:**

- Modify: `crates/paksmith-core/src/asset/property/containers.rs`

Phase 2c left `ByteProperty` and `EnumProperty` element reads returning `None`. Two existing tests assert that. This task replaces those tests with correct-behavior tests and adds the implementation.

**ByteProperty element wire format:** single raw `u8` → `PropertyValue::Byte(u8)`. In direct context `ByteProperty` discriminates via `tag.enum_name`, but a collection element has no per-element tag header — Phase 2d only emits `PropertyValue::Byte`. Resolving `ByteProperty<EnumName>` in element context is deferred.

**EnumProperty element wire format:** FName pair `(i32 index, i32 number)` resolved via the name table → `PropertyValue::Enum { type_name: String::new(), value: resolved }`. The enum class name (`type_name`) is empty because in element context no per-element FPropertyTag carries the `enum_name` field — that is only on the outer array tag, which `read_element_value` does not receive.

Phase 2c's `read_element_value` signature is `fn read_element_value<R: Read + Seek>(type_name: &str, body_field: AssetWireField, reader: &mut R, ctx: &AssetContext, asset_path: &str)`. The new arms must pass `body_field` through to `unexpected_eof` (matching the existing primitive arms in `containers.rs:54-113`) — the caller already names the wire context (`ArrayElementBody`, `SetElement`, `MapKey`, `MapValue`) so the new arms never reach for arbitrary fields. The existing file uses fully-qualified `PropertyValue::*` (no `PV` alias), and `read_fname_pair` is already imported via `use super::{MAX_COLLECTION_ELEMENTS, read_fname_pair, unexpected_eof};` at the top of the file.

- [ ] **Step 1: Replace the two "returns none" tests with correct-behavior tests**

In the `tests` module in `containers.rs`, replace:

```rust
#[test]
fn element_enum_type_returns_none() {
    let ctx = make_ctx(&[]);
    let mut r = Cursor::new(vec![]);
    let v = read_element_value(
        "EnumProperty",
        AssetWireField::ArrayElementBody,
        &mut r,
        &ctx,
        "x.uasset",
    )
    .unwrap();
    assert!(v.is_none());
}

#[test]
fn element_byte_type_returns_none() {
    let ctx = make_ctx(&[]);
    let mut r = Cursor::new(vec![]);
    let v = read_element_value(
        "ByteProperty",
        AssetWireField::ArrayElementBody,
        &mut r,
        &ctx,
        "x.uasset",
    )
    .unwrap();
    assert!(v.is_none());
}
```

with:

```rust
#[test]
fn element_byte_reads_u8() {
    let ctx = make_ctx(&[]);
    let mut r = Cursor::new(vec![0xABu8]);
    let v = read_element_value(
        "ByteProperty",
        AssetWireField::ArrayElementBody,
        &mut r,
        &ctx,
        "x.uasset",
    )
    .unwrap()
    .unwrap();
    assert_eq!(v, PropertyValue::Byte(0xAB));
}

#[test]
fn element_enum_reads_fname() {
    // EnumProperty element: FName (index=1, number=0) → "EColor__Red"
    // type_name is empty because no per-element tag carries the enum class name.
    let ctx = make_ctx(&["None", "EColor__Red"]);
    let mut bytes = 1i32.to_le_bytes().to_vec();
    bytes.extend_from_slice(&0i32.to_le_bytes());
    let mut r = Cursor::new(bytes);
    let v = read_element_value(
        "EnumProperty",
        AssetWireField::ArrayElementBody,
        &mut r,
        &ctx,
        "x.uasset",
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        v,
        PropertyValue::Enum {
            type_name: String::new(),
            value: "EColor__Red".to_string(),
        }
    );
}
```

- [ ] **Step 2: Run test to confirm failure**

```bash
cargo test -p paksmith-core --lib asset::property::containers::tests::element_byte_reads_u8 2>&1 | tail -10
```

Expected: test fails — `read_element_value` returns `None` for `"ByteProperty"` currently.

- [ ] **Step 3: Add `ByteProperty` and `EnumProperty` arms to `read_element_value`, update `is_handled_element_type`**

In `read_element_value`, find `_ => return Ok(None),` and add before it:

```rust
        "ByteProperty" => {
            let b = reader
                .read_u8()
                .map_err(|_| unexpected_eof(asset_path, body_field))?;
            PropertyValue::Byte(b)
        }
        "EnumProperty" => {
            let value = read_fname_pair(reader, ctx, asset_path, body_field)?;
            PropertyValue::Enum {
                type_name: String::new(),
                value,
            }
        }
```

Update `is_handled_element_type` — **preserve the doc-comment above the function intact**; only modify the `matches!` body. The doc warns "Keep this list in sync with `read_element_value`'s match arms" and is load-bearing:

```rust
fn is_handled_element_type(type_name: &str) -> bool {
    matches!(
        type_name,
        "BoolProperty"
            | "Int8Property"
            | "Int16Property"
            | "IntProperty"
            | "Int64Property"
            | "UInt16Property"
            | "UInt32Property"
            | "UInt64Property"
            | "FloatProperty"
            | "DoubleProperty"
            | "StrProperty"
            | "NameProperty"
            | "ByteProperty"
            | "EnumProperty"
    )
}
```

- [ ] **Step 4: Run all container tests**

```bash
cargo test -p paksmith-core --lib asset::property::containers::tests 2>&1 | tail -20
```

Expected: all tests pass (net same count — two tests replaced, not added).

- [ ] **Step 5: Lint and format gates**

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
```

Expected: all clean.

- [ ] **Step 6: Commit**

```bash
git add crates/paksmith-core/src/asset/property/containers.rs
git commit -m "$(cat <<'EOF'
feat(property): decode ByteProperty + EnumProperty as collection elements

ByteProperty element: raw u8 -> PropertyValue::Byte. EnumProperty element:
FName pair resolved from name table -> Enum { type_name: "", value }.
type_name is empty in element context (no per-element enum class name
available; ByteProperty<EnumName> in collection context is deferred).
is_handled_element_type grows from 12 to 14 types. Replaced the two
Phase 2c "returns_none" tests with correct-behavior tests.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: Extend `read_element_value` for TextProperty elements

**Files:**

- Modify: `crates/paksmith-core/src/asset/property/containers.rs`

`TextProperty` elements call `read_ftext(reader, ctx, asset_path, tag_size=0)`. The `tag_size=0` is correct for `FTextHistory::None` and `FTextHistory::Base` — both read fully self-delimiting FStrings. However for `FTextHistory::Unknown`, `read_ftext` skips `tag_size - bytes_already_read` bytes, which with `tag_size=0` skips 0 bytes. This leaves the cursor pointing at garbage for subsequent element reads. Detect the `Unknown` case and return `AssetParseFault::TextHistoryUnsupportedInElement` instead.

- [ ] **Step 1: Write failing tests**

Add to the `tests` module in `containers.rs`:

```rust
#[test]
fn element_text_none_history() {
    let ctx = make_ctx(&[]);
    // FText wire: flags(u32=0) + history_type(i8=-1) + bHasCultureInvariant(u8=0)
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(&0u32.to_le_bytes()); // flags
    bytes.push(0xFFu8);                            // history_type = -1 (i8::from_le_bytes([0xFF]))
    bytes.push(0u8);                               // bHasCultureInvariantString = false
    let mut r = Cursor::new(bytes);
    let v = read_element_value(
        "TextProperty",
        AssetWireField::ArrayElementBody,
        &mut r,
        &ctx,
        "x.uasset",
    )
    .unwrap()
    .unwrap();
    assert!(matches!(
        v,
        PropertyValue::Text(crate::asset::property::text::FText {
            history: crate::asset::property::text::FTextHistory::None {
                culture_invariant: None
            },
            ..
        })
    ));
}

#[test]
fn element_text_unknown_history_errors() {
    let ctx = make_ctx(&[]);
    // history_type=3 is unknown. read_ftext(tag_size=0) returns
    // FTextHistory::Unknown { skipped_bytes: 0 } — cursor uncorrupted but
    // caller cannot proceed safely. Must return TextHistoryUnsupportedInElement.
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(&0u32.to_le_bytes()); // flags
    bytes.push(3u8);                               // history_type = 3
    let mut r = Cursor::new(bytes);
    let err = read_element_value(
        "TextProperty",
        AssetWireField::ArrayElementBody,
        &mut r,
        &ctx,
        "x.uasset",
    )
    .unwrap_err();
    assert!(
        matches!(
            err,
            crate::error::PaksmithError::AssetParse {
                fault: crate::error::AssetParseFault::TextHistoryUnsupportedInElement {
                    history_type: 3
                },
                ..
            }
        ),
        "expected TextHistoryUnsupportedInElement, got {:?}",
        err
    );
}
```

- [ ] **Step 2: Run tests to confirm compile error**

```bash
cargo test -p paksmith-core --lib asset::property::containers::tests::element_text_none_history 2>&1 | tail -10
```

Expected: compile error — `"TextProperty"` arm not in `read_element_value`.

- [ ] **Step 3: Add imports and the `TextProperty` arm**

At the top of `containers.rs`, add to the existing `use` block:

```rust
use crate::asset::property::text::{FTextHistory, read_ftext};
```

In `read_element_value`, add before `_ => return Ok(None),`:

```rust
        "TextProperty" => {
            // tag_size=0: None/Base histories are self-delimiting so this is safe.
            // Unknown history would skip 0 bytes; detect it and error instead.
            let text = read_ftext(reader, ctx, asset_path, 0)?;
            if let FTextHistory::Unknown { history_type, .. } = text.history {
                return Err(PaksmithError::AssetParse {
                    asset_path: asset_path.to_string(),
                    fault: AssetParseFault::TextHistoryUnsupportedInElement { history_type },
                });
            }
            PropertyValue::Text(text)
        }
```

Update `is_handled_element_type` to include `"TextProperty"`. **Preserve the doc-comment above the function intact**; only modify the `matches!` body:

```rust
fn is_handled_element_type(type_name: &str) -> bool {
    matches!(
        type_name,
        "BoolProperty"
            | "Int8Property"
            | "Int16Property"
            | "IntProperty"
            | "Int64Property"
            | "UInt16Property"
            | "UInt32Property"
            | "UInt64Property"
            | "FloatProperty"
            | "DoubleProperty"
            | "StrProperty"
            | "NameProperty"
            | "ByteProperty"
            | "EnumProperty"
            | "TextProperty"
    )
}
```

- [ ] **Step 4: Run all container tests**

```bash
cargo test -p paksmith-core --lib asset::property::containers::tests 2>&1 | tail -20
```

Expected: all tests pass including the 2 new text tests.

- [ ] **Step 5: Lint and format gates**

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
```

Expected: all clean.

- [ ] **Step 6: Commit**

```bash
git add crates/paksmith-core/src/asset/property/containers.rs
git commit -m "$(cat <<'EOF'
feat(property): decode TextProperty as collection element + guard Unknown history

TextProperty elements call read_ftext(tag_size=0). None/Base histories are
self-delimiting and decode correctly. Unknown history with tag_size=0 would
skip 0 bytes and corrupt the cursor; detect and return
TextHistoryUnsupportedInElement instead. is_handled_element_type grows to 15.
Two unit tests: None history decodes, Unknown history errors.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 6: Extend `read_element_value` for SoftObject/Class/Object elements; finalize `is_handled_element_type`

**Files:**

- Modify: `crates/paksmith-core/src/asset/property/containers.rs`

`SoftObjectProperty` and `SoftClassProperty` elements delegate to `read_soft_path_payload` (defined in `primitives.rs` as `pub(super)`). `ObjectProperty` elements read a raw `i32`.

- [ ] **Step 1: Write failing tests**

The first slot of an `FSoftObjectPath` is an FName (resolved via the name table), not an FString — these tests build a name table that contains the asset path string and reference it by index, mirroring the direct-property tests in Task 3 Step 1.

Add to the `tests` module in `containers.rs`:

```rust
#[test]
fn element_soft_object_path() {
    let ctx = make_ctx(&["None", "/Game/Hero.Hero"]);
    let mut bytes: Vec<u8> = Vec::new();
    // FName asset_path: index=1, number=0
    bytes.extend_from_slice(&1i32.to_le_bytes());
    bytes.extend_from_slice(&0i32.to_le_bytes());
    // FString sub_path: empty (len=1 + b'\0')
    bytes.extend_from_slice(&1i32.to_le_bytes());
    bytes.push(0u8);
    let mut r = Cursor::new(bytes);
    let v = read_element_value(
        "SoftObjectProperty",
        AssetWireField::ArrayElementBody,
        &mut r,
        &ctx,
        "x.uasset",
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        v,
        PropertyValue::SoftObjectPath {
            asset_path: "/Game/Hero.Hero".to_string(),
            sub_path: String::new(),
        }
    );
}

#[test]
fn element_soft_class_path() {
    let ctx = make_ctx(&["None", "/Game/BP/Hero.Hero_C"]);
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(&1i32.to_le_bytes());
    bytes.extend_from_slice(&0i32.to_le_bytes());
    bytes.extend_from_slice(&1i32.to_le_bytes());
    bytes.push(0u8);
    let mut r = Cursor::new(bytes);
    let v = read_element_value(
        "SoftClassProperty",
        AssetWireField::ArrayElementBody,
        &mut r,
        &ctx,
        "x.uasset",
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        v,
        PropertyValue::SoftClassPath {
            asset_path: "/Game/BP/Hero.Hero_C".to_string(),
            sub_path: String::new(),
        }
    );
}

#[test]
fn element_object_property_import() {
    let ctx = make_ctx(&[]);
    let mut r = Cursor::new((-2i32).to_le_bytes().to_vec());
    let v = read_element_value(
        "ObjectProperty",
        AssetWireField::ArrayElementBody,
        &mut r,
        &ctx,
        "x.uasset",
    )
    .unwrap()
    .unwrap();
    // wire i32 -2 → Import(1)
    assert_eq!(v, PropertyValue::Object(PackageIndex::Import(1)));
}
```

- [ ] **Step 2: Run tests to confirm compile error**

```bash
cargo test -p paksmith-core --lib asset::property::containers::tests::element_soft_object_path 2>&1 | tail -10
```

Expected: compile error — `SoftObjectProperty` arm not found.

- [ ] **Step 3: Add `read_soft_path_payload` to the primitives import and add three new arms**

Update the existing `primitives` import in `containers.rs`. `Property` is NOT used by `containers.rs`; do not import it. There is no `extract_fstring_fault` helper — `read_asset_fstring` already wraps FString-malformed errors with `asset_path` context, so no shim is needed:

```rust
use crate::asset::property::primitives::{MapEntry, PropertyValue, read_soft_path_payload};
```

Also import `PackageIndex`:

```rust
use crate::asset::package_index::PackageIndex;
```

In `read_element_value`, add before `_ => return Ok(None),`. `read_soft_path_payload` takes `(reader, ctx, asset_path)` (matching Task 3 Step 3) and `body_field` is the second parameter of `read_element_value` already in scope:

```rust
        "SoftObjectProperty" => {
            let (asset_p, sub) = read_soft_path_payload(reader, ctx, asset_path)?;
            PropertyValue::SoftObjectPath {
                asset_path: asset_p,
                sub_path: sub,
            }
        }
        "SoftClassProperty" => {
            let (asset_p, sub) = read_soft_path_payload(reader, ctx, asset_path)?;
            PropertyValue::SoftClassPath {
                asset_path: asset_p,
                sub_path: sub,
            }
        }
        "ObjectProperty" => {
            let raw = reader
                .read_i32::<LittleEndian>()
                .map_err(|_| unexpected_eof(asset_path, body_field))?;
            PropertyValue::Object(PackageIndex::try_from_raw(raw).map_err(|_| {
                PaksmithError::AssetParse {
                    asset_path: asset_path.to_string(),
                    fault: AssetParseFault::PackageIndexUnderflow {
                        field: AssetWireField::ObjectPropertyIndex,
                    },
                }
            })?)
        }
```

Update `is_handled_element_type` to its final Phase 2d form. **Preserve the doc-comment above the function intact**; only modify the `matches!` body:

```rust
fn is_handled_element_type(type_name: &str) -> bool {
    matches!(
        type_name,
        "BoolProperty"
            | "Int8Property"
            | "Int16Property"
            | "IntProperty"
            | "Int64Property"
            | "UInt16Property"
            | "UInt32Property"
            | "UInt64Property"
            | "FloatProperty"
            | "DoubleProperty"
            | "StrProperty"
            | "NameProperty"
            | "ByteProperty"
            | "EnumProperty"
            | "TextProperty"
            | "SoftObjectProperty"
            | "SoftClassProperty"
            | "ObjectProperty"
    )
}
```

- [ ] **Step 4: Run all container tests**

```bash
cargo test -p paksmith-core --lib asset::property::containers::tests 2>&1 | tail -20
```

Expected: all tests pass including the 3 new tests (total container unit tests now ≥ 40).

- [ ] **Step 5: Run workspace tests**

```bash
cargo test --workspace 2>&1 | tail -20
```

Expected: all tests pass.

- [ ] **Step 6: Lint and format gates**

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
```

Expected: all clean.

- [ ] **Step 7: Commit**

```bash
git add crates/paksmith-core/src/asset/property/containers.rs
git commit -m "$(cat <<'EOF'
feat(property): decode Soft*/ObjectProperty as collection elements + finalize is_handled_element_type

SoftObjectProperty and SoftClassProperty elements delegate to
read_soft_path_payload from primitives.rs (pub(super) shared helper —
the UE5 >= 1007 guard fires here too). ObjectProperty element reads a
raw i32 decoded into PackageIndex. is_handled_element_type grows to 18
types, covering every Phase 2d element type. Three unit tests.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 7: Integration tests and fixture builder

**Files:**

- Modify: `crates/paksmith-core/src/testing/uasset.rs` — add `build_minimal_ue4_27_with_extended_types`
- Create: `crates/paksmith-core/tests/extended_types_integration.rs`

- [ ] **Step 1: Add `build_minimal_ue4_27_with_extended_types` to `testing/uasset.rs`**

Mirror the existing `build_minimal_ue4_27_with_containers` pattern at `testing/uasset.rs:688` exactly. The module is already feature-gated upstream (no per-function `#[cfg(feature = "__test_utils")]` needed), `write_fname_pair` is already defined at line 529, and `build_minimal(MinimalPackageSpec { ... })` is the assembly point. **CRITICAL — name table convention:** indices 0..=2 are reserved for `/Script/CoreUObject`, `Package`, `Default__Object` (the cooked-Package import chain). Fixture-specific names start at index 3.

Add to `crates/paksmith-core/src/testing/uasset.rs`:

```rust
/// Builds a synthetic UAsset (UE 4.27, fileVersionUE4=522) whose single
/// export body contains six properties covering Phase 2d extended types,
/// followed by a None terminator.
///
/// Export property layout:
/// - `SoftRef: SoftObjectProperty` = ("/Game/Data/Hero.Hero", "")
/// - `SoftClass: SoftClassProperty` = ("/Game/BP/HeroClass.HeroClass_C", "")
/// - `ObjRef: ObjectProperty` = -1 (decodes to PackageIndex::Import(0))
/// - `Tags: ArrayProperty<ByteProperty>` = [10, 20]
/// - `Flags: ArrayProperty<EnumProperty>` = ["EColor__Red"]
/// - `Desc: ArrayProperty<TextProperty>` = [FText::None]
///
/// Name table (indices 0..=2 reserved for the cooked-Package import):
///   0=/Script/CoreUObject, 1=Package, 2=Default__Object,
///   3=SoftRef, 4=SoftObjectProperty, 5=/Game/Data/Hero.Hero,
///   6=SoftClass, 7=SoftClassProperty, 8=/Game/BP/HeroClass.HeroClass_C,
///   9=ObjRef, 10=ObjectProperty, 11=Tags, 12=ArrayProperty,
///   13=ByteProperty, 14=Flags, 15=EnumProperty, 16=EColor__Red,
///   17=Desc, 18=TextProperty, 19=Hero
#[must_use]
#[allow(
    clippy::too_many_lines,
    reason = "hand-written wire-format construction for six property shapes + 20-entry name table + import/export records; splitting per-property would obscure the layout"
)]
pub fn build_minimal_ue4_27_with_extended_types() -> MinimalPackage {
    let mut body: Vec<u8> = Vec::new();

    // --- Property 1: SoftRef: SoftObjectProperty
    // payload = FName(asset_path) [8 bytes] + FString("") [4+1=5 bytes] = 13 bytes
    {
        write_fname_pair(&mut body, 3, 0); // Name: SoftRef
        write_fname_pair(&mut body, 4, 0); // Type: SoftObjectProperty
        body.extend_from_slice(&13i32.to_le_bytes()); // Size
        body.extend_from_slice(&0i32.to_le_bytes()); // ArrayIndex
        body.push(0u8); // HasPropertyGuid
        // FName asset_path = "/Game/Data/Hero.Hero" (idx 5)
        write_fname_pair(&mut body, 5, 0);
        // FString sub_path = ""
        body.extend_from_slice(&1i32.to_le_bytes());
        body.push(0u8);
    }

    // --- Property 2: SoftClass: SoftClassProperty (same shape, idx 8)
    {
        write_fname_pair(&mut body, 6, 0); // Name: SoftClass
        write_fname_pair(&mut body, 7, 0); // Type: SoftClassProperty
        body.extend_from_slice(&13i32.to_le_bytes());
        body.extend_from_slice(&0i32.to_le_bytes());
        body.push(0u8);
        write_fname_pair(&mut body, 8, 0); // FName asset_path
        body.extend_from_slice(&1i32.to_le_bytes());
        body.push(0u8);
    }

    // --- Property 3: ObjRef: ObjectProperty = -1
    {
        write_fname_pair(&mut body, 9, 0); // Name: ObjRef
        write_fname_pair(&mut body, 10, 0); // Type: ObjectProperty
        body.extend_from_slice(&4i32.to_le_bytes()); // Size: 4
        body.extend_from_slice(&0i32.to_le_bytes()); // ArrayIndex
        body.push(0u8); // HasPropertyGuid
        body.extend_from_slice(&(-1i32).to_le_bytes()); // raw -1 → Import(0)
    }

    // --- Property 4: Tags: ArrayProperty<ByteProperty> = [10, 20]
    // payload = i32 count + 2*u8 = 6 bytes
    {
        write_fname_pair(&mut body, 11, 0); // Name: Tags
        write_fname_pair(&mut body, 12, 0); // Type: ArrayProperty
        body.extend_from_slice(&6i32.to_le_bytes());
        body.extend_from_slice(&0i32.to_le_bytes());
        write_fname_pair(&mut body, 13, 0); // InnerType: ByteProperty
        body.push(0u8); // HasPropertyGuid
        body.extend_from_slice(&2i32.to_le_bytes()); // count
        body.push(10u8);
        body.push(20u8);
    }

    // --- Property 5: Flags: ArrayProperty<EnumProperty> = ["EColor__Red"]
    // payload = i32 count + FName(8 bytes) = 12 bytes
    {
        write_fname_pair(&mut body, 14, 0); // Name: Flags
        write_fname_pair(&mut body, 12, 0); // Type: ArrayProperty
        body.extend_from_slice(&12i32.to_le_bytes());
        body.extend_from_slice(&0i32.to_le_bytes());
        write_fname_pair(&mut body, 15, 0); // InnerType: EnumProperty
        body.push(0u8); // HasPropertyGuid
        body.extend_from_slice(&1i32.to_le_bytes()); // count
        write_fname_pair(&mut body, 16, 0); // EColor__Red
    }

    // --- Property 6: Desc: ArrayProperty<TextProperty> = [FText::None]
    // FText element = u32 flags + i8 history_type + u8 has_culture = 6 bytes
    // payload = i32 count + 6 = 10 bytes
    {
        write_fname_pair(&mut body, 17, 0); // Name: Desc
        write_fname_pair(&mut body, 12, 0); // Type: ArrayProperty
        body.extend_from_slice(&10i32.to_le_bytes());
        body.extend_from_slice(&0i32.to_le_bytes());
        write_fname_pair(&mut body, 18, 0); // InnerType: TextProperty
        body.push(0u8); // HasPropertyGuid
        body.extend_from_slice(&1i32.to_le_bytes()); // count
        body.extend_from_slice(&0u32.to_le_bytes()); // flags
        body.push(0xFFu8); // history_type = -1 (None)
        body.push(0u8); // bHasCultureInvariantString = false
    }

    // None terminator
    write_none_terminator(&mut body);

    let names = NameTable {
        names: vec![
            FName::new("/Script/CoreUObject"),
            FName::new("Package"),
            FName::new("Default__Object"),
            FName::new("SoftRef"),
            FName::new("SoftObjectProperty"),
            FName::new("/Game/Data/Hero.Hero"),
            FName::new("SoftClass"),
            FName::new("SoftClassProperty"),
            FName::new("/Game/BP/HeroClass.HeroClass_C"),
            FName::new("ObjRef"),
            FName::new("ObjectProperty"),
            FName::new("Tags"),
            FName::new("ArrayProperty"),
            FName::new("ByteProperty"),
            FName::new("Flags"),
            FName::new("EnumProperty"),
            FName::new("EColor__Red"),
            FName::new("Desc"),
            FName::new("TextProperty"),
            FName::new("Hero"),
        ],
    };

    let imports = ImportTable {
        imports: vec![ObjectImport {
            class_package_name: 0,
            class_package_number: 0,
            class_name: 1,
            class_name_number: 0,
            outer_index: PackageIndex::Null,
            object_name: 2,
            object_name_number: 0,
            import_optional: None,
        }],
    };

    let serial_size = i64::try_from(body.len()).expect("body fits in i64");
    let exports = ExportTable {
        exports: vec![ObjectExport {
            class_index: PackageIndex::Import(0),
            super_index: PackageIndex::Null,
            template_index: PackageIndex::Null,
            outer_index: PackageIndex::Null,
            object_name: 19, // "Hero"
            object_name_number: 0,
            object_flags: 0,
            serial_size,
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
        }],
    };

    build_minimal(MinimalPackageSpec {
        names,
        imports,
        exports,
        payloads: vec![body],
        ..MinimalPackageSpec::default()
    })
}
```

- [ ] **Step 2: Create integration tests**

The canonical pattern (from `tests/container_integration.rs:16-25`) parses bytes, asserts `parsed.payloads[0]` is a `PropertyBag::Tree`, and works against the `properties` Vec. There is no `exports[0].properties_tree()` accessor — the property tree lives in `parsed.payloads`, parallel to `parsed.exports`.

Create `crates/paksmith-core/tests/extended_types_integration.rs`:

```rust
//! Integration tests for Phase 2d extended property types.

#![allow(missing_docs)]

#[cfg(feature = "__test_utils")]
mod tests {
    use paksmith_core::asset::Package;
    use paksmith_core::asset::package_index::PackageIndex;
    use paksmith_core::asset::property::primitives::Property;
    use paksmith_core::asset::property::text::{FText, FTextHistory};
    use paksmith_core::asset::property::{PropertyBag, PropertyValue};
    use paksmith_core::testing::uasset::build_minimal_ue4_27_with_extended_types;

    fn decode_properties() -> Vec<Property> {
        let pkg = build_minimal_ue4_27_with_extended_types();
        let parsed = Package::read_from(&pkg.bytes, "Game/Data/Test.uasset")
            .expect("Package::read_from failed");
        assert_eq!(parsed.payloads.len(), 1, "expected one export");
        match parsed.payloads.into_iter().next().unwrap() {
            PropertyBag::Tree { properties } => properties,
            other => {
                panic!("expected PropertyBag::Tree on extended-types fixture; got {other:?}")
            }
        }
    }

    #[test]
    fn parse_soft_object_property() {
        let props = decode_properties();
        let prop = props.iter().find(|p| p.name == "SoftRef").unwrap();
        assert_eq!(
            prop.value,
            PropertyValue::SoftObjectPath {
                asset_path: "/Game/Data/Hero.Hero".to_string(),
                sub_path: String::new(),
            }
        );
    }

    #[test]
    fn parse_soft_class_property() {
        let props = decode_properties();
        let prop = props.iter().find(|p| p.name == "SoftClass").unwrap();
        assert_eq!(
            prop.value,
            PropertyValue::SoftClassPath {
                asset_path: "/Game/BP/HeroClass.HeroClass_C".to_string(),
                sub_path: String::new(),
            }
        );
    }

    #[test]
    fn parse_object_property() {
        let props = decode_properties();
        let prop = props.iter().find(|p| p.name == "ObjRef").unwrap();
        assert_eq!(prop.value, PropertyValue::Object(PackageIndex::Import(0)));
    }

    #[test]
    fn parse_array_of_byte_properties() {
        let props = decode_properties();
        let prop = props.iter().find(|p| p.name == "Tags").unwrap();
        assert_eq!(
            prop.value,
            PropertyValue::Array {
                inner_type: "ByteProperty".to_string(),
                elements: vec![PropertyValue::Byte(10), PropertyValue::Byte(20)],
            }
        );
    }

    #[test]
    fn parse_array_of_enum_properties() {
        let props = decode_properties();
        let prop = props.iter().find(|p| p.name == "Flags").unwrap();
        assert_eq!(
            prop.value,
            PropertyValue::Array {
                inner_type: "EnumProperty".to_string(),
                elements: vec![PropertyValue::Enum {
                    type_name: String::new(),
                    value: "EColor__Red".to_string(),
                }],
            }
        );
    }

    #[test]
    fn parse_array_of_text_properties() {
        let props = decode_properties();
        let prop = props.iter().find(|p| p.name == "Desc").unwrap();
        assert_eq!(
            prop.value,
            PropertyValue::Array {
                inner_type: "TextProperty".to_string(),
                elements: vec![PropertyValue::Text(FText {
                    flags: 0,
                    history: FTextHistory::None {
                        culture_invariant: None,
                    },
                })],
            }
        );
    }
}
```

- [ ] **Step 3: Run integration tests**

```bash
cargo test -p paksmith-core --test extended_types_integration --features __test_utils 2>&1 | tail -20
```

Expected: all 6 integration tests pass.

- [ ] **Step 4: Run full workspace tests**

```bash
cargo test --workspace --all-features 2>&1 | tail -20
```

Expected: all tests pass (matches CI).

- [ ] **Step 5: Lint and format gates**

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
```

Expected: all clean.

- [ ] **Step 6: Commit**

```bash
git add crates/paksmith-core/src/testing/uasset.rs \
        crates/paksmith-core/tests/extended_types_integration.rs
git commit -m "$(cat <<'EOF'
test(property): add integration tests + fixture for extended property types

build_minimal_ue4_27_with_extended_types emits six properties: direct
SoftObjectProperty, SoftClassProperty, ObjectProperty, plus Array of
ByteProperty, Array of EnumProperty, Array of TextProperty (None history).
Six integration tests verify each decoded value exactly via the existing
parsed.payloads -> PropertyBag::Tree pattern.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 8: Fixture-gen cross-validation

**Files:**

- Modify: `crates/paksmith-fixture-gen/src/uasset.rs` — add `write_minimal_ue4_27_with_extended_types`

This task assumes the Phase 2c container fixture-gen wiring from `feat/phase-2c-task9-fixture-gen-and-snapshot` (PR #301) has landed. If not, mirror the `write_minimal_ue4_27_with_properties` pattern at `paksmith-fixture-gen/src/uasset.rs:636` directly — write the bytes to a path, self-test by re-parsing via `paksmith_core::asset::Package::read_from`, then call `cross_validate_with_unreal_asset(&bytes, EngineVersion::VER_UE4_27)`.

The existing CLI `paksmith inspect` insta snapshot uses `real_v8b_uasset.pak`, which wraps `build_minimal_ue4_27()` — an asset with no properties. Phase 2d adds property variants but does not affect that snapshot; no snapshot update is needed here.

Property-level cross-validation against the oracle is impractical for the same reason `write_minimal_ue4_27_with_properties` documents: `unreal_asset`'s `NormalExport` classifier carries schema/ancestry assumptions that fail on a minimal synthetic fixture, so the oracle silently downgrades to `RawExport`. Header-level parity (names + imports + exports baseline fields) is what `cross_validate_with_unreal_asset` covers; property-decode correctness is pinned by paksmith's own integration tests added in Task 7.

- [ ] **Step 1: Add `write_minimal_ue4_27_with_extended_types`**

Mirror `write_minimal_ue4_27_with_properties` at `paksmith-fixture-gen/src/uasset.rs:636`:

```rust
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

    // Self-test: paksmith re-parses and decodes the property tree.
    let parsed = paksmith_core::asset::Package::read_from(&bytes, path.to_string_lossy().as_ref())
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

    // Spot-check one variant per Phase 2d category.
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

    // Header-level cross-validation (names + imports + exports baseline).
    // Property-list cross-validation is skipped per the doc comment above.
    cross_validate_with_unreal_asset(
        &bytes,
        unreal_asset::engine_version::EngineVersion::VER_UE4_27,
    )?;

    Ok(())
}
```

Wire this into the fixture-gen `main.rs` invocation list alongside `write_minimal_ue4_27_with_properties` so `cargo run -p paksmith-fixture-gen` emits the new fixture at every regeneration.

- [ ] **Step 2: Run fixture-gen to confirm cross-validation passes**

```bash
cargo run -p paksmith-fixture-gen 2>&1 | tail -20
```

Expected: runs without errors. If the oracle rejects the fixture (`Asset::new` returns Err inside `cross_validate_with_unreal_asset`), the byte layout in `build_minimal_ue4_27_with_extended_types` is wrong — compare against the Phase 2c `build_minimal_ue4_27_with_containers` self-test path to isolate the discrepancy.

- [ ] **Step 3: Run workspace tests**

```bash
cargo test --workspace --all-features 2>&1 | tail -20
```

Expected: all tests pass.

- [ ] **Step 4: Lint and format gates**

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
```

Expected: all clean.

- [ ] **Step 5: Commit**

```bash
git add crates/paksmith-fixture-gen/src/uasset.rs \
        crates/paksmith-fixture-gen/src/main.rs
git commit -m "$(cat <<'EOF'
test(fixture-gen): cross-validate extended-types fixture against unreal_asset

write_minimal_ue4_27_with_extended_types emits the Phase 2d fixture to
disk, re-parses it through paksmith to assert the six expected properties
decode without falling back to PropertyBag::Opaque, then runs the header-
level cross_validate_with_unreal_asset gate. Property-list oracle parity
is impractical at this fixture's minimal-synthetic shape (the oracle
downgrades to RawExport) — the integration tests added in Task 7 cover
that surface.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Self-review

### Spec coverage

| Requirement                                     | Task   |
| ----------------------------------------------- | ------ |
| `SoftObjectProperty` as direct type             | Task 3 |
| `SoftClassProperty` as direct type              | Task 3 |
| `ObjectProperty` as direct type                 | Task 3 |
| `ByteProperty` collection element               | Task 4 |
| `EnumProperty` collection element               | Task 4 |
| `TextProperty` collection element               | Task 5 |
| `TextProperty` Unknown-history guard            | Task 5 |
| `SoftObjectProperty` collection element         | Task 6 |
| `SoftClassProperty` collection element          | Task 6 |
| `ObjectProperty` collection element             | Task 6 |
| `is_handled_element_type` finalized to 18 types | Task 6 |
| New error `TextHistoryUnsupportedInElement`     | Task 1 |
| New error `UnsupportedSoftObjectPathLayout`     | Task 1 |
| 3 new `AssetWireField` variants                 | Task 1 |
| 3 new `PropertyValue` variants                  | Task 2 |
| `read_soft_path_payload` shared helper          | Task 3 |
| UE5 ≥ 1007 wire-layout guard                    | Task 3 |
| Integration fixture + 6 tests                   | Task 7 |
| Fixture-gen oracle cross-validation             | Task 8 |

All spec requirements have a covering task.

### Placeholder scan

No TBD, TODO, or "similar to Task N" shortcuts in any step. Every code block compiles against the post-Phase-2c codebase. Helpers referenced:

- `build_minimal(MinimalPackageSpec { ... })` — the Phase 2a assembly point at `testing/uasset.rs:?` (used by every existing fixture builder; the `_with_containers` builder at line 688 is the closest analog to the new Phase 2d builder).
- `write_fname_pair` and `write_none_terminator` — Phase 2b helpers already in `testing/uasset.rs`.
- `read_fname_pair` and `unexpected_eof` — Phase 2b/2c helpers in `asset/property/mod.rs`.
- `read_asset_fstring` — Phase 2a helper at `asset/fstring.rs:33` that re-categorizes pak-side FString errors with asset context.
- `PackageIndex::try_from_raw` — Phase 2a helper at `asset/package_index.rs:51`.
- `cross_validate_with_unreal_asset` — Phase 2b fixture-gen helper at `paksmith-fixture-gen/src/uasset.rs`.

### Type consistency

- `read_soft_path_payload` declared `pub(super) fn read_soft_path_payload<R: Read>(reader: &mut R, ctx: &AssetContext, asset_path: &str) -> crate::Result<(String, String)>` in Task 3 Step 3; imported into `containers.rs` in Task 6 Step 3. Both call sites pass `(reader, ctx, asset_path)` consistently.
- `read_element_value` signature is `(type_name: &str, body_field: AssetWireField, reader: &mut R, ctx: &AssetContext, asset_path: &str) -> crate::Result<Option<PropertyValue>>` (established by Phase 2c). Every test call in Tasks 4/5/6 passes `body_field` as the second argument (using `AssetWireField::ArrayElementBody` for array context). Every new production arm uses `body_field` for EOF mapping rather than reaching for an arbitrary field.
- `PropertyValue::Object(PackageIndex)` is a tuple variant; serde renders it as `{"Object":"Null"}` / `{"Object":"Import(N)"}` / `{"Object":"Export(N)"}` via `PackageIndex`'s `serialize → collect_str`. Every test assertion and the deliverable JSON example use that shape.
- `FTextHistory::Unknown { history_type, .. }` destructures the `history_type: i8` field (with `..` to ignore `skipped_bytes`); `AssetParseFault::TextHistoryUnsupportedInElement { history_type: i8 }` defined in Task 1 matches the type.
- `PropertyValue::Enum { type_name: String::new(), value }` in Task 4 Step 3 matches the variant defined in Phase 2b (`Enum { type_name: String, value: String }`).
- All three new `AssetWireField` variants (`SoftObjectAssetPath`, `ObjectPropertyIndex`, `EnumElementFName`) are added in Task 1 Step 4, get Display arms in Step 5, and are appended to the pin table in Step 5b. Every Task 3/6 reference to these variants matches.

### Lint and rustdoc gates

Every task ends with three commands:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
```

`cargo fmt --check` is a separate CI gate from clippy (`feedback_run_fmt_and_clippy.md`). `RUSTDOCFLAGS="-D warnings"` enforces `rustdoc::private_intra_doc_links`, which is a CI gate not covered by `cargo clippy` (Phase 2c Task 7 ate a regression here). `--all-targets --all-features` matches CI's clippy invocation; the default `cargo clippy` misses `__test_utils`-gated code (`feedback_ci_checks_beyond_pre_commit.md`). The `.githooks/pre-commit` hook enforces fmt + clippy when wired up via `git config core.hooksPath .githooks` (one-time per clone).

### PR workflow recap

- Branch: `feat/<kebab-case>` (or matching conventional-commit prefix).
- PR title: lowercase verb-first, no `Phase 2d:` prefix.
- PR body: write to a tempfile via `gh pr create --body-file <tmp>` (never inline `--body "$(cat <<EOF ...)"`).
- Run the standard 3-reviewer panel (code-quality + simplifier + security) in parallel before merging; loop until every reviewer says APPROVED.
