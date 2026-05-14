# Paksmith Phase 2d: Extended Property Types

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Decode `SoftObjectProperty`, `SoftClassProperty`, and `ObjectProperty` as direct tagged properties, and extend collection element decoding to handle `ByteProperty`, `EnumProperty`, `TextProperty`, `SoftObjectProperty`, `SoftClassProperty`, and `ObjectProperty` inner types — replacing the `Unknown { skipped_bytes }` fallback for these six types inside `ArrayProperty`, `MapProperty`, and `SetProperty`.

**Architecture:** Three new `PropertyValue` variants (`SoftObjectPath`, `SoftClassPath`, `Object`) land in `primitives.rs`. A new `pub(super) fn read_soft_path_payload` helper there is shared by both the direct reader (`read_primitive_value`) and the element reader (`read_element_value`) in `containers.rs`. One new `AssetParseFault` variant (`TextHistoryUnsupportedInElement`) prevents silent cursor corruption when `read_ftext` encounters an unknown history type with no per-element size available. `is_handled_element_type` grows from 12 to 18 types.

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
          "value": { "Object": { "index": -1 } }
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
- `ObjectProperty` as a direct property: raw `i32` package index → `PropertyValue::Object { index }` (negative = import, positive = export, 0 = null; resolution deferred)
- `ByteProperty` elements inside collections: raw `u8` → `PropertyValue::Byte`
- `EnumProperty` elements inside collections: FName pair → `PropertyValue::Enum { type_name: "".to_string(), value }`
- `TextProperty` elements inside collections: `read_ftext(tag_size=0)` with Unknown-history guard
- `SoftObjectProperty` and `SoftClassProperty` elements inside collections: delegate to `read_soft_path_payload`
- `ObjectProperty` elements inside collections: raw `i32`
- `TextHistoryUnsupportedInElement { history_type: i8 }` fault to prevent cursor corruption on unknown FText history types in element context
- Four new `AssetWireField` variants: `SoftObjectAssetPath`, `SoftObjectSubPath`, `ObjectPropertyIndex`, `EnumElementFName`
- Integration test fixture `build_minimal_ue4_27_with_extended_types` + 6 integration tests
- Fixture-gen cross-validation against `unreal_asset` oracle + CLI snapshot update

**Deferred to Phase 2e+:**

- `StructProperty` as a collection element (wire format requires empirical verification of length-prefix behavior per `feedback_verify_wire_format_claims.md`)
- `ObjectProperty` resolution: mapping the raw `index` to an import/export name requires the full object table
- UInt8/Int8 as enum base types in collection context
- Map key/value types covered by Phase 2d (Soft\*, Object) — already decoded; no extra work needed

---

## File structure

| File                                                       | Action | Responsibility                                                                                                           |
| ---------------------------------------------------------- | ------ | ------------------------------------------------------------------------------------------------------------------------ |
| `crates/paksmith-core/src/error.rs`                        | Modify | Add `TextHistoryUnsupportedInElement` fault + 4 `AssetWireField` variants + Display arms                                 |
| `crates/paksmith-core/src/asset/property/primitives.rs`    | Modify | Add `SoftObjectPath`, `SoftClassPath`, `Object` variants; `read_soft_path_payload` helper; extend `read_primitive_value` |
| `crates/paksmith-core/src/asset/property/containers.rs`    | Modify | Extend `is_handled_element_type` and `read_element_value`; add TextProperty element guard                                |
| `crates/paksmith-core/src/testing/uasset.rs`               | Modify | Add `build_minimal_ue4_27_with_extended_types`                                                                           |
| `crates/paksmith-core/tests/extended_types_integration.rs` | Create | 6 integration tests                                                                                                      |
| `crates/paksmith-fixture-gen/src/uasset.rs`                | Modify | Add Phase 2d oracle cross-validation block                                                                               |
| `crates/paksmith-cli/src/commands/inspect.rs`              | Modify | Update insta snapshot for new property types                                                                             |

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
fn asset_wire_field_display_soft_object_asset_path() {
    assert_eq!(AssetWireField::SoftObjectAssetPath.to_string(), "soft_object_asset_path");
}

#[test]
fn asset_wire_field_display_soft_object_sub_path() {
    assert_eq!(AssetWireField::SoftObjectSubPath.to_string(), "soft_object_sub_path");
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

- [ ] **Step 3: Add `TextHistoryUnsupportedInElement` to `AssetParseFault`**

Find `pub enum AssetParseFault` and add after the last existing variant:

```rust
/// A `TextProperty` element inside an Array/Map/Set used an FText
/// history type that cannot be decoded without per-element size info.
///
/// In element context `tag_size` is 0; for `FTextHistory::Unknown` this
/// would skip 0 bytes and silently corrupt the reader cursor. Returning
/// this error prevents that.
#[error("text history type {history_type} is not supported in collection elements")]
TextHistoryUnsupportedInElement { history_type: i8 },
```

- [ ] **Step 4: Add 4 new `AssetWireField` variants**

Find `pub enum AssetWireField` and add after the last Phase 2c variant (`SetNumToRemove`):

```rust
/// First `FString` of a `SoftObjectProperty` or `SoftClassProperty` payload.
/// Reserved: FString errors currently surface via `FStringMalformed`; this field
/// will carry context when `FStringMalformed` gains a `field` discriminant.
SoftObjectAssetPath,
/// Second `FString` (sub-path) of a `SoftObjectProperty` or `SoftClassProperty` payload.
/// Reserved: see `SoftObjectAssetPath`.
SoftObjectSubPath,
/// The `i32` package index in an `ObjectProperty` payload.
ObjectPropertyIndex,
/// The `(index, number)` FName pair stored in an `EnumProperty` collection element.
EnumElementFName,
```

- [ ] **Step 5: Add Display arms for the new `AssetWireField` variants**

Find `impl fmt::Display for AssetWireField` and add after the last Phase 2c arm:

```rust
            Self::SoftObjectAssetPath => "soft_object_asset_path",
            Self::SoftObjectSubPath => "soft_object_sub_path",
            Self::ObjectPropertyIndex => "object_property_index",
            Self::EnumElementFName => "enum_element_fname",
```

- [ ] **Step 6: Run the Display-stability tests**

```bash
cargo test -p paksmith-core --lib error::tests 2>&1 | tail -20
```

Expected: all tests pass, including the 5 new pin tests.

- [ ] **Step 7: Run workspace clippy**

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Expected: clean.

- [ ] **Step 8: Commit**

```bash
git add crates/paksmith-core/src/error.rs
git commit -m "$(cat <<'EOF'
feat(error): Phase 2d AssetParseFault + AssetWireField variants

TextHistoryUnsupportedInElement prevents silent cursor corruption when
an unknown FText history type appears inside a collection element
(tag_size=0 means Unknown would skip 0 bytes). Four new AssetWireField
variants for SoftObject/ObjectProperty fields and EnumProperty element
FName. Display strings wire-stable, pinned by five new unit tests.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: New `PropertyValue` variants (SoftObjectPath, SoftClassPath, Object)

**Files:**

- Modify: `crates/paksmith-core/src/asset/property/primitives.rs`

- [ ] **Step 1: Write failing serialization tests**

Add to the `tests` module in `primitives.rs`:

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
    let v = PropertyValue::Object { index: -3 };
    let json = serde_json::to_string(&v).unwrap();
    assert_eq!(json, r#"{"Object":{"index":-3}}"#);
}

#[test]
fn property_value_object_null_serializes() {
    let v = PropertyValue::Object { index: 0 };
    let json = serde_json::to_string(&v).unwrap();
    assert_eq!(json, r#"{"Object":{"index":0}}"#);
}
```

- [ ] **Step 2: Run tests to confirm compile error**

```bash
cargo test -p paksmith-core --lib asset::property::primitives::tests::property_value_soft_object_path_serializes 2>&1 | tail -10
```

Expected: compile error — `PropertyValue::SoftObjectPath` not found.

- [ ] **Step 3: Add the three new variants to `PropertyValue`**

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

    /// `ObjectProperty` — a hard object reference as a raw package index.
    ///
    /// Negative = import table entry, positive = export table entry, 0 = null.
    /// Resolution to a named object is deferred to Phase 2e+ when the full
    /// object table is available.
    Object {
        index: i32,
    },
```

- [ ] **Step 4: Run serialization tests**

```bash
cargo test -p paksmith-core --lib asset::property::primitives::tests 2>&1 | tail -20
```

Expected: all primitive tests pass, including the 4 new serialization tests.

- [ ] **Step 5: Run workspace clippy**

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add crates/paksmith-core/src/asset/property/primitives.rs
git commit -m "$(cat <<'EOF'
feat(property): SoftObjectPath, SoftClassPath, Object PropertyValue variants

Three new PropertyValue variants for Phase 2d. SoftObjectPath and
SoftClassPath each carry asset_path + sub_path strings decoded from two
wire FStrings. Object carries a raw i32 package index (negative=import,
positive=export, 0=null). Serialization shapes pinned by four unit tests.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: `read_soft_path_payload` helper + extend `read_primitive_value`

**Files:**

- Modify: `crates/paksmith-core/src/asset/property/primitives.rs`

- [ ] **Step 1: Write failing tests for the three new direct property reads**

Add to the `tests` module in `primitives.rs`:

```rust
#[test]
fn soft_object_property_value() {
    let tag = make_tag("SoftObjectProperty", 12);
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
    let tag = make_tag("SoftClassProperty", 12);
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
    assert_eq!(val, PropertyValue::Object { index: 0 });
}

#[test]
fn object_property_import_index() {
    let tag = make_tag("ObjectProperty", 4);
    let ctx = make_ctx(&["None"]);
    let val =
        read_primitive_value(&tag, &mut Cursor::new(&(-3i32).to_le_bytes()), &ctx, "x")
            .unwrap()
            .unwrap();
    assert_eq!(val, PropertyValue::Object { index: -3 });
}

#[test]
fn object_property_export_index() {
    let tag = make_tag("ObjectProperty", 4);
    let ctx = make_ctx(&["None"]);
    let val = read_primitive_value(&tag, &mut Cursor::new(&2i32.to_le_bytes()), &ctx, "x")
        .unwrap()
        .unwrap();
    assert_eq!(val, PropertyValue::Object { index: 2 });
}
```

- [ ] **Step 2: Run tests to confirm compile error**

```bash
cargo test -p paksmith-core --lib asset::property::primitives::tests::soft_object_property_value 2>&1 | tail -10
```

Expected: compile error — `read_soft_path_payload` and new match arms not found.

- [ ] **Step 3: Add `read_soft_path_payload` before `read_primitive_value`**

Wire format verified against CUE4Parse's `FSoftObjectPath` constructor
(`CUE4Parse/UE4/Objects/UObject/FSoftObjectPath.cs`):

```text
[for UE4 >= ADDED_SOFT_OBJECT_PATH (514), which is always at our floor:]
FName  asset_path_name       (i32 name_index + i32 number = 8 bytes)
FStr   sub_path_string

[for UE5 >= FSOFTOBJECTPATH_REMOVE_ASSET_PATH_FNAMES (1007):]
FTopLevelAssetPath asset_path_name   (2 × FName = 16 bytes — package name + asset name)
FStr   sub_path_string

[for UE5 >= ADD_SOFTOBJECTPATH_LIST (1008) with PKG_FilterEditorOnly set:]
i32    index_into_summary.soft_object_paths   (no FName + FString — the path lives in the summary's list)
```

`read_soft_path_payload` resolves the FName via `resolve_fname` (Phase 2b)
and returns `(asset_path_string, sub_path_string)`. Phase 2d does NOT
implement the UE5 ≥ 1007 `FTopLevelAssetPath` variant nor the UE5 ≥
1008 indexed variant — both are deferred and documented below. Phase 2d
accepts UE5 ∈ [1000, 1006] for SoftObjectProperty parsing.

```rust
/// Reads the SoftObjectProperty / SoftClassProperty payload.
///
/// Wire format at Phase 2d's accepted range (UE4 ≥ 514, UE5 ≤ 1006):
/// `FName asset_path_name` (resolved to String via the name table) +
/// `FString sub_path_string`.
///
/// Returns `(asset_path_string, sub_path_string)`.
///
/// `pub(super)` so `containers.rs` can reuse this for element reads.
pub(super) fn read_soft_path_payload<R: Read>(
    reader: &mut R,
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<(String, String)> {
    use crate::asset::property::tag::resolve_fname;
    use crate::error::AssetWireField;
    // Asset path is an FName (NOT an FString — corrected from an earlier
    // draft of this plan). UE's FSoftObjectPath stores AssetPathName as
    // FName and SubPathString as FString.
    let idx = reader
        .read_i32::<LittleEndian>()
        .map_err(|_| PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::UnexpectedEof {
                field: AssetWireField::SoftObjectAssetPath,
            },
        })?;
    let num = reader
        .read_i32::<LittleEndian>()
        .map_err(|_| PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::UnexpectedEof {
                field: AssetWireField::SoftObjectAssetPath,
            },
        })?;
    let obj_path = resolve_fname(
        idx,
        num,
        ctx,
        asset_path,
        AssetWireField::SoftObjectAssetPath,
    )?;
    let sub = read_fstring(reader).map_err(|e| PaksmithError::AssetParse {
        asset_path: asset_path.to_string(),
        fault: AssetParseFault::FStringMalformed {
            kind: extract_fstring_fault(&e),
        },
    })?;
    Ok((obj_path, sub))
}
```

> **Deferred:** UE5 ≥ 1007 (FSOFTOBJECTPATH_REMOVE_ASSET_PATH_FNAMES)
> changes asset_path_name to `FTopLevelAssetPath` (`FName package + FName asset`).
> UE5 ≥ 1008 (ADD_SOFTOBJECTPATH_LIST) with `PKG_FilterEditorOnly` set
> changes the entire payload to a single i32 index into the summary's
> SoftObjectPaths array. Both variants require summary-side support that
> Phase 2a's accepted range already excludes (UE5 1007+ falls inside the
> 1000..=1010 window Phase 2a accepts, so this is a real gap). Document
> as a Phase 2g concern and lower the UE5 ceiling here if needed.

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
            let idx = reader
                .read_i32::<LittleEndian>()
                .map_err(|_| eof(AssetWireField::ObjectPropertyIndex))?;
            PropertyValue::Object { index: idx }
        }
```

- [ ] **Step 5: Run primitive tests**

```bash
cargo test -p paksmith-core --lib asset::property::primitives::tests 2>&1 | tail -20
```

Expected: all tests pass, including the 5 new tests.

- [ ] **Step 6: Run workspace clippy**

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add crates/paksmith-core/src/asset/property/primitives.rs
git commit -m "$(cat <<'EOF'
feat(property): read_soft_path_payload + SoftObject/Class/ObjectProperty reads

read_soft_path_payload reads two FStrings (asset_path + sub_path) and is
pub(super) for reuse in containers.rs. read_primitive_value gains arms for
SoftObjectProperty, SoftClassProperty (delegate to helper), and ObjectProperty
(raw i32 index). Five unit tests covering null/import/export indices and both
soft path types.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: Extend `read_element_value` for ByteProperty and EnumProperty elements

**Files:**

- Modify: `crates/paksmith-core/src/asset/property/containers.rs`

Phase 2c left `ByteProperty` and `EnumProperty` element reads returning `None`. Two existing tests assert that. This task replaces those tests with correct-behavior tests and adds the implementation.

**ByteProperty element wire format:** single raw `u8` → `PropertyValue::Byte(u8)`.

**EnumProperty element wire format:** FName pair `(i32 index, i32 number)` resolved via the name table → `PropertyValue::Enum { type_name: String::new(), value: resolved }`. The enum class name (`type_name`) is empty because in element context no per-element FPropertyTag carries the `enum_name` field — that is only on the outer array tag, which `read_element_value` does not receive.

- [ ] **Step 1: Replace the two "returns none" tests with correct-behavior tests**

In the `tests` module in `containers.rs`, replace:

```rust
#[test]
fn element_enum_type_returns_none() {
    let ctx = make_ctx(&[]);
    let mut r = Cursor::new(vec![]);
    let v = read_element_value("EnumProperty", &mut r, &ctx, "x.uasset").unwrap();
    assert!(v.is_none());
}

#[test]
fn element_byte_type_returns_none() {
    let ctx = make_ctx(&[]);
    let mut r = Cursor::new(vec![]);
    let v = read_element_value("ByteProperty", &mut r, &ctx, "x.uasset").unwrap();
    assert!(v.is_none());
}
```

with:

```rust
#[test]
fn element_byte_reads_u8() {
    let ctx = make_ctx(&[]);
    let mut r = Cursor::new(vec![0xABu8]);
    let v = read_element_value("ByteProperty", &mut r, &ctx, "x.uasset")
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
    let v = read_element_value("EnumProperty", &mut r, &ctx, "x.uasset")
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
                .map_err(|_| eof(AssetWireField::ArrayElementCount))?;
            PV::Byte(b)
        }
        "EnumProperty" => {
            let idx = reader
                .read_i32::<LE>()
                .map_err(|_| eof(AssetWireField::EnumElementFName))?;
            let num = reader
                .read_i32::<LE>()
                .map_err(|_| eof(AssetWireField::EnumElementFName))?;
            let value =
                resolve_fname(idx, num, ctx, asset_path, AssetWireField::EnumElementFName)?;
            PV::Enum {
                type_name: String::new(),
                value,
            }
        }
```

Update `is_handled_element_type`:

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

- [ ] **Step 5: Run workspace clippy**

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add crates/paksmith-core/src/asset/property/containers.rs
git commit -m "$(cat <<'EOF'
feat(property): ByteProperty + EnumProperty element reads (Phase 2d)

ByteProperty element: raw u8 -> PropertyValue::Byte. EnumProperty element:
FName pair resolved from name table -> Enum { type_name: "", value }.
type_name is empty in element context (no per-element enum class name
available). is_handled_element_type grows from 12 to 14 types. Replaced
the two Phase 2c "returns_none" tests with correct-behavior tests.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
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
    let v = read_element_value("TextProperty", &mut r, &ctx, "x.uasset")
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
    let err = read_element_value("TextProperty", &mut r, &ctx, "x.uasset").unwrap_err();
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
use crate::asset::property::text::{read_ftext, FTextHistory};
```

In `read_element_value`, add before `_ => return Ok(None),`:

```rust
        "TextProperty" => {
            // tag_size=0: None/Base histories are self-delimiting so this is safe.
            // Unknown history would skip 0 bytes; detect it and error instead.
            let text = read_ftext(reader, ctx, asset_path, 0)?;
            if let FTextHistory::Unknown { history_type } = text.history {
                return Err(PaksmithError::AssetParse {
                    asset_path: asset_path.to_string(),
                    fault: AssetParseFault::TextHistoryUnsupportedInElement { history_type },
                });
            }
            PV::Text(text)
        }
```

Update `is_handled_element_type` to include `"TextProperty"`:

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

- [ ] **Step 5: Run workspace clippy**

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add crates/paksmith-core/src/asset/property/containers.rs
git commit -m "$(cat <<'EOF'
feat(property): TextProperty element reads + Unknown history guard (Phase 2d)

TextProperty elements call read_ftext(tag_size=0). None/Base histories are
self-delimiting and decode correctly. Unknown history with tag_size=0 would
skip 0 bytes and corrupt the cursor; detect and return
TextHistoryUnsupportedInElement instead. is_handled_element_type grows to 15.
Two unit tests: None history decodes, Unknown history errors.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task 6: Extend `read_element_value` for SoftObject/Class/Object elements; finalize `is_handled_element_type`

**Files:**

- Modify: `crates/paksmith-core/src/asset/property/containers.rs`

`SoftObjectProperty` and `SoftClassProperty` elements delegate to `read_soft_path_payload` (defined in `primitives.rs` as `pub(super)`). `ObjectProperty` elements read a raw `i32`.

- [ ] **Step 1: Write failing tests**

Add to the `tests` module in `containers.rs`:

```rust
#[test]
fn element_soft_object_path() {
    let ctx = make_ctx(&[]);
    let mut bytes: Vec<u8> = Vec::new();
    // First FString: "/Game/Hero.Hero\0" (16 bytes)
    let s1 = b"/Game/Hero.Hero\0";
    bytes.extend_from_slice(&(s1.len() as i32).to_le_bytes());
    bytes.extend_from_slice(s1);
    // Second FString: empty ("\0", length=1)
    bytes.extend_from_slice(&1i32.to_le_bytes());
    bytes.push(0u8);
    let mut r = Cursor::new(bytes);
    let v = read_element_value("SoftObjectProperty", &mut r, &ctx, "x.uasset")
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
    let ctx = make_ctx(&[]);
    let mut bytes: Vec<u8> = Vec::new();
    let s1 = b"/Game/BP/Hero.Hero_C\0";
    bytes.extend_from_slice(&(s1.len() as i32).to_le_bytes());
    bytes.extend_from_slice(s1);
    bytes.extend_from_slice(&1i32.to_le_bytes());
    bytes.push(0u8);
    let mut r = Cursor::new(bytes);
    let v = read_element_value("SoftClassProperty", &mut r, &ctx, "x.uasset")
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
    let v = read_element_value("ObjectProperty", &mut r, &ctx, "x.uasset")
        .unwrap()
        .unwrap();
    assert_eq!(v, PropertyValue::Object { index: -2 });
}
```

- [ ] **Step 2: Run tests to confirm compile error**

```bash
cargo test -p paksmith-core --lib asset::property::containers::tests::element_soft_object_path 2>&1 | tail -10
```

Expected: compile error — `SoftObjectProperty` arm not found.

- [ ] **Step 3: Add `read_soft_path_payload` to the primitives import and add three new arms**

Update the existing `primitives` import in `containers.rs`:

```rust
use crate::asset::property::primitives::{
    extract_fstring_fault, MapEntry, Property, PropertyValue, read_soft_path_payload,
};
```

In `read_element_value`, add before `_ => return Ok(None),`:

```rust
        "SoftObjectProperty" => {
            let (asset_p, sub) = read_soft_path_payload(reader, asset_path)?;
            PV::SoftObjectPath {
                asset_path: asset_p,
                sub_path: sub,
            }
        }
        "SoftClassProperty" => {
            let (asset_p, sub) = read_soft_path_payload(reader, asset_path)?;
            PV::SoftClassPath {
                asset_path: asset_p,
                sub_path: sub,
            }
        }
        "ObjectProperty" => {
            let idx = reader
                .read_i32::<LE>()
                .map_err(|_| eof(AssetWireField::ObjectPropertyIndex))?;
            PV::Object { index: idx }
        }
```

Update `is_handled_element_type` to its final Phase 2d form:

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

- [ ] **Step 6: Run workspace clippy**

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add crates/paksmith-core/src/asset/property/containers.rs
git commit -m "$(cat <<'EOF'
feat(property): Soft*/ObjectProperty element reads; finalize is_handled_element_type

SoftObjectProperty and SoftClassProperty elements delegate to
read_soft_path_payload from primitives.rs (pub(super) shared helper).
ObjectProperty element reads raw i32 index. is_handled_element_type
grows to 18 types, covering all Phase 2d element types. Three unit tests.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task 7: Integration tests and fixture builder

**Files:**

- Modify: `crates/paksmith-core/src/testing/uasset.rs` — add `build_minimal_ue4_27_with_extended_types`
- Create: `crates/paksmith-core/tests/extended_types_integration.rs`

- [ ] **Step 1: Add `build_minimal_ue4_27_with_extended_types` to `testing/uasset.rs`**

Add to `crates/paksmith-core/src/testing/uasset.rs`:

```rust
/// Builds a synthetic UAsset (UE 4.27, fileVersionUE4=522) whose single
/// export body contains six properties covering Phase 2d extended types,
/// followed by a None terminator.
///
/// Export property layout:
/// - `SoftRef: SoftObjectProperty` = ("/Game/Data/Hero.Hero", "")
/// - `SoftClass: SoftClassProperty` = ("/Game/BP/HeroClass.HeroClass_C", "")
/// - `ObjRef: ObjectProperty` = -1 (import table entry 0)
/// - `Tags: ArrayProperty<ByteProperty>` = [10, 20]
/// - `Flags: ArrayProperty<EnumProperty>` = ["EColor__Red"]
/// - `Desc: ArrayProperty<TextProperty>` = [FText::None (no culture-invariant)]
/// - None terminator
///
/// Name table:
///   0=None, 1=SoftRef, 2=SoftObjectProperty, 3=SoftClass, 4=SoftClassProperty,
///   5=ObjRef, 6=ObjectProperty, 7=Tags, 8=ArrayProperty, 9=ByteProperty,
///   10=Flags, 11=EnumProperty, 12=EColor__Red, 13=Desc, 14=TextProperty
///
/// Returns the raw UAsset bytes.
#[cfg(feature = "__test_utils")]
pub fn build_minimal_ue4_27_with_extended_types() -> Vec<u8> {
    let mut body: Vec<u8> = Vec::new();

    let write_fname = |buf: &mut Vec<u8>, idx: i32, num: i32| {
        buf.extend_from_slice(&idx.to_le_bytes());
        buf.extend_from_slice(&num.to_le_bytes());
    };
    let write_fstring = |buf: &mut Vec<u8>, s: &str| {
        let with_null = format!("{s}\0");
        let len = with_null.len() as i32;
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(with_null.as_bytes());
    };

    // --- Property 1: SoftRef: SoftObjectProperty ---
    {
        let mut payload: Vec<u8> = Vec::new();
        write_fstring(&mut payload, "/Game/Data/Hero.Hero"); // 4+21=25 bytes
        write_fstring(&mut payload, "");                     // 4+1=5 bytes; total=30

        write_fname(&mut body, 1, 0); // Name: SoftRef (idx 1)
        write_fname(&mut body, 2, 0); // Type: SoftObjectProperty (idx 2)
        body.extend_from_slice(&(payload.len() as i32).to_le_bytes()); // Size: 30
        body.extend_from_slice(&0i32.to_le_bytes()); // ArrayIndex: 0
        body.push(0u8);              // HasPropertyGuid: 0
        body.extend_from_slice(&payload);
    }

    // --- Property 2: SoftClass: SoftClassProperty ---
    {
        let mut payload: Vec<u8> = Vec::new();
        write_fstring(&mut payload, "/Game/BP/HeroClass.HeroClass_C"); // 4+31=35 bytes
        write_fstring(&mut payload, "");                                // 4+1=5 bytes; total=40

        write_fname(&mut body, 3, 0); // Name: SoftClass (idx 3)
        write_fname(&mut body, 4, 0); // Type: SoftClassProperty (idx 4)
        body.extend_from_slice(&(payload.len() as i32).to_le_bytes()); // Size: 40
        body.extend_from_slice(&0i32.to_le_bytes());
        body.push(0u8);
        body.extend_from_slice(&payload);
    }

    // --- Property 3: ObjRef: ObjectProperty = -1 ---
    {
        write_fname(&mut body, 5, 0); // Name: ObjRef (idx 5)
        write_fname(&mut body, 6, 0); // Type: ObjectProperty (idx 6)
        body.extend_from_slice(&4i32.to_le_bytes()); // Size: 4
        body.extend_from_slice(&0i32.to_le_bytes()); // ArrayIndex: 0
        body.push(0u8);              // HasPropertyGuid: 0
        body.extend_from_slice(&(-1i32).to_le_bytes()); // index = -1
    }

    // --- Property 4: Tags: ArrayProperty<ByteProperty> = [10, 20] ---
    {
        let mut payload: Vec<u8> = Vec::new();
        payload.extend_from_slice(&2i32.to_le_bytes()); // count: 2
        payload.push(10u8);
        payload.push(20u8);
        // total: 4 + 2 = 6 bytes

        write_fname(&mut body, 7, 0); // Name: Tags (idx 7)
        write_fname(&mut body, 8, 0); // Type: ArrayProperty (idx 8)
        body.extend_from_slice(&(payload.len() as i32).to_le_bytes()); // Size: 6
        body.extend_from_slice(&0i32.to_le_bytes());
        write_fname(&mut body, 9, 0); // InnerType: ByteProperty (idx 9)
        body.push(0u8);
        body.extend_from_slice(&payload);
    }

    // --- Property 5: Flags: ArrayProperty<EnumProperty> = ["EColor__Red"] ---
    {
        let mut payload: Vec<u8> = Vec::new();
        payload.extend_from_slice(&1i32.to_le_bytes()); // count: 1
        // FName(12, 0) = "EColor__Red"
        payload.extend_from_slice(&12i32.to_le_bytes());
        payload.extend_from_slice(&0i32.to_le_bytes());
        // total: 4 + 8 = 12 bytes

        write_fname(&mut body, 10, 0); // Name: Flags (idx 10)
        write_fname(&mut body, 8, 0);  // Type: ArrayProperty (idx 8)
        body.extend_from_slice(&(payload.len() as i32).to_le_bytes()); // Size: 12
        body.extend_from_slice(&0i32.to_le_bytes());
        write_fname(&mut body, 11, 0); // InnerType: EnumProperty (idx 11)
        body.push(0u8);
        body.extend_from_slice(&payload);
    }

    // --- Property 6: Desc: ArrayProperty<TextProperty> = [FText::None] ---
    {
        let mut payload: Vec<u8> = Vec::new();
        payload.extend_from_slice(&1i32.to_le_bytes()); // count: 1
        // FText: flags(u32=0), history_type(i8=-1 = 0xFF), bHasCultureInvariant(u8=0)
        payload.extend_from_slice(&0u32.to_le_bytes()); // flags
        payload.push(0xFFu8);                            // history_type = -1
        payload.push(0u8);                               // bHasCultureInvariantString = false
        // total: 4 + 4 + 1 + 1 = 10 bytes

        write_fname(&mut body, 13, 0); // Name: Desc (idx 13)
        write_fname(&mut body, 8, 0);  // Type: ArrayProperty (idx 8)
        body.extend_from_slice(&(payload.len() as i32).to_le_bytes()); // Size: 10
        body.extend_from_slice(&0i32.to_le_bytes());
        write_fname(&mut body, 14, 0); // InnerType: TextProperty (idx 14)
        body.push(0u8);
        body.extend_from_slice(&payload);
    }

    // None terminator
    body.extend_from_slice(&0i32.to_le_bytes());
    body.extend_from_slice(&0i32.to_le_bytes());

    let names: &[&str] = &[
        "None",
        "SoftRef",
        "SoftObjectProperty",
        "SoftClass",
        "SoftClassProperty",
        "ObjRef",
        "ObjectProperty",
        "Tags",
        "ArrayProperty",
        "ByteProperty",
        "Flags",
        "EnumProperty",
        "EColor__Red",
        "Desc",
        "TextProperty",
    ];
    build_with_payload(names, body)
}
```

- [ ] **Step 2: Create integration tests**

Create `crates/paksmith-core/tests/extended_types_integration.rs`:

```rust
//! Integration tests for Phase 2d extended property types.

#[cfg(feature = "__test_utils")]
mod tests {
    use paksmith_core::asset::property::primitives::PropertyValue;
    use paksmith_core::asset::property::text::{FText, FTextHistory};
    use paksmith_core::asset::Package;
    use paksmith_core::testing::uasset::build_minimal_ue4_27_with_extended_types;

    #[test]
    fn parse_soft_object_property() {
        let bytes = build_minimal_ue4_27_with_extended_types();
        let pkg = Package::read_from(&bytes, "Game/Data/Test.uasset").unwrap();
        let props = pkg.exports[0].properties_tree().unwrap();
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
        let bytes = build_minimal_ue4_27_with_extended_types();
        let pkg = Package::read_from(&bytes, "Game/Data/Test.uasset").unwrap();
        let props = pkg.exports[0].properties_tree().unwrap();
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
        let bytes = build_minimal_ue4_27_with_extended_types();
        let pkg = Package::read_from(&bytes, "Game/Data/Test.uasset").unwrap();
        let props = pkg.exports[0].properties_tree().unwrap();
        let prop = props.iter().find(|p| p.name == "ObjRef").unwrap();
        assert_eq!(prop.value, PropertyValue::Object { index: -1 });
    }

    #[test]
    fn parse_array_of_byte_properties() {
        let bytes = build_minimal_ue4_27_with_extended_types();
        let pkg = Package::read_from(&bytes, "Game/Data/Test.uasset").unwrap();
        let props = pkg.exports[0].properties_tree().unwrap();
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
        let bytes = build_minimal_ue4_27_with_extended_types();
        let pkg = Package::read_from(&bytes, "Game/Data/Test.uasset").unwrap();
        let props = pkg.exports[0].properties_tree().unwrap();
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
        let bytes = build_minimal_ue4_27_with_extended_types();
        let pkg = Package::read_from(&bytes, "Game/Data/Test.uasset").unwrap();
        let props = pkg.exports[0].properties_tree().unwrap();
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
cargo test --workspace --features __test_utils 2>&1 | tail -20
```

Expected: all tests pass.

- [ ] **Step 5: Run workspace clippy**

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add crates/paksmith-core/src/testing/uasset.rs \
        crates/paksmith-core/tests/extended_types_integration.rs
git commit -m "$(cat <<'EOF'
test(property): Phase 2d integration tests + extended-types fixture

build_minimal_ue4_27_with_extended_types emits 6 properties: direct
SoftObjectProperty, SoftClassProperty, ObjectProperty, plus Array of
ByteProperty, Array of EnumProperty, Array of TextProperty (None history).
6 integration tests verify each decoded value exactly.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task 8: Fixture-gen cross-validation and CLI snapshot update

**Files:**

- Modify: `crates/paksmith-fixture-gen/src/uasset.rs` — add Phase 2d oracle cross-validation block
- Modify: `crates/paksmith-cli/src/commands/inspect.rs` — update insta snapshot

- [ ] **Step 1: Extend fixture-gen with Phase 2d cross-validation**

Open `crates/paksmith-fixture-gen/src/uasset.rs`. Find the existing Phase 2c cross-validation block (the one calling `build_minimal_ue4_27_with_containers`) and add a new block after it:

```rust
// Phase 2d: cross-validate extended-type properties against unreal_asset oracle.
let ext_bytes =
    paksmith_core::testing::uasset::build_minimal_ue4_27_with_extended_types();
let _ext_pak = wrap_in_pak(&ext_bytes, "Game/Data/TestExtended.uasset");

let oracle_ext = unreal_asset::Asset::new(
    std::io::Cursor::new(ext_bytes.clone()),
    None,
    unreal_asset::engine_version::EngineVersion::VER_UE4_27,
    None,
)
.expect("oracle should parse Phase 2d extended-types fixture");

let paksmith_ext = paksmith_core::asset::Package::read_from(
    &ext_bytes,
    "Game/Data/TestExtended.uasset",
)
.expect("paksmith should parse Phase 2d extended-types fixture");

assert_eq!(
    oracle_ext.asset_data.exports.len(),
    paksmith_ext.exports.len(),
    "Phase 2d: export count mismatch"
);

let normal_ext = oracle_ext.asset_data.exports[0]
    .get_normal_export()
    .expect("Phase 2d: first export should be normal export");

// Oracle sees SoftRef (SoftObjectProperty)
assert!(
    normal_ext
        .properties
        .iter()
        .any(|p| p.get_name().get_owned_content() == "SoftRef"),
    "Phase 2d: oracle does not find SoftRef property"
);

// Oracle sees Tags (ArrayProperty<ByteProperty>)
assert!(
    normal_ext
        .properties
        .iter()
        .any(|p| p.get_name().get_owned_content() == "Tags"),
    "Phase 2d: oracle does not find Tags property"
);

// Oracle sees Desc (ArrayProperty<TextProperty>)
assert!(
    normal_ext
        .properties
        .iter()
        .any(|p| p.get_name().get_owned_content() == "Desc"),
    "Phase 2d: oracle does not find Desc property"
);
```

- [ ] **Step 2: Run fixture-gen to confirm cross-validation passes**

```bash
cargo run -p paksmith-fixture-gen 2>&1 | tail -20
```

Expected: runs without assertion failures. If the oracle rejects the fixture (panics on `Asset::new`), the byte layout in `build_minimal_ue4_27_with_extended_types` is wrong — compare against the Phase 2c `build_minimal_ue4_27_with_containers` pattern to find the discrepancy.

- [ ] **Step 3: Update the CLI insta snapshot for new property types**

The `paksmith inspect` command has an insta snapshot test. New property types change the JSON output. Run:

```bash
cargo test -p paksmith-cli -- --test-threads=1 2>&1 | tail -30
```

If the snapshot is stale:

```bash
cargo insta review
```

Accept the updated snapshot. The new output should show `SoftObjectPath`, `SoftClassPath`, `Object`, and arrays of `Byte`, `Enum`, `Text` values for any fixtures that exercise Phase 2d types.

- [ ] **Step 4: Run workspace tests**

```bash
cargo test --workspace --features __test_utils 2>&1 | tail -20
```

Expected: all tests pass.

- [ ] **Step 5: Run workspace clippy**

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add crates/paksmith-fixture-gen/src/uasset.rs \
        crates/paksmith-cli/src/commands/inspect.rs \
        crates/paksmith-cli/src/commands/snapshots
git commit -m "$(cat <<'EOF'
test(fixture-gen): Phase 2d oracle cross-validation + CLI snapshot update

Cross-validates build_minimal_ue4_27_with_extended_types against
unreal_asset oracle: export count match, SoftRef/Tags/Desc properties
visible to oracle. CLI insta snapshot updated to include SoftObjectPath,
SoftClassPath, Object, Byte/Enum/Text array elements.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
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
| 4 new `AssetWireField` variants                 | Task 1 |
| 3 new `PropertyValue` variants                  | Task 2 |
| `read_soft_path_payload` shared helper          | Task 3 |
| Integration fixture + 6 tests                   | Task 7 |
| Fixture-gen oracle cross-validation             | Task 8 |
| CLI snapshot update                             | Task 8 |

All spec requirements have a covering task.

### Placeholder scan

No TBD, TODO, "similar to Task N" shortcuts, or undefined functions in any step. All code blocks are complete. `build_with_payload` is the established Phase 2b helper; `wrap_in_pak` is the established Phase 2c fixture-gen helper. `properties_tree()` is the established Phase 2b API.

### Type consistency

- `read_soft_path_payload` declared `pub(super) fn read_soft_path_payload<R: Read>(reader: &mut R, asset_path: &str) -> crate::Result<(String, String)>` in Task 3 Step 3; imported into containers.rs in Task 6 Step 3.
- `FTextHistory::Unknown { history_type }` destructures the `history_type: i8` field; `AssetParseFault::TextHistoryUnsupportedInElement { history_type: i8 }` defined in Task 1 matches.
- `PropertyValue::Enum { type_name: String::new(), value }` in Task 4 Step 3 matches the variant defined in Phase 2b (`Enum { type_name: String, value: String }`).
- `AssetWireField::EnumElementFName` used in Task 4 Step 3 matches the variant added in Task 1 Step 4.
- `AssetWireField::ObjectPropertyIndex` used in Tasks 3 and 6 matches the variant added in Task 1 Step 4.

### Lint gate

Every task ends with `cargo clippy --workspace --all-targets --all-features -- -D warnings` (per `MEMORY.md` `ghas_clippy_extra_lints.md`) AND `cargo fmt --all -- --check`. CI's `Lint` job runs both; clippy passing locally does NOT imply fmt is clean — see PR #149 follow-up. The `.githooks/pre-commit` hook enforces both when wired up via `git config core.hooksPath .githooks` (one-time per clone).
