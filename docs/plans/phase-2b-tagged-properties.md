# Paksmith Phase 2b: Tagged Property Iteration + Primitive Payloads

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Parse `FPropertyTag` headers and primitive property payloads (Bool, Byte, Int variants, Float, Double, Str, Name, Enum, Text) from export bodies, replacing `PropertyBag::Opaque` with a real `PropertyBag::Tree { properties: Vec<Property> }` for tagged assets. `paksmith inspect` output gains a human-readable property tree. Unknown/container property types skip via `tag.size` without panicking.

**Architecture:** New `asset/property/` submodule replaces the flat `asset/property_bag.rs` from Phase 2a (mechanical rename — no behavior change to `PropertyBag::Opaque`). Four focused files: `bag.rs` (migrated), `tag.rs` (FPropertyTag reader + `resolve_fname` helper), `primitives.rs` (`Property`, `PropertyValue`, per-type readers), `text.rs` (`FText` + `FTextHistory`). The property iterator in `mod.rs` drives the outer loop with two hard caps (`MAX_TAGS_PER_EXPORT = 65_536`, `MAX_PROPERTY_TAG_SIZE = 16 MiB`) and a cursor-mismatch invariant after every value. `Package::read_from` gains an early `PKG_UnversionedProperties` rejection before attempting property iteration; the existing `PropertyBag::Opaque` path is retained as a fallback if a parse error occurs mid-iteration (the caller logs at `warn!` and falls back). Error sub-enums are extended with four new `AssetParseFault` variants (`UnversionedPropertiesUnsupported`, `PropertyTagSizeMismatch`, `PropertyDepthExceeded`, `PropertyTagCountExceeded`) and ten new `AssetWireField` variants; negative-size and size-cap rejections **reuse** the existing `NegativeValue` and `BoundsExceeded` variants Phase 2a already uses for `NameCount`/`ImportCount`/`ExportSerialSize` and `TotalHeaderSize`/`NameOffset` respectively (with `field: AssetWireField::PropertyTagSize`). Each new variant is pinned by a wire-stable Display unit test.

**Tech Stack:** Same as Phase 2a — Rust 1.85, `thiserror`, `byteorder` (LE wire reads), `serde` (JSON output), `tracing` (warn-level fallback logging), `proptest` (round-trip + cap-rejection tests), `unreal_asset` (fixture-gen cross-validation oracle, pinned to `f4df5d8e75b1e184832384d1865f0b696b90a614`). No new crate dependencies.

---

## Deliverable

`paksmith inspect <pak> <virtual/path>` now renders a real property tree instead of `"payload_bytes": N`. Container/unknown property types appear as `Unknown` entries with a `skipped_bytes` count.

```json
{
  "asset_path": "Game/Data/Hero.uasset",
  "summary": {
    "legacy_file_version": -8,
    "file_version_ue4": 522,
    "file_version_ue5": null,
    "file_version_licensee_ue4": 0,
    "package_flags": 0,
    "total_header_size": 480,
    "folder_name": "None",
    "saved_by_engine_version": "4.27.2-0+++UE4+Release-4.27",
    "compatible_with_engine_version": "4.27.2-0+++UE4+Release-4.27",
    "custom_versions": []
  },
  "names": [
    "None",
    "Hero",
    "bEnabled",
    "MaxSpeed",
    "ObjectName",
    "BoolProperty",
    "FloatProperty",
    "StrProperty"
  ],
  "imports": [],
  "exports": [
    {
      "class_index": "Null",
      "super_index": "Null",
      "outer_index": "Null",
      "object_name": "Hero",
      "serial_size": 106,
      "serial_offset": 480,
      "properties": [
        {
          "name": "bEnabled",
          "array_index": 0,
          "guid": null,
          "value": { "Bool": true }
        },
        {
          "name": "MaxSpeed",
          "array_index": 0,
          "guid": null,
          "value": { "Float": 1500.0 }
        },
        {
          "name": "ObjectName",
          "array_index": 0,
          "guid": null,
          "value": { "Str": "Hero_Blueprint_C_0" }
        },
        {
          "name": "Tags",
          "array_index": 0,
          "guid": null,
          "value": {
            "Unknown": {
              "type_name": "ArrayProperty",
              "skipped_bytes": 8
            }
          }
        }
      ]
    }
  ]
}
```

## Scope vs deferred work

**In scope (this plan):**

- `FPropertyTag` wire reader (Name, Type, Size, ArrayIndex, type-specific extras, optional PropertyGuid)
- "None" terminator detection (name_index == 0 && name_number == 0, or resolved == "None")
- Primitive payloads: `BoolProperty`, `ByteProperty` (raw u8 or FName-as-Enum), `Int8Property`, `Int16Property`, `IntProperty`, `Int64Property`, `UInt16Property`, `UInt32Property`, `UInt64Property`, `FloatProperty`, `DoubleProperty`, `StrProperty`, `NameProperty`, `EnumProperty`, `TextProperty`
- `FText` for `ETextHistoryType::None (-1)` and `ETextHistoryType::Base (0)` — namespace, key, source string
- `PropertyBag::Tree { properties: Vec<Property> }` variant (alongside existing `::Opaque`)
- Unknown/container types (Array, Map, Set, Struct, SoftObjectPath, etc.) skip via `tag.size` → `PropertyValue::Unknown { type_name, skipped_bytes }`
- `PKG_UnversionedProperties = 0x0000_2000` flag → early `AssetParseFault::UnversionedPropertiesUnsupported` rejection
- Security caps: `MAX_TAGS_PER_EXPORT = 65_536`, `MAX_PROPERTY_TAG_SIZE = 16 MiB`
- Cursor-mismatch invariant: `reader.position() == value_start + tag.size` after every value read
- Six new `AssetParseFault` variants + ten new `AssetWireField` variants, all with wire-stable Display pins
- `paksmith inspect` JSON output updated to render `PropertyBag::Tree` as a `properties` array
- Fixture-gen: extend `build_minimal_ue4_27()` with FPropertyTag byte emission; cross-validate with `unreal_asset`

**Deferred to later milestones:**

- Container properties (ArrayProperty contents, MapProperty, SetProperty) — **Phase 2c**
- StructProperty recursion + struct payload parsing — **Phase 2c**
- `SoftObjectPath`, `SoftClassPath`, `ObjectProperty` (object graph resolution) — **Phase 2d**
- `.uexp` companion file stitching for assets with `SerialOffset >= TotalHeaderSize` — **Phase 2e**
- Unversioned / schema-driven properties (`PKG_UnversionedProperties`) — **Phase 2f** (scoped but requires UE struct schema registry)
- `ETextHistoryType` variants other than None (-1) and Base (0) — stored as `FTextHistory::Unknown` in Phase 2b
- Asset-level AES decryption — Phase 5
- ByteProperty as-byte-enum: when `enum_name` refers to a known UE enum but value fits in one byte, Phase 2b stores as `PropertyValue::Enum` with `value = read_fname_as_string(...)`. If the FName read fails because UE wrote a raw u8 (older cooker path), the cursor-mismatch check fires an error — correct behavior, not a silent skip.

## Design decisions locked here (so 2c–2e don't relitigate)

1. **Module layout:** `asset/property/` submodule with `bag.rs`, `tag.rs`, `primitives.rs`, `text.rs`, `mod.rs`. This matches the ROADMAP's `property/` structure and gives 2c a natural home for `containers.rs` and 2d for `objects.rs`.

2. **`PropertyValue::Unknown` carries resolved String, not `FName`:** `PropertyValue::Unknown { type_name: String, skipped_bytes: usize }` stores the resolved string. This keeps `PropertyValue` standalone-serializable without `&AssetContext` — the same reason all `Property::name` fields are `String` not `FName`. FName resolution happens at property-tag read time, not at JSON serialization time.

3. **`PropertyTag` struct populated at tag-read time:** `struct_name`, `enum_name`, `inner_type`, `value_type`, `struct_guid`, `bool_val` are all decoded and stored in `PropertyTag` regardless of whether the type is "known." This lets 2c's `read_array_value` receive a pre-populated `inner_type` without re-reading the stream.

4. **Security caps:**
   - `MAX_TAGS_PER_EXPORT = 65_536` (guards against missing "None" terminator loop)
   - `MAX_PROPERTY_TAG_SIZE = 16 * 1024 * 1024` (guards unknown-type skip allocation)
     Both are `pub const` in `property/mod.rs` — 2c may lower them but never needs to raise them.

5. **Cursor-mismatch invariant is a hard error:** After reading any property value (including the Unknown skip path), `reader.position() != value_start + tag.size` → `AssetParseFault::PropertyTagSizeMismatch`. This is not a `warn!` + continue — mismatch means either version skew or malicious data, and silently continuing would misparse subsequent properties.

6. **`PKG_UnversionedProperties` rejection fires in `Package::read_from`, before any export-body iteration:** The flag is on the summary (`summary.package_flags`), so the check is performed in `Package::read_from` immediately after `ExportTable::read_from` returns and before `read_payloads`/the property iterator runs. The check **does not live inside `read_properties`** — once an export body is reached, an `UnversionedPropertiesUnsupported` fault would be wrong (the iterator has no business knowing about package flags), and per-export rejection would discard any clean exports in the package before the flagged one. Variant name: `AssetParseFault::UnversionedPropertiesUnsupported`. Not a warn+fallback-to-Opaque — unversioned exports are structurally unreadable by the tagged iterator. Implementation lands in Task 7 Step 4.

7. **`PropertyBag::Tree` as an additive struct variant:** `#[non_exhaustive]` was already present on `PropertyBag` from Phase 2a. Adding `Tree { properties: Vec<Property> }` is a non-breaking additive change. **Struct variant (not newtype):** the parent enum derives `#[serde(tag = "kind", rename_all = "snake_case")]` (`property_bag.rs:44` post-rename). Serde's internal tagging only supports unit and struct variants — newtype/tuple variants like `Tree(Vec<Property>)` fail to compile with a serde error. The deliverable JSON example below shows `"properties": [...]` nested under each export's tagged bag, which is exactly the shape a struct variant produces. The existing `Opaque` variant is retained as the fallback when a parse error is recoverable (e.g., a single export with a malformed tag doesn't abort the whole package).

8. **`resolve_fname(index: i32, number: i32, ctx, asset_path, field)` helper:** Lives in `property/tag.rs` (not `name_table.rs` — avoid polluting the header-parsing module with property context). Uses `ctx.names.get(index as u32)` for the non-error path and emits `AssetParseFault::PackageIndexUnderflow { field }` for `index < 0`, `PackageIndexOob { field, .. }` for OOB. The `number` suffix: `number <= 0` → no suffix; `number > 0` → `format!("{}_{}", name, number - 1)` (UE convention: stored number 1 means `_0` suffix).

   **Intentionally distinct from `NameTable::resolve(index: u32, number: u32)` at `name_table.rs:111`.** The header-side `resolve` takes `u32`s (matching Phase 2a's import/export table layout where FName slots are declared `u32` — `ObjectImport::class_package_name`, `ObjectExport::object_name`, etc. — because in those layouts the value is structurally constrained to be in-range or the table read would have already failed) and renders OOB as `<oob:{index}>` (inspect-friendly tolerant fallback). The property-side `resolve_fname` takes `i32` (matching `FPropertyTag`'s wire layout — see CUE4Parse `FAssetArchive.ReadFName()` which reads `Read<int>()` for both `nameIndex` and `extraIndex/Number`, and `FPropertyTag.cs` which propagates that signed shape) and returns typed errors. The wire-shape signedness difference is intentional: at property-tag-iteration time, an i32::MIN nameIndex is a real attacker-controllable input that must produce a structured error (`PackageIndexUnderflow`), not a placeholder string. At inspect-render time over the header tables, OOB is at worst a Phase-2a parser bug surfacing visibly — typed errors there would mask the bug behind a panicking fault. The two helpers solve different problems and coexist.

9. **FText `ETextHistoryType::Base` reads three FStrings (namespace, key, source_string) unconditionally:** Modern UE writers always emit all three. Pre-Phase-2b floor (FileVersionUE4 < 504) is already rejected at summary parse time, so no version gating is needed here.

10. **FText `ETextHistoryType::None` reads `has_culture_invariant` (u8) unconditionally:** CUE4Parse gates this on `FEditorObjectVersion >= CultureInvariantTextSerializationKeyStability` (a per-plugin custom version added around UE 4.13–4.14). At Phase 2a's UE 4.21+ floor, this custom version is always present in cooked assets, so the unconditional read is safe. If `FEditorObjectVersion` is somehow absent or below the floor, the read would consume one byte from the next field. Defensive option: parse the package's `CustomVersionContainer` and gate this read on the actual custom-version value. Deferred — the failure mode is benign for the targeted version range.

11. **BoolProperty:** `boolVal` is the u8 in the tag header; `tag.size == 0`; no payload bytes follow. The cursor check after `read_property_value` will assert `actual_pos == value_start + 0`.

---

## File Structure

```plaintext
crates/paksmith-core/src/
├── asset/
│   ├── property/                    # NEW submodule (replaces flat property_bag.rs)
│   │   ├── mod.rs                   # NEW — read_properties, MAX_TAGS_PER_EXPORT, MAX_PROPERTY_TAG_SIZE, re-exports
│   │   ├── bag.rs                   # NEW — PropertyBag (content moved from property_bag.rs)
│   │   ├── tag.rs                   # NEW — PropertyTag, read_tag, resolve_fname
│   │   ├── primitives.rs            # NEW — Property, PropertyValue, read_primitive_value
│   │   └── text.rs                  # NEW — FText, FTextHistory, read_ftext
│   ├── property_bag.rs              # REMOVE (task 2 migrates its content to property/bag.rs)
│   ├── mod.rs                       # MODIFY — swap `pub mod property_bag` for `pub mod property`
│   └── package.rs                   # MODIFY — add unversioned flag check + property iteration
├── error.rs                         # MODIFY — six new AssetParseFault variants + ten AssetWireField + three AssetAllocationContext
└── testing/
    └── uasset.rs                    # MODIFY — add property-emitting helpers + build_minimal_ue4_27_with_properties

crates/paksmith-core/tests/
├── property_integration.rs          # NEW — load pak → parse properties → assert tree
└── property_proptest.rs             # NEW — round-trips + cap rejections

crates/paksmith-fixture-gen/src/
└── uasset.rs                        # MODIFY — call build_minimal_ue4_27_with_properties; cross-validate properties

crates/paksmith-cli/src/commands/
└── inspect.rs                       # MODIFY — render PropertyBag::Tree; update insta snapshot
```

---

### Task 1: Extend `AssetParseFault`, `AssetWireField`, and `AssetAllocationContext` for Phase 2b

**Files:**

- Modify: `crates/paksmith-core/src/error.rs` — new variants on three existing enums

**Why:** Every Phase 2b parser returns `Result<T, PaksmithError>` using these typed variants. Build the error API first so all subsequent tasks write to a stable surface.

**Variant reuse:** Negative `FPropertyTag::Size` and size-over-cap rejections reuse Phase 2a's existing `AssetParseFault::NegativeValue { field, value }` (`error.rs:2126`) and `AssetParseFault::BoundsExceeded { field, value, limit, unit }` (`error.rs:2089`) — the same variants used for `NameCount`/`ImportCount`/`ExportSerialSize` negativity and `TotalHeaderSize`/`NameOffset` cap-overflow. Adding property-specific `PropertyTagNegativeSize` and `PropertyTagSizeExceedsCap` variants would duplicate the existing schema. Only the new `AssetWireField::PropertyTagSize` tag is needed to discriminate at the field level. This task adds four new variants (down from six in the original draft): `UnversionedPropertiesUnsupported`, `PropertyTagSizeMismatch`, `PropertyDepthExceeded`, `PropertyTagCountExceeded`.

- [ ] **Step 1: Write failing Display-stability tests for the new variants**

Add to the `#[cfg(test)] mod tests` block inside `error.rs`:

```rust
#[test]
fn asset_parse_display_unversioned_properties() {
    let err = PaksmithError::AssetParse {
        asset_path: "Game/Data/Hero.uasset".to_string(),
        fault: AssetParseFault::UnversionedPropertiesUnsupported,
    };
    assert_eq!(
        format!("{err}"),
        "asset deserialization failed for `Game/Data/Hero.uasset`: \
         unversioned properties (PKG_UnversionedProperties=0x2000) \
         are not supported in Phase 2b"
    );
}

#[test]
fn asset_parse_display_property_tag_negative_size_reuses_negative_value() {
    // Phase 2b property-tag negative sizes reuse the existing
    // AssetParseFault::NegativeValue variant with field=PropertyTagSize.
    // This pins both the variant choice and the field tag's Display
    // string ("property_tag_size") together so a future refactor that
    // renames either is forced through this test.
    let err = PaksmithError::AssetParse {
        asset_path: "x.uasset".to_string(),
        fault: AssetParseFault::NegativeValue {
            field: AssetWireField::PropertyTagSize,
            value: -42,
        },
    };
    assert_eq!(
        format!("{err}"),
        "asset deserialization failed for `x.uasset`: \
         property_tag_size value -42 is negative"
    );
}

#[test]
fn asset_parse_display_property_tag_size_exceeds_cap_reuses_bounds_exceeded() {
    // Phase 2b property-tag oversize reuses the existing
    // AssetParseFault::BoundsExceeded variant with
    // unit=BoundsUnit::Bytes. Same rationale as the negative-size
    // test above.
    let err = PaksmithError::AssetParse {
        asset_path: "x.uasset".to_string(),
        fault: AssetParseFault::BoundsExceeded {
            field: AssetWireField::PropertyTagSize,
            value: 20_000_000,
            limit: 16_777_216,
            unit: BoundsUnit::Bytes,
        },
    };
    // BoundsExceeded's existing Display string format (verify against
    // the actual Phase 2a output at error.rs ~line 2264) — adjust to
    // match. The reuse here is the load-bearing test; the exact
    // Display string is whatever Phase 2a already emits.
    let s = format!("{err}");
    assert!(s.contains("property_tag_size"), "got: {s}");
    assert!(s.contains("20000000"), "got: {s}");
    assert!(s.contains("16777216"), "got: {s}");
}

#[test]
fn asset_parse_display_property_tag_size_mismatch() {
    let err = PaksmithError::AssetParse {
        asset_path: "x.uasset".to_string(),
        fault: AssetParseFault::PropertyTagSizeMismatch {
            expected_end: 1024,
            actual_pos: 1020,
        },
    };
    assert_eq!(
        format!("{err}"),
        "asset deserialization failed for `x.uasset`: \
         property tag size mismatch: expected cursor at 1024, was at 1020"
    );
}

#[test]
fn asset_parse_display_property_depth_exceeded() {
    let err = PaksmithError::AssetParse {
        asset_path: "x.uasset".to_string(),
        fault: AssetParseFault::PropertyDepthExceeded { depth: 129, limit: 128 },
    };
    assert_eq!(
        format!("{err}"),
        "asset deserialization failed for `x.uasset`: \
         property depth 129 exceeds limit 128"
    );
}

#[test]
fn asset_parse_display_property_tag_count_exceeded() {
    let err = PaksmithError::AssetParse {
        asset_path: "x.uasset".to_string(),
        fault: AssetParseFault::PropertyTagCountExceeded { limit: 65536 },
    };
    assert_eq!(
        format!("{err}"),
        "asset deserialization failed for `x.uasset`: \
         property tag count exceeded limit 65536 (missing None terminator?)"
    );
}
```

- [ ] **Step 2: Run tests to confirm they fail (types don't exist yet)**

```bash
cargo test -p paksmith-core --lib error::tests::asset_parse_display_unversioned 2>&1 | tail -10
```

Expected: compile error — `AssetParseFault::UnversionedPropertiesUnsupported` not found.

- [ ] **Step 3: Add new `AssetParseFault` variants**

Find the end of the `AssetParseFault` enum body (just before `impl fmt::Display for AssetParseFault`) and add after `UnexpectedEof`. Four new variants — `PropertyTagNegativeSize` and `PropertyTagSizeExceedsCap` from the audit-superseded draft are dropped; the existing `NegativeValue` and `BoundsExceeded` variants are reused with `field: AssetWireField::PropertyTagSize` (see the task header note above):

```rust
    /// The export's property stream has `PKG_UnversionedProperties`
    /// (flag bit `0x0000_2000`) set — schema-driven (unversioned)
    /// encoding rather than FPropertyTag iteration. Phase 2b only
    /// supports the tagged (versioned) property stream; unversioned
    /// parsing requires the UE struct schema registry, deferred to
    /// Phase 2f.
    UnversionedPropertiesUnsupported,

    /// After reading a property value, the stream cursor was not at
    /// `value_start + tag.size`. Indicates version skew (a
    /// type-specific reader consumed the wrong byte count) or a
    /// malicious archive.
    PropertyTagSizeMismatch {
        /// Expected cursor position (`value_start + tag.size`).
        expected_end: u64,
        /// Actual cursor position after the value read.
        actual_pos: u64,
    },

    /// The property iteration depth exceeded `MAX_PROPERTY_DEPTH`.
    /// Guards against stack overflows from adversarially nested
    /// struct properties (Phase 2c+). Reported even though Phase 2b
    /// itself never recurses, so the variant exists before 2c lands.
    PropertyDepthExceeded {
        /// Depth at which the limit was hit.
        depth: usize,
        /// The cap (`MAX_PROPERTY_DEPTH = 128`).
        limit: usize,
    },

    /// The number of `FPropertyTag` entries in a single export
    /// exceeded `MAX_TAGS_PER_EXPORT`. Guards against a missing
    /// "None" terminator causing an unbounded iteration loop.
    PropertyTagCountExceeded {
        /// The cap (`MAX_TAGS_PER_EXPORT = 65_536`).
        limit: usize,
    },
```

- [ ] **Step 4: Add new Display arms**

Find `impl fmt::Display for AssetParseFault` and add after the `UnexpectedEof` arm. Only four new arms — the negative-size and over-cap cases are dispatched by the existing `Self::NegativeValue { .. }` and `Self::BoundsExceeded { .. }` arms (their Display strings already render `"{field} value {value} is negative"` and the standard bounds-exceeded format; `AssetWireField::PropertyTagSize`'s Display string `"property_tag_size"` slots into both automatically):

```rust
            Self::UnversionedPropertiesUnsupported => f.write_str(
                "unversioned properties (PKG_UnversionedProperties=0x2000) \
                 are not supported in Phase 2b",
            ),
            Self::PropertyTagSizeMismatch { expected_end, actual_pos } => write!(
                f,
                "property tag size mismatch: expected cursor at {expected_end}, \
                 was at {actual_pos}"
            ),
            Self::PropertyDepthExceeded { depth, limit } => {
                write!(f, "property depth {depth} exceeds limit {limit}")
            }
            Self::PropertyTagCountExceeded { limit } => {
                write!(f, "property tag count exceeded limit {limit} (missing None terminator?)")
            }
```

- [ ] **Step 5: Add new `AssetWireField` variants**

Find the end of the `AssetWireField` enum body (just before `impl fmt::Display for AssetWireField`) and add after `CustomVersionValue`:

```rust
    /// `FPropertyTag::Name` — the on-wire (index, number) FName pair
    /// identifying the property.
    PropertyTagName,
    /// `FPropertyTag::Type` — the on-wire type-name FName pair.
    PropertyTagType,
    /// `FPropertyTag::Size` — the serialized value size in bytes.
    PropertyTagSize,
    /// `FPropertyTag::ArrayIndex` — the array element index.
    PropertyTagArrayIndex,
    /// `FPropertyTag::StructName` — the struct type FName
    /// (StructProperty only).
    PropertyTagStructName,
    /// `FPropertyTag::EnumName` — the enum type FName
    /// (ByteProperty / EnumProperty).
    PropertyTagEnumName,
    /// `FPropertyTag::InnerType` — the inner element type FName
    /// (ArrayProperty / SetProperty / MapProperty key).
    PropertyTagInnerType,
    /// `FPropertyTag::ValueType` — the value type FName
    /// (MapProperty value).
    PropertyTagValueType,
    /// `FText::history_type` discriminant byte.
    FTextHistoryType,
    /// Any FText body field (namespace, key, source_string) — used
    /// for `UnexpectedEof` when reading the text body.
    FTextField,
```

- [ ] **Step 6: Add new Display arms for `AssetWireField`**

Find `impl fmt::Display for AssetWireField` and add after `CustomVersionValue`:

```rust
            Self::PropertyTagName => "property_tag_name",
            Self::PropertyTagType => "property_tag_type",
            Self::PropertyTagSize => "property_tag_size",
            Self::PropertyTagArrayIndex => "property_tag_array_index",
            Self::PropertyTagStructName => "property_tag_struct_name",
            Self::PropertyTagEnumName => "property_tag_enum_name",
            Self::PropertyTagInnerType => "property_tag_inner_type",
            Self::PropertyTagValueType => "property_tag_value_type",
            Self::FTextHistoryType => "ftext_history_type",
            Self::FTextField => "ftext_field",
```

- [ ] **Step 7: Add new `AssetAllocationContext` variants**

Find the end of `AssetAllocationContext` enum and add after `ExportPayload`:

```rust
    /// `Vec<Property>` for the decoded property list of one export.
    PropertyList,
    /// `Vec<u8>` for the skipped bytes of an unknown property value.
    UnknownPropertyBytes,
    /// `Vec<u8>` for the skipped bytes of an unknown FText history.
    UnknownFTextBytes,
```

Find `impl fmt::Display for AssetAllocationContext` and add after `ExportPayload`:

```rust
            Self::PropertyList => "property list",
            Self::UnknownPropertyBytes => "unknown property bytes",
            Self::UnknownFTextBytes => "unknown ftext bytes",
```

- [ ] **Step 8: Run the Display-stability tests to confirm they pass**

```bash
cargo test -p paksmith-core --lib error::tests 2>&1 | tail -20
```

Expected: all tests pass including the 6 new `asset_parse_display_*` tests.

- [ ] **Step 9: Run workspace clippy**

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Expected: clean.

- [ ] **Step 10: Commit**

```bash
git add crates/paksmith-core/src/error.rs
git commit -m "$(cat <<'EOF'
feat(error): Phase 2b AssetParseFault variants + AssetWireField + AssetAllocationContext

Four new AssetParseFault variants: UnversionedPropertiesUnsupported,
PropertyTagSizeMismatch, PropertyDepthExceeded, PropertyTagCountExceeded.
Property-tag negative size and over-cap rejections reuse the existing
NegativeValue and BoundsExceeded variants (with field=PropertyTagSize),
matching Phase 2a's convention for NameCount/ImportCount/etc.

Ten new AssetWireField variants for FPropertyTag fields and FText
body fields. Three new AssetAllocationContext variants for property
parsing allocation sites. All Display strings wire-stable, pinned by
six new unit tests (four for the new variants + two cross-checking
the NegativeValue / BoundsExceeded reuse paths with field=PropertyTagSize).

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: Restructure `property_bag.rs` → `asset/property/` submodule

**Files:**

- Create: `crates/paksmith-core/src/asset/property/mod.rs` (placeholder re-exports)
- Create: `crates/paksmith-core/src/asset/property/bag.rs` (moved content)
- Delete: `crates/paksmith-core/src/asset/property_bag.rs` (content migrated)
- Modify: `crates/paksmith-core/src/asset/mod.rs` — swap `pub mod property_bag` for `pub mod property`

**Why:** The ROADMAP specifies `asset/property/` as the module home. Making this a pure structural rename now means Tasks 3–7 just add new files to the directory without touching mod.rs again. **Zero behavior change in this task — all existing tests must still pass byte-for-byte.** Eq removal, custom Debug elision, struct field signatures, dead-code allows, and visibility (`pub(crate)`) are all preserved here; behavior-changing edits are deferred to Tasks 3–8 where they're structurally required (Eq drops in Task 7 because `Tree { properties: Vec<Property> }` is non-Eq; `MAX_PROPERTY_DEPTH` becomes referenced from the iterator in Task 6 — same `pub(crate)` access works in-crate).

- [ ] **Step 1: Move the file**

```bash
git mv crates/paksmith-core/src/asset/property_bag.rs \
       crates/paksmith-core/src/asset/property/bag.rs
```

This is a pure path move. The file content is unchanged. `bag.rs` now contains the verbatim content from `property_bag.rs` (current state at the start of Phase 2b: `pub(crate) const MAX_PROPERTY_DEPTH = 128` with `#[allow(dead_code, reason = ...)]`, the `#[derive(Clone, PartialEq, Eq, Serialize)]` derive, the hand-rolled `impl fmt::Debug` that elides byte content, the `#[serde(serialize_with = "serialize_byte_count")]` field on `Opaque`, the `#[allow(clippy::ptr_arg, reason = "serde's #[serialize_with] requires &Vec<u8> exactly")]` on `serialize_byte_count` with the `&Vec<u8>` first-argument signature, the existing four tests: `opaque_byte_len`, `serialize_renders_byte_count_not_payload`, `max_depth_constant_is_locked`, `debug_elides_byte_content`).

**Do not edit the file content in this task.** Do not derive Debug, do not drop Eq, do not change `pub(crate)` to `pub`, do not change `&Vec<u8>` to `&[u8]`, do not delete the `#[allow]` attributes. Each of these would silently break a pinned test (Eq removal: prevented by Task 7's structurally-required change; Debug derive: trips `debug_elides_byte_content`; `pub` widening: not needed by any in-crate consumer; `&[u8]`: breaks `#[serde(serialize_with)]` which receives `&Vec<u8>` from serde; `#[allow]` removal: trips clippy under `-D warnings`).

- [ ] **Step 2: Create `crates/paksmith-core/src/asset/property/mod.rs`**

```rust
//! Tagged property system for UAsset export bodies.
//!
//! Phase 2a shipped [`PropertyBag::Opaque`]; Phase 2b adds
//! [`PropertyBag::Tree`] via the tagged-property iterator
//! [`read_properties`].
//!
//! Sub-modules:
//! - [`bag`] — `PropertyBag` enum (migrated from `property_bag`)
//! - [`tag`] — `PropertyTag` wire reader (Phase 2b)
//! - [`primitives`] — `Property`, `PropertyValue`, primitive readers (Phase 2b)
//! - [`text`] — `FText` + `FTextHistory` (Phase 2b)

pub mod bag;

pub use bag::PropertyBag;
// MAX_PROPERTY_DEPTH stays `pub(crate)` (matching the visibility on the
// existing constant — see bag.rs). Phase 2b's iterator in mod.rs
// references it as `bag::MAX_PROPERTY_DEPTH`; no re-export is needed,
// and re-exporting a `pub(crate)` item as `pub` would be a privacy error.
```

- [ ] **Step 3: Update `crates/paksmith-core/src/asset/mod.rs`**

Find the line `pub mod property_bag;` and replace with `pub mod property;`.

Find the line `pub use property_bag::PropertyBag;` and replace with `pub use property::PropertyBag;`.

If any other in-crate references resolve through `crate::asset::property_bag::*`, update them to `crate::asset::property::bag::*` or `crate::asset::property::*`. Run `cargo build -p paksmith-core` to surface any stale paths:

```bash
cargo build -p paksmith-core 2>&1 | grep -E "error\[E0432\]|unresolved import" | head -20
```

- [ ] **Step 4: Confirm `git mv` registered correctly**

```bash
git status
```

Expected: `renamed: crates/paksmith-core/src/asset/property_bag.rs -> crates/paksmith-core/src/asset/property/bag.rs` plus a new `crates/paksmith-core/src/asset/property/mod.rs` and a modified `crates/paksmith-core/src/asset/mod.rs`. No deleted+untracked pair — that would mean the rename wasn't tracked and the diff would lose the file's blame history.

- [ ] **Step 5: Run the full test suite**

```bash
cargo test --workspace 2>&1 | tail -20
```

Expected: all tests pass. Zero behavior change.

- [ ] **Step 6: Run workspace clippy**

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Expected: clean.

- [ ] **Step 7: Commit**

`git mv` already staged the rename. Add the new `mod.rs` and the updated `asset/mod.rs`:

```bash
git add crates/paksmith-core/src/asset/property/mod.rs \
        crates/paksmith-core/src/asset/mod.rs
git status  # verify: renamed property_bag.rs -> property/bag.rs, new mod.rs, modified asset/mod.rs
git commit -m "$(cat <<'EOF'
refactor(asset): migrate property_bag.rs → asset/property/ submodule

Pure rename via `git mv property_bag.rs property/bag.rs` + new
property/mod.rs that re-exports PropertyBag and swaps the pub mod
declaration in asset/mod.rs. File content unchanged: Eq derive,
pub(crate) MAX_PROPERTY_DEPTH, hand-rolled Debug elision, &Vec<u8>
serialize_byte_count signature, dead-code + ptr_arg allows all
preserved. Zero behavior change; all four existing bag tests pass
(opaque_byte_len, serialize_renders_byte_count_not_payload,
max_depth_constant_is_locked, debug_elides_byte_content).

Phase 2b will add tag.rs, primitives.rs, and text.rs to this module
(Tasks 3–5), and Task 7 will add the Tree variant + drop Eq.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: `PropertyTag` struct + `read_tag` + `resolve_fname`

**Files:**

- Create: `crates/paksmith-core/src/asset/property/tag.rs`
- Modify: `crates/paksmith-core/src/asset/property/mod.rs` — add `pub mod tag;`

**Why:** `read_tag` is the innermost hot path in the property iterator. Building and testing it standalone (with hand-crafted byte slices) before the iterator is written avoids multi-layer debugging.

- [ ] **Step 1: Write failing tests for `read_tag`**

Create `crates/paksmith-core/src/asset/property/tag.rs` with the test module only:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use crate::asset::{
        name_table::{FName, NameTable},
        version::AssetVersion,
        import_table::ImportTable,
        export_table::ExportTable,
        AssetContext,
    };
    use std::sync::Arc;

    fn make_ctx(names: &[&str]) -> AssetContext {
        let table = NameTable {
            names: names.iter().map(|n| FName::new(n)).collect(),
        };
        AssetContext {
            names: Arc::new(table),
            imports: Arc::new(ImportTable::default()),
            exports: Arc::new(ExportTable::default()),
            version: AssetVersion::default(),
        }
    }

    fn write_fname(buf: &mut Vec<u8>, index: i32, number: i32) {
        buf.extend_from_slice(&index.to_le_bytes());
        buf.extend_from_slice(&number.to_le_bytes());
    }

    #[test]
    fn none_terminator_returns_none() {
        let ctx = make_ctx(&["None"]);
        // Name FName(index=0, number=0)
        let buf: Vec<u8> = vec![0,0,0,0, 0,0,0,0];
        let tag = read_tag(&mut Cursor::new(&buf), &ctx, "x.uasset").unwrap();
        assert!(tag.is_none());
    }

    #[test]
    fn bool_property_tag_decoded() {
        // names: 0=None, 1=bEnabled, 2=BoolProperty
        let ctx = make_ctx(&["None", "bEnabled", "BoolProperty"]);
        let mut buf = Vec::new();
        write_fname(&mut buf, 1, 0);  // Name: "bEnabled"
        write_fname(&mut buf, 2, 0);  // Type: "BoolProperty"
        buf.extend_from_slice(&0i32.to_le_bytes()); // Size: 0
        buf.extend_from_slice(&0i32.to_le_bytes()); // ArrayIndex: 0
        buf.push(1u8);                // boolVal: true
        buf.push(0u8);                // HasPropertyGuid: 0
        let tag = read_tag(&mut Cursor::new(&buf), &ctx, "x.uasset")
            .unwrap()
            .unwrap();
        assert_eq!(tag.name, "bEnabled");
        assert_eq!(tag.type_name, "BoolProperty");
        assert_eq!(tag.size, 0);
        assert!(tag.bool_val);
        assert!(tag.guid.is_none());
    }

    #[test]
    fn int_property_tag_decoded() {
        // names: 0=None, 1=MaxHP, 2=IntProperty
        let ctx = make_ctx(&["None", "MaxHP", "IntProperty"]);
        let mut buf = Vec::new();
        write_fname(&mut buf, 1, 0);  // Name
        write_fname(&mut buf, 2, 0);  // Type
        buf.extend_from_slice(&4i32.to_le_bytes()); // Size: 4
        buf.extend_from_slice(&0i32.to_le_bytes()); // ArrayIndex: 0
        buf.push(0u8);                // HasPropertyGuid: 0
        let tag = read_tag(&mut Cursor::new(&buf), &ctx, "x.uasset")
            .unwrap()
            .unwrap();
        assert_eq!(tag.name, "MaxHP");
        assert_eq!(tag.type_name, "IntProperty");
        assert_eq!(tag.size, 4);
    }

    #[test]
    fn negative_size_is_rejected() {
        let ctx = make_ctx(&["None", "Foo", "IntProperty"]);
        let mut buf = Vec::new();
        write_fname(&mut buf, 1, 0);
        write_fname(&mut buf, 2, 0);
        buf.extend_from_slice(&(-1i32).to_le_bytes()); // Size: -1
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.push(0u8);
        let err = read_tag(&mut Cursor::new(&buf), &ctx, "x.uasset").unwrap_err();
        // Reuses the existing AssetParseFault::NegativeValue variant
        // (same pattern Phase 2a uses for NameCount/ImportCount/etc.);
        // see Task 1's variant-reuse note.
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::NegativeValue {
                    field: AssetWireField::PropertyTagSize,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn size_exceeding_cap_is_rejected() {
        let ctx = make_ctx(&["None", "Foo", "StrProperty"]);
        let mut buf = Vec::new();
        write_fname(&mut buf, 1, 0);
        write_fname(&mut buf, 2, 0);
        buf.extend_from_slice(&(MAX_PROPERTY_TAG_SIZE + 1).to_le_bytes()); // Size > cap
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.push(0u8);
        let err = read_tag(&mut Cursor::new(&buf), &ctx, "x.uasset").unwrap_err();
        // Reuses the existing AssetParseFault::BoundsExceeded variant
        // (same pattern Phase 2a uses for TotalHeaderSize/NameOffset).
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::BoundsExceeded {
                    field: AssetWireField::PropertyTagSize,
                    unit: BoundsUnit::Bytes,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn name_suffix_number_appended() {
        // FName (index=1, number=2) → "Foo_1" (number 2 means _1 in UE convention)
        let ctx = make_ctx(&["None", "Foo", "IntProperty"]);
        let mut buf = Vec::new();
        write_fname(&mut buf, 1, 2);  // Name: "Foo_1"
        write_fname(&mut buf, 2, 0);
        buf.extend_from_slice(&4i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.push(0u8);
        let tag = read_tag(&mut Cursor::new(&buf), &ctx, "x.uasset")
            .unwrap()
            .unwrap();
        assert_eq!(tag.name, "Foo_1");
    }

    #[test]
    fn struct_property_tag_reads_struct_name_and_guid() {
        // names: 0=None, 1=Transform, 2=StructProperty, 3=Transform(struct type)
        let ctx = make_ctx(&["None", "Transform", "StructProperty"]);
        let mut buf = Vec::new();
        write_fname(&mut buf, 1, 0); // Name
        write_fname(&mut buf, 2, 0); // Type: StructProperty
        buf.extend_from_slice(&60i32.to_le_bytes()); // Size
        buf.extend_from_slice(&0i32.to_le_bytes()); // ArrayIndex
        write_fname(&mut buf, 1, 0); // StructName: "Transform"
        buf.extend_from_slice(&[0xAB; 16]); // StructGuid
        buf.push(0u8); // HasPropertyGuid: 0
        let tag = read_tag(&mut Cursor::new(&buf), &ctx, "x.uasset")
            .unwrap()
            .unwrap();
        assert_eq!(tag.struct_name, "Transform");
        assert_eq!(tag.struct_guid, [0xABu8; 16]);
    }

    #[test]
    fn property_guid_decoded_when_present() {
        let ctx = make_ctx(&["None", "Count", "IntProperty"]);
        let mut buf = Vec::new();
        write_fname(&mut buf, 1, 0);
        write_fname(&mut buf, 2, 0);
        buf.extend_from_slice(&4i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.push(1u8); // HasPropertyGuid: 1
        buf.extend_from_slice(&[0x11; 16]); // PropertyGuid
        let tag = read_tag(&mut Cursor::new(&buf), &ctx, "x.uasset")
            .unwrap()
            .unwrap();
        assert_eq!(tag.guid, Some([0x11u8; 16]));
    }
}
```

- [ ] **Step 2: Run tests to confirm compile failure**

```bash
cargo test -p paksmith-core --lib asset::property::tag::tests 2>&1 | tail -10
```

Expected: compile error — `read_tag`, `MAX_PROPERTY_TAG_SIZE`, etc. not found.

- [ ] **Step 3: Implement `tag.rs`**

Replace the file with the full implementation:

````rust
//! `FPropertyTag` wire reader.
//!
//! Phase 2b layout (UE 4.21+, `FileVersionUE4 ≥ 504`):
//! ```text
//! Name:           FName (i32 index, i32 number)
//!   → None terminator when index==0 && number==0
//! Type:           FName
//! Size:           i32   (payload bytes; 0 for BoolProperty)
//! ArrayIndex:     i32
//! [type extras]   (BoolProperty: u8 boolVal;
//!                  StructProperty: FName struct_name + [u8; 16] struct_guid;
//!                  ByteProperty|EnumProperty: FName enum_name;
//!                  ArrayProperty|SetProperty: FName inner_type;
//!                  MapProperty: FName inner_type + FName value_type)
//! HasPropertyGuid: u8
//! [PropertyGuid]: [u8; 16] if HasPropertyGuid != 0
//! ```
//! VER_UE4_STRUCT_GUID_IN_PROPERTY_TAG (441) and
//! VER_UE4_PROPERTY_GUID_IN_PROPERTY_TAG (503) are both below
//! Phase 2a's floor of 504, so both are always present.

use std::io::Read;
use byteorder::{LittleEndian, ReadBytesExt};

use crate::asset::AssetContext;
use crate::error::{AssetParseFault, AssetWireField, PaksmithError};

/// Maximum allowed size for a single property value payload.
/// Prevents a single `Unknown`-type skip from allocating > 16 MiB.
pub const MAX_PROPERTY_TAG_SIZE: i32 = 16 * 1024 * 1024;

/// Decoded `FPropertyTag` header.
///
/// All type-specific fields (struct_name, enum_name, etc.) are
/// populated during tag reading regardless of whether the type is
/// handled — Phase 2c's container readers rely on `inner_type`
/// already being resolved.
#[derive(Debug, Clone)]
pub struct PropertyTag {
    /// Resolved property name (FName base + optional `_N` suffix).
    pub name: String,
    /// Resolved type name (e.g. `"BoolProperty"`, `"IntProperty"`).
    pub type_name: String,
    /// Serialized value size in bytes (0 for BoolProperty).
    pub size: i32,
    /// Array element index (0 for non-array properties).
    pub array_index: i32,
    /// Boolean value for BoolProperty; `false` otherwise.
    pub bool_val: bool,
    /// Struct type name for StructProperty; empty string otherwise.
    pub struct_name: String,
    /// Struct type GUID for StructProperty; zeroed otherwise.
    pub struct_guid: [u8; 16],
    /// Enum type name for ByteProperty / EnumProperty; empty otherwise.
    pub enum_name: String,
    /// Inner element type for ArrayProperty / SetProperty / MapProperty key.
    pub inner_type: String,
    /// Value type for MapProperty; empty otherwise.
    pub value_type: String,
    /// Optional per-property GUID (`HasPropertyGuid` byte was non-zero).
    pub guid: Option<[u8; 16]>,
}

/// Resolve a wire-format `(index, number)` FName pair to a `String`.
///
/// `number <= 0` → no suffix; `number > 0` → `"Base_N"` where N = number − 1.
pub fn resolve_fname(
    index: i32,
    number: i32,
    ctx: &AssetContext,
    asset_path: &str,
    field: AssetWireField,
) -> crate::Result<String> {
    if index < 0 {
        return Err(PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::PackageIndexUnderflow { field },
        });
    }
    let idx = index as u32;
    let fname = ctx.names.get(idx).ok_or_else(|| PaksmithError::AssetParse {
        asset_path: asset_path.to_string(),
        fault: AssetParseFault::PackageIndexOob {
            field,
            index: idx,
            table_size: ctx.names.names.len() as u32,
        },
    })?;
    if number <= 0 {
        Ok(fname.as_str().to_string())
    } else {
        Ok(format!("{}_{}", fname.as_str(), number - 1))
    }
}

/// Read one `FPropertyTag` from `reader`, resolving FNames via `ctx`.
///
/// Returns `None` when the "None" terminator is reached
/// (name_index == 0 && name_number == 0, or resolved name == "None").
///
/// # Errors
/// - [`AssetParseFault::NegativeValue`] with `field: AssetWireField::PropertyTagSize`
///   if Size < 0. Reuses the shared signed-negative variant Phase 2a uses for
///   `NameCount`/`ImportCount`/`ExportSerialSize` — see Decision-#? on
///   variant reuse.
/// - [`AssetParseFault::BoundsExceeded`] with `field: AssetWireField::PropertyTagSize`,
///   `unit: BoundsUnit::Bytes` if Size > [`MAX_PROPERTY_TAG_SIZE`]. Reuses the
///   shared cap-overflow variant Phase 2a uses for `TotalHeaderSize`/`NameOffset`.
/// - [`AssetParseFault::PackageIndexUnderflow`] / [`AssetParseFault::PackageIndexOob`]
///   for out-of-range FName indexes.
/// - [`AssetParseFault::UnexpectedEof`] on short reads.
///
/// The `Read`-only bound is intentional — `read_tag` does sequential
/// `read_*` calls only; no `stream_position`/`seek`. The caller
/// (`read_properties` in mod.rs) is `Read + Seek` and bubbles the
/// stronger bound up to where it's used.
pub fn read_tag<R: Read>(
    reader: &mut R,
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<Option<PropertyTag>> {
    let eof =
        |field: AssetWireField| PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::UnexpectedEof { field },
        };

    let name_index = reader
        .read_i32::<LittleEndian>()
        .map_err(|_| eof(AssetWireField::PropertyTagName))?;
    let name_number = reader
        .read_i32::<LittleEndian>()
        .map_err(|_| eof(AssetWireField::PropertyTagName))?;

    // "None" terminator: the name table's first entry is always "None";
    // index==0 && number==0 is the canonical terminator encoding.
    if name_index == 0 && name_number == 0 {
        return Ok(None);
    }

    let name =
        resolve_fname(name_index, name_number, ctx, asset_path, AssetWireField::PropertyTagName)?;
    // Defensive fallback for exotic encoders that spell "None" differently.
    if name == "None" {
        return Ok(None);
    }

    let type_index = reader
        .read_i32::<LittleEndian>()
        .map_err(|_| eof(AssetWireField::PropertyTagType))?;
    let type_number = reader
        .read_i32::<LittleEndian>()
        .map_err(|_| eof(AssetWireField::PropertyTagType))?;
    let type_name =
        resolve_fname(type_index, type_number, ctx, asset_path, AssetWireField::PropertyTagType)?;

    let size = reader
        .read_i32::<LittleEndian>()
        .map_err(|_| eof(AssetWireField::PropertyTagSize))?;
    // Reuse existing NegativeValue / BoundsExceeded variants (issue
    // #241 I3); the value widens to i64 to match the shared variant's
    // domain.
    if size < 0 {
        return Err(PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::NegativeValue {
                field: AssetWireField::PropertyTagSize,
                value: size as i64,
            },
        });
    }
    if size > MAX_PROPERTY_TAG_SIZE {
        return Err(PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::BoundsExceeded {
                field: AssetWireField::PropertyTagSize,
                value: size as u64,
                limit: MAX_PROPERTY_TAG_SIZE as u64,
                unit: crate::error::BoundsUnit::Bytes,
            },
        });
    }

    let array_index = reader
        .read_i32::<LittleEndian>()
        .map_err(|_| eof(AssetWireField::PropertyTagArrayIndex))?;

    // Type-specific extras.
    let mut bool_val = false;
    let mut struct_name = String::new();
    let mut struct_guid = [0u8; 16];
    let mut enum_name = String::new();
    let mut inner_type = String::new();
    let mut value_type = String::new();

    match type_name.as_str() {
        "BoolProperty" => {
            let bv = reader.read_u8().map_err(|_| eof(AssetWireField::PropertyTagSize))?;
            bool_val = bv != 0;
        }
        "StructProperty" => {
            let sn_i = reader
                .read_i32::<LittleEndian>()
                .map_err(|_| eof(AssetWireField::PropertyTagStructName))?;
            let sn_n = reader
                .read_i32::<LittleEndian>()
                .map_err(|_| eof(AssetWireField::PropertyTagStructName))?;
            struct_name = resolve_fname(
                sn_i,
                sn_n,
                ctx,
                asset_path,
                AssetWireField::PropertyTagStructName,
            )?;
            reader
                .read_exact(&mut struct_guid)
                .map_err(|_| eof(AssetWireField::PropertyTagStructName))?;
        }
        "ByteProperty" | "EnumProperty" => {
            let en_i = reader
                .read_i32::<LittleEndian>()
                .map_err(|_| eof(AssetWireField::PropertyTagEnumName))?;
            let en_n = reader
                .read_i32::<LittleEndian>()
                .map_err(|_| eof(AssetWireField::PropertyTagEnumName))?;
            enum_name = resolve_fname(
                en_i,
                en_n,
                ctx,
                asset_path,
                AssetWireField::PropertyTagEnumName,
            )?;
        }
        "ArrayProperty" | "SetProperty" => {
            let it_i = reader
                .read_i32::<LittleEndian>()
                .map_err(|_| eof(AssetWireField::PropertyTagInnerType))?;
            let it_n = reader
                .read_i32::<LittleEndian>()
                .map_err(|_| eof(AssetWireField::PropertyTagInnerType))?;
            inner_type = resolve_fname(
                it_i,
                it_n,
                ctx,
                asset_path,
                AssetWireField::PropertyTagInnerType,
            )?;
        }
        "MapProperty" => {
            let it_i = reader
                .read_i32::<LittleEndian>()
                .map_err(|_| eof(AssetWireField::PropertyTagInnerType))?;
            let it_n = reader
                .read_i32::<LittleEndian>()
                .map_err(|_| eof(AssetWireField::PropertyTagInnerType))?;
            inner_type = resolve_fname(
                it_i,
                it_n,
                ctx,
                asset_path,
                AssetWireField::PropertyTagInnerType,
            )?;
            let vt_i = reader
                .read_i32::<LittleEndian>()
                .map_err(|_| eof(AssetWireField::PropertyTagValueType))?;
            let vt_n = reader
                .read_i32::<LittleEndian>()
                .map_err(|_| eof(AssetWireField::PropertyTagValueType))?;
            value_type = resolve_fname(
                vt_i,
                vt_n,
                ctx,
                asset_path,
                AssetWireField::PropertyTagValueType,
            )?;
        }
        _ => {} // No type-specific extras; value follows directly.
    }

    // HasPropertyGuid (always present, FileVersionUE4 >= 503 < 504 floor).
    let has_guid = reader.read_u8().map_err(|_| eof(AssetWireField::PropertyTagName))?;
    let guid = if has_guid != 0 {
        let mut g = [0u8; 16];
        reader
            .read_exact(&mut g)
            .map_err(|_| eof(AssetWireField::PropertyTagName))?;
        Some(g)
    } else {
        None
    };

    Ok(Some(PropertyTag {
        name,
        type_name,
        size,
        array_index,
        bool_val,
        struct_name,
        struct_guid,
        enum_name,
        inner_type,
        value_type,
        guid,
    }))
}

#[cfg(test)]
mod tests {
    // (tests already written above — paste them here)
    use super::*;
    // ... (same test content as Step 1)
}
````

- [ ] **Step 4: Add `pub mod tag;` to `property/mod.rs`**

```rust
pub mod bag;
pub mod tag;

pub use bag::{PropertyBag, MAX_PROPERTY_DEPTH};
pub use tag::{read_tag, resolve_fname, PropertyTag, MAX_PROPERTY_TAG_SIZE};
```

- [ ] **Step 5: Run tests to confirm they pass**

```bash
cargo test -p paksmith-core --lib asset::property::tag::tests 2>&1 | tail -20
```

Expected: 8 tests pass.

- [ ] **Step 6: Run workspace clippy**

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

- [ ] **Step 7: Commit**

```bash
git add crates/paksmith-core/src/asset/property/tag.rs \
        crates/paksmith-core/src/asset/property/mod.rs
git commit -m "$(cat <<'EOF'
feat(asset): PropertyTag + read_tag + resolve_fname (Phase 2b)

PropertyTag struct carries all FPropertyTag wire fields including
type-specific extras (struct_name/guid, enum_name, inner_type,
value_type). resolve_fname resolves (index, number) pairs from the
name table with field-tagged errors. Eight unit tests covering None
terminator, Bool/Int tags, negative/over-cap size rejection, name
suffix encoding, StructProperty guid, and optional PropertyGuid.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: `Property`, `PropertyValue`, and primitive readers

**Files:**

- Create: `crates/paksmith-core/src/asset/property/primitives.rs`
- Modify: `crates/paksmith-core/src/asset/property/mod.rs` — add `pub mod primitives;`

**Why:** `Property` and `PropertyValue` are the output types of the iterator. Defining them with their serde shapes before writing `read_properties` means the iterator has a stable output API. Primitive readers (`read_primitive_value`) are tested in isolation per type with hand-crafted byte slices.

**FString handling:** `read_primitive_value` (StrProperty arm) and `read_ftext` (Task 5) both call `crate::asset::fstring::read_asset_fstring(reader, asset_path)` — the asset-side wrapper at `crates/paksmith-core/src/asset/fstring.rs:33`. The wrapper accepts `len == 0` as `""` (CUE4Parse semantics; pak-side `read_fstring` rejects `len == 0` per issue #104) and re-categorizes pak-side `IndexParseFault::FStringMalformed` as `AssetParseFault::FStringMalformed` with `asset_path` context. **Do not** use `crate::container::pak::index::read_fstring` directly from property code — UE writes empty FStrings (StrProperty `""`, FText `namespace=""` / `key=""`) as `len=0` routinely, and the pak-side reader rejects them. The wrapper already maps embedded-NUL faults (issue #239 / PR #239) through to `AssetParseFault::FStringMalformed { kind: EmbeddedNul }`, so no extra shim is needed.

- [ ] **Step 1: Write failing tests for primitive readers**

Create `crates/paksmith-core/src/asset/property/primitives.rs` with tests only:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use crate::asset::{
        name_table::{FName, NameTable},
        version::AssetVersion,
        import_table::ImportTable,
        export_table::ExportTable,
        AssetContext,
    };
    use crate::asset::property::tag::PropertyTag;
    use std::sync::Arc;

    fn make_ctx(names: &[&str]) -> AssetContext {
        let table = NameTable {
            names: names.iter().map(|n| FName::new(n)).collect(),
        };
        AssetContext {
            names: Arc::new(table),
            imports: Arc::new(ImportTable::default()),
            exports: Arc::new(ExportTable::default()),
            version: AssetVersion::default(),
        }
    }

    fn make_tag(type_name: &str, size: i32) -> PropertyTag {
        PropertyTag {
            name: "Prop".to_string(),
            type_name: type_name.to_string(),
            size,
            array_index: 0,
            bool_val: false,
            struct_name: String::new(),
            struct_guid: [0u8; 16],
            enum_name: String::new(),
            inner_type: String::new(),
            value_type: String::new(),
            guid: None,
        }
    }

    fn make_bool_tag(val: bool) -> PropertyTag {
        let mut t = make_tag("BoolProperty", 0);
        t.bool_val = val;
        t
    }

    fn make_byte_enum_tag(enum_name: &str) -> PropertyTag {
        let mut t = make_tag("ByteProperty", 8); // FName = 8 bytes
        t.enum_name = enum_name.to_string();
        t
    }

    #[test]
    fn bool_true() {
        let tag = make_bool_tag(true);
        let ctx = make_ctx(&["None"]);
        let val = read_primitive_value(&tag, &mut Cursor::new(&[]), &ctx, "x").unwrap().unwrap();
        assert_eq!(val, PropertyValue::Bool(true));
    }

    #[test]
    fn bool_false() {
        let tag = make_bool_tag(false);
        let ctx = make_ctx(&["None"]);
        let val = read_primitive_value(&tag, &mut Cursor::new(&[]), &ctx, "x").unwrap().unwrap();
        assert_eq!(val, PropertyValue::Bool(false));
    }

    #[test]
    fn byte_raw() {
        let tag = make_tag("ByteProperty", 1); // enum_name == "" (None)
        let ctx = make_ctx(&["None"]);
        let val = read_primitive_value(&tag, &mut Cursor::new(&[42u8]), &ctx, "x").unwrap().unwrap();
        assert_eq!(val, PropertyValue::Byte(42));
    }

    #[test]
    fn byte_as_enum() {
        // ByteProperty with enum_name set → reads FName (8 bytes) as Enum variant
        let tag = make_byte_enum_tag("EMyEnum");
        // names: 0=None, 1=EMyEnum__Val
        let ctx = make_ctx(&["None", "EMyEnum__Val"]);
        let mut buf = Vec::new();
        buf.extend_from_slice(&1i32.to_le_bytes()); // name index 1
        buf.extend_from_slice(&0i32.to_le_bytes()); // number 0
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf), &ctx, "x").unwrap().unwrap();
        assert_eq!(
            val,
            PropertyValue::Enum {
                type_name: "EMyEnum".to_string(),
                value: "EMyEnum__Val".to_string(),
            }
        );
    }

    #[test]
    fn int8_value() {
        let tag = make_tag("Int8Property", 1);
        let ctx = make_ctx(&["None"]);
        let val = read_primitive_value(&tag, &mut Cursor::new(&[0xFEu8]), &ctx, "x").unwrap().unwrap();
        assert_eq!(val, PropertyValue::Int8(-2i8));
    }

    #[test]
    fn int16_value() {
        let tag = make_tag("Int16Property", 2);
        let ctx = make_ctx(&["None"]);
        let buf = (-1000i16).to_le_bytes();
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf), &ctx, "x").unwrap().unwrap();
        assert_eq!(val, PropertyValue::Int16(-1000));
    }

    #[test]
    fn int_value() {
        let tag = make_tag("IntProperty", 4);
        let ctx = make_ctx(&["None"]);
        let buf = 42i32.to_le_bytes();
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf), &ctx, "x").unwrap().unwrap();
        assert_eq!(val, PropertyValue::Int(42));
    }

    #[test]
    fn int64_value() {
        let tag = make_tag("Int64Property", 8);
        let ctx = make_ctx(&["None"]);
        let buf = i64::MAX.to_le_bytes();
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf), &ctx, "x").unwrap().unwrap();
        assert_eq!(val, PropertyValue::Int64(i64::MAX));
    }

    #[test]
    fn uint16_value() {
        let tag = make_tag("UInt16Property", 2);
        let ctx = make_ctx(&["None"]);
        let buf = 60_000u16.to_le_bytes();
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf), &ctx, "x").unwrap().unwrap();
        assert_eq!(val, PropertyValue::UInt16(60_000));
    }

    #[test]
    fn uint32_value() {
        let tag = make_tag("UInt32Property", 4);
        let ctx = make_ctx(&["None"]);
        let buf = 0xDEAD_BEEFu32.to_le_bytes();
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf), &ctx, "x").unwrap().unwrap();
        assert_eq!(val, PropertyValue::UInt32(0xDEAD_BEEF));
    }

    #[test]
    fn uint64_value() {
        let tag = make_tag("UInt64Property", 8);
        let ctx = make_ctx(&["None"]);
        let buf = u64::MAX.to_le_bytes();
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf), &ctx, "x").unwrap().unwrap();
        assert_eq!(val, PropertyValue::UInt64(u64::MAX));
    }

    #[test]
    fn float_value() {
        let tag = make_tag("FloatProperty", 4);
        let ctx = make_ctx(&["None"]);
        let buf = 1500.0f32.to_le_bytes();
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf), &ctx, "x").unwrap().unwrap();
        assert_eq!(val, PropertyValue::Float(1500.0));
    }

    #[test]
    fn double_value() {
        let tag = make_tag("DoubleProperty", 8);
        let ctx = make_ctx(&["None"]);
        let buf = 3.14f64.to_le_bytes();
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf), &ctx, "x").unwrap().unwrap();
        assert_eq!(val, PropertyValue::Double(3.14));
    }

    #[test]
    fn str_value() {
        let tag = make_tag("StrProperty", 10); // 4 (len) + 5 (bytes) + 1 (null)
        let ctx = make_ctx(&["None"]);
        let mut buf = Vec::new();
        buf.extend_from_slice(&6i32.to_le_bytes()); // len including null
        buf.extend_from_slice(b"Hello\0");
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf), &ctx, "x").unwrap().unwrap();
        assert_eq!(val, PropertyValue::Str("Hello".to_string()));
    }

    #[test]
    fn name_value() {
        // NameProperty → FName (index, number) resolved to String
        let tag = make_tag("NameProperty", 8);
        let ctx = make_ctx(&["None", "MyName"]);
        let mut buf = Vec::new();
        buf.extend_from_slice(&1i32.to_le_bytes()); // index 1 = "MyName"
        buf.extend_from_slice(&0i32.to_le_bytes()); // number 0
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf), &ctx, "x").unwrap().unwrap();
        assert_eq!(val, PropertyValue::Name("MyName".to_string()));
    }

    #[test]
    fn enum_property_value() {
        // EnumProperty → FName (index, number) resolved as Enum
        let mut tag = make_tag("EnumProperty", 8);
        tag.enum_name = "EDirection".to_string();
        let ctx = make_ctx(&["None", "EDirection__Forward"]);
        let mut buf = Vec::new();
        buf.extend_from_slice(&1i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf), &ctx, "x").unwrap().unwrap();
        assert_eq!(
            val,
            PropertyValue::Enum {
                type_name: "EDirection".to_string(),
                value: "EDirection__Forward".to_string(),
            }
        );
    }

    #[test]
    fn unknown_type_returns_none() {
        // ArrayProperty and other unknowns return None (caller handles skip)
        let tag = make_tag("ArrayProperty", 42);
        let ctx = make_ctx(&["None"]);
        let val = read_primitive_value(&tag, &mut Cursor::new(&[]), &ctx, "x").unwrap();
        assert!(val.is_none());
    }
}
```

- [ ] **Step 2: Run tests to confirm compile failure**

```bash
cargo test -p paksmith-core --lib asset::property::primitives::tests 2>&1 | tail -10
```

Expected: compile error — `Property`, `PropertyValue`, `read_primitive_value` not found.

- [ ] **Step 3: Implement `primitives.rs`**

```rust
//! `Property` and `PropertyValue` types + primitive property readers.
//!
//! `read_primitive_value` dispatches by `tag.type_name` and reads
//! the value payload from the stream. Returns `None` for unrecognised
//! types (Array/Map/Set/Struct/SoftObjectPath/etc.) — the caller
//! is responsible for the `MAX_PROPERTY_TAG_SIZE`-bounded skip and
//! constructing `PropertyValue::Unknown`.

use std::io::{Read, Seek};

use byteorder::{LittleEndian, ReadBytesExt};
use serde::Serialize;

use crate::asset::AssetContext;
use crate::asset::fstring::read_asset_fstring;
use crate::error::{AssetParseFault, AssetWireField, PaksmithError};

use super::tag::{resolve_fname, PropertyTag};
use super::text::{read_ftext, FText};

/// One decoded property entry in an export's property stream.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Property {
    /// Resolved property name.
    pub name: String,
    /// Array element index (0 for non-array).
    pub array_index: i32,
    /// Optional per-property GUID from the tag header.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guid: Option<[u8; 16]>,
    /// The decoded property value.
    pub value: PropertyValue,
}

/// Decoded property value.
///
/// `#[non_exhaustive]` — Phase 2c will add Array/Map/Set/Struct
/// variants; Phase 2d will add SoftObjectPath/ObjectReference.
/// `Unknown` is the catch-all for types Phase 2b does not decode;
/// it carries `skipped_bytes` (the count) rather than the raw bytes
/// so JSON output stays compact.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[non_exhaustive]
pub enum PropertyValue {
    Bool(bool),
    Byte(u8),
    Int8(i8),
    Int16(i16),
    Int(i32),
    Int64(i64),
    UInt16(u16),
    UInt32(u32),
    UInt64(u64),
    Float(f32),
    Double(f64),
    Str(String),
    /// FName resolved to a String (no FName → NameTable dependency at
    /// serialization time).
    Name(String),
    /// Enum value: `type_name` from `tag.enum_name`, `value` resolved
    /// from the payload FName. Used by both `ByteProperty` (enum
    /// variant) and `EnumProperty`.
    Enum { type_name: String, value: String },
    Text(FText),
    /// Unknown or container type, value skipped via `tag.size`.
    Unknown {
        /// Resolved type name string (e.g. `"ArrayProperty"`).
        type_name: String,
        /// Number of bytes skipped (not the raw bytes).
        skipped_bytes: usize,
    },
}

/// Read a primitive property value for `tag`, consuming exactly `tag.size` bytes.
///
/// Returns `None` for types that Phase 2b does not handle (container
/// types, SoftObjectPath, ObjectReference, etc.) — the caller must
/// perform the skip and build `PropertyValue::Unknown`.
///
/// For `BoolProperty`, no bytes are consumed (value is in tag header).
///
/// The `Seek` bound is required by the `TextProperty` arm — `read_ftext`
/// uses `stream_position()` to compute remaining bytes for unknown
/// history-type skips (see `text.rs`). The caller in `read_properties`
/// is already `Read + Seek`, so the contagious widening is free.
///
/// # Errors
/// - [`PaksmithError::Io`] / [`AssetParseFault::UnexpectedEof`] on short reads.
/// - [`AssetParseFault::FStringMalformed`] for malformed FStrings.
pub fn read_primitive_value<R: Read + Seek>(
    tag: &PropertyTag,
    reader: &mut R,
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<Option<PropertyValue>> {
    let eof =
        |field: AssetWireField| PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::UnexpectedEof { field },
        };

    let val = match tag.type_name.as_str() {
        "BoolProperty" => PropertyValue::Bool(tag.bool_val),

        "ByteProperty" => {
            if tag.enum_name.is_empty() || tag.enum_name == "None" {
                // Raw byte
                let b = reader.read_u8().map_err(|_| eof(AssetWireField::PropertyTagSize))?;
                PropertyValue::Byte(b)
            } else {
                // Enum encoded as FName (8 bytes)
                let idx = reader
                    .read_i32::<LittleEndian>()
                    .map_err(|_| eof(AssetWireField::PropertyTagEnumName))?;
                let num = reader
                    .read_i32::<LittleEndian>()
                    .map_err(|_| eof(AssetWireField::PropertyTagEnumName))?;
                let value =
                    resolve_fname(idx, num, ctx, asset_path, AssetWireField::PropertyTagEnumName)?;
                PropertyValue::Enum {
                    type_name: tag.enum_name.clone(),
                    value,
                }
            }
        }

        "Int8Property" => {
            let v = reader.read_i8().map_err(|_| eof(AssetWireField::PropertyTagSize))?;
            PropertyValue::Int8(v)
        }

        "Int16Property" => {
            let v = reader
                .read_i16::<LittleEndian>()
                .map_err(|_| eof(AssetWireField::PropertyTagSize))?;
            PropertyValue::Int16(v)
        }

        "IntProperty" => {
            let v = reader
                .read_i32::<LittleEndian>()
                .map_err(|_| eof(AssetWireField::PropertyTagSize))?;
            PropertyValue::Int(v)
        }

        "Int64Property" => {
            let v = reader
                .read_i64::<LittleEndian>()
                .map_err(|_| eof(AssetWireField::PropertyTagSize))?;
            PropertyValue::Int64(v)
        }

        "UInt16Property" => {
            let v = reader
                .read_u16::<LittleEndian>()
                .map_err(|_| eof(AssetWireField::PropertyTagSize))?;
            PropertyValue::UInt16(v)
        }

        "UInt32Property" => {
            let v = reader
                .read_u32::<LittleEndian>()
                .map_err(|_| eof(AssetWireField::PropertyTagSize))?;
            PropertyValue::UInt32(v)
        }

        "UInt64Property" => {
            let v = reader
                .read_u64::<LittleEndian>()
                .map_err(|_| eof(AssetWireField::PropertyTagSize))?;
            PropertyValue::UInt64(v)
        }

        "FloatProperty" => {
            let v = reader
                .read_f32::<LittleEndian>()
                .map_err(|_| eof(AssetWireField::PropertyTagSize))?;
            PropertyValue::Float(v)
        }

        "DoubleProperty" => {
            let v = reader
                .read_f64::<LittleEndian>()
                .map_err(|_| eof(AssetWireField::PropertyTagSize))?;
            PropertyValue::Double(v)
        }

        "StrProperty" => {
            // Asset-side wrapper: accepts len=0 as "" (CUE4Parse semantics)
            // and re-categorizes pak-side FStringMalformed errors as
            // AssetParseFault::FStringMalformed with asset_path context.
            // See `asset/fstring.rs`.
            let s = read_asset_fstring(reader, asset_path)?;
            PropertyValue::Str(s)
        }

        "NameProperty" => {
            let idx = reader
                .read_i32::<LittleEndian>()
                .map_err(|_| eof(AssetWireField::PropertyTagName))?;
            let num = reader
                .read_i32::<LittleEndian>()
                .map_err(|_| eof(AssetWireField::PropertyTagName))?;
            let name = resolve_fname(idx, num, ctx, asset_path, AssetWireField::PropertyTagName)?;
            PropertyValue::Name(name)
        }

        "EnumProperty" => {
            let idx = reader
                .read_i32::<LittleEndian>()
                .map_err(|_| eof(AssetWireField::PropertyTagEnumName))?;
            let num = reader
                .read_i32::<LittleEndian>()
                .map_err(|_| eof(AssetWireField::PropertyTagEnumName))?;
            let value =
                resolve_fname(idx, num, ctx, asset_path, AssetWireField::PropertyTagEnumName)?;
            PropertyValue::Enum {
                type_name: tag.enum_name.clone(),
                value,
            }
        }

        "TextProperty" => {
            let text = read_ftext(reader, ctx, asset_path, tag.size as u64)?;
            PropertyValue::Text(text)
        }

        _ => return Ok(None),
    };

    Ok(Some(val))
}

#[cfg(test)]
mod tests {
    // (paste tests from Step 1 here)
    use super::*;
    use std::io::Cursor;
    use crate::asset::{
        name_table::{FName, NameTable},
        version::AssetVersion,
        import_table::ImportTable,
        export_table::ExportTable,
        AssetContext,
    };
    use crate::asset::property::tag::PropertyTag;
    use std::sync::Arc;

    fn make_ctx(names: &[&str]) -> AssetContext {
        let table = NameTable { names: names.iter().map(|n| FName::new(n)).collect() };
        AssetContext {
            names: Arc::new(table),
            imports: Arc::new(ImportTable::default()),
            exports: Arc::new(ExportTable::default()),
            version: AssetVersion::default(),
        }
    }

    fn make_tag(type_name: &str, size: i32) -> PropertyTag {
        PropertyTag {
            name: "Prop".to_string(),
            type_name: type_name.to_string(),
            size,
            array_index: 0,
            bool_val: false,
            struct_name: String::new(),
            struct_guid: [0u8; 16],
            enum_name: String::new(),
            inner_type: String::new(),
            value_type: String::new(),
            guid: None,
        }
    }

    fn make_bool_tag(val: bool) -> PropertyTag {
        let mut t = make_tag("BoolProperty", 0);
        t.bool_val = val;
        t
    }

    fn make_byte_enum_tag(enum_name: &str) -> PropertyTag {
        let mut t = make_tag("ByteProperty", 8);
        t.enum_name = enum_name.to_string();
        t
    }

    #[test]
    fn bool_true() {
        let tag = make_bool_tag(true);
        let ctx = make_ctx(&["None"]);
        let val = read_primitive_value(&tag, &mut Cursor::new(&[]), &ctx, "x").unwrap().unwrap();
        assert_eq!(val, PropertyValue::Bool(true));
    }

    #[test]
    fn bool_false() {
        let tag = make_bool_tag(false);
        let ctx = make_ctx(&["None"]);
        let val = read_primitive_value(&tag, &mut Cursor::new(&[]), &ctx, "x").unwrap().unwrap();
        assert_eq!(val, PropertyValue::Bool(false));
    }

    #[test]
    fn byte_raw() {
        let tag = make_tag("ByteProperty", 1);
        let ctx = make_ctx(&["None"]);
        let val = read_primitive_value(&tag, &mut Cursor::new(&[42u8]), &ctx, "x").unwrap().unwrap();
        assert_eq!(val, PropertyValue::Byte(42));
    }

    #[test]
    fn byte_as_enum() {
        let tag = make_byte_enum_tag("EMyEnum");
        let ctx = make_ctx(&["None", "EMyEnum__Val"]);
        let mut buf = Vec::new();
        buf.extend_from_slice(&1i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf), &ctx, "x").unwrap().unwrap();
        assert_eq!(
            val,
            PropertyValue::Enum { type_name: "EMyEnum".to_string(), value: "EMyEnum__Val".to_string() }
        );
    }

    #[test]
    fn int8_value() {
        let tag = make_tag("Int8Property", 1);
        let ctx = make_ctx(&["None"]);
        let val = read_primitive_value(&tag, &mut Cursor::new(&[0xFEu8]), &ctx, "x").unwrap().unwrap();
        assert_eq!(val, PropertyValue::Int8(-2i8));
    }

    #[test]
    fn int16_value() {
        let tag = make_tag("Int16Property", 2);
        let ctx = make_ctx(&["None"]);
        let buf = (-1000i16).to_le_bytes();
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf), &ctx, "x").unwrap().unwrap();
        assert_eq!(val, PropertyValue::Int16(-1000));
    }

    #[test]
    fn int_value() {
        let tag = make_tag("IntProperty", 4);
        let ctx = make_ctx(&["None"]);
        let buf = 42i32.to_le_bytes();
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf), &ctx, "x").unwrap().unwrap();
        assert_eq!(val, PropertyValue::Int(42));
    }

    #[test]
    fn int64_value() {
        let tag = make_tag("Int64Property", 8);
        let ctx = make_ctx(&["None"]);
        let buf = i64::MAX.to_le_bytes();
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf), &ctx, "x").unwrap().unwrap();
        assert_eq!(val, PropertyValue::Int64(i64::MAX));
    }

    #[test]
    fn uint16_value() {
        let tag = make_tag("UInt16Property", 2);
        let ctx = make_ctx(&["None"]);
        let buf = 60_000u16.to_le_bytes();
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf), &ctx, "x").unwrap().unwrap();
        assert_eq!(val, PropertyValue::UInt16(60_000));
    }

    #[test]
    fn uint32_value() {
        let tag = make_tag("UInt32Property", 4);
        let ctx = make_ctx(&["None"]);
        let buf = 0xDEAD_BEEFu32.to_le_bytes();
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf), &ctx, "x").unwrap().unwrap();
        assert_eq!(val, PropertyValue::UInt32(0xDEAD_BEEF));
    }

    #[test]
    fn uint64_value() {
        let tag = make_tag("UInt64Property", 8);
        let ctx = make_ctx(&["None"]);
        let buf = u64::MAX.to_le_bytes();
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf), &ctx, "x").unwrap().unwrap();
        assert_eq!(val, PropertyValue::UInt64(u64::MAX));
    }

    #[test]
    fn float_value() {
        let tag = make_tag("FloatProperty", 4);
        let ctx = make_ctx(&["None"]);
        let buf = 1500.0f32.to_le_bytes();
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf), &ctx, "x").unwrap().unwrap();
        assert_eq!(val, PropertyValue::Float(1500.0));
    }

    #[test]
    fn double_value() {
        let tag = make_tag("DoubleProperty", 8);
        let ctx = make_ctx(&["None"]);
        let buf = 3.14f64.to_le_bytes();
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf), &ctx, "x").unwrap().unwrap();
        assert_eq!(val, PropertyValue::Double(3.14));
    }

    #[test]
    fn str_value() {
        let tag = make_tag("StrProperty", 10);
        let ctx = make_ctx(&["None"]);
        let mut buf = Vec::new();
        buf.extend_from_slice(&6i32.to_le_bytes());
        buf.extend_from_slice(b"Hello\0");
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf), &ctx, "x").unwrap().unwrap();
        assert_eq!(val, PropertyValue::Str("Hello".to_string()));
    }

    #[test]
    fn name_value() {
        let tag = make_tag("NameProperty", 8);
        let ctx = make_ctx(&["None", "MyName"]);
        let mut buf = Vec::new();
        buf.extend_from_slice(&1i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf), &ctx, "x").unwrap().unwrap();
        assert_eq!(val, PropertyValue::Name("MyName".to_string()));
    }

    #[test]
    fn enum_property_value() {
        let mut tag = make_tag("EnumProperty", 8);
        tag.enum_name = "EDirection".to_string();
        let ctx = make_ctx(&["None", "EDirection__Forward"]);
        let mut buf = Vec::new();
        buf.extend_from_slice(&1i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf), &ctx, "x").unwrap().unwrap();
        assert_eq!(
            val,
            PropertyValue::Enum { type_name: "EDirection".to_string(), value: "EDirection__Forward".to_string() }
        );
    }

    #[test]
    fn unknown_type_returns_none() {
        let tag = make_tag("ArrayProperty", 42);
        let ctx = make_ctx(&["None"]);
        let val = read_primitive_value(&tag, &mut Cursor::new(&[]), &ctx, "x").unwrap();
        assert!(val.is_none());
    }
}
```

- [ ] **Step 4: Update `property/mod.rs`**

```rust
pub mod bag;
pub mod primitives;
pub mod tag;
// text added in Task 5

pub use bag::{PropertyBag, MAX_PROPERTY_DEPTH};
pub use primitives::{Property, PropertyValue};
pub use tag::{read_tag, resolve_fname, PropertyTag, MAX_PROPERTY_TAG_SIZE};
```

Note: `text` module is added in Task 5 but `primitives.rs` imports `read_ftext` from it. To keep this task self-contained, add a stub `text.rs` for now:

Create `crates/paksmith-core/src/asset/property/text.rs` stub. The `R: Read + Seek` bound matches the final signature in Task 5 (read_ftext needs `stream_position` for the unknown-history-type skip path) so primitives.rs's call site doesn't need a signature change when Task 5 lands:

```rust
use serde::Serialize;
use std::io::{Read, Seek};
use crate::asset::AssetContext;
use crate::error::PaksmithError;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FText {
    pub flags: u32,
    pub history: FTextHistory,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[non_exhaustive]
pub enum FTextHistory {
    None { culture_invariant: Option<String> },
    Base { namespace: String, key: String, source_string: String },
    Unknown { history_type: i8, skipped_bytes: usize },
}

pub fn read_ftext<R: Read + Seek>(
    _reader: &mut R,
    _ctx: &AssetContext,
    _asset_path: &str,
    _tag_size: u64,
) -> crate::Result<FText> {
    // Replaced in Task 5.
    unimplemented!("read_ftext not yet implemented — Task 5")
}
```

Add `pub mod text;` to `mod.rs` so it compiles.

- [ ] **Step 5: Run tests to confirm they pass**

```bash
cargo test -p paksmith-core --lib asset::property::primitives::tests 2>&1 | tail -20
```

Expected: 16 tests pass (TextProperty test is not included because `read_ftext` is a stub; the `unimplemented!` is only reached if TextProperty bytes are actually fed in — tests above don't include that case).

- [ ] **Step 6: Run workspace clippy**

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

- [ ] **Step 7: Commit**

```bash
git add crates/paksmith-core/src/asset/property/
git commit -m "$(cat <<'EOF'
feat(asset): Property + PropertyValue + primitive readers (Phase 2b)

Property struct (name, array_index, guid, value) and PropertyValue
enum (Bool/Byte/Int variants/Float/Double/Str/Name/Enum/Text/Unknown).
read_primitive_value dispatches by tag.type_name; returns None for
unrecognised types (caller handles skip). text.rs stub allows
compilation pending Task 5. 16 primitive-reader unit tests.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: `FText` reader

**Files:**

- Modify: `crates/paksmith-core/src/asset/property/text.rs` — replace stub with full implementation

**Why:** `TextProperty` is present in many Blueprint assets. Deferring FText to "later" causes the cursor-mismatch check to fire on every text property. Implementing None (-1) and Base (0) history types covers ~95% of UE4 assets.

- [ ] **Step 1: Write failing tests for `read_ftext`**

Replace the stub tests (add at the bottom of `text.rs`):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use crate::asset::{
        name_table::{FName, NameTable},
        version::AssetVersion,
        import_table::ImportTable,
        export_table::ExportTable,
        AssetContext,
    };
    use std::sync::Arc;

    fn make_ctx() -> AssetContext {
        AssetContext {
            names: Arc::new(NameTable::default()),
            imports: Arc::new(ImportTable::default()),
            exports: Arc::new(ExportTable::default()),
            version: AssetVersion::default(),
        }
    }

    fn write_fstring(buf: &mut Vec<u8>, s: &str) {
        let bytes = s.as_bytes();
        let len = bytes.len() + 1; // include null terminator
        buf.extend_from_slice(&(len as i32).to_le_bytes());
        buf.extend_from_slice(bytes);
        buf.push(0u8);
    }

    #[test]
    fn history_none_no_culture_invariant() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u32.to_le_bytes()); // flags
        buf.push(0xFFu8);                            // history_type = -1 (None)
        buf.push(0u8);                               // bHasCultureInvariantString: false

        let tag_size = buf.len() as u64;
        let text = read_ftext(&mut Cursor::new(&buf), &make_ctx(), "x", tag_size).unwrap();
        assert_eq!(text.flags, 0);
        assert_eq!(text.history, FTextHistory::None { culture_invariant: None });
    }

    #[test]
    fn history_none_with_culture_invariant() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u32.to_le_bytes()); // flags
        buf.push(0xFFu8);                            // history_type = -1
        buf.push(1u8);                               // bHasCultureInvariantString: true
        write_fstring(&mut buf, "Hello World");

        let tag_size = buf.len() as u64;
        let text = read_ftext(&mut Cursor::new(&buf), &make_ctx(), "x", tag_size).unwrap();
        assert_eq!(
            text.history,
            FTextHistory::None { culture_invariant: Some("Hello World".to_string()) }
        );
    }

    #[test]
    fn history_base() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u32.to_le_bytes()); // flags
        buf.push(0u8);                               // history_type = 0 (Base)
        write_fstring(&mut buf, "MyNamespace");
        write_fstring(&mut buf, "MyKey");
        write_fstring(&mut buf, "Source string value");

        let tag_size = buf.len() as u64;
        let text = read_ftext(&mut Cursor::new(&buf), &make_ctx(), "x", tag_size).unwrap();
        assert_eq!(
            text.history,
            FTextHistory::Base {
                namespace: "MyNamespace".to_string(),
                key: "MyKey".to_string(),
                source_string: "Source string value".to_string(),
            }
        );
    }

    #[test]
    fn unknown_history_type_skips_remaining_bytes() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u32.to_le_bytes()); // flags
        buf.push(3u8);                               // history_type = 3 (StringTableEntry — unknown in 2b)
        buf.extend_from_slice(&[0xAAu8; 20]);        // 20 opaque bytes

        // tag_size = 5 (flags + history_type) + 20 = 25
        let tag_size = buf.len() as u64;
        let text = read_ftext(&mut Cursor::new(&buf), &make_ctx(), "x", tag_size).unwrap();
        assert_eq!(
            text.history,
            FTextHistory::Unknown { history_type: 3, skipped_bytes: 20 }
        );
    }
}
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
cargo test -p paksmith-core --lib asset::property::text::tests 2>&1 | tail -10
```

Expected: tests fail — `read_ftext` is `unimplemented!`.

- [ ] **Step 3: Implement `text.rs`**

````rust
//! `FText` deserialization.
//!
//! Wire layout for `ETextHistoryType::None (-1)`:
//! ```text
//! Flags:                    u32
//! HistoryType:              i8  (= -1)
//! bHasCultureInvariantString: u8
//! if bHasCultureInvariantString:
//!   CultureInvariantString: FString
//! ```
//!
//! Wire layout for `ETextHistoryType::Base (0)`:
//! ```text
//! Flags:        u32
//! HistoryType:  i8  (= 0)
//! Namespace:    FString
//! Key:          FString
//! SourceString: FString
//! ```
//!
//! All other history types: Flags + HistoryType read, remaining bytes
//! skipped to `value_start + tag_size`. Stored as [`FTextHistory::Unknown`].

use std::io::{Read, Seek};

use byteorder::{LittleEndian, ReadBytesExt};
use serde::Serialize;

use crate::asset::AssetContext;
use crate::asset::fstring::read_asset_fstring;
use crate::error::{AssetParseFault, AssetWireField, PaksmithError};

/// Decoded `FText` value.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FText {
    /// UE text flags (serialization hints; usually 0).
    pub flags: u32,
    /// The decoded history variant.
    pub history: FTextHistory,
}

/// Discriminated union over `ETextHistoryType` variants.
///
/// Phase 2b handles None (-1) and Base (0). All other variants are
/// stored as `Unknown { history_type, skipped_bytes }`.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[non_exhaustive]
pub enum FTextHistory {
    /// `ETextHistoryType::None` — optionally a culture-invariant string.
    None {
        /// The culture-invariant override string, if present.
        culture_invariant: Option<String>,
    },
    /// `ETextHistoryType::Base` — the canonical localized text triple.
    Base {
        namespace: String,
        key: String,
        source_string: String,
    },
    /// Any `ETextHistoryType` variant Phase 2b does not decode.
    Unknown {
        history_type: i8,
        skipped_bytes: usize,
    },
}

/// Read one `FText` from `reader`.
///
/// `tag_size` is the `FPropertyTag::Size` for the enclosing
/// `TextProperty` — used to compute how many bytes to skip for
/// unknown history types. `reader` must be positioned at the start of
/// the FText payload (i.e. immediately after the tag header).
///
/// # Errors
/// - [`AssetParseFault::UnexpectedEof`] / [`PaksmithError::Io`] on short reads.
/// - [`AssetParseFault::FStringMalformed`] for malformed text body strings.
pub fn read_ftext<R: Read + Seek>(
    reader: &mut R,
    _ctx: &AssetContext,
    asset_path: &str,
    tag_size: u64,
) -> crate::Result<FText> {
    let eof = |field: AssetWireField| PaksmithError::AssetParse {
        asset_path: asset_path.to_string(),
        fault: AssetParseFault::UnexpectedEof { field },
    };

    // Track start so we can compute remaining bytes for Unknown.
    let start_pos = reader
        .stream_position()
        .map_err(|_| eof(AssetWireField::FTextHistoryType))?;

    let flags = reader
        .read_u32::<LittleEndian>()
        .map_err(|_| eof(AssetWireField::FTextHistoryType))?;
    let history_type = reader
        .read_i8()
        .map_err(|_| eof(AssetWireField::FTextHistoryType))?;

    let history = match history_type {
        -1 => {
            let has_culture = reader.read_u8().map_err(|_| eof(AssetWireField::FTextField))?;
            let culture_invariant = if has_culture != 0 {
                // Asset-side wrapper: accepts len=0 as "" and uses
                // asset_path context. See `asset/fstring.rs`.
                Some(read_asset_fstring(reader, asset_path)?)
            } else {
                None
            };
            FTextHistory::None { culture_invariant }
        }
        0 => {
            // Modern UE writers emit all three FStrings unconditionally for
            // ETextHistoryType::Base. Empty namespace/key strings are common
            // (UE often emits namespace="" for non-localized text); the
            // asset-side wrapper accepts len=0 as "" — see Decision #9 and
            // `asset/fstring.rs`.
            let namespace = read_asset_fstring(reader, asset_path)?;
            let key = read_asset_fstring(reader, asset_path)?;
            let source_string = read_asset_fstring(reader, asset_path)?;
            FTextHistory::Base { namespace, key, source_string }
        }
        other => {
            // Compute remaining bytes to skip (tag_size - bytes already consumed).
            let current_pos = reader
                .stream_position()
                .map_err(|_| eof(AssetWireField::FTextHistoryType))?;
            let consumed = current_pos.saturating_sub(start_pos);
            let remaining = tag_size.saturating_sub(consumed) as usize;
            // Read and discard.
            let mut skip_buf = vec![0u8; remaining];
            reader
                .read_exact(&mut skip_buf)
                .map_err(|_| eof(AssetWireField::FTextField))?;
            FTextHistory::Unknown {
                history_type: other,
                skipped_bytes: remaining,
            }
        }
    };

    Ok(FText { flags, history })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use crate::asset::{
        name_table::NameTable,
        version::AssetVersion,
        import_table::ImportTable,
        export_table::ExportTable,
        AssetContext,
    };
    use std::sync::Arc;

    fn make_ctx() -> AssetContext {
        AssetContext {
            names: Arc::new(NameTable::default()),
            imports: Arc::new(ImportTable::default()),
            exports: Arc::new(ExportTable::default()),
            version: AssetVersion::default(),
        }
    }

    fn write_fstring(buf: &mut Vec<u8>, s: &str) {
        let bytes = s.as_bytes();
        buf.extend_from_slice(&((bytes.len() + 1) as i32).to_le_bytes());
        buf.extend_from_slice(bytes);
        buf.push(0u8);
    }

    #[test]
    fn history_none_no_culture_invariant() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.push(0xFFu8); // -1i8 as u8
        buf.push(0u8);
        let tag_size = buf.len() as u64;
        let text = read_ftext(&mut Cursor::new(&buf), &make_ctx(), "x", tag_size).unwrap();
        assert_eq!(text.history, FTextHistory::None { culture_invariant: None });
    }

    #[test]
    fn history_none_with_culture_invariant() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.push(0xFFu8);
        buf.push(1u8);
        write_fstring(&mut buf, "Hello World");
        let tag_size = buf.len() as u64;
        let text = read_ftext(&mut Cursor::new(&buf), &make_ctx(), "x", tag_size).unwrap();
        assert_eq!(
            text.history,
            FTextHistory::None { culture_invariant: Some("Hello World".to_string()) }
        );
    }

    #[test]
    fn history_base() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.push(0u8);
        write_fstring(&mut buf, "MyNamespace");
        write_fstring(&mut buf, "MyKey");
        write_fstring(&mut buf, "Source string value");
        let tag_size = buf.len() as u64;
        let text = read_ftext(&mut Cursor::new(&buf), &make_ctx(), "x", tag_size).unwrap();
        assert_eq!(
            text.history,
            FTextHistory::Base {
                namespace: "MyNamespace".to_string(),
                key: "MyKey".to_string(),
                source_string: "Source string value".to_string(),
            }
        );
    }

    #[test]
    fn unknown_history_type_skips_remaining_bytes() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.push(3u8); // history_type = 3
        buf.extend_from_slice(&[0xAAu8; 20]);
        let tag_size = buf.len() as u64;
        let text = read_ftext(&mut Cursor::new(&buf), &make_ctx(), "x", tag_size).unwrap();
        assert_eq!(
            text.history,
            FTextHistory::Unknown { history_type: 3, skipped_bytes: 20 }
        );
    }
}
````

- [ ] **Step 4: Run tests**

```bash
cargo test -p paksmith-core --lib asset::property::text::tests 2>&1 | tail -20
```

Expected: 4 tests pass.

- [ ] **Step 5: Run full workspace tests + clippy**

```bash
cargo test --workspace && cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add crates/paksmith-core/src/asset/property/text.rs
git commit -m "$(cat <<'EOF'
feat(asset): FText reader — ETextHistoryType None and Base (Phase 2b)

FText struct + FTextHistory enum (None, Base, Unknown). read_ftext
handles history_type -1 (None/culture-invariant) and 0 (Base:
namespace+key+sourcestring). Unknown history types skip remaining
tag bytes. Four unit tests.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task 6: Property iterator `read_properties`

**Files:**

- Modify: `crates/paksmith-core/src/asset/property/mod.rs` — add `read_properties`, `MAX_TAGS_PER_EXPORT`

**Why:** This is the core loop that drives the whole property system. Testing it in isolation (with hand-crafted byte streams) confirms all the guard conditions before it touches Package.

- [ ] **Step 1: Write failing tests**

Add a test module to `property/mod.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use crate::asset::{
        name_table::{FName, NameTable},
        version::AssetVersion,
        import_table::ImportTable,
        export_table::ExportTable,
        AssetContext,
    };
    use std::sync::Arc;

    fn make_ctx(names: &[&str]) -> AssetContext {
        let table = NameTable { names: names.iter().map(|n| FName::new(n)).collect() };
        AssetContext {
            names: Arc::new(table),
            imports: Arc::new(ImportTable::default()),
            exports: Arc::new(ExportTable::default()),
            version: AssetVersion::default(),
        }
    }

    // Builds a BoolProperty tag + None terminator in-memory.
    // names: 0=None, 1=bEnabled, 2=BoolProperty
    fn bool_property_then_none() -> (Vec<u8>, AssetContext) {
        let ctx = make_ctx(&["None", "bEnabled", "BoolProperty"]);
        let mut buf = Vec::new();
        // Name: bEnabled (index=1)
        buf.extend_from_slice(&1i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        // Type: BoolProperty (index=2)
        buf.extend_from_slice(&2i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        // Size: 0, ArrayIndex: 0
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        // boolVal: 1, HasPropertyGuid: 0
        buf.push(1u8);
        buf.push(0u8);
        // None terminator
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        (buf, ctx)
    }

    #[test]
    fn reads_bool_property() {
        let (buf, ctx) = bool_property_then_none();
        let export_end = buf.len() as u64;
        let props = read_properties(
            &mut Cursor::new(&buf),
            &ctx,
            0,
            export_end,
            "x.uasset",
        ).unwrap();
        assert_eq!(props.len(), 1);
        assert_eq!(props[0].name, "bEnabled");
        assert_eq!(props[0].value, crate::asset::property::primitives::PropertyValue::Bool(true));
    }

    #[test]
    fn stops_at_export_end() {
        // No None terminator — stops when cursor reaches export_end
        let ctx = make_ctx(&["None"]);
        let buf: Vec<u8> = Vec::new(); // empty: already at end
        let props = read_properties(
            &mut Cursor::new(&buf),
            &ctx,
            0,
            0,
            "x.uasset",
        ).unwrap();
        assert!(props.is_empty());
    }

    #[test]
    fn unknown_type_stored_as_unknown_variant() {
        // ArrayProperty (unknown in 2b) should be stored as Unknown
        // names: 0=None, 1=Tags, 2=ArrayProperty, 3=IntProperty (inner)
        let ctx = make_ctx(&["None", "Tags", "ArrayProperty", "IntProperty"]);
        let mut buf = Vec::new();
        // Name: Tags
        buf.extend_from_slice(&1i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        // Type: ArrayProperty
        buf.extend_from_slice(&2i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        // Size: 8
        buf.extend_from_slice(&8i32.to_le_bytes());
        // ArrayIndex: 0
        buf.extend_from_slice(&0i32.to_le_bytes());
        // InnerType: IntProperty
        buf.extend_from_slice(&3i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        // HasPropertyGuid: 0
        buf.push(0u8);
        // Value payload: 8 opaque bytes
        buf.extend_from_slice(&[0u8; 8]);
        // None terminator
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        let export_end = buf.len() as u64;
        let props = read_properties(
            &mut Cursor::new(&buf),
            &ctx,
            0,
            export_end,
            "x.uasset",
        ).unwrap();
        assert_eq!(props.len(), 1);
        assert_eq!(props[0].name, "Tags");
        assert!(matches!(
            props[0].value,
            crate::asset::property::primitives::PropertyValue::Unknown {
                ref type_name, skipped_bytes: 8
            } if type_name == "ArrayProperty"
        ));
    }

    #[test]
    fn depth_guard_rejects_depth_over_limit() {
        let (buf, ctx) = bool_property_then_none();
        let export_end = buf.len() as u64;
        let err = read_properties(
            &mut Cursor::new(&buf),
            &ctx,
            bag::MAX_PROPERTY_DEPTH + 1, // over limit
            export_end,
            "x.uasset",
        ).unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::PropertyDepthExceeded { .. },
                ..
            }
        ));
    }

    /// T2 — Cursor-mismatch invariant (Decision #5) test.
    ///
    /// Construct an IntProperty tag claiming `Size = 8` but only emit
    /// 4 bytes of payload before the "None" terminator. The primitive
    /// reader consumes 4 bytes (correct for IntProperty); the cursor-
    /// check then fires PropertyTagSizeMismatch because actual_pos
    /// (value_start + 4) != expected_end (value_start + 8).
    #[test]
    fn size_mismatch_after_value_read_is_rejected() {
        // names: 0=None, 1=Foo, 2=IntProperty
        let ctx = make_ctx(&["None", "Foo", "IntProperty"]);
        let mut buf = Vec::new();
        // Tag: Name=Foo, Type=IntProperty
        buf.extend_from_slice(&1i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.extend_from_slice(&2i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        // Size: 8 (lying — IntProperty payload is actually 4 bytes)
        buf.extend_from_slice(&8i32.to_le_bytes());
        // ArrayIndex
        buf.extend_from_slice(&0i32.to_le_bytes());
        // HasPropertyGuid
        buf.push(0u8);
        // Value payload: only 4 bytes (the read_primitive_value path
        // for IntProperty consumes exactly 4); the trailing 4 bytes
        // belong to neither the value nor the next tag.
        buf.extend_from_slice(&42i32.to_le_bytes());
        // Filler bytes the reader will not consume — cursor stays at
        // value_start+4 while expected_end is value_start+8.
        buf.extend_from_slice(&[0u8; 4]);
        // None terminator afterward (unreachable due to the mismatch).
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());

        let export_end = buf.len() as u64;
        let err = read_properties(
            &mut Cursor::new(&buf),
            &ctx,
            0,
            export_end,
            "x.uasset",
        ).unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::PropertyTagSizeMismatch { .. },
                    ..
                }
            ),
            "expected PropertyTagSizeMismatch; got: {err:?}"
        );
    }

    /// T3 — MAX_TAGS_PER_EXPORT cap test.
    ///
    /// Write `MAX_TAGS_PER_EXPORT + 1` valid-shaped 0-byte BoolProperty
    /// tags (smallest possible header at 18 bytes each: 8 name + 8 type +
    /// 4 size + 4 arr_idx + 1 boolVal + 1 hasGuid = 18; size=0 means
    /// no value payload, no terminator emitted). The iterator hits the
    /// count cap before encountering a None terminator, producing
    /// PropertyTagCountExceeded.
    ///
    /// 65_537 * 18 bytes ≈ 1.18 MiB — small enough to materialize in a
    /// unit test without a special test-only cap override. If the cost
    /// is ever an issue in CI, a Phase 2c follow-up could thread a
    /// `pub(crate) const TEST_MAX_TAGS_OVERRIDE` through the iterator.
    #[test]
    fn tag_count_cap_is_rejected() {
        // names: 0=None, 1=p, 2=BoolProperty
        let ctx = make_ctx(&["None", "p", "BoolProperty"]);
        let mut buf = Vec::with_capacity(20 * (MAX_TAGS_PER_EXPORT + 1));
        for _ in 0..=MAX_TAGS_PER_EXPORT {
            // Name: "p" (index 1)
            buf.extend_from_slice(&1i32.to_le_bytes());
            buf.extend_from_slice(&0i32.to_le_bytes());
            // Type: BoolProperty (index 2)
            buf.extend_from_slice(&2i32.to_le_bytes());
            buf.extend_from_slice(&0i32.to_le_bytes());
            // Size: 0
            buf.extend_from_slice(&0i32.to_le_bytes());
            // ArrayIndex: 0
            buf.extend_from_slice(&0i32.to_le_bytes());
            // boolVal: 0
            buf.push(0u8);
            // HasPropertyGuid: 0
            buf.push(0u8);
        }
        // No terminator on purpose — the iterator must stop on cap, not None.
        let export_end = buf.len() as u64;
        let err = read_properties(
            &mut Cursor::new(&buf),
            &ctx,
            0,
            export_end,
            "x.uasset",
        ).unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::PropertyTagCountExceeded { .. },
                    ..
                }
            ),
            "expected PropertyTagCountExceeded; got: {err:?}"
        );
    }
}
```

- [ ] **Step 2: Run tests to confirm compile failure**

```bash
cargo test -p paksmith-core --lib asset::property::tests 2>&1 | tail -10
```

Expected: compile error — `read_properties`, `MAX_TAGS_PER_EXPORT` not found.

- [ ] **Step 3: Implement `read_properties` in `property/mod.rs`**

Add to `mod.rs` (after the `pub use` lines):

```rust
use std::io::{Read, Seek};

use crate::asset::AssetContext;
use crate::error::{
    AssetAllocationContext, AssetParseFault, BoundsUnit, PaksmithError,
};

use primitives::{Property, PropertyValue};
use tag::read_tag;

/// Maximum number of `FPropertyTag` entries per export stream.
/// Guards against a missing "None" terminator looping forever.
pub const MAX_TAGS_PER_EXPORT: usize = 65_536;

/// Read all `FPropertyTag` entries from `reader` until the "None"
/// terminator, `export_end`, or `MAX_TAGS_PER_EXPORT`, whichever
/// comes first.
///
/// `depth` is the current recursion depth (0 for top-level export
/// bodies; Phase 2c increments it for struct contents). Errors
/// immediately if `depth > MAX_PROPERTY_DEPTH`.
///
/// Unknown/container property types skip exactly `tag.size` bytes and
/// are stored as [`PropertyValue::Unknown`].
///
/// After reading each property value, the cursor MUST be at
/// `value_start + tag.size`; a mismatch returns
/// [`AssetParseFault::PropertyTagSizeMismatch`].
///
/// # Errors
/// - [`AssetParseFault::PropertyDepthExceeded`] if `depth > MAX_PROPERTY_DEPTH`.
/// - [`AssetParseFault::PropertyTagCountExceeded`] if tag count hits `MAX_TAGS_PER_EXPORT`.
/// - [`AssetParseFault::PropertyTagSizeMismatch`] on cursor mismatch.
/// - Any error from [`read_tag`] or the primitive/text readers.
pub fn read_properties<R: Read + Seek>(
    reader: &mut R,
    ctx: &AssetContext,
    depth: usize,
    export_end: u64,
    asset_path: &str,
) -> crate::Result<Vec<Property>> {
    if depth > bag::MAX_PROPERTY_DEPTH {
        return Err(PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::PropertyDepthExceeded {
                depth,
                limit: bag::MAX_PROPERTY_DEPTH,
            },
        });
    }

    let mut props: Vec<Property> = Vec::new();

    for _ in 0..MAX_TAGS_PER_EXPORT {
        // Stop if we've consumed the full export payload.
        let pos = reader
            .stream_position()
            .map_err(|e| PaksmithError::Io(e))?;
        if pos >= export_end {
            break;
        }

        let tag = match read_tag(reader, ctx, asset_path)? {
            Some(t) => t,
            None => break, // "None" terminator
        };

        let value_start = reader
            .stream_position()
            .map_err(|e| PaksmithError::Io(e))?;
        let expected_end = value_start + tag.size as u64;

        let value = match primitives::read_primitive_value(&tag, reader, ctx, asset_path)? {
            Some(v) => v,
            None => {
                // Unknown / container type: skip exactly tag.size bytes.
                let n = tag.size as usize;
                let mut skip = vec![0u8; n];
                skip.try_reserve_exact(n).map_err(|source| PaksmithError::AssetParse {
                    asset_path: asset_path.to_string(),
                    fault: AssetParseFault::AllocationFailed {
                        context: AssetAllocationContext::UnknownPropertyBytes,
                        requested: n,
                        unit: BoundsUnit::Bytes,
                        source,
                    },
                })?;
                reader
                    .read_exact(&mut skip)
                    .map_err(|_| PaksmithError::AssetParse {
                        asset_path: asset_path.to_string(),
                        fault: AssetParseFault::UnexpectedEof {
                            field: crate::error::AssetWireField::PropertyTagSize,
                        },
                    })?;
                PropertyValue::Unknown {
                    type_name: tag.type_name.clone(),
                    skipped_bytes: n,
                }
            }
        };

        // Cursor-mismatch invariant.
        let actual_pos = reader
            .stream_position()
            .map_err(|e| PaksmithError::Io(e))?;
        if actual_pos != expected_end {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::PropertyTagSizeMismatch {
                    expected_end,
                    actual_pos,
                },
            });
        }

        props.push(Property {
            name: tag.name,
            array_index: tag.array_index,
            guid: tag.guid,
            value,
        });
    }

    // If we exhausted the loop without a None terminator, that's an error.
    if props.len() == MAX_TAGS_PER_EXPORT {
        let pos = reader
            .stream_position()
            .map_err(|e| PaksmithError::Io(e))?;
        if pos < export_end {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::PropertyTagCountExceeded { limit: MAX_TAGS_PER_EXPORT },
            });
        }
    }

    Ok(props)
}
```

Update the `pub use` block to export `read_properties` and `MAX_TAGS_PER_EXPORT`:

```rust
pub mod bag;
pub mod primitives;
pub mod tag;
pub mod text;

pub use bag::{PropertyBag, MAX_PROPERTY_DEPTH};
pub use primitives::{Property, PropertyValue};
pub use tag::{read_tag, resolve_fname, PropertyTag, MAX_PROPERTY_TAG_SIZE};
// `read_properties` and `MAX_TAGS_PER_EXPORT` are defined directly in this
// `mod.rs` (see Task 8), so they're already public from this module — no
// `pub use self::{...}` indirection needed.
```

- [ ] **Step 4: Run tests**

```bash
cargo test -p paksmith-core --lib asset::property::tests 2>&1 | tail -20
```

Expected: 6 tests pass — `reads_bool_property`, `stops_at_export_end`, `unknown_type_stored_as_unknown_variant`, `depth_guard_rejects_depth_over_limit`, `size_mismatch_after_value_read_is_rejected` (T2), `tag_count_cap_is_rejected` (T3).

- [ ] **Step 5: Run workspace clippy**

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

- [ ] **Step 6: Commit**

```bash
git add crates/paksmith-core/src/asset/property/mod.rs
git commit -m "$(cat <<'EOF'
feat(asset): read_properties iterator with depth + count guards (Phase 2b)

read_properties iterates FPropertyTag entries until None terminator,
export_end, or MAX_TAGS_PER_EXPORT (65536). Cursor-mismatch invariant
fires PropertyTagSizeMismatch after each value read. Unknown/container
types skip tag.size bytes → PropertyValue::Unknown. PropertyDepthExceeded
fires immediately when depth > MAX_PROPERTY_DEPTH (128). Six unit tests
covering: bool decode, export_end stop, Unknown variant for container
types, depth-cap rejection, cursor-mismatch invariant
(size_mismatch_after_value_read_is_rejected), tag-count cap
(tag_count_cap_is_rejected).

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task 7: `PropertyBag::Tree` + `Package` integration + unversioned flag

**Files:**

- Modify: `crates/paksmith-core/src/asset/property/bag.rs` — add `Tree` variant
- Modify: `crates/paksmith-core/src/asset/package.rs` — add unversioned check + property iteration

**Why:** Connects all the pieces. `Package::read_from` now checks `PKG_UnversionedProperties` before attempting property iteration, then replaces `PropertyBag::Opaque` with `PropertyBag::Tree` when the iterator succeeds.

- [ ] **Step 1: Write failing tests for PropertyBag::Tree**

Add to `bag.rs` tests:

```rust
#[test]
fn tree_variant_serializes_properties_array() {
    use crate::asset::property::primitives::{Property, PropertyValue};
    let bag = PropertyBag::tree(vec![Property {
        name: "bEnabled".to_string(),
        array_index: 0,
        guid: None,
        value: PropertyValue::Bool(true),
    }]);
    let json = serde_json::to_string(&bag).unwrap();
    // Struct variant serializes via #[serde(tag = "kind", rename_all =
    // "snake_case")] as {"kind":"tree","properties":[...]}. Pin the
    // shape literally — a future change to `Tree`'s field layout
    // (e.g. adding a count) must update the contract here.
    assert!(
        json.contains(r#""kind":"tree""#),
        "expected internally-tagged kind=tree; got: {json}"
    );
    assert!(
        json.contains(r#""properties":["#),
        "expected nested properties array; got: {json}"
    );
    assert!(json.contains("bEnabled"), "got: {json}");
    assert!(json.contains("Bool"), "got: {json}");
}

#[test]
fn tree_variant_round_trips_through_byte_len_as_property_count() {
    use crate::asset::property::primitives::{Property, PropertyValue};
    let props = vec![
        Property {
            name: "a".into(), array_index: 0, guid: None,
            value: PropertyValue::Bool(true),
        },
        Property {
            name: "b".into(), array_index: 0, guid: None,
            value: PropertyValue::Int(42),
        },
    ];
    let bag = PropertyBag::tree(props);
    // For Tree, byte_len returns the property count (not raw bytes,
    // since Tree is decoded). Pinned so a future change keeps the
    // semantics explicit.
    assert_eq!(bag.byte_len(), 2);
}
```

- [ ] **Step 2: Run tests to confirm compile failure**

```bash
cargo test -p paksmith-core --lib asset::property::bag::tests::tree_variant 2>&1 | tail -10
```

Expected: compile error — `Tree` variant and `PropertyBag::tree` constructor not found.

- [ ] **Step 3: Add `Tree` struct variant to `PropertyBag`**

In `bag.rs`, add after the `Opaque` variant (inside the enum). **Struct variant — not newtype/tuple** (`Tree(Vec<Property>)` won't compile because the parent enum derives `#[serde(tag = "kind", rename_all = "snake_case")]` and internal tagging requires struct or unit variants):

```rust
    /// Phase 2b: decoded FPropertyTag sequence.
    Tree {
        /// The decoded property list (one entry per FPropertyTag).
        properties: Vec<crate::asset::property::primitives::Property>,
    },
```

Add constructor:

```rust
    /// Convenience constructor for the Phase-2b tree variant.
    #[must_use]
    pub fn tree(properties: Vec<crate::asset::property::primitives::Property>) -> Self {
        Self::Tree { properties }
    }
```

Update `byte_len`:

```rust
    pub fn byte_len(&self) -> usize {
        match self {
            Self::Opaque { bytes } => bytes.len(),
            Self::Tree { properties } => properties.len(), // count, not bytes
        }
    }
```

Update the hand-rolled `impl fmt::Debug for PropertyBag` (preserved verbatim from Phase 2a — see Task 2 — emits a byte count, not raw bytes; pinned by `debug_elides_byte_content`) to handle the new `Tree` variant:

```rust
impl fmt::Debug for PropertyBag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Opaque { bytes } => f
                .debug_struct("Opaque")
                .field("bytes", &format_args!("<{} bytes>", bytes.len()))
                .finish(),
            Self::Tree { properties } => f
                .debug_struct("Tree")
                .field("properties", &format_args!("<{} entries>", properties.len()))
                .finish(),
        }
    }
}
```

**Remove `Eq` from the `PropertyBag` derive at this step.** `PropertyValue::Float(f32)` and `PropertyValue::Double(f64)` are not `Eq`, so `Vec<Property>` is not `Eq`, so `Tree { properties: Vec<Property> }` makes the whole enum non-Eq. Change `#[derive(Clone, PartialEq, Eq, Serialize)]` to `#[derive(Clone, PartialEq, Serialize)]` in `bag.rs` (preserve `Clone`, `PartialEq`, `Serialize`; drop `Eq`). This is the first task where the Eq removal is structurally required — Task 2 deliberately preserves it for the literal-rename property. Update or remove any `Eq`-dependent call sites if they exist.

- [ ] **Step 4: Reject `PKG_UnversionedProperties` in `Package::read_from`**

Per Decision #6, the check fires at the summary level — not in `read_properties`, not in the export-body loop. In `package.rs`, inside `Package::read_from`, add the check between `ExportTable::read_from` and `read_payloads` (currently `package.rs:268–277`):

```rust
let exports = ExportTable::read_from(
    &mut cursor,
    i64::from(summary.export_offset),
    summary.export_count,
    summary.version,
    summary.package_flags,
    asset_path,
)?;

// Phase 2b: reject unversioned (schema-driven) property streams at
// the summary level — before any per-export property iteration. The
// flag lives on `summary.package_flags`, so the gate is correctly
// summary-scoped: a single flagged package cannot mix versioned and
// unversioned exports, so per-export checks would be wasteful and
// also misplace the error (the iterator has no business knowing
// about package flags). See Decision #6.
const PKG_UNVERSIONED_PROPERTIES: u32 = 0x0000_2000;
if summary.package_flags & PKG_UNVERSIONED_PROPERTIES != 0 {
    return Err(PaksmithError::AssetParse {
        asset_path: asset_path.to_string(),
        fault: AssetParseFault::UnversionedPropertiesUnsupported,
    });
}

let payloads = read_payloads(&mut cursor, &exports, asset_size, asset_path)?;
```

`read_payloads` is then unchanged in this aspect — the iterator inside it never sees an unversioned package, by construction.

Then replace the `PropertyBag::opaque(buf)` construction with a property-iteration attempt:

```rust
use crate::asset::property::read_properties;

let export_start = u64::try_from(export.serial_offset).unwrap_or(0);
let export_end = export_start + u64::try_from(export.serial_size).unwrap_or(0);

let mut cur = std::io::Cursor::new(asset_bytes);
cur.seek(std::io::SeekFrom::Start(export_start))?;

let bag = match read_properties(&mut cur, ctx, 0, export_end, asset_path) {
    Ok(props) => {
        tracing::debug!(
            asset = asset_path,
            export = %export.object_name,
            count = props.len(),
            "decoded property tree"
        );
        PropertyBag::tree(props)
    }
    Err(e) => {
        tracing::warn!(
            asset = asset_path,
            export = %export.object_name,
            error = %e,
            "property iteration failed, falling back to Opaque"
        );
        // Re-read bytes for the opaque fallback.
        let mut buf = vec![0u8; export.serial_size as usize];
        let mut r2 = std::io::Cursor::new(asset_bytes);
        r2.seek(std::io::SeekFrom::Start(export_start))?;
        r2.read_exact(&mut buf)?;
        PropertyBag::opaque(buf)
    }
};
payloads.push(bag);
```

Note: the exact placement of this code depends on the package.rs structure established in Phase 2a (Task 11). Read `package.rs` before editing to find the correct insertion point. The pattern above assumes `asset_bytes: &[u8]` is in scope and `payloads: Vec<PropertyBag>` is being built per-export.

- [ ] **Step 5: Run the full test suite**

```bash
cargo test --workspace 2>&1 | tail -20
```

Expected: all previous tests pass; the new `tree_variant_serializes_property_array` test passes.

- [ ] **Step 6: Run workspace clippy**

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

- [ ] **Step 7: Commit**

```bash
git add crates/paksmith-core/src/asset/property/bag.rs \
        crates/paksmith-core/src/asset/package.rs
git commit -m "$(cat <<'EOF'
feat(asset): PropertyBag::Tree + Package property iteration (Phase 2b)

PropertyBag gains Tree(Vec<Property>) variant; Package::read_from
checks PKG_UnversionedProperties (0x2000) and errors early, then
attempts property iteration for each export. Successful decode →
PropertyBag::Tree; parse error → warn! + PropertyBag::Opaque fallback.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task 8: `Package::Serialize` per-export integration + CLI snapshot update

**Files:**

- Modify: `crates/paksmith-core/src/asset/package.rs` — extend `ObjectExportView` to carry `&'a PropertyBag` and emit a per-export `properties` (Tree) or `payload_bytes` (Opaque) field; remove the top-level `payload_bytes` scalar from `Package::serialize`; reshape the pinned `serialize_emits_payload_bytes_scalar_not_payloads_array` test
- Modify: `crates/paksmith-cli/tests/snapshots/inspect_cli__inspect_json_snapshot.snap` — regenerated snapshot reflecting the new per-export shape
- Touch (if present): `crates/paksmith-cli/src/commands/inspect.rs` — the CLI serializes `Package` directly, so no struct changes are needed once `Package::Serialize` carries the per-export bag

**Why:** Phase 2a hand-rolled `impl Serialize for Package` (`package.rs:67-116`) and `impl Serialize for ObjectExportView` (`package.rs:173-232`) — `Package::serialize` emits a top-level `payload_bytes` scalar sum, pinned by `serialize_emits_payload_bytes_scalar_not_payloads_array` (`package.rs:500-503`). The Deliverable JSON for Phase 2b nests `properties` (or `payload_bytes` for opaque fallback) **inside each export**, which requires:

1. Wiring `&'a PropertyBag` into `ObjectExportView`.
2. Removing the now-redundant top-level `payload_bytes` scalar (the per-export field replaces it).
3. Rewriting the pinned test so a future Serialize refactor can't silently regress.

The `#[serde(flatten)]` trick the audit-superseded version of this task suggested doesn't apply — `ObjectExportView`'s Serialize is hand-rolled (`SerializeStruct`), not derived, so the bag field is wired by adding explicit `serialize_field("properties", ...)` / `serialize_field("payload_bytes", ...)` arms keyed on the bag variant.

- [ ] **Step 1: Extend `ObjectExportView` with a `bag` field**

In `package.rs`, change the struct definition (~line 168):

```rust
struct ObjectExportView<'a> {
    inner: &'a ObjectExport,
    names: &'a NameTable,
    bag: &'a PropertyBag,
}
```

Update the `export_views` construction in `Package::serialize` (~line 98):

```rust
let export_views: Vec<ObjectExportView<'_>> = self
    .exports
    .exports
    .iter()
    .zip(self.payloads.iter())
    .map(|(inner, bag)| ObjectExportView {
        inner,
        names: &self.names,
        bag,
    })
    .collect();
```

`self.exports.exports.len() == self.payloads.len()` is an invariant of `Package::read_from` (see `read_payloads` in `package.rs:323`); the `zip` is sound.

- [ ] **Step 2: Emit the per-export bag inside `ObjectExportView::serialize`**

The hand-rolled impl currently passes 24 fields. Bump to 25 and append, keyed on the bag variant (after the last existing `serialize_field("create_before_create_count", ...)` call):

```rust
let mut s = serializer.serialize_struct("ObjectExportView", 25)?;
// ... all existing 24 serialize_field calls unchanged ...
match self.bag {
    PropertyBag::Opaque { bytes } => {
        s.serialize_field("payload_bytes", &bytes.len())?;
    }
    PropertyBag::Tree { properties } => {
        s.serialize_field("properties", properties)?;
    }
}
s.end()
```

The two `PropertyBag` variants are mutually exclusive at this layer, so emitting only one of the two field names per export is correct. The struct's declared length grows to 25 even when only 24 + 1 fields fire — serde's `serialize_struct` size argument is advisory for some formats; `serde_json` ignores it.

- [ ] **Step 3: Remove the top-level `payload_bytes` scalar from `Package::serialize`**

In `Package::serialize` (~line 82-114), drop the `payload_bytes` computation and the `serialize_field("payload_bytes", ...)` call. The struct length drops from 6 to 5:

```rust
let mut s = serializer.serialize_struct("Package", 5)?;
s.serialize_field("asset_path", &self.asset_path)?;
s.serialize_field("summary", &self.summary)?;
s.serialize_field("names", &self.names)?;
s.serialize_field("imports", &import_views)?;
s.serialize_field("exports", &export_views)?;
s.end()
```

- [ ] **Step 4: Rewrite the pinned test**

The existing test at `package.rs:490-503` pins the OLD shape (top-level scalar, no payloads array). It must be renamed and reshaped to pin the NEW shape (per-export `payload_bytes` for Opaque fallback in the Phase 2a minimal fixture; no top-level `payload_bytes`):

```rust
#[test]
fn serialize_emits_per_export_payload_bytes_not_top_level_scalar() {
    // Phase 2b deliverable JSON shape: each export carries its own
    // payload_bytes (Opaque) or properties (Tree) field; the top-level
    // scalar payload_bytes from Phase 2a is removed. Pinned so a
    // future Serialize refactor can't silently regress the contract.
    let MinimalPackage { bytes, .. } = build_minimal_ue4_27();
    let pkg = Package::read_from(&bytes, "test.uasset").unwrap();
    let json = serde_json::to_string(&pkg).unwrap();

    // Per-export field present (the minimal fixture is opaque-only).
    assert!(
        json.contains(r#""payload_bytes":16"#),
        "expected per-export payload_bytes for Opaque fallback; got: {json}"
    );
    // Top-level scalar removed (no `"payload_bytes":<sum>` at the root).
    // The minimal fixture has exactly one export with size 16, so this
    // assertion can't false-positive on a top-level scalar that happens
    // to match the per-export value. Verify by checking the JSON
    // structure rather than a substring count.
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(
        parsed.get("payload_bytes").is_none(),
        "top-level payload_bytes must not be emitted; got: {json}"
    );
    assert!(
        parsed["exports"][0].get("payload_bytes").is_some(),
        "per-export payload_bytes must be present; got: {json}"
    );
    // No top-level payloads array (Phase 2a guarantee preserved).
    assert!(
        parsed.get("payloads").is_none(),
        "top-level payloads array must not be emitted; got: {json}"
    );
}
```

The minimal fixture used by `serialize_resolves_fname_references_in_imports_and_exports` (`package.rs:506-544`) is not affected by this change — that test asserts on import/export name resolution, not payload shape.

- [ ] **Step 5: Run the existing CLI snapshot test to see it fail**

```bash
cargo test -p paksmith-cli -- inspect 2>&1 | tail -20
```

Expected: snapshot mismatch. The new shape moves `payload_bytes` from a top-level scalar to a per-export field; depending on whether the fixture's single export decodes as `PropertyBag::Tree` (after Task 7's iterator wiring) or `PropertyBag::Opaque` (fallback for the Phase 2a minimal fixture that has no real FPropertyTag bytes), the per-export field will be either `"properties": [...]` or `"payload_bytes": 16`.

- [ ] **Step 6: Update the insta snapshot**

```bash
cargo insta review
```

Accept the new snapshot at `crates/paksmith-cli/tests/snapshots/inspect_cli__inspect_json_snapshot.snap`. Verify the new shape:

- The top-level `"payload_bytes": 16` is gone.
- The single export under `exports[0]` ends with either `"properties": [...]` (if the Phase 2a minimal fixture's opaque payload happens to parse as a property tree — unlikely, since the bytes were synthetic filler) or `"payload_bytes": 16` (the Opaque fallback path).

For the Phase 2a minimal fixture specifically: the export payload is 16 zero bytes. The property iterator will read FName(0, 0) — the "None" terminator on the very first read — and emit `PropertyBag::Tree { properties: vec![] }`. Cursor check at `expected_end = serial_offset + 16` vs `actual_pos = serial_offset + 8` fires `PropertyTagSizeMismatch` → fallback to `PropertyBag::Opaque`. So the snapshot will show `"payload_bytes": 16` per-export. The Task 9 fixture (real FPropertyTag bytes) will be the first one to show `"properties": [...]` in its snapshot.

- [ ] **Step 7: Run full workspace tests + clippy**

```bash
cargo test --workspace && cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Expected: all green.

- [ ] **Step 8: Commit**

```bash
git add crates/paksmith-core/src/asset/package.rs \
        crates/paksmith-cli/tests/snapshots/inspect_cli__inspect_json_snapshot.snap
git commit -m "$(cat <<'EOF'
feat(asset): per-export properties/payload_bytes in Package::Serialize (Phase 2b)

ObjectExportView gains a `bag: &'a PropertyBag` field and emits either
"properties": [...] (Tree) or "payload_bytes": N (Opaque) per export.
The top-level `payload_bytes` scalar sum is removed from Package's
hand-rolled Serialize impl — per-export fields replace it. Pinned test
renamed and reshaped: serialize_emits_per_export_payload_bytes_not_top_level_scalar.
CLI inspect snapshot regenerated.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task 9: Fixture-gen extension + cross-validation

**Files:**

- Modify: `crates/paksmith-core/src/testing/uasset.rs` — add property-emitting helpers + `build_minimal_ue4_27_with_properties()`; extend `MinimalPackage` with `package_flags_offset: usize`
- Modify: `crates/paksmith-fixture-gen/src/uasset.rs` — call `build_minimal_ue4_27_with_properties`; extend `cross_validate_with_unreal_asset` (the existing one — see `fixture-gen/src/uasset.rs:56-83`) to assert property tree

**Why:** The cross-parser oracle (unreal_asset) confirms that paksmith's property reader sees the same values that the reference implementation sees. This closes the same verification loop that Phase 1 used trumank/repak for.

- [ ] **Step 1: Verify the `unreal_asset` property API at the pinned commit**

The existing `cross_validate_with_unreal_asset` at `crates/paksmith-fixture-gen/src/uasset.rs:56-83` already documents the verified header API at commit `f4df5d8e75b1e184832384d1865f0b696b90a614`:

- `Asset::new(reader, bulk_reader, EngineVersion::VER_UE4_27, mappings)` — constructor parses inline.
- `asset.imports: Vec<Import>` — public field.
- `asset.asset_data.exports: Vec<Export<PackageIndex>>` — reached via `asset_data`.
- `asset.get_name_map().get_ref().get_name_map_index_list()` — name list.

For Task 9, the additional property-access API needs verification before code is written. Check out the pinned commit and grep:

```bash
# Locate the unreal_asset source under ~/.cargo/git/checkouts/.
# The path-discriminated name `unreal_asset-*/<commit-prefix>` makes
# `find` simpler than parsing cargo metadata.
UA_DIR=$(find ~/.cargo/git/checkouts -type d -name 'unreal_asset' \
              -path '*/unreal_asset/*' 2>/dev/null | head -1)
test -n "$UA_DIR" || { echo "unreal_asset not vendored; run cargo build first"; exit 1; }

# 1) Confirm `Export` has `get_normal_export()` (Option<&NormalExport<PI>>).
grep -rn "fn get_normal_export\|impl.*Export" "$UA_DIR/unreal_asset_exports/" \
    --include="*.rs" 2>/dev/null | grep -i "normal" | head -10

# 2) Confirm `NormalExport.properties` field exists and is a `Vec<Property>`.
grep -rn "pub properties" "$UA_DIR/unreal_asset_exports/" \
    --include="*.rs" 2>/dev/null | head -10

# 3) Confirm Property has a `get_name()` accessor returning FName-like.
grep -rn "fn get_name" "$UA_DIR/unreal_asset_properties/" \
    --include="*.rs" 2>/dev/null | head -10

# 4) Confirm FName has `get_owned_content()` or `get_content()` returning String.
grep -rn "fn get_owned_content\|fn get_content" "$UA_DIR/unreal_asset_base/" \
    --include="*.rs" 2>/dev/null | head -10
```

If any expected method is missing, locate the equivalent in the actual API surface and update the cross-validation function accordingly. The pattern to extend is **exactly** the existing `cross_validate_with_unreal_asset` (same `Asset::new` call, same `EngineVersion::VER_UE4_27` — already verified working), just adding property-list assertions on top.

Expected post-verification shape (revise to match the actual API surface — do not write the cross-validation function without confirming each accessor exists):

```rust
// Inside cross_validate_with_unreal_asset, after the existing
// name/imports/exports assertions, add:
let export = asset.asset_data.exports
    .first()
    .ok_or_else(|| anyhow::anyhow!("expected at least one export"))?;
let normal = export.get_normal_export()
    .ok_or_else(|| anyhow::anyhow!("expected NormalExport"))?;
anyhow::ensure!(
    normal.properties.len() == 3,
    "unreal_asset saw {} properties; paksmith wrote 3",
    normal.properties.len()
);
let prop_names: Vec<String> = normal.properties.iter()
    .map(|p| p.get_name().get_owned_content())
    .collect();
anyhow::ensure!(prop_names.contains(&"bEnabled".to_string()), "missing bEnabled");
anyhow::ensure!(prop_names.contains(&"MaxSpeed".to_string()), "missing MaxSpeed");
anyhow::ensure!(prop_names.contains(&"ObjectName".to_string()), "missing ObjectName");
```

Confirm compilation before writing the fixture caller:

```bash
cargo check -p paksmith-fixture-gen 2>&1 | grep -E "error\[|no method|not found" | head -20
```

Empty output = API resolved.

- [ ] **Step 2: Extend `MinimalPackage` with `package_flags_offset: usize`**

Task 10's `unversioned_flag_is_rejected` test (Task 10 Step 1) needs to flip the `PKG_UnversionedProperties` bit in an already-built minimal package's wire bytes. To do that without re-deriving the FPackageFileSummary offset arithmetic in every test, add a field to the existing `MinimalPackage` struct in `testing/uasset.rs`:

```rust
pub struct MinimalPackage {
    pub bytes: Vec<u8>,
    pub summary: PackageSummary,
    pub names: NameTable,
    pub imports: ImportTable,
    pub exports: ExportTable,
    pub payload: Vec<u8>,
    /// Byte offset of `FPackageFileSummary::PackageFlags` within
    /// `bytes`. Phase 2b's `unversioned_flag_is_rejected` test (Task 10)
    /// flips the `0x0000_2000` bit at this offset to assert rejection.
    pub package_flags_offset: usize,
}
```

Populate it during the two-pass write in `build_minimal_ue4_27` (and the new `build_minimal_ue4_27_with_properties`): track the cursor position immediately before the `PackageFlags` u32 is written, and assign that to `package_flags_offset`. Any future field added before `PackageFlags` updates this offset automatically — that's the whole point of computing it at write time rather than hardcoding a constant.

Without this step, Task 10's test becomes the non-functional `let _ = pkg_bytes;` placeholder the audit-superseded draft showed.

- [ ] **Step 3: Add property-emitting helpers to `testing/uasset.rs`**

Add (inside the `#[cfg(feature = "__test_utils")]` guard if present, or at module level):

```rust
// ─── FPropertyTag wire-format write helpers ─────────────────────────────────
// Indices into the MinimalPackage name table (must match build_minimal_ue4_27):
//   0 = "None"
//   1 = <object name> (varies)
// For build_minimal_ue4_27_with_properties the table is extended:
//   0 = "None"
//   1 = "Hero"
//   2 = "bEnabled"
//   3 = "BoolProperty"
//   4 = "MaxSpeed"
//   5 = "FloatProperty"
//   6 = "ObjectName"
//   7 = "StrProperty"

pub(crate) fn write_fname_pair(buf: &mut Vec<u8>, index: i32, number: i32) {
    buf.extend_from_slice(&index.to_le_bytes());
    buf.extend_from_slice(&number.to_le_bytes());
}

/// Write a BoolProperty FPropertyTag + value (boolVal in tag, no payload).
pub(crate) fn write_bool_property_tag(
    buf: &mut Vec<u8>,
    name_idx: i32,
    type_idx: i32,
    value: bool,
) {
    write_fname_pair(buf, name_idx, 0); // Name
    write_fname_pair(buf, type_idx, 0); // Type: BoolProperty
    buf.extend_from_slice(&0i32.to_le_bytes()); // Size: 0
    buf.extend_from_slice(&0i32.to_le_bytes()); // ArrayIndex: 0
    buf.push(if value { 1u8 } else { 0u8 }); // boolVal
    buf.push(0u8); // HasPropertyGuid: 0
}

/// Write an IntProperty FPropertyTag + 4-byte LE payload.
pub(crate) fn write_int_property_tag(
    buf: &mut Vec<u8>,
    name_idx: i32,
    type_idx: i32,
    value: i32,
) {
    write_fname_pair(buf, name_idx, 0);
    write_fname_pair(buf, type_idx, 0);
    buf.extend_from_slice(&4i32.to_le_bytes()); // Size: 4
    buf.extend_from_slice(&0i32.to_le_bytes()); // ArrayIndex: 0
    buf.push(0u8); // HasPropertyGuid: 0
    // Value payload:
    buf.extend_from_slice(&value.to_le_bytes());
}

/// Write a FloatProperty FPropertyTag + 4-byte LE payload.
pub(crate) fn write_float_property_tag(
    buf: &mut Vec<u8>,
    name_idx: i32,
    type_idx: i32,
    value: f32,
) {
    write_fname_pair(buf, name_idx, 0);
    write_fname_pair(buf, type_idx, 0);
    buf.extend_from_slice(&4i32.to_le_bytes()); // Size: 4
    buf.extend_from_slice(&0i32.to_le_bytes()); // ArrayIndex: 0
    buf.push(0u8); // HasPropertyGuid: 0
    buf.extend_from_slice(&value.to_le_bytes());
}

/// Write a StrProperty FPropertyTag + FString payload.
pub(crate) fn write_str_property_tag(
    buf: &mut Vec<u8>,
    name_idx: i32,
    type_idx: i32,
    value: &str,
) {
    let bytes = value.as_bytes();
    let str_size = 4 + bytes.len() + 1; // 4 for len field, +1 for null
    write_fname_pair(buf, name_idx, 0);
    write_fname_pair(buf, type_idx, 0);
    buf.extend_from_slice(&(str_size as i32).to_le_bytes()); // Size
    buf.extend_from_slice(&0i32.to_le_bytes()); // ArrayIndex: 0
    buf.push(0u8); // HasPropertyGuid: 0
    // FString payload:
    buf.extend_from_slice(&((bytes.len() + 1) as i32).to_le_bytes());
    buf.extend_from_slice(bytes);
    buf.push(0u8); // null terminator
}

/// Write the "None" FPropertyTag terminator.
pub(crate) fn write_none_terminator(buf: &mut Vec<u8>) {
    buf.extend_from_slice(&0i32.to_le_bytes()); // index 0 = "None"
    buf.extend_from_slice(&0i32.to_le_bytes()); // number 0
}
```

- [ ] **Step 4: Add `build_minimal_ue4_27_with_properties()` to `testing/uasset.rs`**

```rust
/// Build a minimal UE4.27 package with three known properties:
/// `bEnabled = true` (BoolProperty), `MaxSpeed = 1500.0` (FloatProperty),
/// `ObjectName = "Hero_C"` (StrProperty).
///
/// The name table is extended relative to `build_minimal_ue4_27`:
///   0 = "None", 1 = "Hero", 2 = "bEnabled", 3 = "BoolProperty",
///   4 = "MaxSpeed", 5 = "FloatProperty", 6 = "ObjectName", 7 = "StrProperty"
///
/// Returns a `MinimalPackage` whose `payloads[0]` will decode as
/// `PropertyBag::Tree` with exactly three `Property` entries.
#[cfg(feature = "__test_utils")]
pub fn build_minimal_ue4_27_with_properties() -> MinimalPackage {
    use std::io::{Cursor, Write};
    use byteorder::{LittleEndian, WriteBytesExt};

    // Build the property payload first so we know its size.
    let mut payload = Vec::new();
    write_bool_property_tag(&mut payload, 2, 3, true);  // bEnabled = true
    write_float_property_tag(&mut payload, 4, 5, 1500.0); // MaxSpeed = 1500.0
    write_str_property_tag(&mut payload, 6, 7, "Hero_C"); // ObjectName = "Hero_C"
    write_none_terminator(&mut payload);

    // Build the rest of the package using the same pattern as
    // build_minimal_ue4_27(), but with an 8-entry name table and
    // the real payload bytes.
    let names = vec![
        "None", "Hero", "bEnabled", "BoolProperty",
        "MaxSpeed", "FloatProperty", "ObjectName", "StrProperty",
    ];
    // (delegate to the internal builder with the extended name table)
    build_with_payload(names, payload)
}

/// Internal builder: constructs a minimal UE4.27 package with a custom
/// name table and export payload. Follows the same two-pass layout as
/// `build_minimal_ue4_27`.
fn build_with_payload(names: Vec<&str>, payload: Vec<u8>) -> MinimalPackage {
    // Delegate to build_minimal_ue4_27's logic but parameterised.
    // Rather than duplicating the layout logic, extend MinimalPackage
    // to accept an injected payload.
    //
    // Implementation note: read build_minimal_ue4_27 in this file and
    // extract its header-writing logic into a shared helper if the two
    // differ only in name-table + payload. Keeping them separate is
    // acceptable if the code remains readable.
    todo!("delegate to shared header builder — see build_minimal_ue4_27 for the layout")
}
```

**Important:** Before committing, replace the `todo!` with a real implementation that reuses `build_minimal_ue4_27`'s header serialization logic. The cleanest approach is to refactor `build_minimal_ue4_27` to accept `(names: &[&str], payload: Vec<u8>)` and call it from both:

```rust
pub fn build_minimal_ue4_27() -> MinimalPackage {
    build_with_payload(
        &["None", "Default__Object"],
        vec![0u8; 84], // opaque filler
    )
}

pub fn build_minimal_ue4_27_with_properties() -> MinimalPackage {
    let mut payload = Vec::new();
    write_bool_property_tag(&mut payload, 2, 3, true);
    write_float_property_tag(&mut payload, 4, 5, 1500.0);
    write_str_property_tag(&mut payload, 6, 7, "Hero_C");
    write_none_terminator(&mut payload);
    build_with_payload(
        &[
            "None", "Hero", "bEnabled", "BoolProperty",
            "MaxSpeed", "FloatProperty", "ObjectName", "StrProperty",
        ],
        payload,
    )
}

fn build_with_payload(names: &[&str], export_payload: Vec<u8>) -> MinimalPackage {
    // Full package header layout from build_minimal_ue4_27 — parameterised
    // on names and payload. Write the FPackageFileSummary, name table,
    // import table (empty), export table (one entry), then payload.
    // (See build_minimal_ue4_27 for the detailed implementation.)
    // ...
}
```

- [ ] **Step 5: Extend `cross_validate_with_unreal_asset` in `fixture-gen/src/uasset.rs`**

Do **not** add a separate `cross_validate_properties_with_unreal_asset` function — extend the existing `cross_validate_with_unreal_asset` at `crates/paksmith-fixture-gen/src/uasset.rs:56-83` with property assertions, reusing the verified `Asset::new` setup. The function already does the header-level checks (name count, imports.len(), exports.len()) and is already called from `write_minimal_ue4_27`; layering property assertions on top keeps the verification single-pass.

Per Step 1's API verification (run that grep first; don't write code if any accessor is missing): append after the existing `asset.asset_data.exports.len() == 1` assertion:

```rust
// Phase 2b: assert the property tree the fixture-gen wrote round-trips
// through unreal_asset's parser. The exact accessor names below are
// confirmed in Step 1 — adjust if the unreal_asset API differs.
let export = asset
    .asset_data
    .exports
    .first()
    .ok_or_else(|| anyhow::anyhow!("expected at least one export"))?;

let normal = export
    .get_normal_export()
    .ok_or_else(|| anyhow::anyhow!("expected NormalExport"))?;

anyhow::ensure!(
    normal.properties.len() == 3,
    "unreal_asset saw {} properties; paksmith wrote 3",
    normal.properties.len()
);
let prop_names: Vec<String> = normal
    .properties
    .iter()
    .map(|p| p.get_name().get_owned_content())
    .collect();
anyhow::ensure!(prop_names.contains(&"bEnabled".to_string()), "missing bEnabled");
anyhow::ensure!(prop_names.contains(&"MaxSpeed".to_string()), "missing MaxSpeed");
anyhow::ensure!(prop_names.contains(&"ObjectName".to_string()), "missing ObjectName");
```

If `cross_validate_with_unreal_asset` is currently called only from `write_minimal_ue4_27`, branch the new property assertions on a parameter (e.g. `expect_properties: bool`) or split the property-assertion arm into a private helper that `write_minimal_ue4_27_with_properties` calls in addition to the base validator. Don't add a second top-level `Asset::new` call — that would double the cross-parser cost.

Add the writer entry point used by `main.rs`:

```rust
pub fn write_minimal_ue4_27_with_properties(path: &std::path::Path) -> anyhow::Result<()> {
    use paksmith_core::testing::uasset::build_minimal_ue4_27_with_properties;
    let pkg = build_minimal_ue4_27_with_properties();
    std::fs::write(path, &pkg.bytes)?;
    // Single cross-parser pass: header + property assertions.
    cross_validate_with_unreal_asset(&pkg.bytes)?;
    println!("wrote + cross-validated {}", path.display());
    Ok(())
}
```

Confirm compilation:

```bash
cargo check -p paksmith-fixture-gen 2>&1 | grep -E "error\[|no method|not found" | head -20
```

Adjust any accessor calls if the Step 1 verification surfaced a different API spelling.

- [ ] **Step 6: Run fixture-gen to produce the updated pak**

```bash
cargo run -p paksmith-fixture-gen 2>&1 | tail -20
```

Expected: `wrote + cross-validated tests/fixtures/real_v8b_uasset.pak` (or similar) with no errors.

- [ ] **Step 7: Update the fixture anchor SHA1**

In `crates/paksmith-core/tests/fixture_anchor.rs` (established in Phase 2a Task 15), update the SHA1 pin for `real_v8b_uasset.pak` with the new hash:

```bash
sha1sum tests/fixtures/real_v8b_uasset.pak
```

Replace the previous hash in the anchor test.

- [ ] **Step 8: Run full test suite**

```bash
cargo test --workspace 2>&1 | tail -20
```

Expected: all tests pass.

- [ ] **Step 9: Run workspace clippy**

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

- [ ] **Step 10: Commit**

```bash
git add crates/paksmith-core/src/testing/uasset.rs \
        crates/paksmith-fixture-gen/src/uasset.rs \
        crates/paksmith-core/tests/fixture_anchor.rs \
        tests/fixtures/real_v8b_uasset.pak
git commit -m "$(cat <<'EOF'
feat(fixture-gen): emit FPropertyTag bytes; cross-validate properties (Phase 2b)

build_minimal_ue4_27_with_properties() emits a 3-property export
(bEnabled=true, MaxSpeed=1500.0, ObjectName="Hero_C"). Fixture-gen
cross-validates property names against unreal_asset at commit
f4df5d8e. Fixture anchor SHA1 updated for real_v8b_uasset.pak.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task 10: Integration tests (`property_integration.rs`)

**Files:**

- Create: `crates/paksmith-core/tests/property_integration.rs`

**Why:** End-to-end test: load the fixture pak → extract the uasset → parse → assert property tree values. This test validates the full stack (pak → bytes → header → properties) rather than individual components.

- [ ] **Step 1: Create `property_integration.rs`**

```rust
//! End-to-end integration tests for Phase 2b property parsing.
//!
//! Requires the fixture pak generated by `paksmith-fixture-gen`.
//! If the fixture is missing, the test panics with a clear message
//! (same policy as `fixture_anchor.rs`).

use std::path::Path;

use paksmith_core::asset::{
    package::Package,
    property::{PropertyBag, PropertyValue},
};

fn fixture_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures/real_v8b_uasset.pak")
}

#[test]
fn pak_uasset_decodes_property_tree() {
    let pak = fixture_path();
    assert!(
        pak.exists(),
        "fixture {} missing — run `cargo run -p paksmith-fixture-gen`",
        pak.display()
    );

    let pkg = Package::read_from_pak(&pak, "Game/Maps/Demo.uasset")
        .expect("failed to parse package");

    assert_eq!(pkg.payloads.len(), 1, "expected one export");

    let bag = &pkg.payloads[0];
    let props = match bag {
        PropertyBag::Tree { properties } => properties,
        other => panic!("expected PropertyBag::Tree, got {other:?}"),
    };

    // Three properties: bEnabled, MaxSpeed, ObjectName
    assert_eq!(props.len(), 3, "expected 3 properties, got {}", props.len());

    let enabled = props.iter().find(|p| p.name == "bEnabled")
        .expect("bEnabled not found");
    assert_eq!(enabled.value, PropertyValue::Bool(true));

    let speed = props.iter().find(|p| p.name == "MaxSpeed")
        .expect("MaxSpeed not found");
    assert_eq!(speed.value, PropertyValue::Float(1500.0));

    let name = props.iter().find(|p| p.name == "ObjectName")
        .expect("ObjectName not found");
    assert_eq!(name.value, PropertyValue::Str("Hero_C".to_string()));
}

#[cfg(feature = "__test_utils")]
#[test]
fn unversioned_flag_is_rejected() {
    use paksmith_core::asset::Package;
    use paksmith_core::error::{AssetParseFault, PaksmithError};
    use paksmith_core::testing::uasset::build_minimal_ue4_27;

    // Task 9 Step 2 added `package_flags_offset: usize` to MinimalPackage,
    // populated during the two-pass header write. Reading the byte
    // position from the builder is robust against future field additions
    // in FPackageFileSummary.
    let pkg = build_minimal_ue4_27();
    let mut pkg_bytes = pkg.bytes.clone();
    let off = pkg.package_flags_offset;

    // Flip the PKG_UnversionedProperties bit (0x0000_2000) in place.
    let mut flags = u32::from_le_bytes(pkg_bytes[off..off + 4].try_into().unwrap());
    flags |= 0x0000_2000;
    pkg_bytes[off..off + 4].copy_from_slice(&flags.to_le_bytes());

    let err = Package::read_from(&pkg_bytes, "x.uasset").unwrap_err();
    assert!(
        matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::UnversionedPropertiesUnsupported,
                ..
            }
        ),
        "expected UnversionedPropertiesUnsupported; got: {err:?}"
    );
}

#[test]
fn opaque_fallback_for_truncated_payload() {
    // An export whose payload is truncated (fewer bytes than serial_size)
    // should fall back to PropertyBag::Opaque rather than panicking.
    // Build such a package in memory and assert the fallback fires.
    //
    // Full implementation: use build_minimal_ue4_27() and truncate
    // the bytes to 1 byte past the header — property read fails,
    // fallback to Opaque.
    #[cfg(feature = "__test_utils")]
    {
        use paksmith_core::testing::uasset::build_minimal_ue4_27;
        let pkg_bytes = build_minimal_ue4_27().bytes.clone();
        // Truncate: keep header + 1 byte so property read gets EOF.
        let summary_end = build_minimal_ue4_27().summary.total_header_size as usize;
        let truncated = &pkg_bytes[..summary_end + 1];

        let pkg = Package::read_from(truncated, "x.uasset")
            .expect("truncated package should return Ok (Opaque fallback)");

        assert!(
            matches!(pkg.payloads[0], PropertyBag::Opaque { .. }),
            "expected Opaque fallback for truncated payload"
        );
    }
}
```

- [ ] **Step 2: Run tests**

```bash
cargo test -p paksmith-core --test property_integration 2>&1 | tail -20
```

Expected: `pak_uasset_decodes_property_tree` passes; the `__test_utils`-gated tests are skipped in CI unless the feature is enabled.

- [ ] **Step 3: Run workspace clippy**

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

- [ ] **Step 4: Commit**

```bash
git add crates/paksmith-core/tests/property_integration.rs
git commit -m "$(cat <<'EOF'
test(asset): property_integration end-to-end tests (Phase 2b)

Loads real_v8b_uasset.pak, asserts PropertyBag::Tree with 3 known
properties (Bool/Float/Str). Includes stubs for unversioned-flag
rejection and opaque-fallback tests gated on __test_utils.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task 11: Proptest (`property_proptest.rs`)

**Files:**

- Create: `crates/paksmith-core/tests/property_proptest.rs`

**Why:** Proptest finds edge cases in primitive readers that hand-written tests miss — particularly around boundary values (i32::MIN, f32::NAN, empty strings) and the security cap thresholds.

- [ ] **Step 1: Create `property_proptest.rs`**

```rust
//! Property-based tests for Phase 2b property parsing.
//!
//! Covers: primitive value round-trips, security cap rejections,
//! and cursor-position invariants.

use std::io::Cursor;
use std::sync::Arc;

use paksmith_core::asset::{
    name_table::{FName, NameTable},
    version::AssetVersion,
    import_table::ImportTable,
    export_table::ExportTable,
    property::{
        primitives::{read_primitive_value, PropertyValue},
        tag::PropertyTag,
        read_properties,
        // MAX_TAGS_PER_EXPORT is not imported here — the cap test
        // lives in Task 6's mod.rs unit tests where the constant is
        // a `use super::*;` away. Importing it here without a
        // consumer in this file would trip clippy under `-D warnings`.
    },
    AssetContext,
};
use paksmith_core::error::{AssetParseFault, PaksmithError};
use proptest::prelude::*;

fn make_ctx(names: &[&str]) -> AssetContext {
    let table = NameTable { names: names.iter().map(|n| FName::new(n)).collect() };
    AssetContext {
        names: Arc::new(table),
        imports: Arc::new(ImportTable::default()),
        exports: Arc::new(ExportTable::default()),
        version: AssetVersion::default(),
    }
}

fn make_tag(type_name: &str, size: i32) -> PropertyTag {
    PropertyTag {
        name: "Prop".to_string(),
        type_name: type_name.to_string(),
        size,
        array_index: 0,
        bool_val: false,
        struct_name: String::new(),
        struct_guid: [0u8; 16],
        enum_name: String::new(),
        inner_type: String::new(),
        value_type: String::new(),
        guid: None,
    }
}

proptest! {
    #[test]
    fn int_property_round_trip(v in i32::MIN..=i32::MAX) {
        let tag = make_tag("IntProperty", 4);
        let ctx = make_ctx(&["None"]);
        let buf = v.to_le_bytes();
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf[..]), &ctx, "x")
            .unwrap()
            .unwrap();
        prop_assert_eq!(val, PropertyValue::Int(v));
    }

    #[test]
    fn int64_property_round_trip(v in i64::MIN..=i64::MAX) {
        let tag = make_tag("Int64Property", 8);
        let ctx = make_ctx(&["None"]);
        let buf = v.to_le_bytes();
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf[..]), &ctx, "x")
            .unwrap()
            .unwrap();
        prop_assert_eq!(val, PropertyValue::Int64(v));
    }

    #[test]
    fn uint32_property_round_trip(v in 0u32..=u32::MAX) {
        let tag = make_tag("UInt32Property", 4);
        let ctx = make_ctx(&["None"]);
        let buf = v.to_le_bytes();
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf[..]), &ctx, "x")
            .unwrap()
            .unwrap();
        prop_assert_eq!(val, PropertyValue::UInt32(v));
    }

    #[test]
    fn float_property_round_trip(bits in 0u32..=u32::MAX) {
        // Any 4-byte pattern is a valid f32 (NaN, inf included).
        let v = f32::from_bits(bits);
        let tag = make_tag("FloatProperty", 4);
        let ctx = make_ctx(&["None"]);
        let buf = v.to_le_bytes();
        let val = read_primitive_value(&tag, &mut Cursor::new(&buf[..]), &ctx, "x")
            .unwrap()
            .unwrap();
        // f32::NaN != f32::NaN, so direct prop_assert_eq! on the value
        // would spuriously fail for every NaN bit pattern. Compare bits
        // instead. TestCaseError::fail(reason: impl Into<Reason>)
        // accepts &'static str; verified against proptest 1.11.0
        // (`proptest/src/test_runner/errors.rs` v1.11.0).
        if let PropertyValue::Float(got) = val {
            prop_assert_eq!(got.to_bits(), v.to_bits());
        } else {
            return Err(TestCaseError::fail("expected Float variant"));
        }
    }

    #[test]
    fn bool_property_round_trip(v in any::<bool>()) {
        let mut tag = make_tag("BoolProperty", 0);
        tag.bool_val = v;
        let ctx = make_ctx(&["None"]);
        let val = read_primitive_value(&tag, &mut Cursor::new(&[][..]), &ctx, "x")
            .unwrap()
            .unwrap();
        prop_assert_eq!(val, PropertyValue::Bool(v));
    }
}

#[test]
fn negative_size_rejected_in_read_properties() {
    // Build a stream with a tag whose size field is negative.
    // names: 0=None, 1=Foo, 2=IntProperty
    let ctx = make_ctx(&["None", "Foo", "IntProperty"]);
    let mut buf = Vec::new();
    buf.extend_from_slice(&1i32.to_le_bytes()); // Name: Foo
    buf.extend_from_slice(&0i32.to_le_bytes());
    buf.extend_from_slice(&2i32.to_le_bytes()); // Type: IntProperty
    buf.extend_from_slice(&0i32.to_le_bytes());
    buf.extend_from_slice(&(-5i32).to_le_bytes()); // Size: -5
    buf.extend_from_slice(&0i32.to_le_bytes()); // ArrayIndex
    buf.push(0u8); // HasPropertyGuid
    let export_end = buf.len() as u64 + 4;
    let err = read_properties(&mut Cursor::new(&buf), &ctx, 0, export_end, "x").unwrap_err();
    // Reuses the existing AssetParseFault::NegativeValue variant — see Task 1.
    assert!(matches!(
        err,
        PaksmithError::AssetParse {
            fault: AssetParseFault::NegativeValue {
                field: paksmith_core::error::AssetWireField::PropertyTagSize,
                ..
            },
            ..
        }
    ));
}

#[test]
fn oversized_property_rejected() {
    use paksmith_core::asset::property::tag::MAX_PROPERTY_TAG_SIZE;
    use paksmith_core::error::BoundsUnit;
    let ctx = make_ctx(&["None", "Foo", "StrProperty"]);
    let mut buf = Vec::new();
    buf.extend_from_slice(&1i32.to_le_bytes());
    buf.extend_from_slice(&0i32.to_le_bytes());
    buf.extend_from_slice(&2i32.to_le_bytes());
    buf.extend_from_slice(&0i32.to_le_bytes());
    buf.extend_from_slice(&(MAX_PROPERTY_TAG_SIZE + 1).to_le_bytes());
    buf.extend_from_slice(&0i32.to_le_bytes());
    buf.push(0u8);
    let export_end = (buf.len() + MAX_PROPERTY_TAG_SIZE as usize + 2) as u64;
    let err = read_properties(&mut Cursor::new(&buf), &ctx, 0, export_end, "x").unwrap_err();
    // Reuses the existing AssetParseFault::BoundsExceeded variant — see Task 1.
    assert!(matches!(
        err,
        PaksmithError::AssetParse {
            fault: AssetParseFault::BoundsExceeded {
                field: paksmith_core::error::AssetWireField::PropertyTagSize,
                unit: BoundsUnit::Bytes,
                ..
            },
            ..
        }
    ));
}

#[test]
fn depth_exceeded_is_rejected() {
    let ctx = make_ctx(&["None"]);
    let err = read_properties(
        &mut Cursor::new(&[][..]),
        &ctx,
        129, // > MAX_PROPERTY_DEPTH
        0,
        "x",
    ).unwrap_err();
    assert!(matches!(
        err,
        PaksmithError::AssetParse {
            fault: AssetParseFault::PropertyDepthExceeded { depth: 129, limit: 128 },
            ..
        }
    ));
}
```

- [ ] **Step 2: Run the proptest suite**

```bash
cargo test -p paksmith-core --test property_proptest 2>&1 | tail -20
```

Expected: all tests pass including proptest cases (default 256 cases per test).

- [ ] **Step 3: Run workspace clippy**

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

- [ ] **Step 4: Commit**

```bash
git add crates/paksmith-core/tests/property_proptest.rs
git commit -m "$(cat <<'EOF'
test(asset): proptest round-trips + cap rejections for Phase 2b

Int/Int64/UInt32/Float round-trip proptests across full value range.
Bool round-trip. Negative-size, oversized, and depth-exceeded cap
rejection tests. Float NaN round-trip via bit comparison.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task 12: Documentation

**Files:**

- Modify: `ARCHITECTURE.md` — update asset/ description to include Phase 2b
- Modify: `README.md` — note that inspect now shows property trees
- Modify: `docs/plans/ROADMAP.md` — mark Phase 2b complete, scope 2c
- Modify: `crates/paksmith-core/src/lib.rs` — update top-doc

**Why:** Docs ship with the code — same precedent as PR #126.

- [ ] **Step 1: Update `ARCHITECTURE.md`**

Find the asset/ module description (added in Phase 2a) and append:

```markdown
Phase 2b adds tagged-property iteration: `asset/property/` submodule
with `FPropertyTag` reader, `Property`/`PropertyValue` types,
`FText` for `ETextHistoryType::None` and `Base`, and
`PropertyBag::Tree { properties: Vec<Property> }`. Unknown/container types skip
via `tag.size`. Security caps: `MAX_TAGS_PER_EXPORT=65536`,
`MAX_PROPERTY_TAG_SIZE=16MiB`, `MAX_PROPERTY_DEPTH=128`.
Assets with `PKG_UnversionedProperties` are rejected early.
```

- [ ] **Step 2: Update `README.md`**

Find the `paksmith inspect` section added in Phase 2a and update the description:

````markdown
### `paksmith inspect`

Dump a uasset's structural header and property tree as JSON. Phase 2b
decodes primitive properties (Bool, Int variants, Float, Double, Str,
Name, Enum, Text). Container properties (Array/Map/Set/Struct) appear
as `Unknown` entries with a `skipped_bytes` count until Phase 2c.

```bash
paksmith inspect path/to/archive.pak Game/Data/Hero.uasset
```
````

- [ ] **Step 3: Update `docs/plans/ROADMAP.md`**

Find the Phase 2 entry. Update the status line to:

```markdown
**Status:** Phase 2a complete (`phase-2a-uasset-header.md`). Phase 2b
complete (`phase-2b-tagged-properties.md`). Phases 2c–2e (container
properties, object refs, .uexp stitching) scoped but not yet planned.
````

- [ ] **Step 4: Update `crates/paksmith-core/src/lib.rs` top-doc**

```rust
//! Core library for parsing and extracting Unreal Engine game assets.
//!
//! **Phase 1 scope**: container readers for the `.pak` archive format
//! (see [`container::pak`]).
//!
//! **Phase 2a scope**: UAsset structural-header parsing —
//! [`asset::PackageSummary`], [`asset::NameTable`], [`asset::ImportTable`],
//! [`asset::ExportTable`], with property bodies carried as opaque
//! byte payloads via [`asset::PropertyBag::Opaque`].
//!
//! **Phase 2b scope** (current): tagged-property iteration —
//! [`asset::PropertyBag::Tree`] replaces `Opaque` for assets with
//! parseable FPropertyTag streams. Primitive property payloads
//! (Bool, Int variants, Float, Double, Str, Name, Enum, Text) are
//! decoded; container/unknown types skip via `tag.size` →
//! [`asset::property::PropertyValue::Unknown`]. Assets with
//! `PKG_UnversionedProperties` are rejected with a typed fault.
//!
//! IoStore, format handlers, and game profile management remain
//! planned per `docs/plans/ROADMAP.md`.
```

- [ ] **Step 5: Run full test suite + clippy**

```bash
cargo test --workspace && cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add ARCHITECTURE.md README.md docs/plans/ROADMAP.md crates/paksmith-core/src/lib.rs
git commit -m "$(cat <<'EOF'
docs: Phase 2b complete — update ARCHITECTURE, README, ROADMAP, lib.rs

ARCHITECTURE.md adds Phase 2b property-system summary to asset/ section.
README.md updates inspect description to mention property tree decoding.
ROADMAP.md marks Phase 2b complete; 2c–2e noted as scoped but unplanned.
lib.rs top-doc adds Phase 2b scope entry.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Self-review checklist (run before opening the PR)

1. **Spec coverage:** every property type listed in scope (Bool/Byte/Int variants/Float/Double/Str/Name/Enum/Text) has a `read_primitive_value` arm and a unit test with hand-crafted bytes. ✓

2. **Wire-stable Display:** every new `AssetParseFault` variant has a `error::tests::asset_parse_display_*` pin. ✓ (6 tests in Task 1)

3. **Security caps:** `MAX_TAGS_PER_EXPORT` and `MAX_PROPERTY_TAG_SIZE` both have unit tests in `property_proptest.rs` and `property::tests`. `MAX_PROPERTY_DEPTH` inherited from Phase 2a; `PropertyDepthExceeded` guard tested. ✓

4. **Cursor-mismatch invariant:** `read_properties` checks `actual_pos == expected_end` after every value (including Unknown skip path). ✓

5. **Unversioned flag:** `PKG_UnversionedProperties = 0x0000_2000` check in `Package::read_from` before property iteration. `UnversionedPropertiesUnsupported` Display pinned. ✓

6. **No panics:** the only `unimplemented!` is the `build_with_payload` stub in Task 9, which is replaced before commit. The `todo!` in `text.rs` stub is replaced in Task 5. ✓

7. **`#[non_exhaustive]`:** on `PropertyValue`, `FTextHistory`, `PropertyBag` (inherited). ✓

8. **Module structure:** `asset/property/` with `bag.rs`, `tag.rs`, `primitives.rs`, `text.rs`, `mod.rs`. `property_bag.rs` removed. `asset/mod.rs` updated. ✓

9. **Type consistency:** `PropertyTag.struct_name/enum_name/inner_type/value_type` are `String` (resolved at tag-read time). `Property.name` is `String`. `PropertyValue::Name(String)`, `PropertyValue::Enum { type_name: String, value: String }`. ✓

10. **Commit cadence:** one commit per task, ≤ 200 lines of diff each. Task 4 (primitives.rs) may approach the limit due to the test suite; if so, split the type definitions (Step 3 first commit) from the test body (second commit) at implementation time. ✓

11. **Clippy with `--all-targets --all-features`:** every task ends with this command per `MEMORY.md`. ✓

12. **`cargo fmt --all -- --check`:** every task ends with this command. CI's `Lint` job runs both fmt AND clippy; clippy passing locally does NOT imply fmt is clean — see PR #149 follow-up. The `.githooks/pre-commit` hook also enforces this when wired up via `git config core.hooksPath .githooks` (one-time per clone). ✓

13. **Fixture oracle API verified:** the `cross_validate_properties_with_unreal_asset` function compiles before commit. `cargo build -p paksmith-fixture-gen` is the checkpoint. ✓

## Out-of-scope reminders for the implementor

Do not let these creep into the diff:

- `ArrayProperty` contents (inner element parsing) — Phase 2c
- `MapProperty`, `SetProperty` inner parsing — Phase 2c
- `StructProperty` recursion — Phase 2c
- `SoftObjectPath`, `SoftClassPath`, `ObjectProperty` payload — Phase 2d
- `.uexp` companion file merging — Phase 2e
- Unversioned (schema-driven) property decoding — Phase 2f
- `ETextHistoryType` variants other than -1 and 0 (stored as `Unknown` in Phase 2b)
- Asset-level AES decryption
- `AssetRegistry`, `ThumbnailTable`, `GatherableTextData` body parsing
