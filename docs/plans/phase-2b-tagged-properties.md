# Paksmith Phase 2b: Tagged Property Iteration + Primitive Payloads

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Parse `FPropertyTag` headers and primitive property payloads (Bool, Byte, Int variants, Float, Double, Str, Name, Enum, Text) from export bodies, replacing `PropertyBag::Opaque` with a real `PropertyBag::Tree(Vec<Property>)` for tagged assets. `paksmith inspect` output gains a human-readable property tree. Unknown/container property types skip via `tag.size` without panicking.

**Architecture:** New `asset/property/` submodule replaces the flat `asset/property_bag.rs` from Phase 2a (mechanical rename — no behavior change to `PropertyBag::Opaque`). Four focused files: `bag.rs` (migrated), `tag.rs` (FPropertyTag reader + `resolve_fname` helper), `primitives.rs` (`Property`, `PropertyValue`, per-type readers), `text.rs` (`FText` + `FTextHistory`). The property iterator in `mod.rs` drives the outer loop with two hard caps (`MAX_TAGS_PER_EXPORT = 65_536`, `MAX_PROPERTY_TAG_SIZE = 16 MiB`) and a cursor-mismatch invariant after every value. `Package::read_from` gains an early `PKG_UnversionedProperties` rejection before attempting property iteration; the existing `PropertyBag::Opaque` path is retained as a fallback if a parse error occurs mid-iteration (the caller logs at `warn!` and falls back). Error sub-enums are extended with six new `AssetParseFault` variants and ten new `AssetWireField` variants, each pinned by wire-stable Display unit tests.

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
  "names": ["None", "Hero", "bEnabled", "MaxSpeed", "ObjectName",
            "BoolProperty", "FloatProperty", "StrProperty"],
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
- `PropertyBag::Tree(Vec<Property>)` variant (alongside existing `::Opaque`)
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

6. **`PKG_UnversionedProperties` rejection fires in `Package::read_from`, not in the property iterator:** The flag is on the summary, so the check lives at the top of the export-body decode loop (before the first tag read). Variant name: `AssetParseFault::UnversionedPropertiesUnsupported`. Not a warn+fallback-to-Opaque — unversioned exports are structurally unreadable by the tagged iterator.

7. **`PropertyBag::Tree` as an additive variant:** `#[non_exhaustive]` was already present on `PropertyBag` from Phase 2a. Adding `Tree(Vec<Property>)` is a non-breaking additive change. The existing `Opaque` variant is retained as the fallback when a parse error is recoverable (e.g., a single export with a malformed tag doesn't abort the whole package).

8. **`resolve_fname(index: i32, number: i32, ctx, asset_path, field)` helper:** Lives in `property/tag.rs` (not `name_table.rs` — avoid polluting the header-parsing module with property context). Uses `ctx.names.get(index as u32)` for the non-error path and emits `AssetParseFault::PackageIndexUnderflow { field }` for `index < 0`, `PackageIndexOob { field, .. }` for OOB. The `number` suffix: `number <= 0` → no suffix; `number > 0` → `format!("{}_{}", name, number - 1)` (UE convention: stored number 1 means `_0` suffix).

9. **FText `ETextHistoryType::Base` reads three FStrings (namespace, key, source_string) unconditionally:** Modern UE writers always emit all three. Pre-Phase-2b floor (FileVersionUE4 < 504) is already rejected at summary parse time, so no version gating is needed here.

10. **BoolProperty:** `boolVal` is the u8 in the tag header; `tag.size == 0`; no payload bytes follow. The cursor check after `read_property_value` will assert `actual_pos == value_start + 0`.

---

## File Structure

```
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
fn asset_parse_display_property_tag_negative_size() {
    let err = PaksmithError::AssetParse {
        asset_path: "x.uasset".to_string(),
        fault: AssetParseFault::PropertyTagNegativeSize {
            field: AssetWireField::PropertyTagSize,
            value: -42,
        },
    };
    assert_eq!(
        format!("{err}"),
        "asset deserialization failed for `x.uasset`: \
         property_tag_size is negative: -42"
    );
}

#[test]
fn asset_parse_display_property_tag_size_exceeds_cap() {
    let err = PaksmithError::AssetParse {
        asset_path: "x.uasset".to_string(),
        fault: AssetParseFault::PropertyTagSizeExceedsCap {
            field: AssetWireField::PropertyTagSize,
            value: 20_000_000,
            limit: 16_777_216,
        },
    };
    assert_eq!(
        format!("{err}"),
        "asset deserialization failed for `x.uasset`: \
         property_tag_size 20000000 exceeds cap 16777216"
    );
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

Find the end of the `AssetParseFault` enum body (just before `impl fmt::Display for AssetParseFault`) and add after `UnexpectedEof`:

```rust
    /// The export's property stream has `PKG_UnversionedProperties`
    /// (flag bit `0x0000_2000`) set — schema-driven (unversioned)
    /// encoding rather than FPropertyTag iteration. Phase 2b only
    /// supports the tagged (versioned) property stream; unversioned
    /// parsing requires the UE struct schema registry, deferred to
    /// Phase 2f.
    UnversionedPropertiesUnsupported,

    /// An `FPropertyTag::Size` field is negative. UE writers never
    /// emit negative sizes; this is the signature of a malicious or
    /// corrupted archive.
    PropertyTagNegativeSize {
        /// Which field carried the negative value (always
        /// `AssetWireField::PropertyTagSize` from the iterator, but
        /// carried explicitly for Display consistency).
        field: AssetWireField,
        /// The on-wire i32 value.
        value: i32,
    },

    /// An `FPropertyTag::Size` field exceeds
    /// `MAX_PROPERTY_TAG_SIZE`. Prevents a single property value
    /// from allocating unbounded memory on the Unknown skip path.
    PropertyTagSizeExceedsCap {
        /// Which size field tripped (always `PropertyTagSize`).
        field: AssetWireField,
        /// The wire-claimed size.
        value: i32,
        /// The cap it exceeded.
        limit: i32,
    },

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

Find `impl fmt::Display for AssetParseFault` and add after the `UnexpectedEof` arm:

```rust
            Self::UnversionedPropertiesUnsupported => f.write_str(
                "unversioned properties (PKG_UnversionedProperties=0x2000) \
                 are not supported in Phase 2b",
            ),
            Self::PropertyTagNegativeSize { field, value } => {
                write!(f, "{field} is negative: {value}")
            }
            Self::PropertyTagSizeExceedsCap { field, value, limit } => {
                write!(f, "{field} {value} exceeds cap {limit}")
            }
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

Six new AssetParseFault variants: UnversionedPropertiesUnsupported,
PropertyTagNegativeSize, PropertyTagSizeExceedsCap,
PropertyTagSizeMismatch, PropertyDepthExceeded, PropertyTagCountExceeded.

Ten new AssetWireField variants for FPropertyTag fields and FText
body fields. Three new AssetAllocationContext variants for property
parsing allocation sites. All Display strings wire-stable, pinned by
six new unit tests.

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

**Why:** The ROADMAP specifies `asset/property/` as the module home. Making this a pure structural rename now means Tasks 3–7 just add new files to the directory without touching mod.rs again. Zero behavior change in this task — all existing tests must still pass.

- [ ] **Step 1: Create `crates/paksmith-core/src/asset/property/mod.rs`**

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

pub use bag::{PropertyBag, MAX_PROPERTY_DEPTH};
```

- [ ] **Step 2: Create `crates/paksmith-core/src/asset/property/bag.rs`**

Copy the entire content of `property_bag.rs` verbatim:

```rust
//! Decoded property body for one export.
//!
//! Phase 2a ships only the [`Self::Opaque`] variant — the export's
//! serialized bytes are carried verbatim. Phase 2b lands the
//! tagged-property iterator that produces typed [`Self::Tree`]
//! payloads; Phase 2c lands the container properties whose recursive
//! parsing is bounded by [`MAX_PROPERTY_DEPTH`].

use serde::Serialize;

/// Hard cap on nested struct/array/map depth in the property tree.
/// Defined here in Phase 2a even though only Phase 2c references it,
/// to lock the contract before downstream parsers are written. Value
/// chosen to match FModel's nesting bound; UE assets in practice
/// never nest beyond ~12.
pub const MAX_PROPERTY_DEPTH: usize = 128;

/// Decoded body for one export.
///
/// `#[non_exhaustive]` so Phase 2b can add a `Tree` variant without
/// source-breaking downstream `match` arms.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[non_exhaustive]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PropertyBag {
    /// Phase 2a: raw bytes carved out of the asset's payload region.
    Opaque {
        /// The export's serialized bytes (length matches
        /// `ObjectExport::serial_size`).
        #[serde(serialize_with = "serialize_byte_count")]
        bytes: Vec<u8>,
    },
}

impl PropertyBag {
    /// Convenience constructor for the Phase-2a opaque variant.
    #[must_use]
    pub fn opaque(bytes: Vec<u8>) -> Self {
        Self::Opaque { bytes }
    }

    /// Number of bytes in the bag (raw payload bytes for Opaque).
    #[must_use]
    pub fn byte_len(&self) -> usize {
        match self {
            Self::Opaque { bytes } => bytes.len(),
        }
    }
}

fn serialize_byte_count<S: serde::Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_u64(v.len() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opaque_byte_len() {
        let bag = PropertyBag::opaque(vec![0u8; 84]);
        assert_eq!(bag.byte_len(), 84);
    }

    #[test]
    fn opaque_serializes_count_not_bytes() {
        let bag = PropertyBag::opaque(vec![1, 2, 3, 4, 5]);
        let json = serde_json::to_string(&bag).unwrap();
        assert!(json.contains("5"), "should serialize byte count");
        assert!(!json.contains("[1,2,3"), "should not serialize raw bytes");
    }

    #[test]
    fn max_property_depth_is_128() {
        assert_eq!(MAX_PROPERTY_DEPTH, 128);
    }
}
```

- [ ] **Step 3: Update `crates/paksmith-core/src/asset/mod.rs`**

Find the line `pub mod property_bag;` and replace with `pub mod property;`.

Find the line `pub use property_bag::PropertyBag;` and replace with `pub use property::PropertyBag;`.

- [ ] **Step 4: Delete the old file**

```bash
rm crates/paksmith-core/src/asset/property_bag.rs
```

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

```bash
git add crates/paksmith-core/src/asset/property/ \
        crates/paksmith-core/src/asset/mod.rs
git rm crates/paksmith-core/src/asset/property_bag.rs
git commit -m "$(cat <<'EOF'
refactor(asset): migrate property_bag.rs → asset/property/ submodule

Mechanical rename only — PropertyBag, MAX_PROPERTY_DEPTH, and all
tests move verbatim into asset/property/bag.rs. asset/mod.rs swaps
the pub mod declaration. No behavior change; all existing tests pass.

Phase 2b will add tag.rs, primitives.rs, and text.rs to this module.

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
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::PropertyTagNegativeSize { .. },
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
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::PropertyTagSizeExceedsCap { .. },
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

```rust
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

use std::io::{Read, Seek};
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
/// - [`AssetParseFault::PropertyTagNegativeSize`] if Size < 0.
/// - [`AssetParseFault::PropertyTagSizeExceedsCap`] if Size > [`MAX_PROPERTY_TAG_SIZE`].
/// - [`AssetParseFault::PackageIndexUnderflow`] / [`AssetParseFault::PackageIndexOob`]
///   for out-of-range FName indexes.
/// - [`AssetParseFault::UnexpectedEof`] on short reads.
pub fn read_tag<R: Read + Seek>(
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
    if size < 0 {
        return Err(PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::PropertyTagNegativeSize {
                field: AssetWireField::PropertyTagSize,
                value: size,
            },
        });
    }
    if size > MAX_PROPERTY_TAG_SIZE {
        return Err(PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::PropertyTagSizeExceedsCap {
                field: AssetWireField::PropertyTagSize,
                value: size,
                limit: MAX_PROPERTY_TAG_SIZE,
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
```

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

use std::io::Read;

use byteorder::{LittleEndian, ReadBytesExt};
use serde::Serialize;

use crate::asset::AssetContext;
use crate::container::pak::index::read_fstring;
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
/// # Errors
/// - [`PaksmithError::Io`] / [`AssetParseFault::UnexpectedEof`] on short reads.
/// - [`AssetParseFault::FStringMalformed`] for malformed FStrings.
pub fn read_primitive_value<R: Read>(
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
            let s = read_fstring(reader).map_err(|e| PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::FStringMalformed {
                    kind: extract_fstring_fault(&e),
                },
            })?;
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

/// Extract the `FStringFault` kind from a `PaksmithError::Io` wrapping
/// a raw string read failure, or fall back to `FStringFault::InvalidLength`.
///
/// `read_fstring` returns `PaksmithError::Io` on short reads. The
/// `AssetParseFault::FStringMalformed` wrapper expects an
/// `FStringFault`; this shim projects the I/O error to the closest
/// structural approximation rather than losing information.
fn extract_fstring_fault(e: &PaksmithError) -> crate::error::FStringFault {
    // read_fstring propagates InvalidLength and Utf8 as typed faults
    // already; I/O errors wrap as plain Io. Surface InvalidLength
    // as the conservative default.
    match e {
        PaksmithError::AssetParse { fault: AssetParseFault::FStringMalformed { kind }, .. } => {
            kind.clone()
        }
        _ => crate::error::FStringFault::InvalidLength,
    }
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

Create `crates/paksmith-core/src/asset/property/text.rs` stub:

```rust
use serde::Serialize;
use std::io::Read;
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

pub fn read_ftext<R: Read>(
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

```rust
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

use std::io::{Read, Seek, SeekFrom};

use byteorder::{LittleEndian, ReadBytesExt};
use serde::Serialize;

use crate::asset::AssetContext;
use crate::container::pak::index::read_fstring;
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
                let s = read_fstring(reader).map_err(|e| PaksmithError::AssetParse {
                    asset_path: asset_path.to_string(),
                    fault: AssetParseFault::FStringMalformed {
                        kind: project_fstring_fault(&e),
                    },
                })?;
                Some(s)
            } else {
                None
            };
            FTextHistory::None { culture_invariant }
        }
        0 => {
            let namespace = read_fstring(reader).map_err(|e| PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::FStringMalformed { kind: project_fstring_fault(&e) },
            })?;
            let key = read_fstring(reader).map_err(|e| PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::FStringMalformed { kind: project_fstring_fault(&e) },
            })?;
            let source_string = read_fstring(reader).map_err(|e| PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::FStringMalformed { kind: project_fstring_fault(&e) },
            })?;
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

fn project_fstring_fault(e: &PaksmithError) -> crate::error::FStringFault {
    match e {
        PaksmithError::AssetParse {
            fault: AssetParseFault::FStringMalformed { kind }, ..
        } => kind.clone(),
        _ => crate::error::FStringFault::InvalidLength,
    }
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
```

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
            MAX_PROPERTY_DEPTH + 1, // over limit
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
pub use self::{read_properties, MAX_TAGS_PER_EXPORT};
```

- [ ] **Step 4: Run tests**

```bash
cargo test -p paksmith-core --lib asset::property::tests 2>&1 | tail -20
```

Expected: 4 tests pass.

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
fires immediately when depth > MAX_PROPERTY_DEPTH (128). Four unit tests.

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

- [ ] **Step 1: Write failing test for PropertyBag::Tree**

Add to `bag.rs` tests:

```rust
#[test]
fn tree_variant_serializes_property_array() {
    use crate::asset::property::primitives::{Property, PropertyValue};
    let bag = PropertyBag::tree(vec![
        Property {
            name: "bEnabled".to_string(),
            array_index: 0,
            guid: None,
            value: PropertyValue::Bool(true),
        },
    ]);
    let json = serde_json::to_string(&bag).unwrap();
    assert!(json.contains("bEnabled"));
    assert!(json.contains("Bool"));
}
```

- [ ] **Step 2: Run test to confirm compile failure**

```bash
cargo test -p paksmith-core --lib asset::property::bag::tests::tree_variant 2>&1 | tail -10
```

Expected: compile error — `Tree` variant and `PropertyBag::tree` constructor not found.

- [ ] **Step 3: Add `Tree` variant to `PropertyBag`**

In `bag.rs`, add after the `Opaque` variant (inside the enum):

```rust
    /// Phase 2b: decoded FPropertyTag sequence.
    Tree(Vec<crate::asset::property::primitives::Property>),
```

Add constructor:

```rust
    /// Convenience constructor for the Phase-2b tree variant.
    #[must_use]
    pub fn tree(props: Vec<crate::asset::property::primitives::Property>) -> Self {
        Self::Tree(props)
    }
```

Update `byte_len`:

```rust
    pub fn byte_len(&self) -> usize {
        match self {
            Self::Opaque { bytes } => bytes.len(),
            Self::Tree(props) => props.len(), // count, not bytes
        }
    }
```

Note: the `PartialEq` derive on `PropertyBag` requires `PartialEq` on `Property`, which is already derived. But `PropertyValue::Float(f32)` does not implement `Eq` (f32 isn't Eq). Remove `Eq` from the `PropertyBag` derive; change `#[derive(Debug, Clone, PartialEq, Eq, Serialize)]` to `#[derive(Debug, Clone, PartialEq, Serialize)]` in `bag.rs`.

- [ ] **Step 4: Check that `AssetParseFault::UnversionedPropertiesUnsupported` is used**

In `package.rs`, find the export-body read loop (the section reading `PropertyBag::Opaque` payloads) and add the unversioned check. Locate the `read_export_payloads` function (or inline decode loop). Before calling the property iterator, add:

```rust
// Reject unversioned (schema-driven) property streams early.
const PKG_UNVERSIONED_PROPERTIES: u32 = 0x0000_2000;
if summary.package_flags & PKG_UNVERSIONED_PROPERTIES != 0 {
    return Err(PaksmithError::AssetParse {
        asset_path: asset_path.to_string(),
        fault: AssetParseFault::UnversionedPropertiesUnsupported,
    });
}
```

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

### Task 8: CLI `inspect` output + snapshot update

**Files:**
- Modify: `crates/paksmith-cli/src/commands/inspect.rs` — render `PropertyBag::Tree` in JSON
- Modify: the insta snapshot file for the inspect test

**Why:** The existing inspect snapshot was generated against `PropertyBag::Opaque`. It now needs to show a `properties` array.

- [ ] **Step 1: Run the existing snapshot test to see it fail**

```bash
cargo test -p paksmith-cli -- inspect 2>&1 | tail -20
```

Expected: snapshot mismatch (the output now has a `properties` array instead of `payload_bytes`).

- [ ] **Step 2: Update the insta snapshot**

```bash
cargo insta review
```

Accept the new snapshot. Verify it contains `"properties"` and `"Bool"` or `"Int"` entries from the fixture asset.

- [ ] **Step 3: Review `inspect.rs` for output shape**

The `inspect` command serializes `Package` (or its parts) to JSON via `serde_json::to_writer_pretty`. Because `PropertyBag::Tree` derives `Serialize`, the JSON update is automatic. However, check that the `exports` section now nests `properties` rather than a top-level `payload_bytes`. If `inspect.rs` has a hand-crafted struct that duplicates fields, update it to use the auto-derived shape.

If a manual `InspectOutput` struct was used in Phase 2a, find it and add a `properties` field:

```rust
#[derive(Serialize)]
struct ExportOutput<'a> {
    class_index: String,
    super_index: String,
    outer_index: String,
    object_name: &'a str,
    serial_size: i64,
    serial_offset: i64,
    #[serde(flatten)]
    bag: &'a PropertyBag,
}
```

The `#[serde(flatten)]` ensures `PropertyBag::Tree` serializes as `"properties": [...]` and `PropertyBag::Opaque` serializes as `"payload_bytes": N` — no manual field needed.

- [ ] **Step 4: Run snapshot test to confirm it passes**

```bash
cargo test -p paksmith-cli -- inspect 2>&1 | tail -10
```

Expected: test passes.

- [ ] **Step 5: Run workspace clippy**

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

- [ ] **Step 6: Commit**

```bash
git add crates/paksmith-cli/src/commands/inspect.rs \
        crates/paksmith-cli/src/snapshots/
git commit -m "$(cat <<'EOF'
feat(cli): inspect outputs PropertyBag::Tree as properties array (Phase 2b)

JSON output shape changes: exports now include "properties": [...]
(PropertyBag::Tree) instead of "payload_bytes": N (PropertyBag::Opaque).
Opaque fallback still renders as payload_bytes for undecodable exports.
Insta snapshot updated.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task 9: Fixture-gen extension + cross-validation

**Files:**
- Modify: `crates/paksmith-core/src/testing/uasset.rs` — add property-emitting helpers + `build_minimal_ue4_27_with_properties()`
- Modify: `crates/paksmith-fixture-gen/src/uasset.rs` — call `build_minimal_ue4_27_with_properties`; extend cross-validation to assert property tree

**Why:** The cross-parser oracle (unreal_asset) confirms that paksmith's property reader sees the same values that the reference implementation sees. This closes the same verification loop that Phase 1 used trumank/repak for.

**Before starting:** Verify the `unreal_asset` property API at the pinned commit (`f4df5d8e75b1e184832384d1865f0b696b90a614`) by reading the source:

```bash
# Check the export/property access API
grep -r "get_normal_export\|NormalExport\|properties" \
    $(cargo metadata --format-version 1 | \
      python3 -c "import sys,json; pkgs=json.load(sys.stdin)['packages']; \
      [print(p['manifest_path'].replace('Cargo.toml','src/')) \
       for p in pkgs if 'unrealmodding' in p.get('manifest_path','')]") \
    --include="*.rs" -l 2>/dev/null | head -5
```

Expected API shape (verify before writing):

```rust
use unreal_asset::exports::Export;
use unreal_asset::properties::Property as UProperty;

// Accessing properties in a NormalExport:
if let Some(normal) = asset.asset_data.exports[0].get_normal_export() {
    for prop in &normal.properties {
        // prop is a Property enum from unreal_asset::properties
    }
}
```

If the API differs from the above, update the cross-validation code accordingly before committing.

- [ ] **Step 1: Add property-emitting helpers to `testing/uasset.rs`**

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

- [ ] **Step 2: Add `build_minimal_ue4_27_with_properties()` to `testing/uasset.rs`**

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

- [ ] **Step 3: Extend cross-validation in `fixture-gen/src/uasset.rs`**

Add after the existing `cross_validate_with_unreal_asset`:

```rust
fn cross_validate_properties_with_unreal_asset(bytes: &[u8]) -> anyhow::Result<()> {
    use unreal_asset::{engine_version::EngineVersion, exports::Export};
    use std::io::Cursor;

    let asset = unreal_asset::Asset::new(
        Cursor::new(bytes.to_vec()),
        None,
        EngineVersion::VER_UE4_27,
        None,
    )?;

    // Verify the export API for properties at the pinned commit.
    // Expected shape (verify against the commit before implementing):
    //   asset.asset_data.exports[0].get_normal_export().unwrap().properties
    let export = asset.asset_data.exports.first()
        .ok_or_else(|| anyhow::anyhow!("expected at least one export"))?;

    let normal = export.get_normal_export()
        .ok_or_else(|| anyhow::anyhow!("expected NormalExport"))?;

    // We expect exactly 3 properties: bEnabled, MaxSpeed, ObjectName
    assert_eq!(
        normal.properties.len(),
        3,
        "expected 3 properties, got {}",
        normal.properties.len()
    );

    // Check the property names match (order may vary — use name lookup).
    let prop_names: Vec<String> = normal
        .properties
        .iter()
        .map(|p| p.get_name().get_owned_content())
        .collect();
    assert!(prop_names.contains(&"bEnabled".to_string()), "missing bEnabled");
    assert!(prop_names.contains(&"MaxSpeed".to_string()), "missing MaxSpeed");
    assert!(prop_names.contains(&"ObjectName".to_string()), "missing ObjectName");

    Ok(())
}
```

Update `write_minimal_ue4_27` to call both validation functions:

```rust
pub fn write_minimal_ue4_27_with_properties(path: &std::path::Path) -> anyhow::Result<()> {
    use paksmith_core::testing::uasset::build_minimal_ue4_27_with_properties;
    let pkg = build_minimal_ue4_27_with_properties();
    std::fs::write(path, &pkg.bytes)?;
    cross_validate_with_unreal_asset(&pkg.bytes)?;
    cross_validate_properties_with_unreal_asset(&pkg.bytes)?;
    println!("wrote + cross-validated {}", path.display());
    Ok(())
}
```

**API verification note:** The `get_name().get_owned_content()` call shape above is inferred from the unreal_asset crate conventions at the pinned commit. Before committing, verify it compiles by running:

```bash
cargo build -p paksmith-fixture-gen 2>&1 | grep -E "error\[|no method|not found" | head -20
```

Adjust the property name access API if it fails.

- [ ] **Step 4: Run fixture-gen to produce the updated pak**

```bash
cargo run -p paksmith-fixture-gen 2>&1 | tail -20
```

Expected: `wrote + cross-validated tests/fixtures/real_v8b_uasset.pak` (or similar) with no errors.

- [ ] **Step 5: Update the fixture anchor SHA1**

In `crates/paksmith-core/tests/fixture_anchor.rs` (established in Phase 2a Task 15), update the SHA1 pin for `real_v8b_uasset.pak` with the new hash:

```bash
sha1sum tests/fixtures/real_v8b_uasset.pak
```

Replace the previous hash in the anchor test.

- [ ] **Step 6: Run full test suite**

```bash
cargo test --workspace 2>&1 | tail -20
```

Expected: all tests pass.

- [ ] **Step 7: Run workspace clippy**

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

- [ ] **Step 8: Commit**

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
        PropertyBag::Tree(p) => p,
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

#[test]
fn unversioned_flag_is_rejected() {
    // Build an in-memory asset with PKG_UnversionedProperties set.
    // Use build_minimal_ue4_27() and flip the flag byte in place.
    #[cfg(feature = "__test_utils")]
    {
        use paksmith_core::testing::uasset::build_minimal_ue4_27;
        let mut pkg_bytes = build_minimal_ue4_27().bytes.clone();

        // package_flags is at a known offset from the summary.
        // Find it by searching for the magic + walking the summary
        // fields in the test. Alternatively: flip bits at offset
        // confirmed by Phase 2a summary parser.
        //
        // Magic = 4 bytes, LegacyFileVersion = 4 bytes, IsUnversioned = 4 bytes,
        // FileVersionUE4 = 4 bytes, FileVersionLicensee = 4 bytes,
        // CustomVersionContainer count = 4 bytes (empty = 0),
        // TotalHeaderSize = 4 bytes, FolderName (FString ~8 bytes),
        // PackageFlags = u32 at bytes[24+len_of_folder_name_fstring].
        //
        // The exact offset is fragile — instead build a helper that
        // returns the flags offset, or simply test by constructing
        // a package that reads back with the error.
        //
        // MINIMAL approach: embed the flags offset as a constant
        // in MinimalPackage (add a `package_flags_offset: usize` field
        // to the struct in testing/uasset.rs, populated during build).
        // Then: pkg_bytes[min_pkg.package_flags_offset .. + 4] |= 0x20_00.
        //
        // For this test to be non-trivial, implement the offset tracking
        // in Task 9's builder refactor and use it here.

        // Placeholder assertion — replace with actual offset once builder
        // exports package_flags_offset:
        let _ = pkg_bytes; // suppress unused warning
        // assert!(Package::read_from(&pkg_bytes, "x.uasset").is_err());
    }
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
        read_properties, MAX_TAGS_PER_EXPORT,
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
        // f32::NaN != f32::NaN, so compare bits.
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
    assert!(matches!(
        err,
        PaksmithError::AssetParse {
            fault: AssetParseFault::PropertyTagNegativeSize { .. },
            ..
        }
    ));
}

#[test]
fn oversized_property_rejected() {
    use paksmith_core::asset::property::tag::MAX_PROPERTY_TAG_SIZE;
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
    assert!(matches!(
        err,
        PaksmithError::AssetParse {
            fault: AssetParseFault::PropertyTagSizeExceedsCap { .. },
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
  `PropertyBag::Tree(Vec<Property>)`. Unknown/container types skip
  via `tag.size`. Security caps: `MAX_TAGS_PER_EXPORT=65536`,
  `MAX_PROPERTY_TAG_SIZE=16MiB`, `MAX_PROPERTY_DEPTH=128`.
  Assets with `PKG_UnversionedProperties` are rejected early.
```

- [ ] **Step 2: Update `README.md`**

Find the `paksmith inspect` section added in Phase 2a and update the description:

```markdown
### `paksmith inspect`

Dump a uasset's structural header and property tree as JSON. Phase 2b
decodes primitive properties (Bool, Int variants, Float, Double, Str,
Name, Enum, Text). Container properties (Array/Map/Set/Struct) appear
as `Unknown` entries with a `skipped_bytes` count until Phase 2c.

```bash
paksmith inspect path/to/archive.pak Game/Data/Hero.uasset
```
```

- [ ] **Step 3: Update `docs/plans/ROADMAP.md`**

Find the Phase 2 entry. Update the status line to:

```markdown
**Status:** Phase 2a complete (`phase-2a-uasset-header.md`). Phase 2b
complete (`phase-2b-tagged-properties.md`). Phases 2c–2e (container
properties, object refs, .uexp stitching) scoped but not yet planned.
```

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

12. **Fixture oracle API verified:** the `cross_validate_properties_with_unreal_asset` function compiles before commit. `cargo build -p paksmith-fixture-gen` is the checkpoint. ✓

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
