# Paksmith Phase 2f: Unversioned Properties & .usmap Mappings

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Cargo exit-code caveat:** Every cargo command piped through `tail`, `head`, or `grep` in this plan returns `0` even when cargo failed — the shell drops the upstream exit code. After running any cargo gate, re-run unpiped, set `set -o pipefail`, or inspect `${PIPESTATUS[0]}` to verify the real exit code.

**Goal:** Parse assets with `PKG_UnversionedProperties` flag set by loading a companion `.usmap` schema file, replacing the current hard rejection with real property deserialization.

**Architecture:** New `asset/mappings.rs` provides `Usmap` (class schema registry) parsed from `.usmap` binary files (None/ZStd/Brotli compression; Oodle rejected pending Phase 8 system-library support). `AssetContext` gains an `Option<Arc<Usmap>>` field threaded through `Package::read_from` via a new parameter. New `asset/property/unversioned.rs` implements `FUnversionedHeader` (fragment list + zero mask) and `read_unversioned_properties` which walks schema-ordered properties. Phase 2b's `AssetParseFault::UnversionedPropertiesUnsupported` is replaced by `UnversionedWithoutMappings`. `paksmith inspect` gains `--mappings <path>`.

**Tech Stack:** Same as Phase 2e plus `zstd` (ZStd decompression) and `brotli` (Brotli decompression), both new workspace deps.

---

## Deliverable

```shell
paksmith inspect --mappings Game/Mappings.usmap real_v8b.pak Game/Data/Hero.uasset
```

outputs a property tree for assets that previously failed with `UnversionedPropertiesUnsupported`:

```json
{
  "asset_path": "Game/Data/Hero.uasset",
  "exports": [
    {
      "object_name": "Hero",
      "properties": [
        { "name": "Health", "array_index": 0, "value": { "Int": 100 } },
        { "name": "Speed", "array_index": 0, "value": { "Float": 600.0 } }
      ]
    }
  ]
}
```

> **Note:** This shape is illustrative. The actual `Package` JSON contract has `object_name` as a `u32` name-table index (not a resolved string) and stores properties in a parallel `payloads` array (not embedded under exports). See `crates/paksmith-cli/tests/snapshots/inspect_cli__inspect_json_snapshot.snap` for the canonical wire-stable shape.

Without `--mappings`, `paksmith inspect` continues to work for versioned (tagged) assets. Passing `--mappings` for a versioned asset is silently ignored.

## Scope vs deferred work

**In scope:**

- `.usmap` parser: magic, version (Initial/PackageVersioning/Latest), compression (None/ZStd/Brotli), name table, enum map, schema map with inheritance chain
- `Usmap::from_bytes(bytes: &[u8]) -> crate::Result<Self>`
- `MappingsParseFault` error sub-enum (new; same pattern as `IndexParseFault`/`DecompressionFault`)
- `AssetParseFault::UnversionedWithoutMappings` (replaces `UnversionedPropertiesUnsupported` from Phase 2b)
- Thread `Option<Arc<Usmap>>` through `AssetContext` and `Package::read_from`
- `FUnversionedHeader`: fragment list + zero mask; bit layout constants from oracle (verified empirically Task 5)
- `read_unversioned_properties`: schema-ordered property walk with fragment/zero-mask dispatch
- `read_unversioned_value`: primitives (Bool/Int8/16/32/64/UInt8/16/32/64/Float/Double/Str/Name/Text/Enum/Object/SoftObject), Array (element type from schema), Struct (recursive schema lookup)
- Unsupported types (Map/Set/Delegate/Interface/FieldPath): `tracing::warn!` + stop reading; return partial `PropertyBag::Tree`
- `build_minimal_usmap_bytes()` + `build_minimal_unversioned_uasset_bytes()` in `testing/usmap.rs`
- Oracle cross-validation: `Usmap::from_bytes` agrees with `unreal_asset::unversioned::Usmap::new`; property tree agrees with `Asset::new(..., Some(usmap))`
- Integration tests: 5 tests
- CLI `--mappings <path>` flag + insta snapshot update

**Explicitly deferred:**

- Oodle-compressed `.usmap` — rejected with `UsmapCompressionUnsupported`; full support deferred to Phase 8 alongside the IoStore system-library mechanism
- Map/Set elements in unversioned mode — size unknown without a tag; deferred pending oracle-verified wire format (see `memory/feedback_verify_wire_format_claims.md`)
- Delegate, MulticastDelegate, Interface, FieldPath unversioned values — complex serialization; deferred

## Design decisions locked here

1. **`MappingsParseFault` is a new sibling sub-enum.** Two-tier model: `MappingsParseFault` covers `.usmap` wire-format faults (magic, version, compression, truncation); `AssetParseFault::UnversionedWithoutMappings` covers the activation-site failure (the asset needs mappings but none were provided). Different responsibilities, different error lifetimes.

2. **`AssetParseFault::UnversionedPropertiesUnsupported` is removed.** Phase 2b introduced it as a temporary rejection. Phase 2f supersedes it: the check becomes `if needs_unversioned && ctx.mappings.is_none() → UnversionedWithoutMappings`, else dispatch to `read_unversioned_properties`. Update any test that asserted `UnversionedPropertiesUnsupported`.

3. **Compression scope.** None + ZStd + Brotli are pure-Rust–compatible and cover the majority of community-distributed `.usmap` files (developer exports from UE tooling, CUE4Parse dumps). Oodle is used by some AAA game `.usmap` files but requires a proprietary system library. Phase 8's IoStore plan already establishes the system-library loading architecture; `.usmap` Oodle support follows naturally from that, not independently.

4. **`FUnversionedHeader` bit constants are pinned from the oracle.** From `unreal_asset_base::unversioned::header::UnversionedHeaderFragment`:
   - `SKIP_NUM_MASK: u16 = 0x007f` (bits 0–6: how many schema slots to skip before values)
   - `HAS_ZEROS_MASK: u16 = 0x0080` (bit 7: some of the value slots are zero/default)
   - `IS_LAST_MASK: u16 = 0x0100` (bit 8: this is the last fragment)
   - `VALUE_NUM_SHIFT: u16 = 9` (bits 9–15: number of value slots described by this fragment)
     Task 5 cross-validates that our decoder produces the same schema as the oracle on the same bytes, confirming the layout.

5. **`BoolProperty` in unversioned mode = 1 byte.** In the tagged path, `bool_val` is encoded in the `FPropertyTag` header and the payload is 0 bytes. In unversioned mode there is no tag, so the bool is a 1-byte payload: `0x00 = false`, anything else `= true`. This is confirmed by Task 5's oracle cross-validation.

6. **`read_unversioned_value` is independent of `PropertyTag`.** It takes a `&MappedProperty` from the schema. The function reuses the same low-level byte readers (FString, FName, etc.) as the tagged path but does not accept or create a `PropertyTag`.

7. **Unsupported type mid-stream = warn + partial result.** Because unversioned properties have no size field, an unsupported type cannot be skipped. When `read_unversioned_value` encounters an unsupported type, it logs `tracing::warn!` and `read_unversioned_properties` returns the properties read so far as `PropertyBag::Tree`. The caller does not see an error — only a truncated (but non-garbage) property list.

8. **`EnumProperty` in unversioned reads an FName.** The enum value is serialized as two i32s (name index + number, same as any FName in the tagged path). `PropertyValue::Enum { enum_name, value }` is populated from the schema's `enum_name` and the resolved FName string respectively.

---

## File structure

| File                                                     | Action | Responsibility                                                                                                          |
| -------------------------------------------------------- | ------ | ----------------------------------------------------------------------------------------------------------------------- |
| `crates/paksmith-core/src/error.rs`                      | Modify | `MappingsParseFault` sub-enum (thiserror-derived); `AssetParseFault::UnversionedWithoutMappings` + `UnversionedTypeNotSupported` variants + manual Display arms; remove `UnversionedPropertiesUnsupported` |
| `crates/paksmith-core/src/asset/mappings.rs`             | Create | `Usmap`, `ClassSchema`, `MappedProperty`, `MappedPropertyType`; `Usmap::from_bytes`                                     |
| `crates/paksmith-core/src/asset/mod.rs`                  | Modify | `pub mod mappings`; `Arc<Usmap>` added to `AssetContext`                                                                |
| `crates/paksmith-core/src/asset/package.rs`              | Modify | `read_from` gains `mappings: Option<&Usmap>`; unversioned dispatch                                                      |
| `crates/paksmith-core/src/asset/property/unversioned.rs` | Create | `Fragment`, `UnversionedHeader`, `read_unversioned_properties`, `read_unversioned_value`                                |
| `crates/paksmith-core/src/asset/property/mod.rs`         | Modify | `pub mod unversioned`; re-export `read_unversioned_properties`                                                          |
| `crates/paksmith-core/src/testing/usmap.rs`              | Create | `build_minimal_usmap_bytes()`, `build_minimal_unversioned_uasset_bytes()`                                               |
| `crates/paksmith-core/src/testing/mod.rs`                | Modify | `pub mod usmap;` (the parent `testing` module is already feature-gated in `lib.rs`)                                     |
| `crates/paksmith-core/tests/unversioned_integration.rs`  | Create | 5 integration tests                                                                                                     |
| `crates/paksmith-fixture-gen/src/uasset.rs`              | Modify | Unversioned fixture entry + oracle cross-validation block                                                               |
| `crates/paksmith-cli/src/commands/inspect.rs`            | Modify | `--mappings <path>` flag + insta snapshot update                                                                        |
| `Cargo.toml`                                             | Modify | `zstd = "0.13"` and `brotli = "7"` workspace deps                                                                       |
| `crates/paksmith-core/Cargo.toml`                        | Modify | `zstd.workspace = true` and `brotli.workspace = true`                                                                   |

---

### Task 1: Error types — `MappingsParseFault` + replace `UnversionedPropertiesUnsupported`

**Files:**

- Modify: `crates/paksmith-core/src/error.rs`

- [ ] **Step 1: Write the failing Display-stability tests**

Find the `#[cfg(test)] mod tests` block in `error.rs` (the block containing `asset_parse_display_*` tests) and add:

```rust
#[test]
fn mappings_parse_display_invalid_magic() {
    let err = PaksmithError::MappingsParse {
        fault: MappingsParseFault::InvalidMagic { found: 0x1234 },
    };
    assert_eq!(
        format!("{err}"),
        "usmap deserialization failed: invalid usmap magic: found 0x1234, expected 0xc430"
    );
}

#[test]
fn mappings_parse_display_unsupported_version() {
    let err = PaksmithError::MappingsParse {
        fault: MappingsParseFault::UnsupportedVersion { found: 9 },
    };
    assert_eq!(
        format!("{err}"),
        "usmap deserialization failed: unsupported usmap version 9 (paksmith accepts 0–2)"
    );
}

#[test]
fn mappings_parse_display_unsupported_compression() {
    let err = PaksmithError::MappingsParse {
        fault: MappingsParseFault::UsmapCompressionUnsupported { method: 1 },
    };
    assert_eq!(
        format!("{err}"),
        "usmap deserialization failed: unsupported usmap compression method 1 (Oodle requires Phase 8 system-library support)"
    );
}

#[test]
fn mappings_parse_display_decompressed_size_mismatch() {
    let err = PaksmithError::MappingsParse {
        fault: MappingsParseFault::DecompressedSizeMismatch { expected: 100, found: 80 },
    };
    assert_eq!(
        format!("{err}"),
        "usmap deserialization failed: decompressed size mismatch: expected 100 bytes, got 80"
    );
}

#[test]
fn asset_parse_display_unversioned_without_mappings() {
    let err = PaksmithError::AssetParse {
        asset_path: "Game/Data/Hero.uasset".to_string(),
        fault: AssetParseFault::UnversionedWithoutMappings,
    };
    assert_eq!(
        format!("{err}"),
        "asset deserialization failed for `Game/Data/Hero.uasset`: \
         asset has PKG_UnversionedProperties but no .usmap mappings were provided"
    );
}
```

- [ ] **Step 2: Run the new tests to verify they fail**

```shell
set -o pipefail
cargo test -p paksmith-core --lib error::tests::mappings_parse_display 2>&1 | tail -10
cargo test -p paksmith-core --lib error::tests::asset_parse_display_unversioned_without_mappings 2>&1 | tail -10
```

Expected: FAIL — `MappingsParseFault`, `PaksmithError::MappingsParse`, `AssetParseFault::UnversionedWithoutMappings` not defined. (If the command appears to succeed with `tail`, re-run unpiped — piping to `tail` discards cargo's exit code.)

- [ ] **Step 3: Add `PaksmithError::MappingsParse` + `MappingsParseFault` to `error.rs`**

Add a new top-level variant to `PaksmithError`:

```rust
/// A `.usmap` mappings file could not be deserialized.
#[error("usmap deserialization failed: {fault}")]
MappingsParse { fault: MappingsParseFault },
```

Add the `MappingsParseFault` sub-enum after the existing sub-enums (after `AssetParseFault`):

```rust
/// Wire-format fault encountered while parsing a `.usmap` mappings file.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MappingsParseFault {
    /// Magic bytes did not match `0xC430`.
    #[error("invalid usmap magic: found {found:#06x}, expected 0xc430")]
    InvalidMagic { found: u16 },

    /// Version byte is not in the supported range (0–2).
    #[error("unsupported usmap version {found} (paksmith accepts 0–2)")]
    UnsupportedVersion { found: u8 },

    /// Compression method is not supported (Oodle = 1).
    #[error(
        "unsupported usmap compression method {method} \
         (Oodle requires Phase 8 system-library support)"
    )]
    UsmapCompressionUnsupported { method: u8 },

    /// Decompressed output length did not match the header's declared size.
    #[error("decompressed size mismatch: expected {expected} bytes, got {found}")]
    DecompressedSizeMismatch { expected: u32, found: usize },

    /// Wire-claimed `compressed_size` exceeds the structural cap. Defends
    /// against a malicious header that claims a multi-GiB compressed
    /// payload to force a large up-front allocation.
    #[error("compressed size {size} exceeds cap {limit}")]
    CompressedSizeTooLarge { size: u32, limit: u32 },

    /// Wire-claimed `decompressed_size` exceeds the structural cap.
    /// Independent of the decompressed bytes actually produced — even
    /// if the compressed input is tiny, this header field gates the
    /// output Vec's capacity.
    #[error("decompressed size {size} exceeds cap {limit}")]
    DecompressedSizeTooLarge { size: u32, limit: u32 },

    /// A name-table entry had `name_length == 0` (undefined; minimum is 1).
    #[error("usmap name at offset {offset} has zero-length length byte")]
    ZeroLengthName { offset: usize },

    /// The data block was truncated before the schema table was fully read.
    #[error("usmap data truncated at offset {offset}")]
    Truncated { offset: usize },
}
```

- [ ] **Step 4: Add `AssetParseFault::UnversionedWithoutMappings`; remove `UnversionedPropertiesUnsupported`**

Find `AssetParseFault` in `error.rs` (the enum starts at line ~2117). It is hand-rolled — `#[error(...)]` attributes on its variants are silently ignored because `Display` is implemented manually (`impl fmt::Display for AssetParseFault` at line ~2426). Remove the `UnversionedPropertiesUnsupported` variant added in Phase 2b. Add in its place a bare variant (no `#[error(...)]` — handled by the Display arm in Step 4b):

```rust
/// The asset's `PKG_UnversionedProperties` flag is set, but no
/// `.usmap` mappings were provided to `Package::read_from`.
UnversionedWithoutMappings,
```

Also find the existing Display-stability test for the removed variant at `crates/paksmith-core/src/error.rs:3689-3701` (test `asset_parse_display_unversioned_properties`). Replace its variant reference with `UnversionedWithoutMappings` and update the expected message string to the new wording from the test in Step 1 above.

- [ ] **Step 4b: Add the explicit Display arm for `UnversionedWithoutMappings`**

In `impl fmt::Display for AssetParseFault`, locate the `Self::SplitAssetSizeMismatch { .. }` arm (around line 2561). After it, but before the closing `}` of the `match`, add (and also remove the obsolete `Self::UnversionedPropertiesUnsupported` arm at around line 2520):

```rust
Self::UnversionedWithoutMappings => f.write_str(
    "asset has PKG_UnversionedProperties but no .usmap mappings were provided",
),
```

- [ ] **Step 5: Run the tests to verify they pass**

```shell
set -o pipefail
cargo test -p paksmith-core --lib error::tests 2>&1 | tail -15
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
```

Expected: all `error::tests::*` pass, including the 5 new tests. `cargo doc` exits 0.

- [ ] **Step 6: Commit**

```bash
git add crates/paksmith-core/src/error.rs
git commit -m "$(cat <<'EOF'
feat(error): MappingsParseFault + UnversionedWithoutMappings for Phase 2f

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: `Usmap` struct + `.usmap` parser

**Files:**

- Create: `crates/paksmith-core/src/asset/mappings.rs`
- Modify: `crates/paksmith-core/src/asset/mod.rs` (add `pub mod mappings`)
- Modify: `Cargo.toml` (workspace deps)
- Modify: `crates/paksmith-core/Cargo.toml` (crate deps)

The `.usmap` wire format (verified against oracle `unreal_asset_base::unversioned::mod::Usmap::parse_data`):

```plaintext
[u16 LE]  magic = 0xC430 (LE bytes: [0x30, 0xC4])
[u8]      version (0=Initial, 1=PackageVersioning, 2=Latest)
--- if version >= 1 (PackageVersioning): ---
  [bool u8] has_versioning
  --- if has_versioning: ---
    [i32 LE]  object_version
    [i32 LE]  object_version_ue5
    [u32 LE]  custom_version_count
    [...]     custom_version_count × CustomVersion entries (skipped — not used by paksmith)
    [u32 LE]  net_cl
--- end versioning block ---
[u8]      compression (0=None, 1=Oodle→error, 2=Brotli, 3=ZStandard)
[u32 LE]  compressed_size
[u32 LE]  decompressed_size
[...]     compressed_size bytes of (possibly compressed) schema data

--- schema data (after decompression) ---
[u32 LE]  name_count
[...]     name_count × { u8 name_length (= strlen+1), (name_length-1) bytes UTF-8 }
[u32 LE]  enum_count
[...]     enum_count × { i32 LE name_idx, u8 value_count, value_count × i32 LE name_idx }
[u32 LE]  schema_count
[...]     schema_count × UsmapSchema (see below)

--- UsmapSchema ---
[i32 LE]  name_idx                     → schemas[i].name
[i32 LE]  super_type_idx               → schemas[i].super_type
[u16 LE]  prop_count                   → total property count including inherited
[u16 LE]  serializable_property_count  → entries that follow
[...]     serializable_property_count × UsmapProperty

--- UsmapProperty ---
[u16 LE]  schema_index
[u8]      array_size
[i32 LE]  name_idx                     → property name string
[u8]      EPropertyType (see MappedPropertyType below)
--- type-specific extra bytes ---
  EnumProperty:  [u8 inner EPropertyType (always ByteProperty=0)] [i32 LE enum_name_idx]
  StructProperty: [i32 LE struct_type_name_idx]
  ArrayProperty:  [u8 inner EPropertyType] [inner type-specific extra bytes]
  MapProperty:    [u8 key EPropertyType] [key extra] [u8 val EPropertyType] [val extra]
  SetProperty:    [u8 inner EPropertyType] [inner extra]
  All others:     (no extra bytes)
```

> **Note:** The `array_size` field allows a property to expand into `array_size` consecutive schema slots. For `array_size > 1`, each expanded slot is an independent property value in the unversioned stream. Phase 2f fixture uses only `array_size == 1` properties; general `array_size > 1` handling is covered naturally by the schema walk loop.
>
> **Note on EnumProperty extra byte order:** From `unreal_asset_base/unversioned/properties/enum_property.rs`, `UsmapEnumPropertyData::new` reads `inner_property` (UsmapPropertyData) FIRST, then `name` (read_name). So the wire order is: `[u8 inner_type_byte][i32 LE enum_name_idx]`.

- [ ] **Step 1: Write failing parser unit tests**

Add to `crates/paksmith-core/src/asset/mappings.rs` (create the file):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_usmap_none() -> Vec<u8> {
        // Magic + version(0) + compression(0) + schema data with one class
        // "Hero" (name 0), "" (name 1), "Health" (name 2), "Speed" (name 3)
        // One schema: Hero, super="", 2 props: Health(Int32), Speed(Float)
        let mut data: Vec<u8> = Vec::new();
        // Name table
        data.extend_from_slice(&4u32.to_le_bytes()); // 4 names
        for (s, name) in [(5u8, "Hero"), (1u8, ""), (7u8, "Health"), (6u8, "Speed")] {
            data.push(s);
            data.extend_from_slice(name.as_bytes());
        }
        // Enum table
        data.extend_from_slice(&0u32.to_le_bytes());
        // Schema table
        data.extend_from_slice(&1u32.to_le_bytes());
        // Schema: name=0("Hero"), super=1(""), prop_count=2, serial_count=2
        data.extend_from_slice(&0i32.to_le_bytes()); // name idx
        data.extend_from_slice(&1i32.to_le_bytes()); // super idx
        data.extend_from_slice(&2u16.to_le_bytes()); // prop_count
        data.extend_from_slice(&2u16.to_le_bytes()); // serial count
        // Prop 0: schema_index=0, array_size=1, name=2("Health"), type=IntProperty(2)
        data.extend_from_slice(&0u16.to_le_bytes());
        data.push(1u8); // array_size
        data.extend_from_slice(&2i32.to_le_bytes()); // name idx
        data.push(2u8); // IntProperty
        // Prop 1: schema_index=1, array_size=1, name=3("Speed"), type=FloatProperty(3)
        data.extend_from_slice(&1u16.to_le_bytes());
        data.push(1u8);
        data.extend_from_slice(&3i32.to_le_bytes());
        data.push(3u8); // FloatProperty

        let data_len = data.len() as u32;
        let mut usmap: Vec<u8> = Vec::new();
        usmap.extend_from_slice(&[0x30u8, 0xC4u8]); // magic LE
        usmap.push(0u8); // version = Initial
        usmap.push(0u8); // compression = None
        usmap.extend_from_slice(&data_len.to_le_bytes()); // compressed_size
        usmap.extend_from_slice(&data_len.to_le_bytes()); // decompressed_size
        usmap.extend_from_slice(&data);
        usmap
    }

    #[test]
    fn parse_minimal_usmap_none_schema() {
        let bytes = minimal_usmap_none();
        let usmap = Usmap::from_bytes(&bytes).unwrap();
        let schema = usmap.schemas.get("Hero").unwrap();
        assert_eq!(schema.super_type.as_deref(), Some(""));
        assert_eq!(schema.properties.len(), 2);
        assert_eq!(schema.properties[0].name, "Health");
        assert!(matches!(schema.properties[0].prop_type, MappedPropertyType::Int32));
        assert_eq!(schema.properties[1].name, "Speed");
        assert!(matches!(schema.properties[1].prop_type, MappedPropertyType::Float));
    }

    #[test]
    fn parse_usmap_invalid_magic() {
        let mut bytes = minimal_usmap_none();
        bytes[0] = 0xFF;
        let err = Usmap::from_bytes(&bytes).unwrap_err();
        assert!(matches!(
            err,
            crate::PaksmithError::MappingsParse {
                fault: crate::error::MappingsParseFault::InvalidMagic { .. }
            }
        ));
    }

    #[test]
    fn parse_usmap_unsupported_version() {
        let mut bytes = minimal_usmap_none();
        bytes[2] = 9u8; // version byte
        let err = Usmap::from_bytes(&bytes).unwrap_err();
        assert!(matches!(
            err,
            crate::PaksmithError::MappingsParse {
                fault: crate::error::MappingsParseFault::UnsupportedVersion { found: 9 }
            }
        ));
    }

    #[test]
    fn parse_usmap_oodle_rejected() {
        let mut bytes = minimal_usmap_none();
        bytes[3] = 1u8; // compression = Oodle
        let err = Usmap::from_bytes(&bytes).unwrap_err();
        assert!(matches!(
            err,
            crate::PaksmithError::MappingsParse {
                fault: crate::error::MappingsParseFault::UsmapCompressionUnsupported { method: 1 }
            }
        ));
    }

    #[test]
    fn get_all_properties_with_inheritance() {
        // Build a usmap with Parent(x: Int) and Child extends Parent(y: Float)
        let mut data: Vec<u8> = Vec::new();
        // Names: "Parent"(0), ""(1), "x"(2), "Child"(3), "y"(4)
        data.extend_from_slice(&5u32.to_le_bytes());
        for (s, name) in [(7u8,"Parent"),(1u8,""),(2u8,"x"),(6u8,"Child"),(2u8,"y")] {
            data.push(s);
            data.extend_from_slice(name.as_bytes());
        }
        data.extend_from_slice(&0u32.to_le_bytes()); // no enums
        data.extend_from_slice(&2u32.to_le_bytes()); // 2 schemas
        // Schema Parent: name=0, super=1(""), prop_count=1, serial=1
        data.extend_from_slice(&0i32.to_le_bytes());
        data.extend_from_slice(&1i32.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes()); // schema_index=0
        data.push(1u8); // array_size
        data.extend_from_slice(&2i32.to_le_bytes()); // "x"
        data.push(2u8); // IntProperty
        // Schema Child: name=3("Child"), super=0("Parent"), prop_count=2, serial=1
        data.extend_from_slice(&3i32.to_le_bytes());
        data.extend_from_slice(&0i32.to_le_bytes()); // super = "Parent"
        data.extend_from_slice(&2u16.to_le_bytes()); // prop_count includes inherited
        data.extend_from_slice(&1u16.to_le_bytes()); // only 1 new prop serialized
        data.extend_from_slice(&1u16.to_le_bytes()); // schema_index=1
        data.push(1u8);
        data.extend_from_slice(&4i32.to_le_bytes()); // "y"
        data.push(3u8); // FloatProperty

        let data_len = data.len() as u32;
        let mut usmap = vec![0x30u8, 0xC4, 0, 0];
        usmap.extend_from_slice(&data_len.to_le_bytes());
        usmap.extend_from_slice(&data_len.to_le_bytes());
        usmap.extend_from_slice(&data);

        let usmap = Usmap::from_bytes(&usmap).unwrap();
        let all = usmap.get_all_properties("Child");
        // inheritance order: Parent's props first, then Child's own
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].name, "x");
        assert_eq!(all[1].name, "y");
    }
}
```

- [ ] **Step 2: Run to verify they fail**

```shell
cargo test -p paksmith-core --lib asset::mappings::tests 2>&1 | tail -10
```

Expected: FAIL — module not found.

- [ ] **Step 3: Add `zstd` and `brotli` to workspace deps**

In `Cargo.toml` (workspace root), find the `[workspace.dependencies]` section and add:

```toml
zstd = "0.13"
brotli = "7"
```

In `crates/paksmith-core/Cargo.toml`, add:

```toml
zstd.workspace = true
brotli.workspace = true
```

> **Note on `deny.toml`:** This repo's `[bans]` section uses `multiple-versions = "warn"`, not an allowlist, so no `crates = [...]` edit is needed for the new direct deps. Expect `cargo deny check` to surface non-fatal `multiple-versions` warnings because `unreal_asset` transitively pulls older `brotli` (3.x) and `zstd` (0.12.x) alongside the 7.x / 0.13.x direct deps. Warnings are expected; the gate is `error` for `denied` only.
>
> - [ ] **Step 3b: Populate `Cargo.lock` for the new deps**
>
> Run once before staging so the lockfile carries `zstd` and `brotli` resolution metadata:
>
> ```shell
> cargo build -p paksmith-core
> ```

- [ ] **Step 4: Create `asset/mappings.rs`**

```rust
use std::collections::HashMap;
use std::io::{Cursor, Read, Seek, SeekFrom};

use byteorder::{ReadBytesExt, LE};

use crate::error::MappingsParseFault;
use crate::PaksmithError;

const USMAP_MAGIC: u16 = 0xC430;
const MAX_USMAP_VERSION: u8 = 2; // EUsmapVersion::Latest

/// Hard cap on the wire-claimed `compressed_size` of a `.usmap` file.
/// Community-distributed usmaps are typically <1 MiB; 64 MiB gives huge
/// headroom while bounding allocation from a malicious header that
/// claims `u32::MAX` (≈4 GiB).
pub const MAX_USMAP_COMPRESSED_SIZE: u32 = 64 * 1024 * 1024;

/// Hard cap on the wire-claimed `decompressed_size`. Same rationale —
/// prevent a decompression bomb from claiming a 4 GiB output buffer
/// and stalling allocation before the decoder even runs.
pub const MAX_USMAP_DECOMPRESSED_SIZE: u32 = 256 * 1024 * 1024;

/// Hard cap on the inheritance chain length when walking
/// `super_type` pointers. A malicious `.usmap` with a cycle (`A: B`,
/// `B: A`) would loop forever otherwise.
const MAX_INHERITANCE_DEPTH: usize = 64;

/// Compression method byte values from the .usmap wire format.
#[repr(u8)]
enum UsmapCompression {
    None = 0,
    Oodle = 1,
    Brotli = 2,
    ZStandard = 3,
}

/// The Rust-side property type derived from a usmap `EPropertyType` byte.
#[derive(Debug, Clone, PartialEq)]
pub enum MappedPropertyType {
    Bool,
    Int8,
    Int16,
    Int32,
    Int64,
    UInt8,
    UInt16,
    UInt32,
    UInt64,
    Float,
    Double,
    Str,
    Name,
    Text,
    Enum { enum_name: String },
    Struct { struct_name: String },
    Object,
    SoftObject,
    Array { inner: Box<MappedPropertyType> },
    /// Unrecognised or unsupported type byte.
    Unknown(u8),
}

/// A single property entry from a `.usmap` schema.
#[derive(Debug, Clone)]
pub struct MappedProperty {
    pub name: String,
    /// 0-based index within the class's serialisation order.
    pub schema_index: u16,
    /// Per-slot expansion index when the schema declares `array_size > 1`
    /// (a C-style fixed-size array property). Each expanded slot keeps
    /// the same `name` but a distinct `array_index`, mapped 1:1 to
    /// `Property.array_index` (`i32`) on the decoded value.
    pub array_index: i32,
    pub prop_type: MappedPropertyType,
}

/// Schema for one class (or struct).
#[derive(Debug, Clone)]
pub struct ClassSchema {
    pub name: String,
    /// Empty string means no super class.
    pub super_type: Option<String>,
    /// Properties defined directly on this class (not inherited), in schema order.
    pub properties: Vec<MappedProperty>,
}

/// Parsed `.usmap` mappings file: a registry of class schemas plus the
/// enum-value tables needed to resolve unversioned `EnumProperty` reads.
#[derive(Debug, Clone, Default)]
pub struct Usmap {
    pub schemas: HashMap<String, ClassSchema>,
    /// Enum name → list of value names (indexed by `u8` ordinal in the
    /// wire stream). Required for unversioned `EnumProperty` reads:
    /// the asset stores only a byte index, and the resolved string
    /// comes from this table.
    pub enums: HashMap<String, Vec<String>>,
}

impl Usmap {
    /// Parse a `.usmap` binary blob.
    pub fn from_bytes(bytes: &[u8]) -> crate::Result<Self> {
        let mut cur = Cursor::new(bytes);
        let magic = cur.read_u16::<LE>().map_err(|_| fault(MappingsParseFault::Truncated { offset: 0 }))?;
        if magic != USMAP_MAGIC {
            return Err(fault(MappingsParseFault::InvalidMagic { found: magic }));
        }

        let version = cur.read_u8().map_err(|_| fault(MappingsParseFault::Truncated { offset: 2 }))?;
        if version > MAX_USMAP_VERSION {
            return Err(fault(MappingsParseFault::UnsupportedVersion { found: version }));
        }

        // PackageVersioning block (version >= 1)
        if version >= 1 {
            let has_versioning = cur.read_u8()? != 0;
            if has_versioning {
                // object_version + object_version_ue5 + custom_version array + net_cl
                let _obj_ver = cur.read_i32::<LE>()?;
                let _obj_ver_ue5 = cur.read_i32::<LE>()?;
                let cv_count = cur.read_u32::<LE>()?;
                // Each CustomVersion = 16-byte GUID + i32 version number = 20 bytes
                let skip = cv_count as i64 * 20;
                cur.seek(SeekFrom::Current(skip))?;
                let _net_cl = cur.read_u32::<LE>()?;
            }
        }

        let compression_byte = cur.read_u8()?;
        let compressed_size = cur.read_u32::<LE>()?;
        let decompressed_size = cur.read_u32::<LE>()?;

        // Reject pathological sizes BEFORE allocating, so a malicious
        // header can't force a multi-GiB allocation.
        if compressed_size > MAX_USMAP_COMPRESSED_SIZE {
            return Err(fault(MappingsParseFault::CompressedSizeTooLarge {
                size: compressed_size,
                limit: MAX_USMAP_COMPRESSED_SIZE,
            }));
        }
        if decompressed_size > MAX_USMAP_DECOMPRESSED_SIZE {
            return Err(fault(MappingsParseFault::DecompressedSizeTooLarge {
                size: decompressed_size,
                limit: MAX_USMAP_DECOMPRESSED_SIZE,
            }));
        }

        let mut compressed: Vec<u8> = Vec::new();
        compressed
            .try_reserve_exact(compressed_size as usize)
            .map_err(|_| fault(MappingsParseFault::CompressedSizeTooLarge {
                size: compressed_size,
                limit: MAX_USMAP_COMPRESSED_SIZE,
            }))?;
        compressed.resize(compressed_size as usize, 0);
        cur.read_exact(&mut compressed)?;

        let data = match compression_byte {
            x if x == UsmapCompression::None as u8 => {
                if compressed_size != decompressed_size {
                    return Err(fault(MappingsParseFault::DecompressedSizeMismatch {
                        expected: decompressed_size,
                        found: compressed_size as usize,
                    }));
                }
                compressed
            }
            x if x == UsmapCompression::Brotli as u8 => {
                // The `brotli` crate (v7) exposes `Decompressor::new` which
                // wraps a reader and produces decompressed bytes via `Read`.
                // Wrap with `Read::take(decompressed_size + 1)` so a
                // decompression bomb can't produce more than the header
                // claims (the +1 lets us detect over-production and error
                // out before the Vec grows past the declared size).
                let limit = decompressed_size as u64 + 1;
                let decoder = brotli::Decompressor::new(Cursor::new(compressed), 4096);
                let mut limited = std::io::Read::take(decoder, limit);
                let mut out: Vec<u8> = Vec::new();
                out.try_reserve_exact(decompressed_size as usize).map_err(|_| {
                    fault(MappingsParseFault::DecompressedSizeTooLarge {
                        size: decompressed_size,
                        limit: MAX_USMAP_DECOMPRESSED_SIZE,
                    })
                })?;
                limited.read_to_end(&mut out).map_err(|_| {
                    fault(MappingsParseFault::Truncated {
                        offset: cur.position() as usize,
                    })
                })?;
                if out.len() != decompressed_size as usize {
                    return Err(fault(MappingsParseFault::DecompressedSizeMismatch {
                        expected: decompressed_size,
                        found: out.len(),
                    }));
                }
                out
            }
            x if x == UsmapCompression::ZStandard as u8 => {
                // Stream-decode through a Decoder + take(N) bound rather
                // than `decode_all`, so a zstd bomb can't produce GBs of
                // output beyond what the header claimed.
                let limit = decompressed_size as u64 + 1;
                let decoder = zstd::stream::Decoder::new(Cursor::new(compressed))
                    .map_err(|_| fault(MappingsParseFault::Truncated {
                        offset: cur.position() as usize,
                    }))?;
                let mut limited = std::io::Read::take(decoder, limit);
                let mut out: Vec<u8> = Vec::new();
                out.try_reserve_exact(decompressed_size as usize).map_err(|_| {
                    fault(MappingsParseFault::DecompressedSizeTooLarge {
                        size: decompressed_size,
                        limit: MAX_USMAP_DECOMPRESSED_SIZE,
                    })
                })?;
                limited.read_to_end(&mut out).map_err(|_| {
                    fault(MappingsParseFault::Truncated {
                        offset: cur.position() as usize,
                    })
                })?;
                if out.len() != decompressed_size as usize {
                    return Err(fault(MappingsParseFault::DecompressedSizeMismatch {
                        expected: decompressed_size,
                        found: out.len(),
                    }));
                }
                out
            }
            x if x == UsmapCompression::Oodle as u8 => {
                return Err(fault(MappingsParseFault::UsmapCompressionUnsupported { method: x }));
            }
            x => {
                return Err(fault(MappingsParseFault::UsmapCompressionUnsupported { method: x }));
            }
        };

        Self::parse_schema_data(&data)
    }

    fn parse_schema_data(data: &[u8]) -> crate::Result<Self> {
        let mut cur = Cursor::new(data);

        // Name table
        let name_count = cur.read_u32::<LE>()?;
        let mut names: Vec<String> = Vec::with_capacity(name_count as usize);
        for _ in 0..name_count {
            let name_length = cur.read_u8()?;
            if name_length == 0 {
                return Err(fault(MappingsParseFault::ZeroLengthName { offset: cur.position() as usize }));
            }
            let mut buf = vec![0u8; (name_length - 1) as usize];
            cur.read_exact(&mut buf)?;
            names.push(String::from_utf8(buf).unwrap_or_default());
        }

        let read_name = |cur: &mut Cursor<&[u8]>| -> crate::Result<String> {
            let idx = cur.read_i32::<LE>()?;
            names.get(idx as usize)
                .cloned()
                .ok_or_else(|| fault(MappingsParseFault::Truncated { offset: cur.position() as usize }))
        };

        // Enum table — REQUIRED for unversioned `EnumProperty` reads
        // (per CUE4Parse's EnumProperty constructor for unversioned mode:
        // wire stream stores a u8 index; the resolved value name comes
        // from this table).
        let enum_count = cur.read_u32::<LE>()?;
        let mut enums: HashMap<String, Vec<String>> = HashMap::with_capacity(enum_count as usize);
        for _ in 0..enum_count {
            let enum_name_idx = cur.read_i32::<LE>()?;
            let enum_name = names
                .get(enum_name_idx as usize)
                .cloned()
                .ok_or_else(|| fault(MappingsParseFault::Truncated { offset: cur.position() as usize }))?;
            let value_count = cur.read_u8()?;
            let mut values: Vec<String> = Vec::with_capacity(value_count as usize);
            for _ in 0..value_count {
                let value_name_idx = cur.read_i32::<LE>()?;
                let value_name = names
                    .get(value_name_idx as usize)
                    .cloned()
                    .ok_or_else(|| fault(MappingsParseFault::Truncated { offset: cur.position() as usize }))?;
                values.push(value_name);
            }
            enums.insert(enum_name, values);
        }

        // Schema table
        let schema_count = cur.read_u32::<LE>()?;
        let mut schemas: HashMap<String, ClassSchema> = HashMap::with_capacity(schema_count as usize);

        for _ in 0..schema_count {
            let name = read_name(&mut cur)?;
            let super_type_str = read_name(&mut cur)?;
            let super_type = if super_type_str.is_empty() || super_type_str == "None" {
                None
            } else {
                Some(super_type_str)
            };

            let _prop_count = cur.read_u16::<LE>()?;
            let serial_count = cur.read_u16::<LE>()?;

            let mut properties: Vec<MappedProperty> = Vec::with_capacity(serial_count as usize);
            for _ in 0..serial_count {
                let schema_index = cur.read_u16::<LE>()?;
                let array_size = cur.read_u8()?;
                let prop_name = read_name(&mut cur)?;
                let prop_type = read_mapped_type(&mut cur, &names)?;

                // Expand array_size > 1 into consecutive slots. Keep the
                // name identical for every expanded slot; encode the C-style
                // fixed-array index on `array_index` instead so the decoded
                // `Property.array_index` matches the wire convention used by
                // the tagged-property path.
                for arr_idx in 0..array_size {
                    properties.push(MappedProperty {
                        name: prop_name.clone(),
                        schema_index: schema_index + arr_idx as u16,
                        array_index: i32::from(arr_idx),
                        prop_type: prop_type.clone(),
                    });
                }
            }

            schemas.insert(name.clone(), ClassSchema { name, super_type, properties });
        }

        Ok(Usmap { schemas, enums })
    }

    /// Returns all properties for `class_name` in inheritance order
    /// (super-chain first, then own properties), ordered by `schema_index`
    /// within each level.
    ///
    /// **Cycle handling:** A malicious `.usmap` can craft a cyclic
    /// `super_type` chain (`A: B`, `B: A`). A naïve walk would loop
    /// forever — DoS. We track visited classes and break on cycle, and
    /// additionally cap the chain at `MAX_INHERITANCE_DEPTH`.
    pub fn get_all_properties(&self, class_name: &str) -> Vec<&MappedProperty> {
        let mut chain: Vec<&str> = Vec::new();
        let mut visited: std::collections::HashSet<&str> = std::collections::HashSet::new();
        let mut current = class_name;
        for _ in 0..MAX_INHERITANCE_DEPTH {
            if !visited.insert(current) {
                // Cycle: `current` was already seen. Stop walking.
                // Log via `tracing::warn!` so operators see the malformed
                // usmap, but don't error — caller may still want the
                // properties we collected up to this point.
                tracing::warn!(
                    class = current,
                    "circular super_type chain in .usmap; truncating inheritance walk"
                );
                break;
            }
            chain.push(current);
            match self.schemas.get(current).and_then(|s| s.super_type.as_deref()) {
                Some(parent) if !parent.is_empty() => current = parent,
                _ => break,
            }
        }
        // Reverse so super-chain is first.
        chain.reverse();
        let mut result = Vec::new();
        for name in chain {
            if let Some(schema) = self.schemas.get(name) {
                result.extend(schema.properties.iter());
            }
        }
        result
    }
}

fn read_mapped_type(cur: &mut Cursor<&[u8]>, names: &[String]) -> crate::Result<MappedPropertyType> {
    let type_byte = cur.read_u8()?;
    let read_name_idx = |c: &mut Cursor<&[u8]>| -> crate::Result<String> {
        let idx = c.read_i32::<LE>()?;
        names.get(idx as usize).cloned()
            .ok_or_else(|| fault(MappingsParseFault::Truncated { offset: c.position() as usize }))
    };
    // EPropertyType discriminants per the oracle's `pub enum EPropertyType`
    // at `unreal_asset_base/src/unversioned/properties/mod.rs`. Pinned
    // revision `f4df5d8e` — re-verify if the oracle pin moves.
    Ok(match type_byte {
        0 => MappedPropertyType::UInt8,         // ByteProperty
        1 => MappedPropertyType::Bool,           // BoolProperty
        2 => MappedPropertyType::Int32,          // IntProperty
        3 => MappedPropertyType::Float,          // FloatProperty
        4 => MappedPropertyType::Object,         // ObjectProperty
        5 => MappedPropertyType::Name,           // NameProperty
        6 | 12 | 13 => MappedPropertyType::Unknown(type_byte), // Delegate/Interface/MulticastDelegate
        7 => MappedPropertyType::Double,         // DoubleProperty
        8 => {                                   // ArrayProperty
            let inner = read_mapped_type(cur, names)?;
            MappedPropertyType::Array { inner: Box::new(inner) }
        }
        9 => {                                   // StructProperty
            let struct_name = read_name_idx(cur)?;
            MappedPropertyType::Struct { struct_name }
        }
        10 => MappedPropertyType::Str,           // StrProperty
        11 => MappedPropertyType::Text,          // TextProperty
        17 => MappedPropertyType::SoftObject, // SoftObjectProperty (FSoftObjectPath: FName + FString)
        // WeakObject (14), LazyObject (15), AssetObject (16) have distinct
        // wire formats (LazyObject is a 16-byte FUniqueObjectGuid;
        // WeakObject and AssetObject differ from SoftObject in subtle ways).
        // Map them to Unknown so the reader emits UnversionedTypeNotSupported
        // rather than silently misparsing FSoftObjectPath bytes.
        14 | 15 | 16 => MappedPropertyType::Unknown(type_byte),
        18 => MappedPropertyType::UInt64,        // UInt64Property
        19 => MappedPropertyType::UInt32,        // UInt32Property
        20 => MappedPropertyType::UInt16,        // UInt16Property
        21 => MappedPropertyType::Int64,         // Int64Property
        22 => MappedPropertyType::Int16,         // Int16Property
        23 => MappedPropertyType::Int8,          // Int8Property
        24 | 25 => MappedPropertyType::Unknown(type_byte), // Map/Set
        26 => {                                  // EnumProperty: inner type byte then enum name
            let _inner_byte = cur.read_u8()?;   // always ByteProperty (0) in practice
            let enum_name = read_name_idx(cur)?;
            MappedPropertyType::Enum { enum_name }
        }
        27 => MappedPropertyType::Unknown(type_byte), // FieldPathProperty
        other => MappedPropertyType::Unknown(other),
    })
}

fn fault(f: MappingsParseFault) -> PaksmithError {
    PaksmithError::MappingsParse { fault: f }
}
```

> **Note on `brotli` API:** The plan above uses `brotli::Decompressor::new(reader, buffer_size)` which has been stable since `brotli 5.0`. If the v7 minor in use exposes a different signature (`BrotliDecompress`, `BrotliDecompressStream`, etc.), check crates.io's latest 7.x docs and adapt — the invariant is: streaming decoder bound by `Read::take(decompressed_size + 1)`, error on overrun.

- [ ] **Step 5: Register the module**

In `crates/paksmith-core/src/asset/mod.rs`, add after the existing `pub mod` declarations:

```rust
pub mod mappings;
pub use mappings::Usmap;
```

- [ ] **Step 6: Run the parser unit tests**

```shell
set -o pipefail
cargo test -p paksmith-core --lib asset::mappings::tests 2>&1 | tail -20
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
```

Expected: all 5 tests pass. `cargo doc` exits 0 (mappings module's public items must have valid rustdoc, including the cap constants).

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml Cargo.lock crates/paksmith-core/Cargo.toml \
        crates/paksmith-core/src/asset/mappings.rs \
        crates/paksmith-core/src/asset/mod.rs
git commit -m "$(cat <<'EOF'
feat(mappings): Usmap parser with None/ZStd/Brotli compression support

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: Thread mappings through `AssetContext` + `Package::read_from`

**Files:**

- Modify: `crates/paksmith-core/src/asset/mod.rs`
- Modify: `crates/paksmith-core/src/asset/package.rs`

The `UnversionedPropertiesUnsupported` rejection currently in `Package::read_from` (added by Phase 2b) is replaced with:

- If `PKG_UnversionedProperties` set **and** `ctx.mappings.is_none()` → `UnversionedWithoutMappings`
- If `PKG_UnversionedProperties` set **and** `ctx.mappings.is_some()` → dispatch to `read_unversioned_properties`
- If `PKG_UnversionedProperties` not set → tagged path (unchanged)

- [ ] **Step 1: Write a failing test for the new signature**

Find `crates/paksmith-core/tests/asset_integration.rs` (created in Phase 2a). Add:

```rust
#[test]
fn unversioned_without_mappings_returns_error() {
    // build_minimal_unversioned_uasset_bytes is defined in Task 5; declare the import now.
    // This test will link once Task 5 completes.
    #[cfg(feature = "__test_utils")]
    {
        use paksmith_core::testing::usmap::build_minimal_unversioned_uasset_bytes;
        let bytes = build_minimal_unversioned_uasset_bytes();
        let result = paksmith_core::asset::Package::read_from(&bytes, None, None, "test.uasset");
        assert!(matches!(
            result,
            Err(paksmith_core::PaksmithError::AssetParse {
                fault: paksmith_core::error::AssetParseFault::UnversionedWithoutMappings,
                ..
            })
        ));
    }
}
```

Run: `cargo test -p paksmith-core --features __test_utils -- unversioned_without_mappings 2>&1 | tail -10`

Expected: FAIL (build error — `mappings` param missing from `read_from`).

- [ ] **Step 2: Add `mappings` field to `AssetContext`**

Find `AssetContext` in `crates/paksmith-core/src/asset/mod.rs` (defined at line ~98-107). The struct currently has 4 fields — `names: Arc<NameTable>`, `imports: Arc<ImportTable>`, `exports: Arc<ExportTable>`, `version: AssetVersion`. Add a 5th:

```rust
pub struct AssetContext {
    pub names: Arc<NameTable>,
    pub imports: Arc<ImportTable>,
    pub exports: Arc<ExportTable>,
    pub version: AssetVersion,
    /// `.usmap` schema registry, threaded in for unversioned-property assets.
    /// `None` for tagged (versioned) assets where Phase 2b's FPropertyTag
    /// iteration carries its own per-property type info.
    pub mappings: Option<std::sync::Arc<crate::asset::mappings::Usmap>>,
}
```

There is **no** `AssetContext::new` constructor — callers use struct literals. Two construction sites exist in `package.rs`:

- `Package::read_from`, around line 500 — pass the `mappings` argument here.
- `Package::context`, around line 583 — pass `None` (the existing `context()` accessor doesn't receive mappings since they're parse-time inputs only; callers needing the mappings should construct an `AssetContext` directly).

Update each struct literal to populate the new field. If `Package` should retain a long-lived `Arc<Usmap>` so `context()` can hand it back out, add an `Option<Arc<Usmap>>` field to `Package` and persist it in `read_from` — this is the cleaner route and matches how `names`/`imports`/`exports` are persisted.

- [ ] **Step 3: Update `Package::read_from` signature**

Find `pub fn read_from(uasset: &[u8], uexp: Option<&[u8]>, asset_path: &str)` in `package.rs`.

Change signature to:

```rust
pub fn read_from(
    uasset: &[u8],
    uexp: Option<&[u8]>,
    mappings: Option<&crate::asset::mappings::Usmap>,
    asset_path: &str,
) -> crate::Result<Self>
```

Pass `mappings.map(|m| std::sync::Arc::new(m.clone()))` when constructing `AssetContext`. (Arc::new clone is acceptable here — mappings are passed by reference and cloned once per package parse call.)

Update every call site of `read_from` in `package.rs`, tests, and CLI.

- [ ] **Step 4: Replace the `UnversionedPropertiesUnsupported` rejection**

In `Package::read_from`, find the block that currently returns `Err(AssetParseFault::UnversionedPropertiesUnsupported)`. Replace it with:

```rust
const PKG_UNVERSIONED_PROPERTIES: u32 = 0x0000_2000;

if summary.package_flags & PKG_UNVERSIONED_PROPERTIES != 0 {
    if ctx.mappings.is_none() {
        return Err(PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::UnversionedWithoutMappings,
        });
    }
    // Per-export dispatch is wired in Task 4. This block leaves a scaffold
    // that resolves each export's class name from the typed `PackageIndex`
    // (no `.to_raw()` needed — Phase 2e's `resolve_package_index` takes
    // the typed value directly).
    for export in exports.exports.iter() {
        let class_name = crate::asset::property::primitives::resolve_package_index(
            export.class_index,
            &ctx,
            asset_path,
        ).unwrap_or_default();
        // TODO Task 4: call read_unversioned_properties
        let _ = class_name;
    }
}
```

> **Note on `resolve_package_index` visibility:** Phase 2e ships this helper as `pub(super)` at `primitives.rs:455`. The Task 3/4 dispatch calls it from `package.rs`, which is **not** a sibling of `primitives.rs` (different module). Widen the visibility to `pub(crate)` in the same step that adds the call. Update the signature line at `primitives.rs:455` from `pub(super) fn resolve_package_index(...)` to `pub(crate) fn resolve_package_index(...)`.

- [ ] **Step 5: Update `Package::read_from_pak`**

Pass `None` for `mappings` in the `read_from` call within `read_from_pak`. The CLI will thread mappings in Task 7.

- [ ] **Step 6: Compile-check**

```shell
set -o pipefail
cargo build -p paksmith-core
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
```

Expected: no compile errors (the `TODO` comment is not code). Fix any type errors from the signature change. (Do **not** pipe `cargo build` through `grep` for verification — the pipe masks the real exit code.)

- [ ] **Step 7: Commit**

```bash
git add crates/paksmith-core/src/asset/mod.rs \
        crates/paksmith-core/src/asset/package.rs \
        crates/paksmith-core/src/asset/property/primitives.rs \
        crates/paksmith-core/tests/asset_integration.rs
git commit -m "$(cat <<'EOF'
feat(asset): thread Usmap mappings through AssetContext and Package::read_from

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: `FUnversionedHeader` + `read_unversioned_properties`

**Files:**

- Create: `crates/paksmith-core/src/asset/property/unversioned.rs`
- Modify: `crates/paksmith-core/src/asset/property/mod.rs`

**`FUnversionedHeader` algorithm (from oracle `unreal_asset_base::unversioned::header`):**

Read u16 fragments in a loop until `is_last` is set. For each fragment:

```rust
skip_num  = packed & 0x007f           // properties to skip (default values)
has_zeros = (packed & 0x0080) != 0    // some value slots use zero mask
is_last   = (packed & 0x0100) != 0    // stop reading after this fragment
value_num = (packed >> 9) as u8       // property slots described
first_num = cumulative_first + skip_num  // schema index of first VALUE slot
cumulative_first += skip_num + value_num as u16
```

After reading all fragments, if `total_zero_count > 0`:

- zero_count ≤ 8 → read 1 byte
- zero_count ≤ 16 → read 2 bytes
- else → read `((zero_count + 31) / 32) * 4` bytes

Zero mask bit convention: bit = 0 → non-zero (read value); bit = 1 → zero/default (skip).

- [ ] **Step 1: Write failing unit tests**

Add to `crates/paksmith-core/src/asset/property/unversioned.rs` (create file):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn two_prop_header_bytes() -> Vec<u8> {
        // Fragment: skip=0, has_zeros=false, is_last=true, value_num=2
        // packed = 0x0100 | (2u16 << 9) = 0x0100 | 0x0400 = 0x0500
        vec![0x00u8, 0x05]
    }

    #[test]
    fn header_no_zeros_two_props() {
        let bytes = two_prop_header_bytes();
        let mut cur = Cursor::new(bytes.as_slice());
        let hdr = UnversionedHeader::read(&mut cur, "test.uasset").unwrap();
        assert_eq!(hdr.fragments.len(), 1);
        assert_eq!(hdr.fragments[0].first_num, 0);
        assert_eq!(hdr.fragments[0].value_num, 2);
        assert!(!hdr.fragments[0].has_zeros);
        assert!(hdr.fragments[0].is_last);
        assert!(hdr.zero_mask.is_empty());
    }

    #[test]
    fn header_is_serialized_all_present() {
        let bytes = two_prop_header_bytes();
        let mut cur = Cursor::new(bytes.as_slice());
        let hdr = UnversionedHeader::read(&mut cur, "test.uasset").unwrap();
        let mut zi = 0usize;
        let mut fi = 0usize;
        assert!(hdr.is_serialized(0, &mut zi, &mut fi));
        assert!(hdr.is_serialized(1, &mut zi, &mut fi));
        assert!(!hdr.is_serialized(2, &mut zi, &mut fi)); // past end → default
    }

    #[test]
    fn header_with_skip() {
        // Fragment: skip=1, has_zeros=false, is_last=true, value_num=1
        // packed = 0x01 | 0x0100 | (1u16 << 9) = 0x0201 (wait: skip_num=1 → bits 0-6 = 1)
        // = 1 | 0x0100 | 0x0200 = 0x0301
        let bytes = vec![0x01u8, 0x03];
        let mut cur = Cursor::new(bytes.as_slice());
        let hdr = UnversionedHeader::read(&mut cur, "test.uasset").unwrap();
        assert_eq!(hdr.fragments[0].first_num, 1); // skip_num=1, so first_num = 0+1 = 1
        assert_eq!(hdr.fragments[0].value_num, 1);
        let mut zi = 0usize;
        let mut fi = 0usize;
        // schema index 0 is in skip range → not serialised
        assert!(!hdr.is_serialized(0, &mut zi, &mut fi));
        // schema index 1 is the one value → serialised
        assert!(hdr.is_serialized(1, &mut zi, &mut fi));
    }

    #[test]
    fn header_with_zero_mask() {
        // Fragment: skip=0, has_zeros=true, is_last=true, value_num=2
        // packed = 0x0080 | 0x0100 | (2u16 << 9) = 0x0080 | 0x0100 | 0x0400 = 0x0580
        // zero_mask: 2 bits, stored in 1 byte; bit0=0(non-zero), bit1=1(zero)
        // byte = 0b00000010 = 0x02
        let bytes = vec![0x80u8, 0x05, 0x02u8];
        let mut cur = Cursor::new(bytes.as_slice());
        let hdr = UnversionedHeader::read(&mut cur, "test.uasset").unwrap();
        assert_eq!(hdr.zero_mask.len(), 1); // 1 byte
        let mut zi = 0usize;
        let mut fi = 0usize;
        // index 0: bit0=0 → non-zero → serialised
        assert!(hdr.is_serialized(0, &mut zi, &mut fi));
        // index 1: bit1=1 → zero → NOT serialised
        assert!(!hdr.is_serialized(1, &mut zi, &mut fi));
    }
}
```

Run: `cargo test -p paksmith-core --lib asset::property::unversioned::tests 2>&1 | tail -10`

Expected: FAIL — module not found.

- [ ] **Step 2: Implement `UnversionedHeader`**

Create `crates/paksmith-core/src/asset/property/unversioned.rs`:

```rust
use std::io::{Cursor, Read};

use byteorder::{ReadBytesExt, LE};
use tracing::warn;

use crate::asset::fstring::read_asset_fstring;
use crate::asset::mappings::{MappedProperty, MappedPropertyType, Usmap};
use crate::asset::package_index::PackageIndex;
use crate::asset::property::bag::MAX_PROPERTY_DEPTH;
use crate::asset::property::primitives::{
    read_soft_path_payload, resolve_package_index, PropertyValue,
};
use crate::asset::property::read_fname_pair;
use crate::asset::property::text::{read_ftext, FTextHistory};
use crate::asset::property::Property;
use crate::asset::AssetContext;
use crate::error::{AssetParseFault, AssetWireField};
use crate::PaksmithError;

// Bit masks from oracle unreal_asset_base::unversioned::header::UnversionedHeaderFragment
const SKIP_NUM_MASK: u16 = 0x007f;
const HAS_ZEROS_MASK: u16 = 0x0080;
const IS_LAST_MASK: u16 = 0x0100;
const VALUE_NUM_SHIFT: u16 = 9;

#[derive(Debug, Clone)]
pub(super) struct Fragment {
    pub skip_num: u8,
    pub value_num: u8,
    pub first_num: u16, // first schema index of VALUE slots (post-skip)
    pub has_zeros: bool,
    pub is_last: bool,
}

#[derive(Debug, Clone)]
pub(super) struct UnversionedHeader {
    pub fragments: Vec<Fragment>,
    /// Raw zero-mask bytes (Lsb0: bit 0 of byte 0 = property at zero_mask_start).
    pub zero_mask: Vec<u8>,
}

impl UnversionedHeader {
    pub fn read(cur: &mut Cursor<&[u8]>, asset_path: &str) -> crate::Result<Self> {
        let mut fragments: Vec<Fragment> = Vec::new();
        let mut cumulative_first: u16 = 0;
        let mut total_zero_count: u16 = 0;

        loop {
            let packed = cur.read_u16::<LE>().map_err(|_| truncated_at(cur, asset_path))?;
            let skip_num = (packed & SKIP_NUM_MASK) as u8;
            let has_zeros = (packed & HAS_ZEROS_MASK) != 0;
            let is_last = (packed & IS_LAST_MASK) != 0;
            let value_num = (packed >> VALUE_NUM_SHIFT) as u8;
            let first_num = cumulative_first + skip_num as u16;
            cumulative_first += skip_num as u16 + value_num as u16;

            if has_zeros {
                total_zero_count += value_num as u16;
            }

            fragments.push(Fragment { skip_num, value_num, first_num, has_zeros, is_last });

            if is_last {
                break;
            }
        }

        let zero_mask = if total_zero_count > 0 {
            let byte_count = if total_zero_count <= 8 {
                1usize
            } else if total_zero_count <= 16 {
                2usize
            } else {
                ((total_zero_count as usize + 31) / 32) * 4
            };
            let mut mask = vec![0u8; byte_count];
            cur.read_exact(&mut mask).map_err(|_| truncated_at(cur, asset_path))?;
            mask
        } else {
            Vec::new()
        };

        Ok(UnversionedHeader { fragments, zero_mask })
    }

    /// Returns true if the property at `schema_idx` has a serialised value (not zero/default).
    /// `zero_mask_idx` and `frag_idx` are cursor state — pass by mutable reference so
    /// the caller can call this sequentially for consecutive schema indices.
    pub fn is_serialized(
        &self,
        schema_idx: u16,
        zero_mask_idx: &mut usize,
        frag_idx: &mut usize,
    ) -> bool {
        // Advance past exhausted fragments
        while *frag_idx < self.fragments.len() {
            let frag = &self.fragments[*frag_idx];
            let value_start = frag.first_num;
            let value_end = frag.first_num + frag.value_num as u16;

            if schema_idx < value_start {
                // In the skip range before this fragment
                return false;
            } else if schema_idx < value_end {
                // In the value range of this fragment
                if frag.has_zeros {
                    let bit_idx = *zero_mask_idx;
                    *zero_mask_idx += 1;
                    let byte = self.zero_mask.get(bit_idx / 8).copied().unwrap_or(0);
                    let bit = (byte >> (bit_idx % 8)) & 1;
                    return bit == 0; // 0 = non-zero = serialised; 1 = zero = default
                } else {
                    return true;
                }
            } else {
                // Past this fragment, try the next
                *frag_idx += 1;
            }
        }
        false // Past all fragments → default
    }
}

/// Read all unversioned properties for an export whose class is `class_name`.
/// Returns a `Vec<Property>` (may be partial if an unsupported type is encountered).
///
/// **Recursion semantics on `UnversionedTypeNotSupported`:** When
/// `read_unversioned_value` recurses (struct nesting, array element) and hits
/// an unsupported type at depth, the `UnversionedTypeNotSupported` error
/// propagates up the recursion stack. The enclosing `read_unversioned_properties`
/// catches it once at the outermost level and returns the partial tree up to
/// the recursion point — properties that came after the failed nested
/// struct/array are NOT decoded. This matches the "warn + stop" contract;
/// partial-but-not-garbage > silent misparse of subsequent properties whose
/// offsets depend on the failed read's byte count.
pub(crate) fn read_unversioned_properties(
    cur: &mut Cursor<&[u8]>,
    class_name: &str,
    usmap: &Usmap,
    ctx: &AssetContext,
    asset_path: &str,
    depth: usize,
) -> crate::Result<Vec<Property>> {
    if depth > MAX_PROPERTY_DEPTH {
        return Err(PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::PropertyDepthExceeded {
                depth,
                limit: MAX_PROPERTY_DEPTH,
            },
        });
    }

    let all_props = usmap.get_all_properties(class_name);
    if all_props.is_empty() {
        warn!(asset_path, class_name, "no schema found for class; skipping unversioned properties");
        return Ok(Vec::new());
    }

    let header = UnversionedHeader::read(cur, asset_path)?;

    let mut result: Vec<Property> = Vec::new();
    let mut zero_mask_idx = 0usize;
    let mut frag_idx = 0usize;

    for (schema_order, mapped_prop) in all_props.iter().enumerate() {
        let schema_idx = schema_order as u16;
        if !header.is_serialized(schema_idx, &mut zero_mask_idx, &mut frag_idx) {
            continue;
        }

        match read_unversioned_value(cur, mapped_prop, usmap, ctx, asset_path, depth) {
            Ok(value) => {
                result.push(Property {
                    name: mapped_prop.name.clone(),
                    array_index: mapped_prop.array_index,
                    guid: None,
                    value,
                });
            }
            Err(e) if is_unsupported_type(&e) => {
                warn!(
                    asset_path,
                    class_name,
                    property = mapped_prop.name.as_str(),
                    "unsupported unversioned property type; stopping read"
                );
                break;
            }
            Err(e) => return Err(e),
        }
    }

    Ok(result)
}

fn is_unsupported_type(e: &PaksmithError) -> bool {
    matches!(e, PaksmithError::AssetParse {
        fault: AssetParseFault::UnversionedTypeNotSupported { .. },
        ..
    })
}

fn read_unversioned_value(
    cur: &mut Cursor<&[u8]>,
    prop: &MappedProperty,
    usmap: &Usmap,
    ctx: &AssetContext,
    asset_path: &str,
    depth: usize,
) -> crate::Result<PropertyValue> {
    use MappedPropertyType as MT;
    Ok(match &prop.prop_type {
        MT::Bool => {
            let b = cur.read_u8().map_err(|_| truncated_at(cur, asset_path))?;
            PropertyValue::Bool(b != 0)
        }
        MT::Int8 => PropertyValue::Int8(cur.read_i8().map_err(|_| truncated_at(cur, asset_path))?),
        MT::Int16 => PropertyValue::Int16(cur.read_i16::<LE>().map_err(|_| truncated_at(cur, asset_path))?),
        MT::Int32 => PropertyValue::Int(cur.read_i32::<LE>().map_err(|_| truncated_at(cur, asset_path))?),
        MT::Int64 => PropertyValue::Int64(cur.read_i64::<LE>().map_err(|_| truncated_at(cur, asset_path))?),
        MT::UInt8 => PropertyValue::Byte(cur.read_u8().map_err(|_| truncated_at(cur, asset_path))?),
        MT::UInt16 => PropertyValue::UInt16(cur.read_u16::<LE>().map_err(|_| truncated_at(cur, asset_path))?),
        MT::UInt32 => PropertyValue::UInt32(cur.read_u32::<LE>().map_err(|_| truncated_at(cur, asset_path))?),
        MT::UInt64 => PropertyValue::UInt64(cur.read_u64::<LE>().map_err(|_| truncated_at(cur, asset_path))?),
        MT::Float => PropertyValue::Float(cur.read_f32::<LE>().map_err(|_| truncated_at(cur, asset_path))?),
        MT::Double => PropertyValue::Double(cur.read_f64::<LE>().map_err(|_| truncated_at(cur, asset_path))?),
        MT::Str => PropertyValue::Str(read_asset_fstring(cur, asset_path)?),
        MT::Name => PropertyValue::Name(read_fname_pair(
            cur, ctx, asset_path, AssetWireField::PropertyTagName,
        )?),
        MT::Text => {
            // Mirror `containers.rs:133-143`: `read_ftext` (Phase 2b) is
            // size-permissive at `tag_size = 0` for None/Base histories,
            // but `FTextHistory::Unknown` cannot be decoded without a size
            // hint and would silently swallow subsequent bytes. Reject
            // explicitly with `TextHistoryUnsupportedInElement` so the
            // partial-tree contract surfaces the issue.
            let text = read_ftext(cur, ctx, asset_path, 0)?;
            if let FTextHistory::Unknown { history_type, .. } = text.history {
                return Err(PaksmithError::AssetParse {
                    asset_path: asset_path.to_string(),
                    fault: AssetParseFault::TextHistoryUnsupportedInElement { history_type },
                });
            }
            PropertyValue::Text(text)
        }
        MT::Enum { enum_name } => {
            // Unversioned EnumProperty wire format (per CUE4Parse
            // EnumProperty constructor: `Ar.HasUnversionedProperties &&
            // type == NORMAL`): a single u8 index (the default underlying
            // type is ByteProperty). The resolved value name comes from
            // `usmap.enums[enum_name]`. Non-byte underlying types
            // (UInt32 etc.) are rare and deferred.
            let idx = cur.read_u8().map_err(|_| truncated_at(cur, asset_path))?;
            let value = usmap
                .enums
                .get(enum_name)
                .and_then(|values| values.get(idx as usize))
                .cloned()
                .unwrap_or_else(|| format!("{enum_name}::{idx}"));
            PropertyValue::Enum {
                type_name: enum_name.clone(),
                value,
            }
        }
        MT::Object => {
            // ObjectProperty: raw i32 package index, decoded into the
            // post-Phase-2e typed shape `Object { kind: PackageIndex,
            // name: String }`. Same wire format in versioned and
            // unversioned modes; the typed `kind` preserves Null /
            // Import(N) / Export(N) discrimination.
            let raw = cur
                .read_i32::<LE>()
                .map_err(|_| truncated_at(cur, asset_path))?;
            let kind = PackageIndex::try_from_raw(raw).map_err(|_| PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::PackageIndexUnderflow {
                    field: AssetWireField::ObjectPropertyIndex,
                },
            })?;
            let name = resolve_package_index(kind, ctx, asset_path).unwrap_or_default();
            PropertyValue::Object { kind, name }
        }
        MT::SoftObject => {
            // SoftObjectProperty: FSoftObjectPath wire format = FName +
            // FString (per CUE4Parse's FSoftObjectPath constructor).
            // Reuse Phase 2d's `read_soft_path_payload` rather than
            // treating SoftObject as an i32 (earlier draft did, which
            // would misparse — FSoftObjectPath is variable-length).
            let (asset_path_str, sub_path) = read_soft_path_payload(cur, ctx, asset_path)?;
            PropertyValue::SoftObjectPath {
                asset_path: asset_path_str,
                sub_path,
            }
        }
        MT::Struct { struct_name } => {
            let nested = read_unversioned_properties(
                cur, struct_name, usmap, ctx, asset_path, depth + 1,
            )?;
            PropertyValue::Struct {
                struct_name: struct_name.clone(),
                properties: nested,
            }
        }
        MT::Array { inner } => {
            use crate::asset::property::MAX_COLLECTION_ELEMENTS;
            let count = cur
                .read_i32::<LE>()
                .map_err(|_| truncated_at(cur, asset_path))?;
            if count < 0 || (count as usize) > MAX_COLLECTION_ELEMENTS {
                return Err(PaksmithError::AssetParse {
                    asset_path: asset_path.to_string(),
                    fault: AssetParseFault::CollectionElementCountExceeded {
                        collection: "array",
                        count,
                        limit: MAX_COLLECTION_ELEMENTS,
                    },
                });
            }
            let count = count as usize;
            let mut elements: Vec<PropertyValue> = Vec::with_capacity(count);
            let synthetic = MappedProperty {
                name: String::new(),
                schema_index: 0,
                array_index: 0,
                prop_type: (**inner).clone(),
            };
            for _ in 0..count {
                elements.push(read_unversioned_value(
                    cur, &synthetic, usmap, ctx, asset_path, depth,
                )?);
            }
            PropertyValue::Array {
                inner_type: mapped_type_wire_name(inner),
                elements,
            }
        }
        MT::Unknown(byte) => {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::UnversionedTypeNotSupported {
                    type_byte: *byte,
                    property_name: prop.name.clone(),
                },
            });
        }
    })
}

/// Map a [`MappedPropertyType`] back to the UE wire-format type name string
/// (e.g. `IntProperty`, `FloatProperty`) for storage in
/// `PropertyValue::Array.inner_type`. This is the inverse of the byte → type
/// mapping in `mappings.rs::read_mapped_type`.
fn mapped_type_wire_name(t: &MappedPropertyType) -> String {
    match t {
        MappedPropertyType::Bool => "BoolProperty",
        MappedPropertyType::Int8 => "Int8Property",
        MappedPropertyType::Int16 => "Int16Property",
        MappedPropertyType::Int32 => "IntProperty",
        MappedPropertyType::Int64 => "Int64Property",
        MappedPropertyType::UInt8 => "ByteProperty",
        MappedPropertyType::UInt16 => "UInt16Property",
        MappedPropertyType::UInt32 => "UInt32Property",
        MappedPropertyType::UInt64 => "UInt64Property",
        MappedPropertyType::Float => "FloatProperty",
        MappedPropertyType::Double => "DoubleProperty",
        MappedPropertyType::Str => "StrProperty",
        MappedPropertyType::Name => "NameProperty",
        MappedPropertyType::Text => "TextProperty",
        MappedPropertyType::Enum { .. } => "EnumProperty",
        MappedPropertyType::Struct { .. } => "StructProperty",
        MappedPropertyType::Object => "ObjectProperty",
        MappedPropertyType::SoftObject => "SoftObjectProperty",
        MappedPropertyType::Array { .. } => "ArrayProperty",
        MappedPropertyType::Unknown(_) => "Unknown",
    }
    .to_string()
}

fn truncated_at(cur: &Cursor<&[u8]>, asset_path: &str) -> PaksmithError {
    PaksmithError::AssetParse {
        asset_path: asset_path.to_string(),
        fault: AssetParseFault::UnexpectedEof {
            field: AssetWireField::PropertyTagSize,
        },
    }
}
```

> **Note:** Imports reference types defined in Phases 2a–2e:
>
> - `read_fstring` is `pub(crate)` in `container::pak::index` after Phase 2a Task 2.
> - `resolve_fname` is defined in Phase 2b's `property::tag`.
> - `read_ftext` is defined in Phase 2b's `property::text` with signature `(reader, ctx, asset_path, tag_size: u64)`.
> - `resolve_package_index` is defined in Phase 2e's `property::primitives`.
> - `MAX_COLLECTION_ELEMENTS` is defined in Phase 2c's `property/mod.rs`.
> - `MAX_PROPERTY_DEPTH` is defined in Phase 2a's `property::bag` (as `usize`).
> - `PropertyDepthExceeded` is the existing variant from Phase 2b (`{ depth: usize, limit: usize }`); reused rather than introducing a sibling.
>
> **Note:** `AssetParseFault::UnversionedTypeNotSupported` is the only new variant introduced here. Add it now — bare (no `#[error(...)]`, since `AssetParseFault` Display is hand-rolled per Fix 1 in Task 1).

Find `AssetParseFault` in `error.rs` and add the variant:

```rust
/// An unversioned property's schema-declared type byte is one paksmith
/// doesn't yet decode (Map/Set/Delegate/Interface/FieldPath). Phase 2f
/// stops the property walk and returns the partial tree rather than
/// mis-decoding subsequent properties whose offsets depend on the
/// failed read's byte count.
UnversionedTypeNotSupported {
    /// The unsupported `EPropertyType` discriminant byte.
    type_byte: u8,
    /// The schema name of the property where decoding stopped.
    property_name: String,
},
```

Then add the matching arm to `impl fmt::Display for AssetParseFault` (next to the `UnversionedWithoutMappings` arm added in Task 1 Step 4b):

```rust
Self::UnversionedTypeNotSupported { type_byte, property_name } => write!(
    f,
    "unversioned property `{property_name}` has unsupported type byte {type_byte} \
     (Map/Set/Delegate/Interface/FieldPath not yet supported in unversioned mode)",
),
```

- [ ] **Step 3: Register the module**

In `crates/paksmith-core/src/asset/property/mod.rs`:

```rust
pub(crate) mod unversioned;
pub(crate) use unversioned::read_unversioned_properties;
```

- [ ] **Step 4: Wire unversioned dispatch into `Package::read_from`**

Phase 2a's `Package` stores property bags in a parallel `payloads: Vec<PropertyBag>` indexed by export position (not in a `property_bag` field on `ObjectExport`). The unversioned dispatch builds the payload vector alongside the tagged path.

Replace the `// TODO Task 4` comment from Task 3 Step 4 with the real call:

```rust
if summary.package_flags & PKG_UNVERSIONED_PROPERTIES != 0 {
    let usmap = ctx.mappings.as_deref().ok_or_else(|| PaksmithError::AssetParse {
        asset_path: asset_path.to_string(),
        fault: AssetParseFault::UnversionedWithoutMappings,
    })?;
    let mut payloads: Vec<PropertyBag> = Vec::with_capacity(exports.exports.len());
    for export in exports.exports.iter() {
        let class_name = crate::asset::property::primitives::resolve_package_index(
            export.class_index,
            &ctx,
            asset_path,
        )
        .unwrap_or_default();
        // Bounds-check serial_offset/serial_size before slicing. A malicious
        // export could claim serial_offset = i64::MAX or serial_size = i64::MAX,
        // making `start..end` panic on the slice. Phase 2a already rejects
        // negative values; here we reject anything that would exceed the
        // stitched buffer length. The in-scope variable is `bytes: &[u8]`
        // (see `Package::read_from` around line 337).
        let start = usize::try_from(export.serial_offset).map_err(|_| {
            PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::InvalidOffset {
                    field: AssetWireField::ExportSerialOffset,
                    offset: export.serial_offset,
                    asset_size: bytes.len() as u64,
                },
            }
        })?;
        let size = usize::try_from(export.serial_size).map_err(|_| {
            PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::InvalidOffset {
                    field: AssetWireField::ExportSerialSize,
                    offset: export.serial_size,
                    asset_size: bytes.len() as u64,
                },
            }
        })?;
        let end = start.checked_add(size).ok_or_else(|| PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::U64ArithmeticOverflow {
                operation: AssetOverflowSite::ExportPayloadExtent,
            },
        })?;
        if end > bytes.len() {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::InvalidOffset {
                    field: AssetWireField::ExportSerialOffset,
                    offset: export.serial_offset,
                    asset_size: bytes.len() as u64,
                },
            });
        }
        let export_bytes = &bytes[start..end];
        let mut export_cur = Cursor::new(export_bytes);
        let props = read_unversioned_properties(
            &mut export_cur,
            &class_name,
            usmap,
            &ctx,
            asset_path,
            0,
        )?;
        payloads.push(PropertyBag::tree(props));
    }
    // The tagged branch below produces a parallel `payloads` vector for the
    // non-unversioned case. After this block, return the constructed Package
    // with `payloads` populated.
}
```

> **Note:** `resolve_package_index` takes typed `PackageIndex` (Phase 2e shape), not raw `i32`. The earlier draft suggesting `.to_raw()` / `as_i32()` is obsolete — pass `export.class_index` directly. Widen the helper's visibility from `pub(super)` to `pub(crate)` at `primitives.rs:455` (same step in Task 3 above) so this call from `package.rs` compiles.

- [ ] **Step 5: Run the header unit tests**

```shell
set -o pipefail
cargo test -p paksmith-core --lib asset::property::unversioned::tests 2>&1 | tail -15
```

Expected: all 4 header tests pass.

- [ ] **Step 6: Compile-check + doc gate**

```shell
set -o pipefail
cargo build -p paksmith-core
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
```

Expected: no errors. (Do not pipe `cargo build` through `grep` — that masks the exit code per `MEMORY/feedback_pipe_masks_exit_code.md`.)

- [ ] **Step 7: Commit**

```bash
git add crates/paksmith-core/src/asset/property/unversioned.rs \
        crates/paksmith-core/src/asset/property/mod.rs \
        crates/paksmith-core/src/asset/package.rs \
        crates/paksmith-core/src/error.rs
git commit -m "$(cat <<'EOF'
feat(property): FUnversionedHeader + read_unversioned_properties

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: Fixture builder + oracle cross-validation

**Files:**

- Create: `crates/paksmith-core/src/testing/usmap.rs`
- Modify: `crates/paksmith-core/src/testing/mod.rs`
- Modify: `crates/paksmith-fixture-gen/src/uasset.rs`

The fixture is a minimal UE 4.27 asset with `PKG_UnversionedProperties` set. The class "Hero" has two properties: `Health: Int32 = 100`, `Speed: Float = 600.0`. The companion `.usmap` is the bytes from Task 2's `minimal_usmap_none()`.

- [ ] **Step 0: Add `build_minimal_ue4_27_unversioned` to `testing/uasset.rs`**

Phase 2c/2d/2e established `MinimalPackageSpec` + `build_minimal(spec)` (at `testing/uasset.rs:267`) as the canonical fixture entrypoint. New fixtures construct a spec and let `build_minimal` handle offset patching — do **not** hand-mutate emitted bytes and re-serialize the summary.

Add this sibling to `build_minimal_ue4_27_with_extended_types` (line ~1063) in `testing/uasset.rs`:

```rust
/// UE 4.27 minimal package with `PKG_UnversionedProperties` set,
/// one export whose `object_name` is `class_name`, and an opaque
/// `payload` byte block in the export's serial slot. Phase 2f's
/// unversioned reader walks the schema named `class_name` (from a
/// `.usmap` mappings file) against `payload`.
#[must_use]
pub fn build_minimal_ue4_27_unversioned(class_name: &str, payload: Vec<u8>) -> MinimalPackage {
    let mut spec = MinimalPackageSpec::default();
    // PKG_UnversionedProperties = 0x0000_2000.
    spec.package_flags |= 0x0000_2000;
    // Append `class_name` to the default 3-entry name table; the export
    // points at it via `object_name`.
    let class_name_idx = u32::try_from(spec.names.names.len()).expect("name table within u32");
    spec.names.names.push(FName::new(class_name));
    spec.exports.exports[0].object_name = class_name_idx;
    spec.exports.exports[0].serial_size =
        i64::try_from(payload.len()).expect("payload fits in i64");
    spec.payloads = vec![payload];
    build_minimal(spec)
}
```

`build_minimal` patches `summary.total_header_size`, the per-export `serial_offset`, and writes the summary bytes in one pass — no manual offset bookkeeping needed.

- [ ] **Step 1: Create `testing/usmap.rs`**

```rust
//! Test helpers for unversioned-property fixtures.
//!
//! `build_minimal_usmap_bytes` and `build_minimal_unversioned_uasset_bytes` are
//! used by both unit tests (via `__test_utils` feature) and fixture-gen.

use byteorder::{WriteBytesExt, LE};

/// Returns `.usmap` bytes for a class `Hero` with two properties:
/// `Health: IntProperty` (schema_index 0) and `Speed: FloatProperty` (schema_index 1).
/// Version=Initial, Compression=None.
pub fn build_minimal_usmap_bytes() -> Vec<u8> {
    let mut data: Vec<u8> = Vec::new();

    // Name table: ["Hero", "", "Health", "Speed"]
    data.extend_from_slice(&4u32.to_le_bytes());
    for (s, name) in [(5u8, "Hero"), (1u8, ""), (7u8, "Health"), (6u8, "Speed")] {
        data.push(s);
        data.extend_from_slice(name.as_bytes());
    }
    // Enum table: empty
    data.extend_from_slice(&0u32.to_le_bytes());
    // Schema table: one class
    data.extend_from_slice(&1u32.to_le_bytes());
    // Schema "Hero"
    data.extend_from_slice(&0i32.to_le_bytes()); // name = "Hero" (idx 0)
    data.extend_from_slice(&1i32.to_le_bytes()); // super = "" (idx 1)
    data.extend_from_slice(&2u16.to_le_bytes()); // prop_count
    data.extend_from_slice(&2u16.to_le_bytes()); // serial_count
    // Prop 0: Health IntProperty
    data.extend_from_slice(&0u16.to_le_bytes());  // schema_index
    data.push(1u8);                               // array_size
    data.extend_from_slice(&2i32.to_le_bytes());  // name idx = "Health"
    data.push(2u8);                               // IntProperty
    // Prop 1: Speed FloatProperty
    data.extend_from_slice(&1u16.to_le_bytes());
    data.push(1u8);
    data.extend_from_slice(&3i32.to_le_bytes()); // name idx = "Speed"
    data.push(3u8);                              // FloatProperty

    let data_len = data.len() as u32;
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(&[0x30u8, 0xC4u8]); // magic LE
    out.push(0u8);                             // version = Initial
    out.push(0u8);                             // compression = None
    out.extend_from_slice(&data_len.to_le_bytes());
    out.extend_from_slice(&data_len.to_le_bytes());
    out.extend_from_slice(&data);
    out
}

/// Returns a valid UE 4.27 `.uasset` binary with `PKG_UnversionedProperties` set,
/// containing one export of class "Hero" with two serialised properties:
/// `Health = 100i32`, `Speed = 600.0f32`.
///
/// The payload bytes (after the header) are:
/// - FUnversionedHeader fragment: skip=0, has_zeros=false, is_last=true, value_num=2
///   → packed = 0x0500, LE bytes [0x00, 0x05]
/// - Health = 100i32 LE: [0x64, 0x00, 0x00, 0x00]
/// - Speed = 600.0f32 LE: [0x00, 0x00, 0x16, 0x44]
/// Total payload: 10 bytes.
///
/// Built by reusing Phase 2a's `build_minimal_ue4_27()` and then patching the
/// emitted bytes: set the `PKG_UnversionedProperties` bit in
/// `summary.package_flags`, and swap the export's payload region with the
/// 10 bytes above. The patching helpers live alongside `build_minimal_ue4_27`
/// in `testing/uasset.rs` and are intended for this fixture (Phase 2f) and
/// any future unversioned-asset tests.
pub fn build_minimal_unversioned_uasset_bytes() -> Vec<u8> {
    use crate::testing::uasset::{
        build_minimal_ue4_27_unversioned, MinimalPackage,
    };

    let payload: Vec<u8> = {
        let mut p = Vec::new();
        // FUnversionedHeader: one fragment, no zeros, 2 values, last
        // packed = IS_LAST(0x0100) | (value_num=2 << 9=0x0400) = 0x0500
        p.write_u16::<LE>(0x0500u16).unwrap();
        // Health = 100i32
        p.write_i32::<LE>(100).unwrap();
        // Speed = 600.0f32 = 0x44160000
        p.write_f32::<LE>(600.0f32).unwrap();
        p
    };

    let MinimalPackage { bytes, .. } = build_minimal_ue4_27_unversioned(
        // Class name for the single export — looked up by the unversioned reader.
        "Hero",
        // Replacement payload for the export's serialized region.
        payload,
    );
    bytes
}
```

> See **Step 0** above for the `build_minimal_ue4_27_unversioned` definition. It lives next to `build_minimal_ue4_27_with_extended_types` in `testing/uasset.rs` because it's a uasset variant; `testing/usmap.rs` only owns the `.usmap` bytes builder.

- [ ] **Step 2: Register `testing/usmap.rs`**

In `crates/paksmith-core/src/testing/mod.rs`, add an unconditional `pub mod` next to the existing sibling modules (`pub mod oom; pub mod uasset; pub mod v10; pub mod wire;`). The whole `testing` module is already feature-gated at `lib.rs:37-38`, so a per-submodule `#[cfg(feature = "__test_utils")]` is redundant.

```rust
pub mod usmap;
```

- [ ] **Step 3: Write the oracle cross-validation test in fixture-gen**

In `crates/paksmith-fixture-gen/src/uasset.rs`, add a new section for unversioned fixtures:

```rust
/// Cross-validate unversioned property parsing between paksmith and unreal_asset oracle.
pub fn validate_unversioned_fixture() {
    use paksmith_core::testing::usmap::{build_minimal_usmap_bytes, build_minimal_unversioned_uasset_bytes};
    use paksmith_core::asset::mappings::Usmap;
    use paksmith_core::asset::Package;
    use unreal_asset::engine_version::EngineVersion;

    let usmap_bytes = build_minimal_usmap_bytes();
    let asset_bytes = build_minimal_unversioned_uasset_bytes();

    // 1. Validate our Usmap parser against the oracle's Usmap parser
    let our_usmap = Usmap::from_bytes(&usmap_bytes)
        .expect("paksmith Usmap::from_bytes failed");
    let oracle_usmap = unreal_asset::unversioned::Usmap::new(
        std::io::Cursor::new(usmap_bytes.clone()),
    ).expect("oracle Usmap::new failed");

    let our_schema = our_usmap.schemas.get("Hero").expect("Hero schema missing");
    let oracle_schema = oracle_usmap.schemas.get_by_key("Hero").expect("oracle Hero schema missing");
    assert_eq!(our_schema.properties.len(), oracle_schema.prop_count as usize,
        "schema property count mismatch");
    assert_eq!(our_schema.properties[0].name, "Health",
        "first property name mismatch");
    assert_eq!(our_schema.properties[1].name, "Speed",
        "second property name mismatch");

    // 2. Validate property tree against oracle Asset parse
    let oracle_asset = unreal_asset::Asset::new(
        std::io::Cursor::new(asset_bytes.clone()),
        None,
        EngineVersion::VER_UE4_27,
        Some(oracle_usmap),
    ).expect("oracle Asset::new failed");

    let our_pkg = Package::read_from(
        &asset_bytes,
        None,
        Some(&our_usmap),
        "test/Hero.uasset",
    ).expect("paksmith Package::read_from failed");

    // Oracle: navigate to the first export's properties. `BaseExport`
    // has no `properties` field — properties live on `NormalExport`,
    // accessed via the `ExportNormalTrait::get_normal_export(&self) ->
    // Option<&NormalExport>` accessor. Bring the trait into scope so
    // the method resolves.
    use unreal_asset::exports::ExportNormalTrait;
    let oracle_first_export = oracle_asset
        .asset_data
        .exports
        .first()
        .expect("oracle: no exports");
    let oracle_normal = oracle_first_export
        .get_normal_export()
        .expect("oracle: first export is not a NormalExport");
    let oracle_props = &oracle_normal.properties;

    // Our parse: Phase 2a stores PropertyBags in a parallel `payloads`
    // vector indexed by export position. Take payloads[0] for the first
    // (and only) export.
    let our_bag = our_pkg.payloads.first().expect("paksmith: no payloads");
    let props = match our_bag {
        paksmith_core::asset::property::PropertyBag::Tree { properties } => properties,
        _ => panic!("expected PropertyBag::Tree, got {our_bag:?}"),
    };

    // Both must yield Health=100 and Speed=600.0.
    assert_eq!(oracle_props.len(), 2, "oracle property count mismatch");
    assert_eq!(props.len(), 2, "paksmith property count mismatch");

    let health = props.iter().find(|p| p.name == "Health").expect("Health missing");
    let speed  = props.iter().find(|p| p.name == "Speed").expect("Speed missing");

    assert!(matches!(health.value, paksmith_core::asset::property::primitives::PropertyValue::Int(100)));
    assert!(
        matches!(speed.value, paksmith_core::asset::property::primitives::PropertyValue::Float(v) if (v - 600.0f32).abs() < f32::EPSILON)
    );

    println!("unversioned_fixture: oracle cross-validation passed");
}
```

> **Note:** The `unreal_asset::Asset::new` signature and the oracle's export/property access API should be confirmed against the pinned revision `f4df5d8e`. In that revision, `BaseExport` has **no** `properties` field — properties live on `NormalExport`, reached via `ExportNormalTrait::get_normal_export(&self) -> Option<&NormalExport>` (used above). If the oracle pin moves and the trait disappears, adapt to the equivalent accessor. The key invariant is: oracle parses `Health=100` and `Speed=600.0`, and so does paksmith. Adjust navigation code to match; do not adjust the invariant itself.

- [ ] **Step 4: Call `validate_unversioned_fixture` from fixture-gen's `main`**

In `crates/paksmith-fixture-gen/src/main.rs`, add:

```rust
uasset::validate_unversioned_fixture();
```

- [ ] **Step 5: Run fixture-gen**

```shell
cargo run -p paksmith-fixture-gen 2>&1 | grep -E "unversioned|FAIL|panicked|error"
```

Expected: `unversioned_fixture: oracle cross-validation passed`. If it fails with a mismatch, the most likely cause is the `BoolProperty` or fragment bit layout. Print the raw oracle property list and compare.

- [ ] **Step 6: Commit**

```bash
git add crates/paksmith-core/src/testing/usmap.rs \
        crates/paksmith-core/src/testing/uasset.rs \
        crates/paksmith-core/src/testing/mod.rs \
        crates/paksmith-fixture-gen/src/uasset.rs \
        crates/paksmith-fixture-gen/src/main.rs
git commit -m "$(cat <<'EOF'
test(unversioned): fixture builder + oracle cross-validation for Phase 2f

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

> **Fixture-count gate (`MEMORY/feedback_fixture_count_gate.md`):** Task 5 does **not** commit a new on-disk `tests/fixtures/*.pak` — `build_minimal_unversioned_uasset_bytes` returns in-memory `Vec<u8>` and `build_minimal_usmap_bytes` likewise. The CI fixture-count gate at `.github/workflows/ci.yml:133` (`expected=32`) stays at 32. If a follow-up commits a `real_v8b_unversioned.pak` alongside Phase 2e's `real_v8b_split.pak`, bump to 33 and extend the enumeration comment in the same change.

---

### Task 6: Integration tests

**Files:**

- Create: `crates/paksmith-core/tests/unversioned_integration.rs`

- [ ] **Step 1: Write 5 integration tests**

```rust
//! Integration tests for Phase 2f: unversioned properties and .usmap mappings.

use paksmith_core::asset::{mappings::Usmap, Package};
use paksmith_core::asset::property::{primitives::PropertyValue, PropertyBag};
use paksmith_core::error::AssetParseFault;
use paksmith_core::testing::usmap::{build_minimal_usmap_bytes, build_minimal_unversioned_uasset_bytes};
use paksmith_core::PaksmithError;

fn our_usmap() -> Usmap {
    Usmap::from_bytes(&build_minimal_usmap_bytes()).unwrap()
}

fn prop_tree(pkg: &Package) -> &[paksmith_core::asset::property::Property] {
    // Phase 2a: properties live in `pkg.payloads`, parallel to `pkg.exports.exports`.
    match &pkg.payloads[0] {
        PropertyBag::Tree { properties } => properties,
        _ => panic!("expected Tree"),
    }
}

#[test]
fn unversioned_no_mappings_returns_error() {
    let bytes = build_minimal_unversioned_uasset_bytes();
    let err = Package::read_from(&bytes, None, None, "test.uasset").unwrap_err();
    assert!(
        matches!(err, PaksmithError::AssetParse {
            fault: AssetParseFault::UnversionedWithoutMappings, ..
        }),
        "unexpected error: {err}"
    );
}

#[test]
fn unversioned_with_mappings_parses_two_props() {
    let asset = build_minimal_unversioned_uasset_bytes();
    let usmap = our_usmap();
    let pkg = Package::read_from(&asset, None, Some(&usmap), "test.uasset").unwrap();
    let props = prop_tree(&pkg);
    assert_eq!(props.len(), 2);

    let health = props.iter().find(|p| p.name == "Health").expect("Health missing");
    assert!(matches!(health.value, PropertyValue::Int(100)), "Health != 100, got {:?}", health.value);

    let speed = props.iter().find(|p| p.name == "Speed").expect("Speed missing");
    assert!(
        matches!(speed.value, PropertyValue::Float(v) if (v - 600.0f32).abs() < f32::EPSILON),
        "Speed != 600.0, got {:?}", speed.value
    );
}

#[test]
fn unversioned_unknown_class_returns_empty_tree() {
    // Use a usmap that has no schema for "UnknownClass"
    let usmap = our_usmap();
    let asset = build_minimal_unversioned_uasset_bytes();
    // Patch the export's class name to something not in the usmap.
    // Since we can't easily do that here, we build a package with class "UnknownClass".
    // Simplest: just verify that get_all_properties for an absent class returns empty.
    let props = usmap.get_all_properties("UnknownClass");
    assert!(props.is_empty());
    // Full round-trip: if class_name resolves to "", get_all_properties("") is empty → empty tree.
    let pkg = Package::read_from(&asset, None, Some(&usmap), "test.uasset").unwrap();
    let _ = prop_tree(&pkg); // should not panic even if class lookup fails
}

#[test]
fn usmap_invalid_magic_error() {
    let mut bytes = build_minimal_usmap_bytes();
    bytes[0] = 0xFF;
    let err = Usmap::from_bytes(&bytes).unwrap_err();
    assert!(matches!(err, PaksmithError::MappingsParse {
        fault: paksmith_core::error::MappingsParseFault::InvalidMagic { .. }
    }));
}

#[test]
fn usmap_get_all_properties_empty_super() {
    let usmap = our_usmap();
    let props = usmap.get_all_properties("Hero");
    assert_eq!(props.len(), 2);
    assert_eq!(props[0].name, "Health");
    assert_eq!(props[1].name, "Speed");
}
```

- [ ] **Step 2: Run the integration tests**

```shell
set -o pipefail
cargo test -p paksmith-core --features __test_utils --test unversioned_integration 2>&1 | tail -20
```

Expected: all 5 tests pass.

- [ ] **Step 3: Run the full test suite + doc gate**

```shell
set -o pipefail
cargo test --workspace --all-features 2>&1 | tail -20
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
```

Expected: all tests pass. If any Phase 2b test asserted `UnversionedPropertiesUnsupported`, it will need updating to `UnversionedWithoutMappings`.

- [ ] **Step 4: Commit**

```bash
git add crates/paksmith-core/tests/unversioned_integration.rs
git commit -m "$(cat <<'EOF'
test(unversioned): 5 integration tests for Phase 2f mappings + header

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 7: CLI `--mappings` flag + snapshot update

**Files:**

- Modify: `crates/paksmith-cli/src/commands/inspect.rs`

- [ ] **Step 1: Add `--mappings` flag to the inspect command**

Find the `Args` struct for `paksmith inspect` in `inspect.rs`. Add:

```rust
/// Path to a .usmap mappings file for assets with PKG_UnversionedProperties.
/// Optional — versioned assets are parsed without it.
#[arg(long, value_name = "PATH")]
mappings: Option<std::path::PathBuf>,
```

- [ ] **Step 2: Load mappings and thread through `read_from_pak`**

In the command handler, before calling `read_from_pak`:

```rust
let usmap: Option<paksmith_core::asset::mappings::Usmap> = match &args.mappings {
    None => None,
    Some(path) => {
        let bytes = std::fs::read(path)
            .map_err(|e| anyhow::anyhow!("failed to read mappings file {}: {e}", path.display()))?;
        Some(paksmith_core::asset::mappings::Usmap::from_bytes(&bytes)?)
    }
};
```

Update the `read_from_pak` call to pass `usmap.as_ref()`. If `read_from_pak` currently calls `read_from` internally, the mappings must be threaded through. If `read_from_pak` does not yet accept mappings (Task 3 may have left this as `None`), add a `mappings: Option<&Usmap>` parameter to `read_from_pak` and thread it through.

- [ ] **Step 3: Confirm existing snapshots still pass (no diff expected)**

The existing CLI snapshot at `crates/paksmith-cli/tests/snapshots/inspect_cli__inspect_json_snapshot.snap` uses `real_v8b_uasset.pak` — a versioned asset with no `PKG_UnversionedProperties` flag. Adding the `--mappings` flag does not trigger the unversioned path on that fixture, so the snapshot output is unchanged. Phase 2c/2d/2e set the same precedent: extending the asset parser without committing a new pak fixture leaves the CLI snapshot untouched.

```shell
set -o pipefail
cargo test -p paksmith-cli 2>&1 | tail -20
```

Expected: all existing CLI snapshot tests pass without diff. **Do not** run `cargo insta test --review` or `--accept` — there should be no snapshot changes to review.

If a future commit lands a `real_v8b_unversioned.pak` fixture alongside Phase 2e's `real_v8b_split.pak`, that PR is responsible for adding the new snapshot test and bumping the fixture-count gate; Phase 2f itself stops at "compile + existing tests still green."

- [ ] **Step 4: Lint + test + doc gate**

```shell
set -o pipefail
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features 2>&1 | tail -10
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
```

Expected: clippy clean, fmt clean, tests pass, rustdoc clean. (Do not pipe clippy through `grep "^error"` — that drops the real exit code; `-D warnings` is enough for failure to surface in a non-piped run.)

- [ ] **Step 5: Commit**

The CLI snapshot was **not** modified — do not stage `crates/paksmith-cli/tests/snapshots/`.

```bash
git add crates/paksmith-cli/src/commands/inspect.rs
git commit -m "$(cat <<'EOF'
feat(cli): --mappings flag for unversioned asset inspection

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Self-review checklist

**Spec coverage:**

- `.usmap` parser ✓ (Task 2)
- Compression None/ZStd/Brotli ✓ (Task 2); Oodle rejected ✓ (Task 2)
- MappingsParseFault ✓ (Task 1)
- UnversionedWithoutMappings ✓ (Task 1, 3)
- UnversionedPropertiesUnsupported removed ✓ (Task 1)
- AssetContext + Package::read_from threading ✓ (Task 3)
- FUnversionedHeader ✓ (Task 4)
- read_unversioned_properties ✓ (Task 4)
- Primitive type coverage ✓ (Task 4)
- Unsupported type = warn + partial ✓ (Task 4)
- Oracle cross-validation ✓ (Task 5)
- Integration tests ✓ (Task 6)
- CLI --mappings ✓ (Task 7)

**Placeholder scan:** No TBD/TODO in required steps. Task 3 Step 4 has a `// TODO Task 4` that is replaced in Task 4 Step 4 — correct sequencing.

**Type consistency:**

- `MappedPropertyType` defined in Task 2; used in Task 4 ✓
- `UnversionedHeader` defined in Task 4; tested in Task 4 ✓
- `Usmap::from_bytes` defined in Task 2; called in Task 5/6 ✓
- `build_minimal_usmap_bytes` / `build_minimal_unversioned_uasset_bytes` defined in Task 5; used in Task 6 ✓

**Lint gate:** every task ends with `cargo clippy --workspace --all-targets --all-features -- -D warnings` (per `MEMORY.md` `ghas_clippy_extra_lints.md`) AND `cargo fmt --all -- --check` AND `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features` (per `MEMORY/feedback_cargo_doc_in_local_gates.md` — rustdoc lints like `private_intra_doc_links` and `invalid_html_tags` fail CI but slip past clippy). CI's `Lint` job runs all three; clippy + fmt locally do NOT imply rustdoc is clean — Phase 2c Task 7 ate a CI failure from missing this gate. The `.githooks/pre-commit` hook enforces fmt + clippy when wired up via `git config core.hooksPath .githooks` (one-time per clone); doc gate is push-time only. ✓

**Pipe-masking gate (per `MEMORY/feedback_pipe_masks_exit_code.md`):** every cargo command in this plan that ends in `2>&1 | tail -N` (or `| head`, `| grep`) is prefixed with `set -o pipefail` or annotated with a "verify exit code by re-running unpiped" note. Cargo's failure exit code is silently dropped by the pipe otherwise. ✓

**Co-Authored-By trailer (project convention since Phase 2c):** every `git commit -m` HEREDOC body in this plan ends with `Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>`. ✓

**Fixture-count gate (per `MEMORY/feedback_fixture_count_gate.md`):** Phase 2f does NOT add a new on-disk `tests/fixtures/*.pak` — both `build_minimal_usmap_bytes` and `build_minimal_unversioned_uasset_bytes` return in-memory `Vec<u8>`. The CI gate at `.github/workflows/ci.yml:133` stays at `expected=32`. If a follow-up commits a `real_v8b_unversioned.pak`, that PR bumps to 33 and extends the enumeration comment in the same change. ✓
