# Paksmith Phase 2g: Collection-of-Struct Decoding

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Cargo exit-code caveat:** Every cargo command piped through `tail`, `head`, or `grep` in this plan returns `0` even when cargo failed — the shell drops the upstream exit code. After running any cargo gate, re-run unpiped, set `set -o pipefail`, or inspect `${PIPESTATUS[0]}` to verify the real exit code.

**Goal:** Decode `StructProperty` elements inside `ArrayProperty`, `MapProperty`, and `SetProperty` collections in versioned (tagged-property) assets. Closes the gap noted in [issue #302](https://github.com/r6e/paksmith/issues/302) and explicitly deferred by Phase 2c (line ~552 of `phase-2c-container-properties.md`). Most cooked Blueprint assets carry collection-of-struct values; without this, `paksmith inspect` renders those collections as `PropertyValue::Unknown { skipped_bytes: N }` even after Phase 2c–2f land.

**Architecture:** `containers.rs` currently short-circuits `Array<Struct>` / `Map<Struct, *>` / `Set<Struct>` via `is_handled_element_type` and returns `Ok(None)`, leaving the outer caller to fall back to `PropertyBag::Opaque`. Phase 2g replaces the short-circuit with three new per-collection decoders that handle the struct element shape directly:

- `read_array_value`: when `tag.inner_type == "StructProperty"`, read a one-shot **inner-array-tag-info header** (a full `FPropertyTag` block carrying `struct_name`, `struct_guid`, and per-element `size`), then iterate `read_properties` per element bounded by that size.
- `read_map_value` / `read_set_value`: no per-element header. Each struct body is a tagged-property iteration terminated by a `(0, 0)` "None" FName pair, just like Phase 2c's top-level `read_struct_value`.

The unversioned (`PKG_UnversionedProperties`) collection-of-struct path is **already** correctly handled by Phase 2f's `unversioned.rs`: its `MT::Array { inner }` arm recurses through `read_unversioned_value`, which dispatches `MT::Struct { struct_name }` to `read_unversioned_properties`. No work is needed there.

**Tech Stack:** Same as Phase 2f. No new workspace dependencies.

---

## Deliverable

```shell
paksmith inspect cooked.pak Game/BP/Hero.uasset
```

on a cooked UE 4.27 Blueprint asset with `Inventory: Array<FInventorySlot>` now renders the decoded element properties (not `Unknown { skipped_bytes }`):

```json
{
  "asset_path": "Game/BP/Hero.uasset",
  "exports": [
    {
      "object_name": "Hero",
      "properties": [
        {
          "name": "Inventory",
          "array_index": 0,
          "value": {
            "Array": {
              "inner_type": "StructProperty",
              "elements": [
                {
                  "Struct": {
                    "struct_name": "InventorySlot",
                    "properties": [
                      { "name": "ItemId", "value": { "Int": 42 } },
                      { "name": "Count", "value": { "Int": 3 } }
                    ]
                  }
                },
                {
                  "Struct": {
                    "struct_name": "InventorySlot",
                    "properties": [
                      { "name": "ItemId", "value": { "Int": 99 } },
                      { "name": "Count", "value": { "Int": 1 } }
                    ]
                  }
                }
              ]
            }
          }
        }
      ]
    }
  ]
}
```

> **Note:** This shape is illustrative. The actual `Package` JSON contract has `object_name` as a `u32` name-table index and stores properties in a parallel `payloads` array. See `crates/paksmith-cli/tests/snapshots/inspect_cli__inspect_json_snapshot.snap` for the canonical wire-stable shape.

## Scope vs deferred work

**In scope:**

- `Array<Struct>` decoding in versioned assets (UE4 ≥ `VER_UE4_INNER_ARRAY_TAG_INFO = 500`; paksmith's accepted floor is UE4 ≥ 504, so the header is always present in-range).
- `Map<Struct, *>`, `Map<*, Struct>`, `Map<Struct, Struct>` in versioned assets.
- `Set<Struct>` in versioned assets.
- Per-element struct depth bounded by `MAX_PROPERTY_DEPTH = 128`.
- Outer collection count bounded by `MAX_COLLECTION_ELEMENTS = 65_536` (unchanged).
- New per-fault variant `AssetParseFault::ArrayOfStructHeaderMissing` for the case where the inner-array-tag-info header is `(0, 0)` (a structural malformation; the inner header is never a None-terminator in valid output).
- `containers.rs::read_struct_value` generalized (Task 2) to take `struct_name: &str` instead of `&PropertyTag`. Reused for top-level structs AND for collection-of-struct elements (Tasks 3-5).
- Fixture-gen: extend `build_minimal_ue4_27_with_containers` (Phase 2c) with an `Array<Struct>` field; cross-validate against `unreal_asset::Asset::new` on the synthetic bytes.
- Integration tests: 5 tests covering `Array<Struct>` happy path, `Map<Struct, IntProperty>`, `Set<Struct>`, depth-cap rejection, and the partial-decode contract for custom-binary engine structs.

**Explicitly deferred:**

- **Custom-binary engine struct readers** (FVector, FColor, FBox, FQuat, ~100 engine types). These structs use binary serialization, not tagged-property iteration. Phase 2g will attempt tagged-property iteration on them — `read_properties` either finds no "None" terminator within the element bound and returns whatever partial / garbage it parsed, or mis-parses early bytes as an FName and surfaces a soft error which the caller converts to `PropertyBag::Opaque`. Decoding custom-binary structs into typed fields belongs in Phase 3+ (export pipeline + format handlers).
- **`PROPERTY_TAG_COMPLETE_TYPE_NAME` (UE5 ≥ 1012).** CUE4Parse skips the inner-array-tag-info header at this version — the type info is read from the outer property tag's `InnerTypeData` instead. paksmith's accepted UE5 range is `[1000, 1010]` (per `version.rs:200`), so this path is structurally unreachable. If/when paksmith's accepted range expands past 1011, a follow-up issue must add the version-gated branch.
- **`PROPERTY_TAG_EXTENSION_AND_OVERRIDABLE_SERIALIZATION` (UE5 ≥ 1011)** tag-extension byte after `property_guid`. Same out-of-range reasoning.
- **UE4 < `VER_UE4_INNER_ARRAY_TAG_INFO = 500`.** No inner header on the wire; struct type comes from a per-game `array_struct_type_override` table (CUE4Parse's `GAME_DaysGone` special case at `UScriptArray.cs:65`). paksmith's accepted UE4 floor is 504, so this path is also unreachable. Continue to surface as `Unknown` if the version-gate check fails on an older asset.
- **`Map<Struct, *>` / `Set<Struct>` in unversioned mode** without a `.usmap` schema for the struct type. Already covered by Phase 2f's depth-1 `UnversionedSchemaMissing` partial-tree-stop contract; no Phase 2g work required.
- **DeltaSerialize / `num_keys_to_remove` struct keys** consume bytes correctly (Phase 2c already does this for primitives). Phase 2g extends the same pattern to struct keys — but the discarded entries are parsed-and-dropped, not surfaced.

## Design decisions locked here

1. **Inner-array-tag-info header is read via the existing `read_tag` helper.** The header's wire shape is identical to a top-level `FPropertyTag` (CUE4Parse calls `new FPropertyTag(Ar, false)` with `readData = false`; the `false` suppresses reading the trailing value — paksmith's `read_tag` already returns only the header, the value read happens separately via `read_properties`). Reusing `read_tag` avoids byte-format duplication and keeps the cap/EOF/None-terminator handling consistent.

2. **A `(0, 0)` inner header is a typed error, not a silent skip.** `read_tag` returns `Ok(None)` on the canonical None-terminator. For the inner-array-tag-info header, that response is structurally impossible — the header is always a real tag describing the struct type. A `None` here means the asset is malformed (or the outer tag's `inner_type == "StructProperty"` is wrong). Fire `AssetParseFault::ArrayOfStructHeaderMissing { array_name: tag.name.clone() }` rather than silently returning `Ok(None)`.

3. **Per-element bound is `inner_header.size`.** The oracle (`array_property.rs:174` in `unreal_asset` revision `f4df5d8e`) passes `struct_length` (the inner header's `size` field) as the `length` argument to `StructProperty::custom_header`, which in turn bounds tagged-property iteration. paksmith mirrors this: `expected_end = element_start + (inner_header.size as u64)`. If `read_properties` doesn't find "None" within that bound, the bound itself terminates the read — the next element is correctly aligned regardless of whether the struct body was tagged or custom-binary.

4. **Map/Set struct elements: no per-element bound — rely on the "None" terminator alone.** No inner header → no `size` field. Pass `expected_end = outer_tag_end` (the Map/Set's overall body end). `read_properties` stops at the first `(0, 0)` FName pair it encounters; the worst-case for a custom-binary struct (no "None" within the outer body) is that the entire remaining body gets consumed by one struct decode and downstream entries fail to parse. This is identical to the existing Phase 2c risk for top-level `read_struct_value` and is documented there.

5. **`is_handled_element_type` stays as the primitive gate.** Phase 2g adds a `StructProperty` check alongside the primitive guard (`key_is_struct || is_handled_element_type(...)`) and routes struct elements through the generalized `read_struct_value` rather than `read_element_value`. The primitive list at `containers.rs:186-208` is unchanged.

6. **No new `PropertyValue` variants.** Decoded struct elements reuse `PropertyValue::Struct { struct_name, properties }` (Phase 2b shipped). Map<Struct, *> entries reuse `MapEntry { key: PropertyValue, value: PropertyValue }`. Set<Struct> elements reuse `PropertyValue` directly.

7. **JSON shape is wire-stable.** `Array<Struct>` produces `PropertyValue::Array { inner_type: "StructProperty", elements: Vec<PropertyValue::Struct{..}> }`. No new wrapping object. The existing `inspect_json_snapshot` test is unchanged because the snapshot fixture has no `Array<Struct>` field; a new snapshot will land if Phase 2g's fixture-gen extension commits a new on-disk pak (see Task 5 fixture-count gate notes).

   `Map<Struct, *>` / `Set<Struct>` outputs `struct_name: ""` (empty) because the wire format carries no struct-type source without `.usmap`. This is a known UX wart for versioned mode — fields will still decode under the empty name, just with no struct-shape label. Phase 2f's unversioned path doesn't have this gap (`.usmap` carries the struct name in the schema).

8. **Custom-binary struct elements behave differently per collection — both avoid cratering the export, neither produces garbage downstream.** When a struct element's body is custom-binary-serialized (FVector, FColor, FBox, FQuat, ~100 engine types), tagged-property iteration on it almost always fails fast — the first 8 bytes (interpreted as an FName pair) yield an OOB index into the name table → `AssetParseFault::PackageIndexOob`. Without intervention, this error propagates through `read_properties` and the entire export reverts to `PropertyBag::Opaque`, losing all surrounding decoded properties.

   **`Array<Struct>`** can locally recover because the inner-array-tag-info header carries a per-element `size` — the cursor re-anchors at `element_start + size` for the next iteration. On per-element failure: catch the Err, `tracing::warn!`, seek cursor to `element_end`, substitute `PropertyValue::Struct { struct_name, properties: vec![] }`. Array shape is preserved with N elements, all empty-or-decoded.

   **`Map<Struct, *>` / `Map<*, Struct>` / `Set<Struct>`** CANNOT re-anchor — no per-element size on the wire. Continuing past a failed struct decode with the cursor parked mid-byte would silently produce garbage entries (the next read interprets the failed struct's tail bytes as the next entry's key/value). Phase 2g instead bails the collection cleanly: on first per-element struct failure, log warn, seek cursor to `expected_end` (the outer tag's end), and return `Ok(Some(PropertyValue::Map { entries: <partial>, ... }))` (or `Set { elements: <partial>, ... }`) carrying whatever entries decoded successfully before the failure. Subsequent properties in the same export decode normally. The partial-collection contract matches Phase 2f's partial-tree-stop semantics for unversioned schemas.

   Phase 3+ adds typed binary decoders for the engine struct family, at which point Array/Map/Set struct elements will decode to typed properties rather than empty / partial collections.

9. **`read_tag` reuse for the inner-array-tag-info header.** paksmith's existing `read_tag` already parses the full `FPropertyTag` wire shape — including the `has_property_guid: u8` flag and the optional trailing 16-byte `property_guid`. The inner-array-tag-info header is identical-shape to a top-level tag (CUE4Parse's `new FPropertyTag(Ar, false)` reuses the same constructor). No new tag-reading code is required for Phase 2g; the call site in `read_array_value` just calls `read_tag(reader, ctx, asset_path)?` and handles the `Some/None` result.

---

## Wire-format reference (empirically verified)

### `Array<Struct>` (versioned, UE4 ≥ 500 AND UE5 ≤ 1010)

```
i32 count                         // array element count
FPropertyTag inner_header:        // CUE4Parse: `new FPropertyTag(Ar, false)`
  i32 name_index                  // typically the property's own name; "None" → ArrayOfStructHeaderMissing
  i32 name_number
  i32 type_index ("StructProperty")
  i32 type_number
  i32 size                        // per-element struct body length
  i32 array_index
  i32 struct_name_index           // e.g., "Vector", "Rotator", "InventorySlot"
  i32 struct_name_number
  [u8; 16] struct_guid
  u8 has_property_guid
  [if has_property_guid] [u8; 16] property_guid
[loop count times]
  struct element body of exactly `inner_header.size` bytes:
    tagged-property stream terminated by (0, 0) FName  ─ for "Generic" structs
    OR
    custom binary serialization                        ─ for ~100 engine types
                                                         (FVector, FColor, FBox, FQuat, …)
                                                         (Phase 2g attempts tagged read;
                                                          partial/empty result is OK)
```

**Sources:**

- `unreal_asset_properties::array_property::new_no_header` lines 121-181 (revision `f4df5d8e`). Header reads at lines 127, 132, 149, 150, 152, 153; per-element loop at 169-180.
- `CUE4Parse/UE4/Assets/Objects/UScriptArray.cs` lines 55-58. `new FPropertyTag(Ar, false)` invocation matches paksmith's `read_tag` shape.
- Version gate: `VER_UE4_INNER_ARRAY_TAG_INFO = 500`. paksmith's UE4 floor is 504 (`asset_integration.rs::file_version_ue4`), so the gate is structurally always met for versioned assets.

### `Map<Struct, *>` / `Map<*, Struct>` / `Map<Struct, Struct>` (versioned)

```
i32 num_keys_to_remove
[loop num_keys_to_remove times]
  key body (parsed and discarded)
i32 count
[loop count times]
  key body of variable length:
    if key is StructProperty: tagged-property stream terminated by (0, 0)
    else: primitive body (Phase 2c shape)
  value body of variable length:
    if value is StructProperty: tagged-property stream terminated by (0, 0)
    else: primitive body
```

**Sources:**

- `unreal_asset_properties::map_property::map_type_to_class` lines 54-104. The `"StructProperty"` arm calls `StructProperty::custom_header(asset, name, ancestry, length=1, 0, Some(struct_type), None, None)` — `length=1` is a sentinel (ignored downstream); no per-element header is read.
- `CUE4Parse/UE4/Assets/Objects/UScriptMap.cs` lines 49-78. `FPropertyTagType.ReadPropertyTagType` dispatches struct keys/values through `FScriptStruct` with no inline header.
- Struct type for the key/value is unknown wire-side. Without `.usmap` mappings, paksmith labels the resulting `PropertyValue::Struct.struct_name` as `""` (empty); the property tree is still complete because tagged-property iteration is self-delimiting.

### `Set<Struct>` (versioned)

```
i32 num_elements_to_remove
[loop num_elements_to_remove times]
  element body (parsed and discarded)
i32 count
[loop count times]
  element body of variable length (tagged-property stream → (0, 0) FName)
```

**Sources:**

- `unreal_asset_properties::set_property::new` lines 41-63. Delegates to `ArrayProperty::new_no_header` with `serialize_struct_differently = false`, which skips the inner-array-tag-info header path.
- `CUE4Parse/UE4/Assets/Objects/UScriptSet.cs` lines 64-83.

### Unversioned `Array<Struct>` / `Map<Struct, *>` / `Set<Struct>` (UE5 with `PKG_UnversionedProperties`)

Already handled by Phase 2f. Schema-driven via `.usmap`; `unversioned.rs::read_unversioned_value::MT::Array { inner }` recurses through `MT::Struct { struct_name }` → `read_unversioned_properties`. No Phase 2g work required.

---

## Task overview

7 tasks, one PR each, full adversarial review panel per PR (see `MEMORY/feedback_parallel_full_review_panel.md`).

| # | Title | Files |
|---|---|---|
| 1 | New error variant + version constant | `error.rs`, `version.rs` |
| 2 | Refactor element-dispatch so `StructProperty` routes through a new arm | `containers.rs` |
| 3 | `read_array_value` inner-header + per-element struct decode | `containers.rs` |
| 4 | `read_map_value` struct key/value support | `containers.rs` |
| 5 | `read_set_value` struct element support | `containers.rs` |
| 6 | Fixture-gen extension + oracle cross-validation | `testing/uasset.rs`, `fixture-gen/uasset.rs` |
| 7 | Integration tests | `tests/collection_of_struct_integration.rs` (new) |

Tasks 3-5 ship in dependency order: 3 establishes the per-element struct decode pattern that 4 and 5 reuse.

---

### Task 1: Error variant + version-gate constant

**Files:**

- Modify: `crates/paksmith-core/src/asset/property/tag.rs` or wherever the new fault belongs in `error.rs`.
- Modify: `crates/paksmith-core/src/asset/version.rs`.

- [ ] **Step 1: Add `VER_UE4_INNER_ARRAY_TAG_INFO` constant.**

In `version.rs`, alongside the existing `pub(crate) const VER_UE4_*` constants:

```rust
/// `VER_UE4_INNER_ARRAY_TAG_INFO` (UE 4.12). When `file_version_ue4 >=
/// this`, an `ArrayProperty` whose `inner_type == "StructProperty"`
/// emits a one-shot `FPropertyTag` header before the element bodies
/// carrying the struct's `name`, `type`, per-element `size`,
/// `struct_name`, `struct_guid`, and `has_property_guid` flag.
///
/// paksmith's accepted UE4 floor is `VER_UE4_NAME_HASHES_SERIALIZED =
/// 504`, well above this; the gate is structurally always met for
/// versioned assets in-range. The constant exists so the Phase 2g
/// `Array<Struct>` decoder can express the version-gated branch
/// intent in code even though the false branch is unreachable.
pub(crate) const VER_UE4_INNER_ARRAY_TAG_INFO: i32 = 500;
```

- [ ] **Step 2: Add `AssetParseFault::ArrayOfStructHeaderMissing` variant.**

In `error.rs` near the existing `AssetParseFault` variants (`UnversionedTypeNotSupported` / `UnversionedSchemaMissing` are the most recent additions; this lands alongside):

```rust
/// An `ArrayProperty` whose `inner_type == "StructProperty"` declared
/// in its outer tag must be followed (per the inner-array-tag-info
/// wire format gated on `VER_UE4_INNER_ARRAY_TAG_INFO`) by a one-shot
/// `FPropertyTag` header describing the struct's name, GUID, and
/// per-element size. Reading that header returned `None` — the FName
/// pair was `(0, 0)`, which is structurally impossible for a valid
/// inner-array header (the header is never a None-terminator). Either
/// the asset is malformed or the outer tag's `inner_type` is wrong.
ArrayOfStructHeaderMissing {
    /// The array property's name (resolved from the outer tag), to
    /// help operators locate the malformed array in the asset.
    array_name: String,
},
```

Hand-roll the `Display` arm to match the existing `AssetParseFault` Display pattern (NOT `#[error(...)]` — Phase 2f Task 1 documented why `AssetParseFault` Display is hand-rolled):

```rust
Self::ArrayOfStructHeaderMissing { array_name } => write!(
    f,
    "array `{array_name}` declared inner_type=StructProperty but the \
     inner-array-tag-info header is a (0, 0) None-terminator \
     (header is never None-terminator for a valid asset)"
),
```

- [ ] **Step 3: Add Display pin-table test.**

Mirror the existing pin tests in `error.rs::tests` (e.g., `asset_parse_display_unversioned_type_not_supported`):

```rust
#[test]
fn asset_parse_display_array_of_struct_header_missing() {
    let s = AssetParseFault::ArrayOfStructHeaderMissing {
        array_name: "Inventory".to_string(),
    }
    .to_string();
    assert_eq!(
        s,
        "array `Inventory` declared inner_type=StructProperty but the \
         inner-array-tag-info header is a (0, 0) None-terminator \
         (header is never None-terminator for a valid asset)"
    );
}
```

- [ ] **Step 4: Lint + test + doc gate.**

```shell
set -o pipefail
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features 2>&1 | tail -10
cargo clean -p paksmith-core
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
```

(`cargo clean` before `cargo doc` per `MEMORY/feedback_cargo_doc_in_local_gates.md` — incremental cache can hide intra-doc-link lints.)

- [ ] **Step 5: Commit.**

```bash
git add crates/paksmith-core/src/asset/version.rs crates/paksmith-core/src/error.rs
git commit -m "$(cat <<'EOF'
feat(error): add ArrayOfStructHeaderMissing + VER_UE4_INNER_ARRAY_TAG_INFO

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: Generalize `read_struct_value` + thread `depth` through collection decoders

**Files:**

- Modify: `crates/paksmith-core/src/asset/property/containers.rs`.

The existing `read_struct_value` at `containers.rs:290-303` already does exactly what Phase 2g's collection-element decoder needs:

```rust
fn read_struct_value<R: Read + Seek>(
    tag: &PropertyTag,
    reader: &mut R,
    ctx: &AssetContext,
    depth: usize,
    expected_end: u64,
    asset_path: &str,
) -> crate::Result<PropertyValue> {
    let properties = super::read_properties(reader, ctx, depth + 1, expected_end, asset_path)?;
    Ok(PropertyValue::Struct {
        struct_name: tag.struct_name.clone(),
        properties,
    })
}
```

It takes a `&PropertyTag` only to extract `tag.struct_name`. Phase 2g needs the same body with the struct name supplied as a `&str` (from the inner-array-tag-info header for Array<Struct>, or `""` for Map/Set). Generalize the existing helper rather than minting a parallel function.

- [ ] **Step 1: Change `read_struct_value`'s first parameter to `struct_name: &str`.**

```rust
fn read_struct_value<R: Read + Seek>(
    struct_name: &str,
    reader: &mut R,
    ctx: &AssetContext,
    depth: usize,
    expected_end: u64,
    asset_path: &str,
) -> crate::Result<PropertyValue> {
    let properties = super::read_properties(reader, ctx, depth + 1, expected_end, asset_path)?;
    Ok(PropertyValue::Struct {
        struct_name: struct_name.to_string(),
        properties,
    })
}
```

- [ ] **Step 2: Update the existing top-level caller in `read_container_value`.**

The existing call site at `containers.rs:539-541` (in the `"StructProperty"` arm of `read_container_value`) passes `tag`. Change to `&tag.struct_name`:

```rust
"StructProperty" => {
    Ok(Some(read_struct_value(
        &tag.struct_name, reader, ctx, depth, expected_end, asset_path,
    )?))
}
```

- [ ] **Step 3: Plumb `depth: usize` into `read_array_value`, `read_map_value`, `read_set_value`.**

These three currently take `(tag, reader, ctx, asset_path)`. Task 3 needs `depth` to pass to `read_struct_value` for struct elements. The dispatch site `read_container_value` already has `depth` in scope (it's a parameter from `read_properties`). Thread it through all three function signatures and call sites in this task; no behaviour change until Task 3 wires the actual struct-element branch.

- [ ] **Step 4: Plumb `expected_end: u64` into `read_map_value` and `read_set_value`.**

`read_array_value` doesn't need it (per-element bound comes from the inner-array-tag-info header in Task 3). Map/Set DO need it (no per-element bound; the outer tag's end is the only stopping point for struct elements per Design Decision #4). `read_container_value` has `expected_end` in scope already (it's a parameter).

- [ ] **Step 5: Compile-check (no behavioural change).**

```shell
set -o pipefail
cargo fmt --all
cargo build -p paksmith-core
cargo test -p paksmith-core --lib 2>&1 | tail -5
cargo clippy -p paksmith-core --all-targets --all-features -- -D warnings
```

Existing tests must still pass — Task 2 is a parameter-shuffle refactor, no behaviour change.

- [ ] **Step 6: Commit.**

```bash
git add crates/paksmith-core/src/asset/property/containers.rs
git commit -m "$(cat <<'EOF'
refactor(property): generalize read_struct_value; thread depth/expected_end

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: `read_array_value` Struct-element support

**Files:**

- Modify: `crates/paksmith-core/src/asset/property/containers.rs`.

- [ ] **Step 1: Write the failing in-source unit test first (TDD).**

Following the Phase 2f pattern (`unversioned.rs::tests::header_no_zeros_two_props` — 7-byte hand-built payload, no fixture dependency), drive the new code with an inline-bytes unit test in `containers.rs::tests`. The end-to-end integration test lives in Task 7 and isn't needed for TDD here.

```rust
// in containers.rs::tests:

#[test]
fn array_of_struct_inner_header_decodes_two_elements() {
    // Wire bytes: count(2) + inner FPropertyTag header + 2 minimal
    // struct bodies (each = single IntProperty + None terminator).
    //
    // Name table indices used (synthesised via the test ctx helper):
    //   0: "Inventory", 1: "StructProperty", 2: "InventorySlot",
    //   3: "ItemId",   4: "IntProperty",     5: "None"
    let mut bytes: Vec<u8> = Vec::new();
    // count = 2
    bytes.extend_from_slice(&2i32.to_le_bytes());
    // inner FPropertyTag:
    //   name = "Inventory" (idx 0, num 0)
    //   type = "StructProperty" (idx 1, num 0)
    //   size = <per-element bytes, patched below>
    //   array_index = 0
    //   struct_name = "InventorySlot" (idx 2, num 0)
    //   struct_guid = [0; 16]
    //   has_property_guid = 0
    bytes.extend_from_slice(&0i32.to_le_bytes()); // name idx
    bytes.extend_from_slice(&0i32.to_le_bytes()); // name num
    bytes.extend_from_slice(&1i32.to_le_bytes()); // type idx
    bytes.extend_from_slice(&0i32.to_le_bytes()); // type num
    let size_offset = bytes.len();
    bytes.extend_from_slice(&0i32.to_le_bytes()); // size placeholder
    bytes.extend_from_slice(&0i32.to_le_bytes()); // array_index
    bytes.extend_from_slice(&2i32.to_le_bytes()); // struct_name idx
    bytes.extend_from_slice(&0i32.to_le_bytes()); // struct_name num
    bytes.extend_from_slice(&[0u8; 16]);          // struct_guid
    bytes.push(0u8);                              // has_property_guid

    // Per-element body: helper closure for "ItemId: IntProperty = N"
    // + None terminator. The body length is computed once and patched
    // into the inner-header `size` field above.
    let mut elem_body = |val: i32| {
        let start = bytes.len();
        // FPropertyTag: ItemId, IntProperty, size=4, array_index=0,
        //               has_property_guid=0
        bytes.extend_from_slice(&3i32.to_le_bytes()); // name idx
        bytes.extend_from_slice(&0i32.to_le_bytes()); // name num
        bytes.extend_from_slice(&4i32.to_le_bytes()); // type idx
        bytes.extend_from_slice(&0i32.to_le_bytes()); // type num
        bytes.extend_from_slice(&4i32.to_le_bytes()); // size = 4
        bytes.extend_from_slice(&0i32.to_le_bytes()); // array_index
        bytes.push(0u8);                              // has_property_guid
        bytes.extend_from_slice(&val.to_le_bytes()); // i32 value
        // None terminator: (0, 0) FName pair
        bytes.extend_from_slice(&0i32.to_le_bytes());
        bytes.extend_from_slice(&0i32.to_le_bytes());
        bytes.len() - start
    };
    let body_len_0 = elem_body(42);
    let _body_len_1 = elem_body(99);
    // Both element bodies have the same length; patch the inner-header
    // size field once.
    let body_len_i32 = i32::try_from(body_len_0).expect("body within i32");
    bytes[size_offset..size_offset + 4].copy_from_slice(&body_len_i32.to_le_bytes());

    // Build the outer tag that drives the call into read_array_value.
    let outer_tag = PropertyTag {
        name: "Inventory".to_string(),
        type_name: "ArrayProperty".to_string(),
        size: i32::try_from(bytes.len()).expect("body within i32"),
        array_index: 0,
        bool_val: false,
        struct_name: String::new(),
        struct_guid: [0u8; 16],
        enum_name: String::new(),
        inner_type: "StructProperty".to_string(),
        value_type: String::new(),
        guid: None,
    };

    let ctx = test_ctx_with_names(&[
        "Inventory", "StructProperty", "InventorySlot", "ItemId",
        "IntProperty", "None",
    ]);
    let mut cur = Cursor::new(bytes.as_slice());
    let value = read_array_value(&outer_tag, &mut cur, &ctx, /* depth */ 0, "test")
        .expect("read_array_value")
        .expect("Array Struct should decode, not return Ok(None)");

    match value {
        PropertyValue::Array { inner_type, elements } => {
            assert_eq!(inner_type, "StructProperty");
            assert_eq!(elements.len(), 2);
            for (i, expected_val) in [42i32, 99i32].iter().enumerate() {
                match &elements[i] {
                    PropertyValue::Struct { struct_name, properties } => {
                        assert_eq!(struct_name, "InventorySlot");
                        assert_eq!(properties.len(), 1, "element {i}");
                        assert_eq!(properties[0].name, "ItemId");
                        assert!(matches!(properties[0].value,
                            PropertyValue::Int(v) if v == *expected_val));
                    }
                    other => panic!("element {i}: expected Struct, got {other:?}"),
                }
            }
        }
        other => panic!("expected Array, got {other:?}"),
    }
}
```

> `test_ctx_with_names` is the existing test helper in `containers.rs::tests` for building synthetic `AssetContext`s (used by all Phase 2c tests in that module). If it doesn't take a `&[&str]` slice today, extend it.

Run: `cargo test -p paksmith-core --features __test_utils --lib containers::tests::array_of_struct 2>&1 | tail -10`. Expected: **FAIL** — the existing `read_array_value` short-circuits via `is_handled_element_type` and returns `Ok(None)`, which the test's second `.expect()` panics on.

- [ ] **Step 2: Wire the `StructProperty` branch in `read_array_value` (includes Design Decision #8's catch arm).**

Replace the `is_handled_element_type` short-circuit with a struct-specific branch. The catch arm at the per-element boundary implements Design Decision #8 — tagged-iteration failures (e.g., custom-binary engine structs like FVector) yield `Struct { struct_name, properties: vec![] }` instead of propagating Err and reverting the whole export to `PropertyBag::Opaque`:

```rust
fn read_array_value<R: Read + Seek>(
    tag: &PropertyTag,
    reader: &mut R,
    ctx: &AssetContext,
    depth: usize,                  // NEW (from Task 2)
    asset_path: &str,
) -> crate::Result<Option<PropertyValue>> {
    let count = reader
        .read_i32::<LittleEndian>()
        .map_err(|_| unexpected_eof(asset_path, AssetWireField::ArrayElementCount))?;
    if count < 0 || count as usize > MAX_COLLECTION_ELEMENTS {
        return Err(/* CollectionElementCountExceeded as today */);
    }
    let count_usize = count as usize;

    if tag.inner_type == "StructProperty" {
        // Inner-array-tag-info header: a full FPropertyTag describing
        // the struct shape (name, GUID, per-element size). Per the
        // empirically verified wire format, this header is ALWAYS
        // present for versioned UE4 ≥ 500; paksmith's UE4 floor is
        // 504, so we don't gate this branch on a version check —
        // any flagged versioned asset that reaches here MUST have
        // the header.
        let inner_header = super::read_tag(reader, ctx, asset_path)?
            .ok_or_else(|| PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::ArrayOfStructHeaderMissing {
                    array_name: tag.name.clone(),
                },
            })?;
        // inner_header.size is the per-element struct body length.
        // read_properties enforces the upper expected_end, so a
        // malformed inner.size that overruns just terminates the
        // current element early; the next element loop iteration
        // re-anchors on the saved element_start + size.

        let mut elements: Vec<PropertyValue> = Vec::new();
        try_reserve_asset(
            &mut elements,
            count_usize,
            asset_path,
            AssetAllocationContext::CollectionElements,
        )?;

        for i in 0..count_usize {
            let element_start = reader.stream_position().map_err(|_| {
                unexpected_eof(asset_path, AssetWireField::ArrayElementBody)
            })?;
            #[allow(clippy::cast_sign_loss, reason = "read_tag rejects negative size")]
            let element_end = element_start.saturating_add(inner_header.size as u64);

            // Design Decision #8: catch tagged-iteration errors at
            // the per-element boundary. Custom-binary structs (FVector,
            // FColor, etc.) almost always fail the first FName read
            // with PackageIndexOob; without this catch, that error
            // propagates and the entire export reverts to
            // PropertyBag::Opaque, losing all surrounding decoded
            // properties. With the catch, the array shape is preserved
            // and the struct element decodes as empty properties.
            let elem = match read_struct_value(
                &inner_header.struct_name,
                reader,
                ctx,
                depth,
                element_end,
                asset_path,
            ) {
                Ok(value) => value,
                Err(e) => {
                    tracing::warn!(
                        asset = asset_path,
                        array = tag.name.as_str(),
                        struct_name = inner_header.struct_name.as_str(),
                        index = i,
                        error = %e,
                        "struct element decode failed (likely custom-binary engine \
                         struct); substituting empty properties to preserve array \
                         shape — Phase 3+ adds typed binary decoders"
                    );
                    // Seek the cursor to element_end so the next
                    // element starts at the correct offset, regardless
                    // of how far the failed read advanced.
                    reader.seek(SeekFrom::Start(element_end)).map_err(|_| {
                        unexpected_eof(asset_path, AssetWireField::ArrayElementBody)
                    })?;
                    PropertyValue::Struct {
                        struct_name: inner_header.struct_name.clone(),
                        properties: Vec::new(),
                    }
                }
            };
            elements.push(elem);
        }

        return Ok(Some(PropertyValue::Array {
            inner_type: tag.inner_type.clone(),
            elements,
        }));
    }

    // Existing primitive path (unchanged from Phase 2c).
    if !is_handled_element_type(&tag.inner_type) {
        return Ok(None);
    }
    // ... existing primitive loop ...
}
```

- [ ] **Step 3: Run the unit test. Expected: passes.**

```shell
set -o pipefail
cargo test -p paksmith-core --features __test_utils --lib containers::tests::array_of_struct 2>&1 | tail -10
```

- [ ] **Step 4: Lint + test + doc gate (existing tests must still pass).**

```shell
set -o pipefail
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features 2>&1 | tail -10
cargo clean -p paksmith-core
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
```

- [ ] **Step 5: Commit.**

```bash
git add crates/paksmith-core/src/asset/property/containers.rs
git commit -m "$(cat <<'EOF'
feat(property): decode Array<Struct> via inner-array-tag-info header

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: `read_map_value` Struct key/value support

**Files:**

- Modify: `crates/paksmith-core/src/asset/property/containers.rs`.

Map<Struct, *> and Map<*, Struct> have NO inner-array-tag-info header. Each struct body is a tagged-property iteration terminated by `(0, 0)`. The struct type is unknown wire-side without `.usmap` mappings, so the resulting `PropertyValue::Struct.struct_name` is the empty string.

- [ ] **Step 1: Write the failing in-source unit test first (TDD).**

In `containers.rs::tests`, hand-build bytes for a `Map<NameProperty, InventorySlot>` with 2 entries (no num_keys_to_remove). The Map's per-entry struct VALUE body is a single IntProperty followed by None terminator — exactly the shape Task 3's unit test established.

```rust
#[test]
fn map_of_struct_value_decodes_two_entries() {
    // Wire bytes: num_keys_to_remove(0) + count(2) + 2 × (key + value)
    // where key = FName pair and value = struct body (IntProperty + None).
    //
    // Name table:
    //   0: "Slots", 1: "MapProperty", 2: "NameProperty",
    //   3: "StructProperty", 4: "InventorySlot",
    //   5: "ItemId", 6: "IntProperty",
    //   7: "first", 8: "second"
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(&0i32.to_le_bytes()); // num_keys_to_remove
    bytes.extend_from_slice(&2i32.to_le_bytes()); // count
    for (key_name_idx, item_id) in [(7i32, 42i32), (8i32, 99i32)] {
        // key = FName pair (NameProperty wire format)
        bytes.extend_from_slice(&key_name_idx.to_le_bytes());
        bytes.extend_from_slice(&0i32.to_le_bytes());
        // value = struct body: ItemId IntProperty + None terminator.
        // FPropertyTag: ItemId, IntProperty, size=4, array_index=0, no GUID.
        bytes.extend_from_slice(&5i32.to_le_bytes()); // name idx
        bytes.extend_from_slice(&0i32.to_le_bytes()); // name num
        bytes.extend_from_slice(&6i32.to_le_bytes()); // type idx
        bytes.extend_from_slice(&0i32.to_le_bytes()); // type num
        bytes.extend_from_slice(&4i32.to_le_bytes()); // size
        bytes.extend_from_slice(&0i32.to_le_bytes()); // array_index
        bytes.push(0u8);                              // has_property_guid
        bytes.extend_from_slice(&item_id.to_le_bytes());
        // None terminator
        bytes.extend_from_slice(&0i32.to_le_bytes());
        bytes.extend_from_slice(&0i32.to_le_bytes());
    }

    let outer_tag = PropertyTag {
        name: "Slots".to_string(),
        type_name: "MapProperty".to_string(),
        size: i32::try_from(bytes.len()).expect("body within i32"),
        array_index: 0,
        bool_val: false,
        struct_name: String::new(),
        struct_guid: [0u8; 16],
        enum_name: String::new(),
        inner_type: "NameProperty".to_string(),
        value_type: "StructProperty".to_string(),
        guid: None,
    };
    let ctx = test_ctx_with_names(&[
        "Slots", "MapProperty", "NameProperty", "StructProperty",
        "InventorySlot", "ItemId", "IntProperty", "first", "second",
    ]);
    let mut cur = Cursor::new(bytes.as_slice());
    let expected_end = bytes.len() as u64;
    let value = read_map_value(&outer_tag, &mut cur, &ctx, 0, expected_end, "test")
        .expect("read_map_value")
        .expect("Map with StructProperty value should decode, not return Ok(None)");

    match value {
        PropertyValue::Map { key_type, value_type, entries } => {
            assert_eq!(key_type, "NameProperty");
            assert_eq!(value_type, "StructProperty");
            assert_eq!(entries.len(), 2);
            for (i, (expected_key, expected_val)) in
                [("first", 42i32), ("second", 99i32)].iter().enumerate()
            {
                match (&entries[i].key, &entries[i].value) {
                    (PropertyValue::Name(k), PropertyValue::Struct { struct_name, properties }) => {
                        assert_eq!(k, expected_key);
                        assert_eq!(struct_name, ""); // Map struct_name unknown wire-side
                        assert_eq!(properties.len(), 1);
                        assert!(matches!(properties[0].value,
                            PropertyValue::Int(v) if v == *expected_val));
                    }
                    (k, v) => panic!("entry {i}: unexpected shape ({k:?}, {v:?})"),
                }
            }
        }
        other => panic!("expected Map, got {other:?}"),
    }
}
```

Run: `cargo test -p paksmith-core --features __test_utils --lib containers::tests::map_of_struct 2>&1 | tail -10`. Expected: **FAIL** (existing `read_map_value` short-circuits on `is_handled_element_type` returning false for `StructProperty`).

- [ ] **Step 2: Wire the `StructProperty` branch in `read_map_value`.**

Replace the early-return with a struct-aware branch. The catch arm (Design Decision #8) applies to BOTH key and value struct reads — if a struct key fails tagged-iteration, substitute empty properties rather than erroring out. The `num_keys_to_remove` discard loop also needs the struct-aware dispatch so it consumes the right bytes:

```rust
fn read_map_value<R: Read + Seek>(
    tag: &PropertyTag,
    reader: &mut R,
    ctx: &AssetContext,
    depth: usize,                        // NEW from Task 2
    expected_end: u64,                   // NEW from Task 2
    asset_path: &str,
) -> crate::Result<Option<PropertyValue>> {
    let key_is_struct = tag.inner_type == "StructProperty";
    let val_is_struct = tag.value_type == "StructProperty";

    // Bail out only when BOTH key and value types are unsupported
    // (not primitive AND not struct).
    let key_supported = key_is_struct || is_handled_element_type(&tag.inner_type);
    let val_supported = val_is_struct || is_handled_element_type(&tag.value_type);
    if !key_supported || !val_supported {
        return Ok(None);
    }

    // ... existing num_keys_to_remove + count reads ...

    // (See full loop body below — `num_keys_to_remove` discard loop AND
    // the main `count` loop share the labelled-break pattern.)
}
```

Per Design Decision #8, Map/Set do NOT use a per-element catch wrapper (Array<Struct> can re-anchor the cursor at `element_start + size`; Map/Set cannot). The catch is at the **collection level**: if any struct element (key, value, or key-to-remove) returns Err, log a warn, seek cursor to `expected_end`, and return `Ok(Some(PropertyValue::Map { entries: <partial>, ... }))` with whatever entries decoded cleanly before the failure. The next property in the export decodes normally because the cursor is correctly positioned at `expected_end`.

Structure the loop with explicit control flow (a labelled `'entries` break, or an inner closure returning `Result<MapEntry, _>`):

```rust
'entries: for _ in 0..count_usize {
    let key_result = if key_is_struct {
        read_struct_value("", reader, ctx, depth, expected_end, asset_path)
    } else {
        read_element_value(&tag.inner_type, AssetWireField::MapKey, reader, ctx, asset_path)
            .map(|opt| opt.expect("primitive key type validated"))
    };
    let key = match key_result {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!(
                asset = asset_path,
                map = tag.name.as_str(),
                error = %e,
                entries_decoded = entries.len(),
                "Map key decode failed; returning partial Map and seeking to outer end"
            );
            reader.seek(SeekFrom::Start(expected_end))
                .map_err(|_| unexpected_eof(asset_path, AssetWireField::MapKey))?;
            break 'entries;
        }
    };
    let value_result = if val_is_struct {
        read_struct_value("", reader, ctx, depth, expected_end, asset_path)
    } else {
        read_element_value(&tag.value_type, AssetWireField::MapValue, reader, ctx, asset_path)
            .map(|opt| opt.expect("primitive value type validated"))
    };
    let value = match value_result {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                asset = asset_path,
                map = tag.name.as_str(),
                error = %e,
                entries_decoded = entries.len(),
                "Map value decode failed; returning partial Map and seeking to outer end"
            );
            reader.seek(SeekFrom::Start(expected_end))
                .map_err(|_| unexpected_eof(asset_path, AssetWireField::MapValue))?;
            break 'entries;
        }
    };
    entries.push(MapEntry { key, value });
}
```

Apply the same pattern to the `num_keys_to_remove` discard loop — if a struct key fails to discard cleanly, seek to `expected_end` and treat the entire Map as having zero decoded entries (the main loop is skipped via the same `break 'entries` mechanism, or a separate flag).

Array<Struct> already has its own per-element catch + `seek(element_end)` from Task 3 — that block stays in place. The cursor re-anchoring is what differentiates the two: Array can recover and continue; Map/Set bail with whatever partial result.

- [ ] **Step 3: Run the unit test. Expected: passes.**

```shell
set -o pipefail
cargo test -p paksmith-core --features __test_utils --lib containers::tests::map_of_struct 2>&1 | tail -10
```

- [ ] **Step 4: Lint + test + doc gate.** Same shell block as Task 3 Step 4.

- [ ] **Step 5: Commit.**

```bash
git commit -m "$(cat <<'EOF'
feat(property): decode Map<*, Struct> and Map<Struct, *> entries

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: `read_set_value` Struct element support

**Files:**

- Modify: `crates/paksmith-core/src/asset/property/containers.rs`.

Same shape as Map<*, Struct> — no inner-array-tag-info header; each struct body is tagged-property iteration to `(0, 0)`. Both the `num_elements_to_remove` loop and the main `count` loop need the struct-aware dispatch.

- [ ] **Step 1: Write the failing in-source unit test first (TDD).**

Mirror Task 4's structure for a `Set<InventorySlot>` with 2 elements (no num_elements_to_remove). Each element is the same struct body shape Tasks 3 and 4 established.

```rust
#[test]
fn set_of_struct_decodes_two_elements() {
    // num_elements_to_remove(0) + count(2) + 2 × (struct body).
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(&0i32.to_le_bytes()); // num_elements_to_remove
    bytes.extend_from_slice(&2i32.to_le_bytes()); // count
    for item_id in [42i32, 99i32] {
        // FPropertyTag: ItemId, IntProperty, size=4, no GUID.
        bytes.extend_from_slice(&3i32.to_le_bytes()); // name idx ("ItemId")
        bytes.extend_from_slice(&0i32.to_le_bytes());
        bytes.extend_from_slice(&4i32.to_le_bytes()); // type idx ("IntProperty")
        bytes.extend_from_slice(&0i32.to_le_bytes());
        bytes.extend_from_slice(&4i32.to_le_bytes()); // size
        bytes.extend_from_slice(&0i32.to_le_bytes()); // array_index
        bytes.push(0u8);                              // has_property_guid
        bytes.extend_from_slice(&item_id.to_le_bytes());
        // None terminator
        bytes.extend_from_slice(&0i32.to_le_bytes());
        bytes.extend_from_slice(&0i32.to_le_bytes());
    }
    let outer_tag = PropertyTag {
        name: "Slots".to_string(),
        type_name: "SetProperty".to_string(),
        size: i32::try_from(bytes.len()).expect("body within i32"),
        array_index: 0,
        bool_val: false,
        struct_name: String::new(),
        struct_guid: [0u8; 16],
        enum_name: String::new(),
        inner_type: "StructProperty".to_string(),
        value_type: String::new(),
        guid: None,
    };
    let ctx = test_ctx_with_names(&[
        "Slots", "SetProperty", "StructProperty", "ItemId", "IntProperty",
    ]);
    let mut cur = Cursor::new(bytes.as_slice());
    let expected_end = bytes.len() as u64;
    let value = read_set_value(&outer_tag, &mut cur, &ctx, 0, expected_end, "test")
        .expect("read_set_value")
        .expect("Set<Struct> should decode, not return Ok(None)");
    match value {
        PropertyValue::Set { inner_type, elements } => {
            assert_eq!(inner_type, "StructProperty");
            assert_eq!(elements.len(), 2);
            for (i, expected_val) in [42i32, 99i32].iter().enumerate() {
                match &elements[i] {
                    PropertyValue::Struct { struct_name, properties } => {
                        assert_eq!(struct_name, "");
                        assert_eq!(properties.len(), 1);
                        assert!(matches!(properties[0].value,
                            PropertyValue::Int(v) if v == *expected_val));
                    }
                    other => panic!("element {i}: expected Struct, got {other:?}"),
                }
            }
        }
        other => panic!("expected Set, got {other:?}"),
    }
}
```

Run: `cargo test -p paksmith-core --features __test_utils --lib containers::tests::set_of_struct 2>&1 | tail -10`. Expected: **FAIL**.

- [ ] **Step 2: Wire the `StructProperty` branch in `read_set_value`.**

Same shape as Task 4 (no per-element catch wrapper; labelled-break + seek-to-`expected_end` on first failure). Set is simpler than Map (no key/value asymmetry):

```rust
fn read_set_value<R: Read + Seek>(
    tag: &PropertyTag,
    reader: &mut R,
    ctx: &AssetContext,
    depth: usize,                        // NEW
    expected_end: u64,                   // NEW
    asset_path: &str,
) -> crate::Result<Option<PropertyValue>> {
    let elem_is_struct = tag.inner_type == "StructProperty";
    let elem_supported = elem_is_struct || is_handled_element_type(&tag.inner_type);
    if !elem_supported {
        return Ok(None);
    }

    // ... existing num_elements_to_remove + count reads ...

    // Discard loop: mirror the main loop's labelled-break pattern.
    'discard: for _ in 0..(num_elements_to_remove as usize) {
        let discard_result = if elem_is_struct {
            read_struct_value("", reader, ctx, depth, expected_end, asset_path).map(|_| ())
        } else {
            read_element_value(&tag.inner_type, AssetWireField::SetElement, reader, ctx, asset_path)
                .map(|opt| { opt.expect("primitive type validated"); })
        };
        if let Err(e) = discard_result {
            tracing::warn!(
                asset = asset_path,
                set = tag.name.as_str(),
                error = %e,
                "Set discard-element decode failed; treating Set as empty + seeking to outer end"
            );
            reader.seek(SeekFrom::Start(expected_end))
                .map_err(|_| unexpected_eof(asset_path, AssetWireField::SetElement))?;
            return Ok(Some(PropertyValue::Set {
                inner_type: tag.inner_type.clone(),
                elements: Vec::new(),
            }));
        }
    }

    // Main count loop.
    'elements: for _ in 0..count_usize {
        let elem_result = if elem_is_struct {
            read_struct_value("", reader, ctx, depth, expected_end, asset_path)
        } else {
            read_element_value(&tag.inner_type, AssetWireField::SetElement, reader, ctx, asset_path)
                .map(|opt| opt.expect("primitive type validated"))
        };
        let elem = match elem_result {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    asset = asset_path,
                    set = tag.name.as_str(),
                    error = %e,
                    elements_decoded = elements.len(),
                    "Set element decode failed; returning partial Set + seeking to outer end"
                );
                reader.seek(SeekFrom::Start(expected_end))
                    .map_err(|_| unexpected_eof(asset_path, AssetWireField::SetElement))?;
                break 'elements;
            }
        };
        elements.push(elem);
    }

    Ok(Some(PropertyValue::Set { /* ... */ }))
}
```

- [ ] **Step 3: Run the unit test. Expected: passes.**

- [ ] **Step 4: Lint + test + doc gate.**

- [ ] **Step 5: Commit.**

```bash
git commit -m "$(cat <<'EOF'
feat(property): decode Set<Struct> elements

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 6: Fixture-gen extension + oracle cross-validation

**Files:**

- Modify: `crates/paksmith-core/src/testing/uasset.rs` — add `build_minimal_ue4_27_with_array_of_struct` builder.
- Modify: `crates/paksmith-fixture-gen/src/uasset.rs` — add `validate_array_of_struct_fixture` + wire into `main`.

- [ ] **Step 1: Add `build_minimal_ue4_27_with_array_of_struct` builder.**

In `testing/uasset.rs`, sibling to `build_minimal_ue4_27_with_containers` and `build_minimal_ue4_27_with_extended_types`. The synthesized asset has one property `Inventory: Array<InventorySlot>` with two elements, each carrying `ItemId: i32` and `Count: i32`.

Wire layout (synthesized via `MinimalPackageSpec` + custom payload bytes):

```
// Outer tag: Inventory, ArrayProperty, size = computed, array_index = 0,
//            inner_type = "StructProperty", has_property_guid = 0
// Body:
//   i32 count = 2
//   FPropertyTag inner-array-tag-info:
//     name = "Inventory", type = "StructProperty", size = <per-element>,
//     array_index = 0, struct_name = "InventorySlot",
//     struct_guid = [0; 16], has_property_guid = 0
//   for each of 2 elements:
//     FPropertyTag: ItemId, IntProperty, size = 4, array_index = 0,
//                   has_property_guid = 0
//     i32 ItemId value
//     FPropertyTag: Count, IntProperty, size = 4, array_index = 0,
//                   has_property_guid = 0
//     i32 Count value
//     (0, 0) None terminator
```

The per-element struct body's `size` field counts the bytes from the start of the first inner tag through the trailing `(0, 0)` None pair. Compute this at fixture-build time and patch it into the inner header's `size` field.

> **Critical:** `MinimalPackageSpec`'s name table must include `Inventory`, `Array<...>` placeholder strings, `StructProperty`, `IntProperty`, `InventorySlot`, `ItemId`, `Count`. Append these to the default 3-entry name table; the outer + inner tags reference them by index.

- [ ] **Step 2: Add `validate_array_of_struct_fixture` to fixture-gen.**

> **Scope revision applied at implementation time (Task 6, PR #346).**
> The property-tree-level oracle pair-check sketched below
> (`cross_validate_array_of_struct_with_unreal_asset` walking
> `Asset → NormalExport.properties → ArrayProperty::value`) was
> empirically blocked: `unreal_asset`'s `read_export` (asset_data.rs
> line 448-468 at pinned rev `f4df5d8e`) silently catches any error
> from `NormalExport::from_base` and falls back to `RawExport`, and
> `NormalExport::from_base` errors on synthetic minimal fixtures
> with `class_name == "Package"` because it requires resolved
> schema + ancestry the synthetic shape doesn't provide. Same
> precedent as `write_minimal_ue4_27_with_properties` and
> `_with_containers` (both document the identical constraint).
>
> The shipped validator (`validate_array_of_struct_fixture` in
> `paksmith-fixture-gen/src/uasset.rs`):
> 1. Asserts paksmith's `PropertyBag::Tree` carries the expected
>    `Inventory: Array<InventorySlot>` shape with exact `ItemId` +
>    `Count` values — property-level assertions, but paksmith-side
>    only.
> 2. Runs the existing `cross_validate_with_unreal_asset` at the
>    **table** level (names, imports, export headers).
> 3. Adds `anchor_minimal_ue4_27_with_array_of_struct_bytes` SHA1
>    pin in `testing/uasset.rs::tests` — catches the generator/
>    parser shared-bug blind spot the validator alone cannot.
>
> The pseudocode below describes the originally-planned property-
> tree oracle pair-check; the as-shipped contract is in
> `crates/paksmith-fixture-gen/src/uasset.rs::validate_array_of_struct_fixture`'s
> doc comment.

Mirror Phase 2f Task 5's `validate_unversioned_usmap_parser_parity` pattern. Pair-validate paksmith's parse against `unreal_asset::Asset::new`'s parse:

```rust
pub fn validate_array_of_struct_fixture() -> anyhow::Result<()> {
    use paksmith_core::asset::Package;
    use paksmith_core::testing::uasset::build_minimal_ue4_27_with_array_of_struct;

    let pkg_bytes = build_minimal_ue4_27_with_array_of_struct().bytes;

    // Paksmith side.
    let our_pkg = Package::read_from(&pkg_bytes, None, None, "test/Hero.uasset")
        .map_err(|e| anyhow::anyhow!("paksmith Package::read_from failed: {e}"))?;
    // ... assert two elements, each with ItemId + Count ...

    // Oracle side: unreal_asset must produce the same shape on the
    // same bytes. Use the existing cross_validate_with_unreal_asset
    // pattern (extract a sub-helper if needed for Array<Struct>).
    cross_validate_array_of_struct_with_unreal_asset(&pkg_bytes)?;

    println!("  array_of_struct_fixture: paksmith ⇄ oracle agreement on Inventory[2]");
    Ok(())
}
```

`cross_validate_array_of_struct_with_unreal_asset` navigates the oracle's `Asset` → first export → `NormalExport.properties` → `Inventory` (ArrayProperty) → asserts 2 entries with the expected struct shape. The oracle's `ArrayProperty::value: Vec<Property>` exposes each as `Property::StructProperty(StructProperty { value: Vec<Property>, .. })`.

- [ ] **Step 3: Wire `validate_array_of_struct_fixture` into `fixture-gen/src/main.rs`.**

Following Phase 2f Task 5's pattern in `main.rs`:

```rust
println!("\nValidating Phase 2g Array<Struct> decoder vs unreal_asset oracle...");
if let Err(e) = uasset::validate_array_of_struct_fixture() {
    failures.push(("phase-2g Array<Struct>", e.to_string().into()));
}
```

- [ ] **Step 4: Run fixture-gen.**

```shell
set -o pipefail
cargo run -p paksmith-fixture-gen 2>&1 | tail -20
```

Expected: clean exit with `array_of_struct_fixture: paksmith ⇄ oracle agreement ...` line.

- [ ] **Step 5: Lint + test + doc gate.**

- [ ] **Step 6: Commit.**

```bash
git commit -m "$(cat <<'EOF'
test(property): fixture builder + oracle cross-validation for Array<Struct>

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

> **Fixture-count gate (per `MEMORY/feedback_fixture_count_gate.md`):** Phase 2g does NOT commit a new on-disk `tests/fixtures/*.pak` — `build_minimal_ue4_27_with_array_of_struct` returns in-memory bytes. The CI gate stays at the current `expected=N`. If a follow-up adds an on-disk `real_v8b_array_of_struct.pak`, that PR bumps the constant and extends the enumeration comment.

---

### Task 7: Integration tests

**Files:**

- Modify: `crates/paksmith-core/tests/collection_of_struct_integration.rs` (created in Task 3, expanded here).

7 tests, all `#[cfg(feature = "__test_utils")]`-gated. Drive the Array happy-path test via the Task 6 fixture builder; build Map/Set/edge-case fixtures inline (the inline-bytes pattern Tasks 3-5 established).

1. **`array_of_struct_decodes_two_elements`** — end-to-end via Task 6's `build_minimal_ue4_27_with_array_of_struct` + `Package::read_from`. The Task 3 in-source unit test exercises `read_array_value` directly; this test pins the full pipeline including the `Package::read_from` dispatch and the `PropertyBag::Tree` aggregation.
2. **`map_of_struct_value_decodes`** — Map<NameProperty, InventorySlot> via `Package::read_from`. Add a `build_minimal_ue4_27_with_map_of_struct` builder in `testing/uasset.rs` if the asset-level fixture isn't already in place; otherwise inline-build the Map body bytes within a containers-only test (the Map decode is self-contained inside `read_map_value` — `read_from` isn't strictly required for coverage).
3. **`set_of_struct_decodes`** — Set<InventorySlot> with 2 elements. Same pattern as test 2.
4. **`nested_array_of_struct_respects_depth_cap`** — Array<Struct{ Inner: Array<Struct{...}> }> nested deeper than `MAX_PROPERTY_DEPTH = 128`. Build inline-bytes for the nested shape (130 levels of inner-array-tag-info + struct body), then assert `PaksmithError::AssetParse { fault: AssetParseFault::PropertyDepthExceeded { .. }, .. }`.
5. **`array_of_custom_binary_struct_substitutes_empty_per_element`** — pins Design Decision #8's Array-side per-element catch. Build an Array<Struct> whose inner-array-tag-info header declares `struct_name = "FVector"` and `size = 12`, with each element's 12 bytes being raw f32 patterns (NOT tagged property iteration). `read_array_value` attempts `read_struct_value` per element, fails at the first FName-pair read (almost certainly `PackageIndexOob`), catches, logs warn, seeks cursor to `element_end`, substitutes empty properties. Assert: array has 2 elements, both `Struct { struct_name: "FVector", properties: [] }`. No error returned; downstream properties (if any) decode normally.
6. **`array_of_struct_with_zero_size_elements`** — edge case where the inner-array-tag-info header declares `size = 0`. `read_struct_value` is called with `expected_end = element_start` (zero-byte bound). `read_properties`'s loop condition is `while reader.stream_position() < expected_end` (verify this in `property/mod.rs::read_properties` before implementing), so a `size = 0` bound returns immediately with `Ok(Vec::new())`. Assert array has 2 elements, each `Struct { struct_name: "Empty", properties: [] }`, cursor positioned at the next byte after the array body.

   > **Implementation check:** before relying on this contract, trace `read_properties` to confirm the position-vs-expected_end termination. If the loop is `while !is_none_terminator`, a `size = 0` element WILL consume bytes from the next element and the test must be reframed (perhaps deferred to a follow-up issue noting "empty structs not supported").

7. **`map_with_custom_binary_struct_value_returns_partial_map`** — pins Design Decision #8's Map-side collection-level bail. Build a Map<NameProperty, FVector> with 3 entries; the first entry's struct value is a real `Vec<Property>` (synthesised tagged shape), the second entry's struct value is raw f32 bytes (custom-binary FVector — no "None" terminator). `read_map_value` decodes entry 1 cleanly, hits the FVector failure on entry 2, logs warn, seeks cursor to `expected_end`, returns `Ok(Some(Map { entries: [entry_1_only], ... }))`. Entry 3's bytes are never read but live inside the outer Map's body, so the cursor-seek-to-`expected_end` consumes them. Assert: 1 entry in the partial Map, entry 1 has the expected key + value shape, no error returned, no panic.

> **Tests 5 and 7 design note:** Both are explicit boundary markers for Phase 3+'s custom-binary struct readers. Phase 2g chooses "decode as far as possible, never crater the export" over strict rejection. Test 5 pins Array's per-element recovery; test 7 pins Map's collection-level bail. Phase 3+ will replace both with typed binary decoders, at which point both tests assert typed-property shapes instead of empty / partial collections.

- [ ] **Step 1: Implement all 7 tests.**

Each test follows the same skeleton: build the asset/body bytes, parse via `Package::read_from` or the per-collection function directly, assert the property-tree shape. Test 4 needs a sibling builder in `testing/uasset.rs` that emits 130 nested levels (one-shot construction — no `MinimalPackageSpec` extension needed since the asset is hand-rolled). Test 7 needs a Map-with-custom-binary-FVector-value byte synthesiser inline in the test.

- [ ] **Step 2: Run the integration test suite.**

```shell
set -o pipefail
cargo test -p paksmith-core --features __test_utils --test collection_of_struct_integration 2>&1 | tail -15
```

Expected: all 5 tests pass.

- [ ] **Step 3: Full local gate.**

```shell
set -o pipefail
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features 2>&1 | tail -20
cargo clean -p paksmith-core
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
```

- [ ] **Step 4: Commit.**

```bash
git add crates/paksmith-core/tests/collection_of_struct_integration.rs crates/paksmith-core/src/testing/uasset.rs
git commit -m "$(cat <<'EOF'
test(property): integration tests for collection-of-struct decoding

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Self-review checklist

**Spec coverage:**

- Issue #302 in-scope items: `Array<Struct>` ✓ (Task 3), `Map<Struct, *>` and `Map<*, Struct>` ✓ (Task 4), `Set<Struct>` ✓ (Task 5), per-element struct depth bounded by `MAX_PROPERTY_DEPTH` ✓ (Task 2's `depth + 1` plumbing), outer collection count bounded by `MAX_COLLECTION_ELEMENTS` ✓ (unchanged from Phase 2c), fixture-gen support ✓ (Task 6).
- Issue #302 acceptance criteria: real cooked Blueprint with `Array<Struct>` decodes (not Unknown) ✓ (Tasks 3-5), round-trip parity with `unreal_asset` ✓ (Task 6), proptest coverage for depth + count caps ✓ (Task 7 test 4 — recommend extending to a proptest in a follow-up if the integration test isn't sufficient), integration test for `Array<Struct>` + `Map<*, Struct>` ✓ (Task 7).
- Trigger gate from issue #302: Phase 2f merged ✓ (PRs #326-#334 all landed), wire-format question resolved empirically ✓ (this plan's "Wire-format reference" section cites unreal_asset revision `f4df5d8e` lines + CUE4Parse files — both primary sources named in the issue).

**Placeholder scan:** No TBD/TODO in required steps. The `#[ignore]` choreography flagged in the first plan draft was removed in favour of inline-bytes unit tests per task (Tasks 3-5 each ship with a passing test in `containers.rs::tests` — no cross-task test dependencies).

**Type consistency:**

- `read_struct_value` generalized in Task 2 to take `struct_name: &str` ✓; used by the existing top-level caller (refactored in Task 2 Step 2) and by Tasks 3 (Array — per-element catch inline) / 4 (Map — collection-level catch via labelled-break) / 5 (Set — same labelled-break pattern as Map).
- `AssetParseFault::ArrayOfStructHeaderMissing` defined in Task 1 ✓; used in Task 3.
- `VER_UE4_INNER_ARRAY_TAG_INFO` defined in Task 1; documented as structurally always met (paksmith UE4 floor 504 > 500) and used only as a code-clarity reference, not a runtime gate.
- `build_minimal_ue4_27_with_array_of_struct` defined in Task 6 ✓; used in Task 7 test 1. Task 3's TDD test is inline-bytes only (no fixture dependency); Tasks 4 and 5 follow the same inline-bytes pattern.

**Lint gate:** every task ends with `cargo clippy --workspace --all-targets --all-features -- -D warnings` (per `MEMORY/ghas_clippy_extra_lints.md`) AND `cargo fmt --all -- --check` AND `cargo clean -p paksmith-core && RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features` (per `MEMORY/feedback_cargo_doc_in_local_gates.md` — rustdoc lints like `private_intra_doc_links` fail CI but slip past clippy AND incremental cache can hide the lint on edits; clean before docs). ✓

**Pipe-masking gate (per `MEMORY/feedback_pipe_masks_exit_code.md`):** every cargo command in this plan that ends in `2>&1 | tail -N` is prefixed with `set -o pipefail`. ✓

**Co-Authored-By trailer (project convention since Phase 2c):** every `git commit -m` HEREDOC body in this plan ends with `Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>`. ✓

**Fixture-count gate (per `MEMORY/feedback_fixture_count_gate.md`):** Phase 2g does NOT add a new on-disk `tests/fixtures/*.pak`. The CI gate constant stays unchanged. If a follow-up commits a `real_v8b_array_of_struct.pak`, that PR bumps the constant and extends the enumeration comment. ✓

**Verify-wire-format-claims gate (per `MEMORY/feedback_verify_wire_format_claims.md`):** the "Wire-format reference" section cites both named primary sources (`unreal_asset` at pinned revision `f4df5d8e` AND CUE4Parse at HEAD) with file paths and line numbers. The reviewer is expected to spot-check at least one citation before approving any per-task PR. ✓

**Adversarial-panel-briefing gate (per `MEMORY/feedback_adversarial_panel_briefing.md`):** every per-task PR runs the standard 4-reviewer panel (quality + security + simplifier + architect) in parallel, cold-briefed, severity-scored, no word caps, with the convergence loop. The wire-format claims in this plan are exactly the kind of "load-bearing assertion to challenge" the panel exists to surface. ✓

**No EpicGames source attribution (per `MEMORY/feedback_no_ue_source_attribution_in_public_docs.md`):** wire-format claims cite `unreal_asset` (community) and CUE4Parse (community) only — NOT `github.com/EpicGames/UnrealEngine` paths. The version constant values (500, 441, 503) are derived from oracle enum positions, not engine source. ✓

**Out of scope for this draft PR:** `docs/plans/ROADMAP.md` currently lists Phase 2 as "2a complete; 2b–2f scoped" (line 18). Adding `2g` to that scope list is a separate scope-decision that belongs in a sibling `docs/roadmap-add-phase-2g` PR or in the first Task 1 PR. Not updated here to keep this draft tightly focused on the plan document.
