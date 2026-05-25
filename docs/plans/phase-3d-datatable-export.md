# Paksmith Phase 3d: DataTable → CSV / JSON export

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Cargo exit-code caveat:** Every cargo command piped through `tail`, `head`, or `grep` in this plan returns `0` even when cargo failed. After running any cargo gate, re-run unpiped, set `set -o pipefail`, or inspect `${PIPESTATUS[0]}`.

**Goal:** First typed export sub-phase. Adds parse-time specialization for `UDataTable` (per the dispatch table 3a wired) and two `FormatHandler` impls (`CsvHandler`, `JsonHandler`). DataTables are the highest-priority extraction target per `docs/formats/data/data-table.md` §Overview — game studios ship configurable content (items, abilities, NPC stats, dialogue) through DataTables, and bulk row-extraction is a frequently requested capability.

DataTable is the smallest practical export to validate the FormatHandler trait shape: rows live entirely in the export's inline payload (no `.ubulk` needed → 3d doesn't depend on 3b), the per-row body is just tagged-property iteration (the existing Phase 2 system already handles it), and the export targets (CSV / JSON) need only stdlib + the `csv` crate.

**Architecture:** Two new pieces:

1. **Parse-time:** `asset/exports/data_table.rs` — typed reader for `UDataTable` exports. Reads the tagged-property segment (via existing `read_properties`) plus the segment-2 row table (`NumRows: i32`, then `(FName, tagged-property stream)` pairs).
2. **Export-time:** `export/data_table.rs` — `CsvHandler` and `JsonHandler` impls of `FormatHandler`. Both consume `Asset::DataTable` and produce row-keyed output.

**Tech Stack:** Adds workspace dep on `csv` (~v1.3); `serde_json` already in dev-deps gets promoted to runtime dep.

---

## Deliverable

```shell
$ paksmith inspect game.pak Game/Items/WeaponTable.uasset --format json
{
  "asset_path": "Game/Items/WeaponTable.uasset",
  "exports": [{
    "object_name": "WeaponTable",
    "class_name": "DataTable",
    "data_table": {
      "row_struct": "ItemRow",
      "rows": [
        { "name": "Weapon_Sword", "properties": [
            { "name": "Damage", "value": { "Int": 10 } },
            { "name": "Cost",   "value": { "Int": 100 } }
        ]},
        { "name": "Weapon_Bow",   "properties": [
            { "name": "Damage", "value": { "Int": 8 } },
            { "name": "Cost",   "value": { "Int": 120 } }
        ]}
      ]
    }
  }]
}
```

And the registry-driven export path (no CLI yet — Phase 4):

```rust
let registry = HandlerRegistry::all_default_handlers();
let handler = registry.find_handler_by_extension("csv", &package.export_at(0).asset).unwrap();
let bytes = handler.export(&package.export_at(0).asset, None).unwrap();
// bytes = b"Name,Damage,Cost\nWeapon_Sword,10,100\nWeapon_Bow,8,120\n"
```

---

## Scope vs deferred work

**In scope:**

- `Asset::DataTable { row_struct: String, rows: Vec<DataTableRow> }` — new `Asset` variant. `DataTableRow { name: String, properties: Vec<NamedProperty> }`.
- `data_table::read_from(payload_bytes, &AssetContext) -> Result<Asset>` — parses segment 1 (tagged properties to "None") + segment 2 (i32 row count + N × `(FName, tagged-prop stream → "None")` pairs). Reuses existing `read_properties` for the row body.
- `class_dispatch_init()` in 3a's dispatch table gains `table.insert("DataTable", ExportFamily::DataTable);`.
- `read_payloads` in `package.rs` routes `ExportFamily::DataTable` to `data_table::read_from`.
- `CsvHandler` — `FormatHandler` impl. Output extension: `"csv"`. Computes the column header by union-ing all rows' property names (preserve first-seen order). Each cell renders the property value as a human-readable string (Bool → "true"/"false", Int → decimal, Float → minimum-precision decimal, Str/Name → quoted CSV string, complex types → JSON-encoded inline).
- `JsonHandler` — `FormatHandler` impl. Output extension: `"json"`. Pretty-printed serde_json. The full `Asset::DataTable` tree.
- Extended `HandlerRegistry::all_default_handlers()` — the single Phase 3 default-registry constructor (per master-index Design Decision #12) now also registers CSV + JSON handlers under the `Asset::DataTable` discriminant. Callers wanting a subset use `HandlerRegistry::new()` + explicit `register(discriminant, handler)`.
- 1 new cap: `MAX_ROWS_PER_DATATABLE = 1_048_576` (2^20; conservative per the format doc's recommendation at `data-table.md:255`).
- 4 new `AssetParseFault` variants:
  - `DataTableRowCountExceeded { count, cap }`.
  - `DataTableRowCountNegative { count: i32 }` — `NumRows < 0` (sign-extension guard per `data-table.md:251`).
  - `DataTableRowNameOob { name_index, name_table_len }` — row name's FName index out of bounds.
  - `DataTableRowOverrun { row, expected_end, actual_pos }` — row body parse overran the export's `serial_size + serial_offset` boundary (`data-table.md:274` invariant).
- 1 fixture-gen extension: `build_minimal_uasset_with_data_table(rows: &[(name, properties)])`.
- 6 integration tests: empty table, 2-row table happy path, row-count cap, negative row count, row name OOB, row overrun.

**Outside Phase 3d (kept):**

- **`UCompositeDataTable`.** Per format doc §Variants: same wire shape as `UDataTable` for standard builds; runtime composite-merging is a game-engine concern. 3d treats `CompositeDataTable` class as a `DataTable` synonym in the dispatch table (`table.insert("CompositeDataTable", ExportFamily::DataTable);`).
- **Custom-serialized row structs.** Per format doc §Variants: when a row body uses native binary serialization (not tagged-property iteration), the row read errors mid-row. 3d's behavior per format doc §Caps "Implementation hardening": reject the file (option a) with `DataTableRowOverrun` rather than silently truncating. The format doc's option (b) — advance to next row via per-row-size — is impossible without per-row-size on wire.

**Explicitly deferred (named target phases):**

- **`paksmith extract` CLI command** that takes a DataTable asset and writes CSV/JSON to disk. → **Phase 4.** 3d's `JsonHandler` integrates with existing `paksmith inspect`; `CsvHandler` exists in the library API but isn't yet CLI-reachable.
- **TSV output.** → Phase 4 follow-up (CSV handler with `'\t'` separator). Trivial to add when needed.
- **Row schema validation against `.usmap` `RowStruct` shape.** Per format doc §RowStruct resolution failure: rows still parse without schema. 3d emits them with property bag shape. Validating that decoded rows match the `RowStruct` schema is a separate concern for Phase 4+ when type-safe extraction matters.

---

## Design decisions locked here

1. **Row name resolution happens at parse time, NOT export time.** `data_table::read_from` resolves the `FName` row name to a `String` immediately via `AssetContext::resolve_name`. CSV/JSON handlers don't need the name table.

2. **`DataTableRow.properties` reuses Phase 2's `NamedProperty`.** No new property-tree type. The row body is exactly the same shape as a `StructProperty` body — just without the outer tag.

3. **Row bodies parse with `expected_end = serial_offset + serial_size`** (the export's full byte range). Per format doc §`Implementation hardening`: the cursor advances naturally through tagged-property iteration; if a row body fails to find "None" within `expected_end`, the whole iteration fails. This matches Phase 2g's collection-of-struct fallback semantics.

4. **CSV column union is order-preserving.** First row defines the initial column ordering. Subsequent rows add new columns at the end as they appear. A row missing a previously-seen column emits an empty cell (`,,`). This avoids the alternative — alphabetical sort — which would be a layout regression when the user's intent is "extract this table to inspect it" (preserving cooker order is usually closer to designer intent).

5. **CSV cell escaping uses RFC 4180 conventions.** The `csv` crate handles this — wraps in `"..."` when the cell contains `,`, `"`, or `\n`; doubles internal `"` to `""`.

6. **JSON output mirrors the existing `inspect_json_snapshot` shape.** `Asset::DataTable` serializes via `#[derive(serde::Serialize)]`; the snapshot regression test confirms wire-stable output.

7. **`UCompositeDataTable` is mapped to `DataTable` in the dispatch table.** Same `Asset::DataTable` variant; same handlers. The format doc's note on `CustomGameData` (game-profile-specific) is a Phase 5+ concern; 3d ignores it as a UE-default standard parse.

---

## Wire-format reference

Authoritative source: [`../formats/data/data-table.md`](../formats/data/data-table.md). Recap:

```
Segment 1 (tagged-property stream):
  Standard FPropertyTag iteration terminated by "None".
  RowStruct: ObjectProperty resolves to the UScriptStruct import.
  Optional strip-flag booleans.

Segment 2 (row table):
  i32 NumRows
  [loop NumRows times]
    FName RowName       (8 bytes: i32 name_index + i32 name_number)
    tagged-property-stream RowBody    (terminated by "None")
```

The "row body ends with None tag" rule means the reader iterates exactly `NumRows` times and per-iteration runs the standard property iterator until "None"; the stopping position becomes the start of the next row.

---

## Task overview

5 tasks.

| # | Title | Files |
|---|---|---|
| 1 | `Asset::DataTable` variant + error variants + cap | `asset/mod.rs`, `error.rs`, `seams.rs` |
| 2 | `data_table::read_from` parser + dispatch wiring | `asset/exports/data_table.rs`, `asset/package.rs`, `asset/exports/dispatch.rs` |
| 3 | `JsonHandler` impl | `export/data_table.rs` |
| 4 | `CsvHandler` impl + workspace `csv` dep | `Cargo.toml`, `export/data_table.rs` |
| 5 | Fixture-gen + 6 integration tests + snapshot update | `paksmith-fixture-gen/`, `paksmith-core-tests/` |

---

### Task 1: `Asset::DataTable` variant + new caps + error variants

**Files:**

- Modify: `crates/paksmith-core/src/asset/mod.rs` — add the variant.
- Modify: `crates/paksmith-core/src/error.rs` — add 4 variants + Display arms + pin tests.
- Modify: `crates/paksmith-core/src/seams.rs` — add the cap.

- [ ] **Step 1: Add `MAX_ROWS_PER_DATATABLE` to `seams.rs`.**

```rust
/// Maximum rows in a single DataTable. Per
/// `docs/formats/data/data-table.md` §Caps & limits — production
/// DataTables hold ~1k rows; 2^20 is generous against attack but
/// well above legitimate content.
pub(crate) const MAX_ROWS_PER_DATATABLE: usize = 1_048_576;

#[cfg(feature = "__test_utils")]
pub fn max_rows_per_datatable() -> usize { MAX_ROWS_PER_DATATABLE }
```

- [ ] **Step 2: Add `Asset::DataTable` variant.**

```rust
// In Asset enum (alongside Generic):

#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub enum Asset {
    Generic(crate::asset::property::bag::PropertyBag),
    DataTable(DataTableData),
    // 3e: Texture2D(...), 3f: SoundWave(...), 3g: StaticMesh(...), 3h: SkeletalMesh(...).
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct DataTableData {
    /// Empty when the table's `RowStruct` couldn't be resolved (a
    /// warn is logged at parse time per format doc §RowStruct
    /// resolution failure).
    pub row_struct: String,
    pub rows: Vec<DataTableRow>,
    /// Class-level tagged properties (RowStruct ObjectProperty, strip
    /// flags `bStripFromClientBuilds` / `bStripFromDedicatedServerBuilds`,
    /// `bIgnoreExtraFields`, `bIgnoreMissingFields`, etc.). Consumed by
    /// `DataTableJsonHandler` to round-trip the table's metadata into
    /// JSON output — without it, JSON consumers lose the strip-flag
    /// state that determined whether the cooker emitted zero rows.
    /// `DataTableCsvHandler` ignores this field (CSV has no schema
    /// for class-level metadata).
    pub class_properties: crate::asset::property::bag::PropertyBag,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct DataTableRow {
    pub name: String,
    pub properties: Vec<crate::asset::property::bag::NamedProperty>,
}
```

- [ ] **Step 3: Add the 4 error variants in `error.rs`.**

```rust
// In AssetParseFault:

/// Segment-2 `NumRows` prefix exceeds [`MAX_ROWS_PER_DATATABLE`].
DataTableRowCountExceeded { count: usize, cap: usize },

/// Segment-2 `NumRows` prefix is negative (sign-extension attack).
DataTableRowCountNegative { count: i32 },

/// Row name's FName index points outside the package's name table.
DataTableRowNameOob { name_index: u32, name_table_len: usize },

/// Row body's tagged-property iteration overran the export's
/// `serial_offset + serial_size` boundary. The asset is corrupt or
/// uses custom-binary row serialization (out of scope for 3d).
DataTableRowOverrun { row: usize, expected_end: u64, actual_pos: u64 },
```

Display arms (hand-rolled):

```rust
Self::DataTableRowCountExceeded { count, cap } => write!(
    f, "DataTable NumRows {count} exceeds cap {cap}"
),
Self::DataTableRowCountNegative { count } => write!(
    f, "DataTable NumRows {count} is negative (sign-extension or corrupt asset)"
),
Self::DataTableRowNameOob { name_index, name_table_len } => write!(
    f, "DataTable row name index {name_index} >= name table size {name_table_len}"
),
Self::DataTableRowOverrun { row, expected_end, actual_pos } => write!(
    f, "DataTable row {row} body overran export boundary: pos {actual_pos} > end {expected_end}"
),
```

- [ ] **Step 4: Add pin tests.**

```rust
#[test]
fn asset_parse_display_data_table_row_count_exceeded() {
    let s = AssetParseFault::DataTableRowCountExceeded { count: 2_000_000, cap: 1_048_576 }.to_string();
    assert_eq!(s, "DataTable NumRows 2000000 exceeds cap 1048576");
}
#[test]
fn asset_parse_display_data_table_row_count_negative() {
    let s = AssetParseFault::DataTableRowCountNegative { count: -1 }.to_string();
    assert_eq!(s, "DataTable NumRows -1 is negative (sign-extension or corrupt asset)");
}
#[test]
fn asset_parse_display_data_table_row_name_oob() {
    let s = AssetParseFault::DataTableRowNameOob { name_index: 99, name_table_len: 10 }.to_string();
    assert_eq!(s, "DataTable row name index 99 >= name table size 10");
}
#[test]
fn asset_parse_display_data_table_row_overrun() {
    let s = AssetParseFault::DataTableRowOverrun { row: 3, expected_end: 1024, actual_pos: 1100 }.to_string();
    assert_eq!(s, "DataTable row 3 body overran export boundary: pos 1100 > end 1024");
}
```

- [ ] **Step 5: Lint + test + doc gate.**

```shell
set -o pipefail
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features 2>&1 | tail -15
cargo clean -p paksmith-core
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
```

- [ ] **Step 6: Commit.**

```bash
git add crates/paksmith-core/src/asset/mod.rs crates/paksmith-core/src/error.rs crates/paksmith-core/src/seams.rs
git commit -m "$(cat <<'EOF'
feat(asset): add Asset::DataTable variant + DataTable* error variants

3d Task 1. Defines the typed shape that the upcoming parser fills in.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: `data_table::read_from` parser + dispatch wiring

**Files:**

- Create: `crates/paksmith-core/src/asset/exports/data_table.rs`.
- Modify: `crates/paksmith-core/src/asset/exports/dispatch.rs` — register class.
- Modify: `crates/paksmith-core/src/asset/package.rs` — replace the `unreachable!` arm for `ExportFamily::DataTable` with a real call.

- [ ] **Step 1: Write failing TDD test in `data_table.rs`.**

```rust
//! UDataTable export reader. See
//! `docs/plans/phase-3d-datatable-export.md`.

use std::io::{Cursor, Read, Seek};
use byteorder::{LittleEndian, ReadBytesExt};

use crate::asset::{AssetContext, DataTableData, DataTableRow};
use crate::asset::property::bag::{NamedProperty, PropertyBag};

/// Parse a UDataTable export payload.
///
/// `payload` is the export's `serial_size`-bounded slice. Returns
/// the typed `DataTableData` ready to wrap in `Asset::DataTable`.
pub fn read_from(
    payload: &[u8],
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<DataTableData> {
    let mut cur = Cursor::new(payload);
    let total_len = payload.len() as u64;

    // Segment 1: class-level tagged properties.
    let class_properties_inner = crate::asset::property::read_properties(
        &mut cur, ctx, /* depth */ 0, total_len, asset_path,
    )?;
    let class_properties = PropertyBag::Tree { properties: class_properties_inner.clone() };

    // Resolve RowStruct name from class properties for diagnostic
    // shape. Empty string if not present; warn-log when present but
    // unresolvable (the format doc's graceful-recovery clause).
    let row_struct = match class_properties_inner.iter()
        .find(|p| p.name == "RowStruct")
        .map(|p| &p.value)
    {
        Some(crate::asset::property::bag::PropertyValue::Object(idx)) => {
            // resolve_package_index takes 3 args: (index, ctx, asset_path).
            // Phase 2g's signature, verified at runtime.
            crate::asset::property::primitives::resolve_package_index(*idx, ctx, asset_path)
                .into_owned()
        }
        Some(other_kind) => {
            tracing::warn!(
                asset = asset_path,
                row_struct_kind = ?other_kind,
                "DataTable RowStruct property has unexpected non-Object value; \
                 emitting empty row_struct (rows still parse as property-bag)"
            );
            String::new()
        }
        None => {
            tracing::warn!(
                asset = asset_path,
                "DataTable has no RowStruct property; rows will parse but \
                 carry no schema-type label"
            );
            String::new()
        }
    };

    // Segment 2: i32 row count.
    let raw_count = cur.read_i32::<LittleEndian>().map_err(|_| eof(asset_path))?;
    if raw_count < 0 {
        return Err(crate::PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: crate::AssetParseFault::DataTableRowCountNegative { count: raw_count },
        });
    }
    let num_rows = raw_count as usize;
    if num_rows > crate::seams::MAX_ROWS_PER_DATATABLE {
        return Err(crate::PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: crate::AssetParseFault::DataTableRowCountExceeded {
                count: num_rows,
                cap: crate::seams::MAX_ROWS_PER_DATATABLE,
            },
        });
    }

    let mut rows = Vec::new();
    rows.try_reserve(num_rows).map_err(|_| /* allocation cap */ {
        crate::PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: crate::AssetParseFault::DataTableRowCountExceeded {
                count: num_rows,
                cap: crate::seams::MAX_ROWS_PER_DATATABLE,
            },
        }
    })?;

    for row_idx in 0..num_rows {
        let name_index = cur.read_u32::<LittleEndian>().map_err(|_| eof(asset_path))?;
        let _name_number = cur.read_u32::<LittleEndian>().map_err(|_| eof(asset_path))?;
        if (name_index as usize) >= ctx.names.len() {
            return Err(crate::PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: crate::AssetParseFault::DataTableRowNameOob {
                    name_index,
                    name_table_len: ctx.names.len(),
                },
            });
        }
        let name = ctx.names[name_index as usize].to_string();

        // Row body — tagged-property iteration to "None".
        let row_props = crate::asset::property::read_properties(
            &mut cur, ctx, /* depth */ 0, total_len, asset_path,
        )?;
        let actual = cur.stream_position().map_err(|_| eof(asset_path))?;
        if actual > total_len {
            return Err(crate::PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: crate::AssetParseFault::DataTableRowOverrun {
                    row: row_idx,
                    expected_end: total_len,
                    actual_pos: actual,
                },
            });
        }
        rows.push(DataTableRow { name, properties: row_props });
    }

    Ok(DataTableData { row_struct, rows, class_properties })
}

fn eof(asset_path: &str) -> crate::PaksmithError {
    crate::PaksmithError::AssetParse {
        asset_path: asset_path.to_string(),
        fault: crate::AssetParseFault::UnexpectedEof {
            field: crate::AssetWireField::DataTableSegment2,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::testing::context_with_names;

    #[test]
    fn empty_data_table_parses() {
        // Segment 1: just None terminator (8 bytes).
        // Segment 2: NumRows = 0 (4 bytes).
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0i32.to_le_bytes()); // None idx
        bytes.extend_from_slice(&0i32.to_le_bytes()); // None num
        bytes.extend_from_slice(&0i32.to_le_bytes()); // NumRows = 0
        let ctx = context_with_names(&["None"]);
        let result = read_from(&bytes, &ctx, "test").expect("parse");
        assert_eq!(result.rows.len(), 0);
    }

    #[test]
    fn negative_row_count_rejected() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0i32.to_le_bytes()); // None idx
        bytes.extend_from_slice(&0i32.to_le_bytes()); // None num
        bytes.extend_from_slice(&(-1i32).to_le_bytes()); // NumRows = -1

        let ctx = context_with_names(&["None"]);
        match read_from(&bytes, &ctx, "test") {
            Err(crate::PaksmithError::AssetParse {
                fault: crate::AssetParseFault::DataTableRowCountNegative { count },
                ..
            }) => assert_eq!(count, -1),
            other => panic!("expected DataTableRowCountNegative, got {other:?}"),
        }
    }

    #[test]
    fn row_count_over_cap_rejected() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0i32.to_le_bytes());
        bytes.extend_from_slice(&0i32.to_le_bytes());
        bytes.extend_from_slice(&(crate::seams::MAX_ROWS_PER_DATATABLE as i32 + 1).to_le_bytes());

        let ctx = context_with_names(&["None"]);
        match read_from(&bytes, &ctx, "test") {
            Err(crate::PaksmithError::AssetParse {
                fault: crate::AssetParseFault::DataTableRowCountExceeded { .. },
                ..
            }) => {}
            other => panic!("expected DataTableRowCountExceeded, got {other:?}"),
        }
    }
}
```

- [ ] **Step 2: Define the registry-shim `read_typed` and register `DataTable` / `CompositeDataTable` in `dispatch.rs`.**

Per 3a's new dispatch shape (`HashMap<&'static str, TypedReaderFn>`), the data-table reader needs a shim with the registry-compatible signature `fn(&[u8], &AssetContext, &str) -> Result<Asset>`. The shim calls `read_from` and wraps the result.

```rust
// In asset/exports/data_table.rs, alongside read_from:

/// Registry-compatible shim. Wraps `read_from`'s `DataTableData` in
/// the typed `Asset::DataTable` variant.
pub(crate) fn read_typed(
    payload: &[u8],
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<crate::asset::Asset> {
    let data = read_from(payload, ctx, asset_path)?;
    Ok(crate::asset::Asset::DataTable(data))
}
```

```rust
// In asset/exports/dispatch.rs::class_dispatch_init, add two entries:

table.insert("DataTable", crate::asset::exports::data_table::read_typed);
table.insert("CompositeDataTable", crate::asset::exports::data_table::read_typed);
```

- [ ] **Step 3: NO change required in `package.rs::read_payloads`.**

3a Task 4 already wired the dispatch as an `if let Some(read_typed) = class_dispatch().get(...)` lookup. 3d's only additions are (a) Task 2 above to register the class name + shim, and (b) the new `Asset::DataTable` variant defined in 3d Task 1. The `read_payloads` loop body is unchanged — the new dispatch-table entries route `"DataTable"` / `"CompositeDataTable"` classes through `read_typed` without any new match arms.

- [ ] **Step 4: Run tests.**

```shell
set -o pipefail
cargo test -p paksmith-core asset::exports::data_table::tests 2>&1 | tail -10
cargo test --workspace --all-features 2>&1 | tail -15
```

- [ ] **Step 5: Lint + test + doc gate.** Same as Task 1 Step 5.

- [ ] **Step 6: Commit.**

```bash
git add crates/paksmith-core/src/asset/exports/data_table.rs crates/paksmith-core/src/asset/exports/dispatch.rs crates/paksmith-core/src/asset/package.rs
git commit -m "$(cat <<'EOF'
feat(data-table): read_from parser + class-name dispatch wiring

DataTable + CompositeDataTable class names now route through the
typed reader; produces Asset::DataTable variants.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: `JsonHandler` impl

**Files:**

- Create: `crates/paksmith-core/src/export/data_table.rs`.
- Modify: `crates/paksmith-core/src/export/mod.rs` — declare submodule, re-export `JsonHandler`.

- [ ] **Step 1: Write failing TDD test.**

```rust
use crate::asset::{Asset, DataTableData, DataTableRow};
use crate::asset::property::bag::{NamedProperty, PropertyValue, PropertyBag};
use super::{BulkData, FormatHandler};

#[derive(Debug, Default, Clone, Copy)]
pub struct DataTableJsonHandler;

impl FormatHandler for DataTableJsonHandler {
    fn output_extension(&self) -> &'static str { "json" }

    fn supports(&self, asset: &Asset) -> bool {
        matches!(asset, Asset::DataTable(_))
    }

    fn export(&self, asset: &Asset, _bulk: Option<&BulkData>) -> crate::Result<Vec<u8>> {
        let Asset::DataTable(data) = asset else {
            return Err(crate::PaksmithError::Internal {
                context: "DataTableJsonHandler::export called on non-DataTable Asset".into(),
            });
        };
        serde_json::to_vec_pretty(data).map_err(|e| crate::PaksmithError::Internal {
            context: format!("DataTable JSON serialize: {e}"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_handler_emits_data_table_tree() {
        let data = DataTableData {
            row_struct: "ItemRow".to_string(),
            class_properties: PropertyBag::Tree { properties: Vec::new() },
            rows: vec![
                DataTableRow {
                    name: "Weapon_Sword".to_string(),
                    properties: vec![NamedProperty {
                        name: "Damage".to_string(),
                        array_index: 0,
                        value: PropertyValue::Int(10),
                    }],
                },
            ],
        };
        let asset = Asset::DataTable(data);
        let handler = DataTableJsonHandler;
        assert!(handler.supports(&asset));
        let bytes = handler.export(&asset, None).expect("export");
        let json = std::str::from_utf8(&bytes).expect("utf-8");
        assert!(json.contains("\"row_struct\": \"ItemRow\""));
        assert!(json.contains("\"name\": \"Weapon_Sword\""));
        assert!(json.contains("\"Int\": 10"));
    }

    #[test]
    fn json_handler_does_not_support_generic() {
        let asset = Asset::Generic(PropertyBag::Opaque { payload_bytes: 0 });
        assert!(!DataTableJsonHandler.supports(&asset));
    }
}
```

- [ ] **Step 2: Run.** `cargo test -p paksmith-core export::data_table::tests::json 2>&1 | tail -10`.

- [ ] **Step 3: Lint + test + doc gate.** Same as Task 1 Step 5.

- [ ] **Step 4: Commit.**

```bash
git add crates/paksmith-core/src/export/data_table.rs crates/paksmith-core/src/export/mod.rs
git commit -m "$(cat <<'EOF'
feat(export): DataTableJsonHandler emits Asset::DataTable as JSON

3d Task 3. Pretty-printed serde_json shape matches the existing
inspect_json_snapshot precedent.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: `CsvHandler` impl + workspace `csv` dep

**Files:**

- Modify: `Cargo.toml` (workspace) — add `csv = "1.3"`.
- Modify: `crates/paksmith-core/Cargo.toml` — add `csv.workspace = true`.
- Modify: `crates/paksmith-core/src/export/data_table.rs`.

- [ ] **Step 1: Write failing TDD test.**

```rust
#[derive(Debug, Default, Clone, Copy)]
pub struct DataTableCsvHandler;

impl FormatHandler for DataTableCsvHandler {
    fn output_extension(&self) -> &'static str { "csv" }

    fn supports(&self, asset: &Asset) -> bool {
        matches!(asset, Asset::DataTable(_))
    }

    fn export(&self, asset: &Asset, _bulk: Option<&BulkData>) -> crate::Result<Vec<u8>> {
        let Asset::DataTable(data) = asset else {
            return Err(crate::PaksmithError::Internal {
                context: "DataTableCsvHandler on non-DataTable".into(),
            });
        };

        // Order-preserving column union: first-seen wins.
        let mut columns: Vec<String> = Vec::new();
        for row in &data.rows {
            for prop in &row.properties {
                if !columns.iter().any(|c| c == &prop.name) {
                    columns.push(prop.name.clone());
                }
            }
        }

        // csv::WriterBuilder default is CRLF (`\r\n`); paksmith picks
        // LF (`\n`) line endings because (a) UE asset paths are
        // Unix-style virtual paths and (b) test fixtures + diff tools
        // are LF-friendly. Document the choice; both terminators are
        // RFC 4180-valid.
        let mut writer = csv::WriterBuilder::new()
            .terminator(csv::Terminator::Any(b'\n'))
            .from_writer(Vec::new());
        let mut header = vec!["Name".to_string()];
        header.extend(columns.iter().cloned());
        writer.write_record(&header).map_err(|e| crate::PaksmithError::Internal {
            context: format!("CSV header: {e}"),
        })?;

        for row in &data.rows {
            let mut record = vec![row.name.clone()];
            for col in &columns {
                let cell = row.properties.iter()
                    .find(|p| &p.name == col)
                    .map(|p| value_to_csv_cell(&p.value))
                    .unwrap_or_default();
                record.push(cell);
            }
            writer.write_record(&record).map_err(|e| crate::PaksmithError::Internal {
                context: format!("CSV row: {e}"),
            })?;
        }

        writer.into_inner().map_err(|e| crate::PaksmithError::Internal {
            context: format!("CSV finish: {e}"),
        })
    }
}

/// Render a property value as a CSV cell. Primitive types format
/// directly; complex types JSON-inline (escaped by the csv crate).
fn value_to_csv_cell(value: &PropertyValue) -> String {
    use PropertyValue::*;
    match value {
        Bool(b) => b.to_string(),
        Int(n) => n.to_string(),
        Int8(n) => n.to_string(),
        Int16(n) => n.to_string(),
        Int64(n) => n.to_string(),
        UInt16(n) => n.to_string(),
        UInt32(n) => n.to_string(),
        UInt64(n) => n.to_string(),
        Float(f) => f.to_string(),
        Double(d) => d.to_string(),
        Str(s) => s.clone(),
        Name(s) => s.clone(),
        // Complex types: JSON-inline. 3d's match arm covers Phase 2's
        // existing PropertyValue variants only; 3c's PropertyValue::
        // TypedStruct(_) variant is added in 3c Task 1 and that PR
        // widens the match. Keeps 3d shippable in parallel with 3c.
        Struct { .. } | Array { .. } | Map { .. } | Set { .. }
        | Object(_) | SoftObject { .. } | Text { .. } | Byte { .. } | Enum { .. }
        | Unknown { .. } => {
            serde_json::to_string(value).unwrap_or_else(|_| String::from("<error>"))
        }
    }
}

#[test]
fn csv_handler_emits_header_and_rows() {
    let data = DataTableData {
        row_struct: "ItemRow".to_string(),
        class_properties: PropertyBag::Tree { properties: Vec::new() },
        rows: vec![
            DataTableRow {
                name: "Weapon_Sword".to_string(),
                properties: vec![
                    NamedProperty { name: "Damage".to_string(), array_index: 0, value: PropertyValue::Int(10) },
                    NamedProperty { name: "Cost".to_string(),   array_index: 0, value: PropertyValue::Int(100) },
                ],
            },
            DataTableRow {
                name: "Weapon_Bow".to_string(),
                properties: vec![
                    NamedProperty { name: "Damage".to_string(), array_index: 0, value: PropertyValue::Int(8) },
                    NamedProperty { name: "Cost".to_string(),   array_index: 0, value: PropertyValue::Int(120) },
                ],
            },
        ],
    };
    let asset = Asset::DataTable(data);
    let bytes = DataTableCsvHandler.export(&asset, None).expect("export");
    let csv = std::str::from_utf8(&bytes).expect("utf-8");
    assert_eq!(csv, "Name,Damage,Cost\nWeapon_Sword,10,100\nWeapon_Bow,8,120\n");
}
```

- [ ] **Step 2: Run.** `cargo test -p paksmith-core export::data_table::tests::csv 2>&1 | tail -10`.

- [ ] **Step 3: Extend `HandlerRegistry::all_default_handlers()` (single constructor, NOT a new `default_with_*` helper).**

Per master-index Design Decision #12 and 3a Design Decision #13: there is ONE registration site, `all_default_handlers()`. 3d adds its handlers there inline:

```rust
// In crates/paksmith-core/src/export/mod.rs, inside the existing
// HandlerRegistry::all_default_handlers() function body that 3a
// established. Add immediately after the Asset::Generic registration:

use crate::asset::{Asset, DataTableData};

let dt_sentinel = Asset::DataTable(DataTableData::empty());
let dt_disc = std::mem::discriminant(&dt_sentinel);
reg.register(dt_disc, Box::new(data_table::DataTableCsvHandler));
reg.register(dt_disc, Box::new(data_table::DataTableJsonHandler));
```

Order within the bucket matters: when `find_handler(&asset)` walks the per-discriminant Vec for an `Asset::DataTable`, CSV is registered first → CSV returned by default. Callers wanting JSON go through `find_handler_by_extension("json", &asset)`. The CSV-first default matches the format doc's "high-priority extraction target" framing (`data-table.md:28`).

**`DataTableData::empty()` constructor MUST be defined as part of Task 1** (alongside the struct declaration) so the sentinel construction doesn't trigger unexpected allocations. Per 3a Design Decision #14:

```rust
impl DataTableData {
    /// Cheap default for sentinel-discriminant construction. All
    /// fields are zero-allocation `Vec::new()` / `String::new()`.
    pub fn empty() -> Self {
        Self {
            row_struct: String::new(),
            rows: Vec::new(),
            class_properties: crate::asset::property::bag::PropertyBag::tree(Vec::new()),
        }
    }
}
```

- [ ] **Step 4: Lint + test + doc gate.** Same as Task 1 Step 5.

- [ ] **Step 5: Commit.**

```bash
git add Cargo.toml crates/paksmith-core/Cargo.toml crates/paksmith-core/src/export/data_table.rs crates/paksmith-core/src/export/mod.rs
git commit -m "$(cat <<'EOF'
feat(export): DataTableCsvHandler + extend all_default_handlers

3d Task 4. CSV column union is order-preserving; complex cell types
JSON-inline. Registry convenience constructor wires GenericHandler +
DataTable handlers together.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: Fixture-gen + integration tests + snapshot update

**Files:**

- Modify: `crates/paksmith-fixture-gen/src/uasset.rs`.
- Create: `crates/paksmith-core-tests/tests/data_table_integration.rs`.
- Possibly update: `crates/paksmith-cli/tests/snapshots/inspect_cli__inspect_json_snapshot.snap`.

- [ ] **Step 1: Add `build_minimal_uasset_with_data_table` to fixture-gen.**

Synthesizes a UDataTable asset with a known row schema and 2 rows. Cross-validate against CUE4Parse per the master-index protocol.

- [ ] **Step 2: Write 6 integration tests.**

```rust
// tests/data_table_integration.rs

use paksmith_core::asset::{Asset, Package};
use paksmith_core::export::{HandlerRegistry, FormatHandler};
use paksmith_core::PaksmithError;

#[test]
fn empty_data_table_parses_to_zero_rows() {
    let pak = include_bytes!("../../tests/fixtures/data_table_empty.pak");
    let pkg = Package::read_from_pak_bytes(pak, "Game/Empty.uasset", None).expect("read");
    let exports = pkg.export_payloads();
    match &exports[0] {
        Asset::DataTable(data) => assert_eq!(data.rows.len(), 0),
        other => panic!("expected DataTable, got {other:?}"),
    }
}

#[test]
fn two_row_data_table_exports_to_csv() {
    let pak = include_bytes!("../../tests/fixtures/data_table_weapons.pak");
    let pkg = Package::read_from_pak_bytes(pak, "Game/Weapons.uasset", None).expect("read");
    let reg = HandlerRegistry::all_default_handlers();
    let handler = reg.find_handler_by_extension("csv", &pkg.export_payloads()[0]).expect("csv handler");
    let bytes = handler.export(&pkg.export_payloads()[0], None).expect("export");
    let csv = std::str::from_utf8(&bytes).expect("utf-8");
    assert!(csv.starts_with("Name,"));
    assert!(csv.contains("Weapon_Sword"));
    assert!(csv.contains("Weapon_Bow"));
}

#[test]
fn two_row_data_table_exports_to_json() {
    let pak = include_bytes!("../../tests/fixtures/data_table_weapons.pak");
    let pkg = Package::read_from_pak_bytes(pak, "Game/Weapons.uasset", None).expect("read");
    let reg = HandlerRegistry::all_default_handlers();
    let handler = reg.find_handler_by_extension("json", &pkg.export_payloads()[0]).expect("json handler");
    let bytes = handler.export(&pkg.export_payloads()[0], None).expect("export");
    let json = std::str::from_utf8(&bytes).expect("utf-8");
    assert!(json.contains("\"row_struct\""));
    assert!(json.contains("\"Weapon_Sword\""));
}

#[test]
fn row_count_over_cap_errors_typed() {
    // Synthetic asset with NumRows = MAX + 1 (no actual row bodies).
    let pak = include_bytes!("../../tests/fixtures/data_table_over_cap.pak");
    match Package::read_from_pak_bytes(pak, "Game/Bad.uasset", None) {
        Err(PaksmithError::AssetParse {
            fault: paksmith_core::AssetParseFault::DataTableRowCountExceeded { .. },
            ..
        }) => {}
        other => panic!("expected DataTableRowCountExceeded, got {other:?}"),
    }
}

#[test]
fn negative_row_count_errors_typed() {
    let pak = include_bytes!("../../tests/fixtures/data_table_negative_count.pak");
    match Package::read_from_pak_bytes(pak, "Game/Bad.uasset", None) {
        Err(PaksmithError::AssetParse {
            fault: paksmith_core::AssetParseFault::DataTableRowCountNegative { .. },
            ..
        }) => {}
        other => panic!("expected DataTableRowCountNegative, got {other:?}"),
    }
}

#[test]
fn row_overrun_errors_typed() {
    let pak = include_bytes!("../../tests/fixtures/data_table_row_overrun.pak");
    match Package::read_from_pak_bytes(pak, "Game/Bad.uasset", None) {
        Err(PaksmithError::AssetParse {
            fault: paksmith_core::AssetParseFault::DataTableRowOverrun { .. },
            ..
        }) => {}
        other => panic!("expected DataTableRowOverrun, got {other:?}"),
    }
}
```

- [ ] **Step 3: Bump CI fixture-count gate by +5.**

- [ ] **Step 4: Update `inspect_json_snapshot` if the snapshot fixture now carries a DataTable export.**

If the existing fixture is rebuilt to include a DataTable, `cargo insta review` and accept the new shape.

- [ ] **Step 5: Lint + test + doc gate.** Same as Task 1 Step 5.

- [ ] **Step 6: Commit.**

```bash
git add crates/paksmith-fixture-gen/src/uasset.rs tests/fixtures/data_table_*.pak crates/paksmith-core-tests/tests/data_table_integration.rs .github/workflows/ci.yml
git commit -m "$(cat <<'EOF'
test(data-table): fixture-gen + 6 integration tests covering 3d

Closes Phase 3d. CSV + JSON export, cap rejection, sign-extension
guard, overrun rejection.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Review panel (Phase 3d specifics)

- **Wire-format pass** — MANDATORY. Cross-validate `read_from` against `docs/formats/data/data-table.md` and CUE4Parse `UDataTable.cs` at the format doc's SHA.
- **Security pass** — MANDATORY for Task 1 + Task 2 (cap, sign-extension, OOB guards).
- **Deep-impact tracer** — MANDATORY for Task 1 (adds `Asset::DataTable` variant — affects every `Asset`-consumer).
- **Performance** — soft trigger.

Total reviewers per task: 4-5 (standard 3 + wire-format + security).

---

## After 3d lands

- `paksmith inspect` JSON output renders DataTable assets with full row tree (instead of `PropertyBag::Opaque` past the "None" tag, which would have happened in Phase 2 closure).
- `HandlerRegistry::all_default_handlers()` produces a registry that handles `Asset::Generic` (passthrough) AND `Asset::DataTable` (CSV / JSON).
- 3a's trait shape is empirically validated against a real export type — if 3a's signature needs revision, 3d's experience surfaces it.
- 3e/3f/3g/3h follow exactly the same 5-task structure: variant + parser + handler + handler + fixture-gen.

---

## References

- Master index: [`phase-3-export-pipeline.md`](phase-3-export-pipeline.md).
- Wire-format reference: [`../formats/data/data-table.md`](../formats/data/data-table.md).
- Phase 3a's `ExportFamily::DataTable` placeholder: `crates/paksmith-core/src/asset/exports/dispatch.rs` (introduced empty in 3a).
- Phase 2's `read_properties`: `crates/paksmith-core/src/asset/property/mod.rs`.
