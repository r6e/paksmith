//! `UDataTable` export reader (Phase 3d).
//!
//! Wire-format reference: `docs/formats/data/data-table.md` (oracle
//! `FabianFG/CUE4Parse` `UDataTable.cs` @ `cf74fc32`). The export
//! payload has two back-to-back segments:
//!
//! 1. **Class-level tagged properties** — the standard
//!    None-terminated `FPropertyTag` stream (`RowStruct` object ref,
//!    strip flags, …), decoded by the existing
//!    [`read_properties`](crate::asset::property::read_properties).
//! 2. **Row blob** — an `i32 NumRows` prefix, then `NumRows` pairs of
//!    `(FName RowName, None-terminated tagged-property RowBody)`.
//!
//! `UCompositeDataTable` shares this exact on-disk shape for standard
//! (non-game-specific) builds — its `Deserialize` calls
//! `base.Deserialize` with no extra pre-reads outside a
//! `GAME_HonorofKingsWorld` array (a Phase-5 game-profile concern).
//! See the format doc's `UCompositeDataTable` section. Both class
//! names route here.

use std::io::Cursor;

use byteorder::{LittleEndian, ReadBytesExt};

use crate::PaksmithError;
use crate::asset::bulk_data::FByteBulkData;
use crate::asset::property::bag::PropertyBag;
use crate::asset::property::primitives::{Property, PropertyValue};
use crate::asset::property::{
    MAX_ROWS_PER_DATATABLE, read_fname_pair, read_object_guid_tail, read_properties,
};
use crate::asset::{Asset, AssetContext, DataTableData, DataTableRow, decode_warn};
use crate::error::{AssetParseFault, AssetWireField, try_reserve_asset};
use crate::seams::AssetSeam;

/// Lower bound on a single row's wire size: an 8-byte `RowName` FName
/// pair plus the 8-byte `"None"` terminator that ends the (possibly
/// empty) row body. Used to clamp the `NumRows`-driven row-vec
/// reservation to what the payload could actually contain, so a lying
/// `NumRows` prefix can't force an allocation disproportionate to the
/// input size (the `MAX_ROWS_PER_DATATABLE` cap alone permits a ~2^20
/// reservation regardless of how few bytes follow).
const MIN_ROW_BYTES: u64 = 16;

/// Parse a `UDataTable` export payload into [`DataTableData`].
///
/// `payload` is the export's `serial_size`-bounded byte slice.
///
/// # Errors
/// - [`AssetParseFault::DataTableRowCountNegative`] if the `NumRows`
///   prefix is negative.
/// - [`AssetParseFault::DataTableRowCountExceeded`] if `NumRows`
///   exceeds [`MAX_ROWS_PER_DATATABLE`].
/// - [`AssetParseFault::UnexpectedEof`] (`field: DataTableNumRows`) on
///   a short `NumRows` read; FName / tagged-property faults from the
///   nested [`read_fname_pair`] / [`read_properties`] reads (an
///   out-of-range `RowName` index surfaces as `PackageIndexOob`; an
///   unterminated row body surfaces as `PropertyTagSizeMismatch`).
/// - [`AssetParseFault::AllocationFailed`] if the row-vec reservation
///   is refused.
/// - [`AssetParseFault::DerivedStringBudgetExceeded`] when the copied
///   row names or row struct pass the package's derived-string budget.
pub(crate) fn read_from(
    payload: &[u8],
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<DataTableData> {
    let mut cur = Cursor::new(payload);
    let total_len = payload.len() as u64;

    // Segment 1: class-level tagged properties (None-terminated), then the
    // `UObject::Serialize` object-GUID tail (bSerializeGuid + optional FGuid)
    // that precedes the UDataTable row map.
    // UE5 >= 1011: per-object serialization-control byte precedes the
    // export root's tagged stream (#643).
    crate::asset::property::read_class_serialization_control(&mut cur, ctx, asset_path)?;
    let class_props = read_properties(&mut cur, ctx, 0, total_len, asset_path)?;
    let _object_guid = read_object_guid_tail(&mut cur, total_len, asset_path)?;

    // Resolve the RowStruct type name for diagnostics BEFORE moving
    // `class_props` into the bag (avoids a clone).
    let row_struct = resolve_row_struct(&class_props, ctx, asset_path)?;
    let class_properties = PropertyBag::Tree {
        properties: class_props,
    };

    // Segment 2: i32 NumRows prefix. `try_from` both rejects a
    // negative count (sign-extension / corrupt asset) AND converts —
    // no `as usize` sign-loss cast.
    let raw_count = cur
        .read_i32::<LittleEndian>()
        .map_err(|_| PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::UnexpectedEof {
                field: AssetWireField::DataTableNumRows,
            },
        })?;
    let num_rows = usize::try_from(raw_count).map_err(|_| PaksmithError::AssetParse {
        asset_path: asset_path.to_string(),
        fault: AssetParseFault::DataTableRowCountNegative { count: raw_count },
    })?;
    if num_rows > MAX_ROWS_PER_DATATABLE {
        return Err(PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::DataTableRowCountExceeded {
                count: num_rows,
                cap: MAX_ROWS_PER_DATATABLE,
            },
        });
    }

    // Reserve clamped to the most rows the bytes still ahead of the
    // cursor could hold (see `reserve_count`): an honest NumRows
    // reserves exactly `num_rows`; a dishonest one reserves
    // proportional to the input, never amplified. `try_reserve_asset`
    // keeps it OOM-graceful.
    let remaining = total_len.saturating_sub(cur.position());
    let mut rows: Vec<DataTableRow> = Vec::new();
    try_reserve_asset(
        &mut rows,
        reserve_count(num_rows, remaining),
        asset_path,
        AssetSeam::DataTableRows,
    )?;

    for _ in 0..num_rows {
        // RowName: `read_fname_pair` resolves + bounds-checks (an
        // out-of-range index surfaces as `PackageIndexOob` tagged with
        // `DataTableRowName` — no DataTable-specific OOB variant).
        let name = read_fname_pair(&mut cur, ctx, asset_path, AssetWireField::DataTableRowName)?;
        // Row body: tagged-property iteration to "None", bounded by
        // `total_len`. An unterminated body running past the payload
        // surfaces as `PropertyTagSizeMismatch` from `read_properties`.
        let properties = read_properties(&mut cur, ctx, 0, total_len, asset_path)?;
        rows.push(DataTableRow {
            name: ctx.charge_derived(name.to_string(), asset_path)?,
            properties,
        });
    }

    Ok(DataTableData {
        row_struct,
        rows,
        class_properties,
    })
}

/// Row-vec reservation count: `num_rows` clamped to the most rows
/// `remaining_bytes` (the payload still ahead of the row cursor) could
/// hold (each row is `>= MIN_ROW_BYTES`). Keeps a dishonest `NumRows`
/// prefix from forcing a reservation disproportionate to the actual
/// input size.
fn reserve_count(num_rows: usize, remaining_bytes: u64) -> usize {
    num_rows.min(usize::try_from(remaining_bytes / MIN_ROW_BYTES).unwrap_or(usize::MAX))
}

/// Extract the `RowStruct` class name from the class-level properties.
/// Returns an empty string when the `RowStruct`
/// property is absent or isn't an `ObjectProperty` — rows still parse;
/// they just carry no schema-type label, per the format doc's
/// graceful-recovery clause.
///
/// # Errors
///
/// [`AssetParseFault::DerivedStringBudgetExceeded`] when the copied
/// class name passes the package's derived-string budget.
fn resolve_row_struct(
    class_props: &[Property],
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<String> {
    match class_props
        .iter()
        .find(|p| p.name() == "RowStruct")
        .map(|p| &p.value)
    {
        Some(PropertyValue::Object { name, .. }) => {
            ctx.charge_derived(name.to_string(), asset_path)
        }
        Some(_) => {
            decode_warn!(
                ctx,
                asset_path,
                "DataTable RowStruct property is not an ObjectProperty; \
                 emitting empty row_struct (rows still parse)"
            );
            Ok(String::new())
        }
        None => {
            decode_warn!(
                ctx,
                asset_path,
                "DataTable has no RowStruct property; emitting empty \
                 row_struct (rows still parse)"
            );
            Ok(String::new())
        }
    }
}

/// Registry-compatible shim ([`crate::asset::exports::dispatch::TypedReaderFn`]).
/// Wraps [`read_from`]'s [`DataTableData`] in the typed
/// [`Asset::DataTable`] variant. DataTables carry no bulk-data
/// records, so the companion-records vec is always empty.
pub(crate) fn read_typed(
    payload: &[u8],
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<(Asset, Vec<FByteBulkData>)> {
    let data = read_from(payload, ctx, asset_path)?;
    Ok((Asset::DataTable(data), Vec::new()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::property::test_utils::{
        assert_derived_budget_exceeded, make_ctx, with_derived_budget,
    };

    // --- wire-byte builders (kept explicit so the fixture bytes are
    // independently auditable against the format doc, not circular
    // with the parser) ---

    /// Append an FName pair `(index, number=0)`.
    fn fname(buf: &mut Vec<u8>, index: i32) {
        buf.extend_from_slice(&index.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
    }

    /// Append the `(0, 0)` "None" terminator — a bare property-stream end, used
    /// for the **nested** per-row property bodies.
    fn none(buf: &mut Vec<u8>) {
        fname(buf, 0);
    }

    /// Append the **top-level export** object-body terminator: the `None` tag
    /// plus the `UObject::Serialize` object-GUID tail (`bSerializeGuid = 0`, no
    /// `FGuid`) the reader consumes after the class-level properties, before the
    /// row map. Use this for segment-1's terminator; per-row bodies use [`none`].
    fn object_end(buf: &mut Vec<u8>) {
        none(buf);
        buf.extend_from_slice(&0i32.to_le_bytes()); // bSerializeGuid = 0 (bool32)
    }

    /// Append a UE4.27 `IntProperty` FPropertyTag + its i32 value.
    /// `name_idx` / `type_idx` are name-table indices.
    fn int_property(buf: &mut Vec<u8>, name_idx: i32, type_idx: i32, value: i32) {
        fname(buf, name_idx); // Name
        fname(buf, type_idx); // Type ("IntProperty")
        buf.extend_from_slice(&4i32.to_le_bytes()); // Size
        buf.extend_from_slice(&0i32.to_le_bytes()); // ArrayIndex
        buf.push(0u8); // HasPropertyGuid
        buf.extend_from_slice(&value.to_le_bytes()); // value
    }

    #[test]
    fn empty_data_table_parses() {
        // Segment 1: bare None terminator. Segment 2: NumRows = 0.
        let mut bytes = Vec::new();
        object_end(&mut bytes); // segment 1 terminator
        bytes.extend_from_slice(&0i32.to_le_bytes()); // NumRows = 0
        let ctx = make_ctx(&["None"]);
        let data = read_from(&bytes, &ctx, "test.uasset").expect("parse");
        assert_eq!(data.rows, [] as [DataTableRow; 0]);
        assert_eq!(data.row_struct, ""); // no RowStruct property
    }

    #[test]
    fn negative_row_count_rejected() {
        let mut bytes = Vec::new();
        object_end(&mut bytes);
        bytes.extend_from_slice(&(-1i32).to_le_bytes());
        let ctx = make_ctx(&["None"]);
        match read_from(&bytes, &ctx, "test.uasset") {
            Err(PaksmithError::AssetParse {
                fault: AssetParseFault::DataTableRowCountNegative { count },
                ..
            }) => assert_eq!(count, -1),
            other => panic!("expected DataTableRowCountNegative, got {other:?}"),
        }
    }

    #[test]
    fn row_count_over_cap_rejected() {
        let mut bytes = Vec::new();
        object_end(&mut bytes);
        let over =
            i32::try_from(MAX_ROWS_PER_DATATABLE + 1).expect("cap+1 fits in i32 for the test");
        bytes.extend_from_slice(&over.to_le_bytes());
        let ctx = make_ctx(&["None"]);
        match read_from(&bytes, &ctx, "test.uasset") {
            Err(PaksmithError::AssetParse {
                fault: AssetParseFault::DataTableRowCountExceeded { count, cap },
                ..
            }) => {
                assert_eq!(count, MAX_ROWS_PER_DATATABLE + 1);
                assert_eq!(cap, MAX_ROWS_PER_DATATABLE);
            }
            other => panic!("expected DataTableRowCountExceeded, got {other:?}"),
        }
    }

    #[test]
    fn row_count_at_cap_passes_cap_check() {
        // Exactly MAX rows must NOT be rejected by the cap (`>`, not
        // `>=`). It proceeds to row reads and fails downstream on the
        // missing body, so the error is anything BUT
        // DataTableRowCountExceeded.
        let mut bytes = Vec::new();
        object_end(&mut bytes);
        let at_cap = i32::try_from(MAX_ROWS_PER_DATATABLE).expect("cap fits in i32");
        bytes.extend_from_slice(&at_cap.to_le_bytes());
        let ctx = make_ctx(&["None"]);
        let err = read_from(&bytes, &ctx, "test.uasset").unwrap_err();
        assert!(
            !matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::DataTableRowCountExceeded { .. },
                    ..
                }
            ),
            "NumRows == cap must pass the cap check, got {err:?}"
        );
    }

    #[test]
    fn reserve_count_clamps_to_payload_capacity() {
        // Honest count below the byte-derived ceiling reserves exactly
        // `num_rows`; a lying count clamps to `total_len / MIN_ROW_BYTES`.
        assert_eq!(reserve_count(2, 320), 2); // 2 <= 320/16=20 → 2
        assert_eq!(reserve_count(100, 320), 20); // 100 > 20 → clamp to 20
        assert_eq!(reserve_count(1_000_000, 0), 0); // no bytes → reserve nothing
    }

    #[test]
    fn truncated_num_rows_is_eof() {
        // Segment 1 present, but the NumRows i32 is short (2 bytes).
        let mut bytes = Vec::new();
        object_end(&mut bytes);
        bytes.extend_from_slice(&[0u8, 0u8]); // only 2 of 4 NumRows bytes
        let ctx = make_ctx(&["None"]);
        match read_from(&bytes, &ctx, "test.uasset") {
            Err(PaksmithError::AssetParse {
                fault:
                    AssetParseFault::UnexpectedEof {
                        field: AssetWireField::DataTableNumRows,
                    },
                ..
            }) => {}
            other => panic!("expected UnexpectedEof(DataTableNumRows), got {other:?}"),
        }
    }

    #[test]
    fn two_rows_with_bodies_parse() {
        // Name table: 0=None, 1=RowAlpha, 2=RowBeta, 3=Damage,
        // 4=IntProperty.
        let ctx = make_ctx(&["None", "RowAlpha", "RowBeta", "Damage", "IntProperty"]);
        let mut bytes = Vec::new();
        object_end(&mut bytes); // segment 1: empty class props
        bytes.extend_from_slice(&2i32.to_le_bytes()); // NumRows = 2
        // Row 1: RowName = RowAlpha, empty body.
        fname(&mut bytes, 1);
        none(&mut bytes);
        // Row 2: RowName = RowBeta, body = { Damage: Int(42) }.
        fname(&mut bytes, 2);
        int_property(&mut bytes, 3, 4, 42);
        none(&mut bytes);

        let data = read_from(&bytes, &ctx, "test.uasset").expect("parse");
        assert_eq!(data.rows.len(), 2);
        assert_eq!(data.rows[0].name, "RowAlpha");
        assert_eq!(data.rows[0].properties, [] as [Property; 0]);
        assert_eq!(data.rows[1].name, "RowBeta");
        assert_eq!(data.rows[1].properties.len(), 1);
        assert_eq!(data.rows[1].properties[0].name(), "Damage");
        assert_eq!(data.rows[1].properties[0].value, PropertyValue::Int(42));
    }

    #[test]
    fn row_names_are_charged_to_the_derived_budget() {
        let limit = ("RowAlpha".len() + "RowBeta".len()) as u64;
        let ctx = with_derived_budget(make_ctx(&["None", "RowAlpha", "RowBeta"]), limit);
        let mut bytes = Vec::new();
        object_end(&mut bytes);
        bytes.extend_from_slice(&2i32.to_le_bytes()); // NumRows = 2
        for row in [1, 2] {
            fname(&mut bytes, row);
            none(&mut bytes);
        }
        assert_eq!(
            read_from(&bytes, &ctx, "test.uasset").unwrap().rows.len(),
            2
        );
        assert_derived_budget_exceeded(read_from(&bytes, &ctx, "test.uasset"), limit);
    }

    #[test]
    fn row_name_out_of_bounds_surfaces_package_index_oob() {
        // NumRows = 1, RowName index = 99 (past the 1-entry name
        // table). The shared FName resolver rejects it — proving the
        // architect's "reuse existing FName errors" decision (no
        // DataTable-specific OOB variant) holds end-to-end.
        let mut bytes = Vec::new();
        object_end(&mut bytes);
        bytes.extend_from_slice(&1i32.to_le_bytes()); // NumRows = 1
        fname(&mut bytes, 99); // RowName index 99 — OOB
        let ctx = make_ctx(&["None"]);
        match read_from(&bytes, &ctx, "test.uasset") {
            Err(PaksmithError::AssetParse {
                fault: AssetParseFault::PackageIndexOob { field, .. },
                ..
            }) => assert_eq!(field, AssetWireField::DataTableRowName),
            other => panic!("expected PackageIndexOob(DataTableRowName), got {other:?}"),
        }
    }

    // `resolve_row_struct` tested directly with hand-built properties
    // (in-crate construction; no import table needed to exercise a
    // non-empty resolved Object name).
    fn prop(name: &str, value: PropertyValue) -> Property {
        Property {
            name: std::sync::Arc::from(name),
            array_index: 0,
            guid: None,
            value,
        }
    }

    fn row_struct_prop(class: &str) -> Property {
        prop(
            "RowStruct",
            PropertyValue::Object {
                kind: crate::asset::PackageIndex::Import(0),
                name: class.into(),
            },
        )
    }

    #[test]
    fn row_struct_resolved_from_object_property() {
        let props = vec![
            prop("Other", PropertyValue::Int(1)),
            row_struct_prop("ItemRow"),
        ];
        let ctx = make_ctx(&["None"]);
        assert_eq!(
            resolve_row_struct(&props, &ctx, "test.uasset").unwrap(),
            "ItemRow"
        );
    }

    #[test]
    fn row_struct_is_charged_to_the_derived_budget() {
        let props = [row_struct_prop("ItemRow")];
        let limit = "ItemRow".len() as u64;
        let ctx = with_derived_budget(make_ctx(&["None"]), limit);
        assert_eq!(
            resolve_row_struct(&props, &ctx, "test.uasset").unwrap(),
            "ItemRow"
        );
        assert_derived_budget_exceeded(resolve_row_struct(&props, &ctx, "test.uasset"), limit);
    }

    /// Arms the `DataTableRows` OOM seam and confirms the row-vec
    /// reservation surfaces `AllocationFailed { DataTableRows }` —
    /// pins the seam wiring + `AssetSeam::DataTableRows.context()` arm.
    #[cfg(feature = "__test_utils")]
    #[test]
    fn row_reservation_surfaces_allocation_failed_under_oom() {
        let mut bytes = Vec::new();
        object_end(&mut bytes);
        bytes.extend_from_slice(&1i32.to_le_bytes()); // NumRows = 1
        let ctx = make_ctx(&["None"]);
        let _guard = crate::testing::oom::arm_at(
            crate::seams::SeamSite::Asset(crate::seams::AssetSeam::DataTableRows),
            0,
        );
        match read_from(&bytes, &ctx, "test.uasset") {
            Err(PaksmithError::AssetParse {
                fault: AssetParseFault::AllocationFailed { context, .. },
                ..
            }) => assert_eq!(context, crate::error::AssetAllocationContext::DataTableRows),
            other => panic!("expected AllocationFailed(DataTableRows), got {other:?}"),
        }
    }

    /// Both fallbacks draw on the package's decode-time warning budget:
    /// with it spent, they still resolve to "" but log nothing.
    #[tracing_test::traced_test]
    #[test]
    fn row_struct_warnings_respect_a_spent_budget() {
        use crate::asset::property::test_utils::with_decode_warnings_spent;
        use crate::untrusted::test_support::lines_counted;

        let absent = [prop("Other", PropertyValue::Int(1))];
        let non_object = [prop("RowStruct", PropertyValue::Int(7))];
        let fresh = make_ctx(&["None"]);
        let spent = with_decode_warnings_spent(make_ctx(&["None"]));
        for ctx in [&fresh, &spent] {
            assert_eq!(resolve_row_struct(&absent, ctx, "t").unwrap(), "");
            assert_eq!(resolve_row_struct(&non_object, ctx, "t").unwrap(), "");
            // The fresh pass logs one of each; the spent pass adds none.
            logs_assert(lines_counted("has no RowStruct property", 1));
            logs_assert(lines_counted("is not an ObjectProperty", 1));
        }
    }
}
