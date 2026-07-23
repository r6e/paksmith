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
use crate::asset::{Asset, AssetContext, DataTableData, DataTableRow};
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
    let row_struct = resolve_row_struct(&class_props, asset_path);
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
            name: name.to_string(),
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
/// Returns an empty string (and warn-logs) when the `RowStruct`
/// property is absent or isn't an `ObjectProperty` — rows still parse;
/// they just carry no schema-type label, per the format doc's
/// graceful-recovery clause.
fn resolve_row_struct(class_props: &[Property], asset_path: &str) -> String {
    match class_props
        .iter()
        .find(|p| p.name() == "RowStruct")
        .map(|p| &p.value)
    {
        Some(PropertyValue::Object { name, .. }) => name.clone(),
        Some(_) => {
            tracing::warn!(
                asset = asset_path,
                "DataTable RowStruct property is not an ObjectProperty; \
                 emitting empty row_struct (rows still parse)"
            );
            String::new()
        }
        None => {
            tracing::warn!(
                asset = asset_path,
                "DataTable has no RowStruct property; emitting empty \
                 row_struct (rows still parse)"
            );
            String::new()
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
    use crate::asset::property::test_utils::make_ctx;

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
        assert!(data.rows.is_empty());
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
        assert!(data.rows[0].properties.is_empty());
        assert_eq!(data.rows[1].name, "RowBeta");
        assert_eq!(data.rows[1].properties.len(), 1);
        assert_eq!(data.rows[1].properties[0].name(), "Damage");
        assert_eq!(data.rows[1].properties[0].value, PropertyValue::Int(42));
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

    #[test]
    fn row_struct_resolved_from_object_property() {
        let props = vec![
            prop("Other", PropertyValue::Int(1)),
            prop(
                "RowStruct",
                PropertyValue::Object {
                    kind: crate::asset::PackageIndex::Import(0),
                    name: "ItemRow".to_string(),
                },
            ),
        ];
        assert_eq!(resolve_row_struct(&props, "test.uasset"), "ItemRow");
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

    #[test]
    fn row_struct_empty_when_absent_or_non_object() {
        // Absent → "".
        assert_eq!(
            resolve_row_struct(&[prop("Other", PropertyValue::Int(1))], "test.uasset"),
            ""
        );
        // Present but not an ObjectProperty → "" (warn-logged).
        assert_eq!(
            resolve_row_struct(&[prop("RowStruct", PropertyValue::Int(7))], "test.uasset"),
            ""
        );
    }
}
