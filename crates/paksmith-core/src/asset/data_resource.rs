//! UE 5.2+ `FObjectDataResource` table parsing (#642).
//!
//! At the summary's `DataResourceOffset` (present when
//! `FileVersionUE5 >= DATA_RESOURCES (1009)` and `> 0`), UE serializes:
//!
//! ```text
//! version: u32   (EObjectDataResourceVersion; valid = 1..=2)
//! count:   i32
//! count × FObjectDataResource:
//!   flags:                   u32  (EObjectDataResourceFlags)
//!   cooked_index:            u8   (only when version >= 2, AddedCookedIndex)
//!   serial_offset:           i64
//!   duplicate_serial_offset: i64  (-1 = no duplicate copy)
//!   serial_size:             i64  (on-disk byte count)
//!   raw_size:                i64  (uncompressed byte count)
//!   outer_index:             i32  (FPackageIndex of the owning export)
//!   legacy_bulk_data_flags:  u32  (verbatim classic EBulkDataFlags)
//! ```
//!
//! Entry stride: 44 bytes (version 1) / 45 bytes (version 2). Verified
//! against CUE4Parse `Package.cs` (`SeekAbsolute(DataResourceOffset)` →
//! `Read<uint>()` version → `ReadArray(...)`) and
//! `FObjectDataResource.cs` (field order + the `AddedCookedIndex` gate).
//!
//! When the table is non-empty, every `FByteBulkData` field in the
//! package's export data serializes as a **single `i32` index** into
//! this table instead of the classic inline header — see
//! `FByteBulkData::read_from_ctx` (crate-private). The entry
//! translates to the classic bulk model as: `flags =
//! legacy_bulk_data_flags` (the classic bit meanings, verbatim),
//! `element_count = raw_size`, `size_on_disk = serial_size`,
//! `offset_in_file = serial_offset` with **no** `BulkDataStartOffset`
//! fix-up (CUE4Parse applies none on this path).

use crate::error::{AssetParseFault, AssetWireField, BoundsUnit, PaksmithError};

/// `EObjectDataResourceVersion::Latest` (= `AddedCookedIndex`).
/// Versions outside `(Invalid = 0, Latest = 2]` mean "no table" and
/// fall through to the classic inline parse, matching CUE4Parse's
/// `> Invalid && <= Latest` gate.
const LATEST_DATA_RESOURCE_VERSION: u32 = 2;

/// Wire size of one entry, version-dependent (the `cooked_index` u8
/// exists only at version >= 2).
fn entry_wire_size(version: u32) -> usize {
    // flags u32 + serial/duplicate/size/raw i64×4 + outer i32 + legacy u32
    let base = 4 + 8 * 4 + 4 + 4;
    if version >= 2 { base + 1 } else { base }
}

/// One `FObjectDataResource` entry — the bulk-data metadata a UE 5.2+
/// package stores per data resource instead of inline bulk headers.
///
/// Fields are stored wire-raw; the translation to the classic
/// `FByteBulkData` shape happens in the crate-private
/// `FByteBulkData::read_from_ctx`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FObjectDataResource {
    /// `EObjectDataResourceFlags` (Inline/Streaming/Optional/Duplicate/
    /// MemoryMapped/DerivedDataReference). Stored for fidelity; payload
    /// resolution is driven by `legacy_bulk_data_flags` alone (CUE4Parse
    /// never consults this word on its read path).
    pub flags: u32,
    /// Numbered-sidecar selector (version >= 2 only; `0` at version 1).
    /// Non-zero selects `.NNN.ubulk`-style numbered payload files —
    /// currently fail-closed at the bulk-read site (no numbered
    /// companion loaders).
    pub cooked_index: u8,
    /// Absolute payload offset within the file the legacy flags select.
    /// NOT subject to the `BulkDataStartOffset` fix-up.
    pub serial_offset: i64,
    /// Offset of the non-optional duplicate copy; `-1` = none. Ignored
    /// for resolution (CUE4Parse parity).
    pub duplicate_serial_offset: i64,
    /// On-disk (possibly compressed) byte count.
    pub serial_size: i64,
    /// Uncompressed byte count.
    pub raw_size: i64,
    /// `FPackageIndex` of the owning export, stored wire-raw. Not used
    /// for payload resolution.
    pub outer_index: i32,
    /// The classic `EBulkDataFlags` word, verbatim — drives tier
    /// dispatch exactly as an inline header's flags would.
    pub legacy_bulk_data_flags: u32,
}

/// Parse the data-resource table at `offset` within `bytes` (the
/// stitched package buffer).
///
/// Returns an **empty vec** — "no table, classic inline bulk headers" —
/// for a non-positive offset, an unrecognized table version (0 or
/// `> 2`, matching CUE4Parse's silent skip), or `count == 0`. A
/// populated table parses fully; structural violations are errors:
///
/// # Errors
///
/// - [`AssetParseFault::UnexpectedEof`] — offset/header/entries past the
///   end of `bytes`.
/// - [`AssetParseFault::NegativeValue`] — negative entry count.
/// - [`AssetParseFault::BoundsExceeded`] — count × entry size exceeds
///   the bytes actually present (a lying count cannot force
///   proportional allocation; the reserve happens after this check).
pub(crate) fn parse_data_resource_table(
    bytes: &[u8],
    offset: i32,
    asset_path: &str,
) -> crate::Result<Vec<FObjectDataResource>> {
    let eof = || PaksmithError::AssetParse {
        asset_path: asset_path.to_string(),
        fault: AssetParseFault::UnexpectedEof {
            field: AssetWireField::DataResourceTable,
        },
    };

    // Non-positive offset = "no table", NOT a fault: CUE4Parse's gate is
    // exactly `Summary.DataResourceOffset > 0`, and the engine writes
    // INDEX_NONE (-1) for the absent case — failing closed on negative
    // would reject legitimate packages. Pinned by
    // `empty_and_absent_tables_yield_empty` (offsets 0 and -1).
    let Ok(offset) = usize::try_from(offset) else {
        return Ok(Vec::new());
    };
    if offset == 0 {
        return Ok(Vec::new());
    }
    let header = bytes
        .get(offset..offset.checked_add(8).ok_or_else(eof)?)
        .ok_or_else(eof)?;
    let version = u32::from_le_bytes(header[0..4].try_into().expect("4-byte slice"));
    if version == 0 || version > LATEST_DATA_RESOURCE_VERSION {
        // Unrecognized table version: fall through to classic parsing,
        // matching CUE4Parse's `<= Latest` gate. A future populated
        // format would surface as a bulk-read desync fault downstream,
        // not silence — the classic header read fails loud.
        return Ok(Vec::new());
    }
    let count_i32 = i32::from_le_bytes(header[4..8].try_into().expect("4-byte slice"));
    if count_i32 < 0 {
        return Err(PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::NegativeValue {
                field: AssetWireField::DataResourceCount,
                value: i64::from(count_i32),
            },
        });
    }
    #[allow(clippy::cast_sign_loss, reason = "sign-checked non-negative above")]
    let count = count_i32 as u32 as usize;
    if count == 0 {
        return Ok(Vec::new());
    }

    let entry_size = entry_wire_size(version);
    let entries_start = offset + 8;
    let remaining = bytes.len().saturating_sub(entries_start);
    let needed = count.checked_mul(entry_size).ok_or_else(eof)?;
    if needed > remaining {
        return Err(PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::BoundsExceeded {
                // The bounded quantity is the TABLE's byte extent
                // (count × entry size vs bytes remaining), so blame the
                // table field — the count itself was already validated.
                field: AssetWireField::DataResourceTable,
                value: needed as u64,
                limit: remaining as u64,
                unit: BoundsUnit::Bytes,
            },
        });
    }

    let mut entries = Vec::with_capacity(count);
    let mut pos = entries_start;
    let word_at =
        |p: usize| -> u32 { u32::from_le_bytes(bytes[p..p + 4].try_into().expect("in-bounds")) };
    let quad_at =
        |p: usize| -> i64 { i64::from_le_bytes(bytes[p..p + 8].try_into().expect("in-bounds")) };
    for _ in 0..count {
        // In-bounds: `needed <= remaining` was checked above, and `pos`
        // advances by exactly `entry_size` per iteration.
        let flags = word_at(pos);
        let mut p = pos + 4;
        let cooked_index = if version >= 2 {
            let b = bytes[p];
            p += 1;
            b
        } else {
            0
        };
        let serial_offset = quad_at(p);
        let duplicate_serial_offset = quad_at(p + 8);
        let serial_size = quad_at(p + 16);
        let raw_size = quad_at(p + 24);
        let outer_index = i32::from_le_bytes(bytes[p + 32..p + 36].try_into().expect("in-bounds"));
        let legacy_bulk_data_flags = word_at(p + 36);
        entries.push(FObjectDataResource {
            flags,
            cooked_index,
            serial_offset,
            duplicate_serial_offset,
            serial_size,
            raw_size,
            outer_index,
            legacy_bulk_data_flags,
        });
        pos += entry_size;
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialize a table at offset 4 (with a 4-byte lead-in) and return
    /// the full buffer.
    fn table_bytes(version: u32, entries: &[FObjectDataResource]) -> Vec<u8> {
        let mut b = vec![0u8; 4]; // lead-in so offset != 0
        b.extend_from_slice(&version.to_le_bytes());
        b.extend_from_slice(&i32::try_from(entries.len()).unwrap().to_le_bytes());
        for e in entries {
            b.extend_from_slice(&e.flags.to_le_bytes());
            if version >= 2 {
                b.push(e.cooked_index);
            }
            b.extend_from_slice(&e.serial_offset.to_le_bytes());
            b.extend_from_slice(&e.duplicate_serial_offset.to_le_bytes());
            b.extend_from_slice(&e.serial_size.to_le_bytes());
            b.extend_from_slice(&e.raw_size.to_le_bytes());
            b.extend_from_slice(&e.outer_index.to_le_bytes());
            b.extend_from_slice(&e.legacy_bulk_data_flags.to_le_bytes());
        }
        b
    }

    fn sample_entry() -> FObjectDataResource {
        FObjectDataResource {
            flags: 0x2, // Streaming
            cooked_index: 0,
            serial_offset: 0x100,
            duplicate_serial_offset: -1,
            serial_size: 64,
            raw_size: 64,
            outer_index: 1,
            legacy_bulk_data_flags: 0x0100, // PayloadInSeperateFile
        }
    }

    /// Version 1 (Initial): 44-byte entries, no cooked_index. #642.
    #[test]
    fn parses_version_1_table() {
        let entries = vec![sample_entry(), {
            let mut e = sample_entry();
            e.serial_offset = 0x200;
            e.legacy_bulk_data_flags = 0x0001; // PayloadAtEndOfFile
            e
        }];
        let bytes = table_bytes(1, &entries);
        let parsed = parse_data_resource_table(&bytes, 4, "t").unwrap();
        assert_eq!(parsed, entries);
    }

    /// Version 2 (AddedCookedIndex): 45-byte entries with the u8. Two
    /// entries so the 45-byte stride itself is pinned — a wrong stride
    /// (44/43) parses entry 1 fine (field offsets are explicit) but
    /// misaligns every field of entry 2. #642.
    #[test]
    fn parses_version_2_table_with_cooked_index() {
        let mut e = sample_entry();
        e.cooked_index = 3;
        let entries = vec![e, {
            let mut e2 = sample_entry();
            e2.cooked_index = 7;
            e2.serial_offset = 0x0123_4567_89AB;
            e2.serial_size = 0x51;
            e2.raw_size = 0x52;
            e2.outer_index = 9;
            e2.legacy_bulk_data_flags = 0x0001;
            e2
        }];
        let bytes = table_bytes(2, &entries);
        let parsed = parse_data_resource_table(&bytes, 4, "t").unwrap();
        assert_eq!(parsed, entries);
    }

    /// Unrecognized versions (0 = Invalid, > 2 = future) mean "no
    /// table" — classic parsing continues, matching CUE4Parse. #642.
    #[test]
    fn unrecognized_versions_yield_empty() {
        for v in [0u32, 3, u32::MAX] {
            let bytes = table_bytes(v, &[sample_entry()]);
            assert!(
                parse_data_resource_table(&bytes, 4, "t")
                    .unwrap()
                    .is_empty(),
                "version {v} must be treated as no-table"
            );
        }
    }

    /// Non-positive offsets and count == 0 yield empty. #642.
    #[test]
    fn empty_and_absent_tables_yield_empty() {
        let bytes = table_bytes(1, &[]);
        assert!(
            parse_data_resource_table(&bytes, 4, "t")
                .unwrap()
                .is_empty()
        );
        assert!(
            parse_data_resource_table(&bytes, 0, "t")
                .unwrap()
                .is_empty()
        );
        assert!(
            parse_data_resource_table(&bytes, -1, "t")
                .unwrap()
                .is_empty()
        );
    }

    /// A negative count is a structural fault, not an empty table. #642.
    #[test]
    fn negative_count_rejected() {
        let mut bytes = vec![0u8; 4];
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&(-5i32).to_le_bytes());
        let err = parse_data_resource_table(&bytes, 4, "t").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::NegativeValue { .. },
                ..
            }
        ));
    }

    /// A count claiming more entries than the bytes present fails
    /// BEFORE any allocation proportional to the claim. #642.
    #[test]
    fn lying_count_rejected_before_alloc() {
        let mut bytes = vec![0u8; 4];
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&i32::MAX.to_le_bytes());
        let err = parse_data_resource_table(&bytes, 4, "t").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::BoundsExceeded {
                    field: AssetWireField::DataResourceTable,
                    unit: BoundsUnit::Bytes,
                    ..
                },
                ..
            }
        ));
    }

    /// A truncated header (offset near EOF) is a fault. #642.
    #[test]
    fn truncated_header_rejected() {
        let bytes = vec![0u8; 8]; // offset 4 leaves only 4 bytes
        let err = parse_data_resource_table(&bytes, 4, "t").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::UnexpectedEof { .. },
                ..
            }
        ));
    }
}
