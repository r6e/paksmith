//! FName pool — the string table referenced by import/export entries.
//!
//! Phase 2a layout (UE 4.21+, `FileVersionUE4 ≥ 504`):
//! ```text
//! per entry:
//!   FString  name        // base name string (no `_NN` suffix)
//!   u16      hash_no_case
//!   u16      hash_case
//! ```
//!
//! The two CityHash16 trailers are read and discarded — paksmith
//! doesn't need them (linear scan suffices for header-time parsing),
//! and FModel doesn't surface them either.

#[cfg(any(test, feature = "__test_utils"))]
use std::io::Write;
use std::io::{Read, Seek, SeekFrom};
use std::sync::Arc;

#[cfg(any(test, feature = "__test_utils"))]
use byteorder::WriteBytesExt;
use byteorder::{LittleEndian, ReadBytesExt};
use serde::Serialize;

use crate::asset::read_asset_fstring;
use crate::error::{
    AssetAllocationContext, AssetParseFault, AssetWireField, BoundsUnit, PaksmithError,
};

/// Hard cap on the wire-claimed name count.
const MAX_NAME_TABLE_ENTRIES: u32 = 1_048_576;

/// One name in the table. Wraps an `Arc<str>` so refs are cheap to
/// clone — `FName::clone()` is one atomic refcount bump.
///
/// UE encodes a "name reference" as `(name_table_index, number)`, but
/// the `number` lives at each *use* site (import/export records),
/// not in the table itself. The table only owns the base strings.
///
/// `Serialize` is hand-rolled (delegating to `&str`) rather than
/// derived because serde's `Arc<str>` impl is gated behind the `rc`
/// feature, which would expand the workspace serde footprint for one
/// type. The wire-equivalent output is identical to
/// `#[serde(transparent)]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FName(Arc<str>);

impl Serialize for FName {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl FName {
    /// Construct from a `&str`.
    #[must_use]
    pub fn new(s: &str) -> Self {
        Self(Arc::from(s))
    }

    /// Borrow the underlying name string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for FName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// FName pool.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct NameTable {
    /// Names in wire order — index `i` matches UE's name-index `i`.
    pub names: Vec<FName>,
}

impl NameTable {
    /// Look up a name by index. Returns `None` if the index is out of
    /// bounds; callers convert this to
    /// [`AssetParseFault::PackageIndexOob`].
    #[must_use]
    pub fn get(&self, index: u32) -> Option<&FName> {
        self.names.get(index as usize)
    }

    /// Look up a name by index, returning a typed error if OOB.
    ///
    /// # Errors
    /// [`PaksmithError::AssetParse`] with
    /// [`AssetParseFault::PackageIndexOob`] (using
    /// [`AssetWireField::NameIndex`] as the field tag).
    pub fn lookup(&self, index: u32, asset_path: &str) -> crate::Result<FName> {
        self.names
            .get(index as usize)
            .cloned()
            .ok_or_else(|| PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::PackageIndexOob {
                    field: AssetWireField::NameIndex,
                    index,
                    table_size: self.names.len() as u32,
                },
            })
    }

    /// Read the table by seeking `reader` to `offset` and decoding
    /// `count` records.
    ///
    /// # Errors
    /// - [`AssetParseFault::NegativeValue`] if `offset < 0` or `count < 0`.
    /// - [`AssetParseFault::BoundsExceeded`] if `count > MAX_NAME_TABLE_ENTRIES`.
    /// - [`AssetParseFault::AllocationFailed`] on reservation failure.
    /// - [`AssetParseFault::FStringMalformed`] if any name FString is malformed.
    /// - [`PaksmithError::Io`] on seek/read failures.
    pub fn read_from<R: Read + Seek>(
        reader: &mut R,
        offset: i64,
        count: i32,
        asset_path: &str,
    ) -> crate::Result<Self> {
        if offset < 0 {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::NegativeValue {
                    field: AssetWireField::NameOffset,
                    value: offset,
                },
            });
        }
        if count < 0 {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::NegativeValue {
                    field: AssetWireField::NameCount,
                    value: i64::from(count),
                },
            });
        }
        let count_u32 = count as u32;
        if u64::from(count_u32) > u64::from(MAX_NAME_TABLE_ENTRIES) {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::BoundsExceeded {
                    field: AssetWireField::NameCount,
                    value: u64::from(count_u32),
                    limit: u64::from(MAX_NAME_TABLE_ENTRIES),
                    unit: BoundsUnit::Items,
                },
            });
        }

        let _ = reader.seek(SeekFrom::Start(offset as u64))?;
        let mut names: Vec<FName> = Vec::new();
        names
            .try_reserve_exact(count_u32 as usize)
            .map_err(|source| PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::AllocationFailed {
                    context: AssetAllocationContext::NameTable,
                    requested: count_u32 as usize,
                    unit: BoundsUnit::Items,
                    source,
                },
            })?;
        for _ in 0..count_u32 {
            let s = read_asset_fstring(reader, asset_path)?;
            // Discard the dual CityHash16 trailers; paksmith doesn't
            // use them.
            let _hash_no_case = reader.read_u16::<LittleEndian>()?;
            let _hash_case = reader.read_u16::<LittleEndian>()?;
            names.push(FName(Arc::from(s)));
        }
        Ok(Self { names })
    }

    /// Write the table (no header — caller is responsible for any
    /// surrounding count/offset). Each record: `FString` + two
    /// zero-filled u16 hash slots. Test- and fixture-gen-only via the
    /// `__test_utils` feature; release builds drop this method.
    ///
    /// # Errors
    /// Returns [`std::io::Error`] if writes fail or if any name length
    /// exceeds `i32::MAX`.
    #[cfg(any(test, feature = "__test_utils"))]
    pub fn write_to<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        for name in &self.names {
            let bytes_with_null = name.0.len() + 1;
            let len_i32 = i32::try_from(bytes_with_null)
                .map_err(|_| std::io::Error::other("FName length exceeds i32::MAX"))?;
            writer.write_i32::<LittleEndian>(len_i32)?;
            writer.write_all(name.0.as_bytes())?;
            writer.write_u8(0)?;
            writer.write_u16::<LittleEndian>(0)?; // hash_no_case
            writer.write_u16::<LittleEndian>(0)?; // hash_case
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn make_table(names: &[&str]) -> NameTable {
        NameTable {
            names: names.iter().map(|n| FName::new(n)).collect(),
        }
    }

    #[test]
    fn round_trip_three_names() {
        let table = make_table(&["Engine", "Default__Object", "Root"]);
        let mut buf = Vec::new();
        table.write_to(&mut buf).unwrap();
        let mut cursor = Cursor::new(buf);
        let parsed = NameTable::read_from(&mut cursor, 0, 3, "x.uasset").unwrap();
        assert_eq!(parsed, table);
    }

    #[test]
    fn empty_table_round_trip() {
        let table = NameTable::default();
        let mut buf = Vec::new();
        table.write_to(&mut buf).unwrap();
        assert!(buf.is_empty());
        let mut cursor = Cursor::new(&buf[..]);
        let parsed = NameTable::read_from(&mut cursor, 0, 0, "x.uasset").unwrap();
        assert_eq!(parsed, table);
    }

    #[test]
    fn lookup_in_range() {
        let table = make_table(&["A", "B", "C"]);
        assert_eq!(table.lookup(0, "x.uasset").unwrap(), FName::new("A"));
        assert_eq!(table.lookup(1, "x.uasset").unwrap(), FName::new("B"));
        assert_eq!(table.lookup(2, "x.uasset").unwrap(), FName::new("C"));
    }

    #[test]
    fn lookup_oob() {
        let table = make_table(&["A", "B"]);
        let err = table.lookup(5, "x.uasset").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::PackageIndexOob {
                    field: AssetWireField::NameIndex,
                    index: 5,
                    table_size: 2,
                },
                ..
            }
        ));
    }

    #[test]
    fn rejects_negative_offset() {
        let mut buf = Vec::<u8>::new();
        let mut cursor = Cursor::new(&mut buf);
        let err = NameTable::read_from(&mut cursor, -1, 0, "x.uasset").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::NegativeValue {
                    field: AssetWireField::NameOffset,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn rejects_negative_count() {
        let mut buf = Vec::<u8>::new();
        let mut cursor = Cursor::new(&mut buf);
        let err = NameTable::read_from(&mut cursor, 0, -1, "x.uasset").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::NegativeValue {
                    field: AssetWireField::NameCount,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn rejects_count_over_cap() {
        let mut buf = Vec::<u8>::new();
        let mut cursor = Cursor::new(&mut buf);
        let err = NameTable::read_from(
            &mut cursor,
            0,
            MAX_NAME_TABLE_ENTRIES as i32 + 1,
            "x.uasset",
        )
        .unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::BoundsExceeded {
                    field: AssetWireField::NameCount,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn fname_display() {
        let n = FName::new("RootComponent");
        assert_eq!(format!("{n}"), "RootComponent");
    }

    #[test]
    fn fname_serializes_as_bare_string() {
        // Pin the JSON shape — manual impl Serialize delegates to
        // serialize_str. Matches the plan's Task 14 deliverable:
        // "names": ["Engine", ...] — each FName is a bare string.
        let n = FName::new("Engine");
        assert_eq!(serde_json::to_string(&n).unwrap(), r#""Engine""#);
    }

    #[test]
    fn name_table_serializes_as_bare_array() {
        // Pin the #[serde(transparent)] container shape — NameTable
        // serializes as just its inner Vec<FName> (a JSON array), not
        // {"names": [...]}.
        let t = make_table(&["Engine", "None"]);
        assert_eq!(serde_json::to_string(&t).unwrap(), r#"["Engine","None"]"#);
    }
}
