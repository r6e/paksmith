//! `FObjectImport` table.
//!
//! Wire shape per record (UE 4.21+ baseline, UE5 trailer):
//! ```text
//! FName  class_package        // 2 × u32 (name_index + number)
//! FName  class_name           // 2 × u32
//! i32    outer_index          // PackageIndex
//! FName  object_name          // 2 × u32
//! i32    import_optional      // bool32; only if UE5 ≥ VER_UE5_OPTIONAL_RESOURCES (1003)
//! ```
//!
//! Wire format verified against CUE4Parse's `FObjectImport.cs`.
//! Cross-validation via the unreal_asset oracle is deferred to Task 12
//! (fixture-gen), which adds unreal_asset as a fixture-gen dev-dep.
//! An earlier draft used a `u8` for `import_optional` — that
//! mis-advances the cursor by 3 bytes.

#[cfg(any(test, feature = "__test_utils"))]
use std::io::Write;
use std::io::{Read, Seek, SeekFrom};

#[cfg(any(test, feature = "__test_utils"))]
use byteorder::WriteBytesExt;
use byteorder::{LittleEndian, ReadBytesExt};
use serde::Serialize;

use crate::asset::package_index::PackageIndex;
use crate::asset::read_package_index;
use crate::asset::version::{AssetVersion, VER_UE5_OPTIONAL_RESOURCES};
use crate::error::{
    AssetAllocationContext, AssetParseFault, AssetWireField, BoundsUnit, PaksmithError,
};

/// Hard cap on the wire-claimed import count.
const MAX_IMPORT_TABLE_ENTRIES: u32 = 524_288;

/// One row in the import table. Phase 2a stores the raw name indexes
/// (not yet resolved against a NameTable); resolution happens at JSON
/// rendering time so a malformed name reference fails the inspect
/// command rather than the parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ObjectImport {
    /// Name-table index of the import's class package
    /// (e.g. `/Script/CoreUObject`).
    pub class_package_name: u32,
    /// Disambiguator suffix for `class_package_name`. Zero for unique
    /// names; non-zero values render as `Name_<number-1>` in UE.
    pub class_package_number: u32,
    /// Name-table index of the class (e.g. `Package`, `Object`).
    pub class_name: u32,
    /// Disambiguator for `class_name`.
    pub class_name_number: u32,
    /// Reference to the owning outer object (typically `Null` for
    /// top-level imports).
    pub outer_index: PackageIndex,
    /// Name-table index of the import's object name.
    pub object_name: u32,
    /// Disambiguator for `object_name`.
    pub object_name_number: u32,
    /// `bImportOptional` — read as `i32` bool32 (4 bytes); `None` when
    /// `FileVersionUE5 < OPTIONAL_RESOURCES (1003)`.
    pub import_optional: Option<bool>,
}

impl ObjectImport {
    /// Read one record. Records are version-dependent; pass the
    /// resolved [`AssetVersion`] from the package summary.
    ///
    /// # Preconditions
    ///
    /// Assumes the asset was cooked (package summary has
    /// `PKG_FilterEditorOnly` set). Uncooked editor assets at
    /// `file_version_ue4 ≥ VER_UE4_NON_OUTER_PACKAGE_IMPORT` carry an
    /// additional `FName PackageName` field per record (8 wire bytes)
    /// per CUE4Parse's `FObjectImport.cs` gate `Ar.Ver >=
    /// NON_OUTER_PACKAGE_IMPORT && !Ar.IsFilterEditorOnly`. This reader
    /// does NOT consume that field and will silently mis-align all
    /// subsequent bytes on uncooked input.
    ///
    /// Task 9 (`PackageSummary`) is expected to enforce this
    /// precondition at the summary boundary by rejecting uncooked
    /// assets — paksmith targets pak-extracted (cooked) assets per
    /// the Phase 2a scope statement.
    ///
    /// # Errors
    /// - [`AssetParseFault::PackageIndexUnderflow`] if `outer_index`
    ///   is `i32::MIN` (no representable positive counterpart).
    /// - [`PaksmithError::Io`] on EOF or other I/O failures.
    pub fn read_from<R: Read>(
        reader: &mut R,
        version: AssetVersion,
        asset_path: &str,
    ) -> crate::Result<Self> {
        let class_package_name = reader.read_u32::<LittleEndian>()?;
        let class_package_number = reader.read_u32::<LittleEndian>()?;
        let class_name = reader.read_u32::<LittleEndian>()?;
        let class_name_number = reader.read_u32::<LittleEndian>()?;
        let outer_index = read_package_index(reader, asset_path, AssetWireField::ImportOuterIndex)?;
        let object_name = reader.read_u32::<LittleEndian>()?;
        let object_name_number = reader.read_u32::<LittleEndian>()?;

        // UE writes bImportOptional as a 4-byte bool32 (i32), not a single
        // byte. Verified against CUE4Parse's FObjectImport.cs reader. An
        // earlier draft of this plan read a `u8`, mis-advancing the cursor
        // by 3 bytes. Cross-validation via the unreal_asset oracle is
        // deferred to Task 12 (fixture-gen).
        let import_optional = if version.ue5_at_least(VER_UE5_OPTIONAL_RESOURCES) {
            Some(reader.read_i32::<LittleEndian>()? != 0)
        } else {
            None
        };

        Ok(Self {
            class_package_name,
            class_package_number,
            class_name,
            class_name_number,
            outer_index,
            object_name,
            object_name_number,
            import_optional,
        })
    }

    /// Write one record. Test- and fixture-gen-only via the
    /// `__test_utils` feature; release builds drop this method.
    /// Matches `read_from` field order, including the UE5-gated
    /// `import_optional` tail.
    ///
    /// # Errors
    /// Returns [`std::io::Error`] if writes fail.
    #[cfg(any(test, feature = "__test_utils"))]
    pub fn write_to<W: Write>(&self, writer: &mut W, version: AssetVersion) -> std::io::Result<()> {
        writer.write_u32::<LittleEndian>(self.class_package_name)?;
        writer.write_u32::<LittleEndian>(self.class_package_number)?;
        writer.write_u32::<LittleEndian>(self.class_name)?;
        writer.write_u32::<LittleEndian>(self.class_name_number)?;
        writer.write_i32::<LittleEndian>(self.outer_index.to_raw())?;
        writer.write_u32::<LittleEndian>(self.object_name)?;
        writer.write_u32::<LittleEndian>(self.object_name_number)?;
        if version.ue5_at_least(VER_UE5_OPTIONAL_RESOURCES) {
            writer.write_i32::<LittleEndian>(i32::from(self.import_optional.unwrap_or(false)))?;
        }
        Ok(())
    }
}

/// `TArray<FObjectImport>` from the summary's `ImportOffset/Count`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ImportTable {
    /// Imports in wire order.
    pub imports: Vec<ObjectImport>,
}

impl ImportTable {
    /// Look up by 0-based index.
    #[must_use]
    pub fn get(&self, index: u32) -> Option<&ObjectImport> {
        self.imports.get(index as usize)
    }

    /// Read the table by seeking to `offset` and decoding `count` records.
    ///
    /// # Errors
    /// - [`AssetParseFault::NegativeValue`] if `offset < 0` or `count < 0`.
    /// - [`AssetParseFault::BoundsExceeded`] if `count > MAX_IMPORT_TABLE_ENTRIES`.
    /// - [`AssetParseFault::AllocationFailed`] on reservation failure.
    /// - [`AssetParseFault::PackageIndexUnderflow`] if any import has
    ///   `outer_index == i32::MIN`.
    /// - [`PaksmithError::Io`] on seek/read failures.
    pub fn read_from<R: Read + Seek>(
        reader: &mut R,
        offset: i64,
        count: i32,
        version: AssetVersion,
        asset_path: &str,
    ) -> crate::Result<Self> {
        if offset < 0 {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::NegativeValue {
                    field: AssetWireField::ImportOffset,
                    value: offset,
                },
            });
        }
        if count < 0 {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::NegativeValue {
                    field: AssetWireField::ImportCount,
                    value: i64::from(count),
                },
            });
        }
        let count_u32 = count as u32;
        if u64::from(count_u32) > u64::from(MAX_IMPORT_TABLE_ENTRIES) {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::BoundsExceeded {
                    field: AssetWireField::ImportCount,
                    value: u64::from(count_u32),
                    limit: u64::from(MAX_IMPORT_TABLE_ENTRIES),
                    unit: BoundsUnit::Items,
                },
            });
        }
        // expression-statement; seek's u64 return is discarded
        let _ = reader.seek(SeekFrom::Start(offset as u64))?;
        let mut imports: Vec<ObjectImport> = Vec::new();
        imports
            .try_reserve_exact(count_u32 as usize)
            .map_err(|source| PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::AllocationFailed {
                    context: AssetAllocationContext::ImportTable,
                    requested: count_u32 as usize,
                    unit: BoundsUnit::Items,
                    source,
                },
            })?;
        for _ in 0..count_u32 {
            imports.push(ObjectImport::read_from(reader, version, asset_path)?);
        }
        Ok(Self { imports })
    }

    /// Write the table. Test- and fixture-gen-only via the
    /// `__test_utils` feature; release builds drop this method.
    ///
    /// # Errors
    /// Returns [`std::io::Error`] if writes fail.
    #[cfg(any(test, feature = "__test_utils"))]
    pub fn write_to<W: Write>(&self, writer: &mut W, version: AssetVersion) -> std::io::Result<()> {
        for i in &self.imports {
            i.write_to(writer, version)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn ue4_27() -> AssetVersion {
        AssetVersion {
            legacy_file_version: -7,
            file_version_ue4: 522,
            file_version_ue5: None,
            file_version_licensee_ue4: 0,
        }
    }

    fn ue5_1() -> AssetVersion {
        AssetVersion {
            legacy_file_version: -8,
            file_version_ue4: 522,
            file_version_ue5: Some(1009),
            file_version_licensee_ue4: 0,
        }
    }

    fn sample_import_ue4() -> ObjectImport {
        ObjectImport {
            class_package_name: 1,
            class_package_number: 0,
            class_name: 2,
            class_name_number: 0,
            outer_index: PackageIndex::Null,
            object_name: 3,
            object_name_number: 0,
            import_optional: None,
        }
    }

    fn sample_import_ue5() -> ObjectImport {
        ObjectImport {
            class_package_name: 1,
            class_package_number: 0,
            class_name: 2,
            class_name_number: 0,
            outer_index: PackageIndex::Null,
            object_name: 3,
            object_name_number: 0,
            import_optional: Some(false),
        }
    }

    #[test]
    fn ue4_27_round_trip() {
        let v = ue4_27();
        let original = sample_import_ue4();
        let mut buf = Vec::new();
        original.write_to(&mut buf, v).unwrap();
        // 3 FNames (3 × 8) + i32 outer_index (4) = 28 bytes for UE4.
        // (Plan-defect fix: spec asserted 32 bytes, a stale arithmetic
        // from an earlier draft that included PackageName unconditionally.
        // CUE4Parse FObjectImport.cs gates PackageName on
        // Ar.Ver >= NON_OUTER_PACKAGE_IMPORT (~533); UE4.27=522 is below
        // the gate so the record is 28 bytes.)
        assert_eq!(buf.len(), 28);
        let parsed = ObjectImport::read_from(&mut Cursor::new(&buf), v, "x.uasset").unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn ue5_round_trip() {
        let v = ue5_1();
        let original = sample_import_ue5();
        let mut buf = Vec::new();
        original.write_to(&mut buf, v).unwrap();
        // UE5: 28 bytes (UE4 baseline) + 4 bytes (i32 bool32
        // import_optional) = 32 bytes. Plan-defect fix: spec asserted
        // 36 bytes, off by the same 4 bytes as the UE4 case.
        assert_eq!(buf.len(), 32);
        let parsed = ObjectImport::read_from(&mut Cursor::new(&buf), v, "x.uasset").unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn ue5_round_trip_import_optional_true() {
        // Pin the i32 != 0 → true branch of import_optional decoding.
        // ue5_round_trip exercises Some(false); this completes the bool
        // round-trip coverage.
        let v = ue5_1();
        let original = ObjectImport {
            import_optional: Some(true),
            ..sample_import_ue5()
        };
        let mut buf = Vec::new();
        original.write_to(&mut buf, v).unwrap();
        assert_eq!(buf.len(), 32);
        let parsed = ObjectImport::read_from(&mut Cursor::new(&buf), v, "x.uasset").unwrap();
        assert_eq!(parsed, original);
        assert_eq!(parsed.import_optional, Some(true));
    }

    #[test]
    fn table_round_trip_two_records() {
        let v = ue4_27();
        let table = ImportTable {
            imports: vec![sample_import_ue4(), sample_import_ue4()],
        };
        let mut buf = Vec::new();
        table.write_to(&mut buf, v).unwrap();
        let mut cursor = Cursor::new(buf);
        let parsed = ImportTable::read_from(&mut cursor, 0, 2, v, "x.uasset").unwrap();
        assert_eq!(parsed, table);
    }

    #[test]
    fn rejects_count_over_cap() {
        let v = ue4_27();
        let mut cursor = Cursor::new(Vec::<u8>::new());
        let err = ImportTable::read_from(
            &mut cursor,
            0,
            MAX_IMPORT_TABLE_ENTRIES as i32 + 1,
            v,
            "x.uasset",
        )
        .unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::BoundsExceeded {
                    field: AssetWireField::ImportCount,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn rejects_negative_offset() {
        let v = ue4_27();
        let mut cursor = Cursor::new(Vec::<u8>::new());
        let err = ImportTable::read_from(&mut cursor, -1, 0, v, "x.uasset").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::NegativeValue {
                    field: AssetWireField::ImportOffset,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn rejects_negative_count() {
        let v = ue4_27();
        let mut cursor = Cursor::new(Vec::<u8>::new());
        let err = ImportTable::read_from(&mut cursor, 0, -1, v, "x.uasset").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::NegativeValue {
                    field: AssetWireField::ImportCount,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn package_index_underflow_on_outer_index() {
        // Craft a UE4.27 ObjectImport with outer_index = i32::MIN. The
        // wire layout up to outer_index is 16 bytes of u32 fields + 4
        // bytes i32 outer = 20 bytes minimum. Fill the FName slots
        // with placeholder zeros, then i32::MIN, then continue.
        let v = ue4_27();
        let mut buf = Vec::new();
        buf.extend_from_slice(&1u32.to_le_bytes()); // class_package_name
        buf.extend_from_slice(&0u32.to_le_bytes()); // class_package_number
        buf.extend_from_slice(&2u32.to_le_bytes()); // class_name
        buf.extend_from_slice(&0u32.to_le_bytes()); // class_name_number
        buf.extend_from_slice(&i32::MIN.to_le_bytes()); // outer_index — undecodable
        // The reader bails before consuming the remaining bytes.
        let err = ObjectImport::read_from(&mut Cursor::new(&buf), v, "x.uasset").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::PackageIndexUnderflow {
                    field: AssetWireField::ImportOuterIndex,
                },
                ..
            }
        ));
    }

    #[test]
    fn object_import_serializes_with_raw_indices() {
        // The Task 14 deliverable JSON shows resolved name strings, but
        // that resolution happens in inspect's render layer — not in
        // ObjectImport's Serialize impl. This test pins the type's own
        // derived shape (raw u32 indices) so a future refactor that
        // changes the field set is caught.
        let i = sample_import_ue5();
        let json = serde_json::to_string(&i).unwrap();
        assert!(json.contains(r#""class_package_name":1"#), "got: {json}");
        assert!(json.contains(r#""class_name":2"#), "got: {json}");
        assert!(json.contains(r#""object_name":3"#), "got: {json}");
        assert!(json.contains(r#""outer_index":"Null""#), "got: {json}");
        assert!(json.contains(r#""import_optional":false"#), "got: {json}");
    }

    #[test]
    fn import_table_serializes_as_bare_array() {
        // #[serde(transparent)] container: the wrapping JSON is just
        // the inner Vec, not {"imports": [...]}.
        let t = ImportTable {
            imports: vec![sample_import_ue4()],
        };
        let json = serde_json::to_string(&t).unwrap();
        assert!(json.starts_with('['), "expected array, got: {json}");
        assert!(json.ends_with(']'), "expected array, got: {json}");
        assert!(!json.starts_with(r#"{"imports":"#), "got: {json}");
    }
}
