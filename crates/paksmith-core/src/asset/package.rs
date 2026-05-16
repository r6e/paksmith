//! Top-level UAsset aggregate.
//!
//! [`Package::read_from`] orchestrates the per-component parsers:
//! 1. [`PackageSummary::read_from`] from byte 0.
//! 2. [`NameTable::read_from`] seeked to `summary.name_offset`.
//! 3. [`ImportTable::read_from`] seeked to `summary.import_offset`.
//! 4. [`ExportTable::read_from`] seeked to `summary.export_offset`.
//! 5. Per-export payload bytes carved out of the buffer.
//!
//! Each export's bytes are stored as
//! [`PropertyBag::Opaque`](crate::asset::property_bag::PropertyBag)
//! for Phase 2a; Phase 2b's tagged-property iterator replaces this.

use std::io::{Cursor, Read, Seek, SeekFrom};
use std::sync::Arc;

use crate::asset::AssetContext;
use crate::asset::export_table::ExportTable;
use crate::asset::import_table::ImportTable;
use crate::asset::name_table::NameTable;
use crate::asset::property_bag::PropertyBag;
use crate::asset::summary::PackageSummary;
use crate::error::{
    AssetAllocationContext, AssetOverflowSite, AssetParseFault, AssetWireField, BoundsUnit,
    PaksmithError,
};

/// One parsed `.uasset` package: structural header + opaque payloads.
///
/// `Serialize` is hand-rolled to match the Phase 2a deliverable JSON
/// shape (scalar `payload_bytes` sum instead of per-export array). See
/// the impl below.
#[derive(Debug, Clone)]
pub struct Package {
    /// Virtual path of the asset within its archive (e.g.
    /// `Game/Maps/Demo.uasset`).
    pub asset_path: String,
    /// Parsed package summary.
    pub summary: PackageSummary,
    /// Parsed FName pool.
    pub names: NameTable,
    /// Parsed import table.
    pub imports: ImportTable,
    /// Parsed export table.
    pub exports: ExportTable,
    /// Per-export opaque payload bodies — same order as
    /// `self.exports.exports`. Internal field; serialized as
    /// `payload_bytes` scalar sum (not a per-export array) per the
    /// Phase 2a deliverable JSON shape.
    pub payloads: Vec<PropertyBag>,
}

impl serde::Serialize for Package {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        // Phase 2a deliverable JSON shape: top-level scalar
        // `payload_bytes` (sum across exports), not per-export
        // payload objects. Phase 2b will replace this with per-export
        // `properties` arrays additively (doesn't change top-level
        // shape).
        let payload_bytes: usize = self.payloads.iter().map(PropertyBag::byte_len).sum();
        let mut s = serializer.serialize_struct("Package", 6)?;
        s.serialize_field("asset_path", &self.asset_path)?;
        s.serialize_field("summary", &self.summary)?;
        s.serialize_field("names", &self.names)?;
        s.serialize_field("imports", &self.imports)?;
        s.serialize_field("exports", &self.exports)?;
        s.serialize_field("payload_bytes", &payload_bytes)?;
        s.end()
    }
}

impl Package {
    /// Parse a `.uasset` from `bytes`.
    ///
    /// # Errors
    /// Propagates any [`AssetParseFault`] from the component readers:
    /// - [`AssetParseFault::InvalidMagic`],
    ///   [`AssetParseFault::UnsupportedLegacyFileVersion`],
    ///   etc. from [`PackageSummary::read_from`]
    /// - [`AssetParseFault::NegativeValue`], [`AssetParseFault::BoundsExceeded`],
    ///   [`AssetParseFault::AllocationFailed`] from the table readers
    /// - [`AssetParseFault::InvalidOffset`] if any export's
    ///   `serial_offset + serial_size` extends past `bytes.len()`
    /// - [`AssetParseFault::U64ArithmeticOverflow`] if `serial_offset + serial_size`
    ///   overflows
    /// - [`AssetParseFault::U64ExceedsPlatformUsize`] on 32-bit targets if any
    ///   `serial_size` exceeds `usize::MAX`
    pub fn read_from(bytes: &[u8], asset_path: &str) -> crate::Result<Self> {
        let asset_size = bytes.len() as u64;
        let mut cursor = Cursor::new(bytes);
        let summary = PackageSummary::read_from(&mut cursor, asset_path)?;

        let names = NameTable::read_from(
            &mut cursor,
            i64::from(summary.name_offset),
            summary.name_count,
            asset_path,
        )?;
        let imports = ImportTable::read_from(
            &mut cursor,
            i64::from(summary.import_offset),
            summary.import_count,
            summary.version,
            asset_path,
        )?;
        let exports = ExportTable::read_from(
            &mut cursor,
            i64::from(summary.export_offset),
            summary.export_count,
            summary.version,
            asset_path,
        )?;

        let payloads = read_payloads(&mut cursor, &exports, asset_size, asset_path)?;

        Ok(Self {
            asset_path: asset_path.to_string(),
            summary,
            names,
            imports,
            exports,
            payloads,
        })
    }

    /// Open a `.pak` archive at `pak_path`, find the entry at
    /// `virtual_path`, decompress its bytes, and parse as a UAsset.
    ///
    /// # Errors
    /// Any [`PaksmithError`] from the pak layer (open, find entry,
    /// decompress) or the asset layer (parse).
    pub fn read_from_pak<P: AsRef<std::path::Path>>(
        pak_path: P,
        virtual_path: &str,
    ) -> crate::Result<Self> {
        use crate::container::ContainerReader;
        let reader = crate::container::pak::PakReader::open(pak_path)?;
        let bytes = reader.read_entry(virtual_path)?;
        Self::read_from(&bytes, virtual_path)
    }

    /// Build an [`AssetContext`] from this package. Used by Phase 2b+
    /// property parsers; Phase 2a only constructs it for the API
    /// shape sanity check in tests.
    #[must_use]
    pub fn context(&self) -> AssetContext {
        AssetContext {
            names: Arc::new(self.names.clone()),
            imports: Arc::new(self.imports.clone()),
            exports: Arc::new(self.exports.clone()),
            version: self.summary.version,
        }
    }
}

fn read_payloads<R: Read + Seek>(
    reader: &mut R,
    exports: &ExportTable,
    asset_size: u64,
    asset_path: &str,
) -> crate::Result<Vec<PropertyBag>> {
    let mut payloads: Vec<PropertyBag> = Vec::new();
    payloads
        .try_reserve_exact(exports.exports.len())
        .map_err(|source| PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::AllocationFailed {
                context: AssetAllocationContext::ExportTable,
                requested: exports.exports.len(),
                unit: BoundsUnit::Items,
                source,
            },
        })?;

    for e in &exports.exports {
        // serial_offset and serial_size are validated `>= 0` by
        // ObjectExport::read_from (export_table.rs); the i64 -> u64
        // casts are sign-safe here.
        let offset = e.serial_offset as u64;
        let size = e.serial_size as u64;
        let end = offset
            .checked_add(size)
            .ok_or_else(|| PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::U64ArithmeticOverflow {
                    operation: AssetOverflowSite::ExportPayloadExtent,
                },
            })?;
        if end > asset_size {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::InvalidOffset {
                    field: AssetWireField::ExportSerialOffset,
                    offset: e.serial_offset,
                    asset_size,
                },
            });
        }
        let _ = reader.seek(SeekFrom::Start(offset))?;
        let size_usize = usize::try_from(size).map_err(|_| PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::U64ExceedsPlatformUsize {
                field: AssetWireField::ExportSerialSize,
                value: size,
            },
        })?;
        let mut buf: Vec<u8> = Vec::new();
        buf.try_reserve_exact(size_usize)
            .map_err(|source| PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::AllocationFailed {
                    context: AssetAllocationContext::ExportPayloadBytes,
                    requested: size_usize,
                    unit: BoundsUnit::Bytes,
                    source,
                },
            })?;
        buf.resize(size_usize, 0);
        reader.read_exact(&mut buf)?;
        payloads.push(PropertyBag::opaque(buf));
    }
    Ok(payloads)
}

#[cfg(all(test, feature = "__test_utils"))]
mod tests {
    use super::*;
    use crate::testing::uasset::{MinimalPackage, build_minimal_ue4_27};

    #[test]
    fn round_trip_minimal_ue4_27() {
        let MinimalPackage {
            bytes,
            summary,
            names,
            imports,
            exports,
            payload,
        } = build_minimal_ue4_27();
        let parsed = Package::read_from(&bytes, "test.uasset").unwrap();
        assert_eq!(parsed.summary, summary);
        assert_eq!(parsed.names, names);
        assert_eq!(parsed.imports, imports);
        assert_eq!(parsed.exports, exports);
        assert_eq!(parsed.payloads.len(), 1);
        assert_eq!(parsed.payloads[0], PropertyBag::opaque(payload));
    }

    #[test]
    fn rejects_export_payload_past_eof() {
        let MinimalPackage { mut bytes, .. } = build_minimal_ue4_27();
        bytes.truncate(bytes.len() - 8);
        let err = Package::read_from(&bytes, "test.uasset").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::InvalidOffset {
                    field: AssetWireField::ExportSerialOffset,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn context_clones_cheaply() {
        let MinimalPackage { bytes, .. } = build_minimal_ue4_27();
        let pkg = Package::read_from(&bytes, "test.uasset").unwrap();
        let ctx_a = pkg.context();
        let ctx_b = ctx_a.clone();
        assert!(Arc::ptr_eq(&ctx_a.names, &ctx_b.names));
    }

    #[test]
    fn serialize_emits_payload_bytes_scalar_not_payloads_array() {
        // Phase 2a deliverable JSON shape: top-level scalar payload_bytes,
        // no per-export payloads array. Pinned so a future change to
        // Package's Serialize impl can't silently break the contract.
        let MinimalPackage { bytes, .. } = build_minimal_ue4_27();
        let pkg = Package::read_from(&bytes, "test.uasset").unwrap();
        let json = serde_json::to_string(&pkg).unwrap();
        assert!(json.contains(r#""payload_bytes":16"#), "got: {json}");
        assert!(
            !json.contains(r#""payloads":"#),
            "should not emit payloads array; got: {json}"
        );
    }
}
