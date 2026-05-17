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

use serde::Serialize;
use serde::ser::SerializeStruct;

use crate::asset::AssetContext;
use crate::asset::export_table::{ExportTable, ObjectExport};
use crate::asset::import_table::{ImportTable, ObjectImport};
use crate::asset::name_table::NameTable;
use crate::asset::property_bag::PropertyBag;
use crate::asset::summary::PackageSummary;
use crate::error::{
    AssetAllocationContext, AssetOverflowSite, AssetParseFault, AssetWireField, BoundsUnit,
    PaksmithError, try_reserve_asset,
};

/// Maximum permitted per-export payload size. Defense-in-depth against
/// crafted assets that declare overlapping or oversized export ranges:
/// a single export can encode an arbitrary `i64` `serial_size` on the
/// wire, and the per-export `try_reserve_exact` below would otherwise
/// be the only allocator gate between malicious bytes and a process-
/// wide OOM. 256 MiB is far above any cooked-game export observed in
/// practice (typical asset payloads are kilobytes; the largest cooked
/// textures are tens of megabytes) and well below the `usize::MAX`
/// allocator-domain ceiling on 32-bit targets.
pub(crate) const MAX_PAYLOAD_BYTES: u64 = 256 * 1024 * 1024;

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

impl Serialize for Package {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Phase 2a deliverable JSON shape: top-level scalar
        // `payload_bytes` (sum across exports), not per-export
        // payload objects. Phase 2b will replace this with per-export
        // `properties` arrays additively (doesn't change top-level
        // shape).
        //
        // Imports/exports are wrapped in `ObjectImportView` /
        // `ObjectExportView` so FName references are resolved to
        // their UE display strings (e.g. `"class_package":
        // "/Script/CoreUObject"` instead of the raw u32 index pair).
        // The raw wire indices are still recoverable from the
        // top-level `names` array, which preserves wire order and
        // remains the source of truth for index-based lookups.
        let payload_bytes: usize = self.payloads.iter().map(PropertyBag::byte_len).sum();

        // Build per-entry views. The intermediate `Vec` allocation is
        // fine here — `inspect` is a one-shot diagnostic, not a hot
        // path, and the view borrows are zero-copy aside from the
        // resolved string fields which `serde_json` would have to
        // materialize regardless.
        let import_views: Vec<ObjectImportView<'_>> = self
            .imports
            .imports
            .iter()
            .map(|inner| ObjectImportView {
                inner,
                names: &self.names,
            })
            .collect();
        let export_views: Vec<ObjectExportView<'_>> = self
            .exports
            .exports
            .iter()
            .map(|inner| ObjectExportView {
                inner,
                names: &self.names,
            })
            .collect();

        let mut s = serializer.serialize_struct("Package", 6)?;
        s.serialize_field("asset_path", &self.asset_path)?;
        s.serialize_field("summary", &self.summary)?;
        s.serialize_field("names", &self.names)?;
        s.serialize_field("imports", &import_views)?;
        s.serialize_field("exports", &export_views)?;
        s.serialize_field("payload_bytes", &payload_bytes)?;
        s.end()
    }
}

/// Serialization-only borrowed view of an [`ObjectImport`] that
/// resolves FName references to their canonical UE display strings.
///
/// The owning type [`ObjectImport`] keeps its derived `Serialize`
/// impl emitting raw `u32` indices (pinned by
/// `object_import_serializes_with_raw_indices` in `import_table.rs`)
/// — this view layers resolution on top for the
/// [`Package`]-level JSON output. The two shapes are deliberately
/// distinct: type-level Serialize is wire-format-faithful for
/// debugging an isolated record; the package-level Serialize
/// produces the human-readable Deliverable JSON.
struct ObjectImportView<'a> {
    inner: &'a ObjectImport,
    names: &'a NameTable,
}

impl Serialize for ObjectImportView<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let class_package = self.names.resolve(
            self.inner.class_package_name,
            self.inner.class_package_number,
        );
        let class_name = self
            .names
            .resolve(self.inner.class_name, self.inner.class_name_number);
        let object_name = self
            .names
            .resolve(self.inner.object_name, self.inner.object_name_number);

        let mut s = serializer.serialize_struct("ObjectImportView", 5)?;
        s.serialize_field("class_package", &class_package)?;
        s.serialize_field("class_name", &class_name)?;
        s.serialize_field("outer_index", &self.inner.outer_index)?;
        s.serialize_field("object_name", &object_name)?;
        // `import_optional` stays as the parsed `Option<bool>` —
        // `null` for UE4 (gate inactive) and `false`/`true` for UE5
        // ≥ 1003. Kept in the view so consumers don't need to track
        // version gating just to count fields.
        s.serialize_field("import_optional", &self.inner.import_optional)?;
        s.end()
    }
}

/// Serialization-only borrowed view of an [`ObjectExport`] mirroring
/// [`ObjectImportView`]'s contract — FName references resolved
/// against the package's [`NameTable`], all other fields passed
/// through. The disambiguator-suffix folding means `object_name`
/// emits the canonical UE display string with no separate
/// `object_name_number` field.
struct ObjectExportView<'a> {
    inner: &'a ObjectExport,
    names: &'a NameTable,
}

impl Serialize for ObjectExportView<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let object_name = self
            .names
            .resolve(self.inner.object_name, self.inner.object_name_number);

        // 24 fields — same count as ObjectExport minus
        // `object_name_number` (folded into `object_name`).
        let mut s = serializer.serialize_struct("ObjectExportView", 24)?;
        s.serialize_field("class_index", &self.inner.class_index)?;
        s.serialize_field("super_index", &self.inner.super_index)?;
        s.serialize_field("template_index", &self.inner.template_index)?;
        s.serialize_field("outer_index", &self.inner.outer_index)?;
        s.serialize_field("object_name", &object_name)?;
        s.serialize_field("object_flags", &self.inner.object_flags)?;
        s.serialize_field("serial_size", &self.inner.serial_size)?;
        s.serialize_field("serial_offset", &self.inner.serial_offset)?;
        s.serialize_field("forced_export", &self.inner.forced_export)?;
        s.serialize_field("not_for_client", &self.inner.not_for_client)?;
        s.serialize_field("not_for_server", &self.inner.not_for_server)?;
        s.serialize_field("package_guid", &self.inner.package_guid)?;
        s.serialize_field("is_inherited_instance", &self.inner.is_inherited_instance)?;
        s.serialize_field("package_flags", &self.inner.package_flags)?;
        s.serialize_field(
            "not_always_loaded_for_editor_game",
            &self.inner.not_always_loaded_for_editor_game,
        )?;
        s.serialize_field("is_asset", &self.inner.is_asset)?;
        s.serialize_field("generate_public_hash", &self.inner.generate_public_hash)?;
        s.serialize_field(
            "script_serialization_start_offset",
            &self.inner.script_serialization_start_offset,
        )?;
        s.serialize_field(
            "script_serialization_end_offset",
            &self.inner.script_serialization_end_offset,
        )?;
        s.serialize_field(
            "first_export_dependency",
            &self.inner.first_export_dependency,
        )?;
        s.serialize_field(
            "serialization_before_serialization_count",
            &self.inner.serialization_before_serialization_count,
        )?;
        s.serialize_field(
            "create_before_serialization_count",
            &self.inner.create_before_serialization_count,
        )?;
        s.serialize_field(
            "serialization_before_create_count",
            &self.inner.serialization_before_create_count,
        )?;
        s.serialize_field(
            "create_before_create_count",
            &self.inner.create_before_create_count,
        )?;
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
            summary.package_flags,
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
    ///
    /// Two independent calls produce semantically-equal but not
    /// pointer-equal contexts. Call once and clone for downstream
    /// caching that uses [`Arc::ptr_eq`] as a key.
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
    try_reserve_asset(
        &mut payloads,
        exports.exports.len(),
        asset_path,
        AssetAllocationContext::ExportPayloads,
    )?;

    for e in &exports.exports {
        // serial_offset and serial_size are validated `>= 0` by
        // ObjectExport::read_from (export_table.rs); the i64 -> u64
        // casts are sign-safe here.
        let offset = e.serial_offset as u64;
        let size = e.serial_size as u64;
        if size > MAX_PAYLOAD_BYTES {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::BoundsExceeded {
                    field: AssetWireField::ExportSerialSize,
                    value: size,
                    limit: MAX_PAYLOAD_BYTES,
                    unit: BoundsUnit::Bytes,
                },
            });
        }
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
        try_reserve_asset(
            &mut buf,
            size_usize,
            asset_path,
            AssetAllocationContext::ExportPayloadBytes,
        )?;
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
    fn rejects_export_payload_exceeding_max_payload_bytes() {
        // Defense-in-depth: a single export claiming a payload larger
        // than MAX_PAYLOAD_BYTES is rejected at the cap check before
        // any byte read or allocation. The synthesized bytes are tiny
        // (no 256 MiB allocation needed) because the check fires on
        // the wire-claimed `serial_size`, not on the asset's actual
        // length.
        use crate::asset::export_table::EXPORT_RECORD_SIZE_UE4_27;

        let MinimalPackage {
            mut bytes,
            mut exports,
            summary,
            ..
        } = build_minimal_ue4_27();
        // Push the wire-claimed size one byte past the cap. The
        // serial_offset stays valid (still points at end-of-header);
        // the cap check fires before the offset+size bounds check.
        exports.exports[0].serial_size = MAX_PAYLOAD_BYTES as i64 + 1;
        let mut export_buf = Vec::new();
        exports
            .write_to(&mut export_buf, summary.version, summary.package_flags)
            .unwrap();
        assert_eq!(export_buf.len(), EXPORT_RECORD_SIZE_UE4_27);
        let export_offset = summary.export_offset as usize;
        bytes[export_offset..export_offset + EXPORT_RECORD_SIZE_UE4_27]
            .copy_from_slice(&export_buf);

        let err = Package::read_from(&bytes, "test.uasset").unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::BoundsExceeded {
                        field: AssetWireField::ExportSerialSize,
                        unit: BoundsUnit::Bytes,
                        ..
                    },
                    ..
                }
            ),
            "expected BoundsExceeded(ExportSerialSize); got {err:?}"
        );
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

    #[test]
    fn serialize_resolves_fname_references_in_imports_and_exports() {
        // Phase 2a follow-up: the package-level Serialize emits
        // resolved FName strings for imports/exports (matching the
        // plan's Deliverable example), distinct from the type-level
        // Serialize impls which emit raw u32 indices for debugging
        // an isolated record.
        //
        // The minimal UE4.27 fixture has names = ["/Script/CoreUObject",
        // "Package", "Default__Object"]; its single import points
        // class_package=0, class_name=1, object_name=2 → resolved
        // strings below.
        let MinimalPackage { bytes, .. } = build_minimal_ue4_27();
        let pkg = Package::read_from(&bytes, "test.uasset").unwrap();
        let json = serde_json::to_string(&pkg).unwrap();

        // Resolved import — bare strings, no raw `class_package_name:0`
        // / `class_package_number:0` field pair.
        assert!(
            json.contains(r#""class_package":"/Script/CoreUObject""#),
            "got: {json}"
        );
        assert!(json.contains(r#""class_name":"Package""#), "got: {json}");
        assert!(
            json.contains(r#""object_name":"Default__Object""#),
            "got: {json}"
        );
        assert!(
            !json.contains(r#""class_package_name":"#),
            "raw index field must not leak into package-level JSON; got: {json}"
        );
        assert!(
            !json.contains(r#""class_package_number":"#),
            "raw number field must not leak into package-level JSON; got: {json}"
        );
        assert!(
            !json.contains(r#""object_name_number":"#),
            "raw number field must not leak into package-level JSON; got: {json}"
        );
    }
}
