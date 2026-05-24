//! Top-level UAsset aggregate.
//!
//! [`Package::read_from`] orchestrates the per-component parsers:
//! 1. [`PackageSummary::read_from`] from byte 0.
//! 2. [`NameTable::read_from`] seeked to `summary.name_offset`.
//! 3. [`ImportTable::read_from`] seeked to `summary.import_offset`.
//! 4. [`ExportTable::read_from`] seeked to `summary.export_offset`.
//! 5. Per-export payload bytes carved out of the buffer.
//!
//! Each export's bytes are decoded by Phase 2b's tagged-property
//! iterator into [`PropertyBag::Tree`](crate::asset::property::PropertyBag),
//! falling back to [`PropertyBag::Opaque`](crate::asset::property::PropertyBag)
//! on any parse error (with a `tracing::warn!` event so operators see
//! the version-skew signal). One corrupt export does not abort the
//! package.

use std::io::Cursor;
use std::sync::Arc;

use serde::Serialize;
use serde::ser::SerializeStruct;

use crate::asset::AssetContext;
use crate::asset::export_table::{ExportTable, ObjectExport};
use crate::asset::import_table::{ImportTable, ObjectImport};
use crate::asset::mappings::Usmap;
use crate::asset::name_table::NameTable;
use crate::asset::property::PropertyBag;
use crate::asset::property::unversioned::read_unversioned_properties;
use crate::asset::summary::{PKG_UNVERSIONED_PROPERTIES, PackageSummary};
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

/// Hard cap on the `.uexp` companion file size. `total_header_size`
/// already caps the `.uasset` at 256 MiB; the export-body section in
/// `.uexp` is typically smaller. 1 GiB is generous headroom; bigger
/// would already be suspicious for an UE-cooked asset.
///
/// Enforced at the stitch boundary inside [`Package::read_from`] before
/// any allocation runs, so a malicious pak entry cannot force a
/// multi-GiB combined-buffer reservation by claiming a huge `.uexp`.
pub const MAX_UEXP_SIZE: usize = 1024 * 1024 * 1024;

/// One parsed `.uasset` package: structural header + per-export
/// property bags.
///
/// **Thread safety:** `Package: Send + Sync`. The result of
/// [`Self::read_from`] is an immutable parsed representation; safe
/// to share across threads (clone the `Package` or wrap in `Arc`).
/// Pinned by the `send_sync_assertions` test in `lib.rs`.
///
/// `Serialize` is hand-rolled to emit the Phase 2b deliverable JSON
/// shape — each export carries either `"properties": [...]`
/// (`PropertyBag::Tree`) or `"payload_bytes": N`
/// (`PropertyBag::Opaque` fallback). See the impl below.
///
/// **Round-trip note:** `Deserialize` is intentionally NOT implemented.
/// The view-based `Serialize` resolves FName indices to display
/// strings (via `ObjectImportView` / `ObjectExportView`) and the
/// `Opaque` variant emits a byte count rather than payload bytes —
/// both are one-way mappings. Consumers needing wire-faithful
/// round-trip should serialize the constituent types
/// ([`PackageSummary`], [`NameTable`], [`ImportTable`], [`ExportTable`])
/// and each [`PropertyBag`] directly, all of which DO implement
/// `Deserialize`.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Package {
    /// Virtual path of the asset within its archive (e.g.
    /// `Game/Maps/Demo.uasset`).
    pub asset_path: String,
    /// Parsed package summary.
    pub summary: PackageSummary,
    /// Parsed FName pool.
    ///
    /// `Arc`-wrapped so [`Self::context`] is a refcount bump rather
    /// than a deep clone of the (potentially 1M-entry) name pool
    /// (issue #369). Consumers reading the table via `&pkg.names`
    /// continue to work — `Arc<NameTable>` derefs to `&NameTable`.
    pub names: Arc<NameTable>,
    /// Parsed import table. `Arc`-wrapped for the same reason as
    /// [`Self::names`] (issue #369).
    pub imports: Arc<ImportTable>,
    /// Parsed export table. `Arc`-wrapped for the same reason as
    /// [`Self::names`] (issue #369).
    pub exports: Arc<ExportTable>,
    /// Per-export property bags — same order as `self.exports.exports`.
    /// Each entry is either `PropertyBag::Tree` (decoded properties)
    /// or `PropertyBag::Opaque` (raw bytes when the property iterator
    /// failed mid-parse). Serialized per-export via `ObjectExportView`
    /// — see the Phase 2b deliverable JSON shape.
    pub payloads: Vec<PropertyBag>,
    /// Mappings supplied to [`Package::read_from`], retained so
    /// [`Package::context()`] can resurface them to Phase 3+ format
    /// handlers that drive secondary decode passes. Private because
    /// the storage shape (`Arc<Usmap>`) is an implementation detail;
    /// callers access mappings via [`Package::context()`].
    mappings: Option<Arc<Usmap>>,
}

impl Serialize for Package {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Phase 2b deliverable JSON shape: per-export `properties`
        // (for Tree) or `payload_bytes` (for Opaque) — the Phase 2a
        // top-level `payload_bytes` scalar sum is removed in favor of
        // per-export fields. ObjectExportView carries `&PropertyBag`
        // and emits the right variant arm.
        //
        // Imports/exports are wrapped in `ObjectImportView` /
        // `ObjectExportView` so FName references are resolved to
        // their UE display strings (e.g. `"class_package":
        // "/Script/CoreUObject"` instead of the raw u32 index pair).
        // The raw wire indices are still recoverable from the
        // top-level `names` array, which preserves wire order and
        // remains the source of truth for index-based lookups.

        // Build per-entry views. The intermediate `Vec` allocation is
        // fine here — `inspect` is a one-shot diagnostic, not a hot
        // path, and the view borrows are zero-copy aside from the
        // resolved string fields which `serde_json` would have to
        // materialize regardless. The export view zip relies on the
        // invariant `exports.exports.len() == payloads.len()`
        // established by `read_payloads`.
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
            .zip(self.payloads.iter())
            .map(|(inner, bag)| ObjectExportView {
                inner,
                names: &self.names,
                bag,
            })
            .collect();

        let mut s = serializer.serialize_struct("Package", 5)?;
        s.serialize_field("asset_path", &self.asset_path)?;
        s.serialize_field("summary", &self.summary)?;
        // Deref the Arc to avoid serde's `rc`-gated `Arc<T>: Serialize`
        // impl — serializing through the inner `&NameTable` is the
        // wire-identical path and doesn't pull in the extra feature.
        s.serialize_field("names", &*self.names)?;
        s.serialize_field("imports", &import_views)?;
        s.serialize_field("exports", &export_views)?;
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
    bag: &'a PropertyBag,
}

impl Serialize for ObjectExportView<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let object_name = self
            .names
            .resolve(self.inner.object_name, self.inner.object_name_number);

        // 25 fields — same 24 as Phase 2a (ObjectExport minus
        // object_name_number, which folds into object_name) plus one
        // of `properties` (Tree) or `payload_bytes` (Opaque) at the
        // tail. The two PropertyBag variants are mutually exclusive
        // at this layer, so emitting only one of the two field names
        // per export is correct; serde's `serialize_struct` length
        // is advisory for serde_json and the per-export shape is
        // pinned by tests.
        let mut s = serializer.serialize_struct("ObjectExportView", 25)?;
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
        match self.bag {
            PropertyBag::Opaque { bytes } => {
                s.serialize_field("payload_bytes", &bytes.len())?;
            }
            PropertyBag::Tree { properties } => {
                s.serialize_field("properties", properties)?;
            }
        }
        s.end()
    }
}

/// Derive a companion file path from an asset path by swapping the extension.
///
/// `"Game/Weapon/Sword.uasset"` + `".uexp"` → `"Game/Weapon/Sword.uexp"`.
/// Suffix match is case-insensitive (CLI users may type `.UASSET`)
/// but the stem's casing is preserved — pak entry lookup is
/// exact-match, so lowercasing the whole path would break entries
/// that aren't all-lowercase. If `base` does not end in `.uasset`
/// (any casing), appends `new_ext` directly.
pub(super) fn derive_companion_path(base: &str, new_ext: &str) -> String {
    const UASSET_EXT: &str = ".uasset";
    // `str::get(split_at..)` returns `None` if `split_at` falls
    // inside a multibyte UTF-8 sequence (a real possibility for
    // attacker-crafted pak entry paths); the byte-index slice
    // `base[split_at..]` would panic on the same input and violate
    // CLAUDE.md's "No panics in core" invariant.
    if let Some(split_at) = base.len().checked_sub(UASSET_EXT.len())
        && let Some(tail) = base.get(split_at..)
        && tail.eq_ignore_ascii_case(UASSET_EXT)
    {
        return format!("{}{}", &base[..split_at], new_ext);
    }
    format!("{base}{new_ext}")
}

impl Package {
    /// Parse a `.uasset` from `uasset`, optionally stitched with a
    /// companion `.uexp` slice.
    ///
    /// For monolithic assets (all export payloads inside `uasset`), pass
    /// `uexp = None` and the call is zero-copy on the input slice. For
    /// split assets (UE writes `.uasset` truncated at
    /// `total_header_size` with payloads in a separate `.uexp`), pass
    /// `Some(&uexp_bytes)`; the implementation concatenates the two
    /// into one contiguous buffer (capped by [`MAX_UEXP_SIZE`]) and
    /// parses the combined byte stream so the wire-encoded
    /// `serial_offset` values resolve naturally.
    ///
    /// The companion need-detection runs after the export table parse:
    /// if any export's payload extends past `uasset.len()` and `uexp`
    /// is `None`, returns
    /// [`AssetParseFault::MissingCompanionFile`]; if `uexp` is provided
    /// but no payload needs it, logs `tracing::warn!` and proceeds.
    ///
    /// # Errors
    /// Propagates any [`AssetParseFault`] from the component readers:
    /// - [`AssetParseFault::InvalidMagic`],
    ///   [`AssetParseFault::UnsupportedLegacyFileVersion`],
    ///   etc. from [`PackageSummary::read_from`]
    /// - [`AssetParseFault::NegativeValue`], [`AssetParseFault::BoundsExceeded`],
    ///   [`AssetParseFault::AllocationFailed`] from the table readers
    /// - [`AssetParseFault::InvalidOffset`] if any export's
    ///   `serial_offset + serial_size` extends past the stitched buffer
    /// - [`AssetParseFault::U64ArithmeticOverflow`] if `serial_offset + serial_size`
    ///   overflows, or if `uasset.len() + uexp.len()` overflows `usize`
    /// - [`AssetParseFault::U64ExceedsPlatformUsize`] on 32-bit targets if any
    ///   `serial_size` exceeds `usize::MAX`
    /// - [`AssetParseFault::BoundsExceeded`] with
    ///   `field = AssetWireField::UexpSize` if `uexp.len() > MAX_UEXP_SIZE`
    /// - [`AssetParseFault::MissingCompanionFile`] when a payload
    ///   extends past `uasset.len()` and no `.uexp` was provided
    /// - [`AssetParseFault::SplitAssetSizeMismatch`] when a `.uexp` is
    ///   needed but `uasset.len() != total_header_size`
    #[allow(
        clippy::too_many_lines,
        reason = "Phase 2e stitching + 4-state companion detection + the existing summary/name/import/export/payload pipeline naturally cross the 100-line cap; splitting would obscure the linear top-to-bottom byte-stream flow that's the function's whole point"
    )]
    pub fn read_from(
        uasset: &[u8],
        uexp: Option<&[u8]>,
        mappings: Option<&Usmap>,
        asset_path: &str,
    ) -> crate::Result<Self> {
        // Stitch .uasset and optional .uexp into one contiguous buffer.
        // For monolithic assets (uexp = None), borrow uasset directly
        // (zero-copy). The stitched buffer is the byte universe
        // `serial_offset` indexes into; `asset_size` below MUST reflect
        // the stitched length, not just `.uasset`'s length, or the
        // per-export bounds check in `read_payloads` would falsely
        // reject every split asset.
        let combined_owned: Vec<u8>;
        let bytes: &[u8] = match uexp {
            Some(uexp_data) => {
                // Cap the .uexp size before allocating a combined buffer
                // sized to `uasset.len() + uexp_data.len()`. Without
                // this guard a malicious pak entry could force a
                // multi-GiB allocation by claiming a huge .uexp payload.
                if uexp_data.len() > MAX_UEXP_SIZE {
                    return Err(PaksmithError::AssetParse {
                        asset_path: asset_path.to_string(),
                        fault: AssetParseFault::BoundsExceeded {
                            field: AssetWireField::UexpSize,
                            value: uexp_data.len() as u64,
                            limit: MAX_UEXP_SIZE as u64,
                            unit: BoundsUnit::Bytes,
                        },
                    });
                }
                // Defensive: use try_reserve_exact so an OOM here
                // surfaces as a typed error instead of aborting the
                // process. The bounded `uexp_data.len()` above also
                // bounds the addition; the overflow arm is for the
                // 32-bit-target case where `uasset.len() + uexp.len()`
                // could overflow `usize` even with both individually
                // valid.
                let total = uasset.len().checked_add(uexp_data.len()).ok_or_else(|| {
                    PaksmithError::AssetParse {
                        asset_path: asset_path.to_string(),
                        fault: AssetParseFault::U64ArithmeticOverflow {
                            operation: AssetOverflowSite::SplitAssetConcatExtent,
                        },
                    }
                })?;
                let mut buf: Vec<u8> = Vec::new();
                buf.try_reserve_exact(total)
                    .map_err(|source| PaksmithError::AssetParse {
                        asset_path: asset_path.to_string(),
                        fault: AssetParseFault::AllocationFailed {
                            context: AssetAllocationContext::SplitAssetCombined,
                            requested: total,
                            source,
                        },
                    })?;
                buf.extend_from_slice(uasset);
                buf.extend_from_slice(uexp_data);
                combined_owned = buf;
                &combined_owned
            }
            None => uasset,
        };
        let mut cursor = Cursor::new(bytes);
        let summary = PackageSummary::read_from(&mut cursor, asset_path)?;

        // `Arc`-wrap the tables immediately at parse time (#369).
        // The same Arc is then shared between `Package` and the
        // `AssetContext` below (and any future `context()` callers)
        // — refcount bumps replace the previous per-clone deep
        // copies of the (potentially 1M-entry) tables.
        let names = Arc::new(NameTable::read_from(
            &mut cursor,
            i64::from(summary.name_offset),
            summary.name_count,
            asset_path,
        )?);
        let imports = Arc::new(ImportTable::read_from(
            &mut cursor,
            i64::from(summary.import_offset),
            summary.import_count,
            summary.version,
            asset_path,
        )?);
        let exports = Arc::new(ExportTable::read_from(
            &mut cursor,
            i64::from(summary.export_offset),
            summary.export_count,
            summary.version,
            summary.package_flags,
            asset_path,
        )?);

        // Four-state companion detection.
        //
        // `needs_uexp` is determined by whether any export's payload
        // region extends past the `.uasset` slice's length — that's the
        // structural discriminator between monolithic and split. A
        // naive `serial_offset >= total_header_size` check would
        // misfire on every asset (in both layouts, payloads sit at
        // offsets ≥ total_header_size; the difference is whether those
        // bytes physically live in the `.uasset` file or in `.uexp`).
        // Asking the file-length question directly avoids that trap.
        //
        // `serial_offset` and `serial_size` are validated `>= 0` by
        // `ObjectExport::read_from` (export_table.rs); the i64 -> u64
        // casts here are sign-safe (mirrors the pattern in
        // `read_payloads` below).
        let uasset_len_u64 = uasset.len() as u64;
        let needs_uexp = exports.exports.iter().any(|e| {
            #[allow(
                clippy::cast_sign_loss,
                reason = "serial_offset/serial_size validated >= 0 by ObjectExport::read_from"
            )]
            let end = (e.serial_offset as u64).saturating_add(e.serial_size as u64);
            end > uasset_len_u64
        });

        if needs_uexp && uexp.is_none() {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::MissingCompanionFile {
                    kind: crate::error::CompanionFileKind::Uexp,
                },
            });
        }

        if !needs_uexp && uexp.is_some() {
            tracing::warn!(
                asset = asset_path,
                total_header_size = summary.total_header_size,
                "'.uexp' companion bytes provided but no export payload extends \
                 past .uasset.len(); ignoring companion"
            );
        }

        // Verify the load-bearing invariant: when split, the `.uasset`
        // file contains exactly the header bytes (everything before the
        // export payload region). UE writes split assets with this
        // layout by convention, but a pathological writer could break
        // it (e.g. by appending AssetRegistryData past
        // `total_header_size` in `.uasset`). If
        // `uasset.len() != total_header_size`, then `serial_offset` —
        // which points into the logical full-asset byte stream — does
        // NOT index naturally into `[uasset || uexp]`. Fire a clear
        // error instead of silently misparsing.
        if needs_uexp {
            #[allow(
                clippy::cast_possible_wrap,
                reason = "usize fits in i64 on all paksmith targets (64-bit usize ≤ i64::MAX = 2^63 - 1; 32-bit usize ≤ u32::MAX); the wrap arm is structurally unreachable"
            )]
            let uasset_signed = uasset.len() as i64;
            if uasset_signed != i64::from(summary.total_header_size) {
                return Err(PaksmithError::AssetParse {
                    asset_path: asset_path.to_string(),
                    fault: AssetParseFault::SplitAssetSizeMismatch {
                        uasset_len: uasset.len(),
                        total_header_size: summary.total_header_size,
                    },
                });
            }
        }

        // Build the AssetContext now so read_payloads can drive the
        // tagged-property iterator per export. Tables share the
        // Arcs owned by `Package` (#369) — refcount bumps replace
        // the previous deep-clone-twice pattern. The optional
        // `Usmap` is `Arc`-wrapped once here so downstream clones
        // of the context are refcount-cheap.
        let ctx = AssetContext {
            names: Arc::clone(&names),
            imports: Arc::clone(&imports),
            exports: Arc::clone(&exports),
            version: summary.version,
            custom_versions: Arc::new(summary.custom_versions.clone()),
            mappings: mappings.map(|m| Arc::new(m.clone())),
        };

        // Phase 2f: dispatch the unversioned (schema-driven) property
        // path when `PKG_UnversionedProperties` is set.
        //
        // Without mappings: fire `UnversionedWithoutMappings`.
        // With mappings: walk each export's payload slice through
        // `read_unversioned_properties` and skip `read_payloads`
        // entirely — running the tagged-property decoder on
        // unversioned bytes would fall back to `PropertyBag::Opaque`
        // and emit a spurious warn-level log per export.
        //
        // The flag lives on `summary.package_flags`, so the gate is
        // summary-scoped: a single flagged package cannot mix
        // versioned and unversioned exports.
        let payloads = if summary.package_flags & PKG_UNVERSIONED_PROPERTIES != 0 {
            let usmap = ctx
                .mappings
                .as_deref()
                .ok_or_else(|| PaksmithError::AssetParse {
                    asset_path: asset_path.to_string(),
                    fault: AssetParseFault::UnversionedWithoutMappings,
                })?;
            let mut payloads: Vec<PropertyBag> = Vec::new();
            try_reserve_asset(
                &mut payloads,
                exports.exports.len(),
                asset_path,
                AssetAllocationContext::ExportPayloads,
            )?;
            for export in &exports.exports {
                // Propagate OOB errors here rather than swallowing them
                // with `unwrap_or_default()`. `PackageIndex::Null`
                // already returns `Ok(String::new())` from
                // `resolve_package_index`, so null class refs flow
                // through cleanly and `get_all_properties("")` returns
                // an empty schema (handled inside the decoder).
                let class_name = crate::asset::property::primitives::resolve_package_index(
                    export.class_index,
                    &ctx,
                    asset_path,
                )?;
                let export_slice = carve_export_slice(bytes, export, asset_path)?;
                let mut export_cur = Cursor::new(export_slice);
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
            payloads
        } else {
            read_payloads(bytes, &exports, &ctx, asset_path)?
        };

        Ok(Self {
            asset_path: asset_path.to_string(),
            summary,
            names,
            imports,
            exports,
            payloads,
            mappings: ctx.mappings.clone(),
        })
    }

    /// Open a `.pak` archive at `pak_path`, find the entry at
    /// `virtual_path`, decompress its bytes, and parse as a UAsset.
    ///
    /// Companion files are looked up automatically: a sibling `.uexp`
    /// entry (if present) is stitched in for split assets; a sibling
    /// `.ubulk` entry triggers a warning but is not yet stitched
    /// (deferred to Phase 2f).
    ///
    /// `mappings` is a parsed `.usmap` schema registry — supply
    /// `Some(&usmap)` to decode assets whose `PKG_UnversionedProperties`
    /// flag is set, and `None` for versioned (tagged-property) assets.
    /// A flagged asset paired with `None` fires
    /// [`AssetParseFault::UnversionedWithoutMappings`].
    ///
    /// # Errors
    /// Any [`PaksmithError`] from the pak layer (open, find entry,
    /// decompress) or the asset layer (parse). A missing `.uexp`
    /// companion is silently treated as a monolithic asset; any other
    /// error from the companion lookup propagates.
    pub fn read_from_pak<P: AsRef<std::path::Path>>(
        pak_path: P,
        virtual_path: &str,
        mappings: Option<&Usmap>,
    ) -> crate::Result<Self> {
        use crate::container::ContainerReader;
        let reader = crate::container::pak::PakReader::open(pak_path)?;

        let uasset_bytes = reader.read_entry(virtual_path)?;

        // Look up the `.uexp` companion. Absence is normal for
        // monolithic assets; any other error from the pak layer
        // propagates.
        let uexp_path = derive_companion_path(virtual_path, ".uexp");
        let uexp_bytes = match reader.read_entry(&uexp_path) {
            Ok(bytes) => Some(bytes),
            Err(PaksmithError::EntryNotFound { .. }) => None,
            Err(e) => return Err(e),
        };

        // Detect a `.ubulk` companion. Phase 2e does not stitch bulk
        // data; warn so downstream consumers know the asset is
        // partially loaded. Phase 2f will replace this with real
        // bulk-data stitching.
        //
        // Use `index_entry` (O(1) hashmap probe) instead of
        // `read_entry` — we only need to know whether the entry
        // exists, not materialize its bytes. `read_entry` would
        // decompress + allocate the full bulk payload only to
        // discard it.
        let ubulk_path = derive_companion_path(virtual_path, ".ubulk");
        if reader.index_entry(&ubulk_path).is_some() {
            tracing::warn!(
                asset = virtual_path,
                ubulk_path,
                "'.ubulk' companion found but bulk data stitching is not yet \
                 supported; bulk data will be absent from the parsed asset"
            );
        }

        Self::read_from(&uasset_bytes, uexp_bytes.as_deref(), mappings, virtual_path)
    }

    /// Build an [`AssetContext`] from this package. Used by Phase 2b+
    /// property parsers; Phase 2a only constructs it for the API
    /// shape sanity check in tests.
    ///
    /// Two independent calls produce semantically-equal contexts.
    /// `names` / `imports` / `exports` / `mappings` are all
    /// refcount-shared via `Arc` (#369) — context() is essentially
    /// allocator-free (only the `custom_versions` field still pays a
    /// `clone` because `PackageSummary` stores it by value).
    /// Pointer-equal via [`Arc::ptr_eq`] across calls; use that as a
    /// cache key on the individual fields, not the full context
    /// struct.
    #[must_use]
    pub fn context(&self) -> AssetContext {
        AssetContext {
            names: Arc::clone(&self.names),
            imports: Arc::clone(&self.imports),
            exports: Arc::clone(&self.exports),
            version: self.summary.version,
            custom_versions: Arc::new(self.summary.custom_versions.clone()),
            mappings: self.mappings.clone(),
        }
    }
}

/// Validate and carve out an `&[u8]` view of `export`'s payload from
/// the stitched asset buffer.
///
/// `bytes` is the full stitched `.uasset` + `.uexp` buffer (must not
/// be a sub-view — the bounds reporting uses `bytes.len()` as the
/// asset-size in error payloads). Checks `serial_size`, computes
/// `offset + size`, validates against `bytes.len()`, and returns the
/// borrowed slice. Both Phase 2f's unversioned branch in
/// `Package::read_from` and `read_payloads` route through this helper
/// so the bounds-check ordering stays identical at both sites.
///
/// # Errors
/// - [`AssetParseFault::BoundsExceeded`] for `serial_size >
///   MAX_PAYLOAD_BYTES`.
/// - [`AssetParseFault::U64ArithmeticOverflow`] for the addition.
/// - [`AssetParseFault::InvalidOffset`] when the computed end exceeds
///   the stitched buffer.
fn carve_export_slice<'a>(
    bytes: &'a [u8],
    export: &ObjectExport,
    asset_path: &str,
) -> crate::Result<&'a [u8]> {
    // `serial_offset` / `serial_size` are validated `>= 0` by
    // `ObjectExport::read_from`, so the i64→u64 casts are sign-safe.
    #[allow(
        clippy::cast_sign_loss,
        reason = "serial_offset/serial_size validated >= 0 by ObjectExport::read_from"
    )]
    let offset = export.serial_offset as u64;
    #[allow(
        clippy::cast_sign_loss,
        reason = "serial_offset/serial_size validated >= 0 by ObjectExport::read_from"
    )]
    let size = export.serial_size as u64;
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
    let asset_size = bytes.len() as u64;
    if end > asset_size {
        return Err(PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::InvalidOffset {
                field: AssetWireField::ExportSerialOffset,
                offset: export.serial_offset,
                asset_size,
            },
        });
    }
    // Post bounds-check: both `offset` and `end` are `<= asset_size`
    // = `bytes.len() as u64`. `bytes.len()` is bounded by `isize::MAX`
    // on every platform Rust supports, so both casts to `usize` are
    // infallible.
    #[allow(
        clippy::cast_possible_truncation,
        reason = "bounded by asset_size = bytes.len() above"
    )]
    let start = offset as usize;
    #[allow(
        clippy::cast_possible_truncation,
        reason = "bounded by asset_size = bytes.len() above"
    )]
    let end_usize = end as usize;
    Ok(&bytes[start..end_usize])
}

fn read_payloads(
    bytes: &[u8],
    exports: &ExportTable,
    ctx: &AssetContext,
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
        let export_slice = carve_export_slice(bytes, e, asset_path)?;

        // Phase 2b: attempt tagged-property iteration over the
        // export's bytes. On success, store as `PropertyBag::Tree`;
        // on parse error, fall back to `PropertyBag::Opaque` with
        // the original bytes (one corrupt export shouldn't lose every
        // other export's data). The fallback is logged at warn level
        // so operators see the version-skew signal.
        //
        // `Opaque` needs `Vec<u8>` ownership for storage in the
        // `Package` struct. The cold error path uses
        // `try_reserve_asset` + `extend_from_slice` (NOT
        // `to_vec()`, which routes through the infallible global
        // allocator path and would abort on OOM — violating
        // CLAUDE.md's "no panics in core" invariant). The hot
        // success path stays allocation-free.
        let bag = match crate::asset::property::read_properties(
            &mut Cursor::new(export_slice),
            ctx,
            0,
            export_slice.len() as u64,
            asset_path,
        ) {
            Ok(props) => {
                tracing::debug!(
                    asset = asset_path,
                    export = %e.object_name,
                    count = props.len(),
                    "decoded property tree"
                );
                PropertyBag::tree(props)
            }
            Err(err) => {
                tracing::warn!(
                    asset = asset_path,
                    export = %e.object_name,
                    error = %err,
                    "property iteration failed, falling back to Opaque"
                );
                let mut buf: Vec<u8> = Vec::new();
                try_reserve_asset(
                    &mut buf,
                    export_slice.len(),
                    asset_path,
                    AssetAllocationContext::ExportPayloadBytes,
                )?;
                buf.extend_from_slice(export_slice);
                PropertyBag::opaque(buf)
            }
        };
        payloads.push(bag);
    }
    Ok(payloads)
}

#[cfg(all(test, feature = "__test_utils"))]
mod tests {
    use super::*;
    use crate::error::CompanionFileKind;
    use crate::testing::uasset::{
        MinimalPackage, build_minimal_ue4_27, build_minimal_ue4_27_split,
    };

    #[test]
    fn derive_companion_path_strips_uasset() {
        assert_eq!(
            derive_companion_path("Game/Weapon/Sword.uasset", ".uexp"),
            "Game/Weapon/Sword.uexp"
        );
    }

    #[test]
    fn derive_companion_path_non_uasset_appends() {
        assert_eq!(derive_companion_path("Game/raw", ".uexp"), "Game/raw.uexp");
    }

    #[test]
    fn derive_companion_path_strips_uasset_case_insensitive() {
        // See `derive_companion_path` docs for the case-insensitive
        // + stem-case-preserving rationale (issue #374).
        assert_eq!(
            derive_companion_path("Game/Weapon/Sword.UASSET", ".uexp"),
            "Game/Weapon/Sword.uexp"
        );
        assert_eq!(
            derive_companion_path("Game/Weapon/Sword.UAsset", ".ubulk"),
            "Game/Weapon/Sword.ubulk"
        );
    }

    #[test]
    fn derive_companion_path_handles_multibyte_at_suffix_boundary() {
        // An attacker-crafted pak entry path can be any valid UTF-8
        // (`FString` decode does not enforce ASCII). The byte index
        // `base.len() - ".uasset".len()` may land inside a multibyte
        // character; the slice `&base[split_at..]` would panic.
        // Verifies the fix uses `str::get(split_at..)` which returns
        // `None` instead, falling through to the no-suffix branch.
        //
        // `"ab😀abcd"` is 10 bytes (`a`, `b`, 4-byte emoji, `a`, `b`,
        // `c`, `d`); `split_at = 3` lands inside the emoji.
        let result = derive_companion_path("ab😀abcd", ".uexp");
        // Either treats as no-match (append) or strip; the function
        // contract is "append" because no `.uasset` suffix is present
        // at the byte level.
        assert_eq!(result, "ab😀abcd.uexp");
    }

    #[test]
    fn read_from_monolithic_no_uexp_succeeds() {
        // Standard monolithic fixture: payloads live within `bytes`.
        let pkg = build_minimal_ue4_27();
        let result = Package::read_from(&pkg.bytes, None, None, "test.uasset");
        assert!(result.is_ok(), "monolithic parse failed: {result:?}");
    }

    #[test]
    fn read_from_split_with_uexp_succeeds() {
        // Split fixture: header bytes + uexp bytes. Stitch and parse.
        let (uasset, uexp) = build_minimal_ue4_27_split();
        let result = Package::read_from(&uasset, Some(&uexp), None, "test.uasset");
        assert!(result.is_ok(), "split parse failed: {result:?}");
    }

    #[test]
    fn read_from_split_missing_uexp_errors() {
        // Split fixture header with no uexp provided → MissingCompanionFile.
        let (uasset, _uexp) = build_minimal_ue4_27_split();
        let err = Package::read_from(&uasset, None, None, "test.uasset").unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::MissingCompanionFile {
                        kind: CompanionFileKind::Uexp,
                    },
                    ..
                }
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn read_from_monolithic_with_extra_uexp_warns_and_succeeds() {
        // Monolithic fixture (no export needs .uexp) but we pass Some(uexp)
        // anyway. Should warn and succeed (no error).
        let pkg = build_minimal_ue4_27();
        let dummy_uexp: Vec<u8> = vec![0xDE, 0xAD];
        let result = Package::read_from(&pkg.bytes, Some(&dummy_uexp), None, "test.uasset");
        assert!(result.is_ok(), "extra-uexp warn path failed: {result:?}");
    }

    #[test]
    fn round_trip_minimal_ue4_27() {
        let MinimalPackage {
            bytes,
            summary,
            names,
            imports,
            exports,
            payload,
            ..
        } = build_minimal_ue4_27();
        let parsed = Package::read_from(&bytes, None, None, "test.uasset").unwrap();
        assert_eq!(parsed.summary, summary);
        assert_eq!(*parsed.names, names);
        assert_eq!(*parsed.imports, imports);
        assert_eq!(*parsed.exports, exports);
        assert_eq!(parsed.payloads.len(), 1);
        assert_eq!(parsed.payloads[0], PropertyBag::opaque(payload));
    }

    #[test]
    fn rejects_export_payload_past_eof() {
        // Phase 2e: with the companion-file detection in place, a
        // monolithic-shape truncated asset trips `MissingCompanionFile`
        // first (any payload extending past `uasset.len()` is now
        // treated as a split-asset hint). To exercise the original
        // `InvalidOffset` path inside `read_payloads`, split the fixture
        // into header + truncated-uexp so companion detection sees the
        // uexp and the `end > asset_size` check in `read_payloads`
        // fires on the post-stitch buffer length.
        let pkg = build_minimal_ue4_27();
        #[allow(
            clippy::cast_sign_loss,
            reason = "total_header_size is non-negative by construction"
        )]
        let split_at = pkg.summary.total_header_size as usize;
        let uasset = pkg.bytes[..split_at].to_vec();
        let mut uexp = pkg.bytes[split_at..].to_vec();
        // Truncate 8 bytes off the end of the payload region so the
        // stitched buffer is short of what the export table claims.
        uexp.truncate(uexp.len() - 8);
        let err = Package::read_from(&uasset, Some(&uexp), None, "test.uasset").unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::InvalidOffset {
                        field: AssetWireField::ExportSerialOffset,
                        ..
                    },
                    ..
                }
            ),
            "expected InvalidOffset(ExportSerialOffset); got {err:?}"
        );
    }

    #[test]
    // MAX_PAYLOAD_BYTES (256 MiB) + 1 fits comfortably in i64.
    #[allow(clippy::cast_possible_wrap)]
    fn rejects_export_payload_exceeding_max_payload_bytes() {
        // Defense-in-depth: a single export claiming a payload larger
        // than MAX_PAYLOAD_BYTES is rejected at the cap check before
        // any byte read or allocation. The synthesized bytes are tiny
        // (no 256 MiB allocation needed) because the check fires on
        // the wire-claimed `serial_size`, not on the asset's actual
        // length.
        //
        // Phase 2e: with companion detection, a 256-MiB `serial_size`
        // also pushes `end > uasset.len()` and trips
        // `MissingCompanionFile` first when fed as a monolithic blob.
        // Split into header + tiny-uexp so detection is satisfied and
        // execution reaches `read_payloads` — where the actual
        // `MAX_PAYLOAD_BYTES` cap check lives and the test's intent
        // applies.
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
        // summary.export_offset is set by the fixture builder to the
        // header's end position — always positive in this test.
        #[allow(clippy::cast_sign_loss)]
        let export_offset = summary.export_offset as usize;
        bytes[export_offset..export_offset + EXPORT_RECORD_SIZE_UE4_27]
            .copy_from_slice(&export_buf);

        #[allow(
            clippy::cast_sign_loss,
            reason = "total_header_size is non-negative by construction"
        )]
        let split_at = summary.total_header_size as usize;
        let uasset = bytes[..split_at].to_vec();
        let uexp = bytes[split_at..].to_vec();

        let err = Package::read_from(&uasset, Some(&uexp), None, "test.uasset").unwrap_err();
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
        let pkg = Package::read_from(&bytes, None, None, "test.uasset").unwrap();
        let ctx_a = pkg.context();
        let ctx_b = ctx_a.clone();
        assert!(Arc::ptr_eq(&ctx_a.names, &ctx_b.names));
    }

    /// Pins issue #369's `context()` contract: two separate
    /// `pkg.context()` calls (not `.clone()` of a single context)
    /// return `Arc::ptr_eq`-equal tables — refcount-shared with the
    /// `Arc<NameTable>`/`Arc<ImportTable>`/`Arc<ExportTable>` stored
    /// on `Package`, NOT deep-cloned per call. A regression that
    /// re-introduces `Arc::new((*self.names).clone())` would type-
    /// check and pass `context_clones_cheaply` (which only exercises
    /// the `Arc::clone` of a single ctx); this test fails on it.
    #[test]
    fn two_context_calls_share_arc_tables() {
        let MinimalPackage { bytes, .. } = build_minimal_ue4_27();
        let pkg = Package::read_from(&bytes, None, None, "test.uasset").unwrap();
        let ctx_a = pkg.context();
        let ctx_b = pkg.context();
        assert!(
            Arc::ptr_eq(&ctx_a.names, &ctx_b.names),
            "names: two context() calls must share the Arc, not deep-clone"
        );
        assert!(
            Arc::ptr_eq(&ctx_a.imports, &ctx_b.imports),
            "imports: two context() calls must share the Arc, not deep-clone"
        );
        assert!(
            Arc::ptr_eq(&ctx_a.exports, &ctx_b.exports),
            "exports: two context() calls must share the Arc, not deep-clone"
        );
    }

    #[test]
    fn context_preserves_mappings_passed_to_read_from() {
        // Phase 3+ format handlers reconstruct an `AssetContext` from
        // a parsed `Package` to drive secondary decode passes. The
        // mappings supplied to `Package::read_from` must persist —
        // dropping them would silently misparse unversioned assets
        // downstream.
        use crate::testing::usmap::build_minimal_usmap_bytes;
        let usmap = Usmap::from_bytes(&build_minimal_usmap_bytes()).expect("Usmap parse");
        let MinimalPackage { bytes, .. } = build_minimal_ue4_27();
        let pkg = Package::read_from(&bytes, None, Some(&usmap), "test.uasset").unwrap();
        let ctx = pkg.context();
        assert!(
            ctx.mappings.is_some(),
            "mappings supplied to read_from must survive into context()"
        );
        // Pointer-equality on the second clone: the stored Arc<Usmap>
        // is reused, not deep-cloned per context() call.
        let ctx_b = pkg.context();
        let (a, b) = (
            ctx.mappings.as_ref().unwrap(),
            ctx_b.mappings.as_ref().unwrap(),
        );
        assert!(
            Arc::ptr_eq(a, b),
            "two context() calls must share the same Arc<Usmap>"
        );
    }

    #[test]
    fn serialize_emits_per_export_payload_bytes_not_top_level_scalar() {
        // Phase 2b deliverable JSON shape: each export carries its
        // own `payload_bytes` (Opaque) or `properties` (Tree) field;
        // the top-level `payload_bytes` scalar from Phase 2a is
        // removed. Pinned so a future Serialize refactor can't
        // silently regress the contract.
        let MinimalPackage { bytes, .. } = build_minimal_ue4_27();
        let pkg = Package::read_from(&bytes, None, None, "test.uasset").unwrap();
        let json = serde_json::to_string(&pkg).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        // Top-level scalar removed.
        assert!(
            parsed.get("payload_bytes").is_none(),
            "top-level payload_bytes must not be emitted; got: {json}"
        );
        // Top-level payloads array still absent (Phase 2a guarantee).
        assert!(
            parsed.get("payloads").is_none(),
            "top-level payloads array must not be emitted; got: {json}"
        );
        // Per-export field present. The minimal fixture's 0xAA bytes
        // trigger negative-FName rejection in read_properties → Opaque
        // fallback, so the per-export field is `payload_bytes`, not
        // `properties`.
        assert!(
            parsed["exports"][0].get("payload_bytes").is_some(),
            "per-export payload_bytes must be present for Opaque fallback; got: {json}"
        );
        assert_eq!(
            parsed["exports"][0]["payload_bytes"], 16,
            "expected per-export payload_bytes = 16; got: {json}"
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
        let pkg = Package::read_from(&bytes, None, None, "test.uasset").unwrap();
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
