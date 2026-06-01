//! UAsset deserialization.
//!
//! # Scope (Phase 2a)
//!
//! Parses the structural header of UE 4.21–UE 5.x `.uasset` files.
//! Property bodies (`FPropertyTag`-iterated payloads inside export
//! serialized regions) are carried as opaque bytes via the
//! [`PropertyBag::Opaque`] variant; tagged-property iteration and the
//! typed property surface arrive in Phase 2b.
//!
//! # Module layout
//!
//! [`Package::read_from`] / [`Package::read_from_pak`] are the entry
//! points — both return a fully parsed [`Package`] (summary + name /
//! import / export tables + opaque payload). [`Asset`] wraps the
//! `Package` as its `Generic` variant; specialized variants
//! (`Texture`, `StaticMesh`, …) land in Phase 3. [`AssetContext`]
//! bundles the `Arc`-shared tables for downstream property parsers.
//!
//! See `docs/plans/phase-2a-uasset-header.md` for the implementation
//! plan and `docs/design/SPEC.md` § "Asset Data Model" for the
//! architectural intent.

use std::sync::Arc;

use serde::Serialize;

pub mod bulk_data;
pub mod custom_version;
pub mod engine_version;
pub mod export_table;
pub(crate) mod exports;
pub(crate) mod fstring;
pub mod guid;
pub mod import_table;
pub mod mappings;
pub mod name_table;
pub mod package;
pub mod package_index;
pub mod property;
pub mod structs;
pub mod summary;
pub mod version;
pub mod wire;

pub use custom_version::{CustomVersion, CustomVersionContainer};
pub use engine_version::EngineVersion;
pub use export_table::{ExportTable, ObjectExport};
pub use guid::FGuid;
pub use import_table::{ImportTable, ObjectImport};
pub use mappings::Usmap;
pub use name_table::{FName, NameTable};
pub use package::Package;
pub use package_index::{PackageIndex, PackageIndexError};
pub use property::PropertyBag;
pub use summary::PackageSummary;
pub use version::AssetVersion;

#[cfg(any(test, feature = "__test_utils"))]
pub(crate) use fstring::write_asset_fstring;
pub(crate) use fstring::{read_asset_fstring, skip_asset_bytes, skip_asset_fstring};
pub(crate) use package_index::read_package_index;
pub(crate) use wire::read_bool32;
#[cfg(any(test, feature = "__test_utils"))]
pub(crate) use wire::write_bool32;

/// Per-export typed payload for a deserialized UE asset.
///
/// Phase 3 ships only the [`Self::Generic`] variant carrying a
/// [`property::bag::PropertyBag`] (Tree or Opaque
/// fallback). Typed variants for known export classes —
/// `DataTable`, `Texture2D`, `SoundWave`, `StaticMesh`,
/// `SkeletalMesh` — land in Phase 3 sub-phases 3d-3h on this same
/// `#[non_exhaustive]` enum.
///
/// `#[non_exhaustive]` so downstream consumers can pattern-match with
/// `_` and survive future variant additions.
///
/// The default `#[derive(Serialize)]` form produces an externally-
/// tagged JSON object (`{"Generic": {"kind": "...", ...}}`).
/// Externally-tagged was chosen over `#[serde(untagged)]` precisely
/// because future variants need a discriminator: locking in the tag
/// shape now lets 3d-3h add `DataTable` / `Texture2D` / etc. without
/// breaking consumers who already match on the tag.
///
/// `Package::payloads: Vec<Asset>` carries one entry per export; this
/// enum is the per-export payload (NOT a per-package wrapper —
/// Phase 2 briefly used a `Generic(Package)` shape as a forward-compat
/// placeholder; Phase 3 inverted to per-export semantics).
///
/// **`PartialEq` derive — forward-compat constraint:** every variant's
/// inner type MUST implement `PartialEq` (PropertyBag already does;
/// 3d-3h's typed inner types (`DataTableData`, `Texture2DData`, etc.)
/// must follow. If a future variant carries decoder-state or other
/// non-`PartialEq` interiors, this derive will need to be removed
/// and the relevant test assertions (`assert_eq!(asset, ...)`)
/// rewritten as `matches!` checks.
// `Deserialize` is intentionally NOT derived on `Asset` because the
// inner property-bag content has a hand-rolled, view-based
// serialization that loses information (Opaque renders as a byte
// count only; FName references resolve to display strings). That
// JSON shape is designed for human consumption (`paksmith inspect`),
// not round-trip.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[non_exhaustive]
pub enum Asset {
    /// The universal fallback: a single export's parsed property bag.
    /// Phase 2 produced this for every export; Phase 3 sub-phases
    /// (3d-3h) add typed variants for known export classes.
    Generic(property::bag::PropertyBag),
    /// A `UDataTable` export: a row-keyed table whose rows share a
    /// `RowStruct` schema. Phase 3d. The upcoming `data_table::read_from`
    /// parser fills this in; `CsvHandler` / `JsonHandler` export it.
    DataTable(DataTableData),
    /// A `UTexture2D` export. Phase 3e. Carries the segment-1 tagged
    /// properties (`SRGB`, `CompressionSettings`, …) plus the
    /// `FTexturePlatformData` header *start* (dimensions, pixel format,
    /// slice/cubemap bits) as of 3e-2a; the remaining header fields, the
    /// mip chain, and virtual-texture data are added to [`Texture2DData`]
    /// in the later 3e milestones, and `PngHandler` exports it in 3e-8.
    Texture2D(Texture2DData),
}

/// Parsed contents of a `UDataTable` export — the row-keyed table plus
/// the class-level metadata needed to round-trip it.
///
/// Phase 3d. Produced by `data_table::read_from`; consumed by the
/// DataTable `FormatHandler` impls.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[non_exhaustive]
pub struct DataTableData {
    /// Name of the `RowStruct` (`UScriptStruct`) every row conforms to.
    /// Empty when the table's `RowStruct` couldn't be resolved (a
    /// `tracing::warn!` is logged at parse time — see the format doc's
    /// §RowStruct resolution failure).
    pub row_struct: String,
    /// One entry per table row, in wire order.
    pub rows: Vec<DataTableRow>,
    /// Class-level tagged properties (the `RowStruct` `ObjectProperty`,
    /// the strip flags `bStripFromClientBuilds` /
    /// `bStripFromDedicatedServerBuilds`, `bIgnoreExtraFields`,
    /// `bIgnoreMissingFields`, …). `JsonHandler` round-trips these into
    /// its output so JSON consumers keep the strip-flag state that
    /// determined whether the cooker emitted zero rows; `CsvHandler`
    /// ignores them (CSV has no schema for class-level metadata).
    pub class_properties: property::bag::PropertyBag,
}

impl DataTableData {
    /// Cheap, zero-allocation empty table — used as the discriminant
    /// sentinel when registering DataTable handlers in
    /// [`crate::export::HandlerRegistry::all_default_handlers`]
    /// (`std::mem::discriminant` ignores the payload). All fields are
    /// `Vec::new()` / `String::new()`; `class_properties` is an empty
    /// `Tree`.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            row_struct: String::new(),
            rows: Vec::new(),
            class_properties: property::bag::PropertyBag::tree(Vec::new()),
        }
    }
}

/// A single `UDataTable` row: a `RowName` plus the row's
/// tagged-property body (decoded against the shared `RowStruct`).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[non_exhaustive]
pub struct DataTableRow {
    /// The row's `RowName` (resolved from the package name table).
    pub name: String,
    /// The row body's decoded tagged properties, in wire order.
    pub properties: Vec<property::primitives::Property>,
}

/// Parsed contents of a `UTexture2D` export.
///
/// Phase 3e. Produced by `texture::texture2d::read_from`; consumed by
/// the upcoming `PngHandler` (3e-8).
///
/// **Grows across the 3e milestones.** As of 3e-2b it carries the
/// segment-1 tagged properties plus the full `FTexturePlatformData`
/// header (`size_x`, `size_y`, `pixel_format`, `num_slices`,
/// `is_cubemap`, `num_mips_in_tail`, `first_mip_to_serialize`,
/// `mip_count`); the decoded mip chain lands in 3e-3 and the
/// virtual-texture page-table data in its own milestone. The struct is
/// `#[non_exhaustive]` and constructed only inside this crate, so adding
/// fields is non-breaking — matching the [`DataTableData`] precedent.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[non_exhaustive]
pub struct Texture2DData {
    /// Segment-1 tagged properties (`SRGB`, `CompressionSettings`,
    /// `Filter`, `AddressX`/`AddressY`, `LODBias`, …), decoded by the
    /// standard `FPropertyTag` iterator. See
    /// `docs/formats/texture/texture2d.md` §"Segment 1".
    pub properties: property::bag::PropertyBag,
    /// Top-mip width in pixels (`FTexturePlatformData::SizeX`). Phase 3e-2.
    pub size_x: u32,
    /// Top-mip height in pixels (`FTexturePlatformData::SizeY`). Phase 3e-2.
    pub size_y: u32,
    /// `EPixelFormat` variant name (e.g. `"PF_DXT5"`) — drives mip-byte
    /// interpretation once the per-format decoders land. Phase 3e-2.
    pub pixel_format: String,
    /// Slice count from `PackedData` (`& 0x3FFF_FFFF`; `1` for a plain
    /// 2D texture). Follows CUE4Parse's `GetNumSlices()` convention of
    /// NOT stripping the overlapping `HasCpuCopy` bit. Phase 3e-2.
    pub num_slices: u32,
    /// Cubemap flag (`PackedData` bit 31). Phase 3e-2.
    pub is_cubemap: bool,
    /// `FOptTexturePlatformData::NumMipsInTail` — the count of trailing
    /// packed mips — when the optional-data record is present
    /// (`PackedData` bit 30), else `None`. Feeds 3e-3's mip-tail
    /// unpacking. The sibling `ExtData` is read-and-discarded (opaque
    /// platform extension data). Phase 3e-2b.
    pub num_mips_in_tail: Option<u32>,
    /// `FirstMipToSerialize` — the top-mip skip-count the cooker applied
    /// for downscaled platforms. Phase 3e-2b.
    pub first_mip_to_serialize: i32,
    /// Number of `FTexture2DMipMap` records that follow in segment 2
    /// (the mip-count prefix). The records themselves are read in 3e-3.
    /// Phase 3e-2b.
    pub mip_count: u32,
}

/// Bundle threading the parsed name/import/export tables, version, and
/// optional `.usmap` schema registry through downstream property
/// parsers (Phase 2b+).
///
/// **Thread safety:** `AssetContext: Send + Sync`. All components are
/// `Arc`-shared immutable data — safe to clone and share across
/// worker threads. Pinned by the `send_sync_assertions` test in
/// `lib.rs`.
///
/// `Arc`-wrapped components so `clone()` is a handful of atomic refcount
/// bumps — important because the GUI's PropertyInspector widget holds a
/// context across many event-loop ticks and must not block on table
/// copies. (`version` is `Copy`; `mappings` is `Option<Arc<_>>`.) Built
/// from a parsed [`Package`] via [`Package::context`].
///
/// Marked `#[non_exhaustive]` because additional version-gate fields
/// land here without a major bump (`custom_versions` shipped with #355;
/// future ones may follow). Construct via [`AssetContext::new`] or
/// [`Package::context`] — struct-literal construction is blocked at
/// the public-API boundary.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct AssetContext {
    /// The parsed FName pool (shared by all import/export references).
    pub names: Arc<NameTable>,
    /// The parsed import table.
    pub imports: Arc<ImportTable>,
    /// The parsed export table.
    pub exports: Arc<ExportTable>,
    /// Version constants the parsers branch on.
    pub version: AssetVersion,
    /// Per-plugin custom-version stamps from the package summary.
    /// Required by readers that gate wire-format fields on a specific
    /// plugin's local version (e.g., `FText::None` gates the
    /// `bHasCultureInvariantString` u32 on `FEditorObjectVersion`).
    /// `Arc`-wrapped to keep `clone()` refcount-cheap.
    pub custom_versions: Arc<custom_version::CustomVersionContainer>,
    /// Optional `.usmap` schema registry. Required when
    /// `summary.package_flags & PKG_UnversionedProperties != 0`; `None`
    /// for tagged-property packages (Phase 2b/2c). `Arc`-wrapped so
    /// multiple Phase 2f call paths can share one parsed `Usmap`
    /// without cloning the registry on every context clone.
    pub mappings: Option<Arc<mappings::Usmap>>,
}

impl AssetContext {
    /// Construct an `AssetContext`. The public constructor; the struct
    /// is `#[non_exhaustive]` so external callers cannot use a struct
    /// literal.
    #[must_use]
    pub fn new(
        names: Arc<NameTable>,
        imports: Arc<ImportTable>,
        exports: Arc<ExportTable>,
        version: AssetVersion,
        custom_versions: Arc<custom_version::CustomVersionContainer>,
        mappings: Option<Arc<mappings::Usmap>>,
    ) -> Self {
        Self {
            names,
            imports,
            exports,
            version,
            custom_versions,
            mappings,
        }
    }
}

#[cfg(all(test, feature = "__test_utils"))]
mod tests {
    use super::*;

    #[test]
    fn asset_generic_clone_and_debug() {
        // Phase 3 per-export shape: Asset::Generic wraps a single
        // export's PropertyBag (not the whole Package).
        let bag = crate::asset::property::bag::PropertyBag::opaque(vec![0u8; 32]);
        let asset = Asset::Generic(bag);
        let cloned = asset.clone();
        let dbg = format!("{cloned:?}");
        assert!(dbg.starts_with("Generic("), "got: {dbg}");
    }

    #[test]
    fn asset_generic_serializes_with_externally_tagged_shape() {
        // Pin the externally-tagged JSON shape: {"Generic": <PropertyBag JSON>}.
        // The inner PropertyBag has `#[serde(tag = "kind", rename_all = "snake_case")]`
        // so an Opaque bag renders as {"kind": "opaque", "bytes": <count>}.
        // Phase 3 sub-phases (3d-3h) add typed Asset variants (DataTable,
        // Texture2D, etc.) under sibling tags ("DataTable", "Texture2D", ...).
        let bag = crate::asset::property::bag::PropertyBag::opaque(vec![0u8; 32]);
        let asset = Asset::Generic(bag);
        let json = serde_json::to_string(&asset).unwrap();
        assert!(
            json.starts_with(r#"{"Generic":{"kind":"opaque""#),
            "expected externally-tagged Generic shape; got: {json}"
        );
        assert!(
            json.contains(r#""bytes":32"#),
            "expected PropertyBag::Opaque byte count; got: {json}"
        );
    }
}
