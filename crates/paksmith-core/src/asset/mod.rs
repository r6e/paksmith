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
