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

pub mod custom_version;
pub mod engine_version;
pub mod export_table;
pub(crate) mod fstring;
pub mod guid;
pub mod import_table;
pub mod name_table;
pub mod package;
pub mod package_index;
pub mod property_bag;
pub mod summary;
pub mod version;
pub mod wire;

pub use custom_version::{CustomVersion, CustomVersionContainer};
pub use engine_version::EngineVersion;
pub use export_table::{ExportTable, ObjectExport};
pub use guid::FGuid;
pub use import_table::{ImportTable, ObjectImport};
pub use name_table::{FName, NameTable};
pub use package::Package;
pub use package_index::PackageIndex;
pub use property_bag::PropertyBag;
pub use summary::PackageSummary;
pub use version::AssetVersion;

pub(crate) use fstring::read_asset_fstring;
#[cfg(any(test, feature = "__test_utils"))]
pub(crate) use fstring::write_asset_fstring;
pub(crate) use package_index::read_package_index;
pub(crate) use wire::read_bool32;
#[cfg(any(test, feature = "__test_utils"))]
pub(crate) use wire::write_bool32;

/// Top-level domain type for a deserialized UE asset.
///
/// Phase 2a ships only the [`Self::Generic`] variant carrying a
/// [`Package`] (structural header plus opaque payload bytes).
/// Specialized variants (`Texture`, `StaticMesh`, etc., per
/// `docs/design/SPEC.md`) land in Phase 3 once the property system
/// can decode them.
///
/// `#[non_exhaustive]` so downstream consumers can pattern-match with
/// `_` and survive future variant additions.
///
/// The default `#[derive(Serialize)]` form produces an externally-
/// tagged JSON object (`{"Generic": <Package JSON>}`). Externally-
/// tagged was chosen over `#[serde(untagged)]` precisely because
/// future variants will need a discriminator: locking in the tag
/// shape now lets Phase 3 add `Texture` / `StaticMesh` without a
/// breaking serialization shape change for `Asset::Generic` consumers
/// who already match on the tag. (The `paksmith inspect` CLI command
/// serializes the inner `Package` directly, not the `Asset` wrapper,
/// so this tag does not appear in the inspect JSON output.)
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub enum Asset {
    /// The universal fallback: structural header + opaque payload.
    Generic(Package),
}

/// Bundle threading the parsed name/import/export tables and version
/// through downstream property parsers (Phase 2b+).
///
/// `Arc`-wrapped components so `clone()` is three atomic refcount bumps —
/// important because the GUI's PropertyInspector widget holds a
/// context across many event-loop ticks and must not block on table
/// copies. (The fourth field, `version`, is `Copy`.) Built from a
/// parsed [`Package`] via [`Package::context`].
#[derive(Debug, Clone)]
pub struct AssetContext {
    /// The parsed FName pool (shared by all import/export references).
    pub names: Arc<NameTable>,
    /// The parsed import table.
    pub imports: Arc<ImportTable>,
    /// The parsed export table.
    pub exports: Arc<ExportTable>,
    /// Version constants the parsers branch on.
    pub version: AssetVersion,
}

#[cfg(all(test, feature = "__test_utils"))]
mod tests {
    use super::*;
    use crate::testing::uasset::{MinimalPackage, build_minimal_ue4_27};

    #[test]
    fn asset_generic_clone_and_debug() {
        let MinimalPackage { bytes, .. } = build_minimal_ue4_27();
        let pkg = Package::read_from(&bytes, "test.uasset").unwrap();
        let asset = Asset::Generic(pkg);
        // Clone path — exercises both the enum's derived Clone and the
        // inner Package's Clone (which Arc-shares NameTable contents
        // via FName's Arc<str>).
        let cloned = asset.clone();
        // Debug formatting — derived form. Just verify it produces
        // something non-empty containing the variant name; pinning the
        // exact string is brittle across rustc minor versions.
        let dbg = format!("{cloned:?}");
        assert!(dbg.starts_with("Generic("), "got: {dbg}");
    }

    #[test]
    fn asset_generic_serializes_with_externally_tagged_shape() {
        // Pin the externally-tagged JSON shape: {"Generic": <Package>}.
        // Documented in Asset's doc comment as the forward-compat form
        // for Phase 3's Texture / StaticMesh variants. If a future
        // refactor adds `#[serde(untagged)]` or `#[serde(tag = ...)]`,
        // this test catches the shape break.
        let MinimalPackage { bytes, .. } = build_minimal_ue4_27();
        let pkg = Package::read_from(&bytes, "test.uasset").unwrap();
        let asset = Asset::Generic(pkg);
        let json = serde_json::to_string(&asset).unwrap();
        assert!(
            json.starts_with(r#"{"Generic":{"#),
            "expected externally-tagged shape; got: {json}"
        );
        assert!(
            json.ends_with("}}"),
            "expected wrapping object; got: {json}"
        );
        // The inner Package JSON must still surface its own fields —
        // verify a load-bearing sentinel (asset_path) is present so a
        // bug that silently elides the inner serialization is caught.
        assert!(
            json.contains(r#""asset_path":"test.uasset""#),
            "got: {json}"
        );
    }
}
