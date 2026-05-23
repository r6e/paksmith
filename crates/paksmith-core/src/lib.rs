//! Core library for parsing and extracting Unreal Engine game assets.
//!
//! **Phase 1 scope**: container readers for the `.pak` archive format
//! (see [`container::pak`]).
//!
//! **Phase 2a scope**: UAsset structural-header parsing —
//! [`asset::PackageSummary`] (`FPackageFileSummary`),
//! [`asset::NameTable`] (FName pool), [`asset::ImportTable`],
//! [`asset::ExportTable`].
//!
//! **Phase 2b scope** (current): tagged-property iteration —
//! [`asset::PropertyBag::Tree`] replaces `Opaque` for assets with
//! parseable FPropertyTag streams. Primitive property payloads
//! (Bool, Int variants, Float, Double, Str, Name, Enum, Text) are
//! decoded; container/unknown types skip via `tag.size` →
//! `PropertyValue::Unknown`. Assets with `PKG_UnversionedProperties`
//! are rejected with a typed fault. Parse errors mid-iteration fall
//! back to [`asset::PropertyBag::Opaque`] with a `tracing::warn!`
//! event.
//!
//! IoStore container reading, format handlers, and game profile
//! management remain planned per `docs/plans/ROADMAP.md`.

pub mod asset;
pub mod container;
pub mod digest;
pub mod error;

mod seams;

/// Test-utility surface shared between in-source tests and the
/// integration suite under `tests/`. Gated behind the
/// `__test_utils` feature so production builds never compile or
/// expose it. Issue #68 promoted the v10+ fixture builder out of
/// the in-source test module so the integration proptest doesn't
/// need to duplicate ~30 lines of wire-format assembly.
#[cfg(feature = "__test_utils")]
pub mod testing;

pub use digest::Sha1Digest;
pub use error::PaksmithError;

/// Convenience alias for `Result<T, PaksmithError>`.
pub type Result<T> = std::result::Result<T, PaksmithError>;

// Top-level public-API re-exports so consumers can write
// `use paksmith_core::{Package, Asset, PropertyBag, PropertyValue, Usmap};`
// instead of reaching into `asset::*` and `asset::property::*`. Mirrors
// the convention established for [`Sha1Digest`] and [`PaksmithError`].
//
// **One-way serialization note:** [`Package`] and [`Asset`] implement
// `Serialize` only — their JSON output is intentionally lossy
// (view-based FName resolution + byte-count `Opaque`). Most other
// serializable types re-exported below also implement `Deserialize`
// with caveats documented on the type itself (e.g.,
// [`EngineVersion`] drops the licensee bit; [`PropertyBag::Opaque`]
// reconstructs zero-filled bytes from the count). [`AssetContext`]
// and [`PackageIndexError`] are runtime-only (no serde at all).
// See each type's docs for the round-trip contract.
//
// **`#[non_exhaustive]` + `Deserialize` caveat:** `#[non_exhaustive]`
// types ([`PropertyBag`], [`PropertyValue`], `FTextHistory`) DO permit
// future variants without a source-breaking match, but adding a new
// variant IS a JSON wire-compatibility break for `Deserialize`
// consumers — serde rejects unknown tag discriminants by default.
// Pin against specific paksmith versions if you rely on bidirectional
// JSON round-trips of stored content.
pub use asset::property::text::{FText, FTextHistory};
pub use asset::property::{MapEntry, Property, PropertyValue};
pub use asset::{
    Asset, AssetContext, AssetVersion, CustomVersion, CustomVersionContainer, EngineVersion,
    ExportTable, FGuid, FName, ImportTable, NameTable, ObjectExport, ObjectImport, Package,
    PackageIndex, PackageIndexError, PackageSummary, PropertyBag, Usmap,
};
