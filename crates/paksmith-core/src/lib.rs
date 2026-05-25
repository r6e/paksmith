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

/// Compile-time `Send + Sync` assertions on the public-API type
/// surface.
///
/// `assert_send_sync::<T>()` has an empty body; the bounds check
/// happens at compile time when each call is monomorphized. Any
/// future PR that introduces an `Rc`, `RefCell`, or other `!Send` /
/// `!Sync` field deep inside any listed type fails this test at
/// `cargo build --tests`, surfacing the regression before it lands
/// in a downstream consumer's build.
///
/// Issue #387 motivated the guard — a thread-safety audit verified
/// every public type was `Send + Sync` by structural inspection but
/// found no automated check protecting that invariant as the type
/// hierarchy grew. Adding `Usmap::flattened_cache` (issue #370) or
/// future Phase 3+ types would otherwise risk a silent regression.
#[cfg(test)]
mod send_sync_assertions {
    use super::*;
    use crate::asset::mappings::{
        ClassSchema, MappedProperty, MappedPropertyType, ResolvedProperty,
    };
    use crate::container::pak::footer::PakFooter;
    use crate::container::pak::index::{PakIndex, PakIndexEntry};
    use crate::container::pak::version::PakVersion;
    use crate::container::pak::{PakReader, RegionVerifyState, VerifyOutcome, VerifyStats};
    use crate::container::{ContainerFormat, EntryFlags, EntryMetadata};
    use crate::error::{
        AssetParseFault, CompanionFileKind, DecompressionFault, IndexParseFault,
        InvalidFooterFault, MappingsAllocationContext, MappingsParseFault,
    };

    // Empty-body bounds check; the assertion happens at
    // monomorphization. Plain `fn` (not `const fn`) — there is no
    // `const`-context caller and the `const` keyword would only
    // suggest some compile-time evaluation that doesn't exist.
    fn assert_send_sync<T: Send + Sync + 'static>() {}

    #[test]
    fn public_types_are_send_sync() {
        // Container surface
        assert_send_sync::<PakReader>();
        // Direct fields of `PakReader` (`PakFooter`, `PakVersion`,
        // `PakIndex` + its `PakIndexEntry` rows) are transitively
        // covered today, but explicit assertions lockpin them
        // against a future refactor that converts a field to a
        // `OnceCell`-style lazy wrapper — which would silently
        // remove the inner type from the transitive `Send + Sync`
        // graph.
        assert_send_sync::<PakFooter>();
        assert_send_sync::<PakVersion>();
        assert_send_sync::<PakIndex>();
        assert_send_sync::<PakIndexEntry>();
        // Container-trait return types — NOT stored on `PakReader`,
        // so transitive coverage doesn't apply. Explicit assertions
        // close the gap. `EntryFlags` is consumed by
        // `EntryMetadata::new` (not stored on `EntryMetadata`), so
        // it gets its own pin rather than relying on transitivity.
        assert_send_sync::<ContainerFormat>();
        assert_send_sync::<EntryMetadata>();
        assert_send_sync::<EntryFlags>();
        // `PakReader::verify_*` return types — also NOT stored on
        // `PakReader`. Lockpinned explicitly.
        assert_send_sync::<VerifyOutcome>();
        assert_send_sync::<VerifyStats>();
        assert_send_sync::<RegionVerifyState>();

        // Asset top-level
        assert_send_sync::<Asset>();
        assert_send_sync::<AssetContext>();
        assert_send_sync::<Package>();
        assert_send_sync::<PackageSummary>();
        assert_send_sync::<AssetVersion>();
        assert_send_sync::<EngineVersion>();

        // Name / index / GUID
        assert_send_sync::<FName>();
        assert_send_sync::<FGuid>();
        assert_send_sync::<NameTable>();
        assert_send_sync::<PackageIndex>();
        assert_send_sync::<PackageIndexError>();

        // Tables
        assert_send_sync::<ImportTable>();
        assert_send_sync::<ObjectImport>();
        assert_send_sync::<ExportTable>();
        assert_send_sync::<ObjectExport>();
        assert_send_sync::<CustomVersion>();
        assert_send_sync::<CustomVersionContainer>();

        // Properties
        assert_send_sync::<PropertyBag>();
        assert_send_sync::<Property>();
        assert_send_sync::<PropertyValue>();
        assert_send_sync::<MapEntry>();
        assert_send_sync::<FText>();
        assert_send_sync::<FTextHistory>();

        // Mappings (.usmap)
        assert_send_sync::<Usmap>();
        assert_send_sync::<ClassSchema>();
        assert_send_sync::<MappedProperty>();
        assert_send_sync::<MappedPropertyType>();
        assert_send_sync::<ResolvedProperty>();

        // Digest / errors
        assert_send_sync::<Sha1Digest>();
        assert_send_sync::<PaksmithError>();
        assert_send_sync::<InvalidFooterFault>();
        assert_send_sync::<DecompressionFault>();
        assert_send_sync::<IndexParseFault>();
        assert_send_sync::<AssetParseFault>();
        assert_send_sync::<MappingsParseFault>();
        assert_send_sync::<MappingsAllocationContext>();
        assert_send_sync::<CompanionFileKind>();
    }
}
