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
