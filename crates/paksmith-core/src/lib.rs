//! Core library for parsing and extracting Unreal Engine game assets.
//!
//! **Phase 1 scope**: container readers for the `.pak` archive format
//! (see [`container::pak`]).
//!
//! **Phase 2a scope** (current): UAsset structural-header parsing —
//! [`asset::PackageSummary`] (`FPackageFileSummary`),
//! [`asset::NameTable`] (FName pool), [`asset::ImportTable`],
//! [`asset::ExportTable`], with property bodies carried as opaque
//! byte payloads via [`asset::PropertyBag::Opaque`]. Tagged-property
//! iteration lands in Phase 2b.
//!
//! IoStore container reading, format handlers, and game profile
//! management remain planned per `docs/plans/ROADMAP.md`.

pub mod asset;
pub mod container;
pub mod digest;
pub mod error;

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
