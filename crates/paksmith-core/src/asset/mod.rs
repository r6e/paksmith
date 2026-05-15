//! UAsset deserialization.
//!
//! # Scope (Phase 2a)
//!
//! Parses the structural header of UE 4.21–UE 5.x `.uasset` files.
//! Property bodies (`FPropertyTag`-iterated payloads inside export
//! serialized regions) are carried as opaque bytes via the
//! `PropertyBag::Opaque` variant landing in a later task; tagged-
//! property iteration arrives in Phase 2b.
//!
//! # Module layout (Phase 2a, growing per-task)
//!
//! Phase 2a builds incrementally: each task in `docs/plans/phase-2a-
//! uasset-header.md` adds one submodule. This `mod.rs` re-exports the
//! types that have landed so far. The aggregate `Package::read_from`
//! plus `Asset` and `AssetContext` types land alongside the orchestrating
//! parser in a later task.
//!
//! See `docs/plans/phase-2a-uasset-header.md` for the implementation
//! plan and `docs/design/SPEC.md` § "Asset Data Model" for the
//! architectural intent.

pub mod engine_version;
pub(crate) mod fstring;
pub mod package_index;
pub mod version;

pub use engine_version::EngineVersion;
pub use package_index::PackageIndex;
pub use version::AssetVersion;

pub(crate) use fstring::read_asset_fstring;
