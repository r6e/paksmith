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

pub mod version;

pub use version::AssetVersion;

/// Compile-time pin: `read_fstring` is reachable from this module via
/// the `pub(crate)` re-export at [`crate::container::pak::index`].
/// The `use` import below would fail to resolve if visibility
/// regressed; later tasks (e.g., the FName / NameTable parsers) will
/// remove this anchor when they import `read_fstring` for real.
#[allow(unused_imports)]
use crate::container::pak::index::read_fstring as _phase_2a_fstring_anchor;
