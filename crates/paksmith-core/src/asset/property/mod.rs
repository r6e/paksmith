//! Tagged property system for UAsset export bodies.
//!
//! Phase 2a shipped [`PropertyBag`]'s `Opaque` variant; Phase 2b adds
//! a `Tree` variant via the tagged-property iterator `read_properties`
//! (lands in Task 7).
//!
//! Sub-modules:
//! - [`bag`] — `PropertyBag` enum (migrated from `property_bag`)
//! - `tag` — `PropertyTag` wire reader (Phase 2b, Task 3)
//! - `primitives` — `Property`, `PropertyValue`, primitive readers (Phase 2b, Task 4)
//! - `text` — `FText` + `FTextHistory` (Phase 2b, Task 5)

pub mod bag;

pub use bag::PropertyBag;
// `MAX_PROPERTY_DEPTH` stays `pub(crate)` (matching the visibility on the
// existing constant — see bag.rs). Phase 2b's iterator in mod.rs will
// reference it as `bag::MAX_PROPERTY_DEPTH`; re-exporting a `pub(crate)`
// item as `pub` would be a privacy error (E0364).
