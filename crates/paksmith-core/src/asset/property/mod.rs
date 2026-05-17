//! Tagged property system for UAsset export bodies.
//!
//! Phase 2a shipped [`PropertyBag`]'s `Opaque` variant; Phase 2b adds
//! a `Tree` variant (lands in Task 7) populated by the tagged-property
//! iterator `read_properties` (lands in Task 6).
//!
//! Sub-modules:
//! - [`bag`] — `PropertyBag` enum (migrated from `property_bag`)
//! - `tag` — `PropertyTag` wire reader (Phase 2b, Task 3)
//! - `primitives` — `Property`, `PropertyValue`, primitive readers (Phase 2b, Task 4)
//! - `text` — `FText` + `FTextHistory` (Phase 2b, Task 5)

pub mod bag;

pub use bag::PropertyBag;
// `MAX_PROPERTY_DEPTH` stays `pub(crate)` in `bag` (matching every other
// in-crate parser cap — see bag.rs). Phase 2b's `read_properties`
// iterator (lands in Task 6, in this `mod.rs`) and Phase 2c's recursive
// container readers (sibling sub-modules) reach it via
// `bag::MAX_PROPERTY_DEPTH` / `super::bag::MAX_PROPERTY_DEPTH`;
// re-exporting a `pub(crate)` item as `pub` from here would be a
// privacy error (E0364).
