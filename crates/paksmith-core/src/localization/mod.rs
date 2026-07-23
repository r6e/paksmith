//! Standalone localization formats.
//!
//! `.locres` (`FTextLocalizationResource`) files are **not** UE
//! packages — no summary, name table, or export table — so this module
//! lives beside [`crate::asset`] rather than inside it (see
//! `docs/formats/data/locres.md` §Paksmith implementation). The
//! `.locmeta` companion format (different magic) is out of scope.

pub mod locres;

pub use locres::{LocresEntry, LocresNamespace, LocresResource, LocresVersion};
