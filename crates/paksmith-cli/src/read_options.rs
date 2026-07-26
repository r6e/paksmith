//! The single construction point for a package read's optional inputs:
//! the `.usmap` schema registry (#651) and the profile's declared
//! engine version (#656).
//!
//! ADDING THE NEXT PARSE INPUT: add the field to
//! `paksmith_core::asset::ReadOptions`, then thread it through `build`
//! here — not through the `inspect`/`extract` call sites, which is what
//! left the #656 wiring untested. The same convention is recorded on
//! `ReadOptions` itself, so it is reachable from either end.
//!
//! Extracted as a PURE fn on purpose. Both consumers — `inspect::run`
//! and `ExtractJob::extract_asset` — are otherwise I/O-bound paths that
//! a test can only reach with a fixture pak containing an asset at the
//! ambiguous object version, which does not exist yet. Inline, the
//! wiring that delivers this whole feature was pinned by nothing: the
//! `.with_engine_version_hint(..)` call could be deleted from either
//! site and the entire gate battery stayed green. Here it is one
//! function with direct unit tests.
//!
//! Note on mutation coverage: CI's cargo-mutants job triggers on a
//! `paksmith-core*` path filter, so a CLI-ONLY change never re-runs it.
//! When it does run it is workspace-scoped and `--in-diff`, so these
//! lines are mutated whenever the same PR also touches core. The unit
//! tests below are therefore the primary guard, not the mutation run.

use std::sync::Arc;

use paksmith_core::asset::{ReadOptions, UeVersion, Usmap};

/// Assemble the read options for one package parse.
///
/// Both inputs are optional and INDEPENDENT: an explicit `--mappings`
/// with no profile yields a usmap and no hint, a profile with an
/// `engine_version` and no mappings source yields the reverse. Callers
/// pass the resolved usmap (explicit `--mappings` already having won
/// over the profile's source) and the context's engine version.
pub(crate) fn build(
    usmap: Option<&Arc<Usmap>>,
    engine_version: Option<UeVersion>,
) -> ReadOptions<'_> {
    ReadOptions::new()
        .with_mappings(usmap)
        .with_engine_version_hint(engine_version)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Option<UeVersion> {
        let parsed = UeVersion::parse_lenient(s);
        assert!(parsed.is_some(), "fixture version {s:?} must parse");
        parsed
    }

    /// The engine version reaches `ReadOptions`. Dropping the
    /// `.with_engine_version_hint(..)` call — which is precisely what
    /// was untested while this lived inline at two call sites — fails
    /// here.
    #[test]
    fn carries_the_engine_version_hint() {
        let opts = build(None, v("5.3"));
        assert_eq!(opts.engine_version_hint, v("5.3"));
    }

    /// A hint is carried through VERBATIM rather than normalized, so a
    /// patch component survives and an early version is not silently
    /// promoted.
    #[test]
    fn carries_the_hint_unmodified() {
        assert_eq!(build(None, v("5.3.2")).engine_version_hint, v("5.3.2"));
        assert_eq!(build(None, v("4.27")).engine_version_hint, v("4.27"));
    }

    /// No profile engine version ⇒ no hint, which is the pre-#656
    /// behaviour every existing call site relies on.
    #[test]
    fn no_engine_version_yields_no_hint() {
        assert_eq!(build(None, None).engine_version_hint, None);
    }

    /// The two inputs do not clobber each other. Uses a REAL usmap so
    /// the mappings arm is asymmetric to the `None` default — a
    /// `None`-only test would pass against a builder that dropped the
    /// argument entirely.
    #[test]
    fn both_inputs_compose() {
        let usmap = Arc::new(Usmap::default());
        let opts = build(Some(&usmap), v("5.3"));
        assert!(opts.mappings.is_some(), "mappings must survive");
        assert_eq!(
            opts.engine_version_hint,
            v("5.3"),
            "the hint must survive alongside mappings"
        );

        // …and mappings alone must not invent a hint.
        let opts = build(Some(&usmap), None);
        assert!(opts.mappings.is_some());
        assert_eq!(opts.engine_version_hint, None);
    }
}
