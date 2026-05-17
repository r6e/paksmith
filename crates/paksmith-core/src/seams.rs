//! Crate-internal `seam_check!` macro for OOM-injection sites.
//!
//! Production parser/decompression code at each `try_reserve` site
//! invokes [`seam_check!`] to fold a possible synthetic OOM failure
//! into the result. When the `__test_utils` feature is OFF, the
//! macro expands to nothing and the production code path runs
//! unmodified.
//!
//! This module lives outside `crate::testing` (which is itself
//! `__test_utils`-feature-gated) so the macro is callable at every
//! production site regardless of feature configuration; the cfg
//! gate sits inside the macro body. See issue #266.

/// Fold an OOM-injection seam check into an existing `Result<(),
/// TryReserveError>` binding by name. Expansion when `__test_utils`
/// is on:
///
/// ```text
/// let $binding = $binding
///     .and_then(|()| maybe_fail_at($site));
/// ```
///
/// Expansion when `__test_utils` is off: empty — the production
/// code path is unmodified and the seam compiles out entirely.
///
/// `$binding` names an existing `let` binding the macro shadows;
/// `$site` is a [`crate::testing::oom::SeamSite`] variant.
///
/// `and_then` short-circuits when `$binding` is already `Err`, so a
/// real allocation failure takes precedence over the test-armed
/// synthetic one — armed seams only force failure at sites where
/// the real allocation would have succeeded.
macro_rules! seam_check {
    ($binding:ident, $site:expr) => {
        #[cfg(feature = "__test_utils")]
        let $binding = $binding.and_then(|()| $crate::testing::oom::maybe_fail_at($site));
    };
}

pub(crate) use seam_check;

#[cfg(all(test, feature = "__test_utils"))]
mod tests {
    use std::collections::TryReserveError;

    use crate::testing::oom::{SeamSite, arm_at};

    /// Armed seam turns `Ok(())` into `Err(_)`. Pins the basic
    /// macro-expansion contract.
    #[test]
    fn seam_check_fires_when_armed() {
        let _guard = arm_at(SeamSite::CompressedReserve, 0);
        let result: Result<(), TryReserveError> = Ok(());
        seam_check!(result, SeamSite::CompressedReserve);
        assert!(result.is_err(), "armed seam must turn Ok into Err");
    }

    /// Unarmed seam passes `Ok(())` through unchanged.
    #[test]
    fn seam_check_passes_when_unarmed() {
        let result: Result<(), TryReserveError> = Ok(());
        seam_check!(result, SeamSite::FdiFullPath);
        assert!(result.is_ok(), "unarmed seam must passthrough Ok");
    }

    /// When the binding is already `Err`, `and_then` short-circuits
    /// — the seam is NOT consumed and the original error is
    /// preserved. This is the load-bearing invariant: a real
    /// allocation failure always wins over an armed synthetic one,
    /// so tests can't accidentally mask real OOMs.
    #[test]
    fn seam_check_preserves_prior_error_without_consuming_arm() {
        let _guard = arm_at(SeamSite::ScratchReserve, 0);
        let original = Vec::<u8>::new()
            .try_reserve_exact(usize::MAX)
            .expect_err("synthetic capacity-overflow must fail");
        let result: Result<(), TryReserveError> = Err(original);
        seam_check!(result, SeamSite::ScratchReserve);
        assert!(result.is_err(), "original error must propagate");
        // Arm state must NOT have been consumed by the short-circuit.
        let probe = crate::testing::oom::maybe_fail_at(SeamSite::ScratchReserve);
        assert!(
            probe.is_err(),
            "seam was incorrectly consumed despite Err short-circuit"
        );
    }
}
