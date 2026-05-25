//! Cfg-gated OOM-injection seams for the `try_reserve` sites across
//! `container::pak`'s parser and decompression code. Lets integration
//! tests exercise the typed `AllocationFailed` / `*ReserveFailed`
//! production paths without relying on real allocator pressure.
//!
//! Gated behind the `__test_utils` feature; production builds never
//! compile this module. The [`SeamSite`], [`PakSeam`], and
//! [`AssetSeam`] types themselves live in the always-compiled
//! `crate::seams` module so production helpers like
//! `crate::error::try_reserve_index` (mandatory `PakSeam`) and
//! `crate::error::try_reserve_asset` (mandatory `AssetSeam`) can
//! accept seam parameters regardless of feature configuration; only
//! the runtime `maybe_fail_at` / [`arm_at`] dispatch lives here. [`SeamSite`] is
//! re-exported from this module to preserve the
//! `paksmith_core::testing::oom::SeamSite` external path used by the
//! integration suite under `tests/`.
//!
//! Arm state lives in a per-thread array indexed by [`SeamSite`], so
//! parallel test threads don't interfere. Production decompression and
//! parser code runs synchronously on the calling thread, so the seam
//! fires on the same thread as the arming test.
//!
//! The synthetic [`TryReserveError`] returned on failure comes from a
//! real failed allocation (`Vec::<u8>::new().try_reserve_exact(usize::MAX)`),
//! which trips `RawVec`'s `isize::MAX` capacity guard before the
//! allocator is consulted. Tests should match on the typed fault
//! variant + structured fields rather than the inner `TryReserveError`'s
//! Display or `kind()` — forward-compat insurance.

use std::cell::Cell;
use std::collections::TryReserveError;
use std::marker::PhantomData;

pub use crate::seams::{AssetSeam, PakSeam, SeamSite};

thread_local! {
    /// Per-seam arm state, one slot per [`SeamSite`] discriminant.
    /// `None` = unarmed; `Some(n)` = pass the next `n` invocations,
    /// fail (and auto-disarm) on the `(n+1)`th.
    static ARM_STATE: [Cell<Option<u64>>; SeamSite::COUNT] =
        const { [const { Cell::new(None) }; SeamSite::COUNT] };
}

/// RAII guard returned by [`arm_at`]; its `Drop` impl calls
/// [`disarm`] on the current thread (clearing ALL armed sites, not
/// just the one the guard was issued for — this matches the prior
/// per-site design where disarm was global). The `#[must_use]`
/// attribute makes `arm_at(...);` (with no binding) a compile-time
/// warning so tests can't accidentally arm without owning the
/// cleanup.
///
/// Bind it to a named local (`let _guard = arm_at(...)`) — never
/// `let _ = arm_at(...)`, which drops the guard immediately and
/// makes the arm state vanish before the production code runs.
#[must_use = "DisarmGuard must be bound to a named local (`let _guard = arm_at(...)`); \
              `let _ = ...` drops the guard immediately and disarms before the seam fires"]
pub struct DisarmGuard {
    // `PhantomData<*const ()>` opts out of `Send`/`Sync` so the guard
    // can't be moved to a different thread (where `Drop` would call
    // `disarm()` on the wrong thread's arm state, leaving the
    // arming thread's state leaked). The arm cells are already
    // thread-local; this makes the thread-locality structural rather
    // than discipline-enforced.
    //
    // Named (not tuple) so the lack of `pub` is unambiguous on
    // inspection — tuple syntax can be misread as a public
    // constructor.
    _opt_out: PhantomData<*const ()>,
}

impl Drop for DisarmGuard {
    fn drop(&mut self) {
        disarm();
    }
}

/// Arm OOM injection at `site`. The next `skip_count` invocations of
/// the corresponding seam pass through; the `(skip_count + 1)`th
/// returns `Err` and auto-disarms. Pass `0` to fail the very next
/// invocation. Affects only the calling thread.
///
/// `pub` for `paksmith-core-tests`'s integration suite (the only
/// expected external caller); `#[doc(hidden)]` so it doesn't surface
/// in workspace-consumer rustdoc if `__test_utils` is transitively
/// activated via Cargo feature unification.
#[doc(hidden)]
pub fn arm_at(site: SeamSite, skip_count: u64) -> DisarmGuard {
    ARM_STATE.with(|cells| cells[site.slot()].set(Some(skip_count)));
    DisarmGuard {
        _opt_out: PhantomData,
    }
}

/// Production-side seam check at `site`. Returns `Err` with a
/// synthetic [`TryReserveError`] when armed and the skip-counter has
/// reached zero; otherwise `Ok`.
///
/// `pub(crate)` rather than `pub` because the only legitimate callers
/// are the production sites in `crate::container::pak` and the
/// always-compiled `crate::seams` / `crate::error::try_reserve_index`
/// helpers; integration tests drive the seams via [`arm_at`] + the
/// production code path. `pub(crate)` makes the wrong-call boundary
/// structural rather than docs-only.
pub(crate) fn maybe_fail_at(site: SeamSite) -> Result<(), TryReserveError> {
    if take_arm(site) {
        Err(synthetic_try_reserve_error())
    } else {
        Ok(())
    }
}

/// Disarm all OOM injection seams on the calling thread. Normally
/// called via the [`DisarmGuard`] returned by [`arm_at`]; exposed
/// directly for the rare case where a test wants to re-arm mid-flight
/// without dropping the existing guard.
pub fn disarm() {
    ARM_STATE.with(|cells| {
        for cell in cells {
            cell.set(None);
        }
    });
}

fn take_arm(site: SeamSite) -> bool {
    ARM_STATE.with(|cells| {
        let cell = &cells[site.slot()];
        match cell.get() {
            None => false,
            Some(0) => {
                cell.set(None);
                true
            }
            Some(n) => {
                cell.set(Some(n - 1));
                false
            }
        }
    })
}

fn synthetic_try_reserve_error() -> TryReserveError {
    // `usize::MAX` exceeds the `RawVec` `isize::MAX` capacity guard,
    // so this fails synchronously inside stdlib before the allocator
    // is consulted. Platform-invariant on every supported target; if
    // this ever returns `Ok`, the stdlib `RawVec` invariants have
    // changed and the synthesis path needs revisiting.
    Vec::<u8>::new()
        .try_reserve_exact(usize::MAX)
        .expect_err("usize::MAX byte reservation must fail (capacity overflow on isize::MAX guard)")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Arming one site must not fire at a different site. Pins the
    /// per-site isolation the array-indexed design provides.
    #[test]
    fn arm_at_isolates_per_site() {
        let _guard = arm_at(SeamSite::Pak(PakSeam::FstringUtf8), 0);
        // Unrelated site stays unarmed.
        assert!(maybe_fail_at(SeamSite::Pak(PakSeam::FstringUtf16)).is_ok());
        assert!(maybe_fail_at(SeamSite::Pak(PakSeam::CompressedReserve)).is_ok());
        assert!(maybe_fail_at(SeamSite::Pak(PakSeam::ScratchReserve)).is_ok());
        assert!(maybe_fail_at(SeamSite::Pak(PakSeam::FdiFullPath)).is_ok());
        // The armed site fires.
        assert!(maybe_fail_at(SeamSite::Pak(PakSeam::FstringUtf8)).is_err());
        // ...and auto-disarms after firing.
        assert!(maybe_fail_at(SeamSite::Pak(PakSeam::FstringUtf8)).is_ok());
    }

    /// `arm_at(site, n)` passes the next `n` invocations and fails
    /// the `(n+1)`th, as documented.
    #[test]
    fn arm_at_skip_count_passes_n_then_fails() {
        let _guard = arm_at(SeamSite::Pak(PakSeam::ScratchReserve), 2);
        // First two invocations pass.
        assert!(maybe_fail_at(SeamSite::Pak(PakSeam::ScratchReserve)).is_ok());
        assert!(maybe_fail_at(SeamSite::Pak(PakSeam::ScratchReserve)).is_ok());
        // Third invocation fails (skip_count + 1 = 3rd).
        assert!(maybe_fail_at(SeamSite::Pak(PakSeam::ScratchReserve)).is_err());
        // Auto-disarmed.
        assert!(maybe_fail_at(SeamSite::Pak(PakSeam::ScratchReserve)).is_ok());
    }

    /// `synthetic_try_reserve_error` must keep tripping `RawVec`'s
    /// `isize::MAX` capacity guard synchronously inside stdlib. If
    /// that synthesis path ever changes (e.g., a future `RawVec`
    /// rewrite delegates to the allocator for the `usize::MAX`
    /// case), every armed-seam test in `tests/oom_pak.rs` would
    /// start failing simultaneously with no signal pointing at the
    /// cause. Pinning the variant here surfaces that drift at the
    /// helper instead.
    #[test]
    fn synthetic_try_reserve_error_trips_capacity_guard() {
        let err = synthetic_try_reserve_error();
        let debug = format!("{err:?}");
        assert!(
            debug.contains("CapacityOverflow"),
            "stdlib may have changed `try_reserve_exact(usize::MAX)` \
             behavior — revisit testing::oom synthesis. Debug: {debug}"
        );
    }

    /// `DisarmGuard` Drop clears state across all sites, not just
    /// the one the guard was issued for. Matches the prior global-
    /// disarm semantics that integration tests rely on.
    #[test]
    fn disarm_guard_clears_all_sites_on_drop() {
        {
            let _guard_a = arm_at(SeamSite::Pak(PakSeam::FstringUtf8), 100);
            let _guard_b = arm_at(SeamSite::Pak(PakSeam::FdiFullPath), 100);
            // Both armed.
            // Drop both guards at scope exit.
        }
        // After drop: both sites are unarmed.
        assert!(maybe_fail_at(SeamSite::Pak(PakSeam::FstringUtf8)).is_ok());
        assert!(maybe_fail_at(SeamSite::Pak(PakSeam::FdiFullPath)).is_ok());
    }

    /// `DisarmGuard::drop` runs on panic unwind — the actual
    /// invariant RAII was chosen to provide. Without this, a
    /// `#[should_panic]` test or a test-body panic between `arm_at`
    /// and the production call would leak arm state into the next
    /// test on the same thread. Requires the default `panic =
    /// "unwind"` setting (the workspace uses it; this test would
    /// abort under `panic = "abort"` and surface that mismatch).
    #[test]
    fn disarm_guard_drops_on_panic_unwind() {
        // Make sure no prior test leaked arm state onto this thread.
        disarm();
        let result = std::panic::catch_unwind(|| {
            let _guard = arm_at(SeamSite::Pak(PakSeam::CompressedReserve), 100);
            panic!("intentional panic to exercise guard unwind drop");
        });
        assert!(result.is_err(), "catch_unwind must observe the panic");
        // Guard's Drop ran during unwind → arm state cleared.
        assert!(
            maybe_fail_at(SeamSite::Pak(PakSeam::CompressedReserve)).is_ok(),
            "arm state leaked across panic unwind — DisarmGuard::drop did not fire"
        );
    }
}
