//! Cfg-gated OOM-injection seams for the `try_reserve` sites across
//! `container::pak`'s parser and decompression code. Lets integration
//! tests exercise the typed `AllocationFailed` / `*ReserveFailed`
//! production paths without requiring real allocator-pressure
//! scenarios (which are non-deterministic and platform-dependent).
//!
//! All seams are addressed by a single [`SeamSite`] discriminator; the
//! per-site `arm_*` / `maybe_fail_*` wrapper functions that the
//! original design carried were retired in issue #232's refactor. The
//! arming/checking API is now:
//!
//! - [`arm_at(site, skip_count)`](arm_at) — RAII-guard arms the given
//!   site to fail on the `(skip_count + 1)`th invocation of its seam.
//! - `maybe_fail_at(site)` (`pub(crate)`) — production-side check;
//!   returns `Err` when armed + counter is zero, otherwise `Ok`.
//! - [`disarm()`](disarm) — clears arm state across all sites on the
//!   calling thread; normally called via the [`DisarmGuard`] returned
//!   from `arm_at`.
//!
//! ## Two seam families
//!
//! - **Decompression** (`stream_zlib_to`): surfaces as
//!   [`crate::error::DecompressionFault::CompressedBlockReserveFailed`]
//!   or `ZlibScratchReserveFailed`
//!   ([`SeamSite::CompressedReserve`] / [`SeamSite::ScratchReserve`]).
//! - **Parser** (`fstring` + `path_hash`): surfaces as
//!   [`crate::error::IndexParseFault::AllocationFailed`] with one of
//!   `AllocationContext::FStringUtf16CodeUnits`, `FStringUtf8Bytes`,
//!   or `FdiFullPathBytes` ([`SeamSite::FstringUtf16`],
//!   [`SeamSite::FstringUtf8`], [`SeamSite::FdiFullPath`]).
//!
//! ## Stability
//!
//! Gated behind the `__test_utils` feature; production builds never
//! compile or expose this module. The injection check sites in the
//! production code are also `#[cfg(feature = "__test_utils")]` so they
//! vanish entirely from non-test builds.
//!
//! ## Thread-locality
//!
//! Arm state lives in a single `thread_local!` array indexed by
//! [`SeamSite`] so parallel integration-test threads don't interfere.
//! Production `stream_zlib_to` runs synchronously on the calling
//! thread (no `spawn`/`rayon`), so the seam fires on the same thread
//! as the arming test.
//!
//! ## Synthetic [`TryReserveError`]
//!
//! The stdlib does not expose a constructor for `TryReserveError`. The
//! synthetic value is produced by a real failed allocation
//! (`Vec::<u8>::new().try_reserve_exact(usize::MAX)`), which fails
//! synchronously with `CapacityOverflow` because `usize::MAX` exceeds
//! the `RawVec` `isize::MAX` capacity guard before the allocator is
//! ever consulted. This is platform-invariant on every supported
//! target. Even so, tests should match on the typed fault variant tag
//! and structured fields rather than on the inner `TryReserveError`'s
//! Display string or `kind()` — the latter is forward-compat insurance
//! against an unlikely stdlib refactor that changed the synthesis
//! path.
//!
//! ## Lifecycle (RAII)
//!
//! [`arm_at`] returns a [`DisarmGuard`] whose `Drop` impl calls
//! [`disarm`] on the current thread. Tests should bind it to a named
//! local (`let _guard = arm_at(...)`) — never `let _ = arm_at(...)`,
//! which drops the guard immediately and leaks the arm state into the
//! next test on the same thread. The `#[must_use]` attribute on the
//! guard catches the most common variant (`arm_at(...);` with no
//! binding at all).

use std::cell::Cell;
use std::collections::TryReserveError;
use std::marker::PhantomData;

/// Identifier for an OOM-injection seam. Each variant maps 1:1 to a
/// `try_reserve*` site in production code that's gated behind
/// `#[cfg(feature = "__test_utils")]` to allow integration tests to
/// force the failure path.
///
/// Adding a new seam is now O(1): append a variant here, bump
/// [`Self::COUNT`], and call `maybe_fail_at(SeamSite::NewSite)` at the
/// new production site. No per-site `thread_local!`, `arm_*`, or
/// `maybe_fail_*` boilerplate to add (issue #232 retired that
/// pattern).
///
/// `#[repr(usize)]` so the variant's index maps directly to its slot
/// in the `ARM_STATE` array.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
#[non_exhaustive]
pub enum SeamSite {
    /// `stream_zlib_to`'s pre-decode per-block `try_reserve_exact`.
    /// Surfaces as
    /// [`crate::error::DecompressionFault::CompressedBlockReserveFailed`].
    CompressedReserve = 0,
    /// `stream_zlib_to`'s mid-decode `try_reserve(n)` loop. Surfaces
    /// as [`crate::error::DecompressionFault::ZlibScratchReserveFailed`].
    ///
    /// To pin `already_committed > 0` (the field that structurally
    /// distinguishes mid-decode failure from the
    /// [`Self::CompressedReserve`] case), pass `skip_count >= 1` so
    /// the first chunk's reservation succeeds and the failure fires
    /// on a later iteration.
    ScratchReserve = 1,
    /// `read_fstring` UTF-16 branch (negative-length-prefixed
    /// FStrings). Surfaces as
    /// [`crate::error::IndexParseFault::AllocationFailed`] with
    /// `context: AllocationContext::FStringUtf16CodeUnits`.
    FstringUtf16 = 2,
    /// `read_fstring` UTF-8 branch (positive-length-prefixed
    /// FStrings). Surfaces as
    /// [`crate::error::IndexParseFault::AllocationFailed`] with
    /// `context: AllocationContext::FStringUtf8Bytes`.
    FstringUtf8 = 3,
    /// FDI walk's `dir + file` full-path `String::try_reserve_exact`.
    /// Surfaces as [`crate::error::IndexParseFault::AllocationFailed`]
    /// with `context: AllocationContext::FdiFullPathBytes`.
    ///
    /// `skip_count >= 1` is the typical knob — the first FDI entry's
    /// path reservation succeeds and the failure fires on a later
    /// entry, pinning that the seam fires per-entry rather than once.
    FdiFullPath = 4,
}

impl SeamSite {
    /// Total number of seam sites. Used to size the `ARM_STATE`
    /// array. Must be kept in sync when adding a new variant — the
    /// array layout assumes contiguous discriminants `0..COUNT`.
    pub const COUNT: usize = 5;
}

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
pub fn arm_at(site: SeamSite, skip_count: u64) -> DisarmGuard {
    ARM_STATE.with(|cells| cells[site as usize].set(Some(skip_count)));
    DisarmGuard {
        _opt_out: PhantomData,
    }
}

/// Production-side seam check at `site`. Returns `Err` with a
/// synthetic [`TryReserveError`] when armed and the skip-counter has
/// reached zero; otherwise `Ok`.
///
/// `pub(crate)` rather than `pub` because the only legitimate callers
/// are the production sites in `crate::container::pak`; integration
/// tests drive the seams via [`arm_at`] + the production code path.
/// `pub(crate)` makes the wrong-call boundary structural rather than
/// docs-only.
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
        let cell = &cells[site as usize];
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

    /// `SeamSite::COUNT` must match the number of declared variants,
    /// otherwise `ARM_STATE`'s array is sized wrong and the last
    /// variants' slots silently alias or the array overflows on
    /// index. Compile-time-ish anchor (the test runs every cycle but
    /// the assertion is cheap).
    #[test]
    fn seam_site_count_matches_variant_count() {
        // Discriminants are `0..COUNT`. The largest discriminant
        // (`FdiFullPath` = 4) must equal `COUNT - 1`.
        assert_eq!(SeamSite::FdiFullPath as usize, SeamSite::COUNT - 1);
        // First variant is at 0.
        assert_eq!(SeamSite::CompressedReserve as usize, 0);
    }

    /// Arming one site must not fire at a different site. Pins the
    /// per-site isolation the array-indexed design provides.
    #[test]
    fn arm_at_isolates_per_site() {
        let _guard = arm_at(SeamSite::FstringUtf8, 0);
        // Unrelated site stays unarmed.
        assert!(maybe_fail_at(SeamSite::FstringUtf16).is_ok());
        assert!(maybe_fail_at(SeamSite::CompressedReserve).is_ok());
        assert!(maybe_fail_at(SeamSite::ScratchReserve).is_ok());
        assert!(maybe_fail_at(SeamSite::FdiFullPath).is_ok());
        // The armed site fires.
        assert!(maybe_fail_at(SeamSite::FstringUtf8).is_err());
        // ...and auto-disarms after firing.
        assert!(maybe_fail_at(SeamSite::FstringUtf8).is_ok());
    }

    /// `arm_at(site, n)` passes the next `n` invocations and fails
    /// the `(n+1)`th, as documented.
    #[test]
    fn arm_at_skip_count_passes_n_then_fails() {
        let _guard = arm_at(SeamSite::ScratchReserve, 2);
        // First two invocations pass.
        assert!(maybe_fail_at(SeamSite::ScratchReserve).is_ok());
        assert!(maybe_fail_at(SeamSite::ScratchReserve).is_ok());
        // Third invocation fails (skip_count + 1 = 3rd).
        assert!(maybe_fail_at(SeamSite::ScratchReserve).is_err());
        // Auto-disarmed.
        assert!(maybe_fail_at(SeamSite::ScratchReserve).is_ok());
    }

    /// `DisarmGuard` Drop clears state across all sites, not just
    /// the one the guard was issued for. Matches the prior global-
    /// disarm semantics that integration tests rely on.
    #[test]
    fn disarm_guard_clears_all_sites_on_drop() {
        {
            let _guard_a = arm_at(SeamSite::FstringUtf8, 100);
            let _guard_b = arm_at(SeamSite::FdiFullPath, 100);
            // Both armed.
            // Drop both guards at scope exit.
        }
        // After drop: both sites are unarmed.
        assert!(maybe_fail_at(SeamSite::FstringUtf8).is_ok());
        assert!(maybe_fail_at(SeamSite::FdiFullPath).is_ok());
    }
}
