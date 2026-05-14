//! Cfg-gated OOM-injection seams for the two `try_reserve` sites in
//! `container::pak::stream_zlib_to`. Lets integration tests exercise
//! the [`crate::error::DecompressionFault::CompressedBlockReserveFailed`]
//! and [`crate::error::DecompressionFault::ZlibScratchReserveFailed`]
//! production paths without requiring a real allocator-pressure
//! scenario (which is non-deterministic and platform-dependent).
//!
//! **Stability:** gated behind the `__test_utils` feature; production
//! builds never compile or expose this module. The injection check
//! sites in `stream_zlib_to` are also `#[cfg(feature = "__test_utils")]`
//! so they vanish entirely from non-test builds.
//!
//! **Thread-locality:** arm state lives in `thread_local!` cells so
//! parallel integration-test threads don't interfere. Production
//! `stream_zlib_to` runs synchronously on the calling thread (no
//! `spawn`/`rayon`), so the seam fires on the same thread as the
//! arming test.
//!
//! **Synthetic [`TryReserveError`]:** the stdlib does not expose a
//! constructor for `TryReserveError`. The synthetic value is produced
//! by a real failed allocation
//! (`Vec::<u8>::new().try_reserve_exact(usize::MAX)`), which always
//! fails with `CapacityOverflow` regardless of platform. The error's
//! `kind()` is therefore not pinnable across platforms; tests should
//! match on the `DecompressionFault` variant tag and structured fields,
//! not on the inner `TryReserveError`'s Display string.

use std::cell::Cell;
use std::collections::TryReserveError;
use std::thread::LocalKey;

thread_local! {
    static COMPRESSED_RESERVE_OOM: Cell<Option<u64>> = const { Cell::new(None) };
    static SCRATCH_RESERVE_OOM: Cell<Option<u64>> = const { Cell::new(None) };
}

/// Arm OOM injection at the
/// [`CompressedBlockReserveFailed`](crate::error::DecompressionFault::CompressedBlockReserveFailed)
/// site (the `try_reserve_exact(block_len_usize)` call in
/// `stream_zlib_to`'s per-block prologue).
///
/// The next `skip_count` invocations of the seam pass through; the
/// `(skip_count + 1)`th returns `Err` and auto-disarms. Pass `0` to
/// fail the very next invocation.
///
/// **Thread-local:** affects only the calling thread. See module docs.
pub fn arm_compressed_reserve_oom(skip_count: u64) {
    COMPRESSED_RESERVE_OOM.with(|c| c.set(Some(skip_count)));
}

/// Arm OOM injection at the
/// [`ZlibScratchReserveFailed`](crate::error::DecompressionFault::ZlibScratchReserveFailed)
/// site (the `try_reserve(n)` call inside `stream_zlib_to`'s read loop).
///
/// To pin `already_committed > 0` (the field that structurally
/// distinguishes mid-decode failure from the
/// [`arm_compressed_reserve_oom`] case), pass `skip_count >= 1` so the
/// first chunk's reservation succeeds and the failure fires on a
/// later iteration.
pub fn arm_scratch_reserve_oom(skip_count: u64) {
    SCRATCH_RESERVE_OOM.with(|c| c.set(Some(skip_count)));
}

/// Disarm both OOM injection seams on the calling thread. Tests
/// should call this in a teardown step (or via a guard) to avoid
/// leaking arm state into subsequent tests on the same thread.
pub fn disarm() {
    COMPRESSED_RESERVE_OOM.with(|c| c.set(None));
    SCRATCH_RESERVE_OOM.with(|c| c.set(None));
}

/// Production-side seam: called from `stream_zlib_to`'s
/// `try_reserve_exact` site. Returns `Err` with a synthetic
/// [`TryReserveError`] when armed and the skip-counter has reached
/// zero; otherwise `Ok`.
#[doc(hidden)]
pub fn maybe_fail_compressed_reserve() -> Result<(), TryReserveError> {
    if take_arm(&COMPRESSED_RESERVE_OOM) {
        Err(synthetic_try_reserve_error())
    } else {
        Ok(())
    }
}

/// Production-side seam: called from `stream_zlib_to`'s
/// `try_reserve(n)` site inside the read loop.
#[doc(hidden)]
pub fn maybe_fail_scratch_reserve() -> Result<(), TryReserveError> {
    if take_arm(&SCRATCH_RESERVE_OOM) {
        Err(synthetic_try_reserve_error())
    } else {
        Ok(())
    }
}

fn take_arm(cell: &'static LocalKey<Cell<Option<u64>>>) -> bool {
    cell.with(|c| match c.get() {
        None => false,
        Some(0) => {
            c.set(None);
            true
        }
        Some(n) => {
            c.set(Some(n - 1));
            false
        }
    })
}

fn synthetic_try_reserve_error() -> TryReserveError {
    Vec::<u8>::new()
        .try_reserve_exact(usize::MAX)
        .expect_err("usize::MAX byte reservation must always fail with CapacityOverflow")
}
