//! Cfg-gated OOM-injection seams for the five `try_reserve` sites
//! across `container::pak`'s parser and decompression code. Lets
//! integration tests exercise the typed `AllocationFailed` /
//! `*ReserveFailed` production paths without requiring real
//! allocator-pressure scenarios (which are non-deterministic and
//! platform-dependent).
//!
//! Two seam families:
//!
//! - **Decompression** (`stream_zlib_to`): the two sites added with
//!   the typed-OOM work surface as
//!   [`crate::error::DecompressionFault::CompressedBlockReserveFailed`]
//!   and `ZlibScratchReserveFailed`. Armed via
//!   [`arm_compressed_reserve_oom`] / [`arm_scratch_reserve_oom`].
//!
//! - **Parser** (`fstring` + `path_hash`): the three sites added in
//!   #132 (issue #191) surface as
//!   [`crate::error::IndexParseFault::AllocationFailed`] with one
//!   of `AllocationContext::FStringUtf16CodeUnits`,
//!   `FStringUtf8Bytes`, or `FdiFullPathBytes`. Armed via
//!   [`arm_fstring_utf16_reserve_oom`],
//!   [`arm_fstring_utf8_reserve_oom`],
//!   [`arm_fdi_full_path_reserve_oom`].
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
//! (`Vec::<u8>::new().try_reserve_exact(usize::MAX)`), which fails
//! synchronously with `CapacityOverflow` because `usize::MAX` exceeds
//! the `RawVec` `isize::MAX` capacity guard before the allocator is
//! ever consulted. This is platform-invariant on every supported
//! target. Even so, tests should match on the `DecompressionFault`
//! variant tag and structured fields rather than on the inner
//! `TryReserveError`'s Display string or `kind()` — the latter is
//! forward-compat insurance against an unlikely stdlib refactor that
//! changed the synthesis path.
//!
//! **Lifecycle (RAII):** [`arm_compressed_reserve_oom`] and
//! [`arm_scratch_reserve_oom`] return a [`DisarmGuard`] whose `Drop`
//! impl clears all arm state on the calling thread. Tests should
//! bind it to a named local (`let _guard = arm_*(...)`) — never
//! `let _ = arm_*(...)`, which drops the guard immediately and leaks
//! the arm state into the next test on the same thread. The
//! `#[must_use]` attribute on the guard catches the most common
//! variant (`arm_*(...);` with no binding at all).

use std::cell::Cell;
use std::collections::TryReserveError;
use std::marker::PhantomData;
use std::thread::LocalKey;

thread_local! {
    static COMPRESSED_RESERVE_OOM: Cell<Option<u64>> = const { Cell::new(None) };
    static SCRATCH_RESERVE_OOM: Cell<Option<u64>> = const { Cell::new(None) };
    static FSTRING_UTF16_RESERVE_OOM: Cell<Option<u64>> = const { Cell::new(None) };
    static FSTRING_UTF8_RESERVE_OOM: Cell<Option<u64>> = const { Cell::new(None) };
    static FDI_FULL_PATH_RESERVE_OOM: Cell<Option<u64>> = const { Cell::new(None) };
}

/// RAII guard returned by every `arm_*_reserve_oom` function; its
/// `Drop` impl calls [`disarm`] on the current thread. The
/// `#[must_use]` attribute makes `arm_*(...);` (with no binding) a
/// compile-time warning so tests can't accidentally arm without
/// owning the cleanup.
///
/// Bind it to a named local (`let _guard = arm_*(...)`) — never
/// `let _ = arm_*(...)`, which drops the guard immediately and
/// makes the arm state vanish before the production code runs.
#[must_use = "DisarmGuard must be bound to a named local (`let _guard = arm_*(...)`); \
              `let _ = ...` drops the guard immediately and disarms before the seam fires"]
pub struct DisarmGuard(
    // `PhantomData<*const ()>` opts out of `Send`/`Sync` so the guard
    // can't be moved to a different thread (where `Drop` would call
    // `disarm()` on the wrong thread's arm state, leaving the
    // arming thread's state leaked). The arm cells are already
    // thread-local; this makes the thread-locality structural rather
    // than discipline-enforced.
    PhantomData<*const ()>,
);

impl Drop for DisarmGuard {
    fn drop(&mut self) {
        disarm();
    }
}

/// Shared arm-helper. The next `skip_count` invocations of the
/// seam pass through; the `(skip_count + 1)`th returns `Err` and
/// auto-disarms (see [`take_arm`]). Pass `0` to fail the very next
/// invocation. Affects only the calling thread.
fn arm_cell(cell: &'static LocalKey<Cell<Option<u64>>>, skip_count: u64) -> DisarmGuard {
    cell.with(|c| c.set(Some(skip_count)));
    DisarmGuard(PhantomData)
}

/// Shared production-side helper. Returns `Err` with a synthetic
/// [`TryReserveError`] when armed and the skip-counter has reached
/// zero; otherwise `Ok`.
fn maybe_fail(cell: &'static LocalKey<Cell<Option<u64>>>) -> Result<(), TryReserveError> {
    if take_arm(cell) {
        Err(synthetic_try_reserve_error())
    } else {
        Ok(())
    }
}

/// Arm OOM injection at the
/// [`CompressedBlockReserveFailed`](crate::error::DecompressionFault::CompressedBlockReserveFailed)
/// site (the `try_reserve_exact(block_len_usize)` call in
/// `stream_zlib_to`'s per-block prologue).
pub fn arm_compressed_reserve_oom(skip_count: u64) -> DisarmGuard {
    arm_cell(&COMPRESSED_RESERVE_OOM, skip_count)
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
pub fn arm_scratch_reserve_oom(skip_count: u64) -> DisarmGuard {
    arm_cell(&SCRATCH_RESERVE_OOM, skip_count)
}

/// Arm OOM injection at the parser's UTF-16 FString reservation
/// site. Triggers
/// [`AllocationContext::FStringUtf16CodeUnits`](crate::error::AllocationContext::FStringUtf16CodeUnits).
pub fn arm_fstring_utf16_reserve_oom(skip_count: u64) -> DisarmGuard {
    arm_cell(&FSTRING_UTF16_RESERVE_OOM, skip_count)
}

/// Arm OOM injection at the parser's UTF-8 FString reservation
/// site. Triggers
/// [`AllocationContext::FStringUtf8Bytes`](crate::error::AllocationContext::FStringUtf8Bytes).
pub fn arm_fstring_utf8_reserve_oom(skip_count: u64) -> DisarmGuard {
    arm_cell(&FSTRING_UTF8_RESERVE_OOM, skip_count)
}

/// Arm OOM injection at the FDI full-path reservation site
/// (`path_hash.rs::read_v10_plus_index`'s dir+file concat).
/// Triggers
/// [`AllocationContext::FdiFullPathBytes`](crate::error::AllocationContext::FdiFullPathBytes).
///
/// `skip_count >= 1` is the typical knob — the first FDI entry's
/// path reservation succeeds and the failure fires on a later
/// entry, pinning that the seam fires per-entry rather than once.
pub fn arm_fdi_full_path_reserve_oom(skip_count: u64) -> DisarmGuard {
    arm_cell(&FDI_FULL_PATH_RESERVE_OOM, skip_count)
}

/// Disarm all OOM injection seams on the calling thread. Normally
/// called via the [`DisarmGuard`] returned by `arm_*`; exposed
/// directly for the rare case where a test wants to re-arm
/// mid-flight without dropping the existing guard.
pub fn disarm() {
    COMPRESSED_RESERVE_OOM.with(|c| c.set(None));
    SCRATCH_RESERVE_OOM.with(|c| c.set(None));
    FSTRING_UTF16_RESERVE_OOM.with(|c| c.set(None));
    FSTRING_UTF8_RESERVE_OOM.with(|c| c.set(None));
    FDI_FULL_PATH_RESERVE_OOM.with(|c| c.set(None));
}

// Production-side seams: each called from the corresponding
// `try_reserve*` site under `#[cfg(feature = "__test_utils")]`.
// `pub(crate)` rather than `pub` because the only legitimate
// callers are the production sites in `crate::container::pak`;
// integration tests use the `arm_*_oom` functions above.
// `pub(crate)` makes the wrong-call boundary structural rather
// than docs-only.

/// Site: `stream_zlib_to`'s pre-decode per-block `try_reserve_exact`.
pub(crate) fn maybe_fail_compressed_reserve() -> Result<(), TryReserveError> {
    maybe_fail(&COMPRESSED_RESERVE_OOM)
}

/// Site: `stream_zlib_to`'s mid-decode `try_reserve(n)` loop.
pub(crate) fn maybe_fail_scratch_reserve() -> Result<(), TryReserveError> {
    maybe_fail(&SCRATCH_RESERVE_OOM)
}

/// Site: `read_fstring` UTF-16 branch.
pub(crate) fn maybe_fail_fstring_utf16_reserve() -> Result<(), TryReserveError> {
    maybe_fail(&FSTRING_UTF16_RESERVE_OOM)
}

/// Site: `read_fstring` UTF-8 branch.
pub(crate) fn maybe_fail_fstring_utf8_reserve() -> Result<(), TryReserveError> {
    maybe_fail(&FSTRING_UTF8_RESERVE_OOM)
}

/// Site: FDI walk's `dir + file` full-path `String::try_reserve_exact`.
pub(crate) fn maybe_fail_fdi_full_path_reserve() -> Result<(), TryReserveError> {
    maybe_fail(&FDI_FULL_PATH_RESERVE_OOM)
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
    // `usize::MAX` exceeds the `RawVec` `isize::MAX` capacity guard,
    // so this fails synchronously inside stdlib before the allocator
    // is consulted. Platform-invariant on every supported target; if
    // this ever returns `Ok`, the stdlib `RawVec` invariants have
    // changed and the synthesis path needs revisiting.
    Vec::<u8>::new()
        .try_reserve_exact(usize::MAX)
        .expect_err("usize::MAX byte reservation must fail (capacity overflow on isize::MAX guard)")
}
