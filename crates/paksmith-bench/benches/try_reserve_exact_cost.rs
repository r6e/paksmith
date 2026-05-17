//! `Vec::try_reserve_exact` cost across allocation sizes (issue
//! #228).
//!
//! Devil's-advocate review on PR #226 (closing #181) flagged that
//! the "thrashes the allocator on constrained runners" claim for
//! v3-v9 `try_reserve_exact(10M)` and v10+ `try_reserve_exact(1 GiB)`
//! is unmeasured. This bench measures the actual wall-clock cost of
//! both successful and refused reservations across sizes bracketing
//! the current caps:
//!
//! - `MAX_FDI_BYTES = 256 MiB`
//! - `MAX_INDEX_BYTES = 1 GiB`
//! - `MAX_FLAT_INDEX_ENTRIES = 10M × sizeof(PakIndexEntry) ≈ 1-2 GiB`
//!
//! ## Methodology
//!
//! Each bench function allocates a fresh `Vec<u8>::new()` per
//! iteration and calls `try_reserve_exact(N)`. Wall-clock is
//! measured by criterion; reservation success or failure is
//! discarded via `black_box` so the compiler can't constant-fold
//! the call away. The drop runs inside the measured closure, so for
//! successful reservations the time covers `alloc + drop`.
//!
//! ## Cost model
//!
//! All current production caps are byte counts (`MAX_FDI_BYTES`,
//! `MAX_INDEX_BYTES`) OR translate to byte counts via the receiver
//! type (`MAX_FLAT_INDEX_ENTRIES × sizeof(PakIndexEntry)`). Allocator
//! cost is dominated by byte count, not element count, so this
//! `Vec<u8>` benchmark covers both cap families without needing a
//! separate `Vec<PakIndexEntry>` target.
//!
//! ## Interpretation
//!
//! - If refusal cost is **< 10 ms** for all values past the cap, the
//!   "thrashing" claim is unsupported — caps are defense-in-depth
//!   theater (still useful for predictable error shape, but not
//!   load-bearing for resource exhaustion).
//! - If refusal cost is **seconds-to-minutes**, the caps are
//!   load-bearing and the existing thresholds need empirical
//!   tuning against the CI-runner pressure model (2 GiB GHA hosted
//!   runner).
//!
//! ## Platform coverage
//!
//! This bench captures local-machine numbers. Linux/Windows
//! measurements need a separate `bench.yml` matrix run. Allocator
//! behavior differs:
//!
//! - **Linux**: `mmap(MAP_ANONYMOUS)` overcommits by default —
//!   reservation is lazy, success is fast regardless of physical
//!   memory.
//! - **macOS**: `vm_allocate` similarly lazy.
//! - **Windows**: `HeapAlloc` may commit eagerly via Low Fragmentation
//!   Heap policy; behavior depends on size class.
//!
//! The `usize::MAX` and `isize::MAX` cases trip Rust's `RawVec`
//! capacity guard synchronously inside stdlib *before* the allocator
//! is consulted — those are platform-invariant and measure stdlib
//! overhead alone.

#![allow(unused_results, missing_docs)]

use std::hint::black_box;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

/// Reservation sizes bracketing the production caps.
///
/// Labeled with `(name, N_bytes)`. Values above ~1 GiB rely on
/// platform overcommit semantics to succeed without backing
/// physical pages; the `isize::MAX` and `usize::MAX` entries
/// deliberately trip stdlib's `RawVec` capacity guard for
/// platform-invariant baseline measurement of the synchronous
/// refusal path.
const RESERVATION_SIZES: &[(&str, usize)] = &[
    ("1KiB", 1024),
    ("1MiB", 1024 * 1024),
    ("256MiB__MAX_FDI_BYTES", 256 * 1024 * 1024),
    ("1GiB__MAX_INDEX_BYTES", 1024 * 1024 * 1024),
    ("10GiB", 10 * 1024 * 1024 * 1024),
    ("100GiB", 100 * 1024 * 1024 * 1024),
    ("isize__MAX", isize::MAX as usize),
    ("usize__MAX", usize::MAX),
];

fn try_reserve_exact_cost(c: &mut Criterion) {
    let mut group = c.benchmark_group("try_reserve_exact_cost");
    // Keep total runtime bounded: large-N benches can be slow.
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(50);

    for &(label, n) in RESERVATION_SIZES {
        group.throughput(Throughput::Bytes(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(label), &n, |b, &n| {
            b.iter(|| {
                let mut v = Vec::<u8>::new();
                let res = v.try_reserve_exact(black_box(n));
                // black_box on both prevents the optimizer from
                // eliding the allocation when `res` is unused.
                black_box(&v);
                let _ = black_box(res);
            });
        });
    }

    group.finish();
}

criterion_group!(benches, try_reserve_exact_cost);
criterion_main!(benches);
