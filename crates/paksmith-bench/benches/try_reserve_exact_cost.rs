//! `Vec::try_reserve_exact` cost across allocation sizes (issue
//! #228). See `docs/security/allocation-caps.md` for methodology,
//! findings, and the cap-rationale decision.
//!
//! Two bench groups:
//!
//! - `try_reserve_exact_cost` — measures `try_reserve_exact(N)` on a
//!   fresh `Vec::<u8>::new()`. This is the call whose cost the
//!   original "allocator thrash" claim was about. Each iteration's
//!   drop runs inside the measured closure; for lazy-mmap platforms
//!   the cost is dominated by the address-space reservation, not
//!   the (zero) physical commit.
//!
//! - `resize_fill_cost` — measures the production-actual pattern at
//!   bounded sizes: `try_reserve_exact(N)` + `Vec::resize(N, 0)`.
//!   `resize` zero-fills, forcing page commits. Capped at 256 MiB
//!   with `sample_size(10)` so the total memory pressure stays
//!   manageable (10 samples × 256 MiB ≈ 2.5 GiB touched).
//!
//! ## Skipped at-rest sizes
//!
//! `10 GiB` and `100 GiB` were removed after R1 review: on
//! lazy-mmap platforms they merely repeat the `1 GiB` finding
//! (microseconds for an unwritten reservation), and on
//! eager-commit platforms (Windows `HeapAlloc` LFH above certain
//! size classes, restrictive `vm.overcommit_memory=2` Linux) they
//! risk DoS'ing developer machines.

// `unused_results` allow rationale (matches the existing pak/asset/
// name_table/inspect benches): criterion's `BenchmarkGroup` builder
// methods return `&mut Self` for chaining, and discarding that
// borrow is the documented call shape, not a missed return.
#![allow(unused_results, missing_docs)]

use std::hint::black_box;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

/// Reservation sizes for the `try_reserve_exact_cost` group.
/// Bracket the production caps and include both the `RawVec`
/// capacity-overflow refusal paths.
const RESERVATION_SIZES: &[(&str, usize)] = &[
    ("1KiB", 1024),
    ("1MiB", 1024 * 1024),
    ("256MiB-MAX_FDI_BYTES", 256 * 1024 * 1024),
    ("1GiB-MAX_INDEX_BYTES", 1024 * 1024 * 1024),
    ("isize-MAX", isize::MAX as usize),
    ("usize-MAX", usize::MAX),
];

/// Resize+fill sizes for the `resize_fill_cost` group. Bounded ≤
/// 256 MiB to keep `sample_size(10) × N` total touched memory
/// reasonable on a workstation.
const RESIZE_FILL_SIZES: &[(&str, usize)] = &[
    ("1KiB", 1024),
    ("1MiB", 1024 * 1024),
    ("64MiB", 64 * 1024 * 1024),
    ("256MiB-MAX_FDI_BYTES", 256 * 1024 * 1024),
];

fn try_reserve_exact_cost(c: &mut Criterion) {
    let mut group = c.benchmark_group("try_reserve_exact_cost");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(50);

    for &(label, n) in RESERVATION_SIZES {
        // `Throughput::Bytes` is meaningful only for entries that
        // actually represent byte movement; the `isize::MAX` and
        // `usize::MAX` entries trip stdlib's `RawVec` capacity guard
        // synchronously without ever touching memory, so a bytes/s
        // figure for those would be nonsensical (e.g. 1e18 GiB/s).
        let is_refusal_path = n > (1 << 40); // > 1 TiB → guaranteed refusal
        if !is_refusal_path {
            // SAFETY of `as u64`: only reached for `n ≤ 1 TiB`,
            // which fits u64 trivially on every supported target.
            #[allow(clippy::cast_possible_truncation)]
            group.throughput(Throughput::Bytes(n as u64));
        }
        group.bench_with_input(BenchmarkId::from_parameter(label), &n, |b, &n| {
            b.iter(|| {
                let mut v = Vec::<u8>::new();
                let res = v.try_reserve_exact(black_box(n));
                black_box(&v);
                let _ = black_box(res);
            });
        });
    }

    group.finish();
}

fn resize_fill_cost(c: &mut Criterion) {
    let mut group = c.benchmark_group("resize_fill_cost");
    // Smaller sample count + tighter measurement window than the
    // sibling group: each iteration writes N zero-bytes, so 50
    // samples × 256 MiB ≈ 12 GiB of touched memory per measurement
    // run. 10 samples keeps the upper-bound total under 2.5 GiB.
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(10);

    for &(label, n) in RESIZE_FILL_SIZES {
        // `as u64` safe: `RESIZE_FILL_SIZES` is capped at 256 MiB.
        #[allow(clippy::cast_possible_truncation)]
        group.throughput(Throughput::Bytes(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(label), &n, |b, &n| {
            b.iter(|| {
                let mut v: Vec<u8> = Vec::new();
                // `.expect`: a silently-failed reservation would let
                // `resize` succeed trivially on an empty vec and
                // fabricate a fast measurement. Bounded ≤ 256 MiB
                // here so reservation must succeed on any sane host;
                // panic loud if not.
                v.try_reserve_exact(n)
                    .expect("bench precondition: 256 MiB reservation must succeed");
                v.resize(n, 0);
                black_box(&v);
            });
        });
    }

    group.finish();
}

criterion_group!(benches, try_reserve_exact_cost, resize_fill_cost);
criterion_main!(benches);
