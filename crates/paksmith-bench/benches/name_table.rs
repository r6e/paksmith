//! NameTable benchmarks (issue #245).
//!
//! - `name_table_resolve_hot` — 1000 `NameTable::resolve` calls
//!   against a 500-entry pool. Pinpoints the FName-resolution
//!   throughput before Phase 2b's typed-property iteration starts
//!   funneling per-property name lookups through this path.
//!
//! Phase 2b will add typed-property iteration where each property
//! pays a name resolution. Without this baseline, the additional
//! resolution cost is impossible to budget against the existing
//! pre-Phase-2b work.

// No cast allows: this file has no `as` cast sites. criterion's
// bencher API requires `unused_results`.
#![allow(unused_results, missing_docs)]

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use paksmith_core::asset::{FName, NameTable};

fn name_table_resolve_hot(c: &mut Criterion) {
    // 500-entry table; lookups cycle through `index = i % 500`
    // (with `number` rotating through {0, 1, 2} to exercise both
    // the bare-name and the disambiguator-suffix paths).
    let names = NameTable {
        names: (0..500).map(|i| FName::new(&format!("Name_{i}"))).collect(),
    };
    let lookups: Vec<(u32, u32)> = (0..1000).map(|i| (i % 500, i % 3)).collect();

    let mut group = c.benchmark_group("name_table_resolve_hot");
    // Throughput in operations rather than bytes — `resolve` returns
    // a fresh `String`, so the work is "1000 name lookups + 1000
    // owned-string materializations" per iteration.
    group.throughput(Throughput::Elements(1000));
    group.bench_function("resolve_1000", |b| {
        b.iter(|| {
            for &(idx, num) in &lookups {
                let s = names.resolve(black_box(idx), black_box(num));
                black_box(s);
            }
        });
    });
    group.finish();
}

criterion_group!(benches, name_table_resolve_hot);
criterion_main!(benches);
