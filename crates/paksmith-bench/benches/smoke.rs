//! Smoke bench — keeps the crate compilable until the real benches
//! land in commits C/D. The body times a `1 + 1` addition so the
//! criterion harness is exercised end-to-end (group construction,
//! sample collection, summary report) without depending on any
//! paksmith API. When `pak.rs` / `asset.rs` ship, this file can be
//! removed.
//!
//! `unused_results` is suppressed because `Criterion::bench_function`
//! returns `&mut Criterion` for builder-chaining — discarding that
//! borrow is the documented call shape, not a missed return value.
//! `missing_docs` is suppressed because the `criterion_group!` macro
//! expands to private items that don't satisfy the workspace-wide
//! `missing_docs = "warn"` lint.

#![allow(unused_results, missing_docs)]

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

fn smoke(c: &mut Criterion) {
    c.bench_function("smoke_add", |b| {
        b.iter(|| black_box(1u64) + black_box(1u64));
    });
}

criterion_group!(benches, smoke);
criterion_main!(benches);
