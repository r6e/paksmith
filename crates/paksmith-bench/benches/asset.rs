//! Asset-parser benchmarks (issue #245).
//!
//! Four targets covering the Phase-2a UAsset hot path:
//!
//! - `package_read_from_tiny` — the 447-byte canonical UE 4.27
//!   fixture (`MinimalPackageSpec::default()`). Measures the
//!   per-parse constant overhead (summary header + 3-entry name
//!   table + 1 import + 1 export).
//! - `package_read_from_small` — a 50-name, 20-import, 5-export
//!   asset (1 KiB payloads each). Measures how the parser scales
//!   under modest table sizes.
//! - `package_read_from_medium` — a 500/200/50/20 KiB asset (~1
//!   MiB total). The pre-Phase-2b ceiling — beyond this, parser
//!   pressure shifts from header parse to property bag iteration
//!   (which Phase 2b changes).
//! - `package_read_from_pak_tiny` — full pipeline:
//!   `Package::read_from_pak` (open + locate + decompress + parse)
//!   against the canonical 818-byte pak.
//!
//! Lint allows: criterion's bencher API requires `unused_results`.
//!
//! Cast safety: every `usize -> u64` conversion uses
//! `u64::try_from(...).expect(...)` (lossless on all supported
//! targets), keeping the workspace's deny-cast policy intact.

#![allow(unused_results, missing_docs)]

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use paksmith_bench::tiny_pak_path;
use paksmith_core::asset::Package;
use paksmith_fixture_gen::uasset::synthesize_uasset;

fn package_read_from_tiny(c: &mut Criterion) {
    // 3 names, 1 import, 1 export, 16-byte payload — the canonical
    // shape. Synthesized rather than hard-coded so a future change
    // to the wire format doesn't drift the bench from the parser.
    let bytes = synthesize_uasset(3, 1, 1, 16);
    let size = u64::try_from(bytes.len()).expect("synthesized fixture size fits u64");

    let mut group = c.benchmark_group("package_read_from_tiny");
    group.throughput(Throughput::Bytes(size));
    group.bench_function("read_from", |b| {
        b.iter(|| {
            let pkg = Package::read_from(black_box(&bytes), None, None, "bench_tiny")
                .expect("Package::read_from tiny fixture");
            black_box(pkg);
        });
    });
    group.finish();
}

fn package_read_from_small(c: &mut Criterion) {
    // 50 names, 20 imports, 5 exports, 1 KiB payloads — ~10 KiB total.
    let bytes = synthesize_uasset(50, 20, 5, 1024);
    let size = u64::try_from(bytes.len()).expect("synthesized fixture size fits u64");

    let mut group = c.benchmark_group("package_read_from_small");
    group.throughput(Throughput::Bytes(size));
    group.bench_function("read_from", |b| {
        b.iter(|| {
            let pkg = Package::read_from(black_box(&bytes), None, None, "bench_small")
                .expect("Package::read_from small fixture");
            black_box(pkg);
        });
    });
    group.finish();
}

fn package_read_from_medium(c: &mut Criterion) {
    // 500 names, 200 imports, 50 exports, 20 KiB payloads — ~1 MiB.
    let bytes = synthesize_uasset(500, 200, 50, 20 * 1024);
    let size = u64::try_from(bytes.len()).expect("synthesized fixture size fits u64");

    let mut group = c.benchmark_group("package_read_from_medium");
    // Lighter sample count: 1 MiB parse × 100 default samples = 100 MiB
    // of work × warmup overhead would balloon the suite wall-clock.
    group.sample_size(20);
    group.throughput(Throughput::Bytes(size));
    group.bench_function("read_from", |b| {
        b.iter(|| {
            let pkg = Package::read_from(black_box(&bytes), None, None, "bench_medium")
                .expect("Package::read_from medium fixture");
            black_box(pkg);
        });
    });
    group.finish();
}

fn package_read_from_pak_tiny(c: &mut Criterion) {
    // The canonical 818-byte v8b pak wraps the same UE 4.27 minimal
    // fixture. Full pipeline: pak open + locate entry + extract bytes
    // + parse uasset. Single-bench answer to "what does `paksmith
    // inspect <pak>::<entry>` cost end-to-end at the tiny end?"
    let pak_path = tiny_pak_path();

    let mut group = c.benchmark_group("package_read_from_pak_tiny");
    group.bench_function("read_from_pak", |b| {
        b.iter(|| {
            let pkg =
                Package::read_from_pak(black_box(&pak_path), black_box("Game/Maps/Demo.uasset"))
                    .expect("Package::read_from_pak tiny fixture");
            black_box(pkg);
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    package_read_from_tiny,
    package_read_from_small,
    package_read_from_medium,
    package_read_from_pak_tiny,
);
criterion_main!(benches);
