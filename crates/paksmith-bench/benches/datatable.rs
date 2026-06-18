//! Phase 3d DataTable export benchmarks (CSV + JSON).
//!
//! A 10K-row × 50-column table (uniform `Float` schema). CSV exercises the
//! column-union + per-cell lookup hot path (the O(rows × cols²) surface the A3
//! finding targets); JSON is the single-pass serde path for comparison.
//! Throughput reported in rows/s.

#![allow(unused_results, missing_docs)]

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use paksmith_core::export::{DataTableCsvHandler, DataTableJsonHandler, FormatHandler};
use paksmith_core::testing::bench::large_data_table;

const ROWS: usize = 10_000;
const COLS: usize = 50;

fn datatable_export_csv(c: &mut Criterion) {
    let asset = large_data_table(ROWS, COLS);
    let mut group = c.benchmark_group("datatable_export_csv_10k_50");
    group.throughput(Throughput::Elements(u64::try_from(ROWS).expect("fits u64")));
    group.bench_function("export_csv", |b| {
        b.iter(|| {
            let out = DataTableCsvHandler
                .export(black_box(&asset), &[])
                .expect("csv export");
            black_box(out);
        });
    });
    group.finish();
}

fn datatable_export_json(c: &mut Criterion) {
    let asset = large_data_table(ROWS, COLS);
    let mut group = c.benchmark_group("datatable_export_json_10k_50");
    group.throughput(Throughput::Elements(u64::try_from(ROWS).expect("fits u64")));
    group.bench_function("export_json", |b| {
        b.iter(|| {
            let out = DataTableJsonHandler
                .export(black_box(&asset), &[])
                .expect("json export");
            black_box(out);
        });
    });
    group.finish();
}

criterion_group!(benches, datatable_export_csv, datatable_export_json);
criterion_main!(benches);
