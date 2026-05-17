//! Inspect/JSON emission benchmarks (issue #245).
//!
//! Two targets covering `paksmith inspect`'s JSON output path:
//!
//! - `inspect_json_pretty` — `serde_json::to_writer_pretty` on a
//!   medium-tier parsed Package.
//! - `inspect_json_compact` — `serde_json::to_writer` on the same
//!   input. Comparing the two quantifies the pretty-mode tax
//!   (extra whitespace + indentation work) on the CLI's
//!   default-on `--pretty` output.
//!
//! Reusing a single parsed Package between both benches isolates
//! the JSON-emit path — without it, parse-time variance would
//! dominate the measurement.

#![allow(
    unused_results,
    missing_docs,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

use std::hint::black_box;
use std::io::Write;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use paksmith_core::asset::Package;
use paksmith_fixture_gen::uasset::synthesize_uasset;

/// `/dev/null`-equivalent sink — counts nothing, drops everything.
/// Keeps the bench focused on serialization work rather than
/// allocator churn from a growing `Vec` sink.
struct NullWriter;
impl Write for NullWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Build the shared parsed package: medium-tier shape (500/200/50
/// names/imports/exports, 20 KiB payloads). Matches `asset.rs`'s
/// medium tier so the JSON emit time is directly comparable to the
/// parse time on the same input.
fn medium_package() -> Package {
    let bytes = synthesize_uasset(500, 200, 50, 20 * 1024);
    Package::read_from(&bytes, "bench_inspect_medium")
        .expect("parse medium fixture for inspect benches")
}

/// Pre-measure the compact JSON output size — `serde_json::to_vec`
/// once at setup, then the byte count drives the criterion
/// `Throughput::Bytes` for both pretty and compact (the comparison
/// is meaningful relative to the same input scale).
fn json_compact_size(pkg: &Package) -> u64 {
    let mut buf = Vec::<u8>::new();
    serde_json::to_writer(&mut buf, pkg).expect("setup serialize");
    buf.len() as u64
}

fn inspect_json_pretty(c: &mut Criterion) {
    let pkg = medium_package();
    let compact_size = json_compact_size(&pkg);

    let mut group = c.benchmark_group("inspect_json_pretty");
    group.sample_size(20);
    // Throughput keyed on compact size — pretty emits more bytes,
    // but the comparable work-per-byte metric uses compact as the
    // base so the pretty-vs-compact tax is read directly.
    group.throughput(Throughput::Bytes(compact_size));
    group.bench_function("to_writer_pretty", |b| {
        b.iter(|| {
            let mut sink = NullWriter;
            serde_json::to_writer_pretty(&mut sink, black_box(&pkg)).expect("to_writer_pretty");
        });
    });
    group.finish();
}

fn inspect_json_compact(c: &mut Criterion) {
    let pkg = medium_package();
    let compact_size = json_compact_size(&pkg);

    let mut group = c.benchmark_group("inspect_json_compact");
    group.sample_size(20);
    group.throughput(Throughput::Bytes(compact_size));
    group.bench_function("to_writer", |b| {
        b.iter(|| {
            let mut sink = NullWriter;
            serde_json::to_writer(&mut sink, black_box(&pkg)).expect("to_writer");
        });
    });
    group.finish();
}

criterion_group!(benches, inspect_json_pretty, inspect_json_compact);
criterion_main!(benches);
