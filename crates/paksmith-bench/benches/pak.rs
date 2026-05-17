//! Pak container benchmarks (issue #245).
//!
//! Six targets covering the open + read + verify hot paths:
//!
//! - `pak_open_tiny` — the 818-byte canonical `real_v8b_uasset.pak`
//!   committed under `tests/fixtures/`. Measures the per-open
//!   constant overhead (footer parse, index parse, per-entry
//!   bounds-check loop).
//! - `pak_open_large` — a lazy-generated 1000-entry v8b pak (no
//!   compression, 100 KiB/entry, ~100 MiB total). Measures how the
//!   open path scales with index size + the index-walk EOF bounds
//!   check.
//! - `pak_read_entry_uncompressed_small` — read one 10 KiB
//!   uncompressed entry. Measures the no-decompress code path
//!   (read into a pre-reserved `Vec`, SHA1 verify off the read).
//! - `pak_read_entry_zlib_small` — same shape but zlib-compressed
//!   payload. Quantifies the flate2-miniz decompressor's
//!   contribution before any future swap to `zlib-rs`.
//! - `pak_read_entry_zlib_large` — single 100 MiB zlib entry. Tests
//!   sustained streaming-decompress throughput.
//! - `pak_verify_full` — `PakReader::verify()` over a 100-entry pak
//!   (SHA1 over every entry payload + the FDI + the PHI).
//!
//! Lint allow rationale: bench-fixture synthesis uses
//! `usize → u32 / i32 / i64` casts against test-controlled inputs
//! (entry counts ≤ 1000, payload sizes ≤ 100 MiB). Per-site allows
//! would repeat the same "test-fixture, bounded-input" justification
//! across every call. `unused_results` is suppressed because
//! `Criterion::bench_function` / `Throughput` setters return
//! `&mut Criterion` for builder-chaining — discarding that borrow
//! is the documented call shape, not a missed return value.

#![allow(
    unused_results,
    missing_docs,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

use std::hint::black_box;
use std::io::Cursor;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use paksmith_bench::{NullWriter, lazy_fixture, tiny_pak_path};
use paksmith_core::container::ContainerReader;
use paksmith_core::container::pak::PakReader;
use repak::{Compression, PakBuilder, Version};

/// Build a multi-entry v8b pak via repak's writer. Mirrors the
/// pattern in `paksmith-fixture-gen/src/main.rs::write_fixture` —
/// atomic via `.tmp` + rename so a panic mid-write doesn't leave a
/// half-written cache file. Returns the bytes for `lazy_fixture` to
/// commit to disk.
///
/// Payload bytes are zero — zlib compresses an all-zero block to
/// almost nothing, so for benches that need realistic compressed
/// I/O the caller flips `payload_byte` to a non-zero value (which
/// trades cache size for representativeness).
fn build_pak(entry_count: u32, payload_size: u32, compressed: bool, payload_byte: u8) -> Vec<u8> {
    let payload: Vec<u8> = vec![payload_byte; usize::try_from(payload_size).expect("usize")];

    // repak's PakWriter requires `Write + Seek`; `Cursor<Vec<u8>>`
    // satisfies both. The cursor is reclaimed via `into_inner()`
    // after `write_index()` consumes the writer.
    let cursor = Cursor::new(Vec::<u8>::new());
    let builder = if compressed {
        PakBuilder::new().compression([Compression::Zlib])
    } else {
        PakBuilder::new()
    };
    let mut writer = builder.writer(cursor, Version::V8B, "../../../".to_string(), None);
    for i in 0..entry_count {
        // Distinct paths per entry — repak deduplicates by path,
        // so reusing one would collapse to a single entry.
        writer
            .write_file(
                &format!("Game/Bench/Entry_{i:06}.dat"),
                compressed,
                &payload,
            )
            .expect("repak write_file");
    }
    writer
        .write_index()
        .expect("repak write_index")
        .into_inner()
}

/// Bench: open the 818-byte canonical v8b pak.
///
/// Uses `PakReader::open(&path)` (the filesystem entry point) rather
/// than `from_bytes(bytes.clone())` — the latter pulls a `Vec::clone`
/// into the timed region, which inflates the apparent open cost by
/// the size of the input. With `open(&path)` the timed region is the
/// real wire-format work: footer read, index read, per-entry
/// bounds-check loop.
fn pak_open_tiny(c: &mut Criterion) {
    let path = tiny_pak_path();
    let size_bytes = std::fs::metadata(&path)
        .expect("stat tiny pak fixture")
        .len();

    let mut group = c.benchmark_group("pak_open_tiny");
    group.throughput(Throughput::Bytes(size_bytes));
    group.bench_function("open", |b| {
        b.iter(|| {
            let reader =
                PakReader::open(black_box(&path)).expect("PakReader::open on tiny fixture");
            black_box(reader);
        });
    });
    group.finish();
}

/// Bench: open a ~100 MiB / 1000-entry v8b pak. Scales the
/// index-walk + per-entry bounds-check loop. Issue #245 originally
/// called for 10k entries / 1GB — scaled down here to keep the
/// generation step under ~30s and the on-disk cache under
/// `target/bench-fixtures/` at a sane size. The shape (open-time
/// scaling with N entries) is what matters; absolute entry count
/// is a tunable. Bumped back up after `phase-2a-done` if the
/// resulting numbers show interesting scaling.
///
/// `PakReader::open(&path)` rather than `from_bytes` — see the
/// rationale on `pak_open_tiny` above.
fn pak_open_large(c: &mut Criterion) {
    let path = lazy_fixture("pak_large_1000_entries.pak", || {
        build_pak(1000, 100 * 1024, false, 0)
    });
    let size_bytes = std::fs::metadata(&path)
        .expect("stat large pak fixture")
        .len();

    let mut group = c.benchmark_group("pak_open_large");
    // `sample_size(10)` keeps the wall-clock for this bench tractable;
    // the open path is dominated by the per-entry bounds-check loop
    // over 1000 entries, which is fast per iter but still benefits
    // from a reduced sample count under the warmup overhead.
    group.sample_size(10);
    group.throughput(Throughput::Bytes(size_bytes));
    group.bench_function("open", |b| {
        b.iter(|| {
            let reader =
                PakReader::open(black_box(&path)).expect("PakReader::open on large fixture");
            black_box(reader);
        });
    });
    group.finish();
}

/// Bench: read one 10 KiB uncompressed entry. The from_bytes setup is
/// outside `b.iter()` so the timed region is exactly the entry-read
/// path (index lookup, seek, read).
fn pak_read_entry_uncompressed_small(c: &mut Criterion) {
    let path = lazy_fixture("pak_uncompressed_small.pak", || {
        build_pak(10, 10 * 1024, false, 0xAA)
    });
    let bytes = std::fs::read(&path).expect("read uncompressed small pak fixture");
    let reader = PakReader::from_bytes(bytes).expect("PakReader::from_bytes");

    let mut group = c.benchmark_group("pak_read_entry_uncompressed_small");
    // Per-entry uncompressed_size = 10 KiB.
    group.throughput(Throughput::Bytes(10 * 1024));
    group.bench_function("read_entry", |b| {
        b.iter(|| {
            let v = reader
                .read_entry(black_box("Game/Bench/Entry_000000.dat"))
                .expect("read_entry");
            black_box(v);
        });
    });
    group.finish();
}

/// Bench: read one 10 KiB zlib-compressed entry. Throughput is keyed
/// on the *uncompressed* size — that's the work the parser performs
/// (allocate + decompress into the target Vec).
fn pak_read_entry_zlib_small(c: &mut Criterion) {
    let path = lazy_fixture("pak_zlib_small.pak", || {
        build_pak(10, 10 * 1024, true, 0xAA)
    });
    let bytes = std::fs::read(&path).expect("read zlib small pak fixture");
    let reader = PakReader::from_bytes(bytes).expect("PakReader::from_bytes");

    let mut group = c.benchmark_group("pak_read_entry_zlib_small");
    group.throughput(Throughput::Bytes(10 * 1024));
    group.bench_function("read_entry", |b| {
        b.iter(|| {
            let v = reader
                .read_entry(black_box("Game/Bench/Entry_000000.dat"))
                .expect("read_entry");
            black_box(v);
        });
    });
    group.finish();
}

/// Bench: read one 100 MiB zlib-compressed entry. Tests sustained
/// streaming-decompress throughput. The non-zero payload byte makes
/// the compressed size large enough to exercise multi-block
/// decompression (zlib's default block size is 32 KiB; an all-zero
/// 100 MiB payload would compress to ~100 KiB, defeating the bench).
fn pak_read_entry_zlib_large(c: &mut Criterion) {
    // Single 100 MiB entry; the 0xAA byte fill compresses tighter
    // than random data (zlib finds the run) but still produces a
    // multi-block stream because zlib chunks anyway.
    let path = lazy_fixture("pak_zlib_large.pak", || {
        build_pak(1, 100 * 1024 * 1024, true, 0xAA)
    });
    let bytes = std::fs::read(&path).expect("read zlib large pak fixture");
    let reader = PakReader::from_bytes(bytes).expect("PakReader::from_bytes");

    let mut group = c.benchmark_group("pak_read_entry_zlib_large");
    group.sample_size(10);
    group.throughput(Throughput::Bytes(100 * 1024 * 1024));
    group.bench_function("read_entry_to", |b| {
        b.iter(|| {
            // Stream into /dev/null-equivalent sink so the bench
            // doesn't include `Vec` growth in the timed region —
            // pure decompress + read throughput.
            let mut sink = NullWriter;
            let n = reader
                .read_entry_to(black_box("Game/Bench/Entry_000000.dat"), &mut sink)
                .expect("read_entry_to");
            black_box(n);
        });
    });
    group.finish();
}

/// Bench: `PakReader::verify()` over a 100-entry pak (~10 MiB total).
/// SHA1s every entry payload + the FDI + the PHI. Provides the
/// "operator runs `paksmith verify`" baseline.
fn pak_verify_full(c: &mut Criterion) {
    let path = lazy_fixture("pak_verify_100_entries.pak", || {
        build_pak(100, 100 * 1024, false, 0xAA)
    });
    // Open from path so `verify_*` sees the canonical from-disk shape.
    // The reader is held by `Mutex` internally; closing/reopening per
    // sample would dominate the bench, so the reader is hoisted out of
    // `b.iter()`.
    let reader = PakReader::open(&path).expect("PakReader::open");
    let total_bytes = std::fs::metadata(&path).expect("stat pak fixture").len();

    let mut group = c.benchmark_group("pak_verify_full");
    group.sample_size(10);
    group.throughput(Throughput::Bytes(total_bytes));
    group.bench_function("verify", |b| {
        b.iter(|| {
            let stats = reader.verify().expect("verify");
            black_box(stats);
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    pak_open_tiny,
    pak_open_large,
    pak_read_entry_uncompressed_small,
    pak_read_entry_zlib_small,
    pak_read_entry_zlib_large,
    pak_verify_full
);
criterion_main!(benches);
