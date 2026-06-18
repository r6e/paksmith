//! Phase 3b bulk-data decompression benchmark.
//!
//! Zlib decompression is the highest-*volume* byte path in the bulk resolver
//! (every compressed mip/buffer flows through it). Decompresses an 8 MiB
//! semi-compressible payload via the `__test_utils` `zlib_decompress` accessor,
//! reporting throughput over the decompressed bytes.

#![allow(unused_results, missing_docs)]

use std::hint::black_box;
use std::io::Write;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use flate2::Compression;
use flate2::write::ZlibEncoder;
use paksmith_core::testing::bench::zlib_decompress;

const UNCOMPRESSED: usize = 8 * 1024 * 1024;

fn make_payload() -> (Vec<u8>, i64) {
    // Semi-compressible: deterministic xorshift noise masked to 6 bits, so the
    // stream is neither trivially compressible nor incompressible — representative
    // of a cooked-texture mip.
    let mut data = vec![0u8; UNCOMPRESSED];
    let mut s: u32 = 0x1234_5678;
    for b in &mut data {
        s ^= s << 13;
        s ^= s >> 17;
        s ^= s << 5;
        #[allow(clippy::cast_possible_truncation)]
        {
            *b = (s & 0x3F) as u8;
        }
    }
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
    enc.write_all(&data).expect("zlib write");
    let compressed = enc.finish().expect("zlib finish");
    (compressed, i64::try_from(UNCOMPRESSED).expect("fits i64"))
}

fn bulk_decompress_zlib_8mib(c: &mut Criterion) {
    let (compressed, expected) = make_payload();
    let mut group = c.benchmark_group("bulk_decompress_zlib_8mib");
    group.throughput(Throughput::Bytes(
        u64::try_from(UNCOMPRESSED).expect("fits u64"),
    ));
    group.bench_function("decompress", |b| {
        b.iter(|| {
            let out = zlib_decompress(black_box(&compressed), expected).expect("zlib_decompress");
            black_box(out);
        });
    });
    group.finish();
}

criterion_group!(benches, bulk_decompress_zlib_8mib);
criterion_main!(benches);
