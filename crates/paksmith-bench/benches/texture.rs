//! Phase 3e texture block-decode benchmarks.
//!
//! The heaviest per-pixel inner loop in the repo. Each bench decodes a
//! 1024×1024 mip (one full block grid) to RGBA8 via the `__test_utils`
//! `decode_texture_mip` accessor, isolating the per-block decode from the
//! surrounding parse + PNG encode. Throughput is reported over the decoded
//! RGBA output (`w·h·4 = 4 MiB`). Encoded block bytes are a fixed pattern — the
//! BCn decoders (`bcdec_rs`) decode any byte pattern at constant per-block cost,
//! so the pattern only needs to be the correct size.
//!
//! Covers the BCn formats (the primary desktop path). ASTC/ETC (mobile, via
//! `texture2ddecoder`) are intentionally out of scope here: that decoder panics
//! on structurally-invalid blocks, so the fixed-pattern input this bench relies
//! on cannot drive it — an ASTC/ETC throughput bench is a self-contained work
//! item requiring valid-block synthesis, not a fixed-pattern fill.

#![allow(unused_results, missing_docs)]

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use paksmith_core::testing::bench::decode_texture_mip;

const DIM: u32 = 1024;

fn run(c: &mut Criterion, group_name: &str, format: &str, block_bytes: usize) {
    let blocks = (DIM.div_ceil(4) as usize) * (DIM.div_ceil(4) as usize);
    let encoded = vec![0x7Fu8; blocks * block_bytes];
    let out_bytes = u64::from(DIM) * u64::from(DIM) * 4;

    let mut group = c.benchmark_group(group_name);
    group.throughput(Throughput::Bytes(out_bytes));
    group.bench_function("decode_1024", |b| {
        b.iter(|| {
            let rgba = decode_texture_mip(black_box(format), black_box(&encoded), DIM, DIM)
                .expect("decode_mip");
            black_box(rgba);
        });
    });
    group.finish();
}

fn texture_decode_bc1(c: &mut Criterion) {
    run(c, "texture_decode_bc1", "PF_DXT1", 8);
}
fn texture_decode_bc3(c: &mut Criterion) {
    run(c, "texture_decode_bc3", "PF_DXT5", 16);
}
fn texture_decode_bc7(c: &mut Criterion) {
    run(c, "texture_decode_bc7", "PF_BC7", 16);
}

criterion_group!(
    benches,
    texture_decode_bc1,
    texture_decode_bc3,
    texture_decode_bc7
);
criterion_main!(benches);
