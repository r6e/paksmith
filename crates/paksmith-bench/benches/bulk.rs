//! Phase 3b bulk-data decompression benchmark.
//!
//! Zlib decompression is the highest-*volume* byte path in the bulk resolver
//! (every compressed mip/buffer flows through it). Decompresses an 8 MiB
//! semi-compressible payload (engine chunked `FCompressedChunkInfo` framing,
//! 64 × 128 KiB chunks) via the `__test_utils` `zlib_decompress` accessor,
//! reporting throughput over the decompressed bytes.
//!
//! Three crafted shapes from #846 time the decoder's cost on untrusted
//! records, reporting throughput per chunk or per block: a flood of empty
//! chunks whose streams each hold one fixed-Huffman block, ending in a
//! corrupt chunk; the same flood with stored blocks; and one chunk of empty
//! fixed-Huffman blocks.

#![allow(unused_results, missing_docs)]

use std::hint::black_box;

use criterion::{Criterion, SamplingMode, Throughput, criterion_group, criterion_main};
use paksmith_core::testing::bench::{
    FOUR_EMPTY_FIXED_BLOCKS, zlib_compress_framed, zlib_decompress, zlib_framing,
    zlib_padded_stream, zlib_stream,
};

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
    let compressed = zlib_compress_framed(&data);
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

const CHUNK_128K: i64 = 131_072;
const FLOOD_CHUNKS: usize = 16_384;

/// A framing at 128 KiB chunks over `table` and its `streams`, whose summary
/// claims `claim` uncompressed bytes.
fn framing(table: &[(i64, i64)], streams: &[u8], claim: i64) -> Vec<u8> {
    let tag = i64::from(paksmith_core::asset::version::PACKAGE_FILE_TAG);
    let total_comp = table.iter().map(|&(c, _)| c).sum();
    zlib_framing((tag, CHUNK_128K), None, (total_comp, claim), table, streams)
}

/// Times one decode of `framed` against `claim`, reporting `elements` per run.
fn time_decode(c: &mut Criterion, name: &str, elements: usize, framed: &[u8], claim: i64) {
    let mut group = c.benchmark_group(name);
    // Flat: every sample runs the same number of these slow iterations.
    group.sampling_mode(SamplingMode::Flat);
    group.sample_size(20);
    group.throughput(Throughput::Elements(elements as u64));
    group.bench_function("decompress", |b| {
        b.iter(|| black_box(zlib_decompress(black_box(framed), claim)));
    });
    group.finish();
}

/// `FLOOD_CHUNKS` chunks: the first `FLOOD_CHUNKS - 1` are `empty`, claiming
/// 0 bytes, and the last is 8 bytes of 0xFF claiming the rest, so every run
/// decodes the empty chunks and then fails at the last.
fn flood_group(c: &mut Criterion, name: &str, empty: &[u8]) {
    let empty_chunks = FLOOD_CHUNKS - 1;
    let len = i64::try_from(empty.len()).expect("fits i64");
    let claim = i64::try_from(empty_chunks).expect("fits i64") * CHUNK_128K + 1;
    let mut table = vec![(len, 0); empty_chunks];
    table.push((8, claim));
    let mut streams = empty.repeat(empty_chunks);
    streams.extend_from_slice(&[0xFF; 8]);
    let framed = framing(&table, &streams, claim);
    let last = format!("chunk {empty_chunks}:");
    let err = zlib_decompress(&framed, claim).expect_err("last chunk is corrupt");
    assert!(err.to_string().contains(&last), "{err}");
    time_decode(c, name, FLOOD_CHUNKS, &framed, claim);
}

/// Each empty chunk is an 8-byte stream holding one fixed-Huffman block.
fn bulk_decompress_zlib_chunk_flood(c: &mut Criterion) {
    let empty = zlib_stream(&[]);
    assert_eq!(empty.len(), 8);
    flood_group(c, "bulk_decompress_zlib_chunk_flood", &empty);
}

/// Each empty chunk is an 11-byte stream holding one stored block, which
/// builds no Huffman table.
fn bulk_decompress_zlib_stored_chunk_flood(c: &mut Criterion) {
    let empty = [
        0x78, 0x01, 0x01, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
    ];
    flood_group(c, "bulk_decompress_zlib_stored_chunk_flood", &empty);
}

/// Groups of four empty non-final fixed-Huffman blocks in the one chunk.
const PADDING_GROUPS: usize = 26_000;

/// One chunk claiming 1 byte, whose stream decodes to b"B" after
/// `4 * PADDING_GROUPS` empty fixed-Huffman blocks.
fn bulk_decompress_zlib_empty_fixed_blocks(c: &mut Criterion) {
    let stream = zlib_padded_stream(FOUR_EMPTY_FIXED_BLOCKS, PADDING_GROUPS);
    let len = i64::try_from(stream.len()).expect("fits i64");
    let framed = framing(&[(len, 1)], &stream, 1);
    assert_eq!(zlib_decompress(&framed, 1).expect("padded stream"), b"B");
    time_decode(
        c,
        "bulk_decompress_zlib_empty_fixed_blocks",
        4 * PADDING_GROUPS,
        &framed,
        1,
    );
}

criterion_group!(
    benches,
    bulk_decompress_zlib_8mib,
    bulk_decompress_zlib_chunk_flood,
    bulk_decompress_zlib_stored_chunk_flood,
    bulk_decompress_zlib_empty_fixed_blocks
);
criterion_main!(benches);
