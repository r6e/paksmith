// Coverage-guided fuzzing of the bulk-data zlib decompression path
// (chunked `FCompressedChunkInfo` framing, #644).
//
// What this catches:
//   - Panics / aborts from the framing parser: arbitrary bytes exercise the
//     tag/summary/chunk-table validation (truncation, negative sizes, sum
//     mismatches, overflow-checked chunk-count math) and the F1 pre-size
//     discipline (table allocation bounded by real input; output pre-sized
//     from `compressed.len()`).
//   - Decompression bombs: a tiny compressed input claiming a huge size must
//     surface an `Err` (the `MAX_BULK_DATA_SIZE` claim cap, framing-sum
//     checks, per-chunk `take(chunk_unc + 1)` bounds), never inflate
//     unbounded.
//   - Malformed deflate streams in chunk payloads: the decoder must return
//     an error, not panic.
//
// This reaches `decompress_zlib` directly via the `__test_utils`
// `testing::bench::zlib_decompress` seam — far more iterations/coverage than
// driving it through a full `.pak` parse (whose `verify()` never inflates).
//
// No committed seed corpus: the harness input is a synthetic
// `[8-byte LE i64 size][compressed stream]` layout, so a raw `.zlib` file
// wouldn't be a valid input. The fuzzer starts from scratch — the reject + cap
// paths (the DoS-relevant surface) are reached on random input by construction.

#![no_main]

use libfuzzer_sys::fuzz_target;
use paksmith_core::testing::bench::zlib_decompress;

fuzz_target!(|data: &[u8]| {
    // First 8 bytes = the wire-claimed decompressed size (`ElementCount`, an
    // attacker-controlled `i64`); the remainder is the compressed stream. This
    // is the exact split `decompress_zlib` sees: a claimed length plus bytes
    // that may or may not inflate to it.
    if data.len() < 8 {
        return;
    }
    let expected = i64::from_le_bytes(data[..8].try_into().expect("8 bytes"));
    let _ = zlib_decompress(&data[8..], expected);
});
