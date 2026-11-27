// Coverage-guided fuzzing of the pak LZ4 entry decode path
// (`stream_block_codec_to`, #636), through the harness
// `paksmith_fuzz::fuzz_v8b_block_codec_pak` documents.
//
// What this catches:
//   - Panics / aborts in the per-block decode loop: arbitrary bytes
//     exercise `block_output_cap` (the input-proportional
//     reservation cap), the raw-block decoder (`decompress_into` via
//     lz4_flex `safe-decode`), the non-final block-size invariant, and
//     `check_cumulative_size` — all must surface typed errors, never
//     panic or allocate past the cap.
//   - Decompression bombs: a tiny block claiming a huge
//     `compression_block_size` / `uncompressed_size` must be held to
//     `compressed_len × 255` at reservation time and error out of the
//     decode — never eagerly allocate the claim. Claims stay below
//     `MAX_CLAIMED_BYTES` (~1 MiB), and the cap-vs-claim interplay is
//     fully exercised well below it — a 50-byte block claiming ~1 MiB
//     already trips `block_output_cap` at `50 × 255`.
//
// The reject + cap paths (the DoS-relevant surface) are reached on
// random input by construction.

#![no_main]

use libfuzzer_sys::fuzz_target;

use paksmith_fuzz::{LZ4, fuzz_v8b_block_codec_pak};

fuzz_target!(|data: &[u8]| fuzz_v8b_block_codec_pak(data, &LZ4));
