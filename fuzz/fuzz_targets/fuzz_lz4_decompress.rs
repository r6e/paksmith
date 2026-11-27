// Coverage-guided fuzzing of the pak LZ4 entry decode path
// (`stream_block_codec_to`, #636), through the harness
// `paksmith_fuzz::fuzz_v8b_block_codec_pak` documents.
//
// What this exercises:
//   - The per-block decode loop: arbitrary bytes reach
//     `block_output_cap` (the input-proportional reservation cap), the
//     raw-block decoder (`decompress_into` via lz4_flex `safe-decode`),
//     the non-final block-size invariant, and `check_cumulative_size`.
//   - Decompression-bomb shapes: a tiny block claiming a large
//     `compression_block_size` / `uncompressed_size` reaches the cap's
//     `compressed_len × 255` clamp. Claims stay below
//     `MAX_CLAIMED_BYTES` (~1 MiB), and the cap-vs-claim interplay is
//     fully exercised well below it — a 50-byte block claiming ~1 MiB
//     already trips `block_output_cap` at `50 × 255`.
//
// It can't see a reservation of the claim or of `compressed_len × 255`
// in place of the cap, since under `-max_len` both stay under
// libFuzzer's malloc limit; the codec unit tests
// `lz4_reserve_requests_min_budget_and_255x`,
// `lz4_block_output_cap_bounds_crafted_oversized_claim` and
// `lz4_output_past_budget_is_corrupt` pin the reservation and the budget.
//
// The reject + cap paths (the DoS-relevant surface) are reached on
// random input by construction.

#![no_main]

use libfuzzer_sys::fuzz_target;

use paksmith_fuzz::{LZ4, fuzz_v8b_block_codec_pak};

fuzz_target!(|data: &[u8]| fuzz_v8b_block_codec_pak(data, &LZ4));
