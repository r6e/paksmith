// Coverage-guided fuzzing of the pak Gzip entry decode path
// (`stream_block_codec_to`, #1082), the path that hands archive payload
// bytes to flate2's gzip decoder, through the harness
// `paksmith_fuzz::fuzz_v8b_block_codec_pak` documents.
//
// What this exercises:
//   - The per-block decode loop: arbitrary bytes reach flate2's gzip
//     header parse (the magic, the method, the flags and the optional
//     extra, name, comment and header-CRC fields), and members that pass
//     it reach the inflate, the CRC-32 and length trailer checks, the
//     `take` of the block's budget plus one byte, `read_to_end_within`'s
//     fallible growth of the output buffer, the past-the-budget check,
//     the non-final block-size invariant, and `check_cumulative_size`.
//   - Decompression-bomb shapes: a tiny block claiming a large
//     `compression_block_size` / `uncompressed_size`, or a member that
//     inflates past its block's budget, reaches the `take` and the
//     past-the-budget check. Gzip reserves nothing from the claim: the
//     output buffer grows as the member inflates.
//
// Its oracle doesn't check how far the buffer grows; the codec unit tests
// `gzip_take_stops_a_member_past_its_budget` and
// `gzip_growth_stops_at_the_budget` pin the take that stops it and the
// ceiling on doubling.
//
// The nightly passes `fuzz/dicts/gzip.dict`.

#![no_main]

use libfuzzer_sys::fuzz_target;

use paksmith_fuzz::{GZIP, fuzz_v8b_block_codec_pak};

fuzz_target!(|data: &[u8]| fuzz_v8b_block_codec_pak(data, &GZIP));
