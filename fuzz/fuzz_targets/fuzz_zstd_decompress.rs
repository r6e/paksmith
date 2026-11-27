// Coverage-guided fuzzing of the pak Zstd entry decode path
// (`stream_block_codec_to`, #1082), the first path that hands archive
// payload bytes to libzstd, through the harness
// `paksmith_fuzz::fuzz_v8b_block_codec_pak` documents.
//
// What this catches:
//   - Panics / aborts in the per-block decode loop: arbitrary bytes
//     exercise the v1-frame gate (`zstd_v1_frames`, which checks every
//     frame's magic so pre-v1 frames never reach libzstd's legacy
//     decoders), and blocks that pass it exercise `block_output_cap`
//     (the input-proportional reservation cap), the one-shot libzstd
//     decode into the output buffer's spare capacity, the
//     past-the-bound check on what libzstd produced, the non-final
//     block-size invariant, and `check_cumulative_size` — all must
//     surface typed errors, never panic or allocate past the cap.
//   - Decompression bombs: a tiny block claiming a huge
//     `compression_block_size` / `uncompressed_size` must be held to
//     `compressed_len × 32768` at reservation time and error out of the
//     decode — never eagerly allocate the claim. Claims stay below
//     `MAX_CLAIMED_BYTES` (~1 MiB), and the cap-vs-claim interplay is
//     fully exercised well below it — a 16-byte block claiming ~1 MiB
//     already trips `block_output_cap` at `16 × 32768`.
//
// Random input reaches only the gate's rejection; the cap, the
// reservation and the libzstd decode run once the fuzzer builds a block
// of whole v1 or skippable frames, which a 60-second local run did.

#![no_main]

use libfuzzer_sys::fuzz_target;

use paksmith_fuzz::{ZSTD, fuzz_v8b_block_codec_pak};

fuzz_target!(|data: &[u8]| fuzz_v8b_block_codec_pak(data, &ZSTD));
