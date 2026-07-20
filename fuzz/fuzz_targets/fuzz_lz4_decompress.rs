// Coverage-guided fuzzing of the pak LZ4 entry decode path
// (`stream_lz4_to`, #636).
//
// What this catches:
//   - Panics / aborts in the per-block decode loop: arbitrary bytes
//     exercise `lz4_block_output_cap` (the input-proportional
//     reservation cap), the raw-block decoder (`decompress_into` via
//     lz4_flex `safe-decode`), the non-final block-size invariant, and
//     `check_cumulative_size` — all must surface typed errors, never
//     panic or allocate past the cap.
//   - Decompression bombs: a tiny block claiming a huge
//     `compression_block_size` / `uncompressed_size` must be held to
//     `compressed_len × 255` at reservation time and error out of the
//     decode — never eagerly allocate the claim.
//
// The harness synthesizes a structurally-valid v8b LZ4 pak around the
// fuzz payload with `testing::wire::build_v8b_lz4_pak` (real footer,
// slot table, legacy index + entry SHA1), so iterations spend their
// budget in the decode loop rather than bouncing off footer/index
// validation. This drives the REAL public path (`PakReader::from_bytes`
// → `read_entry_to`), not a bench seam.
//
// No committed seed corpus: the harness input is a synthetic
// `[4-byte LE uncompressed_size][4-byte LE block_size][split byte][block bytes]`
// layout, so a committed fixture file wouldn't be well-formed for the
// harness. The fuzzer starts from scratch — the reject + cap paths (the
// DoS-relevant surface) are reached on random input by construction.

#![no_main]

use libfuzzer_sys::fuzz_target;
use paksmith_core::container::ContainerReader as _;
use paksmith_core::container::pak::PakReader;
use paksmith_core::testing::wire::{LZ4_SYNTH_PATH, build_v8b_lz4_pak};

/// Cap on the wire-claimed sizes (both `uncompressed_size` and
/// `compression_block_size` stay below ~1 MiB) so a fuzz iteration's
/// honest work (output buffer + `Vec` writer) stays small and
/// iterations stay fast. The cap-vs-claim interplay is fully exercised
/// well below this — a 50-byte block claiming ~1 MiB already trips
/// `lz4_block_output_cap` at `50 × 255`.
const MAX_CLAIMED_BYTES: u32 = 1 << 20;

fuzz_target!(|data: &[u8]| {
    if data.len() < 9 {
        return;
    }
    let uncompressed_size =
        u64::from(u32::from_le_bytes(data[..4].try_into().expect("4 bytes")) % MAX_CLAIMED_BYTES);
    let block_size =
        u32::from_le_bytes(data[4..8].try_into().expect("4 bytes")) % MAX_CLAIMED_BYTES;
    let split = u64::from(data[8]);
    let rest = &data[9..];

    // One or two compression blocks: a mid-payload pivot derived from
    // the split byte exercises the non-final block-size invariant and
    // the multi-block accounting; a pivot of 0 / len degenerates to a
    // single block. The multiply is widened to u64 so it can't
    // overflow usize on a 32-bit target with a pathologically large
    // input (fuzz builds carry overflow checks); the quotient is
    // <= rest.len(), so the narrowing cast back is lossless.
    let pivot = (split * rest.len() as u64 / 256) as usize;
    let streams: Vec<Vec<u8>> = if pivot > 0 && pivot < rest.len() {
        vec![rest[..pivot].to_vec(), rest[pivot..].to_vec()]
    } else {
        vec![rest.to_vec()]
    };

    let pak = build_v8b_lz4_pak(&streams, uncompressed_size, block_size);
    let Ok(reader) = PakReader::from_bytes(pak) else {
        return;
    };
    let mut out = Vec::new();
    let _ = reader.read_entry_to(LZ4_SYNTH_PATH, &mut out);
});
