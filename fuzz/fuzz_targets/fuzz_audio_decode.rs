// Coverage-guided fuzzing of the audio transcoders (ADPCM/WAV + Vorbis).
//
// What this catches:
//   - Panics in the untrusted-header parsers: `parse_wav` / the IMA & MS-ADPCM
//     block decoders and the symphonia-backed Vorbis path all parse
//     attacker-controlled container headers and must surface malformed input
//     as an `Err` / `Ok(None)`, never a panic (core forbids panics).
//   - Unbounded / eager allocation from a lying sample count or data size: the
//     decoders derive + validate geometry and cap the projected PCM size
//     before allocating; the fuzzer probes that bound.
//   - Integer overflow / OOB in block iteration.
//
// Reaches `transcode_adpcm_to_pcm` / `transcode_vorbis_to_pcm` directly via the
// `__test_utils` `testing::bench::transcode_audio` seam.
//
// No committed seed corpus: the harness input is a synthetic
// `[codec-selector byte][payload]` layout, so a raw `.wav`/`.ogg` file wouldn't
// be a valid input. The fuzzer starts from scratch — the untrusted-header
// reject/cap paths (the DoS-relevant surface) are reached on random input.

#![no_main]

use libfuzzer_sys::fuzz_target;
use paksmith_core::testing::bench::transcode_audio;

fuzz_target!(|data: &[u8]| {
    // Byte 0 selects the codec branch (ADPCM/WAV vs Vorbis); the rest is the
    // cooked audio payload the transcoder parses.
    if data.is_empty() {
        return;
    }
    let vorbis = data[0] & 1 == 1;
    let _ = transcode_audio(&data[1..], vorbis);
});
