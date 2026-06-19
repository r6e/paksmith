// Coverage-guided fuzzing of the BC + linear texture mip decoders.
//
// What this catches:
//   - Decode-time panics / OOB / overflow in the safe BC path (`bcdec_rs`,
//     covering BC1-7) and the linear repack path. These decoders are NOT
//     `catch_unwind`-wrapped — the code relies on them being panic-free on a
//     correctly-sized buffer — so a panic here is a REAL uncaught DoS, not a
//     contained one.
//
// **ASTC/ETC are deliberately excluded.** Those route through the C
// `texture2ddecoder` library, which panics on malformed block bit-patterns and
// is therefore wrapped in `std::panic::catch_unwind` (a corrupt texture becomes
// an `Err`, not a crash). But `libfuzzer-sys` installs a global panic hook that
// aborts the process on ANY panic — it fires before the unwind reaches that
// `catch_unwind`, so fuzzing ASTC/ETC would report contained-and-handled panics
// as false-positive crashes (a perpetually-red target). That containment is
// already pinned by the `astc_decoder_panics_are_contained` unit test; fuzzing
// adds value only on the un-contained BC/linear path, where a panic is a bug.
//
// Reaching the decoder requires an exactly-sized encoded buffer: `decode_mip`
// rejects any mismatched length BEFORE decoding. The target sizes the buffer to
// the format's exact encoded length (via the `texture_encoded_len` seam) and
// fills it with fuzz bytes, so every iteration reaches the decoder and explores
// block CONTENT rather than bouncing off the length check. Dimensions are
// clamped small so the fuzzer probes block bit-patterns, not the size cap.
//
// No committed seed corpus: the harness input is a synthetic
// `[format byte][width byte][height byte][block-content fill]` layout, so no
// fixture file is a valid input. Every input reaches the decoder by
// construction (the buffer is sized to the exact length `decode_mip` accepts),
// so the fuzzer explores block content from scratch.

#![no_main]

use libfuzzer_sys::fuzz_target;
use paksmith_core::testing::bench::{decode_texture_mip, texture_encoded_len};

// The BC (block, via `bcdec_rs`) + linear (uncompressed / HDR-float repack)
// decodable `EPixelFormat` names — the 13 formats left when the 8
// `catch_unwind`-contained ones (`PF_ASTC_4x4/6x6/8x8/10x10/12x12`, `PF_ETC1`,
// `PF_ETC2_RGB`, `PF_ETC2_RGBA`; see the header note) are removed from the 21
// that `PixelFormat::from_name` decodes. Every format here routes through a
// non-`catch_unwind` decoder, so a panic on any of them is an un-contained bug
// worth a crash report.
const FORMATS: &[&str] = &[
    // BC, via bcdec_rs (BC6H is its most complex bit-parser).
    "PF_DXT1",
    "PF_DXT3",
    "PF_DXT5",
    "PF_BC4",
    "PF_BC5",
    "PF_BC6H",
    "PF_BC7",
    // Linear / HDR-float repack, pure Rust.
    "PF_R8G8B8A8",
    "PF_B8G8R8A8",
    "PF_G8",
    "PF_G16",
    "PF_FloatRGB",
    "PF_FloatRGBA",
];

fuzz_target!(|data: &[u8]| {
    // Byte 0 selects the format; bytes 1-2 the (clamped 1..=256) dimensions;
    // the rest fills the encoded buffer.
    if data.len() < 3 {
        return;
    }
    let format = FORMATS[data[0] as usize % FORMATS.len()];
    let width = 1 + u32::from(data[1]); // 1..=256
    let height = 1 + u32::from(data[2]); // 1..=256

    // The exact length `decode_mip` accepts; `None` skips (overflow / unknown).
    let Some(len) = texture_encoded_len(format, width, height) else {
        return;
    };

    // Fill an exactly-`len` buffer by cycling the remaining fuzz bytes so the
    // decoder always runs on attacker-controlled block content.
    let fill = &data[3..];
    let encoded: Vec<u8> = if fill.is_empty() {
        vec![0u8; len]
    } else {
        (0..len).map(|i| fill[i % fill.len()]).collect()
    };

    let _ = decode_texture_mip(format, &encoded, width, height);
});
