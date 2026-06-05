//! IMA/DVI ADPCM (`WAVE_FORMAT_DVI_ADPCM`, `wFormatTag = 0x0011`) → PCM decode
//! for the `WavHandler` export path (Phase 3f).
//!
//! UE cooks the `"ADPCM"` codec key as a complete RIFF/WAVE container whose
//! `data` chunk holds IMA-ADPCM-encoded blocks (see
//! `docs/formats/audio/audio-codecs.md`). [`WavHandler`] already exports that
//! WAV verbatim — a valid file that ADPCM-aware players decode. This module
//! adds the decode: it transcodes the IMA-ADPCM blocks to 16-bit PCM and
//! re-wraps them as a `WAVE_FORMAT_PCM` WAV, which plays everywhere.
//!
//! **No CUE4Parse oracle.** Unlike every other Phase 3f wire format, CUE4Parse
//! has no ADPCM decoder — its `SoundDecoder` passes the ADPCM WAV through
//! unchanged. The decode here is implemented against the public Microsoft
//! WAV / IMA-ADPCM specification and **cross-validated against `ffmpeg`'s
//! `adpcm_ima_wav` codec** via committed golden-vector fixtures (mono + stereo;
//! see the test module). Correctness is "matches the IMA-WAV reference"; that
//! UE's cooked `"ADPCM"` buffers are standard IMA-WAV is assumed from the
//! confirmed standard RIFF/WAVE container (`WavHandler` already ships them as
//! playable passthrough `.wav`s), pending a real-asset confirmation fixture.
//!
//! [`WavHandler`]: crate::export::WavHandler

use crate::PaksmithError;

/// `wFormatTag` values this module dispatches on (subset of the WAV registry).
const WAVE_FORMAT_DVI_ADPCM: u16 = 0x0011;

/// Upper bound on a single decode's PCM output, enforced **before** allocating
/// the output buffer (decompression-bomb guard). IMA is a fixed ~4:1 ratio and
/// the input is already resolver-capped, so this is generous headroom for real
/// audio (≈1.5 h of 48 kHz stereo) while still bounding a crafted-header attack.
pub(crate) const MAX_AUDIO_DECODED_BYTES: usize = 1024 * 1024 * 1024;

/// `__test_utils` accessor so out-of-crate boundary tests read the live cap
/// value (mirrors the `bulk_data` cap accessors). Re-exported from
/// [`crate::export`] so `paksmith-core-tests` can reach it past the private
/// `adpcm` module.
#[cfg(feature = "__test_utils")]
#[must_use]
pub fn max_audio_decoded_bytes() -> usize {
    MAX_AUDIO_DECODED_BYTES
}

/// IMA-ADPCM step-size table (89 entries), per the Microsoft / IMA spec.
#[rustfmt::skip]
const STEP_TABLE: [i32; 89] = [
    7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 19, 21, 23, 25, 28, 31, 34, 37, 41, 45,
    50, 55, 60, 66, 73, 80, 88, 97, 107, 118, 130, 143, 157, 173, 190, 209, 230,
    253, 279, 307, 337, 371, 408, 449, 494, 544, 598, 658, 724, 796, 876, 963,
    1060, 1166, 1282, 1411, 1552, 1707, 1878, 2066, 2272, 2499, 2749, 3024, 3327,
    3660, 4026, 4428, 4871, 5358, 5894, 6484, 7132, 7845, 8630, 9493, 10442,
    11487, 12635, 13899, 15289, 16818, 18500, 20350, 22385, 24623, 27086, 29794,
    32767,
];

/// IMA-ADPCM step-index adjustment table (16 entries; indexed by the 4-bit code).
#[rustfmt::skip]
const INDEX_TABLE: [i32; 16] = [-1, -1, -1, -1, 2, 4, 6, 8, -1, -1, -1, -1, 2, 4, 6, 8];

/// Highest valid step index (`STEP_TABLE.len() - 1 == 88`); the step index is
/// clamped to `0..=MAX_STEP_INDEX`.
const MAX_STEP_INDEX: i32 = 88;
const _: () = assert!(STEP_TABLE.len() == 89);

/// The parsed `fmt ` fields this decoder needs.
struct WavFmt {
    format_tag: u16,
    channels: u16,
    sample_rate: u32,
    block_align: u16,
    /// `samplesPerBlock` from the ADPCM `fmt ` extension (`0` if absent).
    samples_per_block: u16,
}

fn read_u16le(buf: &[u8], off: usize) -> Option<u16> {
    buf.get(off..off + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
}

fn read_u32le(buf: &[u8], off: usize) -> Option<u32> {
    buf.get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Parse a RIFF/WAVE container, returning its `fmt ` fields and `data` chunk
/// bytes. Walks the chunk list (skipping `fact` / `LIST` / any non-`fmt`/`data`
/// chunk, honoring RIFF word-padding) and bounds-checks every read. Returns
/// `None` when the buffer is not a well-formed RIFF/WAVE with both a `fmt ` and
/// a `data` chunk — the caller treats that as "not decodable here, pass
/// through".
fn parse_wav(buf: &[u8]) -> Option<(WavFmt, &[u8])> {
    if buf.get(0..4)? != b"RIFF" || buf.get(8..12)? != b"WAVE" {
        return None;
    }
    let mut fmt: Option<WavFmt> = None;
    let mut data: Option<&[u8]> = None;
    let mut pos = 12; // past "RIFF" + size + "WAVE"
    while pos + 8 <= buf.len() {
        let id = buf.get(pos..pos + 4)?;
        let size = read_u32le(buf, pos + 4)? as usize;
        let body_start = pos + 8;
        let body = buf.get(body_start..body_start.checked_add(size)?)?;
        match id {
            b"fmt " => {
                fmt = Some(WavFmt {
                    format_tag: read_u16le(body, 0)?,
                    channels: read_u16le(body, 2)?,
                    sample_rate: read_u32le(body, 4)?,
                    block_align: read_u16le(body, 12)?,
                    // `cbSize` (off 16) ≥ 2 ⇒ `samplesPerBlock` at off 18.
                    samples_per_block: read_u16le(body, 18).unwrap_or(0),
                });
            }
            b"data" => data = Some(body),
            _ => {}
        }
        // Chunks are word-aligned: an odd size carries a trailing pad byte.
        pos = body_start + size + (size & 1);
    }
    Some((fmt?, data?))
}

/// Computed per-block geometry for an IMA-ADPCM WAV, with the corrupt-input
/// guards the format requires.
struct BlockGeometry {
    /// Decoded samples per channel per block (= the `fmt ` `samplesPerBlock`).
    samples_per_block: usize,
    /// Number of 4-byte data words per channel per block (after the header).
    words_per_channel: usize,
    /// Number of whole blocks in the `data` chunk.
    num_blocks: usize,
}

/// Validate the IMA-ADPCM block layout and derive its geometry. Mirrors the
/// hardening checks in `docs/formats/audio/audio-codecs.md`: reject
/// `nBlockAlign == 0` (div-by-zero), a block too small for the per-channel
/// headers, a `data` size not a whole multiple of `nBlockAlign`, and a stored
/// `samplesPerBlock` inconsistent with the derived geometry (a header-inflation
/// guard — the decoder sizes its output from this).
fn block_geometry(fmt: &WavFmt, data_len: usize) -> crate::Result<BlockGeometry> {
    let channels = usize::from(fmt.channels);
    let block_align = usize::from(fmt.block_align);
    let internal = |msg: String| PaksmithError::Internal { context: msg };

    if channels == 0 {
        return Err(internal("ADPCM decode: zero channels".to_string()));
    }
    let header_bytes = 4 * channels; // 4-byte IMA header per channel
    if block_align <= header_bytes {
        return Err(internal(format!(
            "ADPCM decode: nBlockAlign {block_align} too small for {channels}-channel header"
        )));
    }
    let data_bytes = block_align - header_bytes;
    if !data_bytes.is_multiple_of(4 * channels) {
        return Err(internal(format!(
            "ADPCM decode: block data {data_bytes} not a whole {channels}×4-byte interleave group"
        )));
    }
    if !data_len.is_multiple_of(block_align) {
        return Err(internal(format!(
            "ADPCM decode: data size {data_len} not a multiple of nBlockAlign {block_align}"
        )));
    }
    let words_per_channel = data_bytes / (4 * channels);
    let derived_spb = 1 + words_per_channel * 8; // 1 predictor + 8 samples/word
    // The stored value is the oracle's declaration; require it to match the
    // geometry so a crafted `samplesPerBlock` can't drive the output sizing.
    if usize::from(fmt.samples_per_block) != derived_spb {
        return Err(internal(format!(
            "ADPCM decode: samplesPerBlock {} disagrees with block geometry {derived_spb}",
            fmt.samples_per_block
        )));
    }
    Ok(BlockGeometry {
        samples_per_block: derived_spb,
        words_per_channel,
        num_blocks: data_len / block_align,
    })
}

/// Total decoded PCM byte count for `num_blocks` blocks of `samples_per_block`
/// samples across `channels` (16-bit), or `Err` if it overflows or exceeds
/// [`MAX_AUDIO_DECODED_BYTES`]. Pure + checked so the cap is unit-testable
/// without a gigabyte fixture.
fn projected_pcm_bytes(
    num_blocks: usize,
    samples_per_block: usize,
    channels: usize,
) -> crate::Result<usize> {
    let bytes = num_blocks
        .checked_mul(samples_per_block)
        .and_then(|n| n.checked_mul(channels))
        .and_then(|n| n.checked_mul(2));
    match bytes {
        Some(n) if n <= MAX_AUDIO_DECODED_BYTES => Ok(n),
        _ => Err(PaksmithError::Internal {
            context: format!(
                "ADPCM decode: projected output exceeds the {MAX_AUDIO_DECODED_BYTES}-byte cap"
            ),
        }),
    }
}

/// Decode one 4-bit IMA code, advancing `predictor` and `step_index` in place,
/// and return the emitted 16-bit sample.
///
/// `step_index` stays in `0..=MAX_STEP_INDEX` and `predictor` is clamped to the
/// `i16` range every step, so the `as usize` (table index) and `as i16`
/// (output) casts are exact, not lossy.
#[allow(
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    reason = "step_index ∈ 0..=MAX_STEP_INDEX, predictor clamped to i16 range before each cast"
)]
fn decode_nibble(code: u8, predictor: &mut i32, step_index: &mut i32) -> i16 {
    let step = STEP_TABLE[*step_index as usize];
    let mut diff = step >> 3;
    if code & 1 != 0 {
        diff += step >> 2;
    }
    if code & 2 != 0 {
        diff += step >> 1;
    }
    if code & 4 != 0 {
        diff += step;
    }
    if code & 8 != 0 {
        *predictor -= diff;
    } else {
        *predictor += diff;
    }
    *predictor = (*predictor).clamp(i32::from(i16::MIN), i32::from(i16::MAX));
    *step_index = (*step_index + INDEX_TABLE[usize::from(code)]).clamp(0, MAX_STEP_INDEX);
    *predictor as i16
}

/// Decode one block into `out` (length `samples_per_block * channels`,
/// frame-interleaved). Each channel's 4-byte header seeds its predictor +
/// step-index (frame 0 is the predictor); the per-channel 4-byte data words are
/// interleaved (`[ch0 w0][ch1 w0][ch0 w1]…`), each byte's low nibble before its
/// high nibble.
fn decode_block(
    block: &[u8],
    channels: usize,
    geom: &BlockGeometry,
    out: &mut [i16],
) -> crate::Result<()> {
    for ch in 0..channels {
        // 4-byte header: predictor (i16 LE), step index (u8), reserved (u8).
        let head = ch * 4;
        let predictor_init = i16::from_le_bytes([block[head], block[head + 1]]);
        let mut predictor = i32::from(predictor_init);
        let mut step_index = i32::from(block[head + 2]);
        if step_index > MAX_STEP_INDEX {
            return Err(PaksmithError::Internal {
                context: format!("ADPCM decode: block step index {step_index} out of range"),
            });
        }
        out[ch] = predictor_init; // frame 0
        for w in 0..geom.words_per_channel {
            let word_off = 4 * channels + (w * channels + ch) * 4;
            let word = &block[word_off..word_off + 4];
            for (byte_i, &byte) in word.iter().enumerate() {
                for (nib_i, code) in [byte & 0x0F, byte >> 4].into_iter().enumerate() {
                    let frame = 1 + w * 8 + byte_i * 2 + nib_i;
                    out[frame * channels + ch] =
                        decode_nibble(code, &mut predictor, &mut step_index);
                }
            }
        }
    }
    Ok(())
}

/// Build a minimal `WAVE_FORMAT_PCM` 16-bit WAV (`RIFF`/`fmt `/`data`) around
/// frame-interleaved `samples`.
///
/// The decode path caps its output at [`MAX_AUDIO_DECODED_BYTES`] (1 GiB) before
/// calling this, so `samples.len() * 2` always fits in the `u32` chunk-size
/// fields.
#[allow(
    clippy::cast_possible_truncation,
    reason = "samples.len()*2 ≤ MAX_AUDIO_DECODED_BYTES (1 GiB) < u32::MAX (cap-checked before decode)"
)]
fn build_pcm_wav(samples: &[i16], channels: u16, sample_rate: u32) -> Vec<u8> {
    // `channels` and `sample_rate` come from the wire. The production caller
    // bounds `channels` via `block_geometry`, but saturate both multiplies here
    // so this helper is overflow-panic-safe on its own — a crafted (or a future
    // direct-caller's) value writes cosmetically-wrong header fields, not a panic.
    let block_align = channels.saturating_mul(2);
    let byte_rate = sample_rate.saturating_mul(u32::from(block_align));
    let data_len = (samples.len() * 2) as u32;
    let mut wav = Vec::with_capacity(44 + samples.len() * 2);
    wav.extend_from_slice(b"RIFF");
    wav.extend_from_slice(&(36 + data_len).to_le_bytes());
    wav.extend_from_slice(b"WAVE");
    wav.extend_from_slice(b"fmt ");
    wav.extend_from_slice(&16u32.to_le_bytes()); // PCM fmt chunk size
    wav.extend_from_slice(&1u16.to_le_bytes()); // WAVE_FORMAT_PCM
    wav.extend_from_slice(&channels.to_le_bytes());
    wav.extend_from_slice(&sample_rate.to_le_bytes());
    wav.extend_from_slice(&byte_rate.to_le_bytes());
    wav.extend_from_slice(&block_align.to_le_bytes());
    wav.extend_from_slice(&16u16.to_le_bytes()); // bits per sample
    wav.extend_from_slice(b"data");
    wav.extend_from_slice(&data_len.to_le_bytes());
    for &s in samples {
        wav.extend_from_slice(&s.to_le_bytes());
    }
    wav
}

/// Transcode an IMA-ADPCM WAV buffer to a 16-bit PCM WAV.
///
/// Returns `Ok(Some(pcm_wav))` when `buf` is a well-formed IMA-ADPCM
/// (`wFormatTag = 0x0011`) WAV; `Ok(None)` when it is any other format
/// (`WAVE_FORMAT_PCM`, Microsoft ADPCM, an unknown tag, or not a parseable
/// RIFF/WAVE) so the caller passes the buffer through unchanged; `Err` when it
/// *is* IMA-ADPCM but the block layout is corrupt or the projected output
/// exceeds [`MAX_AUDIO_DECODED_BYTES`].
pub(crate) fn transcode_ima_adpcm_to_pcm(buf: &[u8]) -> crate::Result<Option<Vec<u8>>> {
    let Some((fmt, data)) = parse_wav(buf) else {
        return Ok(None);
    };
    if fmt.format_tag != WAVE_FORMAT_DVI_ADPCM {
        return Ok(None);
    }
    let channels = usize::from(fmt.channels);
    let geom = block_geometry(&fmt, data.len())?;
    let projected = projected_pcm_bytes(geom.num_blocks, geom.samples_per_block, channels)?;

    let mut samples = vec![0i16; projected / 2];
    let frame_stride = geom.samples_per_block * channels;
    for (block, out) in data
        .chunks_exact(usize::from(fmt.block_align))
        .zip(samples.chunks_mut(frame_stride))
    {
        decode_block(block, channels, &geom, out)?;
    }
    Ok(Some(build_pcm_wav(&samples, fmt.channels, fmt.sample_rate)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "__test_utils")]
    #[test]
    fn cap_accessor_reports_the_live_cap() {
        assert_eq!(super::max_audio_decoded_bytes(), MAX_AUDIO_DECODED_BYTES);
    }

    const MONO_ADPCM: &[u8] = include_bytes!("testdata/adpcm_ima_mono.wav");
    const MONO_PCM: &[u8] = include_bytes!("testdata/adpcm_ima_mono_expected.pcm");
    const STEREO_ADPCM: &[u8] = include_bytes!("testdata/adpcm_ima_stereo.wav");
    const STEREO_PCM: &[u8] = include_bytes!("testdata/adpcm_ima_stereo_expected.pcm");

    /// Extract the `data` chunk bytes from a PCM WAV the decoder produced.
    fn pcm_data(wav: &[u8]) -> Vec<u8> {
        let (fmt, data) = parse_wav(wav).expect("decoder output is a valid WAV");
        assert_eq!(fmt.format_tag, 1, "output is WAVE_FORMAT_PCM");
        assert_eq!(read_u16le(&wav[20..], 14), Some(16), "16-bit");
        data.to_vec()
    }

    // ===== golden vectors vs ffmpeg adpcm_ima_wav =====

    #[test]
    fn ima_mono_decode_matches_ffmpeg() {
        let out = transcode_ima_adpcm_to_pcm(MONO_ADPCM)
            .expect("decode ok")
            .expect("mono is IMA-ADPCM");
        assert_eq!(pcm_data(&out), MONO_PCM);
        // Mono PCM header (channels = 1): block align 2, byte rate 22050*1*2.
        assert_eq!(read_u16le(&out[20..], 2), Some(1)); // channels
        assert_eq!(read_u16le(&out[20..], 12), Some(2)); // block align = 1*2
        assert_eq!(read_u32le(&out[20..], 8), Some(44100)); // byte rate
    }

    #[test]
    fn ima_stereo_decode_matches_ffmpeg() {
        // The interleave + multi-block path: distinct L/R content, 2 blocks.
        let out = transcode_ima_adpcm_to_pcm(STEREO_ADPCM)
            .expect("decode ok")
            .expect("stereo is IMA-ADPCM");
        assert_eq!(pcm_data(&out), STEREO_PCM);
    }

    #[test]
    fn decoded_wav_header_is_spec_correct() {
        let out = transcode_ima_adpcm_to_pcm(STEREO_ADPCM).unwrap().unwrap();
        // fmt: PCM, 2ch, 22050 Hz, block align 4, byte rate 88200, 16-bit.
        assert_eq!(&out[0..4], b"RIFF");
        assert_eq!(&out[8..12], b"WAVE");
        assert_eq!(read_u16le(&out[20..], 0), Some(1)); // WAVE_FORMAT_PCM
        assert_eq!(read_u16le(&out[20..], 2), Some(2)); // channels
        assert_eq!(read_u32le(&out[20..], 4), Some(22050)); // sample rate
        assert_eq!(read_u32le(&out[20..], 8), Some(88200)); // byte rate = 22050*2*2
        assert_eq!(read_u16le(&out[20..], 12), Some(4)); // block align = 2*2
        assert_eq!(read_u16le(&out[20..], 14), Some(16)); // bits
        // Total length consistent with declared sizes.
        let riff_size = read_u32le(&out, 4).unwrap() as usize;
        assert_eq!(riff_size + 8, out.len());
    }

    // ===== passthrough (Ok(None)) dispatch =====

    #[test]
    fn non_adpcm_formats_pass_through() {
        // A PCM (0x0001) WAV → None (already PCM, no decode).
        let pcm = build_pcm_wav(&[1, 2, 3, 4], 2, 22050);
        assert!(transcode_ima_adpcm_to_pcm(&pcm).unwrap().is_none());
        // A Microsoft-ADPCM (0x0002) WAV → None (handled by a later slice).
        let mut ms = pcm.clone();
        ms[20] = 0x02; // fmt tag low byte → 0x0002
        assert!(transcode_ima_adpcm_to_pcm(&ms).unwrap().is_none());
        // An unknown tag → None.
        let mut unknown = pcm.clone();
        unknown[20] = 0x99;
        assert!(transcode_ima_adpcm_to_pcm(&unknown).unwrap().is_none());
    }

    #[test]
    fn non_wav_buffer_passes_through() {
        assert!(
            transcode_ima_adpcm_to_pcm(b"OggS not a wav")
                .unwrap()
                .is_none()
        );
        assert!(transcode_ima_adpcm_to_pcm(&[]).unwrap().is_none());
    }

    // ===== corrupt-input + cap guards =====

    /// Build a minimal IMA-ADPCM WAV header with the given fmt fields and a
    /// `data` chunk of `data_len` zero bytes (no real audio — only the geometry
    /// guards are exercised).
    fn ima_header(
        channels: u16,
        block_align: u16,
        samples_per_block: u16,
        data_len: usize,
    ) -> Vec<u8> {
        let mut w = Vec::new();
        w.extend_from_slice(b"RIFF");
        w.extend_from_slice(&0u32.to_le_bytes()); // size (unused by parser)
        w.extend_from_slice(b"WAVE");
        w.extend_from_slice(b"fmt ");
        w.extend_from_slice(&20u32.to_le_bytes());
        w.extend_from_slice(&WAVE_FORMAT_DVI_ADPCM.to_le_bytes());
        w.extend_from_slice(&channels.to_le_bytes());
        w.extend_from_slice(&22050u32.to_le_bytes());
        w.extend_from_slice(&0u32.to_le_bytes()); // byte rate
        w.extend_from_slice(&block_align.to_le_bytes());
        w.extend_from_slice(&4u16.to_le_bytes()); // bits
        w.extend_from_slice(&2u16.to_le_bytes()); // cbSize
        w.extend_from_slice(&samples_per_block.to_le_bytes());
        w.extend_from_slice(b"data");
        w.extend_from_slice(&u32::try_from(data_len).unwrap().to_le_bytes());
        w.extend(std::iter::repeat_n(0u8, data_len));
        w
    }

    fn is_internal_err(buf: &[u8]) -> bool {
        matches!(
            transcode_ima_adpcm_to_pcm(buf),
            Err(PaksmithError::Internal { .. })
        )
    }

    #[test]
    fn rejects_zero_block_align() {
        // block_align 0 → too small for header (no div-by-zero panic).
        assert!(is_internal_err(&ima_header(1, 0, 1, 0)));
    }

    #[test]
    fn rejects_block_align_smaller_than_header() {
        assert!(is_internal_err(&ima_header(1, 3, 1, 3))); // < 4-byte mono header
        assert!(is_internal_err(&ima_header(2, 8, 1, 8))); // == 8-byte stereo header (no data)
    }

    #[test]
    fn rejects_data_not_multiple_of_block_align() {
        // mono block_align 8 (spb=9), data 12 ≠ k*8.
        assert!(is_internal_err(&ima_header(1, 8, 9, 12)));
    }

    #[test]
    fn rejects_samples_per_block_geometry_mismatch() {
        // mono block_align 8 → derived spb = 1 + (8-4)/4*8 = 9; claim 999.
        assert!(is_internal_err(&ima_header(1, 8, 999, 8)));
    }

    #[test]
    fn rejects_block_data_not_whole_interleave_group() {
        // stereo block_align 14 → data_bytes 6, not a multiple of 4*2=8.
        assert!(is_internal_err(&ima_header(2, 14, 1, 14)));
    }

    #[test]
    fn accepts_block_step_index_at_max() {
        // A valid 1-block mono WAV (block_align 8 → spb 9) whose block-header
        // step index is exactly MAX_STEP_INDEX decodes — the bound is `>`, not `>=`.
        let mut w = ima_header(1, 8, 9, 8);
        let step_index_byte = w.len() - 6; // block 0 header: [pred:2][step:1][rsv:1]
        w[step_index_byte] = 88;
        assert!(transcode_ima_adpcm_to_pcm(&w).unwrap().is_some());
    }

    #[test]
    fn rejects_block_step_index_above_max() {
        let mut w = ima_header(1, 8, 9, 8);
        let step_index_byte = w.len() - 6;
        w[step_index_byte] = 89; // > MAX_STEP_INDEX
        assert!(is_internal_err(&w));
    }

    // ===== WAV chunk parsing =====

    #[test]
    fn parse_wav_requires_riff_and_wave_magic() {
        // "RIFF" present but the WAVE magic replaced → not a WAV, even though a
        // valid fmt + data follow (the magic check short-circuits on either).
        let mut w = Vec::new();
        w.extend_from_slice(b"RIFF");
        w.extend_from_slice(&0u32.to_le_bytes());
        w.extend_from_slice(b"XXXX"); // not "WAVE"
        w.extend_from_slice(b"fmt ");
        w.extend_from_slice(&16u32.to_le_bytes());
        w.extend_from_slice(&[0u8; 16]);
        w.extend_from_slice(b"data");
        w.extend_from_slice(&4u32.to_le_bytes());
        w.extend_from_slice(&[1, 2, 3, 4]);
        assert!(parse_wav(&w).is_none());
    }

    #[test]
    fn parse_wav_honors_odd_chunk_word_padding() {
        // A 3-byte (odd) chunk between `fmt ` and `data`: the parser must skip
        // the RIFF word-pad byte to land on `data`.
        let mut w = Vec::new();
        w.extend_from_slice(b"RIFF");
        w.extend_from_slice(&0u32.to_le_bytes());
        w.extend_from_slice(b"WAVE");
        w.extend_from_slice(b"fmt ");
        w.extend_from_slice(&16u32.to_le_bytes());
        w.extend_from_slice(&1u16.to_le_bytes()); // PCM
        w.extend_from_slice(&1u16.to_le_bytes());
        w.extend_from_slice(&8000u32.to_le_bytes());
        w.extend_from_slice(&16000u32.to_le_bytes());
        w.extend_from_slice(&2u16.to_le_bytes());
        w.extend_from_slice(&16u16.to_le_bytes());
        w.extend_from_slice(b"JUNK");
        w.extend_from_slice(&3u32.to_le_bytes());
        w.extend_from_slice(&[0xAA, 0xBB, 0xCC]); // 3 bytes (odd)
        w.push(0); // word-pad
        w.extend_from_slice(b"data");
        w.extend_from_slice(&4u32.to_le_bytes());
        w.extend_from_slice(&[1, 2, 3, 4]);
        let (fmt, data) = parse_wav(&w).expect("fmt + data found past the odd chunk");
        assert_eq!(fmt.format_tag, 1);
        assert_eq!(data, [1, 2, 3, 4]);
    }

    #[test]
    fn cap_constant_is_one_gib() {
        assert_eq!(MAX_AUDIO_DECODED_BYTES, 1_073_741_824);
    }

    #[test]
    fn build_pcm_wav_saturates_byte_rate_without_overflow() {
        // `sample_rate` is wire-controlled and unbounded; a near-`u32::MAX` rate
        // must saturate the byte-rate header field, not overflow-panic.
        let wav = build_pcm_wav(&[1, 2, 3, 4], 2, u32::MAX);
        assert_eq!(read_u32le(&wav[20..], 8), Some(u32::MAX)); // byte rate saturated
    }

    #[test]
    fn build_pcm_wav_saturates_block_align_without_overflow() {
        // A `u16::MAX` channel count saturates the block-align field instead of
        // overflow-panicking (the helper is self-safe regardless of caller).
        let wav = build_pcm_wav(&[], u16::MAX, 8000);
        assert_eq!(read_u16le(&wav[20..], 12), Some(u16::MAX)); // block align saturated
    }

    // ===== projected-size cap (pure, no gigabyte fixture) =====

    #[test]
    fn projected_pcm_bytes_accepts_within_cap() {
        // mono fixture geometry: 1 block × 2041 samples × 1 ch × 2 = 4082.
        assert_eq!(projected_pcm_bytes(1, 2041, 1).unwrap(), 4082);
    }

    #[test]
    fn projected_pcm_bytes_rejects_over_cap() {
        // Just past the cap.
        let blocks = MAX_AUDIO_DECODED_BYTES / 2 + 1; // ×1 sample ×1 ch ×2 bytes
        assert!(matches!(
            projected_pcm_bytes(blocks, 1, 1),
            Err(PaksmithError::Internal { .. })
        ));
    }

    #[test]
    fn projected_pcm_bytes_rejects_overflow() {
        assert!(matches!(
            projected_pcm_bytes(usize::MAX, 2, 2),
            Err(PaksmithError::Internal { .. })
        ));
    }

    // ===== nibble decode unit pin (secondary to the golden vectors) =====

    #[test]
    fn decode_nibble_follows_ima_formula() {
        // From step_index 0 (step = 7): code 4 ⇒ diff = (7>>3=0) + 7 = 7,
        // predictor 0 → 7; index advances by INDEX_TABLE[4] = 2.
        let mut pred = 0i32;
        let mut idx = 0i32;
        let s = decode_nibble(4, &mut pred, &mut idx);
        assert_eq!(s, 7);
        assert_eq!(pred, 7);
        assert_eq!(idx, 2);
        // Sign bit (8) subtracts: from a fresh state, code 12 = 8|4 ⇒ diff 7,
        // predictor 0 → -7.
        let mut pred = 0i32;
        let mut idx = 0i32;
        assert_eq!(decode_nibble(12, &mut pred, &mut idx), -7);
        assert_eq!(pred, -7);
    }

    #[test]
    fn step_index_clamps_at_table_bounds() {
        // code 0 at index 0 holds the floor (INDEX_TABLE[0] = -1 clamps to 0).
        let mut pred = 0i32;
        let mut idx = 0i32;
        let _ = decode_nibble(0, &mut pred, &mut idx);
        assert_eq!(idx, 0);
        // code 7 (+8) repeatedly saturates at MAX_STEP_INDEX.
        let mut idx = 80i32;
        let mut pred = 0i32;
        for _ in 0..5 {
            let _ = decode_nibble(7, &mut pred, &mut idx);
        }
        assert_eq!(idx, MAX_STEP_INDEX);
    }
}
