//! Shared 16-bit PCM WAV writer + the audio decompression-bomb cap, used by
//! every audio decoder (`adpcm`, `vorbis`, …). Each decoder produces
//! frame-interleaved `i16` samples and re-wraps them with [`build_pcm_wav`].

/// Upper bound on a single decode's PCM output (decompression-bomb guard). ADPCM
/// is a fixed ~4:1 ratio and checks this **before** allocating; streaming codecs
/// (Vorbis) enforce it **incrementally** as samples accumulate. The input is
/// already resolver-capped, so 1 GiB is generous headroom for real audio (≈1.5 h
/// of 48 kHz stereo) while still bounding a crafted-header attack.
pub(crate) const MAX_AUDIO_DECODED_BYTES: usize = 1024 * 1024 * 1024;

/// `__test_utils` accessor so out-of-crate boundary tests read the live cap
/// value (mirrors the `bulk_data` cap accessors). Re-exported from
/// [`crate::export`] so `paksmith-core-tests` can reach it past the private
/// module.
#[cfg(feature = "__test_utils")]
#[must_use]
pub fn max_audio_decoded_bytes() -> usize {
    MAX_AUDIO_DECODED_BYTES
}

/// Build a minimal `WAVE_FORMAT_PCM` 16-bit WAV (`RIFF`/`fmt `/`data`) around
/// frame-interleaved `samples`.
///
/// Callers cap their output at [`MAX_AUDIO_DECODED_BYTES`] (1 GiB) before calling
/// this, so `samples.len() * 2` always fits in the `u32` chunk-size fields.
#[allow(
    clippy::cast_possible_truncation,
    reason = "samples.len()*2 ≤ MAX_AUDIO_DECODED_BYTES (1 GiB) < u32::MAX (cap-checked before decode)"
)]
pub(crate) fn build_pcm_wav(samples: &[i16], channels: u16, sample_rate: u32) -> Vec<u8> {
    // `channels` and `sample_rate` come from the wire. Production callers bound
    // `channels`, but saturate both multiplies here so this helper is
    // overflow-panic-safe on its own — a crafted (or a future direct-caller's)
    // value writes cosmetically-wrong header fields, not a panic.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn u16_at(wav: &[u8], off: usize) -> u16 {
        u16::from_le_bytes([wav[off], wav[off + 1]])
    }
    fn u32_at(wav: &[u8], off: usize) -> u32 {
        u32::from_le_bytes([wav[off], wav[off + 1], wav[off + 2], wav[off + 3]])
    }

    #[test]
    fn cap_constant_is_one_gib() {
        assert_eq!(MAX_AUDIO_DECODED_BYTES, 1_073_741_824);
    }

    #[cfg(feature = "__test_utils")]
    #[test]
    fn cap_accessor_reports_the_live_cap() {
        assert_eq!(super::max_audio_decoded_bytes(), MAX_AUDIO_DECODED_BYTES);
    }

    #[test]
    fn build_pcm_wav_writes_a_spec_correct_header() {
        // 2ch, 22050 Hz, two frames → block align 4, byte rate 88200, data 8 bytes.
        let wav = build_pcm_wav(&[1, 2, 3, 4], 2, 22050);
        assert_eq!(&wav[0..4], b"RIFF");
        assert_eq!(&wav[8..12], b"WAVE");
        assert_eq!(u16_at(&wav, 20), 1); // WAVE_FORMAT_PCM
        assert_eq!(u16_at(&wav, 22), 2); // channels
        assert_eq!(u32_at(&wav, 24), 22050); // sample rate
        assert_eq!(u32_at(&wav, 28), 88200); // byte rate = 22050*2*2
        assert_eq!(u16_at(&wav, 32), 4); // block align = 2*2
        assert_eq!(u16_at(&wav, 34), 16); // bits
        assert_eq!(u32_at(&wav, 40), 8); // data chunk size
        assert_eq!(u32_at(&wav, 4) as usize + 8, wav.len()); // RIFF size consistent
    }

    #[test]
    fn build_pcm_wav_saturates_byte_rate_without_overflow() {
        // `sample_rate` is wire-controlled and unbounded; a near-`u32::MAX` rate
        // must saturate the byte-rate header field, not overflow-panic.
        let wav = build_pcm_wav(&[1, 2, 3, 4], 2, u32::MAX);
        assert_eq!(u32_at(&wav, 28), u32::MAX); // byte rate saturated
    }

    #[test]
    fn build_pcm_wav_saturates_block_align_without_overflow() {
        // A `u16::MAX` channel count saturates the block-align field instead of
        // overflow-panicking (the helper is self-safe regardless of caller).
        let wav = build_pcm_wav(&[], u16::MAX, 8000);
        assert_eq!(u16_at(&wav, 32), u16::MAX); // block align saturated
    }
}
