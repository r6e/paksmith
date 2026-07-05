//! Shared 16-bit PCM WAV writer + the audio decompression-bomb cap, used by
//! every audio decoder (`adpcm`, `vorbis`, …). Each decoder produces
//! frame-interleaved `i16` samples and re-wraps them with [`build_pcm_wav`].

use super::adpcm::parse_wav;

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

/// The decoded `Vec<i16>` from [`parse_pcm_wav`] is `byte_len` bytes (one i16 per
/// 2 bytes). Reject a PCM `data` chunk that would exceed the shared decode cap
/// BEFORE allocating — the ADPCM/Vorbis paths cap the same way, so the whole
/// audio subsystem is uniformly bounded. `byte_len` is the raw `data`-chunk
/// length (which equals the resulting sample bytes).
///
/// Uses [`crate::PaksmithError::Internal`] to match the `vorbis`/`adpcm` cap
/// guards (a resource bound, not an unsupported-format condition), keeping the
/// three audio paths' rejection variant uniform.
fn pcm_data_within_cap(byte_len: usize) -> crate::Result<()> {
    if byte_len > MAX_AUDIO_DECODED_BYTES {
        return Err(crate::PaksmithError::Internal {
            context: format!(
                "PCM decode: audio data ({byte_len} bytes) exceeds the {MAX_AUDIO_DECODED_BYTES}-byte cap"
            ),
        });
    }
    Ok(())
}

/// Parse a 16-bit PCM WAV into `(channels, sample_rate, interleaved i16 samples)`.
///
/// Rejects non-PCM (`wFormatTag != 1`) or non-16-bit (`wBitsPerSample != 16`)
/// with [`crate::PaksmithError::UnsupportedFeature`], a `data` chunk exceeding
/// [`MAX_AUDIO_DECODED_BYTES`] with [`crate::PaksmithError::Internal`]
/// (decompression-bomb guard, checked before allocating), and a malformed
/// RIFF/WAVE container with [`crate::PaksmithError::Internal`].
pub(crate) fn parse_pcm_wav(wav: &[u8]) -> crate::Result<(u16, u32, Vec<i16>)> {
    let (fmt, data) = parse_wav(wav).ok_or_else(|| crate::PaksmithError::Internal {
        context: "decoded audio is not a valid WAV".to_string(),
    })?;
    if fmt.format_tag != 1 || fmt.bits_per_sample != 16 {
        return Err(crate::PaksmithError::UnsupportedFeature {
            context: format!(
                "audio WAV is not 16-bit PCM (tag={}, bits={})",
                fmt.format_tag, fmt.bits_per_sample
            ),
        });
    }
    pcm_data_within_cap(data.len())?;
    let samples = data
        .chunks_exact(2)
        .map(|b| i16::from_le_bytes([b[0], b[1]]))
        .collect();
    Ok((fmt.channels, fmt.sample_rate, samples))
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

    // ===== pcm_data_within_cap (pure, no gigabyte allocation) =====

    #[test]
    fn pcm_data_within_cap_accepts_at_and_below_cap() {
        assert!(pcm_data_within_cap(MAX_AUDIO_DECODED_BYTES).is_ok());
        assert!(pcm_data_within_cap(MAX_AUDIO_DECODED_BYTES - 1).is_ok());
    }

    #[test]
    fn pcm_data_within_cap_rejects_above_cap() {
        // The divergent boundary pair: one byte past the cap must reject. Kills the
        // `>`→`>=`/`<` and const mutants without a multi-GiB allocation. Uses the
        // `Internal` variant to match the vorbis/adpcm cap guards.
        assert!(matches!(
            pcm_data_within_cap(MAX_AUDIO_DECODED_BYTES + 1),
            Err(crate::PaksmithError::Internal { .. })
        ));
    }

    // ===== parse_pcm_wav =====

    fn make_wav(tag: u16, channels: u16, sample_rate: u32, bits: u16, samples: &[u8]) -> Vec<u8> {
        let data_len = u32::try_from(samples.len()).expect("test data fits in u32");
        let block_align = channels * (bits / 8);
        let byte_rate = sample_rate * u32::from(block_align);
        let mut wav = Vec::new();
        wav.extend_from_slice(b"RIFF");
        wav.extend_from_slice(&(36u32 + data_len).to_le_bytes());
        wav.extend_from_slice(b"WAVE");
        wav.extend_from_slice(b"fmt ");
        wav.extend_from_slice(&16u32.to_le_bytes());
        wav.extend_from_slice(&tag.to_le_bytes());
        wav.extend_from_slice(&channels.to_le_bytes());
        wav.extend_from_slice(&sample_rate.to_le_bytes());
        wav.extend_from_slice(&byte_rate.to_le_bytes());
        wav.extend_from_slice(&block_align.to_le_bytes());
        wav.extend_from_slice(&bits.to_le_bytes());
        wav.extend_from_slice(b"data");
        wav.extend_from_slice(&data_len.to_le_bytes());
        wav.extend_from_slice(samples);
        wav
    }

    #[test]
    fn parse_pcm_wav_extracts_16bit_stereo_samples() {
        // Two stereo frames: [1,0,2,0] → [i16::LE(1), i16::LE(2)]
        let wav = make_wav(1, 2, 44100, 16, &[1, 0, 2, 0]);
        let (ch, rate, samples) = parse_pcm_wav(&wav).expect("ok");
        assert_eq!(ch, 2);
        assert_eq!(rate, 44100);
        assert_eq!(samples, vec![1_i16, 2_i16]);
    }

    #[test]
    fn parse_pcm_wav_rejects_8bit_pcm() {
        // tag=1 (PCM) but bits=8: must be UnsupportedFeature, not silent corruption.
        let wav = make_wav(1, 1, 22050, 8, &[128u8]);
        let err = parse_pcm_wav(&wav).unwrap_err();
        assert!(
            matches!(err, crate::PaksmithError::UnsupportedFeature { .. }),
            "8-bit PCM must yield UnsupportedFeature, got {err:?}"
        );
    }

    #[test]
    fn parse_pcm_wav_rejects_non_pcm_tag() {
        // tag=0x0011 (IMA-ADPCM): the output of transcode_adpcm_to_pcm is always
        // tag=1; this guard fires when a codec returns a non-PCM WAV unexpectedly.
        let wav = make_wav(0x0011, 1, 22050, 16, &[1, 0]);
        let err = parse_pcm_wav(&wav).unwrap_err();
        assert!(
            matches!(err, crate::PaksmithError::UnsupportedFeature { .. }),
            "non-PCM tag must yield UnsupportedFeature, got {err:?}"
        );
    }

    #[test]
    fn parse_pcm_wav_rejects_invalid_riff() {
        let err = parse_pcm_wav(b"not a wav").unwrap_err();
        assert!(
            matches!(err, crate::PaksmithError::Internal { .. }),
            "invalid RIFF must yield Internal, got {err:?}"
        );
    }
}
