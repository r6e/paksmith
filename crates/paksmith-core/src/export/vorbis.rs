//! Vorbis → PCM decode for the [`VorbisHandler`](crate::export::VorbisHandler)
//! export path (Phase 3f).
//!
//! UE cooks the `"OGG"` codec key as a complete Ogg-Vorbis container.
//! [`OggHandler`](crate::export::OggHandler) already exports that `.ogg`
//! verbatim — a valid, playable file. This module adds the opt-in decode that
//! `VorbisHandler` exposes as `.wav`: [`transcode_vorbis_to_pcm`] drives the
//! [`symphonia`] Ogg demuxer + Vorbis decoder, collects the interleaved samples,
//! and re-wraps them as a 16-bit `WAVE_FORMAT_PCM` WAV via
//! [`build_pcm_wav`](super::pcm::build_pcm_wav).
//!
//! **Validation.** Unlike the ADPCM decoders, Vorbis is lossy and float-based —
//! there is **no byte-exact oracle**: independent decoders (symphonia, ffmpeg,
//! libvorbis) differ by sub-LSB float rounding, and even symphonia is not
//! guaranteed bit-identical across CPU architectures (the inverse-MDCT/windowing
//! uses transcendental math). The decode here is **symphonia's** — a trusted,
//! separately-tested decoder; paksmith's responsibility is to drive it correctly
//! and wrap its output losslessly. Correctness is validated by deterministic
//! synthetic unit tests of the wrapper surface (the cap, dispatch, WAV writer)
//! plus a structural + per-channel-RMS check of a committed fixture's real
//! decode. Emitting 16-bit PCM is a deliberate (lossy) choice matching the
//! ADPCM→WAV path; symphonia's `copy_to_vec_interleaved::<i16>` does the f32→i16
//! conversion.

use std::io::Cursor;

use symphonia::core::codecs::CodecParameters;
use symphonia::core::codecs::audio::AudioDecoderOptions;
use symphonia::core::errors::Error as SymphoniaError;
use symphonia::core::formats::probe::Hint;
use symphonia::core::formats::{FormatOptions, TrackType};
use symphonia::core::io::{MediaSourceStream, MediaSourceStreamOptions};
use symphonia::core::meta::MetadataOptions;

use super::pcm::{MAX_AUDIO_DECODED_BYTES, build_pcm_wav};
use crate::PaksmithError;

fn internal(msg: String) -> PaksmithError {
    PaksmithError::Internal { context: msg }
}

/// Add `new_samples` (16-bit = 2 bytes each) to the running decoded-byte
/// `total`, returning the updated total or `Err` if it would exceed
/// [`MAX_AUDIO_DECODED_BYTES`]. The streaming decode has no upfront size to
/// project against, so the decompression-bomb guard is enforced incrementally —
/// the caller checks **before** growing its sample buffer, so the allocation
/// never exceeds the cap.
fn accumulate_within_cap(total: usize, new_samples: usize) -> crate::Result<usize> {
    let next = total.saturating_add(new_samples.saturating_mul(2));
    if next > MAX_AUDIO_DECODED_BYTES {
        return Err(internal(format!(
            "Vorbis decode: output exceeds the {MAX_AUDIO_DECODED_BYTES}-byte cap"
        )));
    }
    Ok(next)
}

/// Transcode an Ogg-Vorbis buffer to a 16-bit PCM WAV.
///
/// Returns `Ok(Some(pcm_wav))` when `buf` decodes to at least one audio frame;
/// `Ok(None)` when it is not a usable Ogg-Vorbis audio stream (probe fails, no
/// Vorbis track, or zero decoded frames) so the caller can pass it through
/// unchanged; `Err` only on a demux-level error mid-stream or when the decoded
/// output exceeds [`MAX_AUDIO_DECODED_BYTES`].
///
/// Robustness: a single corrupt *packet* (`DecodeError`) is skipped, not fatal,
/// and a truncated stream yields the partial PCM decoded so far — so "corrupt
/// mid-decode" is salvaged where possible rather than erroring.
pub(crate) fn transcode_vorbis_to_pcm(buf: &[u8]) -> crate::Result<Option<Vec<u8>>> {
    // symphonia needs an owned, seekable source; the cooked buffer is already in
    // memory and resolver-capped, so a copy is acceptable.
    let mss = MediaSourceStream::new(
        Box::new(Cursor::new(buf.to_vec())),
        MediaSourceStreamOptions::default(),
    );
    // Probe for an Ogg container. A non-Ogg buffer is "not decodable here" → None
    // (passthrough), not an error. (symphonia 0.6: `Probe::format` → `Probe::probe`,
    // which returns the `FormatReader` box directly; the format/metadata options are
    // now passed by value.)
    let Ok(mut format) = symphonia::default::get_probe().probe(
        &Hint::new(),
        mss,
        FormatOptions::default(),
        MetadataOptions::default(),
    ) else {
        return Ok(None);
    };
    // (0.6: `default_track` now takes a `TrackType`.)
    let Some(track) = format.default_track(TrackType::Audio) else {
        return Ok(None);
    };
    let track_id = track.id;
    // (0.6: `Track::codec_params` is `Option<CodecParameters>`; the audio variant
    // carries the `AudioCodecParameters` the decoder factory needs. `None`/non-audio
    // → passthrough.)
    let Some(CodecParameters::Audio(audio_params)) = &track.codec_params else {
        return Ok(None);
    };
    // Only the Vorbis codec is registered (feature-gated); any other audio codec
    // yields no decoder → passthrough. (0.6: `CodecRegistry::make` →
    // `make_audio_decoder`.)
    //
    // Disable gapless trimming to preserve the 0.5 decode policy: 0.5's
    // `FormatOptions::default()` set `enable_gapless: false` (untrimmed), but 0.6
    // moved gapless to the decoder and defaults it ON. Leaving it on would trim
    // encoder delay/padding — a decode-output change out of scope for a dependency
    // bump. (`AudioDecoderOptions` is `#[non_exhaustive]`, so mutate the field on a
    // `default()` value rather than a struct literal.)
    let mut decoder_opts = AudioDecoderOptions::default();
    decoder_opts.gapless = false;
    let Ok(mut decoder) =
        symphonia::default::get_codecs().make_audio_decoder(audio_params, &decoder_opts)
    else {
        return Ok(None);
    };

    let mut samples: Vec<i16> = Vec::new();
    // Per-packet scratch, reused across the loop; `clear`ed before each copy so the
    // copy semantics (overwrite vs append) don't matter.
    let mut frame: Vec<i16> = Vec::new();
    let mut channels = 0u16;
    let mut sample_rate = 0u32;
    let mut decoded_bytes = 0usize;

    loop {
        let packet = match format.next_packet() {
            Ok(Some(p)) => p,
            // Loop ends on: a clean end-of-stream (0.6 returns `Ok(None)`, not an
            // `IoError`), a truncated in-memory `Cursor` (surfaces as an `IoError`),
            // or `ResetRequired` (ends our single-stream decode). All break to
            // salvage the partial PCM decoded so far rather than erroring.
            Ok(None) | Err(SymphoniaError::IoError(_) | SymphoniaError::ResetRequired) => break,
            Err(e) => return Err(internal(format!("Vorbis demux: {e}"))),
        };
        if packet.track_id != track_id {
            continue;
        }
        let audio_buf = match decoder.decode(&packet) {
            Ok(b) => b,
            // A single malformed packet is recoverable — skip it, keep decoding.
            Err(SymphoniaError::DecodeError(_)) => continue,
            Err(e) => return Err(internal(format!("Vorbis decode: {e}"))),
        };
        // Detect the channel layout + rate once, from the first decoded packet.
        if channels == 0 {
            let spec = audio_buf.spec();
            channels = u16::try_from(spec.channels().count()).unwrap_or(0);
            sample_rate = spec.rate();
        }
        // Cap-check before growing `samples` (and before the scratch copy), so
        // neither buffer ever exceeds the cap. `samples_interleaved()` =
        // channels × frames is exactly the i16 count this packet contributes —
        // a decoder-block-size value (header-validated), not an attacker granule.
        decoded_bytes = accumulate_within_cap(decoded_bytes, audio_buf.samples_interleaved())?;
        // (0.6: `SampleBuffer` removed; `copy_to_vec_interleaved` does the f32→i16
        // `ConvertibleSample` conversion into our scratch vec.)
        frame.clear();
        audio_buf.copy_to_vec_interleaved(&mut frame);
        samples.extend_from_slice(&frame);
    }

    // `channels` is still 0 only if no packet ever decoded (a non-audio Ogg
    // bitstream, or every packet skipped as a `DecodeError`). Treat that as "not
    // a usable Ogg-Vorbis audio stream" → None; `VorbisHandler` turns it into a
    // hard error, while a passthrough caller keeps the verbatim buffer.
    if channels == 0 {
        return Ok(None);
    }
    Ok(Some(build_pcm_wav(&samples, channels, sample_rate)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const STEREO_OGG: &[u8] = include_bytes!("testdata/vorbis_stereo.ogg");

    // ===== cap guard (synthetic, no gigabyte fixture) =====

    #[test]
    fn accumulate_within_cap_accepts_under_and_at_cap() {
        // `new_samples` are 16-bit (2 bytes each): 100 samples → 200 bytes.
        assert_eq!(accumulate_within_cap(0, 100).unwrap(), 200);
        // 10 samples = 20 bytes lands exactly on the cap.
        assert_eq!(
            accumulate_within_cap(MAX_AUDIO_DECODED_BYTES - 20, 10).unwrap(),
            MAX_AUDIO_DECODED_BYTES
        );
    }

    #[test]
    fn accumulate_within_cap_rejects_over_cap() {
        assert!(accumulate_within_cap(MAX_AUDIO_DECODED_BYTES - 20, 11).is_err());
        assert!(accumulate_within_cap(MAX_AUDIO_DECODED_BYTES, 1).is_err());
    }

    #[test]
    fn accumulate_within_cap_saturates_without_overflow() {
        // Neither the ×2 sample→byte widening nor the running-total add can wrap a
        // near-`usize::MAX` value to a small one and slip past the cap.
        assert!(accumulate_within_cap(0, usize::MAX).is_err());
        assert!(accumulate_within_cap(usize::MAX - 1, 100).is_err());
    }

    // ===== dispatch (Ok(None)) =====

    #[test]
    fn non_ogg_buffer_passes_through() {
        assert!(
            transcode_vorbis_to_pcm(b"not an ogg stream at all")
                .unwrap()
                .is_none()
        );
        assert!(transcode_vorbis_to_pcm(&[]).unwrap().is_none());
    }

    #[test]
    fn truncated_ogg_header_passes_through() {
        // "OggS" magic but nothing valid after → probe fails → None (passthrough).
        assert!(
            transcode_vorbis_to_pcm(b"OggS\x00\x02truncated")
                .unwrap()
                .is_none()
        );
    }

    // ===== real decode (structural + per-channel RMS; no byte-exact oracle) =====

    /// Parse a PCM WAV the decoder produced into (channels, sample_rate, samples).
    fn parse_pcm(wav: &[u8]) -> (u16, u32, Vec<i16>) {
        assert_eq!(&wav[0..4], b"RIFF");
        assert_eq!(&wav[8..12], b"WAVE");
        let tag = u16::from_le_bytes([wav[20], wav[21]]);
        assert_eq!(tag, 1, "output is WAVE_FORMAT_PCM");
        assert_eq!(u16::from_le_bytes([wav[34], wav[35]]), 16, "16-bit");
        let channels = u16::from_le_bytes([wav[22], wav[23]]);
        let rate = u32::from_le_bytes([wav[24], wav[25], wav[26], wav[27]]);
        let samples = wav[44..]
            .chunks_exact(2)
            .map(|b| i16::from_le_bytes([b[0], b[1]]))
            .collect();
        (channels, rate, samples)
    }

    #[test]
    #[allow(
        clippy::cast_precision_loss,
        reason = "frame counts are small (thousands); RMS f64 precision is non-critical in a test"
    )]
    fn decodes_vorbis_fixture_structure_and_energy() {
        let out = transcode_vorbis_to_pcm(STEREO_OGG)
            .expect("decode ok")
            .expect("fixture is Ogg-Vorbis");
        let (channels, rate, samples) = parse_pcm(&out);
        assert_eq!(channels, 2);
        assert_eq!(rate, 44100);
        let frames = samples.len() / 2;
        // No byte-exact oracle for a lossy Vorbis decode (see the module note):
        // ffmpeg and symphonia 0.5 decode this fixture to ~9216 frames, but
        // symphonia 0.6's untrimmed decode emits an extra ~1024-frame boundary
        // block → ~10240. Band covers the 0.6 output with a platform/sub-LSB margin.
        assert!(
            (10000..=10400).contains(&frames),
            "frames {frames} outside the expected ~10240 band"
        );

        // Per-channel RMS catches channel-swap / scale / silence without a
        // brittle sample-by-sample byte match. The fixture's L is a mid-amplitude
        // sine (RMS ~8289), R is low-amplitude noise (RMS ~1196) — distinct
        // enough that a swap moves each out of its band.
        let rms = |ch: usize| -> f64 {
            let sumsq: f64 = samples
                .iter()
                .skip(ch)
                .step_by(2)
                .map(|&s| f64::from(s) * f64::from(s))
                .sum();
            (sumsq / frames as f64).sqrt()
        };
        let (l, r) = (rms(0), rms(1));
        assert!((7500.0..=9000.0).contains(&l), "left RMS {l} out of band");
        assert!((900.0..=1500.0).contains(&r), "right RMS {r} out of band");
    }
}
