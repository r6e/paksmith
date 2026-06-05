//! Audio passthrough handlers — extract a `USoundWave`'s cooked codec buffer as
//! a playable file with no decode (Phase 3f).
//!
//! UE cooks several audio codecs as **complete standard containers**, so export
//! is a verbatim passthrough. Two handlers share one codec-agnostic core
//! ([`passthrough_export`]) — buffer selection is identical for every codec;
//! only the matched codec key(s) and the output extension differ:
//!
//! - [`OggHandler`] → `"OGG"` → `.ogg`. UE cooks Vorbis as a complete
//!   Ogg-Vorbis container.
//! - [`WavHandler`] → `"PCM"` / `"ADPCM"` → `.wav`. UE cooks these as a complete
//!   RIFF/WAVE container (CUE4Parse `ADPCMDecoder.GetAudioFormat` reads the
//!   standard `RIFF` / `WAVE` / `fmt ` chunks + `wFormatTag` straight off the
//!   buffer, confirming it is a standard WAV). The `"ADPCM"` buffer's audio data
//!   stays ADPCM-encoded inside that WAV — a valid file that ADPCM-aware players
//!   decode; an ADPCM→PCM *decode* (a later milestone) would only widen player
//!   support, it is not required for a correct `.wav`.
//!
//! The compressed bytes live in one of two storage shapes (see
//! `docs/formats/audio/sound-wave.md`):
//!
//! - **Non-streaming** (`FFormatContainer`): each codec buffer is a whole file
//!   keyed by format; returned as-is.
//! - **Streaming** (`FStreamedAudioPlatformData`): the container byte stream is
//!   split across chunks. Each chunk's `FByteBulkData` payload is
//!   `DataSize`-padded, so the real audio is the first `AudioDataSize` bytes.
//!   Reassembly concatenates `payload[..AudioDataSize]` across chunks — mirroring
//!   CUE4Parse `SoundDecoder` (`Sum(AudioDataSize)`-sized output, then
//!   `BlockCopy(payload, 0, .., AudioDataSize)` per chunk).
//!
//! **Codec selection.** The streaming codec is `AudioFormat` verbatim; the
//! non-streaming active codec is the **first wire-order**
//! `CompressedFormatData` key with any `_` platform suffix stripped (the suffix
//! strip mirrors CUE4Parse `Key.Text.SubstringBefore('_')`). Real cooked,
//! single-platform audio carries exactly one format key, so "first" is
//! unambiguous. paksmith does **not** replicate CUE4Parse's sorted-`.First()`
//! selection over a `SortedDictionary<FName, …>` (alphabetically-smallest key),
//! which only diverges for the exotic multi-format container — an unverified
//! case for which paksmith conservatively claims the asset only when the matched
//! codec is the first wire key, otherwise falling through (never the wrong
//! bytes). The match is ASCII-case-insensitive (CUE4Parse normalizes
//! `OrdinalIgnoreCase`). `"OPUS"` (framing unverified) and the proprietary keys
//! (`"BINKA"` / `"XMA2"` / `"AT9"` / `"OPUSNX"`) are claimed by no handler yet
//! and fall through to `GenericHandler`. The non-cooked `RawData` path carries
//! no codec key, so neither handler matches it.

use crate::PaksmithError;
use crate::asset::{Asset, SoundWaveData, StreamedAudioChunk};
use crate::export::{BulkData, FormatHandler};

/// The Ogg-Vorbis codec key (UE `FName`). Non-streaming keys may carry a
/// platform suffix (`OGG_…`), which [`active_codec`] strips before comparing.
const OGG_CODEC: &str = "OGG";

/// The codec keys whose cooked buffer is a complete RIFF/WAVE container: `"PCM"`
/// (PCM-in-WAV) and `"ADPCM"` (ADPCM-in-WAV). Both export verbatim to `.wav`.
const WAV_CODECS: &[&str] = &["PCM", "ADPCM"];

/// Exports `Asset::SoundWave` Ogg-Vorbis audio to a `.ogg` file. Stateless.
#[derive(Debug, Default, Clone, Copy)]
pub struct OggHandler;

impl FormatHandler for OggHandler {
    fn output_extension(&self) -> &'static str {
        "ogg"
    }

    fn supports(&self, asset: &Asset) -> bool {
        supports_codec(asset, std::slice::from_ref(&OGG_CODEC))
    }

    fn export(&self, asset: &Asset, bulk: &[BulkData]) -> crate::Result<Vec<u8>> {
        passthrough_export(asset, bulk)
    }
}

/// Exports `Asset::SoundWave` PCM / ADPCM audio to a `.wav` file. Stateless.
#[derive(Debug, Default, Clone, Copy)]
pub struct WavHandler;

impl FormatHandler for WavHandler {
    fn output_extension(&self) -> &'static str {
        "wav"
    }

    fn supports(&self, asset: &Asset) -> bool {
        supports_codec(asset, WAV_CODECS)
    }

    fn export(&self, asset: &Asset, bulk: &[BulkData]) -> crate::Result<Vec<u8>> {
        passthrough_export(asset, bulk)
    }
}

/// Whether `asset` is a `USoundWave` whose [`active_codec`] case-insensitively
/// matches any key in `codecs`. The shared `supports` predicate for every audio
/// passthrough handler.
fn supports_codec(asset: &Asset, codecs: &[&str]) -> bool {
    let Asset::SoundWave(data) = asset else {
        return false;
    };
    active_codec(data).is_some_and(|codec| codecs.iter().any(|key| codec.eq_ignore_ascii_case(key)))
}

/// The shared passthrough export for every audio codec whose cooked buffer is a
/// complete standard container: select the codec buffer (non-streaming) or
/// reassemble the chunk stream (streaming) and return its bytes verbatim. The
/// output container type is the handler's concern (its `output_extension`); the
/// byte selection here is codec-agnostic.
fn passthrough_export(asset: &Asset, bulk: &[BulkData]) -> crate::Result<Vec<u8>> {
    let Asset::SoundWave(data) = asset else {
        return Err(PaksmithError::Internal {
            context: "audio passthrough export called on a non-SoundWave Asset".to_string(),
        });
    };
    match &data.streamed {
        Some(streamed) => assemble_streaming(&streamed.chunks, bulk),
        None => extract_nonstreaming(bulk),
    }
}

/// The active audio codec of a parsed `USoundWave`, or `None` when there is no
/// codec buffer to export (the non-cooked `RawData` / no-format path, or a
/// `streaming && !cooked` asset that carries only a GUID).
///
/// The streaming codec is `AudioFormat` verbatim; the non-streaming codec is the
/// **first wire-order** `CompressedFormatData` key with any `_` suffix stripped
/// (see the module-level note on the divergence from CUE4Parse's sorted
/// `.First()` for multi-format containers). The returned codec is compared
/// case-insensitively by [`supports_codec`].
fn active_codec(data: &SoundWaveData) -> Option<&str> {
    if let Some(streamed) = &data.streamed {
        return Some(streamed.audio_format.as_ref());
    }
    let first_key = data.compressed_format_keys.first()?;
    Some(codec_prefix(first_key))
}

/// The codec identity of a non-streaming format key: the substring before the
/// first `_` (CUE4Parse `Key.Text.SubstringBefore('_')`), or the whole key when
/// there is no `_`.
fn codec_prefix(key: &str) -> &str {
    key.split_once('_').map_or(key, |(prefix, _suffix)| prefix)
}

/// Non-streaming passthrough: the first format buffer is the complete codec
/// container file. The caller's `supports` guarantees that buffer's codec, so
/// its bytes are returned verbatim.
fn extract_nonstreaming(bulk: &[BulkData]) -> crate::Result<Vec<u8>> {
    let buffer = bulk.first().ok_or_else(|| PaksmithError::Internal {
        context: "audio passthrough: non-streaming SoundWave has no codec buffer \
                  (resolved bulk is empty)"
            .to_string(),
    })?;
    Ok(buffer.bytes.clone())
}

/// Streaming reassembly: concatenate the leading `AudioDataSize` bytes of each
/// chunk's payload (the remainder is `DataSize` zero padding). Mirrors CUE4Parse
/// `SoundDecoder`. Errors if the resolved bulk count desyncs from the chunk
/// metadata, or a chunk's `AudioDataSize` is negative or exceeds its payload.
fn assemble_streaming(chunks: &[StreamedAudioChunk], bulk: &[BulkData]) -> crate::Result<Vec<u8>> {
    if chunks.len() != bulk.len() {
        return Err(PaksmithError::Internal {
            context: format!(
                "audio passthrough: streaming chunk/bulk desync ({} chunks, {} bulk records)",
                chunks.len(),
                bulk.len()
            ),
        });
    }
    let mut out = Vec::new();
    for (index, (chunk, record)) in chunks.iter().zip(bulk).enumerate() {
        let audio_len =
            usize::try_from(chunk.audio_data_size).map_err(|_| PaksmithError::Internal {
                context: format!(
                    "audio passthrough: chunk {index} has negative AudioDataSize ({})",
                    chunk.audio_data_size
                ),
            })?;
        let payload = &record.bytes;
        if audio_len > payload.len() {
            return Err(PaksmithError::Internal {
                context: format!(
                    "audio passthrough: chunk {index} AudioDataSize {audio_len} exceeds its \
                     {}-byte payload",
                    payload.len()
                ),
            });
        }
        out.extend_from_slice(&payload[..audio_len]);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::StreamedAudioData;
    use crate::asset::bulk_data::{BulkDataTier, make_zero_record};
    use crate::asset::property::bag::PropertyBag;
    use crate::export::HandlerRegistry;
    use std::sync::Arc;

    fn bulk(bytes: &[u8]) -> BulkData {
        BulkData {
            bytes: bytes.to_vec(),
            record: make_zero_record(),
            tier: BulkDataTier::Inline,
        }
    }

    fn chunk(data_size: i32, audio_data_size: i32) -> StreamedAudioChunk {
        StreamedAudioChunk {
            data_size,
            audio_data_size,
            seek_offset_in_audio_frames: None,
        }
    }

    fn nonstreaming(keys: &[&str]) -> SoundWaveData {
        let mut data = SoundWaveData::empty();
        data.cooked = true;
        data.compressed_format_keys = keys.iter().map(|k| Arc::from(*k)).collect();
        data
    }

    fn streaming(format: &str, chunks: Vec<StreamedAudioChunk>) -> SoundWaveData {
        let mut data = SoundWaveData::empty();
        data.cooked = true;
        data.streaming = true;
        data.streamed = Some(StreamedAudioData {
            audio_format: Arc::from(format),
            chunks,
        });
        data
    }

    // ===== output extension + codec_prefix =====

    #[test]
    fn output_extension_is_ogg() {
        assert_eq!(OggHandler.output_extension(), "ogg");
    }

    #[test]
    fn codec_prefix_strips_suffix() {
        assert_eq!(codec_prefix("OGG"), "OGG");
        assert_eq!(codec_prefix("OGG_LowQuality"), "OGG");
        assert_eq!(codec_prefix("OPUS"), "OPUS");
        assert_eq!(codec_prefix("_leading"), "");
    }

    // ===== supports =====

    #[test]
    fn supports_nonstreaming_ogg() {
        assert!(OggHandler.supports(&Asset::SoundWave(nonstreaming(&["OGG"]))));
    }

    #[test]
    fn supports_nonstreaming_ogg_with_platform_suffix() {
        assert!(OggHandler.supports(&Asset::SoundWave(nonstreaming(&["OGG_Switch"]))));
    }

    #[test]
    fn supports_streaming_ogg() {
        assert!(OggHandler.supports(&Asset::SoundWave(streaming("OGG", vec![]))));
    }

    #[test]
    fn rejects_non_ogg_nonstreaming_codecs() {
        for codec in ["OPUS", "ADPCM", "PCM", "BINKA"] {
            assert!(
                !OggHandler.supports(&Asset::SoundWave(nonstreaming(&[codec]))),
                "{codec} must not be claimed by the OGG handler"
            );
        }
    }

    #[test]
    fn rejects_streaming_non_ogg() {
        assert!(!OggHandler.supports(&Asset::SoundWave(streaming("OPUS", vec![]))));
    }

    #[test]
    fn supports_uses_first_wire_key_only() {
        // The active codec is the first wire-order key; a non-OGG first key is
        // not claimed even when a later key is OGG. (paksmith deliberately does
        // not sort keys the way CUE4Parse's `SortedDictionary.First()` does;
        // the two coincide for the single-format cooked norm.)
        assert!(!OggHandler.supports(&Asset::SoundWave(nonstreaming(&["OPUS", "OGG"]))));
    }

    #[test]
    fn supports_ogg_match_is_case_insensitive() {
        // CUE4Parse normalizes the codec name `OrdinalIgnoreCase`; paksmith
        // matches ASCII-case-insensitively so a non-canonical `"ogg"` key is
        // still claimed (and the suffix strip still applies).
        assert!(OggHandler.supports(&Asset::SoundWave(nonstreaming(&["ogg"]))));
        assert!(OggHandler.supports(&Asset::SoundWave(streaming("Ogg", vec![]))));
        assert!(OggHandler.supports(&Asset::SoundWave(nonstreaming(&["oGg_Switch"]))));
    }

    #[test]
    fn rejects_rawdata_path_with_no_codec() {
        // Non-cooked RawData: no format keys, no streamed data → no codec.
        assert!(!OggHandler.supports(&Asset::SoundWave(SoundWaveData::empty())));
    }

    #[test]
    fn rejects_non_soundwave_asset() {
        assert!(!OggHandler.supports(&Asset::Generic(PropertyBag::opaque(Vec::new()))));
    }

    // ===== export: non-streaming passthrough =====

    #[test]
    fn nonstreaming_export_is_byte_exact_passthrough() {
        let ogg = b"OggS\x00\x02 a complete vorbis file";
        let out = OggHandler
            .export(&Asset::SoundWave(nonstreaming(&["OGG"])), &[bulk(ogg)])
            .expect("passthrough");
        assert_eq!(out, ogg);
    }

    #[test]
    fn nonstreaming_export_empty_bulk_errs() {
        let err = OggHandler
            .export(&Asset::SoundWave(nonstreaming(&["OGG"])), &[])
            .unwrap_err();
        assert!(matches!(err, PaksmithError::Internal { .. }));
    }

    #[test]
    fn export_on_non_soundwave_errs() {
        let err = OggHandler
            .export(&Asset::Generic(PropertyBag::opaque(Vec::new())), &[])
            .unwrap_err();
        assert!(matches!(err, PaksmithError::Internal { .. }));
    }

    // ===== export: streaming reassembly =====

    #[test]
    fn streaming_export_concatenates_audio_data_size_prefixes() {
        // Two chunks, each padded to 8 bytes; only the leading AudioDataSize
        // bytes are real audio. Output must be the trimmed prefixes joined,
        // NOT the padded payloads concatenated.
        let chunks = vec![chunk(8, 4), chunk(8, 3)];
        let data = streaming("OGG", chunks);
        let bulks = [
            bulk(&[1, 2, 3, 4, 0, 0, 0, 0]),
            bulk(&[5, 6, 7, 0, 0, 0, 0, 0]),
        ];
        let out = OggHandler
            .export(&Asset::SoundWave(data), &bulks)
            .expect("reassembled");
        assert_eq!(out, vec![1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn streaming_export_zero_audio_chunk_contributes_nothing() {
        let data = streaming("OGG", vec![chunk(4, 0), chunk(4, 2)]);
        let bulks = [bulk(&[9, 9, 9, 9]), bulk(&[1, 2, 0, 0])];
        let out = OggHandler
            .export(&Asset::SoundWave(data), &bulks)
            .expect("reassembled");
        assert_eq!(out, vec![1, 2]);
    }

    #[test]
    fn streaming_export_zero_chunks_yields_empty() {
        // A zero-chunk streaming asset passes the desync guard (0 == 0), the
        // loop runs zero times, and the output is empty — no panic, no error.
        let out = OggHandler
            .export(&Asset::SoundWave(streaming("OGG", vec![])), &[])
            .expect("zero chunks → empty output");
        assert!(out.is_empty());
    }

    #[test]
    fn streaming_export_unpadded_chunk_uses_full_payload() {
        // An unpadded chunk (AudioDataSize == DataSize == payload length) is
        // valid — the whole payload is audio. The bounds check must accept the
        // exact-fit case (`audio_len == payload.len()`), not reject it.
        let data = streaming("OGG", vec![chunk(4, 4)]);
        let out = OggHandler
            .export(&Asset::SoundWave(data), &[bulk(&[1, 2, 3, 4])])
            .expect("exact-fit chunk is valid");
        assert_eq!(out, vec![1, 2, 3, 4]);
    }

    #[test]
    fn streaming_negative_audio_data_size_errs() {
        let data = streaming("OGG", vec![chunk(8, -1)]);
        let err = OggHandler
            .export(&Asset::SoundWave(data), &[bulk(&[0; 8])])
            .unwrap_err();
        assert!(matches!(err, PaksmithError::Internal { .. }));
    }

    #[test]
    fn streaming_audio_data_size_exceeding_payload_errs() {
        let data = streaming("OGG", vec![chunk(4, 10)]);
        let err = OggHandler
            .export(&Asset::SoundWave(data), &[bulk(&[1, 2, 3, 4])])
            .unwrap_err();
        assert!(matches!(err, PaksmithError::Internal { .. }));
    }

    #[test]
    fn streaming_chunk_bulk_count_desync_errs() {
        let data = streaming("OGG", vec![chunk(4, 4), chunk(4, 4)]);
        let err = OggHandler
            .export(&Asset::SoundWave(data), &[bulk(&[1, 2, 3, 4])])
            .unwrap_err();
        assert!(matches!(err, PaksmithError::Internal { .. }));
    }

    // ===== WavHandler (PCM / ADPCM) =====

    #[test]
    fn output_extension_is_wav() {
        assert_eq!(WavHandler.output_extension(), "wav");
    }

    #[test]
    fn supports_wav_codecs() {
        // Both keys in WAV_CODECS are claimed — PCM (first) and ADPCM (second,
        // so the `.any` walk must reach it), streaming or non-streaming.
        assert!(WavHandler.supports(&Asset::SoundWave(nonstreaming(&["PCM"]))));
        assert!(WavHandler.supports(&Asset::SoundWave(nonstreaming(&["ADPCM"]))));
        assert!(WavHandler.supports(&Asset::SoundWave(streaming("ADPCM", vec![]))));
        assert!(WavHandler.supports(&Asset::SoundWave(nonstreaming(&["ADPCM_Switch"]))));
    }

    #[test]
    fn supports_wav_match_is_case_insensitive() {
        assert!(WavHandler.supports(&Asset::SoundWave(nonstreaming(&["pcm"]))));
        assert!(WavHandler.supports(&Asset::SoundWave(streaming("Adpcm", vec![]))));
    }

    #[test]
    fn wav_rejects_ogg_opus_and_proprietary() {
        for codec in ["OGG", "OPUS", "BINKA", "XMA2", "AT9", "OPUSNX"] {
            assert!(
                !WavHandler.supports(&Asset::SoundWave(nonstreaming(&[codec]))),
                "{codec} must not be claimed by the WAV handler"
            );
        }
    }

    #[test]
    fn wav_rejects_rawdata_and_non_soundwave() {
        assert!(!WavHandler.supports(&Asset::SoundWave(SoundWaveData::empty())));
        assert!(!WavHandler.supports(&Asset::Generic(PropertyBag::opaque(Vec::new()))));
    }

    #[test]
    fn wav_nonstreaming_export_is_byte_exact_passthrough() {
        // The cooked PCM/ADPCM buffer is already a complete RIFF/WAVE container;
        // export returns it verbatim.
        let wav = b"RIFF\x24\x00\x00\x00WAVEfmt \x10\x00\x00\x00";
        let out = WavHandler
            .export(&Asset::SoundWave(nonstreaming(&["ADPCM"])), &[bulk(wav)])
            .expect("passthrough");
        assert_eq!(out, wav);
    }

    #[test]
    fn wav_streaming_export_reassembles_audio_data_size_prefixes() {
        // Streaming WAV reuses the shared chunk reassembly (padding-trimmed).
        let data = streaming("PCM", vec![chunk(4, 2), chunk(4, 4)]);
        let bulks = [bulk(&[1, 2, 0, 0]), bulk(&[3, 4, 5, 6])];
        let out = WavHandler
            .export(&Asset::SoundWave(data), &bulks)
            .expect("reassembled");
        assert_eq!(out, vec![1, 2, 3, 4, 5, 6]);
    }

    // ===== registry wiring =====

    #[test]
    fn registry_routes_ogg_soundwave_to_ogg_handler() {
        let reg = HandlerRegistry::all_default_handlers();
        for data in [nonstreaming(&["OGG"]), streaming("OGG", vec![])] {
            let handler = reg
                .find_handler(&Asset::SoundWave(data))
                .expect("OGG SoundWave routes to a handler");
            assert_eq!(handler.output_extension(), "ogg");
        }
    }

    #[test]
    fn registry_routes_wav_soundwave_to_wav_handler() {
        let reg = HandlerRegistry::all_default_handlers();
        for data in [nonstreaming(&["PCM"]), nonstreaming(&["ADPCM"])] {
            let handler = reg
                .find_handler(&Asset::SoundWave(data))
                .expect("PCM/ADPCM SoundWave routes to a handler");
            assert_eq!(handler.output_extension(), "wav");
        }
    }

    #[test]
    fn registry_does_not_route_unclaimed_soundwave_codec() {
        // OGG → OggHandler, PCM/ADPCM → WavHandler; OPUS and the proprietary
        // codecs are claimed by no handler yet, so find_handler returns None
        // (they fall through to GenericHandler only via the Generic discriminant,
        // not the SoundWave bucket).
        let reg = HandlerRegistry::all_default_handlers();
        for codec in ["OPUS", "BINKA", "OPUSNX"] {
            assert!(
                reg.find_handler(&Asset::SoundWave(nonstreaming(&[codec])))
                    .is_none(),
                "{codec} must not route to any SoundWave handler yet"
            );
        }
    }
}
