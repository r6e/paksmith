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
//! `OrdinalIgnoreCase`). The codecs paksmith does **not** decode — the UE Opus
//! keys (desktop `"OPUS"`, a custom "UE4OPUS" framing of raw Opus packets; and
//! Switch `"OPUSNX"`, the *distinct* "NXOpus" framing — both custom, *neither*
//! standard Ogg-Opus) and the proprietary keys (`"BINKA"` / `"XMA2"` / `"AT9"`)
//! — are claimed by [`RawSoundHandler`] instances that pass the raw cooked buffer
//! through with a codec-appropriate extension (`.binka` / `.xma` / `.at9` /
//! `.ue4opus` / `.nxopus`) so the asset surfaces and is extractable for an
//! external decoder, rather than `HandlerRegistry::find_handler` returning
//! `None`. The non-cooked `RawData` path carries no codec key, so no
//! handler matches it.

use crate::PaksmithError;
use crate::asset::{Asset, SoundWaveData, StreamedAudioChunk};
use crate::export::{BulkData, FormatHandler};

/// The Ogg-Vorbis codec key (UE `FName`). Non-streaming keys may carry a
/// platform suffix (`OGG_…`), which [`codec_prefix`] strips before comparing.
/// A single-element set so both handlers call `supports_codec(asset, <CONST>)`.
const OGG_CODECS: &[&str] = &["OGG"];

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
        supports_codec(asset, OGG_CODECS)
    }

    fn export(&self, asset: &Asset, bulk: &[BulkData]) -> crate::Result<Vec<u8>> {
        passthrough_export(asset, bulk)
    }
}

/// Decodes `Asset::SoundWave` Ogg-Vorbis audio to a 16-bit PCM `.wav` file — the
/// opt-in alternative to [`OggHandler`]'s verbatim `.ogg` passthrough. The cooked
/// `.ogg` is already universally playable, so this handler exists for callers
/// that want uncompressed PCM (reached via `find_handler_by_extension("wav", …)`;
/// `OggHandler` stays the `find_handler` default for the `"OGG"` codec). Stateless.
#[derive(Debug, Default, Clone, Copy)]
pub struct VorbisHandler;

impl FormatHandler for VorbisHandler {
    fn output_extension(&self) -> &'static str {
        "wav"
    }

    fn supports(&self, asset: &Asset) -> bool {
        supports_codec(asset, OGG_CODECS)
    }

    fn export(&self, asset: &Asset, bulk: &[BulkData]) -> crate::Result<Vec<u8>> {
        let ogg = passthrough_export(asset, bulk)?;
        // Unlike `WavHandler` (whose output is always a WAV, so a decode failure
        // can fall back to the cooked WAV), this handler's contract is a *decoded*
        // PCM WAV — a corrupt/undecodable Ogg-Vorbis stream is a hard error here.
        // The verbatim `.ogg` remains available via `OggHandler`.
        match crate::export::vorbis::transcode_vorbis_to_pcm(&ogg)? {
            Some(pcm) => Ok(pcm),
            None => Err(crate::PaksmithError::Internal {
                context:
                    "Vorbis decode: cooked \"OGG\" buffer is not a decodable Ogg-Vorbis stream"
                        .to_string(),
            }),
        }
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
        let wav = passthrough_export(asset, bulk)?;
        // The cooked `"PCM"`/`"ADPCM"` buffer (non-streaming) or the reassembled
        // chunk stream (streaming) is a complete WAV. IMA/DVI ADPCM
        // (`wFormatTag = 0x0011`) and Microsoft ADPCM (`0x0002`) are decoded to a
        // 16-bit PCM WAV; every other format (PCM, unknown tag, non-WAV) passes
        // through unchanged. A decode *failure* (corrupt block layout, or a decoded size
        // over the [`MAX_AUDIO_DECODED_BYTES`] cap) is non-fatal: the cooked
        // ADPCM WAV is itself a valid, ADPCM-player-playable file, so we fall
        // back to the verbatim passthrough (the pre-decoder behavior) and log
        // why — never allocating the over-cap output. See [`crate::export::adpcm`].
        //
        // [`MAX_AUDIO_DECODED_BYTES`]: crate::export::pcm::MAX_AUDIO_DECODED_BYTES
        match crate::export::adpcm::transcode_adpcm_to_pcm(&wav) {
            Ok(Some(pcm)) => Ok(pcm),
            Ok(None) => Ok(wav),
            Err(err) => {
                tracing::warn!(%err, "ADPCM decode failed; exporting the cooked WAV verbatim");
                Ok(wav)
            }
        }
    }
}

/// Surfaces `Asset::SoundWave` audio in a codec paksmith does **not** decode —
/// the proprietary / platform-licensed formats (`"BINKA"` Bink Audio, `"XMA2"`
/// Xbox, `"AT9"` PlayStation ATRAC9) and UE Opus (desktop `"OPUS"`, a custom
/// "UE4OPUS" framing of raw Opus packets; and Switch `"OPUSNX"`, the distinct
/// "NXOpus" framing — both custom, *neither* standard Ogg-Opus — see
/// `docs/formats/audio/audio-codecs.md`).
///
/// These need a licensed SDK or unverified custom framing, so paksmith can't
/// produce a playable file. Instead of silently dropping the asset
/// ([`HandlerRegistry::find_handler`] would otherwise return `None`), this
/// handler exports the **raw cooked buffer verbatim** with a codec-appropriate
/// extension (e.g. `.binka`, `.xma`, `.at9`, `.ue4opus`, `.nxopus`) so an external
/// tool (vgmstream, the RAD Bink SDK, …) can decode it, and logs a `warn` that the
/// output is undecoded. Each registered instance claims one codec family.
///
/// [`HandlerRegistry::find_handler`]: crate::export::HandlerRegistry::find_handler
#[derive(Debug, Clone, Copy)]
pub struct RawSoundHandler {
    codecs: &'static [&'static str],
    extension: &'static str,
}

impl RawSoundHandler {
    /// A handler claiming `codecs` (case-insensitive) and emitting the raw buffer
    /// as `extension` (no leading dot).
    #[must_use]
    pub const fn new(codecs: &'static [&'static str], extension: &'static str) -> Self {
        Self { codecs, extension }
    }
}

impl FormatHandler for RawSoundHandler {
    fn output_extension(&self) -> &'static str {
        self.extension
    }

    fn supports(&self, asset: &Asset) -> bool {
        supports_codec(asset, self.codecs)
    }

    fn export(&self, asset: &Asset, bulk: &[BulkData]) -> crate::Result<Vec<u8>> {
        let raw = passthrough_export(asset, bulk)?;
        if let Asset::SoundWave(data) = asset {
            tracing::warn!(
                codec = active_codec(data).unwrap_or("?"),
                extension = self.extension,
                bytes = raw.len(),
                "exported an undecoded audio buffer verbatim; paksmith does not decode \
                 this codec — decode the raw file with an external tool"
            );
        }
        Ok(raw)
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
    // Pre-size from the per-chunk audio sizes so the concatenation does not
    // re-grow (doubling) across many chunks. Each contribution is clamped to its
    // payload length, so a lying `AudioDataSize` cannot force an over-reservation
    // beyond the bytes actually present; `saturating_add` guards corrupt totals.
    // The per-chunk validation below still runs and errors on bad input — this is
    // only a capacity hint.
    let total: usize = chunks
        .iter()
        .zip(bulk)
        .map(|(chunk, record)| {
            usize::try_from(chunk.audio_data_size)
                .unwrap_or(0)
                .min(record.bytes.len())
        })
        .fold(0usize, usize::saturating_add);
    let mut out = Vec::with_capacity(total);
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

    // ===== VorbisHandler: "OGG" codec → decoded .wav (opt-in) =====

    const VORBIS_OGG: &[u8] = include_bytes!("testdata/vorbis_stereo.ogg");

    #[test]
    fn vorbis_handler_extension_is_wav() {
        assert_eq!(VorbisHandler.output_extension(), "wav");
    }

    #[test]
    fn vorbis_handler_supports_same_ogg_codecs_as_ogg_handler() {
        let ogg = Asset::SoundWave(nonstreaming(&["OGG"]));
        assert!(VorbisHandler.supports(&ogg));
        assert!(!VorbisHandler.supports(&Asset::SoundWave(nonstreaming(&["ADPCM"]))));
        assert!(!VorbisHandler.supports(&Asset::SoundWave(nonstreaming(&["OPUS"]))));
    }

    #[test]
    fn vorbis_handler_decodes_ogg_to_pcm_wav() {
        let out = VorbisHandler
            .export(
                &Asset::SoundWave(nonstreaming(&["OGG"])),
                &[bulk(VORBIS_OGG)],
            )
            .expect("decode ok");
        // Structural: a 16-bit PCM WAV, stereo, 44100 Hz (the decode itself is
        // exhaustively checked in `vorbis`'s own test module).
        assert_eq!(&out[0..4], b"RIFF");
        assert_eq!(&out[8..12], b"WAVE");
        assert_eq!(u16::from_le_bytes([out[20], out[21]]), 1); // WAVE_FORMAT_PCM
        assert_eq!(u16::from_le_bytes([out[22], out[23]]), 2); // channels
        assert_eq!(
            u32::from_le_bytes([out[24], out[25], out[26], out[27]]),
            44100
        );
        assert_eq!(u16::from_le_bytes([out[34], out[35]]), 16); // bits
    }

    #[test]
    fn vorbis_handler_errs_on_undecodable_ogg_buffer() {
        // An "OGG"-keyed SoundWave whose cooked buffer is not a decodable
        // Ogg-Vorbis stream is a hard error here (the verbatim `.ogg` stays
        // available via OggHandler), NOT a passthrough.
        let err = VorbisHandler
            .export(
                &Asset::SoundWave(nonstreaming(&["OGG"])),
                &[bulk(b"OggS not a real vorbis stream")],
            )
            .unwrap_err();
        assert!(matches!(err, crate::PaksmithError::Internal { .. }));
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

    /// A complete, valid `WAVE_FORMAT_PCM` (0x0001) container — parses cleanly
    /// but is not IMA-ADPCM, so the transcode returns `None`.
    fn valid_pcm_wav() -> Vec<u8> {
        let mut wav = Vec::new();
        wav.extend_from_slice(b"RIFF");
        wav.extend_from_slice(&40u32.to_le_bytes());
        wav.extend_from_slice(b"WAVE");
        wav.extend_from_slice(b"fmt ");
        wav.extend_from_slice(&16u32.to_le_bytes());
        wav.extend_from_slice(&1u16.to_le_bytes()); // WAVE_FORMAT_PCM
        wav.extend_from_slice(&1u16.to_le_bytes()); // mono
        wav.extend_from_slice(&8000u32.to_le_bytes());
        wav.extend_from_slice(&16000u32.to_le_bytes());
        wav.extend_from_slice(&2u16.to_le_bytes());
        wav.extend_from_slice(&16u16.to_le_bytes());
        wav.extend_from_slice(b"data");
        wav.extend_from_slice(&4u32.to_le_bytes());
        wav.extend_from_slice(&[1, 2, 3, 4]);
        wav
    }

    #[test]
    fn wav_nonstreaming_export_passes_through_valid_pcm_wav() {
        // A fully-parseable PCM WAV is exported verbatim — real passthrough
        // dispatch (transcode parses it, sees it's not IMA, returns None), not a
        // parse failure.
        let wav = valid_pcm_wav();
        let out = WavHandler
            .export(&Asset::SoundWave(nonstreaming(&["PCM"])), &[bulk(&wav)])
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

    #[test]
    fn wav_handler_decodes_ima_adpcm_buffer() {
        // End-to-end: an IMA-ADPCM cooked buffer is transcoded to a PCM WAV
        // (wFormatTag 0x0011 → 0x0001), not passed through. (The byte-exact
        // decode vs ffmpeg is pinned in `export::adpcm`.)
        const MONO_ADPCM: &[u8] = include_bytes!("testdata/adpcm_ima_mono.wav");
        let out = WavHandler
            .export(
                &Asset::SoundWave(nonstreaming(&["ADPCM"])),
                &[bulk(MONO_ADPCM)],
            )
            .expect("decode");
        assert_eq!(&out[0..4], b"RIFF");
        assert_eq!(u16::from_le_bytes([out[20], out[21]]), 1, "decoded to PCM");
        assert_ne!(out, MONO_ADPCM, "decoded, not passed through");
    }

    #[test]
    fn wav_handler_passes_through_non_ima_buffer() {
        // A buffer that is not IMA-ADPCM (here: not even a WAV) exports
        // verbatim — the transcode returns None and WavHandler returns the
        // assembled bytes unchanged.
        let raw = b"RIFFxxxxWAVE not really a wav chunk list";
        let out = WavHandler
            .export(&Asset::SoundWave(nonstreaming(&["PCM"])), &[bulk(raw)])
            .expect("passthrough");
        assert_eq!(out, raw);
    }

    #[test]
    fn wav_handler_passes_through_corrupt_ima_on_decode_error() {
        // An IMA-ADPCM (0x0011) WAV with corrupt geometry (nBlockAlign 0): the
        // decode errors, but WavHandler falls back to the verbatim passthrough
        // (the cooked ADPCM WAV is still a valid file) rather than failing.
        let mut wav = Vec::new();
        wav.extend_from_slice(b"RIFF");
        wav.extend_from_slice(&0u32.to_le_bytes());
        wav.extend_from_slice(b"WAVE");
        wav.extend_from_slice(b"fmt ");
        wav.extend_from_slice(&20u32.to_le_bytes());
        wav.extend_from_slice(&0x0011u16.to_le_bytes()); // IMA-ADPCM
        wav.extend_from_slice(&1u16.to_le_bytes());
        wav.extend_from_slice(&22050u32.to_le_bytes());
        wav.extend_from_slice(&0u32.to_le_bytes());
        wav.extend_from_slice(&0u16.to_le_bytes()); // nBlockAlign = 0 → geometry error
        wav.extend_from_slice(&4u16.to_le_bytes());
        wav.extend_from_slice(&2u16.to_le_bytes());
        wav.extend_from_slice(&0u16.to_le_bytes());
        wav.extend_from_slice(b"data");
        wav.extend_from_slice(&4u32.to_le_bytes());
        wav.extend_from_slice(&[1, 2, 3, 4]);
        let out = WavHandler
            .export(&Asset::SoundWave(nonstreaming(&["ADPCM"])), &[bulk(&wav)])
            .expect("decode error falls back to passthrough");
        assert_eq!(out, wav);
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
    fn registry_routes_proprietary_codecs_to_raw_passthrough() {
        // The codecs paksmith can't decode (proprietary + custom-framed UE Opus)
        // surface via RawSoundHandler with a codec-appropriate extension — raw
        // extraction, not a silent drop.
        let reg = HandlerRegistry::all_default_handlers();
        for (codec, ext) in [
            ("BINKA", "binka"),
            ("XMA2", "xma"),
            ("AT9", "at9"),
            ("OPUS", "ue4opus"),
            ("OPUSNX", "nxopus"),
        ] {
            let handler = reg
                .find_handler(&Asset::SoundWave(nonstreaming(&[codec])))
                .unwrap_or_else(|| panic!("{codec} must route to RawSoundHandler"));
            assert_eq!(handler.output_extension(), ext, "{codec} → .{ext}");
        }
    }

    #[test]
    fn registry_does_not_route_genuinely_unknown_soundwave_codec() {
        // A codec key claimed by no handler is still dropped (find_handler → None);
        // GenericHandler (Asset::Generic bucket only) is never reached.
        let reg = HandlerRegistry::all_default_handlers();
        assert!(
            reg.find_handler(&Asset::SoundWave(nonstreaming(&["NOTACODEC"])))
                .is_none(),
            "an unknown codec must not route to any SoundWave handler"
        );
    }

    // ===== RawSoundHandler: undecoded proprietary/Opus → raw passthrough =====

    #[test]
    fn raw_sound_handler_passes_buffer_through_verbatim() {
        let raw = b"BINKA raw cooked audio bytes \x01\x02\x03";
        let handler = RawSoundHandler::new(&["BINKA"], "binka");
        let out = handler
            .export(&Asset::SoundWave(nonstreaming(&["BINKA"])), &[bulk(raw)])
            .expect("raw passthrough");
        assert_eq!(out, raw);
        assert_eq!(handler.output_extension(), "binka");
    }

    #[test]
    fn raw_sound_handler_supports_only_its_codec_family() {
        // Desktop UE4OPUS and Switch NXOpus are distinct framings → distinct
        // single-codec handlers, each claiming only its own key.
        let ue4 = RawSoundHandler::new(&["OPUS"], "ue4opus");
        assert!(ue4.supports(&Asset::SoundWave(nonstreaming(&["OPUS"]))));
        // Case-insensitive (CUE4Parse normalizes).
        assert!(ue4.supports(&Asset::SoundWave(nonstreaming(&["opus"]))));
        assert!(ue4.supports(&Asset::SoundWave(streaming("OPUS", vec![]))));
        assert!(!ue4.supports(&Asset::SoundWave(nonstreaming(&["OPUSNX"]))));
        assert!(!ue4.supports(&Asset::SoundWave(nonstreaming(&["BINKA"]))));
        assert!(!ue4.supports(&Asset::SoundWave(nonstreaming(&["OGG"]))));

        let nx = RawSoundHandler::new(&["OPUSNX"], "nxopus");
        assert!(nx.supports(&Asset::SoundWave(nonstreaming(&["OPUSNX"]))));
        assert!(!nx.supports(&Asset::SoundWave(nonstreaming(&["OPUS"]))));
    }
}
