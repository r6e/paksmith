//! `USoundWave` (and related audio) export parsing (Phase 3f).
//!
//! Wire-format reference: `docs/formats/audio/sound-wave.md` (oracle
//! `FabianFG/CUE4Parse` `USoundWave.cs`). The export payload is, in order:
//!
//! 1. **`USoundBase` tagged properties** — the standard None-terminated
//!    `FPropertyTag` stream carrying the audio settings (sample rate, channel
//!    count, duration, loop / attenuation metadata), decoded by the existing
//!    [`read_properties`](crate::asset::property::read_properties).
//! 2. **USoundWave binary header** — `Flags` (with `bCooked` in bit 0), a
//!    version-conditional `DummyCompressionName`, optional UE 5.4+ cue points,
//!    then the platform-data segment (`FFormatContainer` non-streaming or
//!    `FStreamedAudioPlatformData` streaming) carrying the per-codec audio
//!    buffers as `FByteBulkData`.
//!
//! The `SoundWave` class routes to a typed reader producing [`Asset::SoundWave`]
//! (rather than falling through to `Asset::Generic`). Parsing lands
//! incrementally — see the per-milestone notes in [`sound_wave`] for the
//! current wire coverage. The full USoundWave binary is now parsed: segment 1,
//! the binary-header `Flags`/`bCooked`, the `DummyCompressionName`, and all
//! platform-data branches — the non-streaming `FFormatContainer` (cooked) /
//! `RawData` (non-cooked), the streaming `FStreamedAudioPlatformData`, each with
//! the `CompressedDataGuid`, plus the (now unconditional) streaming-flip retry.
//! What remains is the per-codec audio decoding (the `FormatHandler`s).

pub(crate) mod sound_wave;

use crate::asset::package::Package;
use crate::asset::property::{PropertyBag, PropertyValue};
use crate::asset::{Asset, SoundWaveData};
use crate::export::{active_codec, assemble_streaming, extract_nonstreaming};

/// Lightweight summary of a `USoundWave` export — produced by
/// [`classify_audio`] without resolving or decoding any bulk data.
///
/// The GUI audio player uses this to populate tab headers and decide whether
/// the play button is enabled (codec is decodable in-app) before issuing a
/// full [`decode_audio_to_pcm`] call.
#[derive(Debug, Clone, PartialEq)]
pub struct AudioInfo {
    /// Index into `Package.payloads` of the `Asset::SoundWave` export.
    pub export_idx: usize,
    /// Human-readable codec label. `"Vorbis (Ogg)"` for OGG; the raw
    /// codec string (uppercased) for all other codecs.
    pub codec_label: String,
    /// Channel count from the `NumChannels` tagged property, or `None`
    /// when the property is absent.
    pub channels: Option<u16>,
    /// Duration in seconds from the `Duration` tagged property, or `None`
    /// when the property is absent.
    pub duration_secs: Option<f32>,
    /// Whether the codec is decodable in-app via [`decode_audio_to_pcm`].
    /// `true` for PCM, ADPCM, and OGG (Vorbis); `false` for everything
    /// else (e.g. OPUS, BINKA, XMA2).
    pub playable: bool,
}

/// Find the first `USoundWave` export with registered bulk records and return
/// a lightweight [`AudioInfo`] summary, or `None` if no playable audio export
/// is present.
///
/// "Has bulk records" means the typed reader populated the package's bulk map
/// for that export index — guaranteed for any `Package` built via the
/// `read_from*` constructors. A hand-assembled `Package` without a
/// `bulk_data` entry would classify as `None`.
///
/// This function is **pure and does no I/O**. The `codec_label` and `playable`
/// flag are derived from the export's active codec; the `channels` and
/// `duration_secs` fields are read from the segment-1 tagged-property bag.
pub fn classify_audio(package: &Package) -> Option<AudioInfo> {
    let (export_idx, data) = package
        .payloads
        .iter()
        .enumerate()
        .find_map(|(i, a)| match a {
            Asset::SoundWave(d) if package.has_bulk_records(i) => Some((i, d)),
            _ => None,
        })?;
    let codec = active_codec(data)?;
    let (codec_label, playable) = match codec.to_ascii_uppercase().as_str() {
        "PCM" => ("PCM".to_string(), true),
        "ADPCM" => ("ADPCM".to_string(), true),
        "OGG" => ("Vorbis (Ogg)".to_string(), true),
        other => (other.to_string(), false),
    };
    let (channels, duration_secs) = read_sound_metadata(data);
    Some(AudioInfo {
        export_idx,
        codec_label,
        channels,
        duration_secs,
        playable,
    })
}

/// Read `NumChannels` (Int → `u16`) and `Duration` (Float) from the
/// segment-1 tagged-property bag. Both are `Option` — an absent property
/// yields `None` without error.
fn read_sound_metadata(data: &SoundWaveData) -> (Option<u16>, Option<f32>) {
    let PropertyBag::Tree { properties } = &data.properties else {
        return (None, None);
    };
    let channels =
        sound_wave::scalar_property(properties, "NumChannels").and_then(|p| match p.value {
            PropertyValue::Int(n) => u16::try_from(n).ok(),
            _ => None,
        });
    let duration =
        sound_wave::scalar_property(properties, "Duration").and_then(|p| match p.value {
            PropertyValue::Float(f) => Some(f),
            _ => None,
        });
    (channels, duration)
}

/// A decoded audio clip as interleaved 16-bit PCM samples.
///
/// Produced by [`decode_audio_to_pcm`] — the source `USoundWave` is decoded
/// (ADPCM → PCM or Ogg-Vorbis → PCM) and wrapped in this struct so GUI and
/// CLI consumers don't have to know the codec.
#[derive(Debug, Clone)]
pub struct AudioPcm {
    /// Frame-interleaved signed 16-bit samples (channel 0, channel 1, …).
    pub samples: Vec<i16>,
    /// Sample rate in Hz (e.g. 44100).
    pub sample_rate: u32,
    /// Number of channels (1 = mono, 2 = stereo, …).
    pub channels: u16,
}

/// Decode a `USoundWave` export into interleaved 16-bit PCM.
///
/// Resolves the cooked codec buffer from `package.bulk_data`, routes it
/// through the appropriate codec decoder (ADPCM → PCM transcoder,
/// Ogg-Vorbis → PCM transcoder, or raw PCM passthrough), then parses the
/// resulting 16-bit PCM WAV.
///
/// # Errors
///
/// - [`crate::PaksmithError::InvalidArgument`] — `export_idx` is out of range
///   or does not point at a `USoundWave` export.
/// - [`crate::PaksmithError::UnsupportedFeature`] — the codec is not decodable
///   in-app (e.g. `OPUS`, `BINKA`), or the resulting PCM WAV is not 16-bit.
/// - [`crate::PaksmithError::Internal`] — bulk resolution failed, streaming
///   chunk reassembly desynced, or the decoded WAV is structurally invalid.
pub fn decode_audio_to_pcm(package: &Package, export_idx: usize) -> crate::Result<AudioPcm> {
    let asset =
        package
            .payloads
            .get(export_idx)
            .ok_or_else(|| crate::PaksmithError::InvalidArgument {
                arg: "export_idx",
                reason: format!("out of range (payloads: {})", package.payloads.len()),
            })?;
    let Asset::SoundWave(data) = asset else {
        return Err(crate::PaksmithError::InvalidArgument {
            arg: "export_idx",
            reason: "export is not a USoundWave".to_string(),
        });
    };
    let bulk = package.resolve_bulk_for_export(export_idx)?;
    let cooked = match &data.streamed {
        Some(streamed) => assemble_streaming(&streamed.chunks, bulk)?,
        None => extract_nonstreaming(bulk)?,
    };
    let codec = active_codec(data).ok_or_else(|| crate::PaksmithError::Internal {
        context: "USoundWave has no active codec".to_string(),
    })?;
    let wav: Vec<u8> = match codec.to_ascii_uppercase().as_str() {
        "OGG" => crate::export::transcode_vorbis_to_pcm(&cooked)?.ok_or_else(|| {
            crate::PaksmithError::Internal {
                context: "cooked OGG buffer is not decodable Ogg-Vorbis".to_string(),
            }
        })?,
        "ADPCM" | "PCM" => {
            match crate::export::transcode_adpcm_to_pcm(&cooked)? {
                Some(decoded) => decoded, // ADPCM transcoded to PCM WAV
                None => cooked,           // already PCM WAV — passthrough
            }
        }
        other => {
            return Err(crate::PaksmithError::UnsupportedFeature {
                context: format!("audio codec `{other}` is not decodable in-app"),
            });
        }
    };
    let (channels, sample_rate, samples) = crate::export::parse_pcm_wav(&wav)?;
    Ok(AudioPcm {
        samples,
        sample_rate,
        channels,
    })
}

#[cfg(all(test, feature = "__test_utils"))]
mod tests {
    use super::*;
    use crate::asset::bulk_data::{BulkData, BulkDataTier, make_zero_record};
    use crate::asset::package::Package;
    use crate::asset::{Asset, SoundWaveData, StreamedAudioChunk, StreamedAudioData};
    use crate::testing::uasset::build_minimal_ue4_27;
    use std::sync::{Arc, OnceLock};

    fn nonstreaming(keys: &[&str]) -> SoundWaveData {
        let mut data = SoundWaveData::empty();
        data.cooked = true;
        data.compressed_format_keys = keys.iter().map(|k| Arc::from(*k)).collect();
        data
    }

    fn bulk(bytes: &[u8]) -> BulkData {
        BulkData {
            bytes: bytes.to_vec(),
            record: make_zero_record(),
            tier: BulkDataTier::Inline,
        }
    }

    /// Build a `Package` whose primary export (index 0) is the given
    /// `SoundWaveData` with `audio_bytes` pre-loaded as its resolved bulk.
    fn audio_pkg(sound_wave: SoundWaveData, audio_bytes: &[u8]) -> Package {
        let fixture = build_minimal_ue4_27();
        let mut pkg = Package::read_from(&fixture.bytes, None, None, "Game/Test.uasset")
            .expect("parse minimal package");
        pkg.payloads[0] = Asset::SoundWave(sound_wave);
        let cache: OnceLock<Vec<BulkData>> = OnceLock::new();
        cache
            .set(vec![bulk(audio_bytes)])
            .expect("OnceLock was empty");
        let _ = pkg.bulk_data.insert(0, (Vec::new(), cache));
        pkg
    }

    // ===== IMA-ADPCM mono — byte-exact golden vector =====

    #[test]
    fn decode_audio_to_pcm_ima_adpcm_mono_matches_expected() {
        const MONO_ADPCM: &[u8] = include_bytes!("../../../export/testdata/adpcm_ima_mono.wav");
        const EXPECTED: &[u8] =
            include_bytes!("../../../export/testdata/adpcm_ima_mono_expected.pcm");
        let pkg = audio_pkg(nonstreaming(&["ADPCM"]), MONO_ADPCM);
        let pcm = decode_audio_to_pcm(&pkg, 0).expect("decode ok");
        assert_eq!(pcm.channels, 1);
        assert_eq!(pcm.sample_rate, 22050); // adpcm_ima_mono.wav is 22050 Hz
        let bytes: Vec<u8> = pcm.samples.iter().flat_map(|s| s.to_le_bytes()).collect();
        assert_eq!(bytes, EXPECTED);
    }

    // ===== MS-ADPCM stereo — byte-exact golden vector =====

    #[test]
    fn decode_audio_to_pcm_ms_adpcm_stereo_matches_expected() {
        const STEREO_ADPCM: &[u8] = include_bytes!("../../../export/testdata/adpcm_ms_stereo.wav");
        const EXPECTED: &[u8] =
            include_bytes!("../../../export/testdata/adpcm_ms_stereo_expected.pcm");
        let pkg = audio_pkg(nonstreaming(&["ADPCM"]), STEREO_ADPCM);
        let pcm = decode_audio_to_pcm(&pkg, 0).expect("decode ok");
        assert_eq!(pcm.channels, 2);
        assert_eq!(pcm.sample_rate, 22050); // adpcm_ms_stereo.wav is 22050 Hz
        let bytes: Vec<u8> = pcm.samples.iter().flat_map(|s| s.to_le_bytes()).collect();
        assert_eq!(bytes, EXPECTED);
    }

    // ===== Ogg-Vorbis stereo — structural check (lossy codec) =====

    #[test]
    fn decode_audio_to_pcm_ogg_vorbis_stereo_structural() {
        const VORBIS: &[u8] = include_bytes!("../../../export/testdata/vorbis_stereo.ogg");
        let pkg = audio_pkg(nonstreaming(&["OGG"]), VORBIS);
        let pcm = decode_audio_to_pcm(&pkg, 0).expect("decode ok");
        assert_eq!(pcm.channels, 2);
        assert_eq!(pcm.sample_rate, 44100); // vorbis_stereo.ogg is 44100 Hz
        // Lossy codec: not byte-exact, but must produce non-trivial output with
        // non-zero energy (matches the structural check in export/audio.rs tests).
        assert!(!pcm.samples.is_empty(), "must produce samples");
        assert!(
            pcm.samples.iter().any(|&s| s != 0),
            "decoded samples must have non-zero energy"
        );
    }

    // ===== Error paths =====

    #[test]
    fn decode_audio_to_pcm_out_of_range_export_idx() {
        let fixture = build_minimal_ue4_27();
        let pkg =
            Package::read_from(&fixture.bytes, None, None, "Game/Test.uasset").expect("parse");
        let err = decode_audio_to_pcm(&pkg, 9999).unwrap_err();
        assert!(
            matches!(
                err,
                crate::PaksmithError::InvalidArgument {
                    arg: "export_idx",
                    ..
                }
            ),
            "expected InvalidArgument, got {err:?}"
        );
    }

    #[test]
    fn decode_audio_to_pcm_non_soundwave_export() {
        let fixture = build_minimal_ue4_27();
        let pkg =
            Package::read_from(&fixture.bytes, None, None, "Game/Test.uasset").expect("parse");
        // build_minimal_ue4_27 produces a Generic export — do not replace it.
        let err = decode_audio_to_pcm(&pkg, 0).unwrap_err();
        assert!(
            matches!(
                err,
                crate::PaksmithError::InvalidArgument {
                    arg: "export_idx",
                    ..
                }
            ),
            "expected InvalidArgument, got {err:?}"
        );
    }

    #[test]
    fn decode_audio_to_pcm_proprietary_codec_unsupported() {
        // OPUS, BINKA, XMA2 etc. are proprietary; the function must return
        // UnsupportedFeature rather than panicking or silently producing garbage.
        let pkg = audio_pkg(nonstreaming(&["OPUS"]), b"OggS\x00 fake opus data");
        let err = decode_audio_to_pcm(&pkg, 0).unwrap_err();
        assert!(
            matches!(err, crate::PaksmithError::UnsupportedFeature { .. }),
            "expected UnsupportedFeature, got {err:?}"
        );
    }

    // ===== PCM passthrough arm =====

    #[test]
    fn decode_audio_to_pcm_pcm_wav_passthrough_exact_roundtrip() {
        // "PCM" codec with a valid 16-bit PCM WAV → transcode_adpcm_to_pcm
        // returns Ok(None) (tag is WAVE_FORMAT_PCM, not ADPCM), so the `None =>
        // cooked` passthrough arm is taken and parse_pcm_wav round-trips the
        // buffer.  Divergent sample values / stereo / non-standard rate ensure a
        // broken passthrough (e.g. returning silence or wrong channel count) is
        // immediately visible as an exact-equality failure.
        let samples: Vec<i16> = vec![100, -200, 300, -400];
        let wav = crate::export::build_pcm_wav(&samples, 2, 22050);
        let pkg = audio_pkg(nonstreaming(&["PCM"]), &wav);
        let pcm = decode_audio_to_pcm(&pkg, 0).expect("PCM passthrough must succeed");
        assert_eq!(pcm.channels, 2, "channel count must round-trip");
        assert_eq!(pcm.sample_rate, 22050, "sample rate must round-trip");
        assert_eq!(pcm.samples, samples, "samples must round-trip exactly");
    }

    // ===== OGG-undecodable arm =====

    #[test]
    fn decode_audio_to_pcm_ogg_undecodable_errs_internal() {
        // A SoundWave tagged "OGG" but whose bulk is not an Ogg-Vorbis stream →
        // transcode_vorbis_to_pcm returns Ok(None) (non-OGG passthrough in the
        // vorbis layer) → the OGG arm's .ok_or_else converts None to
        // Err(Internal).  Mirrors the assertion in
        // `vorbis::tests::vorbis_handler_errs_on_undecodable_ogg_buffer`.
        let pkg = audio_pkg(nonstreaming(&["OGG"]), b"not ogg data at all");
        let err = decode_audio_to_pcm(&pkg, 0).unwrap_err();
        assert!(
            matches!(err, crate::PaksmithError::Internal { .. }),
            "expected Internal for undecodable OGG buffer, got {err:?}"
        );
    }

    // ===== Streaming path — exercises assemble_streaming branch =====

    #[test]
    fn decode_audio_to_pcm_streaming_adpcm_mono_matches_expected() {
        // Build a streaming SoundWave whose single chunk contains the full
        // IMA-ADPCM WAV. `assemble_streaming` trims to `audio_data_size` bytes;
        // set it equal to the full length so the output is identical to the
        // non-streaming case.
        const MONO_ADPCM: &[u8] = include_bytes!("../../../export/testdata/adpcm_ima_mono.wav");
        const EXPECTED: &[u8] =
            include_bytes!("../../../export/testdata/adpcm_ima_mono_expected.pcm");
        let audio_len = i32::try_from(MONO_ADPCM.len()).expect("fits in i32");
        let mut data = SoundWaveData::empty();
        data.cooked = true;
        data.streaming = true;
        data.streamed = Some(StreamedAudioData {
            audio_format: Arc::from("ADPCM"),
            chunks: vec![StreamedAudioChunk {
                data_size: audio_len,
                audio_data_size: audio_len,
                seek_offset_in_audio_frames: None,
            }],
        });
        let fixture = build_minimal_ue4_27();
        let mut pkg =
            Package::read_from(&fixture.bytes, None, None, "Game/Test.uasset").expect("parse");
        pkg.payloads[0] = Asset::SoundWave(data);
        let cache: OnceLock<Vec<BulkData>> = OnceLock::new();
        cache
            .set(vec![bulk(MONO_ADPCM)])
            .expect("OnceLock was empty");
        let _ = pkg.bulk_data.insert(0, (Vec::new(), cache));
        let pcm = decode_audio_to_pcm(&pkg, 0).expect("streaming decode ok");
        assert_eq!(pcm.channels, 1);
        assert_eq!(pcm.sample_rate, 22050);
        let bytes: Vec<u8> = pcm.samples.iter().flat_map(|s| s.to_le_bytes()).collect();
        assert_eq!(bytes, EXPECTED);
    }

    // ===== classify_audio =====

    /// Build a SoundWaveData with tagged properties in a Tree bag.
    ///
    /// `num_channels` and `duration_secs` are both optional — pass `None` to
    /// omit the corresponding property from the bag, mirroring the case where the
    /// cooker didn't write the field.
    fn nonstreaming_with_metadata(
        keys: &[&str],
        num_channels: Option<i32>,
        duration_secs: Option<f32>,
    ) -> SoundWaveData {
        use crate::asset::property::{Property, PropertyBag, PropertyValue};
        let mut props: Vec<Property> = Vec::new();
        if let Some(ch) = num_channels {
            props.push(Property {
                name: Arc::from("NumChannels"),
                array_index: 0,
                guid: None,
                value: PropertyValue::Int(ch),
            });
        }
        if let Some(dur) = duration_secs {
            props.push(Property {
                name: Arc::from("Duration"),
                array_index: 0,
                guid: None,
                value: PropertyValue::Float(dur),
            });
        }
        let mut data = nonstreaming(keys);
        data.properties = PropertyBag::tree(props);
        data
    }

    #[test]
    fn classify_audio_reports_playable_adpcm_with_channels_and_duration() {
        // ADPCM is playable; NumChannels=1, Duration=1.5 both present.
        // Pins: export_idx==0, codec_label=="ADPCM", playable==true,
        //       channels==Some(1), duration_secs==Some(1.5).
        let sw = nonstreaming_with_metadata(&["ADPCM"], Some(1), Some(1.5));
        let pkg = audio_pkg(sw, b"dummy");
        let info = classify_audio(&pkg).expect("is a sound");
        assert_eq!(info.export_idx, 0);
        assert_eq!(info.codec_label, "ADPCM");
        assert_eq!(info.channels, Some(1));
        assert_eq!(info.duration_secs, Some(1.5));
        assert!(info.playable);
    }

    #[test]
    fn classify_audio_ogg_label_is_vorbis_ogg_and_playable() {
        // OGG → codec_label == "Vorbis (Ogg)", playable == true.
        let sw = nonstreaming_with_metadata(&["OGG"], Some(2), None);
        let pkg = audio_pkg(sw, b"dummy");
        let info = classify_audio(&pkg).expect("is a sound");
        assert_eq!(info.codec_label, "Vorbis (Ogg)");
        assert!(info.playable);
    }

    #[test]
    fn classify_audio_pcm_is_playable_with_pcm_label() {
        // PCM arm: codec_label == "PCM", playable == true.
        let sw = nonstreaming_with_metadata(&["PCM"], Some(1), None);
        let pkg = audio_pkg(sw, b"dummy");
        let info = classify_audio(&pkg).expect("is a sound");
        assert_eq!(info.codec_label, "PCM");
        assert!(info.playable);
    }

    #[test]
    fn classify_audio_opus_not_playable() {
        // OPUS is proprietary — playable == false, codec_label == "OPUS".
        let sw = nonstreaming_with_metadata(&["OPUS"], None, None);
        let pkg = audio_pkg(sw, b"dummy");
        let info = classify_audio(&pkg).expect("is a sound");
        assert!(!info.playable);
        assert_eq!(info.codec_label, "OPUS");
    }

    #[test]
    fn classify_audio_none_for_non_soundwave_package() {
        // A package with no SoundWave export → classify_audio returns None.
        let fixture = build_minimal_ue4_27();
        let pkg =
            Package::read_from(&fixture.bytes, None, None, "Game/Test.uasset").expect("parse");
        // build_minimal_ue4_27 produces a Generic export — not a SoundWave.
        assert!(
            classify_audio(&pkg).is_none(),
            "expected None for a non-SoundWave package"
        );
    }

    #[test]
    fn classify_audio_none_when_no_bulk_records() {
        // A SoundWave payload exists but no bulk records → classify_audio returns None.
        let sw = nonstreaming(&["ADPCM"]);
        let fixture = build_minimal_ue4_27();
        let mut pkg =
            Package::read_from(&fixture.bytes, None, None, "Game/Test.uasset").expect("parse");
        pkg.payloads[0] = Asset::SoundWave(sw);
        // Intentionally do NOT call pkg.bulk_data.insert(...) so has_bulk_records returns false.
        assert!(
            classify_audio(&pkg).is_none(),
            "expected None when no bulk records registered"
        );
    }

    #[test]
    fn classify_audio_absent_numchannels_gives_none_channels() {
        // NumChannels property absent → channels == None (graceful).
        let sw = nonstreaming_with_metadata(&["OGG"], None, None);
        let pkg = audio_pkg(sw, b"dummy");
        let info = classify_audio(&pkg).expect("is a sound");
        assert_eq!(info.channels, None);
    }
}
