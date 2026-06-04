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
//! current wire coverage (segment 1, the binary-header `Flags`/`bCooked`, the
//! `DummyCompressionName`, and the non-streaming cooked platform data —
//! `FFormatContainer` + `CompressedDataGuid`) and what remains deferred (the
//! streaming `FStreamedAudioPlatformData` branch, the non-cooked `RawData`
//! path, and the streaming-flip retry).

pub(crate) mod sound_wave;
