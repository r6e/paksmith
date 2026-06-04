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
//! **3f-1 scope:** segment 1 only — route the `SoundWave` class to a typed
//! reader and capture the tagged-property segment as [`Asset::SoundWave`]
//! (instead of falling through to `Asset::Generic`). The binary header
//! (segment 2) is parsed in 3f-2 onward.

pub(crate) mod sound_wave;
