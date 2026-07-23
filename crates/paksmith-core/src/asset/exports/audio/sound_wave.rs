//! `USoundWave` export reader (Phase 3f).
//!
//! Wire-format reference: `docs/formats/audio/sound-wave.md` (oracle
//! `FabianFG/CUE4Parse` `USoundWave.cs`). See the module docs ([`super`]).
//!
//! **3f-1** captured segment 1a (the `USoundBase` tagged-property stream).
//! **3f-2** added the start of the binary header: it resolves `bStreaming`,
//! reads the `Flags` `u32`, and extracts `bCooked` (bit 0). **3f** consumes the
//! version-conditional `DummyCompressionName` (a discarded `FName`). **3f-3**
//! parses the non-streaming cooked platform data — the `FFormatContainer`
//! (per-codec keys + `FByteBulkData` buffers) + `CompressedDataGuid`. **3f-4**
//! parses the streaming branch: the `CompressedDataGuid` then (when cooked) the
//! `FStreamedAudioPlatformData` (`AudioFormat` + per-chunk metadata + chunk
//! `FByteBulkData` buffers). **3f-5** adds the oracle's streaming-flip retry —
//! re-parsing the opposite branch when a mis-resolved `streaming` guess makes
//! the chosen branch fail. **This slice** parses the non-streaming non-cooked
//! `RawData` path (a single `FByteBulkData` + `CompressedDataGuid`), completing
//! the platform-data matrix — so every `(streaming, cooked)` combo is a real
//! read and the retry is now unconditional. (The oracle's UE 5.4+ cue points
//! are unreachable — they need object version 1012, above paksmith's 1011
//! `FPropertyTag` ceiling
//! — so platform data follows
//! `DummyCompressionName` directly.)

use std::io::Cursor;
use std::sync::Arc;

use byteorder::{LittleEndian, ReadBytesExt};

use crate::asset::bulk_data::{FByteBulkData, MAX_BULK_DATA_RECORDS_PER_EXPORT};
use crate::asset::custom_version::{
    FRAMEWORK_OBJECT_VERSION_GUID, FRAMEWORK_OBJECT_VERSION_REMOVE_SOUND_WAVE_COMPRESSION_NAME,
};
use crate::asset::property::bag::PropertyBag;
use crate::asset::property::primitives::{Property, PropertyValue};
use crate::asset::property::{read_fname_pair, read_object_guid_tail, read_properties};
use crate::asset::version::AssetVersion;
use crate::asset::{
    Asset, AssetContext, FGuid, SoundWaveData, StreamedAudioChunk, StreamedAudioData,
};
use crate::error::{AssetParseFault, AssetWireField, BoundsUnit, PaksmithError};

/// `ESoundWaveFlag::CookedFlag` — bit 0 of the `Flags` header (CUE4Parse
/// `ESoundWaveFlag`). The other bits (`HasOwnerLoadingBehaviorFlag`, the
/// loading-behavior enum) are not consumed by paksmith's cooked-export path.
/// (Written as the bit-0 literal rather than `1 << 0`: a `<<`→`>>` mutant of
/// the shift is equivalent at shift-0, so the literal avoids a dead mutant.)
const SOUND_WAVE_COOKED_FLAG: u32 = 0b0000_0001;

/// Cap on the non-streaming `FFormatContainer` entry count (`numFormats`). A
/// cooked `USoundWave` carries one format per target codec/platform — a handful
/// in practice — so this generous ceiling rejects an `i32`-count allocation
/// bomb without rejecting valid content. Defense-in-depth: the loop is already
/// EOF-bounded (each entry reads an `FByteBulkData` header that errors on
/// truncation), and the returned records are additionally capped downstream by
/// [`MAX_BULK_DATA_RECORDS_PER_EXPORT`](crate::asset::bulk_data).
const MAX_SOUND_FORMATS: i32 = 64;

/// Cap on the streaming `FStreamedAudioPlatformData` chunk count (`NumChunks`).
///
/// This is NOT a guess at how many chunks real audio carries (CUE4Parse imposes
/// no cap and reads `NumChunks` unconditionally). It is the largest chunk count
/// that CANNOT dangle the `chunks[i] ↔ bulk record i` invariant: each chunk
/// contributes exactly one `FByteBulkData` record, the typed asset is pushed to
/// the package BEFORE the deferred `insert_bulk_records` pass runs, and that pass
/// DROPS the whole record list for an export whose count exceeds
/// [`MAX_BULK_DATA_RECORDS_PER_EXPORT`]. A cap above the budget would let an
/// over-budget asset parse (asset pushed with N chunks) yet lose all N records on
/// insert — re-creating the dangling invariant at a higher threshold. So the cap
/// is BOUND to the budget by design, not coincidence (this reader's bulk vec
/// starts empty, so the full budget applies — vs. the VT reader's
/// remaining-budget subtraction; `MAX_SOUND_FORMATS` = 64 is already within the
/// budget, so the non-streaming branch needs no equivalent bound).
///
/// **Limitation.** A cooked streaming asset whose `NumChunks` exceeds the budget
/// fails LOUD at parse (→ `Asset::Generic` via the dispatch fallback) rather than
/// corrupting. With UE's default 256 KiB stream-chunk size, 256 chunks is ~64 MiB
/// of compressed audio (hours-long) — far above any normal single cue — so this
/// is a tolerable per-export-budget ceiling, not a chunk-count limit on realistic
/// content. Raising the ceiling for pathological long/small-chunk assets is a
/// per-export-budget change (with its own allocation-bomb analysis), deferred.
#[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)] // 256 fits i32
const MAX_STREAMED_AUDIO_CHUNKS: i32 = MAX_BULK_DATA_RECORDS_PER_EXPORT as i32;

/// `EStreamedAudioChunk::HasSeekOffset` (bit 1) — when set in a chunk's `Flags`,
/// the chunk carries a trailing `SeekOffsetInAudioFrames` `u32` (CUE4Parse
/// `FStreamedAudioChunk`). The other bits (`IsCooked` 1<<0, `IsInlined` 1<<2)
/// don't gate a paksmith read.
const STREAMED_AUDIO_CHUNK_HAS_SEEK_OFFSET: u32 = 1 << 1;

/// The parsed platform-data segment (segment 3). The `FByteBulkData` records are
/// the non-streaming cooked `FFormatContainer` buffers (with `format_keys`,
/// positionally aligned), the streaming chunk buffers (with `streamed`), or the
/// single non-cooked `RawData` record (no keys, no `streamed`) — never a mix.
/// `guid` (the `CompressedDataGuid`) is read on every branch.
#[derive(Default, Debug)]
struct PlatformData {
    format_keys: Vec<Arc<str>>,
    streamed: Option<StreamedAudioData>,
    guid: FGuid,
    bulk: Vec<FByteBulkData>,
}

/// Parse a `USoundWave` export payload into [`SoundWaveData`] plus its
/// `FByteBulkData` records.
///
/// The returned `Vec<FByteBulkData>` carries the platform-data buffer headers in
/// wire order — the non-streaming `FFormatContainer` buffers (cooked, aligned
/// with [`SoundWaveData::compressed_format_keys`]), the single `RawData` record
/// (non-cooked), or the streaming `FStreamedAudioPlatformData` chunk buffers
/// (aligned with the [`SoundWaveData::streamed`] chunks) — never a mix — for lazy
/// `.ubulk` resolution by the package, the same contract as the texture readers.
/// It is empty only when the asset carries no buffers (e.g. a cooked
/// `FFormatContainer` with zero formats, or a `streaming && !cooked` asset whose
/// platform data is just the GUID).
///
/// # Errors
/// - Any tagged-property fault from the nested
///   [`read_properties`](crate::asset::property::read_properties) read.
/// - [`AssetParseFault::UnexpectedEof`] on a short read of the `Flags` header,
///   the version-conditional `DummyCompressionName`, or the platform-data
///   segment.
/// - [`AssetParseFault::NegativeValue`] / [`AssetParseFault::BoundsExceeded`]
///   on a bad format / chunk count, or any `FName` / `FByteBulkData` fault.
pub(crate) fn read_from(
    payload: &[u8],
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<(SoundWaveData, Vec<FByteBulkData>)> {
    let mut cur = Cursor::new(payload);
    let total_len = payload.len() as u64;

    // Segment 1a: the USoundBase tagged-property stream, None-terminated, then
    // the `UObject::Serialize` object-GUID tail (bSerializeGuid + optional FGuid)
    // that precedes the USoundWave class-specific fields.
    // UE5 >= 1011: per-object serialization-control byte precedes the
    // export root's tagged stream (#643).
    crate::asset::property::read_class_serialization_control(&mut cur, ctx, asset_path)?;
    let properties = read_properties(&mut cur, ctx, 0, total_len, asset_path)?;
    let _object_guid = read_object_guid_tail(&mut cur, total_len, asset_path)?;

    // `bStreaming` is resolved from the version-table default + the tagged
    // properties — no binary read — and is evaluated BEFORE `Flags` per the
    // oracle's Deserialize order.
    let streaming = resolve_streaming(&properties, ctx.version);

    // Segment 1b: the `Flags` u32. `bCooked` is bit 0.
    let flags = cur
        .read_u32::<LittleEndian>()
        .map_err(|_| eof(asset_path, AssetWireField::SoundWaveFlags))?;
    let cooked = flags & SOUND_WAVE_COOKED_FLAG != 0;

    // The version-conditional `DummyCompressionName` `FName` (discarded).
    maybe_skip_dummy_compression_name(&mut cur, ctx, asset_path)?;

    // The oracle reads UE 5.4+ cue points (`FStructFallback[]`) here when
    // cooked — but they require object version 1012 (UE 5.4), above paksmith's
    // `FIRST_UNSUPPORTED_UE5_VERSION` (1011) `FPropertyTag` ceiling, so no asset
    // paksmith parses carries them. Platform data therefore follows
    // `DummyCompressionName` directly.
    //
    // Segment 3: platform data, branched on the resolved `streaming` per the
    // oracle's `SerializePlatformData` (see [`read_platform_data`]). The resolved
    // `streaming` is a heuristic (version default + tags) that can be wrong, so
    // the oracle wraps the parse in a try/catch streaming-flip retry: on failure
    // it rewinds, flips `bStreaming`, and re-parses the opposite branch (3f-5).
    let saved = cur.position();
    let mut effective_streaming = streaming;
    let platform = match read_platform_data(&mut cur, ctx, streaming, cooked, total_len, asset_path)
    {
        Ok(platform) => platform,
        Err(_first) => {
            // Streaming-flip retry. The reader returns a fresh `PlatformData` by
            // value, so the failed attempt's partial state (incl. its `bulk`
            // Vec) is dropped here — no explicit field reset needed (vs the
            // oracle nulling its in-place fields). A second failure propagates
            // (→ `Asset::Generic`).
            //
            // Unconditional (matching the oracle), now that both branches are
            // real reads in every `(streaming, cooked)` combo — `FFormatContainer`
            // / `RawData` (non-streaming) and `FStreamedAudioPlatformData` /
            // GUID-only (streaming). (3f-5 gated this on `cooked` while `RawData`
            // was a no-op that would false-recover; the RawData path removed that
            // gate.)
            cur.set_position(saved);
            effective_streaming = !streaming;
            read_platform_data(
                &mut cur,
                ctx,
                effective_streaming,
                cooked,
                total_len,
                asset_path,
            )?
        }
    };

    Ok((
        SoundWaveData {
            properties: PropertyBag::Tree { properties },
            cooked,
            streaming: effective_streaming,
            compressed_format_keys: platform.format_keys,
            compressed_data_guid: platform.guid,
            streamed: platform.streamed,
        },
        platform.bulk,
    ))
}

/// Read the platform-data segment (segment 3) for the given resolved
/// `streaming` / `cooked`, per the oracle's `SerializePlatformData` branch:
/// `!streaming` → `FFormatContainer` (cooked) or a single `RawData`
/// `FByteBulkData` (non-cooked), then `CompressedDataGuid`; `streaming` →
/// `CompressedDataGuid` + (when `cooked`) `FStreamedAudioPlatformData`. Every
/// `(streaming, cooked)` combo is a real read. Driven twice (with flipped
/// `streaming`) by the [`read_from`] streaming-flip retry.
fn read_platform_data(
    cur: &mut Cursor<&[u8]>,
    ctx: &AssetContext,
    streaming: bool,
    cooked: bool,
    total_len: u64,
    asset_path: &str,
) -> crate::Result<PlatformData> {
    if streaming {
        read_streaming_platform_data(cur, ctx, cooked, total_len, asset_path)
    } else {
        read_nonstreaming_platform_data(cur, ctx, cooked, total_len, asset_path)
    }
}

/// Read the non-streaming platform-data segment per CUE4Parse
/// `USoundWave.SerializePlatformData` (the `!bStreaming` branch): when `cooked`,
/// the `FFormatContainer` (`i32 numFormats`, then `numFormats` `(FName key,
/// FByteBulkData value)` pairs); when **not** cooked, a single `RawData`
/// `FByteBulkData` (the uncompressed editor PCM). Both are followed by the
/// 16-byte `CompressedDataGuid`.
///
/// Cooked returns the per-codec keys (wire order) + the `FByteBulkData` records
/// (positionally aligned); the keys are **resolved** against the name table
/// because they identify each buffer's codec. The count is capped
/// ([`MAX_SOUND_FORMATS`]) and the records grow as read. The non-cooked
/// `RawData` path returns one record in `bulk` with no keys — disambiguated by
/// `!cooked && !streaming` (paksmith targets cooked content, so this is the edge
/// path).
///
/// **Bulk-payload placement.** Each `FByteBulkData` value is read by
/// [`FByteBulkData::read_from`], which advances the cursor past an in-stream
/// inline payload (`ForceInlinePayload` / exactly-`LazyLoadable` / no-flags
/// records) exactly as CUE4Parse's `TBulkData` does, and leaves the cursor at
/// the header's end for `PayloadAtEndOfFile` / separate-file records (the cooked
/// norm — payload resolved later by `OffsetInFile`). Either way the next format
/// key and the trailing `CompressedDataGuid` read at the right offset.
///
/// # Errors
/// [`AssetParseFault::NegativeValue`] / [`AssetParseFault::BoundsExceeded`] on a
/// bad format count; [`AssetParseFault::UnexpectedEof`] on the GUID; any `FName`
/// or `FByteBulkData` fault.
fn read_nonstreaming_platform_data(
    cur: &mut Cursor<&[u8]>,
    ctx: &AssetContext,
    cooked: bool,
    total_len: u64,
    asset_path: &str,
) -> crate::Result<PlatformData> {
    let mut keys: Vec<Arc<str>> = Vec::new();
    let mut bulk: Vec<FByteBulkData> = Vec::new();
    if cooked {
        // `FFormatContainer`: numFormats × (FName key, FByteBulkData value).
        let num_formats = read_capped_count(
            cur,
            asset_path,
            AssetWireField::SoundWaveFormatCount,
            MAX_SOUND_FORMATS,
        )?;
        for _ in 0..num_formats {
            keys.push(read_fname_pair(
                cur,
                ctx,
                asset_path,
                AssetWireField::SoundWaveFormatKey,
            )?);
            bulk.push(FByteBulkData::read_from_ctx(cur, ctx, asset_path)?);
        }
    } else {
        // `RawData`: a single uncompressed `FByteBulkData` (no codec key).
        bulk.push(FByteBulkData::read_from_ctx(cur, ctx, asset_path)?);
    }
    debug_assert!(cur.position() <= total_len);

    let guid = FGuid::read_from(cur)
        .map_err(|_| eof(asset_path, AssetWireField::SoundWaveCompressedDataGuid))?;
    Ok(PlatformData {
        format_keys: keys,
        guid,
        bulk,
        streamed: None,
    })
}

/// Read the streaming platform-data segment per CUE4Parse
/// `USoundWave.SerializePlatformData` (the `bStreaming` branch): the 16-byte
/// `CompressedDataGuid` first, then — when `cooked` — the
/// `FStreamedAudioPlatformData` (`i32 NumChunks`, the `AudioFormat` `FName`, and
/// `NumChunks` `FStreamedAudioChunk` records). A `streaming && !cooked` asset
/// carries only the GUID.
///
/// Each chunk is `Flags` `u32` + an `FByteBulkData` + `DataSize` `i32` +
/// `AudioDataSize` `i32` + (when `Flags & HasSeekOffset`) a
/// `SeekOffsetInAudioFrames` `u32`. The chunk buffers grow as read (count capped
/// by [`MAX_STREAMED_AUDIO_CHUNKS`], records EOF-bounded) and are returned
/// positionally aligned with the chunk metadata. `AudioFormat` is resolved
/// against the name table (the shared codec identity). The `DataSize` /
/// `AudioDataSize` are stored unvalidated — the oracle does not check them, and
/// the decode-time `MAX_AUDIO_DECODED_BYTES` clamp is a later 3f decoder milestone's job.
///
/// # Errors
/// [`AssetParseFault::NegativeValue`] / [`AssetParseFault::BoundsExceeded`] on a
/// bad chunk count; [`AssetParseFault::UnexpectedEof`] on the GUID, the
/// `AudioFormat`, or any chunk field; any `FName` / `FByteBulkData` fault.
fn read_streaming_platform_data(
    cur: &mut Cursor<&[u8]>,
    ctx: &AssetContext,
    cooked: bool,
    total_len: u64,
    asset_path: &str,
) -> crate::Result<PlatformData> {
    // The streaming branch reads the GUID first (before the platform data).
    let guid = FGuid::read_from(cur)
        .map_err(|_| eof(asset_path, AssetWireField::SoundWaveCompressedDataGuid))?;
    if !cooked {
        // `streaming && !cooked`: the oracle's `if (bCooked)` gates the platform
        // data, so only the GUID is on the wire here.
        return Ok(PlatformData {
            guid,
            ..PlatformData::default()
        });
    }

    // `FStreamedAudioPlatformData`: NumChunks + AudioFormat + chunk records.
    let num_chunks = read_capped_count(
        cur,
        asset_path,
        AssetWireField::SoundWaveChunkCount,
        MAX_STREAMED_AUDIO_CHUNKS,
    )?;
    let audio_format = read_fname_pair(cur, ctx, asset_path, AssetWireField::SoundWaveAudioFormat)?;

    let mut chunks: Vec<StreamedAudioChunk> = Vec::new();
    let mut bulk: Vec<FByteBulkData> = Vec::new();
    for _ in 0..num_chunks {
        let flags = cur
            .read_u32::<LittleEndian>()
            .map_err(|_| eof(asset_path, AssetWireField::SoundWaveChunk))?;
        bulk.push(FByteBulkData::read_from_ctx(cur, ctx, asset_path)?);
        let data_size = read_chunk_i32(cur, asset_path)?;
        let audio_data_size = read_chunk_i32(cur, asset_path)?;
        let seek_offset_in_audio_frames = if flags & STREAMED_AUDIO_CHUNK_HAS_SEEK_OFFSET != 0 {
            Some(
                cur.read_u32::<LittleEndian>()
                    .map_err(|_| eof(asset_path, AssetWireField::SoundWaveChunk))?,
            )
        } else {
            None
        };
        chunks.push(StreamedAudioChunk {
            data_size,
            audio_data_size,
            seek_offset_in_audio_frames,
        });
    }
    debug_assert!(cur.position() <= total_len);

    Ok(PlatformData {
        streamed: Some(StreamedAudioData {
            audio_format,
            chunks,
        }),
        guid,
        bulk,
        format_keys: Vec::new(),
    })
}

/// Read one `FStreamedAudioChunk` `i32` body field (`DataSize` / `AudioDataSize`),
/// tagging EOF as [`AssetWireField::SoundWaveChunk`].
fn read_chunk_i32(cur: &mut Cursor<&[u8]>, asset_path: &str) -> crate::Result<i32> {
    cur.read_i32::<LittleEndian>()
        .map_err(|_| eof(asset_path, AssetWireField::SoundWaveChunk))
}

/// Read a counted-array `i32` length prefix, rejecting a negative
/// ([`AssetParseFault::NegativeValue`]) or over-`limit`
/// ([`AssetParseFault::BoundsExceeded`]) count before any element is read. EOF
/// and both faults are tagged `field`. Shared by the format (3f-3) and chunk
/// (3f-4) array readers.
fn read_capped_count(
    cur: &mut Cursor<&[u8]>,
    asset_path: &str,
    field: AssetWireField,
    limit: i32,
) -> crate::Result<i32> {
    let count = cur
        .read_i32::<LittleEndian>()
        .map_err(|_| eof(asset_path, field))?;
    if count < 0 {
        return Err(negative(asset_path, field, count));
    }
    if count > limit {
        return Err(bounds(asset_path, field, count, limit));
    }
    Ok(count)
}

/// Resolve `bStreaming` per CUE4Parse `USoundWave.Deserialize`:
/// 1. **Default** — `Ar.Versions["SoundWave.UseAudioStreaming"]`, whose stock
///    value is `Ar.Game >= GAME_UE4_25` ([`AssetVersion::is_ue4_25_or_later`]).
/// 2. A tagged **`bStreaming`** `BoolProperty` **wins** (`LoadingBehavior` is
///    then NOT consulted).
/// 3. Else a tagged **`LoadingBehavior`** `NameProperty`: streaming unless the
///    name is `None` or `ESoundWaveLoadingBehavior::ForceInline`.
///
/// Steps 2 and 3 are mutually exclusive. The per-game `OverrideUseAudioStreaming`
/// refinement (and the `GAME_Stray` `RetainOnLoad` clamp) are Phase-5
/// game-profile concerns, deferred. A wrong initial guess is corrected by the
/// 3f-5 streaming-flip retry once the platform-data parse runs.
fn resolve_streaming(properties: &[Property], version: AssetVersion) -> bool {
    if let Some(streaming) = bool_property(properties, "bStreaming") {
        return streaming;
    }
    if let Some(loading_behavior) = name_property(properties, "LoadingBehavior") {
        return loading_behavior != "None"
            && loading_behavior != "ESoundWaveLoadingBehavior::ForceInline";
    }
    version.is_ue4_25_or_later()
}

/// Consume (and discard) the `USoundWave` `DummyCompressionName` `FName` when
/// the package's `FFrameworkObjectVersion` predates
/// `RemoveSoundWaveCompressionName` (CUE4Parse `USoundWave.Deserialize`:
/// `Ar.Ver >= SOUND_COMPRESSION_TYPE_ADDED && FFrameworkObjectVersion.Get(Ar) <
/// RemoveSoundWaveCompressionName`).
///
/// The lower bound (`SOUND_COMPRESSION_TYPE_ADDED`, UE 4.12) is unconditionally
/// satisfied at paksmith's `VER_UE4_NAME_HASHES_SERIALIZED` (504 / UE 4.13)
/// floor — it sits earlier in the append-only UE4 object-version enum — so only
/// the framework-version upper bound is a live gate.
///
/// The name is **read-and-discarded**: the 8 wire bytes (two `i32`s — name
/// index + number) must be consumed so the platform-data reader (3f-3) starts
/// at the right offset, but the value is never resolved against the name table
/// (a discarded name must not false-reject a valid asset on a bounds check, and
/// [`read_fname_pair`](crate::asset::property) would resolve it).
///
/// **Absent `FFrameworkObjectVersion` ⇒ field not present.** CUE4Parse's
/// `FFrameworkObjectVersion.Get` falls back to `LatestVersion` (≥
/// `RemoveSoundWaveCompressionName`) for a package carrying no framework stamp
/// that matches no game profile, so paksmith — which has no game profiles —
/// treats an absent stamp as modern and skips the field. A genuinely
/// pre-removal asset that omits the explicit stamp would desync here; that
/// game-profile-dependent case is **UNVERIFIED** (no fixture) and deferred to
/// Phase 5.
///
/// # Errors
/// [`AssetParseFault::UnexpectedEof`] on a short read of the discarded `FName`.
fn maybe_skip_dummy_compression_name(
    cur: &mut Cursor<&[u8]>,
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<()> {
    let has_dummy_name = ctx
        .custom_versions
        .version_for(FRAMEWORK_OBJECT_VERSION_GUID)
        .is_some_and(|v| v < FRAMEWORK_OBJECT_VERSION_REMOVE_SOUND_WAVE_COMPRESSION_NAME);
    if has_dummy_name {
        // A discarded `FName` on the wire is two LE `i32`s (name index +
        // number). Consume both, do NOT resolve.
        let on_eof = |_| eof(asset_path, AssetWireField::SoundWaveDummyCompressionName);
        let _name_index = cur.read_i32::<LittleEndian>().map_err(on_eof)?;
        let _name_number = cur.read_i32::<LittleEndian>().map_err(on_eof)?;
    }
    Ok(())
}

/// The scalar (`array_index == 0`) tagged property named `name`, if present.
pub(crate) fn scalar_property<'a>(properties: &'a [Property], name: &str) -> Option<&'a Property> {
    properties
        .iter()
        .find(|p| p.name() == name && p.array_index == 0)
}

/// The value of a scalar `BoolProperty` named `name`, if present.
fn bool_property(properties: &[Property], name: &str) -> Option<bool> {
    scalar_property(properties, name).and_then(|p| match p.value {
        PropertyValue::Bool(b) => Some(b),
        _ => None,
    })
}

/// The resolved name of a scalar `NameProperty` named `name`, if present.
fn name_property<'a>(properties: &'a [Property], name: &str) -> Option<&'a str> {
    scalar_property(properties, name).and_then(|p| match &p.value {
        PropertyValue::Name(n) => Some(n.as_ref()),
        _ => None,
    })
}

/// [`crate::asset::exports::dispatch::TypedReaderFn`] entry for the `SoundWave`
/// class. The returned records are the platform-data buffers — `FFormatContainer`
/// codec buffers (cooked non-streaming), the single `RawData` record (non-cooked
/// non-streaming), or `FStreamedAudioPlatformData` chunk buffers (streaming).
pub(crate) fn read_typed(
    payload: &[u8],
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<(Asset, Vec<FByteBulkData>)> {
    let (data, bulk) = read_from(payload, ctx, asset_path)?;
    Ok((Asset::SoundWave(data), bulk))
}

/// Wrap a parse `fault` with the asset path (the shared `AssetParse`
/// constructor for this reader's error helpers).
fn fault(asset_path: &str, fault: AssetParseFault) -> PaksmithError {
    PaksmithError::AssetParse {
        asset_path: asset_path.to_string(),
        fault,
    }
}

fn eof(asset_path: &str, field: AssetWireField) -> PaksmithError {
    fault(asset_path, AssetParseFault::UnexpectedEof { field })
}

fn negative(asset_path: &str, field: AssetWireField, value: i32) -> PaksmithError {
    fault(
        asset_path,
        AssetParseFault::NegativeValue {
            field,
            value: i64::from(value),
        },
    )
}

// `value` is checked `> limit` (hence `>= 0`) before this call, and the caps
// passed as `limit` are positive consts, so both `as u64` casts are exact.
#[allow(clippy::cast_sign_loss)]
fn bounds(asset_path: &str, field: AssetWireField, value: i32, limit: i32) -> PaksmithError {
    fault(
        asset_path,
        AssetParseFault::BoundsExceeded {
            field,
            value: value as u64,
            limit: limit as u64,
            unit: BoundsUnit::Items,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::property::test_utils::{
        make_ctx,
        make_ctx_with_version,
        write_fname,
        write_int_property,
        // `none` ends a top-level export body: the `None` tag + the object-GUID
        // tail (bSerializeGuid = 0) the reader now consumes after the properties.
        write_object_end as none,
    };

    // --- wire-byte builders (explicit so the fixture bytes are auditable
    // against the FPropertyTag layout, not circular with the parser) ---

    /// A `BoolProperty` tag: its value lives in the tag (a `u8` `bool_val`),
    /// the body is empty (`Size == 0`).
    fn write_bool_property(buf: &mut Vec<u8>, name_idx: i32, type_idx: i32, value: bool) {
        write_fname(buf, name_idx, 0); // Name
        write_fname(buf, type_idx, 0); // Type ("BoolProperty")
        buf.extend_from_slice(&0i32.to_le_bytes()); // Size (empty body)
        buf.extend_from_slice(&0i32.to_le_bytes()); // ArrayIndex
        buf.push(u8::from(value)); // bool_val
        buf.push(0u8); // HasPropertyGuid
    }

    /// A `NameProperty` tag: an 8-byte `FName` body.
    fn write_name_property(buf: &mut Vec<u8>, name_idx: i32, type_idx: i32, value_idx: i32) {
        write_fname(buf, name_idx, 0); // Name
        write_fname(buf, type_idx, 0); // Type ("NameProperty")
        buf.extend_from_slice(&8i32.to_le_bytes()); // Size (one FName)
        buf.extend_from_slice(&0i32.to_le_bytes()); // ArrayIndex
        buf.push(0u8); // HasPropertyGuid
        write_fname(buf, value_idx, 0); // body: the name value
    }

    fn write_flags(buf: &mut Vec<u8>, flags: u32) {
        buf.extend_from_slice(&flags.to_le_bytes());
    }

    /// Append an empty non-streaming platform-data segment: `numFormats = 0`
    /// then a 16-byte zero `CompressedDataGuid`. Lets header-focused tests parse
    /// cleanly through `read_from` on the `!streaming && cooked` branch (and
    /// trails harmlessly within the payload otherwise).
    fn write_empty_platform_data(buf: &mut Vec<u8>) {
        write_format_container(buf, &[]); // numFormats = 0
        buf.extend_from_slice(&[0u8; 16]); // CompressedDataGuid
    }

    /// Append one `FStreamedAudioChunk`: `Flags` u32, an inline `FByteBulkData`
    /// (`PayloadAtEndOfFile`), `DataSize`, `AudioDataSize`, and — when `seek` is
    /// `Some` (caller must also set `Flags & HasSeekOffset`) — a trailing
    /// `SeekOffsetInAudioFrames` u32.
    fn write_streamed_chunk(
        buf: &mut Vec<u8>,
        flags: u32,
        size_on_disk: u32,
        data_size: i32,
        audio_data_size: i32,
        seek: Option<u32>,
    ) {
        buf.extend_from_slice(&flags.to_le_bytes());
        write_byte_bulk_data(buf, size_on_disk, 0);
        buf.extend_from_slice(&data_size.to_le_bytes());
        buf.extend_from_slice(&audio_data_size.to_le_bytes());
        if let Some(off) = seek {
            buf.extend_from_slice(&off.to_le_bytes());
        }
    }

    /// Parse `bytes` and return just the [`SoundWaveData`] (dropping the
    /// bulk-record list) — for header-focused tests that assert on the parsed
    /// fields rather than the returned buffers.
    fn parse_data(bytes: &[u8], ctx: &AssetContext) -> SoundWaveData {
        read_from(bytes, ctx, "s").expect("parse").0
    }

    /// Run the non-streaming platform-data reader (cooked `FFormatContainer`
    /// branch) over just `platform` (the `FFormatContainer` + GUID bytes) — for
    /// tests pinning the reader's own error tagging in isolation from the
    /// `read_from` streaming-flip retry.
    fn read_nonstreaming(ctx: &AssetContext, platform: &[u8]) -> crate::Result<PlatformData> {
        let mut cur = Cursor::new(platform);
        let len = u64::try_from(platform.len()).unwrap();
        read_nonstreaming_platform_data(&mut cur, ctx, true, len, "s")
    }

    /// Run the non-streaming RawData reader (`!cooked` branch) over just
    /// `platform` (a single `FByteBulkData` + GUID).
    fn read_rawdata(ctx: &AssetContext, platform: &[u8]) -> crate::Result<PlatformData> {
        let mut cur = Cursor::new(platform);
        let len = u64::try_from(platform.len()).unwrap();
        read_nonstreaming_platform_data(&mut cur, ctx, false, len, "s")
    }

    /// Run the streaming platform-data reader (cooked) over just `platform` (the
    /// GUID + `FStreamedAudioPlatformData` bytes) — likewise retry-isolated.
    fn read_streaming(ctx: &AssetContext, platform: &[u8]) -> crate::Result<PlatformData> {
        let mut cur = Cursor::new(platform);
        let len = u64::try_from(platform.len()).unwrap();
        read_streaming_platform_data(&mut cur, ctx, true, len, "s")
    }

    /// Resolve `bStreaming` from `None`-terminated tagged-property wire bytes +
    /// `version`, calling `resolve_streaming` DIRECTLY. Resolution tests must
    /// bypass `read_from` here: at `read_from` level the streaming-flip retry can
    /// recover a mis-resolved guess, masking the resolution logic the test pins.
    fn resolve_streaming_from(ctx: &AssetContext, props: &[u8], version: AssetVersion) -> bool {
        let mut cur = Cursor::new(props);
        let len = u64::try_from(props.len()).unwrap();
        let parsed = read_properties(&mut cur, ctx, 0, len, "s").expect("props");
        resolve_streaming(&parsed, version)
    }

    /// Assert `data` carries exactly the single `NumChannels` tagged property
    /// (the segment-1a survivor in the shared `IntProperty` fixtures).
    fn assert_single_numchannels(data: &SoundWaveData) {
        let PropertyBag::Tree { properties } = &data.properties else {
            panic!("expected a Tree bag");
        };
        assert_eq!(properties.len(), 1);
        assert_eq!(properties[0].name(), "NumChannels");
    }

    #[test]
    fn captures_tagged_properties_then_flags_bcooked() {
        // Segment 1a: one IntProperty; segment 1b: Flags with CookedFlag set.
        let ctx = make_ctx(&["None", "NumChannels", "IntProperty"]);
        let mut bytes = Vec::new();
        write_int_property(&mut bytes, 1, 2, 2);
        none(&mut bytes);
        write_flags(&mut bytes, 0x0000_0001); // CookedFlag
        write_empty_platform_data(&mut bytes); // !streaming && cooked → parsed

        let data = parse_data(&bytes, &ctx);
        assert!(data.cooked);
        assert_single_numchannels(&data);
    }

    #[test]
    fn bcooked_is_bit_zero_of_flags() {
        let ctx = make_ctx(&["None"]);
        // Bit 0 clear (e.g. only HasOwnerLoadingBehaviorFlag set) → not cooked
        // (the `!streaming && !cooked` RawData branch then reads its tail).
        let mut not_cooked = Vec::new();
        none(&mut not_cooked);
        write_flags(&mut not_cooked, 0b0000_0010);
        write_rawdata_platform_data(&mut not_cooked, 8, [0u8; 16]);
        assert!(!parse_data(&not_cooked, &ctx).cooked);
        // Bit 0 set among other bits → cooked.
        let mut cooked = Vec::new();
        none(&mut cooked);
        write_flags(&mut cooked, 0b0000_0011);
        write_empty_platform_data(&mut cooked);
        assert!(parse_data(&cooked, &ctx).cooked);
    }

    // Resolution tests call `resolve_streaming` directly (via
    // `resolve_streaming_from`): the `read_from` retry would recover a
    // mis-resolved guess and mask the resolution logic these pin.

    #[test]
    fn streaming_default_follows_ue4_25_proxy() {
        // No bStreaming / LoadingBehavior tags → the version-table default.
        let ctx = make_ctx(&["None"]);
        let mut props = Vec::new();
        none(&mut props);
        let ver = |ue4, ue5| make_ctx_with_version(ue4, ue5).version;
        // UE5 (and UE4.25+) → default true.
        assert!(resolve_streaming_from(&ctx, &props, ver(522, Some(1009))));
        assert!(resolve_streaming_from(&ctx, &props, ver(518, None)));
        // UE4.20 (pre-4.25) → default false.
        assert!(!resolve_streaming_from(&ctx, &props, ver(516, None)));
    }

    #[test]
    fn tagged_bstreaming_wins_over_loading_behavior_and_version_default() {
        // bStreaming=false, with BOTH a LoadingBehavior that would yield
        // streaming=true AND a UE5 version whose default is true. bStreaming
        // must win over both (LoadingBehavior ignored, default ignored).
        let ctx = make_ctx(&[
            "None",
            "bStreaming",
            "BoolProperty",
            "LoadingBehavior",
            "NameProperty",
            "ESoundWaveLoadingBehavior::Inline",
        ]);
        let mut props = Vec::new();
        write_bool_property(&mut props, 1, 2, false); // bStreaming = false
        write_name_property(&mut props, 3, 4, 5); // LoadingBehavior = Inline
        none(&mut props);
        let ue5 = make_ctx_with_version(522, Some(1009)).version; // default true
        assert!(!resolve_streaming_from(&ctx, &props, ue5));
    }

    #[test]
    fn streaming_lookup_respects_name_and_array_index() {
        // `resolve_streaming` must find the scalar `bStreaming` BY NAME, not the
        // first array_index-0 property — pins `scalar_property`'s
        // `name == ... && array_index == 0` against `&&`→`||`. A decoy
        // BoolProperty (different name, array_index 0, value true) precedes the
        // real `bStreaming = false`.
        let ctx = make_ctx(&["None", "Decoy", "BoolProperty", "bStreaming"]);
        let mut props = Vec::new();
        write_bool_property(&mut props, 1, 2, true); // Decoy (array_index 0) = true
        write_bool_property(&mut props, 3, 2, false); // real bStreaming = false
        none(&mut props);
        // `&&` finds bStreaming=false → not streaming. `||` would match the
        // array_index-0 Decoy first (→ true) → wrong.
        assert!(!resolve_streaming_from(
            &ctx,
            &props,
            AssetVersion::default()
        ));
    }

    #[test]
    fn loading_behavior_resolves_streaming_when_no_bstreaming_tag() {
        // Pins the `!= "None" && != "ForceInline"` rule against `&&`→`||`.
        let names = &[
            "None",
            "LoadingBehavior",
            "NameProperty",
            "ESoundWaveLoadingBehavior::ForceInline",
            "ESoundWaveLoadingBehavior::PrimeOnLoad",
        ];
        let ctx = make_ctx(names);
        let resolve = |value_idx: i32| {
            let mut props = Vec::new();
            write_name_property(&mut props, 1, 2, value_idx);
            none(&mut props);
            resolve_streaming_from(&ctx, &props, AssetVersion::default())
        };
        // ForceInline → NOT streaming.
        assert!(!resolve(3));
        // Any other behavior → streaming.
        assert!(resolve(4));
        // The literal "None" name → NOT streaming (IsNone; `||` would yield true).
        assert!(!resolve(0));
    }

    #[test]
    fn read_typed_wraps_the_sound_wave_variant() {
        let ctx = make_ctx(&["None"]);
        let mut bytes = Vec::new();
        none(&mut bytes);
        write_flags(&mut bytes, 0x1);
        write_empty_platform_data(&mut bytes); // 0 formats → still no bulk records

        let (asset, bulk) = read_typed(&bytes, &ctx, "sound.uasset").expect("parse");
        assert!(matches!(asset, Asset::SoundWave(_)));
        assert!(bulk.is_empty());
    }

    #[test]
    fn missing_flags_is_unexpected_eof() {
        // Tagged-property None terminator but no Flags → short read.
        let ctx = make_ctx(&["None"]);
        let mut bytes = Vec::new();
        none(&mut bytes);
        match read_from(&bytes, &ctx, "sound.uasset") {
            Err(PaksmithError::AssetParse {
                fault: AssetParseFault::UnexpectedEof { field },
                ..
            }) => assert_eq!(field, AssetWireField::SoundWaveFlags),
            other => panic!("expected UnexpectedEof(SoundWaveFlags), got {other:?}"),
        }
    }

    // --- DummyCompressionName (FFrameworkObjectVersion-gated, discarded) ---

    /// The raw 16 GUID bytes of `FFrameworkObjectVersion`, authored
    /// independently of [`FRAMEWORK_OBJECT_VERSION_GUID`] so a byte-order error
    /// in the constant is caught: the helper looks the constant up by GUID, so a
    /// container built from these literal bytes only matches if the constant's
    /// bytes equal the real UE GUID.
    const FRAMEWORK_GUID_RAW: [u8; 16] = [
        0x3F, 0x74, 0xFC, 0xCF, // 0xCFFC743F LE
        0x80, 0x44, 0xB0, 0x43, // 0x43B04480 LE
        0xDF, 0x14, 0x91, 0x93, // 0x939114DF LE
        0x73, 0x20, 0x1D, 0x17, // 0x171D2073 LE
    ];

    fn ctx_with_framework_guid(names: &[&str], guid: FGuid, version: i32) -> AssetContext {
        use crate::asset::custom_version::{CustomVersion, CustomVersionContainer};
        use std::sync::Arc;
        let mut ctx = make_ctx(names);
        ctx.custom_versions = Arc::new(CustomVersionContainer {
            versions: vec![CustomVersion { guid, version }],
        });
        ctx
    }

    /// Run the helper over `payload` and return how far the cursor advanced.
    fn dummy_skip_advance(ctx: &AssetContext, payload: &[u8]) -> u64 {
        let mut cur = Cursor::new(payload);
        maybe_skip_dummy_compression_name(&mut cur, ctx, "s").expect("skip");
        cur.position()
    }

    #[test]
    fn dummy_name_consumed_below_remove_version_boundary() {
        let payload = [0xAAu8; 8]; // an FName's worth of bytes
        // v = 11 (< RemoveSoundWaveCompressionName = 12) → consume the 8 bytes.
        let below = ctx_with_framework_guid(&["None"], FRAMEWORK_OBJECT_VERSION_GUID, 11);
        assert_eq!(dummy_skip_advance(&below, &payload), 8);
        // v = 12 (== RemoveSoundWaveCompressionName) → NOT consumed. Pins the
        // strict `<` boundary against `<=`.
        let at = ctx_with_framework_guid(&["None"], FRAMEWORK_OBJECT_VERSION_GUID, 12);
        assert_eq!(dummy_skip_advance(&at, &payload), 0);
    }

    #[test]
    fn dummy_name_skipped_when_framework_version_absent() {
        // No FFrameworkObjectVersion stamp → CUE4Parse Get() defaults to
        // LatestVersion → field treated as removed. make_ctx's container is
        // empty, so `version_for` returns None and `is_some_and` is false.
        let ctx = make_ctx(&["None"]);
        assert_eq!(dummy_skip_advance(&ctx, &[0xAAu8; 8]), 0);
    }

    #[test]
    fn dummy_name_gate_matches_framework_guid_by_raw_bytes() {
        let payload = [0xAAu8; 8];
        // Container built from the raw UE GUID bytes (independent of the
        // constant) → must match → consume.
        let real = ctx_with_framework_guid(&["None"], FGuid::from_bytes(FRAMEWORK_GUID_RAW), 11);
        assert_eq!(dummy_skip_advance(&real, &payload), 8, "real GUID matches");
        // A decoy GUID must NOT match → no consume.
        let decoy = ctx_with_framework_guid(&["None"], FGuid::from_bytes([0x01; 16]), 11);
        assert_eq!(
            dummy_skip_advance(&decoy, &payload),
            0,
            "decoy GUID must not match"
        );
    }

    #[test]
    fn read_from_errors_on_truncated_dummy_name() {
        // Gate fires (v = 11) but only 4 of the 8 FName bytes follow Flags →
        // EOF on the second i32. Pins that `read_from` actually CALLS the
        // consume: a deleted call would leave the 4 bytes unread and return Ok.
        let ctx = ctx_with_framework_guid(&["None"], FRAMEWORK_OBJECT_VERSION_GUID, 11);
        let mut bytes = Vec::new();
        none(&mut bytes);
        write_flags(&mut bytes, 0x1);
        bytes.extend_from_slice(&[0u8; 4]); // only half an FName
        match read_from(&bytes, &ctx, "sound.uasset") {
            Err(PaksmithError::AssetParse {
                fault: AssetParseFault::UnexpectedEof { field },
                ..
            }) => assert_eq!(field, AssetWireField::SoundWaveDummyCompressionName),
            other => panic!("expected UnexpectedEof(SoundWaveDummyCompressionName), got {other:?}"),
        }
    }

    #[test]
    fn read_from_consumes_full_dummy_name_below_boundary() {
        // Gate fires (v = 11), the full 8-byte FName is present → parse succeeds
        // and the tagged properties (read before the dummy) survive intact.
        let ctx = ctx_with_framework_guid(
            &["None", "NumChannels", "IntProperty"],
            FRAMEWORK_OBJECT_VERSION_GUID,
            11,
        );
        let mut bytes = Vec::new();
        write_int_property(&mut bytes, 1, 2, 2);
        none(&mut bytes);
        write_flags(&mut bytes, 0x1);
        bytes.extend_from_slice(&[0u8; 8]); // discarded DummyCompressionName FName
        write_empty_platform_data(&mut bytes); // !streaming && cooked → parsed

        let data = parse_data(&bytes, &ctx);
        assert!(data.cooked);
        assert_single_numchannels(&data);
    }

    // --- non-streaming platform data: FFormatContainer + CompressedDataGuid (3f-3) ---

    /// Append a minimal inline `FByteBulkData` header (20 bytes): flags
    /// `PAYLOAD_AT_END_OF_FILE | NO_OFFSET_FIXUP`, `i32` ElementCount, `u32`
    /// SizeOnDisk, `i64` OffsetInFile. No inline payload follows.
    fn write_byte_bulk_data(buf: &mut Vec<u8>, size_on_disk: u32, offset: i64) {
        buf.extend_from_slice(&0x0001_0001u32.to_le_bytes()); // flags
        buf.extend_from_slice(&i32::try_from(size_on_disk).unwrap().to_le_bytes()); // ElementCount
        buf.extend_from_slice(&size_on_disk.to_le_bytes()); // SizeOnDisk
        buf.extend_from_slice(&offset.to_le_bytes()); // OffsetInFile
    }

    /// Append a non-streaming `!cooked` RawData tail: a single `FByteBulkData`
    /// (`size_on_disk`) + a 16-byte `CompressedDataGuid`.
    fn write_rawdata_platform_data(buf: &mut Vec<u8>, size_on_disk: u32, guid: [u8; 16]) {
        write_byte_bulk_data(buf, size_on_disk, 0); // RawData FByteBulkData
        buf.extend_from_slice(&guid); // CompressedDataGuid
    }

    /// Append a `ForceInlinePayload` `FByteBulkData`: the 20-byte header then
    /// `payload` in-stream (`payload.len()` must equal `size_on_disk`). The
    /// reader must consume those bytes so a following field reads at the right
    /// offset.
    fn write_inline_byte_bulk_data(buf: &mut Vec<u8>, size_on_disk: u32, payload: &[u8]) {
        buf.extend_from_slice(&0x0000_0040u32.to_le_bytes()); // BULKDATA_ForceInlinePayload
        buf.extend_from_slice(&i32::try_from(size_on_disk).unwrap().to_le_bytes()); // ElementCount
        buf.extend_from_slice(&size_on_disk.to_le_bytes()); // SizeOnDisk
        buf.extend_from_slice(&0i64.to_le_bytes()); // OffsetInFile
        buf.extend_from_slice(payload); // inline payload bytes
    }

    /// Append an `FFormatContainer`: `i32 numFormats`, then for each
    /// `(name_idx, size_on_disk)` an `FName` key + an inline `FByteBulkData`.
    fn write_format_container(buf: &mut Vec<u8>, formats: &[(i32, u32)]) {
        buf.extend_from_slice(&i32::try_from(formats.len()).unwrap().to_le_bytes());
        for (i, &(name_idx, size)) in formats.iter().enumerate() {
            write_fname(buf, name_idx, 0);
            write_byte_bulk_data(buf, size, i64::try_from(i).unwrap() * 0x1000);
        }
    }

    /// Build a non-streaming cooked `USoundWave` payload: empty tagged-property
    /// segment, `Flags = CookedFlag` (default `make_ctx` version resolves
    /// `streaming = false`), the `FFormatContainer`, then a `CompressedDataGuid`.
    fn nonstreaming_cooked(formats: &[(i32, u32)], guid: [u8; 16]) -> Vec<u8> {
        let mut b = Vec::new();
        none(&mut b);
        write_flags(&mut b, 0x1);
        write_format_container(&mut b, formats);
        b.extend_from_slice(&guid);
        b
    }

    #[test]
    fn nonstreaming_cooked_parses_format_keys_guid_and_records() {
        let ctx = make_ctx(&["None", "OGG", "OPUS"]);
        let guid = [0x11u8; 16];
        let bytes = nonstreaming_cooked(&[(1, 100), (2, 200)], guid);

        let (data, bulk) = read_from(&bytes, &ctx, "s").expect("parse");
        assert!(!data.streaming && data.cooked);
        // Keys resolved against the name table, in wire order.
        let keys: Vec<&str> = data
            .compressed_format_keys
            .iter()
            .map(Arc::as_ref)
            .collect();
        assert_eq!(keys, ["OGG", "OPUS"]);
        // The cook GUID is captured.
        assert_eq!(data.compressed_data_guid, FGuid::from_bytes(guid));
        // Records returned positionally: `compressed_format_keys[i]` ↔ `bulk[i]`.
        assert_eq!(bulk.len(), 2);
        assert_eq!(bulk[0].size_on_disk, 100);
        assert_eq!(bulk[1].size_on_disk, 200);
    }

    // --- streaming platform data: FStreamedAudioPlatformData (3f-4) ---

    /// Build a `streaming && cooked` payload: a `bStreaming = true` tag, `Flags`,
    /// the `CompressedDataGuid`, `NumChunks`, the `AudioFormat` FName (`name_idx`),
    /// then the given chunks via [`write_streamed_chunk`] args
    /// `(flags, size_on_disk, data_size, audio_data_size, seek)`.
    fn streaming_cooked(
        name_idx: i32,
        guid: [u8; 16],
        chunks: &[(u32, u32, i32, i32, Option<u32>)],
    ) -> Vec<u8> {
        let mut b = Vec::new();
        write_bool_property(&mut b, 1, 2, true); // bStreaming = true
        none(&mut b);
        write_flags(&mut b, 0x1); // cooked
        b.extend_from_slice(&guid); // CompressedDataGuid (read first on streaming)
        b.extend_from_slice(&i32::try_from(chunks.len()).unwrap().to_le_bytes()); // NumChunks
        write_fname(&mut b, name_idx, 0); // AudioFormat
        for &(flags, size, data, audio, seek) in chunks {
            write_streamed_chunk(&mut b, flags, size, data, audio, seek);
        }
        b
    }

    #[test]
    fn streaming_cooked_parses_guid_format_and_chunks() {
        let ctx = make_ctx(&["None", "bStreaming", "BoolProperty", "OGG"]);
        let guid = [0x33u8; 16];
        // Chunk 0 sets HasSeekOffset (→ trailing seek u32); chunk 1 does not.
        let bytes = streaming_cooked(
            3,
            guid,
            &[
                (STREAMED_AUDIO_CHUNK_HAS_SEEK_OFFSET, 50, 50, 500, Some(7)),
                (0, 80, 80, 800, None),
            ],
        );
        let (data, bulk) = read_from(&bytes, &ctx, "s").expect("parse");
        assert!(data.streaming && data.cooked);
        assert_eq!(data.compressed_data_guid, FGuid::from_bytes(guid));
        assert!(data.compressed_format_keys.is_empty()); // XOR: streaming → no format keys
        let streamed = data.streamed.expect("streamed");
        assert_eq!(streamed.audio_format.as_ref(), "OGG");
        assert_eq!(streamed.chunks.len(), 2);
        assert_eq!(streamed.chunks[0].data_size, 50);
        assert_eq!(streamed.chunks[0].audio_data_size, 500);
        assert_eq!(streamed.chunks[0].seek_offset_in_audio_frames, Some(7));
        assert_eq!(streamed.chunks[1].data_size, 80);
        assert_eq!(streamed.chunks[1].audio_data_size, 800);
        assert_eq!(streamed.chunks[1].seek_offset_in_audio_frames, None);
        // Chunk buffers returned positionally (chunks[i] ↔ bulk[i]).
        assert_eq!(bulk.len(), 2);
        assert_eq!(bulk[0].size_on_disk, 50);
        assert_eq!(bulk[1].size_on_disk, 80);
    }

    #[test]
    fn streaming_noncooked_reads_guid_only() {
        // streaming && !cooked → only the GUID (the oracle's `if (bCooked)` gates
        // the platform data); no chunks, no error.
        let ctx = make_ctx(&["None", "bStreaming", "BoolProperty"]);
        let guid = [0x44u8; 16];
        let mut bytes = Vec::new();
        write_bool_property(&mut bytes, 1, 2, true); // bStreaming = true
        none(&mut bytes);
        write_flags(&mut bytes, 0b0000_0010); // cooked = false
        bytes.extend_from_slice(&guid);

        let (data, bulk) = read_from(&bytes, &ctx, "s").expect("parse");
        assert!(data.streaming && !data.cooked);
        assert_eq!(data.compressed_data_guid, FGuid::from_bytes(guid));
        assert!(data.streamed.is_none());
        assert!(bulk.is_empty());
    }

    #[test]
    fn inlined_chunk_bulk_does_not_desync() {
        // A chunk whose `FByteBulkData` is `ForceInlinePayload` with in-stream
        // bytes: the shared reader skips them so the chunk's `DataSize` and any
        // next field read at the right offset (validates the 3f-3 inline fix on
        // the streaming caller).
        let ctx = make_ctx(&["None", "bStreaming", "BoolProperty", "OGG"]);
        let mut bytes = Vec::new();
        write_bool_property(&mut bytes, 1, 2, true);
        none(&mut bytes);
        write_flags(&mut bytes, 0x1);
        bytes.extend_from_slice(&[0u8; 16]); // GUID
        bytes.extend_from_slice(&1i32.to_le_bytes()); // NumChunks = 1
        write_fname(&mut bytes, 3, 0); // AudioFormat = OGG
        bytes.extend_from_slice(&(1u32 << 2).to_le_bytes()); // EStreamedAudioChunk::IsInlined
        write_inline_byte_bulk_data(&mut bytes, 4, &[0xDE, 0xAD, 0xBE, 0xEF]);
        bytes.extend_from_slice(&111i32.to_le_bytes()); // DataSize
        bytes.extend_from_slice(&222i32.to_le_bytes()); // AudioDataSize

        let (data, bulk) = read_from(&bytes, &ctx, "s").expect("parse");
        let streamed = data.streamed.expect("streamed");
        assert_eq!(streamed.chunks.len(), 1);
        assert_eq!(streamed.chunks[0].data_size, 111); // read past the inline payload
        assert_eq!(streamed.chunks[0].audio_data_size, 222);
        assert_eq!(bulk.len(), 1);
        assert_eq!(bulk[0].size_on_disk, 4);
    }

    // These pin the streaming reader's OWN error tagging, so they call
    // `read_streaming_platform_data` directly — at `read_from` level a
    // first-attempt failure triggers the streaming-flip retry (tested
    // separately), which would recover or change the surfaced fault.

    #[test]
    fn chunk_count_negative_and_over_cap_rejected() {
        // platform = GUID + NumChunks (the reader's first two reads).
        let build = |num: i32| {
            let mut b = Vec::new();
            b.extend_from_slice(&[0u8; 16]); // GUID
            b.extend_from_slice(&num.to_le_bytes()); // NumChunks
            b
        };
        let ctx = make_ctx(&["None"]);
        match read_streaming(&ctx, &build(-1)) {
            Err(PaksmithError::AssetParse {
                fault: AssetParseFault::NegativeValue { field, value },
                ..
            }) => {
                assert_eq!(field, AssetWireField::SoundWaveChunkCount);
                assert_eq!(value, -1);
            }
            other => panic!("expected NegativeValue(SoundWaveChunkCount), got {other:?}"),
        }
        match read_streaming(&ctx, &build(MAX_STREAMED_AUDIO_CHUNKS + 1)) {
            Err(PaksmithError::AssetParse {
                fault: AssetParseFault::BoundsExceeded { field, limit, .. },
                ..
            }) => {
                assert_eq!(field, AssetWireField::SoundWaveChunkCount);
                assert_eq!(limit, u64::try_from(MAX_STREAMED_AUDIO_CHUNKS).unwrap());
            }
            other => panic!("expected BoundsExceeded(SoundWaveChunkCount), got {other:?}"),
        }
    }

    #[test]
    fn chunk_count_at_cap_is_not_over_cap() {
        // NumChunks == cap must PASS the cap (then EOF on the absent AudioFormat),
        // not be rejected as BoundsExceeded. Pins `>` vs `>=`.
        let ctx = make_ctx(&["None"]);
        let mut platform = Vec::new();
        platform.extend_from_slice(&[0u8; 16]); // GUID
        platform.extend_from_slice(&MAX_STREAMED_AUDIO_CHUNKS.to_le_bytes()); // == cap, nothing follows
        let err = read_streaming(&ctx, &platform).expect_err("missing audio format");
        assert!(
            !matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::BoundsExceeded { .. },
                    ..
                }
            ),
            "count == cap must not be BoundsExceeded, got {err:?}"
        );
    }

    #[test]
    fn truncated_audio_format_is_eof() {
        // NumChunks present but no AudioFormat FName bytes → EOF tagged
        // SoundWaveAudioFormat.
        let ctx = make_ctx(&["None"]);
        let mut platform = Vec::new();
        platform.extend_from_slice(&[0u8; 16]); // GUID
        platform.extend_from_slice(&1i32.to_le_bytes()); // NumChunks = 1
        match read_streaming(&ctx, &platform) {
            Err(PaksmithError::AssetParse {
                fault: AssetParseFault::UnexpectedEof { field },
                ..
            }) => assert_eq!(field, AssetWireField::SoundWaveAudioFormat),
            other => panic!("expected UnexpectedEof(SoundWaveAudioFormat), got {other:?}"),
        }
    }

    #[test]
    fn truncated_chunk_data_size_is_eof_tagged_chunk() {
        // Chunk with Flags + a full FByteBulkData header (size 0, no inline) but
        // no DataSize → EOF tagged SoundWaveChunk.
        let ctx = make_ctx(&["None", "OGG"]);
        let mut platform = Vec::new();
        platform.extend_from_slice(&[0u8; 16]); // GUID
        platform.extend_from_slice(&1i32.to_le_bytes()); // NumChunks = 1
        write_fname(&mut platform, 1, 0); // AudioFormat = "OGG"
        platform.extend_from_slice(&0u32.to_le_bytes()); // chunk Flags
        write_byte_bulk_data(&mut platform, 0, 0); // FByteBulkData header, no inline
        // (no DataSize)
        match read_streaming(&ctx, &platform) {
            Err(PaksmithError::AssetParse {
                fault: AssetParseFault::UnexpectedEof { field },
                ..
            }) => assert_eq!(field, AssetWireField::SoundWaveChunk),
            other => panic!("expected UnexpectedEof(SoundWaveChunk), got {other:?}"),
        }
    }

    #[test]
    fn noncooked_nonstreaming_reads_rawdata() {
        // `!streaming && !cooked` → the RawData path: a single `FByteBulkData`
        // (no codec key) + the `CompressedDataGuid`.
        let ctx = make_ctx(&["None"]);
        let guid = [0x77u8; 16];
        let mut bytes = Vec::new();
        none(&mut bytes);
        write_flags(&mut bytes, 0b0000_0010); // cooked = false (pre-4.25 default → !streaming)
        write_rawdata_platform_data(&mut bytes, 64, guid);

        let (data, bulk) = read_from(&bytes, &ctx, "s").expect("parse");
        assert!(!data.cooked && !data.streaming);
        assert!(data.compressed_format_keys.is_empty()); // raw PCM → no codec keys
        assert!(data.streamed.is_none());
        assert_eq!(data.compressed_data_guid, FGuid::from_bytes(guid));
        assert_eq!(bulk.len(), 1); // the single RawData record
        assert_eq!(bulk[0].size_on_disk, 64);
    }

    #[test]
    fn rawdata_truncated_is_bulk_eof() {
        // The RawData reader's single FByteBulkData errors on truncation (a
        // bulk-data fault, not a SoundWave* field).
        let ctx = make_ctx(&["None"]);
        let platform = [0x01u8, 0x00, 0x01, 0x00]; // valid flags, then truncated header
        match read_rawdata(&ctx, &platform) {
            Err(PaksmithError::AssetParse { fault, .. }) => {
                let s = format!("{fault:?}");
                assert!(
                    s.contains("BulkData"),
                    "expected a bulk-data fault, got {s}"
                );
            }
            other => panic!("expected a bulk-data AssetParse error, got {other:?}"),
        }
    }

    // These pin the non-streaming reader's OWN error tagging, so they call
    // `read_nonstreaming_platform_data` directly (the `read_from` retry would
    // otherwise recover or re-tag a first-attempt failure).

    #[test]
    fn format_count_negative_rejected() {
        let ctx = make_ctx(&["None"]);
        let platform = (-1i32).to_le_bytes(); // numFormats = -1
        match read_nonstreaming(&ctx, &platform) {
            Err(PaksmithError::AssetParse {
                fault: AssetParseFault::NegativeValue { field, value },
                ..
            }) => {
                assert_eq!(field, AssetWireField::SoundWaveFormatCount);
                assert_eq!(value, -1);
            }
            other => panic!("expected NegativeValue(SoundWaveFormatCount), got {other:?}"),
        }
    }

    #[test]
    fn format_count_over_cap_rejected() {
        let ctx = make_ctx(&["None"]);
        let platform = (MAX_SOUND_FORMATS + 1).to_le_bytes();
        match read_nonstreaming(&ctx, &platform) {
            Err(PaksmithError::AssetParse {
                fault: AssetParseFault::BoundsExceeded { field, limit, .. },
                ..
            }) => {
                assert_eq!(field, AssetWireField::SoundWaveFormatCount);
                assert_eq!(limit, u64::try_from(MAX_SOUND_FORMATS).unwrap());
            }
            other => panic!("expected BoundsExceeded(SoundWaveFormatCount), got {other:?}"),
        }
    }

    #[test]
    fn format_count_at_cap_is_not_over_cap() {
        // numFormats == MAX_SOUND_FORMATS must PASS the cap (then EOF on the
        // absent records), not be rejected as BoundsExceeded. Pins `>` vs `>=`.
        let ctx = make_ctx(&["None"]);
        let platform = MAX_SOUND_FORMATS.to_le_bytes(); // no records follow
        let err = read_nonstreaming(&ctx, &platform).expect_err("missing records");
        assert!(
            !matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::BoundsExceeded { .. },
                    ..
                }
            ),
            "count == cap must not be BoundsExceeded, got {err:?}"
        );
    }

    #[test]
    fn format_key_out_of_range_index_is_error_tagged_format_key() {
        // A format-key `FName` index past the name table → the resolver error is
        // tagged `SoundWaveFormatKey` (pins the field wiring).
        let ctx = make_ctx(&["None"]); // only index 0 is valid
        let mut platform = Vec::new();
        platform.extend_from_slice(&1i32.to_le_bytes()); // numFormats = 1
        write_fname(&mut platform, 99, 0); // key index 99 — out of range
        match read_nonstreaming(&ctx, &platform) {
            Err(PaksmithError::AssetParse {
                fault: AssetParseFault::PackageIndexOob { field, .. },
                ..
            }) => assert_eq!(field, AssetWireField::SoundWaveFormatKey),
            other => panic!("expected PackageIndexOob(SoundWaveFormatKey), got {other:?}"),
        }
    }

    #[test]
    fn truncated_compressed_data_guid_is_eof() {
        // One full format, then a short (8-of-16-byte) CompressedDataGuid.
        let ctx = make_ctx(&["None", "OGG"]);
        let mut platform = Vec::new();
        write_format_container(&mut platform, &[(1, 50)]);
        platform.extend_from_slice(&[0u8; 8]); // only half a GUID
        match read_nonstreaming(&ctx, &platform) {
            Err(PaksmithError::AssetParse {
                fault: AssetParseFault::UnexpectedEof { field },
                ..
            }) => assert_eq!(field, AssetWireField::SoundWaveCompressedDataGuid),
            other => panic!("expected UnexpectedEof(SoundWaveCompressedDataGuid), got {other:?}"),
        }
    }

    #[test]
    fn truncated_format_count_is_eof() {
        // Empty platform region — no bytes for `numFormats` → EOF tagged
        // SoundWaveFormatCount.
        let ctx = make_ctx(&["None"]);
        match read_nonstreaming(&ctx, &[]) {
            Err(PaksmithError::AssetParse {
                fault: AssetParseFault::UnexpectedEof { field },
                ..
            }) => assert_eq!(field, AssetWireField::SoundWaveFormatCount),
            other => panic!("expected UnexpectedEof(SoundWaveFormatCount), got {other:?}"),
        }
    }

    #[test]
    fn inline_payload_format_does_not_desync_later_fields() {
        // Regression for the in-stream inline-payload cursor desync: a 2-format
        // `FFormatContainer` whose first `FByteBulkData` is `ForceInlinePayload`
        // with 4 in-stream bytes. `FByteBulkData::read_from` must consume them so
        // the second format's key and the `CompressedDataGuid` read at the right
        // offset (without the skip, the 2nd key reads the payload bytes).
        let ctx = make_ctx(&["None", "OGG", "OPUS"]);
        let guid = [0x22u8; 16];
        let mut bytes = Vec::new();
        none(&mut bytes);
        write_flags(&mut bytes, 0x1); // cooked, streaming = false
        bytes.extend_from_slice(&2i32.to_le_bytes()); // numFormats = 2
        write_fname(&mut bytes, 1, 0); // key "OGG"
        write_inline_byte_bulk_data(&mut bytes, 4, &[0xDE, 0xAD, 0xBE, 0xEF]);
        write_fname(&mut bytes, 2, 0); // key "OPUS"
        write_byte_bulk_data(&mut bytes, 100, 0); // PayloadAtEndOfFile (no inline)
        bytes.extend_from_slice(&guid);

        let (data, bulk) = read_from(&bytes, &ctx, "s").expect("parse");
        let keys: Vec<&str> = data
            .compressed_format_keys
            .iter()
            .map(Arc::as_ref)
            .collect();
        assert_eq!(keys, ["OGG", "OPUS"]); // 2nd key read at the right offset
        assert_eq!(data.compressed_data_guid, FGuid::from_bytes(guid));
        assert_eq!(bulk.len(), 2);
        assert_eq!(bulk[0].size_on_disk, 4);
        assert_eq!(bulk[1].size_on_disk, 100);
    }

    // --- streaming-flip retry (3f-5) ---

    #[test]
    fn streaming_flip_retry_recovers_mis_resolved_streaming() {
        // Resolved `streaming = true` (tag), but the platform data is a valid
        // non-streaming `FFormatContainer`. The streaming first attempt fails —
        // its `NumChunks` read lands on the format's `FByteBulkData` ElementCount
        // (1000 > the chunk cap → BoundsExceeded) — and the retry re-parses as
        // non-streaming and recovers, flipping the stored `streaming` to false.
        let ctx = make_ctx(&["None", "bStreaming", "BoolProperty", "OGG"]);
        let guid = [0x55u8; 16];
        let mut bytes = Vec::new();
        write_bool_property(&mut bytes, 1, 2, true); // bStreaming = true → resolves streaming
        none(&mut bytes);
        write_flags(&mut bytes, 0x1); // cooked
        write_format_container(&mut bytes, &[(3, 1000)]); // valid non-streaming; ElementCount 1000 > cap
        bytes.extend_from_slice(&guid);

        let (data, bulk) = read_from(&bytes, &ctx, "s").expect("parse");
        assert!(
            !data.streaming,
            "retry must flip the stored streaming to false"
        );
        assert!(data.cooked);
        let keys: Vec<&str> = data
            .compressed_format_keys
            .iter()
            .map(Arc::as_ref)
            .collect();
        assert_eq!(keys, ["OGG"]); // recovered the non-streaming format
        assert_eq!(data.compressed_data_guid, FGuid::from_bytes(guid));
        assert!(data.streamed.is_none());
        assert_eq!(bulk.len(), 1);
        assert_eq!(bulk[0].size_on_disk, 1000);
    }

    #[test]
    fn streaming_flip_retry_recovers_mis_resolved_nonstreaming() {
        // Mirror of `streaming_flip_retry_recovers_mis_resolved_streaming` in the
        // opposite direction (false → true): resolved `streaming = false` (no
        // `bStreaming`/`LoadingBehavior` tag + a pre-4.25 version), but the
        // platform data is a valid streaming `FStreamedAudioPlatformData`. The
        // non-streaming first attempt fails — its `numFormats` reads the GUID's
        // first 4 bytes (`MAX_SOUND_FORMATS + 1` > cap → BoundsExceeded) — and the
        // retry re-parses as streaming, flipping the stored `streaming` to `true`
        // and populating `streamed`. This is the branch ordering
        // (nonstreaming-first → streaming-retry) the streaming-first test can't
        // reach, and asserting `streaming == true` here makes the flip
        // (`!streaming`) discriminating against a constant (`= false`) mutant the
        // false-direction tests would otherwise leave alive.
        let ctx = make_ctx_with_version(516, None); // pre-4.25 → default streaming = false
        let mut bytes = Vec::new();
        none(&mut bytes); // no bStreaming / LoadingBehavior tags
        write_flags(&mut bytes, 0x1); // cooked
        // Platform region: a streaming GUID whose first 4 bytes are
        // `MAX_SOUND_FORMATS + 1` (so the non-streaming first attempt reads an
        // over-cap `numFormats` → BoundsExceeded), then a valid 1-chunk streaming
        // tail the retry parses.
        let mut guid = [0x66u8; 16];
        guid[0..4].copy_from_slice(&(MAX_SOUND_FORMATS + 1).to_le_bytes());
        bytes.extend_from_slice(&guid);
        bytes.extend_from_slice(&1i32.to_le_bytes()); // streaming NumChunks = 1
        write_fname(&mut bytes, 0, 0); // AudioFormat = "None"
        write_streamed_chunk(&mut bytes, 0, 77, 77, 770, None); // one chunk

        let (data, bulk) = read_from(&bytes, &ctx, "s").expect("parse");
        assert!(
            data.streaming,
            "retry must flip the stored streaming to true"
        );
        assert!(data.cooked);
        assert!(data.compressed_format_keys.is_empty()); // streaming → no format keys
        let streamed = data.streamed.expect("streamed populated by the retry");
        assert_eq!(streamed.audio_format.as_ref(), "None");
        assert_eq!(streamed.chunks.len(), 1);
        assert_eq!(streamed.chunks[0].data_size, 77);
        assert_eq!(streamed.chunks[0].audio_data_size, 770);
        assert_eq!(data.compressed_data_guid, FGuid::from_bytes(guid));
        assert_eq!(bulk.len(), 1);
        assert_eq!(bulk[0].size_on_disk, 77);
    }

    #[test]
    fn streaming_flip_retry_drops_first_attempt_partial_records() {
        // Pins that the retry's fresh `PlatformData` replaces the failed
        // attempt's partial state. The streaming first attempt reads ONE chunk
        // (into its `bulk`) then fails on a truncated 2nd chunk; the retry
        // recovers as an EMPTY non-streaming `FFormatContainer` (its GUID's first
        // 4 bytes read as `numFormats = 0`), so the final `bulk` is empty — the
        // first attempt's chunk record is NOT leaked.
        let ctx = make_ctx(&["None", "bStreaming", "BoolProperty"]);
        let mut bytes = Vec::new();
        write_bool_property(&mut bytes, 1, 2, true); // streaming = true
        none(&mut bytes);
        write_flags(&mut bytes, 0x1); // cooked
        // Platform region: a streaming GUID whose first 4 bytes are 0 (so the
        // non-streaming retry sees numFormats = 0), then 2 chunks but only 1
        // present.
        let mut guid = [0xEEu8; 16];
        guid[0..4].copy_from_slice(&0i32.to_le_bytes());
        bytes.extend_from_slice(&guid);
        bytes.extend_from_slice(&2i32.to_le_bytes()); // streaming NumChunks = 2
        write_fname(&mut bytes, 0, 0); // AudioFormat = "None"
        write_streamed_chunk(&mut bytes, 0, 99, 99, 990, None); // chunk 0 (one record)
        // chunk 1 omitted → streaming truncates after reading chunk 0

        let (data, bulk) = read_from(&bytes, &ctx, "s").expect("parse");
        assert!(!data.streaming); // recovered as non-streaming
        assert!(data.streamed.is_none());
        assert!(data.compressed_format_keys.is_empty());
        assert!(
            bulk.is_empty(),
            "the first attempt's chunk record must not leak into the retry's bulk: {bulk:?}"
        );
    }

    #[test]
    fn noncooked_retry_now_fires_after_rawdata_lands() {
        // The RawData path made both `!cooked` branches real reads, so the retry
        // is no longer `cooked`-gated. Resolved `streaming = false` (pre-4.25, no
        // tags) → the non-streaming RawData branch runs first; here its
        // `FByteBulkData` truncates (OffsetInFile EOF), and the retry recovers as
        // the streaming `!cooked` GUID-only branch — flipping the stored
        // `streaming` to true.
        let ctx = make_ctx_with_version(516, None); // pre-4.25 → default streaming = false
        let mut bytes = Vec::new();
        none(&mut bytes); // no bStreaming / LoadingBehavior tags
        write_flags(&mut bytes, 0b0000_0010); // cooked = false
        // 16 platform bytes: valid bulk flags + ElementCount + SizeOnDisk, but
        // OffsetInFile (i64) is truncated → RawData fails. As a GUID, all 16 read.
        let guid = [
            0x01, 0x00, 0x01, 0x00, // bulk flags (valid) / GUID[0..4]
            0, 0, 0, 0, // ElementCount / GUID[4..8]
            0, 0, 0, 0, // SizeOnDisk / GUID[8..12]
            0xAA, 0xBB, 0xCC, 0xDD, // 4 of OffsetInFile's 8 bytes / GUID[12..16]
        ];
        bytes.extend_from_slice(&guid);

        let (data, bulk) = read_from(&bytes, &ctx, "s").expect("parse");
        assert!(
            data.streaming,
            "retry recovered the !cooked asset as streaming"
        );
        assert!(!data.cooked);
        assert_eq!(data.compressed_data_guid, FGuid::from_bytes(guid));
        assert!(data.streamed.is_none()); // streaming && !cooked → GUID only, no chunks
        assert!(bulk.is_empty());
    }

    #[test]
    fn both_branches_fail_propagates_error() {
        // A cooked asset whose platform data fails BOTH as streaming (GUID EOF)
        // and, on retry, as non-streaming (numFormats EOF) → the second failure
        // propagates (→ Generic).
        let ctx = make_ctx(&["None", "bStreaming", "BoolProperty"]);
        let mut bytes = Vec::new();
        write_bool_property(&mut bytes, 1, 2, true); // streaming = true
        none(&mut bytes);
        write_flags(&mut bytes, 0x1); // cooked
        bytes.extend_from_slice(&[0u8; 2]); // 2 bytes — too short for either branch
        assert!(read_from(&bytes, &ctx, "s").is_err());
    }

    #[test]
    fn noncooked_both_branches_fail_propagates() {
        // The `!cooked` counterpart: RawData's `FByteBulkData` needs a 20-byte
        // header and the streaming GUID needs 16, so an 8-byte tail fails both
        // branches → error (→ Generic). Pins that the now-ungated `!cooked` retry
        // still propagates a genuine double-failure rather than false-recovering.
        let ctx = make_ctx_with_version(516, None); // pre-4.25 → streaming = false
        let mut bytes = Vec::new();
        none(&mut bytes);
        write_flags(&mut bytes, 0b0000_0010); // cooked = false
        // valid bulk flags then a short tail: RawData EOFs on SizeOnDisk, the
        // streaming-retry GUID EOFs (only 8 of 16 bytes).
        bytes.extend_from_slice(&[0x01, 0x00, 0x01, 0x00, 0, 0, 0, 0]);
        assert!(read_from(&bytes, &ctx, "s").is_err());
    }
}
