//! `USoundWave` export reader (Phase 3f).
//!
//! Wire-format reference: `docs/formats/audio/sound-wave.md` (oracle
//! `FabianFG/CUE4Parse` `USoundWave.cs`). See the module docs ([`super`]).
//!
//! **3f-1** captured segment 1a (the `USoundBase` tagged-property stream).
//! **3f-2** added the start of the binary header: it resolves `bStreaming`,
//! reads the `Flags` `u32`, and extracts `bCooked` (bit 0). **3f** consumes the
//! version-conditional `DummyCompressionName` (a discarded `FName`). **This
//! slice (3f-3)** parses the non-streaming cooked platform-data segment — the
//! `FFormatContainer` (per-codec keys + `FByteBulkData` buffers) and the
//! `CompressedDataGuid` — on the `!streaming` branch. The streaming branch
//! (`FStreamedAudioPlatformData`), the non-cooked `RawData` path, and the
//! oracle's streaming-flip retry land in later 3f milestones. (The oracle's UE
//! 5.4+ cue points are unreachable here — they need object version 1012, above
//! paksmith's 1011 `FPropertyTag` ceiling — so platform data follows
//! `DummyCompressionName` directly.)

use std::io::Cursor;
use std::sync::Arc;

use byteorder::{LittleEndian, ReadBytesExt};

use crate::asset::bulk_data::FByteBulkData;
use crate::asset::custom_version::{
    FRAMEWORK_OBJECT_VERSION_GUID, FRAMEWORK_OBJECT_VERSION_REMOVE_SOUND_WAVE_COMPRESSION_NAME,
};
use crate::asset::property::bag::PropertyBag;
use crate::asset::property::primitives::{Property, PropertyValue};
use crate::asset::property::{read_fname_pair, read_properties};
use crate::asset::version::AssetVersion;
use crate::asset::{Asset, AssetContext, FGuid, SoundWaveData};
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

/// The non-streaming platform-data segment: per-codec keys (wire order), the
/// cook GUID, and the `FByteBulkData` buffer headers (positionally aligned with
/// the keys). Returned by [`read_nonstreaming_platform_data`].
type NonStreamingPlatformData = (Vec<Arc<str>>, Option<FGuid>, Vec<FByteBulkData>);

/// Parse a `USoundWave` export payload into [`SoundWaveData`] plus its
/// `FByteBulkData` records (3f-1 → 3f-3).
///
/// The returned `Vec<FByteBulkData>` carries the non-streaming
/// `FFormatContainer`'s per-codec buffer headers in wire order — positionally
/// aligned with [`SoundWaveData::compressed_format_keys`] — for lazy `.ubulk`
/// resolution by the package, the same contract as the texture readers. It is
/// empty when the asset took the streaming branch (3f-4), is non-cooked, or
/// carries no formats.
///
/// # Errors
/// - Any tagged-property fault from the nested
///   [`read_properties`](crate::asset::property::read_properties) read.
/// - [`AssetParseFault::UnexpectedEof`] on a short read of the `Flags` header,
///   the version-conditional `DummyCompressionName`, or the non-streaming
///   platform-data segment.
/// - [`AssetParseFault::NegativeValue`] / [`AssetParseFault::BoundsExceeded`]
///   on a bad `FFormatContainer` count, or any `FByteBulkData` fault.
pub(crate) fn read_from(
    payload: &[u8],
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<(SoundWaveData, Vec<FByteBulkData>)> {
    let mut cur = Cursor::new(payload);
    let total_len = payload.len() as u64;

    // Segment 1a: the USoundBase tagged-property stream, None-terminated.
    let properties = read_properties(&mut cur, ctx, 0, total_len, asset_path)?;

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
    // Segment 3: platform data, branched on the resolved `streaming`. 3f-3
    // parses only the non-streaming cooked path (`FFormatContainer` +
    // `CompressedDataGuid`); the streaming branch (`FStreamedAudioPlatformData`)
    // and the non-cooked `RawData` path are deferred (3f-4), as is the oracle's
    // streaming-flip retry — so `streaming` is taken at face value here, and a
    // streaming-resolved asset leaves its platform data unconsumed within the
    // export's `serial_size` boundary.
    let (compressed_format_keys, compressed_data_guid, bulk) = if !streaming && cooked {
        read_nonstreaming_platform_data(&mut cur, ctx, total_len, asset_path)?
    } else {
        (Vec::new(), None, Vec::new())
    };

    Ok((
        SoundWaveData {
            properties: PropertyBag::Tree { properties },
            cooked,
            streaming,
            compressed_format_keys,
            compressed_data_guid,
        },
        bulk,
    ))
}

/// Read the non-streaming cooked platform-data segment per CUE4Parse
/// `USoundWave.SerializePlatformData` (the `!bStreaming && bCooked` branch):
/// the `FFormatContainer` (`i32 numFormats`, then `numFormats` `(FName key,
/// FByteBulkData value)` pairs) followed by the 16-byte `CompressedDataGuid`.
///
/// Returns the per-codec keys (wire order) and the `FByteBulkData` records
/// (positionally aligned) plus the cook GUID. The keys are **resolved** against
/// the name table (unlike the discarded `DummyCompressionName`) because they
/// identify each buffer's codec and are kept as real metadata. The count is
/// capped ([`MAX_SOUND_FORMATS`]) and the records grow as read — never
/// pre-allocated to the claimed count — so a lying count is bounded by the
/// payload (`FByteBulkData::read_from` errors on truncation).
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
/// bad count; [`AssetParseFault::UnexpectedEof`] on the GUID; any `FName` or
/// `FByteBulkData` fault.
fn read_nonstreaming_platform_data(
    cur: &mut Cursor<&[u8]>,
    ctx: &AssetContext,
    total_len: u64,
    asset_path: &str,
) -> crate::Result<NonStreamingPlatformData> {
    let num_formats = cur
        .read_i32::<LittleEndian>()
        .map_err(|_| eof(asset_path, AssetWireField::SoundWaveFormatCount))?;
    if num_formats < 0 {
        return Err(negative(
            asset_path,
            AssetWireField::SoundWaveFormatCount,
            num_formats,
        ));
    }
    if num_formats > MAX_SOUND_FORMATS {
        return Err(bounds(
            asset_path,
            AssetWireField::SoundWaveFormatCount,
            num_formats,
        ));
    }

    let mut keys: Vec<Arc<str>> = Vec::new();
    let mut bulk: Vec<FByteBulkData> = Vec::new();
    for _ in 0..num_formats {
        keys.push(read_fname_pair(
            cur,
            ctx,
            asset_path,
            AssetWireField::SoundWaveFormatKey,
        )?);
        bulk.push(FByteBulkData::read_from(cur, asset_path)?);
    }
    debug_assert!(cur.position() <= total_len);

    let guid = FGuid::read_from(cur)
        .map_err(|_| eof(asset_path, AssetWireField::SoundWaveCompressedDataGuid))?;
    Ok((keys, Some(guid), bulk))
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
/// 3f-3/4 streaming-flip retry once the platform-data parse runs.
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
fn scalar_property<'a>(properties: &'a [Property], name: &str) -> Option<&'a Property> {
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
/// class. The returned records are the non-streaming `FFormatContainer`'s
/// per-codec buffers (3f-3); empty for streaming / non-cooked assets until 3f-4.
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

// `value` is checked `> MAX_SOUND_FORMATS` (hence `>= 0`) before this call, and
// `MAX_SOUND_FORMATS` is a positive const, so both `as u64` casts are exact.
#[allow(clippy::cast_sign_loss)]
fn bounds(asset_path: &str, field: AssetWireField, value: i32) -> PaksmithError {
    fault(
        asset_path,
        AssetParseFault::BoundsExceeded {
            field,
            value: value as u64,
            limit: MAX_SOUND_FORMATS as u64,
            unit: BoundsUnit::Items,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::property::test_utils::{
        make_ctx, make_ctx_with_version, write_fname, write_int_property, write_none_tag as none,
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

    /// Parse `bytes` and return just the [`SoundWaveData`] (dropping the
    /// bulk-record list) — for header-focused tests that assert on the parsed
    /// fields rather than the returned buffers.
    fn parse_data(bytes: &[u8], ctx: &AssetContext) -> SoundWaveData {
        read_from(bytes, ctx, "s").expect("parse").0
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
        // (and the non-cooked branch skips platform data, so no tail needed).
        let mut not_cooked = Vec::new();
        none(&mut not_cooked);
        write_flags(&mut not_cooked, 0b0000_0010);
        assert!(!parse_data(&not_cooked, &ctx).cooked);
        // Bit 0 set among other bits → cooked.
        let mut cooked = Vec::new();
        none(&mut cooked);
        write_flags(&mut cooked, 0b0000_0011);
        write_empty_platform_data(&mut cooked);
        assert!(parse_data(&cooked, &ctx).cooked);
    }

    #[test]
    fn streaming_default_follows_ue4_25_proxy() {
        // No bStreaming / LoadingBehavior tags → the version-table default.
        let payload = {
            let mut b = Vec::new();
            none(&mut b);
            write_flags(&mut b, 0x1);
            write_empty_platform_data(&mut b); // consumed iff !streaming (UE4.20)
            b
        };
        // UE5 (and UE4.25+) → default true.
        let ue5 = make_ctx_with_version(522, Some(1009));
        assert!(parse_data(&payload, &ue5).streaming);
        let ue4_25 = make_ctx_with_version(518, None);
        assert!(parse_data(&payload, &ue4_25).streaming);
        // UE4.20 (pre-4.25) → default false.
        let ue4_20 = make_ctx_with_version(516, None);
        assert!(!parse_data(&payload, &ue4_20).streaming);
    }

    #[test]
    fn tagged_bstreaming_wins_over_loading_behavior_and_version_default() {
        // bStreaming=false, with BOTH a LoadingBehavior that would yield
        // streaming=true AND a UE5 version whose default is true. bStreaming
        // must win over both (LoadingBehavior ignored, default ignored).
        let mut ctx = make_ctx(&[
            "None",
            "bStreaming",
            "BoolProperty",
            "LoadingBehavior",
            "NameProperty",
            "ESoundWaveLoadingBehavior::Inline",
        ]);
        ctx.version = make_ctx_with_version(522, Some(1009)).version; // UE5 → default true
        let mut bytes = Vec::new();
        write_bool_property(&mut bytes, 1, 2, false); // bStreaming = false
        write_name_property(&mut bytes, 3, 4, 5); // LoadingBehavior = Inline
        none(&mut bytes);
        write_flags(&mut bytes, 0x1);
        write_empty_platform_data(&mut bytes); // !streaming && cooked → parsed
        assert!(!parse_data(&bytes, &ctx).streaming);
    }

    #[test]
    fn streaming_lookup_respects_name_and_array_index() {
        // `resolve_streaming` must find the scalar `bStreaming` BY NAME, not the
        // first array_index-0 property — pins `scalar_property`'s
        // `name == ... && array_index == 0` against `&&`→`||`. A decoy
        // BoolProperty (different name, array_index 0, value true) precedes the
        // real `bStreaming = false`.
        let ctx = make_ctx(&["None", "Decoy", "BoolProperty", "bStreaming"]);
        let mut bytes = Vec::new();
        write_bool_property(&mut bytes, 1, 2, true); // Decoy (array_index 0) = true
        write_bool_property(&mut bytes, 3, 2, false); // real bStreaming = false
        none(&mut bytes);
        write_flags(&mut bytes, 0x1);
        write_empty_platform_data(&mut bytes); // !streaming && cooked → parsed
        // `&&` finds bStreaming=false → not streaming. `||` would match the
        // array_index-0 Decoy first (→ true) → wrong.
        assert!(!parse_data(&bytes, &ctx).streaming);
    }

    #[test]
    fn loading_behavior_resolves_streaming_when_no_bstreaming_tag() {
        let names = &[
            "None",
            "LoadingBehavior",
            "NameProperty",
            "ESoundWaveLoadingBehavior::ForceInline",
            "ESoundWaveLoadingBehavior::PrimeOnLoad",
        ];
        let ctx = make_ctx(names);
        let build = |value_idx: i32| {
            let mut b = Vec::new();
            write_name_property(&mut b, 1, 2, value_idx);
            none(&mut b);
            write_flags(&mut b, 0x1);
            write_empty_platform_data(&mut b); // consumed iff !streaming
            b
        };
        // ForceInline → NOT streaming.
        assert!(!parse_data(&build(3), &ctx).streaming);
        // Any other behavior → streaming.
        assert!(parse_data(&build(4), &ctx).streaming);
        // The literal "None" name → NOT streaming (IsNone).
        assert!(!parse_data(&build(0), &ctx).streaming);
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
        assert_eq!(data.compressed_data_guid, Some(FGuid::from_bytes(guid)));
        // Records returned positionally: `compressed_format_keys[i]` ↔ `bulk[i]`.
        assert_eq!(bulk.len(), 2);
        assert_eq!(bulk[0].size_on_disk, 100);
        assert_eq!(bulk[1].size_on_disk, 200);
    }

    #[test]
    fn streaming_branch_defers_platform_data() {
        // bStreaming = true → the streaming branch (3f-4); the FFormatContainer
        // bytes that follow are NOT parsed (no keys/guid/records) and no error.
        let ctx = make_ctx(&["None", "bStreaming", "BoolProperty", "OGG"]);
        let mut bytes = Vec::new();
        write_bool_property(&mut bytes, 1, 2, true); // bStreaming = true
        none(&mut bytes);
        write_flags(&mut bytes, 0x1); // cooked
        write_format_container(&mut bytes, &[(3, 100)]); // would-be platform data

        let (data, bulk) = read_from(&bytes, &ctx, "s").expect("parse");
        assert!(data.streaming);
        assert!(data.compressed_format_keys.is_empty());
        assert_eq!(data.compressed_data_guid, None);
        assert!(bulk.is_empty());
    }

    #[test]
    fn noncooked_branch_defers_platform_data() {
        // !streaming but !cooked → the `RawData` path (deferred); the
        // FFormatContainer is NOT read, no error.
        let ctx = make_ctx(&["None", "OGG"]);
        let mut bytes = Vec::new();
        none(&mut bytes);
        write_flags(&mut bytes, 0b0000_0010); // cooked = false
        write_format_container(&mut bytes, &[(1, 100)]); // would-be data, not read

        let (data, bulk) = read_from(&bytes, &ctx, "s").expect("parse");
        assert!(!data.cooked && !data.streaming);
        assert!(data.compressed_format_keys.is_empty());
        assert_eq!(data.compressed_data_guid, None);
        assert!(bulk.is_empty());
    }

    #[test]
    fn format_count_negative_rejected() {
        let ctx = make_ctx(&["None"]);
        let mut bytes = Vec::new();
        none(&mut bytes);
        write_flags(&mut bytes, 0x1);
        bytes.extend_from_slice(&(-1i32).to_le_bytes()); // numFormats = -1
        match read_from(&bytes, &ctx, "s") {
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
        let mut bytes = Vec::new();
        none(&mut bytes);
        write_flags(&mut bytes, 0x1);
        bytes.extend_from_slice(&(MAX_SOUND_FORMATS + 1).to_le_bytes());
        match read_from(&bytes, &ctx, "s") {
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
        let mut bytes = Vec::new();
        none(&mut bytes);
        write_flags(&mut bytes, 0x1);
        bytes.extend_from_slice(&MAX_SOUND_FORMATS.to_le_bytes()); // no records follow
        let err = read_from(&bytes, &ctx, "s").expect_err("missing records");
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
        let mut bytes = Vec::new();
        none(&mut bytes);
        write_flags(&mut bytes, 0x1);
        bytes.extend_from_slice(&1i32.to_le_bytes()); // numFormats = 1
        write_fname(&mut bytes, 99, 0); // key index 99 — out of range
        match read_from(&bytes, &ctx, "s") {
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
        let mut bytes = Vec::new();
        none(&mut bytes);
        write_flags(&mut bytes, 0x1);
        write_format_container(&mut bytes, &[(1, 50)]);
        bytes.extend_from_slice(&[0u8; 8]); // only half a GUID
        match read_from(&bytes, &ctx, "s") {
            Err(PaksmithError::AssetParse {
                fault: AssetParseFault::UnexpectedEof { field },
                ..
            }) => assert_eq!(field, AssetWireField::SoundWaveCompressedDataGuid),
            other => panic!("expected UnexpectedEof(SoundWaveCompressedDataGuid), got {other:?}"),
        }
    }

    #[test]
    fn truncated_format_count_is_eof() {
        // `!streaming && cooked`, but the payload ends at `Flags` — no bytes for
        // `numFormats`. Pins that the platform-data parse is reached and its
        // count read is tagged `SoundWaveFormatCount`.
        let ctx = make_ctx(&["None"]);
        let mut bytes = Vec::new();
        none(&mut bytes);
        write_flags(&mut bytes, 0x1);
        match read_from(&bytes, &ctx, "s") {
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
        assert_eq!(data.compressed_data_guid, Some(FGuid::from_bytes(guid)));
        assert_eq!(bulk.len(), 2);
        assert_eq!(bulk[0].size_on_disk, 4);
        assert_eq!(bulk[1].size_on_disk, 100);
    }
}
