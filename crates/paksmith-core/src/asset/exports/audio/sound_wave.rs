//! `USoundWave` export reader (Phase 3f).
//!
//! Wire-format reference: `docs/formats/audio/sound-wave.md` (oracle
//! `FabianFG/CUE4Parse` `USoundWave.cs`). See the module docs ([`super`]).
//!
//! **3f-1** captured segment 1a (the `USoundBase` tagged-property stream).
//! **3f-2** added the start of the binary header: it resolves `bStreaming`
//! (from the version-table default + the tagged `bStreaming` / `LoadingBehavior`
//! properties — no binary read), reads the `Flags` `u32`, and extracts
//! `bCooked` (bit 0). **This slice** consumes the version-conditional
//! `DummyCompressionName` (a discarded `FName`) that follows `Flags`. The read
//! stops there; the UE 5.4+ cue points and the platform-data segment (codec
//! buffers / streamed chunks) land in later 3f milestones.

use std::io::Cursor;

use byteorder::{LittleEndian, ReadBytesExt};

use crate::asset::bulk_data::FByteBulkData;
use crate::asset::custom_version::{
    FRAMEWORK_OBJECT_VERSION_GUID, FRAMEWORK_OBJECT_VERSION_REMOVE_SOUND_WAVE_COMPRESSION_NAME,
};
use crate::asset::property::bag::PropertyBag;
use crate::asset::property::primitives::{Property, PropertyValue};
use crate::asset::property::read_properties;
use crate::asset::version::AssetVersion;
use crate::asset::{Asset, AssetContext, SoundWaveData};
use crate::error::{AssetParseFault, AssetWireField, PaksmithError};

/// `ESoundWaveFlag::CookedFlag` — bit 0 of the `Flags` header (CUE4Parse
/// `ESoundWaveFlag`). The other bits (`HasOwnerLoadingBehaviorFlag`, the
/// loading-behavior enum) are not consumed by paksmith's cooked-export path.
/// (Written as the bit-0 literal rather than `1 << 0`: a `<<`→`>>` mutant of
/// the shift is equivalent at shift-0, so the literal avoids a dead mutant.)
const SOUND_WAVE_COOKED_FLAG: u32 = 0b0000_0001;

/// Parse a `USoundWave` export payload into [`SoundWaveData`] (3f-1 + 3f-2).
///
/// # Errors
/// - Any tagged-property fault from the nested
///   [`read_properties`](crate::asset::property::read_properties) read.
/// - [`AssetParseFault::UnexpectedEof`] on a short read of the `Flags` header
///   or the version-conditional `DummyCompressionName`.
pub(crate) fn read_from(
    payload: &[u8],
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<SoundWaveData> {
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

    // STOP. The remaining header field is the UE 5.4+ cue-point
    // `FStructFallback[]` (when `cooked`), which sits between
    // `DummyCompressionName` and the platform-data segment. It MUST be consumed
    // before the platform-data reader (3f-3) is added: a header desync has no
    // recovery point (the streaming-flip retry only re-parses platform data
    // from a saved position).

    Ok(SoundWaveData {
        properties: PropertyBag::Tree { properties },
        cooked,
        streaming,
    })
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
/// class. No `FByteBulkData` records yet — the per-codec audio buffers are
/// collected once the platform-data segment is parsed (3f-3 / 3f-4).
pub(crate) fn read_typed(
    payload: &[u8],
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<(Asset, Vec<FByteBulkData>)> {
    let data = read_from(payload, ctx, asset_path)?;
    Ok((Asset::SoundWave(data), Vec::new()))
}

fn eof(asset_path: &str, field: AssetWireField) -> PaksmithError {
    PaksmithError::AssetParse {
        asset_path: asset_path.to_string(),
        fault: AssetParseFault::UnexpectedEof { field },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::FGuid;
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

        let data = read_from(&bytes, &ctx, "sound.uasset").expect("parse");
        assert!(data.cooked);
        assert_single_numchannels(&data);
    }

    #[test]
    fn bcooked_is_bit_zero_of_flags() {
        let ctx = make_ctx(&["None"]);
        // Bit 0 clear (e.g. only HasOwnerLoadingBehaviorFlag set) → not cooked.
        let mut not_cooked = Vec::new();
        none(&mut not_cooked);
        write_flags(&mut not_cooked, 0b0000_0010);
        assert!(!read_from(&not_cooked, &ctx, "s").expect("parse").cooked);
        // Bit 0 set among other bits → cooked.
        let mut cooked = Vec::new();
        none(&mut cooked);
        write_flags(&mut cooked, 0b0000_0011);
        assert!(read_from(&cooked, &ctx, "s").expect("parse").cooked);
    }

    #[test]
    fn streaming_default_follows_ue4_25_proxy() {
        // No bStreaming / LoadingBehavior tags → the version-table default.
        let payload = {
            let mut b = Vec::new();
            none(&mut b);
            write_flags(&mut b, 0x1);
            b
        };
        // UE5 (and UE4.25+) → default true.
        let ue5 = make_ctx_with_version(522, Some(1009));
        assert!(read_from(&payload, &ue5, "s").expect("parse").streaming);
        let ue4_25 = make_ctx_with_version(518, None);
        assert!(read_from(&payload, &ue4_25, "s").expect("parse").streaming);
        // UE4.20 (pre-4.25) → default false.
        let ue4_20 = make_ctx_with_version(516, None);
        assert!(!read_from(&payload, &ue4_20, "s").expect("parse").streaming);
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
        assert!(!read_from(&bytes, &ctx, "s").expect("parse").streaming);
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
        // `&&` finds bStreaming=false → not streaming. `||` would match the
        // array_index-0 Decoy first (→ true) → wrong.
        assert!(!read_from(&bytes, &ctx, "s").expect("parse").streaming);
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
            b
        };
        // ForceInline → NOT streaming.
        assert!(!read_from(&build(3), &ctx, "s").expect("parse").streaming);
        // Any other behavior → streaming.
        assert!(read_from(&build(4), &ctx, "s").expect("parse").streaming);
        // The literal "None" name → NOT streaming (IsNone).
        assert!(!read_from(&build(0), &ctx, "s").expect("parse").streaming);
    }

    #[test]
    fn read_typed_wraps_the_sound_wave_variant() {
        let ctx = make_ctx(&["None"]);
        let mut bytes = Vec::new();
        none(&mut bytes);
        write_flags(&mut bytes, 0x1);

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

        let data = read_from(&bytes, &ctx, "s").expect("parse");
        assert!(data.cooked);
        assert_single_numchannels(&data);
    }
}
