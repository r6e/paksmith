//! `USoundWave` export reader (Phase 3f-1).
//!
//! Wire-format reference: `docs/formats/audio/sound-wave.md` (oracle
//! `FabianFG/CUE4Parse` `USoundWave.cs`). See the module docs
//! ([`super`]) for the full segment layout.
//!
//! **3f-1 scope:** parse only segment 1 — the `USoundBase` tagged-property
//! segment (the None-terminated `FPropertyTag` stream carrying the audio
//! settings) — into [`SoundWaveData`]. The USoundWave binary header that
//! follows (`Flags`, codec buffers / streamed chunks) is parsed in 3f-2
//! onward; until then it is left unconsumed, the same way the non-virtual
//! texture path leaves trailing bytes within the export's `serial_size`
//! boundary.

use std::io::Cursor;

use crate::asset::bulk_data::FByteBulkData;
use crate::asset::property::bag::PropertyBag;
use crate::asset::property::read_properties;
use crate::asset::{Asset, AssetContext, SoundWaveData};

/// Parse a `USoundWave` export payload into [`SoundWaveData`].
///
/// 3f-1 reads the leading tagged-property segment (audio settings) and stops;
/// the trailing USoundWave-specific binary is a later-milestone concern.
///
/// # Errors
/// Any tagged-property fault from the nested
/// [`read_properties`](crate::asset::property::read_properties) read.
pub(crate) fn read_from(
    payload: &[u8],
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<SoundWaveData> {
    let mut cur = Cursor::new(payload);
    let total_len = payload.len() as u64;

    // Segment 1: the USoundBase tagged-property stream, None-terminated.
    let properties = read_properties(&mut cur, ctx, 0, total_len, asset_path)?;

    Ok(SoundWaveData {
        properties: PropertyBag::Tree { properties },
    })
}

/// [`crate::asset::exports::dispatch::TypedReaderFn`] entry for the `SoundWave`
/// class: parse into [`Asset::SoundWave`]. No `FByteBulkData` records yet — the
/// per-codec audio buffers are collected once the binary header is parsed
/// (3f-3 / 3f-4).
pub(crate) fn read_typed(
    payload: &[u8],
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<(Asset, Vec<FByteBulkData>)> {
    let data = read_from(payload, ctx, asset_path)?;
    Ok((Asset::SoundWave(data), Vec::new()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::property::primitives::PropertyValue;
    use crate::asset::property::test_utils::{
        make_ctx, write_int_property, write_none_tag as none,
    };

    #[test]
    fn sound_wave_captures_tagged_property_segment() {
        // Segment 1: one IntProperty ("NumChannels" = 2), then the None
        // terminator. (The USoundWave binary header after None is 3f-2+.)
        let ctx = make_ctx(&["None", "NumChannels", "IntProperty"]);
        let mut bytes = Vec::new();
        write_int_property(&mut bytes, 1, 2, 2); // name "NumChannels", type "IntProperty"
        none(&mut bytes);

        let data = read_from(&bytes, &ctx, "sound.uasset").expect("parse");
        let PropertyBag::Tree { properties } = &data.properties else {
            panic!("expected a Tree bag, got {:?}", data.properties);
        };
        assert_eq!(properties.len(), 1);
        assert_eq!(properties[0].name(), "NumChannels");
        assert!(matches!(properties[0].value, PropertyValue::Int(2)));
    }

    #[test]
    fn read_typed_wraps_the_sound_wave_variant() {
        // A bare None terminator (no settings) still yields the typed variant
        // with no bulk records.
        let ctx = make_ctx(&["None"]);
        let mut bytes = Vec::new();
        none(&mut bytes);

        let (asset, bulk) = read_typed(&bytes, &ctx, "sound.uasset").expect("parse");
        assert!(matches!(asset, Asset::SoundWave(_)));
        assert!(bulk.is_empty());
    }
}
