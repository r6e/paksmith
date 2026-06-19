//! Pick which export to convert and which handler converts it.

use paksmith_core::asset::Asset;
use paksmith_core::export::{FormatHandler, HandlerRegistry};

use crate::commands::extract::{AudioFormat, DataTableFormat};

#[derive(Copy, Clone)]
pub(crate) struct FormatPrefs {
    pub(crate) audio: AudioFormat,
    pub(crate) datatable: DataTableFormat,
}

pub(crate) fn preferred_extension(asset: &Asset, prefs: FormatPrefs) -> Option<&'static str> {
    match asset {
        Asset::SoundWave(_) => Some(match prefs.audio {
            AudioFormat::Ogg => "ogg",
            AudioFormat::Wav => "wav",
        }),
        Asset::DataTable(_) => Some(match prefs.datatable {
            DataTableFormat::Csv => "csv",
            DataTableFormat::Json => "json",
        }),
        _ => None,
    }
}

/// Resolve the handler for `asset`: honor the per-domain preferred
/// extension if one exists for the asset AND a handler serves it,
/// otherwise fall back to the variant default (`find_handler`).
/// The fallback also covers raw-codec audio (e.g. BINKA), whose only
/// handler is a `RawSoundHandler` that no preferred extension selects.
pub(crate) fn resolve_handler<'r>(
    asset: &Asset,
    registry: &'r HandlerRegistry,
    prefs: FormatPrefs,
) -> Option<&'r dyn FormatHandler> {
    preferred_extension(asset, prefs)
        .and_then(|ext| registry.find_handler_by_extension(ext, asset))
        .or_else(|| registry.find_handler(asset))
}

/// First non-`Generic` payload that has a handler. `Generic` exports
/// are skipped — extract emits raw bytes for untyped assets rather
/// than a JSON property dump (that is `inspect`'s role).
pub(crate) fn select_export<'r>(
    payloads: &[Asset],
    registry: &'r HandlerRegistry,
    prefs: FormatPrefs,
) -> Option<(usize, &'r dyn FormatHandler)> {
    payloads
        .iter()
        .enumerate()
        .filter(|(_, a)| !matches!(a, Asset::Generic(_)))
        .find_map(|(idx, a)| resolve_handler(a, registry, prefs).map(|h| (idx, h)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use paksmith_core::asset::property::bag::PropertyBag;
    use paksmith_core::asset::{Asset, DataTableData, SoundWaveData, Texture2DData};

    fn prefs(audio: AudioFormat, datatable: DataTableFormat) -> FormatPrefs {
        FormatPrefs { audio, datatable }
    }

    #[test]
    fn preferred_extension_maps_domains() {
        let p = prefs(AudioFormat::Wav, DataTableFormat::Json);
        assert_eq!(
            preferred_extension(&Asset::SoundWave(SoundWaveData::empty()), p),
            Some("wav")
        );
        assert_eq!(
            preferred_extension(&Asset::DataTable(DataTableData::empty()), p),
            Some("json")
        );
        assert_eq!(
            preferred_extension(&Asset::Texture2D(Texture2DData::empty()), p),
            None
        );
    }

    #[test]
    fn select_skips_generic_and_picks_typed() {
        let reg = HandlerRegistry::all_default_handlers();
        let p = prefs(AudioFormat::Ogg, DataTableFormat::Csv);
        let payloads = vec![
            Asset::Generic(PropertyBag::opaque(Vec::new())),
            Asset::DataTable(DataTableData::empty()),
        ];
        let (idx, handler) = select_export(&payloads, &reg, p).unwrap();
        assert_eq!(idx, 1);
        assert_eq!(handler.output_extension(), "csv");
    }

    #[test]
    fn select_returns_none_when_all_generic() {
        let reg = HandlerRegistry::all_default_handlers();
        let p = prefs(AudioFormat::Ogg, DataTableFormat::Csv);
        let payloads = vec![Asset::Generic(PropertyBag::opaque(Vec::new()))];
        assert!(select_export(&payloads, &reg, p).is_none());
    }
}
