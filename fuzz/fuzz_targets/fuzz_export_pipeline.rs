// Coverage-guided fuzzing of the parse -> export-handler emission pipeline.
//
// What this catches:
//   - Panics / unbounded work in the format handlers' `export` emission
//     (DataTable CSV column-union + cell formatting, JSON serialization,
//     generic property-bag rendering) when driven by a parsed asset rather
//     than a hand-built one — the path `fuzz_asset_parse` stops short of.
//   - Mismatches between what the typed readers produce and what the handlers
//     assume (a handler indexing into an asset shape the parser can emit).
//
// Drives the public pipeline end to end: `Package::read_from` -> the default
// `HandlerRegistry` -> `find_handler` -> `export` with no bulk (so the
// emission logic runs; decode handlers that need bulk return early). No seam
// needed — every step is public API.
//
// Seed corpus lives at `fuzz/corpus/fuzz_export_pipeline/`, populated from
// `tests/fixtures/*.uasset` so the fuzzer starts from parseable assets.

#![no_main]

use libfuzzer_sys::fuzz_target;
use paksmith_core::asset::Package;
use paksmith_core::export::HandlerRegistry;

fuzz_target!(|data: &[u8]| {
    // No companion `.uexp` / mappings: exercises the inline-export path. A
    // parse failure is the common case and simply yields nothing to export.
    let Ok(package) = Package::read_from(data, None, None, "fuzz.uasset") else {
        return;
    };
    let registry = HandlerRegistry::all_default_handlers();
    for asset in &package.payloads {
        if let Some(handler) = registry.find_handler(asset) {
            // Empty bulk: the emission/formatting logic runs; handlers needing
            // resolved bulk (texture/mesh/audio) return early without it.
            let _ = handler.export(asset, &[]);
        }
    }
});
