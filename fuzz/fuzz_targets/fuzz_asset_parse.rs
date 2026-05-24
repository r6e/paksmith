// Coverage-guided fuzzing of `Package::read_from` (uasset parser).
// Memory-safety scope and rationale are documented in
// `fuzz_pak_open.rs`; the same `unsafe_code = "deny"` policy applies
// workspace-wide.
//
// Target-specific arms this exercises:
//   - Asset summary header parsing + version dispatch.
//   - Name table / import table / export table cap rejection.
//   - Tagged-property iteration (the `PKG_UnversionedProperties`-off
//     branch). The unversioned branch needs a `.usmap`; a future
//     `fuzz_asset_parse_with_usmap` harness can take it.
//
// Seed corpus lives at `fuzz/corpus/fuzz_asset_parse/` and is
// populated by the CI workflow from `tests/fixtures/*.uasset`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use paksmith_core::asset::Package;

fuzz_target!(|data: &[u8]| {
    let _ = Package::read_from(data, None, None, "fuzz.uasset");
});
