// Coverage-guided fuzzing of the `.locres` (FTextLocalizationResource)
// parser. Memory-safety scope and rationale are documented in
// `fuzz_pak_open.rs`; the same `unsafe_code = "deny"` policy applies
// workspace-wide.
//
// Target-specific arms this exercises:
//   - magic-or-legacy discrimination + version-byte rejection.
//   - the two-cursor read (header + strings array at its i64 offset,
//     bounds-checked before the seek).
//   - MAX_LOCRES_COUNT caps on namespace/key/strings counts rejecting
//     over-cap headers before allocation.
//   - FString decode (ANSI + UTF-16, null-terminator + length checks).
//   - fail-closed StringIndex bounds (negative and over-range).
//
// Seed corpus lives at `fuzz/corpus/fuzz_locres_parse/` and is
// populated by the CI workflow from `tests/fixtures/data/*.locres`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use paksmith_core::localization::LocresResource;

fuzz_target!(|data: &[u8]| {
    let _ = LocresResource::parse(data);
});
