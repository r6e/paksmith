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
// No committed seed corpus: the sole `.locres` fixture lives at
// `tests/fixtures/data/`, below the CI seed step's top-level
// `-maxdepth 1` glob, so this target fuzzes from scratch (the flat
// header-first parser reaches its magic/version/count/string paths on
// random input by construction).

#![no_main]

use libfuzzer_sys::fuzz_target;
use paksmith_core::localization::LocresResource;

fuzz_target!(|data: &[u8]| {
    let _ = LocresResource::parse(data);
});
