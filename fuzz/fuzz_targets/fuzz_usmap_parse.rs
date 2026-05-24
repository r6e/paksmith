// Coverage-guided fuzzing of the `.usmap` mappings parser. Memory-
// safety scope and rationale are documented in `fuzz_pak_open.rs`;
// the same `unsafe_code = "deny"` policy applies workspace-wide.
//
// Target-specific arms this exercises:
//   - `MAX_USMAP_*` wire caps (name count, schema count, decompressed
//     size) rejecting over-cap headers before allocation.
//   - Compression byte dispatch (none / zstd / oodle).
//   - Schema-table inheritance walk + per-class property iteration.
//
// Seed corpus lives at `fuzz/corpus/fuzz_usmap_parse/` and is
// populated by the CI workflow from `tests/fixtures/*.usmap`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use paksmith_core::asset::mappings::Usmap;

fuzz_target!(|data: &[u8]| {
    let _ = Usmap::from_bytes(data);
});
