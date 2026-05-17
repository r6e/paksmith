// Coverage-guided fuzzing of the pak open + verify path.
//
// What this catches:
//   - Panics from invariant violations (unwrap/expect on malformed
//     input, integer underflow, array OOB in safe code).
//   - Pathological inputs that allocate beyond declared caps despite
//     the `MAX_UNCOMPRESSED_ENTRY_BYTES` / `MAX_FDI_BYTES` guards.
//   - Infinite loops / pathologically slow parses (libfuzzer
//     `-timeout=60` flag in the workflow surfaces these).
//
// What this does NOT primarily catch: memory-corruption findings of
// the classical ASan kind. The workspace declares `unsafe_code = "deny"`,
// so memory-safety bugs would have to come from a compiler bug or a
// dependency's unsafe block — vanishingly unlikely.
//
// Seed corpus lives at `fuzz/corpus/fuzz_pak_open/` and is populated
// by the CI workflow from `tests/fixtures/*.pak` so the fuzzer starts
// from valid pak structures and mutates outward.

#![no_main]

use libfuzzer_sys::fuzz_target;
use paksmith_core::container::pak::PakReader;

fuzz_target!(|data: &[u8]| {
    // Issue #161: in-memory entry point eliminates the
    // tempfile-write/file-open syscall per iteration that the prior
    // version paid. `to_vec()` copies the input once into an owned
    // `Vec<u8>`; the disk roundtrip the prior code did was ~10-100x
    // more expensive at fuzz throughput scale.
    if let Ok(reader) = PakReader::from_bytes(data.to_vec()) {
        // Successful open ≠ done. The verify path exercises footer
        // SHA1 + main-index SHA1 + FDI/PHI region SHA1 checks; the
        // fuzzer would otherwise have no signal that those branches
        // were reachable without a follow-on call.
        let _ = reader.verify();
    }
});
