//! Phase 3b Task 7 — shared bulk-data fixture sentinels.
//!
//! Lives under `__test_utils` so both `paksmith-fixture-gen` (which
//! writes the sentinel bytes into `tests/fixtures/real_v8b_{ubulk,uptnl}.pak`)
//! and `paksmith-core-tests` (which asserts the resolver returns
//! them verbatim) share a single source of truth. Avoids the
//! duplicate-constant drift risk the architect's R1 panel flagged.

/// 32-byte sentinel baked into the Phase 3b `.ubulk` / `.uptnl`
/// companion fixtures. Ascending `0xB0..=0xCF` — hex-anchorable,
/// easy to spot in a hex dump, intentionally NOT one of UE's
/// common cooked-asset byte patterns.
pub const BULK_COMPANION_SENTINEL: &[u8] = &[
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
];
