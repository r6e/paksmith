//! Panic-safety canaries for parser entry points on random byte input.
//!
//! Complements `property_proptest.rs` (paksmith-domain generators for
//! primitive round-trips) by exercising the rejection / cap-check arms
//! of `Usmap::from_bytes` and `Package::read_from` with arbitrary
//! bytes. The contract: every entry point returns `Result` — none
//! panic, none abort via `handle_alloc_error`.
//!
//! This is not a substitute for the corpus-driven fuzz harness (#375
//! when it lands). Random `any::<u8>()` input almost never passes the
//! magic / sanity gates, so deep parser arms remain effectively
//! unreached here. The narrow but real coverage: any panic introduced
//! into a path that fires on most rejection inputs (`.unwrap()` on a
//! header field, `.expect()` after a try_from, etc.) surfaces fast.

#![allow(missing_docs)]

use paksmith_core::asset::Package;
use paksmith_core::asset::mappings::Usmap;
use proptest::prelude::*;

// 4 KiB cap keeps each case under a few milliseconds; larger inputs
// burn CPU on allocator churn without exercising more entry-point
// arms (everything past the magic check requires structured bytes
// that random `any::<u8>()` produces with negligible probability).
fn arb_parser_input() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..4096)
}

proptest! {
    /// `Usmap::from_bytes` on arbitrary bytes returns `Result`. The
    /// 0x30C4 magic gate rejects ~99.998% of random 2-byte prefixes,
    /// so this is primarily a canary against panics in the
    /// magic-mismatch / EOF / cap-rejection arms — not against deep
    /// parser bugs (those need corpus-driven fuzzing).
    #[test]
    fn usmap_parser_no_panic_on_arbitrary_bytes(bytes in arb_parser_input()) {
        let _ = Usmap::from_bytes(&bytes);
    }

    /// `Package::read_from` (no `.usmap`) on arbitrary bytes returns
    /// `Result`. Canary against panics in the asset summary /
    /// name-table / import-table entry rejection paths.
    #[test]
    fn package_parser_no_panic_on_arbitrary_bytes(bytes in arb_parser_input()) {
        let _ = Package::read_from(&bytes, None, None, "fuzz.uasset");
    }

    /// Same as above but with a hand-built `.usmap` supplied. Random
    /// bytes effectively never reach the unversioned dispatch
    /// branch, but the `Some(&usmap)` arg shape still exercises a
    /// distinct code path through the dispatch's argument handling
    /// — any panic there (e.g. an `.unwrap()` on the usmap in a
    /// rejection arm) wouldn't be caught by the no-usmap variant.
    #[test]
    fn package_parser_with_usmap_no_panic_on_arbitrary_bytes(
        bytes in arb_parser_input()
    ) {
        let usmap_bytes = build_empty_schema_usmap();
        let usmap = Usmap::from_bytes(&usmap_bytes)
            .expect("static minimal usmap must parse");
        let _ = Package::read_from(&bytes, None, Some(&usmap), "fuzz.uasset");
    }
}

/// Minimal valid `.usmap`: name table `["Hero", "None"]`, empty enum
/// table, single class `Hero` with `prop_count = 0, serial_count = 0`.
/// Intentionally different from the canonical
/// `testing::usmap::build_minimal_usmap_bytes` (which builds a 2-prop
/// `Hero { Health, Speed }` shape under `__test_utils`): this is the
/// smallest schema that parses cleanly, with zero decoder work to do
/// when an asset references it. The proptest only needs a `Usmap`
/// instance the dispatch will accept; it doesn't decode against the
/// schema. Inlining here avoids gating the file behind
/// `__test_utils`, so default `cargo test` runs the panic canaries.
fn build_empty_schema_usmap() -> Vec<u8> {
    let mut data: Vec<u8> = Vec::new();
    // Name table: 2 entries — ["Hero", "None"]
    data.extend_from_slice(&2u32.to_le_bytes());
    data.push(4u8);
    data.extend_from_slice(b"Hero");
    data.push(4u8);
    data.extend_from_slice(b"None");
    // Enum table: empty
    data.extend_from_slice(&0u32.to_le_bytes());
    // Schema table: 1 class, zero properties
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&0i32.to_le_bytes()); // class name idx
    data.extend_from_slice(&1i32.to_le_bytes()); // super idx ("None")
    data.extend_from_slice(&0u16.to_le_bytes()); // prop_count
    data.extend_from_slice(&0u16.to_le_bytes()); // serial_count
    // Header wrapping: magic 0x30C4 LE + version 0 + compression 0 +
    // compressed_size u32 + decompressed_size u32 + data
    let data_len = u32::try_from(data.len()).expect("usmap data within u32");
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(&[0xC4u8, 0x30u8]);
    out.push(0u8);
    out.push(0u8);
    out.extend_from_slice(&data_len.to_le_bytes());
    out.extend_from_slice(&data_len.to_le_bytes());
    out.extend_from_slice(&data);
    out
}
