//! Fixture-bytes anchor — independent of repak so it runs in default
//! `cargo test` (no `--workspace` required).
//!
//! The cross-parser tests live in `crates/paksmith-fixture-gen` because
//! they need `repak`, which we keep out of routine local builds. This
//! file holds the one assertion that *doesn't* need repak: a SHA1
//! anchor on a single committed fixture, catching the silent failure
//! mode where a future repak update or accidental fixture touch
//! changes the bytes underneath us.

#![allow(missing_docs)]

use std::fmt::Write as _;
use std::path::PathBuf;

use sha1::{Digest, Sha1};

fn fixture_path(name: &str) -> PathBuf {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir.join("../../tests/fixtures").join(name)
}

fn sha1_hex(bytes: &[u8]) -> String {
    let digest: [u8; 20] = Sha1::digest(bytes).into();
    digest.iter().fold(String::with_capacity(40), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

/// Pin the exact bytes of one canonical repak-generated fixture.
///
/// Catches the silent failure mode the cross-agreement tests in the
/// `paksmith-fixture-gen` crate miss: a future repak update that subtly
/// changes its writer output (e.g., different padding, mount-point
/// encoding, hash semantics). Both Layer 1 and Layer 2 of the
/// cross-parser tests would still pass on regenerated fixtures because
/// both parsers would agree on the new bytes — but every byte-level
/// invariant downstream would have shifted underneath us.
///
/// We anchor exactly one fixture (the smallest v3 minimal, lowest blast
/// radius) so a legitimate repak update only requires updating one hex
/// string, not nine. Drift in any of the other 8 fixtures still surfaces
/// indirectly through cross-agreement asserts.
///
/// This test deliberately lives in `paksmith-core` (not the fixture-gen
/// crate) so it runs on every `cargo test` from the repo root, without
/// requiring `--workspace` to pull in repak.
///
/// # When this test fails
///
/// 1. **Investigate first** — was the fixture regenerated deliberately
///    (`cargo run -p paksmith-fixture-gen` invoked, or repak rev bumped
///    in `crates/paksmith-fixture-gen/Cargo.toml`)? If not, the file
///    was touched accidentally — restore it from git and stop.
/// 2. **If a deliberate regeneration happened**, this test catches drift
///    but not correctness. Before pasting the new SHA1, verify:
///    - All 9 `cross_parser_agreement_*` tests still pass against the
///      regenerated fixtures
///      (`cargo test -p paksmith-fixture-gen --test cross_validation`).
///    - The wire-level shape is sane. Pak layout is
///      `data records | index | footer`, so:
///      - `xxd tests/fixtures/real_v3_minimal.pak | head` — confirm
///        the file starts with the data records (you'll see the
///        `EXAMPLE_PAYLOAD_BYTES` payload near the top after a small
///        FPakEntry header).
///      - `xxd tests/fixtures/real_v3_minimal.pak | tail -n 6` —
///        confirm the index section right before the footer contains
///        the mount-point FString `../../../` and the entry filename.
///      - `xxd -s -44 tests/fixtures/real_v3_minimal.pak` — confirm
///        the trailing 44-byte legacy footer starts with the magic
///        `e1 12 6f 5a` (PAK_MAGIC = 0x5A6F12E1, little-endian),
///        followed by version (4 bytes), index_offset (8 bytes),
///        index_size (8 bytes), and the SHA1 (20 bytes). The magic is
///        at the START of the footer (`len - 44`), NOT at `len - 4`
///        — the last four bytes are the tail of the random SHA1 hash.
///    - If the repak rev changed, read the upstream changelog/diff for
///      writer-side changes to confirm the byte delta is intentional.
/// 3. **Then** paste the new hex string into `EXPECTED_SHA1` below.
#[test]
fn anchor_real_v3_minimal_fixture_bytes() {
    const EXPECTED_SHA1: &str = "8a039eeddfc2035077edc2af35b01f81dcfd31e9";
    let bytes = std::fs::read(fixture_path("real_v3_minimal.pak")).expect("anchor fixture");
    let actual = sha1_hex(&bytes);
    assert_eq!(
        actual, EXPECTED_SHA1,
        "real_v3_minimal.pak SHA1 changed: expected {EXPECTED_SHA1}, got {actual}.\n\
         If this was a deliberate fixture regeneration via \
         `cargo run -p paksmith-fixture-gen`, update EXPECTED_SHA1 in this test."
    );
}
