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

/// Pin the exact bytes of canonical repak-generated fixtures, one per
/// version family.
///
/// Catches the silent failure mode the cross-agreement tests in the
/// `paksmith-fixture-gen` crate miss: a future repak update that subtly
/// changes its writer output for ONE version family (e.g., different
/// padding, mount-point encoding, hash semantics). The Layer 1 and
/// Layer 2 cross-parser tests would still pass on regenerated
/// fixtures because both parsers would agree on the new bytes — but
/// every byte-level invariant downstream would have shifted underneath
/// us.
///
/// **Round 1 (issue #18)** anchored only `real_v3_minimal.pak`. The
/// silent-failure-hunter on the Phase 1 holistic review (issue #31)
/// flagged that a repak version-specific bug would slip through if it
/// only affected, say, v8b's compression-method-table encoding —
/// because v3 is structurally distinct from v8b and the v3 anchor
/// can't catch v8b drift. Round 2 (this commit) extends anchoring to
/// one fixture per version family that paksmith claims to support:
/// v3 (legacy), v6 (DeleteRecords), v7 (EncryptionKeyGuid), v8a/v8b
/// (FName-based compression at differing slot counts), v9 (FrozenIndex),
/// v10 (PathHashIndex), v11 (Fnv64BugFix). 8 anchors total.
///
/// All anchors target the `_minimal` variant of each family — smallest
/// per-version blast radius for legitimate fixture updates. Drift in
/// the `_multi` and `_mixed_paths` fixtures still surfaces indirectly
/// via the cross-agreement tests.
///
/// These tests deliberately live in `paksmith-core` (not the
/// fixture-gen crate) so they run on every `cargo test` from the repo
/// root, without requiring `--workspace` to pull in repak.
///
/// # When one of these tests fails
///
/// 1. **Investigate first** — was the fixture regenerated deliberately
///    (`cargo run -p paksmith-fixture-gen` invoked, or repak rev bumped
///    in `crates/paksmith-fixture-gen/Cargo.toml`)? If not, the file
///    was touched accidentally — restore from git and stop.
/// 2. **If a deliberate regeneration happened**, this test catches drift
///    but not correctness. Before pasting the new SHA1, verify:
///    - All 24 `cross_parser_agreement_*` tests still pass against the
///      regenerated fixtures
///      (`cargo test -p paksmith-fixture-gen --test cross_validation`).
///    - For v3-v9: the trailing 44-byte legacy footer (or 61-byte v7+
///      footer, or 189/221-byte v8a/v8b/v9 footer) starts with the
///      magic `e1 12 6f 5a` (PAK_MAGIC = 0x5A6F12E1 little-endian).
///    - For v10/v11: the trailing 221-byte footer + path-hash + FDI
///      sections are sane. `xxd tests/fixtures/real_v11_minimal.pak |
///      head` to confirm the file starts with data records.
///    - If the repak rev changed, read the upstream changelog/diff for
///      writer-side changes to confirm the byte delta is intentional.
/// 3. **Then** paste the new hex string into the relevant `EXPECTED_SHA1`
///    constant below.
fn anchor_fixture_sha1(fixture_name: &str, expected_sha1: &str) {
    let bytes = std::fs::read(fixture_path(fixture_name))
        .unwrap_or_else(|e| panic!("read fixture `{fixture_name}`: {e}"));
    let actual = sha1_hex(&bytes);
    assert_eq!(
        actual, expected_sha1,
        "{fixture_name} SHA1 changed: expected {expected_sha1}, got {actual}.\n\
         If this was a deliberate fixture regeneration via \
         `cargo run -p paksmith-fixture-gen`, update the EXPECTED_SHA1 \
         constant in `anchor_{fixture_name}_fixture_bytes` (this test)."
    );
}

#[test]
fn anchor_real_v3_minimal_fixture_bytes() {
    anchor_fixture_sha1(
        "real_v3_minimal.pak",
        "8a039eeddfc2035077edc2af35b01f81dcfd31e9",
    );
}

#[test]
fn anchor_real_v6_minimal_fixture_bytes() {
    anchor_fixture_sha1(
        "real_v6_minimal.pak",
        "91805195d5b8293740cbc46ce272fc07ab2d61f7",
    );
}

#[test]
fn anchor_real_v7_minimal_fixture_bytes() {
    anchor_fixture_sha1(
        "real_v7_minimal.pak",
        "9d58c22a473acc14924f107db3beb73d49a65171",
    );
}

#[test]
fn anchor_real_v8a_minimal_fixture_bytes() {
    anchor_fixture_sha1(
        "real_v8a_minimal.pak",
        "c7dbe259cd5946566039636a4a659b1d71cd9dc2",
    );
}

#[test]
fn anchor_real_v8b_minimal_fixture_bytes() {
    anchor_fixture_sha1(
        "real_v8b_minimal.pak",
        "810b7490d2a4412a76b33db3c6e7a0b7f8d64f2b",
    );
}

#[test]
fn anchor_real_v9_minimal_fixture_bytes() {
    anchor_fixture_sha1(
        "real_v9_minimal.pak",
        "7865ec179cc4747459aed70524d4745a6abd7a6c",
    );
}

#[test]
fn anchor_real_v10_minimal_fixture_bytes() {
    anchor_fixture_sha1(
        "real_v10_minimal.pak",
        "b6af3240c4c9d8bd820ff1c14a654ff1efa19cb9",
    );
}

#[test]
fn anchor_real_v11_minimal_fixture_bytes() {
    anchor_fixture_sha1(
        "real_v11_minimal.pak",
        "be13d5d9769831db06ffe54ae0c0826972f6612e",
    );
}
