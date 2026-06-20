//! Integration tests for the `profile` subcommand.
#![allow(missing_docs)]

use assert_cmd::Command;
use tempfile::tempdir;

fn paksmith(config_dir: &std::path::Path) -> Command {
    let mut c = Command::cargo_bin("paksmith").unwrap();
    let _ = c.env("PAKSMITH_CONFIG_DIR", config_dir);
    c
}

#[test]
fn add_list_show_remove_roundtrip() {
    let cfg = tempdir().unwrap();
    // add
    let _add = paksmith(cfg.path())
        .args([
            "profile",
            "add",
            "fortnite",
            "--name",
            "Fortnite",
            "--engine-version",
            "5.3",
        ])
        .assert()
        .success();
    // list shows it
    let out = paksmith(cfg.path())
        .args(["profile", "list"])
        .assert()
        .success();
    let txt = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(txt.contains("fortnite"), "list shows the id: {txt}");
    assert!(txt.contains("Fortnite"), "list shows the name: {txt}");
    // show
    let shown = paksmith(cfg.path())
        .args(["profile", "show", "fortnite"])
        .assert()
        .success();
    let stxt = String::from_utf8(shown.get_output().stdout.clone()).unwrap();
    assert!(stxt.contains("5.3"), "show includes engine version: {stxt}");
    // remove
    let _remove = paksmith(cfg.path())
        .args(["profile", "remove", "fortnite"])
        .assert()
        .success();
    let out2 = paksmith(cfg.path())
        .args(["profile", "list"])
        .assert()
        .success();
    let txt2 = String::from_utf8(out2.get_output().stdout.clone()).unwrap();
    assert!(
        !txt2.contains("fortnite"),
        "removed profile is gone: {txt2}"
    );
}

#[test]
fn show_unknown_profile_exits_2() {
    let cfg = tempdir().unwrap();
    let _assert = paksmith(cfg.path())
        .args(["profile", "show", "nope"])
        .assert()
        .code(2);
}

#[test]
fn add_duplicate_id_is_rejected() {
    let cfg = tempdir().unwrap();
    let _add1 = paksmith(cfg.path())
        .args(["profile", "add", "g", "--name", "G"])
        .assert()
        .success();
    let _add2 = paksmith(cfg.path())
        .args(["profile", "add", "g", "--name", "G2"])
        .assert()
        .code(2);
}

#[test]
fn remove_unknown_profile_exits_2() {
    let cfg = tempdir().unwrap();
    let _assert = paksmith(cfg.path())
        .args(["profile", "remove", "nope"])
        .assert()
        .code(2);
}

#[test]
fn show_redacts_keys_by_default() {
    let cfg = tempdir().unwrap();
    let _add = paksmith(cfg.path())
        .args(["profile", "add", "g", "--name", "G"])
        .assert()
        .success();
    // Verify show on a no-key profile succeeds and contains a "keys:" section.
    let out = paksmith(cfg.path())
        .args(["profile", "show", "g"])
        .assert()
        .success();
    let txt = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(
        txt.contains("keys:"),
        "show output contains keys section: {txt}"
    );
    // No raw 64-hex key material should appear.
    assert!(
        !txt.contains(&"a".repeat(64)),
        "show must not expose raw key hex by default: {txt}"
    );
}

#[test]
fn list_empty_is_success() {
    let cfg = tempdir().unwrap();
    let _assert = paksmith(cfg.path())
        .args(["profile", "list"])
        .assert()
        .success();
}

const KEY: &str = "94d25bc3aeb420e0be914edc9d5435a1eaab5f2864e09e94019ac205b727a7de";

fn fixture(name: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures")
        .join(name)
}

#[test]
fn key_add_then_show_redacts_then_reveals() {
    let cfg = tempdir().unwrap();
    let _ = paksmith(cfg.path())
        .args(["profile", "add", "g", "--name", "G"])
        .assert()
        .success();
    // add a default (zero-guid) key
    let _ = paksmith(cfg.path())
        .args(["profile", "key", "add", "g", "--key", KEY])
        .assert()
        .success();
    // show redacts by default
    let red = paksmith(cfg.path())
        .args(["profile", "show", "g"])
        .assert()
        .success();
    let rtxt = String::from_utf8(red.get_output().stdout.clone()).unwrap();
    assert!(rtxt.contains("<redacted>"), "default show redacts: {rtxt}");
    assert!(
        !rtxt.contains(KEY),
        "default show must not leak the key: {rtxt}"
    );
    // --show-keys reveals
    let rev = paksmith(cfg.path())
        .args(["profile", "show", "g", "--show-keys"])
        .assert()
        .success();
    let vtxt = String::from_utf8(rev.get_output().stdout.clone()).unwrap();
    assert!(vtxt.contains(KEY), "--show-keys reveals: {vtxt}");
}

#[test]
fn profile_test_reports_verified_for_correct_key() {
    let cfg = tempdir().unwrap();
    let _ = paksmith(cfg.path())
        .args(["profile", "add", "g", "--name", "G"])
        .assert()
        .success();
    let _ = paksmith(cfg.path())
        .args(["profile", "key", "add", "g", "--key", KEY])
        .assert()
        .success();
    let out = paksmith(cfg.path())
        .args(["profile", "test", "g"])
        .arg(fixture("real_v8b_encrypted_index.pak"))
        .assert()
        .success();
    let txt = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(
        txt.to_lowercase().contains("verified"),
        "correct key reports verified: {txt}"
    );
}

#[test]
fn key_add_bad_hex_exits_2() {
    let cfg = tempdir().unwrap();
    let _ = paksmith(cfg.path())
        .args(["profile", "add", "g", "--name", "G"])
        .assert()
        .success();
    let _ = paksmith(cfg.path())
        .args(["profile", "key", "add", "g", "--key", "nothex"])
        .assert()
        .code(2);
}

// ── key remove ────────────────────────────────────────────────────────────────

#[test]
fn key_remove_happy_path() {
    let cfg = tempdir().unwrap();
    let _ = paksmith(cfg.path())
        .args(["profile", "add", "g", "--name", "G"])
        .assert()
        .success();
    // add a default (zero-guid) key
    let _ = paksmith(cfg.path())
        .args(["profile", "key", "add", "g", "--key", KEY])
        .assert()
        .success();
    // remove by zero guid (32 zeros)
    let _ = paksmith(cfg.path())
        .args([
            "profile",
            "key",
            "remove",
            "g",
            "--guid",
            "00000000000000000000000000000000",
        ])
        .assert()
        .success();
    // show must no longer contain the key material or <redacted>
    let out = paksmith(cfg.path())
        .args(["profile", "show", "g"])
        .assert()
        .success();
    let txt = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(
        !txt.contains("<redacted>"),
        "after remove, no redacted entry expected: {txt}"
    );
    assert!(!txt.contains(KEY), "after remove, key must be gone: {txt}");
}

#[test]
fn key_remove_missing_guid_exits_2() {
    let cfg = tempdir().unwrap();
    let _ = paksmith(cfg.path())
        .args(["profile", "add", "g", "--name", "G"])
        .assert()
        .success();
    // profile has no keys; attempt to remove a non-existent GUID → NoKeyForGuid → exit 2
    let _ = paksmith(cfg.path())
        .args([
            "profile",
            "key",
            "remove",
            "g",
            "--guid",
            "deadbeefdeadbeefdeadbeefdeadbeef",
        ])
        .assert()
        .code(2);
}

#[test]
fn key_remove_unknown_profile_exits_2() {
    let cfg = tempdir().unwrap();
    // no profiles at all — ProfileNotFound → exit 2
    let _ = paksmith(cfg.path())
        .args([
            "profile",
            "key",
            "remove",
            "nope",
            "--guid",
            "00000000000000000000000000000000",
        ])
        .assert()
        .code(2);
}

// ── profile test negative paths ───────────────────────────────────────────────

#[test]
fn profile_test_wrong_key_exits_1() {
    let cfg = tempdir().unwrap();
    let _ = paksmith(cfg.path())
        .args(["profile", "add", "g", "--name", "G"])
        .assert()
        .success();
    // 64 hex zeros = a valid AES key that is NOT the correct key for the fixture
    let _ = paksmith(cfg.path())
        .args(["profile", "key", "add", "g", "--key", &"00".repeat(32)])
        .assert()
        .success();
    let out = paksmith(cfg.path())
        .args(["profile", "test", "g"])
        .arg(fixture("real_v8b_encrypted_index.pak"))
        .assert()
        .code(1);
    let txt = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(
        txt.to_lowercase().contains("wrong key"),
        "wrong-key failure must mention 'wrong key': {txt}"
    );
}

#[test]
fn profile_test_no_key_for_guid_exits_2() {
    let cfg = tempdir().unwrap();
    let _ = paksmith(cfg.path())
        .args(["profile", "add", "g", "--name", "G"])
        .assert()
        .success();
    // Add the correct key but under a NON-zero GUID only — no zero-default entry.
    // The fixture's GUID is all-zero, so resolve_key will find no entry → NoKeyForGuid → exit 2.
    let _ = paksmith(cfg.path())
        .args([
            "profile",
            "key",
            "add",
            "g",
            "--key",
            KEY,
            "--guid",
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
        ])
        .assert()
        .success();
    let _ = paksmith(cfg.path())
        .args(["profile", "test", "g"])
        .arg(fixture("real_v8b_encrypted_index.pak"))
        .assert()
        .code(2);
}

// ── key add --guid bad-hex ────────────────────────────────────────────────────

#[test]
fn key_add_bad_guid_exits_2() {
    let cfg = tempdir().unwrap();
    let _ = paksmith(cfg.path())
        .args(["profile", "add", "g", "--name", "G"])
        .assert()
        .success();
    let _ = paksmith(cfg.path())
        .args([
            "profile", "key", "add", "g", "--key", KEY, "--guid", "nothex",
        ])
        .assert()
        .code(2);
}
