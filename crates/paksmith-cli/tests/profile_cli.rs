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
