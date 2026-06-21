//! Integration tests for `profile detect`.
#![allow(missing_docs)]
use std::fmt::Write as _;

use assert_cmd::Command;
use tempfile::tempdir;

fn paksmith(cfg: &std::path::Path) -> Command {
    let mut c = Command::cargo_bin("paksmith").unwrap();
    let _ = c.env("PAKSMITH_CONFIG_DIR", cfg);
    c
}

/// Add a profile via the CLI, then hand-append a `[profiles.<id>.detect]` table
/// into `profiles.toml`. This exercises the append-TOML round-trip path; if the
/// store rejects the hand-appended table, the seed step itself will panic.
fn seed_profile_with_detect(cfg: &std::path::Path, marker: &str) {
    let _ = paksmith(cfg)
        .args(["profile", "add", "fortnite", "--name", "Fortnite"])
        .assert()
        .success();
    let store = cfg.join("paksmith/profiles.toml");
    let mut s = std::fs::read_to_string(&store).unwrap();
    write!(
        s,
        "\n[profiles.fortnite.detect]\nrequire_paths = [\"{marker}\"]\n"
    )
    .unwrap();
    std::fs::write(&store, s).unwrap();
}

#[test]
fn detect_lists_matching_local_profile() {
    let cfg = tempdir().unwrap();
    let game = tempdir().unwrap();
    std::fs::create_dir_all(game.path().join("FortniteGame/Content/Paks")).unwrap();
    seed_profile_with_detect(cfg.path(), "FortniteGame/Content/Paks");
    let out = paksmith(cfg.path())
        .args(["profile", "detect"])
        .arg(game.path())
        .assert()
        .success();
    let txt = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(
        txt.contains("fortnite"),
        "detect lists the matched id: {txt}"
    );
}

#[test]
fn detect_no_match_is_success_with_message() {
    let cfg = tempdir().unwrap();
    let game = tempdir().unwrap();
    // marker path is NOT created in game dir — must not match
    seed_profile_with_detect(cfg.path(), "FortniteGame/Content/Paks");
    let out = paksmith(cfg.path())
        .args(["profile", "detect"])
        .arg(game.path())
        .assert()
        .success();
    let txt = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(
        txt.to_lowercase().contains("no profiles matched"),
        "no-match message: {txt}"
    );
}
