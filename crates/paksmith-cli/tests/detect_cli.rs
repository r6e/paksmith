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

// ---------------------------------------------------------------------------
// Task 5: --detect <dir> flag tests
// ---------------------------------------------------------------------------

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
fn detect_flag_resolves_single_match_key() {
    let cfg = tempdir().unwrap();
    let game = tempdir().unwrap();
    std::fs::create_dir_all(game.path().join("FortniteGame/Content/Paks")).unwrap();
    seed_profile_with_detect(cfg.path(), "FortniteGame/Content/Paks");
    // Give the profile the fixture's default key so --detect can decrypt it.
    let _ = paksmith(cfg.path())
        .args(["profile", "key", "add", "fortnite", "--key", KEY])
        .assert()
        .success();
    // --detect <game-dir> list <encrypted-index fixture> → succeeds + lists entries.
    let out = paksmith(cfg.path())
        .args(["--detect"])
        .arg(game.path())
        .arg("list")
        .arg(fixture("real_v8b_encrypted_index.pak"))
        .assert()
        .success();
    assert!(
        String::from_utf8(out.get_output().stdout.clone())
            .unwrap()
            .contains("test.txt"),
        "listing should include test.txt"
    );
}

#[test]
fn detect_flag_no_match_exits_nonzero() {
    let cfg = tempdir().unwrap();
    let game = tempdir().unwrap();
    // Marker path is NOT created in game dir — must not match.
    seed_profile_with_detect(cfg.path(), "FortniteGame/Content/Paks");
    let out = paksmith(cfg.path())
        .args(["--detect"])
        .arg(game.path())
        .arg("list")
        .arg(fixture("real_v8b_encrypted_index.pak"))
        .assert()
        .failure();
    let stderr = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(
        stderr.contains("no game profile matched directory"),
        "expected no-match error in stderr, got: {stderr}"
    );
}

#[test]
fn detect_flag_ambiguous_exits_nonzero() {
    let cfg = tempdir().unwrap();
    let game = tempdir().unwrap();
    std::fs::create_dir_all(game.path().join("Common")).unwrap();
    // Two local profiles, both matching "Common".
    for id in ["g1", "g2"] {
        let _ = paksmith(cfg.path())
            .args(["profile", "add", id, "--name", id])
            .assert()
            .success();
    }
    let store = cfg.path().join("paksmith/profiles.toml");
    let mut s = std::fs::read_to_string(&store).unwrap();
    s.push_str(
        "\n[profiles.g1.detect]\nrequire_paths = [\"Common\"]\n\
         [profiles.g2.detect]\nrequire_paths = [\"Common\"]\n",
    );
    std::fs::write(&store, s).unwrap();
    let out = paksmith(cfg.path())
        .args(["--detect"])
        .arg(game.path())
        .arg("list")
        .arg(fixture("real_v8b_encrypted_index.pak"))
        .assert()
        .failure();
    let stderr = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(
        stderr.contains("matched multiple game profiles"),
        "expected ambiguous error in stderr, got: {stderr}"
    );
}

#[test]
fn detect_flag_nonexistent_dir_exits_nonzero() {
    let cfg = tempdir().unwrap();
    let out = paksmith(cfg.path())
        .args(["--detect", "/nonexistent/no/such/dir"])
        .arg("list")
        .arg(fixture("real_v8b_encrypted_index.pak"))
        .assert()
        .failure();
    let stderr = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(
        stderr.contains("not a directory"),
        "expected not-a-directory error in stderr, got: {stderr}"
    );
}

#[test]
fn detect_query_nonexistent_dir_exits_nonzero() {
    let cfg = tempdir().unwrap();
    let out = paksmith(cfg.path())
        .args(["profile", "detect", "/nonexistent/no/such/dir"])
        .assert()
        .failure();
    let stderr = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(
        stderr.contains("not a directory"),
        "expected not-a-directory error in stderr, got: {stderr}"
    );
}
