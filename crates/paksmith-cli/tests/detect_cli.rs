//! Integration tests for `profile detect`.
#![allow(missing_docs)]
use std::fmt::Write as _;

use assert_cmd::Command;
use tempfile::tempdir;

/// A `paksmith` invocation pinned to TABLE output, for this file's
/// `profile`-family assertions.
///
/// `profile detect` honours `--format` since #658, and `--format auto`
/// resolves to JSON whenever stdout is not a TTY — always true under
/// `assert_cmd`. Tests asserting on human output must ask for the table
/// explicitly, as `cli_integration`'s `list ... --format table` already does.
///
/// The `--detect … list <pak>` tests use [`paksmith_unpinned`] instead.
fn paksmith(cfg: &std::path::Path) -> Command {
    let mut c = Command::cargo_bin("paksmith").unwrap();
    let _ = c.env("PAKSMITH_CONFIG_DIR", cfg);
    let _ = c.args(["--format", "table"]);
    c
}

/// A `paksmith` invocation with NO `--format`, exercising the default
/// resolution.
///
/// For the `--detect … list <pak>` tests, whose subject is the global
/// `--detect` flag rather than `profile`. `list` already honoured `--format`
/// before #658, so off-TTY these have always asserted against the JSON
/// writer; pinning them to the table would be an undeclared coverage shift
/// dressed as consistency.
fn paksmith_unpinned(cfg: &std::path::Path) -> Command {
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

/// A NON-EMPTY `byte_signatures` must survive a store REWRITE: `profile key add`
/// rewrites every profile, and nothing else exercises a rule at
/// `[[profiles.<id>.detect.byte_signatures]]` depth.
///
/// Scope, measured rather than assumed. This does NOT pin the
/// `skip_serializing_if` decision — dropping that attribute leaves this test
/// green, and core's `empty_byte_signatures_is_omitted_from_toml` is what pins
/// it. What fails here is the attribute made UNCONDITIONAL, i.e. a rewrite
/// dropping a non-empty rule. There is no field-order hazard to catch either:
/// the serializer emits values before tables whatever the declaration order.
#[test]
fn byte_signatures_survive_a_store_rewrite() {
    let cfg = tempdir().unwrap();
    let game = tempdir().unwrap();
    std::fs::write(game.path().join("game.exe"), [0xDE, 0xAD, 0xBE, 0xEF]).unwrap();

    let _ = paksmith(cfg.path())
        .args(["profile", "add", "fortnite", "--name", "Fortnite"])
        .assert()
        .success();
    let store = cfg.path().join("paksmith/profiles.toml");
    let mut s = std::fs::read_to_string(&store).unwrap();
    write!(
        s,
        "\n[[profiles.fortnite.detect.byte_signatures]]\npath = \"game.exe\"\nhex = \"DEADBEEF\"\n"
    )
    .unwrap();
    std::fs::write(&store, s).unwrap();

    // Matches before any rewrite, so a later failure is the rewrite's doing.
    let before = paksmith(cfg.path())
        .args(["profile", "detect"])
        .arg(game.path())
        .assert()
        .success();
    assert!(
        String::from_utf8(before.get_output().stdout.clone())
            .unwrap()
            .contains("fortnite"),
        "the hand-seeded byte signature must match"
    );

    // `key add` rewrites EVERY profile, nested table-array included.
    let _ = paksmith(cfg.path())
        .args(["profile", "key", "add", "fortnite", "--key", KEY])
        .assert()
        .success();

    let after = std::fs::read_to_string(&store).unwrap();
    assert!(
        after.contains("byte_signatures") && after.contains("DEADBEEF"),
        "the rewrite dropped the rule: {after}"
    );
    let out = paksmith(cfg.path())
        .args(["profile", "detect"])
        .arg(game.path())
        .assert()
        .success();
    assert!(
        String::from_utf8(out.get_output().stdout.clone())
            .unwrap()
            .contains("fortnite"),
        "the rule must still match after the rewrite"
    );
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
    let out = paksmith_unpinned(cfg.path())
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
    let out = paksmith_unpinned(cfg.path())
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
    let out = paksmith_unpinned(cfg.path())
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
    let out = paksmith_unpinned(cfg.path())
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

/// A `paksmith` invocation pinned to JSON output (#658).
fn paksmith_json(cfg: &std::path::Path) -> Command {
    let mut c = Command::cargo_bin("paksmith").unwrap();
    let _ = c.env("PAKSMITH_CONFIG_DIR", cfg);
    let _ = c.args(["--format", "json"]);
    c
}

/// `schema_version` must be the FIRST key in the raw bytes, not merely
/// present — asserting presence passes on any envelope, including one that
/// emits it last. Mirrors `profile_cli::assert_envelope_first`.
fn assert_envelope_first(stdout: &str, ctx: &str) {
    let after_brace = stdout
        .trim_start()
        .strip_prefix('{')
        .unwrap_or_else(|| panic!("{ctx}: not a JSON object: {stdout}"))
        .trim_start();
    assert!(
        after_brace.starts_with("\"schema_version\""),
        "{ctx}: schema_version must be the FIRST key, got: {stdout}"
    );
}

#[test]
fn detect_json_carries_envelope_dir_and_matches() {
    // `detect --format json` had NO test at all: its schema constant, its
    // `dir` field and its rows were entirely unpinned, so hardcoding any of
    // them survived the suite.
    let cfg = tempdir().unwrap();
    let game = tempdir().unwrap();
    std::fs::create_dir_all(game.path().join("FortniteGame/Content/Paks")).unwrap();
    seed_profile_with_detect(cfg.path(), "FortniteGame/Content/Paks");

    let out = paksmith_json(cfg.path())
        .args(["profile", "detect"])
        .arg(game.path())
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert_envelope_first(&stdout, "detect");
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["schema_version"], 1);
    assert_eq!(
        v["dir"],
        game.path().display().to_string(),
        "dir echoes the probed directory: {stdout}"
    );
    let m = &v["matches"][0];
    assert_eq!(m["id"], "fortnite");
    assert_eq!(m["name"], "Fortnite");
    assert_eq!(m["source"], "local", "exact wire token: {stdout}");
}

#[test]
fn detect_json_emits_an_empty_array_when_nothing_matches() {
    // The divergent case: the table prints "no profiles matched <dir>" and
    // exits 0, so JSON must emit the SAME envelope with an empty array —
    // not a message, not an error, not a bare `{}`.
    let cfg = tempdir().unwrap();
    let game = tempdir().unwrap();
    seed_profile_with_detect(cfg.path(), "SomeOtherGame/Content/Paks");

    let out = paksmith_json(cfg.path())
        .args(["profile", "detect"])
        .arg(game.path())
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert_envelope_first(&stdout, "detect/empty");
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        v["matches"].as_array().map(Vec::len),
        Some(0),
        "no matches is an empty array, not an absent key: {stdout}"
    );
    assert!(
        !stdout.contains("no profiles matched"),
        "the human message must not leak into the document: {stdout}"
    );
}

#[test]
fn detect_json_dedupes_a_repeated_registry_id_and_labels_it_registry() {
    // Two findings in one test, deliberately.
    //
    // 1. `detect.matches` is an array consumers key by id, and core's
    //    `detect_in` only skipped ids shadowed by the LOCAL store — a registry
    //    document repeating an id (nothing validates uniqueness) produced two
    //    rows for one profile. `--detect` then failed with "matched multiple
    //    game profiles: dup, dup" — a profile ambiguous with ITSELF, whose
    //    suggested remedy `--game dup` would have worked.
    // 2. `source: "registry"` was pinned by no test on this surface, though a
    //    core doc claims the per-surface pins are what catch a partial rename.
    //    A registry-only match exercises both at once.
    let cfg = tempdir().unwrap();
    let game = tempdir().unwrap();
    std::fs::create_dir_all(game.path().join("DupGame/Content/Paks")).unwrap();

    let base = cfg.path().join("paksmith");
    std::fs::create_dir_all(&base).unwrap();
    let rules = r#"{"require_paths":["DupGame/Content/Paks"]}"#;
    std::fs::write(
        base.join("registry-cache.json"),
        format!(
            r#"{{"fetched_at_unix":9999999999,"profiles":[
                 {{"id":"dup","name":"First Copy","keys":{{}},"detect":{rules}}},
                 {{"id":"dup","name":"Second Copy","keys":{{}},"detect":{rules}}}]}}"#
        ),
    )
    .unwrap();

    let out = paksmith_json(cfg.path())
        .args(["profile", "detect"])
        .arg(game.path())
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let matches = v["matches"].as_array().unwrap();

    assert_eq!(
        matches.len(),
        1,
        "a repeated registry id must match ONCE: {stdout}"
    );
    assert_eq!(matches[0]["id"], "dup");
    assert_eq!(
        matches[0]["name"], "First Copy",
        "first occurrence wins, as RegistryCache::get's .find() does: {stdout}"
    );
    assert_eq!(
        matches[0]["source"], "registry",
        "exact wire token on the registry arm: {stdout}"
    );
}

#[test]
fn detect_flag_resolves_a_repeated_registry_id_instead_of_calling_it_ambiguous() {
    // The user-visible half of the same defect: `--detect` requires exactly
    // one match, so before the dedupe a duplicated id was reported ambiguous
    // with itself and exited 2.
    let cfg = tempdir().unwrap();
    let game = tempdir().unwrap();
    std::fs::create_dir_all(game.path().join("DupGame/Content/Paks")).unwrap();

    let base = cfg.path().join("paksmith");
    std::fs::create_dir_all(&base).unwrap();
    let rules = r#"{"require_paths":["DupGame/Content/Paks"]}"#;
    std::fs::write(
        base.join("registry-cache.json"),
        format!(
            r#"{{"fetched_at_unix":9999999999,"profiles":[
                 {{"id":"dup","name":"First Copy","keys":{{"00000000000000000000000000000000":"{KEY}"}},"detect":{rules}}},
                 {{"id":"dup","name":"Second Copy","keys":{{"00000000000000000000000000000000":"{KEY}"}},"detect":{rules}}}]}}"#
        ),
    )
    .unwrap();

    let out = paksmith_unpinned(cfg.path())
        .args(["--detect"])
        .arg(game.path())
        .arg("list")
        .arg(fixture("real_v8b_encrypted_index.pak"))
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.contains("test.txt"),
        "the duplicated id must resolve to one profile and decrypt: {stdout}"
    );
}
