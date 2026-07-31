//! Integration tests for `profile detect`.
#![allow(missing_docs)]
use std::fmt::Write as _;

use tempfile::tempdir;

mod common;
use common::{
    assert_envelope_first, paksmith_json, paksmith_table, paksmith_unpinned,
    seed_registry_cache_json,
};

/// Add a profile via the CLI, then hand-append a `[profiles.<id>.detect]` table
/// into `profiles.toml`. This exercises the append-TOML round-trip path; if the
/// store rejects the hand-appended table, the seed step itself will panic.
fn seed_profile_with_detect(cfg: &std::path::Path, marker: &str) {
    let _ = paksmith_table(cfg)
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
    let out = paksmith_table(cfg.path())
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
    let out = paksmith_table(cfg.path())
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

/// The fixture key, by REFERENCE to the shared constant — re-spelling the
/// 64 hex bytes here is how the two drift.
const KEY: &str = common::FIXTURE_AES_KEY_HEX;

/// A DIFFERENT (wrong) key, so a duplicate-id test can distinguish first-wins
/// from last-wins. With both copies on the same key the assertion passes under
/// either order — and the order is the security-relevant half: `cache.get` is
/// a `.find()`, so whichever copy answers must be the one whose key
/// `--game`/`--detect` will actually use.
const WRONG_KEY: &str = "11111111111111111111111111111111111111111111111111111111111111ff";

/// The detect rules every duplicate-id test seeds, and the directory that
/// satisfies them — four tests re-spelled both.
const DUP_RULES: &str = r#"{"require_paths":["DupGame/Content/Paks"]}"#;

/// A game dir matching [`DUP_RULES`].
fn dup_game_dir() -> tempfile::TempDir {
    let game = tempdir().unwrap();
    std::fs::create_dir_all(game.path().join("DupGame/Content/Paks")).unwrap();
    game
}

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

    let _ = paksmith_table(cfg.path())
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
    let before = paksmith_table(cfg.path())
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
    let _ = paksmith_table(cfg.path())
        .args(["profile", "key", "add", "fortnite", "--key", KEY])
        .assert()
        .success();

    let after = std::fs::read_to_string(&store).unwrap();
    assert!(
        after.contains("byte_signatures") && after.contains("DEADBEEF"),
        "the rewrite dropped the rule: {after}"
    );
    let out = paksmith_table(cfg.path())
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
    let _ = paksmith_table(cfg.path())
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
        let _ = paksmith_table(cfg.path())
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
    let out = paksmith_table(cfg.path())
        .args(["profile", "detect", "/nonexistent/no/such/dir"])
        .assert()
        .failure();
    let stderr = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(
        stderr.contains("not a directory"),
        "expected not-a-directory error in stderr, got: {stderr}"
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
    assert_envelope_first(&stdout, "matches", "detect");
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
    assert_envelope_first(&stdout, "matches", "detect/empty");
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
    //    game profiles: dup, dup". Where the copies are IDENTICAL, as here,
    //    that was a profile ambiguous with itself and the suggested remedy
    //    `--game dup` would have worked. Where they DIFFER it was a true
    //    positive, and collapsing to the first copy is the deliberate trade —
    //    resolution answers with that copy anyway.
    // 2. `source: "registry"` was pinned by no test on this surface, though a
    //    core doc claims the per-surface pins are what catch a partial rename.
    //    A registry-only match exercises both at once.
    let cfg = tempdir().unwrap();
    let game = dup_game_dir();

    seed_registry_cache_json(
        cfg.path(),
        &format!(
            r#"
                 {{"id":"dup","name":"First Copy","keys":{{}},"detect":{DUP_RULES}}},
                 {{"id":"dup","name":"Second Copy","keys":{{}},"detect":{DUP_RULES}}}"#
        ),
    );

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
    let game = dup_game_dir();

    seed_registry_cache_json(
        cfg.path(),
        &format!(
            r#"
                 {{"id":"dup","name":"First Copy","keys":{{"00000000000000000000000000000000":"{KEY}"}},"detect":{DUP_RULES}}},
                 {{"id":"dup","name":"Second Copy","keys":{{"00000000000000000000000000000000":"{WRONG_KEY}"}},"detect":{DUP_RULES}}}"#
        ),
    );

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

#[test]
fn detect_ignores_rules_on_a_later_copy_of_a_duplicated_id() {
    // The ordering that makes the dedupe safe, and it is load-bearing.
    //
    // `unshadowed_registry` consumes an id at CANDIDATE selection, before
    // `rules_match` runs, so only the FIRST copy's rules are ever consulted.
    // That is deliberate: `RegistryCache::get` is a `.find()`, so the first
    // copy is the one whose KEY `--game`/`--detect` will use. Honouring a later
    // copy's rules would match on one profile and then decrypt with another's
    // key — which is exactly what this command did before the dedupe.
    //
    // Both existing duplicate tests give BOTH copies matching rules, so moving
    // the dedupe after the rules check leaves them green while silently
    // reinstating that key confusion. This is the case that distinguishes them.
    let cfg = tempdir().unwrap();
    let game = dup_game_dir();

    seed_registry_cache_json(
        cfg.path(),
        &format!(
            r#"
                 {{"id":"dup","name":"First, no rules","keys":{{"00000000000000000000000000000000":"{KEY}"}}}},
                 {{"id":"dup","name":"Second, matching rules","keys":{{}},"detect":{DUP_RULES}}}"#
        ),
    );

    let out = paksmith_json(cfg.path())
        .args(["profile", "detect"])
        .arg(game.path())
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        v["matches"].as_array().map(Vec::len),
        Some(0),
        "the first copy declares no rules, so the id must NOT detect — \
         fail closed rather than match on a copy whose key will not be used: {stdout}"
    );

    // And the flag agrees. The first copy carries a VALID key deliberately:
    // with both copies keyless, exit 2 arrived in both worlds by different
    // routes — correct tree "no profile matched", mutated tree "matched, then
    // failed to decrypt with an empty key map" — so the code alone could not
    // discriminate. Now the correct tree exits 2 (no match) while the mutated
    // tree would exit 0, matching on copy 2's rules and listing with copy 1's
    // working key.
    let _ = paksmith_unpinned(cfg.path())
        .args(["--detect"])
        .arg(game.path())
        .arg("list")
        .arg(fixture("real_v8b_encrypted_index.pak"))
        .assert()
        .code(2);
}

#[test]
fn detect_table_also_dedupes_a_repeated_registry_id() {
    // The dedupe feeds BOTH arms, so `matched N profile(s):` changes too. The
    // ROADMAP discloses that as a deliberate human-arm behaviour change; this
    // is what makes the claim pinned rather than asserted.
    let cfg = tempdir().unwrap();
    let game = dup_game_dir();

    seed_registry_cache_json(
        cfg.path(),
        &format!(
            r#"
                 {{"id":"dup","name":"First Copy","keys":{{}},"detect":{DUP_RULES}}},
                 {{"id":"dup","name":"Second Copy","keys":{{}},"detect":{DUP_RULES}}},
                 {{"id":"uniq","name":"Unique","keys":{{}},"detect":{DUP_RULES}}}"#
        ),
    );

    let out = paksmith_table(cfg.path())
        .args(["profile", "detect"])
        .arg(game.path())
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.starts_with("matched 2 profile(s):"),
        "three entries under two ids must report 2, not 3: {stdout}"
    );
    assert_eq!(
        stdout.matches("dup\t").count(),
        1,
        "the repeated id renders once: {stdout}"
    );
    assert!(
        stdout.contains("First Copy") && !stdout.contains("Second Copy"),
        "first occurrence wins in the table too: {stdout}"
    );
}
