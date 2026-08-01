//! Integration tests for profile-paks mode (#655): commands run WITHOUT
//! an explicit pak path, sourcing archives from the selected profile's
//! `pak_paths` glob patterns.
#![allow(missing_docs)]

use assert_cmd::Command;
use tempfile::tempdir;

fn paksmith(config_dir: &std::path::Path) -> Command {
    let mut c = Command::cargo_bin("paksmith").unwrap();
    let _ = c.env("PAKSMITH_CONFIG_DIR", config_dir);
    c
}

fn fixture(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures")
        .join(name)
}

/// `profile add <id> --pak-path <pattern>` under `cfg`.
fn add_pak_path_profile(cfg: &std::path::Path, id: &str, pattern: &str) {
    let _ = paksmith(cfg)
        // `--format table`: `profile` honours --format since #658 and auto
        // resolves to JSON off-TTY. Pinned at the two `profile` call sites
        // rather than in this file's shared helper, which also drives
        // `list`/`search`/`extract` — commands that already honoured `--format`
        // and should keep resolving it themselves.
        .args([
            "--format", "table", "profile", "add", id, "--name", id, "--pak-path", pattern,
        ])
        .assert()
        .success();
}

/// An "install dir" holding copies of both plain fixtures under `Paks/`,
/// plus a profile whose absolute glob matches them.
fn seeded_install(cfg: &std::path::Path) -> tempfile::TempDir {
    let install = tempdir().unwrap();
    let paks = install.path().join("Paks");
    std::fs::create_dir_all(&paks).unwrap();
    let _ = std::fs::copy(fixture("real_v8b_uasset.pak"), paks.join("a_uasset.pak")).unwrap();
    let _ = std::fs::copy(fixture("real_v8b_multi.pak"), paks.join("b_multi.pak")).unwrap();
    add_pak_path_profile(cfg, "hero", &paks.join("*.pak").to_string_lossy());
    install
}

#[test]
fn list_over_profile_paks_merges_archives_with_source() {
    let cfg = tempdir().unwrap();
    let _install = seeded_install(cfg.path());
    let out = paksmith(cfg.path())
        .args(["--game", "hero", "list", "--format", "json"])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let doc: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        doc["schema_version"], 1,
        "additive source key does not bump"
    );
    let entries = doc["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 4, "1 + 3 entries across both archives");
    assert!(
        entries.iter().all(|e| e["source"].is_string()),
        "every row carries its source archive: {stdout}"
    );
    let demo = entries
        .iter()
        .find(|e| e["path"] == "Game/Maps/Demo.uasset")
        .unwrap();
    assert!(
        demo["source"].as_str().unwrap().ends_with("a_uasset.pak"),
        "source names the archive the entry came from: {stdout}"
    );
    // A second, DISTINCT source proves per-row attribution — a
    // regression collapsing every row onto one source passes the
    // assertion above but not this one.
    let click = entries
        .iter()
        .find(|e| e["path"] == "Content/Sounds/click.uasset")
        .unwrap();
    assert!(
        click["source"].as_str().unwrap().ends_with("b_multi.pak"),
        "each row carries ITS archive: {stdout}"
    );
}

#[test]
fn list_explicit_path_has_no_source_key() {
    // Explicit-path invocations must stay byte-identical to pre-#655:
    // no `source` key anywhere.
    let cfg = tempdir().unwrap();
    let out = paksmith(cfg.path())
        .args(["list"])
        .arg(fixture("real_v8b_multi.pak"))
        .args(["--format", "json"])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let doc: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(
        doc["entries"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e.get("source").is_none()),
        "explicit-path rows must not carry source: {stdout}"
    );
}

#[test]
fn search_over_profile_paks_spans_archives() {
    let cfg = tempdir().unwrap();
    let _install = seeded_install(cfg.path());
    let out = paksmith(cfg.path())
        .args([
            "--game", "hero", "search", "--type", "uasset", "--format", "json",
        ])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let doc: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let paths: Vec<&str> = doc["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["path"].as_str().unwrap())
        .collect();
    assert!(
        paths.contains(&"Game/Maps/Demo.uasset") && paths.contains(&"Content/Sounds/click.uasset"),
        "matches span both archives: {paths:?}"
    );
}

#[test]
fn inspect_single_positional_locates_asset_across_profile_paks() {
    // The git-diff pattern: one positional = the asset, sourced via the
    // profile. Demo.uasset exists only in a_uasset.pak — unique hit.
    let cfg = tempdir().unwrap();
    let _install = seeded_install(cfg.path());
    let out = paksmith(cfg.path())
        .args([
            "--game",
            "hero",
            "inspect",
            "Game/Maps/Demo.uasset",
            "--format",
            "json",
        ])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let doc: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(
        doc.get("summary").is_some(),
        "full inspect output: {stdout}"
    );
}

#[test]
fn inspect_ambiguous_asset_across_profile_paks_is_an_error() {
    // The same archive under two names -> the asset exists in both ->
    // fail-closed with both archives named.
    let cfg = tempdir().unwrap();
    let install = tempdir().unwrap();
    let paks = install.path().join("Paks");
    std::fs::create_dir_all(&paks).unwrap();
    let _ = std::fs::copy(fixture("real_v8b_uasset.pak"), paks.join("a.pak")).unwrap();
    let _ = std::fs::copy(fixture("real_v8b_uasset.pak"), paks.join("b.pak")).unwrap();
    add_pak_path_profile(cfg.path(), "hero", &paks.join("*.pak").to_string_lossy());
    let out = paksmith(cfg.path())
        .args(["--game", "hero", "inspect", "Game/Maps/Demo.uasset"])
        .assert()
        .failure()
        .code(2);
    let stderr = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(
        stderr.contains("multiple archives") && stderr.contains("a.pak"),
        "ambiguity error names the archives: {stderr}"
    );
}

#[test]
fn extract_over_profile_paks_merges_summary() {
    let cfg = tempdir().unwrap();
    let _install = seeded_install(cfg.path());
    let outdir = tempdir().unwrap();
    // real_v8b_multi's entries are dummy payloads (not parseable
    // uassets), so its 3 entries are per-entry failures — exit 1
    // (partial) proves the exit code aggregates across archives.
    let out = paksmith(cfg.path())
        .args(["--game", "hero", "extract", "--format", "json", "-o"])
        .arg(outdir.path())
        .assert()
        .failure()
        .code(1);
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let doc: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let pak_label = doc["pak"].as_str().unwrap();
    assert!(
        pak_label.contains("a_uasset.pak") && pak_label.contains("b_multi.pak"),
        "summary labels every source archive: {pak_label}"
    );
    assert_eq!(doc["counts"]["failed"], 3, "failures merged: {stdout}");
    assert!(
        outdir.path().join("Game/Maps/Demo.uasset").exists(),
        "the parseable archive's output is on disk"
    );
}

#[test]
fn inspect_asset_absent_from_every_profile_archive_is_not_found() {
    // Kills `delete match arm 0` in select_containing_pak: zero
    // containing archives must surface EntryNotFound, not fall through
    // to the multiple-archives ambiguity error.
    let cfg = tempdir().unwrap();
    let _install = seeded_install(cfg.path());
    let out = paksmith(cfg.path())
        .args(["--game", "hero", "inspect", "Game/Maps/Absent.uasset"])
        .assert()
        .failure()
        .code(2);
    let stderr = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(
        stderr.contains("Game/Maps/Absent.uasset") && !stderr.contains("multiple archives"),
        "absent asset is not-found, never ambiguity: {stderr}"
    );
}

#[test]
fn single_archive_profile_mode_still_carries_source() {
    // Kills `replace match guard explicit_path with true` in
    // print_entry_groups: source presence is decided by MODE, not by
    // archive count — a profile whose patterns match exactly one
    // archive still emits per-row provenance.
    let cfg = tempdir().unwrap();
    let install = tempdir().unwrap();
    let paks = install.path().join("Paks");
    std::fs::create_dir_all(&paks).unwrap();
    let _ = std::fs::copy(fixture("real_v8b_multi.pak"), paks.join("only.pak")).unwrap();
    add_pak_path_profile(cfg.path(), "hero", &paks.join("*.pak").to_string_lossy());
    let out = paksmith(cfg.path())
        .args(["--game", "hero", "list", "--format", "json"])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let doc: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let entries = doc["entries"].as_array().unwrap();
    assert!(
        !entries.is_empty() && entries.iter().all(|e| e["source"].is_string()),
        "single-archive profile mode still attributes rows: {stdout}"
    );
}

#[test]
fn overlapping_archives_extract_without_spurious_failures() {
    // The UE base+patch layout: the same virtual path in two archives.
    // Pre-fix this produced a create_new per-entry failure (exit 1) for
    // every shadowed path; the winner map extracts each path once, from
    // the LAST archive in sorted order (UE alphabetical-mount
    // semantics), and the run is clean.
    let cfg = tempdir().unwrap();
    let install = tempdir().unwrap();
    let paks = install.path().join("Paks");
    std::fs::create_dir_all(&paks).unwrap();
    let _ = std::fs::copy(fixture("real_v8b_uasset.pak"), paks.join("base.pak")).unwrap();
    let _ = std::fs::copy(fixture("real_v8b_uasset.pak"), paks.join("zpatch.pak")).unwrap();
    add_pak_path_profile(cfg.path(), "hero", &paks.join("*.pak").to_string_lossy());
    let outdir = tempdir().unwrap();
    let out = paksmith(cfg.path())
        .args(["--game", "hero", "extract", "--format", "json", "-o"])
        .arg(outdir.path())
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let doc: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        doc["counts"]["failed"], 0,
        "no spurious collisions: {stdout}"
    );
    assert_eq!(
        doc["counts"]["raw_copied"], 1,
        "each path extracts once: {stdout}"
    );
    let sources = doc["sources"].as_array().unwrap();
    assert_eq!(sources.len(), 2, "machine-readable source list: {stdout}");
    // The shipped fixture's one entry raw-copies; its output record
    // exists exactly once (the zpatch copy won, base was shadowed).
    assert_eq!(doc["outputs"].as_array().unwrap().len(), 1);
}

#[test]
fn explicit_path_extract_summary_has_no_sources_key() {
    // Explicit-path summaries stay byte-compatible: no `sources` key.
    let cfg = tempdir().unwrap();
    let outdir = tempdir().unwrap();
    let out = paksmith(cfg.path())
        .args(["extract", "--format", "json", "-o"])
        .arg(outdir.path())
        .arg(fixture("real_v8b_uasset.pak"))
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let doc: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(doc.get("sources").is_none(), "no sources key: {stdout}");
}

#[test]
fn no_path_and_no_selector_is_a_loud_error() {
    let cfg = tempdir().unwrap();
    let out = paksmith(cfg.path())
        .args(["list"])
        .assert()
        .failure()
        .code(2);
    let stderr = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(
        stderr.contains("profile selector"),
        "missing path + missing selector must explain itself: {stderr}"
    );
}

#[test]
fn profile_without_pak_paths_is_a_loud_error() {
    let cfg = tempdir().unwrap();
    let _ = paksmith(cfg.path())
        .args([
            "--format", "table", "profile", "add", "plain", "--name", "Plain",
        ])
        .assert()
        .success();
    let out = paksmith(cfg.path())
        .args(["--game", "plain", "list"])
        .assert()
        .failure()
        .code(2);
    let stderr = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(
        stderr.contains("no pak_paths"),
        "the NoPakPaths fault must surface: {stderr}"
    );
}

#[test]
fn relative_pattern_resolves_against_detect_dir() {
    // Acceptance (b): detection populates concrete pak locations at run
    // time — a relative pattern joins the --detect install dir.
    let cfg = tempdir().unwrap();
    let install = tempdir().unwrap();
    let paks = install.path().join("Paks");
    std::fs::create_dir_all(&paks).unwrap();
    let _ = std::fs::copy(fixture("real_v8b_multi.pak"), paks.join("game.pak")).unwrap();
    add_pak_path_profile(cfg.path(), "hero", "Paks/*.pak");
    // Detect rules have no `profile add` flag; seed them by appending a
    // TOML table (the detect_cli.rs pattern — the store round-trips it
    // or the run below fails on CorruptStore).
    let store_path = cfg.path().join("paksmith/profiles.toml");
    let mut text = std::fs::read_to_string(&store_path).unwrap();
    text.push_str("\n[profiles.hero.detect]\nrequire_paths = [\"Paks\"]\n");
    std::fs::write(&store_path, text).unwrap();
    let out = paksmith(cfg.path())
        .args(["--detect"])
        .arg(install.path())
        .args(["list", "--format", "json"])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let doc: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        doc["entries"].as_array().unwrap().len(),
        3,
        "relative pattern expanded against the detect dir: {stdout}"
    );
}
