#![allow(missing_docs)]

use std::path::PathBuf;

use assert_cmd::Command;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures")
        .join(name)
}

const PAK: &str = "real_v8b_mixed_paths.pak";

#[test]
fn search_help_lists_flags() {
    let assert = Command::cargo_bin("paksmith")
        .unwrap()
        .args(["search", "--help"])
        .assert()
        .success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    for flag in [
        "--type",
        "--name",
        "--regex",
        "--min-size",
        "--max-size",
        "--filter",
    ] {
        assert!(out.contains(flag), "help missing {flag}");
    }
}

#[test]
fn search_filter_matches_full_path_glob() {
    // #652 (d): `--filter <glob>` matches the FULL virtual path, exactly
    // like list/extract — `Content/**` selects both Content entries and
    // excludes root.txt.
    let assert = Command::cargo_bin("paksmith")
        .unwrap()
        .args(["--format", "json", "search"])
        .arg(fixture(PAK))
        .args(["--filter", "Content/**"])
        .assert()
        .success();
    let v: serde_json::Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    let arr = v["entries"].as_array().unwrap();
    assert_eq!(
        arr.len(),
        2,
        "Content/** must match exactly the 2 Content entries"
    );
    for e in arr {
        assert!(
            e["path"].as_str().unwrap().starts_with("Content/"),
            "non-Content entry leaked through --filter: {e}"
        );
    }
}

#[test]
fn search_filter_composes_with_other_predicates() {
    // Predicates AND-compose, with DIVERGENT evidence: on this fixture
    // `--filter "Content/**"` alone matches 2 entries and
    // `--max-size 15` alone matches 2 (a.uasset 14 B + root.txt 15 B) —
    // only the conjunction narrows to exactly {Content/a.uasset}, so
    // deleting EITHER predicate arm from Predicates::matches fails this.
    let assert = Command::cargo_bin("paksmith")
        .unwrap()
        .args(["--format", "json", "search"])
        .arg(fixture(PAK))
        .args(["--filter", "Content/**", "--max-size", "15"])
        .assert()
        .success();
    let v: serde_json::Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    let arr = v["entries"].as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["path"], "Content/a.uasset");
}

#[test]
fn search_filter_bad_glob_exits_2_naming_flag() {
    let assert = Command::cargo_bin("paksmith")
        .unwrap()
        .arg("search")
        .arg(fixture(PAK))
        .args(["--filter", "[unclosed"])
        .assert()
        .code(2);
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(
        stderr.contains("--filter"),
        "bad glob must be attributed to --filter: {stderr}"
    );
}

#[test]
fn search_no_predicates_lists_all_as_json() {
    let assert = Command::cargo_bin("paksmith")
        .unwrap()
        .args(["--format", "json", "search"])
        .arg(fixture(PAK))
        .assert()
        .success();
    let v: serde_json::Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert!(
        v["entries"].as_array().is_some_and(|a| !a.is_empty()),
        "expected a non-empty `entries` array in the envelope"
    );
}

#[test]
fn search_type_filters_to_extension() {
    let assert = Command::cargo_bin("paksmith")
        .unwrap()
        .args(["--format", "json", "search"])
        .arg(fixture(PAK))
        .args(["--type", "uasset"])
        .assert()
        .success();
    let v: serde_json::Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert!(
        !v["entries"].as_array().unwrap().is_empty(),
        "--type uasset should match at least one entry in the fixture"
    );
    // Every returned entry's path ends with .uasset (case-insensitive).
    for e in v["entries"].as_array().unwrap() {
        let p = e["path"].as_str().unwrap().to_ascii_lowercase();
        assert!(
            p.ends_with(".uasset"),
            "non-uasset in --type uasset results: {p}"
        );
    }
}

#[test]
fn search_zero_match_is_exit_0_empty_array() {
    let assert = Command::cargo_bin("paksmith")
        .unwrap()
        .args(["--format", "json", "search"])
        .arg(fixture(PAK))
        .args(["--name", "definitely-no-such-entry-xyz"])
        .assert()
        .success(); // zero matches is NOT an error
    let v: serde_json::Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_eq!(v["entries"].as_array().unwrap().len(), 0);
}

#[test]
fn search_bad_regex_exits_2() {
    let _assert = Command::cargo_bin("paksmith")
        .unwrap()
        .args(["search"])
        .arg(fixture(PAK))
        .args(["--regex", "("])
        .assert()
        .code(2);
}

#[test]
fn search_bad_size_exits_2() {
    let _assert = Command::cargo_bin("paksmith")
        .unwrap()
        .args(["search"])
        .arg(fixture(PAK))
        .args(["--min-size", "1ZB"])
        .assert()
        .code(2);
}

#[test]
fn search_min_gt_max_exits_2() {
    let _assert = Command::cargo_bin("paksmith")
        .unwrap()
        .args(["search"])
        .arg(fixture(PAK))
        .args(["--min-size", "10", "--max-size", "5"])
        .assert()
        .code(2);
}

// Fixture entries for `real_v8b_mixed_paths.pak`:
//   Content/Subdir/Deep/nested.uasset  size=16
//   Content/a.uasset                   size=14
//   root.txt                           size=15

#[test]
fn search_regex_matches_subpath() {
    // --regex 'Subdir/.*\.uasset$' must match exactly the nested entry,
    // not a.uasset (no Subdir) or root.txt (no .uasset).
    let assert = Command::cargo_bin("paksmith")
        .unwrap()
        .args(["--format", "json", "search"])
        .arg(fixture(PAK))
        .args(["--regex", r"Subdir/.*\.uasset$"])
        .assert()
        .success();
    let v: serde_json::Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    let arr = v["entries"].as_array().unwrap();
    assert_eq!(arr.len(), 1, "expected exactly 1 match");
    assert_eq!(
        arr[0]["path"].as_str().unwrap(),
        "Content/Subdir/Deep/nested.uasset"
    );
}

#[test]
fn search_min_size_filters_out_small_entries() {
    // --min-size 1 should match all three entries (all ≥ 1 byte).
    let assert = Command::cargo_bin("paksmith")
        .unwrap()
        .args(["--format", "json", "search"])
        .arg(fixture(PAK))
        .args(["--min-size", "1"])
        .assert()
        .success();
    let v: serde_json::Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_eq!(
        v["entries"].as_array().unwrap().len(),
        3,
        "--min-size 1 should match all entries"
    );
}

#[test]
fn search_min_size_huge_returns_none() {
    // --min-size 999999999 is far beyond any fixture entry size → empty.
    let assert = Command::cargo_bin("paksmith")
        .unwrap()
        .args(["--format", "json", "search"])
        .arg(fixture(PAK))
        .args(["--min-size", "999999999"])
        .assert()
        .success();
    let v: serde_json::Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_eq!(
        v["entries"].as_array().unwrap().len(),
        0,
        "--min-size 999999999 should match no entries"
    );
}

#[test]
fn search_max_size_filters_out_large_entries() {
    // Entry sizes are 14, 15, 16. --max-size 14 → only a.uasset (14 bytes).
    let assert = Command::cargo_bin("paksmith")
        .unwrap()
        .args(["--format", "json", "search"])
        .arg(fixture(PAK))
        .args(["--max-size", "14"])
        .assert()
        .success();
    let v: serde_json::Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    let arr = v["entries"].as_array().unwrap();
    assert_eq!(arr.len(), 1, "--max-size 14 should match exactly 1 entry");
    assert_eq!(arr[0]["path"].as_str().unwrap(), "Content/a.uasset");
}
