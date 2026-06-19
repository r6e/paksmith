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
    for flag in ["--type", "--name", "--regex", "--min-size", "--max-size"] {
        assert!(out.contains(flag), "help missing {flag}");
    }
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
        v.as_array().is_some_and(|a| !a.is_empty()),
        "expected non-empty JSON array"
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
        !v.as_array().unwrap().is_empty(),
        "--type uasset should match at least one entry in the fixture"
    );
    // Every returned entry's path ends with .uasset (case-insensitive).
    for e in v.as_array().unwrap() {
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
    assert_eq!(v.as_array().unwrap().len(), 0);
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
