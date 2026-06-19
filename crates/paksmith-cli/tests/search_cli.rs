#![allow(missing_docs)]
use assert_cmd::Command;

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
