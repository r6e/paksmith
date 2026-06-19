//! Integration tests for the `extract` subcommand.

use assert_cmd::Command;

#[test]
fn extract_help_lists_flags() {
    let mut cmd = Command::cargo_bin("paksmith").unwrap();
    let assert = cmd.args(["extract", "--help"]).assert().success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    for flag in [
        "--output",
        "--filter",
        "--flat",
        "--dry-run",
        "--overwrite",
        "--audio-format",
        "--datatable-format",
        "--jobs",
        "--game",
    ] {
        assert!(out.contains(flag), "help missing {flag}");
    }
}
