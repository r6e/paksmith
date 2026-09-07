//! `--log-json`: line-delimited JSON log records on stderr, opt-in.
//!
//! Driven event: `--aes-key` + `--game` fires
//! `debug!("--aes-key overrides --game")` before any store or file I/O, so
//! the record is deterministic on every platform; the command's subsequent
//! failure on the nonexistent profile id is irrelevant.

mod common;

/// The one flag combination that logs before it can fail.
fn overriding_cmd(config_dir: &std::path::Path) -> assert_cmd::Command {
    let mut c = common::paksmith_unpinned(config_dir);
    let _ = c.env_remove("RUST_LOG"); // a caller's RUST_LOG must not steer the filter
    let _ = c.args([
        "-v",
        "--aes-key",
        &"ab".repeat(32),
        "--game",
        "no-such-profile",
        "list",
        "does-not-exist.pak",
    ]);
    c
}

const OVERRIDE_MESSAGE: &str = "--aes-key overrides --game";

#[test]
fn log_json_emits_line_delimited_json_records() {
    let dir = tempfile::tempdir().unwrap();
    let out = overriding_cmd(dir.path())
        .arg("--log-json")
        .output()
        .unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();

    let record = stderr
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .find(|v| v["fields"]["message"] == OVERRIDE_MESSAGE)
        .unwrap_or_else(|| panic!("no JSON record with the driven message; stderr={stderr}"));
    assert_eq!(record["level"], "DEBUG", "record carries its level");
    assert!(
        record["target"].as_str().is_some_and(|t| !t.is_empty()),
        "record carries a target for module filtering"
    );

    // Every non-empty line is one complete JSON document, except the
    // `paksmith: error:` line — the exit-2 reporting path, exempt by contract.
    for line in stderr.lines().filter(|l| !l.trim().is_empty()) {
        if line.starts_with("paksmith: error:") {
            continue;
        }
        let _: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("non-JSON stderr line under --log-json: {e}; line={line}"));
    }
    assert!(
        stderr.lines().any(|l| l.starts_with('{')),
        "at least one JSON record was emitted; stderr={stderr}"
    );
}

#[test]
fn successful_piped_run_keeps_stderr_pure_json_lines() {
    // A succeeding piped run resolves `--format auto` to JSON and would fire
    // the piped-auto advisory; under --log-json it is suppressed, so every
    // non-empty stderr line must be a complete JSON document.
    let dir = tempfile::tempdir().unwrap();
    let mut c = common::paksmith_unpinned(dir.path());
    let _ = c.env_remove("RUST_LOG");
    let out = c
        .args(["-v", "--log-json", "list"])
        .arg(common::fixture_path("real_v11_minimal.pak"))
        .output()
        .unwrap();
    assert!(out.status.success(), "list must succeed on the fixture");

    let stdout = String::from_utf8(out.stdout).unwrap();
    let _: serde_json::Value =
        serde_json::from_str(&stdout).expect("piped stdout auto-resolves to the JSON payload");

    let stderr = String::from_utf8(out.stderr).unwrap();
    for line in stderr.lines().filter(|l| !l.trim().is_empty()) {
        let _: serde_json::Value = serde_json::from_str(line).unwrap_or_else(|e| {
            panic!("non-JSON stderr line on a successful --log-json run: {e}; line={line}")
        });
    }
    assert!(
        !stderr.contains("note:"),
        "the piped-auto advisory is suppressed under --log-json; stderr={stderr}"
    );
}

#[test]
fn default_logging_stays_human_fmt() {
    let dir = tempfile::tempdir().unwrap();
    let out = overriding_cmd(dir.path()).output().unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();

    let line = stderr
        .lines()
        .find(|l| l.contains(OVERRIDE_MESSAGE))
        .unwrap_or_else(|| panic!("the driven message must appear on stderr; stderr={stderr}"));
    assert!(
        serde_json::from_str::<serde_json::Value>(line).is_err(),
        "without --log-json the record is human fmt, not JSON: {line}"
    );
}
