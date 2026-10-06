//! `--log-json`: line-delimited JSON log records on stderr, opt-in.
//!
//! Driven event: `--aes-key` + `--game` fires
//! `debug!("--aes-key overrides --game")` before any store or file I/O, so
//! the record is deterministic on every platform; the command's subsequent
//! failure on the nonexistent profile id is irrelevant.

mod common;

/// `paksmith` against `config_dir`, with the caller's `RUST_LOG` removed so
/// it cannot steer the filter.
fn log_cmd(config_dir: &std::path::Path) -> assert_cmd::Command {
    let mut c = common::paksmith_unpinned(config_dir);
    let _ = c.env_remove("RUST_LOG");
    c
}

/// Each non-empty stderr line, parsed as one JSON document.
fn json_lines(stderr: &[u8]) -> Vec<serde_json::Value> {
    std::str::from_utf8(stderr)
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            serde_json::from_str(l)
                .unwrap_or_else(|e| panic!("non-JSON stderr line under --log-json: {e}; {l:?}"))
        })
        .collect()
}

/// The one flag combination that logs before it can fail.
fn overriding_cmd(config_dir: &std::path::Path) -> assert_cmd::Command {
    let mut c = log_cmd(config_dir);
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
    let out = log_cmd(dir.path())
        .args(["-v", "--log-json", "list"])
        .arg(common::fixture_path("real_v11_minimal.pak"))
        .output()
        .unwrap();
    assert!(out.status.success(), "list must succeed on the fixture");

    let stdout = String::from_utf8(out.stdout).unwrap();
    let _: serde_json::Value =
        serde_json::from_str(&stdout).expect("piped stdout auto-resolves to the JSON payload");

    let _ = json_lines(&out.stderr);
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        !stderr.contains("note:"),
        "the piped-auto advisory is suppressed under --log-json; stderr={stderr}"
    );
}

/// [`json_lines`], after checking no raw hazard byte sequence reached
/// stderr.
fn escaped_records(stderr: &[u8]) -> Vec<serde_json::Value> {
    common::assert_no_raw_json_hazards(stderr);
    json_lines(stderr)
}

#[test]
fn log_json_escapes_del_c1_and_bidi_in_event_fields() {
    let dir = tempfile::tempdir().unwrap();
    let hostile = dir.path().join("x\u{7f}\u{9b}\u{202e}y");
    let out = log_cmd(dir.path())
        .args(["--log-json", "--aes-key", &"ab".repeat(32), "--detect"])
        .arg(&hostile)
        .arg("list")
        .arg(common::fixture_path("real_v11_minimal.pak"))
        .output()
        .unwrap();

    assert!(out.status.success(), "{out:?}");
    let records = escaped_records(&out.stderr);
    let warning = records
        .iter()
        .find(|r| {
            r["fields"]["message"]
                .as_str()
                .is_some_and(|m| m.starts_with("--detect found no unique profile"))
        })
        .unwrap_or_else(|| panic!("no --detect warning in {records:?}"));
    let error = warning["fields"]["error"].as_str().unwrap();
    assert!(error.contains(hostile.to_str().unwrap()), "{error:?}");
}

#[test]
fn log_json_escapes_span_fields() {
    let dir = tempfile::tempdir().unwrap();
    let pak = dir.path().join("C\u{9b}\u{202e}x.pak");
    let _ = std::fs::copy(common::fixture_path("real_v11_minimal.pak"), &pak).unwrap();
    let out = log_cmd(dir.path())
        .args(["-v", "--log-json", "list"])
        .arg(&pak)
        .output()
        .unwrap();

    assert!(out.status.success(), "{out:?}");
    let records = escaped_records(&out.stderr);
    let pak_open = records
        .iter()
        .filter_map(|r| r["spans"].as_array())
        .flatten()
        .find(|s| s["name"] == "pak_open")
        .unwrap_or_else(|| panic!("no record inside pak_open in {records:?}"));
    assert_eq!(pak_open["path"], pak.display().to_string());
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
