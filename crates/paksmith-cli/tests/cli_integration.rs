#![allow(missing_docs, unused_results)]

use assert_cmd::Command;
use predicates::prelude::*;

fn fixture_path(name: &str) -> String {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .join("../../tests/fixtures")
        .join(name)
        .display()
        .to_string()
}

#[test]
fn list_json_output() {
    let mut cmd = Command::cargo_bin("paksmith").unwrap();
    cmd.args(["list", &fixture_path("minimal_v6.pak"), "--format", "json"]);

    let output = cmd.output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();

    let entries: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let arr = entries.as_array().unwrap();
    assert_eq!(arr.len(), 3);

    let paths: Vec<&str> = arr.iter().map(|e| e["path"].as_str().unwrap()).collect();
    assert!(paths.contains(&"Content/Textures/hero.uasset"));
    assert!(paths.contains(&"Content/Maps/level01.umap"));
    assert!(paths.contains(&"Content/Sounds/bgm.uasset"));
}

#[test]
fn list_table_output() {
    let mut cmd = Command::cargo_bin("paksmith").unwrap();
    cmd.args(["list", &fixture_path("minimal_v6.pak"), "--format", "table"]);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("hero.uasset"))
        .stdout(predicate::str::contains("level01.umap"))
        .stdout(predicate::str::contains("bgm.uasset"));
}

#[test]
fn list_format_auto_resolves_to_json_when_piped() {
    // Under assert_cmd, stdout is captured (not a TTY), so --format auto
    // should produce JSON.
    let mut cmd = Command::cargo_bin("paksmith").unwrap();
    cmd.args(["list", &fixture_path("minimal_v6.pak")]);

    let output = cmd.output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();

    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("auto format should produce JSON when not a TTY");
    assert_eq!(parsed.as_array().unwrap().len(), 3);
}

#[test]
fn list_with_filter() {
    let mut cmd = Command::cargo_bin("paksmith").unwrap();
    cmd.args([
        "list",
        &fixture_path("minimal_v6.pak"),
        "--format",
        "json",
        "--filter",
        "*.uasset",
    ]);

    let output = cmd.output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();

    let entries: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let arr = entries.as_array().unwrap();
    assert_eq!(arr.len(), 2); // hero.uasset and bgm.uasset, not level01.umap
}

#[test]
fn list_with_invalid_glob_reports_invalid_argument() {
    let mut cmd = Command::cargo_bin("paksmith").unwrap();
    cmd.args([
        "list",
        &fixture_path("minimal_v6.pak"),
        "--filter",
        "[unclosed",
    ]);

    cmd.assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("invalid argument"))
        .stderr(predicate::str::contains("--filter"));
}

#[test]
fn list_nonexistent_file() {
    let mut cmd = Command::cargo_bin("paksmith").unwrap();
    cmd.args(["list", "/tmp/nonexistent_file.pak"]);

    cmd.assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("error:"));
}

#[test]
fn no_args_shows_help() {
    let mut cmd = Command::cargo_bin("paksmith").unwrap();
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Usage"));
}

#[test]
fn version_flag() {
    let mut cmd = Command::cargo_bin("paksmith").unwrap();
    cmd.arg("--version");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("paksmith"));
}

/// When stdout's reader closes before the CLI writes (or mid-write), the CLI
/// must exit cleanly rather than panic, abort with SIGPIPE (137/141), or
/// surface a misleading error. Unix-only — Windows doesn't deliver SIGPIPE on
/// closed-pipe writes; the equivalent ErrorKind::BrokenPipe path is still
/// covered, just not via the same OS mechanism.
///
/// This test closes the pipe's read end before reading anything. To reliably
/// surface BrokenPipe even with the small v6 fixture (whose JSON fits in a
/// single pipe buffer), we use a workload large enough to force multiple
/// writes from `serde_json::to_writer_pretty`: invoke `--filter '*'` against
/// the fixture and then immediately drop stdout. Any subsequent write from
/// the child fails with EPIPE.
#[cfg(unix)]
#[test]
fn list_with_closed_stdout_exits_cleanly() {
    use std::io::Read;
    use std::process::{Command as StdCommand, Stdio};
    use std::thread;

    let bin = env!("CARGO_BIN_EXE_paksmith");

    let mut child = StdCommand::new(bin)
        .args(["list", &fixture_path("minimal_v6.pak"), "--format", "json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // Close the read end of stdout immediately. The child's writes to its
    // stdout will fail with EPIPE on the first byte.
    drop(child.stdout.take());

    // Drain stderr concurrently so the child doesn't block on a full stderr
    // pipe while we wait.
    let mut stderr = child.stderr.take().unwrap();
    let stderr_handle = thread::spawn(move || {
        let mut buf = String::new();
        let _ = stderr.read_to_string(&mut buf);
        buf
    });

    let status = child.wait().unwrap();
    let stderr_text = stderr_handle.join().unwrap();

    assert!(
        !stderr_text.contains("panicked"),
        "paksmith panicked when stdout was closed: {stderr_text}"
    );
    // Exit 0 = our BrokenPipe handler caught it. 141 = killed by SIGPIPE
    // (default Rust behavior we explicitly want to avoid). Any other code
    // means we leaked an error.
    assert_eq!(
        status.code(),
        Some(0),
        "expected exit 0 on BrokenPipe, got {status:?} (stderr: {stderr_text})"
    );
}
