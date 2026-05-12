#![allow(missing_docs, unused_results)]

use std::io::Write;

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
    assert_eq!(arr.len(), 5);

    let paths: Vec<&str> = arr.iter().map(|e| e["path"].as_str().unwrap()).collect();
    assert!(paths.contains(&"Content/Textures/hero.uasset"));
    assert!(paths.contains(&"Content/Maps/level01.umap"));
    assert!(paths.contains(&"Content/Sounds/bgm.uasset"));
    assert!(paths.contains(&"Content/Text/lorem.txt"));
    assert!(paths.contains(&"Content/Text/lorem_multi.txt"));
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
    assert_eq!(parsed.as_array().unwrap().len(), 5);
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

/// A truncated/garbage input file (something that exists but isn't
/// a valid pak) must surface as exit code 2 + stderr "error:". Today
/// only the missing-file path is covered; a refactor that swapped the
/// error wrapper for a panic, or one that changed the exit code for
/// parse failures, wouldn't be caught. Issue #31.
#[test]
fn list_garbage_input_file_exits_with_error() {
    // 100 bytes of random-but-non-pak data. Smaller than the smallest
    // valid pak footer (44 bytes legacy / 61 bytes v7+), and even if
    // the size dispatcher matched a candidate, the bytes don't carry
    // a valid magic.
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(&[0xABu8; 100]).unwrap();
    tmp.flush().unwrap();

    let mut cmd = Command::cargo_bin("paksmith").unwrap();
    cmd.args(["list", &tmp.path().display().to_string()]);
    cmd.assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("error:"));
}

/// `--filter zzz` with zero matches must produce exit 0 and a valid
/// JSON empty array (`[]`), NOT an error. Issue #31's coverage gap:
/// today this behavior is unspecified — a future "error if filter
/// matches nothing" change would compile silently.
#[test]
fn list_filter_zero_matches_returns_empty_array() {
    let mut cmd = Command::cargo_bin("paksmith").unwrap();
    cmd.args([
        "list",
        &fixture_path("minimal_v6.pak"),
        "--format",
        "json",
        "--filter",
        "Content/zzz_no_such_path.uasset",
    ]);

    let output = cmd.output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        output.status.success(),
        "exit must be 0 on zero-match filter, got {:?} (stderr: {})",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .expect("zero-match filter must produce parseable JSON, not error text");
    assert_eq!(
        parsed.as_array().unwrap().len(),
        0,
        "zero-match filter must produce an empty JSON array"
    );
}

/// JSON output schema is part of the CLI's load-bearing public
/// contract — downstream scripts and CI integrations parse these
/// fields. The existing `list_json_output` test only asserts on
/// `path` and `arr.len()`. Pin every field of `EntryRow` so a rename
/// or type change surfaces here. Issue #31.
#[test]
fn list_json_output_schema_pins_all_fields() {
    let mut cmd = Command::cargo_bin("paksmith").unwrap();
    cmd.args(["list", &fixture_path("minimal_v6.pak"), "--format", "json"]);

    let output = cmd.output().unwrap();
    assert!(output.status.success(), "list --format json must succeed");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let entries: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let arr = entries.as_array().unwrap();
    assert!(!arr.is_empty(), "fixture must have at least one entry");

    let first = &arr[0];
    let obj = first.as_object().expect("each entry must be a JSON object");

    // Pin EXACTLY the field names from EntryRow. A rename to e.g.
    // `is_compressed` to match the core type would surface here.
    let expected_keys = ["path", "size", "compressed_size", "compressed", "encrypted"];
    for key in expected_keys {
        assert!(
            obj.contains_key(key),
            "EntryRow JSON must contain key `{key}`, got keys: {:?}",
            obj.keys().collect::<Vec<_>>()
        );
    }

    // Pin field types so a future serde derive change (e.g., size →
    // string for u64-doesn't-fit-i53 reasons) surfaces here.
    assert!(obj["path"].is_string(), "`path` must be a JSON string");
    assert!(obj["size"].is_u64(), "`size` must be a JSON number");
    assert!(
        obj["compressed_size"].is_u64(),
        "`compressed_size` must be a JSON number"
    );
    assert!(
        obj["compressed"].is_boolean(),
        "`compressed` must be a JSON boolean"
    );
    assert!(
        obj["encrypted"].is_boolean(),
        "`encrypted` must be a JSON boolean"
    );

    // Pin no extra unexpected keys — surfaces a serde drift that adds
    // fields without a deliberate doc update.
    assert_eq!(
        obj.len(),
        expected_keys.len(),
        "EntryRow JSON has unexpected extra keys: {:?}",
        obj.keys().collect::<Vec<_>>()
    );
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
