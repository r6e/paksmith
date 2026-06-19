//! Integration tests for the `extract` subcommand.

use assert_cmd::Command;
use std::fs;
use tempfile::tempdir;

// The repo's only asset-bearing pak holds a Phase-2-era *generic* asset
// (`Game/Maps/Demo.uasset` → `Asset::Generic`), which extract raw-copies
// (no typed handler). There is NO typed cooked-asset pak fixture (the 3d–3h
// handlers are tested with in-memory `*Data` structs, not packed paks), so
// integration tests assert the RAW + summary + flag mechanics, not a typed
// conversion. The typed convert path is unit-tested in `extract/mod.rs`
// (`write_output`) + Task 5 (`select_export`) + the core handler tests. See
// the "Coverage limitation" note at the end of this plan.
//
// Path is repo-root tests/fixtures (two parents up from the crate manifest),
// matching `inspect_cli.rs`'s `fixture_path` helper.
fn fixture_pak() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures/real_v8b_uasset.pak")
}

#[test]
fn extract_writes_outputs_and_reports_summary() {
    let out = tempdir().unwrap();
    let mut cmd = Command::cargo_bin("paksmith").unwrap();
    let assert = cmd
        .args(["--format", "json", "extract"])
        .arg(fixture_pak())
        .arg("-o")
        .arg(out.path())
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    // Generic asset → raw fallback; every emitted entry lands in `outputs`.
    assert!(v["counts"]["raw_copied"].as_u64().unwrap() >= 1);
    assert_eq!(v["counts"]["failed"].as_u64().unwrap(), 0);
    // At least one output file exists on disk.
    let any = v["outputs"][0]["output"].as_str().unwrap();
    assert!(fs::metadata(any).is_ok(), "output not written: {any}");
}

#[test]
fn extract_dry_run_writes_nothing() {
    let out = tempdir().unwrap();
    let _ = Command::cargo_bin("paksmith")
        .unwrap()
        .arg("extract")
        .arg(fixture_pak())
        .arg("--dry-run")
        .arg("-o")
        .arg(out.path())
        .assert()
        .success();
    assert_eq!(fs::read_dir(out.path()).unwrap().count(), 0);
}

#[test]
fn extract_game_flag_is_rejected() {
    let _ = Command::cargo_bin("paksmith")
        .unwrap()
        .arg("extract")
        .arg(fixture_pak())
        .args(["--game", "fortnite", "-o", "/tmp/x"])
        .assert()
        .failure()
        .code(2);
}

#[test]
fn extract_summary_is_stable_across_jobs() {
    /// Strip tempdir-specific output paths so two runs with different tempdirs
    /// can be compared. Keeps `entry` and `kind`; drops the absolute `output`
    /// path which differs per `tempdir()` call.
    fn normalize_outputs(v: &serde_json::Value) -> serde_json::Value {
        let outputs = v["outputs"].as_array().unwrap();
        let normalized: Vec<serde_json::Value> = outputs
            .iter()
            .map(|o| {
                serde_json::json!({
                    "entry": o["entry"],
                    "kind":  o["kind"],
                })
            })
            .collect();
        serde_json::Value::Array(normalized)
    }

    fn summary_json(jobs: &str) -> serde_json::Value {
        let out = tempfile::tempdir().unwrap();
        let assert = assert_cmd::Command::cargo_bin("paksmith")
            .unwrap()
            .args(["--format", "json", "extract"])
            .arg(fixture_pak())
            .args(["--jobs", jobs])
            .arg("-o")
            .arg(out.path())
            .assert()
            .success();
        let s = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
        serde_json::from_str(&s).unwrap()
    }
    let one = summary_json("1");
    let four = summary_json("4");
    assert_eq!(one["counts"], four["counts"]);
    // Compare entry+kind (sorted by from_outcomes); strip the tempdir-local output path.
    assert_eq!(normalize_outputs(&one), normalize_outputs(&four));
}

#[test]
fn extract_rejects_zero_jobs() {
    let _ = Command::cargo_bin("paksmith")
        .unwrap()
        .args(["extract"])
        .arg(fixture_pak())
        .args(["--jobs", "0", "-o", "/tmp/x"])
        .assert()
        .failure()
        .code(2); // clap usage error → exit 2
}

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
