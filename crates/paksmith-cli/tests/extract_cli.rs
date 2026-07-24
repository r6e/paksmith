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

/// Per-entry AES-encrypted fixture (plaintext index). Entries: test.txt,
/// directory/nested.txt, zeros.bin (2048 × 0x00), test.png.
fn encrypted_entries_pak() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures/real_v8b_encrypted_entries.pak")
}

mod common;
use common::FIXTURE_AES_KEY_HEX as AES_KEY_HEX;

use common::{fixture_path, seed_hero_profile};

/// Pak whose single entry is an UNVERSIONED uasset (class `Hero`); pairs
/// with `external_minimal_v0.usmap` (issue #651).
fn unversioned_pak() -> std::path::PathBuf {
    fixture_path("real_v8b_unversioned.pak")
}

/// The `.usmap` fixture carrying the `Hero { Health, Speed }` schema.
fn hero_usmap() -> std::path::PathBuf {
    fixture_path("external_minimal_v0.usmap")
}

#[test]
fn extract_unversioned_without_mappings_fails_entry() {
    // Pins the pre-#651 baseline the mappings pipeline exists to fix: an
    // unversioned asset with NO mappings source is a per-entry failure
    // (`UnversionedWithoutMappings`) and the run exits 1.
    let out = tempdir().unwrap();
    let mut cmd = Command::cargo_bin("paksmith").unwrap();
    let assert = cmd
        .args(["--format", "json", "extract"])
        .arg(unversioned_pak())
        .arg("-o")
        .arg(out.path())
        .assert()
        .code(1);
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["counts"]["failed"].as_u64().unwrap(), 1);
}

#[test]
fn extract_unversioned_with_mappings_converts() {
    // #651: `extract --mappings <usmap>` decodes the unversioned asset —
    // the entry no longer fails (the generic Hero asset raw-copies).
    let out = tempdir().unwrap();
    let mut cmd = Command::cargo_bin("paksmith").unwrap();
    let assert = cmd
        .args(["--format", "json", "extract"])
        .arg(unversioned_pak())
        .arg("--mappings")
        .arg(hero_usmap())
        .arg("-o")
        .arg(out.path())
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["counts"]["failed"].as_u64().unwrap(), 0);
    assert!(v["counts"]["raw_copied"].as_u64().unwrap() >= 1);
}

#[test]
fn extract_unversioned_with_profile_mappings_converts() {
    // #651: a mappings-bearing profile selected via `--game` supplies the
    // usmap with no explicit `--mappings`.
    let config_dir = tempdir().unwrap();
    let out = tempdir().unwrap();
    seed_hero_profile(config_dir.path(), &hero_usmap());
    let mut cmd = Command::cargo_bin("paksmith").unwrap();
    let assert = cmd
        .env("PAKSMITH_CONFIG_DIR", config_dir.path())
        .args(["--format", "json", "extract"])
        .arg(unversioned_pak())
        .args(["--game", "hero"])
        .arg("-o")
        .arg(out.path())
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["counts"]["failed"].as_u64().unwrap(), 0);
    assert!(v["counts"]["raw_copied"].as_u64().unwrap() >= 1);
}

#[test]
fn extract_explicit_mappings_wins_over_profile() {
    // #651 precedence: the profile's mappings path is BROKEN; the explicit
    // `--mappings` is good. Success proves the explicit flag won (a
    // profile-first order would exit 2 on the broken path).
    let config_dir = tempdir().unwrap();
    let out = tempdir().unwrap();
    seed_hero_profile(
        config_dir.path(),
        std::path::Path::new("/nonexistent/broken.usmap"),
    );
    let _ = Command::cargo_bin("paksmith")
        .unwrap()
        .env("PAKSMITH_CONFIG_DIR", config_dir.path())
        .args(["--format", "json", "extract"])
        .arg(unversioned_pak())
        .args(["--game", "hero"])
        .arg("--mappings")
        .arg(hero_usmap())
        .arg("-o")
        .arg(out.path())
        .assert()
        .success();
}

#[test]
fn extract_mappings_nonexistent_file_errors() {
    // Mirror of inspect's `--mappings` arg-attribution contract: a bad
    // explicit path is exit 2 with the flag name in stderr.
    let out = tempdir().unwrap();
    let assert = Command::cargo_bin("paksmith")
        .unwrap()
        .arg("extract")
        .arg(unversioned_pak())
        .args(["--mappings", "/nonexistent/nope.usmap"])
        .arg("-o")
        .arg(out.path())
        .assert()
        .code(2);
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(
        stderr.contains("--mappings") && stderr.contains("nope.usmap"),
        "stderr must attribute the bad path to --mappings: {stderr}"
    );
}

#[test]
fn extract_broken_profile_mappings_errors_loudly() {
    // #651: a profile whose mappings path can't load is a HARD error
    // attributed to --game — never a silent fall-through to the
    // no-mappings behavior (which would resurface per-entry failures
    // the user thinks they've configured away).
    let config_dir = tempdir().unwrap();
    let out = tempdir().unwrap();
    seed_hero_profile(
        config_dir.path(),
        std::path::Path::new("/nonexistent/broken.usmap"),
    );
    let assert = Command::cargo_bin("paksmith")
        .unwrap()
        .env("PAKSMITH_CONFIG_DIR", config_dir.path())
        .arg("extract")
        .arg(unversioned_pak())
        .args(["--game", "hero"])
        .arg("-o")
        .arg(out.path())
        .assert()
        .code(2);
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(
        stderr.contains("--game") && stderr.contains("broken.usmap"),
        "stderr must attribute the bad path to the profile selection: {stderr}"
    );
}

#[test]
fn extract_aes_key_with_game_profile_keeps_mappings() {
    // #651: --aes-key short-circuits the KEY lookup but must NOT drop the
    // --game profile's mappings — the unversioned entry still decodes.
    // (The key is unused: the fixture pak is unencrypted.)
    let config_dir = tempdir().unwrap();
    let out = tempdir().unwrap();
    seed_hero_profile(config_dir.path(), &hero_usmap());
    let assert = Command::cargo_bin("paksmith")
        .unwrap()
        .env("PAKSMITH_CONFIG_DIR", config_dir.path())
        .args(["--format", "json", "--aes-key", AES_KEY_HEX, "extract"])
        .arg(unversioned_pak())
        .args(["--game", "hero"])
        .arg("-o")
        .arg(out.path())
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["counts"]["failed"].as_u64().unwrap(), 0);
}

#[test]
fn extract_aes_key_with_unknown_game_still_exits_2() {
    // #651 (R1 architect finding): --game keeps its hard contract even
    // with --aes-key set — a typo'd id must NOT silently produce a
    // no-mappings run.
    let config_dir = tempdir().unwrap();
    let out = tempdir().unwrap();
    let assert = Command::cargo_bin("paksmith")
        .unwrap()
        .env("PAKSMITH_CONFIG_DIR", config_dir.path())
        .args(["--aes-key", AES_KEY_HEX, "extract"])
        .arg(unversioned_pak())
        .args(["--game", "nope"])
        .arg("-o")
        .arg(out.path())
        .assert()
        .code(2);
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(
        stderr.contains("nope"),
        "stderr must name the unknown profile id: {stderr}"
    );
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
fn extract_unknown_game_profile_exits_2() {
    // Use an isolated, empty config dir so no profile named "nope" can exist
    // regardless of what is installed on the host machine.
    let config_dir = tempdir().unwrap();
    let out_dir = tempdir().unwrap();
    let _ = Command::cargo_bin("paksmith")
        .unwrap()
        .env("PAKSMITH_CONFIG_DIR", config_dir.path())
        .arg("extract")
        .arg(fixture_pak())
        .args(["--game", "nope"])
        .arg("-o")
        .arg(out_dir.path())
        .assert()
        .code(2); // unknown profile → ProfileNotFound → exit 2
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
fn extract_progress_goes_to_stderr_not_stdout_json() {
    let out = tempfile::tempdir().unwrap();
    let assert = assert_cmd::Command::cargo_bin("paksmith")
        .unwrap()
        .args(["--format", "json", "extract"])
        .arg(fixture_pak())
        .arg("-o")
        .arg(out.path())
        .assert()
        .success();
    // stdout must be pure JSON (parseable) — no progress bytes mixed in.
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let _parsed = serde_json::from_str::<serde_json::Value>(&stdout)
        .expect("stdout is not clean JSON — progress leaked to stdout");
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
        "--locres-format",
        "--jobs",
        "--game",
        "--mappings",
    ] {
        assert!(out.contains(flag), "help missing {flag}");
    }
}

#[test]
fn extract_overwrite_guard() {
    let out = tempdir().unwrap();
    // First run: must succeed and write outputs.
    let _ = Command::cargo_bin("paksmith")
        .unwrap()
        .arg("extract")
        .arg(fixture_pak())
        .arg("-o")
        .arg(out.path())
        .assert()
        .success();
    // Second run without --overwrite: existing files → failures → exit 1.
    let _ = Command::cargo_bin("paksmith")
        .unwrap()
        .arg("extract")
        .arg(fixture_pak())
        .arg("-o")
        .arg(out.path())
        .assert()
        .code(1);
    // Third run with --overwrite: success again.
    let _ = Command::cargo_bin("paksmith")
        .unwrap()
        .arg("extract")
        .arg(fixture_pak())
        .arg("--overwrite")
        .arg("-o")
        .arg(out.path())
        .assert()
        .success();
}

#[test]
fn extract_missing_pak_is_fatal() {
    let _ = Command::cargo_bin("paksmith")
        .unwrap()
        .args(["extract", "/no/such.pak", "-o", "/tmp/x"])
        .assert()
        .code(2);
}

#[test]
fn extract_filter_matches_subset() {
    // Game/** should match Game/Maps/Demo.uasset (the fixture's only entry).
    let out = tempdir().unwrap();
    let assert = Command::cargo_bin("paksmith")
        .unwrap()
        .args(["--format", "json", "extract"])
        .arg(fixture_pak())
        .args(["--filter", "Game/**"])
        .arg("-o")
        .arg(out.path())
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let matched =
        v["counts"]["raw_copied"].as_u64().unwrap() + v["counts"]["converted"].as_u64().unwrap();
    assert!(
        matched >= 1,
        "expected >=1 matched entries with Game/**, got {matched}"
    );
    assert_eq!(v["counts"]["failed"].as_u64().unwrap(), 0);

    // A filter that matches nothing should yield zero outputs, still exit 0.
    let out2 = tempdir().unwrap();
    let assert2 = Command::cargo_bin("paksmith")
        .unwrap()
        .args(["--format", "json", "extract"])
        .arg(fixture_pak())
        .args(["--filter", "Nonexistent/**"])
        .arg("-o")
        .arg(out2.path())
        .assert()
        .success();
    let stdout2 = String::from_utf8(assert2.get_output().stdout.clone()).unwrap();
    let v2: serde_json::Value = serde_json::from_str(&stdout2).unwrap();
    let matched2 =
        v2["counts"]["raw_copied"].as_u64().unwrap() + v2["counts"]["converted"].as_u64().unwrap();
    assert_eq!(matched2, 0, "non-matching filter must yield 0 outputs");
}

#[test]
fn extract_flat_strips_dirs() {
    let out = tempdir().unwrap();
    let assert = Command::cargo_bin("paksmith")
        .unwrap()
        .args(["--format", "json", "extract"])
        .arg(fixture_pak())
        .arg("--flat")
        .arg("-o")
        .arg(out.path())
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    // The fixture entry Game/Maps/Demo.uasset must land at <out>/Demo.uasset.
    let expected = out.path().join("Demo.uasset");
    assert!(
        fs::metadata(&expected).is_ok(),
        "expected flat output at {}, not found",
        expected.display()
    );
    // The JSON outputs record should report the flattened path.
    let output_path = v["outputs"][0]["output"].as_str().unwrap();
    assert!(
        output_path.ends_with("Demo.uasset") && !output_path.contains("Game"),
        "output path should be flat, got: {output_path}"
    );
}

#[test]
fn extract_summary_snapshot() {
    let out = tempdir().unwrap();
    let assert = Command::cargo_bin("paksmith")
        .unwrap()
        .args(["--format", "json", "extract"])
        .arg(fixture_pak())
        .arg("--dry-run")
        .arg("-o")
        .arg(out.path())
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let mut v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    // Redact host-specific paths so the snapshot is portable across machines.
    v["output_dir"] = serde_json::Value::String("<tmp>".into());
    if let Some(outs) = v["outputs"].as_array_mut() {
        for o in outs {
            o["output"] = serde_json::Value::String("<tmp>/redacted".into());
        }
    }
    // Redact the absolute pak path — it differs between machines and worktrees.
    v["pak"] = serde_json::Value::String("<fixture>".into());
    insta::assert_json_snapshot!(v);
}

// ── Phase 5a: per-entry AES decryption ──────────────────────────────────────

/// Prove that `--aes-key` decrypts entry payloads end-to-end.
///
/// The fixture's `zeros.bin` contains 2048 bytes of 0x00. AES-256-ECB of an
/// all-zero block under this key is a fixed non-zero ciphertext block, so
/// asserting the extracted file is 2048 × 0x00 proves actual decryption, not
/// identity passthrough.
#[test]
fn extract_with_aes_key_decrypts_entry_payload() {
    let out = tempdir().unwrap();
    let assert = Command::cargo_bin("paksmith")
        .unwrap()
        .args(["--format", "json", "--aes-key", AES_KEY_HEX, "extract"])
        .arg(encrypted_entries_pak())
        .arg("-o")
        .arg(out.path())
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        v["counts"]["failed"].as_u64().unwrap(),
        0,
        "all entries must decrypt cleanly"
    );

    // Locate the zeros.bin output record.
    let outputs = v["outputs"].as_array().unwrap();
    let zeros_record = outputs
        .iter()
        .find(|o| o["entry"].as_str().unwrap_or("").ends_with("zeros.bin"))
        .expect("zeros.bin entry must appear in outputs");
    let zeros_path = zeros_record["output"].as_str().unwrap();

    let bytes = fs::read(zeros_path).expect("zeros.bin must be written to disk");
    assert_eq!(bytes.len(), 2048, "zeros.bin must be exactly 2048 bytes");
    assert!(
        bytes.iter().all(|&b| b == 0x00),
        "every byte of zeros.bin must be 0x00 — non-zero bytes indicate failed decryption"
    );
}

/// Prove that extracting an entry-encrypted pak WITHOUT a key fails closed:
/// the entry reads fail, `counts.failed` is non-zero, and the process exits 1.
///
/// The fixture has a plaintext index (no index decryption needed), so the
/// reader opens successfully; the failure occurs during per-entry payload read.
#[test]
fn extract_encrypted_entry_without_key_fails() {
    let out = tempdir().unwrap();
    let assert = Command::cargo_bin("paksmith")
        .unwrap()
        .args(["--format", "json", "extract"])
        .arg(encrypted_entries_pak())
        .arg("-o")
        .arg(out.path())
        .assert()
        .code(1); // had_failures() → exit 1 (per-entry fail, not whole-run abort)

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(
        v["counts"]["failed"].as_u64().unwrap() >= 1,
        "at least one entry must fail without an AES key"
    );
}
