#![allow(missing_docs)]

use std::path::PathBuf;
use std::process::Command;

fn fixture_path(name: &str) -> PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    PathBuf::from(manifest)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures")
        .join(name)
}

#[test]
fn inspect_emits_valid_json_with_expected_fields() {
    let pak = fixture_path("real_v8b_uasset.pak");
    assert!(
        pak.exists(),
        "fixture {} is missing — run `cargo run -p paksmith-fixture-gen`. \
         The fixture is also pinned in crates/paksmith-core/tests/fixture_anchor.rs, \
         so silent-skip on absence here would still fail the anchor test.",
        pak.display()
    );

    let output = Command::new(env!("CARGO_BIN_EXE_paksmith"))
        .args(["inspect", pak.to_str().unwrap(), "Game/Maps/Demo.uasset"])
        .output()
        .expect("run paksmith inspect");
    assert!(
        output.status.success(),
        "paksmith inspect failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("inspect output must be valid JSON");
    assert_eq!(json["asset_path"], "Game/Maps/Demo.uasset");
    assert_eq!(json["names"].as_array().unwrap().len(), 3);
    assert_eq!(json["imports"].as_array().unwrap().len(), 1);
    assert_eq!(json["exports"].as_array().unwrap().len(), 1);
    assert_eq!(json["summary"]["version"]["legacy_file_version"], -7);
}

/// Snapshot the full JSON shape so the inspect contract (the
/// "Deliverable" section of the Phase 2a plan) is pinned at the byte
/// level. Insta is wired in `paksmith-cli/Cargo.toml` dev-deps; on
/// first run, `INSTA_UPDATE=always` writes the baseline.
///
/// The `payload_bytes` count and `serial_offset` may shift if the
/// summary/import/export wire layouts gain a field — that's a real
/// change worth surfacing in review rather than silently approving.
#[test]
fn inspect_json_snapshot() {
    let pak = fixture_path("real_v8b_uasset.pak");
    assert!(pak.exists(), "fixture missing — run paksmith-fixture-gen");
    let output = Command::new(env!("CARGO_BIN_EXE_paksmith"))
        .args(["inspect", pak.to_str().unwrap(), "Game/Maps/Demo.uasset"])
        .output()
        .expect("run paksmith inspect");
    assert!(output.status.success());
    let json_str = String::from_utf8(output.stdout).unwrap();
    insta::assert_snapshot!(json_str);
}

/// A missing pak path must surface the conventional Unix CLI shape
/// `paksmith: error: <msg>` with non-zero exit, mirroring
/// `list_nonexistent_file` in `cli_integration.rs`.
#[test]
fn inspect_nonexistent_pak() {
    let output = Command::new(env!("CARGO_BIN_EXE_paksmith"))
        .args([
            "inspect",
            "/nonexistent/path/foo.pak",
            "Game/Maps/Demo.uasset",
        ])
        .output()
        .expect("run paksmith inspect");
    assert_eq!(
        output.status.code(),
        Some(2),
        "expected exit 2 on missing pak, got {:?}",
        output.status
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.starts_with("paksmith: error: "),
        "stderr must start with `paksmith: error:`, got: {stderr}"
    );
}

/// Asking for an asset not present in the archive must error with the
/// `paksmith: error:` prefix and a non-zero exit — not silently emit
/// an empty Package.
#[test]
fn inspect_asset_not_in_pak() {
    let pak = fixture_path("real_v8b_uasset.pak");
    assert!(pak.exists(), "fixture missing — run paksmith-fixture-gen");

    let output = Command::new(env!("CARGO_BIN_EXE_paksmith"))
        .args(["inspect", pak.to_str().unwrap(), "NonExistent/Asset.uasset"])
        .output()
        .expect("run paksmith inspect");
    assert_eq!(
        output.status.code(),
        Some(2),
        "inspect on missing asset must exit with code 2; stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.starts_with("paksmith: error: "),
        "stderr must start with `paksmith: error:`, got: {stderr}"
    );
}

/// `--format table` now renders the human tree view (Phase 4b Task 5).
/// The output must NOT be JSON (it's a tree), must exit 0, and must
/// carry the header summary + the per-export block markers. `--format
/// table` is explicit, so it resolves to the table renderer regardless
/// of the (piped, non-TTY) test stdout.
#[test]
fn inspect_with_format_table_renders_tree() {
    let pak = fixture_path("real_v8b_uasset.pak");
    assert!(pak.exists(), "fixture missing — run paksmith-fixture-gen");

    let output = Command::new(env!("CARGO_BIN_EXE_paksmith"))
        .args([
            "inspect",
            pak.to_str().unwrap(),
            "Game/Maps/Demo.uasset",
            "--format",
            "table",
        ])
        .output()
        .expect("run paksmith inspect --format table");
    assert!(
        output.status.success(),
        "inspect --format table must exit 0; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    // The tree view is not JSON — a JSON parse must fail.
    assert!(
        serde_json::from_str::<serde_json::Value>(&stdout).is_err(),
        "table output must NOT be valid JSON; got: {stdout}"
    );
    // Header summary markers.
    assert!(
        stdout.contains("Game/Maps/Demo.uasset"),
        "header must name the asset path; got: {stdout}"
    );
    assert!(
        stdout.contains("engine") && stdout.contains("exports"),
        "header must carry engine + table-count markers; got: {stdout}"
    );
    // The single export's block: a `[0] <name> : <class>` line.
    assert!(
        stdout.contains("[0]"),
        "must render the export-0 block header; got: {stdout}"
    );
}

/// `--mappings` pointed at a missing path must exit 2 AND surface the
/// path + flag name in the error message — a bare `?` on
/// `std::fs::read` would drop both, leaving the user with an opaque
/// "No such file or directory (os error 2)". Pin the
/// `PaksmithError::InvalidArgument` wrap so a future regression of
/// the helper restores the broken UX.
#[test]
fn inspect_mappings_nonexistent_file_errors() {
    let pak = fixture_path("real_v8b_uasset.pak");
    assert!(pak.exists(), "fixture missing — run paksmith-fixture-gen");

    let output = Command::new(env!("CARGO_BIN_EXE_paksmith"))
        .args([
            "inspect",
            pak.to_str().unwrap(),
            "Game/Maps/Demo.uasset",
            "--mappings",
            "/nonexistent/path/Hero.usmap",
        ])
        .output()
        .expect("run paksmith inspect --mappings nonexistent");
    assert_eq!(
        output.status.code(),
        Some(2),
        "inspect --mappings nonexistent must exit 2; stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.starts_with("paksmith: error: "),
        "stderr must start with `paksmith: error:`, got: {stderr}"
    );
    assert!(
        stderr.contains("--mappings"),
        "stderr must name `--mappings` so the user knows which arg failed, got: {stderr}"
    );
    assert!(
        stderr.contains("/nonexistent/path/Hero.usmap"),
        "stderr must include the offending path, got: {stderr}"
    );
}

#[test]
fn inspect_json_has_schema_version_first() {
    let pak = fixture_path("real_v8b_uasset.pak");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_paksmith"))
        .args(["inspect", pak.to_str().unwrap(), "Game/Maps/Demo.uasset"])
        .output()
        .expect("run inspect");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["schema_version"], 1);
    assert_eq!(v["asset_path"], "Game/Maps/Demo.uasset"); // package fields still present
    // schema_version must be the FIRST key in the raw output.
    let first_key = stdout.find("\"schema_version\"").unwrap();
    let asset_path_key = stdout.find("\"asset_path\"").unwrap();
    assert!(
        first_key < asset_path_key,
        "schema_version must precede package fields"
    );
}

#[test]
fn inspect_path_drills_to_value() {
    let pak = fixture_path("real_v8b_uasset.pak");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_paksmith"))
        .args([
            "inspect",
            pak.to_str().unwrap(),
            "Game/Maps/Demo.uasset",
            "--path",
            "schema_version",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(String::from_utf8(out.stdout).unwrap().trim(), "1");
}

#[test]
fn inspect_path_unresolved_exits_2() {
    let pak = fixture_path("real_v8b_uasset.pak");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_paksmith"))
        .args([
            "inspect",
            pak.to_str().unwrap(),
            "Game/Maps/Demo.uasset",
            "--path",
            "nope.nope",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn inspect_path_with_table_exits_2() {
    let pak = fixture_path("real_v8b_uasset.pak");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_paksmith"))
        .args([
            "inspect",
            pak.to_str().unwrap(),
            "Game/Maps/Demo.uasset",
            "--path",
            "summary",
            "--format",
            "table",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn inspect_export_by_index() {
    let pak = fixture_path("real_v8b_uasset.pak");
    assert!(pak.exists(), "fixture missing — run paksmith-fixture-gen");
    let out = Command::new(env!("CARGO_BIN_EXE_paksmith"))
        .args([
            "inspect",
            pak.to_str().unwrap(),
            "Game/Maps/Demo.uasset",
            "--export",
            "0",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "inspect --export 0 failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["schema_version"], 1);
    assert!(
        v.get("asset").is_some(),
        "single-export body must carry its asset"
    );
    assert!(
        v.get("exports").is_none(),
        "single-export body is not the whole package"
    );
}

#[test]
fn inspect_export_bad_index_exits_2() {
    let pak = fixture_path("real_v8b_uasset.pak");
    assert!(pak.exists(), "fixture missing — run paksmith-fixture-gen");
    let out = Command::new(env!("CARGO_BIN_EXE_paksmith"))
        .args([
            "inspect",
            pak.to_str().unwrap(),
            "Game/Maps/Demo.uasset",
            "--export",
            "99",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}

/// Shared redaction helper for inspect snapshots: replaces GUID values,
/// engine-version strings, and any absolute paths with stable placeholders
/// so snapshots are portable across machines and worktrees.
fn redact_inspect_volatile(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::Object(map) => {
            for (key, val) in map.iter_mut() {
                // Redact GUID fields (UUID-format strings like "00000000-0000-…").
                if key == "guid"
                    || key == "package_guid"
                    || key == "persistent_guid"
                    || key == "owner_persistent_guid"
                {
                    if val.is_string() {
                        *val = serde_json::Value::String("<guid>".into());
                    }
                // Redact engine-version strings.
                } else if key == "saved_by_engine_version"
                    || key == "compatible_with_engine_version"
                {
                    if val.is_string() {
                        *val = serde_json::Value::String("<engine-version>".into());
                    }
                } else {
                    redact_inspect_volatile(val);
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for elem in arr.iter_mut() {
                redact_inspect_volatile(elem);
            }
        }
        _ => {}
    }
}

/// Snapshot the single-export JSON body emitted by `--export 0`.
/// Redacts GUIDs and engine-version strings to keep the snapshot
/// portable; structure and byte counts are fixture-deterministic.
#[test]
fn inspect_export_0_snapshot() {
    let pak = fixture_path("real_v8b_uasset.pak");
    assert!(pak.exists(), "fixture missing — run paksmith-fixture-gen");
    let output = Command::new(env!("CARGO_BIN_EXE_paksmith"))
        .args([
            "inspect",
            pak.to_str().unwrap(),
            "Game/Maps/Demo.uasset",
            "--export",
            "0",
        ])
        .output()
        .expect("run paksmith inspect --export 0");
    assert!(
        output.status.success(),
        "inspect --export 0 failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut v: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("--export 0 output must be valid JSON");
    redact_inspect_volatile(&mut v);
    insta::assert_json_snapshot!(v);
}

/// Snapshot the `--path summary` subtree.
/// Redacts GUIDs and engine-version strings; version numbers, counts,
/// and offsets are all fixture-deterministic and left unredacted.
#[test]
fn inspect_path_summary_snapshot() {
    let pak = fixture_path("real_v8b_uasset.pak");
    assert!(pak.exists(), "fixture missing — run paksmith-fixture-gen");
    let output = Command::new(env!("CARGO_BIN_EXE_paksmith"))
        .args([
            "inspect",
            pak.to_str().unwrap(),
            "Game/Maps/Demo.uasset",
            "--path",
            "summary",
        ])
        .output()
        .expect("run paksmith inspect --path summary");
    assert!(
        output.status.success(),
        "inspect --path summary failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut v: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("--path summary output must be valid JSON");
    redact_inspect_volatile(&mut v);
    insta::assert_json_snapshot!(v);
}

// Pipe-close coverage (analogue of `list_with_closed_stdout_exits_cleanly`)
// is intentionally omitted. The minimal `real_v8b_uasset.pak` fixture
// produces a small JSON Package (~1 KiB pretty-printed) that fits inside
// a single pipe buffer (typ. 64 KiB on Linux, 16 KiB on macOS). Without a
// workload large enough to force multiple `serde_json::to_writer_pretty`
// writes, the kernel buffers the whole payload before the reader closes,
// so EPIPE never fires — the test would be a no-op that passes for the
// wrong reason. `inspect` currently has no equivalent of `list --filter '*'`
// for forcing repeated writes; revisit when a larger inspect fixture
// lands or when streaming-serialization concerns surface.
