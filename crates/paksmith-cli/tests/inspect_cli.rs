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

/// `--format table` is a global flag in `main.rs` and would otherwise
/// be silently accepted for `inspect`. The reject path must surface a
/// non-zero exit, the conventional error prefix, and a message that
/// names both `--format` and `table` so the user sees a clear signal.
#[test]
fn inspect_with_format_table_rejected() {
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
        .expect("run paksmith inspect");
    assert_eq!(
        output.status.code(),
        Some(2),
        "inspect --format table must exit with code 2; stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.starts_with("paksmith: error: "),
        "stderr must start with `paksmith: error:`, got: {stderr}"
    );
    assert!(
        stderr.contains("--format"),
        "stderr must name the rejected flag `--format`, got: {stderr}"
    );
    assert!(
        stderr.contains("table"),
        "stderr must mention `table` (the rejected value), got: {stderr}"
    );
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
