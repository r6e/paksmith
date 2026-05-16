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
