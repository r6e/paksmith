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
    cmd.args(["list", &fixture_path("minimal_v11.pak"), "--format", "json"]);

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
    cmd.args([
        "list",
        &fixture_path("minimal_v11.pak"),
        "--format",
        "table",
    ]);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("hero.uasset"))
        .stdout(predicate::str::contains("level01.umap"))
        .stdout(predicate::str::contains("bgm.uasset"));
}

#[test]
fn list_with_filter() {
    let mut cmd = Command::cargo_bin("paksmith").unwrap();
    cmd.args([
        "list",
        &fixture_path("minimal_v11.pak"),
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
fn list_nonexistent_file() {
    let mut cmd = Command::cargo_bin("paksmith").unwrap();
    cmd.args(["list", "/tmp/nonexistent_file.pak"]);

    cmd.assert()
        .failure()
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
