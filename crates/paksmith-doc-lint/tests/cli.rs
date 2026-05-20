#![allow(missing_docs)]

use assert_cmd::Command;
use predicates::str::contains;
use std::fs;
use tempfile::TempDir;

const VALID_DOC: &str = include_str!("fixtures/well-formed-doc.md");

const INVALID_INVENTORY: &str = "\
# Inventory

## Inventory

| Doc | Doc status | Parser status | Parser module | Reference oracle | Last verified |
|-----|------------|---------------|----------------|-------------------|---------------|
| `x.md` | done | complete | — | — | n/a |
";

#[test]
fn prints_usage_with_no_args() {
    let mut cmd = Command::cargo_bin("paksmith-doc-lint").unwrap();
    let _ = cmd
        .assert()
        .failure()
        .code(2)
        .stderr(contains("usage: paksmith-doc-lint"));
}

#[test]
fn required_headings_subcommand_exits_zero_on_valid_dir() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("pak.md"), VALID_DOC).unwrap();
    let mut cmd = Command::cargo_bin("paksmith-doc-lint").unwrap();
    let _ = cmd
        .arg("required-headings")
        .arg(dir.path())
        .assert()
        .success();
}

#[test]
fn status_enum_subcommand_exits_nonzero_on_invalid_value() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("README.md");
    fs::write(&path, INVALID_INVENTORY).unwrap();
    let mut cmd = Command::cargo_bin("paksmith-doc-lint").unwrap();
    let _ = cmd
        .arg("status-enum")
        .arg(&path)
        .assert()
        .failure()
        .stderr(contains("status-enum lint failed"));
}

#[test]
fn inventory_files_subcommand_exits_zero_on_match() {
    let dir = TempDir::new().unwrap();
    let readme = dir.path().join("README.md");
    let valid_inventory = "\
# Inv

## Inventory

| Doc | Doc status | Parser status | Parser module | Reference oracle | Last verified |
|-----|------------|---------------|----------------|-------------------|---------------|
| `foo/bar.md` | stub | not impl | — | — | n/a |
";
    fs::write(&readme, valid_inventory).unwrap();
    fs::create_dir(dir.path().join("foo")).unwrap();
    fs::write(dir.path().join("foo").join("bar.md"), "# stub").unwrap();

    let mut cmd = Command::cargo_bin("paksmith-doc-lint").unwrap();
    let _ = cmd
        .arg("inventory-files")
        .arg(&readme)
        .arg(dir.path())
        .assert()
        .success();
}
