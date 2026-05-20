#![allow(missing_docs)]

use paksmith_doc_lint::status_enum::check_file;
use std::fs;
use tempfile::TempDir;

const EMPTY_INVENTORY: &str = "\
# docs/formats inventory

## Inventory

| Doc | Doc status | Parser status | Parser module | Reference oracle | Last verified |
|-----|------------|---------------|----------------|-------------------|---------------|
";

#[test]
fn accepts_empty_inventory() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("README.md");
    fs::write(&path, EMPTY_INVENTORY).unwrap();
    check_file(&path).expect("empty inventory should pass");
}

const VALID_INVENTORY: &str = "\
# docs/formats inventory

## Inventory

| Doc | Doc status | Parser status | Parser module | Reference oracle | Last verified |
|-----|------------|---------------|----------------|-------------------|---------------|
| `container/pak.md` | complete | complete | `container/pak/` | repak @ `abc123` | `def456` |
| `container/iostore-utoc.md` | stub | not impl | — | CUE4Parse @ `ghi789` | n/a |
";

#[test]
fn accepts_valid_populated_inventory() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("README.md");
    fs::write(&path, VALID_INVENTORY).unwrap();
    check_file(&path).expect("valid rows should pass");
}

const INVALID_DOC_STATUS: &str = "\
# docs/formats inventory

## Inventory

| Doc | Doc status | Parser status | Parser module | Reference oracle | Last verified |
|-----|------------|---------------|----------------|-------------------|---------------|
| `container/pak.md` | done | complete | `container/pak/` | repak @ `abc123` | `def456` |
";

#[test]
fn rejects_invalid_doc_status_value() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("README.md");
    fs::write(&path, INVALID_DOC_STATUS).unwrap();
    let err = check_file(&path).expect_err("invalid value should fail");
    assert!(err.to_string().contains("doc status"), "got: {err}");
    assert!(err.to_string().contains("done"), "got: {err}");
}

const INVALID_PARSER_STATUS: &str = "\
# docs/formats inventory

## Inventory

| Doc | Doc status | Parser status | Parser module | Reference oracle | Last verified |
|-----|------------|---------------|----------------|-------------------|---------------|
| `container/pak.md` | complete | shipped | `container/pak/` | repak @ `abc123` | `def456` |
";

#[test]
fn rejects_invalid_parser_status_value() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("README.md");
    fs::write(&path, INVALID_PARSER_STATUS).unwrap();
    let err = check_file(&path).expect_err("invalid value should fail");
    assert!(err.to_string().contains("parser status"), "got: {err}");
    assert!(err.to_string().contains("shipped"), "got: {err}");
}

const WRONG_COLUMN_COUNT: &str = "\
# docs/formats inventory

## Inventory

| Doc | Doc status | Parser status | Parser module | Reference oracle | Last verified |
|-----|------------|---------------|----------------|-------------------|---------------|
| `container/pak.md` | complete | complete | `container/pak/` |
";

#[test]
fn rejects_row_with_wrong_column_count() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("README.md");
    fs::write(&path, WRONG_COLUMN_COUNT).unwrap();
    let err = check_file(&path).expect_err("malformed row should fail");
    assert!(err.to_string().contains("expected 6 cells"), "got: {err}");
}

const NO_INVENTORY_TABLE: &str = "\
# docs/formats inventory

Some narrative here, but no inventory table at all.
";

#[test]
fn rejects_file_with_no_inventory_table() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("README.md");
    fs::write(&path, NO_INVENTORY_TABLE).unwrap();
    let err = check_file(&path).expect_err("missing table should fail");
    assert!(
        err.to_string()
            .contains("inventory table header row not found"),
        "got: {err}"
    );
}

const SMELL_COMPLETE_DOC_NOT_IMPL_PARSER: &str = "\
# docs/formats inventory

## Inventory

| Doc | Doc status | Parser status | Parser module | Reference oracle | Last verified |
|-----|------------|---------------|----------------|-------------------|---------------|
| `container/iostore-utoc.md` | complete | not impl | — | CUE4Parse @ `abc` | n/a |
";

#[test]
fn accepts_smell_complete_doc_not_impl_parser() {
    // Doc claims complete but parser absent — smell-worthy, but not a hard fail.
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("README.md");
    fs::write(&path, SMELL_COMPLETE_DOC_NOT_IMPL_PARSER).unwrap();
    check_file(&path).expect("smell row should warn but not fail");
}

const SMELL_STUB_DOC_COMPLETE_PARSER: &str = "\
# docs/formats inventory

## Inventory

| Doc | Doc status | Parser status | Parser module | Reference oracle | Last verified |
|-----|------------|---------------|----------------|-------------------|---------------|
| `container/pak.md` | stub | complete | `container/pak/` | repak @ `def` | `abc` |
";

#[test]
fn accepts_smell_stub_doc_complete_parser() {
    // Parser exists but doc is still stub — smell-worthy (under-documented),
    // but not a hard fail.
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("README.md");
    fs::write(&path, SMELL_STUB_DOC_COMPLETE_PARSER).unwrap();
    check_file(&path).expect("smell row should warn but not fail");
}

const SMELL_COMPLETE_DOC_PARTIAL_PARSER: &str = "\
# docs/formats inventory

## Inventory

| Doc | Doc status | Parser status | Parser module | Reference oracle | Last verified |
|-----|------------|---------------|----------------|-------------------|---------------|
| `container/pak.md` | complete | partial | `container/pak/` | repak @ `abc` | `def` |
";

#[test]
fn accepts_smell_complete_doc_partial_parser() {
    // Doc claims complete but parser is only partial — likely outdated doc,
    // smell-worthy, but not a hard fail.
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("README.md");
    fs::write(&path, SMELL_COMPLETE_DOC_PARTIAL_PARSER).unwrap();
    check_file(&path).expect("smell row should warn but not fail");
}

const SMELL_PARTIAL_DOC_COMPLETE_PARSER: &str = "\
# docs/formats inventory

## Inventory

| Doc | Doc status | Parser status | Parser module | Reference oracle | Last verified |
|-----|------------|---------------|----------------|-------------------|---------------|
| `asset/uasset.md` | partial | complete | `asset/` | unreal_asset @ `xyz` | `abc` |
";

#[test]
fn accepts_smell_partial_doc_complete_parser() {
    // Parser is complete but doc still partial — under-documented,
    // smell-worthy, but not a hard fail.
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("README.md");
    fs::write(&path, SMELL_PARTIAL_DOC_COMPLETE_PARSER).unwrap();
    check_file(&path).expect("smell row should warn but not fail");
}

const HEADER_WITHOUT_SEPARATOR: &str = "\
# docs/formats inventory

## Inventory

| Doc | Doc status | Parser status | Parser module | Reference oracle | Last verified |
| `container/pak.md` | complete | complete | `container/pak/` | repak @ `abc` | `def` |
";

#[test]
fn rejects_header_without_separator_row() {
    // `skip(header_idx + 2)` unconditionally throws away the line after
    // the header. If a contributor omits the separator (paste corruption,
    // programmatic generation), the first data row is silently skipped
    // and a fully populated inventory lints as empty. Guard against that.
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("README.md");
    fs::write(&path, HEADER_WITHOUT_SEPARATOR).unwrap();
    let err = check_file(&path).expect_err("missing separator should fail");
    assert!(
        err.to_string().contains("separator row missing"),
        "got: {err}"
    );
}

const INVENTORY_HEADER_INSIDE_CODE_FENCE: &str = "\
# docs/formats inventory

The template below shows what a row looks like:

````markdown
| Doc | Doc status | Parser status | Parser module | Reference oracle | Last verified |
|-----|------------|---------------|----------------|-------------------|---------------|
| `example.md` | done | done | — | — | n/a |
````

## Inventory

| Doc | Doc status | Parser status | Parser module | Reference oracle | Last verified |
|-----|------------|---------------|----------------|-------------------|---------------|
| `container/pak.md` | complete | complete | `container/pak/` | repak @ `abc` | `def` |
";

#[test]
fn skips_inventory_header_inside_fenced_code_block() {
    // A pasted example inventory inside a fenced code block must not
    // be mistaken for the real table. Without fence tracking, the
    // linter would lock onto the fake "done" rows and reject them as
    // invalid enum values — masking the real table beneath.
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("README.md");
    fs::write(&path, INVENTORY_HEADER_INSIDE_CODE_FENCE).unwrap();
    check_file(&path).expect("real inventory below fenced example should pass");
}

#[test]
fn rejects_file_exceeding_size_cap() {
    // Same DoS guard the required-headings linter has. A multi-GB README
    // committed (or symlinked) into docs/formats/ must not be able to OOM
    // the linter step.
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("README.md");
    let cap = usize::try_from(paksmith_doc_lint::MAX_DOC_BYTES).unwrap();
    let mut content = String::with_capacity(cap + 1);
    content.push_str("# huge\n");
    content.push_str(&"a".repeat(cap + 1 - content.len()));
    fs::write(&path, content).unwrap();
    let err = check_file(&path).expect_err("oversized file should fail");
    assert!(
        err.to_string().contains("exceeds cap"),
        "expected 'exceeds cap' in error, got: {err}"
    );
}
