#![allow(missing_docs)]

use paksmith_doc_lint::inventory_files::check;
use std::fs;
use tempfile::TempDir;

const HEADER: &str = "\
# docs/formats inventory

## Inventory

| Doc | Doc status | Parser status | Parser module | Reference oracle | Last verified |
|-----|------------|---------------|----------------|-------------------|---------------|
";

fn write_docs_dir(dir: &std::path::Path, files: &[(&str, &str)]) {
    for (rel, body) in files {
        let path = dir.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, body).unwrap();
    }
}

#[test]
fn accepts_inventory_matching_disk() {
    let dir = TempDir::new().unwrap();
    let readme = dir.path().join("README.md");
    let inventory = format!(
        "{HEADER}\
         | `container/pak.md` | complete | complete | `container/pak/` | repak @ `abc` | `def` |\n\
         | `asset/uasset.md` | partial | partial | `asset/` | unreal_asset @ `xyz` | `uvw` |\n",
    );
    fs::write(&readme, &inventory).unwrap();
    write_docs_dir(
        dir.path(),
        &[
            ("container/pak.md", "# pak"),
            ("asset/uasset.md", "# uasset"),
        ],
    );

    check(&readme, dir.path()).expect("matching inventory + disk should pass");
}

#[test]
fn rejects_concrete_inventory_row_missing_file() {
    let dir = TempDir::new().unwrap();
    let readme = dir.path().join("README.md");
    let inventory = format!(
        "{HEADER}\
         | `container/pak.md` | complete | complete | `container/pak/` | repak @ `abc` | `def` |\n",
    );
    fs::write(&readme, &inventory).unwrap();
    // No `container/pak.md` on disk.

    let err = check(&readme, dir.path()).expect_err("concrete row + missing file should fail");
    assert!(
        err.to_string().contains("no corresponding file on disk"),
        "got: {err}",
    );
    assert!(err.to_string().contains("container/pak.md"), "got: {err}");
}

#[test]
fn accepts_stub_inventory_row_missing_file() {
    // Stub rows are placeholders for not-yet-authored docs. They are
    // exempt from the "missing on disk" check by design — the live
    // scaffold ships ~40 stub rows with no matching files.
    let dir = TempDir::new().unwrap();
    let readme = dir.path().join("README.md");
    let inventory = format!(
        "{HEADER}\
         | `container/pak.md` | stub | not impl | — | — | n/a |\n",
    );
    fs::write(&readme, &inventory).unwrap();

    check(&readme, dir.path()).expect("stub rows should not require an on-disk file");
}

#[test]
fn rejects_disk_file_missing_inventory_row() {
    let dir = TempDir::new().unwrap();
    let readme = dir.path().join("README.md");
    fs::write(&readme, HEADER).unwrap();
    write_docs_dir(dir.path(), &[("primitive/fstring.md", "# fstring")]);

    let err = check(&readme, dir.path()).expect_err("orphan file should fail");
    assert!(
        err.to_string().contains("has no inventory row"),
        "got: {err}",
    );
    assert!(
        err.to_string().contains("primitive/fstring.md"),
        "got: {err}"
    );
}

#[test]
fn skips_excluded_filenames_on_disk() {
    // README.md, TEMPLATE.md, CONVENTIONS.md never need inventory rows.
    let dir = TempDir::new().unwrap();
    let readme = dir.path().join("README.md");
    fs::write(&readme, HEADER).unwrap();
    write_docs_dir(
        dir.path(),
        &[
            // README.md already written above; nested family READMEs too.
            ("container/README.md", "# container"),
            ("asset/README.md", "# asset"),
            ("TEMPLATE.md", "# template"),
            ("CONVENTIONS.md", "# conventions"),
        ],
    );

    check(&readme, dir.path()).expect("excluded files should be skipped");
}

#[test]
fn skips_inventory_header_inside_fenced_code_block() {
    // A pasted example inventory inside a fenced code block must not
    // be mistaken for the real table. The shared find_inventory_header
    // helper tracks fences so the example below the prose doesn't
    // shadow the real table.
    let dir = TempDir::new().unwrap();
    let readme = dir.path().join("README.md");
    let body = "\
# Inv

The template below shows what a row looks like:

````markdown
| Doc | Doc status | Parser status | Parser module | Reference oracle | Last verified |
|-----|------------|---------------|----------------|-------------------|---------------|
| `bogus.md` | done | done | — | — | n/a |
````

## Inventory

| Doc | Doc status | Parser status | Parser module | Reference oracle | Last verified |
|-----|------------|---------------|----------------|-------------------|---------------|
| `container/pak.md` | complete | complete | `container/pak/` | repak @ `abc` | `def` |
";
    fs::write(&readme, body).unwrap();
    write_docs_dir(dir.path(), &[("container/pak.md", "# pak")]);

    check(&readme, dir.path()).expect("fenced example should not shadow the real table");
}

#[test]
fn rejects_inventory_missing_separator_row() {
    // inventory_files now uses the shared validate_separator helper.
    // Without it, a paste-corrupted inventory with no separator would
    // silently lint clean because the data row got skipped along with
    // the missing separator.
    let dir = TempDir::new().unwrap();
    let readme = dir.path().join("README.md");
    let body = "\
# Inv

## Inventory

| Doc | Doc status | Parser status | Parser module | Reference oracle | Last verified |
| `container/pak.md` | complete | complete | `container/pak/` | repak @ `abc` | `def` |
";
    fs::write(&readme, body).unwrap();
    write_docs_dir(dir.path(), &[("container/pak.md", "# pak")]);

    let err = check(&readme, dir.path()).expect_err("missing separator should fail");
    assert!(
        err.to_string().contains("separator row missing"),
        "got: {err}",
    );
}

#[test]
fn errors_on_missing_readme() {
    let dir = TempDir::new().unwrap();
    let missing = dir.path().join("does-not-exist.md");
    let err = check(&missing, dir.path()).expect_err("missing readme should fail");
    assert!(
        err.to_string().contains("inventory README not found"),
        "got: {err}",
    );
}
