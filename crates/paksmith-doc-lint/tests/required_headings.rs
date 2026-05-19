#![allow(missing_docs)]

use paksmith_doc_lint::required_headings::check_dir;
use std::fs;
use tempfile::TempDir;

const WELL_FORMED: &str = "\
# Some format

## Overview
text
## Versions
text
## Wire layout
text
## Variants
text
## Caps & limits
text
## Verification
text
## Paksmith implementation
text
## References
text
";

#[test]
fn accepts_well_formed_doc() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("some-format.md"), WELL_FORMED).unwrap();
    check_dir(dir.path()).expect("well-formed doc should pass");
}

const MISSING_REFERENCES: &str = "\
# Some format

## Overview
text
## Versions
text
## Wire layout
text
## Variants
text
## Caps & limits
text
## Verification
text
## Paksmith implementation
text
";

#[test]
fn rejects_doc_missing_references_section() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("some-format.md"), MISSING_REFERENCES).unwrap();
    let err = check_dir(dir.path()).expect_err("should fail");
    assert!(
        err.to_string().contains("missing required headings")
            || err.to_string().contains("expected"),
        "unexpected error: {err}"
    );
}

const REORDERED: &str = "\
# Some format

## Overview
text
## Wire layout
text
## Versions
text
## Variants
text
## Caps & limits
text
## Verification
text
## Paksmith implementation
text
## References
text
";

#[test]
fn rejects_doc_with_headings_in_wrong_order() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("some-format.md"), REORDERED).unwrap();
    let err = check_dir(dir.path()).expect_err("should fail");
    assert!(
        err.to_string().contains("position 2"),
        "expected error to name position 2 (Versions vs Wire layout swap), got: {err}"
    );
}

#[test]
fn skips_readme_template_conventions() {
    let dir = TempDir::new().unwrap();
    // These would fail required-headings if they were checked.
    fs::write(
        dir.path().join("README.md"),
        "# Front door\n\nNo H2s here.\n",
    )
    .unwrap();
    fs::write(dir.path().join("TEMPLATE.md"), "# Skeleton\n\nNo H2s.\n").unwrap();
    fs::write(
        dir.path().join("CONVENTIONS.md"),
        "# Conventions\n\nNone.\n",
    )
    .unwrap();
    check_dir(dir.path()).expect("excluded files should be skipped");
}

#[test]
fn descends_into_family_subdirectories() {
    let dir = TempDir::new().unwrap();
    let sub = dir.path().join("container");
    fs::create_dir(&sub).unwrap();
    fs::write(sub.join("pak.md"), "# Pak\n\nNo H2s — should fail.\n").unwrap();
    let err = check_dir(dir.path()).expect_err("subdir doc should be checked");
    assert!(
        err.to_string().contains("pak.md"),
        "error should reference pak.md, got: {err}"
    );
}
