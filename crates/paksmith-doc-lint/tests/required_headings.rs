#![allow(missing_docs)]

use paksmith_doc_lint::required_headings::check_dir;
use std::fs;
use tempfile::TempDir;

const WELL_FORMED: &str = include_str!("fixtures/well-formed-doc.md");

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
        err.to_string().contains("missing required headings"),
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

const WITH_CODE_BLOCK: &str = "\
# Some format

## Overview
text
## Versions
text
## Wire layout

```
## sample output
field: u32
```

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
fn accepts_doc_with_hash_lines_in_code_block() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("some-format.md"), WITH_CODE_BLOCK).unwrap();
    check_dir(dir.path())
        .expect("`## ...` lines inside a fenced code block must not count as headings");
}

const TRAILING_WHITESPACE: &str = concat!(
    "# Some format\n",
    "\n",
    "## Overview \n",
    "text\n",
    "## Versions  \n",
    "text\n",
    "## Wire layout \n",
    "text\n",
    "## Variants \n",
    "text\n",
    "## Caps & limits \n",
    "text\n",
    "## Verification \n",
    "text\n",
    "## Paksmith implementation \n",
    "text\n",
    "## References \n",
    "text\n",
);

#[test]
fn accepts_heading_with_trailing_whitespace() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("some-format.md"), TRAILING_WHITESPACE).unwrap();
    check_dir(dir.path()).expect("headings with trailing whitespace should pass");
}

const NESTED_FENCE: &str = "\
# Some format

## Overview
````markdown
## not a heading
```
## also not a heading
```
````
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
fn accepts_doc_with_nested_code_fences() {
    // CommonMark allows N-backtick outer fences to wrap shorter inner
    // fences (CONVENTIONS.md uses this exact pattern). A bool toggle
    // desyncs on the inner fence and starts counting the closing inner
    // ``` as opening a new block, so the outer's `## ...` inner lines
    // would leak into the heading list. The Option<usize> length-aware
    // tracker handles this correctly.
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("some-format.md"), NESTED_FENCE).unwrap();
    check_dir(dir.path()).expect("nested-fence doc should pass");
}

#[test]
fn rejects_file_exceeding_size_cap() {
    // Defense in depth: an attacker (or a stray multi-GB file under
    // `docs/formats/`) cannot OOM the linter step. The cap mirrors
    // `paksmith_doc_lint::MAX_DOC_BYTES`; this test pushes one byte over.
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("huge.md");
    let cap = usize::try_from(paksmith_doc_lint::MAX_DOC_BYTES).unwrap();
    let mut content = String::with_capacity(cap + 1);
    content.push_str("# Huge\n");
    content.push_str(&"a".repeat(cap + 1 - content.len()));
    fs::write(&path, content).unwrap();
    let err = check_dir(dir.path()).expect_err("oversized file should fail");
    assert!(
        err.to_string().contains("exceeds cap"),
        "expected 'exceeds cap' in error, got: {err}"
    );
}

#[test]
fn rejects_nonexistent_directory() {
    // Without an explicit existence check, `WalkDir::new(...).filter_map(Result::ok)`
    // silently swallows the IO error and the loop body never runs, leaving the linter
    // returning `Ok(())` on a missing path. Guard against that regression: a vanished
    // family directory or a path-typo in the workflow must fail loudly.
    let dir = TempDir::new().unwrap();
    let missing = dir.path().join("does-not-exist");
    let err = check_dir(&missing).expect_err("nonexistent dir should fail");
    assert!(
        err.to_string().contains("does not exist"),
        "expected 'does not exist' in error, got: {err}"
    );
}
