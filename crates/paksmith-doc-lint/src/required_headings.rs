//! `required-headings` linter: enforces the eight-section template from
//! `docs/design/2026-05-19-ue-format-docs.md` on every `.md` under
//! `docs/formats/` except `README.md`, `TEMPLATE.md`, and `CONVENTIONS.md`.

use anyhow::{Context, Result, bail};
use std::path::Path;
use walkdir::WalkDir;

const REQUIRED: &[&str] = &[
    "## Overview",
    "## Versions",
    "## Wire layout",
    "## Variants",
    "## Caps & limits",
    "## Verification",
    "## Paksmith implementation",
    "## References",
];

const EXCLUDED_FILENAMES: &[&str] = &["README.md", "TEMPLATE.md", "CONVENTIONS.md"];

pub fn check_dir(dir: &Path) -> Result<()> {
    let mut failures: Vec<String> = Vec::new();
    for entry in WalkDir::new(dir).into_iter().filter_map(Result::ok) {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("md") {
            continue;
        }
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if EXCLUDED_FILENAMES.contains(&name) {
            continue;
        }
        let content =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        if let Err(msg) = check_content(&content) {
            failures.push(format!("{}: {msg}", path.display()));
        }
    }
    if !failures.is_empty() {
        bail!(
            "required-headings lint failed:\n  - {}",
            failures.join("\n  - ")
        );
    }
    Ok(())
}

fn check_content(content: &str) -> Result<(), String> {
    let h2s: Vec<&str> = content.lines().filter(|l| l.starts_with("## ")).collect();
    if h2s.len() < REQUIRED.len() {
        return Err(format!(
            "missing required headings: found {}, expected {}",
            h2s.len(),
            REQUIRED.len()
        ));
    }
    for (i, expected) in REQUIRED.iter().enumerate() {
        if h2s.get(i) != Some(expected) {
            return Err(format!(
                "heading at position {} is {:?}, expected {:?}",
                i + 1,
                h2s.get(i).copied().unwrap_or(""),
                expected
            ));
        }
    }
    Ok(())
}
