//! `required-headings` linter: enforces the eight-section template from
//! `docs/design/2026-05-19-ue-format-docs.md` on every `.md` under
//! `docs/formats/` except `README.md`, `TEMPLATE.md`, and `CONVENTIONS.md`.

use anyhow::{Context, Result, bail};
use std::path::Path;
use walkdir::WalkDir;

use crate::{EXCLUDED_FILENAMES, iter_non_fenced_lines, read_capped};

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

pub fn check_dir(dir: &Path) -> Result<()> {
    if !dir.exists() {
        bail!(
            "required-headings lint: directory {} does not exist",
            dir.display(),
        );
    }
    let mut failures: Vec<String> = Vec::new();
    for entry_result in WalkDir::new(dir) {
        let entry = entry_result.with_context(|| format!("walking {}", dir.display()))?;
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
        let content = read_capped(path)?;
        if let Err(err) = check_content(&content) {
            failures.push(format!("{}: {err:#}", path.display()));
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

fn check_content(content: &str) -> Result<()> {
    // Fence tracking lives in `iter_non_fenced_lines` (lib.rs) so this
    // body and `find_inventory_header` share one implementation.
    // CommonMark allows N-backtick outer fences to wrap shorter inner
    // fences (CONVENTIONS.md itself uses a 4-backtick outer wrapping
    // 3-backtick inner), which the helper handles.
    let h2s: Vec<&str> = iter_non_fenced_lines(content.lines())
        .filter(|(_, line)| line.starts_with("## "))
        .map(|(_, line)| line.trim_end())
        .collect();
    if h2s.len() < REQUIRED.len() {
        bail!(
            "missing required headings: found {}, expected {}",
            h2s.len(),
            REQUIRED.len()
        );
    }
    for (i, expected) in REQUIRED.iter().enumerate() {
        // The `h2s.len() < REQUIRED.len()` guard above proves `i < h2s.len()`,
        // so direct indexing is safe and clearer than `h2s.get(i)`.
        if h2s[i] != *expected {
            bail!(
                "heading at position {} is {:?}, expected {:?}",
                i + 1,
                h2s[i],
                expected
            );
        }
    }
    Ok(())
}
