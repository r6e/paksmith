//! `inventory-files` linter: cross-checks the inventory table's `Doc`
//! column against actual on-disk files under `docs/formats/`.
//!
//! Fails if:
//! - A **concrete** inventory row (doc_status != `stub`) names a file
//!   that does not exist on disk.
//! - A `.md` file exists on disk (under `<docs-dir>`, excluding
//!   `README.md`, `TEMPLATE.md`, `CONVENTIONS.md`) with no inventory
//!   row at all.
//!
//! Stub rows are deliberately exempt from the "missing on disk" half
//! of the check: per the design spec, stub rows are placeholders for
//! not-yet-authored docs and are added in bulk before the matching
//! per-family content PRs land.

use anyhow::{Context, Result, bail};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use walkdir::WalkDir;

use crate::{
    EXCLUDED_FILENAMES, find_inventory_header, iter_inventory_rows, read_capped, validate_separator,
};

pub fn check(readme: &Path, docs_dir: &Path) -> Result<()> {
    if !readme.exists() {
        bail!("inventory README not found: {}", readme.display());
    }
    if !docs_dir.exists() {
        bail!("docs directory not found: {}", docs_dir.display());
    }

    let content = read_capped(readme)?;
    let (concrete, stubs) = extract_inventoried_paths(&content, readme)?;
    let on_disk = collect_disk_paths(docs_dir)?;

    let mut failures: Vec<String> = Vec::new();

    // Concrete rows MUST have a matching file on disk.
    for path in &concrete {
        if !on_disk.contains(path) {
            failures.push(format!(
                "concrete inventory row `{path}` has no corresponding file on disk",
            ));
        }
    }

    // Stub rows whose file exists on disk are real drift: the spec
    // defines `stub` as "the pre-authoring placeholder state, not used
    // by any authored doc." A file existing on disk implies the doc
    // has been authored, so the row MUST be at least `partial`. Warn
    // (don't fail) so the row gets bumped on the next pass, matching
    // the smell-warning shape `status_enum` already uses.
    for path in &stubs {
        if on_disk.contains(path) {
            eprintln!(
                "warning: {}: inventory row `{}` is `stub` but the file exists on disk — bump the row to `partial` or `complete`",
                readme.display(),
                path,
            );
        }
    }

    // Every on-disk file MUST have an inventory row (concrete or stub).
    let all_inventoried: HashSet<&String> = concrete.iter().chain(stubs.iter()).collect();
    for path in &on_disk {
        if !all_inventoried.contains(path) {
            failures.push(format!(
                "file `{path}` exists on disk but has no inventory row",
            ));
        }
    }

    if !failures.is_empty() {
        bail!(
            "inventory-files lint failed for {}:\n  - {}",
            readme.display(),
            failures.join("\n  - "),
        );
    }
    Ok(())
}

/// Returns `(concrete_paths, stub_paths)` — paths from rows with
/// doc_status != "stub" and == "stub" respectively. Both sets carry the
/// inventory's view of which docs SHOULD exist; only concrete rows are
/// required to back that claim with a file on disk.
///
/// Duplicate rows (same Doc cell appearing twice) emit a stderr
/// warning; the FIRST row's status wins, and the duplicate is dropped
/// before bucketing. Without the first-seen gate, a cross-status
/// duplicate (row 1 `stub`, row 2 `partial`) lands the path in BOTH
/// sets and triggers contradictory downstream diagnostics (concrete-
/// missing-file failure AND stub-with-file warning) for the same path.
/// Malformed rows are silently skipped; `status_enum` is the canonical
/// reporter for that diagnostic and runs first in CI.
fn extract_inventoried_paths(
    content: &str,
    readme: &Path,
) -> Result<(HashSet<String>, HashSet<String>)> {
    let lines: Vec<&str> = content.lines().collect();
    let header_idx = find_inventory_header(&lines, readme)?;
    validate_separator(&lines, readme, header_idx)?;

    // Walk via HashMap<path, first-seen line> so the dedup-into-HashSet
    // step doesn't hide a contributor who pasted the same row twice
    // (easy to do when bulk-stubbing new families).
    let mut seen: HashMap<String, usize> = HashMap::new();
    let mut concrete: HashSet<String> = HashSet::new();
    let mut stubs: HashSet<String> = HashSet::new();
    for (offset, row) in iter_inventory_rows(&lines, header_idx) {
        let Ok(cells) = row else { continue };
        let doc_cell = cells[0]
            .trim_start_matches('`')
            .trim_end_matches('`')
            .to_string();
        let doc_status = cells[1];
        if let Some(prev_line) = seen.get(&doc_cell) {
            eprintln!(
                "warning: {}: inventory row `{}` at line {} duplicates the row at line {}",
                readme.display(),
                doc_cell,
                offset + 1,
                prev_line + 1,
            );
            // Skip bucketing the duplicate: the first-seen row's status
            // is authoritative. Otherwise a cross-status duplicate lands
            // the path in both sets and emits spurious downstream
            // diagnostics for the same row.
            continue;
        }
        let _ = seen.insert(doc_cell.clone(), offset);
        let target = if doc_status == "stub" {
            &mut stubs
        } else {
            &mut concrete
        };
        let _ = target.insert(doc_cell);
    }
    Ok((concrete, stubs))
}

fn collect_disk_paths(docs_dir: &Path) -> Result<HashSet<String>> {
    let mut paths: HashSet<String> = HashSet::new();
    for entry_result in WalkDir::new(docs_dir) {
        let entry = entry_result.with_context(|| format!("walking {}", docs_dir.display()))?;
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
        let relative = path
            .strip_prefix(docs_dir)
            .with_context(|| format!("path {} not under {}", path.display(), docs_dir.display()))?;
        // Normalize to forward slashes so Windows runners produce the
        // same key shape as the inventory cells (which always use `/`).
        // Gated on Windows because `\` is a legal filename byte on
        // Linux/macOS, where an unconditional replace would corrupt
        // names that legitimately contain a backslash.
        let raw = relative.to_string_lossy();
        let as_string = if cfg!(windows) {
            raw.replace('\\', "/")
        } else {
            raw.into_owned()
        };
        let _ = paths.insert(as_string);
    }
    Ok(paths)
}
