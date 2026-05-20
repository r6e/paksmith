//! `status-enum` linter: validates the inventory table in
//! `docs/formats/README.md`.
//!
//! Walks the inventory table, validates the Doc status and Parser status
//! cells against fixed enum sets, and emits warnings for smell combinations
//! (doc=complete + parser=not impl, doc=stub + parser=complete).

use anyhow::{Result, bail};
use std::path::Path;

use crate::{INVENTORY_HEADER_PREFIX, read_capped};

const DOC_STATUSES: &[&str] = &["stub", "partial", "complete"];
const PARSER_STATUSES: &[&str] = &["not impl", "partial", "complete"];

pub fn check_file(file: &Path) -> Result<()> {
    let content = read_capped(file)?;

    let lines: Vec<&str> = content.lines().collect();
    let header_idx = lines
        .iter()
        .position(|l| l.trim_start().starts_with(INVENTORY_HEADER_PREFIX))
        .ok_or_else(|| {
            // Surface the closest table-like line so contributors see
            // the diff between what they wrote and what the linter
            // expected (trailing whitespace, reordered columns, column-
            // width drift all hide behind an opaque "not found").
            let candidate = lines.iter().find(|l| l.trim_start().starts_with("| "));
            match candidate {
                Some(actual) => anyhow::anyhow!(
                    "{}: inventory table header row not found.\n  Expected: {:?}\n  Found (closest match): {:?}",
                    file.display(),
                    INVENTORY_HEADER_PREFIX,
                    actual,
                ),
                None => anyhow::anyhow!(
                    "{}: inventory table header row not found (no markdown table detected at all; expected line starting with {:?})",
                    file.display(),
                    INVENTORY_HEADER_PREFIX,
                ),
            }
        })?;

    // Header row is followed by a separator row (|---|---|...|). Verify
    // the line at header_idx + 1 actually looks like one — otherwise
    // `skip(header_idx + 2)` silently throws away what was meant to be
    // the first data row, and an inventory written without a separator
    // (paste corruption, programmatic generation) lints clean.
    let separator = lines.get(header_idx + 1).copied().unwrap_or("");
    if !separator.trim_start().starts_with("|-") {
        bail!(
            "{}: inventory table separator row missing or malformed at line {} (expected `|---|---|...|`, got {:?})",
            file.display(),
            header_idx + 2,
            separator,
        );
    }

    let mut failures: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    for (offset, raw) in lines.iter().enumerate().skip(header_idx + 2) {
        let trimmed = raw.trim();
        if !trimmed.starts_with('|') {
            // Table ended (blank line or other content).
            break;
        }
        let cells: Vec<&str> = trimmed
            .trim_start_matches('|')
            .trim_end_matches('|')
            .split('|')
            .map(str::trim)
            .collect();
        if cells.len() != 6 {
            failures.push(format!(
                "line {}: expected 6 cells, found {} ({:?})",
                offset + 1,
                cells.len(),
                trimmed,
            ));
            continue;
        }
        let doc_status = cells[1];
        let parser_status = cells[2];
        if !DOC_STATUSES.contains(&doc_status) {
            failures.push(format!(
                "line {}: doc status {:?} not in {:?}",
                offset + 1,
                doc_status,
                DOC_STATUSES,
            ));
        }
        if !PARSER_STATUSES.contains(&parser_status) {
            failures.push(format!(
                "line {}: parser status {:?} not in {:?}",
                offset + 1,
                parser_status,
                PARSER_STATUSES,
            ));
        }
        // Smell warnings (do not fail).
        if doc_status == "complete" && parser_status == "not impl" {
            warnings.push(format!(
                "line {}: doc marked complete but parser not impl",
                offset + 1,
            ));
        }
        if doc_status == "stub" && parser_status == "complete" {
            warnings.push(format!(
                "line {}: parser complete but doc still stub",
                offset + 1,
            ));
        }
        if doc_status == "complete" && parser_status == "partial" {
            warnings.push(format!(
                "line {}: doc marked complete but parser only partial (likely outdated doc)",
                offset + 1,
            ));
        }
        if doc_status == "partial" && parser_status == "complete" {
            warnings.push(format!(
                "line {}: parser complete but doc still partial (under-documented)",
                offset + 1,
            ));
        }
    }

    for w in &warnings {
        eprintln!("warning: {}: {w}", file.display());
    }
    if !failures.is_empty() {
        bail!(
            "status-enum lint failed for {}:\n  - {}",
            file.display(),
            failures.join("\n  - "),
        );
    }
    Ok(())
}
