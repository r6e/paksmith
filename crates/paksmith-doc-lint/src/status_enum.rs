//! `status-enum` linter: validates the inventory table in
//! `docs/formats/README.md`.
//!
//! Walks the inventory table, validates the Doc status and Parser status
//! cells against fixed enum sets, and emits warnings for smell combinations
//! (doc=complete + parser=not impl, doc=stub + parser=complete).

use anyhow::{Result, bail};
use std::path::Path;

use crate::{find_inventory_header, iter_inventory_rows, read_capped, validate_separator};

const DOC_STATUSES: &[&str] = &["stub", "partial", "complete"];
const PARSER_STATUSES: &[&str] = &["not impl", "partial", "complete"];

pub fn check_file(file: &Path) -> Result<()> {
    let content = read_capped(file)?;

    let lines: Vec<&str> = content.lines().collect();
    let header_idx = find_inventory_header(&lines, file)?;
    validate_separator(&lines, file, header_idx)?;

    let mut failures: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    for (offset, row) in iter_inventory_rows(&lines, header_idx) {
        match row {
            Ok(cells) => check_row(&cells, offset, &mut failures, &mut warnings),
            Err(actual) => failures.push(format!(
                "line {}: expected 6 cells, found {}",
                offset + 1,
                actual,
            )),
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

/// Validates one inventory row's six cells, pushing enum-violation
/// errors onto `failures` and smell-combo notices onto `warnings`.
/// `offset` is the zero-based line index in the file (caller adds 1
/// for human-friendly reporting).
fn check_row(
    cells: &[&str; 6],
    offset: usize,
    failures: &mut Vec<String>,
    warnings: &mut Vec<String>,
) {
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
    let line = offset + 1;
    let smell = match (doc_status, parser_status) {
        ("complete", "not impl") => Some(format!(
            "line {line}: doc marked complete but parser not impl"
        )),
        ("stub", "complete") => Some(format!("line {line}: parser complete but doc still stub")),
        ("complete", "partial") => Some(format!(
            "line {line}: doc marked complete but parser only partial (likely outdated doc)"
        )),
        ("partial", "complete") => Some(format!(
            "line {line}: parser complete but doc still partial (under-documented)"
        )),
        _ => None,
    };
    if let Some(msg) = smell {
        warnings.push(msg);
    }
}
