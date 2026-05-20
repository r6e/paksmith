//! Library surface for `paksmith-doc-lint` — hosts the CI lint
//! routines that validate the `docs/formats/` per-format documentation
//! template introduced in the UE format documentation framework.
//!
//! Three subcommands ship with this crate:
//!   - `required-headings` — verifies every per-format README under a
//!     given directory contains the canonical section headings.
//!   - `status-enum` — verifies the inventory README's status column
//!     only uses values from a fixed enum.
//!   - `inventory-files` — cross-checks inventory rows against on-disk
//!     `.md` files under `docs/formats/`.
//!
//! Not intended for downstream consumers — this crate is excluded
//! from the workspace's `default-members` and not published.

#![allow(missing_docs)]

use anyhow::{Context, Result, bail};
use std::path::Path;

pub mod inventory_files;
pub mod required_headings;
pub mod status_enum;

/// Hard cap on per-file size for any doc-lint input. Real format docs are
/// 2-8 KiB; 5 MiB is generous. Without this cap a single multi-GB file
/// committed under `docs/formats/` would OOM the linter step and stall CI.
pub const MAX_DOC_BYTES: u64 = 5 * 1024 * 1024;

/// Header row prefix used by the `docs/formats/README.md` inventory table.
/// Shared by `status_enum` (column validation) and `inventory_files`
/// (file cross-check); hoisted so a column-order change touches one
/// constant instead of two.
pub const INVENTORY_HEADER_PREFIX: &str =
    "| Doc | Doc status | Parser status | Parser module | Reference oracle | Last verified |";

/// Files under `docs/formats/` that are NOT per-format docs and therefore
/// skip both the required-headings lint (no `## Wire layout` etc.) and the
/// inventory-files cross-check (they don't get inventory rows). Shared by
/// `required_headings` and `inventory_files`.
pub const EXCLUDED_FILENAMES: &[&str] = &["README.md", "TEMPLATE.md", "CONVENTIONS.md"];

/// Reads `path` to a string, refusing files larger than [`MAX_DOC_BYTES`].
///
/// Used by every lint routine that ingests untrusted on-disk markdown so
/// the CI step has a deterministic memory ceiling regardless of what
/// lands under `docs/formats/`.
pub fn read_capped(path: &Path) -> Result<String> {
    let len = std::fs::metadata(path)
        .with_context(|| format!("stat {}", path.display()))?
        .len();
    if len > MAX_DOC_BYTES {
        bail!(
            "{}: file size {} exceeds cap {} bytes",
            path.display(),
            len,
            MAX_DOC_BYTES,
        );
    }
    std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))
}

/// Locates the inventory header row in `lines`, returning its index.
///
/// Skips lines inside fenced code blocks so an example inventory pasted
/// into a `` ``` `` block (CONVENTIONS.md does this) cannot be mistaken
/// for the live table. Nested fences are tracked the same way
/// `required_headings` tracks them (an outer N-backtick fence stays
/// open until a fence of length ≥ N closes it; shorter inner fences
/// are ignored).
///
/// On miss, surfaces the closest table-like line so contributors see
/// the diff between what they wrote and what the linter expected —
/// trailing whitespace, reordered columns, column-width drift all hide
/// behind an opaque "not found" otherwise.
pub(crate) fn find_inventory_header(lines: &[&str], file: &Path) -> Result<usize> {
    let mut open_fence_len: Option<usize> = None;
    let mut found: Option<usize> = None;
    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        let backticks = trimmed.chars().take_while(|c| *c == '`').count();
        if backticks >= 3 {
            match open_fence_len {
                None => open_fence_len = Some(backticks),
                Some(open) if backticks >= open => open_fence_len = None,
                Some(_) => {} // shorter fence inside outer; ignore
            }
            continue;
        }
        if open_fence_len.is_none() && trimmed.starts_with(INVENTORY_HEADER_PREFIX) {
            found = Some(idx);
            break;
        }
    }
    found.ok_or_else(|| {
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
    })
}

/// Verifies the line at `header_idx + 1` is a markdown table separator
/// row (`|---|---|...|`). Without this guard, callers' `skip(header_idx + 2)`
/// loop silently throws away what was meant to be the first data row,
/// and an inventory written without a separator (paste corruption,
/// programmatic generation) lints clean.
pub(crate) fn validate_separator(lines: &[&str], file: &Path, header_idx: usize) -> Result<()> {
    let separator = lines.get(header_idx + 1).copied().unwrap_or("");
    if !separator.trim_start().starts_with("|-") {
        bail!(
            "{}: inventory table separator row missing or malformed at line {} (expected `|---|---|...|`, got {:?})",
            file.display(),
            header_idx + 2,
            separator,
        );
    }
    Ok(())
}

/// One inventory data row: `(line_offset, cells)` where `cells` carries
/// the six trimmed cell values, or `Err(actual_count)` if the row had a
/// different column count (`status_enum` reports that as a hard failure;
/// `inventory_files` filters them out and lets `status_enum` be the
/// canonical reporter).
pub(crate) type InventoryRow<'a> = (usize, std::result::Result<[&'a str; 6], usize>);

/// Iterates the data rows of the inventory table, starting two lines
/// past the header and stopping at the first non-table line. Yields
/// `(line_offset, Result<[&str; 6], usize>)` per row.
///
/// Callers that care about malformed rows match on `Err(count)`;
/// callers that don't filter via `.filter_map(|(o, r)| r.ok().map(|c| (o, c)))`.
pub(crate) fn iter_inventory_rows<'a>(
    lines: &'a [&'a str],
    header_idx: usize,
) -> impl Iterator<Item = InventoryRow<'a>> + 'a {
    lines
        .iter()
        .enumerate()
        .skip(header_idx + 2)
        .take_while(|(_, raw)| raw.trim().starts_with('|'))
        .map(|(offset, raw)| {
            let trimmed = raw.trim();
            let cells: Vec<&str> = trimmed
                .trim_start_matches('|')
                .trim_end_matches('|')
                .split('|')
                .map(str::trim)
                .collect();
            let parsed = <[&str; 6]>::try_from(cells.as_slice()).map_err(|_| cells.len());
            (offset, parsed)
        })
}
