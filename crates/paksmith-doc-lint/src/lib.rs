//! Library surface for `paksmith-doc-lint` — hosts the CI lint
//! routines that validate the `docs/formats/` per-format documentation
//! template introduced in the UE format documentation framework.
//!
//! Two subcommands ship with this crate:
//!   - `required-headings` — verifies every per-format README under a
//!     given directory contains the canonical section headings.
//!   - `status-enum` — verifies the inventory README's status column
//!     only uses values from a fixed enum.
//!
//! Not intended for downstream consumers — this crate is excluded
//! from the workspace's `default-members` and not published.

#![allow(missing_docs)]

use anyhow::{Context, Result, bail};
use std::path::Path;

pub mod required_headings;
pub mod status_enum;

/// Hard cap on per-file size for any doc-lint input. Real format docs are
/// 2-8 KiB; 5 MiB is generous. Without this cap a single multi-GB file
/// committed under `docs/formats/` would OOM the linter step and stall CI.
pub const MAX_DOC_BYTES: u64 = 5 * 1024 * 1024;

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
