//! `paksmith inspect <pak> <virtual/path>` — dump a uasset's parsed
//! shape as JSON.
//!
//! The output covers the structural header (summary, name table,
//! imports, exports, custom versions, engine version) PLUS each
//! export's typed [`paksmith_core::Asset`] payload under an
//! `"asset"` field. Phase 3 ships only the `Generic` variant, so
//! the per-export shape is
//! `"asset": {"Generic": {"kind": "tree", "properties": [...]}}`
//! for decoded property streams and
//! `"asset": {"Generic": {"kind": "opaque", "bytes": N}}` for
//! iterator-failure fallbacks (byte count only — raw bytes are
//! omitted to keep CLI output bounded). Phase 3 sub-phases (3d-3h)
//! add typed variants — `"asset": {"DataTable": {...}}`,
//! `"asset": {"Texture2D": {...}}`, etc. — under the same
//! externally-tagged shape.
//!
//! Pass `--mappings <file.usmap>` to decode `.usmap`-driven
//! unversioned assets that would otherwise reject with
//! `UnversionedWithoutMappings`.

use std::path::{Path, PathBuf};

use clap::Args;

use paksmith_core::PaksmithError;
use paksmith_core::asset::Package;
use paksmith_core::asset::mappings::Usmap;

use crate::output::OutputFormat;

#[derive(Args)]
pub(crate) struct InspectArgs {
    /// Path to the .pak file.
    pub(crate) pak: PathBuf,
    /// Virtual path of the asset within the archive.
    pub(crate) asset: String,
    /// Optional `.usmap` mappings file. Required for assets whose
    /// `PKG_UnversionedProperties` flag is set (UE 4.25+ cooked
    /// content; common in both UE4 and UE5 shipping games).
    /// Versioned (tagged-property) assets parse without it.
    #[arg(long, value_name = "PATH")]
    pub(crate) mappings: Option<PathBuf>,
    /// Emit only the value at this dotted path (e.g. `summary.guid`,
    /// `exports.0.asset`). Implies structured output; cannot combine with
    /// `--format table`.
    #[arg(long, value_name = "DOTTED")]
    pub(crate) path: Option<String>,
}

/// Load a `.usmap` mappings file from disk via [`Usmap::from_path`],
/// rewrapping the library's `PaksmithError::Io` / `MappingsParse` into
/// `PaksmithError::InvalidArgument { arg: "--mappings", ... }` so the
/// user gets the offending CLI arg name in the error message.
fn load_mappings(path: &Path) -> paksmith_core::Result<Usmap> {
    Usmap::from_path(path).map_err(|e| PaksmithError::InvalidArgument {
        arg: "--mappings",
        reason: e.to_string(),
    })
}

/// Run the `inspect` subcommand.
///
/// Validates `--format table` before parsing so the user gets a clean
/// error without WARN logs from the parsing path. Then delegates all
/// output assembly (including `--path` handling) to [`crate::inspect::emit`].
pub(crate) fn run(args: &InspectArgs, format: OutputFormat) -> paksmith_core::Result<()> {
    // Reject `--format table` before parsing (with or without `--path`):
    // keeps stderr clean — no WARN logs from the asset parser appear before
    // the error message. `emit` re-checks as a safety net for future callers
    // that bypass `run()`.
    // `OutputFormat::Auto` is intentionally NOT rejected here: inspect's Auto
    // always resolves to JSON, never to table.
    if matches!(format, OutputFormat::Table) {
        return Err(PaksmithError::InvalidArgument {
            arg: "--format",
            reason: crate::inspect::TABLE_NOT_SUPPORTED.into(),
        });
    }
    let usmap = args.mappings.as_deref().map(load_mappings).transpose()?;
    let pkg = Package::read_from_pak(&args.pak, &args.asset, usmap.as_ref())?;
    crate::inspect::emit(&pkg, args, format)
}
