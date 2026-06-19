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
/// Validates format, parses the asset + optional mappings, then delegates
/// all output assembly to [`crate::inspect::emit`].
///
/// The format check intentionally runs before parsing so that
/// `--format table` errors on stderr without producing any WARN logs
/// from the parsing path (behaviour identical to the prior inline
/// implementation).
pub(crate) fn run(args: &InspectArgs, format: OutputFormat) -> paksmith_core::Result<()> {
    // Match on the raw variant rather than `format.resolve()`, because
    // `Auto` resolves to `Table` on a TTY — and inspect has no tabular
    // renderer for `Package`. Explicit `--format table` is rejected;
    // `--format auto` falls through to JSON regardless of TTY.
    if matches!(format, OutputFormat::Table) {
        return Err(PaksmithError::InvalidArgument {
            arg: "--format",
            reason: "table format is not yet supported for `inspect`; use `json` or `auto`".into(),
        });
    }
    let usmap = args.mappings.as_deref().map(load_mappings).transpose()?;
    let pkg = Package::read_from_pak(&args.pak, &args.asset, usmap.as_ref())?;
    crate::inspect::emit(&pkg, args, format)
}
