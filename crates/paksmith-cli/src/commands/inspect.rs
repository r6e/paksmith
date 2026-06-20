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
use std::sync::Arc;

use clap::Args;

use paksmith_core::AesKey;
use paksmith_core::PaksmithError;
use paksmith_core::asset::Package;
use paksmith_core::asset::mappings::Usmap;
use paksmith_core::container::pak::PakReader;

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
    /// Emit only a single export: a numeric export-table index, or an export
    /// object name. Errors on an unknown/ambiguous name or out-of-range index.
    #[arg(long, value_name = "IDX|NAME")]
    pub(crate) export: Option<String>,
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
/// Loads any `--mappings`, parses the package, then delegates all output
/// assembly — format resolution, `--export` selection, `--path` drilling,
/// and the `--format table` human tree view — to [`crate::inspect::emit`].
pub(crate) fn run(
    args: &InspectArgs,
    format: OutputFormat,
    aes_key: Option<&AesKey>,
    game: Option<&str>,
) -> paksmith_core::Result<()> {
    let usmap = args.mappings.as_deref().map(load_mappings).transpose()?;
    let key = crate::commands::key_resolve::resolve_pak_key(&args.pak, aes_key, game)?;
    let reader = Arc::new(match &key {
        Some(k) => PakReader::open_with_key(&args.pak, k.clone())?,
        None => PakReader::open(&args.pak)?,
    });
    let pkg = Package::read_from_reader(&reader, &args.asset, usmap.as_ref())?;
    crate::inspect::emit(&pkg, args, format)
}
