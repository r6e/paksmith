//! `paksmith inspect <pak> <virtual/path>` — dump a uasset's parsed
//! shape as JSON.
//!
//! The output covers the full Phase 2 surface: structural header
//! (summary, name table, imports, exports, custom versions, engine
//! version) PLUS the decoded property tree from each export's
//! `PropertyBag`. Exports that decode cleanly serialize as
//! `PropertyBag::Tree { properties: [...] }`; an iterator failure
//! falls back to `PropertyBag::Opaque { payload_bytes: N }` (a byte
//! count, not the raw bytes, to keep CLI output bounded).
//!
//! Pass `--mappings <file.usmap>` to decode `.usmap`-driven
//! unversioned assets that would otherwise reject with
//! `UnversionedWithoutMappings`.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use clap::Args;

use paksmith_core::PaksmithError;
use paksmith_core::asset::Package;
use paksmith_core::asset::mappings::Usmap;

use crate::output::{OutputFormat, serde_json_to_io};

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
/// `--format json` and `--format auto` both produce JSON. `--format
/// table` is rejected (Phase 2a doesn't support tabular Package
/// rendering; tabular output for nested types is a Phase 2c+ concern).
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

    let stdout = io::stdout();
    let mut out = stdout.lock();
    // `serde_json_to_io` preserves the wrapped `io::ErrorKind` (notably
    // `BrokenPipe`) so `main.rs`'s pipe-clean-exit handler still fires
    // when the reader (e.g. `| head`) closes the pipe mid-write.
    serde_json::to_writer_pretty(&mut out, &pkg).map_err(serde_json_to_io)?;
    writeln!(out)?;
    Ok(())
}
