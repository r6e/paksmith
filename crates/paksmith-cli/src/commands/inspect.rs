//! `paksmith inspect <pak> <virtual/path>` — dump a uasset's structural
//! header as JSON.

use std::io::{self, Write};
use std::path::PathBuf;

use clap::Args;

use paksmith_core::PaksmithError;
use paksmith_core::asset::Package;

use crate::output::{OutputFormat, serde_json_to_io};

#[derive(Args)]
pub struct InspectArgs {
    /// Path to the .pak file.
    pub pak: PathBuf,
    /// Virtual path of the asset within the archive.
    pub asset: String,
}

/// Run the `inspect` subcommand.
///
/// `--format json` and `--format auto` both produce JSON. `--format
/// table` is rejected (Phase 2a doesn't support tabular Package
/// rendering; tabular output for nested types is a Phase 2c+ concern).
pub fn run(args: &InspectArgs, format: OutputFormat) -> paksmith_core::Result<()> {
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

    let pkg = Package::read_from_pak(&args.pak, &args.asset)?;

    let stdout = io::stdout();
    let mut out = stdout.lock();
    // `serde_json_to_io` preserves the wrapped `io::ErrorKind` (notably
    // `BrokenPipe`) so `main.rs`'s pipe-clean-exit handler still fires
    // when the reader (e.g. `| head`) closes the pipe mid-write.
    serde_json::to_writer_pretty(&mut out, &pkg).map_err(serde_json_to_io)?;
    writeln!(out)?;
    Ok(())
}
