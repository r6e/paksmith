//! `paksmith inspect <pak> <virtual/path>` — dump a uasset's structural
//! header as JSON.

use std::io::{self, Write};
use std::path::PathBuf;

use clap::Args;

use paksmith_core::asset::Package;

use crate::output::OutputFormat;

#[derive(Args)]
pub struct InspectArgs {
    /// Path to the .pak file.
    pub pak: PathBuf,
    /// Virtual path of the asset within the archive.
    pub asset: String,
}

/// Run the `inspect` subcommand.
///
/// Currently emits JSON only; `format` is accepted for signature
/// consistency with sibling commands (e.g. `list`) but ignored.
/// Adding `--format table` for `Package` is a Phase 2c+ concern —
/// Phase 2a's deliverable is the JSON shape pinned by the integration
/// test snapshot.
pub fn run(args: &InspectArgs, _format: OutputFormat) -> paksmith_core::Result<()> {
    let pkg = Package::read_from_pak(&args.pak, &args.asset)?;

    let stdout = io::stdout();
    let mut out = stdout.lock();
    // Preserve the underlying io::ErrorKind through serde_json's wrapping
    // so main.rs's `BrokenPipe -> ExitCode::SUCCESS` handler still fires
    // when the reader (e.g. `| head`) closes the pipe mid-write. Mirrors
    // the pattern in `output::print_entries`.
    serde_json::to_writer_pretty(&mut out, &pkg).map_err(|e| {
        e.io_error_kind()
            .map_or_else(|| io::Error::other(e.to_string()), io::Error::from)
    })?;
    writeln!(out)?;
    Ok(())
}
