//! `paksmith search <pak>` — query archive entries by extension, name
//! (basename glob), full-path regex, and uncompressed size range. Index-only;
//! no asset parsing.

use std::path::PathBuf;

use clap::Args;
use paksmith_core::PaksmithError;
use paksmith_core::container::ContainerReader;
use paksmith_core::container::pak::PakReader;

use crate::output::{OutputFormat, ResolvedFormat};
use crate::search::Predicates;

#[derive(Args)]
pub(crate) struct SearchArgs {
    /// Path to the .pak file.
    pub(crate) pak: PathBuf,

    /// Match entries whose file extension is any of these (repeatable,
    /// case-insensitive, no leading dot). e.g. `--type uasset --type umap`.
    #[arg(long, value_name = "EXT")]
    pub(crate) r#type: Vec<String>,

    /// Glob matched against the entry BASENAME (filename), e.g. `Hero*`.
    #[arg(long, value_name = "GLOB")]
    pub(crate) name: Option<String>,

    /// Regex matched against the FULL virtual path (unanchored).
    #[arg(long, value_name = "RE")]
    pub(crate) regex: Option<String>,

    /// Minimum uncompressed size (e.g. `1MB`, `512KiB`, `1048576`).
    #[arg(long, value_name = "SIZE")]
    pub(crate) min_size: Option<String>,

    /// Maximum uncompressed size (e.g. `10MB`).
    #[arg(long, value_name = "SIZE")]
    pub(crate) max_size: Option<String>,
}

pub(crate) fn run(args: &SearchArgs, format: OutputFormat) -> paksmith_core::Result<()> {
    let predicates = Predicates::from_args(args)
        .map_err(|(arg, reason)| PaksmithError::InvalidArgument { arg, reason })?;

    let reader = PakReader::open(&args.pak)?;
    let matches: Vec<_> = reader.entries().filter(|e| predicates.matches(e)).collect();

    let resolved = format.resolve();
    // Mirror `list`: warn when Auto silently became JSON because stdout
    // isn't a TTY, so users piping into head/jq aren't surprised.
    if matches!(format, OutputFormat::Auto) && matches!(resolved, ResolvedFormat::Json) {
        eprintln!(
            "note: stdout is not a terminal — emitting JSON. \
             Pass --format table to force table output."
        );
    }
    crate::output::print_entries(&matches, resolved)?;
    Ok(())
}
