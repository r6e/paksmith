//! `paksmith search <pak>` — query archive entries by extension, name
//! (basename glob), full-path regex, and uncompressed size range. Index-only;
//! no asset parsing.

use std::path::PathBuf;

use clap::Args;

use crate::output::OutputFormat;

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

#[allow(
    clippy::unnecessary_wraps,
    reason = "stub; real logic + fallible ops land in Task 4"
)]
pub(crate) fn run(_args: &SearchArgs, _format: OutputFormat) -> paksmith_core::Result<()> {
    Ok(())
}
