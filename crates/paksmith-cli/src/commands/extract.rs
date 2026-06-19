//! `paksmith extract <pak> -o <dir>` — batch export pak contents.

use std::path::PathBuf;

use clap::{Args, ValueEnum};

use crate::output::OutputFormat;

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum AudioFormat {
    Ogg,
    Wav,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum DataTableFormat {
    Csv,
    Json,
}

#[derive(Args)]
pub(crate) struct ExtractArgs {
    /// Path to the .pak file.
    pub(crate) pak: PathBuf,

    /// Output directory (created if absent).
    #[arg(short, long)]
    pub(crate) output: PathBuf,

    /// Only extract entries whose path matches this glob.
    #[arg(long)]
    pub(crate) filter: Option<String>,

    /// Strip directories; write basenames into the output root.
    #[arg(long)]
    pub(crate) flat: bool,

    /// Parse and report would-be outputs without writing anything.
    #[arg(long)]
    pub(crate) dry_run: bool,

    /// Overwrite existing output files (and resolve --flat collisions
    /// last-writer-wins). Without it, an existing target is an error.
    #[arg(long)]
    pub(crate) overwrite: bool,

    /// Output format for USoundWave assets.
    #[arg(long, value_enum, default_value_t = AudioFormat::Ogg)]
    pub(crate) audio_format: AudioFormat,

    /// Output format for UDataTable assets.
    #[arg(long, value_enum, default_value_t = DataTableFormat::Csv)]
    pub(crate) datatable_format: DataTableFormat,

    /// Worker-thread cap (default: CPU count).
    #[arg(long)]
    pub(crate) jobs: Option<usize>,

    /// Game profile id. Reserved for Phase 5; not yet supported.
    #[arg(long, value_name = "ID")]
    pub(crate) game: Option<String>,
}

#[allow(clippy::unnecessary_wraps)]
pub(crate) fn run(_args: &ExtractArgs, _format: OutputFormat) -> paksmith_core::Result<u8> {
    // Stub — filled in by later tasks.
    Ok(0)
}
