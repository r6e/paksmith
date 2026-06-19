//! `paksmith extract <pak> -o <dir>` — batch export pak contents.

use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Arc;

use clap::{Args, ValueEnum};

use paksmith_core::PaksmithError;
use paksmith_core::container::ContainerReader;
use paksmith_core::container::pak::PakReader;
use paksmith_core::export::HandlerRegistry;

use crate::extract::select::FormatPrefs;
use crate::extract::summary::ExtractSummary;
use crate::extract::{ExtractConfig, ExtractJob};
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

pub(crate) fn run(args: &ExtractArgs, format: OutputFormat) -> paksmith_core::Result<u8> {
    if args.game.is_some() {
        return Err(PaksmithError::InvalidArgument {
            arg: "--game",
            reason: "game profiles are not supported until Phase 5".into(),
        });
    }

    let reader = Arc::new(PakReader::open(&args.pak)?);

    let pattern = match &args.filter {
        Some(p) => Some(
            glob::Pattern::new(p).map_err(|e| PaksmithError::InvalidArgument {
                arg: "--filter",
                reason: e.to_string(),
            })?,
        ),
        None => None,
    };

    let entries: Vec<String> = reader
        .entries()
        .filter(|e| pattern.as_ref().is_none_or(|pat| pat.matches(e.path())))
        .map(|e| e.path().to_string())
        .collect();

    let registry = HandlerRegistry::all_default_handlers();
    let cfg = ExtractConfig {
        output_dir: args.output.clone(),
        flat: args.flat,
        dry_run: args.dry_run,
        overwrite: args.overwrite,
        prefs: FormatPrefs {
            audio: args.audio_format,
            datatable: args.datatable_format,
        },
    };
    let job = ExtractJob {
        reader: Arc::clone(&reader),
        registry: &registry,
        cfg: &cfg,
    };

    let outcomes = job.run_sequential(&entries);
    let summary = ExtractSummary::from_outcomes(
        args.pak.display().to_string(),
        args.output.display().to_string(),
        args.dry_run,
        outcomes,
    );

    let resolved = format.resolve();
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    summary.render(resolved, &mut out)?;
    out.flush()?;

    Ok(u8::from(summary.had_failures()))
}
