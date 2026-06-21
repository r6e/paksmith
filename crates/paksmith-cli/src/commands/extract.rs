//! `paksmith extract <pak> -o <dir>` — batch export pak contents.

use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::sync::Arc;

use clap::Args;
use indicatif::{ProgressBar, ProgressStyle};

use paksmith_core::AesKey;
use paksmith_core::PaksmithError;
use paksmith_core::container::ContainerReader;
use paksmith_core::container::pak::PakReader;
use paksmith_core::export::HandlerRegistry;

use crate::extract::summary::ExtractSummary;
use crate::extract::{ExtractConfig, ExtractJob};
use crate::output::OutputFormat;

// Re-export the format enums so other modules (tests, etc.) can reach them via
// `commands::extract::{AudioFormat, DataTableFormat}`. Definitions live in
// `extract::select` (logic layer); the command layer is a thin re-exporter.
pub(crate) use crate::extract::select::{AudioFormat, DataTableFormat, FormatPrefs};

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
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
    pub(crate) jobs: Option<u32>,
}

pub(crate) fn run(
    args: &ExtractArgs,
    format: OutputFormat,
    aes_key: Option<&AesKey>,
    game: Option<&str>,
    detect: Option<&std::path::Path>,
) -> paksmith_core::Result<u8> {
    let key = crate::commands::key_resolve::resolve_pak_key(&args.pak, aes_key, game, detect)?;
    let reader = Arc::new(match &key {
        Some(k) => PakReader::open_with_key(&args.pak, k.clone())?,
        None => PakReader::open(&args.pak)?,
    });

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

    // FIX 6: hide progress when stderr is not a TTY (e.g. CI, piped output) so
    // non-interactive callers get clean stderr without ANSI escape sequences.
    let target = if std::io::stderr().is_terminal() {
        indicatif::ProgressDrawTarget::stderr()
    } else {
        indicatif::ProgressDrawTarget::hidden()
    };
    let progress = ProgressBar::with_draw_target(Some(entries.len() as u64), target);
    progress.set_style(
        ProgressStyle::with_template("{bar:40} {pos}/{len} {msg}")
            .unwrap_or_else(|_| ProgressStyle::default_bar()),
    );

    let outcomes = match args.jobs {
        Some(n) => {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(n as usize)
                .build()
                .map_err(|e| PaksmithError::InvalidArgument {
                    arg: "--jobs",
                    reason: e.to_string(),
                })?;
            pool.install(|| job.run_with_progress(&entries, &progress))
        }
        None => job.run_with_progress(&entries, &progress),
    };
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
