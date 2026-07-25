//! `paksmith extract [pak] -o <dir>` — batch export pak contents.

use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::sync::Arc;

use clap::Args;
use indicatif::{ProgressBar, ProgressStyle};

use paksmith_core::AesKey;
use paksmith_core::PaksmithError;
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
    /// Path to the .pak file. Optional when `--game`/`--detect` selects
    /// a profile with `pak_paths` patterns — then every matching
    /// archive is extracted. Archives mount in sorted path order, and a
    /// virtual path present in several archives extracts from the LAST
    /// one only (UE patch semantics: later alphabetical mounts
    /// override; shadowed copies are skipped, not collisions).
    pub(crate) pak: Option<PathBuf>,

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

    /// Output format for .locres localization tables.
    #[arg(long, value_enum, default_value_t = DataTableFormat::Csv)]
    pub(crate) locres_format: DataTableFormat,

    /// Worker-thread cap (default: CPU count).
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
    pub(crate) jobs: Option<u32>,

    /// Optional `.usmap` mappings file. Required for assets whose
    /// `PKG_UnversionedProperties` flag is set (UE 4.25+ cooked
    /// content; common in both UE4 and UE5 shipping games) — without
    /// it every such asset is a per-entry failure. Wins over the
    /// mappings source of a `--game`/`--detect`-selected profile.
    #[arg(long, value_name = "PATH")]
    pub(crate) mappings: Option<PathBuf>,
}

pub(crate) fn run(
    args: &ExtractArgs,
    format: OutputFormat,
    aes_key: Option<&AesKey>,
    game: Option<&str>,
    detect: Option<&std::path::Path>,
    quiet: bool,
) -> paksmith_core::Result<u8> {
    let sources = crate::profile_paks::resolve_pak_sources(args.pak.as_deref(), game, detect)?;
    let pattern = crate::path_util::compile_opt_glob_arg("--filter", args.filter.as_deref())?;

    let registry = HandlerRegistry::all_default_handlers();
    let cfg = ExtractConfig {
        output_dir: args.output.clone(),
        flat: args.flat,
        dry_run: args.dry_run,
        overwrite: args.overwrite,
        prefs: FormatPrefs {
            audio: args.audio_format,
            datatable: args.datatable_format,
            locres: args.locres_format,
        },
    };
    let (usmap, opened) =
        open_and_collect(&sources, args, aes_key, game, detect, pattern.as_ref())?;
    let entry_lists: Vec<Vec<String>> = opened.iter().map(|(_, e)| e.clone()).collect();
    let winning = winning_entries(&entry_lists);

    // FIX 6: hide progress when stderr is not a TTY (e.g. CI, piped
    // output) so non-interactive callers get clean stderr without ANSI
    // escape sequences. --quiet hides it even on a TTY: the bar is
    // advisory chatter (#652). One bar spans every archive.
    let target = if show_progress(std::io::stderr().is_terminal(), quiet) {
        indicatif::ProgressDrawTarget::stderr()
    } else {
        indicatif::ProgressDrawTarget::hidden()
    };
    let total: u64 = winning.iter().map(|v| v.len() as u64).sum();
    let progress = ProgressBar::with_draw_target(Some(total), target);
    progress.set_style(
        ProgressStyle::with_template("{bar:40} {pos}/{len} {msg}")
            .unwrap_or_else(|_| ProgressStyle::default_bar()),
    );
    let pool = args
        .jobs
        .map(|n| {
            rayon::ThreadPoolBuilder::new()
                .num_threads(n as usize)
                .build()
                .map_err(|e| PaksmithError::InvalidArgument {
                    arg: "--jobs",
                    reason: e.to_string(),
                })
        })
        .transpose()?;

    let mut all_outcomes = Vec::new();
    for ((reader, _), entries) in opened.iter().zip(&winning) {
        let job = ExtractJob {
            reader: Arc::clone(reader),
            registry: &registry,
            cfg: &cfg,
            mappings: usmap.clone(),
        };
        let outcomes = match &pool {
            Some(p) => p.install(|| job.run_with_progress(entries, &progress)),
            None => job.run_with_progress(entries, &progress),
        };
        all_outcomes.extend(outcomes);
    }

    // Explicit-path invocations keep the pre-#655 label (the one path);
    // profile-paks runs label the summary with every source archive and
    // carry the machine-readable `sources` array.
    let mut summary = ExtractSummary::from_outcomes(
        crate::profile_paks::join_display(&sources),
        args.output.display().to_string(),
        args.dry_run,
        all_outcomes,
    );
    if args.pak.is_none() {
        summary.sources = sources.iter().map(|p| p.display().to_string()).collect();
    }
    let summary = summary;

    let resolved = format.resolve();
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    summary.render(resolved, &mut out)?;
    out.flush()?;

    Ok(u8::from(summary.had_failures()))
}

type OpenedSource = (
    std::sync::Arc<dyn paksmith_core::container::ContainerReader>,
    Vec<String>,
);

/// Phase 1 of a (possibly multi-archive) extract: resolve and open
/// EVERY source, collecting its filtered entry list, before any writes.
/// A bad archive (missing key, corrupt index) fails the whole run
/// cleanly at exit 2 with nothing partial on disk, instead of
/// discarding a half-finished run's summary. Per-source context
/// resolution repeats the store load / detection sweep (known cost —
/// hoisting needs a batch core entry point); the usmap is
/// profile-derived and pak-independent, so it is resolved and parsed
/// exactly once.
#[allow(clippy::type_complexity)]
fn open_and_collect(
    sources: &[std::path::PathBuf],
    args: &ExtractArgs,
    aes_key: Option<&AesKey>,
    game: Option<&str>,
    detect: Option<&std::path::Path>,
    pattern: Option<&glob::Pattern>,
) -> paksmith_core::Result<(
    Option<std::sync::Arc<paksmith_core::asset::Usmap>>,
    Vec<OpenedSource>,
)> {
    let mut usmap = None;
    let mut opened = Vec::with_capacity(sources.len());
    for pak in sources {
        let ctx = crate::commands::key_resolve::resolve_pak_context(pak, aes_key, game, detect)?;
        if usmap.is_none() {
            usmap = Some(crate::commands::mappings_resolve::resolve_usmap(
                args.mappings.as_deref(),
                ctx.mappings.as_ref(),
                crate::commands::mappings_resolve::mappings_selector(game),
            )?);
        }
        let reader = paksmith_core::container::open(pak, ctx.key.as_ref())?;
        let entries: Vec<String> = reader
            .entries()
            .filter(|e| pattern.is_none_or(|pat| pat.matches(e.path())))
            .map(|e| e.path().to_string())
            .collect();
        opened.push((reader, entries));
    }
    Ok((usmap.unwrap_or(None), opened))
}

/// Phase 2's winner decision, pure: UE mounts paks alphabetically and
/// later mounts override, so a virtual path present in several archives
/// extracts from the LAST source in sorted expansion order. Shadowed
/// copies are simply not extracted — no spurious create_new failures,
/// no order-dependent winner at the filesystem layer.
fn winning_entries(entry_lists: &[Vec<String>]) -> Vec<Vec<String>> {
    let mut winner: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for (idx, entries) in entry_lists.iter().enumerate() {
        for entry in entries {
            let _ = winner.insert(entry.as_str(), idx);
        }
    }
    entry_lists
        .iter()
        .enumerate()
        .map(|(idx, entries)| {
            entries
                .iter()
                .filter(|e| winner[e.as_str()] == idx)
                .cloned()
                .collect()
        })
        .collect()
}

/// Whether the extract progress bar draws: stderr must be a real TTY
/// (piped/CI stderr stays clean) AND `--quiet` must be off (the bar is
/// advisory chatter). Pure, like `styling_enabled`/`resolve_with_tty`
/// and for the same reason: a black-box test's captured stderr is never
/// a TTY, so the `quiet` leg of this decision is observable only here.
fn show_progress(stderr_is_tty: bool, quiet: bool) -> bool {
    stderr_is_tty && !quiet
}

#[cfg(test)]
mod winner_tests {
    use super::winning_entries;

    fn lists(input: &[&[&str]]) -> Vec<Vec<String>> {
        input
            .iter()
            .map(|l| l.iter().map(|s| (*s).to_string()).collect())
            .collect()
    }

    #[test]
    fn disjoint_lists_pass_through() {
        let got = winning_entries(&lists(&[&["a", "b"], &["c"]]));
        assert_eq!(got, lists(&[&["a", "b"], &["c"]]));
    }

    #[test]
    fn duplicate_path_extracts_from_last_archive_only() {
        // UE alphabetical-mount semantics: later archive wins; the
        // shadowed copy is dropped from the earlier list entirely.
        let got = winning_entries(&lists(&[&["shared", "base_only"], &["shared"]]));
        assert_eq!(got, lists(&[&["base_only"], &["shared"]]));
    }

    #[test]
    fn three_way_duplicate_keeps_only_the_final_copy() {
        let got = winning_entries(&lists(&[&["x"], &["x"], &["x", "y"]]));
        assert_eq!(got, lists(&[&[], &[], &["x", "y"]]));
    }
}

#[cfg(test)]
mod progress_tests {
    use super::show_progress;

    /// All four quadrants — the `quiet` leg cannot be seen by any
    /// integration test (captured stderr is never a TTY), so the full
    /// truth table lives here.
    #[test]
    fn show_progress_truth_table() {
        assert!(show_progress(true, false), "TTY, loud → bar");
        assert!(!show_progress(true, true), "TTY, quiet → hidden");
        assert!(!show_progress(false, false), "piped, loud → hidden");
        assert!(!show_progress(false, true), "piped, quiet → hidden");
    }
}
