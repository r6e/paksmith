use std::path::PathBuf;

use clap::Args;

use paksmith_core::AesKey;

use crate::output::OutputFormat;

#[derive(Args)]
pub(crate) struct ListArgs {
    /// Path to .pak file. Optional when `--game`/`--detect` selects a
    /// profile with `pak_paths` patterns (#655) — then every matching
    /// archive is listed.
    pub(crate) path: Option<PathBuf>,

    /// Filter entries by glob pattern
    #[arg(long)]
    pub(crate) filter: Option<String>,
}

pub(crate) fn run(
    args: &ListArgs,
    format: OutputFormat,
    aes_key: Option<&AesKey>,
    game: Option<&str>,
    detect: Option<&std::path::Path>,
    quiet: bool,
) -> paksmith_core::Result<()> {
    let sources = crate::profile_paks::resolve_pak_sources(args.path.as_deref(), game, detect)?;
    let pattern = crate::path_util::compile_opt_glob_arg("--filter", args.filter.as_deref())?;

    let mut groups = Vec::with_capacity(sources.len());
    for pak in sources {
        let key = crate::commands::key_resolve::resolve_pak_key(&pak, aes_key, game, detect)?;
        let reader = paksmith_core::container::open(&pak, key.as_ref())?;
        let filtered: Vec<_> = reader
            .entries()
            .filter(|e| pattern.as_ref().is_none_or(|pat| pat.matches(e.path())))
            .collect();
        groups.push((pak, filtered));
    }

    let resolved = format.resolve();
    crate::output::note_auto_resolved_to_json(format, resolved, quiet);
    if args.path.is_some() {
        // Explicit-path invocation: byte-identical output to pre-#655.
        crate::output::print_entries(&groups[0].1, resolved)?;
    } else {
        crate::output::print_entries_grouped(&groups, resolved)?;
    }
    Ok(())
}
