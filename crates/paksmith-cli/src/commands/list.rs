use std::path::PathBuf;

use clap::Args;

use paksmith_core::AesKey;

use crate::output::OutputFormat;

#[derive(Args)]
pub(crate) struct ListArgs {
    /// Path to .pak file
    pub(crate) path: PathBuf,

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
    let key = crate::commands::key_resolve::resolve_pak_key(&args.path, aes_key, game, detect)?;
    let reader = paksmith_core::container::open(&args.path, key.as_ref())?;

    let pattern = crate::path_util::compile_opt_glob_arg("--filter", args.filter.as_deref())?;
    let filtered: Vec<_> = reader
        .entries()
        .filter(|e| pattern.as_ref().is_none_or(|pat| pat.matches(e.path())))
        .collect();

    let resolved = format.resolve();
    crate::output::note_auto_resolved_to_json(format, resolved, quiet);
    crate::output::print_entries(&filtered, resolved)?;
    Ok(())
}
