//! `paksmith search <pak>` — query archive entries by extension, name
//! (basename glob), full-path regex, and uncompressed size range. Index-only;
//! no asset parsing.

use std::path::PathBuf;

use clap::Args;
use paksmith_core::AesKey;
use paksmith_core::PaksmithError;

use crate::output::OutputFormat;
use crate::search::Predicates;

#[derive(Args)]
pub(crate) struct SearchArgs {
    /// Path to the .pak file. Optional when `--game`/`--detect` selects
    /// a profile with `pak_paths` patterns (#655) — then every matching
    /// archive is searched.
    pub(crate) pak: Option<PathBuf>,

    /// Match entries whose file extension is any of these (repeatable,
    /// case-insensitive, no leading dot). e.g. `--type uasset --type umap`.
    #[arg(long, value_name = "EXT")]
    pub(crate) r#type: Vec<String>,

    /// Glob matched against the FULL virtual path (like list/extract's
    /// `--filter`), e.g. `Game/**`.
    #[arg(long, value_name = "GLOB")]
    pub(crate) filter: Option<String>,

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

pub(crate) fn run(
    args: &SearchArgs,
    format: OutputFormat,
    aes_key: Option<&AesKey>,
    game: Option<&str>,
    detect: Option<&std::path::Path>,
    quiet: bool,
) -> paksmith_core::Result<()> {
    let predicates = Predicates::from_args(args)
        .map_err(|(arg, reason)| PaksmithError::InvalidArgument { arg, reason })?;

    let sources = crate::profile_paks::resolve_pak_sources(args.pak.as_deref(), game, detect)?;
    let mut groups = Vec::with_capacity(sources.len());
    for pak in sources {
        let key = crate::commands::key_resolve::resolve_pak_key(&pak, aes_key, game, detect)?;
        let reader = paksmith_core::container::open(&pak, key.as_ref())?;
        let matches: Vec<_> = reader.entries().filter(|e| predicates.matches(e)).collect();
        groups.push((pak, matches));
    }

    let resolved = format.resolve();
    crate::output::note_auto_resolved_to_json(format, resolved, quiet);
    if args.pak.is_some() {
        // Explicit-path invocation: byte-identical output to pre-#655.
        crate::output::print_entries(&groups[0].1, resolved)?;
    } else {
        crate::output::print_entries_grouped(&groups, resolved)?;
    }
    Ok(())
}
