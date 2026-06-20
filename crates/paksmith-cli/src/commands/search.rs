//! `paksmith search <pak>` — query archive entries by extension, name
//! (basename glob), full-path regex, and uncompressed size range. Index-only;
//! no asset parsing.

use std::path::PathBuf;

use clap::Args;
use paksmith_core::AesKey;
use paksmith_core::PaksmithError;
use paksmith_core::container::ContainerReader;
use paksmith_core::container::pak::PakReader;

use crate::output::OutputFormat;
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

pub(crate) fn run(
    args: &SearchArgs,
    format: OutputFormat,
    aes_key: Option<&AesKey>,
    game: Option<&str>,
) -> paksmith_core::Result<()> {
    let predicates = Predicates::from_args(args)
        .map_err(|(arg, reason)| PaksmithError::InvalidArgument { arg, reason })?;

    let key = crate::commands::key_resolve::resolve_pak_key(&args.pak, aes_key, game)?;
    let reader = match &key {
        Some(k) => PakReader::open_with_key(&args.pak, k.clone())?,
        None => PakReader::open(&args.pak)?,
    };
    let matches: Vec<_> = reader.entries().filter(|e| predicates.matches(e)).collect();

    let resolved = format.resolve();
    crate::output::note_auto_resolved_to_json(format, resolved);
    crate::output::print_entries(&matches, resolved)?;
    Ok(())
}
