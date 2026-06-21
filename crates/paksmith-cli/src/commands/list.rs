use std::path::PathBuf;

use clap::Args;

use paksmith_core::AesKey;
use paksmith_core::PaksmithError;
use paksmith_core::container::ContainerReader;
use paksmith_core::container::pak::PakReader;

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
) -> paksmith_core::Result<()> {
    let key = crate::commands::key_resolve::resolve_pak_key(&args.path, aes_key, game, detect)?;
    let reader = match &key {
        Some(k) => PakReader::open_with_key(&args.path, k.clone())?,
        None => PakReader::open(&args.path)?,
    };

    let filtered: Vec<_> = match &args.filter {
        Some(pattern) => {
            let pat = glob::Pattern::new(pattern).map_err(|e| PaksmithError::InvalidArgument {
                arg: "--filter",
                reason: e.to_string(),
            })?;
            reader.entries().filter(|e| pat.matches(e.path())).collect()
        }
        None => reader.entries().collect(),
    };

    let resolved = format.resolve();
    crate::output::note_auto_resolved_to_json(format, resolved);
    crate::output::print_entries(&filtered, resolved)?;
    Ok(())
}
