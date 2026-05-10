use std::path::PathBuf;

use clap::Args;

use paksmith_core::PaksmithError;
use paksmith_core::container::ContainerReader;
use paksmith_core::container::pak::PakReader;

use crate::output::OutputFormat;

#[derive(Args)]
pub struct ListArgs {
    /// Path to .pak file
    pub path: PathBuf,

    /// Filter entries by glob pattern
    #[arg(long)]
    pub filter: Option<String>,
}

pub fn run(args: &ListArgs, format: OutputFormat) -> paksmith_core::Result<()> {
    let reader = PakReader::open(&args.path)?;
    let entries = reader.list_entries();

    let filtered: Vec<_> = match &args.filter {
        Some(pattern) => {
            let pat = glob::Pattern::new(pattern).map_err(|e| PaksmithError::InvalidArgument {
                arg: "--filter",
                reason: e.to_string(),
            })?;
            entries.iter().filter(|e| pat.matches(&e.path)).collect()
        }
        None => entries.iter().collect(),
    };

    let resolved = format.resolve();
    crate::output::print_entries(&filtered, resolved)?;
    Ok(())
}
