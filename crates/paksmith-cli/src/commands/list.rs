use std::path::PathBuf;

use clap::Args;

use paksmith_core::PaksmithError;
use paksmith_core::container::ContainerReader;
use paksmith_core::container::pak::PakReader;

use crate::output::{OutputFormat, ResolvedFormat};

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
    // Surface the implicit Auto → Json fallback so a user who saw a
    // table on the terminal isn't confused when piping (e.g. into
    // `head` or `jq`) silently switches the output shape.
    if matches!(format, OutputFormat::Auto) && matches!(resolved, ResolvedFormat::Json) {
        eprintln!(
            "note: stdout is not a terminal — emitting JSON. Pass --format table to force table output."
        );
    }
    crate::output::print_entries(&filtered, resolved)?;
    Ok(())
}
