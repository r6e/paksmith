pub(crate) mod extract;
pub(crate) mod inspect;
pub(crate) mod list;
pub(crate) mod search;

use clap::Subcommand;

use crate::output::OutputFormat;

#[derive(Subcommand)]
pub(crate) enum Command {
    /// List archive contents
    List(list::ListArgs),
    /// Dump a uasset's structural header as JSON
    Inspect(inspect::InspectArgs),
    /// Extract and convert archive contents to disk
    Extract(extract::ExtractArgs),
    /// Query archive entries by type, name, regex, and size
    Search(search::SearchArgs),
}

impl Command {
    pub(crate) fn run(&self, format: OutputFormat) -> paksmith_core::Result<u8> {
        match self {
            Self::List(args) => list::run(args, format).map(|()| 0),
            Self::Inspect(args) => inspect::run(args, format).map(|()| 0),
            Self::Extract(args) => extract::run(args, format),
            Self::Search(args) => search::run(args, format).map(|()| 0),
        }
    }
}
