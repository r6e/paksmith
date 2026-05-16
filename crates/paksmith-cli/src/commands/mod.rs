pub(crate) mod inspect;
pub(crate) mod list;

use clap::Subcommand;

use crate::output::OutputFormat;

#[derive(Subcommand)]
pub(crate) enum Command {
    /// List archive contents
    List(list::ListArgs),
    /// Dump a uasset's structural header as JSON
    Inspect(inspect::InspectArgs),
}

impl Command {
    pub(crate) fn run(&self, format: OutputFormat) -> paksmith_core::Result<()> {
        match self {
            Self::List(args) => list::run(args, format),
            Self::Inspect(args) => inspect::run(args, format),
        }
    }
}
