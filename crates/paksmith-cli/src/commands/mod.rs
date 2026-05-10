pub mod list;

use clap::Subcommand;

use crate::output::OutputFormat;

#[derive(Subcommand)]
pub enum Command {
    /// List archive contents
    List(list::ListArgs),
}

impl Command {
    pub fn run(&self, format: OutputFormat) -> paksmith_core::Result<()> {
        match self {
            Self::List(args) => list::run(args, format),
        }
    }
}
