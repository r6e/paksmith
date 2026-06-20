pub(crate) mod extract;
pub(crate) mod inspect;
pub(crate) mod key_resolve;
pub(crate) mod list;
pub(crate) mod profile;
pub(crate) mod search;

use clap::Subcommand;
use paksmith_core::AesKey;

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
    /// Manage game profiles and AES keys
    Profile {
        #[command(subcommand)]
        cmd: profile::ProfileCmd,
    },
}

impl Command {
    pub(crate) fn run(
        &self,
        format: OutputFormat,
        aes_key: Option<&AesKey>,
        game: Option<&str>,
    ) -> paksmith_core::Result<u8> {
        match self {
            Self::List(args) => list::run(args, format, aes_key, game).map(|()| 0),
            Self::Inspect(args) => inspect::run(args, format, aes_key, game).map(|()| 0),
            Self::Extract(args) => extract::run(args, format, aes_key, game),
            Self::Search(args) => search::run(args, format, aes_key, game).map(|()| 0),
            Self::Profile { cmd } => profile::run(cmd, format),
        }
    }
}
