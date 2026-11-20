pub(crate) mod detect;
pub(crate) mod extract;
pub(crate) mod inspect;
pub(crate) mod key_resolve;
pub(crate) mod list;
pub(crate) mod mappings_resolve;
pub(crate) mod profile;
pub(crate) mod search;
pub(crate) mod verify;

use std::path::Path;

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
    /// Check the hashes in archives' indexes and report what was checked
    ///
    /// Every archive is reported, and one that fails doesn't stop the
    /// rest, whether it fails to open, to verify, or under --game/--detect
    /// to have its footer read or its key found. A selector or profile
    /// lookup that fails, such as for a profile store that won't load,
    /// ends the run with no report. The exit code is the highest any
    /// archive produced: 0 when it verified, including entries the entry
    /// listing records no hash for; 1 when a stored hash didn't match, or
    /// was zeroed in an archive whose index is hashed; 2 when it couldn't
    /// be opened or verified, such as a plaintext entry whose listing
    /// records a hash, in a compression method paksmith doesn't recognise. A
    /// stdout closed before the report is written exits 0.
    Verify(verify::VerifyArgs),
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
        detect: Option<&Path>,
        quiet: bool,
    ) -> paksmith_core::Result<u8> {
        match self {
            Self::List(args) => list::run(args, format, aes_key, game, detect, quiet).map(|()| 0),
            Self::Inspect(args) => {
                inspect::run(args, format, aes_key, game, detect, quiet).map(|()| 0)
            }
            Self::Extract(args) => extract::run(args, format, aes_key, game, detect, quiet),
            Self::Search(args) => {
                search::run(args, format, aes_key, game, detect, quiet).map(|()| 0)
            }
            Self::Verify(args) => verify::run(args, format, aes_key, game, detect, quiet),
            Self::Profile { cmd } => profile::run(cmd, format, quiet),
        }
    }
}
