//! Paksmith CLI — explore and extract Unreal Engine game assets.

mod commands;
mod output;

use std::io;
use std::process::ExitCode;

use clap::Parser;
use paksmith_core::PaksmithError;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "paksmith",
    version,
    about = "Explore and extract Unreal Engine game assets"
)]
struct Cli {
    #[command(subcommand)]
    command: commands::Command,

    /// Output format
    #[arg(long, global = true, default_value = "auto")]
    format: output::OutputFormat,

    /// Verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let filter = if cli.verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("warn")
    };

    // `try_init` instead of `init` so a host that has already wired up a
    // global subscriber (e.g. a future embed-paksmith-as-a-library scenario)
    // doesn't panic during CLI startup.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();

    match cli.command.run(cli.format) {
        Ok(()) => ExitCode::SUCCESS,
        // The reader on the other end of our stdout went away (e.g. piped to
        // `head`). That's a normal CLI outcome, not an error — exit cleanly so
        // shell pipelines don't surface a misleading non-zero status.
        Err(PaksmithError::Io(e)) if e.kind() == io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}
