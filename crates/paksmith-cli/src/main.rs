//! Paksmith CLI — explore and extract Unreal Engine game assets.

mod commands;
mod output;

use std::process::ExitCode;

use clap::Parser;
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

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();

    match cli.command.run(cli.format) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}
