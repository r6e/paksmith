//! Paksmith CLI — explore and extract Unreal Engine game assets.

mod commands;
mod output;

use std::io;
use std::process::ExitCode;

use clap::Parser;
use paksmith_core::PaksmithError;
use tracing::error;
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
    //
    // Issue #93: drop timestamp + module-path target from the format so
    // the user-facing CLI error path (which now goes through
    // `tracing::error!` below) renders as `ERROR <msg>` rather than
    // `<timestamp> ERROR <module>: <msg>`. Keeps the level prefix so
    // log-aggregation users can still distinguish ERROR/WARN/DEBUG.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .without_time()
        .try_init();

    match cli.command.run(cli.format) {
        Ok(()) => ExitCode::SUCCESS,
        // The reader on the other end of our stdout went away (e.g. piped to
        // `head`). That's a normal CLI outcome, not an error — exit cleanly so
        // shell pipelines don't surface a misleading non-zero status.
        Err(PaksmithError::Io(e)) if e.kind() == io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
        Err(e) => {
            // Issue #93: route the user-facing top-level error through
            // `tracing::error!` (writing to stderr via the subscriber
            // wired above) rather than a bare `eprintln!`. CLAUDE.md
            // mandates `tracing` for structured logging; using it here
            // unifies the channel so log-aggregation users see the
            // top-level summary in the same stream as any deeper
            // contextual `error!` logs the failed code path may have
            // emitted before bubbling up.
            //
            // The subscriber's filter passes `error` level under both
            // default (`warn`) and `--verbose` (`debug`), so the user
            // always sees the message.
            error!("{e}");
            ExitCode::from(2)
        }
    }
}
