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

    // Honor RUST_LOG when set so users can target specific modules
    // (e.g. `RUST_LOG=paksmith_core::container::pak=trace`) without
    // recompiling. Falls through to the --verbose-derived default
    // when RUST_LOG is unset or unparseable — issue #140.
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(if cli.verbose { "debug" } else { "warn" }));

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
            // Issue #93 design note: this `eprintln!` is the user-facing
            // top-level error summary, deliberately NOT routed through
            // `tracing::error!` despite CLAUDE.md's tracing discipline.
            // Two reasons:
            //   1. Unix CLI convention is `progname: error: msg`
            //      (lowercase, colon-prefixed) — what `git`/`cargo`/
            //      `rustc` all ship. Tracing's default formatter emits
            //      `<timestamp> ERROR <module>: msg` and even with
            //      `.with_target(false).without_time()` the level
            //      prefix is uppercase `ERROR ` — visually a log line,
            //      not a CLI error.
            //   2. The dual-print concern (a deep code path emitting
            //      `tracing::error!` AND propagating the error up to
            //      this final-print) is real but bounded — call sites
            //      generally do one or the other, not both, and the
            //      two messages serve distinct purposes (contextual
            //      mid-flight log vs top-level user summary). A
            //      log-aggregation user filtering for the top-level
            //      summary can grep stderr for `^paksmith: error:`
            //      while letting tracing handle the rest.
            //
            // If a future paksmith ships as a library to be embedded
            // in a host with its own logging, the host can suppress
            // this print by intercepting the `Err(_)` before
            // `main()` returns.
            eprintln!("paksmith: error: {e}");
            ExitCode::from(2)
        }
    }
}
