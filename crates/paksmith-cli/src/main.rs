//! Paksmith CLI — explore and extract Unreal Engine game assets.

mod commands;
mod extract;
mod inspect;
mod output;
mod path_util;
mod search;

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

    /// AES-256 key as 64 hex chars (optional 0x prefix) for encrypted paks
    #[arg(long, global = true, value_name = "HEX")]
    aes_key: Option<String>,

    /// Resolve the AES key from a stored profile id (see `paksmith profile`).
    /// Ignored if `--aes-key` is also given (explicit key wins).
    #[arg(long, global = true, value_name = "ID")]
    game: Option<String>,

    /// Verbose logging (debug-level). If `RUST_LOG` is set, it
    /// takes precedence — use it for per-module targeting like
    /// `RUST_LOG=paksmith_core::container::pak=trace`.
    #[arg(short, long, global = true)]
    verbose: bool,
}

/// Drive an async future to completion on a new current-thread tokio runtime.
///
/// Commands that need async I/O (e.g. `profile fetch`) call this helper instead
/// of pulling in a full multi-thread runtime. The runtime is created fresh each
/// call — acceptable for the few CLI commands that need async, where startup
/// latency is dominated by network I/O anyway.
pub(crate) fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build current-thread tokio runtime")
        .block_on(fut)
}

/// Decode a 64-hex-char (optional `0x`/`0X` prefix) AES-256 key string into
/// a [`paksmith_core::AesKey`].  Returns [`PaksmithError::InvalidArgument`] on any parse
/// failure; key material is never included in the error message.
fn parse_aes_key(s: &str) -> paksmith_core::Result<paksmith_core::AesKey> {
    paksmith_core::AesKey::from_hex(s).map_err(|e| paksmith_core::PaksmithError::InvalidArgument {
        arg: "--aes-key",
        reason: e.to_string(),
    })
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // Honor RUST_LOG when set so users can target specific modules
    // (e.g. `RUST_LOG=paksmith_core::container::pak=trace`) without
    // recompiling. Falls through to the --verbose-derived default
    // when RUST_LOG is unset or unparsable — issue #140.
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(if cli.verbose { "debug" } else { "warn" }));

    // `try_init` instead of `init` so a host that has already wired up a
    // global subscriber (e.g. a future embed-paksmith-as-a-library scenario)
    // doesn't panic during CLI startup.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();

    let result = cli
        .aes_key
        .as_deref()
        .map(parse_aes_key)
        .transpose()
        .and_then(|key| {
            cli.command
                .run(cli.format, key.as_ref(), cli.game.as_deref())
        });
    match result {
        Ok(code) => ExitCode::from(code),
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

#[cfg(test)]
mod tests {
    use super::parse_aes_key;

    #[test]
    fn parse_aes_key_accepts_64_hex_no_prefix() {
        let k = parse_aes_key(&"ab".repeat(32)).unwrap();
        let _ = k;
    }

    #[test]
    fn parse_aes_key_accepts_64_hex_0x_prefix() {
        let key_str = format!("0x{}", "ab".repeat(32));
        let _ = parse_aes_key(&key_str).unwrap();
    }

    #[test]
    fn parse_aes_key_accepts_64_hex_0x_upper_prefix() {
        let key_str = format!("0X{}", "AB".repeat(32));
        let _ = parse_aes_key(&key_str).unwrap();
    }

    #[test]
    fn parse_aes_key_accepts_uppercase_hex() {
        let _ = parse_aes_key(&"AB".repeat(32)).unwrap();
    }

    #[test]
    fn parse_aes_key_known_vector_all_zeros() {
        // AesKey has no byte accessor — construction success is the invariant.
        let _ = parse_aes_key(&"00".repeat(32)).unwrap();
    }

    #[test]
    fn parse_aes_key_known_vector_fixture_key() {
        // The real_v8b_encrypted_index.pak AES key.
        let _ = parse_aes_key("94d25bc3aeb420e0be914edc9d5435a1eaab5f2864e09e94019ac205b727a7de")
            .unwrap();
    }

    #[test]
    fn parse_aes_key_rejects_63_chars() {
        // One hex char short → 31.5 bytes.
        let short = format!("{}{}", "ab".repeat(31), "a");
        assert!(parse_aes_key(&short).is_err());
    }

    #[test]
    fn parse_aes_key_rejects_65_chars() {
        let long = format!("{}{}", "ab".repeat(32), "a");
        assert!(parse_aes_key(&long).is_err());
    }

    #[test]
    fn parse_aes_key_rejects_non_hex_char() {
        // 'g' is not a valid hex digit.
        let bad = format!("g{}", "0".repeat(63));
        assert!(parse_aes_key(&bad).is_err());
    }

    #[test]
    fn parse_aes_key_rejects_empty() {
        assert!(parse_aes_key("").is_err());
    }

    #[test]
    fn parse_aes_key_error_contains_no_key_material() {
        // Error message must not echo back key chars — verify for a known-bad input.
        let bad = format!("zz{}", "00".repeat(31));
        let err = parse_aes_key(&bad).unwrap_err().to_string();
        // The raw `zz` should not appear verbatim in the error.
        assert!(
            !err.contains("zz"),
            "error message must not echo key material: {err}"
        );
    }
}
