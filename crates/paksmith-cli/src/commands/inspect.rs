//! `paksmith inspect <pak> <virtual/path>` — dump a uasset's structural
//! header as JSON.

use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use clap::Args;

use paksmith_core::PaksmithError;
use paksmith_core::asset::Package;
use paksmith_core::asset::mappings::Usmap;

use crate::output::{OutputFormat, serde_json_to_io};

/// Hard cap on the `.usmap` file size the CLI will read into memory.
/// The `Usmap` parser itself caps decompressed size at 256 MiB and
/// compressed at 64 MiB, but both checks run against the wire-claimed
/// header fields — which sit AFTER the bytes that have already been
/// read. Without a CLI-side cap, `--mappings /dev/urandom` (or a
/// 10 GiB regular file, or a symlink to either) would OOM the process
/// before the parser's caps could fire. 128 MiB is roughly twice the
/// compressed cap, giving headroom for the header + uncompressed
/// `.usmap` files while still rejecting clearly-pathological inputs.
const MAX_USMAP_FILE_SIZE: u64 = 128 * 1024 * 1024;

#[derive(Args)]
pub(crate) struct InspectArgs {
    /// Path to the .pak file.
    pub(crate) pak: PathBuf,
    /// Virtual path of the asset within the archive.
    pub(crate) asset: String,
    /// Optional `.usmap` mappings file. Required for assets whose
    /// `PKG_UnversionedProperties` flag is set (UE 4.25+ cooked
    /// content; common in both UE4 and UE5 shipping games).
    /// Versioned (tagged-property) assets parse without it.
    #[arg(long, value_name = "PATH")]
    pub(crate) mappings: Option<PathBuf>,
}

/// Load a `.usmap` mappings file from disk with defensive bounds.
///
/// Rejects non-regular files (FIFO / socket / device) before reading
/// to avoid hang-style and unbounded-read DoS via paths like
/// `/dev/urandom` or a symlinked FIFO. Caps the read at
/// [`MAX_USMAP_FILE_SIZE`] so an oversized regular file fails fast
/// instead of OOM-ing the process. Both kinds of failure surface as
/// `PaksmithError::InvalidArgument` so the user gets the offending
/// path and arg name in the error message (a bare `?` on
/// `std::fs::read` would drop both).
fn load_mappings(path: &Path) -> paksmith_core::Result<Usmap> {
    let metadata = std::fs::metadata(path).map_err(|e| PaksmithError::InvalidArgument {
        arg: "--mappings",
        reason: format!("failed to stat `{}`: {e}", path.display()),
    })?;
    if !metadata.is_file() {
        return Err(PaksmithError::InvalidArgument {
            arg: "--mappings",
            reason: format!("`{}` is not a regular file", path.display()),
        });
    }

    let mut buf = Vec::new();
    // `_ = …` rather than `let _bytes_read = …`: the `usize` count
    // returned by `read_to_end` is intentionally discarded (the cap
    // check below reads `buf.len()`, not this). A named binding here
    // would falsely imply the count is consumed downstream.
    let _ = File::open(path)
        .map_err(|e| PaksmithError::InvalidArgument {
            arg: "--mappings",
            reason: format!("failed to open `{}`: {e}", path.display()),
        })?
        .take(MAX_USMAP_FILE_SIZE + 1)
        .read_to_end(&mut buf)
        .map_err(|e| PaksmithError::InvalidArgument {
            arg: "--mappings",
            reason: format!("failed to read `{}`: {e}", path.display()),
        })?;
    if buf.len() as u64 > MAX_USMAP_FILE_SIZE {
        return Err(PaksmithError::InvalidArgument {
            arg: "--mappings",
            reason: format!(
                "`{}` exceeds the {} MiB limit for .usmap files",
                path.display(),
                MAX_USMAP_FILE_SIZE / (1024 * 1024)
            ),
        });
    }

    Usmap::from_bytes(&buf).map_err(|e| PaksmithError::InvalidArgument {
        arg: "--mappings",
        reason: format!("failed to parse `{}`: {e}", path.display()),
    })
}

/// Run the `inspect` subcommand.
///
/// `--format json` and `--format auto` both produce JSON. `--format
/// table` is rejected (Phase 2a doesn't support tabular Package
/// rendering; tabular output for nested types is a Phase 2c+ concern).
pub(crate) fn run(args: &InspectArgs, format: OutputFormat) -> paksmith_core::Result<()> {
    // Match on the raw variant rather than `format.resolve()`, because
    // `Auto` resolves to `Table` on a TTY — and inspect has no tabular
    // renderer for `Package`. Explicit `--format table` is rejected;
    // `--format auto` falls through to JSON regardless of TTY.
    if matches!(format, OutputFormat::Table) {
        return Err(PaksmithError::InvalidArgument {
            arg: "--format",
            reason: "table format is not yet supported for `inspect`; use `json` or `auto`".into(),
        });
    }

    let usmap = args.mappings.as_deref().map(load_mappings).transpose()?;
    let pkg = Package::read_from_pak(&args.pak, &args.asset, usmap.as_ref())?;

    let stdout = io::stdout();
    let mut out = stdout.lock();
    // `serde_json_to_io` preserves the wrapped `io::ErrorKind` (notably
    // `BrokenPipe`) so `main.rs`'s pipe-clean-exit handler still fires
    // when the reader (e.g. `| head`) closes the pipe mid-write.
    serde_json::to_writer_pretty(&mut out, &pkg).map_err(serde_json_to_io)?;
    writeln!(out)?;
    Ok(())
}
