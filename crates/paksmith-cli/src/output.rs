use std::io::{self, IsTerminal, Write};

use comfy_table::Table;
use comfy_table::presets::UTF8_FULL_CONDENSED;
use serde::Serialize;

use paksmith_core::container::EntryMetadata;

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub(crate) enum OutputFormat {
    Auto,
    Json,
    Table,
}

impl OutputFormat {
    pub(crate) fn resolve(self) -> ResolvedFormat {
        self.resolve_with_tty(std::io::stdout().is_terminal())
    }

    /// Pure resolution logic, taking the TTY signal as an explicit
    /// argument so the Auto branch is testable without touching
    /// stdout. `resolve()` is the call site that wires in the real
    /// `is_terminal()` probe.
    pub(crate) fn resolve_with_tty(self, is_tty: bool) -> ResolvedFormat {
        match self {
            Self::Json => ResolvedFormat::Json,
            Self::Table => ResolvedFormat::Table,
            Self::Auto => {
                if is_tty {
                    ResolvedFormat::Table
                } else {
                    ResolvedFormat::Json
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum ResolvedFormat {
    Json,
    Table,
}

/// Coerce `serde_json::Error` to `io::Error` preserving the wrapped
/// `ErrorKind`, notably `BrokenPipe`, so `main.rs`'s pipe-clean-exit
/// handler keeps working when writing JSON to stdout closed by the
/// downstream reader (e.g. `paksmith inspect ... | head -1`).
///
/// Takes its argument by value because the canonical call site is
/// `.map_err(serde_json_to_io)`, whose closure receives the error
/// owned. A `&Error` signature would force every caller into a
/// `|e| serde_json_to_io(&e)` shim, defeating the helper.
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn serde_json_to_io(e: serde_json::Error) -> io::Error {
    e.io_error_kind()
        .map_or_else(|| io::Error::other(e.to_string()), io::Error::from)
}

#[derive(Serialize)]
struct EntryRow<'a> {
    path: &'a str,
    size: u64,
    compressed_size: u64,
    compressed: bool,
    encrypted: bool,
}

pub(crate) fn print_entries(entries: &[EntryMetadata], format: ResolvedFormat) -> io::Result<()> {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    match format {
        ResolvedFormat::Json => {
            let rows: Vec<EntryRow> = entries
                .iter()
                .map(|e| EntryRow {
                    path: e.path(),
                    size: e.uncompressed_size(),
                    compressed_size: e.compressed_size(),
                    compressed: e.is_compressed(),
                    encrypted: e.is_encrypted(),
                })
                .collect();
            // Stream directly to stdout instead of building the full string in
            // memory. serde_json wraps the underlying io::Error; the helper
            // surfaces its kind so callers can distinguish BrokenPipe from
            // real errors.
            serde_json::to_writer_pretty(&mut out, &rows).map_err(serde_json_to_io)?;
            writeln!(out)?;
        }
        ResolvedFormat::Table => {
            let mut table = Table::new();
            let _ = table.load_preset(UTF8_FULL_CONDENSED);
            let _ = table.set_header(vec!["Path", "Size", "Compressed", "Encrypted"]);

            for entry in entries {
                let _ = table.add_row(vec![
                    entry.path().to_string(),
                    format_size(entry.uncompressed_size()),
                    if entry.is_compressed() {
                        "yes".into()
                    } else {
                        "no".into()
                    },
                    if entry.is_encrypted() {
                        "yes".into()
                    } else {
                        "no".into()
                    },
                ]);
            }

            writeln!(out, "{table}")?;
        }
    }
    Ok(())
}

// `bytes as f64` loses precision past 2^53, but a one-decimal human-readable
// size formatter doesn't care — KiB/MiB/GiB/TiB display is approximate by design.
// (Workspace clippy policy already allows `cast_precision_loss`.)
//
// Issue #93: extends the ladder past MiB to GiB and TiB. Entries can be
// up to `MAX_UNCOMPRESSED_ENTRY_BYTES = 8 GiB` (per pak/mod.rs); pre-fix
// the table printed "8192.0 MiB" instead of "8.0 GiB" at the cap.
// TiB tier is forward-compat for any future cap loosening.
fn format_size(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;
    const TIB: u64 = GIB * 1024;
    if bytes < KIB {
        format!("{bytes} B")
    } else if bytes < MIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else if bytes < GIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes < TIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else {
        format!("{:.1} TiB", bytes as f64 / TIB as f64)
    }
}

#[cfg(test)]
mod resolve_tests {
    use super::{OutputFormat, ResolvedFormat};

    #[test]
    fn explicit_json_ignores_tty() {
        assert!(matches!(
            OutputFormat::Json.resolve_with_tty(true),
            ResolvedFormat::Json
        ));
        assert!(matches!(
            OutputFormat::Json.resolve_with_tty(false),
            ResolvedFormat::Json
        ));
    }

    #[test]
    fn explicit_table_ignores_tty() {
        assert!(matches!(
            OutputFormat::Table.resolve_with_tty(true),
            ResolvedFormat::Table
        ));
        assert!(matches!(
            OutputFormat::Table.resolve_with_tty(false),
            ResolvedFormat::Table
        ));
    }

    #[test]
    fn auto_picks_table_on_tty() {
        assert!(matches!(
            OutputFormat::Auto.resolve_with_tty(true),
            ResolvedFormat::Table
        ));
    }

    #[test]
    fn auto_picks_json_when_piped() {
        assert!(matches!(
            OutputFormat::Auto.resolve_with_tty(false),
            ResolvedFormat::Json
        ));
    }
}

#[cfg(test)]
mod format_size_tests {
    use super::format_size;

    /// Issue #93: pin every tier boundary so a regression that
    /// reorders the ladder or off-by-ones a comparator surfaces here
    /// instead of in user-facing `paksmith list` output.
    #[test]
    fn each_tier_renders_correctly() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(1023), "1023 B");
        assert_eq!(format_size(1024), "1.0 KiB");
        assert_eq!(format_size(1024 * 1024 - 1), "1024.0 KiB");
        assert_eq!(format_size(1024 * 1024), "1.0 MiB");
        assert_eq!(format_size(1024 * 1024 * 1024 - 1), "1024.0 MiB");
        assert_eq!(format_size(1024 * 1024 * 1024), "1.0 GiB");
        // Pin the MAX_UNCOMPRESSED_ENTRY_BYTES = 8 GiB case explicitly:
        // pre-#93 this rendered as "8192.0 MiB", not "8.0 GiB".
        assert_eq!(format_size(8 * 1024 * 1024 * 1024), "8.0 GiB");
        assert_eq!(format_size(1024_u64.pow(4) - 1), "1024.0 GiB");
        assert_eq!(format_size(1024_u64.pow(4)), "1.0 TiB");
        // Beyond TiB: stays in TiB tier (no PiB tier — wildly beyond
        // anything realistic for a single pak entry).
        assert_eq!(format_size(2 * 1024_u64.pow(4)), "2.0 TiB");
    }
}
