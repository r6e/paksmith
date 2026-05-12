use std::io::{self, IsTerminal, Write};

use comfy_table::Table;
use comfy_table::presets::UTF8_FULL_CONDENSED;
use serde::Serialize;

use paksmith_core::container::EntryMetadata;

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum OutputFormat {
    Auto,
    Json,
    Table,
}

impl OutputFormat {
    pub fn resolve(self) -> ResolvedFormat {
        match self {
            Self::Json => ResolvedFormat::Json,
            Self::Table => ResolvedFormat::Table,
            Self::Auto => {
                if std::io::stdout().is_terminal() {
                    ResolvedFormat::Table
                } else {
                    ResolvedFormat::Json
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ResolvedFormat {
    Json,
    Table,
}

#[derive(Serialize)]
struct EntryRow<'a> {
    path: &'a str,
    size: u64,
    compressed_size: u64,
    compressed: bool,
    encrypted: bool,
}

pub fn print_entries(entries: &[EntryMetadata], format: ResolvedFormat) -> io::Result<()> {
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
            // memory. serde_json wraps the underlying io::Error; surface its
            // kind so callers can distinguish BrokenPipe from real errors.
            serde_json::to_writer_pretty(&mut out, &rows).map_err(|e| {
                e.io_error_kind()
                    .map_or_else(|| io::Error::other(e.to_string()), io::Error::from)
            })?;
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
// size formatter doesn't care — KiB/MiB display is approximate by design.
// (Workspace clippy policy already allows `cast_precision_loss`.)
fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    }
}
