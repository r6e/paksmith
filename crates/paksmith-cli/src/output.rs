use std::io::IsTerminal;

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

pub fn print_entries(entries: &[&EntryMetadata], format: ResolvedFormat) {
    match format {
        ResolvedFormat::Json => {
            let rows: Vec<EntryRow> = entries
                .iter()
                .map(|e| EntryRow {
                    path: &e.path,
                    size: e.uncompressed_size,
                    compressed_size: e.compressed_size,
                    compressed: e.is_compressed,
                    encrypted: e.is_encrypted,
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&rows).unwrap());
        }
        ResolvedFormat::Table => {
            let mut table = Table::new();
            let _ = table.load_preset(UTF8_FULL_CONDENSED);
            let _ = table.set_header(vec!["Path", "Size", "Compressed", "Encrypted"]);

            for entry in entries {
                let _ = table.add_row(vec![
                    entry.path.clone(),
                    format_size(entry.uncompressed_size),
                    if entry.is_compressed {
                        "yes".into()
                    } else {
                        "no".into()
                    },
                    if entry.is_encrypted {
                        "yes".into()
                    } else {
                        "no".into()
                    },
                ]);
            }

            println!("{table}");
        }
    }
}

fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}
