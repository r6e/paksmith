//! Per-entry outcomes + the stable extract summary (JSON / table).

// All public items in this module are consumed by Task 7 (the extract
// command). Until that wiring lands, `dead_code` fires on every struct
// and method here. Suppress it rather than fighting clippy -D warnings
// in CI on an intentionally-incomplete feature branch.
#![allow(dead_code)]

use std::io::{self, Write};

use serde::Serialize;

use crate::output::{ResolvedFormat, serde_json_to_io};

#[derive(Debug, Clone)]
pub(crate) enum EntryOutcome {
    Converted {
        entry: String,
        output: String,
        handler: String,
    },
    RawCopied {
        entry: String,
        output: String,
    },
    SkippedCompanion {
        entry: String,
    },
    Failed {
        entry: String,
        error: String,
    },
}

#[derive(Debug, Default, Serialize)]
pub(crate) struct Counts {
    pub(crate) converted: usize,
    pub(crate) raw_copied: usize,
    pub(crate) skipped_companion: usize,
    pub(crate) failed: usize,
}

#[derive(Debug, Serialize)]
pub(crate) struct OutputRecord {
    pub(crate) entry: String,
    pub(crate) output: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) handler: Option<String>,
    pub(crate) kind: &'static str,
}

#[derive(Debug, Serialize)]
pub(crate) struct FailureRecord {
    pub(crate) entry: String,
    pub(crate) error: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct ExtractSummary {
    pub(crate) pak: String,
    pub(crate) output_dir: String,
    pub(crate) dry_run: bool,
    pub(crate) counts: Counts,
    pub(crate) failures: Vec<FailureRecord>,
    pub(crate) outputs: Vec<OutputRecord>,
}

impl ExtractSummary {
    pub(crate) fn from_outcomes(
        pak: String,
        output_dir: String,
        dry_run: bool,
        outcomes: Vec<EntryOutcome>,
    ) -> Self {
        let mut counts = Counts::default();
        let mut failures = Vec::new();
        let mut outputs = Vec::new();
        for o in outcomes {
            match o {
                EntryOutcome::Converted {
                    entry,
                    output,
                    handler,
                } => {
                    counts.converted += 1;
                    outputs.push(OutputRecord {
                        entry,
                        output,
                        handler: Some(handler),
                        kind: "converted",
                    });
                }
                EntryOutcome::RawCopied { entry, output } => {
                    counts.raw_copied += 1;
                    outputs.push(OutputRecord {
                        entry,
                        output,
                        handler: None,
                        kind: "raw_copied",
                    });
                }
                EntryOutcome::SkippedCompanion { .. } => counts.skipped_companion += 1,
                EntryOutcome::Failed { entry, error } => {
                    counts.failed += 1;
                    failures.push(FailureRecord { entry, error });
                }
            }
        }
        // Deterministic ordering regardless of parallel completion order.
        outputs.sort_by(|a, b| a.entry.cmp(&b.entry));
        failures.sort_by(|a, b| a.entry.cmp(&b.entry));
        Self {
            pak,
            output_dir,
            dry_run,
            counts,
            failures,
            outputs,
        }
    }

    pub(crate) fn had_failures(&self) -> bool {
        self.counts.failed > 0
    }

    pub(crate) fn render(&self, format: ResolvedFormat, w: &mut dyn Write) -> io::Result<()> {
        match format {
            ResolvedFormat::Json => {
                serde_json::to_writer_pretty(&mut *w, self).map_err(serde_json_to_io)?;
                writeln!(w)
            }
            ResolvedFormat::Table => {
                writeln!(w, "extracted from {}", self.pak)?;
                writeln!(w, "  converted:         {}", self.counts.converted)?;
                writeln!(w, "  raw copied:        {}", self.counts.raw_copied)?;
                writeln!(w, "  skipped companion: {}", self.counts.skipped_companion)?;
                writeln!(w, "  failed:            {}", self.counts.failed)?;
                for f in &self.failures {
                    writeln!(w, "  FAILED {}: {}", f.entry, f.error)?;
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ExtractSummary {
        ExtractSummary::from_outcomes(
            "Game.pak".into(),
            "out".into(),
            false,
            vec![
                EntryOutcome::Converted {
                    entry: "A.uasset".into(),
                    output: "out/A.png".into(),
                    handler: "png".into(),
                },
                EntryOutcome::RawCopied {
                    entry: "C.ini".into(),
                    output: "out/C.ini".into(),
                },
                EntryOutcome::SkippedCompanion {
                    entry: "A.uexp".into(),
                },
                EntryOutcome::Failed {
                    entry: "B.uasset".into(),
                    error: "boom".into(),
                },
            ],
        )
    }

    #[test]
    fn counts_are_bucketed() {
        let s = sample();
        assert_eq!(s.counts.converted, 1);
        assert_eq!(s.counts.raw_copied, 1);
        assert_eq!(s.counts.skipped_companion, 1);
        assert_eq!(s.counts.failed, 1);
        assert!(s.had_failures());
    }

    #[test]
    fn json_shape_matches_spec() {
        let s = sample();
        let mut buf = Vec::new();
        s.render(ResolvedFormat::Json, &mut buf).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(v["pak"], "Game.pak");
        assert_eq!(v["counts"]["converted"], 1);
        assert_eq!(v["failures"][0]["entry"], "B.uasset");
        assert_eq!(v["outputs"].as_array().unwrap().len(), 2); // converted + raw_copied
        assert_eq!(v["outputs"][0]["kind"], "converted");
    }
}
