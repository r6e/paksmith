//! Per-entry outcomes + the stable extract summary (JSON / table).

use std::io::{self, Write};

use serde::Serialize;

use crate::output::{ResolvedFormat, sanitize_for_display, serde_json_to_io};

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
        // Retained for future tracing; counted but not rendered in summaries.
        #[allow(dead_code)]
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
    /// Schema version for forward-compatibility. Consumers may check this
    /// before parsing; currently always 1. Additive optional keys that
    /// never appear in a pre-existing output mode (`sources`, #655) do
    /// not bump.
    pub(crate) schema_version: u32,
    /// Source archive label. Explicit-path runs: the one path,
    /// unchanged from pre-#655. Profile-paks runs: every source
    /// archive, comma-joined — HUMAN display only (", " is a legal
    /// path substring); machine consumers use `sources`.
    pub(crate) pak: String,
    /// The source archives, one element per path — present only in
    /// profile-paks mode (#655); the machine-readable counterpart of
    /// the joined `pak` label.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) sources: Vec<String>,
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
            sources: Vec::new(),
            schema_version: 1,
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
                // In profile-paks mode `pak` carries glob-DISCOVERED
                // filenames, not user-typed argv — same trust class as
                // list/search's grouped header, same neutralization.
                writeln!(w, "extracted from {}", sanitize_for_display(&self.pak))?;
                writeln!(w, "  converted:         {}", self.counts.converted)?;
                writeln!(w, "  raw copied:        {}", self.counts.raw_copied)?;
                writeln!(w, "  skipped companion: {}", self.counts.skipped_companion)?;
                writeln!(w, "  failed:            {}", self.counts.failed)?;
                for f in &self.failures {
                    // Both the entry path AND the error text can embed
                    // hostile pak/asset strings (error Displays quote the
                    // asset path). Per-FIELD sanitization: equivalent to
                    // whole-line on today's control-free literals, keeps
                    // the per-field Cow fast path, and never feeds
                    // trusted text (future styling escapes) to the
                    // sanitizer.
                    writeln!(
                        w,
                        "  FAILED {}: {}",
                        sanitize_for_display(&f.entry),
                        sanitize_for_display(&f.error)
                    )?;
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

    /// Hostile control chars in a FAILED entry's path or error text
    /// must not reach the terminal through the table summary — each
    /// field routes through `sanitize_for_display` independently (a
    /// dropped wrapper call on either field would fail this).
    #[test]
    fn table_header_sanitizes_discovered_pak_label() {
        // In profile-paks mode `pak` carries glob-DISCOVERED filenames;
        // a hostile archive name must not reach the terminal raw.
        let s = ExtractSummary::from_outcomes(
            "evil\u{1b}[31m.pak, ok.pak".into(),
            "out".into(),
            false,
            vec![],
        );
        let mut buf = Vec::new();
        s.render(ResolvedFormat::Table, &mut buf).unwrap();
        let rendered = String::from_utf8(buf).unwrap();
        assert!(
            !rendered.contains('\u{1b}') && rendered.contains('\u{FFFD}'),
            "escape neutralized in the extracted-from header: {rendered:?}"
        );
    }

    #[test]
    fn table_failed_lines_are_control_char_free() {
        let s = ExtractSummary::from_outcomes(
            "Game.pak".into(),
            "out".into(),
            false,
            vec![EntryOutcome::Failed {
                entry: "B\u{1b}]0;pwned\u{7}.uasset".into(),
                error: "bad \u{9b}2J asset".into(),
            }],
        );
        let mut buf = Vec::new();
        s.render(ResolvedFormat::Table, &mut buf).unwrap();
        let rendered = String::from_utf8(buf).unwrap();
        assert!(
            !rendered.contains('\u{1b}')
                && !rendered.contains('\u{7}')
                && !rendered.contains('\u{9b}'),
            "control chars must be neutralized in the FAILED line: {rendered:?}"
        );
        assert!(
            rendered.contains("FAILED") && rendered.contains('\u{FFFD}'),
            "the failure stays visible with replacement marks: {rendered:?}"
        );
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
        assert_eq!(v["schema_version"], 1);
        assert_eq!(v["pak"], "Game.pak");
        assert_eq!(v["counts"]["converted"], 1);
        assert_eq!(v["failures"][0]["entry"], "B.uasset");
        assert_eq!(v["outputs"].as_array().unwrap().len(), 2); // converted + raw_copied
        assert_eq!(v["outputs"][0]["kind"], "converted");

        // Determinism: outputs are sorted by `entry`.
        assert_eq!(v["outputs"][0]["entry"], "A.uasset");
        assert_eq!(v["outputs"][1]["entry"], "C.ini");
        // raw_copied entries omit `handler` (skip_serializing_if).
        assert_eq!(v["outputs"][1]["kind"], "raw_copied");
        assert!(
            v["outputs"][1].get("handler").is_none(),
            "raw_copied must omit handler"
        );
    }
}
