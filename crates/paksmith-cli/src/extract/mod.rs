pub(crate) mod classify;
pub(crate) mod safe_path;
pub(crate) mod select;
pub(crate) mod summary;

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use indicatif::ProgressBar;
use rayon::prelude::*;

use paksmith_core::asset::Package;
use paksmith_core::container::ContainerReader;
use paksmith_core::container::pak::PakReader;
use paksmith_core::export::HandlerRegistry;

use self::classify::{EntryClass, classify};
use self::select::{FormatPrefs, select_export};
use self::summary::EntryOutcome;

pub(crate) struct ExtractConfig {
    pub(crate) output_dir: PathBuf,
    pub(crate) flat: bool,
    pub(crate) dry_run: bool,
    pub(crate) overwrite: bool,
    pub(crate) prefs: FormatPrefs,
}

pub(crate) struct ExtractJob<'a> {
    pub(crate) reader: Arc<PakReader>,
    pub(crate) registry: &'a HandlerRegistry,
    pub(crate) cfg: &'a ExtractConfig,
}

impl ExtractJob<'_> {
    /// Extract one entry, mapping every error into a `Failed` outcome so
    /// the batch never aborts.
    pub(crate) fn extract_entry(&self, entry_path: &str) -> EntryOutcome {
        match classify(entry_path) {
            EntryClass::Companion => EntryOutcome::SkippedCompanion {
                entry: entry_path.to_string(),
            },
            EntryClass::Raw => self.extract_raw(entry_path),
            EntryClass::Asset => self.extract_asset(entry_path),
        }
    }

    fn extract_asset(&self, entry_path: &str) -> EntryOutcome {
        let pkg = match Package::read_from_reader(&self.reader, entry_path, None) {
            Ok(p) => p,
            Err(e) => {
                return EntryOutcome::Failed {
                    entry: entry_path.to_string(),
                    error: e.to_string(),
                };
            }
        };
        match select_export(&pkg.payloads, self.registry, self.cfg.prefs) {
            Some((idx, handler)) => self.convert(entry_path, &pkg, idx, handler),
            None => self.extract_raw(entry_path),
        }
    }

    fn convert(
        &self,
        entry_path: &str,
        pkg: &Package,
        idx: usize,
        handler: &dyn paksmith_core::export::FormatHandler,
    ) -> EntryOutcome {
        let bulk = match pkg.resolve_bulk_for_export(idx) {
            Ok(b) => b,
            Err(e) => {
                return EntryOutcome::Failed {
                    entry: entry_path.to_string(),
                    error: e.to_string(),
                };
            }
        };
        let bytes = match handler.export(&pkg.payloads[idx], bulk) {
            Ok(b) => b,
            Err(e) => {
                return EntryOutcome::Failed {
                    entry: entry_path.to_string(),
                    error: e.to_string(),
                };
            }
        };
        let ext = handler.output_extension();
        match write_output(self.cfg, entry_path, Some(ext), &bytes) {
            Ok(output) => EntryOutcome::Converted {
                entry: entry_path.to_string(),
                output,
                handler: ext.to_string(),
            },
            Err(e) => EntryOutcome::Failed {
                entry: entry_path.to_string(),
                error: e,
            },
        }
    }

    fn extract_raw(&self, entry_path: &str) -> EntryOutcome {
        let bytes = match self.reader.read_entry(entry_path) {
            Ok(b) => b,
            Err(e) => {
                return EntryOutcome::Failed {
                    entry: entry_path.to_string(),
                    error: e.to_string(),
                };
            }
        };
        match write_output(self.cfg, entry_path, None, &bytes) {
            Ok(output) => EntryOutcome::RawCopied {
                entry: entry_path.to_string(),
                output,
            },
            Err(e) => EntryOutcome::Failed {
                entry: entry_path.to_string(),
                error: e,
            },
        }
    }

    pub(crate) fn run_with_progress(
        &self,
        entries: &[String],
        progress: &ProgressBar,
    ) -> Vec<EntryOutcome> {
        let out = entries
            .par_iter()
            .map(|e| {
                let outcome = self.extract_entry(e);
                progress.inc(1);
                outcome
            })
            .collect();
        progress.finish_and_clear();
        out
    }
}

/// Derive the safe output path, replacing the extension when `new_ext` is
/// `Some` (converted) or keeping it (raw). Honors `--dry-run` (no write) and
/// `--overwrite`. Returns the output path as a String, or a human error
/// string. Free function (no reader/registry dependency) so the entire
/// write / dry-run / overwrite / extension-swap surface is unit-testable
/// without a pak — see the `#[cfg(test)]` block below.
fn write_output(
    cfg: &ExtractConfig,
    entry_path: &str,
    new_ext: Option<&str>,
    bytes: &[u8],
) -> Result<String, String> {
    let mut path =
        safe_path::safe_join(&cfg.output_dir, entry_path, cfg.flat).map_err(|e| e.to_string())?;
    if let Some(ext) = new_ext {
        let _ = path.set_extension(ext);
    }
    let display = path.to_string_lossy().into_owned();

    if cfg.dry_run {
        return Ok(display);
    }
    if path.exists() && !cfg.overwrite {
        return Err(format!("output exists (use --overwrite): {display}"));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create dir {}: {e}", parent.display()))?;
    }
    let mut f = fs::File::create(&path).map_err(|e| format!("create {display}: {e}"))?;
    f.write_all(bytes)
        .map_err(|e| format!("write {display}: {e}"))?;
    Ok(display)
}

#[cfg(test)]
mod write_output_tests {
    use super::*;
    use crate::commands::extract::{AudioFormat, DataTableFormat};

    fn cfg(dir: &std::path::Path, flat: bool, dry_run: bool, overwrite: bool) -> ExtractConfig {
        ExtractConfig {
            output_dir: dir.to_path_buf(),
            flat,
            dry_run,
            overwrite,
            prefs: FormatPrefs {
                audio: AudioFormat::Ogg,
                datatable: DataTableFormat::Csv,
            },
        }
    }

    #[test]
    fn writes_converted_with_swapped_extension() {
        let dir = tempfile::tempdir().unwrap();
        let c = cfg(dir.path(), false, false, false);
        let out = write_output(&c, "Game/Hero.uasset", Some("png"), b"PNGDATA").unwrap();
        assert!(out.ends_with("Game/Hero.png"), "got {out}");
        assert_eq!(std::fs::read(&out).unwrap(), b"PNGDATA");
    }

    #[test]
    fn raw_keeps_extension() {
        let dir = tempfile::tempdir().unwrap();
        let c = cfg(dir.path(), false, false, false);
        let out = write_output(&c, "Config/Game.ini", None, b"[x]").unwrap();
        assert!(out.ends_with("Config/Game.ini"), "got {out}");
        assert_eq!(std::fs::read(&out).unwrap(), b"[x]");
    }

    #[test]
    fn dry_run_writes_nothing_but_reports_path() {
        let dir = tempfile::tempdir().unwrap();
        let c = cfg(dir.path(), false, true, false);
        let out = write_output(&c, "Game/Hero.uasset", Some("png"), b"X").unwrap();
        assert!(out.ends_with("Game/Hero.png"));
        assert!(!std::path::Path::new(&out).exists());
    }

    #[test]
    fn overwrite_guard_then_allow() {
        let dir = tempfile::tempdir().unwrap();
        let guard = cfg(dir.path(), false, false, false);
        let _ = write_output(&guard, "A.bin", None, b"1").unwrap();
        assert!(write_output(&guard, "A.bin", None, b"2").is_err()); // exists, no overwrite
        let force = cfg(dir.path(), false, false, true);
        let _ = write_output(&force, "A.bin", None, b"2").unwrap(); // last-writer-wins
        let out = dir.path().join("A.bin");
        assert_eq!(std::fs::read(out).unwrap(), b"2");
    }

    #[test]
    fn flat_uses_basename() {
        let dir = tempfile::tempdir().unwrap();
        let c = cfg(dir.path(), true, false, false);
        let out = write_output(&c, "Deep/Nested/Hero.uasset", Some("png"), b"X").unwrap();
        assert_eq!(std::path::Path::new(&out), dir.path().join("Hero.png"));
    }

    #[test]
    fn rejects_traversal_entry() {
        let dir = tempfile::tempdir().unwrap();
        let c = cfg(dir.path(), false, false, false);
        assert!(write_output(&c, "../../evil", None, b"X").is_err());
    }
}
