pub(crate) mod classify;
pub(crate) mod safe_path;
pub(crate) mod select;
pub(crate) mod summary;

use std::fs;
use std::fs::OpenOptions;
use std::io::{ErrorKind, Write};
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
            EntryClass::Locres => self.extract_locres(entry_path),
            EntryClass::Asset => self.extract_asset(entry_path),
        }
    }

    fn extract_asset(&self, entry_path: &str) -> EntryOutcome {
        let pkg = match Package::read_from_reader(&self.reader, entry_path, None) {
            Ok(p) => p,
            Err(e) => return failed(entry_path, e),
        };
        match select_export(&pkg.payloads, self.registry, self.cfg.prefs) {
            Some((idx, handler)) => self.convert(entry_path, &pkg, idx, handler),
            // All payloads were Generic (no typed handler). Fall back to a
            // second raw read. 4a accepted trade-off: optimizing this away
            // requires read_from_reader to also return the raw bytes, which
            // is a core API change deferred past 4a.
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
            Err(e) => return failed(entry_path, e),
        };
        let bytes = match handler.export(&pkg.payloads[idx], bulk) {
            Ok(b) => b,
            Err(e) => return failed(entry_path, e),
        };
        let ext = handler.output_extension();
        match write_output(self.cfg, entry_path, Some(ext), &bytes) {
            Ok(output) => EntryOutcome::Converted {
                entry: entry_path.to_string(),
                output,
                handler: ext.to_string(),
            },
            Err(e) => failed(entry_path, e),
        }
    }

    /// `.locres` entries: parse + export per `--locres-format`. A parse
    /// failure degrades to a raw copy with a warning (mirroring the
    /// asset path's no-typed-handler fallback) — one malformed file
    /// must not fail the batch, and the raw bytes stay available for
    /// offline analysis.
    fn extract_locres(&self, entry_path: &str) -> EntryOutcome {
        let bytes = match self.reader.read_entry(entry_path) {
            Ok(b) => b,
            Err(e) => return failed(entry_path, e),
        };
        match locres_output(&bytes, self.cfg.prefs.locres) {
            Some((ext, out)) => match write_output(self.cfg, entry_path, Some(ext), &out) {
                Ok(output) => EntryOutcome::Converted {
                    entry: entry_path.to_string(),
                    output,
                    handler: ext.to_string(),
                },
                Err(e) => failed(entry_path, e),
            },
            None => match write_output(self.cfg, entry_path, None, &bytes) {
                Ok(output) => EntryOutcome::RawCopied {
                    entry: entry_path.to_string(),
                    output,
                },
                Err(e) => failed(entry_path, e),
            },
        }
    }

    fn extract_raw(&self, entry_path: &str) -> EntryOutcome {
        let bytes = match self.reader.read_entry(entry_path) {
            Ok(b) => b,
            Err(e) => return failed(entry_path, e),
        };
        match write_output(self.cfg, entry_path, None, &bytes) {
            Ok(output) => EntryOutcome::RawCopied {
                entry: entry_path.to_string(),
                output,
            },
            Err(e) => failed(entry_path, e),
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

/// Build a `Failed` outcome. Centralises the repeated construction so callers
/// use `return failed(entry_path, e)` rather than inlining the struct literal.
/// Pure conversion step for a `.locres` entry: parse + export per the
/// preference. `None` = unparsable (caller degrades to a raw copy).
/// Factored out of [`ExtractJob::extract_locres`] so the parse/convert/
/// degrade logic is unit-testable without a pak reader.
fn locres_output(bytes: &[u8], pref: select::DataTableFormat) -> Option<(&'static str, Vec<u8>)> {
    let resource = match paksmith_core::LocresResource::parse(bytes) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "locres parse failed, copying raw");
            return None;
        }
    };
    let result = match pref {
        select::DataTableFormat::Csv => paksmith_core::locres_to_csv(&resource).map(|b| ("csv", b)),
        select::DataTableFormat::Json => {
            paksmith_core::locres_to_json(&resource).map(|b| ("json", b))
        }
    };
    match result {
        Ok(pair) => Some(pair),
        Err(e) => {
            tracing::warn!(error = %e, "locres export failed, copying raw");
            None
        }
    }
}

fn failed(entry_path: &str, e: impl std::fmt::Display) -> EntryOutcome {
    EntryOutcome::Failed {
        entry: entry_path.to_owned(),
        error: e.to_string(),
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
        // Discard the bool — entries reaching convert always have a stem,
        // so set_extension always succeeds.
        let _ = path.set_extension(ext);
    }
    let display = path.to_string_lossy().into_owned();

    if cfg.dry_run {
        return Ok(display);
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create dir {}: {e}", parent.display()))?;
    }
    // Atomic create: use O_CREAT|O_EXCL (create_new) when overwrite is off so
    // that two rayon workers racing to the same --flat path both fail rather
    // than silently producing last-writer-wins with a wrong exit code.
    let mut file = if cfg.overwrite {
        fs::File::create(&path).map_err(|e| format!("create {display}: {e}"))?
    } else {
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                return Err(format!("output exists (use --overwrite): {display}"));
            }
            Err(e) => return Err(format!("create {display}: {e}")),
        }
    };
    file.write_all(bytes)
        .map_err(|e| format!("write {display}: {e}"))?;
    Ok(display)
}

#[cfg(test)]
mod write_output_tests {
    use super::*;
    use crate::extract::select::{AudioFormat, DataTableFormat};

    fn cfg(dir: &std::path::Path, flat: bool, dry_run: bool, overwrite: bool) -> ExtractConfig {
        ExtractConfig {
            output_dir: dir.to_path_buf(),
            flat,
            dry_run,
            overwrite,
            prefs: FormatPrefs {
                audio: AudioFormat::Ogg,
                datatable: DataTableFormat::Csv,
                locres: DataTableFormat::Csv,
            },
        }
    }

    /// `locres_output` (#646): CSV/JSON per pref on the committed
    /// fixture; unparsable bytes → None (degrade to raw copy).
    #[test]
    fn locres_output_converts_or_degrades() {
        let fixture = include_bytes!("../../../../tests/fixtures/data/sample_v2.locres");
        let (ext, csv) = locres_output(fixture, DataTableFormat::Csv).expect("fixture parses");
        assert_eq!(ext, "csv");
        assert_eq!(
            String::from_utf8(csv).unwrap(),
            "namespace,key,localized\nGame,key1,Hello\nGame,key2,World\n"
        );
        let (ext, json) = locres_output(fixture, DataTableFormat::Json).expect("fixture parses");
        assert_eq!(ext, "json");
        let v: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(v["namespaces"][0]["entries"][0]["localized"], "Hello");

        // Unparsable (truncated) → None.
        assert!(locres_output(&fixture[..20], DataTableFormat::Csv).is_none());
    }

    #[test]
    fn writes_converted_with_swapped_extension() {
        let dir = tempfile::tempdir().unwrap();
        let c = cfg(dir.path(), false, false, false);
        let out = write_output(&c, "Game/Hero.uasset", Some("png"), b"PNGDATA").unwrap();
        // Component-wise `Path::ends_with` so the assertion holds regardless of
        // the platform path separator (`\` on Windows).
        assert!(
            std::path::Path::new(&out).ends_with("Game/Hero.png"),
            "got {out}"
        );
        assert_eq!(std::fs::read(&out).unwrap(), b"PNGDATA");
    }

    #[test]
    fn raw_keeps_extension() {
        let dir = tempfile::tempdir().unwrap();
        let c = cfg(dir.path(), false, false, false);
        let out = write_output(&c, "Config/Game.ini", None, b"[x]").unwrap();
        assert!(
            std::path::Path::new(&out).ends_with("Config/Game.ini"),
            "got {out}"
        );
        assert_eq!(std::fs::read(&out).unwrap(), b"[x]");
    }

    #[test]
    fn dry_run_writes_nothing_but_reports_path() {
        let dir = tempfile::tempdir().unwrap();
        let c = cfg(dir.path(), false, true, false);
        let out = write_output(&c, "Game/Hero.uasset", Some("png"), b"X").unwrap();
        assert!(std::path::Path::new(&out).ends_with("Game/Hero.png"));
        assert!(!std::path::Path::new(&out).exists());
    }

    #[test]
    fn overwrite_guard_then_allow() {
        let dir = tempfile::tempdir().unwrap();
        let guard = cfg(dir.path(), false, false, false);
        let _ = write_output(&guard, "A.bin", None, b"1").unwrap();
        // The collision must be reported via the SPECIFIC "output exists" guard
        // (the `AlreadyExists` arm), not a generic create error — asserting the
        // message pins that the guard discriminates the error kind correctly.
        let err = write_output(&guard, "A.bin", None, b"2").unwrap_err();
        assert!(
            err.contains("output exists"),
            "collision must hit the AlreadyExists guard, got: {err}"
        );
        let force = cfg(dir.path(), false, false, true);
        let _ = write_output(&force, "A.bin", None, b"2").unwrap(); // last-writer-wins
        let out = dir.path().join("A.bin");
        assert_eq!(std::fs::read(out).unwrap(), b"2");
    }

    /// A create failure that is NOT a collision (here: a read-only output dir →
    /// `PermissionDenied`) must NOT be misreported as "output exists". This pins
    /// that the `AlreadyExists` match guard actually discriminates the error
    /// kind rather than swallowing every error into the collision branch.
    #[cfg(unix)]
    #[test]
    fn non_collision_create_error_is_not_reported_as_exists() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let ro = dir.path().join("ro");
        std::fs::create_dir(&ro).unwrap();
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o555)).unwrap();
        let c = cfg(&ro, false, false, false);
        let err = write_output(&c, "X.bin", None, b"1").unwrap_err();
        // Restore perms so the tempdir can be cleaned up.
        let _ = std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o755));
        assert!(
            !err.contains("output exists"),
            "a permission error must not be reported as a collision: {err}"
        );
        assert!(
            err.contains("create"),
            "expected a create error, got: {err}"
        );
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
