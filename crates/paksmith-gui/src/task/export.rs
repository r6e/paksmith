//! Async Export As… pipeline: enumerate formats for a cold (unopened) entry,
//! and run a chosen export to a user-selected path off the UI thread.
//!
//! The dialog-bearing [`run`] can't be tested headlessly; its dialog-free core
//! [`write_export`] is integration-tested with a real pak fixture.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use paksmith_core::asset::Package;
use paksmith_core::container::ContainerReader as _;
use paksmith_core::container::pak::PakReader;
use paksmith_core::export::{ExportFormat, HandlerRegistry, available_formats, export_payload};

use crate::state::export::{ExportChoice, default_export_filename};

/// Parse `path` and enumerate its exportable formats. Used only for the cold
/// path (no open parsed tab); a parse failure yields an empty list (the picker
/// then offers Raw only). Builds `all_default_handlers()` so the offered formats
/// match exactly what [`write_export`] can dispatch.
#[allow(clippy::unused_async, reason = "async required by iced Task::perform")]
pub async fn available(reader: Arc<PakReader>, path: String) -> Vec<ExportFormat> {
    match Package::read_from_reader(&reader, &path, None) {
        Ok(pkg) => available_formats(&HandlerRegistry::all_default_handlers(), &pkg),
        Err(_) => Vec::new(),
    }
}

/// Outcome of an export run, kept `Clone` so it can ride a `Message`.
#[derive(Debug, Clone)]
pub enum ExportOutcome {
    /// File written to this path.
    Written(PathBuf),
    /// User cancelled the save dialog — no toast.
    Cancelled,
    /// Export failed; stringified reason for the error toast.
    Failed(String),
}

/// Open a save dialog (default name from `src_path` + `choice`), then write the
/// export to the chosen path. Untestable headlessly (the dialog); the work is
/// [`write_export`].
pub async fn run(reader: Arc<PakReader>, src_path: String, choice: ExportChoice) -> ExportOutcome {
    let default_name = default_export_filename(&src_path, &choice);
    let Some(handle) = rfd::AsyncFileDialog::new()
        .set_file_name(default_name)
        .save_file()
        .await
    else {
        return ExportOutcome::Cancelled;
    };
    let dest = handle.path().to_path_buf();
    match write_export(&reader, &src_path, &choice, &dest) {
        Ok(()) => ExportOutcome::Written(dest),
        Err(e) => ExportOutcome::Failed(e.to_string()),
    }
}

/// Sibling temp path for an in-progress export (`<dest>.part`), renamed onto
/// `dest` only after the write fully succeeds.
fn export_temp_path(dest: &Path) -> PathBuf {
    let mut s = dest.as_os_str().to_os_string();
    s.push(".part");
    PathBuf::from(s)
}

/// Dialog-free export work: write the chosen export of `src_path` to `dest`.
///
/// Writes to a sibling temp first and renames into place on success, so a
/// failed export never clobbers an existing file the user chose to overwrite.
/// `std::fs::rename` replaces an existing destination atomically on Linux/macOS
/// and with `MOVEFILE_REPLACE_EXISTING` on Windows.
fn write_export(
    reader: &Arc<PakReader>,
    src_path: &str,
    choice: &ExportChoice,
    dest: &Path,
) -> Result<(), paksmith_core::PaksmithError> {
    let tmp = export_temp_path(dest);
    if let Err(e) = write_export_to(reader, src_path, choice, &tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = std::fs::rename(&tmp, dest) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    Ok(())
}

/// The actual per-choice write (Raw streams uncapped via `read_entry_to`;
/// Typed parses + dispatches the handler), targeting `out`.
///
/// Raw streams the decompressed entry straight to the file — **no size cap, no
/// parse** (it must not reuse `task::asset::load`, which caps at `HEX_BYTES_CAP`
/// for the hex preview). Typed parses the package and runs the matching handler.
fn write_export_to(
    reader: &Arc<PakReader>,
    src_path: &str,
    choice: &ExportChoice,
    out: &Path,
) -> Result<(), paksmith_core::PaksmithError> {
    match choice {
        ExportChoice::Raw => {
            let mut file = std::fs::File::create(out)?;
            let _ = reader.read_entry_to(src_path, &mut file)?;
            Ok(())
        }
        ExportChoice::Typed {
            payload_idx,
            extension,
        } => {
            let pkg = Package::read_from_reader(reader, src_path, None)?;
            let registry = HandlerRegistry::all_default_handlers();
            let bytes = export_payload(&pkg, *payload_idx, extension, &registry)?;
            std::fs::write(out, bytes)?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("tests/fixtures")
            .join(name)
    }

    /// Unique temp path per test (no tempfile dep); caller removes it.
    fn tmp_dest(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "paksmith_export_{}_{}.out",
            tag,
            std::process::id()
        ))
    }

    #[test]
    fn write_export_raw_writes_the_full_uncapped_entry() {
        let reader = Arc::new(PakReader::open(fixture("real_v8b_uasset.pak")).unwrap());
        let path = "Game/Maps/Demo.uasset";
        let dest = tmp_dest("raw");
        write_export(&reader, path, &ExportChoice::Raw, &dest).expect("raw export");

        let written = std::fs::read(&dest).unwrap();
        let mut expected = Vec::new();
        let _ = reader.read_entry_to(path, &mut expected).unwrap();
        let _ = std::fs::remove_file(&dest);

        assert!(!written.is_empty(), "raw export must produce bytes");
        assert_eq!(
            written, expected,
            "raw export must be the full entry, uncapped"
        );
    }

    #[tokio::test]
    async fn write_export_typed_writes_handler_output() {
        let reader = Arc::new(PakReader::open(fixture("real_v8b_uasset.pak")).unwrap());
        let path = "Game/Maps/Demo.uasset".to_string();
        // Discover a real format for this entry (also exercises `available`).
        let formats = available(reader.clone(), path.clone()).await;
        let fmt = formats
            .first()
            .copied()
            .expect("Demo.uasset must offer at least one typed format");
        let dest = tmp_dest("typed");
        write_export(
            &reader,
            &path,
            &ExportChoice::Typed {
                payload_idx: fmt.payload_idx,
                extension: fmt.extension,
            },
            &dest,
        )
        .expect("typed export");
        let written = std::fs::read(&dest).unwrap();
        let _ = std::fs::remove_file(&dest);
        assert!(!written.is_empty(), "typed export must produce bytes");
    }

    #[test]
    fn write_export_failure_leaves_destination_untouched() {
        // A failing export (non-existent source entry) must NOT clobber an
        // existing destination and must leave no `.part` temp behind.
        let reader = Arc::new(PakReader::open(fixture("real_v8b_uasset.pak")).unwrap());
        let dest = tmp_dest("atomic");
        std::fs::write(&dest, b"ORIGINAL").unwrap();
        let err = write_export(
            &reader,
            "Game/Does/Not/Exist.bin",
            &ExportChoice::Raw,
            &dest,
        );
        assert!(err.is_err(), "exporting a missing entry must fail");
        assert_eq!(
            std::fs::read(&dest).unwrap(),
            b"ORIGINAL",
            "dest must be untouched on failure"
        );
        assert!(
            !export_temp_path(&dest).exists(),
            "no .part temp may remain after failure"
        );
        let _ = std::fs::remove_file(&dest);
    }
}
