//! Async Export As… pipeline: enumerate formats for a cold (unopened) entry,
//! and run a chosen export to a user-selected path off the UI thread.
//!
//! The dialog-bearing [`run`] can't be tested headlessly; its dialog-free core
//! [`write_export`] is integration-tested with a real pak fixture.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use paksmith_core::StagedReplace;
use paksmith_core::asset::Package;
use paksmith_core::container::ContainerReader;
use paksmith_core::export::{ExportFormat, HandlerRegistry, available_formats, export_payload};

use crate::state::export::{ExportChoice, default_export_filename};

/// Parse `path` and enumerate its exportable formats. Used only for the cold
/// path (no open parsed tab); a parse failure yields an empty list (the picker
/// then offers Raw only). Builds `all_default_handlers()` so the offered formats
/// match exactly what [`write_export`] can dispatch.
#[allow(clippy::unused_async, reason = "async required by iced Task::perform")]
pub async fn available(reader: Arc<dyn ContainerReader>, path: String) -> Vec<ExportFormat> {
    // Bare entry point ⇒ no mappings and no engine-version hint (#706);
    // see the seam note in `task/open.rs`.
    match Package::read_from_reader(&reader, &path, None) {
        Ok(pkg) => available_formats(&pkg, &HandlerRegistry::all_default_handlers()),
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
pub async fn run(
    reader: Arc<dyn ContainerReader>,
    src_path: String,
    choice: ExportChoice,
) -> ExportOutcome {
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

/// Dialog-free export work: write the chosen export of `src_path` to `dest`
/// through core's [`StagedReplace`], so a failed export never clobbers a file
/// the user chose to overwrite.
fn write_export(
    reader: &Arc<dyn ContainerReader>,
    src_path: &str,
    choice: &ExportChoice,
    dest: &Path,
) -> Result<(), paksmith_core::PaksmithError> {
    let mut staged = StagedReplace::create(dest).map_err(std::io::Error::from)?;
    write_payload_to(reader, src_path, choice, staged.file_mut())?;
    staged.commit().map_err(std::io::Error::from)?;
    Ok(())
}

/// The per-choice write into the staged temp `file`.
///
/// Raw streams the decompressed entry straight to the file — **no size cap, no
/// parse** (it must not reuse `task::asset::load`, which caps at `HEX_BYTES_CAP`
/// for the hex preview). Typed parses the package and runs the matching handler.
fn write_payload_to(
    reader: &Arc<dyn ContainerReader>,
    src_path: &str,
    choice: &ExportChoice,
    file: &mut std::fs::File,
) -> Result<(), paksmith_core::PaksmithError> {
    match choice {
        ExportChoice::Raw => {
            let _ = reader.read_entry_to(src_path, file)?;
            Ok(())
        }
        ExportChoice::Typed {
            payload_idx,
            extension,
        } => {
            // Bare entry point ⇒ no mappings and no engine-version
            // hint (#706). This is the GUI path that writes artifacts,
            // so until #706 lands it and CLI `extract` can decode the
            // same bytes differently when a profile declares an engine
            // version — see the seam note in `task/open.rs`.
            let pkg = Package::read_from_reader(reader, src_path, None)?;
            let registry = HandlerRegistry::all_default_handlers();
            let bytes = export_payload(&pkg, *payload_idx, extension, &registry)?;
            file.write_all(&bytes)?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEMO_ENTRY: &str = "Game/Maps/Demo.uasset";

    fn demo_reader() -> Arc<dyn ContainerReader> {
        let pak = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("tests/fixtures/real_v8b_uasset.pak");
        paksmith_core::container::open(&pak, None).unwrap()
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn write_export_raw_writes_the_full_uncapped_entry() {
        let reader = demo_reader();
        let root = tempfile::tempdir().unwrap();
        let dest = root.path().join("raw.out");
        write_export(&reader, DEMO_ENTRY, &ExportChoice::Raw, &dest).expect("raw export");

        let written = std::fs::read(&dest).unwrap();
        assert!(!written.is_empty(), "raw export must produce bytes");
        assert_eq!(
            written,
            reader.read_entry(DEMO_ENTRY).unwrap(),
            "raw export must be the full entry, uncapped"
        );
    }

    #[tokio::test]
    async fn write_export_typed_writes_handler_output() {
        let reader = demo_reader();
        // Discover a real format for this entry (also exercises `available`).
        let formats = available(reader.clone(), DEMO_ENTRY.to_string()).await;
        let fmt = formats
            .first()
            .copied()
            .expect("Demo.uasset must offer at least one typed format");
        let root = tempfile::tempdir().unwrap();
        let dest = root.path().join("typed.out");
        write_export(
            &reader,
            DEMO_ENTRY,
            &ExportChoice::Typed {
                payload_idx: fmt.payload_idx,
                extension: fmt.extension,
            },
            &dest,
        )
        .expect("typed export");
        let written = std::fs::read(&dest).unwrap();
        assert!(!written.is_empty(), "typed export must produce bytes");
    }

    #[test]
    fn write_export_failure_leaves_destination_untouched() {
        // A failing export (non-existent source entry) must NOT clobber an
        // existing destination and must leave nothing else behind.
        let reader = demo_reader();
        let root = tempfile::tempdir().unwrap();
        let dest = root.path().join("atomic.out");
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
        assert_eq!(names(root.path()), ["atomic.out"]);
    }

    /// Replaces the destination and nothing beside it, a user's own
    /// `<dest>.part` included.
    #[test]
    fn write_export_overwrites_existing_destination() {
        let reader = demo_reader();
        let root = tempfile::tempdir().unwrap();
        let dest = root.path().join("overwrite.out");
        std::fs::write(&dest, b"STALE CONTENT").unwrap();
        let user_part = root.path().join("overwrite.out.part");
        std::fs::write(&user_part, b"USER FILE").unwrap();

        write_export(&reader, DEMO_ENTRY, &ExportChoice::Raw, &dest).expect("overwrite export");

        assert_eq!(
            std::fs::read(&dest).unwrap(),
            reader.read_entry(DEMO_ENTRY).unwrap(),
            "an existing destination must be replaced"
        );
        assert_eq!(std::fs::read(&user_part).unwrap(), b"USER FILE");
        assert_eq!(names(root.path()), ["overwrite.out", "overwrite.out.part"]);
    }

    /// Replacing hands the destination a fresh inode, so a restricted file
    /// must not come back at the umask's default. Owner-execute never comes
    /// from creation, so this holds under any umask.
    #[cfg(unix)]
    #[test]
    fn write_export_keeps_the_destination_mode() {
        use std::os::unix::fs::PermissionsExt;
        let reader = demo_reader();
        let root = tempfile::tempdir().unwrap();
        let dest = root.path().join("secret.out");
        std::fs::write(&dest, b"ORIGINAL").unwrap();
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o700)).unwrap();

        write_export(&reader, DEMO_ENTRY, &ExportChoice::Raw, &dest).expect("export ok");

        assert_eq!(
            std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    /// A destination name the platform accepts must not fail on its temp's.
    #[test]
    fn write_export_accepts_a_destination_name_near_the_length_limit() {
        let reader = demo_reader();
        let root = tempfile::tempdir().unwrap();
        let name = "x".repeat(250);
        let dest = root.path().join(&name);

        write_export(&reader, DEMO_ENTRY, &ExportChoice::Raw, &dest).expect("export ok");

        assert_eq!(names(root.path()), [name]);
    }
}
