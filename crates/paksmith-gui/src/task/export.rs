//! Async Export As… pipeline: enumerate formats for a cold (unopened) entry,
//! and run a chosen export to a user-selected path off the UI thread.
//!
//! The dialog-bearing [`run`] can't be tested headlessly; its dialog-free core
//! [`write_export`] is integration-tested with a real pak fixture.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use paksmith_core::StagedReplace;
use paksmith_core::asset::{Package, ParseInputs};
use paksmith_core::container::ContainerReader;
use paksmith_core::export::{ExportFormat, HandlerRegistry, available_formats, export_payload};

use crate::state::export::{ExportChoice, default_export_filename};

/// Parse `path` and enumerate its exportable formats. Used only for the cold
/// path (no open parsed tab); a parse failure yields an empty list (the picker
/// then offers Raw only). Builds `all_default_handlers()` so the offered formats
/// match exactly what [`write_export`] can dispatch.
#[allow(clippy::unused_async, reason = "async required by iced Task::perform")]
pub async fn available(
    reader: Arc<dyn ContainerReader>,
    inputs: ParseInputs,
    path: String,
) -> Vec<ExportFormat> {
    match Package::read_from_reader_with(&reader, &path, &inputs.read_options()) {
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
    inputs: ParseInputs,
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
    match write_export(&reader, &inputs, &src_path, &choice, &dest) {
        Ok(()) => ExportOutcome::Written(dest),
        Err(e) => ExportOutcome::Failed(e.to_string()),
    }
}

/// Dialog-free export work: write the chosen export of `src_path` to `dest`
/// through core's [`StagedReplace`], so a failed export never clobbers a file
/// the user chose to overwrite.
fn write_export(
    reader: &Arc<dyn ContainerReader>,
    inputs: &ParseInputs,
    src_path: &str,
    choice: &ExportChoice,
    dest: &Path,
) -> Result<(), paksmith_core::PaksmithError> {
    let mut staged = StagedReplace::create(dest).map_err(std::io::Error::from)?;
    write_payload_to(reader, inputs, src_path, choice, staged.file_mut())?;
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
    inputs: &ParseInputs,
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
            let pkg = Package::read_from_reader_with(reader, src_path, &inputs.read_options())?;
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
    use crate::task::test_support::{
        DEMO_ENTRY, HERO_ENTRY, demo_reader, hero_inputs, hero_reader,
    };

    /// Raw never reads the parse inputs.
    fn write_raw(
        reader: &Arc<dyn ContainerReader>,
        src_path: &str,
        dest: &Path,
    ) -> Result<(), paksmith_core::PaksmithError> {
        write_export(
            reader,
            &ParseInputs::default(),
            src_path,
            &ExportChoice::Raw,
            dest,
        )
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
        write_raw(&reader, DEMO_ENTRY, &dest).expect("raw export");

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
        let formats = available(
            reader.clone(),
            ParseInputs::default(),
            DEMO_ENTRY.to_string(),
        )
        .await;
        let fmt = formats
            .first()
            .copied()
            .expect("Demo.uasset must offer at least one typed format");
        let root = tempfile::tempdir().unwrap();
        let dest = root.path().join("typed.out");
        write_export(
            &reader,
            &ParseInputs::default(),
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
        let err = write_raw(&reader, "Game/Does/Not/Exist.bin", &dest);
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

        write_raw(&reader, DEMO_ENTRY, &dest).expect("overwrite export");

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

        write_raw(&reader, DEMO_ENTRY, &dest).expect("export ok");

        assert_eq!(
            std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[tokio::test]
    async fn available_offers_typed_formats_for_unversioned_only_with_mappings() {
        let reader = hero_reader();

        let with = available(reader.clone(), hero_inputs(), HERO_ENTRY.to_string()).await;
        let without = available(reader, ParseInputs::default(), HERO_ENTRY.to_string()).await;

        assert_ne!(with, [] as [ExportFormat; 0]);
        assert_eq!(without, [] as [ExportFormat; 0]);
    }

    #[tokio::test]
    async fn write_export_typed_decodes_unversioned_with_the_archive_mappings() {
        let reader = hero_reader();
        let inputs = hero_inputs();
        let fmt = available(reader.clone(), inputs.clone(), HERO_ENTRY.to_string())
            .await
            .first()
            .copied()
            .expect("Hero must offer a typed format with mappings");
        let choice = ExportChoice::Typed {
            payload_idx: fmt.payload_idx,
            extension: fmt.extension,
        };
        let root = tempfile::tempdir().unwrap();
        let dest = root.path().join("hero.out");

        write_export(&reader, &inputs, HERO_ENTRY, &choice, &dest).expect("typed export");
        let written = String::from_utf8_lossy(&std::fs::read(&dest).unwrap()).into_owned();
        assert!(written.contains("Health"), "{written}");

        let err = write_export(&reader, &ParseInputs::default(), HERO_ENTRY, &choice, &dest)
            .unwrap_err()
            .to_string();
        assert!(err.contains("no .usmap mappings"), "{err}");
    }

    /// A destination name the platform accepts must not fail on its temp's.
    #[test]
    fn write_export_accepts_a_destination_name_near_the_length_limit() {
        let reader = demo_reader();
        let root = tempfile::tempdir().unwrap();
        let name = "x".repeat(250);
        let dest = root.path().join(&name);

        write_raw(&reader, DEMO_ENTRY, &dest).expect("export ok");

        assert_eq!(names(root.path()), [name]);
    }
}
