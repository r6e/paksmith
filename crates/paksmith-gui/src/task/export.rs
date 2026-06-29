//! Async Export As… pipeline: enumerate formats for a cold (unopened) entry,
//! and run a chosen export to a user-selected path off the UI thread.
//!
//! The dialog-bearing [`run`] can't be tested headlessly; its dialog-free core
//! [`write_export`] is integration-tested with a real pak fixture.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

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

/// Monotonic counter making each in-flight export temp name process-unique.
static EXPORT_TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// A process-unique sibling temp path for an in-progress export
/// (`<dest>.<pid>.<seq>.part`), renamed onto `dest` only after the write fully
/// succeeds. Unique — not a fixed `<dest>.part` — so a concurrent export, or a
/// pre-existing `<dest>.part` the user happens to own, is never collided with or
/// clobbered. Same directory as `dest` so the finalizing rename stays on one
/// filesystem (atomic, no cross-device copy).
fn export_temp_path(dest: &Path) -> PathBuf {
    let seq = EXPORT_TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let mut s = dest.as_os_str().to_os_string();
    s.push(format!(".{}.{}.part", std::process::id(), seq));
    PathBuf::from(s)
}

/// Open `tmp` for writing, failing closed if anything already occupies that
/// path: `create_new` (O_EXCL on Unix, `CREATE_NEW` on Windows) refuses to
/// truncate a pre-existing file or follow a pre-planted symlink. A later failure
/// may safely remove `tmp` precisely because this exclusive create proves the
/// temp is ours.
fn create_temp_exclusive(tmp: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(tmp)
}

/// Dialog-free export work: write the chosen export of `src_path` to `dest`.
///
/// Writes to a process-unique sibling temp first and renames it into place only
/// on full success, so a failed export never clobbers an existing file the user
/// chose to overwrite and leaves no partial behind. `std::fs::rename` replaces an
/// existing destination *file* atomically on Linux/macOS and on Windows (via
/// `MoveFileExW` / `SetFileInformationByHandle`); per its docs only a *directory*
/// `to` would error there, which a save-dialog file path never is.
fn write_export(
    reader: &Arc<PakReader>,
    src_path: &str,
    choice: &ExportChoice,
    dest: &Path,
) -> Result<(), paksmith_core::PaksmithError> {
    let tmp = export_temp_path(dest);
    // Exclusive create: if the temp path is already taken it isn't ours, so this
    // returns the error without removing anything.
    let file = create_temp_exclusive(&tmp)?;
    // The temp is now ours. Consuming `file` in `write_payload_to` closes it at
    // that call's return — before the rename below, which Windows requires (it
    // cannot rename a file that still has an open handle). Any failure from here
    // cleans up the temp we created.
    let result = write_payload_to(reader, src_path, choice, file)
        .and_then(|()| std::fs::rename(&tmp, dest).map_err(Into::into));
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// The actual per-choice write into the owned temp `file` (Raw streams uncapped
/// via `read_entry_to`; Typed parses + dispatches the handler). Takes `file` by
/// value so it is closed when this returns, before the caller renames it.
///
/// Raw streams the decompressed entry straight to the file — **no size cap, no
/// parse** (it must not reuse `task::asset::load`, which caps at `HEX_BYTES_CAP`
/// for the hex preview). Typed parses the package and runs the matching handler.
fn write_payload_to(
    reader: &Arc<PakReader>,
    src_path: &str,
    choice: &ExportChoice,
    mut file: std::fs::File,
) -> Result<(), paksmith_core::PaksmithError> {
    match choice {
        ExportChoice::Raw => {
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
            file.write_all(&bytes)?;
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

    /// Count leftover export temp siblings (`<dest filename>*.part`) next to
    /// `dest` — must be zero after any completed `write_export`.
    fn temp_siblings(dest: &Path) -> usize {
        let dir = dest.parent().unwrap();
        let prefix = dest.file_name().unwrap().to_string_lossy().into_owned();
        std::fs::read_dir(dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                name.starts_with(&prefix)
                    && std::path::Path::new(&name)
                        .extension()
                        .is_some_and(|ext| ext.eq_ignore_ascii_case("part"))
            })
            .count()
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
        assert_eq!(
            temp_siblings(&dest),
            0,
            "no .part temp may remain after failure"
        );
        let _ = std::fs::remove_file(&dest);
    }

    #[test]
    fn write_export_overwrites_existing_destination() {
        // Exporting over an existing file must replace it — including on Windows,
        // where `std::fs::rename` replaces an existing *file* destination
        // (MoveFileExW / SetFileInformationByHandle). Empirically refutes the
        // claim that rename errors when the destination exists.
        let reader = Arc::new(PakReader::open(fixture("real_v8b_uasset.pak")).unwrap());
        let path = "Game/Maps/Demo.uasset";
        let dest = tmp_dest("overwrite");
        std::fs::write(&dest, b"STALE CONTENT").unwrap();
        write_export(&reader, path, &ExportChoice::Raw, &dest).expect("overwrite export");

        let written = std::fs::read(&dest).unwrap();
        let _ = std::fs::remove_file(&dest);
        assert_ne!(
            written.as_slice(),
            b"STALE CONTENT",
            "an existing destination must be replaced, not preserved"
        );
        assert!(!written.is_empty(), "overwrite export must produce bytes");
    }

    #[test]
    fn write_export_leaves_unrelated_part_file_untouched() {
        // A pre-existing `<dest>.part` the user owns must never be truncated or
        // deleted: the temp name is process-unique, not a fixed `<dest>.part`.
        let reader = Arc::new(PakReader::open(fixture("real_v8b_uasset.pak")).unwrap());
        let path = "Game/Maps/Demo.uasset";
        let dest = tmp_dest("unrelated");
        let mut legacy_part = dest.as_os_str().to_os_string();
        legacy_part.push(".part");
        let legacy_part = PathBuf::from(legacy_part);
        std::fs::write(&legacy_part, b"USER FILE").unwrap();

        write_export(&reader, path, &ExportChoice::Raw, &dest).expect("export ok");

        let preserved = std::fs::read(&legacy_part);
        let _ = std::fs::remove_file(&dest);
        let _ = std::fs::remove_file(&legacy_part);
        assert_eq!(
            preserved.unwrap().as_slice(),
            b"USER FILE",
            "a pre-existing <dest>.part must be left untouched"
        );
    }

    #[test]
    fn create_temp_exclusive_refuses_an_existing_path() {
        // O_EXCL: opening must fail closed if anything already occupies the temp
        // path, so a pre-existing file is never truncated (nor a symlink
        // followed). Pins `create_new` against a silent downgrade to `create`.
        let tmp = tmp_dest("excl");
        std::fs::write(&tmp, b"PRE-EXISTING").unwrap();
        let kind = create_temp_exclusive(&tmp).err().map(|e| e.kind());
        let after = std::fs::read(&tmp).unwrap();
        let _ = std::fs::remove_file(&tmp);
        assert_eq!(
            kind,
            Some(std::io::ErrorKind::AlreadyExists),
            "exclusive create over an existing path must fail with AlreadyExists"
        );
        assert_eq!(after, b"PRE-EXISTING", "exclusive create must not truncate");
    }
}
