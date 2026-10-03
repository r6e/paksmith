//! Replacing a file by renaming an exclusively created sibling temp over it,
//! so the destination is never rewritten in place. Nothing is synced before
//! the rename.

use std::collections::hash_map::RandomState;
use std::fs::{self, File, OpenOptions};
use std::hash::BuildHasher;
use std::io;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};

const TEMP_PREFIX: &str = ".paksmith-";
const TEMP_SUFFIX: &str = ".part";

/// Distinguishes every in-flight temp in the process, so two replaces racing
/// for one destination never collide on the temp itself.
static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Drawn once per process. `RandomState` seeds itself from the OS, so this
/// needs no dependency.
static TEMP_KEY: LazyLock<RandomState> = LazyLock::new(RandomState::new);

/// Keyed, so one observed temp name does not predict later ones.
fn mix_temp_seq(key: &RandomState, seq: u64) -> u64 {
    key.hash_one(seq)
}

/// A sibling name of constant width, so a destination within `NAME_MAX` never
/// has a temp that is not. Unguessable, because a destination may be named by
/// untrusted input, and a crafted name must not land on another in-flight temp.
fn temp_path_for(dest: &Path) -> PathBuf {
    let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    dest.with_file_name(format!(
        "{TEMP_PREFIX}{:016x}{TEMP_SUFFIX}",
        mix_temp_seq(&TEMP_KEY, seq)
    ))
}

/// New content for a destination, staged in a sibling temp and renamed over
/// it by [`commit`](Self::commit).
///
/// The temp, `.paksmith-<16 hex>.part`, is created exclusively, so a taken
/// name fails rather than being written through, and only a temp this value
/// created is ever removed. On Unix the temp is created with no more than the
/// access bits of an existing regular-file destination, read without following
/// a leaf link, and then given exactly those; nothing else of the old inode
/// carries over. On Windows nothing carries, and
/// a read-only destination, or one held open without delete sharing, fails the
/// commit. The rename replaces the destination entry, so a symlink there is
/// replaced, not followed. Dropped uncommitted, or failed after the temp
/// exists, the temp is closed and then removed, ignoring a failed removal; the
/// destination is untouched.
#[derive(Debug)]
#[must_use = "dropping a StagedReplace uncommitted discards the staged content"]
pub struct StagedReplace {
    // Before `temp`: fields drop in declaration order, so the handle is closed
    // before the name is removed.
    file: File,
    temp: TempGuard,
    dest: PathBuf,
}

/// The temp's name, removed on drop while armed.
#[derive(Debug)]
struct TempGuard {
    path: PathBuf,
    armed: bool,
}

impl Drop for TempGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

impl StagedReplace {
    /// Creates the staging temp beside `dest`, which need not exist.
    ///
    /// # Errors
    ///
    /// [`StagedReplaceError::CreateTemp`] when `dest` has no file name or the
    /// exclusive create fails; nothing was created.
    /// [`StagedReplaceError::PreservePermissions`] when the bits the umask
    /// stripped cannot be restored.
    pub fn create(dest: &Path) -> Result<Self, StagedReplaceError> {
        if dest.file_name().is_none() {
            return Err(StagedReplaceError::CreateTemp(io::Error::new(
                io::ErrorKind::InvalidInput,
                "destination has no file name",
            )));
        }
        Self::create_at(dest, temp_path_for(dest))
    }

    /// [`Self::create`] with the temp at a name the caller picks.
    fn create_at(dest: &Path, temp: PathBuf) -> Result<Self, StagedReplaceError> {
        let mut options = OpenOptions::new();
        let _ = options.write(true).create_new(true);
        // Read once, above the open: the temp is safe because its creation
        // mode is a subset of what is settled on it.
        #[cfg(unix)]
        let mode = destination_mode(dest);
        // Born with the destination's bits, not narrowed to them afterwards:
        // an fd opened on a wider temp keeps its read rights across a chmod.
        #[cfg(unix)]
        if let Some(mode) = mode {
            let _ = options.mode(mode);
        }
        let file = options
            .open(&temp)
            .map_err(StagedReplaceError::CreateTemp)?;
        let staged = Self {
            file,
            temp: TempGuard {
                path: temp,
                armed: true,
            },
            dest: dest.to_path_buf(),
        };
        #[cfg(unix)]
        if let Some(mode) = mode {
            settle_mode(&staged.file, mode).map_err(StagedReplaceError::PreservePermissions)?;
        }
        Ok(staged)
    }

    /// The temp's open handle, for writing the new content with the caller's
    /// own writer and error type.
    pub fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    /// Closes the temp and renames it over the destination.
    ///
    /// # Errors
    ///
    /// [`StagedReplaceError::Replace`] when the rename fails.
    pub fn commit(self) -> Result<(), StagedReplaceError> {
        let Self {
            file,
            mut temp,
            dest,
        } = self;
        // Closed before the rename so the handle cannot outlive the temp's
        // name.
        drop(file);
        fs::rename(&temp.path, &dest).map_err(StagedReplaceError::Replace)?;
        temp.armed = false;
        Ok(())
    }
}

/// The step of a [`StagedReplace`] that failed, with its I/O error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StagedReplaceError {
    /// The temp could not be created beside the destination.
    #[error("create temp file: {0}")]
    CreateTemp(io::Error),
    /// The destination's access bits could not be restored on the temp.
    #[error("preserve permissions: {0}")]
    PreservePermissions(io::Error),
    /// The temp could not be renamed over the destination.
    #[error("replace destination: {0}")]
    Replace(io::Error),
}

/// Keeps the failed step's [`io::ErrorKind`]; the message names the step.
impl From<StagedReplaceError> for io::Error {
    fn from(e: StagedReplaceError) -> Self {
        let kind = match &e {
            StagedReplaceError::CreateTemp(inner)
            | StagedReplaceError::PreservePermissions(inner)
            | StagedReplaceError::Replace(inner) => inner.kind(),
        };
        Self::new(kind, e)
    }
}

/// The access bits an existing regular-file destination passes on, or `None`
/// when there is nothing to carry.
///
/// Reads with `symlink_metadata`, so a leaf link cannot source this from its
/// target.
#[cfg(unix)]
fn destination_mode(dest: &Path) -> Option<u32> {
    let meta = fs::symlink_metadata(dest).ok()?;
    meta.file_type()
        .is_file()
        .then(|| access_bits(meta.permissions().mode()))
}

/// Restores what `open`'s umask stripped from the temp's creation mode.
/// Skipped where nothing was stripped: a filesystem that fixes the bits itself
/// (FAT's `fmask`) already matches, and may refuse a chmod to anyone but the
/// mount's owner.
#[cfg(unix)]
fn settle_mode(file: &File, mode: u32) -> io::Result<()> {
    if access_bits(file.metadata()?.permissions().mode()) == mode {
        return Ok(());
    }
    file.set_permissions(fs::Permissions::from_mode(mode))
}

/// The permission bits of an `st_mode`, which `Permissions` round-trips
/// whole. The payload write does not strip everything this does: sticky
/// always survives, and setuid survives a zero-byte payload.
#[cfg(unix)]
fn access_bits(st_mode: u32) -> u32 {
    st_mode & 0o777
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::io::Write as _;

    use super::*;

    fn replace(dest: &Path, bytes: &[u8]) -> io::Result<()> {
        let mut staged = StagedReplace::create(dest)?;
        staged.file_mut().write_all(bytes)?;
        staged.commit()?;
        Ok(())
    }

    fn is_temp(name: &OsStr) -> bool {
        let name = name.to_string_lossy();
        name.starts_with(TEMP_PREFIX) && name.ends_with(TEMP_SUFFIX)
    }

    fn names(dir: &Path) -> Vec<String> {
        fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn commit_replaces_the_destination() {
        let root = tempfile::tempdir().unwrap();
        let dest = root.path().join("x.bin");
        fs::write(&dest, b"ORIGINAL").unwrap();

        replace(&dest, b"NEW").unwrap();

        assert_eq!(fs::read(&dest).unwrap(), b"NEW");
        assert_eq!(names(root.path()), ["x.bin"]);
    }

    #[test]
    fn an_absent_destination_is_created() {
        let root = tempfile::tempdir().unwrap();
        let dest = root.path().join("x.bin");

        replace(&dest, b"NEW").unwrap();

        assert_eq!(fs::read(&dest).unwrap(), b"NEW");
        assert_eq!(names(root.path()), ["x.bin"]);
    }

    #[test]
    fn dropping_an_uncommitted_stage_removes_its_temp() {
        let root = tempfile::tempdir().unwrap();
        let dest = root.path().join("x.bin");
        fs::write(&dest, b"ORIGINAL").unwrap();

        let mut staged = StagedReplace::create(&dest).unwrap();
        staged.file_mut().write_all(b"PAYLOAD").unwrap();
        let staged_temps = fs::read_dir(root.path())
            .unwrap()
            .filter(|e| is_temp(&e.as_ref().unwrap().file_name()))
            .count();
        drop(staged);

        assert_eq!(staged_temps, 1, "the filter must see the live temp");
        assert_eq!(names(root.path()), ["x.bin"]);
        assert_eq!(fs::read(&dest).unwrap(), b"ORIGINAL");
    }

    /// A directory destination makes the rename fail with the temp written.
    #[test]
    fn a_failed_commit_leaves_no_temp_behind() {
        let root = tempfile::tempdir().unwrap();
        let dest = root.path().join("blocked.bin");
        fs::create_dir(&dest).unwrap();

        let mut staged = StagedReplace::create(&dest).unwrap();
        staged.file_mut().write_all(b"PAYLOAD").unwrap();
        let err = staged.commit().unwrap_err();

        assert!(
            matches!(err, StagedReplaceError::Replace(_)),
            "expected a rename failure: {err}"
        );
        assert_eq!(names(root.path()), ["blocked.bin"]);
    }

    #[test]
    fn a_destination_without_a_file_name_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let dest = root.path().join("sub").join("..");

        let err = StagedReplace::create(&dest).unwrap_err();

        assert!(
            matches!(&err, StagedReplaceError::CreateTemp(e) if e.kind() == io::ErrorKind::InvalidInput),
            "{err}"
        );
        assert_eq!(names(root.path()), [] as [&str; 0]);
    }

    /// The message is what a caller showing the `io::Error` displays.
    #[test]
    fn a_stage_error_keeps_its_kind_and_message_as_an_io_error() {
        let boom = |kind| io::Error::new(kind, "boom");
        let cases = [
            (
                StagedReplaceError::CreateTemp(boom(io::ErrorKind::AlreadyExists)),
                io::ErrorKind::AlreadyExists,
                "create temp file: boom",
            ),
            (
                StagedReplaceError::PreservePermissions(boom(io::ErrorKind::PermissionDenied)),
                io::ErrorKind::PermissionDenied,
                "preserve permissions: boom",
            ),
            (
                StagedReplaceError::Replace(boom(io::ErrorKind::NotFound)),
                io::ErrorKind::NotFound,
                "replace destination: boom",
            ),
        ];
        for (err, kind, message) in cases {
            let err = io::Error::from(err);
            assert_eq!((err.kind(), err.to_string().as_str()), (kind, message));
        }
    }

    /// Execute bits never come from creation (`0o666 & !umask`), so 0o777
    /// shows the mode was carried, under any umask.
    #[cfg(unix)]
    #[test]
    fn the_destination_access_bits_carry_over() {
        let root = tempfile::tempdir().unwrap();
        let dest = root.path().join("x.bin");
        fs::write(&dest, b"ORIGINAL").unwrap();
        fs::set_permissions(&dest, fs::Permissions::from_mode(0o777)).unwrap();

        replace(&dest, b"NEW").unwrap();

        assert_eq!(
            fs::metadata(&dest).unwrap().permissions().mode() & 0o777,
            0o777
        );
    }

    /// Planted sticky rather than setuid so the assertion observes the mask and
    /// not the kernel: an unprivileged write strips setuid, and nothing strips
    /// sticky.
    #[cfg(unix)]
    #[test]
    fn bits_outside_the_access_range_do_not_carry() {
        let root = tempfile::tempdir().unwrap();
        let dest = root.path().join("planted.bin");
        fs::write(&dest, b"ORIGINAL").unwrap();
        fs::set_permissions(&dest, fs::Permissions::from_mode(0o1755)).unwrap();

        replace(&dest, b"PAYLOAD").unwrap();

        let mode = fs::metadata(&dest).unwrap().permissions().mode();
        assert_eq!(mode & 0o7000, 0, "setuid/setgid/sticky survived: {mode:o}");
        assert_eq!(mode & 0o777, 0o755, "access bits should still carry");
    }

    /// The target carries an owner-execute bit, which creation cannot produce
    /// under any umask, so its absence shows the mode was not read through
    /// the link.
    #[cfg(unix)]
    #[test]
    fn the_mode_is_not_sourced_through_a_leaf_link() {
        let root = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let target = other.path().join("privileged");
        fs::write(&target, b"T").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o4707)).unwrap();
        let via = root.path().join("via.bin");
        std::os::unix::fs::symlink(&target, &via).unwrap();

        replace(&via, b"PAYLOAD").unwrap();

        let mode = fs::metadata(&via).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o111,
            0,
            "execute bits can only have come from the link target: {mode:o}"
        );
        assert_eq!(
            mode & 0o7000,
            0,
            "harvested setuid through a link: {mode:o}"
        );
        assert_eq!(fs::read(&target).unwrap(), b"T");
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o7777,
            0o4707
        );
    }

    /// The temp's `create_new` is what stops a link planted at the temp's name
    /// from turning the replace into a write through that link. The name's
    /// secrecy is a separate layer, so this plants the link at a known name.
    #[cfg(unix)]
    #[test]
    fn a_link_at_the_temp_name_is_not_written_through() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let victim = outside.path().join("victim");
        fs::write(&victim, b"VICTIM").unwrap();
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o644)).unwrap();
        let dest = root.path().join("x.bin");
        fs::write(&dest, b"ORIGINAL").unwrap();
        fs::set_permissions(&dest, fs::Permissions::from_mode(0o600)).unwrap();
        let temp = root.path().join(".paksmith-planted.part");
        std::os::unix::fs::symlink(&victim, &temp).unwrap();

        let err = StagedReplace::create_at(&dest, temp.clone()).unwrap_err();

        assert!(
            matches!(&err, StagedReplaceError::CreateTemp(e) if e.kind() == io::ErrorKind::AlreadyExists),
            "{err}"
        );
        assert_eq!(fs::read(&victim).unwrap(), b"VICTIM");
        assert_eq!(
            fs::metadata(&victim).unwrap().permissions().mode() & 0o777,
            0o644
        );
        assert!(
            fs::symlink_metadata(&temp)
                .unwrap()
                .file_type()
                .is_symlink(),
            "a name the replace did not create was removed"
        );
        assert_eq!(fs::read(&dest).unwrap(), b"ORIGINAL");
    }

    /// Once renamed, the temp's name is the destination's, so the guard must
    /// stand down. Staging at the destination's own name makes that visible.
    #[cfg(unix)]
    #[test]
    fn a_committed_temp_name_is_not_removed_afterwards() {
        let root = tempfile::tempdir().unwrap();
        let dest = root.path().join("x.bin");

        let mut staged = StagedReplace::create_at(&dest, dest.clone()).unwrap();
        staged.file_mut().write_all(b"PAYLOAD").unwrap();
        staged.commit().unwrap();

        assert_eq!(fs::read(&dest).unwrap(), b"PAYLOAD");
    }

    /// The temp must never be wider than the destination while it holds the
    /// payload: an fd another user opens in that window keeps its read rights
    /// across a later chmod. Watches the temp from a second thread, because
    /// the final mode cannot tell creating-with-the-bits from narrowing later.
    #[cfg(unix)]
    #[test]
    fn a_temp_is_never_wider_than_the_destination() {
        use std::sync::atomic::{AtomicBool, AtomicUsize};

        let root = tempfile::tempdir().unwrap();
        let dest = root.path().join("secret.bin");
        fs::write(&dest, b"ORIGINAL").unwrap();
        fs::set_permissions(&dest, fs::Permissions::from_mode(0o600)).unwrap();

        // Results are collected, not unwrapped, inside the scope: it joins
        // every thread before propagating a panic, so a failing replace with
        // `done` still false would spin the watcher and hang the binary.
        let done = AtomicBool::new(false);
        let seen = AtomicUsize::new(0);
        let (widest, results) = std::thread::scope(|scope| {
            let watcher = scope.spawn(|| {
                let mut widest = 0u32;
                while !done.load(Ordering::Relaxed) {
                    if let Ok(entries) = fs::read_dir(root.path()) {
                        for e in entries.flatten() {
                            if is_temp(&e.file_name())
                                && let Ok(m) = e.metadata()
                            {
                                widest |= m.permissions().mode() & 0o777;
                                let _ = seen.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
                widest
            });
            // Until the watcher has seen a temp, within a bound.
            let mut results = Vec::new();
            while results.len() < 200
                || (seen.load(Ordering::Relaxed) == 0 && results.len() < 20_000)
            {
                results.push(replace(&dest, b"NEW"));
            }
            done.store(true, Ordering::Relaxed);
            (watcher.join().unwrap(), results)
        });
        for result in results {
            result.unwrap();
        }

        assert!(seen.into_inner() > 0, "the watcher never saw a temp");
        assert_eq!(
            widest & !0o600,
            0,
            "a temp was observed with bits {widest:o}, outside the 0o600 destination's"
        );
        assert_eq!(
            fs::metadata(&dest).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn access_bits_keeps_only_the_permission_bits() {
        assert_eq!(access_bits(0o104_755), 0o755);
    }

    /// Independent of the umask, unlike a full replace.
    #[cfg(unix)]
    #[test]
    fn settle_restores_bits_the_open_stripped() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("x.bin");
        fs::write(&path, b"X").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let file = File::options().write(true).open(&path).unwrap();

        settle_mode(&file, 0o666).unwrap();

        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o666
        );
    }

    /// An unkeyed hash is as predictable as the counter.
    #[test]
    fn the_temp_name_depends_on_the_key() {
        let (a, b) = (RandomState::new(), RandomState::new());
        assert_ne!(
            mix_temp_seq(&a, 7),
            mix_temp_seq(&b, 7),
            "the temp name does not depend on the key"
        );
    }

    /// A constant difference or a constant xor against the counter both mean
    /// one observed name yields the rest.
    #[test]
    fn the_temp_name_is_not_a_fixed_relation_to_the_counter() {
        let key = RandomState::new();
        let seqs: Vec<u64> = (0..16).collect();
        let mixed: Vec<u64> = seqs.iter().map(|&s| mix_temp_seq(&key, s)).collect();

        let diffs: std::collections::HashSet<u64> = seqs
            .iter()
            .zip(&mixed)
            .map(|(s, m)| m.wrapping_sub(*s))
            .collect();
        let xors: std::collections::HashSet<u64> =
            seqs.iter().zip(&mixed).map(|(s, m)| m ^ s).collect();

        assert!(
            diffs.len() > 1,
            "name sits a constant distance from the counter: {mixed:?}"
        );
        assert!(
            xors.len() > 1,
            "name is a constant xor of the counter: {mixed:?}"
        );
    }

    /// The emitted name goes through the keyed hash: a raw counter emits small
    /// integers, while a keyed hash leaves the high half zero with probability
    /// 2^-32 per name.
    #[test]
    fn the_emitted_temp_name_is_not_the_raw_counter() {
        let dest = Path::new("/out/x.bin");
        let with_high_bits = (0..16)
            .map(|_| temp_path_for(dest))
            .map(|p| {
                let name = p.file_name().unwrap().to_string_lossy().into_owned();
                let hex = &name[TEMP_PREFIX.len()..name.len() - TEMP_SUFFIX.len()];
                u64::from_str_radix(hex, 16).unwrap()
            })
            .filter(|v| v >> 32 != 0)
            .count();
        assert!(
            with_high_bits > 0,
            "every temp name is a small integer: the counter is emitted raw"
        );
    }

    /// Constant width, so a destination that fits within `NAME_MAX` can never
    /// have a temp that does not.
    #[test]
    fn the_temp_name_width_does_not_follow_the_destination() {
        let short = temp_path_for(Path::new("/out/a"));
        let long = temp_path_for(&PathBuf::from(format!("/out/{}", "x".repeat(200))));
        assert_eq!(
            short.file_name().unwrap().len(),
            long.file_name().unwrap().len(),
            "temp width follows the destination: {short:?} vs {long:?}"
        );
    }

    /// Two replaces racing for one destination would otherwise pick the same
    /// temp, and the second `create_new` would fail.
    #[test]
    fn each_temp_name_is_distinct() {
        let dest = Path::new("/out/x.bin");
        let names: std::collections::HashSet<_> = (0..64).map(|_| temp_path_for(dest)).collect();
        assert_eq!(names.len(), 64, "temp names repeated");
        assert!(
            names.iter().all(|p| p.parent() == dest.parent()),
            "the temp must be a sibling so the rename stays on one filesystem"
        );
    }
}
