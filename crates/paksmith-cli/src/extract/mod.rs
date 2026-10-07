pub(crate) mod classify;
pub(crate) mod safe_path;
pub(crate) mod select;
pub(crate) mod summary;

use std::fmt;
use std::fs;
use std::fs::OpenOptions;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use indicatif::ProgressBar;
use rayon::prelude::*;

use paksmith_core::asset::Package;
use paksmith_core::asset::ParseInputs;
use paksmith_core::container::ContainerReader;
use paksmith_core::export::HandlerRegistry;
use paksmith_core::{StagedReplace, StagedReplaceError};

use self::bounded::BoundedAbsolute;
use self::classify::{EntryClass, classify};
use self::select::{FormatPrefs, select_export};
use self::summary::EntryOutcome;

pub(crate) struct ExtractConfig {
    output_dir: PathBuf,
    /// `output_dir` with every symlink resolved, so each entry is checked
    /// against a fixed root. Used for COMPARISON only: writes and reported
    /// paths keep the caller's spelling.
    ///
    /// `None` only under `--dry-run` against a root that does not exist; an
    /// `Option` because `Path::starts_with("")` is true for every path.
    canonical_root: Option<PathBuf>,
    /// `output_dir` absolutized once, for the guard's bound and climb only:
    /// writes, reported paths and messages keep the caller's spelling, which
    /// the kernel can resolve where its absolute form exceeds `PATH_MAX`. For
    /// a relative root it assumes the cwd's path, not just the cwd, is stable
    /// for the run.
    absolute_root: PathBuf,
    flat: bool,
    dry_run: bool,
    overwrite: bool,
    prefs: FormatPrefs,
}

/// The three extract mode switches, named so a transposition is visible at
/// the call site rather than hidden in argument order.
#[derive(Clone, Copy)]
pub(crate) struct ExtractFlags {
    pub(crate) flat: bool,
    pub(crate) dry_run: bool,
    pub(crate) overwrite: bool,
}

impl ExtractConfig {
    /// The root every reported path is built under: the caller's spelling less
    /// trailing separators and trailing `.` components. The summary's
    /// `output_dir` has to be this same spelling.
    pub(crate) fn output_dir(&self) -> &Path {
        &self.output_dir
    }

    /// Bound the output directory, then create it and resolve it once, so
    /// every entry is checked against a fixed root. A root past the guard's
    /// climb bounds is refused before anything is created.
    ///
    /// Under `--dry-run` an absent root is classified but not created, since a
    /// preview that writes is not a preview.
    pub(crate) fn prepare(
        output_dir: &Path,
        flags: ExtractFlags,
        prefs: FormatPrefs,
    ) -> std::io::Result<Self> {
        // Trailing separators and `.` components are stripped once, here:
        // POSIX resolves `foo/` as `foo/.`, which FOLLOWS a final-component
        // symlink, so the probe and `create_dir_all` would act on the link's
        // target rather than the link. `components()` decides it lexically.
        let output_dir = output_dir.components().as_path().to_path_buf();
        // One classification for both modes, so they agree on the SHAPE of the
        // root. Write permission is not consulted: an absent root under an
        // unwritable parent previews and then fails the run, and an existing
        // unwritable root previews clean and fails per entry in the run.
        let absolute_root = absolute_root(&output_dir)?;
        let canonical_root = resolve_root(&output_dir, &absolute_root, flags.dry_run)?;
        Ok(Self {
            output_dir,
            canonical_root,
            absolute_root,
            flat: flags.flat,
            dry_run: flags.dry_run,
            overwrite: flags.overwrite,
            prefs,
        })
    }

    /// `candidate`, a path under `output_dir`, spelled from `absolute_root`.
    /// `None` for a path outside it, which `safe_join` never produces.
    fn absolute_of(&self, candidate: &Path) -> Option<PathBuf> {
        let tail = candidate.strip_prefix(&self.output_dir).ok()?;
        Some(self.absolute_root.join(tail))
    }
}

/// The canonical root for `--output`, or `None` for an absent one a preview
/// leaves absent. Decided by its deepest existing ancestor as the kernel sees
/// the spelling: darwin's `realpath` pops a `..` that follows a regular file,
/// and Windows reports a file in the chain as an absent path.
fn resolve_root(
    output_dir: &Path,
    absolute: &Path,
    dry_run: bool,
) -> std::io::Result<Option<PathBuf>> {
    // Climbed from the ABSOLUTE root so a relative one reaches something that
    // exists (`out` -> `""` -> `None` otherwise). Bounded like an entry's
    // parent: `safe_join` appends only `Normal` components, so a root past
    // either bound would fail every entry, in both modes and under `--flat`.
    let bounded = BoundedAbsolute::check(absolute)
        .map_err(|e| std::io::Error::new(ErrorKind::InvalidInput, e))?;
    let Some(found) = deepest_existing(bounded) else {
        return Err(std::io::Error::from(ErrorKind::NotFound));
    };
    // POSIX resolves the missing component before applying the `..`, so
    // `create_dir_all` would build it and the root would then name something
    // that already existed.
    if has_parent_dir_below(absolute, found) {
        return Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            "`..` follows a directory that does not exist",
        ));
    }
    // No path in any message here: the caller prefixes the spelled one.
    let meta = fs::metadata(found).map_err(|e| match e.kind() {
        // Only a dangling link stats as absent once `lstat` has found it, and
        // its ENOENT would read as an absence `mkdir -p` could fill.
        ErrorKind::NotFound => std::io::Error::new(ErrorKind::NotFound, DANGLING_LINK),
        ErrorKind::NotADirectory => std::io::Error::from(ErrorKind::NotADirectory),
        _ => e,
    })?;
    if !meta.is_dir() {
        return Err(std::io::Error::from(ErrorKind::NotADirectory));
    }
    // Before anything is created, so a volume that cannot produce a final path
    // (some Windows drivers) is refused in both modes rather than after the
    // run has made the root.
    let resolved = found.canonicalize()?;
    if found == absolute {
        return Ok(Some(resolved));
    }
    if dry_run {
        return Ok(None);
    }
    fs::create_dir_all(output_dir)?;
    Ok(Some(output_dir.canonicalize()?))
}

/// `output_dir` absolutized as a segment with more below it, so every path
/// the guard builds under it is spelled as the writes traverse it: Windows
/// normalizes a path's last segment differently from the others (see
/// Microsoft's "File path formats on Windows systems"). A syscall on the root
/// itself still sees it as a last segment. An empty path keeps
/// `std::path::absolute`'s refusal (clap refuses `-o ""` first), and a spelling
/// that absorbs the child into its prefix (`\\server`) is refused.
fn absolute_root(output_dir: &Path) -> std::io::Result<PathBuf> {
    if output_dir.as_os_str().is_empty() {
        return std::path::absolute(output_dir);
    }
    let mut absolute = std::path::absolute(output_dir.join("x"))?;
    if !absolute.pop() {
        return Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            "not a path a directory can be created under",
        ));
    }
    Ok(absolute)
}

/// Bounds the path the guard walks and resolves. An entry path is untrusted
/// index data with no depth or length limit of its own, and both the `lstat`
/// climb and the `realpath` after it cost a syscall per component over a
/// growing prefix, so an absurd entry turns an O(1) refusal into quadratic
/// churn. One byte under `PATH_MAX`, taken as 1024 unless the platform is
/// known to allow 4096, so it is the bound, not the walk's ENAMETOOLONG, that
/// refuses an over-long spelling in both modes. The output root is held to
/// the same bound. A spelling that grows as it resolves (macOS's `/tmp`) can
/// still fail the walk in a real run that its preview of an absent root
/// passed.
const MAX_CLIMB_PATH_BYTES: usize =
    if cfg!(any(target_os = "linux", target_os = "android", windows)) {
        4095
    } else {
        1023
    };
/// Counted over the ABSOLUTE path, so the output root and, for a relative one,
/// the cwd are spent from the same budget.
const MAX_CLIMB_STEPS: usize = 256;

/// A path past either climb bound. Its own message, naming the ceilings: the
/// remedy is a shorter path. Path-free, so each caller names the path it was
/// asked about.
#[derive(Debug)]
struct TooDeepOrLong;

impl fmt::Display for TooDeepOrLong {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "too deep or too long to check (max {MAX_CLIMB_STEPS} components, \
             {MAX_CLIMB_PATH_BYTES} bytes)"
        )
    }
}

impl std::error::Error for TooDeepOrLong {}

mod bounded {
    use std::path::Path;

    use super::{MAX_CLIMB_PATH_BYTES, MAX_CLIMB_STEPS, TooDeepOrLong};

    /// An absolute path inside both climb bounds, decided from the text before
    /// anything touches the filesystem. Its field is private to this module, so
    /// [`BoundedAbsolute::check`] is the only way to build one, and a climb
    /// that takes one is bounded. The caller absolutizes, so a relative path's
    /// cwd is charged too.
    #[derive(Clone, Copy)]
    pub(super) struct BoundedAbsolute<'a>(&'a Path);

    impl<'a> BoundedAbsolute<'a> {
        pub(super) fn check(absolute: &'a Path) -> Result<Self, TooDeepOrLong> {
            debug_assert!(absolute.is_absolute(), "{}", absolute.display());
            if absolute.as_os_str().len() > MAX_CLIMB_PATH_BYTES
                || absolute.components().count() > MAX_CLIMB_STEPS
            {
                return Err(TooDeepOrLong);
            }
            Ok(Self(absolute))
        }

        pub(super) fn path(self) -> &'a Path {
            self.0
        }
    }
}

/// The deepest ancestor of `absolute` (itself included) that exists, or the
/// first whose `lstat` fails for any reason other than absence.
///
/// `symlink_metadata`, not `exists`: `exists` follows links and reports a
/// dangling one as absent. And only ABSENCE continues the climb — on macOS an
/// ACL on a planted link can deny its `lstat` while traversal still follows
/// it, so stepping past any other failure would step past the link.
fn deepest_existing(absolute: BoundedAbsolute<'_>) -> Option<&Path> {
    absolute.path().ancestors().find(|ancestor| {
        !matches!(fs::symlink_metadata(ancestor), Err(e) if e.kind() == ErrorKind::NotFound)
    })
}

/// Reported for a dangling link at, above or inside the output root.
const DANGLING_LINK: &str = "resolves through a symlink whose target does not exist";

/// Reported for a regular file where an entry needs a directory.
const NOT_A_DIRECTORY: &str = "a component of the parent path is not a directory";

/// Reported for a candidate that resolves, or is spelled, outside the root.
const OUTSIDE_ROOT: &str = "resolves outside the output directory";

/// Whether a `..` appears in the part of `absolute` below `found`, its deepest
/// existing ancestor.
fn has_parent_dir_below(absolute: &Path, found: &Path) -> bool {
    absolute.strip_prefix(found).is_ok_and(|tail| {
        tail.components()
            .any(|c| c == std::path::Component::ParentDir)
    })
}

/// Reject `path` unless the deepest existing ancestor of its PARENT resolves
/// to a directory inside `canonical_root` — where the text of
/// [`safe_path::safe_join`]'s result actually lands. Walks from the parent
/// because neither write branch follows a symlink at the leaf: `create_new`
/// is `O_EXCL`, and `rename` replaces the entry. Judged on the canonical spelling, so a
/// second spelling of the root — a bind mount, or macOS's
/// `/System/Volumes/Data` — counts as outside it.
fn verify_resolves_inside_root(cfg: &ExtractConfig, path: &Path) -> Result<(), String> {
    // Spelled from the root `prepare` absolutized, so no entry pays a `getcwd`.
    let Some(absolute) = cfg.absolute_of(path) else {
        return Err(format!("{OUTSIDE_ROOT}: {}", path.display()));
    };
    // Bounded BEFORE the walk and before the root check, so a preview and the
    // run it previews agree on a path over the bound.
    let parent = BoundedAbsolute::check(absolute.parent().unwrap_or(&absolute))
        .map_err(|e| format!("{e}: {}", path.display()))?;

    // Nothing to compare against — `--dry-run` on a root that does not exist —
    // so the walk is not paid for.
    let Some(canonical_root) = cfg.canonical_root.as_deref() else {
        return Ok(());
    };

    let Some(ancestor) = deepest_existing(parent) else {
        return Err(format!("no resolvable ancestor: {}", path.display()));
    };

    // Rejected, never skipped, and named by the CANDIDATE: the ancestor is
    // spelled from `absolute_root`, absolutized against a symlink-resolved
    // `getcwd`.
    let resolved = ancestor.canonicalize().map_err(|e| match e.kind() {
        ErrorKind::NotFound if ancestor.is_symlink() => {
            format!("{DANGLING_LINK}: {}", path.display())
        }
        ErrorKind::NotADirectory => format!("{NOT_A_DIRECTORY}: {}", path.display()),
        _ => format!("resolve ancestor of {}: {e}", path.display()),
    })?;

    // `Path::starts_with` is component-wise; a string comparison would accept
    // a sibling whose name merely extends the root's (`out` vs `outside`).
    if !resolved.starts_with(canonical_root) {
        return Err(format!("{OUTSIDE_ROOT}: {}", path.display()));
    }
    // `canonicalize` resolves a regular file happily; a file higher up has
    // already failed it with ENOTDIR above.
    if !resolved.is_dir() {
        return Err(format!("{NOT_A_DIRECTORY}: {}", path.display()));
    }
    Ok(())
}

pub(crate) struct ExtractJob<'a> {
    /// Type-erased container handle — any container format.
    pub(crate) reader: Arc<dyn ContainerReader>,
    pub(crate) registry: &'a HandlerRegistry,
    pub(crate) cfg: &'a ExtractConfig,
    /// Effective `.usmap` mappings (explicit `--mappings` or the
    /// selected profile's source — #651) and the profile's engine
    /// version (#656), shared across all workers.
    pub(crate) inputs: &'a ParseInputs,
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
        let opts = self.inputs.read_options();
        let pkg = match Package::read_from_reader_with(&self.reader, entry_path, &opts) {
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
        // A handler export error fails the entry with NO raw fallback —
        // the deliberate typed-asset policy (unlike the locres path, which
        // degrades to a raw copy): a typed asset that fails conversion is
        // surfaced loudly rather than silently downgraded. Note the set of
        // affected assets grows with each dispatch registration — #648
        // extended it to cube/array/volume textures, so e.g. a cubemap
        // whose 6-face composite exceeds the 1 GiB decode cap now fails
        // here where it previously fell through to a raw copy as Generic.
        // #650 moved external-bulk skeletal meshes into the set: their LOD
        // geometry resolves at parse time, so meshes that previously carried
        // empty geometry (no supporting handler → raw copy) now take the
        // glTF path and any export error fails the entry here.
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
        match locres_output(entry_path, &bytes, self.cfg.prefs.locres) {
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

/// Pure conversion step for a `.locres` entry: parse + export per the
/// preference. `None` = unparsable (caller degrades to a raw copy), with a
/// warning naming `entry_path`.
/// Factored out of [`ExtractJob::extract_locres`] so the parse/convert/
/// degrade logic is unit-testable without a pak reader.
fn locres_output(
    entry_path: &str,
    bytes: &[u8],
    pref: select::DataTableFormat,
) -> Option<(&'static str, Vec<u8>)> {
    let resource = match paksmith_core::LocresResource::parse(bytes) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(entry = ?entry_path, error = e.to_string(), "locres parse failed, copying raw");
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
            tracing::warn!(entry = ?entry_path, error = e.to_string(), "locres export failed, copying raw");
            None
        }
    }
}

/// Build a `Failed` outcome. Centralises the repeated construction so callers
/// use `return failed(entry_path, e)` rather than inlining the struct literal.
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

    // Above the dry-run return, and before any directory is created: creating
    // them outside the root is part of the vulnerability, not just the write.
    verify_resolves_inside_root(cfg, &path)?;
    if cfg.dry_run {
        return Ok(display);
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create dir {}: {e}", parent.display()))?;
    }
    // `O_CREAT|O_EXCL`, which refuses a leaf symlink live or dangling, so a
    // planted link never takes the direct write.
    match OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(mut file) => file
            .write_all(bytes)
            .map_err(|e| format!("write {display}: {e}"))?,
        // A file can never replace a directory, so neither mode suggests or
        // stages it. Any failure qualifies: Windows reports a directory there
        // as access denied, not as existing.
        Err(_) if fs::symlink_metadata(&path).is_ok_and(|m| m.is_dir()) => {
            return Err(format!("output is a directory: {display}"));
        }
        Err(e) if cfg.overwrite && e.kind() == ErrorKind::AlreadyExists => {
            replace_via_temp(&path, &display, bytes)?;
        }
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {
            return Err(format!("output exists (use --overwrite): {display}"));
        }
        Err(e) => return Err(format!("create {display}: {e}")),
    }
    Ok(display)
}

/// Write `bytes` over `path` through core's [`StagedReplace`]. As one rename,
/// it keeps `--flat`'s last-writer-wins.
fn replace_via_temp(path: &Path, display: &str, bytes: &[u8]) -> Result<(), String> {
    let mut staged = StagedReplace::create(path).map_err(|e| replace_failure(display, e))?;
    staged
        .file_mut()
        .write_all(bytes)
        .map_err(|e| format!("write {display}: {e}"))?;
    staged.commit().map_err(|e| replace_failure(display, e))
}

/// This command's wording for each step of a staged replace.
fn replace_failure(display: &str, e: StagedReplaceError) -> String {
    match e {
        StagedReplaceError::CreateTemp(e) => format!("create temp beside {display}: {e}"),
        StagedReplaceError::PreservePermissions(e) => {
            format!("preserve permissions of {display}: {e}")
        }
        StagedReplaceError::Replace(e) => format!("replace {display}: {e}"),
        other => format!("overwrite {display}: {other}"),
    }
}

#[cfg(test)]
mod write_output_tests {
    use super::*;
    use crate::extract::select::{AudioFormat, DataTableFormat};

    /// Builds through the real constructor, so every test resolves its root
    /// exactly as production does.
    fn cfg(dir: &std::path::Path, flat: bool, dry_run: bool, overwrite: bool) -> ExtractConfig {
        try_cfg(dir, flat, dry_run, overwrite).unwrap()
    }

    /// For the roots whose REFUSAL is the property under test.
    fn try_cfg(
        dir: &std::path::Path,
        flat: bool,
        dry_run: bool,
        overwrite: bool,
    ) -> std::io::Result<ExtractConfig> {
        ExtractConfig::prepare(
            dir,
            ExtractFlags {
                flat,
                dry_run,
                overwrite,
            },
            FormatPrefs {
                audio: AudioFormat::Ogg,
                datatable: DataTableFormat::Csv,
                locres: DataTableFormat::Csv,
            },
        )
    }

    /// `locres_output` (#646): CSV/JSON per pref on the committed
    /// fixture; unparsable bytes → None (degrade to a raw copy) with a
    /// warning naming the entry, its control characters escaped (#843).
    ///
    /// The only in-process caller of the degrade arm, so its `warn!`
    /// callsite first registers after `traced_test`'s global subscriber is
    /// installed and no untraced sibling can cache it as disabled.
    #[tracing_test::traced_test]
    #[test]
    fn locres_output_converts_or_degrades() {
        let fixture = include_bytes!("../../../../tests/fixtures/data/sample_v2.locres");
        let entry = "Game/L10N/de.locres";
        let (ext, csv) =
            locres_output(entry, fixture, DataTableFormat::Csv).expect("fixture parses");
        assert_eq!(ext, "csv");
        assert_eq!(
            String::from_utf8(csv).unwrap(),
            "namespace,key,localized\nGame,key1,Hello\nGame,key2,World\n"
        );
        let (ext, json) =
            locres_output(entry, fixture, DataTableFormat::Json).expect("fixture parses");
        assert_eq!(ext, "json");
        let v: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(v["namespaces"][0]["entries"][0]["localized"], "Hello");

        // Unparsable (truncated) → None, and the warning names a hostile
        // entry with its controls escaped rather than sent to the terminal.
        let hostile = "Game/L10N/\u{1b}[2J\u{9b}2Jde.locres";
        assert!(locres_output(hostile, &fixture[..20], DataTableFormat::Csv).is_none());
        logs_assert(|lines| {
            let warning = lines
                .iter()
                .find(|l| l.contains("locres parse failed, copying raw"))
                .ok_or_else(|| format!("no degrade warning in {lines:?}"))?;
            if warning.contains(r#"entry="Game/L10N/\u{1b}[2J\u{9b}2Jde.locres""#)
                && !warning.contains(['\u{1b}', '\u{9b}'])
            {
                Ok(())
            } else {
                Err(format!("warning must name the escaped entry: {warning:?}"))
            }
        });
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

    /// `--dry-run` must stay free of side effects, and only a root that does
    /// NOT exist can show the constructor creating one.
    #[test]
    fn dry_run_does_not_create_a_missing_output_root() {
        let parent = tempfile::tempdir().unwrap();
        let missing = parent.path().join("not-created");

        let c = cfg(&missing, false, true, false);
        let reported = write_output(&c, "a/b.bin", None, b"x").unwrap();
        assert!(
            reported.ends_with("b.bin"),
            "dry-run still reports the path"
        );

        assert!(
            !missing.exists(),
            "--dry-run created the output root it promised not to touch"
        );
    }

    /// Issue #723: a symlink planted in the output directory before extraction
    /// redirects the write through it, because `safe_join` is lexical and
    /// `create_dir_all` resolves links on every component.
    ///
    /// `sub/passwd` is lexically pristine on purpose — no `..`, no leading
    /// separator, no drive-ish segment — so the lexical guard cannot be what
    /// rejects it. `overwrite` is off on purpose too: this vector is live in
    /// the DEFAULT configuration, and `O_EXCL` does not mask it because the
    /// link is an intermediate component, not the leaf.
    ///
    /// The victim-side assertion is the load-bearing one. It cannot pass for
    /// a path-does-not-exist reason, because non-existence IS the requirement.
    #[cfg(unix)]
    #[test]
    fn a_planted_symlink_cannot_redirect_a_write_outside_the_output_root() {
        let root = tempfile::tempdir().unwrap();
        let victim = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(victim.path(), root.path().join("sub")).unwrap();

        let c = cfg(root.path(), false, false, false);
        let err = write_output(&c, "sub/passwd", None, b"PWNED").unwrap_err();

        assert!(
            !victim.path().join("passwd").exists(),
            "write escaped the output root through a pre-planted symlink: {err}"
        );
        assert!(
            err.contains("resolves outside the output directory"),
            "must be rejected by resolving the path, not lexically: {err}"
        );
    }

    /// The same vector at the leaf, which only `--overwrite` can reach: the
    /// default branch's `create_new` already refuses to follow a symlink final
    /// component.
    #[cfg(unix)]
    #[test]
    fn overwrite_cannot_clobber_through_a_planted_leaf_symlink() {
        let root = tempfile::tempdir().unwrap();
        let victim = tempfile::tempdir().unwrap();
        let target = victim.path().join("leaf.bin");
        std::fs::write(&target, b"ORIGINAL").unwrap();
        std::os::unix::fs::symlink(&target, root.path().join("leaf.bin")).unwrap();

        let c = cfg(root.path(), false, false, true);
        // Succeeds by design: the leaf link is replaced, not refused.
        let _reported = write_output(&c, "leaf.bin", None, b"PWNED").unwrap();

        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"ORIGINAL",
            "--overwrite followed a leaf symlink and clobbered a file outside the output root"
        );
        assert!(
            !std::fs::symlink_metadata(root.path().join("leaf.bin"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "the link should have been replaced by a regular file"
        );
    }

    /// An entry naming a DOS device (#811) or holding a control or bidi
    /// character is refused before any of its directories is created, on
    /// every platform, in the real run and in a preview, including a preview
    /// of an absent root, where containment has no root to compare against.
    #[test]
    fn an_entry_naming_a_device_or_holding_a_hazard_is_refused() {
        let base = tempfile::tempdir().unwrap();
        let existing = base.path().join("existing");
        std::fs::create_dir(&existing).unwrap();
        let absent = base.path().join("absent");
        for (entry, refusal) in [
            ("Game/NUL.uasset", "entry path names a reserved device"),
            ("Game/a\u{1b}b.uasset", "entry path contains a control"),
        ] {
            for (root, dry_run) in [(&existing, false), (&existing, true), (&absent, true)] {
                let c = cfg(root, false, dry_run, false);
                let err = write_output(&c, entry, Some("png"), b"DATA").unwrap_err();
                let case = format!("{entry:?} {} dry_run={dry_run}", root.display());
                assert!(err.starts_with(refusal), "{case}: {err:?}");
                assert!(
                    !root.join("Game").exists(),
                    "{case}: the entry's directory was created"
                );
            }
        }
    }

    /// A directory junction needs no privilege on Windows, so it is the
    /// planted-intermediate shape reachable there (#808).
    #[cfg(windows)]
    fn junction(link: &std::path::Path, target: &std::path::Path) {
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .status()
            .unwrap();
        assert!(status.success(), "mklink /J failed: {status}");
    }

    /// The junction twin of the planted-symlink escape: refused, victim
    /// untouched.
    #[cfg(windows)]
    #[test]
    fn a_planted_junction_cannot_redirect_a_write_outside_the_output_root() {
        let root = tempfile::tempdir().unwrap();
        let victim = tempfile::tempdir().unwrap();
        junction(&root.path().join("sub"), victim.path());

        let c = cfg(root.path(), false, false, false);
        let err = write_output(&c, "sub/x.bin", None, b"PWNED").unwrap_err();

        assert!(
            !victim.path().join("x.bin").exists(),
            "write escaped the output root through a planted junction: {err}"
        );
        assert!(
            err.contains("resolves outside the output directory"),
            "got {err}"
        );
    }

    /// The junction twin of a link back inside the root: written through.
    #[cfg(windows)]
    #[test]
    fn a_junction_back_inside_the_root_is_written_through() {
        let root = tempfile::tempdir().unwrap();
        let real = root.path().join("b");
        std::fs::create_dir(&real).unwrap();
        junction(&root.path().join("a"), &real);

        let c = cfg(root.path(), false, false, false);
        let _reported = write_output(&c, "a/x.bin", None, b"X").unwrap();
        assert_eq!(std::fs::read(real.join("x.bin")).unwrap(), b"X");
    }

    /// Containment compares COMPONENTS, not the path string: a sibling whose
    /// name extends the root's is a string prefix but not a component prefix.
    #[cfg(unix)]
    #[test]
    fn a_sibling_whose_name_extends_the_root_is_not_inside_it() {
        let base = tempfile::tempdir().unwrap();
        let root = base.path().join("out");
        let outside = base.path().join("outside");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("sub")).unwrap();

        let c = cfg(&root, false, false, false);
        let err = write_output(&c, "sub/x.bin", None, b"PWNED").unwrap_err();

        assert!(
            !outside.join("x.bin").exists(),
            "write escaped into a sibling whose name extends the root's: {err}"
        );
        assert!(
            err.contains("resolves outside the output directory"),
            "{err}"
        );
    }

    /// `base` extended to exactly `len` bytes by components of at most 200
    /// bytes, inside every platform's `NAME_MAX`.
    fn chain_of_len(base: &Path, len: usize) -> PathBuf {
        let mut path = base.to_path_buf();
        while path.as_os_str().len() < len {
            let room = len - path.as_os_str().len() - 1;
            // Never leave a single byte, which a separator alone would overrun.
            let name = if room > 200 { room.min(202) - 2 } else { room };
            path.push("p".repeat(name));
        }
        assert_eq!(path.as_os_str().len(), len);
        path
    }

    /// `prepare` refused `root` as past a climb bound, naming no path.
    fn assert_root_past_bound(root: &Path, dry_run: bool) {
        let err = try_cfg(root, false, dry_run, false)
            .err()
            .unwrap_or_else(|| panic!("accepted a root past the bound: {}", root.display()));
        assert_eq!(err.kind(), ErrorKind::InvalidInput, "{err}");
        assert_eq!(err.to_string(), TooDeepOrLong.to_string());
    }

    /// A path exactly at either bound is accepted: the bounds are ceilings,
    /// not limits one short of them.
    #[test]
    fn the_ancestor_climb_accepts_a_path_at_its_bounds() {
        let dir = tempfile::tempdir().unwrap();
        let base = std::path::absolute(dir.path()).unwrap();

        let base_steps = base.components().count();
        let at_steps = base.join("d/".repeat(MAX_CLIMB_STEPS - base_steps));
        assert_eq!(at_steps.components().count(), MAX_CLIMB_STEPS);
        assert!(
            at_steps.as_os_str().len() < MAX_CLIMB_PATH_BYTES,
            "fixture must isolate the step bound from the byte bound"
        );
        assert!(
            BoundedAbsolute::check(&at_steps).is_ok(),
            "refused a path at the step bound"
        );
        assert!(try_cfg(&at_steps, false, true, false).is_ok());
        #[cfg(unix)]
        {
            let _created = cfg(&at_steps, false, false, false);
            assert!(at_steps.is_dir());
        }

        let base_bytes = base.as_os_str().len();
        let at_bytes = base.join("x".repeat(MAX_CLIMB_PATH_BYTES - base_bytes - 1));
        assert_eq!(at_bytes.as_os_str().len(), MAX_CLIMB_PATH_BYTES);
        assert!(
            BoundedAbsolute::check(&at_bytes).is_ok(),
            "refused a path at the byte bound"
        );
    }

    /// A parent exactly at the byte bound can still be walked and resolved, so
    /// it is the bound, not an ENAMETOOLONG from the walk, that refuses a
    /// longer one — in a preview of an absent root too, which never walks. A
    /// root exactly there is accepted, and created by the real run.
    #[cfg(unix)]
    #[test]
    fn the_byte_bound_is_a_path_the_platform_can_resolve() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().canonicalize().unwrap();
        let parent = chain_of_len(&base, MAX_CLIMB_PATH_BYTES);

        assert!(try_cfg(&parent, false, true, false).is_ok());
        assert_eq!(std::fs::read_dir(&base).unwrap().count(), 0);
        let _created = cfg(&parent, false, false, false);
        assert!(parent.is_dir());

        assert_eq!(
            verify_resolves_inside_root(&cfg(&base, false, true, false), &parent.join("x.bin")),
            Ok(())
        );
    }

    /// Both bounds fail closed, decided from the text before the walk touches
    /// the filesystem.
    #[test]
    fn the_ancestor_climb_refuses_a_path_past_its_bounds() {
        let base = tempfile::tempdir().unwrap();
        assert!(
            BoundedAbsolute::check(base.path()).is_ok(),
            "an ordinary directory must be inside the bounds at all"
        );

        let too_long = base.path().join("x".repeat(MAX_CLIMB_PATH_BYTES));
        assert!(
            BoundedAbsolute::check(&too_long).is_err(),
            "accepted a path past the byte bound"
        );

        // Comfortably inside the byte bound, so this can only be the step one.
        let too_deep = base.path().join("d/".repeat(MAX_CLIMB_STEPS));
        assert!(
            too_deep.as_os_str().len() < MAX_CLIMB_PATH_BYTES,
            "fixture must isolate the step bound from the byte bound"
        );
        assert!(
            BoundedAbsolute::check(&too_deep).is_err(),
            "accepted a path past the step bound"
        );

        // Over the step bound but RESOLVING to something that exists, so a
        // bound that merely capped the walk would find it on the first probe
        // and accept.
        //
        // Unix-only because it needs `..` to SURVIVE absolutization. Windows's
        // `absolute` is `GetFullPathNameW`, which collapses dot-components
        // lexically, so the fixture would shrink to `<base>/a` and trip
        // neither bound. The mechanism is platform-independent; only this
        // spelling of an over-deep-but-present path is not.
        #[cfg(unix)]
        {
            std::fs::create_dir(base.path().join("a")).unwrap();
            let deep_but_present = base
                .path()
                .join(format!("{}a", "a/../".repeat(MAX_CLIMB_STEPS / 2 + 2)));
            assert!(
                fs::symlink_metadata(&deep_but_present).is_ok(),
                "fixture must exist, or it cannot tell the two bounds apart"
            );
            for dry_run in [true, false] {
                assert_root_past_bound(&deep_but_present, dry_run);
            }
        }
    }

    /// An `--output` past either bound is refused before anything is created,
    /// in both modes.
    #[test]
    fn an_output_root_past_either_bound_is_refused_before_anything_is_created() {
        let base = tempfile::tempdir().unwrap();
        let over_steps = base.path().join("d/".repeat(MAX_CLIMB_STEPS));
        assert!(over_steps.as_os_str().len() < MAX_CLIMB_PATH_BYTES);
        let over_bytes = chain_of_len(base.path(), MAX_CLIMB_PATH_BYTES + 1);
        assert!(over_bytes.components().count() < MAX_CLIMB_STEPS);

        for root in [&over_steps, &over_bytes] {
            for dry_run in [true, false] {
                assert_root_past_bound(root, dry_run);
                assert_eq!(std::fs::read_dir(base.path()).unwrap().count(), 0);
            }
        }
    }

    /// A relative root is charged its cwd, as an entry is. Reads the cwd
    /// rather than setting it, because `set_current_dir` is process-global and
    /// this suite runs in parallel. The step shape runs as a preview only: a
    /// regression would make a real run create it inside the source tree.
    #[test]
    fn a_relative_root_is_charged_its_cwd() {
        let cwd = std::env::current_dir().unwrap();

        let deep = PathBuf::from("d/".repeat(MAX_CLIMB_STEPS - cwd.components().count() + 1));
        assert_root_past_bound(&deep, true);

        let long = PathBuf::from("x".repeat(MAX_CLIMB_PATH_BYTES - cwd.as_os_str().len()));
        for dry_run in [true, false] {
            assert_root_past_bound(&long, dry_run);
        }
    }

    /// The guard climbs from the root `prepare` absolutized, not from each
    /// candidate absolutized again: pointed elsewhere, that root moves both
    /// the bound and the climb, while messages keep the caller's spelling.
    #[test]
    fn the_guard_climbs_from_the_root_prepare_absolutized() {
        let base = tempfile::tempdir().unwrap();
        let absent = base.path().join("absent");
        let preview = cfg(&absent, false, true, false);
        assert_eq!(preview.absolute_root, std::path::absolute(&absent).unwrap());
        let stray = base.path().join("elsewhere/x.bin");
        assert_eq!(
            verify_resolves_inside_root(&preview, &stray),
            Err(format!("{OUTSIDE_ROOT}: {}", stray.display()))
        );

        let dir = tempfile::tempdir().unwrap();
        let candidate = dir.path().join("x.bin");
        let deep = std::path::absolute(dir.path())
            .unwrap()
            .join("d/".repeat(MAX_CLIMB_STEPS));
        let mut c = cfg(dir.path(), false, false, false);
        c.absolute_root = deep;
        assert_eq!(
            write_output(&c, "x.bin", None, b"X"),
            Err(format!("{TooDeepOrLong}: {}", candidate.display()))
        );

        let elsewhere = tempfile::tempdir().unwrap();
        c.absolute_root = std::path::absolute(elsewhere.path()).unwrap();
        assert_eq!(
            write_output(&c, "x.bin", None, b"X"),
            Err(format!("{OUTSIDE_ROOT}: {}", candidate.display()))
        );
    }

    /// An empty root stays refused in both modes, rather than taken as the
    /// cwd. clap refuses `-o ""` before `prepare`; this is the layer below.
    #[test]
    fn an_empty_output_is_refused() {
        for dry_run in [true, false] {
            let err = try_cfg(Path::new(""), false, dry_run, false).err().unwrap();
            assert_eq!(err.kind(), ErrorKind::InvalidInput, "{err}");
        }
    }

    /// The root is absolutized the way the writes traverse it, as a segment
    /// with more below it. Windows trims trailing spaces and dots from a
    /// path's LAST segment, so on Windows absolutizing the root alone would
    /// store `out` for both of these.
    #[test]
    fn the_root_is_absolutized_as_the_writes_traverse_it() {
        let base = tempfile::tempdir().unwrap();
        for name in ["out ", "out.."] {
            let c = cfg(&base.path().join(name), false, true, false);
            assert_eq!(
                c.absolute_root.file_name(),
                Some(std::ffi::OsStr::new(name))
            );
        }
    }

    /// A root whose prefix would absorb the probe child is refused up front
    /// rather than classified as that child: on Windows `\\server\x` parses
    /// as a share. Preview only, since elsewhere it is an ordinary relative
    /// name.
    #[test]
    fn a_root_that_absorbs_the_probe_child_is_refused() {
        let root = Path::new(r"\\paksmith-no-such-server");
        let previewed = try_cfg(root, false, true, false);
        if cfg!(windows) {
            assert_eq!(
                previewed.err().map(|e| e.kind()),
                Some(ErrorKind::InvalidInput)
            );
        } else {
            assert!(previewed.is_ok());
        }
    }

    /// A bound trip and a failed walk are different causes and must read as
    /// different causes. "no resolvable ancestor" points at the output
    /// directory, whose remedies — recreate it, check the mount — are all
    /// wrong for a path that is merely too long, and nothing else in the CLI
    /// names the ceilings.
    #[test]
    fn a_bound_trip_does_not_read_as_a_missing_ancestor() {
        let base = tempfile::tempdir().unwrap();
        let c = cfg(base.path(), false, false, false);
        let entry = format!("{}x.bin", "d/".repeat(MAX_CLIMB_STEPS));

        let err = write_output(&c, &entry, None, b"X").unwrap_err();

        let candidate = (0..MAX_CLIMB_STEPS)
            .fold(base.path().to_path_buf(), |path, _| path.join("d"))
            .join("x.bin");
        assert_eq!(
            err,
            format!(
                "too deep or too long to check (max {MAX_CLIMB_STEPS} components, \
                 {MAX_CLIMB_PATH_BYTES} bytes): {}",
                candidate.display()
            )
        );
    }

    /// A relative root's candidate is named as spelled, with no cwd prefix.
    /// Preview only: the root sits exactly at the step bound once its cwd is
    /// charged, and a real run would create it inside the source tree.
    #[test]
    fn a_bound_trip_under_a_relative_root_names_the_candidate_as_spelled() {
        let cwd = std::env::current_dir().unwrap();
        let root = PathBuf::from("d/".repeat(MAX_CLIMB_STEPS - cwd.components().count()));
        let c = cfg(&root, false, true, false);

        let err = write_output(&c, "e/x.bin", None, b"X").unwrap_err();

        let candidate = c.output_dir().join("e").join("x.bin");
        assert_eq!(err, format!("{TooDeepOrLong}: {}", candidate.display()));
        assert!(!root.exists());
    }

    /// The bound refuses in BOTH modes. `--dry-run` against a root that does
    /// not exist is the one configuration with no root to compare against, so
    /// it is also the one where a guard gated on the comparison would let a
    /// bound-tripping entry through and preview a write the real run fails.
    #[test]
    fn dry_run_refuses_a_crafted_depth_against_an_absent_root() {
        let base = tempfile::tempdir().unwrap();
        let absent = base.path().join("fresh");
        let entry = format!("{}x.bin", "d/".repeat(MAX_CLIMB_STEPS));

        let preview = cfg(&absent, false, true, false);
        let err = write_output(&preview, &entry, None, b"X").unwrap_err();
        assert!(
            err.starts_with("too deep or too long"),
            "a preview must refuse what the run refuses: {err}"
        );
        assert!(
            !absent.exists(),
            "--dry-run created the root it only previewed"
        );

        let real = cfg(&absent, false, false, false);
        let real_err = write_output(&real, &entry, None, b"X").unwrap_err();
        assert!(
            real_err.starts_with("too deep or too long"),
            "the real run must refuse it too: {real_err}"
        );
    }

    /// The guard is armed by the path of `prepare` a fresh `-o dir` takes: the
    /// root is created and then resolved. Every planted-link fixture hands in
    /// a live `tempdir()`, which resolves through the EXISTING path, so `None`
    /// from the creating path — the guard switched off for the whole run — is
    /// observable only by planting the link after the config is built.
    #[cfg(unix)]
    #[test]
    fn a_root_created_by_the_run_still_arms_the_guard() {
        let base = tempfile::tempdir().unwrap();
        let victim = tempfile::tempdir().unwrap();
        let fresh = base.path().join("fresh");

        let c = cfg(&fresh, false, false, false);
        assert!(fresh.is_dir(), "the real run must create its root");
        std::os::unix::fs::symlink(victim.path(), fresh.join("sub")).unwrap();

        let err = write_output(&c, "sub/passwd", None, b"PWNED").unwrap_err();
        assert!(
            !victim.path().join("passwd").exists(),
            "write escaped through a root the run itself created: {err}"
        );
        assert!(
            err.contains("resolves outside the output directory"),
            "{err}"
        );
    }

    /// A root the run CREATES under a symlink is resolved, not merely
    /// absolutized: the write is accepted and lands in the link's target.
    #[cfg(unix)]
    #[test]
    fn a_root_created_under_a_symlink_is_written_through() {
        let base = tempfile::tempdir().unwrap();
        let real = base.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = base.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let fresh = link.join("fresh");

        let c = cfg(&fresh, false, false, false);
        let reported = write_output(&c, "sub/x.bin", None, b"X").unwrap();

        assert!(
            reported.starts_with(&fresh.display().to_string()),
            "reported path must keep the caller's spelling: {reported}"
        );
        assert_eq!(std::fs::read(real.join("fresh/sub/x.bin")).unwrap(), b"X");
    }

    /// A planted link whose OWN attributes cannot be read — an ACL on the link,
    /// which its owner can set without privilege — still resolves for `mkdir`
    /// and `open`. Its `lstat` failing must stop the climb, not step past it.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_link_that_hides_from_lstat_is_still_refused() {
        let root = tempfile::tempdir().unwrap();
        let victim = tempfile::tempdir().unwrap();
        let link = root.path().join("sub");
        std::os::unix::fs::symlink(victim.path(), &link).unwrap();
        let acl = std::process::Command::new("/bin/chmod")
            .args([
                "-h",
                "+a",
                "everyone deny readattr,readextattr,readsecurity",
            ])
            .arg(&link)
            .status()
            .unwrap();
        assert!(acl.success(), "fixture must set the ACL");
        assert!(
            std::fs::symlink_metadata(&link).is_err(),
            "fixture must hide the link from lstat"
        );

        for dry_run in [false, true] {
            let c = cfg(root.path(), false, dry_run, false);
            for entry in ["sub/x.bin", "sub/deep/x.bin"] {
                assert!(
                    write_output(&c, entry, None, b"PWNED").is_err(),
                    "dry_run={dry_run}: {entry} escaped through a link lstat cannot see"
                );
            }
        }
        let _ = std::process::Command::new("/bin/chmod")
            .args(["-h", "-N"])
            .arg(&link)
            .status();
        assert_eq!(
            std::fs::read_dir(victim.path()).unwrap().count(),
            0,
            "the victim directory was written to"
        );
    }

    /// A `..` after a component that does not exist is refused in both modes,
    /// before anything is created: POSIX resolves the missing component first,
    /// so `create_dir_all` would build it and the root would then name
    /// something that already existed. Unix-only, because Windows collapses
    /// `..` lexically before any of this runs.
    #[cfg(unix)]
    #[test]
    fn a_parent_dir_after_a_missing_component_is_refused() {
        let base = tempfile::tempdir().unwrap();
        let victim = tempfile::tempdir().unwrap();
        let existing = base.path().join("existing");
        std::fs::create_dir(&existing).unwrap();
        std::os::unix::fs::symlink(victim.path(), existing.join("sub")).unwrap();
        let as_file = base.path().join("afile");
        std::fs::write(&as_file, b"x").unwrap();

        for name in ["existing", "afile"] {
            let spelled = base.path().join("absent").join("..").join(name);
            let preview = try_cfg(&spelled, false, true, false)
                .err()
                .map(|e| e.kind());
            let real = try_cfg(&spelled, false, false, false)
                .err()
                .map(|e| e.kind());
            assert_eq!(
                preview,
                Some(ErrorKind::InvalidInput),
                "{name}: the preview accepted a root the run cannot use"
            );
            assert_eq!(real, preview, "{name}: the modes disagree");
            assert!(
                !base.path().join("absent").exists(),
                "{name}: a refused root left its missing component behind"
            );
        }

        // A `..` inside the EXISTING prefix resolves before anything is built.
        let fresh = base.path().join("existing").join("..").join("fresh");
        assert!(try_cfg(&fresh, false, true, false).is_ok());
        assert!(
            !base.path().join("fresh").exists(),
            "a preview created its root"
        );
        assert!(try_cfg(&fresh, false, false, false).is_ok());
        assert!(
            base.path().join("fresh").is_dir(),
            "the run did not create its root"
        );
    }

    /// A regular file where an entry needs a directory — its own parent or
    /// higher, directly or through a live link — is one refusal in both modes.
    #[cfg(unix)]
    #[test]
    fn a_parent_that_is_a_file_is_refused_in_both_modes() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("afile"), b"x").unwrap();
        std::os::unix::fs::symlink(root.path().join("afile"), root.path().join("lf")).unwrap();

        for dry_run in [true, false] {
            let c = cfg(root.path(), false, dry_run, false);
            for entry in [
                "afile/x.bin",
                "lf/x.bin",
                "afile/deep/x.bin",
                "lf/deep/x.bin",
            ] {
                let err = write_output(&c, entry, None, b"X").unwrap_err();
                assert!(
                    err.starts_with(NOT_A_DIRECTORY),
                    "dry_run={dry_run}: {entry}: {err}"
                );
            }
        }
    }

    /// A link inside the root that resolves INSIDE it is followed, absolute or
    /// relative, in both modes.
    #[cfg(unix)]
    #[test]
    fn an_intermediate_link_back_inside_the_root_is_written_through() {
        let root = tempfile::tempdir().unwrap();
        let real = root.path().join("b");
        std::fs::create_dir(&real).unwrap();
        std::os::unix::fs::symlink(&real, root.path().join("a")).unwrap();
        std::os::unix::fs::symlink("b", root.path().join("rel")).unwrap();

        for dry_run in [true, false] {
            let c = cfg(root.path(), false, dry_run, false);
            for entry in ["a/x.bin", "rel/y.bin"] {
                assert!(
                    write_output(&c, entry, None, b"X").is_ok(),
                    "dry_run={dry_run}: {entry} was refused"
                );
            }
        }
        assert_eq!(std::fs::read(real.join("x.bin")).unwrap(), b"X");
        assert_eq!(std::fs::read(real.join("y.bin")).unwrap(), b"X");
    }

    /// A root reached THROUGH a symlink is written through, not refused: the
    /// comparison is against the RESOLVED root.
    #[cfg(unix)]
    #[test]
    fn a_root_reached_through_a_symlink_is_written_through() {
        let base = tempfile::tempdir().unwrap();
        let real = base.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = base.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let c = cfg(&link, false, false, false);
        let reported = write_output(&c, "sub/x.bin", None, b"X").unwrap();

        assert!(
            reported.starts_with(&link.display().to_string()),
            "reported path must keep the caller's spelling: {reported}"
        );
        assert_eq!(std::fs::read(real.join("sub/x.bin")).unwrap(), b"X");
    }

    /// A regular file as the root or anywhere above it is refused with one
    /// diagnosis in both modes, whichever error the platform reports for it.
    #[test]
    fn a_file_is_not_a_directory_an_absent_root_can_sit_under() {
        let base = tempfile::tempdir().unwrap();
        let as_file = base.path().join("not-a-dir");
        std::fs::write(&as_file, b"x").unwrap();
        let expected = std::io::Error::from(ErrorKind::NotADirectory).to_string();

        for root in [
            as_file.clone(),
            as_file.join("out"),
            as_file.join("out/deeper"),
        ] {
            for dry_run in [true, false] {
                let err = try_cfg(&root, false, dry_run, false).err().unwrap();
                assert_eq!(
                    err.kind(),
                    ErrorKind::NotADirectory,
                    "{}: {err}",
                    root.display()
                );
                assert_eq!(err.to_string(), expected, "{}", root.display());
            }
        }
        assert!(
            try_cfg(&base.path().join("out"), false, true, false).is_ok(),
            "an absent root under a real directory must preview"
        );
    }

    /// The preview's notion of a usable root must match the real run's.
    /// `canonicalize` resolves a regular file happily where `create_dir_all`
    /// refuses it, and reports a DANGLING LINK as `NotFound` — which, taken
    /// as "absent", would leave the comparison empty and skip the guard for
    /// every entry in the run.
    #[cfg(unix)]
    #[test]
    fn dry_run_agrees_with_the_real_run_on_what_counts_as_a_root() {
        let base = tempfile::tempdir().unwrap();

        let as_file = base.path().join("not-a-dir");
        std::fs::write(&as_file, b"x").unwrap();

        let dangling = base.path().join("dangling");
        std::os::unix::fs::symlink(base.path().join("nowhere"), &dangling).unwrap();

        // A LIVE link to a directory above the root: `create_dir_all` follows
        // it, so the preview must too.
        let real_dir = base.path().join("real");
        std::fs::create_dir(&real_dir).unwrap();
        let linked_parent = base.path().join("linked");
        std::os::unix::fs::symlink(&real_dir, &linked_parent).unwrap();
        let under_live_link = linked_parent.join("fresh");

        let preview = try_cfg(&under_live_link, false, true, false);
        assert!(
            preview.is_ok(),
            "a root beneath a live symlinked directory must preview: {:?}",
            preview.err()
        );
        assert!(
            !under_live_link.exists(),
            "--dry-run created the root it only previewed"
        );

        // A dangling link ABOVE the root.
        let under_dangling = dangling.join("out");

        // A LOOP resolves to nothing while EXISTING, so `mkdir` alone would
        // answer the same `EEXIST` it gives for a live directory; the
        // classifier reports ELOOP.
        let looping = base.path().join("loop-a");
        let loop_b = base.path().join("loop-b");
        std::os::unix::fs::symlink(&loop_b, &looping).unwrap();
        std::os::unix::fs::symlink(&looping, &loop_b).unwrap();

        // A TRAILING SEPARATOR on the same dangling root: POSIX resolves
        // `foo/` through the link, so unstripped, the root would be judged on
        // the link's target rather than the link.
        let with_separator = std::path::PathBuf::from(format!("{}/", dangling.display()));

        for root in [
            &as_file,
            &dangling,
            &under_dangling,
            &looping,
            &with_separator,
        ] {
            let preview = try_cfg(root, false, true, false);
            let real = try_cfg(root, false, false, false);
            assert!(
                real.is_err(),
                "{} is not a usable root for the real run",
                root.display()
            );
            assert!(
                preview.is_err(),
                "{} previewed as usable while the real run refuses it",
                root.display()
            );
            // Agreeing on the verdict is not enough: the raw `EEXIST` that
            // `create_dir_all` alone would surface reads as benign.
            assert_eq!(
                real.err().unwrap().kind(),
                preview.err().unwrap().kind(),
                "{} is diagnosed differently by the two modes",
                root.display()
            );
        }

        // A loop is reported as a loop, not as an absent or dangling root.
        let loop_err = try_cfg(&looping, false, false, false).err().unwrap();
        assert_ne!(loop_err.kind(), ErrorKind::NotFound, "{loop_err}");
        assert!(!loop_err.to_string().contains(DANGLING_LINK), "{loop_err}");
    }

    /// An absent root under an UNWRITABLE directory is a genuine `mkdir`
    /// failure, not a broken chain. Reporting what `canonicalize` said would
    /// recast "Permission denied" as "No such file or directory" — the modes
    /// already disagree on the VERDICT here, since the probe consults no
    /// permissions, and the real run's own diagnosis is all the user gets.
    #[cfg(unix)]
    #[test]
    fn an_unwritable_parent_keeps_its_own_error() {
        use std::os::unix::fs::PermissionsExt;
        let base = tempfile::tempdir().unwrap();
        let ro = base.path().join("ro");
        std::fs::create_dir(&ro).unwrap();
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o555)).unwrap();

        let err = try_cfg(&ro.join("fresh"), false, false, false)
            .err()
            .expect("an unwritable parent cannot hold a new root");
        // Restore perms so the tempdir can be cleaned up.
        let _ = std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o755));

        assert_eq!(
            err.kind(),
            ErrorKind::PermissionDenied,
            "a permission failure was recast: {err}"
        );
    }

    /// A root that EXISTS but cannot be resolved fails in both modes rather
    /// than silently disabling the guard for the whole run.
    #[cfg(unix)]
    #[test]
    fn dry_run_rejects_a_root_that_exists_but_cannot_be_resolved() {
        use std::os::unix::fs::PermissionsExt;
        let base = tempfile::tempdir().unwrap();
        let sealed = base.path().join("sealed");
        let root = sealed.join("out");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o000)).unwrap();

        let built = try_cfg(&root, false, true, false);
        std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o755)).unwrap();

        let err = built.err().expect("an unresolvable root must not preview");
        assert_ne!(
            err.kind(),
            ErrorKind::NotFound,
            "only an ABSENT root may yield the empty comparison: {err}"
        );
    }

    /// A `..` after a regular file names nothing the kernel will traverse,
    /// though darwin's `realpath` pops it anyway.
    #[cfg(unix)]
    #[test]
    fn a_parent_dir_after_a_regular_file_is_not_a_root() {
        let base = tempfile::tempdir().unwrap();
        std::fs::write(base.path().join("afile"), b"x").unwrap();

        for dry_run in [true, false] {
            let err = try_cfg(&base.path().join("afile/.."), false, dry_run, false)
                .err()
                .unwrap();
            assert_eq!(
                err.kind(),
                ErrorKind::NotADirectory,
                "dry_run={dry_run}: {err}"
            );
        }
    }

    /// The preview reaches the same CONTAINMENT verdict as the run it
    /// previews. Other write failures, such as an existing output, are only
    /// discovered by the real run.
    #[cfg(unix)]
    #[test]
    fn dry_run_reaches_the_real_runs_containment_verdict() {
        let root = tempfile::tempdir().unwrap();
        let victim = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(victim.path(), root.path().join("sub")).unwrap();

        let real = cfg(root.path(), false, false, false);
        let real_err = write_output(&real, "sub/x.bin", None, b"PWNED").unwrap_err();

        let preview = cfg(root.path(), false, true, false);
        let preview_err = write_output(&preview, "sub/x.bin", None, b"PWNED").unwrap_err();

        assert!(
            real_err.contains("resolves outside the output directory"),
            "{real_err}"
        );
        assert_eq!(
            preview_err, real_err,
            "--dry-run must reach the same verdict as the run it previews"
        );
        // The CALLER's spelling: on macOS `tempdir()` is `/var/...` while its
        // resolution is `/private/var/...`.
        assert!(
            real_err.contains(&root.path().display().to_string()),
            "the rejection must name the root as the caller spelled it: {real_err}"
        );
        assert!(!victim.path().join("x.bin").exists());
    }

    /// A DANGLING intermediate link: the walk must not follow links, and a
    /// resolve failure must reject rather than skip — in the guard, not
    /// downstream in `create_dir_all`.
    #[cfg(unix)]
    #[test]
    fn a_dangling_intermediate_link_is_rejected_by_the_guard() {
        let root = tempfile::tempdir().unwrap();
        let victim = tempfile::tempdir().unwrap();
        // Target deliberately never created.
        std::os::unix::fs::symlink(victim.path().join("ghost"), root.path().join("d")).unwrap();

        let c = cfg(root.path(), false, false, false);
        let err = write_output(&c, "d/x.bin", None, b"PWNED").unwrap_err();

        assert!(
            err.starts_with(DANGLING_LINK),
            "must fail closed in the guard, naming the dangling link: {err}"
        );
        // Names the CANDIDATE, not the ancestor the climb stopped on: that
        // ancestor is `root/d`, so reporting it drops the leaf and hands the
        // user a path they cannot find in the archive.
        assert!(
            err.contains("x.bin"),
            "the rejection must name the entry, not the ancestor: {err}"
        );
        assert!(!victim.path().join("ghost").exists(), "{err}");
    }

    /// The guard must run BEFORE `create_dir_all`, because creating
    /// directories outside the root is part of the vulnerability and not a
    /// precursor to it.
    ///
    /// A missing intermediate beneath the link gives `create_dir_all` work to
    /// do, so a DIRECTORY outside the root is what a late check would leave.
    #[cfg(unix)]
    #[test]
    fn nothing_is_created_outside_the_root_before_the_check_runs() {
        let root = tempfile::tempdir().unwrap();
        let victim = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(victim.path(), root.path().join("sub")).unwrap();

        // Default flags: this vector needs no --overwrite.
        let c = cfg(root.path(), false, false, false);
        let err = write_output(&c, "sub/deep/nested/x.bin", None, b"PWNED").unwrap_err();

        assert!(
            !victim.path().join("deep").exists(),
            "create_dir_all ran before the containment check: {err}"
        );
        assert!(
            err.contains("resolves outside the output directory"),
            "{err}"
        );
    }

    /// Containment is a property of the directory the write happens IN, so the
    /// guard must resolve the parent chain and not the leaf. A leaf link aimed
    /// back INSIDE the root satisfies a leaf-anchored check while an escaping
    /// component above it goes unexamined, and the write then follows the
    /// unresolved chain out of the root.
    #[cfg(unix)]
    #[test]
    fn an_escaping_parent_is_caught_even_when_the_leaf_points_back_inside() {
        let root = tempfile::tempdir().unwrap();
        let evil = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(evil.path(), root.path().join("sub")).unwrap();
        std::os::unix::fs::symlink(root.path(), evil.path().join("leaf.bin")).unwrap();

        let c = cfg(root.path(), false, false, true);
        let err = write_output(&c, "sub/leaf.bin", None, b"PWNED").unwrap_err();

        assert!(
            std::fs::symlink_metadata(evil.path().join("leaf.bin"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "write escaped the root: evil/leaf.bin became a regular file"
        );
        assert!(
            err.contains("resolves outside the output directory"),
            "{err}"
        );
    }

    /// `rename` needs write permission on the PARENT, not on the file: a
    /// destination inside a writable, non-sticky directory is replaced
    /// whatever its own mode, and one inside an unwritable directory is
    /// refused.
    #[cfg(unix)]
    #[test]
    fn overwrite_follows_the_parent_directory_permission_not_the_file() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();

        // Unwritable destination inside a writable root: replaced.
        let unwritable = root.path().join("locked.bin");
        std::fs::write(&unwritable, b"ORIGINAL").unwrap();
        std::fs::set_permissions(&unwritable, std::fs::Permissions::from_mode(0o000)).unwrap();
        let c = cfg(root.path(), false, false, true);
        let _reported = write_output(&c, "locked.bin", None, b"NEW").unwrap();
        std::fs::set_permissions(&unwritable, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(std::fs::read(&unwritable).unwrap(), b"NEW");

        // Writable destination inside an unwritable directory: refused.
        let sealed = root.path().join("sealed");
        std::fs::create_dir(&sealed).unwrap();
        let inside = sealed.join("x.bin");
        std::fs::write(&inside, b"ORIGINAL").unwrap();
        std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o555)).unwrap();
        let err = write_output(&c, "sealed/x.bin", None, b"NEW").unwrap_err();
        std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            err.starts_with("create temp beside "),
            "expected a temp-create failure: {err}"
        );
        assert_eq!(std::fs::read(&inside).unwrap(), b"ORIGINAL");
    }

    /// Replacing the destination hands it a fresh inode, so its access bits
    /// have to be carried across explicitly.
    #[cfg(unix)]
    #[test]
    fn overwrite_preserves_the_destination_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let dest = root.path().join("shared.bin");
        std::fs::write(&dest, b"ORIGINAL").unwrap();
        // GROUP-WRITABLE on purpose. `open` applies the umask to the creation
        // mode, so the settle afterwards is what restores whatever the umask
        // stripped — and at the usual 022 a destination with no group-write
        // bit loses nothing, leaving the settle invisible. 0o666 is the
        // narrowest fixture that separates carrying from not carrying here.
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o666)).unwrap();

        let c = cfg(root.path(), false, false, true);
        let _reported = write_output(&c, "shared.bin", None, b"NEW").unwrap();

        assert_eq!(
            std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777,
            0o666,
            "--overwrite did not carry the destination's mode"
        );
        assert_eq!(std::fs::read(&dest).unwrap(), b"NEW");
    }

    /// `--flat --overwrite` is documented to resolve collisions
    /// last-writer-wins, so every entry targeting one path must succeed. An
    /// unlink-then-create pair would fail whichever racer lost; a rename is a
    /// single atomic replace and cannot.
    ///
    /// Unix-gated: atomic replace-existing is a POSIX `rename(2)` property.
    /// Windows goes through `MoveFileExW`, which must open the destination and
    /// can lose a concurrent replace to a sharing violation — surfacing as a
    /// per-entry failure rather than a wrong write, but not the guarantee this
    /// asserts.
    #[cfg(unix)]
    #[test]
    fn overwrite_lets_repeated_writes_to_one_path_all_succeed() {
        let root = tempfile::tempdir().unwrap();
        let c = cfg(root.path(), true, false, true);

        // Concurrent, because a serial loop cannot distinguish an atomic
        // replace from an unlink-then-create pair: the losing racer is the
        // only observable difference, and a serial loop has no racer.
        std::thread::scope(|scope| {
            for i in 0..8u8 {
                let c = &c;
                let _handle = scope.spawn(move || {
                    // Multi-byte and uniform, so an interleaved write is
                    // observable — a one-byte payload cannot tear, and that
                    // assertion would hold for any implementation.
                    let payload = vec![i; 4096];
                    let reported = write_output(c, &format!("dir{i}/same.bin"), None, &payload)
                        .unwrap_or_else(|e| panic!("write {i} must not collide: {e}"));
                    assert!(
                        reported.ends_with("same.bin"),
                        "--flat collapses to the basename"
                    );
                });
            }
        });

        let landed = std::fs::read(root.path().join("same.bin")).unwrap();
        assert_eq!(landed.len(), 4096, "one writer's payload landed whole");
        assert!(
            landed.iter().all(|b| *b == landed[0]),
            "the file interleaves two writers' payloads"
        );
        let names: Vec<_> = std::fs::read_dir(root.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, ["same.bin"]);
    }

    /// A failed rename is reported as the replace it was. A directory
    /// destination fails it here; `write_output` refuses one up front.
    #[test]
    fn a_failed_rename_is_reported_as_a_replace() {
        let root = tempfile::tempdir().unwrap();
        let dest = root.path().join("blocked.bin");
        std::fs::create_dir(&dest).unwrap();

        let err = replace_via_temp(&dest, "blocked.bin", b"PAYLOAD").unwrap_err();

        assert!(
            err.starts_with("replace blocked.bin: "),
            "expected a rename failure: {err}"
        );
    }

    #[test]
    fn each_replace_step_keeps_its_wording() {
        let boom = || std::io::Error::other("boom");
        assert_eq!(
            [
                StagedReplaceError::CreateTemp(boom()),
                StagedReplaceError::PreservePermissions(boom()),
                StagedReplaceError::Replace(boom()),
            ]
            .map(|e| replace_failure("out/x.bin", e)),
            [
                "create temp beside out/x.bin: boom",
                "preserve permissions of out/x.bin: boom",
                "replace out/x.bin: boom",
            ]
        );
    }

    /// A directory destination is refused up front in both write modes: the
    /// default mode does not suggest `--overwrite`, and `--overwrite` does not
    /// stage a payload only to throw it away.
    #[test]
    fn a_directory_destination_is_refused_up_front() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("blocked.bin")).unwrap();

        for overwrite in [false, true] {
            let c = cfg(root.path(), false, false, overwrite);
            let err = write_output(&c, "blocked.bin", None, b"PAYLOAD").unwrap_err();
            assert!(
                err.starts_with("output is a directory: "),
                "overwrite={overwrite}: {err}"
            );
        }
    }

    /// The directory refusal reads the leaf itself, not what a link there
    /// points at: a link to a directory is replaced under `--overwrite`, and
    /// the directory is left alone.
    #[cfg(unix)]
    #[test]
    fn a_leaf_link_to_a_directory_is_replaced_not_refused() {
        let root = tempfile::tempdir().unwrap();
        let victim = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(victim.path(), root.path().join("leaf.bin")).unwrap();

        let c = cfg(root.path(), false, false, true);
        let _reported = write_output(&c, "leaf.bin", None, b"PAYLOAD").unwrap();

        assert_eq!(
            std::fs::read(root.path().join("leaf.bin")).unwrap(),
            b"PAYLOAD"
        );
        assert_eq!(std::fs::read_dir(victim.path()).unwrap().count(), 0);
    }

    /// A socket at the destination is refused and left in place, or under
    /// `--overwrite` replaced by a regular file. Rooted in `/tmp` so the bind
    /// path fits `sun_path`.
    #[cfg(unix)]
    #[test]
    fn a_socket_destination_is_refused_or_replaced() {
        use std::os::unix::fs::FileTypeExt;

        let root = tempfile::tempdir_in("/tmp").unwrap();
        let leaf = root.path().join("s.bin");
        let _listener = std::os::unix::net::UnixListener::bind(&leaf).unwrap();

        let refused = cfg(root.path(), false, false, false);
        let err = write_output(&refused, "s.bin", None, b"PAYLOAD").unwrap_err();
        assert!(
            err.starts_with("output exists (use --overwrite): "),
            "{err}"
        );
        assert!(
            std::fs::symlink_metadata(&leaf)
                .unwrap()
                .file_type()
                .is_socket()
        );

        let replacing = cfg(root.path(), false, false, true);
        let _reported = write_output(&replacing, "s.bin", None, b"PAYLOAD").unwrap();
        assert_eq!(std::fs::read(&leaf).unwrap(), b"PAYLOAD");
    }

    /// Only an OCCUPIED destination goes to the replace. Any other open failure
    /// is reported as the create it was, not as a temp or rename failure.
    #[test]
    fn overwrite_reports_a_non_collision_create_failure_as_a_create() {
        let root = tempfile::tempdir().unwrap();
        let c = cfg(root.path(), false, false, true);

        let err = write_output(&c, &"n".repeat(300), None, b"X").unwrap_err();

        assert!(
            err.starts_with("create "),
            "expected a create failure: {err}"
        );
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
