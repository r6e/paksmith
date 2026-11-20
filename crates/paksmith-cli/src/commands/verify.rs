//! `paksmith verify [<path>...]` — hash-check archives and report, per
//! archive, what was checked.

use std::io::{self, Write};
use std::path::PathBuf;

use clap::Args;
use serde::Serialize;

use paksmith_core::container::{IntegritySurvey, RegionVerifyState, VerifyStats};
use paksmith_core::error::ProfileFault;
use paksmith_core::{AesKey, PaksmithError};

use crate::output::{OutputFormat, ResolvedFormat, sanitize_for_display};

/// `verify` JSON schema version. Bump on a breaking change to the
/// document.
const VERIFY_SCHEMA_VERSION: u32 = 1;

/// The `error` of an archive whose reader has no verify.
const NO_VERIFY: &str = "this archive's reader can't verify it";

#[derive(Args)]
pub(crate) struct VerifyArgs {
    /// Paths to .pak files. Optional when `--game`/`--detect` selects a
    /// profile with `pak_paths` patterns — then every matching archive
    /// is reported.
    pub(crate) paths: Vec<PathBuf>,
}

pub(crate) fn run(
    args: &VerifyArgs,
    format: OutputFormat,
    aes_key: Option<&AesKey>,
    game: Option<&str>,
    detect: Option<&std::path::Path>,
    quiet: bool,
) -> paksmith_core::Result<u8> {
    let sources = if args.paths.is_empty() {
        crate::profile_paks::resolve_pak_sources(None, game, detect)?
    } else {
        args.paths.clone()
    };
    // Every key is looked up before any archive is verified, so a fault
    // that fails the run does so with nothing verified.
    let keyed = sources
        .into_iter()
        .map(|path| {
            match crate::commands::key_resolve::resolve_pak_key(&path, aes_key, game, detect) {
                Err(e) if fails_the_run(&e) => Err(e),
                key => Ok((path, key)),
            }
        })
        .collect::<paksmith_core::Result<Vec<_>>>()?;
    let reports: Vec<_> = keyed
        .into_iter()
        .map(|(path, key)| verify_one(path, key))
        .collect();
    print(&reports, format.resolve_with_notice(quiet))?;
    Ok(highest_exit_code(&reports))
}

/// Whether a key lookup's failure fails the run, as it does for `list`,
/// rather than the one archive. A selector or profile fault, such as an
/// unknown `--game`, a `--detect` dir no profile matches, or a profile
/// store that won't load, is every archive's. A footer that can't be read,
/// which the lookup reads under `--game`/`--detect` without `--aes-key`,
/// or a profile with no key for the archive's GUID, is that archive's.
fn fails_the_run(error: &PaksmithError) -> bool {
    match error {
        PaksmithError::Profile {
            fault: ProfileFault::NoKeyForGuid { .. },
        } => false,
        PaksmithError::Profile { .. } | PaksmithError::InvalidArgument { .. } => true,
        _ => false,
    }
}

/// One archive's outcome.
struct ArchiveReport {
    path: PathBuf,
    /// The survey of its entries, folded without a verify; `None` when
    /// it didn't open.
    integrity: Option<IntegritySurvey>,
    verified: Result<VerifyStats, Failure>,
}

/// Why an archive isn't ok, and its exit code.
struct Failure {
    code: u8,
    error: String,
}

/// Open the archive at `path` with its looked-up `key` and verify it. A
/// failure, the key lookup's included, is reported, not returned, so the
/// run goes on to the next archive.
fn verify_one(path: PathBuf, key: paksmith_core::Result<Option<AesKey>>) -> ArchiveReport {
    let opened = key.and_then(|key| paksmith_core::container::open(&path, key.as_ref()));
    let (integrity, verified) = match opened {
        Ok(reader) => (
            Some(
                reader
                    .entries()
                    .map(|meta| reader.entry_integrity(&meta))
                    .collect(),
            ),
            judge(reader.verify_archive()),
        ),
        Err(e) => (None, Err(Failure::unverifiable(e.to_string()))),
    };
    ArchiveReport {
        path,
        integrity,
        verified,
    }
}

impl Failure {
    /// Exit 2: the archive couldn't be opened or verified.
    fn unverifiable(error: String) -> Self {
        Self { code: 2, error }
    }
}

/// A verify's result as the report shows it. Only a hash that didn't
/// match, or was zeroed in an archive whose index is hashed, exits 1.
fn judge(verified: paksmith_core::Result<Option<VerifyStats>>) -> Result<VerifyStats, Failure> {
    match verified {
        Ok(Some(stats)) => Ok(stats),
        Ok(None) => Err(Failure::unverifiable(NO_VERIFY.to_owned())),
        Err(e @ (PaksmithError::HashMismatch { .. } | PaksmithError::IntegrityStripped { .. })) => {
            Err(Failure {
                code: 1,
                error: e.to_string(),
            })
        }
        Err(e) => Err(Failure::unverifiable(e.to_string())),
    }
}

impl ArchiveReport {
    /// The archive's exit code: 0 when it verified, else its failure's.
    fn code(&self) -> u8 {
        self.verified.as_ref().map_or_else(|f| f.code, |_| 0)
    }
}

/// The highest exit code any archive produced.
fn highest_exit_code(reports: &[ArchiveReport]) -> u8 {
    reports.iter().map(ArchiveReport::code).max().unwrap_or(0)
}

/// The `{"schema_version": 1, "archives": [...]}` document.
/// `schema_version` is declared first so serde emits it first.
#[derive(Serialize)]
struct VerifyOutput {
    schema_version: u32,
    archives: Vec<ArchiveJson>,
}

/// One archive's object. `archive` is its path, and `code` its own exit
/// code. `index`, `counts` and `fully_verified` are present only when it
/// verified, `integrity` whenever it opened, and `error` whenever `ok` is
/// false.
#[derive(Serialize)]
struct ArchiveJson {
    archive: String,
    ok: bool,
    code: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    index: Option<IndexJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    counts: Option<CountsJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    integrity: Option<IntegrityJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fully_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct IndexJson {
    main: &'static str,
    fdi: &'static str,
    phi: &'static str,
}

#[derive(Serialize)]
struct CountsJson {
    verified: usize,
    skipped_no_hash: usize,
}

#[derive(Serialize)]
struct IntegrityJson {
    claim: usize,
    not_in_index: usize,
    no_claim: usize,
    stripped: usize,
    mixes_hash_presence: bool,
}

impl ArchiveJson {
    fn new(report: &ArchiveReport) -> Self {
        let stats = report.verified.as_ref().ok();
        Self {
            archive: report.path.display().to_string(),
            ok: stats.is_some(),
            code: report.code(),
            index: stats.map(|s| IndexJson {
                main: region_token(main_index_state(s)),
                fdi: region_token(s.fdi()),
                phi: region_token(s.phi()),
            }),
            counts: stats.map(|s| CountsJson {
                verified: s.entries_verified(),
                skipped_no_hash: s.entries_skipped_no_hash(),
            }),
            integrity: report.integrity.map(|i| IntegrityJson {
                claim: i.claim(),
                not_in_index: i.not_in_index(),
                no_claim: i.no_claim(),
                stripped: i.stripped(),
                mixes_hash_presence: i.mixes_hash_presence(),
            }),
            fully_verified: stats.map(VerifyStats::is_fully_verified),
            error: report.verified.as_ref().err().map(|f| f.error.clone()),
        }
    }
}

/// The main index's state in [`RegionVerifyState`]'s terms. A report
/// whose index was neither hashed nor skipped, which pak's verify never
/// returns, reads as not present.
fn main_index_state(stats: &VerifyStats) -> RegionVerifyState {
    if stats.index_verified() {
        RegionVerifyState::Verified
    } else if stats.index_skipped_no_hash() {
        RegionVerifyState::SkippedNoHash
    } else {
        RegionVerifyState::NotPresent
    }
}

/// A region state's wire token.
fn region_token(state: RegionVerifyState) -> &'static str {
    match state {
        RegionVerifyState::Verified => "verified",
        RegionVerifyState::SkippedNoHash => "skipped_no_hash",
        RegionVerifyState::NotPresent => "not_present",
        _ => "unknown",
    }
}

fn print(reports: &[ArchiveReport], format: ResolvedFormat) -> io::Result<()> {
    if matches!(format, ResolvedFormat::Json) {
        return crate::output::print_json(&VerifyOutput {
            schema_version: VERIFY_SCHEMA_VERSION,
            archives: reports.iter().map(ArchiveJson::new).collect(),
        });
    }
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    out.write_all(render_table(reports).as_bytes())?;
    out.flush()
}

/// One line per archive.
fn render_table(reports: &[ArchiveReport]) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for report in reports {
        let path = report.path.display().to_string();
        let _ = writeln!(out, "{}: {}", sanitize_for_display(&path), summary(report));
    }
    out
}

/// What a table line says after the archive's path: whether it verified,
/// and fully, or why it failed. The JSON document has the counts.
fn summary(report: &ArchiveReport) -> String {
    match &report.verified {
        Ok(stats) if stats.is_fully_verified() => "ok, fully verified".to_owned(),
        Ok(_) => "ok, not fully verified".to_owned(),
        Err(failure) => format!("failed: {}", sanitize_for_display(&failure.error)),
    }
}

#[cfg(test)]
mod tests {
    use paksmith_core::error::HashTarget;

    use super::*;

    /// A verify that returned no report, or failed other than on a hash,
    /// exits 2, and only a hash that didn't match or was zeroed exits 1.
    #[test]
    fn judge_ranks_a_failed_hash_below_an_unverifiable_archive() {
        let mismatch = || PaksmithError::HashMismatch {
            target: HashTarget::Index,
            expected: "e".to_owned(),
            actual: "a".to_owned(),
        };
        let stripped = || PaksmithError::IntegrityStripped {
            target: HashTarget::Index,
        };
        let other = || PaksmithError::InvalidArgument {
            arg: "x",
            reason: "y".to_owned(),
        };
        assert!(judge(Ok(Some(VerifyStats::default()))).is_ok());
        for (verified, code, error) in [
            (Ok(None), 2, NO_VERIFY.to_owned()),
            (Err(other()), 2, other().to_string()),
            (Err(mismatch()), 1, mismatch().to_string()),
            (Err(stripped()), 1, stripped().to_string()),
        ] {
            let failure = judge(verified).err().unwrap();
            assert_eq!((failure.code, failure.error), (code, error));
        }
    }

    #[test]
    fn the_exit_code_is_the_highest_any_archive_produced() {
        let report = |verified| ArchiveReport {
            path: PathBuf::new(),
            integrity: None,
            verified,
        };
        let failed = |code| {
            report(Err(Failure {
                code,
                error: String::new(),
            }))
        };
        let ok = || report(Ok(VerifyStats::default()));
        assert_eq!(highest_exit_code(&[ok(), failed(2), failed(1)]), 2);
        assert_eq!(highest_exit_code(&[failed(1), ok()]), 1);
        assert_eq!(highest_exit_code(&[ok()]), 0);
        assert_eq!(highest_exit_code(&[]), 0);
    }

    /// A selector or profile fault fails the run. Reading the archive's
    /// footer, or a profile with no key for its GUID, fails that archive.
    #[test]
    fn only_a_selector_or_profile_fault_fails_the_run() {
        use paksmith_core::error::{InvalidFooterFault, ProfileFault};

        let profile = |fault| PaksmithError::Profile { fault };
        let id = || "hero".to_owned();
        assert!(fails_the_run(&profile(ProfileFault::ProfileNotFound {
            id: id()
        })));
        assert!(fails_the_run(&PaksmithError::InvalidArgument {
            arg: "--detect",
            reason: String::new(),
        }));
        assert!(!fails_the_run(&profile(ProfileFault::NoKeyForGuid {
            id: id(),
            guid: String::new(),
        })));
        assert!(!fails_the_run(&PaksmithError::InvalidFooter {
            fault: InvalidFooterFault::OtherUnpromoted {
                reason: String::new(),
            },
        }));
        assert!(!fails_the_run(&PaksmithError::Io(std::io::Error::other(
            "x"
        ))));
    }

    /// Each region state has its own token, and a report whose main index
    /// was neither hashed nor skipped reads as not present.
    #[test]
    fn region_tokens() {
        assert_eq!(region_token(RegionVerifyState::Verified), "verified");
        assert_eq!(
            region_token(RegionVerifyState::SkippedNoHash),
            "skipped_no_hash"
        );
        assert_eq!(region_token(RegionVerifyState::NotPresent), "not_present");
        assert_eq!(
            main_index_state(&VerifyStats::default()),
            RegionVerifyState::NotPresent
        );
    }
}
