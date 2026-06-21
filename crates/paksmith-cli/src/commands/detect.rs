//! `detect_matches` helper + `paksmith profile detect <dir>` handler.

use std::path::Path;

use paksmith_core::ProfileStore;
use paksmith_core::profile::detection::rules_match;

use crate::commands::key_resolve::load_cache_lenient;

/// One profile that matched a directory scan.
pub(crate) struct DetectMatch {
    /// Profile id.
    pub id: String,
    /// Human-readable display name.
    pub name: String,
    /// Where the profile came from: `"local"` or `"registry"`.
    pub source: &'static str,
}

/// Detect which stored/cached profiles match `dir`.
///
/// Local profiles are always emitted first. A cached registry entry with the
/// same id as a local profile is skipped — the local entry shadows it whether
/// or not it matched. Only profiles that carry detect rules can match.
pub(crate) fn detect_matches(dir: &Path) -> paksmith_core::Result<Vec<DetectMatch>> {
    let store = ProfileStore::load()?;
    let cache = load_cache_lenient();
    let mut out = Vec::new();

    // Pass 1: local profiles (always shadow registry entries of the same id).
    for (id, p) in &store.profiles {
        let Some(rules) = &p.detect else { continue };
        if rules_match(dir, rules) {
            out.push(DetectMatch {
                id: id.clone(),
                name: p.name.clone(),
                source: "local",
            });
        }
    }

    // Pass 2: cached registry profiles not shadowed by a local id.
    let Some(c) = &cache else { return Ok(out) };
    for p in &c.doc.profiles {
        if store.profiles.contains_key(&p.id) {
            continue; // local entry (match or no-match) shadows the cached one
        }
        let Some(rules) = &p.detect else { continue };
        if rules_match(dir, rules) {
            out.push(DetectMatch {
                id: p.id.clone(),
                name: p.name.clone(),
                source: "registry",
            });
        }
    }

    Ok(out)
}

/// `paksmith profile detect <dir>` — list every matching profile (0/1/many).
///
/// A directory with no matching profiles is not an error; it exits 0 with an
/// informational message. A directory with one or more matches prints a summary.
pub(crate) fn run(dir: &Path) -> paksmith_core::Result<u8> {
    let matches = detect_matches(dir)?;
    if matches.is_empty() {
        println!("no profiles matched {}", dir.display());
        return Ok(0);
    }
    println!("matched {} profile(s):", matches.len());
    for m in &matches {
        println!("  {}\t{}\t[{}]", m.id, m.name, m.source);
    }
    Ok(0)
}
