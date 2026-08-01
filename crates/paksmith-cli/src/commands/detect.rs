//! `paksmith profile detect <dir>` handler.

use std::io::{self, Write};
use std::path::Path;

use serde::Serialize;

use paksmith_core::profile::resolve::detect_matches;

/// Own `schema_version`: the repo shares one only when the SHAPE is shared
/// (`list`/`search` both emit `EntryRow`); `detect`'s document matches no
/// other surface, so coupling it would make consumers re-check on unrelated
/// changes.
const DETECT_SCHEMA_VERSION: u32 = 1;

#[derive(Serialize)]
struct DetectOutput {
    schema_version: u32,
    dir: String,
    matches: Vec<DetectRow>,
}

#[derive(Serialize)]
struct DetectRow {
    id: String,
    name: String,
    source: &'static str,
}

/// `paksmith profile detect <dir>` — list every matching profile (0/1/many).
///
/// A directory with no matching profiles is not an error; it exits 0 with an
/// informational message. A directory with one or more matches prints a summary.
pub(crate) fn run(dir: &Path, fmt: crate::output::ResolvedFormat) -> paksmith_core::Result<u8> {
    if !dir.is_dir() {
        return Err(paksmith_core::PaksmithError::InvalidArgument {
            arg: "<DIR>",
            reason: format!("not a directory: {}", dir.display()),
        });
    }
    let matches = detect_matches(dir)?;
    if matches!(fmt, crate::output::ResolvedFormat::Json) {
        // An empty match set is NOT an error here (see the doc above), so it
        // emits the same envelope with an empty array rather than a message.
        let out = DetectOutput {
            schema_version: DETECT_SCHEMA_VERSION,
            dir: dir.display().to_string(),
            matches: matches
                .iter()
                .map(|m| DetectRow {
                    id: m.id.clone(),
                    name: m.name.clone(),
                    source: m.source,
                })
                .collect(),
        };
        crate::output::print_json(&out)?;
        return Ok(0);
    }
    if matches.is_empty() {
        crate::output::print_line(&format!("no profiles matched {}", dir.display()))?;
        return Ok(0);
    }
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    writeln!(out, "matched {} profile(s):", matches.len())?;
    for m in &matches {
        writeln!(out, "  {}\t{}\t[{}]", m.id, m.name, m.source)?;
    }
    out.flush()?;
    Ok(0)
}
