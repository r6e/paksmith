//! `paksmith profile detect <dir>` handler.

use std::path::Path;

use serde::Serialize;

use paksmith_core::profile::resolve::detect_matches;

/// Own `schema_version`: `detect` returns a different document from `list`,
/// and the repo versions each JSON surface separately (`inspect/mod.rs`).
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
        println!(
            "{}",
            serde_json::to_string_pretty(&out).map_err(|e| {
                paksmith_core::PaksmithError::InvalidArgument {
                    arg: "--format",
                    reason: format!("could not serialize JSON output: {e}"),
                }
            })?
        );
        return Ok(0);
    }
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
