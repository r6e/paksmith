//! `paksmith profile detect <dir>` handler.

use std::path::Path;

use paksmith_core::profile::resolve::detect_matches;

/// `paksmith profile detect <dir>` — list every matching profile (0/1/many).
///
/// A directory with no matching profiles is not an error; it exits 0 with an
/// informational message. A directory with one or more matches prints a summary.
pub(crate) fn run(dir: &Path) -> paksmith_core::Result<u8> {
    if !dir.is_dir() {
        return Err(paksmith_core::PaksmithError::InvalidArgument {
            arg: "<DIR>",
            reason: format!("not a directory: {}", dir.display()),
        });
    }
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
