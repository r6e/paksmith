//! `inspect` output assembly: selection and format dispatch.
//!
//! Owns the emit path for `paksmith inspect` output. Phase 4b Task 1
//! contains only a thin delegation wrapper producing byte-identical output
//! to the former inline serializer in `commands/inspect.rs`. Tasks 2–5
//! layer in a versioned JSON wrapper, field selection, and the table
//! renderer.

use std::io::{self, Write};

use serde::Serialize;

use paksmith_core::asset::Package;

use crate::commands::inspect::InspectArgs;
use crate::output::{OutputFormat, serde_json_to_io};

/// Schema version emitted as the first key of every `paksmith inspect` JSON
/// response. Bump when the output shape changes in a backward-incompatible way.
const SCHEMA_VERSION: u32 = 1;

/// Top-level JSON envelope for `paksmith inspect` output.
///
/// `schema_version` is always the first key. `body` is flattened inline
/// so package fields appear at the top level immediately after it.
#[derive(Serialize)]
struct InspectOutput<T: Serialize> {
    schema_version: u32,
    #[serde(flatten)]
    body: T,
}

/// Assemble and emit inspect output for `pkg` per `args` + `format`.
///
/// `--format table` is validated and rejected by the caller
/// (`commands::inspect::run`) before parsing, so `emit` receives only
/// `Auto` or `Json` in Task 1. Task 5 will move format handling fully
/// into `emit` when the table renderer lands.
pub(crate) fn emit(
    pkg: &Package,
    _args: &InspectArgs,
    _format: OutputFormat,
) -> paksmith_core::Result<()> {
    write_json(&InspectOutput {
        schema_version: SCHEMA_VERSION,
        body: pkg,
    })
}

/// Serialize `value` as pretty JSON to stdout through a `BufWriter`,
/// preserving `BrokenPipe` via `serde_json_to_io` so `main.rs`'s
/// clean-pipe-exit handler fires correctly.
fn write_json<T: Serialize>(value: &T) -> paksmith_core::Result<()> {
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    serde_json::to_writer_pretty(&mut out, value).map_err(serde_json_to_io)?;
    writeln!(out)?;
    out.flush()?;
    Ok(())
}
