//! `inspect` output assembly: selection and format dispatch.
//!
//! Owns the emit path for `paksmith inspect` output. Phase 4b Task 1
//! contains only a thin delegation wrapper producing byte-identical output
//! to the former inline serializer in `commands/inspect.rs`. Tasks 2–5
//! layer in a versioned JSON wrapper, field selection, and the table
//! renderer.

pub(crate) mod select;

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
/// When `--path` is present the full document is serialized to a
/// [`serde_json::Value`] first, then the dotted path is resolved and only
/// the located sub-value is written. `--path` is incompatible with
/// `--format table` (returns `InvalidArgument`).
pub(crate) fn emit(
    pkg: &Package,
    args: &InspectArgs,
    format: OutputFormat,
) -> paksmith_core::Result<()> {
    // `--path` drills into the wrapped document and implies structured output.
    if let Some(path) = args.path.as_deref() {
        if matches!(format, OutputFormat::Table) {
            return Err(arg_error(
                "--format",
                "--path cannot be combined with --format table",
            ));
        }
        let doc = serde_json::to_value(InspectOutput {
            schema_version: SCHEMA_VERSION,
            body: pkg,
        })
        .map_err(serde_json_to_io)?;
        let found = select::navigate(&doc, path).map_err(|reason| arg_error("--path", reason))?;
        return write_json(found);
    }

    // Table handling lands in Task 5; full JSON otherwise.
    // `--path` always emits JSON: `OutputFormat::Auto` and `json` both produce
    // JSON for inspect; only an explicit `--format table` is incompatible.
    // `OutputFormat::Auto` is intentionally NOT matched here — inspect's Auto
    // always resolves to JSON at this layer, never to table.
    if matches!(format, OutputFormat::Table) {
        return Err(arg_error(
            "--format",
            "table format is not yet supported for `inspect`; use `json` or `auto`",
        ));
    }
    write_json(&InspectOutput {
        schema_version: SCHEMA_VERSION,
        body: pkg,
    })
}

/// Build an [`paksmith_core::PaksmithError::InvalidArgument`] for a CLI flag.
fn arg_error(arg: &'static str, reason: impl Into<String>) -> paksmith_core::PaksmithError {
    paksmith_core::PaksmithError::InvalidArgument {
        arg,
        reason: reason.into(),
    }
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
