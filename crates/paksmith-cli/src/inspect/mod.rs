//! `inspect` output assembly: selection and format dispatch.
//!
//! Owns the emit path for `paksmith inspect` output. Phase 4b Task 1
//! contains only a thin delegation wrapper producing byte-identical output
//! to the former inline serializer in `commands/inspect.rs`. Tasks 2–5
//! layer in a versioned JSON wrapper, field selection, and the table
//! renderer.

pub(crate) mod select;
pub(crate) mod tree;

use std::io::{self, Write};

use serde::Serialize;

use paksmith_core::asset::Package;

use crate::commands::inspect::InspectArgs;
use crate::output::{OutputFormat, ResolvedFormat, serde_json_to_io};

/// Schema version emitted as the first key of every `paksmith inspect` JSON
/// response. Bump when the output shape changes in a backward-incompatible way.
///
/// This is COMMAND-LOCAL to `inspect`'s JSON schema. `extract`'s summary
/// `schema_version` is an independent value — the two version separately.
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

/// Wrap `body` in an [`InspectOutput`] envelope with the current schema version.
fn wrap<T: Serialize>(body: T) -> InspectOutput<T> {
    InspectOutput {
        schema_version: SCHEMA_VERSION,
        body,
    }
}

/// Assemble and emit inspect output for `pkg` per `args` + `format`.
///
/// `--export` narrows the body to a single export subtree before any further
/// processing. `--path` then drills into whichever body is active (full
/// package or the selected export). `--path` is incompatible with
/// `--format table` (returns `InvalidArgument`).
pub(crate) fn emit(
    pkg: &Package,
    args: &InspectArgs,
    format: OutputFormat,
) -> paksmith_core::Result<()> {
    // Whether the caller asked for table EXPLICITLY (`--format table`).
    // This is intentionally the UNRESOLVED format: the `--path` rejection
    // and the table-render dispatch both key off the explicit request, not
    // the TTY-resolved value, so `--path` under `--format auto` on a TTY
    // still emits JSON rather than rejecting or rendering a tree.
    let explicit_table = matches!(format, OutputFormat::Table);

    // `--export` narrows the body to one export subtree.  Serialize `pkg` to
    // a `Value` exactly ONCE for the index resolution, then cache it so the
    // JSON subtree slice and any `--path` drill can reuse it without a second
    // `to_value` call.  The table renderer doesn't use `pkg_val` at all
    // (it walks the typed `Package` directly via `export_idx`).
    let (export_idx, cached_pkg_val): (Option<usize>, Option<serde_json::Value>) =
        match args.export.as_deref() {
            Some(sel) => {
                let pkg_val = serde_json::to_value(pkg).map_err(serde_json_to_io)?;
                let idx = select::resolve_export(&pkg_val["exports"], sel)
                    .map_err(|reason| arg_error("--export", reason))?;
                (Some(idx), Some(pkg_val))
            }
            None => (None, None),
        };

    if let Some(path) = args.path.as_deref() {
        if explicit_table {
            return Err(arg_error(
                "--format",
                "--path cannot be combined with --format table",
            ));
        }
        // Wrap whichever body is active, then drill. `--path` always emits
        // JSON regardless of the resolved format.
        let doc = match (export_idx, cached_pkg_val) {
            (Some(idx), Some(pkg_val)) => {
                serde_json::to_value(wrap(pkg_val["exports"][idx].clone()))
                    .map_err(serde_json_to_io)?
            }
            _ => serde_json::to_value(wrap(pkg)).map_err(serde_json_to_io)?,
        };
        let found = select::navigate(&doc, path).map_err(|reason| arg_error("--path", reason))?;
        return write_json(found);
    }

    let resolved = format.resolve();

    // Advisory note on stderr when `--format auto` resolves (no `--path`,
    // which always forces JSON). Mirrors `list`'s note so users aren't
    // surprised the format changed from what they saw interactively.
    if matches!(format, OutputFormat::Auto) && matches!(resolved, ResolvedFormat::Json) {
        eprintln!(
            "note: stdout is not a terminal — emitting JSON. Pass --format table to force table output."
        );
    }

    match resolved {
        ResolvedFormat::Table => render_table(pkg, export_idx),
        // JSON: wrapped full package (direct, order-preserved) or wrapped
        // export subtree.  `OutputFormat::Auto` resolves here based on the
        // TTY — piped output stays JSON.
        ResolvedFormat::Json => match (export_idx, cached_pkg_val) {
            (Some(idx), Some(pkg_val)) => write_json(&wrap(pkg_val["exports"][idx].clone())),
            _ => write_json(&wrap(pkg)),
        },
    }
}

/// Render the human tree view to stdout through a `BufWriter`, mirroring
/// [`write_json`]'s explicit `flush()` so `BrokenPipe` routes through `?`
/// (a `BufWriter` drop would swallow it).
fn render_table(pkg: &Package, export_idx: Option<usize>) -> paksmith_core::Result<()> {
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    tree::render(pkg, export_idx, &mut out)?;
    out.flush()?;
    Ok(())
}

/// Build a [`paksmith_core::PaksmithError::InvalidArgument`] for a CLI flag.
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
