//! Binary entry point for `paksmith-doc-lint`. Dispatches on
//! subcommand (`required-headings`, `status-enum`, or `inventory-files`)
//! and forwards to the matching library routine. Exit codes: 0 on
//! success, 1 on lint failure, 2 on usage error.

#![allow(missing_docs)]

use std::path::Path;
use std::process::ExitCode;

const USAGE: &str =
    "usage: paksmith-doc-lint <required-headings|status-enum|inventory-files> <path> [docs-dir]";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("required-headings") => run(
            args.get(2),
            "usage: paksmith-doc-lint required-headings <dir>",
            paksmith_doc_lint::required_headings::check_dir,
        ),
        Some("status-enum") => run(
            args.get(2),
            "usage: paksmith-doc-lint status-enum <readme.md>",
            paksmith_doc_lint::status_enum::check_file,
        ),
        Some("inventory-files") => run_inventory_files(args.get(2), args.get(3)),
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn run<F>(arg: Option<&String>, usage: &str, check: F) -> ExitCode
where
    F: FnOnce(&Path) -> anyhow::Result<()>,
{
    let Some(arg) = arg else {
        eprintln!("{usage}");
        return ExitCode::from(2);
    };
    match check(Path::new(arg)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn run_inventory_files(readme: Option<&String>, docs_dir: Option<&String>) -> ExitCode {
    let usage = "usage: paksmith-doc-lint inventory-files <readme.md> <docs-dir>";
    let (Some(readme), Some(docs_dir)) = (readme, docs_dir) else {
        eprintln!("{usage}");
        return ExitCode::from(2);
    };
    match paksmith_doc_lint::inventory_files::check(Path::new(readme), Path::new(docs_dir)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
