//! Binary entry point for `paksmith-doc-lint`. Dispatches on
//! subcommand (`required-headings` or `status-enum`) and forwards to
//! the matching library routine. Exit codes: 0 on success, 1 on lint
//! failure, 2 on usage error.

#![allow(missing_docs)]

use std::path::Path;
use std::process::ExitCode;

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
        _ => {
            eprintln!("usage: paksmith-doc-lint <required-headings|status-enum> <path>");
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
