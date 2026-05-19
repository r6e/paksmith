//! Binary entry point for `paksmith-doc-lint`. Dispatches on
//! subcommand (`required-headings` or `status-enum`) and forwards to
//! the matching library routine. Exit codes: 0 on success, 1 on lint
//! failure, 2 on usage error.

#![allow(missing_docs)]

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("required-headings") => {
            let Some(dir) = args.get(2) else {
                eprintln!("usage: paksmith-doc-lint required-headings <dir>");
                return ExitCode::from(2);
            };
            match paksmith_doc_lint::required_headings::check_dir(std::path::Path::new(dir)) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("{e}");
                    ExitCode::FAILURE
                }
            }
        }
        Some("status-enum") => {
            let Some(file) = args.get(2) else {
                eprintln!("usage: paksmith-doc-lint status-enum <readme.md>");
                return ExitCode::from(2);
            };
            match paksmith_doc_lint::status_enum::check_file(std::path::Path::new(file)) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("{e}");
                    ExitCode::FAILURE
                }
            }
        }
        _ => {
            eprintln!("usage: paksmith-doc-lint <required-headings|status-enum> <path>");
            ExitCode::from(2)
        }
    }
}
