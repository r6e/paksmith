//! Forbids the `%` sigil in core's tracing fields.
//!
//! `%x` records `field::display(x)`, which tracing-subscriber's text format
//! writes raw, so a `%` field holding archive, registry or store text hands
//! its control characters to the terminal (#708). A `String` or `&str` field
//! other than `message` is Debug-escaped instead.

#![allow(missing_docs)]

use std::path::{Path, PathBuf};

use proc_macro2::{TokenStream, TokenTree};

/// The 1-based lines of `source` that hold a `%` token whose previous token
/// in the same group does not end an operand (see [`ends_operand`]). Rust has
/// no unary `%`, so that `%` is a tracing sigil or a modulo the gate cannot
/// tell from one.
///
/// An error where proc-macro2's tokens part from rustc's, so that the tokens
/// after the split cannot be trusted: when proc-macro2 cannot tokenize
/// `source`; when `source` starts with a shebang line, which rustc skips and
/// proc-macro2 reads as code; and when proc-macro2 splits a lifetime or label
/// from its name, reading `'r"\""` as `'` and the raw string `r"\"` where rustc
/// reads the label `'r` and a string.
fn sigil_lines(source: &str) -> Result<Vec<usize>, String> {
    let code = source.strip_prefix('\u{FEFF}').unwrap_or(source);
    if code.starts_with("#!") && !code.starts_with("#![") {
        return Err("line 1: a shebang line".to_string());
    }
    let stream = code.parse::<TokenStream>().map_err(|e| e.to_string())?;
    let mut hits = Vec::new();
    collect_sigils(stream, &mut hits)?;
    Ok(hits)
}

fn collect_sigils(stream: TokenStream, hits: &mut Vec<usize>) -> Result<(), String> {
    let mut prev = None;
    let mut after_operand = false;
    for tree in stream {
        if let Some(TokenTree::Punct(quote)) = &prev
            && quote.as_char() == '\''
            && !matches!(tree, TokenTree::Ident(_))
        {
            let line = quote.span().start().line;
            return Err(format!(
                "line {line}: a lifetime split from its name (put a space after it)"
            ));
        }
        match &tree {
            TokenTree::Punct(p) if p.as_char() == '%' && !after_operand => {
                hits.push(p.span().start().line);
            }
            TokenTree::Group(group) => collect_sigils(group.stream(), hits)?,
            _ => {}
        }
        after_operand = ends_operand(&tree, prev.as_ref(), after_operand);
        prev = Some(tree);
    }
    Ok(())
}

/// Whether `tree`, after `prev`, ends an operand, which a modulo `%` follows:
/// an identifier, a literal or a bracketed group, unless a `$` before it makes
/// it a macro_rules metavariable or repetition, or a `>` right after an
/// operand, as when it closes generic arguments (`=>` and `->` do not).
/// `?` does not either: a macro_rules `$(...)?` group can precede a sigil, so
/// `x? % y` has to be written `(x?) % y`.
fn ends_operand(tree: &TokenTree, prev: Option<&TokenTree>, after_operand: bool) -> bool {
    match tree {
        TokenTree::Ident(_) | TokenTree::Literal(_) | TokenTree::Group(_) => {
            !matches!(prev, Some(TokenTree::Punct(p)) if p.as_char() == '$')
        }
        TokenTree::Punct(p) => p.as_char() == '>' && after_operand,
    }
}

fn rust_files(dir: &Path, files: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, files);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            files.push(path);
        }
    }
}

#[test]
fn gate_flags_each_sigil_shape() {
    for source in [
        r#"warn!(%err, "m");"#,
        r#"warn!(path, %err, "m");"#,
        r#"warn!(error = %e, "m");"#,
        r#"warn!({ %err }, "m");"#,
        r#"warn!($($k = $v,)? %$e, "m");"#,
        r#"warn!($k $eq %$e, "m");"#,
        r#"warn!($(error =) %$e, "m");"#,
        "warn_kv!(error => %e);",
    ] {
        assert_eq!(sigil_lines(source).unwrap(), [1], "{source}");
    }
    assert_eq!(
        sigil_lines("warn!(\n    path, // the entry path\n    %err,\n    \"m\"\n);").unwrap(),
        [3]
    );
}

#[test]
fn gate_ignores_modulo() {
    for source in [
        "let r = a % b;",
        "let r = 7 % b;",
        "let r = (a) % b;",
        "let r = x as Wrapping<Vec<u8>> % y;",
        "macro_rules! m { ($a:expr) => { ($a) % 2 }; }",
        "#![allow(dead_code)]\nlet r = a % b;",
        "fn f<'a>(x: &'a u32) -> u32 { x % 2 }",
    ] {
        assert_eq!(sigil_lines(source).unwrap(), [] as [usize; 0], "{source}");
    }
}

#[test]
fn gate_fails_on_tokens_it_cannot_trust() {
    for (source, error) in [
        (r#"warn!(error = %e, "m);"#, "cannot parse"),
        (
            r#"let _ = 'r: { break 'r"\"" }; warn!(error = %e); // "}"#,
            "a lifetime split",
        ),
        (
            "#!x \"\nfn f() { warn!(error = %e); } // \"",
            "a shebang line",
        ),
        (
            "\u{FEFF}#!x \"\nfn f() { warn!(error = %e); } // \"",
            "a shebang line",
        ),
    ] {
        let found = sigil_lines(source).unwrap_err();
        assert!(found.contains(error), "{source}: {found}");
    }
}

#[test]
fn core_has_no_display_sigil() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    let nested = src.join("container").join("pak").join("mod.rs");
    assert!(
        files.contains(&nested),
        "the walk must reach {}",
        nested.display()
    );

    let hits: Vec<String> = files
        .iter()
        .flat_map(|path| {
            let source = std::fs::read_to_string(path).unwrap();
            let lines = sigil_lines(&source).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            lines
                .into_iter()
                .map(move |line| format!("{}:{line}", path.display()))
        })
        .collect();

    assert_eq!(
        hits,
        [] as [String; 0],
        "log these fields as a String or a &str, not with `%`; parenthesize the left \
         operand of a modulo the gate flags"
    );
}
