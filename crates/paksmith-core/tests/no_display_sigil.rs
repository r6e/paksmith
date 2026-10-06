//! Forbids the `%` sigil in core's tracing fields.
//!
//! `%x` records `field::display(x)`, which tracing-subscriber's text format
//! writes raw, so a `%` field holding archive, registry or store text hands
//! its control characters to the terminal (#708). A `String` or `&str` field
//! other than `message` is Debug-escaped instead.

#![allow(missing_docs)]

use std::path::{Path, PathBuf};

/// `source` without its comments and string and char literals, newlines
/// kept, so only code is left and line numbers still match.
fn code_only(source: &str) -> String {
    let chars: Vec<char> = source.chars().collect();
    let mut code = String::with_capacity(source.len());
    let mut i = 0;
    while i < chars.len() {
        let rest = &chars[i..];
        let skipped = match rest {
            ['/', '/', ..] => rest.iter().position(|&c| c == '\n').unwrap_or(rest.len()),
            ['/', '*', ..] => block_comment_len(rest),
            ['"', ..] => quoted_len(rest),
            ['\'', ..] => char_literal_len(rest),
            ['r', ..] => raw_string_len(rest),
            _ => 0,
        };
        if skipped == 0 {
            code.push(rest[0]);
            i += 1;
        } else {
            code.extend(rest[..skipped].iter().filter(|&&c| c == '\n'));
            i += skipped;
        }
    }
    code
}

/// The length of the possibly nested block comment `rest` starts with.
fn block_comment_len(rest: &[char]) -> usize {
    let mut depth = 0;
    let mut i = 0;
    while i < rest.len() {
        match rest[i..] {
            ['/', '*', ..] => {
                depth += 1;
                i += 2;
            }
            ['*', '/', ..] => {
                depth -= 1;
                i += 2;
                if depth == 0 {
                    return i;
                }
            }
            _ => i += 1,
        }
    }
    rest.len()
}

/// The length of the `"`-quoted literal `rest` starts with.
fn quoted_len(rest: &[char]) -> usize {
    let mut i = 1;
    while i < rest.len() {
        match rest[i] {
            '\\' => i += 2,
            '"' => return i + 1,
            _ => i += 1,
        }
    }
    rest.len()
}

/// The length of the char literal `rest` starts with, or 0 for a lifetime
/// or label such as `'a`.
fn char_literal_len(rest: &[char]) -> usize {
    match rest {
        ['\'', '\\', _, tail @ ..] => tail.iter().position(|&c| c == '\'').map_or(0, |p| p + 4),
        ['\'', _, '\'', ..] => 3,
        _ => 0,
    }
}

/// The length of the raw string (`r"…"`, `r#"…"#`) `rest` starts with, or 0
/// when its `r` starts something else, such as an identifier. The `b` or `c`
/// of `br"…"` or `cr"…"` stays code.
fn raw_string_len(rest: &[char]) -> usize {
    let hashes = rest[1..].iter().take_while(|&&c| c == '#').count();
    if rest.get(1 + hashes) != Some(&'"') {
        return 0;
    }
    (2 + hashes..rest.len())
        .find(|&i| {
            rest[i] == '"'
                && rest[i + 1..]
                    .iter()
                    .take(hashes)
                    .filter(|&&c| c == '#')
                    .count()
                    == hashes
        })
        .map_or(rest.len(), |i| i + 1 + hashes)
}

/// Whether the gate takes `c` to end an operand, which a modulo `%` follows.
/// `?` is not one: a macro_rules `$(...)?` group can precede a sigil, so
/// `x? % y` has to be written `(x?) % y`.
fn ends_operand(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '_' | ')' | ']' | '}' | '>' | '.')
}

/// The 1-based lines of `source` that hold a `%` in code whose previous
/// non-space code character is not [`ends_operand`]. Rust has no unary `%`,
/// so that `%` is a tracing sigil or a modulo the gate cannot tell from one.
fn sigil_lines(source: &str) -> Vec<usize> {
    let mut hits = Vec::new();
    let mut prev = None;
    for (index, line) in code_only(source).lines().enumerate() {
        for c in line.chars() {
            if c == '%' && !prev.is_some_and(ends_operand) {
                hits.push(index + 1);
            }
            if !c.is_whitespace() {
                prev = Some(c);
            }
        }
    }
    hits
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
        r#"warn!(path, /* the entry */ %err, "m");"#,
        r#"warn!(url = "http://x", %err, "m");"#,
        r#"warn!(c = '"', %err, "m");"#,
        r#"warn!(c = '\"', %err, "m");"#,
        r#"warn!(s = r"\", %err, "m");"#,
        r##"warn!(s = r#"a"b"#, %err, "m");"##,
        "fn f(e: &'static E) { warn!(%e, c = 'x') }",
    ] {
        assert_eq!(sigil_lines(source), [1], "{source}");
    }
    assert_eq!(
        sigil_lines("warn!(\n    path, // the entry path\n    %err,\n    \"m\"\n);"),
        [3]
    );
}

#[test]
fn gate_ignores_modulo_comments_and_literals() {
    for source in [
        "let r = a % b;",
        "let r = n_ % 2;",
        "let r = (a) % b;",
        "let r = v[0] % b;",
        "let r = { a } % b;",
        "let r = x as Wrapping<u32> % y;",
        "let r = 1. % 2.;",
        "let r = a\n    % b;",
        "// warn!(error = %e);",
        "/* a /* (%e */ (%e */",
        r#"let s = "(%e \" = %e";"#,
        "let c = ['%'];",
    ] {
        assert_eq!(sigil_lines(source), [] as [usize; 0], "{source}");
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
            sigil_lines(&source)
                .into_iter()
                .map(move |line| format!("{}:{line}", path.display()))
        })
        .collect();

    assert_eq!(
        hits,
        [] as [String; 0],
        "log these fields as a String or a &str, not with `%`"
    );
}
