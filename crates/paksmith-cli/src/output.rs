use std::io::{self, IsTerminal, Write};

use comfy_table::presets::UTF8_FULL_CONDENSED;
use comfy_table::{Attribute, Cell, Color, Table};
use serde::Serialize;

use paksmith_core::container::EntryMetadata;

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub(crate) enum OutputFormat {
    Auto,
    Json,
    Table,
}

impl OutputFormat {
    pub(crate) fn resolve(self) -> ResolvedFormat {
        self.resolve_with_tty(std::io::stdout().is_terminal())
    }

    /// Pure resolution logic, taking the TTY signal as an explicit
    /// argument so the Auto branch is testable without touching
    /// stdout. `resolve()` is the call site that wires in the real
    /// `is_terminal()` probe.
    pub(crate) fn resolve_with_tty(self, is_tty: bool) -> ResolvedFormat {
        match self {
            Self::Json => ResolvedFormat::Json,
            Self::Table => ResolvedFormat::Table,
            Self::Auto => {
                if is_tty {
                    ResolvedFormat::Table
                } else {
                    ResolvedFormat::Json
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum ResolvedFormat {
    Json,
    Table,
}

/// Emit a one-line stderr note when `--format auto` silently resolved to JSON
/// (stdout isn't a TTY), so users piping into head/jq aren't surprised.
/// `--quiet` (#652) suppresses it — it is advisory chatter, not an error.
pub(crate) fn note_auto_resolved_to_json(
    format: OutputFormat,
    resolved: ResolvedFormat,
    quiet: bool,
) {
    if !quiet && matches!(format, OutputFormat::Auto) && matches!(resolved, ResolvedFormat::Json) {
        eprintln!(
            "note: stdout is not a terminal — emitting JSON. Pass --format table to force table output."
        );
    }
}

/// Coerce `serde_json::Error` to `io::Error` preserving the wrapped
/// `ErrorKind`, notably `BrokenPipe`, so `main.rs`'s pipe-clean-exit
/// handler keeps working when writing JSON to stdout closed by the
/// downstream reader (e.g. `paksmith inspect ... | head -1`).
///
/// Takes its argument by value because the canonical call site is
/// `.map_err(serde_json_to_io)`, whose closure receives the error
/// owned. A `&Error` signature would force every caller into a
/// `|e| serde_json_to_io(&e)` shim, defeating the helper.
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn serde_json_to_io(e: serde_json::Error) -> io::Error {
    e.io_error_kind()
        .map_or_else(|| io::Error::other(e.to_string()), io::Error::from)
}

/// `list`/`search` JSON schema version (#652). COMMAND-SHARED on
/// purpose, unlike `inspect`/`extract`'s command-local versions: both
/// commands emit the same `EntryRow` shape through the same
/// `print_entries` writer, so the schema IS shared — versioning it
/// twice would let the numbers drift apart while describing identical
/// bytes. Bump on a BREAKING change to `EntryRow` or the envelope.
/// Additive optional keys that never appear in a pre-existing output
/// mode do not bump — see `EntryRow::source` (#655), absent from every
/// explicit-path invocation.
const ENTRIES_SCHEMA_VERSION: u32 = 1;

/// The `{"schema_version": 1, "entries": [...]}` envelope for
/// `list`/`search` JSON (SPEC: "JSON output is stable and structured").
/// A NAMED `entries` key rather than inspect's `#[serde(flatten)]`
/// trick — an array cannot flatten into an object. `schema_version` is
/// declared first so serde emits it first (raw-byte ordering is pinned
/// by `list_and_search_json_carry_schema_version_envelope`).
#[derive(Serialize)]
struct EntriesOutput<'a> {
    schema_version: u32,
    entries: Vec<EntryRow<'a>>,
}

#[derive(Serialize)]
struct EntryRow<'a> {
    path: &'a str,
    size: u64,
    compressed_size: u64,
    compressed: bool,
    encrypted: bool,
    /// Which archive the entry came from — present ONLY in profile-paks
    /// mode (#655: no explicit pak path, entries may span archives).
    /// Additive-optional: explicit-path invocations emit byte-identical
    /// output to pre-#655, so ENTRIES_SCHEMA_VERSION stays 1.
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<&'a str>,
}

impl<'a> EntryRow<'a> {
    fn new(e: &'a EntryMetadata, source: Option<&'a str>) -> Self {
        Self {
            path: e.path(),
            size: e.uncompressed_size(),
            compressed_size: e.compressed_size(),
            compressed: e.is_compressed(),
            encrypted: e.is_encrypted(),
            source,
        }
    }
}

fn print_entries(entries: &[EntryMetadata], format: ResolvedFormat) -> io::Result<()> {
    let stdout = io::stdout();
    let stdout_lock = stdout.lock();
    // Wrap stdout in a `BufWriter` so per-entry writes coalesce into
    // 8 KiB batches before hitting the kernel. On a pipe (the JSON path's
    // typical caller is a pipe to `jq` or similar), an unbuffered
    // `StdoutLock` issues one write syscall per `serde_json` field —
    // tens of thousands per large pak. The explicit `flush()` below
    // preserves BrokenPipe routing through `?`; `BufWriter::drop` also
    // flushes but swallows errors, so callers would lose pipe-closed
    // signalling without the explicit pass.
    let mut out = io::BufWriter::new(stdout_lock);
    match format {
        ResolvedFormat::Json => {
            let envelope = EntriesOutput {
                schema_version: ENTRIES_SCHEMA_VERSION,
                entries: entries.iter().map(|e| EntryRow::new(e, None)).collect(),
            };
            // Stream directly to stdout instead of building the full string in
            // memory. serde_json wraps the underlying io::Error; the helper
            // surfaces its kind so callers can distinguish BrokenPipe from
            // real errors.
            serde_json::to_writer_pretty(&mut out, &envelope).map_err(serde_json_to_io)?;
            writeln!(out)?;
        }
        ResolvedFormat::Table => {
            let table = build_entries_table(entries, styling_enabled(std::env::var_os("NO_COLOR")));
            writeln!(out, "{table}")?;
        }
    }
    out.flush()?;
    Ok(())
}

/// Whether to ATTACH styles to the entries table, per the `NO_COLOR`
/// convention (<https://no-color.org>): enabled iff the variable is
/// absent or present-but-empty. Pure and polarity-complete in ONE fn
/// (like [`OutputFormat::resolve_with_tty`], and for the same reason):
/// a black-box test cannot see this decision — comfy-table suppresses
/// ANSI off-TTY whichever way it goes — so the whole contract is
/// unit-pinned here. `print_entries` wires in the real env read.
fn styling_enabled(no_color: Option<std::ffi::OsString>) -> bool {
    no_color.is_none_or(|v| v.is_empty())
}

/// Route entry output for a command that may span archives (#655):
/// a single explicit-path source keeps the pre-#655 writer (and its
/// byte-identical output); anything else renders grouped. The slice
/// pattern also removes the `groups[0]` index the commands carried.
pub(crate) fn print_entry_groups(
    groups: &[(std::path::PathBuf, Vec<EntryMetadata>)],
    explicit_path: bool,
    format: ResolvedFormat,
) -> io::Result<()> {
    match groups {
        // Explicit-path invocation: byte-identical output to pre-#655.
        [(_, entries)] if explicit_path => print_entries(entries, format),
        _ => print_entries_grouped(groups, format),
    }
}

/// Multi-archive variant of [`print_entries`] for profile-paks mode
/// (#655): entries grouped by source archive.
///
/// JSON keeps the same `{schema_version, entries}` envelope with each
/// row carrying an additive `source` key (the archive path, display
/// form). Table mode is rendered by [`render_entry_groups`]. Explicit-
/// path invocations never route here, so their output is byte-identical
/// to pre-#655.
fn print_entries_grouped(
    groups: &[(std::path::PathBuf, Vec<EntryMetadata>)],
    format: ResolvedFormat,
) -> io::Result<()> {
    let stdout = io::stdout();
    let stdout_lock = stdout.lock();
    let mut out = io::BufWriter::new(stdout_lock);
    match format {
        ResolvedFormat::Json => {
            // Owned display strings must outlive the rows that
            // borrow them — this vec exists for the lifetime, not
            // for iteration convenience.
            let sources: Vec<String> = groups
                .iter()
                .map(|(p, _)| p.display().to_string())
                .collect();
            let envelope = EntriesOutput {
                schema_version: ENTRIES_SCHEMA_VERSION,
                entries: groups
                    .iter()
                    .zip(&sources)
                    .flat_map(|((_, entries), src)| {
                        entries
                            .iter()
                            .map(move |e| EntryRow::new(e, Some(src.as_str())))
                    })
                    .collect(),
            };
            serde_json::to_writer_pretty(&mut out, &envelope).map_err(serde_json_to_io)?;
            writeln!(out)?;
        }
        ResolvedFormat::Table => {
            let styled = styling_enabled(std::env::var_os("NO_COLOR"));
            write!(out, "{}", render_entry_groups(groups, styled))?;
        }
    }
    out.flush()?;
    Ok(())
}

/// Pure renderer for the grouped TABLE view: one sanitized
/// `pak: <path>` header per group, that group's table (newline-
/// terminated), and a blank line between groups. Split from the writer
/// so the frame is unit-pinned — a black-box test cannot see the
/// styling decision, and the integration suites only exercise JSON.
fn render_entry_groups(groups: &[(std::path::PathBuf, Vec<EntryMetadata>)], style: bool) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for (i, (pak, entries)) in groups.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        let _ = writeln!(
            out,
            "pak: {}",
            sanitize_for_display(&pak.display().to_string())
        );
        let _ = writeln!(out, "{}", build_entries_table(entries, style));
    }
    out
}

/// Build the `list`/`search` entries table (SPEC Design Principles:
/// "column alignment and color when TTY-attached, plain when piped").
///
/// `style = true` attaches the colors/attributes; comfy-table then
/// applies them ONLY when stdout is a TTY (`should_style`), so piped
/// output stays plain with no extra gating here. `style = false`
/// (the `NO_COLOR` path) builds plain cells outright, so not even a
/// TTY gets ANSI. The split keeps the styling decision unit-testable:
/// tests render with `enforce_styling()` — which would override a
/// `force_no_tty()`-based gate but cannot conjure styles that were
/// never attached.
// `unused_results` allow: comfy-table's builder returns `&mut Table`
// for chaining; discarding is the documented call shape.
#[allow(unused_results)]
fn build_entries_table(entries: &[EntryMetadata], style: bool) -> Table {
    let header = |text: &str| {
        if style {
            Cell::new(text)
                .add_attribute(Attribute::Bold)
                .fg(Color::Cyan)
        } else {
            Cell::new(text)
        }
    };
    // "yes" is the signal state in both flag columns; color it so the
    // eye can scan a big table for encrypted/compressed entries.
    let flag_cell = |val: bool, yes_color: Color| {
        if val {
            let cell = Cell::new("yes");
            if style { cell.fg(yes_color) } else { cell }
        } else {
            Cell::new("no")
        }
    };

    let mut table = Table::new();
    table.load_preset(UTF8_FULL_CONDENSED);
    table.set_header(vec![
        header("Path"),
        header("Size"),
        header("Compressed"),
        header("Encrypted"),
    ]);
    for entry in entries {
        table.add_row(vec![
            Cell::new(sanitize_for_display(entry.path())),
            Cell::new(format_size(entry.uncompressed_size())),
            flag_cell(entry.is_compressed(), Color::Green),
            flag_cell(entry.is_encrypted(), Color::Yellow),
        ]);
    }
    table
}

/// Replace control characters (C0 incl. ESC/BEL/CR, DEL, and C1 incl.
/// the U+009B CSI) with U+FFFD in an untrusted pak string bound for
/// human display. Keyed to the table FORMAT, not TTY-ness — a piped
/// table gets paged into a terminal later. The core FString parser
/// guarantees valid non-NUL Unicode — it does NOT strip controls, so a
/// hostile pak can embed OSC/CSI sequences (title rewrites, screen
/// clears, output-hiding). No legitimate virtual path contains control
/// characters.
///
/// Consumers: the list/search entries table (here) and extract's
/// summary FAILED lines. Two same-class surfaces remain, BOTH tracked
/// as issue #708 (many call sites; their own pass): inspect's table
/// tree renderer, and the `profile` command family — `show`, `list`
/// and `detect` render registry-authored `name`/`id`/`engine_version`,
/// and `profile`'s not-found hints echo an id that may have been copied
/// from a registry listing. Registry strings are length-capped
/// (`MAX_STR`) but not character-class restricted. The JSON path deliberately has no equivalent — NOT
/// because serde escapes everything (it escapes C0 only; DEL and C1
/// incl. U+009B pass through as raw UTF-8) but because JSON is the
/// machine interface: exact path bytes are the round-tripping
/// contract, and machine consumers don't interpret terminal controls.
pub(crate) fn sanitize_for_display(s: &str) -> std::borrow::Cow<'_, str> {
    if s.chars().any(char::is_control) {
        std::borrow::Cow::Owned(
            s.chars()
                .map(|c| if c.is_control() { '\u{FFFD}' } else { c })
                .collect(),
        )
    } else {
        std::borrow::Cow::Borrowed(s)
    }
}

// `bytes as f64` loses precision past 2^53, but the output is `{:.1}`
// (one decimal place) — any precision past `f64`'s 52-bit mantissa is
// rounded away before display. Even at TiB scale, the worst-case
// display error is ~1 KiB in 1 TiB, far below display resolution. The
// widening cast on the divisor (`KIB`/`MIB`/.. `u64 → f64`) is
// similarly bounded by the constants themselves being well within
// f64's exact-integer range.
//
// Issue #93: ladder extends past MiB to GiB and TiB. Entries can be
// up to `MAX_UNCOMPRESSED_ENTRY_BYTES = 8 GiB` (per pak/mod.rs); pre-
// fix the table printed "8192.0 MiB" instead of "8.0 GiB" at the cap.
// TiB tier is forward-compat for any future cap loosening.
#[allow(clippy::cast_precision_loss)]
fn format_size(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;
    const TIB: u64 = GIB * 1024;
    if bytes < KIB {
        format!("{bytes} B")
    } else if bytes < MIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else if bytes < GIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes < TIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else {
        format!("{:.1} TiB", bytes as f64 / TIB as f64)
    }
}

#[cfg(test)]
mod grouped_render_tests {
    use paksmith_core::container::{EntryFlags, EntryMetadata};

    use super::*;

    fn one_entry(path: &str) -> Vec<EntryMetadata> {
        vec![EntryMetadata::new(path.into(), 10, 20, EntryFlags::NONE)]
    }

    /// The grouped frame: one `pak:` header per group, each table
    /// newline-terminated, ONE blank line between groups, and the whole
    /// render ends with a newline. (The integration suites only
    /// exercise JSON; this is the sole pin on the table frame.)
    #[test]
    fn grouped_frame_headers_separator_and_trailing_newline() {
        let groups = vec![
            (
                std::path::PathBuf::from("/a/base.pak"),
                one_entry("Game/a.txt"),
            ),
            (
                std::path::PathBuf::from("/a/patch.pak"),
                one_entry("Game/b.txt"),
            ),
        ];
        let out = render_entry_groups(&groups, false);
        assert!(out.starts_with("pak: /a/base.pak\n"), "first header: {out}");
        assert!(
            out.contains("\n\npak: /a/patch.pak\n"),
            "one blank line between groups: {out}"
        );
        assert!(out.ends_with('\n'), "newline-terminated: {out:?}");
        assert!(
            !out.ends_with("\n\n"),
            "no trailing blank line after the last group: {out:?}"
        );
        assert_eq!(out.matches("pak: ").count(), 2, "one header per group");
    }

    /// A hostile pak path (C0 controls from a crafted store/dir name)
    /// is neutralized in the human header, same policy as entry paths.
    #[test]
    fn grouped_header_sanitizes_control_chars() {
        let groups = vec![(
            std::path::PathBuf::from("/a/evil\x1b[31m.pak"),
            one_entry("Game/a.txt"),
        )];
        let out = render_entry_groups(&groups, false);
        assert!(
            !out.contains('\x1b'),
            "escape byte must not reach the terminal: {out:?}"
        );
        assert!(out.contains('\u{FFFD}'), "replacement char instead: {out}");
    }
}

#[cfg(test)]
mod table_style_tests {
    use paksmith_core::container::{EntryFlags, EntryMetadata};

    use super::*;

    fn entries() -> Vec<EntryMetadata> {
        vec![
            EntryMetadata::new(
                "Game/enc.uasset".into(),
                10,
                20,
                EntryFlags::NONE.encrypted(),
            ),
            EntryMetadata::new(
                "Game/comp.uasset".into(),
                10,
                20,
                EntryFlags::NONE.compressed(),
            ),
            EntryMetadata::new("Game/plain.txt".into(), 10, 20, EntryFlags::NONE),
        ]
    }

    /// `enforce_styling()` renders the attached styles even off-TTY, so
    /// the test can observe the ANSI bytes the SPEC's "color when
    /// TTY-attached" clause produces on a real terminal.
    #[test]
    fn styled_table_attaches_ansi_when_forced() {
        let mut table = build_entries_table(&entries(), true);
        let _ = table.enforce_styling();
        let rendered = table.to_string();
        assert!(
            rendered.contains("\u{1b}[1m"),
            "header must be bold: {rendered}"
        );
        assert!(
            rendered.contains("\u{1b}[38;5;14m"),
            "header must be cyan: {rendered}"
        );
        // 4 headers + the encrypted-yes + compressed-yes cells all carry
        // a foreground color — dropping .fg from flag_cell would fail
        // this count even with the header styles intact.
        assert!(
            rendered.matches("\u{1b}[38;5;").count() >= 6,
            "the two 'yes' flag cells must be colored too: {rendered}"
        );
    }

    /// `style = false` (the NO_COLOR path) attaches nothing — even
    /// `enforce_styling()` cannot conjure escapes that were never set.
    #[test]
    fn unstyled_table_has_no_ansi_even_when_forced() {
        let mut table = build_entries_table(&entries(), false);
        let _ = table.enforce_styling();
        let rendered = table.to_string();
        assert!(
            !rendered.contains('\u{1b}'),
            "NO_COLOR table must be ANSI-free: {rendered}"
        );
        // Content survives unstyled.
        assert!(rendered.contains("Game/enc.uasset") && rendered.contains("yes"));
    }

    /// Hostile pak paths cannot inject terminal escapes through the
    /// table: every control char (ESC, BEL, C1 CSI, …) is replaced
    /// before the cell is built — even under forced styling.
    #[test]
    fn hostile_path_control_chars_are_neutralized() {
        let hostile = vec![EntryMetadata::new(
            "Game/\u{1b}]0;pwned\u{7}/\u{9b}2Jx.uasset".into(),
            10,
            20,
            EntryFlags::NONE,
        )];
        // Unstyled: the ONLY possible ESC source would be the hostile
        // path, so the render must be entirely control-char-free.
        let plain = build_entries_table(&hostile, false).to_string();
        assert!(
            !plain.contains('\u{1b}') && !plain.contains('\u{7}') && !plain.contains('\u{9b}'),
            "control chars from the pak path must be neutralized: {plain:?}"
        );
        assert!(
            plain.contains('\u{FFFD}'),
            "replacement char must mark the stripped spots: {plain:?}"
        );
        // The harmless residue stays visible — only the control bytes
        // are stripped, so the user can still SEE something was there.
        assert!(
            plain.contains("]0;pwned"),
            "non-control residue must stay visible: {plain:?}"
        );

        // Styled: the table's own ANSI is present, but the hostile BEL /
        // C1-CSI still cannot survive.
        let mut styled_table = build_entries_table(&hostile, true);
        let _ = styled_table.enforce_styling();
        let styled = styled_table.to_string();
        assert!(
            !styled.contains('\u{7}') && !styled.contains('\u{9b}'),
            "hostile BEL/CSI must not survive styled rendering: {styled:?}"
        );
    }

    /// no-color.org contract, full polarity: absent or empty → styled;
    /// present-and-non-empty → plain. This IS the whole NO_COLOR
    /// decision (nothing else composes on top), so an inversion cannot
    /// hide from the suite.
    #[test]
    fn styling_enabled_no_color_contract() {
        assert!(styling_enabled(None));
        assert!(styling_enabled(Some("".into())));
        assert!(!styling_enabled(Some("1".into())));
        assert!(!styling_enabled(Some("anything".into())));
    }
}

#[cfg(test)]
mod resolve_tests {
    use super::{OutputFormat, ResolvedFormat};

    #[test]
    fn explicit_json_ignores_tty() {
        assert!(matches!(
            OutputFormat::Json.resolve_with_tty(true),
            ResolvedFormat::Json
        ));
        assert!(matches!(
            OutputFormat::Json.resolve_with_tty(false),
            ResolvedFormat::Json
        ));
    }

    #[test]
    fn explicit_table_ignores_tty() {
        assert!(matches!(
            OutputFormat::Table.resolve_with_tty(true),
            ResolvedFormat::Table
        ));
        assert!(matches!(
            OutputFormat::Table.resolve_with_tty(false),
            ResolvedFormat::Table
        ));
    }

    #[test]
    fn auto_picks_table_on_tty() {
        assert!(matches!(
            OutputFormat::Auto.resolve_with_tty(true),
            ResolvedFormat::Table
        ));
    }

    #[test]
    fn auto_picks_json_when_piped() {
        assert!(matches!(
            OutputFormat::Auto.resolve_with_tty(false),
            ResolvedFormat::Json
        ));
    }
}

#[cfg(test)]
mod format_size_tests {
    use super::format_size;

    /// Issue #93: pin every tier boundary so a regression that
    /// reorders the ladder or off-by-ones a comparator surfaces here
    /// instead of in user-facing `paksmith list` output.
    #[test]
    fn each_tier_renders_correctly() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(1023), "1023 B");
        assert_eq!(format_size(1024), "1.0 KiB");
        assert_eq!(format_size(1024 * 1024 - 1), "1024.0 KiB");
        assert_eq!(format_size(1024 * 1024), "1.0 MiB");
        assert_eq!(format_size(1024 * 1024 * 1024 - 1), "1024.0 MiB");
        assert_eq!(format_size(1024 * 1024 * 1024), "1.0 GiB");
        // Pin the MAX_UNCOMPRESSED_ENTRY_BYTES = 8 GiB case explicitly:
        // pre-#93 this rendered as "8192.0 MiB", not "8.0 GiB".
        assert_eq!(format_size(8 * 1024 * 1024 * 1024), "8.0 GiB");
        assert_eq!(format_size(1024_u64.pow(4) - 1), "1024.0 GiB");
        assert_eq!(format_size(1024_u64.pow(4)), "1.0 TiB");
        // Beyond TiB: stays in TiB tier (no PiB tier — wildly beyond
        // anything realistic for a single pak entry).
        assert_eq!(format_size(2 * 1024_u64.pow(4)), "2.0 TiB");
    }
}
