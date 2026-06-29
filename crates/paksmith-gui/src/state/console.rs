//! Pure filtering and formatting for the debug-console log view.
//!
//! No iced, no `Mutex`, no I/O — operates on slices of [`LogRecord`] so every
//! decision is unit + mutation tested.

use tracing::Level;

use crate::state::log_buffer::LogRecord;

/// The levels offered in the min-level selector, most severe first.
pub const LEVEL_CHOICES: [Level; 5] = [
    Level::ERROR,
    Level::WARN,
    Level::INFO,
    Level::DEBUG,
    Level::TRACE,
];

/// At/above this relative vertical scroll offset (1.0 = very bottom), the
/// console is "following the tail" and auto-scrolls on new records.
const FOLLOW_THRESHOLD: f32 = 0.999;

/// Filter predicates applied before display.
#[derive(Debug, Clone)]
pub struct ConsoleFilters {
    /// Minimum severity to show: a record passes when it is at least as severe
    /// as this (e.g. `WARN` shows WARN+ERROR, hides INFO/DEBUG/TRACE).
    pub min_level: Level,
    /// Case-sensitive substring the target must contain (empty = match any).
    pub target_filter: String,
    /// Case-sensitive substring the message must contain (empty = match any).
    pub search: String,
}

impl Default for ConsoleFilters {
    fn default() -> Self {
        Self {
            // TRACE is least severe; "at least TRACE" shows everything captured.
            min_level: Level::TRACE,
            target_filter: String::new(),
            search: String::new(),
        }
    }
}

/// True when `level` is at least as severe as `min`.
///
/// `tracing::Level` orders ERROR < WARN < INFO < DEBUG < TRACE (ERROR is the
/// smallest), so "at least as severe" is `level <= min`. Pinned by behaviour in
/// `min_level_warn_shows_error_and_warn_hides_less_severe`, not by this comment.
fn level_at_least(level: Level, min: Level) -> bool {
    level <= min
}

/// True when `record` passes all active filters. An empty target/search string
/// matches any record because `str::contains("")` is always true — so no
/// redundant `is_empty()` short-circuit is needed.
pub fn matches(record: &LogRecord, filters: &ConsoleFilters) -> bool {
    level_at_least(record.level, filters.min_level)
        && record.target.contains(filters.target_filter.as_str())
        && record.message.contains(filters.search.as_str())
}

/// The records to display, in capture order, after filtering.
pub fn displayed<'a>(records: &'a [LogRecord], filters: &ConsoleFilters) -> Vec<&'a LogRecord> {
    records.iter().filter(|r| matches(r, filters)).collect()
}

/// Short level label for `format_line`'s `{:<5}` column: ERROR/DEBUG/TRACE are
/// 5 chars, WARN/INFO are 4 (padded to width by the caller, not here).
fn level_label(level: Level) -> &'static str {
    match level {
        Level::ERROR => "ERROR",
        Level::WARN => "WARN",
        Level::INFO => "INFO",
        Level::DEBUG => "DEBUG",
        Level::TRACE => "TRACE",
    }
}

/// One formatted line: `LEVEL target message` (level left-padded to 5 columns).
pub fn format_line(record: &LogRecord) -> String {
    format!(
        "{:<5} {} {}",
        level_label(record.level),
        record.target,
        record.message
    )
}

/// All currently-displayed records joined into one clipboard string, one
/// formatted line each.
pub fn copy_all(records: &[LogRecord], filters: &ConsoleFilters) -> String {
    displayed(records, filters)
        .iter()
        .map(|r| format_line(r))
        .collect::<Vec<_>>()
        .join("\n")
}

/// True when a scrollable's relative vertical offset is close enough to the
/// bottom to count as following the tail.
pub fn at_bottom(relative_y: f32) -> bool {
    relative_y >= FOLLOW_THRESHOLD
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::log_buffer::LogRecord;
    use tracing::Level;

    fn rec(level: Level, target: &str, message: &str) -> LogRecord {
        LogRecord {
            seq: 0,
            level,
            target: target.into(),
            message: message.into(),
        }
    }

    #[test]
    fn min_level_warn_shows_error_and_warn_hides_less_severe() {
        let f = ConsoleFilters {
            min_level: Level::WARN,
            ..Default::default()
        };
        assert!(
            matches(&rec(Level::ERROR, "t", "m"), &f),
            "ERROR more severe"
        );
        assert!(
            matches(&rec(Level::WARN, "t", "m"), &f),
            "WARN at threshold"
        );
        assert!(
            !matches(&rec(Level::INFO, "t", "m"), &f),
            "INFO less severe"
        );
        assert!(!matches(&rec(Level::DEBUG, "t", "m"), &f));
        assert!(!matches(&rec(Level::TRACE, "t", "m"), &f));
    }

    #[test]
    fn default_filters_show_every_level() {
        let f = ConsoleFilters::default();
        for lvl in LEVEL_CHOICES {
            assert!(
                matches(&rec(lvl, "t", "m"), &f),
                "{lvl} should pass default"
            );
        }
    }

    #[test]
    fn target_and_search_are_substring_filters() {
        let ft = ConsoleFilters {
            target_filter: "core".into(),
            ..Default::default()
        };
        assert!(matches(&rec(Level::INFO, "paksmith_core::pak", "m"), &ft));
        assert!(!matches(&rec(Level::INFO, "paksmith_gui::app", "m"), &ft));

        let fs = ConsoleFilters {
            search: "decode".into(),
            ..Default::default()
        };
        assert!(matches(&rec(Level::INFO, "t", "texture decode ok"), &fs));
        assert!(!matches(&rec(Level::INFO, "t", "open ok"), &fs));
    }

    #[test]
    fn displayed_keeps_capture_order_after_filtering() {
        let records = vec![
            rec(Level::INFO, "a", "1"),
            rec(Level::DEBUG, "b", "2"),
            rec(Level::ERROR, "c", "3"),
        ];
        let f = ConsoleFilters {
            min_level: Level::INFO,
            ..Default::default()
        };
        let shown = displayed(&records, &f);
        let targets: Vec<&str> = shown.iter().map(|r| r.target.as_str()).collect();
        assert_eq!(targets, vec!["a", "c"]); // DEBUG dropped, order preserved
    }

    #[test]
    fn level_label_covers_all_five_levels() {
        assert_eq!(level_label(Level::ERROR), "ERROR");
        assert_eq!(level_label(Level::WARN), "WARN");
        assert_eq!(level_label(Level::INFO), "INFO");
        assert_eq!(level_label(Level::DEBUG), "DEBUG");
        assert_eq!(level_label(Level::TRACE), "TRACE");
    }

    #[test]
    fn format_line_is_padded_level_target_message() {
        assert_eq!(
            format_line(&rec(Level::WARN, "paksmith_core", "low disk")),
            "WARN  paksmith_core low disk"
        );
        assert_eq!(format_line(&rec(Level::ERROR, "x", "boom")), "ERROR x boom");
    }

    #[test]
    fn copy_all_joins_displayed_lines_with_newlines() {
        let records = vec![
            rec(Level::INFO, "a", "first"),
            rec(Level::TRACE, "b", "skipme"),
            rec(Level::ERROR, "c", "second"),
        ];
        let f = ConsoleFilters {
            min_level: Level::INFO,
            ..Default::default()
        };
        assert_eq!(copy_all(&records, &f), "INFO  a first\nERROR c second");
    }

    #[test]
    fn at_bottom_is_exact_at_the_follow_threshold() {
        assert!(at_bottom(1.0));
        assert!(at_bottom(0.999));
        assert!(!at_bottom(0.99));
        assert!(!at_bottom(0.3));
        assert!(!at_bottom(0.0));
    }
}
