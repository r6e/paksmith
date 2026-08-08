//! Process-memory reading and formatting for the status bar (#661).
//!
//! The status bar shows the process's resident set size, refreshed on a
//! coarse tick ([`MEMORY_TICK`]). The read is one cheap platform call via
//! the `memory-stats` crate — `task_info` on macOS, a single small
//! `/proc/self/statm` read on Linux (the `always_use_statm` feature; see the
//! Cargo.toml note for why the crate's smaps default is wrong here), and
//! `GetProcessMemoryInfo` on Windows — so the recurring cost is the tick,
//! not the measurement.

use std::time::Duration;

/// How often the status bar re-reads the process RSS.
///
/// Coarse on purpose (the acceptance criterion is "refreshed on a coarse
/// tick"): memory usage is a trend indicator, not a live meter, and every
/// tick redraws the UI. Two seconds keeps the number honest without joining
/// the fast tick tiers (console 250 ms–1 s, audio 100 ms).
pub const MEMORY_TICK: Duration = Duration::from_secs(2);

/// The process's current resident set size in bytes, or `None` where the
/// platform backend has no reading (the label hides rather than guessing).
#[must_use]
pub fn read_rss() -> Option<usize> {
    memory_stats::memory_stats().map(|m| m.physical_mem)
}

/// Binary units for [`memory_label`]'s ladder — module-scope so the boundary
/// tests probe the SAME thresholds the ladder compares against, not a shadow
/// copy that could drift.
const KIB: usize = 1024;
const MIB: usize = 1024 * KIB;
const GIB: usize = 1024 * MIB;

/// Status-bar text for an RSS reading, `None` when there is none to show.
///
/// Fractional binary units, because neither sibling formatter fits: the hex
/// view's [`crate::state::hex_view::binary_size_label`] promotes units only
/// for EXACT multiples, and a real RSS — page-aligned, so a whole KiB count
/// but almost never a whole MiB — falls to its KiB arm and renders as an
/// unreadable flat figure (148 238 336 → "144764 KiB" where this fn says
/// "141.4 MiB"); `panels::detail`'s `human_size` is DECIMAL with a truncated
/// digit (a 512 MiB process reads "536.8 MB"). A memory meter wants binary
/// units with a stable width, so: one-decimal MiB / two-decimal GiB.
#[must_use]
pub fn memory_label(rss: Option<usize>) -> Option<String> {
    // Display-only f64 casts: an RSS is far below 2^53, so the cast is exact.
    #[allow(clippy::cast_precision_loss)]
    rss.map(|b| match b {
        b if b >= GIB => format!("Mem: {:.2} GiB", b as f64 / GIB as f64),
        b if b >= MIB => format!("Mem: {:.1} MiB", b as f64 / MIB as f64),
        b => format!("Mem: {} KiB", b / KIB),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_rss_reports_a_positive_reading_on_supported_platforms() {
        // Positive control for the dependency's capability on every platform
        // CI runs (macOS, Linux, Windows): a live process's RSS is never 0.
        // If this fails, the backend is broken — the label would silently
        // hide and nothing else in the suite would notice.
        assert!(
            read_rss().is_some_and(|b| b > 0),
            "read_rss must report a positive RSS on macOS/Linux/Windows"
        );
    }

    #[test]
    fn memory_label_hides_when_there_is_no_reading() {
        assert_eq!(memory_label(None), None);
    }

    #[test]
    fn memory_label_formats_mib_with_one_decimal() {
        // 100.5 MiB exactly — no rounding ambiguity in the pinned string.
        assert_eq!(
            memory_label(Some(100 * MIB + MIB / 2)).as_deref(),
            Some("Mem: 100.5 MiB")
        );
    }

    #[test]
    fn memory_label_formats_gib_with_two_decimals() {
        assert_eq!(
            memory_label(Some(3 * GIB / 2)).as_deref(),
            Some("Mem: 1.50 GiB")
        );
    }

    #[test]
    fn memory_label_unit_boundaries_are_inclusive_at_the_larger_unit() {
        // Exactly 1 GiB takes the GiB arm; one byte below stays MiB.
        // Kills `>=` → `>` on the GiB threshold.
        assert_eq!(memory_label(Some(GIB)).as_deref(), Some("Mem: 1.00 GiB"));
        assert_eq!(
            memory_label(Some(GIB - 1)).as_deref(),
            Some("Mem: 1024.0 MiB")
        );
        // Same pair for the MiB threshold.
        assert_eq!(memory_label(Some(MIB)).as_deref(), Some("Mem: 1.0 MiB"));
        assert_eq!(
            memory_label(Some(MIB - 1)).as_deref(),
            Some("Mem: 1023 KiB")
        );
    }

    #[test]
    fn memory_label_sub_mib_readings_render_as_whole_kib() {
        // Unreachable for a real GUI process but pins the floor of the
        // ladder: no decimals, no unit promotion, zero stays zero.
        assert_eq!(
            memory_label(Some(512 * KIB)).as_deref(),
            Some("Mem: 512 KiB")
        );
        assert_eq!(memory_label(Some(0)).as_deref(), Some("Mem: 0 KiB"));
    }

    #[test]
    fn memory_tick_is_coarse() {
        // Pins the acceptance criterion: a coarse tick, not a fast tier.
        // (Constants aren't mutation targets; this guards human edits.)
        assert_eq!(MEMORY_TICK, Duration::from_secs(2));
    }
}
