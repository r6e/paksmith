//! Shared detail-pane helpers — `human_size`, `compression_ratio`, and
//! `kv_row`.
//!
//! The original `view`/`empty_detail`/`entry_detail` functions that composed
//! the Phase 6 detail pane were retired in Phase 7a when the tabbed content
//! host (`panels::content`) took over.  The three pure helpers remain because
//! `panels::content`'s Info view imports them directly.

use iced::widget::{row, text};
use iced::{Element, Length};

use crate::app::Message;
use crate::theme::tokens::{DETAIL_LABEL_WIDTH, SPACE_XS, TEXT_MUTED_ALPHA, TEXT_SM};

// ── pure helpers ──────────────────────────────────────────────────────────────

/// Format a byte count as a human-readable decimal string.
///
/// Uses SI (decimal) prefixes (1 KB = 1000 B) to match the test cases in the
/// task brief (`2_400_000 → "2.4 MB"`).
///
/// Boundaries:
/// - < 1 000 B → "N B"
/// - < 1 000 000 B → "N.N KB"
/// - < 1 000 000 000 B → "N.N MB"
/// - ≥ 1 000 000 000 B → "N.N GB"
pub fn human_size(bytes: u64) -> String {
    const KB: u64 = 1_000;
    const MB: u64 = 1_000_000;
    const GB: u64 = 1_000_000_000;

    if bytes < KB {
        format!("{bytes} B")
    } else if bytes < MB {
        let whole = bytes / KB;
        let frac = (bytes % KB) / 100; // one decimal digit
        if frac == 0 {
            format!("{whole} KB")
        } else {
            format!("{whole}.{frac} KB")
        }
    } else if bytes < GB {
        let whole = bytes / MB;
        let frac = (bytes % MB) / 100_000; // one decimal digit
        if frac == 0 {
            format!("{whole} MB")
        } else {
            format!("{whole}.{frac} MB")
        }
    } else {
        let whole = bytes / GB;
        let frac = (bytes % GB) / 100_000_000; // one decimal digit
        if frac == 0 {
            format!("{whole} GB")
        } else {
            format!("{whole}.{frac} GB")
        }
    }
}

/// Format the compression ratio as "N%" (rounded to nearest integer).
///
/// Returns `None` when `uncompressed == 0` to avoid division by zero.
pub fn compression_ratio(uncompressed: u64, compressed: u64) -> Option<String> {
    if uncompressed == 0 {
        return None;
    }
    // Ratio = compressed/uncompressed * 100, clamped to [0, 100].
    // u64 → f64 may lose precision for large sizes (> 2^53 bytes), but
    // ratios at that scale are still meaningfully accurate.
    // `round()` + `clamp(0.0, 100.0)` guarantees the value fits in [0, 100]
    // before the cast, so cast_possible_truncation and cast_sign_loss are safe.
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    let pct = (compressed as f64 / uncompressed as f64 * 100.0)
        .round()
        .clamp(0.0, 100.0) as u64;
    Some(format!("{pct}%"))
}

/// Build one key/value row in the metadata panel.
///
/// Both key and value are taken as owned `String` so the returned element
/// is `'static` — the caller doesn't need to keep them alive beyond the call.
pub(crate) fn kv_row(
    key: impl Into<String>,
    value: impl Into<String>,
) -> Element<'static, Message> {
    row![
        text(key.into())
            .size(f32::from(TEXT_SM))
            .width(Length::Fixed(DETAIL_LABEL_WIDTH))
            .style(|theme: &iced::Theme| iced::widget::text::Style {
                color: Some(theme.palette().text.scale_alpha(TEXT_MUTED_ALPHA)),
            }),
        // `.width(Fill)` lets long paths wrap instead of overflowing the pane.
        text(value.into())
            .size(f32::from(TEXT_SM))
            .width(Length::Fill)
            .style(|theme: &iced::Theme| iced::widget::text::Style {
                color: Some(theme.palette().text),
            }),
    ]
    .spacing(SPACE_XS)
    .align_y(iced::Alignment::Start)
    .into()
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── brief-specified tests (verbatim) ──────────────────────────────────────

    #[test]
    fn formats_size_human_readable() {
        assert_eq!(human_size(2_400_000), "2.4 MB");
        assert_eq!(human_size(512), "512 B");
    }

    // ── additional coverage ───────────────────────────────────────────────────

    #[test]
    fn human_size_zero() {
        assert_eq!(human_size(0), "0 B");
    }

    #[test]
    fn human_size_exact_kb() {
        // 1000 B → "1 KB" (no decimal when frac is 0)
        assert_eq!(human_size(1_000), "1 KB");
    }

    #[test]
    fn human_size_kb_with_decimal() {
        // 1500 B → "1.5 KB"
        assert_eq!(human_size(1_500), "1.5 KB");
    }

    #[test]
    fn human_size_exact_mb() {
        assert_eq!(human_size(1_000_000), "1 MB");
    }

    #[test]
    fn human_size_gb() {
        assert_eq!(human_size(2_500_000_000), "2.5 GB");
    }

    #[test]
    fn human_size_just_below_kb() {
        assert_eq!(human_size(999), "999 B");
    }

    // ── compression ratio tests ───────────────────────────────────────────────

    #[test]
    fn ratio_zero_uncompressed_returns_none() {
        assert_eq!(compression_ratio(0, 0), None);
    }

    #[test]
    fn ratio_half() {
        assert_eq!(compression_ratio(1000, 500), Some("50%".to_string()));
    }

    #[test]
    fn ratio_capped_at_100() {
        // compressed > uncompressed (e.g. incompressible data) → clamped to 100%
        assert_eq!(compression_ratio(100, 150), Some("100%".to_string()));
    }

    #[test]
    fn ratio_identical_is_100() {
        assert_eq!(compression_ratio(1000, 1000), Some("100%".to_string()));
    }

    // ── human_size boundary mutant killers ────────────────────────────────────
    //
    // The surviving mutant replaces `< KB` with `<= KB` (and analogously for MB
    // and GB). At the exact boundary (e.g., 1_000) the correct behaviour is to
    // format as "1 KB"; the `<=` mutant would format 1_000 as "1000 B" (stays
    // in the bytes branch). Asserting both `value - 1` and `value` at each
    // threshold distinguishes `<` from `<=`.

    #[test]
    fn human_size_kb_boundary() {
        // 999 → bytes (< 1000); 1000 → KB (NOT bytes).
        assert_eq!(human_size(999), "999 B", "999 must stay in bytes");
        assert_eq!(human_size(1_000), "1 KB", "1000 must flip to KB");
    }

    #[test]
    fn human_size_mb_boundary() {
        // 999_999 → KB; 1_000_000 → MB.
        assert_eq!(human_size(999_999), "999.9 KB", "999_999 must still be KB");
        assert_eq!(human_size(1_000_000), "1 MB", "1_000_000 must flip to MB");
    }

    #[test]
    fn human_size_gb_boundary() {
        // 999_999_999 → MB; 1_000_000_000 → GB.
        assert_eq!(
            human_size(999_999_999),
            "999.9 MB",
            "999_999_999 must still be MB"
        );
        assert_eq!(
            human_size(1_000_000_000),
            "1 GB",
            "1_000_000_000 must flip to GB"
        );
    }
}
