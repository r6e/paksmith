//! Detail pane — shows per-entry metadata for the selected file.
//!
//! When no file is selected, renders a muted placeholder. When a file is
//! selected, shows its path, sizes (human-formatted), compression status, and
//! encryption status as a clean key/value metadata panel.
//!
//! This pane is the Phase 7 viewer host — metadata only for Phase 6.

use iced::widget::{column, container, row, text};
use iced::{Element, Length};

use crate::app::Message;
use crate::state::archive::EntryMeta;
use crate::theme::tokens::{SPACE_LG, SPACE_SM, SPACE_XS, TEXT_MD, TEXT_SM};

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

// ── view ─────────────────────────────────────────────────────────────────────

/// Renders the detail pane for the selected entry.
///
/// `selected` is `Some((full_path, meta))` when a file row is selected and
/// metadata is available, or `None` (no selection, or a directory is selected).
pub fn view(selected: Option<(&str, &EntryMeta)>) -> Element<'static, Message> {
    match selected {
        None => empty_detail(),
        Some((path, meta)) => entry_detail(path, meta),
    }
}

// ── private helpers ───────────────────────────────────────────────────────────

fn empty_detail() -> Element<'static, Message> {
    container(
        text("Select a file to inspect")
            .size(f32::from(TEXT_MD))
            .style(|theme: &iced::Theme| iced::widget::text::Style {
                color: Some(theme.palette().text.scale_alpha(0.45)),
            }),
    )
    .center_x(Length::Fill)
    .center_y(Length::Fill)
    .width(Length::Fill)
    .height(Length::Fill)
    .into()
}

fn entry_detail(path: &str, meta: &EntryMeta) -> Element<'static, Message> {
    let ucmp = human_size(meta.uncompressed_size);
    let cmp = human_size(meta.compressed_size);
    let ratio_str = compression_ratio(meta.uncompressed_size, meta.compressed_size)
        .unwrap_or_else(|| "\u{2014}".to_string());

    let compressed_label: String = if meta.is_compressed {
        format!("Yes ({cmp}, {ratio_str})")
    } else {
        "No".to_string()
    };

    let encrypted_label: &str = if meta.is_encrypted { "Yes" } else { "No" };

    let content = column![
        // Path — spans full width, may wrap on long paths.
        kv_row("Path", path.to_owned()),
        kv_row("Size", ucmp),
        kv_row("Compressed", compressed_label),
        kv_row("Encrypted", encrypted_label.to_owned()),
    ]
    .spacing(SPACE_SM);

    container(content)
        .padding(SPACE_LG)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}

/// Build one key/value row in the metadata panel.
///
/// Both key and value are taken as owned `String` so the returned element
/// is `'static` — the caller doesn't need to keep them alive beyond the call.
fn kv_row(key: impl Into<String>, value: impl Into<String>) -> Element<'static, Message> {
    row![
        text(key.into())
            .size(f32::from(TEXT_SM))
            .width(Length::Fixed(120.0))
            .style(|theme: &iced::Theme| iced::widget::text::Style {
                color: Some(theme.palette().text.scale_alpha(0.65)),
            }),
        text(value.into())
            .size(f32::from(TEXT_SM))
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
}
