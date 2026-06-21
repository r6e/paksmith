//! File-tree widget: renders the pure `Tree` model as an interactive,
//! scrollable, keyboard-navigable tree.
//!
//! # Virtualization note
//!
//! `Tree::visible_rows()` already contains ONLY currently-expanded nodes, so
//! fully-collapsed sub-trees contribute a single row (their dir). The slice is
//! rendered directly inside a `scrollable` + `column`. This is the pragmatic
//! Phase 6 approach.
//!
//! **Known limitation:** if the user expands all directories of a very large
//! archive (e.g. 100k entries, all expanded), `visible_rows()` will return
//! 100k+ elements and each one is built into an Iced widget during every frame.
//! True viewport virtualization (rendering only on-screen rows via a custom Iced
//! `Widget`) is a follow-up item tracked in the performance review. For typical
//! usage patterns (explore-by-navigation, not expand-all), the scrollable slice
//! is bounded and the overhead is negligible.

use iced::widget::{button, column, scrollable, text};
use iced::{Background, Color, Element, Length};

use crate::app::Message;
use crate::state::tree::{Tree, VisibleRow};
use crate::theme::tokens;

// ── pure helpers ──────────────────────────────────────────────────────────────

/// Pixel indent for a tree node at the given depth.
///
/// Uses `tokens::SPACE_MD` as the per-level step so the design scale is the
/// single source of truth.
pub fn row_indent(depth: usize) -> f32 {
    // Depth values in practice are small (< a few hundred even in pathological
    // trees), so the precision loss from usize→f32 is inconsequential.
    #[allow(clippy::cast_precision_loss)]
    let depth_f32 = depth as f32;
    depth_f32 * tokens::SPACE_MD
}

/// The glyph string rendered before the label for a given row.
///
/// Directories show a caret (▸ collapsed, ▾ expanded); files show a page icon.
pub fn glyph_for_row(row: &VisibleRow) -> &'static str {
    if row.is_dir {
        if row.expanded { "▾" } else { "▸" }
    } else {
        "·"
    }
}

// ── view ─────────────────────────────────────────────────────────────────────

/// Renders `tree.visible_rows()` as a scrollable column of interactive rows.
///
/// # Arguments
///
/// * `tree` — the pure tree model.
/// * `accent` — the system accent color; used for the selection highlight.
/// * `selected_row` — the currently highlighted visible-row index (the
///   keyboard cursor).  May point at either a dir or a file.  `None` means
///   no cursor.
///
/// Each row emits:
/// * `Message::RowToggled(i)` when a directory row is clicked.
/// * `Message::RowSelected(i)` when a file row is clicked.
pub fn view(tree: &Tree, accent: Color, selected_row: Option<usize>) -> Element<'_, Message> {
    let rows = tree.visible_rows();
    let items: Vec<Element<'_, Message>> = rows
        .iter()
        .enumerate()
        .map(|(i, row)| build_row(i, row, accent, selected_row))
        .collect();

    scrollable(column(items).spacing(0).width(Length::Fill))
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}

/// Build one row widget.
fn build_row(
    i: usize,
    row: &VisibleRow,
    accent: Color,
    selected_row: Option<usize>,
) -> Element<'_, Message> {
    let is_selected = selected_row == Some(i);
    let indent = row_indent(row.depth);
    let glyph = glyph_for_row(row);

    // The row content: indent spacer + glyph + label.
    let content = iced::widget::row![
        iced::widget::Space::new().width(indent),
        text(glyph)
            .size(f32::from(tokens::TEXT_MD))
            .style(move |theme: &iced::Theme| iced::widget::text::Style {
                color: Some(theme.palette().text),
            }),
        iced::widget::Space::new().width(tokens::SPACE_XS),
        text(row.label.as_str())
            .size(f32::from(tokens::TEXT_MD))
            .style(move |theme: &iced::Theme| iced::widget::text::Style {
                color: Some(theme.palette().text),
            }),
    ]
    .align_y(iced::Alignment::Center);

    // Choose the message to emit when clicked.
    let message = if row.is_dir {
        Message::RowToggled(i)
    } else {
        Message::RowSelected(i)
    };

    // Wrap the content in a button so we get hover feedback and click handling.
    // The button is styled to look like a flat tree row, with an accent tint
    // for the selected state.
    let btn = button(content)
        .on_press(message)
        .padding([2.0_f32, tokens::SPACE_SM])
        .width(Length::Fill)
        .style(move |theme: &iced::Theme, status| {
            let palette = theme.palette();
            let base = iced::widget::button::Style {
                background: None,
                text_color: palette.text,
                border: iced::Border::default(),
                shadow: iced::Shadow::default(),
                snap: false,
            };
            if is_selected {
                iced::widget::button::Style {
                    background: Some(Background::Color(accent.scale_alpha(0.18))),
                    ..base
                }
            } else {
                match status {
                    iced::widget::button::Status::Hovered
                    | iced::widget::button::Status::Pressed => iced::widget::button::Style {
                        background: Some(Background::Color(palette.text.scale_alpha(0.07))),
                        ..base
                    },
                    _ => base,
                }
            }
        });

    btn.into()
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::tree::VisibleRow;

    #[test]
    fn indent_grows_with_depth() {
        assert!(row_indent(2) > row_indent(1) && row_indent(1) > row_indent(0));
    }

    #[test]
    fn indent_depth_zero_is_zero() {
        #[allow(clippy::float_cmp)]
        {
            assert_eq!(row_indent(0), 0.0_f32);
        }
    }

    #[test]
    fn indent_is_linear() {
        // Each level adds exactly SPACE_MD pixels.
        #[allow(clippy::float_cmp)]
        {
            assert_eq!(row_indent(3) - row_indent(2), tokens::SPACE_MD);
        }
    }

    fn dir_row(expanded: bool) -> VisibleRow {
        VisibleRow {
            depth: 0,
            label: "Dir".to_string(),
            is_dir: true,
            expanded,
            full_path: None,
        }
    }

    fn file_row() -> VisibleRow {
        VisibleRow {
            depth: 1,
            label: "file.txt".to_string(),
            is_dir: false,
            expanded: false,
            full_path: Some("Dir/file.txt".to_string()),
        }
    }

    #[test]
    fn glyph_collapsed_dir() {
        assert_eq!(glyph_for_row(&dir_row(false)), "▸");
    }

    #[test]
    fn glyph_expanded_dir() {
        assert_eq!(glyph_for_row(&dir_row(true)), "▾");
    }

    #[test]
    fn glyph_file() {
        assert_eq!(glyph_for_row(&file_row()), "·");
    }
}
