//! Hex-dump widget: renders a byte slice as an interactive hex editor view
//! with click-drag byte selection and copy-to-clipboard.
//!
//! # Virtualization note
//!
//! All rows in `total_rows(bytes.len())` are built into iced widgets on each
//! frame; for typical asset sizes (< a few MB) this is negligible. For very
//! large files (e.g. > 50 MB), each frame may build tens of thousands of rows.
//! True viewport virtualization (rendering only on-screen rows via a custom
//! iced `Widget`) is a follow-up item. For Phase 7a asset sizes, the scrollable
//! column is bounded and the overhead is acceptable.

use iced::widget::{button, column, container, mouse_area, row, scrollable, text};
use iced::{Background, Element, Font, Length};

use crate::app::Message;
use crate::state::hex_view::{BYTES_PER_ROW, HexState, row_bytes, total_rows};
use crate::theme::tokens;

// ── pure helpers ──────────────────────────────────────────────────────────────

/// 8-digit uppercase hex label for the first byte of the given row.
///
/// `offset_label(0)` → `"00000000"`, `offset_label(1)` → `"00000010"`.
#[must_use]
pub fn offset_label(row: usize) -> String {
    format!("{:08X}", row * BYTES_PER_ROW)
}

/// Two-digit uppercase hex representation of a byte.
///
/// `byte_cell_text(0x0a)` → `"0A"`, `byte_cell_text(0xff)` → `"FF"`.
#[must_use]
pub fn byte_cell_text(b: u8) -> String {
    format!("{b:02X}")
}

/// Printable ASCII character for a byte, or `'.'` for non-printable bytes.
///
/// Printable range: `0x20..0x7f` (space through tilde).  Everything outside
/// (control chars, DEL, and non-ASCII) maps to `'.'`.
#[must_use]
pub fn ascii_cell_char(b: u8) -> char {
    if (0x20..0x7f).contains(&b) {
        b as char
    } else {
        '.'
    }
}

// ── view ──────────────────────────────────────────────────────────────────────

/// Render a hex dump of `bytes` as a scrollable, selectable grid.
///
/// Each row shows: an 8-digit offset gutter, 16 hex-cell columns, and 16
/// ASCII-cell columns.  Byte cells in the current selection get an accent-tint
/// background.  Monospace font is applied to all cells so columns align.
///
/// Above the grid, a "Copy hex" / "Copy ASCII" button pair emits
/// [`Message::HexCopyRequested`] / [`Message::HexCopyAsciiRequested`]; both
/// buttons are disabled (no `on_press`) when there is no active selection.
///
/// `accent` is the system accent colour, used to tint selected byte cells.
#[mutants::skip]
pub fn view<'a>(bytes: &'a [u8], hex: &'a HexState, accent: iced::Color) -> Element<'a, Message> {
    // ── copy toolbar ─────────────────────────────────────────────────────────
    let has_sel = hex.selection.is_some();

    let copy_hex_btn = {
        let b = button(
            text("Copy hex")
                .size(f32::from(tokens::TEXT_SM))
                .font(Font::MONOSPACE),
        )
        .style(iced::widget::button::secondary)
        .padding([tokens::SPACE_XS, tokens::SPACE_SM]);
        if has_sel {
            b.on_press(Message::HexCopyRequested)
        } else {
            b
        }
    };

    let copy_ascii_btn = {
        let b = button(
            text("Copy ASCII")
                .size(f32::from(tokens::TEXT_SM))
                .font(Font::MONOSPACE),
        )
        .style(iced::widget::button::secondary)
        .padding([tokens::SPACE_XS, tokens::SPACE_SM]);
        if has_sel {
            b.on_press(Message::HexCopyAsciiRequested)
        } else {
            b
        }
    };

    let toolbar = row![copy_hex_btn, copy_ascii_btn]
        .spacing(tokens::SPACE_SM)
        .padding([tokens::SPACE_XS, tokens::SPACE_MD]);

    // ── hex grid ──────────────────────────────────────────────────────────────
    let n_rows = total_rows(bytes.len());
    let mut grid_rows: Vec<Element<'_, Message>> = Vec::with_capacity(n_rows);

    for r in 0..n_rows {
        let row_slice = row_bytes(bytes, r);
        let row_start = r * BYTES_PER_ROW;

        // Offset gutter.
        let gutter = text(offset_label(r))
            .font(Font::MONOSPACE)
            .size(f32::from(tokens::TEXT_SM))
            .style(|theme: &iced::Theme| iced::widget::text::Style {
                color: Some(theme.palette().text.scale_alpha(tokens::TEXT_MUTED_ALPHA)),
            });

        // Hex cells.
        let mut hex_cells: Vec<Element<'_, Message>> = Vec::with_capacity(BYTES_PER_ROW);
        for (col, &b) in row_slice.iter().enumerate() {
            let byte_idx = row_start + col;
            let is_selected = hex.selection.is_some_and(|s| s.contains(byte_idx));
            let cell = byte_cell(byte_cell_text(b), byte_idx, is_selected, accent);
            hex_cells.push(cell);
        }
        // Pad short final rows so the ASCII column stays aligned.
        // The container wrapping must match `byte_cell` exactly (same padding,
        // same font, same 2-char width) so the gutter widths stay consistent.
        for col in row_slice.len()..BYTES_PER_ROW {
            let _ = col;
            hex_cells.push(
                container(
                    text("  ")
                        .font(Font::MONOSPACE)
                        .size(f32::from(tokens::TEXT_SM)),
                )
                .padding([0.0, tokens::SPACE_XS / 2.0])
                .into(),
            );
        }

        // ASCII cells.
        let mut ascii_cells: Vec<Element<'_, Message>> = Vec::with_capacity(BYTES_PER_ROW);
        for (col, &b) in row_slice.iter().enumerate() {
            let byte_idx = row_start + col;
            let is_selected = hex.selection.is_some_and(|s| s.contains(byte_idx));
            let ch = ascii_cell_char(b).to_string();
            let cell = byte_cell(ch, byte_idx, is_selected, accent);
            ascii_cells.push(cell);
        }

        let grid_row: Element<'_, Message> = row(std::iter::once(gutter.into())
            .chain(std::iter::once(
                iced::widget::Space::new().width(tokens::SPACE_MD).into(),
            ))
            .chain(hex_cells)
            .chain(std::iter::once(
                iced::widget::Space::new().width(tokens::SPACE_MD).into(),
            ))
            .chain(ascii_cells)
            .collect::<Vec<_>>())
        .align_y(iced::Alignment::Center)
        .into();

        grid_rows.push(grid_row);
    }

    let grid = scrollable(
        column(grid_rows)
            .spacing(0)
            .padding([tokens::SPACE_XS, tokens::SPACE_MD])
            .width(Length::Fill),
    )
    .width(Length::Fill)
    .height(Length::Fill);

    column![toolbar, grid]
        .spacing(0)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}

/// Build a single interactive byte cell (hex or ASCII) with optional selection highlight.
///
/// Wraps a monospaced `text` cell in a uniform `container` (same padding
/// selected vs. unselected so column widths don't jitter) then in a
/// `mouse_area` that emits press/enter events.
#[mutants::skip]
fn byte_cell<'a>(
    label: String,
    byte_idx: usize,
    is_selected: bool,
    accent: iced::Color,
) -> Element<'a, Message> {
    let cell_text = text(label)
        .font(Font::MONOSPACE)
        .size(f32::from(tokens::TEXT_SM));

    // Wrap in a container with uniform padding; vary only the background.
    let cell_container = container(cell_text)
        .padding([0.0, tokens::SPACE_XS / 2.0])
        .style(move |_theme: &iced::Theme| {
            if is_selected {
                iced::widget::container::Style {
                    background: Some(Background::Color(accent.scale_alpha(0.18))),
                    ..Default::default()
                }
            } else {
                iced::widget::container::Style::default()
            }
        });

    mouse_area(cell_container)
        .on_press(Message::HexBytePressed(byte_idx))
        .on_enter(Message::HexByteEntered(byte_idx))
        .into()
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offset_label_is_8_digit_hex_of_row_start() {
        assert_eq!(offset_label(0), "00000000");
        assert_eq!(offset_label(1), "00000010"); // row 1 → byte 16
        assert_eq!(offset_label(16), "00000100");
    }

    #[test]
    fn ascii_cell_char_dots_nonprintable() {
        assert_eq!(ascii_cell_char(b'A'), 'A');
        assert_eq!(ascii_cell_char(0x00), '.');
        assert_eq!(ascii_cell_char(0x7f), '.');
    }

    #[test]
    fn byte_cell_text_is_two_digit_upper() {
        assert_eq!(byte_cell_text(0x0a), "0A");
        assert_eq!(byte_cell_text(0xff), "FF");
    }

    #[test]
    fn offset_label_row_zero_is_all_zeros() {
        // Explicit: kills a `row * BYTES_PER_ROW` → `row + BYTES_PER_ROW` mutant.
        assert_eq!(offset_label(0), "00000000");
    }

    #[test]
    fn offset_label_grows_by_16_per_row() {
        // Row 2 must be 32 (0x20), not row 1's 16 (0x10) — kills `+ with *`.
        assert_eq!(offset_label(2), "00000020");
        assert_ne!(offset_label(2), offset_label(1));
    }

    #[test]
    fn ascii_cell_char_space_is_printable() {
        // 0x20 (space) is the lower inclusive bound — must NOT be '.'.
        assert_eq!(ascii_cell_char(0x20), ' ');
    }

    #[test]
    fn ascii_cell_char_tilde_is_printable() {
        // 0x7e (tilde) is the last printable char in the range.
        assert_eq!(ascii_cell_char(0x7e), '~');
    }

    #[test]
    fn byte_cell_text_zero_is_padded() {
        // 0x00 must yield "00", not "0" — kills a format padding mutation.
        assert_eq!(byte_cell_text(0x00), "00");
    }
}
