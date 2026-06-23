//! Hex-dump widget: renders a byte slice as an interactive hex editor view
//! with click-drag byte selection and copy-to-clipboard.
//!
//! # Byte-cap note
//!
//! The view renders the bytes it receives, which are already bounded to
//! [`crate::task::asset::HEX_BYTES_CAP`] at read time. When the entry was
//! larger than the cap, `truncated = true` is passed to [`view`] and a muted
//! note is shown in the toolbar. True viewport virtualization (rendering only
//! on-screen rows via a custom iced `Widget`) is a follow-up item.

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

/// Build a toolbar copy button, enabled only when `enabled` is true.
///
/// When `enabled` the button emits `msg` on press; otherwise it renders
/// without an `on_press` handler (visually disabled).
#[mutants::skip]
fn copy_toolbar_button(
    label: &str,
    msg: Message,
    enabled: bool,
) -> iced::widget::Button<'_, Message> {
    let b = button(
        text(label)
            .size(f32::from(tokens::TEXT_SM))
            .font(Font::MONOSPACE),
    )
    .style(iced::widget::button::secondary)
    .padding([tokens::SPACE_XS, tokens::SPACE_SM]);
    if enabled { b.on_press(msg) } else { b }
}

/// Render a hex dump of `bytes` as a scrollable, selectable grid.
///
/// `bytes` is already bounded to [`crate::task::asset::HEX_BYTES_CAP`] at read
/// time; all bytes are rendered without further slicing.  When `truncated` is
/// `true` the toolbar shows a muted note that the entry is larger than the cap.
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
#[allow(clippy::too_many_lines)]
pub fn view<'a>(
    bytes: &'a [u8],
    truncated: bool,
    hex: &'a HexState,
    accent: iced::Color,
) -> Element<'a, Message> {
    // ── copy toolbar ─────────────────────────────────────────────────────────
    let has_sel = hex.selection.is_some();

    let copy_hex_btn = copy_toolbar_button("Copy hex", Message::HexCopyRequested, has_sel);
    let copy_ascii_btn = copy_toolbar_button("Copy ASCII", Message::HexCopyAsciiRequested, has_sel);

    let mut toolbar_items: Vec<Element<'_, Message>> =
        vec![copy_hex_btn.into(), copy_ascii_btn.into()];
    if truncated {
        toolbar_items.push(
            text(format!(
                "Showing the first {} KiB \u{2014} entry is larger; see Info for the full size or extract it",
                crate::task::asset::HEX_BYTES_CAP / 1024,
            ))
            .size(f32::from(tokens::TEXT_SM))
            .style(|theme: &iced::Theme| iced::widget::text::Style {
                color: Some(theme.palette().text.scale_alpha(tokens::TEXT_MUTED_ALPHA)),
            })
            .into(),
        );
    }

    let toolbar = row(toolbar_items)
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

        // Hex cells — interactive: on_press always; on_enter only while dragging
        // to avoid a full view rebuild on every plain hover.
        let mut hex_cells: Vec<Element<'_, Message>> = Vec::with_capacity(BYTES_PER_ROW);
        for (col, &b) in row_slice.iter().enumerate() {
            let byte_idx = row_start + col;
            let is_selected = hex.selection.is_some_and(|s| s.contains(byte_idx));
            let cell = hex_byte_cell(
                byte_cell_text(b),
                byte_idx,
                is_selected,
                hex.dragging,
                accent,
            );
            hex_cells.push(cell);
        }
        // Pad short final rows so the ASCII column stays aligned.
        // The container wrapping must match `hex_byte_cell` exactly (same padding,
        // same font, same 2-char width) so the gutter widths stay consistent.
        for _ in row_slice.len()..BYTES_PER_ROW {
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

        // ASCII cells — display only: no on_press, no on_enter.
        // Selection is driven by the hex column; ASCII mirrors the highlight.
        let mut ascii_cells: Vec<Element<'_, Message>> = Vec::with_capacity(BYTES_PER_ROW);
        for (col, &b) in row_slice.iter().enumerate() {
            let byte_idx = row_start + col;
            let is_selected = hex.selection.is_some_and(|s| s.contains(byte_idx));
            let ch = ascii_cell_char(b).to_string();
            let cell = ascii_display_cell(ch, is_selected, accent);
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
        .spacing(tokens::SPACE_XS)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}

/// Build a styled container for a byte cell with selection highlight.
///
/// Selected cells use a stronger tint (0.30 alpha) plus a 1px accent border so
/// the selection is unambiguous on both light and dark themes and any system accent.
#[mutants::skip]
fn styled_byte_container<'a>(
    label: String,
    is_selected: bool,
    accent: iced::Color,
) -> iced::widget::Container<'a, Message> {
    let cell_text = text(label)
        .font(Font::MONOSPACE)
        .size(f32::from(tokens::TEXT_SM));

    container(cell_text)
        .padding([0.0, tokens::SPACE_XS / 2.0])
        .style(move |_theme: &iced::Theme| {
            if is_selected {
                iced::widget::container::Style {
                    background: Some(Background::Color(accent.scale_alpha(0.30))),
                    border: iced::Border {
                        color: accent,
                        width: 1.0,
                        radius: 0.0.into(),
                    },
                    ..Default::default()
                }
            } else {
                iced::widget::container::Style::default()
            }
        })
}

/// Build an interactive hex-column byte cell.
///
/// `on_press` is always attached; `on_enter` is attached ONLY while `dragging`
/// is true to avoid rebuilding the full view on every plain hover.
#[mutants::skip]
fn hex_byte_cell<'a>(
    label: String,
    byte_idx: usize,
    is_selected: bool,
    dragging: bool,
    accent: iced::Color,
) -> Element<'a, Message> {
    let cell_container = styled_byte_container(label, is_selected, accent);
    let ma = mouse_area(cell_container).on_press(Message::HexBytePressed(byte_idx));
    if dragging {
        ma.on_enter(Message::HexByteEntered(byte_idx)).into()
    } else {
        ma.into()
    }
}

/// Build a display-only ASCII-column cell (no press/enter handlers).
///
/// Selection is driven by the hex column; ASCII mirrors the highlight via
/// `is_selected`. No `mouse_area` wrapper — halves drag message volume and
/// eliminates ASCII-column hover rebuilds.
#[mutants::skip]
fn ascii_display_cell<'a>(
    label: String,
    is_selected: bool,
    accent: iced::Color,
) -> Element<'a, Message> {
    styled_byte_container(label, is_selected, accent).into()
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
