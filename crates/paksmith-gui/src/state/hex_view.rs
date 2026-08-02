//! Pure hex-view model: row math, click-drag selection, copy formatting.
//! No `iced` imports.

pub const BYTES_PER_ROW: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Selection {
    pub anchor: usize,
    pub cursor: usize,
}

#[derive(Debug, Clone, Default)]
pub struct HexState {
    pub selection: Option<Selection>,
    /// Whether a drag-select is in progress. Invariant: only `true` between a
    /// `press()` and `end_drag()`, during which `selection` is always `Some`.
    pub dragging: bool,
}

#[must_use]
pub fn total_rows(len: usize) -> usize {
    len.div_ceil(BYTES_PER_ROW)
}

/// Render a byte count in binary units, picking the largest whole unit.
///
/// The hex view's truncation note names the cap, and a single fixed tier
/// stops reading naturally as soon as the values outgrow it — the CLI hit
/// that in #93, where a ladder topping out at MiB printed "8192.0 MiB" for
/// 8 GiB. The GUI
/// cannot reuse the CLI's formatter (the crates never share code directly),
/// and the sibling `human_size` in `panels::detail` is DECIMAL, which would
/// render a binary 8 MiB cap as "8.3 MB".
#[must_use]
pub fn binary_size_label(bytes: usize) -> String {
    const KIB: usize = 1024;
    const MIB: usize = 1024 * KIB;
    const GIB: usize = 1024 * MIB;
    match bytes {
        b if b >= GIB && b % GIB == 0 => format!("{} GiB", b / GIB),
        b if b >= MIB && b % MIB == 0 => format!("{} MiB", b / MIB),
        b if b >= KIB && b % KIB == 0 => format!("{} KiB", b / KIB),
        b => format!("{b} bytes"),
    }
}

/// The hex grid's render window for `n_rows` rows at `scroll`.
///
/// The view calls this rather than [`crate::state::row_window::visible_window`]
/// directly, so which height and overscan this surface passes is a value a
/// test can observe — the view itself is `#[mutants::skip]` and returns an
/// opaque `Element`, so an argument swapped there is invisible to the suite.
#[must_use]
pub fn window(
    n_rows: usize,
    scroll: crate::state::row_window::ScrollPos,
) -> crate::state::row_window::RowWindow {
    crate::state::row_window::visible_window(
        n_rows,
        row_pixel_height(),
        scroll,
        crate::state::row_window::OVERSCAN_ROWS,
    )
}

/// Laid-out pixel height of one hex grid row for viewport windowing (#660):
/// the monospace cell text at `TEXT_SM` through iced's line-height factor,
/// with no vertical cell padding and no column spacing to add.
#[must_use]
pub fn row_pixel_height() -> f32 {
    crate::state::row_window::row_height_px(crate::theme::tokens::TEXT_SM, 0.0)
}

#[must_use]
pub fn row_bytes(bytes: &[u8], row: usize) -> &[u8] {
    let start = row * BYTES_PER_ROW;
    if start >= bytes.len() {
        return &[];
    }
    let end = (start + BYTES_PER_ROW).min(bytes.len());
    &bytes[start..end]
}

impl Selection {
    #[must_use]
    pub fn range(&self) -> (usize, usize) {
        (self.anchor.min(self.cursor), self.anchor.max(self.cursor))
    }
    #[must_use]
    pub fn contains(&self, i: usize) -> bool {
        let (lo, hi) = self.range();
        i >= lo && i <= hi
    }
}

impl HexState {
    pub fn press(&mut self, i: usize) {
        self.selection = Some(Selection {
            anchor: i,
            cursor: i,
        });
        self.dragging = true;
    }
    pub fn enter(&mut self, i: usize) {
        #[allow(clippy::collapsible_if)]
        if self.dragging {
            if let Some(s) = self.selection.as_mut() {
                s.cursor = i;
            }
        }
    }
    pub fn end_drag(&mut self) {
        self.dragging = false;
    }
}

/// Nibble lookup for [`copy_hex`]: infallible by construction (`u8 >> 4` and
/// `u8 & 0x0F` are both < 16), where a `char::from_digit` chain would carry
/// an unreachable error branch a reader has to rule out.
const HEX_DIGITS: &[u8; 16] = b"0123456789ABCDEF";

/// Selected bytes as uppercase, space-separated hex (`"C1 2A FF"`). Empty only
/// when `bytes` is empty; any selection past the end clamps to the last byte.
#[must_use]
pub fn copy_hex(bytes: &[u8], sel: Selection) -> String {
    let (lo, hi) = clamped_range(bytes.len(), sel);
    if lo > hi {
        return String::new();
    }
    // Streamed into one pre-sized buffer rather than a `String` per byte
    // joined at the end: #660 raised `HEX_BYTES_CAP` 512x, and nothing
    // bounds a selection below it — `Selection` holds global byte indices
    // and `clamped_range` clamps only to the buffer end — so a cap-sized
    // selection is reachable by construction, where the per-byte shape
    // would allocate millions of times and block the UI thread for a third
    // of a second.
    let mut out = String::with_capacity((hi - lo + 1) * 3);
    for (i, b) in bytes[lo..=hi].iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.push(char::from(HEX_DIGITS[usize::from(b >> 4)]));
        out.push(char::from(HEX_DIGITS[usize::from(b & 0x0F)]));
    }
    out
}

/// Selected bytes as ASCII, non-printable → `'.'`.
#[must_use]
pub fn copy_ascii(bytes: &[u8], sel: Selection) -> String {
    let (lo, hi) = clamped_range(bytes.len(), sel);
    if lo > hi {
        return String::new();
    }
    // Pre-sized for the same reason as `copy_hex`: one byte in, one char out.
    let mut out = String::with_capacity(hi - lo + 1);
    for &b in &bytes[lo..=hi] {
        out.push(if (0x20..0x7f).contains(&b) {
            b as char
        } else {
            '.'
        });
    }
    out
}

/// Inclusive [lo, hi] clamped to `[0, len)`. Returns `(1, 0)` (lo>hi) when empty.
fn clamped_range(len: usize, sel: Selection) -> (usize, usize) {
    if len == 0 {
        return (1, 0);
    }
    let (lo, hi) = sel.range();
    (lo.min(len - 1), hi.min(len - 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The truncation note names the cap, so its units must follow the cap
    /// when the cap moves. Before #660 the note divided by 1024 and appended
    /// a literal "KiB", which read naturally at 16 KiB and would have read
    /// "8192 KiB" at the raised cap — the same defect the CLI fixed in #93.
    #[test]
    fn binary_size_label_promotes_to_the_largest_whole_unit() {
        assert_eq!(
            binary_size_label(crate::task::asset::HEX_BYTES_CAP),
            "8 MiB",
            "the shipped cap must render in whole MiB"
        );
        assert_eq!(binary_size_label(16 * 1024), "16 KiB");
        assert_eq!(binary_size_label(2 * 1024 * 1024 * 1024), "2 GiB");
        assert_eq!(binary_size_label(512), "512 bytes");
        assert_eq!(
            binary_size_label(1536 * 1024),
            "1536 KiB",
            "a non-whole MiB stays in KiB rather than rounding away detail"
        );
    }

    /// The hex grid's row height must be the HEX one. A review probe swapped
    /// this surface's height for the label row's (26.2 vs 15.6 px, a 68%
    /// error in every spacer and window range) and the whole suite stayed
    /// green. This pins what the helper RETURNS; that the view PASSES it is
    /// pinned by `hex_window_uses_the_hex_height_and_the_shipped_overscan`.
    #[test]
    fn hex_row_height_is_the_monospace_cell_height_not_the_label_row() {
        assert!(
            (row_pixel_height()
                - crate::state::row_window::row_height_px(crate::theme::tokens::TEXT_SM, 0.0))
            .abs()
                < f32::EPSILON,
            "hex rows are TEXT_SM with no vertical padding"
        );
        assert!(
            (row_pixel_height() - crate::state::row_window::label_row_height()).abs()
                > f32::EPSILON,
            "the hex height must differ from the label-row height, or the \
             surfaces cannot have been given the right one"
        );
    }

    /// The window this surface builds must use the HEX geometry. Probes
    /// swapped the height and zeroed the overscan at the view's call site
    /// and the suite stayed green, because the view is mutants-skipped and
    /// returns an opaque `Element`; the seam is what makes those arguments
    /// observable.
    #[test]
    fn hex_window_uses_the_hex_height_and_the_shipped_overscan() {
        let scroll = crate::state::row_window::ScrollPos {
            y: 1560.0,
            viewport_h: 600.0,
        };
        let got = window(10_000, scroll);
        assert_eq!(
            got,
            crate::state::row_window::visible_window(
                10_000,
                crate::state::row_window::row_height_px(crate::theme::tokens::TEXT_SM, 0.0),
                scroll,
                crate::state::row_window::OVERSCAN_ROWS,
            )
        );
        assert_ne!(
            got,
            crate::state::row_window::visible_window(
                10_000,
                crate::state::row_window::label_row_height(),
                scroll,
                crate::state::row_window::OVERSCAN_ROWS,
            ),
            "the label-row height must not produce this surface's window"
        );
        assert_ne!(
            got,
            crate::state::row_window::visible_window(
                10_000,
                crate::state::row_window::row_height_px(crate::theme::tokens::TEXT_SM, 0.0),
                scroll,
                0,
            ),
            "zero overscan must not produce this surface's window"
        );
    }

    #[test]
    fn total_rows_ceil_divides() {
        assert_eq!(total_rows(0), 0);
        assert_eq!(total_rows(1), 1);
        assert_eq!(total_rows(16), 1);
        assert_eq!(total_rows(17), 2);
        assert_eq!(total_rows(32), 2);
    }

    #[test]
    fn row_bytes_returns_short_final_row() {
        let data: Vec<u8> = (0..20).collect();
        assert_eq!(row_bytes(&data, 0).len(), 16);
        assert_eq!(row_bytes(&data, 1), &[16, 17, 18, 19]); // short tail
        assert_eq!(row_bytes(&data, 5), &[] as &[u8]); // out of range → empty
    }

    #[test]
    fn selection_range_normalizes_backward_drag() {
        assert_eq!(
            Selection {
                anchor: 2,
                cursor: 7
            }
            .range(),
            (2, 7)
        );
        assert_eq!(
            Selection {
                anchor: 7,
                cursor: 2
            }
            .range(),
            (2, 7)
        ); // backward
        assert_eq!(
            Selection {
                anchor: 4,
                cursor: 4
            }
            .range(),
            (4, 4)
        ); // single byte
    }

    #[test]
    fn selection_contains_is_inclusive() {
        let s = Selection {
            anchor: 7,
            cursor: 2,
        };
        assert!(s.contains(2) && s.contains(7) && s.contains(5));
        assert!(!s.contains(1) && !s.contains(8));
    }

    #[test]
    fn drag_press_starts_selection_and_dragging() {
        let mut h = HexState::default();
        h.press(5);
        assert_eq!(
            h.selection,
            Some(Selection {
                anchor: 5,
                cursor: 5
            })
        );
        assert!(h.dragging);
    }

    #[test]
    fn drag_enter_extends_only_while_dragging() {
        let mut h = HexState::default();
        h.press(5);
        h.enter(9);
        assert_eq!(h.selection.unwrap().range(), (5, 9));
        h.end_drag();
        assert!(!h.dragging);
        h.enter(0); // not dragging → ignored
        assert_eq!(h.selection.unwrap().range(), (5, 9));
    }

    #[test]
    fn copy_hex_formats_uppercase_space_separated() {
        let data = vec![0x00, 0xC1, 0x2A, 0xFF];
        let sel = Selection {
            anchor: 1,
            cursor: 3,
        }; // bytes 1..=3
        assert_eq!(copy_hex(&data, sel), "C1 2A FF");
    }

    #[test]
    fn copy_hex_zero_pads_bytes_below_0x10() {
        // Every byte here has a zero high nibble — pins the padding half of
        // the byte-for-byte match with the pre-#660 format!("{b:02X}") shape
        // ("0A", never "A"), which no other copy_hex test exercises.
        let data = vec![0x0A, 0x00, 0x0F];
        let sel = Selection {
            anchor: 0,
            cursor: 2,
        };
        assert_eq!(copy_hex(&data, sel), "0A 00 0F");
    }

    #[test]
    fn copy_ascii_uses_dot_for_nonprintable() {
        let data = vec![b'A', 0x00, b'z', 0x7f];
        let sel = Selection {
            anchor: 0,
            cursor: 3,
        };
        assert_eq!(copy_ascii(&data, sel), "A.z."); // 0x00 and 0x7f → '.'
    }

    #[test]
    fn copy_clamps_range_to_data_len() {
        let data = vec![0xAA, 0xBB];
        let sel = Selection {
            anchor: 0,
            cursor: 99,
        }; // cursor past end
        assert_eq!(copy_hex(&data, sel), "AA BB"); // clamped, no panic
    }

    #[test]
    fn copy_ascii_clamps_and_handles_empty() {
        let data = vec![b'A', b'B'];
        let sel = Selection {
            anchor: 0,
            cursor: 99,
        }; // cursor past end
        assert_eq!(copy_ascii(&data, sel), "AB"); // clamped, no panic
        // Empty data → empty string (the (1,0) sentinel short-circuits).
        assert_eq!(
            copy_ascii(
                &[],
                Selection {
                    anchor: 0,
                    cursor: 5
                }
            ),
            ""
        );
    }

    // ── B6: copy_hex / copy_ascii single-byte + clamped_range boundaries ─────

    #[test]
    fn copy_hex_single_byte_selection_returns_that_byte() {
        // lo == hi (single-byte selection). Kills `> with ==` / `> with >=` in
        // copy_hex: a wrong condition would return "" for an equal lo/hi.
        let data = vec![0xAA, 0xBB, 0xCC];
        let sel = Selection {
            anchor: 1,
            cursor: 1,
        };
        assert_eq!(
            copy_hex(&data, sel),
            "BB",
            "single-byte selection must return that byte's hex"
        );
    }

    #[test]
    fn copy_ascii_single_byte_selection_returns_that_char() {
        // Kills `> with >=` in copy_ascii.
        let data = vec![b'A', b'B', b'C'];
        let sel = Selection {
            anchor: 0,
            cursor: 0,
        };
        assert_eq!(
            copy_ascii(&data, sel),
            "A",
            "single-byte selection must return that character"
        );
    }

    #[test]
    fn copy_hex_selection_past_end_clamps_to_last_byte() {
        // cursor far past end exercises the `hi.min(len - 1)` clamp in
        // clamped_range. Kills `- with +` and `- with /` on `len - 1`.
        let data = vec![0x11, 0x22, 0x33];
        let sel = Selection {
            anchor: 2,
            cursor: 50,
        };
        assert_eq!(
            copy_hex(&data, sel),
            "33",
            "cursor past end must clamp to last byte"
        );
    }

    #[test]
    fn copy_hex_lo_also_clamped() {
        // anchor past end: lo is clamped, hi is clamped, both land on last byte.
        let data = vec![0x11, 0x22, 0x33];
        let sel = Selection {
            anchor: 100,
            cursor: 200,
        };
        assert_eq!(
            copy_hex(&data, sel),
            "33",
            "anchor past end: both lo and hi clamp to the last byte"
        );
    }
}
