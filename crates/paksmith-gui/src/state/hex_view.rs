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

/// Selected bytes as uppercase, space-separated hex (`"C1 2A FF"`). Empty only
/// when `bytes` is empty; any selection past the end clamps to the last byte.
#[must_use]
pub fn copy_hex(bytes: &[u8], sel: Selection) -> String {
    let (lo, hi) = clamped_range(bytes.len(), sel);
    if lo > hi {
        return String::new();
    }
    bytes[lo..=hi]
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Selected bytes as ASCII, non-printable → `'.'`.
#[must_use]
pub fn copy_ascii(bytes: &[u8], sel: Selection) -> String {
    let (lo, hi) = clamped_range(bytes.len(), sel);
    if lo > hi {
        return String::new();
    }
    bytes[lo..=hi]
        .iter()
        .map(|&b| {
            if (0x20..0x7f).contains(&b) {
                b as char
            } else {
                '.'
            }
        })
        .collect()
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
