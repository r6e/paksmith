//! Pure viewport-windowing math for the three list-shaped widgets (#660).
//!
//! Maps a scroll position over a uniform-height row list to the slice of
//! rows worth rendering plus the top/bottom spacer heights that stand in for
//! the rest. No `iced` imports: `scrollable::Viewport` cannot be constructed
//! in tests, so the widget glue extracts scalars (the console's
//! `ConsoleScrolled(f32)` pattern) and everything decidable lives here.
//!
//! # What the spacers can and cannot promise
//!
//! The scrollable lays out `top_px + Σ(rendered row heights) + bottom_px`,
//! plus whatever else the caller pushes into the same column (see
//! [`visible_window`] for the two that do).
//! The spacers are computed from [`row_height_px`], so the laid-out height
//! equals a full render's — and stays put as the window moves — exactly to
//! the extent that estimate matches what iced renders. It is derived rather
//! than guessed ([`LINE_HEIGHT_FACTOR`]), so for single-line rows the two
//! agree; a row that WRAPS renders taller than predicted, which shifts the
//! content height by that row's excess — costing scrollbar accuracy, not
//! coverage, since a taller row only extends the rendered block downward.
//! The pure tests below pin the arithmetic in estimate units; they cannot
//! observe what iced actually lays out.

/// The last scroll geometry a widget's `on_scroll` reported.
///
/// `Default` (all zeros) is the never-scrolled state: iced only publishes a
/// `Viewport` once content overflows the bounds, so a fresh surface renders
/// through [`visible_window`]'s viewport fallback until the first event.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct ScrollPos {
    /// Absolute y offset in px, as `Viewport::absolute_offset().y` reported
    /// it. May be stale (larger than the current content allows) after the
    /// row list shrinks — iced stops publishing once content fits, so
    /// [`visible_window`] re-clamps rather than trusting it.
    pub y: f32,
    /// Viewport height in px (`Viewport::bounds().height`). Zero until the
    /// first event arrives.
    pub viewport_h: f32,
}

/// A render window: the row range to build plus the spacer heights that
/// stand in for everything outside it.
#[derive(Clone, Debug, PartialEq)]
pub struct RowWindow {
    /// Rows to render, as indices into the flat row list.
    pub range: std::ops::Range<usize>,
    /// Height of the spacer above the rendered slice.
    pub top_px: f32,
    /// Height of the spacer below the rendered slice.
    pub bottom_px: f32,
}

/// Rows rendered beyond each edge of the visible span.
///
/// Absorbs: sub-row scroll jitter between frames, the one-frame lag between
/// a programmatic `scroll_to` and its `on_scroll` echo, and rows that render
/// SHORTER than [`row_height_px`] predicts — which is the direction that can
/// leave a gap, since the rendered block starts at `top_px` and short rows
/// end it above the viewport's bottom. Taller rows (a wrapped label) only
/// extend the block downward, so they cost content-height accuracy rather
/// than coverage.
pub const OVERSCAN_ROWS: usize = 8;

/// iced's default text line height, as a multiple of the font size.
///
/// `LineHeight::default()` is `Relative(1.3)` (`iced_core::text`), and a
/// paragraph's measured height is the sum of its runs' line heights — so a
/// single-line `text` widget lays out at `1.3 × size`, NOT at `size`. Every
/// row-height estimate here is derived through this factor rather than from
/// the font size alone; a theme that overrides `line_height` would
/// invalidate the estimates, and [`OVERSCAN_ROWS`] is what keeps that from
/// blanking the viewport.
pub const LINE_HEIGHT_FACTOR: f32 = 1.3;

/// Laid-out pixel height of a single-line row: text at `text_size`, plus
/// `vertical_padding` on each side.
///
/// Shared by the file tree and the property inspector, whose rows are the
/// same shape (a `TEXT_MD` label inside `padding([SPACE_XS, SPACE_SM])`),
/// and by the hex grid, whose cells carry no vertical padding.
#[must_use]
pub fn row_height_px(text_size: u16, vertical_padding: f32) -> f32 {
    f32::from(text_size) * LINE_HEIGHT_FACTOR + 2.0 * vertical_padding
}

/// Laid-out height of a file-tree or property-inspector row.
#[must_use]
pub fn label_row_height() -> f32 {
    row_height_px(
        crate::theme::tokens::TEXT_MD,
        crate::theme::tokens::SPACE_XS,
    )
}

/// Viewport height assumed while no `on_scroll` event has reported one.
///
/// Not merely a first-frame stand-in: iced publishes a viewport only once
/// content OVERFLOWS its bounds, so a list that fits its pane never reports
/// one at all and this value is the permanent window height for it. It must
/// therefore exceed any pane a fitting list could occupy, or the tail of
/// that list would render as blank spacer with no event that could ever
/// correct it. 8192 px covers a portrait 8K pane; the cost when the real
/// viewport is small is a few hundred extra rows built on frames before the
/// first scroll, which is bounded work either way.
pub const VIEWPORT_FALLBACK_PX: f32 = 8192.0;

/// Compute the row window for a uniform-height list.
///
/// `overscan` extra rows are rendered on each side of the visible span so
/// that small scrolls, sub-pixel drift in the per-widget row-height
/// estimate, and the one-frame lag between a programmatic `scroll_to` and
/// its `on_scroll` echo never expose an unrendered edge.
///
/// Invariant, in estimate units: `top_px + range.len() * row_height +
/// bottom_px == row_count as f32 * row_height`. This is what keeps the
/// window's position out of the ROWS' contribution to content height.
/// Callers that push extra elements into the same column are outside it:
/// the inspector's truncation note is position-independent (it only adds a
/// fixed height), while the tree's inline action strip is built only when
/// its row is inside the window, so scrolling past an open context menu
/// does change the laid-out height by that strip. Pinned exactly at an
/// `f32`-representable row height; at the shipped heights, which are not
/// representable, the sum rounds by an ulp from a few dozen rows up —
/// sub-pixel there, and bounded by [`MAX_SPACER_DEVIATION_ULPS`] at the
/// millions a broad tree filter can reach. Whether the rendered rows then match
/// `row_height` is the estimate's job, not this function's — see the module
/// docs.
///
/// A non-finite or negative `scroll.y` (a raw wire value) is treated as 0.
/// A stale `scroll.y` past the end of a shrunken list is clamped so the
/// window covers the list's tail.
pub fn visible_window(
    row_count: usize,
    row_height: f32,
    scroll: ScrollPos,
    overscan: usize,
) -> RowWindow {
    if row_count == 0 || row_height <= 0.0 {
        return RowWindow {
            range: 0..row_count,
            top_px: 0.0,
            bottom_px: 0.0,
        };
    }

    // Both wire values are guarded the same way: finite and sane, or the
    // fallback. An unguarded `+inf` viewport would saturate the row count
    // and overflow the `+ 1` below before any clamp could bound it.
    let viewport_h = if scroll.viewport_h.is_finite() && scroll.viewport_h > 0.0 {
        scroll.viewport_h
    } else {
        VIEWPORT_FALLBACK_PX
    };
    let y = if scroll.y.is_finite() {
        scroll.y.max(0.0)
    } else {
        0.0
    };
    let max_y = (rows_px(row_count, row_height) - viewport_h).max(0.0);
    let y = y.min(max_y);

    let first_visible = to_row_count((y / row_height).floor());
    // One extra row covers the partially-visible row at the viewport's
    // bottom edge when the offset is not row-aligned.
    let visible_rows = to_row_count((viewport_h / row_height).ceil()).saturating_add(1);
    let start = first_visible.saturating_sub(overscan).min(row_count);
    let end = first_visible
        .saturating_add(visible_rows)
        .saturating_add(overscan)
        .min(row_count);

    RowWindow {
        range: start..end,
        top_px: rows_px(start, row_height),
        bottom_px: rows_px(row_count - end, row_height),
    }
}

/// Pixel height of `rows` rows.
///
/// `f32` represents a product exactly only while it stays under 2^24 px, and
/// the file tree — unlike the hex view and inspector, which carry byte and
/// row caps — has no cap of its own: a broad filter force-expands every
/// matching directory, so the row count is archive-driven up to core's
/// 10,000,000-entry flat-index ceiling. At such counts the spacer heights
/// round rather than landing exactly — bounded, and pinned by test, at
/// [`MAX_SPACER_DEVIATION_ULPS`].
fn rows_px(rows: usize, row_height: f32) -> f32 {
    #[allow(clippy::cast_precision_loss)]
    {
        rows as f32 * row_height
    }
}

/// Largest deviation the spacer arithmetic may show from an exact
/// `row_count × row_height`, expressed in ULPs of that product.
///
/// A fixed pixel bound was tried twice and falsified twice, for the same
/// reason both times: the shipped row heights are not `f32`-representable
/// (26.199999, 15.599999), so the rounding error tracks the MAGNITUDE of
/// the column rather than being fixed. Measured at the label row height
/// (26.199999 — the hex height's deviations at the same cases are smaller),
/// they are 2 ulps at 9.5M rows (32 px), 3 ulps at 16.9M (96 px) and 2 ulps
/// at 20.6M (128 px): bounded in ulps, while the pixel figure grows with
/// the ulp size of the binade the column lands in. The file tree's row count
/// is unbounded in the sense that matters: core's flat index caps ENTRIES at
/// 10,000,000, but a broad filter also emits a row per matched directory, so
/// the column can sit a binade or two above.
///
/// Stated in ULPs the bound is magnitude-independent, which is what
/// survives the counterexamples that killed both pixel values. Where the
/// error comes from, decomposed against an `f64` reference at the worst
/// case above: the two `usize`-to-`f32` casts past 2^24 rows dominate (more
/// than half of it — a row count in that range has an ulp of 2, so one cast
/// can shift a spacer by a whole row), then the multiply-roundings of the
/// reference and of whichever spacer shares its binade, then one of the two
/// additions. Which split produces the worst case is not
/// predictable from that decomposition — a 32-million-sample sweep finds
/// 3-ulp deviations at near-even splits as readily as lopsided ones — so
/// the bound rests on the measurement rather than on an argument about
/// where the maximum sits.
///
/// Four is therefore a measured bound rather than a sum of worst-case
/// terms. The worst OBSERVED is 3 ulps — over sweeps of millions of
/// (count, offset, viewport) samples out past 9e8 rows at both shipped
/// heights, and over exhaustive scans of every window start at the counts
/// that produced 3 — so the constant carries about one ulp of slack. It is
/// stated as a bound, not as an attained maximum: an earlier round claimed
/// attainment and later rounds could not reproduce it, so the honest claim
/// is the one with a witness behind it. Inside the hex view's own cap
/// (524,288 rows) the worst is 2 ulps, e.g. count 105 at viewport 300.
/// A regression past four means the arithmetic changed, not the
/// representation.
///
/// Nothing in the render path reads this — it exists so the windowing
/// invariant is stated at a width that survives measurement.
pub const MAX_SPACER_DEVIATION_ULPS: f32 = 4.0;

/// Convert a non-negative, finite pixel-derived float to a row count.
///
/// Callers pass values already guarded to be finite and `>= 0`; Rust's
/// float→int `as` cast saturates rather than wrapping, so a hostile value
/// would clamp to `0` or `usize::MAX` and the caller's `.min(row_count)`
/// still bounds it.
fn to_row_count(v: f32) -> usize {
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    {
        v as usize
    }
}

#[cfg(test)]
mod tests {
    // Every float assertion here pins an EXACT value: the spacer heights are
    // integer multiples of a small row height, produced by the same
    // multiplication the assertions spell out, so any difference is a real
    // geometry change rather than rounding noise.
    #![allow(clippy::float_cmp)]

    use super::*;

    const H: f32 = 20.0;

    fn window(count: usize, y: f32, viewport_h: f32) -> RowWindow {
        visible_window(count, H, ScrollPos { y, viewport_h }, 4)
    }

    /// The content-height invariant that keeps scrollbar geometry honest:
    /// spacers plus rendered rows must always sum to the full virtual
    /// height, wherever the window sits.
    // Exact float equality is the property under test: the spacer heights are
    // built from the same `rows_px` multiplication, so any drift is a real
    // content-height change, not rounding noise.
    #[allow(clippy::float_cmp, clippy::cast_precision_loss)]
    #[test]
    fn spacers_plus_slice_always_equal_the_full_height() {
        for count in [0usize, 1, 7, 1_000, 100_000] {
            for y in [0.0f32, 10.0, 999.0, 19_999.0, 1_999_980.0] {
                let w = window(count, y, 600.0);
                let total = w.top_px + w.range.len() as f32 * H + w.bottom_px;
                assert_eq!(
                    total,
                    count as f32 * H,
                    "count={count} y={y}: window {w:?} changes content height"
                );
            }
        }
    }

    #[test]
    fn empty_list_renders_nothing_with_zero_spacers() {
        let w = window(0, 500.0, 600.0);
        assert_eq!(
            w,
            RowWindow {
                range: 0..0,
                top_px: 0.0,
                bottom_px: 0.0
            }
        );
    }

    #[test]
    fn top_of_list_starts_at_row_zero_with_no_top_spacer() {
        let w = window(1_000, 0.0, 600.0);
        assert_eq!(w.range.start, 0);
        assert_eq!(w.top_px, 0.0);
        // 600px / 20px = 30 visible + 1 partial + 4 overscan below.
        assert_eq!(w.range.end, 35);
    }

    #[test]
    fn mid_list_window_covers_the_visible_span_plus_overscan() {
        // y=2000 → first visible row 100; visible span rows 100..=130.
        let w = window(1_000, 2_000.0, 600.0);
        assert_eq!(w.range, 96..135);
        assert_eq!(w.top_px, 96.0 * H);
        assert_eq!(w.bottom_px, (1_000.0 - 135.0) * H);
    }

    #[test]
    fn bottom_of_list_clamps_end_to_row_count() {
        let max_y = 1_000.0 * H - 600.0;
        let w = window(1_000, max_y, 600.0);
        assert_eq!(w.range.end, 1_000);
        assert_eq!(w.bottom_px, 0.0);
        // The last visible span is rows 970..1000, minus overscan above.
        assert_eq!(w.range.start, 966);
    }

    /// iced stops publishing viewports once content fits, so a shrunken
    /// list leaves the stored offset stale and too large. The window must
    /// clamp to the tail rather than render nothing.
    #[test]
    fn stale_offset_past_the_end_clamps_to_the_tail() {
        let w = window(10, 90_000.0, 600.0);
        assert_eq!(w.range, 0..10, "10 rows fit any viewport — render all");
        assert_eq!(w.top_px, 0.0);
        assert_eq!(w.bottom_px, 0.0);
    }

    #[test]
    fn never_scrolled_state_renders_from_the_top_via_the_fallback() {
        let w = visible_window(100_000, H, ScrollPos::default(), 4);
        assert_eq!(w.range.start, 0);
        let expected_end = to_row_count((VIEWPORT_FALLBACK_PX / H).ceil()) + 1 + 4;
        assert_eq!(w.range.end, expected_end);
    }

    #[test]
    fn non_finite_and_negative_offsets_are_treated_as_zero() {
        for bad in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY, -50.0] {
            let w = window(1_000, bad, 600.0);
            assert_eq!(w.range.start, 0, "bad y {bad} must land at the top");
            assert_eq!(w.top_px, 0.0);
        }
    }

    /// The window size is bounded by the viewport, never the list: this is
    /// the #660 acceptance property that a broad filter on a 100k-entry
    /// tree stays responsive (the view builds ~40 rows, not 100k).
    #[test]
    fn window_size_is_independent_of_row_count() {
        let small = window(50, 0.0, 600.0);
        let huge = window(100_000, 0.0, 600.0);
        assert_eq!(huge.range.len(), 35);
        assert!(small.range.len() <= huge.range.len());
        let mid = window(100_000, 1_000_000.0, 600.0);
        assert_eq!(
            mid.range.len(),
            39,
            "31 visible+partial plus 4 overscan each side"
        );
    }

    /// The line-height factor must match what iced actually defaults to.
    /// Every other test routes through the constant, so a probe that reset
    /// it to 1.0 — reinstating the 30%-per-row under-measurement this change
    /// exists to fix — left the whole suite green. Anchoring to the
    /// dependency also fails on an iced upgrade that moves the default,
    /// which the constant's doc otherwise only narrates.
    #[test]
    fn line_height_factor_matches_iceds_default() {
        assert_eq!(
            iced::widget::text::LineHeight::default(),
            iced::widget::text::LineHeight::Relative(LINE_HEIGHT_FACTOR)
        );
    }

    /// The fallback is the PERMANENT window height for any list that fits
    /// its pane (iced never publishes a viewport for one), and every
    /// `forget_viewport_heights` returns each surface to it — so it is a
    /// recurring window height, not a first-frame stand-in.
    ///
    /// Bounded on BOTH sides, because each direction breaks something
    /// different and probes found each unpinned in turn. Too low and a
    /// fitting list renders its tail as unreachable blank spacer. Too high
    /// and the window stops tracking the viewport and starts tracking the
    /// list — at a million px the hex grid would build ~64,000 rows, which
    /// is the per-frame cost #660 exists to remove.
    #[test]
    fn viewport_fallback_covers_a_tall_pane_without_unbounding_the_window() {
        // `black_box` so this reads as a runtime comparison; clippy rejects
        // an assertion it can fold to a constant, and the point is that the
        // CONSTANT is what must satisfy it.
        let fallback = std::hint::black_box(VIEWPORT_FALLBACK_PX);
        assert!(
            fallback >= 7680.0,
            "the fallback must cover a portrait 8K pane, got {fallback}"
        );
        for h in [
            label_row_height(),
            row_height_px(crate::theme::tokens::TEXT_SM, 0.0),
        ] {
            let w = visible_window(1_000_000, h, ScrollPos::default(), OVERSCAN_ROWS);
            assert!(
                w.range.len() < 1_000,
                "h={h}: the fallback window builds {} rows — it must stay \
                 viewport-sized, not list-sized",
                w.range.len()
            );
        }
    }

    /// Overscan must actually overscan. At zero every job its doc claims —
    /// absorbing sub-row jitter, the one-frame scroll_to echo lag, rows
    /// shorter than the estimate — silently stops happening, and the
    /// ~125 px invalidation threshold derived from it in
    /// `app::forget_viewport_heights` collapses with it. A probe setting it
    /// to 0 left the suite green.
    #[test]
    fn overscan_is_nonzero_and_sets_the_invalidation_threshold() {
        assert!(
            std::hint::black_box(OVERSCAN_ROWS) > 0,
            "overscan must render rows beyond the edge"
        );
        #[allow(clippy::cast_precision_loss)]
        let threshold = OVERSCAN_ROWS as f32 * row_height_px(crate::theme::tokens::TEXT_SM, 0.0);
        assert!(
            (threshold - 124.8).abs() < 0.1,
            "the pane-growth threshold documented in app::forget_viewport_heights \
             is OVERSCAN_ROWS x the smallest row height; got {threshold}"
        );
    }

    /// #660's acceptance property, at both shipped row heights and
    /// the shipped overscan: a 100k-row list windows to a few dozen rows, so
    /// a broad filter on a 100k-entry archive builds a viewport-bounded
    /// number of widgets per frame rather than 100k.
    #[test]
    fn hundred_thousand_rows_window_to_a_few_dozen_at_shipped_settings() {
        let viewport = ScrollPos {
            y: 500_000.0,
            viewport_h: 900.0,
        };
        for row_h in [
            label_row_height(),
            row_height_px(crate::theme::tokens::TEXT_SM, 0.0),
        ] {
            let w = visible_window(100_000, row_h, viewport, OVERSCAN_ROWS);
            assert!(
                w.range.len() < 100,
                "row_h={row_h}: windowed {} rows — the window must track the \
                 viewport, not the list",
                w.range.len()
            );
            assert!(w.range.start > 0, "row_h={row_h}: must be mid-list here");
        }
    }

    /// The content-height invariant at the SHIPPED row heights and row
    /// counts far past the 100k the sweep above covers — the file tree is
    /// uncapped, so a broad filter can reach millions of rows. The shipped
    /// heights are not `f32`-representable, so the property past a few
    /// hundred thousand rows is bounded deviation, not equality; anything
    /// larger than [`MAX_SPACER_DEVIATION_ULPS`] would mean the arithmetic,
    /// not the representation, is wrong. The scroll POSITION matters as much
    /// as the count — a review probe found 32 px at a mid-list offset where
    /// the half-way samples showed 4 — so one off-centre case is included.
    /// The gap between `v` and the next representable `f32` above it — the
    /// measurement unit for the deviation bound below. Lives in the test
    /// module because nothing in the render path reads it (same reason
    /// [`MAX_SPACER_DEVIATION_ULPS`]'s doc gives for the constant itself).
    fn ulp(v: f32) -> f32 {
        let next = f32::from_bits(v.abs().to_bits() + 1);
        next - v.abs()
    }

    #[test]
    fn spacer_deviation_stays_bounded_at_tree_reachable_row_counts() {
        // (row count, row the viewport sits at, viewport height). The last
        // three are review probes' measured counterexamples to the two fixed
        // pixel bounds this test carried before: 32 px at 9.5M, 96 px at
        // 16.9M, 128 px at 20.6M. All three are inside the ULP bound, which
        // is the point — the error tracks the magnitude of the column.
        let cases: [(usize, usize, f32); 7] = [
            (500_000, 250_000, 900.0),
            (1_000_001, 500_000, 900.0),
            (2_000_000, 1_000_000, 900.0),
            (10_000_001, 5_000_000, 900.0),
            (9_527_977, 5_285_338, 600.0),
            (16_865_049, 84_114, 600.0),
            (20_570_077, 3_056_310, 600.0),
        ];
        let mut worst = 0.0_f32;
        for h in [
            label_row_height(),
            row_height_px(crate::theme::tokens::TEXT_SM, 0.0),
        ] {
            for (count, at_row, viewport_h) in cases {
                let w = visible_window(
                    count,
                    h,
                    ScrollPos {
                        y: rows_px(at_row, h),
                        viewport_h,
                    },
                    OVERSCAN_ROWS,
                );
                #[allow(clippy::cast_precision_loss)]
                let total = w.top_px + w.range.len() as f32 * h + w.bottom_px;
                let expected = rows_px(count, h);
                let deviation = (total - expected).abs();
                worst = worst.max(deviation / ulp(expected));
                let allowed = MAX_SPACER_DEVIATION_ULPS * ulp(expected);
                assert!(
                    deviation <= allowed,
                    "h={h} count={count}: spacer total {total} deviates {deviation}px \
                     from {expected}, past {allowed}px ({MAX_SPACER_DEVIATION_ULPS} ulps)"
                );
            }
        }
        // Pin the bound against the MEASUREMENT, not only as a tolerance:
        // used only as the allowance above, any larger value — 8, 1e30 —
        // keeps this test green while making it vacuous.
        assert!(
            worst > MAX_SPACER_DEVIATION_ULPS / 2.0,
            "worst observed deviation is {worst} ulps against a bound of \
             {MAX_SPACER_DEVIATION_ULPS}: the bound has drifted above what \
             these cases exercise, so it no longer pins anything"
        );
    }

    /// A `+inf` viewport height must take the fallback like any other
    /// non-finite wire value. Before this guard it saturated the row count
    /// and overflowed the `+ 1`, panicking in debug and near-blanking the
    /// list in release.
    #[test]
    fn non_finite_viewport_height_takes_the_fallback() {
        for bad in [f32::INFINITY, f32::NAN, 0.0, -10.0] {
            let w = visible_window(
                1_000,
                H,
                ScrollPos {
                    y: 0.0,
                    viewport_h: bad,
                },
                4,
            );
            let expected_end = to_row_count((VIEWPORT_FALLBACK_PX / H).ceil()) + 1 + 4;
            assert_eq!(
                w.range,
                0..expected_end.min(1_000),
                "viewport_h {bad} must fall back, not saturate"
            );
        }
    }

    #[test]
    fn zero_row_height_yields_the_whole_list_rather_than_dividing_by_zero() {
        let w = visible_window(
            30,
            0.0,
            ScrollPos {
                y: 10.0,
                viewport_h: 600.0,
            },
            4,
        );
        assert_eq!(w.range, 0..30);
        assert_eq!(w.top_px, 0.0);
        assert_eq!(w.bottom_px, 0.0);
    }
}
