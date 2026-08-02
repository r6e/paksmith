//! Property-tree widget: renders the pure `PropRow` model as an interactive,
//! scrollable, type-aware inspector.
//!
//! # Virtualization (#660)
//!
//! `flatten_capped` contains only currently-expanded nodes, and the view
//! renders only the slice of those rows the viewport can show
//! ([`crate::state::row_window::visible_window`]), with spacers standing in
//! for the rest — see [`crate::state::row_window`] for what that promises
//! about scrollbar geometry. Expanding every branch of a deeply-nested asset
//! therefore builds a viewport-bounded number of widgets per frame.
//!
//! [`MAX_VISIBLE_PROP_ROWS`] survives windowing deliberately: it bounds the
//! per-frame WALK, which windowing cannot — see its own documentation.

use iced::widget::{button, column, container, row, scrollable, text};
use iced::{Element, Length};

use crate::app::Message;
use crate::state::property_view::{NodeId, PropKind, flatten_capped};
use crate::theme::tokens;
use crate::widgets::file_tree::row_indent;

/// Stable [`iced::widget::Id`] for the inspector's scrollable, so the update
/// layer can push a tab's stored offset back after a tab or view switch —
/// see `app::restore_scroll_positions` for why that is required.
pub const PROPS_SCROLL_ID: iced::widget::Id = iced::widget::Id::new("property-tree-scroll");

// ── row cap ───────────────────────────────────────────────────────────────────

/// Maximum number of property rows FLATTENED per frame.
///
/// Retained deliberately after viewport windowing landed (#660), because the
/// two bound different costs. Windowing bounds widget construction — the
/// expensive half — to what the viewport shows. It cannot bound the walk:
/// [`flatten_capped`] runs on every frame to learn the row count the
/// scrollbar needs, so without this cap a crafted asset with hundreds of
/// thousands of exports would still walk (and allocate two `String`s per
/// row for) all of them every frame.
///
/// The value is unchanged rather than raised: the walk is per-frame, so
/// raising it trades a measured-safe bound for an unmeasured one. Raising it
/// belongs with a measurement of the walk itself, not with this change.
pub const MAX_VISIBLE_PROP_ROWS: usize = 2000;

// ── color swatch size ─────────────────────────────────────────────────────────

/// Side length (px) of the color swatch square.
const SWATCH_SIZE: f32 = 12.0;

/// Border alpha for the swatch hairline — subtle enough on colored swatches but
/// enough contrast to make a white/transparent swatch visible against a light
/// background.
/// Decorative hairline (non-text) — WCAG text-contrast rules do not apply; deliberately below TEXT_MUTED_ALPHA.
const SWATCH_BORDER_ALPHA: f32 = 0.35;

// ── view ──────────────────────────────────────────────────────────────────────

/// Render a scrollable property tree for `pkg`.
///
/// * `pkg`      — the parsed asset Package.
/// * `expanded` — the set of currently-expanded node ids (from the active tab).
/// * `scroll`   — the inspector viewport's last reported scroll geometry.
///
/// # Rendering bounds
///
/// Two layers, bounding different costs. [`flatten_capped`] stops the WALK at
/// `MAX_VISIBLE_PROP_ROWS`, so a crafted asset cannot force an O(exports)
/// per-frame flatten; a truncation note is shown when that cap is hit.
/// [`crate::state::row_window::visible_window`] then bounds WIDGET
/// construction to the rows the viewport shows, with spacers standing in for
/// the rest so the scrollbar matches a full render (#660).
#[mutants::skip]
pub fn view<'a>(
    pkg: &'a paksmith_core::asset::Package,
    expanded: &std::collections::HashSet<NodeId>,
    scroll: crate::state::row_window::ScrollPos,
) -> Element<'a, Message> {
    let rows = flatten_capped(pkg, expanded, MAX_VISIBLE_PROP_ROWS);
    let truncated = rows.len() > MAX_VISIBLE_PROP_ROWS;

    let shown = rows.len().min(MAX_VISIBLE_PROP_ROWS);
    let win = window(shown, scroll);
    // `+ 3`: the two spacers plus the optional truncation note.
    let mut items: Vec<Element<'_, Message>> = Vec::with_capacity(win.range.len() + 3);
    crate::widgets::push_spacer(&mut items, win.top_px);
    // No `.take(shown)` cap here: `window(shown, ..)` already clamps
    // `range.end` to `shown`, so this chain can never consume a row at or
    // past the cap (pinned by `row_window`'s clamp tests).
    items.extend(
        rows.into_iter()
            .skip(win.range.start)
            .take(win.range.len())
            .map(build_row),
    );
    crate::widgets::push_spacer(&mut items, win.bottom_px);

    if truncated {
        items.push(
            container(
                text(format!(
                    "Showing the first {MAX_VISIBLE_PROP_ROWS} properties \u{2014} collapse nodes or extract the asset to inspect fully",
                ))
                .size(f32::from(tokens::TEXT_SM))
                .style(|theme: &iced::Theme| iced::widget::text::Style {
                    color: Some(theme.palette().text.scale_alpha(tokens::TEXT_MUTED_ALPHA)),
                }),
            )
            .padding([tokens::SPACE_XS, tokens::SPACE_SM])
            .width(Length::Fill)
            .into(),
        );
    }

    scrollable(column(items).width(Length::Fill))
        .id(PROPS_SCROLL_ID.clone())
        .on_scroll(|v| Message::PropsScrolled {
            y: v.absolute_offset().y,
            viewport_h: v.bounds().height,
        })
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}

/// The inspector's render window for `n_rows` rows at `scroll`.
///
/// The view calls this rather than
/// [`crate::state::row_window::visible_window`] directly, so which height
/// and overscan this surface passes is a value a test can observe — the
/// view itself is `#[mutants::skip]` and returns an opaque `Element`.
#[must_use]
fn window(
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

/// Laid-out pixel height of one property row — the same shape as a file-tree
/// row (a `TEXT_MD` label inside `padding([SPACE_XS, SPACE_SM])`), so both
/// come from the one shared helper.
fn row_pixel_height() -> f32 {
    crate::state::row_window::label_row_height()
}

/// Non-expandable branch row: indent + label, no chevron, no button.
///
/// Used when a `Branch` node has `is_expandable == false` (e.g. an export with
/// no payload). The row is non-interactive so it does not look or act clickable.
///
/// Alignment caveat: the label starts at `indent` (no chevron column reserved),
/// so it sits slightly left of an expandable sibling's label at the same depth.
/// Harmless today — the only non-expandable branch is a payload-less export,
/// which does not occur in practice (every export carries a payload). If Phase 7b
/// introduces reachable non-expandable branches that interleave with expandable
/// ones, reserve a chevron-width column here so labels stay column-aligned.
#[mutants::skip]
fn build_static_branch_row(indent: f32, label: String) -> Element<'static, Message> {
    let content = iced::widget::row![
        iced::widget::Space::new().width(indent),
        text(label)
            .size(f32::from(tokens::TEXT_MD))
            .style(|theme: &iced::Theme| iced::widget::text::Style {
                color: Some(theme.palette().text),
            }),
    ]
    .align_y(iced::Alignment::Center);

    container(content)
        .padding([tokens::SPACE_XS, tokens::SPACE_SM])
        .width(Length::Fill)
        .into()
}

/// Build one row widget from a `PropRow`.
// Pure view: cosmetic Style/Border-field-deletion + button-status match-arm
// mutants aren't regex-excludable in cargo-mutants 27; the testable bits live
// in the pure state module (state::property_view) and in file_tree::row_indent.
#[mutants::skip]
fn build_row(row: crate::state::property_view::PropRow) -> Element<'static, Message> {
    let indent = row_indent(row.depth);

    match row.kind {
        PropKind::Branch if row.is_expandable => {
            let chevron = if row.expanded { "▾" } else { "▸" };
            let node_id = row.node_id;

            let content = iced::widget::row![
                iced::widget::Space::new().width(indent),
                text(chevron)
                    .size(f32::from(tokens::TEXT_MD))
                    .style(|theme: &iced::Theme| iced::widget::text::Style {
                        color: Some(theme.palette().text),
                    }),
                iced::widget::Space::new().width(tokens::SPACE_XS),
                text(row.label)
                    .size(f32::from(tokens::TEXT_MD))
                    .style(|theme: &iced::Theme| iced::widget::text::Style {
                        color: Some(theme.palette().text),
                    }),
            ]
            .align_y(iced::Alignment::Center);

            button(content)
                .on_press(Message::PropToggled(node_id))
                .padding([tokens::SPACE_XS, tokens::SPACE_SM])
                .width(Length::Fill)
                .style(|theme: &iced::Theme, status| {
                    let palette = theme.palette();
                    match status {
                        iced::widget::button::Status::Hovered
                        | iced::widget::button::Status::Pressed => iced::widget::button::Style {
                            background: Some(iced::Background::Color(
                                palette.text.scale_alpha(0.07),
                            )),
                            text_color: palette.text,
                            ..Default::default()
                        },
                        _ => iced::widget::button::Style {
                            text_color: palette.text,
                            ..Default::default()
                        },
                    }
                })
                .into()
        }

        PropKind::Branch => build_static_branch_row(indent, row.label),

        PropKind::Leaf => {
            // Leaf rows: indent spacer + label + optional color swatch + muted value.
            let label_part: Element<'static, Message> = text(row.label)
                .size(f32::from(tokens::TEXT_MD))
                .style(|theme: &iced::Theme| iced::widget::text::Style {
                    color: Some(theme.palette().text),
                })
                .into();

            let swatch_part: Option<Element<'static, Message>> = row.color.map(|[r, g, b, a]| {
                let fill = iced::Color { r, g, b, a };
                container(iced::widget::Space::new())
                    .width(SWATCH_SIZE)
                    .height(SWATCH_SIZE)
                    .style(move |theme: &iced::Theme| iced::widget::container::Style {
                        background: Some(iced::Background::Color(fill)),
                        border: iced::Border {
                            color: theme.palette().text.scale_alpha(SWATCH_BORDER_ALPHA),
                            width: 1.0,
                            radius: 0.0.into(),
                        },
                        ..Default::default()
                    })
                    .into()
            });

            let value_part: Option<Element<'static, Message>> = row.value.map(|v| {
                text(v)
                    .size(f32::from(tokens::TEXT_MD))
                    .style(|theme: &iced::Theme| iced::widget::text::Style {
                        color: Some(theme.palette().text.scale_alpha(tokens::TEXT_MUTED_ALPHA)),
                    })
                    .into()
            });

            let mut leaf_row = row![
                iced::widget::Space::new()
                    .width(crate::widgets::file_tree::file_row_indent(indent)),
                label_part,
            ]
            .align_y(iced::Alignment::Center)
            .spacing(tokens::SPACE_SM);

            if let Some(swatch) = swatch_part {
                leaf_row = leaf_row.push(swatch);
            }
            if let Some(value) = value_part {
                leaf_row = leaf_row.push(value);
            }

            container(leaf_row)
                .padding([tokens::SPACE_XS, tokens::SPACE_SM])
                .width(Length::Fill)
                .into()
        }
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// The inspector's rows are label rows, not hex rows. A review probe
    /// swapped this for the hex height and the whole suite stayed green. This
    /// pins what the helper returns; that the view passes it is pinned by
    /// `props_window_uses_the_label_height_and_the_shipped_overscan`.
    #[test]
    fn property_row_height_is_the_shared_label_row_height() {
        assert!(
            (row_pixel_height() - crate::state::row_window::label_row_height()).abs()
                < f32::EPSILON,
            "property rows are the same shape as file-tree rows"
        );
        assert!(
            (row_pixel_height() - crate::state::hex_view::row_pixel_height()).abs() > f32::EPSILON,
            "and must differ from the hex grid's row height"
        );
    }

    /// The window this surface builds must use the LABEL geometry — probes
    /// swapped the height and zeroed the overscan at the view's call site
    /// with the suite green, since the view is mutants-skipped.
    #[test]
    fn props_window_uses_the_label_height_and_the_shipped_overscan() {
        use crate::state::row_window::{
            OVERSCAN_ROWS, ScrollPos, label_row_height, visible_window,
        };
        let scroll = ScrollPos {
            y: 2620.0,
            viewport_h: 600.0,
        };
        let got = window(1_500, scroll);
        assert_eq!(
            got,
            visible_window(1_500, label_row_height(), scroll, OVERSCAN_ROWS)
        );
        assert_ne!(
            got,
            visible_window(
                1_500,
                crate::state::hex_view::row_pixel_height(),
                scroll,
                OVERSCAN_ROWS
            ),
            "the hex height must not produce the inspector's window"
        );
        assert_ne!(
            got,
            visible_window(1_500, label_row_height(), scroll, 0),
            "zero overscan must not produce the inspector's window"
        );
    }

    #[test]
    fn max_visible_prop_rows_is_2000() {
        assert_eq!(MAX_VISIBLE_PROP_ROWS, 2000);
    }
}
