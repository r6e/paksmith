//! Property-tree widget: renders the pure `PropRow` model as an interactive,
//! scrollable, type-aware inspector.
//!
//! # Virtualization note
//!
//! `flatten()` already contains ONLY currently-expanded nodes, so
//! fully-collapsed sub-trees contribute a single row (their branch header). The
//! slice is rendered directly inside a `scrollable` + `column`. This is the
//! pragmatic Phase 7a approach.
//!
//! **Known limitation:** if the user expands all branches of a deeply-nested
//! asset (e.g. a large DataTable with many properties, all expanded), `flatten`
//! will return many elements and each one is built into an Iced widget during
//! every frame. True viewport virtualization (rendering only on-screen rows via a
//! custom Iced `Widget`) is a follow-up item. For typical usage patterns
//! (explore-by-navigation, not expand-all), the scrollable slice is bounded and
//! the overhead is negligible.

use iced::widget::{button, column, container, row, scrollable, text};
use iced::{Element, Length};

use crate::app::Message;
use crate::state::property_view::{NodeId, PropKind, flatten};
use crate::theme::tokens;
use crate::widgets::file_tree::row_indent;

// ── row cap ───────────────────────────────────────────────────────────────────

/// Maximum number of property rows rendered per frame. A crafted asset with
/// hundreds of thousands of exports would build that many Iced widgets on the
/// Properties view (no interaction required) and freeze the UI. This cap mirrors
/// the hex view's [`crate::widgets::hex_view::MAX_HEX_DISPLAY_BYTES`] strategy:
/// show a bounded slice and append a note when the asset exceeds it.
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
///
/// # Rendering bound
///
/// Rendering is capped at `MAX_VISIBLE_PROP_ROWS` (a truncation note is shown
/// when exceeded), so a deeply-expanded large asset cannot build an unbounded
/// widget tree. TODO(perf): `flatten` still rebuilds the full row `Vec` per
/// call; memoize it (and add a "Collapse All") when wide-DataTable inspection
/// becomes a primary workflow.
#[mutants::skip]
pub fn view<'a>(
    pkg: &'a paksmith_core::asset::Package,
    expanded: &std::collections::HashSet<NodeId>,
) -> Element<'a, Message> {
    let rows = flatten(pkg, expanded);
    let total = rows.len();

    let mut items: Vec<Element<'_, Message>> = rows
        .into_iter()
        .take(MAX_VISIBLE_PROP_ROWS)
        .map(build_row)
        .collect();

    if total > MAX_VISIBLE_PROP_ROWS {
        items.push(
            container(
                text(format!(
                    "Showing first {MAX_VISIBLE_PROP_ROWS} of {total} properties \u{2014} collapse nodes or extract the asset to inspect fully",
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
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
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

    #[test]
    fn max_visible_prop_rows_is_2000() {
        assert_eq!(MAX_VISIBLE_PROP_ROWS, 2000);
    }
}
