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

use iced::widget::{button, column, mouse_area, scrollable, text};
use iced::{Background, Color, Element, Length};

use crate::app::Message;
use crate::state::tree::{Tree, VisibleRow};
use crate::theme::tokens;

/// Stable [`iced::widget::Id`] for the file-tree scrollable, used by keyboard
/// auto-scroll to programmatically set the scroll position.
pub const TREE_SCROLL_ID: iced::widget::Id = iced::widget::Id::new("file-tree-scroll");

// ── pure helpers ──────────────────────────────────────────────────────────────

/// Pixel indent for a tree node at the given depth.
///
/// Uses [`tokens::TREE_INDENT`] as the per-level step so the design scale is
/// the single source of truth.
pub fn row_indent(depth: usize) -> f32 {
    // Depth values in practice are small (< a few hundred even in pathological
    // trees), so the precision loss from usize→f32 is inconsequential.
    #[allow(clippy::cast_precision_loss)]
    let depth_f32 = depth as f32;
    depth_f32 * tokens::TREE_INDENT
}

/// Pixel indent for a file row — one extra [`tokens::TREE_INDENT`] step past
/// the parent directory's indent so the label aligns just after the chevron.
pub fn file_row_indent(depth_indent: f32) -> f32 {
    depth_indent + tokens::TREE_INDENT
}

/// Returns `true` when row index `row_idx` matches the current keyboard cursor.
fn row_is_selected(row_idx: usize, selected: Option<usize>) -> bool {
    selected == Some(row_idx)
}

/// What to render in the inline band beneath a right-clicked file row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowMenu {
    /// Nothing (not the context row, or a dir / pathless row).
    None,
    /// The Open / Copy Path / Export As… action strip.
    Actions,
    /// The Export As… format picker (Export As… was chosen for this row).
    Picker,
}

/// Decide the inline band for visible row `row_idx`.
///
/// Both menus hang off the single right-clicked row (`context_row`). When an
/// `ExportMenu` is open for *this row's path* (`export_menu_path`), the picker
/// supersedes the action strip; otherwise the action strip shows. Directory
/// rows and rows without a resolvable path never get a menu. The path match (not
/// just `context_row == row_idx`) guards against a stale picker after a tree
/// reshuffle moved the path off the context row.
#[must_use]
pub fn row_menu_after(
    context_row: Option<usize>,
    export_menu_path: Option<&str>,
    row_idx: usize,
    row: &VisibleRow,
) -> RowMenu {
    if context_row != Some(row_idx) || row.is_dir || row.full_path.is_none() {
        return RowMenu::None;
    }
    if export_menu_path == row.full_path.as_deref() {
        RowMenu::Picker
    } else {
        RowMenu::Actions
    }
}

/// The glyph string rendered before the label for a directory row.
///
/// Directories show a chevron (▸ collapsed, ▾ expanded). File rows render no
/// glyph — they are indented under their parent dir, which is sufficient
/// visual hierarchy without a redundant icon.
pub fn glyph_for_row(row: &VisibleRow) -> Option<&'static str> {
    if row.is_dir {
        Some(if row.expanded { "▾" } else { "▸" })
    } else {
        None
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
/// * `context_row` — the visible-row index whose inline action strip (Open /
///   Copy Path / Export As…) is shown, or `None`. The strip is rendered
///   immediately after that row (file rows only).
/// * `export_menu` — the open Export As… picker, or `None`. When `Some`, the
///   picker replaces the action strip for the matching row.
///
/// Each row emits:
/// * `Message::RowToggled(i)` when a directory row is clicked.
/// * `Message::RowSelected(i)` when a file row is clicked.
/// * `Message::RowContextOpened(i)` when a file row is right-clicked.
// Pure iced view composition (like the sibling `tab_bar`/`hex_view`/`property_tree`
// view fns). The decision of which inline band shows is extracted into the
// unit-tested `row_menu_after`; this fn only wires the result into the
// opaque scrollable `Element`, so there is nothing here a unit test can observe.
#[mutants::skip]
pub fn view<'a>(
    tree: &'a Tree,
    accent: Color,
    selected_row: Option<usize>,
    context_row: Option<usize>,
    export_menu: Option<&'a crate::state::export::ExportMenu>,
) -> Element<'a, Message> {
    let rows = tree.visible_rows();
    // `+ 1`: when a context menu is open the loop pushes one extra element (the
    // action strip or picker), so reserving `rows.len() + 1` avoids a
    // reallocation in that case. Safe to spell out the arithmetic here because
    // `view` is `#[mutants::skip]` — an off-by-one in a capacity hint changes no
    // behaviour and would otherwise be an unkillable mutant.
    let mut items: Vec<Element<'a, Message>> = Vec::with_capacity(rows.len() + 1);
    let export_menu_path = export_menu.map(|m| m.path.as_str());
    for (i, row) in rows.iter().enumerate() {
        items.push(build_row(i, row, accent, selected_row, context_row));
        match row_menu_after(context_row, export_menu_path, i, row) {
            RowMenu::Actions => items.push(crate::widgets::context_menu::action_strip(i)),
            RowMenu::Picker => {
                // Picker ⇒ export_menu is Some (row_menu_after guarantees it).
                if let Some(menu) = export_menu {
                    items.push(crate::widgets::export_picker::picker_strip(menu));
                }
            }
            RowMenu::None => {}
        }
    }

    scrollable(column(items).width(Length::Fill))
        .id(TREE_SCROLL_ID.clone())
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}

/// Build one row widget.
// Pure view: cosmetic Style/Border-field-deletion + button-status match-arm
// mutants aren't regex-excludable in cargo-mutants 27 (see app::view); the
// testable bits (file_row_indent, row_is_selected) are extracted + unit-tested.
#[mutants::skip]
#[allow(clippy::too_many_lines)] // single-fn row builder; splitting would obscure the structure
fn build_row(
    i: usize,
    row: &VisibleRow,
    accent: Color,
    selected_row: Option<usize>,
    context_row: Option<usize>,
) -> Element<'_, Message> {
    let is_selected = row_is_selected(i, selected_row);
    // The file row whose inline context menu is open. Reuses the same index-match
    // predicate as keyboard selection; only ever true for a file row (the menu
    // can only open on files).
    let is_context_owner = row_is_selected(i, context_row);
    let indent = row_indent(row.depth);

    // The row content: optional accent left-border + indent spacer + optional
    // dir glyph + label.
    //
    // Selected rows get a 3-px accent-coloured left border (VS Code / Xcode
    // pattern) in addition to the background tint, so selection is unambiguous
    // on any accent / background combination.
    let selection_border_width = if is_selected { 3.0_f32 } else { 0.0_f32 };

    let content = if let Some(glyph) = glyph_for_row(row) {
        // Directory row: chevron + label.
        iced::widget::row![
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
        .align_y(iced::Alignment::Center)
    } else {
        // File row: no glyph — indentation under the parent dir is the
        // affordance.  An extra TREE_INDENT step is added so file labels line
        // up just past where the parent chevron would be.
        let file_indent = file_row_indent(indent);
        iced::widget::row![
            iced::widget::Space::new().width(file_indent),
            text(row.label.as_str())
                .size(f32::from(tokens::TEXT_MD))
                .style(move |theme: &iced::Theme| iced::widget::text::Style {
                    color: Some(theme.palette().text),
                }),
        ]
        .align_y(iced::Alignment::Center)
    };

    // Wrap the content in a button so we get hover feedback and click handling.
    // The button is styled to look like a flat tree row.
    //
    // Selected rows:
    //   • background: accent tint (0.18 alpha) — subtle wash
    //   • border: 3-px left edge in the accent colour — unambiguous anchor
    //
    // For file rows, the button is additionally wrapped in a `mouse_area` so
    // double-click emits `Message::OpenAssetByRow(i)` — the row INDEX, not the
    // path, so this per-frame render doesn't clone a path `String` for every
    // file row; `update` resolves the path once on the actual double-click.  We
    // keep the inner `button` (rather than replacing it with `mouse_area`) so
    // hover tint and selection highlight are preserved.  `button::on_press` fires
    // on the single-click; `mouse_area::on_double_click` fires on the second
    // click of a double-click — so both RowSelected AND OpenAssetByRow are emitted
    // on a double-click (RowSelected first), which is the desired behaviour
    // (select + open).  UI/UX note: there is no way to add a
    // hover-tint to the mouse_area layer itself in iced 0.14 (container has no
    // Status-aware style); the existing button hover style covers the row.
    if row.is_dir {
        let btn = button(content)
            .on_press(Message::RowToggled(i))
            .padding([tokens::SPACE_XS, tokens::SPACE_SM])
            .width(Length::Fill)
            .style(move |theme: &iced::Theme, status| {
                let palette = theme.palette();
                if is_selected {
                    iced::widget::button::Style {
                        background: Some(Background::Color(accent.scale_alpha(0.18))),
                        text_color: palette.text,
                        border: iced::Border {
                            color: accent,
                            width: selection_border_width,
                            radius: 0.0.into(),
                        },
                        ..Default::default()
                    }
                } else {
                    match status {
                        iced::widget::button::Status::Hovered
                        | iced::widget::button::Status::Pressed => iced::widget::button::Style {
                            background: Some(Background::Color(palette.text.scale_alpha(0.07))),
                            text_color: palette.text,
                            ..Default::default()
                        },
                        _ => iced::widget::button::Style {
                            text_color: palette.text,
                            ..Default::default()
                        },
                    }
                }
            });
        btn.into()
    } else {
        let btn = button(content)
            .on_press(Message::RowSelected(i))
            .padding([tokens::SPACE_XS, tokens::SPACE_SM])
            .width(Length::Fill)
            .style(move |theme: &iced::Theme, status| {
                let palette = theme.palette();
                // Fill and border are chosen independently so the two cues compose:
                //
                //   • Fill — the context-menu owner takes the strip band's
                //     `background.weak` surface so the row and the strip directly
                //     beneath it read as one block, and this wins even when the row
                //     is ALSO the keyboard cursor (select-then-right-click the same
                //     row). A selected non-owner gets the accent wash; otherwise the
                //     hover tint, or no fill.
                //   • Border — the 3-px accent left edge marks the keyboard cursor
                //     (`is_selected`) and is applied regardless of the fill, so a
                //     selected owner keeps its selection border over the band surface.
                let background = if is_context_owner {
                    Some(Background::Color(
                        theme.extended_palette().background.weak.color,
                    ))
                } else if is_selected {
                    Some(Background::Color(accent.scale_alpha(0.18)))
                } else {
                    match status {
                        iced::widget::button::Status::Hovered
                        | iced::widget::button::Status::Pressed => {
                            Some(Background::Color(palette.text.scale_alpha(0.07)))
                        }
                        _ => None,
                    }
                };
                let border = if is_selected {
                    iced::Border {
                        color: accent,
                        width: selection_border_width,
                        radius: 0.0.into(),
                    }
                } else {
                    iced::Border::default()
                };
                iced::widget::button::Style {
                    background,
                    text_color: palette.text,
                    border,
                    ..Default::default()
                }
            });
        // Wire double-click-to-open using the row index — path resolution happens
        // once in `update` (via `open_path_for_row`), not per-frame here.
        // Rows with no path (the `full_path: None` case) are handled in `update`:
        // `OpenAssetByRow` resolves to `None` and is silently ignored.
        //
        // A right-press toggles the inline context-menu strip for this file row
        // (`Message::RowContextOpened`). The inner `button` only captures LEFT
        // clicks, so right-presses fall through to this `mouse_area`. Files only —
        // directory rows are a plain `button` (no `mouse_area`) and get no menu.
        mouse_area(btn)
            .on_double_click(Message::OpenAssetByRow(i))
            .on_right_press(Message::RowContextOpened(i))
            .into()
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::tree::VisibleRow;
    use crate::theme::tokens;

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
        // Each level adds exactly TREE_INDENT pixels.
        #[allow(clippy::float_cmp)]
        {
            assert_eq!(row_indent(3) - row_indent(2), tokens::TREE_INDENT);
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
        assert_eq!(glyph_for_row(&dir_row(false)), Some("▸"));
    }

    #[test]
    fn glyph_expanded_dir() {
        assert_eq!(glyph_for_row(&dir_row(true)), Some("▾"));
    }

    #[test]
    fn glyph_file_has_none() {
        // Files render no glyph — they are indented under their parent dir.
        assert_eq!(glyph_for_row(&file_row()), None);
    }

    // ── file_row_indent ───────────────────────────────────────────────────────

    #[test]
    fn file_row_indent_adds_tree_indent() {
        let base = 32.0_f32;
        #[allow(clippy::float_cmp)]
        {
            assert_eq!(file_row_indent(base), base + tokens::TREE_INDENT);
        }
    }

    #[test]
    fn file_row_indent_is_greater_than_base() {
        // Adding TREE_INDENT must produce a value strictly greater — kills
        // `+ with -` and `+ with *` mutants.
        let base = 0.0_f32;
        assert!(
            file_row_indent(base) > base,
            "file indent must be deeper than directory indent at same depth"
        );
    }

    // ── row_is_selected ───────────────────────────────────────────────────────

    #[test]
    fn row_is_selected_matching_index_is_true() {
        assert!(row_is_selected(2, Some(2)));
    }

    #[test]
    fn row_is_selected_different_index_is_false() {
        // Kills `== with !=`: would flip this to true.
        assert!(!row_is_selected(2, Some(3)));
    }

    #[test]
    fn row_is_selected_none_is_false() {
        assert!(!row_is_selected(2, None));
    }

    // ── row_menu_after ────────────────────────────────────────────────────────

    #[test]
    fn row_menu_none_when_not_context_row() {
        assert_eq!(row_menu_after(Some(1), None, 0, &file_row()), RowMenu::None);
        assert_eq!(row_menu_after(None, None, 0, &file_row()), RowMenu::None);
    }

    #[test]
    fn row_menu_none_for_dir_or_pathless_row() {
        assert_eq!(
            row_menu_after(Some(0), None, 0, &dir_row(false)),
            RowMenu::None
        );
        let mut r = file_row();
        r.full_path = None;
        assert_eq!(row_menu_after(Some(0), None, 0, &r), RowMenu::None);
    }

    #[test]
    fn row_menu_actions_when_no_picker_open() {
        // file_row()'s full_path must be Some for this to be Actions.
        assert_eq!(
            row_menu_after(Some(0), None, 0, &file_row()),
            RowMenu::Actions
        );
    }

    #[test]
    fn row_menu_picker_when_export_menu_path_matches() {
        let r = file_row();
        let p = r.full_path.as_deref();
        assert_eq!(row_menu_after(Some(0), p, 0, &r), RowMenu::Picker);
    }

    #[test]
    fn row_menu_actions_when_export_menu_path_differs() {
        // Picker open for a different path (stale) → fall back to Actions, not Picker.
        assert_eq!(
            row_menu_after(Some(0), Some("Other/Different.uasset"), 0, &file_row()),
            RowMenu::Actions
        );
    }
}
