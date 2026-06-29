//! Sidebar panel — file-tree explorer with a subtle "Explorer" section header.
//!
//! # Resize divider
//!
//! Resizing is handled by the parent `pane_grid` widget in `app::view`, which
//! tracks the drag cursor relative to its own bounds and emits
//! `Message::PaneResized` only while a drag is active.  The sidebar itself
//! does not need to manage a divider or coordinate-space conversion.

use iced::widget::{column, container, text};
use iced::{Element, Length};

use crate::app::Message;
use crate::state::tree::Tree;
use crate::theme::tokens::{SPACE_SM, SPACE_XS, TEXT_MUTED_ALPHA, TEXT_SM};
use crate::widgets::file_tree;

/// Render the sidebar panel: "EXPLORER" caption + file tree.
///
/// The drag divider is owned by the parent `pane_grid`; this function only
/// produces the sidebar pane content.
///
/// # Arguments
///
/// * `tree` – the archive's file-tree model.
/// * `accent` – system accent color (forwarded to `file_tree::view`).
/// * `selected_row` – keyboard cursor position.
/// * `context_row` – visible-row index whose inline action strip is shown.
/// * `export_menu` – the open Export As… picker, if any.
pub fn view<'a>(
    tree: &'a Tree,
    accent: iced::Color,
    selected_row: Option<usize>,
    context_row: Option<usize>,
    export_menu: Option<&'a crate::state::export::ExportMenu>,
) -> Element<'a, Message> {
    let header = text("EXPLORER")
        .size(f32::from(TEXT_SM))
        .style(|theme: &iced::Theme| iced::widget::text::Style {
            color: Some(theme.palette().text.scale_alpha(TEXT_MUTED_ALPHA)),
        });

    let tree_view = file_tree::view(tree, accent, selected_row, context_row, export_menu);

    container(
        column![header, tree_view]
            .spacing(SPACE_XS)
            .width(Length::Fill)
            .height(Length::Fill),
    )
    .padding([SPACE_SM, SPACE_SM])
    .width(Length::Fill)
    .height(Length::Fill)
    .into()
}
