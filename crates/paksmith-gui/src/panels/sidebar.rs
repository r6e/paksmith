//! Sidebar panel — hosts the file-tree widget with a draggable resize divider.
//!
//! # Resize divider
//!
//! The sidebar uses `iced::widget::responsive` to obtain the full row width at
//! layout time, then wraps a thin divider strip in a `mouse_area`.  The
//! `on_move` closure computes the new ratio directly (absolute_x / row_width)
//! and emits `Message::SidebarResized(ratio)`.  Because the ratio is
//! pre-computed in the closure, `update` only needs to clamp and store it —
//! no window-width look-up required in the update path.
//!
//! The divider is 4 px wide with a subtle background tint + a grab cursor
//! affordance via a thin border highlight on hover.  The sidebar width is
//! `sidebar_ratio × available_width`; the detail pane takes the rest.

use iced::widget::{column, container, mouse_area, responsive, row, text};
use iced::{Element, Length};

use crate::app::Message;
use crate::state::tree::Tree;
use crate::theme::tokens::{SPACE_SM, TEXT_MD};
use crate::widgets::file_tree;

/// Width of the drag divider strip in pixels.
const DIVIDER_PX: f32 = 5.0;

/// Minimum and maximum sidebar ratio to prevent pathological sizes.
const RATIO_MIN: f32 = 0.15;
const RATIO_MAX: f32 = 0.65;

/// Render the sidebar panel: file tree + drag-resize divider.
///
/// Returns a `sidebar + divider` pair as a single element; the caller
/// (`app::view`) places the detail pane after it using `FillPortion`.
/// The drag divider emits `Message::SidebarResized(ratio)` on pointer-move
/// while hovered over the divider strip.
///
/// # Arguments
///
/// * `tree` – the archive's file-tree model.
/// * `accent` – system accent color (forwarded to `file_tree::view`).
/// * `selected_row` – keyboard cursor position.
pub fn view(tree: &Tree, accent: iced::Color, selected_row: Option<usize>) -> Element<'_, Message> {
    // Use `responsive` so we know the available row width at layout time.
    // This lets us pre-compute the new ratio in the `on_move` closure without
    // a separate window-size look-up in `update`.
    responsive(move |size| {
        let row_width = size.width;

        // ── file tree area ────────────────────────────────────────────────────
        let tree_view = file_tree::view(tree, accent, selected_row);

        let sidebar_content = column![tree_view].width(Length::Fill).height(Length::Fill);

        let sidebar_container = container(sidebar_content)
            .width(Length::Fill)
            .height(Length::Fill);

        // ── drag divider ──────────────────────────────────────────────────────
        // A 5-px strip styled as a subtle border. `mouse_area` wraps it so
        // pointer events can be intercepted.
        //
        // `on_move` fires with absolute cursor coordinates within the
        // `mouse_area`. We convert to a ratio by dividing the X position by
        // the total row width (minus the divider's own width).
        let effective_width = (row_width - DIVIDER_PX).max(1.0);

        let divider_content = container(
            iced::widget::Space::new()
                .width(DIVIDER_PX)
                .height(Length::Fill),
        )
        .style(|theme: &iced::Theme| {
            let palette = theme.extended_palette();
            iced::widget::container::Style {
                background: Some(iced::Background::Color(palette.background.strong.color)),
                ..Default::default()
            }
        })
        .width(Length::Fixed(DIVIDER_PX))
        .height(Length::Fill);

        let divider = mouse_area(divider_content).on_move(move |point| {
            // Compute ratio from absolute X within the responsive container.
            // Clamp to safe range so the panels never disappear.
            #[allow(clippy::cast_precision_loss)]
            let raw_ratio = point.x / effective_width;
            let ratio = raw_ratio.clamp(RATIO_MIN, RATIO_MAX);
            Message::SidebarResized(ratio)
        });

        row![sidebar_container, divider,]
            .height(Length::Fill)
            .into()
    })
    .into()
}

/// Build the filter + tree section shown inside the sidebar, as a plain
/// `Element` for callers who want to compose it manually (e.g. in tests).
///
/// This is currently used only by `sidebar::view` above, but is `pub` so
/// future Tasks (e.g. Task 11 menu) can embed it without duplicating code.
#[allow(dead_code)]
pub fn tree_content(
    tree: &Tree,
    accent: iced::Color,
    selected_row: Option<usize>,
) -> Element<'_, Message> {
    // The actual tree is scrollable; the label just provides header context.
    let header = text("Explorer")
        .size(f32::from(TEXT_MD))
        .style(|theme: &iced::Theme| iced::widget::text::Style {
            color: Some(theme.palette().text.scale_alpha(0.65)),
        });

    column![header, file_tree::view(tree, accent, selected_row),]
        .spacing(SPACE_SM)
        .height(Length::Fill)
        .into()
}
