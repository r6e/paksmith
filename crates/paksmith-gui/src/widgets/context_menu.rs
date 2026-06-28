//! Thin inline context-menu strip rendered beneath a right-clicked file row.
//!
//! All decision logic lives in `app::update` and `file_tree::show_strip_after`;
//! this is rendering only. The buttons carry only the row index — the path is
//! resolved in `update` so the per-frame view never clones a path String.

use iced::widget::{Space, button, row, text};
use iced::{Element, Length};

use crate::app::Message;
use crate::theme::tokens::{SPACE_SM, SPACE_XS, TEXT_SM};

/// The inline action strip (Open / Copy Path) for the file row at visible index
/// `row_idx`. `indent` is the leading pixel offset so the strip lines up under
/// the file label.
#[mutants::skip] // pure iced view composition; logic is in update + show_strip_after
pub fn action_strip<'a>(row_idx: usize, indent: f32) -> Element<'a, Message> {
    let open = button(text("Open").size(f32::from(TEXT_SM)))
        .style(iced::widget::button::text)
        .padding([SPACE_XS, SPACE_SM])
        .on_press(Message::OpenAssetByRow(row_idx));

    let copy = button(text("Copy Path").size(f32::from(TEXT_SM)))
        .style(iced::widget::button::text)
        .padding([SPACE_XS, SPACE_SM])
        .on_press(Message::CopyPathRequested(row_idx));

    row![Space::new().width(indent), open, copy]
        .spacing(SPACE_SM)
        .align_y(iced::Alignment::Center)
        .width(Length::Fill)
        .into()
}
