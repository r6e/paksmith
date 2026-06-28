//! Thin inline context-menu strip rendered beneath a right-clicked file row.
//!
//! All decision logic lives in `app::update` and `file_tree::show_strip_after`;
//! this is rendering only. The buttons carry only the row index — the path is
//! resolved in `update` so the per-frame view never clones a path String.
//!
//! Visually the strip is a distinct full-width band (a subtle filled surface
//! with rounded corners) so it reads as a set of *actions* attached to the row
//! above, not as two more tree rows. It is deliberately near-flush (not indented
//! to the owning file's depth): tracking depth made it look like child rows and
//! could push the buttons off-screen at deep nesting in a narrow sidebar.

use iced::widget::{button, container, row, text};
use iced::{Background, Border, Element, Length};

use crate::theme::tokens::{RADIUS, SPACE_SM, SPACE_XS, TEXT_SM};

use crate::app::Message;

/// The inline action strip (Open / Copy Path) for the file row at visible index
/// `row_idx`, rendered as a distinct band that spans the sidebar width.
#[mutants::skip] // pure iced view composition; logic is in update + show_strip_after
pub fn action_strip<'a>(row_idx: usize) -> Element<'a, Message> {
    let open = button(text("Open").size(f32::from(TEXT_SM)))
        .style(iced::widget::button::text)
        .padding([SPACE_XS, SPACE_SM])
        .on_press(Message::OpenAssetByRow(row_idx));

    let copy = button(text("Copy Path").size(f32::from(TEXT_SM)))
        .style(iced::widget::button::text)
        .padding([SPACE_XS, SPACE_SM])
        .on_press(Message::CopyPathRequested(row_idx));

    let actions = row![open, copy]
        .spacing(SPACE_SM)
        .align_y(iced::Alignment::Center);

    container(actions)
        .width(Length::Fill)
        .padding([SPACE_XS, SPACE_SM])
        .style(|theme: &iced::Theme| {
            let palette = theme.extended_palette();
            iced::widget::container::Style {
                background: Some(Background::Color(palette.background.weak.color)),
                border: Border {
                    radius: RADIUS.into(),
                    ..Default::default()
                },
                ..Default::default()
            }
        })
        .into()
}
