//! Toolbar panel — Open button, decryption-status pill, and filter input.
//!
//! # Task 12 forward note
//! The profile selector (game picker) will be inserted to the right of the
//! filter input once the profile-selector overlay is wired up in Task 12.
//! A placeholder `Space` keeps the layout stable until then.

use iced::widget::{button, row, text, text_input};
use iced::{Element, Length};

use crate::app::Message;
use crate::theme::tokens::{SPACE_MD, SPACE_SM, SPACE_XS, TEXT_SM};

/// Render the toolbar row.
///
/// # Arguments
///
/// * `decrypted` – `Some(true)` → 🔓 "Decrypted" pill; `Some(false)` → 🔒
///   "Encrypted" pill; `None` (no archive open) → no pill.
/// * `filter` – current filter text bound to `Message::FilterChanged`.
pub fn view(decrypted: Option<bool>, filter: &str) -> Element<'_, Message> {
    let open_btn = button(text("Open\u{2026}").size(f32::from(TEXT_SM)))
        .style(iced::widget::button::primary)
        .padding([SPACE_SM, SPACE_MD])
        .on_press(Message::OpenRequested);

    let filter_input = text_input("Filter\u{2026}", filter)
        .on_input(Message::FilterChanged)
        .size(f32::from(TEXT_SM))
        .padding(SPACE_SM)
        .width(Length::Fill);

    let mut items: Vec<Element<'_, Message>> = vec![open_btn.into()];

    if let Some(is_decrypted) = decrypted {
        let pill_label = if is_decrypted {
            "\u{1F513} Decrypted"
        } else {
            "\u{1F512} Encrypted"
        };
        let pill = text(pill_label)
            .size(f32::from(TEXT_SM))
            .style(move |theme: &iced::Theme| iced::widget::text::Style {
                color: Some(if is_decrypted {
                    theme.palette().success
                } else {
                    theme.extended_palette().danger.base.text
                }),
            });
        items.push(pill.into());
    }

    items.push(filter_input.into());
    // Task 12 placeholder: profile-selector will be inserted here.

    row(items)
        .spacing(SPACE_SM)
        .align_y(iced::Alignment::Center)
        .padding([SPACE_XS, SPACE_MD])
        .into()
}
