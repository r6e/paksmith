//! Toolbar panel — Open button, decryption-status pill, and filter input.
//!
//! # Task 12 forward note
//! The profile selector (game picker) will be inserted to the right of the
//! filter input once the profile-selector overlay is wired up in Task 12.
//! A placeholder `Space` keeps the layout stable until then.

use iced::widget::{button, container, row, text, text_input};
use iced::{Background, Element, Length};

use crate::app::Message;
use crate::theme::tokens::{RADIUS, SPACE_MD, SPACE_SM, SPACE_XS, TEXT_MD, TEXT_SM};

/// Render the toolbar row.
///
/// The toolbar has the same `background.weak` fill as the status bar so the
/// top and bottom chrome frame the content symmetrically.
///
/// # Arguments
///
/// * `decrypted` – `Some(true)` → 🔓 "Decrypted" chip; `Some(false)` → 🔒
///   "Encrypted" chip; `None` (no archive open) → no chip.
/// * `filter` – current filter text bound to `Message::FilterChanged`.
pub fn view(decrypted: Option<bool>, filter: &str) -> Element<'_, Message> {
    let open_btn = button(text("Open\u{2026}").size(f32::from(TEXT_MD)))
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
        // Chip: tinted background at low alpha + rounded corners.
        // Text uses extended_palette success/danger base text for legibility
        // in both light and dark themes.
        let chip = container(text(pill_label).size(f32::from(TEXT_SM)).style(
            move |theme: &iced::Theme| iced::widget::text::Style {
                color: Some(if is_decrypted {
                    theme.extended_palette().success.base.text
                } else {
                    theme.extended_palette().danger.base.text
                }),
            },
        ))
        .style(move |theme: &iced::Theme| {
            let palette = theme.extended_palette();
            let bg_color = if is_decrypted {
                let mut c = palette.success.base.color;
                c.a = 0.18;
                c
            } else {
                let mut c = palette.danger.base.color;
                c.a = 0.18;
                c
            };
            iced::widget::container::Style {
                background: Some(Background::Color(bg_color)),
                border: iced::Border {
                    radius: RADIUS.into(),
                    ..Default::default()
                },
                ..Default::default()
            }
        })
        .padding([SPACE_XS, SPACE_SM]);
        items.push(chip.into());
    }

    items.push(filter_input.into());
    // Task 12 placeholder: profile-selector will be inserted here.

    container(
        row(items)
            .spacing(SPACE_SM)
            .align_y(iced::Alignment::Center)
            .padding([SPACE_XS, SPACE_MD]),
    )
    .style(|theme: &iced::Theme| {
        let palette = theme.extended_palette();
        iced::widget::container::Style {
            background: Some(Background::Color(palette.background.weak.color)),
            ..Default::default()
        }
    })
    .width(Length::Fill)
    .into()
}
