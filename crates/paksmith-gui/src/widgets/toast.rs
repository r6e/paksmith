//! Thin toast-overlay widget: renders the live toast list as a bottom-trailing
//! stack of cards. All logic lives in `state/toast.rs`; this is rendering only.
//! Exact card/button colours are cosmetic and tuned under the UI/UX review.

use iced::widget::{button, column, container, row, text};
use iced::{Element, Length};

use crate::app::Message;
use crate::state::toast::{Severity, Toasts};
use crate::theme::tokens::{RADIUS, SPACE_MD, SPACE_SM, TEXT_SM};

/// Bottom-trailing toast overlay for the `stack` layer. The container fills the
/// area but is click-through (a plain container ignores mouse events it does not
/// handle, so they pass to the layer below); only each card's `×` button
/// captures clicks.
#[mutants::skip] // pure iced view composition; logic lives in state/toast.rs
pub fn overlay(toasts: &Toasts) -> Element<'_, Message> {
    let cards = toasts
        .items()
        .iter()
        .fold(column![].spacing(SPACE_SM), |col, t| {
            col.push(card(t.id, t.severity, &t.message))
        });
    container(cards)
        .align_right(Length::Fill)
        .align_bottom(Length::Fill)
        .padding(SPACE_MD)
        .into()
}

#[mutants::skip]
fn card(id: u64, severity: Severity, message: &str) -> Element<'_, Message> {
    let dismiss = button(text("\u{00d7}").size(f32::from(TEXT_SM)))
        .padding([0.0, SPACE_SM])
        .style(iced::widget::button::text)
        .on_press(Message::ToastDismissed(id));

    let body = row![text(message).size(f32::from(TEXT_SM)), dismiss]
        .spacing(SPACE_SM)
        .align_y(iced::Alignment::Center);

    container(body)
        .padding([SPACE_SM, SPACE_MD])
        .style(move |theme: &iced::Theme| {
            let palette = theme.extended_palette();
            let pair = match severity {
                Severity::Success => palette.success.base,
                Severity::Error => palette.danger.base,
            };
            iced::widget::container::Style {
                background: Some(iced::Background::Color(pair.color)),
                text_color: Some(pair.text),
                border: iced::Border {
                    radius: RADIUS.into(),
                    ..Default::default()
                },
                ..Default::default()
            }
        })
        .into()
}
