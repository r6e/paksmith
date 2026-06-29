//! Shared inline-menu band for the row context menu (`action_strip`) and the
//! Export As… picker (`picker_strip`), so both read as the same surface: a
//! full-width, subtly-filled, rounded container.

use iced::widget::container;
use iced::{Background, Border, Element, Length};

use crate::app::Message;
use crate::theme::tokens::{RADIUS, SPACE_SM, SPACE_XS};

/// Wrap `content` in the full-width inline-menu band (background.weak fill +
/// RADIUS corners). The single source of truth for the band's surface style.
#[mutants::skip] // pure iced view composition
pub fn band<'a>(content: impl Into<Element<'a, Message>>) -> Element<'a, Message> {
    container(content)
        .width(Length::Fill)
        .padding([SPACE_XS, SPACE_SM])
        .style(|theme: &iced::Theme| {
            let palette = theme.extended_palette();
            container::Style {
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
