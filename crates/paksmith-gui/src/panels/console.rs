//! Debug-console panel: a bounded, filterable view of captured tracing events.
//!
//! Thin rendering only — every decision lives in `crate::state::console` /
//! `crate::state::log_buffer`, which are unit + mutation tested.

use iced::widget::{column, container, scrollable, text};
use iced::{Element, Length};

use crate::app::{App, Message};
use crate::state::console::{self, format_line};
use crate::theme::tokens::{SPACE_SM, TEXT_SM};

/// Stable id so `update` can issue snap-to-bottom scroll tasks.
pub const SCROLL_ID: iced::widget::Id = iced::widget::Id::new("paksmith-console-scroll");

/// Fixed height of the console panel (px).
const CONSOLE_HEIGHT: f32 = 200.0;

#[mutants::skip] // thin view glue: rendering isn't unit-testable
pub fn view(app: &App) -> Element<'_, Message> {
    let records = app.log_buffer.snapshot();
    let shown = console::displayed(&records, &app.console_filters);

    let mut list = column![].spacing(2);
    for record in shown {
        list = list.push(text(format_line(record)).size(f32::from(TEXT_SM)));
    }

    let body = scrollable(list.width(Length::Fill))
        .id(SCROLL_ID)
        .on_scroll(|viewport| Message::ConsoleScrolled(viewport.relative_offset().y))
        .width(Length::Fill)
        .height(Length::Fill);

    container(body)
        .padding(SPACE_SM)
        .width(Length::Fill)
        .height(Length::Fixed(CONSOLE_HEIGHT))
        .style(|theme: &iced::Theme| container::Style {
            background: Some(iced::Background::Color(
                theme.extended_palette().background.weak.color,
            )),
            ..Default::default()
        })
        .into()
}
