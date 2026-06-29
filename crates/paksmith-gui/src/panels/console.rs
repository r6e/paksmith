//! Debug-console panel: a bounded, filterable view of captured tracing events.
//!
//! Thin rendering only — every decision lives in `crate::state::console` /
//! `crate::state::log_buffer`, which are unit + mutation tested.

use iced::widget::{button, column, container, pick_list, row, scrollable, text, text_input};
use iced::{Element, Length};

use crate::app::{App, Message};
use crate::state::console::{self, LEVEL_CHOICES, format_line};
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

    let controls = row![
        pick_list(
            LEVEL_CHOICES.to_vec(),
            Some(app.console_filters.min_level),
            Message::ConsoleMinLevelChanged,
        )
        .text_size(f32::from(TEXT_SM)),
        text_input("target\u{2026}", &app.console_filters.target_filter)
            .on_input(Message::ConsoleTargetFilterChanged)
            .size(f32::from(TEXT_SM))
            .width(Length::FillPortion(2)),
        text_input("search\u{2026}", &app.console_filters.search)
            .on_input(Message::ConsoleSearchChanged)
            .size(f32::from(TEXT_SM))
            .width(Length::FillPortion(3)),
        button(text("Clear").size(f32::from(TEXT_SM)))
            .style(iced::widget::button::secondary)
            .on_press(Message::ConsoleCleared),
        button(text("Copy").size(f32::from(TEXT_SM)))
            .style(iced::widget::button::secondary)
            .on_press(Message::ConsoleCopyAll),
    ]
    .spacing(SPACE_SM)
    .align_y(iced::Alignment::Center);

    container(column![controls, body].spacing(SPACE_SM))
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
