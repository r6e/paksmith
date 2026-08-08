//! Status-bar panel — shows the open file name, entry count, selected
//! entry summary, and process memory usage (#661).
//!
//! The memory reading comes from [`crate::state::memory`] (the lightweight
//! cross-platform RSS reader this module's doc used to defer on), refreshed
//! on the coarse `MEMORY_TICK` subscription.

use std::path::Path;

use iced::widget::{container, row, text};
use iced::{Element, Length};

use crate::app::Message;
use crate::theme::tokens::{SPACE_MD, SPACE_SM, TEXT_SM, muted_text_style};

/// Render the status bar.
///
/// # Arguments
///
/// * `archive_path` – path to the open archive, or `None` when no archive is
///   loaded.
/// * `entry_count` – total number of entries in the archive.
/// * `selected_name` – the file-name (not full path) of the currently selected
///   file, or `None` when nothing is selected.
/// * `memory` – the pre-formatted memory label from
///   [`crate::state::memory::memory_label`], or `None` when there is no
///   reading to show (the segment hides).
// Pure view: cosmetic Style-field-deletion mutants aren't regex-excludable in
// cargo-mutants 27 (see app::view for the rationale); validated by UI/UX review.
#[mutants::skip]
pub fn view<'a>(
    archive_path: Option<&'a Path>,
    entry_count: usize,
    selected_name: Option<&'a str>,
    memory: Option<String>,
) -> Element<'a, Message> {
    let file_label: Element<'a, Message> = match archive_path {
        None => text("No archive open")
            .size(f32::from(TEXT_SM))
            .style(muted_text_style)
            .into(),
        Some(path) => {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("\u{2014}");
            text(format!("{name} \u{2022} {entry_count} entries"))
                .size(f32::from(TEXT_SM))
                .into()
        }
    };

    let selection_label = muted_segment(selected_name.map(|name| format!("Selected: {name}")));

    // Last segment per the SPEC's order ("loaded archive, entry count,
    // memory"); muted like the selection so the file name stays the loudest.
    let memory_label = muted_segment(memory);

    container(
        row![
            file_label,
            iced::widget::Space::new().width(Length::Fill),
            selection_label,
            memory_label,
        ]
        .align_y(iced::Alignment::Center)
        .spacing(SPACE_SM),
    )
    .style(|theme: &iced::Theme| {
        let palette = theme.extended_palette();
        iced::widget::container::Style {
            background: Some(iced::Background::Color(palette.background.weak.color)),
            border: iced::Border {
                color: palette.background.strong.color,
                width: 0.0,
                radius: 0.0.into(),
            },
            ..Default::default()
        }
    })
    .padding([SPACE_SM, SPACE_MD])
    .width(Length::Fill)
    .into()
}

/// An optional muted status-bar segment: the text when present, an empty
/// placeholder when absent (keeping the row's child count and spacing slots
/// stable, the pattern the selection segment always used).
#[mutants::skip]
fn muted_segment(label: Option<String>) -> Element<'static, Message> {
    match label {
        None => text("").size(f32::from(TEXT_SM)).into(),
        Some(label) => text(label)
            .size(f32::from(TEXT_SM))
            .style(muted_text_style)
            .into(),
    }
}
