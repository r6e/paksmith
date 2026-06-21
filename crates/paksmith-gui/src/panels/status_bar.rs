//! Status-bar panel — shows the open file name, entry count, and selected
//! entry summary.
//!
//! Memory usage is omitted: adding `sysinfo` would pull in a heavyweight
//! dependency just for a nice-to-have metric that isn't required for Phase 6
//! functionality. A follow-up issue can add it once a lightweight cross-platform
//! RSS reader is identified.

use std::path::Path;

use iced::widget::{container, row, text};
use iced::{Element, Length};

use crate::app::Message;
use crate::theme::tokens::{SPACE_MD, SPACE_SM, TEXT_SM};

/// Render the status bar.
///
/// # Arguments
///
/// * `archive_path` – path to the open archive, or `None` when no archive is
///   loaded.
/// * `entry_count` – total number of entries in the archive.
/// * `selected_name` – the file-name (not full path) of the currently selected
///   file, or `None` when nothing is selected.
// Pure view: cosmetic Style-field-deletion mutants aren't regex-excludable in
// cargo-mutants 27 (see app::view for the rationale); validated by UI/UX review.
#[mutants::skip]
pub fn view<'a>(
    archive_path: Option<&'a Path>,
    entry_count: usize,
    selected_name: Option<&'a str>,
) -> Element<'a, Message> {
    let file_label: Element<'a, Message> = match archive_path {
        None => text("No archive open")
            .size(f32::from(TEXT_SM))
            .style(|theme: &iced::Theme| iced::widget::text::Style {
                color: Some(theme.palette().text.scale_alpha(0.55)),
            })
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

    let selection_label: Element<'a, Message> = match selected_name {
        None => text("").size(f32::from(TEXT_SM)).into(),
        Some(name) => text(format!("Selected: {name}"))
            .size(f32::from(TEXT_SM))
            .style(|theme: &iced::Theme| iced::widget::text::Style {
                color: Some(theme.palette().text.scale_alpha(0.70)),
            })
            .into(),
    };

    container(
        row![
            file_label,
            iced::widget::Space::new().width(Length::Fill),
            selection_label,
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
