//! Thin inline format-picker strip shown when Export As… is chosen for a row.
//! Rendering only; all decisions live in `app::update` + `state/export.rs`.
//! Visually identical band to the action strip (background.weak + RADIUS) so the
//! two read as the same inline menu surface.

use iced::Element;
use iced::widget::{button, row, text};

use crate::app::Message;
use crate::state::export::{ExportMenu, choice_label};
use crate::theme::tokens::{SPACE_SM, SPACE_XS, TEXT_SM};
use crate::widgets::inline_band::band;

/// The format-picker band for `menu`: one button per choice (label =
/// [`choice_label`]) plus a Cancel that returns to the action strip.
#[mutants::skip] // pure iced view composition; logic is in update + state::export
pub fn picker_strip<'a>(menu: &ExportMenu) -> Element<'a, Message> {
    let mut items: Vec<Element<'a, Message>> = Vec::with_capacity(menu.choices.len() + 1);
    for choice in &menu.choices {
        items.push(
            button(text(choice_label(choice)).size(f32::from(TEXT_SM)))
                .style(iced::widget::button::text)
                .padding([SPACE_XS, SPACE_SM])
                .on_press(Message::ExportChoiceSelected {
                    path: menu.path.clone(),
                    choice: choice.clone(),
                })
                .into(),
        );
    }
    items.push(
        button(text("Cancel").size(f32::from(TEXT_SM)))
            .style(iced::widget::button::text)
            .padding([SPACE_XS, SPACE_SM])
            .on_press(Message::ExportMenuCancelled)
            .into(),
    );

    band(
        row(items)
            .spacing(SPACE_SM)
            .align_y(iced::Alignment::Center),
    )
}
