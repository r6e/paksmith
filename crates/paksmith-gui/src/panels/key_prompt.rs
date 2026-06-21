//! Key-prompt panel — rendered when an encrypted pak has no resolved key.
//!
//! Displays the lock icon, the path being unlocked, a hex key input, and
//! action buttons. Emits [`Message`] variants for all user interactions.

use iced::widget::{button, column, container, row, text, text_input};
use iced::{Element, Length};

use crate::app::Message;
use crate::state::keyflow::KeyFlow;
use crate::theme::tokens::{
    RADIUS, SPACE_LG, SPACE_MD, SPACE_SM, SPACE_XS, TEXT_LG, TEXT_MD, TEXT_SM,
};

// Iced's `.size()` takes `f32`; the token constants are `u16`. Promote here.
const SZ_LG: f32 = TEXT_LG as f32;
const SZ_LG_XL: f32 = TEXT_LG as f32 + 4.0;
const SZ_MD: f32 = TEXT_MD as f32;
const SZ_SM: f32 = TEXT_SM as f32;

/// Render the locked-archive key-entry panel.
///
/// `flow` must be `KeyFlow::Locked`; the function is a no-op for other states
/// (renders an empty container). `hex_input` is the current content of the
/// hex key text field, bound through `Message::KeyInputChanged`.
pub fn view<'a>(flow: &'a KeyFlow, hex_input: &'a str) -> Element<'a, Message> {
    let KeyFlow::Locked { path, error } = flow else {
        // Not in Locked state — render nothing (caller guards this).
        return container(text("")).into();
    };

    // ── header ──────────────────────────────────────────────────────────────
    let heading = row![
        text("\u{1F512}").size(SZ_LG_XL),
        text("  Encrypted Archive").size(SZ_LG),
    ]
    .align_y(iced::Alignment::Center);

    let path_label =
        text(format!("Path: {}", path.display()))
            .size(SZ_SM)
            .style(|theme: &iced::Theme| iced::widget::text::Style {
                color: Some(theme.palette().text.scale_alpha(0.65)),
            });

    let explanation = text(
        "This pak is AES-encrypted. Paste the 64-character hex key below, \
         or choose the game install directory to auto-detect the key.",
    )
    .size(SZ_MD)
    .style(|theme: &iced::Theme| iced::widget::text::Style {
        color: Some(theme.palette().text.scale_alpha(0.80)),
    });

    // ── hex input row ────────────────────────────────────────────────────────
    let input = text_input("64-character hex key\u{2026}", hex_input)
        .on_input(Message::KeyInputChanged)
        .size(SZ_MD)
        .padding(SPACE_SM)
        .width(Length::Fill);

    let use_key_btn = {
        // Disable when hex_input is empty — pressing "Use key" with no input
        // would just produce a parse error; suppress it at the UI level.
        let base = button(text("Use key").size(SZ_MD))
            .style(iced::widget::button::primary)
            .padding([SPACE_SM, SPACE_MD]);
        if hex_input.is_empty() {
            base
        } else {
            base.on_press(Message::KeySubmitted)
        }
    };

    let input_row = row![input, use_key_btn]
        .spacing(SPACE_SM)
        .align_y(iced::Alignment::Center);

    // ── secondary actions ────────────────────────────────────────────────────
    let choose_dir_btn = button(text("Choose install dir\u{2026}").size(SZ_MD))
        .style(iced::widget::button::secondary)
        .padding([SPACE_SM, SPACE_MD])
        .on_press(Message::KeyDirChosen(None)); // triggers the rfd picker in update()

    // Task 12 placeholder: profile picker button — wired to a message now so the
    // panel compiles; the profile-selector overlay is built in Task 12.
    let profile_btn = button(text("Pick profile\u{2026}").size(SZ_MD))
        .style(iced::widget::button::secondary)
        .padding([SPACE_SM, SPACE_MD])
        .on_press(Message::OpenProfilePicker);

    let secondary_row = row![choose_dir_btn, profile_btn]
        .spacing(SPACE_SM)
        .align_y(iced::Alignment::Center);

    // ── error text ───────────────────────────────────────────────────────────
    let error_view: Option<Element<'_, Message>> = error.as_deref().map(|msg| {
        text(format!("\u{26A0}\u{FE0F}  {msg}"))
            .size(SZ_MD)
            .style(|theme: &iced::Theme| iced::widget::text::Style {
                color: Some(theme.palette().danger),
            })
            .into()
    });

    // ── compose ─────────────────────────────────────────────────────────────
    let mut col = column![heading, path_label, explanation, input_row, secondary_row,]
        .spacing(SPACE_MD)
        .padding(SPACE_LG)
        .max_width(600.0);

    if let Some(err_widget) = error_view {
        col = col.push(err_widget);
    }

    container(col)
        .style(move |theme: &iced::Theme| {
            let palette = theme.extended_palette();
            iced::widget::container::Style {
                background: Some(iced::Background::Color(palette.background.weak.color)),
                border: iced::Border {
                    color: palette.background.strong.color,
                    width: 1.0,
                    radius: RADIUS.into(),
                },
                ..Default::default()
            }
        })
        .padding(SPACE_XS)
        .into()
}
