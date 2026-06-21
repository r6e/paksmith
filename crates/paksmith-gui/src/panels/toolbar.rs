//! Toolbar panel — Open button, decryption-status pill, filter input, and
//! game-profile selector.

use iced::widget::{button, container, pick_list, row, text, text_input};
use iced::{Background, Element, Length};

use crate::app::Message;
use crate::state::profiles::ProfileChoice;
use crate::theme::tokens::{RADIUS, SPACE_MD, SPACE_SM, SPACE_XS, TEXT_MD, TEXT_SM};

/// Sentinel value displayed at the top of the profile picker meaning "no game
/// selected" / auto-resolve.  Selecting it emits `GameSelected(None)`.
const AUTO_LABEL: &str = "Auto";

/// A thin wrapper so the pick_list can include a "no selection" sentinel
/// alongside real `ProfileChoice` entries without fighting the `T` → `Message`
/// callback signature.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PickItem {
    Auto,
    Profile(ProfileChoice),
}

impl std::fmt::Display for PickItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PickItem::Auto => f.write_str(AUTO_LABEL),
            PickItem::Profile(c) => f.write_str(&c.name),
        }
    }
}

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
/// * `profiles` – available profiles for the game selector dropdown.
/// * `active_game` – the currently selected profile (or `None` for Auto).
pub fn view<'a>(
    decrypted: Option<bool>,
    filter: &str,
    profiles: &'a [ProfileChoice],
    active_game: Option<&'a ProfileChoice>,
) -> Element<'a, Message> {
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

    // ── game-profile selector ────────────────────────────────────────────────
    // Build the options vec: Auto sentinel first, then one item per profile.
    let mut options: Vec<PickItem> = Vec::with_capacity(profiles.len() + 1);
    options.push(PickItem::Auto);
    for p in profiles {
        options.push(PickItem::Profile(p.clone()));
    }

    // Map the active_game to the currently-selected PickItem.
    let selected: Option<PickItem> = Some(match active_game {
        None => PickItem::Auto,
        Some(c) => PickItem::Profile(c.clone()),
    });

    let game_picker = pick_list(options, selected, |item: PickItem| match item {
        PickItem::Auto => Message::GameSelected(None),
        PickItem::Profile(c) => Message::GameSelected(Some(c)),
    })
    .text_size(f32::from(TEXT_SM))
    .padding(SPACE_SM);

    items.push(game_picker.into());

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
