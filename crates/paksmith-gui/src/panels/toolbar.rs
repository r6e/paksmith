//! Toolbar panel — Open button, decryption-status pill, filter input, and
//! game-profile selector.

use iced::widget::{button, container, pick_list, row, text, text_input};
use iced::{Background, Element, Length};

use crate::app::Message;
use crate::state::profiles::ProfileChoice;
use crate::theme::tokens::{
    RADIUS, SPACE_MD, SPACE_SM, SPACE_XS, TEXT_MD, TEXT_MUTED_ALPHA, TEXT_SM,
};

/// Sentinel value displayed at the top of the profile picker meaning "no game
/// selected" / auto-resolve.  Selecting it emits `GameSelected(None)`.
const AUTO_LABEL: &str = "Auto";

/// Minimum width of the game pick-list to prevent layout twitch on long names.
const GAME_PICKER_WIDTH: f32 = 160.0;

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
/// * `accent` – system accent colour for primary CTA styling.
// Pure view: cosmetic Style-field-deletion mutants aren't regex-excludable in
// cargo-mutants 27 (see app::view for the rationale); validated by UI/UX review.
#[mutants::skip]
pub fn view<'a>(
    decrypted: Option<bool>,
    filter: &str,
    profiles: &'a [ProfileChoice],
    active_game: Option<&'a ProfileChoice>,
    accent: iced::Color,
) -> Element<'a, Message> {
    let open_btn = button(text("Open\u{2026}").size(f32::from(TEXT_MD)))
        .style(crate::app::accent_button(accent))
        .padding([SPACE_SM, SPACE_MD])
        .on_press(Message::OpenRequested);

    let filter_input = text_input("Filter\u{2026}", filter)
        .on_input(Message::FilterChanged)
        .size(f32::from(TEXT_SM))
        .padding(SPACE_SM)
        .width(Length::Fill);

    let mut items: Vec<Element<'_, Message>> = vec![open_btn.into()];

    if let Some(is_decrypted) = decrypted {
        items.push(encryption_chip(is_decrypted).into());
    }

    items.push(filter_input.into());
    game_selector_widgets(profiles, active_game, &mut items);

    // On Windows / Linux the native muda menu is not attached to the window,
    // so Toggle Theme and About are exposed here as compact toolbar buttons.
    // On macOS these actions live in the View / Help menu bar; the toolbar
    // buttons are omitted to avoid duplicating them.
    #[cfg(not(target_os = "macos"))]
    {
        let theme_btn = button(text("\u{2600}/\u{263E}").size(f32::from(TEXT_SM)))
            .style(iced::widget::button::secondary)
            .padding([SPACE_XS, SPACE_SM])
            .on_press(Message::ToggleTheme);
        let about_btn = button(text("About").size(f32::from(TEXT_SM)))
            .style(iced::widget::button::secondary)
            .padding([SPACE_XS, SPACE_SM])
            .on_press(Message::About);
        items.push(theme_btn.into());
        items.push(about_btn.into());
    }

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

/// Build the encrypted/decrypted status chip.
// Pure view: cosmetic Style/Border-field-deletion mutants aren't regex-excludable
// in cargo-mutants 27 (see app::view for the rationale); validated by UI/UX review.
#[mutants::skip]
fn encryption_chip(is_decrypted: bool) -> impl Into<Element<'static, Message>> {
    let pill_label = if is_decrypted {
        "\u{1F513} Decrypted"
    } else {
        "\u{1F512} Encrypted"
    };
    // Chip: tinted background at low alpha + rounded corners.
    // Text uses extended_palette success/danger base text for legibility
    // in both light and dark themes.
    container(
        text(pill_label)
            .size(f32::from(TEXT_SM))
            .style(move |theme: &iced::Theme| iced::widget::text::Style {
                color: Some(if is_decrypted {
                    theme.extended_palette().success.base.text
                } else {
                    theme.extended_palette().danger.base.text
                }),
            }),
    )
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
    .padding([SPACE_XS, SPACE_SM])
}

/// Push the "Game:" label plus either the pick-list (profiles present) or a
/// muted "No profiles" hint (empty list) onto `items`.
fn game_selector_widgets<'a>(
    profiles: &'a [ProfileChoice],
    active_game: Option<&'a ProfileChoice>,
    items: &mut Vec<Element<'a, Message>>,
) {
    let game_label = text("Game:")
        .size(f32::from(TEXT_SM))
        .style(|theme: &iced::Theme| iced::widget::text::Style {
            color: Some(theme.palette().text.scale_alpha(TEXT_MUTED_ALPHA)),
        });
    items.push(game_label.into());

    if profiles.is_empty() {
        // No profiles configured — show a muted hint instead of a dead dropdown.
        let no_profiles =
            text("No profiles")
                .size(f32::from(TEXT_SM))
                .style(|theme: &iced::Theme| iced::widget::text::Style {
                    color: Some(theme.palette().text.scale_alpha(TEXT_MUTED_ALPHA)),
                });
        items.push(no_profiles.into());
        return;
    }

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
    .padding(SPACE_SM)
    .width(Length::Fixed(GAME_PICKER_WIDTH));

    items.push(game_picker.into());
}
