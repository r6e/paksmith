//! Key-prompt panel — rendered when an encrypted pak has no resolved key.
//!
//! Displays the lock icon, the path being unlocked, a hex key input, and
//! action buttons. Emits [`Message`] variants for all user interactions.

use iced::widget::{button, column, container, row, text, text_input};
use iced::{Element, Length};

use crate::app::Message;
use crate::state::keyflow::KeyFlow;
use crate::theme::tokens::{
    RADIUS, SPACE_LG, SPACE_MD, SPACE_SM, TEXT_LG, TEXT_MD, TEXT_MUTED_ALPHA, TEXT_SM, TEXT_XL,
};

// Iced's `.size()` takes `f32`; the token constants are `u16`. Promote here.
const SZ_LG: f32 = TEXT_LG as f32;
const SZ_LG_XL: f32 = TEXT_XL as f32;
const SZ_MD: f32 = TEXT_MD as f32;
const SZ_SM: f32 = TEXT_SM as f32;

/// Render the locked-archive key-entry panel.
///
/// `flow` must be `KeyFlow::Locked`; the function is a no-op for other states
/// (renders an empty container). `hex_input` is the current content of the
/// hex key text field, bound through `Message::KeyInputChanged`.
/// `accent` is the system accent colour used for the primary "Unlock" button.
// Pure view: cosmetic Style-field-deletion mutants aren't regex-excludable in
// cargo-mutants 27 (see app::view for the rationale); validated by UI/UX review.
#[mutants::skip]
pub fn view<'a>(
    flow: &'a KeyFlow,
    hex_input: &'a str,
    accent: iced::Color,
) -> Element<'a, Message> {
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

    // Render the path directly (muted), without a "Path: " prefix.
    let path_label = text(format!("\u{1F4C4}  {}", path.display()))
        .size(SZ_SM)
        .style(|theme: &iced::Theme| iced::widget::text::Style {
            color: Some(theme.palette().text.scale_alpha(TEXT_MUTED_ALPHA)),
        });

    let explanation = text(
        "This pak is AES-encrypted. Paste the 64-character hex key below, \
         or choose the game install directory to auto-detect the key.",
    )
    .size(SZ_MD)
    .style(|theme: &iced::Theme| iced::widget::text::Style {
        color: Some(theme.palette().text.scale_alpha(TEXT_MUTED_ALPHA)),
    });

    // ── hex input row ────────────────────────────────────────────────────────
    let input = text_input("64-character hex key\u{2026}", hex_input)
        .on_input(Message::KeyInputChanged)
        .on_submit(Message::KeySubmitted) // B1: Enter key submits
        .size(SZ_MD)
        .padding(SPACE_SM)
        .width(Length::Fill);

    let unlock_btn = {
        // Disable when hex_input is empty — pressing "Unlock" with no input
        // would just produce a parse error; suppress it at the UI level.
        let base = button(text("Unlock").size(SZ_MD)) // S4: renamed from "Use key"
            .style(crate::app::accent_button(accent))
            .padding([SPACE_SM, SPACE_MD]);
        if hex_input.is_empty() {
            base
        } else {
            base.on_press(Message::KeySubmitted)
        }
    };

    let input_row = row![input, unlock_btn]
        .spacing(SPACE_SM)
        .align_y(iced::Alignment::Center);

    // ── error feedback (S1: between input row and secondary actions) ─────────
    let error_view: Option<Element<'_, Message>> = error.as_deref().map(|msg| {
        text(format!("\u{26A0}\u{FE0F}  {msg}"))
            .size(SZ_MD)
            .style(|theme: &iced::Theme| iced::widget::text::Style {
                // B2: use extended_palette danger text color for legibility in
                // both light and dark themes (danger fill is unreadable on dark).
                color: Some(theme.extended_palette().danger.base.text),
            })
            .into()
    });

    // ── secondary actions ────────────────────────────────────────────────────
    let choose_dir_btn = button(text("Choose install dir\u{2026}").size(SZ_MD))
        .style(iced::widget::button::secondary)
        .padding([SPACE_SM, SPACE_MD])
        .on_press(Message::KeyDirChosen(None)); // triggers the rfd picker in update()

    // The game-profile selector lives in the toolbar (game picker dropdown).
    // Selecting a profile there and then pressing Open is the canonical path.
    // No separate "Pick profile…" button is needed here — removed in Task 12.

    let secondary_row = row![choose_dir_btn]
        .spacing(SPACE_SM)
        .align_y(iced::Alignment::Center);

    // ── compose: input → error → secondary actions ───────────────────────────
    // S1: error renders between input row and secondary-actions row.
    let mut col = column![heading, path_label, explanation, input_row,]
        .spacing(SPACE_MD)
        .padding(SPACE_LG) // S5: single edge padding — outer container has none
        .max_width(600.0);

    if let Some(err_widget) = error_view {
        col = col.push(err_widget);
    }

    col = col.push(secondary_row);

    // S5: no outer .padding() — the inner column's SPACE_LG is the sole card edge.
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
        .into()
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin the heading size constant against the `TEXT_XL` token.
    ///
    /// `SZ_LG_XL` is now `TEXT_XL as f32`; pinning it ensures the token and
    /// the local alias stay in sync.  TEXT_XL is 22, so SZ_LG_XL must be 22.0.
    #[test]
    fn sz_lg_xl_matches_text_xl_token() {
        // TEXT_XL is 22 (u16); SZ_LG_XL must be exactly 22.0.
        // Use f32::from to avoid the cast_lossless lint.
        #[allow(clippy::float_cmp)]
        {
            assert_eq!(SZ_LG_XL, f32::from(TEXT_XL));
        }
    }
}
