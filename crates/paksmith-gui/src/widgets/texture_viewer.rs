//! Texture viewer widget: displays a decoded mip with channel toggles, zoom
//! controls, and a mip-level dropdown. All arithmetic lives in
//! `crate::state::texture_view`; this module is a thin, `#[mutants::skip]`
//! presentation layer that only reads state and emits messages.

use iced::widget::{button, column, container, pick_list, row, scrollable, text};
use iced::{Background, Border, Element, Length};

use crate::app::{Message, readable_text_on};
use crate::state::texture_view::{Channel, TextureState};
use crate::theme::tokens::{
    RADIUS, SPACE_MD, SPACE_SM, SPACE_XS, TEXT_MD, TEXT_MUTED_ALPHA, TEXT_SM,
};

// ── mip-choice wrapper ────────────────────────────────────────────────────────

/// A `pick_list`-compatible wrapper around a mip index and its dimensions.
///
/// `Display` renders as `"{index} — {w}×{h}"` so the dropdown is human-readable
/// without any separate state management.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MipChoice {
    index: usize,
    w: u32,
    h: u32,
}

impl std::fmt::Display for MipChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} \u{2014} {}×{}", self.index, self.w, self.h)
    }
}

// ── channel button styles ─────────────────────────────────────────────────────

/// Returns a button style closure for an ACTIVE channel toggle button.
///
/// Active buttons use the accent fill **plus** a 1.5px accent-coloured border
/// so the on/off state is readable without relying on colour alone
/// (F1: colour-blind accessibility dual-coding).
#[mutants::skip]
fn active_channel_style(
    accent: iced::Color,
) -> impl Fn(&iced::Theme, iced::widget::button::Status) -> iced::widget::button::Style {
    move |_theme, status| {
        let alpha = match status {
            iced::widget::button::Status::Hovered => 0.85,
            iced::widget::button::Status::Pressed => 0.70,
            iced::widget::button::Status::Disabled => 0.40,
            iced::widget::button::Status::Active => 1.0,
        };
        iced::widget::button::Style {
            background: Some(Background::Color(accent.scale_alpha(alpha))),
            text_color: readable_text_on(accent),
            border: Border {
                color: accent,
                width: 1.5,
                radius: RADIUS.into(),
            },
            ..Default::default()
        }
    }
}

/// Returns a button style closure for an INACTIVE channel toggle button.
///
/// Inactive buttons have no fill and a faint hairline border so the button
/// boundary is visible without implying activation.
#[mutants::skip]
fn inactive_channel_style()
-> impl Fn(&iced::Theme, iced::widget::button::Status) -> iced::widget::button::Style {
    |theme: &iced::Theme, status| {
        let bg = match status {
            iced::widget::button::Status::Hovered | iced::widget::button::Status::Pressed => {
                Some(Background::Color(theme.palette().text.scale_alpha(0.07)))
            }
            _ => None,
        };
        iced::widget::button::Style {
            background: bg,
            text_color: theme.palette().text.scale_alpha(TEXT_MUTED_ALPHA),
            border: Border {
                color: theme.palette().text.scale_alpha(0.15),
                width: 1.0,
                radius: RADIUS.into(),
            },
            ..Default::default()
        }
    }
}

// ── view ──────────────────────────────────────────────────────────────────────

/// Render the texture inspector panel for the given `state`.
///
/// The controls row (R/G/B/A toggles + Fit + zoom +/− + mip dropdown) is
/// **always** rendered in texture mode; the area below it shows, in order:
/// - the scaled image when `state.decoded` is `Some` — centred in fit mode, or
///   inside a `scrollable` panning container when manually zoomed;
/// - an attention-coloured error placeholder when the decode failed and there is
///   no retained image (`decoded` is `None` and `error` is `Some`);
/// - a muted "Decoding…" placeholder while the first decode is in flight.
///
/// Keeping the controls visible on error (C19) lets the user pick a different mip
/// to recover when the initial mip fails (e.g. mip 0 exceeds the decode cap) —
/// `TextureMipSelected` clears the error and redispatches. When a *re-selected*
/// mip fails the previous image is retained (C18) and the error is surfaced as a
/// compact banner above it rather than replacing the whole view.
///
/// `accent` is the system accent colour; active-channel buttons are styled with
/// an accent fill **plus** accent border for colour-blind accessibility (F1).
#[mutants::skip]
#[allow(clippy::cast_precision_loss)] // texture dims ≤ 16384 are exact in f32
#[allow(clippy::too_many_lines)] // single view fn; splitting would obscure the layout
pub fn view<'a>(state: &TextureState, accent: iced::Color) -> Element<'a, Message> {
    // ── controls row ─────────────────────────────────────────────────────────
    let channel_buttons: Vec<Element<'_, Message>> = [
        (Channel::R, "R", state.channels.r),
        (Channel::G, "G", state.channels.g),
        (Channel::B, "B", state.channels.b),
        (Channel::A, "A", state.channels.a),
    ]
    .into_iter()
    .map(|(ch, label, is_active)| {
        let btn = button(text(label).size(f32::from(TEXT_SM)))
            .on_press(Message::TextureChannelToggled { channel: ch })
            .padding([SPACE_XS, SPACE_SM]);
        // F1: active buttons: accent fill + 1.5px accent border (dual-code).
        //     Inactive: faint hairline border only.
        if is_active {
            btn.style(active_channel_style(accent)).into()
        } else {
            btn.style(inactive_channel_style()).into()
        }
    })
    .collect();

    let zoom_out_btn = button(text("\u{2212}").size(f32::from(TEXT_SM)))
        .on_press(Message::TextureZoomOut)
        .padding([SPACE_XS, SPACE_SM])
        .style(iced::widget::button::secondary);

    // F5: wrap the zoom % label in a container with padding so it optically
    // groups with its flanking buttons.
    //
    // Issue 1: in fit mode `state.zoom` is not the rendered scale (the real
    // scale is computed per-layout by `fit_zoom`), so showing a percentage
    // would be a lie.  Render the literal "Fit" instead.  Pressing +/− snaps to
    // a discrete `ZOOM_STEPS` entry from `state.zoom` and exits fit mode — the
    // standard image-viewer behaviour (Preview / browsers); the first manual
    // step is not relative to the fit scale, which is an accepted limitation.
    let zoom_label_text = if state.fit_to_window {
        "Fit".to_string()
    } else {
        format!("{:.0}%", state.zoom * 100.0)
    };
    let zoom_label =
        container(text(zoom_label_text).size(f32::from(TEXT_SM))).padding([SPACE_XS, SPACE_SM]);

    let zoom_in_btn = button(text("+").size(f32::from(TEXT_SM)))
        .on_press(Message::TextureZoomIn)
        .padding([SPACE_XS, SPACE_SM])
        .style(iced::widget::button::secondary);

    // F3: "Fit" button — resets to fit-to-window mode.  Visually active when
    // fit_to_window is on so the user can see the current mode at a glance.
    let fit_btn = {
        let btn = button(text("Fit").size(f32::from(TEXT_SM)))
            .on_press(Message::TextureFitToWindow)
            .padding([SPACE_XS, SPACE_SM]);
        if state.fit_to_window {
            btn.style(active_channel_style(accent))
        } else {
            btn.style(iced::widget::button::secondary)
        }
    };

    // Mip dropdown — only shown when there are multiple mip levels to choose from.
    let mip_picker: Option<Element<'_, Message>> = if state.mips.len() > 1 {
        let options: Vec<MipChoice> = state
            .mips
            .iter()
            .enumerate()
            .map(|(i, &(w, h))| MipChoice { index: i, w, h })
            .collect();
        let selected = options.get(state.selected_mip).copied();
        let picker = pick_list(options, selected, |choice: MipChoice| {
            Message::TextureMipSelected(choice.index)
        })
        .text_size(f32::from(TEXT_SM))
        .padding(SPACE_SM);
        Some(picker.into())
    } else {
        None
    };

    // F7: when there is only one mip (picker hidden), show a non-interactive
    // "{w}×{h}" size label so the user knows the resolution. Driven off
    // `state.mips` (not `decoded`) so the controls render even before the first
    // decode lands or after a decode error — in texture mode `classify_texture`
    // always populates at least one mip, so the label is present whenever a
    // single-mip texture is shown.
    let single_mip_size: Option<Element<'_, Message>> = if state.mips.len() <= 1 {
        state.mips.first().map(|&(w, h)| {
            container(
                text(format!("{w}\u{d7}{h}"))
                    .size(f32::from(TEXT_SM))
                    .style(|theme: &iced::Theme| iced::widget::text::Style {
                        color: Some(theme.palette().text.scale_alpha(TEXT_MUTED_ALPHA)),
                    }),
            )
            .padding([SPACE_XS, SPACE_SM])
            .into()
        })
    } else {
        None
    };

    let mut controls_children: Vec<Element<'_, Message>> = channel_buttons;
    controls_children.push(iced::widget::Space::new().width(SPACE_SM).into());
    controls_children.push(fit_btn.into());
    controls_children.push(zoom_out_btn.into());
    controls_children.push(zoom_label.into());
    controls_children.push(zoom_in_btn.into());
    if let Some(picker) = mip_picker {
        controls_children.push(iced::widget::Space::new().width(SPACE_SM).into());
        controls_children.push(picker);
    }
    if let Some(size_label) = single_mip_size {
        controls_children.push(iced::widget::Space::new().width(SPACE_SM).into());
        controls_children.push(size_label);
    }

    // F6: controls toolbar has a 1px bottom border matching the tab_bar.rs strip
    // pattern, providing visual separation from the image area below.
    let controls = container(
        row(controls_children)
            .spacing(SPACE_XS)
            .align_y(iced::Alignment::Center),
    )
    .padding([SPACE_SM, SPACE_MD])
    .style(|theme: &iced::Theme| iced::widget::container::Style {
        background: Some(Background::Color(
            theme.extended_palette().background.weak.color,
        )),
        border: Border {
            color: theme.palette().text.scale_alpha(0.1),
            width: 1.0,
            radius: 0.0.into(),
        },
        ..Default::default()
    })
    .width(Length::Fill);

    // ── content area below the controls ───────────────────────────────────────
    // Renders the image when a decoded mip is present (including a retained
    // last-good mip after a failed re-select, C18), otherwise an error or the
    // in-flight placeholder. The controls above are built unconditionally so the
    // mip picker stays reachable for recovery even on a fresh decode failure (C19).
    let content: Element<'_, Message> = if let Some(decoded) = &state.decoded {
        // Snapshot the Copy values needed inside the `Responsive` closure (avoids
        // borrowing `state` inside a `Fn` closure after it's moved into the column).
        let img_w = decoded.width;
        let img_h = decoded.height;
        let zoom_snapshot = state.zoom;
        let fit_to_window = state.fit_to_window;

        // Issue 3 (perf): the render handle is cached on `TextureState::render`
        // (see its doc for why cloning a cached handle skips the per-frame re-mask,
        // re-alloc, and GPU re-upload); `view()` clones it rather than rebuilding.
        // The `unwrap_or_else` here is *not* a correctness guard: it cannot catch a
        // stale `Some` (a `render` left over from a prior mip/channel set) — that
        // depends on the handlers rebuilding on every `decoded`/`channels` write.
        // It only covers the `None` case (cache not yet populated) by building the
        // handle inline via the same `render_handle` builder the cache uses.
        let handle = state
            .render
            .clone()
            .unwrap_or_else(|| crate::state::texture_view::render_handle(decoded, state.channels));

        // F2: the framed image box uses `background.strong` to distinguish it
        // visually from the controls bar (`background.weak`); a 1px
        // `text.scale_alpha(0.15)` border marks the image boundary so alpha edges
        // read clearly.  (The `canvas` feature is NOT enabled, so a true per-pixel
        // checkerboard is unavailable this pass; the distinct background + boundary
        // border is the approved fallback.)
        //
        // F3: `iced::widget::Responsive` measures the available space at layout time
        // and passes it into the closure.  When `fit_to_window` is true the closure
        // calls `fit_zoom` to scale the texture to fill the area; otherwise it uses
        // the manual `zoom` value.  `Responsive` is placed OUTSIDE any `scrollable`
        // intentionally: inside one it would measure infinite content space and
        // produce a garbage zoom.
        iced::widget::Responsive::new(move |size: iced::Size| {
            let actual_zoom = if fit_to_window {
                crate::state::texture_view::fit_zoom((img_w, img_h), (size.width, size.height))
            } else {
                zoom_snapshot
            };

            let img = iced::widget::image(handle.clone())
                .filter_method(iced::widget::image::FilterMethod::Nearest)
                .width(Length::Fixed(img_w as f32 * actual_zoom))
                .height(Length::Fixed(img_h as f32 * actual_zoom));

            let image_container = container(img)
                .padding(SPACE_MD)
                .style(|theme: &iced::Theme| iced::widget::container::Style {
                    background: Some(Background::Color(
                        theme.extended_palette().background.strong.color,
                    )),
                    border: Border {
                        color: theme.palette().text.scale_alpha(0.15),
                        width: 1.0,
                        radius: 0.0.into(),
                    },
                    ..Default::default()
                })
                .width(Length::Shrink)
                .height(Length::Shrink);

            // Issue 2: in fit mode the image is ≤ viewport on both axes
            // (`fit_zoom` = min of the axis scales), so CENTER it with no
            // scrollbar.  In manual-zoom mode wrap it in a `scrollable`, which
            // owns panning natively (scrollbars + trackpad/wheel, clamped to the
            // content bounds) — there is no separate pan offset to track.
            if fit_to_window {
                container(image_container)
                    .center_x(Length::Fill)
                    .center_y(Length::Fill)
                    .width(Length::Fill)
                    .height(Length::Fill)
                    .into()
            } else {
                // `Direction::Both` is required: a zoomed-in image overflows on
                // BOTH axes, and iced's default scrollable is vertical-only —
                // which would leave the horizontal extent of any wide image
                // unreachable.  Mirrors the explicit-direction pattern in
                // `tab_bar.rs`.
                scrollable(image_container)
                    .direction(scrollable::Direction::Both {
                        vertical: scrollable::Scrollbar::new(),
                        horizontal: scrollable::Scrollbar::new(),
                    })
                    .width(Length::Fill)
                    .height(Length::Fill)
                    .into()
            }
        })
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
    } else if let Some(err) = &state.error {
        // F4: decode failed and there is no retained image — show the error in
        // the content area (danger colour, distinct from "Decoding…"). The
        // controls above remain so the user can select a different mip (C19).
        error_placeholder(err.clone())
    } else {
        muted_placeholder("Decoding\u{2026}".to_string())
    };

    // C18: a *re-selected* mip that fails keeps the previous image (`decoded`
    // still `Some`); surface its error as a compact banner above the retained
    // image rather than discarding it. When no image is retained the error
    // already fills the content area above, so a banner would be redundant.
    let error_banner: Option<Element<'_, Message>> = state
        .decoded
        .as_ref()
        .and(state.error.as_ref())
        .map(|err| error_banner_row(err.clone()));

    let mut children: Vec<Element<'_, Message>> = vec![controls.into()];
    if let Some(banner) = error_banner {
        children.push(banner);
    }
    children.push(content);

    column(children)
        .spacing(0)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Centered muted text placeholder (in-flight decode state).
#[mutants::skip]
fn muted_placeholder(msg: String) -> Element<'static, Message> {
    container(
        text(msg)
            .size(f32::from(TEXT_MD))
            .style(|theme: &iced::Theme| iced::widget::text::Style {
                color: Some(theme.palette().text.scale_alpha(TEXT_MUTED_ALPHA)),
            }),
    )
    .center_x(Length::Fill)
    .center_y(Length::Fill)
    .width(Length::Fill)
    .height(Length::Fill)
    .into()
}

/// Compact full-width error banner shown *above* a retained last-good image
/// (C18) when a re-selected mip fails to decode. Unlike [`error_placeholder`] it
/// does not fill the viewport — it sits between the controls and the kept image
/// so the failure is visible without discarding what the user was looking at.
#[mutants::skip]
fn error_banner_row(msg: String) -> Element<'static, Message> {
    container(
        text(msg)
            .size(f32::from(TEXT_SM))
            .style(|theme: &iced::Theme| iced::widget::text::Style {
                color: Some(theme.palette().danger),
            }),
    )
    .padding([SPACE_XS, SPACE_MD])
    .width(Length::Fill)
    .style(|theme: &iced::Theme| iced::widget::container::Style {
        background: Some(Background::Color(theme.palette().danger.scale_alpha(0.12))),
        ..Default::default()
    })
    .into()
}

/// Centered error text placeholder (decode failed).
///
/// F4: rendered in the palette `danger` colour to distinguish it from the muted
/// "Decoding…" state and communicate that user action may be required.
#[mutants::skip]
fn error_placeholder(msg: String) -> Element<'static, Message> {
    container(
        text(msg)
            .size(f32::from(TEXT_MD))
            .style(|theme: &iced::Theme| iced::widget::text::Style {
                color: Some(theme.palette().danger),
            }),
    )
    .center_x(Length::Fill)
    .center_y(Length::Fill)
    .width(Length::Fill)
    .height(Length::Fill)
    .into()
}

#[cfg(test)]
mod tests {
    use super::MipChoice;

    // `MipChoice`'s `Display` is the one bit of non-`#[mutants::skip]` logic in
    // this widget (it formats the mip-dropdown label), so it earns a unit test:
    // pins the `"{index} — {w}×{h}"` format against the stub-return mutant.
    #[test]
    fn mip_choice_display_formats_index_and_dims() {
        let label = MipChoice {
            index: 2,
            w: 64,
            h: 32,
        }
        .to_string();
        assert_eq!(label, "2 \u{2014} 64\u{d7}32");
    }
}
