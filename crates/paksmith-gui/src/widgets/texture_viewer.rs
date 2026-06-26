//! Texture viewer widget: displays a decoded mip with channel toggles, zoom
//! controls, and a mip-level dropdown. All arithmetic lives in
//! `crate::state::texture_view`; this module is a thin, `#[mutants::skip]`
//! presentation layer that only reads state and emits messages.

use iced::widget::{button, column, container, pick_list, row, scrollable, text};
use iced::{Background, Border, Element, Length};

use crate::app::{Message, readable_text_on};
use crate::state::texture_view::{Channel, TextureState, mask_rgba};
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
/// Returns:
/// - An attention-coloured error message when `state.error` is set (decode failed).
/// - A muted "Decoding…" placeholder when `state.decoded` is `None` (still in flight).
/// - Otherwise: a controls row (R/G/B/A toggles + Fit + zoom +/− + mip dropdown)
///   above the scaled image — centred in fit mode, or inside a `scrollable`
///   panning container when manually zoomed.
///
/// `accent` is the system accent colour; active-channel buttons are styled with
/// an accent fill **plus** accent border for colour-blind accessibility (F1).
#[mutants::skip]
#[allow(clippy::cast_precision_loss)] // texture dims ≤ 16384 are exact in f32
#[allow(clippy::too_many_lines)] // single view fn; splitting would obscure the layout
pub fn view<'a>(state: &TextureState, accent: iced::Color) -> Element<'a, Message> {
    // ── error state ───────────────────────────────────────────────────────────
    // F4: error is distinct from "Decoding…" — uses danger colour, not muted.
    if let Some(err) = &state.error {
        return error_placeholder(err.clone());
    }

    // ── decoding in-flight ────────────────────────────────────────────────────
    let Some(decoded) = &state.decoded else {
        return muted_placeholder("Decoding\u{2026}".to_string());
    };

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
    // "{w}×{h}" size label so the user knows the resolution.
    let single_mip_size: Option<Element<'_, Message>> = if state.mips.len() <= 1 {
        let (w, h) = state
            .mips
            .first()
            .copied()
            .unwrap_or((decoded.width, decoded.height));
        Some(
            container(
                text(format!("{w}\u{d7}{h}"))
                    .size(f32::from(TEXT_SM))
                    .style(|theme: &iced::Theme| iced::widget::text::Style {
                        color: Some(theme.palette().text.scale_alpha(TEXT_MUTED_ALPHA)),
                    }),
            )
            .padding([SPACE_XS, SPACE_SM])
            .into(),
        )
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

    // ── image area ────────────────────────────────────────────────────────────
    // Snapshot the Copy values needed inside the `Responsive` closure (avoids
    // borrowing `state` inside a `Fn` closure after it's moved into the column).
    let img_w = decoded.width;
    let img_h = decoded.height;
    let zoom_snapshot = state.zoom;
    let fit_to_window = state.fit_to_window;

    // Issue 3 (perf): build the channel-masked image `Handle` ONCE per `view()`,
    // here rather than inside the `Responsive` closure.  The mask pass + its
    // allocation happens a single time per render; the closure (re-run on every
    // layout tick, e.g. throughout a window-resize drag) only `clone()`s the
    // handle.  A cloned `Handle` keeps the same cache id, so iced reuses the
    // uploaded texture instead of re-uploading it per tick.  Caching the handle
    // *across* `view()` calls would require storing an iced type in the pure
    // `TextureState`, which the state layer forbids — re-masking once per
    // `view()` is the accepted remaining cost.
    let handle = iced::widget::image::Handle::from_rgba(
        img_w,
        img_h,
        mask_rgba(&decoded.rgba, state.channels),
    );

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
    let image_area: Element<'_, Message> =
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
        .into();

    column![controls, image_area]
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
