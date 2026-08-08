//! Content host panel — the right-hand pane when an archive is open.
//!
//! Renders the tab bar, a `Properties | Hex | Info | Texture` view-mode
//! switcher, and the active tab's body: the type-aware property tree
//! (`widgets/property_tree`), the virtualized hex view (`widgets/hex_view`),
//! the Info metadata view (implemented here), or the texture inspector
//! (`widgets/texture_viewer`).

use std::collections::BTreeMap;

use iced::widget::{button, column, container, row, text};
use iced::{Element, Length};

use crate::app::{Message, accent_button};
use crate::panels::detail::{compression_ratio, human_size, kv_row};
use crate::state::archive::EntryMeta;
use crate::state::tabs::{TabContent, Tabs, ViewMode, audio_available, texture_available};
use crate::theme::tokens::{
    SPACE_LG, SPACE_MD, SPACE_SM, SPACE_XS, TEXT_MD, TEXT_MUTED_ALPHA, TEXT_SM,
};
use crate::widgets::{audio_player, hex_view, property_tree, tab_bar, texture_viewer};

// ── public entry-point ────────────────────────────────────────────────────────

/// Render the content host.
///
/// * `tabs`    — the current tab collection.
/// * `entries` — the archive's per-entry metadata map (keyed by full path).
/// * `accent`  — the system accent colour for the active view-mode button.
/// * `audio_device_available` — whether an audio output device opened; gates the
///   audio player's transport controls (disabled + reason when absent).
#[mutants::skip]
#[allow(clippy::too_many_lines)] // single-fn content host; splitting would obscure layout
pub fn view<'a>(
    tabs: &'a Tabs,
    entries: &'a BTreeMap<String, EntryMeta>,
    accent: iced::Color,
    audio_device_available: bool,
) -> Element<'a, Message> {
    if tabs.open.is_empty() {
        return empty_state();
    }

    // ── tab bar ───────────────────────────────────────────────────────────────
    let tab_strip: Element<'_, Message> = tab_bar::view(tabs, accent);

    // ── active tab body ───────────────────────────────────────────────────────
    let body: Element<'_, Message> = match tabs.active_tab() {
        None => muted_text("No active tab"),
        Some(tab) => {
            let show_texture = texture_available(tab);
            let show_audio = audio_available(tab);
            let switcher = view_mode_switcher(tab.view, accent, show_texture, show_audio);
            let content = match &tab.content {
                TabContent::Loading => muted_text("Loading\u{2026}"),
                TabContent::Ready {
                    bytes,
                    truncated,
                    parsed,
                } => {
                    let meta = entries.get(tab.path.as_str());
                    match tab.view {
                        ViewMode::Info => info_view(tab.path.as_str(), bytes, parsed, meta),
                        ViewMode::Properties => {
                            properties_view(parsed, &tab.expanded, viewer_scroll(tab))
                        }
                        ViewMode::Hex => {
                            hex_view::view(bytes, *truncated, &tab.hex, accent, viewer_scroll(tab))
                        }
                        ViewMode::Texture => texture_viewer::view(&tab.texture, accent),
                        ViewMode::Audio => {
                            audio_player::view(&tab.audio, accent, audio_device_available)
                        }
                    }
                }
            };

            column![switcher, content]
                .spacing(0)
                .width(Length::Fill)
                .height(Length::Fill)
                .into()
        }
    };

    column![tab_strip, body]
        .spacing(0)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}

// ── view-mode switcher ────────────────────────────────────────────────────────

#[mutants::skip]
fn view_mode_switcher(
    active: ViewMode,
    accent: iced::Color,
    show_texture: bool,
    show_audio: bool,
) -> Element<'static, Message> {
    let mut modes: Vec<(ViewMode, &'static str)> = vec![
        (ViewMode::Properties, "Properties"),
        (ViewMode::Hex, "Hex"),
        (ViewMode::Info, "Info"),
    ];
    if show_texture {
        modes.push((ViewMode::Texture, "Texture"));
    }
    if show_audio {
        modes.push((ViewMode::Audio, "Audio"));
    }

    let buttons: Vec<Element<'_, Message>> = modes
        .into_iter()
        .map(|(mode, label)| {
            let is_active = mode == active;
            if is_active {
                button(text(label).size(f32::from(TEXT_SM)))
                    .on_press(Message::ViewModeSet(mode))
                    .padding([SPACE_XS, SPACE_SM])
                    .style(accent_button(accent))
                    .into()
            } else {
                button(text(label).size(f32::from(TEXT_SM)))
                    .on_press(Message::ViewModeSet(mode))
                    .padding([SPACE_XS, SPACE_SM])
                    .style(iced::widget::button::secondary)
                    .into()
            }
        })
        .collect();

    container(
        row(buttons)
            .spacing(SPACE_XS)
            .align_y(iced::Alignment::Center),
    )
    .padding([SPACE_SM, SPACE_MD])
    .style(|theme: &iced::Theme| iced::widget::container::Style {
        // Subtle background tint instead of a 4-sided hairline border, which
        // would stack a second rule under the tab bar's existing bottom
        // hairline.  The weak background colour reads as a distinct toolbar
        // band in both light and dark themes without the doubled-rule artefact.
        background: Some(iced::Background::Color(
            theme.extended_palette().background.weak.color,
        )),
        ..Default::default()
    })
    .width(Length::Fill)
    .into()
}

// ── Info view ─────────────────────────────────────────────────────────────────

#[mutants::skip]
fn info_view(
    path: &str,
    _bytes: &[u8],
    parsed: &Result<std::sync::Arc<paksmith_core::asset::Package>, String>,
    meta: Option<&EntryMeta>,
) -> Element<'static, Message> {
    let mut entry_rows: Vec<Element<'static, Message>> = Vec::new();

    // ── entry-level rows (from EntryMeta) ────────────────────────────────────
    if let Some(m) = meta {
        let ucmp = human_size(m.uncompressed_size);
        let cmp = human_size(m.compressed_size);
        let ratio_str = compression_ratio(m.uncompressed_size, m.compressed_size)
            .unwrap_or_else(|| "\u{2014}".to_string());

        let compressed_label: String = if m.is_compressed {
            format!("Yes ({cmp}, {ratio_str})")
        } else {
            "No".to_string()
        };
        let encrypted_label: &str = if m.is_encrypted { "Yes" } else { "No" };

        entry_rows.push(kv_row("Path", path.to_owned()));
        entry_rows.push(kv_row("Size", ucmp));
        entry_rows.push(kv_row("Compressed", compressed_label));
        entry_rows.push(kv_row("Encrypted", encrypted_label.to_owned()));
    } else {
        // No EntryMeta — still show path.
        entry_rows.push(kv_row("Path", path.to_owned()));
    }

    // ── package-level rows ────────────────────────────────────────────────────
    let mut pkg_rows: Vec<Element<'static, Message>> = Vec::new();
    match parsed {
        Ok(pkg) => {
            let export_count = pkg.exports.exports.len().to_string();
            let name_count = pkg.names.names.len().to_string();
            let engine = pkg.summary.saved_by_engine_version.to_string();

            pkg_rows.push(kv_row("Exports", export_count));
            pkg_rows.push(kv_row("Names", name_count));
            pkg_rows.push(kv_row("Engine", engine));
        }
        Err(reason) => {
            // Muted "Properties unavailable" note.
            pkg_rows.push(
                text(format!("Properties unavailable: {reason}"))
                    .size(f32::from(TEXT_SM))
                    .style(|theme: &iced::Theme| iced::widget::text::Style {
                        color: Some(theme.palette().text.scale_alpha(TEXT_MUTED_ALPHA)),
                    })
                    .into(),
            );
        }
    }

    // Two groups separated by SPACE_MD so the card is scannable.
    let card = column![
        column(entry_rows).spacing(SPACE_SM),
        column(pkg_rows).spacing(SPACE_SM),
    ]
    .spacing(SPACE_MD);

    container(card)
        .padding(SPACE_LG)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}

/// The scroll geometry the given view mode's surface windows with.
///
/// A seam, not a convenience: each surface stores its own offset, and
/// handing the hex grid the inspector's (or vice versa) renders the wrong
/// slice. The view fns are `#[mutants::skip]` and return opaque `Element`s,
/// so that pairing is only observable here.
fn viewer_scroll(tab: &crate::state::tabs::Tab) -> crate::state::row_window::ScrollPos {
    match tab.view {
        ViewMode::Hex => tab.hex_scroll,
        _ => tab.props_scroll,
    }
}

// ── Properties view ───────────────────────────────────────────────────────────

#[mutants::skip]
fn properties_view<'a>(
    parsed: &'a Result<std::sync::Arc<paksmith_core::asset::Package>, String>,
    expanded: &'a std::collections::HashSet<crate::state::property_view::NodeId>,
    scroll: crate::state::row_window::ScrollPos,
) -> Element<'a, Message> {
    match parsed {
        Ok(pkg) => property_tree::view(pkg.as_ref(), expanded, scroll),
        Err(reason) => {
            let msg = format!("Not a parseable asset \u{2014} see Hex: {reason}");
            container(
                text(msg)
                    .size(f32::from(TEXT_SM))
                    .style(|theme: &iced::Theme| iced::widget::text::Style {
                        color: Some(theme.palette().text.scale_alpha(TEXT_MUTED_ALPHA)),
                    }),
            )
            .padding(SPACE_LG)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
        }
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

#[mutants::skip]
fn empty_state() -> Element<'static, Message> {
    container(
        text("Open a file to inspect it")
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

#[mutants::skip]
fn muted_text(s: &'static str) -> Element<'static, Message> {
    container(
        text(s)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::row_window::ScrollPos;
    use crate::state::tabs::Tabs;

    fn tab_with_offsets(hex: f32, props: f32) -> crate::state::tabs::Tab {
        let mut tabs = Tabs::default();
        let _ = tabs.open_or_activate("a.txt");
        let t = tabs.active_tab_mut().expect("harness: a tab");
        t.hex_scroll = ScrollPos {
            y: hex,
            viewport_h: 600.0,
        };
        t.props_scroll = ScrollPos {
            y: props,
            viewport_h: 600.0,
        };
        t.clone()
    }

    /// Each surface must window with ITS OWN stored offset. A review probe
    /// swapped the two at the call sites and the whole suite stayed green,
    /// because the views are mutants-skipped and return opaque `Element`s.
    #[test]
    fn each_view_mode_windows_with_its_own_stored_offset() {
        let tab = tab_with_offsets(300.0, 900.0);
        let mut hex_tab = tab.clone();
        hex_tab.view = ViewMode::Hex;
        let mut props_tab = tab.clone();
        props_tab.view = ViewMode::Properties;
        assert_eq!(viewer_scroll(&hex_tab), tab.hex_scroll);
        assert_eq!(viewer_scroll(&props_tab), tab.props_scroll);
        assert_ne!(
            viewer_scroll(&hex_tab),
            viewer_scroll(&props_tab),
            "the two surfaces must not share one offset"
        );
    }
}
