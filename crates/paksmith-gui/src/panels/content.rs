//! Content host panel — the right-hand pane when an archive is open.
//!
//! Renders the tab bar, a `Properties | Hex | Info` view-mode switcher, and
//! the body of the active tab.  Properties and Hex views are placeholders
//! replaced in Tasks 9 and 10 respectively; the Info view is fully
//! implemented here.

use std::collections::BTreeMap;

use iced::widget::{button, column, container, row, text};
use iced::{Element, Length};

use crate::app::{Message, accent_button};
use crate::panels::detail::{compression_ratio, human_size, kv_row};
use crate::state::archive::EntryMeta;
use crate::state::tabs::{TabContent, Tabs, ViewMode};
use crate::theme::tokens::{SPACE_LG, SPACE_MD, SPACE_SM, TEXT_MD, TEXT_MUTED_ALPHA, TEXT_SM};

// ── public entry-point ────────────────────────────────────────────────────────

/// Render the content host.
///
/// * `tabs`    — the current tab collection.
/// * `entries` — the archive's per-entry metadata map (keyed by full path).
/// * `accent`  — the system accent colour for the active view-mode button.
#[mutants::skip]
#[allow(clippy::too_many_lines)] // single-fn content host; splitting would obscure layout
pub fn view<'a>(
    tabs: &'a Tabs,
    entries: &'a BTreeMap<String, EntryMeta>,
    accent: iced::Color,
) -> Element<'a, Message> {
    if tabs.open.is_empty() {
        return empty_state();
    }

    // ── tab bar ───────────────────────────────────────────────────────────────
    let tab_bar: Element<'_, Message> = {
        let tab_buttons: Vec<Element<'_, Message>> =
            tabs.open
                .iter()
                .enumerate()
                .map(|(i, tab)| {
                    let label = tab
                        .path
                        .rsplit('/')
                        .next()
                        .unwrap_or(tab.path.as_str())
                        .to_string();
                    let is_active = tabs.active == Some(i);

                    // Close (×) button
                    let close_btn = button(text("\u{00D7}").size(f32::from(TEXT_SM)).style(
                        |theme: &iced::Theme| iced::widget::text::Style {
                            color: Some(theme.palette().text.scale_alpha(0.6)),
                        },
                    ))
                    .on_press(Message::TabClosed(i))
                    .padding([0, SPACE_XS_INT])
                    .style(iced::widget::button::text);

                    let name_btn =
                        if is_active {
                            button(text(label).size(f32::from(TEXT_SM)).style(
                                |theme: &iced::Theme| iced::widget::text::Style {
                                    color: Some(theme.palette().text),
                                },
                            ))
                            .on_press(Message::TabActivated(i))
                            .padding([SPACE_XS_FLOAT, SPACE_SM])
                            .style(
                                move |_theme: &iced::Theme, _status| iced::widget::button::Style {
                                    background: Some(iced::Background::Color(
                                        accent.scale_alpha(0.15),
                                    )),
                                    border: iced::Border {
                                        color: accent,
                                        width: 0.0,
                                        radius: crate::theme::tokens::RADIUS.into(),
                                    },
                                    text_color: _theme.palette().text,
                                    ..Default::default()
                                },
                            )
                        } else {
                            button(text(label).size(f32::from(TEXT_SM)).style(
                                |theme: &iced::Theme| iced::widget::text::Style {
                                    color: Some(theme.palette().text.scale_alpha(TEXT_MUTED_ALPHA)),
                                },
                            ))
                            .on_press(Message::TabActivated(i))
                            .padding([SPACE_XS_FLOAT, SPACE_SM])
                            .style(iced::widget::button::text)
                        };

                    row![name_btn, close_btn]
                        .align_y(iced::Alignment::Center)
                        .into()
                })
                .collect();

        container(
            row(tab_buttons)
                .spacing(SPACE_XS_FLOAT)
                .align_y(iced::Alignment::Center),
        )
        .padding([SPACE_XS_FLOAT, SPACE_SM])
        .style(|theme: &iced::Theme| iced::widget::container::Style {
            background: Some(iced::Background::Color(
                theme.palette().background.scale_alpha(0.95),
            )),
            border: iced::Border {
                color: theme.palette().text.scale_alpha(0.1),
                width: 1.0,
                radius: 0.0.into(),
            },
            ..Default::default()
        })
        .width(Length::Fill)
        .into()
    };

    // ── active tab body ───────────────────────────────────────────────────────
    let body: Element<'_, Message> = match tabs.active_tab() {
        None => muted_text("No active tab"),
        Some(tab) => {
            let switcher = view_mode_switcher(tab.view, accent);
            let content = match &tab.content {
                TabContent::Loading => muted_text("Loading\u{2026}"),
                TabContent::Ready { bytes, parsed } => {
                    let meta = entries.get(tab.path.as_str());
                    match tab.view {
                        ViewMode::Info => info_view(tab.path.as_str(), bytes, parsed, meta),
                        ViewMode::Properties => muted_text("(properties view \u{2014} Task 10)"),
                        ViewMode::Hex => muted_text("(hex view \u{2014} Task 9)"),
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

    column![tab_bar, body]
        .spacing(0)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}

// ── view-mode switcher ────────────────────────────────────────────────────────

#[mutants::skip]
fn view_mode_switcher(active: ViewMode, accent: iced::Color) -> Element<'static, Message> {
    let modes = [
        (ViewMode::Properties, "Properties"),
        (ViewMode::Hex, "Hex"),
        (ViewMode::Info, "Info"),
    ];

    let buttons: Vec<Element<'_, Message>> = modes
        .into_iter()
        .map(|(mode, label)| {
            let is_active = mode == active;
            if is_active {
                button(text(label).size(f32::from(TEXT_SM)))
                    .on_press(Message::ViewModeSet(mode))
                    .padding([SPACE_XS_FLOAT, SPACE_SM])
                    .style(accent_button(accent))
                    .into()
            } else {
                button(text(label).size(f32::from(TEXT_SM)))
                    .on_press(Message::ViewModeSet(mode))
                    .padding([SPACE_XS_FLOAT, SPACE_SM])
                    .style(iced::widget::button::secondary)
                    .into()
            }
        })
        .collect();

    container(
        row(buttons)
            .spacing(SPACE_XS_FLOAT)
            .align_y(iced::Alignment::Center),
    )
    .padding([SPACE_SM, SPACE_MD])
    .width(Length::Fill)
    .into()
}

// ── Info view ─────────────────────────────────────────────────────────────────

#[mutants::skip]
fn info_view(
    path: &str,
    _bytes: &[u8],
    parsed: &Result<Box<paksmith_core::asset::Package>, String>,
    meta: Option<&EntryMeta>,
) -> Element<'static, Message> {
    let mut rows: Vec<Element<'static, Message>> = Vec::new();

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

        rows.push(kv_row("Path", path.to_owned()));
        rows.push(kv_row("Size", ucmp));
        rows.push(kv_row("Compressed", compressed_label));
        rows.push(kv_row("Encrypted", encrypted_label.to_owned()));
    } else {
        // No EntryMeta — still show path.
        rows.push(kv_row("Path", path.to_owned()));
    }

    // ── package-level rows ────────────────────────────────────────────────────
    match parsed {
        Ok(pkg) => {
            let export_count = pkg.exports.exports.len().to_string();
            let name_count = pkg.names.names.len().to_string();
            let engine = pkg.summary.saved_by_engine_version.to_string();

            rows.push(kv_row("Exports", export_count));
            rows.push(kv_row("Names", name_count));
            rows.push(kv_row("Engine", engine));
        }
        Err(reason) => {
            // Muted "Properties unavailable" note.
            rows.push(
                text(format!("Properties unavailable: {reason}"))
                    .size(f32::from(TEXT_SM))
                    .style(|theme: &iced::Theme| iced::widget::text::Style {
                        color: Some(theme.palette().text.scale_alpha(TEXT_MUTED_ALPHA)),
                    })
                    .into(),
            );
        }
    }

    container(column(rows).spacing(SPACE_SM))
        .padding(SPACE_LG)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}

// ── helpers ───────────────────────────────────────────────────────────────────

const SPACE_XS_FLOAT: f32 = crate::theme::tokens::SPACE_XS;
const SPACE_XS_INT: u16 = 4;

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
