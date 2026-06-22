//! Polished tab-bar widget for the content host.
//!
//! Renders a horizontally-scrollable strip of tabs — one per open asset.
//! Each tab has:
//! - A label button (left-click = activate, status-aware hover)
//! - A `×` close button (left-click = close, own hover feedback)
//! - Middle-click to close via `mouse_area`
//!
//! The active tab is marked with a 2px bottom underline (accent colour) +
//! accent-tint background wash (0.15 rest / 0.22 hover). Inactive tabs show
//! a subtle hover wash and a 2px transparent spacer so heights match.

use iced::widget::{button, column, container, mouse_area, row, scrollable, text};
use iced::{Background, Color, Element, Length};

use crate::app::Message;
use crate::state::tabs::Tabs;
use crate::theme::tokens;

// ── pure helpers ──────────────────────────────────────────────────────────────

/// Returns the basename (last `/`-segment) of the given asset path.
///
/// - `"Game/Maps/Demo.uasset"` → `"Demo.uasset"`
/// - `"top.uasset"` → `"top.uasset"`
/// - `""` → `""`
pub fn tab_label(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

// ── view ─────────────────────────────────────────────────────────────────────

/// Renders the tab strip for the given `tabs` collection.
///
/// Returns an `Element` that fits within the full width of the content host.
/// Wraps in a horizontal `scrollable` so 6+ tabs scroll instead of compressing.
// Pure view: cosmetic Style/Border/status-match-arm mutants aren't
// regex-excludable in cargo-mutants 27 (see file_tree::build_row for the same
// rationale). The pure logic (`tab_label`) is extracted and unit-tested below.
#[mutants::skip]
#[allow(clippy::too_many_lines)]
pub fn view(tabs: &Tabs, accent: Color) -> Element<'_, Message> {
    let tab_elements: Vec<Element<'_, Message>> = tabs
        .open
        .iter()
        .enumerate()
        .map(|(i, tab)| {
            let is_active = tabs.active == Some(i);
            let label = tab_label(&tab.path);

            // ── label button ───────────────────────────────────────────────
            //
            // Fix 4: inactive tabs use TEXT_MUTED_ALPHA (0.68) so active tab
            // reads as the brightest/primary element (VS Code pattern).
            // Fix 5: label capped at max_width 180px via container+clip so
            // long UE asset names don't push other tabs off-screen.
            //
            // Active tab: accent-tint background wash (0.22 hovered / 0.15 resting),
            // full palette().text label colour.
            // Inactive tab: hover wash only, muted label colour.
            let label_content = container(text(label).size(f32::from(tokens::TEXT_SM)).style(
                move |theme: &iced::Theme| iced::widget::text::Style {
                    color: Some(if is_active {
                        theme.palette().text
                    } else {
                        theme.palette().text.scale_alpha(tokens::TEXT_MUTED_ALPHA)
                    }),
                },
            ))
            .max_width(180.0)
            .clip(true);

            let label_btn = if is_active {
                button(label_content)
                    .on_press(Message::TabActivated(i))
                    .padding([tokens::SPACE_XS, tokens::SPACE_SM])
                    .style(move |_theme: &iced::Theme, status| {
                        let bg_alpha = match status {
                            iced::widget::button::Status::Hovered
                            | iced::widget::button::Status::Pressed => 0.22,
                            _ => 0.15,
                        };
                        iced::widget::button::Style {
                            background: Some(Background::Color(accent.scale_alpha(bg_alpha))),
                            text_color: _theme.palette().text,
                            border: iced::Border {
                                radius: 0.0.into(),
                                ..Default::default()
                            },
                            ..Default::default()
                        }
                    })
            } else {
                button(label_content)
                    .on_press(Message::TabActivated(i))
                    .padding([tokens::SPACE_XS, tokens::SPACE_SM])
                    .style(|theme: &iced::Theme, status| {
                        let bg = match status {
                            iced::widget::button::Status::Hovered
                            | iced::widget::button::Status::Pressed => {
                                Some(Background::Color(theme.palette().text.scale_alpha(0.07)))
                            }
                            _ => None,
                        };
                        iced::widget::button::Style {
                            background: bg,
                            text_color: theme.palette().text.scale_alpha(tokens::TEXT_MUTED_ALPHA),
                            border: iced::Border {
                                radius: 0.0.into(),
                                ..Default::default()
                            },
                            ..Default::default()
                        }
                    })
            };

            // ── close (×) button ───────────────────────────────────────────
            //
            // Fix 1: padding increased to [SPACE_XS, SPACE_SM] for a ~28px
            // hit target (up from the previous ~20px). A SPACE_XS spacer
            // separates it from the label button.
            // Fix 2: own hover feedback — subtle background tint on
            // Hovered/Pressed (palette().text.scale_alpha(0.12) with RADIUS),
            // transparent at rest.
            let close_btn = button(text("\u{00D7}").size(f32::from(tokens::TEXT_SM)).style(
                |theme: &iced::Theme| iced::widget::text::Style {
                    color: Some(theme.palette().text.scale_alpha(tokens::TEXT_MUTED_ALPHA)),
                },
            ))
            .on_press(Message::TabClosed(i))
            .padding([tokens::SPACE_XS, tokens::SPACE_SM])
            .style(|theme: &iced::Theme, status| {
                let background = match status {
                    iced::widget::button::Status::Hovered
                    | iced::widget::button::Status::Pressed => {
                        Some(Background::Color(theme.palette().text.scale_alpha(0.12)))
                    }
                    _ => None,
                };
                iced::widget::button::Style {
                    background,
                    text_color: theme.palette().text.scale_alpha(tokens::TEXT_MUTED_ALPHA),
                    border: iced::Border {
                        radius: tokens::RADIUS.into(),
                        ..Default::default()
                    },
                    ..Default::default()
                }
            });

            // ── Fix 3: bottom-underline anchor ─────────────────────────────
            //
            // Active tab: 2px accent-coloured underline bar.
            // Inactive tab: 2px transparent spacer (same height → no jitter).
            // The 4-sided border + rounded-pill look is replaced with a
            // cleaner tab metaphor: flat label area + bottom underline.
            let tab_inner_row = row![
                label_btn,
                iced::widget::Space::new().width(tokens::SPACE_XS), // Fix 1 gap
                close_btn
            ]
            .align_y(iced::Alignment::Center);

            let underline = if is_active {
                container(iced::widget::Space::new().height(2.0))
                    .width(Length::Fill)
                    .style(move |_theme: &iced::Theme| iced::widget::container::Style {
                        background: Some(Background::Color(accent)),
                        ..Default::default()
                    })
            } else {
                container(iced::widget::Space::new().height(2.0))
                    .width(Length::Fill)
                    .style(|_theme: &iced::Theme| iced::widget::container::Style {
                        background: Some(Background::Color(Color::TRANSPARENT)),
                        ..Default::default()
                    })
            };

            let tab_col = column![tab_inner_row, underline].width(Length::Shrink);

            // ── compose: tab column wrapped in mouse_area ──────────────────
            //
            // Left-clicks go to the inner buttons; middle-click goes to the
            // mouse_area (buttons don't handle middle-click so no conflict).
            mouse_area(tab_col)
                .on_middle_press(Message::TabClosed(i))
                .into()
        })
        .collect();

    // ── horizontal scrollable strip ───────────────────────────────────────────
    //
    // Wrap the tab row in a horizontal scrollable so 6+ open tabs scroll
    // instead of clipping or compressing. Height is Shrink so the strip
    // doesn't eat the content body below it.
    //
    // Fix 6: thin the scrollbar chrome — width(4px) + scroller_width(3px) so
    // the 32px-tall strip doesn't show a heavy default scrollbar rail.
    let tab_row = row(tab_elements)
        .spacing(tokens::SPACE_XS)
        .align_y(iced::Alignment::Center);

    let scroll_strip = scrollable(tab_row)
        .direction(scrollable::Direction::Horizontal(
            scrollable::Scrollbar::new().width(4.0).scroller_width(3.0),
        ))
        .width(Length::Fill)
        .height(Length::Shrink);

    iced::widget::container(scroll_strip)
        .padding([tokens::SPACE_XS, tokens::SPACE_SM])
        .style(|theme: &iced::Theme| iced::widget::container::Style {
            background: Some(Background::Color(
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
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tab_label_is_basename() {
        assert_eq!(tab_label("Game/Maps/Demo.uasset"), "Demo.uasset");
        assert_eq!(tab_label("top.uasset"), "top.uasset");
        assert_eq!(tab_label(""), "");
    }

    #[test]
    fn tab_label_deep_path_returns_last_segment() {
        // Extra assertion: kills a mutant that returns the full path unchanged
        // (rsplit('/') must actually split).
        assert_ne!(tab_label("A/B/C.uasset"), "A/B/C.uasset");
    }

    #[test]
    fn tab_label_no_slash_returns_input() {
        // Ensures `unwrap_or(path)` path is exercised and correct.
        assert_eq!(tab_label("file.uasset"), "file.uasset");
    }
}
