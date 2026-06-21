//! Native menu bar via `muda`.
//!
//! # Platform support
//!
//! - **macOS**: `Menu::init_for_nsapp()` installs a global menu bar before the
//!   iced event loop starts.  `muda` hooks into the NSApp directly — no window
//!   handle needed.
//!
//! - **Windows / Linux**: attaching a `muda` menu requires a raw window handle
//!   (HWND / GTK window) that iced 0.14 does not expose through its public API.
//!   The menu actions (Open, Toggle Theme, About, Quit) remain reachable via the
//!   toolbar buttons.  Native menus on Windows/Linux are tracked as a follow-up.
//!
//! # Event bridge
//!
//! `muda` fires events into a global crossbeam channel (`MenuEvent::receiver()`).
//! The bridge polls this channel on an [`iced::time::every`] tick (50 ms — fast
//! enough to feel instant, slow enough to be cheap) and maps each `MenuId` to a
//! [`crate::app::Message`] via [`message_for`].
//!
//! # Testability
//!
//! [`MenuAction`] decouples the pure id→action→message mapping from the real
//! `muda::MenuId` values so that [`message_for`] can be unit-tested without
//! constructing a live menu.

use muda::{
    Menu, MenuItem, PredefinedMenuItem, Submenu,
    accelerator::{Accelerator, CMD_OR_CTRL, Code},
};

use crate::app::Message;

// ── MenuAction ────────────────────────────────────────────────────────────────

/// Semantic action fired by a menu item.
///
/// The enum is intentionally decoupled from `muda::MenuId` so that
/// [`message_for`] is a pure, unit-testable function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MenuAction {
    Open,
    ToggleTheme,
    About,
    Quit,
}

/// Maps a [`MenuAction`] to the corresponding [`Message`].
///
/// This is a pure function — no muda state, no side effects — so it can be
/// tested without a display or a constructed menu.
pub fn message_for(action: MenuAction) -> Message {
    match action {
        MenuAction::Open => Message::OpenRequested,
        MenuAction::ToggleTheme => Message::ToggleTheme,
        MenuAction::About => Message::About,
        MenuAction::Quit => Message::Quit,
    }
}

// ── Well-known menu item IDs ──────────────────────────────────────────────────

const ID_OPEN: &str = "paksmith.file.open";
const ID_QUIT: &str = "paksmith.file.quit";
const ID_TOGGLE_THEME: &str = "paksmith.view.toggle_theme";
const ID_ABOUT: &str = "paksmith.help.about";

/// Resolves a fired `muda::MenuId` to a [`MenuAction`], if known.
pub fn action_for_id(id: &muda::MenuId) -> Option<MenuAction> {
    match id.0.as_str() {
        ID_OPEN => Some(MenuAction::Open),
        ID_QUIT => Some(MenuAction::Quit),
        ID_TOGGLE_THEME => Some(MenuAction::ToggleTheme),
        ID_ABOUT => Some(MenuAction::About),
        _ => None,
    }
}

// ── Menu construction ─────────────────────────────────────────────────────────

/// Builds the application menu and returns it.
///
/// On macOS, call [`muda::Menu::init_for_nsapp`] on the returned menu before
/// the iced event loop starts to install it as the global app menu bar.
///
/// ```text
/// File          View              Help
/// ─────────     ───────────────   ──────
/// Open…  ⌘O    Toggle Theme      About Paksmith
/// ─────────
/// Quit
/// ```
///
/// # Panics
///
/// Panics if any submenu or item cannot be appended — only possible if muda's
/// internal platform state is inconsistent, which should never happen at
/// startup.
pub fn build() -> Menu {
    let menu = Menu::new();

    // ── File ──────────────────────────────────────────────────────────────────
    let open_item = MenuItem::with_id(
        ID_OPEN,
        "Open\u{2026}",
        true,
        Some(Accelerator::new(Some(CMD_OR_CTRL), Code::KeyO)),
    );
    let quit_item = MenuItem::with_id(ID_QUIT, "Quit", true, None);

    let file_menu = Submenu::with_items(
        "File",
        true,
        &[&open_item, &PredefinedMenuItem::separator(), &quit_item],
    )
    .expect("failed to build File submenu");

    // ── View ──────────────────────────────────────────────────────────────────
    let toggle_theme_item = MenuItem::with_id(ID_TOGGLE_THEME, "Toggle Theme", true, None);

    let view_menu = Submenu::with_items("View", true, &[&toggle_theme_item])
        .expect("failed to build View submenu");

    // ── Help ──────────────────────────────────────────────────────────────────
    let about_item = MenuItem::with_id(ID_ABOUT, "About Paksmith", true, None);

    let help_menu =
        Submenu::with_items("Help", true, &[&about_item]).expect("failed to build Help submenu");

    // ── Assemble ──────────────────────────────────────────────────────────────
    menu.append_items(&[&file_menu, &view_menu, &help_menu])
        .expect("failed to append submenus to root menu");

    menu
}

// ── Subscription bridge ───────────────────────────────────────────────────────

/// Returns a [`iced::Subscription`] that polls `muda`'s global event channel
/// on a 50 ms tick and maps any fired [`muda::MenuEvent`] to a [`Message`].
///
/// The tick rate (50 ms) is fast enough that menu actions feel instant to the
/// user while keeping CPU overhead negligible between events.
pub fn subscription() -> iced::Subscription<Message> {
    use std::time::Duration;

    iced::time::every(Duration::from_millis(50)).map(|_| {
        // Drain all pending menu events; return the first one that maps to a
        // known action, if any.  A single tick rarely has more than one event.
        let receiver = muda::MenuEvent::receiver();
        while let Ok(event) = receiver.try_recv() {
            if let Some(action) = action_for_id(&event.id) {
                return Some(message_for(action));
            }
            // Unknown id — keep draining.
        }
        None
    })
    // Flatten Option<Message> → only produce messages when Some.
    .filter_map(|opt| opt)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::Message;

    #[test]
    fn open_id_maps_to_open_message() {
        assert!(matches!(
            message_for(MenuAction::Open),
            Message::OpenRequested
        ));
    }

    #[test]
    fn toggle_theme_maps_to_toggle_theme_message() {
        assert!(matches!(
            message_for(MenuAction::ToggleTheme),
            Message::ToggleTheme
        ));
    }

    #[test]
    fn about_maps_to_about_message() {
        assert!(matches!(message_for(MenuAction::About), Message::About));
    }

    #[test]
    fn quit_maps_to_quit_message() {
        assert!(matches!(message_for(MenuAction::Quit), Message::Quit));
    }

    #[test]
    fn action_for_known_ids() {
        let cases: &[(&str, MenuAction)] = &[
            (ID_OPEN, MenuAction::Open),
            (ID_QUIT, MenuAction::Quit),
            (ID_TOGGLE_THEME, MenuAction::ToggleTheme),
            (ID_ABOUT, MenuAction::About),
        ];
        for (raw_id, expected) in cases {
            let id = muda::MenuId::new(raw_id);
            assert_eq!(
                action_for_id(&id),
                Some(*expected),
                "id {raw_id} should map to {expected:?}"
            );
        }
    }

    #[test]
    fn action_for_unknown_id_is_none() {
        let id = muda::MenuId::new("paksmith.unknown");
        assert_eq!(action_for_id(&id), None);
    }
}
