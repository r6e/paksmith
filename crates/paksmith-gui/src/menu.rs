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
//!   Toggle Theme and About are exposed via toolbar buttons (compiled in under
//!   `#[cfg(not(target_os = "macos"))]` in `panels/toolbar.rs`).  Open is the
//!   toolbar's primary CTA on all platforms.  Full native-menu support on
//!   Windows/Linux is tracked as a follow-up.
//!
//! # Event bridge
//!
//! `muda` fires events into a global crossbeam channel (`MenuEvent::receiver()`).
//! The bridge uses `iced::Subscription::run` over a stream that drains ALL
//! pending menu events on each 50 ms poll tick, yielding each as a separate
//! [`crate::app::Message`] via [`message_for`].  Using a stream-per-event
//! approach avoids the single-event-per-tick loss that a `.map` + `filter_map`
//! subscription would cause when two events arrive in the same tick window.
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
    }
}

// ── Well-known menu item IDs ──────────────────────────────────────────────────

const ID_OPEN: &str = "paksmith.file.open";
const ID_TOGGLE_THEME: &str = "paksmith.view.toggle_theme";
const ID_ABOUT: &str = "paksmith.help.about";

/// Resolves a fired `muda::MenuId` to a [`MenuAction`], if known.
pub fn action_for_id(id: &muda::MenuId) -> Option<MenuAction> {
    match id.as_ref() {
        ID_OPEN => Some(MenuAction::Open),
        ID_TOGGLE_THEME => Some(MenuAction::ToggleTheme),
        ID_ABOUT => Some(MenuAction::About),
        _ => None,
    }
}

// ── Menu construction ─────────────────────────────────────────────────────────

/// Builds the application menu and returns it, or a [`muda::Error`] if the
/// platform cannot construct the menu (e.g. no display on Linux headless).
///
/// On macOS, call `muda::Menu::init_for_nsapp` on the returned menu before the
/// iced event loop starts to install it as the global app menu bar. (Plain code
/// span, not an intra-doc link: `init_for_nsapp` is macOS-only, so a `[...]`
/// link fails to resolve under rustdoc on Linux/Windows.)
///
/// ```text
/// File          View              Help
/// ─────────     ───────────────   ──────
/// Open…  ⌘O    Toggle Theme      About Paksmith
/// ─────────
/// Quit   ⌘Q   (system-predefined, OS handles Quit directly)
/// ```
///
/// # Errors
///
/// Returns [`muda::Error`] if any submenu or item cannot be created — only
/// possible if muda's internal platform state is inconsistent (e.g. no GTK
/// display on Linux).  Callers should log and continue without the native menu
/// rather than unwrapping.
pub fn build() -> Result<Menu, muda::Error> {
    let menu = Menu::new();

    // ── File ──────────────────────────────────────────────────────────────────
    let open_item = MenuItem::with_id(
        ID_OPEN,
        "Open\u{2026}",
        true,
        Some(Accelerator::new(Some(CMD_OR_CTRL), Code::KeyO)),
    );
    // Use the platform-predefined Quit item: on macOS this provides ⌘Q and
    // correct NSApplication termination semantics automatically.  The OS handles
    // the quit action directly — no muda MenuEvent is fired, and no Message::Quit
    // is needed on this path.
    let quit_item = PredefinedMenuItem::quit(None);

    let file_menu = Submenu::with_items(
        "File",
        true,
        &[&open_item, &PredefinedMenuItem::separator(), &quit_item],
    )?;

    // ── View ──────────────────────────────────────────────────────────────────
    let toggle_theme_item = MenuItem::with_id(ID_TOGGLE_THEME, "Toggle Theme", true, None);

    let view_menu = Submenu::with_items("View", true, &[&toggle_theme_item])?;

    // ── Help ──────────────────────────────────────────────────────────────────
    let about_item = MenuItem::with_id(ID_ABOUT, "About Paksmith", true, None);

    let help_menu = Submenu::with_items("Help", true, &[&about_item])?;

    // ── Assemble ──────────────────────────────────────────────────────────────
    menu.append_items(&[&file_menu, &view_menu, &help_menu])?;

    Ok(menu)
}

// ── Subscription bridge ───────────────────────────────────────────────────────

/// Returns a [`iced::Subscription`] that forwards every `muda` menu event to
/// the iced message loop as a [`Message`].
///
/// The bridge polls muda's global event channel on a 50 ms tick and drains
/// ALL pending events per tick, yielding each one as a separate message.  This
/// avoids the single-event-per-tick loss that a simple `.map` subscription
/// would introduce when two events arrive in the same 50 ms window.
///
/// Implemented via [`iced::Subscription::run`] over a stream that uses
/// [`iced::stream::channel`] to bridge the synchronous crossbeam receiver into
/// async iced subscription machinery.
pub fn subscription() -> iced::Subscription<Message> {
    iced::Subscription::run(menu_event_stream)
}

/// Async stream that drains muda's menu event channel on every 50 ms tick,
/// yielding each recognised event as a [`Message`].
///
/// This is a named `fn` (not a closure) because [`iced::Subscription::run`]
/// requires a function pointer for identity-based deduplication.
fn menu_event_stream() -> impl iced::futures::Stream<Item = Message> {
    use std::time::Duration;

    iced::stream::channel(16, async |mut tx| {
        use iced::futures::sink::SinkExt as _;

        let receiver = muda::MenuEvent::receiver();
        loop {
            tokio::time::sleep(Duration::from_millis(50)).await;
            while let Ok(event) = receiver.try_recv() {
                if let Some(action) = action_for_id(&event.id) {
                    // Ignore send errors: the iced runtime drops the receiver
                    // only on shutdown, at which point losing events is fine.
                    let _ = tx.send(message_for(action)).await;
                }
            }
        }
    })
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
    fn action_for_known_ids() {
        let cases: &[(&str, MenuAction)] = &[
            (ID_OPEN, MenuAction::Open),
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
