//! Native menu bar via `muda`.
//!
//! # Platform support
//!
//! - **macOS**: `main` installs the menu with `Menu::init_for_nsapp()` before
//!   the iced event loop starts, and winit's launch handler then replaces it
//!   (#954).  `muda` hooks into the NSApp directly — no window handle needed.
//!
//! - **Windows / Linux**: the menu is built but never attached, so Toggle
//!   Theme, the debug console, and About are exposed via toolbar buttons
//!   (compiled in under `#[cfg(not(target_os = "macos"))]` in
//!   `panels/toolbar.rs`), and Ctrl+O is supplied by an iced keyboard
//!   listener (`app::open_accelerator_message`) since the menu's own
//!   accelerator never registers unattached. Open is also the toolbar's
//!   primary CTA on all platforms. The attach gap differs per platform —
//!   #662 flagged it, and the audit BELOW (done for that issue's PR)
//!   supersedes the issue body's premise that iced 0.14 exposes no window
//!   handle: on **Windows** it does (`iced::window::run` hands out
//!   `&dyn Window: HasWindowHandle`), so an HWND attach is implementable
//!   follow-up work; on **Linux** muda's backend is GTK-based and an
//!   iced/winit window is not a GTK window, so attach is blocked regardless
//!   of handles.
//!
//! # Descoped: Tools menu
//!
//! SPEC.md's GUI layout sketch lists File/View/Tools/Help in its Menu Bar
//! row; Tools is not built because nothing populates it yet — every current
//! action already has a home (File/View/Help, or the app menu on macOS).
//! Recorded as a deliberate descope per #662 rather than shipping an empty
//! menu; add it when the first tool (e.g. batch export, key manager) exists
//! to live there.
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
    ToggleConsole,
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
        MenuAction::ToggleConsole => Message::ConsoleToggled,
        MenuAction::About => Message::About,
    }
}

// ── Well-known menu item IDs ──────────────────────────────────────────────────

const ID_OPEN: &str = "paksmith.file.open";
const ID_TOGGLE_THEME: &str = "paksmith.view.toggle_theme";
const ID_TOGGLE_CONSOLE: &str = "paksmith.view.toggle_console";
const ID_ABOUT: &str = "paksmith.help.about";

/// Resolves a fired `muda::MenuId` to a [`MenuAction`], if known.
pub fn action_for_id(id: &muda::MenuId) -> Option<MenuAction> {
    match id.as_ref() {
        ID_OPEN => Some(MenuAction::Open),
        ID_TOGGLE_THEME => Some(MenuAction::ToggleTheme),
        ID_TOGGLE_CONSOLE => Some(MenuAction::ToggleConsole),
        ID_ABOUT => Some(MenuAction::About),
        _ => None,
    }
}

// ── Menu construction ─────────────────────────────────────────────────────────

/// Builds the application menu and returns it.
///
/// On macOS `main` installs it with `Menu::init_for_nsapp` before the iced
/// event loop starts, and winit's launch handler then replaces it (#954).
///
/// ```text
/// macOS:            Paksmith            File         View
///                   About Paksmith      Open…  ⌘O    Toggle Theme
///                   Services ▸                       Debug Console
///                   Hide Paksmith  ⌘H
///                   Hide Others, Show All
///                   Quit Paksmith  ⌘Q
///
/// Windows / Linux:  File                View         Help
///                   Open…  Ctrl+O       Toggle Theme About Paksmith
///                   Quit                Debug Console
/// ```
///
/// # Errors
///
/// Returns [`muda::Error`] if muda rejects an item, which this fixed layout
/// does not trigger (muda builds it even without a display). Callers should
/// still log and continue without the native menu rather than unwrapping.
pub fn build() -> Result<Menu, muda::Error> {
    build_for(cfg!(target_os = "macos"))
}

/// [`build`] with macOS's layout or every other platform's: a parameter, not a
/// `cfg`, so the ubuntu and windows test jobs build and pin both layouts and
/// ubuntu's clippy lints both. (macOS tests neither: muda builds a `Menu` there
/// only on the main thread.)
fn build_for(macos: bool) -> Result<Menu, muda::Error> {
    let menu = Menu::new();
    let about_item = MenuItem::with_id(ID_ABOUT, "About Paksmith", true, None);

    // ── App (macOS) ───────────────────────────────────────────────────────────
    // AppKit shows the first submenu as the application menu, under the app's
    // name whatever this title says: without it, File would be taken for it.
    // About and Quit sit here on macOS, beside the rows winit's default app
    // menu had.
    if macos {
        menu.append(&Submenu::with_items(
            "Paksmith",
            true,
            &[
                &about_item,
                &PredefinedMenuItem::separator(),
                &PredefinedMenuItem::services(None),
                &PredefinedMenuItem::separator(),
                &PredefinedMenuItem::hide(Some("Hide Paksmith")),
                &PredefinedMenuItem::hide_others(None),
                &PredefinedMenuItem::show_all(None),
                &PredefinedMenuItem::separator(),
                &PredefinedMenuItem::quit(Some("Quit Paksmith")),
            ],
        )?)?;
    }

    // ── File ──────────────────────────────────────────────────────────────────
    let open_item = MenuItem::with_id(ID_OPEN, "Open\u{2026}", true, Some(open_accelerator()));
    let file_menu = Submenu::with_items("File", true, &[&open_item])?;
    // The platform-predefined Quit: the OS handles it directly, so no muda
    // MenuEvent fires and no Message::Quit is needed. On macOS the app menu
    // holds it instead, so ⌘Q is bound once.
    if !macos {
        file_menu.append_items(&[
            &PredefinedMenuItem::separator(),
            &PredefinedMenuItem::quit(None),
        ])?;
    }

    // ── View ──────────────────────────────────────────────────────────────────
    let toggle_theme_item = MenuItem::with_id(ID_TOGGLE_THEME, "Toggle Theme", true, None);
    let toggle_console_item = MenuItem::with_id(ID_TOGGLE_CONSOLE, "Debug Console", true, None);

    let view_menu = Submenu::with_items("View", true, &[&toggle_theme_item, &toggle_console_item])?;
    menu.append_items(&[&file_menu, &view_menu])?;

    // ── Help (not macOS: About is in the app menu there) ─────────────────────
    if !macos {
        menu.append(&Submenu::with_items("Help", true, &[&about_item])?)?;
    }

    Ok(menu)
}

/// The File → Open shortcut: ⌘O on macOS, Ctrl+O elsewhere.
fn open_accelerator() -> Accelerator {
    Accelerator::new(CMD_OR_CTRL, Code::KeyO)
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

/// Each submenu of `menu` as `(title, items)`, an action item by its id and a
/// predefined one by its label. Off macOS only, like its callers: muda builds a
/// `Menu` there only on the main thread, and libtest runs every test on a
/// spawned thread.
#[cfg(all(test, not(target_os = "macos")))]
pub(crate) fn layout(menu: &Menu) -> Vec<(String, Vec<String>)> {
    let item = |kind: &muda::MenuItemKind| match kind {
        muda::MenuItemKind::MenuItem(action) => action.id().as_ref().to_owned(),
        muda::MenuItemKind::Predefined(predefined) => predefined.text(),
        _ => String::from("?"),
    };
    menu.items()
        .iter()
        .map(|kind| {
            let submenu = kind.as_submenu().expect("the bar holds only submenus");
            (submenu.text(), submenu.items().iter().map(item).collect())
        })
        .collect()
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
    fn toggle_console_maps_to_console_toggled_message() {
        assert!(matches!(
            message_for(MenuAction::ToggleConsole),
            Message::ConsoleToggled
        ));
    }

    #[test]
    fn action_for_known_ids() {
        let cases: &[(&str, MenuAction)] = &[
            (ID_OPEN, MenuAction::Open),
            (ID_TOGGLE_THEME, MenuAction::ToggleTheme),
            (ID_ABOUT, MenuAction::About),
            (ID_TOGGLE_CONSOLE, MenuAction::ToggleConsole),
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

    /// `(title, items)` pairs, the way [`layout`] reports a bar.
    #[cfg(not(target_os = "macos"))]
    fn owned(bar: &[(&str, &[&str])]) -> Vec<(String, Vec<String>)> {
        bar.iter()
            .map(|&(title, items)| {
                (
                    title.to_owned(),
                    items.iter().copied().map(String::from).collect(),
                )
            })
            .collect()
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn macos_leads_with_an_app_menu_holding_about_and_quit() {
        let menu = build_for(true).expect("muda builds a menu off macOS without a display");
        // "" is a separator. No Help: About moved to the app menu.
        let app: &[&str] = &[
            ID_ABOUT,
            "",
            "Services",
            "",
            "Hide Paksmith",
            "Hide Others",
            "Show All",
            "",
            "Quit Paksmith",
        ];
        let expected = [
            ("Paksmith", app),
            ("File", &[ID_OPEN][..]),
            ("View", &[ID_TOGGLE_THEME, ID_TOGGLE_CONSOLE][..]),
        ];
        assert_eq!(layout(&menu), owned(&expected));
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn other_platforms_keep_file_view_help() {
        let menu = build_for(false).expect("muda builds a menu off macOS without a display");
        // muda's own label for the predefined Quit, which differs per platform.
        let quit = PredefinedMenuItem::quit(None).text();
        let expected = [
            ("File", &[ID_OPEN, "", quit.as_str()][..]),
            ("View", &[ID_TOGGLE_THEME, ID_TOGGLE_CONSOLE][..]),
            ("Help", &[ID_ABOUT][..]),
        ];
        assert_eq!(layout(&menu), owned(&expected));
    }

    #[test]
    fn open_accelerator_is_cmd_or_ctrl_o() {
        let expected: Accelerator = "CmdOrCtrl+O".parse().expect("muda parses CmdOrCtrl+O");
        assert_eq!(open_accelerator(), expected);
    }
}
