//! Paksmith GUI — native-feeling explorer for Unreal Engine game assets.

mod app;
mod menu;
mod panels;
#[allow(dead_code)]
// Task 11: tree-view (Node fields, Tree methods)
mod state;
mod task;
mod theme;
mod widgets;

use app::App;

fn main() -> iced::Result {
    // Build and install the native menu bar.
    //
    // macOS: `init_for_nsapp()` attaches the menu as the global app menu bar
    // (the bar at the top of the screen).  This must run on the main thread
    // and before the iced event loop takes over — calling it here in `main()`
    // satisfies both requirements.
    //
    // Windows / Linux: attaching a muda menu requires the raw window handle
    // (HWND / GTK window), which iced 0.14 does not expose through its public
    // API.  The menu is still built (so the subscription bridge is always
    // active) but `init_for_nsapp` is skipped.  Actions remain reachable via
    // the toolbar.  Full Windows/Linux native-menu support is a follow-up.
    let _menu = menu::build();

    #[cfg(target_os = "macos")]
    _menu.init_for_nsapp();

    iced::application(App::default, app::update, app::view)
        .title("Paksmith")
        .theme(|app: &App| theme::iced_theme(app.mode))
        .subscription(app::subscription)
        .run()
}
