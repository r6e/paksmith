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
    // `build()` returns `Err` only if the platform cannot construct the menu
    // (e.g. no GTK display on a Linux headless runner).  In that case we log a
    // warning and continue without the native menu; the toolbar actions remain
    // reachable.  We must not panic here — a missing menu is non-fatal.
    let _menu = match menu::build() {
        Ok(m) => {
            #[cfg(target_os = "macos")]
            m.init_for_nsapp();
            Some(m)
        }
        Err(e) => {
            tracing::warn!("native menu unavailable, continuing without it: {e}");
            None
        }
    };

    iced::application(App::default, app::update, app::view)
        .title("Paksmith")
        .theme(|app: &App| theme::iced_theme(app.mode))
        .subscription(app::subscription)
        .run()
}
