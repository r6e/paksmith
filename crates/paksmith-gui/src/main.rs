//! Paksmith GUI — native-feeling explorer for Unreal Engine game assets.

mod app;
mod menu;
mod panels;
// The `state` module exposes tree/keyflow/archive/profile types.  Some public
// methods and fields (e.g. `Tree::len`, `Tree::is_empty`, `VisibleRow::full_path`,
// `KeyFlow::error`) are used in tests or are Phase 7+ entry-points; clippy's
// dead_code lint fires on them in the binary target but they're intentionally
// kept for that use.
#[allow(dead_code)]
mod state;
mod task;
mod theme;
mod widgets;

use app::App;

// Binary entry point: installs the tracing subscriber, builds the native menu,
// and runs the iced event loop — none of which is unit-testable (no test can
// drive `iced::application().run()`). The one bit of real logic, sharing the
// log buffer into the app, is extracted to the tested `app::boot_app`.
#[mutants::skip]
fn main() -> iced::Result {
    // Capture tracing events into a bounded ring for the in-app debug console.
    // Install before building the menu so the menu-build path's own warnings
    // are captured. `try_init` (inside) is a no-op if a subscriber already
    // exists.
    let log_buffer = state::log_buffer::LogBuffer::default();
    state::log_buffer::init_console_tracing(log_buffer.clone());

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

    iced::application(
        move || app::boot_app(log_buffer.clone()),
        app::update,
        app::view,
    )
    .title("Paksmith")
    .theme(|app: &App| theme::iced_theme(app.mode))
    .subscription(app::subscription)
    .run()
}
