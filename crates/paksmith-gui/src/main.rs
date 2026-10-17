//! Paksmith GUI — native-feeling explorer for Unreal Engine game assets.

mod app;
// The one place that touches `rodio`. Every `AudioOutput` method is now live on
// the playback path (`app.rs`), so no dead-code suppression is needed here — a
// module-wide `#[allow(dead_code)]` would only mask a future genuinely-unused
// item inside the seam.
mod audio_output;
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

// Binary entry point: installs the tracing subscriber and runs the iced event
// loop, neither of which is unit-testable (no test can drive
// `iced::application().run()`). The real logic — sharing the log buffer into
// the app, seeding the appearance and accent reads taken here on the main
// thread, and queuing the native-menu install — is in the tested
// `app::boot_app`.
#[mutants::skip]
fn main() -> iced::Result {
    // Capture tracing events into a bounded ring for the in-app debug console.
    // `try_init` (inside) is a no-op if a subscriber already exists.
    let log_buffer = state::log_buffer::LogBuffer::default();
    state::log_buffer::init_console_tracing(log_buffer.clone());

    // Read here, on the main thread, before iced takes it: mundy's macOS
    // backend requires it and the value has to exist before the first
    // window is themed.
    let appearance = theme::startup_reading();
    let accent = theme::accent::system_accent();

    iced::application(
        move || app::boot_app(log_buffer.clone(), appearance, accent),
        app::update,
        app::view,
    )
    .title("Paksmith")
    .theme(|app: &App| theme::iced_theme(app.mode))
    .subscription(app::subscription)
    .run()
}
