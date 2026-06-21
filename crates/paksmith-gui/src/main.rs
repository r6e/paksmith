//! Paksmith GUI — native-feeling explorer for Unreal Engine game assets.

mod app;
#[allow(dead_code)] // consumed by Tasks 7+; stub-phase only
mod state;
mod task;
mod theme;

use app::App;

fn main() -> iced::Result {
    iced::application(App::default, app::update, app::view)
        .title("Paksmith")
        .theme(|app: &App| theme::iced_theme(app.mode))
        .run()
}
