//! Paksmith GUI — native-feeling explorer for Unreal Engine game assets.

mod app;
mod theme;

use app::App;

fn main() -> iced::Result {
    iced::application(App::default, app::update, app::view)
        .title("Paksmith")
        .theme(|app: &App| theme::iced_theme(app.mode))
        .run()
}
