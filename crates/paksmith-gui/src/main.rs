//! Paksmith GUI — native-feeling explorer for Unreal Engine game assets.

mod app;
#[allow(dead_code)]
// Task 8: keyflow (Locked variant, decrypted field); Task 11: tree-view (Node fields, Tree methods)
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
