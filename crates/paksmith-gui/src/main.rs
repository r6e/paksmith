//! Paksmith GUI — native-feeling explorer for Unreal Engine game assets.

mod app;

use app::App;

fn main() -> iced::Result {
    iced::application(App::default, app::update, app::view)
        .title("Paksmith")
        .theme(iced::Theme::Dark) // replaced by system light/dark in Task 4
        .run()
}
