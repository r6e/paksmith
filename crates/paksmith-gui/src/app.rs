//! Top-level application state, messages, and the update/view cycle.

use iced::widget::{container, text};
use iced::{Element, Length, Task};

/// Root application state.
#[derive(Default)]
pub struct App {
    /// The currently-open archive, if any (populated in later tasks).
    // Stub field — replaced by `state::archive::LoadedArchive` in Task 7.
    #[allow(dead_code)]
    pub archive: Option<()>,
}

/// Every state transition flows through one of these.
#[derive(Debug, Clone)]
pub enum Message {
    /// Placeholder so the enum is non-empty until real messages land.
    // Dead until Task 5 adds the first real message variant.
    #[allow(dead_code)]
    Noop,
}

/// Processes a `Message` and updates the application state.
#[allow(clippy::needless_pass_by_value)] // iced's UpdateFn trait requires Message by value
pub fn update(_app: &mut App, message: Message) -> Task<Message> {
    match message {
        Message::Noop => Task::none(),
    }
}

/// Renders the current application state as a widget tree.
pub fn view(_app: &App) -> Element<'_, Message> {
    container(
        text("Open a .pak to begin")
            .size(16)
            .style(|theme: &iced::Theme| iced::widget::text::Style {
                color: Some(theme.palette().text.scale_alpha(0.55)),
            }),
    )
    .center_x(Length::Fill)
    .center_y(Length::Fill)
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_app_has_no_archive() {
        let app = App::default();
        assert!(app.archive.is_none());
    }
}
