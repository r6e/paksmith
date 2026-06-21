//! Top-level application state, messages, and the update/view cycle.

use std::path::PathBuf;

use iced::widget::{button, container, text};
use iced::{Element, Length, Task};

use crate::state::archive::{LoadedArchive, OpenError};
use crate::theme;

/// Root application state.
pub struct App {
    /// Active appearance mode, detected from the OS at startup.
    pub mode: theme::Mode,
    /// The currently-open archive, if any.
    pub archive: Option<LoadedArchive>,
    /// Non-fatal error banner shown when an open attempt fails.
    pub error: Option<String>,
}

impl Default for App {
    fn default() -> Self {
        Self {
            mode: theme::detect_mode(),
            archive: None,
            error: None,
        }
    }
}

/// Every state transition flows through one of these.
#[derive(Debug, Clone)]
pub enum Message {
    /// The user triggered the "open file" action (e.g. via a button or menu item).
    OpenRequested,
    /// The native file picker resolved to a path (or was cancelled → `None`).
    OpenPathChosen(Option<PathBuf>),
    /// The async open pipeline completed with either a loaded archive or an error.
    ArchiveOpened(Result<LoadedArchive, OpenError>),
}

/// Processes a `Message` and updates the application state.
#[allow(clippy::needless_pass_by_value)] // iced's UpdateFn trait requires Message by value
pub fn update(app: &mut App, message: Message) -> Task<Message> {
    match message {
        Message::OpenRequested => {
            // Spawn the native file picker as an async task.
            Task::perform(
                async {
                    rfd::AsyncFileDialog::new()
                        .add_filter("Unreal pak", &["pak"])
                        .pick_file()
                        .await
                        .map(|h| h.path().to_path_buf())
                },
                Message::OpenPathChosen,
            )
        }
        Message::OpenPathChosen(None) => {
            // User cancelled the dialog — nothing to do.
            Task::none()
        }
        Message::OpenPathChosen(Some(path)) => {
            // Drive the async open pipeline.
            Task::perform(crate::task::open::run(path), Message::ArchiveOpened)
        }
        Message::ArchiveOpened(Ok(loaded)) => {
            app.error = None;
            app.archive = Some(loaded);
            Task::none()
        }
        Message::ArchiveOpened(Err(OpenError::Locked { path })) => {
            // Task 8 will handle the key-entry flow. For now, surface as an error.
            app.error = Some(format!(
                "Pak is encrypted and no key was found: {}",
                path.display()
            ));
            Task::none()
        }
        Message::ArchiveOpened(Err(OpenError::Core(msg))) => {
            app.error = Some(msg);
            Task::none()
        }
    }
}

/// Renders the current application state as a widget tree.
pub fn view(app: &App) -> Element<'_, Message> {
    let body: Element<'_, Message> = if let Some(archive) = &app.archive {
        text(format!(
            "{} — {} entries",
            archive.path.display(),
            archive.entry_count
        ))
        .size(16)
        .style(|theme: &iced::Theme| iced::widget::text::Style {
            color: Some(theme.palette().text),
        })
        .into()
    } else if let Some(err) = &app.error {
        text(format!("Error: {err}"))
            .size(16)
            .style(|theme: &iced::Theme| iced::widget::text::Style {
                color: Some(theme.palette().danger),
            })
            .into()
    } else {
        text("Open a .pak to begin")
            .size(16)
            .style(|theme: &iced::Theme| iced::widget::text::Style {
                color: Some(theme.palette().text.scale_alpha(0.55)),
            })
            .into()
    };

    container(
        iced::widget::column![button("Open…").on_press(Message::OpenRequested), body,].spacing(12),
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
