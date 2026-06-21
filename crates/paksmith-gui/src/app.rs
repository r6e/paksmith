//! Top-level application state, messages, and the update/view cycle.

use std::path::PathBuf;

use iced::widget::{button, container, text};
use iced::{Element, Length, Task};

use crate::panels::key_prompt;
use crate::state::archive::{LoadedArchive, OpenError};
use crate::state::keyflow::KeyFlow;
use crate::theme;

/// Root application state.
pub struct App {
    /// Active appearance mode, detected from the OS at startup.
    pub mode: theme::Mode,
    /// The currently-open archive, if any.
    pub archive: Option<LoadedArchive>,
    /// Non-fatal error banner shown when an open attempt fails (non-Locked).
    pub error: Option<String>,
    /// Key-entry flow state machine (pure).
    pub keyflow: KeyFlow,
    /// Raw hex key text bound to the key-prompt input field.
    pub hex_input: String,
}

impl Default for App {
    fn default() -> Self {
        Self {
            mode: theme::detect_mode(),
            archive: None,
            error: None,
            keyflow: KeyFlow::Idle,
            hex_input: String::new(),
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
    /// The user edited the hex key input field.
    KeyInputChanged(String),
    /// The user pressed "Use key" in the key-prompt panel.
    KeySubmitted,
    /// The user pressed "Choose install dir…": `None` triggers the dir picker;
    /// `Some(path)` is the resolved directory after the picker closes.
    KeyDirChosen(Option<PathBuf>),
    /// Placeholder for the profile-selector overlay (Task 12).
    OpenProfilePicker,
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
            // Advance the flow to Resolving so the UI can respond.
            app.keyflow.begin(path.clone());
            Task::perform(crate::task::open::run(path), Message::ArchiveOpened)
        }
        Message::ArchiveOpened(Ok(loaded)) => {
            app.error = None;
            app.keyflow.unlock();
            app.archive = Some(loaded);
            Task::none()
        }
        Message::ArchiveOpened(Err(OpenError::Locked { path })) => {
            // Enter the key-entry flow: show the inline key-prompt panel.
            app.keyflow.lock(path);
            app.hex_input.clear();
            Task::none()
        }
        Message::ArchiveOpened(Err(OpenError::Core(msg))) => {
            if app.keyflow.is_locked().is_some() {
                // We're mid-key-flow (e.g. wrong manual key) — show the error
                // inside the panel, not as the global banner.
                app.keyflow.set_error(msg);
            } else {
                app.error = Some(msg);
            }
            Task::none()
        }
        Message::KeyInputChanged(s) => {
            app.hex_input = s;
            // Clear any previous key-attempt error when the user starts typing.
            app.keyflow.set_error(String::new());
            Task::none()
        }
        Message::KeySubmitted => {
            if app.hex_input.is_empty() {
                return Task::none();
            }
            match paksmith_core::AesKey::from_hex(&app.hex_input) {
                Err(parse_err) => {
                    // Bad hex — surface inline, no async round-trip needed.
                    app.keyflow.set_error(parse_err.to_string());
                    Task::none()
                }
                Ok(key) => {
                    // Good hex — try to re-open with the supplied key.
                    if let Some(path) = app.keyflow.is_locked().map(PathBuf::from) {
                        Task::perform(
                            crate::task::open::run_with_key(path, key),
                            Message::ArchiveOpened,
                        )
                    } else {
                        Task::none()
                    }
                }
            }
        }
        Message::KeyDirChosen(None) => {
            // Trigger the native dir-picker; the chosen path loops back as
            // `KeyDirChosen(Some(...))`.
            Task::perform(
                async {
                    rfd::AsyncFileDialog::new()
                        .pick_folder()
                        .await
                        .map(|h| h.path().to_path_buf())
                },
                Message::KeyDirChosen,
            )
        }
        Message::KeyDirChosen(Some(dir)) => {
            // Re-resolve with --detect pointing at the install directory.
            if let Some(path) = app.keyflow.is_locked().map(PathBuf::from) {
                Task::perform(
                    crate::task::open::run_with_detect(path, dir),
                    Message::ArchiveOpened,
                )
            } else {
                Task::none()
            }
        }
        Message::OpenProfilePicker => {
            // Task 12 will build the profile-selector overlay. No-op for now.
            Task::none()
        }
    }
}

/// Renders the current application state as a widget tree.
pub fn view(app: &App) -> Element<'_, Message> {
    // Show the key-prompt panel when locked, regardless of archive state.
    if app.keyflow.is_locked().is_some() {
        return container(key_prompt::view(&app.keyflow, &app.hex_input))
            .center_x(Length::Fill)
            .center_y(Length::Fill)
            .into();
    }

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
