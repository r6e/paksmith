//! Top-level application state, messages, and the update/view cycle.

use std::path::PathBuf;

use iced::keyboard::Event as KeyboardEvent;
use iced::keyboard::key::Named;
use iced::widget::{button, container, text};
use iced::{Element, Event, Length, Subscription, Task};

use crate::panels::key_prompt;
use crate::state::archive::{LoadedArchive, OpenError};
use crate::state::keyflow::KeyFlow;
use crate::theme;
use crate::widgets::file_tree;

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
    /// System accent color (read once at startup from the OS).
    pub accent: iced::Color,
    /// Keyboard cursor within the visible-row list.
    ///
    /// Distinct from `tree.selected()` (which is the committed file selection):
    /// this cursor can sit on both dirs and files and moves with Up/Down/Left/Right.
    pub selected_row: Option<usize>,
}

impl Default for App {
    fn default() -> Self {
        Self {
            mode: theme::detect_mode(),
            archive: None,
            error: None,
            keyflow: KeyFlow::Idle,
            hex_input: String::new(),
            accent: theme::accent::system_accent(),
            selected_row: None,
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
    #[allow(dead_code)]
    OpenProfilePicker,
    /// A directory row was clicked — toggle expand/collapse.
    RowToggled(usize),
    /// A file row was clicked — update file selection.
    RowSelected(usize),
    /// A keyboard key was pressed while the archive is open.
    TreeKey(iced::keyboard::Key),
}

/// Processes a `Message` and updates the application state.
#[allow(clippy::needless_pass_by_value)] // iced's UpdateFn trait requires Message by value
#[allow(clippy::too_many_lines)] // single-match-all-messages fn; splitting would obscure the shape
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
            app.keyflow.begin();
            Task::perform(crate::task::open::run(path), Message::ArchiveOpened)
        }
        Message::ArchiveOpened(Ok(loaded)) => {
            app.error = None;
            app.keyflow.unlock();
            app.hex_input.clear();
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
            app.keyflow.clear_error();
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
        Message::RowToggled(i) => {
            if let Some(archive) = &mut app.archive {
                archive.tree.toggle(i);
                // After a toggle the row count may have changed; clamp the
                // cursor to remain in bounds.
                clamp_selected_row(&mut app.selected_row, archive.tree.visible_rows().len());
                // Fix 7: clicking a dir also anchors the keyboard cursor there.
                let row_count = archive.tree.visible_rows().len();
                if i < row_count {
                    app.selected_row = Some(i);
                }
            }
            Task::none()
        }
        Message::RowSelected(i) => {
            if let Some(archive) = &mut app.archive {
                archive.tree.select(i);
                // Move the keyboard cursor to the selected file.
                let row_count = archive.tree.visible_rows().len();
                if i < row_count {
                    app.selected_row = Some(i);
                }
            }
            Task::none()
        }
        Message::TreeKey(ref key) => {
            let scroll_task = handle_tree_key(app, key);
            scroll_task.unwrap_or_else(Task::none)
        }
    }
}

/// Move the keyboard cursor and mutate the tree based on a key press.
///
/// Returns a scroll [`Task`] when `selected_row` changed and the caller
/// should attempt to bring the new cursor row into view, or `None` otherwise.
fn handle_tree_key(app: &mut App, key: &iced::keyboard::Key) -> Option<Task<Message>> {
    let archive = app.archive.as_mut()?;
    let row_count = archive.tree.visible_rows().len();
    if row_count == 0 {
        return None;
    }

    let iced::keyboard::Key::Named(named) = key else {
        return None;
    };
    let named = *named;

    let prev_selected = app.selected_row;

    match named {
        Named::ArrowDown => {
            let next = match app.selected_row {
                None => 0,
                Some(i) => (i + 1).min(row_count - 1),
            };
            app.selected_row = Some(next);
        }
        Named::ArrowUp => {
            let prev = match app.selected_row {
                None | Some(0) => 0,
                Some(i) => i - 1,
            };
            app.selected_row = Some(prev);
        }
        Named::ArrowRight => {
            // Fix 1: expand only when the dir is currently COLLAPSED.
            // Calling toggle() on an already-expanded dir would collapse it,
            // which is the wrong behaviour for ArrowRight.
            if let Some(i) = app.selected_row {
                let should_expand = archive
                    .tree
                    .visible_rows()
                    .get(i)
                    .is_some_and(|r| r.is_dir && !r.expanded);
                if should_expand {
                    archive.tree.toggle(i);
                    clamp_selected_row(&mut app.selected_row, archive.tree.visible_rows().len());
                }
            }
        }
        Named::ArrowLeft => {
            // Collapse the dir under the cursor (no-op on files or already
            // collapsed).
            if let Some(i) = app.selected_row {
                let should_collapse = archive
                    .tree
                    .visible_rows()
                    .get(i)
                    .is_some_and(|r| r.is_dir && r.expanded);
                if should_collapse {
                    archive.tree.toggle(i);
                    clamp_selected_row(&mut app.selected_row, archive.tree.visible_rows().len());
                }
            }
        }
        Named::Enter => {
            if let Some(i) = app.selected_row {
                let row = archive.tree.visible_rows().get(i).cloned();
                if let Some(row) = row {
                    if row.is_dir {
                        archive.tree.toggle(i);
                        clamp_selected_row(
                            &mut app.selected_row,
                            archive.tree.visible_rows().len(),
                        );
                    } else {
                        archive.tree.select(i);
                    }
                }
            }
        }
        _ => {}
    }

    // Fix 8: if selected_row changed, scroll it into view.
    //
    // Row height estimate: TEXT_MD (px) + 2 × SPACE_XS (vertical padding).
    // This is an approximation — iced's actual rendered height may include
    // fractional sub-pixel rounding — so the scroll target drifts slightly on
    // very long lists.  The proportional `snap_to` variant would avoid drift
    // but requires knowing the total scrollable content height, which isn't
    // available here.  Absolute-offset is the simpler choice; the drift is
    // acceptable (the cursor stays within ±1 row of the viewport edge).
    // Two-guard form: avoids let-chains (`&&let`) which require Rust > 1.88.
    #[allow(clippy::collapsible_if)]
    if app.selected_row != prev_selected {
        if let Some(row_idx) = app.selected_row {
            use crate::theme::tokens;
            let row_height = f32::from(tokens::TEXT_MD) + 2.0 * tokens::SPACE_XS;
            #[allow(clippy::cast_precision_loss)]
            let target_y = row_idx as f32 * row_height;
            let task = iced::widget::operation::scroll_to(
                file_tree::TREE_SCROLL_ID.clone(),
                iced::widget::scrollable::AbsoluteOffset {
                    x: 0.0,
                    y: target_y,
                },
            );
            return Some(task);
        }
    }

    None
}

/// Clamp `selected_row` so it stays within `[0, row_count)`.
/// Sets to `None` when `row_count` is 0.
fn clamp_selected_row(selected_row: &mut Option<usize>, row_count: usize) {
    if row_count == 0 {
        *selected_row = None;
        return;
    }
    // Two-guard form kept intentionally: the collapsed form uses let-chains
    // (`if let Some(i) = ... && i >= ...`) which triggered MSRV failures
    // in CI on 1.88 in prior phases.
    #[allow(clippy::collapsible_if)]
    if let Some(i) = *selected_row {
        if i >= row_count {
            *selected_row = Some(row_count - 1);
        }
    }
}

/// Returns a [`Subscription`] that converts keyboard key-press events into
/// [`Message::TreeKey`] while an archive is open.
///
/// Subscribing only when an archive is present avoids capturing keys that
/// belong to other panels (key-prompt text input, etc.).
///
/// Fix 2: uses [`iced::event::listen_with`] and filters at the subscription
/// boundary so that only `KeyPressed` events produce a message.  Key-release,
/// modifier-only, and all non-keyboard events produce `None` and are dropped
/// before the message queue — eliminating spurious `view` calls on every
/// key release.
pub fn subscription(app: &App) -> Subscription<Message> {
    if app.archive.is_none() {
        return Subscription::none();
    }
    iced::event::listen_with(|event, _status, _window| {
        if let Event::Keyboard(KeyboardEvent::KeyPressed { key, .. }) = event {
            Some(Message::TreeKey(key))
        } else {
            None
        }
    })
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

    if let Some(archive) = &app.archive {
        let header = text(format!(
            "{} — {} entries",
            archive.path.display(),
            archive.entry_count
        ))
        .size(14)
        .style(|theme: &iced::Theme| iced::widget::text::Style {
            color: Some(theme.palette().text.scale_alpha(0.7)),
        });

        let tree_view = file_tree::view(&archive.tree, app.accent, app.selected_row);

        iced::widget::column![
            iced::widget::row![button("Open…").on_press(Message::OpenRequested), header,]
                .spacing(12)
                .align_y(iced::Alignment::Center),
            tree_view,
        ]
        .spacing(8)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
    } else {
        let body: Element<'_, Message> = if let Some(err) = &app.error {
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
            iced::widget::column![button("Open…").on_press(Message::OpenRequested), body,]
                .spacing(12),
        )
        .center_x(Length::Fill)
        .center_y(Length::Fill)
        .into()
    }
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
