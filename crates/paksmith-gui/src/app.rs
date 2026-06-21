//! Top-level application state, messages, and the update/view cycle.

use std::path::PathBuf;

use iced::keyboard::Event as KeyboardEvent;
use iced::keyboard::key::Named;
use iced::widget::{button, column, container, row, text};
use iced::{Element, Event, Length, Subscription, Task};

use crate::panels::{detail, key_prompt, sidebar, status_bar, toolbar};
use crate::state::archive::{LoadedArchive, OpenError};
use crate::state::keyflow::KeyFlow;
use crate::theme;
use crate::widgets::file_tree;

/// Default sidebar width as a fraction of the total two-pane row width.
const DEFAULT_SIDEBAR_RATIO: f32 = 0.32;

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
    /// Sidebar width as a fraction of the total two-pane row (0.0–1.0).
    pub sidebar_ratio: f32,
    /// Live filter text (bound to the toolbar text input, forwarded to `tree.set_filter`).
    pub filter: String,
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
            sidebar_ratio: DEFAULT_SIDEBAR_RATIO,
            filter: String::new(),
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
    ArchiveOpened(Box<Result<LoadedArchive, OpenError>>),
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
    /// The toolbar filter text changed.
    FilterChanged(String),
    /// The sidebar drag divider moved; carries the new sidebar ratio [0, 1].
    SidebarResized(f32),
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
            Task::perform(crate::task::open::run(path), |r| {
                Message::ArchiveOpened(Box::new(r))
            })
        }
        Message::ArchiveOpened(boxed) => match *boxed {
            Ok(loaded) => {
                app.error = None;
                app.keyflow.unlock();
                app.hex_input.clear();
                app.archive = Some(loaded);
                Task::none()
            }
            Err(OpenError::Locked { path }) => {
                // Enter the key-entry flow: show the inline key-prompt panel.
                app.keyflow.lock(path);
                app.hex_input.clear();
                Task::none()
            }
            Err(OpenError::Core(msg)) => {
                if app.keyflow.is_locked().is_some() {
                    // We're mid-key-flow (e.g. wrong manual key) — show the error
                    // inside the panel, not as the global banner.
                    app.keyflow.set_error(msg);
                } else {
                    app.error = Some(msg);
                }
                Task::none()
            }
        },
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
                        Task::perform(crate::task::open::run_with_key(path, key), |r| {
                            Message::ArchiveOpened(Box::new(r))
                        })
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
                Task::perform(crate::task::open::run_with_detect(path, dir), |r| {
                    Message::ArchiveOpened(Box::new(r))
                })
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
        Message::FilterChanged(query) => {
            app.filter.clone_from(&query);
            if let Some(archive) = &mut app.archive {
                archive.tree.set_filter(&query);
                // After filtering, the visible-row set changes; clamp the cursor.
                clamp_selected_row(&mut app.selected_row, archive.tree.visible_rows().len());
            }
            Task::none()
        }
        Message::SidebarResized(ratio) => {
            // Ratio is already clamped in `sidebar::view`'s `on_move` closure,
            // but clamp again here as defence in depth.
            app.sidebar_ratio = ratio.clamp(0.15, 0.65);
            Task::none()
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
/// ```text
/// ┌─────────────────────────────────────────┐
/// │  [menu placeholder — Task 11]           │
/// ├─────────────────────────────────────────┤
/// │  toolbar: [Open…] [pill] [filter…]      │
/// ├──────────────┬──────────────────────────┤
/// │              │                          │
/// │   sidebar    │   detail / empty state   │
/// │  (tree)      │                          │
/// │              │                          │
/// ├──────────────┴──────────────────────────┤
/// │  status bar                             │
/// └─────────────────────────────────────────┘
/// ```
#[allow(clippy::too_many_lines)] // single match-all-states fn; splitting would obscure the layout
pub fn view(app: &App) -> Element<'_, Message> {
    use crate::theme::tokens::{SPACE_MD, SPACE_SM};

    // ── toolbar ───────────────────────────────────────────────────────────────
    let decrypted_flag = app.archive.as_ref().map(|a| a.decrypted);
    let toolbar_view = toolbar::view(decrypted_flag, &app.filter);

    // ── status bar ────────────────────────────────────────────────────────────
    let (entry_count, archive_path, selected_name) = match &app.archive {
        None => (0usize, None, None),
        Some(a) => {
            // Extract the file name of the selected entry (last path segment).
            let sel_name = a.tree.selected().and_then(|p| p.rsplit('/').next());
            (a.entry_count, Some(a.path.as_path()), sel_name)
        }
    };
    let status_view = status_bar::view(archive_path, entry_count, selected_name);

    // ── main content area ─────────────────────────────────────────────────────
    let content_area: Element<'_, Message> = if app.keyflow.is_locked().is_some() {
        // Key-prompt replaces the whole content area (sidebar + detail).
        container(key_prompt::view(&app.keyflow, &app.hex_input))
            .center_x(Length::Fill)
            .center_y(Length::Fill)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    } else if let Some(archive) = &app.archive {
        // ── loaded state: two-pane layout ─────────────────────────────────────
        let selected_meta = archive
            .tree
            .selected()
            .and_then(|path| archive.entries.get(path).map(|meta| (path, meta)));
        let detail_view = detail::view(selected_meta);

        // Sidebar takes `sidebar_ratio` of the available width; detail fills the rest.
        // The drag divider is embedded inside `sidebar::view` and emits
        // `Message::SidebarResized`.
        let sidebar_view = sidebar::view(&archive.tree, app.accent, app.selected_row);

        let detail_container = container(detail_view)
            .width(Length::Fill)
            .height(Length::Fill);

        // sidebar_view already includes the divider; detail fills the rest.
        row![
            container(sidebar_view)
                .width(Length::FillPortion(
                    // Convert ratio to an integer fill portion (out of 1000).
                    // This is the standard iced approach for proportional widths
                    // without knowing the exact pixel count.
                    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                    {
                        (app.sidebar_ratio * 1000.0) as u16
                    }
                ))
                .height(Length::Fill),
            detail_container.width(Length::FillPortion(
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                {
                    ((1.0 - app.sidebar_ratio) * 1000.0) as u16
                }
            )),
        ]
        .height(Length::Fill)
        .into()
    } else if let Some(err) = &app.error {
        // ── error state: full-area error banner + retry ────────────────────────
        // Use extended_palette danger text for legibility in both themes.
        let err_text = text(format!("Error: {err}"))
            .size(f32::from(crate::theme::tokens::TEXT_MD))
            .style(|theme: &iced::Theme| iced::widget::text::Style {
                color: Some(theme.extended_palette().danger.base.text),
            });
        container(
            column![
                err_text,
                button(text("Open\u{2026}").size(f32::from(crate::theme::tokens::TEXT_MD)))
                    .style(iced::widget::button::primary)
                    .padding([SPACE_SM, SPACE_MD])
                    .on_press(Message::OpenRequested),
            ]
            .spacing(SPACE_MD)
            .align_x(iced::Alignment::Center),
        )
        .center_x(Length::Fill)
        .center_y(Length::Fill)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
    } else {
        // ── empty state: actionable CTA ────────────────────────────────────────
        // Forward-requirement from T3: primary action must be an Open button.
        let cta_text = text("Open a .pak file to begin exploring")
            .size(f32::from(crate::theme::tokens::TEXT_MD))
            .style(|theme: &iced::Theme| iced::widget::text::Style {
                color: Some(theme.palette().text.scale_alpha(0.55)),
            });
        let hint_text = text("File \u{2192} Open  \u{2318}O")
            .size(f32::from(crate::theme::tokens::TEXT_SM))
            .style(|theme: &iced::Theme| iced::widget::text::Style {
                color: Some(theme.palette().text.scale_alpha(0.40)),
            });
        container(
            column![
                button(text("Open\u{2026}").size(f32::from(crate::theme::tokens::TEXT_MD)))
                    .style(iced::widget::button::primary)
                    .padding([SPACE_SM, SPACE_MD])
                    .on_press(Message::OpenRequested),
                cta_text,
                hint_text,
            ]
            .spacing(SPACE_MD)
            .align_x(iced::Alignment::Center),
        )
        .center_x(Length::Fill)
        .center_y(Length::Fill)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
    };

    // ── menu placeholder (Task 11) ────────────────────────────────────────────
    // A thin reserved strip; the actual menu bar lands in Task 11.
    let menu_placeholder = container(
        text("") // empty; Task 11 will replace this
            .size(f32::from(crate::theme::tokens::TEXT_SM)),
    )
    .style(|theme: &iced::Theme| {
        let palette = theme.extended_palette();
        iced::widget::container::Style {
            background: Some(iced::Background::Color(palette.background.weak.color)),
            ..Default::default()
        }
    })
    .width(Length::Fill)
    .height(Length::Fixed(0.0)); // zero-height until Task 11 fills it

    // ── compose ───────────────────────────────────────────────────────────────
    column![menu_placeholder, toolbar_view, content_area, status_view,]
        .width(Length::Fill)
        .height(Length::Fill)
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
