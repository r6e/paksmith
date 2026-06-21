//! Top-level application state, messages, and the update/view cycle.

use std::path::PathBuf;

use iced::keyboard::Event as KeyboardEvent;
use iced::keyboard::key::Named;
use iced::widget::{button, column, container, pane_grid, text};
use iced::{Element, Event, Length, Subscription, Task};

use crate::panels::{detail, key_prompt, sidebar, status_bar, toolbar};
use crate::state::archive::{LoadedArchive, OpenError};
use crate::state::keyflow::KeyFlow;
use crate::state::profiles::{ProfileChoice, available};
use crate::theme;
use crate::theme::tokens::DIVIDER_GRAB_PX;
use crate::widgets::file_tree;

/// Which pane is which in the two-pane split.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaneKind {
    Sidebar,
    Detail,
}

/// Initial sidebar fraction of the pane_grid width.
const DEFAULT_SIDEBAR_RATIO: f32 = 0.30;

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
    /// Pane-grid state for the two-pane (sidebar | detail) split.
    ///
    /// `pane_grid` handles drag-resize correctly — the split tracks the cursor
    /// relative to the full row bounds, shows a horizontal-resize cursor on
    /// hover, and emits [`Message::PaneResized`] only while dragging.
    pub panes: pane_grid::State<PaneKind>,
    /// Live filter text (bound to the toolbar text input, forwarded to `tree.set_filter`).
    pub filter: String,
    /// Whether the About banner is currently visible.
    pub about_visible: bool,
    /// All profiles available in the toolbar selector (loaded at startup).
    pub profiles: Vec<ProfileChoice>,
    /// The currently selected game profile, if any.
    ///
    /// When `Some`, `task::open::run` passes the profile id to key resolution
    /// so encrypted paks for that game auto-unlock without a prompt.
    pub active_game: Option<ProfileChoice>,
}

impl Default for App {
    fn default() -> Self {
        // Build a left|right split at the default ratio: Sidebar on the left,
        // Detail on the right.  `Configuration::Split` with `Axis::Vertical`
        // produces a vertical divider bar between the two panes.
        let panes = pane_grid::State::with_configuration(pane_grid::Configuration::Split {
            axis: pane_grid::Axis::Vertical,
            ratio: DEFAULT_SIDEBAR_RATIO,
            a: Box::new(pane_grid::Configuration::Pane(PaneKind::Sidebar)),
            b: Box::new(pane_grid::Configuration::Pane(PaneKind::Detail)),
        });
        Self {
            mode: theme::detect_mode(),
            archive: None,
            error: None,
            keyflow: KeyFlow::Idle,
            hex_input: String::new(),
            accent: theme::accent::system_accent(),
            selected_row: None,
            panes,
            filter: String::new(),
            about_visible: false,
            profiles: available(),
            active_game: None,
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
    /// The user selected (or cleared) a game profile in the toolbar dropdown.
    ///
    /// `Some(choice)` selects that profile; `None` is emitted when the
    /// sentinel "Auto" entry is chosen, clearing the active game.
    GameSelected(Option<ProfileChoice>),
    /// A directory row was clicked — toggle expand/collapse.
    RowToggled(usize),
    /// A file row was clicked — update file selection.
    RowSelected(usize),
    /// A keyboard key was pressed while the archive is open.
    TreeKey(iced::keyboard::Key),
    /// The toolbar filter text changed.
    FilterChanged(String),
    /// The pane_grid resize handle was dragged; carries the new split ratio.
    PaneResized(pane_grid::ResizeEvent),
    /// Menu: toggle between light and dark appearance modes.
    ToggleTheme,
    /// Menu: show the About dialog / banner.
    About,
    /// Dismiss the About banner (always closes, never re-opens).
    DismissAbout,
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
            let game = app.active_game.as_ref().map(|c| c.id.clone());
            Task::perform(crate::task::open::run(path, game), |r| {
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
        Message::GameSelected(choice) => {
            app.active_game = choice;
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
        Message::PaneResized(event) => {
            // pane_grid computes the ratio from the cursor's position relative
            // to the full pane-grid bounds — no coordinate-space bug.
            app.panes.resize(event.split, event.ratio);
            Task::none()
        }
        Message::ToggleTheme => {
            app.mode = match app.mode {
                theme::Mode::Light => theme::Mode::Dark,
                theme::Mode::Dark => theme::Mode::Light,
            };
            Task::none()
        }
        Message::About => {
            app.about_visible = !app.about_visible;
            Task::none()
        }
        Message::DismissAbout => {
            app.about_visible = false;
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
/// [`Message::TreeKey`] while an archive is open, merged with the menu event
/// bridge that polls the `muda` global channel.
///
/// Subscribing the tree-key listener only when an archive is present avoids
/// capturing keys that belong to other panels (key-prompt text input, etc.).
///
/// Fix 2: uses [`iced::event::listen_with`] and filters at the subscription
/// boundary so that only `KeyPressed` events produce a message.  Key-release,
/// modifier-only, and all non-keyboard events produce `None` and are dropped
/// before the message queue — eliminating spurious `view` calls on every
/// key release.
pub fn subscription(app: &App) -> Subscription<Message> {
    let menu_sub = crate::menu::subscription();

    if app.archive.is_none() {
        return menu_sub;
    }

    let tree_key_sub = iced::event::listen_with(|event, _status, _window| {
        if let Event::Keyboard(KeyboardEvent::KeyPressed { key, .. }) = event {
            Some(Message::TreeKey(key))
        } else {
            None
        }
    });

    Subscription::batch([menu_sub, tree_key_sub])
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
///
/// The sidebar | detail split is managed by `iced::widget::pane_grid`, which
/// tracks drag-resize relative to the full pane-grid bounds (not the divider
/// strip), shows a horizontal-resize cursor on hover, and emits
/// [`Message::PaneResized`] only while dragging.
#[allow(clippy::too_many_lines)] // single match-all-states fn; splitting would obscure the layout
pub fn view(app: &App) -> Element<'_, Message> {
    use crate::theme::tokens::{SPACE_MD, SPACE_SM};

    // ── toolbar ───────────────────────────────────────────────────────────────
    let decrypted_flag = app.archive.as_ref().map(|a| a.decrypted);
    let toolbar_view = toolbar::view(
        decrypted_flag,
        &app.filter,
        &app.profiles,
        app.active_game.as_ref(),
    );

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
        // ── loaded state: two-pane layout via pane_grid ───────────────────────
        //
        // `pane_grid` tracks the split ratio relative to its own bounds, so
        // drag-resize is cursor-accurate regardless of cursor speed.  The
        // `.on_resize` wiring gives a horizontal-resize cursor on hover and
        // emits `Message::PaneResized` only during an active drag.
        let selected_meta = archive
            .tree
            .selected()
            .and_then(|path| archive.entries.get(path).map(|meta| (path, meta)));

        // Capture locals for the pane_grid closure (can't borrow `app` inside).
        let tree = &archive.tree;
        let accent = app.accent;
        let selected_row = app.selected_row;

        pane_grid(&app.panes, move |_pane, kind, _maximized| {
            let content: Element<'_, Message> = match kind {
                PaneKind::Sidebar => sidebar::view(tree, accent, selected_row),
                PaneKind::Detail => detail::view(selected_meta),
            };
            pane_grid::Content::new(content)
        })
        .on_resize(DIVIDER_GRAB_PX, Message::PaneResized)
        .width(Length::Fill)
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
        //
        // The "File → Open ⌘O" hint is shown only on macOS where the native
        // menu bar (and ⌘O accelerator) exist.  On other platforms the hint
        // is omitted because the File menu is not attached there yet.
        #[cfg(target_os = "macos")]
        let hint_text: Option<iced::widget::Text<'_, iced::Theme, iced::Renderer>> = Some(
            text("File \u{2192} Open  \u{2318}O")
                .size(f32::from(crate::theme::tokens::TEXT_SM))
                .style(|theme: &iced::Theme| iced::widget::text::Style {
                    color: Some(theme.palette().text.scale_alpha(0.40)),
                }),
        );
        #[cfg(not(target_os = "macos"))]
        let hint_text: Option<iced::widget::Text<'_, iced::Theme, iced::Renderer>> = None;

        let cta_text = text("Open a .pak file to begin exploring")
            .size(f32::from(crate::theme::tokens::TEXT_MD))
            .style(|theme: &iced::Theme| iced::widget::text::Style {
                color: Some(theme.palette().text.scale_alpha(0.55)),
            });

        let mut cta_col = column![
            button(text("Open\u{2026}").size(f32::from(crate::theme::tokens::TEXT_MD)))
                .style(iced::widget::button::primary)
                .padding([SPACE_SM, SPACE_MD])
                .on_press(Message::OpenRequested),
            cta_text,
        ]
        .spacing(SPACE_MD)
        .align_x(iced::Alignment::Center);

        if let Some(hint) = hint_text {
            cta_col = cta_col.push(hint);
        }

        container(cta_col)
            .center_x(Length::Fill)
            .center_y(Length::Fill)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    };

    // ── About panel (replaces content area when visible) ─────────────────────
    // When `app.about_visible` is true (Help → About Paksmith), the About panel
    // is rendered IN PLACE OF the main content area so it does not push the
    // pane-grid layout down.  On macOS the native menu bar sits above the iced
    // window so the panel appears inside the window body.
    //
    // The Dismiss button sends `Message::DismissAbout` — always closes, never
    // accidentally re-opens.
    let body: Element<'_, Message> = if app.about_visible {
        container(
            column![
                text(concat!("Paksmith  v", env!("CARGO_PKG_VERSION")))
                    .size(f32::from(crate::theme::tokens::TEXT_LG))
                    .style(|theme: &iced::Theme| iced::widget::text::Style {
                        color: Some(theme.palette().text),
                    }),
                text(concat!(
                    "Cross-platform explorer for Unreal Engine game assets.\n",
                    "Open source — MIT / Apache-2.0."
                ))
                .size(f32::from(crate::theme::tokens::TEXT_SM))
                .style(|theme: &iced::Theme| iced::widget::text::Style {
                    color: Some(theme.palette().text.scale_alpha(0.70)),
                }),
                button(text("Dismiss").size(f32::from(crate::theme::tokens::TEXT_SM)))
                    .style(iced::widget::button::secondary)
                    .padding([SPACE_SM, SPACE_MD])
                    .on_press(Message::DismissAbout),
            ]
            .spacing(SPACE_SM)
            .align_x(iced::Alignment::Center),
        )
        .style(|theme: &iced::Theme| {
            let palette = theme.extended_palette();
            iced::widget::container::Style {
                background: Some(iced::Background::Color(palette.background.weak.color)),
                ..Default::default()
            }
        })
        .padding(SPACE_MD)
        .center_x(Length::Fill)
        .center_y(Length::Fill)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
    } else {
        content_area
    };

    // ── compose ───────────────────────────────────────────────────────────────
    // The menu placeholder strip is removed: on macOS the native menu bar is
    // global (above the window); on other platforms the actions are toolbar-only.
    column![toolbar_view, body, status_view]
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use iced::keyboard::Key;
    use iced::keyboard::key::Named;

    use super::*;
    use crate::state::archive::{EntryMeta, LoadedArchive};
    use crate::state::tree::Tree;

    #[test]
    fn new_app_has_no_archive() {
        let app = App::default();
        assert!(app.archive.is_none());
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    /// Build a minimal `App` with a loaded archive whose tree is built from
    /// `paths` (forward-slash separated).  The archive has no real entries in
    /// the `entries` BTreeMap — keyboard-nav tests only need the tree rows.
    fn app_with_paths(paths: &[&str]) -> App {
        let path_strings: Vec<String> = paths.iter().map(ToString::to_string).collect();
        let tree = Tree::from_paths(path_strings);
        let mut entries = BTreeMap::new();
        for p in paths {
            let _ = entries.insert(
                (*p).to_string(),
                EntryMeta {
                    uncompressed_size: 0,
                    compressed_size: 0,
                    is_compressed: false,
                    is_encrypted: false,
                },
            );
        }
        let entry_count = paths.len();
        let archive = LoadedArchive {
            path: PathBuf::from("test.pak"),
            entry_count,
            decrypted: false,
            tree,
            entries,
        };
        App {
            archive: Some(archive),
            ..App::default()
        }
    }

    fn named_key(n: Named) -> Key {
        Key::Named(n)
    }

    // ── clamp_selected_row ────────────────────────────────────────────────────
    //
    // Survivors: `== with !=`, `>= with <`, `- 1 with + 1` in the clamp body.

    #[test]
    fn clamp_selected_row_empty_sets_none() {
        let mut sel = Some(5);
        clamp_selected_row(&mut sel, 0);
        assert_eq!(sel, None);
    }

    #[test]
    fn clamp_selected_row_in_bounds_unchanged() {
        // row_count=3, index=2 (last valid) — must stay 2, not clamp.
        let mut sel = Some(2);
        clamp_selected_row(&mut sel, 3);
        assert_eq!(sel, Some(2));
    }

    #[test]
    fn clamp_selected_row_exactly_at_row_count_clamps_to_last() {
        // `i >= row_count` triggers when i == row_count.  Result = row_count - 1.
        // The `- with +` mutant would set it to row_count + 1 (out of bounds).
        let mut sel = Some(5);
        clamp_selected_row(&mut sel, 5);
        assert_eq!(
            sel,
            Some(4),
            "out-of-bounds index must clamp to last valid row"
        );
    }

    #[test]
    fn clamp_selected_row_well_above_bounds_clamps() {
        let mut sel = Some(999);
        clamp_selected_row(&mut sel, 3);
        assert_eq!(sel, Some(2));
    }

    #[test]
    fn clamp_selected_row_none_stays_none() {
        // Starting from None with a non-empty list — None must stay None.
        // (The guard only fires for `Some(i)`, not `None`.)
        let mut sel: Option<usize> = None;
        clamp_selected_row(&mut sel, 3);
        assert_eq!(sel, None);
    }

    // ── handle_tree_key: ArrowDown ────────────────────────────────────────────
    //
    // Survivors: `+ 1 with - 1 / * 1`, `min` operator mutations, match-arm deletes.

    #[test]
    fn arrow_down_from_none_goes_to_row_0() {
        // paths: one top-level file
        let mut app = app_with_paths(&["file.txt"]);
        app.selected_row = None;
        let _ = handle_tree_key(&mut app, &named_key(Named::ArrowDown));
        assert_eq!(app.selected_row, Some(0));
    }

    #[test]
    fn arrow_down_increments_by_one() {
        let mut app = app_with_paths(&["Dir/a.txt", "Dir/b.txt"]);
        // Expand Dir so both files are visible.
        if let Some(ref mut a) = app.archive {
            a.tree.toggle(0); // expand Dir
        }
        app.selected_row = Some(1); // pointing at a.txt (row 1)
        let _ = handle_tree_key(&mut app, &named_key(Named::ArrowDown));
        // Should move to row 2 (b.txt).
        assert_eq!(app.selected_row, Some(2));
    }

    #[test]
    fn arrow_down_clamps_at_last_row() {
        // One file = one visible row (index 0).
        // Down from 0 must stay at 0, not go to 1.
        // The `+ 1` → `- 1` mutant would move to -1 (wrapping), or the min
        // would malfunction with a +/-/* replacement.
        let mut app = app_with_paths(&["only.txt"]);
        app.selected_row = Some(0);
        let _ = handle_tree_key(&mut app, &named_key(Named::ArrowDown));
        assert_eq!(
            app.selected_row,
            Some(0),
            "ArrowDown at last row must clamp, not overflow"
        );
    }

    // ── handle_tree_key: ArrowUp ──────────────────────────────────────────────

    #[test]
    fn arrow_up_from_middle_decrements() {
        let mut app = app_with_paths(&["Dir/a.txt", "Dir/b.txt"]);
        if let Some(ref mut a) = app.archive {
            a.tree.toggle(0);
        }
        app.selected_row = Some(2); // b.txt
        let _ = handle_tree_key(&mut app, &named_key(Named::ArrowUp));
        assert_eq!(app.selected_row, Some(1));
    }

    #[test]
    fn arrow_up_clamps_at_zero() {
        let mut app = app_with_paths(&["a.txt", "b.txt"]);
        app.selected_row = Some(0);
        let _ = handle_tree_key(&mut app, &named_key(Named::ArrowUp));
        assert_eq!(
            app.selected_row,
            Some(0),
            "ArrowUp at row 0 must clamp to 0"
        );
    }

    #[test]
    fn arrow_up_from_none_goes_to_row_0() {
        let mut app = app_with_paths(&["a.txt"]);
        app.selected_row = None;
        let _ = handle_tree_key(&mut app, &named_key(Named::ArrowUp));
        // ArrowUp from None falls into the `None | Some(0) => 0` arm.
        assert_eq!(app.selected_row, Some(0));
    }

    // ── handle_tree_key: ArrowRight / ArrowLeft ───────────────────────────────
    //
    // Survivors: `&&` / `!` guard mutants in the `should_expand` / `should_collapse` booleans.

    #[test]
    fn arrow_right_expands_collapsed_dir() {
        // paths build: Dir is row 0 (collapsed dir).
        let mut app = app_with_paths(&["Dir/file.txt"]);
        app.selected_row = Some(0); // Dir row
        let row_count_before = app.archive.as_ref().unwrap().tree.visible_rows().len();
        let _ = handle_tree_key(&mut app, &named_key(Named::ArrowRight));
        let row_count_after = app.archive.as_ref().unwrap().tree.visible_rows().len();
        assert!(
            row_count_after > row_count_before,
            "ArrowRight on a collapsed dir must expand it (row count increases)"
        );
    }

    #[test]
    fn arrow_right_on_expanded_dir_is_noop() {
        // Pre-expand the dir, then ArrowRight must NOT collapse it.
        let mut app = app_with_paths(&["Dir/file.txt"]);
        if let Some(ref mut a) = app.archive {
            a.tree.toggle(0); // expand Dir
        }
        app.selected_row = Some(0);
        let row_count_before = app.archive.as_ref().unwrap().tree.visible_rows().len();
        let _ = handle_tree_key(&mut app, &named_key(Named::ArrowRight));
        let row_count_after = app.archive.as_ref().unwrap().tree.visible_rows().len();
        assert_eq!(
            row_count_after, row_count_before,
            "ArrowRight on an already-expanded dir must be a no-op"
        );
    }

    #[test]
    fn arrow_left_collapses_expanded_dir() {
        let mut app = app_with_paths(&["Dir/file.txt"]);
        if let Some(ref mut a) = app.archive {
            a.tree.toggle(0);
        }
        app.selected_row = Some(0);
        let row_count_before = app.archive.as_ref().unwrap().tree.visible_rows().len();
        let _ = handle_tree_key(&mut app, &named_key(Named::ArrowLeft));
        let row_count_after = app.archive.as_ref().unwrap().tree.visible_rows().len();
        assert!(
            row_count_after < row_count_before,
            "ArrowLeft on an expanded dir must collapse it"
        );
    }

    #[test]
    fn arrow_left_on_collapsed_dir_is_noop() {
        let mut app = app_with_paths(&["Dir/file.txt"]);
        app.selected_row = Some(0);
        let row_count_before = app.archive.as_ref().unwrap().tree.visible_rows().len();
        let _ = handle_tree_key(&mut app, &named_key(Named::ArrowLeft));
        let row_count_after = app.archive.as_ref().unwrap().tree.visible_rows().len();
        assert_eq!(row_count_after, row_count_before);
    }

    // ── handle_tree_key: Enter ────────────────────────────────────────────────

    #[test]
    fn enter_on_dir_toggles_expand() {
        let mut app = app_with_paths(&["Dir/file.txt"]);
        app.selected_row = Some(0);
        let before = app.archive.as_ref().unwrap().tree.visible_rows().len();
        let _ = handle_tree_key(&mut app, &named_key(Named::Enter));
        let after = app.archive.as_ref().unwrap().tree.visible_rows().len();
        assert!(after > before, "Enter on a dir must expand it");
    }

    #[test]
    fn enter_on_file_selects_it() {
        let mut app = app_with_paths(&["file.txt"]);
        app.selected_row = Some(0);
        let _ = handle_tree_key(&mut app, &named_key(Named::Enter));
        assert_eq!(
            app.archive.as_ref().unwrap().tree.selected(),
            Some("file.txt")
        );
    }

    // ── Message::RowToggled / RowSelected OOB bounds ──────────────────────────
    //
    // Survivors: `i < row_count` replaced with `== / > / <=`.
    // These test that huge indices don't set selected_row to an invalid value.

    #[test]
    fn row_toggled_oob_does_not_set_selected_row() {
        let mut app = app_with_paths(&["Dir/file.txt"]);
        // row_count is 1 (only Dir visible); index 999 is OOB.
        let _ = update(&mut app, Message::RowToggled(999));
        // selected_row must not be set to 999.
        assert!(
            app.selected_row.is_none() || app.selected_row.unwrap() < 2,
            "RowToggled(OOB) must not set selected_row to an invalid index"
        );
    }

    #[test]
    fn row_selected_oob_does_not_set_selected_row() {
        let mut app = app_with_paths(&["file.txt"]);
        // row_count is 1; index 9999 is OOB.
        let _ = update(&mut app, Message::RowSelected(9999));
        // selected_row must not be 9999.
        assert!(
            app.selected_row.is_none() || app.selected_row.unwrap() < 2,
            "RowSelected(OOB) must not set selected_row to an invalid index"
        );
    }

    #[test]
    fn row_toggled_in_bounds_sets_selected_row() {
        let mut app = app_with_paths(&["Dir/file.txt"]);
        // row_count is 1 (only Dir); index 0 is valid.
        let _ = update(&mut app, Message::RowToggled(0));
        // The dir gets toggled AND selected_row is anchored to 0.
        assert_eq!(
            app.selected_row,
            Some(0),
            "RowToggled(0) must set selected_row to 0"
        );
    }

    #[test]
    fn row_selected_in_bounds_sets_selected_row() {
        let mut app = app_with_paths(&["file.txt"]);
        let _ = update(&mut app, Message::RowSelected(0));
        assert_eq!(app.selected_row, Some(0));
    }
}
