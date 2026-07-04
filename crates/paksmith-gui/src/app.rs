//! Top-level application state, messages, and the update/view cycle.

use std::path::PathBuf;

use iced::keyboard::Event as KeyboardEvent;
use iced::keyboard::key::Named;
use iced::widget::{button, column, container, pane_grid, text};
use iced::{Element, Event, Length, Subscription, Task};
use zeroize::Zeroizing;

use crate::audio_output::AudioOutput;
use crate::panels::{content, key_prompt, sidebar, status_bar, toolbar};
use crate::state::archive::{LoadedArchive, OpenError};
use crate::state::keyflow::KeyFlow;
use crate::state::profiles::{ProfileChoice, available};
use crate::theme;
use crate::theme::tokens::{DIVIDER_GRAB_PX, TEXT_MUTED_ALPHA, TEXT_XL};
use crate::widgets::file_tree;

/// Which pane is which in the two-pane split.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaneKind {
    Sidebar,
    Detail,
}

/// Initial sidebar fraction of the pane_grid width.
const DEFAULT_SIDEBAR_RATIO: f32 = 0.30;

/// Console refresh cadence while logs are actively arriving. Fast enough that
/// a live tail feels responsive during an open/decode operation.
const CONSOLE_TICK_FAST_MS: u64 = 250;
/// Console refresh cadence once the ring has been stable for a tick. The
/// visible-console poll still rebuilds the view each tick (iced re-views on
/// every message), so when nothing is arriving we space those rebuilds out to
/// cut idle CPU — at the cost of up to this much latency on the first new
/// record after an idle spell.
const CONSOLE_TICK_SLOW_MS: u64 = 1000;

/// Number of `(min, max)` amplitude columns in the audio waveform overview.
/// Matches the bucket count passed to
/// [`crate::state::audio_view::compute_waveform`] on each decode completion.
const WAVEFORM_COLUMNS: usize = 512;

/// Root application state.
// Three of the bools are independent UI toggles (panel visibility, tail-follow,
// about dialog); `console_active` is a cached refresh-cadence signal paired with
// `console_last_pushes`. None form a state machine the heuristic could model, so
// the pedantic bool-count lint is a false positive here.
#[allow(clippy::struct_excessive_bools)]
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
    ///
    /// Wrapped in [`Zeroizing`] so the AES key material is cleared on drop
    /// (e.g. when the archive is swapped or the app exits).
    pub hex_input: Zeroizing<String>,
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
    /// Open asset tabs in the content host.
    pub tabs: crate::state::tabs::Tabs,
    /// Monotonic counter bumped on every archive transition (tab clear). An async
    /// asset load captures the generation at dispatch; a late `AssetLoaded` whose
    /// generation no longer matches the current archive is ignored — prevents a
    /// stale load from the previous archive populating a new archive's tab.
    pub archive_generation: u64,
    /// Live transient notifications (errors + action feedback), rendered as a
    /// non-blocking overlay. See [`crate::state::toast`].
    pub toasts: crate::state::toast::Toasts,
    /// Visible-row index whose inline context-menu strip (Open / Copy Path /
    /// Export As…) is currently shown, or `None`. A *visible-row* index like
    /// [`App::selected_row`]; cleared on every tree-mutating or selection path
    /// so a stale index can never address the wrong row.
    pub context_row: Option<usize>,
    /// The open Export As… format picker, if any. Path-keyed; rendered beneath
    /// the current `context_row`. `None` ⇒ the action strip (or nothing) shows.
    pub export_menu: Option<crate::state::export::ExportMenu>,
    /// Whether the debug-console panel is shown (toggled by F12 / View menu).
    pub console_visible: bool,
    /// Shared ring of captured `tracing` events feeding the debug console.
    /// Injected at boot from `main`; `Default` yields an empty, unshared buffer.
    pub log_buffer: crate::state::log_buffer::LogBuffer,
    /// Whether the console auto-scrolls to the newest line. Set on open/clear;
    /// cleared when the user scrolls up away from the bottom.
    pub console_follow: bool,
    /// Active debug-console filter predicates (min level / target / search).
    pub console_filters: crate::state::console::ConsoleFilters,
    /// True when the last console tick saw the ring grow. Drives the adaptive
    /// refresh interval: fast while logs flow, slow once the buffer is stable.
    pub console_active: bool,
    /// `LogBuffer::total_pushed` observed at the last console tick (or on open).
    /// The tick compares against this to decide `console_active`.
    pub console_last_pushes: u64,
    /// Audio-output backend for the Phase 7d audio player, opened lazily.
    ///
    /// `None` until a device is opened (or if no device is available). Holding
    /// the `!Send` [`AudioOutput`] directly on `App` is sound because iced 0.14
    /// keeps application state on the main thread — see `audio_output`'s module
    /// docs for the placement rationale.
    pub audio: Option<AudioOutput>,
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
            hex_input: Zeroizing::new(String::new()),
            accent: theme::accent::system_accent(),
            selected_row: None,
            panes,
            filter: String::new(),
            about_visible: false,
            profiles: available(),
            active_game: None,
            tabs: crate::state::tabs::Tabs::default(),
            archive_generation: 0,
            toasts: crate::state::toast::Toasts::default(),
            context_row: None,
            export_menu: None,
            console_visible: false,
            log_buffer: crate::state::log_buffer::LogBuffer::default(),
            console_follow: true,
            console_filters: crate::state::console::ConsoleFilters::default(),
            console_active: false,
            console_last_pushes: 0,
            // Opened lazily when the audio player first needs it (later Phase 7d
            // task); `None` keeps `App::default()` — used throughout the tests —
            // free of any real audio-device side effect.
            audio: None,
        }
    }
}

/// Build the initial [`App`], injecting the shared debug-console
/// [`LogBuffer`](crate::state::log_buffer::LogBuffer).
///
/// `main` installs the tracing subscriber over one `LogBuffer` clone, then hands
/// another clone here so the running app reads the same `Arc`-backed ring the
/// subscriber writes to. Extracted from `main`'s boot closure so the
/// buffer-sharing (load-bearing: drop it and the console is permanently empty)
/// is unit-testable rather than buried in the untestable entry point.
pub fn boot_app(log_buffer: crate::state::log_buffer::LogBuffer) -> App {
    App {
        log_buffer,
        ..App::default()
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
    /// Open (or re-activate) an asset tab for the given entry path.
    OpenAsset(String),
    /// The async asset-load task completed.
    AssetLoaded {
        /// Entry path identifying which tab to populate.
        path: String,
        /// Boxed to keep `Message: Clone` via a `Box<AssetLoad>` (which is
        /// `Clone` because `AssetLoad: Clone`).
        load: Box<crate::task::asset::AssetLoad>,
        /// The archive generation at the time the load was dispatched. If this
        /// does not match `app.archive_generation` when the message is received,
        /// the result belongs to a previous archive and is discarded.
        generation: u64,
    },
    /// Switch the active tab.
    TabActivated(usize),
    /// Close the tab at the given index.
    TabClosed(usize),
    /// Change the view mode of the active tab.
    ViewModeSet(crate::state::tabs::ViewMode),
    /// Mouse pressed on byte at index `i` in the hex view — starts a drag-select.
    HexBytePressed(usize),
    /// Mouse entered byte at index `i` in the hex view — extends drag if dragging.
    HexByteEntered(usize),
    /// Left mouse button released (global) — ends any in-progress hex drag.
    HexDragEnded,
    /// Copy the selected bytes as uppercase hex to the clipboard.
    HexCopyRequested,
    /// Copy the selected bytes as ASCII (non-printable → `'.'`) to the clipboard.
    HexCopyAsciiRequested,
    /// Toggle expand/collapse of a property-tree node in the active tab.
    PropToggled(crate::state::property_view::NodeId),
    /// A file row was double-clicked (carries the visible-row index, not the path,
    /// so the per-frame view doesn't clone a path String for every file row).
    OpenAssetByRow(usize),
    /// An async texture decode task completed.
    TextureDecoded {
        /// Entry path identifying which tab holds this decode result.
        path: String,
        /// The mip level that was decoded.
        mip: usize,
        /// The decoded RGBA data or a stringified error.
        result: Result<crate::state::texture_view::DecodedMip, String>,
        /// The archive generation at the time the decode was dispatched.
        /// Results from a previous generation are silently dropped.
        generation: u64,
    },
    /// An async audio decode task completed.
    AudioDecoded {
        /// Entry path identifying which tab holds this decode result.
        path: String,
        /// The decoded PCM data or a stringified error.
        result: Result<crate::state::audio_view::DecodedAudio, String>,
        /// The archive generation at the time the decode was dispatched.
        /// Results from a previous generation are silently dropped.
        generation: u64,
    },
    /// Toggle play/pause for the active tab's audio.
    // Constructed by the audio-player widget (later Phase 7d task).
    #[allow(dead_code)]
    AudioPlayPause,
    /// Stop the active tab's audio and reset the playhead to zero.
    // Constructed by the audio-player widget (later Phase 7d task).
    #[allow(dead_code)]
    AudioStop,
    /// Set the active tab's audio volume (`0.0`–`1.0`; clamped by `AudioState`).
    // Constructed by the audio-player widget (later Phase 7d task).
    #[allow(dead_code)]
    AudioVolume(f32),
    /// Periodic tick while audio is playing: advance the displayed playhead
    /// and detect playback completion.
    AudioTick,
    /// A texture channel was toggled on/off in the active tab.
    TextureChannelToggled {
        channel: crate::state::texture_view::Channel,
    },
    /// Zoom the active tab's texture viewer in one step.
    TextureZoomIn,
    /// Zoom the active tab's texture viewer out one step.
    TextureZoomOut,
    /// Fit the texture to the available viewport in the active tab.
    TextureFitToWindow,
    /// The user selected a different mip level in the active tab.
    TextureMipSelected(usize),
    /// Remove the toast with this id — used by both the `×` button and the
    /// scheduled auto-expiry task.
    ToastDismissed(u64),
    /// A file row was right-clicked — toggle its inline context-menu strip.
    /// Carries the *visible-row* index (no coordinates: `on_right_press` gives
    /// none, and the inline strip needs none).
    RowContextOpened(usize),
    /// Copy the path of the file at the given visible-row index to the clipboard.
    /// The path is resolved in `update` via `open_path_for_row` so the per-frame
    /// view never clones a path String.
    CopyPathRequested(usize),
    /// Right-clicked row chose "Export As…": open the format picker for the file
    /// at this visible-row index.
    ExportAsRequested(usize),
    /// Async format enumeration for a cold (unopened) entry resolved.
    ExportFormatsReady {
        path: String,
        formats: Vec<paksmith_core::export::ExportFormat>,
        generation: u64,
    },
    /// Cancel in the picker: return to the action strip.
    ExportMenuCancelled,
    /// A picker format was chosen: open the save dialog + export.
    ExportChoiceSelected {
        path: String,
        choice: crate::state::export::ExportChoice,
    },
    /// Export run finished (or was cancelled).
    ExportCompleted {
        outcome: crate::task::export::ExportOutcome,
        generation: u64,
    },
    /// Toggle the debug-console panel (F12 or the View menu).
    ConsoleToggled,
    /// Periodic tick while the console is visible, so freshly captured records
    /// render without requiring other UI activity.
    ConsoleTick,
    /// The console scroll position changed; carries the relative vertical
    /// offset (0.0 = top, 1.0 = bottom) so the follow decision is testable
    /// without constructing a non-public `scrollable::Viewport`.
    ConsoleScrolled(f32),
    /// The console min-level selector changed.
    ConsoleMinLevelChanged(tracing::Level),
    /// The console target-filter text changed.
    ConsoleTargetFilterChanged(String),
    /// The console message-search text changed.
    ConsoleSearchChanged(String),
    /// Clear all captured log records.
    ConsoleCleared,
    /// Copy all currently-displayed records to the clipboard.
    ConsoleCopyAll,
}

/// Scroll the debug console to its newest (bottom) line. Shared by the open,
/// tick-follow, and clear paths.
// Thin scroll-operation glue: returns an opaque `Task` with no observable state
// to assert, like the sibling `snap_to` call sites in the keyboard-nav arms.
#[mutants::skip]
fn snap_console_to_bottom() -> Task<Message> {
    iced::widget::operation::snap_to(
        crate::panels::console::SCROLL_ID,
        iced::widget::operation::RelativeOffset::END,
    )
}

/// Console refresh interval given whether the log ring is actively growing.
/// Fast while records flow (responsive tail), slow once stable (cheap idle).
fn console_refresh_interval(active: bool) -> std::time::Duration {
    let ms = if active {
        CONSOLE_TICK_FAST_MS
    } else {
        CONSOLE_TICK_SLOW_MS
    };
    std::time::Duration::from_millis(ms)
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
                // Reset stale per-archive UI state so a new archive doesn't
                // inherit the previous selection cursor or filter query.
                app.filter.clear();
                app.selected_row = None;
                dismiss_row_menus(app);
                // Clear tabs so they never reference a stale reader.
                app.tabs.clear();
                app.archive_generation = app.archive_generation.wrapping_add(1);
                app.archive = Some(loaded);
                Task::none()
            }
            Err(OpenError::Locked { path }) => {
                // Enter the key-entry flow: show the inline key-prompt panel.
                app.keyflow.lock(path);
                app.hex_input.clear();
                // The old archive is kept while the key prompt shows, so clear the
                // stale context-menu index too.
                dismiss_row_menus(app);
                // Clear any stale tabs from a previously-open archive.
                app.tabs.clear();
                app.archive_generation = app.archive_generation.wrapping_add(1);
                Task::none()
            }
            Err(OpenError::Core(msg)) => {
                if app.keyflow.is_locked().is_some() {
                    // We're mid-key-flow (e.g. wrong manual key) — show the error
                    // inside the panel, not as the global banner.
                    app.keyflow.set_error(msg);
                    Task::none()
                } else if app.archive.is_some() {
                    // An archive is already open, so the full-area error banner in
                    // `view` would never render (the `Some(archive)` branch wins).
                    // Surface the failure as a non-blocking toast instead.
                    //
                    // The open attempt began with `keyflow.begin()` (→ Resolving);
                    // it has now terminated, so leave Resolving — otherwise the
                    // state machine keeps claiming an open is in flight. The
                    // previously-loaded archive remains displayed, so restore the
                    // loaded-archive invariant (`Unlocked`, the state the `Ok` arm
                    // sets) rather than `Idle`, which would imply no archive.
                    app.keyflow.unlock();
                    push_toast(
                        app,
                        crate::state::toast::Severity::Error,
                        format!("Couldn't open file: {msg}"),
                    )
                } else {
                    // No archive: the empty-state banner (with retry CTA) is the
                    // right home. The open began with `keyflow.begin()` (→
                    // `Resolving`); reset to `Idle` so `view` falls through to the
                    // banner instead of showing the "Opening…" spinner forever
                    // (the `Resolving` branch precedes the `app.error` branch).
                    app.keyflow.reset();
                    app.error = Some(msg);
                    Task::none()
                }
            }
        },
        Message::KeyInputChanged(s) => {
            app.hex_input = Zeroizing::new(s);
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
            dismiss_row_menus(app);
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
            dismiss_row_menus(app);
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
            dismiss_row_menus(app);
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
        Message::ToastDismissed(id) => {
            app.toasts.remove(id);
            Task::none()
        }
        Message::RowContextOpened(i) => {
            app.context_row = toggle_context_row(app.context_row, i);
            // `dismiss_row_menus` would also clear `context_row`, but here we
            // need `context_row` toggled, not cleared — so reset export_menu
            // manually rather than delegating to the helper.
            app.export_menu = None;
            Task::none()
        }
        Message::CopyPathRequested(i) => match open_path_for_row(app, i) {
            Some(path) => {
                // The action completes here, so close the inline menu.
                dismiss_row_menus(app);
                Task::batch([
                    iced::clipboard::write::<Message>(path),
                    push_toast(
                        app,
                        crate::state::toast::Severity::Success,
                        "Copied path".to_string(),
                    ),
                ])
            }
            // No resolvable path (out-of-range, or a dir row) — silent no-op.
            None => Task::none(),
        },
        Message::ExportAsRequested(row) => {
            let Some(path) = open_path_for_row(app, row) else {
                return Task::none();
            };
            // Hybrid: enumerate synchronously from an already-open parsed tab
            // (instant picker, no re-parse — the common case of exporting what
            // you're viewing); else enumerate off-thread (cold path). The map
            // closure ends the `app.tabs` borrow before we write `app.export_menu`.
            let sync_choices = app.tabs.parsed_package(&path).map(|arc| {
                let registry = paksmith_core::export::HandlerRegistry::all_default_handlers();
                let formats = paksmith_core::export::available_formats(arc, &registry);
                crate::state::export::export_choices(&formats)
            });
            if let Some(choices) = sync_choices {
                app.export_menu = Some(crate::state::export::ExportMenu { path, choices });
                Task::none()
            } else {
                // Cold path (no open parsed tab): show a Raw-only picker
                // immediately — Raw needs no parse, so the menu is usable at once —
                // then enrich it with typed formats when the async enumeration lands
                // (ExportFormatsReady, path-guarded). Set the picker before
                // borrowing `app.archive` so the write stays a disjoint field.
                app.export_menu = Some(crate::state::export::ExportMenu {
                    path: path.clone(),
                    choices: vec![crate::state::export::ExportChoice::Raw],
                });
                if let Some(archive) = &app.archive {
                    let reader = archive.reader.clone();
                    let generation = app.archive_generation;
                    let task_path = path.clone();
                    Task::perform(
                        crate::task::export::available(reader, task_path),
                        move |formats| Message::ExportFormatsReady {
                            path,
                            formats,
                            generation,
                        },
                    )
                } else {
                    Task::none()
                }
            }
        }
        Message::ExportFormatsReady {
            path,
            formats,
            generation,
        } => {
            // Fence: drop a stale enumeration from a previous archive.
            if generation != app.archive_generation {
                return Task::none();
            }
            // Enrich the cold Raw-only picker with typed formats — but ONLY if it
            // is still open for this exact path. If the user cancelled (which clears
            // export_menu) or switched to another entry's picker, drop the
            // enumeration: it must never reopen or replace a picker the user
            // dismissed. Keying on export_menu, not context_row (which Cancel
            // deliberately keeps so the action strip returns), is what prevents a
            // late enumeration from popping the cancelled picker back open.
            let still_open = app
                .export_menu
                .as_ref()
                .is_some_and(|menu| menu.path == path);
            if !still_open {
                return Task::none();
            }
            let choices = crate::state::export::export_choices(&formats);
            app.export_menu = Some(crate::state::export::ExportMenu { path, choices });
            Task::none()
        }
        Message::ExportMenuCancelled => {
            // Back to the action strip; context_row stays so the strip reappears.
            app.export_menu = None;
            Task::none()
        }
        Message::ExportChoiceSelected { path, choice } => {
            // Commit to exporting this entry: collapse both inline menus and run
            // the save dialog + export off-thread. Capture the reader + generation
            // now so a mid-dialog archive swap can't redirect the export.
            dismiss_row_menus(app);
            if let Some(archive) = &app.archive {
                let reader = archive.reader.clone();
                let generation = app.archive_generation;
                Task::perform(
                    crate::task::export::run(reader, path, choice),
                    move |outcome| Message::ExportCompleted {
                        outcome,
                        generation,
                    },
                )
            } else {
                Task::none()
            }
        }
        Message::ConsoleToggled => {
            app.console_visible = !app.console_visible;
            if app.console_visible {
                app.console_follow = true;
                // Open in fast-refresh mode and baseline the change counter to
                // "now", so the first idle tick settles to slow rather than
                // mistaking records that accrued while closed for fresh growth.
                app.console_active = true;
                app.console_last_pushes = app.log_buffer.total_pushed();
                snap_console_to_bottom()
            } else {
                Task::none()
            }
        }
        Message::ConsoleTick => {
            // Processing any message rebuilds the view, refreshing the list from
            // the ring. Detect whether the ring grew since the last tick to keep
            // the refresh fast while logs flow and slow when the buffer is idle.
            let pushes = app.log_buffer.total_pushed();
            app.console_active = pushes != app.console_last_pushes;
            app.console_last_pushes = pushes;
            // Follow the tail only when the user hasn't scrolled up.
            if app.console_follow {
                snap_console_to_bottom()
            } else {
                Task::none()
            }
        }
        Message::ConsoleScrolled(relative_y) => {
            app.console_follow = crate::state::console::at_bottom(relative_y);
            Task::none()
        }
        Message::ConsoleMinLevelChanged(level) => {
            app.console_filters.min_level = level;
            Task::none()
        }
        Message::ConsoleTargetFilterChanged(value) => {
            app.console_filters.target_filter = value;
            Task::none()
        }
        Message::ConsoleSearchChanged(value) => {
            app.console_filters.search = value;
            Task::none()
        }
        Message::ConsoleCleared => {
            app.log_buffer.clear();
            app.console_follow = true;
            snap_console_to_bottom()
        }
        Message::ConsoleCopyAll => {
            let records = app.log_buffer.snapshot();
            let payload = crate::state::console::copy_all(&records, &app.console_filters);
            iced::clipboard::write(payload)
        }
        Message::ExportCompleted {
            outcome,
            generation,
        } => {
            // Fence like other async results; a completed export of a now-closed
            // archive drops its toast (the file was still written).
            if generation != app.archive_generation {
                return Task::none();
            }
            match outcome {
                crate::task::export::ExportOutcome::Written(dest) => {
                    let name = dest
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("file")
                        .to_string();
                    push_toast(
                        app,
                        crate::state::toast::Severity::Success,
                        format!("Exported {name}"),
                    )
                }
                crate::task::export::ExportOutcome::Failed(msg) => push_toast(
                    app,
                    crate::state::toast::Severity::Error,
                    format!("Export failed: {msg}"),
                ),
                crate::task::export::ExportOutcome::Cancelled => Task::none(),
            }
        }
        Message::OpenAsset(path) => {
            // Opening any asset (button, double-click, Enter, or the context-menu
            // strip) dismisses the inline menu.
            dismiss_row_menus(app);
            // Re-opening an already-open asset only reactivates its tab; it keeps its
            // loaded content and must NOT re-read/re-parse (tab dedupe per the spec).
            // Branch on `was_open` directly (load in the `else`) rather than a
            // negated `needs_load`: the dispatch decision isn't observable in a unit
            // test (Task is opaque), so a `!` here would be an unkillable mutant —
            // `is_open` carries the (tested) decision instead.
            let was_open = app.tabs.is_open(&path);
            let _ = app.tabs.open_or_activate(&path);
            if was_open {
                Task::none()
            } else if let Some(archive) = &app.archive {
                let reader = archive.reader.clone();
                let generation = app.archive_generation;
                Task::perform(
                    crate::task::asset::load(reader, path.clone()),
                    move |load| Message::AssetLoaded {
                        path: path.clone(),
                        load: Box::new(load),
                        generation,
                    },
                )
            } else {
                Task::none()
            }
        }
        Message::AssetLoaded {
            path,
            load,
            generation,
        } => {
            use crate::state::tabs::TabContent;
            if generation != app.archive_generation {
                return Task::none(); // stale load from a previous archive — drop it
            }
            app.tabs.set_content(
                &path,
                TabContent::Ready {
                    bytes: load.bytes,
                    truncated: load.truncated,
                    parsed: load.parsed,
                },
            );

            // Classify the loaded asset and populate the per-tab decodable-mip
            // cache (`tab.texture.mips`) BEFORE picking the view. Both
            // `pick_view_after_load` and every later per-frame `texture_available`
            // read that cache instead of re-classifying, so it must be set first
            // — this is the single `classify_texture` call per load.
            //
            // Look up the tab by path (not active tab) — the user may have
            // switched tabs while this load was in flight; operating on the
            // path-keyed tab is always correct.
            // Three-guard form: can't use let-chains on MSRV 1.88.
            let mut decode_task = Task::none();
            let mut audio_task = Task::none();
            #[allow(clippy::collapsible_if)]
            if let Some(tab) = app.tabs.open.iter_mut().find(|t| t.path == path) {
                if let TabContent::Ready {
                    parsed: Ok(arc), ..
                } = &tab.content
                {
                    if let Some(info) = paksmith_core::asset::classify_texture(arc.as_ref()) {
                        tab.texture.export_idx = info.export_idx;
                        tab.texture.mips = info.mips;
                        // `set_content` above already reset the rest of the texture
                        // state to defaults; restate the post-classify baseline here
                        // so this block fully owns the cache it populates (decode of
                        // mip 0 is dispatched below; `render` stays `None` until the
                        // async `TextureDecoded` lands and rebuilds it).
                        tab.texture.selected_mip = 0;
                        tab.texture.decoded = None;
                        tab.texture.error = None;
                        // Extract Arc and path for the task closure.
                        let pkg = arc.clone();
                        let task_path = path.clone();
                        let export_idx = info.export_idx;
                        decode_task = Task::perform(
                            crate::task::texture::decode(pkg, export_idx, 0),
                            move |result| Message::TextureDecoded {
                                path: task_path,
                                mip: 0,
                                result,
                                generation,
                            },
                        );
                    }
                    // Audio classification — single classify_audio call per load,
                    // mirroring the classify_texture pattern above. A real asset is
                    // texture XOR sound, so at most one of these blocks fires per load.
                    // `set_content` already reset `tab.audio` to default; populate only.
                    if let Some(info) = paksmith_core::asset::classify_audio(arc.as_ref()) {
                        // Extract the Copy scalars, then MOVE `info` (avoids
                        // cloning its `codec_label` String).
                        let export_idx = info.export_idx;
                        let playable = info.playable;
                        tab.audio.export_idx = export_idx;
                        tab.audio.info = Some(info);
                        if playable {
                            let pkg = arc.clone();
                            let task_path = path.clone();
                            audio_task = Task::perform(
                                crate::task::audio::decode(pkg, export_idx),
                                move |result| Message::AudioDecoded {
                                    path: task_path,
                                    result,
                                    generation,
                                },
                            );
                        }
                    }
                }
            }
            // INVARIANT: both the decodable-mip cache (texture) and audio.info
            // (audio) were populated just above, so the view picker reads those
            // caches rather than re-classifying. This ordering is
            // `pick_view_after_load`'s documented precondition — do not move it
            // before the populate block.
            app.tabs.pick_view_after_load(&path);
            Task::batch([decode_task, audio_task])
        }
        Message::TabActivated(i) => {
            app.tabs.activate(i);
            Task::none()
        }
        Message::TabClosed(i) => {
            app.tabs.close(i);
            Task::none()
        }
        Message::ViewModeSet(view) => {
            if let Some(i) = app.tabs.active {
                app.tabs.set_view(i, view);
            }
            Task::none()
        }
        Message::HexBytePressed(i) => {
            // Two-guard form: if-let + matches! can't be let-chained on MSRV 1.88.
            #[allow(clippy::collapsible_if)]
            if let Some(tab) = app.tabs.active_tab_mut() {
                if matches!(tab.content, crate::state::tabs::TabContent::Ready { .. }) {
                    tab.hex.press(i);
                }
            }
            Task::none()
        }
        Message::HexByteEntered(i) => {
            // Two-guard form: if-let + matches! can't be let-chained on MSRV 1.88.
            #[allow(clippy::collapsible_if)]
            if let Some(tab) = app.tabs.active_tab_mut() {
                if matches!(tab.content, crate::state::tabs::TabContent::Ready { .. }) {
                    tab.hex.enter(i);
                }
            }
            Task::none()
        }
        Message::HexDragEnded => {
            if let Some(tab) = app.tabs.active_tab_mut() {
                tab.hex.end_drag();
            }
            Task::none()
        }
        Message::HexCopyRequested => {
            copy_from_active_hex(&mut app.tabs, crate::state::hex_view::copy_hex)
        }
        Message::HexCopyAsciiRequested => {
            copy_from_active_hex(&mut app.tabs, crate::state::hex_view::copy_ascii)
        }
        Message::PropToggled(node_id) => {
            // Two-guard form: if-let + matches! can't be let-chained on MSRV 1.88.
            // Guard: only act on an active tab that has a successfully-parsed asset.
            #[allow(clippy::collapsible_if)]
            if let Some(tab) = app.tabs.active_tab_mut() {
                if matches!(
                    &tab.content,
                    crate::state::tabs::TabContent::Ready { parsed: Ok(_), .. }
                ) {
                    if !tab.expanded.remove(&node_id) {
                        let _ = tab.expanded.insert(node_id);
                    }
                }
            }
            Task::none()
        }
        Message::OpenAssetByRow(i) => match open_path_for_row(app, i) {
            Some(path) => Task::done(Message::OpenAsset(path)),
            None => Task::none(),
        },
        Message::TextureDecoded {
            path,
            mip,
            result,
            generation,
        } => {
            // Generation fence: drop results from a previous archive.
            if generation != app.archive_generation {
                return Task::none();
            }
            // Find the tab by path, then write the result only if it still
            // applies. Two guards:
            //   * `mip < mips.len()` — the tab's content must still be the texture
            //     this decode was dispatched for. `set_content` resets `texture`
            //     to default (`mips` empty, `selected_mip` 0) on a content swap,
            //     so an in-flight mip-0 decode landing after a reset/demotion would
            //     otherwise pass the `selected_mip == mip` check (both 0) and write
            //     onto a non-texture tab. An empty `mips` fails `mip < 0`. Mirrors
            //     the same bound the `TextureMipSelected` dispatch applies.
            //   * `selected_mip == mip` — drop a stale mip result (user switched
            //     mips faster than the decode completed).
            // This closes the content-reset race reachable in 7b. A same-path
            // texture→texture in-place reload (both tabs non-empty, both mip 0)
            // is NOT distinguished here; that path doesn't exist until the Phase
            // 7c in-place reload, which will add a per-tab content generation
            // counter (mirroring `archive_generation`) as its fence.
            // Two-guard form: can't use let-chains on MSRV 1.88.
            #[allow(clippy::collapsible_if)]
            if let Some(tab) = app.tabs.open.iter_mut().find(|t| t.path == path) {
                if mip < tab.texture.mips.len() && tab.texture.selected_mip == mip {
                    match result {
                        Ok(decoded) => {
                            tab.texture.decoded = Some(decoded);
                            tab.texture.error = None;
                            // `decoded` changed — rebuild the render cache. Only
                            // the Ok arm rebuilds: the Err arm below keeps the
                            // last-good `decoded` unchanged, so rebuilding would
                            // mint a fresh handle Id and force a needless GPU
                            // re-upload of the same pixels.
                            tab.texture.recompute_render();
                        }
                        Err(msg) => {
                            // C18: keep the previously decoded mip (don't blank the
                            // last-good image on a failed re-select) and set only
                            // the error. `decoded` is intentionally left untouched,
                            // so the render cache stays valid and is not rebuilt
                            // here — see `TextureState::error` for when it clears.
                            tab.texture.error = Some(msg);
                        }
                    }
                }
            }
            Task::none()
        }
        Message::AudioDecoded {
            path,
            result,
            generation,
        } => {
            // Generation fence: drop results from a previous archive.
            if generation != app.archive_generation {
                return Task::none();
            }
            // Find the tab by path, then write the result only if it still
            // applies. The `tab.audio.info.is_some()` guard mirrors the texture
            // handler's `mip < mips.len()` guard: `set_content` resets `tab.audio`
            // to default (`info = None`) on a content swap, so a decode landing
            // after a reset would otherwise write onto a non-audio tab.
            // Two-guard form: can't use let-chains on MSRV 1.88.
            #[allow(clippy::collapsible_if)]
            if let Some(tab) = app.tabs.open.iter_mut().find(|t| t.path == path) {
                if tab.audio.info.is_some() {
                    match result {
                        Ok(decoded) => {
                            tab.audio.waveform = crate::state::audio_view::compute_waveform(
                                &decoded.samples,
                                decoded.channels,
                                WAVEFORM_COLUMNS,
                            );
                            tab.audio.decoded = Some(decoded);
                            tab.audio.error = None;
                        }
                        Err(msg) => {
                            tab.audio.error = Some(msg);
                        }
                    }
                }
            }
            Task::none()
        }
        Message::AudioPlayPause => {
            // Two-phase borrow: compute the pure state transition + copy out
            // the data needed by the seam, then call `apply_playback` after
            // the `active_tab_mut` borrow ends.
            let state = if let Some(tab) = app.tabs.active_tab_mut() {
                let action = tab.audio.toggle_play();
                let decoded = tab.audio.decoded.clone();
                let transport = tab.audio.transport;
                let position_secs = tab.audio.position_secs;
                Some((action, decoded, transport, position_secs))
            } else {
                None
            };
            if let Some((action, decoded, transport, position_secs)) = state {
                apply_playback(
                    &mut app.audio,
                    decoded.as_ref(),
                    transport,
                    position_secs,
                    action,
                );
            }
            Task::none()
        }
        Message::AudioStop => {
            let state = if let Some(tab) = app.tabs.active_tab_mut() {
                let action = tab.audio.stop();
                let decoded = tab.audio.decoded.clone();
                let transport = tab.audio.transport;
                let position_secs = tab.audio.position_secs;
                Some((action, decoded, transport, position_secs))
            } else {
                None
            };
            if let Some((action, decoded, transport, position_secs)) = state {
                apply_playback(
                    &mut app.audio,
                    decoded.as_ref(),
                    transport,
                    position_secs,
                    action,
                );
            }
            Task::none()
        }
        Message::AudioVolume(v) => {
            // Two-phase borrow: set volume in pure state, then forward the
            // clamped value to the seam. Tuple-match sidesteps `collapsible_if`
            // (the fix would be a let-chain, unavailable at MSRV 1.88).
            let volume = if let Some(tab) = app.tabs.active_tab_mut() {
                tab.audio.set_volume(v);
                Some(tab.audio.volume)
            } else {
                None
            };
            if let (Some(vol), Some(out)) = (volume, app.audio.as_mut()) {
                out.set_volume(vol);
            }
            Task::none()
        }
        Message::AudioTick => {
            // Read seam state before borrowing tabs (immutable borrows of
            // `app.audio` are released before `active_tab_mut` takes a
            // mutable borrow of `app.tabs`).
            let pos = app.audio.as_ref().and_then(AudioOutput::position);
            let done = app.audio.as_ref().is_some_and(AudioOutput::finished);
            if let Some(tab) = app.tabs.active_tab_mut() {
                if let Some(dur) = pos {
                    tab.audio.set_position(dur.as_secs_f32());
                }
                if done {
                    let _ = tab.audio.stop();
                }
            }
            // Tuple-match sidesteps `collapsible_if` (let-chain not in MSRV 1.88).
            if let (true, Some(out)) = (done, app.audio.as_mut()) {
                out.stop();
            }
            Task::none()
        }
        Message::TextureChannelToggled { channel } => {
            if let Some(tab) = app.tabs.active_tab_mut() {
                tab.texture.channels.toggle(channel);
                // Channel set changed — rebuild the render cache.
                tab.texture.recompute_render();
            }
            Task::none()
        }
        Message::TextureZoomIn => {
            if let Some(tab) = app.tabs.active_tab_mut() {
                tab.texture.zoom = crate::state::texture_view::zoom_in(tab.texture.zoom);
                // Manual zoom disables fit-to-window.
                tab.texture.fit_to_window = false;
            }
            Task::none()
        }
        Message::TextureZoomOut => {
            if let Some(tab) = app.tabs.active_tab_mut() {
                tab.texture.zoom = crate::state::texture_view::zoom_out(tab.texture.zoom);
                // Manual zoom disables fit-to-window.
                tab.texture.fit_to_window = false;
            }
            Task::none()
        }
        Message::TextureFitToWindow => {
            if let Some(tab) = app.tabs.active_tab_mut() {
                tab.texture.fit_to_window = true;
            }
            Task::none()
        }
        Message::TextureMipSelected(m) => {
            // Compute `dispatch` (the decode-task inputs) within a single tab
            // borrow: validate the index, update view state, then extract the
            // path + pkg Arc + export_idx. The `Task::perform` runs after the
            // borrow ends so it can read `app.archive_generation`, matching the
            // single-return funnel the sibling texture arms use.
            let dispatch = if let Some(tab) = app.tabs.active_tab_mut() {
                // Guard against an out-of-range index (a stale `pick_list`
                // message, or one raced against a content swap that shrank the
                // mip list): committing an invalid `selected_mip` would wedge the
                // tab — the decode would fail and the stale-mip fence in
                // `TextureDecoded` could then drop later valid results. Ignore
                // anything past the current mip list.
                if m >= tab.texture.mips.len() {
                    None
                } else {
                    tab.texture.selected_mip = m;
                    // Keep the previously decoded mip on screen while the newly
                    // selected mip decodes asynchronously — clearing it here would
                    // blank the viewer on every mip change. The generation/stale-mip
                    // fence in `TextureDecoded` swaps in the new image when ready.
                    tab.texture.error = None;
                    // Try to extract what we need to dispatch a new decode task.
                    if let crate::state::tabs::TabContent::Ready {
                        parsed: Ok(arc), ..
                    } = &tab.content
                    {
                        Some((tab.path.clone(), arc.clone(), tab.texture.export_idx))
                    } else {
                        None
                    }
                }
            } else {
                None
            };
            if let Some((path, pkg, export_idx)) = dispatch {
                let generation = app.archive_generation;
                Task::perform(
                    crate::task::texture::decode(pkg, export_idx, m),
                    move |result| Message::TextureDecoded {
                        path,
                        mip: m,
                        result,
                        generation,
                    },
                )
            } else {
                Task::none()
            }
        }
    }
}

/// Copy bytes from the active hex tab using the supplied formatting function.
///
/// Returns an [`iced::clipboard::write`] task when a selection is active on a
/// `Ready` tab, or [`Task::none`] otherwise. Shared by
/// [`Message::HexCopyRequested`] and [`Message::HexCopyAsciiRequested`].
fn copy_from_active_hex(
    tabs: &mut crate::state::tabs::Tabs,
    copy_fn: fn(&[u8], crate::state::hex_view::Selection) -> String,
) -> Task<Message> {
    // Triple-nested if-let chains can't be collapsed without let-chains (MSRV 1.88).
    #[allow(clippy::collapsible_if)]
    if let Some(tab) = tabs.active_tab_mut() {
        if let crate::state::tabs::TabContent::Ready { bytes, .. } = &tab.content {
            if let Some(sel) = tab.hex.selection {
                return iced::clipboard::write::<Message>(copy_fn(bytes, sel));
            }
        }
    }
    Task::none()
}

/// Push a toast and return the task that auto-dismisses it after its severity's
/// TTL. The scheduled message reuses [`Message::ToastDismissed`], so it is a
/// no-op if the user already dismissed the toast manually.
fn push_toast(
    app: &mut App,
    severity: crate::state::toast::Severity,
    message: String,
) -> Task<Message> {
    let id = app.toasts.push(severity, message);
    let ttl = severity.ttl();
    // The `async move {}` wrapper is load-bearing: it defers the
    // `tokio::time::sleep(ttl)` call until the future is polled by the iced
    // runtime. Calling `sleep` eagerly here would panic ("no reactor running")
    // whenever `push_toast` runs outside a tokio runtime — e.g. in the unit
    // tests that drive `update` directly.
    Task::perform(async move { tokio::time::sleep(ttl).await }, move |()| {
        Message::ToastDismissed(id)
    })
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

    // F12 is the debug-console toggle, routed via its own always-on
    // subscription and excluded from the tree-key listener. Guard here too so a
    // direct call (or any future routing change) can never let F12 disturb tree
    // state or dismiss the context/export menus.
    if named == Named::F12 {
        return None;
    }

    // Any tree-key navigation (arrows, Enter, Escape, or any other *named* key —
    // bare character keys already returned via the `else` guard above) dismisses
    // the inline context menu. This is load-bearing, not just cosmetic: the strip
    // inserts an extra row that shifts the Y of every row below it, which would
    // desync the keyboard auto-scroll's `row_idx * row_height` math at the bottom
    // of this function. Clearing here (before that scroll offset is computed) keeps
    // row height uniform. Disjoint-field write — `archive` borrows `app.archive`,
    // these write `app.context_row` / `app.export_menu` (same pattern as the
    // `app.selected_row = …` writes below; can't call `dismiss_row_menus` here
    // because the live `archive` borrow from the caller is still active).
    app.context_row = None;
    app.export_menu = None;

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
                        // Open the file in a new asset tab.
                        if let Some(path) = row.full_path {
                            return Some(Task::done(Message::OpenAsset(path)));
                        }
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
            let target_y = tree_scroll_offset(row_idx);
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

/// Pixel height of one tree row (text height + vertical padding on both sides).
///
/// Used to map a row index to an absolute Y scroll offset. This is an
/// approximation — iced's actual rendered height may include fractional
/// sub-pixel rounding — but the drift is within ±1 row even at large list
/// sizes, which is acceptable for keyboard auto-scroll.
fn tree_row_pixel_height() -> f32 {
    f32::from(crate::theme::tokens::TEXT_MD) + 2.0 * crate::theme::tokens::SPACE_XS
}

/// Absolute Y scroll offset that brings visible-row `row_idx` to the viewport top.
fn tree_scroll_offset(row_idx: usize) -> f32 {
    #[allow(clippy::cast_precision_loss)]
    {
        row_idx as f32 * tree_row_pixel_height()
    }
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

/// The new `context_row` after a right-press on visible row `clicked`.
///
/// Right-pressing the row that already owns the inline menu closes it (toggle);
/// right-pressing any other row moves the menu to that row.
fn toggle_context_row(current: Option<usize>, clicked: usize) -> Option<usize> {
    if current == Some(clicked) {
        None
    } else {
        Some(clicked)
    }
}

/// Clear both inline row menus (the action strip and the Export As… picker).
/// Used at every site that dismisses the menu, so a dismissing gesture (nav,
/// archive swap, a committed export) never leaves a stale picker visible.
fn dismiss_row_menus(app: &mut App) {
    app.context_row = None;
    app.export_menu = None;
}

/// The asset path to open for visible tree row `i`, if it is a file row with a
/// path. Resolving here (once, on the actual open event) keeps the per-frame
/// view from cloning a path String for every file row.
pub fn open_path_for_row(app: &App, i: usize) -> Option<String> {
    app.archive.as_ref().and_then(|a| {
        a.tree
            .visible_rows()
            .get(i)
            .and_then(|r| r.full_path.clone())
    })
}

/// Returns `true` when the active tab is a Hex view (so the drag-release
/// subscription should be active).
///
/// Extracted from [`subscription`] so the predicate is unit-testable.
/// Kills the `== with !=` mutant on the `ViewMode::Hex` comparison.
pub fn hex_drag_listener_active(app: &App) -> bool {
    app.tabs
        .active_tab()
        .is_some_and(|t| t.view == crate::state::tabs::ViewMode::Hex)
}

/// Returns `true` when the active tab is currently playing audio (so the
/// play-gated [`Message::AudioTick`] subscription should be active).
///
/// Extracted from [`subscription`] so the predicate is unit- and
/// mutation-tested without a headless iced runtime. Kills the
/// `Transport::Playing == Transport::Paused` mutant.
pub fn audio_tick_active(app: &App) -> bool {
    app.tabs
        .active_tab()
        .is_some_and(|t| t.audio.transport == crate::state::audio_view::Transport::Playing)
}

/// Apply a [`PlaybackAction`] from the pure state machine to the audio-output seam.
///
/// The decision of *which* action to take was already made by the pure
/// `AudioState` methods (`toggle_play`, `stop`, …) and is mutation-tested there.
/// This function is glue — it dispatches that decision to the `!Send` rodio
/// backend — and cannot be unit-tested without a real audio device, so the
/// whole impl is `#[mutants::skip]`.
///
/// On `Play` (and `SeekTo` when currently `Playing`), the decoded samples are
/// re-fed from the current `position_secs` so that both a stopped→play transition
/// (position 0) and a paused→resume transition (position > 0) route through the
/// same uniform path.
#[mutants::skip]
fn apply_playback(
    audio: &mut Option<AudioOutput>,
    decoded: Option<&crate::state::audio_view::DecodedAudio>,
    transport: crate::state::audio_view::Transport,
    position_secs: f32,
    action: crate::state::audio_view::PlaybackAction,
) {
    use crate::state::audio_view::PlaybackAction;
    let Some(out) = audio else { return };
    match action {
        PlaybackAction::Play => {
            if let Some(dec) = decoded {
                // Slice samples from the current playhead position so that
                // Stopped→play starts from 0 and Paused→resume starts mid-clip.
                // `position_secs` is non-negative (reset to 0 by `stop`;
                // `set_position` only receives seam-reported values).  The product
                // fits `usize`: realistic audio lengths stay well within usize::MAX.
                #[allow(
                    clippy::cast_possible_truncation,
                    clippy::cast_sign_loss,
                    clippy::cast_precision_loss
                )]
                let mut start =
                    (position_secs * dec.sample_rate as f32 * f32::from(dec.channels)) as usize;
                start = start.min(dec.samples.len());
                start -= start % usize::from(dec.channels).max(1);
                out.play_samples(dec.samples[start..].to_vec(), dec.channels, dec.sample_rate);
            }
        }
        PlaybackAction::Pause => out.pause(),
        PlaybackAction::Stop => out.stop(),
        PlaybackAction::SeekTo(_) => {
            // Re-feed only when already playing; a seek while paused/stopped just
            // updates `position_secs` in the pure state and play will read it later.
            // `collapsible_if`: the suggested collapse would use a let-chain
            // (`transport == … && let Some(dec) = decoded`) which is not
            // available on MSRV 1.88.
            #[allow(clippy::collapsible_if)]
            if transport == crate::state::audio_view::Transport::Playing {
                if let Some(dec) = decoded {
                    #[allow(
                        clippy::cast_possible_truncation,
                        clippy::cast_sign_loss,
                        clippy::cast_precision_loss
                    )]
                    let mut start =
                        (position_secs * dec.sample_rate as f32 * f32::from(dec.channels)) as usize;
                    start = start.min(dec.samples.len());
                    start -= start % usize::from(dec.channels).max(1);
                    out.play_samples(dec.samples[start..].to_vec(), dec.channels, dec.sample_rate);
                }
            }
        }
        PlaybackAction::None => {}
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
// Iced event-wiring glue: the two match-arm-delete mutants (KeyPressed /
// ButtonReleased arms) produce opaque `Subscription` values; no unit test can
// inspect what events a Subscription will fire without a full headless runtime.
// The testable predicate (`hex_drag_listener_active`) is extracted and tested.
#[mutants::skip]
pub fn subscription(app: &App) -> Subscription<Message> {
    let menu_sub = crate::menu::subscription();

    // F12 toggles the debug console. Always active — even with no archive open —
    // so startup/open-error logs are reachable. Kept OFF the tree-key listener
    // below so it never doubles as a TreeKey that would dismiss menus.
    let console_toggle_sub = iced::event::listen_with(|event, _status, _window| match event {
        Event::Keyboard(KeyboardEvent::KeyPressed {
            key: iced::keyboard::Key::Named(Named::F12),
            ..
        }) => Some(Message::ConsoleToggled),
        _ => None,
    });

    // While the console is visible, tick so freshly captured records render
    // without requiring other UI activity. The interval is adaptive: fast while
    // logs are arriving, slow once the ring is stable, to cut idle-CPU churn.
    let console_tick_sub = if app.console_visible {
        iced::time::every(console_refresh_interval(app.console_active))
            .map(|_| Message::ConsoleTick)
    } else {
        Subscription::none()
    };

    // Tick at 100 ms while audio is playing so the displayed playhead advances
    // and the finish condition is polled. Gated on `audio_tick_active` so the
    // subscription costs nothing when no audio is playing.
    let audio_tick_sub = if audio_tick_active(app) {
        iced::time::every(std::time::Duration::from_millis(100)).map(|_| Message::AudioTick)
    } else {
        Subscription::none()
    };

    if app.archive.is_none() {
        return Subscription::batch([
            menu_sub,
            console_toggle_sub,
            console_tick_sub,
            audio_tick_sub,
        ]);
    }

    // Tree navigation keys. The decision (F12 exclusion + only-act-on-unconsumed
    // keys) lives in the tested `tree_key_for`; this closure just destructures
    // the event and forwards the key + capture status.
    let tree_key_sub = iced::event::listen_with(|event, status, _window| match event {
        Event::Keyboard(KeyboardEvent::KeyPressed { key, .. }) => tree_key_for(key, status),
        _ => None,
    });

    // Only subscribe to left-button-release when a Hex tab is active. Drag can
    // only start inside a Hex view, so firing this app-wide would cause spurious
    // update+view rebuilds on every click elsewhere.
    let hex_drag_sub = if hex_drag_listener_active(app) {
        iced::event::listen_with(|event, _status, _window| match event {
            Event::Mouse(iced::mouse::Event::ButtonReleased(iced::mouse::Button::Left)) => {
                Some(Message::HexDragEnded)
            }
            _ => None,
        })
    } else {
        Subscription::none()
    };

    Subscription::batch([
        menu_sub,
        console_toggle_sub,
        console_tick_sub,
        audio_tick_sub,
        tree_key_sub,
        hex_drag_sub,
    ])
}

/// Decide whether a key press should drive tree navigation.
///
/// Two guards, both load-bearing:
/// - **F12** is the debug-console toggle (its own always-on listener); routing
///   it to [`Message::TreeKey`] would dismiss the context/export menus via
///   `handle_tree_key`'s clear-at-top.
/// - Only act when the event was **not** already consumed by a focused widget
///   ([`iced::event::Status::Ignored`]). A focused `text_input` — the toolbar
///   filter or the console target/search fields — captures the editing keys it
///   uses (ArrowLeft/Right, printable characters, Backspace, Home/End) as
///   `Captured`, so those no longer also navigate or mutate the file tree. Keys
///   a single-line input doesn't consume (ArrowUp/Down, and Enter when no
///   `on_submit` is set) stay `Ignored` and still reach the tree — acceptable,
///   as they have no editing meaning inside the input.
///
/// Extracted from [`subscription`]'s opaque `listen_with` closure so the
/// decision is unit- and mutation-tested.
fn tree_key_for(key: iced::keyboard::Key, status: iced::event::Status) -> Option<Message> {
    if matches!(key, iced::keyboard::Key::Named(Named::F12)) {
        return None;
    }
    match status {
        iced::event::Status::Ignored => Some(Message::TreeKey(key)),
        iced::event::Status::Captured => None,
    }
}

/// Returns a button style closure that uses the system accent colour so that
/// primary CTAs (Open, Unlock) match the tree-row selection highlight.
///
/// This avoids a clash between the iced-built-in blue `button::primary` and a
/// non-blue OS accent colour when the two appear on screen simultaneously.
/// Shared with `panels::toolbar` and `panels::key_prompt`.
/// Pick a readable text colour (black or white) to sit on top of `accent`,
/// using the WCAG relative-luminance coefficients: a light accent gets dark
/// text, a dark accent gets light text. Pure + unit-tested.
pub fn readable_text_on(accent: iced::Color) -> iced::Color {
    let lum = 0.2126 * accent.r + 0.7152 * accent.g + 0.0722 * accent.b;
    if lum > 0.5 {
        iced::Color::BLACK
    } else {
        iced::Color::WHITE
    }
}

// The closure assembles an opaque `button::Style` whose field values are
// cosmetic (background/border/radius); cargo-mutants 27 can't regex-exclude the
// "delete struct field" genus here (see app::view), and the Style isn't
// observable from a test. The one bit of real logic — the readable-text pick —
// is extracted into the unit-tested `readable_text_on`.
#[mutants::skip]
pub fn accent_button(
    accent: iced::Color,
) -> impl Fn(&iced::Theme, iced::widget::button::Status) -> iced::widget::button::Style {
    move |_theme, status| {
        let alpha = match status {
            iced::widget::button::Status::Hovered => 0.85,
            iced::widget::button::Status::Pressed => 0.70,
            iced::widget::button::Status::Disabled => 0.40,
            iced::widget::button::Status::Active => 1.0,
        };
        iced::widget::button::Style {
            background: Some(iced::Background::Color(accent.scale_alpha(alpha))),
            text_color: readable_text_on(accent),
            border: iced::Border {
                radius: crate::theme::tokens::RADIUS.into(),
                ..Default::default()
            },
            ..Default::default()
        }
    }
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
#[allow(clippy::too_many_lines)]
// single match-all-states fn; splitting would obscure the layout
// Pure Iced view composition. cargo-mutants emits "delete struct field" mutants
// on the widget Style/Border literals here that its `exclude_re` cannot match
// (27.0.0 doesn't match that genus against the displayed name); they are
// cosmetic, validated by the UI/UX review + manual runs, not unit-testable
// without a render harness. Testable logic lives in update/handle_tree_key/clamp.
#[mutants::skip]
pub fn view(app: &App) -> Element<'_, Message> {
    use crate::theme::tokens::{SPACE_MD, SPACE_SM};

    // ── toolbar ───────────────────────────────────────────────────────────────
    let decrypted_flag = app.archive.as_ref().map(|a| a.decrypted);
    let toolbar_view = toolbar::view(
        decrypted_flag,
        &app.filter,
        &app.profiles,
        app.active_game.as_ref(),
        app.accent,
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
        container(key_prompt::view(&app.keyflow, &app.hex_input, app.accent))
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
        // Capture locals for the pane_grid closure (can't borrow `app` inside).
        let tree = &archive.tree;
        let accent = app.accent;
        let selected_row = app.selected_row;
        let context_row = app.context_row;
        let export_menu = app.export_menu.as_ref();
        let tabs = &app.tabs;
        let entries = &archive.entries;

        pane_grid(&app.panes, move |_pane, kind, _maximized| {
            let content: Element<'_, Message> = match kind {
                PaneKind::Sidebar => {
                    sidebar::view(tree, accent, selected_row, context_row, export_menu)
                }
                PaneKind::Detail => content::view(tabs, entries, accent),
            };
            pane_grid::Content::new(content)
        })
        .on_resize(DIVIDER_GRAB_PX, Message::PaneResized)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
    } else if matches!(app.keyflow, KeyFlow::Resolving) {
        // ── resolving state: neutral "Opening…" message ────────────────────────
        // Shown while the async open task is in flight.  Prevents the "Open a
        // .pak file to begin" CTA from appearing while a file is already loading.
        container(
            text("Opening\u{2026}")
                .size(f32::from(crate::theme::tokens::TEXT_MD))
                .style(|theme: &iced::Theme| iced::widget::text::Style {
                    color: Some(theme.palette().text.scale_alpha(TEXT_MUTED_ALPHA)),
                }),
        )
        .center_x(Length::Fill)
        .center_y(Length::Fill)
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
                    .style(accent_button(app.accent))
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
                    color: Some(theme.palette().text.scale_alpha(TEXT_MUTED_ALPHA)),
                }),
        );
        #[cfg(not(target_os = "macos"))]
        let hint_text: Option<iced::widget::Text<'_, iced::Theme, iced::Renderer>> = None;

        let cta_text = text("Open a .pak file to begin exploring")
            .size(f32::from(crate::theme::tokens::TEXT_MD))
            .style(|theme: &iced::Theme| iced::widget::text::Style {
                color: Some(theme.palette().text.scale_alpha(TEXT_MUTED_ALPHA)),
            });

        let mut cta_col = column![
            button(text("Open\u{2026}").size(f32::from(crate::theme::tokens::TEXT_MD)))
                .style(accent_button(app.accent))
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
                    .size(f32::from(TEXT_XL))
                    .style(|theme: &iced::Theme| iced::widget::text::Style {
                        color: Some(theme.palette().text),
                    }),
                text(concat!(
                    "Cross-platform explorer for Unreal Engine game assets.\n",
                    "Open source — MIT / Apache-2.0."
                ))
                .size(f32::from(crate::theme::tokens::TEXT_SM))
                .style(|theme: &iced::Theme| iced::widget::text::Style {
                    color: Some(theme.palette().text.scale_alpha(TEXT_MUTED_ALPHA)),
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
    let mut root = column![toolbar_view, body];
    if app.console_visible {
        root = root.push(crate::panels::console::view(app));
    }
    let root = root
        .push(status_view)
        .width(Length::Fill)
        .height(Length::Fill);

    // Layer the non-blocking toast overlay on top when there are toasts. The
    // overlay container is click-through except over each card's dismiss button,
    // so the rest of the UI stays interactive while toasts are showing.
    if app.toasts.is_empty() {
        root.into()
    } else {
        iced::widget::stack([root.into(), crate::widgets::toast::overlay(&app.toasts)])
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use iced::keyboard::Key;
    use iced::keyboard::key::Named;

    use crate::state::export::{ExportChoice, ExportMenu};
    use crate::task::export::ExportOutcome;

    #[test]
    fn readable_text_picks_dark_on_light_accent_and_light_on_dark() {
        use iced::Color;
        // Extremes: white → black text; black → white text.
        assert_eq!(super::readable_text_on(Color::WHITE), Color::BLACK);
        assert_eq!(super::readable_text_on(Color::BLACK), Color::WHITE);
        // Channel-specific near-threshold colours that pin the luminance
        // coefficients: each has a low true luminance (correctly WHITE text), but
        // a mutated coefficient operator (`*`→`+`) would inflate it past 0.5 and
        // wrongly pick BLACK — so these kill the per-channel `*` mutants.
        // 0.2126*0.6 = 0.128  (mutant 0.2126+0.6 = 0.81 → black)
        assert_eq!(
            super::readable_text_on(Color::from_rgb(0.6, 0.0, 0.0)),
            Color::WHITE
        );
        // 0.7152*0.6 = 0.429  (mutant 0.7152+0.6 = 1.31 → black)
        assert_eq!(
            super::readable_text_on(Color::from_rgb(0.0, 0.6, 0.0)),
            Color::WHITE
        );
        // 0.0722*0.9 = 0.065  (mutant 0.0722+0.9 = 0.97 → black)
        assert_eq!(
            super::readable_text_on(Color::from_rgb(0.0, 0.0, 0.9)),
            Color::WHITE
        );
        // g+b term sum crosses the threshold (0.472+0.072 = 0.544 → black); a
        // `+`→`-` mutation drops it to 0.400 → white, pinning the term `+`.
        assert_eq!(
            super::readable_text_on(Color::from_rgb(0.0, 0.66, 1.0)),
            Color::BLACK
        );
    }

    use super::*;
    use crate::state::archive::{EntryMeta, LoadedArchive};
    use crate::state::tree::Tree;

    #[test]
    fn new_app_has_no_archive() {
        let app = App::default();
        assert!(app.archive.is_none());
    }

    // ── toast consumer: open-failure-while-loaded ─────────────────────────────

    use crate::state::archive::OpenError;
    use crate::state::toast::Severity;

    #[test]
    fn open_error_while_archive_loaded_pushes_error_toast_not_banner() {
        // An archive is already open and an open of another file is in flight
        // (keyflow.begin() → Resolving). The failed open would set `app.error`,
        // but `view` shows the archive (the Some(archive) branch wins), so the
        // banner never renders — the error is swallowed. It must become a toast.
        let mut app = app_with_paths(&["Game/A.uasset"]);
        app.keyflow.begin();
        let _ = update(
            &mut app,
            Message::ArchiveOpened(Box::new(Err(OpenError::Core("boom".to_string())))),
        );
        assert_eq!(app.toasts.items().len(), 1, "one error toast pushed");
        assert_eq!(app.toasts.items()[0].severity, Severity::Error);
        assert!(
            app.toasts.items()[0].message.contains("boom"),
            "toast carries the core error message"
        );
        assert!(
            app.error.is_none(),
            "no full-area banner when an archive is open"
        );
        // The completed open must leave Resolving; the displayed archive stays
        // loaded, so keyflow returns to the loaded-archive state (Unlocked), not
        // Resolving (which would falsely claim an open is still in flight).
        assert!(
            matches!(app.keyflow, crate::state::keyflow::KeyFlow::Unlocked),
            "keyflow must leave Resolving when the open completes with an archive still loaded"
        );
    }

    #[test]
    fn open_error_with_no_archive_uses_banner_not_toast() {
        // Empty state: the full-area banner (with the retry CTA) is the right
        // home, so no toast and `app.error` is set.
        let mut app = App::default();
        let _ = update(
            &mut app,
            Message::ArchiveOpened(Box::new(Err(OpenError::Core("nope".to_string())))),
        );
        assert!(app.toasts.is_empty(), "no toast in the empty state");
        assert_eq!(app.error.as_deref(), Some("nope"), "banner error is set");
    }

    #[test]
    fn open_error_no_archive_after_resolving_shows_banner_not_spinner() {
        // Realistic flow: OpenPathChosen runs `keyflow.begin()` → Resolving before
        // the async open completes. A Core error with no archive must leave
        // Resolving (else `view`'s Resolving branch — which precedes the error
        // branch — shows "Opening…" forever and swallows the banner).
        let mut app = App::default();
        app.keyflow.begin();
        assert!(matches!(
            app.keyflow,
            crate::state::keyflow::KeyFlow::Resolving
        ));
        let _ = update(
            &mut app,
            Message::ArchiveOpened(Box::new(Err(OpenError::Core("boom".to_string())))),
        );
        assert!(
            matches!(app.keyflow, crate::state::keyflow::KeyFlow::Idle),
            "keyflow must return to Idle (not just leave Resolving) on a terminal \
             no-archive error — Unlocked would falsely imply a successful unlock"
        );
        assert_eq!(app.error.as_deref(), Some("boom"), "banner error is set");
        assert!(app.toasts.is_empty(), "no toast in the empty state");
    }

    #[test]
    fn open_error_mid_keyflow_sets_keyflow_error_no_toast() {
        // Mid key-entry (wrong manual key): the error belongs inside the key panel.
        let mut app = App::default();
        app.keyflow.lock(PathBuf::from("locked.pak"));
        let _ = update(
            &mut app,
            Message::ArchiveOpened(Box::new(Err(OpenError::Core("bad key".to_string())))),
        );
        assert!(app.toasts.is_empty(), "no toast during the key flow");
        assert!(app.error.is_none(), "no banner during the key flow");
    }

    #[test]
    fn toast_dismissed_removes_the_targeted_toast() {
        let mut app = App::default();
        let id = app.toasts.push(Severity::Error, "x".to_string());
        let _ = update(&mut app, Message::ToastDismissed(id));
        assert!(app.toasts.is_empty(), "dismiss removes the toast");
    }

    // ── Message::RowContextOpened ─────────────────────────────────────────────
    #[test]
    fn row_context_opened_toggles_the_strip() {
        let mut app = app_with_paths(&["file.txt"]);
        let _ = update(&mut app, Message::RowContextOpened(0));
        assert_eq!(
            app.context_row,
            Some(0),
            "first right-press opens the strip"
        );
        let _ = update(&mut app, Message::RowContextOpened(0));
        assert_eq!(
            app.context_row, None,
            "second right-press on same row closes it"
        );
    }

    // ── context_row clear triggers ────────────────────────────────────────────
    #[test]
    fn row_toggled_clears_context_row() {
        let mut app = app_with_paths(&["Dir/file.txt"]);
        app.context_row = Some(0);
        let _ = update(&mut app, Message::RowToggled(0));
        assert_eq!(app.context_row, None, "toggling a dir clears the menu");
    }

    #[test]
    fn row_selected_clears_context_row() {
        let mut app = app_with_paths(&["file.txt"]);
        app.context_row = Some(0);
        let _ = update(&mut app, Message::RowSelected(0));
        assert_eq!(app.context_row, None, "selecting a row clears the menu");
    }

    #[test]
    fn filter_changed_clears_context_row() {
        let mut app = app_with_paths(&["file.txt"]);
        app.context_row = Some(0);
        let _ = update(&mut app, Message::FilterChanged("f".to_string()));
        assert_eq!(app.context_row, None, "filtering clears the menu");
    }

    #[test]
    fn open_asset_clears_context_row() {
        let mut app = app_with_paths(&["file.txt"]);
        app.context_row = Some(0);
        let _ = update(&mut app, Message::OpenAsset("file.txt".to_string()));
        assert_eq!(app.context_row, None, "opening an asset clears the menu");
    }

    #[test]
    fn archive_opened_ok_clears_context_row() {
        let mut app = app_with_paths(&["old.uasset"]);
        app.context_row = Some(0);
        // Move a freshly-built loaded archive out of a throwaway App and swap it in.
        let new_archive = app_with_paths(&["new.uasset"]).archive.unwrap();
        let _ = update(&mut app, Message::ArchiveOpened(Box::new(Ok(new_archive))));
        assert_eq!(app.context_row, None, "archive swap clears the menu");
    }

    #[test]
    fn archive_opened_locked_clears_context_row() {
        // Opening a locked pak keeps the old archive but enters the key flow; the
        // stale menu index must still be cleared (the "archive swap" trigger covers
        // both the Ok and the Locked transition).
        let mut app = app_with_paths(&["old.uasset"]);
        app.context_row = Some(0);
        let _ = update(
            &mut app,
            Message::ArchiveOpened(Box::new(Err(OpenError::Locked {
                path: PathBuf::from("locked.pak"),
            }))),
        );
        assert_eq!(
            app.context_row, None,
            "entering the key flow clears the menu"
        );
    }

    #[test]
    fn arrow_down_clears_context_row() {
        let mut app = app_with_paths(&["a.txt", "b.txt"]);
        app.context_row = Some(0);
        let _ = handle_tree_key(&mut app, &named_key(Named::ArrowDown));
        assert_eq!(app.context_row, None, "keyboard navigation clears the menu");
    }

    #[test]
    fn escape_clears_context_row() {
        let mut app = app_with_paths(&["file.txt"]);
        app.context_row = Some(0);
        let _ = handle_tree_key(&mut app, &named_key(Named::Escape));
        assert_eq!(app.context_row, None, "Escape clears the menu");
    }

    // ── Message::CopyPathRequested ────────────────────────────────────────────
    #[test]
    fn copy_path_requested_pushes_success_toast_and_closes_menu() {
        let mut app = app_with_paths(&["file.txt"]);
        app.context_row = Some(0);
        let _ = update(&mut app, Message::CopyPathRequested(0));
        assert_eq!(app.toasts.items().len(), 1, "one success toast pushed");
        assert_eq!(app.toasts.items()[0].severity, Severity::Success);
        assert!(
            app.toasts.items()[0].message.contains("Copied"),
            "toast confirms the copy"
        );
        assert_eq!(app.context_row, None, "copy closes the menu");
    }

    #[test]
    fn copy_path_requested_oob_does_nothing() {
        // An index with no resolvable path is a silent no-op — no toast, no panic.
        let mut app = app_with_paths(&["file.txt"]);
        let _ = update(&mut app, Message::CopyPathRequested(999));
        assert!(app.toasts.is_empty(), "no toast when the row has no path");
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    /// Returns a shared `Arc<PakReader>` opened from the real_v8b_uasset fixture.
    ///
    /// The reader is opened exactly once per test binary via `OnceLock`; every
    /// call clones the `Arc`, so 100+ `app_with_paths` calls pay only a single
    /// disk-open.
    fn shared_test_reader() -> std::sync::Arc<paksmith_core::container::pak::PakReader> {
        use std::sync::{Arc, OnceLock};
        static READER: OnceLock<Arc<paksmith_core::container::pak::PakReader>> = OnceLock::new();
        READER
            .get_or_init(|| {
                let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .parent()
                    .unwrap()
                    .parent()
                    .unwrap()
                    .join("tests/fixtures/real_v8b_uasset.pak");
                Arc::new(
                    paksmith_core::container::pak::PakReader::open(path)
                        .expect("open fixture reader"),
                )
            })
            .clone()
    }

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
        let reader = shared_test_reader();
        let archive = LoadedArchive {
            path: PathBuf::from("test.pak"),
            entry_count,
            decrypted: false,
            tree,
            entries,
            reader,
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

    // ── toggle_context_row ────────────────────────────────────────────────────
    #[test]
    fn toggle_context_row_from_none_opens_clicked() {
        assert_eq!(toggle_context_row(None, 3), Some(3));
    }

    #[test]
    fn toggle_context_row_from_other_moves_to_clicked() {
        // Right-clicking a different row moves the menu there (not a toggle-off).
        assert_eq!(toggle_context_row(Some(2), 3), Some(3));
    }

    #[test]
    fn toggle_context_row_same_row_closes() {
        // Second right-press on the same row closes it. Kills `== with !=`.
        assert_eq!(toggle_context_row(Some(3), 3), None);
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

    // ── Kill 2: `< with <=` boundary at exactly row_count ────────────────────
    //
    // The guards are `if i < row_count { ... }`.  A huge index (used above)
    // fails both `<` and `<=`, so it doesn't pin the boundary.  At
    // i == row_count: `<` rejects it (guard fails, selected_row unchanged);
    // `<=` accepts it (mutant sets selected_row = Some(row_count), which is
    // an invalid one-past-the-end index).  The assertion below distinguishes.

    #[test]
    fn row_toggled_exactly_at_row_count_is_rejected() {
        let mut app = app_with_paths(&["Dir/file.txt"]);
        let row_count = app.archive.as_ref().unwrap().tree.visible_rows().len();
        // row_count is the one-past-the-end index — must be out-of-bounds.
        let _ = update(&mut app, Message::RowToggled(row_count));
        assert_ne!(
            app.selected_row,
            Some(row_count),
            "RowToggled(row_count) must not set selected_row to an invalid index"
        );
    }

    #[test]
    fn row_selected_exactly_at_row_count_is_rejected() {
        let mut app = app_with_paths(&["file.txt"]);
        let row_count = app.archive.as_ref().unwrap().tree.visible_rows().len();
        let _ = update(&mut app, Message::RowSelected(row_count));
        assert_ne!(
            app.selected_row,
            Some(row_count),
            "RowSelected(row_count) must not set selected_row to an invalid index"
        );
    }

    // ── Kill 3: `delete !` on About toggle ───────────────────────────────────
    //
    // `Message::About` does `app.about_visible = !app.about_visible`.
    // The `delete !` mutant turns this into a no-op (always stays false).
    // Dispatching twice verifies the toggle: false→true→false.

    #[test]
    fn about_toggles_on_each_dispatch() {
        let mut app = App::default();
        assert!(!app.about_visible, "starts false");
        let _ = update(&mut app, Message::About);
        assert!(
            app.about_visible,
            "first About must set about_visible = true"
        );
        let _ = update(&mut app, Message::About);
        assert!(
            !app.about_visible,
            "second About must toggle about_visible back to false"
        );
    }

    // ── Kill 4: `!= with ==` in handle_tree_key scroll guard ─────────────────
    //
    // `handle_tree_key` returns `Some(task)` only when `selected_row != prev_selected`.
    // The `== ` mutant inverts this: returns Some on NO movement and None on movement.
    // An ArrowDown that MOVES the selection must return Some (scroll was emitted);
    // an ArrowUp at row 0 (no movement) must return None.

    #[test]
    fn arrow_down_that_moves_returns_scroll_task() {
        // Start at row 0; ArrowDown moves to row 1 → selected_row changed → Some.
        let mut app = app_with_paths(&["a.txt", "b.txt"]);
        app.selected_row = Some(0);
        let result = handle_tree_key(&mut app, &named_key(Named::ArrowDown));
        assert!(
            result.is_some(),
            "ArrowDown that moves the selection must return Some(scroll task)"
        );
    }

    #[test]
    fn arrow_up_at_row_zero_returns_none() {
        // At row 0, ArrowUp is a no-op (stays at 0) → no scroll task → None.
        let mut app = app_with_paths(&["a.txt", "b.txt"]);
        app.selected_row = Some(0);
        let result = handle_tree_key(&mut app, &named_key(Named::ArrowUp));
        assert!(
            result.is_none(),
            "ArrowUp at row 0 must return None (no movement, no scroll task)"
        );
    }

    // ── Task 7: tabs + open-asset wiring ─────────────────────────────────────

    #[tokio::test]
    async fn open_asset_creates_loading_tab_then_ready() {
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("tests/fixtures/real_v8b_uasset.pak");
        let loaded = crate::task::open::run(fixture, None).await.unwrap();
        let mut app = App {
            archive: Some(loaded),
            ..App::default()
        };

        let _ = update(&mut app, Message::OpenAsset("Game/Maps/Demo.uasset".into()));
        assert_eq!(app.tabs.open.len(), 1);
        assert!(matches!(
            app.tabs.open[0].content,
            crate::state::tabs::TabContent::Loading
        ));

        // Simulate the async result.
        let reader = app.archive.as_ref().unwrap().reader.clone();
        let load = crate::task::asset::load(reader, "Game/Maps/Demo.uasset".into()).await;
        let current_gen = app.archive_generation;
        let _ = update(
            &mut app,
            Message::AssetLoaded {
                path: "Game/Maps/Demo.uasset".into(),
                load: Box::new(load),
                generation: current_gen,
            },
        );
        assert!(matches!(
            app.tabs.open[0].content,
            crate::state::tabs::TabContent::Ready { .. }
        ));
    }

    #[test]
    fn view_mode_set_changes_active_tab_view() {
        let mut app = app_with_paths(&["a.uasset"]);
        let _ = update(&mut app, Message::OpenAsset("a.uasset".into()));
        let _ = update(
            &mut app,
            Message::ViewModeSet(crate::state::tabs::ViewMode::Hex),
        );
        assert_eq!(app.tabs.open[0].view, crate::state::tabs::ViewMode::Hex);
    }

    #[tokio::test]
    async fn opening_new_archive_clears_tabs() {
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("tests/fixtures/real_v8b_uasset.pak");
        let loaded = crate::task::open::run(fixture.clone(), None).await.unwrap();
        let mut app = App {
            archive: Some(loaded),
            ..App::default()
        };
        let _ = update(&mut app, Message::OpenAsset("Game/Maps/Demo.uasset".into()));
        assert_eq!(app.tabs.open.len(), 1);
        // Re-open (same fixture) → tabs cleared.
        let reloaded = crate::task::open::run(fixture, None).await.unwrap();
        let _ = update(&mut app, Message::ArchiveOpened(Box::new(Ok(reloaded))));
        assert!(
            app.tabs.open.is_empty(),
            "opening an archive must clear stale tabs"
        );
    }

    #[test]
    fn tab_closed_out_of_bounds_is_noop() {
        let mut app = app_with_paths(&["a.uasset"]);
        let _ = update(&mut app, Message::OpenAsset("a.uasset".into()));
        let _ = update(&mut app, Message::TabClosed(99));
        assert_eq!(app.tabs.open.len(), 1);
    }

    #[test]
    fn tab_activated_changes_active() {
        let mut app = app_with_paths(&["a.uasset", "b.uasset"]);
        let _ = update(&mut app, Message::OpenAsset("a.uasset".into()));
        let _ = update(&mut app, Message::OpenAsset("b.uasset".into()));
        // active is 1 (b) — activate 0 (a).
        let _ = update(&mut app, Message::TabActivated(0));
        assert_eq!(app.tabs.active, Some(0));
    }

    #[test]
    fn tab_closed_in_bounds_removes_tab() {
        let mut app = app_with_paths(&["a.uasset", "b.uasset"]);
        let _ = update(&mut app, Message::OpenAsset("a.uasset".into()));
        let _ = update(&mut app, Message::OpenAsset("b.uasset".into()));
        assert_eq!(app.tabs.open.len(), 2);
        let _ = update(&mut app, Message::TabClosed(0));
        assert_eq!(
            app.tabs.open.len(),
            1,
            "in-bounds close must remove the tab"
        );
    }

    #[test]
    fn enter_on_file_returns_open_asset_task() {
        let mut app = app_with_paths(&["Dir/file.txt"]);
        // Expand Dir so file row is visible.
        if let Some(ref mut a) = app.archive {
            a.tree.toggle(0);
        }
        // file row is at index 1 (Dir=0, file.txt=1).
        app.selected_row = Some(1);
        let result = handle_tree_key(&mut app, &named_key(Named::Enter));
        assert!(
            result.is_some(),
            "Enter on a file must return Some(Task) for OpenAsset"
        );
    }

    // ── scroll-offset helpers ────────────────────────────────────────────────

    #[test]
    fn tree_row_pixel_height_equals_text_plus_padding() {
        use crate::theme::tokens;
        // Expected: TEXT_MD (as f32) + 2 * SPACE_XS
        let expected = f32::from(tokens::TEXT_MD) + 2.0 * tokens::SPACE_XS;
        #[allow(clippy::float_cmp)]
        {
            assert_eq!(tree_row_pixel_height(), expected);
        }
        // Adding vertical padding must produce a value strictly greater than just
        // the text size alone — kills a `+ with -` mutant on the padding term.
        assert!(
            tree_row_pixel_height() > f32::from(tokens::TEXT_MD),
            "row height must be taller than bare text — vertical padding is additive"
        );
    }

    #[test]
    fn tree_scroll_offset_row_zero_is_zero() {
        #[allow(clippy::float_cmp)]
        {
            assert_eq!(tree_scroll_offset(0), 0.0_f32);
        }
    }

    #[test]
    fn tree_scroll_offset_row_three_is_three_heights() {
        let h = tree_row_pixel_height();
        // Exact equality: kills `* with /` and `* with +` mutants.
        #[allow(clippy::float_cmp)]
        {
            assert_eq!(tree_scroll_offset(3), 3.0 * h);
        }
        // Monotone: row 3 must be further than row 2 — kills `+ with /`.
        assert!(
            tree_scroll_offset(3) > tree_scroll_offset(2),
            "scroll offset must grow with row index"
        );
    }

    // ── Task 9: hex view wiring ───────────────────────────────────────────────

    /// Build an App whose active tab has `TabContent::Ready` bytes.
    fn app_with_ready_tab(bytes: Vec<u8>) -> App {
        let mut app = app_with_paths(&["a.uasset"]);
        let _ = update(&mut app, Message::OpenAsset("a.uasset".into()));
        // Directly set tab content to Ready (bypasses async I/O).
        app.tabs.set_content(
            "a.uasset",
            crate::state::tabs::TabContent::Ready {
                bytes,
                truncated: false,
                parsed: Err("no parse needed for hex test".into()),
            },
        );
        app
    }

    #[test]
    fn hex_byte_pressed_sets_selection_on_ready_tab() {
        let mut app = app_with_ready_tab(vec![0x00; 32]);
        // Before press: no selection.
        assert!(app.tabs.active_tab().unwrap().hex.selection.is_none());
        let _ = update(&mut app, Message::HexBytePressed(5));
        let sel = app.tabs.active_tab().unwrap().hex.selection;
        assert!(sel.is_some(), "HexBytePressed must set a selection");
        assert_eq!(sel.unwrap().anchor, 5);
        assert_eq!(sel.unwrap().cursor, 5);
        assert!(
            app.tabs.active_tab().unwrap().hex.dragging,
            "HexBytePressed must set dragging = true"
        );
    }

    #[test]
    fn hex_byte_entered_extends_drag_while_dragging() {
        let mut app = app_with_ready_tab(vec![0x00; 32]);
        let _ = update(&mut app, Message::HexBytePressed(3));
        let _ = update(&mut app, Message::HexByteEntered(10));
        let sel = app.tabs.active_tab().unwrap().hex.selection.unwrap();
        assert_eq!(sel.range(), (3, 10), "HexByteEntered must extend cursor");
    }

    #[test]
    fn hex_drag_ended_clears_dragging_flag() {
        let mut app = app_with_ready_tab(vec![0x00; 32]);
        let _ = update(&mut app, Message::HexBytePressed(0));
        assert!(app.tabs.active_tab().unwrap().hex.dragging);
        let _ = update(&mut app, Message::HexDragEnded);
        assert!(
            !app.tabs.active_tab().unwrap().hex.dragging,
            "HexDragEnded must clear dragging"
        );
    }

    #[test]
    fn hex_drag_ended_is_noop_when_no_tab() {
        // No crash when there are no tabs at all.
        let mut app = App::default();
        let _ = update(&mut app, Message::HexDragEnded);
        // If we get here without panic, the test passes.
    }

    #[test]
    fn hex_byte_pressed_on_loading_tab_is_noop() {
        // Pressing on a Loading tab must not set selection (no bytes to select).
        let mut app = app_with_paths(&["a.uasset"]);
        let _ = update(&mut app, Message::OpenAsset("a.uasset".into()));
        // Tab is still Loading (no set_content call).
        assert!(matches!(
            app.tabs.active_tab().unwrap().content,
            crate::state::tabs::TabContent::Loading
        ));
        let _ = update(&mut app, Message::HexBytePressed(0));
        // Selection remains None.
        assert!(app.tabs.active_tab().unwrap().hex.selection.is_none());
    }

    #[test]
    fn active_tab_mut_returns_none_when_no_tabs() {
        let mut tabs = crate::state::tabs::Tabs::default();
        assert!(tabs.active_tab_mut().is_none());
    }

    #[test]
    fn active_tab_mut_matches_active_tab() {
        use crate::state::tabs::Tabs;
        let mut tabs = Tabs::default();
        let _ = tabs.open_or_activate("a.uasset");
        // Verify immutable access first, then mutable access — can't borrow both at once.
        assert_eq!(tabs.active_tab().unwrap().path, "a.uasset");
        assert_eq!(tabs.active_tab_mut().unwrap().path, "a.uasset");
    }

    // ── Task 10: PropToggled wiring ───────────────────────────────────────────

    /// PropToggled inserts the id on first dispatch, then removes it on second
    /// dispatch (toggle semantics). Requires a Ready+Ok tab so the guard passes.
    #[tokio::test]
    async fn prop_toggled_inserts_then_removes_from_expanded() {
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("tests/fixtures/real_v8b_uasset.pak");
        let loaded = crate::task::open::run(fixture, None).await.unwrap();
        let mut app = App {
            archive: Some(loaded),
            ..App::default()
        };

        // Open the tab (Loading state) then simulate the async load completing.
        let _ = update(&mut app, Message::OpenAsset("Game/Maps/Demo.uasset".into()));
        let reader = app.archive.as_ref().unwrap().reader.clone();
        let load = crate::task::asset::load(reader, "Game/Maps/Demo.uasset".into()).await;
        let current_gen = app.archive_generation;
        let _ = update(
            &mut app,
            Message::AssetLoaded {
                path: "Game/Maps/Demo.uasset".into(),
                load: Box::new(load),
                generation: current_gen,
            },
        );

        // Confirm the tab is Ready with a parsed Ok(pkg).
        assert!(
            matches!(
                app.tabs.open[0].content,
                crate::state::tabs::TabContent::Ready { parsed: Ok(_), .. }
            ),
            "tab must be Ready+Ok before toggling"
        );

        // Use an arbitrary node_id — toggle is id-agnostic.
        let test_id: crate::state::property_view::NodeId = 0xDEAD_BEEF_1234_5678;

        // First dispatch: id must be inserted into expanded.
        assert!(
            app.tabs.open[0].expanded.is_empty(),
            "expanded must be empty before first toggle"
        );
        let _ = update(&mut app, Message::PropToggled(test_id));
        assert!(
            app.tabs.open[0].expanded.contains(&test_id),
            "PropToggled must insert the id on first dispatch"
        );

        // Second dispatch: id must be removed (toggle off).
        let _ = update(&mut app, Message::PropToggled(test_id));
        assert!(
            !app.tabs.open[0].expanded.contains(&test_id),
            "PropToggled must remove the id on second dispatch"
        );
    }

    #[test]
    fn prop_toggled_is_noop_on_loading_tab() {
        // A Loading tab (no parsed content) must not crash or mutate expanded.
        let mut app = app_with_paths(&["a.uasset"]);
        let _ = update(&mut app, Message::OpenAsset("a.uasset".into()));
        // Tab is Loading — no set_content call.
        let test_id: crate::state::property_view::NodeId = 42;
        let _ = update(&mut app, Message::PropToggled(test_id));
        assert!(
            app.tabs.open[0].expanded.is_empty(),
            "PropToggled on a Loading tab must be a no-op"
        );
    }

    // ── B8: hex_drag_listener_active predicate ────────────────────────────────

    #[test]
    fn hex_drag_listener_active_true_only_for_hex_view_tab() {
        // A tab in Hex view → true (Kills `== with !=`).
        let mut app = app_with_paths(&["a.uasset"]);
        let _ = update(&mut app, Message::OpenAsset("a.uasset".into()));
        let _ = update(
            &mut app,
            Message::ViewModeSet(crate::state::tabs::ViewMode::Hex),
        );
        assert!(
            hex_drag_listener_active(&app),
            "Hex-view active tab must return true"
        );
    }

    #[test]
    fn hex_drag_listener_active_false_for_properties_view() {
        // Default view is Properties → false.
        let mut app = app_with_paths(&["a.uasset"]);
        let _ = update(&mut app, Message::OpenAsset("a.uasset".into()));
        // Tab defaults to Properties.
        assert_eq!(
            app.tabs.active_tab().unwrap().view,
            crate::state::tabs::ViewMode::Properties
        );
        assert!(
            !hex_drag_listener_active(&app),
            "Properties-view tab must return false"
        );
    }

    #[test]
    fn hex_drag_listener_active_false_when_no_tabs() {
        // No tabs at all → false.
        let app = App::default();
        assert!(
            !hex_drag_listener_active(&app),
            "no active tab must return false"
        );
    }

    #[test]
    fn hex_drag_listener_active_false_for_info_view() {
        let mut app = app_with_paths(&["a.uasset"]);
        let _ = update(&mut app, Message::OpenAsset("a.uasset".into()));
        let _ = update(
            &mut app,
            Message::ViewModeSet(crate::state::tabs::ViewMode::Info),
        );
        assert!(
            !hex_drag_listener_active(&app),
            "Info-view tab must return false"
        );
    }

    #[test]
    fn prop_toggled_is_noop_on_ready_err_tab() {
        // A Ready+Err tab (failed parse) must not toggle expanded.
        let mut app = app_with_paths(&["a.uasset"]);
        let _ = update(&mut app, Message::OpenAsset("a.uasset".into()));
        app.tabs.set_content(
            "a.uasset",
            crate::state::tabs::TabContent::Ready {
                bytes: vec![],
                truncated: false,
                parsed: Err("no parse".into()),
            },
        );
        let test_id: crate::state::property_view::NodeId = 99;
        let _ = update(&mut app, Message::PropToggled(test_id));
        assert!(
            app.tabs.open[0].expanded.is_empty(),
            "PropToggled on a Ready+Err tab must be a no-op"
        );
    }

    // ── archive_generation guard (Copilot race fix) ───────────────────────────

    #[test]
    fn asset_loaded_with_stale_generation_is_ignored() {
        use crate::state::tabs::TabContent;
        let mut app = app_with_paths(&["a.uasset"]);
        app.archive_generation = 5;
        let _ = app.tabs.open_or_activate("a.uasset"); // Loading tab
        let load = crate::task::asset::AssetLoad {
            bytes: vec![1, 2, 3],
            truncated: false,
            parsed: Err("x".into()),
        };
        let _ = update(
            &mut app,
            Message::AssetLoaded {
                path: "a.uasset".into(),
                load: Box::new(load),
                generation: 4, // stale
            },
        );
        assert!(
            matches!(app.tabs.open[0].content, TabContent::Loading),
            "stale-generation AssetLoaded must be ignored (tab stays Loading)"
        );
    }

    #[test]
    fn asset_loaded_with_current_generation_applies() {
        use crate::state::tabs::TabContent;
        let mut app = app_with_paths(&["a.uasset"]);
        app.archive_generation = 5;
        let _ = app.tabs.open_or_activate("a.uasset");
        let load = crate::task::asset::AssetLoad {
            bytes: vec![1, 2, 3],
            truncated: false,
            parsed: Err("x".into()),
        };
        let _ = update(
            &mut app,
            Message::AssetLoaded {
                path: "a.uasset".into(),
                load: Box::new(load),
                generation: 5, // current
            },
        );
        assert!(
            matches!(app.tabs.open[0].content, TabContent::Ready { .. }),
            "current-generation AssetLoaded must populate the tab"
        );
    }

    #[test]
    fn asset_loaded_decodable_texture_populates_path_keyed_tab() {
        use std::sync::Arc;
        // Drives the classify+dispatch branch, which looks up the destination
        // tab by `t.path == path`. With the `==`->`!=` mutant the sole matching
        // tab is skipped, so no texture metadata is stored — `mips` stays empty.
        let mut app = app_with_paths(&["Game/T_Rock.uasset"]);
        let _ = app.tabs.open_or_activate("Game/T_Rock.uasset");
        let mp = paksmith_core::testing::uasset::build_minimal_with_decodable_texture2d();
        let pkg =
            paksmith_core::asset::Package::read_from(&mp.bytes, None, None, "Game/T_Rock.uasset")
                .expect("fixture must parse");
        let load = crate::task::asset::AssetLoad {
            bytes: mp.bytes.clone(),
            truncated: false,
            parsed: Ok(Arc::new(pkg)),
        };
        let generation = app.archive_generation;
        let _ = update(
            &mut app,
            Message::AssetLoaded {
                path: "Game/T_Rock.uasset".into(),
                load: Box::new(load),
                generation,
            },
        );
        assert!(
            !app.tabs.open[0].texture.mips.is_empty(),
            "a decodable-texture load must populate texture.mips on the path-keyed tab"
        );
        // Ordering guard: the handler must populate the decodable-mip cache
        // BEFORE `pick_view_after_load` reads it. If the two are reordered, the
        // cache is empty when `pick_view` runs and the view stays Properties.
        assert_eq!(
            app.tabs.open[0].view,
            crate::state::tabs::ViewMode::Texture,
            "a decodable-texture load must promote the tab to Texture view"
        );
    }

    #[test]
    fn asset_loaded_non_texture_leaves_mips_empty_and_view_properties() {
        use std::sync::Arc;
        // A non-texture Ok load must classify as `None`: the decodable-mip cache
        // stays empty and the view is not promoted. This pins the classify→None
        // correctness now that `texture_available` no longer re-classifies.
        let mut app = app_with_paths(&["Game/Foo.uasset"]);
        let _ = app.tabs.open_or_activate("Game/Foo.uasset");
        let mp = paksmith_core::testing::uasset::build_minimal_ue4_27();
        let pkg =
            paksmith_core::asset::Package::read_from(&mp.bytes, None, None, "Game/Foo.uasset")
                .expect("fixture must parse");
        let load = crate::task::asset::AssetLoad {
            bytes: mp.bytes.clone(),
            truncated: false,
            parsed: Ok(Arc::new(pkg)),
        };
        let generation = app.archive_generation;
        let _ = update(
            &mut app,
            Message::AssetLoaded {
                path: "Game/Foo.uasset".into(),
                load: Box::new(load),
                generation,
            },
        );
        assert!(
            app.tabs.open[0].texture.mips.is_empty(),
            "a non-texture load must leave texture.mips empty"
        );
        assert_eq!(
            app.tabs.open[0].view,
            crate::state::tabs::ViewMode::Properties,
            "a non-texture load must not promote the tab to Texture view"
        );
    }

    #[test]
    fn asset_loaded_non_texture_over_texture_clears_mip_cache() {
        use std::sync::Arc;
        // Integration guard for the no-stale-true invariant through the full
        // `update` path: a texture load populates the decodable-mip cache, then a
        // second `AssetLoaded` for the SAME path with non-texture content must
        // clear it (via `set_content`'s reset). Pins the reset inside the handler
        // context, not just the direct-`set_content` unit test. The view stays
        // `Texture` here — `pick_view_after_load` only promotes from `Properties`,
        // never demotes; auto-demote-on-reload is the deferred Phase 7c seam.
        let mut app = app_with_paths(&["Game/Reload.uasset"]);
        let _ = app.tabs.open_or_activate("Game/Reload.uasset");
        let generation = app.archive_generation;

        let tex = paksmith_core::testing::uasset::build_minimal_with_decodable_texture2d();
        let tex_pkg =
            paksmith_core::asset::Package::read_from(&tex.bytes, None, None, "Game/Reload.uasset")
                .expect("texture fixture must parse");
        let _ = update(
            &mut app,
            Message::AssetLoaded {
                path: "Game/Reload.uasset".into(),
                load: Box::new(crate::task::asset::AssetLoad {
                    bytes: tex.bytes.clone(),
                    truncated: false,
                    parsed: Ok(Arc::new(tex_pkg)),
                }),
                generation,
            },
        );
        assert!(
            !app.tabs.open[0].texture.mips.is_empty(),
            "precondition: the texture load must populate the mip cache"
        );

        let plain = paksmith_core::testing::uasset::build_minimal_ue4_27();
        let plain_pkg = paksmith_core::asset::Package::read_from(
            &plain.bytes,
            None,
            None,
            "Game/Reload.uasset",
        )
        .expect("non-texture fixture must parse");
        let _ = update(
            &mut app,
            Message::AssetLoaded {
                path: "Game/Reload.uasset".into(),
                load: Box::new(crate::task::asset::AssetLoad {
                    bytes: plain.bytes.clone(),
                    truncated: false,
                    parsed: Ok(Arc::new(plain_pkg)),
                }),
                generation,
            },
        );
        assert!(
            app.tabs.open[0].texture.mips.is_empty(),
            "reloading non-texture content over a texture must clear the mip cache"
        );
        // Pin the no-demote contract: `pick_view_after_load` only promotes from
        // `Properties`, so a tab already in `Texture` view stays there even though
        // the new content has no texture. Auto-demote-on-reload is the deferred
        // Phase 7c seam; a future demotion path must not regress this silently.
        assert_eq!(
            app.tabs.open[0].view,
            crate::state::tabs::ViewMode::Texture,
            "reload must not auto-demote a tab already in Texture view (Phase 7c seam)"
        );
    }

    #[test]
    fn asset_loaded_after_tab_close_same_generation_is_noop() {
        use std::sync::Arc;
        // Race guard: the user opens a file, then closes the tab while the load is
        // still in flight. The late `AssetLoaded` arrives with the SAME generation
        // (no archive swap), so the generation fence does not drop it — instead the
        // handler's path lookups must all no-op against the now-closed tab. Pins
        // that the late load neither re-opens the tab nor panics.
        let mut app = app_with_paths(&["Game/Gone.uasset"]);
        let _ = app.tabs.open_or_activate("Game/Gone.uasset");
        app.tabs.close(0);
        assert!(app.tabs.open.is_empty(), "precondition: the tab is closed");

        let mp = paksmith_core::testing::uasset::build_minimal_with_decodable_texture2d();
        let pkg =
            paksmith_core::asset::Package::read_from(&mp.bytes, None, None, "Game/Gone.uasset")
                .expect("fixture must parse");
        let generation = app.archive_generation;
        let _ = update(
            &mut app,
            Message::AssetLoaded {
                path: "Game/Gone.uasset".into(),
                load: Box::new(crate::task::asset::AssetLoad {
                    bytes: mp.bytes.clone(),
                    truncated: false,
                    parsed: Ok(Arc::new(pkg)),
                }),
                generation,
            },
        );
        assert!(
            app.tabs.open.is_empty(),
            "a late AssetLoaded for a closed tab must not re-open it"
        );
    }

    #[tokio::test]
    async fn opening_archive_bumps_generation() {
        // ArchiveOpened(Ok) must advance the generation so prior in-flight loads go stale.
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("tests/fixtures/real_v8b_uasset.pak");
        let mut app = App::default();
        let before = app.archive_generation;
        let loaded = crate::task::open::run(fixture, None).await.unwrap();
        let _ = update(&mut app, Message::ArchiveOpened(Box::new(Ok(loaded))));
        assert_eq!(
            app.archive_generation,
            before.wrapping_add(1),
            "ArchiveOpened(Ok) must bump archive_generation by 1"
        );
    }

    #[test]
    fn opening_locked_archive_bumps_generation() {
        // ArchiveOpened(Locked) also clears tabs, so it must bump the generation
        // too — a load in flight when an encrypted archive is opened goes stale.
        let mut app = App::default();
        let before = app.archive_generation;
        let _ = update(
            &mut app,
            Message::ArchiveOpened(Box::new(Err(crate::state::archive::OpenError::Locked {
                path: std::path::PathBuf::from("x.pak"),
            }))),
        );
        assert_eq!(
            app.archive_generation,
            before.wrapping_add(1),
            "ArchiveOpened(Locked) must bump archive_generation by 1"
        );
    }

    // ── open_path_for_row resolver ────────────────────────────────────────────

    #[test]
    fn open_path_for_row_resolves_file_row_path() {
        let mut app = app_with_paths(&["Dir/file.txt"]);
        // Row 0 is "Dir" (a dir row, collapsed). Expand it so "Dir/file.txt" appears.
        if let Some(ref mut a) = app.archive {
            a.tree.toggle(0); // expand Dir → file row appears at index 1
        }
        // Dir row (index 0) has no path → None.
        assert_eq!(
            open_path_for_row(&app, 0),
            None,
            "dir row must resolve to None"
        );
        // File row (index 1) has the path → Some.
        assert_eq!(
            open_path_for_row(&app, 1),
            Some("Dir/file.txt".to_string()),
            "file row must resolve to its full path"
        );
        // Out-of-bounds index → None (no panic, no path).
        assert_eq!(
            open_path_for_row(&app, 999),
            None,
            "out-of-bounds index must resolve to None"
        );
    }

    #[test]
    fn open_path_for_row_returns_none_without_archive() {
        // No archive loaded → always None, regardless of index.
        let app = App::default();
        assert_eq!(open_path_for_row(&app, 0), None);
    }

    // ── Task 4: texture message wiring ────────────────────────────────────────

    /// Build an App whose active tab is in `TabContent::Ready` with a parsed
    /// texture `Package` (synthetic, from `__test_utils`).
    ///
    /// Mirrors the `AssetLoaded` handler's postcondition: it classifies the
    /// package and populates `tab.texture.mips` from `classify_texture`, so
    /// `texture_available` reads `true` and a mip-0 decode passes the
    /// `mip < mips.len()` guard. Tests needing a specific mip configuration
    /// (e.g. multi-mip selection) may still seed `tab.texture.mips` directly to
    /// override the single-mip fixture default.
    fn app_with_open_texture_tab() -> App {
        use crate::state::tabs::TabContent;
        use std::sync::Arc;
        let mp = paksmith_core::testing::uasset::build_minimal_with_decodable_texture2d();
        let pkg =
            paksmith_core::asset::Package::read_from(&mp.bytes, None, None, "Game/T_Rock.uasset")
                .expect("build_minimal_with_decodable_texture2d must parse");
        // Classify before moving `pkg` into the Arc so the helper can populate
        // the decodable-mip cache exactly as the `AssetLoaded` handler does.
        let info = paksmith_core::asset::classify_texture(&pkg)
            .expect("the fixture texture must classify as decodable");
        let mut app = App::default();
        let _ = app.tabs.open_or_activate("Game/T_Rock.uasset");
        app.tabs.set_content(
            "Game/T_Rock.uasset",
            TabContent::Ready {
                bytes: mp.bytes.clone(),
                truncated: false,
                parsed: Ok(Arc::new(pkg)),
            },
        );
        // Mirror the `AssetLoaded` handler: `set_content` reset `texture` to
        // default (empty `mips`), so restate the post-classify cache here. Without
        // this the tab would be a texture tab with an empty mip list — an
        // unrealistic state in which `texture_available` is false and a mip-0
        // decode would be dropped by the `mip < mips.len()` guard. The just-opened
        // path is the active tab (`open_or_activate` activated it; `set_content`
        // does not change `active`).
        let tab = app
            .tabs
            .active_tab_mut()
            .expect("the just-opened texture tab must be active");
        tab.texture.export_idx = info.export_idx;
        tab.texture.mips = info.mips;
        app
    }

    #[test]
    fn texture_decoded_stale_generation_is_dropped() {
        use crate::state::texture_view::DecodedMip;
        let mut app = app_with_open_texture_tab();
        app.archive_generation = 3;
        let stale = 2u64;
        let _ = update(
            &mut app,
            Message::TextureDecoded {
                path: "Game/T_Rock.uasset".into(),
                mip: 0,
                result: Ok(DecodedMip {
                    width: 2,
                    height: 2,
                    rgba: vec![0u8; 16],
                }),
                generation: stale,
            },
        );
        assert!(
            app.tabs.active_tab().unwrap().texture.decoded.is_none(),
            "a stale-generation decode must be ignored"
        );
    }

    #[test]
    fn texture_decoded_stale_mip_is_dropped() {
        use crate::state::texture_view::DecodedMip;
        let mut app = app_with_open_texture_tab();
        // Give the tab ≥2 mips so the delivered mip 1 is *in-bounds*: this test
        // pins the stale-mip guard (`selected_mip == mip`), not the bounds guard
        // (`mip < mips.len()`), which would otherwise drop mip 1 for the wrong
        // reason on a single-mip fixture.
        app.tabs.active_tab_mut().unwrap().texture.mips = vec![(4, 4), (2, 2)];
        // selected_mip defaults to 0; deliver a current-generation decode for mip 1.
        assert_eq!(
            app.tabs.active_tab().unwrap().texture.selected_mip,
            0,
            "selected_mip must start at 0"
        );
        let current_gen = app.archive_generation;
        let _ = update(
            &mut app,
            Message::TextureDecoded {
                path: "Game/T_Rock.uasset".into(),
                mip: 1,
                result: Ok(DecodedMip {
                    width: 2,
                    height: 2,
                    rgba: vec![0u8; 16],
                }),
                generation: current_gen,
            },
        );
        assert!(
            app.tabs.active_tab().unwrap().texture.decoded.is_none(),
            "a decode for a non-selected mip must be dropped even when generation matches"
        );
    }

    #[test]
    fn texture_decoded_current_generation_writes_decoded() {
        use crate::state::texture_view::DecodedMip;
        let mut app = app_with_open_texture_tab();
        app.archive_generation = 3;
        let mip = DecodedMip {
            width: 4,
            height: 4,
            rgba: vec![255u8; 64],
        };
        let _ = update(
            &mut app,
            Message::TextureDecoded {
                path: "Game/T_Rock.uasset".into(),
                mip: 0,
                result: Ok(mip.clone()),
                generation: 3,
            },
        );
        assert_eq!(
            app.tabs.active_tab().unwrap().texture.decoded.as_ref(),
            Some(&mip),
            "a current-generation decode must populate texture.decoded"
        );
    }

    #[test]
    fn texture_decoded_after_tab_close_same_generation_is_noop() {
        use crate::state::texture_view::DecodedMip;
        // Race guard mirroring `asset_loaded_after_tab_close_same_generation_is_noop`:
        // a decode finishes after its tab was closed. The result carries the SAME
        // generation (no archive swap), so the fence does not drop it — the
        // handler's path lookup must no-op against the closed tab. Pins no re-open
        // and no panic.
        let mut app = app_with_open_texture_tab();
        app.tabs.close(0);
        assert!(app.tabs.open.is_empty(), "precondition: the tab is closed");
        let generation = app.archive_generation;
        let _ = update(
            &mut app,
            Message::TextureDecoded {
                path: "Game/T_Rock.uasset".into(),
                mip: 0,
                result: Ok(DecodedMip {
                    width: 4,
                    height: 4,
                    rgba: vec![255u8; 64],
                }),
                generation,
            },
        );
        assert!(
            app.tabs.open.is_empty(),
            "a late TextureDecoded for a closed tab must not re-open it"
        );
    }

    #[test]
    fn texture_decoded_after_content_reset_is_dropped() {
        use crate::state::texture_view::DecodedMip;
        // A mip-0 decode is dispatched, then the tab's content is swapped/reset
        // (e.g. an in-place reload) before it lands. `set_content` resets the
        // texture cache to default (`mips` empty, `selected_mip` 0), so the
        // arriving result still satisfies `selected_mip == mip` (both 0) — only
        // the `mip < mips.len()` bound (0 < 0 is false) stops it from being
        // written onto the now-non-texture tab. Same archive generation, so the
        // generation fence does NOT cover this; the bound guard is what does.
        let mut app = app_with_open_texture_tab();
        let generation = app.archive_generation;
        // Reset the tab's content in place (mirrors a reload): texture → default.
        app.tabs.set_content(
            "Game/T_Rock.uasset",
            crate::state::tabs::TabContent::Loading,
        );
        assert!(
            app.tabs.active_tab().unwrap().texture.mips.is_empty(),
            "precondition: set_content reset the mip cache to empty"
        );
        let _ = update(
            &mut app,
            Message::TextureDecoded {
                path: "Game/T_Rock.uasset".into(),
                mip: 0,
                result: Ok(DecodedMip {
                    width: 4,
                    height: 4,
                    rgba: vec![255u8; 64],
                }),
                generation,
            },
        );
        assert!(
            app.tabs.active_tab().unwrap().texture.decoded.is_none(),
            "a decode landing after a content reset must not write onto the reset tab"
        );
    }

    #[test]
    fn texture_channel_toggle_updates_active_tab_state() {
        use crate::state::texture_view::Channel;
        let mut app = app_with_open_texture_tab();
        let before = app.tabs.active_tab().unwrap().texture.channels.r;
        let _ = update(
            &mut app,
            Message::TextureChannelToggled {
                channel: Channel::R,
            },
        );
        assert_ne!(
            app.tabs.active_tab().unwrap().texture.channels.r,
            before,
            "TextureChannelToggled must flip the channel flag on the active tab"
        );
    }

    #[test]
    fn texture_mip_selected_updates_selected_mip() {
        let mut app = app_with_open_texture_tab();
        // Set up mips so mip index 1 is valid.
        if let Some(tab) = app.tabs.active_tab_mut() {
            tab.texture.mips = vec![(64, 64), (32, 32)];
        }
        let _ = update(&mut app, Message::TextureMipSelected(1));
        assert_eq!(
            app.tabs.active_tab().unwrap().texture.selected_mip,
            1,
            "TextureMipSelected must update selected_mip on the active tab"
        );
    }

    #[test]
    fn texture_mip_selected_out_of_range_is_ignored() {
        // A stale / out-of-range index (e.g. a pick_list message raced against a
        // content swap) must not commit an invalid `selected_mip` that would
        // wedge the tab. The handler ignores anything at or past the current mip
        // list length. Test the exact boundary `m == mips.len()` (the first
        // invalid index) so the `>=` guard is pinned tight — paired with the
        // valid `m = 1` case in `texture_mip_selected_updates_selected_mip`, this
        // kills the `>=` → `>` / `<` / `<=` mutants and the guard deletion.
        let mut app = app_with_open_texture_tab();
        if let Some(tab) = app.tabs.active_tab_mut() {
            tab.texture.mips = vec![(64, 64), (32, 32)];
            tab.texture.selected_mip = 0;
        }
        let len = app.tabs.active_tab().unwrap().texture.mips.len();
        let _ = update(&mut app, Message::TextureMipSelected(len));
        assert_eq!(
            app.tabs.active_tab().unwrap().texture.selected_mip,
            0,
            "a mip index == mips.len() (first out-of-range) must leave selected_mip unchanged"
        );
    }

    #[test]
    fn texture_mip_selected_keeps_previous_decoded_visible() {
        use crate::state::texture_view::DecodedMip;
        let mut app = app_with_open_texture_tab();
        // Seed a decoded mip and a second selectable mip.
        if let Some(tab) = app.tabs.active_tab_mut() {
            tab.texture.mips = vec![(64, 64), (32, 32)];
            tab.texture.decoded = Some(DecodedMip {
                width: 64,
                height: 64,
                rgba: vec![255u8; 64 * 64 * 4],
            });
        }
        let _ = update(&mut app, Message::TextureMipSelected(1));
        assert!(
            app.tabs.active_tab().unwrap().texture.decoded.is_some(),
            "selecting a new mip must keep the previous decoded image visible \
             until the new mip finishes decoding"
        );
    }

    #[test]
    fn texture_mip_selected_clears_prior_error() {
        let mut app = app_with_open_texture_tab();
        if let Some(tab) = app.tabs.active_tab_mut() {
            tab.texture.mips = vec![(64, 64), (32, 32)];
            tab.texture.error = Some("stale decode failure from a prior mip".into());
        }
        let _ = update(&mut app, Message::TextureMipSelected(1));
        assert!(
            app.tabs.active_tab().unwrap().texture.error.is_none(),
            "selecting a new mip must clear the prior mip's error slate"
        );
    }

    /// The masked RGBA bytes carried by a texture tab's cached render handle,
    /// or `None` if no handle is cached.
    fn render_pixels(tex: &crate::state::texture_view::TextureState) -> Option<Vec<u8>> {
        tex.render.as_ref().map(|h| match h {
            iced::widget::image::Handle::Rgba { pixels, .. } => pixels.as_ref().to_vec(),
            other => panic!("expected an Rgba handle, got {other:?}"),
        })
    }

    /// The `Id` of a texture tab's cached render handle, or `None` if uncached.
    /// Returned opaquely (the `image::Id` type lives behind iced's `advanced`
    /// feature, which the GUI does not enable) — callers only compare it.
    fn render_id(
        tex: &crate::state::texture_view::TextureState,
    ) -> Option<impl PartialEq + std::fmt::Debug + use<>> {
        tex.render.as_ref().map(iced::widget::image::Handle::id)
    }

    #[test]
    fn texture_decoded_rebuilds_render_cache() {
        use crate::state::texture_view::{DecodedMip, mask_rgba};
        let mut app = app_with_open_texture_tab();
        app.archive_generation = 5;
        let mip = DecodedMip {
            width: 1,
            height: 1,
            rgba: vec![10, 20, 30, 40],
        };
        let _ = update(
            &mut app,
            Message::TextureDecoded {
                path: "Game/T_Rock.uasset".into(),
                mip: 0,
                result: Ok(mip.clone()),
                generation: 5,
            },
        );
        let tex = &app.tabs.active_tab().unwrap().texture;
        assert_eq!(
            render_pixels(tex).as_deref(),
            Some(mask_rgba(&mip.rgba, tex.channels).as_slice()),
            "a current-generation decode must rebuild the render cache"
        );
    }

    #[test]
    fn texture_channel_toggle_rebuilds_render_cache() {
        use crate::state::texture_view::{Channel, DecodedMip};
        let mut app = app_with_open_texture_tab();
        if let Some(tab) = app.tabs.active_tab_mut() {
            tab.texture.decoded = Some(DecodedMip {
                width: 1,
                height: 1,
                rgba: vec![10, 20, 30, 40],
            });
            tab.texture.recompute_render();
        }
        let pixels_before = render_pixels(&app.tabs.active_tab().unwrap().texture);
        let id_before = render_id(&app.tabs.active_tab().unwrap().texture);
        let _ = update(
            &mut app,
            Message::TextureChannelToggled {
                channel: Channel::G,
            },
        );
        let tex = &app.tabs.active_tab().unwrap().texture;
        assert_ne!(
            pixels_before,
            render_pixels(tex),
            "toggling a channel must re-mask the render cache (not leave it stale)"
        );
        assert_ne!(
            id_before,
            render_id(tex),
            "the rebuilt handle must take a fresh Id so iced re-uploads it"
        );
    }

    #[test]
    fn texture_mip_select_keeps_render_until_new_decode_lands() {
        // Guards the recompute-on-write design against the keyed-cache bug:
        // selecting a mip leaves `decoded` (and thus `render`) on the old mip
        // until the new mip's decode arrives, at which point `render` must flip
        // to the NEW bytes — never serve the stale old-mip cache for the new mip.
        use crate::state::texture_view::{DecodedMip, mask_rgba};
        let mut app = app_with_open_texture_tab();
        app.archive_generation = 7;
        if let Some(tab) = app.tabs.active_tab_mut() {
            tab.texture.mips = vec![(1, 1), (1, 1)];
            tab.texture.decoded = Some(DecodedMip {
                width: 1,
                height: 1,
                rgba: vec![10, 20, 30, 40],
            });
            tab.texture.recompute_render();
        }
        let mip0_id = render_id(&app.tabs.active_tab().unwrap().texture);
        let mip0_pixels = render_pixels(&app.tabs.active_tab().unwrap().texture);

        // Select mip 1 — decoded/render must stay on mip 0 (C1: keep old image).
        let _ = update(&mut app, Message::TextureMipSelected(1));
        assert_eq!(
            render_id(&app.tabs.active_tab().unwrap().texture),
            mip0_id,
            "mip select must not rebuild the render handle before the new mip decodes"
        );

        // Mip-1 decode lands with different bytes — render must now reflect mip 1.
        let mip1 = DecodedMip {
            width: 1,
            height: 1,
            rgba: vec![99, 88, 77, 66],
        };
        let _ = update(
            &mut app,
            Message::TextureDecoded {
                path: "Game/T_Rock.uasset".into(),
                mip: 1,
                result: Ok(mip1.clone()),
                generation: 7,
            },
        );
        let tex = &app.tabs.active_tab().unwrap().texture;
        assert_eq!(
            render_pixels(tex).as_deref(),
            Some(mask_rgba(&mip1.rgba, tex.channels).as_slice()),
            "once mip 1 decodes, render must reflect mip 1, not the stale mip-0 cache"
        );
        assert_ne!(
            render_pixels(tex),
            mip0_pixels,
            "the mip-1 render must differ from the mip-0 bytes"
        );
    }

    #[test]
    fn texture_decode_error_keeps_last_good_decoded() {
        // C18: a decode error for the *selected* mip must keep the previously
        // decoded image (so the viewer doesn't blank the last-good mip) and only
        // set `error`. The Err arm must NOT rebuild the render cache — `decoded`
        // is unchanged, so the cached handle's Id is preserved and iced skips a
        // needless GPU re-upload of the same pixels.
        use crate::state::texture_view::DecodedMip;
        let mut app = app_with_open_texture_tab();
        app.archive_generation = 9;
        let mip0 = DecodedMip {
            width: 1,
            height: 1,
            rgba: vec![10, 20, 30, 40],
        };
        if let Some(tab) = app.tabs.active_tab_mut() {
            tab.texture.decoded = Some(mip0.clone());
            tab.texture.recompute_render();
        }
        let id_before = render_id(&app.tabs.active_tab().unwrap().texture);

        // The currently selected mip (0) fails to decode.
        let _ = update(
            &mut app,
            Message::TextureDecoded {
                path: "Game/T_Rock.uasset".into(),
                mip: 0,
                result: Err("decode blew up".to_string()),
                generation: 9,
            },
        );

        let tex = &app.tabs.active_tab().unwrap().texture;
        assert_eq!(
            tex.decoded.as_ref(),
            Some(&mip0),
            "a failed decode for the selected mip must retain the last-good decoded image (C18)"
        );
        assert_eq!(
            tex.error.as_deref(),
            Some("decode blew up"),
            "a failed decode must surface the error message"
        );
        assert_eq!(
            render_id(tex),
            id_before,
            "the Err arm must not rebuild the render cache (decoded unchanged → no re-upload)"
        );
    }

    #[test]
    fn texture_zoom_in_increases_zoom() {
        let mut app = app_with_open_texture_tab();
        let before = app.tabs.active_tab().unwrap().texture.zoom;
        let _ = update(&mut app, Message::TextureZoomIn);
        assert!(
            app.tabs.active_tab().unwrap().texture.zoom > before,
            "TextureZoomIn must increase zoom"
        );
    }

    #[test]
    fn texture_zoom_out_decreases_zoom() {
        let mut app = app_with_open_texture_tab();
        // Start at a non-minimum zoom so zoom-out has room to move.
        if let Some(tab) = app.tabs.active_tab_mut() {
            tab.texture.zoom = 4.0;
        }
        let _ = update(&mut app, Message::TextureZoomOut);
        assert!(
            app.tabs.active_tab().unwrap().texture.zoom < 4.0,
            "TextureZoomOut must decrease zoom"
        );
    }

    #[test]
    fn texture_zoom_in_disables_fit_to_window() {
        let mut app = app_with_open_texture_tab();
        // Default state is fit_to_window = true.
        assert!(app.tabs.active_tab().unwrap().texture.fit_to_window);
        let _ = update(&mut app, Message::TextureZoomIn);
        assert!(
            !app.tabs.active_tab().unwrap().texture.fit_to_window,
            "manual zoom-in must exit fit-to-window mode"
        );
    }

    #[test]
    fn texture_zoom_out_disables_fit_to_window() {
        let mut app = app_with_open_texture_tab();
        if let Some(tab) = app.tabs.active_tab_mut() {
            tab.texture.zoom = 4.0;
            tab.texture.fit_to_window = true;
        }
        let _ = update(&mut app, Message::TextureZoomOut);
        assert!(
            !app.tabs.active_tab().unwrap().texture.fit_to_window,
            "manual zoom-out must exit fit-to-window mode"
        );
    }

    #[test]
    fn texture_fit_to_window_re_enables_fit() {
        let mut app = app_with_open_texture_tab();
        // First drop into manual-zoom mode.
        let _ = update(&mut app, Message::TextureZoomIn);
        assert!(!app.tabs.active_tab().unwrap().texture.fit_to_window);
        let _ = update(&mut app, Message::TextureFitToWindow);
        assert!(
            app.tabs.active_tab().unwrap().texture.fit_to_window,
            "TextureFitToWindow must restore fit-to-window mode"
        );
    }

    // ── Export As… update-arm tests ───────────────────────────────────────────

    fn minimal_export_menu() -> ExportMenu {
        ExportMenu {
            path: "a.uasset".into(),
            choices: vec![ExportChoice::Raw],
        }
    }

    fn app_with_parsed_tab() -> App {
        let mut app = app_with_paths(&["a.uasset"]);
        let _ = update(&mut app, Message::OpenAsset("a.uasset".into()));
        // Parse a known-good fixture so parsed_package returns Some.
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("tests/fixtures/minimal_uasset_v5.uasset");
        let bytes = std::fs::read(&fixture).expect("read minimal_uasset_v5.uasset");
        let pkg = paksmith_core::asset::Package::read_from(&bytes, None, None, "a.uasset")
            .expect("parse minimal_uasset_v5.uasset");
        app.tabs.set_content(
            "a.uasset",
            crate::state::tabs::TabContent::Ready {
                bytes,
                truncated: false,
                parsed: Ok(std::sync::Arc::new(pkg)),
            },
        );
        app
    }

    #[test]
    fn export_as_open_parsed_tab_opens_picker_synchronously() {
        let mut app = app_with_parsed_tab();
        app.context_row = Some(0);
        let _ = update(&mut app, Message::ExportAsRequested(0));
        let menu = app
            .export_menu
            .expect("picker must open for a parsed open tab");
        assert_eq!(menu.path, "a.uasset");
        assert_eq!(
            menu.choices.last(),
            Some(&ExportChoice::Raw),
            "the picker must always end with Raw"
        );
    }

    #[test]
    fn export_as_cold_row_shows_raw_picker_immediately() {
        // An unopened row has no parsed tab, so Export As… takes the cold path: the
        // picker must appear at once with Raw (which needs no parse), to be enriched
        // with typed formats when the async enumeration lands.
        let mut app = app_with_paths(&["a.uasset"]); // row 0, never opened → parsed_package None
        app.context_row = Some(0);
        let _ = update(&mut app, Message::ExportAsRequested(0));
        let menu = app
            .export_menu
            .expect("cold Export As… must open a picker immediately");
        assert_eq!(menu.path, "a.uasset");
        assert_eq!(
            menu.choices,
            vec![ExportChoice::Raw],
            "the cold picker shows Raw only until async enrichment replaces it"
        );
    }

    #[test]
    fn export_formats_ready_stale_generation_dropped() {
        let mut app = App::default();
        let _ = update(
            &mut app,
            Message::ExportFormatsReady {
                path: "x.uasset".into(),
                formats: vec![],
                generation: 99, // != default 0
            },
        );
        assert!(
            app.export_menu.is_none(),
            "stale-generation enumeration must be dropped"
        );
    }

    /// A single typed format for enrichment tests, so the enriched menu
    /// (`[Typed, Raw]`) is observably different from the pre-set Raw-only picker —
    /// otherwise an empty `formats` yields `[Raw]` and the test can't tell
    /// enrichment from a no-op (or a dropped message).
    fn one_typed_format() -> paksmith_core::export::ExportFormat {
        paksmith_core::export::ExportFormat {
            payload_idx: 0,
            extension: "json",
        }
    }

    #[test]
    fn export_formats_ready_enriches_open_cold_picker() {
        // The cold path opens a Raw-only picker, then the async enumeration enriches
        // it IN PLACE with the typed formats. Precondition mirrors the real flow: the
        // Raw-only picker is already open for this path when the enumeration lands.
        // A non-empty format list must observably change the menu — proving both the
        // enrichment AND the generation fence ahead of it actually ran.
        let mut app = app_with_paths(&["a.uasset"]);
        app.context_row = Some(0);
        let archive_gen = app.archive_generation;
        app.export_menu = Some(minimal_export_menu()); // Raw-only, path "a.uasset"
        let _ = update(
            &mut app,
            Message::ExportFormatsReady {
                path: "a.uasset".into(),
                formats: vec![one_typed_format()],
                generation: archive_gen,
            },
        );
        let menu = app
            .export_menu
            .expect("an open picker must remain open after enrichment");
        assert_eq!(menu.path, "a.uasset");
        assert_eq!(
            menu.choices,
            vec![
                ExportChoice::Typed {
                    payload_idx: 0,
                    extension: "json",
                },
                ExportChoice::Raw,
            ],
            "enrichment must replace the Raw-only menu with the typed formats + Raw"
        );
    }

    #[test]
    fn export_formats_ready_for_other_path_does_not_clobber_open_picker() {
        // An enumeration for a different entry must not replace the picker currently
        // open for "a.uasset" — neither its path nor its choices.
        let mut app = app_with_paths(&["a.uasset"]);
        app.context_row = Some(0);
        let archive_gen = app.archive_generation;
        app.export_menu = Some(minimal_export_menu()); // Raw-only, path "a.uasset"
        let _ = update(
            &mut app,
            Message::ExportFormatsReady {
                path: "other.uasset".into(),
                formats: vec![one_typed_format()],
                generation: archive_gen,
            },
        );
        let menu = app
            .export_menu
            .expect("the open picker must survive a mismatched enumeration");
        assert_eq!(
            menu.path, "a.uasset",
            "an enumeration for a different path must not replace the open picker"
        );
        assert_eq!(
            menu.choices,
            vec![ExportChoice::Raw],
            "a mismatched enumeration must not alter the open picker's choices"
        );
    }

    #[test]
    fn export_formats_ready_does_not_reopen_cancelled_picker() {
        // Regression: if the user cancels the cold picker before the async
        // enumeration lands, the late ExportFormatsReady must NOT reopen it.
        // context_row stays set after Cancel (so the action strip returns), so the
        // guard cannot rely on context_row — it must key on export_menu being open.
        let mut app = app_with_paths(&["a.uasset"]);
        app.context_row = Some(0); // still resolves to "a.uasset" after Cancel
        let archive_gen = app.archive_generation;
        app.export_menu = None; // cold picker was opened, then cancelled
        let _ = update(
            &mut app,
            Message::ExportFormatsReady {
                path: "a.uasset".into(),
                formats: vec![],
                generation: archive_gen,
            },
        );
        assert!(
            app.export_menu.is_none(),
            "a cancelled picker must not be reopened by a late enumeration"
        );
    }

    #[test]
    fn export_menu_cancelled_clears_picker_keeps_context_row() {
        let mut app = App {
            context_row: Some(2),
            export_menu: Some(minimal_export_menu()),
            ..App::default()
        };
        let _ = update(&mut app, Message::ExportMenuCancelled);
        assert!(app.export_menu.is_none(), "Cancel clears the picker");
        assert_eq!(
            app.context_row,
            Some(2),
            "Cancel keeps the action strip's row"
        );
    }

    #[test]
    fn export_choice_selected_dismisses_both_menus() {
        // archive None → no task dispatched
        let mut app = App {
            context_row: Some(1),
            export_menu: Some(minimal_export_menu()),
            ..App::default()
        };
        let _ = update(
            &mut app,
            Message::ExportChoiceSelected {
                path: "a.uasset".into(),
                choice: ExportChoice::Raw,
            },
        );
        assert!(
            app.context_row.is_none(),
            "choosing a format dismisses the action strip"
        );
        assert!(
            app.export_menu.is_none(),
            "choosing a format dismisses the picker"
        );
    }

    #[test]
    fn export_completed_written_pushes_success_toast() {
        let mut app = App::default();
        let archive_gen = app.archive_generation;
        let _ = update(
            &mut app,
            Message::ExportCompleted {
                outcome: ExportOutcome::Written("/tmp/T_Rock.png".into()),
                generation: archive_gen,
            },
        );
        assert_eq!(app.toasts.items().len(), 1);
        assert_eq!(app.toasts.items()[0].severity, Severity::Success);
        assert!(app.toasts.items()[0].message.contains("T_Rock.png"));
    }

    #[test]
    fn export_completed_failed_pushes_error_toast() {
        let mut app = App::default();
        let archive_gen = app.archive_generation;
        let _ = update(
            &mut app,
            Message::ExportCompleted {
                outcome: ExportOutcome::Failed("disk full".into()),
                generation: archive_gen,
            },
        );
        assert_eq!(app.toasts.items().len(), 1);
        assert_eq!(app.toasts.items()[0].severity, Severity::Error);
        assert!(app.toasts.items()[0].message.contains("disk full"));
    }

    #[test]
    fn export_completed_cancelled_pushes_no_toast() {
        let mut app = App::default();
        let archive_gen = app.archive_generation;
        let _ = update(
            &mut app,
            Message::ExportCompleted {
                outcome: ExportOutcome::Cancelled,
                generation: archive_gen,
            },
        );
        assert!(app.toasts.is_empty(), "a cancelled export shows no toast");
    }

    #[test]
    fn export_completed_stale_generation_dropped() {
        let mut app = App::default();
        let _ = update(
            &mut app,
            Message::ExportCompleted {
                outcome: ExportOutcome::Written("/tmp/x".into()),
                generation: 99, // != default 0
            },
        );
        assert!(
            app.toasts.is_empty(),
            "stale-generation completion drops its toast"
        );
    }

    // ── export_menu inline-clear coverage ────────────────────────────────────
    // These tests pin the two `app.export_menu = None;` statements that are
    // written inline (not via dismiss_row_menus) because a live archive borrow
    // is held at those call sites. Without them, deleting either statement
    // passes the suite.

    #[test]
    fn row_context_opened_clears_export_menu() {
        let mut app = app_with_paths(&["a.uasset", "b.uasset"]);
        app.context_row = Some(0);
        app.export_menu = Some(minimal_export_menu());
        // Right-click a different row — must dismiss the picker.
        let _ = update(&mut app, Message::RowContextOpened(1));
        assert!(
            app.export_menu.is_none(),
            "new right-click must clear the export picker"
        );
    }

    #[test]
    fn keyboard_nav_clears_export_menu() {
        let mut app = app_with_paths(&["a.uasset", "b.uasset"]);
        app.context_row = Some(0);
        app.export_menu = Some(minimal_export_menu());
        let _ = handle_tree_key(&mut app, &named_key(Named::ArrowDown));
        assert!(
            app.export_menu.is_none(),
            "keyboard nav must clear the export picker"
        );
    }

    // ── console toggle / scroll / F12 ────────────────────────────────────────

    #[test]
    fn boot_app_shares_the_injected_log_buffer() {
        // `boot_app` must hand the running app the SAME ring the caller (main,
        // alongside the subscriber) writes to. If the `log_buffer` field were
        // dropped, the app would get a fresh empty buffer and this snapshot
        // would be 0 — a permanently-dead console. Kills the
        // delete-struct-field mutant on the boot path.
        let buffer = crate::state::log_buffer::LogBuffer::default();
        let app = super::boot_app(buffer.clone());
        buffer.push(tracing::Level::INFO, "t".into(), "x".into());
        assert_eq!(app.log_buffer.snapshot().len(), 1);
    }

    #[test]
    fn console_toggled_flips_visibility_and_arms_follow() {
        // Diverge from the open-branch's effect so the `console_follow = true`
        // assignment is observable: `App::default()` already sets it true, which
        // would mask a deleted/mutated assignment (see the PR #620 lesson on
        // divergent test inputs).
        let mut app = super::App {
            console_follow: false,
            ..super::App::default()
        };
        assert!(!app.console_visible);
        let _ = super::update(&mut app, super::Message::ConsoleToggled);
        assert!(app.console_visible);
        assert!(app.console_follow, "opening re-arms tail-follow");
        let _ = super::update(&mut app, super::Message::ConsoleToggled);
        assert!(!app.console_visible);
    }

    #[test]
    fn console_refresh_interval_is_fast_when_active_and_slow_when_idle() {
        use std::time::Duration;
        assert_eq!(
            super::console_refresh_interval(true),
            Duration::from_millis(super::CONSOLE_TICK_FAST_MS),
            "actively-flowing logs refresh fast"
        );
        assert_eq!(
            super::console_refresh_interval(false),
            Duration::from_millis(super::CONSOLE_TICK_SLOW_MS),
            "a stable ring refreshes slowly to cut idle CPU"
        );
    }

    #[test]
    fn console_tick_marks_active_on_new_records_and_idle_when_stable() {
        let mut app = super::App {
            console_visible: true,
            ..super::App::default()
        };
        // A record arrived since the baseline (0) -> the tick observes growth.
        app.log_buffer
            .push(tracing::Level::INFO, "t".into(), "x".into());
        let _ = super::update(&mut app, super::Message::ConsoleTick);
        assert!(
            app.console_active,
            "a fresh record makes the next tick active"
        );
        // No further records -> the ring is stable, so the tick goes idle.
        let _ = super::update(&mut app, super::Message::ConsoleTick);
        assert!(
            !app.console_active,
            "a stable ring makes the tick idle (slow refresh)"
        );
        // Another record re-activates fast refresh.
        app.log_buffer
            .push(tracing::Level::INFO, "t".into(), "y".into());
        let _ = super::update(&mut app, super::Message::ConsoleTick);
        assert!(app.console_active, "a new record re-activates the tick");
    }

    #[test]
    fn opening_console_baselines_push_counter_and_starts_active() {
        let mut app = super::App::default();
        // Records accrued while the console was closed.
        app.log_buffer
            .push(tracing::Level::INFO, "t".into(), "x".into());
        app.log_buffer
            .push(tracing::Level::INFO, "t".into(), "y".into());
        let _ = super::update(&mut app, super::Message::ConsoleToggled);
        assert!(app.console_visible);
        assert!(app.console_active, "opening starts in fast-refresh mode");
        assert_eq!(
            app.console_last_pushes, 2,
            "opening baselines the counter to the current total, not 0"
        );
        // With no new records, the first tick settles to idle (proves the
        // baseline: without it the tick would see 2 != 0 and stay active).
        let _ = super::update(&mut app, super::Message::ConsoleTick);
        assert!(!app.console_active);
    }

    #[test]
    fn console_scrolled_tracks_follow_from_offset() {
        let mut app = super::App::default();
        let _ = super::update(&mut app, super::Message::ConsoleScrolled(0.3));
        assert!(!app.console_follow, "scrolled up => stop following");
        let _ = super::update(&mut app, super::Message::ConsoleScrolled(1.0));
        assert!(app.console_follow, "back at bottom => follow again");
    }

    #[test]
    fn f12_is_a_noop_in_handle_tree_key_and_preserves_menus() {
        let mut app = app_with_paths(&["a.uasset", "b.uasset"]);
        app.context_row = Some(0);
        app.export_menu = Some(minimal_export_menu());
        let r = super::handle_tree_key(&mut app, &Key::Named(Named::F12));
        assert!(r.is_none(), "F12 produces no scroll task");
        assert_eq!(app.context_row, Some(0), "F12 must not clear context row");
        assert!(app.export_menu.is_some(), "F12 must not clear export menu");
    }

    #[test]
    fn tree_key_for_gates_on_capture_and_excludes_f12() {
        use iced::event::Status;

        // A nav key the UI did NOT consume drives the tree, carrying its key.
        match super::tree_key_for(Key::Named(Named::ArrowDown), Status::Ignored) {
            Some(super::Message::TreeKey(Key::Named(Named::ArrowDown))) => {}
            other => panic!("expected TreeKey(ArrowDown), got {other:?}"),
        }
        // Once a focused widget (e.g. a console filter `text_input`) captured the
        // key, it must NOT also navigate/mutate the tree.
        assert!(
            super::tree_key_for(Key::Named(Named::ArrowDown), Status::Captured).is_none(),
            "a captured key must not reach the tree"
        );
        // F12 is the console toggle — never a tree key, regardless of status.
        assert!(super::tree_key_for(Key::Named(Named::F12), Status::Ignored).is_none());
        assert!(super::tree_key_for(Key::Named(Named::F12), Status::Captured).is_none());
    }

    // ── console filter controls ───────────────────────────────────────────────

    #[test]
    fn console_min_level_changed_sets_filter() {
        let mut app = super::App::default();
        let _ = super::update(
            &mut app,
            super::Message::ConsoleMinLevelChanged(tracing::Level::WARN),
        );
        assert_eq!(app.console_filters.min_level, tracing::Level::WARN);
    }

    #[test]
    fn console_target_and_search_changed_set_filters() {
        let mut app = super::App::default();
        let _ = super::update(
            &mut app,
            super::Message::ConsoleTargetFilterChanged("core".into()),
        );
        assert_eq!(app.console_filters.target_filter, "core");
        let _ = super::update(
            &mut app,
            super::Message::ConsoleSearchChanged("decode".into()),
        );
        assert_eq!(app.console_filters.search, "decode");
    }

    #[test]
    fn console_cleared_empties_buffer_and_rearms_follow() {
        let mut app = super::App::default();
        app.log_buffer
            .push(tracing::Level::INFO, "t".into(), "x".into());
        app.console_follow = false;
        let _ = super::update(&mut app, super::Message::ConsoleCleared);
        assert!(app.log_buffer.snapshot().is_empty());
        assert!(app.console_follow, "clearing re-arms tail-follow");
    }

    // ── Task 7: AudioDecoded message wiring ──────────────────────────────────

    /// Build an App whose active tab has `tab.audio.info` populated, mirroring
    /// the postcondition of the `AssetLoaded` handler after a sound-wave load.
    ///
    /// The tab has no `TabContent::Ready` (left as `Loading`) because the
    /// `AudioDecoded` arm looks up the tab by path and checks `audio.info`,
    /// not the content variant. Setting `info` is sufficient to exercise all
    /// four `AudioDecoded` paths (generation fence, path lookup, info guard,
    /// Ok/Err decode result).
    fn app_with_open_audio_tab() -> App {
        use paksmith_core::asset::AudioInfo;
        let mut app = App::default();
        let _ = app.tabs.open_or_activate("Game/SFX_Hit.uasset");
        let tab = app
            .tabs
            .active_tab_mut()
            .expect("just-opened tab must be active");
        tab.audio.info = Some(AudioInfo {
            export_idx: 0,
            codec_label: "Vorbis (Ogg)".to_owned(),
            channels: Some(2),
            duration_secs: Some(1.0),
            playable: true,
        });
        app
    }

    /// Minimal non-trivial `DecodedAudio` for assertion tests.
    ///
    /// 2 mono frames so the waveform helper produces a non-empty result (min
    /// effective columns = min(WAVEFORM_COLUMNS, frame_count) = min(512, 2) = 2).
    /// Divergent values (MAX, MIN) pin the waveform normalization path: a
    /// no-op body replacement would leave `waveform` empty, failing the
    /// `!waveform.is_empty()` assertion.
    fn two_frame_decoded_audio() -> crate::state::audio_view::DecodedAudio {
        crate::state::audio_view::DecodedAudio {
            samples: vec![i16::MAX, i16::MIN],
            sample_rate: 44_100,
            channels: 1,
        }
    }

    #[test]
    fn audio_decoded_stale_generation_is_dropped() {
        let mut app = app_with_open_audio_tab();
        app.archive_generation = 3;
        let stale = 2u64;
        let _ = update(
            &mut app,
            Message::AudioDecoded {
                path: "Game/SFX_Hit.uasset".into(),
                result: Ok(two_frame_decoded_audio()),
                generation: stale,
            },
        );
        assert!(
            app.tabs.active_tab().unwrap().audio.decoded.is_none(),
            "a stale-generation audio decode must be ignored"
        );
        assert!(
            app.tabs.active_tab().unwrap().audio.waveform.is_empty(),
            "a stale-generation audio decode must not populate the waveform"
        );
    }

    #[test]
    fn audio_decoded_current_generation_writes_decoded_and_waveform() {
        let mut app = app_with_open_audio_tab();
        app.archive_generation = 3;
        // Pre-seed an error so the test verifies it is cleared on success.
        app.tabs.active_tab_mut().unwrap().audio.error = Some("prev".to_owned());
        let _ = update(
            &mut app,
            Message::AudioDecoded {
                path: "Game/SFX_Hit.uasset".into(),
                result: Ok(two_frame_decoded_audio()),
                generation: 3,
            },
        );
        let tab = app.tabs.active_tab().unwrap();
        assert!(
            tab.audio.decoded.is_some(),
            "a current-generation Ok decode must populate audio.decoded"
        );
        assert!(
            !tab.audio.waveform.is_empty(),
            "a current-generation Ok decode must populate the waveform"
        );
        assert!(
            tab.audio.error.is_none(),
            "a successful decode must clear any previous error"
        );
    }

    #[test]
    fn audio_decoded_error_sets_error_field() {
        let mut app = app_with_open_audio_tab();
        app.archive_generation = 3;
        let _ = update(
            &mut app,
            Message::AudioDecoded {
                path: "Game/SFX_Hit.uasset".into(),
                result: Err("boom".to_owned()),
                generation: 3,
            },
        );
        let tab = app.tabs.active_tab().unwrap();
        assert_eq!(
            tab.audio.error.as_deref(),
            Some("boom"),
            "an Err result must set audio.error to the error message"
        );
        assert!(
            tab.audio.decoded.is_none(),
            "an Err result must not populate audio.decoded"
        );
    }

    #[test]
    fn audio_decoded_without_info_is_dropped() {
        // Pins the `tab.audio.info.is_some()` guard: a decode arriving after a
        // content reset (which sets `audio.info = None` via `set_content`) must
        // not write onto the now-non-audio tab. Mirrors
        // `texture_decoded_after_content_reset_is_dropped` (mips-empty guard).
        let mut app = app_with_open_audio_tab();
        app.archive_generation = 3;
        // Clear info to simulate a content swap / reset.
        app.tabs.active_tab_mut().unwrap().audio.info = None;
        let _ = update(
            &mut app,
            Message::AudioDecoded {
                path: "Game/SFX_Hit.uasset".into(),
                result: Ok(two_frame_decoded_audio()),
                generation: 3,
            },
        );
        assert!(
            app.tabs.active_tab().unwrap().audio.decoded.is_none(),
            "a decode landing after audio.info was cleared must not write decoded"
        );
    }

    #[test]
    fn audio_decoded_after_tab_close_same_generation_is_noop() {
        // Race guard: a decode completes after its tab was closed. The result
        // carries the SAME generation (no archive swap), so the fence does not
        // drop it — the path lookup must silently no-op and must not re-open
        // the tab. Mirrors `texture_decoded_after_tab_close_same_generation_is_noop`.
        let mut app = app_with_open_audio_tab();
        app.tabs.close(0);
        assert!(app.tabs.open.is_empty(), "precondition: the tab is closed");
        let generation = app.archive_generation;
        let _ = update(
            &mut app,
            Message::AudioDecoded {
                path: "Game/SFX_Hit.uasset".into(),
                result: Ok(two_frame_decoded_audio()),
                generation,
            },
        );
        assert!(
            app.tabs.open.is_empty(),
            "a late AudioDecoded for a closed tab must not re-open it"
        );
    }

    // ── Task 8: audio playback wiring ─────────────────────────────────────────

    /// Build an `App` with an active tab that has decoded audio, so transport
    /// arms have a real `decoded` payload to act on.
    fn app_with_decoded_audio() -> App {
        let mut app = App::default();
        let _ = app.tabs.open_or_activate("Game/SFX.uasset");
        let tab = app
            .tabs
            .active_tab_mut()
            .expect("just-opened tab must be active");
        tab.audio.decoded = Some(crate::state::audio_view::DecodedAudio {
            // 4 samples, stereo (2 ch): 2 frames at 44 100 Hz → tiny but non-empty.
            samples: vec![1_i16, -1_i16, 2_i16, -2_i16],
            sample_rate: 44_100,
            channels: 2,
        });
        tab.audio.info = Some(paksmith_core::asset::AudioInfo {
            export_idx: 0,
            codec_label: "Vorbis (Ogg)".to_owned(),
            channels: Some(2),
            duration_secs: Some(1.0),
            playable: true,
        });
        app
    }

    // --- audio_tick_active ---

    #[test]
    fn audio_tick_active_true_when_playing() {
        let mut app = app_with_decoded_audio();
        app.tabs.active_tab_mut().unwrap().audio.transport =
            crate::state::audio_view::Transport::Playing;
        assert!(
            audio_tick_active(&app),
            "audio_tick_active must return true when transport is Playing"
        );
    }

    #[test]
    fn audio_tick_active_false_when_paused() {
        let mut app = app_with_decoded_audio();
        app.tabs.active_tab_mut().unwrap().audio.transport =
            crate::state::audio_view::Transport::Paused;
        assert!(
            !audio_tick_active(&app),
            "audio_tick_active must return false when transport is Paused"
        );
    }

    #[test]
    fn audio_tick_active_false_when_stopped() {
        let app = app_with_decoded_audio();
        // Transport starts Stopped (default).
        assert_eq!(
            app.tabs.active_tab().unwrap().audio.transport,
            crate::state::audio_view::Transport::Stopped,
            "precondition: transport is Stopped"
        );
        assert!(
            !audio_tick_active(&app),
            "audio_tick_active must return false when transport is Stopped"
        );
    }

    #[test]
    fn audio_tick_active_false_when_no_tab() {
        let app = App::default(); // no tabs open
        assert!(
            !audio_tick_active(&app),
            "audio_tick_active must return false when no tab is open"
        );
    }

    // --- AudioVolume arm ---

    #[test]
    fn audio_volume_clamps_above_one() {
        let mut app = app_with_decoded_audio();
        // `app.audio` is None so the seam call is skipped; only pure state is tested.
        let _ = update(&mut app, Message::AudioVolume(1.5));
        assert!(
            (app.tabs.active_tab().unwrap().audio.volume - 1.0).abs() < 1e-6,
            "volume 1.5 must clamp to 1.0 (got {})",
            app.tabs.active_tab().unwrap().audio.volume
        );
    }

    // --- AudioStop arm ---

    #[test]
    fn audio_stop_resets_transport_and_position() {
        let mut app = app_with_decoded_audio();
        // Prime the tab into Playing state with a non-zero position.
        {
            let tab = app.tabs.active_tab_mut().unwrap();
            tab.audio.transport = crate::state::audio_view::Transport::Playing;
            tab.audio.position_secs = 3.0;
        }
        let _ = update(&mut app, Message::AudioStop);
        let tab = app.tabs.active_tab().unwrap();
        assert_eq!(
            tab.audio.transport,
            crate::state::audio_view::Transport::Stopped,
            "transport must be Stopped after AudioStop"
        );
        assert!(
            tab.audio.position_secs.abs() < 1e-6,
            "position must reset to 0.0 after AudioStop (got {})",
            tab.audio.position_secs
        );
    }

    // --- AudioPlayPause arm ---

    #[test]
    fn audio_play_pause_toggles_transport() {
        let mut app = app_with_decoded_audio();
        // Stopped → Playing
        let _ = update(&mut app, Message::AudioPlayPause);
        assert_eq!(
            app.tabs.active_tab().unwrap().audio.transport,
            crate::state::audio_view::Transport::Playing,
            "first toggle: Stopped → Playing"
        );
        // Playing → Paused
        let _ = update(&mut app, Message::AudioPlayPause);
        assert_eq!(
            app.tabs.active_tab().unwrap().audio.transport,
            crate::state::audio_view::Transport::Paused,
            "second toggle: Playing → Paused"
        );
        // Paused → Playing
        let _ = update(&mut app, Message::AudioPlayPause);
        assert_eq!(
            app.tabs.active_tab().unwrap().audio.transport,
            crate::state::audio_view::Transport::Playing,
            "third toggle: Paused → Playing"
        );
    }
}
