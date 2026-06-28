//! Top-level application state, messages, and the update/view cycle.

use std::path::PathBuf;

use iced::keyboard::Event as KeyboardEvent;
use iced::keyboard::key::Named;
use iced::widget::{button, column, container, pane_grid, text};
use iced::{Element, Event, Length, Subscription, Task};
use zeroize::Zeroizing;

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
    /// Visible-row index whose inline context-menu strip (Open / Copy Path) is
    /// currently shown, or `None`. A *visible-row* index like
    /// [`App::selected_row`]; cleared on every tree-mutating or selection path
    /// so a stale index can never address the wrong row.
    pub context_row: Option<usize>,
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
        Message::ToastDismissed(id) => {
            app.toasts.remove(id);
            Task::none()
        }
        Message::RowContextOpened(i) => {
            app.context_row = toggle_context_row(app.context_row, i);
            Task::none()
        }
        Message::OpenAsset(path) => {
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
                }
            }
            // INVARIANT: the decodable-mip cache was populated (or left empty for
            // a non-texture) just above, so the view picker reads `mips` rather
            // than re-classifying. This ordering is `pick_view_after_load`'s
            // documented precondition — do not move it before the populate block.
            app.tabs.pick_view_after_load(&path);
            decode_task
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

    if app.archive.is_none() {
        return menu_sub;
    }

    let tree_key_sub = iced::event::listen_with(|event, _status, _window| match event {
        Event::Keyboard(KeyboardEvent::KeyPressed { key, .. }) => Some(Message::TreeKey(key)),
        _ => None,
    });

    // Only subscribe to left-button-release when a Hex tab is active. Drag can
    // only start inside a Hex view, so firing this app-wide would cause
    // spurious update+view rebuilds on every click elsewhere.
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

    Subscription::batch([menu_sub, tree_key_sub, hex_drag_sub])
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
        let tabs = &app.tabs;
        let entries = &archive.entries;

        pane_grid(&app.panes, move |_pane, kind, _maximized| {
            let content: Element<'_, Message> = match kind {
                PaneKind::Sidebar => sidebar::view(tree, accent, selected_row),
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
    let root = column![toolbar_view, body, status_view]
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
}
